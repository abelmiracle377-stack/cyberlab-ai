#!/usr/bin/env python3
"""CyberLab local Kali bridge. Loopback-only, paired, explicitly authorised Nmap TCP checks."""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = 8765
MAX_BODY = 8192
MAX_OLLAMA_BODY = 65536
OLLAMA_URL = "http://127.0.0.1:11434"
MAX_PORTS = 100
MAX_RUNTIME = 55
ALLOWED_ORIGINS = {"https://cyberlab-ai.vercel.app", "http://localhost:3000", "http://127.0.0.1:3000"}
CONFIG_DIR = Path.home() / ".config" / "cyberlab"
TOKEN_FILE = CONFIG_DIR / "bridge-token"
scan_lock = threading.Lock()


def load_token() -> str:
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if len(token) >= 40:
            return token
    token = secrets.token_urlsafe(48)
    fd = os.open(str(TOKEN_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass
    return token


def valid_target(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or any(ch in value for ch in "/\\:@?#"):
        raise ValueError("Enter a single IP address or hostname, not a URL or network range.")
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("Loopback, link-local, multicast and reserved targets are blocked.")
        return str(ip)
    except ValueError as exc:
        if "blocked" in str(exc):
            raise
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        raise ValueError("Enter a valid fully-qualified domain name or IP address.")
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(value, None, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError as exc:
        raise ValueError("Target could not be resolved to IPv4.") from exc
    if not addresses or len(addresses) > 4:
        raise ValueError("Domain must resolve to between one and four IPv4 addresses. For larger/CDN domains, use an explicitly authorised single IP.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("Resolved target includes loopback, link-local, multicast or reserved addresses.")
    return value


def parse_report(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        addresses = [{"address": n.get("addr", ""), "type": n.get("addrtype", "")} for n in host.findall("address")]
        ports = []
        for node in host.findall("./ports/port"):
            state = node.find("state")
            service = node.find("service")
            ports.append({
                "protocol": node.get("protocol", "tcp"),
                "port": int(node.get("portid", "0")),
                "state": state.get("state", "unknown") if state is not None else "unknown",
                "service": service.get("name", "unknown") if service is not None else "unknown",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            })
        hosts.append({
            "status": status.get("state", "unknown") if status is not None else "unknown",
            "addresses": addresses,
            "ports": ports,
        })
    return {
        "hosts": hosts,
        "open_ports": [
            {"address": (h["addresses"][0]["address"] if h["addresses"] else "unknown"), **p}
            for h in hosts for p in h["ports"] if p["state"] == "open"
        ],
        "state_summary": {state: sum(1 for h in hosts for p in h["ports"] if p["state"] == state) for state in ("open", "closed", "filtered")},
    }



def ollama_request(path: str, payload: dict | None = None, timeout: int = 12) -> dict:
    """Talk only to the fixed Ollama loopback service; callers cannot supply a host or URL."""
    if path not in {"/api/tags", "/api/chat"}:
        raise ValueError("Unsupported local model operation.")
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        OLLAMA_URL + path,
        data=body,
        headers={"Content-Type": "application/json"} if body is not None else {},
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("Local model response exceeded the 2 MB limit.")
        result = json.loads(raw.decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("Local model service returned an invalid response.")
        return result
    except urllib.error.URLError as exc:
        raise ConnectionError("Ollama is unavailable at 127.0.0.1:11434. Start Ollama locally and try again.") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Ollama returned invalid JSON.") from exc


def ollama_models() -> list[dict]:
    result = ollama_request("/api/tags")
    models = result.get("models", [])
    if not isinstance(models, list):
        raise ValueError("Ollama model catalogue is malformed.")
    return [
        {"name": str(item.get("name", "")), "size": item.get("size"), "modified_at": item.get("modified_at")}
        for item in models if isinstance(item, dict) and item.get("name")
    ][:100]


def ollama_chat(model: str, prompt: str, history: list | None = None) -> dict:
    model = model.strip()
    prompt = prompt.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", model):
        raise ValueError("Choose a valid model name from your local Ollama catalogue.")
    if not prompt or len(prompt) > 12000:
        raise ValueError("Prompt must contain between 1 and 12,000 characters.")
    available = {item["name"] for item in ollama_models()}
    if model not in available:
        raise ValueError("Selected model is not installed in local Ollama.")
    # Bound the aggregate conversation, not just each message, so the JSON body
    # remains comfortably below MAX_OLLAMA_BODY even with a full history.
    messages = []
    history_budget = 32000
    if isinstance(history, list):
        for item in history[-12:]:
            if not isinstance(item, dict) or item.get("role") not in {"user", "assistant"}:
                continue
            content = item.get("content")
            if not isinstance(content, str) or not content.strip():
                continue
            remaining = history_budget - sum(len(message["content"]) for message in messages)
            if remaining <= 0:
                break
            bounded = content[:min(4000, remaining)]
            messages.append({"role": item["role"], "content": bounded})
    messages.append({"role": "user", "content": prompt})
    result = ollama_request("/api/chat", {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"num_predict": 4096},
    }, timeout=120)
    message = result.get("message", {})
    content = message.get("content", "") if isinstance(message, dict) else ""
    if not isinstance(content, str):
        raise ValueError("Local model returned an invalid message.")
    return {"model": model, "response": content[:50000], "done": bool(result.get("done", False))}


def environment_capabilities() -> dict:
    """Read-only discovery for CyberLab OS; never installs or starts runtimes."""
    os_release = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass

    runtimes = {
        "docker": {"installed": bool(shutil.which("docker")), "executable": shutil.which("docker")},
        "podman": {"installed": bool(shutil.which("podman")), "executable": shutil.which("podman")},
        "qemu": {"installed": bool(shutil.which("qemu-system-x86_64") or shutil.which("qemu-system-aarch64")), "executable": shutil.which("qemu-system-x86_64") or shutil.which("qemu-system-aarch64")},
        "libvirt": {"installed": bool(shutil.which("virsh")), "executable": shutil.which("virsh")},
        "virtualbox": {"installed": bool(shutil.which("VBoxManage")), "executable": shutil.which("VBoxManage")},
    }
    return {
        "platform": platform.system(),
        "distribution": os_release.get("PRETTY_NAME") or platform.platform(),
        "distribution_id": os_release.get("ID", "").lower(),
        "architecture": platform.machine(),
        "cpu_count": os.cpu_count(),
        "hardware_virtualization_device": Path("/dev/kvm").exists(),
        "wsl": bool(os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP")),
        "runtimes": runtimes,
        "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": "Read-only capability discovery. No packages were installed, no containers or virtual machines were started, and no host commands were executed.",
    }


def system_snapshot() -> dict:
    """Return bounded, non-sensitive host health metrics; never process args or user data."""
    memory = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            if key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                memory[key] = int(value.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        memory = {}
    try:
        uptime_seconds = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        uptime_seconds = None
    try:
        process_count = sum(1 for entry in Path("/proc").iterdir() if entry.name.isdigit())
    except OSError:
        process_count = None
    disk = shutil.disk_usage("/")
    try:
        load_average = list(os.getloadavg())
    except (AttributeError, OSError):
        load_average = None
    return {
        "platform": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "uptime_seconds": round(uptime_seconds) if uptime_seconds is not None else None,
        "load_average_1_5_15": load_average,
        "memory_bytes": memory,
        "disk_root_bytes": {"total": disk.total, "used": disk.used, "free": disk.free},
        "process_count": process_count,
        "nmap_available": bool(shutil.which("nmap")),
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": "Local host health summary only; no usernames, process names, command lines, files or network payloads are collected.",
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberLabKaliBridge/1.0"

    def log_message(self, fmt, *args):
        print("[bridge] " + (fmt % args))

    def send_json(self, status: int, payload: dict, origin: str | None = None):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")
        if origin not in ALLOWED_ORIGINS:
            return self.send_json(403, {"error": "Origin not allowed."})
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Vary", "Origin")
        self.end_headers()

    def authorised(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        expected = "Bearer " + self.server.bridge_token
        return hmac.compare_digest(supplied, expected)

    def do_GET(self):
        origin = self.headers.get("Origin", "")
        if origin not in ALLOWED_ORIGINS:
            return self.send_json(403, {"error": "Origin not allowed."})
        path = urlparse(self.path).path
        if path not in {"/health", "/system", "/capabilities", "/ollama/health", "/ollama/models"}:
            return self.send_json(404, {"error": "Not found."}, origin)
        if not self.authorised():
            return self.send_json(401, {"error": "Pairing token required."}, origin)
        if path == "/system":
            return self.send_json(200, {"status": "ok", "metrics": system_snapshot()}, origin)
        if path == "/capabilities":
            return self.send_json(200, {"status": "ok", "capabilities": environment_capabilities()}, origin)
        if path == "/ollama/health":
            try:
                models = ollama_models()
                return self.send_json(200, {"status": "available", "endpoint": OLLAMA_URL, "model_count": len(models)}, origin)
            except (ConnectionError, ValueError) as exc:
                return self.send_json(503, {"status": "unavailable", "error": str(exc)}, origin)
        if path == "/ollama/models":
            try:
                return self.send_json(200, {"models": ollama_models()}, origin)
            except (ConnectionError, ValueError) as exc:
                return self.send_json(503, {"error": str(exc)}, origin)
        self.send_json(200, {"status": "connected", "agent": "CyberLab Kali Bridge", "nmap": bool(shutil.which("nmap")), "ollama": True}, origin)

    def do_POST(self):
        origin = self.headers.get("Origin", "")
        if origin not in ALLOWED_ORIGINS:
            return self.send_json(403, {"error": "Origin not allowed."})
        path = urlparse(self.path).path
        if path not in {"/scan", "/ollama/chat"}:
            return self.send_json(404, {"error": "Not found."}, origin)
        if not self.authorised():
            return self.send_json(401, {"error": "Invalid pairing token."}, origin)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            limit = MAX_OLLAMA_BODY if path == "/ollama/chat" else MAX_BODY
            if length < 2 or length > limit:
                raise ValueError("Request body is missing or too large.")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object.")
            if path == "/ollama/chat":
                result = ollama_chat(str(data.get("model", "")), str(data.get("prompt", "")), data.get("history"))
                return self.send_json(200, result, origin)
            target = valid_target(str(data.get("target", "")))
            confirmation = str(data.get("confirmationTarget", "")).strip().lower().rstrip(".")
            reference = str(data.get("authorizationReference", "")).strip()
            if data.get("authorizationConfirmed") is not True or confirmation != str(data.get("target", "")).strip().lower().rstrip(".") or not reference or len(reference) > 160:
                raise ValueError("Confirm ownership or written permission, provide an approval reference and retype the exact target.")
            ports_raw = data.get("ports", [])
            if not isinstance(ports_raw, list) or not ports_raw or len(ports_raw) > MAX_PORTS or any(type(p) is not int or not 1 <= p <= 65535 for p in ports_raw):
                raise ValueError("Select between 1 and 100 unique TCP ports in the range 1–65535.")
            ports = sorted(set(ports_raw))
            if len(ports) != len(ports_raw):
                raise ValueError("Duplicate ports are not accepted.")
            if not shutil.which("nmap"):
                return self.send_json(503, {"error": "Nmap is not installed. Install it with: sudo apt install nmap"}, origin)
            if not scan_lock.acquire(blocking=False):
                return self.send_json(409, {"error": "A local assessment is already running."}, origin)
            try:
                command = [
                    "nmap", "-n", "-sT", "-sV", "--version-light", "-T2",
                    "--max-retries", "1", "--host-timeout", "45s",
                    "-p", ",".join(map(str, ports)), "-oX", "-", target,
                ]
                started = time.time()
                completed = subprocess.run(command, capture_output=True, text=True, timeout=MAX_RUNTIME, check=False)
                if completed.returncode not in (0, 1) or not completed.stdout.strip():
                    raise RuntimeError((completed.stderr or "Nmap did not return a report.")[:700])
                report = parse_report(completed.stdout)
                return self.send_json(200, {
                    "status": "completed",
                    "target": target,
                    "ports_checked": ports,
                    "duration_seconds": round(time.time() - started, 1),
                    "method": "Nmap TCP connect scan with light service version detection",
                    **report,
                    "note": "Nmap reports selected TCP ports as open, closed or filtered when determinable. Filtered means a firewall or network control prevented a definitive result. This is not a vulnerability verdict. No NSE scripts, exploit checks, credentials, evasion or denial-of-service options are used. Assess only systems explicitly in scope.",
                }, origin)
            finally:
                scan_lock.release()
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json(400, {"error": str(exc)}, origin)
        except ConnectionError as exc:
            self.send_json(503, {"error": str(exc)}, origin)
        except subprocess.TimeoutExpired:
            self.send_json(504, {"error": "Assessment exceeded the 55-second time limit."}, origin)
        except Exception as exc:
            self.send_json(502, {"error": str(exc)[:700]}, origin)


def main():
    parser = argparse.ArgumentParser(description="CyberLab local Kali bridge (loopback only).")
    parser.add_argument("--host", default=HOST, choices=[HOST], help="Must remain bound to 127.0.0.1.")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be between 1024 and 65535.")
    token = load_token()
    if not shutil.which("nmap"):
        print("Nmap not found. Install with: sudo apt update && sudo apt install -y nmap")
    print("\nCyberLab Kali Bridge is ready.")
    print("Listening only on http://127.0.0.1:" + str(args.port))
    print("Pairing token (keep private; enter it in your CyberLab dashboard):\n" + token)
    print("\nPress Ctrl+C to stop the bridge.\n")
    server = ThreadingHTTPServer((HOST, args.port), Handler)
    server.bridge_token = token
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CyberLab Kali Bridge...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
