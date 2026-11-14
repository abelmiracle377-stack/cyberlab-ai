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
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HOST = "127.0.0.1"
PORT = 8765
MAX_BODY = 16384
OLLAMA_BASE_URL = "http://127.0.0.1:11434"
MAX_PORTS = 100
MAX_RUNTIME = 180
JOB_TTL_SECONDS = 900
MAX_RETAINED_JOBS = 8
SCAN_PROFILES = {"quick": [22, 80, 443], "standard": list(range(1, 101))}
ALLOWED_ORIGINS = {"https://cyberlab-ai.vercel.app", "http://localhost:3000", "http://127.0.0.1:3000"}
CONFIG_DIR = Path.home() / ".config" / "cyberlab"
TOKEN_FILE = CONFIG_DIR / "bridge-token"
scan_lock = threading.Lock()
job_lock = threading.Lock()
scan_jobs: dict[str, dict] = {}


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
    """Parse Nmap XML with the same evidence fields as the CLI/browser parser."""
    raw = xml_text.encode("utf-8")
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Nmap XML exceeds the 2 MB limit.")
    if re.search(rb"<!DOCTYPE|<!ENTITY", raw, re.I):
        raise ValueError("DOCTYPE and entity declarations are not accepted.")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError("Invalid Nmap XML: " + str(exc)) from exc
    if root.tag != "nmaprun":
        raise ValueError("XML root element is not nmaprun.")
    hosts = []
    for index, host in enumerate(root.findall("host"), 1):
        status = host.find("status")
        addresses = [{"address": n.get("addr", ""), "type": n.get("addrtype", "unknown")} for n in host.findall("address")]
        hostnames = [{"name": n.get("name", ""), "type": n.get("type", "unknown")} for n in host.findall("./hostnames/hostname") if n.get("name")]
        ports = []
        for node in host.findall("./ports/port"):
            state, service = node.find("state"), node.find("service")
            try:
                number = int(node.get("portid", "0"))
            except ValueError:
                continue
            if not 1 <= number <= 65535:
                continue
            ports.append({
                "protocol": node.get("protocol", "unknown"), "port": number,
                "state": state.get("state", "unknown") if state is not None else "unknown",
                "reason": state.get("reason", "") if state is not None else "",
                "reason_ttl": state.get("reason_ttl") if state is not None else None,
                "service": service.get("name", "unknown") if service is not None else "unknown",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "extra_info": service.get("extrainfo", "") if service is not None else "",
                "tunnel": service.get("tunnel", "") if service is not None else "",
                "method": service.get("method", "") if service is not None else "",
                "confidence": service.get("conf") if service is not None else None,
            })
        hosts.append({
            "index": index, "status": status.get("state", "unknown") if status is not None else "unknown",
            "status_reason": status.get("reason", "") if status is not None else "",
            "addresses": addresses, "hostnames": hostnames, "ports": ports,
        })
    all_ports = [port for host in hosts for port in host["ports"]]
    states = ("open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered", "unknown")
    scaninfo = [{"type": n.get("type", ""), "protocol": n.get("protocol", ""),
                 "numservices": n.get("numservices", ""), "services": n.get("services", "")}
                for n in root.findall("./scaninfo")]
    runstats = root.find("runstats")
    finished = runstats.find("finished") if runstats is not None else None
    host_stats = runstats.find("hosts") if runstats is not None else None
    completion = {
        "finished": finished.attrib if finished is not None else {},
        "hosts": host_stats.attrib if host_stats is not None else {},
        "scanner": root.get("scanner", ""), "version": root.get("version", ""),
        "args": root.get("args", ""), "start": root.get("start", ""),
    }
    open_ports = [
        {"host": host["addresses"][0]["address"] if host["addresses"] else f"Host {host['index']}", **port}
        for host in hosts for port in host["ports"] if port["state"] == "open"
    ]
    state_counts = {state: sum(1 for port in all_ports if port["state"] == state) for state in states}
    evidence_status = "completed" if completion["finished"].get("exit") == "success" else ("partial" if hosts or completion["finished"] else "no_port_evidence")
    return {
        "hosts": hosts, "open_ports": open_ports, "state_summary": state_counts,
        "summary": {"hosts": len(hosts), "up": sum(1 for host in hosts if host["status"] == "up"),
                    "ports": len(all_ports), "open_ports": len(open_ports), "state_counts": state_counts},
        "scaninfo": scaninfo, "completion": completion, "evidence_status": evidence_status,
    }

def resolve_scan_ports(profile: str, ports_raw) -> list[int]:
    """Return a bounded TCP port selection for one named scan profile."""
    if profile in SCAN_PROFILES:
        expected = SCAN_PROFILES[profile]
        if ports_raw and (not isinstance(ports_raw, list) or sorted(set(ports_raw)) != expected):
            raise ValueError("Selected ports do not match the chosen scan profile.")
        return list(expected)
    if profile != "custom":
        raise ValueError("Choose the quick, standard or custom scan profile.")
    if not isinstance(ports_raw, list) or not ports_raw or len(ports_raw) > MAX_PORTS or any(type(port) is not int or not 1 <= port <= 65535 for port in ports_raw):
        raise ValueError("Select between 1 and 100 unique TCP ports in the range 1–65535.")
    selected = sorted(set(ports_raw))
    if len(selected) != len(ports_raw):
        raise ValueError("Duplicate ports are not accepted.")
    return selected


def ollama_request(path: str, payload: dict | None = None, timeout: int = 3) -> dict:
    """Talk only to the Ollama service on this same machine; never accepts a remote base URL."""
    if path not in {"/api/version", "/api/tags", "/api/chat"}:
        raise ValueError("Unsupported local Ollama endpoint.")
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(OLLAMA_BASE_URL + path, data=data, headers={"Content-Type": "application/json"} if data else {})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("Ollama is unavailable on 127.0.0.1:11434. Start Ollama locally and try again.") from exc
    if len(raw) > 2 * 1024 * 1024:
        raise RuntimeError("Ollama response exceeded the 2 MB limit.")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Ollama returned an invalid JSON response.") from exc
    if not isinstance(result, dict):
        raise RuntimeError("Ollama returned an unexpected response.")
    return result


def validate_ollama_chat(data: dict, installed_models: set[str]) -> dict:
    """Validate a local chat request against installed model names and bounded text history."""
    model = data.get("model")
    messages = data.get("messages")
    if not isinstance(model, str) or model not in installed_models:
        raise ValueError("Choose a model already installed in local Ollama. CyberLab will not download models automatically.")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 12:
        raise ValueError("Provide between 1 and 12 chat messages.")
    safe_messages = []
    for item in messages:
        if not isinstance(item, dict) or item.get("role") not in {"user", "assistant"} or not isinstance(item.get("content"), str):
            raise ValueError("Messages must contain only user or assistant text.")
        content = item["content"].strip()
        if not content or len(content) > 4000:
            raise ValueError("Each message must contain 1 to 4,000 characters.")
        safe_messages.append({"role": item["role"], "content": content})
    return {"model": model, "messages": safe_messages, "stream": False,
            "options": {"num_ctx": 2048, "num_predict": 512, "temperature": 0.2}}


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
        if not self.authorised():
            return self.send_json(401, {"error": "Pairing token required."}, origin)
        if path == "/system":
            return self.send_json(200, {"status": "ok", "metrics": system_snapshot()}, origin)
        if path == "/health":
            return self.send_json(200, {"status": "connected", "agent": "CyberLab Kali Bridge", "nmap": bool(shutil.which("nmap"))}, origin)
        if path == "/ollama/health":
            try:
                version = ollama_request("/api/version", timeout=2).get("version", "unknown")
                return self.send_json(200, {"status": "connected", "version": str(version)[:80], "endpoint": "127.0.0.1:11434"}, origin)
            except RuntimeError as exc:
                return self.send_json(503, {"status": "unavailable", "error": str(exc)}, origin)
        if path == "/ollama/models":
            try:
                payload = ollama_request("/api/tags", timeout=5)
                models = [{"name": str(item.get("name", ""))[:160], "size": item.get("size"),
                           "parameter_size": str(item.get("details", {}).get("parameter_size", ""))[:40],
                           "quantization": str(item.get("details", {}).get("quantization_level", ""))[:40]}
                          for item in payload.get("models", []) if isinstance(item, dict) and item.get("name")]
                return self.send_json(200, {"models": models, "count": len(models)}, origin)
            except RuntimeError as exc:
                return self.send_json(503, {"models": [], "error": str(exc)}, origin)
        match = re.fullmatch(r"/scan/([A-Za-z0-9_-]{20,100})", path)
        if match:
            job_id = match.group(1)
            with job_lock:
                job = scan_jobs.get(job_id)
                if not job or time.time() - job["created_at"] > JOB_TTL_SECONDS:
                    scan_jobs.pop(job_id, None)
                    return self.send_json(404, {"error": "Scan job not found or expired."}, origin)
                snapshot = {key: value for key, value in job.items() if key != "created_at"}
            return self.send_json(200, snapshot, origin)
        return self.send_json(404, {"error": "Not found."}, origin)

    def run_scan_job(self, job_id: str, target: str, ports: list[int], profile: str):
        started = time.time()
        try:
            command = ["nmap", "-n", "-sT", "-sV", "--version-light", "-T2", "--max-retries", "1", "--host-timeout", "150s", "-p", ",".join(map(str, ports)), "-oX", "-", target]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=MAX_RUNTIME, check=False)
            if completed.returncode not in (0, 1) or not completed.stdout.strip():
                raise RuntimeError((completed.stderr or "Nmap did not return a report.")[:700])
            report = parse_report(completed.stdout)
            payload = {
                "status": "completed" if report["evidence_status"] == "completed" else "partial",
                "target": target, "profile": profile, "ports_checked": ports,
                "duration_seconds": round(time.time() - started, 1),
                "method": "Nmap TCP connect scan with light service version detection",
                "exit_code": completed.returncode, "stderr": completed.stderr[:2000],
                "ports_checked_count": len(ports), **report,
                "note": "Nmap reports selected TCP ports as open, closed or filtered when determinable. Filtered means a firewall or network control prevented a definitive result. This is not a vulnerability verdict. No NSE scripts, exploit checks, credentials, evasion or denial-of-service options are used. Assess only systems explicitly in scope.",
            }
            with job_lock:
                scan_jobs[job_id].update(payload)
        except subprocess.TimeoutExpired:
            with job_lock:
                scan_jobs[job_id].update({"status": "timeout", "error": "Assessment exceeded the 180-second time limit."})
        except Exception as exc:
            with job_lock:
                scan_jobs[job_id].update({"status": "failed", "error": str(exc)[:700]})
        finally:
            with job_lock:
                if job_id in scan_jobs:
                    scan_jobs[job_id]["finished_at"] = time.time()
            scan_lock.release()

    def do_POST(self):
        origin = self.headers.get("Origin", "")
        if origin not in ALLOWED_ORIGINS:
            return self.send_json(403, {"error": "Origin not allowed."})
        request_path = urlparse(self.path).path
        if request_path == "/ollama/chat":
            if not self.authorised():
                return self.send_json(401, {"error": "Pairing token required."}, origin)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 2 or length > MAX_BODY:
                    raise ValueError("Request body is missing or too large.")
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError("Invalid chat request.")
                catalogue = ollama_request("/api/tags", timeout=5)
                installed = {str(item.get("name")) for item in catalogue.get("models", []) if isinstance(item, dict) and item.get("name")}
                payload = validate_ollama_chat(data, installed)
                result = ollama_request("/api/chat", payload, timeout=90)
                message = result.get("message", {})
                content = message.get("content", "") if isinstance(message, dict) else ""
                if not isinstance(content, str):
                    content = ""
                return self.send_json(200, {"model": payload["model"], "content": content[:12000], "done": bool(result.get("done", True)), "provider": "local Ollama"}, origin)
            except (ValueError, json.JSONDecodeError) as exc:
                return self.send_json(400, {"error": str(exc)}, origin)
            except RuntimeError as exc:
                return self.send_json(503, {"error": str(exc)}, origin)
        if request_path != "/scan":
            return self.send_json(404, {"error": "Not found."}, origin)
        if not self.authorised():
            return self.send_json(401, {"error": "Invalid pairing token."}, origin)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > MAX_BODY:
                raise ValueError("Request body is missing or too large.")
            data = json.loads(self.rfile.read(length))
            target = valid_target(str(data.get("target", "")))
            confirmation = str(data.get("confirmationTarget", "")).strip().lower().rstrip(".")
            reference = str(data.get("authorizationReference", "")).strip()
            if data.get("authorizationConfirmed") is not True or confirmation != str(data.get("target", "")).strip().lower().rstrip(".") or not reference or len(reference) > 160:
                raise ValueError("Confirm ownership or written permission, provide an approval reference and retype the exact target.")
            profile = str(data.get("profile", "custom")).lower()
            ports = resolve_scan_ports(profile, data.get("ports", []))
            if not shutil.which("nmap"):
                return self.send_json(503, {"error": "Nmap is not installed. Install it with: sudo apt install nmap"}, origin)
            if not scan_lock.acquire(blocking=False):
                return self.send_json(409, {"error": "A local assessment is already running."}, origin)
            job_id = secrets.token_urlsafe(24)
            now = time.time()
            with job_lock:
                expired = [key for key, value in scan_jobs.items() if now - value["created_at"] > JOB_TTL_SECONDS]
                for key in expired:
                    scan_jobs.pop(key, None)
                if len(scan_jobs) >= MAX_RETAINED_JOBS:
                    oldest = sorted(scan_jobs, key=lambda key: scan_jobs[key]["created_at"])[0]
                    if scan_jobs[oldest]["status"] in {"queued", "running"}:
                        scan_lock.release()
                        return self.send_json(503, {"error": "Local scan history is full. Wait for the active job to finish."}, origin)
                    scan_jobs.pop(oldest, None)
                scan_jobs[job_id] = {"job_id": job_id, "status": "queued", "target": target, "profile": profile, "created_at": now}
            with job_lock:
                scan_jobs[job_id]["status"] = "running"
            worker = threading.Thread(target=self.run_scan_job, args=(job_id, target, ports, profile), daemon=True)
            try:
                worker.start()
            except Exception:
                with job_lock:
                    scan_jobs[job_id].update({"status": "failed", "error": "Could not start the local scan worker."})
                scan_lock.release()
                raise
            return self.send_json(202, {"job_id": job_id, "status": "running", "target": target, "profile": profile, "poll": "/scan/" + job_id}, origin)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json(400, {"error": str(exc)}, origin)
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
