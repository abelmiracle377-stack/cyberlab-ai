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
from urllib.parse import urlparse, parse_qs

from forensics import get_image_job, inspect_image_filesystem, inspect_image_partitions, list_block_devices, start_foremost_recovery, start_image_acquisition
from filesystem_analysis import inspect_partition_filesystem
from tool_catalog import inspect_tool_catalog
from burp_connector import inspect_burp_status, inspect_burp_proxy_history, inspect_burp_site_map, inspect_burp_issues, open_burp_history_in_repeater
from network_capture import list_capture_interfaces, capture_packets
from web_testing import execute_request, request_history
from web_crawler import run_crawl
from web_active_scan import run_active_scan
from proxy_certificates import ca_status, create_local_ca
from intercept_proxy import PROXY, proxy_history
from task_planner import plan_task
from research_workflows import run_research_action
from service_enumeration import enumerate_services
from evidence_analysis import build_service_report, validate_report_payload
from artifact_analysis import build_artifact_report, validate_artifact_payload
from case_management import build_case_report, validate_case_payload, verify_audit_ledger
from case_export import export_case_bundle, verify_case_archive

HOST = "127.0.0.1"
PORT = 8765
MAX_BODY = 8192
MAX_PORTS = 100
MAX_RUNTIME = 55
ALLOWED_ORIGINS = {"https://cyberlab-ai.vercel.app", "http://localhost:3000", "http://127.0.0.1:3000"} | {origin.strip().rstrip("/") for origin in os.environ.get("CYBERLAB_ALLOWED_ORIGINS", "").split(",") if origin.strip()}
CONFIG_DIR = Path.home() / ".config" / "cyberlab"
TOKEN_FILE = CONFIG_DIR / "bridge-token"
scan_lock = threading.Lock()
research_lock = threading.Lock()
service_lock = threading.Lock()
evidence_lock = threading.Lock()
artifact_lock = threading.Lock()
case_lock = threading.Lock()
case_export_lock = threading.Lock()
network_capture_lock = threading.Lock()
web_request_lock = threading.Lock()
web_crawl_lock = threading.Lock()
web_active_scan_lock = threading.Lock()
proxy_ca_lock = threading.Lock()
proxy_control_lock = threading.Lock()


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
        "tcpdump_available": bool(shutil.which("tcpdump")),
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
        if not (path in {"/health", "/system", "/forensics/devices", "/tools", "/burp/status", "/burp/proxy/history", "/burp/site-map", "/burp/issues", "/network/interfaces", "/web/history", "/proxy/ca/status", "/proxy/status", "/proxy/history", "/evidence/case/ledger/verify"} or re.fullmatch(r"/forensics/jobs/[a-f0-9]{32}", path)):
            return self.send_json(404, {"error": "Not found."}, origin)
        if not self.authorised():
            return self.send_json(401, {"error": "Pairing token required."}, origin)
        if path == "/tools":
            return self.send_json(200, inspect_tool_catalog(), origin)
        if path == "/proxy/ca/status":
            return self.send_json(200, ca_status(), origin)
        if path == "/proxy/status":
            return self.send_json(200, PROXY.status(), origin)
        if path == "/proxy/history":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["50"])[0])
            except (TypeError, ValueError):
                limit = 50
            return self.send_json(200, proxy_history(limit), origin)
        if path == "/network/interfaces":
            return self.send_json(200, list_capture_interfaces(), origin)
        if path == "/web/history":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["20"])[0])
            except (TypeError, ValueError):
                limit = 20
            return self.send_json(200, request_history(limit), origin)
        if path == "/burp/status":
            return self.send_json(200, inspect_burp_status(), origin)
        if path == "/burp/proxy/history":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["50"])[0])
            except (TypeError, ValueError):
                limit = 50
            return self.send_json(200, inspect_burp_proxy_history(limit), origin)
        if path == "/burp/site-map":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["50"])[0])
            except (TypeError, ValueError):
                limit = 50
            return self.send_json(200, inspect_burp_site_map(limit), origin)
        if path == "/burp/issues":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["50"])[0])
            except (TypeError, ValueError):
                limit = 50
            return self.send_json(200, inspect_burp_issues(limit), origin)
        if path == "/evidence/case/ledger/verify":
            return self.send_json(200, verify_audit_ledger(), origin)
        if path == "/forensics/devices":
            try:
                return self.send_json(200, list_block_devices(), origin)
            except (ValueError, OSError, json.JSONDecodeError) as exc:
                return self.send_json(400, {"error": str(exc)}, origin)
        if path.startswith("/forensics/jobs/"):
            job = get_image_job(path.rsplit("/", 1)[-1])
            return self.send_json(200 if job else 404, job or {"error": "Unknown or expired acquisition job."}, origin)
        if path == "/system":
            return self.send_json(200, {"status": "ok", "metrics": system_snapshot()}, origin)
        self.send_json(200, {"status": "connected", "agent": "CyberLab Kali Bridge", "nmap": bool(shutil.which("nmap"))}, origin)

    def do_POST(self):
        origin = self.headers.get("Origin", "")
        if origin not in ALLOWED_ORIGINS:
            return self.send_json(403, {"error": "Origin not allowed."})
        path = urlparse(self.path).path
        if path not in {"/plan", "/research", "/services", "/evidence/report", "/evidence/artifacts", "/evidence/case", "/evidence/case/export", "/evidence/case/verify", "/scan", "/forensics/image", "/forensics/foremost", "/forensics/inspect", "/forensics/partitions", "/forensics/fsstat", "/burp/repeater/from-history", "/network/capture", "/web/request", "/web/crawl", "/web/active-scan", "/proxy/ca/create", "/proxy/start", "/proxy/stop"}:
            return self.send_json(404, {"error": "Not found."}, origin)
        if not self.authorised():
            return self.send_json(401, {"error": "Invalid pairing token."}, origin)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body_limit = 600000 if path == "/evidence/case/export" else (8192 if path == "/evidence/case/verify" else (131072 if path == "/evidence/case" else (65536 if path in {"/evidence/report", "/evidence/artifacts"} else (32768 if path in {"/web/request", "/web/crawl", "/web/active-scan"} else MAX_BODY))))
            if length < 2 or length > body_limit:
                raise ValueError("Request body is missing or too large.")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object.")
            if path == "/proxy/start":
                if not proxy_control_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A proxy control operation is already running."}, origin)
                try:
                    return self.send_json(201, PROXY.start(data), origin)
                finally:
                    proxy_control_lock.release()
            if path == "/proxy/stop":
                return self.send_json(200, PROXY.stop(), origin)
            if path == "/proxy/ca/create":
                if data.get("confirmCreateLocalCA") is not True:
                    return self.send_json(400, {"error": "Explicitly confirm creation of a local CA whose certificate must be manually trusted by the operator."}, origin)
                if not proxy_ca_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "Local inspection CA creation is already running."}, origin)
                try:
                    return self.send_json(201, create_local_ca(), origin)
                finally:
                    proxy_ca_lock.release()
            if path == "/web/active-scan":
                if not web_active_scan_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A native active web check is already running."}, origin)
                try:
                    result = run_active_scan(data)
                    return self.send_json(200, result, origin)
                finally:
                    web_active_scan_lock.release()
            if path == "/web/crawl":
                if not web_crawl_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A native web crawl is already running."}, origin)
                try:
                    result = run_crawl(data)
                    return self.send_json(200, result, origin)
                finally:
                    web_crawl_lock.release()
            if path == "/web/request":
                if not web_request_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A native HTTP request is already running."}, origin)
                try:
                    result = execute_request(data)
                    return self.send_json(200, result, origin)
                finally:
                    web_request_lock.release()
            if path == "/network/capture":
                if not network_capture_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A packet capture is already running."}, origin)
                try:
                    result = capture_packets(
                        interface=data.get("interface"),
                        confirmation_interface=data.get("confirmationInterface"),
                        authorization_confirmed=data.get("authorizationConfirmed") is True,
                        authorization_reference=data.get("authorizationReference"),
                        duration_seconds=data.get("durationSeconds", 10),
                        packet_limit=data.get("packetLimit", 500),
                        filter_name=data.get("filter", "ssh"),
                    )
                    status_code = 200 if result.get("status") == "completed" else (503 if result.get("status") == "unavailable" else 502)
                    return self.send_json(status_code, result, origin)
                finally:
                    network_capture_lock.release()
            if path == "/burp/repeater/from-history":
                if data.get("confirmOpenInRepeater") is not True:
                    return self.send_json(400, {"status": "confirmation_required", "request_sent": False}, origin)
                history_id = data.get("historyId")
                if isinstance(history_id, bool) or not isinstance(history_id, int):
                    return self.send_json(400, {"status": "invalid_request", "request_sent": False}, origin)
                result = open_burp_history_in_repeater(history_id, confirmed=True)
                status_code = 200 if result.get("status") == "opened_in_repeater" else 400
                return self.send_json(status_code, result, origin)
            if path == "/plan":
                return self.send_json(200, plan_task(data.get("prompt", "")), origin)
            if path == "/research":
                if not research_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A passive research request is already running."}, origin)
                try:
                    return self.send_json(200, run_research_action(data), origin)
                finally:
                    research_lock.release()
            if path == "/evidence/case/verify":
                return self.send_json(200, verify_case_archive(data.get("caseId")), origin)
            if path == "/evidence/case/export":
                case_report = data.get("caseReport")
                if not case_export_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A case export is already being written."}, origin)
                try:
                    return self.send_json(200, export_case_bundle(case_report), origin)
                finally:
                    case_export_lock.release()
            if path == "/evidence/case":
                service_evidence, artifact_evidence = validate_case_payload(data)
                if not case_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A case report is already being written."}, origin)
                try:
                    report = build_case_report(service_evidence, artifact_evidence)
                    return self.send_json(201, report, origin)
                finally:
                    case_lock.release()
            if path == "/evidence/artifacts":
                triage_evidence, recovery_evidence = validate_artifact_payload(data)
                if not artifact_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "An artifact analysis request is already running."}, origin)
                try:
                    report = build_artifact_report(triage_evidence, recovery_evidence)
                    return self.send_json(200, report, origin)
                finally:
                    artifact_lock.release()
            if path == "/evidence/report":
                scan_evidence, service_evidence = validate_report_payload(data)
                if not evidence_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "An evidence analysis request is already running."}, origin)
                try:
                    report = build_service_report(scan_evidence, service_evidence)
                    return self.send_json(200, report, origin)
                finally:
                    evidence_lock.release()
            if path == "/services":
                target_value = data.get("target")
                if not isinstance(target_value, str):
                    raise ValueError("Enter one IP address or hostname.")
                target = valid_target(target_value)
                confirmation = data.get("confirmationTarget")
                reference = data.get("authorizationReference")
                if (data.get("authorizationConfirmed") is not True or not isinstance(confirmation, str)
                        or confirmation.strip().lower().rstrip(".") != target_value.strip().lower().rstrip(".")
                        or not isinstance(reference, str) or not reference.strip() or len(reference) > 160):
                    raise ValueError("Confirm ownership or written permission, provide an approval reference and retype the exact target.")
                if not service_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A service-identification request is already running."}, origin)
                try:
                    result = enumerate_services(target, data.get("ports"))
                    return self.send_json(200, result, origin)
                finally:
                    service_lock.release()
            if path == "/forensics/fsstat":
                result = inspect_partition_filesystem(
                    str(data.get("imageJobId", "")),
                    str(data.get("confirmationImage", "")),
                    data.get("startSector"),
                )
                return self.send_json(200, result, origin)
            if path == "/forensics/partitions":
                result = inspect_image_partitions(
                    str(data.get("imageJobId", "")),
                    str(data.get("confirmationImage", "")),
                )
                return self.send_json(200, result, origin)
            if path == "/forensics/inspect":
                result = inspect_image_filesystem(
                    str(data.get("imageJobId", "")),
                    str(data.get("confirmationImage", "")),
                )
                return self.send_json(200, result, origin)
            if path == "/forensics/foremost":
                result = start_foremost_recovery(
                    str(data.get("imageJobId", "")),
                    str(data.get("outputDirectory", "")),
                    str(data.get("confirmationImage", "")),
                )
                return self.send_json(202, result, origin)
            if path == "/forensics/image":
                result = start_image_acquisition(
                    str(data.get("source", "")),
                    str(data.get("destinationDirectory", "")),
                    str(data.get("filename", "")),
                    str(data.get("confirmationSource", "")),
                )
                return self.send_json(202, result, origin)
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
