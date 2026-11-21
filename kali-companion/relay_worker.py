#!/usr/bin/env python3
"""Outbound-only CyberLab relay worker for the paired Kali companion.

Only fixed typed actions are dispatched to the existing loopback bridge.
No job can provide a shell command, executable path, or arbitrary HTTP endpoint.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
import urllib.error
from urllib.parse import urlsplit, urlsplit as parse_url

RELAY_URL = os.environ.get("CYBERLAB_RELAY_URL", "").rstrip("/")
DEVICE_TOKEN = os.environ.get("CYBERLAB_DEVICE_TOKEN", "")
BRIDGE_TOKEN = os.environ.get("CYBERLAB_BRIDGE_TOKEN", "")
BRIDGE_URL = os.environ.get("CYBERLAB_BRIDGE_URL", "http://127.0.0.1:8765").rstrip("/")
POLL_SECONDS = max(2, min(30, int(os.environ.get("CYBERLAB_RELAY_POLL_SECONDS", "4"))))
MAX_RESPONSE = 65536
BRIDGE_ORIGIN = "https://cyberlab-ai.vercel.app"


def request_json(url: str, token: str, method: str = "GET", payload: dict | None = None,
                 timeout: int = 20, origin: str | None = None) -> dict:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if origin:
        headers["Origin"] = origin
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        raw = exc.read(4096).decode("utf-8", "replace")
        raise RuntimeError(f"HTTP {exc.code}: {raw[:1000]}") from exc
    if len(raw) > MAX_RESPONSE:
        raise RuntimeError("Remote response exceeded the 64 KB limit.")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Remote service returned invalid JSON.") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Remote service returned an unexpected response.")
    return value


def bridge_request(method: str, path: str, body: dict | None = None) -> dict:
    parsed = parse_url(path)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/") or ".." in parsed.path.split("/"):
        raise ValueError("Invalid local bridge path.")
    get_paths = {
        "/", "/health", "/system", "/identity", "/capabilities", "/ollama/health", "/ollama/models",
        "/solidity/compiler", "/solidity/tests/status", "/wallet/status", "/tools/runners",
        "/telemetry/security", "/telemetry/system", "/forensics/devices", "/tools", "/burp/status",
        "/burp/extension/status", "/burp/scanner/tasks", "/burp/site-map",
        "/network/interfaces", "/academy/lab/status", "/wifi/interfaces", 
        "/proxy/ca/status", "/proxy/ca/certificate", "/proxy/status", 
        
        "/evidence/case/ledger/verify",
    }
    post_paths = {
        "/plan", "/research", "/services",   
          "/scan",  
         "/forensics/inspect", "/forensics/partitions", "/forensics/fsstat",
           
          
          
         "/web/crawl",  
        "/web/parameters/inspect", "/web/parameters/generate",  "/proxy/ca/create",
        
        "/ollama/chat", "/solidity/compile", "/solidity/project/compile",
        "/solidity/tests/run", "/wallet/recovery-assess", 
        
         
           
        "/academy/lab/start", "/academy/lab/stop",   
         "/wifi/scan", "/wifi/audit", "/wifi/monitor/start", "/wifi/monitor/stop",
        "/wifi/deauth", "/wifi/wps",
        "/wifi/auto", "/tools/run", "/ssh/audit",
    }
    allowed = parsed.path in (get_paths if method == "GET" else post_paths)
    if parsed.path.startswith("/forensics/jobs/") and method == "GET":
        import re
        allowed = bool(re.fullmatch(r"/forensics/jobs/[a-f0-9]{32}", parsed.path))
    if not allowed:
        raise ValueError("Kali bridge route is not in the worker allowlist.")
    if parsed.query:
        from urllib.parse import parse_qs
        query = parse_qs(parsed.query)
        if set(query) != {"limit"} or len(query["limit"]) != 1 or not query["limit"][0].isdigit():
            raise ValueError("Unsupported bridge query parameters.")
    encoded = json.dumps(body).encode("utf-8") if body is not None else None
    if encoded is not None and len(encoded) > 32768:
        raise ValueError("Bridge request body exceeds 32 KB.")
    headers = {"Authorization": "Bearer " + BRIDGE_TOKEN, "Accept": "application/json", "Origin": BRIDGE_ORIGIN}
    if encoded is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BRIDGE_URL + path, data=encoded, headers=headers, method=method)
    timeout = 150 if parsed.path in {"/scan", "/wifi/scan", "/wifi/audit",     "/soc/run-cycle"} else 25
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, raw = response.status, response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise RuntimeError("Kali bridge response exceeded 64 KB.")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Kali bridge returned a non-JSON response.") from exc
    if not isinstance(result, dict):
        raise RuntimeError("Kali bridge returned an unexpected response.")
    return {"bridge_status": status, "bridge_body": result}


def dispatch(action: str, payload: dict, approval_reference: str) -> dict:
    routes = {
        "kali.health": ("GET", "/health"),
        "kali.tools.inventory": ("GET", "/tools"),
        "kali.ollama.models": ("GET", "/ollama/models"),
    }
    if action in routes:
        method, path = routes[action]
        return request_json(BRIDGE_URL + path, BRIDGE_TOKEN, method, timeout=15, origin=BRIDGE_ORIGIN)
    if action == "kali.bridge.request":
        if set(payload) - {"method", "path", "body"} or not {"method", "path"} <= set(payload):
            raise ValueError("Malformed remote bridge request.")
        return bridge_request(payload["method"], payload["path"], payload.get("body"))
    if action == "kali.ollama.chat":
        if set(payload) != {"model", "prompt"}:
            raise ValueError("Malformed local Ollama chat job.")
        return request_json(BRIDGE_URL + "/ollama/chat", BRIDGE_TOKEN, "POST", payload,
                            timeout=90, origin=BRIDGE_ORIGIN)
    if action == "kali.tool.run":
        required = {"tool", "parameters", "confirmRun", "authorizationReference", "targetConfirmation", "timeoutSeconds"}
        if set(payload) != required or payload.get("confirmRun") is not True:
            raise ValueError("Malformed or unapproved tool-run job.")
        if not approval_reference or payload.get("authorizationReference") != approval_reference:
            raise ValueError("Missing authorisation reference.")
        timeout = min(130, max(5, int(payload["timeoutSeconds"]) + 5))
        return request_json(BRIDGE_URL + "/tools/run", BRIDGE_TOKEN, "POST", payload,
                            timeout=timeout, origin=BRIDGE_ORIGIN)
    raise ValueError("Unsupported Kali relay action.")


def main() -> int:
    relay = urlsplit(RELAY_URL)
    bridge = urlsplit(BRIDGE_URL)
    if relay.scheme != "https" or not relay.hostname or relay.username or relay.password:
        print("CYBERLAB_RELAY_URL must be an HTTPS URL without embedded credentials.", file=sys.stderr)
        return 2
    if bridge.scheme != "http" or bridge.hostname not in {"127.0.0.1", "localhost", "::1"} or bridge.username or bridge.password:
        print("CYBERLAB_BRIDGE_URL must point to the local loopback bridge only.", file=sys.stderr)
        return 2
    if len(DEVICE_TOKEN) < 32 or len(BRIDGE_TOKEN) < 40:
        print("Set CYBERLAB_DEVICE_TOKEN and CYBERLAB_BRIDGE_TOKEN securely.", file=sys.stderr)
        return 2
    print("CyberLab Kali relay worker started; outbound HTTPS polling only.")
    while True:
        try:
            response = request_json(RELAY_URL + "/v1/jobs/next", DEVICE_TOKEN, timeout=20)
            job = response.get("job")
            if not job:
                time.sleep(POLL_SECONDS)
                continue
            job_id = job.get("job_id")
            lease = job.get("lease_token")
            action = job.get("action")
            try:
                result = dispatch(action, job.get("payload") or {}, job.get("approval_reference", ""))
                submission = {"lease_token": lease, "status": "completed", "result": result, "error": ""}
            except Exception as exc:
                submission = {"lease_token": lease, "status": "failed", "result": {}, "error": str(exc)[:1000]}
            request_json(RELAY_URL + "/v1/jobs/" + str(job_id) + "/result", DEVICE_TOKEN,
                         "POST", submission, timeout=20)
            print("Job " + str(job_id) + " -> " + submission["status"] + " (" + str(action) + ")")
        except KeyboardInterrupt:
            print("\nStopping relay worker.")
            return 0
        except Exception as exc:
            print("Relay polling error: " + str(exc)[:500], file=sys.stderr)
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
