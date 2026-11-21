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
from typing import Any

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


def dispatch(action: str, payload: dict) -> dict:
    routes = {
        "kali.health": ("GET", "/health"),
        "kali.tools.inventory": ("GET", "/tools"),
        "kali.ollama.models": ("GET", "/ollama/models"),
    }
    if action in routes:
        method, path = routes[action]
        return request_json(BRIDGE_URL + path, BRIDGE_TOKEN, method, timeout=15, origin=BRIDGE_ORIGIN)
    if action == "kali.tool.run":
        required = {"tool", "parameters", "confirmRun", "authorizationReference", "targetConfirmation", "timeoutSeconds"}
        if set(payload) != required or payload.get("confirmRun") is not True:
            raise ValueError("Malformed or unapproved tool-run job.")
        if not payload.get("authorizationReference") or payload["authorizationReference"] != payload.get("authorizationReference"):
            raise ValueError("Missing authorisation reference.")
        timeout = min(130, max(5, int(payload["timeoutSeconds"]) + 5))
        return request_json(BRIDGE_URL + "/tools/run", BRIDGE_TOKEN, "POST", payload,
                            timeout=timeout, origin=BRIDGE_ORIGIN)
    raise ValueError("Unsupported Kali relay action.")


def main() -> int:
    if not RELAY_URL.startswith("https://"):
        print("CYBERLAB_RELAY_URL must use HTTPS.", file=sys.stderr)
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
                result = dispatch(action, job.get("payload") or {})
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
