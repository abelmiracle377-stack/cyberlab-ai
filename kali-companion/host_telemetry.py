"""Read-only SOC host telemetry for the paired companion.

Collects host-defence signals a local analyst needs — listening sockets and
logged-in users — in addition to the privacy-scoped health summary in
system_snapshot(). Everything here reads the local host only, runs fixed
read-only commands (no shell), and returns bounded, structured results. It
never connects to a target, modifies the host, or collects file contents or
network payloads.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time

MAX_ROWS = 500


def parse_ss_listening(output: str) -> list[dict]:
    """Parse `ss -tulnH` rows into structured listening-socket entries."""
    entries = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        netid, state, local = parts[0], parts[1], parts[4]
        if state.upper() not in {"LISTEN", "UNCONN"}:
            continue
        # Local address is host:port; host may be IPv6 in brackets.
        match = re.match(r"^(.*):(\d{1,5})$", local)
        if not match:
            continue
        address, port = match.group(1), int(match.group(2))
        if not 0 <= port <= 65535:
            continue
        entries.append({
            "protocol": netid.lower(),
            "address": address.strip("[]"),
            "port": port,
            "listening": state.upper() == "LISTEN",
        })
        if len(entries) >= MAX_ROWS:
            break
    return entries


def parse_who(output: str) -> list[dict]:
    """Parse `who` rows into structured logged-in-user entries."""
    sessions = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        remote = ""
        match = re.search(r"\(([^)]*)\)\s*$", line)
        if match:
            remote = match.group(1)
        sessions.append({
            "user": parts[0][:64],
            "tty": parts[1][:32],
            "since": " ".join(parts[2:4])[:40] if len(parts) >= 4 else "",
            "remote": remote[:80],
        })
        if len(sessions) >= MAX_ROWS:
            break
    return sessions


def collect_security_telemetry(runner=subprocess.run, which=shutil.which) -> dict:
    """Collect listening sockets and logged-in users. Fails soft per-signal."""
    listening = []
    listening_available = bool(which("ss"))
    if listening_available:
        try:
            result = runner(["ss", "-tulnH"], capture_output=True, text=True, timeout=10, check=False)
            listening = parse_ss_listening(result.stdout or "")
        except (subprocess.TimeoutExpired, OSError):
            listening_available = False

    sessions = []
    who_available = bool(which("who"))
    if who_available:
        try:
            result = runner(["who"], capture_output=True, text=True, timeout=10, check=False)
            sessions = parse_who(result.stdout or "")
        except (subprocess.TimeoutExpired, OSError):
            who_available = False

    exposed = sorted({e["port"] for e in listening if e["listening"]})
    return {
        "listening_sockets": listening,
        "listening_count": len(listening),
        "exposed_ports": exposed,
        "logged_in_users": sessions,
        "session_count": len(sessions),
        "tools": {"ss": listening_available, "who": who_available},
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": "Read-only local host-defence telemetry: listening sockets and interactive sessions. No file contents, process command lines or network payloads are collected, and no target is contacted.",
    }
