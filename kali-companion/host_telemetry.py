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


def parse_meminfo(text: str) -> dict:
    info = {}
    for line in text.splitlines():
        match = re.match(r"^(\w+):\s+(\d+)\s*kB", line)
        if match:
            info[match.group(1)] = int(match.group(2)) * 1024
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    used = max(total - available, 0)
    return {"total_bytes": total, "available_bytes": available, "used_bytes": used,
            "used_percent": round(100 * used / total, 1) if total else 0.0}


def parse_uptime_seconds(text: str) -> float:
    try:
        return float(text.split()[0])
    except (IndexError, ValueError):
        return 0.0


def parse_loadavg(text: str) -> dict:
    parts = text.split()
    try:
        return {"1m": float(parts[0]), "5m": float(parts[1]), "15m": float(parts[2])}
    except (IndexError, ValueError):
        return {"1m": 0.0, "5m": 0.0, "15m": 0.0}


def parse_os_release(text: str) -> dict:
    values = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, raw = line.partition("=")
            values[key.strip()] = raw.strip().strip('"').strip("'")
    return {"name": values.get("NAME", "")[:80], "version": values.get("VERSION_ID", "")[:40],
            "id": values.get("ID", "")[:40]}


def parse_df(output: str) -> list[dict]:
    rows = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            size, used, avail = int(parts[1]), int(parts[2]), int(parts[3])
        except ValueError:
            continue
        rows.append({"filesystem": parts[0][:80], "mount": parts[5][:120],
                     "size_bytes": size, "used_bytes": used, "available_bytes": avail,
                     "used_percent": round(100 * used / size, 1) if size else 0.0})
        if len(rows) >= MAX_ROWS:
            break
    return rows


_IP_TOKEN = re.compile(r"\A(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,}|[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\Z")


def parse_last(output: str, limit: int = 25) -> list[dict]:
    """Parse `last`/`lastb` rows into {user, tty, from} entries (source IP if present)."""
    rows = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("wtmp", "btmp")):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        source = ""
        if len(parts) >= 3 and _IP_TOKEN.match(parts[2]):
            source = parts[2][:80]
        rows.append({"user": parts[0][:64], "tty": parts[1][:32], "from": source})
        if len(rows) >= limit:
            break
    return rows


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(1024 * 1024)
    except OSError:
        return ""


def collect_system_telemetry(runner=subprocess.run, which=shutil.which, read_file=_read_text) -> dict:
    """Read-only system posture: OS, uptime, load, memory, disk, recent/failed logins."""
    memory = parse_meminfo(read_file("/proc/meminfo"))
    uptime_seconds = parse_uptime_seconds(read_file("/proc/uptime"))
    load = parse_loadavg(read_file("/proc/loadavg"))
    os_release = parse_os_release(read_file("/etc/os-release"))
    kernel = read_file("/proc/sys/kernel/osrelease").strip()[:80]

    disks = []
    if which("df"):
        try:
            result = runner(["df", "-P", "-B1", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay"],
                            capture_output=True, text=True, timeout=10, check=False)
            disks = parse_df(result.stdout or "")
        except (subprocess.TimeoutExpired, OSError):
            disks = []

    recent_logins = []
    last_available = bool(which("last"))
    if last_available:
        try:
            result = runner(["last", "-w", "-n", "25"], capture_output=True, text=True, timeout=10, check=False)
            recent_logins = parse_last(result.stdout or "")
        except (subprocess.TimeoutExpired, OSError):
            last_available = False

    failed_logins = []
    failed_available = bool(which("lastb"))
    failed_needs_root = False
    if failed_available:
        try:
            result = runner(["lastb", "-w", "-n", "25"], capture_output=True, text=True, timeout=10, check=False)
            if result.returncode != 0 and not (result.stdout or "").strip():
                failed_needs_root = True
            else:
                failed_logins = parse_last(result.stdout or "")
        except (subprocess.TimeoutExpired, OSError):
            failed_available = False

    return {
        "os": os_release, "kernel": kernel,
        "uptime_seconds": int(uptime_seconds),
        "load_average": load, "memory": memory,
        "disks": disks, "disk_count": len(disks),
        "recent_logins": recent_logins, "recent_login_count": len(recent_logins),
        "failed_logins": failed_logins, "failed_login_count": len(failed_logins),
        "sources": {"df": bool(disks) or bool(which("df")), "last": last_available,
                    "lastb": failed_available and not failed_needs_root},
        "failed_logins_need_root": failed_needs_root,
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": "Read-only local system posture. No file contents, process command lines or network payloads are collected, and no target is contacted.",
    }


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
