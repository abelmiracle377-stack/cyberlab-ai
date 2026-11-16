"""Bounded, consent-gated passive packet capture for the local CyberLab companion.

Only fixed tcpdump filters are accepted. Packet payloads are never returned to the
web dashboard or model; a short-snaplen PCAP is retained locally as evidence.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

CAPTURE_DIR = Path.home() / ".local" / "share" / "cyberlab" / "captures"
MAX_DURATION_SECONDS = 30
MAX_PACKETS = 2000
SNAPLEN_BYTES = 96
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")

# Deliberately fixed filters: no caller-supplied BPF expressions.
CAPTURE_FILTERS = {
    "ssh": "tcp port 22",
    "dns": "port 53",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp or icmp6",
}


def list_capture_interfaces() -> dict:
    """List local interface names only; do not expose MAC or address details."""
    items = []
    for index, name in socket.if_nameindex():
        if not INTERFACE_RE.fullmatch(name):
            continue
        state_path = Path("/sys/class/net") / name / "operstate"
        try:
            state = state_path.read_text(encoding="ascii").strip()
        except OSError:
            state = "unknown"
        items.append({
            "index": int(index),
            "name": name,
            "state": state,
            "loopback": name == "lo",
        })
    return {"status": "ok", "interfaces": items, "count": len(items)}


def _validate_capture_request(
    interface: str,
    confirmation_interface: str,
    authorization_confirmed: bool,
    authorization_reference: str,
    duration_seconds: int,
    packet_limit: int,
    filter_name: str,
) -> tuple[str, int, int, str]:
    if not isinstance(interface, str) or not INTERFACE_RE.fullmatch(interface):
        raise ValueError("Select a valid local network interface.")
    available = {name for _, name in socket.if_nameindex()}
    if interface not in available:
        raise ValueError("The selected interface is not present on this workstation.")
    if not isinstance(confirmation_interface, str) or confirmation_interface != interface:
        raise ValueError("Retype the exact interface name to confirm the capture scope.")
    if authorization_confirmed is not True:
        raise ValueError("Confirm that you own or are authorised to monitor this network.")
    if not isinstance(authorization_reference, str) or not authorization_reference.strip() or len(authorization_reference) > 160:
        raise ValueError("Provide an authorisation or lab reference (maximum 160 characters).")
    if type(duration_seconds) is not int or not 1 <= duration_seconds <= MAX_DURATION_SECONDS:
        raise ValueError("Capture duration must be between 1 and 30 seconds.")
    if type(packet_limit) is not int or not 1 <= packet_limit <= MAX_PACKETS:
        raise ValueError("Packet limit must be between 1 and 2,000.")
    if filter_name not in CAPTURE_FILTERS:
        raise ValueError("Choose one of the supported filters: ssh, dns, tcp, udp or icmp.")
    return interface, duration_seconds, packet_limit, filter_name


def _summarise_pcap(pcap_path: Path, packet_limit: int) -> dict:
    """Use tcpdump's text dissection; never return packet payloads."""
    command = [
        shutil.which("tcpdump") or "tcpdump",
        "-nn", "-tttt", "-r", str(pcap_path), "-c", str(packet_limit),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    if result.returncode not in (0, 1):
        return {"analysis_status": "unavailable", "packet_count": 0, "protocol_counts": {}, "ssh_packet_count": 0}
    protocol_counts: Counter[str] = Counter()
    endpoints: Counter[str] = Counter()
    ssh_packets = 0
    packet_count = 0
    endpoint_pattern = re.compile(r"(?:IP|IP6)\s+(.+?)\s+>\s+(.+?):\s+(.*)$")
    for line in result.stdout.splitlines()[:packet_limit]:
        match = endpoint_pattern.search(line)
        if not match:
            continue
        source, destination, detail = match.groups()
        packet_count += 1
        endpoints[source[:100]] += 1
        endpoints[destination[:100]] += 1
        combined = source + " " + destination
        if re.search(r"(?:\.22|:22)(?:\s|$)", combined):
            protocol_counts["ssh"] += 1
            ssh_packets += 1
        elif re.search(r"(?:\.53|:53)(?:\s|$)", combined):
            protocol_counts["dns"] += 1
        elif "ICMP" in detail.upper():
            protocol_counts["icmp"] += 1
        elif "UDP" in detail.upper() or " UDP" in line:
            protocol_counts["udp"] += 1
        else:
            protocol_counts["tcp"] += 1
    return {
        "analysis_status": "completed",
        "packet_count": packet_count,
        "protocol_counts": dict(protocol_counts),
        "ssh_packet_count": ssh_packets,
        "top_endpoints": [{"endpoint": value, "packets": count} for value, count in endpoints.most_common(20)],
    }


def capture_packets(
    interface: str,
    confirmation_interface: str,
    authorization_confirmed: bool,
    authorization_reference: str,
    duration_seconds: int = 10,
    packet_limit: int = 500,
    filter_name: str = "ssh",
) -> dict:
    """Capture a short, bounded packet sample on one explicitly confirmed interface."""
    interface, duration_seconds, packet_limit, filter_name = _validate_capture_request(
        interface, confirmation_interface, authorization_confirmed,
        authorization_reference, duration_seconds, packet_limit, filter_name,
    )
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        return {"status": "unavailable", "error": "tcpdump is not installed on the paired workstation."}

    CAPTURE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(CAPTURE_DIR, 0o700)
    except OSError:
        pass
    capture_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(5)
    pcap_path = CAPTURE_DIR / (capture_id + ".pcap")
    command = [
        tcpdump, "-i", interface, "-nn", "-s", str(SNAPLEN_BYTES),
        "-c", str(packet_limit), "-w", str(pcap_path), CAPTURE_FILTERS[filter_name],
    ]
    started = time.monotonic()
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        deadline = started + duration_seconds
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            _stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            _stdout, stderr = process.communicate(timeout=2)
    except (OSError, subprocess.SubprocessError) as exc:
        try:
            pcap_path.unlink(missing_ok=True)
        except OSError:
            pass
        return {"status": "capture_failed", "error": str(exc)[:240]}

    if not pcap_path.is_file():
        detail = (stderr or "").strip()
        return {
            "status": "capture_failed",
            "error": "tcpdump did not produce a capture file. Check interface permissions and capture capabilities.",
            "detail": detail[:240],
        }
    try:
        os.chmod(pcap_path, 0o600)
        size_bytes = pcap_path.stat().st_size
        digest = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    except OSError as exc:
        return {"status": "capture_failed", "error": "Could not secure or read the local capture file: " + str(exc)[:180]}

    summary = _summarise_pcap(pcap_path, packet_limit)
    return {
        "status": "completed",
        "capture_id": capture_id,
        "interface": interface,
        "filter": filter_name,
        "duration_seconds": round(time.monotonic() - started, 2),
        "packet_limit": packet_limit,
        "snaplen_bytes": SNAPLEN_BYTES,
        "file_name": pcap_path.name,
        "local_file": str(pcap_path),
        "file_size_bytes": size_bytes,
        "sha256": digest,
        "authorization_reference": authorization_reference.strip(),
        "payload_exported": False,
        **summary,
        "note": "Passive capture only. Packet payloads are not returned to CyberLab or the AI. The local PCAP is owner-only and may contain sensitive network metadata; retain and share it only under the engagement's evidence-handling rules. SSH application data remains encrypted.",
    }
