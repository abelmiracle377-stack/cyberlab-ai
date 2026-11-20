"""Read-only packet-capture analysis with tshark (Wireshark's CLI).

Wireshark's GUI is not run on the companion; tshark provides the same dissection
engine headlessly. This reads an existing .pcap/.pcapng file (never a live
interface here — live capture goes through the consent-gated network_capture
module) and returns a protocol hierarchy and top IP conversations. Fixed
read-only tshark invocations, no shell, bounded output; fails closed if tshark
is absent.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

MAX_PCAP_BYTES = 512 * 1024 * 1024


def _validate_pcap(path_value: str) -> Path:
    path = Path(str(path_value or "").strip()).expanduser()
    if path.is_symlink():
        raise ValueError("The capture path must not be a symlink.")
    if not path.is_file():
        raise ValueError("Capture file not found: " + str(path))
    if path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise ValueError("Capture must be a .pcap, .pcapng or .cap file.")
    size = path.stat().st_size
    if size == 0 or size > MAX_PCAP_BYTES:
        raise ValueError("Capture file is empty or larger than the 512 MB limit.")
    return path


_PHS_ROW = re.compile(r"^(?P<indent>\s*)(?P<proto>[A-Za-z0-9_.\-]+)\s+frames:(?P<frames>\d+)\s+bytes:(?P<bytes>\d+)")


def parse_protocol_hierarchy(output: str) -> list[dict]:
    """Parse `tshark -z io,phs` protocol hierarchy rows into a flat, depth-tagged list."""
    rows = []
    for line in output.splitlines():
        match = _PHS_ROW.match(line)
        if not match:
            continue
        rows.append({
            "protocol": match.group("proto"),
            "depth": len(match.group("indent")) // 2,
            "frames": int(match.group("frames")),
            "bytes": int(match.group("bytes")),
        })
    return rows


_CONV_ROW = re.compile(r"^(?P<a>[0-9a-fA-F:.]+)\s+<->\s+(?P<b>[0-9a-fA-F:.]+)\s+(?P<nums>[\d\s.]+)$")


def parse_ip_conversations(output: str, limit: int = 50) -> list[dict]:
    """Parse `tshark -z conv,ip` rows into conversation pairs with total frames/bytes."""
    conversations = []
    for line in output.splitlines():
        match = _CONV_ROW.match(line.strip())
        if not match:
            continue
        numbers = match.group("nums").split()
        # Columns: <- frames, <- bytes, -> frames, -> bytes, total frames, total bytes, [start, duration]
        if len(numbers) < 6:
            continue
        try:
            total_frames = int(numbers[4])
            total_bytes = int(numbers[5])
        except ValueError:
            continue
        conversations.append({
            "endpointA": match.group("a"), "endpointB": match.group("b"),
            "frames": total_frames, "bytes": total_bytes,
        })
        if len(conversations) >= limit:
            break
    conversations.sort(key=lambda item: item["bytes"], reverse=True)
    return conversations


def analyze_pcap(pcap_path: str, runner=subprocess.run, which=shutil.which) -> dict:
    """Produce a protocol hierarchy and top IP conversations from a capture file."""
    path = _validate_pcap(pcap_path)
    executable = which("tshark")
    if not executable:
        raise ValueError("tshark (Wireshark CLI) is not installed. Install it with: "
                         "sudo apt install -y tshark")
    phs = runner([executable, "-r", str(path), "-q", "-z", "io,phs"],
                 capture_output=True, text=True, timeout=120, check=False)
    conv = runner([executable, "-r", str(path), "-q", "-z", "conv,ip"],
                  capture_output=True, text=True, timeout=120, check=False)
    hierarchy = parse_protocol_hierarchy(phs.stdout or "")
    conversations = parse_ip_conversations(conv.stdout or "")
    total_frames = max((row["frames"] for row in hierarchy if row["depth"] == 0), default=0)
    return {
        "file": str(path),
        "protocol_hierarchy": hierarchy,
        "conversations": conversations,
        "total_frames": total_frames,
        "conversation_count": len(conversations),
        "method": "tshark read-only capture analysis (io,phs and conv,ip)",
        "note": "Read-only analysis of an existing capture with Wireshark's tshark engine. No live interface was opened and the file was not modified.",
    }
