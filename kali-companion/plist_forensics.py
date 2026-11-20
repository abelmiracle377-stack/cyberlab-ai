"""Read-only Apple property-list (.plist) forensic parsing.

Parses binary or XML plists (browser/app preferences, macOS/iOS artefacts) into
a bounded, depth-limited structural summary. Uses only the Python standard
library (plistlib), never modifies the file, and truncates large values so a
huge plist cannot flood the caller. It does not execute anything embedded in a
plist; values are converted to safe JSON-friendly previews.
"""
from __future__ import annotations

import datetime
import plistlib
from pathlib import Path

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 8
MAX_KEYS = 200
MAX_ITEMS = 200
MAX_STRING = 512


def _preview(value, depth: int):
    """Convert a plist value into a bounded, JSON-safe preview."""
    if depth >= MAX_DEPTH:
        return {"_truncated": "max depth reached"}
    if isinstance(value, dict):
        out = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_KEYS:
                out["_truncated"] = "%d more keys" % (len(value) - MAX_KEYS)
                break
            out[str(key)[:MAX_STRING]] = _preview(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for index, item in enumerate(value):
            if index >= MAX_ITEMS:
                out.append({"_truncated": "%d more items" % (len(value) - MAX_ITEMS)})
                break
            out.append(_preview(item, depth + 1))
        return out
    if isinstance(value, bytes):
        return {"_type": "data", "length": len(value), "hex_prefix": value[:32].hex()}
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, datetime.datetime):
        return {"_type": "date", "value": value.isoformat()}
    text = str(value)
    if len(text) > MAX_STRING:
        return text[:MAX_STRING] + "…"
    return text


def _top_type(obj) -> str:
    if isinstance(obj, dict):
        return "dict"
    if isinstance(obj, (list, tuple)):
        return "array"
    return type(obj).__name__


def analyze_plist(path: str, reader=None) -> dict:
    """Parse a .plist file and return a bounded structural summary."""
    resolved = Path(path).expanduser()
    if resolved.is_symlink():
        raise ValueError("Plist path must not be a symlink.")
    if not resolved.is_file():
        raise ValueError("Plist file not found: " + str(resolved))
    size = resolved.stat().st_size
    if size == 0:
        raise ValueError("Plist file is empty.")
    if size > MAX_FILE_BYTES:
        raise ValueError("Plist file exceeds the 64 MiB limit.")

    raw = reader(str(resolved)) if reader else resolved.read_bytes()
    fmt = "binary" if raw[:8] == b"bplist00" else "xml"
    try:
        obj = plistlib.loads(raw)
    except Exception as exc:  # malformed plist -> reported, not raised to the caller as a crash
        raise ValueError("Could not parse the plist: " + str(exc)[:200]) from exc

    top_keys = sorted(str(k) for k in obj.keys())[:MAX_KEYS] if isinstance(obj, dict) else []
    return {
        "file": str(resolved), "format": fmt, "size_bytes": size,
        "top_level_type": _top_type(obj),
        "top_level_keys": top_keys,
        "key_count": len(obj) if isinstance(obj, (dict, list, tuple)) else 0,
        "content": _preview(obj, 0),
        "note": "Read-only plist summary; large values are truncated and nothing embedded is executed.",
    }
