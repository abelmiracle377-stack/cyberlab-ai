"""Deterministic JSON/HTML case exports with a private local archive."""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

EXPORT_ROOT = Path.home() / ".local" / "state" / "cyberlab" / "exports"
MAX_EXPORT_BYTES = 512_000


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _validate(report):
    if not isinstance(report, dict) or report.get("status") != "completed":
        raise ValueError("A completed investigation case report is required.")
    case = report.get("case")
    if not isinstance(case, dict) or not isinstance(case.get("case_id"), str) or not re.fullmatch(r"[a-f0-9]{32}", case["case_id"]):
        raise ValueError("Case report has an invalid case identifier.")
    if not isinstance(case.get("sources"), list) or not 1 <= len(case["sources"]) <= 2:
        raise ValueError("Case report must contain one or two source records.")
    encoded = _canonical(report)
    if len(encoded) > MAX_EXPORT_BYTES:
        raise ValueError("Case report exceeds the 512 KB export limit.")
    return case, encoded


def render_case_html(report):
    case, _ = _validate(report)
    title = "CyberLab Investigation " + case["case_id"]
    # Escape all report-derived values; render structured evidence as escaped JSON.
    safe_title = html.escape(title)
    body = html.escape(json.dumps(report, ensure_ascii=False, indent=2))
    created = html.escape(str(case.get("created_at", "Unknown")))
    return ("<!doctype html><html lang=\"en\">"
            "<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>" + safe_title + "</title><style>body{font:15px/1.55 system-ui,sans-serif;max-width:1000px;margin:40px auto;padding:0 20px;background:#10151d;color:#e8edf4}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#18212d;padding:20px;border-radius:10px}small{color:#aab7c7}</style></head>"
            "<body><h1>" + safe_title + "</h1><small>Created " + created + " · JSON evidence follows</small><pre>" + body + "</pre></body></html>")


def _write_exclusive(path, content):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def export_case_bundle(report):
    case, json_bytes = _validate(report)
    html_bytes = render_case_html(report).encode("utf-8")
    if len(json_bytes) + len(html_bytes) > MAX_EXPORT_BYTES * 2:
        raise ValueError("Combined JSON and HTML exports exceed the archive limit.")
    exported_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    manifest = {
        "schema": "cyberlab.case-export-manifest.v1",
        "case_id": case["case_id"],
        "exported_at": exported_at,
        "files": {
            "case.json": {"sha256": _sha(json_bytes), "size_bytes": len(json_bytes)},
            "case.html": {"sha256": _sha(html_bytes), "size_bytes": len(html_bytes)},
        },
        "source_digests": [source.get("sha256") for source in case["sources"]],
        "note": "Integrity manifest for exported report files; not a digital signature or proof of chain of custody.",
    }
    manifest_bytes = _canonical(manifest)
    EXPORT_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Do not silently write an evidence archive through a symlinked export root.
    # lstat checks the configured root itself without following its final component.
    root_info = EXPORT_ROOT.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("The configured export root must be a regular directory, not a symlink or special file.")
    try:
        os.chmod(EXPORT_ROOT, 0o700)
    except OSError:
        pass
    case_dir = EXPORT_ROOT / case["case_id"]
    case_dir.mkdir(mode=0o700, exist_ok=False)
    try:
        _write_exclusive(case_dir / "case.json", json_bytes)
        _write_exclusive(case_dir / "case.html", html_bytes)
        _write_exclusive(case_dir / "manifest.json", manifest_bytes)
        try:
            os.chmod(case_dir, 0o700)
        except OSError:
            pass
        dir_fd = os.open(str(case_dir), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        for name in ("case.json", "case.html", "manifest.json"):
            try:
                (case_dir / name).unlink()
            except OSError:
                pass
        try:
            case_dir.rmdir()
        except OSError:
            pass
        raise
    return {
        "status": "completed",
        "archive": {"directory": str(case_dir), "permissions": "0700 directory / 0600 files",
                    "manifest": manifest, "manifest_sha256": _sha(manifest_bytes)},
        "json_export": json_bytes.decode("utf-8"),
        "html_export": html_bytes.decode("utf-8"),
        "note": "A private local archive was written without overwriting existing files. Original samples and forensic images are not copied into this report archive.",
    }


def verify_case_archive(case_id):
    """Verify one archive selected by identifier, never by caller-supplied path."""
    if not isinstance(case_id, str) or not re.fullmatch(r"[a-f0-9]{32}", case_id):
        raise ValueError("Enter a valid case identifier.")
    root = EXPORT_ROOT
    case_dir = root / case_id
    try:
        root_info = root.lstat()
        directory_info = case_dir.lstat()
    except OSError:
        return {"status": "failed", "case_id": case_id, "verified": False,
                "errors": ["Case archive does not exist or cannot be inspected."], "checked_files": []}
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("The configured export root is not a regular directory.")
    if stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(directory_info.st_mode):
        raise ValueError("Case archive path is not a regular directory.")
    expected = {"case.json", "case.html", "manifest.json"}
    try:
        actual = {entry.name for entry in case_dir.iterdir()}
    except OSError as exc:
        raise ValueError("Case archive directory could not be listed.") from exc
    if actual != expected:
        return {"status": "failed", "case_id": case_id, "verified": False,
                "errors": ["Archive file set differs from the expected three files."], "checked_files": sorted(actual)}
    errors = []
    checked = []
    contents = {}
    for name in sorted(expected):
        path = case_dir / name
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                errors.append(name + " is not a regular file.")
                continue
            if info.st_size > MAX_EXPORT_BYTES * 2:
                errors.append(name + " exceeds the permitted verification size.")
                continue
            data = path.read_bytes()
            contents[name] = data
            checked.append(name)
        except OSError:
            errors.append(name + " could not be read.")
    manifest = None
    if "manifest.json" in contents:
        try:
            manifest = json.loads(contents["manifest.json"])
            if not isinstance(manifest, dict) or manifest.get("schema") != "cyberlab.case-export-manifest.v1":
                errors.append("Manifest schema is missing or unsupported.")
            elif manifest.get("case_id") != case_id:
                errors.append("Manifest case identifier does not match the requested archive.")
            files = manifest.get("files")
            if not isinstance(files, dict) or set(files) != {"case.json", "case.html"}:
                errors.append("Manifest file inventory is invalid.")
            else:
                for name in ("case.json", "case.html"):
                    if name not in contents:
                        errors.append(name + " is unavailable for verification.")
                        continue
                    record = files.get(name)
                    if not isinstance(record, dict):
                        errors.append(name + " manifest entry is invalid.")
                        continue
                    data = contents[name]
                    if record.get("sha256") != _sha(data):
                        errors.append(name + " SHA-256 mismatch.")
                    if type(record.get("size_bytes")) is not int or record["size_bytes"] != len(data):
                        errors.append(name + " byte-size mismatch.")
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            errors.append("Manifest JSON is malformed.")
    return {
        "status": "completed" if not errors else "failed",
        "case_id": case_id,
        "verified": not errors and len(checked) == 3,
        "checked_files": checked,
        "errors": errors,
        "manifest_sha256": _sha(contents["manifest.json"]) if "manifest.json" in contents else None,
        "note": "Verification checks local file presence, regular-file type, manifest schema, byte sizes and SHA-256 digests. It does not establish authenticity, trusted time or chain of custody.",
    }
