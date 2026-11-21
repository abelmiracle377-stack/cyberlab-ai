"""Authorised SSH service posture audit; never attempts authentication or key collection."""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import time
from urllib.parse import urlsplit


def _target(value: str) -> str:
    raw = str(value or "").strip()
    if not raw or len(raw) > 253 or any(c in raw for c in "/\\\\@?#"):
        raise ValueError("Provide a single authorised SSH host, not a URL or network range.")
    try:
        ip = ipaddress.ip_address(raw)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise ValueError("SSH audit blocks loopback, link-local, multicast, unspecified and reserved targets.")
        return str(ip)
    except ValueError as exc:
        if "blocks" in str(exc):
            raise
    host = raw.rstrip(".").lower()
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
        raise ValueError("Provide a valid fully-qualified hostname or public IP.")
    return host


def audit_ssh(data: dict) -> dict:
    """Collect SSH banner and, when installed, ssh-audit posture output.

    Requires explicit authorisation reference. Does not authenticate, brute-force,
    enumerate users, collect private keys, or attempt credential validation.
    """
    if not isinstance(data, dict) or data.get("authorized") is not True:
        raise ValueError("Explicitly confirm that you are authorised to assess this SSH host.")
    reference = str(data.get("authorizationReference", "")).strip()
    if not reference or len(reference) > 200:
        raise ValueError("Provide a short authorisation or engagement reference.")
    host = _target(data.get("host", ""))
    try:
        port = int(data.get("port", 22))
    except (TypeError, ValueError) as exc:
        raise ValueError("SSH port must be an integer from 1 to 65535.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("SSH port must be an integer from 1 to 65535.")
    timeout = min(max(float(data.get("timeoutSeconds", 5)), 1), 10)
    started = time.monotonic()
    banner = ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            raw = conn.recv(512)
            banner = raw.decode("ascii", "replace").strip()[:200]
    except OSError as exc:
        return {
            "status": "unreachable", "target": {"host": host, "port": port},
            "authorizationReference": reference, "banner": None,
            "error": str(exc)[:180], "findings": [],
            "limitations": ["No SSH authentication or credential testing was attempted."],
        }
    if not banner.startswith("SSH-"):
        return {"status": "not_ssh_or_unexpected_banner", "target": {"host": host, "port": port},
                "authorizationReference": reference, "banner": banner, "findings": [],
                "limitations": ["The endpoint did not return a valid SSH identification string."]}
    findings = []
    if "SSH-1." in banner:
        findings.append({"severity": "high", "title": "Obsolete SSH protocol version advertised",
                         "evidence": banner, "confidence": "high"})
    if re.search(r"OpenSSH_[1-6]\.", banner):
        findings.append({"severity": "review", "title": "Potentially old OpenSSH version advertised",
                         "evidence": banner, "confidence": "low",
                         "note": "Banner versions may be backported; verify against vendor package advisories."})
    tool_result = None
    executable = shutil.which("ssh-audit")
    if executable:
        try:
            run = subprocess.run([executable, "-j", "-p", str(port), host],
                                 capture_output=True, text=True, timeout=20, check=False,
                                 env={"PATH": "/usr/bin:/bin", "LANG": "C"})
            output = (run.stdout or run.stderr or "")[:30000]
            tool_result = {"available": True, "exitCode": run.returncode, "output": output}
        except (OSError, subprocess.TimeoutExpired) as exc:
            tool_result = {"available": True, "error": str(exc)[:200]}
    else:
        tool_result = {"available": False, "installHint": "Install the distribution package for ssh-audit to enumerate key exchange, cipher, MAC and host-key algorithms."}
    return {
        "status": "completed", "target": {"host": host, "port": port},
        "authorizationReference": reference, "banner": banner,
        "sshAudit": tool_result, "findings": findings,
        "summary": {"bannerReceived": True, "sshAuditAvailable": bool(executable),
                    "elapsedMs": round((time.monotonic() - started) * 1000)},
        "limitations": ["No login, password guessing, private-key collection, user enumeration or authentication attempt was performed.",
                        "Banner-only results cannot establish the full SSH cryptographic configuration."],
    }
