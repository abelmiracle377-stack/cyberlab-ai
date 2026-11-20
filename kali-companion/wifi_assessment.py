"""Authorized Wi-Fi security assessment — passive recon + posture audit + offline crack.

Scope of this module, by design:
  * PASSIVE observation only — it lists wireless interfaces, and parses the
    beacon data airodump-ng already receives, to inventory nearby networks.
  * A pure security-posture AUDIT (open / WEP / WPA / WPA2 / WPA3) with
    remediation, so operators can assess their own estate.
  * OFFLINE cracking of a capture file the operator SUPPLIES, gated behind an
    explicit authorization confirmation — a WPA password-strength audit of your
    own network, the same primitive as any hash-strength check.

What this module deliberately does NOT do: it never transmits deauthentication
or disassociation frames, never runs WPS PIN brute-force, and never forces a
client off a network. Those are denial-of-service / active-injection techniques
that cannot be constrained to an authorized target over the air, so they are out
of scope. Capture a handshake by waiting for a legitimate association on your own
network, then audit it offline here.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile


def list_interfaces(runner=subprocess.run) -> list:
    """Enumerate wireless interfaces and their mode via `iw dev` (read-only)."""
    try:
        proc = runner(["iw", "dev"], capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
        return [{"error": str(exc)[:200]}]
    out = getattr(proc, "stdout", "") or ""
    interfaces, current = [], None
    for line in out.splitlines():
        s = line.strip()
        m = re.match(r"Interface\s+(\S+)", s)
        if m:
            current = {"interface": m.group(1), "type": None}
            interfaces.append(current)
        elif current is not None and s.startswith("type "):
            current["type"] = s.split(None, 1)[1]
    return interfaces


def parse_airodump_csv(text: str) -> list:
    """Parse the AP section of an airodump-ng CSV into structured networks (pure)."""
    aps = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("BSSID") or line.startswith("Station MAC"):
            if line.startswith("Station MAC"):
                break  # client section — stop
            continue
        cols = [c.strip() for c in line.split(",")]
        if len(cols) < 14 or ":" not in cols[0]:
            continue
        aps.append({
            "bssid": cols[0], "channel": cols[3], "privacy": cols[5],
            "cipher": cols[6], "auth": cols[7], "power": cols[8],
            "essid": cols[13] or "<hidden>",
        })
    return aps


def _posture(privacy: str, auth: str) -> tuple:
    """Map a network's advertised crypto to (severity, label, recommendation)."""
    p = (privacy or "").upper()
    a = (auth or "").upper()
    if not p or "OPN" in p:
        return ("critical", "Open (no encryption)", "Enable WPA2/WPA3; never run an open network for trusted use.")
    if "WEP" in p:
        return ("critical", "WEP (broken)", "WEP is trivially cracked. Replace with WPA2-AES or WPA3 immediately.")
    if "WPA3" in p or "SAE" in a:
        if "WPA2" in p:
            return ("low", "WPA2/WPA3 transition", "Transition mode allows WPA2 downgrade; move to WPA3-only where clients allow.")
        return ("info", "WPA3 (SAE)", "Strong. Keep firmware current.")
    if "WPA2" in p:
        return ("info", "WPA2", "Acceptable with a long passphrase; consider WPA3 where supported.")
    if "WPA" in p:
        return ("high", "WPA (v1/TKIP)", "WPA1/TKIP is weak. Upgrade to WPA2-AES or WPA3.")
    return ("info", p or "unknown", "Review the network's encryption configuration.")


def audit_networks(aps: list) -> dict:
    """Assess the security posture of observed networks (pure)."""
    findings = []
    by_sev = {}
    for ap in aps:
        sev, label, rec = _posture(ap.get("privacy", ""), ap.get("auth", ""))
        by_sev[sev] = by_sev.get(sev, 0) + 1
        findings.append({
            "bssid": ap.get("bssid"), "essid": ap.get("essid"),
            "channel": ap.get("channel"), "severity": sev,
            "posture": label, "recommendation": rec,
        })
    order = {"critical": 0, "high": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return {"networks": len(aps), "by_severity": by_sev, "findings": findings,
            "note": "Posture is inferred from passively observed beacons; no frames were transmitted."}


def scan(interface: str, seconds: int = 15, runner=subprocess.run) -> dict:
    """Passively capture beacons for a bounded time and inventory nearby networks.

    Listens only — airodump-ng is run without any injection. Requires a
    monitor-mode interface the operator has already prepared.
    """
    if not interface or not re.match(r"^[a-zA-Z0-9_]+$", interface):
        raise ValueError("A valid monitor-mode interface name is required.")
    seconds = max(5, min(int(seconds), 120))
    workdir = tempfile.mkdtemp(prefix="cyberlab_wifi_")
    prefix = os.path.join(workdir, "scan")
    try:
        runner(["timeout", str(seconds), "airodump-ng", "-w", prefix,
                "--output-format", "csv", interface],
               capture_output=True, text=True, timeout=seconds + 15)
    except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
        return {"error": str(exc)[:200], "interface": interface}
    csv_path = prefix + "-01.csv"
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as fh:
            aps = parse_airodump_csv(fh.read())
    except OSError:
        aps = []
    return {"interface": interface, "seconds": seconds, "networks": aps, "audit": audit_networks(aps)}


def crack_capture(data: dict, runner=subprocess.run) -> dict:
    """Offline WPA password-strength audit of an operator-supplied capture.

    Authorization-gated: the operator must confirm they own or are authorized to
    test the network the capture came from. No frames are transmitted.
    """
    if not isinstance(data, dict):
        raise ValueError("Request must be a JSON object.")
    if data.get("authorizationConfirmed") is not True or data.get("confirmRun") is not True:
        raise ValueError("Confirm you own or are authorized to test this network, and approve the run.")
    reference = data.get("authorizationReference")
    if not isinstance(reference, str) or not reference.strip():
        raise ValueError("An authorization reference is required.")
    capture = data.get("capturePath")
    wordlist = data.get("wordlistPath")
    for label, path in (("capture", capture), ("wordlist", wordlist)):
        if not isinstance(path, str) or not path:
            raise ValueError(f"A {label} file path is required.")
        if not os.path.isfile(path):
            raise ValueError(f"The {label} file was not found: {path}")

    try:
        proc = runner(["aircrack-ng", capture, "-w", wordlist],
                      capture_output=True, text=True, timeout=data.get("timeout", 1800))
    except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
        return {"status": "error", "error": str(exc)[:200]}
    out = getattr(proc, "stdout", "") or ""
    match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", out)
    if match:
        return {"status": "completed", "keyFound": True, "key": match.group(1),
                "authorizationReference": reference.strip(),
                "note": "Password recovered from the supplied capture — it is weak and should be changed."}
    return {"status": "completed", "keyFound": False,
            "authorizationReference": reference.strip(),
            "note": "No password in the wordlist matched; the passphrase resisted this dictionary."}
