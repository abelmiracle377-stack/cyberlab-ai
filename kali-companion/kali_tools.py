"""Vetted execution layer for Kali tooling.

This lets the paired companion actually run recognised security tools on behalf
of an operator — the gap between "a catalogue of tools" and "a companion that
runs them". It is deliberately NOT an arbitrary shell:

  * Every tool has a fixed argument template; user input only fills validated,
    typed slots (hostname, URL, port spec, wordlist path, bounded integers).
  * No value is ever passed through a shell; argv lists are executed directly.
  * Active/network tools additionally require an authorisation reference and an
    exact-target confirmation, mirroring the Nmap scan flow.
  * If a tool is not installed the call fails closed with an install hint; a
    result is only ever the real tool's own output.

Add a tool by adding one entry to TOOL_SPECS. The framework handles validation,
consent, execution bounds and output limits.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from urllib.parse import urlsplit

MAX_OUTPUT_BYTES = 512 * 1024
DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 1800

_HOSTNAME = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


# --- validators (each returns a safe, normalised value or raises) -----------
def v_host(value: object) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if not _HOSTNAME.fullmatch(text):
        raise ValueError("Enter one valid IP address or fully-qualified domain name.")
    return text


def v_url(value: object) -> str:
    text = str(value or "").strip()
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter an http(s) URL without embedded credentials.")
    if len(text) > 2048:
        raise ValueError("URL exceeds the 2048-character limit.")
    v_host(parsed.hostname)  # reject malformed hosts
    return text


def v_port_spec(value: object) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*", text):
        raise ValueError("Ports must be numbers or ranges, e.g. 80,443,8000-8100.")
    for part in text.split(","):
        for bound in part.split("-"):
            if not 1 <= int(bound) <= 65535:
                raise ValueError("Each port must be between 1 and 65535.")
    return text


def v_wordlist(value: object) -> str:
    from pathlib import Path
    path = Path(str(value or "").strip()).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError("Wordlist must be an existing regular file on this machine.")
    if not 1 <= path.stat().st_size <= 2 * 1024 * 1024 * 1024:
        raise ValueError("Wordlist is empty or larger than 2 GiB.")
    return str(path)


def v_bounded_int(low: int, high: int):
    def check(value: object) -> str:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("Expected an integer between %d and %d." % (low, high))
        if not low <= value <= high:
            raise ValueError("Value must be between %d and %d." % (low, high))
        return str(value)
    return check


# --- tool registry ----------------------------------------------------------
# active=True tools reach out to a target and require authorisation + exact-target
# confirmation. 'target_param' names the slot the operator must retype to confirm.
TOOL_SPECS = {
    "whois": {
        "binary": "whois", "package": "whois", "active": False, "category": "passive-osint",
        "params": {"host": v_host}, "argv": lambda p: ["whois", "--", p["host"]],
        "purpose": "Domain/IP registration lookup (passive).",
    },
    "dnsrecon": {
        "binary": "dnsrecon", "package": "dnsrecon", "active": False, "category": "passive-dns",
        "params": {"host": v_host}, "argv": lambda p: ["dnsrecon", "-d", p["host"], "-t", "std"],
        "purpose": "Standard DNS record enumeration (passive).",
    },
    "whatweb": {
        "binary": "whatweb", "package": "whatweb", "active": True, "category": "web-fingerprint",
        "target_param": "url", "params": {"url": v_url},
        "argv": lambda p: ["whatweb", "--no-errors", "-a", "1", "--", p["url"]],
        "purpose": "Passive-leaning web technology fingerprint on an authorised URL.",
    },
    "nmap": {
        "binary": "nmap", "package": "nmap", "active": True, "category": "port-scan",
        "target_param": "host",
        "params": {"host": v_host, "ports": v_port_spec},
        "argv": lambda p: ["nmap", "-n", "-sT", "-sV", "--version-light", "--reason",
                           "-T2", "-p", p["ports"], "--", p["host"]],
        "purpose": "Bounded TCP connect + service scan on an authorised host.",
    },
    "nikto": {
        "binary": "nikto", "package": "nikto", "active": True, "category": "web-scan",
        "target_param": "url", "params": {"url": v_url},
        "argv": lambda p: ["nikto", "-ask", "no", "-maxtime", "600", "-h", p["url"]],
        "purpose": "Web server configuration checks on an authorised target.",
    },
    "gobuster-dir": {
        "binary": "gobuster", "package": "gobuster", "active": True, "category": "web-content",
        "target_param": "url",
        "params": {"url": v_url, "wordlist": v_wordlist, "threads": v_bounded_int(1, 30)},
        "argv": lambda p: ["gobuster", "dir", "-q", "-z", "-t", p["threads"],
                           "-w", p["wordlist"], "-u", p["url"]],
        "purpose": "Directory/content discovery on an authorised URL with your wordlist.",
    },
}


def list_tools() -> dict:
    """Report each tool, its mode and whether its binary is installed locally."""
    tools = []
    for name, spec in sorted(TOOL_SPECS.items()):
        tools.append({
            "name": name, "binary": spec["binary"], "category": spec["category"],
            "active": spec["active"], "installed": bool(shutil.which(spec["binary"])),
            "parameters": sorted(spec["params"].keys()), "purpose": spec["purpose"],
        })
    return {"tools": tools,
            "note": "Active tools require an authorisation reference and exact-target confirmation. The companion never installs tools or runs arbitrary commands."}


def run_tool(name: str, params: dict, confirmed: bool = False,
             authorization_reference: str = "", target_confirmation: str = "",
             timeout: int = DEFAULT_TIMEOUT, runner=subprocess.run, resolve=shutil.which) -> dict:
    """Validate, authorise and execute one registered tool with a fixed argv."""
    spec = TOOL_SPECS.get(name)
    if spec is None:
        raise ValueError("Unknown tool: " + str(name))
    if not confirmed:
        raise ValueError("This tool run must be explicitly confirmed before it starts.")
    if not isinstance(params, dict):
        raise ValueError("Tool parameters must be an object.")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_TIMEOUT:
        raise ValueError("Timeout must be an integer between 1 and %d seconds." % MAX_TIMEOUT)

    validated = {}
    for key, validator in spec["params"].items():
        if key not in params:
            raise ValueError("Missing required parameter: " + key)
        validated[key] = validator(params[key])

    if spec["active"]:
        if not isinstance(authorization_reference, str) or not 1 <= len(authorization_reference.strip()) <= 200:
            raise ValueError("Active tools require a written authorisation/engagement reference.")
        target_value = validated[spec["target_param"]]
        if str(target_confirmation or "").strip().lower() != str(target_value).strip().lower():
            raise ValueError("Retype the exact target to confirm you are authorised to assess it.")

    executable = resolve(spec["binary"])
    if not executable:
        raise ValueError("{bin} is not installed. Install it on this machine (for example: "
                         "sudo apt install {pkg}); the companion never downloads tools."
                         .format(bin=spec["binary"], pkg=spec["package"]))

    argv = spec["argv"](validated)
    argv[0] = executable
    try:
        completed = runner(argv, capture_output=True, text=True, timeout=int(timeout), check=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": name, "argv": argv[1:],
                "note": "The tool did not finish within the time limit."}
    stdout = (completed.stdout or "")[:MAX_OUTPUT_BYTES]
    stderr = (completed.stderr or "")[:16384]
    return {"status": "completed", "tool": name, "exitCode": completed.returncode,
            "argv": argv[1:], "stdout": stdout, "stderr": stderr,
            "truncated": len(completed.stdout or "") > MAX_OUTPUT_BYTES,
            "note": "Real tool output. Exit code and findings are the tool's own; interpret them in context."}
