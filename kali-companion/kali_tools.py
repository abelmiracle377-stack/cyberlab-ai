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


def v_single_port(value: object) -> str:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("Port must be a single integer between 1 and 65535.")
    if isinstance(value, bool) or not 1 <= port <= 65535:
        raise ValueError("Port must be a single integer between 1 and 65535.")
    return str(port)


def v_search_term(value: object) -> str:
    text = str(value or "").strip()
    if not 1 <= len(text) <= 120:
        raise ValueError("Search term must be 1 to 120 characters.")
    # Restrict to characters that are safe inside a single msfconsole -x command;
    # there is no shell, but this keeps the term from injecting extra msf commands.
    if not re.fullmatch(r"[A-Za-z0-9 _/.:+\-]+", text):
        raise ValueError("Search term may contain only letters, numbers, spaces and _ / . : + -")
    return text


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
    "sslscan": {
        "binary": "sslscan", "package": "sslscan", "active": True, "category": "tls",
        "target_param": "host", "params": {"host": v_host},
        "argv": lambda p: ["sslscan", "--no-colour", "--", p["host"]],
        "purpose": "TLS protocol and cipher review of an authorised host (port 443).",
    },
    "masscan": {
        "binary": "masscan", "package": "masscan", "active": True, "category": "fast-scan",
        "target_param": "host",
        "params": {"host": v_host, "ports": v_port_spec, "rate": v_bounded_int(1, 5000)},
        "argv": lambda p: ["masscan", "-p", p["ports"], "--rate", p["rate"], "--wait", "0", p["host"]],
        "purpose": "Rate-limited high-speed port discovery on an authorised host (may require root).",
    },
    "netcat-banner": {
        "binary": "nc", "package": "netcat-openbsd", "active": True, "category": "connectivity",
        "target_param": "host", "stdin_devnull": True,
        "params": {"host": v_host, "port": v_single_port},
        "argv": lambda p: ["nc", "-w", "5", "-v", "--", p["host"], p["port"]],
        "purpose": "Connect to one authorised host/port and read the service banner.",
    },
    "sqlmap": {
        "binary": "sqlmap", "package": "sqlmap", "active": True, "category": "web-sqli",
        "target_param": "url", "params": {"url": v_url},
        "argv": lambda p: ["sqlmap", "-u", p["url"], "--batch", "--level", "1", "--risk", "1",
                           "--crawl", "0", "--flush-session", "--disable-coloring"],
        "purpose": "Bounded SQL-injection testing (level 1 / risk 1) of an authorised URL.",
    },
    "ftp-anon": {
        "binary": "curl", "package": "curl", "active": True, "category": "ftp",
        "target_param": "host", "params": {"host": v_host},
        "argv": lambda p: ["curl", "-sS", "--connect-timeout", "10", "--max-time", "25",
                           "--ftp-method", "nocwd", "ftp://" + p["host"] + "/"],
        "purpose": "Anonymous FTP root directory listing on an authorised host.",
    },
    "metasploit-search": {
        "binary": "msfconsole", "package": "metasploit-framework", "active": False,
        "category": "exploit-research", "params": {"query": v_search_term},
        "argv": lambda p: ["msfconsole", "-q", "-x", "search " + p["query"] + "; exit -y"],
        "purpose": "Search local Metasploit modules by keyword (metadata only; no exploit is run).",
    },
    # --- passive DNS / OSINT recon (no authorisation required) ---
    "dig": {
        "binary": "dig", "package": "bind9-dnsutils", "active": False, "category": "passive-dns",
        "params": {"host": v_host}, "argv": lambda p: ["dig", "+short", "+timeout=5", "A", p["host"]],
        "purpose": "Resolve A records for a domain (passive).",
    },
    "host": {
        "binary": "host", "package": "bind9-host", "active": False, "category": "passive-dns",
        "params": {"host": v_host}, "argv": lambda p: ["host", "-W", "5", p["host"]],
        "purpose": "Basic DNS lookup for a domain or IP (passive).",
    },
    "dnsenum": {
        "binary": "dnsenum", "package": "dnsenum", "active": False, "category": "passive-dns",
        "params": {"host": v_host}, "argv": lambda p: ["dnsenum", "--noreverse", "--nocolor", p["host"]],
        "purpose": "DNS record and subdomain enumeration (recon).",
    },
    "fierce": {
        "binary": "fierce", "package": "fierce", "active": False, "category": "passive-dns",
        "params": {"host": v_host}, "argv": lambda p: ["fierce", "--domain", p["host"]],
        "purpose": "DNS reconnaissance and subdomain discovery.",
    },
    "sublist3r": {
        "binary": "sublist3r", "package": "sublist3r", "active": False, "category": "passive-osint",
        "params": {"host": v_host}, "argv": lambda p: ["sublist3r", "-n", "-d", p["host"]],
        "purpose": "Passive subdomain enumeration from public sources.",
    },
    "theharvester": {
        "binary": "theHarvester", "package": "theharvester", "active": False, "category": "passive-osint",
        "params": {"host": v_host},
        "argv": lambda p: ["theHarvester", "-d", p["host"], "-b", "duckduckgo,bing,crtsh", "-l", "100"],
        "purpose": "Passive public-source host and e-mail discovery.",
    },
    # --- active web (authorisation + exact-target confirmation required) ---
    "wpscan": {
        "binary": "wpscan", "package": "wpscan", "active": True, "category": "web-cms",
        "target_param": "url", "params": {"url": v_url},
        "argv": lambda p: ["wpscan", "--url", p["url"], "--no-banner", "--no-update",
                           "--random-user-agent", "--format", "cli-no-color"],
        "purpose": "WordPress enumeration of an authorised site.",
    },
    "nuclei": {
        "binary": "nuclei", "package": "nuclei", "active": True, "category": "web-scan",
        "target_param": "url", "params": {"url": v_url},
        "argv": lambda p: ["nuclei", "-u", p["url"], "-silent", "-rl", "50", "-timeout", "10",
                           "-severity", "low,medium,high,critical", "-nc"],
        "purpose": "Template-based checks against an authorised URL (rate-limited).",
    },
    "wafw00f": {
        "binary": "wafw00f", "package": "wafw00f", "active": True, "category": "web-fingerprint",
        "target_param": "url", "params": {"url": v_url},
        "argv": lambda p: ["wafw00f", "-a", p["url"]],
        "purpose": "Detect and fingerprint a web application firewall on an authorised URL.",
    },
    "ffuf": {
        "binary": "ffuf", "package": "ffuf", "active": True, "category": "web-content",
        "target_param": "url",
        "params": {"url": v_url, "wordlist": v_wordlist, "threads": v_bounded_int(1, 40)},
        "argv": lambda p: ["ffuf", "-u", p["url"].rstrip("/") + "/FUZZ", "-w", p["wordlist"],
                           "-mc", "200,204,301,302,307,401,403", "-t", p["threads"], "-s"],
        "purpose": "Web content fuzzing on an authorised URL with your wordlist.",
    },
    "dirb": {
        "binary": "dirb", "package": "dirb", "active": True, "category": "web-content",
        "target_param": "url", "params": {"url": v_url, "wordlist": v_wordlist},
        "argv": lambda p: ["dirb", p["url"], p["wordlist"], "-S", "-r"],
        "purpose": "Directory/content discovery on an authorised URL with your wordlist.",
    },
    # --- active network / SMB / SSH (authorisation + exact-target confirmation) ---
    "enum4linux-ng": {
        "binary": "enum4linux-ng", "package": "enum4linux-ng", "active": True, "category": "smb-enum",
        "target_param": "host", "params": {"host": v_host},
        "argv": lambda p: ["enum4linux-ng", "-A", p["host"]],
        "purpose": "SMB/Windows enumeration of an authorised host.",
    },
    "smbmap": {
        "binary": "smbmap", "package": "smbmap", "active": True, "category": "smb-enum",
        "target_param": "host", "params": {"host": v_host},
        "argv": lambda p: ["smbmap", "-H", p["host"]],
        "purpose": "Enumerate SMB shares and access on an authorised host.",
    },
    "nbtscan": {
        "binary": "nbtscan", "package": "nbtscan", "active": True, "category": "netbios",
        "target_param": "host", "params": {"host": v_host},
        "argv": lambda p: ["nbtscan", p["host"]],
        "purpose": "NetBIOS name scan of an authorised host.",
    },
    "ssh-audit": {
        "binary": "ssh-audit", "package": "ssh-audit", "active": True, "category": "ssh",
        "target_param": "host", "params": {"host": v_host},
        "argv": lambda p: ["ssh-audit", "--", p["host"]],
        "purpose": "SSH server configuration and algorithm audit of an authorised host.",
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
    run_kwargs = {"capture_output": True, "text": True, "timeout": int(timeout), "check": False}
    if spec.get("stdin_devnull"):
        run_kwargs["stdin"] = subprocess.DEVNULL  # tools like nc must not block on inherited stdin
    try:
        completed = runner(argv, **run_kwargs)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": name, "argv": argv[1:],
                "note": "The tool did not finish within the time limit."}
    stdout = (completed.stdout or "")[:MAX_OUTPUT_BYTES]
    stderr = (completed.stderr or "")[:16384]
    return {"status": "completed", "tool": name, "exitCode": completed.returncode,
            "argv": argv[1:], "stdout": stdout, "stderr": stderr,
            "truncated": len(completed.stdout or "") > MAX_OUTPUT_BYTES,
            "note": "Real tool output. Exit code and findings are the tool's own; interpret them in context."}
