"""Deterministic, non-executing planner for authorised cybersecurity tasks.

The planner classifies user intent and proposes reviewed next steps. It never
executes commands, chooses exploit payloads, or treats a mentioned host as
proof of authorisation.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from tool_catalog import inspect_tool_catalog

MAX_PROMPT_CHARS = 4000

PATTERNS = [
    ("network_recon", ("nmap", "port scan", "open ports", "service scan", "network scan", "scan ", "host discovery", "enumerate ports")),
    ("web_assessment", ("web app", "website", "http", "https", "web server", "directory scan", "wordpress", "sql injection", "xss", "api endpoint")),
    ("dns_osint", ("dns", "subdomain", "domain", "whois", "certificate transparency", "theharvester", "amass")),
    ("vulnerability_research", ("vulnerability", "cve", "exploit-db", "searchsploit", "is it vulnerable", "security advisory")),
    ("service_enumeration", ("ftp", "ssh", "smb", "rdp", "snmp", "smtp", "mysql", "postgres", "ldap", "enum4linux")),
    ("metasploit_research", ("metasploit", "msfconsole", "msf module", "auxiliary module")),
    ("password_audit", ("password audit", "hashcat", "john the ripper", "password hash", "credential audit")),
    ("wireless_assessment", ("wifi", "wi-fi", "wireless", "aircrack", "wpa")),
    ("traffic_analysis", ("pcap", "packet capture", "wireshark", "tcpdump", "network traffic")),
    ("active_directory", ("active directory", "bloodhound", "kerberos", "domain controller", "netexec", "impacket")),
    ("digital_forensics", ("forensic", "deleted files", "disk image", "memory dump", "volatility", "autopsy", "binwalk", "photorec", "foremost")),
    ("reverse_engineering", ("reverse engineer", "ghidra", "radare2", "gdb", "disassemble", "binary analysis", "apk")),
    ("malware_triage", ("malware", "suspicious file", "sample", "ransomware", "static analysis", "file triage")),
    ("lab_question", ("hack the box", "htb", "tryhackme", "lab question", "challenge", "flag", "what is the answer")),
]

TOOL_MAP = {
    "network_recon": ["Nmap"],
    "web_assessment": ["CyberLab Web Crawler & Baseline Auditor", "CyberLab Safe Active Web Checks", "CyberLab HTTP Workbench", "WhatWeb", "Nmap"],
    "dns_osint": ["WHOIS", "theHarvester", "Amass", "dnsenum", "dnsrecon"],
    "vulnerability_research": ["SearchSploit", "Metasploit Framework"],
    "service_enumeration": ["Nmap", "FTP client", "Impacket", "NetExec"],
    "metasploit_research": ["Metasploit Framework", "SearchSploit", "Nmap"],
    "password_audit": ["John the Ripper", "Hashcat"],
    "wireless_assessment": ["Aircrack-ng", "Kismet"],
    "traffic_analysis": ["Wireshark / TShark", "tcpdump"],
    "active_directory": ["Impacket", "NetExec", "BloodHound", "Nmap"],
    "digital_forensics": ["Autopsy", "Sleuth Kit", "Foremost", "Volatility 3", "Binwalk"],
    "reverse_engineering": ["Ghidra", "Radare2", "GDB"],
    "malware_triage": ["Ghidra", "Radare2", "Binwalk"],
    "lab_question": ["Nmap", "SearchSploit", "Metasploit Framework"],
}

BLOCKED_HINTS = {
    "phishing": "Phishing/camera-capture workflows are not automated.",
    "camphish": "CamPhish is blocked; the companion will not capture cameras or trick users into granting access.",
    "brute force": "Online brute-force and credential-guessing runs are not available as unattended actions.",
    "hydra": "Hydra is inventoried for reference but is not launched by the task planner.",
    "persistence": "Persistence installation or concealment is not automated.",
    "steal credentials": "Credential theft is not supported.",
    "exfiltrat": "Data exfiltration is not supported.",
    "ransomware": "Ransomware creation or deployment is not supported; static defensive analysis is available.",
    "dos": "Denial-of-service and resource-exhaustion actions are not automated.",
}


def _extract_target(prompt: str) -> str | None:
    # Only extract a single explicit URL, IPv4, or FQDN. Never infer a target
    # from a company/person name or silently scan a broad network range.
    urls = re.findall(r"https?://[^\s<>\"']+", prompt, flags=re.I)
    if urls:
        candidate = urls[0].rstrip(".,);]")
        parsed = urlparse(candidate)
        return parsed.hostname
    ipv4 = re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", prompt)
    for candidate in ipv4:
        octets = candidate.split(".")
        if all(0 <= int(part) <= 255 for part in octets):
            return candidate
    domains = re.findall(r"(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-])", prompt, flags=re.I)
    ignored = {"example.com", "example.org", "example.net", "localhost"}
    for candidate in domains:
        if candidate.lower() not in ignored:
            return candidate.lower()
    return None


def plan_task(prompt: str) -> dict:
    if not isinstance(prompt, str):
        raise ValueError("Task description must be text.")
    prompt = prompt.strip()
    if not prompt:
        raise ValueError("Describe the cybersecurity question or task.")
    if len(prompt) > MAX_PROMPT_CHARS:
        raise ValueError(f"Task description must be {MAX_PROMPT_CHARS} characters or fewer.")

    lowered = prompt.lower()
    categories = [key for key, terms in PATTERNS if any(term in lowered for term in terms)]
    if not categories:
        categories = ["general_security_question"]

    target = _extract_target(prompt)
    inventory = inspect_tool_catalog()
    by_name = {tool["name"]: tool for group in inventory["categories"] for tool in group["tools"]}
    tool_names = list(dict.fromkeys(name for category in categories for name in TOOL_MAP.get(category, [])))
    suggested_tools = [
        {
            "name": name,
            "installed": by_name[name]["installed"],
            "mode": by_name[name]["mode"],
            "purpose": by_name[name]["purpose"],
            "install_hint": by_name[name]["install_hint"],
        }
        for name in tool_names if name in by_name
    ]

    blocked = [message for term, message in BLOCKED_HINTS.items() if term in lowered]
    active_categories = {"network_recon", "web_assessment", "service_enumeration", "wireless_assessment", "active_directory", "metasploit_research"}
    needs_authorisation = any(category in active_categories for category in categories)
    missing = []
    if needs_authorisation and not target:
        missing.append("A single in-scope IP address or hostname is needed before an active network assessment.")
    if needs_authorisation:
        missing.append("Confirm ownership or written permission and provide the engagement/ticket reference before any active scan.")
    if "digital_forensics" in categories and not any(term in lowered for term in ("image", "disk", "drive", "memory", "file")):
        missing.append("Specify the evidence type (disk image, memory image, firmware or file).")
    if "password_audit" in categories:
        missing.append("Provide a hash file you are authorised to audit; online login guessing is not planned.")
    if "wireless_assessment" in categories:
        missing.append("Identify the owned lab adapter/network and confirm monitor-mode support; no wireless action is started by this plan.")
    if "lab_question" in categories and not target:
        missing.append("Paste the challenge prompt and provide the assigned lab target or VPN-reachable address when one is issued.")

    steps = [
        "Interpret the task and separate facts supplied by the user from assumptions.",
        "Check local tool availability and show package installation guidance for missing dependencies.",
        "Validate the exact target/evidence and the user's authorisation and scope.",
        "Run only a reviewed CyberLab-native workflow that matches the task; enforce exact host scope, request budgets and approval gates. Do not pass free-form shell commands to the local machine.",
        "Collect bounded tool output, explain findings with supporting evidence, and state uncertainty and next steps.",
    ]
    if not needs_authorisation:
        steps[2] = "Confirm that supplied files, data and systems are owned by the user or authorised for analysis."
    passive_suggestion = None
    if "dns_osint" in categories and target:
        # Domain OSINT is a passive lookup; it never implies permission to scan.
        try:
            import ipaddress
            ipaddress.ip_address(target)
        except ValueError:
            if re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", target, flags=re.I):
                passive_suggestion = {"action": "domain", "value": target}
    service_suggestion = None
    if "service_enumeration" in categories and target:
        suggested_ports = []
        for term, port in (("ftp", 21), ("ssh", 22), ("smtp", 25), ("http", 80), ("https", 443), ("smb", 445), ("imap", 143), ("pop3", 110)):
            if term in lowered and port not in suggested_ports:
                suggested_ports.append(port)
        if suggested_ports:
            service_suggestion = {"ports": suggested_ports[:8], "target": target}
    recommended_workflow = []
    if "web_assessment" in categories:
        recommended_workflow = [
            {"phase": "application discovery", "tool": "CyberLab Web Crawler & Baseline Auditor", "mode": "bounded same-origin GET-only crawl", "status": "available", "approval_required": True},
            {"phase": "manual request inspection", "tool": "CyberLab HTTP Workbench", "mode": "scope-bound HTTP request and response analysis", "status": "available", "approval_required": True},
            {"phase": "safe active checks", "tool": "CyberLab Safe Active Web Checks", "mode": "CORS preflight and inert GET query-reflection indicators", "status": "available_limited", "approval_required": True},
            {"phase": "advanced vulnerability validation", "tool": "CyberLab native vulnerability scanner", "mode": "SQL injection, SSRF, IDOR, authentication and deeper checks with evidence verification", "status": "not_implemented", "approval_required": True},
            {"phase": "fuzzing and request replay", "tool": "CyberLab native repeater and fuzzer", "mode": "bounded parameter testing", "status": "not_implemented", "approval_required": True},
        ]
    return {
        "status": "plan_only",
        "summary": "Detected task type(s): " + ", ".join(categories).replace("_", " "),
        "categories": categories,
        "passive_research_suggestion": passive_suggestion,
        "service_enumeration_suggestion": service_suggestion,
        "target": target,
        "target_status": "candidate extracted; not yet validated or authorised" if target else "not provided",
        "requires_authorisation": needs_authorisation,
        "missing_information": list(dict.fromkeys(missing)),
        "suggested_tools": suggested_tools,
        "recommended_workflow": recommended_workflow,
        "safety_notes": blocked,
        "steps": steps,
        "execution_started": False,
        "note": "This is a deterministic first-pass planner, not an AI conclusion or a vulnerability verdict. It has not scanned, connected to, or modified any target. A named target in text is not proof of scope or permission. Web assessments use CyberLab-native HTTP tooling; no Burp installation is required.",
    }
