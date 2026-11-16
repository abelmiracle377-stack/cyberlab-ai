"""Curated Kali tool inventory and installation guidance for CyberLab.

This module only detects installed executables. It never installs or runs tools.
"""
from __future__ import annotations

import shutil

# Each entry is descriptive metadata, not an executable command template.
# Tools marked manual_only are visible for education/inventory but are not
# eligible for unattended execution by the bridge.
TOOL_CATALOG = [
    {"name": "Nmap", "category": "Information gathering", "binary": "nmap", "package": "nmap", "mode": "safe_scan", "purpose": "Host discovery, port and service enumeration."},
    {"name": "Masscan", "category": "Information gathering", "binary": "masscan", "package": "masscan", "mode": "manual_only", "purpose": "High-speed port discovery; requires strict rate and scope controls."},
    {"name": "Netdiscover", "category": "Information gathering", "binary": "netdiscover", "package": "netdiscover", "mode": "manual_only", "purpose": "Local network host discovery."},
    {"name": "theHarvester", "category": "Information gathering", "binary": "theHarvester", "package": "theharvester", "mode": "passive", "purpose": "Passive public-source domain and contact discovery."},
    {"name": "Amass", "category": "Information gathering", "binary": "amass", "package": "amass", "mode": "passive", "purpose": "Attack-surface and subdomain intelligence; active modes require scope."},
    {"name": "Recon-ng", "category": "Information gathering", "binary": "recon-ng", "package": "recon-ng", "mode": "passive", "purpose": "Modular reconnaissance framework."},
    {"name": "Maltego", "category": "Information gathering", "binary": "maltego", "package": "maltego", "mode": "manual_only", "purpose": "Visual link analysis and OSINT."},
    {"name": "dnsenum", "category": "Information gathering", "binary": "dnsenum", "package": "dnsenum", "mode": "passive", "purpose": "DNS enumeration; active queries require scope."},
    {"name": "dnsrecon", "category": "Information gathering", "binary": "dnsrecon", "package": "dnsrecon", "mode": "passive", "purpose": "DNS record and configuration enumeration."},
    {"name": "WHOIS", "category": "Information gathering", "binary": "whois", "package": "whois", "mode": "passive", "purpose": "Domain and IP registration information."},
    {"name": "enum4linux-ng", "category": "Information gathering", "binary": "enum4linux-ng", "package": "enum4linux-ng", "mode": "manual_only", "purpose": "SMB/Windows enumeration; use only on authorised systems."},
    {"name": "Nikto", "category": "Vulnerability analysis", "binary": "nikto", "package": "nikto", "mode": "manual_only", "purpose": "Web server configuration and known-issue checks."},
    {"name": "Greenbone / OpenVAS", "category": "Vulnerability analysis", "binary": "gvm-cli", "package": "gvm", "mode": "manual_only", "purpose": "Managed vulnerability assessment; requires configured services."},
    {"name": "Lynis", "category": "Vulnerability analysis", "binary": "lynis", "package": "lynis", "mode": "local_audit", "purpose": "Local Linux security configuration audit."},
    {"name": "Nuclei", "category": "Vulnerability analysis", "binary": "nuclei", "package": "nuclei", "mode": "manual_only", "purpose": "Template-based checks; templates and target scope must be reviewed."},
    {"name": "CyberLab HTTP Workbench", "category": "Web application analysis", "binary": None, "package": None, "mode": "native_http", "native": True, "purpose": "Native, scope-bound HTTP request inspection and replay through the authenticated local companion."},
    {"name": "CyberLab Web Crawler & Baseline Auditor", "category": "Web application analysis", "binary": None, "package": None, "mode": "native_crawl", "native": True, "purpose": "Bounded same-origin GET-only page discovery, form inventory and baseline HTTP header/cookie review with explicit scope and approval."},
    {"name": "OWASP ZAP", "category": "Web application analysis", "binary": "zaproxy", "package": "zaproxy", "mode": "manual_only", "purpose": "Web application proxy and controlled scanning."},
    {"name": "sqlmap", "category": "Web application analysis", "binary": "sqlmap", "package": "sqlmap", "mode": "manual_only", "purpose": "SQL injection testing; potentially intrusive."},
    {"name": "WPScan", "category": "Web application analysis", "binary": "wpscan", "package": "wpscan", "mode": "manual_only", "purpose": "WordPress security enumeration."},
    {"name": "Commix", "category": "Web application analysis", "binary": "commix", "package": "commix", "mode": "manual_only", "purpose": "Command-injection testing; potentially intrusive."},
    {"name": "Gobuster", "category": "Web application analysis", "binary": "gobuster", "package": "gobuster", "mode": "manual_only", "purpose": "Directory and DNS enumeration; requires rate and scope limits."},
    {"name": "Dirb", "category": "Web application analysis", "binary": "dirb", "package": "dirb", "mode": "manual_only", "purpose": "Web content discovery."},
    {"name": "ffuf", "category": "Web application analysis", "binary": "ffuf", "package": "ffuf", "mode": "manual_only", "purpose": "Web fuzzing; requires explicit scope and rate limits."},
    {"name": "wfuzz", "category": "Web application analysis", "binary": "wfuzz", "package": "wfuzz", "mode": "manual_only", "purpose": "Web fuzzing; requires explicit scope and rate limits."},
    {"name": "WhatWeb", "category": "Web application analysis", "binary": "whatweb", "package": "whatweb", "mode": "passive", "purpose": "Web technology fingerprinting."},
    {"name": "John the Ripper", "category": "Password auditing", "binary": "john", "package": "john", "mode": "manual_only", "purpose": "Offline password-hash auditing on supplied hashes."},
    {"name": "Hashcat", "category": "Password auditing", "binary": "hashcat", "package": "hashcat", "mode": "manual_only", "purpose": "Offline password-hash auditing on supplied hashes."},
    {"name": "Hydra", "category": "Password auditing", "binary": "hydra", "package": "hydra", "mode": "blocked_automation", "purpose": "Online login guessing; never launched unattended."},
    {"name": "Medusa", "category": "Password auditing", "binary": "medusa", "package": "medusa", "mode": "blocked_automation", "purpose": "Online login guessing; never launched unattended."},
    {"name": "Aircrack-ng", "category": "Wireless security", "binary": "aircrack-ng", "package": "aircrack-ng", "mode": "manual_only", "purpose": "Wireless security analysis on owned lab networks."},
    {"name": "Kismet", "category": "Wireless security", "binary": "kismet", "package": "kismet", "mode": "manual_only", "purpose": "Wireless network monitoring and discovery."},
    {"name": "Metasploit Framework", "category": "Exploitation research", "binary": "msfconsole", "package": "metasploit-framework", "mode": "safe_metadata_only", "purpose": "Module search, module information and safe checks; no unattended exploit or payload execution."},
    {"name": "SearchSploit", "category": "Exploitation research", "binary": "searchsploit", "package": "exploitdb", "mode": "passive", "purpose": "Local Exploit-DB reference search."},
    {"name": "BeEF", "category": "Exploitation research", "binary": "beef-xss", "package": "beef-xss", "mode": "blocked_automation", "purpose": "Browser exploitation framework; no unattended hook or control actions."},
    {"name": "tcpdump", "category": "Traffic analysis", "binary": "tcpdump", "package": "tcpdump", "mode": "passive_capture", "purpose": "Bounded passive packet capture through CyberLab's consent-gated local network capture module."},
    {"name": "Wireshark / TShark", "category": "Traffic analysis", "binary": "tshark", "package": "tshark", "mode": "local_analysis", "purpose": "Read and analyse packet captures."},
    {"name": "Bettercap", "category": "Traffic analysis", "binary": "bettercap", "package": "bettercap", "mode": "manual_only", "purpose": "Network analysis; active interception features are not automated."},
    {"name": "Impacket", "category": "Active Directory", "binary": "impacket-smbclient", "package": "python3-impacket", "mode": "manual_only", "purpose": "Protocol tooling for authorised Windows/AD labs."},
    {"name": "NetExec", "category": "Active Directory", "binary": "nxc", "package": "netexec", "mode": "manual_only", "purpose": "Network and AD assessment; credentialed actions require explicit controls."},
    {"name": "BloodHound", "category": "Active Directory", "binary": "bloodhound", "package": "bloodhound", "mode": "manual_only", "purpose": "Active Directory relationship analysis."},
    {"name": "Autopsy", "category": "Forensics", "binary": "autopsy", "package": "autopsy", "mode": "local_analysis", "purpose": "Digital forensic case analysis."},
    {"name": "Binwalk", "category": "Forensics", "binary": "binwalk", "package": "binwalk", "mode": "local_analysis", "purpose": "Firmware and binary structure analysis."},
    {"name": "Foremost", "category": "Forensics", "binary": "foremost", "package": "foremost", "mode": "local_analysis", "purpose": "File carving from forensic images."},
    {"name": "Volatility 3", "category": "Forensics", "binary": "vol", "package": "volatility3", "mode": "local_analysis", "purpose": "Memory image analysis."},
    {"name": "Ghidra", "category": "Reverse engineering", "binary": "ghidra", "package": "ghidra", "mode": "manual_only", "purpose": "Static reverse engineering."},
    {"name": "Radare2", "category": "Reverse engineering", "binary": "r2", "package": "radare2", "mode": "local_analysis", "purpose": "Binary analysis and reverse engineering."},
    {"name": "GDB", "category": "Reverse engineering", "binary": "gdb", "package": "gdb", "mode": "local_analysis", "purpose": "Debugging and binary inspection."},
    {"name": "FTP client", "category": "Network utilities", "binary": "ftp", "package": "tnftp", "mode": "manual_only", "purpose": "Interactive FTP client; no automated credential guessing."},
    {"name": "Netcat", "category": "Network utilities", "binary": "nc", "package": "netcat-openbsd", "mode": "manual_only", "purpose": "Manual TCP/UDP connectivity diagnostics."},
    {"name": "Socat", "category": "Network utilities", "binary": "socat", "package": "socat", "mode": "manual_only", "purpose": "Manual socket and stream diagnostics."},
    {"name": "CamPhish", "category": "Social engineering", "binary": "camphish", "package": None, "mode": "blocked", "purpose": "Camera phishing/unauthorised capture; deliberately excluded from automation."},
]


def inspect_tool_catalog() -> dict:
    """Return installed status and safe install hints without running package managers."""
    categories: dict[str, list[dict]] = {}
    installed_count = 0
    for entry in TOOL_CATALOG:
        found = "native" if entry.get("native") else (shutil.which(entry["binary"]) if entry.get("binary") else None)
        item = {
            **entry,
            "installed": bool(found),
            "path": found,
            "install_hint": (
                f"sudo apt update && sudo apt install -y {entry['package']}"
                if not found and entry["package"] else None
            ),
        }
        installed_count += int(item["installed"])
        categories.setdefault(entry["category"], []).append(item)
    return {
        "categories": [
            {"name": name, "tools": tools}
            for name, tools in categories.items()
        ],
        "tool_count": len(TOOL_CATALOG),
        "installed_count": installed_count,
        "missing_count": len(TOOL_CATALOG) - installed_count,
        "note": "Inventory only: no packages were installed and no tools were executed. Install hints are suggestions; review package names and prompts before installing. Execution eligibility is separately enforced by the bridge.",
    }
