#!/usr/bin/env python3
"""CyberLab AI Kali companion: passive OSINT and local evidence analysis."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
import socket
import sys
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_XML_BYTES = 2 * 1024 * 1024
USER_AGENT = "CyberLabAI-Kali-Companion/1.0 (passive-security-research)"
INDICATORS = {
    "PowerShell": re.compile(r"powershell(?:\.exe)?|pwsh(?:\.exe)?", re.I),
    "Windows script host": re.compile(r"wscript(?:\.exe)?|cscript(?:\.exe)?", re.I),
    "Command interpreter": re.compile(r"cmd\.exe|\\cmd\.exe", re.I),
    "LOLBIN utility": re.compile(r"rundll32|regsvr32|mshta|certutil|bitsadmin", re.I),
    "Download utility": re.compile(r"(?:^|\s)(?:curl|wget)(?:\s|$)", re.I),
    "Base64-related string": re.compile(r"base64|frombase64string", re.I),
    "Process memory API": re.compile(r"virtualalloc|writeprocessmemory|createremotethread", re.I),
    "Linux preload variable": re.compile(r"LD_PRELOAD", re.I),
    "Shell execution": re.compile(r"/bin/(?:ba)?sh|execve\s*\(", re.I),
    "Debugger or anti-analysis string": re.compile(r"IsDebuggerPresent|CheckRemoteDebuggerPresent|ptrace", re.I),
}

def identify(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "Windows PE / DOS executable header (MZ)"
    if data.startswith(b"\x7fELF"):
        return "ELF executable"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O executable"
    if data.startswith(b"%PDF-"):
        return "PDF document"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP archive"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    return "Unknown or unrecognised file signature"

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return round(-sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values()), 3)

def triage_file(path: Path) -> dict:
    data = path.read_bytes()
    if not data:
        raise ValueError("Selected file is empty.")
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("File exceeds the 10 MB limit.")
    strings = re.findall(rb"[\x20-\x7e]{5,}", data)
    decoded = [item.decode("latin-1", errors="replace") for item in strings]
    matches = [(name, value) for name, pattern in INDICATORS.items() for value in decoded if pattern.search(value)]
    return {
        "file_name": path.name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "file_type": identify(data),
        "entropy": calculate_entropy(data),
        "printable_string_count": len(decoded),
        "indicator_groups": sorted({name for name, _ in matches}),
        "matched_strings": list(dict.fromkeys(value[:240] for _, value in matches))[:50],
        "note": "Static triage only. The sample was not executed, unpacked, uploaded or stored. Indicators are not a malware verdict."
    }

def parse_nmap_xml(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > MAX_XML_BYTES:
        raise ValueError("Nmap XML exceeds the 2 MB limit.")
    if re.search(rb"<!DOCTYPE|<!ENTITY", raw, re.I):
        raise ValueError("DOCTYPE and entity declarations are not accepted.")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError("Invalid XML: " + str(exc)) from exc
    if root.tag != "nmaprun":
        raise ValueError("XML root element is not nmaprun.")
    hosts = []
    for index, host in enumerate(root.findall("host"), 1):
        status = host.find("status")
        addresses = [{"address": node.get("addr", ""), "type": node.get("addrtype", "unknown")} for node in host.findall("address")]
        names = [node.get("name", "") for node in host.findall("./hostnames/hostname") if node.get("name")]
        ports = []
        for node in host.findall("./ports/port"):
            state = node.find("state")
            service = node.find("service")
            try:
                port_number = int(node.get("portid", "0"))
            except ValueError:
                continue
            if not 1 <= port_number <= 65535:
                continue
            ports.append({
                "protocol": node.get("protocol", "unknown"), "port": port_number,
                "state": state.get("state", "unknown") if state is not None else "unknown",
                "service": service.get("name", "unknown") if service is not None else "unknown",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            })
        hosts.append({
            "index": index, "status": status.get("state", "unknown") if status is not None else "unknown",
            "addresses": addresses, "hostnames": names, "ports": ports,
        })
    open_ports = []
    for host in hosts:
        address = host["addresses"][0]["address"] if host["addresses"] else "Host " + str(host["index"])
        for port in host["ports"]:
            if port["state"] == "open":
                open_ports.append({"host": address, **port})
    return {
        "summary": {"hosts": len(hosts), "hosts_up": sum(1 for host in hosts if host["status"] == "up"),
                    "ports_parsed": sum(len(host["ports"]) for host in hosts), "open_ports": len(open_ports)},
        "hosts": hosts, "open_ports": open_ports,
        "note": "Parses an existing Nmap XML report only. It does not launch scans or contact hosts."
    }

def http_json(url: str, timeout: int = 12):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError("Remote service returned HTTP " + str(response.status))
        payload = response.read(2_000_001)
        if len(payload) > 2_000_000:
            raise ValueError("Remote response exceeded the 2 MB safety limit.")
        return json.loads(payload.decode("utf-8"))

def validate_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if len(domain) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise ValueError("Enter a valid public domain name, for example example.com.")
    return domain

def dns_lookup(domain: str, timeout: int = 12) -> dict:
    domain = validate_domain(domain)
    output = {}
    for record in ("A", "AAAA", "MX", "NS", "TXT"):
        url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": domain, "type": record})
        try:
            data = http_json(url, timeout)
            answers = []
            for answer in data.get("Answer", []):
                answers.append({"ttl": answer.get("TTL"), "value": answer.get("data", "")})
            output[record] = {"status": data.get("Status"), "answers": answers}
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            output[record] = {"error": str(exc)}
    return {"domain": domain, "records": output, "source": "Cloudflare public DNS-over-HTTPS"}

def domain_osint(value: str, timeout: int = 12) -> dict:
    domain = validate_domain(value)
    result = {"domain": domain, "sources": {}, "limitations": [
        "Passive public-source research only; no brute-force enumeration or active probing.",
        "Certificate names can include historical, wildcard or unrelated entries; validate ownership and current status."
    ]}
    encoded = urllib.parse.quote(domain, safe="")
    try:
        result["sources"]["rdap"] = http_json("https://rdap.org/domain/" + encoded, timeout)
    except Exception as exc:
        result["sources"]["rdap_error"] = str(exc)
    try:
        query = urllib.parse.urlencode({"q": "%." + domain, "output": "json"})
        certs = http_json("https://crt.sh/?" + query, timeout)
        names = sorted({name.strip().lower().lstrip("*.") for row in certs if isinstance(row, dict)
                        for name in str(row.get("name_value", "")).splitlines() if name.strip()})
        result["sources"]["certificate_transparency"] = {"entries_returned": len(certs), "unique_names": names[:500]}
    except Exception as exc:
        result["sources"]["certificate_transparency_error"] = str(exc)
    result["sources"]["dns"] = dns_lookup(domain, timeout)["records"]
    return result

def ip_intelligence(value: str, timeout: int = 12) -> dict:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 or IPv6 address.") from exc
    if not address.is_global:
        raise ValueError("For privacy and safety, this lookup accepts public global IP addresses only.")
    try:
        rdap = http_json("https://rdap.org/ip/" + urllib.parse.quote(str(address), safe=""), timeout)
    except Exception as exc:
        rdap = {"lookup_error": str(exc)}
    return {"ip": str(address), "rdap": rdap,
            "note": "RDAP provides network registration context, not a person's identity or exact physical location."}

def cve_search(term: str, limit: int = 10, timeout: int = 12) -> dict:
    term = term.strip()
    if len(term) < 2 or len(term) > 120:
        raise ValueError("Enter a product, vendor, version or CVE keyword (2–120 characters).")
    limit = max(1, min(limit, 20))
    params = urllib.parse.urlencode({"keywordSearch": term, "resultsPerPage": limit})
    data = http_json("https://services.nvd.nist.gov/rest/json/cves/2.0?" + params, timeout)
    items = []
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        descriptions = cve.get("descriptions", [])
        english = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        severity = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss = metrics[key][0].get("cvssData", {})
                score, severity = cvss.get("baseScore"), cvss.get("baseSeverity")
                break
        items.append({"id": cve.get("id"), "published": cve.get("published"),
                      "last_modified": cve.get("lastModified"), "cvss": score,
                      "severity": severity, "description": english[:1200]})
    return {"query": term, "total_results": data.get("totalResults", 0), "results": items,
            "source": "NIST National Vulnerability Database"}

def save_or_print(result: dict, output: str | None):
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if output:
        destination = Path(output).expanduser()
        destination.write_text(rendered + "\n", encoding="utf-8")
        print("Saved report to " + str(destination.resolve()))
    else:
        print(rendered)

def print_banner() -> None:
    """Show the CyberLab welcome art in interactive terminals only."""
    if not sys.stderr.isatty() or "NO_COLOR" in __import__("os").environ:
        return

    bold = "\033[1m"
    blue = "\033[94m"
    green = "\033[92m"
    reset = "\033[0m"
    figlet = shutil.which("figlet")
    if figlet:
        for phrase, colour in (
            ("CYBERLAB SAYS", blue),
            ('"FUCK HATERS"', green),
            ("AND HACK FOR", green),
            ("ZODIAC M BY ABEL", blue),
        ):
            rendered = subprocess.run(
                [figlet, "-w", "100", "-f", "big", phrase],
                check=False, capture_output=True, text=True,
            )
            if rendered.returncode == 0:
                print(f"{bold}{colour}{rendered.stdout.rstrip()}{reset}", file=sys.stderr)
    else:
        print(f"{bold}{blue}CYBERLAB SAYS{reset}", file=sys.stderr)
        print(f'{bold}{green}"FUCK HATERS"{reset}', file=sys.stderr)
        print(f"{bold}{green}AND HACK FOR{reset}", file=sys.stderr)
        print(f"{bold}{blue}ZODIAC M BY ABEL{reset}", file=sys.stderr)

    asset = Path(__file__).resolve().parent / "assets" / "cyberlab-mascot.jpg"
    chafa = shutil.which("chafa")
    if chafa and asset.is_file():
        rendered_image = subprocess.run(
            [chafa, "--colors=full", "--symbols=ascii", "--size=52x32", str(asset)],
            check=False, capture_output=True, text=True,
        )
        if rendered_image.returncode == 0:
            print(rendered_image.stdout, file=sys.stderr)
    print(reset, file=sys.stderr)
    print(file=sys.stderr)



def analyze_url(value: str) -> dict:
    """Inspect URL structure without visiting it or contacting its host."""
    from urllib.parse import urlsplit
    raw = value.strip()
    if not raw or len(raw) > 2048:
        raise ValueError("Enter a URL between 1 and 2048 characters.")
    candidate = raw if "://" in raw else "https://" + raw
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL could not be parsed safely: " + str(exc)) from exc
    if parsed.scheme.lower() not in ("http", "https") or not host:
        raise ValueError("Only complete HTTP or HTTPS URLs are supported.")
    if any(ord(ch) < 32 for ch in raw):
        raise ValueError("Control characters are not allowed in URLs.")
    flags = []
    if parsed.scheme.lower() != "https":
        flags.append("URL does not use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        flags.append("URL contains embedded user information")
    if "@" in parsed.netloc:
        flags.append("Authority contains @, which can disguise the destination")
    if host.lower().startswith("xn--") or ".xn--" in host.lower():
        flags.append("Hostname contains an IDN/punycode label")
    try:
        ipaddress.ip_address(host)
        flags.append("Destination is an IP literal rather than a domain name")
    except ValueError:
        pass
    if len(raw) > 180:
        flags.append("Unusually long URL")
    if host.count(".") >= 4:
        flags.append("Hostname has many subdomain labels")
    if port not in (None, 80, 443):
        flags.append("URL specifies a non-standard port")
    if parsed.scheme.lower() == "http" and parsed.path.lower().endswith((".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".apk")):
        flags.append("URL path appears to reference an executable or installer")
    return {
        "submitted_url": raw,
        "normalized_host": host.lower(),
        "scheme": parsed.scheme.lower(),
        "port": port,
        "path_length": len(parsed.path),
        "query_present": bool(parsed.query),
        "structural_indicators": flags,
        "risk_note": "Heuristic URL structure review only. The URL was NOT opened, resolved, downloaded or submitted to a reputation service. Indicators are not proof of maliciousness.",
    }


def evidence_directory() -> Path:
    directory = Path.home() / "CyberLab" / "evidence"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def show_evidence_manager() -> None:
    directory = evidence_directory()
    files = sorted((p for p in directory.iterdir() if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True)
    print("\\nLOCAL EVIDENCE MANAGER")
    print(f"Storage: {directory}")
    if not files:
        print("No evidence files stored yet.")
        print("Place an authorised sample in this folder, then use option 7 for static analysis.")
        return
    for index, item in enumerate(files[:50], 1):
        print(f"  [{index}] {item.name} ({item.stat().st_size} bytes)")
    if len(files) > 50:
        print(f"  ... and {len(files) - 50} more file(s)")


def show_connection_status() -> None:
    print("\\nDEVICE CONNECTION")
    print("Remote gateway: NOT CONFIGURED")
    print("No VPS endpoint or authenticated pairing service is configured.")
    print("Device pairing and live sessions are not active yet.")
    print("This menu will become operational after the gateway and device companions are implemented.")
    print("No fake pairing link or simulated device connection has been created.")


def show_session_status() -> None:
    print("\\nLIVE SESSION MANAGER")
    print("No remote session backend is configured.")
    print("Pause, resume and disconnect controls require an authenticated active session.")
    print("Configure the CyberLab gateway before starting remote sessions.")


def content_analysis_menu(timeout: int = 12) -> None:
    print("\\nMALICIOUS FILE & LINK ANALYSIS")
    print("  [1] Static file analysis")
    print("  [2] Image/file signature analysis")
    print("  [3] URL structure analysis (does not open the URL)")
    print("  [0] Back")
    choice = input("analysis> ").strip()
    try:
        if choice in ("1", "2"):
            sample = Path(input("Path to local file: ").strip()).expanduser()
            result = triage_file(sample)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            destination = save_investigation(result, "file-triage")
            print(f"Saved locally: {destination}")
        elif choice == "3":
            result = analyze_url(input("URL to inspect: ").strip())
            print(json.dumps(result, indent=2, ensure_ascii=False))
            destination = save_investigation(result, "url-analysis")
            print(f"Saved locally: {destination}")
        elif choice != "0":
            print("Choose one of the listed options.")
    except (OSError, ValueError) as exc:
        print(f"Analysis failed: {exc}")


def investigation_directory() -> Path:
    """Return the local, user-owned directory for JSON investigation reports."""
    directory = Path.home() / "CyberLab" / "investigations"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def save_investigation(result: dict, service: str) -> Path:
    """Save a timestamped JSON report locally; never upload it automatically."""
    from datetime import datetime, timezone
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_service = re.sub(r"[^a-z0-9-]+", "-", service.lower()).strip("-") or "report"
    destination = investigation_directory() / f"{stamp}_{safe_service}.json"
    destination.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return destination


def show_investigation_history() -> None:
    directory = investigation_directory()
    reports = sorted(directory.glob("*.json"), reverse=True)
    print("\nLOCAL INVESTIGATION HISTORY")
    print(f"Location: {directory}")
    if not reports:
        print("No reports saved yet.")
        return
    for report in reports[:30]:
        print(f"  {report.name} ({report.stat().st_size} bytes)")
    if len(reports) > 30:
        print(f"  ... and {len(reports) - 30} older report(s)")



def interactive_menu(timeout: int = 12) -> int:
    """Run the local-first CyberLab operations menu."""
    services = {
        "1": ("Domain OSINT", "domain"),
        "2": ("DNS intelligence", "dns"),
        "3": ("Public IP intelligence", "ip"),
        "4": ("CVE research", "cve"),
        "5": ("Static file triage", "triage"),
        "6": ("Nmap XML analysis", "nmap-xml"),
    }
    while True:
        print("\\nCYBERLAB AI")
        print("     SECURITY OPERATIONS\\n")
        print("  [1] Domain OSINT")
        print("  [2] DNS Intelligence")
        print("  [3] IP Intelligence")
        print("  [4] CVE Research")
        print("  [5] File Triage")
        print("  [6] Nmap XML Analysis")
        print("  [7] Malicious File & Link Analysis")
        print("  [8] Connect Device")
        print("  [9] Connected Devices")
        print("  [10] Manage Live Sessions")
        print("  [11] Evidence Manager")
        print("  [12] Investigation Reports")
        print("  [0] Exit")
        try:
            choice = input("\\ncyberlab> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\\nExiting CyberLab.")
            return 0
        if choice == "0":
            print("CyberLab closed.")
            return 0
        if choice == "7":
            content_analysis_menu(timeout)
            continue
        if choice in ("8", "9"):
            show_connection_status()
            continue
        if choice == "10":
            show_session_status()
            continue
        if choice == "11":
            show_evidence_manager()
            continue
        if choice == "12":
            show_investigation_history()
            continue
        if choice not in services:
            print("Choose one of the listed options.")
            continue

        label, command = services[choice]
        try:
            if command == "domain":
                result = domain_osint(input("Public domain: ").strip(), timeout)
            elif command == "dns":
                result = dns_lookup(input("Public domain: ").strip(), timeout)
            elif command == "ip":
                result = ip_intelligence(input("Public global IP: ").strip(), timeout)
            elif command == "cve":
                term = input("Product, vendor or CVE keyword: ").strip()
                raw_limit = input("Maximum results [10]: ").strip()
                limit = int(raw_limit) if raw_limit else 10
                result = cve_search(term, limit, timeout)
            elif command == "triage":
                result = triage_file(Path(input("Path to local sample file: ").strip()).expanduser())
            else:
                result = parse_nmap_xml(Path(input("Path to existing Nmap XML report: ").strip()).expanduser())
            print(json.dumps(result, indent=2, ensure_ascii=False))
            destination = save_investigation(result, command)
            print(f"\\nSaved locally: {destination}")
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            print(f"\\nOperation failed: {exc}")
        except (EOFError, KeyboardInterrupt):
            print("\\nReturning to the CyberLab menu.")

def main() -> int:
    print_banner()
    parser = argparse.ArgumentParser(
        description="CyberLab AI: passive OSINT, vulnerability intelligence and local evidence analysis.",
        epilog="No port scanning, exploitation, sample execution, brute-force enumeration or private-data lookup is performed."
    )
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout in seconds (default: 12)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Check Python and companion readiness")
    sub.add_parser("menu", help="Open the interactive Kali command centre")
    url_cmd = sub.add_parser("url", help="Inspect URL structure without opening it")
    url_cmd.add_argument("url")
    url_cmd.add_argument("-o", "--output", help="Save JSON results to this file")
    triage = sub.add_parser("triage", help="Statically inspect a local file (max 10 MB)")
    triage.add_argument("file", type=Path)
    nmap = sub.add_parser("nmap-xml", help="Parse an existing Nmap XML report (max 2 MB)")
    nmap.add_argument("file", type=Path)
    dns = sub.add_parser("dns", help="Resolve public DNS records for a domain")
    dns.add_argument("domain")
    domain = sub.add_parser("domain", help="Passive domain RDAP, certificate and DNS research")
    domain.add_argument("domain")
    ip = sub.add_parser("ip", help="Look up public IP network registration context")
    ip.add_argument("address")
    cve = sub.add_parser("cve", help="Search the public NIST NVD vulnerability database")
    cve.add_argument("query", help="Vendor, product, version or CVE keyword")
    cve.add_argument("--limit", type=int, default=10)
    for command in (triage, nmap, dns, domain, ip, cve):
        command.add_argument("-o", "--output", help="Save JSON results to this file")
    args = parser.parse_args()
    try:
        if args.timeout < 2 or args.timeout > 60:
            raise ValueError("Timeout must be between 2 and 60 seconds.")
        if args.command == "menu":
            return interactive_menu(args.timeout)
        if args.command == "url":
            result = analyze_url(args.url)
            save_or_print(result, args.output)
            return 0
        if args.command == "doctor":
            result = {"status": "ready", "python": sys.version.split()[0],
                      "network_modules": ["domain", "dns", "ip", "cve"],
                      "offline_modules": ["triage", "nmap-xml"],
                      "dependencies": "Python standard library only"}
            save_or_print(result, None)
            return 0
        if args.command == "triage":
            result = triage_file(args.file)
        elif args.command == "nmap-xml":
            result = parse_nmap_xml(args.file)
        elif args.command == "dns":
            result = dns_lookup(args.domain, args.timeout)
        elif args.command == "domain":
            result = domain_osint(args.domain, args.timeout)
        elif args.command == "ip":
            result = ip_intelligence(args.address, args.timeout)
        else:
            result = cve_search(args.query, args.limit, args.timeout)
        save_or_print(result, args.output)
        return 0
    except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
