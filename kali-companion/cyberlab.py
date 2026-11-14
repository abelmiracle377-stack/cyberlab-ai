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

def parse_nmap_xml_text(raw: bytes) -> dict:
    """Parse bounded Nmap XML and preserve port-state and service evidence."""
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
        addresses = [{"address": n.get("addr", ""), "type": n.get("addrtype", "unknown")} for n in host.findall("address")]
        names = [{"name": n.get("name", ""), "type": n.get("type", "unknown")} for n in host.findall("./hostnames/hostname") if n.get("name")]
        ports = []
        for node in host.findall("./ports/port"):
            state, service = node.find("state"), node.find("service")
            try:
                number = int(node.get("portid", "0"))
            except ValueError:
                continue
            if not 1 <= number <= 65535:
                continue
            ports.append({
                "protocol": node.get("protocol", "unknown"), "port": number,
                "state": state.get("state", "unknown") if state is not None else "unknown",
                "reason": state.get("reason", "") if state is not None else "",
                "reason_ttl": state.get("reason_ttl") if state is not None else None,
                "service": service.get("name", "unknown") if service is not None else "unknown",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "extra_info": service.get("extrainfo", "") if service is not None else "",
                "tunnel": service.get("tunnel", "") if service is not None else "",
                "method": service.get("method", "") if service is not None else "",
                "confidence": service.get("conf") if service is not None else None,
            })
        hosts.append({"index": index, "status": status.get("state", "unknown") if status is not None else "unknown",
                      "status_reason": status.get("reason", "") if status is not None else "",
                      "addresses": addresses, "hostnames": names, "ports": ports})
    all_ports = [p for h in hosts for p in h["ports"]]
    states = ("open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered", "unknown")
    scaninfo = [{"type": n.get("type", ""), "protocol": n.get("protocol", ""),
                 "numservices": n.get("numservices", ""), "services": n.get("services", "")}
                for n in root.findall("./scaninfo")]
    runstats = root.find("runstats")
    finished = runstats.find("finished") if runstats is not None else None
    host_stats = runstats.find("hosts") if runstats is not None else None
    open_ports = []
    for host in hosts:
        address = host["addresses"][0]["address"] if host["addresses"] else "Host " + str(host["index"])
        open_ports.extend({"host": address, **p} for p in host["ports"] if p["state"] == "open")
    return {
        "summary": {"hosts": len(hosts), "hosts_up": sum(h["status"] == "up" for h in hosts),
                    "ports_parsed": len(all_ports), "open_ports": len(open_ports),
                    "state_counts": {s: sum(p["state"] == s for p in all_ports) for s in states}},
        "hosts": hosts, "open_ports": open_ports, "scaninfo": scaninfo,
        "completion": {"finished": finished.attrib if finished is not None else {},
                       "hosts": host_stats.attrib if host_stats is not None else {},
                       "scanner": root.get("scanner", ""), "version": root.get("version", ""),
                       "args": root.get("args", ""), "start": root.get("start", ""),
                       "startstr": root.get("startstr", "")},
        "evidence_status": "completed" if finished is not None and finished.get("exit") == "success" else ("partial" if hosts or finished is not None else "no_port_evidence"),
        "note": "Parses an existing Nmap XML report only. It does not launch scans or contact hosts. Missing XML evidence is not interpreted as zero findings."
    }


def parse_nmap_xml(path: Path) -> dict:
    return parse_nmap_xml_text(path.read_bytes())

def port_scan(target: str, port_spec: str, timeout: int = 60) -> dict:
    target = target.strip().lower().rstrip('.')
    try:
        ipaddress.ip_address(target)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', target):
            raise ValueError('Enter one valid IP address or fully-qualified domain name.')
    ports = set()
    for part in port_spec.split(','):
        if '-' in part:
            bits = part.split('-')
            if len(bits) != 2 or not all(x.isdigit() for x in bits): raise ValueError('Use ports like 22,80,443 or 1-100.')
            start, end = map(int, bits)
            if start < 1 or end > 65535 or start > end or end - start + 1 > 100: raise ValueError('Each range must contain 1–100 valid ports.')
            ports.update(range(start, end + 1))
        else:
            if not part.isdigit() or not 1 <= int(part) <= 65535: raise ValueError('Ports must be between 1 and 65535.')
            ports.add(int(part))
        if len(ports) > 100: raise ValueError('Choose no more than 100 unique ports.')
    if not ports: raise ValueError('Select at least one TCP port.')
    nmap = shutil.which('nmap')
    if not nmap: raise ValueError('Nmap is not installed. Run: sudo apt install -y nmap')
    command = [nmap, '-n', '-sT', '-sV', '--version-light', '-T2', '--max-retries', '1', '--host-timeout', '55s', '-p', ','.join(map(str, sorted(ports))), '-oX', '-', target]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ValueError('Nmap exceeded the time limit; try fewer ports.') from exc
    if completed.returncode not in (0, 1) or not completed.stdout.strip(): raise ValueError((completed.stderr or 'Nmap returned no report.')[:700])
    root = ET.fromstring(completed.stdout)
    hosts, all_ports = [], []
    for host in root.findall('host'):
        status = host.find('status')
        addresses = [n.get('addr', '') for n in host.findall('address')]
        rows = []
        for node in host.findall('./ports/port'):
            state, service = node.find('state'), node.find('service')
            row = {'port': int(node.get('portid', '0')), 'protocol': node.get('protocol', 'tcp'), 'state': state.get('state', 'unknown') if state is not None else 'unknown', 'reason': state.get('reason', '') if state is not None else '', 'service': service.get('name', 'unknown') if service is not None else 'unknown', 'product': service.get('product', '') if service is not None else '', 'version': service.get('version', '') if service is not None else '', 'method': service.get('method', '') if service is not None else '', 'confidence': service.get('conf') if service is not None else None}
            rows.append(row); all_ports.append(row)
        hosts.append({'status': status.get('state', 'unknown') if status is not None else 'unknown', 'addresses': addresses, 'ports': rows})
    return {'target': target, 'ports_checked': sorted(ports), 'hosts': hosts, 'state_summary': {s: sum(1 for p in all_ports if p['state'] == s) for s in ('open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered', 'unknown')}, 'open_ports': [p for p in all_ports if p['state'] == 'open'], 'evidence_status': 'completed' if root.find('./runstats/finished') is not None else ('partial' if hosts else 'no_port_evidence'), 'stderr': completed.stderr[:2000], 'exit_code': completed.returncode, 'note': 'Selected TCP ports retain Nmap's reported state, including open, closed, filtered, unfiltered and ambiguous states. Filtered means a firewall or network control prevented a definitive result. This is not a vulnerability verdict. Use only with explicit authorisation.'}

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

def main() -> int:
    print_banner()
    parser = argparse.ArgumentParser(
        description="CyberLab AI: passive OSINT, vulnerability intelligence and local evidence analysis.",
        epilog="Port scanning is limited to one explicitly authorised IP/domain and up to 100 selected TCP ports. No exploitation, sample execution, brute-force enumeration or private-data lookup is performed."
    )
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout in seconds (default: 12)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Check Python and companion readiness")
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
    scan = sub.add_parser("port-scan", aliases=["nmap", "nmap-scan"], help="Run an Nmap TCP port scan on one authorised IP or domain (aliases: nmap, nmap-scan)")
    scan.add_argument("target", help="One IP address or domain name")
    scan.add_argument("--ports", default="1-100", help="Up to 100 TCP ports, e.g. 22,80,443 or 1-100")
    scan.add_argument("--scan-timeout", type=int, default=60, help="Scan timeout in seconds (10–120)")
    cve = sub.add_parser("cve", help="Search the public NIST NVD vulnerability database")
    cve.add_argument("query", help="Vendor, product, version or CVE keyword")
    cve.add_argument("--limit", type=int, default=10)
    for command in (triage, nmap, dns, domain, ip, cve):
        command.add_argument("-o", "--output", help="Save JSON results to this file")
    args = parser.parse_args()
    try:
        if args.timeout < 2 or args.timeout > 60:
            raise ValueError("Timeout must be between 2 and 60 seconds.")
        if args.command == "doctor":
            result = {"status": "ready", "python": sys.version.split()[0],
                      "network_modules": ["domain", "dns", "ip", "cve"],
                      "offline_modules": ["triage", "nmap-xml"],
                      "dependencies": "Python standard library only"}
            save_or_print(result, None)
            return 0
        if args.command in ("port-scan", "nmap", "nmap-scan"):
            if args.scan_timeout < 10 or args.scan_timeout > 120:
                raise ValueError("Scan timeout must be between 10 and 120 seconds.")
            result = port_scan(args.target, args.ports, args.scan_timeout)
        elif args.command == "triage":
            result = triage_file(args.file)
        elif args.command == "nmap-xml":
            result = parse_nmap_xml(args.file)
        elif args.command == "dns":
            result = dns_lookup(args.domain, args.timeout)
        elif args.command == "domain":
            result = domain_osint(args.domain, args.timeout)
        elif args.command == "ip":
            result = ip_intelligence(args.address, args.timeout)
        elif args.command == "cve":
            result = cve_search(args.query, args.limit, args.timeout)
        save_or_print(result, args.output)
        return 0
    except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
