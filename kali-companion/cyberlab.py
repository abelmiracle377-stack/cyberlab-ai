#!/usr/bin/env python3
"""CyberLab AI Kali companion: passive OSINT and local evidence analysis."""
from __future__ import annotations

import argparse
import hashlib
import getpass
import secrets
import string
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
    """Perform bounded, read-only triage; never execute or unpack the selected file."""
    if not path.is_file() or path.is_symlink():
        raise ValueError("Select an existing regular local file (symbolic links are not accepted).")
    size = path.stat().st_size
    if size == 0:
        raise ValueError("Selected file is empty.")
    if size > MAX_FILE_BYTES:
        raise ValueError("File exceeds the 10 MB limit.")
    data = path.read_bytes()
    signature = identify(data)
    suffix = path.suffix.lower()
    expected = {".exe": "Windows PE", ".dll": "Windows PE", ".sys": "Windows PE",
                ".elf": "ELF", ".so": "ELF", ".pdf": "PDF", ".png": "PNG",
                ".jpg": "JPEG", ".jpeg": "JPEG", ".zip": "ZIP", ".gz": "GZIP"}.get(suffix)
    strings = re.findall(rb"[\\x20-\\x7e]{5,}", data)
    decoded = [item.decode("latin-1", errors="replace") for item in strings]
    matches = [(name, value) for name, pattern in INDICATORS.items() for value in decoded if pattern.search(value)]
    entropy = calculate_entropy(data)
    return {
        "file_name": path.name, "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "file_type": signature,
        "extension": suffix or None,
        "extension_signature_mismatch": bool(expected and expected not in signature),
        "entropy": entropy,
        "entropy_interpretation": "high; may reflect compression or encryption" if entropy >= 7.2 else ("moderate" if entropy >= 6.0 else "lower"),
        "printable_string_count": len(decoded),
        "indicator_groups": sorted({name for name, _ in matches}),
        "matched_strings": list(dict.fromkeys(value[:240] for _, value in matches))[:50],
        "triage_limits": ["No execution, unpacking, macro activation, archive extraction or network upload.",
                          "High entropy and string indicators are heuristics, not proof of malware.",
                          "This lightweight parser does not validate complete PE/ELF structures or digital signatures."],
        "note": "Static triage only. Indicators are not a malware verdict."
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
    service_counts = Counter(port["service"] for port in open_ports if port.get("service"))
    versioned_services = [{"host": item["host"], "port": item["port"], "protocol": item["protocol"],
                           "service": item["service"], "product": item["product"], "version": item["version"]}
                          for item in open_ports if item.get("product") or item.get("version")]
    return {
        "summary": {"hosts": len(hosts), "hosts_up": sum(1 for host in hosts if host["status"] == "up"),
                    "ports_parsed": sum(len(host["ports"]) for host in hosts), "open_ports": len(open_ports),
                    "open_service_counts": dict(service_counts)},
        "hosts": hosts, "open_ports": open_ports, "versioned_services": versioned_services[:200],
        "review_guidance": ["Treat service banners as reported observations; they can be inaccurate or masked.",
                            "Confirm exact product builds and patch levels from asset inventory before CVE matching.",
                            "This parser reads an existing XML file and performs no network activity."],
        "note": "Parses an existing Nmap XML report only. It does not launch scans or contact hosts."
    }

def http_json(url: str, timeout: int = 12):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/dns-json, application/json"})
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

class _PageMetadata(__import__("html.parser", fromlist=["HTMLParser"]).HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = []
        self.in_title = False
        self.meta = {}
        self.links = []
        self.forms = []
        self.form = None
    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title": self.in_title = True
        if tag == "meta":
            key = (a.get("name") or a.get("property") or "").lower()
            if key in ("description", "og:description", "og:site_name", "generator"): self.meta[key] = a.get("content", "")[:500]
        if tag == "a" and a.get("href"): self.links.append(a["href"][:1000])
        if tag == "form":
            self.form = {"method": a.get("method", "get").lower(), "fields": []}
            self.forms.append(self.form)
        if tag == "input" and self.form is not None:
            self.form["fields"].append({"type": a.get("type", "text").lower(), "name": a.get("name", "")[:100]})
    def handle_endtag(self, tag):
        if tag == "title": self.in_title = False
        if tag == "form": self.form = None
    def handle_data(self, data):
        if self.in_title and data.strip(): self.title.append(data.strip())

def public_site_profile(domain: str, timeout: int = 12) -> dict:
    """Fetch only the public HTTPS home page; never crawl or submit forms."""
    from html.parser import HTMLParser
    request = urllib.request.Request("https://" + domain + "/", headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            final_host = urllib.parse.urlsplit(response.geturl()).hostname
            if final_host and final_host.lower() != domain.lower():
                return {"status": "cross_domain_redirect", "note": "Not followed for profile extraction."}
            if "html" not in response.headers.get("Content-Type", "").lower():
                return {"status": "non_html", "content_type": response.headers.get("Content-Type", "")}
            raw = response.read(1000001)
            if len(raw) > 1000000: raw = raw[:1000000]
            parser = _PageMetadata()
            parser.feed(raw.decode(response.headers.get_content_charset() or "utf-8", errors="replace"))
            emails = sorted(set(re.findall(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", raw.decode("utf-8", errors="ignore"))))[:30]
            phones = sorted(set(re.findall(r"(?<!\w)(?:\+\d[\d ().-]{7,}\d)", raw.decode("utf-8", errors="ignore"))))[:20]
            social_hosts = ("facebook.com", "instagram.com", "linkedin.com", "x.com", "twitter.com", "youtube.com", "tiktok.com", "github.com")
            socials = []
            for link in parser.links:
                absolute = urllib.parse.urljoin(response.geturl(), link)
                host = (urllib.parse.urlsplit(absolute).hostname or "").lower()
                if any(host == item or host.endswith("." + item) for item in social_hosts): socials.append(absolute.split("?")[0][:300])
            forms = []
            for form in parser.forms[:20]:
                types = sorted({field["type"] for field in form["fields"]})
                names = [field["name"] for field in form["fields"] if field["name"]]
                forms.append({"method": form["method"], "input_types": types, "field_names": names[:20], "appears_auth_related": "password" in types or any(any(x in n.lower() for x in ("user", "email", "login")) for n in names)})
            headers = response.headers
            sec = {n: headers.get(n) for n in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy") if headers.get(n)}
            return {"status": "ok", "page_title": " ".join(parser.title)[:300], "description": parser.meta.get("description") or parser.meta.get("og:description", ""), "generator": parser.meta.get("generator", ""), "public_contact_emails": emails, "public_contact_phone_numbers": phones, "social_media_links": sorted(set(socials))[:30], "visible_forms": forms, "security_headers_present": sec, "security_headers_missing": [n for n in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy") if n not in sec], "ai_build_assessment": "Inconclusive; public HTML alone cannot reliably establish AI authorship.", "limitations": ["Only the HTTPS home page was fetched.", "No hidden-path enumeration, login attempts, form submissions or exploit tests were performed.", "Visible form fields do not prove the authentication backend or its security."]}
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return {"status": "unavailable", "error": str(exc), "note": "RDAP, certificate and DNS research continues independently."}

class _NoRedirect(__import__("urllib.request", fromlist=["HTTPRedirectHandler"]).HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validate_assessment_url(value: str) -> str:
    """Accept an explicit HTTPS URL only when its resolved addresses are public."""
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Assessment URLs must be explicit HTTPS URLs without embedded credentials.")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)})
        except OSError as exc:
            raise ValueError("Could not resolve the supplied assessment host: " + str(exc)) from exc
    if not addresses:
        raise ValueError("The assessment host did not resolve to an address.")
    for item in addresses:
        address = ipaddress.ip_address(item.split("%", 1)[0])
        if not address.is_global:
            raise ValueError("Assessment URL resolves to a non-public address; local/private targets are not fetched by this passive module.")
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))


def inspect_assessment_page(value: str, timeout: int = 12, method: str = "GET") -> dict:
    """Inspect one explicitly supplied public HTTPS page; no redirects or form submissions."""
    url = _validate_assessment_url(value)
    if method not in ("GET", "HEAD"):
        raise ValueError("Only GET and HEAD metadata inspection are supported.")
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, method=method, headers={
        "User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"
    })
    try:
        with opener.open(request, timeout=timeout) as response:
            headers = response.headers
            result = {
                "requested_url": url, "method": method, "status_code": response.status,
                "final_url": response.geturl(),
                "security_headers": {name: headers.get(name) for name in (
                    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                    "X-Content-Type-Options", "Referrer-Policy"
                ) if headers.get(name)},
                "security_headers_missing": [name for name in (
                    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                    "X-Content-Type-Options", "Referrer-Policy"
                ) if not headers.get(name)],
                "set_cookie_headers": headers.get_all("Set-Cookie", [])[:30],
                "redirects_followed": False,
            }
            cookies = []
            for raw_cookie in result["set_cookie_headers"]:
                first = raw_cookie.split(";", 1)[0]
                attrs = [part.strip() for part in raw_cookie.split(";")[1:]]
                attr_names = {part.split("=", 1)[0].strip().lower() for part in attrs}
                cookies.append({
                    "name": first.split("=", 1)[0][:100],
                    "secure": "secure" in attr_names,
                    "httponly": "httponly" in attr_names,
                    "samesite": next((part.split("=", 1)[1].strip() for part in attrs if part.lower().startswith("samesite=")), None),
                    "path": next((part.split("=", 1)[1].strip() for part in attrs if part.lower().startswith("path=")), None),
                    "max_age": next((part.split("=", 1)[1].strip() for part in attrs if part.lower().startswith("max-age=")), None),
                })
            result["cookies"] = cookies
            result["cookie_note"] = "Only cookies set by this one response are visible; this does not verify session rotation, server-side expiry or logout invalidation."
            if method == "GET" and "html" in headers.get("Content-Type", "").lower():
                raw = response.read(500001)
                parser = _PageMetadata()
                parser.feed(raw.decode(headers.get_content_charset() or "utf-8", errors="replace"))
                forms = []
                for form in parser.forms[:20]:
                    types = sorted({field["type"] for field in form["fields"]})
                    names = [field["name"].lower() for field in form["fields"] if field["name"]]
                    email_field = "email" in types or any("email" in name for name in names)
                    username_field = any(any(term in name for term in ("user", "login", "account")) for name in names)
                    password_field = "password" in types
                    forms.append({
                        "method": form["method"], "input_types": types, "field_names": names[:20],
                        "email_password_pattern": bool(email_field and password_field),
                        "username_password_pattern": bool(username_field and password_field),
                        "authentication_form_likely": bool(password_field or email_field or username_field),
                    })
                result["page_title"] = " ".join(parser.title)[:300]
                result["visible_forms"] = forms
                result["login_classification"] = (
                    "email/password form pattern" if any(f["email_password_pattern"] for f in forms) else
                    "username/password form pattern" if any(f["username_password_pattern"] for f in forms) else
                    "no password-based form detected in this page; SSO/passkey/backend auth remains possible"
                )
                result["sql_injection_observation"] = "Forms and field names are identified only. SQL injection cannot be confirmed from HTML; review server-side query construction and parameter binding."
            else:
                result["body_inspection"] = "Not performed (HEAD request or non-HTML response)."
            return result
    except urllib.error.HTTPError as exc:
        return {"requested_url": url, "method": method, "status_code": exc.code,
                "response_headers": {name: exc.headers.get(name) for name in ("Location", "WWW-Authenticate", "Set-Cookie") if exc.headers.get(name)},
                "redirects_followed": False, "note": "Response metadata only; access control was not bypassed or challenged."}
    except urllib.error.URLError as exc:
        return {"requested_url": url, "method": method, "error": str(exc.reason),
                "note": "No redirect or alternative path was attempted."}


def _rdap_summary(data: dict) -> dict:
    events = {e.get("eventAction", "").lower(): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
    return {"registered_on": events.get("registration"), "expires_on": events.get("expiration"),
            "last_registry_change": events.get("last changed"),
            "last_registry_database_update": events.get("last update of rdap database"),
            "registrar_or_network_name": data.get("name"), "country": data.get("country"),
            "nameservers": [n.get("ldhName") for n in data.get("nameservers", []) if isinstance(n, dict) and n.get("ldhName")]}

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
        rdap_data = http_json("https://rdap.org/domain/" + encoded, timeout)
        result["sources"]["rdap"] = rdap_data
        events = {e.get("eventAction", "").lower(): e.get("eventDate") for e in rdap_data.get("events", []) if isinstance(e, dict)}
        result["registration_summary"] = {"registered_on": events.get("registration"), "expires_on": events.get("expiration"), "last_registry_change": events.get("last changed"), "registrar": next((e.get("vcardArray", [None, []])[1][0][3] for e in rdap_data.get("entities", []) if "registrar" in e.get("roles", []) and e.get("vcardArray") and e["vcardArray"][1]), None)}
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
    result["sources"]["public_website_profile"] = public_site_profile(domain, timeout)
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
    events = {e.get("eventAction", "").lower(): e.get("eventDate") for e in rdap.get("events", []) if isinstance(e, dict)} if isinstance(rdap, dict) else {}
    entities = rdap.get("entities", []) if isinstance(rdap, dict) else []
    network_contacts = []
    for entity in entities:
        if not isinstance(entity, dict): continue
        vcard = entity.get("vcardArray", [])
        if len(vcard) > 1 and isinstance(vcard[1], list):
            fields = {item[0]: item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] in ("fn", "org", "email", "tel")}
            if fields: network_contacts.append({"roles": entity.get("roles", []), "public_registry_contact": fields})
    summary = {"network_name": rdap.get("name") if isinstance(rdap, dict) else None, "country": rdap.get("country") if isinstance(rdap, dict) else None, "registration_date": events.get("registration"), "last_registry_change": events.get("last changed"), "network_contacts": network_contacts[:10]}
    return {"ip": str(address), "rdap_summary": summary, "rdap": rdap, "activity_visibility": {"last_connected": "Not available from public IP registration data.", "websites_visited_or_interacted_with": "Not available from RDAP or public IP ownership records.", "individual_identity": "An IP address does not reliably identify an individual; shared, dynamic and carrier-grade NAT addresses are common."}, "note": "Public network-registration intelligence, not device tracking or a person identity/location lookup."}

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
        score = severity = vector = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss = metrics[key][0].get("cvssData", {})
                score, severity, vector = cvss.get("baseScore"), cvss.get("baseSeverity"), cvss.get("vectorString")
                break
        weaknesses = sorted({d.get("value", "") for w in cve.get("weaknesses", [])
                             for d in w.get("description", []) if d.get("lang") == "en" and d.get("value")})
        references = [{"url": ref.get("url"), "tags": ref.get("tags", [])}
                      for ref in cve.get("references", [])[:12] if ref.get("url")]
        configurations = []
        for config in cve.get("configurations", [])[:8]:
            for node in config.get("nodes", [])[:8]:
                for match in node.get("cpeMatch", [])[:12]:
                    if match.get("criteria"):
                        configurations.append({
                            "criteria": match["criteria"][:300], "vulnerable": bool(match.get("vulnerable")),
                            "version_start_including": match.get("versionStartIncluding"),
                            "version_start_excluding": match.get("versionStartExcluding"),
                            "version_end_including": match.get("versionEndIncluding"),
                            "version_end_excluding": match.get("versionEndExcluding")})
        items.append({"id": cve.get("id"), "published": cve.get("published"),
                      "last_modified": cve.get("lastModified"), "status": cve.get("vulnStatus"),
                      "cvss": score, "severity": severity, "cvss_vector": vector,
                      "description": english[:1200], "weaknesses": weaknesses[:20],
                      "affected_product_configurations": configurations[:40], "references": references,
                      "assessment_note": "Search match only. Verify exact vendor, product, version, configuration and patch status before treating this CVE as applicable."})
    return {"query": term, "total_results": data.get("totalResults", 0), "results": items,
            "source": "NIST National Vulnerability Database",
            "interpretation": "CVSS severity describes a vulnerability, not the risk of a particular asset. Applicability requires exact version/configuration verification."}


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


def register_evidence(path: Path, case_id: str = "general", notes: str = "") -> dict:
    """Copy a bounded local evidence file into the evidence vault with a SHA-256 manifest."""
    from datetime import datetime, timezone
    source = path.expanduser()
    if not source.is_file() or source.is_symlink():
        raise ValueError("Evidence must be an existing regular local file, not a symbolic link.")
    size = source.stat().st_size
    if size <= 0 or size > MAX_FILE_BYTES:
        raise ValueError("Evidence must be between 1 byte and 10 MB.")
    safe_case = re.sub(r"[^a-zA-Z0-9_-]+", "-", case_id).strip("-_")[:48] or "general"
    safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", source.name)[:100] or "evidence.bin"
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = evidence_directory()
    destination = directory / f"{stamp}_{safe_case}_{safe_name}"
    if destination.exists():
        raise FileExistsError("Evidence destination already exists; retry to generate a new timestamp.")
    destination.write_bytes(data)
    manifest = {"case_id": safe_case, "evidence_file": destination.name, "original_name": source.name,
                "size_bytes": size, "sha256": digest, "registered_at_utc": stamp,
                "notes": notes[:1000], "storage": "local_only",
                "handling": "Copied as inert evidence; never executed or uploaded."}
    manifest_path = destination.with_name(destination.name + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"evidence": manifest, "manifest_path": str(manifest_path), "evidence_path": str(destination)}


def verify_evidence_integrity() -> dict:
    """Verify SHA-256 values in local evidence manifests without modifying evidence."""
    directory = evidence_directory()
    checked, valid, missing, mismatched = 0, 0, [], []
    for manifest_path in sorted(directory.glob("*.manifest.json")):
        checked += 1
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            evidence_path = directory / manifest["evidence_file"]
            if not evidence_path.is_file() or evidence_path.is_symlink():
                missing.append(manifest["evidence_file"])
                continue
            digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            if digest == manifest.get("sha256"):
                valid += 1
            else:
                mismatched.append(manifest["evidence_file"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            mismatched.append(manifest_path.name)
    return {"manifests_checked": checked, "integrity_valid": valid,
            "missing_evidence": missing, "hash_mismatches_or_invalid_manifests": mismatched,
            "note": "Integrity verification only; files are not modified, executed or uploaded."}


def show_evidence_manager() -> None:
    directory = evidence_directory()
    files = sorted((p for p in directory.iterdir() if p.is_file() and not p.name.endswith(".manifest.json")),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    print("\\nLOCAL EVIDENCE MANAGER")
    print(f"Storage: {directory}")
    print("Evidence is stored locally; manifests record SHA-256 integrity hashes.")
    if not files:
        print("No evidence files stored yet.")
    else:
        for index, item in enumerate(files[:50], 1):
            print(f"  [{index}] {item.name} ({item.stat().st_size} bytes)")
        if len(files) > 50:
            print(f"  ... and {len(files) - 50} more file(s)")
    print("  [A] Add a local evidence file")
    print("  [V] Verify evidence integrity")
    choice = input("evidence> ").strip().lower()
    if choice == "a":
        source = Path(input("Path to local evidence file: ").strip()).expanduser()
        case_id = input("Case/reference label: ").strip() or "general"
        notes = input("Evidence notes (no passwords or access tokens): ").strip()
        result = register_evidence(source, case_id, notes)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif choice == "v":
        result = verify_evidence_integrity()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        save_investigation(result, "evidence-integrity")
    elif choice:
        print("Choose A, V or press Enter to return.")


def show_connection_status() -> None:
    print("\nDEVICE CONNECTION")
    print("Remote gateway: NOT CONFIGURED")
    print("No VPS endpoint or authenticated pairing service is configured.")
    print("Device pairing and live sessions are not active yet.")
    print("This menu will become operational after the gateway and device companions are implemented.")
    print("No fake pairing link or simulated device connection has been created.")


def show_session_status() -> None:
    print("\nLIVE SESSION MANAGER")
    print("No remote session backend is configured.")
    print("Pause, resume and disconnect controls require an authenticated active session.")
    print("Configure the CyberLab gateway before starting remote sessions.")


def content_analysis_menu(timeout: int = 12) -> None:
    print("\nMALICIOUS FILE & LINK ANALYSIS")
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



def manual_security_assessment() -> dict:
    """Guide an authorised, evidence-based review without sending attack traffic."""
    print("\nMANUAL SECURITY ASSESSMENT & VERIFICATION")
    print("Use only on a system you own or are explicitly authorised to assess.")
    target = input("Application/domain or approved test environment: ").strip()[:253]
    if not target:
        raise ValueError("A target label is required.")
    authorised = input("Confirm you have permission to assess this system (yes/no): ").strip().lower()
    if authorised not in ("yes", "y"):
        raise ValueError("Assessment stopped: explicit authorisation was not confirmed.")

    print("\nSQL INJECTION — WHAT IT IS")
    print("SQL injection occurs when an application mixes untrusted input into SQL text")
    print("instead of binding that input as data. A crafted value can change query logic.")
    print("Depending on the query and database permissions, impact can include unauthorised")
    print("data access, data changes, authentication bypass or, in severe cases, server impact.")
    print("The safe fix is parameterised queries/prepared statements or correctly bound ORM inputs.")
    print("CyberLab will not submit SQL payloads, bypass a login, extract records or alter data.")

    checks = [
        ("sql_parameter_binding", "Can the relevant source code/configuration be reviewed for parameterised queries or bound ORM parameters?"),
        ("sql_string_concatenation", "Does reviewed code concatenate user-controlled input into SQL statements?"),
        ("sql_error_disclosure", "Do existing, safely collected application logs show database errors exposed to end users?"),
        ("sql_test_environment", "Has a qualified tester verified input handling in an isolated staging environment using non-destructive methods?"),
        ("rate_limit", "Is there documented and verified rate limiting or throttling on authentication?"),
        ("lockout", "Are progressive delays or account-protection controls applied after repeated failed logins?"),
        ("captcha", "Is an appropriate bot challenge applied when suspicious authentication activity is detected?"),
        ("session_secure", "Are session cookies marked Secure and served only over HTTPS?"),
        ("session_httponly", "Are session cookies marked HttpOnly?"),
        ("session_samesite", "Are session cookies configured with an appropriate SameSite policy?"),
        ("session_rotation", "Are session identifiers rotated after login and privilege changes?"),
        ("session_expiry", "Are idle and absolute session expiry enforced, with logout invalidating the session?"),
        ("admin_access", "Has the owner supplied the admin URL, and are access controls/MFA/role restrictions verified there?"),
        ("login_method", "What login method is visibly documented or confirmed by the application owner?"),
        ("breach_response", "Has the organisation checked its own addresses through an approved breach-notification service without retrieving passwords?"),
    ]
    answers = {}
    print("\nFor each check enter: yes / no / unknown / not-applicable.")
    print("Answer from code review, owner documentation or evidence you already have;")
    print("do not probe a live login or submit attack strings.")
    for key, prompt in checks:
        while True:
            answer = input(f"\n{prompt}\n  Result: ").strip().lower()
            if answer in ("yes", "y", "no", "n", "unknown", "u", "not-applicable", "na"):
                answers[key] = {"yes": "yes", "y": "yes", "no": "no", "n": "no",
                                "unknown": "unknown", "u": "unknown",
                                "not-applicable": "not_applicable", "na": "not_applicable"}[answer]
                break
            print("Enter yes, no, unknown or not-applicable.")

    page_url = input("\nOwner-approved public login/home page HTTPS URL (optional): ").strip()[:1000]
    page_inspection = None
    if page_url:
        page_inspection = inspect_assessment_page(page_url, method="GET")
        print("\nPASSIVE PAGE INSPECTION")
        print(json.dumps(page_inspection, indent=2, ensure_ascii=False))
    admin_url = input("\nOwner-provided admin panel HTTPS URL (optional; HEAD metadata only): ").strip()[:1000]
    admin_inspection = inspect_assessment_page(admin_url, method="HEAD") if admin_url else None
    if admin_inspection:
        print("\nADMIN URL RESPONSE METADATA")
        print(json.dumps(admin_inspection, indent=2, ensure_ascii=False))
    login_method = (
        page_inspection.get("login_classification", "unknown") if page_inspection else
        input("Login method (email/password, username/password, SSO, passkey, mixed, unknown): ").strip()[:100] or "unknown"
    )
    evidence = input("Evidence notes (no passwords, tokens or personal records): ").strip()[:2000]
    findings = []
    if answers["sql_string_concatenation"] == "yes":
        findings.append({"area": "SQL injection", "status": "potential",
                         "severity": "high",
                         "detail": "Reviewed code appears to concatenate user-controlled input into SQL. Confirm the data flow and query construction in an isolated authorised review; do not infer exploitability from this indicator alone.",
                         "remediation": "Replace dynamic concatenation with parameterised queries/prepared statements or safely bound ORM parameters; use least-privilege database accounts and generic client-facing errors."})
    elif answers["sql_parameter_binding"] == "yes" and answers["sql_string_concatenation"] == "no":
        findings.append({"area": "SQL injection", "status": "not_detected",
                         "severity": "informational",
                         "detail": "The reviewed code indicates parameter binding and no concatenation in the reviewed path. This does not prove every query path is safe.",
                         "remediation": "Extend code review to all input-to-query paths and retain regression tests."})
    else:
        findings.append({"area": "SQL injection", "status": "inconclusive",
                         "severity": "unknown",
                         "detail": "There is not enough source or staging evidence to determine whether SQL injection is present.",
                         "remediation": "Review query construction and verify parameter binding in an isolated staging environment."})
    mapping = [
        ("rate_limit", "Authentication rate limiting"),
        ("lockout", "Account lockout / progressive delay"),
        ("captcha", "Adaptive bot protection"),
        ("session_secure", "Secure session cookie"),
        ("session_httponly", "HttpOnly session cookie"),
        ("session_samesite", "SameSite session cookie"),
        ("session_rotation", "Session rotation"),
        ("session_expiry", "Session expiry and invalidation"),
        ("admin_access", "Owner-provided admin access controls"),
        ("breach_response", "Organisation-owned email exposure review"),
    ]
    for key, label in mapping:
        status = "confirmed" if answers[key] == "yes" else ("potential" if answers[key] == "no" else ("not_applicable" if answers[key] == "not_applicable" else "inconclusive"))
        findings.append({"area": label, "status": status, "detail": "Self-reported/manual evidence; not independently tested."})
    return {
        "assessment": "Manual Security Assessment & Verification",
        "target": target,
        "authorisation_confirmed_by_operator": True,
        "login_method": login_method,
        "page_inspection": page_inspection,
        "owner_provided_admin_url": admin_url or None,
        "admin_response_inspection": admin_inspection,
        "checks": answers,
        "findings": findings,
        "evidence_notes": evidence,
        "method": "One GET to the explicitly supplied HTTPS page and one HEAD to the owner-provided admin URL when supplied, plus operator-led checklist. No redirects followed, forms submitted, payloads sent, login attempts, endpoint discovery or account lookups were performed.",
        "sql_injection_explanation": {
            "cause": "Untrusted input is concatenated into SQL text instead of being passed separately as a bound parameter.",
            "impact": ["Potential unauthorised data access", "Potential data modification or deletion", "Potential authentication bypass", "In severe configurations, broader server impact"],
            "safe_remediation": ["Use parameterised queries/prepared statements", "Use correctly bound ORM parameters", "Apply least-privilege database permissions", "Avoid exposing database errors to users", "Add regression tests for every query path"]
        },
        "limitations": ["A checklist is not a penetration test.", "No automated brute-force, SQL injection payloads, session hijacking, hidden-path enumeration or credential harvesting is performed. Rate-limit/lockout protections, session rotation/expiry and server-side admin authorization still require source/configuration review or owner-provided evidence; a single page response cannot prove them.", "Unknown and inconclusive results must not be represented as secure or vulnerable."]
    }



def audit_password_strength(password: str) -> dict:
    """Return password quality signals without retaining or returning the password."""
    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty password is required.")
    length = len(password)
    classes = {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digits": any(c.isdigit() for c in password),
        "symbols": any(not c.isalnum() for c in password),
    }
    score = sum(classes.values()) + (1 if length >= 12 else 0) + (1 if length >= 16 else 0)
    common_patterns = [
        bool(re.search(r"(.)\1{3,}", password)),
        bool(re.search(r"(?i)(password|qwerty|letmein|welcome|admin|123456)", password)),
        bool(re.search(r"^(?:\d+|[a-z]+)$", password, re.I)),
    ]
    recommendations = []
    if length < 14: recommendations.append("Use at least 14 characters; a longer unique passphrase is better.")
    if not classes["lowercase"] or not classes["uppercase"] or not classes["digits"] or not classes["symbols"]:
        recommendations.append("Prefer a long, unique password or passphrase; include varied character types if required by policy.")
    if any(common_patterns): recommendations.append("Avoid common words, predictable sequences and repeated characters.")
    recommendations.append("Use a password manager and never reuse passwords across services.")
    return {"length": length, "character_classes": classes, "quality_band": "stronger" if score >= 6 and not any(common_patterns) else ("moderate" if score >= 4 else "weak"),
            "risk_signals": {"long_repeated_character_run": common_patterns[0], "common_word_or_sequence": common_patterns[1], "only_letters_or_digits": common_patterns[2]},
            "recommendations": recommendations,
            "privacy": "The password value is not included in this result or saved to an investigation report."}


def review_password_storage(algorithm: str, salt: str, work_factor: str) -> dict:
    """Review operator-supplied password-storage metadata; never accepts hashes."""
    alg = algorithm.strip().lower()
    known_weak = {"md5", "sha1", "sha-1", "sha256", "sha-256", "plain", "plaintext", "unsalted-sha256"}
    modern = {"argon2id", "scrypt", "bcrypt", "pbkdf2-sha256"}
    if not alg: raise ValueError("Enter the password-storage algorithm name.")
    status = "needs_review"
    if alg in known_weak: status = "weak_or_inappropriate"
    elif alg in modern: status = "modern_family_check_parameters"
    return {"algorithm": alg, "salted": salt.strip().lower() in ("yes", "y", "true"),
            "work_factor_or_parameters_documented": bool(work_factor.strip()),
            "status": status,
            "recommendations": ["Prefer Argon2id where supported; otherwise evaluate scrypt, bcrypt or PBKDF2 with current parameters.",
                                "Use a unique per-password salt generated by a vetted password-hashing library.",
                                "Never use plain SHA-256/MD5/SHA-1 as a password hashing scheme.",
                                "Do not paste password hashes or plaintext passwords into CyberLab; review metadata only."]}


def review_authentication_policy(rate_limit: str, lockout: str, mfa: str, breached: str, reset: str) -> dict:
    fields = {"rate_limiting": rate_limit, "progressive_delay_or_lockout": lockout,
              "mfa": mfa, "breached_password_blocklist": breached, "secure_reset_flow": reset}
    normal = {k: v.strip().lower() for k, v in fields.items()}
    findings = []
    for key, value in normal.items():
        status = "implemented_reported" if value in ("yes", "y") else ("gap_reported" if value in ("no", "n") else "unknown")
        findings.append({"control": key, "status": status})
    return {"controls": findings, "note": "Operator-reported configuration review only; CyberLab did not submit authentication requests or independently verify controls."}


def analyse_auth_log(path: Path) -> dict:
    """Summarise locally supplied auth logs without attempting authentication."""
    if not path.is_file(): raise ValueError("Select an existing local log file.")
    if path.stat().st_size > 5 * 1024 * 1024: raise ValueError("Log file exceeds the 5 MB analysis limit.")
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines()
    failed = [line for line in lines if re.search(r"(?i)(failed password|authentication failure|login failed|invalid user|failed login)", line)]
    success = [line for line in lines if re.search(r"(?i)(accepted password|authentication success|login successful)", line)]
    sources = Counter()
    for line in failed:
        match = re.search(r"(?i)\bfrom\s+([0-9a-f:.]+)", line)
        if match: sources[match.group(1)] += 1
    return {"file_name": path.name, "lines_reviewed": len(lines), "failed_authentication_indicators": len(failed),
            "successful_authentication_indicators": len(success), "source_addresses_in_failed_lines": sources.most_common(20),
            "sample_failed_lines_redacted": [re.sub(r"(?i)(password|token|secret)=\S+", r"\1=[REDACTED]", line)[:240] for line in failed[:10]],
            "note": "Local log pattern analysis only. Counts may include false positives; no login attempts or network connections were made."}


def password_authentication_menu() -> dict:
    print("\nPASSWORD & AUTHENTICATION SECURITY")
    print("  [1] Check a password's strength locally (input is not saved)")
    print("  [2] Generate a strong password for a NEW account/reset")
    print("  [3] Create labelled usernames for YOUR test accounts")
    print("  [4] Review password-storage algorithm metadata")
    print("  [5] Review authentication defence controls")
    print("  [6] Analyse a local authentication log")
    print("  [0] Back")
    choice = input("password-audit> ").strip()
    if choice == "1":
        password = getpass.getpass("Password to assess (hidden; not saved): ")
        try: result = audit_password_strength(password)
        finally: password = None
    elif choice == "2":
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        generated = "".join(secrets.choice(alphabet) for _ in range(24))
        print("\nGenerated password for setting a NEW account credential (shown once):")
        print(generated)
        print("Save it directly in your password manager. It is not added to the report.")
        return {"feature": "new_account_password_generation", "length": 24, "plaintext_saved": False}
    elif choice == "3":
        prefix = re.sub(r"[^a-z0-9_-]", "", input("Short label for your own lab (e.g. blue-team): ").lower())[:16].strip("-_")
        if not prefix: raise ValueError("A simple lab label is required.")
        count = int(input("Number of test-account labels (1-20): ").strip())
        if not 1 <= count <= 20: raise ValueError("Choose between 1 and 20.")
        names = [f"{prefix}-test-{i:02d}" for i in range(1, count + 1)]
        print("For provisioning your own lab accounts only; these are not guesses for existing users.")
        return {"feature": "lab_test_account_labels", "usernames": names}
    elif choice == "4":
        result = review_password_storage(input("Algorithm name (e.g. argon2id, bcrypt, SHA-256): "),
                                         input("Unique per-password salt used? (yes/no/unknown): "),
                                         input("Work factor/parameters documented? (yes/no/unknown): "))
    elif choice == "5":
        result = review_authentication_policy(input("Rate limiting enabled? yes/no/unknown: "),
                                              input("Progressive delay/lockout enabled? yes/no/unknown: "),
                                              input("MFA enforced where appropriate? yes/no/unknown: "),
                                              input("Breached-password blocklist used? yes/no/unknown: "),
                                              input("Secure password reset flow? yes/no/unknown: "))
    elif choice == "6":
        result = analyse_auth_log(Path(input("Path to local auth log (max 5 MB): ").strip()).expanduser())
    elif choice == "0":
        return {}
    else:
        raise ValueError("Choose one of the listed options.")
    return result



def classify_hash_inventory(path: Path) -> dict:
    """Count local hash-format indicators without retaining hashes or attempting cracks."""
    if not path.is_file():
        raise ValueError("Select an existing local hash-inventory file.")
    if path.stat().st_size > 5 * 1024 * 1024:
        raise ValueError("Hash inventory exceeds the 5 MB analysis limit.")
    counts = Counter()
    total = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            total += 1
            if value.startswith("$argon2id$") or value.startswith("$argon2i$"):
                kind = "Argon2"
            elif value.startswith(("$2a$", "$2b$", "$2y$")):
                kind = "bcrypt"
            elif value.startswith("$pbkdf2-") or value.startswith("pbkdf2:"):
                kind = "PBKDF2"
            elif re.fullmatch(r"[0-9a-fA-F]{32}", value):
                kind = "32-character hex (MD5-like; ambiguous)"
            elif re.fullmatch(r"[0-9a-fA-F]{40}", value):
                kind = "40-character hex (SHA-1-like; ambiguous)"
            elif re.fullmatch(r"[0-9a-fA-F]{64}", value):
                kind = "64-character hex (SHA-256-like; ambiguous)"
            else:
                kind = "unclassified"
            counts[kind] += 1
    return {
        "file_name": path.name,
        "nonempty_records_reviewed": total,
        "format_counts": dict(counts),
        "hash_values_saved": False,
        "cracking_attempted": False,
        "note": "Metadata-only format classification. Hex lengths are ambiguous; no hash values are returned, stored in the report, or tested against passwords."
    }


def scam_investigation_menu(timeout: int = 12) -> dict:
    """Collect public scam-site intelligence and locally supplied evidence."""
    print("\\nLAW ENFORCEMENT & SCAM INVESTIGATION")
    print("Use only public information and evidence you are legally authorised to handle.")
    print("This module does not access accounts, bypass logins or impersonate anyone.")
    print("  [1] Public scam-website intelligence (RDAP, DNS, certificates, homepage)")
    print("  [2] Inspect one explicitly supplied public HTTPS page (read-only)")
    print("  [3] Analyse a local authentication log (Hydra-style defence review)")
    print("  [4] Classify a local password-hash inventory (John-style metadata only)")
    print("  [5] Record an evidence note")
    print("  [0] Back")
    choice = input("scam-investigation> ").strip()
    if choice == "1":
        domain = validate_domain(input("Public website domain: "))
        result = domain_osint(domain, timeout)
        result["investigation_type"] = "public_scam_website_intelligence"
        result["scope_note"] = "Public records and the supplied domain's homepage only; no account access or active probing."
    elif choice == "2":
        print("Only inspect a page you are authorised to review. One HTTPS GET; redirects are not followed.")
        url = input("Explicit page HTTPS URL: ").strip()[:1000]
        result = inspect_assessment_page(url, timeout=timeout, method="GET")
        result["investigation_type"] = "read_only_authentication_surface_review"
    elif choice == "3":
        path = Path(input("Path to locally acquired authentication log (max 5 MB): ").strip()).expanduser()
        result = analyse_auth_log(path)
        result["investigation_type"] = "offline_authentication_abuse_detection"
        result["interpretation"] = "Repeated failures can indicate password spraying or brute-force activity; correlate with provider logs, timestamps and known NAT/VPN infrastructure before attribution."
    elif choice == "4":
        print("Use only an authorised inventory. Do not provide stolen or third-party credential dumps.")
        path = Path(input("Path to authorised local hash inventory (max 5 MB): ").strip()).expanduser()
        result = classify_hash_inventory(path)
        result["investigation_type"] = "offline_hash_format_inventory"
    elif choice == "5":
        note = input("Evidence note (no passwords, tokens or unnecessary personal data): ").strip()[:3000]
        source = input("Source URL or local evidence reference: ").strip()[:1000]
        result = {"investigation_type": "evidence_note", "note": note, "source_reference": source,
                  "recorded_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                  "handling": "Locally recorded; preserve original evidence separately and document chain of custody."}
    elif choice == "0":
        return {}
    else:
        raise ValueError("Choose one of the listed options.")
    return result

def interactive_menu(timeout: int = 12) -> int:
    """Run the local-first CyberLab operations menu."""
    services = {
        "1": ("Domain OSINT", "domain"),
        "2": ("DNS intelligence", "dns"),
        "4": ("Public IP intelligence", "ip"),
        "5": ("CVE research", "cve"),
        "6": ("Static file triage", "triage"),
        "7": ("Nmap XML analysis", "nmap-xml"),
    }
    while True:
        print("\nCYBERLAB AI")
        print("     SECURITY OPERATIONS\n")
        print("  [1] Domain OSINT")
        print("  [2] DNS Intelligence")
        print("  [3] Manual Security Assessment & Verification")
        print("  [4] IP Intelligence")
        print("  [5] CVE Research")
        print("  [6] File Triage")
        print("  [7] Nmap XML Analysis")
        print("  [8] Malicious File & Link Analysis")
        print("  [9] Connect Device")
        print("  [10] Connected Devices")
        print("  [11] Manage Live Sessions")
        print("  [12] Evidence Manager")
        print("  [13] Investigation Reports")
        print("  [14] Password & Authentication Security")
        print("  [15] Law Enforcement & Scam Investigation")
        print("  [0] Exit")
        try:
            choice = input("\ncyberlab> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting CyberLab.")
            return 0
        if choice == "0":
            print("CyberLab closed.")
            return 0
        if choice == "15":
            try:
                result = scam_investigation_menu(timeout)
                if result:
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                    destination = save_investigation(result, "scam-investigation")
                    print(f"\\nSaved locally: {destination}")
            except (OSError, ValueError) as exc:
                print(f"Investigation failed: {exc}")
            continue
        if choice == "3":
            try:
                result = manual_security_assessment()
                print(json.dumps(result, indent=2, ensure_ascii=False))
                destination = save_investigation(result, "manual-security-assessment")
                print(f"\nSaved locally: {destination}")
            except (OSError, ValueError) as exc:
                print(f"Assessment stopped: {exc}")
            continue
        if choice == "8":
            content_analysis_menu(timeout)
            continue
        if choice in ("9", "10"):
            show_connection_status()
            continue
        if choice == "11":
            show_session_status()
            continue
        if choice == "12":
            show_evidence_manager()
            continue
        if choice == "13":
            show_investigation_history()
            continue
        if choice == "14":
            try:
                result = password_authentication_menu()
                if result:
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                    if result.get("feature") != "new_account_password_generation":
                        destination = save_investigation(result, "password-authentication-security")
                        print(f"\nSaved locally: {destination}")
            except (OSError, ValueError) as exc:
                print(f"Password audit stopped: {exc}")
            except (EOFError, KeyboardInterrupt):
                print("\nReturning to the CyberLab menu.")
            continue
        if choice not in services:
            print("Choose one of the listed options.")
            continue

        label, command = services[choice]
        try:
            if command == "domain":
                result = domain_osint(input("Public domain: ").strip(), timeout)
            elif command == "dns":
                domain = input("Public domain: ").strip()
                result = dns_lookup(domain, timeout)
                result["public_website_profile"] = public_site_profile(validate_domain(domain), timeout)
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
            print(f"\nSaved locally: {destination}")
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            print(f"\nOperation failed: {exc}")
        except (EOFError, KeyboardInterrupt):
            print("\nReturning to the CyberLab menu.")

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
