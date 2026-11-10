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
import os
import re
import socket
import sys
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from camera_intelligence import camera_intelligence_menu

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
    strings = re.findall(rb"[\x20-\x7e]{5,}", data)
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
        self.scripts = []
        self.forms = []
        self.form = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self.in_title = True
        if tag == "meta":
            key = (a.get("name") or a.get("property") or "").lower()
            if key in ("description", "og:description", "og:site_name", "generator",
                       "csrf-token", "csrf-param", "viewport"):
                self.meta[key] = a.get("content", "")[:500]
        if tag == "a" and a.get("href"):
            self.links.append(a["href"][:1000])
        if tag == "script":
            if a.get("src"):
                self.scripts.append({"src": a["src"][:1000], "type": a.get("type", "")[:100],
                                     "integrity_present": bool(a.get("integrity")),
                                     "crossorigin": a.get("crossorigin", "")[:50]})
        if tag == "form":
            self.form = {"method": a.get("method", "get").lower(),
                         "action": a.get("action", ""), "enctype": a.get("enctype", ""),
                         "autocomplete": a.get("autocomplete", ""),
                         "fields": []}
            self.forms.append(self.form)
        if tag in ("input", "button", "select", "textarea") and self.form is not None:
            self.form["fields"].append({
                "tag": tag, "type": a.get("type", "text" if tag == "input" else tag).lower(),
                "name": a.get("name", "")[:100], "autocomplete": a.get("autocomplete", "")[:100],
                "required": "required" in a, "disabled": "disabled" in a,
                "value_present": bool(a.get("value")),
            })

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag == "form":
            self.form = None

    def handle_data(self, data):
        if self.in_title and data.strip():
            self.title.append(data.strip())


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
            social_hosts = ("facebook.com", "instagram.com", "linkedin.com", "x.com", "twitter.com", "youtube.com", "tiktok.com", "github.com", "slack.com", "discord.com")
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
            availability_headers = {n: headers.get(n) for n in ("Retry-After", "RateLimit-Limit", "RateLimit-Remaining", "X-RateLimit-Limit", "X-RateLimit-Remaining", "Server", "Via", "CF-Ray", "X-CDN") if headers.get(n)}
            cdn_indicators = [name for name, value in (("Cloudflare", headers.get("CF-Ray") or headers.get("Server", "").lower().startswith("cloudflare")), ("Via proxy", headers.get("Via")), ("CDN header", headers.get("X-CDN"))) if value]
            organisation = parser.meta.get("og:site_name", "")
            address_values = sorted(set(re.findall(r"(?i)\b\d{1,6}\s+[\w .'-]{2,60}\b(?:street|st|road|rd|avenue|ave|drive|dr|lane|ln|boulevard|blvd|suite|way)\b[^<\n]{0,80}", raw.decode("utf-8", errors="ignore"))))[:10]
            location_values = sorted(set(re.findall(r"(?i)\b(?:location|address|headquarters|based in)\b\s*[:\-]?\s*([^<\n]{3,100})", raw.decode("utf-8", errors="ignore"))))[:10]
            return {"status": "ok", "page_title": " ".join(parser.title)[:300], "description": parser.meta.get("description") or parser.meta.get("og:description", ""), "generator": parser.meta.get("generator", ""), "site_name": organisation, "organisation_name": organisation, "public_address": address_values, "public_location": location_values, "public_contact_emails": emails, "public_contact_phone_numbers": phones, "social_media_links": sorted(set(socials))[:50], "visible_forms": forms, "security_headers_present": sec, "security_headers_missing": [n for n in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy") if n not in sec], "availability_headers": availability_headers, "cdn_indicators": cdn_indicators, "ai_build_assessment": "Inconclusive; public HTML alone cannot reliably establish AI authorship.", "limitations": ["Only the HTTPS home page was fetched.", "No hidden-path enumeration, login attempts, form submissions or exploit tests were performed.", "Visible form fields do not prove the authentication backend or its security.", "Company, address and location extraction is heuristic and may be incomplete or incorrect; verify against authoritative sources."]}
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


def _tls_certificate_summary(host: str, port: int, timeout: int = 12) -> dict:
    """Read the public TLS certificate and negotiated protocol without sending HTTP data."""
    import ssl
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert()
                sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"][:30]
                subject = {key: value for group in cert.get("subject", ()) for key, value in group}
                issuer = {key: value for group in cert.get("issuer", ()) for key, value in group}
                not_after = cert.get("notAfter")
                import datetime
                expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=datetime.timezone.utc) if not_after else None
                days_left = (expires - datetime.datetime.now(datetime.timezone.utc)).days if expires else None
                return {
                    "status": "validated", "protocol": tls_socket.version(),
                    "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                    "certificate_subject": subject, "certificate_issuer": issuer,
                    "subject_alternative_names": sans,
                    "not_before": cert.get("notBefore"), "not_after": not_after,
                    "days_until_expiry": days_left,
                    "hostname_match_and_trust": True,
                    "note": "Certificate was validated by the local trusted CA store during a TLS handshake; this does not test application authentication."
                }
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"status": "unavailable_or_invalid", "error": str(exc),
                "hostname_match_and_trust": False,
                "note": "TLS certificate validation could not be completed; review the reported error."}


def _analyse_login_forms(forms: list, page_url: str) -> dict:
    base = urllib.parse.urlsplit(page_url)
    analysed = []
    for index, form in enumerate(forms[:20], 1):
        fields = form.get("fields", [])
        types = sorted({field.get("type", "") for field in fields})
        names = [field.get("name", "").lower() for field in fields if field.get("name")]
        password_fields = [field for field in fields if field.get("type") == "password"]
        hidden_fields = [field for field in fields if field.get("type") == "hidden"]
        email_fields = [field for field in fields if field.get("type") == "email" or "email" in field.get("name", "").lower()]
        username_fields = [field for field in fields if any(term in field.get("name", "").lower()
                            for term in ("user", "login", "account", "identifier"))]
        csrf_names = [field.get("name") for field in hidden_fields
                      if any(term in field.get("name", "").lower() for term in ("csrf", "token", "authenticity"))]
        action = urllib.parse.urljoin(page_url, form.get("action") or page_url)
        action_parts = urllib.parse.urlsplit(action)
        same_origin = (action_parts.scheme == base.scheme and action_parts.hostname == base.hostname
                       and action_parts.port == base.port)
        autocomplete_values = sorted({field.get("autocomplete", "").lower() for field in fields
                                      if field.get("autocomplete")})
        auth_likely = bool(password_fields or email_fields or username_fields)
        analysed.append({
            "form_number": index, "method": form.get("method", "get").upper(),
            "action_url": action[:500], "action_same_origin": same_origin,
            "enctype": form.get("enctype") or "application/x-www-form-urlencoded (browser default)",
            "form_autocomplete": form.get("autocomplete") or "browser default",
            "input_types": types, "field_names": names[:30],
            "password_field_count": len(password_fields), "email_field_count": len(email_fields),
            "username_like_field_count": len(username_fields), "hidden_field_count": len(hidden_fields),
            "csrf_or_token_field_names": csrf_names[:10],
            "autocomplete_values": autocomplete_values,
            "required_field_count": sum(1 for field in fields if field.get("required")),
            "authentication_form_likely": auth_likely,
            "security_observations": [
                *([] if not password_fields else ["Password input is present; this does not prove password handling or storage is secure."]),
                *([] if not password_fields or csrf_names else ["No clearly named CSRF/token hidden field was observed; frameworks may use another mechanism or JavaScript/header token."]),
                *([] if same_origin else ["Form action is cross-origin or could not be matched to the page origin; verify that this is intentional."]),
                *([] if form.get("method", "get").lower() == "post" else (["Authentication-like form uses GET; query-string exposure risk should be reviewed."] if auth_likely else [])),
            ]
        })
    auth_forms = [form for form in analysed if form["authentication_form_likely"]]
    return {
        "forms_found": len(forms), "forms_analysed": analysed,
        "authentication_form_count": len(auth_forms),
        "login_classification": (
            "password-based authentication form observed" if any(x["password_field_count"] for x in auth_forms)
            else "authentication-like form observed; password input not present"
            if auth_forms else "no authentication form identified in returned HTML; JavaScript/SSO/passkey flows may be rendered later"
        ),
        "csrf_token_field_observed": any(x["csrf_or_token_field_names"] for x in analysed),
        "note": "Only static HTML form structure is inspected. No form is submitted and CSRF enforcement is not tested."
    }


def inspect_assessment_page(value: str, timeout: int = 12, method: str = "GET") -> dict:
    """Perform bounded read-only analysis of one explicitly supplied public HTTPS page."""
    url = _validate_assessment_url(value)
    if method not in ("GET", "HEAD"):
        raise ValueError("Only GET and HEAD metadata inspection are supported.")
    parsed_url = urllib.parse.urlsplit(url)
    host = parsed_url.hostname
    port = parsed_url.port or 443
    tls = _tls_certificate_summary(host, port, timeout)
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, method=method, headers={
        "User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"
    })
    try:
        with opener.open(request, timeout=timeout) as response:
            headers = response.headers
            security_names = (
                "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
                "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
                "Cross-Origin-Embedder-Policy"
            )
            result = {
                "requested_url": url, "method": method, "status_code": response.status,
                "final_url": response.geturl(), "content_type": headers.get("Content-Type", ""),
                "server_header": headers.get("Server"),
                "security_headers": {name: headers.get(name) for name in security_names if headers.get(name)},
                "security_headers_missing": [name for name in security_names if not headers.get(name)],
                "response_headers": {name: headers.get(name) for name in (
                    "Retry-After", "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset",
                    "X-RateLimit-Limit", "X-RateLimit-Remaining", "WWW-Authenticate"
                ) if headers.get(name)},
                "set_cookie_headers": headers.get_all("Set-Cookie", [])[:30],
                "redirects_followed": False, "tls_certificate": tls,
            }
            cookies = []
            for raw_cookie in result["set_cookie_headers"]:
                first = raw_cookie.split(";", 1)[0]
                attrs = [part.strip() for part in raw_cookie.split(";")[1:]]
                attr_names = {part.split("=", 1)[0].strip().lower() for part in attrs}
                cookies.append({
                    "name": first.split("=", 1)[0][:100],
                    "secure": "secure" in attr_names, "httponly": "httponly" in attr_names,
                    "samesite": next((part.split("=", 1)[1].strip() for part in attrs if part.lower().startswith("samesite=")), None),
                    "path": next((part.split("=", 1)[1].strip() for part in attrs if part.lower().startswith("path=")), None),
                    "max_age": next((part.split("=", 1)[1].strip() for part in attrs if part.lower().startswith("max-age=")), None),
                    "expires_present": any(part.lower().startswith("expires=") for part in attrs),
                })
            result["cookies"] = cookies
            result["cookie_note"] = "Only cookies set by this response are visible; session rotation, server-side expiry and logout invalidation require authenticated owner-side tests."
            if method == "GET" and "html" in headers.get("Content-Type", "").lower():
                raw = response.read(1000001)
                truncated = len(raw) > 1000000
                raw = raw[:1000000]
                html = raw.decode(headers.get_content_charset() or "utf-8", errors="replace")
                parser = _PageMetadata()
                parser.feed(html)
                forms = _analyse_login_forms(parser.forms, url)
                scripts = []
                for item in parser.scripts[:50]:
                    script_url = urllib.parse.urljoin(url, item["src"])
                    script_parts = urllib.parse.urlsplit(script_url)
                    scripts.append({**item, "same_origin": script_parts.hostname == parsed_url.hostname,
                                    "url": script_url[:500]})
                mixed_content = sorted(set(re.findall(r"""(?:src|href)\s*=\s*["'](http://[^"']+)["']""", html, re.I)))[:30]
                result.update({
                    "page_title": " ".join(parser.title)[:300],
                    "page_metadata": parser.meta,
                    "visible_forms": parser.forms[:20],
                    "authentication_analysis": forms,
                    "login_classification": forms["login_classification"],
                    "scripts": scripts,
                    "external_script_count": sum(1 for item in scripts if not item["same_origin"]),
                    "scripts_without_subresource_integrity": [item["url"] for item in scripts
                        if not item["same_origin"] and not item["integrity_present"]][:30],
                    "mixed_content_http_references": mixed_content,
                    "html_truncated_at_1mb": truncated,
                    "csrf_meta_tag_observed": bool(parser.meta.get("csrf-token") or parser.meta.get("csrf-param")),
                    "sql_injection_observation": "SQL injection cannot be established from HTML. Review server-side query construction, parameter binding and ORM usage in source code."
                })
            else:
                result["body_inspection"] = "Not performed (HEAD request or non-HTML response)."
            findings = []
            for name in result["security_headers_missing"]:
                findings.append({"severity": "low", "area": "HTTP response hardening",
                                 "finding": name + " was not observed on this response.",
                                 "confidence": "observed_absence_on_one_response"})
            if tls.get("status") != "validated":
                findings.append({"severity": "high", "area": "TLS certificate",
                                 "finding": "TLS certificate validation did not complete successfully.",
                                 "evidence": tls.get("error", tls.get("status"))})
            elif isinstance(tls.get("days_until_expiry"), int) and tls["days_until_expiry"] < 21:
                findings.append({"severity": "medium", "area": "TLS certificate",
                                 "finding": "Certificate expires within 21 days.",
                                 "days_until_expiry": tls["days_until_expiry"]})
            for cookie in cookies:
                if not cookie["secure"] or not cookie["httponly"]:
                    findings.append({"severity": "medium", "area": "Cookie attributes",
                                     "finding": "Cookie " + cookie["name"] + " lacks " +
                                     ", ".join(name for name, present in (("Secure", cookie["secure"]),
                                     ("HttpOnly", cookie["httponly"])) if not present) + ".",
                                     "confidence": "observed_cookie_attribute"})
            if result.get("mixed_content_http_references"):
                findings.append({"severity": "medium", "area": "Mixed content",
                                 "finding": "The HTML references HTTP resources from an HTTPS page.",
                                 "evidence_count": len(result["mixed_content_http_references"])})
            for form in forms["forms_analysed"]:
                for observation in form["security_observations"]:
                    findings.append({"severity": "medium" if "cross-origin" in observation or "GET;" in observation else "info",
                                     "area": "Authentication form", "finding": observation,
                                     "form_number": form["form_number"]})
            if any(item["password_field_count"] for item in forms["forms_analysed"]):
                findings.append({"severity": "info", "area": "Authentication form",
                                 "finding": "Password input observed. Password validation, storage, MFA, throttling and account recovery are server-side controls and remain unverified."})
            if not result.get("response_headers", {}).keys() & {"RateLimit-Limit", "RateLimit-Remaining", "X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"}:
                findings.append({"severity": "info", "area": "Rate limiting",
                                 "finding": "No rate-limit header observed on this single GET. This is not evidence that authentication throttling is absent."})
            result["evidence_based_findings"] = findings
            result["unverified_controls"] = [
                "Password validation and storage", "SQL injection resistance and server-side parameter binding",
                "Rate limiting and progressive delay", "Account lockout and enumeration resistance",
                "MFA enforcement and recovery controls", "Session rotation, expiry and logout invalidation",
                "Authorisation and role-based access control", "CSRF enforcement on state-changing requests"
            ]
            result["assessment_summary"] = {
                "forms_observed": len(parser.forms) if method == "GET" and "html" in headers.get("Content-Type", "").lower() else 0,
                "authentication_forms_observed": forms["authentication_form_count"] if method == "GET" and "html" in headers.get("Content-Type", "").lower() else 0,
                "findings_count": len(findings),
                "scope": "One GET/HEAD request to the exact supplied page plus one TLS handshake; no crawling or authentication attempts."
            }
            return result
    except urllib.error.HTTPError as exc:
        return {"requested_url": url, "method": method, "status_code": exc.code,
                "tls_certificate": tls,
                "response_headers": {name: exc.headers.get(name) for name in (
                    "Location", "WWW-Authenticate", "Set-Cookie", "Retry-After",
                    "RateLimit-Limit", "RateLimit-Remaining", "X-RateLimit-Limit",
                    "X-RateLimit-Remaining") if exc.headers.get(name)},
                "redirects_followed": False,
                "note": "Response metadata only; access control was not bypassed or challenged."}
    except urllib.error.URLError as exc:
        return {"requested_url": url, "method": method, "tls_certificate": tls,
                "error": str(exc.reason), "note": "No redirect or alternative path was attempted."}


def _rdap_summary(data: dict) -> dict:
    events = {e.get("eventAction", "").lower(): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
    return {"registered_on": events.get("registration"), "expires_on": events.get("expiration"),
            "last_registry_change": events.get("last changed"),
            "last_registry_database_update": events.get("last update of rdap database"),
            "registrar_or_network_name": data.get("name"), "country": data.get("country"),
            "nameservers": [n.get("ldhName") for n in data.get("nameservers", []) if isinstance(n, dict) and n.get("ldhName")]}

def _dns_over_https(query_name: str, query_type: str, timeout: int = 12) -> dict:
    """Query public DNS JSON endpoints with a fallback; returns normalised DNS JSON."""
    failures = []
    endpoints = (
        ("https://cloudflare-dns.com/dns-query?", {"Accept": "application/dns-json"}),
        ("https://dns.google/resolve?", {"Accept": "application/json"}),
    )
    for endpoint, headers in endpoints:
        url = endpoint + urllib.parse.urlencode({"name": query_name, "type": query_type})
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read(500001)
                if len(payload) > 500000:
                    raise ValueError("DNS response exceeded the 500 KB limit.")
                data = json.loads(payload.decode("utf-8"))
                return {"status": data.get("Status"), "answers": [
                    {"ttl": row.get("TTL"), "value": row.get("data", "")}
                    for row in data.get("Answer", []) if isinstance(row, dict)
                ], "resolver": endpoint.split("/")[2]}
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            failures.append(endpoint.split("/")[2] + ": " + str(exc))
    raise ValueError("All public DNS resolvers failed: " + " | ".join(failures))


def dns_lookup(domain: str, timeout: int = 12) -> dict:
    domain = validate_domain(domain)
    output = {}
    queries = (("A", domain), ("AAAA", domain), ("MX", domain), ("NS", domain),
               ("TXT", domain), ("DMARC", "_dmarc." + domain), ("CAA", domain))
    for record, query_name in queries:
        query_type = "TXT" if record == "DMARC" else record
        try:
            output[record] = {"query_name": query_name, **_dns_over_https(query_name, query_type, timeout)}
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            output[record] = {"query_name": query_name, "error": str(exc)}
    return {"domain": domain, "records": output, "source": "Cloudflare DNS-over-HTTPS with Google DNS fallback"}


def _email_security_findings(domain: str, records: dict, submitted_email: str | None = None) -> dict:
    """Summarise public mail-routing and sender-policy signals; never verify a mailbox."""
    mx = records.get("MX", {}).get("answers", [])
    txt = records.get("TXT", {}).get("answers", [])
    dmarc_answers = records.get("DMARC", {}).get("answers", [])
    spf_records = [str(row.get("value", "")) for row in txt if "v=spf1" in str(row.get("value", "")).lower()]
    dmarc_records = [str(row.get("value", "")) for row in dmarc_answers if "v=dmarc1" in str(row.get("value", "")).lower()]
    spf_qualifiers = []
    for record in spf_records:
        if record.rstrip().endswith("-all"):
            spf_qualifiers.append("hard_fail")
        elif record.rstrip().endswith("~all"):
            spf_qualifiers.append("soft_fail")
        elif record.rstrip().endswith("?all"):
            spf_qualifiers.append("neutral")
        elif record.rstrip().endswith("+all"):
            spf_qualifiers.append("allow_all")
        else:
            spf_qualifiers.append("no_explicit_all_mechanism")
    dmarc_policy = []
    for record in dmarc_records:
        match = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)", record, re.I)
        dmarc_policy.append(match.group(1).lower() if match else "policy_missing_or_unrecognised")
    findings = []
    if not mx:
        findings.append({"severity": "medium", "finding": "No public MX record returned", "meaning": "The domain may not receive email directly, or DNS data may be incomplete."})
    if not spf_records:
        findings.append({"severity": "medium", "finding": "SPF record not found", "meaning": "Receivers may lack a published SPF sender-authorisation policy for this domain."})
    elif len(spf_records) > 1:
        findings.append({"severity": "high", "finding": "Multiple SPF records found", "meaning": "More than one SPF policy can cause SPF permerror; consolidate to one policy."})
    elif spf_qualifiers and spf_qualifiers[0] == "allow_all":
        findings.append({"severity": "high", "finding": "SPF ends with +all", "meaning": "This explicitly authorises any sender and defeats SPF restriction."})
    elif spf_qualifiers and spf_qualifiers[0] == "soft_fail":
        findings.append({"severity": "low", "finding": "SPF uses ~all", "meaning": "Unauthorised senders are marked soft-fail rather than explicitly rejected by SPF."})
    if not dmarc_records:
        findings.append({"severity": "medium", "finding": "DMARC record not found", "meaning": "The domain has no observed DMARC policy at _dmarc." + domain + "."})
    elif any(policy == "none" for policy in dmarc_policy):
        findings.append({"severity": "low", "finding": "DMARC policy is p=none", "meaning": "DMARC reporting may be enabled, but receivers are not asked to quarantine or reject failing mail."})
    if len(dmarc_records) > 1:
        findings.append({"severity": "high", "finding": "Multiple DMARC records found", "meaning": "Multiple DMARC TXT records at the same name can make policy evaluation fail."})
    if not records.get("CAA", {}).get("answers"):
        findings.append({"severity": "info", "finding": "No CAA record observed", "meaning": "No CAA restriction was returned at this exact domain; parent-domain CAA inheritance is not evaluated."})
    return {
        "domain": domain, "submitted_email_address": submitted_email,
        "mx_records": mx, "spf_records": spf_records, "spf_policy_count": len(spf_records),
        "spf_terminal_qualifiers": spf_qualifiers, "dmarc_records": dmarc_records,
        "dmarc_policy": dmarc_policy, "findings": findings,
        "mailbox_existence": "Not tested", "mailbox_ownership": "Not tested",
        "deliverability": "Not tested", "breach_exposure": "Not queried",
        "limits": ["DNS policy presence does not prove mail delivery or inbox existence.",
                   "SPF include/redirect DNS lookup counts and full RFC evaluation are not calculated.",
                   "DKIM selectors are not guessed; publish and provide known selectors for targeted checks.",
                   "Breach databases and private mailbox activity are not queried."]
    }


def _url_intelligence_findings(value: str) -> dict:
    """Add richer URL-only indicators without visiting the supplied URL."""
    analysis = analyze_url(value)
    parsed = urllib.parse.urlsplit(value if "://" in value else "https://" + value)
    query_keys = sorted({key[:80] for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)})[:40]
    safe_query = urllib.parse.urlencode([(key, "") for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)])
    safe_submitted_url = urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", safe_query, ""))
    path_lower = parsed.path.lower()
    flags = list(analysis["structural_indicators"])
    if parsed.query:
        flags.append("URL contains query parameters; values are deliberately not retained")
    if parsed.fragment:
        flags.append("URL contains a fragment identifier")
    if any(token in path_lower for token in ("/wp-admin", "/admin", "/login", "/signin", "/auth")):
        flags.append("Path name suggests an administrative or authentication route; route existence is not checked")
    if any(token in path_lower for token in ("/redirect", "/out", "/url=", "/continue")):
        flags.append("Path may implement a redirect or continuation flow; redirect behaviour is not tested")
    if re.search(r"%(?:2e|2f|5c|00)", parsed.path, re.I):
        flags.append("Path contains encoded dot, slash, backslash or NUL characters")
    if len(parsed.query) > 500:
        flags.append("URL has an unusually long query string")
    return {
        **analysis, "submitted_url": safe_submitted_url,
        "path_depth": len([part for part in parsed.path.split("/") if part]),
        "query_parameter_names": query_keys, "query_values_saved": False,
        "fragment_present": bool(parsed.fragment), "enhanced_indicators": sorted(set(flags)),
        "reputation_check": "Not performed", "redirect_chain": "Not followed",
        "certificate_validation": "Not performed by this URL-only structural check",
        "risk_note": "Structural and lexical indicators only. The URL was not opened, resolved, downloaded, crawled or submitted to a reputation service. Findings are leads for analyst review, not a maliciousness verdict."
    }

def _normalise_osint_input(value: str) -> dict:
    """Accept a domain, website URL, email address or public social profile URL."""
    raw = value.strip()
    if not raw:
        raise ValueError("Enter a domain, website URL, email address or public social profile URL.")
    if "@" in raw and "://" not in raw:
        if raw.count("@") != 1:
            raise ValueError("Email address format is invalid.")
        local, host = raw.rsplit("@", 1)
        if not local or not host:
            raise ValueError("Email address format is invalid.")
        return {"input_type": "email", "input": raw[:320], "domain": validate_domain(host),
                "email_address": raw[:320]}
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urllib.parse.urlsplit(candidate)
    if not parsed.hostname:
        raise ValueError("Could not identify a domain in the supplied input.")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    social_hosts = ("facebook.com", "linkedin.com", "instagram.com", "x.com",
                    "twitter.com", "tiktok.com", "youtube.com", "slack.com",
                    "github.com", "discord.com")
    is_social = any(host == item or host.endswith("." + item) for item in social_hosts)
    if is_social:
        return {"input_type": "social_profile_url", "input": raw[:1000],
                "platform_host": host, "social_profile_reference": candidate[:1000],
                "domain": None,
                "limitations": ["The supplied social profile is recorded as a public reference only; platform login walls, privacy settings and anti-automation controls prevent reliable profile or follower extraction."]}
    domain = validate_domain(host)
    safe_query = urllib.parse.urlencode([(key, "") for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)])
    safe_url = urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", safe_query, ""))
    return {"input_type": "website_url" if "://" in raw else "domain",
            "input": safe_url[:1000] if "://" in raw else raw[:1000], "domain": domain,
            "website_url": safe_url[:1000]}


def resolve_public_site_ips(domain: str) -> dict:
    """Resolve the site's public A/AAAA addresses without scanning them."""
    try:
        rows = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        addresses = sorted({row[4][0] for row in rows})
        public = [address for address in addresses if ipaddress.ip_address(address.split("%")[0]).is_global]
        return {"addresses": public, "count": len(public),
                "note": "DNS resolution only; no port scan, service probe or owner identity inference."}
    except (OSError, ValueError) as exc:
        return {"addresses": [], "count": 0, "error": str(exc)}


def _dkim_selector_checks(domain: str, timeout: int = 12) -> dict:
    """Check a short, documented set of common DKIM selectors; never brute-force."""
    selectors = ("default", "google", "selector1", "selector2", "s1", "s2", "smtp", "k1")
    found, errors = [], []
    for selector in selectors:
        name = selector + "._domainkey." + domain
        try:
            answer = _dns_over_https(name, "TXT", timeout)
            values = [row["value"] for row in answer.get("answers", []) if "v=dkim1" in row.get("value", "").lower() or "p=" in row.get("value", "")]
            if values:
                found.append({"selector": selector, "records": values})
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            errors.append({"selector": selector, "error": str(exc)})
    return {"selectors_checked": list(selectors), "published_selectors_found": found,
            "errors": errors, "note": "Limited common-selector check only; absence does not mean DKIM is not configured. Use a selector supplied by the mail administrator for a definitive lookup."}


def _public_search_hints(kind: str, value: str) -> list:
    """Provide focused, user-controlled search terms without disclosing identifiers automatically."""
    if kind == "email":
        return [
            {"source": "Search engine", "query": '"' + value + '"'},
            {"source": "Search engine", "query": '"' + value.split("@", 1)[1] + '" email'},
            {"source": "Search engine", "query": '"' + value + '" filetype:pdf'},
        ]
    if kind == "social_profile_url":
        path = urllib.parse.urlsplit(value).path.strip("/")
        handle = path.split("/")[-1] if path else ""
        return [{"source": "Search engine", "query": '"' + handle + '" ' + kind},
                {"source": "Search engine", "query": 'site:' + urllib.parse.urlsplit(value).hostname + ' "' + handle + '"'}] if handle else []
    return []


def _public_social_account_refs(urls: list) -> list:
    """Extract public account URLs and visible path handles from published links."""
    results = []
    for value in urls[:50]:
        try:
            parsed = urllib.parse.urlsplit(value)
            host = (parsed.hostname or "").lower()
            path_parts = [part for part in parsed.path.split("/") if part]
            if not host or not path_parts:
                continue
            results.append({
                "platform": host.removeprefix("www."),
                "public_profile_url": urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")),
                "public_path_identifier": path_parts[-1][:120],
                "identifier_type": "public URL path; not independently verified as a person's username"
            })
        except ValueError:
            continue
    return results


def _dns_passive_domain_assets(domain: str, timeout: int = 12, limit: int = 30) -> dict:
    """Discover certificate-listed subdomains and resolve their public IPs; never scan hosts."""
    query = urllib.parse.urlencode({"q": "%." + domain, "output": "json"})
    try:
        rows = http_json("https://crt.sh/?" + query, timeout)
        names = sorted({
            name.strip().lower().rstrip(".").lstrip("*.")
            for row in rows if isinstance(row, dict)
            for name in str(row.get("name_value", "")).splitlines()
            if name.strip() and name.strip().lower().rstrip(".").lstrip("*.").endswith("." + domain)
        })
    except Exception as exc:
        return {"status": "unavailable", "source": "Certificate Transparency (crt.sh)",
                "error": str(exc), "subdomains": [], "public_ip_addresses": [],
                "note": "No host scanning or service probing is performed."}
    assets = []
    all_ips = set()
    for name in names[:max(1, min(limit, 50))]:
        resolved = resolve_public_site_ips(name)
        addresses = resolved.get("addresses", [])
        all_ips.update(addresses)
        assets.append({"hostname": name, "public_ip_addresses": addresses,
                       "resolution_status": "resolved" if addresses else "no_public_address_returned"})
    return {"status": "ok", "source": "Certificate Transparency (crt.sh) plus public DNS resolution",
            "certificate_names_returned": len(names), "subdomains": assets,
            "public_ip_addresses": sorted(all_ips),
            "note": "Certificate names can be historical or inactive. IP resolution is passive DNS only; no ports or services are tested."}


def _clean_public_location_values(values: list) -> list:
    """Drop obvious markup/script fragments from heuristic homepage location matches."""
    cleaned = []
    for value in values:
        item = re.sub(r"\\s+", " ", str(value)).strip(" \\t\\r\\n.;,")
        if not item or any(token in item.lower() for token in (".href=", "</", "<script", "function(", "=>", "{", "}", "var ")):
            continue
        if len(item) > 100 or not re.search(r"[A-Za-z]", item):
            continue
        cleaned.append(item)
    return list(dict.fromkeys(cleaned))[:10]


def dns_intelligence_lookup(value: str, timeout: int = 12) -> dict:
    """Route input to a type-specific public intelligence workflow."""
    identity = _normalise_osint_input(value)
    kind = identity["input_type"]
    result = {"investigation_type": kind + "_intelligence", "submitted_input": identity,
              "scope_note": "Results are specific to the submitted input type; no generic cross-category report is appended."}

    if kind == "email":
        domain = identity["domain"]
        records = dns_lookup(domain, timeout)["records"]
        result["email_intelligence"] = _email_security_findings(domain, records, identity["email_address"])
        result["email_intelligence"]["dkim"] = _dkim_selector_checks(domain, timeout)
        result["email_intelligence"]["public_search_hints"] = _public_search_hints("email", identity["email_address"])
        result["email_intelligence"]["domain_ip_addresses"] = resolve_public_site_ips(domain)
        # Enrich only from the email domain's own public business website.
        # Do not attempt to discover private accounts or correlate a person across services.
        public_site = public_site_profile(domain, timeout)
        passive_assets = _dns_passive_domain_assets(domain, timeout)
        public_locations = _clean_public_location_values(public_site.get("public_location", []))
        result["email_intelligence"]["public_domain_associations"] = {
            "source_domain": domain,
            "source": "The domain's public HTTPS homepage, when available",
            "status": public_site.get("status", "unavailable"),
            "organisation_name": public_site.get("organisation_name", ""),
            "public_business_emails": public_site.get("public_contact_emails", []),
            "public_business_phone_numbers": public_site.get("public_contact_phone_numbers", []),
            "public_social_media_links": public_site.get("social_media_links", []),
            "public_locations": public_locations,
            "public_addresses": public_site.get("public_address", []),
            "public_ip_addresses": result["email_intelligence"]["domain_ip_addresses"].get("addresses", []),
            "certificate_transparency_assets": passive_assets,
            "public_social_account_identifiers": _public_social_account_refs(public_site.get("social_media_links", [])),
            "association_quality": {
                "public_contact_source": "Domain homepage only",
                "social_username_source": "Visible public profile URL path only",
                "ip_source": "Public DNS and certificate-transparency names",
                "identity_linking": "Not performed"
            },
            "relationship_note": "These are domain-level DNS assets and contact/social references published by the domain or listed in public certificate records. A shared IP, email address, phone number or social URL does not establish that the submitted mailbox owner controls an account."
        }
        result["limitations"] = [
            "Mailbox existence, ownership, inbox activity and deliverability are not tested.",
            "No passwords, private messages, breach credentials or private-person contact details are retrieved.",
            "Public contacts and social links are extracted only from the email domain's own public homepage; no cross-platform identity matching is performed.",
            "Certificate-transparency subdomains may be historical; public IP resolution does not test whether ports or services are exposed.",
            "Search hints are optional manual research leads, not live search results.",
            "DKIM checks cover a short common-selector list only; they are not exhaustive."
        ]
        return result

    if kind == "website_url":
        url = identity["website_url"]
        result["url_intelligence"] = _url_intelligence_findings(url)
        result["url_intelligence"]["page_inspection"] = inspect_assessment_page(url, timeout, method="GET")
        result["url_intelligence"]["scope"] = [
            "One explicitly supplied HTTPS page is requested after public-IP validation.",
            "Redirects are not followed; no forms are submitted and no hidden paths are enumerated.",
            "Page metadata, response headers, cookies and visible authentication-form patterns are observational only."
        ]
        return result

    if kind == "social_profile_url":
        profile_url = identity["social_profile_reference"]
        parsed = urllib.parse.urlsplit(profile_url)
        path_parts = [part for part in parsed.path.split("/") if part]
        result["social_profile_intelligence"] = {
            "platform": identity["platform_host"],
            "profile_reference": profile_url,
            "profile_path": parsed.path,
            "profile_identifier_or_slug": path_parts[-1] if path_parts else None,
            "public_page_inspection": inspect_assessment_page(profile_url, timeout, method="GET"),
            "public_search_hints": _public_search_hints(kind, profile_url),
            "privacy_boundary": "Only the supplied public profile URL is inspected. No login, private profile access, follower scraping, contact harvesting or identity correlation is attempted."
        }
        result["limitations"] = [
            "Platforms may return login walls, consent pages, bot challenges or incomplete metadata.",
            "A page title or public slug is not proof of a person's identity.",
            "Follower counts, private email/phone details and account activity are not inferred."
        ]
        return result

    domain = identity["domain"]
    result["domain"] = domain
    result["dns_records"] = dns_lookup(domain, timeout)["records"]
    result["site_ip_resolution"] = resolve_public_site_ips(domain)
    result["sources"] = {"website_profile": public_site_profile(domain, timeout)}
    result["domain_email_security"] = _email_security_findings(domain, result["dns_records"])
    result["domain_email_security"]["dkim"] = _dkim_selector_checks(domain, timeout)
    return result


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


def _safe_case_id(value: str) -> str:
    case_id = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip()).strip("-_")[:48]
    if not case_id:
        raise ValueError("Case/reference ID must contain letters or numbers.")
    return case_id


def case_timeline_path(case_id: str) -> Path:
    safe_case = _safe_case_id(case_id)
    return evidence_directory() / (safe_case + ".timeline.jsonl")


def _safe_timeline_source_reference(value: str) -> str:
    """Remove URL query/fragment data that may contain credentials or tracking tokens."""
    value = value.strip()
    if len(value) > 1000:
        raise ValueError("Timeline source reference is too long.")
    if value.lower().startswith(("http://", "https://")):
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Source URL must be valid HTTP(S) without embedded credentials.")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        if parsed.port:
            host += ":" + str(parsed.port)
        return urllib.parse.urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", "", ""))
    return value


def append_case_event(case_id: str, event_type: str, description: str,
                      source_reference: str = "") -> dict:
    """Append a local case event to a SHA-256 linked JSONL timeline."""
    from datetime import datetime, timezone
    path = case_timeline_path(case_id)
    if len(description.strip()) < 3:
        raise ValueError("Enter a meaningful event description.")
    if len(description) > 2000:
        raise ValueError("Timeline description is too long.")
    source_reference = _safe_timeline_source_reference(source_reference)
    if path.is_symlink():
        raise ValueError("Case timeline must not be a symbolic link.")
    if path.exists() and path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Case timeline exceeds the 2 MB limit.")
    previous_hash = "0" * 64
    if path.exists() and path.stat().st_size:
        verification = verify_case_timeline(case_id)
        if verification.get("status") != "valid":
            raise ValueError("Existing case timeline failed integrity verification; refusing to append.")
        lines = path.read_text(encoding="utf-8").splitlines()
        try:
            previous = json.loads(lines[-1])
            previous_hash = previous["entry_hash"]
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise ValueError("Existing timeline is invalid; verify it before adding events.") from exc
    event = {
        "case_id": _safe_case_id(case_id),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "event_type": re.sub(r"[^a-zA-Z0-9_-]+", "_", event_type.strip().lower())[:40] or "note",
        "description": description.strip(),
        "source_reference": source_reference.strip()[:1000],
        "previous_entry_hash": previous_hash,
    }
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    event["entry_hash"] = hashlib.sha256(canonical).hexdigest()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    return {"timeline_file": str(path), "event": event,
            "note": "Local hash-linked timeline; this is not a trusted timestamp or externally anchored audit log."}


def verify_case_timeline(case_id: str) -> dict:
    """Verify each event hash and previous-hash link in a local case timeline."""
    path = case_timeline_path(case_id)
    if not path.exists():
        return {"case_id": _safe_case_id(case_id), "events_checked": 0, "status": "not_found"}
    if path.is_symlink():
        return {"case_id": _safe_case_id(case_id), "events_checked": 0, "status": "unsafe_symlink"}
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Case timeline exceeds the 2 MB verification limit.")
    previous_hash = "0" * 64
    checked = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        checked += 1
        try:
            event = json.loads(line)
            stored_hash = event.pop("entry_hash")
            if event.get("previous_entry_hash") != previous_hash:
                return {"case_id": _safe_case_id(case_id), "events_checked": checked,
                        "status": "chain_mismatch", "line": line_number}
            canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            actual_hash = hashlib.sha256(canonical).hexdigest()
            if actual_hash != stored_hash:
                return {"case_id": _safe_case_id(case_id), "events_checked": checked,
                        "status": "entry_hash_mismatch", "line": line_number}
            previous_hash = stored_hash
        except (ValueError, KeyError, TypeError):
            return {"case_id": _safe_case_id(case_id), "events_checked": checked,
                    "status": "invalid_entry", "line": line_number}
    return {"case_id": _safe_case_id(case_id), "events_checked": checked,
            "status": "valid" if checked else "empty",
            "final_entry_hash": previous_hash,
            "note": "Local hash-chain verification only; deletion of the final entries cannot be detected without an external trusted checkpoint."}


def read_case_timeline(case_id: str) -> dict:
    path = case_timeline_path(case_id)
    if not path.exists():
        return {"case_id": _safe_case_id(case_id), "events": [], "status": "not_found"}
    verification = verify_case_timeline(case_id)
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            break
    return {"case_id": _safe_case_id(case_id), "events": events[-100:],
            "verification": verification, "timeline_file": str(path)}


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
    print("  [E] Add a case timeline event")
    print("  [T] View a case timeline")
    print("  [C] Verify a case timeline hash chain")
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
    elif choice in ("e", "t", "c"):
        case_id = input("Case/reference ID: ").strip()
        if choice == "e":
            event_type = input("Event type (e.g. observation, collection, review): ").strip() or "note"
            description = input("Event description (no passwords or access tokens): ").strip()
            source = input("Source/evidence reference (optional): ").strip()
            result = append_case_event(case_id, event_type, description, source)
        elif choice == "t":
            result = read_case_timeline(case_id)
        else:
            result = verify_case_timeline(case_id)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if choice == "e":
            save_investigation({"case_timeline_event": result}, "case-timeline")
    elif choice:
        print("Choose A, V, E, T, C or press Enter to return.")


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
    """Save a timestamped local JSON report and a SHA-256 integrity sidecar."""
    from datetime import datetime, timezone
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safe_service = re.sub(r"[^a-z0-9-]+", "-", service.lower()).strip("-") or "report"
    directory = investigation_directory()
    destination = directory / f"{stamp}_{safe_service}.json"
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    payload = rendered.encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    # Exclusive creation prevents a same-name report from silently overwriting an earlier record.
    with destination.open("xb") as handle:
        handle.write(payload)
    manifest = {
        "report_file": destination.name,
        "sha256": digest,
        "size_bytes": len(payload),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "integrity": "sha256",
        "storage": "local_only",
    }
    sidecar = destination.with_name(destination.name + ".manifest.json")
    with sidecar.open("x", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return destination


def verify_investigation_reports() -> dict:
    """Verify local JSON report hashes against their SHA-256 sidecars."""
    directory = investigation_directory()
    checked, valid, missing, mismatched = 0, 0, [], []
    for sidecar in sorted(directory.glob("*.json.manifest.json")):
        checked += 1
        try:
            manifest = json.loads(sidecar.read_text(encoding="utf-8"))
            filename = manifest["report_file"]
            if Path(filename).name != filename:
                mismatched.append(sidecar.name)
                continue
            report = directory / filename
            if not report.is_file() or report.is_symlink():
                missing.append(filename)
                continue
            data = report.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest == manifest.get("sha256") and len(data) == manifest.get("size_bytes"):
                valid += 1
            else:
                mismatched.append(filename)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            mismatched.append(sidecar.name)
    return {
        "manifests_checked": checked, "integrity_valid": valid,
        "missing_reports": missing, "hash_mismatches_or_invalid_manifests": mismatched,
        "note": "Local integrity check only; reports are not modified or uploaded."
    }


def show_investigation_history() -> None:
    directory = investigation_directory()
    reports = sorted((p for p in directory.glob("*.json") if not p.name.endswith(".manifest.json")),
                     reverse=True)
    print("\nLOCAL INVESTIGATION HISTORY")
    print(f"Location: {directory}")
    print(f"Reports: {len(reports)}")
    if reports:
        for index, report in enumerate(reports[:30], 1):
            print(f"  [{index}] {report.name} ({report.stat().st_size} bytes)")
        if len(reports) > 30:
            print(f"  ... and {len(reports) - 30} older report(s)")
    print("  [number] Open a report")
    print("  [V] Verify report integrity")
    choice = input("reports> ").strip().lower()
    if choice == "v":
        result = verify_investigation_reports()
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif choice.isdigit() and 1 <= int(choice) <= min(len(reports), 30):
        selected = reports[int(choice) - 1]
        try:
            data = json.loads(selected.read_text(encoding="utf-8"))
            print(f"\\nREPORT: {selected.name}")
            print(json.dumps(data, indent=2, ensure_ascii=False)[:20000])
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Could not read report: {exc}")
    elif choice:
        print("Choose a displayed report number, V or press Enter to return.")



def manual_security_assessment(timeout: int = 12) -> dict:
    """Automatically perform a bounded passive review of an explicitly authorised public site."""
    print("\nAUTOMATED PASSIVE SECURITY ASSESSMENT")
    print("Only public HTTPS, DNS and response metadata are inspected.")
    print("No login attempts, payloads, form submissions, endpoint guessing or scans are performed.")
    target = input("Application/domain or approved test environment: ").strip()[:1000]
    if not target:
        raise ValueError("A target label is required.")
    authorised = input("Confirm you own or are explicitly authorised to assess this system (yes/no): ").strip().lower()
    if authorised not in ("yes", "y"):
        raise ValueError("Assessment stopped: explicit authorisation was not confirmed.")

    parsed = urllib.parse.urlsplit(target if "://" in target else "https://" + target)
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("Enter a public domain or HTTPS URL without embedded credentials.")
    domain = validate_domain(parsed.hostname)
    page_url = "https://" + domain + (parsed.path if parsed.path and parsed.path != "/" else "/")
    print("\n[1/3] Reviewing public HTTPS page and visible authentication metadata...")
    page_inspection = inspect_assessment_page(page_url, timeout=timeout, method="GET")
    print("[2/3] Checking public DNS, mail and domain security records...")
    dns_result = dns_lookup(domain, timeout=timeout)
    print("[3/3] Analysing observed evidence and separating unobservable controls...")

    headers = page_inspection.get("response_headers", {})
    observed_headers = page_inspection.get("security_headers", {})
    cookies = page_inspection.get("cookies", [])
    cookie_checks = {
        "session_secure": ("yes" if cookies and all(c.get("secure") for c in cookies) else "no" if cookies else "unknown"),
        "session_httponly": ("yes" if cookies and all(c.get("httponly") for c in cookies) else "no" if cookies else "unknown"),
        "session_samesite": ("yes" if cookies and all(c.get("samesite") for c in cookies) else "no" if cookies else "unknown"),
    }
    rate_headers = {k: v for k, v in headers.items() if any(t in k.lower() for t in ("ratelimit", "retry-after"))}
    forms = page_inspection.get("visible_forms", [])
    login_method = page_inspection.get("login_classification", "unknown")
    records = dns_result.get("records", {})
    def has_answers(record):
        return bool(records.get(record, {}).get("answers"))
    answers = {
        "sql_parameter_binding": "unknown",
        "sql_string_concatenation": "unknown",
        "sql_error_disclosure": "unknown",
        "sql_test_environment": "unknown",
        "rate_limit": "yes" if rate_headers else "unknown",
        "lockout": "unknown",
        "captcha": "unknown",
        **cookie_checks,
        "session_rotation": "unknown",
        "session_expiry": "unknown",
        "admin_access": "unknown",
        "login_method": login_method,
        "breach_response": "not_applicable",
    }
    findings = []
    missing = page_inspection.get("security_headers_missing", [])
    if page_inspection.get("status_code") == 200:
        findings.append({"area": "Public HTTPS page", "severity": "info", "status": "observed",
                         "detail": "The supplied public page returned an HTTP response. This is an availability observation, not a security certification."})
    for name in missing:
        findings.append({"area": "HTTP security headers", "severity": "low", "status": "potential_gap",
                         "detail": name + " was not observed on the inspected response.",
                         "remediation": "Review whether this header is appropriate for the application and configure it at the application or edge."})
    for key, label in (("session_secure", "Secure cookie attribute"), ("session_httponly", "HttpOnly cookie attribute"), ("session_samesite", "SameSite cookie attribute")):
        if answers[key] == "no":
            findings.append({"area": label, "severity": "medium", "status": "potential_gap",
                             "detail": "At least one cookie set by the inspected response lacked the expected attribute.",
                             "remediation": "Review cookie purpose and set Secure, HttpOnly and an appropriate SameSite policy for session cookies."})
        elif answers[key] == "unknown":
            findings.append({"area": label, "severity": "info", "status": "not_observed",
                             "detail": "The inspected response did not set cookies, so this control could not be assessed."})
    if rate_headers:
        findings.append({"area": "Authentication throttling", "severity": "info", "status": "rate_limit_headers_observed",
                         "detail": "Rate-limit or Retry-After response headers were present. This alone does not prove effective authentication throttling."})
    else:
        findings.append({"area": "Authentication throttling", "severity": "info", "status": "not_observed",
                         "detail": "No rate-limit headers were observed on this single request; actual throttling requires owner-side configuration or controlled staging evidence."})
    findings.append({"area": "SQL injection resistance", "severity": "info", "status": "not_assessable_passively",
                     "detail": "Public HTML and DNS cannot establish parameter binding or unsafe SQL concatenation. Server-side source/configuration review is required."})
    findings.append({"area": "Login protection and session lifecycle", "severity": "info", "status": "not_assessable_passively",
                     "detail": "Lockout, bot challenges, session rotation, idle/absolute expiry, logout invalidation and MFA enforcement cannot be proven by a single unauthenticated page request."})
    if not has_answers("MX"):
        findings.append({"area": "Email configuration", "severity": "medium", "status": "review",
                         "detail": "No MX answer was returned by the selected public DNS resolvers."})
    txt_values = [str(x.get("value", "")) for x in records.get("TXT", {}).get("answers", [])]
    if not any("v=spf1" in x.lower() for x in txt_values):
        findings.append({"area": "SPF", "severity": "medium", "status": "not_observed",
                         "detail": "No SPF TXT record was observed at the domain apex."})
    dmarc = records.get("DMARC", {}).get("answers", [])
    if not any("v=dmarc1" in str(x.get("value", "")).lower() for x in dmarc):
        findings.append({"area": "DMARC", "severity": "medium", "status": "not_observed",
                         "detail": "No DMARC record was observed at _dmarc." + domain + "."})
    observed = sum(1 for v in answers.values() if v == "yes")
    unknown = sum(1 for v in answers.values() if v == "unknown")
    return {
        "assessment": "Automated Passive Security Assessment",
        "target": domain,
        "authorisation_confirmed_by_operator": True,
        "scope": {"https_page": page_url, "dns_domain": domain, "requests": "one public HTTPS GET plus bounded DNS queries"},
        "page_inspection": page_inspection,
        "dns_inspection": dns_result,
        "login_method": login_method,
        "checks": answers,
        "findings": findings,
        "analysis": {
            "observed_yes_controls": observed,
            "unknown_or_unverifiable_controls": unknown,
            "finding_count": len(findings),
            "overall_status": "review_required" if any(f.get("severity") in ("high", "medium") for f in findings) else "limited_passive_observations",
            "interpretation": "This is an evidence-based passive review, not a penetration test. 'Not observed' and 'unknown' do not mean a control is absent."
        },
        "method": "Automatically inspected the explicit public HTTPS URL once without following redirects, inspected response headers/cookies/forms, and queried public DNS records. No admin URL guessing, authentication attempts, form submissions, payloads, endpoint discovery, port scans, breach lookups or personal-account searches.",
        "limitations": [
            "SQL injection requires server-side source/configuration review; it cannot be identified reliably from public HTML.",
            "Rate limiting, lockout, CAPTCHA triggers, MFA enforcement, session rotation/expiry and admin role restrictions need owner-side evidence or an isolated staging review.",
            "No breach-notification service was queried and no email address or password was submitted to a third party.",
            "Only one supplied public page was fetched. No hidden paths or admin endpoints were guessed.",
            "DNS answers and HTTP headers are observations at the time of assessment and may vary by CDN, region or deployment."
        ]
    }



def audit_password_strength(password: str) -> dict:
    """Return local password quality signals without retaining or returning the secret."""
    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty password is required.")
    length = len(password)
    classes = {
        "lowercase": any(ch.islower() for ch in password),
        "uppercase": any(ch.isupper() for ch in password),
        "digits": any(ch.isdigit() for ch in password),
        "symbols": any(not ch.isalnum() for ch in password),
    }
    lowered = password.lower()
    repeated = bool(re.search(r"(.)\1{3,}", password))
    common = bool(re.search(r"(?i)(password|qwerty|letmein|welcome|admin|123456|iloveyou)", password))
    sequential = any(token in lowered for token in (
        "123456", "234567", "abcdef", "qwerty", "asdfgh", "zxcvbn", "987654"
    ))
    digits_only_or_letters_only = bool(re.fullmatch(r"(?:\d+|[a-z]+)", password, re.I))
    risks = {
        "long_repeated_character_run": repeated,
        "common_word_or_sequence": common,
        "keyboard_or_sequential_pattern": sequential,
        "only_letters_or_digits": digits_only_or_letters_only,
    }
    recommendations = []
    if length < 14:
        recommendations.append("Prefer at least 14 characters; a longer, unique passphrase is generally better.")
    if length < 20:
        recommendations.append("Consider a longer passphrase made from several unrelated words.")
    if any(risks.values()):
        recommendations.append("Avoid repeated characters, common phrases, keyboard walks and predictable sequences.")
    if not classes["lowercase"] or not classes["uppercase"] or not classes["digits"] or not classes["symbols"]:
        recommendations.append("Follow the service's password policy; length and uniqueness matter more than forced complexity.")
    recommendations.append("Use a password manager and never reuse passwords across services.")
    if length >= 20 and not any(risks.values()):
        band = "strong_candidate"
    elif length >= 14 and not any(risks.values()):
        band = "reasonable_candidate"
    else:
        band = "weak_or_needs_review"
    return {
        "length": length, "character_classes": classes, "quality_band": band,
        "risk_signals": risks, "recommendations": recommendations,
        "assessment_limit": "Offline heuristic only; no breach-corpus lookup, entropy guarantee or account-policy verification is performed.",
        "privacy": "The password value is not included in this result or saved to an investigation report."
    }


def _normalise_yes_no_unknown(value: str, field_name: str) -> str:
    normal = value.strip().lower()
    if not normal:
        normal = "unknown"
    aliases = {"y": "yes", "n": "no", "u": "unknown", "na": "not_applicable"}
    normal = aliases.get(normal, normal)
    if normal not in ("yes", "no", "unknown", "not_applicable"):
        raise ValueError(f"{field_name}: enter yes, no, unknown or not_applicable.")
    return normal


def review_password_storage(algorithm: str, salt: str, work_factor: str) -> dict:
    """Review operator-supplied password-storage metadata; never accepts hashes."""
    alg = algorithm.strip().lower()
    known_weak = {"md5", "sha1", "sha-1", "sha256", "sha-256", "plain", "plaintext", "unsalted-sha256"}
    modern = {"argon2id", "scrypt", "bcrypt", "pbkdf2-sha256"}
    if not alg:
        raise ValueError("Enter the password-storage algorithm name.")
    salt_status = _normalise_yes_no_unknown(salt, "Unique per-password salt")
    work_status = _normalise_yes_no_unknown(work_factor, "Work factor/parameters documented")
    status = "needs_review"
    if alg in known_weak:
        status = "weak_or_inappropriate"
    elif alg in modern:
        status = "modern_family_check_parameters"
    return {"algorithm": alg, "salted": salt_status == "yes",
            "salt_status": salt_status,
            "work_factor_or_parameters_documented": work_status == "yes",
            "work_factor_status": work_status,
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
    print("  [6] Inspect an authorised website login page (read-only assessment)")
    print("  [7] Analyse a local authentication log (optional forensic evidence)")
    print("  [8] Run John the Ripper against an authorised offline hash inventory")
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
        answers = []
        prompts = ("Rate limiting enabled?", "Progressive delay/lockout enabled?",
                   "MFA enforced where appropriate?", "Breached-password blocklist used?",
                   "Secure password reset flow?")
        for prompt in prompts:
            answers.append(_normalise_yes_no_unknown(input(prompt + " yes/no/unknown: "), prompt))
        result = review_authentication_policy(*answers)
    elif choice == "6":
        print("Enter a public HTTPS login page you own or are explicitly authorised to assess.")
        print("CyberLab performs a read-only GET; it does not submit credentials or run Hydra.")
        url = input("Authorised login page HTTPS URL: ").strip()[:1000]
        result = inspect_assessment_page(url, method="GET")
        result["feature"] = "website_authentication_surface_preflight"
        result["hydra_style_note"] = "Read-only preflight only; no password guesses or login attempts are sent."
    elif choice == "7":
        result = analyse_auth_log(Path(input("Path to optional exported auth log (max 5 MB): ").strip()).expanduser())
    elif choice == "8":
        print("John the Ripper audits hashes offline. Use only hashes you own or are authorised to assess.")
        hashes = Path(input("Path to authorised hash file: ").strip()).expanduser()
        default_wordlist = "/usr/share/wordlists/rockyou.txt"
        wordlist_text = input(f"Wordlist path [{default_wordlist}]: ").strip() or default_wordlist
        hash_format = input("John format override (blank = auto-detect): ").strip()
        confirmation = input("Type YES to confirm authorisation for this offline hash audit: ").strip()
        result = run_john_audit(hashes, Path(wordlist_text), hash_format,
                                authorised=(confirmation == "YES"))
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


def run_john_audit(hash_path: Path, wordlist_path: Path, hash_format: str = "",
                   timeout: int = 180, authorised: bool = False) -> dict:
    """Run John against an explicitly authorised offline hash file; never return cracked secrets."""
    if not authorised:
        raise ValueError("Confirm that you own or are authorised to audit this offline hash inventory.")
    john = shutil.which("john")
    if not john:
        raise ValueError("John the Ripper is not installed. On Kali, install it with: sudo apt install john")
    hashes = hash_path.expanduser()
    wordlist = wordlist_path.expanduser()
    for candidate, label in ((hashes, "hash inventory"), (wordlist, "wordlist")):
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError(f"Select an existing regular local {label} file (symbolic links are not accepted).")
    # Resolve before changing cwd to the temporary John session directory.
    hashes = hashes.resolve()
    wordlist = wordlist.resolve()
    if hashes.stat().st_size == 0 or hashes.stat().st_size > 5 * 1024 * 1024:
        raise ValueError("Hash inventory must be between 1 byte and 5 MB.")
    if wordlist.stat().st_size == 0 or wordlist.stat().st_size > 250 * 1024 * 1024:
        raise ValueError("Wordlist must be between 1 byte and 250 MB.")
    selected_format = hash_format.strip()
    if selected_format and not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", selected_format):
        raise ValueError("Hash format must contain only letters, numbers, underscores or hyphens.")
    try:
        with tempfile.TemporaryDirectory(prefix="cyberlab-john-") as work:
            workdir = Path(work)
            pot = workdir / "audit.pot"
            session = "cyberlab-audit"
            command = [john, f"--wordlist={wordlist}", f"--pot={pot}", f"--session={session}"]
            if selected_format:
                command.append(f"--format={selected_format}")
            command.append(str(hashes))
            completed = subprocess.run(command, cwd=work, text=True, capture_output=True,
                                        timeout=max(1, min(int(timeout), 300)), check=False)
            if completed.returncode not in (0, 1):
                detail = (completed.stderr or completed.stdout or "John returned an error").strip()
                raise ValueError("John the Ripper failed: " + detail[-800:])
            shown = subprocess.run([john, f"--show", f"--pot={pot}", str(hashes)],
                                   cwd=work, text=True, capture_output=True,
                                   timeout=30, check=False)
            # --show contains plaintext credentials. Parse only aggregate counts and discard it.
            summary = (shown.stdout or "") + "\n" + (shown.stderr or "")
            match = re.search(r"(\d+)\s+password hash(?:es)? cracked,\s*(\d+)\s+left", summary, re.I)
            return {
                "feature": "john_the_ripper_offline_audit",
                "tool": "John the Ripper",
                "hash_inventory": hashes.name,
                "wordlist": wordlist.name,
                "format_override": selected_format or "automatic detection",
                "cracked_hash_count": int(match.group(1)) if match else None,
                "remaining_hash_count": int(match.group(2)) if match else None,
                "tool_exit_code": completed.returncode,
                "plaintext_passwords_returned_or_saved": False,
                "temporary_pot_file_deleted": True,
                "scope": "Offline hash auditing only; no network connections or website login attempts.",
                "note": "Only aggregate counts are retained. John output containing recovered plaintext passwords is deliberately discarded."
            }
    except subprocess.TimeoutExpired as exc:
        raise ValueError("John audit reached its time limit; no plaintext results were retained.") from exc


def analyse_phone_number_metadata(value: str) -> dict:
    """Parse a supplied phone number into conservative numbering-plan metadata only."""
    raw = value.strip()
    if not raw:
        raise ValueError("Enter a phone number including its country code, e.g. +2348012345678.")
    cleaned = re.sub(r"[\s().-]", "", raw)
    if not re.fullmatch(r"\+?[0-9]{7,15}", cleaned):
        raise ValueError("Use 7-15 digits and an optional leading + country code.")
    if not cleaned.startswith("+"):
        raise ValueError("Include the international country code, for example +234.")
    digits = cleaned[1:]
    # Longest-prefix-first subset of common calling codes; this is not a full numbering-plan database.
    calling_codes = {
        "1": "North America", "7": "Russia/Kazakhstan", "20": "Egypt",
        "27": "South Africa", "30": "Greece", "31": "Netherlands",
        "32": "Belgium", "33": "France", "34": "Spain", "36": "Hungary",
        "39": "Italy", "40": "Romania", "41": "Switzerland", "43": "Austria",
        "44": "United Kingdom", "45": "Denmark", "46": "Sweden", "47": "Norway",
        "48": "Poland", "49": "Germany", "52": "Mexico", "55": "Brazil",
        "61": "Australia", "64": "New Zealand", "65": "Singapore",
        "81": "Japan", "82": "South Korea", "86": "China",
        "91": "India", "234": "Nigeria", "254": "Kenya", "255": "Tanzania",
        "233": "Ghana", "256": "Uganda", "971": "United Arab Emirates",
        "972": "Israel", "974": "Qatar", "966": "Saudi Arabia",
    }
    country_code = next((code for code in sorted(calling_codes, key=len, reverse=True)
                         if digits.startswith(code)), None)
    if not country_code:
        raise ValueError("Country calling code is not in CyberLab's built-in reference list.")
    enrichment = {}
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder
        parsed = phonenumbers.parse(cleaned, None)
        number_types = {
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
            phonenumbers.PhoneNumberType.PAGER: "pager",
            phonenumbers.PhoneNumberType.UAN: "universal_access_number",
            phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
            phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
        }
        assigned_carrier = carrier.name_for_number(parsed, "en")
        enrichment = {
            "enrichment_depth": "libphonenumber_numbering_plan_metadata",
            "library_validation": "phonenumbers",
            "is_possible_number": phonenumbers.is_possible_number(parsed),
            "is_valid_number": phonenumbers.is_valid_number(parsed),
            "line_type": number_types.get(phonenumbers.number_type(parsed), "unknown"),
            "original_carrier_assignment": assigned_carrier or "Not available in numbering metadata",
            "approximate_region_description": geocoder.description_for_number(parsed, "en") or "Not available",
            "formatted_international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "formatted_national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "region_code": phonenumbers.region_code_for_number(parsed),
            "numbering_metadata_source": "Google libphonenumber metadata via the local phonenumbers package; no remote subscriber lookup.",
            "carrier_caveat": "Carrier data describes the original number-range assignment where available; number portability means it may not identify the current carrier."
        }
    except ImportError:
        enrichment = {
            "enrichment_depth": "basic_only",
            "library_validation": "basic built-in calling-code reference only",
            "optional_enrichment": "The phonenumbers dependency is not installed. Install it with: python3 -m pip install phonenumbers",
            "number_validity": "Not assessed",
            "line_type": "Not assessed",
            "original_carrier_assignment": "Not available",
            "approximate_region_description": "Not available",
            "next_step": "Install phonenumbers and rerun option 16 for offline numbering-plan metadata."
        }
    except Exception:
        enrichment = {
            "library_validation": "phonenumbers could not validate this number",
            "optional_enrichment": "Check the international number format and verify with the national numbering authority."
        }
    return {
        "investigation_type": "phone_number_numbering_metadata",
        **enrichment,
        "submitted_number": cleaned,
        "country_calling_code": "+" + country_code,
        "numbering_region_reference": calling_codes[country_code],
        "national_number_digits": digits[len(country_code):],
        "number_length_digits": len(digits),
        "carrier": enrichment.get("original_carrier_assignment", "Not determined; number portability and country-specific numbering data require an authoritative provider."),
        "current_carrier_status": "Not determined; original number-range assignment is not proof of current carrier because of number portability.",
        "registration_date": "Not publicly discoverable from a phone number alone; requires carrier records and lawful authority.",
        "last_used_or_active_status": "Not available from public numbering metadata; requires carrier/account-holder records.",
        "linked_ip_addresses_or_dns": "A phone number does not have a stable public IP address or DNS record. IPs are assigned to network sessions and are not publicly mapped to subscriber numbers.",
        "social_media_accounts": "No account matching or private-profile discovery is performed. Only links explicitly supplied by the user can be reviewed separately.",
        "fraud_reports": "No private fraud database or subscriber lookup is queried. Check reports with the relevant telecom regulator or official fraud-reporting channel.",
        "limitations": [
            "This is a format and country-calling-code reference, not subscriber identification or proof that a number is assigned, active or reachable.",
            "No SMS/call is sent; no carrier, location, owner, registration date, last-used time or linked IP is inferred.",
            "The built-in calling-code list is partial. Verify country and numbering details with the national telecom regulator or carrier."
        ]
    }


def scam_investigation_menu(timeout: int = 12) -> dict:
    """Collect public scam-site intelligence and locally supplied evidence."""
    print("\\nLAW ENFORCEMENT & SCAM INVESTIGATION")
    print("Use only public information and evidence you are legally authorised to handle.")
    print("This module does not access accounts, bypass logins or impersonate anyone.")
    print("  [1] Public scam-website intelligence (RDAP, DNS, certificates, homepage)")
    print("  [2] Inspect one explicitly supplied public HTTPS page (read-only)")
    print("  [3] Inspect an authorised website login page (read-only; enter a URL)")
    print("  [4] Run John the Ripper against an authorised offline hash inventory")
    print("  [5] Record an evidence note")
    print("  [6] Investigate a public website, email domain or social link")
    print("  [7] Legacy read-only website login-surface review")
    print("  [8] Analyse an exported authentication log (optional forensic evidence)")
    print("  [9] Classify an offline hash inventory (optional metadata review)")
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
        print("Enter a public HTTPS login page you own or are explicitly authorised to assess.")
        print("CyberLab inspects the page read-only; it does not submit credentials or run online password guesses.")
        url = input("Authorised website login page HTTPS URL: ").strip()[:1000]
        result = inspect_assessment_page(url, timeout=timeout, method="GET")
        result["investigation_type"] = "website_login_surface_assessment"
        result["hydra_style_note"] = "Read-only authentication preflight; no login attempts or password guesses are sent."
    elif choice == "4":
        print("John the Ripper runs locally against an offline hash file and wordlist; no website is contacted.")
        hashes = Path(input("Path to authorised offline hash file: ").strip()).expanduser()
        default_wordlist = "/usr/share/wordlists/rockyou.txt"
        wordlist_text = input(f"Wordlist path [{default_wordlist}]: ").strip() or default_wordlist
        hash_format = input("John format override (blank = auto-detect): ").strip()
        confirmation = input("Type YES to confirm authorisation for this offline hash audit: ").strip()
        result = run_john_audit(hashes, Path(wordlist_text), hash_format,
                                authorised=(confirmation == "YES"))
        result["investigation_type"] = "john_the_ripper_offline_hash_audit"
    elif choice == "6":
        target = input("Domain, website URL, email address or public social profile URL: ").strip()
        result = dns_intelligence_lookup(target, timeout)
        result["investigation_type"] = "scam_case_expanded_public_digital_footprint"
        result["scope_note"] = "Public-source lookup only. No account access, login bypass, private-profile scraping or active attack testing."
    elif choice == "7":
        print("Provide one owner-approved public HTTPS login page. CyberLab performs a read-only inspection only.")
        url = input("Owner-approved login page HTTPS URL: ").strip()[:1000]
        result = inspect_assessment_page(url, timeout=timeout, method="GET")
        result["investigation_type"] = "authorised_read_only_website_login_surface_review"
    elif choice == "8":
        print("This optional forensic path accepts an exported log from a website host, WAF, reverse proxy or identity provider you administer.")
        path = Path(input("Path to exported authentication log (max 5 MB): ").strip()).expanduser()
        result = analyse_auth_log(path)
        result["investigation_type"] = "offline_authentication_abuse_detection"
        result["interpretation"] = "Repeated failures can indicate password spraying or brute-force activity; correlate with timestamps and known NAT/VPN infrastructure before attribution."
    elif choice == "9":
        print("Optional metadata-only classification of an authorised offline hash inventory.")
        path = Path(input("Path to authorised local hash inventory (max 5 MB): ").strip()).expanduser()
        result = classify_hash_inventory(path)
        result["investigation_type"] = "offline_hash_format_inventory"
    elif choice == "5":
        from datetime import datetime, timezone
        case_id = re.sub(r"[^a-zA-Z0-9_-]+", "-", input("Case/reference ID: ").strip()).strip("-_")[:48] or "general"
        note = input("Evidence note (no passwords, tokens or unnecessary personal data): ").strip()[:3000]
        source = input("Source URL or local evidence reference: ").strip()[:1000]
        source_metadata = {"reference_type": "local_or_other_reference", "reference": source[:500]}
        if source.lower().startswith(("http://", "https://")):
            parsed = urllib.parse.urlsplit(source)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("Source URL must be a valid HTTP(S) URL without embedded credentials.")
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            safe_url = urllib.parse.urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", "", ""))
            source_metadata = {
                "reference_type": "public_url_reference",
                "url_without_query_or_fragment": safe_url,
                "query_and_fragment_saved": False,
                "note": "URL is recorded as a reference only; CyberLab did not fetch or verify this source."
            }
        recorded = datetime.now(timezone.utc).isoformat()
        result = {
            "investigation_type": "evidence_note", "case_id": case_id, "note": note,
            "source": source_metadata, "recorded_utc": recorded,
            "note_sha256": hashlib.sha256(note.encode("utf-8")).hexdigest(),
            "handling": "Local note metadata only. Preserve original evidence separately; this record does not independently establish authenticity, authorship or legal chain of custody."
        }
    elif choice == "0":
        return {}
    else:
        raise ValueError("Choose one of the listed options.")
    return result

def run_credential_guess_lab(username: str, expected_password: str, wordlist_path: Path,
                            mfa_enabled: bool = False, max_attempts: int = 50000,
                            progress_callback=None) -> dict:
    """Compare a local wordlist with a synthetic lab secret; never contacts a login service."""
    account = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", account):
        raise ValueError("Use a lab-only username containing 1-64 letters, numbers, dots, underscores, @ or hyphens.")
    if not isinstance(expected_password, str) or not expected_password:
        raise ValueError("A non-empty synthetic lab password is required.")
    wordlist = Path(wordlist_path).expanduser()
    if wordlist.is_symlink() or not wordlist.is_file():
        raise ValueError("Select an existing regular local wordlist file (symbolic links are not accepted).")
    if wordlist.stat().st_size == 0 or wordlist.stat().st_size > 25 * 1024 * 1024:
        raise ValueError("Wordlist must be between 1 byte and 25 MB.")
    if not 1 <= int(max_attempts) <= 50000:
        raise ValueError("The lab is limited to 1-50,000 candidate comparisons.")
    checked = 0
    matched_at = None
    with wordlist.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            candidate = line.rstrip("\r\n")
            if not candidate:
                continue
            checked += 1
            if candidate == expected_password:
                matched_at = checked
                if progress_callback:
                    progress_callback(checked, "candidate matched in local lab")
                break
            if progress_callback and (checked == 1 or checked % 100 == 0):
                progress_callback(checked, "testing local candidate")
            if checked >= max_attempts:
                break
    password_match = matched_at is not None
    return {
        "feature": "isolated_credential_guessing_lab",
        "username": account,
        "target": "in-memory synthetic lab credential only",
        "wordlist_file": wordlist.name,
        "candidates_checked": checked,
        "candidate_match": password_match,
        "match_position": matched_at,
        "mfa_enabled_in_simulation": bool(mfa_enabled),
        "simulated_outcome": ("password matched; MFA would still be required" if password_match and mfa_enabled
                              else "password matched in lab simulation" if password_match
                              else "no candidate matched within the tested wordlist"),
        "plaintext_password_returned_or_saved": False,
        "network_requests_made": 0,
        "real_accounts_contacted": False,
        "note": "This is a local deterministic simulation, not Hydra and not a test of any real login endpoint. It cannot establish whether an external account is vulnerable."
    }


def username_osint_search(username: str, timeout: int = 12) -> dict:
    """Search indexed public web pages for an operator-authorised username using Brave Search."""
    value = username.strip()
    if not value or len(value) > 64 or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value):
        raise ValueError("Username must be 1-64 characters using letters, digits, dot, underscore or hyphen.")
    api_key = os.environ.get("BRAVE_SEARCH_API_KEY", "").strip()
    if not api_key:
        return {
            "feature": "username_osint_investigation",
            "status": "api_key_required",
            "username": value,
            "search_provider": "Brave Search API",
            "configuration": [
                "Create a Brave Search API key at https://api.search.brave.com/",
                "Set it in this terminal: export BRAVE_SEARCH_API_KEY='your-key'",
                "Restart CyberLab from the same terminal and run option 18 again."
            ],
            "note": "No search was performed. CyberLab does not scrape search-engine result pages."
        }

    queries = [
        '"' + value + '"',
        '"' + value + '" profile OR account OR username',
        '"' + value + '" site:github.com OR site:gitlab.com OR site:reddit.com'
    ]
    collected = {}
    query_reports = []
    for query in queries:
        params = urllib.parse.urlencode({
            "q": query, "count": 10, "country": "NG",
            "search_lang": "en", "safesearch": "moderate"
        })
        request = urllib.request.Request(
            "https://api.search.brave.com/res/v1/web/search?" + params,
            headers={
                "Accept": "application/json",
                "X-Subscription-Token": api_key,
                "User-Agent": USER_AGENT
            }
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read(2_000_001)
                if len(payload) > 2_000_000:
                    raise ValueError("Search response exceeded the 2 MB safety limit.")
                data = json.loads(payload.decode("utf-8"))
            rows = data.get("web", {}).get("results", [])
            query_reports.append({"query": query, "results_returned": len(rows), "status": "ok"})
            for row in rows:
                url = row.get("url")
                if not url:
                    continue
                collected[url] = {
                    "title": str(row.get("title", ""))[:300],
                    "url": url,
                    "description": str(row.get("description", ""))[:700],
                    "page_age": row.get("page_age"),
                    "language": row.get("language"),
                    "matched_query": query
                }
        except urllib.error.HTTPError as exc:
            detail = exc.read(2000).decode("utf-8", errors="replace")
            query_reports.append({"query": query, "status": "http_error", "http_status": exc.code,
                                  "detail": detail[:1000]})
            if exc.code in (401, 403, 429):
                break
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            query_reports.append({"query": query, "status": "error", "detail": str(exc)[:500]})

    results = list(collected.values())[:25]
    return {
        "feature": "username_osint_investigation",
        "status": "completed" if results else "no_indexed_results_or_search_error",
        "username": value,
        "search_provider": "Brave Search API",
        "queries_executed": query_reports,
        "public_web_results": results,
        "result_count": len(results),
        "analysis_guidance": [
            "Open each source and verify that the username is an exact match, not a similar string.",
            "A matching handle on two websites does not prove the accounts belong to the same person.",
            "Search snippets can be stale; check the live source page and its publication/update date.",
            "No private profiles, login-protected content, breach dumps or account-recovery endpoints were queried."
        ],
        "scope": {
            "public_indexed_web_search_only": True,
            "platform_account_existence_verified": False,
            "identity_linkage_inferred": False,
            "private_data_accessed": False
        },
        "note": "Search-engine results are leads, not proof of account ownership or identity."
    }


def assess_username_quality(username: str) -> dict:
    """Review a username string locally without checking whether an account exists."""
    value = username.strip()
    if not value or len(value) > 64:
        raise ValueError("Username must contain 1-64 characters.")
    signals = {
        "contains_email_address": bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value)),
        "contains_full_name_like_separator": bool(re.search(r"[._ -]", value)),
        "contains_birth_year_like_sequence": bool(re.search(r"(?:19|20)\d{2}", value)),
        "contains_long_digit_suffix": bool(re.search(r"\d{4,}$", value)),
        "contains_personal_identifier_hint": bool(re.search(r"(?i)(ssn|nin|passport|account|phone)", value)),
    }
    return {
        "feature": "username_privacy_review",
        "username_length": len(value),
        "risk_signals": signals,
        "account_existence_checked": False,
        "recommendations": [
            "Avoid embedding phone numbers, government identifiers, birth dates or account numbers.",
            "Use a service-specific alias rather than reusing a public handle across sensitive services.",
            "Do not treat username obscurity as an authentication control."
        ],
        "note": "Offline string review only; no account enumeration, directory lookup or social-profile matching."
    }


def audit_password_security_target(target_path: str, timeout: int = 12) -> dict:
    """Automatically audit a local application tree for password/authentication risks."""
    root = Path(target_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("Enter an existing application source/configuration directory.")
    excluded = {".git", ".venv", "venv", "node_modules", "__pycache__", ".next",
                "dist", "build", "vendor", ".tox", ".mypy_cache"}
    allowed_suffixes = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml",
                        ".toml", ".ini", ".env", ".conf", ".cfg", ".properties", ".php",
                        ".rb", ".go", ".java", ".cs", ".html", ".xml", ".md", ".txt", ".log"}
    max_files, max_file_bytes, max_total_bytes = 1200, 2 * 1024 * 1024, 30 * 1024 * 1024
    scanned, total_bytes = [], 0
    emails, usernames, password_candidates = set(), set(), {}
    findings = []
    password_assignment = re.compile(
        r"""(?im)\b(?:password|passwd|pwd|secret|client_secret|api_key)\b\s*[:=]\s*["'](.*?)["']"""
    )
    username_assignment = re.compile(
        r"""(?im)\b(?:username|user_name|login|account_name)\b\s*[:=]\s*["']([^"'\r\n]{2,100})["']"""
    )
    for file_path in root.rglob("*"):
        if any(part in excluded for part in file_path.parts):
            continue
        if not file_path.is_file() or file_path.is_symlink() or file_path.suffix.lower() not in allowed_suffixes:
            continue
        if len(scanned) >= max_files:
            findings.append({"severity": "info", "finding": "File scan limit reached", "evidence": f"Stopped after {max_files} files."})
            break
        try:
            size = file_path.stat().st_size
            if size > max_file_bytes or total_bytes + size > max_total_bytes:
                continue
            raw = file_path.read_bytes()
            total_bytes += len(raw)
            text_data = raw.decode("utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(file_path.relative_to(root))
        scanned.append(rel)
        for email in re.findall(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text_data):
            emails.add(email.lower())
        for match in username_assignment.finditer(text_data):
            candidate = match.group(1).strip()
            if candidate and len(candidate) <= 64 and not re.search(r"(?i)(example|changeme|your_|placeholder)", candidate):
                usernames.add(candidate[:64])
        for match in password_assignment.finditer(text_data):
            candidate = match.group(1)
            if candidate.lower() in {"", "none", "null", "false", "true", "changeme", "your_password", "password"}:
                continue
            digest = hashlib.sha1(candidate.encode("utf-8")).hexdigest().upper()
            password_candidates[digest] = {"file": rel, "length": len(candidate)}
            findings.append({
                "severity": "high",
                "finding": "Possible hard-coded secret in source/configuration",
                "file": rel,
                "evidence": "A password/secret-like assignment contains a literal value; the value is deliberately redacted.",
                "remediation": "Move the secret to a secret manager or environment variable, rotate it, and remove it from repository history."
            })

    breach_checks = []
    for digest, metadata in list(password_candidates.items())[:50]:
        prefix, suffix = digest[:5], digest[5:]
        request = urllib.request.Request(
            "https://api.pwnedpasswords.com/range/" + prefix,
            headers={"User-Agent": USER_AGENT, "Add-Padding": "true"}
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(500_001).decode("ascii", errors="replace")
            count = 0
            for line in body.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[0].upper() == suffix:
                    count = int(parts[1])
                    break
            breach_checks.append({
                "file": metadata["file"], "secret_value_disclosed": False,
                "breached_password_match": count > 0, "breach_corpus_occurrences": count,
                "check_method": "HIBP Pwned Passwords k-anonymity range API (5-character SHA-1 prefix only)"
            })
            if count:
                findings.append({
                    "severity": "critical", "finding": "Hard-coded password appears in known breach corpus",
                    "file": metadata["file"], "breach_corpus_occurrences": count,
                    "remediation": "Rotate immediately, remove the secret from source and repository history, and block it through the password screening control."
                })
        except (OSError, ValueError, urllib.error.URLError) as exc:
            breach_checks.append({
                "file": metadata["file"], "status": "unavailable",
                "breached_password_match": None, "breach_corpus_occurrences": None,
                "secret_value_disclosed": False, "detail": str(exc)[:300]
            })

    if emails:
        findings.append({
            "severity": "info", "finding": "Email addresses discovered in local project files",
            "count": len(emails), "addresses": sorted(emails)[:100],
            "remediation": "Verify these are intended public/project addresses. Do not publish personal addresses unintentionally."
        })
    if usernames:
        findings.append({
            "severity": "info", "finding": "Username-like configuration values discovered",
            "count": len(usernames), "values": sorted(usernames)[:100],
            "remediation": "Review whether these are service accounts, test identities or personal identifiers; redact before sharing reports."
        })
    if not password_candidates:
        findings.append({
            "severity": "info", "finding": "No obvious literal password/secret assignments detected",
            "evidence": "This is a pattern-based source scan; secrets in other formats, encoded values, runtime stores or external services may be missed."
        })
    return {
        "feature": "automated_password_security_audit",
        "target_directory": str(root),
        "scan_summary": {
            "files_scanned": len(scanned), "bytes_scanned": total_bytes,
            "email_addresses_found": len(emails), "username_values_found": len(usernames),
            "literal_secret_candidates_found": len(password_candidates)
        },
        "breached_password_checks": breach_checks,
        "findings": findings,
        "files_scanned_sample": scanned[:100],
        "scope": {
            "manual_control_answers_requested": False,
            "raw_passwords_sent_to_service": False,
            "external_password_check": "Only the first 5 SHA-1 hex characters are sent to the HIBP Pwned Passwords range endpoint; full hashes and plaintext values remain local.",
            "email_breach_lookup": "Not performed; email addresses are identified in local files only. No addresses are submitted to breach-search services.",
            "username_web_search": "Not performed; usernames are extracted from local configuration only.",
            "login_attempts_or_password_guessing": False
        },
        "limitations": [
            "This is a bounded static source/configuration scan, not a full application penetration test.",
            "Pattern matching can produce false positives and miss secrets stored in other formats.",
            "Email addresses and usernames found in source files are not proof of active accounts or breach exposure.",
            "Password reuse, MFA enforcement and reset-flow security require identity-provider configuration or owner-provided authentication logs."
        ]
    }


def review_password_policy(minimum_length: int, breached_blocklist: str,
                           reuse_prevention: str, reset_protection: str) -> dict:
    if not 8 <= int(minimum_length) <= 128:
        raise ValueError("Minimum password length must be between 8 and 128.")
    controls = {
        "minimum_length": {"configured_value": int(minimum_length), "status": "review" if minimum_length < 14 else "reasonable_baseline"},
        "breached_password_blocklist": _normalise_yes_no_unknown(breached_blocklist, "Breached-password blocklist"),
        "password_reuse_prevention": _normalise_yes_no_unknown(reuse_prevention, "Password reuse prevention"),
        "secure_reset_protection": _normalise_yes_no_unknown(reset_protection, "Secure reset protection"),
    }
    return {
        "feature": "password_policy_assessment",
        "controls": controls,
        "note": "Configuration review based on operator-supplied answers; no passwords are collected or tested."
    }


def _mask_email_address(address: str) -> str:
    local, domain = address.rsplit("@", 1)
    return (local[:1] if local else "") + "***@" + domain.lower()


def assess_mfa_target(login_url: str, email_address: str, timeout: int = 12) -> dict:
    """Passively assess a supplied login page and email domain; never signs in."""
    url = _validate_assessment_url(login_url)
    email = email_address.strip()
    if len(email) > 254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+", email):
        raise ValueError("Enter a valid email address; the address is used locally to scope its domain only.")
    email_domain = validate_domain(email.rsplit("@", 1)[1])
    target_host = (urllib.parse.urlsplit(url).hostname or "").lower()
    same_domain = (target_host == email_domain or target_host.endswith("." + email_domain)
                   or email_domain.endswith("." + target_host))

    page = inspect_assessment_page(url, timeout=timeout, method="GET")
    dns = dns_lookup(email_domain, timeout=timeout)
    forms = page.get("authentication_analysis", {})
    form_rows = forms.get("forms_analysed", [])
    field_names = [str(name).lower() for form in form_rows for name in form.get("field_names", [])]
    input_types = [str(kind).lower() for form in form_rows for kind in form.get("input_types", [])]
    script_urls = [str(item.get("url", "")).lower() for item in page.get("scripts", [])]
    metadata_text = json.dumps({
        "title": page.get("page_title", ""), "metadata": page.get("page_metadata", {}),
        "fields": field_names, "types": input_types, "scripts": script_urls,
    }).lower()
    otp_names = [name for name in field_names if any(term in name for term in (
        "otp", "totp", "mfa", "2fa", "one_time", "verification_code", "authenticator",
        "security_code", "passcode"
    ))]
    otp_types = [kind for kind in input_types if kind == "one-time-code"]
    mfa_keywords = sorted(set(term for term in (
        "multi-factor", "multifactor", "two-factor", "two factor", "2fa", "mfa",
        "authenticator", "passkey", "webauthn", "security key", "verification code",
        "one-time code", "one time password", "totp"
    ) if term in metadata_text))
    dmarc_rows = dns.get("records", {}).get("DMARC", {}).get("answers", [])
    txt_rows = dns.get("records", {}).get("TXT", {}).get("answers", [])
    spf = [str(row.get("value", "")) for row in txt_rows if "v=spf1" in str(row.get("value", "")).lower()]
    dmarc = [str(row.get("value", "")) for row in dmarc_rows if "v=dmarc1" in str(row.get("value", "")).lower()]
    mx = dns.get("records", {}).get("MX", {}).get("answers", [])
    page_status = page.get("status_code")
    page_accessible = isinstance(page_status, int) and 200 <= page_status < 400
    mfa_ui_observed = bool(otp_names or otp_types or mfa_keywords)
    findings = [
        {
            "area": "Login page reachability",
            "status": "observed" if page_accessible else "not_confirmed",
            "evidence": {"url_checked": url, "http_status": page_status, "page_title": page.get("page_title")},
            "interpretation": "The supplied public page responded; reachability does not prove account security."
                            if page_accessible else "The supplied login page did not return a confirmed successful response."
        },
        {
            "area": "Email-to-site scope",
            "status": "same_domain_or_parent_domain" if same_domain else "domain_mismatch_review",
            "evidence": {"login_host": target_host, "email_domain": email_domain},
            "interpretation": "The supplied email domain is related to the login host."
                            if same_domain else "The email domain differs from the login host; confirm that this is the intended identity provider."
        },
        {
            "area": "Visible MFA interface indicators",
            "status": "observed" if mfa_ui_observed else "not_observed_in_static_page",
            "evidence": {"field_names": otp_names[:20], "one_time_code_input_types": otp_types,
                         "page_or_script_terms": mfa_keywords},
            "interpretation": "MFA-related indicators were found in returned HTML metadata, form fields or script URLs. This does not prove MFA is required for the supplied account."
                            if mfa_ui_observed else "No MFA-specific input or keyword was identified in the static page evidence. A JavaScript-rendered or post-password challenge may not appear here."
        },
        {
            "area": "Account-specific MFA enforcement",
            "status": "not_verifiable_without_identity_provider_evidence",
            "evidence": {"account": _mask_email_address(email)},
            "interpretation": "A public login page and email address cannot reveal whether this individual account has MFA enrolled or whether policy enforces it. Verify through the authorised identity-provider security console, API or sign-in logs."
        },
        {
            "area": "Email-domain mail routing",
            "status": "observed" if mx else "no_mx_answer_observed",
            "evidence": {"domain": email_domain, "mx_records": mx},
            "interpretation": "MX records were returned for the email domain." if mx else "No MX answer was returned for the email domain."
        },
        {
            "area": "Email-domain sender protection",
            "status": "records_observed" if spf and dmarc else "review",
            "evidence": {"spf_records": spf, "dmarc_records": dmarc},
            "interpretation": "SPF/DMARC are email anti-spoofing controls, not MFA controls. Their presence does not prove correct policy alignment or account MFA."
        }
    ]
    return {
        "feature": "automated_mfa_2fa_target_assessment",
        "target_url_checked": url,
        "email_address": _mask_email_address(email),
        "email_domain_checked": email_domain,
        "account_identity_provider": "Not reliably identified from public page metadata",
        "page_inspection": page,
        "email_domain_dns": dns,
        "mfa_observations": {
            "visible_mfa_ui_indicators": mfa_ui_observed,
            "otp_related_field_names": otp_names[:20],
            "mfa_related_public_page_terms": mfa_keywords,
            "account_mfa_enrollment": "not_verifiable",
            "account_mfa_enforcement": "not_verifiable",
            "recovery_protection": "not_verifiable",
            "suspicious_login_alerting": "not_verifiable"
        },
        "findings": findings,
        "scope": {
            "http_requests": "One read-only GET to the exact supplied URL; redirects are not followed.",
            "tls": "One certificate-validating TLS handshake.",
            "dns": "Bounded public DNS lookups for the email domain.",
            "email_handling": "The full email address is not sent to any remote service; only its domain is queried.",
            "authentication": "No sign-in, challenge, password, recovery flow or account API access was attempted."
        },
        "limitations": [
            "A public login page cannot establish whether this specific email account has MFA enrolled or policy-enforced.",
            "A visible OTP/passkey control is evidence of an interface feature, not proof it is mandatory or correctly enforced.",
            "Account-level verification requires an authorised identity-provider admin API, security console export or sign-in/authentication logs.",
            "SPF and DMARC concern email-domain spoofing and are not substitutes for MFA."
        ]
    }


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
    def wait_for_menu() -> None:
        try:
            input("\nPress Enter to return to the menu (results remain above)...")
        except (EOFError, KeyboardInterrupt):
            print("\nReturning to the menu.")

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
        print("  [16] Phone Number Intelligence (numbering metadata only)")
        print("  [17] Live Authentication Security Assessment (authorised targets)")
        print("  [18] Username Privacy Assessment")
        print("  [19] Password Policy Assessment")
        print("  [20] MFA / 2FA Security Assessment")
        print("  [21] Global Camera Intelligence (authorised cameras and public webcams)")
        print("  [0] Exit")
        valid_choices = set(services) | {"0", "3", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21"}
        try:
            # Read exactly one selection per menu display. This avoids a tight
            # validation loop consuming buffered blank lines or terminal input.
            choice = input("\ncyberlab> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting CyberLab.")
            return 0
        if not choice:
            print("No selection entered. The menu will be shown again.")
            continue
        if choice not in valid_choices:
            print(f"Invalid selection {choice!r}. Enter a listed option from 0 to 21.")
            continue
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
            wait_for_menu()
            continue
        if choice == "17":
            try:
                print("\nLIVE AUTHENTICATION SECURITY ASSESSMENT")
                print("Inspects one real HTTPS login page. No passwords are guessed or submitted.")
                target = input("Full HTTPS login URL on a system you own or are authorised to assess: ").strip()
                approval = input("Confirm written authorisation for this target (type AUTHORISED): ").strip()
                if approval != "AUTHORISED":
                    print("Assessment cancelled: explicit authorisation was not confirmed.")
                else:
                    result = inspect_assessment_page(target, timeout=timeout, method="GET")
                    result["feature"] = "live_authentication_security_assessment"
                    result["authorisation_confirmation"] = "Operator confirmed authorisation"
                    result["assessment_scope"] = {
                        "requests": "One HTTPS GET to the exact supplied URL",
                        "redirects_followed": False,
                        "credentials_submitted": False,
                        "password_guessing_performed": False,
                        "forms_submitted": False,
                    }
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                    destination = save_investigation(result, "live-authentication-assessment")
                    print(f"Saved locally: {destination}")
            except (OSError, ValueError, urllib.error.URLError) as exc:
                print(f"Authentication assessment stopped: {exc}")
            except (EOFError, KeyboardInterrupt):
                print("\nReturning to the CyberLab menu.")
            wait_for_menu()
            continue
        if choice == "18":
            try:
                username = input("Username to investigate (public web only): ").strip()
                approval = input("Confirm this is your username or an authorised investigation (type SEARCH): ").strip()
                if approval != "SEARCH":
                    print("Search cancelled: authorisation was not confirmed.")
                else:
                    result = username_osint_search(username, timeout=timeout)
                    local_review = assess_username_quality(username)
                    result["local_username_review"] = local_review
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                    destination = save_investigation(result, "username-osint-investigation")
                    print(f"Saved locally: {destination}")
            except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
                print(f"Username investigation stopped: {exc}")
            except (EOFError, KeyboardInterrupt):
                print("\\nReturning to the CyberLab menu.")
            wait_for_menu()
            continue
        if choice == "19":
            try:
                target = input("Application source/configuration directory [current directory]: ").strip() or "."
                result = audit_password_security_target(target, timeout=timeout)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                destination = save_investigation(result, "automated-password-security-audit")
                print(f"Saved locally: {destination}")
            except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
                print(f"Password security audit stopped: {exc}")
            except (EOFError, KeyboardInterrupt):
                print("\\nReturning to the CyberLab menu.")
            wait_for_menu()
            continue
        if choice == "21":
            try:
                result = camera_intelligence_menu()
                if result:
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                    destination = save_investigation(result, "camera-intelligence")
                    print(f"\\nSaved locally: {destination}")
            except (OSError, ValueError) as exc:
                print(f"Camera operation stopped: {exc}")
            except (EOFError, KeyboardInterrupt):
                print("\\nReturning to the CyberLab menu.")
            wait_for_menu()
            continue
        if choice == "20":
            try:
                print("\nAUTOMATED MFA / 2FA TARGET ASSESSMENT")
                print("Enter the exact public login URL and the account email address.")
                print("CyberLab inspects public page/DNS evidence only; it does not sign in.")
                target_url = input("Authorised login page URL (HTTPS): ").strip()
                email_address = input("Account email address (used locally; not sent to a lookup service): ").strip()
                approval = input("Confirm you own or are authorised to assess this login page (type AUTHORISED): ").strip()
                if approval != "AUTHORISED":
                    print("Assessment cancelled: explicit authorisation was not confirmed.")
                else:
                    result = assess_mfa_target(target_url, email_address, timeout=timeout)
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                    destination = save_investigation(result, "mfa-security-assessment")
                    print(f"Saved locally: {destination}")
            except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
                print(f"MFA assessment stopped: {exc}")
            except (EOFError, KeyboardInterrupt):
                print("\nReturning to the CyberLab menu.")
            wait_for_menu()
            continue
        if choice == "16":
            try:
                number = input("Phone number in international format (e.g. +2348012345678): ")
                result = analyse_phone_number_metadata(number)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                destination = save_investigation(result, "phone-number-intelligence")
                print(f"\\nSaved locally: {destination}")
            except (OSError, ValueError) as exc:
                print(f"Phone number review stopped: {exc}")
            wait_for_menu()
            continue
        if choice == "3":
            try:
                result = manual_security_assessment(timeout)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                destination = save_investigation(result, "manual-security-assessment")
                print(f"\nSaved locally: {destination}")
            except (OSError, ValueError) as exc:
                print(f"Assessment stopped: {exc}")
            wait_for_menu()
            continue
        if choice == "8":
            content_analysis_menu(timeout)
            wait_for_menu()
            continue
        if choice in ("9", "10"):
            show_connection_status()
            wait_for_menu()
            continue
        if choice == "11":
            show_session_status()
            wait_for_menu()
            continue
        if choice == "12":
            show_evidence_manager()
            wait_for_menu()
            continue
        if choice == "13":
            show_investigation_history()
            wait_for_menu()
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
            wait_for_menu()
            continue
        if choice not in services:
            print("Choose one of the listed options.")
            continue

        label, command = services[choice]
        try:
            if command == "domain":
                result = domain_osint(input("Public domain: ").strip(), timeout)
            elif command == "dns":
                identifier = input("Domain, website URL, email address or public social profile URL: ").strip()
                result = dns_intelligence_lookup(identifier, timeout)
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
        wait_for_menu()

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
