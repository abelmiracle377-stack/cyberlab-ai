"""Bounded, same-origin native web crawler and baseline security review.

This module sends only approved GET requests. It does not submit forms, follow
redirects, inject payloads, authenticate, or attempt exploitation.
"""
from __future__ import annotations

import hashlib
import time
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from web_testing import execute_request, validate_request

MAX_PAGES = 20
MAX_DEPTH = 2
MAX_RUNTIME_SECONDS = 45
MAX_LINKS_PER_PAGE = 200
MAX_URL_LENGTH = 2048
MIN_DELAY_MS = 250
MAX_DELAY_MS = 2000
STATIC_SUFFIXES = (".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".pdf", ".zip", ".mp4", ".mp3", ".webm", ".avif")


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Crawler accepts only absolute HTTP or HTTPS URLs.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Remove URL credentials and fragments before crawling.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Target URL contains an invalid port.") from exc
    return parsed.scheme.lower(), parsed.hostname.rstrip(".").lower(), port


def _canonical(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


def _same_origin(url: str, origin: tuple[str, str, int]) -> bool:
    try:
        return _origin(url) == origin
    except ValueError:
        return False


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        values = {key.lower(): value or "" for key, value in attrs if key}
        if tag in {"a", "area"} and values.get("href"):
            self.links.append(values["href"])
        elif tag == "form":
            self._form = {"action": values.get("action", ""), "method": values.get("method", "GET").upper(), "inputs": []}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append({"name": values.get("name", "")[:100], "type": values.get("type", "text").lower()[:30]})

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _header_map(headers: list[dict]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for item in headers:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            result.setdefault(item["name"].lower(), []).append(str(item.get("value", "")))
    return result


def _finding(findings: list[dict], seen: set[tuple[str, str]], url: str, key: str,
             title: str, severity: str, detail: str):
    identity = (url, key)
    if identity in seen:
        return
    seen.add(identity)
    findings.append({"id": hashlib.sha256((url + "|" + key).encode()).hexdigest()[:16],
                     "title": title, "severity": severity, "url": url, "detail": detail,
                     "confidence": "medium", "source": "native GET-only baseline review"})


def _review_response(url: str, response: dict, findings: list[dict],
                     seen: set[tuple[str, str]]) -> int:
    headers = _header_map(response.get("headers", []))
    scheme = urlsplit(url).scheme
    checks = [
        ("content-security-policy", "Content Security Policy is not present", "low",
         "The response did not include a Content-Security-Policy header. Review whether a policy is appropriate for this application."),
        ("x-content-type-options", "MIME-sniffing protection is not present", "low",
         "The response did not include X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer-Policy is not present", "info",
         "The response did not declare a Referrer-Policy."),
        ("permissions-policy", "Permissions-Policy is not present", "info",
         "The response did not declare a Permissions-Policy."),
    ]
    for header, title, severity, detail in checks:
        if header not in headers:
            _finding(findings, seen, url, header, title, severity, detail)
    if scheme == "https" and "strict-transport-security" not in headers:
        _finding(findings, seen, url, "hsts", "HTTP Strict Transport Security is not present", "low",
                 "The HTTPS response did not include Strict-Transport-Security. Confirm the deployment topology before enabling HSTS.")
    for cookie in headers.get("set-cookie", []):
        name = cookie.split("=", 1)[0].strip()[:100] or "(unnamed cookie)"
        flags = cookie.lower()
        if scheme == "https" and "; secure" not in flags:
            _finding(findings, seen, url, "cookie-secure:" + name, "Cookie is missing the Secure attribute", "low",
                     f"{name} was set without the Secure attribute.")
        if "; httponly" not in flags:
            _finding(findings, seen, url, "cookie-httponly:" + name, "Cookie is missing the HttpOnly attribute", "info",
                     f"{name} was set without the HttpOnly attribute. Review whether client-side access is required.")
        if "samesite=" not in flags:
            _finding(findings, seen, url, "cookie-samesite:" + name, "Cookie does not declare SameSite", "info",
                     f"{name} did not declare a SameSite attribute.")
    return len(headers.get("set-cookie", []))


def run_crawl(data: dict) -> dict:
    """Run an explicitly approved, bounded, same-origin GET-only crawl."""
    if not isinstance(data, dict):
        raise ValueError("Crawler request must be a JSON object.")
    start_url = data.get("url")
    if not isinstance(start_url, str) or len(start_url) > MAX_URL_LENGTH:
        raise ValueError("Enter one HTTP(S) start URL (maximum 2048 characters).")
    origin = _origin(start_url)
    confirmation = data.get("confirmationUrl")
    if not isinstance(confirmation, str) or _origin(confirmation) != origin:
        raise ValueError("Retype the exact scheme, hostname and port in the scope confirmation field.")
    if data.get("authorizationConfirmed") is not True or data.get("confirmRun") is not True:
        raise ValueError("Confirm written authorisation and explicitly approve the crawl.")
    reference = data.get("authorizationReference")
    if not isinstance(reference, str) or not reference.strip() or len(reference) > 160:
        raise ValueError("A valid engagement or authorisation reference is required.")
    max_pages, max_depth, delay_ms = data.get("maxPages", 10), data.get("maxDepth", 2), data.get("delayMs", 500)
    if isinstance(max_pages, bool) or not isinstance(max_pages, int) or not 1 <= max_pages <= MAX_PAGES:
        raise ValueError(f"Page budget must be between 1 and {MAX_PAGES}.")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 0 <= max_depth <= MAX_DEPTH:
        raise ValueError(f"Crawl depth must be between 0 and {MAX_DEPTH}.")
    if isinstance(delay_ms, bool) or not isinstance(delay_ms, int) or not MIN_DELAY_MS <= delay_ms <= MAX_DELAY_MS:
        raise ValueError(f"Request delay must be between {MIN_DELAY_MS} and {MAX_DELAY_MS} milliseconds.")

    start_url = _canonical(start_url)
    base_request = {"url": start_url, "confirmationUrl": confirmation, "authorizationConfirmed": True,
                    "confirmSend": True, "authorizationReference": reference.strip(),
                    "localLabMode": data.get("localLabMode") is True, "method": "GET"}
    validate_request(base_request)

    queue = deque([(start_url, 0)])
    queued = {start_url}
    visited: set[str] = set()
    pages, findings = [], []
    finding_keys: set[tuple[str, str]] = set()
    started = time.monotonic()
    discovered_links = form_count = cookie_count = blocked_out_of_scope = errors = 0

    while queue and len(pages) < max_pages and time.monotonic() - started < MAX_RUNTIME_SECONDS:
        url, depth = queue.popleft()
        if url in visited:
            continue
        if not _same_origin(url, origin):
            blocked_out_of_scope += 1
            continue
        visited.add(url)
        request_data = {**base_request, "url": url}
        try:
            validate_request(request_data)
            if pages:
                time.sleep(delay_ms / 1000)
            response = execute_request(request_data)
        except (ValueError, OSError, TimeoutError) as exc:
            errors += 1
            pages.append({"url": url, "depth": depth, "status": None, "error": str(exc)[:240], "linksDiscovered": 0})
            continue

        body = response.get("body", "")
        if not isinstance(body, str):
            body = ""
        headers = response.get("headers", [])
        content_type = next((str(h.get("value", "")) for h in headers
                             if isinstance(h, dict) and str(h.get("name", "")).lower() == "content-type"), "")
        page = {"url": url, "depth": depth, "status": response.get("status"), "contentType": content_type,
                "bodyBytes": response.get("bodyBytes", len(body.encode("utf-8"))),
                "responseSha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                "truncated": response.get("truncated") is True, "linksDiscovered": 0, "redirectFollowed": False}
        pages.append(page)
        cookie_count += _review_response(url, response, findings, finding_keys)

        if "text/html" not in content_type.lower() or depth >= max_depth or page["truncated"]:
            continue
        parser = _PageParser()
        try:
            parser.feed(body[:MAX_URL_LENGTH * 32])
        except Exception:
            continue
        form_count += len(parser.forms)
        links_added = 0
        for href in parser.links[:MAX_LINKS_PER_PAGE]:
            if not isinstance(href, str) or len(href) > MAX_URL_LENGTH:
                continue
            candidate = _canonical(urljoin(url, href))
            if urlsplit(candidate).path.lower().endswith(STATIC_SUFFIXES):
                continue
            if not _same_origin(candidate, origin):
                blocked_out_of_scope += 1
                continue
            if candidate not in visited and candidate not in queued:
                queue.append((candidate, depth + 1))
                queued.add(candidate)
                links_added += 1
                discovered_links += 1
        page["linksDiscovered"] = links_added

    elapsed_ms = round((time.monotonic() - started) * 1000)
    return {
        "status": "completed",
        "scope": {"origin": f"{origin[0]}://{origin[1]}:{origin[2]}", "authorizationReference": reference.strip(),
                  "localLabMode": base_request["localLabMode"]},
        "limits": {"maxPages": max_pages, "maxDepth": max_depth, "delayMs": delay_ms,
                   "maxRuntimeSeconds": MAX_RUNTIME_SECONDS},
        "summary": {"pagesVisited": len(pages), "htmlPages": sum(1 for p in pages if "text/html" in p.get("contentType", "").lower()),
                    "linksDiscovered": discovered_links, "formsObserved": form_count, "cookiesObserved": cookie_count,
                    "findings": len(findings), "requestErrors": errors,
                    "outOfScopeLinksBlocked": blocked_out_of_scope, "elapsedMs": elapsed_ms},
        "pages": pages, "findings": findings,
        "limitations": [
            "GET requests only; forms are inventoried but never submitted.",
            "Redirects are not followed and links outside the confirmed origin are blocked.",
            "No payload injection, authentication bypass, SQL injection, XSS, IDOR or other exploit testing is performed.",
            "Header and cookie observations are baseline indicators, not proof of exploitability.",
            "Results are limited to pages reached within the configured page, depth, delay and runtime budgets.",
        ],
    }
