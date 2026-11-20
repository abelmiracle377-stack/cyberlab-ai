"""Native web application security assessment — bug-bounty-parity DAST checks.

This extends CyberLab's conservative active scanner with the broader set of
checks a human bug-bounty hunter runs: security-header and cookie hardening,
information disclosure, sensitive-file exposure, open-redirect, SQL-error and
reflected-input detection, and risky HTTP methods. Everything here is
**detection and reporting**, mapped to OWASP/CWE with remediation — no
exploitation, no data extraction, no weaponisation.

Scope is gated exactly like `web_active_scan`: an in-scope origin, a retyped
confirmation, an explicit authorisation reference, and request budgets. The
network-touching entry point is `run_assessment`; the analysers it calls are
pure functions over a response, so the whole check set is unit-tested offline.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from web_active_scan import _headers, _origin, _same_origin
from web_testing import execute_request, validate_request

MAX_TARGETS = 10
MAX_REQUESTS = 25
MAX_RUNTIME_SECONDS = 45
MIN_DELAY_MS = 500
MAX_DELAY_MS = 2000

SENSITIVE_PARAM_HINTS = ("token", "key", "auth", "password", "secret", "session", "signature", "jwt", "csrf", "nonce")
REDIRECT_PARAMS = {"url", "next", "redirect", "redir", "return", "returnurl", "returnto",
                   "dest", "destination", "continue", "goto", "out", "target", "rurl", "link"}
REDIRECT_MARKER = "https://cyberlab-redirect.invalid/"

SENSITIVE_PATHS = (".git/HEAD", ".env", ".well-known/security.txt", "robots.txt", "server-status", ".DS_Store")

SQL_ERROR_SIGNATURES = (
    "you have an error in your sql syntax", "warning: mysqli", "mysql_fetch", "unclosed quotation mark",
    "ora-0", "sqlstate", "psql:", "pg_query", "sqliteexception", "microsoft ole db", "odbc sql server",
    "native client error", "sql syntax",
)
DISCLOSURE_SIGNATURES = (
    "traceback (most recent call last)", "java.lang.", "at org.springframework", ".java:",
    "microsoft .net framework", "warning: include(", "fatal error:", "notice: undefined", "stack trace:",
)


def _finding(url: str, key: str, title: str, severity: str, owasp: str, cwe: str,
             detail: str, remediation: str, confidence: str = "medium") -> dict:
    return {
        "id": hashlib.sha256((url + "|" + key).encode()).hexdigest()[:16],
        "title": title, "severity": severity, "owasp": owasp, "cwe": cwe,
        "url": url, "detail": detail, "remediation": remediation,
        "confidence": confidence, "source": "CyberLab native assessment",
    }


def _first(headers: dict, name: str) -> str:
    return (headers.get(name.lower(), [""]) or [""])[0].strip()


def check_security_headers(url: str, headers: dict, is_https: bool) -> list:
    """Flag missing or weak security response headers."""
    out = []
    if is_https and not _first(headers, "strict-transport-security"):
        out.append(_finding(url, "hsts", "Missing HSTS header", "medium",
                            "A05: Security Misconfiguration", "CWE-319",
                            "No Strict-Transport-Security header; browsers may downgrade to HTTP.",
                            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", "high"))
    if not _first(headers, "content-security-policy"):
        out.append(_finding(url, "csp", "Missing Content-Security-Policy", "medium",
                            "A05: Security Misconfiguration", "CWE-693",
                            "No CSP header; reduces defence-in-depth against XSS and injection.",
                            "Define a restrictive Content-Security-Policy and tighten iteratively.", "high"))
    xfo = _first(headers, "x-frame-options").lower()
    csp = _first(headers, "content-security-policy").lower()
    if xfo not in {"deny", "sameorigin"} and "frame-ancestors" not in csp:
        out.append(_finding(url, "clickjacking", "No clickjacking protection", "medium",
                            "A05: Security Misconfiguration", "CWE-1021",
                            "Neither X-Frame-Options nor CSP frame-ancestors restricts framing.",
                            "Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.", "high"))
    if _first(headers, "x-content-type-options").lower() != "nosniff":
        out.append(_finding(url, "nosniff", "Missing X-Content-Type-Options", "low",
                            "A05: Security Misconfiguration", "CWE-693",
                            "Responses can be MIME-sniffed by the browser.",
                            "Send 'X-Content-Type-Options: nosniff'.", "high"))
    if not _first(headers, "referrer-policy"):
        out.append(_finding(url, "referrer-policy", "Missing Referrer-Policy", "info",
                            "A05: Security Misconfiguration", "CWE-200",
                            "No Referrer-Policy; URLs may leak to third parties.",
                            "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.", "high"))
    for header, label in (("server", "Server"), ("x-powered-by", "X-Powered-By")):
        value = _first(headers, header)
        if value and any(ch.isdigit() for ch in value):
            out.append(_finding(url, "disclosure:" + header, f"Technology disclosure via {label}", "info",
                                "A05: Security Misconfiguration", "CWE-200",
                                f"The {label} header reveals '{value[:80]}', aiding targeted attacks.",
                                f"Remove or genericise the {label} header.", "high"))
    return out


def check_cookies(url: str, set_cookies: list, is_https: bool) -> list:
    """Flag session-cookie flags that are missing (Secure / HttpOnly / SameSite)."""
    out = []
    for raw in set_cookies:
        if not isinstance(raw, str) or "=" not in raw:
            continue
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        if is_https and "secure" not in low:
            out.append(_finding(url, "cookie-secure:" + name, f"Cookie '{name[:40]}' missing Secure", "medium",
                                "A05: Security Misconfiguration", "CWE-614",
                                "Cookie set over HTTPS without the Secure flag; it can leak over HTTP.",
                                "Add the Secure attribute to every cookie.", "high"))
        if "httponly" not in low:
            out.append(_finding(url, "cookie-httponly:" + name, f"Cookie '{name[:40]}' missing HttpOnly", "low",
                                "A05: Security Misconfiguration", "CWE-1004",
                                "Cookie is readable by JavaScript; raises XSS impact.",
                                "Add HttpOnly to session cookies.", "high"))
        if "samesite" not in low:
            out.append(_finding(url, "cookie-samesite:" + name, f"Cookie '{name[:40]}' missing SameSite", "low",
                                "A05: Security Misconfiguration", "CWE-1275",
                                "No SameSite attribute; raises CSRF exposure.",
                                "Set SameSite=Lax or Strict as appropriate.", "high"))
    return out


def check_body_disclosure(url: str, body: str) -> list:
    """Detect directory listings and leaked stack traces / error detail."""
    out = []
    if not isinstance(body, str):
        return out
    low = body.lower()
    if "index of /" in low and "<title>index of" in low:
        out.append(_finding(url, "dir-listing", "Directory listing enabled", "medium",
                            "A05: Security Misconfiguration", "CWE-548",
                            "The server returned an auto-generated directory index.",
                            "Disable automatic directory indexing (e.g. Options -Indexes).", "high"))
    hit = next((s for s in DISCLOSURE_SIGNATURES if s in low), None)
    if hit:
        out.append(_finding(url, "info-disclosure", "Verbose error / stack trace disclosed", "low",
                            "A05: Security Misconfiguration", "CWE-209",
                            f"Response body contains an internal error signature ('{hit}').",
                            "Return generic error pages; log details server-side only.", "medium"))
    return out


def classify_sensitive_path(url: str, path: str, status: int, body: str) -> dict | None:
    """Classify a probed sensitive path from its status and body signature."""
    body = body if isinstance(body, str) else ""
    low = body.lower()
    if status != 200:
        return None
    if path == ".git/HEAD" and body.strip().startswith("ref:"):
        return _finding(url, "git-exposed", "Exposed .git repository", "high",
                        "A05: Security Misconfiguration", "CWE-527",
                        "/.git/HEAD is served and references a git ref; source and history may be downloadable.",
                        "Block access to the .git directory at the web server.", "high")
    if path == ".env" and re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}=", body):
        return _finding(url, "env-exposed", "Exposed environment (.env) file", "high",
                        "A05: Security Misconfiguration", "CWE-538",
                        "An .env file with KEY=VALUE lines is publicly served; likely leaks secrets.",
                        "Remove the file from the web root and rotate any exposed secrets.", "high")
    if path == "server-status" and "apache server status" in low:
        return _finding(url, "server-status", "Apache server-status exposed", "medium",
                        "A05: Security Misconfiguration", "CWE-200",
                        "/server-status is public, exposing requests, clients and internals.",
                        "Restrict mod_status to localhost or remove it.", "high")
    if path == ".DS_Store" and ("bud1" in low or "\x00\x00\x00\x01Bud1" in body):
        return _finding(url, "dsstore", "Exposed .DS_Store file", "low",
                        "A05: Security Misconfiguration", "CWE-538",
                        "A macOS .DS_Store file is served and can reveal directory names.",
                        "Remove .DS_Store files and block the pattern.", "high")
    if path == ".well-known/security.txt":
        return _finding(url, "securitytxt", "security.txt present", "info",
                        "A05: Security Misconfiguration", "CWE-200",
                        "A security.txt is published (a positive signal for coordinated disclosure).",
                        "No action needed; keep contacts current.", "high")
    return None


def detect_open_redirect(url: str, location: str, marker: str = REDIRECT_MARKER) -> dict | None:
    """Detect an open redirect: the Location header points at the inert marker host."""
    if not isinstance(location, str):
        return None
    loc = location.strip().lower()
    if loc.startswith(marker.lower()) or loc.startswith("//cyberlab-redirect.invalid"):
        return _finding(url, "open-redirect", "Open redirect", "high",
                        "A01: Broken Access Control", "CWE-601",
                        "A redirect parameter sent the response to an attacker-controlled external host.",
                        "Allow-list redirect targets or use server-side mapping keys.", "high")
    return None


def detect_sql_error(url: str, param: str, body: str) -> dict | None:
    """Detect an error-based SQL injection candidate from a DB error signature."""
    if not isinstance(body, str):
        return None
    low = body.lower()
    hit = next((s for s in SQL_ERROR_SIGNATURES if s in low), None)
    if hit:
        return _finding(url, "sqli:" + param, "SQL injection candidate (error-based)", "high",
                        "A03: Injection", "CWE-89",
                        f"Parameter '{param[:80]}' triggered a database error signature ('{hit}') after a single quote. "
                        "Detection only — no data was extracted.",
                        "Use parameterised queries / prepared statements; validate input.", "medium")
    return None


def check_http_methods(url: str, allow_header: str) -> list:
    """Flag risky HTTP methods advertised by an OPTIONS Allow header."""
    out = []
    methods = {m.strip().upper() for m in (allow_header or "").split(",") if m.strip()}
    risky = methods & {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
    if "TRACE" in methods:
        out.append(_finding(url, "trace", "HTTP TRACE enabled", "low", "A05: Security Misconfiguration",
                            "CWE-693", "TRACE is enabled and can aid cross-site tracing.",
                            "Disable the TRACE method.", "high"))
    writeable = methods & {"PUT", "DELETE", "PATCH"}
    if writeable:
        out.append(_finding(url, "write-methods", "Write HTTP methods advertised", "medium",
                            "A05: Security Misconfiguration", "CWE-650",
                            f"The server advertises {', '.join(sorted(writeable))} via Allow; verify they are authenticated.",
                            "Disable unused methods and enforce authorisation on the rest.", "low"))
    return [f for f in out] if risky else out


def _validate_scope(data: dict) -> tuple:
    """Reuse the active-scanner scope contract: in-scope origin + explicit authorisation."""
    if not isinstance(data, dict):
        raise ValueError("Assessment request must be a JSON object.")
    urls = data.get("urls")
    if not isinstance(urls, list) or not 1 <= len(urls) <= MAX_TARGETS or any(not isinstance(x, str) for x in urls):
        raise ValueError(f"Provide between 1 and {MAX_TARGETS} in-scope page URLs.")
    origin = _origin(urls[0])
    confirmation = data.get("confirmationUrl")
    if not isinstance(confirmation, str) or _origin(confirmation) != origin:
        raise ValueError("Retype the exact scheme, hostname and port in the scope confirmation field.")
    if data.get("authorizationConfirmed") is not True or data.get("confirmRun") is not True:
        raise ValueError("Confirm written authorisation and explicitly approve the assessment.")
    reference = data.get("authorizationReference")
    if not isinstance(reference, str) or not reference.strip() or len(reference) > 160:
        raise ValueError("A valid engagement or authorisation reference is required.")
    clean = []
    for url in urls:
        if len(url) > 2048 or not _same_origin(url, origin):
            raise ValueError("Every tested URL must remain inside the exact confirmed origin.")
        if url not in clean:
            clean.append(url)
    return origin, confirmation, reference.strip(), clean


def run_assessment(data: dict, executor=execute_request, validator=validate_request) -> dict:
    """Run the full passive + safe-active assessment over an authorised scope."""
    origin, confirmation, reference, clean_urls = _validate_scope(data)
    is_https = origin[0] == "https"
    max_requests, delay_ms = data.get("maxRequests", MAX_REQUESTS), data.get("delayMs", 500)
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or not 1 <= max_requests <= MAX_REQUESTS:
        raise ValueError(f"Request budget must be between 1 and {MAX_REQUESTS}.")
    if isinstance(delay_ms, bool) or not isinstance(delay_ms, int) or not MIN_DELAY_MS <= delay_ms <= MAX_DELAY_MS:
        raise ValueError(f"Request delay must be between {MIN_DELAY_MS} and {MAX_DELAY_MS} milliseconds.")

    base = {"url": clean_urls[0], "confirmationUrl": confirmation, "authorizationConfirmed": True,
            "confirmSend": True, "authorizationReference": reference,
            "localLabMode": data.get("localLabMode") is True}

    findings: list[dict] = []
    checks: list[dict] = []
    requests_sent = errors = skipped = 0
    started = time.monotonic()

    def send(url: str, method: str = "GET", headers: dict | None = None):
        nonlocal requests_sent
        if requests_sent >= max_requests or time.monotonic() - started >= MAX_RUNTIME_SECONDS:
            return None
        request = {**base, "url": url, "method": method, "headers": headers or {}}
        validator(request)
        if requests_sent:
            time.sleep(delay_ms / 1000)
        requests_sent += 1
        return executor(request)

    def _dedupe(new: list):
        seen = {f["id"] for f in findings}
        for f in new:
            if f["id"] not in seen:
                findings.append(f); seen.add(f["id"])

    for url in clean_urls:
        resp = send(url, "GET")
        if resp is None:
            break
        headers = _headers(resp)
        body = resp.get("body", "")
        _dedupe(check_security_headers(url, headers, is_https))
        _dedupe(check_cookies(url, headers.get("set-cookie", []), is_https))
        _dedupe(check_body_disclosure(url, body))
        checks.append({"type": "page", "url": url, "status": resp.get("status"),
                       "responseSha256": hashlib.sha256(str(body).encode()).hexdigest()})

        parsed = urlsplit(url)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if requests_sent >= max_requests or time.monotonic() - started >= MAX_RUNTIME_SECONDS:
                break
            if any(h in name.lower() for h in SENSITIVE_PARAM_HINTS):
                skipped += 1
                continue
            if name.lower() in REDIRECT_PARAMS:
                mutated = [(n, REDIRECT_MARKER if n == name else v) for n, v in parse_qsl(parsed.query, keep_blank_values=True)]
                test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(mutated), ""))
                if _same_origin(test_url, origin):
                    r = send(test_url, "GET")
                    if r is not None:
                        loc = _headers(r).get("location", [""])[0]
                        f = detect_open_redirect(url, loc)
                        if f:
                            _dedupe([f])
                        checks.append({"type": "open_redirect", "url": url, "parameter": name[:100], "location": loc[:200]})
            else:
                mutated = [(n, (v + "'") if n == name else v) for n, v in parse_qsl(parsed.query, keep_blank_values=True)]
                test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(mutated), ""))
                if _same_origin(test_url, origin):
                    r = send(test_url, "GET")
                    if r is not None:
                        f = detect_sql_error(url, name, r.get("body", ""))
                        if f:
                            _dedupe([f])
                        checks.append({"type": "sql_error_probe", "url": url, "parameter": name[:100], "status": r.get("status")})

    # OPTIONS method probe on the first URL.
    if requests_sent < max_requests and time.monotonic() - started < MAX_RUNTIME_SECONDS:
        r = send(clean_urls[0], "OPTIONS")
        if r is not None:
            allow = _headers(r).get("allow", [""])[0]
            _dedupe(check_http_methods(clean_urls[0], allow))
            checks.append({"type": "http_methods", "url": clean_urls[0], "allow": allow[:200]})

    # Sensitive-path probing against the confirmed origin root.
    root = f"{origin[0]}://{origin[1]}:{origin[2]}/"
    for path in SENSITIVE_PATHS:
        if requests_sent >= max_requests or time.monotonic() - started >= MAX_RUNTIME_SECONDS:
            break
        probe = root + path
        try:
            r = send(probe, "GET")
        except (ValueError, OSError, TimeoutError) as exc:
            errors += 1
            checks.append({"type": "sensitive_path", "url": probe, "error": str(exc)[:200]})
            continue
        if r is None:
            break
        f = classify_sensitive_path(root, path, r.get("status", 0), r.get("body", ""))
        if f:
            _dedupe([f])
        checks.append({"type": "sensitive_path", "url": probe, "status": r.get("status")})

    severities = {}
    for f in findings:
        severities[f["severity"]] = severities.get(f["severity"], 0) + 1
    return {
        "status": "completed",
        "scope": {"origin": f"{origin[0]}://{origin[1]}:{origin[2]}",
                  "authorizationReference": reference, "localLabMode": base["localLabMode"]},
        "summary": {"requestsSent": requests_sent, "checksRun": len(checks),
                    "findings": len(findings), "bySeverity": severities,
                    "requestErrors": errors, "sensitiveParametersSkipped": skipped,
                    "elapsedMs": round((time.monotonic() - started) * 1000)},
        "findings": findings, "checks": checks,
        "limitations": [
            "Detection only: no exploitation, data extraction, authentication bypass or state change is performed.",
            "Findings are candidates that require manual verification; they are not proof of exploitability.",
            "Probes are rate-limited and budget-capped; a full manual test covers more than this baseline.",
            "Redirects are not followed; every tested URL stays within the confirmed origin.",
        ],
    }
