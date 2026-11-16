"""Conservative native active web checks with strict scope and request budgets.

Only safe GET reflection probes and OPTIONS CORS preflight requests are sent.
No forms are submitted, no credentials are guessed, and no exploit is executed.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from web_testing import execute_request, validate_request

MAX_TARGETS = 10
MAX_REQUESTS = 10
MAX_RUNTIME_SECONDS = 30
MIN_DELAY_MS = 500
MAX_DELAY_MS = 2000
SENSITIVE_PARAM_HINTS = ("token", "key", "auth", "password", "secret", "session", "code", "signature", "jwt", "csrf", "nonce")


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Active checks accept only absolute HTTP or HTTPS URLs.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Remove URL credentials and fragments before testing.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Target URL contains an invalid port.") from exc
    return parsed.scheme.lower(), parsed.hostname.rstrip(".").lower(), port


def _same_origin(url: str, origin: tuple[str, str, int]) -> bool:
    try:
        return _origin(url) == origin
    except ValueError:
        return False


def _headers(response: dict) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for item in response.get("headers", []):
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            result.setdefault(item["name"].lower(), []).append(str(item.get("value", "")))
    return result


def _record(findings: list[dict], key: str, title: str, severity: str,
            url: str, detail: str, confidence: str = "low"):
    findings.append({"id": hashlib.sha256((url + "|" + key).encode()).hexdigest()[:16],
                     "title": title, "severity": severity, "url": url,
                     "detail": detail, "confidence": confidence,
                     "source": "CyberLab native safe active check"})


def run_active_scan(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Active scan request must be a JSON object.")
    urls = data.get("urls")
    if not isinstance(urls, list) or not 1 <= len(urls) <= MAX_TARGETS or any(not isinstance(x, str) for x in urls):
        raise ValueError(f"Provide between 1 and {MAX_TARGETS} in-scope page URLs.")
    origin = _origin(urls[0])
    confirmation = data.get("confirmationUrl")
    if not isinstance(confirmation, str) or _origin(confirmation) != origin:
        raise ValueError("Retype the exact scheme, hostname and port in the scope confirmation field.")
    if data.get("authorizationConfirmed") is not True or data.get("confirmRun") is not True:
        raise ValueError("Confirm written authorisation and explicitly approve active checks.")
    reference = data.get("authorizationReference")
    if not isinstance(reference, str) or not reference.strip() or len(reference) > 160:
        raise ValueError("A valid engagement or authorisation reference is required.")
    max_requests, delay_ms = data.get("maxRequests", 10), data.get("delayMs", 500)
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or not 1 <= max_requests <= MAX_REQUESTS:
        raise ValueError(f"Request budget must be between 1 and {MAX_REQUESTS}.")
    if isinstance(delay_ms, bool) or not isinstance(delay_ms, int) or not MIN_DELAY_MS <= delay_ms <= MAX_DELAY_MS:
        raise ValueError(f"Request delay must be between {MIN_DELAY_MS} and {MAX_DELAY_MS} milliseconds.")

    clean_urls = []
    for url in urls:
        if len(url) > 2048 or not _same_origin(url, origin):
            raise ValueError("Every tested URL must remain inside the exact confirmed origin.")
        if url not in clean_urls:
            clean_urls.append(url)
    base = {"url": clean_urls[0], "confirmationUrl": confirmation, "authorizationConfirmed": True,
            "confirmSend": True, "authorizationReference": reference.strip(),
            "localLabMode": data.get("localLabMode") is True}
    validate_request({**base, "method": "GET"})

    findings: list[dict] = []
    checks: list[dict] = []
    errors = skipped_params = 0
    requests_sent = 0
    started = time.monotonic()
    probe_origin = "https://cyberlab-probe.invalid"

    def send(url: str, method: str, headers: dict | None = None):
        nonlocal requests_sent
        if requests_sent >= max_requests or time.monotonic() - started >= MAX_RUNTIME_SECONDS:
            return None
        request = {**base, "url": url, "method": method, "headers": headers or {}}
        validate_request(request)
        if requests_sent:
            time.sleep(delay_ms / 1000)
        requests_sent += 1
        return execute_request(request)

    for url in clean_urls:
        if requests_sent >= max_requests or time.monotonic() - started >= MAX_RUNTIME_SECONDS:
            break
        # CORS preflight uses a reserved .invalid origin; it never contacts that origin.
        try:
            response = send(url, "OPTIONS", {
                "Origin": probe_origin,
                "Access-Control-Request-Method": "GET",
            })
            if response is not None:
                headers = _headers(response)
                allow_origin = headers.get("access-control-allow-origin", [""])[0].strip()
                allow_credentials = headers.get("access-control-allow-credentials", [""])[0].strip().lower() == "true"
                check = {"type": "cors_preflight", "url": url, "status": response.get("status"),
                         "allowOrigin": allow_origin or None, "allowCredentials": allow_credentials,
                         "responseSha256": hashlib.sha256(str(response.get("body", "")).encode()).hexdigest()}
                checks.append(check)
                if allow_origin == probe_origin and allow_credentials:
                    _record(findings, "cors-reflection", "Potential permissive CORS origin reflection",
                            "medium", url, "The server allowed an arbitrary test origin and credentials on the preflight response. Verify browser behaviour, authentication sensitivity and the complete CORS policy manually.", "medium")
                elif allow_origin == probe_origin:
                    _record(findings, "cors-origin", "Untrusted origin accepted by CORS",
                            "low", url, "The server accepted CyberLab's reserved .invalid test origin. No credentialed access was demonstrated; review the allow-list.")
                elif allow_origin == "*":
                    _record(findings, "cors-wildcard", "Wildcard CORS policy observed",
                            "info", url, "Access-Control-Allow-Origin is '*'. This alone does not prove sensitive data exposure; review whether the resource is intended to be public.")
        except (ValueError, OSError, TimeoutError) as exc:
            errors += 1
            checks.append({"type": "cors_preflight", "url": url, "error": str(exc)[:200]})

        if requests_sent >= max_requests or time.monotonic() - started >= MAX_RUNTIME_SECONDS:
            break
        parsed = urlsplit(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for index, (name, value) in enumerate(params):
            if requests_sent >= max_requests or time.monotonic() - started >= MAX_RUNTIME_SECONDS:
                break
            if any(hint in name.lower() for hint in SENSITIVE_PARAM_HINTS):
                skipped_params += 1
                continue
            marker = "CYBERLABPROBE" + secrets.token_hex(5)
            payload = marker + '"><cyberlab-probe>'
            mutated = list(params)
            mutated[index] = (name, payload)
            test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(mutated), ""))
            if not _same_origin(test_url, origin):
                continue
            try:
                response = send(test_url, "GET")
                if response is None:
                    break
                body = response.get("body", "")
                raw_reflection = isinstance(body, str) and payload in body
                marker_reflection = isinstance(body, str) and marker in body
                checks.append({"type": "query_reflection", "url": url, "parameter": name[:100],
                               "status": response.get("status"), "markerReflected": marker_reflection,
                               "rawSpecialCharactersReflected": raw_reflection,
                               "responseSha256": hashlib.sha256(str(body).encode()).hexdigest()})
                if raw_reflection:
                    _record(findings, "reflection:" + name, "Potential unescaped query input reflection",
                            "low", url, f"Parameter '{name[:100]}' reflected the scanner's inert HTML marker without escaping. This is a candidate only: the scanner did not execute script and HTML context must be manually verified.")
            except (ValueError, OSError, TimeoutError) as exc:
                errors += 1
                checks.append({"type": "query_reflection", "url": url, "parameter": name[:100], "error": str(exc)[:200]})

    return {
        "status": "completed",
        "scope": {"origin": f"{origin[0]}://{origin[1]}:{origin[2]}",
                  "authorizationReference": reference.strip(), "localLabMode": base["localLabMode"]},
        "summary": {"requestsSent": requests_sent, "checksRun": len(checks),
                    "findings": len(findings), "requestErrors": errors,
                    "sensitiveParametersSkipped": skipped_params,
                    "elapsedMs": round((time.monotonic() - started) * 1000)},
        "checks": checks, "findings": findings,
        "limitations": [
            "Only OPTIONS CORS preflight and GET query-reflection checks are performed.",
            "No forms are submitted; no POST, PUT, PATCH or DELETE requests are sent.",
            "No authentication bypass, SQL injection, SSRF, IDOR, path traversal, credential testing or exploit execution is performed.",
            "Reflection and CORS indicators require manual verification and are not proof of exploitability.",
            "Authentication/session handling, WebSockets, GraphQL, crawler-wide testing and advanced scanner checks are not implemented.",
            "Redirects are not followed; every tested URL must remain within the confirmed origin.",
        ],
    }
