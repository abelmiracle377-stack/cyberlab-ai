"""CyberLab-native, scope-bound HTTP request workbench.

The local companion sends requests directly. Redirects are never followed,
request/response sizes are bounded, and history is process-memory only.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
import uuid
from collections import deque
from urllib.parse import urlsplit, urlunsplit

MAX_REQUEST_BODY = 16 * 1024
MAX_RESPONSE_BODY = 256 * 1024
MAX_TIMEOUT = 12
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
BLOCKED_HEADERS = {"host", "connection", "content-length", "transfer-encoding", "upgrade", "expect", "proxy-authorization", "proxy-connection"}
_HISTORY = deque(maxlen=25)
_HISTORY_LOCK = threading.Lock()


def _resolve_pinned(host: str, port: int, local_lab: bool) -> list[str]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("Target hostname could not be resolved.") from exc
    addresses = sorted({record[4][0].split("%", 1)[0] for record in records})
    if not addresses or len(addresses) > 8:
        raise ValueError("Target must resolve to between one and eight addresses.")
    parsed = [ipaddress.ip_address(item) for item in addresses]
    if local_lab:
        if not all(item.is_loopback for item in parsed):
            raise ValueError("Local-lab mode is restricted to loopback addresses only.")
    elif not all(item.is_global for item in parsed):
        raise ValueError("Private, loopback, link-local, reserved and mixed public/private DNS targets are blocked.")
    return addresses


def validate_request(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Request must be a JSON object.")
    raw_url = data.get("url")
    confirmation = data.get("confirmationUrl")
    reference = data.get("authorizationReference")
    if not isinstance(raw_url, str) or len(raw_url) > 2048:
        raise ValueError("Enter one HTTP or HTTPS target URL (maximum 2048 characters).")
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Use an HTTP(S) URL without embedded credentials.")
    if parsed.fragment:
        raise ValueError("Remove the URL fragment; fragments are not sent to servers.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Target URL contains an invalid port.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Target port must be between 1 and 65535.")
    host = parsed.hostname.rstrip(".").lower()
    confirmed = urlsplit(confirmation).hostname.rstrip(".").lower() if isinstance(confirmation, str) and confirmation else ""
    if not host or confirmed != host:
        raise ValueError("Retype the exact target hostname in the scope confirmation field.")
    if data.get("authorizationConfirmed") is not True or data.get("confirmSend") is not True:
        raise ValueError("Confirm written authorisation and explicitly approve sending this request.")
    if not isinstance(reference, str) or not reference.strip() or len(reference) > 160:
        raise ValueError("A valid engagement or authorisation reference is required.")
    method = data.get("method", "GET")
    if not isinstance(method, str) or method.upper() not in ALLOWED_METHODS:
        raise ValueError("Supported methods: GET, HEAD, OPTIONS, POST, PUT, PATCH and DELETE.")
    method = method.upper()
    if method in MUTATING_METHODS and data.get("confirmStateChange") is not True:
        raise ValueError("This method can change server state. Explicitly confirm that this action is safe and authorised.")
    local_lab = data.get("localLabMode") is True
    if local_lab and host not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Local-lab mode accepts localhost or a loopback IP only.")
    addresses = _resolve_pinned(host, port, local_lab)
    path = parsed.path or "/"
    if not path.startswith("/") or any(ord(char) < 32 for char in path):
        raise ValueError("Invalid request path.")
    target = path + (("?" + parsed.query) if parsed.query else "")
    # The companion writes an HTTP/1.1 request line directly. Reject raw
    # whitespace and control bytes instead of emitting an ambiguous request
    # target; callers must percent-encode them as required by URI syntax.
    if any(ord(char) <= 32 or ord(char) == 127 for char in target):
        raise ValueError("Request path and query must be percent-encoded; whitespace and control characters are not accepted.")
    headers = data.get("headers", {})
    if not isinstance(headers, dict) or len(headers) > 40:
        raise ValueError("Headers must be an object containing no more than 40 entries.")
    clean_headers = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str) or len(key) > 100 or len(value) > 4096:
            raise ValueError("Header names and values must be bounded text.")
        if not key or any(ord(char) < 33 or ord(char) > 126 for char in key):
            raise ValueError("Invalid HTTP header name.")
        if any(char in key for char in '()<>@,;:/[]?={}'):
            raise ValueError("Invalid HTTP header name.")
        lowered = key.lower()
        if lowered in BLOCKED_HEADERS or lowered.startswith("proxy-"):
            raise ValueError("Host, connection, proxy and framing headers are controlled by CyberLab.")
        if any((ord(char) < 32 and char != "\t") or ord(char) == 127 or ord(char) > 255 for char in value):
            raise ValueError("Header values must contain only valid HTTP field characters representable in ISO-8859-1.")
        clean_headers[key] = value
    body = data.get("body", "")
    if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_REQUEST_BODY:
        raise ValueError("Request body must be text no larger than 16 KB.")
    if method in {"GET", "HEAD", "OPTIONS"} and body:
        raise ValueError("GET, HEAD and OPTIONS requests must not include a request body.")
    return {
        "url": raw_url, "scheme": parsed.scheme, "host": host, "port": port,
        "addresses": addresses, "target": target, "method": method,
        "headers": clean_headers, "body": body.encode("utf-8"),
        "authorization_reference": reference.strip(),
    }


SENSITIVE_HISTORY_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token", "x-access-token"}


def _safe_history_request(request: dict) -> dict:
    """Keep replayable non-secret request metadata, never credentials or body content."""
    safe_headers = {}
    for key, value in request.get("headers", {}).items():
        lowered = key.lower()
        sensitive = lowered in SENSITIVE_HISTORY_HEADERS or "token" in lowered or "secret" in lowered
        safe_headers[key] = "[REDACTED]" if sensitive else value
    body_length = len(request.get("body", b""))
    return {
        "requestHeaders": safe_headers,
        "requestBodyOmitted": body_length > 0,
        "requestBodyLength": body_length,
    }


SENSITIVE_RESPONSE_HEADERS = {
    "authorization", "proxy-authenticate", "www-authenticate", "authentication-info",
    "proxy-authentication-info", "cookie", "set-cookie", "x-api-key", "api-key",
    "x-auth-token", "x-access-token",
}


def _safe_history_response(result: dict) -> dict:
    """Retain replay metadata and response summary, never response secrets or bodies."""
    safe = dict(result)
    safe_headers = []
    for item in result.get("headers", []):
        name = str(item.get("name", ""))
        lowered = name.lower()
        sensitive = (lowered in SENSITIVE_RESPONSE_HEADERS or "token" in lowered
                     or "secret" in lowered or "session" in lowered)
        safe_headers.append({"name": name, "value": "[REDACTED]" if sensitive else item.get("value", "")})
    safe["headers"] = safe_headers
    target = result.get("target", "")
    if isinstance(target, str) and target:
        parsed_target = urlsplit(target)
        safe["target"] = urlunsplit((parsed_target.scheme, parsed_target.netloc, parsed_target.path, "", ""))
        safe["targetQueryOmitted"] = bool(parsed_target.query)
    safe["responseBodyOmitted"] = bool(result.get("bodyBytes", 0))
    safe["responseBodyLength"] = result.get("bodyBytes", 0)
    safe["body"] = ""
    return safe


def execute_request(data: dict) -> dict:
    request = validate_request(data)
    started = time.monotonic()
    address = request["addresses"][0]
    sock = socket.create_connection((address, request["port"]), timeout=MAX_TIMEOUT)
    try:
        sock.settimeout(MAX_TIMEOUT)
        if request["scheme"] == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=request["host"])
        headers = dict(request["headers"])
        host_header = f'[{request["host"]}]' if ":" in request["host"] else request["host"]
        headers["Host"] = host_header if request["port"] in (80, 443) else f'{host_header}:{request["port"]}'
        headers["Connection"] = "close"
        if request["body"]:
            headers["Content-Length"] = str(len(request["body"]))
        lines = [f'{request["method"]} {request["target"]} HTTP/1.1']
        lines.extend(f"{key}: {value}" for key, value in headers.items())
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + request["body"])
        response = http.client.HTTPResponse(sock)
        response.begin()
        body = response.read(MAX_RESPONSE_BODY + 1)
        truncated = len(body) > MAX_RESPONSE_BODY
        body = body[:MAX_RESPONSE_BODY]
        result = {
            "id": uuid.uuid4().hex, "status": response.status, "reason": response.reason,
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": key, "value": value} for key, value in response.getheaders()],
            "body": body.decode("utf-8", errors="replace"), "bodyBytes": len(body),
            "truncated": truncated, "durationMs": round((time.monotonic() - started) * 1000),
            "target": request["url"], "method": request["method"], "resolvedAddress": address,
            "redirectFollowed": False, "authorizationReference": request["authorization_reference"],
            **_safe_history_request(request),
            "capturedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        with _HISTORY_LOCK:
            _HISTORY.appendleft(_safe_history_response(result))
        return {"status": "completed", **result}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def request_history(limit: int = 20) -> dict:
    if isinstance(limit, bool) or not isinstance(limit, int):
        limit = 20
    limit = max(1, min(limit, 25))
    with _HISTORY_LOCK:
        items = list(_HISTORY)[:limit]
    return {"items": items, "count": len(items), "storage": "process memory only; cleared when the companion stops"}
