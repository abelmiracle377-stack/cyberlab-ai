"""CyberLab-native, scope-bound HTTP/1.1 proxy with optional WebSocket inspection.

The listener is loopback-only and bound to one approved origin. HTTPS CONNECT
uses a CyberLab leaf certificate and independently verified upstream TLS.
Bodies and sensitive metadata are excluded from persistent history.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import select
import json
import re
import socket
import socketserver
import ssl
import threading
import time
import uuid
from collections import deque
from urllib.parse import urlsplit, urlunsplit

from proxy_certificates import ca_status, issue_host_certificate
from web_testing import _resolve_pinned
from websocket_frames import WebSocketFrameObserver
from websocket_interception import (WebSocketFrameDecisionQueue, WebSocketMessageAssembler,
                                     decode_frame, encode_frame, forward_message_frames)

LISTEN_HOST = "127.0.0.1"
DEFAULT_PORT = 8081
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADER_COUNT = 100
MAX_REQUEST_BODY = 64 * 1024
MAX_RESPONSE_BODY = 2 * 1024 * 1024
MAX_TIMEOUT = 12
MAX_CONCURRENT_CLIENTS = 16
MAX_PENDING_INTERCEPTS = 20
INTERCEPT_DECISION_TIMEOUT = 120
_INTERCEPTS = {}
_RESPONSE_INTERCEPTS = {}
_INTERCEPT_LOCK = threading.RLock()
_HISTORY = deque(maxlen=100)
_HISTORY_LOCK = threading.Lock()
_SENSITIVE = {"authorization", "proxy-authorization", "cookie", "set-cookie",
              "www-authenticate", "proxy-authenticate", "x-api-key", "api-key",
              "x-auth-token", "x-access-token", "referer", "location", "content-location", "refresh", "link"}
_WEBSOCKET_FRAME_HISTORY = deque(maxlen=500)
_WEBSOCKET_FRAME_LOCK = threading.Lock()
_WEBSOCKET_FRAME_QUEUE = WebSocketFrameDecisionQueue()


def pending_websocket_frames() -> dict:
    return _WEBSOCKET_FRAME_QUEUE.pending()


def decide_websocket_frame(frame_id: str, action: str, edited_payload: str | None = None) -> dict:
    return _WEBSOCKET_FRAME_QUEUE.decide(frame_id, action, edited_payload)


def websocket_frame_history(limit: int = 100) -> dict:
    if isinstance(limit, bool) or not isinstance(limit, int):
        limit = 100
    limit = max(1, min(limit, 500))
    with _WEBSOCKET_FRAME_LOCK:
        items = list(_WEBSOCKET_FRAME_HISTORY)[:limit]
    return {"items": items, "count": len(items),
            "storage": "metadata only; WebSocket payloads are never retained"}


def _record_websocket_frame(item: dict) -> None:
    safe = {key: item[key] for key in
            ("direction", "fin", "opcode", "opcodeName", "masked", "payloadLength",
             "messageId", "fragmentIndex", "messageComplete", "capturedAt")}
    with _WEBSOCKET_FRAME_LOCK:
        _WEBSOCKET_FRAME_HISTORY.appendleft(safe)


_HOP_BY_HOP = {"connection", "proxy-connection", "keep-alive", "te", "trailer",
               "transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization", "expect"}


def _origin(value: str) -> tuple[str, str, int]:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Enter one exact HTTP or HTTPS origin.")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Proxy scope must be an HTTP(S) origin without credentials.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Proxy scope must be an origin only; paths, queries and fragments are not accepted.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Proxy scope contains an invalid port.") from exc
    host = parsed.hostname.rstrip(".").lower()
    if not host or not 1 <= port <= 65535:
        raise ValueError("Proxy scope contains an invalid host or port.")
    return parsed.scheme.lower(), host, port


def _safe_headers(headers: list[tuple[str, str]]) -> list[dict]:
    output = []
    for name, value in headers:
        lowered = name.lower()
        secret = (lowered in _SENSITIVE or any(hint in lowered for hint in
                  ("token", "secret", "session", "authorization", "password", "credential")))
        output.append({"name": name, "value": "[REDACTED]" if secret else value[:512]})
    return output


def _redact_url_path(url: str) -> str:
    parsed = urlsplit(url)
    parts = []
    for segment in parsed.path.split("/"):
        lowered = segment.lower()
        if (any(word in lowered for word in ("token", "secret", "password", "passwd", "reset", "session", "auth", "key"))
                or re.fullmatch(r"eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", segment)
                or len(segment) >= 48 and re.fullmatch(r"[A-Za-z0-9_-]+", segment)):
            parts.append("[REDACTED]")
        else:
            parts.append(segment[:160])
    return urlunsplit((parsed.scheme, parsed.netloc, "/".join(parts), "", ""))


def pending_intercepts() -> dict:
    with _INTERCEPT_LOCK:
        items = [entry["public"] for entry in _INTERCEPTS.values()]
    return {"items": items, "count": len(items), "maxPending": MAX_PENDING_INTERCEPTS}


def _validated_intercept_edit(entry: dict, edits: dict) -> dict:
    if not isinstance(edits, dict):
        raise ValueError("Edited request must be an object.")
    method = edits.get("method", entry["method"])
    path = edits.get("path", entry["path"])
    default_headers = [{"name": name, "value": value} for name, value in entry["headers"]
                       if name.lower() not in _HOP_BY_HOP and name.lower() not in {"host", "content-length"}]
    headers = edits.get("headers", default_headers)
    if not entry["bodyEditable"]:
        if "body" in edits:
            raise ValueError("This binary request body cannot be changed in the text editor.")
        body = entry["body"]
    else:
        body_text = edits.get("body", entry["body"].decode("utf-8"))
        if not isinstance(body_text, str):
            raise ValueError("Edited request body must be text.")
        body = body_text.encode("utf-8")
    if not isinstance(method, str) or method.upper() not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ValueError("Edited HTTP method is not supported.")
    method = method.upper()
    if method in {"POST", "PUT", "PATCH", "DELETE"} and not entry["allowStateChangingMethods"]:
        raise ValueError("State-changing methods are disabled for this proxy session.")
    if not isinstance(path, str) or len(path) > 8192 or not path.startswith("/") or path.startswith("//"):
        raise ValueError("Edited path must remain an origin-form path on the approved host.")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment or "\\" in path or any(ord(ch) <= 32 or ord(ch) == 127 for ch in path):
        raise ValueError("Edited path cannot change origin or contain fragments, whitespace or control characters.")
    if not isinstance(headers, list) or len(headers) > MAX_HEADER_COUNT:
        raise ValueError("Edited headers must be a list of at most 100 name/value entries.")
    original_by_name = {}
    for name, value in entry["headers"]:
        original_by_name.setdefault(name.lower(), []).append(value)
    clean_headers = []
    for item in headers:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str):
            raise ValueError("Each edited header must contain string name and value fields.")
        name, value = item["name"], item["value"]
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", name):
            raise ValueError("Edited header name is invalid.")
        lowered = name.lower()
        if lowered in _HOP_BY_HOP or lowered in {"host", "content-length"}:
            raise ValueError("Host, Content-Length and hop-by-hop headers are managed by CyberLab.")
        if any(ord(ch) in (10, 13, 127) or ord(ch) < 32 and ch != "\t" for ch in value) or len(value) > 8192:
            raise ValueError("Edited header value contains invalid characters or exceeds the limit.")
        if value == "[REDACTED]":
            remaining = original_by_name.get(lowered, [])
            if remaining:
                value = remaining.pop(0)
        clean_headers.append((name, value))
    if len(body) > MAX_REQUEST_BODY:
        raise ValueError("Edited request body exceeds 64 KB.")
    return {"method": method, "path": path, "headers": clean_headers, "body": body}


def decide_intercept(intercept_id: str, action: str, edits: dict | None = None) -> dict:
    if not isinstance(intercept_id, str) or not re.fullmatch(r"[a-f0-9]{32}", intercept_id):
        raise ValueError("Interception request ID is invalid.")
    if not isinstance(action, str) or action not in {"forward", "forward_edited", "drop"}:
        raise ValueError("Interception decision must be forward or drop, or forward_edited.")
    with _INTERCEPT_LOCK:
        entry = _INTERCEPTS.get(intercept_id)
        if entry is None:
            raise ValueError("This request is no longer pending; it may have timed out or already been handled.")
        decision = {"action": action}
        if action == "forward_edited":
            decision["edited"] = _validated_intercept_edit(entry, edits)
        entry["decision"] = decision
        entry["event"].set()
    return {"id": intercept_id, "decision": action, "accepted": True}


def _await_intercept_decision(method: str, url: str, headers: list[tuple[str, str]], body: bytes,
                              path: str, allow_state_changing_methods: bool) -> dict:
    intercept_id = uuid.uuid4().hex
    event = threading.Event()
    try:
        body_text = body.decode("utf-8")
        body_editable = True
    except UnicodeDecodeError:
        body_text, body_editable = "", False
    public = {
        "id": intercept_id, "method": method.upper(), "url": _redact_url_path(url),
        "path": path, "headers": _safe_headers(headers), "bodyLength": len(body),
        "bodyOmitted": not body_editable, "body": body_text if body_editable else "",
        "bodyEditable": body_editable,
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "decisionTimeoutSeconds": INTERCEPT_DECISION_TIMEOUT,
    }
    entry = {"event": event, "decision": None, "public": public, "method": method.upper(),
             "path": path, "headers": headers, "body": body,
             "allowStateChangingMethods": allow_state_changing_methods, "bodyEditable": body_editable}
    with _INTERCEPT_LOCK:
        if len(_INTERCEPTS) >= MAX_PENDING_INTERCEPTS:
            raise ValueError("The interception queue is full; forward or drop pending requests first.")
        _INTERCEPTS[intercept_id] = entry
    try:
        if not event.wait(INTERCEPT_DECISION_TIMEOUT):
            return {"action": "timeout"}
        return entry["decision"] or {"action": "drop"}
    finally:
        with _INTERCEPT_LOCK:
            _INTERCEPTS.pop(intercept_id, None)


def _drop_all_pending_intercepts() -> None:
    with _INTERCEPT_LOCK:
        for entry in list(_INTERCEPTS.values()) + list(_RESPONSE_INTERCEPTS.values()):
            entry["decision"] = {"action": "drop"}
            entry["event"].set()

def pending_response_intercepts() -> dict:
    with _INTERCEPT_LOCK:
        items = [entry["public"] for entry in _RESPONSE_INTERCEPTS.values()]
    return {"items": items, "count": len(items), "maxPending": MAX_PENDING_INTERCEPTS}


def _validated_response_edit(entry: dict, edits: dict) -> dict:
    if not isinstance(edits, dict):
        raise ValueError("Edited response must be a JSON object.")
    status = edits.get("status", entry["status"])
    if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status <= 599:
        raise ValueError("Edited response status must be an integer from 200 to 599.")
    reason = edits.get("reason", entry["reason"])
    if not isinstance(reason, str) or len(reason) > 120 or any(ord(ch) < 32 or ord(ch) == 127 for ch in reason):
        raise ValueError("Edited response reason contains invalid characters or exceeds 120 characters.")
    raw_headers = edits.get("headers")
    if raw_headers is None:
        headers = list(entry["headers"])
    else:
        if not isinstance(raw_headers, list) or len(raw_headers) > MAX_HEADER_COUNT:
            raise ValueError("Edited response headers must be a list of at most 100 name/value entries.")
        original_by_name = {}
        for name, value in entry["headers"]:
            original_by_name.setdefault(name.lower(), []).append(value)
        headers = []
        for item in raw_headers:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str):
                raise ValueError("Each edited response header must contain string name and value fields.")
            name, value = item["name"], item["value"]
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", name):
                raise ValueError("Edited response header name is invalid.")
            lowered = name.lower()
            if lowered in _HOP_BY_HOP or lowered in {"content-length", "host"}:
                raise ValueError("Content-Length and hop-by-hop response headers are managed by CyberLab.")
            if any(ord(ch) in (10, 13, 127) or ord(ch) < 32 and ch != "\t" for ch in value) or len(value) > 8192:
                raise ValueError("Edited response header value contains invalid characters or exceeds the limit.")
            remaining = original_by_name.get(lowered, [])
            if remaining and (value == "[REDACTED]" or value == remaining[0][:512]):
                value = remaining.pop(0)
            headers.append((name, value))
    body = entry["body"]
    if "body" in edits:
        if not entry["bodyEditable"]:
            raise ValueError("This response body is binary, non-UTF-8, or too large for safe text editing.")
        if not isinstance(edits["body"], str):
            raise ValueError("Edited response body must be UTF-8 text.")
        body = edits["body"].encode("utf-8")
        if len(body) > MAX_RESPONSE_BODY:
            raise ValueError("Edited response body exceeds the 2 MB response limit.")
    if "body" in edits:
        headers = [(name, value) for name, value in headers
                   if name.lower() not in {"content-encoding", "content-md5", "digest", "etag", "content-range", "accept-ranges"}]
    if status in {204, 205, 304}:
        body = b""
    return {"status": status, "reason": reason, "headers": headers, "body": body}


def decide_response_intercept(intercept_id: str, action: str, edits: dict | None = None) -> dict:
    if not isinstance(intercept_id, str) or not re.fullmatch(r"[a-f0-9]{32}", intercept_id):
        raise ValueError("Response interception request ID is invalid.")
    if not isinstance(action, str) or action not in {"forward", "forward_edited", "drop"}:
        raise ValueError("Response interception decision must be forward, forward_edited or drop.")
    with _INTERCEPT_LOCK:
        entry = _RESPONSE_INTERCEPTS.get(intercept_id)
        if entry is None:
            raise ValueError("This response is no longer pending; it may have timed out or already been handled.")
        decision = {"action": action}
        if action == "forward_edited":
            decision["edited"] = _validated_response_edit(entry, edits)
        entry["decision"] = decision
        entry["event"].set()
    return {"id": intercept_id, "decision": action, "accepted": True}


def _await_response_decision(method: str, url: str, status: int, reason: str,
                             headers: list[tuple[str, str]], body: bytes) -> dict:
    intercept_id = uuid.uuid4().hex
    event = threading.Event()
    content_type = next((value.lower() for name, value in headers if name.lower() == "content-type"), "")
    textual = any(kind in content_type for kind in ("text/", "json", "xml", "javascript", "x-www-form-urlencoded"))
    try:
        preview = body[:16384].decode("utf-8") if textual else ""
        body_visible = textual
    except UnicodeDecodeError:
        preview, body_visible = "", False
    public = {
        "id": intercept_id, "method": method.upper(), "url": _redact_url_path(url),
        "status": status, "reason": str(reason)[:120],
        "headers": _safe_headers([(name, value) for name, value in headers
                                  if name.lower() not in _HOP_BY_HOP and name.lower() not in {"host", "content-length"}]),
        "bodyLength": len(body),
        "body": preview, "bodyVisible": body_visible,
        "bodyTruncated": body_visible and len(body) > 16384,
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "decisionTimeoutSeconds": INTERCEPT_DECISION_TIMEOUT,
    }
    body_editable = body_visible and len(body) <= 16384 and method.upper() != "HEAD"
    public["bodyEditable"] = body_editable
    entry = {"event": event, "decision": None, "public": public,
             "status": status, "reason": str(reason or ""),
             "headers": list(headers), "body": body, "bodyEditable": body_editable}
    with _INTERCEPT_LOCK:
        if len(_RESPONSE_INTERCEPTS) >= MAX_PENDING_INTERCEPTS:
            raise ValueError("The response interception queue is full; forward or drop pending responses first.")
        _RESPONSE_INTERCEPTS[intercept_id] = entry
    try:
        if not event.wait(INTERCEPT_DECISION_TIMEOUT):
            return {"action": "timeout"}
        return entry["decision"] or {"action": "drop"}
    finally:
        with _INTERCEPT_LOCK:
            _RESPONSE_INTERCEPTS.pop(intercept_id, None)



def _history_entry(method: str, url: str, status: int, request_headers: list[tuple[str, str]],
                   response_headers: list[tuple[str, str]], request_size: int,
                   response_size: int, duration_ms: int) -> None:
    parsed = urlsplit(url)
    safe_url = _redact_url_path(url)
    item = {
        "id": str(time.time_ns()), "method": method, "url": safe_url,
        "queryOmitted": bool(parsed.query), "status": status,
        "requestHeaders": _safe_headers(request_headers),
        "responseHeaders": _safe_headers(response_headers),
        "requestBodyOmitted": request_size > 0, "requestBodyLength": request_size,
        "responseBodyOmitted": response_size > 0, "responseBodyLength": response_size,
        "durationMs": duration_ms, "capturedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with _HISTORY_LOCK:
        _HISTORY.appendleft(item)


def proxy_history(limit: int = 50) -> dict:
    if isinstance(limit, bool) or not isinstance(limit, int):
        limit = 50
    limit = max(1, min(limit, 100))
    with _HISTORY_LOCK:
        items = list(_HISTORY)[:limit]
    return {"items": items, "count": len(items), "storage": "process memory only; bodies and URL queries omitted"}


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str):
        super().__init__(host, port, timeout=MAX_TIMEOUT)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str):
        super().__init__(host, port, timeout=MAX_TIMEOUT, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, server_address, request_handler):
        self._client_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CLIENTS)
        super().__init__(server_address, request_handler)

    def process_request(self, request, client_address):
        if not self._client_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._client_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._client_slots.release()


class _ProxyHandler(socketserver.StreamRequestHandler):
    def finish(self):
        try:
            super().finish()
        finally:
            try:
                self.connection.close()
            except OSError:
                pass

    def handle(self):
        self.connection.settimeout(MAX_TIMEOUT)
        try:
            line = self.rfile.readline(8193)
            if not line:
                return
            if len(line) > 8192 or not line.endswith(b"\r\n"):
                self._error(400, "Invalid or oversized request line")
                return
            parts = line.decode("iso-8859-1").strip().split(" ")
            if len(parts) != 3:
                self._error(400, "Malformed request line")
                return
            method, target, version = parts
            if version not in {"HTTP/1.0", "HTTP/1.1"}:
                self._error(505, "HTTP version not supported")
                return
            if method.upper() == "CONNECT":
                self._handle_connect(target)
                return
            self._serve_requests(line)
        except socket.timeout:
            return
        except ValueError as exc:
            try:
                self._error(400, str(exc)[:250])
            except OSError:
                pass
        except (OSError, RuntimeError, ssl.SSLError, http.client.HTTPException):
            try:
                self._error(502, "Upstream or TLS handling failed")
            except OSError:
                pass

    def _serve_requests(self, first_line: bytes | None = None, tunneled_host: str | None = None,
                        tunneled_port: int | None = None) -> None:
        # Requests are handled strictly in wire order. This safely supports
        # sequential keep-alive and pipelined clients without concurrent writes.
        for request_number in range(MAX_REQUESTS_PER_CLIENT):
            line = first_line if first_line is not None else self.rfile.readline(8193)
            first_line = None
            if not line:
                return
            if len(line) > 8192 or not line.endswith(b"\r\n"):
                self._error(400, "Invalid or oversized request line")
                return
            parts = line.decode("iso-8859-1").strip().split(" ")
            if len(parts) != 3:
                self._error(400, "Malformed request line")
                return
            method, target, version = parts
            if version not in {"HTTP/1.0", "HTTP/1.1"}:
                self._error(505, "HTTP version not supported")
                return
            if tunneled_host is not None:
                parsed = urlsplit(target)
                if (parsed.scheme or parsed.netloc or parsed.fragment or not target.startswith("/")
                        or target.startswith("//") or "\\" in target
                        or any(ord(char) <= 32 or ord(char) == 127 for char in target)):
                    self._error(400, "HTTPS request target must be a valid origin-form path")
                    return
                host, port, scheme, path = tunneled_host, tunneled_port, "https", target
            else:
                parsed = urlsplit(target)
                if (parsed.scheme != "http" or not parsed.hostname or parsed.username
                        or parsed.password or parsed.fragment):
                    self._error(400, "Use an absolute HTTP URL or HTTPS CONNECT")
                    return
                try:
                    port = parsed.port or 80
                except ValueError:
                    self._error(400, "Request target contains an invalid port")
                    return
                host, scheme = parsed.hostname, parsed.scheme
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                if any(ord(char) <= 32 or ord(char) == 127 for char in path):
                    self._error(400, "Request target contains unescaped whitespace or control characters")
                    return
            keep_alive = self._process_request(method, scheme, host, port, path, version)
            if not keep_alive:
                return
        self._error(429, "Maximum requests per proxy connection reached")


    def _read_headers(self) -> list[tuple[str, str]]:
        headers = []
        total = 0
        while True:
            line = self.rfile.readline(8193)
            if not line or len(line) > 8192:
                raise ValueError("Invalid or oversized request headers.")
            total += len(line)
            if total > MAX_HEADER_BYTES:
                raise ValueError("Request headers exceed the size limit.")
            if line in (b"\r\n", b"\n"):
                break
            if not line.endswith(b"\r\n") or line[:1] in (b" ", b"\t") or b":" not in line:
                raise ValueError("Malformed HTTP header.")
            name, value = line[:-2].split(b":", 1)
            key = name.decode("ascii")
            val = value.decode("iso-8859-1").strip()
            if not key or any(ord(ch) < 33 or ord(ch) > 126 for ch in key):
                raise ValueError("Invalid HTTP header name.")
            if any(ord(ch) < 32 and ch != "\t" or ord(ch) == 127 for ch in val):
                raise ValueError("Invalid HTTP header value.")
            headers.append((key, val))
            if len(headers) > MAX_HEADER_COUNT:
                raise ValueError("Too many request headers.")
        return headers

    def _handle_connect(self, authority: str) -> None:
        host, port = _parse_authority(authority, 443)
        origin = self.server.controller.scope
        if origin != ("https", host, port):
            self._error(403, "CONNECT host is outside the approved proxy scope")
            return
        self._read_headers()
        cert = issue_host_certificate(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert["certificate"], cert["privateKey"])
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: CyberLab AI\r\n\r\n")
        self.wfile.flush()
        self.rfile.close()
        self.wfile.close()
        tls = context.wrap_socket(self.connection, server_side=True)
        self.connection = tls
        self.rfile = tls.makefile("rb")
        self.wfile = tls.makefile("wb")
        self._serve_requests(tunneled_host=host, tunneled_port=port)


    def _read_upstream_response_head(self, upstream: socket.socket) -> tuple[int, str, list[tuple[str, str]]]:
        raw = bytearray()
        while not raw.endswith(b"\r\n\r\n"):
            chunk = upstream.recv(1)
            if not chunk:
                raise OSError("Upstream closed during WebSocket handshake.")
            raw.extend(chunk)
            if len(raw) > MAX_HEADER_BYTES:
                raise ValueError("Upstream WebSocket handshake headers exceed the size limit.")
        lines = bytes(raw[:-4]).split(b"\r\n")
        if not lines:
            raise ValueError("Upstream WebSocket handshake is malformed.")
        try:
            status_parts = lines[0].decode("iso-8859-1").split(" ", 2)
            if len(status_parts) < 2 or status_parts[0] not in {"HTTP/1.0", "HTTP/1.1"}:
                raise ValueError
            status = int(status_parts[1])
            reason = status_parts[2] if len(status_parts) == 3 else ""
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Upstream WebSocket status line is malformed.") from exc
        headers = []
        for line in lines[1:]:
            if not line or line[:1] in (b" ", b"\t") or b":" not in line:
                raise ValueError("Upstream WebSocket response contains a malformed header.")
            name, value = line.split(b":", 1)
            try:
                key = name.decode("ascii")
                val = value.decode("iso-8859-1").strip()
            except UnicodeDecodeError as exc:
                raise ValueError("Upstream WebSocket response contains an invalid header.") from exc
            if not re.fullmatch(r"[!#$%&'*+.^_|~0-9A-Za-z-]{1,128}", key):
                raise ValueError("Upstream WebSocket response contains an invalid header name.")
            if any(ord(ch) < 32 and ch != "\t" or ord(ch) == 127 for ch in val):
                raise ValueError("Upstream WebSocket response contains an invalid header value.")
            headers.append((key, val))
            if len(headers) > MAX_HEADER_COUNT:
                raise ValueError("Upstream WebSocket response contains too many headers.")
        return status, reason, headers

    @staticmethod
    def _recv_websocket_frame(source: socket.socket, direction: str) -> tuple[bytes, dict, bytes]:
        def exact(count: int) -> bytes:
            chunks = bytearray()
            while len(chunks) < count:
                part = source.recv(count - len(chunks))
                if not part:
                    raise EOFError("WebSocket peer closed during a frame.")
                chunks.extend(part)
            return bytes(chunks)

        head = exact(2)
        length_code = head[1] & 0x7F
        extra = b""
        if length_code == 126:
            extra = exact(2)
            length = int.from_bytes(extra, "big")
            if length < 126:
                raise ValueError("Non-canonical WebSocket frame length.")
        elif length_code == 127:
            extra = exact(8)
            if extra[0] & 0x80:
                raise ValueError("Invalid WebSocket frame length.")
            length = int.from_bytes(extra, "big")
            if length < 65536:
                raise ValueError("Non-canonical WebSocket frame length.")
        else:
            length = length_code
        masked = bool(head[1] & 0x80)
        mask = exact(4) if masked else b""
        if length > 64 * 1024:
            raise ValueError("Frame exceeds the 64 KB manual-interception limit.")
        payload = exact(length)
        raw = head + extra + mask + payload
        metadata, decoded = decode_frame(raw, direction)
        return raw, metadata, decoded

    def _relay_websocket(self, upstream: socket.socket) -> None:
        client = self.connection
        client.settimeout(None)
        upstream.settimeout(None)
        open_read = {client, upstream}
        observers = {
            "client-to-server": WebSocketFrameObserver("client-to-server", _record_websocket_frame),
            "server-to-client": WebSocketFrameObserver("server-to-client", _record_websocket_frame),
        }
        assemblers = {
            "client-to-server": WebSocketMessageAssembler(),
            "server-to-client": WebSocketMessageAssembler(),
        }
        controller = self.server.controller
        while open_read and not controller._stop_event.is_set():
            readable, _, _ = select.select(list(open_read), [], [], 1.0)
            if controller.intercept_websocket_frames and any(
                    assembler.expired for assembler in assemblers.values()):
                # An incomplete fragmented message must not pin relay memory indefinitely.
                break
            for candidate in open_read:
                if isinstance(candidate, ssl.SSLSocket) and candidate.pending() > 0 and candidate not in readable:
                    readable.append(candidate)
            for source in readable:
                destination = upstream if source is client else client
                direction = "client-to-server" if source is client else "server-to-client"
                try:
                    if controller.intercept_websocket_frames:
                        raw, metadata, payload = self._recv_websocket_frame(source, direction)
                        observers[direction].feed(raw)
                        if observers[direction].disabled:
                            raise ValueError("Invalid WebSocket frame sequence.")
                        assembler = assemblers[direction]
                        state, messages = assembler.feed(metadata, payload)
                        if state == "pending":
                            continue
                        if state == "control" and assembler.pending:
                            # Keep ping/pong traffic responsive during message assembly.
                            destination.sendall(encode_frame(metadata, payload, direction))
                            continue
                        message = messages[0]
                        decision = _WEBSOCKET_FRAME_QUEUE.submit(
                            direction, message["metadata"], message["payload"])
                        if decision["action"] == "timeout":
                            raise TimeoutError("WebSocket message decision timed out; tunnel closed safely.")
                        if decision["action"] == "drop":
                            if message["metadata"]["opcode"] == 0x8:
                                raise ConnectionAbortedError("Dropping a WebSocket close frame closes the tunnel.")
                            continue
                        edited = "payload" in decision
                        forwarded_payload = decision.get("payload", message["payload"])
                        for frame in forward_message_frames(message, forwarded_payload, direction, edited=edited):
                            destination.sendall(frame)
                    else:
                        data = source.recv(65536)
                        if data:
                            observers[direction].feed(data)
                            destination.sendall(data)
                        else:
                            open_read.discard(source)
                            try:
                                destination.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                except (OSError, ssl.SSLError, ValueError, EOFError, TimeoutError):
                    open_read.discard(source)
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    try:
                        source.shutdown(socket.SHUT_RD)
                    except OSError:
                        pass

    def _forward_websocket(self, method: str, scheme: str, host: str, port: int,
                           path: str, headers: list[tuple[str, str]], address: str,
                           url: str) -> None:
        lowered = {}
        for name, value in headers:
            lowered.setdefault(name.lower(), []).append(value)
        connection_tokens = {token.strip().lower() for value in lowered.get("connection", [])
                             for token in value.split(",") if token.strip()}
        if method.upper() != "GET" or "upgrade" not in connection_tokens:
            self._error(400, "WebSocket upgrade requires GET and Connection: Upgrade")
            return
        upgrades = [part.strip().lower() for value in lowered.get("upgrade", []) for part in value.split(",")]
        keys = lowered.get("sec-websocket-key", [])
        versions = lowered.get("sec-websocket-version", [])
        if upgrades != ["websocket"] or len(keys) != 1 or versions != ["13"]:
            self._error(400, "Only RFC 6455 WebSocket version 13 handshakes are supported")
            return
        try:
            decoded_key = base64.b64decode(keys[0], validate=True)
        except (ValueError, TypeError):
            decoded_key = b""
        if len(decoded_key) != 16:
            self._error(400, "WebSocket key is invalid")
            return
        controller = self.server.controller
        if controller.intercept_requests or controller.intercept_responses:
            self._error(501, "WebSocket tunnelling is unavailable while manual HTTP interception is enabled")
            return
        started = time.monotonic()
        connection = (_PinnedHTTPSConnection(host, port, address) if scheme == "https"
                      else _PinnedHTTPConnection(host, port, address))
        try:
            connection.connect()
            upstream = connection.sock
            host_header = f"[{host}]" if ":" in host else host
            if port not in (80, 443):
                host_header += f":{port}"
            request_lines = [f"GET {path} HTTP/1.1", f"Host: {host_header}",
                             "Connection: Upgrade", "Upgrade: websocket"]
            for name, value in headers:
                lowered_name = name.lower()
                if (lowered_name in _HOP_BY_HOP or lowered_name in connection_tokens
                        or lowered_name in {"host", "content-length"}):
                    continue
                request_lines.append(f"{name}: {value}")
            upstream.sendall(("\r\n".join(request_lines) + "\r\n\r\n").encode("iso-8859-1"))
            status, reason, response_headers = self._read_upstream_response_head(upstream)
            if status != 101:
                self._error(502, f"Origin declined WebSocket upgrade ({status})")
                return
            response_lowered = {}
            for name, value in response_headers:
                response_lowered.setdefault(name.lower(), []).append(value)
            response_connection_tokens = {token.strip().lower() for value in response_lowered.get("connection", [])
                                           for token in value.split(",") if token.strip()}
            response_upgrade = [part.strip().lower() for value in response_lowered.get("upgrade", [])
                                for part in value.split(",")]
            expected_accept = base64.b64encode(hashlib.sha1(
                (keys[0] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()).decode("ascii")
            if ("upgrade" not in response_connection_tokens or response_upgrade != ["websocket"]
                    or response_lowered.get("sec-websocket-accept") != [expected_accept]):
                self._error(502, "Origin returned an invalid WebSocket upgrade handshake")
                return
            safe_headers = [(name, value) for name, value in response_headers
                            if name.lower() not in _HOP_BY_HOP
                            and name.lower() not in response_connection_tokens
                            and name.lower() not in {"content-length", "transfer-encoding"}
                            and not any(ord(ch) in (10, 13) or (ord(ch) < 32 and ch != "\t") for ch in value)]
            self.wfile.write(f"HTTP/1.1 101 {reason or 'Switching Protocols'}\r\n".encode("iso-8859-1", errors="replace"))
            for name, value in safe_headers:
                self.wfile.write(f"{name}: {value}\r\n".encode("iso-8859-1", errors="replace"))
            self.wfile.write(b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            self.wfile.flush()
            _history_entry(method.upper(), url, 101, headers, response_headers, 0, 0,
                           round((time.monotonic() - started) * 1000))
            self._relay_websocket(upstream)
        finally:
            connection.close()

    def _process_request(self, method: str, scheme: str, host: str, port: int,
                         path: str, version: str, tunneled: bool = False) -> bool:
        controller = self.server.controller
        if controller.scope != (scheme, host.rstrip(".").lower(), port):
            self._error(403, "Request is outside the approved proxy scope")
            return
        if method.upper() not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            self._error(405, "HTTP method is not supported")
            return
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and not controller.allow_state_changing_methods:
            self._error(403, "State-changing methods are disabled for this proxy session")
            return
        headers = self._read_headers()
        lowered = {}
        for name, value in headers:
            lowered.setdefault(name.lower(), []).append(value)
        if "transfer-encoding" in lowered or "expect" in lowered:
            self._error(501, "Chunked request bodies and Expect are not supported")
            return
        connection_tokens = {token.strip().lower() for value in lowered.get("connection", [])
                             for token in value.split(",") if token.strip()}
        host_values = lowered.get("host", [])
        if version == "HTTP/1.1" and len(host_values) != 1:
            self._error(400, "HTTP/1.1 requires exactly one Host header")
            return False
        if host_values:
            try:
                header_host, header_port = _parse_authority(
                    host_values[0], 443 if scheme == "https" else 80)
            except ValueError:
                self._error(400, "Invalid Host header")
                return False
            if (header_host.rstrip(".").lower(), header_port) != (host.rstrip(".").lower(), port):
                self._error(421, "Host header does not match the requested proxy origin")
                return False
        client_keep_alive = ("close" not in connection_tokens and
                             (version == "HTTP/1.1" or "keep-alive" in connection_tokens))
        lengths = lowered.get("content-length", ["0"])
        if len(lengths) != 1 or not lengths[0].isdigit():
            self._error(400, "Invalid Content-Length")
            return
        body_size = int(lengths[0])
        if body_size > MAX_REQUEST_BODY:
            self._error(413, "Request body exceeds 64 KB")
            return
        body = self.rfile.read(body_size) if body_size else b""
        if len(body) != body_size:
            self._error(400, "Incomplete request body")
            return
        if "upgrade" in lowered or "upgrade" in connection_tokens:
            if body_size:
                self._error(400, "WebSocket upgrade requests cannot contain a request body")
                return
            addresses = _resolve_pinned(host, port, controller.local_lab_mode)
            url = scheme + "://" + (f"[{host}]" if ":" in host else host) + (f":{port}" if port not in (80, 443) else "") + path
            self._forward_websocket(method, scheme, host, port, path, headers, addresses[0], url)
            return
        addresses = _resolve_pinned(host, port, controller.local_lab_mode)
        address = addresses[0]
        url = scheme + "://" + (f"[{host}]" if ":" in host else host) + (f":{port}" if port not in (80, 443) else "") + path
        if controller.intercept_requests:
            try:
                decision = _await_intercept_decision(method, url, headers, body, path,
                                                     controller.allow_state_changing_methods)
            except ValueError as exc:
                self._error(503, str(exc))
                return
            action = decision.get("action")
            if action == "timeout":
                self._error(504, "Operator did not approve this request in time")
                return
            if action == "drop":
                self._error(403, "Request dropped by the CyberLab operator")
                return
            if action == "forward_edited":
                edited = decision["edited"]
                method, path, headers, body = edited["method"], edited["path"], edited["headers"], edited["body"]
                body_size = len(body)
                # Preserve Connection-nominated hop-by-hop fields from the original
                # client request even when the operator edits the request.
                url = scheme + "://" + (f"[{host}]" if ":" in host else host) + (f":{port}" if port not in (80, 443) else "") + path
        started = time.monotonic()
        connection = (_PinnedHTTPSConnection(host, port, address) if scheme == "https"
                      else _PinnedHTTPConnection(host, port, address))
        try:
            clean = [(name, value) for name, value in headers
                     if name.lower() not in _HOP_BY_HOP and name.lower() not in connection_tokens
                     and name.lower() not in {"host", "content-length"}]
            host_header = f"[{host}]" if ":" in host else host
            if port not in (80, 443):
                host_header += f":{port}"
            clean.append(("Host", host_header))
            clean.append(("Connection", "close"))
            if body:
                clean.append(("Content-Length", str(len(body))))
            connection.putrequest(method.upper(), path, skip_host=True, skip_accept_encoding=True)
            for name, value in clean:
                connection.putheader(name, value)
            connection.endheaders(body if body else None)
            response = connection.getresponse()
            response_body = response.read(MAX_RESPONSE_BODY + 1) if method.upper() != "HEAD" else b""
            if len(response_body) > MAX_RESPONSE_BODY:
                self._error(502, "Upstream response exceeds the 2 MB inspection limit")
                return
            response_headers = response.getheaders()
            response_connection_tokens = {token.strip().lower() for name, value in response_headers
                                          if name.lower() == "connection"
                                          for token in value.split(",") if token.strip()}
            if controller.intercept_responses:
                try:
                    decision = _await_response_decision(method, url, response.status,
                                                        response.reason or "", response_headers, response_body)
                except ValueError as exc:
                    self._error(503, str(exc))
                    return
                if decision.get("action") == "timeout":
                    self._error(504, "Operator did not approve this response in time")
                    return
                if decision.get("action") == "drop":
                    self._error(502, "Response dropped by the CyberLab operator")
                    return
                if decision.get("action") == "forward_edited":
                    edited_response = decision["edited"]
                    response.status = edited_response["status"]
                    response.reason = edited_response["reason"]
                    response_headers = edited_response["headers"]
                    response_body = edited_response["body"]
            response_connection_tokens.update(token.strip().lower() for name, value in response_headers
                                               if name.lower() == "connection"
                                               for token in value.split(",") if token.strip())
            safe_forward = [(name, value) for name, value in response_headers
                            if name.lower() not in _HOP_BY_HOP and name.lower() not in response_connection_tokens and name.lower() != "content-length"
                            and not any(ord(char) in (10, 13) or (ord(char) < 32 and char != "\t") for char in value)]
            reason = str(response.reason).replace(chr(10), "").replace(chr(13), "")
            self.wfile.write(f"HTTP/1.1 {response.status} {reason}\r\n".encode("iso-8859-1", errors="replace"))
            for name, value in safe_forward:
                self.wfile.write(f"{name}: {value}\r\n".encode("iso-8859-1", errors="replace"))
            upstream_length = response.getheader("Content-Length")
            outgoing_length = (int(upstream_length) if method.upper() == "HEAD" and upstream_length and upstream_length.isdigit()
                               else len(response_body))
            reusable = client_keep_alive and response.status not in {101, 204, 304}
            if response.status in {204, 205, 304}:
                self.wfile.write((b"Connection: keep-alive\r\nKeep-Alive: timeout=12, max=50\r\n\r\n"
                                  if reusable else b"Connection: close\r\n\r\n"))
            else:
                connection_header = ("Connection: keep-alive\r\nKeep-Alive: timeout=12, max=50\r\n"
                                     if reusable else "Connection: close\r\n")
                self.wfile.write(f"Content-Length: {outgoing_length}\r\n{connection_header}\r\n".encode("ascii"))
            self.wfile.write(response_body)
            self.wfile.flush()
            _history_entry(method.upper(), url, response.status, headers, response_headers,
                           body_size, len(response_body), round((time.monotonic() - started) * 1000))
            return reusable
        finally:
            connection.close()

    def _error(self, status: int, message: str) -> None:
        body = message.encode("utf-8", errors="replace")
        self.wfile.write(f"HTTP/1.1 {status} Error\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii"))
        self.wfile.write(body)
        self.wfile.flush()


def _parse_authority(authority: str, default_port: int) -> tuple[str, int]:
    if not isinstance(authority, str) or len(authority) > 300 or any(ch in authority for ch in "/\\@?#"):
        raise ValueError("Invalid CONNECT authority.")
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            raise ValueError("Invalid IPv6 CONNECT authority.")
        host = authority[1:closing]
        suffix = authority[closing + 1:]
        if suffix and not suffix.startswith(":"):
            raise ValueError("Invalid CONNECT authority.")
        port_text = suffix[1:] if suffix else str(default_port)
    else:
        host, separator, port_text = authority.partition(":")
        if not separator:
            port_text = str(default_port)
    address = ipaddress.ip_address(host) if ":" in host else None
    if address is not None:
        host = address.compressed
    else:
        host = host.rstrip(".").lower()
        if not host or len(host) > 253 or any(not part or len(part) > 63 for part in host.split(".")):
            raise ValueError("Invalid CONNECT hostname.")
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ValueError("Invalid CONNECT port.")
    return host, int(port_text)


class NativeInterceptProxy:
    def __init__(self):
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._server = None
        self._thread = None
        self.scope = None
        self.local_lab_mode = False
        self.authorization_reference = ""
        self.allow_state_changing_methods = False
        self.intercept_requests = False
        self.intercept_responses = False
        self.intercept_websocket_frames = False

    def start(self, data: dict) -> dict:
        if not isinstance(data, dict):
            raise ValueError("Proxy start request must be an object.")
        target = data.get("origin")
        confirmation = data.get("confirmationOrigin")
        if not isinstance(target, str) or target != confirmation:
            raise ValueError("Retype the exact approved origin before starting the proxy.")
        scope = _origin(target)
        if data.get("authorizationConfirmed") is not True or data.get("confirmStart") is not True:
            raise ValueError("Confirm written authorisation and explicitly approve starting the interception proxy.")
        reference = data.get("authorizationReference")
        if not isinstance(reference, str) or not reference.strip() or len(reference) > 160:
            raise ValueError("An engagement or written-authorisation reference is required.")
        local_lab = data.get("localLabMode") is True
        if local_lab and scope[1] not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Local-lab mode accepts localhost or loopback IP addresses only.")
        _resolve_pinned(scope[1], scope[2], local_lab)
        allow_mutating = data.get("allowStateChangingMethods") is True
        if allow_mutating and data.get("confirmStateChangingMethods") is not True:
            raise ValueError("Separately approve forwarding POST, PUT, PATCH and DELETE requests.")
        pause_requests = data.get("interceptRequests") is True
        if pause_requests and data.get("confirmInterceptRequests") is not True:
            raise ValueError("Separately approve pausing browser requests for manual forward or drop decisions.")
        pause_responses = data.get("interceptResponses") is True
        if pause_responses and data.get("confirmInterceptResponses") is not True:
            raise ValueError("Separately approve pausing server responses for manual inspection and forward or drop decisions.")
        pause_websocket_frames = data.get("interceptWebSocketFrames") is True
        if pause_websocket_frames and data.get("confirmInterceptWebSocketFrames") is not True:
            raise ValueError("Separately approve pausing WebSocket frames for manual inspection and forward, edit or drop decisions.")
        if pause_websocket_frames and (pause_requests or pause_responses):
            raise ValueError("WebSocket frame interception must be enabled separately from HTTP request/response interception.")
        port = data.get("listenPort", DEFAULT_PORT)
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError("Proxy listen port must be between 1024 and 65535.")
        with self._lock:
            if self._server is not None:
                raise ValueError("The native interception proxy is already running.")
            self._stop_event.clear()
            if scope[0] == "https" and not ca_status()["ready"]:
                raise ValueError("Create the local inspection CA before starting HTTPS interception.")
            server = _ProxyServer((LISTEN_HOST, port), _ProxyHandler)
            server.controller = self
            self.scope = scope
            self.local_lab_mode = local_lab
            self.authorization_reference = reference.strip()
            self.allow_state_changing_methods = allow_mutating
            self.intercept_requests = pause_requests
            self.intercept_responses = pause_responses
            self.intercept_websocket_frames = pause_websocket_frames
            self._server = server
            self._thread = threading.Thread(target=server.serve_forever, name="cyberlab-intercept-proxy", daemon=True)
            self._thread.start()
        return self.status()

    def stop(self) -> dict:
        with self._lock:
            server, thread = self._server, self._thread
            self._server = None
            self._thread = None
            self.scope = None
            self.authorization_reference = ""
            self.local_lab_mode = False
            self.allow_state_changing_methods = False
            self.intercept_requests = False
            self.intercept_responses = False
            self.intercept_websocket_frames = False
            self._stop_event.set()
        _drop_all_pending_intercepts()
        _WEBSOCKET_FRAME_QUEUE.drop_all()
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)
        return self.status()

    def status(self) -> dict:
        with self._lock:
            active = self._server is not None
            scope = self.scope
            return {
                "active": active, "listenHost": LISTEN_HOST if active else None,
                "listenPort": self._server.server_address[1] if active else None,
                "scope": (scope[0] + "://" + (f"[{scope[1]}]" if ":" in scope[1] else scope[1])
                          + (f":{scope[2]}" if scope[2] not in (80, 443) else "")) if scope else None,
                "authorizationReference": self.authorization_reference if active else None,
                "allowStateChangingMethods": self.allow_state_changing_methods if active else False,
                "interceptRequests": self.intercept_requests if active else False,
                "interceptResponses": self.intercept_responses if active else False,
                "interceptWebSocketFrames": self.intercept_websocket_frames if active else False,
                "mode": "HTTP/1.1 request/response inspection and WebSocket tunnelling; HTTPS CONNECT TLS termination" if active else "stopped",
                "limitations": ["one approved origin", "up to 50 sequential HTTP/1.1 requests per client connection", "no HTTP/2",
                                "WebSocket manual frame inspection is optional and limited to 64 KB frames", "WebSocket frame interception is separate from HTTP interception", "no chunked client request bodies", "no client certificates", "manual request and response interception queues are each bounded to 20 pending items"],
                "historyCount": len(_HISTORY),
            }


PROXY = NativeInterceptProxy()
