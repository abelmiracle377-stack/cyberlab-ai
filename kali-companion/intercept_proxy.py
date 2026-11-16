"""CyberLab-native, scope-bound HTTP/1.1 interception proxy.

The listener is loopback-only. One exact origin is approved when starting it.
HTTPS CONNECT is terminated with a CyberLab-managed leaf certificate and a
separately verified upstream TLS connection. Request/response bodies and
sensitive metadata are not retained in history. HTTP/2, WebSockets, chunked
client request bodies and client-certificate authentication are unsupported.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import socketserver
import ssl
import threading
import time
from collections import deque
from urllib.parse import urlsplit, urlunsplit

from proxy_certificates import ca_status, issue_host_certificate
from web_testing import _resolve_pinned

LISTEN_HOST = "127.0.0.1"
DEFAULT_PORT = 8081
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADER_COUNT = 100
MAX_REQUEST_BODY = 64 * 1024
MAX_RESPONSE_BODY = 2 * 1024 * 1024
MAX_TIMEOUT = 12
_HISTORY = deque(maxlen=100)
_HISTORY_LOCK = threading.Lock()
_SENSITIVE = {"authorization", "proxy-authorization", "cookie", "set-cookie",
              "www-authenticate", "proxy-authenticate", "x-api-key", "api-key",
              "x-auth-token", "x-access-token"}
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
        secret = (lowered in _SENSITIVE or "token" in lowered or "secret" in lowered
                  or "session" in lowered or "authorization" in lowered)
        output.append({"name": name, "value": "[REDACTED]" if secret else value[:512]})
    return output


def _history_entry(method: str, url: str, status: int, request_headers: list[tuple[str, str]],
                   response_headers: list[tuple[str, str]], request_size: int,
                   response_size: int, duration_ms: int) -> None:
    parsed = urlsplit(url)
    safe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
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


class _ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(MAX_TIMEOUT)
        try:
            line = self.rfile.readline(8193)
            if not line or len(line) > 8192 or not line.endswith(b"\r\n"):
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
            parsed = urlsplit(target)
            if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                self._error(400, "Use an absolute HTTP URL or HTTPS CONNECT")
                return
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            self._process_request(method, parsed.scheme, parsed.hostname, port, path, version)
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
            try:
                self._error(502, "Upstream or TLS handling failed")
            except OSError:
                pass

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
        cert = issue_host_certificate(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert["certificate"], cert["privateKey"])
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: CyberLab AI\r\n\r\n")
        self.wfile.flush()
        tls = context.wrap_socket(self.connection, server_side=True)
        self.connection = tls
        self.rfile = tls.makefile("rb")
        self.wfile = tls.makefile("wb")
        line = self.rfile.readline(8193)
        if not line or len(line) > 8192 or not line.endswith(b"\r\n"):
            return
        parts = line.decode("iso-8859-1").strip().split(" ")
        if len(parts) != 3 or parts[2] not in {"HTTP/1.0", "HTTP/1.1"}:
            self._error(400, "Malformed HTTPS request line")
            return
        method, path, version = parts
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or not path.startswith("/") or path.startswith("//"):
            self._error(400, "HTTPS request target must be origin-form")
            return
        self._process_request(method, "https", host, port, path, version, tunneled=True)

    def _process_request(self, method: str, scheme: str, host: str, port: int,
                         path: str, version: str, tunneled: bool = False) -> None:
        controller = self.server.controller
        if controller.scope != (scheme, host.rstrip(".").lower(), port):
            self._error(403, "Request is outside the approved proxy scope")
            return
        if method.upper() not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            self._error(405, "HTTP method is not supported")
            return
        headers = self._read_headers()
        lowered = {}
        for name, value in headers:
            lowered.setdefault(name.lower(), []).append(value)
        if "transfer-encoding" in lowered or "expect" in lowered:
            self._error(501, "Chunked request bodies and Expect are not supported")
            return
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
        addresses = _resolve_pinned(host, port, controller.local_lab_mode)
        address = addresses[0]
        url = scheme + "://" + (f"[{host}]" if ":" in host else host) + (f":{port}" if port not in (80, 443) else "") + path
        started = time.monotonic()
        connection = (_PinnedHTTPSConnection(host, port, address) if scheme == "https"
                      else _PinnedHTTPConnection(host, port, address))
        try:
            clean = [(name, value) for name, value in headers
                     if name.lower() not in _HOP_BY_HOP and name.lower() not in {"host", "content-length"}]
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
            safe_forward = [(name, value) for name, value in response_headers
                            if name.lower() not in _HOP_BY_HOP and name.lower() != "content-length"]
            self.wfile.write(f"HTTP/1.1 {response.status} {response.reason}\r\n".encode("iso-8859-1"))
            for name, value in safe_forward:
                self.wfile.write(f"{name}: {value}\r\n".encode("iso-8859-1", errors="replace"))
            self.wfile.write(f"Content-Length: {len(response_body)}\r\nConnection: close\r\n\r\n".encode("ascii"))
            self.wfile.write(response_body)
            self.wfile.flush()
            _history_entry(method.upper(), url, response.status, headers, response_headers,
                           body_size, len(response_body), round((time.monotonic() - started) * 1000))
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
        self._server = None
        self._thread = None
        self.scope = None
        self.local_lab_mode = False
        self.authorization_reference = ""

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
        port = data.get("listenPort", DEFAULT_PORT)
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError("Proxy listen port must be between 1024 and 65535.")
        with self._lock:
            if self._server is not None:
                raise ValueError("The native interception proxy is already running.")
            if scope[0] == "https" and not ca_status()["ready"]:
                raise ValueError("Create the local inspection CA before starting HTTPS interception.")
            server = _ProxyServer((LISTEN_HOST, port), _ProxyHandler)
            server.controller = self
            self.scope = scope
            self.local_lab_mode = local_lab
            self.authorization_reference = reference.strip()
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
                "mode": "HTTP/1.1 request/response inspection; HTTPS CONNECT TLS termination" if active else "stopped",
                "limitations": ["one approved origin", "one request per client connection", "no HTTP/2",
                                "no WebSockets", "no chunked client request bodies", "no client certificates"],
                "historyCount": len(_HISTORY),
            }


PROXY = NativeInterceptProxy()
