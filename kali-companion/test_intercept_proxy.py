"""Integration tests for the native HTTP interception proxy using loopback only."""
import base64
import hashlib
import http.client
import http.server
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import intercept_proxy
import proxy_certificates as certs


class _TargetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"local-lab-response"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "session=secret-cookie; HttpOnly")
        self.send_header("X-Password-Reset", "secret-password")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class ChunkedRequestBodyTests(unittest.TestCase):
    def test_reads_multiple_chunks_and_discards_valid_trailers(self):
        import io
        stream = io.BytesIO(
            b"4;ext=value\r\nWiki\r\n5\r\npedia\r\n"
            b"0\r\nX-Checksum: ignored\r\n\r\n"
        )
        self.assertEqual(intercept_proxy._read_chunked_body(stream), b"Wikipedia")
        self.assertEqual(stream.read(), b"")

    def test_rejects_chunked_body_over_limit_before_reading_payload(self):
        import io
        stream = io.BytesIO(f"{intercept_proxy.MAX_REQUEST_BODY + 1:x}\r\n".encode("ascii"))
        with self.assertRaisesRegex(ValueError, "exceeds 64 KB"):
            intercept_proxy._read_chunked_body(stream)

    def test_rejects_unsafe_framing_trailer(self):
        import io
        stream = io.BytesIO(b"0\r\nContent-Length: 5\r\n\r\n")
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            intercept_proxy._read_chunked_body(stream)


class NativeInterceptProxyTests(unittest.TestCase):
    def _free_port(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def test_chunked_http_request_is_decoded_and_forwarded_with_content_length(self):
        class EchoHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-CHUNKED-001",
                    "allowStateChangingMethods": True, "confirmStateChangingMethods": True,
                    "localLabMode": True, "listenPort": listen_port,
                })
                with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                    client.sendall((
                        f"POST {origin}/echo HTTP/1.1\\r\\n"
                        f"Host: localhost:{target.server_port}\\r\\n"
                        "Transfer-Encoding: chunked\\r\\n"
                        "Connection: close\\r\\n\\r\\n"
                        "4;part=one\\r\\nWiki\\r\\n"
                        "5\\r\\npedia\\r\\n"
                        "0\\r\\nX-Checksum: ignored\\r\\n\\r\\n"
                    ).encode("ascii"))
                    response = b""
                    while True:
                        chunk = client.recv(8192)
                        if not chunk:
                            break
                        response += chunk
                self.assertIn(b"200 OK", response)
                self.assertIn(b"Wikipedia", response)
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_http_proxy_forwards_only_approved_origin_and_redacts_history(self):
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                status = proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-PROXY-001",
                    "localLabMode": True, "listenPort": listen_port,
                })
                self.assertTrue(status["active"])
                self.assertEqual(status["listenHost"], "127.0.0.1")
                with socket.create_connection(("127.0.0.1", listen_port), timeout=3) as client:
                    request = (
                        f"GET {origin}/inspect?access_token=secret-query HTTP/1.1\r\n"
                        f"Host: localhost:{target.server_port}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                    client.sendall(request)
                    chunks = []
                    while True:
                        chunk = client.recv(8192)
                        if not chunk:
                            break
                        chunks.append(chunk)
                response = b"".join(chunks)
                self.assertIn(b"200 OK", response)
                self.assertIn(b"local-lab-response", response)
                history = intercept_proxy.proxy_history()["items"]
                self.assertGreaterEqual(len(history), 1)
                entry = history[0]
                self.assertTrue(entry["queryOmitted"])
                self.assertNotIn("secret-query", str(entry))
                self.assertTrue(entry["responseBodyOmitted"])
                self.assertNotIn("secret-cookie", str(entry))
                self.assertNotIn("secret-password", str(entry))
                with socket.create_connection(("127.0.0.1", listen_port), timeout=3) as client:
                    client.sendall((f"GET http://127.0.0.1:{target.server_port}/outside HTTP/1.1\r\n"
                                    f"Host: 127.0.0.1:{target.server_port}\r\nConnection: close\r\n\r\n").encode("ascii"))
                    blocked = b""
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        blocked += chunk
                self.assertIn(b"403 Error", blocked)
                self.assertIn(b"outside the approved proxy scope", blocked)
                with socket.create_connection(("127.0.0.1", listen_port), timeout=3) as client:
                    client.sendall((f"POST {origin}/change HTTP/1.1\r\n"
                                    f"Host: localhost:{target.server_port}\r\n"
                                    "Content-Length: 0\r\nConnection: close\r\n\r\n").encode("ascii"))
                    denied = b""
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        denied += chunk
                self.assertIn(b"403 Error", denied)
                self.assertIn(b"State-changing methods are disabled", denied)
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_https_connect_terminates_client_tls_and_validates_upstream_tls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / ".config" / "cyberlab"
            patches = [
                patch.object(certs, "CONFIG_ROOT", root),
                patch.object(certs, "CA_DIR", root / "proxy-ca"),
                patch.object(certs, "CA_KEY", root / "proxy-ca" / "ca-key.pem"),
                patch.object(certs, "CA_CERT", root / "proxy-ca" / "ca-cert.pem"),
                patch.object(certs, "LEAF_DIR", root / "proxy-ca" / "hosts"),
            ]
            for item in patches:
                item.start()
            target = None
            proxy = intercept_proxy.NativeInterceptProxy()
            target_thread = None
            try:
                certs.create_local_ca()
                leaf = certs.issue_host_certificate("localhost")
                target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
                server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_context.load_cert_chain(leaf["certificate"], leaf["privateKey"])
                target.socket = server_context.wrap_socket(target.socket, server_side=True)
                target_thread = threading.Thread(target=target.serve_forever, daemon=True)
                target_thread.start()

                origin = f"https://localhost:{target.server_port}"
                listen_port = self._free_port()
                browser_context = ssl.create_default_context(cafile=str(certs.CA_CERT))
                upstream_context = ssl.create_default_context(cafile=str(certs.CA_CERT))
                with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]), patch.object(intercept_proxy.ssl, "create_default_context", return_value=upstream_context):
                    proxy.start({
                        "origin": origin, "confirmationOrigin": origin,
                        "authorizationConfirmed": True, "confirmStart": True,
                        "authorizationReference": "LOCAL-HTTPS-PROXY-001",
                        "localLabMode": True, "listenPort": listen_port,
                    })
                    raw = socket.create_connection(("127.0.0.1", listen_port), timeout=5)
                    raw.sendall((f"CONNECT localhost:{target.server_port} HTTP/1.1\r\n"
                                 f"Host: localhost:{target.server_port}\r\n"
                                 "Proxy-Connection: keep-alive\r\n\r\n").encode("ascii"))
                    handshake_reply = b""
                    while b"\r\n\r\n" not in handshake_reply:
                        chunk = raw.recv(4096)
                        if not chunk:
                            break
                        handshake_reply += chunk
                    self.assertIn(b"200 Connection Established", handshake_reply)
                    tls_client = browser_context.wrap_socket(raw, server_hostname="localhost")
                    tls_client.sendall((f"GET /secure?session=secret HTTP/1.1\r\n"
                                        f"Host: localhost:{target.server_port}\r\n"
                                        "Connection: close\r\n\r\n").encode("ascii"))
                    response = b""
                    while True:
                        chunk = tls_client.recv(8192)
                        if not chunk:
                            break
                        response += chunk
                    tls_client.close()
                    self.assertIn(b"200 OK", response)
                    self.assertIn(b"local-lab-response", response)
                    entry = intercept_proxy.proxy_history()["items"][0]
                    self.assertTrue(entry["queryOmitted"])
                    self.assertNotIn("secret", str(entry))
            finally:
                proxy.stop()
                if target is not None:
                    target.shutdown()
                    target.server_close()
                if target_thread is not None:
                    target_thread.join(timeout=2)
                for item in reversed(patches):
                    item.stop()

    def test_manual_interception_waits_for_forward_or_drop_decision(self):
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                status = proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-INTERCEPT-001",
                    "localLabMode": True, "listenPort": listen_port,
                    "interceptRequests": True, "confirmInterceptRequests": True,
                })
                self.assertTrue(status["interceptRequests"])

                def send_request(path):
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                        client.sendall((f"GET {origin}{path} HTTP/1.1\r\n"
                                        f"Host: localhost:{target.server_port}\r\n"
                                        "Connection: close\r\n\r\n").encode("ascii"))
                        response = b""
                        while True:
                            chunk = client.recv(8192)
                            if not chunk:
                                break
                            response += chunk
                        return response

                forwarded = {}
                first = threading.Thread(target=lambda: forwarded.setdefault("response", send_request("/manual-forward")))
                first.start()
                pending = []
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pending = intercept_proxy.pending_intercepts()["items"]
                    if pending:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0]["method"], "GET")
                self.assertNotIn("secret-cookie", str(pending[0]))
                intercept_proxy.decide_intercept(pending[0]["id"], "forward")
                first.join(timeout=5)
                self.assertFalse(first.is_alive())
                self.assertIn(b"200 OK", forwarded["response"])

                dropped = {}
                second = threading.Thread(target=lambda: dropped.setdefault("response", send_request("/manual-drop")))
                second.start()
                pending = []
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pending = intercept_proxy.pending_intercepts()["items"]
                    if pending:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(pending), 1)
                intercept_proxy.decide_intercept(pending[0]["id"], "drop")
                second.join(timeout=5)
                self.assertFalse(second.is_alive())
                self.assertIn(b"403 Error", dropped["response"])
                self.assertIn(b"Request dropped by the CyberLab operator", dropped["response"])
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_proxy_history_redacts_sensitive_path_segments_and_jwt(self):
        safe = intercept_proxy._redact_url_path(
            "https://lab.example.test/account/reset-password/eyJabcdefghijklmno.abcdefghijk.abcdefghijk/profile?token=secret"
        )
        self.assertIn("/[REDACTED]/[REDACTED]/profile", safe)
        self.assertNotIn("eyJabcdefghijklmno", safe)
        self.assertNotIn("reset-password", safe)
        self.assertNotIn("secret", safe)
        self.assertNotIn("?", safe)

    def test_interception_decisions_reject_malformed_identifiers_and_actions(self):
        with self.assertRaisesRegex(ValueError, "ID is invalid"):
            intercept_proxy.decide_intercept([], "forward")
        with self.assertRaisesRegex(ValueError, "forward or drop"):
            intercept_proxy.decide_intercept("a" * 32, [])

    def test_proxy_start_requires_exact_origin_and_explicit_approval(self):
        proxy = intercept_proxy.NativeInterceptProxy()
        origin = "http://localhost:8080"
        with self.assertRaisesRegex(ValueError, "Retype the exact approved origin"):
            proxy.start({
                "origin": origin, "confirmationOrigin": "http://localhost:8081",
                "authorizationConfirmed": True, "confirmStart": True,
                "authorizationReference": "LOCAL-PROXY-002", "localLabMode": True,
            })
        with self.assertRaisesRegex(ValueError, "explicitly approve"):
            proxy.start({
                "origin": origin, "confirmationOrigin": origin,
                "authorizationConfirmed": True, "confirmStart": False,
                "authorizationReference": "LOCAL-PROXY-002", "localLabMode": True,
            })
        with self.assertRaisesRegex(ValueError, "Separately approve"):
            proxy.start({
                "origin": origin, "confirmationOrigin": origin,
                "authorizationConfirmed": True, "confirmStart": True,
                "authorizationReference": "LOCAL-PROXY-002", "localLabMode": True,
                "allowStateChangingMethods": True, "confirmStateChangingMethods": False,
            })


    def test_edited_interception_request_is_validated_and_applied(self):
        entry = {
            "method": "GET", "path": "/original", "headers": [("Cookie", "session=secret"), ("Accept", "*/*")],
            "body": b"", "bodyEditable": True, "allowStateChangingMethods": True,
        }
        edited = intercept_proxy._validated_intercept_edit(entry, {
            "method": "POST", "path": "/edited?mode=1",
            "headers": [{"name": "Cookie", "value": "[REDACTED]"}, {"name": "Content-Type", "value": "text/plain"}],
            "body": "edited payload",
        })
        self.assertEqual(edited["method"], "POST")
        self.assertEqual(edited["path"], "/edited?mode=1")
        self.assertEqual(edited["body"], b"edited payload")
        self.assertEqual(edited["headers"][0], ("Cookie", "session=secret"))

    def test_edited_interception_rejects_scope_escape_and_header_injection(self):
        entry = {
            "method": "GET", "path": "/", "headers": [], "body": b"",
            "bodyEditable": True, "allowStateChangingMethods": True,
        }
        for path in ("//evil.example/path", "https://evil.example/", "/\r\nHost: evil.example"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                intercept_proxy._validated_intercept_edit(entry, {"path": path})
        with self.assertRaisesRegex(ValueError, "managed by CyberLab"):
            intercept_proxy._validated_intercept_edit(entry, {
                "headers": [{"name": "Host", "value": "evil.example"}],
            })
        with self.assertRaisesRegex(ValueError, "invalid characters"):
            intercept_proxy._validated_intercept_edit(entry, {
                "headers": [{"name": "X-Test", "value": "ok\r\nInjected: yes"}],
            })

    def test_edited_interception_enforces_body_limit_and_method_permissions(self):
        entry = {
            "method": "GET", "path": "/", "headers": [], "body": b"",
            "bodyEditable": True, "allowStateChangingMethods": False,
        }
        with self.assertRaisesRegex(ValueError, "State-changing methods are disabled"):
            intercept_proxy._validated_intercept_edit(entry, {"method": "DELETE"})
        with self.assertRaisesRegex(ValueError, "exceeds 64 KB"):
            intercept_proxy._validated_intercept_edit(entry, {"body": "x" * (intercept_proxy.MAX_REQUEST_BODY + 1)})

    def test_edited_request_still_strips_connection_nominated_headers(self):
        received = {}

        class ConnectionHeaderHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received["private"] = self.headers.get("X-Private")
                received["connection"] = self.headers.get("Connection")
                payload = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ConnectionHeaderHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        result = {}
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-CONNECTION-TOKEN-001",
                    "localLabMode": True, "listenPort": listen_port,
                    "interceptRequests": True, "confirmInterceptRequests": True,
                })

                def send_request():
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                        client.sendall((f"GET {origin}/connection-token HTTP/1.1\r\n"
                                        f"Host: localhost:{target.server_port}\r\n"
                                        "Connection: X-Private, close\r\n"
                                        "X-Private: must-not-reach-origin\r\n\r\n").encode("ascii"))
                        result["response"] = client.recv(4096)

                worker = threading.Thread(target=send_request)
                worker.start()
                pending = []
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pending = intercept_proxy.pending_intercepts()["items"]
                    if pending:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(pending), 1)
                intercept_proxy.decide_intercept(pending[0]["id"], "forward_edited", {
                    "path": "/connection-token-edited",
                    "headers": [header for header in pending[0]["headers"]
                                if header["name"].lower() not in {"host", "connection"}],
                })
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertIn(b"200 OK", result["response"])
                self.assertIsNone(received.get("private"))
                self.assertEqual(received.get("connection"), "close")
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_proxy_forwards_operator_edited_request_to_same_origin(self):
        received = {}
        class EditHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                received["method"] = self.command
                received["path"] = self.path
                received["body"] = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                payload = b"edited-request-arrived"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *_args):
                pass

        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), EditHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-EDIT-001",
                    "localLabMode": True, "listenPort": listen_port,
                    "interceptRequests": True, "confirmInterceptRequests": True,
                    "allowStateChangingMethods": True, "confirmStateChangingMethods": True,
                })
                result = {}
                def send_original():
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                        client.sendall((f"GET {origin}/before HTTP/1.1\r\n"
                                        f"Host: localhost:{target.server_port}\r\n"
                                        "Connection: close\r\n\r\n").encode("ascii"))
                        chunks = []
                        while True:
                            chunk = client.recv(4096)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        result["response"] = b"".join(chunks)
                worker = threading.Thread(target=send_original)
                worker.start()
                pending = []
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pending = intercept_proxy.pending_intercepts()["items"]
                    if pending:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(pending), 1)
                intercept_proxy.decide_intercept(pending[0]["id"], "forward_edited", {
                    "method": "POST", "path": "/after?edited=1",
                    "headers": [{"name": "Content-Type", "value": "text/plain"}],
                    "body": "edited payload",
                })
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertIn(b"200 OK", result["response"])
                self.assertEqual(received, {
                    "method": "POST", "path": "/after?edited=1", "body": b"edited payload",
                })
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_binary_request_body_is_preserved_when_other_fields_are_edited(self):
        entry = {
            "method": "PUT", "path": "/binary", "headers": [], "body": b"\xff\x00",
            "bodyEditable": False, "allowStateChangingMethods": True,
        }
        edited = intercept_proxy._validated_intercept_edit(entry, {"path": "/binary-updated"})
        self.assertEqual(edited["path"], "/binary-updated")
        self.assertEqual(edited["body"], b"\xff\x00")
        with self.assertRaisesRegex(ValueError, "binary request body cannot be changed"):
            intercept_proxy._validated_intercept_edit(entry, {"body": "replacement"})

    def test_stop_drops_pending_intercepts_using_decision_record(self):
        event = threading.Event()
        intercept_proxy._INTERCEPTS["a" * 32] = {
            "event": event, "decision": None, "public": {},
        }
        try:
            intercept_proxy._drop_all_pending_intercepts()
            self.assertTrue(event.is_set())
            self.assertEqual(intercept_proxy._INTERCEPTS["a" * 32]["decision"], {"action": "drop"})
        finally:
            intercept_proxy._INTERCEPTS.pop("a" * 32, None)


    def test_proxy_stop_releases_paused_request_and_drops_it(self):
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        result = {}
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-STOP-REQUEST-001",
                    "localLabMode": True, "listenPort": listen_port,
                    "interceptRequests": True, "confirmInterceptRequests": True,
                })

                def send_request():
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                        client.sendall((f"GET {origin}/request-stop HTTP/1.1\r\n"
                                        f"Host: localhost:{target.server_port}\r\n"
                                        "Connection: close\r\n\r\n").encode("ascii"))
                        chunks = []
                        while True:
                            chunk = client.recv(8192)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        result["response"] = b"".join(chunks)

                worker = threading.Thread(target=send_request)
                worker.start()
                pending = []
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pending = intercept_proxy.pending_intercepts()["items"]
                    if pending:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(pending), 1)
                self.assertTrue(worker.is_alive(), "The browser request must pause before reaching the target.")
                proxy.stop()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive(), "Stopping the proxy must release the paused handler.")
                self.assertIn(b"403 Error", result["response"])
                self.assertIn(b"Request dropped by the CyberLab operator", result["response"])
                self.assertNotIn(b"local-lab-response", result["response"])
                self.assertEqual(intercept_proxy.pending_intercepts()["count"], 0)
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_proxy_stop_releases_paused_response_and_drops_it(self):
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        result = {}
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-STOP-RESPONSE-001",
                    "localLabMode": True, "listenPort": listen_port,
                    "interceptResponses": True, "confirmInterceptResponses": True,
                })

                def send_request():
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                        client.sendall((f"GET {origin}/response-stop HTTP/1.1\r\n"
                                        f"Host: localhost:{target.server_port}\r\n"
                                        "Connection: close\r\n\r\n").encode("ascii"))
                        chunks = []
                        while True:
                            chunk = client.recv(8192)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        result["response"] = b"".join(chunks)

                worker = threading.Thread(target=send_request)
                worker.start()
                pending = []
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pending = intercept_proxy.pending_response_intercepts()["items"]
                    if pending:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(pending), 1)
                self.assertTrue(worker.is_alive(), "The browser request must be paused before proxy shutdown.")
                proxy.stop()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive(), "Stopping the proxy must release the paused handler.")
                self.assertIn(b"502 Error", result["response"])
                self.assertIn(b"Response dropped by the CyberLab operator", result["response"])
                self.assertNotIn(b"local-lab-response", result["response"])
                self.assertEqual(intercept_proxy.pending_response_intercepts()["count"], 0)
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_response_interception_requires_separate_explicit_approval(self):
        proxy = intercept_proxy.NativeInterceptProxy()
        origin = "http://localhost:8080"
        with self.assertRaisesRegex(ValueError, "Separately approve pausing server responses"):
            proxy.start({
                "origin": origin, "confirmationOrigin": origin,
                "authorizationConfirmed": True, "confirmStart": True,
                "authorizationReference": "LOCAL-RESPONSE-APPROVAL",
                "localLabMode": True, "listenPort": self._free_port(),
                "interceptResponses": True, "confirmInterceptResponses": False,
            })


    def test_manual_response_interception_pauses_until_operator_forwards(self):
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                status = proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-RESPONSE-001",
                    "localLabMode": True, "listenPort": listen_port,
                    "interceptResponses": True, "confirmInterceptResponses": True,
                })
                self.assertTrue(status["interceptResponses"])
                result = {}

                def send_request():
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                        client.sendall((f"GET {origin}/response-inspect HTTP/1.1\r\n"
                                        f"Host: localhost:{target.server_port}\r\n"
                                        "Connection: close\r\n\r\n").encode("ascii"))
                        chunks = []
                        while True:
                            chunk = client.recv(8192)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        result["response"] = b"".join(chunks)

                worker = threading.Thread(target=send_request)
                worker.start()
                pending = []
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pending = intercept_proxy.pending_response_intercepts()["items"]
                    if pending:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0]["status"], 200)
                self.assertIn("local-lab-response", pending[0]["body"])
                self.assertNotIn("secret-cookie", str(pending[0]))
                self.assertNotIn("secret-password", str(pending[0]))
                self.assertTrue(worker.is_alive(), "Client must remain paused until the operator decides.")
                intercept_proxy.decide_response_intercept(pending[0]["id"], "forward")
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertIn(b"200 OK", result["response"])
                self.assertIn(b"local-lab-response", result["response"])
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)


    def test_manual_response_interception_edits_status_headers_and_text_body(self):
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-RESPONSE-EDIT-001",
                    "localLabMode": True, "listenPort": listen_port,
                    "interceptResponses": True, "confirmInterceptResponses": True,
                })
                result = {}

                def send_request():
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                        client.sendall((f"GET {origin}/response-edit HTTP/1.1\r\n"
                                        f"Host: localhost:{target.server_port}\r\n"
                                        "Connection: close\r\n\r\n").encode("ascii"))
                        chunks = []
                        while True:
                            chunk = client.recv(8192)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        result["response"] = b"".join(chunks)

                worker = threading.Thread(target=send_request)
                worker.start()
                pending = []
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pending = intercept_proxy.pending_response_intercepts()["items"]
                    if pending:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(pending), 1)
                item = pending[0]
                self.assertTrue(item["bodyEditable"])
                self.assertEqual(next(header["value"] for header in item["headers"] if header["name"].lower() == "set-cookie"), "[REDACTED]")
                self.assertNotIn("content-length", [header["name"].lower() for header in item["headers"]])
                with self.assertRaisesRegex(ValueError, "status"):
                    intercept_proxy.decide_response_intercept(item["id"], "forward_edited", {
                        "status": 700, "headers": item["headers"], "body": "edited",
                    })
                with self.assertRaisesRegex(ValueError, "header value"):
                    intercept_proxy.decide_response_intercept(item["id"], "forward_edited", {
                        "status": 201, "headers": [{"name": "X-Test", "value": "bad\r\nheader"}],
                        "body": "edited",
                    })
                intercept_proxy.decide_response_intercept(item["id"], "forward_edited", {
                    "status": 201, "reason": "Created by CyberLab",
                    "headers": [
                        {"name": "Content-Type", "value": "text/plain"},
                        {"name": "Set-Cookie", "value": "[REDACTED]"},
                        {"name": "X-Password-Reset", "value": "[REDACTED]"},
                        {"name": "X-CyberLab-Edited", "value": "yes"},
                    ],
                    "body": "edited-local-response",
                })
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                response = result["response"]
                self.assertIn(b"201 Created by CyberLab", response)
                self.assertIn(b"X-CyberLab-Edited: yes", response)
                self.assertIn(b"Set-Cookie: session=secret-cookie; HttpOnly", response)
                self.assertIn(b"X-Password-Reset: secret-password", response)
                self.assertIn(b"edited-local-response", response)
                self.assertNotIn(b"local-lab-response", response)
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_manual_response_interception_can_drop_origin_response(self):
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-RESPONSE-002",
                    "localLabMode": True, "listenPort": listen_port,
                    "interceptResponses": True, "confirmInterceptResponses": True,
                })
                result = {}

                def send_request():
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                        client.sendall((f"GET {origin}/response-drop HTTP/1.1\r\n"
                                        f"Host: localhost:{target.server_port}\r\n"
                                        "Connection: close\r\n\r\n").encode("ascii"))
                        chunks = []
                        while True:
                            chunk = client.recv(8192)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        result["response"] = b"".join(chunks)

                worker = threading.Thread(target=send_request)
                worker.start()
                pending = []
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pending = intercept_proxy.pending_response_intercepts()["items"]
                    if pending:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(pending), 1)
                intercept_proxy.decide_response_intercept(pending[0]["id"], "drop")
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertIn(b"502 Error", result["response"])
                self.assertIn(b"Response dropped by the CyberLab operator", result["response"])
                self.assertNotIn(b"local-lab-response", result["response"])
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)


    def test_edited_response_still_strips_origin_connection_nominated_headers(self):
        received = {}

        class ConnectionResponseHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                payload = b"response-ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Connection", "X-Private")
                self.send_header("X-Private", "must-not-reach-browser")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ConnectionResponseHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        result = {}
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-RESPONSE-CONNECTION-001",
                    "localLabMode": True, "listenPort": listen_port,
                    "interceptResponses": True, "confirmInterceptResponses": True,
                })

                def send_request():
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                        client.sendall((f"GET {origin}/response-connection-token HTTP/1.1\r\n"
                                        f"Host: localhost:{target.server_port}\r\n"
                                        "Connection: close\r\n\r\n").encode("ascii"))
                        chunks = []
                        while True:
                            chunk = client.recv(8192)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        result["response"] = b"".join(chunks)

                worker = threading.Thread(target=send_request)
                worker.start()
                pending = []
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    pending = intercept_proxy.pending_response_intercepts()["items"]
                    if pending:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(pending), 1)
                item = pending[0]
                self.assertNotIn("connection", [header["name"].lower() for header in item["headers"]])
                self.assertIn("x-private", [header["name"].lower() for header in item["headers"]])
                intercept_proxy.decide_response_intercept(item["id"], "forward_edited", {
                    "status": item["status"], "reason": item["reason"],
                    "headers": item["headers"], "body": item["body"],
                })
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertIn(b"200 OK", result["response"])
                self.assertIn(b"response-ok", result["response"])
                self.assertNotIn(b"X-Private:", result["response"])
                self.assertNotIn(b"must-not-reach-browser", result["response"])
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)



    def test_websocket_upgrade_tunnels_masked_client_and_server_frames(self):
        received = {}

        class WebSocketHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                key = self.headers.get("Sec-WebSocket-Key")
                accept = base64.b64encode(hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
                ).digest()).decode("ascii")
                self.send_response(101, "Switching Protocols")
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", accept)
                self.end_headers()
                self.wfile.flush()
                frame = self.rfile.read(8)
                if len(frame) == 8:
                    mask, payload = frame[2:6], frame[6:8]
                    received["message"] = bytes(value ^ mask[index % 4]
                                                for index, value in enumerate(payload))
                    self.wfile.write(b"\x81\x02ok")
                    self.wfile.flush()

            def log_message(self, *_args):
                pass

        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), WebSocketHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        key = base64.b64encode(b"cyberlab-websock").decode("ascii")
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-WEBSOCKET-001",
                    "localLabMode": True, "listenPort": listen_port,
                })
                with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                    client.settimeout(5)
                    client.sendall((f"GET {origin}/socket HTTP/1.1\r\n"
                                    f"Host: localhost:{target.server_port}\r\n"
                                    "Connection: keep-alive, Upgrade\r\n"
                                    "Upgrade: websocket\r\n"
                                    f"Sec-WebSocket-Key: {key}\r\n"
                                    "Sec-WebSocket-Version: 13\r\n\r\n").encode("ascii"))
                    response = bytearray()
                    while not response.endswith(b"\r\n\r\n"):
                        response.extend(client.recv(1))
                    self.assertIn(b"101 Switching Protocols", response)
                    self.assertIn(b"Upgrade: websocket", response)
                    mask = bytes([1, 2, 3, 4])
                    payload = b"hi"
                    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
                    client.sendall(b"\x81\x82" + mask + masked)
                    frame = client.recv(4)
                    self.assertEqual(frame, b"\x81\x02ok")
                self.assertEqual(received.get("message"), b"hi")
                history = []
                history_deadline = time.monotonic() + 3
                while time.monotonic() < history_deadline:
                    history = intercept_proxy.proxy_history()["items"]
                    if any(item["status"] == 101 and item["url"].endswith("/socket") for item in history):
                        break
                    time.sleep(0.01)
                self.assertTrue(any(item["status"] == 101 and item["url"].endswith("/socket") for item in history))
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)


    def test_websocket_frame_observer_parses_fragmented_frames_without_payload(self):
        from websocket_frames import WebSocketFrameObserver
        captured = []
        observer = WebSocketFrameObserver("client-to-server", captured.append)
        mask = bytes([1, 2, 3, 4])
        payload = b"hello"
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        frame = bytes([0x81, 0x85]) + mask + masked
        observer.feed(frame[:3])
        self.assertEqual(captured, [])
        observer.feed(frame[3:])
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["opcodeName"], "text")
        self.assertEqual(captured[0]["payloadLength"], 5)
        self.assertTrue(captured[0]["masked"])
        self.assertNotIn("payload", captured[0])

    def test_websocket_frame_observer_handles_extended_lengths_and_rejects_wrong_mask(self):
        from websocket_frames import WebSocketFrameObserver
        captured = []
        server = WebSocketFrameObserver("server-to-client", captured.append)
        server.feed(bytes([0x82, 0x7e, 0x00, 0x80]) + (b'x' * 128))
        self.assertEqual(captured[0]["payloadLength"], 128)
        self.assertFalse(captured[0]["masked"])
        client = WebSocketFrameObserver("client-to-server", captured.append)
        client.feed(bytes([0x81, 0x01, ord("x")]))
        self.assertTrue(client.disabled)


    def test_websocket_observer_rejects_reserved_bits_and_noncanonical_lengths(self):
        from websocket_frames import WebSocketFrameObserver
        cases = [
            ("server-to-client", bytes([0xC1, 0x00])),  # RSV1 without extension
            ("server-to-client", bytes([0x82, 126, 0x00, 0x7D])),  # 125 encoded as 16-bit
            ("server-to-client", bytes([0x82, 127]) + (65535).to_bytes(8, "big")),
            ("server-to-client", bytes([0x88, 1, 0x00])),  # invalid one-byte close payload
            ("server-to-client", bytes([0x83, 0x00])),  # reserved opcode
        ]
        for direction, frame in cases:
            with self.subTest(frame=frame):
                observer = WebSocketFrameObserver(direction, lambda item: None)
                observer.feed(frame)
                self.assertTrue(observer.disabled)

    def test_websocket_observer_tracks_fragmented_messages_and_allows_control_frames(self):
        from websocket_frames import WebSocketFrameObserver
        captured = []
        observer = WebSocketFrameObserver("server-to-client", captured.append)
        observer.feed(bytes([0x01, 0x01]) + b"a")  # non-final text
        observer.feed(bytes([0x89, 0x00]))  # ping may interleave
        observer.feed(bytes([0x80, 0x01]) + b"b")  # final continuation
        self.assertEqual([item["opcodeName"] for item in captured],
                         ["text", "ping", "continuation"])
        invalid = WebSocketFrameObserver("server-to-client", lambda item: None)
        invalid.feed(bytes([0x80, 0x00]))  # continuation without initial fragment
        self.assertTrue(invalid.disabled)


    def test_websocket_observer_handles_multiple_large_frames_in_one_read(self):
        from websocket_frames import WebSocketFrameObserver
        captured = []
        observer = WebSocketFrameObserver("server-to-client", captured.append)
        payload = b"x" * (600 * 1024)
        frame = bytes([0x82, 127]) + len(payload).to_bytes(8, "big") + payload
        observer.feed(frame + frame)
        self.assertFalse(observer.disabled)
        self.assertEqual(len(captured), 2)
        self.assertEqual([item["payloadLength"] for item in captured],
                         [len(payload), len(payload)])


    def test_websocket_observer_assigns_message_and_fragment_metadata(self):
        from websocket_frames import WebSocketFrameObserver
        captured = []
        observer = WebSocketFrameObserver("server-to-client", captured.append)
        observer.feed(bytes([0x01, 0x01]) + b"a")
        observer.feed(bytes([0x89, 0x00]))  # control frame is outside message sequence
        observer.feed(bytes([0x00, 0x01]) + b"b")
        observer.feed(bytes([0x80, 0x01]) + b"c")
        observer.feed(bytes([0x82, 0x00]))  # next independent binary message
        self.assertEqual([item["messageId"] for item in captured],
                         [1, None, 1, 1, 2])
        self.assertEqual([item["fragmentIndex"] for item in captured],
                         [0, None, 1, 2, 0])
        self.assertEqual([item["messageComplete"] for item in captured],
                         [False, None, False, True, True])


    def test_websocket_frame_codec_round_trips_both_masking_directions(self):
        from websocket_interception import decode_frame, encode_frame
        for direction in ("client-to-server", "server-to-client"):
            frame = encode_frame({"fin": True, "opcode": 1}, b"hello", direction)
            metadata, payload = decode_frame(frame, direction)
            self.assertEqual(payload, b"hello")
            self.assertEqual(metadata["opcode"], 1)
            self.assertEqual(metadata["masked"], direction == "client-to-server")

    def test_websocket_frame_codec_rejects_incomplete_noncanonical_and_oversized_frames(self):
        from websocket_interception import decode_frame
        with self.assertRaises(ValueError):
            decode_frame(b"\\x81", "server-to-client")
        with self.assertRaises(ValueError):
            decode_frame(b"\\x81\\x7e\\x00\\x05hello", "server-to-client")
        with self.assertRaises(ValueError):
            decode_frame(b"\\x82\\x7f" + (65537).to_bytes(8, "big"), "server-to-client")

    def test_websocket_frame_decision_queue_requires_explicit_forward_and_bounds_pending(self):
        from websocket_interception import WebSocketFrameDecisionQueue
        queue = WebSocketFrameDecisionQueue(max_pending=1, timeout=2)
        result = []
        worker = threading.Thread(target=lambda: result.append(
            queue.submit("client-to-server", {"fin": True, "opcode": 1}, b"hello")))
        worker.start()
        deadline = time.monotonic() + 1
        while not queue.pending()["items"] and time.monotonic() < deadline:
            time.sleep(0.005)
        item = queue.pending()["items"][0]
        with self.assertRaises(ValueError):
            queue.submit("server-to-client", {"fin": True, "opcode": 1}, b"second")
        queue.decide(item["id"], "forward_edited", "edited")
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [{"action": "forward", "payload": b"edited"}])

    def test_websocket_frame_decision_queue_drops_on_timeout_and_rejects_binary_edits(self):
        from websocket_interception import WebSocketFrameDecisionQueue
        queue = WebSocketFrameDecisionQueue(timeout=1)
        result = []
        worker = threading.Thread(target=lambda: result.append(
            queue.submit("server-to-client", {"fin": True, "opcode": 2}, b"\\x00\\xff")))
        worker.start()
        deadline = time.monotonic() + 1
        while not queue.pending()["items"] and time.monotonic() < deadline:
            time.sleep(0.005)
        item = queue.pending()["items"][0]
        with self.assertRaises(ValueError):
            queue.decide(item["id"], "forward_edited", "text")
        queue.decide(item["id"], "drop")
        worker.join(timeout=1)
        self.assertEqual(result, [{"action": "drop"}])


    def test_websocket_proxy_frame_reader_handles_fragmented_masked_input(self):
        from websocket_interception import encode_frame
        left, right = socket.socketpair()
        try:
            expected = b"hello"
            raw = encode_frame({"fin": True, "opcode": 1}, expected, "client-to-server")
            right.sendall(raw[:3])
            right.sendall(raw[3:])
            frame, metadata, payload = intercept_proxy._ProxyHandler._recv_websocket_frame(
                left, "client-to-server")
            self.assertEqual(frame, raw)
            self.assertEqual(payload, expected)
            self.assertEqual(metadata["opcode"], 1)
            self.assertTrue(metadata["masked"])
        finally:
            left.close()
            right.close()

    def test_websocket_proxy_frame_reader_rejects_frames_over_interception_limit(self):
        left, right = socket.socketpair()
        try:
            right.sendall(bytes([0x82, 127]) + (65537).to_bytes(8, "big"))
            with self.assertRaises(ValueError):
                intercept_proxy._ProxyHandler._recv_websocket_frame(left, "server-to-client")
        finally:
            left.close()
            right.close()


    def test_websocket_frame_queue_does_not_allow_editing_fragmented_text_frames(self):
        from websocket_interception import WebSocketFrameDecisionQueue
        queue = WebSocketFrameDecisionQueue(timeout=2)
        result = []
        worker = threading.Thread(target=lambda: result.append(
            queue.submit("client-to-server", {"fin": False, "opcode": 1}, b"part")))
        worker.start()
        deadline = time.monotonic() + 1
        while not queue.pending()["items"] and time.monotonic() < deadline:
            time.sleep(0.005)
        item = queue.pending()["items"][0]
        self.assertFalse(item["editable"])
        with self.assertRaises(ValueError):
            queue.decide(item["id"], "forward_edited", "replacement")
        queue.decide(item["id"], "forward")
        worker.join(timeout=1)
        self.assertEqual(result, [{"action": "forward"}])


    def test_websocket_message_assembler_reassembles_fragmented_utf8_text(self):
        from websocket_interception import WebSocketMessageAssembler
        assembler = WebSocketMessageAssembler()
        encoded = "café".encode("utf-8")
        state, messages = assembler.feed({"fin": False, "opcode": 1}, encoded[:3])
        self.assertEqual(state, "pending")
        self.assertEqual(messages, [])
        state, messages = assembler.feed({"fin": True, "opcode": 0}, encoded[3:])
        self.assertEqual(state, "complete")
        self.assertEqual(messages[0]["payload"], encoded)
        self.assertEqual(len(messages[0]["originalFrames"]), 2)

    def test_websocket_message_assembler_passes_control_frames_during_fragmented_message(self):
        from websocket_interception import WebSocketMessageAssembler
        assembler = WebSocketMessageAssembler()
        state, _ = assembler.feed({"fin": False, "opcode": 1}, b"part")
        self.assertEqual(state, "pending")
        state, frames = assembler.feed({"fin": True, "opcode": 9}, b"ping")
        self.assertEqual(state, "control")
        self.assertEqual(frames[0]["payload"], b"ping")
        self.assertTrue(assembler.pending)
        state, messages = assembler.feed({"fin": True, "opcode": 0}, b"two")
        self.assertEqual(state, "complete")
        self.assertEqual(messages[0]["payload"], b"parttwo")

    def test_websocket_message_assembler_bounds_total_message_and_validates_utf8(self):
        from websocket_interception import WebSocketMessageAssembler, MAX_MESSAGE_PAYLOAD
        assembler = WebSocketMessageAssembler()
        assembler.feed({"fin": False, "opcode": 2}, b"x" * MAX_MESSAGE_PAYLOAD)
        with self.assertRaises(ValueError):
            assembler.feed({"fin": True, "opcode": 0}, b"y")
        assembler.reset()
        assembler.feed({"fin": False, "opcode": 1}, b"\xff")
        with self.assertRaises(UnicodeDecodeError):
            assembler.feed({"fin": True, "opcode": 0}, b"")

    def test_websocket_edited_fragmented_message_rebuilds_as_single_text_frame(self):
        from websocket_interception import WebSocketMessageAssembler, forward_message_frames, decode_frame
        assembler = WebSocketMessageAssembler()
        assembler.feed({"fin": False, "opcode": 1}, b"old ")
        _, messages = assembler.feed({"fin": True, "opcode": 0}, b"text")
        rebuilt = forward_message_frames(messages[0], b"new text", "client-to-server", edited=True)
        self.assertEqual(len(rebuilt), 1)
        metadata, payload = decode_frame(rebuilt[0], "client-to-server")
        self.assertTrue(metadata["fin"])
        self.assertEqual(metadata["opcode"], 1)
        self.assertEqual(payload, b"new text")


    def test_websocket_message_assembler_exposes_fragment_assembly_timeout(self):
        from websocket_interception import WebSocketMessageAssembler
        assembler = WebSocketMessageAssembler()
        assembler.feed({"fin": False, "opcode": 1}, b"partial")
        self.assertFalse(assembler.expired)
        assembler._started -= 16
        self.assertTrue(assembler.expired)
        with self.assertRaises(ValueError):
            assembler.feed({"fin": True, "opcode": 0}, b"tail")
        self.assertFalse(assembler.pending)


    def test_http_proxy_reuses_client_connection_for_sequential_keep_alive_requests(self):
        received = []

        class KeepAliveHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                received.append(self.path)
                body = ("response:" + self.path).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), KeepAliveHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-KEEPALIVE-001",
                    "localLabMode": True, "listenPort": listen_port,
                })
                with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                    client.settimeout(5)
                    client.sendall((f"GET {origin}/first HTTP/1.1\r\n"
                                    f"Host: localhost:{target.server_port}\r\n\r\n").encode("ascii"))
                    first_response = http.client.HTTPResponse(client)
                    first_response.begin()
                    self.assertEqual(first_response.status, 200)
                    self.assertIn("keep-alive", first_response.getheader("Connection", "").lower())
                    self.assertEqual(first_response.read(), b"response:/first")

                    client.sendall((f"GET {origin}/second HTTP/1.1\r\n"
                                    f"Host: localhost:{target.server_port}\r\n"
                                    "Connection: close\r\n\r\n").encode("ascii"))
                    second_response = http.client.HTTPResponse(client)
                    second_response.begin()
                    self.assertEqual(second_response.status, 200)
                    self.assertEqual(second_response.read(), b"response:/second")
                    self.assertEqual(client.recv(1), b"")
                self.assertEqual(received, ["/first", "/second"])
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_http_proxy_rejects_host_header_that_disagrees_with_absolute_target(self):
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        proxy = intercept_proxy.NativeInterceptProxy()
        listen_port = self._free_port()
        origin = f"http://localhost:{target.server_port}"
        try:
            with patch.object(intercept_proxy, "_resolve_pinned", return_value=["127.0.0.1"]):
                proxy.start({
                    "origin": origin, "confirmationOrigin": origin,
                    "authorizationConfirmed": True, "confirmStart": True,
                    "authorizationReference": "LOCAL-HOST-CHECK-001",
                    "localLabMode": True, "listenPort": listen_port,
                })
                with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
                    client.sendall((f"GET {origin}/ HTTP/1.1\r\n"
                                    "Host: other.example\r\n\r\n").encode("ascii"))
                    response = b""
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                self.assertIn(b"421 Error", response)
                self.assertIn(b"Host header does not match", response)
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)



if __name__ == "__main__":
    unittest.main()
