"""Integration tests for the native HTTP interception proxy using loopback only."""
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


class NativeInterceptProxyTests(unittest.TestCase):
    def _free_port(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

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
                                    "Host: 127.0.0.1\r\nConnection: close\r\n\r\n").encode("ascii"))
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
                        client.sendall((f"GET {origin}/response-inspect HTTP/1.1\\r\\n"
                                        f"Host: localhost:{target.server_port}\\r\\n"
                                        "Connection: close\\r\\n\\r\\n").encode("ascii"))
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
                        client.sendall((f"GET {origin}/response-drop HTTP/1.1\\r\\n"
                                        f"Host: localhost:{target.server_port}\\r\\n"
                                        "Connection: close\\r\\n\\r\\n").encode("ascii"))
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


if __name__ == "__main__":
    unittest.main()
