"""Integration tests for the native HTTP interception proxy using loopback only."""
import http.server
import socket
import ssl
import tempfile
import threading
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
                    client.sendall((f"POST {origin}/change HTTP/1.1\\r\\n"
                                    f"Host: localhost:{target.server_port}\\r\\n"
                                    "Content-Length: 0\\r\\nConnection: close\\r\\n\\r\\n").encode("ascii"))
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


if __name__ == "__main__":
    unittest.main()
