"""Integration tests for the native HTTP interception proxy using loopback only."""
import http.server
import socket
import threading
import unittest
from unittest.mock import patch

import intercept_proxy


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
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

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


if __name__ == "__main__":
    unittest.main()
