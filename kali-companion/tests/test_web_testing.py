"""Tests for CyberLab-native HTTP request scope and approval policy."""
import unittest
from unittest.mock import patch

import web_testing


class WebTestingValidationTests(unittest.TestCase):
    def base(self):
        return {
            "url": "http://localhost:8080/",
            "confirmationUrl": "http://localhost:8080/",
            "authorizationConfirmed": True,
            "confirmSend": True,
            "authorizationReference": "LOCAL-LAB-001",
            "localLabMode": True,
            "method": "GET",
        }

    @patch("web_testing.socket.getaddrinfo")
    def test_valid_local_lab_request_is_pinned_to_loopback(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        request = web_testing.validate_request(self.base())
        self.assertEqual(request["addresses"], ["127.0.0.1"])
        self.assertEqual(request["target"], "/")

    @patch("web_testing.socket.getaddrinfo")
    def test_local_lab_rejects_non_loopback_resolution(self, resolve):
        resolve.return_value = [(None, None, None, None, ("192.168.1.5", 8080))]
        with self.assertRaisesRegex(ValueError, "loopback"):
            web_testing.validate_request(self.base())

    def test_send_requires_explicit_approval(self):
        data = self.base()
        data["confirmSend"] = False
        with self.assertRaisesRegex(ValueError, "explicitly approve"):
            web_testing.validate_request(data)

    @patch("web_testing.socket.getaddrinfo")
    def test_mutating_method_requires_separate_confirmation(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        data = self.base()
        data.update({"method": "POST", "body": "hello"})
        with self.assertRaisesRegex(ValueError, "change server state"):
            web_testing.validate_request(data)
        data["confirmStateChange"] = True
        self.assertEqual(web_testing.validate_request(data)["body"], b"hello")

    @patch("web_testing.socket.getaddrinfo")
    def test_exact_host_confirmation_is_required(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        data = self.base()
        data["confirmationUrl"] = "http://other.local/"
        with self.assertRaisesRegex(ValueError, "exact target hostname"):
            web_testing.validate_request(data)

    @patch("web_testing.socket.getaddrinfo")
    def test_private_address_is_rejected_outside_local_lab_mode(self, resolve):
        resolve.return_value = [(None, None, None, None, ("10.0.0.8", 8080))]
        data = self.base()
        data["localLabMode"] = False
        data["url"] = "http://lab.example.org:8080/"
        data["confirmationUrl"] = data["url"]
        with self.assertRaisesRegex(ValueError, "Private"):
            web_testing.validate_request(data)

    @patch("web_testing.socket.getaddrinfo")
    def test_host_header_cannot_override_scope(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        data = self.base()
        data["headers"] = {"Host": "attacker.example"}
        with self.assertRaisesRegex(ValueError, "controlled by CyberLab"):
            web_testing.validate_request(data)

    @patch("web_testing.socket.getaddrinfo")
    def test_unsupported_method_is_rejected(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        data = self.base()
        data["method"] = "CONNECT"
        with self.assertRaisesRegex(ValueError, "Supported methods"):
            web_testing.validate_request(data)

    @patch("web_testing.socket.getaddrinfo")
    def test_history_metadata_redacts_secrets_and_never_stores_request_body(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        data = self.base()
        data.update({"headers": {"Accept": "application/json", "Authorization": "Bearer secret",
                                 "X-API-Key": "private-key", "X-Correlation-ID": "trace-1"},
                     "method": "POST", "body": "password=do-not-store", "confirmStateChange": True})
        request = web_testing.validate_request(data)
        metadata = web_testing._safe_history_request(request)
        self.assertEqual(metadata["requestHeaders"]["Accept"], "application/json")
        self.assertEqual(metadata["requestHeaders"]["Authorization"], "[REDACTED]")
        self.assertEqual(metadata["requestHeaders"]["X-API-Key"], "[REDACTED]")
        self.assertEqual(metadata["requestHeaders"]["X-Correlation-ID"], "trace-1")
        self.assertTrue(metadata["requestBodyOmitted"])
        self.assertEqual(metadata["requestBodyLength"], len("password=do-not-store"))
        self.assertNotIn("password=do-not-store", str(metadata))

    @patch("web_testing.socket.getaddrinfo")
    def test_body_size_is_bounded(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        data = self.base()
        data["body"] = "x" * (web_testing.MAX_REQUEST_BODY + 1)
        with self.assertRaisesRegex(ValueError, "16 KB"):
            web_testing.validate_request(data)


    def test_history_omits_response_body_and_redacts_response_secrets(self):
        live = {
            "body": "session-token=secret-response",
            "bodyBytes": 26,
            "headers": [
                {"name": "Content-Type", "value": "text/plain"},
                {"name": "Set-Cookie", "value": "session=secret; HttpOnly"},
                {"name": "X-Auth-Token", "value": "secret-token"},
            ],
        }
        history = web_testing._safe_history_response(live)
        self.assertEqual(history["body"], "")
        self.assertTrue(history["responseBodyOmitted"])
        self.assertEqual(history["responseBodyLength"], 26)
        self.assertEqual(history["headers"][0]["value"], "text/plain")
        self.assertEqual(history["headers"][1]["value"], "[REDACTED]")
        self.assertEqual(history["headers"][2]["value"], "[REDACTED]")
        self.assertNotIn("secret-response", str(history))
        self.assertNotIn("secret-token", str(history))


    @patch("web_testing.socket.getaddrinfo")
    def test_rejects_unescaped_whitespace_in_request_target(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        data = self.base()
        data["url"] = "http://localhost:8080/search term"
        data["confirmationUrl"] = "http://localhost:8080/"
        with self.assertRaisesRegex(ValueError, "percent-encoded"):
            web_testing.validate_request(data)

    @patch("web_testing.socket.getaddrinfo")
    def test_rejects_header_values_that_cannot_be_encoded_as_http_bytes(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        data = self.base()
        data["headers"] = {"X-Test": "漢字"}
        with self.assertRaisesRegex(ValueError, "ISO-8859-1"):
            web_testing.validate_request(data)

    @patch("web_testing.socket.getaddrinfo")
    def test_rejects_delete_control_character_in_header_value(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        data = self.base()
        data["headers"] = {"X-Test": "value\x7f"}
        with self.assertRaisesRegex(ValueError, "HTTP field characters"):
            web_testing.validate_request(data)

    @patch("web_testing.socket.create_connection")
    @patch("web_testing.socket.getaddrinfo")
    def test_ipv6_host_header_uses_brackets(self, resolve, connect):
        import io

        resolve.return_value = [(None, None, None, None, ("::1", 8080, 0, 0))]

        class FakeSocket:
            def __init__(self):
                self.sent = b""
            def settimeout(self, _timeout):
                pass
            def sendall(self, payload):
                self.sent += payload
            def makefile(self, *_args, **_kwargs):
                return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            def close(self):
                pass

        fake = FakeSocket()
        connect.return_value = fake
        data = self.base()
        data.update({"url": "http://[::1]:8080/", "confirmationUrl": "http://[::1]:8080/"})
        result = web_testing.execute_request(data)
        self.assertEqual(result["status"], 200)
        self.assertIn(b"Host: [::1]:8080", fake.sent)

if ( __name__ == "__main__" ):
    unittest.main()
