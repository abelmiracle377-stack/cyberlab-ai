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
    def test_body_size_is_bounded(self, resolve):
        resolve.return_value = [(None, None, None, None, ("127.0.0.1", 8080))]
        data = self.base()
        data["body"] = "x" * (web_testing.MAX_REQUEST_BODY + 1)
        with self.assertRaisesRegex(ValueError, "16 KB"):
            web_testing.validate_request(data)


if ( __name__ == "__main__" ):
    unittest.main()
