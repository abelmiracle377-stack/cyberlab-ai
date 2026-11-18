"""Regression tests for native HTTP scope and SSRF protections."""
from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

import web_testing


def _addr(ip: str):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return (family, socket.SOCK_STREAM, 6, "", (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443))


def _request(url="https://example.test/path", confirmation="https://example.test/"):
    return {
        "url": url,
        "confirmationUrl": confirmation,
        "authorizationConfirmed": True,
        "confirmSend": True,
        "authorizationReference": "ENG-TEST-001",
        "method": "GET",
    }


class NativeWebScopeTests(unittest.TestCase):
    @patch("web_testing.socket.getaddrinfo", return_value=[_addr("93.184.216.34")])
    def test_same_origin_confirmation_accepts_path_difference(self, resolver):
        result = web_testing.validate_request(_request())
        self.assertEqual(result["host"], "example.test")
        self.assertEqual(result["port"], 443)
        resolver.assert_called_once()

    @patch("web_testing.socket.getaddrinfo", return_value=[_addr("93.184.216.34")])
    def test_rejects_confirmation_with_different_scheme(self, resolver):
        with self.assertRaisesRegex(ValueError, "exact target scheme"):
            web_testing.validate_request(_request(confirmation="http://example.test/"))
        resolver.assert_not_called()

    @patch("web_testing.socket.getaddrinfo", return_value=[_addr("93.184.216.34")])
    def test_rejects_confirmation_with_different_port(self, resolver):
        with self.assertRaisesRegex(ValueError, "exact target scheme"):
            web_testing.validate_request(_request(confirmation="https://example.test:8443/"))
        resolver.assert_not_called()

    @patch("web_testing.socket.getaddrinfo", return_value=[_addr("93.184.216.34"), _addr("127.0.0.1")])
    def test_rejects_mixed_public_and_loopback_dns_answers(self, resolver):
        with self.assertRaisesRegex(ValueError, "Private, loopback"):
            web_testing.validate_request(_request())

    @patch("web_testing.socket.getaddrinfo", return_value=[_addr("10.0.0.8")])
    def test_rejects_private_dns_answer(self, resolver):
        with self.assertRaisesRegex(ValueError, "Private, loopback"):
            web_testing.validate_request(_request())

    @patch("web_testing.socket.getaddrinfo", return_value=[_addr("2606:4700:4700::1111")])
    def test_accepts_public_ipv6_dns_answer(self, resolver):
        result = web_testing.validate_request(_request())
        self.assertIn("2606:4700:4700::1111", result["addresses"])

    @patch("web_testing.socket.getaddrinfo", return_value=[_addr("127.0.0.1")])
    def test_local_lab_mode_allows_loopback_only(self, resolver):
        data = _request("http://127.0.0.1:8080/", "http://127.0.0.1:8080/")
        data["localLabMode"] = True
        result = web_testing.validate_request(data)
        self.assertEqual(result["addresses"], ["127.0.0.1"])

    @patch("web_testing.socket.getaddrinfo", return_value=[_addr("93.184.216.34")])
    def test_local_lab_mode_rejects_public_target(self, resolver):
        data = _request("https://example.test/", "https://example.test/")
        data["localLabMode"] = True
        with self.assertRaisesRegex(ValueError, "loopback"):
            web_testing.validate_request(data)


if __name__ == "__main__":
    unittest.main()
