import unittest
from unittest.mock import patch

import burp_connector


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class BurpConnectorTests(unittest.TestCase):
    def test_rejects_non_loopback_api_url(self):
        result = burp_connector.inspect_burp_status(
            api_url="http://192.0.2.10:1337",
            api_key="secret",
        )
        self.assertEqual(result["status"], "invalid_configuration")

    def test_rejects_localhost_hostname_to_avoid_dns_rebinding(self):
        result = burp_connector.inspect_burp_status(
            api_url="http://localhost:1337",
            api_key="secret",
        )
        self.assertEqual(result["status"], "invalid_configuration")

    def test_reports_missing_key_without_network_request(self):
        with patch.object(burp_connector, "_load_api_key", return_value=None), \
             patch.object(burp_connector, "urlopen") as open_url:
            result = burp_connector.inspect_burp_status()
        self.assertEqual(result["status"], "not_configured")
        open_url.assert_not_called()

    def test_reports_connection_without_leaking_key(self):
        with patch.object(burp_connector, "urlopen", return_value=FakeResponse()) as open_url, \
             patch.object(burp_connector.shutil, "which", return_value="/usr/bin/burpsuite"):
            result = burp_connector.inspect_burp_status(
                api_url="http://127.0.0.1:1337",
                api_key="never-return-this-secret",
            )
        self.assertEqual(result["status"], "connected")
        self.assertTrue(result["installed"])
        self.assertNotIn("never-return-this-secret", repr(result))
        request = open_url.call_args.args[0]
        self.assertIn("never-return-this-secret", request.full_url)

    def test_marks_scanner_as_not_implemented_until_verified(self):
        with patch.object(burp_connector, "urlopen", return_value=FakeResponse()):
            result = burp_connector.inspect_burp_status(
                api_url="http://127.0.0.1:1337",
                api_key="local-key",
            )
        self.assertEqual(result["capabilities"]["scanner"], "not_implemented")

    def test_proxy_history_requires_local_token(self):
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen") as open_url:
            token_file.read_text.side_effect = OSError("missing")
            result = burp_connector.inspect_burp_proxy_history(25)
        self.assertEqual(result["status"], "not_configured")
        open_url.assert_not_called()

    def test_proxy_history_is_bounded_and_returns_only_metadata(self):
        payload = {
            "status": "ok",
            "items": [
                {"id": 7, "timestamp": "2026-11-16T12:00:00Z", "method": "GET",
                 "url": "https://lab.example.org/", "status_code": 200, "in_scope": True,
                 "request": "must not be forwarded"}
            ]
        }
        class HistoryResponse(FakeResponse):
            def read(self, _limit):
                import json
                return json.dumps(payload).encode("utf-8")
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen", return_value=HistoryResponse()) as open_url:
            token_file.read_text.return_value = "local-extension-token-12345678901234567890"
            result = burp_connector.inspect_burp_proxy_history(999)
        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["count"], 1)
        self.assertNotIn("request", result["items"][0])
        request = open_url.call_args.args[0]
        self.assertIn("limit=100", request.full_url)

    def test_site_map_excludes_out_of_scope_items(self):
        payload = {
            "status": "ok",
            "items": [
                {"method": "GET", "url": "https://lab.example.org/", "status_code": 200, "in_scope": True},
                {"method": "POST", "url": "https://other.example.net/", "status_code": 200, "in_scope": False},
            ]
        }
        class SiteMapResponse(FakeResponse):
            def read(self, _limit):
                import json
                return json.dumps(payload).encode("utf-8")
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen", return_value=SiteMapResponse()) as open_url:
            token_file.read_text.return_value = "local-extension-token-12345678901234567890"
            result = burp_connector.inspect_burp_site_map(20)
        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["count"], 1)
        self.assertTrue(result["items"][0]["in_scope"])
        self.assertNotIn("other.example.net", repr(result))
        self.assertIn("limit=20", open_url.call_args.args[0].full_url)

    def test_audit_issues_returns_only_in_scope_bounded_metadata(self):
        payload = {
            "status": "ok",
            "items": [
                {"name": "Reflected XSS", "base_url": "https://lab.example.org/",
                 "severity": "HIGH", "confidence": "FIRM", "in_scope": True,
                 "detail": "must not be forwarded"},
                {"name": "Out of scope", "base_url": "https://other.example.net/",
                 "severity": "HIGH", "confidence": "FIRM", "in_scope": False},
            ]
        }
        class IssuesResponse(FakeResponse):
            def read(self, _limit):
                import json
                return json.dumps(payload).encode("utf-8")
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen", return_value=IssuesResponse()) as open_url:
            token_file.read_text.return_value = "local-extension-token-12345678901234567890"
            result = burp_connector.inspect_burp_issues(500)
        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["name"], "Reflected XSS")
        self.assertNotIn("detail", result["items"][0])
        self.assertNotIn("other.example.net", repr(result))
        self.assertIn("limit=100", open_url.call_args.args[0].full_url)

    def test_repeater_handoff_requires_explicit_confirmation(self):
        with patch.object(burp_connector, "urlopen") as open_url:
            result = burp_connector.open_burp_history_in_repeater(12, confirmed=False)
        self.assertEqual(result["status"], "confirmation_required")
        self.assertFalse(result["request_sent"])
        open_url.assert_not_called()

    def test_repeater_handoff_is_posted_and_never_claims_request_sent(self):
        class RepeaterResponse(FakeResponse):
            def read(self, _limit):
                import json
                return json.dumps({"status": "opened_in_repeater", "request_sent": False}).encode("utf-8")
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen", return_value=RepeaterResponse()) as open_url:
            token_file.read_text.return_value = "local-extension-token-12345678901234567890"
            result = burp_connector.open_burp_history_in_repeater(12, confirmed=True)
        self.assertEqual(result["status"], "opened_in_repeater")
        self.assertFalse(result["request_sent"])
        request = open_url.call_args.args[0]
        self.assertEqual(request.method, "POST")
        self.assertIn("id=12&confirm=true", request.full_url)

    def test_rejects_url_credentials(self):
        result = burp_connector.inspect_burp_status(
            api_url="http://user:pass@127.0.0.1:1337",
            api_key="secret",
        )
        self.assertEqual(result["status"], "invalid_configuration")


if __name__ == "__main__":
    unittest.main()


class _FakeToken:
    def __init__(self, value): self._value = value
    def read_text(self, encoding="utf-8"): return self._value


class SendInScopeRequestTests(unittest.TestCase):
    def _opener(self, payload_bytes, status=200):
        class Resp:
            def __enter__(self_inner): return self_inner
            def __exit__(self_inner, *a): return False
            def read(self_inner, n=-1): return payload_bytes
        def opener(request, timeout=0):
            opener.url = request.full_url
            return Resp()
        return opener

    def test_requires_confirmation(self):
        result = burp_connector.send_in_scope_request(5, confirmed=False)
        self.assertEqual(result["status"], "confirmation_required")
        self.assertFalse(result["request_sent"])

    def test_rejects_invalid_history_id(self):
        self.assertEqual(burp_connector.send_in_scope_request(0, confirmed=True)["status"], "invalid_request")
        self.assertEqual(burp_connector.send_in_scope_request(True, confirmed=True)["status"], "invalid_request")

    def test_returns_response_metadata_on_send(self):
        body = b'{"status":"sent","history_id":7,"method":"GET","status_code":200,"mime_type":"HTML","body_length":1234,"in_scope":true}'
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE", _FakeToken("tok")):
            result = burp_connector.send_in_scope_request(7, confirmed=True, opener=self._opener(body))
        self.assertEqual(result["status"], "sent")
        self.assertTrue(result["request_sent"])
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["body_length"], 1234)

    def test_out_of_scope_is_reported(self):
        from urllib.error import HTTPError
        def opener(request, timeout=0):
            raise HTTPError(request.full_url, 403, "forbidden", {}, None)
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE", _FakeToken("tok")):
            result = burp_connector.send_in_scope_request(7, confirmed=True, opener=opener)
        self.assertEqual(result["status"], "out_of_scope")
        self.assertFalse(result["request_sent"])


class BurpExtensionHealthTests(unittest.TestCase):
    def test_extension_health_requires_local_token(self):
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen") as open_url:
            token_file.read_text.side_effect = OSError("missing")
            result = burp_connector.inspect_burp_extension_status()
        self.assertEqual(result["status"], "not_configured")
        open_url.assert_not_called()

    def test_extension_health_reports_only_verified_local_capabilities(self):
        class HealthResponse(FakeResponse):
            def read(self, _limit):
                import json
                return json.dumps({"status": "ok", "connector": "montoya"}).encode("utf-8")
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen", return_value=HealthResponse()) as open_url:
            token_file.read_text.return_value = "local-extension-token-12345678901234567890"
            result = burp_connector.inspect_burp_extension_status()
        self.assertEqual(result["status"], "connected")
        self.assertTrue(result["authenticated"])
        self.assertIn("repeater_handoff", result["capabilities"])
        self.assertIn("confirmed_single_request_replay", result["capabilities"])
        self.assertEqual(open_url.call_args.args[0].full_url, burp_connector.EXTENSION_HEALTH_URL)

    def test_extension_health_rejects_wrong_connector_payload(self):
        class WrongResponse(FakeResponse):
            def read(self, _limit):
                import json
                return json.dumps({"status": "ok", "connector": "other"}).encode("utf-8")
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen", return_value=WrongResponse()):
            token_file.read_text.return_value = "local-extension-token-12345678901234567890"
            result = burp_connector.inspect_burp_extension_status()
        self.assertEqual(result["status"], "invalid_response")




class BurpAdvancedIntegrationTests(unittest.TestCase):
    class JsonResponse(FakeResponse):
        def __init__(self, payload):
            self.payload = payload

        def read(self, _limit):
            import json
            return json.dumps(self.payload).encode("utf-8")

    def test_intruder_handoff_requires_explicit_authorization(self):
        result = burp_connector.open_burp_history_in_intruder(
            12, confirmed=False, authorization_reference="LAB-42")
        self.assertEqual(result["status"], "confirmation_required")

    def test_intruder_handoff_calls_local_extension_and_does_not_claim_attack_started(self):
        response = self.JsonResponse({"status": "opened_in_intruder", "history_id": 12, "attack_started": False})
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen", return_value=response) as open_url:
            token_file.read_text.return_value = "local-extension-token-12345678901234567890"
            result = burp_connector.open_burp_history_in_intruder(
                12, confirmed=True, authorization_reference="ENGAGEMENT-42")
        self.assertEqual(result["status"], "opened_in_intruder")
        self.assertFalse(result["attack_started"])
        request = open_url.call_args.args[0]
        self.assertIn("/v1/intruder/from-history?", request.full_url)
        self.assertIn("authorizationReference=ENGAGEMENT-42", request.full_url)
        self.assertEqual(request.get_method(), "POST")

    def test_scanner_rejects_non_http_target_before_network(self):
        with patch.object(burp_connector, "urlopen") as open_url:
            result = burp_connector.start_burp_scanner_task(
                "audit", "file:///etc/passwd", confirmed=True,
                authorization_reference="LAB-42")
        self.assertEqual(result["status"], "invalid_request")
        open_url.assert_not_called()

    def test_scanner_requires_explicit_approval_and_reference(self):
        result = burp_connector.start_burp_scanner_task(
            "audit", "https://lab.example/", confirmed=False,
            authorization_reference="LAB-42")
        self.assertEqual(result["status"], "confirmation_required")

    def test_scanner_start_uses_local_extension_and_returns_real_task_id(self):
        response = self.JsonResponse({"status": "started", "task_id": "task-123", "kind": "crawl"})
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen", return_value=response) as open_url:
            token_file.read_text.return_value = "local-extension-token-12345678901234567890"
            result = burp_connector.start_burp_scanner_task(
                "crawl", "https://lab.example/start", confirmed=True,
                authorization_reference="LAB-42")
        self.assertEqual(result["task_id"], "task-123")
        request = open_url.call_args.args[0]
        self.assertIn("/v1/scanner/crawl?", request.full_url)
        self.assertIn("authorizationReference=LAB-42", request.full_url)
        self.assertEqual(request.get_method(), "POST")

    def test_cancel_scanner_requires_confirmation(self):
        result = burp_connector.cancel_burp_scanner_task("task-123", confirmed=False)
        self.assertEqual(result["status"], "confirmation_required")


