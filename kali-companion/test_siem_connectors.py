"""Tests for the Splunk and Wazuh connectors using an injected HTTP opener
(no network). Verifies request shaping, auth headers, and result normalization.
"""
import json
import unittest

import splunk_connector as splunk
import wazuh_connector as wazuh


class FakeResponse:
    def __init__(self, status, text):
        self.status = status
        self._body = text.encode("utf-8")

    def read(self):
        return self._body


class FakeOpener:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        return FakeResponse(*self.responses.pop(0))


class SplunkTests(unittest.TestCase):
    def test_hec_send_shapes_request_and_reports_ok(self):
        opener = FakeOpener((200, json.dumps({"text": "Success", "code": 0})))
        out = splunk.send_hec_event("https://splunk:8088", "TOK", {"msg": "hi"},
                                    index="main", opener=opener)
        self.assertTrue(out["ok"])
        req = opener.requests[0]
        self.assertTrue(req.full_url.endswith("/services/collector/event"))
        self.assertEqual(req.headers["Authorization"], "Splunk TOK")
        self.assertEqual(json.loads(req.data.decode())["index"], "main")

    def test_hec_send_reports_failure_code(self):
        opener = FakeOpener((403, json.dumps({"text": "Invalid token", "code": 4})))
        out = splunk.send_hec_event("https://splunk:8088", "BAD", {"m": 1}, opener=opener)
        self.assertFalse(out["ok"])

    def test_search_normalizes_export_rows(self):
        lines = "\n".join(json.dumps({"preview": False, "result": r}) for r in [
            {"_time": "2026-11-20T03:00:00Z", "host": "web01", "src_ip": "45.33.32.156",
             "dest_port": "22", "event_type": "auth_failure", "user": "root"},
            {"_time": "2026-11-20T03:01:00Z", "host": "web01", "_raw": "accepted"},
        ])
        opener = FakeOpener((200, lines))
        out = splunk.search("https://splunk:8089", "TOK", "index=linux sshd", opener=opener)
        self.assertTrue(out["ok"])
        self.assertEqual(out["result_count"], 2)
        self.assertEqual(out["events"][0]["type"], "auth_failure")
        self.assertEqual(out["events"][0]["src_ip"], "45.33.32.156")
        self.assertEqual(out["events"][0]["dst_port"], 22)
        # The query is wrapped with "search " and uses Bearer auth.
        req = opener.requests[0]
        self.assertEqual(req.headers["Authorization"], "Bearer TOK")
        self.assertIn("search+index%3Dlinux", req.data.decode())

    def test_search_rejects_empty_query(self):
        with self.assertRaisesRegex(ValueError, "SPL search query"):
            splunk.search("https://s:8089", "T", "   ", opener=FakeOpener())


class WazuhTests(unittest.TestCase):
    def test_login_returns_token_with_basic_auth(self):
        opener = FakeOpener((200, json.dumps({"data": {"token": "JWT123"}})))
        token = wazuh.api_login("https://wazuh:55000", "user", "pass", opener=opener)
        self.assertEqual(token, "JWT123")
        self.assertTrue(opener.requests[0].headers["Authorization"].startswith("Basic "))

    def test_login_failure_raises(self):
        opener = FakeOpener((401, "{}"))
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            wazuh.api_login("https://wazuh:55000", "user", "bad", opener=opener)

    def test_list_agents_normalizes(self):
        payload = {"data": {"affected_items": [
            {"id": "001", "name": "web01", "ip": "10.0.0.5", "status": "active",
             "os": {"name": "Ubuntu"}, "version": "4.7"},
            {"id": "002", "name": "db01", "ip": "10.0.0.6", "status": "disconnected"},
        ]}}
        opener = FakeOpener((200, json.dumps(payload)))
        out = wazuh.list_agents("https://wazuh:55000", "JWT", opener=opener)
        self.assertEqual(out["agent_count"], 2)
        self.assertEqual(out["active"], 1)
        self.assertEqual(out["agents"][0]["os"], "Ubuntu")

    def test_alert_search_normalizes_and_maps_severity(self):
        hits = {"hits": {"hits": [
            {"_source": {"timestamp": "2026-11-20T03:00:00Z",
                         "rule": {"id": "5710", "level": 10, "description": "sshd brute force",
                                  "mitre": {"id": ["T1110"], "technique": ["Brute Force"],
                                            "tactic": ["Credential Access"]}},
                         "agent": {"name": "web01"}, "data": {"srcip": "45.33.32.156"}}},
        ]}}
        opener = FakeOpener((200, json.dumps(hits)))
        out = wazuh.search_alerts("https://indexer:9200", "u", "p", opener=opener)
        self.assertTrue(out["ok"])
        event = out["events"][0]
        self.assertEqual(event["type"], "siem_alert")
        self.assertEqual(event["severity"], "high")  # level 10 -> high
        self.assertEqual(event["src_ip"], "45.33.32.156")
        self.assertEqual(event["details"]["mitre"]["technique_id"], "T1110")

    def test_level_to_severity_mapping(self):
        self.assertEqual(wazuh._level_to_severity(15), "critical")
        self.assertEqual(wazuh._level_to_severity(9), "high")
        self.assertEqual(wazuh._level_to_severity(6), "medium")
        self.assertEqual(wazuh._level_to_severity(2), "low")
        self.assertEqual(wazuh._level_to_severity(0), "informational")


if __name__ == "__main__":
    unittest.main()
