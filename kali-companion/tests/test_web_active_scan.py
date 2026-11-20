"""Tests for conservative native active web checks."""
import unittest
from unittest.mock import patch
import web_active_scan


class WebActiveScanTests(unittest.TestCase):
    def base(self):
        return {"urls": ["http://localhost:8080/search?q=hello"],
                "confirmationUrl": "http://localhost:8080/",
                "authorizationConfirmed": True, "confirmRun": True,
                "authorizationReference": "LOCAL-LAB-002", "localLabMode": True,
                "maxRequests": 5, "delayMs": 500}

    def response(self, headers=None, body="", status=200):
        return {"status": status, "headers": headers or [], "body": body}

    def test_requires_explicit_approval(self):
        data = self.base()
        data["confirmRun"] = False
        with self.assertRaisesRegex(ValueError, "explicitly approve"):
            web_active_scan.run_active_scan(data)

    def test_rejects_out_of_scope_url(self):
        data = self.base()
        data["urls"].append("https://outside.example/")
        with self.assertRaisesRegex(ValueError, "exact confirmed origin"):
            web_active_scan.run_active_scan(data)

    def test_request_budget_is_bounded(self):
        data = self.base()
        data["maxRequests"] = 11
        with self.assertRaisesRegex(ValueError, "between 1 and 10"):
            web_active_scan.run_active_scan(data)

    @patch("web_active_scan.time.sleep")
    @patch("web_active_scan.validate_request", return_value={"addresses": ["127.0.0.1"]})
    @patch("web_active_scan.secrets.token_hex", return_value="0123456789")
    @patch("web_active_scan.execute_request")
    def test_detects_unescaped_reflection_and_cors_reflection(self, execute, token, validate, sleep):
        execute.side_effect = [
            self.response([{"name": "Access-Control-Allow-Origin", "value": "https://cyberlab-probe.invalid"},
                           {"name": "Access-Control-Allow-Credentials", "value": "true"}]),
            self.response([], 'value="CYBERLABPROBE0123456789"><cyberlab-probe>'),
        ]
        result = web_active_scan.run_active_scan(self.base())
        self.assertEqual(result["summary"]["requestsSent"], 2)
        titles = {f["title"] for f in result["findings"]}
        self.assertIn("Potential permissive CORS origin reflection", titles)
        self.assertIn("Potential unescaped query input reflection", titles)
        self.assertEqual(execute.call_args_list[0].args[0]["method"], "OPTIONS")
        self.assertEqual(execute.call_args_list[1].args[0]["method"], "GET")

    @patch("web_active_scan.time.sleep")
    @patch("web_active_scan.validate_request", return_value={"addresses": ["127.0.0.1"]})
    @patch("web_active_scan.execute_request")
    def test_sensitive_query_parameters_are_not_mutated(self, execute, validate, sleep):
        data = self.base()
        data["urls"] = ["http://localhost:8080/?token=secret"]
        execute.return_value = self.response()
        result = web_active_scan.run_active_scan(data)
        self.assertEqual(result["summary"]["sensitiveParametersSkipped"], 1)
        self.assertEqual(result["summary"]["requestsSent"], 1)
        self.assertEqual(execute.call_args_list[0].args[0]["method"], "OPTIONS")

    @patch("web_active_scan.time.sleep")
    @patch("web_active_scan.validate_request", return_value={"addresses": ["127.0.0.1"]})
    @patch("web_active_scan.execute_request")
    def test_wildcard_cors_is_info_not_a_confirmed_vulnerability(self, execute, validate, sleep):
        data = self.base()
        data["urls"] = ["http://localhost:8080/"]
        execute.return_value = self.response([{"name": "Access-Control-Allow-Origin", "value": "*"}])
        result = web_active_scan.run_active_scan(data)
        self.assertEqual(result["findings"][0]["severity"], "info")
        self.assertIn("does not prove sensitive data exposure", result["findings"][0]["detail"])


if __name__ == "__main__":
    unittest.main()
