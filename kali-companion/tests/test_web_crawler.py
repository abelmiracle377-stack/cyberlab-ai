"""Safety and behaviour tests for the native bounded web crawler."""
import unittest
from unittest.mock import patch
import web_crawler
from task_planner import plan_task


class WebCrawlerTests(unittest.TestCase):
    def base(self):
        return {"url": "http://localhost:8080/", "confirmationUrl": "http://localhost:8080/",
                "authorizationConfirmed": True, "confirmRun": True, "authorizationReference": "LOCAL-LAB-001",
                "localLabMode": True, "maxPages": 5, "maxDepth": 2, "delayMs": 250}

    def response(self, body, content_type="text/html; charset=utf-8", status=200):
        return {"status": status, "headers": [{"name": "Content-Type", "value": content_type}],
                "body": body, "bodyBytes": len(body.encode()), "truncated": False}

    def test_requires_written_authorisation_and_run_approval(self):
        data = self.base()
        data["confirmRun"] = False
        with self.assertRaisesRegex(ValueError, "explicitly approve"):
            web_crawler.run_crawl(data)

    def test_confirmation_must_match_exact_origin_including_port(self):
        data = self.base()
        data["confirmationUrl"] = "http://localhost:8081/"
        with self.assertRaisesRegex(ValueError, "exact scheme"):
            web_crawler.run_crawl(data)

    def test_page_budget_is_bounded(self):
        data = self.base()
        data["maxPages"] = 21
        with self.assertRaisesRegex(ValueError, "between 1 and 20"):
            web_crawler.run_crawl(data)

    @patch("web_crawler.time.sleep")
    @patch("web_crawler.validate_request", return_value={"addresses": ["127.0.0.1"]})
    @patch("web_crawler.execute_request")
    def test_crawl_is_same_origin_get_only_and_does_not_submit_forms(self, execute, validate, sleep):
        execute.side_effect = [self.response('<a href="/account">Account</a><a href="https://outside.example/path">Outside</a><form action="/transfer" method="POST"><input name="amount"></form>'),
                              self.response("<h1>Account</h1>")]
        result = web_crawler.run_crawl(self.base())
        self.assertEqual(result["summary"]["pagesVisited"], 2)
        self.assertEqual(result["summary"]["formsObserved"], 1)
        self.assertEqual(result["pages"][0]["forms"][0]["method"], "POST")
        self.assertEqual(result["pages"][0]["forms"][0]["fields"][0]["name"], "amount")
        self.assertFalse(result["pages"][0]["forms"][0]["submitted"])
        self.assertEqual(result["summary"]["outOfScopeLinksBlocked"], 1)
        self.assertEqual(execute.call_count, 2)
        for call in execute.call_args_list:
            self.assertEqual(call.args[0]["method"], "GET")
            self.assertNotIn("confirmStateChange", call.args[0])
        self.assertEqual(result["pages"][1]["url"], "http://localhost:8080/account")

    def test_planner_recommends_native_crawler_and_labels_active_scan_as_pending(self):
        plan = plan_task("Assess this web app http://localhost:8080")
        names = {item["name"] for item in plan["suggested_tools"]}
        self.assertIn("CyberLab Web Crawler & Baseline Auditor", names)
        phases = {item["phase"]: item for item in plan["recommended_workflow"]}
        self.assertEqual(phases["application discovery"]["status"], "available")
        self.assertEqual(phases["safe active checks"]["status"], "available_limited")
        self.assertEqual(phases["advanced vulnerability validation"]["status"], "not_implemented")

    @patch("web_crawler.time.sleep")
    @patch("web_crawler.validate_request", return_value={"addresses": ["127.0.0.1"]})
    @patch("web_crawler.execute_request")
    def test_redirect_is_recorded_but_never_followed(self, execute, validate, sleep):
        execute.return_value = self.response("", "text/html", 302)
        execute.return_value["headers"].append({"name": "Location", "value": "http://outside.example/"})
        result = web_crawler.run_crawl(self.base())
        self.assertEqual(execute.call_count, 1)
        self.assertFalse(result["pages"][0]["redirectFollowed"])

    @patch("web_crawler.time.sleep")
    @patch("web_crawler.validate_request", return_value={"addresses": ["127.0.0.1"]})
    @patch("web_crawler.execute_request")
    def test_baseline_headers_are_reported_with_response_evidence(self, execute, validate, sleep):
        execute.return_value = self.response("<html></html>")
        result = web_crawler.run_crawl(self.base())
        titles = {item["title"] for item in result["findings"]}
        self.assertIn("Content Security Policy is not present", titles)
        self.assertEqual(len(result["pages"][0]["responseSha256"]), 64)
        self.assertIn("No payload injection", " ".join(result["limitations"]))

    @patch("web_crawler.time.sleep")
    @patch("web_crawler.validate_request", return_value={"addresses": ["127.0.0.1"]})
    @patch("web_crawler.execute_request")
    def test_request_errors_are_recorded_without_expanding_scope(self, execute, validate, sleep):
        execute.side_effect = OSError("connection refused")
        result = web_crawler.run_crawl(self.base())
        self.assertEqual(result["summary"]["requestErrors"], 1)
        self.assertIsNone(result["pages"][0]["status"])


if __name__ == "__main__":
    unittest.main()
