"""Tests for the native web application security assessment engine."""
import unittest

import web_assessment as wa


class AnalyzerTests(unittest.TestCase):
    def test_missing_security_headers_flagged(self):
        out = wa.check_security_headers("https://t.example/", {}, is_https=True)
        keys = {f["title"] for f in out}
        self.assertIn("Missing HSTS header", keys)
        self.assertIn("Missing Content-Security-Policy", keys)
        self.assertIn("No clickjacking protection", keys)
        self.assertIn("Missing X-Content-Type-Options", keys)

    def test_present_headers_not_flagged(self):
        headers = {
            "strict-transport-security": ["max-age=31536000"],
            "content-security-policy": ["default-src 'self'; frame-ancestors 'none'"],
            "x-frame-options": ["DENY"], "x-content-type-options": ["nosniff"],
            "referrer-policy": ["no-referrer"],
        }
        out = wa.check_security_headers("https://t.example/", headers, is_https=True)
        self.assertEqual(out, [])

    def test_cookie_flags(self):
        out = wa.check_cookies("https://t.example/", ["sid=abc; Path=/"], is_https=True)
        titles = {f["title"] for f in out}
        self.assertTrue(any("Secure" in t for t in titles))
        self.assertTrue(any("HttpOnly" in t for t in titles))
        self.assertTrue(any("SameSite" in t for t in titles))
        hardened = wa.check_cookies("https://t.example/", ["sid=abc; Secure; HttpOnly; SameSite=Lax"], is_https=True)
        self.assertEqual(hardened, [])

    def test_sql_error_detection(self):
        hit = wa.detect_sql_error("https://t.example/?q=1", "q",
                                  "Error: You have an error in your SQL syntax near '1''")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["cwe"], "CWE-89")
        self.assertIsNone(wa.detect_sql_error("https://t.example/?q=1", "q", "all good"))

    def test_open_redirect_detection(self):
        hit = wa.detect_open_redirect("https://t.example/go?next=x", "https://cyberlab-redirect.invalid/")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["cwe"], "CWE-601")
        self.assertIsNone(wa.detect_open_redirect("https://t.example/go", "/dashboard"))

    def test_sensitive_path_classification(self):
        git = wa.classify_sensitive_path("https://t.example/", ".git/HEAD", 200, "ref: refs/heads/main\n")
        self.assertEqual(git["severity"], "high")
        env = wa.classify_sensitive_path("https://t.example/", ".env", 200, "DB_PASSWORD=secret\nAPI_KEY=xyz\n")
        self.assertEqual(env["severity"], "high")
        self.assertIsNone(wa.classify_sensitive_path("https://t.example/", ".env", 404, ""))

    def test_directory_listing_and_disclosure(self):
        out = wa.check_body_disclosure("https://t.example/files/",
                                       "<title>Index of /files</title><h1>Index of /files</h1>")
        self.assertTrue(any(f["title"] == "Directory listing enabled" for f in out))
        tb = wa.check_body_disclosure("https://t.example/", "Traceback (most recent call last): ...")
        self.assertTrue(any(f["cwe"] == "CWE-209" for f in tb))

    def test_http_methods(self):
        out = wa.check_http_methods("https://t.example/", "GET, PUT, DELETE, TRACE")
        titles = {f["title"] for f in out}
        self.assertIn("HTTP TRACE enabled", titles)
        self.assertIn("Write HTTP methods advertised", titles)


def _resp(status=200, headers=None, body=""):
    return {"status": status, "headers": [{"name": k, "value": v} for k, v in (headers or {}).items()], "body": body}


class RunAssessmentTests(unittest.TestCase):
    def _data(self, url):
        return {"urls": [url], "confirmationUrl": url, "authorizationConfirmed": True,
                "confirmRun": True, "authorizationReference": "ENG-123", "delayMs": 500}

    def test_requires_authorization(self):
        with self.assertRaises(ValueError):
            wa.run_assessment({"urls": ["https://t.example/"]}, executor=lambda r: _resp(), validator=lambda r: None)

    def test_end_to_end_flags_findings(self):
        calls = []

        def fake(request):
            calls.append((request["method"], request["url"]))
            url = request["url"]
            if request["method"] == "OPTIONS":
                return _resp(headers={"Allow": "GET, TRACE"})
            if url.endswith(".git/HEAD"):
                return _resp(body="ref: refs/heads/main\n")
            if "%27" in url or "'" in url:  # sql error probe (quote is URL-encoded)
                return _resp(body="Warning: mysqli SQL syntax error")
            # base page: no security headers at all
            return _resp(headers={"Set-Cookie": "sid=1; Path=/"}, body="<html>ok</html>")

        out = wa.run_assessment(self._data("https://shop.example/item?id=1"),
                                executor=fake, validator=lambda r: None)
        titles = {f["title"] for f in out["findings"]}
        self.assertIn("Missing HSTS header", titles)
        self.assertIn("SQL injection candidate (error-based)", titles)
        self.assertIn("Exposed .git repository", titles)
        self.assertIn("HTTP TRACE enabled", titles)
        self.assertEqual(out["status"], "completed")
        self.assertGreater(out["summary"]["findings"], 0)

    def test_scope_is_enforced(self):
        with self.assertRaises(ValueError):
            wa.run_assessment({"urls": ["https://a.example/"], "confirmationUrl": "https://b.example/",
                               "authorizationConfirmed": True, "confirmRun": True,
                               "authorizationReference": "X"}, executor=lambda r: _resp(), validator=lambda r: None)


if __name__ == "__main__":
    unittest.main()
