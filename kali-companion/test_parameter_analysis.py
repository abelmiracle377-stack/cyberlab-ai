"""Tests for offline captured-response comparison."""
import unittest

from parameter_analysis import compare_responses


def response(status=200, body="ok", duration=100, headers=None):
    return {"status": status, "body": body, "bodyBytes": len(body.encode()),
            "durationMs": duration, "headers": headers or []}


class ParameterAnalysisTests(unittest.TestCase):
    def test_reports_status_body_size_and_timing_differences(self):
        result = compare_responses(
            response(),
            response(302, "redirected", 900, [{"name": "Location", "value": "/login"}]),
        )
        self.assertTrue(result["summary"]["statusChanged"])
        self.assertTrue(result["summary"]["bodyChanged"])
        self.assertEqual(result["summary"]["bodyLengthDelta"], 8)
        self.assertEqual(result["summary"]["durationDeltaMs"], 800.0)
        self.assertIn("status_changed", [item["code"] for item in result["indicators"]])

    def test_redacts_sensitive_headers_in_report(self):
        result = compare_responses(
            response(headers=[{"name": "Set-Cookie", "value": "sid=secret"}]),
            response(headers=[{"name": "Set-Cookie", "value": "sid=other"}]),
        )
        self.assertEqual(result["headers"][0]["before"], "[REDACTED]")
        self.assertEqual(result["headers"][0]["after"], "[REDACTED]")

    def test_identical_responses_have_no_indicators(self):
        result = compare_responses(response(), response())
        self.assertEqual(result["indicators"], [])
        self.assertFalse(result["summary"]["bodyChanged"])

    def test_rejects_invalid_status_and_oversized_body(self):
        with self.assertRaises(ValueError):
            compare_responses(response(status=99), response())
        with self.assertRaisesRegex(ValueError, "64 KB"):
            compare_responses(response(body="x" * 65537), response())


if __name__ == "__main__":
    unittest.main()
