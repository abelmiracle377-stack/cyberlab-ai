"""Tests for the offline parameter mutation planner."""
import unittest

from parameter_lab import generate_cases, inspect_parameters


class ParameterLabTests(unittest.TestCase):
    def test_inspects_query_and_form_and_excludes_sensitive_names(self):
        result = inspect_parameters(
            "https://lab.example/search?q=hello&session_token=abc",
            "item=book&csrf=secret", "application/x-www-form-urlencoded")
        self.assertEqual(result["count"], 4)
        self.assertEqual(result["eligibleCount"], 2)
        self.assertFalse(result["items"][1]["eligible"])
        self.assertFalse(result["items"][3]["eligible"])

    def test_query_cases_mutate_one_parameter_and_never_send(self):
        result = generate_cases(
            "https://lab.example/search?q=hello&lang=en", "", "",
            "query", 0, ["alpha beta", "<test>"])
        self.assertEqual(result["count"], 2)
        self.assertIn("q=alpha+beta", result["cases"][0]["url"])
        self.assertIn("lang=en", result["cases"][0]["url"])
        self.assertFalse(result["sent"])
        self.assertTrue(all(case["sent"] is False for case in result["cases"]))

    def test_form_cases_preserve_other_fields(self):
        result = generate_cases(
            "https://lab.example/login", "user=alice&role=reader",
            "application/x-www-form-urlencoded", "form", 1, ["viewer"], method="POST")
        self.assertEqual(result["cases"][0]["method"], "POST")
        self.assertEqual(result["cases"][0]["body"], "user=alice&role=viewer")

    def test_sensitive_parameter_mutation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Sensitive-looking"):
            generate_cases("https://lab.example/?api_key=secret", "", "",
                           "query", 0, ["x"])

    def test_payload_and_parameter_limits_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 25"):
            generate_cases("https://lab.example/?q=x", "", "", "query", 0, [])
        with self.assertRaisesRegex(ValueError, "512 characters"):
            generate_cases("https://lab.example/?q=x", "", "", "query", 0, ["x" * 513])

    def test_mutation_method_is_validated_and_normalised(self):
        result = generate_cases(
            "https://lab.example/?q=x", "", "", "query", 0, ["y"], method="post")
        self.assertEqual(result["cases"][0]["method"], "POST")
        with self.assertRaisesRegex(ValueError, "supported HTTP method"):
            generate_cases("https://lab.example/?q=x", "", "", "query", 0, ["y"], method="TRACE")
        with self.assertRaisesRegex(ValueError, "require POST, PUT or PATCH"):
            generate_cases("https://lab.example/", "q=x",
                           "application/x-www-form-urlencoded", "form", 0, ["y"], method="GET")

    def test_non_form_body_is_not_parsed(self):
        with self.assertRaisesRegex(ValueError, "Only URL-encoded"):
            inspect_parameters("https://lab.example/", '{"x":1}', "application/json")

    def test_invalid_target_is_rejected(self):
        with self.assertRaises(ValueError):
            inspect_parameters("https://user:pass@lab.example/?q=x")


if __name__ == "__main__":
    unittest.main()
