"""Tests for the Academy CTF vulnerable lab target."""
import json
import unittest

import academy_lab as lab


class LabResponseTests(unittest.TestCase):
    def test_home_has_no_security_headers(self):
        status, headers, body = lab.build_response("GET", "/")
        self.assertEqual(status, 200)
        names = {k.lower() for k, _ in headers}
        self.assertNotIn("content-security-policy", names)
        self.assertIn("CyberLab Vulnerable Shop", body)

    def test_robots_discloses_hidden_path_and_flag(self):
        _, _, robots = lab.build_response("GET", "/robots.txt")
        self.assertIn(lab.HIDDEN_PATH, robots)
        status, _, body = lab.build_response("GET", lab.HIDDEN_PATH)
        self.assertEqual(status, 200)
        self.assertIn(lab.FLAG_RECON, body)

    def test_env_file_leaks_flag(self):
        _, _, body = lab.build_response("GET", "/.env")
        self.assertIn(lab.FLAG_ENV, body)

    def test_git_config_leaks_flag_and_head_detectable(self):
        _, _, cfg = lab.build_response("GET", "/.git/config")
        self.assertIn(lab.FLAG_GIT, cfg)
        _, _, head = lab.build_response("GET", "/.git/HEAD")
        self.assertTrue(head.strip().startswith("ref:"))

    def test_status_header_leaks_flag(self):
        status, headers, _ = lab.build_response("GET", "/api/status")
        hdr = {k.lower(): v for k, v in headers}
        self.assertEqual(hdr.get("x-flag"), lab.FLAG_HEADER)

    def test_sql_injection_only_on_quote(self):
        status_ok, _, ok = lab.build_response("GET", "/product", "id=1")
        self.assertEqual(status_ok, 200)
        self.assertNotIn(lab.FLAG_SQLI, ok)
        status_err, _, err = lab.build_response("GET", "/product", "id=1'")
        self.assertEqual(status_err, 500)
        self.assertIn(lab.FLAG_SQLI, err)

    def test_idor_reveals_other_order(self):
        _, _, mine = lab.build_response("GET", "/api/orders", "id=1001")
        self.assertNotIn(lab.FLAG_IDOR, mine)
        _, _, other = lab.build_response("GET", "/api/orders", "id=1000")
        self.assertIn(lab.FLAG_IDOR, other)

    def test_path_traversal_only_on_climb_to_flag(self):
        _, _, normal = lab.build_response("GET", "/download", "file=report.txt")
        self.assertNotIn(lab.FLAG_TRAVERSAL, normal)
        _, _, hacked = lab.build_response("GET", "/download", "file=../../secret/flag.txt")
        self.assertIn(lab.FLAG_TRAVERSAL, hacked)

    def test_admin_requires_forged_role_cookie(self):
        status, _, body = lab.build_response("GET", "/admin")
        self.assertEqual(status, 403)
        status2, _, body2 = lab.build_response("GET", "/admin", "", {"Cookie": "session=x; role=admin"})
        self.assertEqual(status2, 200)
        self.assertIn(lab.FLAG_AUTHBYPASS, body2)

    def test_jwt_alg_none_admin(self):
        import base64 as b64, json as j
        def seg(d): return b64.urlsafe_b64encode(j.dumps(d).encode()).decode().rstrip("=")
        token = seg({"alg": "none", "typ": "JWT"}) + "." + seg({"role": "admin"}) + "."
        status, _, body = lab.build_response("GET", "/api/profile", "", {"Authorization": "Bearer " + token})
        self.assertEqual(status, 200)
        self.assertIn(lab.FLAG_JWT, body)
        # A signed HS256 token (alg not none) is rejected.
        bad = seg({"alg": "HS256"}) + "." + seg({"role": "admin"}) + ".sig"
        status2, _, _ = lab.build_response("GET", "/api/profile", "", {"Authorization": "Bearer " + bad})
        self.assertEqual(status2, 401)

    def test_ssrf_internal_target(self):
        _, _, ext = lab.build_response("GET", "/fetch", "url=https://example.com")
        self.assertNotIn(lab.FLAG_SSRF, ext)
        _, _, ssrf = lab.build_response("GET", "/fetch", "url=http://169.254.169.254/latest/meta-data/")
        self.assertIn(lab.FLAG_SSRF, ssrf)

    def test_unknown_path_is_404(self):
        status, _, _ = lab.build_response("GET", "/does-not-exist")
        self.assertEqual(status, 404)

    def test_non_get_rejected(self):
        status, _, _ = lab.build_response("POST", "/")
        self.assertEqual(status, 405)

    def test_flags_catalogue_matches_challenges(self):
        ids = {c["id"] for c in lab.CHALLENGES}
        self.assertEqual(ids, set(lab.flags().keys()))


class LabServerTests(unittest.TestCase):
    def test_start_status_stop(self):
        info = lab.start_lab(0)  # port 0 -> ephemeral
        try:
            self.assertEqual(info["status"], "running")
            self.assertTrue(info["baseUrl"].startswith("http://127.0.0.1:"))
            self.assertEqual(lab.lab_status()["status"], "running")
        finally:
            self.assertEqual(lab.stop_lab()["status"], "stopped")
        self.assertEqual(lab.lab_status()["status"], "stopped")


if __name__ == "__main__":
    unittest.main()
