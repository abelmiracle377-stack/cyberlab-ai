"""Tests for the vetted Kali tool-execution layer.

An injected runner/resolver stands in for the real binaries so we can prove the
validation, consent, authorisation, exact-target confirmation and argv
construction without any tool installed. No result is fabricated: the tests feed
the runner's own output back through the parser.
"""
import subprocess
import tempfile
import unittest
from pathlib import Path

import kali_tools as kt

FAKE = lambda name: "/usr/bin/" + name


def ok_runner(stdout="done", code=0):
    def run(argv, **kwargs):
        run.argv = argv
        return subprocess.CompletedProcess(argv, code, stdout, "")
    return run


class ValidationTests(unittest.TestCase):
    def test_host_validator_accepts_ip_and_fqdn_rejects_junk(self):
        self.assertEqual(kt.v_host("93.184.216.34"), "93.184.216.34")
        self.assertEqual(kt.v_host("Example.COM."), "example.com")
        for bad in ("not a host", "http://x", "a;b", "`id`", ""):
            with self.assertRaises(ValueError):
                kt.v_host(bad)

    def test_port_spec_validator(self):
        self.assertEqual(kt.v_port_spec("80,443,8000-8100"), "80,443,8000-8100")
        for bad in ("0", "70000", "80;rm", "abc", "-5"):
            with self.assertRaises(ValueError):
                kt.v_port_spec(bad)

    def test_url_validator_rejects_credentials_and_non_http(self):
        self.assertEqual(kt.v_url("https://example.com/a"), "https://example.com/a")
        for bad in ("ftp://example.com", "https://user:pw@example.com", "file:///etc/passwd"):
            with self.assertRaises(ValueError):
                kt.v_url(bad)


class ConsentAndAuthorisationTests(unittest.TestCase):
    def test_requires_confirmation(self):
        with self.assertRaisesRegex(ValueError, "explicitly confirmed"):
            kt.run_tool("whois", {"host": "example.com"}, confirmed=False, resolve=FAKE)

    def test_unknown_tool_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown tool"):
            kt.run_tool("rm-rf", {}, confirmed=True, resolve=FAKE)

    def test_active_tool_requires_authorisation_and_exact_target(self):
        # No authorisation reference.
        with self.assertRaisesRegex(ValueError, "authorisation"):
            kt.run_tool("nmap", {"host": "example.com", "ports": "80"}, confirmed=True,
                        target_confirmation="example.com", resolve=FAKE, runner=ok_runner())
        # Wrong target confirmation.
        with self.assertRaisesRegex(ValueError, "Retype the exact target"):
            kt.run_tool("nmap", {"host": "example.com", "ports": "80"}, confirmed=True,
                        authorization_reference="TICKET-1", target_confirmation="evil.com",
                        resolve=FAKE, runner=ok_runner())

    def test_passive_tool_needs_no_authorisation(self):
        run = ok_runner("Registrant: ACME")
        result = kt.run_tool("whois", {"host": "example.com"}, confirmed=True,
                             resolve=FAKE, runner=run)
        self.assertEqual(result["status"], "completed")
        self.assertIn("ACME", result["stdout"])


class ArgvConstructionTests(unittest.TestCase):
    def test_nmap_builds_bounded_connect_scan(self):
        run = ok_runner("Nmap scan report")
        result = kt.run_tool("nmap", {"host": "93.184.216.34", "ports": "80,443"}, confirmed=True,
                             authorization_reference="ENGAGE-9", target_confirmation="93.184.216.34",
                             resolve=FAKE, runner=run)
        self.assertEqual(result["argv"][:5], ["-n", "-sT", "-sV", "--version-light", "--reason"])
        self.assertIn("93.184.216.34", run.argv)
        self.assertIn("--", run.argv)  # end-of-options guard before the target
        self.assertEqual(run.argv[0], "/usr/bin/nmap")

    def test_gobuster_requires_wordlist_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            wl = Path(tmp) / "w.txt"
            wl.write_text("admin\nlogin\n", encoding="utf-8")
            run = ok_runner("/admin (Status: 200)")
            result = kt.run_tool("gobuster-dir",
                                 {"url": "https://example.com", "wordlist": str(wl), "threads": 10},
                                 confirmed=True, authorization_reference="ENGAGE-9",
                                 target_confirmation="https://example.com", resolve=FAKE, runner=run)
            self.assertEqual(result["status"], "completed")
            self.assertIn("-w", run.argv)
            self.assertIn(str(wl), run.argv)

    def test_missing_tool_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "not installed"):
            kt.run_tool("whois", {"host": "example.com"}, confirmed=True,
                        resolve=lambda name: None)

    def test_timeout_is_reported(self):
        def timeout_runner(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 1))
        result = kt.run_tool("whois", {"host": "example.com"}, confirmed=True,
                             resolve=FAKE, runner=timeout_runner)
        self.assertEqual(result["status"], "timeout")


class ListingTests(unittest.TestCase):
    def test_list_reports_installed_flag_and_mode(self):
        listed = kt.list_tools()
        names = {t["name"] for t in listed["tools"]}
        self.assertIn("nmap", names)
        self.assertIn("whois", names)
        for tool in listed["tools"]:
            self.assertIn("installed", tool)
            self.assertIn("active", tool)


if __name__ == "__main__":
    unittest.main()
