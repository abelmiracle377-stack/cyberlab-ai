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


class ExpandedToolTests(unittest.TestCase):
    def test_single_port_validator(self):
        self.assertEqual(kt.v_single_port(443), "443")
        for bad in (0, 70000, "abc", True):
            with self.assertRaises(ValueError):
                kt.v_single_port(bad)

    def test_search_term_rejects_command_injection_characters(self):
        self.assertEqual(kt.v_search_term("type:exploit smb"), "type:exploit smb")
        for bad in ("smb; exit", "a`id`", "a&&b", "x|y"):
            with self.assertRaises(ValueError):
                kt.v_search_term(bad)

    def test_metasploit_search_is_passive_metadata_only(self):
        run = ok_runner("Matching Modules\n...\nexploit/windows/smb/ms17_010_eternalblue")
        result = kt.run_tool("metasploit-search", {"query": "ms17-010"}, confirmed=True,
                             resolve=FAKE, runner=run)
        self.assertEqual(result["status"], "completed")
        self.assertIn("search ms17-010; exit -y", run.argv)
        self.assertEqual(run.argv[:3], ["/usr/bin/msfconsole", "-q", "-x"])

    def test_netcat_banner_passes_devnull_stdin(self):
        captured = {}

        def run(argv, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(argv, 0, "220 vsFTPd 3.0.3", "")

        result = kt.run_tool("netcat-banner", {"host": "example.com", "port": 21}, confirmed=True,
                             authorization_reference="ENG-1", target_confirmation="example.com",
                             resolve=FAKE, runner=run)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(captured.get("stdin"), subprocess.DEVNULL)

    def test_sqlmap_is_bounded_level_and_risk(self):
        run = ok_runner("sqlmap output")
        kt.run_tool("sqlmap", {"url": "https://example.com/item?id=1"}, confirmed=True,
                    authorization_reference="ENG-1", target_confirmation="https://example.com/item?id=1",
                    resolve=FAKE, runner=run)
        self.assertEqual(run.argv[run.argv.index("--level") + 1], "1")
        self.assertEqual(run.argv[run.argv.index("--risk") + 1], "1")
        self.assertIn("--batch", run.argv)

    def test_masscan_includes_rate_limit(self):
        run = ok_runner("Discovered open port 80/tcp")
        kt.run_tool("masscan", {"host": "93.184.216.34", "ports": "80,443", "rate": 1000},
                    confirmed=True, authorization_reference="ENG-1",
                    target_confirmation="93.184.216.34", resolve=FAKE, runner=run)
        self.assertEqual(run.argv[run.argv.index("--rate") + 1], "1000")

    def test_masscan_rate_bounds_enforced(self):
        with self.assertRaises(ValueError):
            kt.run_tool("masscan", {"host": "93.184.216.34", "ports": "80", "rate": 999999},
                        confirmed=True, authorization_reference="ENG-1",
                        target_confirmation="93.184.216.34", resolve=FAKE, runner=ok_runner())


    def test_ftp_anon_builds_anonymous_listing(self):
        run = ok_runner("drwxr-xr-x pub")
        kt.run_tool("ftp-anon", {"host": "ftp.example.com"}, confirmed=True,
                    authorization_reference="ENG-1", target_confirmation="ftp.example.com",
                    resolve=FAKE, runner=run)
        self.assertIn("ftp://ftp.example.com/", run.argv)
        self.assertIn("--ftp-method", run.argv)


class NewToolBatchTests(unittest.TestCase):
    def test_passive_dns_tools_need_no_authorisation(self):
        for name in ("dig", "host", "dnsenum", "sublist3r", "theharvester"):
            with self.subTest(tool=name):
                run = ok_runner("result")
                result = kt.run_tool(name, {"host": "example.com"}, confirmed=True,
                                     resolve=FAKE, runner=run)
                self.assertEqual(result["status"], "completed")

    def test_active_web_tools_require_authorisation(self):
        for name in ("wpscan", "nuclei", "wafw00f"):
            with self.subTest(tool=name):
                with self.assertRaisesRegex(ValueError, "authorisation"):
                    kt.run_tool(name, {"url": "https://example.com"}, confirmed=True,
                                target_confirmation="https://example.com",
                                resolve=FAKE, runner=ok_runner())

    def test_ffuf_appends_fuzz_keyword_and_uses_wordlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            wl = Path(tmp) / "w.txt"
            wl.write_text("admin\n", encoding="utf-8")
            run = ok_runner("admin [Status: 200]")
            kt.run_tool("ffuf", {"url": "https://example.com/", "wordlist": str(wl), "threads": 20},
                        confirmed=True, authorization_reference="ENG-1",
                        target_confirmation="https://example.com/", resolve=FAKE, runner=run)
            self.assertIn("https://example.com/FUZZ", run.argv)
            self.assertIn(str(wl), run.argv)

    def test_smb_and_ssh_tools_target_the_host(self):
        for name in ("enum4linux-ng", "smbmap", "nbtscan", "ssh-audit"):
            with self.subTest(tool=name):
                run = ok_runner("enum output")
                kt.run_tool(name, {"host": "10.0.0.5"}, confirmed=True,
                            authorization_reference="ENG-1", target_confirmation="10.0.0.5",
                            resolve=FAKE, runner=run)
                self.assertIn("10.0.0.5", run.argv)

    def test_registry_has_grown(self):
        self.assertGreaterEqual(len(kt.TOOL_SPECS), 38)

    def test_new_passive_osint_tools(self):
        for name in ("amass", "subfinder", "assetfinder", "gau"):
            with self.subTest(tool=name):
                run = ok_runner("sub.example.com")
                result = kt.run_tool(name, {"host": "example.com"}, confirmed=True,
                                     resolve=FAKE, runner=run)
                self.assertEqual(result["status"], "completed")
                self.assertIn("example.com", run.argv)

    def test_new_active_tools_require_authorisation(self):
        for name, params, target in (
            ("httpx", {"url": "https://example.com"}, "https://example.com"),
            ("naabu", {"host": "example.com"}, "example.com"),
            ("sslyze", {"host": "example.com"}, "example.com"),
            ("dalfox", {"url": "https://example.com"}, "https://example.com"),
        ):
            with self.subTest(tool=name):
                with self.assertRaisesRegex(ValueError, "authorisation"):
                    kt.run_tool(name, params, confirmed=True, target_confirmation=target,
                                resolve=FAKE, runner=ok_runner())

    def test_feroxbuster_requires_wordlist_file(self):
        with self.assertRaisesRegex(ValueError, "Wordlist"):
            kt.run_tool("feroxbuster", {"url": "https://example.com", "wordlist": "/nope", "threads": 10},
                        confirmed=True, authorization_reference="E1",
                        target_confirmation="https://example.com", resolve=FAKE, runner=ok_runner())

    def test_registry_reached_52(self):
        self.assertGreaterEqual(len(kt.TOOL_SPECS), 52)

    def test_cms_scanners_and_focused_scans_need_authorisation(self):
        for name, params, target in (
            ("joomscan", {"url": "https://example.com"}, "https://example.com"),
            ("droopescan", {"url": "https://example.com"}, "https://example.com"),
            ("nuclei-cves", {"url": "https://example.com"}, "https://example.com"),
        ):
            with self.subTest(tool=name):
                with self.assertRaisesRegex(ValueError, "authorisation"):
                    kt.run_tool(name, params, confirmed=True, target_confirmation=target,
                                resolve=FAKE, runner=ok_runner())

    def test_nuclei_cves_uses_cve_tags(self):
        run = ok_runner("[cve]")
        kt.run_tool("nuclei-cves", {"url": "https://example.com"}, confirmed=True,
                    authorization_reference="E1", target_confirmation="https://example.com",
                    resolve=FAKE, runner=run)
        self.assertEqual(run.argv[run.argv.index("-tags") + 1], "cve")

    def test_smtp_user_enum_requires_userlist_file(self):
        with self.assertRaisesRegex(ValueError, "Wordlist|file"):
            kt.run_tool("smtp-user-enum", {"host": "mail.example.com", "userlist": "/nope"},
                        confirmed=True, authorization_reference="E1",
                        target_confirmation="mail.example.com", resolve=FAKE, runner=ok_runner())

    def test_metasploit_info_is_passive_metadata(self):
        run = ok_runner("Name: MS17-010 EternalBlue")
        kt.run_tool("metasploit-info", {"module": "exploit/windows/smb/ms17_010_eternalblue"},
                    confirmed=True, resolve=FAKE, runner=run)
        self.assertIn("info exploit/windows/smb/ms17_010_eternalblue; exit -y", run.argv)

    def test_searchsploit_is_passive(self):
        run = ok_runner("EternalBlue | windows/remote/42315.py")
        result = kt.run_tool("searchsploit", {"query": "eternalblue"}, confirmed=True,
                             resolve=FAKE, runner=run)
        self.assertEqual(result["status"], "completed")

    def test_nmap_vuln_runs_vuln_scripts_with_authorisation(self):
        run = ok_runner("| vulners:")
        kt.run_tool("nmap-vuln", {"host": "10.0.0.5", "ports": "80,443"}, confirmed=True,
                    authorization_reference="E1", target_confirmation="10.0.0.5",
                    resolve=FAKE, runner=run)
        self.assertIn("--script", run.argv)
        self.assertEqual(run.argv[run.argv.index("--script") + 1], "vuln")

    def test_new_active_tools_need_authorisation(self):
        for name, params, target in (
            ("snmp-check", {"host": "10.0.0.5"}, "10.0.0.5"),
            ("arjun", {"url": "https://example.com"}, "https://example.com"),
            ("cmseek", {"url": "https://example.com"}, "https://example.com"),
            ("gospider", {"url": "https://example.com"}, "https://example.com"),
        ):
            with self.subTest(tool=name):
                with self.assertRaisesRegex(ValueError, "authorisation"):
                    kt.run_tool(name, params, confirmed=True, target_confirmation=target,
                                resolve=FAKE, runner=ok_runner())


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
