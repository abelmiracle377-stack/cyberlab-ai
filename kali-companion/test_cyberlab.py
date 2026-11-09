"""Unit tests for the CyberLab AI Kali companion."""
import hashlib
import importlib.util
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("cyberlab.py")
SPEC = importlib.util.spec_from_file_location("cyberlab", MODULE_PATH)
cyberlab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(cyberlab)


class CompanionTests(unittest.TestCase):

    def test_investigation_report_is_saved_locally(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cyberlab.Path, "home", return_value=Path(directory)):
                report = cyberlab.save_investigation({"status": "ok"}, "DNS intelligence")
                self.assertTrue(report.exists())
                self.assertIn("dns-intelligence", report.name)
                self.assertIn('"status": "ok"', report.read_text(encoding="utf-8"))


    def test_url_analysis_flags_http_without_visiting_url(self):
        result = cyberlab.analyze_url("http://example.test/login")
        self.assertEqual(result["normalized_host"], "example.test")
        self.assertIn("URL does not use HTTPS", result["structural_indicators"])
        self.assertIn("NOT opened", result["risk_note"])

    def test_url_analysis_rejects_non_http_scheme(self):
        with self.assertRaisesRegex(ValueError, "HTTP or HTTPS"):
            cyberlab.analyze_url("file:///etc/passwd")

    def test_public_page_parser_detects_login_form_without_submitting(self):
        parser = cyberlab._PageMetadata()
        parser.feed("<title>Example Portal</title><meta name=\"description\" content=\"Example service\"><form><input name=\"email\" type=\"email\"><input name=\"password\" type=\"password\"></form>")
        self.assertEqual(" ".join(parser.title), "Example Portal")
        self.assertEqual(parser.meta["description"], "Example service")
        self.assertEqual(parser.forms[0]["fields"][1]["type"], "password")

    def test_rdap_summary_extracts_registry_dates(self):
        data = {"events": [{"eventAction": "registration", "eventDate": "2020-01-01"}], "name": "Example Net", "country": "NG"}
        summary = cyberlab._rdap_summary(data)
        self.assertEqual(summary["registered_on"], "2020-01-01")
        self.assertEqual(summary["registrar_or_network_name"], "Example Net")
    def test_manual_assessment_is_guided_and_does_not_send_requests(self):
        answers = [
            "staging.example.test", "yes",
            "yes", "no", "no", "unknown",
            "yes", "yes", "yes", "yes", "yes", "yes", "yes", "yes",
            "yes", "yes", "unknown", "email/password", "", "Reviewed source and cookie configuration."
        ]
        with patch("builtins.input", side_effect=answers):
            result = cyberlab.manual_security_assessment()
        self.assertTrue(result["authorisation_confirmed_by_operator"])
        self.assertEqual(result["login_method"], "email/password")
        self.assertEqual(result["findings"][0]["status"], "not_detected")
        self.assertIn("No requests", result["method"])
        self.assertIn("Potential authentication bypass", result["sql_injection_explanation"]["impact"])

    def test_static_triage_hash_and_signature(self):
        payload = b"MZ" + b"sample executable content"
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            sample.write_bytes(payload)
            result = cyberlab.triage_file(sample)
        self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertIn("Windows PE", result["file_type"])
        self.assertGreaterEqual(result["entropy"], 0)
        self.assertLessEqual(result["entropy"], 8)

    def test_empty_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "empty.bin"
            sample.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "empty"):
                cyberlab.triage_file(sample)

    def test_domain_validation(self):
        self.assertEqual(cyberlab.validate_domain("Example.COM."), "example.com")
        with self.assertRaisesRegex(ValueError, "valid public domain"):
            cyberlab.validate_domain("not a domain")

    def test_private_ip_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "public global"):
            cyberlab.ip_intelligence("127.0.0.1")

    def test_invalid_ip_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "valid IPv4 or IPv6"):
            cyberlab.ip_intelligence("999.999.999.999")

    def test_nmap_xml_summary(self):
        xml = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="lab.example.test" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Example" version="1.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "scan.xml"
            report.write_bytes(xml)
            result = cyberlab.parse_nmap_xml(report)
        self.assertEqual(result["summary"]["hosts"], 1)
        self.assertEqual(result["summary"]["hosts_up"], 1)
        self.assertEqual(result["summary"]["open_ports"], 1)
        self.assertEqual(result["open_ports"][0]["port"], 443)
        self.assertEqual(result["open_ports"][0]["service"], "https")

    def test_nmap_xml_rejects_entity_declarations(self):
        xml = b'<!DOCTYPE nmaprun [<!ENTITY x "expanded">]><nmaprun>&x;</nmaprun>'
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "unsafe.xml"
            report.write_bytes(xml)
            with self.assertRaisesRegex(ValueError, "entity"):
                cyberlab.parse_nmap_xml(report)

    def test_nmap_xml_rejects_wrong_root(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "wrong.xml"
            report.write_text("<root/>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "root"):
                cyberlab.parse_nmap_xml(report)


if __name__ == "__main__":
    unittest.main()
