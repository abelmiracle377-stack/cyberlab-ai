"""Unit tests for the CyberLab AI Kali companion."""
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("cyberlab.py")
SPEC = importlib.util.spec_from_file_location("cyberlab", MODULE_PATH)
cyberlab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(cyberlab)


class CompanionTests(unittest.TestCase):
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

    def test_oversized_file_is_rejected_before_full_read(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "oversized.bin"
            sample.write_bytes(b"x" * (cyberlab.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "10 MB limit"):
                cyberlab.triage_file(sample)

    def test_oversized_nmap_xml_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "oversized.xml"
            report.write_bytes(b" " * (cyberlab.MAX_XML_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "2 MB limit"):
                cyberlab.parse_nmap_xml(report)

    def test_domain_validation(self):
        self.assertEqual(cyberlab.validate_domain("Example.COM."), "example.com")
        with self.assertRaisesRegex(ValueError, "valid public domain"):
            cyberlab.validate_domain("not a domain")

    def test_private_ip_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "public global"):
            cyberlab.ip_intelligence("127.0.0.1")

    def test_port_scan_rejects_url_targets_before_invoking_nmap(self):
        with patch.object(cyberlab.shutil, "which") as which:
            with self.assertRaisesRegex(ValueError, "single IP address|fully-qualified"):
                cyberlab.port_scan("https://example.org", "80")
        which.assert_not_called()

    def test_port_scan_rejects_ranges_over_one_hundred_ports(self):
        with patch.object(cyberlab.shutil, "which") as which:
            with self.assertRaisesRegex(ValueError, "1–100"):
                cyberlab.port_scan("example.org", "1-101")
        which.assert_not_called()

    def test_port_scan_rejects_more_than_one_hundred_unique_ports(self):
        ports = ",".join(str(port) for port in range(1, 102))
        with patch.object(cyberlab.shutil, "which") as which:
            with self.assertRaisesRegex(ValueError, "no more than 100"):
                cyberlab.port_scan("example.org", ports)
        which.assert_not_called()

    def test_port_scan_uses_argument_vector_and_bounded_safe_flags(self):
        completed = type("Result", (), {
            "returncode": 0,
            "stdout": '<nmaprun><host><status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>',
            "stderr": "",
        })()
        with patch.object(cyberlab.shutil, "which", return_value="/usr/bin/nmap"), patch.object(
            cyberlab.subprocess, "run", return_value=completed
        ) as run:
            result = cyberlab.port_scan("example.org", "443", timeout=30)
        command = run.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertIn("-sT", command)
        self.assertIn("-sV", command)
        self.assertIn("--version-light", command)
        self.assertIn("--max-retries", command)
        self.assertIn("1", command)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertEqual(result["open_ports"][0]["port"], 443)

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
