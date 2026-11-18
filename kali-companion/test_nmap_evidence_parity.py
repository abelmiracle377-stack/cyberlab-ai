"""Parity tests for browser, bridge and CLI Nmap evidence parsing."""
import tempfile
import unittest
from pathlib import Path

import cyberlab
import bridge


XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" args="nmap -n -sT --reason -p 443 192.0.2.10" start="1700000000" startstr="Tue Nov 14 22:13:20 2023">
  <scaninfo type="connect" protocol="tcp" numservices="1" services="443"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="example.test" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="https" product="nginx" version="1.24" extrainfo="test" tunnel="ssl" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1700000001" elapsed="1.0" exit="success" summary="Nmap done"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""


class NmapEvidenceParityTests(unittest.TestCase):
    def test_cli_parser_preserves_reason_service_and_completion(self):
        result = cyberlab.parse_nmap_xml_text(XML)
        self.assertEqual(result["summary"]["state_counts"]["open"], 1)
        self.assertEqual(result["summary"]["state_counts"]["closed"], 1)
        port = result["open_ports"][0]
        self.assertEqual(port["reason"], "syn-ack")
        self.assertEqual(port["reason_ttl"], "64")
        self.assertEqual(port["extra_info"], "test")
        self.assertEqual(port["method"], "probed")
        self.assertEqual(result["completion"]["finished"]["exit"], "success")
        self.assertEqual(result["evidence_status"], "completed")

    def test_bridge_parser_preserves_the_same_evidence(self):
        result = bridge.parse_report(XML.decode("utf-8"))
        self.assertEqual(result["state_summary"]["open"], 1)
        self.assertEqual(result["state_summary"]["closed"], 1)
        self.assertEqual(result["open_ports"][0]["reason"], "syn-ack")
        self.assertEqual(result["completion"]["finished"]["exit"], "success")
        self.assertEqual(result["evidence_status"], "completed")

    def test_cli_file_parser_uses_the_same_evidence_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "scan.xml"
            report.write_bytes(XML)
            result = cyberlab.parse_nmap_xml(report)
            self.assertEqual(result["scaninfo"][0]["services"], "443")
            self.assertEqual(result["completion"]["hosts"]["total"], "1")

    def test_both_parsers_reject_entity_declarations(self):
        unsafe = b'<!DOCTYPE nmaprun [<!ENTITY x "expanded">]><nmaprun>&x;</nmaprun>'
        with self.assertRaisesRegex(ValueError, "entity"):
            cyberlab.parse_nmap_xml_text(unsafe)
        with self.assertRaisesRegex(ValueError, "entity"):
            bridge.parse_report(unsafe.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
