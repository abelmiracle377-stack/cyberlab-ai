"""Tests for tshark-based pcap analysis (parsers + injected-runner flow)."""
import subprocess
import tempfile
import unittest
from pathlib import Path

import pcap_analysis as pa

PHS_SAMPLE = """===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:100 bytes:12000
  ip                                     frames:95 bytes:11500
    tcp                                  frames:80 bytes:10000
      http                               frames:10 bytes:2000
    udp                                  frames:15 bytes:1500
===================================================================
"""

CONV_SAMPLE = """================================================================================
IPv4 Conversations
Filter:<No Filter>
                                           |       <-      |       ->      |     Total     |
                                           | Frames  Bytes | Frames  Bytes | Frames  Bytes |
10.0.0.1  <-> 10.0.0.2                          5    600       5    600      10   1200   0.0  1.0
10.0.0.3  <-> 10.0.0.4                          2    200       3    400       5    600   0.0  2.0
================================================================================
"""


class ProtocolHierarchyParserTests(unittest.TestCase):
    def test_parses_depth_frames_bytes(self):
        rows = pa.parse_protocol_hierarchy(PHS_SAMPLE)
        by_proto = {r["protocol"]: r for r in rows}
        self.assertEqual(by_proto["eth"]["depth"], 0)
        self.assertEqual(by_proto["ip"]["depth"], 1)
        self.assertEqual(by_proto["http"]["depth"], 3)
        self.assertEqual(by_proto["tcp"]["frames"], 80)
        self.assertEqual(by_proto["tcp"]["bytes"], 10000)


class ConversationParserTests(unittest.TestCase):
    def test_parses_and_sorts_conversations(self):
        conv = pa.parse_ip_conversations(CONV_SAMPLE)
        self.assertEqual(len(conv), 2)
        # Sorted by total bytes descending.
        self.assertEqual(conv[0]["endpointA"], "10.0.0.1")
        self.assertEqual(conv[0]["frames"], 10)
        self.assertEqual(conv[0]["bytes"], 1200)


class AnalyzePcapTests(unittest.TestCase):
    def test_analyze_combines_both_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "capture.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

            def runner(cmd, **kwargs):
                return subprocess.CompletedProcess(
                    cmd, 0, PHS_SAMPLE if "io,phs" in cmd else CONV_SAMPLE, "")

            result = pa.analyze_pcap(str(pcap), runner=runner, which=lambda n: "/usr/bin/" + n)
            self.assertEqual(result["total_frames"], 100)
            self.assertEqual(result["conversation_count"], 2)
            self.assertTrue(any(r["protocol"] == "http" for r in result["protocol_hierarchy"]))

    def test_rejects_non_pcap_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "notes.txt"
            bad.write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "pcap"):
                pa.analyze_pcap(str(bad), which=lambda n: "/usr/bin/" + n)

    def test_fails_closed_when_tshark_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "c.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 10)
            with self.assertRaisesRegex(ValueError, "tshark"):
                pa.analyze_pcap(str(pcap), which=lambda n: None)


if __name__ == "__main__":
    unittest.main()
