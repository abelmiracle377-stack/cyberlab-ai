"""Tests for the read-only plist forensic parser (binary + XML, bounded output)."""
import os
import plistlib
import tempfile
import unittest

import plist_forensics as pf


def write_plist(directory, name, data, fmt):
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        plistlib.dump(data, handle, fmt=fmt)
    return path


SAMPLE = {"Name": "Safari", "count": 42, "flag": True,
          "History": [{"url": "https://example.com", "visits": 3}],
          "Blob": b"\x00\x01\x02\x03"}


class PlistParserTests(unittest.TestCase):
    def test_xml_and_binary_both_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml = write_plist(tmp, "a.plist", SAMPLE, plistlib.FMT_XML)
            binary = write_plist(tmp, "b.plist", SAMPLE, plistlib.FMT_BINARY)
            rx = pf.analyze_plist(xml)
            rb = pf.analyze_plist(binary)
            self.assertEqual(rx["format"], "xml")
            self.assertEqual(rb["format"], "binary")
            self.assertEqual(rx["top_level_type"], "dict")
            self.assertIn("Name", rx["top_level_keys"])
            self.assertEqual(rx["content"]["Name"], "Safari")
            self.assertEqual(rx["content"]["History"][0]["url"], "https://example.com")

    def test_bytes_become_data_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_plist(tmp, "c.plist", SAMPLE, plistlib.FMT_BINARY)
            out = pf.analyze_plist(path)
            self.assertEqual(out["content"]["Blob"], {"_type": "data", "length": 4, "hex_prefix": "00010203"})

    def test_long_string_is_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_plist(tmp, "d.plist", {"big": "x" * 5000}, plistlib.FMT_XML)
            out = pf.analyze_plist(path)
            self.assertTrue(out["content"]["big"].endswith("…"))
            self.assertLessEqual(len(out["content"]["big"]), pf.MAX_STRING + 1)

    def test_deep_nesting_is_bounded(self):
        node = {"leaf": 1}
        for _ in range(20):
            node = {"child": node}
        with tempfile.TemporaryDirectory() as tmp:
            path = write_plist(tmp, "e.plist", node, plistlib.FMT_XML)
            out = pf.analyze_plist(path)
            text = repr(out["content"])
            self.assertIn("max depth reached", text)

    def test_missing_and_malformed(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            pf.analyze_plist("/no/such/file.plist")
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.plist")
            with open(bad, "wb") as handle:
                handle.write(b"not a plist at all")
            with self.assertRaisesRegex(ValueError, "Could not parse"):
                pf.analyze_plist(bad)


if __name__ == "__main__":
    unittest.main()
