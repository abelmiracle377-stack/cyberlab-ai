"""Tests for the read-only Kali tool inventory."""
import unittest
from unittest.mock import patch

import tool_catalog


class ToolCatalogTests(unittest.TestCase):
    def test_inventory_detects_installed_tools_without_running_them(self):
        with patch.object(tool_catalog.shutil, "which", side_effect=lambda name: "/usr/bin/" + name if name == "nmap" else None):
            result = tool_catalog.inspect_tool_catalog()
        self.assertGreaterEqual(result["tool_count"], 40)
        self.assertEqual(result["installed_count"], 2)
        nmap = next(tool for category in result["categories"] for tool in category["tools"] if tool["name"] == "Nmap")
        self.assertTrue(nmap["installed"])
        self.assertIsNone(nmap["install_hint"])
        self.assertIn("no tools were executed", result["note"])
        native = next(tool for category in result["categories"] for tool in category["tools"] if tool["name"] == "CyberLab HTTP Workbench")
        self.assertTrue(native["installed"])
        self.assertEqual(native["mode"], "native_http")
        self.assertNotIn("Burp Suite", {tool["name"] for category in result["categories"] for tool in category["tools"]})

    def test_missing_tools_receive_package_install_guidance(self):
        with patch.object(tool_catalog.shutil, "which", return_value=None):
            result = tool_catalog.inspect_tool_catalog()
        nikto = next(tool for category in result["categories"] for tool in category["tools"] if tool["name"] == "Nikto")
        self.assertFalse(nikto["installed"])
        self.assertEqual(nikto["install_hint"], "sudo apt update && sudo apt install -y nikto")

    def test_dangerous_automation_is_explicitly_not_eligible(self):
        with patch.object(tool_catalog.shutil, "which", return_value="/usr/bin/tool"):
            result = tool_catalog.inspect_tool_catalog()
        by_name = {tool["name"]: tool for category in result["categories"] for tool in category["tools"]}
        self.assertEqual(by_name["CamPhish"]["mode"], "blocked")
        self.assertEqual(by_name["Hydra"]["mode"], "blocked_automation")
        self.assertEqual(by_name["Metasploit Framework"]["mode"], "safe_metadata_only")
        self.assertEqual(by_name["Nmap"]["mode"], "safe_scan")

    def test_catalog_groups_tools_by_kali_category(self):
        with patch.object(tool_catalog.shutil, "which", return_value=None):
            result = tool_catalog.inspect_tool_catalog()
        names = {category["name"] for category in result["categories"]}
        self.assertIn("Information gathering", names)
        self.assertIn("Web application analysis", names)
        self.assertIn("Forensics", names)
        self.assertIn("Reverse engineering", names)
        self.assertIn("Social engineering", names)


if __name__ == "__main__":
    unittest.main()
