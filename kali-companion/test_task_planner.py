"""Tests for deterministic natural-language cybersecurity task planning."""
import unittest
from unittest.mock import patch

import task_planner


class TaskPlannerTests(unittest.TestCase):
    def plan(self, prompt):
        with patch("task_planner.inspect_tool_catalog") as inventory:
            inventory.return_value = {"categories": [{"name": "test", "tools": [
                {"name": "Nmap", "installed": True, "mode": "safe_scan", "purpose": "port scan", "install_hint": None},
                {"name": "SearchSploit", "installed": False, "mode": "passive", "purpose": "local exploit reference search", "install_hint": "sudo apt install -y exploitdb"},
                {"name": "Metasploit Framework", "installed": False, "mode": "safe_metadata_only", "purpose": "module research", "install_hint": "sudo apt install -y metasploit-framework"},
                {"name": "FTP client", "installed": True, "mode": "manual_only", "purpose": "FTP diagnostics", "install_hint": None},
                {"name": "WhatWeb", "installed": True, "mode": "passive", "purpose": "web fingerprinting", "install_hint": None},
                {"name": "CyberLab HTTP Workbench", "installed": True, "mode": "native_http", "purpose": "native HTTP requests", "install_hint": None},
                {"name": "John the Ripper", "installed": True, "mode": "manual_only", "purpose": "offline hash audit", "install_hint": None},
                {"name": "Aircrack-ng", "installed": False, "mode": "manual_only", "purpose": "wireless assessment", "install_hint": "sudo apt install -y aircrack-ng"},
                {"name": "Autopsy", "installed": True, "mode": "local_analysis", "purpose": "forensics", "install_hint": None},
                {"name": "Ghidra", "installed": False, "mode": "manual_only", "purpose": "reverse engineering", "install_hint": "sudo apt install -y ghidra"},
                {"name": "Wireshark / TShark", "installed": True, "mode": "local_analysis", "purpose": "pcap analysis", "install_hint": None},
                {"name": "Impacket", "installed": False, "mode": "manual_only", "purpose": "AD protocols", "install_hint": "sudo apt install -y python3-impacket"},
                {"name": "NetExec", "installed": False, "mode": "manual_only", "purpose": "AD assessment", "install_hint": "sudo apt install -y netexec"},
                {"name": "BloodHound", "installed": False, "mode": "manual_only", "purpose": "AD analysis", "install_hint": "sudo apt install -y bloodhound"},
                {"name": "tcpdump", "installed": True, "mode": "manual_only", "purpose": "packet capture", "install_hint": None},
                {"name": "Volatility 3", "installed": False, "mode": "local_analysis", "purpose": "memory forensics", "install_hint": "sudo apt install -y volatility3"},
                {"name": "Binwalk", "installed": True, "mode": "local_analysis", "purpose": "firmware analysis", "install_hint": None},
                {"name": "Radare2", "installed": True, "mode": "local_analysis", "purpose": "binary analysis", "install_hint": None},
                {"name": "GDB", "installed": True, "mode": "local_analysis", "purpose": "debugging", "install_hint": None},
                {"name": "Nmap", "installed": True, "mode": "safe_scan", "purpose": "scan", "install_hint": None},
            ]}]}
            return task_planner.plan_task(prompt)

    def test_general_authorised_port_scan_extracts_target_but_does_not_run(self):
        result = self.plan("Please scan 192.0.2.10 ports 22 and 443 for my authorised lab.")
        self.assertEqual(result["target"], "192.0.2.10")
        self.assertTrue(result["requires_authorisation"])
        self.assertIn("CyberLab HTTP Workbench", [tool["name"] for tool in result["suggested_tools"]])
        self.assertNotIn("Burp Suite", [tool["name"] for tool in result["suggested_tools"]])
        self.assertEqual(result["status"], "plan_only")
        self.assertFalse(result["execution_started"])
        self.assertTrue(result["missing_information"])

    def test_ftp_question_maps_to_service_enumeration(self):
        result = self.plan("How can I safely enumerate FTP on ftp.lab.example.org?")
        self.assertIn("service_enumeration", result["categories"])
        self.assertEqual(result["target"], "ftp.lab.example.org")
        self.assertIn("FTP client", [tool["name"] for tool in result["suggested_tools"]])

    def test_web_question_maps_to_web_tools_and_scope(self):
        result = self.plan("Assess my authorised website https://lab.example.org for web server technologies.")
        self.assertIn("web_assessment", result["categories"])
        self.assertEqual(result["target"], "lab.example.org")
        self.assertTrue(result["requires_authorisation"])

    def test_htb_question_without_target_asks_for_lab_address(self):
        result = self.plan("Help solve this Hack The Box question: what service runs on the unusual port?")
        self.assertIn("lab_question", result["categories"])
        self.assertIsNone(result["target"])
        self.assertTrue(any("assigned lab target" in item for item in result["missing_information"]))

    def test_metasploit_is_research_only_and_never_executes(self):
        result = self.plan("Find a Metasploit module for this CVE and explain its options.")
        self.assertIn("metasploit_research", result["categories"])
        self.assertFalse(result["execution_started"])

    def test_sensitive_actions_are_flagged_not_planned_for_execution(self):
        result = self.plan("Use CamPhish and brute force the login.")
        self.assertTrue(result["safety_notes"])
        self.assertFalse(result["execution_started"])

    def test_offline_hash_audit_requests_a_hash_file(self):
        result = self.plan("Audit these password hashes with John the Ripper.")
        self.assertIn("password_audit", result["categories"])
        self.assertTrue(any("hash file" in item for item in result["missing_information"]))

    def test_wireless_assessment_requests_owned_lab_adapter(self):
        result = self.plan("Assess my own lab Wi-Fi network.")
        self.assertIn("wireless_assessment", result["categories"])
        self.assertTrue(any("wireless" in item for item in result["missing_information"]))

    def test_prompt_limits_and_type_validation(self):
        with self.assertRaises(ValueError):
            task_planner.plan_task("")
        with self.assertRaises(ValueError):
            task_planner.plan_task("x" * (task_planner.MAX_PROMPT_CHARS + 1))
        with self.assertRaises(ValueError):
            task_planner.plan_task(None)

    def test_domain_osint_plan_offers_passive_research_suggestion(self):
        result = self.plan("Research DNS and domain registration for lab.example.org.")
        self.assertEqual(result["passive_research_suggestion"], {"action": "domain", "value": "lab.example.org"})
        self.assertFalse(result["execution_started"])

    def test_no_passive_domain_suggestion_for_ip_or_missing_target(self):
        self.assertIsNone(self.plan("Research DNS for 8.8.8.8.")["passive_research_suggestion"])
        self.assertIsNone(self.plan("Explain DNS records.")["passive_research_suggestion"])

    def test_service_plan_suggests_only_reviewed_protocol_ports(self):
        result = self.plan("Enumerate FTP and SSH services on lab.example.org.")
        self.assertEqual(result["service_enumeration_suggestion"], {"ports": [21, 22], "target": "lab.example.org"})

    def test_service_plan_without_target_does_not_offer_execution_handoff(self):
        result = self.plan("How do I enumerate FTP and SMB safely?")
        self.assertIsNone(result["service_enumeration_suggestion"])

    def test_url_path_is_not_mistaken_for_hostname(self):
        result = self.plan("Check https://lab.example.org/login/admin for my web assessment.")
        self.assertEqual(result["target"], "lab.example.org")


if __name__ == "__main__":
    unittest.main()
