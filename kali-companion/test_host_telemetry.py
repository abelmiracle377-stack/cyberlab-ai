"""Tests for the read-only SOC host-telemetry collector."""
import subprocess
import unittest

import host_telemetry as ht

SS_SAMPLE = (
    "tcp   LISTEN 0 128  0.0.0.0:22        0.0.0.0:*\n"
    "tcp   LISTEN 0 128  [::]:80           [::]:*\n"
    "udp   UNCONN 0 0    0.0.0.0:68        0.0.0.0:*\n"
    "tcp   ESTAB  0 0    10.0.0.2:51000    10.0.0.3:443\n"  # not listening
)

WHO_SAMPLE = (
    "root     pts/0        2026-11-19 14:00 (192.168.1.5)\n"
    "alex     tty1         2026-11-19 09:12\n"
)


class SsParserTests(unittest.TestCase):
    def test_parses_listening_sockets_and_ports(self):
        entries = ht.parse_ss_listening(SS_SAMPLE)
        ports = {e["port"] for e in entries}
        self.assertEqual(ports, {22, 80, 68})  # ESTAB row excluded from listeners set below
        listening_ports = {e["port"] for e in entries if e["listening"]}
        self.assertEqual(listening_ports, {22, 80})

    def test_ipv6_address_is_unbracketed(self):
        entry = [e for e in ht.parse_ss_listening(SS_SAMPLE) if e["port"] == 80][0]
        self.assertEqual(entry["address"], "::")


class WhoParserTests(unittest.TestCase):
    def test_parses_users_and_remote(self):
        sessions = ht.parse_who(WHO_SAMPLE)
        self.assertEqual(sessions[0]["user"], "root")
        self.assertEqual(sessions[0]["remote"], "192.168.1.5")
        self.assertEqual(sessions[1]["user"], "alex")
        self.assertEqual(sessions[1]["remote"], "")


class CollectTests(unittest.TestCase):
    def test_collects_and_summarises(self):
        def runner(cmd, **kwargs):
            out = SS_SAMPLE if cmd[0] == "ss" else WHO_SAMPLE
            return subprocess.CompletedProcess(cmd, 0, out, "")
        telemetry = ht.collect_security_telemetry(runner=runner, which=lambda n: "/usr/bin/" + n)
        self.assertEqual(telemetry["exposed_ports"], [22, 80])
        self.assertEqual(telemetry["session_count"], 2)
        self.assertTrue(telemetry["tools"]["ss"])

    def test_fails_soft_when_tools_absent(self):
        telemetry = ht.collect_security_telemetry(runner=subprocess.run, which=lambda n: None)
        self.assertEqual(telemetry["listening_count"], 0)
        self.assertFalse(telemetry["tools"]["ss"])
        self.assertFalse(telemetry["tools"]["who"])


if __name__ == "__main__":
    unittest.main()
