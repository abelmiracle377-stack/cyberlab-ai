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


class SystemTelemetryTests(unittest.TestCase):
    def test_meminfo_and_loadavg_parse(self):
        mem = ht.parse_meminfo("MemTotal:  8000000 kB\nMemAvailable: 2000000 kB\n")
        self.assertEqual(mem["total_bytes"], 8000000 * 1024)
        self.assertEqual(mem["used_bytes"], 6000000 * 1024)
        self.assertEqual(mem["used_percent"], 75.0)
        self.assertEqual(ht.parse_loadavg("0.50 0.30 0.10 1/200 1234")["5m"], 0.30)

    def test_df_parse(self):
        rows = ht.parse_df("Filesystem 1B-blocks Used Available Capacity Mounted\n"
                           "/dev/sda1 1000 400 600 40% /\n")
        self.assertEqual(rows[0]["mount"], "/")
        self.assertEqual(rows[0]["used_percent"], 40.0)

    def test_last_extracts_source_ip(self):
        rows = ht.parse_last("alice pts/0 10.0.0.5 Wed Nov 19 10:00 still logged in\n"
                             "root tty1 Wed Nov 19 09:00\n"
                             "wtmp begins ...\n")
        self.assertEqual(rows[0]["from"], "10.0.0.5")
        self.assertEqual(rows[1]["from"], "")  # local login, no source

    def test_collect_uses_injected_readers(self):
        files = {
            "/proc/meminfo": "MemTotal: 4000 kB\nMemAvailable: 1000 kB\n",
            "/proc/uptime": "12345.6 0.0",
            "/proc/loadavg": "0.1 0.2 0.3 1/1 1",
            "/etc/os-release": 'NAME="CyberLab AI OS"\nVERSION_ID=1.0\nID=cyberlab\n',
            "/proc/sys/kernel/osrelease": "6.1.0-cyberlab\n",
        }

        def fake_runner(argv, **kwargs):
            if argv[0] == "df":
                return subprocess.CompletedProcess(argv, 0, "H b u a c m\n/dev/sda1 100 50 50 50% /\n", "")
            if argv[0] == "last":
                return subprocess.CompletedProcess(argv, 0, "alice pts/0 10.0.0.5 Wed\n", "")
            if argv[0] == "lastb":
                return subprocess.CompletedProcess(argv, 1, "", "lastb: permission denied")
            return subprocess.CompletedProcess(argv, 0, "", "")

        out = ht.collect_system_telemetry(runner=fake_runner, which=lambda n: "/usr/bin/" + n,
                                          read_file=lambda p: files.get(p, ""))
        self.assertEqual(out["os"]["name"], "CyberLab AI OS")
        self.assertEqual(out["kernel"], "6.1.0-cyberlab")
        self.assertEqual(out["uptime_seconds"], 12345)
        self.assertEqual(out["memory"]["used_percent"], 75.0)
        self.assertEqual(out["recent_login_count"], 1)
        # lastb returned permission-denied: reported as needing root, not crashed.
        self.assertTrue(out["failed_logins_need_root"])
        self.assertEqual(out["failed_login_count"], 0)


if __name__ == "__main__":
    unittest.main()
