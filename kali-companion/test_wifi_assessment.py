"""Tests for the authorized Wi-Fi assessment module (no RF, injected runner)."""
import unittest

import wifi_assessment as wa

AIRODUMP_CSV = """
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:BB:CC:00:11:22, 2026-11-20 10:00:00, 2026-11-20 10:05:00, 6, 130, WPA2, CCMP, PSK, -42, 120, 0, 0.0.0.0, 9, HomeNet,
DD:EE:FF:33:44:55, 2026-11-20 10:00:00, 2026-11-20 10:05:00, 11, 54, OPN, , , -70, 60, 0, 0.0.0.0, 7, FreeWiFi,
11:22:33:44:55:66, 2026-11-20 10:00:00, 2026-11-20 10:05:00, 1, 54, WEP, WEP, , -80, 30, 0, 0.0.0.0, 6, OldAP,
99:88:77:66:55:44, 2026-11-20 10:00:00, 2026-11-20 10:05:00, 36, 866, WPA3, CCMP, SAE, -50, 90, 0, 0.0.0.0, 8, SecureNet,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
A0:A1:A2:A3:A4:A5, 2026-11-20 10:01:00, 2026-11-20 10:05:00, -60, 500, AA:BB:CC:00:11:22,
"""


class FakeProc:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.returncode = 0


class ParseAuditTests(unittest.TestCase):
    def test_parse_airodump_csv(self):
        aps = wa.parse_airodump_csv(AIRODUMP_CSV)
        self.assertEqual(len(aps), 4)  # stops at Station section
        essids = {a["essid"] for a in aps}
        self.assertEqual(essids, {"HomeNet", "FreeWiFi", "OldAP", "SecureNet"})

    def test_audit_flags_open_and_wep_critical(self):
        audit = wa.audit_networks(wa.parse_airodump_csv(AIRODUMP_CSV))
        sev = {f["essid"]: f["severity"] for f in audit["findings"]}
        self.assertEqual(sev["FreeWiFi"], "critical")   # open
        self.assertEqual(sev["OldAP"], "critical")      # WEP
        self.assertEqual(sev["SecureNet"], "info")      # WPA3
        self.assertEqual(sev["HomeNet"], "info")        # WPA2
        # critical findings sort first
        self.assertEqual(audit["findings"][0]["severity"], "critical")

    def test_posture_wpa1_is_high(self):
        sev, label, _ = wa._posture("WPA", "PSK")
        self.assertEqual(sev, "high")

    def test_list_interfaces_parses_iw(self):
        iw = "phy#0\n\tInterface wlan0mon\n\t\ttype monitor\n\tInterface wlan0\n\t\ttype managed\n"
        out = wa.list_interfaces(runner=lambda *a, **k: FakeProc(iw))
        self.assertEqual(out, [
            {"interface": "wlan0mon", "type": "monitor"},
            {"interface": "wlan0", "type": "managed"},
        ])


class CrackGateTests(unittest.TestCase):
    def test_crack_requires_authorization(self):
        with self.assertRaises(ValueError):
            wa.crack_capture({"capturePath": "/tmp/x.cap", "wordlistPath": "/tmp/w.txt"})

    def test_crack_requires_existing_files(self):
        with self.assertRaises(ValueError):
            wa.crack_capture({"authorizationConfirmed": True, "confirmRun": True,
                              "authorizationReference": "LAB-1", "capturePath": "/no/such.cap",
                              "wordlistPath": "/no/such.txt"})

    def test_scan_rejects_bad_interface(self):
        with self.assertRaises(ValueError):
            wa.scan("wlan0; rm -rf /", 10)


if __name__ == "__main__":
    unittest.main()
