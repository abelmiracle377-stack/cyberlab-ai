"""Tests for authorized active Wi-Fi testing (no radio — recording runner)."""
import unittest

import wifi_authorized as wz


class RecProc:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.returncode = 0


class Recorder:
    """A runner that records the argv of each call and returns canned stdout."""
    def __init__(self, stdout=""):
        self.calls = []
        self.stdout = stdout

    def __call__(self, args, capture_output=True, text=True, timeout=None):
        self.calls.append(list(args))
        return RecProc(self.stdout)


AUTH = {"authorizationConfirmed": True, "confirmRun": True, "authorizationReference": "ENG-WIFI-1"}


class AuthGateTests(unittest.TestCase):
    def test_every_active_op_requires_authorization(self):
        for fn, payload in [
            (wz.deauth, {"interface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:FF"}),
            (wz.capture_handshake, {"interface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:FF", "channel": "6"}),
            (wz.capture_pmkid, {"interface": "wlan0mon"}),
            (wz.wps_attack, {"interface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:FF"}),
            (wz.auto_audit, {"interface": "wlan0mon"}),
            (wz.crack_wpa, {"capturePath": "/tmp/a.cap", "wordlistPath": "/tmp/w.txt"}),
        ]:
            with self.assertRaises(ValueError):
                fn(payload, runner=Recorder())


class CommandTests(unittest.TestCase):
    def test_deauth_is_targeted_and_bounded(self):
        rec = Recorder("Sending DeAuth")
        out = wz.deauth({**AUTH, "interface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:FF", "count": 5}, runner=rec)
        self.assertEqual(out["status"], "completed")
        self.assertEqual(rec.calls[0], ["aireplay-ng", "--deauth", "5", "-a", "AA:BB:CC:DD:EE:FF", "wlan0mon"])
        with self.assertRaises(ValueError):  # count over the cap
            wz.deauth({**AUTH, "interface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:FF", "count": 999}, runner=rec)

    def test_deauth_rejects_bad_bssid(self):
        with self.assertRaises(ValueError):
            wz.deauth({**AUTH, "interface": "wlan0mon", "bssid": "not-a-mac"}, runner=Recorder())

    def test_wps_pixie_dust_default(self):
        rec = Recorder("WPS PIN: '12345670'\nWPA PSK: 'hunter2password'")
        out = wz.wps_attack({**AUTH, "interface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:FF"}, runner=rec)
        self.assertEqual(rec.calls[0][0], "reaver")
        self.assertIn("-K", rec.calls[0])
        self.assertEqual(out["wpsPin"], "12345670")

    def test_enable_monitor(self):
        rec = Recorder("monitor mode enabled on wlan0mon")
        out = wz.enable_monitor("wlan0", runner=rec)
        self.assertEqual(rec.calls[0], ["airmon-ng", "start", "wlan0"])
        self.assertEqual(out["status"], "ok")

    def test_capture_handshake_builds_airodump(self):
        rec = Recorder("")
        out = wz.capture_handshake({**AUTH, "interface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:FF",
                                    "channel": "6", "seconds": 20}, runner=rec)
        cap = next(c for c in rec.calls if "airodump-ng" in c)
        self.assertIn("--bssid", cap)
        self.assertIn("AA:BB:CC:DD:EE:FF", cap)
        self.assertEqual(out["status"], "completed")

    def test_iface_injection_blocked(self):
        with self.assertRaises(ValueError):
            wz.enable_monitor("wlan0; rm -rf /", runner=Recorder())


class CrackUploadTests(unittest.TestCase):
    def _wordlist(self):
        import tempfile
        fh = tempfile.NamedTemporaryFile(prefix="wl_", suffix=".txt", delete=False)
        fh.write(b"password\nhunter2\n")
        fh.close()
        self.addCleanup(lambda: __import__("os").remove(fh.name))
        return fh.name

    def test_upload_requires_authorization(self):
        with self.assertRaises(ValueError):
            wz.crack_upload({"captureBase64": "AAAA", "wordlistPath": "/tmp/w"})

    def test_upload_rejects_bad_base64(self):
        with self.assertRaises(ValueError):
            wz.crack_upload({**AUTH, "captureBase64": "not base64!!!", "wordlistPath": self._wordlist()})

    def test_upload_rejects_oversize(self):
        import base64 as b64
        big = b64.b64encode(b"A" * (wz.MAX_UPLOAD_BYTES + 1)).decode()
        with self.assertRaises(ValueError):
            wz.crack_upload({**AUTH, "captureBase64": big, "wordlistPath": self._wordlist()})

    def test_upload_decodes_and_cracks(self):
        import base64 as b64
        rec = Recorder("KEY FOUND! [ hunter2 ]")
        cap = b64.b64encode(b"fake-handshake-bytes").decode()
        out = wz.crack_upload({**AUTH, "captureBase64": cap, "captureName": "h.cap",
                               "wordlistPath": self._wordlist(), "tool": "aircrack"}, runner=rec)
        self.assertTrue(out["keyFound"])
        self.assertEqual(out["key"], "hunter2")
        self.assertEqual(out["captureName"], "h.cap")
        # aircrack-ng was run against the written temp capture file
        self.assertEqual(rec.calls[0][0], "aircrack-ng")


if __name__ == "__main__":
    unittest.main()
