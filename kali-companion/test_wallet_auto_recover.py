"""Routing tests for /wallet/auto-recover: the right scheme(s) for each seed.

No network is touched (balance checks are opt-in and not exercised here).
"""
import hashlib
import hmac
import unittest

import bridge
import wallet_recovery as wr


class AutoRecoverRoutingTests(unittest.TestCase):
    def test_electrum_segwit_seed_routes_to_electrum(self):
        out = bridge.wallet_auto_recover(
            {"mnemonic": "bitter grass shiver impose acquire brush forget axis eager alone wine silver"})
        self.assertEqual(out["schemes"], ["electrum-segwit"])
        self.assertTrue(any(a["address"].startswith("bc1q") for a in out["accounts"]))

    def test_electrum_standard_seed_routes_to_electrum(self):
        out = bridge.wallet_auto_recover(
            {"mnemonic": "cycle rocket west magnet parrot shuffle foot correct salt library feed song"})
        self.assertEqual(out["schemes"], ["electrum-standard"])

    def test_old_electrum_seed_is_included(self):
        # Keep the BIP39 sweep cheap (one template) — we only assert old Electrum here.
        out = bridge.wallet_auto_recover(
            {"mnemonic": "powerful random nobody notice nothing important anyway look away hidden message over",
             "count": 1, "templates": ["bip44-legacy"], "includeChange": False})
        self.assertIn("electrum-old", out["schemes"])
        self.assertTrue(any(a["scheme"] == "electrum-old"
                            and a["address"] == "1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo"
                            for a in out["accounts"]))

    def test_bip39_phrase_routes_to_bip39(self):
        out = bridge.wallet_auto_recover({"mnemonic": "abandon " * 11 + "about", "count": 1,
                                          "templates": ["bip44-legacy"], "includeChange": False})
        self.assertIn("bip39", out["schemes"])
        self.assertTrue(out["derived_count"] > 0)

    def test_2fa_electrum_seed_is_reported_unrecoverable(self):
        # Construct a phrase whose HMAC-SHA512("Seed version") starts with "101" (2fa).
        phrase = None
        for i in range(200000):
            candidate = "twofa seed probe " + str(i)
            digest = hmac.new(b"Seed version", candidate.encode(), hashlib.sha512).hexdigest()
            if digest.startswith("101"):
                phrase = candidate
                break
        self.assertIsNotNone(phrase)
        self.assertEqual(wr.electrum_seed_type(phrase), "2fa")
        out = bridge.wallet_auto_recover({"mnemonic": phrase})
        self.assertFalse(out["recoverable"])
        self.assertEqual(out["detected"], "electrum-2fa")

    def test_missing_mnemonic_rejected(self):
        with self.assertRaisesRegex(ValueError, "recovery phrase"):
            bridge.wallet_auto_recover({})

    def test_balance_check_requires_network_confirmation(self):
        with self.assertRaisesRegex(ValueError, "confirmNetwork"):
            bridge.wallet_auto_recover({"mnemonic": "abandon " * 11 + "about", "checkBalances": True})


if __name__ == "__main__":
    unittest.main()
