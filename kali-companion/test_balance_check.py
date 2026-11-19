"""Tests for the optional read-only balance lookup. A stub fetcher stands in for
the explorer, so no test touches the network; only public addresses are passed.
"""
import unittest

import balance_check as bc


def blockchair_payload(address, balance, tx_count):
    return {"data": {address: {"address": {"balance": balance, "transaction_count": tx_count}}}}


class BalanceCheckTests(unittest.TestCase):
    def test_funded_and_active_are_summarised(self):
        accounts = [
            {"address": "1Afunded", "coin": "bitcoin", "path": "m/44'/0'/0'/0/0"},
            {"address": "1Bempty", "coin": "bitcoin", "path": "m/44'/0'/0'/0/1"},
        ]

        def fetcher(url):
            if "1Afunded" in url:
                return blockchair_payload("1Afunded", 123456, 4)
            return blockchair_payload("1Bempty", 0, 0)

        out = bc.check_balances(accounts, fetcher=fetcher)
        self.assertEqual(out["checked"], 2)
        self.assertEqual(out["funded_addresses"], 1)
        self.assertEqual(out["active_addresses"], 1)
        funded = next(r for r in out["results"] if r["address"] == "1Afunded")
        self.assertEqual(funded["balance"], "0.00123456")
        self.assertTrue(funded["has_activity"])

    def test_emptied_wallet_still_flagged_active(self):
        accounts = [{"address": "1Cused", "coin": "bitcoin", "path": "m/44'/0'/0'/0/0"}]
        out = bc.check_balances(accounts, fetcher=lambda url: blockchair_payload("1Cused", 0, 9))
        self.assertEqual(out["funded_addresses"], 0)
        self.assertEqual(out["active_addresses"], 1)
        self.assertTrue(out["results"][0]["has_activity"])

    def test_ethereum_wei_formatting(self):
        accounts = [{"address": "0xabc", "coin": "ethereum", "path": "m/44'/60'/0'/0/0"}]
        out = bc.check_balances(accounts, fetcher=lambda url: blockchair_payload("0xabc", 10 ** 18, 2))
        self.assertEqual(out["results"][0]["balance"], "1")

    def test_cashaddr_prefix_is_stripped_for_lookup(self):
        captured = {}

        def fetcher(url):
            captured["url"] = url
            return blockchair_payload("qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", 0, 0)

        bc.check_balances([{"address": "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
                            "coin": "bitcoincash", "path": "m/44'/145'/0'/0/0"}], fetcher=fetcher)
        self.assertIn("/bitcoin-cash/", captured["url"])
        self.assertNotIn("bitcoincash:", captured["url"])

    def test_unsupported_coin_is_marked_not_errored(self):
        out = bc.check_balances([{"address": "X", "coin": "monero", "path": "m"}],
                                fetcher=lambda url: {})
        self.assertEqual(out["results"][0]["status"], "unsupported")

    def test_fetch_error_is_contained(self):
        def boom(url):
            raise OSError("network down")
        out = bc.check_balances([{"address": "1A", "coin": "bitcoin", "path": "m"}], fetcher=boom)
        self.assertEqual(out["results"][0]["status"], "error")
        self.assertEqual(out["checked"], 1)

    def test_default_fetcher_refuses_other_hosts(self):
        with self.assertRaisesRegex(ValueError, "non-allow-listed host"):
            bc._default_fetcher("https://evil.example.com/steal")

    def test_empty_accounts_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-empty"):
            bc.check_balances([])


if __name__ == "__main__":
    unittest.main()
