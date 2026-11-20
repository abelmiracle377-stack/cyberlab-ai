"""BIP38 decryption verified against the BIP38 specification's own test vectors."""
import tempfile
import unittest
from pathlib import Path

import wallet_recovery as wr

# (passphrase, encrypted key, expected WIF, compressed)
VECTORS = [
    ("TestingOneTwoThree", "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
     "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR", False),
    ("Satoshi", "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
     "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5", False),
    ("TestingOneTwoThree", "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
     "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP", True),
]

# EC-multiply vectors (prefix 6Pf / 6Pg), from the BIP38 specification.
EC_VECTORS = [
    ("TestingOneTwoThree", "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
     "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2"),
    ("Satoshi", "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
     "5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH"),
    ("MOLON LABE", "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
     "5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8"),
    ("ΜΟΛΩΝ ΛΑΒΕ",
     "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
     "5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D"),
]


class Bip38DecryptTests(unittest.TestCase):
    def test_official_vectors(self):
        for passphrase, encrypted, wif, compressed in VECTORS:
            result = wr.decrypt_bip38(encrypted, passphrase)
            self.assertEqual(result["wif"], wif)
            self.assertEqual(result["compressed"], compressed)

    def test_ec_multiply_vectors(self):
        # Covers no-lot/sequence, lot/sequence, and a Greek UTF-8 passphrase.
        for passphrase, encrypted, wif in EC_VECTORS:
            result = wr.decrypt_bip38(encrypted, passphrase)
            self.assertEqual(result["wif"], wif)

    def test_ec_multiply_wrong_passphrase_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Incorrect passphrase"):
            wr.decrypt_bip38(EC_VECTORS[0][1], "wrong")

    def test_wrong_passphrase_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Incorrect passphrase"):
            wr.decrypt_bip38(VECTORS[0][1], "not the passphrase")

    def test_non_bip38_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Not a BIP38"):
            wr.decrypt_bip38("5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR", "x")

    def test_recovered_wif_reproduces_the_address(self):
        result = wr.decrypt_bip38(VECTORS[2][1], VECTORS[2][0])
        priv = wr.base58check_decode(result["wif"])[1:-1]  # strip version + compression flag
        self.assertEqual(wr.p2pkh_address(wr.private_to_public(priv, compressed=True)), result["address"])


class Bip38CrackTests(unittest.TestCase):
    def test_crack_finds_passphrase_in_list(self):
        found = wr.crack_bip38(VECTORS[1][1], ["wrong", "nope", "Satoshi", "later"])
        self.assertEqual(found["status"], "cracked")
        self.assertEqual(found["passphrase"], "Satoshi")
        self.assertEqual(found["wif"], VECTORS[1][2])

    def test_crack_reports_exhausted(self):
        found = wr.crack_bip38(VECTORS[0][1], ["a", "b", "c"])
        self.assertEqual(found["status"], "exhausted")
        self.assertEqual(found["attempts"], 3)

    def test_crack_respects_attempt_cap(self):
        found = wr.crack_bip38(VECTORS[0][1], ["a", "b", "c", "d"], max_attempts=2)
        self.assertEqual(found["status"], "exhausted")
        self.assertEqual(found["attempts"], 2)


if __name__ == "__main__":
    unittest.main()
