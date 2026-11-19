"""AES-256 core verified against the FIPS-197 appendix C.3 test vector."""
import unittest

import aes

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
PLAIN = bytes.fromhex("00112233445566778899aabbccddeeff")
CIPHER = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")


class AesVectorTests(unittest.TestCase):
    def test_fips197_encrypt(self):
        self.assertEqual(aes.encrypt_block(PLAIN, KEY), CIPHER)

    def test_fips197_decrypt(self):
        self.assertEqual(aes.decrypt_block(CIPHER, KEY), PLAIN)

    def test_roundtrip(self):
        self.assertEqual(aes.decrypt_block(aes.encrypt_block(PLAIN, KEY), KEY), PLAIN)

    def test_rejects_bad_sizes(self):
        with self.assertRaises(ValueError):
            aes.decrypt_block(b"short", KEY)
        with self.assertRaises(ValueError):
            aes.encrypt_block(PLAIN, b"shortkey")


if __name__ == "__main__":
    unittest.main()
