"""Correctness tests for wallet_recovery against published standard test vectors.

Sources of truth:
  * BIP-0032 test vector 1 (master and child extended keys)
  * BIP-0039 reference vector (Trezor) mnemonic -> seed with passphrase "TREZOR"
  * Known-answer address/WIF vectors (Bitcoin wiki, EIP-55)
These vectors are deterministic and need no network or external tools, so a pass
proves the cryptography is correct, not merely self-consistent.
"""
import unittest

import wallet_recovery as wr


class Secp256k1Tests(unittest.TestCase):
    def test_generator_times_one_is_g(self):
        self.assertEqual(wr._point_mul(1), wr._G)

    def test_known_private_key_to_address(self):
        # Private key 0x18e1...: standard Bitcoin wiki example.
        priv = (0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725).to_bytes(32, "big")
        pub = wr.private_to_public(priv, compressed=False)
        self.assertEqual(wr.p2pkh_address(pub), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")


class Bip32Vector1Tests(unittest.TestCase):
    """BIP-0032 test vector 1, seed 000102...0f."""

    def setUp(self):
        self.seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        self.master = wr.HDKey.from_seed(self.seed)

    def test_master_keys(self):
        self.assertEqual(
            self.master.xprv(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        self.assertEqual(
            self.master.xpub(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")

    def test_hardened_child_m0h(self):
        child = self.master.derive_path("m/0'")
        self.assertEqual(
            child.xprv(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        self.assertEqual(
            child.xpub(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

    def test_deep_path_m0h_1_2h_2_1000000000(self):
        child = self.master.derive_path("m/0'/1/2'/2/1000000000")
        self.assertEqual(
            child.xprv(),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")


class Bip39Tests(unittest.TestCase):
    def test_trezor_vector_seed(self):
        mnemonic = ("abandon abandon abandon abandon abandon abandon "
                    "abandon abandon abandon abandon abandon about")
        seed = wr.mnemonic_to_seed(mnemonic, "TREZOR")
        self.assertEqual(
            seed.hex(),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
            "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")

    def test_mnemonic_to_ethereum_address(self):
        # The canonical, widely-published first Ethereum address (m/44'/60'/0'/0/0)
        # for the all-"abandon ... about" test mnemonic with no passphrase.
        mnemonic = ("abandon abandon abandon abandon abandon abandon "
                    "abandon abandon abandon abandon abandon about")
        seed = wr.mnemonic_to_seed(mnemonic)
        eth = wr.derive_accounts(seed, "bip44-ethereum", 1)[0]
        self.assertEqual(eth["address"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
        # The returned private key must itself reproduce the address.
        priv = bytes.fromhex(eth["privateKey"][2:])
        self.assertEqual(wr.ethereum_address(wr.private_to_public(priv, compressed=False)), eth["address"])

    def test_validate_mnemonic_with_synthetic_wordlist(self):
        # Checksum logic is validated without the real wordlist by constructing a
        # 2048-word list and a matching 12-word mnemonic for entropy 0x00..00.
        words = ["w%04d" % i for i in range(2048)]
        entropy = bytes(16)
        checksum = wr._sha256(entropy)[0] >> 4  # 4 checksum bits for 128-bit entropy
        indexes = [0] * 11 + [checksum]  # 11 zero groups + checksum group
        mnemonic = " ".join(words[i] for i in indexes)
        self.assertTrue(wr.validate_mnemonic(mnemonic, words))
        bad = " ".join(words[i] for i in ([0] * 11 + [(checksum + 1) % 2048]))
        self.assertFalse(wr.validate_mnemonic(bad, words))


class AddressAndWifTests(unittest.TestCase):
    def test_wif_round_trip(self):
        priv = bytes.fromhex("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
        wif = wr.wif_encode(priv, compressed=False)
        self.assertEqual(wif, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        self.assertEqual(wr.base58check_decode(wif)[1:], priv)

    def test_ethereum_eip55_checksum(self):
        priv = bytes.fromhex("4646464646464646464646464646464646464646464646464646464646464646")
        pub = wr.private_to_public(priv, compressed=False)
        self.assertEqual(wr.ethereum_address(pub), "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F")

    def test_keccak256_empty(self):
        self.assertEqual(
            wr.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_bech32_segwit_address(self):
        # Known P2WPKH for the compressed pubkey of private key = 1.
        pub = wr.private_to_public((1).to_bytes(32, "big"), compressed=True)
        addr = wr.p2wpkh_address(pub)
        self.assertTrue(addr.startswith("bc1q"))
        self.assertEqual(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")


class HashExtractionTests(unittest.TestCase):
    def test_extract_scrypt_keystore(self):
        keystore = (
            '{"version":3,"crypto":{"kdf":"scrypt","ciphertext":"' + "aa" * 32 + '",'
            '"mac":"' + "bb" * 32 + '","kdfparams":{"n":262144,"r":8,"p":1,"salt":"' + "cc" * 16 + '"}}}')
        result = wr.extract_keystore_hash(keystore)
        self.assertEqual(result["hashcatMode"], 15700)
        self.assertTrue(result["hash"].startswith("$ethereum$s*262144*8*1*"))

    def test_extract_pbkdf2_keystore(self):
        keystore = (
            '{"version":3,"crypto":{"kdf":"pbkdf2","ciphertext":"' + "aa" * 32 + '",'
            '"mac":"' + "bb" * 32 + '","kdfparams":{"c":262144,"salt":"' + "cc" * 16 + '"}}}')
        result = wr.extract_keystore_hash(keystore)
        self.assertEqual(result["hashcatMode"], 16300)
        self.assertTrue(result["hash"].startswith("$ethereum$p*262144*"))

    def test_rejects_non_v3_keystore(self):
        with self.assertRaisesRegex(ValueError, "version 3"):
            wr.extract_keystore_hash('{"version":1}')

    def test_extract_wallet_dat_master_key(self):
        encrypted = bytes(range(48))
        salt = bytes.fromhex("1122334455667788")
        record = (b"\x04mkey\x01\x00\x00\x00"
                  + bytes([48]) + encrypted
                  + bytes([8]) + salt
                  + bytes([0])
                  + (50000).to_bytes(4, "little"))
        blob = b"\x00" * 100 + record + b"\xff" * 20
        result = wr.extract_wallet_dat_hash(blob)
        self.assertEqual(result["hashcatMode"], 11300)
        self.assertEqual(result["iterations"], 50000)
        self.assertIn("$bitcoin$96$" + encrypted.hex() + "$16$" + salt.hex() + "$50000$", result["hash"])

    def test_wallet_dat_without_mkey_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no encrypted master key|No encrypted master key"):
            wr.extract_wallet_dat_hash(b"\x00" * 200)


if __name__ == "__main__":
    unittest.main()
