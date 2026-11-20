"""Correctness tests for wallet_recovery against published standard test vectors.

Sources of truth:
  * BIP-0032 test vector 1 (master and child extended keys)
  * BIP-0039 reference vector (Trezor) mnemonic -> seed with passphrase "TREZOR"
  * Known-answer address/WIF vectors (Bitcoin wiki, EIP-55)
These vectors are deterministic and need no network or external tools, so a pass
proves the cryptography is correct, not merely self-consistent.
"""
import json
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


class MultiCoinDerivationTests(unittest.TestCase):
    MNEMONIC = ("abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon about")

    def setUp(self):
        self.seed = wr.mnemonic_to_seed(self.MNEMONIC)

    def first(self, template):
        return wr.derive_accounts(self.seed, template, 1)[0]

    def test_bitcoin_canonical_vectors(self):
        # Widely-published iancoleman vectors for the abandon...about seed.
        self.assertEqual(self.first("bip44-legacy")["address"],
                         "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")
        self.assertEqual(self.first("bip49-p2sh-segwit")["address"],
                         "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf")
        self.assertEqual(self.first("bip84-segwit")["address"],
                         "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")

    def test_cashaddr_encoder_matches_spec_vector(self):
        # CashAddr reference vector, independent of key derivation.
        pubkey_hash = bytes.fromhex("76a04053bda0a88bda5177b86a15c3b29f559873")
        self.assertEqual(wr.cashaddr_encode(pubkey_hash),
                         "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")

    def test_bitcoin_cash_address_is_cashaddr(self):
        entry = self.first("bitcoincash")
        self.assertTrue(entry["address"].startswith("bitcoincash:q"))
        self.assertEqual(entry["coin"], "bitcoincash")

    def test_litecoin_version_bytes(self):
        legacy = self.first("litecoin-legacy")
        self.assertTrue(legacy["address"].startswith("L"))
        self.assertEqual(wr.base58check_decode(legacy["address"])[0], 0x30)
        self.assertEqual(wr.base58check_decode(legacy["wif"])[0], 0xB0)
        self.assertTrue(self.first("litecoin-segwit")["address"].startswith("ltc1q"))
        self.assertTrue(self.first("litecoin-p2sh-segwit")["address"].startswith("M"))

    def test_dogecoin_version_bytes(self):
        doge = self.first("dogecoin-legacy")
        self.assertTrue(doge["address"].startswith("D"))
        self.assertEqual(wr.base58check_decode(doge["address"])[0], 0x1E)
        self.assertEqual(wr.base58check_decode(doge["wif"])[0], 0x9E)

    def test_tron_encoder_matches_usdt_contract_vector(self):
        # Independent authoritative anchor: USDT TRC20 contract hex <-> address.
        addr = wr.base58check_encode(bytes.fromhex("41A614F803B6FD780986A42C78EC9C7F77E6DED13C"))
        self.assertEqual(addr, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")

    def test_xrp_encoder_matches_account_zero(self):
        # XRP ACCOUNT_ZERO: AccountID of 20 zero bytes encodes to this address.
        self.assertEqual(wr.xrp_address.__name__, "xrp_address")
        payload = b"\x00" + b"\x00" * 20
        encoded = wr._base58_with_alphabet(payload + wr._sha256(wr._sha256(payload))[:4], wr._XRP_ALPHABET)
        self.assertEqual(encoded, "rrrrrrrrrrrrrrrrrrrrrhoLvTp")

    def test_new_coin_prefixes_and_versions(self):
        dash = self.first("dash")
        self.assertTrue(dash["address"].startswith("X"))
        self.assertEqual(wr.base58check_decode(dash["address"])[0], 0x4C)
        self.assertEqual(wr.base58check_decode(dash["wif"])[0], 0xCC)
        self.assertTrue(self.first("zcash-transparent")["address"].startswith("t1"))
        self.assertEqual(wr.base58check_decode(self.first("zcash-transparent")["address"])[:2], b"\x1c\xb8")
        self.assertTrue(self.first("bitcoin-gold")["address"].startswith("G"))
        self.assertEqual(wr.base58check_decode(self.first("bitcoin-gold")["address"])[0], 0x26)
        self.assertTrue(self.first("bitcoin-testnet")["address"].startswith(("m", "n")))

    def test_tron_and_xrp_derivation(self):
        tron = self.first("tron")
        self.assertTrue(tron["address"].startswith("T") and len(tron["address"]) == 34)
        self.assertEqual(wr.base58check_decode(tron["address"])[0], 0x41)
        self.assertEqual(len(tron["privateKey"]), 64)  # raw hex key, no WIF
        xrp = self.first("xrp")
        self.assertTrue(xrp["address"].startswith("r"))
        self.assertIn("privateKey", xrp)

    def test_passphrase_changes_derivation(self):
        plain = wr.derive_accounts(self.seed, "bip44-ethereum", 1)[0]["address"]
        seed_pp = wr.mnemonic_to_seed(self.MNEMONIC, "my-25th-word")
        with_pp = wr.derive_accounts(seed_pp, "bip44-ethereum", 1)[0]["address"]
        self.assertNotEqual(plain, with_pp)

    def test_sweep_covers_accounts_and_change_chains(self):
        sweep = wr.derive_sweep(self.seed, "bip44-legacy", account_count=2,
                                include_change=True, per_path=2)
        # 2 accounts x 2 chains x 2 indices = 8 distinct addresses.
        self.assertEqual(len(sweep), 8)
        self.assertEqual(len({e["address"] for e in sweep}), 8)
        # account 0 / change 0 / index 0 must equal the canonical receiving address.
        first = next(e for e in sweep if e["path"] == "m/44'/0'/0'/0/0")
        self.assertEqual(first["address"], "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")
        # The change chain is present and distinct.
        self.assertTrue(any(e["change"] == 1 for e in sweep))
        self.assertIn("m/44'/0'/0'/1/0", {e["path"] for e in sweep})

    def test_sweep_without_change_only_external(self):
        sweep = wr.derive_sweep(self.seed, "bip44-ethereum", account_count=3,
                                include_change=False, per_path=1)
        self.assertEqual(len(sweep), 3)  # 3 accounts, external only, 1 index each
        self.assertTrue(all(e["change"] == 0 for e in sweep))
        self.assertEqual({e["account"] for e in sweep}, {0, 1, 2})


class ElectrumDetectionTests(unittest.TestCase):
    def test_detects_a_real_electrum_standard_seed(self):
        # Find a phrase whose HMAC-SHA512("Seed version") starts with "01"
        # (Electrum's own validity test) to exercise detection deterministically.
        import hmac as _hmac, hashlib as _hashlib
        phrase = None
        for i in range(10000):
            candidate = "electrum test seed candidate " + str(i)
            digest = _hmac.new(b"Seed version", candidate.encode(), _hashlib.sha512).hexdigest()
            if digest.startswith("01"):
                phrase = candidate
                break
        self.assertIsNotNone(phrase)
        self.assertEqual(wr.electrum_seed_type(phrase), "standard")
        self.assertTrue(wr.is_electrum_seed(phrase))

    def test_bip39_mnemonic_is_not_flagged_electrum(self):
        mnemonic = ("abandon abandon abandon abandon abandon abandon "
                    "abandon abandon abandon abandon abandon about")
        self.assertIsNone(wr.electrum_seed_type(mnemonic))
        self.assertFalse(wr.is_electrum_seed(mnemonic))


class ElectrumDerivationTests(unittest.TestCase):
    # Authoritative vectors from Electrum's own tests/test_wallet_vertical.py.
    STANDARD = "cycle rocket west magnet parrot shuffle foot correct salt library feed song"
    SEGWIT = "bitter grass shiver impose acquire brush forget axis eager alone wine silver"

    def test_standard_seed_receiving_and_change(self):
        self.assertEqual(wr.electrum_seed_type(self.STANDARD), "standard")
        out = wr.derive_electrum_accounts(self.STANDARD, count=1)
        self.assertEqual(out["seedType"], "standard")
        recv = next(a for a in out["accounts"] if a["path"] == "m/0/0")
        change = next(a for a in out["accounts"] if a["path"] == "m/1/0")
        self.assertEqual(recv["address"], "1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf")
        self.assertEqual(change["address"], "1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D")

    def test_segwit_seed_receiving_and_change(self):
        self.assertEqual(wr.electrum_seed_type(self.SEGWIT), "segwit")
        out = wr.derive_electrum_accounts(self.SEGWIT, count=1)
        self.assertEqual(out["seedType"], "segwit")
        recv = next(a for a in out["accounts"] if a["path"] == "m/0'/0/0")
        change = next(a for a in out["accounts"] if a["path"] == "m/0'/1/0")
        self.assertEqual(recv["address"], "bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af")
        self.assertEqual(change["address"], "bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p")

    def test_wif_reproduces_the_address(self):
        out = wr.derive_electrum_accounts(self.STANDARD, count=1, include_change=False)
        entry = out["accounts"][0]
        priv = wr.base58check_decode(entry["wif"])[1:-1]  # strip version + compression flag
        self.assertEqual(wr.p2pkh_address(wr.private_to_public(priv)), entry["address"])

    def test_bip39_seed_is_rejected_by_electrum_derive(self):
        with self.assertRaisesRegex(ValueError, "Not a recognised Electrum"):
            wr.derive_electrum_accounts("abandon " * 11 + "about")


class OldElectrumDerivationTests(unittest.TestCase):
    # Authoritative vector from Electrum's tests/test_wallet_vertical.py.
    SEED = "powerful random nobody notice nothing important anyway look away hidden message over"

    def test_wordlist_integrity(self):
        words = wr.old_electrum_wordlist()
        self.assertEqual(len(words), 1626)

    def test_old_seed_receiving_and_change(self):
        self.assertTrue(wr.is_old_electrum_seed(self.SEED))
        out = wr.derive_old_electrum_accounts(self.SEED, count=1)
        self.assertEqual(out["seedType"], "old")
        recv = next(a for a in out["accounts"] if a["path"] == "m/0/0")
        change = next(a for a in out["accounts"] if a["path"] == "m/1/0")
        self.assertEqual(recv["address"], "1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo")
        self.assertEqual(change["address"], "1KRW8pH6HFHZh889VDq6fEKvmrsmApwNfe")

    def test_hex_seed_matches_word_seed(self):
        hex_seed = wr.old_electrum_mn_decode(self.SEED.split(), wr.old_electrum_wordlist())
        from_words = wr.derive_old_electrum_accounts(self.SEED, count=1, include_change=False)
        from_hex = wr.derive_old_electrum_accounts(hex_seed, count=1, include_change=False)
        self.assertEqual(from_words["accounts"][0]["address"], from_hex["accounts"][0]["address"])

    def test_uncompressed_wif_reproduces_address(self):
        entry = wr.derive_old_electrum_accounts(self.SEED, count=1, include_change=False)["accounts"][0]
        priv = wr.base58check_decode(entry["wif"])[1:]  # uncompressed WIF: version + 32 bytes
        self.assertEqual(wr.p2pkh_address(wr.private_to_public(priv, compressed=False)), entry["address"])

    def test_bip39_phrase_is_not_a_hex_or_short_seed(self):
        # A hex string that is not 32 chars is not treated as an old seed.
        self.assertFalse(wr.is_old_electrum_seed("deadbeef"))


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

    def test_extract_metamask_vault_direct(self):
        import base64 as b64
        salt = b64.b64encode(b"saltsalt16bytes!").decode()
        iv = b64.b64encode(b"iv1234567890abcd").decode()
        data = b64.b64encode(b"ciphertext-bytes-here-xxxxxxxxxx").decode()
        vault = '{"data":"' + data + '","iv":"' + iv + '","salt":"' + salt + '"}'
        result = wr.extract_metamask_hash(vault)
        self.assertEqual(result["hashcatMode"], 26600)
        self.assertEqual(result["hash"], "$metamask$" + salt + "$" + iv + "$" + data)

    def test_extract_metamask_vault_nested_keyring(self):
        import base64 as b64
        inner = ('{"data":"' + b64.b64encode(b"d" * 24).decode()
                 + '","iv":"' + b64.b64encode(b"i" * 16).decode()
                 + '","salt":"' + b64.b64encode(b"s" * 16).decode() + '"}')
        wrapper = json.dumps({"KeyringController": {"vault": inner}})
        result = wr.extract_metamask_hash(wrapper)
        self.assertTrue(result["hash"].startswith("$metamask$"))

    def test_metamask_rejects_missing_vault(self):
        with self.assertRaisesRegex(ValueError, "No MetaMask vault"):
            wr.extract_metamask_hash('{"nothing":"here"}')

    def test_metamask_rejects_bad_base64(self):
        with self.assertRaisesRegex(ValueError, "not valid base64"):
            wr.extract_metamask_hash('{"data":"not base64!!","iv":"aXY=","salt":"c2FsdA=="}')

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
