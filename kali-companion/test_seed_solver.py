"""Tests for the partial / scrambled BIP-39 seed solver.

A synthetic but structurally real 2048-word list is used, and valid mnemonics
are built from the same BIP-39 checksum math the solver checks, so the logic is
exercised fully offline without the canonical english.txt on disk.
"""
import math
import unittest

import seed_solver as ss
import wallet_recovery as wr

WORDLIST = ["w%04d" % i for i in range(2048)]


def make_valid_mnemonic(entropy: bytes):
    """Build a checksum-valid mnemonic (words + indices) from entropy bytes."""
    ent_bits = len(entropy) * 8
    checksum_len = ent_bits // 32
    checksum = wr._sha256(entropy)[0] >> (8 - checksum_len)
    value = (int.from_bytes(entropy, "big") << checksum_len) | checksum
    word_count = (ent_bits + checksum_len) // 11
    indices = [(value >> (11 * (word_count - 1 - i))) & 0x7FF for i in range(word_count)]
    return [WORDLIST[i] for i in indices], indices


class MissingWordTests(unittest.TestCase):
    def setUp(self):
        self.words, _ = make_valid_mnemonic(bytes(range(16)))  # 12-word phrase

    def test_single_blank_is_recovered(self):
        blanked = list(self.words)
        blanked[3] = "?"
        result = ss.solve_missing_words(blanked, WORDLIST)
        self.assertIn(" ".join(self.words), result["candidates"])
        self.assertTrue(all(len(c.split()) == 12 for c in result["candidates"]))

    def test_two_unknowns_with_small_candidate_sets(self):
        # Two unknown positions, each narrowed to a few possibilities: proves the
        # product search over multiple unknowns without enumerating 4M combos.
        blanked = list(self.words)
        blanked[5] = [self.words[5], "w0000", "w0001"]
        blanked[9] = [self.words[9], "w0002", "w0003"]
        result = ss.solve_slots(blanked, WORDLIST)
        self.assertIn(" ".join(self.words), result["candidates"])

    def test_known_address_pins_the_single_phrase(self):
        # Narrow the unknown position to a handful of candidates so the address
        # match (real secp256k1 derivation) runs on a few phrases, not thousands.
        blanked = list(self.words)
        blanked[2] = [self.words[2], "w0000", "w0001", "w0002", "w0005"]
        seed = wr.mnemonic_to_seed(" ".join(self.words))
        address = wr.derive_accounts(seed, "bip44-ethereum", 1)[0]["address"]
        result = ss.solve_slots(blanked, WORDLIST, match_address=address,
                                templates=["bip44-ethereum"], address_gap=1)
        self.assertEqual(result["candidates"], [" ".join(self.words)])
        self.assertEqual(result["matched_address"], address)

    def test_wrong_length_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "12/15/18/21/24|must be"):
            ss.solve_missing_words(self.words[:11], WORDLIST)

    def test_candidate_slot_list_is_searched(self):
        slots = list(self.words)
        true_word = slots[7]
        slots[7] = [true_word, "w0001", "w0002"]  # the right word plus decoys
        result = ss.solve_slots(slots, WORDLIST)
        self.assertIn(" ".join(self.words), result["candidates"])

    def test_combination_cap_is_enforced(self):
        slots = ["?"] * 12  # 2048**12 combinations
        with self.assertRaisesRegex(ValueError, "search space exceeds"):
            ss.solve_slots(slots, WORDLIST)

    def test_time_budget_is_honoured(self):
        # Two blanks (~4.2M combos, under the hard cap); a zero budget stops early.
        slots = list(self.words)
        slots[1] = slots[8] = "?"
        result = ss.solve_slots(slots, WORDLIST, time_budget=0.0)
        self.assertFalse(result["exhausted"])
        self.assertLess(result["checked"], result["combinations"])


class ScrambledOrderTests(unittest.TestCase):
    def test_identity_ordering_is_found_with_address(self):
        words, _ = make_valid_mnemonic(bytes(range(16)))
        seed = wr.mnemonic_to_seed(" ".join(words))
        address = wr.derive_accounts(seed, "bip84-segwit", 1)[0]["address"]
        result = ss.solve_scrambled_order(
            words, WORDLIST, max_permutations=math.factorial(12),
            match_address=address, templates=["bip84-segwit"], address_gap=1, max_results=1)
        self.assertEqual(result["candidates"], [" ".join(words)])
        self.assertEqual(result["checked"], 1)

    def test_full_twelve_word_scramble_is_refused(self):
        words, _ = make_valid_mnemonic(bytes(range(16)))
        with self.assertRaisesRegex(ValueError, "permutations"):
            ss.solve_scrambled_order(words, WORDLIST)

    def test_unknown_word_is_rejected(self):
        words, _ = make_valid_mnemonic(bytes(range(16)))
        words[0] = "notaword"
        with self.assertRaisesRegex(ValueError, "not in the BIP-39 list"):
            ss.solve_scrambled_order(words, WORDLIST, max_permutations=math.factorial(12))


if __name__ == "__main__":
    unittest.main()
