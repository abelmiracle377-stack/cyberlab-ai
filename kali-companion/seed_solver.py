"""Reconstruct a BIP-39 mnemonic that is incomplete or out of order.

Everything here is offline and deterministic. The solver only ever returns
candidate phrases that pass the BIP-39 checksum; when a known address is
supplied it narrows the result to the phrase whose derivation matches it. No
phrase is fabricated and nothing leaves the machine.

The public functions take a verified 2048-word list (the caller loads it with
wallet_recovery.load_wordlist, which checks its SHA-256). This keeps the search
logic pure and fully testable without the canonical file on disk.
"""
from __future__ import annotations

import math
import time
import unicodedata
from itertools import permutations, product

import wallet_recovery as wr

# Tokens a user might type for a word they cannot remember.
BLANK_MARKERS = {"", "?", "??", "???", "????", "_", "__", "___", "____",
                 "*", "**", "x", "xx", "...", "…", "-", "--"}
VALID_LENGTHS = (12, 15, 18, 21, 24)
DEFAULT_TIME_BUDGET = 30
DEFAULT_MAX_RESULTS = 200
# Refuse hopeless brute searches up front rather than hanging.
MAX_COMBINATIONS = 50_000_000


def _wordlist_index(wordlist: list[str]) -> dict:
    if len(wordlist) != 2048:
        raise ValueError("A BIP-39 wordlist must contain exactly 2048 words.")
    return {word: position for position, word in enumerate(wordlist)}


def _normalize(token: str) -> str:
    return unicodedata.normalize("NFKD", str(token).strip().lower())


def _checksum_ok(indices) -> bool:
    """True when the word indices form a valid BIP-39 checksum."""
    count = len(indices)
    total_bits = count * 11
    checksum_len = total_bits // 33
    value = 0
    for index in indices:
        value = (value << 11) | index
    entropy_int = value >> checksum_len
    checksum_int = value & ((1 << checksum_len) - 1)
    entropy_bytes = entropy_int.to_bytes((total_bits - checksum_len) // 8, "big")
    expected = wr._sha256(entropy_bytes)[0] >> (8 - checksum_len)
    return checksum_int == expected


def phrase_matches_address(phrase: str, address: str, templates: list[str] | None = None,
                           gap: int = 5, passphrase: str = "") -> bool:
    """True when any derived receiving address for `phrase` equals `address`."""
    templates = templates or list(wr.ACCOUNT_TEMPLATES.keys())
    seed = wr.mnemonic_to_seed(phrase, passphrase)
    target = address.strip()
    target_lower = target.lower()
    for template in templates:
        for entry in wr.derive_accounts(seed, template, gap):
            derived = entry["address"]
            if derived == target or derived.lower() == target_lower:
                return True
    return False


def solve_slots(slots: list, wordlist: list[str], *, time_budget: float = DEFAULT_TIME_BUDGET,
                max_results: int = DEFAULT_MAX_RESULTS, match_address: str | None = None,
                templates: list[str] | None = None, address_gap: int = 5,
                passphrase: str = "", clock=time.monotonic) -> dict:
    """Search a per-position candidate space for checksum-valid mnemonics.

    `slots` has one entry per word position: None (unknown -> all 2048 words),
    a single word, or a short list of possible words for that position.
    """
    length = len(slots)
    if length not in VALID_LENGTHS:
        raise ValueError("A mnemonic must be 12, 15, 18, 21 or 24 words long.")
    index = _wordlist_index(wordlist)

    option_lists: list[list[int]] = []
    for slot in slots:
        if slot is None:
            option_lists.append(list(range(2048)))
        elif isinstance(slot, str):
            token = _normalize(slot)
            if token in BLANK_MARKERS:
                option_lists.append(list(range(2048)))
            elif token in index:
                option_lists.append([index[token]])
            else:
                raise ValueError("Word not in the BIP-39 list and not a blank: " + repr(slot))
        elif isinstance(slot, (list, tuple)) and slot:
            choices = []
            for candidate in slot:
                token = _normalize(candidate)
                if token not in index:
                    raise ValueError("Candidate word not in the BIP-39 list: " + repr(candidate))
                choices.append(index[token])
            option_lists.append(choices)
        else:
            raise ValueError("Each slot must be None, a word, or a non-empty list of words.")

    combinations = 1
    for options in option_lists:
        combinations *= len(options)
        if combinations > MAX_COMBINATIONS:
            raise ValueError(
                "The search space exceeds {:,} combinations. Fix more positions, "
                "narrow the candidates, or supply a known address to match.".format(MAX_COMBINATIONS))

    results: list[str] = []
    checked = 0
    exhausted = True
    start = clock()
    for combo in product(*option_lists):
        checked += 1
        if checked % 20000 == 0 and clock() - start > time_budget:
            exhausted = False
            break
        if not _checksum_ok(combo):
            continue
        phrase = " ".join(wordlist[i] for i in combo)
        if match_address is not None and not phrase_matches_address(
                phrase, match_address, templates, address_gap, passphrase):
            continue
        results.append(phrase)
        if len(results) >= max_results:
            exhausted = False
            break
    return {
        "candidates": results,
        "candidate_count": len(results),
        "checked": checked,
        "combinations": combinations,
        "exhausted": exhausted,
        "matched_address": match_address if match_address is not None else None,
        "note": ("Each candidate passes the BIP-39 checksum. "
                 + ("The listed phrase derives the supplied address."
                    if match_address is not None else
                    "Supply a known receiving address to pin the exact phrase.")),
    }


def solve_missing_words(phrase, wordlist: list[str], **kwargs) -> dict:
    """Recover unknown words in a phrase; mark each unknown with ? or _.

    Example: "legal winner thank ? ? ... (12 tokens)" fills the two blanks.
    """
    words = phrase.split() if isinstance(phrase, str) else list(phrase)
    if len(words) not in VALID_LENGTHS:
        raise ValueError("Provide all " + "/".join(map(str, VALID_LENGTHS))
                         + " positions, using a blank marker (? or _) for each missing word.")
    return solve_slots(words, wordlist, **kwargs)


def solve_scrambled_order(words, wordlist: list[str], *, max_permutations: int = 400_000,
                          time_budget: float = DEFAULT_TIME_BUDGET,
                          max_results: int = DEFAULT_MAX_RESULTS, match_address: str | None = None,
                          templates: list[str] | None = None, address_gap: int = 5,
                          passphrase: str = "", clock=time.monotonic) -> dict:
    """Find the word order(s) that produce a valid checksum for a known word set."""
    tokens = words.split() if isinstance(words, str) else list(words)
    if len(tokens) not in VALID_LENGTHS:
        raise ValueError("A mnemonic must be 12, 15, 18, 21 or 24 words long.")
    index = _wordlist_index(wordlist)
    base = []
    for token in tokens:
        normalized = _normalize(token)
        if normalized not in index:
            raise ValueError("Word not in the BIP-39 list: " + repr(token))
        base.append(index[normalized])

    total = math.factorial(len(base))
    if total > max_permutations:
        raise ValueError(
            "Ordering {count} words is {total:,} permutations, beyond the {cap:,} cap. "
            "Fix the positions you are sure of and use the missing-word solver for the rest."
            .format(count=len(base), total=total, cap=max_permutations))

    results: list[str] = []
    seen: set[tuple] = set()
    checked = 0
    exhausted = True
    start = clock()
    for permutation in permutations(base):
        checked += 1
        if checked % 20000 == 0 and clock() - start > time_budget:
            exhausted = False
            break
        if permutation in seen:
            continue
        if not _checksum_ok(permutation):
            continue
        seen.add(permutation)
        phrase = " ".join(wordlist[i] for i in permutation)
        if match_address is not None and not phrase_matches_address(
                phrase, match_address, templates, address_gap, passphrase):
            continue
        results.append(phrase)
        if len(results) >= max_results:
            exhausted = False
            break
    return {
        "candidates": results,
        "candidate_count": len(results),
        "checked": checked,
        "permutations": total,
        "exhausted": exhausted,
        "matched_address": match_address if match_address is not None else None,
        "note": ("Each candidate is a valid-checksum ordering of the supplied words. "
                 + ("The listed phrase derives the supplied address."
                    if match_address is not None else
                    "Supply a known receiving address to pin the exact ordering.")),
    }
