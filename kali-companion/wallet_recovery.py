"""Local-first wallet recovery primitives for owned or explicitly authorised backups.

Everything here is real, standards-based cryptography implemented on Python's
standard library only (hashlib/hmac) — no third-party dependencies, no network,
no simulated results. Functions either produce a correct result or raise.

Covered:
  * secp256k1 field/curve arithmetic (keys and public points)
  * BIP32 hierarchical deterministic derivation (xprv master + child keys)
  * BIP39 mnemonic -> seed (PBKDF2-HMAC-SHA512) and checksum validation
  * BIP44/BIP49/BIP84 account paths
  * Address encoding: P2PKH (Base58Check), P2WPKH (bech32), Ethereum (keccak)
  * WIF private-key encoding
  * Password-recovery hash extraction from Ethereum V3 keystores and Bitcoin
    Core wallet.dat master keys, in hashcat/John formats

This module never transmits key material and never decrypts a backup without the
owner's password. Cracking is performed only by invoking a real, locally
installed tool (see wallet_cracking.py); this file prepares inputs for it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct
import unicodedata
from pathlib import Path

# --- secp256k1 -------------------------------------------------------------
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_A = 0
_B = 7
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)


def _inv(value: int, modulus: int = _P) -> int:
    return pow(value % modulus, modulus - 2, modulus)


def _point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p == q:
        slope = (3 * x1 * x1 + _A) * _inv(2 * y1) % _P
    else:
        slope = (y2 - y1) * _inv(x2 - x1) % _P
    x3 = (slope * slope - x1 - x2) % _P
    y3 = (slope * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_mul(scalar: int, point=_G):
    scalar %= _N
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _ser32(index: int) -> bytes:
    return struct.pack(">I", index)


def _ser_point(point) -> bytes:
    x, y = point
    return (b"\x03" if y & 1 else b"\x02") + x.to_bytes(32, "big")


def private_to_public(private_key: bytes, compressed: bool = True) -> bytes:
    """Return the public key for a 32-byte private key."""
    secret = int.from_bytes(private_key, "big")
    if not 1 <= secret < _N:
        raise ValueError("Private key is out of the valid secp256k1 range.")
    point = _point_mul(secret)
    if point is None:
        raise ValueError("Derived the point at infinity; invalid private key.")
    if compressed:
        return _ser_point(point)
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# --- hashing helpers -------------------------------------------------------
def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", _sha256(data)).digest()


_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (Ethereum's hash, distinct from NIST SHA3-256)."""
    rate = 136  # 1088-bit rate for 256-bit output
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80
    mask = (1 << 64) - 1
    for block in range(0, len(padded), rate):
        chunk = padded[block:block + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(chunk[i * 8:i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        # Keccak-f[1600]
        for rnd in range(24):
            c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & mask) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= d[x]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    rot = _KECCAK_ROT[x][y]
                    value = state[x][y]
                    b[y][(2 * x + 3 * y) % 5] = ((value << rot) | (value >> (64 - rot))) & mask if rot else value
            for x in range(5):
                for y in range(5):
                    state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) & mask
            state[0][0] ^= _KECCAK_RC[rnd]
    out = bytearray()
    for i in range(4):  # 32 bytes
        out += (state[i % 5][i // 5] & mask).to_bytes(8, "little")
    return bytes(out)


# --- Base58 / bech32 -------------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check_encode(payload: bytes) -> str:
    checksum = _sha256(_sha256(payload))[:4]
    data = payload + checksum
    number = int.from_bytes(data, "big")
    encoded = ""
    while number > 0:
        number, remainder = divmod(number, 58)
        encoded = _B58[remainder] + encoded
    pad = len(data) - len(data.lstrip(b"\x00"))
    return _B58[0] * pad + encoded


def base58check_decode(text: str) -> bytes:
    number = 0
    for char in text:
        index = _B58.find(char)
        if index < 0:
            raise ValueError("Invalid Base58 character in input.")
        number = number * 58 + index
    full = number.to_bytes((number.bit_length() + 7) // 8, "big")
    pad = len(text) - len(text.lstrip(_B58[0]))
    full = b"\x00" * pad + full
    if len(full) < 4 or _sha256(_sha256(full[:-4]))[:4] != full[-4:]:
        raise ValueError("Base58Check checksum does not validate.")
    return full[:-4]


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    result = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            result.append((acc >> bits) & maxv)
    if pad and bits:
        result.append((acc << (tobits - bits)) & maxv)
    return result


def bech32_encode_segwit(witness_program: bytes, hrp: str = "bc", witver: int = 0) -> str:
    data = [witver] + _convertbits(list(witness_program), 8, 5)
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


# --- address + WIF ---------------------------------------------------------
def p2pkh_address(public_key: bytes, version: int = 0x00) -> str:
    return base58check_encode(bytes([version]) + _hash160(public_key))


def p2wpkh_address(public_key: bytes, hrp: str = "bc") -> str:
    return bech32_encode_segwit(_hash160(public_key), hrp=hrp)


def ethereum_address(public_key_uncompressed: bytes) -> str:
    if len(public_key_uncompressed) == 33:
        raise ValueError("Ethereum addresses require the uncompressed public key.")
    body = public_key_uncompressed[1:] if public_key_uncompressed[0] == 0x04 else public_key_uncompressed
    digest = keccak256(body)[-20:]
    hex_addr = digest.hex()
    checksum_hash = keccak256(hex_addr.encode()).hex()
    out = "".join(c.upper() if int(checksum_hash[i], 16) >= 8 else c for i, c in enumerate(hex_addr))
    return "0x" + out


def wif_encode(private_key: bytes, compressed: bool = True, version: int = 0x80) -> str:
    payload = bytes([version]) + private_key + (b"\x01" if compressed else b"")
    return base58check_encode(payload)


def p2sh_p2wpkh_address(public_key: bytes, version: int = 0x05) -> str:
    """BIP49 nested SegWit: a P2WPKH program wrapped in P2SH (addresses start 3/M)."""
    redeem_script = b"\x00\x14" + _hash160(public_key)  # OP_0 <20-byte keyhash>
    return base58check_encode(bytes([version]) + _hash160(redeem_script))


# --- Bitcoin Cash CashAddr -------------------------------------------------
_CASHADDR_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _cashaddr_polymod(values) -> int:
    generator = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]
    chk = 1
    for value in values:
        top = chk >> 35
        chk = ((chk & 0x07ffffffff) << 5) ^ value
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk ^ 1


def cashaddr_encode(pubkey_hash: bytes, prefix: str = "bitcoincash", type_bits: int = 0) -> str:
    """Encode a 160-bit hash as a CashAddr (type 0 = P2PKH, 1 = P2SH)."""
    if len(pubkey_hash) != 20:
        raise ValueError("CashAddr here supports 160-bit hashes only.")
    version_byte = (type_bits & 0x0f) << 3  # size bits 0 => 160-bit hash
    payload = _convertbits([version_byte] + list(pubkey_hash), 8, 5)
    prefix_expand = [ord(c) & 31 for c in prefix] + [0]
    polymod = _cashaddr_polymod(prefix_expand + payload + [0] * 8)
    checksum = [(polymod >> 5 * (7 - i)) & 31 for i in range(8)]
    return prefix + ":" + "".join(_CASHADDR_CHARSET[d] for d in payload + checksum)


# --- BIP32 -----------------------------------------------------------------
_HARDENED = 0x80000000


class HDKey:
    def __init__(self, key: bytes, chain_code: bytes, depth=0, parent_fp=b"\x00\x00\x00\x00", index=0):
        self.key = key  # 32-byte private key
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fp = parent_fp
        self.index = index

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDKey":
        digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        secret = int.from_bytes(digest[:32], "big")
        if secret == 0 or secret >= _N:
            raise ValueError("Seed produced an invalid master key; use a different seed.")
        return cls(digest[:32], digest[32:])

    def public_key(self, compressed: bool = True) -> bytes:
        return private_to_public(self.key, compressed)

    def fingerprint(self) -> bytes:
        return _hash160(self.public_key())[:4]

    def derive_child(self, index: int) -> "HDKey":
        if index & _HARDENED:
            data = b"\x00" + self.key + _ser32(index)
        else:
            data = self.public_key() + _ser32(index)
        digest = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        offset = int.from_bytes(digest[:32], "big")
        child = (offset + int.from_bytes(self.key, "big")) % _N
        if offset >= _N or child == 0:
            raise ValueError("Invalid child key at index %d; skip to the next index." % index)
        return HDKey(child.to_bytes(32, "big"), digest[32:], self.depth + 1, self.fingerprint(), index)

    def derive_path(self, path: str) -> "HDKey":
        if path in ("m", "m/", ""):
            return self
        if not path.startswith("m/"):
            raise ValueError("Derivation path must start with 'm/'.")
        node = self
        for element in path[2:].split("/"):
            if not element:
                continue
            hardened = element.endswith("'") or element.endswith("h")
            number = int(element.rstrip("'h"))
            if not 0 <= number < _HARDENED:
                raise ValueError("Path index out of range: " + element)
            node = node.derive_child(number + _HARDENED if hardened else number)
        return node

    def xprv(self, version: int = 0x0488ADE4) -> str:
        payload = (struct.pack(">I", version) + bytes([self.depth]) + self.parent_fp
                   + _ser32(self.index) + self.chain_code + b"\x00" + self.key)
        return base58check_encode(payload)

    def xpub(self, version: int = 0x0488B21E) -> str:
        payload = (struct.pack(">I", version) + bytes([self.depth]) + self.parent_fp
                   + _ser32(self.index) + self.chain_code + self.public_key())
        return base58check_encode(payload)


# --- BIP39 -----------------------------------------------------------------
# sha256 of the canonical BIP-0039 English wordlist (english.txt).
BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP39 mnemonic -> 64-byte seed. Does not require the wordlist."""
    mnemonic_n = unicodedata.normalize("NFKD", mnemonic.strip())
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", mnemonic_n.encode(), salt.encode(), 2048, dklen=64)


def load_wordlist(path: Path) -> list[str]:
    """Load and verify the canonical English wordlist by its SHA-256 before use."""
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != BIP39_ENGLISH_SHA256:
        raise ValueError("Wordlist SHA-256 does not match the canonical BIP-0039 English list.")
    words = raw.decode("utf-8").split()
    if len(words) != 2048:
        raise ValueError("A BIP-0039 wordlist must contain exactly 2048 words.")
    return words


def validate_mnemonic(mnemonic: str, wordlist: list[str]) -> bool:
    """Validate a mnemonic's checksum against the supplied 2048-word list."""
    words = unicodedata.normalize("NFKD", mnemonic.strip()).split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("Mnemonic length must be 12, 15, 18, 21 or 24 words.")
    index = {word: i for i, word in enumerate(wordlist)}
    try:
        bits = "".join(format(index[word], "011b") for word in words)
    except KeyError as exc:
        raise ValueError("Mnemonic contains a word that is not in the wordlist: " + str(exc)) from exc
    checksum_len = len(words) * 11 // 33
    entropy_bits, checksum_bits = bits[:-checksum_len], bits[-checksum_len:]
    entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big")
    expected = format(_sha256(entropy)[0], "08b")[:checksum_len]
    return checksum_bits == expected


# Standard account templates for recovery sweeps. Each carries the derivation
# path, the address encoding, and the coin's version bytes so one derivation
# routine serves every supported coin and script type.
ACCOUNT_TEMPLATES = {
    # Bitcoin
    "bip44-legacy": {"path": "m/44'/0'/0'/0", "address": "p2pkh", "coin": "bitcoin",
                     "addr_version": 0x00, "wif_version": 0x80},
    "bip49-p2sh-segwit": {"path": "m/49'/0'/0'/0", "address": "p2sh-p2wpkh", "coin": "bitcoin",
                          "addr_version": 0x05, "wif_version": 0x80},
    "bip84-segwit": {"path": "m/84'/0'/0'/0", "address": "p2wpkh", "coin": "bitcoin",
                     "hrp": "bc", "wif_version": 0x80},
    # Litecoin
    "litecoin-legacy": {"path": "m/44'/2'/0'/0", "address": "p2pkh", "coin": "litecoin",
                        "addr_version": 0x30, "wif_version": 0xB0},
    "litecoin-p2sh-segwit": {"path": "m/49'/2'/0'/0", "address": "p2sh-p2wpkh", "coin": "litecoin",
                             "addr_version": 0x32, "wif_version": 0xB0},
    "litecoin-segwit": {"path": "m/84'/2'/0'/0", "address": "p2wpkh", "coin": "litecoin",
                        "hrp": "ltc", "wif_version": 0xB0},
    # Dogecoin
    "dogecoin-legacy": {"path": "m/44'/3'/0'/0", "address": "p2pkh", "coin": "dogecoin",
                        "addr_version": 0x1E, "wif_version": 0x9E},
    # Bitcoin Cash (CashAddr)
    "bitcoincash": {"path": "m/44'/145'/0'/0", "address": "cashaddr", "coin": "bitcoincash",
                    "cashaddr_prefix": "bitcoincash", "cashaddr_type": 0, "wif_version": 0x80},
    # Ethereum (and EVM chains)
    "bip44-ethereum": {"path": "m/44'/60'/0'/0", "address": "ethereum", "coin": "ethereum"},
}


def _encode_address(spec: dict, child: "HDKey") -> str:
    kind = spec["address"]
    if kind == "p2pkh":
        return p2pkh_address(child.public_key(), spec.get("addr_version", 0x00))
    if kind == "p2wpkh":
        return p2wpkh_address(child.public_key(), spec.get("hrp", "bc"))
    if kind == "p2sh-p2wpkh":
        return p2sh_p2wpkh_address(child.public_key(), spec.get("addr_version", 0x05))
    if kind == "cashaddr":
        return cashaddr_encode(_hash160(child.public_key()),
                               spec.get("cashaddr_prefix", "bitcoincash"),
                               spec.get("cashaddr_type", 0))
    return ethereum_address(child.public_key(compressed=False))


def derive_accounts(seed: bytes, template: str, count: int = 5) -> list[dict]:
    """Derive the first `count` receiving addresses for a standard account template."""
    if template not in ACCOUNT_TEMPLATES:
        raise ValueError("Unknown account template: " + template)
    if not 1 <= count <= 100:
        raise ValueError("Address count must be between 1 and 100.")
    spec = ACCOUNT_TEMPLATES[template]
    root = HDKey.from_seed(seed).derive_path(spec["path"])
    results = []
    for i in range(count):
        child = root.derive_child(i)
        entry = {"path": spec["path"] + "/" + str(i), "address": _encode_address(spec, child),
                 "coin": spec["coin"]}
        if spec["coin"] == "ethereum":
            entry["privateKey"] = "0x" + child.key.hex()
        else:
            entry["wif"] = wif_encode(child.key, version=spec.get("wif_version", 0x80))
        results.append(entry)
    return results


# --- password-recovery hash extraction -------------------------------------
def extract_keystore_hash(keystore_json: str) -> dict:
    """Extract a John/hashcat hash from an Ethereum V3 (Web3 Secret Storage) keystore."""
    data = json.loads(keystore_json)
    if not isinstance(data, dict) or data.get("version") != 3:
        raise ValueError("Not a version 3 Ethereum keystore.")
    crypto = data.get("crypto") or data.get("Crypto")
    if not isinstance(crypto, dict):
        raise ValueError("Keystore has no crypto section.")
    kdf = str(crypto.get("kdf", "")).lower()
    params = crypto.get("kdfparams") or {}
    ciphertext = str(crypto.get("ciphertext", ""))
    mac = str(crypto.get("mac", ""))
    salt = str(params.get("salt", ""))
    if not re.fullmatch(r"[0-9a-fA-F]+", ciphertext or "") or not re.fullmatch(r"[0-9a-fA-F]{64}", mac or ""):
        raise ValueError("Keystore ciphertext or MAC is malformed.")
    if kdf == "scrypt":
        john = "$ethereum$s*{n}*{r}*{p}*{salt}*{ct}*{mac}".format(
            n=int(params["n"]), r=int(params["r"]), p=int(params["p"]),
            salt=salt, ct=ciphertext, mac=mac)
        mode = 15700
    elif kdf == "pbkdf2":
        john = "$ethereum$p*{c}*{salt}*{ct}*{mac}".format(
            c=int(params["c"]), salt=salt, ct=ciphertext, mac=mac)
        mode = 16300
    else:
        raise ValueError("Unsupported keystore KDF: " + kdf)
    return {"format": "ethereum-keystore-v3", "kdf": kdf, "hashcatMode": mode,
            "hash": john, "note": "Run against a locally installed hashcat/John with your own wordlist."}


_MKEY = re.compile(rb"\x04mkey\x01\x00\x00\x00")


def extract_wallet_dat_hash(wallet_dat: bytes) -> dict:
    """Extract the encrypted master-key hash ($bitcoin$...) from a Bitcoin Core wallet.dat.

    Scans the Berkeley DB file for the 'mkey' record rather than fully parsing BDB,
    matching the approach used by bitcoin2john.
    """
    match = _MKEY.search(wallet_dat)
    if not match:
        raise ValueError("No encrypted master key (mkey) record found in this wallet.dat.")
    pos = match.end()
    enc_len = wallet_dat[pos]
    pos += 1
    encrypted = wallet_dat[pos:pos + enc_len]
    pos += enc_len
    salt_len = wallet_dat[pos]
    pos += 1
    salt = wallet_dat[pos:pos + salt_len]
    pos += salt_len
    pos += 1  # derivation method byte
    (deriv_iters,) = struct.unpack("<I", wallet_dat[pos:pos + 4])
    if enc_len not in (48, 64) or salt_len != 8 or not 1 <= deriv_iters <= 10_000_000:
        raise ValueError("Master-key record is present but its fields are out of range.")
    john = "$bitcoin${el}${ec}${sl}${sc}${it}$2$00$2$00".format(
        el=enc_len * 2, ec=encrypted.hex(), sl=salt_len * 2, sc=salt.hex(), it=deriv_iters)
    return {"format": "bitcoin-core-wallet.dat", "hashcatMode": 11300, "hash": john,
            "iterations": deriv_iters,
            "note": "Run against a locally installed hashcat (-m 11300) or John with your own wordlist."}
