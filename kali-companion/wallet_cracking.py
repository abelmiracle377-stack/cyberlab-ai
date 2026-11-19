"""Drive a locally installed hashcat or John the Ripper against an extracted
wallet hash, using the owner's own wordlist. No tool is bundled or downloaded;
if the tool is absent the call fails closed with an actionable message. Nothing
here fabricates a recovered password — a result is returned only when the real
tool reports a crack.
"""
from __future__ import annotations

import os
import re
import shutil
import string
import subprocess
import tempfile
from pathlib import Path

MAX_WORDLIST_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_RULES_BYTES = 64 * 1024 * 1024  # 64 MiB
DEFAULT_TIMEOUT = 3600
HASHCAT_MODES = {11300: "Bitcoin/Litecoin wallet.dat", 15700: "Ethereum keystore (scrypt)",
                 16300: "Ethereum keystore (PBKDF2)"}

# hashcat attack modes we expose for a single forgotten wallet password.
ATTACK_MODES = {
    "dictionary": "0",            # straight wordlist (optionally + rules)
    "mask": "3",                  # brute force over a described keyspace
    "hybrid-wordlist-mask": "6",  # each word + a mask suffix
    "hybrid-mask-wordlist": "7",  # a mask prefix + each word
}
_MASK_TOKENS = set("ludsabhH1234")
_MASK_LITERALS = set(string.ascii_letters + string.digits + string.punctuation) - {"?"}


def _validate_wordlist(wordlist: str) -> Path:
    path = Path(wordlist).expanduser()
    if path.is_symlink():
        raise ValueError("Wordlist path must not be a symlink.")
    if not path.is_file():
        raise ValueError("Wordlist file not found: " + str(path))
    size = path.stat().st_size
    if size == 0:
        raise ValueError("Wordlist is empty.")
    if size > MAX_WORDLIST_BYTES:
        raise ValueError("Wordlist exceeds the 2 GiB limit.")
    return path


def _validate_rules_file(rules_file: str) -> Path:
    path = Path(rules_file).expanduser()
    if path.is_symlink():
        raise ValueError("Rules file path must not be a symlink.")
    if not path.is_file():
        raise ValueError("Rules file not found: " + str(path))
    if path.stat().st_size > MAX_RULES_BYTES:
        raise ValueError("Rules file exceeds the 64 MiB limit.")
    return path


def _validate_mask(mask: str) -> str:
    """Accept a hashcat mask string (?l ?u ?d ?s ?a ?b ?h ?H / ?1-?4 and literals)."""
    if not isinstance(mask, str) or not mask.strip():
        raise ValueError("A mask is required for a mask or hybrid attack.")
    if len(mask) > 256:
        raise ValueError("Mask is too long (max 256 characters).")
    i = 0
    while i < len(mask):
        char = mask[i]
        if char == "?":
            if i + 1 >= len(mask) or mask[i + 1] not in _MASK_TOKENS:
                raise ValueError("Invalid mask placeholder; use ?l ?u ?d ?s ?a ?b ?h ?H or ?1-?4.")
            i += 2
        elif char in _MASK_LITERALS:
            i += 1
        else:
            raise ValueError("Mask contains an unsupported character: " + repr(char))
    return mask


def _validate_custom_charsets(custom_charsets) -> list[str]:
    if custom_charsets is None:
        return []
    if not isinstance(custom_charsets, (list, tuple)) or len(custom_charsets) > 4:
        raise ValueError("custom_charsets must be a list of at most four charset strings.")
    cleaned = []
    for charset in custom_charsets:
        if not isinstance(charset, str) or not charset.strip() or len(charset) > 256:
            raise ValueError("Each custom charset must be a non-empty string up to 256 characters.")
        # A charset may itself reference built-in tokens (?l?d) plus literal characters.
        i = 0
        while i < len(charset):
            if charset[i] == "?":
                if i + 1 >= len(charset) or charset[i + 1] not in _MASK_TOKENS:
                    raise ValueError("Invalid token in a custom charset.")
                i += 2
            elif charset[i] in _MASK_LITERALS:
                i += 1
            else:
                raise ValueError("Custom charset has an unsupported character: " + repr(charset[i]))
        cleaned.append(charset)
    return cleaned


def _require(executable: str, apt_package: str, resolve=shutil.which) -> str:
    resolved = resolve(executable)
    if not resolved:
        raise ValueError(
            "{exe} is not installed. Install it on this machine (for example: "
            "sudo apt install {pkg}); the companion never downloads cracking tools."
            .format(exe=executable, pkg=apt_package))
    return resolved


def _exhausted_note(attack_mode: str) -> str:
    if attack_mode == "dictionary":
        return "The password was not in the supplied wordlist. Try a larger or targeted wordlist, rules, or a mask."
    if attack_mode == "mask":
        return "The described keyspace was exhausted without a match. Widen the mask or try a different pattern."
    return "The hybrid keyspace was exhausted without a match. Adjust the wordlist or the mask."


def run_hashcat(hash_value: str, hashcat_mode: int, wordlist: str | None = None,
                confirmed: bool = False, timeout: int = DEFAULT_TIMEOUT,
                attack_mode: str = "dictionary", mask: str | None = None,
                rules_file: str | None = None, custom_charsets=None,
                runner=subprocess.run, resolve=shutil.which) -> dict:
    """Run hashcat against one extracted wallet hash.

    attack_mode selects how the keyspace is produced:
      * dictionary (default)      -a 0, a wordlist, optionally with a rules file
      * mask                      -a 3, a brute-force mask (?l?d... and literals)
      * hybrid-wordlist-mask      -a 6, each word followed by a mask
      * hybrid-mask-wordlist      -a 7, a mask followed by each word
    Nothing is fabricated: a password is reported only from hashcat's own outfile.
    """
    if not confirmed:
        raise ValueError("Password recovery must be explicitly confirmed before it runs.")
    if hashcat_mode not in HASHCAT_MODES:
        raise ValueError("Unsupported hashcat mode for wallet recovery.")
    if not isinstance(hash_value, str) or "\n" in hash_value or not hash_value.strip():
        raise ValueError("Hash value is missing or malformed.")
    if not 1 <= int(timeout) <= 86400:
        raise ValueError("Timeout must be between 1 and 86400 seconds.")
    if attack_mode not in ATTACK_MODES:
        raise ValueError("Unsupported attack mode: " + str(attack_mode))

    needs_wordlist = attack_mode in {"dictionary", "hybrid-wordlist-mask", "hybrid-mask-wordlist"}
    needs_mask = attack_mode in {"mask", "hybrid-wordlist-mask", "hybrid-mask-wordlist"}
    wordlist_path = _validate_wordlist(wordlist) if needs_wordlist else None
    validated_mask = _validate_mask(mask) if needs_mask else None
    charsets = _validate_custom_charsets(custom_charsets) if needs_mask else []
    if rules_file is not None and attack_mode != "dictionary":
        raise ValueError("Rules files apply only to a dictionary attack.")
    rules_path = _validate_rules_file(rules_file) if rules_file else None

    executable = _require("hashcat", "hashcat", resolve)
    workdir = Path(tempfile.mkdtemp(prefix="cyberlab-wallet-"))
    hash_file = workdir / "target.hash"
    potfile = workdir / "cyberlab.potfile"
    hash_file.write_text(hash_value + "\n", encoding="utf-8")
    command = [executable, "-m", str(hashcat_mode), "-a", ATTACK_MODES[attack_mode],
               "--quiet", "--potfile-path", str(potfile),
               "--outfile", str(workdir / "cracked.txt"), "--outfile-format", "2"]
    for index, charset in enumerate(charsets, start=1):
        command += ["-" + str(index), charset]
    if rules_path is not None:
        command += ["-r", str(rules_path)]
    command.append(str(hash_file))
    if attack_mode == "dictionary":
        command.append(str(wordlist_path))
    elif attack_mode == "mask":
        command.append(validated_mask)
    elif attack_mode == "hybrid-wordlist-mask":
        command += [str(wordlist_path), validated_mask]
    else:  # hybrid-mask-wordlist
        command += [validated_mask, str(wordlist_path)]

    try:
        completed = runner(command, capture_output=True, text=True, timeout=int(timeout),
                           check=False, cwd=str(workdir),
                           env={**os.environ, "HOME": str(workdir)})
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "hashcat", "mode": hashcat_mode, "attack": attack_mode,
                "note": "hashcat did not finish within the time limit; the password was not found in the attempted keyspace."}
    cracked_file = workdir / "cracked.txt"
    password = None
    if cracked_file.exists():
        content = cracked_file.read_text(encoding="utf-8", errors="replace").strip()
        if content:
            password = content.splitlines()[0]
    status_code = completed.returncode
    if password is not None:
        return {"status": "cracked", "tool": "hashcat", "mode": hashcat_mode, "attack": attack_mode,
                "password": password,
                "note": "Password recovered. Keep it offline and secure."}
    if status_code == 1:
        return {"status": "exhausted", "tool": "hashcat", "mode": hashcat_mode, "attack": attack_mode,
                "note": _exhausted_note(attack_mode)}
    return {"status": "error", "tool": "hashcat", "mode": hashcat_mode, "attack": attack_mode,
            "exitCode": status_code, "stderr": (completed.stderr or "")[:2000],
            "note": "hashcat exited with an error; review the installation and hash format."}


_JOHN_CRACK = re.compile(r"^(?P<password>.*?):", re.MULTILINE)


_JOHN_NAME = re.compile(r"\A[A-Za-z0-9_.\-]{1,64}\Z")


def _validate_john_name(name: str, label: str) -> str:
    if not isinstance(name, str) or not _JOHN_NAME.match(name):
        raise ValueError("Invalid John " + label + " name.")
    return name


def run_john(hash_value: str, wordlist: str | None = None, confirmed: bool = False,
             timeout: int = DEFAULT_TIMEOUT, rules=None, incremental=None,
             runner=subprocess.run, resolve=shutil.which) -> dict:
    """Run John the Ripper against a single extracted hash.

    Default is wordlist mode. Pass rules=True (or a named rule section) to apply
    mangling rules to the wordlist, or incremental=True (or a named mode) to run
    John's incremental brute force instead of a wordlist.
    """
    if not confirmed:
        raise ValueError("Password recovery must be explicitly confirmed before it runs.")
    if not isinstance(hash_value, str) or "\n" in hash_value or not hash_value.strip():
        raise ValueError("Hash value is missing or malformed.")
    if not 1 <= int(timeout) <= 86400:
        raise ValueError("Timeout must be between 1 and 86400 seconds.")
    use_incremental = bool(incremental)
    wordlist_path = None if use_incremental else _validate_wordlist(wordlist)
    executable = _require("john", "john", resolve)
    workdir = Path(tempfile.mkdtemp(prefix="cyberlab-wallet-"))
    hash_file = workdir / "target.hash"
    pot_file = workdir / "john.pot"
    hash_file.write_text(hash_value + "\n", encoding="utf-8")
    env = {**os.environ, "HOME": str(workdir)}
    if use_incremental:
        flag = "--incremental"
        if isinstance(incremental, str):
            flag += "=" + _validate_john_name(incremental, "incremental mode")
        command = [executable, flag, "--pot=" + str(pot_file), str(hash_file)]
    else:
        command = [executable, "--wordlist=" + str(wordlist_path),
                   "--pot=" + str(pot_file), str(hash_file)]
        if rules:
            flag = "--rules"
            if isinstance(rules, str):
                flag += "=" + _validate_john_name(rules, "rules")
            command.insert(2, flag)
    try:
        runner(command, capture_output=True, text=True, timeout=int(timeout),
               check=False, cwd=str(workdir), env=env)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "john",
                "note": "John did not finish within the time limit; the password was not found in the attempted keyspace."}
    show = runner([executable, "--show", "--pot=" + str(pot_file), str(hash_file)],
                  capture_output=True, text=True, timeout=60, check=False,
                  cwd=str(workdir), env=env)
    output = show.stdout or ""
    for line in output.splitlines():
        if line.count(":") >= 1 and not line.endswith("password hash cracked, 0 left"):
            match = _JOHN_CRACK.match(line)
            if match and "0 password hashes cracked" not in line:
                password = line.split(":", 1)[1] if ":" in line else None
                if password:
                    return {"status": "cracked", "tool": "john", "password": password,
                            "note": "Password recovered. Keep it offline and secure."}
    if use_incremental:
        return {"status": "exhausted", "tool": "john",
                "note": "John's incremental run ended without a match in the attempted keyspace."}
    return {"status": "exhausted", "tool": "john",
            "note": "The password was not in the supplied wordlist. Try a larger or targeted wordlist, rules, or incremental mode."}
