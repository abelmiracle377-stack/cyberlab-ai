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
import subprocess
import tempfile
from pathlib import Path

MAX_WORDLIST_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB
DEFAULT_TIMEOUT = 3600
HASHCAT_MODES = {11300: "Bitcoin/Litecoin wallet.dat", 15700: "Ethereum keystore (scrypt)",
                 16300: "Ethereum keystore (PBKDF2)"}


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


def _require(executable: str, apt_package: str, resolve=shutil.which) -> str:
    resolved = resolve(executable)
    if not resolved:
        raise ValueError(
            "{exe} is not installed. Install it on this machine (for example: "
            "sudo apt install {pkg}); the companion never downloads cracking tools."
            .format(exe=executable, pkg=apt_package))
    return resolved


def run_hashcat(hash_value: str, hashcat_mode: int, wordlist: str,
                confirmed: bool = False, timeout: int = DEFAULT_TIMEOUT,
                runner=subprocess.run, resolve=shutil.which) -> dict:
    """Run hashcat in straight dictionary mode against a single extracted hash."""
    if not confirmed:
        raise ValueError("Password recovery must be explicitly confirmed before it runs.")
    if hashcat_mode not in HASHCAT_MODES:
        raise ValueError("Unsupported hashcat mode for wallet recovery.")
    if not isinstance(hash_value, str) or "\n" in hash_value or not hash_value.strip():
        raise ValueError("Hash value is missing or malformed.")
    if not 1 <= int(timeout) <= 86400:
        raise ValueError("Timeout must be between 1 and 86400 seconds.")
    wordlist_path = _validate_wordlist(wordlist)
    executable = _require("hashcat", "hashcat", resolve)
    workdir = Path(tempfile.mkdtemp(prefix="cyberlab-wallet-"))
    hash_file = workdir / "target.hash"
    potfile = workdir / "cyberlab.potfile"
    hash_file.write_text(hash_value + "\n", encoding="utf-8")
    command = [executable, "-m", str(hashcat_mode), "-a", "0",
               "--quiet", "--potfile-path", str(potfile),
               "--outfile", str(workdir / "cracked.txt"), "--outfile-format", "2",
               str(hash_file), str(wordlist_path)]
    try:
        completed = runner(command, capture_output=True, text=True, timeout=int(timeout),
                           check=False, cwd=str(workdir),
                           env={**os.environ, "HOME": str(workdir)})
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "hashcat", "mode": hashcat_mode,
                "note": "hashcat did not finish within the time limit; the password was not found in the attempted keyspace."}
    cracked_file = workdir / "cracked.txt"
    password = None
    if cracked_file.exists():
        content = cracked_file.read_text(encoding="utf-8", errors="replace").strip()
        if content:
            password = content.splitlines()[0]
    status_code = completed.returncode
    if password is not None:
        return {"status": "cracked", "tool": "hashcat", "mode": hashcat_mode,
                "password": password,
                "note": "Password recovered from the supplied wordlist. Keep it offline and secure."}
    if status_code == 1:
        return {"status": "exhausted", "tool": "hashcat", "mode": hashcat_mode,
                "note": "The password was not in the supplied wordlist. Try a larger or targeted wordlist or rules."}
    return {"status": "error", "tool": "hashcat", "mode": hashcat_mode,
            "exitCode": status_code, "stderr": (completed.stderr or "")[:2000],
            "note": "hashcat exited with an error; review the installation and hash format."}


_JOHN_CRACK = re.compile(r"^(?P<password>.*?):", re.MULTILINE)


def run_john(hash_value: str, wordlist: str, confirmed: bool = False,
             timeout: int = DEFAULT_TIMEOUT, runner=subprocess.run, resolve=shutil.which) -> dict:
    """Run John the Ripper in wordlist mode against a single extracted hash."""
    if not confirmed:
        raise ValueError("Password recovery must be explicitly confirmed before it runs.")
    if not isinstance(hash_value, str) or "\n" in hash_value or not hash_value.strip():
        raise ValueError("Hash value is missing or malformed.")
    if not 1 <= int(timeout) <= 86400:
        raise ValueError("Timeout must be between 1 and 86400 seconds.")
    wordlist_path = _validate_wordlist(wordlist)
    executable = _require("john", "john", resolve)
    workdir = Path(tempfile.mkdtemp(prefix="cyberlab-wallet-"))
    hash_file = workdir / "target.hash"
    pot_file = workdir / "john.pot"
    hash_file.write_text(hash_value + "\n", encoding="utf-8")
    env = {**os.environ, "HOME": str(workdir)}
    command = [executable, "--wordlist=" + str(wordlist_path),
               "--pot=" + str(pot_file), str(hash_file)]
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
                            "note": "Password recovered from the supplied wordlist. Keep it offline and secure."}
    return {"status": "exhausted", "tool": "john",
            "note": "The password was not in the supplied wordlist. Try a larger or targeted wordlist or rules."}
