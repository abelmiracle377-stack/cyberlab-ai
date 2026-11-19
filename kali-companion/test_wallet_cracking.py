"""Tests for the wallet password-recovery runner.

These use an injected runner (no real hashcat/John needed) to prove the command
construction, consent gate, wordlist validation and result parsing. A real crack
result is only ever produced from the tool's own output, never fabricated.
"""
import subprocess
import tempfile
import unittest
from pathlib import Path

import wallet_cracking as wc


def make_wordlist(tmp):
    path = Path(tmp) / "words.txt"
    path.write_text("password\nhunter2\ncorrecthorse\n", encoding="utf-8")
    return str(path)


class ConsentAndValidationTests(unittest.TestCase):
    def test_requires_confirmation(self):
        with self.assertRaisesRegex(ValueError, "explicitly confirmed"):
            wc.run_hashcat("$ethereum$p*1*aa*bb*cc", 16300, "/none", confirmed=False)

    def test_rejects_unknown_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "Unsupported hashcat mode"):
                wc.run_hashcat("x", 9999, make_wordlist(tmp), confirmed=True)

    def test_missing_wordlist_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Wordlist file not found"):
            wc.run_hashcat("$bitcoin$...", 11300, "/does/not/exist", confirmed=True)

    def test_empty_wordlist_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.txt"
            empty.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty"):
                wc.run_hashcat("$bitcoin$...", 11300, str(empty), confirmed=True)


class HashcatRunnerTests(unittest.TestCase):
    def test_builds_dictionary_attack_command(self):
        captured = {}

        def fake_runner(command, **kwargs):
            captured["command"] = command
            # Simulate hashcat writing the recovered password to the outfile.
            out_index = command.index("--outfile") + 1
            Path(command[out_index]).write_text("letmein\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            result = wc.run_hashcat("$ethereum$s*1*1*1*aa*bb*cc", 15700,
                                    make_wordlist(tmp), confirmed=True, runner=fake_runner, resolve=lambda name: "/usr/bin/" + name)
        self.assertEqual(result["status"], "cracked")
        self.assertEqual(result["password"], "letmein")
        command = captured["command"]
        self.assertIn("-m", command)
        self.assertEqual(command[command.index("-m") + 1], "15700")
        self.assertEqual(command[command.index("-a") + 1], "0")  # straight dictionary

    def test_exhausted_wordlist_reports_not_found(self):
        def fake_runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, "", "")  # hashcat: exhausted

        with tempfile.TemporaryDirectory() as tmp:
            result = wc.run_hashcat("$bitcoin$...", 11300, make_wordlist(tmp),
                                    confirmed=True, runner=fake_runner, resolve=lambda name: "/usr/bin/" + name)
        self.assertEqual(result["status"], "exhausted")
        self.assertNotIn("password", result)

    def test_timeout_is_reported_not_hidden(self):
        def fake_runner(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs.get("timeout", 1))

        with tempfile.TemporaryDirectory() as tmp:
            result = wc.run_hashcat("$bitcoin$...", 11300, make_wordlist(tmp),
                                    confirmed=True, timeout=5, runner=fake_runner, resolve=lambda name: "/usr/bin/" + name)
        self.assertEqual(result["status"], "timeout")


class JohnRunnerTests(unittest.TestCase):
    def test_parses_cracked_password_from_show(self):
        calls = []

        def fake_runner(command, **kwargs):
            calls.append(command)
            if "--show" in command:
                return subprocess.CompletedProcess(command, 0, "target:s3cret\n\n1 password hash cracked, 0 left\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            result = wc.run_john("$ethereum$p*1*aa*bb*cc", make_wordlist(tmp),
                                 confirmed=True, runner=fake_runner, resolve=lambda name: "/usr/bin/" + name)
        self.assertEqual(result["status"], "cracked")
        self.assertEqual(result["password"], "s3cret")
        self.assertTrue(any("--wordlist=" in "".join(c) for c in calls))


if __name__ == "__main__":
    unittest.main()
