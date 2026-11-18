"""Security tests for local CyberLab pairing-token storage."""
import os
import stat
import tempfile
import unittest
from pathlib import Path

from bridge_security import load_or_create_pairing_token


class PairingTokenSecurityTests(unittest.TestCase):
    def test_creates_random_owner_only_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / ".config" / "cyberlab"
            token_file = config / "bridge-token"
            token = load_or_create_pairing_token(config, token_file)
            self.assertGreaterEqual(len(token), 40)
            self.assertEqual(token, token_file.read_text(encoding="ascii").strip())
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(token_file.stat().st_mode), 0o600)

    def test_reuses_existing_valid_token_and_repairs_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "cyberlab"
            config.mkdir(mode=0o755)
            token_file = config / "bridge-token"
            token_file.write_text("A" * 48 + "\\n", encoding="ascii")
            token_file.chmod(0o644)
            token = load_or_create_pairing_token(config, token_file)
            self.assertEqual(token, "A" * 48)
            self.assertEqual(stat.S_IMODE(token_file.stat().st_mode), 0o600)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_rejects_token_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "cyberlab"
            config.mkdir()
            target = root / "outside"
            target.write_text("B" * 48, encoding="ascii")
            token_file = config / "bridge-token"
            token_file.symlink_to(target)
            with self.assertRaisesRegex(PermissionError, "symlink"):
                load_or_create_pairing_token(config, token_file)
            self.assertEqual(target.read_text(encoding="ascii"), "B" * 48)

    def test_rejects_invalid_existing_token_without_replacing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "cyberlab"
            config.mkdir()
            token_file = config / "bridge-token"
            token_file.write_text("short", encoding="ascii")
            with self.assertRaisesRegex(PermissionError, "invalid"):
                load_or_create_pairing_token(config, token_file)
            self.assertEqual(token_file.read_text(encoding="ascii"), "short")


if __name__ == "__main__":
    unittest.main()
