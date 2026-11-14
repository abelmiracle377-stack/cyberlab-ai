"""Unit tests for the offline-first CyberLab OS terminal menu."""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cyberlab_menu  # noqa: E402


class CyberLabMenuTests(unittest.TestCase):
    def test_missing_companion_fails_closed(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.py"
            with patch.object(cyberlab_menu, "COMPANION", missing), contextlib.redirect_stderr(stderr):
                self.assertEqual(cyberlab_menu.main(), 2)
        self.assertIn("CyberLab companion not found", stderr.getvalue())

    def test_readiness_action_dispatches_and_returns_to_menu(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            companion = Path(directory) / "cyberlab.py"
            companion.write_text("# test fixture\n", encoding="utf-8")
            with patch.object(cyberlab_menu, "COMPANION", companion), patch.object(
                cyberlab_menu, "run", return_value=0
            ) as run, patch("builtins.input", side_effect=["1", "", "0"]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cyberlab_menu.main(), 0)
        run.assert_called_once_with(["doctor"])

    def test_passive_domain_option_dispatches_domain_argument(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            companion = Path(directory) / "cyberlab.py"
            companion.write_text("# test fixture\n", encoding="utf-8")
            with patch.object(cyberlab_menu, "COMPANION", companion), patch.object(
                cyberlab_menu, "run", return_value=0
            ) as run, patch("builtins.input", side_effect=["3", "example.org", "", "0"]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cyberlab_menu.main(), 0)
        run.assert_called_once_with(["domain", "example.org"])


if __name__ == "__main__":
    unittest.main()
