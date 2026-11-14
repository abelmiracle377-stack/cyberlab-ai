"""Unit tests for the offline-first CyberLab OS terminal menu."""
from __future__ import annotations

import contextlib
import io
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MENU_PATH = Path(__file__).resolve().parent / "cyberlab-menu.py"
SPEC = importlib.util.spec_from_file_location("cyberlab_menu", MENU_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Cannot load CyberLab menu module: {MENU_PATH}")
cyberlab_menu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cyberlab_menu)


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

    def test_eof_at_main_prompt_exits_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            companion = Path(directory) / "cyberlab.py"
            companion.write_text("# test fixture\\n", encoding="utf-8")
            with patch.object(cyberlab_menu, "COMPANION", companion), patch(
                "builtins.input", side_effect=EOFError
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cyberlab_menu.main(), 0)

    def test_keyboard_interrupt_at_main_prompt_returns_interrupt_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            companion = Path(directory) / "cyberlab.py"
            companion.write_text("# test fixture\\n", encoding="utf-8")
            with patch.object(cyberlab_menu, "COMPANION", companion), patch(
                "builtins.input", side_effect=KeyboardInterrupt
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cyberlab_menu.main(), 130)

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
