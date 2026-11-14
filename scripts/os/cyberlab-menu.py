#!/usr/bin/env python3
"""Small, offline-first interactive entry point for the CyberLab companion."""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

COMPANION = Path("/opt/cyberlab-ai/kali-companion/cyberlab.py")


def run(args: list[str]) -> int:
    return subprocess.run([sys.executable, str(COMPANION), *args], check=False).returncode


def ask(label: str) -> str:
    return input(label).strip()


def main() -> int:
    if not COMPANION.is_file():
        print(f"CyberLab companion not found: {COMPANION}", file=sys.stderr)
        return 2
    actions = {
        "1": ("Readiness check", lambda: run(["doctor"])),
        "2": ("Public DNS lookup", lambda: run(["dns", ask("Domain: ")])),
        "3": ("Passive domain research (RDAP/certificates/DNS)", lambda: run(["domain", ask("Domain: ")])),
        "4": ("Public IP registration lookup", lambda: run(["ip", ask("Public IP: ")])),
        "5": ("NIST CVE search", lambda: run(["cve", ask("Product/vendor/CVE keyword: ")])),
        "6": ("Static local file triage (max 10 MB)", lambda: run(["triage", ask("File path: ")])),
        "7": ("Parse an existing Nmap XML report (no scan)", lambda: run(["nmap-xml", ask("XML file path: ")])),
    }
    while True:
        print("\nCYBERLAB AI — TERMINAL WORKSPACE")
        print("Passive research and local evidence analysis")
        for key, (label, _) in actions.items():
            print(f"  {key}. {label}")
        print("  8. Show command-line help")
        print("  0. Exit")
        choice = ask("Select an option: ")
        if choice == "0":
            return 0
        if choice == "8":
            return run(["--help"])
        action = actions.get(choice)
        if action is None:
            print("Choose one of the listed options.")
            continue
        try:
            status = action[1]()
            print(f"\nCompleted with exit status {status}.")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 130
        except (OSError, ValueError) as exc:
            print(f"Input error: {exc}", file=sys.stderr)
        ask("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    raise SystemExit(main())
