#!/usr/bin/env python3
"""Cross-platform installer for the small, required NIKHIL AI dependency set."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def run(command):
    print(f"[i] Running: {' '.join(str(part) for part in command)}")
    return subprocess.run(command, check=False).returncode


def main():
    root = Path(__file__).resolve().parent
    requirements = root / "requirements.txt"
    if sys.version_info < (3, 10):
        print("[-] Python 3.10 or newer is required.")
        return 2
    if not requirements.exists():
        print("[-] requirements.txt was not found.")
        return 1

    code = run([sys.executable, "-m", "pip", "install", "-r", str(requirements)])
    if code:
        print("[-] Dependency installation failed. Check the pip output above.")
        return code
    print("[+] Core Python dependencies installed.")
    if shutil.which("nmap"):
        print("[i] Optional nmap detected; external-tool scans remain disabled in Safe Mode.")
    else:
        print("[i] Optional nmap not installed; all built-in scanners remain available.")
    if shutil.which("sslyze"):
        print("[i] Optional sslyze detected; use only in an authorized environment and outside Safe Mode.")
    else:
        print("[i] Optional sslyze not installed; native TLS checks remain available.")
    print("[i] Run tests with: python -m unittest discover -s tests -v")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
