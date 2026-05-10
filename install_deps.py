#!/usr/bin/env python3
"""Cross-platform dependency installer for NIKHIL AI."""

import shutil
import subprocess
import sys
from pathlib import Path


def run(cmd):
    print(f"[i] Running: {' '.join(cmd)}")
    return subprocess.run(cmd, check=False).returncode


def main():
    root = Path(__file__).resolve().parent
    req = root / "requirements.txt"

    if not req.exists():
        print("[!] requirements.txt not found.")
        return 1

    code = run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--upgrade",
            "--force-reinstall",
            "-r",
            str(req),
        ]
    )
    if code != 0:
        print("[!] Python dependency install failed.")
        return code

    print("[+] Core Python dependencies installed/reinstalled successfully.")

    if shutil.which("nmap"):
        print("[+] nmap detected on system.")
    else:
        print("[!] nmap not found (optional but recommended for SSL module deep scan).")
        print("    Kali/Debian: sudo apt install nmap")
        print("    Windows: https://nmap.org/download.html")

    if shutil.which("sslyze"):
        print("[+] sslyze CLI detected on system.")
    else:
        print("[i] sslyze CLI not detected (optional).")
        print(f"    Install via: {sys.executable} -m pip install --upgrade --force-reinstall sslyze")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
