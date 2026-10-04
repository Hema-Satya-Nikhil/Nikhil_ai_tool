"""Safe optional-tool discovery and bounded subprocess helpers."""
from __future__ import annotations

import shutil
import subprocess
import threading
from dataclasses import dataclass
from typing import Iterable

from nikhil_ai_modules.evidence import redact_text


@dataclass(frozen=True)
class ToolSpec:
    key: str
    binary: str
    display_name: str
    version_args: tuple[str, ...]
    default_enabled: bool = False
    safe_mode_policy: str = "inventory_only"
    description: str = ""


TOOLS = (
    ToolSpec("nmap", "nmap", "Nmap", ("--version",), False, "explicit_conservative_scan", "Conservative TCP/service inventory; no NSE scripts."),
    ToolSpec("subfinder", "subfinder", "Subfinder", ("-version",), False, "passive_only", "Passive subdomain candidate source; candidates are scope-filtered."),
    ToolSpec("amass", "amass", "Amass", ("-version",), False, "passive_only", "Passive enumeration adapter; active modes are not enabled."),
    ToolSpec("httpx", "httpx", "httpx", ("-version",), False, "native_client_only", "Use the shared scoped HTTP client for requests; binary probing is not invoked."),
    ToolSpec("dnsx", "dnsx", "dnsx", ("-version",), False, "scope_checked_dns_only", "DNS resolution is performed through the shared Scope Guard."),
    ToolSpec("whatweb", "whatweb", "WhatWeb", ("--version",), False, "inventory_only", "Binary is detected; network requests remain on native scoped probes."),
    ToolSpec("sslyze", "sslyze", "SSLyze", ("--version",), False, "inventory_only", "Native TLS checks are used unless an independently scoped adapter is configured."),
    ToolSpec("nuclei", "nuclei", "Nuclei", ("-version",), False, "disabled_safe_mode", "Template execution is disabled in Safe Mode; no arbitrary template runs."),
)


def _version(binary: str, args: Iterable[str]) -> str:
    if not shutil.which(binary):
        return ""
    try:
        _code, output, _error = run_bounded([binary, *args], timeout=3, max_output=4000)
        return redact_text(output.strip().splitlines()[0] if output.strip() else "available", 180)
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return "version unavailable"


def integration_status(config=None):
    config = config or {}
    enabled = config.get("enabled_integrations", {})
    result = []
    for tool in TOOLS:
        path = shutil.which(tool.binary)
        result.append({
            "key": tool.key,
            "name": tool.display_name,
            "binary": tool.binary,
            "installed": bool(path),
            "path": path or "",
            "version": _version(tool.binary, tool.version_args) if path else "",
            "enabled": bool(enabled.get(tool.key, tool.default_enabled)) if isinstance(enabled, dict) else False,
            "policy": tool.safe_mode_policy,
            "description": tool.description,
        })
    return result


def run_bounded(command: list[str], *, timeout: int = 60, max_output: int = 1_000_000):
    """Run an argv vector with a hard timeout and bounded in-memory stdout/stderr."""
    if not isinstance(command, list) or not command or any(not isinstance(arg, str) or "\x00" in arg for arg in command):
        raise ValueError("Invalid subprocess argument vector")
    if not isinstance(max_output, int) or max_output < 1:
        raise ValueError("max_output must be a positive integer")
    executable = shutil.which(command[0])
    if not executable:
        raise FileNotFoundError(f"Optional tool not installed: {command[0]}")
    safe_timeout = max(1, min(int(timeout), 180))
    stdout_limit = max_output
    stderr_limit = min(max_output, 200_000)
    process = subprocess.Popen(
        [executable, *command[1:]], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
        close_fds=True, bufsize=0,
    )
    assert process.stdout is not None and process.stderr is not None
    stdout_buffer, stderr_buffer = bytearray(), bytearray()
    truncated = {"stdout": False, "stderr": False}

    def drain(stream, buffer, limit, key):
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            room = max(0, limit - len(buffer))
            if room:
                buffer.extend(chunk[:room])
            if len(chunk) > room:
                truncated[key] = True

    readers = [
        threading.Thread(target=drain, args=(process.stdout, stdout_buffer, stdout_limit, "stdout"), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr_buffer, stderr_limit, "stderr"), daemon=True),
    ]
    try:
        for reader in readers:
            reader.start()
        try:
            return_code = process.wait(timeout=safe_timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        for reader in readers:
            reader.join(timeout=2)
        if any(reader.is_alive() for reader in readers):
            process.kill()
            raise RuntimeError("Optional tool output streams did not close")
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        for reader in readers:
            if reader.ident is not None:
                reader.join(timeout=2)
        raise
    finally:
        process.stdout.close()
        process.stderr.close()
    stdout = bytes(stdout_buffer).decode("utf-8", "replace")
    stderr = bytes(stderr_buffer).decode("utf-8", "replace")
    if truncated["stdout"]:
        stdout += "\n[stdout truncated at configured limit]"
    if truncated["stderr"]:
        stderr += "\n[stderr truncated at configured limit]"
    return return_code, redact_text(stdout, stdout_limit + 128), redact_text(stderr, stderr_limit + 128)
