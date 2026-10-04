"""Passive Amass adapter. Active brute-force/discovery modes are never invoked."""
from __future__ import annotations

import shutil

from nikhil_ai_modules.integrations.base import run_bounded
from nikhil_ai_modules.scope import ScopeError, normalize_host


def enumerate_passive(context, seed, *, confirmed_authorization=False):
    if not confirmed_authorization:
        raise ScopeError("Amass requires explicit authorization confirmation")
    if not context.config.get("enabled_integrations", {}).get("amass", False):
        raise ScopeError("Amass is not enabled in local integration settings")
    if not shutil.which("amass"):
        raise FileNotFoundError("Amass is not installed")
    domain = normalize_host(str(seed).strip().lstrip("*."))
    wildcard_authorized = any(rule == f"*.{domain}" for rule in context.scope.in_scope)
    if not context.scope.is_in_scope(domain) and not wildcard_authorized:
        raise ScopeError("Passive enumeration seed is not covered by the current scope")
    code, stdout, stderr = run_bounded(["amass", "enum", "-passive", "-d", domain, "-timeout", "1"], timeout=90, max_output=500_000)
    if code != 0:
        raise RuntimeError("Amass passive enumeration failed: " + (stderr[:250] or f"exit {code}"))
    found, skipped = set(), 0
    for line in stdout.splitlines()[:5000]:
        try:
            host = normalize_host(line.strip())
        except ValueError:
            continue
        try:
            context.scope.require_host_rule(host)
            found.add(host)
        except ScopeError:
            skipped += 1
    rows = [{"host": host, "status": "DISCOVERED", "source": "amass passive"} for host in sorted(found)[:1000]]
    return {"seed": domain, "source": "amass passive", "subdomains": rows, "assets": rows, "skipped_out_of_scope": skipped, "potential_findings": []}
