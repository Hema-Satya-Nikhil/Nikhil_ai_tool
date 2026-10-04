"""Strictly passive command-injection indicators; never sends shell syntax."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import SENSITIVE_KEY, sanitize_url
from nikhil_ai_modules.output import header, info, warn
from nikhil_ai_modules.scope import normalize_url

SHELL_ERRORS = (
    re.compile(r"/bin/(?:ba)?sh:|sh: .* not found|command not found", re.I),
    re.compile(r"cmd\.exe|CreateProcess.*failed|is not recognized as an internal or external command", re.I),
    re.compile(r"shell_exec\(\).*disabled|ProcessBuilder.*Exception", re.I),
)
PARAM_HINTS = {"cmd", "command", "exec", "ping", "host", "ip", "lookup", "utility"}


def detect_command_injection_signals(target, context=None):
    ctx = resolve_context(context)
    url = normalize_url(target)
    response = ctx.http.get(url)
    text = response.text[:300000]
    error_labels = [pattern.pattern for pattern in SHELL_ERRORS if pattern.search(text)]
    params = [key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True) if not SENSITIVE_KEY.search(key)]
    candidates = [key for key in params if key.lower() in PARAM_HINTS or any(hint in key.lower() for hint in ("command", "exec", "host", "ping"))]
    findings = []
    if error_labels and candidates:
        warn("Potential command-execution error signal observed; no command payload was sent.")
        findings.append({
            "title": "Potential command injection behavior",
            "category": "Command Injection Detection",
            "target": sanitize_url(url), "endpoint": sanitize_url(url), "parameter": candidates[0],
            "severity": "LOW", "confidence": "LOW",
            "description": "A shell/command-style error appeared in a normal baseline response for an operation-like parameter. This can be unrelated application text and is not proof of command execution.",
            "evidence": f"Baseline response matched {len(error_labels)} command-error indicator(s); no shell payload was sent.",
            "observed_behavior": "A command execution error signature appeared in an ordinary response.",
            "reproduction_notes": "Validate only in an isolated authorized lab with a harmless application-specific check; do not use shell metacharacters or OS commands.",
            "remediation": "Avoid shell invocation where possible; use fixed argument arrays, strict allowlists, and never concatenate user input into commands.",
            "status": "NEEDS_REVIEW", "request_method": "GET", "status_code": response.status_code,
            "response_size": getattr(response, "_nikhil_response_size", len(response.content)),
            "response_excerpt": "Error body withheld; only indicator labels retained.",
        })
    header("Command Injection Detection Assistant")
    info("Passive inspection only. No shell metacharacters, commands, or blind callbacks were used.")
    info(f"Operation-like parameters: {', '.join(candidates) if candidates else 'none identified'}")
    info(f"Command error indicators: {len(error_labels)}")
    return {"target": sanitize_url(url), "candidate_parameters": candidates, "error_indicators": error_labels,
            "status_code": response.status_code, "potential_findings": findings}
