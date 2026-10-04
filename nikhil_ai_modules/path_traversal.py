"""Path/file parameter inventory without traversal payloads or file retrieval."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import SENSITIVE_KEY, sanitize_url
from nikhil_ai_modules.output import header, info, warn
from nikhil_ai_modules.scope import normalize_url

FILE_HINTS = ("file", "path", "folder", "dir", "document", "download", "template", "include", "view", "page", "filename")


def detect_path_parameters(target, context=None):
    ctx = resolve_context(context)
    url = normalize_url(target)
    parsed = urlsplit(url)
    params = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if not SENSITIVE_KEY.search(key)]
    candidates = [key for key in params if any(hint in key.lower() for hint in FILE_HINTS)]
    response = ctx.http.get(url)
    # This check intentionally sends only the unmodified baseline request.
    findings = []
    header("Path Traversal Detection Assistant")
    info("Read-only baseline inspection; no ../ payloads or sensitive file paths were requested.")
    if candidates:
        for name in candidates:
            warn(f"File/path-like parameter observed: {name} — manual validation required")
    else:
        info("No file/path-like query parameter was identified.")
    info(f"Baseline status: {response.status_code}")
    return {
        "target": sanitize_url(url), "endpoint": sanitize_url(url), "candidate_parameters": candidates,
        "status_code": response.status_code, "manual_validation_required": True,
        "note": "Automated output is an endpoint lead only; no traversal test was performed.",
        "potential_findings": findings,
    }
