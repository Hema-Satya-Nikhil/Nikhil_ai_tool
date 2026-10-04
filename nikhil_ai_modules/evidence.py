"""Evidence sanitization and persistence.

Credentials, cookies, token-like values and common personal identifiers are
redacted before anything reaches logs, SQLite, or a report.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_KEY = re.compile(r"(pass(word)?|credential|bearer|\bauth(?:entication)?\b|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|session|private[_-]?key|client[_-]?secret|signature|\bsig\b|oauth|\bkey\b)", re.I)
QUERY_SECRET_KEY = re.compile(r"^(?:code|state|oauth[_-]?(?:code|state|token|verifier))$", re.I)
PATH_SECRET_SEGMENT_RE = re.compile(
    r"(?i)(/(?:api[_-]?key|access[_-]?token|refresh[_-]?token|oauth(?:[_-]?(?:code|token|verifier))?|token|secret|client[_-]?secret|password|passwd|credential|credentials|session(?:[_-]?id)?|reset[_-]?token|password[_-]?reset|signature|sig)/)([^/?#]+)"
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")
COMMON_TOKEN_RE = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\b")
ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|credential|credentials|bearer|auth(?:entication)?|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|cookie|set-cookie|session(?:[_-]?id)?|state|(?<![A-Za-z0-9_-])code|oauth[_-]?code)\b\s*[=:]\s*)"
    r"(['\"]?)[^\s,;\"']+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.I | re.S)
URL_IN_TEXT_RE = re.compile(r"""https?://[^\s<>"']+""", re.I)
MAX_EXCERPT = 1600


def sanitize_url(url: str) -> str:
    try:
        parsed = urlsplit(str(url))
        safe_query = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            sensitive = SENSITIVE_KEY.search(key) or QUERY_SECRET_KEY.fullmatch(key)
            safe_query.append((key, "[REDACTED]" if sensitive else value))
        safe_path = PATH_SECRET_SEGMENT_RE.sub(r"\1%5BREDACTED%5D", parsed.path)
        safe_path = PRIVATE_KEY_RE.sub("%5BREDACTED%20PRIVATE%20KEY%5D", safe_path)
        safe_path = BEARER_RE.sub(lambda match: match.group(1) + "%20%5BREDACTED%5D", safe_path)
        safe_path = JWT_RE.sub("%5BREDACTED%5D", safe_path)
        safe_path = COMMON_TOKEN_RE.sub("%5BREDACTED%5D", safe_path)
        safe_path = ASSIGNMENT_RE.sub(lambda match: match.group(1) + "%5BREDACTED%5D", safe_path)
        netloc = parsed.hostname or ""
        if ":" in netloc and not netloc.startswith("["):
            netloc = f"[{netloc}]"
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, safe_path, urlencode(safe_query), ""))
    except (ValueError, TypeError):
        return "[URL REDACTED]"


def redact_text(value: Any, limit: int = MAX_EXCERPT) -> str:
    text = str(value or "")
    text = URL_IN_TEXT_RE.sub(lambda match: sanitize_url(match.group(0)), text)
    text = PATH_SECRET_SEGMENT_RE.sub(r"\1%5BREDACTED%5D", text)
    text = PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = BEARER_RE.sub(lambda m: m.group(1) + " [REDACTED]", text)
    text = JWT_RE.sub("[REDACTED TOKEN]", text)
    text = COMMON_TOKEN_RE.sub("[REDACTED TOKEN]", text)
    text = ASSIGNMENT_RE.sub(lambda m: m.group(1) + "[REDACTED]", text)
    text = EMAIL_RE.sub("[REDACTED EMAIL]", text)
    # Common JSON/form values even when their key uses camelCase.
    text = re.sub(
        r'(?i)(["\']?(?:password|token|secret|credential|credentials|bearer|auth|apiKey|accessKey|cookie|set-cookie|session[_-]?id|state|(?<![A-Za-z0-9_-])code(?![A-Za-z0-9_-]))["\']?\s*:\s*["\'])[^"\']*(["\'])',
        r"\1[REDACTED]\2", text,
    )
    return text[:limit] + ("…[truncated]" if len(text) > limit else "")


def redact_headers(headers: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    safe: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        name = str(key)
        if SENSITIVE_KEY.search(name) or name.lower() in {"set-cookie", "proxy-authenticate"}:
            safe[name] = "[REDACTED]"
        else:
            safe[name] = redact_text(value, 400)
    return safe


def sanitize_value(value: Any, key: str = "") -> Any:
    if isinstance(value, Mapping):
        output = {}
        for field_name, child in value.items():
            field_key = str(field_name)
            output[field_key] = "[REDACTED]" if SENSITIVE_KEY.search(field_key) else sanitize_value(child, field_key)
        return output
    if isinstance(value, (list, tuple)):
        return [sanitize_value(item, key) for item in value]
    if isinstance(value, str):
        if key.lower() in {"target", "endpoint", "url", "requested_url", "final_url", "location"} and "://" in value:
            return sanitize_url(value)
        return redact_text(value)
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return redact_text(value)


class EvidenceStore:
    def __init__(self, database, project_id: int):
        self.database = database
        self.project_id = project_id

    def record(
        self,
        *,
        target: str,
        endpoint: Optional[str] = None,
        request_method: Optional[str] = None,
        request: Optional[Mapping[str, Any]] = None,
        response_headers: Optional[Mapping[str, Any]] = None,
        response_excerpt: str = "",
        status_code: Optional[int] = None,
        response_size: Optional[int] = None,
        evidence_description: str = "",
        finding_id: Optional[str] = None,
        scan_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": sanitize_url(target) if "://" in str(target) else redact_text(target, 300),
            "endpoint": sanitize_url(endpoint) if endpoint and "://" in endpoint else (redact_text(endpoint, 300) if endpoint else None),
            "request_method": str(request_method or "")[:12].upper() or None,
            "sanitized_request": sanitize_value(request or {}),
            "response_headers": redact_headers(response_headers),
            "response_excerpt": redact_text(response_excerpt),
            "status_code": status_code,
            "response_size": response_size,
            "evidence_description": redact_text(evidence_description, 500),
            "finding_id": finding_id,
            "scan_id": scan_id,
        }
        self.database.add_evidence(self.project_id, record)
        return record
