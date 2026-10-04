"""Conservative SQL-injection signal checks (no extraction or time payloads)."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import QUERY_SECRET_KEY, SENSITIVE_KEY, sanitize_url
from nikhil_ai_modules.output import header, info, section, warn
from nikhil_ai_modules.scope import normalize_url

SQL_ERROR_PATTERNS = (
    ("generic SQL syntax error", re.compile(r"sql syntax|syntax error.*sql|unterminated quoted string", re.I)),
    ("database error detail", re.compile(r"mysql_fetch|mysqli_|postgresql.*error|ora-\d{4,}|sqlite_error|sqlstate\[", re.I)),
    ("ORM/database parser error", re.compile(r"sequelize.*error|prisma.*error|invalid.*query", re.I)),
)


def _mutating_path(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(part in path for part in ("delete", "remove", "logout", "purchase", "checkout", "payment", "reset", "update", "create", "transfer", "unsubscribe"))


def _safe_url_with_query(url, pairs):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(pairs, doseq=True), ""))


def detect_sqli(target, context=None, *, max_parameters: int = 3, confirm_read_only: bool = False):
    ctx = resolve_context(context)
    url = normalize_url(target)
    if not confirm_read_only:
        return {"target": sanitize_url(url), "tested": [], "confirmation_required": "Researcher must confirm this is a read-only endpoint before any test request.", "potential_findings": []}
    if _mutating_path(url):
        return {"target": sanitize_url(url), "tested": [], "skipped": "Path appears state-changing; safe check not run.", "potential_findings": []}
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    candidates = [
        (key, value) for key, value in query
        if not SENSITIVE_KEY.search(key) and not QUERY_SECRET_KEY.fullmatch(key)
    ][:max(1, min(int(max_parameters), 5))]
    results = []
    findings = []
    if not candidates:
        info("No non-sensitive query parameter was available; no injection payload was sent.")
        return {"target": sanitize_url(url), "tested": [], "note": "Supply an in-scope read-only URL with a researcher-selected candidate parameter for controlled comparison.", "potential_findings": []}

    header("SQL Injection Detection Assistant")
    section("Controlled Non-destructive Comparison")
    baseline = ctx.http.get(url)
    baseline_text = baseline.text[:500000]
    for key, value in candidates:
        altered = list(query)
        replaced = False
        for index, (current_key, current_value) in enumerate(altered):
            if current_key == key and not replaced:
                altered[index] = (current_key, current_value + "'")
                replaced = True
        probe_url = _safe_url_with_query(url, altered)
        response = ctx.http.get(probe_url)
        body = response.text[:500000]
        matched = [label for label, pattern in SQL_ERROR_PATTERNS if pattern.search(body)]
        length_delta = abs(len(body) - len(baseline_text))
        relative_delta = length_delta / max(1, len(baseline_text))
        status_changed = response.status_code != baseline.status_code
        changed = status_changed or relative_delta >= 0.20
        confidence = "HIGH" if matched and changed else "MEDIUM" if matched else "LOW"
        result = {
            "parameter": key,
            "baseline_status": baseline.status_code,
            "test_status": response.status_code,
            "response_length_delta": length_delta,
            "status_changed": status_changed,
            "database_error_indicators": matched,
            "confidence": confidence,
            "manual_validation_required": True,
        }
        results.append(result)
        info(f"Parameter {key}: status {baseline.status_code} -> {response.status_code}; length delta {length_delta}; error indicators {len(matched)}")
        if matched or changed:
            warn("Potential SQL Injection signal — manual validation required")
            findings.append({
                "title": "Potential SQL Injection",
                "category": "SQL Injection Detection",
                "target": sanitize_url(url),
                "endpoint": sanitize_url(url),
                "parameter": key,
                "severity": "MEDIUM" if matched else "INFO",
                "confidence": confidence,
                "description": "A single quote-only input produced a response difference or database-style error indicator. This is not proof of SQL injection; application validation and normal error handling can cause differences.",
                "evidence": f"Parameter {key} compared with a baseline; HTTP {baseline.status_code} vs {response.status_code}; response length delta {length_delta}; matched indicator labels: {', '.join(matched) or 'none'}.",
                "observed_behavior": "Response changed after a quote-only test input." if changed else "Database-style error text was detected after a quote-only input.",
                "reproduction_notes": "Repeat only in an authorized test environment and manually validate with a harmless, application-specific test. No database data was retrieved or modified.",
                "remediation": "Use parameterized queries, strict input handling, and generic client-facing error responses.",
                "status": "NEEDS_REVIEW",
                "request_method": "GET",
                "status_code": response.status_code,
                "response_size": getattr(response, "_nikhil_response_size", len(response.content)),
                "response_excerpt": "Database error content intentionally not retained.",
            })
    return {"target": sanitize_url(url), "tested": results, "potential_findings": findings}
