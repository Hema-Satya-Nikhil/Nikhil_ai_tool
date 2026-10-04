"""NoSQL injection detection assistant; passive signals only by default."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import SENSITIVE_KEY, sanitize_url
from nikhil_ai_modules.output import header, info, warn
from nikhil_ai_modules.scope import normalize_url

ERROR_PATTERNS = (
    re.compile(r"MongoServerError|MongoError|BSONTypeError|CastError", re.I),
    re.compile(r"\$where.*(?:error|exception)|unknown operator.*\$", re.I),
    re.compile(r"document query failed|failed to parse.*json query", re.I),
)


def detect_nosql_signals(target, context=None):
    ctx = resolve_context(context)
    url = normalize_url(target)
    response = ctx.http.get(url)
    text = response.text[:300000]
    indicators = [pattern.pattern for pattern in ERROR_PATTERNS if pattern.search(text)]
    parameters = [key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True) if not SENSITIVE_KEY.search(key)]
    candidate_params = [key for key in parameters if any(term in key.lower() for term in ("filter", "query", "where", "search", "user", "id"))]
    findings = []
    if indicators and candidate_params:
        warn("Potential NoSQL Injection signal in baseline response; no operator payload was sent.")
        findings.append({
            "title": "Potential NoSQL Injection",
            "category": "NoSQL Injection Detection",
            "target": sanitize_url(url),
            "endpoint": sanitize_url(url),
            "parameter": candidate_params[0],
            "severity": "LOW",
            "confidence": "LOW",
            "description": "A database/parser-style error appeared in an ordinary baseline response alongside a query-like parameter. No injection operator was sent.",
            "evidence": f"Baseline response included {len(indicators)} NoSQL-style indicator(s); candidate parameter names: {', '.join(candidate_params[:10])}.",
            "observed_behavior": "A NoSQL/database parser error indicator appeared in the response.",
            "reproduction_notes": "Manually validate only with a non-production test account and a controlled test resource; never enumerate documents or databases.",
            "remediation": "Use typed query construction, strict schema validation, and generic error responses.",
            "status": "NEEDS_REVIEW", "request_method": "GET", "status_code": response.status_code,
            "response_size": getattr(response, "_nikhil_response_size", len(response.content)),
            "response_excerpt": "Error body withheld; only indicator labels retained.",
        })
    header("NoSQL Injection Detection Assistant")
    info("Passive baseline inspection only; no NoSQL operators or data-changing inputs were sent.")
    info(f"Candidate parameter names: {', '.join(candidate_params) if candidate_params else 'none identified'}")
    info(f"NoSQL-style error indicators: {len(indicators)}")
    return {
        "target": sanitize_url(url), "endpoint": sanitize_url(url), "candidate_parameters": candidate_params,
        "error_indicators": indicators, "status_code": response.status_code,
        "manual_validation_required": True, "potential_findings": findings,
    }
