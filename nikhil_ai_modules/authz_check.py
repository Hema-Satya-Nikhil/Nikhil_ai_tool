"""Read-only comparison using two researcher-controlled test accounts."""
from __future__ import annotations

import hashlib

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import sanitize_url
from nikhil_ai_modules.output import header, info, section, warn
from nikhil_ai_modules.scope import ScopeError, normalize_url


def compare_test_accounts(resource_url, context=None, *, account_a_token=None, account_b_token=None, confirmed=False):
    ctx = resolve_context(context)
    url = normalize_url(resource_url)
    if not confirmed:
        raise ScopeError("Authorization comparison requires confirmation that both accounts and the resource are researcher-controlled")
    if not account_a_token or not account_b_token:
        raise ValueError("Two test-account bearer tokens are required; they are used in-memory only")
    headers_a = {"Authorization": "Bearer " + str(account_a_token)}
    headers_b = {"Authorization": "Bearer " + str(account_b_token)}
    response_a = ctx.http.get(url, headers=headers_a)
    response_b = ctx.http.get(url, headers=headers_b)
    digest_a = hashlib.sha256(response_a.content).digest()
    digest_b = hashlib.sha256(response_b.content).digest()
    same_content = digest_a == digest_b
    account_a_access = 200 <= response_a.status_code < 300
    account_b_access = 200 <= response_b.status_code < 300
    suspicious = account_a_access and account_b_access and same_content
    findings = []
    if suspicious:
        warn("Potential Broken Access Control / IDOR / BOLA — manual confirmation required")
        findings.append({
            "title": "Potential Broken Access Control / IDOR / BOLA",
            "category": "Authorization Testing",
            "target": sanitize_url(url), "endpoint": sanitize_url(url),
            "severity": "MEDIUM", "confidence": "MEDIUM",
            "description": "A resource created for test account A returned a successful response with identical content to test account B. Confirm both identities, resource ownership, and intended sharing rules.",
            "evidence": f"Account A HTTP {response_a.status_code}; account B HTTP {response_b.status_code}; response bodies matched by in-memory comparison. No response body or credential was stored.",
            "observed_behavior": "Both researcher-controlled accounts received the same successful representation of the test resource.",
            "reproduction_notes": "Repeat only with a resource explicitly created for Account A and the two controlled accounts. Do not substitute unrelated users' resource IDs.",
            "remediation": "Enforce server-side ownership/authorization checks for each object and operation.",
            "status": "NEEDS_REVIEW", "request_method": "GET", "status_code": response_b.status_code,
            "response_size": getattr(response_b, "_nikhil_response_size", len(response_b.content)),
            "response_excerpt": "Response body intentionally not stored.",
        })
    header("Authorization / IDOR Test Assistant")
    section("Two-account read-only comparison")
    info(f"Account A: HTTP {response_a.status_code}; Account B: HTTP {response_b.status_code}")
    info(f"Responses {'matched' if same_content else 'differed'} by in-memory content comparison; body was not displayed or stored")
    if not suspicious:
        warn("No likely authorization inconsistency was observed; this does not prove the resource is correctly protected.")
    return {
        "target": sanitize_url(url),
        "account_a_status": response_a.status_code,
        "account_b_status": response_b.status_code,
        "same_content": same_content,
        "potential_findings": findings,
        "credentials_retained": False,
    }
