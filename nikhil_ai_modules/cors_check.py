"""Low-impact CORS behavior check using a non-existent test origin."""
from __future__ import annotations

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import sanitize_url
from nikhil_ai_modules.output import good, header, info, kv, section, warn

TEST_ORIGIN = "https://untrusted.invalid"


def _apply_test_origin(headers, test_origin):
    previous = headers.get("Origin")
    headers["Origin"] = test_origin
    return ("replaced", previous) if previous else ("added", None)


def analyze_cors(status_code: int, response_headers, test_origin: str = TEST_ORIGIN) -> dict:
    headers = {str(key).lower(): str(value) for key, value in response_headers.items()}
    acao = headers.get("access-control-allow-origin")
    credentials = headers.get("access-control-allow-credentials", "")
    reflected = bool(acao and acao.strip().lower() == test_origin.lower())
    wildcard = bool(acao and acao.strip() == "*")
    null_origin = bool(acao and acao.strip().lower() == "null")
    risky = wildcard or reflected or null_origin
    credentialed_reflection = reflected and credentials.strip().lower() == "true"
    return {
        "status": status_code,
        "headers": {
            "Access-Control-Allow-Origin": acao,
            "Access-Control-Allow-Credentials": credentials or None,
            "Access-Control-Allow-Methods": headers.get("access-control-allow-methods"),
            "Access-Control-Allow-Headers": headers.get("access-control-allow-headers"),
            "Access-Control-Expose-Headers": headers.get("access-control-expose-headers"),
        },
        "test_origin": test_origin,
        "wildcard": wildcard,
        "reflected_origin": reflected,
        "null_origin": null_origin,
        "credentials": credentials.strip().lower() == "true",
        "vulnerable": "Permissive origin behavior observed; manual review required" if risky else None,
        "confidence": "HIGH" if credentialed_reflection else "MEDIUM" if risky else "LOW",
    }


def check_cors(target, context=None):
    ctx = resolve_context(context)
    headers = {"Origin": TEST_ORIGIN, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
    response = ctx.http.get(target, headers=headers)
    result = analyze_cors(response.status_code, response.headers)
    result.update({"target": sanitize_url(response.url), "potential_findings": []})
    header("CORS Misconfiguration Check")
    info(f"Target: {sanitize_url(response.url)}")
    section("CORS Header Analysis")
    kv("HTTP Status", response.status_code)
    for name, value in result["headers"].items():
        if value:
            kv(name, value)
    if result["vulnerable"]:
        warn(result["vulnerable"])
        result["potential_findings"].append({
            "title": "Potentially permissive CORS policy",
            "category": "CORS",
            "target": response.url,
            "endpoint": response.url,
            "severity": "MEDIUM" if result["credentials"] and result["reflected_origin"] else "LOW",
            "confidence": result["confidence"],
            "description": "The response accepted a non-existent test origin. Actual impact depends on browser behavior, credentials, and the sensitivity of the resource.",
            "evidence": f"Access-Control-Allow-Origin={result['headers'].get('Access-Control-Allow-Origin')!r}; credentials={result['credentials']}; test origin={TEST_ORIGIN}.",
            "observed_behavior": result["vulnerable"],
            "reproduction_notes": "Repeat with a researcher-controlled origin and verify in a browser using an authorized test account. No data was exfiltrated.",
            "remediation": "Allow only explicitly trusted origins; avoid reflecting arbitrary Origin values and review credentialed CORS responses.",
            "status": "NEEDS_REVIEW",
            "request_method": "GET",
            "response_headers": response.headers,
            "status_code": response.status_code,
            "response_size": getattr(response, "_nikhil_response_size", len(response.content)),
        })
    else:
        good("No permissive CORS acceptance pattern observed")
    return result
