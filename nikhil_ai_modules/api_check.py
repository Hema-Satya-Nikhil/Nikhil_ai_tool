"""Read-only API surface review (GET + OPTIONS only)."""
from __future__ import annotations

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import redact_headers, sanitize_url
from nikhil_ai_modules.output import header, info, section, warn
from nikhil_ai_modules.scope import normalize_url


def analyze_api_response(url, status_code, headers, body="", options_headers=None, options_status=None):
    response_headers = {str(key).lower(): str(value) for key, value in headers.items()}
    options = {str(key).lower(): str(value) for key, value in (options_headers or {}).items()}
    content_type = response_headers.get("content-type", "")
    body_lower = (body or "").lower()
    parsed = {
        "url": sanitize_url(url),
        "status_code": status_code,
        "content_type": content_type,
        "json_endpoint": "json" in content_type.lower() or body_lower.lstrip().startswith(("{", "[")),
        "graphql_indicator": "graphql" in url.lower() or "graphql" in body_lower[:10000],
        "openapi_indicator": any(token in body_lower[:20000] for token in ("openapi", "swagger")) or "openapi" in url.lower() or "swagger" in url.lower(),
        "authentication_signal": status_code in (401, 403) or "www-authenticate" in response_headers,
        "allowed_methods": [method.strip() for method in options.get("allow", "").split(",") if method.strip()],
        "options_status": options_status,
        "rate_limit_headers": {key: value for key, value in response_headers.items() if "ratelimit" in key or "rate-limit" in key or key == "retry-after"},
        "response_headers": redact_headers(headers),
        "options_headers": redact_headers(options_headers or {}),
    }
    return parsed


def analyze_api(target, context=None):
    ctx = resolve_context(context)
    url = normalize_url(target)
    response = ctx.http.get(url, headers={"Accept": "application/json,*/*;q=0.8"})
    try:
        options = ctx.http.options(response.url)
        options_headers = options.headers
        options_status = options.status_code
    except Exception:
        options_headers, options_status = {}, None
    result = analyze_api_response(response.url, response.status_code, response.headers, response.text[:20000], options_headers, options_status)
    result.update({
        "target": sanitize_url(url),
        "potential_findings": [],
        "note": "Only GET and OPTIONS were used. Mutating methods and GraphQL introspection were not attempted.",
    })
    header("API Security Analysis")
    section("Read-only Signals")
    info(f"HTTP status: {response.status_code}; content type: {result['content_type'] or 'not set'}")
    if result["authentication_signal"]:
        info("Authentication-required response signal observed")
    if result["graphql_indicator"]:
        info("GraphQL indicator observed; introspection not attempted")
    if result["openapi_indicator"]:
        info("Swagger/OpenAPI indicator observed")
    if result["allowed_methods"]:
        warn("OPTIONS Allow header: " + ", ".join(result["allowed_methods"]))
    if result["rate_limit_headers"]:
        info("Rate-limit response headers observed")
    return result
