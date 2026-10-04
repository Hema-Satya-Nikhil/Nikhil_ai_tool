"""HTTP security-header inspection with structured output."""
from __future__ import annotations

import re
from typing import Dict, Mapping

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import sanitize_url
from nikhil_ai_modules.output import good, header, info, kv, section, warn

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def analyze_headers(response_headers: Mapping[str, str], is_https: bool = True) -> Dict:
    headers = {str(key).lower(): str(value) for key, value in response_headers.items()}
    present = {name: headers[name.lower()] for name in REQUIRED_HEADERS if name.lower() in headers}
    required = [name for name in REQUIRED_HEADERS if is_https or name != "Strict-Transport-Security"]
    missing = [name for name in required if name.lower() not in headers]

    csp = headers.get("content-security-policy", "")
    csp_issues = []
    if csp:
        lowered = csp.lower()
        if "unsafe-inline" in lowered:
            csp_issues.append("uses 'unsafe-inline'")
        if "unsafe-eval" in lowered:
            csp_issues.append("uses 'unsafe-eval'")
        if "default-src" not in lowered:
            csp_issues.append("missing default-src baseline")
        if re.search(r"(?:default-src|script-src)\s+[^;]*\*", lowered):
            csp_issues.append("contains a wildcard source")

    hsts = headers.get("strict-transport-security", "")
    hsts_data = {"max_age": None, "include_subdomains": False, "preload": False, "strength": "missing"}
    if hsts:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        max_age = int(match.group(1)) if match else 0
        include_subdomains = bool(re.search(r"\bincludeSubDomains\b", hsts, re.I))
        preload = bool(re.search(r"\bpreload\b", hsts, re.I))
        strength = "strong" if max_age >= 31536000 and include_subdomains else (
            "medium" if max_age >= 15552000 else "weak"
        )
        hsts_data = {
            "max_age": max_age or None,
            "include_subdomains": include_subdomains,
            "preload": preload,
            "strength": strength,
        }
    return {
        "present": present,
        "missing": missing,
        "csp": {"present": bool(csp), "issues": csp_issues, "strength": "weak" if csp_issues else ("configured" if csp else "missing")},
        "hsts": hsts_data,
    }


def check_headers(target, context=None):
    ctx = resolve_context(context)
    response = ctx.http.get(target)
    result = analyze_headers(response.headers, response.url.lower().startswith("https://"))
    result.update({"target": sanitize_url(response.url), "status_code": response.status_code, "potential_findings": []})

    header("HTTP Security Headers Scan")
    info(f"Target: {sanitize_url(response.url)}")
    kv("HTTP Status", response.status_code)
    section("Security Header Analysis")
    for name in REQUIRED_HEADERS:
        if name in result["present"]:
            good(f"{name} present")
        elif name == "Strict-Transport-Security" and not response.url.lower().startswith("https://"):
            info("HSTS is evaluated only after HTTPS is used")
        else:
            warn(f"{name} missing")
            result["potential_findings"].append({
                "title": f"Missing HTTP Security Header: {name}",
                "category": "HTTP Security Headers",
                "target": response.url,
                "endpoint": response.url,
                "severity": "LOW",
                "confidence": "HIGH",
                "description": f"The response did not include {name}. Confirm that this is appropriate for the application before treating it as a vulnerability.",
                "evidence": f"HTTP {response.status_code} response omitted {name}.",
                "observed_behavior": f"{name} was absent from the response headers.",
                "remediation": f"Review the application and configure an appropriate {name} policy.",
                "status": "NEEDS_REVIEW",
                "request_method": "GET",
                "response_headers": response.headers,
                "status_code": response.status_code,
                "response_size": getattr(response, "_nikhil_response_size", len(response.content)),
            })
    section("Header Strength Review")
    if result["csp"]["present"]:
        if result["csp"]["issues"]:
            warn("CSP may be permissive: " + ", ".join(result["csp"]["issues"]))
            result["potential_findings"].append({
                "title": "Potentially weak Content-Security-Policy",
                "category": "HTTP Security Headers",
                "target": response.url,
                "endpoint": response.url,
                "severity": "LOW",
                "confidence": "MEDIUM",
                "description": "The Content-Security-Policy contains one or more patterns that may weaken its protection.",
                "evidence": "; ".join(result["csp"]["issues"]),
                "observed_behavior": "Potentially permissive CSP directives were observed.",
                "remediation": "Review CSP directives against application requirements and remove unnecessary permissive sources.",
                "status": "NEEDS_REVIEW",
                "request_method": "GET",
                "response_headers": response.headers,
                "status_code": response.status_code,
                "response_size": getattr(response, "_nikhil_response_size", len(response.content)),
            })
        else:
            good("CSP configured; no basic weak patterns detected")
    else:
        warn("CSP: missing")
    if result["hsts"]["strength"] == "strong":
        good("HSTS strength: strong baseline")
    elif result["hsts"]["strength"] in ("medium", "weak"):
        warn(f"HSTS strength: {result['hsts']['strength']}")
    elif response.url.lower().startswith("https://"):
        warn("HSTS: missing")
    result["present"] = {key: value for key, value in result["present"].items()}
    return result
