"""Cookie attribute review without retaining or printing cookie values."""
from __future__ import annotations

from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.output import good, header, info, section, warn


def _set_cookie_headers(response):
    raw = getattr(response, "raw", None)
    headers = getattr(raw, "headers", None)
    getter = getattr(headers, "getlist", None)
    if callable(getter):
        values = getter("Set-Cookie")
        if values:
            return values
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def analyze_cookies(set_cookie_headers, request_url: str):
    request_host = (urlsplit(request_url).hostname or "").lower()
    is_https = urlsplit(request_url).scheme.lower() == "https"
    results = []
    for header_value in set_cookie_headers or []:
        cookie = SimpleCookie()
        try:
            cookie.load(str(header_value))
        except Exception:
            continue
        for name, morsel in cookie.items():
            domain = (morsel["domain"] or request_host).lstrip(".").lower()
            same_site = morsel["samesite"] or None
            flags = {
                "secure": bool(morsel["secure"]),
                "http_only": bool(morsel["httponly"]),
                "same_site": same_site,
                "path": morsel["path"] or "/",
                "domain": domain,
            }
            issues = []
            session_like = any(token in name.lower() for token in ("session", "sess", "auth", "token", "sid"))
            if is_https and not flags["secure"]:
                issues.append("Secure attribute missing on HTTPS response")
            if session_like and not flags["http_only"]:
                issues.append("HttpOnly attribute missing on session-like cookie")
            if not same_site:
                issues.append("SameSite attribute missing")
            elif same_site.lower() not in ("strict", "lax", "none"):
                issues.append("Unrecognized SameSite value")
            if domain and request_host and domain != request_host and not request_host.endswith("." + domain):
                issues.append("Cookie Domain does not appear to match the response host")
            results.append({"name": name, **flags, "session_like": session_like, "issues": issues})
    return results


def analyze_cookie_security(target, context=None):
    ctx = resolve_context(context)
    response = ctx.http.get(target)
    cookies = analyze_cookies(_set_cookie_headers(response), response.url)
    findings = []
    header("Cookie Security Analysis")
    section("Cookie Attributes (values withheld)")
    if not cookies:
        info("No Set-Cookie headers observed on this response")
    for cookie in cookies:
        print(f"Cookie: {cookie['name']}")
        print(f"Secure: {'YES' if cookie['secure'] else 'NO'}")
        print(f"HttpOnly: {'YES' if cookie['http_only'] else 'NO'}")
        print(f"SameSite: {cookie['same_site'] or 'MISSING'}")
        if cookie["issues"]:
            for issue in cookie["issues"]:
                warn(f"Potential weakness: {issue}")
                findings.append({
                    "title": "Potential cookie security weakness",
                    "category": "Cookie Security",
                    "target": response.url,
                    "endpoint": response.url,
                    "parameter": cookie["name"],
                    "severity": "LOW",
                    "confidence": "MEDIUM" if cookie["session_like"] else "LOW",
                    "description": "A cookie attribute may be missing or unusual. Impact depends on cookie purpose, transport, and application behavior.",
                    "evidence": f"Cookie name={cookie['name']}; {issue}; cookie value withheld.",
                    "observed_behavior": issue,
                    "remediation": "Set Secure on HTTPS cookies, HttpOnly for session identifiers, and an intentional SameSite policy; use the narrowest appropriate Domain and Path.",
                    "status": "NEEDS_REVIEW",
                    "request_method": "GET",
                    "response_headers": response.headers,
                    "status_code": response.status_code,
                    "response_size": getattr(response, "_nikhil_response_size", len(response.content)),
                })
        else:
            good("No basic cookie-attribute issue observed")
    return {"target": response.url, "cookies": cookies, "potential_findings": findings}
