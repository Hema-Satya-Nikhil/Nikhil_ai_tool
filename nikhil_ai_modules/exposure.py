"""Low-impact sensitive exposure indicators; sensitive bodies are never fetched."""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import sanitize_url
from nikhil_ai_modules.output import header, info, section, warn
from nikhil_ai_modules.scope import normalize_url

HEAD_ONLY_PATHS = (
    "/.env", "/.git/config", "/backup.zip", "/backup.tar.gz", "/config.json",
    "/server-status", "/phpinfo.php", "/debug", "/openapi.json", "/swagger.json",
)
SAFE_PUBLIC_PATHS = ("/.well-known/security.txt", "/robots.txt", "/sitemap.xml")
STACK_PATTERNS = (
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r" at [^\n]+\([^\n]+:\d+\)", re.I),
    re.compile(r"exception in thread|stack trace", re.I),
)


def _origin_path(base, path):
    parsed = urlsplit(base)
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def inspect_exposure(target, context=None):
    ctx = resolve_context(context)
    base = normalize_url(target)
    home = ctx.http.get(base)
    body = home.text[:200000]
    base_url = urlunsplit((urlsplit(home.url).scheme, urlsplit(home.url).netloc, "/", "", ""))
    results = []
    findings = []
    for path in SAFE_PUBLIC_PATHS:
        url = _origin_path(base_url, path)
        try:
            response = ctx.http.get(url)
            results.append({"path": path, "method": "GET", "status_code": response.status_code,
                            "content_type": response.headers.get("Content-Type"), "body_retained": False})
        except Exception as exc:
            results.append({"path": path, "method": "GET", "error": str(exc)[:160]})
    for path in HEAD_ONLY_PATHS:
        url = _origin_path(base_url, path)
        try:
            response = ctx.http.head(url)
            item = {"path": path, "method": "HEAD", "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type"),
                    "content_length": response.headers.get("Content-Length"), "body_fetched": False}
            results.append(item)
            if response.status_code in (200, 206):
                warn(f"Potentially exposed resource endpoint responds to HEAD: {path} (body not fetched)")
                findings.append({
                    "title": "Potential security-sensitive resource exposure",
                    "category": "Sensitive Exposure",
                    "target": base_url,
                    "endpoint": sanitize_url(url),
                    "severity": "MEDIUM" if path in ("/.env", "/.git/config", "/backup.zip", "/backup.tar.gz") else "LOW",
                    "confidence": "LOW",
                    "description": "A security-relevant path returned a successful HEAD status. SPA fallbacks and custom routing can produce false positives; no response body was retrieved.",
                    "evidence": f"HEAD {path} returned HTTP {response.status_code}; body was not downloaded.",
                    "observed_behavior": "A candidate security-sensitive path returned a successful HEAD response.",
                    "reproduction_notes": "Review the resource directly in an authorized environment without retrieving or disclosing credentials or private data.",
                    "remediation": "Remove unintended public artifacts and configure explicit deny rules for private files and debug endpoints.",
                    "status": "NEEDS_REVIEW", "request_method": "HEAD", "response_headers": response.headers,
                    "status_code": response.status_code, "response_size": 0,
                })
        except Exception as exc:
            results.append({"path": path, "method": "HEAD", "error": str(exc)[:160]})

    directory_listing = bool(re.search(r"<title>\s*Index of /|Index of /</h1>", body, re.I))
    stack_trace = any(pattern.search(body) for pattern in STACK_PATTERNS)
    if directory_listing or stack_trace:
        findings.append({
            "title": "Potential verbose debug or directory-listing exposure",
            "category": "Sensitive Exposure",
            "target": sanitize_url(home.url), "endpoint": sanitize_url(home.url),
            "severity": "LOW", "confidence": "LOW",
            "description": "The ordinary page response contains a directory-listing or stack-trace marker. Markers may be documentation or examples.",
            "evidence": "A generic directory listing / exception marker was observed; response content was not retained.",
            "observed_behavior": "Potential directory listing or verbose error text appeared in the base response.",
            "remediation": "Disable directory indexing and return generic client-facing errors while keeping diagnostic details server-side.",
            "status": "NEEDS_REVIEW", "request_method": "GET", "status_code": home.status_code,
            "response_size": getattr(home, "_nikhil_response_size", len(home.content)),
            "response_excerpt": "Sensitive response excerpt withheld.",
        })
    header("Sensitive Exposure Detection")
    section("Safe probes")
    info("Potentially sensitive paths were checked with HEAD only; response bodies were not fetched.")
    for item in results:
        status = item.get("status_code", "error")
        info(f"{item['method']} {item['path']}: {status}")
    return {"target": sanitize_url(home.url), "checks": results, "potential_findings": findings}
