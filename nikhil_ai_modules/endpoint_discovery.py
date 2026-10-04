"""Low-impact endpoint inventory from robots, sitemap, HTML and API docs."""
from __future__ import annotations

import re
from html import unescape
from urllib.parse import urljoin, urlsplit, urlunsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import redact_text, sanitize_url
from nikhil_ai_modules.output import header, info, section, warn
from nikhil_ai_modules.parsers import parse_page
from nikhil_ai_modules.scope import ScopeError, normalize_url

INTERESTING = ("/api/", "/login", "/logout", "/admin", "/graphql", "/upload", "/search", "/profile", "/account", "/orders", "/swagger", "/openapi")
DOC_PATHS = ("/openapi.json", "/swagger.json", "/api-docs", "/.well-known/openapi.json")
MAX_ENDPOINTS = 250


def _clean_url(base: str, candidate: str):
    joined = urljoin(base, unescape(candidate.strip()))
    parsed = urlsplit(joined)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return None
    return normalize_url(urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")))


def _same_or_scoped(url: str, context) -> bool:
    host = urlsplit(url).hostname
    return bool(host and context.scope.is_in_scope(host))


def discover_endpoints(target, context=None):
    ctx = resolve_context(context)
    base = normalize_url(target)
    base_host = urlsplit(base).hostname
    if not base_host:
        raise ScopeError("Target URL is missing a host")
    initial = ctx.http.get(base)
    base = initial.url
    page = parse_page(initial.text)
    found = {}

    def add(url, source, status=None, content_type=None):
        if len(found) >= MAX_ENDPOINTS:
            return
        try:
            cleaned = _clean_url(base, url)
        except ValueError:
            return
        if not cleaned or not _same_or_scoped(cleaned, ctx):
            return
        path = urlsplit(cleaned).path.lower()
        found.setdefault(cleaned, {
            "url": cleaned,
            "method": "GET",
            "status_code": status,
            "content_type": content_type,
            "source": source,
            "interesting_patterns": [pattern for pattern in INTERESTING if pattern in path],
        })

    add(base, "HTML page", initial.status_code, initial.headers.get("Content-Type"))
    for link in page.links:
        add(link, "HTML link")
    for script in page.scripts:
        add(script, "HTML script reference")

    robots_url = urljoin(base, "/robots.txt")
    try:
        robots = ctx.http.get(robots_url)
        if robots.status_code < 400:
            for line in robots.text.splitlines()[:500]:
                text = line.strip()
                if text.lower().startswith(("allow:", "disallow:")):
                    path = text.split(":", 1)[1].strip()
                    if path and "*" not in path and "?" not in path:
                        add(urljoin(base, path), "robots.txt")
                elif text.lower().startswith("sitemap:"):
                    add(text.split(":", 1)[1].strip(), "robots.txt sitemap reference")
            add(robots_url, "robots.txt", robots.status_code, robots.headers.get("Content-Type"))
    except Exception as exc:
        info(f"robots.txt not collected: {redact_text(exc, 120)}")

    sitemap_urls = [urljoin(base, "/sitemap.xml")]
    sitemap_urls.extend(item["url"] for item in found.values() if "sitemap" in item["source"].lower())
    for sitemap_url in list(dict.fromkeys(sitemap_urls))[:3]:
        try:
            response = ctx.http.get(sitemap_url)
            if response.status_code < 400:
                for loc in re.findall(r"<loc[^>]*>(.*?)</loc>", response.text, re.I | re.S)[:500]:
                    add(unescape(re.sub(r"<.*?>", "", loc)).strip(), "sitemap.xml")
                add(sitemap_url, "sitemap.xml", response.status_code, response.headers.get("Content-Type"))
        except Exception as exc:
            info(f"Sitemap not collected: {redact_text(exc, 120)}")

    # Check only a tiny, fixed set of documentation locations, not a wordlist.
    for path in DOC_PATHS:
        candidate = urljoin(base, path)
        try:
            response = ctx.http.head(candidate)
            if response.status_code in (405, 501):
                response = ctx.http.get(candidate)
            if response.status_code < 400:
                add(candidate, "public API documentation check", response.status_code, response.headers.get("Content-Type"))
        except Exception:
            continue

    endpoint_list = list(found.values())
    header("Endpoint / URL Discovery")
    section("Scope-filtered Inventory")
    info(f"Collected {len(endpoint_list)} URL reference(s); active probing was limited to the base page, robots/sitemap, and documentation checks.")
    for item in endpoint_list:
        label = ", ".join(item["interesting_patterns"]) or item["source"]
        print(f"{sanitize_url(item['url'])}  [{label}]")
    return {"target": target, "endpoints": endpoint_list, "assets": [{"host": base_host, "status": "LIVE"}], "potential_findings": []}
