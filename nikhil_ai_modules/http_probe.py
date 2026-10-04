"""Scope-aware HTTP/HTTPS reachability and response metadata collection."""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import redact_headers, redact_text, sanitize_url
from nikhil_ai_modules.output import good, header, info, kv, section, warn
from nikhil_ai_modules.parsers import parse_page
from nikhil_ai_modules.scope import normalize_url


def _scheme_url(target: str, scheme: str) -> str:
    normalized = normalize_url(target)
    parsed = urlsplit(normalized)
    # Any explicit non-default port is respected for both candidates. A URL
    # written with a scheme's default port is normalized without that port.
    return urlunsplit((scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def probe_url(url: str, context=None) -> dict:
    ctx = resolve_context(context)
    normalized = normalize_url(url)
    response = ctx.http.get(normalized)
    content_type = response.headers.get("Content-Type", "")
    page = parse_page(response.text) if "html" in content_type.lower() or "text/" in content_type.lower() else parse_page("")
    redirect_chain = list(getattr(response, "_nikhil_redirect_chain", []))
    redirect_chain.append({"url": sanitize_url(response.url), "status": response.status_code})
    return {
        "requested_url": sanitize_url(normalized),
        "final_url": sanitize_url(response.url),
        "status_code": response.status_code,
        "redirect_chain": redirect_chain,
        "response_headers": redact_headers(response.headers),
        "content_type": content_type,
        "response_size": getattr(response, "_nikhil_response_size", len(response.content)),
        "response_truncated": bool(getattr(response, "_nikhil_truncated", False)),
        "page_title": redact_text(page.title, 300),
        "server": response.headers.get("Server"),
        "live": True,
        "content_excerpt": redact_text(response.text[:700], 700) if "html" in content_type.lower() else "",
    }


def probe_http_https(target, context=None, *, include_body_for_analysis: bool = False):
    ctx = resolve_context(context)
    candidates = [_scheme_url(target, "https"), _scheme_url(target, "http")]
    results = []
    endpoints = []
    assets = []
    for url in dict.fromkeys(candidates):
        try:
            probe = probe_url(url, ctx)
            # Keep the body transient and only for local indicator matching;
            # ordinary probe results never return or persist an excerpt.
            from nikhil_ai_modules.tech_detect import detect_technologies
            probe["technologies"] = detect_technologies(
                probe.get("response_headers", {}), probe.get("content_excerpt", "")
            )
            if not include_body_for_analysis:
                probe.pop("content_excerpt", None)
            results.append(probe)
            endpoints.append({
                "url": probe["final_url"], "method": "GET", "status_code": probe["status_code"],
                "content_type": probe["content_type"], "source": "HTTP/HTTPS probe",
            })
            host = urlsplit(probe["final_url"]).hostname
            if host:
                assets.append({"host": host, "status": "LIVE", "scheme": urlsplit(probe["final_url"]).scheme})
        except Exception as exc:
            results.append({"requested_url": sanitize_url(url), "live": False, "error": redact_text(exc, 400)})
    header("HTTP / HTTPS Prober")
    section("Probe Results")
    for item in results:
        if item.get("live"):
            good(f"{item['requested_url']} -> HTTP {item['status_code']} ({item['response_size']} bytes)")
            if item.get("final_url") != item["requested_url"]:
                info(f"Redirected to {item['final_url']}")
        else:
            warn(f"{item['requested_url']} unavailable: {item.get('error', 'unknown error')}")
    return {
        "target": target,
        "probes": results,
        "assets": assets,
        "endpoints": endpoints,
        "potential_findings": [],
    }


# Legacy-friendly alias for integrations that prefer this name.
http_probe = probe_http_https
