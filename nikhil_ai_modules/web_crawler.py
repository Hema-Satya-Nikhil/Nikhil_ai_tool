"""Bounded, same-scope, robots-aware GET crawler for authorized inventory."""
from __future__ import annotations

from collections import deque
from urllib.parse import parse_qsl, urljoin, urlsplit
from urllib.robotparser import RobotFileParser

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import sanitize_url
from nikhil_ai_modules.output import header, info, section
from nikhil_ai_modules.parsers import parse_page
from nikhil_ai_modules.scope import ScopeError, normalize_url


HTML_TYPES = ("text/html", "application/xhtml+xml")


def crawl_site(target, context=None, *, max_depth=None, max_urls=None):
    ctx = resolve_context(context)
    root = normalize_url(target)
    depth_limit = max(0, min(int(max_depth if max_depth is not None else ctx.config.get("max_crawl_depth", 2)), 5))
    url_limit = max(1, min(int(max_urls if max_urls is not None else ctx.config.get("max_urls", 50)), 500))
    root_host = urlsplit(root).hostname
    if not root_host:
        raise ScopeError("Crawler target URL has no hostname")

    robots = RobotFileParser()
    robots.set_url(urljoin(root, "/robots.txt"))
    try:
        robots_response = ctx.http.get(robots.url)
        robots.parse(robots_response.text.splitlines() if robots_response.status_code < 400 else [])
    except Exception:
        robots.parse([])

    pending = deque([(root, 0)])
    visited = set()
    endpoints = []
    assets = [{"host": root_host, "status": "LIVE", "source": "bounded web crawl"}]
    discovered = set()
    skipped_scope = 0
    errors = []
    while pending and len(visited) < url_limit:
        current, depth = pending.popleft()
        try:
            current = normalize_url(current)
            host = urlsplit(current).hostname
            if not host or not ctx.scope.is_in_scope(host):
                skipped_scope += 1
                continue
            ctx.scope.require_host_rule(host)
            if current in visited:
                continue
            visited.add(current)
            if not robots.can_fetch(ctx.config.get("user_agent", "NIKHIL-AI-Safe"), current):
                ctx.events.publish("warning", severity="info", target=current, message="Robots policy disallowed this crawl URL")
                continue
            response = ctx.http.get(current)
            final_url = normalize_url(response.url)
            final_host = urlsplit(final_url).hostname
            if not final_host or not ctx.scope.is_in_scope(final_host):
                skipped_scope += 1
                continue
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            entry = {
                "url": sanitize_url(final_url),
                "method": "GET",
                "status_code": int(response.status_code),
                "content_type": content_type,
                "source": "bounded web crawler",
                "depth": depth,
                "parameters": sorted({key for key, _ in parse_qsl(urlsplit(final_url).query, keep_blank_values=True)})[:50],
            }
            endpoints.append(entry)
            discovered.add(final_url)
            ctx.events.publish("scan_progress", message="Crawler visited an in-scope page", data={"crawled": len(visited), "max_urls": url_limit, "current_action": sanitize_url(final_url)})
            if content_type not in HTML_TYPES or depth >= depth_limit:
                continue
            page = parse_page(response.text)
            candidates = list(page.links) + list(page.scripts)
            for href in candidates:
                try:
                    absolute = normalize_url(urljoin(final_url, href))
                    candidate_host = urlsplit(absolute).hostname
                    if not candidate_host or not ctx.scope.is_in_scope(candidate_host):
                        skipped_scope += 1
                        continue
                    ctx.scope.require_host_rule(candidate_host)
                    if absolute not in visited and len(visited) + len(pending) < url_limit:
                        pending.append((absolute, depth + 1))
                except (ScopeError, ValueError):
                    skipped_scope += 1
            for form in page.forms:
                action = normalize_url(urljoin(final_url, form.get("action") or final_url))
                action_host = urlsplit(action).hostname
                if action_host and ctx.scope.is_in_scope(action_host):
                    endpoints.append({"url": sanitize_url(action), "method": "FORM_" + str(form.get("method", "GET")).upper(), "status_code": None, "content_type": "", "source": "HTML form inventory", "depth": depth, "parameters": sorted({f.get("name") for f in form.get("fields", []) if f.get("name")})[:50]})
        except Exception as exc:
            errors.append({"url": sanitize_url(current), "error": str(exc)[:180]})
            ctx.events.publish("warning", severity="warning", target=current, message="Crawler could not collect this in-scope page")

    # Deduplicate URL/method without changing first-seen order.
    unique = {}
    for item in endpoints:
        unique.setdefault((item["url"], item["method"]), item)
    endpoints = list(unique.values())[:url_limit * 2]
    header("Bounded Web Crawler")
    section("Scope-checked inventory")
    info(f"Visited {len(visited)} unique pages; discovered {len(endpoints)} endpoint references; skipped {skipped_scope} out-of-scope links.")
    return {"target": root, "assets": assets, "endpoints": endpoints, "visited": len(visited), "max_depth": depth_limit, "max_urls": url_limit, "skipped_out_of_scope": skipped_scope, "errors": errors[:50], "potential_findings": []}
