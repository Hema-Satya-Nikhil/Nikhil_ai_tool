"""Read-only analysis of in-scope public JavaScript with secret-safe output."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import redact_text, sanitize_url
from nikhil_ai_modules.output import header, info, section, warn
from nikhil_ai_modules.parsers import parse_page
from nikhil_ai_modules.scope import normalize_url

PATH_RE = re.compile(r"(?:['\"`])((?:https?://[^'\"`\s]+)?/(?:api|graphql|auth|login|logout|admin|upload|search|v\d+)[^'\"`\s]*)", re.I)
PARAM_RE = re.compile(r"(?:URLSearchParams\([^)]*\)\.get\s*\(|[?&])['\"]?([A-Za-z_][\w.-]{0,60})", re.I)
ENV_RE = re.compile(r"(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]{1,80})")
SECRET_RE = re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|private[_-]?key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")
SOURCEMAP_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)")


def analyze_javascript(text: str) -> dict:
    api_paths = sorted(set(match.group(1) for match in PATH_RE.finditer(text or "")))[:250]
    parameters = sorted(set(match.group(1) for match in PARAM_RE.finditer(text or "")))[:150]
    env_names = sorted(set(ENV_RE.findall(text or "")))[:100]
    sourcemaps = sorted(set(SOURCEMAP_RE.findall(text or "")))[:30]
    possible_secret_count = len(list(SECRET_RE.finditer(text or "")))
    return {
        "api_paths": api_paths,
        "parameter_names": parameters,
        "environment_names": env_names,
        "source_maps": sourcemaps,
        "possible_secret_count": possible_secret_count,
    }


def analyze_javascript_files(target, context=None, *, max_files: int = 15):
    ctx = resolve_context(context)
    page_url = normalize_url(target)
    page_response = ctx.http.get(page_url)
    page = parse_page(page_response.text)
    results = []
    endpoint_inventory = []
    potential_findings = []
    visited = set()
    for reference in page.scripts[:max(1, min(int(max_files), 30))]:
        absolute = urljoin(page_response.url, reference)
        parsed = urlsplit(absolute)
        if not parsed.hostname or not ctx.scope.is_in_scope(parsed.hostname):
            continue
        try:
            absolute = normalize_url(absolute)
        except ValueError:
            continue
        if absolute in visited:
            continue
        visited.add(absolute)
        try:
            response = ctx.http.get(absolute, headers={"Accept": "application/javascript,text/javascript,*/*;q=0.5"})
            if response.status_code >= 400:
                continue
            analysis = analyze_javascript(response.text)
            item = {"url": sanitize_url(response.url), **analysis, "status_code": response.status_code}
            results.append(item)
            for path in analysis["api_paths"]:
                endpoint = urljoin(page_response.url, path)
                try:
                    endpoint = normalize_url(endpoint)
                except ValueError:
                    continue
                endpoint_host = urlsplit(endpoint).hostname
                if endpoint_host and ctx.scope.is_in_scope(endpoint_host):
                    endpoint_inventory.append({"url": sanitize_url(endpoint), "method": "GET", "source": "JavaScript reference"})
            if analysis["possible_secret_count"]:
                potential_findings.append({
                    "title": "POSSIBLE SECRET / REVIEW REQUIRED",
                    "category": "JavaScript Exposure",
                    "target": page_url,
                    "endpoint": sanitize_url(response.url),
                    "severity": "LOW",
                    "confidence": "LOW",
                    "description": "A public JavaScript file contains text patterns resembling credential assignments. Values are intentionally not shown or stored; many matches are placeholders or public client identifiers.",
                    "evidence": f"{analysis['possible_secret_count']} candidate assignment pattern(s) were detected; values withheld.",
                    "observed_behavior": "Credential-like assignment syntax appeared in a public script.",
                    "reproduction_notes": "Review the script manually and determine whether any value is a real secret. Do not authenticate with or disclose candidate values.",
                    "remediation": "Remove private credentials from client-side code and rotate any confirmed exposed secret.",
                    "status": "NEEDS_REVIEW",
                    "request_method": "GET",
                    "status_code": response.status_code,
                    "response_size": getattr(response, "_nikhil_response_size", len(response.content)),
                    "evidence_description": "Secret-like content withheld; manual review required.",
                })
        except Exception as exc:
            info(f"Could not analyze in-scope JS {sanitize_url(absolute)}: {redact_text(exc, 120)}")
    header("JavaScript Analysis")
    section("Public Script Indicators")
    for item in results:
        info(f"{item['url']} — {len(item['api_paths'])} API path(s), {len(item['parameter_names'])} parameter name(s)")
        if item["environment_names"]:
            info("Environment/config names: " + ", ".join(item["environment_names"][:20]))
        if item["source_maps"]:
            warn(f"Source-map reference(s) observed: {len(item['source_maps'])}; maps were not fetched")
        if item["possible_secret_count"]:
            warn("POSSIBLE SECRET / REVIEW REQUIRED — candidate values were withheld")
    return {
        "target": page_url,
        "scripts": results,
        "endpoints": endpoint_inventory,
        "potential_findings": potential_findings,
    }
