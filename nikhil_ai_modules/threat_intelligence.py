"""Opt-in, cached public advisory enrichment; never asserts a product is vulnerable."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from nikhil_ai_modules.evidence import redact_text, sanitize_url
from nikhil_ai_modules.scope import ScopeError

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _advisory(row):
    cve = row.get("cve", {})
    descriptions = cve.get("descriptions", [])
    summary = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    cvss, severity = None, "UNKNOWN"
    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_rows = metrics.get(metric_key, [])
        if metric_rows:
            data = metric_rows[0].get("cvssData", {})
            cvss = data.get("baseScore")
            severity = data.get("baseSeverity") or metric_rows[0].get("baseSeverity") or severity
            break
    references = [sanitize_url(ref.get("url", "")) for ref in cve.get("references", [])[:8] if ref.get("url", "").startswith(("http://", "https://"))]
    return {
        "cve": cve.get("id", ""), "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""), "cvss": cvss,
        "severity": severity, "summary": redact_text(summary, 800), "references": references,
        "match_note": "Keyword candidate only; affected product and version ranges require manual verification.",
        "status": "POTENTIAL_ADVISORY_REVIEW_REQUIRED",
    }


def refresh_intelligence(context, product: str, version: str, *, force: bool = False):
    config = context.config.get("threat_intelligence", {})
    if not config.get("enabled", False):
        raise ScopeError("Threat intelligence is disabled; enable it in local configuration before refreshing")
    name = " ".join(str(product or "").split())[:100]
    detected_version = " ".join(str(version or "").split())[:60]
    if len(name) < 2 or len(detected_version) < 1:
        raise ValueError("Product and detected version are required")
    key = hashlib.sha256((name.casefold() + "\0" + detected_version.casefold()).encode()).hexdigest()
    cache = context.database.get_threat_intel_cache(key)
    ttl = int(config.get("cache_ttl_seconds", 86400))
    if cache and not force:
        fetched = _parse_time(cache["fetched_at"])
        if fetched and datetime.now(timezone.utc) - fetched < timedelta(seconds=ttl):
            return {**cache["result"], "cached": True}

    response = context.http.get(NVD_ENDPOINT, params={"keywordSearch": f"{name} {detected_version}", "resultsPerPage": 10}, purpose="passive_source", timeout=min(20, float(context.config.get("timeout", 6)) + 10))
    if response.status_code != 200:
        raise RuntimeError(f"NVD returned HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("NVD response was not valid JSON") from exc
    rows = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    advisories = [_advisory(row) for row in rows[:10] if isinstance(row, dict)]
    result = {
        "provider": "NVD",
        "product": name,
        "detected_version": detected_version,
        "confidence": "LOW",
        "manual_verification_required": True,
        "warning": "A keyword match does not establish that the installed product or version is affected.",
        "advisories": advisories,
        "total_results": payload.get("totalResults", len(advisories)),
        "cached": False,
    }
    context.database.put_threat_intel_cache(key, "NVD", result)
    context.events.publish("threat_intel_refreshed", message="Public advisory enrichment updated", data={"provider": "NVD", "product": name, "candidate_count": len(advisories)})
    return result
