"""Evidence-based technology indicators; detections are hints, not guarantees."""
from __future__ import annotations

import re

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.http_probe import probe_http_https
from nikhil_ai_modules.output import header, info, section, warn


def detect_technologies(headers, body="", cookies=""):
    lower_headers = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    body_lower = (body or "").lower()
    cookie_lower = (cookies or "").lower()
    detections = {}

    def add(name, evidence, confidence="MEDIUM"):
        current = detections.setdefault(name, {"confidence": confidence, "evidence": []})
        current["evidence"].append(evidence)
        if confidence == "HIGH":
            current["confidence"] = "HIGH"

    server = lower_headers.get("server", "")
    for product, regex in (("Apache", r"apache"), ("Nginx", r"nginx"), ("IIS", r"microsoft-iis"), ("Cloudflare", r"cloudflare")):
        if re.search(regex, server, re.I):
            add(product, f"Server header: {server[:100]}", "HIGH")
    powered = lower_headers.get("x-powered-by", "")
    for product, regex in (("PHP", r"php/?[\d.]*"), ("Express", r"express"), ("ASP.NET", r"asp\.net")):
        if re.search(regex, powered, re.I):
            add(product, f"X-Powered-By header: {powered[:100]}", "HIGH")
    if "cf-ray" in lower_headers or "cf-cache-status" in lower_headers:
        add("Cloudflare/CDN", "Cloudflare response header observed", "HIGH")
    if "wp-content/" in body_lower or "wp-includes/" in body_lower:
        add("WordPress", "WordPress asset path observed in HTML", "MEDIUM")
    if "wp-content" in cookie_lower or "wordpress_" in cookie_lower:
        add("WordPress", "WordPress cookie indicator observed", "MEDIUM")
    if "__next_data__" in body_lower or "_next/static/" in body_lower:
        add("Next.js", "Next.js page/data marker observed", "HIGH")
    if "react" in body_lower and ("data-reactroot" in body_lower or "react-dom" in body_lower):
        add("React", "React DOM marker observed in HTML", "MEDIUM")
    if "drupal.settings" in body_lower or "drupal.js" in body_lower:
        add("Drupal", "Drupal settings/script marker observed", "MEDIUM")
    if "laravel_session" in cookie_lower or "laravel_session" in lower_headers.get("set-cookie", "").lower():
        add("Laravel", "Laravel session-cookie name observed", "MEDIUM")
    if "x-aspnet-version" in lower_headers:
        add("ASP.NET", "X-AspNet-Version header observed", "HIGH")
    return [{"technology": name, **details} for name, details in sorted(detections.items())]


def detect_technology(target, context=None):
    ctx = resolve_context(context)
    probes = probe_http_https(target, ctx)
    detected = []
    for probe in probes.get("probes", []):
        if not probe.get("live"):
            continue
        detected.append({"url": probe["final_url"], "technologies": probe.get("technologies", [])})
    header("Technology Detection")
    section("Evidence-backed Indicators")
    any_found = False
    for item in detected:
        info(item["url"])
        if not item["technologies"]:
            warn("No recognizable technology indicator in the captured response")
        for technology in item["technologies"]:
            any_found = True
            info(f"{technology['technology']} ({technology['confidence']} confidence): " + "; ".join(technology["evidence"]))
    if not any_found:
        warn("No technology indicators detected; absence is not proof a technology is not used.")
    return {"target": target, "detections": detected, "assets": probes.get("assets", []), "potential_findings": []}
