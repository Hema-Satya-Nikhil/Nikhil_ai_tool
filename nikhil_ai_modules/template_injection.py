"""Passive server-side template error review; does not send template expressions."""
from __future__ import annotations

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import redact_text, sanitize_url
from nikhil_ai_modules.output import header, info, section, warn
from nikhil_ai_modules.scope import normalize_url

INDICATORS = {
    "Jinja2": ("jinja2.exceptions", "jinja2.exceptions.templatesyntaxerror", "unexpected end of template"),
    "Twig": ("twig\\error\\syntaxerror", "twig\\error\\loadererror"),
    "Freemarker": ("freemarker.core.parseexception", "freemarker template error"),
    "Velocity": ("org.apache.velocity.exception", "velocityexception"),
    "Thymeleaf": ("thymeleaf.exceptions", "templateinputexception"),
    "Handlebars": ("handlebars: error", "parse error on line"),
}


def review_template_signals(target, context=None):
    ctx = resolve_context(context)
    url = normalize_url(target)
    response = ctx.http.get(url)
    body = response.text[:ctx.config.get("max_response_bytes", 1048576)]
    lower = body.lower()
    observed = []
    for engine, tokens in INDICATORS.items():
        matched = [token for token in tokens if token.lower() in lower]
        if matched:
            observed.append({"engine_hint": engine, "indicators": matched[:4]})
    findings = []
    if observed:
        findings.append({
            "title": "Potential server-side template error disclosure",
            "category": "Template Injection Signals",
            "target": sanitize_url(response.url),
            "endpoint": sanitize_url(response.url),
            "severity": "LOW",
            "confidence": "LOW",
            "description": "Template-engine error markers appeared in an ordinary response. This does not demonstrate expression evaluation or template injection.",
            "impact": "Implementation details may be exposed if verbose errors reach users.",
            "evidence": "; ".join(f"{item['engine_hint']}: {', '.join(item['indicators'])}" for item in observed),
            "observed_behavior": "Passive response inspection only; no template payload or expression was sent.",
            "reproduction_notes": "Manually review the ordinary response in the authorized application and validate using a controlled non-production fixture.",
            "remediation": "Disable verbose template exceptions in production and handle rendering errors safely.",
        })
    header("Template Error Review")
    section("Passive signals")
    info("No template expressions, payloads, or mutation requests were sent.")
    if observed:
        for item in observed:
            warn(f"Potential {item['engine_hint']} error signal; manual verification required")
    else:
        info("No recognized template-error markers were present in the response body.")
    return {"target": sanitize_url(response.url), "status_code": response.status_code, "engine_hints": observed, "potential_findings": findings}
