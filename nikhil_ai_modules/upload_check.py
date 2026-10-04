"""Upload-form inventory. No file content is uploaded."""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import sanitize_url
from nikhil_ai_modules.output import header, info, warn
from nikhil_ai_modules.parsers import parse_page
from nikhil_ai_modules.scope import normalize_url


def inspect_upload_surfaces(target, context=None):
    ctx = resolve_context(context)
    url = normalize_url(target)
    response = ctx.http.get(url)
    page = parse_page(response.text)
    uploads = []
    endpoints = []
    for form in page.forms:
        file_fields = [field for field in form["fields"] if field["type"] == "file"]
        if not file_fields:
            continue
        action = normalize_url(urljoin(response.url, form["action"] or response.url))
        action_host = urlsplit(action).hostname or ""
        if not ctx.scope.is_in_scope(action_host):
            continue
        item = {
            "action": sanitize_url(action),
            "method": form["method"],
            "enctype": form["enctype"],
            "file_fields": [{"name": field["name"], "accept_hint": field["accept"] or None} for field in file_fields],
            "status_code": response.status_code,
            "file_upload_performed": False,
            "limitations": ["Extension/MIME validation, filename handling, size limits, and storage behavior require an explicitly approved harmless-file test."],
        }
        uploads.append(item)
        endpoints.append({"url": action, "method": form["method"], "status_code": None, "content_type": None, "source": "HTML upload form"})
    header("File Upload Security Checks")
    if not uploads:
        info("No in-scope HTML file-upload form was observed on this page.")
    for item in uploads:
        warn(f"Upload surface: {item['action']} — no file was sent")
        info(f"Method: {item['method']}; encoding: {item['enctype'] or 'not set'}")
        info("Advertised accept hints: " + ", ".join(field["accept_hint"] or "not specified" for field in item["file_fields"]))
    return {"target": sanitize_url(response.url), "upload_surfaces": uploads, "endpoints": endpoints, "potential_findings": []}
