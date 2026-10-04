"""Secret-redacted JSON/HTML reports (optional PDF when reportlab is installed)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Dict

from nikhil_ai_modules.config import resolve_path
from nikhil_ai_modules.evidence import SENSITIVE_KEY, redact_text, sanitize_url
from nikhil_ai_modules.output import good, info, warn


def _report_safe(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {str(child_key): _report_safe(child, str(child_key)) for child_key, child in value.items()
                if not SENSITIVE_KEY.search(str(child_key))}
    if isinstance(value, list):
        return [_report_safe(item, key) for item in value]
    if isinstance(value, str):
        if key.lower() in {"target", "endpoint", "url", "requested_url", "final_url"} and "://" in value:
            return sanitize_url(value)
        return redact_text(value, 4000)
    return value


def build_report_data(context) -> Dict[str, Any]:
    scans = context.database.list_scans(context.project_id, limit=1000)
    findings = context.database.list_findings(context.project_id, limit=2000)
    evidence = context.database.list_evidence(context.project_id, limit=5000)
    assets = context.database.list_assets(context.project_id)
    endpoints = context.database.list_endpoints(context.project_id, limit=5000)
    services = context.database.list_services(context.project_id)
    technologies = context.database.list_technologies(context.project_id)
    relations = context.database.list_asset_relations(context.project_id)
    project = next((item for item in context.database.list_projects() if item["id"] == context.project_id), {})
    automated = [item for item in findings if item.get("status") in {"NEW", "NEEDS_REVIEW"}]
    confirmed = [item for item in findings if item.get("status") in {"CONFIRMED", "REPORTED", "RESOLVED"}]
    false_positives = [item for item in findings if item.get("status") == "FALSE_POSITIVE"]
    modules = sorted({scan.get("module", "") for scan in scans if scan.get("module")})
    data = {
        "report_title": f"Authorized Security Assessment — {context.config.get('project_name', 'Project')}",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "project": {
            "name": project.get("name", context.config.get("project_name", "Default Project")),
            "program": project.get("program", ""),
            "description": project.get("description", ""),
            "notes": project.get("notes", ""),
        },
        "methodology": {
            "safe_mode": bool(context.config.get("safe_mode", True)),
            "scan_modules": modules,
            "note": "Conservative authorized assessment observations; results may be incomplete and require manual validation.",
        },
        "executive_summary": {
            "scans_recorded": len(scans),
            "assets_discovered": len(assets),
            "services_observed": len(services),
            "endpoints_in_inventory": len(endpoints),
            "automated_detections_needing_review": len(automated),
            "human_verified_findings": len(confirmed),
            "false_positives": len(false_positives),
            "important_note": "Automated detections are leads, not confirmed vulnerabilities. No guarantee of exhaustive coverage is made.",
        },
        "scope": context.scope.show(),
        "assets_discovered": assets,
        "asset_relationships": relations,
        "services": services,
        "endpoints": endpoints,
        "technologies": technologies,
        "timeline": scans,
        "scan_modules": modules,
        "scan_history": scans,
        "potential_findings_automated_detection": automated,
        "human_verified_findings": confirmed,
        "false_positives": false_positives,
        "evidence": evidence,
    }
    return _report_safe(data)


def _render_html(data: Dict[str, Any]) -> str:
    summary = data["executive_summary"]
    sections = []
    sections.append(f"<h1>{escape(data['report_title'])}</h1><p>Generated: {escape(data['generated_at'])}</p>")
    sections.append("<h2>Executive Summary</h2><ul>" + "".join(
        f"<li><strong>{escape(str(key.replace('_', ' ').title()))}:</strong> {escape(str(value))}</li>"
        for key, value in summary.items()
    ) + "</ul>")
    scope = data["scope"]
    sections.append("<h2>Scope</h2><h3>In scope</h3><ul>" + "".join(f"<li>{escape(item)}</li>" for item in scope.get("in_scope", [])) + "</ul>")
    sections.append("<h3>Explicit exclusions</h3><ul>" + "".join(f"<li>{escape(item)}</li>" for item in scope.get("exclusions", [])) + "</ul>")

    def table_section(title, rows, columns):
        parts = [f"<h2>{escape(title)}</h2>"]
        if not rows:
            return "".join(parts + ["<p>None recorded.</p>"])
        parts.append("<table><thead><tr>" + "".join(f"<th>{escape(column.replace('_', ' ').title())}</th>" for column in columns) + "</tr></thead><tbody>")
        for row in rows:
            parts.append("<tr>" + "".join(f"<td>{escape(str(row.get(column, '')))}</td>" for column in columns) + "</tr>")
        parts.append("</tbody></table>")
        return "".join(parts)

    sections.append("<h2>Methodology</h2><p>" + escape(data["methodology"]["note"]) + "</p><p>Safe Mode: " + ("ON" if data["methodology"]["safe_mode"] else "OFF") + "</p>")
    sections.append(table_section("Assets Discovered", data["assets_discovered"], ["host", "status", "last_seen"]))
    sections.append(table_section("Asset Relationships", data["asset_relationships"], ["source_type", "source_value", "relation", "target_type", "target_value", "last_seen"]))
    sections.append(table_section("Services", data["services"], ["host", "ip", "port", "protocol", "state", "service", "version", "last_seen"]))
    sections.append(table_section("Endpoints", data["endpoints"], ["url", "method", "status_code", "content_type", "source"]))
    sections.append(table_section("Technologies", data["technologies"], ["host", "technology", "category", "confidence", "source", "evidence"]))
    sections.append(table_section("Timeline / Scan History", data["timeline"], ["id", "display_id", "module", "status", "started_at", "finished_at", "requests"]))
    sections.append("<h2>Scan Modules</h2><p>" + escape(", ".join(data["scan_modules"]) or "None recorded") + "</p>")
    sections.append(table_section("Automated Detection — Manual Review Required", data["potential_findings_automated_detection"], ["finding_id", "title", "category", "target", "endpoint", "severity", "confidence", "status", "description", "impact", "evidence", "observed_behavior", "reproduction_notes", "remediation", "researcher_notes"]))
    sections.append(table_section("Human Verified Findings", data["human_verified_findings"], ["finding_id", "title", "category", "target", "endpoint", "severity", "confidence", "status", "description", "impact", "evidence", "observed_behavior", "reproduction_notes", "remediation", "researcher_notes"]))
    sections.append(table_section("False Positives", data["false_positives"], ["finding_id", "title", "category", "target", "status", "evidence"]))
    sections.append(table_section("Evidence", data["evidence"], ["timestamp", "target", "endpoint", "request_method", "status_code", "response_size", "evidence_description", "response_excerpt"]))
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Assessment Report</title><style>
body{font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;color:#17202a;max-width:1180px;margin:32px auto;padding:0 22px}h1,h2{color:#123f46}h2{margin-top:2em;border-bottom:1px solid #ccd8d8;padding-bottom:.3em}table{border-collapse:collapse;width:100%;font-size:13px;display:block;overflow-x:auto}td,th{border:1px solid #d3dddd;padding:7px;vertical-align:top;text-align:left;white-space:pre-wrap}th{background:#e9f1f1}li{margin:.2em 0}.notice{background:#fff5d6;padding:12px;border-left:4px solid #ddaa00}
</style></head><body><p class="notice"><strong>AUTOMATED DETECTION</strong> is separate from <strong>HUMAN VERIFIED FINDING</strong>. Validate every result manually within authorized scope.</p>""" + "".join(sections) + "</body></html>"


def _render_pdf(data: Dict[str, Any], destination: Path) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("PDF generation is optional; install reportlab to enable it") from exc
    doc = SimpleDocTemplate(str(destination), pagesize=landscape(A4), rightMargin=14 * mm, leftMargin=14 * mm)
    styles = getSampleStyleSheet()
    story = [Paragraph(escape(data["report_title"]), styles["Title"]), Paragraph(escape(data["generated_at"]), styles["Normal"]), Spacer(1, 8)]
    story.append(Paragraph("Automated detections are not confirmed vulnerabilities. Human validation is required.", styles["BodyText"]))
    project = data.get("project", {})
    story.append(Paragraph("Program: " + escape(str(project.get("program", ""))), styles["BodyText"]))
    if project.get("notes"):
        story.append(Paragraph("Researcher / project notes: " + escape(str(project["notes"])), styles["BodyText"]))
    for title, key, columns in (
        ("Scope", None, []), ("Assets Discovered", "assets_discovered", ["host", "status"]),
        ("Services", "services", ["host", "port", "protocol", "service", "version", "state"]),
        ("Endpoints", "endpoints", ["url", "method", "status_code"]),
        ("Technologies", "technologies", ["host", "technology", "category", "confidence", "source"]),
        ("Scan Timeline", "timeline", ["display_id", "module", "status", "started_at", "finished_at"]),
        ("Automated Detection — Manual Review Required", "potential_findings_automated_detection", ["finding_id", "title", "severity", "confidence", "status", "evidence", "remediation"]),
        ("Human Verified Findings", "human_verified_findings", ["finding_id", "title", "severity", "status", "evidence", "remediation"]),
        ("False Positives", "false_positives", ["finding_id", "title", "category", "status", "evidence"]),
        ("Evidence", "evidence", ["timestamp", "target", "endpoint", "request_method", "status_code", "response_size", "evidence_description", "response_excerpt"]),
    ):
        story.append(Paragraph(escape(title), styles["Heading2"]))
        if key is None:
            story.append(Paragraph("In scope: " + escape(", ".join(data["scope"].get("in_scope", []))), styles["BodyText"]))
            story.append(Paragraph("Exclusions: " + escape(", ".join(data["scope"].get("exclusions", []))), styles["BodyText"]))
            continue
        rows = [columns] + [[str(row.get(column, "")) for column in columns] for row in data.get(key, [])]
        if len(rows) == 1:
            story.append(Paragraph("None recorded.", styles["BodyText"]))
        else:
            table = Table(rows, repeatRows=1)
            table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dceaea")), ("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story.append(table)
    doc.build(story)


def generate_report(context=None, report_format: str = "html", output_path: str | Path | None = None) -> Path:
    if context is None:
        from nikhil_ai_modules.context import get_default_context
        context = get_default_context()
    selected = report_format.lower().lstrip(".")
    if selected not in {"html", "json", "pdf"}:
        raise ValueError("Report format must be html, json, or pdf")
    default_dir = resolve_path(context.config.get("report_dir", Path(context.config.get("output_dir", "output")) / "reports"))
    default_dir.mkdir(parents=True, exist_ok=True)
    if output_path:
        destination = Path(output_path).expanduser()
        if not destination.is_absolute():
            destination = default_dir / destination
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        destination = default_dir / f"assessment-report-{stamp}.{selected}"
    if destination.suffix.lower() != "." + selected:
        destination = destination.with_suffix("." + selected)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = build_report_data(context)
    if selected == "json":
        destination.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    elif selected == "html":
        destination.write_text(_render_html(data), encoding="utf-8")
    else:
        _render_pdf(data, destination)
    try:
        destination.chmod(0o600)
    except OSError:
        pass
    good(f"Report generated: {destination}")
    return destination
