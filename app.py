"""Same-origin local dashboard API, persistent scan queue and SSE event stream."""
from __future__ import annotations

import json
import os
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, send_file, stream_with_context

from nikhil_ai_modules.config import resolve_path
from nikhil_ai_modules.context import activate_project, get_default_context, get_scan_manager
from nikhil_ai_modules.dns_check import check_dns
from nikhil_ai_modules.evidence import redact_text
from nikhil_ai_modules.headers import check_headers
from nikhil_ai_modules.cors_check import check_cors
from nikhil_ai_modules.port_scan import scan_ports
from nikhil_ai_modules.report import generate_report
from nikhil_ai_modules.scan_runner import run_scan
from nikhil_ai_modules.scope import ScopeError, host_from_target, normalize_rule
from nikhil_ai_modules.ssl_check import check_ssl
from nikhil_ai_modules.plugins import list_scanners
from nikhil_ai_modules.integrations import integration_status
from nikhil_ai_modules.threat_intelligence import refresh_intelligence

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

# Compatibility routes used by the earlier dashboard and existing API clients.
SCAN_MODULES = {
    "headers": ("security_headers", check_headers, "url"),
    "ssl": ("ssl_tls_audit", check_ssl, "url"),
    "dns": ("dns_origin_exposure", check_dns, "host"),
    "cors": ("cors_check", check_cors, "url"),
    "ports": ("open_port_scan", scan_ports, "host"),
}


def validate_target(url, context=None):
    """Validate an HTTP(S) URL against explicit scope and DNS safety policy."""
    ctx = context or get_default_context()
    return ctx.scope.validate_url(url)


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _scan_one(module_key: str, url: str, context):
    if module_key not in SCAN_MODULES:
        raise ValueError("Unknown compatibility scanner module")
    module_name, scanner, target_kind = SCAN_MODULES[module_key]
    manager = get_scan_manager(context)
    with manager.protect_project_switch():
        validated = validate_target(url, context)
        target = host_from_target(validated) if target_kind == "host" else validated
        result = run_scan(module_name, target, scanner, context=context)
    return {module_key: result}


def _bounded_limit(value, default=100, maximum=5000):
    try:
        return max(1, min(int(value), maximum))
    except (TypeError, ValueError):
        return default


def _json_response(data, status=200):
    return jsonify({"success": True, "data": data}), status


SQLITE_INTEGER_MAX = (1 << 63) - 1
DATABASE_ID_FIELDS = {"scan_id", "project_id", "evidence_id", "report_id"}


@app.before_request
def reject_unrepresentable_database_ids():
    for name, value in (request.view_args or {}).items():
        if name in DATABASE_ID_FIELDS and (not isinstance(value, int) or not 1 <= value <= SQLITE_INTEGER_MAX):
            return jsonify({"success": False, "error": "Resource ID is outside the supported range"}), 404


def _project_payload(ctx):
    return {
        "id": ctx.project_id,
        "name": ctx.config.get("project_name", "Default Project"),
        "safe_mode": bool(ctx.config.get("safe_mode", True)),
        "scope": ctx.scope.show(),
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    context = get_default_context()
    return jsonify({"success": True, "status": "ready", "safe_mode": bool(context.config.get("safe_mode", True)), "database": "sqlite"})


@app.get("/api/scope")
def scope_status():
    context = get_default_context()
    return jsonify({
        "project": context.config.get("project_name", "Default Project"),
        "project_id": context.project_id,
        "safe_mode": bool(context.config.get("safe_mode", True)),
        "in_scope": context.scope.in_scope,
        "exclusions": context.scope.exclusions,
    })


@app.post("/api/validate")
def validate():
    try:
        url = _json_body().get("url", "")
        if not url:
            return jsonify({"success": False, "error": "URL is required"}), 400
        validated = validate_target(str(url))
        return jsonify({"success": True, "url": validated}), 200
    except ScopeError as exc:
        return jsonify({"success": False, "error": redact_text(exc, 500)}), 403
    except Exception as exc:
        return jsonify({"success": False, "error": redact_text(exc, 500)}), 400


@app.get("/api/summary")
def summary():
    ctx = get_default_context()
    data = ctx.database.summary(ctx.project_id)
    data["project"] = _project_payload(ctx)
    data["scope_count"] = len(ctx.scope.in_scope)
    data["exclusion_count"] = len(ctx.scope.exclusions)
    data["active_scans_list"] = get_scan_manager(ctx).active()
    data["recent_events"] = ctx.events.snapshot(12)
    return _json_response(data)


@app.get("/api/scanners")
def scanners():
    return _json_response(list_scanners())


@app.post("/api/scans")
def create_scan():
    ctx = get_default_context()
    payload = _json_body()
    module = str(payload.get("module", "")).strip().lower()
    target = str(payload.get("target", "")).strip()
    if not module or not target:
        return jsonify({"success": False, "error": "Both module and target are required"}), 400
    options = payload.get("options", {})
    if not isinstance(options, dict):
        return jsonify({"success": False, "error": "options must be an object"}), 400
    # Only the bounded crawler accepts public options through the browser. Auth
    # tokens, passwords and external-tool commands are intentionally excluded.
    safe_options = {}
    if module == "crawler":
        for key, maximum in (("max_depth", 5), ("max_urls", 200)):
            if key in options:
                try:
                    safe_options[key] = max(0, min(int(options[key]), maximum))
                except (TypeError, ValueError):
                    return jsonify({"success": False, "error": f"Invalid {key}"}), 400
    try:
        scan = get_scan_manager(ctx).submit(module, target, options=safe_options)
        return jsonify({"success": True, "data": scan}), 202
    except ScopeError as exc:
        return jsonify({"success": False, "error": redact_text(exc, 500)}), 403
    except (ValueError, FileNotFoundError) as exc:
        return jsonify({"success": False, "error": redact_text(exc, 500)}), 400
    except Exception as exc:
        ctx.logger.error("scan queue failure module=%s: %s", module, redact_text(exc, 300))
        return jsonify({"success": False, "error": "Scan could not be queued; see local event log."}), 500


@app.get("/api/scans")
def list_scans():
    ctx = get_default_context()
    return _json_response(ctx.database.list_scans(ctx.project_id, _bounded_limit(request.args.get("limit"), 100, 500)))


@app.get("/api/scans/<int:scan_id>")
def scan_detail(scan_id):
    ctx = get_default_context()
    scan = ctx.database.get_scan(ctx.project_id, scan_id)
    if not scan:
        return jsonify({"success": False, "error": "Scan not found"}), 404
    scan["events"] = ctx.database.list_events(ctx.project_id, scan_id=scan_id, limit=100)
    return _json_response(scan)


@app.get("/api/scans/<int:scan_id>/logs")
def scan_logs(scan_id):
    ctx = get_default_context()
    if not ctx.database.get_scan(ctx.project_id, scan_id):
        return jsonify({"success": False, "error": "Scan not found"}), 404
    return _json_response(ctx.database.list_events(ctx.project_id, scan_id=scan_id, limit=_bounded_limit(request.args.get("limit"), 200, 1000)))


@app.get("/api/scans/<int:scan_id>/findings")
def scan_findings(scan_id):
    ctx = get_default_context()
    scan = ctx.database.get_scan(ctx.project_id, scan_id)
    if not scan:
        return jsonify({"success": False, "error": "Scan not found"}), 404
    linked = {event.get("data", {}).get("finding_id") for event in ctx.database.list_events(ctx.project_id, scan_id=scan_id, limit=1000) if event["type"] in {"finding_created", "finding_updated"}}
    findings = [item for item in ctx.database.list_findings(ctx.project_id, 5000) if item.get("finding_id") in linked]
    return _json_response(findings)


@app.post("/api/scans/<int:scan_id>/pause")
def pause_scan(scan_id):
    ctx = get_default_context()
    if get_scan_manager(ctx).pause(scan_id):
        return _json_response(ctx.database.get_scan(ctx.project_id, scan_id))
    return jsonify({"success": False, "error": "Scan is not active or cannot be paused"}), 409


@app.post("/api/scans/<int:scan_id>/resume")
def resume_scan(scan_id):
    ctx = get_default_context()
    if get_scan_manager(ctx).resume(scan_id):
        return _json_response(ctx.database.get_scan(ctx.project_id, scan_id))
    return jsonify({"success": False, "error": "Scan is not paused"}), 409


@app.post("/api/scans/<int:scan_id>/cancel")
def cancel_scan(scan_id):
    ctx = get_default_context()
    if get_scan_manager(ctx).cancel(scan_id):
        return _json_response(ctx.database.get_scan(ctx.project_id, scan_id))
    return jsonify({"success": False, "error": "Scan is not active or cannot be cancelled"}), 409


@app.post("/api/scans/<int:scan_id>/retry")
def retry_scan(scan_id):
    ctx = get_default_context()
    try:
        return jsonify({"success": True, "data": get_scan_manager(ctx).retry(scan_id)}), 202
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400


@app.get("/api/events")
def list_events():
    ctx = get_default_context()
    try:
        after = max(0, int(request.args.get("after", 0)))
        scan_id = int(request.args["scan_id"]) if request.args.get("scan_id") else None
    except ValueError:
        return jsonify({"success": False, "error": "after and scan_id must be integers"}), 400
    if after > SQLITE_INTEGER_MAX or (scan_id is not None and not 1 <= scan_id <= SQLITE_INTEGER_MAX):
        return jsonify({"success": False, "error": "after and scan_id are outside the supported range"}), 400
    return _json_response(ctx.database.list_events(ctx.project_id, after_id=after, limit=_bounded_limit(request.args.get("limit"), 100, 1000), scan_id=scan_id))


@app.get("/api/events/stream")
def event_stream():
    ctx = get_default_context()
    try:
        initial_id = int(request.headers.get("Last-Event-ID", request.args.get("after", "0")) or 0)
    except ValueError:
        initial_id = 0
    if initial_id < 0:
        initial_id = 0
    elif initial_id > SQLITE_INTEGER_MAX:
        initial_id = SQLITE_INTEGER_MAX
    once = request.args.get("once") == "1"

    @stream_with_context
    def generate():
        cursor = max(0, initial_id)
        delivered = 0
        while True:
            events = ctx.events.events_after(cursor, 250)
            if events:
                for event in events:
                    cursor = max(cursor, int(event["event_id"]))
                    payload = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                    yield f"id: {cursor}\nevent: {event['type']}\ndata: {payload}\n\n"
                    delivered += 1
                if once and delivered:
                    return
                continue
            if once:
                return
            ctx.events.wait_for_event(15)
            yield ": keep-alive\n\n"

    return Response(generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


@app.get("/api/projects")
def list_projects():
    ctx = get_default_context()
    projects = ctx.database.list_projects()
    for project in projects:
        project["active"] = project["id"] == ctx.project_id
    return _json_response(projects)


@app.post("/api/projects")
def create_project():
    ctx = get_default_context()
    payload = _json_body()
    try:
        project_id = ctx.database.create_project(
            str(payload.get("name", "")), description=str(payload.get("description", "")),
            program=str(payload.get("program", "")), notes=str(payload.get("notes", "")),
        )
        ctx.events.publish("project_created", message="Project created", data={"project_id": project_id})
        return _json_response(next((p for p in ctx.database.list_projects() if p["id"] == project_id), {"id": project_id}), 201)
    except Exception as exc:
        return jsonify({"success": False, "error": redact_text(exc, 300)}), 400


@app.post("/api/projects/<int:project_id>/activate")
def activate_project_route(project_id):
    ctx = get_default_context()
    project = next((row for row in ctx.database.list_projects() if row["id"] == project_id), None)
    if not project:
        return jsonify({"success": False, "error": "Project not found"}), 404
    manager = get_scan_manager(ctx)
    with manager.lock:
        if manager.active() or manager.has_project_operation(ctx.project_id):
            return jsonify({"success": False, "error": "Cannot switch project while scans are active"}), 409
        try:
            activate_project(ctx, project["name"])
            return _json_response(_project_payload(ctx))
        except Exception as exc:
            return jsonify({"success": False, "error": redact_text(exc, 300)}), 400


@app.patch("/api/projects/current")
def update_current_project():
    ctx = get_default_context()
    payload = _json_body()
    allowed = {key: str(payload[key]) for key in ("description", "program", "notes") if key in payload}
    ctx.database.update_project(ctx.project_id, **allowed)
    return _json_response(next((p for p in ctx.database.list_projects() if p["id"] == ctx.project_id), _project_payload(ctx)))


@app.get("/api/scope/rules")
def list_scope_rules():
    ctx = get_default_context()
    return _json_response(ctx.database.list_target_rules(ctx.project_id))


@app.post("/api/scope/rules")
def add_scope_rule():
    ctx = get_default_context()
    payload = _json_body()
    kind = str(payload.get("kind", "include")).lower()
    if kind not in {"include", "exclude"}:
        return jsonify({"success": False, "error": "kind must be include or exclude"}), 400
    manager = get_scan_manager(ctx)
    with manager.lock:
        if manager.active() or manager.has_project_operation(ctx.project_id):
            return jsonify({"success": False, "error": "Cannot modify scope while scans are active"}), 409
        try:
            rule = normalize_rule(str(payload.get("rule", "")))
            if kind == "include":
                ctx.scope.add_target(rule)
            else:
                ctx.scope.add_exclusion(rule)
            ctx.database.add_target_rule(ctx.project_id, rule, kind)
            ctx.events.publish("scope_updated", severity="warning", message=f"Scope {kind} rule updated", data={"kind": kind, "rule": rule})
            return _json_response(ctx.scope.show(), 201)
        except Exception as exc:
            return jsonify({"success": False, "error": redact_text(exc, 300)}), 400


@app.delete("/api/scope/rules")
def delete_scope_rule():
    ctx = get_default_context()
    payload = _json_body()
    kind = str(payload.get("kind", "include")).lower()
    if kind not in {"include", "exclude"}:
        return jsonify({"success": False, "error": "kind must be include or exclude"}), 400
    manager = get_scan_manager(ctx)
    with manager.lock:
        if manager.active() or manager.has_project_operation(ctx.project_id):
            return jsonify({"success": False, "error": "Cannot modify scope while scans are active"}), 409
        try:
            rule = normalize_rule(str(payload.get("rule", "")))
            removed = ctx.scope.remove_target(rule, exclusion=(kind == "exclude"))
            if removed:
                ctx.database.delete_target_rule(ctx.project_id, rule, kind)
                ctx.events.publish("scope_updated", message="Scope rule removed", data={"kind": kind, "rule": rule})
            return _json_response({"removed": removed, "scope": ctx.scope.show()})
        except Exception as exc:
            return jsonify({"success": False, "error": redact_text(exc, 300)}), 400


@app.get("/api/assets")
@app.get("/api/hosts")
def list_assets():
    ctx = get_default_context()
    assets = ctx.database.list_assets(ctx.project_id, _bounded_limit(request.args.get("limit"), 1000, 10000))
    for item in assets:
        item["in_scope"] = ctx.scope.is_in_scope(item["host"])
    return _json_response(assets)


@app.get("/api/assets/graph")
def asset_graph():
    ctx = get_default_context()
    assets = ctx.database.list_assets(ctx.project_id)
    for item in assets:
        item["in_scope"] = ctx.scope.is_in_scope(item["host"])
    return _json_response({"assets": assets, "relations": ctx.database.list_asset_relations(ctx.project_id), "services": ctx.database.list_services(ctx.project_id), "technologies": ctx.database.list_technologies(ctx.project_id)})


@app.get("/api/endpoints")
def list_endpoints():
    ctx = get_default_context()
    return _json_response(ctx.database.list_endpoints(ctx.project_id, _bounded_limit(request.args.get("limit"), 2000, 10000)))


@app.get("/api/technologies")
def list_technologies():
    ctx = get_default_context()
    return _json_response(ctx.database.list_technologies(ctx.project_id, _bounded_limit(request.args.get("limit"), 2000, 10000)))


@app.get("/api/services")
def list_services():
    ctx = get_default_context()
    return _json_response(ctx.database.list_services(ctx.project_id, _bounded_limit(request.args.get("limit"), 2000, 10000)))


@app.get("/api/findings")
def list_findings():
    ctx = get_default_context()
    filters = {key: request.args.get(key, "") for key in ("severity", "confidence", "status", "module", "target")}
    return _json_response(ctx.database.list_findings(ctx.project_id, _bounded_limit(request.args.get("limit"), 500, 5000), filters))


@app.patch("/api/findings/<finding_id>")
def patch_finding(finding_id):
    ctx = get_default_context()
    payload = _json_body()
    status = payload.get("status")
    notes = payload.get("researcher_notes")
    if status is not None and str(status).upper() == "CONFIRMED" and payload.get("confirmation") != "HUMAN VERIFIED":
        return jsonify({"success": False, "error": "Type HUMAN VERIFIED after manual validation to confirm a finding"}), 403
    try:
        safe_notes = redact_text(str(notes), 4000) if notes is not None else None
        updated = ctx.database.update_finding(ctx.project_id, str(finding_id), status=str(status) if status is not None else None, researcher_notes=safe_notes)
        if not updated:
            return jsonify({"success": False, "error": "Finding not found"}), 404
        ctx.events.publish("finding_updated", message="Finding updated by researcher", data={"finding_id": finding_id, "status": status})
        return _json_response(next((x for x in ctx.database.list_findings(ctx.project_id, 5000) if x["finding_id"] == finding_id), {}))
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400


@app.get("/api/evidence")
def list_evidence():
    ctx = get_default_context()
    return _json_response(ctx.database.list_evidence(ctx.project_id, _bounded_limit(request.args.get("limit"), 500, 5000)))


@app.get("/api/evidence/<int:evidence_id>")
def evidence_detail(evidence_id):
    ctx = get_default_context()
    row = ctx.database.get_evidence(ctx.project_id, evidence_id)
    if not row:
        return jsonify({"success": False, "error": "Evidence not found"}), 404
    return _json_response(row)


@app.get("/api/reports")
def list_reports():
    ctx = get_default_context()
    return _json_response(ctx.database.list_reports(ctx.project_id))


@app.post("/api/reports")
def create_report():
    ctx = get_default_context()
    payload = _json_body()
    report_format = str(payload.get("format", "html")).lower()
    if report_format not in {"html", "json", "pdf"}:
        return jsonify({"success": False, "error": "format must be html, json or pdf"}), 400
    try:
        path = generate_report(ctx, report_format)
        report_id = ctx.database.add_report(ctx.project_id, report_format, str(path))
        ctx.events.publish("report_created", message="Report generated", data={"report_id": report_id, "format": report_format})
        return _json_response(ctx.database.get_report(ctx.project_id, report_id), 201)
    except Exception as exc:
        return jsonify({"success": False, "error": redact_text(exc, 500)}), 400


@app.get("/api/reports/<int:report_id>")
def report_detail(report_id):
    ctx = get_default_context()
    row = ctx.database.get_report(ctx.project_id, report_id)
    if not row:
        return jsonify({"success": False, "error": "Report not found"}), 404
    return _json_response(row)


@app.get("/api/reports/<int:report_id>/download")
def download_report(report_id):
    ctx = get_default_context()
    row = ctx.database.get_report(ctx.project_id, report_id)
    if not row:
        return jsonify({"success": False, "error": "Report not found"}), 404
    candidate = Path(row["path"]).resolve()
    root = resolve_path(ctx.config.get("report_dir", Path(ctx.config.get("output_dir", "output")) / "reports"))
    if root not in candidate.parents or not candidate.is_file():
        return jsonify({"success": False, "error": "Report file is unavailable"}), 404
    return send_file(candidate, as_attachment=True, download_name=candidate.name)


@app.get("/api/integrations")
def integrations():
    ctx = get_default_context()
    return _json_response({
        "tools": integration_status(ctx.config),
        "providers": [{"key": "nvd", "name": "NVD public CVE data", "enabled": bool(ctx.config.get("threat_intelligence", {}).get("enabled", False)), "policy": "opt-in, cached, keyword candidates only", "requires_network": True}],
    })


@app.get("/api/threat-intelligence")
def threat_intelligence_settings():
    ctx = get_default_context()
    return _json_response({"enabled": bool(ctx.config.get("threat_intelligence", {}).get("enabled", False)), "provider": "NVD", "manual_verification_required": True})


@app.post("/api/threat-intelligence/refresh")
def threat_intelligence_refresh():
    ctx = get_default_context()
    payload = _json_body()
    force = payload.get("force", False)
    if not isinstance(force, bool):
        return jsonify({"success": False, "error": "force must be a boolean"}), 400
    try:
        result = refresh_intelligence(ctx, str(payload.get("product", "")), str(payload.get("version", "")), force=force)
        return _json_response(result)
    except ScopeError as exc:
        return jsonify({"success": False, "error": redact_text(exc, 300)}), 403
    except (ValueError, RuntimeError) as exc:
        return jsonify({"success": False, "error": redact_text(exc, 400)}), 400


@app.get("/api/settings")
def settings():
    ctx = get_default_context()
    keys = ("safe_mode", "timeout", "request_interval", "max_requests", "max_response_bytes", "max_redirects", "max_crawl_depth", "max_urls", "scan_workers", "user_agent")
    data = {key: ctx.config.get(key) for key in keys}
    data["threat_intelligence_enabled"] = bool(ctx.config.get("threat_intelligence", {}).get("enabled", False))
    data["enabled_integrations"] = dict(ctx.config.get("enabled_integrations", {}))
    return _json_response(data)


@app.patch("/api/settings")
def update_settings():
    ctx = get_default_context()
    payload = _json_body()
    allowed = {"timeout": (1.0, 30.0), "request_interval": (0.25, 60.0), "max_requests": (1, 10000), "max_response_bytes": (4096, 5 * 1024 * 1024), "max_crawl_depth": (0, 5), "max_urls": (1, 500), "scan_workers": (1, 5)}
    config_updates = {}
    response_updates = {}
    try:
        # Validate the complete patch before mutating shared configuration. A
        # rejected field must not leave earlier fields partially applied.
        for key, bounds in allowed.items():
            if key in payload:
                value = float(payload[key]) if key in {"timeout", "request_interval"} else int(payload[key])
                if not bounds[0] <= value <= bounds[1]:
                    raise ValueError(f"{key} is outside its safe range")
                config_updates[key] = value
                response_updates[key] = value
        if "enabled_integrations" in payload:
            requested = payload["enabled_integrations"]
            allowed_tools = {"nmap", "subfinder", "amass", "httpx", "dnsx", "whatweb", "sslyze", "nuclei"}
            if not isinstance(requested, dict) or set(requested) - allowed_tools:
                raise ValueError("enabled_integrations contains invalid tool names")
            enabled = dict(ctx.config.get("enabled_integrations", {}))
            for tool, raw_value in requested.items():
                if isinstance(raw_value, bool):
                    value = raw_value
                elif str(raw_value).lower() in {"true", "1", "on"}:
                    value = True
                elif str(raw_value).lower() in {"false", "0", "off"}:
                    value = False
                else:
                    raise ValueError(f"{tool} enabled value must be boolean")
                if tool == "nuclei" and value:
                    raise ValueError("Nuclei template execution remains disabled in Safe Mode")
                enabled[tool] = value
            config_updates["enabled_integrations"] = enabled
            response_updates["enabled_integrations"] = enabled
        if "threat_intelligence_enabled" in payload:
            value = payload["threat_intelligence_enabled"]
            if not isinstance(value, bool):
                if str(value).lower() in {"true", "1", "on"}: value = True
                elif str(value).lower() in {"false", "0", "off"}: value = False
                else: raise ValueError("threat_intelligence_enabled must be boolean")
            intelligence = dict(ctx.config.get("threat_intelligence", {}))
            intelligence["enabled"] = value
            config_updates["threat_intelligence"] = intelligence
            response_updates["threat_intelligence_enabled"] = value
        if "safe_mode" in payload and payload["safe_mode"] is not True:
            raise ValueError("Safe Mode cannot be disabled through the dashboard")

        manager = ctx.scan_manager
        if manager is not None and "scan_workers" in config_updates:
            manager.resize_workers(int(config_updates["scan_workers"]))
        ctx.config.update(config_updates)
        ctx.config["safe_mode"] = True
        ctx.http.config = ctx.config
        ctx.http.rate_limiter.interval = max(0.25, float(ctx.config.get("request_interval", 1.0)))
        if ctx.global_config_path:
            from nikhil_ai_modules.config import save_config
            save_config(ctx.config, ctx.global_config_path)
        return _json_response({"updated": response_updates, "safe_mode": True})
    except (TypeError, ValueError) as exc:
        return jsonify({"success": False, "error": str(exc)}), 400


@app.get("/api/lab/status")
def local_lab_info():
    return _json_response({"bind_address": "127.0.0.1", "url": "http://127.0.0.1:5001", "start_command": "python tests/lab_app.py", "reset_path": "/__lab/reset", "note": "The lab binds only to loopback. This endpoint does not probe the lab or fabricate availability."})


@app.get("/api/search")
def global_search():
    ctx = get_default_context()
    return _json_response(ctx.database.search(ctx.project_id, request.args.get("q", ""), _bounded_limit(request.args.get("limit"), 100, 200)))


@app.post("/api/scan/<module_key>")
def scan_module(module_key):
    context = get_default_context()
    try:
        url = _json_body().get("url", "")
        if not url:
            return jsonify({"success": False, "error": "URL is required"}), 400
        data = _scan_one(module_key, str(url), context)
        return jsonify({"success": True, "data": data}), 200
    except ScopeError as exc:
        return jsonify({"success": False, "error": redact_text(exc, 500)}), 403
    except ValueError as exc:
        return jsonify({"success": False, "error": redact_text(exc, 300)}), 400
    except Exception as exc:
        context.logger.error("web scan failed module=%s: %s", module_key, redact_text(exc, 300))
        return jsonify({"success": False, "error": "Scan failed; consult local scanner.log for sanitized details."}), 500


@app.post("/api/scan/all")
def scan_all():
    context = get_default_context()
    manager = get_scan_manager(context)
    try:
        with manager.protect_project_switch():
            url = _json_body().get("url", "")
            if not url:
                return jsonify({"success": False, "error": "URL is required"}), 400
            validated = validate_target(str(url), context)
            host = host_from_target(validated)
            results, errors = {}, {}
            for key, (module_name, scanner, target_kind) in SCAN_MODULES.items():
                scan_target = host if target_kind == "host" else validated
                try:
                    results[key] = run_scan(module_name, scan_target, scanner, context=context)
                except Exception as exc:
                    errors[key] = redact_text(exc, 300)
                    results[key] = {"error": "Scan failed; see sanitized local log."}
            return jsonify({"success": not errors, "data": results, "errors": errors}), 200
    except ScopeError as exc:
        return jsonify({"success": False, "error": redact_text(exc, 500)}), 403
    except Exception as exc:
        context.logger.error("full scan request failed: %s", redact_text(exc, 300))
        return jsonify({"success": False, "error": "Full scan request failed; consult local scanner.log."}), 500


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"success": False, "error": "Request body exceeds the configured limit"}), 413


if __name__ == "__main__":
    # Localhost is the secure default: do not expose this unauthenticated
    # researcher console on a public interface. Override only for a trusted,
    # isolated preview/deployment with the required access controls.
    app.run(debug=False, host=os.environ.get("BUGHUNTER_HOST", "127.0.0.1"), port=int(os.environ.get("BUGHUNTER_PORT", "5000")))
