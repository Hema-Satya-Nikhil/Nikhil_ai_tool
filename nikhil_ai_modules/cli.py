"""Optional command-line subcommands; the interactive menu remains the default."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import time
from pathlib import Path

from nikhil_ai_modules.context import activate_project, get_default_context, get_scan_manager
from nikhil_ai_modules.evidence import redact_text
from nikhil_ai_modules.plugins import REGISTRY
from nikhil_ai_modules.report import generate_report
from nikhil_ai_modules.scan_runner import run_scan
from nikhil_ai_modules.scope import ScopeError


def _select_project(context, selection):
    if not selection:
        return None
    path = Path(selection).expanduser()
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("Project file must be readable JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("Project file must contain a JSON object")
        name = str(payload.get("project_name") or payload.get("name") or "").strip()
        if not name:
            raise ValueError("Project file must contain project_name or name")
        target = payload.get("target")
        if isinstance(payload.get("targets"), list):
            if target or len(payload["targets"]) != 1:
                raise ValueError("Project-file scans require exactly one explicit target field")
            target = payload["targets"][0]
        project = next((item for item in context.database.list_projects() if item["name"] == name), None)
        if not project:
            raise ValueError("Project is not registered locally; create it and configure its scope first")
        activate_project(context, name)
        return {"target": str(target or ""), "module": str(payload.get("module", ""))}
    project = next((item for item in context.database.list_projects() if item["name"] == selection), None)
    if not project:
        raise ValueError("Project name not found in local database")
    activate_project(context, selection)
    return None


def build_parser():
    parser = argparse.ArgumentParser(prog="nikhil_toolkit.py", description="NIKHIL Security Platform — authorized testing only")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Queue and monitor a scope-checked scan")
    scan.add_argument("--target", help="In-scope URL or host")
    scan.add_argument("--project", help="Existing project name or local JSON file with project_name and target")
    scan.add_argument("--module", choices=["baseline", *sorted(REGISTRY)], default="baseline")
    scan.add_argument("--json", action="store_true", help="Print one structured JSON result")
    findings = subparsers.add_parser("findings", help="List findings for the active or named local project")
    findings.add_argument("--project")
    findings.add_argument("--status")
    findings.add_argument("--severity")
    findings.add_argument("--json", action="store_true")
    report = subparsers.add_parser("report", help="Generate a redacted report")
    report.add_argument("--project")
    report.add_argument("--format", choices=["html", "json", "pdf"], default="html")
    integrations = subparsers.add_parser("integrations", help="Show optional tool availability")
    integrations.add_argument("--json", action="store_true")
    integration = subparsers.add_parser("integration", help="Run an explicitly authorized optional adapter")
    integration.add_argument("--tool", choices=["nmap", "subfinder", "amass"], required=True)
    integration.add_argument("--target", help="In-scope host (Nmap)")
    integration.add_argument("--seed", help="In-scope domain seed (passive Subfinder/Amass)")
    integration.add_argument("--confirm-authorized", action="store_true", help="Required explicit authorization acknowledgement")
    integration.add_argument("--intensity", choices=["conservative", "standard"], default="conservative")
    integration.add_argument("--detect-versions", action="store_true", help="Allow limited service version probes")
    integration.add_argument("--json", action="store_true")
    return parser


def run_cli(argv=None):
    args = build_parser().parse_args(argv)
    context = get_default_context()
    try:
        project_input = _select_project(context, getattr(args, "project", None))
        if args.command == "scan":
            target = args.target or (project_input or {}).get("target", "")
            module = args.module
            file_module = (project_input or {}).get("module")
            if file_module and module == "baseline":
                module = file_module
            if not target:
                raise ValueError("Provide --target or a project JSON file containing target")
            manager = get_scan_manager(context)
            capture = io.StringIO()
            stream_context = contextlib.redirect_stdout(capture) if args.json else contextlib.nullcontext()
            with stream_context:
                scan = manager.submit(module, target)
                scan_id = int(scan["id"])
                with manager.lock:
                    job = manager.jobs.get(scan_id)
                    future = job.future if job else None
                last_id = 0
                if not args.json:
                    print(f"Queued {scan.get('display_id', f'SCAN-{scan_id:04d}')} · {module} · {redact_text(scan.get('target', target), 300)}")
                while future and not future.done():
                    if not args.json:
                        for event in context.events.events_after(last_id, 100):
                            last_id = int(event["event_id"])
                            if event.get("type") in {"scan_progress", "asset_discovered", "endpoint_discovered", "finding_created", "warning", "error", "scope_block"}:
                                print(f"{event['timestamp']} [{event['type'].upper()}] {event['message']}")
                    context.events.wait_for_event(0.25)
                if future:
                    future.result()
                final = context.database.get_scan(context.project_id, scan_id)
            if args.json:
                print(json.dumps(final, ensure_ascii=False, default=str))
            else:
                print(f"{final['display_id']} {final['status']} · {final.get('requests', 0)} requests · {final.get('current_action', '')}")
            return 0 if final["status"] == "COMPLETED" else 1
        if args.command == "integration":
            if not args.confirm_authorized:
                raise ValueError("Pass --confirm-authorized only after verifying written authorization and program scope")
            if args.tool == "nmap":
                if not args.target:
                    raise ValueError("Nmap requires --target")
                from nikhil_ai_modules.integrations.nmap_adapter import run_nmap_safe
                def nmap_scan(target, context=None):
                    return run_nmap_safe(context, target, confirmed_authorization=True, intensity=args.intensity, detect_versions=args.detect_versions)
                result = run_scan("nmap_integration", args.target, nmap_scan, context=context)
            else:
                if not args.seed:
                    raise ValueError("Passive subdomain adapters require --seed")
                adapter_name = "subfinder_adapter" if args.tool == "subfinder" else "amass_adapter"
                adapter = __import__(f"nikhil_ai_modules.integrations.{adapter_name}", fromlist=["enumerate_passive"])
                result = adapter.enumerate_passive(context, args.seed, confirmed_authorization=True)
                for item in result.get("assets", []):
                    host = item.get("host") if isinstance(item, dict) else item
                    if host and context.scope.is_in_scope(host):
                        if context.database.upsert_asset(context.project_id, host, "DISCOVERED", {"source": args.tool}):
                            context.events.publish("asset_discovered", target=host, message="New in-scope passive asset discovered", data={"host": host, "source": args.tool})
            if args.json:
                print(json.dumps(result, ensure_ascii=False, default=str))
            else:
                print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
            return 0
        if args.command == "findings":
            filters = {key: value for key, value in (("status", args.status), ("severity", args.severity)) if value}
            result = context.database.list_findings(context.project_id, 1000, filters)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, default=str))
            else:
                for item in result:
                    print(f"{item['finding_id']} [{item['status']}] {item['severity']}/{item['confidence']} {item['title']} — {item['target']}")
                if not result:
                    print("No findings recorded for this project.")
            return 0
        if args.command == "report":
            path = generate_report(context, args.format)
            context.database.add_report(context.project_id, args.format, str(path))
            print(path)
            return 0
        if args.command == "integrations":
            from nikhil_ai_modules.integrations import integration_status
            result = integration_status(context.config)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, default=str))
            else:
                for item in result:
                    print(f"{item['name']:<14} {'INSTALLED' if item['installed'] else 'NOT INSTALLED':<14} {item['version']}")
            return 0
    except (ScopeError, ValueError, OSError, RuntimeError) as exc:
        if getattr(args, "json", False):
            print(json.dumps({"success": False, "error": redact_text(exc, 500)}))
        else:
            print(f"Error: {redact_text(exc, 500)}", file=sys.stderr)
        return 2
    return 2
