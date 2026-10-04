"""Shared scope preflight, structured result persistence and scan lifecycle."""
from __future__ import annotations

from contextlib import nullcontext
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlsplit

from nikhil_ai_modules.context import ScannerContext, get_default_context
from nikhil_ai_modules.events import ScanCancelled
from nikhil_ai_modules.evidence import redact_text, sanitize_url, sanitize_value
from nikhil_ai_modules.scope import ScopeError, host_from_target, normalize_host, normalize_url


def _asset_host(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        host = urlsplit(text).hostname if "://" in text else text
        return normalize_host(host or "")
    except Exception:
        return None


def _safe_endpoint(value: Any, context: ScannerContext) -> Optional[str]:
    try:
        cleaned = sanitize_url(normalize_url(str(value)))
        host = urlsplit(cleaned).hostname
        if not host:
            return None
        context.scope.validate_host(host, resolve=True)
        return cleaned
    except (ScopeError, ValueError, TypeError):
        return None


def _persist_assets(ctx: ScannerContext, result: Dict[str, Any], module_name: str, scan_id: int) -> None:
    assets = result.get("assets", [])
    if not isinstance(assets, list):
        return
    accepted = []
    for asset in assets:
        record = {"host": asset, "status": None, "details": {"source": module_name}} if isinstance(asset, str) else asset
        if not isinstance(record, dict) or not record.get("host"):
            continue
        record = dict(record)
        host = _asset_host(str(record["host"]))
        if not host:
            continue
        try:
            ctx.scope.require_host_rule(host)
            resolved_addresses = set(ctx.scope.validate_host(host, resolve=True))
        except ScopeError as exc:
            ctx.events.fail_scope(host, str(exc), scan_id)
            continue
        safe_addresses = []
        addresses = record.get("addresses", [])
        if isinstance(addresses, list):
            for address in addresses[:32]:
                try:
                    ip = normalize_host(str(address))
                except ValueError:
                    continue
                if ip not in resolved_addresses:
                    continue
                safe_addresses.append(ip)
                ctx.database.add_asset_relation(ctx.project_id, "host", host, "resolves_to", "ip", ip)
        if "addresses" in record:
            record["addresses"] = safe_addresses
        record["host"] = host
        is_new = ctx.database.upsert_asset(ctx.project_id, host, record.get("status"), record)
        accepted.append(record)
        if is_new:
            ctx.events.publish("asset_discovered", scan_id=scan_id, target=host, message="New in-scope asset discovered", data={"host": host, "status": record.get("status"), "source": module_name})
    result["assets"] = accepted


def _persist_endpoints(ctx: ScannerContext, result: Dict[str, Any], module_name: str, scan_id: int) -> None:
    endpoints = result.get("endpoints", [])
    if not isinstance(endpoints, list):
        return
    accepted = []
    for endpoint in endpoints:
        record = {"url": endpoint, "method": "GET", "source": module_name} if isinstance(endpoint, str) else endpoint
        if not isinstance(record, dict) or not record.get("url"):
            continue
        record = dict(record)
        url = _safe_endpoint(record["url"], ctx)
        if not url:
            raw = str(record.get("url", ""))[:300]
            ctx.events.fail_scope(raw, "Discovered endpoint did not match explicit scope", scan_id)
            continue
        record["url"] = url
        is_new = ctx.database.upsert_endpoint(
            ctx.project_id, url, record.get("method", "GET"), record.get("status_code"),
            record.get("content_type"), record.get("source", module_name), record,
        )
        accepted.append(record)
        if is_new:
            ctx.events.publish("endpoint_discovered", scan_id=scan_id, target=url, message="New in-scope endpoint discovered", data={"url": url, "method": record.get("method", "GET"), "status_code": record.get("status_code")})
        host = urlsplit(url).hostname
        if host:
            ctx.database.add_asset_relation(ctx.project_id, "host", host, "has_endpoint", "endpoint", url)
    result["endpoints"] = accepted


def _persist_services(ctx: ScannerContext, result: Dict[str, Any], scan_id: int, target: str) -> None:
    services = result.get("services", [])
    if not isinstance(services, list):
        services = []
    if isinstance(result.get("open"), list):
        host_from_result = _asset_host(target) or str(target)
        services.extend({"host": host_from_result, "ip": row.get("address", ""), "port": row.get("port"), "protocol": row.get("protocol", "tcp"), "state": "open", "service": row.get("service", "unknown"), "version": "", "evidence": {"details": row.get("details", ""), "source": "native port scanner"}} for row in result["open"] if isinstance(row, dict))
    accepted = []
    for item in services:
        if not isinstance(item, dict) or item.get("state") != "open":
            continue
        item = dict(item)
        host = _asset_host(item.get("host", ""))
        if not host:
            continue
        try:
            addresses = set(ctx.scope.validate_host(host, resolve=True))
        except ScopeError as exc:
            ctx.events.fail_scope(host, str(exc), scan_id)
            continue
        try:
            port = int(item.get("port", 0))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        protocol = str(item.get("protocol", "tcp")).lower()
        if protocol not in {"tcp", "udp"}:
            continue
        ip_value = ""
        if item.get("ip"):
            try:
                ip_value = normalize_host(str(item["ip"]))
            except ValueError:
                continue
            if ip_value not in addresses:
                continue
        service = str(item.get("service", "unknown"))[:80]
        version = str(item.get("version", ""))[:160]
        safe_item = {**item, "host": host, "ip": ip_value, "port": port, "protocol": protocol, "state": "open", "service": service, "version": version}
        accepted.append(safe_item)
        created = ctx.database.upsert_service(ctx.project_id, host, ip_value, port, protocol, "open", service, version, item.get("evidence", {}))
        ctx.database.add_asset_relation(ctx.project_id, "host", host, "exposes", "service", f"{service}:{port}/{protocol}")
        if created:
            ctx.events.publish("host_up", scan_id=scan_id, target=host, message=f"New in-scope service observed: {service} {protocol.upper()}/{port}", data={"service": service, "port": port, "protocol": protocol, "ip": ip_value})
    result["services"] = accepted


def _persist_technologies(ctx: ScannerContext, result: Dict[str, Any], module_name: str, scan_id: int, target: str) -> None:
    nested = result.get("modules")
    if isinstance(nested, dict):
        for name, child in nested.items():
            if isinstance(child, dict):
                _persist_technologies(ctx, child, str(name), scan_id, target)
    groups = []
    if isinstance(result.get("technologies"), list):
        groups.append({"url": target, "technologies": result["technologies"]})
    if isinstance(result.get("detections"), list):
        groups.extend(x for x in result["detections"] if isinstance(x, dict))
    if isinstance(result.get("probes"), list):
        for probe in result["probes"]:
            if isinstance(probe, dict) and isinstance(probe.get("technologies"), list):
                groups.append({"url": probe.get("final_url") or probe.get("requested_url") or target, "technologies": probe["technologies"]})
    for group in groups:
        host = _asset_host(group.get("url") or target) or _asset_host(target)
        if not host:
            continue
        try:
            ctx.scope.validate_host(host, resolve=True)
        except ScopeError as exc:
            ctx.events.fail_scope(host, str(exc), scan_id)
            continue
        for item in group.get("technologies", []) if isinstance(group.get("technologies"), list) else []:
            if not isinstance(item, dict) or not item.get("technology"):
                continue
            name = str(item["technology"])[:120]
            confidence = str(item.get("confidence", "LOW")).upper()
            evidence = "; ".join(str(x) for x in item.get("evidence", [])[:5]) if isinstance(item.get("evidence"), list) else str(item.get("evidence", ""))
            ctx.database.upsert_technology(ctx.project_id, host, name, item.get("category", "Unknown"), confidence, module_name, evidence)
            ctx.database.add_asset_relation(ctx.project_id, "host", host, "uses", "technology", name)
            ctx.events.publish("technology_detected", scan_id=scan_id, target=host, message=f"Technology indicator: {name}", data={"technology": name, "confidence": confidence, "evidence": evidence[:500]})


def run_scan(
    module_name: str,
    target: str,
    scanner: Callable,
    *,
    context: Optional[ScannerContext] = None,
    scan_id: Optional[int] = None,
    **kwargs,
) -> Dict[str, Any]:
    ctx = context or get_default_context()
    safe_target = sanitize_url(target) if "://" in str(target) else redact_text(target, 300)
    owns_scan = scan_id is None
    if owns_scan:
        # Keep prior CLI behavior: reject unsafe targets before opening a history row.
        if "://" in str(target):
            ctx.scope.validate_url(target)
        else:
            ctx.scope.validate_host(host_from_target(target), resolve=True)
        scan_id = ctx.database.start_scan(ctx.project_id, safe_target, module_name, status="RUNNING")
    assert scan_id is not None
    ctx.logger.info("scan start module=%s target=%s scan_id=%s", module_name, safe_target, scan_id)
    runtime = ctx.events.runtime()
    binding = nullcontext() if runtime and runtime.get("scan_id") == scan_id else ctx.events.bind_scan(scan_id, target)
    try:
        with binding:
            if "://" in str(target):
                ctx.scope.validate_url(target)
            else:
                ctx.scope.validate_host(host_from_target(target), resolve=True)
            if owns_scan:
                ctx.database.update_scan_state(scan_id, "RUNNING", current_action=f"Running {module_name}")
            else:
                ctx.database.update_scan_state(scan_id, current_action=f"Running {module_name}")
            ctx.events.publish("scan_progress", scan_id=scan_id, target=safe_target, message=f"Running {module_name}", data={"module": module_name, "progress": None, "current_action": f"Running {module_name}"})
            raw_result = scanner(target, context=ctx, **kwargs)
            from nikhil_ai_modules.plugins import ScanResult
            if isinstance(raw_result, ScanResult):
                raw_result = raw_result.to_dict()
            if not isinstance(raw_result, dict):
                raw_result = {"result": raw_result}
            result = sanitize_value(raw_result)
            _persist_assets(ctx, result, module_name, scan_id)
            _persist_endpoints(ctx, result, module_name, scan_id)
            _persist_services(ctx, result, scan_id, target)
            _persist_technologies(ctx, result, module_name, scan_id, target)

            persisted_ids = []
            accepted_findings = []
            potential_findings = result.get("potential_findings", [])
            if isinstance(potential_findings, list):
                for raw_candidate in potential_findings[:500]:
                    if not isinstance(raw_candidate, dict):
                        continue
                    try:
                        candidate = dict(raw_candidate)
                        candidate.setdefault("target", safe_target)
                        candidate_target = str(candidate.get("target") or safe_target)[:2000]
                        finding_host = _asset_host(candidate_target)
                        if not finding_host:
                            raise ValueError("Finding target is not a valid host or URL")
                        try:
                            ctx.scope.validate_host(finding_host, resolve=True)
                        except ScopeError as exc:
                            ctx.events.fail_scope(candidate_target, str(exc), scan_id)
                            continue
                        candidate["target"] = sanitize_url(candidate_target) if "://" in candidate_target else redact_text(candidate_target, 300)
                        if candidate.get("endpoint"):
                            endpoint = _safe_endpoint(candidate["endpoint"], ctx)
                            if not endpoint:
                                ctx.events.fail_scope(str(candidate.get("endpoint", ""))[:300], "Finding endpoint did not match explicit scope", scan_id)
                                continue
                            candidate["endpoint"] = endpoint
                        candidate["module"] = module_name
                        candidate["status"] = "NEEDS_REVIEW"
                        stored = ctx.findings.add(candidate)
                        persisted_ids.append(stored["finding_id"])
                        accepted_findings.append(candidate)
                        ctx.database.add_asset_relation(ctx.project_id, "host", finding_host, "has_finding", "finding", stored["finding_id"])
                        event_type = "finding_created" if stored.get("was_created") else "finding_updated"
                        ctx.events.publish(event_type, scan_id=scan_id, target=candidate["target"], severity=str(candidate.get("severity", "info")).lower(), message=str(candidate.get("title", "Potential finding")), data={"finding_id": stored["finding_id"], "status": "NEEDS_REVIEW", "severity": stored.get("severity"), "confidence": stored.get("confidence"), "module": module_name})
                        ctx.logger.info("finding recorded id=%s category=%s target=%s title=%s status=NEEDS_REVIEW", stored["finding_id"], redact_text(candidate.get("category", ""), 120), safe_target, redact_text(candidate.get("title", ""), 200))
                        ev = candidate.get("evidence")
                        ctx.evidence.record(
                            target=candidate["target"], endpoint=candidate.get("endpoint"),
                            request_method=candidate.get("request_method"), request=candidate.get("request", {}),
                            response_headers=candidate.get("response_headers", {}), response_excerpt=candidate.get("response_excerpt", ""),
                            status_code=candidate.get("status_code"), response_size=candidate.get("response_size"),
                            evidence_description=ev if isinstance(ev, str) else candidate.get("observed_behavior", "Automated observation; manual verification required."),
                            finding_id=stored["finding_id"], scan_id=scan_id,
                        )
                    except Exception as exc:
                        ctx.events.publish("warning", scan_id=scan_id, target=safe_target, severity="warning", message="Malformed scanner finding was skipped", data={"module": module_name, "error": redact_text(exc, 200)})
                        ctx.logger.warning("malformed finding skipped module=%s error=%s", module_name, redact_text(exc, 200))
            if isinstance(potential_findings, list):
                result["potential_findings"] = accepted_findings
            if persisted_ids:
                result["finding_ids"] = list(dict.fromkeys(persisted_ids))
            if isinstance(result.get("evidence"), list):
                accepted_evidence = []
                for item in result["evidence"][:200]:
                    if not isinstance(item, dict):
                        continue
                    item = dict(item)
                    evidence_target = str(item.get("target") or safe_target)[:2000]
                    evidence_host = _asset_host(evidence_target)
                    try:
                        if not evidence_host:
                            raise ScopeError("Scanner evidence target is not a valid host or URL")
                        ctx.scope.validate_host(evidence_host, resolve=True)
                    except ScopeError as exc:
                        ctx.events.fail_scope(evidence_target, str(exc), scan_id)
                        continue
                    endpoint = item.get("endpoint")
                    if endpoint:
                        endpoint = _safe_endpoint(endpoint, ctx)
                        if not endpoint:
                            ctx.events.fail_scope(str(item.get("endpoint", ""))[:300], "Scanner evidence endpoint did not match explicit scope", scan_id)
                            continue
                        item["endpoint"] = endpoint
                    item["target"] = sanitize_url(evidence_target) if "://" in evidence_target else redact_text(evidence_target, 300)
                    accepted_evidence.append(item)
                    ctx.evidence.record(
                        target=item["target"], endpoint=endpoint, request_method=item.get("request_method"), request=item.get("request", {}),
                        response_headers=item.get("response_headers", {}), response_excerpt=item.get("response_excerpt", ""),
                        status_code=item.get("status_code"), response_size=item.get("response_size"),
                        evidence_description=item.get("description", item.get("evidence_description", "Scanner evidence; manual interpretation required.")),
                        finding_id=item.get("finding_id"), scan_id=scan_id,
                    )
                result["evidence"] = accepted_evidence
            if isinstance(result.get("events"), list):
                accepted_events = []
                for item in result["events"][:200]:
                    if not isinstance(item, dict) or not item.get("type"):
                        continue
                    item = dict(item)
                    event_target = str(item.get("target") or safe_target)[:2000]
                    event_host = _asset_host(event_target)
                    try:
                        if not event_host:
                            raise ScopeError("Scanner event target is not a valid host or URL")
                        ctx.scope.validate_host(event_host, resolve=True)
                    except ScopeError as exc:
                        ctx.events.fail_scope(event_target, str(exc), scan_id)
                        continue
                    item["target"] = sanitize_url(event_target) if "://" in event_target else redact_text(event_target, 300)
                    accepted_events.append(item)
                    ctx.events.publish(str(item["type"]), scan_id=scan_id, target=item["target"], severity=item.get("severity", "info"), message=str(item.get("message", "Scanner event")), data=item.get("data", {}))
                result["events"] = accepted_events
            runtime_state = ctx.events.runtime()
            control = runtime_state.get("control") if runtime_state else None
            manager = ctx.scan_manager if control is not None else None
            if manager is not None:
                while True:
                    control.wait_for_resume()
                    with manager.lock:
                        if control.cancel_event.is_set():
                            raise ScanCancelled("Scan cancellation requested")
                        if not control.resume_event.is_set():
                            continue
                        ctx.database.finish_scan(scan_id, "COMPLETED", result)
                        break
            else:
                if control is not None:
                    control.wait_for_resume()
                ctx.database.finish_scan(scan_id, "COMPLETED", result)
            ctx.events.publish("scan_progress", scan_id=scan_id, target=safe_target, message="Result persistence complete", data={"progress": 100, "current_action": "Result persistence complete"})
            ctx.logger.info("scan complete module=%s target=%s findings=%d", module_name, safe_target, len(persisted_ids))
            return result
    except ScanCancelled as exc:
        safe_error = redact_text(exc, 500)
        ctx.database.finish_scan(scan_id, "CANCELLED", {"cancelled": True}, safe_error)
        ctx.events.publish("scan_cancelled", scan_id=scan_id, target=safe_target, severity="warning", message="Scan cancelled at a safe checkpoint")
        raise
    except Exception as exc:
        safe_error = redact_text(exc, 1000)
        if isinstance(exc, ScopeError):
            ctx.events.fail_scope(safe_target, safe_error, scan_id)
        ctx.database.finish_scan(scan_id, "FAILED", {"error": safe_error}, safe_error)
        ctx.logger.error("scan failed module=%s target=%s error=%s", module_name, safe_target, safe_error)
        raise
