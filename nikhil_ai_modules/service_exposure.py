"""Read-only reachability inventory for common database/search service ports."""
from __future__ import annotations

import socket
import time

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import redact_text
from nikhil_ai_modules.output import header, info, section, warn
from nikhil_ai_modules.scope import ScopeError, host_from_target, normalize_host

SERVICE_PORTS = {
    3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB",
    6379: "Redis", 9200: "Elasticsearch",
}


def inspect_service_exposure(target, context=None, *, ports=None):
    ctx = resolve_context(context)
    host = host_from_target(str(target))
    approved = ctx.scope.validate_host(host, resolve=True)
    requested = ports if ports is not None else list(SERVICE_PORTS)
    selected = []
    for value in requested[:12]:
        try:
            port = int(value)
            if port in SERVICE_PORTS and port not in selected:
                selected.append(port)
        except (TypeError, ValueError):
            continue
    rows = []
    for address in approved[:8]:
        # Enforce current DNS/scope policy again immediately before the socket
        # operation. The peer is a literal validated IP, not a second DNS lookup.
        current = ctx.scope.validate_host(host, resolve=True)
        if address not in current:
            raise ScopeError("Resolved address changed before service inspection")
        for port in selected:
            operation_url = f"tcp://{address}:{port}"
            ctx.events.before_request("SERVICE_CONNECT", operation_url)
            runtime = ctx.events.runtime()
            control = runtime.get("control") if runtime else None
            waited = ctx.http.rate_limiter.acquire(getattr(control, "cancel_event", None))
            if waited >= 0.2:
                ctx.events.publish("rate_limit", severity="info", target=host, message="Service reachability check delayed by the shared rate limiter", data={"wait_seconds": round(waited, 3)})
            if control is not None:
                control.wait_for_resume()
            started = time.monotonic()
            banner = ""
            reachable = False
            try:
                with socket.create_connection((address, port), timeout=min(2.0, float(ctx.config.get("timeout", 6.0)))) as sock:
                    reachable = True
                    sock.settimeout(0.15)
                    try:
                        banner = redact_text(sock.recv(512), 250)
                    except (socket.timeout, OSError):
                        banner = ""
            except (OSError, TimeoutError):
                pass
            finally:
                ctx.events.after_request("SERVICE_CONNECT", operation_url, "open" if reachable else "unreachable", time.monotonic() - started)
            elapsed_ms = round((time.monotonic() - started) * 1000)
            item = {
                "host": host, "ip": address, "port": port, "protocol": "tcp",
                "state": "open" if reachable else "closed_or_filtered",
                "service": SERVICE_PORTS[port], "version": "", "banner": banner,
                "latency_ms": elapsed_ms,
                "evidence": "TCP connection outcome only; no authentication or protocol command was sent.",
            }
            rows.append(item)
    header("Database / Search Service Exposure")
    section("Connection inventory")
    info("Only TCP connection and unsolicited banner checks were performed; no commands, logins, queries, or data access were attempted.")
    for item in rows:
        if item["state"] == "open":
            warn(f"{item['service']} TCP/{item['port']} reachable at {item['ip']} ({item['latency_ms']} ms)")
    return {"target": host, "assets": [{"host": host, "status": "REACHABLE"}], "services": rows, "potential_findings": []}
