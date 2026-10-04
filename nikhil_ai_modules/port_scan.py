"""Rate-limited TCP check of a conservative, fixed list of common ports."""
from __future__ import annotations

import socket
import ssl
import time
from colorama import Fore, Style

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.events import ScanCancelled
from nikhil_ai_modules.evidence import redact_text
from nikhil_ai_modules.output import good, header, info, kv, section
from nikhil_ai_modules.scope import host_from_target

ports = [21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]


def _rate_limited_io(context, method: str, url: str):
    context.events.before_request(method, url)
    runtime = context.events.runtime()
    control = runtime.get("control") if runtime else None
    waited = context.http.rate_limiter.acquire(getattr(control, "cancel_event", None))
    if waited >= 0.2:
        context.events.publish("rate_limit", severity="info", target=url, message="Socket check delayed by the shared rate limiter", data={"wait_seconds": round(waited, 3)})
    if control is not None:
        control.wait_for_resume()
    return time.monotonic()


def _tcp_check(address: str, port: int, timeout: float, limiter, context=None) -> str:
    url = f"tcp://{address}:{port}"
    started = _rate_limited_io(context, "TCP_CONNECT", url) if context else None
    if not context:
        limiter.acquire()
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    endpoint = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
    sock = None
    state = "filtered"
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex(endpoint)
        if code == 0:
            state = "open"
        elif code in (111, 10061, 61):
            state = "closed"
        else:
            state = "filtered"
        return state
    except (OSError, socket.timeout):
        return "filtered"
    finally:
        if sock is not None:
            sock.close()
        if context and started is not None:
            context.events.after_request("TCP_CONNECT", url, state, time.monotonic() - started)


def scan_port(host, port, context=None):
    ctx = resolve_context(context)
    address = ctx.scope.validate_host(host, resolve=True)[0]
    return port if _tcp_check(address, int(port), 1.0, ctx.http.rate_limiter, ctx) == "open" else None


def _service_detail(host: str, address: str, port: int, context) -> tuple[str, str]:
    try:
        service = socket.getservbyport(port, "tcp")
    except OSError:
        service = "unknown"
    details = "-"
    try:
        if port in (80, 8080):
            # HTTP HEAD avoids downloading application content.
            scheme_host = f"[{host}]" if ":" in host else host
            response = context.http.head(f"http://{scheme_host}:{port}/")
            details = f"HTTP {response.status_code}"
            server = response.headers.get("Server")
            if server:
                details += f"; Server: {redact_text(server, 80)}"
        elif port == 443:
            url = f"tls://{address}:{port}"
            started = _rate_limited_io(context, "TLS_HANDSHAKE", url)
            status = "error"
            try:
                family = socket.AF_INET6 if ":" in address else socket.AF_INET
                endpoint = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
                raw = socket.create_connection(endpoint, timeout=2.0)
                with raw:
                    tls_context = ssl.create_default_context()
                    with tls_context.wrap_socket(raw, server_hostname=host) as wrapped:
                        details = f"TLS {wrapped.version() or 'unknown'}"
                        status = "success"
            finally:
                context.events.after_request("TLS_HANDSHAKE", url, status, time.monotonic() - started)
        elif port in (21, 22, 25, 110, 143):
            url = f"tcp://{address}:{port}"
            started = _rate_limited_io(context, "SERVICE_BANNER", url)
            status = "error"
            try:
                family = socket.AF_INET6 if ":" in address else socket.AF_INET
                endpoint = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
                with socket.create_connection(endpoint, timeout=1.5) as sock:
                    status = "success"
                    sock.settimeout(0.4)
                    try:
                        data = sock.recv(128)
                        details = redact_text(data.decode("utf-8", errors="replace").strip(), 90) or "banner unavailable"
                    except (OSError, socket.timeout):
                        details = "banner unavailable"
            finally:
                context.events.after_request("SERVICE_BANNER", url, status, time.monotonic() - started)
    except ScanCancelled:
        raise
    except Exception:
        details = "service details unavailable"
    return service, details


def scan_ports(host, context=None):
    ctx = resolve_context(context)
    target_host = host_from_target(host)
    addresses = ctx.scope.validate_host(target_host, resolve=True)
    address = addresses[0]
    selected_ports = []
    configured_ports = ctx.config.get("port_scan_ports", ports)
    if not isinstance(configured_ports, (list, tuple)):
        configured_ports = ports
    for value in configured_ports:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in selected_ports:
            selected_ports.append(port)
        if len(selected_ports) >= 100:
            break
    timeout = min(1.2, float(ctx.config.get("timeout", 6.0)))
    header("Open Port Scanner")
    info(f"Safe Mode: {'ON' if ctx.config.get('safe_mode', True) else 'OFF'} | Checking {len(selected_ports)} configured TCP ports")
    kv("Target", target_host)
    kv("Resolved address", address)

    # Sequential connects deliberately preserve one cooperative scan runtime,
    # a shared request budget, and the central minimum interval.
    states = [_tcp_check(address, port, timeout, ctx.http.rate_limiter, ctx) for port in selected_ports]
    open_ports = [port for port, state in zip(selected_ports, states) if state == "open"]
    closed_ports = [port for port, state in zip(selected_ports, states) if state == "closed"]
    filtered_ports = [port for port, state in zip(selected_ports, states) if state == "filtered"]
    open_details = []
    for port in open_ports:
        service, details = _service_detail(target_host, address, port, ctx)
        open_details.append({"port": port, "protocol": "tcp", "service": service, "details": details, "address": address})

    kv("Total ports checked", len(selected_ports))
    kv("Open ports", len(open_ports))
    if open_details:
        section("Open Port Results")
        print(f"{Fore.CYAN}{'PORT':<10}{'STATE':<10}{'SERVICE':<16}DETAILS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-' * 64}{Style.RESET_ALL}")
        for item in open_details:
            print(f"{item['port']}/tcp{'':<4}{Fore.GREEN}{'open':<10}{Fore.YELLOW}{item['service']:<16}{Fore.CYAN}{item['details']}{Style.RESET_ALL}")
    else:
        good("No open ports observed in the configured list")
    info("Port scan complete; results are limited to the configured common TCP ports.")
    return {
        "target": target_host,
        "resolved": addresses,
        "open": open_details,
        "closed": closed_ports,
        "filtered": filtered_ports,
        "checked": selected_ports,
        "potential_findings": [],
    }
