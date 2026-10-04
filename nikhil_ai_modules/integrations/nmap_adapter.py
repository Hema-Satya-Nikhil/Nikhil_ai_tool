"""Nmap adapter using literal, DNS-validated IP arguments and no NSE scripts."""
from __future__ import annotations

import shutil
import xml.etree.ElementTree as ET

from nikhil_ai_modules.integrations.base import run_bounded
from nikhil_ai_modules.scope import ScopeError, host_from_target


def run_nmap_safe(context, target, *, confirmed_authorization=False, ports=None, intensity="conservative", detect_versions=False):
    if not confirmed_authorization:
        raise ScopeError("Nmap requires explicit authorization confirmation")
    if context.config.get("safe_mode", True) and not context.config.get("enabled_integrations", {}).get("nmap", False):
        raise ScopeError("Nmap is not enabled in local integration settings")
    if not shutil.which("nmap"):
        raise FileNotFoundError("Nmap is not installed; native port checks remain available")
    host = host_from_target(str(target))
    addresses = context.scope.validate_host(host, resolve=True)
    configured = set(context.config.get("port_scan_ports", []))
    chosen = []
    for value in ports if ports is not None else list(configured):
        try:
            port = int(value)
            if 1 <= port <= 65535 and (not configured or port in configured) and port not in chosen:
                chosen.append(port)
        except (ValueError, TypeError):
            continue
        if len(chosen) >= 100:
            break
    if not chosen:
        raise ValueError("No configured TCP ports were selected")
    if intensity not in {"conservative", "standard"}:
        raise ValueError("Nmap intensity must be conservative or standard")
    args_common = ["-n", "-Pn", "-sT", "-T2" if intensity == "conservative" else "-T3", "--max-retries", "1", "--host-timeout", "90s", "-p", ",".join(map(str, chosen)), "--open"]
    if detect_versions:
        args_common.extend(["-sV", "--version-light"])
    rows = []
    for address in addresses[:8]:
        # No hostname is handed to Nmap: it receives only an address already
        # resolved and checked by Scope Guard. NSE and shell interpolation are absent.
        current = context.scope.validate_host(host, resolve=True)
        if address not in current:
            raise ScopeError("DNS answers changed before Nmap could run")
        context.http.rate_limiter.acquire()
        code, stdout, stderr = run_bounded(["nmap", *args_common, "-oX", "-", address], timeout=120, max_output=1_000_000)
        if code not in (0, 1):
            raise RuntimeError("Nmap exited unsuccessfully: " + (stderr[:300] or f"exit {code}"))
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as exc:
            raise RuntimeError("Nmap returned invalid or truncated XML") from exc
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            rows.append({
                "host": host,
                "ip": address,
                "port": int(port.get("portid", "0")),
                "protocol": port.get("protocol", "tcp"),
                "state": "open",
                "service": service.get("name", "unknown") if service is not None else "unknown",
                "version": " ".join(filter(None, [service.get("product", ""), service.get("version", "")])) if service is not None else "",
                "evidence": {"source": "Nmap adapter", "method": "TCP connect", "nse": False},
            })
    return {"target": host, "services": rows, "assets": [{"host": host, "status": "SCANNED"}], "potential_findings": [], "tool": "nmap", "intensity": intensity, "version_probes": bool(detect_versions)}
