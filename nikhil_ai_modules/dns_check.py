"""DNS resolution and explicitly authorized direct-origin visibility check."""
from __future__ import annotations

import ipaddress

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.output import good, header, info, kv, warn
from nikhil_ai_modules.scope import normalize_host


def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def check_dns(domain, context=None):
    ctx = resolve_context(context)
    host = normalize_host(domain)
    addresses = ctx.scope.validate_host(host, resolve=True)
    public = all(_is_public_ip(address) for address in addresses)
    result = {
        "domain": host,
        "resolved": addresses[0] if addresses else None,
        "addresses": addresses,
        "public": public,
        "origin_probe": "not_run",
        "potential_findings": [],
    }
    header("DNS / Origin Exposure Check")
    kv("Domain", host)
    kv("Resolved addresses", ", ".join(addresses))
    if not public:
        info("Private/lab address resolution observed; direct public-origin check is not applicable.")
        return result

    scoped_addresses = [address for address in addresses if ctx.scope.is_explicitly_ip_scoped(address)]
    if not scoped_addresses:
        info("Direct-IP origin test skipped: resolved IP is not explicitly included in scope.")
        result["origin_probe"] = "skipped_ip_not_explicitly_in_scope"
        return result

    ip = scoped_addresses[0]
    ip_host = f"[{ip}]" if ":" in ip else ip
    url = f"http://{ip_host}/"
    response = ctx.http.get(url, headers={"Host": host})
    visible = response.status_code == 200 and any(
        marker in response.text[:5000].lower() for marker in ("<html", "<title", "<body")
    )
    result["origin_probe"] = {"ip": ip, "status_code": response.status_code, "visible_content": visible}
    kv("Direct-IP HTTP status", response.status_code)
    if visible:
        warn("Potential origin exposure signal observed; verify that this IP is intended to be hidden.")
        result["potential_findings"].append({
            "title": "Potential origin exposure via public IP",
            "category": "DNS / Origin Exposure",
            "target": host,
            "endpoint": url,
            "severity": "LOW",
            "confidence": "LOW",
            "description": "A direct-IP request returned HTML-like content. Shared hosting, default pages, and CDN behavior can produce the same result.",
            "evidence": f"Authorized direct-IP HTTP probe to {ip} returned status {response.status_code} with HTML-like content.",
            "observed_behavior": "A direct-IP request returned a response resembling an HTML page.",
            "reproduction_notes": "Compare the direct-IP response with the in-scope hostname while preserving the Host header; confirm infrastructure ownership and intended exposure.",
            "remediation": "If origin isolation is required, restrict origin access to trusted proxy/CDN networks and review DNS/infrastructure configuration.",
            "status": "NEEDS_REVIEW",
            "request_method": "GET",
            "response_headers": response.headers,
            "response_excerpt": "Response content was checked for an HTML marker but intentionally not retained.",
            "status_code": response.status_code,
            "response_size": getattr(response, "_nikhil_response_size", len(response.content)),
        })
    else:
        good("No HTML-like direct-origin response observed")
    return result
