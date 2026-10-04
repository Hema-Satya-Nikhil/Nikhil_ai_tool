"""Native, conservative TLS configuration inspection."""
from __future__ import annotations

import socket
import ssl
import time
import warnings
from datetime import datetime, timezone
from urllib.parse import urlsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.output import good, header, info, kv, section, warn
from nikhil_ai_modules.scope import host_from_target, normalize_url


def _parse_cert_time(value):
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _format_name(name):
    try:
        return ", ".join(f"{key}={value}" for group in name for key, value in group)
    except (TypeError, ValueError):
        return str(name or "Unknown")


def _connect_tls(host, ip, port, timeout, context):
    address = (ip, port, 0, 0) if ":" in ip else (ip, port)
    raw = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect(address)
        return context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise


def _open_tls(context, host, ip, port, timeout, tls_context, method="TLS_HANDSHAKE"):
    url = f"tls://{ip}:{port}"
    context.events.before_request(method, url)
    runtime = context.events.runtime()
    control = runtime.get("control") if runtime else None
    waited = context.http.rate_limiter.acquire(getattr(control, "cancel_event", None))
    if waited >= 0.2:
        context.events.publish("rate_limit", severity="info", target=host, message="TLS check delayed by the shared rate limiter", data={"wait_seconds": round(waited, 3)})
    if control is not None:
        control.wait_for_resume()
    started = time.monotonic()
    try:
        tls_socket = _connect_tls(host, ip, port, timeout, tls_context)
        context.events.after_request(method, url, "connected", time.monotonic() - started)
        return tls_socket
    except Exception:
        context.events.after_request(method, url, "error", time.monotonic() - started)
        raise


def _probe_protocol(host, ip, port, version, timeout, context):
    if version is None:
        return False
    try:
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            tls_context.minimum_version = version
            tls_context.maximum_version = version
        with _open_tls(context, host, ip, port, timeout, tls_context, "TLS_VERSION_PROBE") as tls_socket:
            return bool(tls_socket.version())
    except (OSError, ssl.SSLError, ValueError):
        return False


def _optional_tool_snapshot(_host, _port, context):
    """Report tool capability only; TLS scans never invoke optional binaries."""
    if context.config.get("safe_mode", True) or not context.config.get("include_optional_tools", False):
        return []
    from nikhil_ai_modules.integrations.base import integration_status
    return [
        {"tool": item["name"], "installed": item["installed"], "enabled": item["enabled"],
         "policy": item["policy"], "execution": "not invoked by the native TLS scanner"}
        for item in integration_status(context.config)
        if item["key"] in {"nmap", "sslyze"}
    ]


def check_ssl(domain, context=None):
    ctx = resolve_context(context)
    if "://" in str(domain):
        target_url = normalize_url(domain)
        parsed = urlsplit(target_url)
        host = host_from_target(target_url)
        port = parsed.port or 443
    else:
        host = host_from_target(domain)
        port = 443
    addresses = ctx.scope.validate_host(host, resolve=True)
    ip = addresses[0]
    timeout = float(ctx.config.get("timeout", 6.0))
    result = {
        "target": host,
        "port": port,
        "resolved": addresses,
        "certificate": {},
        "protocols": {},
        "optional_tools": [],
        "potential_findings": [],
    }
    header("SSL/TLS Audit")
    info(f"Target: {host}:{port}")

    certificate = {}
    verified = True
    cert_context = ssl.create_default_context()
    try:
        with _open_tls(ctx, host, ip, port, timeout, cert_context, "TLS_CERTIFICATE_CHECK") as tls_socket:
            cert = tls_socket.getpeercert() or {}
            cipher = tls_socket.cipher()
            certificate = {
                "issuer": _format_name(cert.get("issuer")),
                "subject": _format_name(cert.get("subject")),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "verified": True,
                "negotiated_tls": tls_socket.version(),
                "cipher": cipher[0] if cipher else None,
            }
    except (OSError, ssl.SSLError, ValueError) as verify_error:
        verified = False
        # A second, read-only handshake collects certificate dates for triage,
        # clearly labelled unverified. No application credentials are sent.
        try:
            unverified_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            unverified_context.check_hostname = False
            unverified_context.verify_mode = ssl.CERT_NONE
            with _open_tls(ctx, host, ip, port, timeout, unverified_context, "TLS_UNVERIFIED_REVIEW") as tls_socket:
                cert_der = tls_socket.getpeercert(binary_form=True)
                decoded = ssl.DER_cert_to_PEM_cert(cert_der) if cert_der else ""
                certificate = {
                    "issuer": "Not available without a verified certificate parser",
                    "subject": "Not available without a verified certificate parser",
                    "not_before": None,
                    "not_after": None,
                    "verified": False,
                    "negotiated_tls": tls_socket.version(),
                    "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                    "verification_error": str(verify_error)[:300],
                    "certificate_observed": bool(decoded),
                }
        except (OSError, ssl.SSLError, ValueError) as retry_error:
            certificate = {"verified": False, "verification_error": str(verify_error)[:300], "error": str(retry_error)[:300]}
    result["certificate"] = certificate
    section("Certificate / Negotiation")
    kv("Certificate verified", "yes" if verified else "no")
    kv("Negotiated TLS", certificate.get("negotiated_tls", "unavailable"))
    kv("Cipher", certificate.get("cipher", "unavailable"))
    if certificate.get("issuer"):
        kv("Issuer", certificate["issuer"])
    if certificate.get("not_after"):
        expiry = _parse_cert_time(certificate["not_after"])
        if expiry:
            days_left = (expiry - datetime.now(timezone.utc)).days
            certificate["days_left"] = days_left
            kv("Certificate days left", days_left)
            if days_left < 0:
                warn("Certificate appears expired")
                result["potential_findings"].append({
                    "title": "Potential expired TLS certificate", "category": "SSL/TLS", "target": host,
                    "endpoint": f"https://{host}:{port}", "severity": "MEDIUM", "confidence": "HIGH",
                    "description": "The observed certificate validity period has ended; confirm with a trusted client and check certificate deployment.",
                    "evidence": f"Certificate notAfter={certificate['not_after']}.",
                    "observed_behavior": "The certificate expiry timestamp is earlier than the scan time.",
                    "remediation": "Renew and deploy a currently valid certificate chain.", "status": "NEEDS_REVIEW",
                    "request_method": "TLS handshake",
                })
            elif days_left <= 30:
                warn("Certificate expires within 30 days")
            else:
                good("Certificate validity window looks healthy")
    if not verified:
        warn("Certificate verification failed or could not be completed; inspect the verification error manually.")
        if certificate.get("certificate_observed"):
            result["potential_findings"].append({
                "title": "Potential TLS certificate trust or hostname issue",
                "category": "SSL/TLS", "target": host, "endpoint": f"https://{host}:{port}",
                "severity": "MEDIUM", "confidence": "MEDIUM",
                "description": "The default certificate-verifying handshake failed, while an unverified TLS handshake observed a certificate. Misconfigured trust chains, hostname mismatch, expiration, and local trust-store problems are possible explanations.",
                "evidence": f"Verified handshake failed: {certificate.get('verification_error', 'verification failed')[:250]}.",
                "observed_behavior": "A certificate was presented but was not accepted by the default validating TLS context.",
                "reproduction_notes": "Verify from a clean, trusted client and inspect the certificate chain and hostname before confirming.",
                "remediation": "Deploy a valid certificate chain matching the hostname and ensure clients trust the issuing CA.",
                "status": "NEEDS_REVIEW", "request_method": "TLS handshake",
            })

    section("TLS Protocol Support")
    version_map = [
        ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    for label, version in version_map:
        supported = _probe_protocol(host, ip, port, version, timeout, ctx)
        result["protocols"][label] = supported
        if supported and label in ("TLS 1.0", "TLS 1.1"):
            warn(f"{label} accepted (legacy protocol)")
            result["potential_findings"].append({
                "title": f"Legacy TLS protocol enabled: {label}", "category": "SSL/TLS", "target": host,
                "endpoint": f"https://{host}:{port}", "severity": "MEDIUM", "confidence": "MEDIUM",
                "description": f"A handshake using {label} succeeded. Confirm server-side configuration and client reachability.",
                "evidence": f"A constrained TLS handshake negotiated {label}.",
                "observed_behavior": f"{label} was accepted by the TLS endpoint.",
                "remediation": "Disable deprecated TLS protocol versions and allow TLS 1.2 or later.",
                "status": "NEEDS_REVIEW", "request_method": "TLS handshake",
            })
        elif supported:
            good(f"{label} accepted")
        else:
            info(f"{label} not observed")

    result["optional_tools"] = _optional_tool_snapshot(host, port, ctx)
    return result
