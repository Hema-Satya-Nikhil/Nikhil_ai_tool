import ssl
import socket
import shutil
import subprocess
from datetime import datetime, timezone
from nikhil_ai_modules.output import header, section, info, good, warn, kv, vuln


def _parse_cert_time(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _probe_protocol(domain, version):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = version
    context.maximum_version = version

    try:
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def _run_tool(command, timeout=120):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        return result.returncode, output.strip()
    except Exception as e:
        return 1, str(e)


def _print_tool_preview(label, output, max_lines=45):
    section(label)
    if not output.strip():
        warn("No output returned.")
        return
    lines = output.splitlines()
    for line in lines[:max_lines]:
        print(line)
    if len(lines) > max_lines:
        info(f"Output truncated: showing {max_lines}/{len(lines)} lines")


def check_ssl(domain):
    header("SSL/TLS Audit")
    info(f"Target: {domain}:443")

    try:
        section("Native SSL/TLS Snapshot")
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()
                kv("Negotiated TLS Version", ssock.version())
                kv("Negotiated Cipher", ssock.cipher()[0] if ssock.cipher() else "Unknown")
                kv("Issuer", cert.get("issuer"))
                kv("Subject", cert.get("subject"))
                kv("Valid From", cert.get("notBefore"))
                kv("Valid Until", cert.get("notAfter"))

                expires = _parse_cert_time(cert.get("notAfter"))
                if expires:
                    days_left = (expires - datetime.now(timezone.utc)).days
                    kv("Certificate Days Left", days_left)
                    if days_left < 0:
                        vuln("Certificate is expired")
                    elif days_left <= 30:
                        warn("Certificate expires in 30 days or less")
                    else:
                        good("Certificate validity window looks healthy")

        section("TLS Protocol Support (Native Probe)")
        supported = []
        protocol_map = [
            ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
            ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
            ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
            ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
        ]

        for name, version in protocol_map:
            if version is None:
                continue
            if _probe_protocol(domain, version):
                supported.append(name)
                if name in ("TLSv1.0", "TLSv1.1"):
                    warn(f"{name} is enabled (legacy/insecure)")
                else:
                    good(f"{name} is enabled")
            else:
                info(f"{name} not enabled")

        if not supported:
            warn("Could not confirm supported protocol versions")

        if shutil.which("nmap"):
            info("Running nmap SSL scripts (ssl-enum-ciphers, ssl-cert)")
            cmd = ["nmap", "--script", "ssl-enum-ciphers,ssl-cert", "-p", "443", domain]
            code, output = _run_tool(cmd, timeout=150)
            if code == 0 and output:
                _print_tool_preview("Nmap SSL Script Output", output)
            else:
                warn("Nmap scan did not return usable output")
                if output:
                    _print_tool_preview("Nmap Error Output", output, max_lines=20)
        else:
            warn("nmap not found on system, skipping nmap SSL script stage")

        if shutil.which("sslyze"):
            info("Running sslyze regular scan")
            cmd = ["sslyze", "--regular", f"{domain}:443"]
            code, output = _run_tool(cmd, timeout=180)
            if code == 0 and output:
                _print_tool_preview("SSLyze Output", output)
            else:
                warn("SSLyze scan did not return usable output")
                if output:
                    _print_tool_preview("SSLyze Error Output", output, max_lines=20)
        else:
            warn("sslyze not found on system, skipping sslyze stage")

    except Exception as e:
        vuln(f"SSL check failed: {e}")