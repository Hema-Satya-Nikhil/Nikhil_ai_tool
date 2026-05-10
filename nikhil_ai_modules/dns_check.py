import socket
import ipaddress
import requests
from nikhil_ai_modules.output import header, info, good, warn, vuln, kv


def _is_public_ip(ip: str) -> bool:
    obj = ipaddress.ip_address(ip)
    return not (
        obj.is_private
        or obj.is_loopback
        or obj.is_link_local
        or obj.is_multicast
        or obj.is_reserved
        or obj.is_unspecified
    )


def check_dns(domain):
    header("Origin Exposure Check")

    try:
        info("Resolving domain")

        ip = socket.gethostbyname(domain)
        kv("Domain", domain)
        kv("Resolved IP", ip)

        if not _is_public_ip(ip):
            warn("Resolved IP is not public. Direct public-IP visibility test not applicable.")
            return

        info("Resolved IP is public. Testing direct access via public IP.")

        headers = {"User-Agent": "NIKHIL-AI"}
        url = f"http://{ip}"
        r = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
        kv("HTTP Status", r.status_code)

        body = (r.text or "").strip().lower()
        looks_visible = any(tag in body for tag in ["<html", "<title", "<body"])

        if r.status_code == 200 or looks_visible:
            warn("Potential Origin Exposure: Public IP is directly accessible/visible")
        else:
            good("No direct website visibility detected on public IP")

    except Exception as e:
        vuln(f"Origin exposure check failed: {e}")