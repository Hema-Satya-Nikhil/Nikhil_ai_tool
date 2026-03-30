import requests
import re
import sys
import time
from vapt_modules.output import info, warn, good, vuln, header, section, kv


def _show_analysis_progress():
    msg = "Analyzing HTTP headers"
    steps = 24
    bar_size = 24
    for i in range(steps + 1):
        filled = int((i / steps) * bar_size)
        bar = "#" * filled + "-" * (bar_size - filled)
        percent = int((i / steps) * 100)
        sys.stdout.write(f"\r[i] {msg} [{bar}] {percent}%")
        sys.stdout.flush()
        time.sleep(0.035)
    print()


def _analyze_csp(csp_value):
    if not csp_value:
        warn("CSP: Missing")
        return

    lower = csp_value.lower()
    issues = []

    if "unsafe-inline" in lower:
        issues.append("uses 'unsafe-inline'")
    if "unsafe-eval" in lower:
        issues.append("uses 'unsafe-eval'")
    if "default-src" not in lower:
        issues.append("missing default-src baseline")
    if "script-src *" in lower or "default-src *" in lower:
        issues.append("contains wildcard (*) source")

    if issues:
        warn("CSP Strength: Weak")
        for issue in issues:
            warn(f"CSP issue: {issue}")
    else:
        good("CSP Strength: Strong")


def _analyze_hsts(hsts_value):
    if not hsts_value:
        warn("HSTS: Missing")
        return

    lower = hsts_value.lower()
    match = re.search(r"max-age=(\d+)", lower)
    max_age = int(match.group(1)) if match else 0
    has_subdomains = "includesubdomains" in lower
    has_preload = "preload" in lower

    if max_age >= 31536000 and has_subdomains and has_preload:
        good("HSTS Strength: Strong")
    elif max_age >= 15552000 and has_subdomains:
        warn("HSTS Strength: Medium")
    else:
        warn("HSTS Strength: Weak")

    kv("HSTS max-age", max_age if max_age else "not set")
    kv("HSTS includeSubDomains", "yes" if has_subdomains else "no")
    kv("HSTS preload", "yes" if has_preload else "no")


def check_headers(target):

    header("HTTP Security Headers Scan")

    try:

        r = requests.get(target, timeout=5)

        headers = r.headers

        info(f"Scanning {target}")
        section("Raw HTTP Response")
        print(f"HTTP/1.1 {r.status_code} {r.reason}")
        for key, value in r.headers.items():
            print(f"{key}: {value}")
        print()

        _show_analysis_progress()

        section("Security Header Analysis")
        required_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]

        for h in required_headers:
            if h in headers:
                good(f"{h} present")
            else:
                warn(f"{h} missing")

        section("Header Strength Review")
        _analyze_csp(headers.get("Content-Security-Policy"))
        _analyze_hsts(headers.get("Strict-Transport-Security"))

    except Exception as e:

        vuln(f"Request failed: {e}")
