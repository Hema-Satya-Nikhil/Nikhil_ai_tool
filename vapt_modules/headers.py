import requests
from vapt_modules.output import info, warn, good, vuln, header
from vapt_modules.vapt_summary import add

def check_headers(target):

    header("HTTP Security Headers Scan")

    try:

        r = requests.get(target, timeout=5)

        headers = r.headers

        info(f"Scanning {target}")

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
                add(f"Missing security header: {h}")

    except Exception as e:

        vuln(f"Request failed: {e}")