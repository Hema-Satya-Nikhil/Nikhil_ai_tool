import requests
from urllib.parse import urlsplit
from vapt_modules.output import header, section, info, warn, good, vuln, kv


def _apply_test_origin(headers, test_origin):
    previous = headers.get("Origin")
    if previous:
        headers["Origin"] = test_origin
        return "replaced", previous
    headers["Origin"] = test_origin
    return "added", None


def check_cors(target):

    if not target.startswith("http"):
        target = "https://" + target

    parsed_target = urlsplit(target)
    host = parsed_target.netloc
    path = parsed_target.path or "/"
    if parsed_target.query:
        path = f"{path}?{parsed_target.query}"

    test_origins = ["evil.com"]

    header("CORS Misconfiguration Check")
    info(f"Target: {target}")

    for origin in test_origins:

        section(f"Testing Origin: {origin}")

        headers = {
            "Host": host,
            "User-Agent": "VAPT-Toolkit-Pro",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        action, previous_origin = _apply_test_origin(headers, origin)
        if action == "added":
            info(f"Origin header added for test: {origin}")
        else:
            info(f"Origin header replaced: {previous_origin} -> {origin}")

        try:
            r = requests.get(target, headers=headers, timeout=5)

            acao = r.headers.get("Access-Control-Allow-Origin")
            acc = r.headers.get("Access-Control-Allow-Credentials")
            acam = r.headers.get("Access-Control-Allow-Methods")
            acah = r.headers.get("Access-Control-Allow-Headers")
            acae = r.headers.get("Access-Control-Expose-Headers")

            section("Raw Request")
            print(f"GET {path} HTTP/1.1")
            for key, value in headers.items():
                print(f"{key}: {value}")
            print()

            section("Raw Response")
            print(f"HTTP/1.1 {r.status_code} {r.reason}")
            for key, value in r.headers.items():
                print(f"{key}: {value}")
            print()

            section("CORS Header Analysis")
            if acao:
                kv("Access-Control-Allow-Origin", acao)
                kv("Access-Control-Allow-Credentials", acc or "not set")
                kv("Access-Control-Allow-Methods", acam or "not set")
                kv("Access-Control-Allow-Headers", acah or "not set")
                kv("Access-Control-Expose-Headers", acae or "not set")

                acao_value = acao.strip().lower()
                origin_value = origin.strip().lower()
                reflected_origin = (acao_value == origin_value) or (origin_value in acao_value)

                if r.status_code == 200 and acao_value == "*":
                    warn("CORS Misconfiguration: 200 OK with Access-Control-Allow-Origin: *")
                elif r.status_code == 200 and reflected_origin:
                    warn("CORS Misconfiguration: 200 OK with reflected/accepted Origin")
                elif acao_value == "null":
                    warn("Potential CORS risk: null origin allowed")
                else:
                    good("No high-confidence CORS acceptance pattern detected")

                if acc == "true" and (acao_value == "*" or reflected_origin):
                    warn("High risk: credentials allowed with permissive/reflected origin")

            else:
                good("No Access-Control-Allow-Origin header detected")

        except Exception as e:
            vuln(f"Request failed: {e}")
