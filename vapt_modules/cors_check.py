import requests

def check_cors(target):

    if not target.startswith("http"):
        target = "https://" + target

    test_origins = [
        "https://evil.com",
        "null"
    ]

    print("\n[+] Starting CORS Misconfiguration Scan\n")

    for origin in test_origins:

        print(f"[+] Testing Origin: {origin}")

        headers = {
            "Origin": origin,
            "User-Agent": "VAPT-Toolkit-Pro"
        }

        try:
            r = requests.get(target, headers=headers, timeout=5)

            acao = r.headers.get("Access-Control-Allow-Origin")
            acc = r.headers.get("Access-Control-Allow-Credentials")

            if acao:

                print("Access-Control-Allow-Origin:", acao)

                if acao == "*":
                    print("[!] Wildcard CORS detected")

                elif acao == origin:
                    print("[!] Origin reflection detected")

                elif acao == "null":
                    print("[!] Null origin allowed")

                if acc == "true":
                    print("[!] Credentials allowed with CORS")

            else:
                print("[OK] No CORS header detected")

        except Exception as e:
            print("Request failed:", e)

        print("\n-----------------------------------\n")