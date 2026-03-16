import socket
import requests

def check_dns(domain):

    try:
        print("\n[+] Resolving domain...")

        ip = socket.gethostbyname(domain)

        print(f"[+] {domain} resolves to {ip}")

        url = f"http://{ip}"

        print("\n[+] Sending request directly to origin IP")

        headers = {
            "Host": domain,
            "User-Agent": "VAPT-Toolkit-Pro"
        }

        r = requests.get(url, headers=headers, timeout=5, allow_redirects=False)

        print(f"[+] Response Status Code: {r.status_code}")

        if r.status_code == 200:
            print("[!] Potential Origin Exposure (200 OK returned from IP)")

        elif r.status_code in [301,302,307,308]:
            print("[OK] Redirect detected (likely protected)")

        elif r.status_code == 403:
            print("[OK] Access forbidden (WAF or protection detected)")

        else:
            print("[INFO] Unexpected response:", r.status_code)

    except Exception as e:
        print("[-] DNS Misconfiguration check failed:", e)