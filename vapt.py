import sys
import os
import ipaddress
# NOTE:
# This tool intentionally performs HTTP requests to user supplied targets
# for vulnerability scanning. Input validation is implemented to mitigate SSRF risks.
from urllib.parse import urlparse

from vapt_modules.banner import show_banner
from vapt_modules.headers import check_headers
from vapt_modules.ssl_check import check_ssl
from vapt_modules.dns_check import check_dns
from vapt_modules.cors_check import check_cors
from vapt_modules.port_scan import scan_ports


# -------------------------------------------------
# SSRF Protection + Input Validation
# -------------------------------------------------

def validate_target(url):

    # add https automatically
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        raise ValueError("Only HTTP/HTTPS URLs allowed")

    host = parsed.hostname

    if host in ["localhost", "127.0.0.1"]:
        raise ValueError("Localhost targets are blocked")

    try:
        ip = ipaddress.ip_address(host)

        if ip.is_private or ip.is_loopback:
            raise ValueError("Private IP ranges are not allowed")

    except ValueError:
        # hostname instead of IP (normal case)
        pass

    return url


# -------------------------------------------------
# Menu
# -------------------------------------------------

def menu():

    print("""
1. HTTP Security Headers Check
2. SSL/TLS Audit
3. Origin Exposure Check
4. Port Scanner
5. CORS Misconfiguration Check
6. Exit
""")


# -------------------------------------------------
# Main Application
# -------------------------------------------------
import socket
import ipaddress


def validate_domain(domain):

    try:
        ip = socket.gethostbyname(domain)

        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            raise ValueError("Target resolves to a private/internal IP")

    except Exception as e:
        raise ValueError(f"Invalid or unsafe domain: {e}")

    return domain


def main():

    show_banner()

    while True:

        menu()

        choice = input("Select option: ")

        try:

            if choice == "1":

                target = input("Enter URL: ")
                target = validate_target(target)

                check_headers(target)

            elif choice == "2":

                domain = input("Enter domain: ")
                check_ssl(domain)

            elif choice == "3":

                domain = input("Enter domain: ")
                check_dns(domain)

            elif choice == "4":

                host = input("Enter host: ")
                scan_ports(host)

            elif choice == "5":

                target = input("Enter URL: ")
                target = validate_target(target)

                check_cors(target)

            elif choice == "6":

                print("Exiting VAPT Toolkit Pro")
                sys.exit()

            else:

                print("Invalid option")

        except Exception as e:

            print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()