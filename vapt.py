import sys
import os
import ipaddress
import socket
try:
    import readline  # noqa: F401
except Exception:
    readline = None
# NOTE:
# This tool intentionally performs HTTP requests to user supplied targets
# for vulnerability scanning. Input validation is implemented to mitigate SSRF risks.
from urllib.parse import urlparse
from colorama import Fore, Style

from vapt_modules.banner import show_banner
from vapt_modules.headers import check_headers
from vapt_modules.ssl_check import check_ssl
from vapt_modules.dns_check import check_dns
from vapt_modules.cors_check import check_cors
from vapt_modules.port_scan import scan_ports
from vapt_modules.output import info, warn, prompt, ExitRequested


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
    except ValueError as e:
        # If parsing as IP fails, host is likely a domain name.
        # Re-raise our own explicit block messages.
        if "Private IP ranges are not allowed" in str(e):
            raise
        # hostname instead of IP (normal case)
        pass

    return url


# -------------------------------------------------
# Menu
# -------------------------------------------------

def menu():
    inner_width = 64
    def box_line(text=""):
        print(f"{Fore.CYAN}|{Style.RESET_ALL} {text.ljust(inner_width)} {Fore.CYAN}|{Style.RESET_ALL}")

    def module_row(idx, name, color):
        plain = f"[{idx:>2}]  {name}".ljust(inner_width)
        token = f"[{idx:>2}]"
        styled = plain.replace(token, f"{color}{token}{Style.RESET_ALL}", 1)
        box_line(styled)

    border = f"{Fore.CYAN}+{'-' * 66}+{Style.RESET_ALL}"
    print(border)
    box_line(f"{Fore.LIGHTCYAN_EX}{'SELECT A SCAN MODULE':^64}{Style.RESET_ALL}")
    print(border)
    module_row(1, "Missing Security Headers (MSH)", Fore.GREEN)
    module_row(2, "DNS Misconfiguration Check", Fore.GREEN)
    module_row(3, "SSL/TLS Configuration Audit", Fore.GREEN)
    module_row(4, "Open Port Scanner", Fore.GREEN)
    module_row(5, "CORS Misconfiguration Check", Fore.GREEN)
    module_row(6, "Exit", Fore.RED)
    print(border)


# -------------------------------------------------
# Main Application
# -------------------------------------------------


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
    last_choice = ""

    while True:

        print()
        menu()

        try:
            choice = input(f"{Fore.CYAN}module{Style.RESET_ALL} > ").strip()

            if choice in ("\x1b[A", "\x1b[B"):
                if last_choice:
                    info(f"Using previous option: {last_choice}")
                    choice = last_choice
                else:
                    warn("No previous option available yet.")
                    continue
            elif choice.startswith("\x1b["):
                warn("Unsupported control key input ignored.")
                continue

            if choice.casefold() == "exit":
                info("Exiting VAPT Toolkit Pro")
                sys.exit()
            elif choice == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                continue
            else:
                last_choice = choice

            if choice == "1":

                target = prompt("enter URL")
                target = validate_target(target)

                check_headers(target)

            elif choice == "2":

                domain = prompt("enter domain")
                domain = validate_domain(domain)
                check_dns(domain)

            elif choice == "3":

                domain = prompt("enter domain")
                domain = validate_domain(domain)
                check_ssl(domain)

            elif choice == "4":

                host = prompt("enter host/domain")
                host = validate_domain(host)
                scan_ports(host)

            elif choice == "5":

                target = prompt("enter URL")
                target = validate_target(target)

                check_cors(target)

            elif choice == "6":

                info("Exiting VAPT Toolkit Pro")
                sys.exit()

            else:

                warn("Invalid option")

        except (ExitRequested, KeyboardInterrupt):
            info("Exiting VAPT Toolkit Pro")
            sys.exit()

        except EOFError:
            info("Exiting VAPT Toolkit Pro")
            sys.exit()

        except Exception as e:

            print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
