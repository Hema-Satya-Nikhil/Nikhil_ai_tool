import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
from nikhil_ai_modules.output import good, info, warn, header, kv, section

ports = [21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]


def scan_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.8)
    try:
        result = s.connect_ex((host, port))
        return port if result == 0 else None
    except Exception:
        return None
    finally:
        s.close()


def _read_banner(host, port, timeout=1.2):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
            return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def _http_probe(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: NIKHIL-AI\r\n"
                f"Connection: close\r\n\r\n"
            )
            s.sendall(req.encode())
            raw = s.recv(512).decode(errors="ignore")
            first_line = raw.splitlines()[0] if raw.splitlines() else ""
            return first_line.strip() or "http service"
    except Exception:
        return ""


def _https_probe(host, timeout=2.0):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                cn = ""
                for part in cert.get("subject", []):
                    for k, v in part:
                        if k == "commonName":
                            cn = v
                            break
                return f"tls service (CN: {cn})" if cn else "tls service"
    except Exception:
        return ""


def enumerate_service(host, port):
    try:
        base = socket.getservbyport(port, "tcp")
    except Exception:
        base = "unknown"

    # Lightweight protocol-aware hints.
    if port in (21, 22, 25, 110, 143):
        banner = _read_banner(host, port)
        if banner:
            return f"{base} | {banner[:90]}"

    if port in (80, 8080):
        http_hint = _http_probe(host, port)
        if http_hint:
            return f"http | {http_hint[:90]}"

    if port == 443:
        https_hint = _https_probe(host)
        if https_hint:
            return f"https | {https_hint[:90]}"

    return base


def scan_ports(host):
    header("Port Scanner")
    info(f"Starting threaded scan against {host}")

    target_ip = socket.gethostbyname(host)
    kv("Target", host)
    kv("Resolved IP", target_ip)

    with ThreadPoolExecutor(max_workers=40) as executor:
        open_ports = [p for p in executor.map(lambda p: scan_port(host, p), ports) if p is not None]

    open_ports.sort()

    kv("Total ports checked", len(ports))
    kv("Open ports found", len(open_ports))

    if open_ports:
        section("Open Port Results")
        print(f"{Fore.CYAN}{'PORT':<10}{'STATE':<10}{'SERVICE':<16}DETAILS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-' * 64}{Style.RESET_ALL}")
        for port in open_ports:
            service = enumerate_service(host, port)
            if " | " in service:
                service_name, details = service.split(" | ", 1)
            else:
                service_name, details = service, "-"
            print(
                f"{Fore.WHITE}{f'{port}/tcp':<10}"
                f"{Fore.GREEN}{'open':<10}"
                f"{Fore.YELLOW}{service_name:<16}"
                f"{Fore.CYAN}{details}{Style.RESET_ALL}"
            )
    else:
        warn("No open ports found in current scan scope")

    info("Scan complete")