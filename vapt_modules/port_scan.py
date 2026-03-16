import socket
from concurrent.futures import ThreadPoolExecutor
from vapt_modules.output import good, info, header

ports = [21,22,25,53,80,110,139,143,443,445,3306,3389,8080]

def scan_port(host, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    result = s.connect_ex((host, port))

    if result == 0:
        good(f"Port {port} OPEN")

    s.close()

def scan_ports(host):

    header("Port Scanner")

    info("Starting threaded scan...")

    with ThreadPoolExecutor(max_workers=50) as executor:

        executor.map(lambda p: scan_port(host, p), ports)

    info("Scan complete")