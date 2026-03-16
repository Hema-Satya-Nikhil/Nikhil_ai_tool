import ssl
import socket

def check_ssl(domain):

    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()

                print("\n[+] SSL Certificate Info\n")

                print("Issuer:", cert['issuer'])
                print("Subject:", cert['subject'])
                print("Valid From:", cert['notBefore'])
                print("Valid Until:", cert['notAfter'])

    except Exception as e:
        print("SSL check failed:", e)