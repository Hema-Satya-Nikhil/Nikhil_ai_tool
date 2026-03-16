vulnerabilities = []

def add(vuln):
    vulnerabilities.append(vuln)

def show():

    print("\n==============================")
    print(" Vulnerability Summary")
    print("==============================\n")

    if not vulnerabilities:
        print("No major issues detected\n")
        return

    for v in vulnerabilities:
        print("[!] ", v)

    print("\nTotal issues found:", len(vulnerabilities))