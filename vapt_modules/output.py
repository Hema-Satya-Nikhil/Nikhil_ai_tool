from colorama import Fore, Style, init

init(autoreset=True)

def info(msg):
    print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")

def good(msg):
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

def warn(msg):
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

def bad(msg):
    print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")

def vuln(msg):
    print(f"{Fore.MAGENTA}[VULN] {msg}{Style.RESET_ALL}")

def header(msg):
    print(f"\n{Fore.BLUE}==== {msg} ===={Style.RESET_ALL}\n")