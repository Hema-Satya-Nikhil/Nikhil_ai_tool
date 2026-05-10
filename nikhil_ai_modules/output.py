from colorama import Fore, Style, init

init(autoreset=True)
WIDTH = 64


class ExitRequested(Exception):
    """Raised when user explicitly asks to exit from a prompt."""


def _line(char="-", color=Fore.BLUE):
    print(f"{color}{char * WIDTH}{Style.RESET_ALL}")


def title(msg):
    _line("=", Fore.RED)
    print(f"{Fore.RED}[ NIKHIL AI ] {msg}{Style.RESET_ALL}")
    _line("=", Fore.RED)


def section(msg):
    print(f"\n{Fore.BLUE}[#] {msg}{Style.RESET_ALL}")
    _line("-", Fore.BLUE)


def info(msg):
    print(f"{Fore.CYAN}[i] {msg}{Style.RESET_ALL}")


def good(msg):
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")


def warn(msg):
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")


def bad(msg):
    print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")


def vuln(msg):
    print(f"{Fore.MAGENTA}[VULN] {msg}{Style.RESET_ALL}")


def header(msg):
    section(msg)


def kv(key, value):
    print(f"{Fore.WHITE}{key:<30}{Style.RESET_ALL}: {Fore.CYAN}{value}{Style.RESET_ALL}")


def prompt(label):
    value = input(f"{Fore.RED}nikhil{Style.RESET_ALL}:{Fore.CYAN}{label}{Style.RESET_ALL} > ")
    if value.strip().casefold() == "exit":
        raise ExitRequested
    return value