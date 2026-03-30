from colorama import Fore, Style

def show_banner():

    banner = f"""
{Fore.RED}================================================================
{Fore.RED} ██    ██  █████  ██████  ████████     ██████  ██████   ██████
{Fore.RED} ██    ██ ██   ██ ██   ██    ██        ██   ██ ██   ██ ██    ██
{Fore.RED} ██    ██ ███████ ██████     ██        ██████  ██████  ██    ██
{Fore.RED}  ██  ██  ██   ██ ██         ██        ██      ██   ██ ██    ██
{Fore.RED}   ████   ██   ██ ██         ██   ██   ██      ██   ██  ██████
{Fore.RED}================================================================
{Fore.CYAN}              VAPT Toolkit Pro | Python Edition
{Fore.YELLOW}          Kali-Inspired Vulnerability Assessment CLI
{Style.RESET_ALL}
"""
    print(banner)
