from colorama import Fore, Style


def show_banner():

    banner = f"""
{Fore.LIGHTMAGENTA_EX}================================================================
{Fore.LIGHTMAGENTA_EX}          THIS TOOL IS DESIGNED BY THE NIKHIL
{Fore.LIGHTMAGENTA_EX}================================================================{Style.RESET_ALL}

{Fore.LIGHTBLUE_EX}Connect with the Developer:
{Fore.CYAN}  📱 Instagram   : @unknown_person_nikhil
{Fore.CYAN}  🐙 GitHub      : @Hema-Satya=Nikhil
{Fore.CYAN}  💼 LinkedIn    : @hemasatyanikhil{Style.RESET_ALL}

{Fore.LIGHTYELLOW_EX}================== TOOL OVERVIEW ==================
{Fore.GREEN}Purpose:
{Fore.WHITE}  NIKHIL AI is a comprehensive Vulnerability Assessment and Penetration
  Testing (VAPT) toolkit designed to help security professionals, developers,
  and system administrators identify and assess security vulnerabilities.

{Fore.GREEN}Why It Was Designed:
{Fore.WHITE}  This tool was created to provide an accessible, command-line based
  security assessment solution inspired by Kali Linux tools. It combines
  multiple security scanning capabilities into one integrated platform.

{Fore.GREEN}Key Benefits:
{Fore.WHITE}  ✓ Multi-module vulnerability scanning
  ✓ Quick security assessments for web applications
  ✓ SSRF protection and input validation
  ✓ User-friendly CLI interface
  ✓ Comprehensive reporting on security misconfigurations

{Fore.GREEN}How To Use:
{Fore.WHITE}  1. Run the tool and select a scan module
  2. Provide target URL or domain
  3. Wait for the scan to complete
  4. Review the results and recommendations
  5. Take action on identified vulnerabilities

{Fore.LIGHTYELLOW_EX}=================================================={Style.RESET_ALL}

{Fore.RED}================================================================
{Fore.RED}█   █  █████  █   █  █   █  █████  █        ███   █████
{Fore.RED}██  █    █    █  █   █   █    █    █       █   █    █
{Fore.RED}█ █ █    █    █ █    █   █    █    █       █   █    █
{Fore.RED}█  ██    █    ██     █████    █    █       █████    █
{Fore.RED}█   █    █    █ █    █   █    █    █       █   █    █
{Fore.RED}█   █    █    █  █   █   █    █    █       █   █    █
{Fore.RED}█   █  █████  █   █  █   █  █████  █████   █   █  █████
{Fore.RED}================================================================
{Fore.CYAN}              NIKHIL AI | Python Edition
{Fore.YELLOW}          Kali-Inspired Vulnerability Assessment CLI
{Style.RESET_ALL}
"""
    print(banner)