#!/usr/bin/env python3
"""NIKHIL AI — modular, scope-first ethical security assessment toolkit."""
from __future__ import annotations

import getpass

from colorama import Fore, Style

from nikhil_ai_modules.auth_check import analyze_authentication
from nikhil_ai_modules.authz_check import compare_test_accounts
from nikhil_ai_modules.api_check import analyze_api
from nikhil_ai_modules.banner import show_banner
from nikhil_ai_modules.command_injection import detect_command_injection_signals
from nikhil_ai_modules.context import activate_project, get_default_context
from nikhil_ai_modules.evidence import redact_text
from nikhil_ai_modules.cookies import analyze_cookie_security
from nikhil_ai_modules.dns_check import check_dns
from nikhil_ai_modules.endpoint_discovery import discover_endpoints
from nikhil_ai_modules.exposure import inspect_exposure
from nikhil_ai_modules.findings import STATUSES
from nikhil_ai_modules.headers import check_headers
from nikhil_ai_modules.http_probe import probe_http_https
from nikhil_ai_modules.js_analysis import analyze_javascript_files
from nikhil_ai_modules.output import ExitRequested, bad, good, info, prompt, warn
from nikhil_ai_modules.path_traversal import detect_path_parameters
from nikhil_ai_modules.port_scan import scan_ports
from nikhil_ai_modules.report import generate_report
from nikhil_ai_modules.scan_runner import run_scan
from nikhil_ai_modules.scope import ScopeError, host_from_target, normalize_rule
from nikhil_ai_modules.sqli_check import detect_sqli
from nikhil_ai_modules.ssl_check import check_ssl
from nikhil_ai_modules.subdomains import enumerate_subdomains
from nikhil_ai_modules.web_crawler import crawl_site
from nikhil_ai_modules.template_injection import review_template_signals
from nikhil_ai_modules.service_exposure import inspect_service_exposure
from nikhil_ai_modules.tech_detect import detect_technology
from nikhil_ai_modules.upload_check import inspect_upload_surfaces
from nikhil_ai_modules.nosql_check import detect_nosql_signals


def validate_target(url, context=None):
    """Compatibility helper: normalize and scope-check an HTTP(S) target."""
    ctx = context or get_default_context()
    return ctx.scope.validate_url(url)


def validate_domain(domain, context=None):
    """Compatibility helper: validate and resolve an explicitly scoped host."""
    ctx = context or get_default_context()
    host = host_from_target(domain)
    ctx.scope.validate_host(host, resolve=True)
    return host


def _menu_items():
    return [
        (1, "Scope Manager"),
        (2, "Subdomain Enumeration"),
        (3, "HTTP / HTTPS Probing"),
        (4, "Technology Detection"),
        (5, "Endpoint / URL Discovery"),
        (6, "JavaScript Analysis"),
        (7, "HTTP Security Headers"),
        (8, "DNS / Origin Exposure"),
        (9, "SSL/TLS Audit"),
        (10, "Open Port Scanner"),
        (11, "CORS Misconfiguration"),
        (12, "Cookie Security Analysis"),
        (13, "SQL Injection Detection Assistant"),
        (14, "NoSQL Injection Detection Assistant"),
        (15, "Command Injection Detection Assistant"),
        (16, "Path Traversal Detection Assistant"),
        (17, "Authentication / Session Analysis"),
        (18, "Authorization Testing (two owned accounts)"),
        (19, "API Security Analysis"),
        (20, "File Upload Security Checks"),
        (21, "Sensitive Exposure Detection"),
        (22, "Scan History"),
        (23, "Findings"),
        (24, "Generate Report"),
        (25, "Bounded Web Crawler"),
        (26, "Template Injection Signals"),
        (27, "Database / Search Service Exposure"),
        (28, "Exit"),
    ]


def menu():
    width = 76
    border = f"{Fore.CYAN}+{'-' * (width + 2)}+{Style.RESET_ALL}"
    print(border)
    title = "NIKHIL AI | ETHICAL SECURITY ASSESSMENT"
    print(f"{Fore.CYAN}|{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{title:^{width}}{Style.RESET_ALL} {Fore.CYAN}|{Style.RESET_ALL}")
    safe_label = f"SAFE MODE: {'ON' if get_default_context().config.get('safe_mode', True) else 'OFF'}"
    print(f"{Fore.CYAN}|{Style.RESET_ALL} {Fore.GREEN}{safe_label:^{width}}{Style.RESET_ALL} {Fore.CYAN}|{Style.RESET_ALL}")
    print(border)
    for number, label in _menu_items():
        color = Fore.RED if number == 28 else Fore.GREEN if number == 1 else Fore.WHITE
        row = f"[{number:>2}]  {label}".ljust(width)
        print(f"{Fore.CYAN}|{Style.RESET_ALL} {color}{row}{Style.RESET_ALL} {Fore.CYAN}|{Style.RESET_ALL}")
    print(border)
    print(f"{Fore.CYAN}Current project:{Style.RESET_ALL} {get_default_context().config.get('project_name', 'Default Project')}")


def _ask_yes_no(label: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{label} [{suffix}] > ").strip().lower()
    return default if not answer else answer in ("y", "yes")


def _target_prompt(label="enter in-scope URL"):
    return prompt(label).strip()


def _run(module_name, target, scanner, context, **kwargs):
    result = run_scan(module_name, target, scanner, context=context, **kwargs)
    if result.get("finding_ids"):
        info("Finding IDs (NEEDS_REVIEW): " + ", ".join(result["finding_ids"]))
    return result


def _scope_manager(context):
    while True:
        print(f"\n{Fore.CYAN}SCOPE MANAGER{Style.RESET_ALL}")
        print("[1] Add in-scope domain / wildcard / IP / CIDR")
        print("[2] Add explicit exclusion")
        print("[3] Show current scope")
        print("[4] Remove an include rule")
        print("[5] Remove an exclusion")
        print("[6] Project list / create / switch")
        print("[0] Back")
        choice = prompt("scope").strip()
        if choice == "0":
            return
        if choice == "1":
            rule = prompt("scope add (example.com, *.example.com, IP, or CIDR)").strip()
            added = context.scope.add_target(rule)
            context.database.add_target_rule(context.project_id, added, "include")
            good(f"Added in-scope rule: {added}")
        elif choice == "2":
            rule = prompt("scope exclude").strip()
            added = context.scope.add_exclusion(rule)
            context.database.add_target_rule(context.project_id, added, "exclude")
            warn(f"Added exclusion (takes precedence): {added}")
        elif choice == "3":
            scope = context.scope.show()
            info("IN-SCOPE:")
            for rule in scope["in_scope"]:
                print(f"  + {rule}")
            info("OUT-OF-SCOPE / EXCLUSIONS:")
            for rule in scope["exclusions"]:
                print(f"  - {rule}")
            if not scope["in_scope"]:
                warn("No targets authorized yet. Add scope before running any scanner.")
        elif choice in ("4", "5"):
            exclusion = choice == "5"
            rule = prompt("rule to remove").strip()
            removed = context.scope.remove_target(rule, exclusion=exclusion)
            if removed:
                context.database.delete_target_rule(context.project_id, normalize_rule(rule), "exclude" if exclusion else "include")
                good("Scope rule removed")
            else:
                warn("That rule was not in the selected list")
        elif choice == "6":
            _project_menu(context)
        else:
            warn("Choose 0–6")


def _project_menu(context):
    while True:
        print("\n[1] List projects\n[2] Create project\n[3] Switch active project\n[0] Back")
        choice = prompt("project").strip()
        if choice == "0":
            return
        projects = context.database.list_projects()
        if choice == "1":
            for project in projects:
                active = " (active)" if project["id"] == context.project_id else ""
                print(f"{project['id']}: {project['name']}{active}")
            if not projects:
                info("No projects recorded")
        elif choice == "2":
            name = prompt("new project name").strip()
            context.database.create_project(name)
            activate_project(context, name)
            good(f"Created and activated project: {name} (new scope starts empty)")
        elif choice == "3":
            for project in projects:
                print(f"{project['id']}: {project['name']}")
            name = prompt("project name to activate").strip()
            if any(project["name"] == name for project in projects):
                activate_project(context, name)
                good(f"Activated project: {name}")
            else:
                warn("Project not found; create it first")
        else:
            warn("Choose 0–3")


def _show_history(context):
    rows = context.database.list_scans(context.project_id, limit=50)
    print(f"\n{Fore.CYAN}SCAN HISTORY{Style.RESET_ALL}")
    if not rows:
        info("No scans recorded for this project")
        return
    for row in rows:
        print(f"#{row['id']:<5} {row['started_at']}  {row['module']:<24} {row['status']:<10} {row['target']}")
        if row.get("error"):
            warn(row["error"])


def _show_findings(context):
    rows = context.database.list_findings(context.project_id, limit=200)
    print(f"\n{Fore.CYAN}FINDINGS (automated items are never auto-confirmed){Style.RESET_ALL}")
    if not rows:
        info("No findings recorded")
        return
    for row in rows:
        endpoints = row.get("affected_endpoints", [])
        print(f"{row['finding_id']}  [{row['status']}] {row['severity']}/{row['confidence']}  {row['title']}")
        print(f"  Category: {row['category']} | Target: {row['target']}")
        if endpoints:
            print(f"  Affected endpoints: {len(endpoints)}")
        print(f"  {row['description']}")
    if not _ask_yes_no("Update a finding's human review status?", default=False):
        return
    finding_id = prompt("finding ID").strip().upper()
    status = prompt("new status (NEW / NEEDS_REVIEW / CONFIRMED / FALSE_POSITIVE / REPORTED / RESOLVED)").strip().upper()
    if status == "CONFIRMED":
        confirmation = input("Type HUMAN VERIFIED after manual validation > ").strip()
        if confirmation != "HUMAN VERIFIED":
            warn("Confirmation status unchanged")
            return
    if context.database.update_finding_status(context.project_id, finding_id, status):
        good(f"Finding {finding_id} status updated to {status}")
    else:
        warn("Finding ID was not found")


def _generate_report(context):
    fmt = prompt("report format (html/json/pdf)").strip().lower() or "html"
    generate_report(context, fmt)


def _dispatch(choice, context):
    if choice == "1":
        _scope_manager(context)
    elif choice == "2":
        domain = prompt("in-scope seed domain").strip()
        use_ct = _ask_yes_no("Query crt.sh for passive certificate-transparency names?", default=False)
        _run("subdomain_enumeration", domain, enumerate_subdomains, context, use_ct=use_ct)
    elif choice == "3":
        target = _target_prompt()
        _run("http_https_probe", target, probe_http_https, context)
    elif choice == "4":
        target = _target_prompt()
        _run("technology_detection", target, detect_technology, context)
    elif choice == "5":
        target = _target_prompt()
        _run("endpoint_discovery", target, discover_endpoints, context)
    elif choice == "6":
        target = _target_prompt()
        _run("javascript_analysis", target, analyze_javascript_files, context)
    elif choice == "7":
        target = _target_prompt()
        _run("security_headers", target, check_headers, context)
    elif choice == "8":
        domain = prompt("in-scope domain").strip()
        _run("dns_origin_exposure", domain, check_dns, context)
    elif choice == "9":
        target = _target_prompt("in-scope domain or HTTPS URL")
        _run("ssl_tls_audit", target, check_ssl, context)
    elif choice == "10":
        host = prompt("in-scope host/domain or IP").strip()
        _run("open_port_scan", host, scan_ports, context)
    elif choice == "11":
        target = _target_prompt()
        _run("cors_check", target, check_cors, context)
    elif choice == "12":
        target = _target_prompt()
        _run("cookie_security", target, analyze_cookie_security, context)
    elif choice == "13":
        target = _target_prompt("in-scope read-only URL with candidate query parameter")
        if not _ask_yes_no("Confirm this GET endpoint is read-only and safe for one quote-only comparison?", default=False):
            warn("SQLi test not run")
            return
        _run("sqli_detection", target, detect_sqli, context, confirm_read_only=True)
    elif choice == "14":
        target = _target_prompt()
        _run("nosql_detection", target, detect_nosql_signals, context)
    elif choice == "15":
        target = _target_prompt()
        _run("command_injection_detection", target, detect_command_injection_signals, context)
    elif choice == "16":
        target = _target_prompt()
        _run("path_traversal_detection", target, detect_path_parameters, context)
    elif choice == "17":
        target = _target_prompt("in-scope login page URL")
        if _ask_yes_no("Perform one login POST with a researcher-controlled test account?", default=False):
            username = input("Test-account username > ").strip()
            password = getpass.getpass("Test-account password (not saved) > ")
            typed = input("Type TEST ACCOUNT LOGIN to confirm one authentication request > ").strip()
            if typed != "TEST ACCOUNT LOGIN":
                warn("Login request not sent")
                return
            _run("authentication_session_analysis", target, analyze_authentication, context,
                 test_login=True, confirm_login=True, credentials={"username": username, "password": password})
        else:
            _run("authentication_session_analysis", target, analyze_authentication, context)
    elif choice == "18":
        target = _target_prompt("URL of a resource created for test Account A")
        confirmation = input("Type I OWN BOTH TEST ACCOUNTS AND THIS RESOURCE > ").strip()
        if confirmation != "I OWN BOTH TEST ACCOUNTS AND THIS RESOURCE":
            warn("Authorization comparison cancelled")
            return
        token_a = getpass.getpass("Account A bearer token (not saved) > ")
        token_b = getpass.getpass("Account B bearer token (not saved) > ")
        _run("authorization_comparison", target, compare_test_accounts, context,
             account_a_token=token_a, account_b_token=token_b, confirmed=True)
    elif choice == "19":
        target = _target_prompt("in-scope API / JSON / GraphQL / docs URL")
        _run("api_security_analysis", target, analyze_api, context)
    elif choice == "20":
        target = _target_prompt()
        _run("upload_surface_review", target, inspect_upload_surfaces, context)
    elif choice == "21":
        target = _target_prompt()
        _run("sensitive_exposure_check", target, inspect_exposure, context)
    elif choice == "22":
        _show_history(context)
    elif choice == "23":
        _show_findings(context)
    elif choice == "24":
        _generate_report(context)
    elif choice == "25":
        target = _target_prompt("in-scope URL to crawl")
        _run("bounded_web_crawler", target, crawl_site, context)
    elif choice == "26":
        target = _target_prompt("in-scope URL for passive template error review")
        _run("template_injection_signals", target, review_template_signals, context)
    elif choice == "27":
        host = prompt("in-scope host for database/search service inventory").strip()
        _run("database_service_exposure", host, inspect_service_exposure, context)
    elif choice == "28":
        info("Exiting NIKHIL AI")
        raise SystemExit(0)
    else:
        warn("Invalid option")


def main():
    context = get_default_context()
    show_banner()
    info(f"Project: {context.config.get('project_name', 'Default Project')} | SAFE MODE: {'ON' if context.config.get('safe_mode', True) else 'OFF'}")
    info("Only explicitly authorized assets can be scanned. Configure scope before proceeding.")
    while True:
        try:
            print()
            menu()
            choice = prompt("module").strip()
            if choice.casefold() == "exit":
                info("Exiting NIKHIL AI")
                return
            if choice.casefold() == "clear":
                # Avoid invoking a shell command; ANSI clear works on common terminals.
                print("\033[2J\033[H", end="")
                continue
            _dispatch(choice, context)
        except (ExitRequested, KeyboardInterrupt, EOFError):
            info("Exiting NIKHIL AI")
            return
        except SystemExit:
            raise
        except Exception as exc:
            bad(f"Operation failed safely: {redact_text(exc, 500)}")
            info("No further scan was started for this menu action. Review scope and target input, then retry.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        from nikhil_ai_modules.cli import run_cli
        raise SystemExit(run_cli())
    main()
