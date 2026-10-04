"""Declarative registry for assessment modules and their safe-mode capabilities."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from nikhil_ai_modules.api_check import analyze_api
from nikhil_ai_modules.auth_check import analyze_authentication
from nikhil_ai_modules.authz_check import compare_test_accounts
from nikhil_ai_modules.command_injection import detect_command_injection_signals
from nikhil_ai_modules.cors_check import check_cors
from nikhil_ai_modules.cookies import analyze_cookie_security
from nikhil_ai_modules.dns_check import check_dns
from nikhil_ai_modules.endpoint_discovery import discover_endpoints
from nikhil_ai_modules.exposure import inspect_exposure
from nikhil_ai_modules.headers import check_headers
from nikhil_ai_modules.http_probe import probe_http_https
from nikhil_ai_modules.js_analysis import analyze_javascript_files
from nikhil_ai_modules.nosql_check import detect_nosql_signals
from nikhil_ai_modules.path_traversal import detect_path_parameters
from nikhil_ai_modules.port_scan import scan_ports
from nikhil_ai_modules.sqli_check import detect_sqli
from nikhil_ai_modules.ssl_check import check_ssl
from nikhil_ai_modules.subdomains import enumerate_subdomains
from nikhil_ai_modules.tech_detect import detect_technology
from nikhil_ai_modules.upload_check import inspect_upload_surfaces
from nikhil_ai_modules.web_crawler import crawl_site
from nikhil_ai_modules.template_injection import review_template_signals
from nikhil_ai_modules.service_exposure import inspect_service_exposure


@dataclass
class ScanResult:
    """Normalized result envelope accepted by the scan runner and plugins."""
    assets: List[Any] = field(default_factory=list)
    endpoints: List[Any] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = dict(self.data)
        result.update({"assets": self.assets, "endpoints": self.endpoints, "potential_findings": self.findings,
                       "evidence": self.evidence, "events": self.events, "metrics": self.metrics})
        return result


@dataclass(frozen=True)
class ScannerSpec:
    key: str
    name: str
    description: str
    category: str
    scanner: Callable
    target_kind: str = "url"
    requires_network: bool = True
    supports_safe_mode: bool = True


_SPECS = (
    ScannerSpec("subdomains", "Subdomain Enumeration", "Opt-in passive certificate-transparency discovery with strict scope filtering.", "recon", enumerate_subdomains, "host"),
    ScannerSpec("http", "HTTP / HTTPS Probe", "Bounded, scope-checked response metadata and technology indicators.", "recon", probe_http_https),
    ScannerSpec("technology", "Technology Detection", "Evidence-backed technology indicators; heuristics are not proof.", "recon", detect_technology),
    ScannerSpec("endpoints", "Endpoint Discovery", "Shallow links, scripts, robots, sitemap and API documentation inventory.", "recon", discover_endpoints),
    ScannerSpec("crawler", "Bounded Web Crawler", "Robots-aware, depth- and URL-limited same-scope GET inventory.", "recon", crawl_site),
    ScannerSpec("javascript", "JavaScript Analysis", "Review public script references for routes and possible exposure indicators.", "recon", analyze_javascript_files),
    ScannerSpec("headers", "HTTP Security Headers", "Review security headers and associated defensive configuration.", "misconfiguration", check_headers),
    ScannerSpec("dns", "DNS / Origin Exposure", "Resolve an explicitly scoped host and review authorized origin exposure.", "network", check_dns, "host"),
    ScannerSpec("tls", "SSL / TLS Audit", "Review certificate and negotiated protocol configuration.", "misconfiguration", check_ssl),
    ScannerSpec("ports", "Open Port Scanner", "Check only configured common TCP ports with scope validation and low concurrency.", "network", scan_ports, "host"),
    ScannerSpec("services", "Database / Search Service Exposure", "Read-only TCP reachability inventory for common database and search ports.", "network", inspect_service_exposure, "host"),
    ScannerSpec("cors", "CORS Review", "Inspect CORS response behavior without reading cross-origin data.", "misconfiguration", check_cors),
    ScannerSpec("cookies", "Cookie Security", "Review cookie attributes; values are withheld.", "misconfiguration", analyze_cookie_security),
    ScannerSpec("sqli", "SQL Injection Signals", "Baseline comparison assistant; quote-only comparison requires explicit read-only confirmation.", "injection", detect_sqli),
    ScannerSpec("nosql", "NoSQL Injection Signals", "Passive parser/error and parameter-name review only.", "injection", detect_nosql_signals),
    ScannerSpec("command", "Command Injection Signals", "Passive operation-parameter and response-error review only.", "injection", detect_command_injection_signals),
    ScannerSpec("template", "Template Injection Signals", "Passive template error disclosure review; sends no expressions.", "injection", review_template_signals),
    ScannerSpec("path", "Path Traversal Signals", "Identify path-like inputs without traversal payloads or file reads.", "injection", detect_path_parameters),
    ScannerSpec("auth", "Authentication / Session Review", "Inspect login and cookie behavior; optional single test-account action is separately confirmed.", "identity", analyze_authentication),
    ScannerSpec("authorization", "Authorization Comparison", "GET-only comparison using two explicitly supplied researcher-owned test accounts.", "identity", compare_test_accounts),
    ScannerSpec("api", "API Security Review", "Review API documentation and read-only metadata signals.", "api", analyze_api),
    ScannerSpec("uploads", "Upload Surface Review", "Inventory upload forms; no file is sent.", "api", inspect_upload_surfaces),
    ScannerSpec("exposure", "Sensitive Exposure Review", "HEAD-only checks for sensitive-path candidates; response bodies are withheld.", "misconfiguration", inspect_exposure),
)

REGISTRY: Dict[str, ScannerSpec] = {spec.key: spec for spec in _SPECS}


def register_plugin(spec: ScannerSpec) -> None:
    if not isinstance(spec, ScannerSpec) or not spec.key or not callable(spec.scanner):
        raise ValueError("Plugin must be a ScannerSpec with a callable scanner")
    key = spec.key.strip().lower()
    if not key.replace("_", "").replace("-", "").isalnum() or len(key) > 40:
        raise ValueError("Invalid plugin key")
    if key in REGISTRY:
        raise ValueError("Plugin key is already registered")
    if spec.target_kind not in {"url", "host"}:
        raise ValueError("Plugin target_kind must be url or host")
    REGISTRY[key] = ScannerSpec(key, spec.name[:100], spec.description[:500], spec.category[:60], spec.scanner, spec.target_kind, bool(spec.requires_network), bool(spec.supports_safe_mode))


def get_scanner(key: str) -> Optional[ScannerSpec]:
    return REGISTRY.get(str(key or "").strip().lower())


def list_scanners():
    return [
        {
            "key": item.key,
            "name": item.name,
            "description": item.description,
            "category": item.category,
            "target_kind": item.target_kind,
            "requires_network": item.requires_network,
            "supports_safe_mode": item.supports_safe_mode,
        }
        for item in _SPECS
    ]
