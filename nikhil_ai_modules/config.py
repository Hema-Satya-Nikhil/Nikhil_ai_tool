"""Conservative, local configuration for NIKHIL AI.

The project intentionally uses JSON and the Python standard library so setup
stays cross-platform and does not add a YAML dependency.
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.json"

DEFAULTS: Dict[str, Any] = {
    "project_name": "Default Project",
    "timeout": 6.0,
    "request_interval": 1.0,
    "threads": 3,
    "scan_workers": 3,
    "max_requests": 250,
    "max_crawl_depth": 2,
    "max_urls": 50,
    "user_agent": "NIKHIL-AI-Safe/2.0 (authorized assessment)",
    "safe_mode": True,
    "max_response_bytes": 1048576,
    "max_redirects": 5,
    "max_retries": 1,
    "output_dir": "output",
    "report_dir": "output/reports",
    "database_path": "output/nikhil.sqlite3",
    "log_dir": "logs",
    "include_optional_tools": False,
    "enabled_integrations": {},
    "threat_intelligence": {"enabled": False, "cache_ttl_seconds": 86400},
    "port_scan_ports": [21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080],
    "scope": {"in_scope": [], "exclusions": []},
}


def resolve_path(value: str | Path, base: Optional[Path] = None) -> Path:
    """Resolve a configured path relative to the repository/config directory."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (base or PROJECT_ROOT) / path
    return path.resolve()


def _scope_rules(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip()[:255] for item in value[:1000] if isinstance(item, str) and item.strip()]


def _config_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in {"true", "1", "on"}:
            return True
        if value.strip().lower() in {"false", "0", "off"}:
            return False
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    return default


def load_config(path: str | Path | None = None) -> Dict[str, Any]:
    """Load settings, falling back safely when the local config is absent/bad."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not config_path.is_absolute():
        config_path = (PROJECT_ROOT / config_path).resolve()
    config = deepcopy(DEFAULTS)
    try:
        if config_path.exists():
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                config.update({key: value for key, value in loaded.items() if key in DEFAULTS})
                scope = loaded.get("scope")
                if isinstance(scope, dict):
                    config["scope"] = {
                        "in_scope": _scope_rules(scope.get("in_scope", [])),
                        "exclusions": _scope_rules(scope.get("exclusions", [])),
                    }
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        # Keep conservative defaults; the caller can overwrite a malformed file.
        pass

    # Clamp values that affect load or safety. Safe mode cannot be disabled by
    # malformed values; disabling it must be an explicit boolean config change.
    try:
        config["timeout"] = max(1.0, min(float(config["timeout"]), 30.0))
    except (TypeError, ValueError):
        config["timeout"] = DEFAULTS["timeout"]
    try:
        config["request_interval"] = max(0.25, min(float(config["request_interval"]), 60.0))
    except (TypeError, ValueError):
        config["request_interval"] = DEFAULTS["request_interval"]
    try:
        config["threads"] = max(1, min(int(config["threads"]), 5))
    except (TypeError, ValueError):
        config["threads"] = DEFAULTS["threads"]
    try:
        config["scan_workers"] = max(1, min(int(config.get("scan_workers", config["threads"])), 5))
    except (TypeError, ValueError):
        config["scan_workers"] = DEFAULTS["scan_workers"]
    try:
        config["max_requests"] = max(1, min(int(config.get("max_requests", DEFAULTS["max_requests"])), 10000))
    except (TypeError, ValueError):
        config["max_requests"] = DEFAULTS["max_requests"]
    try:
        config["max_crawl_depth"] = max(0, min(int(config.get("max_crawl_depth", 2)), 5))
    except (TypeError, ValueError):
        config["max_crawl_depth"] = DEFAULTS["max_crawl_depth"]
    try:
        config["max_urls"] = max(1, min(int(config.get("max_urls", 50)), 500))
    except (TypeError, ValueError):
        config["max_urls"] = DEFAULTS["max_urls"]
    try:
        config["max_response_bytes"] = max(4096, min(int(config["max_response_bytes"]), 5 * 1024 * 1024))
    except (TypeError, ValueError):
        config["max_response_bytes"] = DEFAULTS["max_response_bytes"]
    try:
        config["max_redirects"] = max(0, min(int(config["max_redirects"]), 10))
    except (TypeError, ValueError):
        config["max_redirects"] = DEFAULTS["max_redirects"]
    try:
        config["max_retries"] = max(0, min(int(config["max_retries"]), 2))
    except (TypeError, ValueError):
        config["max_retries"] = DEFAULTS["max_retries"]
    ports = config.get("port_scan_ports", DEFAULTS["port_scan_ports"])
    if not isinstance(ports, list):
        ports = DEFAULTS["port_scan_ports"]
    normalized_ports = []
    for port in ports[:100]:
        try:
            numeric_port = int(port)
            if 1 <= numeric_port <= 65535 and numeric_port not in normalized_ports:
                normalized_ports.append(numeric_port)
        except (TypeError, ValueError):
            continue
    config["port_scan_ports"] = normalized_ports or list(DEFAULTS["port_scan_ports"])
    integrations = config.get("enabled_integrations", {})
    if not isinstance(integrations, dict):
        integrations = {}
    config["enabled_integrations"] = {str(key)[:40]: _config_bool(value, False) for key, value in integrations.items() if str(key) in {"nmap", "subfinder", "amass", "httpx", "dnsx", "whatweb", "sslyze", "nuclei"}}
    intelligence = config.get("threat_intelligence", {})
    if not isinstance(intelligence, dict):
        intelligence = {}
    try:
        cache_ttl = max(300, min(int(intelligence.get("cache_ttl_seconds", 86400)), 30 * 86400))
    except (TypeError, ValueError):
        cache_ttl = 86400
    config["threat_intelligence"] = {"enabled": _config_bool(intelligence.get("enabled", False), False), "cache_ttl_seconds": cache_ttl}
    if not isinstance(config.get("safe_mode"), bool):
        config["safe_mode"] = True
    if not isinstance(config.get("scope"), dict):
        config["scope"] = deepcopy(DEFAULTS["scope"])
    return config


def save_config(config: Dict[str, Any], path: str | Path | None = None) -> Path:
    """Persist project configuration atomically with owner-only permissions when possible."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not config_path.is_absolute():
        config_path = (PROJECT_ROOT / config_path).resolve()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = config_path.with_suffix(config_path.suffix + ".tmp")
    temporary.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    temporary.replace(config_path)
    return config_path
