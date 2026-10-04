"""Mandatory target authorization and scope matching.

Rules are deliberately explicit: ``example.org`` matches that exact host;
``*.example.org`` matches subdomains but not the apex; CIDRs match IPs. Any
matching exclusion wins. Private lab addresses require an explicit IP/CIDR
rule in addition to the hostname rule. Link-local, multicast, reserved, and
unspecified addresses are always rejected.
"""
from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit


class ScopeError(ValueError):
    """Raised whenever an asset or outbound destination is not authorized."""


def normalize_host(host: str) -> str:
    value = (host or "").strip().rstrip(".").lower()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        try:
            value = value.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ScopeError("Invalid internationalized hostname") from exc
        if not value or len(value) > 253:
            raise ScopeError("Invalid hostname")
        labels = value.split(".")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
               or not all(ch.isalnum() or ch == "-" for ch in label) for label in labels):
            # localhost and single-label lab names are valid hostnames here.
            raise ScopeError("Invalid hostname")
        return value


def normalize_url(url: str) -> str:
    """Normalize an HTTP(S) URL and reject ambiguous or credential-bearing URLs."""
    raw = (url or "").strip()
    if not raw:
        raise ScopeError("A target URL or host is required")
    if "://" in raw and not raw.lower().startswith(("http://", "https://")):
        raise ScopeError("Only HTTP and HTTPS URLs are supported")
    if not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ScopeError("Only HTTP and HTTPS URLs are supported")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeError("URLs containing embedded credentials are not allowed")
        if not parsed.hostname:
            raise ScopeError("The target URL must include a hostname")
        host = normalize_host(parsed.hostname)
        port = parsed.port
    except ValueError as exc:
        if isinstance(exc, ScopeError):
            raise
        raise ScopeError("Malformed target URL or port") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ScopeError("Port must be between 1 and 65535")
    if ":" in host and not host.startswith("["):
        netloc_host = f"[{host}]"
    else:
        netloc_host = host
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)
    netloc = netloc_host if port is None or default_port else f"{netloc_host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def normalize_rule(rule: str) -> str:
    raw = (rule or "").strip()
    if not raw:
        raise ScopeError("Scope rule cannot be empty")
    if raw.startswith(("http://", "https://")):
        raw = urlsplit(raw).hostname or ""
    if raw.startswith("*."):
        base = normalize_host(raw[2:])
        try:
            ipaddress.ip_address(base)
        except ValueError:
            return "*." + base
        raise ScopeError("Wildcard rules can only be used with domain names")
    try:
        return ipaddress.ip_network(raw, strict=False).with_prefixlen
    except ValueError:
        return normalize_host(raw)


def _is_network_rule(rule: str) -> bool:
    try:
        ipaddress.ip_network(rule, strict=False)
        return "/" in rule
    except ValueError:
        return False


class ScopeManager:
    """Owns the project's allowlist/exclusions and validates every target."""

    # This host is only used as a passive certificate-transparency data source.
    # It can never be scanned as a target, and the in-scope seed is checked first.
    PASSIVE_SOURCE_HOSTS = frozenset({"crt.sh", "services.nvd.nist.gov"})

    def __init__(self, config: Dict, config_path: Optional[Path] = None):
        self.config = config
        self.config_path = config_path
        scope = config.get("scope")
        if not isinstance(scope, dict):
            scope = {}

        def valid_rules(value):
            if not isinstance(value, (list, tuple)):
                return []
            return [normalize_rule(rule) for rule in value[:1000] if isinstance(rule, str) and rule.strip()]

        self.in_scope: List[str] = valid_rules(scope.get("in_scope", []))
        self.exclusions: List[str] = valid_rules(scope.get("exclusions", []))
        self.config["scope"] = {"in_scope": self.in_scope, "exclusions": self.exclusions}

    @staticmethod
    def _matches(host: str, rule: str) -> bool:
        host = normalize_host(host)
        if rule.startswith("*."):
            base = rule[2:]
            return host != base and host.endswith("." + base)
        if _is_network_rule(rule):
            try:
                return ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False)
            except ValueError:
                return False
        return host == rule

    def is_excluded(self, host: str) -> bool:
        normalized = normalize_host(host)
        return any(self._matches(normalized, rule) for rule in self.exclusions)

    def is_in_scope(self, host: str) -> bool:
        normalized = normalize_host(host)
        if self.is_excluded(normalized):
            return False
        return any(self._matches(normalized, rule) for rule in self.in_scope)

    def is_explicitly_ip_scoped(self, address: str) -> bool:
        """Whether a literal IP/CIDR allow rule explicitly covers this address."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if any(self._matches(ip.compressed, rule) for rule in self.exclusions):
            return False
        for rule in self.in_scope:
            if rule.startswith("*."):
                continue
            try:
                candidate = ipaddress.ip_network(rule, strict=False)
                if ip in candidate:
                    return True
            except ValueError:
                continue
        return False

    def add_target(self, rule: str) -> str:
        value = normalize_rule(rule)
        if value not in self.in_scope:
            self.in_scope.append(value)
            self._persist()
        return value

    def add_exclusion(self, rule: str) -> str:
        value = normalize_rule(rule)
        if value not in self.exclusions:
            self.exclusions.append(value)
            self._persist()
        return value

    def remove_target(self, rule: str, exclusion: bool = False) -> bool:
        value = normalize_rule(rule)
        rules = self.exclusions if exclusion else self.in_scope
        if value not in rules:
            return False
        rules.remove(value)
        self._persist()
        return True

    def show(self) -> Dict[str, List[str]]:
        return {"in_scope": list(self.in_scope), "exclusions": list(self.exclusions)}

    def _persist(self) -> None:
        self.config["scope"] = {"in_scope": self.in_scope, "exclusions": self.exclusions}
        if self.config_path:
            # Project scopes live beside the project, not in generated reports.
            from nikhil_ai_modules.projects import save_project_scope
            save_project_scope(self.config.get("project_name", "Default Project"), self.config["scope"], self.config_path)

    def _resolve(self, host: str) -> List[str]:
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        try:
            rows = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ScopeError(f"Could not resolve in-scope host {host}: {exc}") from exc
        addresses = sorted({normalize_host(row[4][0]) for row in rows})
        if not addresses:
            raise ScopeError(f"Host {host} did not resolve to an address")
        return addresses

    def validate_host(
        self,
        host: str,
        *,
        resolve: bool = True,
        purpose: str = "target",
    ) -> List[str]:
        normalized = normalize_host(host)
        if purpose == "passive_source":
            if self.is_excluded(normalized):
                raise ScopeError(f"External passive source {normalized} is explicitly excluded")
            if normalized not in self.PASSIVE_SOURCE_HOSTS:
                raise ScopeError(f"External passive source {normalized} is not approved")
        elif not self.is_in_scope(normalized):
            raise ScopeError(f"Out-of-scope target refused: {normalized}. Add it to scope first.")

        addresses = self._resolve(normalized) if resolve else []
        for address in addresses:
            if self.is_excluded(address):
                raise ScopeError(f"Resolved address {address} is explicitly excluded")
            ip = ipaddress.ip_address(address)
            # Python classifies IPv6 loopback (::1) as reserved. Permit it only
            # when the exact loopback address is explicitly in the project's
            # allowlist; other reserved/special-use ranges remain blocked.
            if ip.is_link_local or ip.is_multicast or ip.is_unspecified or (ip.is_reserved and not ip.is_loopback):
                raise ScopeError(f"Special-use address {address} is not allowed")
            if not ip.is_global and not self.is_explicitly_ip_scoped(address):
                raise ScopeError(
                    f"{normalized} resolves to non-public address {address}; explicitly add an authorized IP/CIDR lab rule"
                )
        return addresses

    def authorize_url(self, url: str, *, purpose: str = "target") -> Tuple[str, List[str]]:
        normalized_url = normalize_url(url)
        host = urlsplit(normalized_url).hostname
        assert host is not None
        addresses = self.validate_host(host, resolve=True, purpose=purpose)
        return normalized_url, addresses

    def validate_url(self, url: str, *, purpose: str = "target") -> str:
        return self.authorize_url(url, purpose=purpose)[0]

    def require_host_rule(self, host: str) -> str:
        """Validate authorization without doing DNS; used to filter discoveries."""
        normalized = normalize_host(host)
        if not self.is_in_scope(normalized):
            raise ScopeError(f"Out-of-scope target refused: {normalized}")
        return normalized


def host_from_target(target: str) -> str:
    raw = (target or "").strip()
    if "://" in raw:
        normalized = normalize_url(raw)
        host = urlsplit(normalized).hostname
        if not host:
            raise ScopeError("Target URL has no hostname")
        return normalize_host(host)
    # Remove a harmless path suffix supplied with a bare host.
    return normalize_host(raw.split("/", 1)[0])
