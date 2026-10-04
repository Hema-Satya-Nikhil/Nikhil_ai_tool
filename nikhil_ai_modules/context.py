"""Shared services injected into scanner modules."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from nikhil_ai_modules.config import DEFAULT_CONFIG_PATH, load_config, save_config
from nikhil_ai_modules.database import Database
from nikhil_ai_modules.events import ScanEventBus
from nikhil_ai_modules.evidence import EvidenceStore
from nikhil_ai_modules.findings import FindingManager
from nikhil_ai_modules.http_client import ScopedHTTPClient
from nikhil_ai_modules.logging_setup import configure_logger
from nikhil_ai_modules.projects import load_project_scope, project_config_path, save_project_scope
from nikhil_ai_modules.scope import ScopeManager


@dataclass
class ScannerContext:
    config: Dict[str, Any]
    scope: ScopeManager
    http: ScopedHTTPClient
    database: Database
    logger: Any
    project_id: int
    findings: FindingManager
    evidence: EvidenceStore
    events: ScanEventBus
    config_path: Optional[Path] = None
    global_config_path: Optional[Path] = None
    scan_manager: Any = None


def build_context(
    config: Optional[Dict[str, Any]] = None,
    *,
    config_path: str | Path | None = None,
    database_path: str | Path | None = None,
) -> ScannerContext:
    global_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if not global_path.is_absolute():
        global_path = (Path.cwd() / global_path).resolve()
    loaded = config if config is not None else load_config(global_path)
    project_name = loaded.get("project_name", "Default Project")
    project_path = project_config_path(project_name, global_path.parent)

    # Prefer project-specific scope. Existing installations with scope stored in
    # config.json are migrated without dropping any allowlist entries.
    legacy_scope = loaded.get("scope", {"in_scope": [], "exclusions": []})
    if project_path.exists():
        loaded["scope"] = load_project_scope(project_name, project_path)
    else:
        loaded["scope"] = {
            "in_scope": list(legacy_scope.get("in_scope", [])),
            "exclusions": list(legacy_scope.get("exclusions", [])),
        }
        save_project_scope(project_name, loaded["scope"], project_path)

    logger = configure_logger(loaded.get("log_dir", "logs"))
    database = Database(database_path or loaded.get("database_path", "output/nikhil.sqlite3"))
    project_id = database.ensure_project(project_name)
    scope = ScopeManager(loaded, project_path)
    for rule in scope.in_scope:
        database.add_target_rule(project_id, rule, "include")
    for rule in scope.exclusions:
        database.add_target_rule(project_id, rule, "exclude")
    events = ScanEventBus(database, project_id, loaded)
    http = ScopedHTTPClient(scope, loaded, logger, events=events)
    return ScannerContext(
        config=loaded,
        scope=scope,
        http=http,
        database=database,
        logger=logger,
        project_id=project_id,
        findings=FindingManager(database, project_id),
        evidence=EvidenceStore(database, project_id),
        events=events,
        config_path=project_path,
        global_config_path=global_path,
    )


def activate_project(context: ScannerContext, project_name: str) -> None:
    """Switch the active project and its local scope without mixing records."""
    name = (project_name or "").strip()[:100]
    if not name:
        raise ValueError("Project name cannot be empty")
    context.config["project_name"] = name
    path = project_config_path(name, context.global_config_path.parent if context.global_config_path else None)
    scope_data = load_project_scope(name, path)
    if not path.exists():
        save_project_scope(name, scope_data, path)
    context.config["scope"] = scope_data
    context.scope = ScopeManager(context.config, path)
    context.http.scope = context.scope
    context.project_id = context.database.ensure_project(name)
    context.findings = FindingManager(context.database, context.project_id)
    context.evidence = EvidenceStore(context.database, context.project_id)
    context.events.project_id = context.project_id
    if context.global_config_path:
        save_config(context.config, context.global_config_path)


_default_context: Optional[ScannerContext] = None
_context_lock = threading.Lock()


def get_default_context() -> ScannerContext:
    global _default_context
    with _context_lock:
        if _default_context is None:
            _default_context = build_context()
        return _default_context


def reset_default_context() -> None:
    """Test helper to discard the process-wide context cache."""
    global _default_context
    with _context_lock:
        _default_context = None


def resolve_context(context: Optional[ScannerContext] = None) -> ScannerContext:
    return context or get_default_context()


def get_scan_manager(context: Optional[ScannerContext] = None):
    ctx = resolve_context(context)
    with _context_lock:
        if ctx.scan_manager is None:
            from nikhil_ai_modules.scan_manager import ScanManager
            ctx.scan_manager = ScanManager(ctx)
        return ctx.scan_manager
