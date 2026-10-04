"""Local per-project scope configuration helpers."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict

from nikhil_ai_modules.config import PROJECT_ROOT, _scope_rules

PROJECT_CONFIG_DIR = PROJECT_ROOT / "projects"


def project_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "project").strip().lower()).strip("-")
    return (slug[:60] or "project")


def project_config_path(name: str, base_dir: Path | None = None) -> Path:
    directory = (Path(base_dir) / "projects") if base_dir else PROJECT_CONFIG_DIR
    return directory / f"{project_slug(name)}.json"


def load_project_scope(name: str, path: Path | None = None) -> Dict:
    path = Path(path) if path else project_config_path(name)
    if not path.exists():
        return {"in_scope": [], "exclusions": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        scope = data.get("scope", {}) if isinstance(data, dict) else {}
        if not isinstance(scope, dict):
            return {"in_scope": [], "exclusions": []}
        return {"in_scope": _scope_rules(scope.get("in_scope", [])), "exclusions": _scope_rules(scope.get("exclusions", []))}
    except (OSError, ValueError, TypeError):
        return {"in_scope": [], "exclusions": []}


def save_project_scope(name: str, scope: Dict, path: Path | None = None) -> Path:
    destination = Path(path) if path else project_config_path(name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "project_name": (name or "Default Project")[:100],
        "safe_mode": True,
        "scope": {
            "in_scope": list(scope.get("in_scope", [])),
            "exclusions": list(scope.get("exclusions", [])),
        },
    }
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    temporary.replace(destination)
    return destination
