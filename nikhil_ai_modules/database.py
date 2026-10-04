"""SQLite persistence for project scope, scans, events, assets, findings and evidence."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from nikhil_ai_modules.config import resolve_path
from nikhil_ai_modules.evidence import redact_text


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json_load(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


class Database:
    """Short-lived SQLite connections keep threaded scans safe and transactions small."""

    def __init__(self, path: str | Path):
        self.path = resolve_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 15000")
        return connection

    def initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            program TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            rule TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'include',
            created_at TEXT NOT NULL,
            UNIQUE(project_id, rule, kind),
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            host TEXT NOT NULL,
            status TEXT,
            details_json TEXT NOT NULL DEFAULT '{}',
            last_seen TEXT NOT NULL,
            UNIQUE(project_id, host),
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'GET',
            status_code INTEGER,
            content_type TEXT,
            source TEXT,
            details_json TEXT NOT NULL DEFAULT '{}',
            last_seen TEXT NOT NULL,
            UNIQUE(project_id, url, method),
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            module TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            result_json TEXT NOT NULL DEFAULT '{}',
            error TEXT,
            progress INTEGER,
            requests INTEGER NOT NULL DEFAULT 0,
            rate REAL NOT NULL DEFAULT 0,
            current_action TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            finding_id TEXT NOT NULL UNIQUE,
            fingerprint TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            target TEXT NOT NULL,
            endpoint TEXT,
            parameter TEXT,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            description TEXT NOT NULL,
            impact TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '[]',
            observed_behavior TEXT NOT NULL DEFAULT '',
            reproduction_notes TEXT NOT NULL DEFAULT '',
            remediation TEXT NOT NULL DEFAULT '',
            references_json TEXT NOT NULL DEFAULT '[]',
            affected_endpoints_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            module TEXT NOT NULL DEFAULT '',
            researcher_notes TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
            UNIQUE(project_id, fingerprint)
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            finding_id TEXT,
            scan_id INTEGER,
            timestamp TEXT NOT NULL,
            target TEXT NOT NULL,
            endpoint TEXT,
            request_method TEXT,
            sanitized_request TEXT NOT NULL DEFAULT '{}',
            response_headers TEXT NOT NULL DEFAULT '{}',
            response_excerpt TEXT NOT NULL DEFAULT '',
            status_code INTEGER,
            response_size INTEGER,
            evidence_description TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS scan_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            scan_id INTEGER,
            timestamp TEXT NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            target TEXT,
            message TEXT NOT NULL,
            data_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS asset_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            source_type TEXT NOT NULL,
            source_value TEXT NOT NULL,
            relation TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_value TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(project_id, source_type, source_value, relation, target_type, target_value),
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS technologies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            host TEXT NOT NULL,
            technology TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'Unknown',
            confidence TEXT NOT NULL DEFAULT 'LOW',
            source TEXT NOT NULL DEFAULT '',
            evidence TEXT NOT NULL DEFAULT '',
            last_seen TEXT NOT NULL,
            UNIQUE(project_id, host, technology, source),
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            host TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT '',
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'tcp',
            state TEXT NOT NULL DEFAULT 'open',
            service TEXT NOT NULL DEFAULT 'unknown',
            version TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            last_seen TEXT NOT NULL,
            UNIQUE(project_id, host, port, protocol),
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            format TEXT NOT NULL,
            path TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'READY',
            created_at TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT 'Security Assessment Report',
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS threat_intel_cache (
            cache_key TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            fetched_at TEXT NOT NULL,
            result_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_scans_project_started ON scans(project_id, started_at DESC);
        CREATE INDEX IF NOT EXISTS idx_scans_project_status ON scans(project_id, status);
        CREATE INDEX IF NOT EXISTS idx_findings_project_status ON findings(project_id, status);
        CREATE INDEX IF NOT EXISTS idx_endpoints_project ON endpoints(project_id);
        CREATE INDEX IF NOT EXISTS idx_events_project_id ON scan_events(project_id, id);
        CREATE INDEX IF NOT EXISTS idx_assets_project_host ON assets(project_id, host);
        CREATE INDEX IF NOT EXISTS idx_technologies_project_host ON technologies(project_id, host);
        CREATE INDEX IF NOT EXISTS idx_services_project_host ON services(project_id, host);
        """
        with self.connect() as connection:
            connection.executescript(schema)
            self._ensure_column(connection, "projects", "description", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "projects", "program", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "projects", "notes", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "findings", "impact", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "findings", "module", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "findings", "researcher_notes", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "scans", "progress", "INTEGER")
            self._ensure_column(connection, "scans", "requests", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(connection, "scans", "rate", "REAL NOT NULL DEFAULT 0")
            self._ensure_column(connection, "scans", "current_action", "TEXT NOT NULL DEFAULT ''")

    @staticmethod
    def _ensure_column(connection: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
        names = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if column not in names:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

    def ensure_project(self, name: str) -> int:
        clean = (name or "Default Project").strip()[:100] or "Default Project"
        with self.connect() as connection:
            connection.execute("INSERT OR IGNORE INTO projects(name, created_at) VALUES(?, ?)", (clean, utc_now()))
            row = connection.execute("SELECT id FROM projects WHERE name=?", (clean,)).fetchone()
            return int(row["id"])

    def create_project(self, name: str, *, description: str = "", program: str = "", notes: str = "") -> int:
        clean = (name or "").strip()[:100]
        if not clean:
            raise ValueError("Project name cannot be empty")
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO projects(name, created_at, description, program, notes) VALUES(?, ?, ?, ?, ?)",
                (clean, utc_now(), redact_text(description[:1000], 1000), redact_text(program[:200], 200), redact_text(notes[:4000], 4000)),
            )
            return int(cursor.lastrowid)

    def list_projects(self) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, name, created_at, description, program, notes FROM projects ORDER BY name"
            ).fetchall()
        return [dict(row) for row in rows]

    def update_project(self, project_id: int, *, description: Optional[str] = None, program: Optional[str] = None, notes: Optional[str] = None) -> bool:
        fields = {"description": description, "program": program, "notes": notes}
        values = {key: redact_text(value[:4000], 4000) for key, value in fields.items() if value is not None}
        if not values:
            return False
        assignments = ", ".join(f"{key}=?" for key in values)
        with self.connect() as connection:
            cursor = connection.execute(f"UPDATE projects SET {assignments} WHERE id=?", (*values.values(), project_id))
            return cursor.rowcount > 0

    def add_target_rule(self, project_id: int, rule: str, kind: str = "include") -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO targets(project_id, rule, kind, created_at) VALUES(?, ?, ?, ?)",
                (project_id, rule, kind, utc_now()),
            )

    def delete_target_rule(self, project_id: int, rule: str, kind: str = "include") -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM targets WHERE project_id=? AND rule=? AND kind=?", (project_id, rule, kind))

    def list_target_rules(self, project_id: int) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT rule, kind, created_at FROM targets WHERE project_id=? ORDER BY kind, rule", (project_id,)).fetchall()
        return [dict(row) for row in rows]

    def start_scan(self, project_id: int, target: str, module: str, status: str = "RUNNING") -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO scans(project_id, target, module, status, started_at, progress) VALUES(?, ?, ?, ?, ?, ?)",
                (project_id, target, module, status, utc_now(), 0 if status in {"QUEUED", "STARTING", "RUNNING"} else None),
            )
            return int(cursor.lastrowid)

    def update_scan_state(self, scan_id: int, status: Optional[str] = None, *, progress: Optional[int] = None, current_action: Optional[str] = None, finished_at: Optional[str] = None, error: Optional[str] = None) -> None:
        fields, values = [], []
        if status is not None:
            fields.append("status=?"); values.append(status)
        if progress is not None:
            fields.append("progress=?"); values.append(max(0, min(int(progress), 100)))
        if current_action is not None:
            fields.append("current_action=?"); values.append(current_action[:500])
        if finished_at is not None:
            fields.append("finished_at=?"); values.append(finished_at)
        if error is not None:
            fields.append("error=?"); values.append(error[:1000])
        if not fields:
            return
        with self.connect() as connection:
            connection.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id=?", (*values, scan_id))

    def update_scan_runtime(self, scan_id: int, *, requests: Optional[int] = None, rate: Optional[float] = None, progress: Optional[int] = None, current_action: Optional[str] = None) -> None:
        fields, values = [], []
        if requests is not None:
            fields.append("requests=?"); values.append(max(0, int(requests)))
        if rate is not None:
            fields.append("rate=?"); values.append(max(0.0, float(rate)))
        if progress is not None:
            fields.append("progress=?"); values.append(max(0, min(int(progress), 100)))
        if current_action is not None:
            fields.append("current_action=?"); values.append(current_action[:500])
        if fields:
            with self.connect() as connection:
                connection.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id=?", (*values, scan_id))

    def finish_scan(self, scan_id: int, status: str, result: Any = None, error: Optional[str] = None) -> None:
        payload = json.dumps(result if result is not None else {}, ensure_ascii=False, default=str)
        progress = 100 if status == "COMPLETED" else None
        with self.connect() as connection:
            connection.execute(
                "UPDATE scans SET status=?, finished_at=?, result_json=?, error=?, progress=COALESCE(?, progress), current_action=? WHERE id=?",
                (status, utc_now(), payload, error, progress, status.lower(), scan_id),
            )

    def fail_unfinished_scans(self) -> int:
        """Mark jobs left active by a prior process as failed, never as complete."""
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE scans SET status='FAILED', finished_at=?, error='Process restarted before scan completion', current_action='recovered after restart' "
                "WHERE status IN ('QUEUED','STARTING','RUNNING','PAUSED','CANCELLING')",
                (utc_now(),),
            )
            return cursor.rowcount

    def get_scan(self, project_id: int, scan_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM scans WHERE project_id=? AND id=?", (project_id, scan_id)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["display_id"] = f"SCAN-{item['id']:04d}"
        item["result"] = _json_load(item.pop("result_json", "{}"), {})
        return item

    def list_scans(self, project_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, target, module, status, started_at, finished_at, error, progress, requests, rate, current_action "
                "FROM scans WHERE project_id=? ORDER BY id DESC LIMIT ?",
                (project_id, max(1, min(int(limit), 500))),
            ).fetchall()
        result = [dict(row) for row in rows]
        for item in result:
            item["display_id"] = f"SCAN-{item['id']:04d}"
        return result

    def upsert_asset(self, project_id: int, host: str, status: Optional[str] = None, details: Any = None) -> bool:
        with self.connect() as connection:
            existing = connection.execute("SELECT 1 FROM assets WHERE project_id=? AND host=?", (project_id, host)).fetchone()
            connection.execute(
                "INSERT INTO assets(project_id, host, status, details_json, last_seen) VALUES(?, ?, ?, ?, ?) "
                "ON CONFLICT(project_id, host) DO UPDATE SET status=COALESCE(excluded.status, assets.status), "
                "details_json=excluded.details_json, last_seen=excluded.last_seen",
                (project_id, host, status, json.dumps(details or {}, ensure_ascii=False, default=str), utc_now()),
            )
        return existing is None

    def list_assets(self, project_id: int, limit: int = 5000) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT host, status, details_json, last_seen FROM assets WHERE project_id=? ORDER BY host LIMIT ?",
                (project_id, max(1, min(int(limit), 10000))),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["details"] = _json_load(item.pop("details_json"), {})
            results.append(item)
        return results

    def upsert_endpoint(self, project_id: int, url: str, method: str = "GET", status_code: Optional[int] = None, content_type: Optional[str] = None, source: Optional[str] = None, details: Any = None) -> bool:
        method = str(method or "GET").upper()[:12]
        with self.connect() as connection:
            existing = connection.execute("SELECT 1 FROM endpoints WHERE project_id=? AND url=? AND method=?", (project_id, url, method)).fetchone()
            connection.execute(
                "INSERT INTO endpoints(project_id, url, method, status_code, content_type, source, details_json, last_seen) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(project_id, url, method) DO UPDATE SET "
                "status_code=excluded.status_code, content_type=excluded.content_type, source=excluded.source, "
                "details_json=excluded.details_json, last_seen=excluded.last_seen",
                (project_id, url, method, status_code, content_type, source,
                 json.dumps(details or {}, ensure_ascii=False, default=str), utc_now()),
            )
        return existing is None

    def list_endpoints(self, project_id: int, limit: int = 2000) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT url, method, status_code, content_type, source, details_json, last_seen "
                "FROM endpoints WHERE project_id=? ORDER BY url LIMIT ?",
                (project_id, max(1, min(int(limit), 10000))),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["details"] = _json_load(item.pop("details_json"), {})
            results.append(item)
        return results

    def upsert_technology(self, project_id: int, host: str, technology: str, category: str = "Unknown", confidence: str = "LOW", source: str = "", evidence: str = "") -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO technologies(project_id, host, technology, category, confidence, source, evidence, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(project_id, host, technology, source) DO UPDATE SET category=excluded.category, confidence=excluded.confidence, evidence=excluded.evidence, last_seen=excluded.last_seen",
                (project_id, host, technology[:120], category[:80], confidence[:12].upper(), source[:120], evidence[:1000], utc_now()),
            )

    def list_technologies(self, project_id: int, limit: int = 2000) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT host, technology, category, confidence, source, evidence, last_seen FROM technologies WHERE project_id=? ORDER BY technology, host LIMIT ?", (project_id, max(1, min(int(limit), 10000)))).fetchall()
        return [dict(row) for row in rows]

    def upsert_service(self, project_id: int, host: str, ip: str, port: int, protocol: str = "tcp", state: str = "open", service: str = "unknown", version: str = "", evidence: Any = None) -> bool:
        with self.connect() as connection:
            existing = connection.execute("SELECT 1 FROM services WHERE project_id=? AND host=? AND port=? AND protocol=?", (project_id, host, int(port), protocol.lower())).fetchone()
            connection.execute(
                "INSERT INTO services(project_id, host, ip, port, protocol, state, service, version, evidence_json, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(project_id, host, port, protocol) DO UPDATE SET ip=excluded.ip, state=excluded.state, service=excluded.service, version=excluded.version, evidence_json=excluded.evidence_json, last_seen=excluded.last_seen",
                (project_id, host, ip, int(port), protocol.lower(), state.lower(), service[:80], version[:160], json.dumps(evidence or {}, ensure_ascii=False, default=str), utc_now()),
            )
        return existing is None

    def list_services(self, project_id: int, limit: int = 5000) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT host, ip, port, protocol, state, service, version, evidence_json, last_seen FROM services WHERE project_id=? ORDER BY host, port LIMIT ?", (project_id, max(1, min(int(limit), 10000)))).fetchall()
        result = []
        for row in rows:
            item = dict(row); item["evidence"] = _json_load(item.pop("evidence_json"), {})
            result.append(item)
        return result

    def add_asset_relation(self, project_id: int, source_type: str, source_value: str, relation: str, target_type: str, target_value: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO asset_relations(project_id, source_type, source_value, relation, target_type, target_value, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(project_id, source_type, source_value, relation, target_type, target_value) DO UPDATE SET last_seen=excluded.last_seen",
                (project_id, source_type[:40], source_value[:500], relation[:60], target_type[:40], target_value[:500], utc_now()),
            )

    def list_asset_relations(self, project_id: int, limit: int = 5000) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT source_type, source_value, relation, target_type, target_value, last_seen FROM asset_relations WHERE project_id=? ORDER BY source_value LIMIT ?", (project_id, max(1, min(int(limit), 10000)))).fetchall()
        return [dict(row) for row in rows]

    def add_finding(self, project_id: int, finding: Dict[str, Any], fingerprint: str) -> tuple[str, bool]:
        """Insert a finding or merge duplicates; automated states stay review-only."""
        endpoints = list(dict.fromkeys(x for x in [finding.get("endpoint"), *(finding.get("affected_endpoints") or [])] if x))
        with self.connect() as connection:
            existing = connection.execute("SELECT finding_id, affected_endpoints_json, evidence_json FROM findings WHERE project_id=? AND fingerprint=?", (project_id, fingerprint)).fetchone()
            now = utc_now()
            if existing:
                old_endpoints = _json_load(existing["affected_endpoints_json"], [])
                merged_endpoints = list(dict.fromkeys(old_endpoints + endpoints))
                old_evidence = _json_load(existing["evidence_json"], [])
                if not isinstance(old_evidence, list): old_evidence = [old_evidence] if old_evidence else []
                new_evidence = finding.get("evidence")
                if new_evidence and new_evidence not in old_evidence: old_evidence.append(new_evidence)
                connection.execute("UPDATE findings SET affected_endpoints_json=?, evidence_json=?, updated_at=? WHERE finding_id=?", (json.dumps(merged_endpoints), json.dumps(old_evidence, ensure_ascii=False, default=str), now, existing["finding_id"]))
                return str(existing["finding_id"]), False
            finding_id = str(finding.get("finding_id") or "")
            if not finding_id:
                import uuid
                finding_id = "F-" + uuid.uuid4().hex[:10].upper()
            connection.execute(
                "INSERT INTO findings(project_id, finding_id, fingerprint, title, category, target, endpoint, parameter, severity, confidence, description, impact, evidence_json, observed_behavior, reproduction_notes, remediation, references_json, affected_endpoints_json, status, created_at, updated_at, module, researcher_notes) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (project_id, finding_id, fingerprint, finding.get("title", "Potential finding"), finding.get("category", "General"), finding.get("target", ""), finding.get("endpoint"), finding.get("parameter"), finding.get("severity", "INFO"), finding.get("confidence", "LOW"), finding.get("description", ""), finding.get("impact", ""), json.dumps(finding.get("evidence", []), ensure_ascii=False, default=str), finding.get("observed_behavior", ""), finding.get("reproduction_notes", ""), finding.get("remediation", ""), json.dumps(finding.get("references", []), ensure_ascii=False), json.dumps(endpoints, ensure_ascii=False), "NEEDS_REVIEW" if finding.get("status") == "CONFIRMED" else finding.get("status", "NEEDS_REVIEW"), now, now, finding.get("module", ""), finding.get("researcher_notes", "")),
            )
            return finding_id, True

    def list_findings(self, project_id: int, limit: int = 500, filters: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        filters = filters or {}
        clauses, values = ["project_id=?"], [project_id]
        for key in ("severity", "confidence", "status", "module", "target"):
            value = filters.get(key)
            if value:
                if key == "target":
                    clauses.append("target LIKE ?"); values.append("%" + value[:150] + "%")
                else:
                    clauses.append(f"UPPER({key})=?"); values.append(value.upper()[:100])
        query = "SELECT * FROM findings WHERE " + " AND ".join(clauses) + " ORDER BY updated_at DESC LIMIT ?"
        values.append(max(1, min(int(limit), 5000)))
        with self.connect() as connection:
            rows = connection.execute(query, values).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            for source, destination, default in (("evidence_json", "evidence", []), ("references_json", "references", []), ("affected_endpoints_json", "affected_endpoints", [])):
                item[destination] = _json_load(item.pop(source), default)
            result.append(item)
        return result

    def update_finding(self, project_id: int, finding_id: str, *, status: Optional[str] = None, researcher_notes: Optional[str] = None) -> bool:
        allowed = {"NEW", "NEEDS_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "REPORTED", "RESOLVED"}
        fields, values = [], []
        if status is not None:
            status = status.upper()
            if status not in allowed: raise ValueError("Invalid finding status")
            fields.append("status=?"); values.append(status)
        if researcher_notes is not None:
            fields.append("researcher_notes=?"); values.append(researcher_notes[:4000])
        if not fields: return False
        fields.append("updated_at=?"); values.append(utc_now())
        with self.connect() as connection:
            cursor = connection.execute(f"UPDATE findings SET {', '.join(fields)} WHERE project_id=? AND finding_id=?", (*values, project_id, finding_id))
            return cursor.rowcount > 0

    def update_finding_status(self, project_id: int, finding_id: str, status: str) -> bool:
        return self.update_finding(project_id, finding_id, status=status)

    def add_evidence(self, project_id: int, evidence: Dict[str, Any]) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO evidence(project_id, finding_id, scan_id, timestamp, target, endpoint, request_method, sanitized_request, response_headers, response_excerpt, status_code, response_size, evidence_description) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (project_id, evidence.get("finding_id"), evidence.get("scan_id"), evidence.get("timestamp", utc_now()), evidence.get("target", ""), evidence.get("endpoint"), evidence.get("request_method"), json.dumps(evidence.get("sanitized_request", {}), ensure_ascii=False, default=str), json.dumps(evidence.get("response_headers", {}), ensure_ascii=False, default=str), evidence.get("response_excerpt", ""), evidence.get("status_code"), evidence.get("response_size"), evidence.get("evidence_description", "")),
            )
            return int(cursor.lastrowid)

    def get_evidence(self, project_id: int, evidence_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM evidence WHERE project_id=? AND id=?", (project_id, evidence_id)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["sanitized_request"] = _json_load(item.pop("sanitized_request"), {})
        item["response_headers"] = _json_load(item.pop("response_headers"), {})
        return item

    def list_evidence(self, project_id: int, limit: int = 2000) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM evidence WHERE project_id=? ORDER BY id DESC LIMIT ?", (project_id, max(1, min(int(limit), 10000)))).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["sanitized_request"] = _json_load(item.pop("sanitized_request"), {})
            item["response_headers"] = _json_load(item.pop("response_headers"), {})
            result.append(item)
        return result

    def add_event(self, project_id: int, *, scan_id: Optional[int], event_type: str, severity: str, target: Optional[str], message: str, data: Any) -> Dict[str, Any]:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO scan_events(project_id, scan_id, timestamp, type, severity, target, message, data_json) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (project_id, scan_id, utc_now(), event_type, severity, target, message, json.dumps(data or {}, ensure_ascii=False, default=str)),
            )
            event_id = int(cursor.lastrowid)
            # Bound long-running local databases; keep the newest 20,000 project events.
            connection.execute("DELETE FROM scan_events WHERE project_id=? AND id NOT IN (SELECT id FROM scan_events WHERE project_id=? ORDER BY id DESC LIMIT 20000)", (project_id, project_id))
            row = connection.execute("SELECT * FROM scan_events WHERE id=?", (event_id,)).fetchone()
        return self._event_row(row)

    @staticmethod
    def _event_row(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        item["event_id"] = item.pop("id")
        item["data"] = _json_load(item.pop("data_json"), {})
        return item

    def list_events(self, project_id: int, *, after_id: int = 0, limit: int = 100, newest: bool = False, scan_id: Optional[int] = None) -> List[Dict[str, Any]]:
        lim = max(1, min(int(limit), 1000))
        if newest:
            query = "SELECT * FROM scan_events WHERE project_id=?"
            values: List[Any] = [project_id]
            if scan_id is not None: query += " AND scan_id=?"; values.append(scan_id)
            query += " ORDER BY id DESC LIMIT ?"; values.append(lim)
            query = f"SELECT * FROM ({query}) ORDER BY id ASC"
        else:
            query = "SELECT * FROM scan_events WHERE project_id=? AND id>?"
            values = [project_id, max(0, int(after_id))]
            if scan_id is not None: query += " AND scan_id=?"; values.append(scan_id)
            query += " ORDER BY id ASC LIMIT ?"; values.append(lim)
        with self.connect() as connection:
            rows = connection.execute(query, values).fetchall()
        return [self._event_row(row) for row in rows]

    def add_report(self, project_id: int, report_format: str, path: str, title: str = "Security Assessment Report") -> int:
        with self.connect() as connection:
            cursor = connection.execute("INSERT INTO reports(project_id, format, path, status, created_at, title) VALUES(?, ?, ?, 'READY', ?, ?)", (project_id, report_format.lower(), path, utc_now(), title[:200]))
            return int(cursor.lastrowid)

    def list_reports(self, project_id: int, limit: int = 500) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT id, format, path, status, created_at, title FROM reports WHERE project_id=? ORDER BY id DESC LIMIT ?", (project_id, max(1, min(int(limit), 1000)))).fetchall()
        return [dict(row) for row in rows]

    def get_report(self, project_id: int, report_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute("SELECT id, format, path, status, created_at, title FROM reports WHERE project_id=? AND id=?", (project_id, report_id)).fetchone()
        return dict(row) if row else None

    def get_threat_intel_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute("SELECT provider, fetched_at, result_json FROM threat_intel_cache WHERE cache_key=?", (cache_key,)).fetchone()
        if not row:
            return None
        return {"provider": row["provider"], "fetched_at": row["fetched_at"], "result": _json_load(row["result_json"], {})}

    def put_threat_intel_cache(self, cache_key: str, provider: str, result: Any) -> None:
        with self.connect() as connection:
            connection.execute("INSERT INTO threat_intel_cache(cache_key, provider, fetched_at, result_json) VALUES(?, ?, ?, ?) ON CONFLICT(cache_key) DO UPDATE SET provider=excluded.provider, fetched_at=excluded.fetched_at, result_json=excluded.result_json", (cache_key, provider[:80], utc_now(), json.dumps(result, ensure_ascii=False, default=str)))

    def summary(self, project_id: int) -> Dict[str, Any]:
        with self.connect() as connection:
            counts = {}
            for key, table in (("assets", "assets"), ("endpoints", "endpoints"), ("findings", "findings"), ("technologies", "technologies"), ("services", "services"), ("evidence", "evidence"), ("reports", "reports")):
                counts[key] = int(connection.execute(f"SELECT COUNT(*) FROM {table} WHERE project_id=?", (project_id,)).fetchone()[0])
            counts["active_scans"] = int(connection.execute("SELECT COUNT(*) FROM scans WHERE project_id=? AND status IN ('QUEUED','STARTING','RUNNING','PAUSED','CANCELLING')", (project_id,)).fetchone()[0])
            counts["confirmed_findings"] = int(connection.execute("SELECT COUNT(*) FROM findings WHERE project_id=? AND status='CONFIRMED'", (project_id,)).fetchone()[0])
            counts["needs_review"] = int(connection.execute("SELECT COUNT(*) FROM findings WHERE project_id=? AND status='NEEDS_REVIEW'", (project_id,)).fetchone()[0])
            counts["severity"] = {row["severity"]: int(row["n"]) for row in connection.execute("SELECT severity, COUNT(*) AS n FROM findings WHERE project_id=? GROUP BY severity", (project_id,)).fetchall()}
            counts["finding_status"] = {row["status"]: int(row["n"]) for row in connection.execute("SELECT status, COUNT(*) AS n FROM findings WHERE project_id=? GROUP BY status", (project_id,)).fetchall()}
            counts["scan_history"] = [dict(row) for row in connection.execute("SELECT id, module, status, started_at, finished_at FROM scans WHERE project_id=? ORDER BY id DESC LIMIT 20", (project_id,)).fetchall()]
        return counts

    def search(self, project_id: int, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        text = (query or "").strip()[:120]
        if len(text) < 2: return []
        pattern = "%" + text.replace("%", "\\%").replace("_", "\\_") + "%"
        cap = max(1, min(int(limit), 200))
        results: List[Dict[str, Any]] = []
        with self.connect() as connection:
            for kind, sql, fields in (
                ("asset", "SELECT host AS value, status AS detail FROM assets WHERE project_id=? AND host LIKE ? ESCAPE '\\' LIMIT ?", ("value", "detail")),
                ("endpoint", "SELECT url AS value, method AS detail FROM endpoints WHERE project_id=? AND url LIKE ? ESCAPE '\\' LIMIT ?", ("value", "detail")),
                ("finding", "SELECT finding_id AS value, title AS detail FROM findings WHERE project_id=? AND (title LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\') LIMIT ?", ("value", "detail")),
                ("technology", "SELECT technology AS value, host AS detail FROM technologies WHERE project_id=? AND technology LIKE ? ESCAPE '\\' LIMIT ?", ("value", "detail")),
            ):
                params = (project_id, pattern, pattern, cap) if kind == "finding" else (project_id, pattern, cap)
                for row in connection.execute(sql, params).fetchall():
                    results.append({"kind": kind, "value": row[fields[0]], "detail": row[fields[1]]})
                    if len(results) >= cap: return results
        return results
