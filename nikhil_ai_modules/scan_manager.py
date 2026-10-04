"""In-process scan queue with persisted lifecycle and cooperative controls."""
from __future__ import annotations

import threading
import time
import uuid
from contextlib import contextmanager
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional

from nikhil_ai_modules.events import ScanCancelled
from nikhil_ai_modules.evidence import redact_text, sanitize_url
from nikhil_ai_modules.plugins import ScannerSpec, get_scanner
from nikhil_ai_modules.scan_runner import run_scan
from nikhil_ai_modules.scope import ScopeError, host_from_target

ACTIVE_STATES = {"QUEUED", "STARTING", "RUNNING", "PAUSED", "CANCELLING"}
TERMINAL_STATES = {"CANCELLED", "COMPLETED", "FAILED"}
MAX_PENDING_SCANS = 100


class ScanControl:
    def __init__(self):
        self.resume_event = threading.Event()
        self.resume_event.set()
        self.cancel_event = threading.Event()

    def wait_for_resume(self):
        while not self.resume_event.wait(0.2):
            if self.cancel_event.is_set():
                raise ScanCancelled("Scan cancellation requested")
        if self.cancel_event.is_set():
            raise ScanCancelled("Scan cancellation requested")

    def cancel(self):
        self.cancel_event.set()
        self.resume_event.set()

    def pause(self):
        self.resume_event.clear()

    def resume(self):
        self.resume_event.set()


@dataclass
class ScanJob:
    scan_id: int
    target: str
    module: str
    specs: list[ScannerSpec]
    project_id: int
    options: Dict[str, Any] = field(default_factory=dict)
    control: ScanControl = field(default_factory=ScanControl)
    future: Optional[Future] = None
    submitted_at: float = field(default_factory=time.monotonic)


class ScanManager:
    """Local worker queue: no Redis dependency and no fake progress generation."""

    def __init__(self, context):
        self.context = context
        context.scan_manager = self
        worker_count = max(1, min(int(context.config.get("scan_workers", context.config.get("threads", 3))), 5))
        self.worker_count = worker_count
        self.executor = ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="nikhil-scan")
        self.lock = threading.RLock()
        self.jobs: Dict[int, ScanJob] = {}
        self._project_operations: Dict[str, int] = {}
        self.context.database.fail_unfinished_scans()

    def resize_workers(self, worker_count: int) -> None:
        """Apply a worker-pool size change only while no jobs are active."""
        count = max(1, min(int(worker_count), 5))
        with self.lock:
            if count == self.worker_count:
                return
            if self.jobs:
                raise ValueError("Scan workers can only be changed while the scan queue is idle")
            previous = self.executor
            self.executor = ThreadPoolExecutor(max_workers=count, thread_name_prefix="nikhil-scan")
            self.worker_count = count
        previous.shutdown(wait=True)

    def submit(self, module: str, target: str, *, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        from nikhil_ai_modules.plugins import REGISTRY
        key = str(module or "").strip().lower()
        if key == "baseline":
            specs = [REGISTRY[name] for name in ("headers", "tls", "dns", "cors", "ports")]
        else:
            spec = get_scanner(key)
            if spec is None:
                raise ValueError("Unknown scanner module")
            specs = [spec]
        return self._enqueue(key, target, specs, options)

    def submit_spec(self, spec: ScannerSpec, target: str, *, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Extension point for trusted in-process plugins and deterministic tests."""
        if not isinstance(spec, ScannerSpec) or not spec.key or not callable(spec.scanner):
            raise ValueError("Invalid scanner plugin")
        return self._enqueue(spec.key, target, [spec], options)

    def _enqueue(self, key: str, target: str, specs: list[ScannerSpec], options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if self.context.config.get("safe_mode", True) and any(not spec.supports_safe_mode for spec in specs):
            raise ValueError("Safe Mode blocks a plugin that does not declare safe-mode support")
        raw_target = str(target or "").strip()[:2000]
        if not raw_target:
            raise ValueError("Target is required")
        # Project activation and enqueue share this lock. Otherwise a concurrent
        # project switch could validate under one scope and persist under another.
        with self.lock:
            if len(self.jobs) >= MAX_PENDING_SCANS:
                raise ValueError(f"Scan queue is full (maximum {MAX_PENDING_SCANS} active or pending scans)")
            project_id = int(self.context.project_id)
            try:
                if specs[0].target_kind == "host":
                    host = host_from_target(raw_target)
                    self.context.scope.validate_host(host, resolve=True)
                    scan_target = host
                else:
                    scan_target = self.context.scope.validate_url(raw_target)
            except ScopeError as exc:
                self.context.events.fail_scope(raw_target, str(exc))
                raise
            safe_target = sanitize_url(scan_target) if "://" in scan_target else redact_text(scan_target, 300)
            scan_id = self.context.database.start_scan(project_id, safe_target, key, status="QUEUED")
            job = ScanJob(scan_id, scan_target, key, specs, project_id, dict(options or {}))
            self.jobs[scan_id] = job
            self.context.events.publish("scan_queued", scan_id=scan_id, target=safe_target, message=f"{key} scan queued", data={"module": key})
            job.future = self.executor.submit(self._execute, job)
            scan = self.context.database.get_scan(project_id, scan_id)
            return scan or {"id": scan_id, "display_id": f"SCAN-{scan_id:04d}", "status": "QUEUED", "module": key, "target": safe_target}

    def _target_for(self, spec: ScannerSpec, target: str) -> str:
        if spec.target_kind == "host":
            return host_from_target(target)
        return target

    def _mark_running_at_checkpoint(self, job: ScanJob) -> None:
        while True:
            job.control.wait_for_resume()
            with self.lock:
                if job.control.cancel_event.is_set():
                    raise ScanCancelled("Scan cancellation requested")
                if not job.control.resume_event.is_set():
                    continue
                self.context.database.update_scan_state(job.scan_id, "RUNNING", progress=0, current_action="Running scanner")
                return

    def _execute(self, job: ScanJob):
        database = self.context.database
        events = self.context.events
        safe_target = sanitize_url(job.target) if "://" in job.target else redact_text(job.target, 300)
        try:
            with self.lock:
                if job.control.cancel_event.is_set():
                    raise ScanCancelled("Scan cancelled before execution")
                if job.control.resume_event.is_set():
                    database.update_scan_state(job.scan_id, "STARTING", current_action="Starting worker")
                events.publish("scan_started", scan_id=job.scan_id, target=safe_target, message=f"{job.module} scan starting", data={"module": job.module})
            with events.bind_scan(job.scan_id, job.target, job.control):
                self._mark_running_at_checkpoint(job)
                if len(job.specs) == 1:
                    spec = job.specs[0]
                    def invoke(target, context=None, **kwargs):
                        return spec.scanner(self._target_for(spec, target), context=context, **{**job.options, **kwargs})
                    result = run_scan(spec.key, job.target, invoke, context=self.context, scan_id=job.scan_id)
                else:
                    def batch(target, context=None, **_kwargs):
                        return self._execute_batch(job)
                    result = run_scan("baseline", job.target, batch, context=self.context, scan_id=job.scan_id)
            if job.control.cancel_event.is_set():
                database.finish_scan(job.scan_id, "CANCELLED", {"cancelled": True})
                events.publish("scan_cancelled", scan_id=job.scan_id, target=safe_target, severity="warning", message="Scan cancelled by operator")
            else:
                events.publish("scan_completed", scan_id=job.scan_id, target=safe_target, message="Scan completed", data={"finding_ids": result.get("finding_ids", [])})
        except ScanCancelled as exc:
            safe_error = redact_text(exc, 300)
            row = database.get_scan(job.project_id, job.scan_id)
            if not row or row["status"] != "CANCELLED":
                database.finish_scan(job.scan_id, "CANCELLED", {"cancelled": True}, safe_error)
                events.publish("scan_cancelled", scan_id=job.scan_id, target=safe_target, severity="warning", message="Scan cancelled at a safe checkpoint")
        except Exception as exc:
            safe_error = redact_text(exc, 500)
            database.finish_scan(job.scan_id, "FAILED", {"error": safe_error}, safe_error)
            self.context.logger.error("scan job failed id=%s module=%s: %s", job.scan_id, job.module, safe_error)
            events.publish("error", scan_id=job.scan_id, target=safe_target, severity="error", message=f"Scan failed: {safe_error}")
        finally:
            with self.lock:
                self.jobs.pop(job.scan_id, None)

    def _execute_batch(self, job: ScanJob) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        combined: Dict[str, list] = {"assets": [], "endpoints": [], "potential_findings": []}
        total = len(job.specs)
        for index, spec in enumerate(job.specs):
            job.control.wait_for_resume()
            if job.control.cancel_event.is_set():
                raise ScanCancelled("Scan cancelled between modules")
            action = f"{spec.name} ({index + 1}/{total})"
            self.context.database.update_scan_state(job.scan_id, current_action=action)
            self.context.events.publish("scan_progress", scan_id=job.scan_id, target=job.target, message=f"Started {spec.name}", data={"completed_modules": index, "total_modules": total, "progress": round(index * 100 / total), "current_action": action})
            try:
                module_target = self._target_for(spec, job.target)
                self.context.scope.validate_host(module_target, resolve=True) if spec.target_kind == "host" else self.context.scope.validate_url(module_target)
                raw = spec.scanner(module_target, context=self.context, **job.options)
                if hasattr(raw, "to_dict") and callable(raw.to_dict):
                    raw = raw.to_dict()
                if not isinstance(raw, dict):
                    raw = {"result": raw}
                results[spec.key] = raw
                for field in combined:
                    if isinstance(raw.get(field), list):
                        combined[field].extend(raw[field])
            except ScanCancelled:
                raise
            except ScopeError as exc:
                self.context.events.fail_scope(job.target, str(exc), job.scan_id)
                results[spec.key] = {"error": redact_text(exc, 300), "status": "scope_blocked"}
            except Exception as exc:
                message = redact_text(exc, 300)
                results[spec.key] = {"error": message, "status": "failed"}
                self.context.events.publish("warning", scan_id=job.scan_id, target=job.target, severity="warning", message=f"{spec.name} failed: {message}")
            completed = index + 1
            percent = round(completed * 100 / total)
            action = f"Completed {spec.name} ({completed}/{total})"
            self.context.database.update_scan_state(job.scan_id, progress=percent, current_action=action)
            self.context.events.publish("scan_progress", scan_id=job.scan_id, target=job.target, message=action, data={"completed_modules": completed, "total_modules": total, "progress": percent, "current_action": action})
        return {"modules": results, **combined}

    def pause(self, scan_id: int) -> bool:
        with self.lock:
            job = self.jobs.get(int(scan_id))
            if not job:
                return False
            row = self.context.database.get_scan(self.context.project_id, int(scan_id))
            if not row or row["status"] not in {"QUEUED", "STARTING", "RUNNING"}:
                return False
            job.control.pause()
            self.context.database.update_scan_state(job.scan_id, "PAUSED", current_action="Paused; waiting at next safe checkpoint")
            self.context.events.publish("scan_paused", scan_id=job.scan_id, target=job.target, severity="warning", message="Scan paused by operator")
            return True

    def resume(self, scan_id: int) -> bool:
        with self.lock:
            job = self.jobs.get(int(scan_id))
            if not job:
                return False
            row = self.context.database.get_scan(self.context.project_id, int(scan_id))
            if not row or row["status"] != "PAUSED":
                return False
            job.control.resume()
            self.context.database.update_scan_state(job.scan_id, "RUNNING", current_action="Resuming at next safe checkpoint")
            self.context.events.publish("scan_resumed", scan_id=job.scan_id, target=job.target, message="Scan resumed by operator")
            return True

    def cancel(self, scan_id: int) -> bool:
        with self.lock:
            job = self.jobs.get(int(scan_id))
            if not job:
                return False
            row = self.context.database.get_scan(self.context.project_id, int(scan_id))
            if not row or row["status"] in TERMINAL_STATES:
                return False
            job.control.cancel()
            self.context.database.update_scan_state(job.scan_id, "CANCELLING", current_action="Cancellation requested")
            self.context.events.publish("scan_progress", scan_id=job.scan_id, target=job.target, severity="warning", message="Cancellation requested; stopping at the next safe checkpoint")
            if job.future and job.future.cancel():
                self.context.database.finish_scan(job.scan_id, "CANCELLED", {"cancelled": True})
                self.context.events.publish("scan_cancelled", scan_id=job.scan_id, target=job.target, severity="warning", message="Queued scan cancelled before a worker started")
                self.jobs.pop(job.scan_id, None)
            return True

    def retry(self, scan_id: int) -> Dict[str, Any]:
        with self.lock:
            project_id = int(self.context.project_id)
            row = self.context.database.get_scan(project_id, int(scan_id))
            if not row:
                raise ValueError("Scan not found")
            if row["status"] not in {"FAILED", "CANCELLED"}:
                raise ValueError("Only failed or cancelled scans can be retried")
            module = str(row["module"])
            retried = self.submit(module, row["target"])
            self.context.events.publish("task_retry", scan_id=retried.get("id"), target=row["target"], message="Scan retry queued", data={"previous_scan_id": int(scan_id), "new_scan_id": retried.get("id")})
            return retried

    @contextmanager
    def protect_project_switch(self):
        """Keep synchronous compatibility scans attached to their starting project."""
        token = uuid.uuid4().hex
        with self.lock:
            project_id = int(self.context.project_id)
            self._project_operations[token] = project_id
        try:
            yield project_id
        finally:
            with self.lock:
                self._project_operations.pop(token, None)

    def has_project_operation(self, project_id: Optional[int] = None) -> bool:
        with self.lock:
            selected = int(self.context.project_id if project_id is None else project_id)
            return any(active_project == selected for active_project in self._project_operations.values())

    def active(self):
        with self.lock:
            project_id = int(self.context.project_id)
            rows = {row["id"]: row for row in self.context.database.list_scans(project_id, 200) if row["status"] in ACTIVE_STATES}
            # Keep a job active through its final event publication, even if
            # run_scan has already written a terminal SQLite status. This closes
            # the narrow window where a project switch could move the event.
            for job in self.jobs.values():
                if job.project_id == project_id and job.future and not job.future.done():
                    row = self.context.database.get_scan(project_id, job.scan_id)
                    if row:
                        rows[job.scan_id] = row
            return list(rows.values())

    def shutdown(self, wait: bool = False):
        with self.lock:
            for job in list(self.jobs.values()):
                job.control.cancel()
        self.executor.shutdown(wait=wait, cancel_futures=True)
