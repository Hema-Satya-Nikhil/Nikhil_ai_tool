"""Persisted local event bus used by scans and the SSE dashboard stream."""
from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

from nikhil_ai_modules.evidence import redact_text, sanitize_url, sanitize_value


class ScanCancelled(Exception):
    """Raised at a safe checkpoint after an operator requests cancellation."""


class ScanEventBus:
    """SQLite-backed events with in-process notifications for local SSE clients.

    The SQLite event log is the source of truth. The condition variable only
    reduces latency for a single-process local deployment; SSE reconnects read
    from persisted event IDs and therefore do not rely on in-memory history.
    """

    def __init__(self, database, project_id: int, config=None):
        self.database = database
        self.project_id = int(project_id)
        self.config = config or {}
        self._condition = threading.Condition()
        self._local = threading.local()

    @contextmanager
    def bind_scan(self, scan_id: int, target: str, control=None) -> Iterator[None]:
        old = getattr(self._local, "runtime", None)
        self._local.runtime = {
            "scan_id": int(scan_id),
            "target": target,
            "control": control,
            "started": time.monotonic(),
            "requests": 0,
            "request_times": deque(maxlen=20),
        }
        try:
            yield
        finally:
            self._local.runtime = old

    def runtime(self) -> Optional[Dict[str, Any]]:
        return getattr(self._local, "runtime", None)

    def publish(
        self,
        event_type: str,
        *,
        scan_id: Optional[int] = None,
        severity: str = "info",
        target: Optional[str] = None,
        message: str = "",
        data: Any = None,
    ) -> Dict[str, Any]:
        runtime = self.runtime()
        if scan_id is None and runtime:
            scan_id = runtime.get("scan_id")
        if target is None and runtime:
            target = runtime.get("target")
        safe_target = None
        if target:
            safe_target = sanitize_url(target) if "://" in str(target) else redact_text(target, 300)
        safe_data = sanitize_value(data or {})
        event_name = str(event_type or "info").lower()[:60]
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,59}", event_name):
            event_name = "scanner_event"
        safe_severity = str(severity or "info").lower()[:16]
        if safe_severity not in {"debug", "info", "warning", "error", "critical"}:
            safe_severity = "info"
        event = self.database.add_event(
            self.project_id,
            scan_id=scan_id,
            event_type=event_name,
            severity=safe_severity,
            target=safe_target,
            message=redact_text(message, 500),
            data=safe_data if isinstance(safe_data, (dict, list)) else {"value": safe_data},
        )
        with self._condition:
            self._condition.notify_all()
        return event

    def before_request(self, method: str, url: str) -> None:
        runtime = self.runtime()
        if not runtime:
            return
        control = runtime.get("control")
        if control is not None:
            control.wait_for_resume()
        limit = max(1, int(self.config.get("max_requests", 250)))
        if runtime.get("requests", 0) >= limit:
            runtime["limit_reached"] = True
            if control is not None:
                control.cancel()
            self.publish("warning", severity="warning", message="Per-scan request budget reached; further requests are blocked", data={"max_requests": limit})
            raise ScanCancelled("Per-scan request budget reached")
        if runtime.get("limit_reached"):
            raise ScanCancelled("Per-scan request budget reached")
        runtime["requests"] += 1
        action = f"{method.upper()} {sanitize_url(url)}"
        self.database.update_scan_runtime(
            runtime["scan_id"], requests=runtime["requests"], current_action=action,
        )
        self.publish(
            "scan_progress", message=f"Request started: {method.upper()}",
            data={"requests": runtime["requests"], "current_action": action},
        )

    def after_request(self, method: str, url: str, status_code: Optional[int], elapsed: float) -> None:
        runtime = self.runtime()
        if not runtime:
            return
        now = time.monotonic()
        times = runtime["request_times"]
        times.append(now)
        rate = len(times) / max(1.0, now - (times[0] if len(times) > 1 else runtime["started"]))
        self.database.update_scan_runtime(
            runtime["scan_id"], requests=runtime["requests"], rate=round(rate, 3),
            current_action=f"{method.upper()} {sanitize_url(url)} -> {status_code if status_code is not None else 'error'}",
        )
        self.publish(
            "scan_progress", message=f"Network operation {method.upper()} completed",
            data={
                "requests": runtime["requests"], "rate": round(rate, 3),
                "elapsed_request_seconds": round(max(0.0, elapsed), 3),
                "status_code": status_code,
                "current_action": f"{method.upper()} {sanitize_url(url)}",
            },
        )

    def set_progress(self, progress: Optional[int], action: str = "") -> None:
        runtime = self.runtime()
        if not runtime:
            return
        bounded = None if progress is None else max(0, min(int(progress), 100))
        self.database.update_scan_runtime(runtime["scan_id"], progress=bounded, current_action=action or None)
        self.publish("scan_progress", message=action or "Scan progress updated", data={"progress": bounded, "current_action": action})

    def wait_for_event(self, timeout: float = 15.0) -> None:
        with self._condition:
            self._condition.wait(max(0.1, min(float(timeout), 30.0)))

    def events_after(self, after_id: int = 0, limit: int = 100):
        return self.database.list_events(self.project_id, after_id=after_id, limit=limit)

    def fail_scope(self, target: str, message: str, scan_id: Optional[int] = None) -> None:
        self.publish("scope_block", scan_id=scan_id, severity="warning", target=target, message=message)

    def snapshot(self, limit: int = 50) -> list[Dict[str, Any]]:
        return self.database.list_events(self.project_id, after_id=0, limit=limit, newest=True)
