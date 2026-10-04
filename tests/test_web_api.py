from __future__ import annotations

import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import app as app_module
from app import app
from nikhil_ai_modules.context import build_context
from nikhil_ai_modules.findings import Finding
from nikhil_ai_modules.plugins import ScannerSpec


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<title>Local API fixture</title><p>authorized lab</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class WebAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.context = build_context(config_path=root / "config.json", database_path=root / "db.sqlite3")
        self.context.config["request_interval"] = 0.25
        self.context.http.rate_limiter.interval = 0.25
        self.context.scope.add_target("127.0.0.1/32")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        self.client = app.test_client()
        self.patch_context = patch("app.get_default_context", return_value=self.context)
        self.patch_context.start()

    def tearDown(self):
        self.patch_context.stop()
        if self.context.scan_manager is not None:
            self.context.scan_manager.shutdown(wait=True)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def test_same_origin_api_enforces_scope_and_returns_structured_data(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIsNone(page.headers.get("Access-Control-Allow-Origin"))
        state = self.client.get("/api/scope")
        self.assertTrue(state.json["safe_mode"])
        denied = self.client.post("/api/validate", json={"url": "http://127.0.0.2:1/"})
        self.assertEqual(denied.status_code, 403)
        allowed = self.client.post("/api/validate", json={"url": self.url})
        self.assertEqual(allowed.status_code, 200)
        result = self.client.post("/api/scan/headers", json={"url": self.url})
        self.assertEqual(result.status_code, 200)
        self.assertIn("headers", result.json["data"])
        self.assertIsInstance(result.json["data"]["headers"]["missing"], list)

    def test_finding_notes_are_redacted_before_persistence_and_api_readback(self):
        finding = self.context.findings.add(Finding(
            title="Potential local observation", category="Test", target=self.url,
            description="Synthetic test lead", severity="LOW", confidence="LOW",
        ))
        response = self.client.patch(
            f"/api/findings/{finding['finding_id']}",
            json={"researcher_notes": "credential=qa-only-secret"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("qa-only-secret", response.get_data(as_text=True))
        listed = self.client.get("/api/findings")
        self.assertEqual(listed.status_code, 200)
        self.assertNotIn("qa-only-secret", listed.get_data(as_text=True))
        self.assertIn("[REDACTED]", listed.get_data(as_text=True))

    def test_project_metadata_redacts_credentials_before_storage(self):
        secrets = ("qa-description-secret", "qa-program-secret", "qa-cookie-secret")
        response = self.client.post("/api/projects", json={
            "name": "QA Metadata Redaction",
            "description": "Review /api/token/qa-description-secret",
            "program": "token=qa-program-secret",
            "notes": "Set-Cookie: sessionid=qa-cookie-secret; Path=/",
        })
        self.assertEqual(response.status_code, 201)
        project_id = response.json["data"]["id"]
        row = next(item for item in self.context.database.list_projects() if item["id"] == project_id)
        serialized = str(row) + response.get_data(as_text=True)
        for secret in secrets:
            self.assertNotIn(secret, serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_project_switch_is_blocked_during_legacy_synchronous_scan(self):
        other_project_id = self.context.database.create_project("Other local project")
        manager = app_module.get_scan_manager(self.context)
        entered = threading.Event()
        release = threading.Event()
        responses = []

        def slow_scan(*_args, **_kwargs):
            entered.set()
            release.wait(3)
            return {"potential_findings": []}

        def request_scan():
            with app.test_client() as worker_client:
                responses.append(worker_client.post("/api/scan/headers", json={"url": self.url}))

        try:
            with patch("app.run_scan", side_effect=slow_scan):
                worker = threading.Thread(target=request_scan, daemon=True)
                worker.start()
                self.assertTrue(entered.wait(2))
                switch = self.client.post(f"/api/projects/{other_project_id}/activate")
                self.assertEqual(switch.status_code, 409)
                self.assertTrue(manager.has_project_operation(self.context.project_id))
                add_rule = self.client.post("/api/scope/rules", json={"kind": "exclude", "rule": "192.0.2.1/32"})
                delete_rule = self.client.delete("/api/scope/rules", json={"kind": "include", "rule": "127.0.0.1/32"})
                self.assertEqual(add_rule.status_code, 409)
                self.assertEqual(delete_rule.status_code, 409)
                release.set()
                worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(responses[0].status_code, 200)
        finally:
            release.set()

    def test_settings_validate_safe_defaults_and_opt_in_integrations(self):
        initial = self.client.get("/api/settings")
        self.assertTrue(initial.json["data"]["safe_mode"])
        self.assertFalse(initial.json["data"]["threat_intelligence_enabled"])
        with patch.object(self.context.http, "get", side_effect=AssertionError("external HTTP must not run")) as fetch:
            denied = self.client.post("/api/threat-intelligence/refresh", json={"product":"Apache", "version":"2.4"})
            self.assertEqual(denied.status_code, 403)
            malformed_force = self.client.post("/api/threat-intelligence/refresh", json={"product":"Apache", "version":"2.4", "force":"false"})
            self.assertEqual(malformed_force.status_code, 400)
            fetch.assert_not_called()
        enabled = self.client.patch("/api/settings", json={"threat_intelligence_enabled":True,"enabled_integrations":{"nmap":True}})
        self.assertEqual(enabled.status_code, 200)
        self.assertTrue(self.context.config["threat_intelligence"]["enabled"])
        self.assertTrue(self.context.config["enabled_integrations"]["nmap"])
        bad_nuclei = self.client.patch("/api/settings", json={"enabled_integrations":{"nuclei":True}})
        self.assertEqual(bad_nuclei.status_code, 400)
        bad_value = self.client.patch("/api/settings", json={"enabled_integrations":{"nmap":"sometimes"}})
        self.assertEqual(bad_value.status_code, 400)
        unsafe = self.client.patch("/api/settings", json={"safe_mode":False})
        self.assertEqual(unsafe.status_code, 400)
        out_of_bounds = self.client.patch("/api/settings", json={"max_requests":10001})
        self.assertEqual(out_of_bounds.status_code, 400)

    def test_settings_patch_is_atomic_and_resizes_workers_only_when_idle(self):
        manager = app_module.get_scan_manager(self.context)
        original_timeout = self.context.config["timeout"]
        rejected = self.client.patch(
            "/api/settings",
            json={"timeout": 2, "enabled_integrations": {"not-a-tool": True}},
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(self.context.config["timeout"], original_timeout)

        updated = self.client.patch("/api/settings", json={"timeout": 2, "scan_workers": 1})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(self.context.config["timeout"], 2)
        self.assertEqual(manager.worker_count, 1)

        entered, release = threading.Event(), threading.Event()

        def blocker(_target, context=None):
            entered.set()
            release.wait(3)
            return {}

        scan = manager.submit_spec(
            ScannerSpec("settings_blocker", "Settings blocker", "test", "test", blocker), self.url
        )
        self.assertTrue(entered.wait(2))
        unchanged_workers = self.client.patch("/api/settings", json={"timeout": 2.5, "scan_workers": 1})
        self.assertEqual(unchanged_workers.status_code, 200)
        self.assertEqual(self.context.config["timeout"], 2.5)
        rejected_active = self.client.patch("/api/settings", json={"timeout": 3, "scan_workers": 2})
        self.assertEqual(rejected_active.status_code, 400)
        self.assertEqual(self.context.config["timeout"], 2.5)
        self.assertEqual(manager.worker_count, 1)
        release.set()
        deadline = time.monotonic() + 5
        row = None
        while time.monotonic() < deadline:
            row = self.context.database.get_scan(self.context.project_id, scan["id"])
            if row and row["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
                break
            time.sleep(0.02)
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "COMPLETED")

    def test_oversized_ids_return_structured_errors_instead_of_sqlite_500s(self):
        huge = "999999999999999999999999999999"
        for path in (
            f"/api/scans/{huge}",
            f"/api/scans/{huge}/logs",
            f"/api/reports/{huge}",
            f"/api/reports/{huge}/download",
            f"/api/evidence/{huge}",
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 404, path)
            self.assertFalse(response.json["success"], path)
        for query in (f"after={huge}", f"scan_id={huge}"):
            response = self.client.get(f"/api/events?{query}")
            self.assertEqual(response.status_code, 400, query)
            self.assertFalse(response.json["success"], query)
        self.context.events.publish("fixture_event", message="Persisted event")
        stream = self.client.get(f"/api/events/stream?after={huge}&once=1")
        self.assertEqual(stream.status_code, 200)
        self.assertEqual(stream.get_data(as_text=True), "")

    def test_async_scan_queue_and_read_routes_are_database_backed(self):
        response = self.client.post("/api/scans", json={"module": "headers", "target": self.url})
        self.assertEqual(response.status_code, 202)
        scan_id = response.json["data"]["id"]
        deadline = time.monotonic() + 6
        scan = None
        while time.monotonic() < deadline:
            scan = self.context.database.get_scan(self.context.project_id, scan_id)
            if scan and scan["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
                break
            time.sleep(0.02)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["status"], "COMPLETED")
        events = self.client.get(f"/api/scans/{scan_id}/logs")
        self.assertEqual(events.status_code, 200)
        self.assertTrue(any(item["type"] == "scan_completed" for item in events.json["data"]))
        self.assertEqual(self.client.get("/api/findings").status_code, 200)
        self.assertEqual(self.client.get("/api/assets/graph").status_code, 200)
        self.assertEqual(self.client.get("/api/integrations").status_code, 200)
        denied = self.client.post("/api/scans", json={"module": "headers", "target": "http://127.0.0.2:1/"})
        self.assertEqual(denied.status_code, 403)


if __name__ == "__main__":
    unittest.main()
