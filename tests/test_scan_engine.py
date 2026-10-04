from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import app
from nikhil_ai_modules.context import build_context
from nikhil_ai_modules.events import ScanCancelled
from nikhil_ai_modules.plugins import ScannerSpec
from nikhil_ai_modules.scan_manager import ScanManager
from nikhil_ai_modules.scope import ScopeError


class Handler(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        Handler.hits += 1
        body = b"<title>Queue Fixture</title><a href='/api/profile'>profile</a>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class ScanEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Handler.hits = 0
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.context = build_context(config_path=root / "config.json", database_path=root / "database.sqlite3")
        self.context.config["request_interval"] = 0.25
        self.context.config["scan_workers"] = 1
        self.context.http.rate_limiter.interval = 0.25
        self.context.scope.add_target("127.0.0.1/32")
        self.manager = ScanManager(self.context)

    def tearDown(self):
        self.manager.shutdown(wait=True)
        self.tmp.cleanup()

    def wait_terminal(self, scan_id, timeout=6):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = self.context.database.get_scan(self.context.project_id, scan_id)
            if row and row["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
                return row
            threading.Event().wait(0.02)
        self.fail(f"scan {scan_id} did not reach a terminal state")

    def test_plugin_scan_persists_assets_endpoints_findings_and_events(self):
        def fixture_scanner(target, context=None):
            response = context.http.get(target)
            return {
                "assets": [{"host": "127.0.0.1", "status": "LIVE"}],
                "endpoints": [{"url": response.url + "api/profile", "method": "GET", "status_code": 200, "source": "fixture"}],
                "potential_findings": [{
                    "title": "Potential fixture observation", "category": "Test", "target": response.url,
                    "endpoint": response.url, "severity": "LOW", "confidence": "LOW",
                    "description": "Synthetic event test", "evidence": "response received",
                }],
                "metrics": {"fixture_completed": True},
            }

        spec = ScannerSpec("fixture_plugin", "Fixture plugin", "test-only", "test", fixture_scanner)
        scan = self.manager.submit_spec(spec, self.url)
        row = self.wait_terminal(scan["id"])
        self.assertEqual(row["status"], "COMPLETED")
        self.assertGreaterEqual(row["requests"], 1)
        self.assertTrue(self.context.database.list_assets(self.context.project_id))
        self.assertTrue(self.context.database.list_endpoints(self.context.project_id))
        findings = self.context.database.list_findings(self.context.project_id)
        self.assertEqual(findings[0]["status"], "NEEDS_REVIEW")
        self.assertEqual(findings[0]["module"], "fixture_plugin")
        types = {item["type"] for item in self.context.database.list_events(self.context.project_id, scan_id=scan["id"], limit=100)}
        self.assertTrue({"scan_started", "scan_progress", "asset_discovered", "endpoint_discovered", "finding_created", "scan_completed"}.issubset(types))

    def test_scan_queue_has_bounded_capacity(self):
        blocked = threading.Event()
        release = threading.Event()

        def blocker(target, context=None):
            blocked.set()
            release.wait(3)
            return {}

        with patch("nikhil_ai_modules.scan_manager.MAX_PENDING_SCANS", 2):
            first = self.manager.submit_spec(ScannerSpec("queue_first", "Queue first", "test", "test", blocker), self.url)
            self.assertTrue(blocked.wait(2))
            second = self.manager.submit_spec(ScannerSpec("queue_second", "Queue second", "test", "test", lambda *_args, **_kwargs: {}), self.url)
            with self.assertRaisesRegex(ValueError, "Scan queue is full"):
                self.manager.submit_spec(ScannerSpec("queue_third", "Queue third", "test", "test", lambda *_args, **_kwargs: {}), self.url)
            release.set()
            self.assertEqual(self.wait_terminal(first["id"])["status"], "COMPLETED")
            self.assertEqual(self.wait_terminal(second["id"])["status"], "COMPLETED")

    def test_scope_guard_filters_plugin_inventory_and_malformed_findings(self):
        def fixture_scanner(target, context=None):
            return {
                "assets": [
                    {"host":"127.0.0.1","status":"LIVE","addresses":["127.0.0.1","127.0.0.2"]},
                    {"host":"127.0.0.2","status":"LIVE"},
                ],
                "endpoints": [
                    {"url":target,"method":"GET","source":"fixture"},
                    {"url":"http://127.0.0.2:5001/private","method":"GET","source":"fixture"},
                ],
                "potential_findings": [
                    {"title":"Out-of-scope finding","category":"test","target":"http://127.0.0.2/","severity":"HIGH"},
                    {"title":None,"category":"test","target":target,"severity":"LOW"},
                    {"title":"In-scope synthetic finding","category":"test","target":target,"severity":"LOW"},
                ],
                "evidence":[{"target":"http://127.0.0.2/","description":"must be dropped"}],
            }

        scan=self.manager.submit_spec(ScannerSpec("filter_fixture","Filter fixture","test","test",fixture_scanner),self.url)
        row=self.wait_terminal(scan["id"])
        self.assertEqual(row["status"],"COMPLETED")
        result=row["result"]
        self.assertEqual([item["host"] for item in result["assets"]],["127.0.0.1"])
        self.assertEqual(result["assets"][0]["addresses"],["127.0.0.1"])
        self.assertEqual([item["url"] for item in result["endpoints"]],[self.url])
        self.assertEqual([item["title"] for item in result["potential_findings"]],["In-scope synthetic finding"])
        self.assertEqual(result["evidence"],[])
        self.assertEqual(len(self.context.database.list_findings(self.context.project_id)),1)
        self.assertTrue(any(item["type"]=="scope_block" for item in self.context.database.list_events(self.context.project_id,scan_id=scan["id"],limit=100)))

    def test_scope_guard_filters_plugin_results_resolving_to_excluded_ip(self):
        self.context.scope.add_target("*.example")
        self.context.scope.add_exclusion("127.0.0.2/32")

        def fixture_scanner(target, context=None):
            return {
                "endpoints": [{"url": "http://service.example/private", "method": "GET"}],
                "potential_findings": [{
                    "title": "Out-of-scope DNS alias", "category": "test",
                    "target": "http://service.example/", "endpoint": "http://service.example/private",
                    "severity": "LOW", "confidence": "LOW",
                }],
                "evidence": [{"target": "http://service.example/", "description": "must be dropped"}],
                "events": [{"type": "plugin_note", "target": "http://service.example/", "message": "must be dropped"}],
                "detections": [{"url": "http://service.example/", "technologies": [{"technology": "Synthetic"}]}],
            }

        real_getaddrinfo = socket.getaddrinfo

        def resolve(host, *args, **kwargs):
            if host == "service.example":
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.2", 0))]
            return real_getaddrinfo(host, *args, **kwargs)

        with patch("nikhil_ai_modules.scope.socket.getaddrinfo", side_effect=resolve):
            scan = self.manager.submit_spec(
                ScannerSpec("dns_filter_fixture", "DNS filter fixture", "test", "test", fixture_scanner), self.url
            )
            row = self.wait_terminal(scan["id"])

        self.assertEqual(row["status"], "COMPLETED")
        result = row["result"]
        self.assertEqual(result["endpoints"], [])
        self.assertEqual(result["potential_findings"], [])
        self.assertEqual(result["evidence"], [])
        self.assertEqual(result["events"], [])
        self.assertEqual(self.context.database.list_findings(self.context.project_id), [])
        self.assertEqual(self.context.database.list_endpoints(self.context.project_id), [])
        self.assertEqual(self.context.database.list_evidence(self.context.project_id), [])
        self.assertEqual(self.context.database.list_technologies(self.context.project_id), [])
        self.assertTrue(any(event["type"] == "scope_block" for event in self.context.database.list_events(self.context.project_id, scan_id=scan["id"], limit=100)))

    def test_pause_and_resume_blocks_requests_at_safe_checkpoint(self):
        ready = threading.Event()
        release = threading.Event()
        start_hits = Handler.hits

        def gated_scanner(target, context=None):
            ready.set()
            release.wait(3)
            response = context.http.get(target)
            return {"target": response.url, "potential_findings": []}

        spec = ScannerSpec("gated_plugin", "Gated fixture", "test-only", "test", gated_scanner)
        scan = self.manager.submit_spec(spec, self.url)
        self.assertTrue(ready.wait(2))
        self.assertTrue(self.manager.pause(scan["id"]))
        release.set()
        threading.Event().wait(0.2)
        self.assertEqual(Handler.hits, start_hits)
        self.assertTrue(self.manager.resume(scan["id"]))
        row = self.wait_terminal(scan["id"])
        self.assertEqual(row["status"], "COMPLETED")
        self.assertEqual(Handler.hits, start_hits + 1)

    def test_queued_pause_is_not_overwritten_when_worker_starts(self):
        blocked = threading.Event()
        release = threading.Event()

        def blocker(target, context=None):
            blocked.set()
            release.wait(3)
            return {}

        first = self.manager.submit_spec(ScannerSpec("blocker", "Blocker", "test", "test", blocker), self.url)
        self.assertTrue(blocked.wait(2))
        start_hits = Handler.hits
        second = self.manager.submit_spec(
            ScannerSpec("paused_queued", "Paused queued", "test", "test", lambda target, context=None: context.http.get(target).status_code),
            self.url,
        )
        self.assertTrue(self.manager.pause(second["id"]))
        self.assertEqual(self.context.database.get_scan(self.context.project_id, second["id"])["status"], "PAUSED")
        release.set()
        first_row = self.wait_terminal(first["id"])
        self.assertEqual(first_row["status"], "COMPLETED")
        time.sleep(0.15)
        paused_row = self.context.database.get_scan(self.context.project_id, second["id"])
        self.assertEqual(paused_row["status"], "PAUSED")
        self.assertEqual(Handler.hits, start_hits)
        self.assertTrue(self.manager.resume(second["id"]))
        self.assertEqual(self.wait_terminal(second["id"])["status"], "COMPLETED")
        self.assertEqual(Handler.hits, start_hits + 1)

    def test_cancel_stops_at_next_http_checkpoint(self):
        ready = threading.Event()
        release = threading.Event()
        start_hits = Handler.hits

        def gated_scanner(target, context=None):
            ready.set()
            release.wait(3)
            response = context.http.get(target)
            return {"target": response.url}

        spec = ScannerSpec("cancel_plugin", "Cancellation fixture", "test-only", "test", gated_scanner)
        scan = self.manager.submit_spec(spec, self.url)
        self.assertTrue(ready.wait(2))
        self.assertTrue(self.manager.cancel(scan["id"]))
        release.set()
        row = self.wait_terminal(scan["id"])
        self.assertEqual(row["status"], "CANCELLED")
        self.assertEqual(Handler.hits, start_hits)
        events = self.context.database.list_events(self.context.project_id, scan_id=scan["id"], limit=100)
        self.assertEqual(sum(event["type"] == "scan_cancelled" for event in events), 1)

    def test_safe_mode_rejects_plugins_without_safe_mode_support(self):
        spec = ScannerSpec("unsafe_fixture", "Unsafe fixture", "not safe", "test", lambda target, context=None: {}, supports_safe_mode=False)
        with self.assertRaises(ValueError):
            self.manager.submit_spec(spec, self.url)
        self.assertEqual(self.context.database.list_scans(self.context.project_id), [])

    def test_queue_rejects_out_of_scope_targets_and_records_scope_block(self):
        with self.assertRaises(ScopeError):
            self.manager.submit("http", "http://127.0.0.2:1/")
        events = self.context.database.list_events(self.context.project_id, newest=True, limit=5)
        self.assertTrue(any(item["type"] == "scope_block" for item in events))
        self.assertEqual(self.context.database.list_scans(self.context.project_id), [])

    def test_job_remains_project_active_through_final_event_publication(self):
        publishing = threading.Event()
        release = threading.Event()
        original_publish = self.context.events.publish

        def delayed_publish(event_type, **kwargs):
            if event_type == "scan_completed":
                publishing.set()
                release.wait(3)
            return original_publish(event_type, **kwargs)

        self.context.events.publish = delayed_publish
        spec = ScannerSpec("quick_fixture", "Quick fixture", "test", "test", lambda target, context=None: {})
        try:
            scan = self.manager.submit_spec(spec, self.url)
            self.assertTrue(publishing.wait(3))
            row = self.context.database.get_scan(self.context.project_id, scan["id"])
            self.assertEqual(row["status"], "COMPLETED")
            self.assertIn(scan["id"], {item["id"] for item in self.manager.active()})
        finally:
            release.set()
            self.context.events.publish = original_publish
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and scan["id"] in self.manager.jobs:
            time.sleep(0.01)
        self.assertNotIn(scan["id"], {item["id"] for item in self.manager.active()})

    def test_restart_recovery_fails_unfinished_jobs(self):
        scan_id = self.context.database.start_scan(self.context.project_id, "http://127.0.0.1/", "fixture", status="RUNNING")
        self.assertEqual(self.context.database.fail_unfinished_scans(), 1)
        row = self.context.database.get_scan(self.context.project_id, scan_id)
        self.assertEqual(row["status"], "FAILED")
        self.assertIn("restarted", row["error"])

    def test_sse_stream_delivers_persisted_backend_event(self):
        self.context.events.publish("asset_discovered", target="127.0.0.1", message="Fixture asset event", data={"host": "127.0.0.1"})
        client = app.app.test_client()
        with patch("app.get_default_context", return_value=self.context):
            response = client.get("/api/events/stream?once=1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/event-stream", response.content_type)
        self.assertIn("asset_discovered", response.get_data(as_text=True))
        self.assertIn("Fixture asset event", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
