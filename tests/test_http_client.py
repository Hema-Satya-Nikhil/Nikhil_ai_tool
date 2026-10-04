from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from requests.exceptions import RequestException

from nikhil_ai_modules.context import build_context
from nikhil_ai_modules.http_client import ResponseTooLargeError
from nikhil_ai_modules.scope import ScopeError


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    redirect_location = "http://127.0.0.2:1/blocked"

    def do_GET(self):
        if self.path in {"/oversized", "/oversized-no-length"}:
            body = b"X" * 128
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            if self.path == "/oversized":
                self.send_header("Content-Length", str(len(body)))
            else:
                self.close_connection = True
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/redirect":
            body = b"redirect"
            self.send_response(302)
            self.send_header("Location", self.redirect_location)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"<title>Scoped Lab</title><p>ok</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class ScopedHTTPClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.context = build_context(config_path=self.root / "config.json", database_path=self.root / "db.sqlite3")
        self.context.config["request_interval"] = 0.25
        self.context.http.rate_limiter.interval = 0.25
        self.context.scope.add_target("127.0.0.1/32")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def test_scoped_get_works_for_explicit_lab_ip(self):
        response = self.context.http.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Scoped Lab", response.text)

    def test_out_of_scope_redirect_is_refused_before_request(self):
        with self.assertRaises(ScopeError):
            self.context.http.get(self.url + "redirect")

    def test_oversized_response_is_rejected_before_body_is_returned(self):
        self.context.config["max_response_bytes"] = 32
        for path in ("oversized", "oversized-no-length"):
            with self.subTest(path=path), self.assertRaisesRegex(ResponseTooLargeError, "32-byte limit"):
                self.context.http.get(self.url + path)

    def test_cross_origin_redirect_drops_credentials_and_routing_headers(self):
        received = {}

        class DestinationHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                received.update({name.lower(): value for name, value in self.headers.items()})
                received["body"] = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
                body = b"destination"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        destination = ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler)
        destination_thread = threading.Thread(target=destination.serve_forever, daemon=True)
        destination_thread.start()
        Handler.redirect_location = f"http://127.0.0.1:{destination.server_port}/landing"
        try:
            response = self.context.http.get(
                self.url + "redirect",
                headers={
                    "Authorization": "Bearer qa-only-secret",
                    "X-Api-Key": "qa-api-secret",
                    "Cookie": "session=qa-cookie-secret",
                    "Host": "127.0.0.1",
                    "Origin": "http://127.0.0.1",
                    "Referer": "http://127.0.0.1/private",
                    "Accept": "text/plain",
                },
                data={"api_key": "qa-body-secret"},
            )
        finally:
            Handler.redirect_location = "http://127.0.0.2:1/blocked"
            destination.shutdown()
            destination.server_close()
            destination_thread.join(timeout=2)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("authorization", received)
        self.assertNotIn("x-api-key", received)
        self.assertNotIn("cookie", received)
        self.assertEqual(received.get("host"), f"127.0.0.1:{destination.server_port}")
        self.assertNotIn("origin", received)
        self.assertNotIn("referer", received)
        self.assertEqual(received.get("accept"), "text/plain")
        self.assertEqual(received.get("body"), b"")

    def test_http_error_logs_redact_query_credentials(self):
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            port = unused.getsockname()[1]
        logger = Mock()
        self.context.http.logger = logger
        with self.assertRaises(RequestException):
            self.context.http.get(f"http://127.0.0.1:{port}/?api_key=qa-only-secret")
        logged = " ".join(str(call.args) for call in logger.warning.call_args_list)
        self.assertNotIn("qa-only-secret", logged)

    def test_out_of_scope_host_is_refused(self):
        with self.assertRaises(ScopeError):
            self.context.http.get("http://127.0.0.2:1/")

    def test_connected_peer_must_match_approved_scope_addresses(self):
        authorize_url = self.context.scope.authorize_url

        def approve_different_peer(url, *, purpose="target"):
            checked_url, _addresses = authorize_url(url, purpose=purpose)
            return checked_url, ["127.0.0.2"]

        with patch.object(self.context.scope, "authorize_url", side_effect=approve_different_peer):
            with self.assertRaisesRegex(ScopeError, "Connected peer"):
                self.context.http.get(self.url)


if __name__ == "__main__":
    unittest.main()
