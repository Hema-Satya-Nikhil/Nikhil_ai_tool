from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from werkzeug.serving import WSGIRequestHandler, make_server

from lab_app import app as lab_app
from nikhil_ai_modules.api_check import analyze_api
from nikhil_ai_modules.auth_check import analyze_authentication
from nikhil_ai_modules.authz_check import compare_test_accounts
from nikhil_ai_modules.command_injection import detect_command_injection_signals
from nikhil_ai_modules.cors_check import check_cors
from nikhil_ai_modules.context import build_context
from nikhil_ai_modules.cookies import analyze_cookie_security
from nikhil_ai_modules.dns_check import check_dns
from nikhil_ai_modules.endpoint_discovery import discover_endpoints
from nikhil_ai_modules.exposure import inspect_exposure
from nikhil_ai_modules.headers import check_headers
from nikhil_ai_modules.http_probe import probe_http_https
from nikhil_ai_modules.js_analysis import analyze_javascript_files
from nikhil_ai_modules.nosql_check import detect_nosql_signals
from nikhil_ai_modules.path_traversal import detect_path_parameters
from nikhil_ai_modules.port_scan import scan_ports
from nikhil_ai_modules.scan_runner import run_scan
from nikhil_ai_modules.sqli_check import detect_sqli
from nikhil_ai_modules.ssl_check import check_ssl
from nikhil_ai_modules.subdomains import enumerate_subdomains
from nikhil_ai_modules.tech_detect import detect_technology
from nikhil_ai_modules.upload_check import inspect_upload_surfaces


class QuietRequestHandler(WSGIRequestHandler):
    def log(self, *_args):
        pass


class ModuleSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server("127.0.0.1", 0, lab_app, threaded=True, request_handler=QuietRequestHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.context = build_context(config_path=root / "config.json", database_path=root / "db.sqlite3")
        self.context.config["request_interval"] = 0.25
        self.context.http.rate_limiter.interval = 0.25
        self.context.config["timeout"] = 1.0
        self.context.config["port_scan_ports"] = [self.port]
        self.context.scope.add_target("127.0.0.1/32")
        self.base = f"http://127.0.0.1:{self.port}/"

    def tearDown(self):
        self.tmp.cleanup()

    def test_all_menu_scanners_smoke_against_local_lab(self):
        cases = [
            ("subdomain_enumeration", "127.0.0.1", enumerate_subdomains, {"use_ct": False}),
            ("http_https_probe", self.base, probe_http_https, {}),
            ("technology_detection", self.base, detect_technology, {}),
            ("endpoint_discovery", self.base, discover_endpoints, {}),
            ("javascript_analysis", self.base, analyze_javascript_files, {}),
            ("security_headers", self.base, check_headers, {}),
            ("dns_origin_exposure", "127.0.0.1", check_dns, {}),
            ("ssl_tls_audit", f"https://127.0.0.1:{self.port}/", check_ssl, {}),
            ("open_port_scan", "127.0.0.1", scan_ports, {}),
            ("cors_check", self.base, check_cors, {}),
            ("cookie_security", self.base, analyze_cookie_security, {}),
            ("sqli_detection", self.base + "sqli-lab?q=search", detect_sqli, {"confirm_read_only": True}),
            ("nosql_detection", self.base + "search?filter=name", detect_nosql_signals, {}),
            ("command_injection_detection", self.base + "search?command=hello", detect_command_injection_signals, {}),
            ("path_traversal_detection", self.base + "search?file=readme.txt", detect_path_parameters, {}),
            ("authentication_session_analysis", self.base, analyze_authentication, {}),
            ("authorization_comparison", self.base + "lab-resource/test-1001", compare_test_accounts,
             {"account_a_token": "local-test-a", "account_b_token": "local-test-b", "confirmed": True}),
            ("api_security_analysis", self.base + "api/profile", analyze_api, {}),
            ("upload_surface_review", self.base + "upload", inspect_upload_surfaces, {}),
            ("sensitive_exposure_check", self.base, inspect_exposure, {}),
        ]
        for name, target, scanner, kwargs in cases:
            with self.subTest(module=name):
                result = run_scan(name, target, scanner, context=self.context, **kwargs)
                self.assertIsInstance(result, dict)
        self.assertTrue(self.context.config["safe_mode"])
        self.assertGreaterEqual(len(self.context.database.list_scans(self.context.project_id)), len(cases))


if __name__ == "__main__":
    unittest.main()
