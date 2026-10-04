from __future__ import annotations

import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from nikhil_ai_modules.config import load_config
from nikhil_ai_modules.context import build_context
from nikhil_ai_modules.cors_check import analyze_cors
from nikhil_ai_modules.findings import Finding, FindingManager
from nikhil_ai_modules.headers import analyze_headers
from nikhil_ai_modules.report import _report_safe, generate_report
from nikhil_ai_modules.sqli_check import detect_sqli
from nikhil_ai_modules.scope import ScopeError, ScopeManager, normalize_url
from nikhil_ai_modules.ssl_check import _parse_cert_time
from nikhil_ai_modules.evidence import redact_headers, redact_text, sanitize_url


class ConfigTests(unittest.TestCase):
    def test_malformed_boolean_flags_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({
                "safe_mode": "false",
                "enabled_integrations": {"nmap": "false", "subfinder": "true", "amass": "perhaps"},
                "threat_intelligence": {"enabled": "false"},
            }), encoding="utf-8")
            config = load_config(path)
        self.assertTrue(config["safe_mode"])
        self.assertFalse(config["enabled_integrations"]["nmap"])
        self.assertTrue(config["enabled_integrations"]["subfinder"])
        self.assertFalse(config["enabled_integrations"]["amass"])
        self.assertFalse(config["threat_intelligence"]["enabled"])

    def test_malformed_scope_values_fail_closed_in_config_and_project_file(self):
        from nikhil_ai_modules.projects import load_project_scope

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            config_path.write_text(json.dumps({"scope": {"in_scope": "127.0.0.1/32", "exclusions": "127.0.0.2/32"}}), encoding="utf-8")
            config = load_config(config_path)
            project_path = root / "project.json"
            project_path.write_text(json.dumps({"scope": {"in_scope": "127.0.0.1/32", "exclusions": "127.0.0.2/32"}}), encoding="utf-8")
            project_scope = load_project_scope("Malformed", project_path)
        self.assertEqual(config["scope"], {"in_scope": [], "exclusions": []})
        self.assertEqual(project_scope, {"in_scope": [], "exclusions": []})


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.manager = ScopeManager({"scope": {"in_scope": [], "exclusions": []}})

    def test_exact_and_wildcard_scope(self):
        self.manager.add_target("example.com")
        self.manager.add_target("*.example.org")
        self.assertTrue(self.manager.is_in_scope("example.com"))
        self.assertFalse(self.manager.is_in_scope("www.example.com"))
        self.assertTrue(self.manager.is_in_scope("api.example.org"))
        self.assertTrue(self.manager.is_in_scope("deep.api.example.org"))
        self.assertFalse(self.manager.is_in_scope("example.org"))

    def test_exclusion_has_priority(self):
        self.manager.add_target("*.example.com")
        self.manager.add_exclusion("admin.example.com")
        self.assertTrue(self.manager.is_in_scope("api.example.com"))
        self.assertFalse(self.manager.is_in_scope("admin.example.com"))
        with self.assertRaises(ScopeError):
            self.manager.require_host_rule("admin.example.com")

    def test_ip_and_cidr_rules(self):
        self.manager.add_target("192.0.2.0/24")
        self.assertTrue(self.manager.is_in_scope("192.0.2.9"))
        self.assertFalse(self.manager.is_in_scope("192.0.3.9"))

    def test_url_normalization(self):
        self.assertEqual(
            normalize_url("HTTPS://EXAMPLE.COM:443/a?x=1#fragment"),
            "https://example.com/a?x=1",
        )
        self.assertEqual(normalize_url("example.com"), "https://example.com/")
        with self.assertRaises(ScopeError):
            normalize_url("file:///etc/passwd")
        with self.assertRaises(ScopeError):
            normalize_url("https://user:password@example.com/")

    def test_excluded_resolved_ip_is_rejected(self):
        self.manager.add_target("example.net")
        self.manager.add_exclusion("8.8.8.0/24")
        addrinfo = [(2, 1, 6, "", ("8.8.8.8", 0))]
        with patch("nikhil_ai_modules.scope.socket.getaddrinfo", return_value=addrinfo):
            with self.assertRaisesRegex(ScopeError, "explicitly excluded"):
                self.manager.validate_host("example.net")

    def test_out_of_scope_and_private_require_explicit_ip_rule(self):
        with self.assertRaises(ScopeError):
            self.manager.validate_host("127.0.0.1")
        self.manager.add_target("127.0.0.1/32")
        self.assertEqual(self.manager.validate_host("127.0.0.1"), ["127.0.0.1"])

    def test_localhost_ipv6_loopback_requires_explicit_allowlist_rule(self):
        import socket

        addrinfo = [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0)),
        ]
        self.manager.add_target("localhost")
        with patch("nikhil_ai_modules.scope.socket.getaddrinfo", return_value=addrinfo):
            with self.assertRaisesRegex(ScopeError, "explicitly add an authorized IP/CIDR"):
                self.manager.validate_host("localhost")
            self.manager.add_target("::1/128")
            self.manager.add_target("127.0.0.1/32")
            self.assertEqual(self.manager.validate_host("localhost"), ["127.0.0.1", "::1"])
            self.manager.add_exclusion("::1/128")
            with self.assertRaisesRegex(ScopeError, "explicitly excluded"):
                self.manager.validate_host("localhost")

    def test_exclusions_block_passive_source_requests(self):
        self.manager.add_exclusion("crt.sh")
        with self.assertRaisesRegex(ScopeError, "explicitly excluded"):
            self.manager.validate_host("crt.sh", purpose="passive_source")

    def test_malformed_scope_shapes_do_not_widen_authorization(self):
        malformed = ScopeManager({"scope": {"in_scope": "127.0.0.1/32", "exclusions": ""}})
        self.assertEqual(malformed.in_scope, [])
        self.assertFalse(malformed.is_in_scope("127.0.0.1"))


class DetectionTests(unittest.TestCase):
    def test_header_detection(self):
        analysis = analyze_headers({"Server": "test"}, is_https=True)
        self.assertIn("Content-Security-Policy", analysis["missing"])
        self.assertIn("Strict-Transport-Security", analysis["missing"])
        strong = analyze_headers({
            "Content-Security-Policy": "default-src 'self'; script-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        })
        self.assertEqual(strong["missing"], [])
        self.assertEqual(strong["hsts"]["strength"], "strong")

    def test_cors_detection(self):
        permissive = analyze_cors(200, {
            "Access-Control-Allow-Origin": "https://untrusted.invalid",
            "Access-Control-Allow-Credentials": "true",
        })
        self.assertTrue(permissive["reflected_origin"])
        self.assertEqual(permissive["confidence"], "HIGH")
        safe = analyze_cors(200, {"Content-Type": "application/json"})
        self.assertIsNone(safe["vulnerable"])

    def test_tls_time_parser(self):
        parsed = _parse_cert_time("Jan 01 00:00:00 2030 GMT")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tzinfo.utcoffset(parsed).total_seconds(), 0)
        self.assertIsNone(_parse_cert_time("not-a-time"))


class StorageAndRedactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.context = build_context(
            config_path=self.root / "config.json",
            database_path=self.root / "data.sqlite3",
        )
        self.context.config["output_dir"] = str(self.root / "output")

    def tearDown(self):
        self.tmp.cleanup()

    def test_finding_dedup_groups_endpoints(self):
        manager = FindingManager(self.context.database, self.context.project_id)
        base = {
            "title": "Potential CORS issue",
            "category": "CORS",
            "target": "https://example.com/a",
            "endpoint": "https://example.com/a",
            "severity": "LOW",
            "confidence": "LOW",
            "description": "Manual review required",
            "status": "CONFIRMED",  # automated input must not confirm it
        }
        first = manager.add(Finding.from_dict(base))
        second_data = dict(base, target="https://example.com/b", endpoint="https://example.com/b")
        second = manager.add(Finding.from_dict(second_data))
        rows = self.context.database.list_findings(self.context.project_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(first["finding_id"], second["finding_id"])
        self.assertEqual(rows[0]["status"], "NEEDS_REVIEW")
        self.assertEqual(len(rows[0]["affected_endpoints"]), 2)

    def test_secret_redaction(self):
        text = redact_text("password=supersecret123 credential=credential-value Bearer abc.def.ghi email user@example.com")
        self.assertNotIn("supersecret123", text)
        self.assertNotIn("credential-value", text)
        self.assertNotIn("abc.def.ghi", text)
        self.assertNotIn("user@example.com", text)
        self.assertEqual(redact_text('{\"credentials\":\"json-credential\"}'), '{\"credentials\":\"[REDACTED]\"}')
        self.assertNotIn("qa-cookie-secret", redact_text("Set-Cookie: sessionid=qa-cookie-secret; Path=/"))
        self.assertNotIn("qa-session-secret", redact_text('{\"sessionId\":\"qa-session-secret\"}'))
        self.assertNotIn("qa-path-secret", redact_text("discovered path: /api/token/qa-path-secret"))
        self.assertNotIn("qa-state-secret", redact_text("state=qa-state-secret"))
        self.assertIn('"status_code":500', redact_text('{"status_code":500,"code":"qa-code-secret"}'))
        self.assertNotIn("qa-code-secret", redact_text('{"status_code":500,"code":"qa-code-secret"}'))
        self.assertNotIn("abc123", redact_text("request failed for https://example.com/?key=abc123"))
        self.assertEqual(redact_headers({"Set-Cookie": "sid=abc", "Server": "safe"})["Set-Cookie"], "[REDACTED]")
        from urllib.parse import unquote
        self.assertIn("[REDACTED]", unquote(sanitize_url("https://example.com/?token=abc123&view=1")))
        protected_url = unquote(sanitize_url("https://example.com/reset-token/qa-path-secret?code=qa-code-secret&state=qa-state-secret&view=1"))
        for secret in ("qa-path-secret", "qa-code-secret", "qa-state-secret"):
            self.assertNotIn(secret, protected_url)
        self.assertIn("view=1", protected_url)

    def test_sqli_never_tests_oauth_code_or_state_parameters(self):
        target = "https://example.com/callback?code=qa-oauth-code&state=qa-oauth-state"
        with patch.object(self.context.http, "get", side_effect=AssertionError("secret query values must not be probed")) as fetch:
            result = detect_sqli(target, self.context, confirm_read_only=True)
        self.assertEqual(result["tested"], [])
        self.assertNotIn("qa-oauth-code", str(result))
        self.assertNotIn("qa-oauth-state", str(result))
        fetch.assert_not_called()

    def test_structured_report_credentials_are_removed(self):
        safe = _report_safe({"credentials": "raw-credential", "bearer": "raw-token", "api_key": "raw-key", "label": "safe"})
        self.assertEqual(safe, {"label": "safe"})

    def test_service_upsert_and_asset_relationships_are_deduplicated(self):
        self.context.database.upsert_asset(self.context.project_id, "example.com", "LIVE", {"source": "fixture"})
        values = (self.context.project_id, "example.com", "192.0.2.8", 443, "tcp", "open", "https", "", {})
        self.assertTrue(self.context.database.upsert_service(*values))
        self.assertFalse(self.context.database.upsert_service(*values))
        self.context.database.add_asset_relation(self.context.project_id, "host", "example.com", "hosts", "ip", "192.0.2.8")
        self.context.database.add_asset_relation(self.context.project_id, "host", "example.com", "hosts", "ip", "192.0.2.8")
        self.assertEqual(len(self.context.database.list_services(self.context.project_id)), 1)
        self.assertEqual(len(self.context.database.list_asset_relations(self.context.project_id)), 1)

    def test_report_generation_is_redacted(self):
        self.context.findings.add(Finding(
            title="Potential secret exposure",
            category="Exposure",
            target="https://example.com/",
            description="password=supersecretvalue should not appear",
            evidence="token=anothersecretvalue",
            researcher_notes="api_key=researcher-secret-value",
            status="NEEDS_REVIEW",
        ))
        self.context.database.upsert_service(self.context.project_id, "example.com", "192.0.2.10", 443, "tcp", "open", "https", "", {"source":"test"})
        self.context.database.upsert_technology(self.context.project_id, "example.com", "ExampleFramework", "framework", "LOW", "test", "X-Framework header observed")
        json_path = generate_report(self.context, "json", self.root / "report.json")
        html_path = generate_report(self.context, "html", self.root / "report.html")
        data = json.loads(json_path.read_text(encoding="utf-8"))
        html = html_path.read_text(encoding="utf-8")
        self.assertEqual(data["executive_summary"]["automated_detections_needing_review"], 1)
        self.assertIn("AUTOMATED DETECTION", html)
        self.assertIn("Services", html)
        self.assertIn("Technologies", html)
        self.assertIn("Researcher Notes", html)
        self.assertNotIn("supersecretvalue", json_path.read_text(encoding="utf-8"))
        self.assertNotIn("anothersecretvalue", html)
        self.assertNotIn("researcher-secret-value", json_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
