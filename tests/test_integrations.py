from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nikhil_ai_modules.context import build_context
from nikhil_ai_modules.integrations.base import integration_status, run_bounded
from nikhil_ai_modules.integrations.nmap_adapter import run_nmap_safe
from nikhil_ai_modules.scope import ScopeError


class IntegrationTests(unittest.TestCase):
    def test_bounded_subprocess_caps_output_and_uses_argument_vectors(self):
        code, stdout, stderr = run_bounded(
            [sys.executable, "-c", "print('x' * 10000); print('safe stderr', file=__import__('sys').stderr)"],
            timeout=5,
            max_output=64,
        )
        self.assertEqual(code, 0)
        self.assertIn("stdout truncated", stdout)
        self.assertLess(len(stdout), 180)
        self.assertIn("safe stderr", stderr)
        with self.assertRaises(ValueError):
            run_bounded("python -c 'print(1)'" )

    def test_bounded_subprocess_times_out(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            run_bounded([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1, max_output=64)

    def test_unavailable_tools_are_reported_without_execution(self):
        with patch("nikhil_ai_modules.integrations.base.shutil.which", return_value=None):
            status = integration_status({"enabled_integrations": {"nmap": True}})
        self.assertEqual(len(status), 8)
        self.assertTrue(all(not item["installed"] for item in status))
        self.assertTrue(next(item for item in status if item["key"] == "nmap")["enabled"])

    def test_nmap_requires_enabled_adapter_and_explicit_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = build_context(config_path=root / "config.json", database_path=root / "db.sqlite3")
            context.scope.add_target("127.0.0.1/32")
            with patch("nikhil_ai_modules.integrations.nmap_adapter.run_bounded", side_effect=AssertionError("must not execute")):
                with self.assertRaises(ScopeError):
                    run_nmap_safe(context, "127.0.0.1", confirmed_authorization=True)
                context.config["enabled_integrations"] = {"nmap": True}
                with self.assertRaises(ScopeError):
                    run_nmap_safe(context, "127.0.0.1", confirmed_authorization=False)


if __name__ == "__main__":
    unittest.main()
