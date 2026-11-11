import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
import zipfile

from n8n_lint.cli import main
from n8n_lint.formatters import format_report
from n8n_lint.redact import redact_workflow_data
from n8n_lint.rules import lint_workflow_data
from scripts.build_release import build_release_zip
from tests.test_rules import _clean_workflow


class TestFormattersAndRedact(unittest.TestCase):
    def test_format_report_outputs_valid_json_sarif_markdown_and_text(self) -> None:
        wf = _clean_workflow()
        wf["settings"] = {}
        findings = lint_workflow_data(wf, "wf.json")
        self.assertEqual(len(findings), 1)

        json_out = json.loads(format_report(findings, files_scanned=1, fmt="json"))
        self.assertEqual(json_out["summary"]["warnings"], 1)
        self.assertEqual(json_out["summary"]["errors"], 0)
        self.assertEqual(json_out["findings"][0]["rule_id"], "REL002")

        sarif_out = json.loads(format_report(findings, files_scanned=1, fmt="sarif"))
        self.assertEqual(sarif_out["version"], "2.1.0")
        self.assertEqual(sarif_out["runs"][0]["tool"]["driver"]["name"], "n8n-lint")
        self.assertEqual(sarif_out["runs"][0]["results"][0]["ruleId"], "REL002")

        md_out = format_report(findings, files_scanned=1, fmt="markdown")
        self.assertIn("REL002", md_out)
        self.assertNotIn("\u2014", md_out)

        text_out = format_report(findings, files_scanned=1, fmt="text", use_color=False)
        self.assertIn("REL002", text_out)
        self.assertIn("wf.json", text_out)

    def test_redact_workflow_scrubs_secrets_pindata_and_credential_ids(self) -> None:
        wf = _clean_workflow()
        wf["active"] = True
        wf["pinData"] = {"Webhook Trigger": [{"json": {"email": "alice@clientcorp.com"}}]}
        wf["nodes"][2]["parameters"]["apiKey"] = "sk-ant-api03-secretvalue1234567890"
        wf["nodes"][2]["parameters"]["headerParameters"] = {
            "parameters": [{"name": "Authorization", "value": "Bearer live-secret-token-9999"}]
        }
        redacted = redact_workflow_data(wf, deactivate=True)

        # Original object must remain untouched
        self.assertTrue(wf["active"])
        self.assertIn("Webhook Trigger", wf["pinData"])

        self.assertFalse(redacted["active"])
        self.assertEqual(redacted["pinData"], {})
        self.assertEqual(
            redacted["nodes"][2]["credentials"]["httpHeaderAuth"]["id"],
            "__SCRUBBED_CREDENTIAL_ID__",
        )
        self.assertEqual(
            redacted["nodes"][2]["credentials"]["httpHeaderAuth"]["name"],
            "CRM Auth",
        )
        self.assertEqual(redacted["nodes"][2]["parameters"]["apiKey"], "__REDACTED__")
        self.assertEqual(
            redacted["nodes"][2]["parameters"]["headerParameters"]["parameters"][0]["value"],
            "__REDACTED__",
        )
        post_findings = lint_workflow_data(redacted, "redacted.json")
        self.assertFalse(any(f["rule_id"] in {"SEC001", "SEC002", "SEC003"} for f in post_findings))

    def test_redact_deactivate_always_sets_active_false_and_disarms_schedule_nodes(self) -> None:
        wf = _clean_workflow()
        wf.pop("active", None)
        wf["nodes"].append(
            {
                "id": "n6",
                "name": "Morning Schedule",
                "type": "n8n-nodes-base.scheduleTrigger",
                "typeVersion": 1.2,
                "position": [100, 400],
                "parameters": {},
            }
        )
        wf["nodes"].append(
            {
                "id": "n7",
                "name": "Legacy Cron",
                "type": "n8n-nodes-base.CRON",
                "typeVersion": 1,
                "position": [100, 520],
                "parameters": {},
            }
        )

        untouched = redact_workflow_data(wf, deactivate=False)
        self.assertNotIn("active", untouched)
        self.assertNotIn("disabled", untouched["nodes"][5])
        self.assertNotIn("disabled", untouched["nodes"][6])

        deactivated = redact_workflow_data(wf, deactivate=True)
        self.assertIs(deactivated["active"], False)
        self.assertIs(deactivated["nodes"][5]["disabled"], True)
        self.assertIs(deactivated["nodes"][6]["disabled"], True)
        self.assertNotIn("disabled", deactivated["nodes"][0])
        self.assertNotIn("active", wf)
        self.assertNotIn("disabled", wf["nodes"][5])


class TestCliBehavior(unittest.TestCase):
    def test_cli_scan_clean_broken_strict_ignore_and_redact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            clean_path = tmp_dir / "clean.json"
            clean_path.write_text(json.dumps(_clean_workflow()), encoding="utf-8")

            warn_wf = _clean_workflow()
            warn_wf["settings"] = {}
            warn_path = tmp_dir / "warn.json"
            warn_path.write_text(json.dumps(warn_wf), encoding="utf-8")

            broken_wf = _clean_workflow()
            broken_wf["nodes"][0]["parameters"]["authentication"] = "none"
            broken_path = tmp_dir / "broken.json"
            broken_path.write_text(json.dumps(broken_wf), encoding="utf-8")

            sarif_out = tmp_dir / "out.sarif"
            redacted_out = tmp_dir / "redacted.json"

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc_clean = main(["scan", str(clean_path), "--no-color"])
            self.assertEqual(rc_clean, 0)

            with redirect_stdout(io.StringIO()):
                rc_warn_default = main(["scan", str(warn_path), "--no-color"])
                rc_warn_strict = main(["scan", str(warn_path), "--strict", "--no-color"])
                rc_warn_ignore = main(["scan", str(warn_path), "--strict", "--ignore", "REL002"])
            self.assertEqual(rc_warn_default, 0)
            self.assertEqual(rc_warn_strict, 1)
            self.assertEqual(rc_warn_ignore, 0)

            with redirect_stdout(io.StringIO()):
                rc_direct = main([str(broken_path), "--format", "sarif", "--output", str(sarif_out)])
            self.assertEqual(rc_direct, 1)
            self.assertEqual(json.loads(sarif_out.read_text(encoding="utf-8"))["version"], "2.1.0")

            with redirect_stdout(io.StringIO()):
                rc_redact = main(["redact", str(broken_path), "--output", str(redacted_out), "--deactivate"])
            self.assertEqual(rc_redact, 0)
            self.assertFalse(json.loads(redacted_out.read_text(encoding="utf-8"))["active"])

            rules_buf = io.StringIO()
            with redirect_stdout(rules_buf):
                rc_rules = main(["rules", "--json"])
            self.assertEqual(rc_rules, 0)
            self.assertGreaterEqual(len(json.loads(rules_buf.getvalue())), 25)

            with redirect_stderr(io.StringIO()):
                rc_missing = main(["scan", str(tmp_dir / "does-not-exist.json")])
            self.assertEqual(rc_missing, 2)

    def test_module_cli_subprocess_entrypoint(self) -> None:
        root = Path(__file__).resolve().parents[1]
        env = dict(os.environ)
        src_path = str(root / "src")
        env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else src_path
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "n8n_lint.cli",
                "scan",
                "examples/broken_workflow.json",
                "--format",
                "json",
            ],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertGreater(payload["summary"]["errors"], 0)


class TestPackagingAndHygiene(unittest.TestCase):
    def test_release_zip_and_no_hardcoded_user_paths(self) -> None:
        root = Path(__file__).resolve().parents[1]
        user_home_re = re.compile(r"(/home/[a-zA-Z0-9._-]+|/Users/[a-zA-Z0-9._-]+|C:\\\\Users\\\\[a-zA-Z0-9._-]+)")
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {".git", ".venv", "__pycache__", "dist", ".pytest_cache"} for part in path.parts):
                continue
            if path.suffix in {".py", ".md", ".sh", ".ps1", ".toml", ".yaml", ".yml", ".json"}:
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(user_home_re.search(text), f"Hardcoded user path in {path}")
                self.assertNotIn("\u2014", text, f"Em dash found in {path}")

        with tempfile.TemporaryDirectory() as tmp:
            built_zip, built_sha = build_release_zip(root, Path(tmp) / "n8n-lint-test.zip")
            built_sha_file = Path(f"{built_zip}.sha256")
            self.assertTrue(built_zip.exists())
            self.assertEqual(built_sha, built_sha_file.read_text(encoding="utf-8").split()[0])
            with zipfile.ZipFile(built_zip) as zf:
                names = zf.namelist()
                self.assertIn("n8n-lint/pyproject.toml", names)
                self.assertIn("n8n-lint/src/n8n_lint/cli.py", names)
                self.assertFalse(any("__pycache__" in n or "/dist/" in n or "/.venv/" in n for n in names))

        dist_zip = root / "dist" / "n8n-lint-v1.0.0.zip"
        sha_file = root / "dist" / "n8n-lint-v1.0.0.zip.sha256"
        if dist_zip.exists():
            self.assertTrue(sha_file.exists())
            actual_sha = hashlib.sha256(dist_zip.read_bytes()).hexdigest()
            recorded_sha = sha_file.read_text(encoding="utf-8").split()[0]
            self.assertEqual(actual_sha, recorded_sha)
