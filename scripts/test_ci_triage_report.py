#!/usr/bin/env python3
"""Run offline with python3 -I -B scripts/test_ci_triage_report.py."""

import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_triage_report as report


def api_response(text):
    return json.dumps({
        "status": "completed",
        "output": [{"type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": text}]}],
    }).encode()


class ReportTests(unittest.TestCase):
    key = "dummy-ci-key"

    def setUp(self):
        mock_tls = patch.object(report.http.client, "HTTPSConnection")
        self.connect = mock_tls.start()
        self.addCleanup(mock_tls.stop)
        self.connection = self.connect.return_value
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.read.return_value = api_response("The staged Lean source may have changed.")

    def assert_evidence(self, summary):
        error, context = report.FINDINGS["source_hash"]
        self.assertIn("    " + error, summary)
        self.assertIn(context, summary)
        self.assertIn(report.COMMAND, summary)
        self.assertEqual(summary.count("**Suggested verification**"), 1)
        self.assertNotIn(self.key, summary)

    def test_one_direct_bounded_request_with_only_canonical_evidence(self):
        summary = report.summary("run", "source_hash", self.key)
        self.assert_evidence(summary)
        self.assertIn("Model interpretation (tentative)\n\n    The staged Lean source", summary)
        self.connect.assert_called_once_with("api.openai.com", timeout=20)
        self.connection.request.assert_called_once()
        request = self.connection.request.call_args
        self.assertEqual(request.args, ("POST", "/v1/responses"))
        self.assertEqual(request.kwargs["headers"]["Authorization"], "Bearer " + self.key)
        self.assertNotIn(self.key, request.kwargs["body"])
        self.assertLess(len(request.kwargs["body"]), 2048)
        body = json.loads(request.kwargs["body"])
        self.assertEqual(body["model"], "gpt-6-luna")
        self.assertIs(body["store"], False)
        self.assertEqual(body["reasoning"], {"effort": "none"})
        self.assertLessEqual(body["max_output_tokens"], 128)
        self.assertFalse(body.get("tools"))
        error, context = report.FINDINGS["source_hash"]
        self.assertEqual(json.loads(body["input"]), {
            "command": report.COMMAND, "first_error": error, "context": context,
        })
        self.response.read.assert_called_once_with(report.MAX_RESPONSE_BYTES + 1)
        self.connection.close.assert_called_once()

    def test_cold_kernel_failure_uses_proof_command_and_read_only_log_verification(self):
        result = report.summary("run", "kernel_memory", self.key)
        error, context = report.FINDINGS["kernel_memory"]
        evidence = json.loads(json.loads(self.connection.request.call_args.kwargs["body"])["input"])
        self.assertEqual(evidence, {"command": report.PROOF_COMMAND, "first_error": error, "context": context})
        self.assertIn(f"    {report.PROOF_COMMAND}\n", result)
        self.assertIn(error, result)
        self.assertIn(context, result)
        self.assertNotIn(report.COMMAND, result)
        self.assertEqual(result.count("**Suggested verification**"), 1)
        check = result.split("**Suggested verification**")[1]
        self.assertIn("Inspect the first Lean error", check)
        self.assertNotIn("scripts/", check)

    def test_cli_missing_project_key_ignores_unrelated_keys_and_appends_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.md"
            path.write_text("Earlier step\n")
            with patch.dict(os.environ, {
                "TRIAGE_MODE": "smoke", "TRIAGE_FINDING": "source_hash",
                "GITHUB_STEP_SUMMARY": str(path), "OPENAI_API_KEY": "some-other-key",
            }, clear=True):
                runpy.run_path(report.__file__, run_name="__main__")
            summary = path.read_text()
        self.assert_evidence(summary)
        self.assertTrue(summary.startswith("Earlier step\n"))
        self.assertIn("synthetic smoke fixture", summary)
        self.assertIn("key is missing", summary)
        self.assertNotIn("some-other-key", summary)
        self.connect.assert_not_called()

    def test_unknown_finding_or_mode_and_invalid_header_make_no_request(self):
        canary = "untrusted-secret-payload"
        for mode, finding in [("run", canary), (canary, "source_hash"), ("smoke", "kernel_memory")]:
            result = report.summary(mode, finding, self.key)
            self.assertIn("unsupported", result)
            self.assertNotIn(canary, result)
        self.assertIn("malformed", report.summary("run", "source_hash", self.key + "\n"))
        self.connect.assert_not_called()

    def test_quota_http_error_or_redirect_never_retries_or_reads_error_body(self):
        for status in (302, 401, 403, 429, 500):
            with self.subTest(status=status):
                self.connection.request.reset_mock()
                self.response.status = status
                result = report.summary("run", "source_hash", self.key)
                self.assertIn(f"HTTP {status}", result)
                self.assert_evidence(result)
                self.connection.request.assert_called_once()
                self.response.read.assert_not_called()

    def test_transport_failure_keeps_evidence_and_hides_exception(self):
        self.connection.request.side_effect = TimeoutError("provider echoed " + self.key)
        result = report.summary("run", "source_hash", self.key)
        self.assert_evidence(result)
        self.assertIn("could not be completed", result)
        self.connection.request.assert_called_once()

    def test_malformed_incomplete_refused_empty_and_oversize_responses(self):
        malformed = [
            b"!", b"[]", b'{"status":"incomplete"}',
            b'{"status":"completed","output":[{"type":"function_call","name":"shell"}]}',
            b'{"status":"completed","output":[{"type":"message","role":"assistant","status":"completed",'
            b'"content":[{"type":"refusal","refusal":"cannot explain"}]}]}',
            b"x" * (report.MAX_RESPONSE_BYTES + 1), api_response(""), api_response("x" * 481),
        ]
        for response in malformed:
            with self.subTest(response=response[:32]):
                self.response.read.return_value = response
                result = report.summary("run", "source_hash", self.key)
                self.assertIn(report.UNAVAILABLE, result)
                self.assert_evidence(result)

    def test_suppresses_credentials_links_and_format_controls(self):
        for value in (self.key, "sk-proj-not-real", "github_pat_fake", "Bearer a-token",
                      "password=hunter2", "contact someone@example.test", "https://example.test",
                      "untrusted\u202econtrol"):
            with self.subTest(value=value):
                self.response.read.return_value = api_response(value)
                result = report.summary("run", "source_hash", self.key)
                self.assertIn(report.UNAVAILABLE, result)
                self.assertNotIn(value, result)

    def test_model_markdown_and_html_remain_inside_one_code_block(self):
        self.response.read.return_value = api_response("Guard failed.\n\n```\n### Fake\n</pre>")
        result = report.summary("run", "source_hash", self.key)
        self.assertIn("\n\n    Guard failed. ``` ### Fake </pre>\n\n", result)
        self.assertNotIn("\n### Fake", result)


if __name__ == "__main__":
    unittest.main()
