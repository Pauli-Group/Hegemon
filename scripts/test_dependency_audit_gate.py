#!/usr/bin/env python3
"""Regression tests for dependency-audit finding classification and waiver handling."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "dependency-audit-gate.sh"


def package(name: str = "sample", version: str = "1.2.3") -> dict:
    return {"name": name, "version": version}


def vulnerability(advisory_id: str = "RUSTSEC-2099-0001") -> dict:
    return {
        "advisory": {"id": advisory_id, "title": "Synthetic vulnerability"},
        "package": package(),
    }


def valid_waiver(kind: str, advisory_id: str) -> dict:
    return {
        "id": advisory_id,
        "package": "sample",
        "version": "1.2.3",
        "kind": kind,
        "expires": "2099-01-01",
        "tracking": "DEP-2099-0001",
        "reason": "Synthetic exact waiver for gate regression coverage.",
        "owner": "release-engineering",
        "reviewed_at": "2026-10-01",
        "remediation": "Remove the synthetic fixture after this test.",
    }


class DependencyAuditGateTests(unittest.TestCase):
    def run_gate(self, audit: dict, waivers: list[dict] | None = None):
        with tempfile.TemporaryDirectory(prefix="dependency-audit-test-") as temp:
            temp_path = Path(temp)
            audit_path = temp_path / "audit.json"
            policy_path = temp_path / "policy.json"
            audit_path.write_text(json.dumps(audit), encoding="utf-8")
            policy_path.write_text(
                json.dumps({"schema": 1, "waivers": waivers or []}),
                encoding="utf-8",
            )
            return subprocess.run(
                [
                    "bash",
                    str(GATE),
                    "--audit-json",
                    str(audit_path),
                    "--policy",
                    str(policy_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

    @staticmethod
    def audit(vulnerabilities: list[dict] | None = None, warnings: dict | None = None):
        return {
            "vulnerabilities": {"list": vulnerabilities or []},
            "warnings": warnings or {},
        }

    def test_unwaived_vulnerability_fails(self):
        result = self.run_gate(self.audit([vulnerability()]))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("unwaived dependency audit blockers", result.stdout)

    def test_exact_current_vulnerability_waiver_is_honored(self):
        result = self.run_gate(
            self.audit([vulnerability()]),
            [valid_waiver("vulnerability", "RUSTSEC-2099-0001")],
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("waived vulnerability RUSTSEC-2099-0001", result.stdout)

    def test_unwaived_yanked_crate_fails(self):
        audit = self.audit(warnings={"yanked": [{"package": package()}]})
        result = self.run_gate(audit)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("unwaived dependency audit blockers", result.stdout)

    def test_unwaived_unsound_finding_fails(self):
        audit = self.audit(
            warnings={
                "unsound": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2099-0004",
                            "title": "Synthetic unsoundness finding",
                        },
                        "package": package(),
                    }
                ]
            }
        )
        result = self.run_gate(audit)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("unsound RUSTSEC-2099-0004", result.stdout)

    def test_exact_current_yanked_waiver_is_honored(self):
        audit = self.audit(warnings={"yanked": [{"package": package()}]})
        result = self.run_gate(audit, [valid_waiver("yanked", "yanked:sample:1.2.3")])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("waived yanked yanked:sample:1.2.3", result.stdout)

    def test_unmaintained_is_reported_but_nonblocking(self):
        audit = self.audit(
            warnings={
                "unmaintained": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2099-0002",
                            "title": "Synthetic maintenance notice",
                        },
                        "package": package("legacy", "0.4.0"),
                    }
                ]
            }
        )
        result = self.run_gate(audit)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("maintenance notice (nonblocking)", result.stdout)
        self.assertIn("legacy 0.4.0", result.stdout)

    def test_unmaintained_waiver_is_rejected_as_unused(self):
        audit = self.audit(warnings={"unmaintained": [{"package": package()}]})
        result = self.run_gate(
            audit,
            [valid_waiver("unmaintained", "RUSTSEC-2099-0003")],
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("unused dependency audit waivers", result.stdout)

    def test_unknown_warning_kind_fails_closed(self):
        audit = self.audit(warnings={"future-warning-kind": []})
        result = self.run_gate(audit)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("unknown cargo audit warning kind; failing closed", result.stderr)


if __name__ == "__main__":
    unittest.main()
