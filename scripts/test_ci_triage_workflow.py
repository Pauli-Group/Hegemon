"""Offline checks for the dispatch and secret boundaries of the RP05 triage pilot."""

import json
from pathlib import Path
import subprocess
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci-failure-triage.yml"
KEY = "HEGEMON_CI_TRIAGE_OPENAI_API_KEY"


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ruby ships Psych on both macOS and GitHub's Ubuntu runners. YAML 1.1
        # parses an unquoted 'on' key as true, which JSON spells "true".
        parsed = subprocess.check_output(
            ["ruby", "-ryaml", "-rjson", "-e",
             "puts JSON.generate(YAML.safe_load(File.read(ARGV.fetch(0))))", str(WORKFLOW)],
            text=True,
        )
        cls.workflow = json.loads(parsed)
        cls.jobs = cls.workflow["jobs"]

    def test_manual_dispatch_only(self):
        triggers = self.workflow.get("on", self.workflow.get("true"))
        self.assertEqual(set(triggers), {"workflow_dispatch"})
        inputs = triggers["workflow_dispatch"]["inputs"]
        self.assertEqual(set(inputs), {"mode", "run_id"})
        self.assertEqual(inputs["mode"]["type"], "choice")
        self.assertEqual(set(inputs["mode"]["options"]), {"run", "smoke"})
        self.assertEqual(inputs["run_id"]["type"], "string")

    def test_forks_prs_other_refs_and_empty_findings_are_excluded(self):
        self.assertEqual(set(self.jobs), {"collect", "report"})
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                guard = job["if"].strip().removeprefix("${{").removesuffix("}}").strip()
                required = {
                    "github.event_name == 'workflow_dispatch'",
                    "github.repository == 'Pauli-Group/Hegemon'",
                    "github.ref == 'refs/heads/main'",
                }
                if name == "report":
                    required.add("needs.collect.outputs.finding != ''")
                terms = {" ".join(term.split()) for term in guard.split("&&")}
                self.assertTrue(required <= terms)
                optional = {"github.ref_type == 'branch'"}
                if name == "report":
                    optional.add("needs.collect.result == 'success'")
                self.assertTrue(terms <= required | optional)
        self.assertIn(self.jobs["report"]["needs"], ("collect", ["collect"]))

    def test_read_only_token_and_trusted_checkout(self):
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                permissions = job.get("permissions", self.workflow.get("permissions"))
                expected = {"contents": "read"}
                if name == "collect":
                    expected["actions"] = "read"
                self.assertEqual(permissions, expected)
                self.assertEqual(job["runs-on"], "ubuntu-latest")
                actions = [step for step in job["steps"] if "uses" in step]
                self.assertEqual(len(actions), 1)
                self.assertRegex(actions[0]["uses"], r"^actions/checkout@[0-9a-f]{40}$")
                settings = actions[0]["with"]
                self.assertEqual(settings["ref"], "${{ github.sha }}")
                self.assertIn(settings["persist-credentials"], (False, "false"))
                self.assertNotIn("repository", settings)
                for step in job["steps"]:
                    self.assertNotIn("${{", step.get("run", ""))

    def test_environment_key_is_available_only_to_the_report_step(self):
        self.assertNotIn("environment", self.jobs["collect"])
        report = self.jobs["report"]
        self.assertEqual(report["environment"], {"name": "ci-triage-main", "deployment": False})
        # The only reference to the secret in the entire document belongs to
        # the fixed executable on a fresh runner with a trusted checkout.
        secret = "${{ secrets." + KEY + " }}"
        self.assertEqual(json.dumps(self.workflow).lower().count("secrets"), 1)
        keyed = [step for step in report["steps"] if step.get("env", {}).get(KEY) == secret]
        self.assertEqual(len(keyed), 1)
        self.assertEqual(keyed[0]["run"].strip(), "python3 -I -B scripts/ci_triage_report.py")
        self.assertEqual(keyed[0]["env"]["TRIAGE_FINDING"], "${{ needs.collect.outputs.finding }}")


if __name__ == "__main__":
    unittest.main()
