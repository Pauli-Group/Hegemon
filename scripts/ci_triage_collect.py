#!/usr/bin/env python3
"""Select one RP05 guard diagnostic without exporting any historical log text."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

REPO = "Pauli-Group/Hegemon"
WORKFLOW = ".github/workflows/rp05-proof.yml"
STEP = "Source/import/manifest and public claim guard (no Lean required)"
PROOF_STEP = "Cold project compilation, body audits, serial kernel replay"
PROOF_COMMAND = "python3 -I -B scripts/rp05_ci.py verify --cold --seconds 14400"
COMMAND = "python3 -I -B scripts/rp05_ci.py source"
JSON_BYTES = 262144
STEP_BYTES = 65536

# The two strings are the complete diagnostic and context allowed to leave this job.
FINDINGS = {
    "kernel_memory": ("[staged Lean source]:[line]:[column]: error: (kernel) excessive memory consumption detected",
                      "Lean reported its kernel memory limit during the cold RP05 proof step."),
    "source_hash": ("source hash mismatch for [module]: expected [digest], got [digest]",
                    "The RP05 source manifest pins the SHA-256 of each staged Lean source."),
    "source_tree": ("generated source tree contains missing or unmanifested Lean files",
                    "The guard compares the staged Lean file set with the manifest."),
    "import_closure": ("source/import closure changed",
                       "The guard compares the public roots' reachable modules and external imports with the manifest."),
    "public_roots": ("public roots changed", "The guard expects the four declared RP05 public roots."),
    "public_claim": ("public claim contract changed",
                     "The guard checks the public theorem and its endpoint module against the declared contract."),
    "wrapper_import": ("public wrapper import changed", "Each public wrapper must import its declared endpoint."),
    "wrapper_drift": ("public wrapper/staged source drift",
                      "The public wrapper and the staged copy must have the same SHA-256."),
    "toolchain_pin": ("toolchain/lock pin drift", "The source manifest pins Lean, the Lake project and its lockfile."),
    "supplemental_hash": ("supplemental source hash mismatch: [module]",
                          "The supplemental registry pins each additional Lean source by SHA-256."),
}


class Skipped(Exception):
    """Only fixed, public messages may be shown in the summary."""


def classify_diagnostic(line: str) -> str | None:
    prefix = "FAIL RP05 CI: "
    if not line.startswith(prefix):
        return None
    message = line[len(prefix):]
    module = r"[A-Za-z_][A-Za-z0-9_.]{0,255}"
    if re.fullmatch(rf"source hash mismatch for {module}: expected [a-f0-9]{{64}}, got [a-f0-9]{{64}}", message):
        return "source_hash"
    if re.fullmatch(rf"supplemental source hash mismatch: {module}", message):
        return "supplemental_hash"
    for code, (error, _) in FINDINGS.items():
        if code not in ("source_hash", "supplemental_hash", "kernel_memory") and error == message:
            return code
    return None


def github_read(path: str) -> bytes:
    limit = STEP_BYTES if path.endswith("/logs") else JSON_BYTES
    with subprocess.Popen(
        ["gh", "api", "--hostname", "github.com", "-H", "X-GitHub-Api-Version: 2026-03-10",
         f"repos/{REPO}/actions/{path}"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ) as process:
        try:
            data = process.stdout.read(limit + 1)
            if len(data) > limit:
                raise Skipped("The selected GitHub response exceeded the pilot size limit.")
            if process.wait() != 0:
                raise Skipped("GitHub could not return the run, its jobs, or the retained step log.")
            return data
        finally:
            if process.poll() is None:
                process.kill()


def metadata(data: bytes) -> dict:
    try:
        if len(data) <= JSON_BYTES:
            value = json.loads(data)
            if isinstance(value, dict):
                return value
    except (ValueError, RecursionError):
        pass
    raise Skipped("GitHub returned unreadable or oversized run metadata.")


def failed(record: dict) -> bool:
    return record.get("status") == "completed" and record.get("conclusion") == "failure"


def positive_id(value) -> bool:
    return type(value) is int and 0 < value < 10**20


def completed_record(records, name: str) -> dict:
    if isinstance(records, list):
        matches = [r for r in records if isinstance(r, dict) and r.get("name") == name]
        if len(matches) == 1 and matches[0].get("status") == "completed":
            return matches[0]
    raise Skipped("The selected attempt has no matching completed RP05 job or step.")


# Lean emits counters, tactic hints and axiom reports before a compiler error.
# Only skip the known forms. An earlier unknown line makes the evidence ambiguous.
LEAN_PROGRESS = re.compile(
    r"\[diag\] Diagnostics|  \[(?:reduction|kernel|def_eq)\] (?:unfolded (?:reducible )?declarations|"
    r"heuristic for solving `f a =\?= f b`) \(max: [0-9]+, num: [0-9]+\):|"
    r"    \[(?:reduction|kernel|def_eq)\] [^:\r\n]+ ↦ [0-9]+|"
    r"  use `set_option diagnostics.threshold <num>` to control threshold for reporting counters|"
    r"Try this:|  \[apply\] (?:ring_nf|abel_nf)|"
    r"  The `ring` tactic failed to close the goal\. Use `ring_nf` to obtain a normal form\.|"
    r"  Note that `ring` works primarily in \*commutative\* rings\. If you have a noncommutative ring, "
    r"abelian group or module, consider using `noncomm_ring`, `abel` or `module` instead\.|"
    r"'[\w.]+' depends on axioms: \[propext,| Classical\.choice,| Quot\.sound\]"
)
KERNEL_ERROR = re.compile(
    r"/home/runner/work/Hegemon/Hegemon/formal/rp05/generated/Sources/(?:[A-Za-z_][A-Za-z0-9_]*/)*"
    r"[A-Za-z_][A-Za-z0-9_]*\.lean:[0-9]{1,8}:[0-9]{1,8}: error: \(kernel\) excessive memory consumption detected"
)


def first_diagnostic(log: bytes, command: str) -> str:
    if len(log) > STEP_BYTES:
        raise Skipped("The selected step log exceeded the pilot size limit.")
    records = [re.sub(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ", "", line) for line in
               log.decode("utf-8-sig", errors="replace").splitlines()]
    if records and records[0] == f"##[group]Run {command}" and "##[endgroup]" in records:
        for line in records[records.index("##[endgroup]") + 1:]:
            if not line.strip():
                continue
            if command == PROOF_COMMAND:
                if LEAN_PROGRESS.fullmatch(line):
                    continue
                if KERNEL_ERROR.fullmatch(line):
                    return "kernel_memory"
            else:
                finding = classify_diagnostic(line)
                if finding:
                    return finding
            break
    raise Skipped("The first substantive diagnostic of the selected step was unavailable or unrecognized.")


def bound_job(jobs: list, name: str, run: dict) -> dict:
    job = completed_record(jobs, name)
    if (not positive_id(job.get("id")) or job.get("run_id") != run["id"]
            or job.get("run_attempt") != run["run_attempt"] or job.get("head_sha") != run["head_sha"]):
        raise Skipped("The job could not be bound to the selected run attempt.")
    return job


def collect(run_id: str, fetch=github_read, *, summary=None) -> str:
    if not re.fullmatch(r"[1-9][0-9]{0,19}", run_id):
        raise Skipped("Enter a positive numeric Actions run ID.")
    run = metadata(fetch(f"runs/{run_id}"))
    attempt = run.get("run_attempt")
    sha = run.get("head_sha")
    repo = run.get("repository")
    head = run.get("head_repository")
    if not (isinstance(repo, dict) and repo.get("full_name") == REPO and repo.get("private") is False
            and isinstance(head, dict) and head.get("full_name") == REPO
            and run.get("id") == int(run_id) and positive_id(attempt) and isinstance(sha, str)
            and re.fullmatch("[0-9a-f]{40}", sha) and run.get("head_branch") == "main"
            and run.get("event") in ("push", "schedule", "workflow_dispatch")
            and run.get("path") == WORKFLOW and failed(run)):
        raise Skipped("The supplied run must be a completed failed RP05 run on the public repository's main branch, from a push, schedule, or manual dispatch.")
    jobs = metadata(fetch(f"runs/{run_id}/attempts/{attempt}/jobs?per_page=100"))
    records = jobs.get("jobs")
    if not isinstance(records, list) or jobs.get("total_count") != len(records):
        raise Skipped("GitHub returned an incomplete list of jobs for this attempt.")
    job = bound_job(records, "source", run)
    step = completed_record(job.get("steps"), STEP)
    command = COMMAND
    if job.get("conclusion") == "success" and step.get("conclusion") == "success":
        job = bound_job(records, "proof", run)
        step = completed_record(job.get("steps"), PROOF_STEP)
        command = PROOF_COMMAND
    if not (failed(job) and failed(step) and positive_id(step.get("number"))):
        raise Skipped("The selected attempt has no matching failed RP05 source guard or cold proof step.")
    job_id, number = job["id"], step["number"]
    finding = first_diagnostic(fetch(f"jobs/{job_id}/steps/{number}/logs"), command)
    if summary is not None:
        url = f"https://github.com/{REPO}/actions/runs/{run_id}/job/{job_id}#step:{number}:1"
        summary.write(f"Source evidence from [RP05 run {run_id}, attempt {attempt}, failed {job['name']} step]({url}).\n")
    return finding


def smoke_finding() -> str:
    """Run the real guard on a disposable copy with one stale staged Lean source."""
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "scripts").mkdir()
        for name in ("rp05_ci.py", "rp05_proof_package.py"):
            shutil.copyfile(repo / "scripts" / name, root / "scripts" / name)
        package = Path("formal/rp05")
        shutil.copytree(repo / package / "generated/Sources", root / package / "generated/Sources")
        shutil.copyfile(repo / package / "source-manifest.json", root / package / "source-manifest.json")
        with (root / package / "generated/Sources/Rp05/Privacy.lean").open("ab") as staged:
            staged.write(b"\n-- CI triage smoke fixture\n")
        result = subprocess.run(
            [sys.executable, "-I", "-B", "scripts/rp05_ci.py", "source"],
            cwd=root, env={}, capture_output=True, text=True, timeout=60, check=False,
        )
    diagnostic = result.stderr.strip()
    if (result.returncode != 1 or classify_diagnostic(diagnostic) != "source_hash"
            or not diagnostic.startswith("FAIL RP05 CI: source hash mismatch for Rp05.Privacy:")):
        raise Skipped("The smoke fixture did not produce its expected diagnostic.")
    return "source_hash"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        finding = ""
        try:
            if args.smoke:
                finding = smoke_finding()
                summary.write("Smoke fixture reproduced a source hash mismatch in a temporary copy of the RP05 package.\n")
            else:
                finding = collect(os.getenv("TRIAGE_RUN_ID", ""), summary=summary)
        except Skipped as reason:
            summary.write(f"RP05 triage skipped. {reason}\n")
        except (OSError, subprocess.SubprocessError):
            summary.write("RP05 triage skipped. Evidence collection was unavailable.\n")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"finding={finding}\n")


if __name__ == "__main__":
    main()
