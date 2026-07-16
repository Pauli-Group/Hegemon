#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_ci_release_gate_policy as policy


def fixture(run: str, condition: str | None = None) -> str:
    condition_line = "" if condition is None else f"        if: {condition}\n"
    indented = "\n".join(f"          {line}" for line in run.splitlines())
    return (
        "jobs:\n"
        "  release-build:\n"
        "    steps:\n"
        "      - name: Gate\n"
        f"{condition_line}"
        "        run: |\n"
        f"{indented}\n"
    )


def expect_missing(workflow: str) -> None:
    try:
        policy.require_executable_command(
            "fixture",
            policy.workflow_steps(workflow, "release-build"),
            "scripts/security-audit.sh",
            ("--require-binary",),
        )
    except SystemExit:
        return
    raise SystemExit("non-executable workflow text unexpectedly satisfied the gate")


def main() -> None:
    expect_missing(fixture("# ./scripts/security-audit.sh --require-binary"))
    expect_missing(fixture("echo ./scripts/security-audit.sh --require-binary"))
    expect_missing(
        fixture("./scripts/security-audit.sh --require-binary", condition="false")
    )
    expect_missing(fixture("false && ./scripts/security-audit.sh --require-binary"))
    expect_missing(fixture("./scripts/security-audit.sh --require-binary || true"))
    expect_missing(fixture("./scripts/security-audit.sh --require-binary; true"))
    expect_missing(fixture("./scripts/security-audit.sh --help # --require-binary"))
    expect_missing(fixture("./scripts/security-audit.sh --require-binary --help"))
    expect_missing(
        fixture("if true; then ./scripts/security-audit.sh --require-binary; fi")
    )
    expect_missing(
        fixture("./scripts/security-audit.sh --require-binary\ntrue")
    )
    expect_missing(
        fixture(
            "./scripts/security-audit.sh --require-binary",
            condition="${{ github.event_name == 'pull_request' }}",
        )
    )

    steps = policy.workflow_steps(
        fixture(
            "set -euo pipefail\n"
            "./scripts/security-audit.sh \\\n"
            "  --require-binary"
        ),
        "release-build",
    )
    index = policy.require_executable_command(
        "fixture", steps, "scripts/security-audit.sh", ("--require-binary",)
    )
    if index != 0:
        raise SystemExit("valid executable workflow step was not identified")
    cargo_steps = policy.workflow_steps(
        fixture("cargo install cargo-audit --version 0.22.2 --locked"),
        "release-build",
    )
    policy.require_executable_command(
        "fixture cargo pin",
        cargo_steps,
        "cargo",
        ("install", "cargo-audit", "--version", "0.22.2", "--locked"),
    )
    try:
        policy.require_step_order("fixture", 2, 1)
    except SystemExit:
        pass
    else:
        raise SystemExit("out-of-order workflow steps unexpectedly passed")
    policy.require_job_env_literal(
        "fixture env",
        '    env:\n      HEGEMON_TIMING_SAMPLE_COUNT: "16"\n    steps:\n',
        "HEGEMON_TIMING_SAMPLE_COUNT",
        "16",
    )
    for invalid_env in (
        '    # HEGEMON_TIMING_SAMPLE_COUNT: "16"\n    steps:\n',
        '    steps:\n      - env:\n          HEGEMON_TIMING_SAMPLE_COUNT: "16"\n',
        '    env:\n      HEGEMON_TIMING_SAMPLE_COUNT: "15"\n    steps:\n',
    ):
        try:
            policy.require_job_env_literal(
                "fixture env",
                invalid_env,
                "HEGEMON_TIMING_SAMPLE_COUNT",
                "16",
            )
        except SystemExit:
            pass
        else:
            raise SystemExit("invalid timing environment unexpectedly passed")
    print("CI/release executable-step policy negative tests passed")


if __name__ == "__main__":
    main()
