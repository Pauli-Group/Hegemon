#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
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
    python_step = policy.workflow_steps(fixture("python3 -B scripts/test_windows_testnet_launcher.py"), "release-build")[0]
    if not policy.step_executes_command(python_step, "scripts/test_windows_testnet_launcher.py"):
        raise SystemExit("reviewed python3 -B script invocation was not recognized")
    for command in ("python3 -c scripts/test_windows_testnet_launcher.py",
                    "python3 -m scripts/test_windows_testnet_launcher.py",
                    "python3 -B -c scripts/test_windows_testnet_launcher.py"):
        step = policy.workflow_steps(fixture(command), "release-build")[0]
        if policy.step_executes_command(step, "scripts/test_windows_testnet_launcher.py"):
            raise SystemExit("alternate Python interpreter mode satisfied runtime gate")
    for ignored in ("true", "${{ github.event_name == 'push' }}"):
        text = fixture("./scripts/security-audit.sh --require-binary").replace(
            "        run: |", f"        continue-on-error: {ignored}\n        run: |")
        expect_missing(text)
    false_text = fixture("./scripts/security-audit.sh --require-binary").replace(
        "        run: |", "        continue-on-error: false\n        run: |")
    policy.require_executable_command("explicit false", policy.workflow_steps(false_text, "release-build"),
                                      "scripts/security-audit.sh", ("--require-binary",))

    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    def check_text(text: str, expected_failure: str | None = None) -> None:
        with tempfile.TemporaryDirectory(prefix="hegemon-ci-release-policy-") as raw:
            path = Path(raw) / "release.yml"
            path.write_text(text)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    policy.check_release_workflow(path)
            except SystemExit as error:
                if expected_failure is None or expected_failure not in str(error):
                    raise
            else:
                if expected_failure is not None:
                    raise SystemExit("required release gate omission unexpectedly accepted: " + expected_failure)
    check_text(workflow)
    for script in ("scripts/check_release_launcher_policy.py", "scripts/test_check_release_launcher_policy.py",
                   "scripts/test_release_launcher_boundaries.py", "scripts/test_check_ci_release_gate_policy.py",
                   "scripts/test_windows_testnet_launcher.py"):
        command = "run: python3 -B " + script
        if workflow.count(command) != 1:
            raise SystemExit("required runtime/source gate fixture must occur once: " + script)
        check_text(workflow.replace(command, "run: echo " + script), "executable command")
        check_text(workflow.replace(command, "continue-on-error: true\n        " + command), "executable command")
    check_text(workflow.replace("runs-on: windows-latest", "runs-on: ubuntu-latest"), "native windows-latest")
    check_text(workflow.replace("run: python3 scripts/package_testnet_downloads.py",
                               "run: echo scripts/package_testnet_downloads.py"), "verified testnet download packaging")
    check_text(workflow.replace('--launchers-dir testnet-release --version "${GITHUB_REF_NAME#v}"',
                               '--launchers-dir other --version "${GITHUB_REF_NAME#v}"'), "verified testnet download packaging")
    check_text(workflow.replace('--version "${GITHUB_REF_NAME#v}"', '--version "0.10.2"'),
               "verified testnet download packaging")
    check_text(workflow.replace("needs: [build-linux, build-macos-intel, build-macos-arm, build-windows]",
                               "needs: [build-linux, build-macos-intel, build-macos-arm]"), "depend on the Windows")
    check_text(workflow.replace("      - name: Package user testnet downloads from verified assets",
                               "      - name: Package user testnet downloads from verified assets\n        continue-on-error: true"),
               "verified testnet download packaging")
    package_step = ('      - name: Package user testnet downloads from verified assets\n'
                    '        run: python3 scripts/package_testnet_downloads.py --assets-dir release-assets '
                    '--launchers-dir testnet-release --version "${GITHUB_REF_NAME#v}"\n')
    if workflow.count(package_step) != 1:
        raise SystemExit("packaging-order fixture must occur once")
    without_package = workflow.replace(package_step, "")
    check_text(without_package.replace("      - name: Verify and assemble manifest-bound release assets",
                                     package_step + "\n      - name: Verify and assemble manifest-bound release assets"),
               "out of order")
    ci_workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    def check_ci_text(text: str, expected_failure: str | None = None) -> None:
        with tempfile.TemporaryDirectory(prefix="hegemon-ci-http-policy-") as raw:
            path = Path(raw) / "ci.yml"
            path.write_text(text)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    policy.check_ci_workflow(path)
            except SystemExit as error:
                if expected_failure is None or expected_failure not in str(error):
                    raise
            else:
                if expected_failure is not None:
                    raise SystemExit("required CI regression gate omission unexpectedly accepted")
    check_ci_text(ci_workflow)
    for source, checker, jobs in (
        (workflow, check_text, ("security-gates", "app-no-ssh-e2e")),
        (ci_workflow, check_ci_text, ("core-tests", "app-no-ssh-e2e")),
    ):
        for job in jobs:
            job_header = f"  {job}:\n"
            if source.count(job_header) != 1:
                raise SystemExit("unconditional job fixture must occur once: " + job)
            for field in ("if: false", "continue-on-error: true"):
                checker(source.replace(job_header, job_header + "    " + field + "\n"),
                        "required regression job must be unconditional and fail closed")
    for source, checker in ((workflow, check_text), (ci_workflow, check_ci_text)):
        for tokens in (*policy.WALLET_HTTP_REGRESSION_COMMANDS, policy.APP_RPC_REGRESSION_COMMAND):
            command = " ".join(tokens)
            command_fixture = "run: " + command
            if source.count(command_fixture) != 1:
                raise SystemExit("regression command fixture must occur once: " + command)
            checker(source.replace(command_fixture, "run: echo " + command), "exact executable regression")
            checker(source.replace(command_fixture, "continue-on-error: true\n        " + command_fixture), "exact executable regression")
            checker(source.replace(command_fixture, command_fixture + " --help"), "exact executable regression")
            checker(source.replace(command_fixture, command_fixture + " --ignored"), "exact executable regression")
        checker(source.replace("cargo test --locked -p wallet --test node_rpc",
                               "cargo test -p wallet --test node_rpc"), "exact executable regression")
        checker(source.replace("tests/walletSync.test.ts tests/walletdProtocol.test.ts", "tests/walletdProtocol.test.ts"),
                "exact executable regression")
        app_step = ("      - name: Test app RPC endpoints and wallet sync watchdog\n"
                    "        run: " + " ".join(policy.APP_RPC_REGRESSION_COMMAND) + "\n")
        if source.count(app_step) != 1:
            raise SystemExit("app regression order fixture must occur once")
        without_app = source.replace(app_step, "")
        after_workflow = "        run: ./scripts/check-app-no-ssh-e2e.sh\n"
        checker(without_app.replace(after_workflow, after_workflow + "\n" + app_step), "out of order")
    print("CI/release executable-step policy, launcher/publication and HTTP/watchdog negative tests passed")


if __name__ == "__main__":
    main()
