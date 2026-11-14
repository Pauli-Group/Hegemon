#!/usr/bin/env python3
"""Run fresh bounded v0.11.5 source rehearsals; final proof/H0 are separate.

Every credited observation comes from a fixed command executed by this process.
These test executables use source-owned rehearsal activations and are never
represented as the ordinary final release binaries or as physical ASIC tests.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ('ntime', 'asert', 'treasury', 'adapter', 'sync')
FEATURES = 'development-candidate,combined-upgrade-rehearsal,asert-rehearsal,wallet/rpc-client,wallet/private-spend-dev-artifacts'
ASERT_FEATURES = FEATURES
EXECUTION_SCOPE = 'same-source-rehearsal-not-ordinary-final-binary'
ADAPTER_TEST_COUNT = 59

NATIVE_TESTS = {
    'ntime': (
        'native::bitcoin_asic_tests::ntime_rolling_boundary_solved_offsets_clock_rollback_expiry_restart_sync_and_reorg',
        'native::timestamp_admission_tests::native_timestamp_rolling_activation_preserves_legacy_and_canonicalizes_new_work',
        'native::timestamp_admission_tests::native_timestamp_rolling_bounds_clamp_without_wrapping_32_bit_ntime',
        'native::timestamp_admission_tests::native_timestamp_rolling_bounds_use_parent_and_fresh_node_clock',
    ),
    'asert': (
        'native::asert_tests::asert_native_mining_activation_admission_and_restart',
        'native::asert_tests::asert_native_candidate_timestamp_does_not_change_target',
        'native::asert_tests::asert_native_sync_branch_anchor_reorg_restart_and_fresh_sync',
        'native::asert_tests::asert_native_cached_anchor_rechecks_storage_and_canonical_indexes',
        'native::asert_tests::asert_native_cold_resolution_is_bounded_resumable_and_not_a_height_cutoff',
    ),
    'treasury': (
        'native::poseidon2_v8_coinbase_tests::premainnet_combined_treasury_selection_admission_and_maturity',
        'native::treasury_formal_tests::lean_generated_treasury_batch_supply_vectors_match_production',
    ),
    'sync': (
        'native::service::sync_queue_qualification_tests::live_blocked_queue_old_completion_preserves_new_target_and_continues',
        'native::tests::mining_recovery_qualification_tests::unknown_equal_height_and_higher_hints_keep_retained_asic_solution_gated_without_write',
        'native::public_rpc_http_tests::public_http_disconnected_safe_read_workers_keep_bounded_reservations_until_completion',
    ),
}
ASERT_VECTOR_TEST = 'asert::tests::all_fourteen_thousand_bch_reference_vectors_match'
LEGACY_TIMESTAMP_TESTS = (
    'native_timestamp_exact_inclusive_limit_full_milliseconds_and_overflow',
    'native_timestamp_mined_cpu_and_asic_shared_import_rejects_then_retries_without_writes',
    'native_timestamp_direct_announcement_rejects_then_accepts_unchanged_bytes',
    'native_timestamp_canonical_sync_late_future_row_rejects_entire_atomic_batch',
    'native_timestamp_mixed_sync_rejects_before_persisting_any_missing_row',
    'native_timestamp_stored_branch_adoption_rejects_after_clock_rollback_but_replay_survives',
    'native_timestamp_cached_work_clock_rollback_rebuilds_and_fast_authoring_uses_milliseconds',
)
LEGACY_TREASURY_TESTS = (
    'treasury_cadence_activation_is_exact_and_legacy_history_stays_valid',
    'treasury_cadence_rejects_early_missing_duplicate_zero_wrong_value_and_policy',
    'treasury_cadence_miner_forfeiture_fees_and_actual_supply_are_independent',
    'treasury_cadence_zero_batches_and_final_exhaustion_residual',
)
TREASURY_LIFECYCLE_TEST = 'native::treasury_lifecycle_tests::native_treasury_cadence_boundary_reorg_restart_and_fresh_sync'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_gate():
    path = ROOT / 'scripts/check_ntime_rolling_candidate.py'
    spec = importlib.util.spec_from_file_location('_ntime_candidate_gate', path)
    require(spec is not None and spec.loader is not None, 'source-owned nTime candidate checker required')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_test_output(raw, name):
    """Reject misspelled filters, ignored tests and successful empty harnesses."""
    text = raw.decode(errors='replace').replace('\r\n', '\n')
    summaries = re.findall(r'^test result: (.*)$', text, re.M)
    require(len(summaries) == 1 and re.fullmatch(
        r'ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in .+',
        summaries[0]) is not None, 'required exact test did not execute once with zero ignored tests: ' + name)
    require(len(re.findall(r'^test ' + re.escape(name) + r' \.\.\. ok$', text, re.M)) == 1,
            'required exact named test success line missing: ' + name)
    require(not re.search(r'^test .+ \.\.\. (?:FAILED|ignored)|^failures:', text, re.M),
            'failed or ignored test output: ' + name)
    return {'passed': 1, 'failed': 0, 'ignored': 0, 'measured': 0}


def unittest_output(raw, expected=ADAPTER_TEST_COUNT):
    text = raw.decode(errors='replace').replace('\r\n', '\n')
    counts = re.findall(r'^Ran (\d+) tests? in .+$', text, re.M)
    require(type(expected) is int and expected > 0 and counts == [str(expected)]
            and len(re.findall(r'^OK$', text, re.M)) == 1
            and not re.search(r'^FAILED|^OK \(|^FAIL:|^ERROR:|\bskipped=', text, re.M),
            'complete adapter suite must actually execute exactly ' + str(expected) + ' tests with no skips or failures')
    return {'passed': expected, 'failed': 0, 'ignored': 0, 'skipped': 0}


def diagnostic_tail(raw, maximum=4096):
    # Trim encoded bytes after replacement too: invalid UTF8 can otherwise make
    # a nominal 4096-byte diagnostic many times larger than that limit.
    return raw[-maximum:].decode(errors='replace').encode()[-maximum:].decode(errors='ignore')


def kill_owned_process_group(process):
    if os.name == 'nt':
        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                       capture_output=True, timeout=30, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


@contextlib.contextmanager
def interruption_handlers():
    """Turn outer-runner termination into the same bounded child cleanup path.

    The coordinator owns this runner's process group; cargo owns a separate
    group so that its descendants can be killed together. Catchable termination
    must therefore unwind through communicate/kill/reap before this runner exits.
    Windows forced termination is handled by the coordinator's taskkill /T.
    """
    previous = {}
    def interrupted(signum, _frame):
        # A second signal must not interrupt the bounded cleanup/reap operation.
        for registered in previous:
            signal.signal(registered, signal.SIG_IGN)
        raise RuntimeError('qualification interrupted by signal ' + str(signum))
    try:
        signals = [signal.SIGTERM, signal.SIGINT]
        if hasattr(signal, 'SIGBREAK'):
            signals.append(signal.SIGBREAK)
        for signum in signals:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupted)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def run_command(argv, logdir, *, timeout=1800, exact_name=None, adapter_count=None):
    require(isinstance(argv, list) and argv and all(isinstance(v, str) and v for v in argv),
            'nonempty direct command argv required')
    require(type(timeout) is int and 1 <= timeout <= 7200, 'bounded command timeout required')
    env = {k: v for k, v in os.environ.items() if not k.startswith('HEGEMON_')}
    env.update(CARGO_TERM_COLOR='never', CARGO_INCREMENTAL='0')
    log = logdir / ('command-%03d.log' % len(list(logdir.glob('command-*.log'))))
    started = time.time()
    monotonic_started = time.monotonic()
    options = ({'start_new_session': True} if os.name != 'nt'
               else {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP})
    # Exclusive creation retains prior failures and prevents accidental evidence
    # replacement. No shell, fixture executor, supplied receipt, or PASS hook.
    with log.open('xb') as retained, interruption_handlers():
        process = None
        try:
            process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, **options)
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            if process is not None:
                kill_owned_process_group(process)
                stdout, stderr = process.communicate(timeout=30)
                retained.write(stdout + stderr)
            raise
        raw = stdout + stderr
        retained.write(raw)
    require(process.returncode == 0,
            'qualification command failed: ' + repr(argv) + '; exit=' + str(process.returncode)
            + '; log=' + str(log) + '; output tail (4096 bytes):\n' + diagnostic_tail(raw))
    counts = None
    if exact_name is not None:
        counts = exact_test_output(raw, exact_name)
    if adapter_count is not None:
        require(exact_name is None, 'one output parser per execution required')
        counts = unittest_output(raw, adapter_count)
    command_kind = ('rust-test' if exact_name is not None else
                    'python-unittest' if adapter_count is not None else 'cargo-check')
    return {'argv': argv, 'exit_code': process.returncode, 'started_unix': started,
            'finished_unix': time.time(), 'duration_seconds': time.monotonic() - monotonic_started,
            'log': log.relative_to(ROOT).as_posix(), 'log_sha256': digest(log),
            'processes_reaped': True, 'process_reaped': True, 'actual_command_execution': True,
            'command_kind': command_kind, 'test_name': exact_name, 'test_counts': counts,
            'tests_passed': counts['passed'] if counts is not None else None,
            'tests_failed': 0, 'tests_ignored': 0, 'tests_skipped': 0}


def rust_argv(package, name, features=None, *, ignored=False):
    argv = ['cargo', 'test', '--locked', '--release', '-p', package, '--no-default-features']
    if features:
        argv += ['--features', features]
    argv += ['--lib', name, '--', '--exact', '--nocapture']
    if ignored:
        argv += ['--ignored']
    return argv


def suite_plan(name):
    require(name in CHECKS, 'unknown qualification suite: ' + str(name))
    if name == 'adapter':
        return [{'argv': [sys.executable, '-I', '-B', 'scripts/test_bitcoin_asic_stratum.py'],
                 'adapter_count': ADAPTER_TEST_COUNT}]
    commands = []
    if name == 'asert':
        commands.extend((
            {'argv': rust_argv('consensus-light-client', ASERT_VECTOR_TEST), 'exact_name': ASERT_VECTOR_TEST},
            {'argv': ['cargo', 'check', '--locked', '-p', 'consensus-light-client', '--no-default-features']},
        ))
    features = ASERT_FEATURES if name == 'asert' else FEATURES
    commands.extend({'argv': rust_argv('hegemon-node', test, features), 'exact_name': test}
                    for test in NATIVE_TESTS[name])
    def exact(package, test, test_features=None, *, ignored=False):
        commands.append({'argv': rust_argv(package, test, test_features, ignored=ignored), 'exact_name': test})
    if name == 'ntime':
        for test in LEGACY_TIMESTAMP_TESTS:
            exact('hegemon-node', 'native::timestamp_admission_tests::' + test, features)
    elif name == 'asert':
        exact('hegemon-node', 'native::poseidon2_v8_coinbase_tests::premainnet_combined_native_target_and_mining_payload', features)
    elif name == 'treasury':
        for test in LEGACY_TREASURY_TESTS:
            exact('hegemon-node', 'native::poseidon2_v8_coinbase_tests::' + test, features)
        for test in (
            'activation_and_fresh_genesis_boundaries_do_not_reaccrue_history',
            'exact_rounding_crosses_halving_and_pays_final_residual',
            'checked_bounds_and_branch_height_reconstruction',
        ):
            exact('consensus', 'treasury::tests::' + test)
        for test in (
            'treasury_only_boundary_recovers_threshold_policy_and_restores_maturity_after_reorg',
            'treasury_only_batch_values_remain_valid_in_existing_two_input_private_spend',
        ):
            exact('wallet', 'poseidon2_v8_sync::tests::' + test, 'rpc-client')
        exact('hegemon-node', 'native::tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly', features)
        for test in (
            'tests::private_spend_lock_policy_has_real_authorities_and_never_embeds_preimage',
            'distinct_refund_relation_tests::private_spend_distinct_refund_builds_common_relation_with_local_refund_credential',
        ):
            exact('wallet', 'private_spend_build::' + test, 'rpc-client')
    elif name == 'sync':
        # Explicitly run this expensive inherited lifecycle test. Rust then
        # reports one passed and zero ignored; skipping it earns no credit.
        exact('hegemon-node', TREASURY_LIFECYCLE_TEST, features, ignored=True)
    return commands


def local_suite(name, logdir):
    return [run_command(command['argv'], logdir,
                        exact_name=command.get('exact_name'),
                        adapter_count=command.get('adapter_count'))
            for command in suite_plan(name)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=CHECKS, required=True)
    parser.add_argument('--artifact-manifest', type=Path)
    parser.add_argument('--focused-only', action='store_true',
                        help='execute prefreeze source tests; never emits an authorized actual-check receipt')
    args = parser.parse_args(argv)
    try:
        gate = load_gate()
        require(tuple(gate.CHECKS) == CHECKS, 'candidate suite inventory differs')
        config = gate.load_config(ROOT)
        gate.source_check(ROOT, config)
        require(args.focused_only or config.get('status') == 'frozen',
                'qualification needs an exact frozen source tuple')
        if not args.focused_only:
            gate.review_check(ROOT, config)
            require(args.artifact_manifest is not None, 'final artifact manifest required for qualification')
            manifest = args.artifact_manifest.resolve()
            require(manifest.is_relative_to(ROOT), 'final artifact manifest escapes source')
            identity = gate.artifact_identity(ROOT, manifest)
            gate.recheck_artifacts(ROOT, manifest, identity)
        before = gate.inventory(ROOT)
        output_root = ROOT / 'target/ntime-qualification'
        output_root.mkdir(parents=True, exist_ok=True)
        logdir = Path(tempfile.mkdtemp(prefix=args.suite + '-', dir=output_root))
        executions = local_suite(args.suite, logdir)
        require(executions, 'fresh actual execution required')
        require(gate.inventory(ROOT) == before, 'source changed during affected qualification')
        gate.source_check(ROOT, config)
        require(gate.load_config(ROOT) == config, 'candidate config changed during qualification')
        if args.focused_only:
            print(json.dumps({'schema': 'hegemon.ntime-rolling.focused-source-preparation.v1',
                'status': 'PASS_FOCUSED_SOURCE_TESTS_ONLY', 'name': args.suite,
                'source_inventory_sha256': gate.sha(gate.canonical(before)),
                'executions': executions, 'execution_scope': EXECUTION_SCOPE,
                **gate.BOUNDARIES}, sort_keys=True))
            return 0
        gate.review_check(ROOT, config)
        gate.recheck_artifacts(ROOT, manifest, identity)
        receipt = {'schema': 'hegemon.ntime-rolling.actual-check.v1', 'name': args.suite, 'status': 'PASS',
            'candidate_binding_sha256': gate.binding(config),
            'source_inventory_sha256': config['source_inventory_sha256'], **identity,
            'actual_execution': True, 'processes_reaped': True, **gate.BOUNDARIES,
            'gates': {name: True for name in gate.REQUIRED_GATES[args.suite]},
            'executions': executions, 'execution_scope': EXECUTION_SCOPE,
            'limitations': ['Finite source rehearsal tests; final current-binary proof verification and height-zero startup are separate mandatory checks.',
                            'No physical ASIC, MRR rental, network deployment, or production activation authority.']}
        gate.validate_check(receipt, args.suite, config, identity, root=ROOT, verify_logs=True)
        print(json.dumps(receipt, sort_keys=True))
    except (RuntimeError, OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        print('nTime qualification: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
