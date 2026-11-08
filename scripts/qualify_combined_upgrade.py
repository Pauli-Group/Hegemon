#!/usr/bin/env python3
"""Execute bounded source rehearsal suites; final proof/H0 remain separate.

Runtime evidence is an explicitly SHA-pinned external execution transcript from
the coordinator's disposable funded rehearsal. It never says that a rehearsal
executable is the ordinary release artifact. Missing observations fail closed.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('_combined_gate', ROOT / 'scripts/check_combined_upgrade_candidate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
FEATURES = 'development-candidate,combined-upgrade-rehearsal,asert-rehearsal,wallet/rpc-client,wallet/private-spend-dev-artifacts'
NATIVE = 'native::'
TS = NATIVE + 'timestamp_admission_tests::'
ASERT = NATIVE + 'asert_tests::'
TREASURY = NATIVE + 'poseidon2_v8_coinbase_tests::'
LIFECYCLE = NATIVE + 'treasury_lifecycle_tests::native_treasury_cadence_boundary_reorg_restart_and_fresh_sync'

TIMESTAMP_TESTS = {
    'native_timestamp_exact_inclusive_limit_full_milliseconds_and_overflow': ('exact_boundary', 'beyond_boundary'),
    'native_timestamp_mined_cpu_and_asic_shared_import_rejects_then_retries_without_writes': ('local_cpu', 'local_asic', 'temporary_retry'),
    'native_timestamp_direct_announcement_rejects_then_accepts_unchanged_bytes': ('announcement',),
    'native_timestamp_canonical_sync_late_future_row_rejects_entire_atomic_batch': ('batch_sync', 'fresh_sync'),
    'native_timestamp_mixed_sync_rejects_before_persisting_any_missing_row': ('batch_sync',),
    'native_timestamp_stored_branch_adoption_rejects_after_clock_rollback_but_replay_survives': ('winning_branch', 'historical_replay'),
    'native_timestamp_cached_work_clock_rollback_rebuilds_and_fast_authoring_uses_milliseconds': ('bounded_author',),
}
ASERT_TESTS = {
    'asert_native_mining_activation_admission_and_restart': ('activation_boundary', 'wrong_target_rules'),
    'asert_native_candidate_timestamp_does_not_change_target': ('wrong_target_rules',),
    'asert_native_sync_branch_anchor_reorg_restart_and_fresh_sync': ('branch_anchor',),
    'asert_native_cached_anchor_rechecks_storage_and_canonical_indexes': ('branch_anchor',),
    'asert_native_cold_resolution_is_bounded_resumable_and_not_a_height_cutoff': ('cold_resumption',),
}
TREASURY_TESTS = {
    'treasury_cadence_activation_is_exact_and_legacy_history_stays_valid': ('migration_boundary',),
    'treasury_cadence_rejects_early_missing_duplicate_zero_wrong_value_and_policy': ('invalid_payout_rejection',),
    'treasury_cadence_miner_forfeiture_fees_and_actual_supply_are_independent': ('miner_and_fee_preservation', 'omitted_reward_semantics', 'pending_issued_accounting'),
    'treasury_cadence_zero_batches_and_final_exhaustion_residual': ('zero_and_final_residual',),
}
VERSION_TESTS = {
    'VersionRollingTCPTest.test_default_mask_and_rolled_solution_forward_exact_header_version': ('negotiated_mask',),
    'VersionRollingTCPTest.test_fixed_version_client_retains_five_field_submit_on_active_profile': ('fixed_version',),
    'VersionRollingTCPTest.test_negotiated_client_rejects_missing_bits_outside_mask_and_wrong_time': ('malformed_rejection', 'out_of_mask_rejection'),
    'VersionRollingTCPTest.test_malformed_configuration_does_not_negotiate': ('malformed_rejection',),
    'MiningProfileValidationTest.test_extranonce_split_validation_and_total_width': ('extranonce_20_8', 'extranonce_24_4'),
    'FutureRetentionTest.test_future_busy_success_keeps_exact_payload_and_bounded_owner': ('retained_solution_retry',),
}


def digest(path):
    return gate.sha(path.read_bytes())


def exact_test_output(raw):
    text = raw.decode(errors='replace')
    gate.require(len(re.findall(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', text, re.M)) == 1,
                 'required exact test did not execute once with zero ignored tests')
    gate.require(not re.search(r'^test result: FAILED', text, re.M), 'failed test summary')


def unittest_output(raw):
    # Normalize only the parser view. Logs and their hashes retain exact bytes.
    text = raw.decode(errors='replace').replace('\r\n', '\n')
    count = re.findall(r'^Ran (\d+) tests? in ', text, re.M)
    gate.require(count == ['1'] and re.search(r'^OK$', text, re.M)
                 and not re.search(r'^FAILED', text, re.M),
                 'exact nonignored adapter test did not actually execute once')


def qualification_argv(argv):
    if os.name != 'nt' or not argv or argv[0] != 'bash':
        return argv
    # A bare bash on Windows can select the WSL launcher. Resolve the shell
    # from Git itself without changing PATH or accepting a different Bash.
    git_executable = shutil.which('git.exe') or shutil.which('git')
    message = 'Windows qualification requires Git for Windows Bash adjacent to the installed Git executable'
    gate.require(git_executable is not None, message + ': Git was not found')
    git = Path(git_executable)
    gate.require(git.is_absolute(), message + ': Git path is not absolute')
    if git.parent.name.lower() == 'bin' and git.parent.parent.name.lower() in ('mingw64', 'mingw32'):
        git_root = git.parent.parent.parent
    elif git.parent.name.lower() in ('cmd', 'bin'):
        git_root = git.parent.parent
    else:
        gate.require(False, message + ': unsupported Git executable layout: ' + str(git))
    for bash in (git_root / 'bin' / 'bash.exe', git_root / 'usr' / 'bin' / 'bash.exe'):
        if bash.is_file():
            return [str(bash), *argv[1:]]
    gate.require(False, message + ': bash.exe is missing under ' + str(git_root))


def run_command(argv, logdir, timeout=1800, exact=False, unittest=False):
    # No shell, no inherited simulation hooks, and no receipt-only PASS path.
    argv = qualification_argv(argv)
    env = {k: v for k, v in os.environ.items() if not k.startswith('HEGEMON_')}
    env.update(CARGO_TERM_COLOR='never', CARGO_INCREMENTAL='0')
    started = time.time()
    log = logdir / ('command-%03d.log' % len(list(logdir.glob('command-*.log'))))
    options = {'start_new_session': True} if os.name != 'nt' else {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
    process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=30, check=False)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        stdout, stderr = process.communicate(timeout=30)
        log.write_bytes(stdout + stderr)
        raise
    raw = stdout + stderr
    log.write_bytes(raw)
    if process.returncode != 0:
        gate.require(False, 'qualification command failed: ' + repr(argv)
                     + '; exit=' + str(process.returncode) + '; log=' + str(log)
                     + '; output tail (4096 bytes):\n' + gate.diagnostic_tail(raw, 4096))
    if exact:
        exact_test_output(raw)
    if unittest:
        unittest_output(raw)
    return {'argv': argv, 'exit_code': process.returncode, 'started_unix': started,
            'finished_unix': time.time(), 'log': str(log.relative_to(ROOT)), 'log_sha256': digest(log),
            'exactly_one_nonignored_test': exact}


def rust_test(package, name, logdir, ignored=False, features=None):
    argv = ['cargo', 'test', '--locked', '--release', '-p', package, '--no-default-features']
    if features:
        argv += ['--features', features]
    argv += ['--lib', name, '--', '--exact', '--nocapture']
    if ignored:
        argv += ['--ignored']
    return run_command(argv, logdir, exact=True)


def local_suites(name, logdir):
    completed, executions = set(), []
    def native(test, gates, ignored=False):
        executions.append(rust_test('hegemon-node', test, logdir, ignored, FEATURES))
        completed.update(gates)
    if name == 'timestamp_admission':
        for test, gates in TIMESTAMP_TESTS.items():
            native(TS + test, gates)
    elif name == 'asert':
        executions.append(rust_test('consensus-light-client', 'asert::tests::all_fourteen_thousand_bch_reference_vectors_match', logdir))
        completed.add('reference_vectors')
        executions.append(run_command(['cargo', 'check', '--locked', '-p', 'consensus-light-client', '--no-default-features'], logdir))
        completed.add('no_std')
        executions.append(run_command(['bash', 'scripts/check_asert_formal.sh'], logdir))
        completed.add('lean_vectors')
        for test, gates in ASERT_TESTS.items():
            native(ASERT + test, gates)
        # Manual ASIC solving and finite target vectors do not establish live
        # CPU-author catchup. An actual author transcript is still required.
    elif name == 'version_rolling':
        for test, gates in VERSION_TESTS.items():
            executions.append(run_command([sys.executable, '-I', '-B', 'scripts/test_bitcoin_asic_stratum.py', test], logdir, unittest=True))
            completed.update(gates)
    elif name == 'treasury_cadence':
        for test, gates in TREASURY_TESTS.items():
            native(TREASURY + test, gates)
        native(NATIVE + 'treasury_formal_tests::lean_generated_treasury_batch_supply_vectors_match_production', ('pending_issued_accounting',))
        for test, gates in (
            ('activation_and_fresh_genesis_boundaries_do_not_reaccrue_history', ('fresh_cadence',)),
            ('exact_rounding_crosses_halving_and_pays_final_residual', ('halving_rounding',)),
            ('checked_bounds_and_branch_height_reconstruction', ('pending_issued_accounting',))):
            executions.append(rust_test('consensus', 'treasury::tests::' + test, logdir))
            completed.update(gates)
        for test, gates in (
            ('treasury_only_boundary_recovers_threshold_policy_and_restores_maturity_after_reorg', ('wallet_discovery', 'maturity')),
            # This second test checks packed constraints, not a generated proof.
            ('treasury_only_batch_values_remain_valid_in_existing_two_input_private_spend', ())):
            executions.append(rust_test('wallet', 'poseidon2_v8_sync::tests::' + test, logdir, features='rpc-client'))
            completed.update(gates)
    elif name == 'restart_reorg_fresh_sync':
        native(LIFECYCLE, ('treasury_boundary_reorg', 'accrual_rollback', 'payout_rollback', 'persistent_restart', 'fresh_independent_sync', 'exact_state_work_supply_agreement'), True)
    elif name == 'current_smzl_htlc':
        # These source tests run on every target. None substitutes for the
        # funded lock/claim/refund/recovery observations below.
        native(NATIVE + 'tests::protocol_v8_artifact_codec_matches_private_pending_action_v3_exactly', ())
        for test in (
            'tests::private_spend_lock_policy_has_real_authorities_and_never_embeds_preimage',
            'distinct_refund_relation_tests::private_spend_distinct_refund_builds_common_relation_with_local_refund_credential'):
            executions.append(rust_test('wallet', 'private_spend_build::' + test, logdir, features='rpc-client'))
    return completed, executions


def checked_external_file(base, relative, expected):
    path = gate.safe_file(base, relative)
    gate.require(digest(path) == expected, 'external transcript bytes differ: ' + relative)
    return path


def checked_transcript(base, value):
    transcript = value.get('transcript', {})
    path = checked_external_file(base, transcript['path'], transcript['sha256'])
    gate.require(gate.strict_json(path.read_bytes()) == {k: v for k, v in value.items() if k != 'transcript'},
                 'retained transcript content differs from pinned receipt observations')


def runtime_evidence(path, expected_sha, config, runner_sha, io_sha, binary_pins):
    gate.require(re.fullmatch('[0-9a-f]{64}', expected_sha or '') is not None, 'explicit runtime receipt SHA256 required')
    gate.require(path.is_file() and not path.is_symlink() and digest(path) == expected_sha, 'pinned runtime receipt differs')
    value = gate.strict_json(path.read_bytes())
    gate.require(value.get('schema') == 'hegemon.combined-upgrade.actual-process-acceptance.v1'
                 and value.get('status') == 'PASS_LOCAL_COMBINED_CANDIDATE'
                 and value.get('completed') is True and value.get('production_authorized') is False
                 and value.get('deployment_verified') is False, 'full non-authorizing actual runtime execution required')
    gate.require(all(value.get(k) is True for k in ('all_owned_reaped', 'all_owned_exit0', 'rpc_closed')), 'runtime process closure incomplete')
    solver_path = 'scripts/combined_upgrade_acceptance/exact80_solver.rs'
    solver_rows = [r for r in config['source_inventory'] if r['path'] == solver_path]
    gate.require(len(solver_rows) == 1, 'frozen source-owned exact80 solver required')
    solver = gate.safe_file(ROOT, solver_path)
    gate.require(digest(solver) == solver_rows[0]['sha256'], 'frozen exact80 solver bytes differ')
    gate.require(value.get('harness') == {'run_combined.py': runner_sha, 'combined_io.py': io_sha,
                                        'exact80_solver.rs': solver_rows[0]['sha256']}, 'reviewed runtime harness identity differs')
    invocation = value.get('actual_invocation')
    gate.require(isinstance(invocation, list) and len(invocation) >= 8 and all(isinstance(v, str) for v in invocation)
                 and '--runtime-only' not in invocation and '--node-binary' in invocation and '--private-spend-binary' in invocation,
                 'exact complete runtime argv missing')
    features = value.get('rehearsal_features', {})
    gate.require(features == {'hegemon-node': ['development-candidate', 'combined-upgrade-rehearsal'],
                             'private-spend': ['rpc-client', 'private-spend-dev-artifacts'],
                             'metadata_kind': 'declared build features; runtime activation and CLI paths independently checked'}, 'rehearsal feature identity differs')
    inventory = value.get('source', {}).get('complete_candidate_inventory', {})
    gate.require(inventory.get('canonical_records_sha256') == config['source_inventory_sha256'], 'runtime frozen source inventory differs')
    inv_path = Path(inventory.get('path', ''))
    inv_path = inv_path if inv_path.is_absolute() else path.parent / inv_path
    gate.require(inv_path.is_file() and digest(inv_path) == inventory.get('sha256'), 'runtime complete inventory bytes differ')
    records = json.loads(inv_path.read_bytes())
    gate.require(records == config['source_inventory'] and gate.sha(gate.canonical(records)) == config['source_inventory_sha256'], 'runtime full source records differ')
    for binary, key in (('hegemon-node', '--node-binary'), ('private-spend', '--private-spend-binary')):
        row = value.get('binaries', {}).get(binary, {})
        recorded_path = row.get('path')
        gate.require(isinstance(recorded_path, str) and bool(recorded_path), 'nonempty recorded rehearsal executable path required')
        binary_path = Path(recorded_path)
        pin = binary_pins.get(binary)
        gate.require(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin) and row.get('sha256') == pin, 'independently reviewed rehearsal executable SHA256 required')
        # A retained external execution is reusable by other targets as source
        # evidence. Its executable identity is pinned in reviewed argv; it is
        # never substituted for the target's own ordinary artifact identity.
        if binary_path.exists():
            gate.require(binary_path.is_file() and not binary_path.is_symlink() and digest(binary_path) == pin, 'actual retained rehearsal executable differs')
        gate.require(invocation[invocation.index(key) + 1] == recorded_path, 'runtime argv executable differs')
    closures = value.get('owned_processes', [])
    gate.require(len(closures) >= 7 and all(type(r.get('exit_code')) is int and r['exit_code'] == 0 and r.get('forced') is False for r in closures), 'actual owned process receipts missing')
    return value


def runtime_gates(value, base):
    """Derive only observations actually checked by this specific harness."""
    completed = {name: set() for name in gate.CHECKS}
    gates = value.get('gates', {})
    def observed(name):
        gate.require(gates.get(name, {}).get('passed') is True and isinstance(gates[name].get('evidence'), dict), 'missing runtime observation: ' + name)
        return gates[name]['evidence']
    observed('actual_activation_import')
    observed('independent_bigint_fixed_anchor_asert')
    audit_row = observed('final_exact_canonical_history_and_timestamps')
    audit = gate.strict_json(checked_external_file(base, 'canonical-audit.json', audit_row['audit_sha256']).read_bytes())
    rows = audit.get('rows', [])
    gate.require(len(audit.get('nodes', [])) >= 3 and len(rows) >= 300
                 and [r.get('height') for r in rows] == list(range(len(rows))), 'complete independent canonical history missing')
    gate.require(any(r['height'] >= 120 and r['header'].get('miningVersion') == 0x20000020 for r in rows), 'actual nonzero rolled-version block missing')
    completed['version_rolling'].update(('nonzero_rolled_block', 'independent_import'))
    observed('cadence_and_public_treasury_batch')
    observed('batch_immature_at_parent_H297')
    observed('mature_batch_actual_current_smzl_ordinary')
    observed('actual_claim_and_competing_negative')
    observed('actual_refund')
    observed('final_restart_and_independent_fresh_proof_sync')
    proofs = value.get('proofs', {})
    gate.require(set(proofs) == {'treasury-ordinary', 'claim-lock', 'claim', 'competing-refund', 'refund-lock', 'refund'}, 'actual six-proof lifecycle inventory differs')
    for name, row in proofs.items():
        gate.require(row.get('wallet_local_verify_completed') is True and row.get('fixed_relation_input_slots') == 2, 'actual unchanged relation proof missing')
        checked_external_file(base, row['action'], row['action_sha256'])
        carrier = checked_external_file(base, name + '.carrier.hgps', row['carrier_sha256']).read_bytes()
        proof = checked_external_file(base, name + '.proof.smzl', row['proof_sha256']).read_bytes()
        gate.require(carrier[:8] == b'HGPSLC02' and proof[:4] == b'SMZL'
                     and carrier[24:72].hex() == gate.RELATION[:96]
                     and carrier.endswith(proof) and len(proof) == row['proof_bytes']
                     and 128 < len(proof) <= 171848
                     and len(carrier) == row['carrier_bytes'], 'current SMZL carrier framing differs')
    actions = value.get('actions', {})
    for name in ('treasury-ordinary', 'claim-lock', 'claim', 'refund-lock', 'refund'):
        row = actions.get(name, {})
        gate.require(row.get('exact_pending_and_mined_bytes') is True and row.get('action_sha256') == proofs[name]['action_sha256'], 'exact submitted/mined bytes missing')
        agreement = row.get('node_agreement', {})
        gate.require(len(agreement.get('nodes', [])) >= 3 and len(agreement.get('status', {})) == 5, 'independent runtime state/work/supply agreement missing')
    for name in ('wrong-preimage', 'early-refund'):
        row = value.get('negatives', {}).get(name, {})
        gate.require(all(row.get(k) is True for k in ('rejected', 'unchanged_attempts', 'unchanged_tip')), 'HTLC rejection observation missing')
    for name in ('pending-competing-refund', 'spent-competing-refund'):
        gate.require(value.get('negatives', {}).get(name, {}).get('rejected') is True, 'competing-spend rejection missing')
    completed['treasury_cadence'].update(('maturity', 'wallet_discovery', 'unchanged_relation_spend'))
    completed['current_smzl_htlc'].update(('funded_lock', 'funded_claim', 'funded_refund', 'deadline', 'competing_spend', 'unchanged_carrier', 'ordinary_payout'))
    if 'live_cpu_author_catchup' in gates:
        cpu = observed('live_cpu_author_catchup')
        checked_transcript(base, cpu)
        start = cpu.get('before', {}).get('status', {}).get('height')
        end = cpu.get('after', {}).get('status', {}).get('height')
        gate.require(type(start) is int and start >= 120 and type(end) is int and start + 3 <= end < start + 12,
                     'ASERT live CPU catchup must actually run after activation')
        gate.require(cpu.get('manual_pool_solver_used_in_phase') is False and cpu.get('stable_tip_after_stop') is True
                     and cpu.get('asert_active_phase') is True
                     and cpu.get('start_rpc', {}).get('success') is True and cpu.get('stop_rpc', {}).get('success') is True,
                     'actual bounded native CPU start/stop observations missing')
        imported = cpu.get('independent_imported_headers', [])
        gate.require([r.get('height') for r in imported] == list(range(start + 1, end + 1))
                     and len(cpu.get('after', {}).get('nodes', [])) >= 2, 'CPU-authored independent import inventory missing')
        for row in imported:
            height = row['height']
            gate.require(row.get('hash') == rows[height]['hash'] and row.get('header') == rows[height]['header']
                         and row.get('independent_asert_checked') is True
                         and type(row.get('timestamp_ms')) is int and type(row.get('observed_clock_ms')) is int
                         and row['timestamp_ms'] <= row['observed_clock_ms'] + 90000, 'CPU-authored canonical timestamp/header differs')
        completed['asert'].add('live_author_catchup')
    if 'encrypted_recovery' in value:
        recovery = value['encrypted_recovery']
        gate.require(observed('encrypted_wallet_recovery') == recovery, 'recovery gate/transcript observations differ')
        gate.require(recovery.get('method') == 'current private-spend bootstrap-recover'
                     and all(recovery.get(k) is True for k in ('source_preserved', 'recovered_same_keys', 'new_password_distinct', 'keys_accounts_and_issued_addresses_only', 'deadline_note_discovery_checked', 'post_restart_canonical_payout_discovered'))
                     and recovery.get('proof_journal_restored') is False, 'fresh encrypted key recovery observations missing')
        gate.require(recovery.get('before', {}).get('status') == recovery.get('after', {}).get('status')
                     and isinstance(recovery.get('before', {}).get('status'), dict)
                     and recovery.get('fresh_rescan_mature_treasury_atoms') == 6000000000
                     and recovery.get('fresh_rescan_mature_treasury_position') == value.get('treasury_batch', {}).get('position'), 'recovered mature note/canonical state differs')
        gate.require(recovery.get('recovered_deadline_negative') == 'early-refund' and recovery.get('recovered_htlc_atoms') == 1000000,
                     'recovered wallet deadline/HTLC discovery observation missing')
        retained = recovery.get('retained_original_proof_after_restart', {})
        gate.require(retained.get('same_exact_action_carrier_proof') is True
                     and retained.get('original_action_sha256') == retained.get('reexported_action_sha256') == proofs['treasury-ordinary']['action_sha256'], 'original SMZL proof was not retained unchanged after restart')
        checked_external_file(base, retained['reexported_action'], retained['reexported_action_sha256'])
        old_hash = recovery.get('source_backup', {}).get('sha256')
        new_hash = recovery.get('new_encrypted_wallet', {}).get('sha256')
        gate.require(isinstance(old_hash, str) and re.fullmatch('[0-9a-f]{64}', old_hash)
                     and isinstance(new_hash, str) and re.fullmatch('[0-9a-f]{64}', new_hash)
                     and new_hash != old_hash, 'separately encrypted destination identity missing')
        log = recovery.get('cli_log', {})
        checked_external_file(base, log['path'], log['sha256'])
        metrics = recovery.get('metrics', {})
        gate.require(type(metrics.get('exit_code')) is int and metrics['exit_code'] == 0, 'actual encrypted recovery command did not exit successfully')
        completed['current_smzl_htlc'].add('encrypted_recovery')
    if 'unchanged_action_reorg_resubmission' in gates:
        reorg = observed('unchanged_action_reorg_resubmission')
        checked_transcript(base, reorg)
        proof = proofs['claim']
        gate.require(reorg.get('candidate') == 'claim' and all(reorg.get(k) == proof[k] for k in ('action_sha256', 'carrier_sha256', 'proof_sha256'))
                     and all(reorg.get(k) is True for k in ('fork_work_exceeds_old', 'original_inclusion_detached', 'wallet_mined_receipt_rolled_back', 'identical_action_resubmitted', 'all_reference_and_nullifier_checks_unchanged')),
                     'actual unchanged reorg/resubmission identity missing')
        reference = reorg.get('canonical_reference_height')
        old, new = reorg.get('old_inclusion', {}), reorg.get('reinclusion', {})
        gate.require(type(reference) is int and reference == proof['reference_height']
                     and reorg.get('canonical_reference_hash') == proof['reference_hash'] == rows[reference]['hash']
                     and old.get('height') == reference + 1 and type(new.get('height')) is int
                     and old['height'] < new['height'] <= reference + 13
                     and old.get('action_sha256') == new.get('action_sha256') == proof['action_sha256']
                     and rows[old['height']]['hash'] != old.get('block_hash')
                     and rows[new['height']]['hash'] == new.get('block_hash')
                     and rows[new['height']]['action_sha256'].count(proof['action_sha256']) == 1,
                     'actual detached/reincluded canonical action/reference differs')
        gate.require(int(reorg['higher_work_fork']['header']['cumulativeWork'], 16) > int(reorg['old_tip']['header']['cumulativeWork'], 16), 'fork does not have strictly greater work')
        exported = reorg.get('reexport_after_reorg', {})
        gate.require(exported.get('sha256') == proof['action_sha256'], 'reexported action hash differs')
        checked_external_file(base, exported['path'], exported['sha256'])
        completed['restart_reorg_fresh_sync'].add('unchanged_resubmission')
    return completed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=gate.CHECKS, required=True)
    parser.add_argument('--artifact-manifest', type=Path)
    parser.add_argument('--focused-only', action='store_true', help='execute available source tests before freeze; never emits an authorized actual-check receipt')
    parser.add_argument('--runtime-receipt', type=Path)
    parser.add_argument('--runtime-receipt-sha256')
    parser.add_argument('--runtime-runner-sha256')
    parser.add_argument('--runtime-io-sha256')
    parser.add_argument('--runtime-node-sha256')
    parser.add_argument('--runtime-private-spend-sha256')
    args = parser.parse_args()
    try:
        config = gate.load_config(ROOT)
        gate.source_check(ROOT, config)
        output_root = ROOT / 'target/combined-qualification'
        output_root.mkdir(parents=True, exist_ok=True)
        logdir = Path(tempfile.mkdtemp(prefix=args.suite + '-', dir=output_root))
        if args.focused_only:
            before = gate.inventory(ROOT)
            completed, executions = local_suites(args.suite, logdir)
            gate.require(executions, 'this suite needs the actual funded runtime executor; no local focused test substitute exists')
            gate.require(gate.inventory(ROOT) == before, 'source changed during focused source preparation')
            print(json.dumps({'schema': 'hegemon.combined-upgrade.focused-source-preparation.v1',
                'status': 'PASS_FOCUSED_SOURCE_TESTS_ONLY', 'name': args.suite,
                'source_inventory_sha256': gate.sha(gate.canonical(before)),
                'completed_source_test_gates': sorted(completed),
                'missing_runtime_gates': sorted(set(gate.REQUIRED_GATES[args.suite]) - completed),
                'focused_executions': executions, **gate.BOUNDARIES}, sort_keys=True))
            return 0
        gate.require(config['status'] == 'frozen', 'qualification needs an exact frozen source tuple')
        gate.require(args.artifact_manifest is not None, 'final artifact manifest required for qualification')
        manifest = args.artifact_manifest.resolve()
        gate.require(manifest.is_relative_to(ROOT), 'final artifact manifest escapes source')
        artifacts = gate.strict_json(manifest.read_bytes())
        identity = {'artifact_manifest_sha256': digest(manifest), 'artifact_sha256': {r['binary']: r['sha256'] for r in artifacts['artifacts']}, 'target_triple': artifacts['target_triple']}
        gate.recheck_artifacts(ROOT, manifest, identity)
        completed, executions = local_suites(args.suite, logdir)
        runtime = None
        if args.runtime_receipt:
            runtime = runtime_evidence(args.runtime_receipt.resolve(), args.runtime_receipt_sha256, config, args.runtime_runner_sha256, args.runtime_io_sha256,
                                      {'hegemon-node': args.runtime_node_sha256, 'private-spend': args.runtime_private_spend_sha256})
            completed.update(runtime_gates(runtime, args.runtime_receipt.resolve().parent)[args.suite])
        missing = sorted(set(gate.REQUIRED_GATES[args.suite]) - completed)
        gate.require(not missing, 'unexecuted actual observations: ' + ', '.join(missing) + '; focused logs=' + str(logdir))
        gate.recheck_artifacts(ROOT, manifest, identity)
        gate.source_check(ROOT, config)
        gate.require(gate.load_config(ROOT) == config, 'candidate changed during qualification')
        receipt = {'schema': 'hegemon.combined-upgrade.actual-check.v1', 'name': args.suite, 'status': 'PASS',
            'candidate_binding_sha256': gate.binding(config), 'source_inventory_sha256': config['source_inventory_sha256'],
            **identity, 'actual_execution': True, 'processes_reaped': True, **gate.BOUNDARIES,
            'gates': {name: True for name in gate.REQUIRED_GATES[args.suite]}, 'focused_executions': executions,
            'execution_scope': 'same_source_rehearsal_not_ordinary_final_binary',
            'runtime_receipt_sha256': args.runtime_receipt_sha256 if runtime else None,
            'rehearsal_binaries': runtime['binaries'] if runtime else {},
            'limitations': ['Finite source rehearsal evidence; per-target final proof verification and H0 are separate mandatory checks.', 'No physical ASIC or production activation authority.']}
        print(json.dumps(receipt, sort_keys=True))
    except (RuntimeError, OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        print('combined qualification: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
