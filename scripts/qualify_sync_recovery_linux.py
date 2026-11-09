#!/usr/bin/env python3
"""Execute bounded Linux sync-repair checks; never the full combined release gate."""
from __future__ import annotations
import argparse
import hashlib
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
NEW_TESTS = tuple('native::tests::sync_liveness_tests::' + name for name in (
    'growing_tip_does_not_restart_active_exact_prefix_recovery',
    'growing_tip_does_not_restart_deferred_exact_prefix_recovery',
    'growing_tip_can_replace_an_expired_exact_request_without_opening_gate',
    'growing_tip_waits_for_actual_import_completion_owner_before_retargeting'))
CONTROLS = tuple('native::tests::' + name for name in (
    'request_missing_blocks_recovery_cursor_tracks_same_peer_target_advance',
    'request_missing_blocks_recovery_cursor_survives_expired_request',
    'request_missing_blocks_recovery_cursor_rejects_stale_conflicting_and_foreign_hints',
    'request_missing_blocks_recovery_cursor_rebinds_exact_hash_after_peer_timeout',
    'deep_sync_recovery_cursor_survives_request_expiry_and_beats_near_tip_restart',
    'native_sync_recovery_context_binds_forward_parent_and_final_tip',
    'outbound_native_sync_request_retries_after_live_timeout',
    'authorized_sync_target_resolution_requires_successful_durable_import'))
MODULES = (('hegemon-node', 'native::tests::sync_liveness_tests::'),
           ('hegemon-node', 'native::service::sync_control_backpressure_tests::'),
           ('hegemon-node', 'native::service::sync_body_backpressure::tests::'),
           ('network', 'p2p::tests::'), ('network', 'peer_manager::tests::'),
           ('network', 'service::tests::'))
INHERITED = {
    'scripts/check_v011_release_successor.py': '390f5cbc69e877e29302db4af7b7382bbf6db9bdeccada01942ccba384b0fc67',
    'scripts/check_v011_current_binary_proofs.py': 'd2f0fae819828482093676f831a5d6c621013c02368cdddafcdf491d294eb2f2',
    'scripts/check_v011_public_chain_replay.py': '29c6655f1d8ced3ffa5a042e3c66f0567fc0ef465eda70de473e7a35054159dc',
    'config/combined-upgrade-candidate-20261108.json': 'd8c267c5e879ceed00ba1ca91325882d7eed0aad8179b841a584ca4508316c9e',
    'release-evidence/combined-upgrade-20261108/runtime-v10/receipt.json': 'd3fcdb47e8e2c8b73debd23f97f76c24435db6f75f76dec4561bc5f5e86523c6',
    'release-evidence/combined-upgrade-20261108/independent-review-v10.json': 'b5de7ce14a20aa9ddad1c373528e30806ddbdf83aaca0c446c948002db9aa939',
}

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

source = load('sync_recovery_source', ROOT / 'scripts/qualify_sync_recovery_source.py')

def require(value, message):
    if not value:
        raise RuntimeError(message)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')

def cargo(package):
    return ['cargo', 'test', '--locked', '--release', '-p', package, '--no-default-features', '--lib']

def run(argv, output, label, *, cwd=ROOT, timeout=1800):
    require(shutil.disk_usage(output).free >= 4 * 1024**3, 'four GiB disk reserve exhausted before ' + label)
    path = output / (label + '.log')
    started = time.time()
    with path.open('xb') as stream:
        process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True,
                                   env={**os.environ, 'CARGO_TARGET_DIR': str(ROOT / 'target')})
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                require(time.monotonic() < deadline, 'command timeout: ' + label)
                require(path.stat().st_size <= 64 * 1024**2, 'diagnostic byte cap: ' + label)
                require(shutil.disk_usage(output).free >= 4 * 1024**3, 'disk reserve exhausted: ' + label)
                time.sleep(.2)
        except BaseException:
            # The inherited replay owns detached node sessions and handles
            # SIGTERM by stopping/reaping them. Do not bypass that finally path.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=30)
            raise
        code = process.wait()
    return {'argv': argv, 'cwd': str(cwd), 'exit_code': code, 'started_unix': started,
            'finished_unix': time.time(), 'log': path.name, 'log_sha256': sha(path),
            'owned_leader_reaped': True}, path.read_text(errors='replace')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-source-sha', required=True)
    parser.add_argument('--expected-delta-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pin-provenance', choices=('dispatch-inputs', 'root-external-check-required'), default='dispatch-inputs')
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    receipt = {'schema': 'hegemon.sync-recovery.linux-qualification.v1', 'status': 'RUNNING',
               'production_authorized': False, 'release_publication_authorized': False,
               'deployment_verified': False, 'physical_asic_qualified': False,
               'full_combined_release_gate_rerun': False, 'commands': []}
    receipt['pin_provenance'] = args.pin_provenance
    receipt['external_expected_delta_check_required_root'] = args.pin_provenance == 'root-external-check-required'
    receipt['root_external_acceptance_performed'] = False
    baseline = None
    try:
        before = source.validate_source(ROOT, args.expected_source_sha, args.expected_delta_sha256, pin_provenance=args.pin_provenance)
        write(output / 'source-before.json', before)
        for path, digest in INHERITED.items():
            require(sha(ROOT / path) == digest, 'inherited qualification input differs: ' + path)
        receipt['inherited_unchanged_evidence'] = INHERITED
        receipt['inherited_scope'] = 'Exact earlier combined-upgrade source/proof/rehearsal evidence; not execution on this repaired node.'
        build_inputs = ROOT / 'target/build-inputs.json'
        require(build_inputs.is_file(), 'fresh-clone compiler/build inputs receipt missing')
        receipt['build_inputs_sha256'] = sha(build_inputs)
        for label, command in [('rustc-version', ['rustc', '-vV']), ('cargo-version', ['cargo', '-vV'])]:
            row, text = run(command, output, label, timeout=30)
            receipt['commands'].append(row); require(row['exit_code'] == 0, 'compiler identity readback failed')
            if label == 'rustc-version':
                require('release: 1.91.1\n' in text and 'host: x86_64-unknown-linux-gnu\n' in text,
                        'actual Rust toolchain/platform differs from approved Linux build')
        # Keep the compiling candidate harness; restore ONLY the original core
        # file. This is a controlled core ablation, not an exact old-node build.
        baseline = Path(tempfile.mkdtemp(prefix='sync-recovery-counterfactual-')).resolve() / 'source'
        row, _ = run(['git', 'worktree', 'add', '--detach', str(baseline), args.expected_source_sha], output, 'core-ablation-worktree', timeout=120)
        receipt['commands'].append(row); require(row['exit_code'] == 0, 'cannot create disposable baseline')
        core_path = Path('node/src/native/node_impl.rs')
        original_core = source.git(ROOT, 'show', source.BASELINE_COMMIT + ':' + core_path.as_posix())
        (baseline / core_path).write_bytes(original_core)
        receipt['core_ablation'] = {'scope': 'Exact candidate harness with only node_impl.rs restored to3fb predecessor bytes',
                                   'node_impl_sha256': sha(baseline / core_path),
                                   'test_overlay_sha256': sha(baseline / 'node/src/native/sync_liveness_tests.rs')}
        for index, name in enumerate(NEW_TESTS[:2]):
            row, text = run(cargo('hegemon-node') + [name, '--', '--exact', '--nocapture'], output,
                            'core-ablation-negative-' + str(index), cwd=baseline)
            receipt['commands'].append(row)
            require(row['exit_code'] == 101 and re.search(r'test result: FAILED\. 0 passed; 1 failed; 0 ignored;', text)
                    and name + ' ... FAILED' in text and 'sync_liveness_tests.rs:' in text,
                    'baseline must execute and fail the intended assertion, not compile/timeout/zero-test fail')
        receipt['core_ablation_expected_failure_verified'] = True
        # Restore the candidate core, then ablate ONLY the new owner-pending
        # conjunct. This retains the compiling wrapper and the actual queue
        # worker fixture, while reproducing the prior admission decision.
        shutil.copyfile(ROOT / core_path, baseline / core_path)
        service_path = Path('node/src/native/service.rs')
        service_text = (ROOT / service_path).read_text()
        owner_guard = '        || target_owner_pending\n'
        require(service_text.count(owner_guard) == 1, 'exact completion-owner ablation seam differs')
        (baseline / service_path).write_text(service_text.replace(owner_guard, '', 1))
        row, text = run(cargo('hegemon-node') + [NEW_TESTS[3], '--', '--exact', '--nocapture'], output,
                        'completion-owner-ablation-negative', cwd=baseline)
        receipt['commands'].append(row)
        require(row['exit_code'] == 101 and re.search(r'test result: FAILED\. 0 passed; 1 failed; 0 ignored;', text)
                and NEW_TESTS[3] + ' ... FAILED' in text and 'sync_liveness_tests.rs:' in text
                and 'a foreign compact hint cannot steal a completion-pending exact target' in text,
                'owner-only ablation must execute and fail the exact queue-owner assertion')
        receipt['completion_owner_ablation'] = {
            'scope': 'Exact candidate harness and core; only new target_owner_pending admission conjunct removed',
            'node_impl_sha256': sha(baseline / core_path), 'service_sha256': sha(baseline / service_path),
            'test_overlay_sha256': sha(baseline / 'node/src/native/sync_liveness_tests.rs'),
            'expected_failure_verified': True}
        for index, name in enumerate(NEW_TESTS + CONTROLS):
            row, text = run(cargo('hegemon-node') + [name, '--', '--exact', '--nocapture'], output, 'exact-' + str(index))
            receipt['commands'].append(row)
            require(row['exit_code'] == 0 and re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored;', text),
                    'required exact native test did not pass once: ' + name)
        for index, (package, prefix) in enumerate(MODULES):
            row, text = run(cargo(package) + ['--', '--list'], output, 'module-list-' + str(index))
            receipt['commands'].append(row); require(row['exit_code'] == 0, 'test inventory failed')
            names = [line[:-6] for line in text.splitlines() if line.startswith(prefix) and line.endswith(': test')]
            require(names and len(names) == len(set(names)), 'empty or duplicate required module inventory')
            row, text = run(cargo(package) + [prefix, '--', '--nocapture', '--test-threads=2'], output, 'module-' + str(index))
            receipt['commands'].append({**row, 'required_tests': names})
            require(row['exit_code'] == 0 and ('test result: ok. ' + str(len(names)) + ' passed; 0 failed; 0 ignored;') in text,
                    'required entire module did not pass with no ignored tests: ' + prefix)
        row, _ = run(['bash', 'scripts/build_release_artifacts.sh'], output, 'build-release', timeout=3600)
        receipt['commands'].append(row); require(row['exit_code'] == 0, 'ordinary Linux release build failed')
        manifest_path = ROOT / 'target/release/hegemon-release-artifacts.json'
        manifest = json.loads(manifest_path.read_text())
        require(manifest['target_triple'] == 'x86_64-unknown-linux-gnu' and manifest['source_head'] == args.expected_source_sha,
                'actual release manifest source/platform differs')
        receipt['artifact_manifest_sha256'] = sha(manifest_path)
        receipt['artifact_sha256'] = {r['binary']: r['sha256'] for r in manifest['artifacts']}
        shutil.copyfile(manifest_path, output / 'hegemon-release-artifacts.json')
        # Same authenticated executor and predicates; software label alone is
        # specialized, as in the existing combined-upgrade final artifact path.
        helper = load('sync_recovery_inherited_h0', ROOT / 'scripts/check_v011_release_successor.py')
        helper.CURRENT_NEW_VERSION = '0.11.4'
        identity = json.loads((ROOT / 'config/v0113-release-successor.json').read_text())['current_identity']
        network = json.loads((ROOT / 'config/testnet/0.11/network-manifest.json').read_text())
        smoke = helper.artifact_gate(ROOT, ROOT, manifest_path,
                    {'authorization_kind': helper.CURRENT_SOURCE_KIND, 'identity': identity}, network, 4)
        require(smoke['identity_smoke']['height'] == 0 and smoke['identity_smoke']['peers'] == 0
                and smoke['identity_smoke']['owned_node_reaped'] is True, 'H0 identity smoke incomplete')
        write(output / 'h0-identity-smoke.json', smoke)
        receipt['h0_identity_smoke'] = smoke
        for label, script, timeout in [('current-binary-proofs', 'check_v011_current_binary_proofs.py', 300),
                                       ('public-chain-replay', 'check_v011_public_chain_replay.py', 1250)]:
            command = [sys.executable, '-I', '-B', 'scripts/' + script, '--node-bin', str(ROOT / 'target/release/hegemon-node'),
                       '--artifact-manifest', str(manifest_path), '--output', str(output / label), '--min-free-gib', '4']
            row, _ = run(command, output, label, timeout=timeout)
            receipt['commands'].append(row); require(row['exit_code'] == 0, label + ' failed')
            proof = json.loads((output / label / 'receipt.json').read_text())
            require(proof.get('processes_reaped') is True and proof.get('node_sha256') == receipt['artifact_sha256']['hegemon-node']
                    and proof.get('artifact_manifest_sha256') == receipt['artifact_manifest_sha256'], 'proof/replay binary binding differs')
            receipt[label.replace('-', '_')] = proof
        require(sha(manifest_path) == receipt['artifact_manifest_sha256'], 'manifest changed after native checks')
        require(sha(build_inputs) == receipt['build_inputs_sha256'], 'compiler/build inputs receipt changed')
        for artifact in manifest['artifacts']:
            require(sha(ROOT / artifact['path']) == artifact['sha256'], 'built artifact changed during qualification')
        after = source.validate_source(ROOT, args.expected_source_sha, args.expected_delta_sha256, pin_provenance=args.pin_provenance)
        require(before == after, 'source changed during qualification')
        write(output / 'source-after.json', after)
        receipt.update(status='PASS_EXECUTED_SYNC_RECOVERY_LINUX_CHECKS_ROOT_ACCEPTANCE_PENDING', source_head=args.expected_source_sha,
                       delta_sha256=args.expected_delta_sha256, source_inventory_sha256=before['source_inventory_sha256'],
                       workflow_sha256=before['workflow_sha256'], actual_native_tests=True,
                       current_binary_proofs_verified=True, actual_fresh_sync_restart_verified=True)
    except BaseException as error:
        receipt.update(status='FAIL', error=str(error))
        raise
    finally:
        if baseline is not None and baseline.exists():
            result = subprocess.run(['git', '-C', str(ROOT), 'worktree', 'remove', '--force', str(baseline)], capture_output=True, timeout=120)
            receipt['baseline_worktree_removed'] = result.returncode == 0
            if result.returncode != 0:
                receipt.update(status='FAIL', cleanup_error='owned predecessor worktree removal failed')
        write(output / 'receipt.json', receipt)
    require(receipt['status'] == 'PASS_EXECUTED_SYNC_RECOVERY_LINUX_CHECKS_ROOT_ACCEPTANCE_PENDING', 'qualification or cleanup failed')
    write(output / 'sync-recovery-artifact-manifest.json', {
        'schema': 'hegemon.sync-recovery.artifact-binding.v1',
        'status': 'EXECUTED_SYNC_RECOVERY_LINUX_ARTIFACTS_ROOT_ACCEPTANCE_PENDING',
        'pin_provenance': args.pin_provenance,
        'external_expected_delta_check_required_root': receipt['external_expected_delta_check_required_root'],
        'root_external_acceptance_performed': False,
        'source_head': receipt['source_head'], 'delta_sha256': receipt['delta_sha256'],
        'workflow_sha256': receipt['workflow_sha256'],
        'source_inventory_sha256': receipt['source_inventory_sha256'],
        'release_artifact_manifest_sha256': receipt['artifact_manifest_sha256'],
        'qualification_receipt_sha256': sha(output / 'receipt.json'),
        'build_inputs_sha256': receipt['build_inputs_sha256'],
        'actual_artifacts': manifest['artifacts'],
        'actual_evidence_sha256': {name: sha(output / name) for name in (
            'source-before.json', 'source-after.json', 'h0-identity-smoke.json',
            'current-binary-proofs/receipt.json', 'public-chain-replay/receipt.json')},
        'production_authorized': False, 'deployment_verified': False,
        'release_publication_authorized': False,
        'scope': 'Exact incident Linux source/build/native tests/H0/current-proof/fresh-sync/restart; not a rerun of the full combined-release gate.'})

if __name__ == '__main__':
    def interrupted(number, _frame):
        raise RuntimeError('qualification interrupted by signal ' + str(number))
    signal.signal(signal.SIGTERM, interrupted)
    main()
