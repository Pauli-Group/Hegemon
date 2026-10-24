#!/usr/bin/env python3
"""Artifact-gate identity dataflow unit controls, with no actual execution.

Only bounded temporary test files are real. Process, RPC, disk-space and port
boundaries are mocked; passing these tests is never H0 or proof evidence.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


CURRENT = {'chain_id': '11' * 32, 'genesis_hash': '22' * 32,
    'manifest_digest': '33' * 64, 'relation_id': 'TEST_ONLY_CURRENT_RELATION',
    'relation_digest': '44' * 64}
HISTORICAL = {'chain_id': '55' * 32, 'genesis_hash': '66' * 32,
    'manifest_digest': '77' * 64, 'relation_id': 'TEST_ONLY_HISTORICAL_RELATION',
    'relation_digest': '88' * 64}
ARTIFACT_HELPER_SHA256 = '17178256d95ad03cf663991c3bf68224116f07d6671a7f281c70179987eadbb1'
LAUNCHER_POLICY_SHA256 = '51700e93ac457574f262bff05f48e5e55fa328e37da30f665721a312de9d826e'


class FakeOwnedProcess:
    """Exercise the checker's real stop_owned path without spawning a process."""
    def __init__(self):
        self.returncode = None
        self.terminated = False
        self.wait_timeouts = []

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout):
        self.wait_timeouts.append(timeout)
        if self.returncode is None:
            raise AssertionError('owned fake process was not terminated')
        return self.returncode


class ArtifactGateIdentityControls(unittest.TestCase):
    def exercise_gate(self, receipt, expected_identity):
        with tempfile.TemporaryDirectory(prefix='TEST_ONLY-artifact-gate-') as temporary:
            root = Path(temporary)
            (root / 'scripts').mkdir()
            (root / 'target').mkdir()
            (root / 'scripts/release_artifact_manifest.py').write_bytes(ARTIFACT_HELPER_BYTES)
            (root / 'scripts/check_release_launcher_policy.py').write_bytes(LAUNCHER_POLICY_BYTES)
            artifacts = []
            for package, name in (('hegemon-node', 'hegemon-node'), ('wallet', 'wallet'), ('walletd', 'walletd'), ('wallet', 'private-spend')):
                path = root / 'target' / name
                raw = ('TEST ONLY INERT FILE ' + name).encode()
                path.write_bytes(raw)
                artifacts.append({'package': package, 'binary': name,
                    'path': path.relative_to(root).as_posix(),
                    'sha256': hashlib.sha256(raw).hexdigest()})
            artifact = {'target_triple': 'synthetic-unit-test-target', 'artifacts': artifacts}
            artifact_file = root / 'artifact.json'
            artifact_file.write_text(json.dumps(artifact))
            network_manifest = {'rules_hash': '0x' + '99' * 32, 'test_fixture_only': True}
            process = FakeOwnedProcess()
            rpc_calls = []

            def rpc(port, method, params=None):
                self.assertEqual(port, 41002)
                rpc_calls.append((method, params))
                if method == 'hegemon_nodeConfig':
                    return {'networkProfile': 'pre-mainnet', 'networkManifest': network_manifest,
                        'chainId': '0x' + expected_identity['chain_id'],
                        'networkManifestDigest': '0x' + expected_identity['manifest_digest']}
                if method == 'chain_getBlockHash':
                    self.assertEqual(params, [0])
                    return '0x' + expected_identity['genesis_hash']
                if method == 'system_version':
                    return 'Hegemon Native Node 0.11.0'
                if method == 'hegemon_privateSpendParameters':
                    return {'relation_id': expected_identity['relation_id'],
                        'relation_digest': expected_identity['relation_digest'], 'public_words': 86,
                        'max_proof_bytes': 171848, 'max_carrier_bytes': 177632,
                        'input_slots': 2, 'output_slots': 2, 'production_authorized': False}
                if method == 'chain_getHeader':
                    return {'number': '0x0'}
                if method == 'system_health':
                    return {'peers': 0}
                raise AssertionError('unexpected RPC method: ' + method)

            def run(command, **kwargs):
                if command[0] == sys.executable and 'verify' in command:
                    self.assertEqual(command[command.index('--manifest') + 1], str(artifact_file))
                    return subprocess.CompletedProcess(command, 0, stdout=b'', stderr=b'')
                if command == [str(root / 'target/wallet'), '--version']:
                    return subprocess.CompletedProcess(command, 0, stdout=b'wallet 0.11.0\n', stderr=b'')
                if command == [str(root / 'target/private-spend'), '--version']:
                    return subprocess.CompletedProcess(command, 0, stdout=b'private-spend 0.11.0\n', stderr=b'')
                if '--network-manifest' in command:
                    wrong = Path(command[command.index('--network-manifest') + 1])
                    self.assertEqual(wrong.name, 'wrong-manifest.json')
                    self.assertEqual(json.loads(wrong.read_text())['rules_hash'], '0x' + '00' * 32)
                    return subprocess.CompletedProcess(command, 1, stdout=b'', stderr=b'rules_hash mismatch')
                raise AssertionError('unexpected subprocess command: ' + repr(command))

            with mock.patch.object(CHECKER.subprocess, 'run', side_effect=run) as run_mock, \
                    mock.patch.object(CHECKER.subprocess, 'Popen', return_value=process) as popen_mock, \
                    mock.patch.object(CHECKER, 'rpc', side_effect=rpc), \
                    mock.patch.object(CHECKER, 'free_port', side_effect=[41001, 41002]), \
                    mock.patch.object(CHECKER.shutil, 'disk_usage', return_value=SimpleNamespace(free=64 * 1024**3)):
                result = CHECKER.artifact_gate(root, root / 'unused-predecessor', artifact_file,
                    receipt, network_manifest, 4)

            self.assertEqual(run_mock.call_count, 4)
            popen_mock.assert_called_once()
            environment = popen_mock.call_args.kwargs['env']
            self.assertEqual(environment['HEGEMON_MINE'], '0')
            self.assertEqual(environment['HEGEMON_SEEDS'], '')
            self.assertTrue(process.terminated)
            self.assertEqual(process.wait_timeouts, [15])
            self.assertEqual(len(rpc_calls), 6)
            self.assertEqual(result['status'], 'PASS_PACKAGING_AND_IDENTITY_SMOKE_ONLY')
            self.assertIs(result['actual_new_binary_proof_verification'], False)
            self.assertEqual(result['identity_smoke']['genesis'], expected_identity['genesis_hash'])
            self.assertEqual(result['identity_smoke']['proof_parameters']['relation_digest'], expected_identity['relation_digest'])
            self.assertIs(result['identity_smoke']['owned_node_reaped'], True)
            self.assertEqual(result['identity_smoke']['private_spend_cli_version'], 'private-spend 0.11.0')
            self.assertEqual(result['identity_smoke']['height'], 0)
            self.assertEqual(result['identity_smoke']['peers'], 0)
            self.assertEqual(result['artifact_sha256'], {row['binary']: row['sha256'] for row in artifacts})
            return result

    def test_current_mode_uses_current_identity_without_qualified_alias(self):
        receipt = {'authorization_kind': CHECKER.CURRENT_SOURCE_KIND,
            'identity': copy.deepcopy(CURRENT), 'historical_qualified_identity': copy.deepcopy(HISTORICAL)}
        self.assertNotIn('qualified_identity', receipt)
        result = self.exercise_gate(receipt, CURRENT)
        self.assertNotIn('qualified_identity', result)
        self.assertEqual(result['historical_qualified_identity'], HISTORICAL)

    def test_legacy_mode_still_uses_qualified_identity(self):
        receipt = {'authorization_kind': 'qualified_source_tuple', 'identity': copy.deepcopy(CURRENT),
            'qualified_identity': copy.deepcopy(HISTORICAL)}
        result = self.exercise_gate(receipt, HISTORICAL)
        self.assertEqual(result['identity'], CURRENT)
        self.assertEqual(result['qualified_identity'], HISTORICAL)

    def reject_changed_helper(self, relative, expected_message):
        with tempfile.TemporaryDirectory(prefix='TEST_ONLY-altered-artifact-helper-') as temporary:
            root = Path(temporary)
            (root / 'scripts').mkdir()
            (root / 'scripts/release_artifact_manifest.py').write_bytes(ARTIFACT_HELPER_BYTES)
            (root / 'scripts/check_release_launcher_policy.py').write_bytes(LAUNCHER_POLICY_BYTES)
            helper = root / relative
            helper.write_bytes(helper.read_bytes() + b'\n# TEST ONLY UNREVIEWED MUTATION\n')
            receipt = {'authorization_kind': CHECKER.CURRENT_SOURCE_KIND, 'identity': copy.deepcopy(CURRENT)}
            # No manifest is created: rejection must precede even reading it.
            with mock.patch.object(CHECKER.subprocess, 'run', side_effect=AssertionError('unreviewed helper reached execution')) as run_mock, \
                    mock.patch.object(CHECKER.subprocess, 'Popen', side_effect=AssertionError('unreviewed helper reached node execution')) as popen_mock, \
                    mock.patch.object(CHECKER, 'rpc', side_effect=AssertionError('unreviewed helper reached RPC')) as rpc_mock:
                with self.assertRaisesRegex(CHECKER.SuccessorError, expected_message):
                    CHECKER.artifact_gate(root, root / 'unused-predecessor', root / 'absent-artifact.json',
                        receipt, {'test_fixture_only': True}, 4)
            run_mock.assert_not_called()
            popen_mock.assert_not_called()
            rpc_mock.assert_not_called()

    def test_current_mode_rejects_altered_artifact_helper_before_execution(self):
        self.reject_changed_helper('scripts/release_artifact_manifest.py', 'artifact-manifest helper differs before execution')

    def test_current_mode_rejects_altered_transitive_launcher_helper_before_execution(self):
        self.reject_changed_helper('scripts/check_release_launcher_policy.py', 'launcher-policy helper differs before execution')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checker', type=Path, required=True)
    parser.add_argument('--artifact-helper', type=Path, default=Path(__file__).resolve().parents[3] / 'scripts/release_artifact_manifest.py')
    parser.add_argument('--launcher-helper', type=Path, default=Path('/Users/pldd/.codex/worktrees/premainnet-v011-release/Hegemon/scripts/check_release_launcher_policy.py'))
    args = parser.parse_args()
    global CHECKER, ARTIFACT_HELPER_BYTES, LAUNCHER_POLICY_BYTES
    ARTIFACT_HELPER_BYTES = args.artifact_helper.read_bytes()
    if hashlib.sha256(ARTIFACT_HELPER_BYTES).hexdigest() != ARTIFACT_HELPER_SHA256:
        raise SystemExit('canonical artifact helper differs from independently frozen test pin')
    LAUNCHER_POLICY_BYTES = args.launcher_helper.read_bytes()
    if hashlib.sha256(LAUNCHER_POLICY_BYTES).hexdigest() != LAUNCHER_POLICY_SHA256:
        raise SystemExit('canonical launcher-policy helper differs from independently frozen test pin')
    spec = importlib.util.spec_from_file_location('_artifact_gate_under_test', args.checker.resolve())
    if spec is None or spec.loader is None:
        raise SystemExit('cannot import staged checker')
    CHECKER = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = CHECKER
    spec.loader.exec_module(CHECKER)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ArtifactGateIdentityControls))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
