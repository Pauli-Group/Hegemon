#!/usr/bin/env python3
"""Adversarial validator controls, not proof execution or release evidence.

Run against the reviewed staged checker/consumer.  A hand-built receipt below
tests acceptance rules only; it cannot establish that a proof was executed.
Actual release qualification must separately run the real final node.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

DEFAULT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PREDECESSOR = DEFAULT_ROOT / 'target/v011-predecessor'
CASES = ('ordinary', 'policy_create', 'absolute_height', 'policy_hash_release', 'htlc_release')
CONTROLS = ('changed_statement', 'changed_proof', 'truncated_proof', 'oversize_proof', 'truncated_statement', 'oversize_statement')
NODE_SHA = '11' * 32
ARTIFACT_SHA = '22' * 32
RELATION_DIGEST = '33' * 64
FIXTURE_SHA = '44' * 32
LOCK_SHA = '1c243bf3858f4ee22fa4441c7a2ee6d49b16d264147b0f3a2de845e760821719'


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot load checker: ' + str(path))
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def tagged_sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def proof_checks():
    """Synthetic schema fixture: never publish this as execution evidence."""
    synthetic_inputs = {'TEST_ONLY_SYNTHETIC_INPUT': {
        'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}}
    return {
        'schema': 'hegemon.v011.current-binary-proof-verification.v1',
        'status': 'PASS_CURRENT_BINARY_BACKEND_PROOFS',
        'actual_proof_verification': True,
        'node_sha256': NODE_SHA,
        'artifact_manifest_sha256': ARTIFACT_SHA,
        'cargo_lock_sha256': LOCK_SHA,
        'network_manifest_sha256': SOURCE_CONFIG_DATA['current_network_manifest_sha256'],
        'offline_cli_source_sha256': SOURCE_CONFIG_DATA['reviewed_runtime_deltas']['node/src/bin/native_node.rs']['after_sha256'],
        'relation_digest': RELATION_DIGEST,
        'fixture_manifest_sha256': FIXTURE_SHA,
        'cases_verified': 5,
        'cases': [{
            **copy.deepcopy(descriptor),
            'verified': True,
            'exit_code': 0,
            'processes_reaped': True,
            'negative_controls': {control: {'rejected': True, 'exit_code': 1, 'processes_reaped': True} for control in CONTROLS},
        } for descriptor in FIXTURE_MANIFEST['cases']],
        'inputs_before': copy.deepcopy(synthetic_inputs),
        'inputs_after': copy.deepcopy(synthetic_inputs),
        'test_fixture_only': 'Synthetic validator schema fixture, never execution evidence.',
        'processes_reaped': True,
        'cryptographic_verification_only': True,
        'fresh_network_lifecycle_verified': False,
        'state_admission_verified': False,
        'production_authorized': False,
        'public_cutover_authorized': False,
    }


class CurrentBinaryProofChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = staticmethod(CHECKER.validate_current_binary_proofs)
        # Validate the base before any negative test can pass for the wrong reason.
        cls.validator(proof_checks(), NODE_SHA, ARTIFACT_SHA, RELATION_DIGEST, FIXTURE_SHA)

    def validate(self, payload):
        return self.validator(payload, NODE_SHA, ARTIFACT_SHA, RELATION_DIGEST, FIXTURE_SHA)

    def reject(self, payload):
        with self.assertRaises(CHECKER.SuccessorError):
            self.validate(payload)

    def test_valid_schema_fixture_is_accepted(self):
        self.validate(proof_checks())

    def test_pinned_case_descriptors_match_independent_fixture_manifest(self):
        self.assertEqual(CHECKER.CURRENT_PROOF_CASES, FIXTURE_MANIFEST['cases'])
        self.assertEqual(CHECKER.CURRENT_FIXTURE_SHA256, FIXTURE_SHA)

    def test_each_proof_and_statement_descriptor_is_authenticated(self):
        for index in range(5):
            for kind in ('proof', 'statement'):
                for field, value in (('sha256', '00' * 32), ('path', 'unreviewed.data')):
                    with self.subTest(index=index, kind=kind, field=field):
                        payload = proof_checks()
                        payload['cases'][index][kind][field] = value
                        self.reject(payload)

    def test_one_case_cannot_reuse_another_cases_proof_or_statement(self):
        for kind in ('proof', 'statement'):
            with self.subTest(kind=kind):
                payload = proof_checks()
                payload['cases'][1][kind] = copy.deepcopy(payload['cases'][0][kind])
                self.reject(payload)

    def test_each_external_identity_binding_is_required(self):
        for field in ('node_sha256', 'artifact_manifest_sha256', 'relation_digest', 'fixture_manifest_sha256', 'cargo_lock_sha256', 'network_manifest_sha256', 'offline_cli_source_sha256'):
            with self.subTest(field=field):
                payload = proof_checks()
                payload[field] = ('00' * 64) if field == 'relation_digest' else ('00' * 32)
                self.reject(payload)

    def test_source_and_h0_statuses_cannot_claim_proof_execution(self):
        for status in ('PASS_REVIEWED_SOURCE_SUCCESSOR_CI', 'PASS_PACKAGING_AND_IDENTITY_SMOKE_ONLY', 'PASS_CURRENT_BUILD_AND_H0_ONLY'):
            with self.subTest(status=status):
                payload = proof_checks()
                payload['status'] = status
                self.reject(payload)

    def test_missing_duplicate_extra_and_reordered_cases_are_rejected(self):
        for mode in ('missing', 'duplicate', 'extra', 'reordered'):
            with self.subTest(mode=mode):
                payload = proof_checks()
                if mode == 'missing':
                    payload['cases'].pop()
                elif mode == 'duplicate':
                    payload['cases'][-1] = copy.deepcopy(payload['cases'][0])
                elif mode == 'extra':
                    payload['cases'].append(copy.deepcopy(payload['cases'][0]))
                else:
                    payload['cases'].reverse()
                self.reject(payload)

    def test_case_count_is_an_integer_equal_to_five(self):
        for value in (4, 6, True, '5', None):
            with self.subTest(value=value):
                payload = proof_checks()
                payload['cases_verified'] = value
                self.reject(payload)

    def test_each_case_requires_actual_zero_exit_success(self):
        for case in range(5):
            for field, value in (('verified', False), ('verified', 1), ('verified', 'true'), ('exit_code', 1), ('exit_code', False)):
                with self.subTest(case=case, field=field, value=value):
                    payload = proof_checks()
                    payload['cases'][case][field] = value
                    self.reject(payload)

    def test_every_negative_control_is_mandatory(self):
        for case in range(5):
            for name in CONTROLS:
                with self.subTest(case=case, control=name):
                    payload = proof_checks()
                    del payload['cases'][case]['negative_controls'][name]
                    self.reject(payload)

    def test_each_negative_control_requires_rejection_and_exact_exit_one(self):
        for name in CONTROLS:
            for field, value in (('rejected', False), ('rejected', 1), ('rejected', 'true'), ('exit_code', 0), ('exit_code', 2), ('exit_code', 101), ('exit_code', -9), ('exit_code', -1073741819), ('exit_code', False), ('exit_code', '1')):
                with self.subTest(control=name, field=field, value=value):
                    payload = proof_checks()
                    payload['cases'][0]['negative_controls'][name][field] = value
                    self.reject(payload)

    def test_inputs_are_nonempty_dicts_and_identical_before_and_after(self):
        for mode in ('changed_hash', 'missing_input', 'empty', 'list'):
            with self.subTest(mode=mode):
                payload = proof_checks()
                if mode == 'changed_hash':
                    payload['inputs_after']['TEST_ONLY_SYNTHETIC_INPUT']['sha256'] = '00' * 32
                elif mode == 'missing_input':
                    payload['inputs_after'].clear()
                elif mode == 'empty':
                    payload['inputs_before'].clear()
                    payload['inputs_after'].clear()
                else:
                    payload['inputs_before'] = []
                    payload['inputs_after'] = []
                self.reject(payload)

    def test_each_case_and_negative_control_must_reap_its_process(self):
        for case in range(5):
            for control in (None, *CONTROLS):
                for value in (False, 1, 'true', None):
                    with self.subTest(case=case, control=control, value=value):
                        payload = proof_checks()
                        row = payload['cases'][case]
                        if control is not None:
                            row = row['negative_controls'][control]
                        row['processes_reaped'] = value
                        self.reject(payload)

    def test_proof_and_statement_lengths_are_exact(self):
        for row, field, values in (('proof', 'bytes', (171280, 171282, True, '171281')), ('statement', 'bytes', (687, 689, True, '688'))):
            for value in values:
                with self.subTest(row=row, value=value):
                    payload = proof_checks()
                    payload['cases'][0][row][field] = value
                    self.reject(payload)

    def test_backend_receipt_cannot_be_promoted_to_state_lifecycle_or_launch(self):
        for field, correct in (('actual_proof_verification', True), ('processes_reaped', True), ('cryptographic_verification_only', True), ('fresh_network_lifecycle_verified', False), ('state_admission_verified', False), ('production_authorized', False), ('public_cutover_authorized', False)):
            for value in (not correct, int(correct), str(correct).lower(), None):
                with self.subTest(field=field, value=value):
                    payload = proof_checks()
                    payload[field] = value
                    self.reject(payload)


class RuntimePostimageChecks(unittest.TestCase):
    def test_current_hotfix_version_is_separate_from_legacy(self):
        self.assertEqual(CHECKER.NEW_VERSION, '0.11.0')
        self.assertEqual(CHECKER.CURRENT_NEW_VERSION, '0.11.1')
        self.assertEqual(SOURCE_CONFIG_DATA['new_version'], '0.11.1')

    @staticmethod
    def validate(relative, before, after):
        # Exercise the current mode when the staged checker provides it.
        validator = getattr(CHECKER, 'validate_current_runtime_change', CHECKER.validate_runtime_change)
        return validator(relative, before, after)

    def test_unchanged_bytes_are_reusable(self):
        self.validate('node/src/native/unchanged.rs', b'unchanged', b'unchanged')

    def test_arbitrary_runtime_change_is_rejected(self):
        with self.assertRaises(CHECKER.SuccessorError):
            self.validate('node/src/native/unreviewed.rs', b'before', b'after')

    def test_cargo_manifest_change_is_rejected(self):
        with self.assertRaises(CHECKER.SuccessorError):
            self.validate('node/Cargo.toml', b'before', b'after')

    def test_a_reviewed_path_does_not_allow_an_arbitrary_postimage(self):
        for relative in ('protocol/versioning/src/lib.rs', 'node/src/native/node_impl.rs', 'node/src/native/mod.rs', 'node/src/native/tests.rs', 'wallet/src/bin/private_spend.rs'):
            with self.subTest(relative=relative):
                before = (PREDECESSOR / relative).read_bytes()
                after = (SOURCE_ROOT / relative).read_bytes()
                self.validate(relative, before, after)
                with self.assertRaises(CHECKER.SuccessorError):
                    self.validate(relative, before, after + b'\n// unreviewed mutation\n')


class ImmutableAuthorityChecks(unittest.TestCase):
    def test_immutable_predecessor_commands_force_utf8_without_changing_bytes(self):
        import ast
        import os
        import subprocess
        tree = ast.parse(Path(CHECKER.__file__).read_text(encoding='utf-8'))
        commands = [node.value for node in ast.walk(tree)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.List)
            and any(isinstance(item, ast.Constant) and item.value == '--require-authorized'
                    for item in node.value.elts)]
        self.assertEqual(len(commands), 2)
        with tempfile.TemporaryDirectory(prefix='v011-utf8-child-') as directory:
            predecessor = Path(directory)
            child = predecessor / CHECKER.CHECKER
            child.parent.mkdir(parents=True)
            child.write_text("from pathlib import Path\nimport sys\n"
                "assert sys.flags.utf8_mode == 1\n"
                "assert sys.argv[1:] == ['--require-authorized']\n"
                "assert Path('evidence.txt').read_text() == '\u2080'\n",
                encoding='utf-8')
            evidence = predecessor / 'evidence.txt'
            evidence.write_bytes('\u2080'.encode('utf-8'))
            snapshots = {path: path.read_bytes() for path in (child, evidence)}
            for command in commands:
                argv = eval(compile(ast.Expression(command), '<immutable-child-argv>', 'eval'),
                    {'sys': sys, 'str': str, 'predecessor': predecessor, 'CHECKER': CHECKER.CHECKER})
                result = subprocess.run(argv, cwd=predecessor, capture_output=True, timeout=15,
                    env={**os.environ, 'PYTHONUTF8': '0', 'PYTHONIOENCODING': 'cp1252'})
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))
                self.assertEqual({path: path.read_bytes() for path in snapshots}, snapshots)

    def attempt_tampered_gate(self, tamper, expected_message):
        with tempfile.TemporaryDirectory(prefix='v011-validator-control-') as directory:
            base = Path(directory)
            root, predecessor = base / 'current', base / 'predecessor'
            (root / CHECKER.CONFIG).parent.mkdir(parents=True)
            (root / CHECKER.CONFIG).write_bytes(SOURCE_CONFIG.read_bytes())
            for relative in (CHECKER.CHECKER, CHECKER.REGISTRY):
                for tree, source in ((predecessor, PREDECESSOR), (root, SOURCE_ROOT)):
                    path = tree / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes((source / relative).read_bytes())
            tamper(root, predecessor)
            # A pin failure must precede running any predecessor process.
            with mock.patch.object(CHECKER.subprocess, 'run', side_effect=AssertionError('tampered authority reached execution')):
                with self.assertRaisesRegex(CHECKER.SuccessorError, expected_message):
                    CHECKER.source_gate(root, predecessor)

    def test_predecessor_checker_is_immutable(self):
        self.attempt_tampered_gate(lambda root, old: (old / CHECKER.CHECKER).write_bytes(b'unreviewed checker'), 'immutable predecessor authority differs')

    def test_predecessor_registry_is_immutable(self):
        self.attempt_tampered_gate(lambda root, old: (old / CHECKER.REGISTRY).write_bytes(b'unreviewed registry'), 'immutable predecessor authority differs')

    def test_current_registry_cannot_rewrite_historical_authority(self):
        self.attempt_tampered_gate(lambda root, old: (root / CHECKER.REGISTRY).write_bytes(b'unreviewed registry'), 'historical registry must remain')

    def test_current_dispatcher_cannot_be_arbitrarily_replaced(self):
        self.attempt_tampered_gate(lambda root, old: (root / CHECKER.CHECKER).write_bytes(b'unreviewed dispatcher'), 'current checker differs beyond')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checker', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=DEFAULT_ROOT)
    parser.add_argument('--source-config', type=Path)
    parser.add_argument('--predecessor-root', type=Path, default=DEFAULT_PREDECESSOR)
    parser.add_argument('--fixture-manifest', type=Path, default=DEFAULT_ROOT / 'release-evidence/v0.11-current-proof-fixture/manifest.json')
    parser.add_argument('--authority-only', action='store_true')
    args = parser.parse_args()
    global CHECKER, SOURCE_ROOT, SOURCE_CONFIG, SOURCE_CONFIG_DATA, PREDECESSOR, FIXTURE_MANIFEST, FIXTURE_SHA
    CHECKER = load_module(args.checker.resolve(), '_successor_scope_under_test')
    SOURCE_ROOT = args.source_root.resolve()
    SOURCE_CONFIG = args.source_config.resolve() if args.source_config else SOURCE_ROOT / CHECKER.CONFIG
    SOURCE_CONFIG_DATA = json.loads(SOURCE_CONFIG.read_text())
    PREDECESSOR = args.predecessor_root.resolve()
    if not args.authority_only:
        fixture_raw = args.fixture_manifest.read_bytes()
        FIXTURE_SHA = hashlib.sha256(fixture_raw).hexdigest()
        FIXTURE_MANIFEST = json.loads(fixture_raw)
    classes = [RuntimePostimageChecks, ImmutableAuthorityChecks]
    if not args.authority_only:
        classes.insert(0, CurrentBinaryProofChecks)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in classes)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
