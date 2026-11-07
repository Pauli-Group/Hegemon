#!/usr/bin/env python3
"""Pure policy controls; synthetic receipts are never binary execution evidence."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def module(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


HELPER = module('scripts/check_v011_sync_import_successor.py', '_sync_import_policy_controls')
CONSUMER = module('scripts/check_release_crypto_profile.py', '_sync_import_consumer_controls')
LEGACY_CONTROLS = module('scripts/tests/v011_current_successor/test_successor_consumer.py', '_sync_import_inherited_consumer_controls')
FIXTURES = ROOT / 'scripts/tests/v011_current_successor'
OLD_RECEIPT = json.loads((FIXTURES / 'synthetic-final-receipt.json').read_text())
ARTIFACT_RAW = (FIXTURES / 'synthetic-artifact-manifest.json').read_bytes()
ARTIFACT = json.loads(ARTIFACT_RAW)
REGISTRY = json.loads((FIXTURES / 'synthetic-historical-registry.json').read_text())
CONFIG = json.loads((ROOT / HELPER.CONFIG).read_text())


def synthetic_sync_receipt():
    value = copy.deepcopy(OLD_RECEIPT)
    value.update(authorization_kind=HELPER.KIND, status=HELPER.FINAL_STATUS,
                 final_artifact_scope=HELPER.SCOPE,
                 source_successor_config_sha256=HELPER.CONFIG_SHA256,
                 sync_import_successor=HELPER.attribution(),
                 changed_paths=sorted(CONFIG['reviewed_runtime_deltas']),
                 added_source_paths=sorted(CONFIG['reviewed_source_additions']),
                 reviewed_runtime_deltas=copy.deepcopy(CONFIG['reviewed_runtime_deltas']),
                 reviewed_source_additions=copy.deepcopy(CONFIG['reviewed_source_additions']))
    return value


LEGACY_CONTROLS.CONSUMER = CONSUMER
LEGACY_CONTROLS.RECEIPT = synthetic_sync_receipt()
LEGACY_CONTROLS.ARTIFACT = ARTIFACT
LEGACY_CONTROLS.ARTIFACT_SHA = hashlib.sha256(ARTIFACT_RAW).hexdigest()
LEGACY_CONTROLS.REGISTRY = REGISTRY


class InheritedFinalConsumerControls(LEGACY_CONTROLS.FinalConsumerControls):
    """Run every existing final-artifact adversarial control on the new scope."""


class BindingControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sync-import-policy-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in (HELPER.CONFIG, HELPER.PARENT_CONFIG, HELPER.PARENT_CHECKER, *HELPER.OVERLAY):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)

    def test_exact_binding_inherits_unmodified_runtime_artifact_and_proof_functions(self):
        helper, config, parent = HELPER.load_binding(self.root)
        self.assertEqual(config['sync_import_successor'], HELPER.attribution())
        self.assertEqual(helper.CURRENT_SCOPE, HELPER.SCOPE)
        self.assertEqual(helper.CURRENT_SOURCE_KIND, HELPER.KIND)
        for name in ('current_source_gate', 'validate_current_runtime_change', 'artifact_gate', 'final_replay', 'validate_current_binary_proofs'):
            self.assertEqual(Path(getattr(helper, name).__code__.co_filename), self.root / HELPER.PARENT_CHECKER)
        self.assertEqual(helper.CURRENT_CASE_NAMES, ['ordinary', 'policy_create', 'absolute_height', 'policy_hash_release', 'htlc_release'])
        self.assertEqual(len(helper.CURRENT_NEGATIVE_NAMES), 6)
        for key in parent:
            if key not in ('reviewed_runtime_deltas', 'reviewed_source_additions'):
                self.assertEqual(config[key], parent[key])

    def test_changed_authority_rejects_before_import(self):
        for relative in (HELPER.PARENT_CHECKER, HELPER.PARENT_CONFIG, HELPER.CONFIG):
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(original + b'\n')
            with self.subTest(path=relative), mock.patch.object(HELPER.importlib.util, 'spec_from_file_location', side_effect=AssertionError('untrusted import executed')):
                with self.assertRaises(HELPER.SuccessorError):
                    HELPER.load_binding(self.root)
            path.write_bytes(original)

    def test_each_exact_runtime_postimage_is_required(self):
        for relative in HELPER.OVERLAY:
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(original + b'\n')
            with self.subTest(path=relative), self.assertRaises(HELPER.SuccessorError):
                HELPER.load_binding(self.root)
            path.write_bytes(original)

    def test_inherited_runtime_comparator_rejects_unreviewed_or_arbitrary_changes(self):
        helper, _, _ = HELPER.load_binding(self.root)
        helper.validate_current_runtime_change('node/src/native/unchanged.rs', b'same', b'same')
        for path in ('node/src/native/unreviewed.rs', 'node/Cargo.toml', 'node/src/native/node_impl.rs', 'node/src/native/service.rs'):
            with self.subTest(path=path), self.assertRaises(helper.SuccessorError):
                helper.validate_current_runtime_change(path, b'before', b'unreviewed after')

    def test_symlink_authority_and_runtime_source_reject(self):
        for relative in (HELPER.PARENT_CHECKER, *HELPER.OVERLAY):
            path = self.root / relative
            original = path.read_bytes()
            path.unlink()
            path.symlink_to(ROOT / relative)
            with self.subTest(path=relative), self.assertRaises(HELPER.SuccessorError):
                HELPER.load_binding(self.root)
            path.unlink()
            path.write_bytes(original)

    def test_projection_changes_only_validated_source_fields_and_does_not_mutate_receipt(self):
        receipt = synthetic_sync_receipt()
        before = copy.deepcopy(receipt)
        result = HELPER.project_parent_receipt(receipt)
        allowed = {'authorization_kind', 'status', 'final_artifact_scope', 'source_successor_config_sha256', 'sync_import_successor', 'changed_paths', 'added_source_paths', 'reviewed_runtime_deltas', 'reviewed_source_additions'}
        self.assertEqual(receipt, before)
        self.assertEqual({k: v for k, v in receipt.items() if k not in allowed}, {k: v for k, v in result.items() if k not in allowed})
        self.assertEqual(result, OLD_RECEIPT)

    def test_receipt_overlay_and_parent_attribution_are_exact(self):
        base = synthetic_sync_receipt()
        for field in ('authorization_kind', 'status', 'final_artifact_scope', 'source_successor_config_sha256', 'sync_import_successor', 'changed_paths', 'added_source_paths', 'reviewed_runtime_deltas', 'reviewed_source_additions'):
            value = copy.deepcopy(base)
            del value[field]
            with self.subTest(field=field), self.assertRaises(HELPER.SuccessorError):
                HELPER.project_parent_receipt(value)
        for field in ('parent_checker_sha256', 'parent_config_sha256', 'baseline_commit'):
            value = copy.deepcopy(base)
            value['sync_import_successor'][field] = 'unreviewed'
            with self.subTest(field=field), self.assertRaises(HELPER.SuccessorError):
                HELPER.project_parent_receipt(value)

    def test_new_scope_cannot_be_relabelled_as_the_parent_scope(self):
        value = synthetic_sync_receipt()
        value['final_artifact_scope'] = 'exact_current_source_current_binary_backend_and_h0'
        with self.assertRaises(SystemExit):
            CONSUMER.validate_private_launch_receipt(value, ARTIFACT, LEGACY_CONTROLS.ARTIFACT_SHA, REGISTRY)

    def test_source_and_h0_only_new_receipts_cannot_satisfy_final_consumer(self):
        for status in (HELPER.SOURCE_STATUS, 'PASS_PACKAGING_AND_IDENTITY_SMOKE_ONLY'):
            value = synthetic_sync_receipt()
            value['status'] = status
            with self.subTest(status=status), self.assertRaises(SystemExit):
                CONSUMER.validate_private_launch_receipt(value, ARTIFACT, LEGACY_CONTROLS.ARTIFACT_SHA, REGISTRY)

    def test_parent_consumer_fixture_remains_valid_and_unchanged(self):
        CONSUMER.validate_private_launch_receipt(OLD_RECEIPT, ARTIFACT, LEGACY_CONTROLS.ARTIFACT_SHA, REGISTRY)
        self.assertEqual(HELPER.digest((ROOT / HELPER.PARENT_CHECKER).read_bytes()), HELPER.PARENT_CHECKER_SHA256)
        self.assertEqual(HELPER.digest((ROOT / HELPER.PARENT_CONFIG).read_bytes()), HELPER.PARENT_CONFIG_SHA256)

    def test_live_consumer_routes_to_new_gate_with_mandatory_final_phase(self):
        receipt = synthetic_sync_receipt()
        binaries = tuple(ROOT / ('TEST_ONLY_SYNTHETIC_' + row['binary']) for row in ARTIFACT['artifacts'])
        snapshot = (ARTIFACT, LEGACY_CONTROLS.ARTIFACT_SHA, binaries, ())
        completed = CONSUMER.subprocess.CompletedProcess([], 0, json.dumps(receipt, indent=2), '')
        with mock.patch.object(CONSUMER, 'private_launch_snapshot', return_value=snapshot), \
                mock.patch.object(CONSUMER, 'validate_binary_profile_markers'), \
                mock.patch.object(CONSUMER, 'run_profile', return_value=None), \
                mock.patch.object(CONSUMER.subprocess, 'run', return_value=completed) as runner:
            result = CONSUMER.private_launch_profile(ROOT, FIXTURES / 'synthetic-artifact-manifest.json')
        command = runner.call_args.args[0]
        self.assertEqual(command[3], str(ROOT / 'scripts/check_v011_sync_import_successor.py'))
        self.assertEqual(command[-1], '--require-final-artifact')
        self.assertEqual(command.count('--require-final-artifact'), 1)
        self.assertEqual(result['mode'], 'executed-exact-sync-import-source-backend-h0')
        self.assertIs(result['private_spend_launch_authority'], False)
        self.assertIs(result['current_network_G8_qualified'], False)


if __name__ == '__main__':
    # No Cargo, binary, network, wallet or H0 process belongs in policy controls.
    with mock.patch('subprocess.run', side_effect=AssertionError('policy controls must not execute subprocesses')):
        unittest.main()
