#!/usr/bin/env python3
"""Adversarial validator controls; synthetic receipts grant no execution credit."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def module(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


HELPER = module('scripts/check_v0113_release_successor.py', '_v0113_policy_controls')
CONSUMER = module('scripts/check_release_crypto_profile.py', '_v0113_consumer_controls')
LEGACY = module('scripts/tests/v011_current_successor/test_successor_consumer.py', '_v0113_legacy_controls')
SCOPE_CONTROLS = module('scripts/tests/v011_current_successor/test_successor_scope.py', '_v0113_scope_controls')
FIXTURES = ROOT / 'scripts/tests/v011_current_successor'
OLD_RECEIPT = json.loads((FIXTURES / 'synthetic-final-receipt.json').read_text())
ARTIFACT_RAW = (FIXTURES / 'synthetic-artifact-manifest.json').read_bytes()
ARTIFACT = json.loads(ARTIFACT_RAW)
REGISTRY = json.loads((FIXTURES / 'synthetic-historical-registry.json').read_text())
CONFIG = json.loads((ROOT / HELPER.CONFIG).read_text())


def synthetic_review():
    return {'schema': 'hegemon.v0113.independent-source-review.v1',
            'status': 'accepted_for_scoped_premainnet_qualification',
            'baseline_commit': HELPER.BASELINE_COMMIT,
            'overlay_sha256': HELPER.digest(HELPER.canonical(HELPER.OVERLAY)),
            'source_scope': HELPER.SCOPE, 'production_authorized': False,
            'cryptographic_security_approved': False, 'full_network_lifecycle_verified': False,
            'review_kind': 'independent_model_review', 'reviewer': 'SYNTHETIC VALIDATOR FIXTURE',
            'evidence': ['SYNTHETIC ONLY; no review or execution evidence'],
            'limitations': ['SYNTHETIC ONLY; never publish as source qualification']}


def synthetic_receipt():
    value = copy.deepcopy(OLD_RECEIPT)
    value.update(authorization_kind=HELPER.KIND, status=HELPER.FINAL_STATUS,
                 final_artifact_scope=HELPER.SCOPE, new_version=HELPER.VERSION,
                 source_successor_config_sha256=HELPER.CONFIG_SHA256,
                 v0113_successor=HELPER.attribution(),
                 independent_source_review=HELPER.review_reference(),
                 sync_import_successor=CONFIG['sync_import_successor'],
                 changed_paths=sorted(CONFIG['reviewed_runtime_deltas']),
                 added_source_paths=sorted(CONFIG['reviewed_source_additions']),
                 reviewed_runtime_deltas=copy.deepcopy(CONFIG['reviewed_runtime_deltas']),
                 reviewed_source_additions=copy.deepcopy(CONFIG['reviewed_source_additions']))
    value['identity_smoke'].update(node_rpc_version='Hegemon Native Node ' + HELPER.VERSION,
                                   wallet_cli_version='wallet ' + HELPER.VERSION,
                                   private_spend_cli_version='private-spend ' + HELPER.VERSION)
    value['current_binary_proof_verification']['offline_cli_source_sha256'] = (
        CONFIG['reviewed_runtime_deltas']['node/src/bin/native_node.rs']['after_sha256'])
    return value


LEGACY.CONSUMER = CONSUMER
LEGACY.RECEIPT = synthetic_receipt()
LEGACY.ARTIFACT = ARTIFACT
LEGACY.ARTIFACT_SHA = hashlib.sha256(ARTIFACT_RAW).hexdigest()
LEGACY.REGISTRY = REGISTRY


class InheritedFinalConsumerControls(LEGACY.FinalConsumerControls):
    @classmethod
    def setUpClass(cls):
        # Synthetic unit validation explicitly substitutes only the independent
        # review boundary. The executable source gate never does this.
        review = mock.patch.object(HELPER, 'validate_review', return_value=synthetic_review())
        load = mock.patch.object(CONSUMER, 'v0113_helper', return_value=HELPER)
        review.start(); load.start()
        cls.addClassCleanup(review.stop); cls.addClassCleanup(load.stop)
        super().setUpClass()

    def test_parent_product_version_cannot_be_relabelled_as_v0113(self):
        for field in ('new_version', 'identity_smoke'):
            value = synthetic_receipt()
            value[field] = copy.deepcopy(OLD_RECEIPT[field])
            self.reject(value)

    def test_source_review_overlay_and_deployed_lineage_are_exact(self):
        for field in ('v0113_successor', 'independent_source_review', 'sync_import_successor'):
            for mutation in ('missing', 'changed'):
                value = synthetic_receipt()
                if mutation == 'missing':
                    del value[field]
                else:
                    value[field] = {'unreviewed': True}
                with self.subTest(field=field, mutation=mutation):
                    self.reject(value)

    def test_runtime_proof_or_smoke_values_are_never_projected_to_parent(self):
        value = synthetic_receipt()
        before = copy.deepcopy(value)
        self.validate(value)
        self.assertEqual(value, before)
        for field in ('source_successor_config_sha256', 'changed_paths', 'added_source_paths'):
            value = synthetic_receipt()
            value[field] = copy.deepcopy(OLD_RECEIPT[field])
            self.reject(value)


class BindingControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='v0113-policy-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in (HELPER.CONFIG, HELPER.PARENT_CONFIG, HELPER.PARENT_CHECKER,
                         'scripts/check_v011_release_successor.py',
                         'config/v011-release-successor.json', *HELPER.OVERLAY):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)

    def test_exact_overlay_retains_inherited_comparator_and_executor(self):
        helper, config, parent = HELPER.load_binding(self.root, require_review=False)
        self.assertEqual(helper.CURRENT_NEW_VERSION, '0.11.3')
        self.assertEqual(helper.NEW_VERSION, '0.11.0')
        self.assertEqual(parent['new_version'], '0.11.2')
        self.assertEqual(helper.CURRENT_SCOPE, HELPER.SCOPE)
        self.assertEqual(helper.CURRENT_SOURCE_KIND, HELPER.KIND)
        self.assertEqual(config['current_identity'], parent['current_identity'])
        for name in ('current_source_gate', 'validate_current_runtime_change', 'artifact_gate',
                     'final_replay', 'validate_current_binary_proofs'):
            self.assertEqual(Path(getattr(helper, name).__code__.co_filename),
                             self.root / 'scripts/check_v011_release_successor.py')
        self.assertEqual(len(helper.CURRENT_PROOF_CASES), 5)
        self.assertEqual(len(helper.CURRENT_NEGATIVE_NAMES), 6)

    def test_pending_review_rejects_before_executing_parent_gate(self):
        with mock.patch.object(HELPER, 'SOURCE_REVIEW_SHA256', None):
            with self.assertRaisesRegex(HELPER.SuccessorError, 'review is pending'):
                HELPER.validate_review(self.root)
        with mock.patch.object(HELPER, 'validate_review', side_effect=HELPER.SuccessorError('review is pending')):
            with mock.patch.object(HELPER.importlib.util, 'spec_from_file_location',
                                   side_effect=AssertionError('parent imported before review')):
                with self.assertRaisesRegex(HELPER.SuccessorError, 'review is pending'):
                    HELPER.load_binding(self.root)

    def test_authority_mutation_rejects_before_import(self):
        for relative in (HELPER.CONFIG, HELPER.PARENT_CONFIG, HELPER.PARENT_CHECKER):
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(original + b'\n')
            with self.subTest(path=relative), mock.patch.object(HELPER.importlib.util, 'spec_from_file_location',
                    side_effect=AssertionError('untrusted module imported')):
                with self.assertRaises(HELPER.SuccessorError):
                    HELPER.load_binding(self.root, require_review=False)
            path.write_bytes(original)

    def test_every_runtime_postimage_is_exact_and_missing_source_rejects(self):
        for relative in HELPER.OVERLAY:
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(original + b'\n// unreviewed\n')
            with self.subTest(path=relative, mutation='changed'), self.assertRaises(HELPER.SuccessorError):
                HELPER.load_binding(self.root, require_review=False)
            path.unlink()
            with self.subTest(path=relative, mutation='missing'), self.assertRaises((OSError, HELPER.SuccessorError)):
                HELPER.load_binding(self.root, require_review=False)
            path.write_bytes(original)

    @unittest.skipIf(sys.platform == 'win32', 'symlink creation requires optional Windows privilege')
    def test_symlink_source_and_authority_reject(self):
        for relative in (HELPER.PARENT_CHECKER, 'node/src/native/public_admission.rs'):
            path = self.root / relative
            original = path.read_bytes()
            path.unlink(); path.symlink_to(ROOT / relative)
            with self.subTest(path=relative), self.assertRaises(HELPER.SuccessorError):
                HELPER.load_binding(self.root, require_review=False)
            path.unlink(); path.write_bytes(original)

    def test_cargo_and_unreviewed_runtime_changes_stay_closed(self):
        helper, _, _ = HELPER.load_binding(self.root, require_review=False)
        for path in ('Cargo.lock', 'node/Cargo.toml', 'node/src/native/unknown.rs'):
            with self.subTest(path=path), self.assertRaises(helper.SuccessorError):
                helper.validate_current_runtime_change(path, b'before', b'after')

    def test_historical_checker_config_registry_and_artifact_pins_remain_unchanged(self):
        self.assertEqual(HELPER.digest((ROOT / HELPER.PARENT_CHECKER).read_bytes()), HELPER.PARENT_CHECKER_SHA256)
        self.assertEqual(HELPER.digest((ROOT / HELPER.PARENT_CONFIG).read_bytes()), HELPER.PARENT_CONFIG_SHA256)
        CONSUMER.validate_private_launch_receipt(OLD_RECEIPT, ARTIFACT, LEGACY.ARTIFACT_SHA, REGISTRY)

    def test_consumer_authenticates_additive_helper_before_import(self):
        # Test the production helper loader rather than a synthetic receipt path.
        for relative in CONSUMER.V0113_AUTHORITY_SHA256:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        CONSUMER.v0113_helper(self.root)
        path = self.root / 'scripts/check_v0113_release_successor.py'
        path.write_bytes(path.read_bytes() + b'\n')
        with mock.patch.object(HELPER.importlib.util, 'spec_from_file_location',
                               side_effect=AssertionError('untrusted adapter imported')):
            with self.assertRaises(SystemExit):
                CONSUMER.v0113_helper(self.root)


class ReviewControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='v0113-review-control-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / HELPER.SOURCE_REVIEW_PATH
        self.path.parent.mkdir(parents=True)

    def validate(self, value):
        raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        self.path.write_bytes(raw)
        with mock.patch.object(HELPER, 'SOURCE_REVIEW_SHA256', HELPER.digest(raw)):
            return HELPER.validate_review(self.root)

    def test_synthetic_review_schema_is_valid_before_mutations(self):
        self.assertEqual(self.validate(synthetic_review()), synthetic_review())

    def test_each_identity_scope_boundary_and_attribution_is_required(self):
        base = synthetic_review()
        for field in base:
            value = copy.deepcopy(base); del value[field]
            with self.subTest(field=field), self.assertRaises(HELPER.SuccessorError):
                self.validate(value)
        for field in ('production_authorized', 'cryptographic_security_approved', 'full_network_lifecycle_verified'):
            for replacement in (True, 0, 'false', None):
                value = copy.deepcopy(base); value[field] = replacement
                with self.subTest(field=field, value=replacement), self.assertRaises(HELPER.SuccessorError):
                    self.validate(value)

    def test_review_hash_and_duplicate_keys_reject(self):
        self.path.write_text(json.dumps(synthetic_review()))
        with mock.patch.object(HELPER, 'SOURCE_REVIEW_SHA256', '00' * 32):
            with self.assertRaises(HELPER.SuccessorError):
                HELPER.validate_review(self.root)
        with self.assertRaises(HELPER.SuccessorError):
            HELPER.strict_json('{"status": "pending", "status": "accepted"}')


class SecurityScopeControls(unittest.TestCase):
    def test_v0113_scope_is_distinct_and_cannot_promote_authority(self):
        raw = (ROOT / 'scripts/security-audit.sh').read_text()
        match = re.search(r"PROFILE_SCOPE=\$\(python3 -c '(.*?)' <<<", raw, re.S)
        self.assertIsNotNone(match)
        controls = module('scripts/tests/v011_current_successor/test_security_audit_scope.py', '_v0113_security_scope')
        controls.PREDICATE = compile(match[1], '<pure-security-scope>', 'exec')
        pair = ('executed-exact-v0113-premainnet-source-backend-h0',
                'exact-v0113-premainnet-source-current-binary-backend-and-h0-only')
        base = controls.current_backend(pair)
        self.assertEqual(controls.classify(base), 'current-backend')
        for field in base:
            value = copy.deepcopy(base); del value[field]
            with self.subTest(field=field), self.assertRaises(SystemExit):
                controls.classify(value)
        for field in ('production_authority', 'private_spend_launch_authority', 'current_network_G8_qualified',
                      'fresh_network_lifecycle_verified', 'state_admission_verified', 'public_cutover_authorized'):
            for replacement in (True, 0, 'false'):
                value = copy.deepcopy(base); value[field] = replacement
                with self.subTest(field=field, value=replacement), self.assertRaises(SystemExit):
                    controls.classify(value)
        for old in controls.CURRENT_BACKEND_PAIRS:
            value = copy.deepcopy(base); value['authorization_scope'] = old[1]
            with self.assertRaises(SystemExit):
                controls.classify(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--predecessor-root', type=Path)
    args = parser.parse_args()
    if args.source_root.resolve() != ROOT:
        raise SystemExit('controls must run against their own source root')
    inherited, config, _ = HELPER.load_binding(ROOT, require_review=False)
    fixture_raw = (ROOT / 'release-evidence/v0.11-current-proof-fixture/manifest.json').read_bytes()
    SCOPE_CONTROLS.CHECKER = inherited
    SCOPE_CONTROLS.SOURCE_ROOT = ROOT
    SCOPE_CONTROLS.SOURCE_CONFIG = ROOT / HELPER.CONFIG
    SCOPE_CONTROLS.SOURCE_CONFIG_DATA = config
    SCOPE_CONTROLS.FIXTURE_MANIFEST = json.loads(fixture_raw)
    SCOPE_CONTROLS.FIXTURE_SHA = hashlib.sha256(fixture_raw).hexdigest()
    classes = [BindingControls, ReviewControls, InheritedFinalConsumerControls,
               SecurityScopeControls, SCOPE_CONTROLS.CurrentBinaryProofChecks]
    if args.predecessor_root:
        SCOPE_CONTROLS.PREDECESSOR = args.predecessor_root.resolve(strict=True)
        class CurrentRuntimeControls(SCOPE_CONTROLS.RuntimePostimageChecks):
            def test_current_hotfix_version_is_separate_from_legacy(self):
                self.assertEqual(inherited.NEW_VERSION, '0.11.0')
                self.assertEqual(inherited.CURRENT_NEW_VERSION, '0.11.3')
                self.assertEqual(config['new_version'], '0.11.3')
        classes += [CurrentRuntimeControls, SCOPE_CONTROLS.ImmutableAuthorityChecks]
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in classes)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
