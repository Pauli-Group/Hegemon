#!/usr/bin/env python3
"""Final-consumer adversarial controls, never execution evidence.

The receipt fixture may be synthetic, but must first pass the consumer before
single-field mutations are tested.  This prevents vacuous rejection tests.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest


class FinalConsumerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A broken base must stop the class before negative controls execute.
        CONSUMER.validate_private_launch_receipt(RECEIPT, ARTIFACT, ARTIFACT_SHA, REGISTRY)

    def validate(self, value):
        return CONSUMER.validate_private_launch_receipt(value, ARTIFACT, ARTIFACT_SHA, REGISTRY)

    def reject(self, value):
        with self.assertRaises(SystemExit):
            self.validate(value)

    def test_canonical_fixture_is_valid_before_mutations(self):
        self.validate(RECEIPT)

    def test_source_only_and_h0_only_are_rejected(self):
        for status in ('PASS_REVIEWED_SOURCE_SUCCESSOR_CI', 'PASS_VERSION_AND_PLATFORM_SHUTDOWN_SOURCE_SUCCESSOR', 'PASS_PACKAGING_AND_IDENTITY_SMOKE_ONLY', 'PASS_CURRENT_BUILD_AND_H0_ONLY'):
            with self.subTest(status=status):
                value = copy.deepcopy(RECEIPT)
                value['status'] = status
                value['actual_new_binary_proof_verification'] = False
                self.reject(value)

    def test_artifact_manifest_is_bound(self):
        value = copy.deepcopy(RECEIPT)
        value['artifact_manifest_sha256'] = '00' * 32
        self.reject(value)

    def test_every_shipped_binary_is_bound(self):
        for name in ('hegemon-node', 'wallet', 'walletd', 'private-spend'):
            with self.subTest(binary=name):
                value = copy.deepcopy(RECEIPT)
                value['artifact_sha256'][name] = '00' * 32
                self.reject(value)

    def test_private_spend_cli_version_is_exact_and_required(self):
        for replacement in ('private-spend 0.10.0', 'wallet 0.11.0', True, None):
            with self.subTest(replacement=replacement):
                value = copy.deepcopy(RECEIPT)
                value['identity_smoke']['private_spend_cli_version'] = replacement
                self.reject(value)
        value = copy.deepcopy(RECEIPT)
        del value['identity_smoke']['private_spend_cli_version']
        self.reject(value)

    def test_embedded_proof_checks_match_the_artifact_target_triple(self):
        value = copy.deepcopy(RECEIPT)
        value['current_binary_proof_verification']['target_triple'] = 'unreviewed-other-target'
        self.reject(value)

    def test_proof_execution_cannot_be_false_or_type_coerced(self):
        for replacement in (False, 1, 'true', None):
            with self.subTest(replacement=replacement):
                value = copy.deepcopy(RECEIPT)
                value['actual_new_binary_proof_verification'] = replacement
                self.reject(value)

    def test_consumer_checks_the_embedded_proof_binding(self):
        for field in ('node_sha256', 'artifact_manifest_sha256', 'relation_digest', 'fixture_manifest_sha256', 'cargo_lock_sha256', 'network_manifest_sha256', 'offline_cli_source_sha256'):
            with self.subTest(field=field):
                value = copy.deepcopy(RECEIPT)
                value['current_binary_proof_verification'][field] = '00' * (64 if field == 'relation_digest' else 32)
                self.reject(value)

    def test_consumer_requires_all_five_cases_and_their_negative_controls(self):
        for mode in ('duplicate', 'missing_case', 'missing_control', 'successful_negative', 'input_changed', 'case_not_reaped', 'control_not_reaped'):
            with self.subTest(mode=mode):
                value = copy.deepcopy(RECEIPT)
                cases = value['current_binary_proof_verification']['cases']
                if mode == 'duplicate':
                    cases[-1] = copy.deepcopy(cases[0])
                elif mode == 'missing_case':
                    cases.pop()
                elif mode == 'missing_control':
                    del cases[0]['negative_controls']['changed_statement']
                elif mode == 'successful_negative':
                    cases[0]['negative_controls']['changed_statement']['exit_code'] = 0
                elif mode == 'input_changed':
                    inputs = value['current_binary_proof_verification']['inputs_after']
                    inputs[next(iter(inputs))]['sha256'] = '00' * 32
                elif mode == 'case_not_reaped':
                    cases[0]['processes_reaped'] = False
                else:
                    cases[0]['negative_controls']['changed_statement']['processes_reaped'] = False
                self.reject(value)

    def test_ci_scope_cannot_claim_qualified_source_tuple(self):
        value = copy.deepcopy(RECEIPT)
        value['authorization_kind'] = 'qualified_source_tuple'
        self.reject(value)

    def test_historical_g8_cannot_be_relabelled_current_lifecycle(self):
        for field in ('predecessor_lifecycle_reexecuted', 'affected_lifecycle_verified', 'production_artifacts_verified', 'fresh_network_lifecycle_verified', 'fresh_public_genesis_qualified'):
            with self.subTest(field=field):
                value = copy.deepcopy(RECEIPT)
                value[field] = True
                self.reject(value)

    def test_bounded_ci_cannot_grant_production_deployment_or_cutover(self):
        for field in ('production_authorized', 'deployment_verified', 'public_cutover_authorized'):
            for replacement in (True, 0, 'false', None):
                with self.subTest(field=field, replacement=replacement):
                    value = copy.deepcopy(RECEIPT)
                    value[field] = replacement
                    self.reject(value)

    def test_predecessor_authority_hashes_remain_bound(self):
        for field in ('predecessor_checker_sha256', 'predecessor_registry_sha256', 'runtime_inventory_sha256'):
            with self.subTest(field=field):
                value = copy.deepcopy(RECEIPT)
                value[field] = '00' * 32
                self.reject(value)

    def test_runtime_scope_cannot_add_an_unreviewed_path(self):
        value = copy.deepcopy(RECEIPT)
        value['changed_paths'].append('node/src/native/unreviewed.rs')
        self.reject(value)

    def test_reused_evidence_flag_is_required(self):
        value = copy.deepcopy(RECEIPT)
        value['unchanged_evidence_reused'] = False
        self.reject(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--consumer', type=Path, required=True)
    parser.add_argument('--receipt-fixture', type=Path, required=True)
    parser.add_argument('--artifact-manifest', type=Path, required=True)
    parser.add_argument('--registry', type=Path, required=True)
    args = parser.parse_args()
    global CONSUMER, RECEIPT, ARTIFACT, ARTIFACT_SHA, REGISTRY
    spec = importlib.util.spec_from_file_location('_successor_consumer_under_test', args.consumer.resolve())
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot import staged consumer')
    CONSUMER = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = CONSUMER
    spec.loader.exec_module(CONSUMER)
    RECEIPT = json.loads(args.receipt_fixture.read_text())
    raw = args.artifact_manifest.read_bytes()
    import hashlib
    ARTIFACT_SHA = hashlib.sha256(raw).hexdigest()
    ARTIFACT = json.loads(raw)
    REGISTRY = json.loads(args.registry.read_text())
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FinalConsumerControls))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
