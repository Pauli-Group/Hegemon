#!/usr/bin/env python3
"""Exact workflow and retained-evidence controls; no build or network executes."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('v0115_workflow_tests', ROOT / 'scripts/prepare_v0115_release.py')
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)
pack = preparation.packager


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release = (ROOT / '.github/workflows/release.yml').read_text()
        cls.workflow = preparation.expected_workflow(cls.release)

    def test_checked_in_workflow_is_exact_and_all_nine_jobs_remain(self):
        preparation.verify_preparation(self.release, (ROOT / preparation.WORKFLOW_PATH).read_text())
        names = set(re.findall(r'^  ([a-z0-9-]+):$', self.workflow.split('\njobs:\n', 1)[1], re.M))
        self.assertEqual(names, pack.REQUIRED_JOBS)
        self.assertEqual(len(names), 9)
        self.assertNotIn('contents: write', self.workflow)
        self.assertNotIn('softprops/action-gh-release', self.workflow)
        self.assertNotIn('create-release:', self.workflow)
        self.assertEqual((ROOT / '.github/workflows/release.yml').read_text(), self.release)

    def test_non_pr_push_is_exact_candidate_branch_and_manual_dispatch_remains(self):
        self.assertIn('  workflow_dispatch:\n  push:\n    branches: [ codex/v0.11.5-ntime-rolling ]\n', self.workflow)
        for branch in ('main', 'codex/**', '*'):
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release,
                        self.workflow.replace(pack.CANDIDATE_BRANCH, branch))

    def test_security_proof_formal_and_four_final_binary_gates_remain_blocking(self):
        commands = ('./scripts/dependency-audit-gate.sh', 'bash scripts/check_formal_core.sh',
                    'bash scripts/check_formal_crypto.sh full', './scripts/security-audit.sh --require-binary',
                    './scripts/check-app-no-ssh-e2e.sh --review-only',
                    'scripts/check_ntime_rolling_candidate.py --require-authorized')
        for command in commands:
            self.assertIn(command, self.workflow)
            for changed in ('true # ' + command, command + ' || true'):
                with self.subTest(command=command, changed=changed), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, self.workflow.replace(command, changed, 1))
        self.assertEqual(self.workflow.count('--require-final-artifact'), 4)
        self.assertEqual(self.workflow.count("if: github.event_name != 'pull_request'"), 3)
        self.assertEqual(self.workflow.count('scripts/check_ntime_candidate_formatting.py --manifest'), 3)
        self.assertEqual(self.workflow.count('scripts/check_ntime_rolling_candidate.py --prepare'), 1)

    def test_each_platform_retains_final_receipt_and_original_manifest(self):
        for job, (selected, _artifact, directory) in preparation.PLATFORMS.items():
            body = re.split(r'\n(?=  [a-z0-9-]+:\n)', self.workflow.split(f'  {job}:\n', 1)[1], maxsplit=1)[0]
            receipt = f'{directory}/{pack.qualification_name(selected)}'
            self.assertEqual(body.count('--require-final-artifact > ' + receipt), 1)
            self.assertEqual(body.count('          name: v0115-final-' + selected + '\n'), 1)
            self.assertIn(f'            {directory}/hegemon-release-artifacts.json\n', body)
            self.assertIn(f'            {receipt}\n', body)
            for mutation in (body.replace(' > ' + receipt, '', 1), body.replace('if-no-files-found: error', 'if-no-files-found: warn', 1)):
                with self.subTest(job=job), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, self.workflow.replace(body, mutation))

    def test_assembly_data_cannot_contaminate_source_inventory(self):
        assembly = self.workflow.split('  assemble-prepared-release:\n', 1)[1]
        self.assertIn('path: target/prepared-artifacts\n', assembly)
        self.assertIn('--output-dir target/prepared-release-assets\n', assembly)
        self.assertIn('--collect-qualification --artifacts target/prepared-artifacts', assembly)
        self.assertIn('path: target/v0115-preparation-evidence/\n', assembly)
        self.assertNotIn('--bundle-manifest artifacts/', assembly)
        self.assertEqual(assembly.count('--bundle-manifest target/prepared-artifacts/'), 4)

    def test_complete_original_upload_options_never_attach_to_new_step(self):
        historical = preparation.historical.expected_workflow(self.release, v0113=True, combined=True)
        for _job, (_selected, artifact, _directory) in preparation.PLATFORMS.items():
            anchor = f'          name: {artifact}\n          path: release/\n'
            historical = historical.replace(anchor, anchor + '          if-no-files-found: error\n          retention-days: 14\n', 1)
        with patch.object(preparation.historical, 'expected_workflow', return_value=historical):
            generated = preparation.expected_workflow(self.release)
        for mapping in re.findall(r'        with:\n((?:          [^\n]*\n|            [^\n]*\n)+)', generated):
            keys = re.findall(r'^          ([a-z-]+):', mapping, re.M)
            self.assertEqual(len(keys), len(set(keys)), mapping)

    def test_windows_native_ownership_runs_immediately_after_checkout_before_build_tools(self):
        body = re.split(r'\n(?=  [a-z0-9-]+:\n)',
                        self.workflow.split('  build-windows:\n', 1)[1], maxsplit=1)[0]
        checkout = ('      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n'
                    '        with:\n          persist-credentials: false\n          fetch-depth: 0\n\n')
        self.assertIn(checkout + preparation.WINDOWS_OWNERSHIP_STEP + '\n'
                      + preparation.PROOF_EXECUTION_TEST_STEP + '\n      - name: Install LLVM\n', body)
        self.assertEqual(self.workflow.count(preparation.WINDOWS_OWNERSHIP_COMMAND), 1)
        self.assertLess(body.index(preparation.WINDOWS_OWNERSHIP_COMMAND), body.index('choco install llvm'))
        self.assertLess(body.index(preparation.WINDOWS_OWNERSHIP_COMMAND), body.index('./scripts/build_release_artifacts.sh'))
        self.assertLess(body.index(preparation.WINDOWS_OWNERSHIP_COMMAND), body.index(preparation.PROOF_EXECUTION_TEST_COMMAND))
        self.assertLess(body.index(preparation.PROOF_EXECUTION_TEST_COMMAND), body.index('choco install llvm'))
        step = preparation.WINDOWS_OWNERSHIP_STEP
        softened = (step.replace('--require-windows', ''),
                    step.replace('        shell: bash\n', '        continue-on-error: true\n        shell: bash\n'),
                    step.replace('        shell: bash\n', '        if: false\n        shell: bash\n'),
                    step.replace(preparation.WINDOWS_OWNERSHIP_COMMAND,
                                 preparation.WINDOWS_OWNERSHIP_COMMAND + ' || true'),
                    step.replace(preparation.WINDOWS_OWNERSHIP_COMMAND,
                                 'true # ' + preparation.WINDOWS_OWNERSHIP_COMMAND), '')
        for replacement in softened:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, self.workflow.replace(step, replacement, 1))
        late_body = body.replace(step + '\n', '', 1)
        late_body = late_body.replace('      - name: Verify release artifact manifest\n',
                                     step + '\n      - name: Verify release artifact manifest\n', 1)
        late = self.workflow.replace(body, late_body, 1)
        with self.assertRaises(ValueError):
            preparation.verify_preparation(self.release, late)

    def test_changed_windows_install_anchor_requires_generator_review(self):
        historical = preparation.historical.expected_workflow(self.release, v0113=True, combined=True)
        historical = historical.replace('      - name: Install LLVM\n', '      - name: Changed Windows install\n')
        with patch.object(preparation.historical, 'expected_workflow', return_value=historical):
            with self.assertRaisesRegex(ValueError, 'review changed preparation anchor'):
                preparation.expected_workflow(self.release)

    def test_wrapper_controls_are_blocking_in_policy_and_early_windows(self):
        policy = re.split(r'\n(?=  [a-z0-9-]+:\n)',
                          self.workflow.split('  preparation-policy:\n', 1)[1], maxsplit=1)[0]
        windows = re.split(r'\n(?=  [a-z0-9-]+:\n)',
                           self.workflow.split('  build-windows:\n', 1)[1], maxsplit=1)[0]
        command = preparation.PROOF_EXECUTION_TEST_COMMAND
        policy_command = '/usr/bin/' + command
        self.assertEqual(policy.count(policy_command), 1)
        self.assertEqual(windows.count(command), 1)
        self.assertEqual(self.workflow.count('scripts/test_check_v0115_current_binary_proofs.py'), 2)
        self.assertLess(policy.index('scripts/test_package_v0115_release.py'), policy.index(policy_command))
        for body, selected in ((policy, policy_command), (windows, command)):
            for replacement in ('true # ' + selected, selected + ' || true', selected.replace(' -I -B ', ' ')):
                changed = self.workflow.replace(body, body.replace(selected, replacement, 1), 1)
                with self.subTest(command=selected, mutation=replacement), self.assertRaises(ValueError):
                    preparation.verify_preparation(self.release, changed)
        step = preparation.PROOF_EXECUTION_TEST_STEP
        for replacement in ('', step.replace('        shell: bash\n', '        continue-on-error: true\n        shell: bash\n'),
                            step.replace('        shell: bash\n', '        if: false\n        shell: bash\n')):
            with self.subTest(step=replacement), self.assertRaises(ValueError):
                preparation.verify_preparation(self.release, self.workflow.replace(step, replacement, 1))


class FastWindowsWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / '.github/workflows/ntime-rolling.yml').read_text()

    def test_independent_native_windows_job_is_exact_and_cannot_wait_for_builds(self):
        jobs = self.workflow.split('\njobs:\n', 1)[1]
        self.assertEqual(set(re.findall(r'^  ([a-z0-9-]+):$', jobs, re.M)),
                         {'source-and-adapter', 'consensus', 'native', 'process-ownership-windows'})
        body = re.split(r'\n(?=  [a-z0-9-]+:\n)',
                        jobs.split('  process-ownership-windows:\n', 1)[1], maxsplit=1)[0]
        expected = '''    runs-on: windows-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
        with:
          persist-credentials: false
          fetch-depth: 0
''' + preparation.WINDOWS_OWNERSHIP_STEP + preparation.PROOF_EXECUTION_TEST_STEP
        self.assertEqual(body.rstrip('\n'), expected.rstrip('\n'))
        self.assertNotIn('needs:', body)
        self.assertNotIn('continue-on-error:', body)
        self.assertNotIn('if:', body)
        self.assertNotIn('cargo ', body)
        self.assertEqual(self.workflow.count(preparation.WINDOWS_OWNERSHIP_COMMAND), 1)

    def test_wrapper_controls_run_in_focused_source_and_after_native_windows(self):
        source = re.split(r'\n(?=  [a-z0-9-]+:\n)',
                          self.workflow.split('  source-and-adapter:\n', 1)[1], maxsplit=1)[0]
        windows = re.split(r'\n(?=  [a-z0-9-]+:\n)',
                           self.workflow.split('  process-ownership-windows:\n', 1)[1], maxsplit=1)[0]
        command = preparation.PROOF_EXECUTION_TEST_COMMAND
        self.assertEqual(source.count(command), 1)
        self.assertEqual(windows.count(command), 1)
        self.assertEqual(self.workflow.count('        run: ' + command), 2)
        self.assertIn(preparation.PROOF_EXECUTION_TEST_STEP, source)
        self.assertIn((preparation.WINDOWS_OWNERSHIP_STEP + preparation.PROOF_EXECUTION_TEST_STEP).rstrip('\n'), windows)
        self.assertLess(source.index('scripts/check_ntime_rolling_source.py'), source.index(command))
        self.assertLess(source.index(command), source.index('scripts/test_bitcoin_asic_stratum.py'))

    def test_precise_ownership_and_routing_inputs_trigger_fast_pr_job(self):
        paths = self.workflow.split('  pull_request:\n    paths:\n', 1)[1].split('  workflow_dispatch:', 1)[0]
        for name in ('scripts/v0115_process_ownership.py', 'scripts/test_v0115_process_ownership.py',
                     'scripts/check_v0115_current_binary_proofs.py',
                     'scripts/test_check_v0115_current_binary_proofs.py',
                     'scripts/prepare_v0115_release.py', 'scripts/test_prepare_v0115_release.py',
                     '.github/workflows/prepare-premainnet-release.yml'):
            self.assertIn("      - '" + name + "'\n", paths)
        for command in ('scripts/test_check_ntime_rolling_source.py',
                        'scripts/test_bitcoin_asic_stratum.py',
                        'cargo test --locked -p consensus-light-client',
                        '--lib native_timestamp_rolling', '--lib native::timestamp_admission_tests::',
                        '--lib native::asert_tests::', '--lib treasury_cadence'):
            self.assertIn(command, self.workflow)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='v0115-preparation-unit-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.artifacts, self.assets, self.output = self.root / 'artifacts', self.root / 'assets', self.root / 'output'
        self.artifacts.mkdir()
        self.assets.mkdir()
        predicate = patch.object(pack, 'validate_full_final_receipt', return_value={})
        self.full_predicate = predicate.start()
        self.addCleanup(predicate.stop)
        for selected, (triple, _format) in pack.base.PLATFORMS.items():
            evidence = self.artifacts / ('v0115-final-' + selected)
            evidence.mkdir()
            rows = [{'package': 'wallet' if name == 'private-spend' else name, 'binary': name,
                     'sha256': pack.base.sha((selected + name).encode())} for name in pack.base.IDENTITIES]
            common = {'source_head': '1' * 40, 'source_index_tree': '2' * 40,
                      'source_tree_sha256': '3' * 64, 'cargo_lock_sha256': pack.LOCK_SHA256,
                      'target_triple': triple}
            original = {'schema_version': 1, **common, 'artifacts': rows}
            raw_original = pack.base.encoded(original)
            (evidence / 'hegemon-release-artifacts.json').write_bytes(raw_original)
            manifest = {'schema_version': 1, **common, 'assets': rows,
                        'source_manifest_sha256': pack.base.sha(raw_original)}
            (self.assets / f'hegemon-release-assets-{selected}.json').write_bytes(pack.base.encoded(manifest))
            receipt = {'schema': pack.FINAL_RECEIPT_SCHEMA, 'status': pack.FINAL_RECEIPT_STATUS,
                       'software_version': '0.11.5', 'target_triple': triple,
                       'artifact_manifest_sha256': manifest['source_manifest_sha256'],
                       'artifact_sha256': {r['binary']: r['sha256'] for r in rows},
                       'actual_new_binary_proof_verification': True,
                       'current_binary_backend_artifacts_verified': True,
                       'affected_lifecycle_verified': True,
                       'identity': {'relation_digest': pack.RELATION_DIGEST},
                       'identity_smoke': {'qualified_manifest': True, 'height': 0,
                                          'node_rpc_version': 'Hegemon Native Node 0.11.5'},
                       'production_authorized': False, 'mainnet_authorized': False,
                       'activation_authorized': False, 'public_cutover_authorized': False,
                       'deployment_verified': False, 'physical_asic_qualified': False}
            (evidence / pack.qualification_name(selected)).write_bytes(pack.base.encoded(receipt))

    def collect(self):
        return preparation.collect_qualification(self.artifacts, self.assets, self.output)

    def test_receipts_and_original_manifests_are_retained_verbatim(self):
        receipt = self.collect()
        self.assertEqual(self.full_predicate.call_count, 4)
        self.assertEqual(len(list(self.output.rglob('*.json'))), 8)
        self.assertEqual(set(receipt['qualification_receipts_sha256']), set(pack.base.PLATFORMS))
        for selected in pack.base.PLATFORMS:
            evidence = self.artifacts / ('v0115-final-' + selected)
            self.assertEqual((self.output / 'qualification-receipts' / pack.qualification_name(selected)).read_bytes(),
                             (evidence / pack.qualification_name(selected)).read_bytes())
            self.assertEqual((self.output / 'source-artifact-manifests' / f'hegemon-release-artifacts-{selected}.json').read_bytes(),
                             (evidence / 'hegemon-release-artifacts.json').read_bytes())
        self.assertIs(receipt['publication_authorized'], False)

    def test_changed_original_manifest_rejects_before_output(self):
        path = self.artifacts / 'v0115-final-linux-x86_64/hegemon-release-artifacts.json'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'manifest digest differs'):
            self.collect()
        self.assertFalse(self.output.exists())

    def test_failed_or_relabelled_receipt_rejects_before_output(self):
        path = self.artifacts / 'v0115-final-windows-x86_64' / pack.qualification_name('windows-x86_64')
        original = json.loads(path.read_bytes())
        for name, value in (('actual_new_binary_proof_verification', False), ('software_version', '0.11.4'),
                            ('physical_asic_qualified', True)):
            changed = copy.deepcopy(original)
            changed[name] = value
            path.write_bytes(pack.base.encoded(changed))
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.collect()
            self.assertFalse(self.output.exists())

    def test_existing_output_is_never_overwritten(self):
        self.collect()
        before = {p.relative_to(self.output): p.read_bytes() for p in self.output.rglob('*.json')}
        with self.assertRaises(FileExistsError):
            self.collect()
        self.assertEqual(before, {p.relative_to(self.output): p.read_bytes() for p in self.output.rglob('*.json')})

    def test_duplicate_json_keys_reject(self):
        path = self.artifacts / 'v0115-final-macos-arm64/hegemon-release-artifacts.json'
        path.write_text('{"schema_version":1,"schema_version":2}')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            self.collect()
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
