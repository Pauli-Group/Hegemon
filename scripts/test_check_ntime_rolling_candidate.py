#!/usr/bin/env python3
"""Synthetic fail-closed policy controls; these never qualify release artifacts."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import os
import subprocess
import signal
import py_compile
from types import SimpleNamespace
from unittest.mock import Mock
import sys
import time
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

gate = module('ntime_candidate_policy_controls', ROOT / 'scripts/check_ntime_rolling_candidate.py')
runner = module('ntime_candidate_runner_controls', ROOT / 'scripts/qualify_ntime_rolling.py')


def pending():
    return {'schema': gate.SCHEMA, 'status': 'pending', 'baseline_commit': gate.BASE,
            'software_version': gate.SOFTWARE_VERSION, 'kind': gate.KIND, 'scope': gate.SCOPE,
            'boundaries': dict(gate.BOUNDARIES), 'proof_identity': {}, 'source_inventory': [],
            'source_inventory_sha256': None, 'reviewed_delta': [], 'independent_review': None,
            'qualification_commands': []}


def commands():
    return [{'name': name, 'argv': ['python3', '-I', '-B', 'scripts/qualify_ntime_rolling.py',
            '--suite', name, '--artifact-manifest', '{artifact_manifest}'], 'timeout_seconds': 7200}
            for name in gate.CHECKS]


def frozen():
    value = pending()
    inventory = [{'path': 'synthetic-policy-control-only', 'bytes': 1, 'sha256': '1' * 64, 'mode': '100644'}]
    value.update(status='frozen', source_inventory=inventory,
                 source_inventory_sha256=gate.sha(gate.canonical(inventory)),
                 reviewed_delta=[{'synthetic-control': True}], qualification_commands=commands())
    return value


class CandidatePolicyControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.write('scripts/qualify_ntime_rolling.py', (ROOT / 'scripts/qualify_ntime_rolling.py').read_bytes())

    def write(self, path, raw):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(raw.encode() if isinstance(raw, str) else raw)
        return file

    def test_real_pending_source_has_exact_unchanged_proof_identity_and_no_authority(self):
        config = gate.load_config(ROOT)
        self.assertEqual(len(config['proof_identity']['source_inputs']), 41)
        self.assertEqual(config['proof_identity']['relation_digest'], gate.RELATION)
        self.assertEqual(config['proof_identity']['cargo_lock_sha256'], gate.LOCK)
        receipt = gate.source_check(ROOT, config)
        for field in gate.BOUNDARIES:
            self.assertIs(receipt[field], False)

    def test_pending_cannot_claim_inventory_review_or_execution(self):
        self.assertEqual(gate.validate_config(pending())['status'], 'pending')
        for field, value in (('source_inventory', [{}]), ('source_inventory_sha256', '1' * 64),
                             ('reviewed_delta', [{}]), ('independent_review', {}),
                             ('qualification_commands', commands())):
            candidate = pending(); candidate[field] = value
            with self.subTest(field=field), self.assertRaises(gate.CandidateError):
                gate.validate_config(candidate)

    def test_authority_requires_exact_false_not_false_like_values(self):
        for field in gate.BOUNDARIES:
            for value in (True, 0, None, 'false'):
                candidate = pending(); candidate['boundaries'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(gate.CandidateError):
                    gate.validate_config(candidate)

    def test_software_baseline_scope_and_unknown_fields_are_closed(self):
        for field, value in (('software_version', '0.11.4'), ('kind', 'release'),
                             ('baseline_commit', '0' * 40), ('scope', 'production'),
                             ('schema', 'hegemon.combined-upgrade.candidate.v1'), ('extra', False)):
            candidate = pending(); candidate[field] = value
            with self.subTest(field=field), self.assertRaises(gate.CandidateError):
                gate.validate_config(candidate)

    def test_commands_cannot_skip_reorder_supply_receipt_or_run_shell(self):
        gate.validate_commands(commands())
        variants = [commands()[:-1], list(reversed(commands()))]
        changed = commands(); changed[0]['argv'] += ['--focused-only']; variants.append(changed)
        changed = commands(); changed[0]['argv'][3] = 'scripts/qualify_combined_upgrade.py'; variants.append(changed)
        changed = commands(); changed[0]['timeout_seconds'] = 0; variants.append(changed)
        changed = commands(); changed[0]['argv'] = ['bash', '-c', 'true']; variants.append(changed)
        for candidate in variants:
            with self.subTest(candidate=candidate), self.assertRaises(gate.CandidateError):
                gate.validate_commands(candidate)

    def test_duplicate_json_and_symlink_inputs_are_rejected(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(gate.CandidateError):
                gate.strict_json(raw)
        original = self.write('original.json', '{}')
        link = self.root / 'linked.json'; link.symlink_to(original)
        with self.assertRaises(gate.CandidateError):
            gate.safe_file(self.root, 'linked.json')
        for path in ('../original.json', '/original.json', './original.json'):
            with self.subTest(path=path), self.assertRaises(gate.CandidateError):
                gate.safe_file(self.root, path)

    def test_frozen_source_inventory_and_delta_are_mandatory(self):
        config = frozen()
        for key, value in (('source_inventory', []), ('source_inventory_sha256', '0' * 64),
                           ('reviewed_delta', [])):
            candidate = copy.deepcopy(config); candidate[key] = value
            with self.subTest(key=key), self.assertRaises(gate.CandidateError):
                gate.validate_config(candidate)

    def test_pending_review_never_authorizes(self):
        with self.assertRaisesRegex(gate.CandidateError, 'pending'):
            gate.review_check(self.root, pending())

    def review_fixture(self):
        config = frozen()
        review = {'schema': 'hegemon.ntime-rolling.independent-review.v1',
                  'decision': 'ACCEPT_SOFTWARE_CANDIDATE_SCOPE',
                  'candidate_binding_sha256': gate.binding(config),
                  'source_inventory_sha256': config['source_inventory_sha256'],
                  'qualification_commands_sha256': gate.sha(gate.canonical(config['qualification_commands'])),
                  'review_kind': 'independent_human_review', 'reviewer': 'synthetic test fixture',
                  'limitations': ['Synthetic policy control; no qualification evidence.'], **gate.BOUNDARIES}
        path = gate.EVIDENCE_ROOT + 'synthetic-review.json'
        self.write(path, json.dumps(review)); config['independent_review'] = gate.row(self.root, path)
        return config, review, path

    def test_review_binds_exact_source_commands_and_finite_scope(self):
        config, review, path = self.review_fixture()
        self.assertEqual(gate.review_check(self.root, config), review)
        for field, value in (('candidate_binding_sha256', '0' * 64), ('source_inventory_sha256', '0' * 64),
                             ('qualification_commands_sha256', '0' * 64), ('production_authorized', True),
                             ('limitations', []), ('reviewer', '')):
            changed = dict(review); changed[field] = value
            self.write(path, json.dumps(changed)); config['independent_review'] = gate.row(self.root, path)
            with self.subTest(field=field), self.assertRaises(gate.CandidateError):
                gate.review_check(self.root, config)

    def artifact_fixture(self):
        artifacts = []
        for package, name in (('hegemon-node', 'hegemon-node'), ('wallet', 'wallet'),
                              ('walletd', 'walletd'), ('wallet', 'private-spend')):
            path = 'target/synthetic/' + name
            raw = ('SYNTHETIC CONTROL ONLY ' + name).encode(); self.write(path, raw)
            artifacts.append({'package': package, 'binary': name, 'path': path,
                              'sha256': gate.sha(raw), 'size': len(raw)})
        manifest = {'target_triple': 'synthetic-controls-only', 'cargo_lock_sha256': gate.LOCK,
                    'artifacts': artifacts}
        path = self.write('target/synthetic/manifest.json', json.dumps(manifest))
        return manifest, path

    def test_artifact_identity_rejects_missing_duplicate_lock_and_byte_mutation(self):
        manifest, path = self.artifact_fixture()
        identity = gate.artifact_identity(self.root, path)
        self.assertEqual(len(identity['artifact_sha256']), 4)
        gate.recheck_artifacts(self.root, path, identity)
        for mutate in (lambda v: v['artifacts'].pop(),
                       lambda v: v['artifacts'].__setitem__(1, v['artifacts'][0]),
                       lambda v: v.__setitem__('cargo_lock_sha256', '0' * 64)):
            changed = copy.deepcopy(manifest); mutate(changed); path.write_text(json.dumps(changed))
            with self.assertRaises(gate.CandidateError):
                gate.artifact_identity(self.root, path)
        path.write_text(json.dumps(manifest))
        self.write(manifest['artifacts'][0]['path'], b'changed')
        with self.assertRaises(gate.CandidateError):
            gate.recheck_artifacts(self.root, path, identity)

    def execution_fixture(self, name='ntime'):
        config = frozen(); identity = {'artifact_manifest_sha256': 'a' * 64,
            'artifact_sha256': {n: str(i) * 64 for i, n in enumerate(('hegemon-node', 'wallet', 'walletd', 'private-spend'), 1)},
            'target_triple': 'synthetic-controls-only'}
        records = []
        for index, command in enumerate(runner.suite_plan(name)):
            counts = ({'passed': 1, 'failed': 0, 'ignored': 0, 'measured': 0} if 'exact_name' in command
                      else {'passed': 59, 'failed': 0, 'ignored': 0, 'skipped': 0} if 'adapter_count' in command else None)
            raw = ('test ' + command['exact_name'] + ' ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n').encode() if 'exact_name' in command else b'Ran 59 tests in 0.1s\n\nOK\n'
            log = 'target/ntime-qualification/synthetic/command-%03d.log' % index
            self.write(log, raw)
            records.append({'argv': command['argv'], 'exit_code': 0, 'started_unix': 1., 'finished_unix': 2.,
                            'duration_seconds': 1., 'log': log, 'log_sha256': gate.sha(raw),
                            'process_reaped': True, 'actual_command_execution': True,
                            'test_name': command.get('exact_name'), 'test_counts': counts})
        receipt = {'schema': 'hegemon.ntime-rolling.actual-check.v1', 'name': name, 'status': 'PASS',
                   'candidate_binding_sha256': gate.binding(config),
                   'source_inventory_sha256': config['source_inventory_sha256'], **identity,
                   'actual_execution': True, 'processes_reaped': True, **gate.BOUNDARIES,
                   'gates': {g: True for g in gate.REQUIRED_GATES[name]}, 'executions': records,
                   'execution_scope': runner.EXECUTION_SCOPE}
        return config, identity, receipt

    def test_exact_execution_records_bind_counts_names_plan_scope_and_log_bytes(self):
        config, identity, receipt = self.execution_fixture()
        gate.validate_check(receipt, 'ntime', config, identity, root=self.root, verify_logs=True)
        changes = [lambda v: v['executions'].pop(),
                   lambda v: v['executions'][0].__setitem__('test_counts', {'passed': 0}),
                   lambda v: v['executions'][0].__setitem__('test_name', 'wrong'),
                   lambda v: v['executions'][0].__setitem__('test_counts', {'passed': True, 'failed': 0, 'ignored': 0, 'measured': 0}),
                   lambda v: v['executions'][0]['argv'].append('--ignored'),
                   lambda v: v['executions'][0].__setitem__('process_reaped', False),
                   lambda v: v.__setitem__('execution_scope', 'ordinary-final-binary'),
                   lambda v: v.__setitem__('activation_authorized', True),
                   lambda v: v['gates'].__setitem__('invented', True)]
        for mutate in changes:
            changed = copy.deepcopy(receipt); mutate(changed)
            with self.assertRaises(gate.CandidateError):
                gate.validate_check(changed, 'ntime', config, identity, root=self.root)
        self.write(receipt['executions'][0]['log'], 'changed')
        with self.assertRaises(gate.CandidateError):
            gate.validate_check(receipt, 'ntime', config, identity, root=self.root, verify_logs=True)

    def test_adapter_must_run_full_exact_positive_suite(self):
        config, identity, receipt = self.execution_fixture('adapter')
        gate.validate_check(receipt, 'adapter', config, identity, root=self.root, verify_logs=True)
        receipt['executions'][0]['test_counts']['passed'] = 58
        with self.assertRaises(gate.CandidateError):
            gate.validate_check(receipt, 'adapter', config, identity, root=self.root)

    def test_final_execution_authenticates_before_any_process_or_executor_import(self):
        config = pending()
        with patch.object(gate, 'load_config', return_value=config), \
             patch.object(gate, 'source_check', side_effect=gate.CandidateError('not frozen')), \
             patch.object(gate.importlib.util, 'spec_from_file_location') as load:
            with self.assertRaisesRegex(gate.CandidateError, 'not frozen'):
                gate.final_artifacts(self.root, config, self.root / 'manifest.json', 4)
            load.assert_not_called()

    @unittest.skipIf(os.name == 'nt', 'POSIX real process ownership control')
    def test_outer_timeout_allows_runner_to_reap_separate_child_group(self):
        # A real disposable process tree proves the outer timeout uses TERM,
        # allowing the source runner's owned-child cleanup before escalation.
        child_pid = self.root / 'child.pid'
        runner_path = self.write('synthetic_runner.py',
            'import os,signal,subprocess,sys\n'
            'from pathlib import Path\n'
            'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"],start_new_session=True)\n'
            'Path(sys.argv[1]).write_text(str(p.pid))\n'
            'def stop(signum,frame):\n'
            ' os.killpg(p.pid,signal.SIGKILL)\n'
            ' p.communicate(timeout=5)\n'
            ' raise SystemExit(2)\n'
            'signal.signal(signal.SIGTERM,stop)\n'
            'p.communicate()\n')
        with self.assertRaises(subprocess.TimeoutExpired):
            gate.run_qualification([sys.executable, str(runner_path), str(child_pid)], self.root, 0.2)
        self.assertTrue(child_pid.exists())
        pid = int(child_pid.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


    @unittest.skipIf(os.name == 'nt', 'POSIX real process ownership control')
    def test_coordinator_termination_unwinds_runner_and_separate_child(self):
        child_pid = self.root / 'nested-child.pid'
        script = self.write('nested_runner.py',
            'import os,signal,subprocess,sys\n'
            'from pathlib import Path\n'
            'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"],start_new_session=True)\n'
            'def stop(signum,frame):\n'
            ' os.killpg(p.pid,signal.SIGKILL)\n'
            ' p.communicate(timeout=5)\n'
            ' raise SystemExit(2)\n'
            'signal.signal(signal.SIGTERM,stop)\n'
            'Path(sys.argv[1]).write_text(str(p.pid))\n'
            'p.communicate()\n')
        wrapper = self.write('nested_coordinator.py',
            'import importlib.util,sys\n'
            'from pathlib import Path\n'
            's=importlib.util.spec_from_file_location("control_gate",sys.argv[1])\n'
            'g=importlib.util.module_from_spec(s);s.loader.exec_module(g)\n'
            'g.run_qualification([sys.executable,sys.argv[2],sys.argv[3]],Path(sys.argv[4]),60)\n')
        process = subprocess.Popen([sys.executable, str(wrapper), str(ROOT / 'scripts/check_ntime_rolling_candidate.py'),
                                    str(script), str(child_pid), str(self.root)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not child_pid.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(child_pid.exists())
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(child_pid.read_text()), 0)
        finally:
            if process.poll() is None:
                process.kill(); process.communicate(timeout=5)

    def test_frozen_inventory_rejection_precedes_current_helper_import(self):
        config = frozen()
        with patch.object(gate, 'authenticate', return_value={}), \
             patch.object(gate, 'inventory', return_value=[]), \
             patch.object(gate, 'release_tuple') as helper:
            with self.assertRaisesRegex(gate.CandidateError, 'before importing'):
                gate.source_check(self.root, config)
            helper.assert_not_called()


    def test_h0_identity_versions_and_exact_typed_proof_parameters_are_required(self):
        identity = {'genesis_hash': 'synthetic-genesis'}
        smoke = {'node_rpc_version': 'Hegemon Native Node 0.11.5', 'wallet_cli_version': 'wallet 0.11.5',
                 'private_spend_cli_version': 'private-spend 0.11.5',
                 'walletd_version_cli': 'not implemented; artifact hash/source version checked',
                 'height': 0, 'peers': 0, 'qualified_manifest': True, 'owned_node_reaped': True,
                 'wrong_compiled_rules_manifest_rejected': True, 'genesis': identity['genesis_hash'],
                 'proof_parameters': {'relation_id': gate.RELATION_ID, 'relation_digest': gate.RELATION,
                     'public_words': 86, 'max_proof_bytes': 171848, 'max_carrier_bytes': 177632,
                     'input_slots': 2, 'output_slots': 2, 'production_authorized': False}}
        gate.validate_identity_smoke(smoke, identity)
        for field in smoke:
            changed = copy.deepcopy(smoke); changed.pop(field)
            with self.subTest(missing=field), self.assertRaises(gate.CandidateError):
                gate.validate_identity_smoke(changed, identity)
        for field in smoke['proof_parameters']:
            changed = copy.deepcopy(smoke); changed['proof_parameters'][field] = True
            with self.subTest(proof=field), self.assertRaises(gate.CandidateError):
                gate.validate_identity_smoke(changed, identity)
        for field in ('node_rpc_version', 'wallet_cli_version', 'private_spend_cli_version'):
            changed = copy.deepcopy(smoke); changed[field] = changed[field].replace('0.11.5', '0.11.4')
            with self.subTest(version=field), self.assertRaises(gate.CandidateError):
                gate.validate_identity_smoke(changed, identity)


    def test_owned_proof_stage_requires_both_unchanged_proof_predicate_and_new_harness(self):
        fixture = self.write('release-evidence/v0.11-current-proof-fixture/manifest.json', '{}')
        node = self.write('target/synthetic/node', 'synthetic routing control only')
        manifest = self.write('target/synthetic/proof-manifest.json', json.dumps({
            'target_triple': 'synthetic-policy-only', 'artifacts': [{'binary': 'hegemon-node', 'path': 'target/synthetic/node'}]}))
        executor = SimpleNamespace(frozen_sources=Mock(), validate_harness=Mock())
        old = SimpleNamespace(CURRENT_FIXTURE_SHA256=gate.sha(fixture.read_bytes()), validate_current_binary_proofs=Mock())
        checks = {'target_triple': 'synthetic-policy-only'}
        receipt = {'identity_smoke': {'scratch_directory': str(self.root / 'target/synthetic')},
                   'artifact_sha256': {'hegemon-node': gate.sha(node.read_bytes())},
                   'artifact_manifest_sha256': gate.sha(manifest.read_bytes())}
        result = subprocess.CompletedProcess([], 0, json.dumps(checks).encode(), b'')
        with patch.object(gate, 'current_proof_executor', return_value=executor), \
             patch.object(gate, 'run_qualification', return_value=result) as run, \
             patch.object(gate, 'recheck_artifacts'):
            self.write('scripts/check_v0115_current_binary_proofs.py', '# synthetic routing control')
            actual = gate.current_owned_proofs(self.root, {}, manifest, receipt, 4, old)
        old.validate_current_binary_proofs.assert_called_once()
        executor.validate_harness.assert_called_once_with(checks, self.root)
        self.assertIn('check_v0115_current_binary_proofs.py', run.call_args.args[0][3])
        self.assertTrue(actual['actual_new_binary_proof_verification'])
        old.validate_current_binary_proofs.side_effect = gate.CandidateError('old proof rejection')
        with patch.object(gate, 'current_proof_executor', return_value=executor), \
             patch.object(gate, 'run_qualification', return_value=result), \
             patch.object(gate, 'recheck_artifacts'), self.assertRaisesRegex(gate.CandidateError, 'old proof rejection'):
            gate.current_owned_proofs(self.root, {}, manifest, receipt, 4, old)

    def test_wrapper_import_executes_checked_source_bytes_and_ignores_unchecked_pyc(self):
        path = self.write('scripts/check_v0115_current_binary_proofs.py', 'VALUE="forged-cache"\n')
        py_compile.compile(str(path), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        path.write_text('VALUE="checked-source"\n')
        raw = path.read_bytes()
        config = {'source_inventory': [{'path': 'scripts/check_v0115_current_binary_proofs.py',
                                       'bytes': len(raw), 'sha256': gate.sha(raw), 'mode': '100644'}]}
        self.assertEqual(gate.current_proof_executor(self.root, config).VALUE, 'checked-source')
        config['source_inventory'][0]['sha256'] = '0' * 64
        with self.assertRaises(gate.CandidateError):
            gate.current_proof_executor(self.root, config)



if __name__ == '__main__':
    unittest.main()
