#!/usr/bin/env python3
"""Tests for source-only CI, dependency cache invalidation and failure policy."""
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import call, patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import rp05_ci as ci

class CiTests(unittest.TestCase):
    def test_ordered_dependencies_and_compiler_policy_invalidate(self):
        k=ci.module_key('source',[['A','a'],['B','b']],'compiler')
        for args in [('new',[['A','a'],['B','b']],'compiler'),
                     ('source',[['B','b'],['A','a']],'compiler'),
                     ('source',[['A','changed'],['B','b']],'compiler'),
                     ('source',[['A','a'],['B','b']],'new compiler')]:
            self.assertNotEqual(k,ci.module_key(*args))
    def test_escaped_or_symlink_sources_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t); (p/'inside').mkdir();(p/'outside').write_text('x')
            (p/'inside/link').symlink_to(p/'outside')
            for name in ['../outside','link','missing']:
                with self.assertRaises(RuntimeError): ci.safe_file(p/'inside',name)
    def test_private_object_body_change_invalidates(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'M.olean';p.write_bytes(b'a')
            b=p.with_name('M.olean.private');b.write_bytes(b'body1')
            before=ci.object_parts(p);b.write_bytes(b'body2')
            self.assertNotEqual(before,ci.object_parts(p))
    def test_deadline_never_turns_into_success(self):
        with self.assertRaisesRegex(RuntimeError,'budget exhausted'):
            ci.run(['must-not-launch'],{},time.monotonic()-1)
    def test_compile_timeout_remains_bounded_by_total_deadline(self):
        with patch.object(ci.time, 'monotonic', return_value=100), \
             patch.object(ci.subprocess, 'Popen') as launch:
            proc = launch.return_value
            proc.wait.return_value = 0
            ci.run(['lean'], {}, 700, 180)
            proc.wait.assert_called_once_with(timeout=180)
            launch.assert_called_once_with(
                ['lean'], cwd=ci.package.REPO/'formal/crypto', env={}, start_new_session=True)
            proc.wait.reset_mock()
            ci.run(['lean'], {}, 150, 180)
            proc.wait.assert_called_once_with(timeout=50)
    def test_compile_timeout_kills_and_reaps_owned_group_without_success(self):
        command = ['lean']
        with patch.object(ci.time, 'monotonic', return_value=100), \
             patch.object(ci.subprocess, 'Popen') as launch, \
             patch.object(ci.os, 'killpg') as kill_group:
            proc = launch.return_value
            proc.pid = 4321
            proc.poll.return_value = None
            proc.wait.side_effect = [ci.subprocess.TimeoutExpired(command, 180), 0]
            with self.assertRaises(ci.subprocess.TimeoutExpired):
                ci.run(command, {}, 700, 180)
            kill_group.assert_called_once_with(4321, ci.signal.SIGKILL)
            self.assertEqual(proc.wait.call_args_list, [call(timeout=180), call()])
    def test_source_guard_needs_no_lean(self):
        with patch.object(ci.package,'lake_environment',side_effect=AssertionError('Lean invoked')):
            _,graph,order=ci.source_guard()
            self.assertEqual(set(graph),set(order))
            self.assertTrue(ci.package.EXPECTED_PUBLIC.issubset(graph))
    def test_changed_public_contract_rejected_without_lean(self):
        m=ci.package.load_manifest();m['public_roots'][0]['theorem']='fake'
        with patch.object(ci.package,'load_manifest',return_value=m):
            with self.assertRaisesRegex(RuntimeError,'claim contract'): ci.source_guard()
    def test_documentation_skips_proof_but_real_inputs_do_not(self):
        m, graph, _ = ci.source_guard()
        inputs = ci.proof_inputs(m, graph)
        for path in ['formal/rp05/README.md', 'docs/crypto/RP05_PRIMITIVE_ASSUMPTIONS.md',
                     'scripts/test_rp05_ci.py']:
            self.assertNotIn(path, inputs)
        for path in ['formal/rp05/supplemental-roots.json', 'scripts/rp05_ci.py',
                     m['sources'][0]['source'], m['toolchain']['lean_toolchain_path']]:
            self.assertIn(path, inputs)

class SupplementalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root/'shared').mkdir()
        self.base = self.root/'Base.lean'
        self.base.write_text('-- base\n')
        self.graph = {'Base': self.base}
        self.registry = self.root/'supplemental-roots.json'
        self.patcher = patch.object(ci.package,'PACKAGE',self.root)
        self.patcher.start()
    def tearDown(self):
        self.patcher.stop()
        self.temp.cleanup()
    def entry(self, module, source='import Base\n', theorems=None):
        path=self.root/'shared'/(module+'.lean');path.write_text(source)
        return {'module':module,'path':'shared/'+module+'.lean',
                'sha256':ci.package.sha256_file(path),'theorems':theorems or ['Example.result']}
    def write(self,entries):
        self.registry.write_text(json.dumps({'schema':'hegemon.rp05.supplemental-roots.v1','entries':entries}))
    def test_registry_is_optional(self):
        graph, entries=ci.supplemental_graph(self.graph)
        self.assertEqual(graph,self.graph)
        self.assertEqual(entries,[])
    def test_forward_imports_extend_graph_and_audit_every_named_root(self):
        entries=[self.entry('ExtraB','import ExtraA\n',['Example.b','Example.c']),
                 self.entry('ExtraA','import Base\nimport Mathlib.Data.Nat.Basic\n',['Example.a'])]
        self.write(entries)
        graph,actual=ci.supplemental_graph(self.graph)
        self.assertEqual(ci.package.topological(graph,['ExtraB','ExtraA']),['Base','ExtraA','ExtraB'])
        m={'public_roots':[{'module':'Base','theorem':'Base.root'}],'supplemental_roots':actual}
        self.assertEqual(ci.audit_roots(m),[('Base','Base.root'),('ExtraB','Example.b'),('ExtraB','Example.c'),('ExtraA','Example.a')])
    def test_base_and_external_namespace_shadow_rejected(self):
        for name in ['Base','Mathlib']:
            self.write([self.entry(name)])
            with self.assertRaisesRegex(RuntimeError,'shadows'):ci.supplemental_graph(self.graph)
    def test_hash_and_path_are_enforced(self):
        entry=self.entry('Extra');entry['sha256']='0'*64;self.write([entry])
        with self.assertRaisesRegex(RuntimeError,'hash mismatch'):ci.supplemental_graph(self.graph)
        entry=self.entry('Extra');entry['path']='shared/../Base.lean';self.write([entry])
        with self.assertRaisesRegex(RuntimeError,'path must'):ci.supplemental_graph(self.graph)
    def test_unregistered_project_import_rejected(self):
        self.write([self.entry('Extra','import HiddenProjectHelper\n')])
        with self.assertRaisesRegex(RuntimeError,'unresolved'):ci.supplemental_graph(self.graph)
    def test_supplemental_cycle_rejected(self):
        self.write([self.entry('ExtraA','import ExtraB\n'),self.entry('ExtraB','import ExtraA\n')])
        with self.assertRaisesRegex(RuntimeError,'cycle'):ci.supplemental_graph(self.graph)
    def test_changed_theorem_roots_invalidate_graph_key(self):
        self.write([self.entry('Extra',theorems=['Example.first'])])
        graph,entries=ci.supplemental_graph(self.graph)
        m={'public_roots':[{'module':'Base','theorem':'Base.root'}],'supplemental_roots':entries}
        first=ci.graph_key('compiler',m,graph,['Base','Extra'])
        m['supplemental_roots'][0]['theorems']=['Example.second']
        self.assertNotEqual(first,ci.graph_key('compiler',m,graph,['Base','Extra']))
    def test_duplicate_modules_and_empty_audit_roots_rejected(self):
        entry=self.entry('Extra');self.write([entry,entry])
        with self.assertRaisesRegex(RuntimeError,'shadows'):ci.supplemental_graph(self.graph)
        entry['theorems']=[];self.write([entry])
        with self.assertRaisesRegex(RuntimeError,'theorem roots'):ci.supplemental_graph(self.graph)
if __name__=='__main__': unittest.main()
