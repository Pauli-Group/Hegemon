#!/usr/bin/env python3
"""Exact predecessor debt cannot authorize new or modified unformatted source."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('format_gate',Path(__file__).with_name('check_qualified_formatting.py'))
gate=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(gate)

class FormattingTests(unittest.TestCase):
    def setUp(self):
        scratch=tempfile.TemporaryDirectory();self.addCleanup(scratch.cleanup)
        self.root=Path(scratch.name).resolve();self.file=self.root/'old.rs';self.file.write_text('fn old( ){ }\n')
        self.baseline={'old.rs':hashlib.sha256(self.file.read_bytes()).hexdigest()}
        self.output=f'Diff in {self.file}:1:\n-fn old( ){{ }}\n+fn old() {{}}\n'

    def test_exact_predecessor_and_clean_changed_source(self):
        paths=gate.parse_failure(self.root,1,self.output,'')
        gate.verify_failures(self.root,paths,self.baseline)
        self.file.write_text('fn old() {}\n')
        gate.verify_failures(self.root,gate.parse_failure(self.root,0,'',''),self.baseline)

    def test_changed_unformatted_source_rejects(self):
        self.file.write_text('fn new( ){ }\n')
        with self.assertRaises(gate.Rejected):gate.verify_failures(self.root,{'old.rs'},self.baseline)

    def test_new_debt_rejects(self):
        (self.root/'new.rs').write_text('fn new( ){ }\n')
        with self.assertRaises(gate.Rejected):gate.verify_failures(self.root,{'new.rs'},self.baseline)

    def test_baseline_pin_and_missing_baseline_reject(self):
        with self.assertRaises(gate.Rejected):gate.load_baseline(self.root/'missing.json')
        p=self.root/'baseline.json';p.write_text('{}')
        with self.assertRaises(gate.Rejected):gate.load_baseline(p)

    def test_parse_errors_and_unknown_output_reject(self):
        for code,out,err in [(1,'','parse error'),(2,self.output,''),(1,'mystery',''),(0,self.output,''),(1,'',''),(1,'stray\n'+self.output,'')]:
            with self.subTest(out=out),self.assertRaises(gate.Rejected):gate.parse_failure(self.root,code,out,err)

    def test_path_escape_rejects(self):
        with self.assertRaises(gate.Rejected):gate.parse_failure(self.root,1,'Diff in /outside.rs:1:\n-x\n+y\n','')

    def test_only_exact_version_display_migration_is_allowed(self):
        before=b'old_version() + old_version()\n';after=b'new_version() + new_version()\n'
        self.file.write_bytes(after)
        baseline={'old.rs':hashlib.sha256(before).hexdigest()}
        migration={'path':'old.rs','qualified_sha256':baseline['old.rs'],
                   'postimage_sha256':hashlib.sha256(after).hexdigest(),
                   'old':'old_version()','new':'new_version()','replacement_count':2}
        with patch.object(gate,'VERSION_DISPLAY_MIGRATION',migration):
            gate.verify_failures(self.root,{'old.rs'},baseline)
            self.file.write_bytes(after+b'// unrelated change\n')
            with self.assertRaises(gate.Rejected):gate.verify_failures(self.root,{'old.rs'},baseline)
            self.file.write_bytes(b'new_version() + old_version()\n')
            with self.assertRaises(gate.Rejected):gate.verify_failures(self.root,{'old.rs'},baseline)

    def test_checked_in_baseline_has_identical_qualified_hashes(self):
        baseline=gate.load_baseline(gate.ROOT/gate.BASELINE)
        self.assertEqual(len(baseline),38)

if __name__=='__main__':unittest.main()
