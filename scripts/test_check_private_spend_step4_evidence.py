import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
import io

import check_private_spend_step4_evidence as checker


class EvidenceAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS /var is a symlink; use the canonical temporary root.
        self.root = Path(self.temp.name).resolve()
        (self.root / '.agent').mkdir()
        self.source = self.root / 'source.rs'
        self.source.write_bytes(b'frozen source')
        self.pin = hashlib.sha256(self.source.read_bytes()).hexdigest()

    def freeze(self, **extra):
        doc = {'source_files': [{'path': 'source.rs', 'sha256': self.pin}], 'ignored_cli_source': {'path': 'source.rs', 'sha256': self.pin}}
        doc.update(extra)
        (self.root / checker.FREEZE).write_text(json.dumps(doc))

    def run_audit(self):
        return checker.audit(self.root)

    def test_missing_path_fails(self):
        self.freeze(runtime_inventory={'path': 'gone.json', 'sha256': '0' * 64})
        report, code = self.run_audit()
        self.assertEqual(code, 1)
        self.assertIn('MISSING', report['summary']['status_counts'])

    def test_tampered_source_fails(self):
        self.freeze()
        self.source.write_bytes(b'tampered')
        report, code = self.run_audit()
        self.assertEqual(code, 1)
        self.assertEqual(report['summary']['frozen_runtime_or_formal_drift'], ['source.rs'])

    def test_valid_sources_do_not_replace_missing_proofs(self):
        self.freeze(current_six_proofs={'path': 'proof-progress.json', 'branches': 6}, qualification_status='PASS', production_authorized=True)
        report, code = self.run_audit()
        self.assertEqual(code, 1)
        self.assertEqual(report['summary']['frozen_runtime_or_formal_drift'], [])
        self.assertEqual(report['gates_passed_by_this_audit'], 0)
        self.assertFalse(report['production_authorized'])
        self.assertEqual(report['qualification_status'], 'NOT_ESTABLISHED_BY_THIS_AUDIT')

    def test_stale_descriptor_is_detected_recursively(self):
        self.freeze()
        (self.root / 'object.olean').write_bytes(b'changed object')
        comp = {'status': 'COMPILE_PASS', 'compile': {'command': ['lean', '-o', str(self.root / 'object.olean'), str(self.source)], 'output_olean_sha256': '0' * 64, 'source_sha256': self.pin}}
        (self.root / '.agent/private-spend-test-component.json').write_text(json.dumps(comp))
        report, code = self.run_audit()
        self.assertEqual(code, 1)
        self.assertTrue(any(r['path'].endswith('object.olean') and r['status'] == 'HASH_MISMATCH' for r in report['references']))

    def test_available_inventory_never_fabricates_qualification(self):
        self.freeze(qualification_status='ALL_PASS', production_authorized=True)
        first, code = self.run_audit()
        second, _ = self.run_audit()
        self.assertEqual(code, 0)
        self.assertEqual(first, second)
        self.assertEqual(first['gates_passed_by_this_audit'], 0)
        self.assertFalse(first['production_authorized'])
        self.assertEqual(first['inventory_status'], 'REFERENCED_FILES_AVAILABLE')

    def test_symlink_and_escape_rejected(self):
        (self.root / 'link.rs').symlink_to(self.source)
        self.freeze(extra=[{'path': 'link.rs', 'sha256': self.pin}, {'path': '../outside', 'sha256': self.pin}])
        report, code = self.run_audit()
        self.assertEqual(code, 1)
        statuses = report['summary']['status_counts']
        self.assertIn('REJECTED_OR_UNREADABLE', statuses)
        self.assertIn('REJECTED_PATH', statuses)

    def test_unbound_hash_does_not_guess_path(self):
        self.freeze(receipt_pins={'unlocated.log': '0' * 64})
        report, code = self.run_audit()
        self.assertEqual(code, 0)
        self.assertTrue(report['unbound_hash_claims'])
        self.assertFalse(any(r['path'] == 'unlocated.log' for r in report['references']))

    def test_document_drift_separate(self):
        self.freeze()
        doc = json.loads((self.root / checker.FREEZE).read_text())
        doc['source_files'].append({'path': 'note.md', 'sha256': '0' * 64})
        (self.root / 'note.md').write_text('changed note')
        (self.root / checker.FREEZE).write_text(json.dumps(doc))
        report, code = self.run_audit()
        self.assertEqual(code, 1)
        self.assertEqual(report['summary']['frozen_document_drift'], ['note.md'])
        self.assertEqual(report['summary']['frozen_runtime_or_formal_drift'], [])

    def test_cli_writes_report_outside_source_and_preserves_existing_receipt(self):
        self.freeze()
        destination = self.root.parent / (self.root.name + '-audit.json')
        self.addCleanup(lambda: destination.unlink(missing_ok=True))
        args = ['--root', str(self.root), '--output', str(destination)]
        self.assertEqual(checker.main(args), 0)
        original = destination.read_bytes()
        self.assertFalse(json.loads(original)['production_authorized'])
        with self.assertRaises(FileExistsError):
            checker.main(args)
        self.assertEqual(destination.read_bytes(), original)

    def test_cli_rejects_source_destination_and_symlink_parent(self):
        self.freeze()
        within_root = self.root / 'audit.json'
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            checker.main(['--root', str(self.root), '--output', str(within_root)])
        self.assertFalse(within_root.exists())
        parent_link = self.root.parent / (self.root.name + '-output-link')
        parent_link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(parent_link.unlink)
        with self.assertRaises(OSError):
            checker.main(['--root', str(self.root), '--output', str(parent_link / 'audit.json')])
        self.assertFalse(within_root.exists())


if __name__ == '__main__':
    unittest.main()
