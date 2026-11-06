#!/usr/bin/env python3
"""Run all historical scope controls against the exact sync/import successor.

Both the original test implementation and additive checker are authenticated
before import. The historical checker stays unchanged; its specialized module
receives the new exact configuration. These are validator controls, never
artifact, proof execution, G8, production or deployment evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

WRAPPER = 'scripts/check_v011_sync_import_successor.py'
WRAPPER_SHA256 = '7635a5ae405401b9cba51c60a702cd6ff1bdb6379a9e8c6cb197d067b9766200'
HISTORICAL_TEST = 'scripts/tests/v011_current_successor/test_successor_scope.py'
HISTORICAL_TEST_SHA256 = 'bc00483a0671fe41d9b69f37c2b0bdf27d65f4879263b9b8dcbea915a876fc15'
NEW_MODULES = (
    'node/src/native/sync_body_backpressure.rs',
    'node/src/native/sync_control_backpressure_tests.rs',
)


def load_pinned(root, relative, expected, name):
    path = root / relative
    if (not path.is_file() or path.is_symlink() or path.resolve() != path
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
        raise ValueError('composed scope control input differs: ' + relative)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError('cannot import pinned scope control input: ' + relative)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


class ExactAddedModuleControls(unittest.TestCase):
    def test_both_additions_have_the_exact_reviewed_bytes_and_no_parent_postimage(self):
        for relative in NEW_MODULES:
            with self.subTest(path=relative):
                descriptor = WRAPPED.OVERLAY[relative]
                self.assertIsNone(descriptor['before_sha256'])
                self.assertNotIn(relative, PARENT_CONFIG['reviewed_source_additions'])
                raw = CHECKER.safe_file(SOURCE_ROOT, relative).read_bytes()
                self.assertEqual(len(raw), descriptor['bytes'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), descriptor['after_sha256'])
                self.assertEqual(SOURCE_CONFIG['reviewed_source_additions'][relative],
                                 {'bytes': len(raw), 'sha256': descriptor['after_sha256']})
                self.assertFalse((PREDECESSOR / relative).exists())

    def test_each_missing_or_mutated_added_module_rejects_before_inherited_execution(self):
        # Exercise the real additive preflight against copied exact authorities
        # and postimages; mutate only this invocation's temporary source copy.
        with tempfile.TemporaryDirectory(prefix='sync-import-added-module-control-') as directory:
            scratch = Path(directory)
            for relative in (WRAPPED.CONFIG, WRAPPED.PARENT_CONFIG,
                             WRAPPED.PARENT_CHECKER, *WRAPPED.OVERLAY):
                destination = scratch / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SOURCE_ROOT / relative, destination)
            WRAPPED.load_binding(scratch)
            for relative in NEW_MODULES:
                destination = scratch / relative
                raw = destination.read_bytes()
                destination.write_bytes(raw + b'\n// unreviewed mutation\n')
                with self.subTest(path=relative, mutation='postimage'), self.assertRaises(WRAPPED.SuccessorError):
                    WRAPPED.load_binding(scratch)
                destination.unlink()
                with self.subTest(path=relative, mutation='missing'), self.assertRaises(WRAPPED.SuccessorError):
                    WRAPPED.load_binding(scratch)
                destination.write_bytes(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--predecessor-root', required=True, type=Path)
    parser.add_argument('--fixture-manifest', type=Path)
    args = parser.parse_args()
    global WRAPPED, CHECKER, SOURCE_ROOT, SOURCE_CONFIG, PARENT_CONFIG, PREDECESSOR
    try:
        SOURCE_ROOT = args.source_root.resolve(strict=True)
        PREDECESSOR = args.predecessor_root.resolve(strict=True)
        if not SOURCE_ROOT.is_dir() or not PREDECESSOR.is_dir() or SOURCE_ROOT == PREDECESSOR:
            raise ValueError('separate existing source and authenticated predecessor roots required')
        WRAPPED = load_pinned(SOURCE_ROOT, WRAPPER, WRAPPER_SHA256, '_sync_import_scope_wrapper')
        CHECKER, SOURCE_CONFIG, PARENT_CONFIG = WRAPPED.load_binding(SOURCE_ROOT)
        for relative, expected in ((CHECKER.CHECKER, CHECKER.EXPECTED_CHECKER),
                                   (CHECKER.REGISTRY, CHECKER.EXPECTED_REGISTRY)):
            if CHECKER.digest_bytes(CHECKER.safe_file(PREDECESSOR, relative).read_bytes()) != expected:
                raise ValueError('immutable predecessor authority differs: ' + relative)
        original = load_pinned(SOURCE_ROOT, HISTORICAL_TEST, HISTORICAL_TEST_SHA256,
                               '_sync_import_historical_scope_controls')
        fixture_path = args.fixture_manifest.resolve(strict=True) if args.fixture_manifest else SOURCE_ROOT / 'release-evidence/v0.11-current-proof-fixture/manifest.json'
        fixture_raw = fixture_path.read_bytes()
        fixture_sha = hashlib.sha256(fixture_raw).hexdigest()
        if fixture_sha != CHECKER.CURRENT_FIXTURE_SHA256:
            raise ValueError('current public proof fixture identity differs')
        # Preserve all original test classes and their unmodified assertions.
        # ImmutableAuthorityChecks reads CHECKER.__file__, the pinned old checker.
        original.CHECKER = CHECKER
        original.SOURCE_ROOT = SOURCE_ROOT
        original.SOURCE_CONFIG = SOURCE_ROOT / WRAPPED.CONFIG
        original.SOURCE_CONFIG_DATA = SOURCE_CONFIG
        original.PREDECESSOR = PREDECESSOR
        original.FIXTURE_MANIFEST = json.loads(fixture_raw)
        original.FIXTURE_SHA = fixture_sha
        classes = (original.CurrentBinaryProofChecks, original.RuntimePostimageChecks,
                   original.ImmutableAuthorityChecks, ExactAddedModuleControls)
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in classes)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print('sync/import composed scope controls rejected: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
