#!/usr/bin/env python3
"""Execute only security-audit.sh's extracted pure Python scope predicate.

This never executes the audit shell, binaries, builds, RPCs, or proofs.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import sys
import unittest
from unittest import mock


CURRENT_BACKEND_PAIRS = (
    ('executed-exact-source-backend-h0',
     'exact-current-source-current-binary-backend-and-h0-only'),
    ('executed-exact-sync-import-source-backend-h0',
     'exact-sync-import-source-current-binary-backend-and-h0-only'),
)


def current_backend(pair=CURRENT_BACKEND_PAIRS[0]):
    return {'passed': True, 'production_authority': False,
        'private_spend_launch_authority': False,
        'mode': pair[0], 'authorization_scope': pair[1],
        'actual_new_binary_proof_verification': True,
        'current_network_G8_qualified': False, 'fresh_network_lifecycle_verified': False,
        'state_admission_verified': False, 'public_cutover_authorized': False,
        'historical_G8_reused': True, 'predecessor_lifecycle_reexecuted': False}


def classify(payload):
    output = io.StringIO()
    with mock.patch.object(sys, 'stdin', io.StringIO(json.dumps(payload))), redirect_stdout(output):
        exec(PREDICATE, {'__name__': '_unit_scope_only'})
    return output.getvalue().strip()


class SecurityAuditScopeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for pair in CURRENT_BACKEND_PAIRS:
            if classify(current_backend(pair)) != 'current-backend':
                raise AssertionError('each exact current-backend pair must pass before mutations')

    def test_canonical_current_backend_is_distinct_from_launch_authority(self):
        for pair in CURRENT_BACKEND_PAIRS:
            with self.subTest(pair=pair):
                self.assertEqual(classify(current_backend(pair)), 'current-backend')

    def test_source_only_or_h0_only_cannot_replace_actual_proof_verification(self):
        for pair in CURRENT_BACKEND_PAIRS:
            for value in (False, 1, 'true', None):
                with self.subTest(pair=pair, value=value):
                    payload = current_backend(pair)
                    payload['actual_new_binary_proof_verification'] = value
                    with self.assertRaises(SystemExit):
                        classify(payload)

    def test_each_required_false_boundary_is_enforced(self):
        for pair in CURRENT_BACKEND_PAIRS:
            for field in ('production_authority', 'private_spend_launch_authority', 'current_network_G8_qualified', 'fresh_network_lifecycle_verified', 'state_admission_verified', 'public_cutover_authorized', 'predecessor_lifecycle_reexecuted'):
                for value in (True, 0, 'false', None):
                    with self.subTest(pair=pair, field=field, value=value):
                        payload = current_backend(pair)
                        payload[field] = value
                        with self.assertRaises(SystemExit):
                            classify(payload)

    def test_pass_and_historical_reuse_are_strict_booleans(self):
        for pair in CURRENT_BACKEND_PAIRS:
            for field in ('passed', 'historical_G8_reused'):
                for value in (False, 1, 'true', None):
                    with self.subTest(pair=pair, field=field, value=value):
                        payload = current_backend(pair)
                        payload[field] = value
                        with self.assertRaises(SystemExit):
                            classify(payload)

    def test_each_missing_required_flag_rejects_for_both_pairs(self):
        for pair in CURRENT_BACKEND_PAIRS:
            base = current_backend(pair)
            for field in set(base) - {'mode', 'authorization_scope'}:
                with self.subTest(pair=pair, missing=field):
                    payload = dict(base)
                    del payload[field]
                    with self.assertRaises(SystemExit):
                        classify(payload)

    def test_mode_and_scope_cannot_be_crossed_or_partial(self):
        for index, pair in enumerate(CURRENT_BACKEND_PAIRS):
            payload = current_backend(pair)
            payload['authorization_scope'] = CURRENT_BACKEND_PAIRS[1 - index][1]
            with self.subTest(pair=pair, mutation='crossed'), self.assertRaises(SystemExit):
                classify(payload)
            for field in ('mode', 'authorization_scope'):
                payload = current_backend(pair)
                del payload[field]
                with self.subTest(pair=pair, missing=field), self.assertRaises(SystemExit):
                    classify(payload)

    def test_source_and_h0_modes_cannot_use_current_backend_scope(self):
        for pair in CURRENT_BACKEND_PAIRS:
            for mode in ('reviewed-source-successor-ci', 'source-only', 'H0-only', 'executed-private-spend-launch'):
                with self.subTest(pair=pair, mode=mode):
                    payload = current_backend(pair)
                    payload['mode'] = mode
                    with self.assertRaises(SystemExit):
                        classify(payload)

    def test_legacy_private_launch_branch_is_preserved(self):
        payload = {'passed': True, 'production_authority': False,
            'private_spend_launch_authority': True, 'mode': 'executed-private-spend-launch',
            'authorization_scope': 'source-owned-current86-private-spend-launch'}
        self.assertEqual(classify(payload), 'private')

    def test_legacy_authorized_and_review_branches_are_preserved(self):
        self.assertEqual(classify({'passed': True, 'production_authority': True, 'mode': 'executed'}), 'legacy')
        self.assertEqual(classify({'passed': True, 'production_authority': False, 'mode': 'review-unapproved-profile'}), 'review')


    def manifest_specs(self, root, paths):
        marker = '        python3 "$PROJECT_ROOT/scripts/release_artifact_manifest.py" verify \\\n'
        start = AUDIT_TEXT.index(marker)
        end = AUDIT_TEXT.index(' >/dev/null && \\\n', start)
        command = AUDIT_TEXT[start:end] + ' >/dev/null\n'
        with tempfile.TemporaryDirectory(prefix='hegemon-audit-argv-') as scratch:
            capture = Path(scratch) / 'argv'
            script = (
                f"PROJECT_ROOT={shlex.quote(root)}\n"
                f"BINARY_MANIFEST={shlex.quote(root + '/target/release/manifest.json')}\n"
                f"CAPTURE={shlex.quote(str(capture))}\n"
                "RELEASE_BINS=(" + ' '.join(shlex.quote(p) for p in paths) + ")\n"
                "python3() { printf '%s\\0' \"$@\" > \"$CAPTURE\"; }\n"
                + command
            )
            subprocess.run(['bash', '-c', script], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            raw = capture.read_bytes().split(b'\0')
        self.assertEqual(raw[-1], b'')
        argv = [value.decode('utf-8') for value in raw[:-1]]
        self.assertEqual(argv[:2], [root + '/scripts/release_artifact_manifest.py', 'verify'])
        specs = [argv[i + 1] for i, value in enumerate(argv) if value == '--expect']
        self.assertEqual(len(specs), 4)
        return specs

    def test_manifest_specs_use_relative_paths_for_msys_and_spaced_roots(self):
        identities = ('hegemon-node:hegemon-node', 'wallet:wallet',
            'walletd:walletd', 'wallet:private-spend')
        names = ('hegemon-node.exe', 'wallet.exe', 'walletd.exe', 'private-spend.exe')
        for root in ('/d/a/Hegemon/Hegemon', '/d/a/Hegemon with spaces/Hegemon',
                '/private/tmp/release with spaces'):
            with self.subTest(root=root):
                paths = [root + '/target/release/' + name for name in names]
                specs = self.manifest_specs(root, paths)
                self.assertEqual(specs, [identity + ':target/release/' + name
                    for identity, name in zip(identities, names)])
                self.assertTrue(all(':/' not in spec for spec in specs))

    def test_manifest_specs_preserve_outside_and_prefix_lookalike_paths(self):
        root = '/d/a/Hegemon/Hegemon'
        for outside in ('/d/a/external/node.exe', root + '-other/node.exe'):
            with self.subTest(outside=outside):
                paths = [outside] + [root + '/target/release/' + name
                    for name in ('wallet.exe', 'walletd.exe', 'private-spend.exe')]
                self.assertEqual(self.manifest_specs(root, paths)[0],
                    'hegemon-node:hegemon-node:' + outside)

    def test_manifest_specs_do_not_normalize_away_traversal(self):
        root = '/d/a/Hegemon/Hegemon'
        paths = [root + '/../external/node.exe'] + [root + '/target/release/' + name
            for name in ('wallet.exe', 'walletd.exe', 'private-spend.exe')]
        self.assertEqual(self.manifest_specs(root, paths)[0],
            'hegemon-node:hegemon-node:../external/node.exe')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit-script', type=Path, required=True)
    args = parser.parse_args()
    raw = args.audit_script.read_text()
    matches = re.findall(r"PROFILE_SCOPE=\$\(python3 -c '(.*?)' <<< \"\$PROFILE_RESULT\"\)", raw, re.S)
    if len(matches) != 1:
        raise SystemExit('expected exactly one embedded profile-scope predicate')
    global PREDICATE, AUDIT_TEXT
    AUDIT_TEXT = raw
    PREDICATE = compile(matches[0], str(args.audit_script) + ':embedded-profile-scope', 'exec')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SecurityAuditScopeControls))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
