#!/usr/bin/env python3
"""Execute only security-audit.sh's extracted pure Python scope predicate.

This never executes the audit shell, binaries, builds, RPCs, or proofs.
"""
from __future__ import annotations

import argparse
import copy
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
    ('executed-exact-v0113-premainnet-source-backend-h0',
     'exact-v0113-premainnet-source-current-binary-backend-and-h0-only'),
)
COMBINED_FALSE_FIELDS = (
    'production_authority', 'private_spend_launch_authority', 'current_network_G8_qualified',
    'public_cutover_authorized', 'mainnet_authorized', 'activation_authorized',
    'physical_asic_qualified',
)
COMBINED_TRUE_FIELDS = ('passed', 'actual_new_binary_proof_verification',
    'affected_lifecycle_verified')


def combined_candidate(target='x86_64-unknown-linux-gnu'):
    return {**dict.fromkeys(COMBINED_FALSE_FIELDS, False),
        **dict.fromkeys(COMBINED_TRUE_FIELDS, True),
        'mode': 'executed-combined-upgrade-software-candidate',
        'target_triple': target, 'candidate_binding_sha256': 'a' * 64,
        'artifact_manifest_sha256': 'b' * 64,
        'identity': {'schema': 'hegemon.private-spend.native-launch-identity.v2',
            'kind': 'PrivateSpend', 'network_profile': 'pre-mainnet',
            'relation_id': 'Hegemon.PrivateSpend.BoundedPolicy.CompFF01.Packed.v4',
            'public_words': 86, 'chain_id': 'c' * 64, 'genesis_hash': 'd' * 64,
            'manifest_digest': 'e' * 128, 'relation_digest': 'f' * 128}}


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
            payload['authorization_scope'] = CURRENT_BACKEND_PAIRS[(index + 1) % len(CURRENT_BACKEND_PAIRS)][1]
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

    def test_combined_software_candidate_has_a_distinct_scope_on_all_release_targets(self):
        for target in ('aarch64-apple-darwin', 'x86_64-apple-darwin',
                'x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc'):
            with self.subTest(target=target):
                self.assertEqual(classify(combined_candidate(target)), 'combined-software-candidate')

    def test_combined_requires_strict_true_evidence(self):
        for field in COMBINED_TRUE_FIELDS:
            for value in (False, 1, 'true', None):
                with self.subTest(field=field, value=value):
                    payload = combined_candidate()
                    payload[field] = value
                    with self.assertRaises(SystemExit):
                        classify(payload)

    def test_combined_rejects_every_authority_upgrade_and_wrong_boundary_type(self):
        for field in COMBINED_FALSE_FIELDS:
            for value in (True, 0, 'false', None):
                with self.subTest(field=field, value=value):
                    payload = combined_candidate()
                    payload[field] = value
                    with self.assertRaises(SystemExit):
                        classify(payload)

    def test_combined_rejects_each_missing_required_field(self):
        base = combined_candidate()
        for field in base:
            with self.subTest(missing=field):
                payload = copy.deepcopy(base)
                del payload[field]
                with self.assertRaises(SystemExit):
                    classify(payload)
        for field in base['identity']:
            with self.subTest(missing_identity_field=field):
                payload = copy.deepcopy(base)
                del payload['identity'][field]
                with self.assertRaises(SystemExit):
                    classify(payload)

    def test_combined_rejects_malformed_binding_hashes(self):
        for field in ('candidate_binding_sha256', 'artifact_manifest_sha256'):
            for value in (None, True, 64, [], '', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64):
                with self.subTest(field=field, value=value):
                    payload = combined_candidate()
                    payload[field] = value
                    with self.assertRaises(SystemExit):
                        classify(payload)

    def test_combined_rejects_malformed_target_and_identity(self):
        for value in (None, True, 3, [], '', 'linux', 'x86_64-linux',
                'x86_64/unknown-linux-gnu', ' x86_64-unknown-linux-gnu',
                'x86_64-unknown-linux-gnu\n'):
            with self.subTest(target=value):
                payload = combined_candidate()
                payload['target_triple'] = value
                with self.assertRaises(SystemExit):
                    classify(payload)
        for value in (None, True, 86, [], '', {}):
            with self.subTest(identity=value):
                payload = combined_candidate()
                payload['identity'] = value
                with self.assertRaises(SystemExit):
                    classify(payload)
        for field, values in {
                'schema': (None, True, 'other'),
                'kind': (None, True, 'OtherSpend'),
                'network_profile': (None, True, 'mainnet'),
                'relation_id': (None, True, 'other'),
                'public_words': (None, True, '86', 86.0, 87),
                'chain_id': (None, True, 'C' * 64, 'c' * 63),
                'genesis_hash': (None, True, 'D' * 64, 'd' * 65),
                'manifest_digest': (None, True, 'E' * 128, 'e' * 127),
                'relation_digest': (None, True, 'F' * 128, 'f' * 129),
                }.items():
            for value in values:
                with self.subTest(identity_field=field, value=value):
                    payload = combined_candidate()
                    payload['identity'][field] = value
                    with self.assertRaises(SystemExit):
                        classify(payload)

    def test_combined_mode_cannot_be_crossed_with_other_executed_scopes(self):
        for mode in (None, True, '', 'executed', 'executed-private-spend-launch',
                'source-only', 'H0-only', 'executed-combined-upgrade-software-candidate-extra',
                *(pair[0] for pair in CURRENT_BACKEND_PAIRS)):
            with self.subTest(mode=mode):
                payload = combined_candidate()
                payload['mode'] = mode
                with self.assertRaises(SystemExit):
                    classify(payload)
        for pair in CURRENT_BACKEND_PAIRS:
            with self.subTest(crossed_scope=pair):
                payload = current_backend(pair)
                payload['mode'] = 'executed-combined-upgrade-software-candidate'
                with self.assertRaises(SystemExit):
                    classify(payload)
        payload = combined_candidate()
        payload['mode'] = 'review-unapproved-profile'
        self.assertEqual(classify(payload), 'review')

    def test_combined_attestation_does_not_set_legacy_or_private_authority(self):
        matches = re.findall(r'        if \[ "\$PROFILE_SCOPE" = legacy \]; then\n(.*?)        fi\n',
            AUDIT_TEXT, re.S)
        self.assertEqual(len(matches), 1)
        flags = ('BINARY_PROFILE_AUTHORIZED', 'BINARY_PRIVATE_LAUNCH_AUTHORIZED',
            'BINARY_CURRENT_BACKEND_ATTESTED', 'BINARY_COMBINED_SOFTWARE_CANDIDATE_ATTESTED')
        for scope, expected in (
                (classify(combined_candidate()), ('false', 'false', 'false', 'true')),
                ('legacy', ('true', 'false', 'false', 'false')),
                ('private', ('false', 'true', 'false', 'false')),
                ('current-backend', ('false', 'false', 'true', 'false')),
                ('review', ('false', 'false', 'false', 'false'))):
            with self.subTest(scope=scope):
                script = '\n'.join(flag + '=false' for flag in flags) + '\n'
                script += 'PROFILE_SCOPE=' + shlex.quote(scope) + '\n'
                script += 'if [ "$PROFILE_SCOPE" = legacy ]; then\n' + matches[0] + 'fi\n'
                script += "printf '%s\\n' " + ' '.join('"$' + flag + '"' for flag in flags)
                result = subprocess.run(['bash', '-c', script], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.assertEqual(tuple(result.stdout.splitlines()), expected)


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
