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
import sys
import unittest
from unittest import mock


def current_backend():
    return {'passed': True, 'production_authority': False,
        'private_spend_launch_authority': False,
        'mode': 'executed-exact-source-backend-h0',
        'authorization_scope': 'exact-current-source-current-binary-backend-and-h0-only',
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
        if classify(current_backend()) != 'current-backend':
            raise AssertionError('canonical current-backend base must pass before mutations')

    def test_canonical_current_backend_is_distinct_from_launch_authority(self):
        self.assertEqual(classify(current_backend()), 'current-backend')

    def test_source_only_or_h0_only_cannot_replace_actual_proof_verification(self):
        for value in (False, 1, 'true', None):
            with self.subTest(value=value):
                payload = current_backend()
                payload['actual_new_binary_proof_verification'] = value
                with self.assertRaises(SystemExit):
                    classify(payload)

    def test_each_required_false_boundary_is_enforced(self):
        for field in ('production_authority', 'private_spend_launch_authority', 'current_network_G8_qualified', 'fresh_network_lifecycle_verified', 'state_admission_verified', 'public_cutover_authorized', 'predecessor_lifecycle_reexecuted'):
            for value in (True, 0, 'false', None):
                with self.subTest(field=field, value=value):
                    payload = current_backend()
                    payload[field] = value
                    with self.assertRaises(SystemExit):
                        classify(payload)

    def test_pass_and_historical_reuse_are_strict_booleans(self):
        for field in ('passed', 'historical_G8_reused'):
            for value in (False, 1, 'true', None):
                with self.subTest(field=field, value=value):
                    payload = current_backend()
                    payload[field] = value
                    with self.assertRaises(SystemExit):
                        classify(payload)

    def test_source_and_h0_modes_cannot_use_current_backend_scope(self):
        for mode in ('reviewed-source-successor-ci', 'source-only', 'H0-only', 'executed-private-spend-launch'):
            with self.subTest(mode=mode):
                payload = current_backend()
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit-script', type=Path, required=True)
    args = parser.parse_args()
    raw = args.audit_script.read_text()
    matches = re.findall(r"PROFILE_SCOPE=\$\(python3 -c '(.*?)' <<< \"\$PROFILE_RESULT\"\)", raw, re.S)
    if len(matches) != 1:
        raise SystemExit('expected exactly one embedded profile-scope predicate')
    global PREDICATE
    PREDICATE = compile(matches[0], str(args.audit_script) + ':embedded-profile-scope', 'exec')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SecurityAuditScopeControls))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
