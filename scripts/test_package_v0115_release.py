#!/usr/bin/env python3
"""Synthetic v0.11.5 provenance/archive controls; no Git or binaries execute."""
from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('v0115_packaging_under_test', HERE / 'package_v0115_release.py')
pack = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pack
spec.loader.exec_module(pack)
base = pack.base
FULL_RECEIPT_PREDICATE = pack.validate_full_final_receipt


class PackagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='v0115-packaging-unit-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / 'source'
        self.assets = self.root / 'assets'
        self.qualification = self.root / 'qualification'
        self.source_manifests = self.root / 'source-manifests'
        self.source.mkdir()
        self.assets.mkdir()
        self.qualification.mkdir()
        self.source_manifests.mkdir()
        for name in (*pack._SOURCE_FILES, pack.WRAPPER_PATH, pack.TEST_PATH,
                     *(path for path, _ in pack.HISTORICAL_PROFILES.values())):
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((HERE.parent / name).read_bytes())
        # Keep the actual historical metadata byte-for-byte. The v115 source
        # record is distinct and only the bundle's canonical path is aliased.
        historical_release = self.source / pack.CANONICAL_RELEASE_PATH
        historical_release.write_bytes((HERE.parent / pack.CANONICAL_RELEASE_PATH).read_bytes())
        self.lock = (HERE.parent / 'Cargo.lock').read_bytes()
        (self.source / 'Cargo.lock').write_bytes(self.lock)
        self.build, self.tree, self.tree_sha = '1' * 40, '2' * 40, '3' * 64
        self.commit = '4' * 40
        self.head = self.build
        self.source_product_version = '0.11.5'
        self.package_versions = dict(pack.PACKAGE_VERSIONS)
        self.delta = b''.join(b'M\0' + name.encode() + b'\0' for name in sorted(pack.PACKAGING_PROFILE_CHANGES))
        self.pending = pack.pending_profile()
        self.untracked, self.dirty, self.ancestor = b'', False, True
        # Any unmocked process launch is an error. Provenance tests supply only
        # bounded synthetic Git responses, not a real repository or binary.
        for name in ('check_output', 'run', 'Popen'):
            patcher = mock.patch.object(pack.subprocess, name,
                                        side_effect=AssertionError('external process forbidden in unit tests'))
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(pack, 'git', side_effect=self.git)
        self.git_mock = patcher.start()
        self.addCleanup(patcher.stop)
        self.tree_function = pack.committed_tree_sha256
        patcher = mock.patch.object(pack, 'committed_tree_sha256', return_value=self.tree_sha)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.base_source_check = mock.patch.object(base, 'require_committed_source')
        self.source_check_mock = self.base_source_check.start()
        self.addCleanup(self.base_source_check.stop)
        # Positive synthetic archive controls do not execute proof validation.
        # Its mandatory invocation is asserted separately; the unmocked negative
        # control below proves flags-only records cannot use the real predicate.
        self.full_predicate_patch = mock.patch.object(pack, 'validate_full_final_receipt', return_value={})
        self.full_predicate = self.full_predicate_patch.start()
        self.addCleanup(self.full_predicate_patch.stop)
        for selected, (triple, fmt) in base.PLATFORMS.items():
            rows = []
            for binary in base.IDENTITIES:
                name = f'{binary}-{selected}' + ('.exe' if selected.startswith('windows') else '')
                data = self.native(selected) + binary.encode() + selected.encode()
                (self.assets / name).write_bytes(data)
                digest = base.sha(data)
                (self.assets / (name + '.sha256')).write_text(f'{digest}  {name}\n', encoding='ascii')
                rows.append(dict(package='wallet' if binary == 'private-spend' else binary,
                                 binary=binary, name=name, sha256=digest, size=len(data),
                                 native_format=fmt, checksum_name=name + '.sha256'))
            common = dict(schema_version=1, source_head=self.build, source_index_tree=self.tree,
                            source_tree_sha256=self.tree_sha, cargo_lock_sha256=base.sha(self.lock),
                            target_triple=triple)
            original = dict(common, artifacts=rows)
            raw_original = base.encoded(original)
            (self.source_manifests / f'hegemon-release-artifacts-{selected}.json').write_bytes(raw_original)
            manifest = dict(common, source_manifest_sha256=base.sha(raw_original), assets=rows)
            (self.assets / f'hegemon-release-assets-{selected}.json').write_bytes(base.encoded(manifest))
            receipt = {'schema': pack.FINAL_RECEIPT_SCHEMA, 'status': pack.FINAL_RECEIPT_STATUS,
                       'software_version': '0.11.5', 'target_triple': triple,
                       'artifact_manifest_sha256': manifest['source_manifest_sha256'],
                       'artifact_sha256': {row['binary']: row['sha256'] for row in rows},
                       'actual_new_binary_proof_verification': True,
                       'current_binary_backend_artifacts_verified': True,
                       'affected_lifecycle_verified': True,
                       'identity': {'relation_digest': pack.RELATION_DIGEST},
                       'identity_smoke': {'qualified_manifest': True, 'height': 0,
                                          'node_rpc_version': 'Hegemon Native Node 0.11.5'},
                       'production_authorized': False, 'mainnet_authorized': False,
                       'activation_authorized': False, 'public_cutover_authorized': False,
                       'deployment_verified': False, 'physical_asic_qualified': False}
            (self.qualification / pack.qualification_name(selected)).write_bytes(base.encoded(receipt))
        self.run = dict(databaseId=12345,
                        url='https://github.com/Pauli-Group/Hegemon/actions/runs/12345',
                        event='workflow_dispatch', status='completed', conclusion='success',
                        headSha=self.build, headBranch=pack.CANDIDATE_BRANCH, workflowName=pack.WORKFLOW,
                        jobs=[dict(name=name, status='completed', conclusion='success')
                              for name in sorted(pack.REQUIRED_JOBS)])
        self.run_path = self.root / 'ci-run.json'
        self.write_run()
        self.archive_dir = self.root / 'ci-downloads'
        self.archive_dir.mkdir()
        self.artifact_record = self.root / 'ci-artifacts.json'
        self.write_ci_artifacts()
        self.profile = self.derive()

    def git(self, source, *args):
        self.assertEqual(source, self.source)
        if args == ('rev-parse', 'HEAD'):
            return (self.head + '\n').encode()
        if args == ('rev-parse', self.build + '^{commit}'):
            return (self.build + '\n').encode()
        if args == ('rev-parse', self.build + '^{tree}'):
            return (self.tree + '\n').encode()
        if args == ('show', self.build + ':Cargo.lock'):
            return self.lock
        if args == ('show', self.build + ':protocol/versioning/src/lib.rs'):
            return f'pub const RELEASE_VERSION: &str = "{self.source_product_version}";\n'.encode()
        if len(args) == 2 and args[0] == 'show' and args[1].removeprefix(self.build + ':') in self.package_versions:
            name = args[1].removeprefix(self.build + ':')
            return f'[package]\nname = "fixture"\nversion = "{self.package_versions[name]}"\n'.encode()
        if args == ('show', self.build + ':' + pack.PROFILE_PATH):
            return base.encoded(self.pending)
        if args == ('diff', '--exit-code', 'HEAD', '--'):
            if self.dirty:
                raise subprocess.CalledProcessError(1, ['synthetic-git-diff'])
            return b''
        if args == ('merge-base', '--is-ancestor', self.build, self.commit):
            if not self.ancestor:
                raise subprocess.CalledProcessError(1, ['synthetic-git-ancestor'])
            return b''
        if args == ('diff', '--name-status', '-z', self.build, self.commit):
            return self.delta
        if args == ('ls-files', '--others', '--exclude-standard', '-z'):
            return self.untracked
        raise AssertionError('unexpected synthetic Git request: ' + repr(args))

    @staticmethod
    def native(selected):
        data = bytearray(256)
        if selected.startswith('linux'):
            data[:6] = b'\x7fELF\x02\x01'
            data[18:20] = (62).to_bytes(2, 'little')
        elif selected.startswith('macos'):
            data[:4] = b'\xcf\xfa\xed\xfe'
            data[4:8] = (0x0100000C if selected.endswith('arm64') else 0x01000007).to_bytes(4, 'little')
        else:
            data[:2] = b'MZ'
            data[60:64] = (128).to_bytes(4, 'little')
            data[128:134] = b'PE\0\0\x64\x86'
        return bytes(data)

    def write_run(self):
        self.run_path.write_bytes(base.encoded(self.run))

    def write_ci_artifacts(self):
        groups = {'premainnet-release-assets': {path.name: path for path in self.assets.iterdir()},
                  'v0115-preparation-evidence': {
                      **{'qualification-receipts/' + path.name: path for path in self.qualification.iterdir()},
                      **{'source-artifact-manifests/' + path.name: path for path in self.source_manifests.iterdir()}}}
        rows = []
        for index, (name, files) in enumerate(sorted(groups.items()), 1):
            path = self.archive_dir / (name + '.zip')
            with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as archive:
                for member, source in sorted(files.items()):
                    archive.writestr(member, source.read_bytes())
            rows.append({'id': index, 'name': name, 'size_in_bytes': path.stat().st_size,
                         'digest': 'sha256:' + base.sha(path.read_bytes()), 'expired': False,
                         'archive_download_url': f'https://api.github.com/repos/{pack.REPOSITORY}/actions/artifacts/{index}/zip',
                         'workflow_run': {'id': self.run['databaseId'], 'head_sha': self.build,
                                          'head_branch': pack.CANDIDATE_BRANCH}})
        self.artifact_record.write_bytes(base.encoded({'total_count': len(rows), 'artifacts': rows}))

    def derive(self):
        return pack.derive_profile(self.source, self.assets, self.run_path, self.build, self.qualification,
                                   self.source_manifests, self.artifact_record, self.archive_dir)

    def write_profile(self):
        (self.source / pack.PROFILE_PATH).write_bytes(base.encoded(self.profile))

    def package(self, suffix='one'):
        self.write_profile()
        output = self.root / ('archives-' + suffix)
        pack.package_release(self.source, self.assets, self.qualification, self.source_manifests,
                             self.run_path, self.artifact_record, self.archive_dir, output, self.commit)
        return output

    def test_exact_profile_schema_and_preserved_lock(self):
        self.assertEqual(set(self.profile), pack.FIELDS)
        self.assertEqual(self.profile['schema'], 'hegemon.v0115.release-artifacts.v1')
        self.assertEqual(self.profile['software_release'], 'v0.11.5')
        self.assertEqual(self.profile['software_version'], '0.11.5')
        self.assertEqual(self.profile['cargo_lock_sha256'], pack.LOCK_SHA256)
        self.assertEqual(self.profile['release_source_head'], self.profile['build_source_head'])
        forged = copy.deepcopy(self.profile)
        forged['cargo_lock_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'qualified Cargo.lock'):
            pack.validate_profile(forged, self.source)

    def test_historical_metadata_is_preserved_and_versioned_metadata_is_bundled(self):
        path = self.source / pack.CANONICAL_RELEASE_PATH
        before = path.read_bytes()
        self.assertEqual(before, (HERE.parent / pack.CANONICAL_RELEASE_PATH).read_bytes())
        self.assertEqual(json.loads(before)['software_version'], '0.11.4')
        self.package('versioned-metadata')
        self.assertEqual(path.read_bytes(), before)
        with pack.artifact_profile(self.profile, self.source):
            manifests = base.validate_assets(self.assets)
            entries = base.members(self.source, self.assets, 'linux-x86_64', manifests['linux-x86_64'], self.commit)
        self.assertEqual(json.loads(entries[pack.CANONICAL_RELEASE_PATH][0])['software_version'], '0.11.5')
        record = json.loads(entries['bundle.json'][0])
        self.assertIn(pack.RELEASE_METADATA_PATH, record['packaging_inputs'])
        self.assertNotIn(pack.CANONICAL_RELEASE_PATH, record['packaging_inputs'])

    def test_full_predicate_is_mandatory_and_summary_only_receipts_reject(self):
        self.assertEqual(self.full_predicate.call_count, 4)
        helper = pack.final_receipt_helper(HERE.parent)
        config = helper.load_config(HERE.parent)
        receipt = json.loads((self.qualification / pack.qualification_name('linux-x86_64')).read_bytes())
        original = json.loads((self.source_manifests / 'hegemon-release-artifacts-linux-x86_64.json').read_bytes())
        digest = base.sha(base.encoded(original))
        # Supply source-binding metadata so the real predicate reaches its
        # missing actual lifecycle checks, rather than failing a fixture setup.
        receipt.update(authorization_kind=helper.KIND, final_artifact_scope=helper.SCOPE,
                       independent_source_review=config['independent_review'],
                       candidate_binding_sha256=helper.binding(config),
                       source_inventory_sha256=config['source_inventory_sha256'])
        with mock.patch.object(pack, 'final_receipt_helper', return_value=helper), \
                mock.patch.object(helper, 'source_check'), mock.patch.object(helper, 'review_check'):
            with self.assertRaisesRegex(helper.CandidateError, 'actual proof/lifecycle evidence missing'):
                FULL_RECEIPT_PREDICATE(HERE.parent, receipt, original, digest)

    def test_committed_pending_template_is_exact_and_cannot_package(self):
        checked_in = json.loads((HERE.parent / pack.PROFILE_PATH).read_bytes())
        if checked_in['status'] == 'pending':
            pack.validate_pending_profile(checked_in)
        else:
            pack.validate_profile(checked_in, HERE.parent)
        pending = pack.pending_profile()
        self.assertEqual(pack.validate_pending_profile(pending), pack.pending_profile())
        with self.assertRaisesRegex(ValueError, 'not accepted'):
            pack.validate_profile(pending, self.source)
        for key, value in (('status', 'accepted'), ('build_source_head', self.build)):
            changed = copy.deepcopy(pending)
            changed[key] = value
            with self.assertRaisesRegex(ValueError, 'exact pending'):
                pack.validate_pending_profile(changed)
        pending['boundaries']['publication_authorized'] = 0
        with self.assertRaisesRegex(ValueError, 'exact pending'):
            pack.validate_pending_profile(pending)

    def test_artifact_acceptance_grants_no_publication_or_operational_authority(self):
        for name in pack.BOUNDARIES:
            for value in (True, 0, None):
                profile = copy.deepcopy(self.profile)
                profile['boundaries'][name] = value
                with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, 'cannot grant'):
                    pack.validate_profile(profile, self.source)

    def test_final_qualification_requires_actual_exact_platform_proof_and_lifecycle(self):
        path = self.qualification / pack.qualification_name('linux-x86_64')
        original = json.loads(path.read_bytes())
        changes = [('schema', 'hegemon.combined-upgrade.final-receipt.v1'),
                   ('status', 'PASS_PACKAGING_AND_IDENTITY_SMOKE_ONLY'),
                   ('software_version', '0.11.4'), ('target_triple', 'aarch64-apple-darwin'),
                   ('artifact_manifest_sha256', 'a' * 64),
                   ('artifact_sha256', dict.fromkeys(base.IDENTITIES, 'b' * 64)),
                   ('actual_new_binary_proof_verification', False),
                   ('current_binary_backend_artifacts_verified', False),
                   ('affected_lifecycle_verified', False),
                   ('identity', {'relation_digest': 'c' * 128}),
                   ('identity_smoke', {'qualified_manifest': False, 'height': 0,
                                       'node_rpc_version': 'Hegemon Native Node 0.11.5'})]
        for name, value in changes:
            receipt = copy.deepcopy(original)
            receipt[name] = value
            path.write_bytes(base.encoded(receipt))
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.derive()
        path.write_bytes(base.encoded(original))

    def test_final_qualification_cannot_expand_any_authority(self):
        path = self.qualification / pack.qualification_name('macos-arm64')
        original = json.loads(path.read_bytes())
        for name in ('production_authorized', 'mainnet_authorized', 'activation_authorized',
                     'public_cutover_authorized', 'deployment_verified', 'physical_asic_qualified'):
            for value in (True, None, 0):
                receipt = copy.deepcopy(original)
                receipt[name] = value
                path.write_bytes(base.encoded(receipt))
                with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, 'expanded authority'):
                    self.derive()
        path.write_bytes(base.encoded(original))

    def test_four_final_receipts_required_and_accepted_pins_rechecked_before_output(self):
        path = self.qualification / pack.qualification_name('windows-x86_64')
        raw = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'exactly four'):
            self.derive()
        path.write_bytes(raw)
        extra = self.qualification / 'unreviewed-receipt.json'
        extra.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'exactly four'):
            self.derive()
        extra.unlink()
        path.write_bytes(raw + b'\n')
        with self.assertRaisesRegex(ValueError, 'receipt changed'):
            self.package('must-not-exist')
        self.assertFalse((self.root / 'archives-must-not-exist').exists())

    def test_build_pending_profile_cannot_claim_prequalified_artifacts(self):
        self.pending['status'] = 'accepted'
        with self.assertRaisesRegex(ValueError, 'exact pending'):
            self.derive()

    def test_edited_receipt_cannot_derive_new_pins_against_original_ci_archive(self):
        path = self.qualification / pack.qualification_name('linux-x86_64')
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'supplied bytes differ from checked CI artifact'):
            self.derive()

    def test_actions_artifact_record_binds_exact_run_source_repository_and_digest(self):
        original = json.loads(self.artifact_record.read_bytes())
        variants = []
        for field, value in (('digest', 'sha256:' + '0' * 64), ('expired', True),
                             ('archive_download_url', 'https://example.invalid/not-github.zip'),
                             ('size_in_bytes', 0)):
            changed = copy.deepcopy(original)
            changed['artifacts'][0][field] = value
            variants.append(changed)
        for field, value in (('id', 9999), ('head_sha', 'b' * 40), ('head_branch', 'main')):
            changed = copy.deepcopy(original)
            changed['artifacts'][0]['workflow_run'][field] = value
            variants.append(changed)
        for changed in variants:
            self.artifact_record.write_bytes(base.encoded(changed))
            with self.subTest(record=changed), self.assertRaises(ValueError):
                self.derive()
        self.artifact_record.write_bytes(base.encoded(original))

    def test_original_download_zip_digest_is_checked_before_reading_members(self):
        path = self.archive_dir / 'v0115-preparation-evidence.zip'
        path.write_bytes(path.read_bytes() + b'changed ZIP download')
        with self.assertRaisesRegex(ValueError, 'ZIP digest or size differs'):
            self.derive()

    def test_unsafe_duplicate_or_extra_zip_members_reject_without_extraction(self):
        path = self.archive_dir / 'v0115-preparation-evidence.zip'
        original_zip = path.read_bytes()
        original_record = json.loads(self.artifact_record.read_bytes())
        for member, mode in (('../escape.json', 0), ('unexpected.json', 0),
                             ('qualification-receipts/' + pack.qualification_name('linux-x86_64'), 0),
                             ('link.json', stat.S_IFLNK | 0o777)):
            path.write_bytes(original_zip)
            info = zipfile.ZipInfo(member)
            info.create_system = 3
            info.external_attr = mode << 16
            with zipfile.ZipFile(path, 'a') as archive:
                # A duplicate is deliberately generated only as a rejection
                # control; no archive is ever extracted by this implementation.
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    archive.writestr(info, b'fixture')
            record = copy.deepcopy(original_record)
            row = next(r for r in record['artifacts'] if r['name'] == 'v0115-preparation-evidence')
            row.update(digest='sha256:' + base.sha(path.read_bytes()), size_in_bytes=path.stat().st_size)
            self.artifact_record.write_bytes(base.encoded(record))
            with self.subTest(member=member), self.assertRaises(ValueError):
                self.derive()
            self.assertFalse((self.root / 'escape.json').exists())
        path.write_bytes(original_zip)
        self.artifact_record.write_bytes(base.encoded(original_record))

    def test_missing_extra_pending_or_wrong_profile_fields_reject(self):
        for field in self.profile:
            for remove in (False, True):
                profile = copy.deepcopy(self.profile)
                if remove:
                    del profile[field]
                else:
                    profile[field] = None
                with self.subTest(field=field, remove=remove), self.assertRaises(ValueError):
                    pack.validate_profile(profile, self.source)
        for field, value in (('status', 'pending'), ('software_release', 'v0.11.3'),
                             ('software_version', '0.11.6'), ('network_release', 'v0.12')):
            profile = copy.deepcopy(self.profile)
            profile[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                pack.validate_profile(profile, self.source)
        profile = copy.deepcopy(self.profile)
        profile['release_approved'] = True
        with self.assertRaises(ValueError):
            pack.validate_profile(profile, self.source)

    def test_platform_pins_must_be_complete_distinct_and_exact(self):
        for selected in base.PLATFORMS:
            for value in (None, 'A' * 64, '1' * 63):
                profile = copy.deepcopy(self.profile)
                profile['platform_manifests_sha256'][selected] = value
                with self.subTest(selected=selected, value=value), self.assertRaises(ValueError):
                    pack.validate_profile(profile, self.source)
        profile = copy.deepcopy(self.profile)
        profile['platform_manifests_sha256'] = dict.fromkeys(base.PLATFORMS, 'a' * 64)
        with self.assertRaises(ValueError):
            pack.validate_profile(profile, self.source)

    def test_preparation_receipt_rejects_pr_failure_wrong_head_identity_and_types(self):
        original = copy.deepcopy(self.run)
        for field, value in (('event', 'pull_request'), ('status', 'in_progress'), ('conclusion', 'failure'),
                             ('headSha', 'b' * 40), ('databaseId', True), ('databaseId', 0),
                             ('workflowName', 'Release'), ('url', 'https://example.invalid/run/12345')):
            self.run = copy.deepcopy(original)
            self.run[field] = value
            self.write_run()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.derive()

    def test_only_exact_candidate_branch_push_or_manual_dispatch_can_prepare(self):
        self.run['event'] = 'push'
        self.write_run()
        self.assertEqual(self.derive()['ci_preparation']['head_branch'], pack.CANDIDATE_BRANCH)
        for branch in ('main', 'codex/v0.11.5-other', '', None):
            self.run['headBranch'] = branch
            self.write_run()
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                self.derive()
        self.run['headBranch'] = pack.CANDIDATE_BRANCH
        self.run['event'] = 'workflow_run'
        self.write_run()
        with self.assertRaisesRegex(ValueError, 'non-PR preparation CI'):
            self.derive()

    def test_every_preparation_job_must_complete_successfully_once(self):
        original = copy.deepcopy(self.run)
        variants = [original['jobs'][:-1], original['jobs'][:-1] + [original['jobs'][0]]]
        for name in pack.REQUIRED_JOBS:
            for field, value in (('status', 'in_progress'), ('conclusion', 'skipped'), ('conclusion', 'failure')):
                rows = copy.deepcopy(original['jobs'])
                next(row for row in rows if row['name'] == name)[field] = value
                variants.append(rows)
        for rows in variants:
            self.run = copy.deepcopy(original)
            self.run['jobs'] = rows
            self.write_run()
            with self.subTest(jobs=rows), self.assertRaises(ValueError):
                self.derive()

    def test_required_jobs_match_all_nine_actual_preparation_jobs(self):
        workflow = (HERE.parent / '.github/workflows/prepare-premainnet-release.yml').read_text()
        jobs = set(re.findall(r'^  ([a-z0-9-]+):$', workflow.split('\njobs:\n', 1)[1], re.M))
        self.assertEqual(pack.REQUIRED_JOBS, jobs)
        self.assertEqual(len(jobs), 9)

    def test_original_v0112_and_v0113_artifacts_cannot_be_relabeled(self):
        for label, historical in (('v0.11', pack._ORIGINAL), *pack.historical_profiles(self.source).items()):
            for field in ('build_source_head', 'release_source_head', 'build_index_tree', 'source_tree_sha256'):
                profile = copy.deepcopy(self.profile)
                profile[field] = historical[field]
                if field in ('build_source_head', 'release_source_head'):
                    profile['build_source_head'] = profile['release_source_head'] = historical[field]
                    profile['ci_preparation']['head_sha'] = historical[field]
                with self.subTest(release=label, field=field), self.assertRaises(ValueError):
                    pack.validate_profile(profile, self.source)
            for selected, digest in historical['platform_manifests_sha256'].items():
                profile = copy.deepcopy(self.profile)
                profile['platform_manifests_sha256'][selected] = digest
                with self.subTest(release=label, platform=selected), self.assertRaises(ValueError):
                    pack.validate_profile(profile, self.source)

    def test_historical_profile_bytes_cannot_be_refreshed(self):
        for label, (relative, _) in pack.HISTORICAL_PROFILES.items():
            path = self.source / relative
            original = path.read_bytes()
            path.write_bytes(original + b'\n')
            with self.subTest(release=label), self.assertRaisesRegex(ValueError, 'historical ' + label):
                pack.validate_profile(self.profile, self.source)
            path.write_bytes(original)

    def test_build_commit_tree_lock_and_source_tree_are_rechecked(self):
        pack.verify_build_source(self.source, self.profile)
        for field, value in (('build_index_tree', 'a' * 40), ('source_tree_sha256', 'b' * 64),
                             ('cargo_lock_sha256', 'c' * 64)):
            profile = copy.deepcopy(self.profile)
            profile[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                pack.verify_build_source(self.source, profile)

    def test_product_label_and_relation_bound_internal_package_versions_are_rechecked(self):
        self.source_product_version = '0.11.4'
        with self.assertRaisesRegex(ValueError, 'product version'):
            pack.verify_build_source(self.source, self.profile)
        self.source_product_version = '0.11.5'
        for name in self.package_versions:
            original = self.package_versions[name]
            self.package_versions[name] = '0.11.5'
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'internal package version'):
                pack.verify_build_source(self.source, self.profile)
            self.package_versions[name] = original

    def test_packaging_only_replaces_pending_profile_after_the_binary_commit(self):
        self.assertEqual(pack.PACKAGING_PROFILE_CHANGES, {'config/v0115-release-artifacts.json'})
        pack.require_committed_source(self.source, self.commit, self.profile)
        self.source_check_mock.assert_called_once_with(self.source, self.commit)
        valid = self.delta
        for delta in (b'', valid + b'A\0unexpected.txt\0', valid.replace(b'M\0', b'A\0', 1),
                      valid.replace(b'M\0', b'D\0', 1), valid.replace(b'M\0', b'R100\0', 1),
                      valid.replace(pack.PROFILE_PATH.encode(), b'config/other-profile.json')):
            self.delta = delta
            with self.subTest(delta=delta), self.assertRaisesRegex(ValueError, 'may only modify'):
                pack.require_committed_source(self.source, self.commit, self.profile)

    def test_dirty_untracked_unrelated_or_later_derivation_source_rejects(self):
        self.dirty = True
        with self.assertRaises(subprocess.CalledProcessError):
            pack.require_committed_source(self.source, self.commit, self.profile)
        self.dirty = False
        self.untracked = b'untracked.py\0'
        with self.assertRaisesRegex(ValueError, 'untracked source'):
            pack.require_committed_source(self.source, self.commit, self.profile)
        self.untracked = b''
        self.ancestor = False
        with self.assertRaises(subprocess.CalledProcessError):
            pack.require_committed_source(self.source, self.commit, self.profile)
        self.head = self.commit
        with self.assertRaisesRegex(ValueError, 'frozen CI build source'):
            self.derive()

    def test_four_archives_are_reproducible_and_preserve_binary_provenance(self):
        first, second = self.package(), self.package('two')
        self.assertEqual(len(list(first.iterdir())), 9)
        self.assertEqual({path.name: path.read_bytes() for path in first.iterdir()},
                         {path.name: path.read_bytes() for path in second.iterdir()})
        for selected in base.PLATFORMS:
            prefix = f'hegemon-v0.11.5-{selected}'
            target = self.root / ('extract-' + selected)
            target.mkdir()
            if selected.startswith('windows'):
                with zipfile.ZipFile(first / (prefix + '.zip')) as archive:
                    self.assertEqual(len(archive.infolist()), 13)
                    archive.extractall(target)
            else:
                with tarfile.open(first / (prefix + '.tar.gz')) as archive:
                    self.assertEqual(len(archive.getmembers()), 13)
                    archive.extractall(target, filter='data')
            bundle = target / prefix
            verify = runpy.run_path(str(bundle / 'start.py'))['verify_bundle']
            self.assertTrue(verify(bundle, check_host=False).is_file())
            record = json.loads((bundle / 'bundle.json').read_bytes())
            self.assertEqual(record['software_release'], 'v0.11.5')
            self.assertEqual(record['software_version'], '0.11.5')
            self.assertEqual(record['binary_build_source_head'], self.build)
            self.assertEqual(record['release_binary_source_head'], self.build)
            self.assertEqual(record['packaging_source_commit'], self.commit)
            self.assertEqual(record['binary_build_index_tree'], self.tree)
            self.assertEqual((bundle / f'provenance/hegemon-release-assets-{selected}.json').read_bytes(),
                             (self.assets / f'hegemon-release-assets-{selected}.json').read_bytes())
            self.assertIn(pack.PROFILE_PATH, record['packaging_inputs'])
            quickstart = (bundle / 'QUICKSTART.md').read_bytes()
            self.assertIn(b'v0.11.5', quickstart)
            self.assertIn(b'--public-submit-rpc', quickstart)
            self.assertIn(b'--rpc-cors https://wallet.example', quickstart)
            self.assertIn(b'approved seeds', quickstart)
            self.assertIn(b'NTP', quickstart)

    def test_binary_sidecar_manifest_changes_wrong_architecture_and_extra_files_reject(self):
        for name in ('wallet-linux-x86_64', 'walletd-windows-x86_64.exe.sha256',
                     'hegemon-release-assets-macos-arm64.json'):
            path = self.assets / name
            original = path.read_bytes()
            path.write_bytes(original + b'x')
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.derive()
            path.write_bytes(original)
        (self.assets / 'unexpected').write_bytes(b'extra')
        with self.assertRaises(ValueError):
            self.derive()
        (self.assets / 'unexpected').unlink()
        path = self.assets / 'hegemon-release-assets-linux-x86_64.json'
        manifest = json.loads(path.read_bytes())
        row = manifest['assets'][0]
        data = self.native('macos-arm64')
        (self.assets / row['name']).write_bytes(data)
        row.update(sha256=base.sha(data), size=len(data))
        (self.assets / row['checksum_name']).write_text(f"{row['sha256']}  {row['name']}\n")
        path.write_bytes(base.encoded(manifest))
        receipt_path = self.qualification / pack.qualification_name('linux-x86_64')
        receipt = json.loads(receipt_path.read_bytes())
        receipt['artifact_sha256'][row['binary']] = row['sha256']
        receipt_path.write_bytes(base.encoded(receipt))
        self.write_ci_artifacts()
        with self.assertRaisesRegex(ValueError, 'native format/architecture'):
            self.derive()

    def test_metadata_duplicate_keys_and_existing_outputs_reject_without_overwrite(self):
        first = self.package()
        expected = {path.name: path.read_bytes() for path in first.iterdir()}
        with self.assertRaisesRegex(ValueError, 'nothing is overwritten'):
            self.package()
        self.assertEqual(expected, {path.name: path.read_bytes() for path in first.iterdir()})
        release_path = self.source / pack.RELEASE_METADATA_PATH
        release = json.loads(release_path.read_bytes())
        release['software_version'] = '0.11.3'
        release_path.write_bytes(base.encoded(release))
        with self.assertRaisesRegex(ValueError, 'software metadata'):
            self.package('never')
        self.assertFalse((self.root / 'archives-never').exists())
        (self.source / pack.PROFILE_PATH).write_bytes(b'{"status":"accepted","status":"pending"}')
        with self.assertRaises(ValueError):
            pack.load_profile(self.source)

    def test_historical_globals_restore_after_success_and_failure(self):
        keys = ('SOFTWARE_RELEASE', 'SOFTWARE_VERSION', 'BUILD_SOURCE', 'BUILD_TREE',
                'SOURCE_TREE_SHA256', 'CARGO_LOCK_SHA256', 'APPROVED_MANIFESTS',
                'SOURCE_FILES', 'RELEASE_SOURCE', 'quickstart')
        original = {key: getattr(base, key) for key in keys}
        with pack.artifact_profile(self.profile, self.source):
            self.assertEqual(base.SOFTWARE_RELEASE, 'v0.11.5')
            self.assertIn('config/v0113-release-artifacts.json', base.SOURCE_FILES)
        self.assertEqual({key: getattr(base, key) for key in keys}, original)
        with self.assertRaises(RuntimeError):
            with pack.artifact_profile(self.profile, self.source):
                raise RuntimeError('synthetic packaging error')
        self.assertEqual({key: getattr(base, key) for key in keys}, original)

    def test_profile_cli_derives_only_after_validation_and_never_overwrites(self):
        output = self.source / pack.PROFILE_PATH
        argv = ['--assets', str(self.assets), '--output', str(output), '--derive-profile',
                '--ci-run', str(self.run_path), '--build-source', self.build,
                '--qualification-receipts', str(self.qualification), '--source-manifests', str(self.source_manifests),
                '--ci-artifact-record', str(self.artifact_record), '--ci-artifact-archives', str(self.archive_dir)]
        with mock.patch.object(pack, '__file__', str(self.source / pack.WRAPPER_PATH)), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.run['event'] = 'pull_request'
            self.write_run()
            self.assertEqual(pack.main(argv), 1)
            self.assertFalse(output.exists())
            self.run['event'] = 'workflow_dispatch'
            self.write_run()
            self.assertEqual(pack.main(argv), 0)
            accepted = output.read_bytes()
            self.assertEqual(accepted, base.encoded(self.profile))
            self.assertEqual(pack.main(argv), 1)
            self.assertEqual(output.read_bytes(), accepted)

    def test_packaging_cli_uses_exact_accepted_profile_and_commit(self):
        self.write_profile()
        output = self.root / 'cli-archives'
        with mock.patch.object(pack, '__file__', str(self.source / pack.WRAPPER_PATH)), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(pack.main(['--assets', str(self.assets), '--output', str(output),
                                        '--packaging-commit', self.commit,
                                        '--qualification-receipts', str(self.qualification),
                                        '--source-manifests', str(self.source_manifests), '--ci-run', str(self.run_path),
                                        '--ci-artifact-record', str(self.artifact_record),
                                        '--ci-artifact-archives', str(self.archive_dir)]), 0)
        self.assertEqual(len(list(output.iterdir())), 9)
        self.source_check_mock.assert_called_once_with(self.source, self.commit)

    def test_immutable_tree_hash_reads_bounded_blob_responses_without_process_execution(self):
        rows = [(b'alpha.txt', b'100644', b'a' * 40, b'first\n'),
                (b'bin/tool', b'100755', b'b' * 40, b'bytes\0kept')]
        tree = b''.join(mode + b' blob ' + oid + b'\t' + name + b'\0'
                        for name, mode, oid, data in reversed(rows))
        stream = b''.join(oid + b' blob ' + str(len(data)).encode() + b'\n' + data + b'\n'
                          for name, mode, oid, data in rows)
        expected = hashlib.sha256()
        for name, mode, oid, data in rows:
            expected.update(name + b'\0' + f'file:{int(mode, 8) & 0o777:o}:{len(data)}'.encode()
                            + b'\0' + data + b'\0')
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.stdin, process.stdout = io.BytesIO(), io.BytesIO(stream)
        process.wait.return_value = process.poll.return_value = 0
        with mock.patch.object(pack, 'git', return_value=tree), \
                mock.patch.object(pack.subprocess, 'Popen', return_value=process) as popen:
            self.assertEqual(self.tree_function(self.source, self.build), expected.hexdigest())
        self.assertEqual(popen.call_args.args[0][-2:], ['cat-file', '--batch'])


if __name__ == '__main__':
    unittest.main()
