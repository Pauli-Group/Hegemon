#!/usr/bin/env python3
"""Synthetic v0.11.4 provenance/archive controls; no Git or binaries execute."""
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
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('v0114_packaging_under_test', HERE / 'package_v0114_release.py')
pack = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pack
spec.loader.exec_module(pack)
base = pack.base


class PackagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='v0114-packaging-unit-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        self.assets = self.root / 'assets'
        self.source.mkdir()
        self.assets.mkdir()
        for name in (*pack._SOURCE_FILES, pack.WRAPPER_PATH, pack.TEST_PATH,
                     *(path for path, _ in pack.HISTORICAL_PROFILES.values())):
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((HERE.parent / name).read_bytes())
        release_path = self.source / 'config/testnet/0.11/release.json'
        release = json.loads(release_path.read_bytes())
        release.update(software_release='v0.11.4', software_version='0.11.4',
                       cutover_status='ready', public_genesis_pending=False)
        release_path.write_bytes(base.encoded(release))
        self.lock = (HERE.parent / 'Cargo.lock').read_bytes()
        (self.source / 'Cargo.lock').write_bytes(self.lock)
        self.build, self.tree, self.tree_sha = '1' * 40, '2' * 40, '3' * 64
        self.commit = '4' * 40
        self.head = self.build
        self.delta = b''.join(b'A\0' + name.encode() + b'\0' for name in sorted(pack.PACKAGING_ADDITIONS))
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
            manifest = dict(schema_version=1, source_head=self.build, source_index_tree=self.tree,
                            source_tree_sha256=self.tree_sha, cargo_lock_sha256=base.sha(self.lock),
                            target_triple=triple, source_manifest_sha256=base.sha(selected.encode()), assets=rows)
            (self.assets / f'hegemon-release-assets-{selected}.json').write_bytes(base.encoded(manifest))
        self.run = dict(databaseId=12345,
                        url='https://github.com/Pauli-Group/Hegemon/actions/runs/12345',
                        event='workflow_dispatch', status='completed', conclusion='success',
                        headSha=self.build, workflowName=pack.WORKFLOW,
                        jobs=[dict(name=name, status='completed', conclusion='success')
                              for name in sorted(pack.REQUIRED_JOBS)])
        self.run_path = self.root / 'ci-run.json'
        self.write_run()
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

    def derive(self):
        return pack.derive_profile(self.source, self.assets, self.run_path, self.build)

    def write_profile(self):
        (self.source / pack.PROFILE_PATH).write_bytes(base.encoded(self.profile))

    def package(self, suffix='one'):
        self.write_profile()
        output = self.root / ('archives-' + suffix)
        with pack.artifact_profile(self.profile, self.source):
            pack.require_committed_source(self.source, self.commit, self.profile)
            base.package(self.source, self.assets, output, self.commit)
        return output

    def test_exact_profile_schema_and_preserved_lock(self):
        self.assertEqual(set(self.profile), pack.FIELDS)
        self.assertEqual(self.profile['schema'], 'hegemon.v0114.release-artifacts.v1')
        self.assertEqual(self.profile['software_release'], 'v0.11.4')
        self.assertEqual(self.profile['software_version'], '0.11.4')
        self.assertEqual(self.profile['cargo_lock_sha256'], pack.LOCK_SHA256)
        self.assertEqual(self.profile['release_source_head'], self.profile['build_source_head'])
        forged = copy.deepcopy(self.profile)
        forged['cargo_lock_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'qualified Cargo.lock'):
            pack.validate_profile(forged, self.source)

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
                             ('software_version', '0.11.5'), ('network_release', 'v0.12')):
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

    def test_packaging_is_exactly_three_additions_after_the_binary_commit(self):
        self.assertEqual(pack.PACKAGING_ADDITIONS, {'scripts/package_v0114_release.py',
            'scripts/test_package_v0114_release.py', 'config/v0114-release-artifacts.json'})
        pack.require_committed_source(self.source, self.commit, self.profile)
        self.source_check_mock.assert_called_once_with(self.source, self.commit)
        valid = self.delta
        for delta in (b'', valid + b'A\0unexpected.txt\0', valid.replace(b'A\0', b'M\0', 1),
                      valid.replace(b'A\0', b'D\0', 1), valid.replace(b'A\0', b'R100\0', 1),
                      valid.replace(pack.PROFILE_PATH.encode(), b'config/other-profile.json')):
            self.delta = delta
            with self.subTest(delta=delta), self.assertRaisesRegex(ValueError, 'may only add'):
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
            prefix = f'hegemon-v0.11.4-{selected}'
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
            self.assertEqual(record['software_release'], 'v0.11.4')
            self.assertEqual(record['software_version'], '0.11.4')
            self.assertEqual(record['binary_build_source_head'], self.build)
            self.assertEqual(record['release_binary_source_head'], self.build)
            self.assertEqual(record['packaging_source_commit'], self.commit)
            self.assertEqual(record['binary_build_index_tree'], self.tree)
            self.assertEqual((bundle / f'provenance/hegemon-release-assets-{selected}.json').read_bytes(),
                             (self.assets / f'hegemon-release-assets-{selected}.json').read_bytes())
            self.assertIn(pack.PROFILE_PATH, record['packaging_inputs'])
            quickstart = (bundle / 'QUICKSTART.md').read_bytes()
            self.assertIn(b'v0.11.4', quickstart)
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
        with self.assertRaisesRegex(ValueError, 'native format/architecture'):
            self.derive()

    def test_metadata_duplicate_keys_and_existing_outputs_reject_without_overwrite(self):
        first = self.package()
        expected = {path.name: path.read_bytes() for path in first.iterdir()}
        with self.assertRaisesRegex(ValueError, 'nothing is overwritten'):
            self.package()
        self.assertEqual(expected, {path.name: path.read_bytes() for path in first.iterdir()})
        release_path = self.source / 'config/testnet/0.11/release.json'
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
            self.assertEqual(base.SOFTWARE_RELEASE, 'v0.11.4')
            self.assertIn('config/v0113-release-artifacts.json', base.SOURCE_FILES)
        self.assertEqual({key: getattr(base, key) for key in keys}, original)
        with self.assertRaises(RuntimeError):
            with pack.artifact_profile(self.profile, self.source):
                raise RuntimeError('synthetic packaging error')
        self.assertEqual({key: getattr(base, key) for key in keys}, original)

    def test_profile_cli_derives_only_after_validation_and_never_overwrites(self):
        output = self.source / pack.PROFILE_PATH
        argv = ['--assets', str(self.assets), '--output', str(output), '--derive-profile',
                '--ci-run', str(self.run_path), '--build-source', self.build]
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
                                        '--packaging-commit', self.commit]), 0)
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
