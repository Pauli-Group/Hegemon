#!/usr/bin/env python3
"""Exercise v0.11.3 packaging provenance and archives without executing binaries."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
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
spec = importlib.util.spec_from_file_location('v0113_packaging_under_test', HERE / 'package_v0113_release.py')
pack = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pack
spec.loader.exec_module(pack)
base = pack.base


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        actual = HERE.parent
        for name in (*pack._SOURCE_FILES, pack.HISTORICAL_PROFILE_PATH):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((actual / name).read_bytes())
        release_path = self.source / 'config/testnet/0.11/release.json'
        release = json.loads(release_path.read_bytes())
        release.update(software_release='v0.11.3', software_version='0.11.3',
                       cutover_status='ready', public_genesis_pending=False)
        release_path.write_bytes(base.encoded(release))
        (self.source / 'Cargo.lock').write_bytes(b'# synthetic controlled fixture\n')
        self.git('init', '-q')
        self.git('config', 'user.name', 'Packaging fixture')
        self.git('config', 'user.email', 'packaging-fixture@example.invalid')
        self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic immutable binary build source')
        self.build = self.git('rev-parse', 'HEAD').decode().strip()
        self.tree = self.git('rev-parse', 'HEAD^{tree}').decode().strip()
        self.tree_sha = pack.committed_tree_sha256(self.source, self.build)
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
                            source_tree_sha256=self.tree_sha,
                            cargo_lock_sha256=base.sha((self.source / 'Cargo.lock').read_bytes()),
                            target_triple=triple, source_manifest_sha256=base.sha(selected.encode()),
                            assets=rows)
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

    def git(self, *args):
        return pack.git(self.source, *args)

    def write_run(self):
        self.run_path.write_bytes(base.encoded(self.run))

    def derive(self):
        return pack.derive_profile(self.source, self.assets, self.run_path, self.build)

    def commit_packaging(self):
        for name in (pack.WRAPPER_PATH, pack.TEST_PATH):
            (self.source / name).write_bytes((HERE.parent / name).read_bytes())
        (self.source / pack.PROFILE_PATH).write_bytes(base.encoded(self.profile))
        self.git('add', '.')
        self.git('commit', '-qm', 'Accept synthetic artifacts and add packaging only')
        return self.git('rev-parse', 'HEAD').decode().strip()

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

    def package(self, commit, suffix='one'):
        output = self.root / ('archives-' + suffix)
        with pack.artifact_profile(self.profile, self.source):
            pack.require_committed_source(self.source, commit, self.profile)
            base.package(self.source, self.assets, output, commit)
        return output

    def test_real_commits_package_four_reproducible_archives_and_verify_launchers(self):
        commit = self.commit_packaging()
        output = self.package(commit)
        repeated = self.package(commit, 'two')
        self.assertEqual(len(list(output.iterdir())), 9)
        for artifact in output.iterdir():
            self.assertEqual(artifact.read_bytes(), (repeated / artifact.name).read_bytes())
        for selected in base.PLATFORMS:
            prefix = f'hegemon-v0.11.3-{selected}'
            destination = self.root / ('extract-' + selected)
            destination.mkdir()
            if selected.startswith('windows'):
                with zipfile.ZipFile(output / (prefix + '.zip')) as archive:
                    self.assertEqual(len(archive.infolist()), 13)
                    self.assertTrue(all(not row.is_dir() for row in archive.infolist()))
                    archive.extractall(destination)
            else:
                with tarfile.open(output / (prefix + '.tar.gz')) as archive:
                    self.assertEqual(len(archive.getmembers()), 13)
                    self.assertTrue(all(row.isfile() for row in archive.getmembers()))
                    archive.extractall(destination, filter='data')
            extracted = destination / prefix
            verify = runpy.run_path(str(extracted / 'start.py'))['verify_bundle']
            self.assertTrue(verify(extracted, check_host=False).is_file())
            bundle = json.loads((extracted / 'bundle.json').read_bytes())
            self.assertEqual(bundle['binary_build_source_head'], self.build)
            self.assertEqual(bundle['release_binary_source_head'], self.build)
            self.assertEqual(bundle['packaging_source_commit'], commit)
            self.assertEqual(bundle['software_release'], 'v0.11.3')
            self.assertEqual(bundle['release'], 'v0.11')
            self.assertEqual(bundle['binary_build_index_tree'], self.tree)
            self.assertEqual((extracted / f'provenance/hegemon-release-assets-{selected}.json').read_bytes(),
                             (self.assets / f'hegemon-release-assets-{selected}.json').read_bytes())
            self.assertEqual(base.sha((extracted / 'config/testnet/0.11/network-manifest.json').read_bytes()),
                             base.join.NETWORK_SHA256)
            self.assertIn(pack.PROFILE_PATH, bundle['packaging_inputs'])
            self.assertIn(b'--public-submit-rpc', (extracted / 'QUICKSTART.md').read_bytes())
            self.assertIn(b'--rpc-cors https://wallet.example', (extracted / 'QUICKSTART.md').read_bytes())

    def test_immutable_source_hash_matches_clean_worktree_algorithm(self):
        expected = hashlib.sha256()
        for raw in sorted(self.git('ls-files', '-z').split(b'\0')):
            if not raw:
                continue
            data = (self.source / raw.decode()).read_bytes()
            expected.update(raw + b'\0file:644:' + str(len(data)).encode() + b'\0' + data + b'\0')
        self.assertEqual(self.tree_sha, expected.hexdigest())
        (self.source / 'Cargo.lock').write_bytes(b'dirty bytes must not affect immutable object hash')
        self.assertEqual(pack.committed_tree_sha256(self.source, self.build), self.tree_sha)

    def test_profile_null_wrong_label_pending_and_partial_fields_reject(self):
        for field in self.profile:
            value = copy.deepcopy(self.profile)
            value[field] = None
            with self.subTest(field=field), self.assertRaises(ValueError):
                pack.validate_profile(value, self.source)
        for field, value in [('status', 'pending-ci-artifact-acceptance'), ('software_release', 'v0.11.2'),
                             ('software_version', '0.11.2'), ('network_release', 'v0.12')]:
            profile = copy.deepcopy(self.profile)
            profile[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                pack.validate_profile(profile, self.source)
        for selected in base.PLATFORMS:
            profile = copy.deepcopy(self.profile)
            del profile['platform_manifests_sha256'][selected]
            with self.subTest(platform=selected), self.assertRaises(ValueError):
                pack.validate_profile(profile, self.source)

    def test_ci_pr_failure_incomplete_wrong_source_and_identity_reject(self):
        original = copy.deepcopy(self.run)
        for field, value in [('event', 'pull_request'), ('status', 'in_progress'), ('conclusion', 'failure'),
                             ('headSha', 'b' * 40), ('databaseId', True), ('databaseId', 0),
                             ('workflowName', 'Release'), ('url', 'https://example.invalid/run/12345')]:
            self.run = copy.deepcopy(original)
            self.run[field] = value
            self.write_run()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.derive()

    def test_required_ci_jobs_match_the_actual_preparation_workflow(self):
        workflow = (HERE.parent / '.github/workflows/prepare-premainnet-release.yml').read_text()
        jobs_text = workflow.split('\njobs:\n', 1)[1]
        actual_jobs = set(re.findall(r'^  ([a-z0-9-]+):$', jobs_text, re.MULTILINE))
        self.assertEqual(pack.REQUIRED_JOBS, actual_jobs)
        self.assertIn('app-no-ssh-e2e', actual_jobs)
        self.assertEqual(len(actual_jobs), 9)

    def test_ci_missing_duplicate_skipped_or_failed_mandatory_job_reject(self):
        original = copy.deepcopy(self.run)
        variants = [original['jobs'][:-1], original['jobs'][:-1] + [original['jobs'][0]]]
        for name in pack.REQUIRED_JOBS:
            for conclusion in ('skipped', 'failure'):
                rows = copy.deepcopy(original['jobs'])
                next(row for row in rows if row['name'] == name)['conclusion'] = conclusion
                variants.append(rows)
        for rows in variants:
            self.run = copy.deepcopy(original)
            self.run['jobs'] = rows
            self.write_run()
            with self.subTest(jobs=rows), self.assertRaises(ValueError):
                self.derive()

    def test_original_and_v0112_profiles_cannot_be_relabeled(self):
        for historical in (pack._ORIGINAL, pack.historical_profile(self.source)):
            for field in ('build_source_head', 'release_source_head', 'build_index_tree', 'source_tree_sha256'):
                profile = copy.deepcopy(self.profile)
                profile[field] = historical[field]
                if field in ('build_source_head', 'release_source_head'):
                    profile['build_source_head'] = profile['release_source_head'] = historical[field]
                    profile['ci_preparation']['head_sha'] = historical[field]
                with self.subTest(field=field), self.assertRaises(ValueError):
                    pack.validate_profile(profile, self.source)
            profile = copy.deepcopy(self.profile)
            profile['platform_manifests_sha256']['linux-x86_64'] = historical['platform_manifests_sha256']['linux-x86_64']
            with self.assertRaises(ValueError):
                pack.validate_profile(profile, self.source)

    def test_historical_profile_mutation_rejects(self):
        path = self.source / pack.HISTORICAL_PROFILE_PATH
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'historical v0.11.2 artifact profile changed'):
            pack.validate_profile(self.profile, self.source)

    def test_source_head_tree_digest_and_lock_forgery_reject(self):
        for field, value in [('build_index_tree', 'a' * 40), ('source_tree_sha256', 'b' * 64),
                             ('cargo_lock_sha256', 'c' * 64)]:
            profile = copy.deepcopy(self.profile)
            profile[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                pack.verify_build_source(self.source, profile)

    def test_changed_binary_checksum_sidecar_and_manifest_reject(self):
        names = ['hegemon-node-linux-x86_64', 'walletd-windows-x86_64.exe.sha256',
                 'hegemon-release-assets-macos-arm64.json']
        for name in names:
            path = self.assets / name
            before = path.read_bytes()
            path.write_bytes(before + b'x')
            with self.subTest(name=name), pack.artifact_profile(self.profile, self.source), self.assertRaises(ValueError):
                base.validate_assets(self.assets)
            path.write_bytes(before)

    def test_refreshed_manifest_cannot_hide_wrong_native_architecture_or_provenance(self):
        path = self.assets / 'hegemon-release-assets-linux-x86_64.json'
        original = path.read_bytes()
        for field, value in [('source_head', 'b' * 40), ('source_index_tree', 'c' * 40),
                             ('source_tree_sha256', 'd' * 64), ('cargo_lock_sha256', 'e' * 64),
                             ('target_triple', 'aarch64-apple-darwin')]:
            row = json.loads(original)
            row[field] = value
            path.write_bytes(base.encoded(row))
            profile = copy.deepcopy(self.profile)
            profile['platform_manifests_sha256']['linux-x86_64'] = base.sha(path.read_bytes())
            with self.subTest(field=field), pack.artifact_profile(profile, self.source), self.assertRaises(ValueError):
                base.validate_assets(self.assets)
        path.write_bytes(original)
        row = json.loads(original)
        entry = row['assets'][0]
        data = self.native('macos-arm64')
        (self.assets / entry['name']).write_bytes(data)
        entry.update(sha256=base.sha(data), size=len(data))
        (self.assets / entry['checksum_name']).write_text(f"{entry['sha256']}  {entry['name']}\n")
        path.write_bytes(base.encoded(row))
        self.profile['platform_manifests_sha256']['linux-x86_64'] = base.sha(path.read_bytes())
        with pack.artifact_profile(self.profile, self.source), self.assertRaisesRegex(ValueError, 'native format/architecture'):
            base.validate_assets(self.assets)

    def test_missing_extra_and_symlink_assets_reject(self):
        path = self.assets / 'wallet-linux-x86_64'
        backup = self.root / path.name
        path.rename(backup)
        with self.assertRaises(ValueError):
            self.derive()
        path.symlink_to(backup)
        with self.assertRaises(ValueError):
            self.derive()
        path.unlink()
        backup.rename(path)
        (self.assets / 'unexpected').write_text('extra')
        with self.assertRaises(ValueError):
            self.derive()

    def test_packaging_commit_cannot_alter_any_binary_source_file(self):
        self.commit_packaging()
        (self.source / 'Cargo.lock').write_text('changed source')
        self.git('add', 'Cargo.lock')
        self.git('commit', '-qm', 'Illegal source change after binary build')
        commit = self.git('rev-parse', 'HEAD').decode().strip()
        with self.assertRaisesRegex(ValueError, 'may only add'):
            self.package(commit)
        self.assertFalse((self.root / 'archives-one').exists())

    def test_dirty_and_untracked_packaging_source_reject(self):
        commit = self.commit_packaging()
        path = self.source / 'Cargo.lock'
        original = path.read_bytes()
        path.write_text('dirty')
        with self.assertRaises(subprocess.CalledProcessError):
            self.package(commit)
        path.write_bytes(original)
        (self.source / 'untracked.py').write_text('unexpected source')
        with self.assertRaisesRegex(ValueError, 'untracked source'):
            self.package(commit)

    def test_wrong_packaging_commit_rejects(self):
        self.commit_packaging()
        with self.assertRaisesRegex(ValueError, 'source checkout HEAD'):
            self.package(self.build)

    def test_output_is_not_overwritten_and_metadata_fails_before_creation(self):
        commit = self.commit_packaging()
        output = self.package(commit)
        before = {path.name: base.sha(path.read_bytes()) for path in output.iterdir()}
        with self.assertRaisesRegex(ValueError, 'nothing is overwritten'):
            self.package(commit)
        self.assertEqual(before, {path.name: base.sha(path.read_bytes()) for path in output.iterdir()})
        profile_path = self.source / pack.PROFILE_PATH
        profile_path.write_bytes(b'{"status":"accepted","status":"pending"}')
        with self.assertRaises(ValueError):
            pack.load_profile(self.source)

    def test_historical_globals_restored_after_success_and_failure(self):
        keys = ('SOFTWARE_RELEASE', 'SOFTWARE_VERSION', 'BUILD_SOURCE', 'BUILD_TREE',
                'SOURCE_TREE_SHA256', 'CARGO_LOCK_SHA256', 'APPROVED_MANIFESTS',
                'SOURCE_FILES', 'RELEASE_SOURCE', 'quickstart')
        original = {key: getattr(base, key) for key in keys}
        with pack.artifact_profile(self.profile, self.source):
            self.assertEqual(base.SOFTWARE_RELEASE, 'v0.11.3')
        self.assertEqual({key: getattr(base, key) for key in keys}, original)
        with self.assertRaises(RuntimeError):
            with pack.artifact_profile(self.profile, self.source):
                raise RuntimeError('simulated packaging failure')
        self.assertEqual({key: getattr(base, key) for key in keys}, original)

    def test_isolated_cli_packages_and_rejects_profile_derivation_at_later_commit(self):
        commit = self.commit_packaging()
        script = self.source / pack.WRAPPER_PATH
        output = self.root / 'cli-output'
        result = subprocess.run([sys.executable, '-I', '-B', str(script), '--assets', str(self.assets),
                                 '--output', str(output), '--packaging-commit', commit],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(list(output.iterdir())), 9)
        result = subprocess.run([sys.executable, '-I', '-B', str(script), '--assets', str(self.assets),
                                 '--output', str(self.root / 'never-profile.json'), '--derive-profile',
                                 '--ci-run', str(self.run_path), '--build-source', self.build],
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('frozen CI build source', result.stderr)
        self.assertFalse((self.root / 'never-profile.json').exists())

    def test_isolated_profile_derivation_only_writes_after_acceptance_and_never_overwrites(self):
        for name in (pack.WRAPPER_PATH, pack.TEST_PATH):
            (self.source / name).write_bytes((HERE.parent / name).read_bytes())
        script = self.source / pack.WRAPPER_PATH
        profile_path = self.source / pack.PROFILE_PATH
        command = [sys.executable, '-I', '-B', str(script), '--assets', str(self.assets),
                   '--output', str(profile_path), '--derive-profile', '--ci-run', str(self.run_path),
                   '--build-source', self.build]
        self.run['event'] = 'pull_request'
        self.write_run()
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(profile_path.exists())
        self.run['event'] = 'workflow_dispatch'
        self.write_run()
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(profile_path.read_bytes(), base.encoded(self.profile))
        accepted = profile_path.read_bytes()
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(profile_path.read_bytes(), accepted)


if __name__ == '__main__':
    unittest.main()
