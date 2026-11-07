#!/usr/bin/env python3
"""Package v0.11.3 from its committed, accepted four-platform artifact profile.

Historical profiles remain unchanged and serve only to reject relabeled assets.
This packages verified bytes; it does not build binaries or grant release approval.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import types


def _load_base():
    """Load only this checkout's historical helper, including under python -I."""
    directory = Path(__file__).resolve().parent
    package_name = '_hegemon_v0113_packaging'
    package = types.ModuleType(package_name)
    package.__path__ = [str(directory)]
    sys.modules[package_name] = package
    name = package_name + '.package_v011_release'
    spec = importlib.util.spec_from_file_location(name, directory / 'package_v011_release.py')
    if spec is None or spec.loader is None:
        raise ValueError('cannot load source-owned historical packaging helper')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


base = _load_base()
PROFILE_PATH = 'config/v0113-release-artifacts.json'
WRAPPER_PATH = 'scripts/package_v0113_release.py'
TEST_PATH = 'scripts/test_package_v0113_release.py'
PACKAGING_ADDITIONS = {WRAPPER_PATH, TEST_PATH, PROFILE_PATH}
HISTORICAL_PROFILE_PATH = 'config/v0112-release-artifacts.json'
HISTORICAL_PROFILE_SHA256 = '4a6511b13f60a2506cf349808146a2e5776ef8687f0d9273ab71c4f3c838a6bf'
FIELDS = {'schema', 'status', 'network_release', 'software_release', 'software_version',
          'release_source_head', 'build_source_head', 'build_index_tree',
          'source_tree_sha256', 'cargo_lock_sha256', 'platform_manifests_sha256',
          'ci_preparation'}
REPOSITORY = 'Pauli-Group/Hegemon'
WORKFLOW = 'Prepare pre-mainnet release'
REQUIRED_JOBS = {'preparation-policy', 'transaction-proof-authorization', 'security-gates',
                 'app-no-ssh-e2e',
                 'build-linux', 'build-macos-intel', 'build-macos-arm', 'build-windows',
                 'assemble-prepared-release'}
_ORIGINAL = {
    'release_source_head': base.RELEASE_SOURCE,
    'build_source_head': base.BUILD_SOURCE,
    'build_index_tree': base.BUILD_TREE,
    'source_tree_sha256': base.SOURCE_TREE_SHA256,
    'platform_manifests_sha256': dict(base.APPROVED_MANIFESTS),
}
_SOURCE_FILES = base.SOURCE_FILES
_QUICKSTART = base.quickstart


def _source_root(source):
    return Path(source) if source is not None else Path(__file__).resolve().parent.parent


def _validate_fields(profile, *, historical=False):
    label = 'v0.11.2' if historical else 'v0.11.3'
    expected_fields = FIELDS - {'ci_preparation'} if historical else FIELDS
    if not isinstance(profile, dict) or set(profile) != expected_fields:
        base.join.fail(label + ' artifact profile must contain exactly the reviewed fields')
    labels = {'schema': 'hegemon.v0112.release-artifacts.v1' if historical else 'hegemon.v0113.release-artifacts.v1',
              'status': 'accepted', 'network_release': 'v0.11',
              'software_release': label, 'software_version': label[1:]}
    if any(profile[key] != value for key, value in labels.items()):
        base.join.fail(label + ' artifact profile is not accepted with its exact software/network identity')
    for key in ('release_source_head', 'build_source_head', 'build_index_tree',
                'source_tree_sha256', 'cargo_lock_sha256'):
        length = 40 if key in ('release_source_head', 'build_source_head', 'build_index_tree') else 64
        if not isinstance(profile[key], str) or not re.fullmatch(rf'[0-9a-f]{{{length}}}', profile[key]):
            base.join.fail('missing exact ' + label + ' artifact pin: ' + key)
    pins = profile['platform_manifests_sha256']
    if (not isinstance(pins, dict) or set(pins) != set(base.PLATFORMS)
            or any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)
                   for value in pins.values()) or len(set(pins.values())) != 4):
        base.join.fail(label + ' requires four distinct exact platform manifest digests')


def historical_profile(source=None):
    source = _source_root(source)
    raw = base.join.checked_bytes(source, HISTORICAL_PROFILE_PATH)
    if base.sha(raw) != HISTORICAL_PROFILE_SHA256:
        base.join.fail('historical v0.11.2 artifact profile changed; preserve its accepted pins')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=base.join.unique_object)
    _validate_fields(value, historical=True)
    return value


def validate_profile(profile, source=None):
    _validate_fields(profile)
    if profile['release_source_head'] != profile['build_source_head']:
        base.join.fail('release source must retain the exact CI binary build commit')
    ci = profile['ci_preparation']
    fields = {'repository', 'run_id', 'run_url', 'workflow', 'event', 'head_sha',
              'status', 'conclusion', 'successful_jobs', 'run_record_sha256'}
    if not isinstance(ci, dict) or set(ci) != fields:
        base.join.fail('missing exact full preparation CI receipt')
    if (ci['repository'] != REPOSITORY or type(ci['run_id']) is not int or ci['run_id'] <= 0
            or ci['run_url'] != f"https://github.com/{REPOSITORY}/actions/runs/{ci['run_id']}"
            or ci['workflow'] != WORKFLOW or ci['event'] != 'workflow_dispatch'
            or ci['head_sha'] != profile['build_source_head']
            or ci['status'] != 'completed' or ci['conclusion'] != 'success'
            or ci['successful_jobs'] != sorted(REQUIRED_JOBS)
            or not isinstance(ci['run_record_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', ci['run_record_sha256'])):
        base.join.fail('full non-PR preparation CI did not succeed at the binary source commit')
    for label, previous in (('v0.11', _ORIGINAL), ('v0.11.2', historical_profile(source))):
        old_heads = {previous['release_source_head'], previous['build_source_head']}
        if (profile['release_source_head'] in old_heads or profile['build_source_head'] in old_heads
                or profile['build_index_tree'] == previous['build_index_tree']
                or profile['source_tree_sha256'] == previous['source_tree_sha256']
                or any(pin in set(previous['platform_manifests_sha256'].values())
                       for pin in profile['platform_manifests_sha256'].values())):
            base.join.fail(label + ' artifact provenance cannot be relabeled as v0.11.3')
    return profile


def load_profile(source):
    return validate_profile(base.join.read_json(source, PROFILE_PATH), source)


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args], stderr=subprocess.PIPE)


def committed_tree_sha256(source, commit):
    """Match release_artifact_manifest.source_tree_sha256 for a clean Git commit.

    Read immutable objects through one cat-file process, without checking out,
    changing the index, loading all blobs into RAM, or trusting worktree bytes.
    """
    records = []
    for raw in git(source, 'ls-tree', '-r', '-z', commit).split(b'\0'):
        if not raw:
            continue
        header, separator, name = raw.partition(b'\t')
        match = re.fullmatch(rb'(100644|100755) blob ([0-9a-f]{40})', header)
        if not separator or match is None:
            base.join.fail('build source contains an unsupported Git tree entry')
        mode, oid = match.groups()
        records.append((name, mode, oid))
    digest = hashlib.sha256()
    with subprocess.Popen(['git', '-C', str(source), 'cat-file', '--batch'],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as process:
        try:
            for name, mode, oid in sorted(records):
                process.stdin.write(oid + b'\n')
                process.stdin.flush()
                fields = process.stdout.readline().rstrip(b'\n').split(b' ')
                if len(fields) != 3 or fields[:2] != [oid, b'blob'] or not fields[2].isdigit():
                    base.join.fail('Git blob provenance changed during source inspection')
                size = int(fields[2])
                digest.update(name + b'\0')
                digest.update(f"file:{int(mode, 8) & 0o777:o}:{size}".encode('ascii') + b'\0')
                remaining = size
                while remaining:
                    chunk = process.stdout.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        base.join.fail('truncated immutable build source blob')
                    digest.update(chunk)
                    remaining -= len(chunk)
                if process.stdout.read(1) != b'\n':
                    base.join.fail('malformed immutable build source framing')
                digest.update(b'\0')
            process.stdin.close()
            if process.wait() != 0:
                base.join.fail('failed to inspect immutable build source')
        finally:
            if process.poll() is None:
                process.kill()
    return digest.hexdigest()


def verify_build_source(source, profile):
    commit = profile['build_source_head']
    if git(source, 'rev-parse', commit + '^{commit}').decode().strip() != commit:
        base.join.fail('binary build source is not the exact commit')
    if git(source, 'rev-parse', commit + '^{tree}').decode().strip() != profile['build_index_tree']:
        base.join.fail('binary build index tree does not match its source commit')
    if base.sha(git(source, 'show', commit + ':Cargo.lock')) != profile['cargo_lock_sha256']:
        base.join.fail('binary Cargo.lock digest does not match its source commit')
    if committed_tree_sha256(source, commit) != profile['source_tree_sha256']:
        base.join.fail('binary source tree digest does not match its source commit')


def require_committed_source(source, commit, profile):
    """Only the three additive packaging files may follow the binary CI commit."""
    base.require_committed_source(source, commit)
    git(source, 'merge-base', '--is-ancestor', profile['build_source_head'], commit)
    changes = git(source, 'diff', '--name-status', '-z', profile['build_source_head'], commit).split(b'\0')
    pairs = list(zip(changes[0:-1:2], changes[1:-1:2]))
    if (len(changes) != 2 * len(PACKAGING_ADDITIONS) + 1
            or {name.decode() for status, name in pairs if status == b'A'} != PACKAGING_ADDITIONS):
        base.join.fail('packaging commit may only add the new packager, controls, and accepted profile')
    git(source, 'diff', '--exit-code', 'HEAD', '--')
    if git(source, 'ls-files', '--others', '--exclude-standard', '-z'):
        base.join.fail('packaging checkout has untracked source files')
    verify_build_source(source, profile)


def derive_profile(source, directory, run_path, build_source):
    """Derive reviewable pins only from complete artifacts and a successful CI run.

    run_path is the unmodified JSON returned by authenticated `gh run view`
    with databaseId,url,event,status,conclusion,headSha,workflowName,jobs. It is
    evidence provided by the release operator, not an independently authenticated
    signature. The accepted profile must still be reviewed and committed.
    """
    if not isinstance(build_source, str) or not re.fullmatch('[0-9a-f]{40}', build_source):
        base.join.fail('require the exact frozen binary source commit')
    if git(source, 'rev-parse', 'HEAD').decode().strip() != build_source:
        base.join.fail('derive the accepted artifact profile at the frozen CI build source')
    git(source, 'diff', '--exit-code', 'HEAD', '--')
    raw_run = base.join.checked_bytes(run_path.parent, run_path.name)
    run = json.loads(raw_run.decode('utf-8'), object_pairs_hook=base.join.unique_object)
    jobs = run.get('jobs')
    if (not isinstance(jobs, list) or len(jobs) != len(REQUIRED_JOBS)
            or {row.get('name') for row in jobs if isinstance(row, dict)} != REQUIRED_JOBS
            or any(row.get('status') != 'completed' or row.get('conclusion') != 'success' for row in jobs)):
        base.join.fail('all nine full preparation jobs must have succeeded')
    manifests = {}
    for selected in base.PLATFORMS:
        raw = base.join.checked_bytes(directory, f'hegemon-release-assets-{selected}.json')
        manifests[selected] = (json.loads(raw.decode('utf-8'), object_pairs_hook=base.join.unique_object), raw)
    first = manifests['linux-x86_64'][0]
    profile = {
        'schema': 'hegemon.v0113.release-artifacts.v1', 'status': 'accepted',
        'network_release': 'v0.11', 'software_release': 'v0.11.3', 'software_version': '0.11.3',
        'release_source_head': build_source, 'build_source_head': build_source,
        'build_index_tree': first.get('source_index_tree'),
        'source_tree_sha256': first.get('source_tree_sha256'),
        'cargo_lock_sha256': first.get('cargo_lock_sha256'),
        'platform_manifests_sha256': {selected: base.sha(raw) for selected, (_, raw) in manifests.items()},
        'ci_preparation': {
            'repository': REPOSITORY, 'run_id': run.get('databaseId'), 'run_url': run.get('url'),
            'workflow': run.get('workflowName'), 'event': run.get('event'), 'head_sha': run.get('headSha'),
            'status': run.get('status'), 'conclusion': run.get('conclusion'),
            'successful_jobs': sorted(REQUIRED_JOBS), 'run_record_sha256': base.sha(raw_run),
        },
    }
    validate_profile(profile, source)
    verify_build_source(source, profile)
    with artifact_profile(profile, source):
        base.validate_assets(directory)
    return profile


def public_quickstart(selected):
    command = 'py -3 start.py' if selected.startswith('windows') else 'python3 start.py'
    marker = b'For your local native wallet to submit actions, explicitly start with:\n'
    text = _QUICKSTART(selected)
    if text.count(marker) != 1:
        base.join.fail('review changed historical QUICKSTART before v0.11.3 packaging')
    public = f'''To opt in to bounded PrivateSpend submission with loopback RPC:

    {command} --public-submit-rpc

To deliberately expose that listener on all interfaces:

    {command} --public-submit-rpc --rpc-external

Browser clients also need their one exact Origin, for example:

    {command} --public-submit-rpc --rpc-external --rpc-cors https://wallet.example

Browser access stays closed when --rpc-cors is omitted. CORS selects a browser
Origin; it is not authentication. Public submission exposes the current allowed
PrivateSpend route and safe reads. Mining and administration methods stay private.
Do not combine --public-submit-rpc with --wallet-rpc. The default command above
continues to use safe RPC on loopback, without transaction submission.

'''.encode('utf-8')
    return text.replace(marker, public + marker, 1)


@contextmanager
def artifact_profile(profile, source=None):
    """Apply one exact profile and restore every historical global on exit."""
    validate_profile(profile, source)
    replacements = {
        'SOFTWARE_RELEASE': profile['software_release'],
        'SOFTWARE_VERSION': profile['software_version'],
        'RELEASE_SOURCE': profile['release_source_head'],
        'BUILD_SOURCE': profile['build_source_head'],
        'BUILD_TREE': profile['build_index_tree'],
        'SOURCE_TREE_SHA256': profile['source_tree_sha256'],
        'CARGO_LOCK_SHA256': profile['cargo_lock_sha256'],
        'APPROVED_MANIFESTS': dict(profile['platform_manifests_sha256']),
        'SOURCE_FILES': _SOURCE_FILES + (WRAPPER_PATH, TEST_PATH, PROFILE_PATH, HISTORICAL_PROFILE_PATH),
        'quickstart': public_quickstart,
    }
    original = {key: getattr(base, key) for key in replacements}
    try:
        for key, value in replacements.items():
            setattr(base, key, value)
        yield
    finally:
        for key, value in original.items():
            setattr(base, key, value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--packaging-commit')
    parser.add_argument('--derive-profile', action='store_true')
    parser.add_argument('--ci-run', type=Path)
    parser.add_argument('--build-source')
    args = parser.parse_args(argv)
    source = Path(__file__).resolve().parent.parent
    try:
        if args.derive_profile:
            if args.packaging_commit or args.ci_run is None or args.build_source is None:
                base.join.fail('profile derivation requires --ci-run and --build-source, without --packaging-commit')
            profile = derive_profile(source, args.assets, args.ci_run, args.build_source)
            with args.output.open('xb') as output:
                output.write(base.encoded(profile))
            print('Derived exact v0.11.3 artifact profile for review and commit: ' + str(args.output))
            return 0
        if args.packaging_commit is None or args.ci_run is not None or args.build_source is not None:
            base.join.fail('packaging requires --packaging-commit; CI inputs are only used to derive the profile')
        profile = load_profile(source)
        with artifact_profile(profile, source):
            require_committed_source(source, args.packaging_commit, profile)
            sums = base.package(source, args.assets, args.output, args.packaging_commit)
        print(''.join(sums), end='')
        return 0
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print('v0.11.3 packaging: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
