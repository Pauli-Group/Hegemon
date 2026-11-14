#!/usr/bin/env python3
"""Package v0.11.5 from its committed, accepted four-platform artifact profile.

Historical profiles remain unchanged and serve only to reject relabeled assets.
This packages verified bytes; it does not build binaries or grant publication,
activation or deployment approval. Pending profiles cannot package anything.

Preparation may use workflow_dispatch or a push to the exact candidate branch
codex/v0.11.5-ntime-rolling. Both routes run all nine jobs and upload Actions
artifacts only. The retained run JSON must include headBranch along with
databaseId,url,event,status,conclusion,headSha,workflowName,jobs.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import types
import zipfile


def _load_base():
    """Load only this checkout's historical helper, including under python -I."""
    directory = Path(__file__).resolve().parent
    package_name = '_hegemon_v0115_packaging'
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
PROFILE_PATH = 'config/v0115-release-artifacts.json'
RELEASE_METADATA_PATH = 'config/testnet/0.11/release-v0115.json'
CANONICAL_RELEASE_PATH = 'config/testnet/0.11/release.json'
WRAPPER_PATH = 'scripts/package_v0115_release.py'
TEST_PATH = 'scripts/test_package_v0115_release.py'
PACKAGING_PROFILE_CHANGES = {PROFILE_PATH}
HISTORICAL_PROFILES = {
    'v0.11.2': ('config/v0112-release-artifacts.json',
                '4a6511b13f60a2506cf349808146a2e5776ef8687f0d9273ab71c4f3c838a6bf'),
    'v0.11.3': ('config/v0113-release-artifacts.json',
                'c284f6b5d0d6506e629473523dbfa0bf42c6a2ea671c150b8c4302efa9617786'),
    'v0.11.4': ('config/v0114-release-artifacts.json',
                'dcad9f47fa5a045822516cdc8434a502e5ffdf88405ae71268c258c762a9ffef'),
}
LOCK_SHA256 = base.CARGO_LOCK_SHA256
PACKAGE_VERSIONS = {'node/Cargo.toml': '0.10.0', 'wallet/Cargo.toml': '0.10.0',
                    'walletd/Cargo.toml': '0.10.0', 'protocol/versioning/Cargo.toml': '0.1.0'}
FIELDS = {'schema', 'status', 'network_release', 'software_release', 'software_version',
          'release_source_head', 'build_source_head', 'build_index_tree',
          'source_tree_sha256', 'cargo_lock_sha256', 'platform_manifests_sha256',
          'ci_preparation', 'ci_artifacts', 'qualification_receipts_sha256', 'boundaries'}
CI_ARTIFACTS = {'premainnet-release-assets', 'v0115-preparation-evidence'}
FINAL_RECEIPT_SCHEMA = 'hegemon.ntime-rolling.final-receipt.v1'
FINAL_RECEIPT_STATUS = 'PASS_SOFTWARE_CANDIDATE_ARTIFACTS_AND_AFFECTED_LIFECYCLE'
RELATION_DIGEST = 'b9d22c2f0cb49df519b34620c138d7f2d74fa135a76c7b526cd73a60bb5cd6cec2f910dde83b1a848684e123d02ab0bbc8bdb384b1bcaff1b489fd8794c14685'
BOUNDARIES = {'publication_authorized': False, 'activation_authorized': False,
              'deployment_authorized': False, 'mainnet_authorized': False,
              'physical_asic_qualified': False}
REPOSITORY = 'Pauli-Group/Hegemon'
WORKFLOW = 'Prepare pre-mainnet release'
CANDIDATE_BRANCH = 'codex/v0.11.5-ntime-rolling'
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
_SOURCE_FILES = tuple(RELEASE_METADATA_PATH if name == CANONICAL_RELEASE_PATH else name
                      for name in base.SOURCE_FILES)
_QUICKSTART = base.quickstart


def _source_root(source):
    return Path(source) if source is not None else Path(__file__).resolve().parent.parent


def pending_profile():
    """The committed pre-CI template contains no accepted build or artifact pins."""
    return {'schema': 'hegemon.v0115.release-artifacts.v1', 'status': 'pending',
            'network_release': 'v0.11', 'software_release': 'v0.11.5',
            'software_version': '0.11.5', 'release_source_head': None,
            'build_source_head': None, 'build_index_tree': None,
            'source_tree_sha256': None, 'cargo_lock_sha256': LOCK_SHA256,
            'platform_manifests_sha256': {}, 'ci_preparation': None,
            'ci_artifacts': None,
            'qualification_receipts_sha256': {},
            'boundaries': dict(BOUNDARIES)}


def validate_pending_profile(value):
    if (value != pending_profile()
            or any(flag is not False for flag in value['boundaries'].values())):
        base.join.fail('frozen build must contain the exact pending v0.11.5 artifact template')
    return value


def _validate_fields(profile, *, label='v0.11.5'):
    historical_fields = FIELDS - {'boundaries', 'qualification_receipts_sha256', 'ci_artifacts'}
    expected_fields = (historical_fields - {'ci_preparation'} if label == 'v0.11.2'
                       else historical_fields if label != 'v0.11.5' else FIELDS)
    if not isinstance(profile, dict) or set(profile) != expected_fields:
        base.join.fail(label + ' artifact profile must contain exactly the reviewed fields')
    labels = {'schema': 'hegemon.v' + label[1:].replace('.', '') + '.release-artifacts.v1',
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


def historical_profiles(source=None):
    source = _source_root(source)
    result = {}
    for label, (path, expected) in HISTORICAL_PROFILES.items():
        raw = base.join.checked_bytes(source, path)
        if base.sha(raw) != expected:
            base.join.fail('historical ' + label + ' artifact profile changed; preserve its accepted pins')
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=base.join.unique_object)
        _validate_fields(value, label=label)
        result[label] = value
    return result


def validate_profile(profile, source=None):
    _validate_fields(profile)
    if profile['boundaries'] != BOUNDARIES or any(value is not False for value in profile['boundaries'].values()):
        base.join.fail('artifact acceptance cannot grant publication, activation, deployment, mainnet or hardware authority')
    if profile['cargo_lock_sha256'] != LOCK_SHA256:
        base.join.fail('v0.11.5 must retain the exact qualified Cargo.lock proof input')
    if profile['release_source_head'] != profile['build_source_head']:
        base.join.fail('release source must retain the exact CI binary build commit')
    seal = profile['ci_artifacts']
    if (not isinstance(seal, dict) or set(seal) != {'api_record_sha256', 'artifacts'}
            or not isinstance(seal['api_record_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', seal['api_record_sha256'])
            or not isinstance(seal['artifacts'], dict) or set(seal['artifacts']) != CI_ARTIFACTS):
        base.join.fail('exact Actions artifact API record and archive pins required')
    for item in seal['artifacts'].values():
        if (not isinstance(item, dict) or set(item) != {'id', 'sha256', 'size'}
                or type(item['id']) is not int or item['id'] <= 0
                or type(item['size']) is not int or item['size'] <= 0
                or not isinstance(item['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', item['sha256'])):
            base.join.fail('exact Actions artifact ID/digest/size required')
    pins = profile['qualification_receipts_sha256']
    if (not isinstance(pins, dict) or set(pins) != set(base.PLATFORMS)
            or any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)
                   for value in pins.values()) or len(set(pins.values())) != 4):
        base.join.fail('v0.11.5 requires four distinct exact final-qualification receipt digests')
    ci = profile['ci_preparation']
    fields = {'repository', 'run_id', 'run_url', 'workflow', 'event', 'head_sha', 'head_branch',
              'status', 'conclusion', 'successful_jobs', 'run_record_sha256'}
    if not isinstance(ci, dict) or set(ci) != fields:
        base.join.fail('missing exact full preparation CI receipt')
    if (ci['repository'] != REPOSITORY or type(ci['run_id']) is not int or ci['run_id'] <= 0
            or ci['run_url'] != f"https://github.com/{REPOSITORY}/actions/runs/{ci['run_id']}"
            or ci['workflow'] != WORKFLOW
            or not isinstance(ci['head_branch'], str) or not ci['head_branch']
            or not (ci['event'] == 'workflow_dispatch'
                    or (ci['event'] == 'push' and ci['head_branch'] == CANDIDATE_BRANCH))
            or ci['head_sha'] != profile['build_source_head']
            or ci['status'] != 'completed' or ci['conclusion'] != 'success'
            or ci['successful_jobs'] != sorted(REQUIRED_JOBS)
            or not isinstance(ci['run_record_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', ci['run_record_sha256'])):
        base.join.fail('full non-PR preparation CI did not succeed at the binary source commit')
    for label, previous in (('v0.11', _ORIGINAL), *historical_profiles(source).items()):
        old_heads = {previous['release_source_head'], previous['build_source_head']}
        if (profile['release_source_head'] in old_heads or profile['build_source_head'] in old_heads
                or profile['build_index_tree'] == previous['build_index_tree']
                or profile['source_tree_sha256'] == previous['source_tree_sha256']
                or any(pin in set(previous['platform_manifests_sha256'].values())
                       for pin in profile['platform_manifests_sha256'].values())):
            base.join.fail(label + ' artifact provenance cannot be relabeled as v0.11.5')
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
    product = git(source, 'show', commit + ':protocol/versioning/src/lib.rs').decode('utf-8')
    if re.findall(r'^pub const RELEASE_VERSION: &str = "([^"\n]*)";$', product, re.M) != ['0.11.5']:
        base.join.fail('binary source product version is not exact v0.11.5')
    for name, expected in PACKAGE_VERSIONS.items():
        package = git(source, 'show', commit + ':' + name).decode('utf-8').split('[dependencies]', 1)[0]
        versions = re.findall(r'^version\s*=\s*"([^"\n]*)"\s*$', package, re.M)
        if versions != [expected]:
            base.join.fail('relation-bound internal package version changed: ' + name)
    if committed_tree_sha256(source, commit) != profile['source_tree_sha256']:
        base.join.fail('binary source tree digest does not match its source commit')


def require_committed_source(source, commit, profile):
    """Only pending-to-accepted artifact metadata may follow the CI build commit."""
    base.require_committed_source(source, commit)
    git(source, 'merge-base', '--is-ancestor', profile['build_source_head'], commit)
    changes = git(source, 'diff', '--name-status', '-z', profile['build_source_head'], commit).split(b'\0')
    pairs = list(zip(changes[0:-1:2], changes[1:-1:2]))
    if (len(changes) != 2 * len(PACKAGING_PROFILE_CHANGES) + 1
            or {name.decode() for status, name in pairs if status == b'M'} != PACKAGING_PROFILE_CHANGES):
        base.join.fail('packaging commit may only modify the pending v0.11.5 artifact profile')
    validate_pending_profile(json.loads(git(source, 'show', profile['build_source_head'] + ':' + PROFILE_PATH),
                                       object_pairs_hook=base.join.unique_object))
    git(source, 'diff', '--exit-code', 'HEAD', '--')
    if git(source, 'ls-files', '--others', '--exclude-standard', '-z'):
        base.join.fail('packaging checkout has untracked source files')
    verify_build_source(source, profile)


def qualification_name(selected):
    return f'hegemon-v0115-final-{selected}.json'


def verify_ci_artifacts(record_path, archives, run, assets, qualification, source_manifests):
    """Bind supplied files to the two authenticated Actions download archives.

    The operator retains the raw authenticated GET /actions/runs/RUN/artifacts
    response and the two downloaded ZIPs. No network call or extraction occurs.
    GitHub's API digest authenticates each archive against that retained record;
    member digests then bind every asset, final receipt and original manifest.
    """
    raw = base.join.checked_bytes(record_path.parent, record_path.name, 16 * 1024 * 1024)
    record = json.loads(raw.decode('utf-8'), object_pairs_hook=base.join.unique_object)
    rows = record.get('artifacts') if isinstance(record, dict) else None
    if (not isinstance(rows, list) or type(record.get('total_count')) is not int
            or record['total_count'] != len(rows) or len(rows) > 100):
        base.join.fail('complete bounded Actions artifacts API record required')
    if {p.name for p in archives.iterdir()} != {name + '.zip' for name in CI_ARTIFACTS}:
        base.join.fail('exactly two original Actions artifact ZIP downloads required')
    expected_files = {
        'premainnet-release-assets': {name: (assets, name) for name in base.expected_inputs()},
        'v0115-preparation-evidence': {
            **{'qualification-receipts/' + qualification_name(p): (qualification, qualification_name(p))
               for p in base.PLATFORMS},
            **{f'source-artifact-manifests/hegemon-release-artifacts-{p}.json':
               (source_manifests, f'hegemon-release-artifacts-{p}.json') for p in base.PLATFORMS}},
    }
    result = {}
    for name in sorted(CI_ARTIFACTS):
        matches = [row for row in rows if isinstance(row, dict) and row.get('name') == name]
        if len(matches) != 1:
            base.join.fail('exactly one retained Actions artifact required: ' + name)
        row = matches[0]
        artifact_id, size, workflow = row.get('id'), row.get('size_in_bytes'), row.get('workflow_run')
        if (type(artifact_id) is not int or artifact_id <= 0 or type(size) is not int
                or not 0 < size <= 8 * 1024**3 or row.get('expired') is not False
                or not isinstance(workflow, dict) or workflow.get('id') != run.get('databaseId')
                or workflow.get('head_sha') != run.get('headSha')
                or workflow.get('head_branch') != run.get('headBranch')
                or row.get('archive_download_url') != f'https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip'
                or not isinstance(row.get('digest'), str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest'])):
            base.join.fail('Actions artifact run/source/repository provenance differs: ' + name)
        path = base.join.safe_file(archives, name + '.zip')
        digest = base.join.digest_file(archives, name + '.zip')
        if path.stat().st_size != size or digest != row['digest'][7:]:
            base.join.fail('original Actions artifact ZIP digest or size differs: ' + name)
        files, seen, total = expected_files[name], set(), 0
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                member = info.filename
                relative = PurePosixPath(member.rstrip('/'))
                mode = (info.external_attr >> 16) & 0o170000
                if (not member or relative.is_absolute() or relative.as_posix() != member.rstrip('/')
                        or any(p in ('', '.', '..') or ':' in p or '\\' in p for p in relative.parts)
                        or stat.S_ISLNK(mode) or mode not in (0, stat.S_IFREG, stat.S_IFDIR)
                        or (info.create_system == 0 and info.external_attr & 0x400)
                        or info.flag_bits & 1 or member in seen):
                    base.join.fail('unsafe or duplicate Actions artifact ZIP member')
                seen.add(member)
                if info.is_dir():
                    if not any(key.startswith(member) for key in files):
                        base.join.fail('unexpected Actions artifact ZIP directory')
                    continue
                if member not in files or not 0 < info.file_size <= base.join.MAX_FILE:
                    base.join.fail('unexpected or oversized Actions artifact ZIP file')
                total += info.file_size
                if total > 16 * 1024**3:
                    base.join.fail('Actions artifact uncompressed bytes exceed bound')
                root, filename = files[member]
                supplied = base.join.safe_file(root, filename)
                h = hashlib.sha256()
                with archive.open(info) as stream:
                    while chunk := stream.read(1024 * 1024):
                        h.update(chunk)
                if supplied.stat().st_size != info.file_size or base.join.digest_file(root, filename) != h.hexdigest():
                    base.join.fail('supplied bytes differ from checked CI artifact: ' + member)
        if {member for member in seen if not member.endswith('/')} != set(files):
            base.join.fail('Actions artifact ZIP inventory differs: ' + name)
        result[name] = {'id': artifact_id, 'sha256': digest, 'size': size}
    if len({row['id'] for row in result.values()}) != 2:
        base.join.fail('Actions artifact IDs must be distinct')
    return {'api_record_sha256': base.sha(raw), 'artifacts': result}


def final_receipt_helper(source):
    path = Path(source) / 'scripts/check_ntime_rolling_candidate.py'
    spec = importlib.util.spec_from_file_location('_v0115_full_final_receipt', path)
    if spec is None or spec.loader is None:
        base.join.fail('source-owned v0.11.5 final receipt predicate unavailable')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def validate_full_final_receipt(source, value, original, digest):
    """Use the exact source-owned proof, H0, source-review and lifecycle predicate."""
    helper = final_receipt_helper(source)
    return helper.validate_final_receipt(value, original, digest, root=Path(source))


def qualification_receipts(directory, manifests, source, source_manifests, expected_pins=None):
    """Bind retained successful final-binary checks to the exact packaged bytes.

    These records are CI evidence, not independent signatures. Derivation also
    requires the successful non-PR workflow and immutable build source below.
    """
    expected_names = {qualification_name(selected) for selected in base.PLATFORMS}
    if {path.name for path in directory.iterdir()} != expected_names:
        base.join.fail('qualification directory must contain exactly four final platform receipts')
    result = {}
    for selected, (manifest, _) in manifests.items():
        raw = base.join.checked_bytes(directory, qualification_name(selected), 16 * 1024 * 1024)
        digest = base.sha(raw)
        if expected_pins is not None and expected_pins.get(selected) != digest:
            base.join.fail('accepted final-qualification receipt changed: ' + selected)
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=base.join.unique_object)
        raw_original = base.join.checked_bytes(source_manifests, f'hegemon-release-artifacts-{selected}.json')
        if base.sha(raw_original) != manifest['source_manifest_sha256']:
            base.join.fail('original final artifact manifest changed: ' + selected)
        original = json.loads(raw_original.decode('utf-8'), object_pairs_hook=base.join.unique_object)
        validate_full_final_receipt(source, value, original, base.sha(raw_original))
        expected_artifacts = {row['binary']: row['sha256'] for row in manifest['assets']}
        if (not isinstance(value, dict) or value.get('schema') != FINAL_RECEIPT_SCHEMA
                or value.get('status') != FINAL_RECEIPT_STATUS
                or value.get('software_version') != '0.11.5'
                or value.get('target_triple') != manifest['target_triple']
                or value.get('artifact_manifest_sha256') != manifest['source_manifest_sha256']
                or value.get('artifact_sha256') != expected_artifacts):
            base.join.fail('final-qualification identity does not bind exact v0.11.5 platform bytes: ' + selected)
        if any(value.get(name) is not True for name in
               ('actual_new_binary_proof_verification', 'current_binary_backend_artifacts_verified',
                'affected_lifecycle_verified')):
            base.join.fail('actual current-binary proof and affected lifecycle qualification required: ' + selected)
        if (not isinstance(value.get('identity'), dict)
                or value['identity'].get('relation_digest') != RELATION_DIGEST):
            base.join.fail('final-qualification unchanged proof identity differs: ' + selected)
        smoke = value.get('identity_smoke')
        if (not isinstance(smoke, dict) or smoke.get('qualified_manifest') is not True
                or type(smoke.get('height')) is not int or smoke['height'] != 0
                or smoke.get('node_rpc_version') != 'Hegemon Native Node 0.11.5'):
            base.join.fail('actual v0.11.5 binary H0 identity qualification required: ' + selected)
        if any(value.get(name) is not False for name in
               ('production_authorized', 'mainnet_authorized', 'activation_authorized',
                'public_cutover_authorized', 'deployment_verified', 'physical_asic_qualified')):
            base.join.fail('final-qualification receipt expanded authority: ' + selected)
        result[selected] = digest
    return result


def derive_profile(source, directory, run_path, build_source, qualification_directory, source_manifests, artifact_record, artifact_archives):
    """Derive reviewable pins only from complete artifacts and a successful CI run.

    run_path is the unmodified JSON returned by authenticated `gh run view`
    with databaseId,url,event,status,conclusion,headSha,headBranch,workflowName,jobs. It is
    evidence provided by the release operator, not an independently authenticated
    signature. The accepted profile must still be reviewed and committed.
    """
    if not isinstance(build_source, str) or not re.fullmatch('[0-9a-f]{40}', build_source):
        base.join.fail('require the exact frozen binary source commit')
    if git(source, 'rev-parse', 'HEAD').decode().strip() != build_source:
        base.join.fail('derive the accepted artifact profile at the frozen CI build source')
    git(source, 'diff', '--exit-code', 'HEAD', '--')
    if git(source, 'ls-files', '--others', '--exclude-standard', '-z'):
        base.join.fail('profile derivation checkout has untracked source files')
    validate_pending_profile(json.loads(git(source, 'show', build_source + ':' + PROFILE_PATH),
                                       object_pairs_hook=base.join.unique_object))
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
        'schema': 'hegemon.v0115.release-artifacts.v1', 'status': 'accepted',
        'network_release': 'v0.11', 'software_release': 'v0.11.5', 'software_version': '0.11.5',
        'release_source_head': build_source, 'build_source_head': build_source,
        'build_index_tree': first.get('source_index_tree'),
        'source_tree_sha256': first.get('source_tree_sha256'),
        'cargo_lock_sha256': first.get('cargo_lock_sha256'),
        'platform_manifests_sha256': {selected: base.sha(raw) for selected, (_, raw) in manifests.items()},
        'qualification_receipts_sha256': qualification_receipts(qualification_directory, manifests, source, source_manifests),
        'ci_artifacts': verify_ci_artifacts(artifact_record, artifact_archives, run, directory, qualification_directory, source_manifests),
        'boundaries': dict(BOUNDARIES),
        'ci_preparation': {
            'repository': REPOSITORY, 'run_id': run.get('databaseId'), 'run_url': run.get('url'),
            'workflow': run.get('workflowName'), 'event': run.get('event'), 'head_sha': run.get('headSha'),
            'head_branch': run.get('headBranch'),
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
        base.join.fail('review changed historical QUICKSTART before v0.11.5 packaging')
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
        'SOURCE_FILES': _SOURCE_FILES + (WRAPPER_PATH, TEST_PATH, PROFILE_PATH,
                                       *(path for path, _ in HISTORICAL_PROFILES.values())),
        'quickstart': public_quickstart,
    }
    original = {key: getattr(base, key) for key in replacements}
    original_checked_bytes = base.join.checked_bytes
    def checked_bytes(root, name, *args, **kwargs):
        if Path(root).resolve() == _source_root(source).resolve() and name == CANONICAL_RELEASE_PATH:
            name = RELEASE_METADATA_PATH
        return original_checked_bytes(root, name, *args, **kwargs)
    try:
        for key, value in replacements.items():
            setattr(base, key, value)
        base.join.checked_bytes = checked_bytes
        yield
    finally:
        base.join.checked_bytes = original_checked_bytes
        for key, value in original.items():
            setattr(base, key, value)


def package_release(source, directory, qualification_directory, source_manifests, run_path, artifact_record, artifact_archives, output, commit):
    profile = load_profile(source)
    with artifact_profile(profile, source):
        require_committed_source(source, commit, profile)
        manifests = base.validate_assets(directory)
        qualification_receipts(qualification_directory, manifests, source, source_manifests, profile['qualification_receipts_sha256'])
        raw_run = base.join.checked_bytes(run_path.parent, run_path.name)
        if base.sha(raw_run) != profile['ci_preparation']['run_record_sha256']:
            base.join.fail('accepted preparation run record changed')
        run = json.loads(raw_run.decode('utf-8'), object_pairs_hook=base.join.unique_object)
        if verify_ci_artifacts(artifact_record, artifact_archives, run, directory, qualification_directory, source_manifests) != profile['ci_artifacts']:
            base.join.fail('accepted Actions artifact provenance changed')
        return base.package(source, directory, output, commit)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--packaging-commit')
    parser.add_argument('--derive-profile', action='store_true')
    parser.add_argument('--ci-run', type=Path, required=True)
    parser.add_argument('--ci-artifact-record', type=Path, required=True,
                        help='raw authenticated Actions run-artifacts API JSON, including digest and workflow_run')
    parser.add_argument('--ci-artifact-archives', type=Path, required=True,
                        help='directory with original premainnet-release-assets.zip and v0115-preparation-evidence.zip')
    parser.add_argument('--build-source')
    parser.add_argument('--qualification-receipts', type=Path, required=True,
                        help='directory containing exactly four retained final-platform qualification receipts')
    parser.add_argument('--source-manifests', type=Path, required=True,
                        help='directory containing four retained original artifact manifests')
    args = parser.parse_args(argv)
    source = Path(__file__).resolve().parent.parent
    try:
        if args.derive_profile:
            if args.packaging_commit or args.ci_run is None or args.build_source is None:
                base.join.fail('profile derivation requires --ci-run and --build-source, without --packaging-commit')
            profile = derive_profile(source, args.assets, args.ci_run, args.build_source, args.qualification_receipts, args.source_manifests, args.ci_artifact_record, args.ci_artifact_archives)
            with args.output.open('xb') as output:
                output.write(base.encoded(profile))
            print('Derived exact v0.11.5 artifact profile for review and commit: ' + str(args.output))
            return 0
        if args.packaging_commit is None or args.build_source is not None:
            base.join.fail('packaging requires --packaging-commit; CI inputs are only used to derive the profile')
        sums = package_release(source, args.assets, args.qualification_receipts, args.source_manifests, args.ci_run, args.ci_artifact_record, args.ci_artifact_archives, args.output, args.packaging_commit)
        print(''.join(sums), end='')
        return 0
    except (ValueError, RuntimeError, OSError, UnicodeError, KeyError, TypeError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        print('v0.11.5 packaging: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
