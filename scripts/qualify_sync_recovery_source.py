#!/usr/bin/env python3
"""Exact incident delta validation; no release or activation authority."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

BASELINE_COMMIT = '3fbf18ffec5b104766f5fefc2e515c8059a24c80'
COMPILED_BASELINE = '5c1d278af03c7bd0b0a61a8383bf4d8aede94e59'
WORKFLOW_PATH = '.github/workflows/qualify-sync-recovery-linux.yml'
EXPECTED_BASELINE_FILES = {
    'node/src/native/node_impl.rs': '170823ec4712a1b0118101293603c44622f76ab82edc868e2fc083ec83a5e37b',
    'node/src/native/sync_liveness_tests.rs': 'dc7da2b06aa5dcb3a227bcc2e20aaae5f6fad796272015207f64ad916c0dd5a1',
    'node/src/native/service.rs': '2cdce2dde70626f7ae6f99957dec99cc3d641b051a95c3b2de1490704135acb3',
    'DESIGN.md': '591c245bbd5c3feb57c8aedd7adc05b3d29294ed38a88ed9e9aec62c95abf9c7',
    'METHODS.md': '4dee7cb216244cb826e90a4955ad5a9f634206317a3e63aa59b83a4256e0a205',
}
EXPECTED_SOURCE_FILES = {
    'node/src/native/node_impl.rs': 'f02261f5fb5cd621134f62496da660b4112d9af59dbfa6fd5f7c704b2c99f9a2',
    'node/src/native/sync_liveness_tests.rs': '8d45daeb558f8181898f4f9e864bd13fef41d24ab42c70bf206a69164141f684',
    'node/src/native/service.rs': 'f9e0edc2f8adb5bc8ff8b5eb3f7da6e43faff0a70cc08084a874930024e3db2c',
    'DESIGN.md': '3925a84bdf0c99c936e460f08784b11e40122ee6b964b47770f022c8b2257a12',
    'METHODS.md': '372822f26bc01581ad61482678c8679756fad3964327f3df26d8388f5958eb44',
}
ALLOWED_CHANGED_PATHS = set(EXPECTED_SOURCE_FILES) | {
    WORKFLOW_PATH, 'scripts/qualify_sync_recovery_source.py',
    'scripts/qualify_sync_recovery_linux.py', 'scripts/test_qualify_sync_recovery_source.py',
}

class SourceError(ValueError):
    pass

def require(value, message):
    if not value:
        raise SourceError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, timeout=120, check=False)
    require(result.returncode == 0, 'git failed: ' + result.stderr.decode(errors='replace')[-1000:])
    return result.stdout

def delta_digest(root, head='HEAD'):
    return sha(git(root, 'diff', '--binary', '--full-index', '--no-ext-diff', BASELINE_COMMIT, head))

def validate_workflow(raw):
    text = raw.decode('utf-8')
    require('permissions:\n  contents: read\n' in text, 'workflow needs exact contents: read permissions')
    require(re.search(r'(?m)^\s*[A-Za-z_-]+:\s*(?:write|write-all)\s*(?:#.*)?$', text) is None,
            'workflow write permission rejected')
    require(re.search(r'\bsecrets\s*[.\[]', text) is None, 'workflow secret expression rejected')
    for forbidden in ('contents: write', 'packages: write', 'id-token: write', 'gh release', 'git push', 'secrets:', 'secrets.', 'pull_request_target'):
        require(forbidden not in text, 'forbidden workflow operation: ' + forbidden)
    for reference in re.findall(r'(?m)^\s*-?\s*uses:\s*([^\s#]+)', text):
        require(re.fullmatch(r'[^@\s]+@[0-9a-f]{40}', reference) is not None, 'workflow action is not exact-pinned')

def validate_source(root, expected_source_sha, expected_delta_sha256, *, pin_provenance='dispatch-inputs'):
    root = Path(root).resolve()
    require(re.fullmatch('[0-9a-f]{40}', expected_source_sha or '') is not None, 'source SHA must be forty lowercase hex digits')
    require(re.fullmatch('[0-9a-f]{64}', expected_delta_sha256 or '') is not None, 'delta SHA must be sixty-four lowercase hex digits')
    head = git(root, 'rev-parse', 'HEAD').decode().strip()
    require(head == expected_source_sha, 'source HEAD differs from dispatch pin')
    require(git(root, 'rev-parse', BASELINE_COMMIT + '^{commit}').decode().strip() == BASELINE_COMMIT, 'baseline commit unavailable')
    require(not git(root, 'status', '--porcelain=v1', '--untracked-files=all'), 'dirty or untracked source tree')
    changes = git(root, 'diff', '--name-status', '--no-renames', BASELINE_COMMIT, head).decode().splitlines()
    changed = set()
    for line in changes:
        status, path = line.split('\t')
        require(status in ('A', 'M') and path in ALLOWED_CHANGED_PATHS, 'unexpected source delta: ' + line)
        changed.add(path)
    require(changed == ALLOWED_CHANGED_PATHS, 'exact incident source/CI delta path set required')
    for path, digest in EXPECTED_BASELINE_FILES.items():
        require(sha(git(root, 'show', BASELINE_COMMIT + ':' + path)) == digest, 'baseline preimage differs: ' + path)
    for path, digest in EXPECTED_SOURCE_FILES.items():
        require(sha((root / path).read_bytes()) == digest, 'approved source postimage differs: ' + path)
    actual_delta = delta_digest(root, head)
    require(actual_delta == expected_delta_sha256, 'complete binary Git delta differs from dispatch pin')
    # Git status omits ignored files; Cargo still discovers ignored src/bin/*.rs.
    excluded = {'.git', 'target', 'node_modules', '.lake', '__pycache__', '.venv', 'venv'}
    tracked = set(git(root, 'ls-files', '-z').decode().rstrip('\0').split('\0'))
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in excluded]
        for name in dirs:
            require(not (Path(directory) / name).is_symlink(), 'linked source directory rejected')
        for name in files:
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            build_input = path.suffix in ('.rs', '.lean') or name in ('Cargo.toml', 'Cargo.lock', 'build.rs', 'rust-toolchain', 'rust-toolchain.toml') or rel.startswith('.cargo/')
            if build_input:
                require(not path.is_symlink() and rel in tracked, 'untracked/linked build input: ' + rel)
    validate_workflow((root / WORKFLOW_PATH).read_bytes())
    files = []
    for entry in git(root, 'ls-tree', '-rz', '--full-tree', head).split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, _ = metadata.decode().split()
        require(kind == 'blob' and mode in ('100644', '100755'), 'submodule/symlink/nonregular source rejected')
        path = name.decode(); raw = (root / path).read_bytes()
        files.append({'path': path, 'mode': mode, 'bytes': len(raw), 'sha256': sha(raw)})
    canonical = json.dumps(files, sort_keys=True, separators=(',', ':')).encode()
    require(pin_provenance in ('dispatch-inputs', 'root-external-check-required'), 'unknown source pin provenance')
    return {'schema': 'hegemon.sync-recovery.source-qualification.v1',
            'status': ('PASS_EXACT_FUNCTIONAL_POSTIMAGES_ROOT_DELTA_CHECK_PENDING' if pin_provenance == 'root-external-check-required' else 'PASS_EXACT_REVIEWED_INCIDENT_DELTA'),
            'pin_provenance': pin_provenance, 'external_expected_delta_check_required_root': pin_provenance == 'root-external-check-required',
            'source_head': head, 'baseline_commit': BASELINE_COMMIT, 'compiled_baseline': COMPILED_BASELINE,
            'delta_sha256': actual_delta, 'source_inventory_sha256': sha(canonical), 'source_inventory': files,
            'production_changed': ['node/src/native/node_impl.rs', 'node/src/native/service.rs'], 'workflow_sha256': sha((root / WORKFLOW_PATH).read_bytes()),
            'production_authorized': False, 'deployment_verified': False, 'release_publication_authorized': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--expected-source-sha', required=True)
    parser.add_argument('--expected-delta-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--pin-provenance', choices=('dispatch-inputs', 'root-external-check-required'), default='dispatch-inputs')
    args = parser.parse_args()
    value = validate_source(args.root, args.expected_source_sha, args.expected_delta_sha256, pin_provenance=args.pin_provenance)
    with args.output.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')

if __name__ == '__main__':
    main()
