#!/usr/bin/env python3
"""Exact requested-range transport delta validation; no release or activation authority."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

BASELINE_COMMIT = 'de7a4f31b280eb52ed0c09e055840cec60d1f652'
COMPILED_BASELINE = 'de7a4f31b280eb52ed0c09e055840cec60d1f652'
WORKFLOW_PATH = '.github/workflows/qualify-sync-range-transport-linux.yml'
EXPECTED_BASELINE_FILES = {'node/src/native/service.rs': '54dabf7f40c09e6476de2ce1f0a599feefacc2d187cff5fbf9c738aa05b798e8', 'DESIGN.md': '08595f7a062ce8cd58b64ad6fbe22b8932f2e8645d2a3b373f0ad2d90f4517dc', 'METHODS.md': 'f2ac1269a081534513a25d4868246f0006f2d2fb3d052f83270be505cc417191'}
EXPECTED_SOURCE_FILES = {'node/src/native/service.rs': '7ac58789e3f4fa8c32b29c8723e40386682e1a531ae25b43dd08f390b00077ec', 'DESIGN.md': 'bf144c302f923ed85d32270e6dd3a8daa10aaf08db50ebd9a972f19faa10f5f2', 'METHODS.md': 'b407ecb85f56ea7c0a37d8e8b36837b62bef57026fc47273b554b9d2e7b53c97'}
ALLOWED_CHANGED_PATHS = set(EXPECTED_SOURCE_FILES) | {
 WORKFLOW_PATH, 'scripts/qualify_sync_range_transport_source.py',
 'scripts/qualify_sync_range_transport_linux.py', 'scripts/test_qualify_sync_range_transport_source.py',
 '.agent/sync-range-transport-20261110-plan.md',
 'release-evidence/sync-range-transport-qualification-contract.json',
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
    require(changed == ALLOWED_CHANGED_PATHS, 'exact requested-range source/CI delta path set required')
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
    return {'schema': 'hegemon.sync-range-transport.source-qualification.v1',
            'status': ('PASS_EXACT_FUNCTIONAL_POSTIMAGES_ROOT_DELTA_CHECK_PENDING' if pin_provenance == 'root-external-check-required' else 'PASS_EXACT_REVIEWED_INCIDENT_DELTA'),
            'pin_provenance': pin_provenance, 'external_expected_delta_check_required_root': pin_provenance == 'root-external-check-required',
            'source_head': head, 'baseline_commit': BASELINE_COMMIT, 'compiled_baseline': COMPILED_BASELINE,
            'delta_sha256': actual_delta, 'source_inventory_sha256': sha(canonical), 'source_inventory': files,
            'production_changed': ['node/src/native/service.rs'], 'workflow_sha256': sha((root / WORKFLOW_PATH).read_bytes()),
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
