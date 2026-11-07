#!/usr/bin/env python3
"""Compose v0.11.3 formatting with immutable predecessor debt policy.

Only the existing node_impl migration receives its exact composed postimage.
New modules must format cleanly. This control accepts a pending release review
for formatting inspection only; it grants no release or runtime authority.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SUCCESSOR = 'scripts/check_v0113_release_successor.py'
SYNC_FORMATTING = 'scripts/check_sync_import_formatting.py'
SYNC_FORMATTING_SHA256 = '5f055dd5b8cb1aa651cc3d1cd690dbe7224078f620acaf5e4b3f2e11b4b628fe'
MANIFESTS = {'workspace': None, 'htlc': 'experimental/htlc-prototype/Cargo.toml',
             'proof-backend': 'experimental/htlc-prototype/proof-backend/Cargo.toml'}


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def load_module(root, relative, name, digest=None):
    path = root / relative
    require(path.is_file() and not path.is_symlink() and path.resolve() == path,
            'missing, linked or noncanonical formatting authority: ' + relative)
    if digest is not None:
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                'historical formatting authority differs: ' + relative)
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, 'cannot import formatting authority')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def compose_existing_migration(old, baseline, sync, config, overlay):
    """Specialize one existing debt row, after both predecessors authenticate."""
    require(overlay['before_sha256'] == sync.NODE_IMPL_SHA256,
            'v0.11.3 node predecessor differs from the sync/import postimage')
    postimage = overlay['after_sha256']
    require(isinstance(postimage, str) and re.fullmatch('[0-9a-f]{64}', postimage),
            'v0.11.3 node postimage is not exact')
    migration = config['migration']
    require(migration['path'] == sync.NODE_IMPL
            and migration['postimage_sha256'] == sync.NODE_IMPL_SHA256,
            'sync/import reviewed node migration differs')
    rows = [dict(row) for row in old.REVIEWED_SOURCE_MIGRATIONS]
    positions = [index for index, row in enumerate(rows) if row['path'] == sync.NODE_IMPL]
    require(len(positions) == 1, 'historical node migration is not unique')
    index = positions[0]
    require(rows[index] == {
        'path': sync.NODE_IMPL,
        'qualified_sha256': migration['qualified_sha256'],
        'postimage_sha256': migration['historical_postimage_sha256'],
        'scope': migration['scope'],
    } and baseline[sync.NODE_IMPL] == migration['qualified_sha256'],
        'historical predecessor/migration tuple differs')
    rows[index]['postimage_sha256'] = postimage
    old.REVIEWED_SOURCE_MIGRATIONS = rows


def load_authorized(root):
    root = Path(root).resolve()
    # The current checker is source-owned, and independently reviewed with this
    # adapter. Its loader authenticates the current source/config composition.
    successor = load_module(root, SUCCESSOR, '_v0113_formatting_release')
    successor.load_binding(root, require_sources=True, require_review=False)
    sync = load_module(root, SYNC_FORMATTING, '_v0113_formatting_sync', SYNC_FORMATTING_SHA256)
    _, config_raw = sync.authenticated_file(root, sync.CONFIG, sync.CONFIG_SHA256)
    config = json.loads(config_raw, object_pairs_hook=sync.duplicate_free)
    require(config['schema'] == 'hegemon.sync-import.formatting-successor.v1',
            'sync/import formatting schema differs')
    require(config['historical_checker'] == {
        'path': sync.HISTORICAL_CHECKER, 'sha256': sync.HISTORICAL_CHECKER_SHA256},
        'historical formatting checker identity differs')
    require(config['historical_baseline'] == {
        'path': sync.HISTORICAL_BASELINE, 'sha256': sync.HISTORICAL_BASELINE_SHA256},
        'historical formatting baseline identity differs')
    old = load_module(root, sync.HISTORICAL_CHECKER, '_v0113_formatting_historical',
                      sync.HISTORICAL_CHECKER_SHA256)
    baseline_path, _ = sync.authenticated_file(
        root, sync.HISTORICAL_BASELINE, sync.HISTORICAL_BASELINE_SHA256)
    # Original loader checks all original baseline and migration tuples before
    # the single in-memory postimage specialization below.
    baseline = old.load_baseline(baseline_path)
    require(old.MANIFESTS == MANIFESTS and sync.MANIFESTS == MANIFESTS,
            'historical formatting manifest set differs')
    require(config['direct_module_checks'] == {
        'toolchain': '1.91.1', 'edition': '2021', 'files': sync.DIRECT_MODULES,
        'scope': 'workspace invocation requires direct rustfmt --check success; no debt allowance'},
        'sync/import direct module formatting policy differs')
    direct = dict(sync.DIRECT_MODULES)
    for name, row in successor.OVERLAY.items():
        if name.endswith('.rs') and row['before_sha256'] is None:
            require(name not in baseline, 'new module cannot inherit formatting debt: ' + name)
            direct[name] = row['after_sha256']
    for name, digest in direct.items():
        sync.authenticated_file(root, name, digest)
    compose_existing_migration(old, baseline, sync, config, successor.OVERLAY[sync.NODE_IMPL])
    return old, baseline, direct


def verify_observed_failures(root, failures):
    """Pure policy check; does not execute rustfmt or Cargo."""
    root = Path(root).resolve()
    old, baseline, _ = load_authorized(root)
    old.verify_failures(root, failures, baseline)
    return baseline


def run(root, manifest):
    root = Path(root).resolve()
    old, baseline, direct = load_authorized(root)
    version = subprocess.run(['cargo', '+1.91.1', 'fmt', '--version'], cwd=root,
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    require(version.returncode == 0 and not version.stderr
            and version.stdout.strip() == old.RUSTFMT_VERSION,
            'pinned rustfmt implementation differs')
    command = ['cargo', '+1.91.1', 'fmt']
    if MANIFESTS[manifest]:
        command += ['--manifest-path', MANIFESTS[manifest]]
    command += ['--all', '--', '--check', '--color', 'never']
    result = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=180)
    failures = old.parse_failure(root, result.returncode, result.stdout, result.stderr)
    old.verify_failures(root, failures, baseline)
    if manifest == 'workspace':
        checked = subprocess.run(
            ['rustup', 'run', '1.91.1', 'rustfmt', '--check', '--edition', '2021',
             '--color', 'never', *(str(root/name) for name in sorted(direct))],
            cwd=root, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
        require(checked.returncode == 0 and not checked.stdout and not checked.stderr,
                'new modules must pass direct pinned rustfmt without formatting debt')
    load_authorized(root)
    migrated = sum(hashlib.sha256((root/name).read_bytes()).hexdigest() != baseline[name]
                   for name in failures)
    print(f'Formatting {manifest}: PASS; {len(failures)-migrated} unchanged debt files '
          f'and {migrated} exact migrations; v0.11.3 formatting control only')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', choices=MANIFESTS, default='workspace')
    args = parser.parse_args()
    try:
        run(ROOT, args.manifest)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print('Formatting rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
