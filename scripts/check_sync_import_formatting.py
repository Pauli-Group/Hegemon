#!/usr/bin/env python3
"""Authenticate historical formatting policy and one sync/import successor.

The historical checker and debt baseline stay byte-for-byte unchanged. Only the
reviewed node_impl postimage is specialized in memory, after the original loader
has authenticated its original baseline. New formatting-debt paths still reject.
This check grants no release, cryptographic or deployment authority.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = 'config/sync-import-formatting-20261106.json'
CONFIG_SHA256 = 'a39deb3b9eb482879e1a95c5f039d7387b2ca9bbe72235f998b41d3a40fc02c6'
HISTORICAL_CHECKER = 'scripts/check_qualified_formatting.py'
HISTORICAL_CHECKER_SHA256 = 'be7732c0e30f9b770ef5395be762ec9ea133d39f7fc52170d17639e2579a71a9'
HISTORICAL_BASELINE = 'config/qualified-formatting-baseline.json'
HISTORICAL_BASELINE_SHA256 = '76a60a213994ee887c854cdd33031667a18472611efc7cf16cb8aa802206ec02'
NODE_IMPL = 'node/src/native/node_impl.rs'
NODE_IMPL_SHA256 = 'c588a5dcc5987e2c3f94ca03fae643ae9425dcd0c3abe27f465f6961abbd0a65'
DIRECT_MODULES = {
    'node/src/native/sync_body_backpressure.rs':
        'f78c7b4dcb1d6d3365b8e69c65c8bf3dbcaecd98e9df02015defc50824c8c3ab',
    'node/src/native/sync_control_backpressure_tests.rs':
        'eda6eec5184fc7d01b7f31110e983bbe610b462f7bbbcd9a84ee8a15a65a57af',
}
MANIFESTS = {'workspace': None, 'htlc': 'experimental/htlc-prototype/Cargo.toml',
             'proof-backend': 'experimental/htlc-prototype/proof-backend/Cargo.toml'}


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def authenticated_file(root, relative, expected):
    path = root / relative
    require(path.is_file() and not path.is_symlink() and path.resolve() == path,
            'missing, linked or noncanonical formatting input: ' + relative)
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected,
            'formatting input pin differs: ' + relative)
    return path, raw


def duplicate_free(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate formatting successor key')
        result[key] = value
    return result


def load_authorized(root):
    """Authenticate originals before importing or specializing any old policy."""
    root = Path(root).resolve()
    _, raw = authenticated_file(root, CONFIG, CONFIG_SHA256)
    config = json.loads(raw, object_pairs_hook=duplicate_free)
    require(config['schema'] == 'hegemon.sync-import.formatting-successor.v1',
            'formatting successor schema differs')
    require(config['historical_checker'] == {
        'path': HISTORICAL_CHECKER, 'sha256': HISTORICAL_CHECKER_SHA256},
        'historical checker identity differs')
    require(config['historical_baseline'] == {
        'path': HISTORICAL_BASELINE, 'sha256': HISTORICAL_BASELINE_SHA256},
        'historical baseline identity differs')
    checker, _ = authenticated_file(root, HISTORICAL_CHECKER, HISTORICAL_CHECKER_SHA256)
    baseline_path, _ = authenticated_file(root, HISTORICAL_BASELINE, HISTORICAL_BASELINE_SHA256)
    authenticated_file(root, NODE_IMPL, NODE_IMPL_SHA256)
    require(config['direct_module_checks'] == {
        'toolchain': '1.91.1', 'edition': '2021', 'files': DIRECT_MODULES,
        'scope': 'workspace invocation requires direct rustfmt --check success; no debt allowance'},
        'direct module formatting policy differs')
    for name, digest in DIRECT_MODULES.items():
        authenticated_file(root, name, digest)
    migration = config['migration']
    require(migration['path'] == NODE_IMPL and migration['postimage_sha256'] == NODE_IMPL_SHA256,
            'reviewed node successor differs')

    spec = importlib.util.spec_from_file_location('_sync_import_historical_formatting', checker)
    require(spec is not None and spec.loader is not None, 'cannot load authenticated checker')
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    # No loader/global changes precede this call. It checks the historical schema,
    # predecessor hashes and historical migration tuples exactly as before.
    baseline = old.load_baseline(baseline_path)
    require(old.MANIFESTS == MANIFESTS, 'historical manifest choices differ')
    rows = [dict(row) for row in old.REVIEWED_SOURCE_MIGRATIONS]
    positions = [i for i, row in enumerate(rows) if row['path'] == NODE_IMPL]
    require(len(positions) == 1, 'historical node migration is not unique')
    index = positions[0]
    expected_old = {'path': NODE_IMPL, 'qualified_sha256': migration['qualified_sha256'],
                    'postimage_sha256': migration['historical_postimage_sha256'],
                    'scope': migration['scope']}
    require(rows[index] == expected_old and baseline[NODE_IMPL] == migration['qualified_sha256'],
            'historical predecessor/migration tuple differs')
    rows[index]['postimage_sha256'] = migration['postimage_sha256']
    old.REVIEWED_SOURCE_MIGRATIONS = rows
    return old, baseline


def verify_observed_failures(root, failures):
    """Pure policy entrypoint; never runs rustfmt or Cargo."""
    root = Path(root).resolve()
    old, baseline = load_authorized(root)
    old.verify_failures(root, failures, baseline)
    return baseline


def run(root, manifest):
    root = Path(root).resolve()
    old, baseline = load_authorized(root)
    # Preserve the historical subprocess commands and strict output parser. Its
    # run() rereads the original baseline, so compose these existing operations
    # with the already-authenticated map rather than replace its loader.
    version = subprocess.run(['cargo', '+1.91.1', 'fmt', '--version'], cwd=root,
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    require(version.returncode == 0 and not version.stderr
            and version.stdout.strip() == old.RUSTFMT_VERSION,
            'pinned rustfmt implementation differs')
    command = ['cargo', '+1.91.1', 'fmt']
    if MANIFESTS[manifest]:
        command += ['--manifest-path', MANIFESTS[manifest]]
    command += ['--all', '--', '--check', '--color', 'never']
    process = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=180)
    failures = old.parse_failure(root, process.returncode, process.stdout, process.stderr)
    old.verify_failures(root, failures, baseline)
    if manifest == 'workspace':
        # These files are included with include!, which cargo fmt need not
        # traverse. Directly check both and grant no historical debt exception.
        direct = ['rustup', 'run', '1.91.1', 'rustfmt', '--check', '--edition',
                  '2021', '--color', 'never',
                  *(str(root/name) for name in sorted(DIRECT_MODULES))]
        checked = subprocess.run(direct, cwd=root, stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True, timeout=180)
        require(checked.returncode == 0 and not checked.stdout and not checked.stderr,
                'included modules must pass direct pinned rustfmt without formatting debt')
    # Reauthenticate originals and the postimage after subprocess execution too.
    load_authorized(root)
    migrated = sum(hashlib.sha256((root/name).read_bytes()).hexdigest() != baseline[name]
                   for name in failures)
    print(f'Formatting {manifest}: PASS; {len(failures)-migrated} unchanged debt files '
          f'and {migrated} exact reviewed migrations; sync/import successor only')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', choices=MANIFESTS, default='workspace')
    args = parser.parse_args()
    try:
        run(ROOT, args.manifest)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Formatting rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
