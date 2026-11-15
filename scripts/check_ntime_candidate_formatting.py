#!/usr/bin/env python3
"""Pinned rustfmt for v0.11.5, retaining byte-identical predecessor debt only.

The 38 existing debt paths are the complete allowlist. Their permitted bytes
come from the immutable pre-change Git commit, never a changed postimage. This
formatting policy supplies no release, activation, proof or hardware authority.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASELINE_COMMIT = 'ad77c8d564944972b6ae5e7cab26fcf500972aff'


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot load source formatting checker: ' + str(path))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


source = module(ROOT / 'scripts/check_ntime_rolling_source.py', 'ntime_formatting_source')
require = source.require


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    require(result.returncode == 0, 'immutable formatting baseline unavailable or not an ancestor: '
            + result.stderr.decode(errors='replace')[-500:])
    return result.stdout


def policy(root):
    receipt = source.verify_source(root)
    require(receipt.get('scope') == 'source-preparation-only'
            and all(receipt.get(name) is False for name in source.BOUNDARIES),
            'formatting source check cannot grant release or activation authority')
    require(git(root, 'rev-parse', BASELINE_COMMIT + '^{commit}').decode().strip()
            == BASELINE_COMMIT, 'immutable formatting baseline commit differs')
    git(root, 'merge-base', '--is-ancestor', BASELINE_COMMIT, 'HEAD')
    old = module(source.proof_helper.safe_file(root, 'scripts/check_qualified_formatting.py'),
                 'ntime_original_formatting')
    baseline = old.load_baseline(source.proof_helper.safe_file(root, old.BASELINE))
    require(len(baseline) == 38, 'original formatting debt path count differs')
    inherited = {name: hashlib.sha256(git(root, 'show', BASELINE_COMMIT + ':' + name)).hexdigest()
                 for name in baseline}
    # load_baseline above authenticates its original migration tuples. None of
    # those exceptions applies here: a changed inherited file must format cleanly.
    old.REVIEWED_SOURCE_MIGRATIONS = []
    old.VERSION_DISPLAY_MIGRATION = {'path': None, 'qualified_sha256': None,
                                    'postimage_sha256': None}
    return old, inherited


def run(root, manifest):
    old, inherited = policy(root)
    version = subprocess.run(['cargo', '+1.91.1', 'fmt', '--version'], cwd=root,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    require(version.returncode == 0 and not version.stderr
            and version.stdout.strip() == old.RUSTFMT_VERSION, 'pinned rustfmt differs')
    command = ['cargo', '+1.91.1', 'fmt']
    if old.MANIFESTS[manifest]:
        command += ['--manifest-path', old.MANIFESTS[manifest]]
    command += ['--all', '--', '--check', '--color', 'never']
    result = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=180)
    failures = old.parse_failure(root, result.returncode, result.stdout, result.stderr)
    old.verify_failures(root, failures, inherited)
    require(policy(root)[1] == inherited, 'formatting baseline changed during validation')
    print(f'v0.11.5 formatting {manifest}: PASS; {len(failures)} byte-unchanged predecessor debt files; no changed-file exemptions')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', choices=('workspace', 'htlc', 'proof-backend'), default='workspace')
    args = parser.parse_args(argv)
    try:
        run(ROOT, args.manifest)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('v0.11.5 formatting rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
