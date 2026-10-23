#!/usr/bin/env python3
"""Check pinned rustfmt with exact predecessor debt and one version-label migration.

The RPC exception requires precisely two reviewed product-version replacements;
all other source changes must pass formatting, including formerly qualified files.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASELINE = 'config/qualified-formatting-baseline.json'
BASELINE_SHA256 = '826171a810b5e54ee3ce9fcfaa2b67fb04b07853726d79081e6efef7c0e30bbe'
RUSTFMT_VERSION = 'rustfmt 1.8.0-stable (ed61e7d7e2 2025-11-07)'
# Exact product-version labels only; no proof or protocol source waiver.
VERSION_DISPLAY_MIGRATION = {'path': 'node/src/native/rpc.rs', 'qualified_sha256': '0250f8b5548f9e718d1f2b3fb60c39dc0c171fe31615442628c1af274cb8cd8c', 'postimage_sha256': '74a599d7234621925bddbc9709ecdab37927b9d7e428eaa38590c428b7a435b0', 'old': 'env!("CARGO_PKG_VERSION")', 'new': 'protocol_versioning::RELEASE_VERSION', 'replacement_count': 2}
MANIFESTS = {'workspace': None, 'htlc': 'experimental/htlc-prototype/Cargo.toml',
             'proof-backend': 'experimental/htlc-prototype/proof-backend/Cargo.toml'}

class Rejected(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise Rejected(message)

def duplicate_free(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate baseline key')
        value[key] = item
    return value

def load_baseline(path, expected_hash=BASELINE_SHA256):
    require(path.is_file() and not path.is_symlink(), 'missing or linked formatting baseline')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_hash, 'formatting baseline source pin differs')
    data = json.loads(raw, object_pairs_hook=duplicate_free)
    require(set(data) == {'schema', 'toolchain', 'rustfmt_version', 'scope', 'files', 'version_display_migrations'}, 'baseline schema keys differ')
    require(data['schema'] == 'hegemon.qualified-formatting-debt.v1' and data['toolchain'] == '1.91.1'
            and data['rustfmt_version'] == RUSTFMT_VERSION, 'baseline identity differs')
    require(data['scope'] == 'qualified-predecessor-and-exact-version-display-only', 'baseline scope differs')
    require(isinstance(data['files'], list) and 0 < len(data['files']) <= 1000, 'invalid baseline file set')
    require(data['version_display_migrations'] == [VERSION_DISPLAY_MIGRATION], 'version-display migration tuple differs')
    result = {}
    for row in data['files']:
        require(isinstance(row, dict) and set(row) == {'path', 'qualified_sha256', 'current_sha256'}, 'baseline row differs')
        name = row['path']
        require(isinstance(name, str), 'baseline path must be text')
        p = PurePosixPath(name)
        require(p.as_posix() == name and not p.is_absolute()
                and '..' not in p.parts and '\\' not in name and name.endswith('.rs'), 'noncanonical Rust path')
        value = row['qualified_sha256']
        require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
                and row['current_sha256'] == value, 'baseline must preserve identical predecessor bytes')
        require(name not in result, 'duplicate baseline file')
        result[name] = value
    require(list(result) == sorted(result), 'baseline paths must be sorted')
    return result

def parse_failure(root, returncode, stdout, stderr):
    require(not stderr, 'rustfmt diagnostics are not formatting debt: ' + stderr[:1500])
    if returncode == 0:
        require(not stdout, 'unexpected rustfmt success output')
        return set()
    require(returncode == 1, 'rustfmt failed outside its formatting-check result')
    require(len(stdout) <= 16 * 1024**2, 'rustfmt output exceeds cap')
    found = set(); active = False
    for line in stdout.splitlines():
        match = re.fullmatch(r'Diff in (.+):([1-9][0-9]*):', line)
        if match:
            file = Path(match[1])
            require(file.is_absolute(), 'rustfmt path must be absolute')
            try:
                relative = file.relative_to(root).as_posix()
            except ValueError as error:
                raise Rejected('rustfmt path escapes checkout') from error
            require(file.resolve() == file and file.is_file() and not file.is_symlink(), 'rustfmt path must be a canonical regular file')
            require(relative.endswith('.rs'), 'unexpected non-Rust formatting failure')
            found.add(relative); active = True
        else:
            require(active and (not line or line[0] in ' +-'), 'unrecognized rustfmt output: ' + line[:200])
    require(found, 'rustfmt failure lacks file-specific differences')
    return found

def verify_failures(root, failures, baseline):
    for name in sorted(failures):
        require(name in baseline, 'new formatting debt is not allowed: ' + name)
        file = root / name
        require(file.is_file() and not file.is_symlink(), 'formatting source missing or linked: ' + name)
        current = file.read_bytes()
        if hashlib.sha256(current).hexdigest() == baseline[name]:
            continue
        migration = VERSION_DISPLAY_MIGRATION
        require(name == migration['path'] and baseline[name] == migration['qualified_sha256']
                and hashlib.sha256(current).hexdigest() == migration['postimage_sha256'],
                'changed file must pass formatting: ' + name)
        before, after = migration['old'].encode(), migration['new'].encode()
        require(current.count(after) == migration['replacement_count'] and before not in current,
                'version-display replacement count differs')
        reconstructed = current.replace(after, before)
        require(hashlib.sha256(reconstructed).hexdigest() == migration['qualified_sha256'],
                'version-display migration changed unrelated source')

def run(root, manifest):
    baseline = load_baseline(root / BASELINE)
    version = subprocess.run(['cargo', '+1.91.1', 'fmt', '--version'], cwd=root,
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    require(version.returncode == 0 and not version.stderr and version.stdout.strip() == RUSTFMT_VERSION,
            'pinned rustfmt implementation differs')
    command = ['cargo', '+1.91.1', 'fmt']
    if MANIFESTS[manifest]:
        command += ['--manifest-path', MANIFESTS[manifest]]
    command += ['--all', '--', '--check', '--color', 'never']
    process = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=180)
    failures = parse_failure(root, process.returncode, process.stdout, process.stderr)
    verify_failures(root, failures, baseline)
    migrated = sum(hashlib.sha256((root/name).read_bytes()).hexdigest() != baseline[name] for name in failures)
    print(f'Formatting {manifest}: PASS; debt retained for {len(failures)-migrated} byte-unchanged predecessor files and {migrated} exact version-label migration')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', choices=MANIFESTS, default='workspace')
    args = parser.parse_args()
    try:
        run(ROOT, args.manifest)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('Formatting rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
