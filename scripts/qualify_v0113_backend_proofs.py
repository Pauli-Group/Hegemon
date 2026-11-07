#!/usr/bin/env python3
"""Verify frozen public proof fixtures with an actual local candidate executable.

This separate runner preserves historical accepted source/fixture pins. It checks
five valid proofs and six mutations each, records per-process elapsed time and
peak RSS where wait4 supports it, and produces backend-only candidate evidence.
It does not grant source/build approval, state admission, or release authority.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BASELINE_CHECKER = 'scripts/check_v011_release_successor.py'
BASELINE_CHECKER_SHA256 = '390f5cbc69e877e29302db4af7b7382bbf6db9bdeccada01942ccba384b0fc67'
CASES = ('ordinary', 'policy_create', 'absolute_height', 'policy_hash_release', 'htlc_release')
CONTROLS = ('changed_statement', 'changed_proof', 'truncated_proof', 'oversize_proof',
            'truncated_statement', 'oversize_statement')
PROOF_CAP = 171848
PUBLIC_BYTES = 688
RELATION_ID = 'Hegemon.PrivateSpend.BoundedPolicy.CompFF01.Packed.v4'
SCHEMA = 'hegemon.v0113.candidate-backend-proof-verification.v1'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def regular(path, cap=None):
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        require(not stat.S_ISLNK(part.lstat().st_mode), 'symlink input/ancestor: ' + str(part))
    info = path.stat()
    require(stat.S_ISREG(info.st_mode), 'regular file required: ' + str(path))
    require(cap is None or info.st_size <= cap, 'input byte bound exceeded: ' + str(path))
    return path


def digest(path):
    h = hashlib.sha256()
    with regular(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def row(path, label=None):
    path = regular(path)
    return {'path': str(path) if label is None else label, 'bytes': path.stat().st_size,
            'sha256': digest(path)}


def read_json(path, cap=1024 * 1024):
    raw = regular(path, cap).read_bytes()
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict), 'JSON object required')
    return value


def write_receipt(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def frozen_constants(root):
    checker = regular(root / BASELINE_CHECKER, 1024 * 1024)
    require(digest(checker) == BASELINE_CHECKER_SHA256, 'immutable baseline checker changed')
    wanted = {'CURRENT_CONFIG_SHA256', 'CURRENT_FIXTURE_SHA256', 'CURRENT_PROOF_CASES', 'CURRENT_CARGO_LOCK_SHA256'}
    constants = {}
    # Read literal constants only: never import or execute the historical checker.
    for node in ast.parse(checker.read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in wanted:
                require(name not in constants, 'ambiguous frozen constant')
                constants[name] = ast.literal_eval(node.value)
    require(set(constants) == wanted, 'frozen source constants incomplete')
    config = regular(root / 'config/v011-release-successor.json', 1024 * 1024)
    require(digest(config) == constants['CURRENT_CONFIG_SHA256'], 'historical successor configuration changed')
    return constants, [checker, config]


def validate_fixture(root):
    constants, tracked = frozen_constants(root)
    fixture_path = regular(root / 'release-evidence/v0.11-current-proof-fixture/manifest.json', 128 * 1024)
    require(digest(fixture_path) == constants['CURRENT_FIXTURE_SHA256'], 'frozen public fixture manifest changed')
    fixture = read_json(fixture_path, 128 * 1024)
    require(fixture['schema'] == 'hegemon.v011.public-current-proof-fixture.v1' and
            fixture['relation_id'] == RELATION_ID, 'fixture identity differs')
    require(fixture['cases'] == constants['CURRENT_PROOF_CASES'] and
            [case['name'] for case in fixture['cases']] == list(CASES), 'frozen five-case rows differ')
    require(fixture['disclosure'] == {'public_only': True, 'fixed_disposable_test_data': True,
            'private_witnesses_included': False, 'wallets_or_keys_included': False,
            'operator_wallet_opened': False}, 'public-only fixture disclosure differs')
    tracked.append(fixture_path)
    expected_files = {'manifest.json', 'generation-receipt.json'}
    for case in fixture['cases']:
        for kind, cap in (('proof', PROOF_CAP), ('statement', PUBLIC_BYTES)):
            descriptor = case[kind]
            name = case['name'] + '.' + kind
            require(descriptor['path'] == name, 'noncanonical fixture name')
            file = regular(fixture_path.parent / name, cap)
            require(row(file, name) == descriptor, 'fixture bytes/hash changed: ' + name)
            require(kind != 'statement' or file.stat().st_size == PUBLIC_BYTES, 'statement size differs')
            require(kind != 'proof' or file.read_bytes()[:4] == b'SMZL', 'proof grammar differs')
            tracked.append(file)
            expected_files.add(name)
    generated = fixture['generation_receipt']
    require(generated['path'] == 'generation-receipt.json', 'generation receipt path changed')
    generation_path = regular(fixture_path.parent / generated['path'], 128 * 1024)
    require(row(generation_path, generated['path']) == generated, 'generation receipt bytes/hash changed')
    generation = read_json(generation_path, 128 * 1024)
    require(generation['status'] == 'PASS' and generation['relation_digest'] == fixture['relation_digest'] and
            generation['cargo_lock_sha256'] == fixture['cargo_lock_sha256'] and
            generation['source_inputs'] == fixture['source_inputs'] and
            generation['production_authority'] is False and generation['new_network_lifecycle'] is False,
            'generation scope/source binding differs')
    tracked.append(generation_path)
    require({p.name for p in fixture_path.parent.iterdir()} == expected_files, 'unexpected/missing public fixture file')
    source = regular(root / 'circuits/transaction/src/private_spend.rs', 1024 * 1024)
    includes = re.findall(r'\(\s*"([^"]+)"\s*,\s*include_bytes!\("([^"]+)"\)\s*,?\s*\)', source.read_text())
    require(len(includes) == 41 and all(label == relative for label, relative in includes), 'relation source declaration changed')
    relation = hashlib.sha512(b'Hegemon.PrivateSpend.SourceManifest.v1' + RELATION_ID.encode())
    actual = []
    for label, relative in includes:
        file = regular(root / 'circuits/transaction/src' / relative, 8 * 1024 * 1024)
        # Resolve lexical '..' from the fixed include declaration, retaining link checks above.
        file = file.resolve(strict=True)
        require(file.is_relative_to(root), 'relation input escaped source root')
        data = file.read_bytes()
        encoded = label.encode()
        relation.update(len(encoded).to_bytes(8, 'little') + encoded + len(data).to_bytes(8, 'little') + data)
        actual.append(row(file, file.relative_to(root).as_posix()))
        tracked.append(file)
    # Cargo.lock itself is a relation source input. Even package-only version
    # edits change its source identity; this runner must never waive that fact.
    require(actual == fixture['source_inputs'] and relation.hexdigest() == fixture['relation_digest'],
            'candidate relation source differs from frozen fixture (Cargo.lock is a direct relation input)')
    require(fixture['cargo_lock_sha256'] == constants['CURRENT_CARGO_LOCK_SHA256'], 'generation lock binding differs')
    return fixture, fixture_path.parent, list(dict.fromkeys(tracked))


def bounded_git(root, arguments):
    result = subprocess.run(['git', '-C', str(root), *arguments], capture_output=True, timeout=20, check=True)
    require(len(result.stdout) <= 16 * 1024 * 1024, 'candidate Git metadata exceeds bound')
    return result.stdout


def run_owned(argv, output, label, deadline, reserve):
    stdout = output / (label + '.stdout.log')
    stderr = output / (label + '.stderr.log')
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('HEGEMON_') and key not in {'PQ_IDENTITY_SEED', 'PQ_IDENTITY_SEED_PATH'}}
    env['RAYON_NUM_THREADS'] = '2'
    started = time.monotonic()
    process = None
    usage = None
    def group_alive():
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False
    with stdout.open('xb') as out, stderr.open('xb') as err:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                   cwd=output, env=env, start_new_session=True)
        try:
            while True:
                require(time.monotonic() < deadline, 'candidate offline verifier deadline exceeded')
                require(shutil.disk_usage(output).free >= reserve, '4 GiB disk reserve reached')
                require(stdout.stat().st_size <= 65536 and stderr.stat().st_size <= 65536, 'verifier diagnostics exceeded 64 KiB')
                if hasattr(os, 'wait4'):
                    pid, status, child_usage = os.wait4(process.pid, os.WNOHANG)
                    if pid:
                        process.returncode = os.waitstatus_to_exitcode(status)
                        usage = child_usage
                        break
                elif process.poll() is not None:
                    break
                time.sleep(0.01)
            require(not group_alive(), 'offline verifier left an owned descendant')
        finally:
            if process.returncode is None or group_alive():
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
    elapsed = time.monotonic() - started
    require(stdout.stat().st_size <= 65536 and stderr.stat().st_size <= 65536, 'final diagnostics exceeded bound')
    rss = None
    if usage is not None and sys.platform in ('darwin', 'linux'):
        rss = int(usage.ru_maxrss) * (1 if sys.platform == 'darwin' else 1024)
    return {'argv': argv, 'pid': process.pid, 'exit_code': process.returncode, 'process_reaped': True,
            'elapsed_seconds': elapsed, 'peak_rss_bytes': rss,
            'rss_method': 'wait4.ru_maxrss' if rss is not None else 'unavailable',
            'rss_scope': 'maximum resident set of this verifier process; excludes parallel workloads',
            'stdout': row(stdout), 'stderr': row(stderr)}


def execute(args):
    root = Path(os.path.abspath(args.source_root))
    require(root.is_dir() and root.resolve() == root, 'canonical source-root directory required')
    node = regular(args.node_bin, 256 * 1024 * 1024)
    output = Path(os.path.abspath(args.output))
    require(not output.exists() and not output.is_symlink(), 'output must be a new directory')
    require(output.parent.is_dir() and output.parent.resolve() == output.parent, 'canonical output parent required')
    reserve = 4 * 1024 ** 3
    require(shutil.disk_usage(output.parent).free >= reserve, '4 GiB disk reserve unavailable')
    output.mkdir(mode=0o700)
    started = time.monotonic()
    deadline = started + args.timeout_seconds
    receipt = {'schema': SCHEMA, 'status': 'RUNNING', 'cryptographic_verification_only': True,
               'source_approval': False, 'build_source_provenance_verified': False, 'release_approved': False,
               'state_admission_verified': False, 'fresh_network_lifecycle_verified': False,
               'production_authorized': False, 'publication_performed': False, 'deployment_performed': False,
               'cases': [], 'limitations': ['fixed disposable synthetic proof statements are not canonical chain state',
                   'candidate executable bytes are measured; source build provenance requires separate build receipt',
                   'elapsed/RSS measurements describe these individual local runs, not a verifier hard cutoff']}
    try:
        fixture, fixture_dir, tracked = validate_fixture(root)
        receipt['candidate_git_head'] = bounded_git(root, ['rev-parse', 'HEAD']).decode().strip()
        receipt['tracked_diff_sha256'] = hashlib.sha256(bounded_git(root, ['diff', '--binary', 'HEAD'])).hexdigest()
        receipt['fixture_generation_lock_sha256'] = fixture['cargo_lock_sha256']
        receipt['candidate_lock_sha256'] = digest(root / 'Cargo.lock')
        receipt['candidate_node'] = row(node)
        receipt['relation_digest'] = fixture['relation_digest']
        receipt['fixture_manifest_sha256'] = digest(fixture_dir / 'manifest.json')
        tracked += [node, regular(__file__), regular(root / 'node/src/bin/native_node.rs'),
                    regular(root / 'config/testnet/0.11/network-manifest.json')]
        if args.build_receipt:
            build_receipt = regular(args.build_receipt, 8 * 1024 * 1024)
            receipt['supplied_build_receipt'] = row(build_receipt)
            tracked.append(build_receipt)
        before = {str(path): row(path) for path in dict.fromkeys(tracked)}
        receipt['inputs_before'] = before
        write_receipt(output / 'receipt.json', receipt)
        for case in fixture['cases']:
            name = case['name']
            proof, statement = (fixture_dir / case[k]['path'] for k in ('proof', 'statement'))
            argv = [str(node), 'verify-private-spend', '--statement', str(statement), '--proof', str(proof)]
            result = run_owned(argv, output, name, deadline, reserve)
            require(result['exit_code'] == 0, 'valid candidate proof rejected: ' + name)
            actual = read_json(output / (name + '.stdout.log'), 65536)
            expected = {'schema': 'hegemon.offline-private-spend-verification.v1', 'verified': True,
                        'scope': 'cryptographic-verification-only', 'transaction_or_state_acceptance': False,
                        'relation_digest': fixture['relation_digest'], 'proof_bytes': case['proof']['bytes'],
                        'public_bytes': PUBLIC_BYTES}
            require(actual == expected and actual['verified'] is True and actual['transaction_or_state_acceptance'] is False,
                    'candidate verifier success output differs: ' + name)
            item = {'name': name, 'verified': True, 'proof': case['proof'], 'statement': case['statement'],
                    'positive': result, 'negative_controls': {}}
            receipt['cases'].append(item)
            for control in CONTROLS:
                bad_proof, bad_statement = proof, statement
                if control.endswith('proof'):
                    raw = proof.read_bytes()
                    changed = raw[:-1] if control == 'truncated_proof' else (
                        raw + bytes(PROOF_CAP + 1 - len(raw)) if control == 'oversize_proof' else
                        raw[:-1] + bytes([raw[-1] ^ 1]))
                    bad_proof = output / (name + '-' + control + '.bin')
                    bad_proof.write_bytes(changed)
                else:
                    raw = statement.read_bytes()
                    changed = raw[:-1] if control == 'truncated_statement' else (
                        raw + b'\0' if control == 'oversize_statement' else bytes([raw[0] ^ 1]) + raw[1:])
                    bad_statement = output / (name + '-' + control + '.bin')
                    bad_statement.write_bytes(changed)
                argv = [str(node), 'verify-private-spend', '--statement', str(bad_statement), '--proof', str(bad_proof)]
                rejected = run_owned(argv, output, name + '-' + control, deadline, reserve)
                require(rejected['exit_code'] == 1, 'invalid input accepted or process crashed: ' + name + '/' + control)
                require(Path(rejected['stdout']['path']).read_bytes().strip() == b'', 'rejection printed unexpected success output')
                require(Path(rejected['stderr']['path']).stat().st_size > 0, 'rejection omitted its error diagnostic')
                item['negative_controls'][control] = {'rejected': True, **rejected,
                                                     'proof': row(bad_proof), 'statement': row(bad_statement)}
            write_receipt(output / 'receipt.json', receipt)
            print('verified ' + name + ' and six negative controls', flush=True)
        validate_fixture(root)
        after = {str(path): row(path) for path in dict.fromkeys(tracked)}
        require(after == before, 'candidate/fixture/source bytes changed during verification')
        receipt.update(inputs_after=after, status='PASS_CANDIDATE_BACKEND_PROOFS', cases_verified=5,
                       negative_controls_verified=30, actual_candidate_proof_verification=True,
                       all_owned_processes_reaped=True)
    except BaseException as error:
        receipt.update(status='NON_PASS', error=str(error)[:1000])
        raise
    finally:
        receipt['elapsed_seconds'] = time.monotonic() - started
        write_receipt(output / 'receipt.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--node-bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build-receipt', type=Path, help='optional hashed external candidate provenance record; not auto-approved')
    parser.add_argument('--timeout-seconds', type=int, default=180)
    args = parser.parse_args()
    try:
        require(os.name == 'posix', 'this bounded local runner supports POSIX process groups only')
        require(1 <= args.timeout_seconds <= 1200, 'timeout must be 1..1200 seconds')
        def interrupted(signum, frame):
            raise RuntimeError('interrupted by signal ' + str(signum))
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        receipt = execute(args)
        print(json.dumps({'status': receipt['status'], 'cases_verified': 5, 'negative_controls_verified': 30,
                          'receipt': str(args.output / 'receipt.json')}))
        return 0
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('candidate backend qualification failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
