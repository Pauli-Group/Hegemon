#!/usr/bin/env python3
"""Check public disposable proofs with an actual release binary, without node state.

This is cryptographic backend verification only. It grants no state admission,
new-network lifecycle, deployment, treasury custody or public-cutover authority.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
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
CASES = ('ordinary', 'policy_create', 'absolute_height', 'policy_hash_release', 'htlc_release')
PROOF_CAP = 171848
PUBLIC_BYTES = 688
RELATION_ID = 'Hegemon.PrivateSpend.BoundedPolicy.CompFF01.Packed.v4'
FIXTURE_SCHEMA = 'hegemon.v011.public-current-proof-fixture.v1'
RECEIPT_SCHEMA = 'hegemon.v011.current-binary-proof-verification.v1'
NEGATIVES = ('changed_statement', 'changed_proof', 'truncated_proof', 'oversize_proof', 'truncated_statement', 'oversize_statement')
ARTIFACT_HELPER_SHA256 = '17137d83d092b98c246b0fd7125bbb2f8ad71aba342fdc4717a071128c4efb6a'
LAUNCHER_POLICY_SHA256 = '51700e93ac457574f262bff05f48e5e55fa328e37da30f665721a312de9d826e'

class CheckError(RuntimeError):
    pass

def require(condition, message):
    if not condition:
        raise CheckError(message)

def regular(path, cap=None):
    """Reject symlink/reparse ancestors of controlled inputs before opening."""
    path = Path(os.path.abspath(path))
    for component in (path, *path.parents):
        info = component.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'symlink/reparse input or ancestor: ' + str(component))
    info = path.stat()
    require(stat.S_ISREG(info.st_mode), 'input is not a regular file: ' + str(path))
    require(cap is None or info.st_size <= cap, 'input exceeds size bound: ' + str(path))
    return path

def sha(path):
    h = hashlib.sha256()
    with regular(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def strict_json(path, cap=1024 * 1024):
    raw = regular(path, cap).read_bytes()
    require(len(raw) <= cap, 'JSON exceeds bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict), 'JSON object required')
    return value

def hex_digest(value, width=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(width) + '}', value) is not None

def file_row(path, name=None):
    path = regular(path)
    return {'path': name or str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}

def check_row(directory, row, expected_name, cap, exact_size=None):
    require(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'}, 'file descriptor keys differ')
    require(row['path'] == expected_name and type(row['bytes']) is int and 0 < row['bytes'] <= cap and hex_digest(row['sha256']), 'file descriptor invalid')
    require(exact_size is None or row['bytes'] == exact_size, 'file descriptor length differs')
    path = regular(directory / expected_name, cap)
    require(path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], 'fixture bytes or hash changed')
    return path

def validate_fixture(path, root=ROOT):
    path = regular(path, 128 * 1024)
    m = strict_json(path, 128 * 1024)
    require(set(m) == {'schema', 'relation_id', 'relation_digest', 'cargo_lock_sha256', 'cases', 'generation_receipt', 'source_inputs', 'disclosure'}, 'fixture manifest keys differ')
    require(m['schema'] == FIXTURE_SCHEMA and m['relation_id'] == RELATION_ID and hex_digest(m['relation_digest'], 128) and hex_digest(m['cargo_lock_sha256']), 'fixture identity invalid')
    require(m['disclosure'] == {'public_only': True, 'fixed_disposable_test_data': True, 'private_witnesses_included': False, 'wallets_or_keys_included': False, 'operator_wallet_opened': False}, 'fixture confidentiality boundary differs')
    rows = m['cases']
    require(isinstance(rows, list) and [r.get('name') for r in rows if isinstance(r, dict)] == list(CASES), 'exact five ordered cases required')
    expected = {'manifest.json', 'generation-receipt.json'}
    files = [path]
    for row in rows:
        require(set(row) == {'name', 'proof', 'statement'}, 'case keys differ')
        name = row['name']
        proof = check_row(path.parent, row['proof'], name + '.proof', PROOF_CAP)
        statement = check_row(path.parent, row['statement'], name + '.statement', PUBLIC_BYTES, PUBLIC_BYTES)
        require(proof.read_bytes()[:4] == b'SMZL', 'wrong proof grammar')
        files.extend((proof, statement)); expected.update((proof.name, statement.name))
    generation = check_row(path.parent, m['generation_receipt'], 'generation-receipt.json', 128 * 1024)
    files.append(generation)
    require({p.name for p in path.parent.iterdir()} == expected, 'unlisted fixture file or missing fixture')
    g = strict_json(generation, 128 * 1024)
    require(g.get('status') == 'PASS' and g.get('relation_digest') == m['relation_digest'] and g.get('cargo_lock_sha256') == m['cargo_lock_sha256'] and g.get('new_network_lifecycle') is False and g.get('production_authority') is False, 'generation boundary differs')
    generated = g.get('retained_disposable_artifact_inventory', [])
    require(isinstance(generated, list) and len(generated) == 10, 'generation inventory incomplete')
    wanted = sorted((r[k]['path'], r[k]['bytes'], r[k]['sha256']) for r in rows for k in ('proof', 'statement'))
    require(sorted((r.get('name'), r.get('bytes'), r.get('sha256')) for r in generated) == wanted, 'generation proof inventory differs')
    require(m['source_inputs'] == g.get('source_inputs') and len(m['source_inputs']) == 41, 'generation source inputs differ')
    source = regular(root / 'circuits/transaction/src/private_spend.rs').read_text()
    includes = re.findall(r'\(\s*"([^"]+)"\s*,\s*include_bytes!\("([^"]+)"\)\s*,?\s*\)', source)
    require(len(includes) == 41 and all(a == b for a, b in includes), 'relation input declaration differs')
    relation = hashlib.sha512(b'Hegemon.PrivateSpend.SourceManifest.v1' + RELATION_ID.encode())
    actual_inputs = []
    for label, relative in includes:
        f = regular(root / 'circuits/transaction/src' / relative, 8 * 1024 * 1024)
        require(f.is_relative_to(root), 'relation input escaped source root')
        data = f.read_bytes(); encoded = label.encode()
        relation.update(len(encoded).to_bytes(8, 'little') + encoded + len(data).to_bytes(8, 'little') + data)
        actual_inputs.append(file_row(f, f.relative_to(root).as_posix())); files.append(f)
    require(actual_inputs == m['source_inputs'] and relation.hexdigest() == m['relation_digest'], 'current source relation/input hashes differ')
    require(sha(root / 'Cargo.lock') == m['cargo_lock_sha256'], 'Cargo.lock differs from public proofs')
    return m, files

def verify_artifacts(node, manifest_path, root=ROOT):
    node = regular(node, 256 * 1024 * 1024)
    manifest_path = regular(manifest_path, 8 * 1024 * 1024)
    m = strict_json(manifest_path, 8 * 1024 * 1024)
    require(m.get('schema_version') == 1 and m.get('cargo_lock_sha256') == sha(root / 'Cargo.lock'), 'artifact manifest identity/lock differs')
    artifacts = m.get('artifacts')
    identities = (('hegemon-node', 'hegemon-node'), ('wallet', 'wallet'), ('walletd', 'walletd'))
    require(isinstance(artifacts, list) and len(artifacts) == 3, 'exact three artifacts required')
    files = [manifest_path]
    specs = []
    for row, identity in zip(artifacts, identities):
        require(isinstance(row, dict) and (row.get('package'), row.get('binary')) == identity, 'artifact identities differ')
        relative = row.get('path')
        require(isinstance(relative, str) and Path(relative).as_posix() == relative and not Path(relative).is_absolute() and all(p not in ('', '.', '..') for p in relative.split('/')), 'artifact path invalid')
        f = regular(root / relative, 256 * 1024 * 1024)
        require(f.is_relative_to(root) and sha(f) == row.get('sha256') and type(row.get('size')) is int and f.stat().st_size == row['size'], 'artifact bytes differ')
        if identity[1] == 'hegemon-node':
            require(f == node, 'provided node is not manifest node')
        files.append(f); specs.append(':'.join((*identity, str(f))))
    module_path = regular(root / 'scripts/release_artifact_manifest.py')
    require(sha(module_path) == ARTIFACT_HELPER_SHA256, 'reviewed artifact manifest helper changed before import')
    launcher_path = regular(root / 'scripts/check_release_launcher_policy.py')
    require(sha(launcher_path) == LAUNCHER_POLICY_SHA256, 'reviewed launcher policy changed before helper import')
    spec = importlib.util.spec_from_file_location('current_binary_artifact_manifest', module_path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    module.verify_manifest(root, manifest_path, specs)
    files.extend((module_path, launcher_path))
    return m, files

class WindowsJob:
    def __init__(self, process):
        import ctypes
        from ctypes import wintypes
        self.ctypes = ctypes
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        for name, args, result in (
            ('CreateJobObjectW', [ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            ('AssignProcessToJobObject', [wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            ('QueryInformationJobObject', [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p], wintypes.BOOL),
            ('TerminateJobObject', [wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            ('CloseHandle', [wintypes.HANDLE], wintypes.BOOL)):
            fn = getattr(self.kernel, name); fn.argtypes = args; fn.restype = result
        self.handle = self.kernel.CreateJobObjectW(None, None)
        require(self.handle, 'cannot create owned job')
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            self.close(); raise CheckError('cannot assign owned job')
    def active(self):
        c = self.ctypes
        class Accounting(c.Structure):
            _fields_ = [(n, c.c_longlong) for n in ('a','b','c','d')] + [(n,c.c_uint32) for n in ('faults','total','active','terminated')]
        v = Accounting(); require(self.kernel.QueryInformationJobObject(self.handle, 1, c.byref(v), c.sizeof(v), None), 'cannot inspect job'); return v.active != 0
    def kill(self):
        require(self.kernel.TerminateJobObject(self.handle, 1), 'cannot kill owned job')
    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle); self.handle = None

def run_command(argv, directory, label, deadline):
    stdout = directory / (label + '.stdout.log'); stderr = directory / (label + '.stderr.log')
    env = {k:v for k,v in os.environ.items() if not k.startswith('HEGEMON_') and k not in ('PQ_IDENTITY_SEED', 'PQ_IDENTITY_SEED_PATH')}
    env.update(HOME=str(directory), USERPROFILE=str(directory), RAYON_NUM_THREADS='2')
    kwargs = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
    process = None; job = None; failed = None
    def active():
        if job: return job.active()
        if os.name == 'nt': return process.poll() is None
        try: os.killpg(process.pid, 0); return True
        except ProcessLookupError: return False
    with stdout.open('xb') as out, stderr.open('xb') as err:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, cwd=directory, env=env, **kwargs)
        try:
            if os.name == 'nt': job = WindowsJob(process)
            while process.poll() is None:
                require(time.monotonic() < deadline, 'offline verifier timeout')
                require(stdout.stat().st_size <= 65536 and stderr.stat().st_size <= 65536, 'offline verifier output exceeds bound')
                time.sleep(0.01)
            process.wait(timeout=5)
            require(not active(), 'offline verifier left descendants')
        except BaseException as error:
            failed = error
        finally:
            if process.poll() is None or active():
                if job: job.kill()
                elif os.name == 'nt': process.kill()
                else:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                process.wait(timeout=5)
            if job: job.close()
        if failed: raise failed
    require(stdout.stat().st_size <= 65536 and stderr.stat().st_size <= 65536, 'offline verifier output exceeds bound')
    return {'exit_code': process.returncode, 'processes_reaped': True, 'argv': argv, 'stdout': file_row(stdout), 'stderr': file_row(stderr)}

def validate_success(output, relation, proof_bytes):
    expected = {'schema':'hegemon.offline-private-spend-verification.v1', 'verified':True, 'scope':'cryptographic-verification-only', 'transaction_or_state_acceptance':False, 'relation_digest':relation, 'proof_bytes':proof_bytes, 'public_bytes':PUBLIC_BYTES}
    require(output == expected and type(output.get('proof_bytes')) is int and type(output.get('public_bytes')) is int and output.get('verified') is True and output.get('transaction_or_state_acceptance') is False, 'offline verifier success output differs')

def validate_rejection(result):
    # Rust anyhow::Result errors exit 1. Panics/signals/Windows NTSTATUS crashes
    # are failed checks, not evidence that invalid inputs were rejected safely.
    require(result['exit_code'] == 1, 'negative input accepted or process crashed')

def snapshot(files):
    return {str(f): file_row(f) for f in files}

def execute(args):
    root = ROOT.resolve()
    fixture_path = regular(args.fixture_manifest)
    fixture, inputs = validate_fixture(fixture_path, root)
    artifact, artifact_files = verify_artifacts(args.node_bin, args.artifact_manifest, root)
    tracked = list(dict.fromkeys([*inputs, *artifact_files, regular(__file__), regular(root / 'node/src/bin/native_node.rs'), regular(root / 'config/testnet/0.11/network-manifest.json')]))
    before = snapshot(tracked)
    output = Path(os.path.abspath(args.output))
    require(not output.exists() and not output.is_symlink(), 'output directory must be new')
    regular_parent = output.parent
    for p in (regular_parent, *regular_parent.parents):
        require(not p.is_symlink() and not (getattr(p.lstat(), 'st_file_attributes', 0) & 0x400) and p.is_dir(), 'output parent must be a real directory')
    reserve = args.min_free_gib * 1024**3
    require(shutil.disk_usage(output.parent).free >= reserve, 'insufficient free disk reserve')
    output.mkdir(mode=0o700)
    deadline = time.monotonic() + args.timeout_seconds
    cases = []
    for row in fixture['cases']:
        require(shutil.disk_usage(output).free >= reserve, 'disk reserve exhausted')
        name = row['name']; proof = fixture_path.parent / row['proof']['path']; statement = fixture_path.parent / row['statement']['path']
        command = [str(args.node_bin), 'verify-private-spend', '--statement', str(statement), '--proof', str(proof)]
        result = run_command(command, output, name, deadline)
        require(result['exit_code'] == 0, 'valid proof rejected: ' + name)
        validate_success(strict_json(output / (name + '.stdout.log'), 65536), fixture['relation_digest'], row['proof']['bytes'])
        controls = {}
        for control in NEGATIVES:
            bad_proof = proof; bad_statement = statement
            if control.endswith('proof'):
                raw = proof.read_bytes()
                raw = raw[:-1] if control == 'truncated_proof' else (raw + bytes(PROOF_CAP + 1 - len(raw)) if control == 'oversize_proof' else raw[:-1] + bytes([raw[-1] ^ 1]))
                bad_proof = output / (name + '-' + control + '.bin'); bad_proof.write_bytes(raw)
            else:
                raw = statement.read_bytes()
                raw = raw[:-1] if control == 'truncated_statement' else (raw + b'\0' if control == 'oversize_statement' else bytes([raw[0] ^ 1]) + raw[1:])
                bad_statement = output / (name + '-' + control + '.bin'); bad_statement.write_bytes(raw)
            argv = [str(args.node_bin), 'verify-private-spend', '--statement', str(bad_statement), '--proof', str(bad_proof)]
            rejected = run_command(argv, output, name + '-' + control, deadline)
            validate_rejection(rejected)
            controls[control] = dict(rejected, rejected=True, proof=file_row(bad_proof), statement=file_row(bad_statement))
        cases.append({'name':name, 'proof':row['proof'], 'statement':row['statement'], 'verified':True, **result, 'negative_controls':controls})
    verify_artifacts(args.node_bin, args.artifact_manifest, root)
    validate_fixture(fixture_path, root)
    after = snapshot(tracked); require(before == after, 'artifact/proof/source inputs changed during verification')
    expected_output = {'receipt.json'}
    for case in cases:
        for run in (case, *case['negative_controls'].values()):
            expected_output.update(Path(run[k]['path']).name for k in ('stdout','stderr'))
        for control in NEGATIVES: expected_output.add(case['name'] + '-' + control + '.bin')
    require({p.name for p in output.iterdir()} == expected_output - {'receipt.json'}, 'offline verifier created unexpected state/files')
    receipt = {'schema':RECEIPT_SCHEMA, 'status':'PASS_CURRENT_BINARY_BACKEND_PROOFS', 'actual_proof_verification':True, 'node_sha256':sha(args.node_bin), 'artifact_manifest_sha256':sha(args.artifact_manifest), 'cargo_lock_sha256':fixture['cargo_lock_sha256'], 'relation_digest':fixture['relation_digest'], 'fixture_manifest_sha256':sha(fixture_path), 'network_manifest_sha256':sha(root / 'config/testnet/0.11/network-manifest.json'), 'offline_cli_source_sha256':sha(root / 'node/src/bin/native_node.rs'), 'target_triple':artifact['target_triple'], 'cases_verified':5, 'cases':cases, 'processes_reaped':True, 'cryptographic_verification_only':True, 'fresh_network_lifecycle_verified':False, 'state_admission_verified':False, 'production_authorized':False, 'public_cutover_authorized':False, 'inputs_before':before, 'inputs_after':after}
    (output / 'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--node-bin', required=True, type=Path); p.add_argument('--artifact-manifest', required=True, type=Path); p.add_argument('--output', required=True, type=Path)
    p.add_argument('--fixture-manifest', type=Path, default=ROOT / 'release-evidence/v0.11-current-proof-fixture/manifest.json')
    p.add_argument('--timeout-seconds', type=int, default=180); p.add_argument('--min-free-gib', type=int, default=4)
    args = p.parse_args()
    try:
        require(args.node_bin.is_absolute() and args.artifact_manifest.is_absolute() and args.output.is_absolute(), 'node/manifest/output paths must be absolute')
        require(1 <= args.timeout_seconds <= 1200 and 4 <= args.min_free_gib <= 1024, 'resource bounds invalid')
        result = execute(args); print(json.dumps(result)); return 0
    except (CheckError,OSError,ValueError,subprocess.SubprocessError) as error:
        print(json.dumps({'schema':RECEIPT_SCHEMA,'status':'FAIL','error':str(error),'actual_proof_verification':False,'production_authorized':False,'public_cutover_authorized':False}), file=sys.stderr); return 1

if __name__ == '__main__':
    raise SystemExit(main())
