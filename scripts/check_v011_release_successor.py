#!/usr/bin/env python3
"""Validate exact release-display and platform-shutdown deltas without relabeling G8.

The immutable predecessor checker runs in its own checkout. This validator then
compares all audited runtime bytes, allowing only three exact release-display
postimages and one Windows shutdown-signal postimage. Cargo metadata, dependency
locks and proof-relation source remain byte identical. Artifact mode adds a real
isolated identity smoke, not a replacement
for a new-binary proof/lifecycle qualification or public launch approval.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CONFIG = 'config/v011-release-successor.json'
CHECKER = 'scripts/check_private_spend_launch_authorization.py'
REGISTRY = 'scripts/private_spend_launch_authorized_registry.json'
EXPECTED_CHECKER = '6a0d9d0b6f1864160dd3f07adaa54f142a1ce513584f13d903e07265bee7e112'
EXPECTED_REGISTRY = 'c37455302ad34f631df1938b0ee7980af8bb8a57930ba38c05a6fe86941c145f'
EXPECTED_RUNTIME = 'dfd71b6a265e954261ed209c2ad3c34c97285016557f0f003f7f17f39ff541d0'
UNCHANGED_CARGO_PATHS = ['Cargo.lock', 'node/Cargo.toml', 'wallet/Cargo.toml', 'walletd/Cargo.toml']
OLD_VERSION, NEW_VERSION = '0.10.0', '0.11.0'
DISPATCH = '''    if (ROOT / "config/v011-release-successor.json").is_file():
        command = [sys.executable, "-I", "-B", str(ROOT / "scripts/check_v011_release_successor.py"), *sys.argv[1:]]
        if "--artifact-manifest" in sys.argv[1:]:
            command.append("--require-final-artifact")
        return subprocess.call(command, cwd=ROOT)

'''
# Filled only for a separately reviewed exact platform-shutdown glue change.
SHUTDOWN_DELTA = ('node/src/native/util.rs', 'ccf0764d0059cff43f784171edf58819cabe9645ab2aa1c8f24592beee5e45b1', '51b0333cb00513dc427f4e7cf552f9b3584ffd5133b7ea32b53224ddfed1bea2')
DISPLAY_DELTAS = {
    'protocol/versioning/src/lib.rs': ('150c5018a34fa6d92eba62f070692d10ccb77e477f2257ee6a4045b477c0f5ba', '1b574f0b27635e0d33e42e16763300f2b732cacfe850953fc35f19028a58862d'),
    'node/src/native/rpc.rs': ('0250f8b5548f9e718d1f2b3fb60c39dc0c171fe31615442628c1af274cb8cd8c', '74a599d7234621925bddbc9709ecdab37927b9d7e428eaa38590c428b7a435b0'),
    'wallet/src/bin/wallet.rs': ('df0b673176b10c730285d210f1c9ede4e6ba0b2621118ad63b325c4ffe64b024', '73a50becdd346cedd7ed765c600a3ee70e591ff2fc60564ba6e7d3262ee18f1b'),
}
REVIEWED_RUNTIME_DELTAS = {**DISPLAY_DELTAS, SHUTDOWN_DELTA[0]: SHUTDOWN_DELTA[1:]}
# Exact reviewed consumer postimage is added after its explicit narrow scope fix.
CRYPTO_CONSUMER_DELTA = None

class SuccessorError(RuntimeError):
    pass

def require(value, message):
    if not value:
        raise SuccessorError(message)

def digest_bytes(raw):
    return hashlib.sha256(raw).hexdigest()

def safe_file(root, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(), 'relative file path required')
    parts = Path(relative).parts
    require(all(p not in ('.', '..') for p in parts) and Path(relative).as_posix() == relative, 'noncanonical file path')
    path = root
    for part in parts:
        path = path / part
        require(not path.is_symlink(), 'symlink rejected: ' + relative)
    require(path.is_file(), 'file missing: ' + str(path))
    return path

def load_json(path):
    return json.loads(path.read_text(encoding='utf-8'))

def import_checker(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec and spec.loader, 'cannot load pinned checker')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def validate_runtime_change(relative, before, after):
    if before == after:
        return
    require(relative not in UNCHANGED_CARGO_PATHS, 'Cargo metadata and proof-bound lockfile must remain byte identical: ' + relative)
    expected = REVIEWED_RUNTIME_DELTAS.get(relative)
    require(expected is not None, 'audited runtime/proof source changed: ' + relative)
    require((digest_bytes(before), digest_bytes(after)) == expected, 'exact reviewed runtime postimage differs: ' + relative)

def source_gate(root, predecessor):
    config = load_json(safe_file(root, CONFIG))
    require(config.get('schema') == 'hegemon.release.version-only-successor.v1', 'successor config schema mismatch')
    require(config.get('old_version') == OLD_VERSION and config.get('new_version') == NEW_VERSION, 'successor version mismatch')
    require(config.get('unchanged_cargo_paths') == UNCHANGED_CARGO_PATHS and config.get('internal_cargo_version') == OLD_VERSION, 'Cargo metadata preservation boundary mismatch')
    require(config.get('changed_paths') == sorted(DISPLAY_DELTAS), 'exact release-display allowance mismatch')
    require(config.get('reviewed_display_deltas') == {path: dict(zip(('before_sha256', 'after_sha256'), pair)) for path, pair in DISPLAY_DELTAS.items()}, 'exact release-display postimage bindings missing')
    expected = {CHECKER: EXPECTED_CHECKER, REGISTRY: EXPECTED_REGISTRY}
    require(config.get('immutable_predecessor_sha256') == expected, 'immutable predecessor pins changed')
    for relative, sha in expected.items():
        before = safe_file(predecessor, relative).read_bytes()
        require(digest_bytes(before) == sha, 'immutable predecessor authority differs: ' + relative)
        after = safe_file(root, relative).read_bytes()
        if relative == CHECKER:
            require(before.count(b'def main():\n') == 1, 'ambiguous predecessor main dispatch')
            dispatched = before.replace(b'def main():\n', b'def main():\n'+DISPATCH.encode(), 1)
            require(after in (before, dispatched), 'current checker differs beyond exact successor dispatch')
        else:
            require(after == before, 'historical registry must remain unchanged')
    if CRYPTO_CONSUMER_DELTA is not None:
        relative, old, new = CRYPTO_CONSUMER_DELTA
        require(digest_bytes(safe_file(predecessor, relative).read_bytes()) == old and
                digest_bytes(safe_file(root, relative).read_bytes()) == new,
                'reviewed release consumer bytes differ')
    command = [sys.executable, '-I', '-B', str(predecessor / CHECKER), '--require-authorized']
    result = subprocess.run(command, cwd=predecessor, capture_output=True, timeout=240, check=False)
    require(result.returncode == 0, 'immutable predecessor source gate failed: ' + result.stderr.decode(errors='replace')[-2000:])
    old_receipt = json.loads(result.stdout)
    require(old_receipt.get('authorization_kind') == 'qualified_source_tuple', 'predecessor did not qualify source tuple')
    checker = import_checker(predecessor / CHECKER, '_v011_immutable_predecessor')
    registry = checker.load(checker.path(REGISTRY))
    binding = checker.load(checker.pin(registry['release']['binding'], 'predecessor binding'))
    require(binding['runtime_inventory']['sha256'] == EXPECTED_RUNTIME, 'wrong audited runtime inventory')
    inventory = checker.load(checker.pin(binding['runtime_inventory'], 'predecessor runtime inventory'))
    rows = inventory['files']
    require(len(rows) == 598 and len({r['path'] for r in rows}) == 598, 'exact 598-file audited runtime required')
    # Reject new auto-discovered Rust targets/build scripts as well as changes
    # to the pinned files. Existing proof adapters below .agent are compared by
    # their exact inventory rows rather than scanning unrelated research trees.
    owned_roots = sorted({Path(row['path']).parts[0] for row in rows if len(Path(row['path']).parts) > 1 and not Path(row['path']).parts[0].startswith('.')})
    def build_sources(tree):
        return {p.relative_to(tree).as_posix() for name in owned_roots
                for p in (tree/name).rglob('*')
                if p.is_file() and ('target' not in p.relative_to(tree/name).parts)
                and ((p.suffix == '.rs' and ('src' in p.relative_to(tree/name).parts or p.name == 'build.rs')) or p.name == 'Cargo.toml')}
    require(build_sources(root) == build_sources(predecessor), 'Rust/Cargo source path set differs from predecessor')
    changed = []
    for row in rows:
        before = safe_file(predecessor, row['path']).read_bytes()
        require(len(before) == row['bytes'] and digest_bytes(before) == row['sha256'], 'predecessor runtime file differs: ' + row['path'])
        after = safe_file(root, row['path']).read_bytes()
        if before == after:
            continue
        changed.append(row['path'])
        validate_runtime_change(row['path'], before, after)
    expected_paths = config['changed_paths'] + ([SHUTDOWN_DELTA[0]] if SHUTDOWN_DELTA is not None else [])
    require(sorted(changed) == sorted(expected_paths), 'exact version/shutdown changes required')
    require(config.get('reviewed_shutdown_delta') == dict(zip(('path','before_sha256','after_sha256'), SHUTDOWN_DELTA)), 'exact platform shutdown delta binding missing')
    identity = registry['release']['identity']
    require(identity == config['qualified_identity'], 'qualified rehearsal network identity changed')
    manifest_path = checker.pin(binding['network_manifest'], 'qualified rehearsal manifest')
    manifest = checker.load(manifest_path)
    require(digest_bytes(manifest_path.read_bytes()) == config['network_manifest_sha256'], 'qualified network manifest changed')
    receipt = {'schema':'hegemon.private-spend.release-authorization.v2', 'authorization_kind':'qualified_source_tuple', 'identity':identity, 'deployment_verified':False, 'production_artifacts_verified':False,
        'status':'PASS_VERSION_AND_PLATFORM_SHUTDOWN_SOURCE_SUCCESSOR', 'new_version':NEW_VERSION,
        'predecessor_checker_sha256':EXPECTED_CHECKER, 'predecessor_registry_sha256':EXPECTED_REGISTRY,
        'runtime_inventory_sha256':EXPECTED_RUNTIME, 'runtime_files_compared':len(rows),
        'changed_paths':sorted(changed), 'qualified_identity':identity, 'reviewed_shutdown_delta':config['reviewed_shutdown_delta'], 'proof_and_protocol_runtime_unchanged':True, 'cargo_metadata_unchanged':True, 'reviewed_display_deltas':config['reviewed_display_deltas'],
        'predecessor_source_gate':old_receipt, 'assumptions':old_receipt['assumptions'], 'binding_sha256':old_receipt['binding_sha256'], 'g7_review_sha256':old_receipt['g7_review_sha256'], 'unchanged_evidence_reused':True,
        'predecessor_lifecycle_reexecuted':False, 'affected_lifecycle_verified':False,
        'production_authorized':False, 'public_cutover_authorized':False,
        'fresh_public_genesis_qualified':False,
        'limitations':['This is an exact release-display and platform-shutdown source successor of the qualified rehearsal identity; Cargo metadata is unchanged.',
            'The prior G8 lifecycle executed predecessor binaries, not these rebuilt executables. The exact Windows shutdown glue change is separately recorded.',
            'A fresh public genesis changes network identity and requires separate affected qualification.',
            'Public deployment and legacy testnet shutdown are not authorized by this receipt.']}
    return receipt, manifest

def rpc(port, method, params=None):
    request = urllib.request.Request('http://127.0.0.1:' + str(port), data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params or []}).encode(), headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=3) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    require(len(raw) <= 2 * 1024 * 1024, 'RPC smoke response too large')
    payload = json.loads(raw)
    require('error' not in payload, 'RPC rejected smoke method: ' + method)
    return payload['result']

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def stop_owned(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        raise SuccessorError('owned smoke node required forced termination')

def artifact_gate(root, predecessor, manifest_file, receipt, manifest, min_free_gib):
    checker_path = safe_file(root, 'scripts/release_artifact_manifest.py')
    artifact_bytes = manifest_file.read_bytes()
    artifact_sha = digest_bytes(artifact_bytes)
    artifact = json.loads(artifact_bytes)
    artifacts = artifact.get('artifacts', [])
    expected = [('hegemon-node','hegemon-node'), ('wallet','wallet'), ('walletd','walletd')]
    require([(row.get('package'), row.get('binary')) for row in artifacts] == expected, 'node/wallet/walletd artifact order required')
    command = [sys.executable, '-I', '-B', str(checker_path), 'verify', '--manifest', str(manifest_file)]
    for row in artifacts:
        safe_file(root, row['path'])
        command.extend(['--expect', row['package'] + ':' + row['binary'] + ':' + row['path']])
    checked = subprocess.run(command, cwd=root, capture_output=True, timeout=120, check=False)
    require(checked.returncode == 0, 'current artifact manifest verification failed: ' + checked.stderr.decode(errors='replace')[-2000:])
    require(shutil.disk_usage(root).free >= min_free_gib * 1024**3, 'configured disk reserve required before smoke')
    scratch = Path(tempfile.mkdtemp(prefix='v011-identity-smoke-', dir=root / 'target'))
    os.chmod(scratch, 0o700)
    (scratch/'manifest.json').write_text(json.dumps(manifest))
    environment = {k:v for k,v in os.environ.items() if not k.startswith('HEGEMON_')}
    environment.update(HEGEMON_MINE='0', HEGEMON_SEEDS='', HEGEMON_BOOTSTRAP_AUTHORING='0', RAYON_NUM_THREADS='2', HEGEMON_PQ_IDENTITY_SEED_PATH=str(scratch/'peer.seed'))
    bins = {row['binary']:safe_file(root,row['path']) for row in artifacts}
    version = subprocess.run([str(bins['wallet']), '--version'], capture_output=True, timeout=15, env=environment, check=False)
    require(version.returncode == 0 and version.stdout.decode().strip() == 'wallet ' + NEW_VERSION, 'rebuilt wallet --version mismatch')
    port, rpc_port = free_port(), free_port()
    while rpc_port == port:
        rpc_port = free_port()
    args = [str(bins['hegemon-node']), '--network','pre-mainnet', '--network-manifest', str(scratch/'manifest.json'), '--base-path',str(scratch/'node'), '--listen-addr','127.0.0.1:' + str(port), '--port',str(port), '--rpc-port',str(rpc_port), '--rpc-methods','safe', '--name','v011-release-identity-smoke']
    with (scratch/'node.log').open('xb') as log:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=environment)
    try:
        deadline = time.monotonic() + 90
        while True:
            require(process.poll() is None, 'smoke node exited before RPC became ready')
            try:
                cfg = rpc(rpc_port, 'hegemon_nodeConfig')
                break
            except (OSError, urllib.error.URLError):
                require(time.monotonic() < deadline, 'smoke node RPC startup timeout')
                time.sleep(.2)
        identity = receipt['qualified_identity']
        require(cfg.get('networkProfile') == 'pre-mainnet' and cfg.get('networkManifest') == manifest and cfg.get('chainId') == '0x'+identity['chain_id'] and cfg.get('networkManifestDigest') == '0x'+identity['manifest_digest'], 'new binary network identity readback mismatch')
        require(rpc(rpc_port,'chain_getBlockHash',[0]) == '0x'+identity['genesis_hash'], 'new binary genesis differs')
        require(rpc(rpc_port,'system_version') == 'Hegemon Native Node '+NEW_VERSION, 'new node RPC version differs')
        params = rpc(rpc_port,'hegemon_privateSpendParameters')
        expected_profile = {'relation_id':identity['relation_id'], 'relation_digest':identity['relation_digest'], 'public_words':86, 'max_proof_bytes':171848, 'max_carrier_bytes':177632, 'input_slots':2, 'output_slots':2, 'production_authorized':False}
        require(all(params.get(k) == v for k,v in expected_profile.items()), 'new binary compact proof profile differs')
        header = rpc(rpc_port,'chain_getHeader')
        require(int(header['number'],16) == 0, 'smoke unexpectedly mined/imported blocks')
        health = rpc(rpc_port,'system_health')
        require(health.get('peers') == 0, 'smoke unexpectedly joined peers')
    finally:
        stop_owned(process)
    wrong = dict(manifest, rules_hash='0x'+'00'*32)
    (scratch/'wrong-manifest.json').write_text(json.dumps(wrong))
    wrong_args = list(args)
    wrong_args[wrong_args.index(str(scratch/'manifest.json'))] = str(scratch/'wrong-manifest.json')
    wrong_args[wrong_args.index(str(scratch/'node'))] = str(scratch/'wrong-node')
    rejected = subprocess.run(wrong_args, stdin=subprocess.DEVNULL, capture_output=True, timeout=20, env=environment, check=False)
    require(rejected.returncode != 0 and b'rules_hash' in rejected.stdout + rejected.stderr, 'wrong compiled-rules manifest was not rejected')
    require(digest_bytes(manifest_file.read_bytes()) == artifact_sha, 'artifact manifest changed during identity smoke')
    for row in artifacts:
        require(digest_bytes(safe_file(root, row['path']).read_bytes()) == row['sha256'], 'artifact changed during identity smoke')
    receipt.update(status='PASS_PACKAGING_AND_IDENTITY_SMOKE_ONLY', artifact_manifest_sha256=artifact_sha, target_triple=artifact['target_triple'], artifact_sha256={r['binary']:r['sha256'] for r in artifacts}, identity_smoke={'scratch_directory':str(scratch), 'node_rpc_version':'Hegemon Native Node '+NEW_VERSION, 'wallet_cli_version':version.stdout.decode().strip(), 'walletd_version_cli':'not implemented; artifact hash/source version checked', 'qualified_manifest':True, 'genesis':identity['genesis_hash'], 'proof_parameters':params, 'height':0, 'peers':0, 'wrong_compiled_rules_manifest_rejected':True, 'owned_node_reaped':True}, actual_new_binary_proof_verification=False)
    return receipt

def final_replay(root, artifact, receipt, min_free_gib):
    fixture = safe_file(root, 'release-evidence/v0.11-public-chain-fixture/manifest.json')
    require(digest_bytes(fixture.read_bytes()) == '16ce37d08a3bcfecca0f8dbe4c323f1f319d1da565ea5473d695a5c13c4676c0', 'reviewed public chain fixture changed')
    runner = safe_file(root, 'scripts/check_v011_public_chain_replay.py')
    require(digest_bytes(runner.read_bytes()) == '29c6655f1d8ced3ffa5a042e3c66f0567fc0ef465eda70de473e7a35054159dc', 'reviewed actual proof replay harness changed')
    replay_output = Path(receipt['identity_smoke']['scratch_directory'])/'public-chain-replay'
    node = next(r for r in load_json(artifact)['artifacts'] if r['binary']=='hegemon-node')
    command = [sys.executable, '-I', '-B', str(runner), '--node-bin', str(safe_file(root, node['path'])), '--artifact-manifest', str(artifact), '--output', str(replay_output), '--min-free-gib', str(min_free_gib)]
    result = subprocess.run(command, cwd=root, capture_output=True, timeout=1250, check=False)
    require(result.returncode == 0, 'actual new-binary public proof replay failed: '+result.stderr.decode(errors='replace')[-2500:])
    replay = json.loads(result.stdout)
    validate_replay(replay, receipt['artifact_sha256']['hegemon-node'], receipt['artifact_manifest_sha256'])
    require(digest_bytes(artifact.read_bytes()) == receipt['artifact_manifest_sha256'], 'artifact manifest changed during public proof replay')
    require(digest_bytes(safe_file(root, node['path']).read_bytes()) == receipt['artifact_sha256']['hegemon-node'], 'node artifact changed during public proof replay')
    receipt.update(status='PASS_VERSION_SUCCESSOR_ARTIFACTS_AND_PUBLIC_PROOF_REPLAY',
                   version_only_artifacts_verified=True, actual_new_binary_proof_verification=True,
                   final_artifact_scope='version_and_exact_platform_shutdown_successor_public_proof_replay',
                   public_proof_replay=replay, public_proof_replay_receipt_sha256=digest_bytes((replay_output/'receipt.json').read_bytes()))
    return receipt

def validate_replay(replay, node_sha, artifact_sha):
    expected = {'status':'PASS', 'actual_proof_verification':True,
                'node_sha256':node_sha, 'artifact_manifest_sha256':artifact_sha,
                'fixture_manifest_sha256':'16ce37d08a3bcfecca0f8dbe4c323f1f319d1da565ea5473d695a5c13c4676c0',
                'network_manifest_sha256':'ffda566f04cee22b2a7ba5c2be88f625e9c668f47a7765f36fb377c79ea25758',
                'canonical_blocks_verified':163, 'proof_cases_verified':6,
                'importer_started_at_genesis':True, 'importer_fixture_copied':False,
                'restart_verified':True, 'processes_reaped':True}
    require(isinstance(replay, dict) and all(type(replay.get(k)) is type(v) and replay[k] == v for k,v in expected.items()), 'actual public proof replay scope/identity is incomplete')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-authorized', action='store_true', help='Explicit intent; receipt remains limited to version-only successor.')
    parser.add_argument('--predecessor-root', type=Path, default=ROOT/'target/v011-predecessor')
    parser.add_argument('--artifact-manifest', type=Path)
    parser.add_argument('--require-final-artifact', action='store_true', help='Require actual fresh-node public proof replay using the produced executable; full predecessor lifecycle remains reused.')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--min-free-gib', type=int, default=4, help='Minimum reserve for bounded CI smoke; local operators should select 15 GiB.')
    args = parser.parse_args()
    try:
        require(args.require_authorized, 'explicit --require-authorized intent required')
        require(args.min_free_gib >= 4, 'at least four GiB reserve required')
        require(not args.require_final_artifact or args.artifact_manifest is not None, 'final artifact phase requires an artifact manifest')
        if not args.predecessor_root.exists():
            command = [sys.executable, '-I', '-B', str(safe_file(ROOT, 'scripts/materialize_v011_predecessor.py')), '--destination', str(args.predecessor_root), '--reserve-bytes', str(args.min_free_gib * 1024**3)]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=240, check=False)
            require(result.returncode == 0, 'authenticated predecessor materialization failed: '+result.stderr.decode(errors='replace')[-2000:])
        predecessor = args.predecessor_root.resolve(strict=True)
        require(predecessor != ROOT.resolve(), 'predecessor must be a separate immutable source tree')
        receipt, manifest = source_gate(ROOT, predecessor)
        if args.artifact_manifest:
            artifact = args.artifact_manifest if args.artifact_manifest.is_absolute() else ROOT/args.artifact_manifest
            receipt = artifact_gate(ROOT, predecessor, artifact, receipt, manifest, args.min_free_gib)
        if args.require_final_artifact:
            receipt = final_replay(ROOT, artifact, receipt, args.min_free_gib)
        output = json.dumps(receipt, sort_keys=True, indent=2)+'\n'
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output)
        print(output, end='')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, SuccessorError) as error:
        print('v0.11 version successor rejected: '+str(error), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
