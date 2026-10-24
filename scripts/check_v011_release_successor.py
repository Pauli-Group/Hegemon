#!/usr/bin/env python3
"""Check exact reviewed v0.11 source and final binary scopes without relabeling G8.

Legacy mode retains its exact version/platform changes and public-chain replay.
Current-source mode compares all 598 authenticated predecessor runtime files and
only exact reviewed additions/postimages, including the four lockfile updates
and fresh identity arrays. Its distinct source-only receipt is not full-network
lifecycle authorization. Final current mode executes the actual rebuilt node's
cryptographic backend against five frozen public proof/statement pairs, cleanly
rejects six invalid-input controls per pair, and checks isolated height-zero
identity on that same executable. Historical G8/PR205 evidence stays conditional
and historical; fresh-network G8, state admission, launch and cutover remain false.
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
        if any(arg == "--artifact-manifest" or arg.startswith("--artifact-manifest=") for arg in sys.argv[1:]):
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
    if receipt.get('authorization_kind') == CURRENT_SOURCE_KIND:
        require(digest_bytes(checker_path.read_bytes()) == CURRENT_ARTIFACT_HELPER_SHA256, 'current artifact-manifest helper differs before execution')
        require(digest_bytes(safe_file(root, 'scripts/check_release_launcher_policy.py').read_bytes()) == CURRENT_LAUNCHER_POLICY_SHA256, 'current launcher-policy helper differs before execution')
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
        identity = receipt['identity'] if receipt.get('authorization_kind') == CURRENT_SOURCE_KIND else receipt['qualified_identity']
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

# Exact current-source mode. Its distinct authorization kind deliberately cannot
# satisfy the maintained full-network lifecycle harness's qualified_source_tuple.
CURRENT_SCOPE = 'exact_current_source_current_binary_backend_and_h0'
CURRENT_SOURCE_KIND = 'reviewed_source_successor_ci'
CURRENT_CONFIG_SHA256 = 'fb40d7e77941cb047382cb6c0146caee9be0da3bce7c0935e67a49b969e06538'
CURRENT_RUNNER_SHA256 = '2d66821c28cb2c057878c86725ff5be6ad337f763d45b5c7ecbf6bcb08a0d06b'
CURRENT_FIXTURE_SHA256 = '50a1c137b7d8d7d03181b7b9e1d353d98cfd26e708e178c75dd7925dff271a8c'
CURRENT_NETWORK_MANIFEST_SHA256 = '386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754'
CURRENT_ARTIFACT_HELPER_SHA256 = 'a429626f609f9f447057a6e362cf53d3e1b42a0c14a6b83c876d6b0faf3feffc'
CURRENT_LAUNCHER_POLICY_SHA256 = '51700e93ac457574f262bff05f48e5e55fa328e37da30f665721a312de9d826e'
CURRENT_CARGO_LOCK_SHA256 = '1c243bf3858f4ee22fa4441c7a2ee6d49b16d264147b0f3a2de845e760821719'
CURRENT_PROOF_CASES = [{'name': 'ordinary',
  'proof': {'bytes': 171281,
            'path': 'ordinary.proof',
            'sha256': 'cbe2dfd00a95c432eb43626d3acf7c31a442cd3db111e4b58db60a0fe4f412f3'},
  'statement': {'bytes': 688,
                'path': 'ordinary.statement',
                'sha256': '07bf3c7ae29cfa21b2654731835e34af244c370e069e6ef1896cde1c8094de80'}},
 {'name': 'policy_create',
  'proof': {'bytes': 171281,
            'path': 'policy_create.proof',
            'sha256': 'd0bb5a49bdb14e252e1658e9cb03abf52f221ace394caf07080a543e939a735c'},
  'statement': {'bytes': 688,
                'path': 'policy_create.statement',
                'sha256': 'cae926d92fc29f4308c9140e218b2e19f78757423cb73489f81a090074f9a3f5'}},
 {'name': 'absolute_height',
  'proof': {'bytes': 171281,
            'path': 'absolute_height.proof',
            'sha256': 'd42fad512039ff1ed2683e52b41e767475d091bb0c70a4e747efef0809b1b992'},
  'statement': {'bytes': 688,
                'path': 'absolute_height.statement',
                'sha256': '66bbd965bf5c9a55c97cd9783dc327fa4c075484e2db22af7ab31cd2d5bc13b0'}},
 {'name': 'policy_hash_release',
  'proof': {'bytes': 171281,
            'path': 'policy_hash_release.proof',
            'sha256': '1c2d063506eab8d528864858a070684318d0e7b096265d701b30ca75a1279687'},
  'statement': {'bytes': 688,
                'path': 'policy_hash_release.statement',
                'sha256': 'd28560ebe0a98fc6cd028bb8e630b4c5af3ba1aa79f814d744aa6a8beb57b06c'}},
 {'name': 'htlc_release',
  'proof': {'bytes': 171281,
            'path': 'htlc_release.proof',
            'sha256': '1b25fc4e5897f43bd59bd91b506837bc90667bb2f7298d6ccb0c2a223a4dffb6'},
  'statement': {'bytes': 688,
                'path': 'htlc_release.statement',
                'sha256': 'c6267fdc99026543872cacf34f9ba52670c34c0523d95a60da49e4c8e1f6ba29'}}]
CURRENT_RUNTIME_DELTAS = {'Cargo.lock': ['bae447660a12610766620cb7e2afacb6b0ad92a3370dd5f15db18e12e753b7ec',
                '1c243bf3858f4ee22fa4441c7a2ee6d49b16d264147b0f3a2de845e760821719'],
 'circuits/transaction/src/asset_recovery_chacha_v1.rs': ['523246cbd6a5440eddb5d62a09877bee29adac45fd7f01f8e996cfa9b386c284',
                                                          'd9d051780a338cacf43fefb3ab3ba39d050fa921b4b0559094ed456d09d8f719'],
 'circuits/transaction/src/asset_recovery_geometry_v1.rs': ['912d6469374a9a3c9e8805c3374e26dbdbda67b7534e6799f169aa30173c040a',
                                                            '03de9a894015dac1e594c8e632beb025cb593b7b26c036f91cadf5469ee14807'],
 'circuits/transaction/src/asset_spend_v1/tests.rs': ['5fdcf939036b882ec1b4748498a1bd1e0233da3ec3dadadc007cd91fba1d8aff',
                                                      '5b1b01c2ee7f91a9538096e7b5f592e1246d3cfe7505e717cef2a66603996124'],
 'circuits/transaction/src/asset_spend_v1_admission.rs': ['e19ee867f5af10cc8234fa2384f11a5a9dc74703bc1760b39281d6a40877b530',
                                                          '8d68021e52f56a00dd936987f5ce251defe977c80ddd9ae37600fda95aac556f'],
 'circuits/transaction/src/asset_spend_v1_state.rs': ['1006ed280fe8a16f8afb61934749c8fe8f4ffa0b5ebaed86b5a10315453b481b',
                                                      '27ff1a411a849d3f0b71b37422f9984facf447f48fe390c962da604c5bcb1b52'],
 'circuits/transaction/src/asset_spend_v1_wire.rs': ['f72252f8c8e3297c115b745bde7130a3af47c011b21b46b2d04344fcac042d3d',
                                                     '81d11e1a46de076d2501a90d1f91bfafa8ff14047c9d2e9292cf6047a52f22a2'],
 'circuits/transaction/src/smallwood_htlc/source_cse.rs': ['9401f9f6a8ea5ac6b1884af0c24c7fd910c3a1452664be5b504b5377dae3825d',
                                                           '9e573c5a8579a516f9cff092abdce06a7a04a49f212fccc14138b088b20f0be6'],
 'circuits/transaction/src/smallwood_htlc_transport.rs': ['4df08a64e1bc8e25c62bc479747730a0f585e6d0233eaac65618ce3bec1694be',
                                                          '0e157cb668ec2602a5ae96cf81269697d5cd3396ab615709fc3f26441f63da26'],
 'config/poseidon2-width16-v1.json': ['b213f05b7db08a26693e4663477ab200d3201b3d3eab2e1dc7635e272ffdddfa',
                                      '43b3c90bfcc1cf4b040e036ce7c32e17b637fd136f59dda0df149da91a0ab9bb'],
 'experimental/htlc-prototype/proof-backend/Cargo.lock': ['03c7da68475157c7dd05a6fbfd8515c56a8b4062c1175e52030b0a41d2e35dfe',
                                                          'ed8d205e44df98040490e7d3270d9ffbbfe242f1b5e5b9460ffbc238d3b72a0b'],
 'network/src/lib.rs': ['d930d38df3cb5c09684e7196d60d1f4b4e3b17caff36e98fc0e03267566b9682',
                        'a3776bf15654a5a3e7c2acc3e29acde25de0f157d8c534b191414e5be2a6ef3f'],
 'node/src/bin/native_node.rs': ['236cfb18659ba1ad624f3c2f25f03bc45601221ff19f586c83094ddadff8ac96',
                                 '1b8382135f934f82191357d4e783f81779885bf51499ea5cd6a96229fdb3ff41'],
 'node/src/native/admission.rs': ['9f9e66d240facd9bd74b24d579734b41ea940154cb2722f14f3bb963e96dd0c1',
                                  'e73b8e689db6b9ed5fe0a27f8e31826bb78337a4a1116cd6030c737319250fba'],
 'node/src/native/asset_native.rs': ['c59fcce5b265862a41903cdf7f6350950fb48c1fc553adaaf33836ae1856da29',
                                     'd739f5060d6b481d5fdd383ab072e7f25633f0848cc1e5170afb0a608cac927b'],
 'node/src/native/asset_recovery_geometry_catalog.rs': ['89508735bc98d26066d4f754407080e0866048b49af44c6181dcdf0e1c46d50f',
                                                        '979f6cee7b45d058f7a04e1c96316bd2b08d7ed740e9eef3242200fa7fb97188'],
 'node/src/native/asset_recovery_lifecycle_tests.rs': ['62cf4bec53d619556bc07a6cf0f66fc36d81130873b122bf88c2bff0353e8415',
                                                       'e2e83d99062b5940a872b672e8d7e7564f45141005b8e5594277ff6d5b8d6950'],
 'node/src/native/asset_recovery_profile.rs': ['308e45158b51e648a4eed81984cd9fd40359861d29bfa8c2109ae0a346bac210',
                                               'a030e331cbe317700eb605757734d37676e689b2b5a4f774a5dea8bc716ea389'],
 'node/src/native/asset_state.rs': ['ac98af4f5f6c13a65a4d2d90a7183121fc5f99d018d9e1a57d24c080f9fd59c9',
                                    'aae89923687a2bd8e296f0bc2aaf4014e98895f2cfea0d9cf61eb34c8db9db56'],
 'node/src/native/block_flow.rs': ['cc650ad4fd11d582c78382d1de2cf27289310ccc5719393dd5df6d750e7bdb95',
                                   '70c59140f1f51d09383276d7c2eabd0b0c4b990109c6403dffcef84e61fb96d8'],
 'node/src/native/mod.rs': ['6be69238c26189dd48d921a5a9c8b2aa2a9057af05060ba62edd9f7d8234bfa9',
                            '60496dc754362a21286d247a55fe76fae197aa7b5611251aaca041c182cac973'],
 'node/src/native/network_profile.rs': ['d1f5276aa03bd5f591a8fcb185761ca2edc26515b60ee1104f94127c9db33a7c',
                                        'c90231a2c84bd18dca45c8b35aee568fd4f65e37b8807e54aa57f47f2e60479c'],
 'node/src/native/node_impl.rs': ['05f84c22738c43c937201470a27649a3d73e4b8ce9dfbc87c7d6e95abd462e3c',
                                  'e6efec45d1a9d3b4c5dee02f1a9d0f38d300a755c711d29ff0120b49a7ec5d00'],
 'node/src/native/poseidon2_v8_pending.rs': ['95b7f63283c59cdf41f82485401afc9941e0a214bbc5538f51e5ae0363e393de',
                                             '8bbed7840590250121db5fa8ff26800d8f2f7af5d27debf2f2ee6f9559dcd07b'],
 'node/src/native/poseidon2_v8_state.rs': ['ae74b57b66c3fb1a0968767197eda87f4ebb23fbfcd3e3a1a74552e0ed85f838',
                                           'eb65fc931e8623dc48751c54df47f096589aa65906889a59b4f4ec4bcdbc942c'],
 'node/src/native/rpc.rs': ['0250f8b5548f9e718d1f2b3fb60c39dc0c171fe31615442628c1af274cb8cd8c',
                            '74a599d7234621925bddbc9709ecdab37927b9d7e428eaa38590c428b7a435b0'],
 'node/src/native/tests.rs': ['9ce2b15b592f82403f451f9fc76974c98cc7bdf74f6c421c7bf91228bc1b0e31',
                              '98b490c43e2538c38c73a2ba5636cd5f23287d5e352c51e271bc3c73a3e2cdd1'],
 'node/src/native/util.rs': ['ccf0764d0059cff43f784171edf58819cabe9645ab2aa1c8f24592beee5e45b1',
                             '51b0333cb00513dc427f4e7cf552f9b3584ffd5133b7ea32b53224ddfed1bea2'],
 'protocol/versioning/src/launch_candidate.rs': ['2ce83547371d7f0904dfc318286e3ae0a17f3776f415518f49c0e22627913539',
                                                 'fab9c38631d069c2e778cf362f3fb63d02b4f29abe7cb20b8253364c24405107'],
 'protocol/versioning/src/lib.rs': ['150c5018a34fa6d92eba62f070692d10ccb77e477f2257ee6a4045b477c0f5ba',
                                    '1b574f0b27635e0d33e42e16763300f2b732cacfe850953fc35f19028a58862d'],
 'scripts/check_transaction_proof_successor_authorization.py': ['e01c8dfd9f8bd256c2b7de065986bf46b78d773e62017601a64937127ffba821',
                                                                'e392df3a774e3e3ab6a1bff1e76b247d4c77be413d85cb37e3ac668a521ed163'],
 'scripts/hegemon_formal_core/src/lib.rs': ['33c1c47853fa7746d5f351db4e16b684590f2e6be568de6b9578e8fd9aa1bf1d',
                                            '4987f1a5634898eae53bcc0103af21e48b775546884af84488399923b87773d3'],
 'wallet/src/bin/wallet.rs': ['df0b673176b10c730285d210f1c9ede4e6ba0b2621118ad63b325c4ffe64b024',
                              '73a50becdd346cedd7ed765c600a3ee70e591ff2fc60564ba6e7d3262ee18f1b'],
 'wallet/src/htlc_prepare.rs': ['54c2df105428a8b45074b0f92f10c16752d20324a0660ade670dc472fb242515',
                                '3e1e1e588e38a8f8b38b646ac4da1c0a7270d629bb1d5df74cfe20b508da9856'],
 'wallet/src/htlc_store.rs': ['032030a1854beca9e395a04ada301bf7893442be6ef5e565b17e5b479353cd95',
                              '20de39f484fd2010f6081529602d1d8158d75e2a020924727a9ab87d06d2f53e'],
 'wallet/src/poseidon2_v8_coinbase.rs': ['a4170caf6fa9dbd47e8dcf8dd4f82bec28a322f316f6d9f32d913d282150dde1',
                                         '96078b0fbb7a945facf76c8e6fd8ef80d83d109ad62138dea7dc25884aed2dc5'],
 'wallet/src/poseidon2_v8_multisig.rs': ['34c134fa553343eab2c5134bea48400e84ff9410fdeb933e9eebb122bd4634ca',
                                         '6ce0854abce3ddba79ee80e26889d6f807f55d06fcdb9790c992f9260edf7e71'],
 'wallet/src/rp06_transfer.rs': ['106f407bca70b1667e39e66ceff19fd8f023ee0bfbd976040df075d160b19203',
                                 'd01dc7029703d08a404b87fd297cae3813708737e6c8a9838ee17d94436f72e3']}
CURRENT_SOURCE_ADDITIONS = {'node/src/native/asset_recovery_profile/geometry_catalog.rs': {'bytes': 41029,
                                                                'sha256': '31175e46be0807ee25880070780417e0a6e26e6ba613a57ed5254449dec7ea6f'}}
CURRENT_CASE_NAMES = ['ordinary', 'policy_create', 'absolute_height', 'policy_hash_release', 'htlc_release']
CURRENT_NEGATIVE_NAMES = ['changed_statement', 'changed_proof', 'truncated_proof', 'oversize_proof', 'truncated_statement', 'oversize_statement']

legacy_source_gate = source_gate
legacy_final_replay = final_replay

def validate_current_runtime_change(relative, before, after):
    if before == after:
        return
    expected = CURRENT_RUNTIME_DELTAS.get(relative)
    require(expected is not None and (digest_bytes(before), digest_bytes(after)) == tuple(expected),
            'current source differs beyond exact reviewed postimage: ' + relative)

def current_source_gate(root, predecessor):
    raw_config = safe_file(root, CONFIG).read_bytes()
    require(digest_bytes(raw_config) == CURRENT_CONFIG_SHA256, 'reviewed current successor configuration differs or is not frozen')
    config = json.loads(raw_config)
    require(config['schema'] == 'hegemon.release.exact-source-successor.v2', 'current source schema differs')
    require(config['new_version'] == NEW_VERSION and config['internal_cargo_version'] == OLD_VERSION, 'current release version boundary differs')
    require(config['reviewed_runtime_deltas'] == {p:dict(zip(('before_sha256','after_sha256'), pair)) for p,pair in CURRENT_RUNTIME_DELTAS.items()}, 'current exact delta configuration differs')
    require(config['reviewed_source_additions'] == CURRENT_SOURCE_ADDITIONS, 'current exact source additions differ')
    for relative, sha in ((CHECKER, EXPECTED_CHECKER), (REGISTRY, EXPECTED_REGISTRY)):
        before = safe_file(predecessor, relative).read_bytes()
        require(digest_bytes(before) == sha, 'immutable predecessor authority differs: ' + relative)
        after = safe_file(root, relative).read_bytes()
        if relative == CHECKER:
            require(before.count(b'def main():\n') == 1, 'ambiguous predecessor main dispatch')
            require(after == before.replace(b'def main():\n', b'def main():\n'+DISPATCH.encode(), 1), 'current checker differs beyond approved successor dispatch')
        else:
            require(after == before, 'historical registry must remain byte identical')
    require(digest_bytes(safe_file(root, 'scripts/release_artifact_manifest.py').read_bytes()) == CURRENT_ARTIFACT_HELPER_SHA256, 'current artifact-manifest helper differs')
    require(digest_bytes(safe_file(root, 'scripts/check_release_launcher_policy.py').read_bytes()) == CURRENT_LAUNCHER_POLICY_SHA256, 'current launcher-policy helper differs')
    command = [sys.executable, '-I', '-B', str(predecessor / CHECKER), '--require-authorized']
    result = subprocess.run(command, cwd=predecessor, capture_output=True, timeout=240, check=False)
    require(result.returncode == 0 and not result.stderr, 'immutable predecessor source gate failed')
    old_receipt = json.loads(result.stdout)
    require(old_receipt.get('authorization_kind') == 'qualified_source_tuple', 'predecessor did not qualify source tuple')
    checker = import_checker(predecessor / CHECKER, '_v011_exact_immutable_predecessor')
    registry = checker.load(checker.path(REGISTRY))
    require(registry['release']['identity'] == config['predecessor_identity'], 'historical qualified identity differs')
    binding = checker.load(checker.pin(registry['release']['binding'], 'predecessor binding'))
    require(binding['runtime_inventory']['sha256'] == EXPECTED_RUNTIME, 'wrong predecessor runtime inventory')
    rows = checker.load(checker.pin(binding['runtime_inventory'], 'predecessor runtime inventory'))['files']
    require(len(rows) == 598 and len({r['path'] for r in rows}) == 598, 'exact 598-file predecessor inventory required')
    roots = sorted({Path(r['path']).parts[0] for r in rows if len(Path(r['path']).parts)>1 and not r['path'].startswith('.')})
    def build_sources(tree):
        paths = set()
        for name in roots:
            for p in (tree/name).rglob('*'):
                rel = p.relative_to(tree/name)
                if 'target' in rel.parts:
                    continue
                if (p.suffix == '.rs' and ('src' in rel.parts or p.name == 'build.rs')) or p.name == 'Cargo.toml':
                    safe_file(tree, p.relative_to(tree).as_posix())
                    paths.add(p.relative_to(tree).as_posix())
        return paths
    require(build_sources(root) == build_sources(predecessor) | set(CURRENT_SOURCE_ADDITIONS), 'Rust/Cargo path set differs beyond exact reviewed additions')
    for relative, expected in CURRENT_SOURCE_ADDITIONS.items():
        require(not (predecessor/relative).exists(), 'new source existed in predecessor: '+relative)
        raw = safe_file(root, relative).read_bytes()
        require(len(raw) == expected['bytes'] and digest_bytes(raw) == expected['sha256'], 'new source postimage differs: '+relative)
    changed = []
    for row in rows:
        before = safe_file(predecessor, row['path']).read_bytes()
        require(len(before) == row['bytes'] and digest_bytes(before) == row['sha256'], 'predecessor runtime differs: '+row['path'])
        after = safe_file(root, row['path']).read_bytes()
        if before != after:
            changed.append(row['path'])
            validate_current_runtime_change(row['path'], before, after)
    require(sorted(changed) == sorted(CURRENT_RUNTIME_DELTAS), 'exact current runtime delta set required')
    for p in config['unchanged_cargo_manifests']:
        require(safe_file(root,p).read_bytes() == safe_file(predecessor,p).read_bytes(), 'Cargo manifest changed: '+p)
    require(digest_bytes(safe_file(root,'Cargo.lock').read_bytes()) == CURRENT_CARGO_LOCK_SHA256, 'exact four-update lockfile differs')
    manifest_raw = safe_file(root, config['current_network_manifest']).read_bytes()
    require(digest_bytes(manifest_raw) == config['current_network_manifest_sha256'], 'current immutable network manifest differs')
    identity = config['current_identity']
    receipt = {'schema':'hegemon.private-spend.release-authorization.v2',
        'authorization_kind':CURRENT_SOURCE_KIND, 'status':'PASS_EXACT_REVIEWED_SOURCE_SUCCESSOR_ONLY',
        'identity':identity, 'historical_qualified_identity':config['predecessor_identity'],
        'source_successor_config_sha256':CURRENT_CONFIG_SHA256,
        'predecessor_checker_sha256':EXPECTED_CHECKER, 'predecessor_registry_sha256':EXPECTED_REGISTRY,
        'runtime_inventory_sha256':EXPECTED_RUNTIME, 'runtime_files_compared':598,
        'changed_paths':sorted(changed), 'added_source_paths':sorted(CURRENT_SOURCE_ADDITIONS),
        'reviewed_runtime_deltas':config['reviewed_runtime_deltas'], 'reviewed_source_additions':CURRENT_SOURCE_ADDITIONS,
        'cargo_lock_sha256':CURRENT_CARGO_LOCK_SHA256, 'cargo_metadata_unchanged':False,
        'proof_and_protocol_runtime_unchanged':False, 'new_version':NEW_VERSION,
        'network_manifest_sha256':config['current_network_manifest_sha256'],
        'predecessor_source_gate':old_receipt, 'assumptions':old_receipt['assumptions'],
        'binding_sha256':old_receipt['binding_sha256'], 'g7_review_sha256':old_receipt['g7_review_sha256'],
        'unchanged_evidence_reused':True, 'historical_G8_reused':True,
        'predecessor_lifecycle_reexecuted':False, 'affected_lifecycle_verified':False,
        'fresh_network_lifecycle_verified':False, 'current_network_G8_qualified':False,
        'fresh_public_genesis_qualified':False, 'state_admission_verified':False,
        'production_artifacts_verified':False, 'production_authorized':False,
        'public_cutover_authorized':False, 'deployment_verified':False,
        'actual_new_binary_proof_verification':False,
        'limitations':config['limitations']}
    return receipt, json.loads(manifest_raw)

def source_gate(root, predecessor):
    config = load_json(safe_file(root, CONFIG))
    if config.get('schema') == 'hegemon.release.exact-source-successor.v2':
        return current_source_gate(root, predecessor)
    return legacy_source_gate(root, predecessor)

def validate_current_binary_proofs(checks, node_sha, artifact_sha, relation_digest, fixture_manifest_sha):
    expected = {'schema':'hegemon.v011.current-binary-proof-verification.v1',
        'status':'PASS_CURRENT_BINARY_BACKEND_PROOFS', 'actual_proof_verification':True,
        'node_sha256':node_sha, 'artifact_manifest_sha256':artifact_sha,
        'cargo_lock_sha256':CURRENT_CARGO_LOCK_SHA256, 'relation_digest':relation_digest,
        'fixture_manifest_sha256':fixture_manifest_sha, 'cases_verified':5,
        'network_manifest_sha256':CURRENT_NETWORK_MANIFEST_SHA256,
        'offline_cli_source_sha256':CURRENT_RUNTIME_DELTAS['node/src/bin/native_node.rs'][1],
        'processes_reaped':True, 'cryptographic_verification_only':True,
        'fresh_network_lifecycle_verified':False, 'state_admission_verified':False,
        'production_authorized':False, 'public_cutover_authorized':False}
    require(isinstance(checks,dict) and all(type(checks.get(k)) is type(v) and checks[k] == v for k,v in expected.items()), 'current binary proof scope/identity incomplete')
    require(isinstance(checks.get('inputs_before'),dict) and bool(checks['inputs_before']) and checks['inputs_before'] == checks.get('inputs_after'), 'current proof execution input snapshots missing or changed')
    cases = checks.get('cases')
    require(isinstance(cases,list) and [r.get('name') for r in cases] == CURRENT_CASE_NAMES, 'exact five current proof cases required')
    require(len(CURRENT_PROOF_CASES) == 5, 'current public fixture descriptors not frozen')
    for actual, frozen in zip(cases, CURRENT_PROOF_CASES):
        require(actual.get('name') == frozen['name'] and actual.get('proof') == frozen['proof'] and actual.get('statement') == frozen['statement'], 'current proof/statement differs from frozen actual fixture')
        require(actual.get('verified') is True and actual.get('processes_reaped') is True and type(actual.get('exit_code')) is int and actual['exit_code'] == 0, 'actual current binary proof verification did not pass')
        controls = actual.get('negative_controls')
        require(isinstance(controls,dict) and sorted(controls) == sorted(CURRENT_NEGATIVE_NAMES), 'complete current-binary negative controls required')
        for control in controls.values():
            require(isinstance(control,dict) and control.get('rejected') is True and control.get('processes_reaped') is True and type(control.get('exit_code')) is int and control['exit_code'] == 1, 'negative input was not rejected by actual binary')

def final_replay(root, artifact, receipt, min_free_gib):
    if receipt.get('authorization_kind') != CURRENT_SOURCE_KIND:
        return legacy_final_replay(root, artifact, receipt, min_free_gib)
    runner = safe_file(root, 'scripts/check_v011_current_binary_proofs.py')
    fixture = safe_file(root, 'release-evidence/v0.11-current-proof-fixture/manifest.json')
    require(digest_bytes(runner.read_bytes()) == CURRENT_RUNNER_SHA256, 'reviewed current proof runner differs or is not frozen')
    require(digest_bytes(fixture.read_bytes()) == CURRENT_FIXTURE_SHA256, 'reviewed current proof fixture differs or is not frozen')
    node = next(r for r in load_json(artifact)['artifacts'] if r['binary'] == 'hegemon-node')
    output = Path(receipt['identity_smoke']['scratch_directory'])/'current-binary-proofs'
    command = [sys.executable, '-I', '-B', str(runner), '--node-bin',str(safe_file(root,node['path'])), '--artifact-manifest',str(artifact), '--output',str(output), '--min-free-gib',str(min_free_gib)]
    result = subprocess.run(command, cwd=root, capture_output=True, timeout=240, check=False)
    require(result.returncode == 0 and not result.stderr, 'actual current-binary proof verification failed: '+result.stderr.decode(errors='replace')[-2000:])
    checks = json.loads(result.stdout)
    require(checks.get('target_triple') == load_json(artifact)['target_triple'], 'current proof runner target differs from final artifact manifest')
    validate_current_binary_proofs(checks, receipt['artifact_sha256']['hegemon-node'], receipt['artifact_manifest_sha256'], receipt['identity']['relation_digest'], CURRENT_FIXTURE_SHA256)
    require(digest_bytes(artifact.read_bytes()) == receipt['artifact_manifest_sha256'], 'artifact manifest changed during current proof checks')
    require(digest_bytes(safe_file(root,node['path']).read_bytes()) == receipt['artifact_sha256']['hegemon-node'], 'node changed during current proof checks')
    receipt.update(status='PASS_EXACT_SOURCE_CURRENT_BINARY_BACKEND_AND_H0',
        final_artifact_scope=CURRENT_SCOPE, current_binary_backend_artifacts_verified=True,
        actual_new_binary_proof_verification=True, current_binary_proof_verification=checks)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-authorized', action='store_true', help='Explicit intent; source-only comparison remains distinct from final binary verification.')
    parser.add_argument('--predecessor-root', type=Path, default=ROOT/'target/v011-predecessor')
    parser.add_argument('--artifact-manifest', type=Path)
    parser.add_argument('--require-final-artifact', action='store_true', help='Require the exact mode-specific final executable proof verification; source-only or H0-only is insufficient.')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--min-free-gib', type=int, default=4, help='Minimum reserve for bounded CI smoke; local operators should select 15 GiB.')
    args = parser.parse_args()
    try:
        require(args.require_authorized, 'explicit --require-authorized intent required')
        require(args.min_free_gib >= 4, 'at least four GiB reserve required')
        require(not args.require_final_artifact or args.artifact_manifest is not None, 'final artifact phase requires an artifact manifest')
        require(args.predecessor_root.is_dir(), 'authenticated predecessor missing: run scripts/materialize_v011_predecessor.py explicitly before this gate')
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
