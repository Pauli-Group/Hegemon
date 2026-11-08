#!/usr/bin/env python3
"""Source-bound software candidate checks; never production/activation authority.

--prepare is useful before source freeze. --require-authorized requires a frozen
source inventory and independent scope review. Final artifacts additionally run
unchanged actual proof/H0 executors and source-owned fresh qualification commands.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = 'config/combined-upgrade-candidate-20261108.json'
BASE = 'eec3bb141f59865d5efc4d97c86e201415a0b839'
SCHEMA = 'hegemon.combined-upgrade.candidate.v1'
KIND = 'reviewed_combined_upgrade_software_candidate'
SCOPE = 'combined_upgrade_source_proofs_h0_and_fresh_affected_lifecycle'
RELATION_ID = 'Hegemon.PrivateSpend.BoundedPolicy.CompFF01.Packed.v4'
RELATION = 'b9d22c2f0cb49df519b34620c138d7f2d74fa135a76c7b526cd73a60bb5cd6cec2f910dde83b1a848684e123d02ab0bbc8bdb384b1bcaff1b489fd8794c14685'
LOCK = '1c243bf3858f4ee22fa4441c7a2ee6d49b16d264147b0f3a2de845e760821719'
EVIDENCE_ROOT = 'release-evidence/combined-upgrade-20261108/'
CHECKS = ('timestamp_admission', 'asert', 'version_rolling', 'treasury_cadence', 'current_smzl_htlc', 'restart_reorg_fresh_sync')
REQUIRED_GATES = {
    'timestamp_admission': ('exact_boundary', 'beyond_boundary', 'local_cpu', 'local_asic', 'announcement', 'batch_sync', 'fresh_sync', 'winning_branch', 'temporary_retry', 'bounded_author', 'historical_replay'),
    'asert': ('reference_vectors', 'no_std', 'lean_vectors', 'activation_boundary', 'branch_anchor', 'wrong_target_rules', 'cold_resumption', 'live_author_catchup'),
    'version_rolling': ('negotiated_mask', 'fixed_version', 'malformed_rejection', 'out_of_mask_rejection', 'nonzero_rolled_block', 'independent_import', 'extranonce_20_8', 'extranonce_24_4', 'retained_solution_retry'),
    'treasury_cadence': ('migration_boundary', 'fresh_cadence', 'halving_rounding', 'zero_and_final_residual', 'invalid_payout_rejection', 'miner_and_fee_preservation', 'omitted_reward_semantics', 'pending_issued_accounting', 'maturity', 'wallet_discovery', 'unchanged_relation_spend'),
    'current_smzl_htlc': ('funded_lock', 'funded_claim', 'funded_refund', 'deadline', 'competing_spend', 'encrypted_recovery', 'unchanged_carrier', 'ordinary_payout'),
    'restart_reorg_fresh_sync': ('treasury_boundary_reorg', 'accrual_rollback', 'payout_rollback', 'unchanged_resubmission', 'persistent_restart', 'fresh_independent_sync', 'exact_state_work_supply_agreement'),
}
BOUNDARIES = {'production_authorized': False, 'mainnet_authorized': False,
              'activation_authorized': False, 'public_cutover_authorized': False,
              'deployment_verified': False, 'physical_asic_qualified': False}
# These exact files retain their historical authority and execution behavior.
IMMUTABLE = {'scripts/check_v0113_release_successor.py': 'af04798400fd70c11b934a743961b271bd9db16a729210d73641b600737df61c', 'config/v0113-release-successor.json': 'a8ca68b402ef5db13caee27c6e3e4f384549f5286f6fa2798b2d8542854bd76f', 'scripts/check_v011_sync_import_successor.py': 'ceceb9f281343f9c730422684b44819ab8e9c2ed973a551de641992153303f0f', 'config/v011-sync-import-successor-20261106.json': '9cc53dc52975d3f9cd5edd3caaaf11d971a77f773430b637377e64561aecd9d6', 'scripts/check_v011_release_successor.py': '390f5cbc69e877e29302db4af7b7382bbf6db9bdeccada01942ccba384b0fc67', 'config/v011-release-successor.json': '94bd9591a8232292d1928198b3d4778a27f7cc4c8fc560c0ff87ac3bfa22fadb', 'scripts/check_private_spend_launch_authorization.py': '7f5265e5ddc8ec947bbc93df31df276c0fae787bfdcbc7b1e5a2547958ae60ab', 'scripts/private_spend_launch_authorized_registry.json': 'c37455302ad34f631df1938b0ee7980af8bb8a57930ba38c05a6fe86941c145f', 'scripts/check_v011_current_binary_proofs.py': 'd2f0fae819828482093676f831a5d6c621013c02368cdddafcdf491d294eb2f2', 'scripts/release_artifact_manifest.py': '0f41da8be0536335978ed42d2f93f930b2c9ee078f3ecbeb6293e44ce20c42cb', 'scripts/check_release_launcher_policy.py': '51700e93ac457574f262bff05f48e5e55fa328e37da30f665721a312de9d826e', '.github/workflows/release.yml': 'd03f65f4eb9a27ce5616c31c90b3b41652e9aaf23d29da9cb1f8707eea64ff81', 'config/testnet/0.11/network-manifest.json': '386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754', 'release-evidence/v0.11-current-proof-fixture/manifest.json': '50a1c137b7d8d7d03181b7b9e1d353d98cfd26e708e178c75dd7925dff271a8c', 'scripts/check_qualified_formatting.py': 'be7732c0e30f9b770ef5395be762ec9ea133d39f7fc52170d17639e2579a71a9', 'config/qualified-formatting-baseline.json': '76a60a213994ee887c854cdd33031667a18472611efc7cf16cb8aa802206ec02'}

class CandidateError(RuntimeError):
    pass

def require(value, message):
    if not value:
        raise CandidateError(message)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def diagnostic_tail(raw, limit):
    # Bound rendered UTF-8 bytes too, including replacement of invalid input.
    encoded = raw[-limit:].decode('utf-8', errors='replace').encode('utf-8')
    return encoded[-limit:].decode('utf-8', errors='ignore')

def strict_json(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, 'duplicate JSON key: ' + key)
            out[key] = value
        return out
    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict), 'JSON object required')
    return value

def safe_file(root, relative):
    require(isinstance(relative, str) and bool(relative), 'relative path required')
    path = Path(relative)
    require(not path.is_absolute() and path.as_posix() == relative
            and all(p not in ('', '.', '..') for p in relative.split('/')), 'canonical path required')
    current = root
    for part in path.parts:
        current /= part
        require(not current.is_symlink(), 'symlink rejected: ' + relative)
        require(not (getattr(current.lstat(), 'st_file_attributes', 0) & 0x400), 'reparse path rejected')
    require(current.is_file(), 'regular file required: ' + relative)
    return current

def row(root, relative):
    raw = safe_file(root, relative).read_bytes()
    return {'path': relative, 'bytes': len(raw), 'sha256': sha(raw)}

def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, timeout=120, check=False)
    require(result.returncode == 0, 'authenticated Git base unavailable: ' + result.stderr.decode(errors='replace')[-500:])
    return result.stdout

def base_tree(root):
    require(git(root, 'rev-parse', BASE + '^{commit}').decode().strip() == BASE, 'immutable base commit differs')
    out = {}
    for entry in git(root, 'ls-tree', '-rz', '--full-tree', BASE).split(b'\0'):
        if not entry:
            continue
        meta, name = entry.split(b'\t', 1)
        mode, kind, oid = meta.decode().split()
        require(kind == 'blob' and mode in ('100644', '100755'), 'submodule/symlink base entry rejected')
        out[name.decode()] = (mode, oid)
    return out

def owned(path):
    return path != CONFIG and not path.startswith(EVIDENCE_ROOT)

def evidence_data(root, index_modes=None):
    """Admit bounded public wire data, never executable source or credentials."""
    index_modes = index_modes or {}
    base = root
    for part in Path(EVIDENCE_ROOT).parts:
        base /= part
        require(not base.is_symlink(), 'linked evidence directory rejected')
        if not base.exists():
            return
        require(base.is_dir(), 'candidate evidence directory must be regular')
    caps = {'.smzl': 171848, '.hgps': 177632, '.action': 177632 + 225}
    for parent, dirs, files in os.walk(base, followlinks=False):
        for name in dirs:
            require(not (Path(parent) / name).is_symlink(), 'linked evidence directory rejected')
        for name in files:
            relative = (Path(parent) / name).relative_to(root).as_posix()
            file = safe_file(root, relative)
            suffix = file.suffix
            require(suffix in ('.json', '.log', '.txt', *caps), 'candidate evidence permits public JSON/log/text/action/HGPS/SMZL data only')
            require(not file.stat().st_mode & 0o111 and index_modes.get(relative) != '100755', 'executable evidence rejected: ' + relative)
            if suffix in caps:
                require(0 < file.stat().st_size <= caps[suffix], 'public wire evidence byte cap exceeded: ' + relative)
                raw = file.read_bytes()
                require((suffix == '.smzl' and raw.startswith(b'SMZL'))
                        or (suffix == '.hgps' and raw.startswith(b'HGPSLC02'))
                        or (suffix == '.action' and raw[48:56] == bytes.fromhex('0c00070001000f00')),
                        'public wire evidence framing differs: ' + relative)

def inventory(root):
    paths = git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').decode().split('\0')
    index_modes = {}
    for entry in git(root, 'ls-files', '--stage', '-z').split(b'\0'):
        if entry:
            meta, name = entry.split(b'\t', 1)
            index_modes[name.decode()] = meta.decode().split()[0]
    evidence_data(root, index_modes)
    names = {p for p in paths if p and owned(p)}
    # Git ignore patterns do not constrain Cargo discovery. In particular bin/
    # may be globally ignored while src/bin/*.rs remains an automatic target.
    excluded = {'.git', 'target', 'node_modules', '.lake', '__pycache__', '.venv', 'venv'}
    for parent, dirs, files in os.walk(root, followlinks=False):
        relative = Path(parent).relative_to(root)
        if relative.parts and relative.parts[0] == 'release-evidence':
            dirs[:] = []; continue
        kept = []
        for name in dirs:
            if name in excluded:
                continue
            require(not (Path(parent) / name).is_symlink(), 'linked source directory rejected')
            kept.append(name)
        dirs[:] = kept
        for name in files:
            path = relative / name
            if (path.suffix in ('.rs', '.lean') or name in ('Cargo.toml', 'Cargo.lock', 'build.rs', 'rust-toolchain', 'rust-toolchain.toml')
                    or (path.parts and path.parts[0] == '.cargo')
                    or (path.parts and path.parts[0] == 'scripts' and path.suffix in ('.py', '.sh'))):
                names.add(path.as_posix())
    output = []
    for path in sorted(names):
        file = safe_file(root, path)
        mode = '100755' if file.stat().st_mode & 0o111 else '100644'
        if os.name == 'nt' and path in index_modes:
            # Windows lacks POSIX executable bits. Match the existing artifact
            # manifest's Git-index interpretation of tracked source modes.
            mode = index_modes[path]
        output.append({**row(root, path), 'mode': mode})
    return output


def proof_identity(root):
    source = safe_file(root, 'circuits/transaction/src/private_spend.rs').read_text()
    types = safe_file(root, 'circuits/transaction/src/private_spend/types.rs').read_text()
    require('pub const RELATION_ID: &str = "' + RELATION_ID + '";' in types, 'relation ID differs')
    files = re.findall(r'\(\s*"([^"]+)"\s*,\s*include_bytes!\("([^"]+)"\)\s*,?\s*\)', source)
    require(len(files) == 41 and all(a == b for a, b in files), 'exact 41 relation inputs required')
    h = hashlib.sha512(b'Hegemon.PrivateSpend.SourceManifest.v1' + RELATION_ID.encode())
    rows = []
    for label, name in files:
        import os
        path = Path(os.path.abspath(root / 'circuits/transaction/src' / name))
        require(path.is_relative_to(root), 'relation path escapes source')
        relative = path.relative_to(root).as_posix()
        data = safe_file(root, relative).read_bytes(); encoded = label.encode()
        h.update(len(encoded).to_bytes(8, 'little') + encoded + len(data).to_bytes(8, 'little') + data)
        rows.append(row(root, relative))
    require(h.hexdigest() == RELATION and sha(safe_file(root, 'Cargo.lock').read_bytes()) == LOCK,
            'proof relation or Cargo.lock differs; new relation qualification required')
    return {'relation_id': RELATION_ID, 'relation_digest': RELATION,
            'cargo_lock_sha256': LOCK, 'source_inputs': rows}

def authenticate(root):
    tree = base_tree(root)
    for path, digest in IMMUTABLE.items():
        require(path in tree and sha(git(root, 'show', BASE + ':' + path)) == digest,
                'immutable predecessor authentication failed: ' + path)
        require(sha(safe_file(root, path).read_bytes()) == digest,
                'historical source authority changed: ' + path)
    return tree

def binding(config):
    return sha(canonical({k: v for k, v in config.items() if k not in ('independent_review', 'qualification_commands')}))

def validate_config(config):
    require(set(config) == {'schema', 'status', 'baseline_commit', 'scope', 'boundaries',
                           'proof_identity', 'source_inventory', 'source_inventory_sha256',
                           'reviewed_delta', 'formatting_debt_migrations', 'independent_review', 'qualification_commands'}, 'candidate config fields differ')
    require(config['schema'] == SCHEMA and config['baseline_commit'] == BASE and config['scope'] == SCOPE,
            'candidate baseline/schema/scope differs')
    require(isinstance(config['boundaries'], dict) and set(config['boundaries']) == set(BOUNDARIES)
            and all(config['boundaries'][k] is v for k, v in BOUNDARIES.items()), 'candidate cannot grant production/activation/hardware authority')
    require(config['status'] in ('pending', 'frozen'), 'candidate status invalid')
    if config['status'] == 'pending':
        require(config['source_inventory'] == [] and config['source_inventory_sha256'] is None
                and config['reviewed_delta'] == [] and config['independent_review'] is None
                and config['qualification_commands'] == [] and config['formatting_debt_migrations'] == [], 'pending config cannot claim frozen evidence')
    else:
        require(isinstance(config['source_inventory'], list) and config['source_inventory'], 'source inventory missing')
        require(config['source_inventory_sha256'] == sha(canonical(config['source_inventory'])), 'source inventory digest differs')
        require(isinstance(config['reviewed_delta'], list) and config['reviewed_delta'], 'exact reviewed delta missing')
    require(isinstance(config['formatting_debt_migrations'], list), 'formatting migration list required')
    return config

def load_config(root):
    return validate_config(strict_json(safe_file(root, CONFIG).read_bytes()))

def source_check(root, config):
    tree = authenticate(root)
    require(config['proof_identity'] == proof_identity(root), 'source-bound relation inventory differs')
    if config['status'] == 'pending':
        return {'status': 'PASS_PENDING_SOURCE_PREPARATION', 'source_frozen': False, **BOUNDARIES}
    current = inventory(root)
    require(current == config['source_inventory'], 'frozen source inventory/path set differs')
    deltas = []
    for item in current:
        path = item['path']; raw = safe_file(root, path).read_bytes()
        oid = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if path in tree and oid == tree[path][1] and item['mode'] == tree[path][0]:
            continue
        before = sha(git(root, 'show', BASE + ':' + path)) if path in tree else None
        deltas.append({'path': path, 'before_sha256': before, 'after_sha256': item['sha256'], 'bytes': item['bytes'], 'before_mode': tree[path][0] if path in tree else None, 'after_mode': item['mode']})
    require(not ({p for p in tree if owned(p)} - {r['path'] for r in current}), 'base source removal rejected')
    require(deltas == config['reviewed_delta'], 'exact reviewed candidate delta differs')
    return {'status': 'PASS_FROZEN_SOURCE_PREPARATION', 'source_frozen': True,
            'candidate_binding_sha256': binding(config), 'source_inventory_sha256': config['source_inventory_sha256'], **BOUNDARIES}

def pinned_json(root, reference):
    require(isinstance(reference, dict) and set(reference) == {'path', 'bytes', 'sha256'}, 'exact evidence pin required')
    require(reference['path'].startswith(EVIDENCE_ROOT), 'evidence must use candidate evidence namespace')
    require(row(root, reference['path']) == reference, 'evidence bytes differ')
    return strict_json(safe_file(root, reference['path']).read_bytes())

def review_check(root, config):
    require(config['status'] == 'frozen', 'candidate source is pending; freeze and actual independent review required')
    review = pinned_json(root, config['independent_review'])
    expected = {'schema': 'hegemon.combined-upgrade.independent-review.v1',
                'decision': 'ACCEPT_SOFTWARE_CANDIDATE_SCOPE', 'candidate_binding_sha256': binding(config),
                'source_inventory_sha256': config['source_inventory_sha256'],
                'qualification_commands_sha256': sha(canonical(config['qualification_commands'])), **BOUNDARIES}
    require(all(type(review.get(k)) is type(v) and review[k] == v for k, v in expected.items()), 'independent review binding/scope differs')
    require(review.get('review_kind') in ('independent_model_review', 'independent_human_review')
            and isinstance(review.get('reviewer'), str) and review['reviewer'].strip()
            and isinstance(review.get('limitations'), list) and review['limitations'], 'independent attribution and limitations required')
    require([r.get('name') for r in config['qualification_commands']] == list(CHECKS), 'complete ordered affected qualification commands required')
    return review

def validate_check(value, name, config, artifacts):
    expected = {'schema': 'hegemon.combined-upgrade.actual-check.v1', 'name': name,
                'status': 'PASS', 'candidate_binding_sha256': binding(config),
                'source_inventory_sha256': config['source_inventory_sha256'],
                'artifact_manifest_sha256': artifacts['artifact_manifest_sha256'],
                'artifact_sha256': artifacts['artifact_sha256'], 'target_triple': artifacts['target_triple'],
                'actual_execution': True, 'processes_reaped': True, **BOUNDARIES}
    require(isinstance(value, dict) and all(type(value.get(k)) is type(v) and value[k] == v
                for k, v in expected.items()), 'fresh qualification identity/scope differs: ' + name)
    require(isinstance(value.get('gates'), dict) and set(value['gates']) == set(REQUIRED_GATES[name])
            and all(v is True for v in value['gates'].values()),
            'complete exact actual qualification gates required: ' + name)


def fresh_checks(root, config, artifacts, manifest_path):
    outputs = []
    source_paths = {r['path'] for r in config['source_inventory']}
    for command in config['qualification_commands']:
        require(set(command) == {'name', 'argv', 'timeout_seconds'}, 'qualification command fields differ')
        argv = command['argv']
        require(isinstance(argv, list) and len(argv) >= 4 and argv[:3] == ['python3', '-I', '-B']
                and argv[3].startswith('scripts/') and argv[3] in source_paths
                and all(isinstance(v, str) and v for v in argv), 'source-owned isolated Python qualification command required')
        require(type(command['timeout_seconds']) is int and 1 <= command['timeout_seconds'] <= 7200, 'bounded qualification timeout required')
        require('{artifact_manifest}' in argv[4:], 'qualification argv must bind the actual artifact manifest placeholder')
        actual_argv = [str(manifest_path.relative_to(root)) if v == '{artifact_manifest}' else v for v in argv]
        result = subprocess.run([sys.executable, *actual_argv[1:]], cwd=root, capture_output=True,
                                timeout=command['timeout_seconds'], check=False)
        if result.returncode != 0 or result.stderr:
            require(False, 'fresh qualification failed: ' + command['name']
                    + '; exit=' + str(result.returncode)
                    + '; stderr tail (4096 bytes):\n' + diagnostic_tail(result.stderr, 4096)
                    + '\nstdout tail (4096 bytes):\n' + diagnostic_tail(result.stdout, 4096))
        value = strict_json(result.stdout)
        validate_check(value, command['name'], config, artifacts)
        outputs.append({'name': command['name'], 'command': command,
                        'receipt_sha256': sha(canonical(value)), 'stdout_sha256': sha(result.stdout), 'receipt': value})
    return outputs


def recheck_artifacts(root, manifest_path, receipt):
    require(sha(manifest_path.read_bytes()) == receipt['artifact_manifest_sha256'], 'artifact manifest changed during affected qualification')
    final_manifest = strict_json(manifest_path.read_bytes())
    for artifact in final_manifest['artifacts']:
        raw = safe_file(root, artifact['path']).read_bytes()
        require(sha(raw) == artifact['sha256'] == receipt['artifact_sha256'][artifact['binary']]
                and len(raw) == artifact['size'], 'artifact changed during affected qualification')


def final_artifacts(root, config, manifest_path, min_free_gib):
    # Import only authenticated historical executor bytes; change attribution only.
    path = safe_file(root, 'scripts/check_v011_release_successor.py')
    spec = importlib.util.spec_from_file_location('_combined_historical_executor', path)
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    helper.CURRENT_SOURCE_KIND = KIND; helper.CURRENT_SCOPE = SCOPE; helper.CURRENT_NEW_VERSION = '0.11.3'
    helper.CURRENT_RUNTIME_DELTAS['node/src/bin/native_node.rs'] = (None, sha(safe_file(root, 'node/src/bin/native_node.rs').read_bytes()))
    identity = strict_json(safe_file(root, 'config/v0113-release-successor.json').read_bytes())['current_identity']
    network = strict_json(safe_file(root, 'config/testnet/0.11/network-manifest.json').read_bytes())
    receipt = {'schema': 'hegemon.combined-upgrade.final-receipt.v1', 'authorization_kind': KIND,
               'identity': identity, 'candidate_binding_sha256': binding(config),
               'source_inventory_sha256': config['source_inventory_sha256'], **BOUNDARIES}
    receipt = helper.artifact_gate(root, root, manifest_path, receipt, network, min_free_gib)
    receipt = helper.final_replay(root, manifest_path, receipt, min_free_gib)
    receipt['affected_checks'] = fresh_checks(root, config, receipt, manifest_path)
    recheck_artifacts(root, manifest_path, receipt)
    require(load_config(root) == config, 'candidate config changed during execution')
    source_check(root, config); review_check(root, config)
    receipt.update(status='PASS_SOFTWARE_CANDIDATE_ARTIFACTS_AND_AFFECTED_LIFECYCLE',
                   final_artifact_scope=SCOPE, affected_lifecycle_verified=True,
                   independent_source_review=config['independent_review'], **BOUNDARIES)
    return receipt

def validate_final_receipt(receipt, manifest, manifest_digest, root=ROOT):
    config = load_config(root); source_check(root, config); review_check(root, config)
    require(receipt.get('schema') == 'hegemon.combined-upgrade.final-receipt.v1'
            and receipt.get('authorization_kind') == KIND and receipt.get('final_artifact_scope') == SCOPE
            and receipt.get('status') == 'PASS_SOFTWARE_CANDIDATE_ARTIFACTS_AND_AFFECTED_LIFECYCLE', 'combined final receipt required')
    require(receipt.get('candidate_binding_sha256') == binding(config)
            and receipt.get('source_inventory_sha256') == config['source_inventory_sha256'], 'combined source receipt differs')
    require(all(receipt.get(k) is v for k, v in BOUNDARIES.items()), 'combined receipt expanded authority')
    require(receipt.get('artifact_manifest_sha256') == manifest_digest
            and receipt.get('target_triple') == manifest['target_triple']
            and receipt.get('artifact_sha256') == {r['binary']: r['sha256'] for r in manifest['artifacts']}, 'combined artifact identity differs')
    require(receipt.get('actual_new_binary_proof_verification') is True
            and receipt.get('affected_lifecycle_verified') is True
            and [r.get('name') for r in receipt.get('affected_checks', [])] == list(CHECKS), 'actual proof/lifecycle evidence missing')
    for actual, command in zip(receipt['affected_checks'], config['qualification_commands'], strict=True):
        require(actual.get('command') == command and actual.get('receipt_sha256') == sha(canonical(actual.get('receipt'))), 'affected command/receipt changed')
        validate_check(actual.get('receipt'), command['name'], config, receipt)
    helper_path = safe_file(root, 'scripts/check_v011_release_successor.py')
    spec = importlib.util.spec_from_file_location('_combined_final_proof_predicate', helper_path)
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    helper.CURRENT_RUNTIME_DELTAS['node/src/bin/native_node.rs'] = (None, sha(safe_file(root, 'node/src/bin/native_node.rs').read_bytes()))
    require(receipt.get('current_binary_proof_verification', {}).get('target_triple') == manifest['target_triple'], 'proof receipt target differs')
    helper.validate_current_binary_proofs(receipt.get('current_binary_proof_verification'), receipt['artifact_sha256']['hegemon-node'], manifest_digest, RELATION, helper.CURRENT_FIXTURE_SHA256)
    smoke = receipt.get('identity_smoke', {})
    require(type(smoke.get('height')) is int and smoke['height'] == 0 and type(smoke.get('peers')) is int and smoke['peers'] == 0 and smoke.get('qualified_manifest') is True
            and smoke.get('owned_node_reaped') is True and smoke.get('wrong_compiled_rules_manifest_rejected') is True,
            'actual isolated H0 evidence missing')
    identity = strict_json(safe_file(root, 'config/v0113-release-successor.json').read_bytes())['current_identity']
    require(receipt.get('identity') == identity and smoke.get('genesis') == identity['genesis_hash'], 'combined identity differs')
    return identity

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true'); mode.add_argument('--require-authorized', action='store_true')
    parser.add_argument('--artifact-manifest', type=Path); parser.add_argument('--require-final-artifact', action='store_true')
    parser.add_argument('--predecessor-root', type=Path, help='retained predecessor archive for inherited workflow attribution; base authenticated through pinned Git commit')
    parser.add_argument('--min-free-gib', type=int, default=4)
    args = parser.parse_args()
    try:
        config = load_config(ROOT); receipt = source_check(ROOT, config)
        if args.require_authorized:
            review_check(ROOT, config)
        require(not args.prepare or (args.artifact_manifest is None and not args.require_final_artifact), 'preparation cannot authorize final artifacts')
        require(not args.require_final_artifact or args.artifact_manifest is not None, 'final artifact manifest required')
        if args.artifact_manifest:
            require(args.require_authorized and args.require_final_artifact and args.min_free_gib >= 4, 'explicit final artifact authorization and disk reserve required')
            artifact = args.artifact_manifest.resolve(); require(artifact.is_relative_to(ROOT), 'artifact escapes source root')
            receipt = final_artifacts(ROOT, config, artifact, args.min_free_gib)
        print(json.dumps(receipt, sort_keys=True))
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('combined candidate: ' + str(error), file=sys.stderr); return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
