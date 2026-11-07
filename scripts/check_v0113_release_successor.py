#!/usr/bin/env python3
"""Qualify an exact v0.11.3 pre-mainnet source and native binary successor.

Historical checkers, configurations and accepted artifacts remain unchanged.
The source gate stays closed until a separately recorded independent review
accepts this exact runtime overlay. The inherited 598-file comparison, native
artifact/H0 executor and five-proof/thirty-negative checks remain mandatory.
This bounded scope grants no cryptographic production or full-network authority.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = 'config/v0113-release-successor.json'
CONFIG_SHA256 = 'a8ca68b402ef5db13caee27c6e3e4f384549f5286f6fa2798b2d8542854bd76f'
PARENT_CHECKER = 'scripts/check_v011_sync_import_successor.py'
PARENT_CHECKER_SHA256 = 'ceceb9f281343f9c730422684b44819ab8e9c2ed973a551de641992153303f0f'
PARENT_CONFIG = 'config/v011-sync-import-successor-20261106.json'
PARENT_CONFIG_SHA256 = '9cc53dc52975d3f9cd5edd3caaaf11d971a77f773430b637377e64561aecd9d6'
BASELINE_COMMIT = '1e56a5c8f97eb6f8abf3e79a728849272c42dd0d'
VERSION = '0.11.3'
KIND = 'reviewed_v0113_premainnet_successor_ci'
SCOPE = 'exact_v0113_premainnet_source_current_binary_backend_and_h0'
SOURCE_STATUS = 'PASS_EXACT_REVIEWED_V0113_PREMAINNET_SOURCE_ONLY'
FINAL_STATUS = 'PASS_EXACT_V0113_PREMAINNET_SOURCE_CURRENT_BINARY_BACKEND_AND_H0'
SOURCE_REVIEW_PATH = 'release-evidence/v0.11.3-source-review.json'
SOURCE_REVIEW_SHA256 = 'fe3c923d306c5d7eaea5ed082e88961c7a4d0d1524549f8b40aab10b57667ae5'
OVERLAY = {'node/src/bin/native_node.rs': {'after_sha256': '3014c3573e613a586cf87cb684c4feb681a44adffeeb50be75adc5db479e0225',
                                 'before_sha256': '1b8382135f934f82191357d4e783f81779885bf51499ea5cd6a96229fdb3ff41',
                                 'bytes': 6108,
                                 'original_sha256': '236cfb18659ba1ad624f3c2f25f03bc45601221ff19f586c83094ddadff8ac96'},
 'node/src/native/asset_recovery_lifecycle_tests.rs': {'after_sha256': '86efcbe4f4f65cc1d0752d7206297c0802f15759e76fc945b2238cabd88099a9',
                                                       'before_sha256': 'e2e83d99062b5940a872b672e8d7e7564f45141005b8e5594277ff6d5b8d6950',
                                                       'bytes': 137137,
                                                       'original_sha256': '62cf4bec53d619556bc07a6cf0f66fc36d81130873b122bf88c2bff0353e8415'},
 'node/src/native/bitcoin_asic_tests.rs': {'after_sha256': '923b6ca65fc2e8ab72367c657843152f5c2800796468ebb3db3ba3f06a1ad4e6',
                                           'before_sha256': '96b330131666a237d86170db913926e4efc98c2e5e7d09e74a1f8be50a8a1724',
                                           'bytes': 13237,
                                           'original_sha256': '96b330131666a237d86170db913926e4efc98c2e5e7d09e74a1f8be50a8a1724'},
 'node/src/native/mod.rs': {'after_sha256': 'd6b49620dc7de42e03af362e55d93ba1d82c25cfa05eb3ddf471c02b0ddeb4e3',
                            'before_sha256': '216495b34c27c4530ec985def5bca1c5edb0884233bd7b2fab64d72a1a263294',
                            'bytes': 183040,
                            'original_sha256': '6be69238c26189dd48d921a5a9c8b2aa2a9057af05060ba62edd9f7d8234bfa9'},
 'node/src/native/network_profile.rs': {'after_sha256': '25a56be48cf1119492d19144a1426734e19b1b22ffb5d69f13b83707f7a2c34a',
                                        'before_sha256': 'c90231a2c84bd18dca45c8b35aee568fd4f65e37b8807e54aa57f47f2e60479c',
                                        'bytes': 58176,
                                        'original_sha256': 'd1f5276aa03bd5f591a8fcb185761ca2edc26515b60ee1104f94127c9db33a7c'},
 'node/src/native/node_impl.rs': {'after_sha256': 'e928104089d165166072ba28784ff3539c05cd8c316ffce58927b6ac4e4260af',
                                  'before_sha256': 'c588a5dcc5987e2c3f94ca03fae643ae9425dcd0c3abe27f465f6961abbd0a65',
                                  'bytes': 618602,
                                  'original_sha256': '05f84c22738c43c937201470a27649a3d73e4b8ce9dfbc87c7d6e95abd462e3c'},
 'node/src/native/pending_action_canonicality_tests.rs': {'after_sha256': 'c4f4aef32b77d6afeabc7b1264bd5c641603978e199d06aac67d6010577ccef1',
                                                          'before_sha256': 'aeb0ca44669f78a5f2b1541d3275fc7551d84b28e62c99acc5538a1342b3a93d',
                                                          'bytes': 14795,
                                                          'original_sha256': 'aeb0ca44669f78a5f2b1541d3275fc7551d84b28e62c99acc5538a1342b3a93d'},
 'node/src/native/pool_rpc_tests.rs': {'after_sha256': '9ca968469865d0579c700a168327e790e4a1095c4f0fd25f7fc6f60b44dee05f',
                                       'before_sha256': 'c9bd760b796556936445de3fa2e449efa2225d579408a52dcdc818237722ac03',
                                       'bytes': 7921,
                                       'original_sha256': 'c9bd760b796556936445de3fa2e449efa2225d579408a52dcdc818237722ac03'},
 'node/src/native/poseidon2_v8_carrier_tests.rs': {'after_sha256': '20365eb217ab7d1f4dd9bbfa968d6bb33a5a724f7d76c30e03e3e1c6b641a151',
                                                   'before_sha256': '36f19e8501bae38b4d8969ea99d5a64c477a0d48f2310cb90214b7b7ba704c69',
                                                   'bytes': 154491,
                                                   'original_sha256': '36f19e8501bae38b4d8969ea99d5a64c477a0d48f2310cb90214b7b7ba704c69'},
 'node/src/native/poseidon2_v8_verifier.rs': {'after_sha256': '25a6e102763a44a13a3a981f6a5e0c75cc9a128d9160fee81fb891e3ca9a6d93',
                                              'before_sha256': '5af943e556f5c51482db820d36534735025c3ddb9356e77c64f53b4c5ec5336a',
                                              'bytes': 187914,
                                              'original_sha256': '5af943e556f5c51482db820d36534735025c3ddb9356e77c64f53b4c5ec5336a'},
 'node/src/native/public_admission.rs': {'after_sha256': '9ece7a92dbea6ea60397908047dfa82fbfe630d834712f434b7098f3f7d9a025',
                                         'before_sha256': None,
                                         'bytes': 24052,
                                         'original_sha256': None},
 'node/src/native/public_rpc_formal_tests.rs': {'after_sha256': 'ce7baeca9c114d2af5ef35182f9b6c7be9e392a3936c37fb1ffc616cd21a82e3',
                                                'before_sha256': None,
                                                'bytes': 8895,
                                                'original_sha256': None},
 'node/src/native/public_rpc_http_tests.rs': {'after_sha256': '8c83e3398716371f05bf687c4680de3b9b6baf14261eeb939c96a4f2e8875fdd',
                                              'before_sha256': None,
                                              'bytes': 23917,
                                              'original_sha256': None},
 'node/src/native/public_submit_fixture_tests.rs': {'after_sha256': 'c728a6adcd6af4c2a2b35d42c4600f22c0702fc90341448a75bd23e7667cc92c',
                                                    'before_sha256': None,
                                                    'bytes': 13197,
                                                    'original_sha256': None},
 'node/src/native/rpc.rs': {'after_sha256': '25f091e4aa24d12d1c5df2d0c3081eef54bb5caa31d2585dcc0e8d20451d58dd',
                            'before_sha256': '74a599d7234621925bddbc9709ecdab37927b9d7e428eaa38590c428b7a435b0',
                            'bytes': 99578,
                            'original_sha256': '0250f8b5548f9e718d1f2b3fb60c39dc0c171fe31615442628c1af274cb8cd8c'},
 'node/src/native/service.rs': {'after_sha256': 'd6fff45736bb92b2f56e5a4dca1c512f26becc1846d5ccb3bd27b6d93f3abd1d',
                                'before_sha256': '8c9593876583aa40c38a8d77362aeaa2c1eb390b9ac7edf7510d81af0f2750e6',
                                'bytes': 290607,
                                'original_sha256': '6a495fc0d0adb765800df9b3ee5d84b0be362843f0e03ef816bff6dd78dd55e0'},
 'node/src/native/tests.rs': {'after_sha256': 'a0dfdab6ba31373fc598a19bfc192919fced16e6b68eb29c1b06ed096281c66d',
                              'before_sha256': '87d7cc3f27d285ae547a05ba0fe96d589e1adc9f640ab88e7a71f13f05d02f19',
                              'bytes': 1550322,
                              'original_sha256': '9ce2b15b592f82403f451f9fc76974c98cc7bdf74f6c421c7bf91228bc1b0e31'},
 'node/src/native/transport_tests.rs': {'after_sha256': '9c92084db8952c67b0fe01b2241b2bafd59474d8e863d906baaea77977d832f2',
                                        'before_sha256': '1f513034b32ab07665f231f6943e7373773f4c87d809be435f6afced13dc12e5',
                                        'bytes': 102291,
                                        'original_sha256': '1f513034b32ab07665f231f6943e7373773f4c87d809be435f6afced13dc12e5'},
 'node/src/native/util.rs': {'after_sha256': '0b56051b7c6820bb9c8ec8b6ed740007be55b44532366277406abc09240931a3',
                             'before_sha256': '51b0333cb00513dc427f4e7cf552f9b3584ffd5133b7ea32b53224ddfed1bea2',
                             'bytes': 34647,
                             'original_sha256': 'ccf0764d0059cff43f784171edf58819cabe9645ab2aa1c8f24592beee5e45b1'},
 'protocol/versioning/src/lib.rs': {'after_sha256': 'f9079908645eec23020edd73d5e78c58758dbfa503d3a8953aafc8c05276b07e',
                                    'before_sha256': '727071dde4afffb5c1c1e0b76ca9383889aaa7a4723e0c673f1bbded155f89aa',
                                    'bytes': 42383,
                                    'original_sha256': '150c5018a34fa6d92eba62f070692d10ccb77e477f2257ee6a4045b477c0f5ba'},
 'scripts/hegemon_formal_core/src/lib.rs': {'after_sha256': '28b363162b4ee10556f9e2b20d8f6b049cc7f7366c4d425f94a6f55864096b26',
                                            'before_sha256': '4987f1a5634898eae53bcc0103af21e48b775546884af84488399923b87773d3',
                                            'bytes': 797720,
                                            'original_sha256': '33c1c47853fa7746d5f351db4e16b684590f2e6be568de6b9578e8fd9aa1bf1d'},
 'wallet/src/multisig.rs': {'after_sha256': 'dec59effecd45844a97978f4b6f6c6c11134b89a076c57ca08ac5c231df45857',
                            'before_sha256': '9f744bd39315f15020f60b0c72b91401fe20ea3bc6daddf4134a6438c32d289b',
                            'bytes': 28087,
                            'original_sha256': '9f744bd39315f15020f60b0c72b91401fe20ea3bc6daddf4134a6438c32d289b'},
 'wallet/src/store.rs': {'after_sha256': '1fae06b73f1f3dbfc90a1e58a9fc776f29f0332baa8af78dfcc7d8154c86bdb0',
                         'before_sha256': 'cc8785a6f1eac90dff9139c215e6cd6963ea4b63922e3f2efd7b948e371f411f',
                         'bytes': 281682,
                         'original_sha256': '9d80022194d56ef287732bb4839f07dbc56a742e533927bf8f30b0b048aa3ed3'},
 'wallet/src/tx_builder.rs': {'after_sha256': 'fa2754714d559246413c3d3474488723562c853a08702892ae06a4da76f319d0',
                              'before_sha256': '9d00cf87982e0eb7d54e3934dafb37744d922cc487f1c75599dd673f81459946',
                              'bytes': 102524,
                              'original_sha256': '9d00cf87982e0eb7d54e3934dafb37744d922cc487f1c75599dd673f81459946'},
 'walletd/src/main.rs': {'after_sha256': '09256276c3706e12355c2165381b7918e8296701c28365f9f1244875894f8a44',
                         'before_sha256': 'f41db4850e49fdc82f8e0a882435dd154e0c82c3256f83f08dafc1d3a116116f',
                         'bytes': 134094,
                         'original_sha256': 'f41db4850e49fdc82f8e0a882435dd154e0c82c3256f83f08dafc1d3a116116f'}}


class SuccessorError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise SuccessorError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def safe_file(root, relative):
    require(isinstance(relative, str) and bool(relative), 'relative file path required')
    path = Path(relative)
    require(not path.is_absolute() and path.parts and path.as_posix() == relative
            and all(p not in ('', '.', '..') for p in relative.split('/')),
            'canonical relative file path required')
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), 'symlink rejected: ' + relative)
        require(not (getattr(current.lstat(), 'st_file_attributes', 0) & 0x400),
                'reparse path rejected: ' + relative)
    require(current.is_file(), 'file missing: ' + relative)
    return current


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict), 'JSON object required')
    return value


def attribution():
    return {'schema': 'hegemon.release.v0113-premainnet-successor-binding.v1',
            'baseline_commit': BASELINE_COMMIT, 'software_version': VERSION,
            'parent_checker': PARENT_CHECKER, 'parent_checker_sha256': PARENT_CHECKER_SHA256,
            'parent_config': PARENT_CONFIG, 'parent_config_sha256': PARENT_CONFIG_SHA256,
            'overlay': copy.deepcopy(OVERLAY), 'overlay_sha256': digest(canonical(OVERLAY))}


def review_reference():
    return {'path': SOURCE_REVIEW_PATH, 'sha256': SOURCE_REVIEW_SHA256}


def validate_review(root):
    require(isinstance(SOURCE_REVIEW_SHA256, str)
            and re.fullmatch('[0-9a-f]{64}', SOURCE_REVIEW_SHA256),
            'independent exact-runtime source review is pending')
    raw = safe_file(root, SOURCE_REVIEW_PATH).read_bytes()
    require(len(raw) <= 1024 * 1024 and digest(raw) == SOURCE_REVIEW_SHA256,
            'independent source review record differs')
    review = strict_json(raw)
    expected = {'schema': 'hegemon.v0113.independent-source-review.v1',
                'status': 'accepted_for_scoped_premainnet_qualification',
                'baseline_commit': BASELINE_COMMIT,
                'overlay_sha256': digest(canonical(OVERLAY)),
                'source_scope': SCOPE,
                'production_authorized': False,
                'cryptographic_security_approved': False,
                'full_network_lifecycle_verified': False}
    require(all(type(review.get(k)) is type(v) and review[k] == v for k, v in expected.items()),
            'independent review scope or runtime identity differs')
    require(review.get('review_kind') in ('independent_model_review', 'independent_human_review')
            and isinstance(review.get('reviewer'), str) and bool(review['reviewer'].strip())
            and isinstance(review.get('evidence'), list) and bool(review['evidence'])
            and isinstance(review.get('limitations'), list) and bool(review['limitations']),
            'independent review attribution, evidence and limitations required')
    return review


def load_binding(root=ROOT, *, require_sources=True, require_review=True):
    # Only these source-owned authenticated modules can supply executable gates.
    for relative, expected in ((PARENT_CHECKER, PARENT_CHECKER_SHA256),
                               (PARENT_CONFIG, PARENT_CONFIG_SHA256)):
        require(digest(safe_file(root, relative).read_bytes()) == expected,
                'immutable deployed-lineage authority differs: ' + relative)
    raw = safe_file(root, CONFIG).read_bytes()
    require(digest(raw) == CONFIG_SHA256, 'exact v0.11.3 configuration differs')
    config = strict_json(raw)
    parent = strict_json(safe_file(root, PARENT_CONFIG).read_bytes())
    expected = copy.deepcopy(parent)
    expected.update(new_version=VERSION, v0113_successor=attribution(),
                    v0113_independent_source_review=review_reference())
    for path, row in OVERLAY.items():
        if row['before_sha256'] is None:
            require(path not in parent['reviewed_source_additions']
                    and path not in parent['reviewed_runtime_deltas']
                    and row['original_sha256'] is None,
                    'new runtime path conflicts with parent: ' + path)
            expected['reviewed_source_additions'][path] = {
                'sha256': row['after_sha256'], 'bytes': row['bytes']}
        elif path in parent['reviewed_source_additions']:
            require(parent['reviewed_source_additions'][path]['sha256'] == row['before_sha256']
                    and row['original_sha256'] is None, 'parent addition postimage differs: ' + path)
            expected['reviewed_source_additions'][path] = {
                'sha256': row['after_sha256'], 'bytes': row['bytes']}
        else:
            old = parent['reviewed_runtime_deltas'].get(path)
            require((old is not None and old['after_sha256'] == row['before_sha256']
                     and old['before_sha256'] == row['original_sha256'])
                    or (old is None and row['before_sha256'] == row['original_sha256']),
                    'parent runtime postimage differs: ' + path)
            expected['reviewed_runtime_deltas'][path] = {
                'before_sha256': row['original_sha256'], 'after_sha256': row['after_sha256']}
        if require_sources:
            source = safe_file(root, path).read_bytes()
            require(len(source) == row['bytes'] and digest(source) == row['after_sha256'],
                    'exact v0.11.3 runtime postimage differs: ' + path)
    require(config == expected, 'configuration differs beyond exact v0.11.3 overlay')
    if require_review:
        validate_review(root)
    spec = importlib.util.spec_from_file_location('_v0113_immutable_sync_import_parent',
                                                safe_file(root, PARENT_CHECKER))
    require(spec is not None and spec.loader is not None, 'cannot load pinned parent checker')
    parent_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parent_module)
    # The deployed adapter authenticates its own parent chain. Its old source
    # postimages are superseded only by the exact reviewed overlay above.
    helper, inherited, _ = parent_module.load_binding(root, require_sources=False)
    require(inherited == parent, 'deployed parent configuration differs')
    helper.CONFIG = CONFIG
    helper.CURRENT_CONFIG_SHA256 = CONFIG_SHA256
    helper.CURRENT_NEW_VERSION = VERSION
    helper.CURRENT_RUNTIME_DELTAS = {
        p: (r['before_sha256'], r['after_sha256'])
        for p, r in config['reviewed_runtime_deltas'].items()}
    helper.CURRENT_SOURCE_ADDITIONS = copy.deepcopy(config['reviewed_source_additions'])
    helper.CURRENT_SOURCE_KIND = KIND
    helper.CURRENT_SCOPE = SCOPE
    return helper, config, parent


def source_gate(root, predecessor):
    helper, config, _ = load_binding(root)
    receipt, manifest = helper.current_source_gate(root, predecessor)
    receipt.update(status=SOURCE_STATUS, v0113_successor=attribution(),
                   independent_source_review=review_reference(),
                   sync_import_successor=config['sync_import_successor'])
    return helper, receipt, manifest


def validate_final_receipt(receipt, manifest, manifest_digest, registry, root=ROOT):
    """Validate actual v0.11.3 evidence without relabeling binary/proof/H0 data."""
    helper, config, _ = load_binding(root, require_sources=False)
    expected = {'schema': 'hegemon.private-spend.release-authorization.v2',
                'authorization_kind': KIND, 'status': FINAL_STATUS,
                'final_artifact_scope': SCOPE, 'new_version': VERSION,
                'source_successor_config_sha256': CONFIG_SHA256,
                'v0113_successor': attribution(), 'independent_source_review': review_reference(),
                'sync_import_successor': config['sync_import_successor'],
                'changed_paths': sorted(config['reviewed_runtime_deltas']),
                'added_source_paths': sorted(config['reviewed_source_additions']),
                'reviewed_runtime_deltas': config['reviewed_runtime_deltas'],
                'reviewed_source_additions': config['reviewed_source_additions'],
                'predecessor_checker_sha256': helper.EXPECTED_CHECKER,
                'predecessor_registry_sha256': helper.EXPECTED_REGISTRY,
                'runtime_inventory_sha256': helper.EXPECTED_RUNTIME,
                'runtime_files_compared': 598, 'artifact_manifest_sha256': manifest_digest,
                'cargo_lock_sha256': helper.CURRENT_CARGO_LOCK_SHA256,
                'network_manifest_sha256': helper.CURRENT_NETWORK_MANIFEST_SHA256,
                'current_binary_backend_artifacts_verified': True,
                'actual_new_binary_proof_verification': True,
                'historical_G8_reused': True, 'unchanged_evidence_reused': True,
                'predecessor_lifecycle_reexecuted': False, 'affected_lifecycle_verified': False,
                'fresh_network_lifecycle_verified': False, 'current_network_G8_qualified': False,
                'fresh_public_genesis_qualified': False, 'state_admission_verified': False,
                'production_artifacts_verified': False, 'production_authorized': False,
                'public_cutover_authorized': False, 'deployment_verified': False,
                'proof_and_protocol_runtime_unchanged': False, 'cargo_metadata_unchanged': False}
    require(isinstance(receipt, dict) and all(type(receipt.get(k)) is type(v) and receipt[k] == v
                                            for k, v in expected.items()),
            'exact final v0.11.3 source/backend/H0 scope required')
    identity = receipt.get('identity')
    require(identity == config['current_identity']
            and receipt.get('historical_qualified_identity') == config['predecessor_identity']
            and isinstance(registry, dict)
            and registry.get('schema') == 'hegemon.private-spend.source-authorized-registry.v2'
            and registry.get('release', {}).get('identity') == config['predecessor_identity'],
            'current or historical network identity differs')
    artifacts = {r['binary']: r['sha256'] for r in manifest['artifacts']}
    require(receipt.get('target_triple') == manifest['target_triple']
            and receipt.get('artifact_sha256') == artifacts, 'final binary identities differ')
    checks = receipt.get('current_binary_proof_verification')
    require(isinstance(checks, dict) and checks.get('target_triple') == manifest['target_triple'],
            'current proof runner target differs')
    helper.validate_current_binary_proofs(checks, artifacts['hegemon-node'], manifest_digest,
                                         identity['relation_digest'], helper.CURRENT_FIXTURE_SHA256)
    smoke = receipt.get('identity_smoke')
    expected_smoke = {'qualified_manifest': True, 'genesis': identity['genesis_hash'],
                      'height': 0, 'peers': 0, 'wrong_compiled_rules_manifest_rejected': True,
                      'owned_node_reaped': True, 'node_rpc_version': 'Hegemon Native Node ' + VERSION,
                      'wallet_cli_version': 'wallet ' + VERSION,
                      'private_spend_cli_version': 'private-spend ' + VERSION}
    require(isinstance(smoke, dict) and all(type(smoke.get(k)) is type(v) and smoke[k] == v
                                          for k, v in expected_smoke.items()),
            'final native v0.11.3 H0 identity differs')
    params = smoke.get('proof_parameters')
    require(isinstance(params, dict) and params.get('relation_digest') == identity['relation_digest']
            and type(params.get('public_words')) is int and params['public_words'] == 86
            and params.get('production_authorized') is False, 'current proof profile differs')
    return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-authorized', action='store_true')
    parser.add_argument('--predecessor-root', type=Path, default=ROOT / 'target/v011-predecessor')
    parser.add_argument('--artifact-manifest', type=Path)
    parser.add_argument('--require-final-artifact', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--min-free-gib', type=int, default=4)
    args = parser.parse_args()
    try:
        require(args.require_authorized, 'explicit --require-authorized intent required')
        require(args.min_free_gib >= 4, 'at least four GiB reserve required')
        require(not args.require_final_artifact or args.artifact_manifest is not None,
                'final artifact phase requires an artifact manifest')
        require(args.predecessor_root.is_dir(), 'authenticated predecessor missing: run scripts/materialize_v011_predecessor.py explicitly before this gate')
        predecessor = args.predecessor_root.resolve(strict=True)
        require(predecessor != ROOT.resolve(), 'predecessor must be a separate immutable source tree')
        helper, receipt, manifest = source_gate(ROOT, predecessor)
        if args.artifact_manifest:
            artifact = args.artifact_manifest if args.artifact_manifest.is_absolute() else ROOT / args.artifact_manifest
            receipt = helper.artifact_gate(ROOT, predecessor, artifact, receipt, manifest, args.min_free_gib)
        if args.require_final_artifact:
            receipt = helper.final_replay(ROOT, artifact, receipt, args.min_free_gib)
            require(receipt.get('status') == 'PASS_EXACT_SOURCE_CURRENT_BINARY_BACKEND_AND_H0'
                    and receipt.get('final_artifact_scope') == SCOPE,
                    'inherited final native proof/H0 verification did not complete')
            receipt['status'] = FINAL_STATUS
            artifact_value = strict_json(artifact.read_bytes())
            registry = strict_json(safe_file(ROOT, helper.REGISTRY).read_bytes())
            validate_final_receipt(receipt, artifact_value, digest(artifact.read_bytes()), registry)
        output = json.dumps(receipt, sort_keys=True, indent=2) + '\n'
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output)
        print(output, end='')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, RuntimeError) as error:
        print('v0.11.3 pre-mainnet successor rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
