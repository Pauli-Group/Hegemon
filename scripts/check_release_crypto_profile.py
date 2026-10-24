#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ACTIVE_ARITHMETIZATION = "DirectPacked64CompressedLevel5"
ACTIVE_ARITHMETIZATION_MARKER = "direct-packed64-compressed-level5"
ACTIVE_NO_GRINDING_PROFILE = {
    "rho": 5,
    "nb_opened_evals": 5,
    "beta": 2,
    "opening_pow_bits": 0,
    "decs_nb_evals": 1048576,
    "decs_nb_opened_evals": 23,
    "decs_eta": 5,
    "decs_pow_bits": 0,
}
REQUIRED_SOUNDNESS_FLOOR_BITS = 260
# Independent release ratchets for the exact active verifier surface. These values
# are intentionally not derived from the attested binary: changing either digest
# requires an explicit checker review alongside the Rust verifier/profile change.
CANONICAL_EXACT_CONSTRAINT_TABLE_DIGEST_HEX = (
    "d4f9cd30c8c3ae7e6bf87a73f929471ae22d09295223925c9f6bfc0777daa5b4"
)
CANONICAL_VERIFIER_PROFILE_SHA384_HEX = (
    "e1a09c264e3025034133c4f70a61da9f1f1ba5e535cd44f7c94e87f90ee71202"
    "5385b0fba1338419c1b2b46ba71b1617"
)
CANONICAL_PROFILE_DIGESTS = {
    "exact_constraint_table_digest_hex": CANONICAL_EXACT_CONSTRAINT_TABLE_DIGEST_HEX,
    "verifier_profile_sha384_hex": CANONICAL_VERIFIER_PROFILE_SHA384_HEX,
}
PROFILE_MARKER_FIELDS = {
    "CIRCUIT": "4",
    "CRYPTO": "3",
    "BACKEND": "smallwood_candidate",
    "ARITH": ACTIVE_ARITHMETIZATION_MARKER,
    "RHO": str(ACTIVE_NO_GRINDING_PROFILE["rho"]),
    "OPENINGS": str(ACTIVE_NO_GRINDING_PROFILE["nb_opened_evals"]),
    "BETA": str(ACTIVE_NO_GRINDING_PROFILE["beta"]),
    "DECS_EVALS": str(ACTIVE_NO_GRINDING_PROFILE["decs_nb_evals"]),
    "DECS_OPENINGS": str(ACTIVE_NO_GRINDING_PROFILE["decs_nb_opened_evals"]),
    "DECS_ETA": str(ACTIVE_NO_GRINDING_PROFILE["decs_eta"]),
    "FLOOR": str(REQUIRED_SOUNDNESS_FLOOR_BITS),
}
PROFILE_MARKER = "HEGEMON_PRODUCTION_CRYPTO_PROFILE:" + ":".join(
    f"{key}={value}" for key, value in PROFILE_MARKER_FIELDS.items()
)
# This exact fail-closed refusal is expected for the compact development profile.
# It is a review result only: it never establishes production authority.
UNAPPROVED_PROFILE_REFUSAL = (
    "constraint system violated: SmallWood parameter bound passes, but production "
    "relation/security integration is not authorized: the exact conventional-hash "
    "relation, complete zero knowledge, composed PQ/QROM bound, and compiled-verifier "
    "refinement are incomplete"
)
PROFILE_MARKER_PATTERN = re.compile(
    rb"HEGEMON_PRODUCTION_CRYPTO_PROFILE:"
    rb"CIRCUIT=(?P<CIRCUIT>[0-9]+):"
    rb"CRYPTO=(?P<CRYPTO>[0-9]+):"
    rb"BACKEND=(?P<BACKEND>[a-z0-9_]+):"
    rb"ARITH=(?P<ARITH>[a-z0-9-]+):"
    rb"RHO=(?P<RHO>[0-9]+):"
    rb"OPENINGS=(?P<OPENINGS>[0-9]+):"
    rb"BETA=(?P<BETA>[0-9]+):"
    rb"DECS_EVALS=(?P<DECS_EVALS>[0-9]+):"
    rb"DECS_OPENINGS=(?P<DECS_OPENINGS>[0-9]+):"
    rb"DECS_ETA=(?P<DECS_ETA>[0-9]+):"
    # Rust string data can be packed immediately after this marker without a NUL
    # terminator. Reject both a fourth decimal digit and a marker-field extension.
    rb"FLOOR=(?P<FLOOR>[0-9]{3})(?=$|[^0-9:])"
)


def fail(message: str) -> None:
    raise SystemExit(message)


def rustc_host() -> str:
    output = subprocess.check_output(["rustc", "-vV"], text=True)
    for line in output.splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ")
    fail("could not determine rustc host triple")


def validate_profile_marker(marker: object, label: str) -> dict[str, str]:
    if not isinstance(marker, str):
        fail(f"{label}: compiled production profile marker must be a string")
    parts = marker.split(":")
    if not parts or parts[0] != "HEGEMON_PRODUCTION_CRYPTO_PROFILE":
        fail(f"{label}: compiled production profile marker has the wrong prefix")
    fields: dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            fail(f"{label}: malformed compiled production profile marker field {part!r}")
        key, value = part.split("=", 1)
        if not key or not value or key in fields:
            fail(f"{label}: malformed or duplicate profile marker field {key!r}")
        fields[key] = value
    if fields != PROFILE_MARKER_FIELDS:
        fail(
            f"{label}: compiled production profile marker contradicts the active "
            f"profile: {fields!r} != {PROFILE_MARKER_FIELDS!r}"
        )
    return fields


def validate_binary_profile_markers(binary: Path, binary_name: str) -> None:
    data = binary.read_bytes()
    prefix = b"HEGEMON_PRODUCTION_CRYPTO_PROFILE:"
    offsets: list[int] = []
    offset = data.find(prefix)
    while offset >= 0:
        offsets.append(offset)
        offset = data.find(prefix, offset + len(prefix))
    if not offsets:
        fail(f"{binary_name}: compiled production profile marker is absent")
    markers: set[str] = set()
    for offset in offsets:
        match = PROFILE_MARKER_PATTERN.match(data, offset)
        if match is None:
            fail(f"{binary_name}: malformed compiled production profile marker")
        fields = {
            key: value.decode("ascii") for key, value in match.groupdict().items()
        }
        marker = "HEGEMON_PRODUCTION_CRYPTO_PROFILE:" + ":".join(
            f"{key}={fields[key]}" for key in PROFILE_MARKER_FIELDS
        )
        validate_profile_marker(marker, binary_name)
        markers.add(marker)
    if markers != {PROFILE_MARKER}:
        fail(f"{binary_name}: release binary contains contradictory profile markers")


def validate_profile(profile: object, label: str) -> dict:
    if not isinstance(profile, dict):
        fail(f"{label}: cryptographic profile must be a JSON object")
    expected_fields = {
        "schema_version": 1,
        "default_version": {"circuit": 4, "crypto": 3},
        "default_backend": "smallwood_candidate",
        "version_mapped_backend": "smallwood_candidate",
        "producer_entrypoint": "transaction_circuit::proof::prove->smallwood_frontend::prove_smallwood_candidate_with_auth",
        "verifier_entrypoint": "transaction_circuit::proof::verify_transaction_proof_bytes_for_backend->smallwood_frontend::verify_smallwood_candidate_proof_bytes",
        "arithmetization": ACTIVE_ARITHMETIZATION,
        "public_value_count": 78,
        "required_soundness_floor_bits": REQUIRED_SOUNDNESS_FLOOR_BITS,
    }
    for field, expected in expected_fields.items():
        if profile.get(field) != expected:
            fail(
                f"{label}: profile {field} must be {expected!r}, "
                f"got {profile.get(field)!r}"
            )
    marker_fields = validate_profile_marker(
        profile.get("compiled_profile_marker"), label
    )
    no_grinding = profile.get("no_grinding_profile")
    if no_grinding != ACTIVE_NO_GRINDING_PROFILE:
        fail(f"{label}: active no-grinding profile mismatch: {no_grinding!r}")
    marker_profile = {
        "rho": int(marker_fields["RHO"]),
        "nb_opened_evals": int(marker_fields["OPENINGS"]),
        "beta": int(marker_fields["BETA"]),
        "decs_nb_evals": int(marker_fields["DECS_EVALS"]),
        "decs_nb_opened_evals": int(marker_fields["DECS_OPENINGS"]),
        "decs_eta": int(marker_fields["DECS_ETA"]),
    }
    for field, marker_value in marker_profile.items():
        if no_grinding.get(field) != marker_value:
            fail(
                f"{label}: compiled marker {field}={marker_value} contradicts "
                f"live profile value {no_grinding.get(field)!r}"
            )
    soundness = profile.get("soundness")
    if not isinstance(soundness, dict):
        fail(f"{label}: soundness report missing")
    if soundness.get("profile") != ACTIVE_NO_GRINDING_PROFILE:
        fail(f"{label}: soundness report profile mismatch")
    floor = soundness.get("security_floor_bits")
    if (
        not isinstance(floor, (int, float))
        or floor < REQUIRED_SOUNDNESS_FLOOR_BITS
    ):
        fail(
            f"{label}: computed security floor is below "
            f"{REQUIRED_SOUNDNESS_FLOOR_BITS} bits: {floor!r}"
        )
    if soundness.get("meets_260_bit_floor") is not True:
        fail(f"{label}: computed soundness report does not meet the 260-bit floor")
    for field, expected in CANONICAL_PROFILE_DIGESTS.items():
        value = profile.get(field)
        length = len(expected)
        if not isinstance(value, str) or len(value) != length:
            fail(f"{label}: {field} has the wrong length")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            fail(f"{label}: {field} is not hex: {exc}")
        if value != expected:
            fail(
                f"{label}: {field} contradicts the canonical active release "
                f"ratchet: {value!r} != {expected!r}"
            )
    return profile


def run_profile(
    binary: Path, binary_name: str, *, allow_unapproved_profile: bool = False
) -> dict | None:
    args = [str(binary)]
    if binary_name == "wallet":
        args.append("print-crypto-profile")
    else:
        args.append("--print-crypto-profile")
    completed = subprocess.run(args, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        stderr = completed.stderr.rstrip("\n")
        known_refusal = stderr in (
            UNAPPROVED_PROFILE_REFUSAL,
            f"Error: {UNAPPROVED_PROFILE_REFUSAL}",
        )
        if (
            allow_unapproved_profile
            and completed.returncode == 1
            and known_refusal
            and completed.stdout == ""
            and completed.stderr.count("\n") <= 1
        ):
            return None
        if known_refusal:
            fail(
                f"{binary_name}: production profile refused; production relation/"
                "security integration is not authorized"
            )
        fail(
            f"{binary_name}: profile command failed with exit status "
            f"{completed.returncode}: {completed.stderr.strip() or completed.stdout.strip()}"
        )
    if completed.stderr:
        fail(f"{binary_name}: profile command wrote unexpected stderr")
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        fail(f"{binary_name}: expected exactly one profile JSON line, got {len(lines)}")
    try:
        return validate_profile(json.loads(lines[0]), binary_name)
    except json.JSONDecodeError as exc:
        fail(f"{binary_name}: invalid profile JSON: {exc}")



# This is a scope check, not an authority registry. Only the existing strict
# source-owned private-spend checker can authorize the exact final artifacts.
SOURCE_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_LAUNCH_PROFILE = {'kind': 'PrivateSpend',
 'circuit': 12,
 'crypto': 7,
 'family': 1,
 'action': 15,
 'backend': 2,
 'profile': 12,
 'domain_set': 8,
 'compression_mode': 'hegemon-p2w16-compress14-left-feedforward-v1',
 'emission_schedule': 'hegemon-native-emission-21m-atoms1e8-5hgn-epoch2100000-prefix-v1',
 'schema': 'hegemon.private-spend.native-launch-identity.v2',
 'relation_id': 'Hegemon.PrivateSpend.BoundedPolicy.CompFF01.Packed.v4',
 'relation_digest': 'cd747b8430b51faee6c4bf94d7b0c8f8dfdb7863c6b927db53e7cea67c7a20a49aaf3ceda5b9ba2947dc9b89d070e1ac5fe9ab1c77cba6d859285c2f324b56f5',
 'public_words': 86}
PRIVATE_LAUNCH_ARTIFACTS = (("hegemon-node", "hegemon-node"), ("wallet", "wallet"), ("walletd", "walletd"), ("wallet", "private-spend"))
PRIVATE_LAUNCH_SCOPE = "source-owned-current86-private-spend-launch"


V011_AUTHORITY_SHA256 = {'config/v011-release-successor.json': '1c23c3055fa8f7c21326d7b9ac1e972f985af95871aa2f54e23eb2b98a0c69fe',
 'release-evidence/v0.11-current-proof-fixture/manifest.json': '50a1c137b7d8d7d03181b7b9e1d353d98cfd26e708e178c75dd7925dff271a8c',
 'release-evidence/v0.11-predecessor/manifest.json': 'dbec7e35d7402e687c3a3aa19f70c45425a127a915c74185eb0054ed57aa76fc',
 'release-evidence/v0.11-public-chain-fixture/manifest.json': '16ce37d08a3bcfecca0f8dbe4c323f1f319d1da565ea5473d695a5c13c4676c0',
 'release-evidence/v0.11-public-chain-fixture/native-chain.sled.tar.gz': '6ea33e96e3279d992475f7f1434b2d5c6ca161575c52ab4b675203ba3466f2c1',
 'scripts/check_private_spend_launch_authorization.py': '7f5265e5ddc8ec947bbc93df31df276c0fae787bfdcbc7b1e5a2547958ae60ab',
 'scripts/check_release_launcher_policy.py': '51700e93ac457574f262bff05f48e5e55fa328e37da30f665721a312de9d826e',
 'scripts/check_v011_current_binary_proofs.py': 'a96a9764633e28df98c323e34b6d0633c0c4cf0baf3747b6797005e68309aa38',
 'scripts/check_v011_public_chain_replay.py': '29c6655f1d8ced3ffa5a042e3c66f0567fc0ef465eda70de473e7a35054159dc',
 'scripts/check_v011_release_successor.py': '78716865c7a831ac59272b2c752ea567b2de8cf154f870a4871ef13010068f0b',
 'scripts/materialize_v011_predecessor.py': '0dc2b129332bf1276e5790a2db2682946e54f5af6b6850eaca50ca9e17b4dee5',
 'scripts/release_artifact_manifest.py': '17178256d95ad03cf663991c3bf68224116f07d6671a7f281c70179987eadbb1',
 'scripts/security-audit.sh': 'b103c1e0ae4a18c7cf873a6b9f95cc13079bd0b5b8c6a526e3c1dae84eb3953b'}


def sha256_file(file: Path) -> str:
    return hashlib.sha256(file.read_bytes()).hexdigest()


def private_launch_snapshot(root: Path, manifest_path: Path) -> tuple:
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict) or manifest.get("target_triple") != rustc_host():
        fail("private launch requires the exact native target")
    artifacts = manifest.get("artifacts")
    if (not isinstance(artifacts, list) or len(artifacts) != 4
        or not all(isinstance(item, dict) for item in artifacts)
        or tuple((item.get("package"), item.get("binary")) for item in artifacts) != PRIVATE_LAUNCH_ARTIFACTS):
        fail("private launch requires exactly node/wallet/walletd/private-spend")
    binary_paths = []
    for item in artifacts:
        if not isinstance(item.get("path"), str):
            fail("private launch artifact path is absent")
        binary = (root / item["path"]).resolve()
        try:
            binary.relative_to(root)
        except ValueError:
            fail("private launch artifact escapes source root")
        if not binary.is_file() or sha256_file(binary) != item.get("sha256"):
            fail("private launch artifact digest differs from manifest")
        binary_paths.append(binary)
    if len(set(binary_paths)) != 4:
        fail("private launch artifact paths must be distinct")
    if (root / "config/v011-release-successor.json").is_file():
        for name, expected in V011_AUTHORITY_SHA256.items():
            if not (root / name).is_file() or sha256_file(root / name) != expected:
                fail("v0.11 reviewed authority changed: " + name)
    authority_files = [root / "scripts/check_release_crypto_profile.py", *(root / name for name in V011_AUTHORITY_SHA256)] if (root / "config/v011-release-successor.json").is_file() else []
    authority = tuple((str(file), sha256_file(file)) for file in (*authority_files,
        root / "scripts/check_private_spend_launch_authorization.py",
        root / "scripts/private_spend_launch_authorized_registry.json",
    ))
    return manifest, hashlib.sha256(manifest_bytes).hexdigest(), tuple(binary_paths), authority


def validate_v011_current_successor_receipt(receipt, manifest, manifest_digest, registry):
    """Exact current-source CI exception; never current-network G8 authority."""
    config_path = SOURCE_ROOT / 'config/v011-release-successor.json'
    if sha256_file(config_path) != V011_AUTHORITY_SHA256.get('config/v011-release-successor.json'):
        fail('current successor configuration is not the exact reviewed postimage')
    config = json.loads(config_path.read_text())
    if config.get('schema') != 'hegemon.release.exact-source-successor.v2':
        fail('current successor exact source configuration missing')
    expected = {'schema':'hegemon.private-spend.release-authorization.v2',
        'authorization_kind':'reviewed_source_successor_ci',
        'status':'PASS_EXACT_SOURCE_CURRENT_BINARY_BACKEND_AND_H0',
        'final_artifact_scope':'exact_current_source_current_binary_backend_and_h0',
        'source_successor_config_sha256':V011_AUTHORITY_SHA256['config/v011-release-successor.json'],
        'predecessor_checker_sha256':'6a0d9d0b6f1864160dd3f07adaa54f142a1ce513584f13d903e07265bee7e112',
        'predecessor_registry_sha256':'c37455302ad34f631df1938b0ee7980af8bb8a57930ba38c05a6fe86941c145f',
        'runtime_inventory_sha256':'dfd71b6a265e954261ed209c2ad3c34c97285016557f0f003f7f17f39ff541d0',
        'runtime_files_compared':598, 'new_version':'0.11.0',
        'artifact_manifest_sha256':manifest_digest,
        'cargo_lock_sha256':config['reviewed_runtime_deltas']['Cargo.lock']['after_sha256'],
        'network_manifest_sha256':config['current_network_manifest_sha256'],
        'current_binary_backend_artifacts_verified':True,
        'actual_new_binary_proof_verification':True,
        'historical_G8_reused':True, 'unchanged_evidence_reused':True,
        'predecessor_lifecycle_reexecuted':False, 'affected_lifecycle_verified':False,
        'fresh_network_lifecycle_verified':False, 'current_network_G8_qualified':False,
        'fresh_public_genesis_qualified':False, 'state_admission_verified':False,
        'production_artifacts_verified':False, 'production_authorized':False,
        'public_cutover_authorized':False, 'deployment_verified':False,
        'proof_and_protocol_runtime_unchanged':False, 'cargo_metadata_unchanged':False}
    if not isinstance(receipt,dict) or not all(type(receipt.get(k)) is type(v) and receipt[k] == v for k,v in expected.items()):
        fail('current successor lacks exact final backend/H0 scope; source-only, H0-only and full-G8 relabeling are rejected')
    identity = receipt.get('identity')
    predecessor = config['predecessor_identity']
    release = registry.get('release') if isinstance(registry,dict) else None
    if (not isinstance(identity,dict) or identity != config['current_identity']
        or identity.get('network_profile') != 'pre-mainnet'
        or any(identity.get(k) != v for k,v in PRIVATE_LAUNCH_PROFILE.items() if k != 'relation_digest')
        or registry.get('schema') != 'hegemon.private-spend.source-authorized-registry.v2'
        or not isinstance(release,dict) or release.get('identity') != predecessor
        or receipt.get('historical_qualified_identity') != predecessor):
        fail('current successor changed the exact current or historical identity')
    if (receipt.get('changed_paths') != sorted(config['reviewed_runtime_deltas'])
        or receipt.get('added_source_paths') != sorted(config['reviewed_source_additions'])
        or receipt.get('reviewed_runtime_deltas') != config['reviewed_runtime_deltas']
        or receipt.get('reviewed_source_additions') != config['reviewed_source_additions']):
        fail('current successor exact reviewed source delta differs')
    artifacts = {row['binary']:row['sha256'] for row in manifest['artifacts']}
    if receipt.get('target_triple') != manifest['target_triple'] or receipt.get('artifact_sha256') != artifacts:
        fail('current successor final binary identities differ')
    checks = receipt.get('current_binary_proof_verification')
    if not isinstance(checks,dict) or checks.get('target_triple') != manifest['target_triple']:
        fail('current proof runner target differs from final artifact manifest')
    smoke = receipt.get('identity_smoke')
    expected_smoke = {'qualified_manifest':True, 'genesis':identity['genesis_hash'],
        'height':0, 'peers':0, 'wrong_compiled_rules_manifest_rejected':True,
        'owned_node_reaped':True, 'node_rpc_version':'Hegemon Native Node 0.11.0',
        'wallet_cli_version':'wallet 0.11.0',
        'private_spend_cli_version':'private-spend 0.11.0'}
    if (not isinstance(smoke,dict) or not all(type(smoke.get(k)) is type(v) and smoke[k] == v for k,v in expected_smoke.items())
        or not isinstance(smoke.get('proof_parameters'),dict)
        or smoke['proof_parameters'].get('relation_digest') != identity['relation_digest']
        or smoke['proof_parameters'].get('public_words') != 86
        or smoke['proof_parameters'].get('production_authorized') is not False):
        fail('current successor final-node H0 scope or current proof profile differs')
    # Invoke the same reviewed strict predicate as the executing gate. The gate
    # itself runs this helper; a caller-supplied prerecorded receipt is not an API.
    import importlib.util
    helper_path = SOURCE_ROOT / 'scripts/check_v011_release_successor.py'
    if sha256_file(helper_path) != V011_AUTHORITY_SHA256['scripts/check_v011_release_successor.py']:
        fail('current successor helper is not the exact reviewed postimage')
    spec = importlib.util.spec_from_file_location('_v011_current_final_predicate', helper_path)
    if spec is None or spec.loader is None:
        fail('cannot import reviewed current successor predicate')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    try:
        helper.validate_current_binary_proofs(receipt.get('current_binary_proof_verification'),
            artifacts['hegemon-node'], manifest_digest, identity['relation_digest'], helper.CURRENT_FIXTURE_SHA256)
    except (ValueError, KeyError, TypeError, helper.SuccessorError) as error:
        fail('current successor final-node proof checks rejected: '+str(error))
    return identity


def validate_v011_successor_receipt(receipt, manifest, manifest_digest, registry):
    """Separate bounded mode: predecessor lifecycle is reused, never relabeled."""
    identity = receipt.get("identity")
    expected = {"schema":"hegemon.private-spend.release-authorization.v2",
        "authorization_kind":"qualified_source_tuple", "status":"PASS_VERSION_SUCCESSOR_ARTIFACTS_AND_PUBLIC_PROOF_REPLAY",
        "final_artifact_scope":"version_and_exact_platform_shutdown_successor_public_proof_replay",
        "production_artifacts_verified":False, "affected_lifecycle_verified":False,
        "production_authorized":False, "deployment_verified":False, "public_cutover_authorized":False,
        "fresh_public_genesis_qualified":False, "predecessor_lifecycle_reexecuted":False,
        "version_only_artifacts_verified":True, "actual_new_binary_proof_verification":True,
        "unchanged_evidence_reused":True, "proof_and_protocol_runtime_unchanged":True, "cargo_metadata_unchanged":True, "runtime_files_compared":598, "new_version":"0.11.0", "artifact_manifest_sha256":manifest_digest}
    if not all(type(receipt.get(k)) is type(v) and receipt[k] == v for k,v in expected.items()):
        fail("v0.11 lacks exact bounded successor/artifact/proof-replay scope")
    release = registry.get("release") if isinstance(registry,dict) else None
    if (not isinstance(identity,dict) or identity.get("network_profile") != "pre-mainnet"
        or any(identity.get(k) != v for k,v in PRIVATE_LAUNCH_PROFILE.items())
        or not isinstance(release,dict) or release.get("identity") != identity
        or registry.get("schema") != "hegemon.private-spend.source-authorized-registry.v2"
        or receipt.get("qualified_identity") != identity):
        fail("v0.11 successor changed its qualified rehearsal identity")
    artifacts = {row["binary"]:row["sha256"] for row in manifest["artifacts"]}
    if (receipt.get("target_triple") != manifest["target_triple"] or receipt.get("artifact_sha256") != artifacts
        or receipt.get("runtime_inventory_sha256") != "dfd71b6a265e954261ed209c2ad3c34c97285016557f0f003f7f17f39ff541d0"
        or receipt.get("changed_paths") != ["node/src/native/rpc.rs","node/src/native/util.rs","protocol/versioning/src/lib.rs","wallet/src/bin/wallet.rs"]):
        fail("v0.11 successor artifact/runtime binding differs")
    replay = receipt.get("public_proof_replay")
    replay_expected = {"status":"PASS", "actual_proof_verification":True,
        "node_sha256":artifacts["hegemon-node"], "artifact_manifest_sha256":manifest_digest,
        "fixture_manifest_sha256":"16ce37d08a3bcfecca0f8dbe4c323f1f319d1da565ea5473d695a5c13c4676c0",
        "network_manifest_sha256":"ffda566f04cee22b2a7ba5c2be88f625e9c668f47a7765f36fb377c79ea25758",
        "canonical_blocks_verified":163, "proof_cases_verified":6, "importer_started_at_genesis":True,
        "importer_fixture_copied":False,"restart_verified":True,"processes_reaped":True}
    if not isinstance(replay,dict) or not all(type(replay.get(k)) is type(v) and replay[k] == v for k,v in replay_expected.items()):
        fail("v0.11 requires actual fresh-import/restart proof verification")
    return identity


def validate_private_launch_receipt(receipt: object, manifest: dict, manifest_digest: str, registry: dict) -> dict:
    if isinstance(receipt,dict) and receipt.get("final_artifact_scope") == "exact_current_source_current_binary_backend_and_h0":
        return validate_v011_current_successor_receipt(receipt, manifest, manifest_digest, registry)
    if isinstance(receipt,dict) and receipt.get("final_artifact_scope") == "version_and_exact_platform_shutdown_successor_public_proof_replay":
        return validate_v011_successor_receipt(receipt, manifest, manifest_digest, registry)
    if (not isinstance(receipt, dict)
        or receipt.get("schema") != "hegemon.private-spend.release-authorization.v2"
        or receipt.get("authorization_kind") != "qualified_source_tuple"
        or receipt.get("production_artifacts_verified") is not True
        or receipt.get("affected_lifecycle_verified") is not True
        or receipt.get("deployment_verified") is not False
        or receipt.get("lifecycle_scope") != "hgn_single_key_composite"
        or receipt.get("artifact_manifest_sha256") != manifest_digest):
        fail("private launch lacks exact final source/artifact/lifecycle authorization")
    identity = receipt.get("identity")
    if (not isinstance(identity, dict)
        or any(identity.get(key) != value for key, value in PRIVATE_LAUNCH_PROFILE.items())
        or identity.get("network_profile") not in ("pre-mainnet", "mainnet")
        or "deactivation_height_exclusive" not in identity
        or identity["deactivation_height_exclusive"] is not None
        or "max_total_proofs" not in identity or identity["max_total_proofs"] is not None):
        fail("private launch is not the current86 ongoing HGN identity")
    release = registry.get("release") if isinstance(registry, dict) else None
    rows = registry.get("final_artifacts") if isinstance(registry, dict) else None
    if (not isinstance(registry, dict)
        or registry.get("schema") != "hegemon.private-spend.source-authorized-registry.v2"
        or not isinstance(release, dict) or release.get("identity") != identity
        or not isinstance(rows, list)):
        fail("private launch receipt differs from source-owned identity")
    matches = [row for row in rows if isinstance(row, dict) and row.get("target_triple") == manifest["target_triple"]]
    expected = {item["binary"]: item["sha256"] for item in manifest["artifacts"]}
    if (len(matches) != 1 or matches[0].get("identity") != identity
        or matches[0].get("artifact_sha256") != expected):
        fail("private launch receipt differs from source-owned final artifacts")
    return identity


def private_launch_profile(root: Path, manifest_path: Path) -> dict:
    # A caller cannot replace the authority checker through the diagnostic --root.
    if root != SOURCE_ROOT:
        fail("private launch must use this checker's source root")
    manifest_path = manifest_path.resolve()
    try:
        manifest_path.relative_to(root)
    except ValueError:
        fail("private launch manifest escapes source root")
    before = private_launch_snapshot(root, manifest_path)
    manifest, manifest_digest, binaries, _ = before
    for item, binary in zip(manifest["artifacts"], binaries, strict=True):
        validate_binary_profile_markers(binary, item["binary"])
        if run_profile(binary, item["binary"], allow_unapproved_profile=True) is not None:
            fail("private launch requires every legacy profile to refuse exactly")
    command = [sys.executable, "-I", "-B", str(root / "scripts/check_private_spend_launch_authorization.py"),
               "--require-authorized", "--artifact-manifest", manifest_path.relative_to(root).as_posix()]
    completed = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=1300 if (root / "config/v011-release-successor.json").is_file() else 180)
    if completed.returncode != 0 or completed.stderr:
        fail("private launch source authorization failed: " + (completed.stderr.strip() or str(completed.returncode)))
    lines = completed.stdout.splitlines()
    receipt = json.loads(completed.stdout)
    if len(lines) != 1 and receipt.get("final_artifact_scope") not in ("version_and_exact_platform_shutdown_successor_public_proof_replay", "exact_current_source_current_binary_backend_and_h0"):
        fail("private launch source authorization must return one JSON receipt")
    registry = json.loads((root / "scripts/private_spend_launch_authorized_registry.json").read_text())
    identity = validate_private_launch_receipt(receipt, manifest, manifest_digest, registry)
    if private_launch_snapshot(root, manifest_path) != before:
        fail("private launch manifest, artifacts or authority changed during validation")
    if receipt.get("final_artifact_scope") == "exact_current_source_current_binary_backend_and_h0":
        return {"passed":True, "mode":"executed-exact-source-backend-h0",
            "target_triple":manifest["target_triple"], "production_authority":False,
            "authorization_scope":"exact-current-source-current-binary-backend-and-h0-only",
            "private_spend_launch_authority":False, "current_network_G8_qualified":False,
            "fresh_network_lifecycle_verified":False, "state_admission_verified":False,
            "public_cutover_authorized":False, "identity":identity,
            "artifact_manifest_sha256":manifest_digest,
            "actual_new_binary_proof_verification":True,
            "historical_G8_reused":True, "predecessor_lifecycle_reexecuted":False}
    return {"passed": True, "mode": "executed-private-spend-launch", "target_triple": manifest["target_triple"],
            "production_authority": False, "authorization_scope": PRIVATE_LAUNCH_SCOPE,
            "private_spend_launch_authority": True, "identity": identity,
            "artifact_manifest_sha256": manifest_digest,
            "receipt_mode": receipt.get("final_artifact_scope", "full_current86_composite_lifecycle"),
            "actual_new_binary_proof_verification": receipt.get("actual_new_binary_proof_verification", False),
            "predecessor_lifecycle_reexecuted": receipt.get("predecessor_lifecycle_reexecuted", True)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--require-executed",
        action="store_true",
        help="reject cross-target marker-only inspection",
    )
    parser.add_argument(
        "--allow-unapproved-profile",
        action="store_true",
        help=(
            "review binaries when every native profile command returns only the "
            "exact known fail-closed production-authorization refusal"
        ),
    )
    parser.add_argument(
        "--private-spend-launch", action="store_true",
        help="require exact current86 source-owned final-artifact authorization and closed legacy profiles",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    if args.private_spend_launch:
        if args.allow_unapproved_profile:
            fail("private launch cannot use review-only unapproved-profile mode")
        try:
            result = private_launch_profile(root, args.manifest)
        except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as error:
            fail("private launch attestation failed: " + str(error))
        print(json.dumps(result, sort_keys=True))
        return
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    target = manifest.get("target_triple")
    artifacts = manifest.get("artifacts")
    if not isinstance(target, str) or not isinstance(artifacts, list):
        fail("release manifest lacks target_triple or artifacts")

    profiles: list[dict] = []
    unapproved_refusals = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            fail("release manifest artifact must be an object")
        binary_name = artifact.get("binary")
        relative = artifact.get("path")
        if not isinstance(binary_name, str) or not isinstance(relative, str):
            fail("release manifest artifact lacks binary/path")
        binary = (root / relative).resolve()
        validate_binary_profile_markers(binary, binary_name)
        if target == rustc_host():
            profile = run_profile(
                binary,
                binary_name,
                allow_unapproved_profile=args.allow_unapproved_profile,
            )
            if profile is None:
                unapproved_refusals += 1
            else:
                profiles.append(profile)

    if unapproved_refusals and profiles:
        fail("release binaries disagree on production profile authorization state")

    if profiles and any(profile != profiles[0] for profile in profiles[1:]):
        fail("release binaries disagree on the compiled production cryptographic profile")
    if unapproved_refusals:
        mode = "review-unapproved-profile"
        production_authority = False
    else:
        mode = "executed" if profiles else "static-cross-target"
        production_authority = bool(profiles)
    if args.require_executed and not profiles and not unapproved_refusals:
        fail(
            "release cryptographic profile attestation must execute target binaries "
            f"natively (manifest target {target}, runner host {rustc_host()})"
        )
    print(
        json.dumps(
            {
                "passed": True,
                "mode": mode,
                "target_triple": target,
                "production_authority": production_authority,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
