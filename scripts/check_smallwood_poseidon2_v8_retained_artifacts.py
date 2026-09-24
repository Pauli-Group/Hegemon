#!/usr/bin/env python3
"""Verify the frozen HGV8RP03 retained proof set without granting authority."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple


ARTIFACT_PARENT = PurePosixPath(".agent/artifacts/smallwood-poseidon2-v8")
MANIFEST_PATH = ARTIFACT_PARENT / "retained-artifact-manifest.json"
MANIFEST_SCHEMA = "hegemon-smallwood-poseidon2-v8-retained-manifest-v2"
EXPECTED_MANIFEST_SHA512 = (
    "6f07e9751f9af6da1710f73b9e1fc689db2a160b357644cf1ba076bcd0b70da5"
    "455a4dd30bee8ea71ee64b9df5d2ecbe2f51351a055deb32a4161516d9adbfe3"
)
CHAIN_SCHEMA = "hegemon-smallwood-poseidon2-v8-retained-chain-verification-v1"
REPORT_SCHEMA = "hegemon-smallwood-poseidon2-v8-retained-artifact-v5"
SOURCE_INVENTORY_SCHEMA = "hegemon-smallwood-poseidon2-v8-release-source-inventory-v2"

RELATION_NAME = "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v2"
RELATION_MAGIC = b"HGV8RP03"
RELATION_BYTES = 852_305
RELATION_SHA512 = (
    "8477896dc765c3776fefc93bb74fb0c7668a677abdc60697b0c216bc9b4363e4"
    "6a8b7cadc557dba4a1e4ccdfe572e5b2833879dd465079b12b6044a51a5612c3"
)
RELATION_DIGEST_HEX = RELATION_SHA512[:96]


class RelationProfile(NamedTuple):
    program_bytes: int
    program_sha512: str
    linear_constraints: int

    @property
    def digest_hex(self) -> str:
        return self.program_sha512[:96]

    @property
    def geometry(self) -> dict[str, int]:
        return {
            "auxiliary_words": 0,
            "constraint_degree": 8,
            "hash_calls": 125,
            "linear_constraints": self.linear_constraints,
            "nonlinear_constraints": 830,
            "packed_witness_words": 43_904,
            "packing_factor": 64,
            "public_words": 120,
            "relation_balance_limbs": 7,
            "witness_rows": 686,
        }


# The fixed retained pointer and all default helper calls retain the historical
# identity. Candidate construction must select one of these exact source pins.
HISTORICAL_RELATION_PROFILE = RelationProfile(RELATION_BYTES, RELATION_SHA512, 19_899)
REPAIRED_RELATION_PROFILE = RelationProfile(
    853_429,
    "180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8"
    "b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84",
    19_935,
)
# The metadata-only correction has its own identity. Old repaired artifacts
# retain their exact profile and are never relabeled as this subject.
METADATA_CORRECTED_RELATION_PROFILE = RelationProfile(
    853_429,
    "7e50eba07d84433a53a6c85ed2b3efecbeff103ca402bb931831e1598e6c9ab8"
    "fa138c9b2f0cb9d21bf2bf044b50d4d057ae0bb12e4def00ec52765245cf9e17",
    19_935,
)
SUPPORTED_RELATION_PROFILES = (
    HISTORICAL_RELATION_PROFILE,
    REPAIRED_RELATION_PROFILE,
    METADATA_CORRECTED_RELATION_PROFILE,
)
GENERATOR_SOURCE = "circuits/transaction/examples/smallwood_poseidon2_v8_artifact.rs"
GENERATOR_SOURCE_SHA512 = (
    "2500a4df3c05b6fc70fecc4e288a326627f61029d51c6bf7192b05d614300b2db"
    "0eff8e956c770f257d0df4333e7ae604e76b3209b13ccb650b86608bdeb4e6f"
)
SOURCE_REVISION = "038ec2d1275d7c1d7de4325d071f43a1fd8e66a1"
GENERATOR_BINARY_BYTES = 2_395_936
GENERATOR_BINARY_SHA512 = (
    "cea3d56a2bc94a778480be697ee29eb9c74a8121e66355f3e08bb624357f7110d"
    "b1e46110480a9a971f2e2a01dab811af8560ec9e4bf69eeb7d170585279ddec"
)

NETWORK_ID = 1_212_632_376
ROUTE = {
    "action_id": 10,
    "backend_id": 2,
    "circuit_version": 8,
    "crypto_suite": 7,
    "domain_set": 4,
    "family_id": 1,
    "profile_id": 6,
}
INNER_MAGIC = b"SMZ9"
NATIVE_MAGIC = b"HGV8TX02"
RPC_MAGIC = b"SWP8LC02"
GOLDILOCKS_MODULUS = 0xFFFF_FFFF_0000_0001

PUBLIC_WORDS = 120
BINDING_LIMBS = 7
FIELD_BYTES = 8
STATEMENT_BYTES = PUBLIC_WORDS * FIELD_BYTES
BINDING_BYTES = BINDING_LIMBS * FIELD_BYTES
CIPHERTEXT_BYTES = 2_147
ACTIVE_OUTPUTS = 2
NATIVE_HEADER_BYTES = 88
NATIVE_FIXED_BYTES = NATIVE_HEADER_BYTES + STATEMENT_BYTES + BINDING_BYTES
RPC_HEADER_BYTES = 32
PROJECTED_PROOF_BYTES = 122_863
PROJECTED_RPC_BYTES = 128_293
PROJECTED_SCALE_BYTES = 128_297
PROJECTED_PENDING_BYTES = 128_522
MAX_PROOF_BYTES = 131_072
MAX_RPC_BYTES = 131_068
MAX_SCALE_BYTES = 131_072
MAX_PENDING_BYTES = 131_297

ROLE_ORDER = ("retained_proof_primary", "retained_proof_independent")
GENERATOR_PATHS = (
    PurePosixPath("generator-binaries/build-a/smallwood_poseidon2_v8_artifact"),
    PurePosixPath("generator-binaries/build-b/smallwood_poseidon2_v8_artifact"),
)
ARTIFACT_FILES = {
    "artifact-report.json",
    "ciphertexts.bin",
    "native-leaf.bin",
    "network-id.bin",
    "pending-action.bin",
    "proof.bin",
    "public-statement.bin",
    "relation-binding.bin",
    "relation-digest.bin",
    "relation-program.bin",
    "rpc-envelope.bin",
    "scale-inline-args.bin",
    "transcript-preamble.bin",
}
COMMON_FILES = (
    "ciphertexts.bin",
    "network-id.bin",
    "public-statement.bin",
    "relation-binding.bin",
    "relation-digest.bin",
    "relation-program.bin",
    "transcript-preamble.bin",
)
AUTHORITY = {
    "artifact_is_release_authority": False,
    "authenticated_review_roots": [],
    "hermetic_release_authority_roots": [],
    "production_capability_enabled": False,
    "successor_registry_ids": [],
}
EXPECTED_FIXTURE = {
    "active_inputs": 2,
    "active_outputs": 2,
    "activity_mask": 15,
    "artifact_alone_authorizes_production": False,
    "authorization_mode": "SingleKey",
    "canonical_empty_note_root_hex": (
        "34d6a0af1423aca9b6b78b4d6635a7e50e188855c0ab49f916190beaeadc5dc7"
        "d67d40c62e13e02bac2b77705d502e298495c320cb88bf24"
    ),
    "ciphertext_bytes_per_output": CIPHERTEXT_BYTES,
    "coinbase_opening_words_sha512": [
        (
            "afd7e6cfae6e8eacafb7eb6ee89d711436b2c11f2defdb96588a81b1baba89a7"
            "cc5f7e1ba776104e523834f5812d0d3728a2f6c504af6342f659bf5bd932f9a4"
        ),
        (
            "e55b18762714c292530e586a6cceeeea4ff49dc109bf618fc9e848826e1416cf2"
            "fb7d3718695fd5fd107bf4638a7a416337052d115554389d34abae8273c3d7f"
        ),
    ],
    "economic_production_evidence": False,
    "economic_value_source": "v8_coinbase_action_11",
    "fee": 0,
    "fixture_group": "retained_coinbase_spend_positions_0_1_v1",
    "inline_ciphertext_bytes": ACTIVE_OUTPUTS * CIPHERTEXT_BYTES,
    "input_merkle_path_sha512": [
        (
            "53820c2b9cd9055a7a3be31ad824e3544e34669e8e408ab10e99ae0b899ae443b"
            "2e82e4fcaad44a6f9e30980fd1cb55f850b1bb015222d83b219869cbc9b546a"
        ),
        (
            "99ba696ade1796144e607ee23b46c393d4f9272cfa2da5b62066fc19c5bd6a087"
            "d2bcbf31be3143ef784c50364316de2d37b44638aefa52bf8ed7ebf580d5b00"
        ),
    ],
    "input_note_commitments_hex": [
        (
            "5b4d4f5946bf66fdc923bf0047958568ac341207bc2cf8bf221365e40dc2608e"
            "a3984c61df993d71bd10cecffb77c16b0960a021be01b3f5"
        ),
        (
            "78a0d37903c631ee8073da81d49ab1b6c248dceeb85c5216b31ca090587c185a"
            "594276c172b5fd82b0ff9d46d0a17f0330e7e30ec44c5bbd"
        ),
    ],
    "input_positions": [0, 1],
    "input_values": [499_429_223, 499_429_223],
    "kind": "two_input_two_output_coinbase_spend",
    "merkle_root_hex": (
        "4234cd0433f8d6908835707d621d274826d6a08124a5b27304f0ecec137d4d91"
        "29e54a87060390ac6bf87eb775c873df4d1e2139275a629a"
    ),
    "parent_height": 2,
    "requires_live_coinbase_carrier_lifecycle": True,
    "retains_private_witness": False,
    "stablecoin_root_hex": "0" * 112,
    "synthetic_fixture_witness_definition_sha512": (
        "8e77fc538021936b7b0a1ac0e756a9df4e02b16f3053a9f5d52ff0a9a38f63ad"
        "569aca6459750e1b7b69a6a85b148392dbb05ee8cd43a0dbba1a57a2904a7a8c"
    ),
}
EXPECTED_PROFILE = {
    "beta": 2,
    "decs_eta": 5,
    "decs_evaluations": 8_388_608,
    "decs_opened_leaves": 20,
    "evaluation_domain": "radix2-disjoint-coset",
    "leaf_tape_bytes": 64,
    "opened_evaluations": 6,
    "rho": 5,
    "transcript": "SHA-512 Poseidon2 V8",
}
EXPECTED_REPORT_KEYS = {
    "artifact_role", "bytes", "fixture", "generated_unix_seconds",
    "generation_provenance", "geometry", "identity", "opening_surface",
    "proof_randomness_binding", "proof_source_inventory", "provenance_transition",
    "retains_private_witness", "schema", "sha512", "successor_evidence",
    "timing_milliseconds", "verification",
}
EXPECTED_VERIFICATION_KEYS = {
    "ciphertext_mutation", "honest_map_audit", "node_pending_action_lifecycle",
    "pending_action_mutations", "proof_and_input_mutations", "readback_before_publish",
    "relation_mutations", "same_smz9_bytes_at_every_layer", "source_factory_immediate",
    "transport_mutations", "transport_parser_stage_checks",
}
EXPECTED_CHAIN_KEYS = {
    "canonical_input_positions", "coinbase_input_commitments_hex",
    "coinbase_input_values", "coinbase_opening_words_sha512",
    "distinct_proof_hashes", "distinct_transcript_roots", "distinct_wire_salts",
    "fixture_group", "independent", "input_merkle_path_sha512",
    "input_merkle_root_hex", "parent_height", "parent_height_nonzero", "primary",
    "production_capability_enabled", "proof_witness_is_not_extracted_or_published",
    "relation_program_magic", "relation_program_sha512",
    "same_proof_bytes_preserved_inside_each_carrier", "same_public_statement",
    "same_source_fixture_witness_definition", "schema", "semantic_relation",
}
EXPECTED_PROOF_RECORDS = {
    "retained_proof_primary": {
        "artifact_role": "retained_proof_primary",
        "decs_transcript_root_hex": (
            "3d7cdff7c64d247643388d0c45869ea636a03180ec4ef14c25620cc4383990600"
            "64fc9fb69ee2ed3147925de23bd8ca1ba1a9b10ac347b2867af0f6ff15d808e"
        ),
        "directory": "retained_proof_primary/smz9-e3413d889b23d818ad144b2c",
        "generation_run_id_hex": (
            "a622c8ed38359b5978390079f68c027739daf2e3f63885ea506eec7cc124d075"
        ),
        "proof": {
            "bytes": 122_735,
            "sha512": (
                "e3413d889b23d818ad144b2ca6dcacbeaf1a7269fb7c8dc8f0f4ab2eaf3e998"
                "3ff7f82a2978583f201d1d6a0ad0f69960070ad884747e64c8b76a40daa8bc522"
            ),
        },
        "wire_salt_hex": (
            "a582600c76299db3d0d81e7ff5fe6e24ed3857bd84244d92cb92caff65ea5214"
        ),
    },
    "retained_proof_independent": {
        "artifact_role": "retained_proof_independent",
        "decs_transcript_root_hex": (
            "3de5d92113dc28f744ff746e48fd6debb4238bc06ed3a1923bb8a300fdc3042e9"
            "cada92b451ade1dc1f6bc3b1bbdb07cffe61ebd2b74a3a5495c5b9fb156faea"
        ),
        "directory": "retained_proof_independent/smz9-a99deca70a5150f82df021e2",
        "generation_run_id_hex": (
            "fe52696061cef28637296fc1d94f23edd7b698bd455c1d13ae985fb8e0111681"
        ),
        "proof": {
            "bytes": 122_607,
            "sha512": (
                "a99deca70a5150f82df021e2275a11ddf97f24daf6ee1fa3791daceac9e3cd39e"
                "78f03c521b62dfdd94b3a3a8a7450ee87d7e0eba33287118c9f8799023e69db"
            ),
        },
        "wire_salt_hex": (
            "4fd80046bcb7fa00b218427828305ea0d449eb324fdcbae1ec87a111e0c552fc"
        ),
    },
}


class RetainedArtifactError(RuntimeError):
    pass


def reject(message: str) -> None:
    raise RetainedArtifactError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        reject(message)


def sha512_bytes(payload: bytes) -> str:
    return hashlib.sha512(payload).hexdigest()


def canonical_json(payload: Any) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def parse_json_object(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"{label}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"{label}: invalid JSON output: {error}")
    require(isinstance(payload, dict), f"{label}: JSON output must be an object")
    return payload


def load_json_exact(path: Path, *, canonical: bool = False) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                reject(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"{path}: invalid JSON: {error}")
    require(isinstance(payload, dict), f"{path}: top-level JSON must be an object")
    if canonical:
        require(raw == canonical_json(payload), f"{path}: JSON is not canonical sorted JSON")
    return payload, raw


def relative_path(value: Any, label: str) -> PurePosixPath:
    require(isinstance(value, str), f"{label}: path must be a string")
    path = PurePosixPath(value)
    require(not path.is_absolute(), f"{label}: absolute path forbidden")
    require(value == path.as_posix(), f"{label}: noncanonical path spelling")
    require(path.parts and all(part not in ("", ".", "..") for part in path.parts),
            f"{label}: noncanonical path")
    return path


def require_lower_hex(value: Any, encoded_bytes: int, label: str) -> str:
    require(isinstance(value, str), f"{label}: must be a string")
    require(len(value) == encoded_bytes * 2, f"{label}: wrong length")
    require(all(character in "0123456789abcdef" for character in value),
            f"{label}: must be canonical lower-case hexadecimal")
    return value


def ensure_no_symlink_path(base: Path, relative: PurePosixPath, label: str) -> Path:
    cursor = base
    for part in relative.parts:
        cursor /= part
        try:
            mode = os.lstat(cursor).st_mode
        except OSError as error:
            reject(f"{label}: cannot inspect {cursor}: {error}")
        require(not stat.S_ISLNK(mode), f"{label}: symlink forbidden at {cursor}")
    return cursor


def recompute_source_inventory(repository_root: Path) -> dict[str, Any]:
    policy_path = Path(__file__).with_name(
        "check_transaction_proof_successor_authorization.py"
    )
    spec = importlib.util.spec_from_file_location("retained_source_policy", policy_path)
    require(spec is not None and spec.loader is not None,
            "release source inventory policy cannot be loaded")
    policy = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = policy
    spec.loader.exec_module(policy)
    observed = policy.recompute_retained_proof_source_inventory(repository_root)
    require(isinstance(observed, dict), "release source inventory is not an object")
    return observed


def inventory_sha512(files: list[dict[str, Any]]) -> str:
    compact = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha512_bytes(compact)


def discover_repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def verifier_environment() -> dict[str, str]:
    tool_directories: list[str] = []
    for tool in ("cargo", "git"):
        executable = shutil.which(tool)
        require(executable is not None, f"retained verifier dependency missing: {tool}")
        directory = str(Path(executable).parent)
        if directory not in tool_directories:
            tool_directories.append(directory)
    for directory in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if directory not in tool_directories:
            tool_directories.append(directory)
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join(tool_directories),
        "TZ": "UTC",
    }
    for name in ("HOME", "CARGO_HOME", "RUSTUP_HOME"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def run_retained_verifier(
    binary: Path,
    arguments: tuple[str, ...],
    repository_root: Path,
) -> dict[str, Any]:
    label = f"{binary.name} {' '.join(arguments)}"
    try:
        result = subprocess.run(
            [str(binary), *arguments],
            check=False,
            close_fds=True,
            cwd=repository_root,
            env=verifier_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        reject(f"retained generator verifier could not run ({label}): {error}")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        reject(f"retained generator verifier rejected ({label}): {detail}")
    return parse_json_object(result.stdout, f"retained generator verifier ({label})")


def walk_exact(root: Path) -> tuple[set[PurePosixPath], set[PurePosixPath]]:
    require(root.exists(), f"retained artifact root missing: {root}")
    require(not root.is_symlink(), f"retained artifact root is a symlink: {root}")
    files: set[PurePosixPath] = set()
    directories: set[PurePosixPath] = set()
    for current, dir_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        current_rel = PurePosixPath(current_path.relative_to(root).as_posix())
        if str(current_rel) != ".":
            directories.add(current_rel)
        for name in dir_names:
            child = current_path / name
            mode = os.lstat(child).st_mode
            require(not stat.S_ISLNK(mode), f"symlinked directory forbidden: {child}")
            require(stat.S_ISDIR(mode), f"non-directory entry in directory set: {child}")
        for name in file_names:
            child = current_path / name
            mode = os.lstat(child).st_mode
            require(not stat.S_ISLNK(mode), f"symlinked file forbidden: {child}")
            require(stat.S_ISREG(mode), f"non-regular file forbidden: {child}")
            files.add(PurePosixPath(child.relative_to(root).as_posix()))
    return files, directories


def read_u16(payload: bytes, offset: int) -> int:
    return int.from_bytes(payload[offset : offset + 2], "little")


def read_u32(payload: bytes, offset: int) -> int:
    return int.from_bytes(payload[offset : offset + 4], "little")


def read_u64(payload: bytes, offset: int) -> int:
    return int.from_bytes(payload[offset : offset + 8], "little")


def decode_compact_u32(payload: bytes, offset: int, label: str) -> tuple[int, int]:
    require(offset < len(payload), f"{label}: missing SCALE compact integer")
    first = payload[offset]
    mode = first & 3
    if mode == 0:
        return first >> 2, offset + 1
    if mode == 1:
        require(offset + 2 <= len(payload), f"{label}: truncated two-byte compact integer")
        encoded = int.from_bytes(payload[offset : offset + 2], "little")
        value = encoded >> 2
        require(value >= 1 << 6, f"{label}: noncanonical two-byte compact integer")
        return value, offset + 2
    if mode == 2:
        require(offset + 4 <= len(payload), f"{label}: truncated four-byte compact integer")
        encoded = int.from_bytes(payload[offset : offset + 4], "little")
        value = encoded >> 2
        require(1 << 14 <= value < 1 << 30, f"{label}: noncanonical four-byte compact integer")
        return value, offset + 4
    reject(f"{label}: big-integer SCALE compact mode is forbidden")


def check_route(payload: bytes, base: int, label: str) -> None:
    require(read_u16(payload, base + 10) == ROUTE["circuit_version"], f"{label}: circuit")
    require(read_u16(payload, base + 12) == ROUTE["crypto_suite"], f"{label}: crypto")
    require(read_u16(payload, base + 14) == ROUTE["family_id"], f"{label}: family")
    require(read_u16(payload, base + 16) == ROUTE["action_id"], f"{label}: action")
    require(payload[base + 18] == ROUTE["backend_id"], f"{label}: backend")
    require(payload[base + 19] == ROUTE["profile_id"], f"{label}: profile")
    require(read_u16(payload, base + 20) == ROUTE["domain_set"], f"{label}: domain")


def check_relation_program(
    program: bytes,
    relation_profile: RelationProfile = HISTORICAL_RELATION_PROFILE,
) -> None:
    require(relation_profile in SUPPORTED_RELATION_PROFILES,
            "unsupported pinned relation profile")
    require(len(program) == relation_profile.program_bytes
            and program.startswith(RELATION_MAGIC)
            and sha512_bytes(program) == relation_profile.program_sha512,
            "relation program differs from the pinned exact identity")


def parse_native_leaf(
    bundle: Path,
    *,
    relation_profile: RelationProfile = HISTORICAL_RELATION_PROFILE,
) -> dict[str, bytes | int]:
    check_relation_program((bundle / "relation-program.bin").read_bytes(), relation_profile)
    leaf = (bundle / "native-leaf.bin").read_bytes()
    proof = (bundle / "proof.bin").read_bytes()
    statement = (bundle / "public-statement.bin").read_bytes()
    binding = (bundle / "relation-binding.bin").read_bytes()
    ciphertexts = (bundle / "ciphertexts.bin").read_bytes()
    relation_digest = (bundle / "relation-digest.bin").read_bytes()
    network = (bundle / "network-id.bin").read_bytes()

    require(len(leaf) <= MAX_RPC_BYTES - RPC_HEADER_BYTES, "native leaf exceeds routed cap")
    require(len(leaf) >= NATIVE_FIXED_BYTES, "native leaf truncated")
    require(leaf[:8] == NATIVE_MAGIC, "native leaf magic")
    require(read_u16(leaf, 8) == 1, "native leaf grammar")
    check_route(leaf, 0, "native leaf")
    require(read_u16(leaf, 22) == PUBLIC_WORDS, "native leaf statement word count")
    require(read_u16(leaf, 24) == BINDING_LIMBS, "native leaf binding limb count")
    require(read_u16(leaf, 26) == 0, "native leaf reserved field")
    require(read_u32(leaf, 28) == NETWORK_ID, "native leaf network")
    proof_len = read_u32(leaf, 32)
    require(proof_len == len(proof), "native leaf proof length")
    require(leaf[36:84] == bytes.fromhex(relation_profile.digest_hex), "native leaf relation digest")
    require(read_u32(leaf, 84) == len(leaf), "native leaf total length")
    require(network == NETWORK_ID.to_bytes(4, "little"), "network-id.bin")
    require(relation_digest == bytes.fromhex(relation_profile.digest_hex), "relation-digest.bin")
    require(len(statement) == STATEMENT_BYTES, "public statement length")
    require(len(binding) == BINDING_BYTES, "relation binding length")
    for offset in range(0, len(statement), FIELD_BYTES):
        require(read_u64(statement, offset) < GOLDILOCKS_MODULUS,
                f"noncanonical public statement word {offset // FIELD_BYTES}")
    for offset in range(0, len(binding), FIELD_BYTES):
        require(read_u64(binding, offset) < GOLDILOCKS_MODULUS,
                f"noncanonical relation binding limb {offset // FIELD_BYTES}")
    output_flags = [read_u64(statement, 2 * FIELD_BYTES), read_u64(statement, 3 * FIELD_BYTES)]
    require(output_flags == [1, 1], "retained proof is not maximum-shape two-output")
    require(len(ciphertexts) == ACTIVE_OUTPUTS * CIPHERTEXT_BYTES, "ciphertext section length")
    statement_start = NATIVE_HEADER_BYTES
    binding_start = statement_start + STATEMENT_BYTES
    ciphertext_start = binding_start + BINDING_BYTES
    proof_start = ciphertext_start + len(ciphertexts)
    require(leaf[statement_start:binding_start] == statement, "statement not preserved in leaf")
    require(leaf[binding_start:ciphertext_start] == binding, "binding not preserved in leaf")
    require(leaf[ciphertext_start:proof_start] == ciphertexts, "ciphertexts not preserved in leaf")
    require(leaf[proof_start:] == proof, "proof not preserved in native leaf")
    require(proof.startswith(INNER_MAGIC), "inner proof magic")
    require(len(proof) <= PROJECTED_PROOF_BYTES < MAX_PROOF_BYTES, "proof size bound")
    return {"leaf": leaf, "proof": proof, "statement": statement, "binding": binding,
            "ciphertexts": ciphertexts, "proof_start": proof_start}


def parse_rpc_and_scale(bundle: Path, native: dict[str, bytes | int]) -> dict[str, bytes]:
    leaf = native["leaf"]
    proof = native["proof"]
    assert isinstance(leaf, bytes) and isinstance(proof, bytes)
    envelope = (bundle / "rpc-envelope.bin").read_bytes()
    inline = (bundle / "scale-inline-args.bin").read_bytes()
    require(len(envelope) <= PROJECTED_RPC_BYTES < MAX_RPC_BYTES, "RPC envelope size bound")
    require(len(inline) <= PROJECTED_SCALE_BYTES < MAX_SCALE_BYTES, "SCALE inline size bound")
    require(len(envelope) == RPC_HEADER_BYTES + len(leaf), "RPC envelope total length")
    require(envelope[:8] == RPC_MAGIC, "RPC envelope magic")
    require(read_u16(envelope, 8) == 1, "RPC envelope grammar")
    check_route(envelope, 0, "RPC envelope")
    require(envelope[22] == 1 and envelope[23] == 0, "RPC envelope mode/reserved")
    require(read_u32(envelope, 24) == len(proof), "RPC proof length")
    require(read_u32(envelope, 28) == len(leaf), "RPC leaf length")
    require(envelope[RPC_HEADER_BYTES:] == leaf, "native leaf not preserved in RPC envelope")
    require(envelope[-len(proof):] == proof, "proof not preserved in RPC envelope")
    inline_len, cursor = decode_compact_u32(inline, 0, "SCALE inline args")
    require(cursor == 4, "SCALE inline envelope length must use canonical four-byte mode")
    require(inline_len == len(envelope), "SCALE inline declared envelope length")
    require(inline[cursor:] == envelope, "RPC envelope not preserved in SCALE inline args")
    require(inline[-len(proof):] == proof, "proof not preserved in SCALE inline args")
    return {"envelope": envelope, "inline": inline}


def parse_pending_action(bundle: Path, transport: dict[str, bytes], proof: bytes) -> None:
    pending = (bundle / "pending-action.bin").read_bytes()
    inline = transport["inline"]
    require(len(pending) <= PROJECTED_PENDING_BYTES < MAX_PENDING_BYTES,
            "pending action size bound")
    require(len(pending) - len(inline) == 225, "pending action outer overhead")
    require(len(pending) >= 225, "pending action truncated")
    require(pending[:48] != bytes(48), "pending action transaction hash is zero")
    require(read_u16(pending, 48) == ROUTE["circuit_version"], "pending binding circuit")
    require(read_u16(pending, 50) == ROUTE["crypto_suite"], "pending binding crypto")
    require(read_u16(pending, 52) == ROUTE["family_id"], "pending family")
    require(read_u16(pending, 54) == ROUTE["action_id"], "pending action")
    require(pending[56:104] == bytes(48), "pending legacy anchor")
    cursor = 104
    nullifiers, cursor = decode_compact_u32(pending, cursor, "pending nullifiers")
    commitments, cursor = decode_compact_u32(pending, cursor, "pending commitments")
    require(nullifiers == 0 and commitments == 0, "pending legacy state is not empty")
    hashes, cursor = decode_compact_u32(pending, cursor, "pending ciphertext hashes")
    require(hashes == ACTIVE_OUTPUTS, "pending ciphertext hash count")
    cursor += hashes * 48
    sizes, cursor = decode_compact_u32(pending, cursor, "pending ciphertext sizes")
    require(sizes == ACTIVE_OUTPUTS, "pending ciphertext size count")
    require(cursor + sizes * 4 <= len(pending), "pending ciphertext sizes truncated")
    observed_sizes = [read_u32(pending, cursor + index * 4) for index in range(sizes)]
    require(observed_sizes == [CIPHERTEXT_BYTES] * ACTIVE_OUTPUTS,
            "pending ciphertext sizes")
    cursor += sizes * 4
    args_len, args_start = decode_compact_u32(pending, cursor, "pending public args")
    args_end = args_start + args_len
    require(args_end + 9 == len(pending), "pending action exact consumption")
    require(pending[args_start:args_end] == inline, "SCALE inline args not preserved in pending action")
    require(pending[args_end:args_end + 8] == (0).to_bytes(8, "little"), "pending fee")
    require(pending[args_end + 8] == 0, "pending candidate artifact must be None")
    require(pending[args_end - len(proof):args_end] == proof,
            "proof not preserved in pending action")


def check_report(
    bundle: Path,
    role: str,
    manifest_proof: dict[str, Any],
    native: dict[str, bytes | int],
    transport: dict[str, bytes],
    source_inventory: dict[str, Any],
    generator: dict[str, Any],
    *,
    expected_source_revision: str = SOURCE_REVISION,
    relation_profile: RelationProfile = HISTORICAL_RELATION_PROFILE,
) -> dict[str, Any]:
    check_relation_program((bundle / "relation-program.bin").read_bytes(), relation_profile)
    report, _ = load_json_exact(bundle / "artifact-report.json")
    proof = native["proof"]
    leaf = native["leaf"]
    assert isinstance(proof, bytes) and isinstance(leaf, bytes)
    require(set(report) == EXPECTED_REPORT_KEYS, f"{role}: artifact report fields")
    require(report.get("schema") == REPORT_SCHEMA, f"{role}: artifact report schema")
    require(report.get("artifact_role") == role, f"{role}: artifact report role")
    require(report.get("retains_private_witness") is False, f"{role}: private witness retained")
    fixture = report.get("fixture", {})
    require(fixture == EXPECTED_FIXTURE, f"{role}: exact canonical coinbase fixture")
    identity = report.get("identity", {})
    require(identity == {
        "consensus_tuple": ROUTE,
        "inner_magic": INNER_MAGIC.decode(),
        "network_id": NETWORK_ID,
        "profile": EXPECTED_PROFILE,
        "relation_digest_hex": relation_profile.digest_hex,
        "relation_program": {
            "bytes": relation_profile.program_bytes,
            "magic": RELATION_MAGIC.decode(),
            "sha512": relation_profile.program_sha512,
        },
        "semantic_relation": RELATION_NAME,
        "transport": {
            "native_leaf_magic": NATIVE_MAGIC.decode(),
            "rpc_envelope_magic": RPC_MAGIC.decode(),
        },
    }, f"{role}: exact identity, profile, and transport")
    require(report.get("geometry") == relation_profile.geometry,
            f"{role}: exact pinned relation geometry")
    sizes = report.get("bytes", {})
    expected_sizes = {
        "measured_inner_proof": len(proof),
        "native_leaf": len(leaf),
        "measured_rpc_envelope": len(transport["envelope"]),
        "measured_scale_inline_args": len(transport["inline"]),
        "measured_pending_action": (bundle / "pending-action.bin").stat().st_size,
        "projected_max_inner_proof": PROJECTED_PROOF_BYTES,
        "projected_max_rpc_envelope": PROJECTED_RPC_BYTES,
        "projected_max_scale_inline_args": PROJECTED_SCALE_BYTES,
        "projected_max_pending_action": PROJECTED_PENDING_BYTES,
        "relation_program": relation_profile.program_bytes,
    }
    for key, value in expected_sizes.items():
        require(sizes.get(key) == value, f"{role}: report byte field {key}")
    report_hashes = report.get("sha512", {})
    hash_files = {
        "ciphertexts": "ciphertexts.bin", "native_leaf": "native-leaf.bin",
        "pending_action": "pending-action.bin", "proof": "proof.bin",
        "public_statement": "public-statement.bin", "relation_binding": "relation-binding.bin",
        "relation_program": "relation-program.bin", "rpc_envelope": "rpc-envelope.bin",
        "scale_inline_action": "scale-inline-args.bin", "transcript_preamble": "transcript-preamble.bin",
    }
    for field, name in hash_files.items():
        require(report_hashes.get(field) == sha512_bytes((bundle / name).read_bytes()),
                f"{role}: report hash {field}")
    source = report.get("proof_source_inventory", {})
    require(source == source_inventory, f"{role}: complete source inventory differs from live source")
    provenance = report.get("generation_provenance", {})
    require(set(provenance) == {
        "artifact_role", "generator_binary_bytes", "generator_binary_sha512",
        "generator_source_path", "generator_source_sha512", "independence_scope",
        "process_id", "proof_sha512", "run_id_hex", "schema", "source_revision",
        "started_unix_seconds",
    }, f"{role}: provenance fields")
    require(provenance.get("schema") ==
            "hegemon-smallwood-poseidon2-v8-generation-provenance-v1",
            f"{role}: provenance schema")
    require(provenance.get("artifact_role") == role, f"{role}: provenance role")
    require(provenance.get("generator_binary_bytes") == generator["bytes"],
            f"{role}: generator bytes")
    require(provenance.get("generator_binary_sha512") == generator["sha512"],
            f"{role}: generator hash")
    require(provenance.get("generator_source_path") == GENERATOR_SOURCE,
            f"{role}: generator source")
    require(provenance.get("generator_source_sha512") == generator["source_sha512"],
            f"{role}: generator source hash")
    require(provenance.get("source_revision") == expected_source_revision,
            f"{role}: source revision")
    require(provenance.get("independence_scope") ==
            "informational_unattested_generation_metadata",
            f"{role}: generation independence scope")
    require(isinstance(provenance.get("process_id"), int)
            and provenance["process_id"] > 0, f"{role}: generator process id")
    require(isinstance(provenance.get("started_unix_seconds"), int)
            and provenance["started_unix_seconds"] > 0, f"{role}: generation start time")
    require(provenance.get("proof_sha512") == sha512_bytes(proof),
            f"{role}: provenance proof hash")
    require(provenance.get("run_id_hex") == manifest_proof.get("generation_run_id_hex"),
            f"{role}: generation run id")
    transition = report.get("provenance_transition", {})
    require(transition == {
        "claim": "two_distinct_source_verified_proofs",
        "generation_independence_established": False,
        "kind": "direct_generation",
        "parent_artifact_report_bytes": 0,
        "parent_artifact_report_path": None,
        "parent_artifact_report_sha512": None,
        "pending_action_bytes_preserved_from_parent": False,
        "proof_bytes_preserved_from_parent": False,
        "schema": "hegemon-smallwood-poseidon2-v8-provenance-transition-v1",
        "source_inventory_root_sha512": source_inventory["root_sha512"],
        "source_inventory_scope": "generation_start_and_prepublication",
        "v4_verifier_binary_bytes": 0,
        "v4_verifier_binary_sha512": None,
        "v4_verifier_output_sha512": None,
    }, f"{role}: exact provenance transition")
    verification = report.get("verification", {})
    require(set(verification) == EXPECTED_VERIFICATION_KEYS,
            f"{role}: verification fields")
    require(verification.get("same_smz9_bytes_at_every_layer") is True,
            f"{role}: report carrier preservation")
    require(verification.get("source_factory_immediate") is True,
            f"{role}: immediate source verification")
    require(verification.get("readback_before_publish") is True,
            f"{role}: readback before publish")
    honest_map = verification.get("honest_map_audit", {})
    require(honest_map.get("production_verifier_accepts") is True,
            f"{role}: source verifier did not accept")
    require(honest_map.get("production_eligible") is False,
            f"{role}: retained report incorrectly claims production eligibility")
    require(honest_map.get("external_poseidon2_security_claim") is False
            and honest_map.get("external_sha512_qrom_claim") is False,
            f"{role}: retained report asserts external security")
    proof_record = manifest_proof.get("proof", {})
    require(proof_record.get("bytes") == len(proof), f"{role}: manifest proof bytes")
    require(proof_record.get("sha512") == sha512_bytes(proof), f"{role}: manifest proof hash")
    randomness = report.get("proof_randomness_binding", {})
    require(randomness == {
        "wire_salt_hex": manifest_proof.get("wire_salt_hex"),
        "decs_transcript_root_hex": manifest_proof.get("decs_transcript_root_hex"),
    }, f"{role}: proof randomness binding")
    require(report.get("successor_evidence") == {
        "proof": {
            "bytes": len(proof), "id": role, "kind": "proof", "path": "proof.bin",
            "sha512": sha512_bytes(proof),
        },
        "relation_program": {
            "bytes": relation_profile.program_bytes, "id": "relation_program", "kind": "program",
            "path": "relation-program.bin", "sha512": relation_profile.program_sha512,
        },
    }, f"{role}: exact successor evidence")
    return report


def check_chain_report(
    root: Path,
    artifact_root: PurePosixPath,
    roles: dict[str, PurePosixPath],
    manifest: dict[str, Any],
    reports: dict[str, dict[str, Any]],
    *,
    relation_profile: RelationProfile = HISTORICAL_RELATION_PROFILE,
) -> dict[str, Any]:
    require(relation_profile in SUPPORTED_RELATION_PROFILES,
            "unsupported pinned relation profile")
    chain_record = manifest.get("chain_verification", {})
    require(chain_record.get("path") == "retained-chain-verification.json",
            "chain report path")
    chain_path = root / "retained-chain-verification.json"
    raw = chain_path.read_bytes()
    require(chain_record.get("bytes") == len(raw), "chain report bytes")
    require(chain_record.get("sha512") == sha512_bytes(raw), "chain report hash")
    chain, _ = load_json_exact(chain_path)
    require(set(chain) == EXPECTED_CHAIN_KEYS, "chain report fields")
    require(chain.get("schema") == CHAIN_SCHEMA, "chain report schema")
    require(chain.get("semantic_relation") == RELATION_NAME, "chain semantic relation")
    require(chain.get("relation_program_magic") == RELATION_MAGIC.decode(), "chain relation magic")
    require(chain.get("relation_program_sha512") == relation_profile.program_sha512,
            "chain relation hash")
    require(chain.get("production_capability_enabled") is False,
            "chain report incorrectly enables production")
    require(chain.get("fixture_group") == EXPECTED_FIXTURE["fixture_group"],
            "chain fixture group")
    require(chain.get("canonical_input_positions") == EXPECTED_FIXTURE["input_positions"],
            "chain canonical input positions")
    require(chain.get("coinbase_input_values") == EXPECTED_FIXTURE["input_values"],
            "chain coinbase input values")
    require(chain.get("coinbase_opening_words_sha512") ==
            EXPECTED_FIXTURE["coinbase_opening_words_sha512"],
            "chain coinbase opening hashes")
    require(chain.get("coinbase_input_commitments_hex") ==
            EXPECTED_FIXTURE["input_note_commitments_hex"],
            "chain coinbase commitments")
    require(chain.get("input_merkle_path_sha512") ==
            EXPECTED_FIXTURE["input_merkle_path_sha512"],
            "chain input Merkle paths")
    require(chain.get("input_merkle_root_hex") == EXPECTED_FIXTURE["merkle_root_hex"],
            "chain input Merkle root")
    require(chain.get("parent_height") == EXPECTED_FIXTURE["parent_height"],
            "chain parent height")
    for field in ("same_public_statement", "same_source_fixture_witness_definition",
                  "same_proof_bytes_preserved_inside_each_carrier",
                  "proof_witness_is_not_extracted_or_published", "parent_height_nonzero",
                  "distinct_proof_hashes", "distinct_wire_salts", "distinct_transcript_roots"):
        require(chain.get(field) is True, f"chain report field {field}")
    for role, chain_key in (("retained_proof_primary", "primary"),
                            ("retained_proof_independent", "independent")):
        report = reports[role]
        entry = chain.get(chain_key, {})
        require(entry.get("artifact") == str(artifact_root / roles[role]),
                f"chain {chain_key} artifact path")
        require(entry.get("proof_sha512") == report["sha512"]["proof"],
                f"chain {chain_key} proof hash")
        require(entry.get("wire_salt_hex") == report["proof_randomness_binding"]["wire_salt_hex"],
                f"chain {chain_key} wire salt")
        require(entry.get("decs_transcript_root_hex") ==
                report["proof_randomness_binding"]["decs_transcript_root_hex"],
                f"chain {chain_key} transcript root")
        require(entry.get("source_factory_verified") is True,
                f"chain {chain_key} source verification")
        expected_carriers = {
            "native_leaf": report["sha512"]["native_leaf"],
            "pending_action": report["sha512"]["pending_action"],
            "rpc_envelope": report["sha512"]["rpc_envelope"],
            "scale_inline_action": report["sha512"]["scale_inline_action"],
        }
        require(entry.get("carrier_sha512") == expected_carriers,
                f"chain {chain_key} carrier hashes")
    return chain


def run_frozen_verifiers(
    root: Path,
    artifact_root: PurePosixPath,
    roles: dict[str, PurePosixPath],
    proof_records: list[dict[str, Any]],
    chain_report: dict[str, Any],
    repository_root: Path,
    *,
    relation_profile: RelationProfile = HISTORICAL_RELATION_PROFILE,
    expected_generation_provenance: dict[str, dict[str, Any]] | None = None,
) -> None:
    require(relation_profile in SUPPORTED_RELATION_PROFILES,
            "unsupported pinned relation profile")
    by_role = {record["artifact_role"]: record for record in proof_records}
    primary_argument = str(artifact_root / roles[ROLE_ORDER[0]])
    independent_argument = str(artifact_root / roles[ROLE_ORDER[1]])
    for generator_path in GENERATOR_PATHS:
        binary = root / Path(generator_path.as_posix())
        for role in ROLE_ORDER:
            record = by_role[role]
            artifact_argument = str(artifact_root / roles[role])
            verification = run_retained_verifier(
                binary, ("verify-v5", artifact_argument), repository_root
            )
            require(verification.get("artifact") == artifact_argument,
                    f"{generator_path}: verifier artifact path")
            require(verification.get("artifact_schema") == REPORT_SCHEMA,
                    f"{generator_path}: verifier artifact schema")
            require(verification.get("proof_bytes") == record["proof"]["bytes"],
                    f"{generator_path}: verifier proof bytes")
            require(verification.get("proof_sha512") == record["proof"]["sha512"],
                    f"{generator_path}: verifier proof SHA-512")
            require(verification.get("proof_randomness_binding") == {
                "decs_transcript_root_hex": record["decs_transcript_root_hex"],
                "wire_salt_hex": record["wire_salt_hex"],
            }, f"{generator_path}: verifier proof randomness binding")
            require(verification.get("fixture") == EXPECTED_FIXTURE,
                    f"{generator_path}: verifier canonical fixture")
            require(verification.get("semantic_relation") == RELATION_NAME,
                    f"{generator_path}: verifier semantic relation")
            require(verification.get("relation_program_sha512") == relation_profile.program_sha512,
                    f"{generator_path}: verifier relation program")
            require(verification.get("consensus_tuple") == ROUTE,
                    f"{generator_path}: verifier route")
            if expected_generation_provenance is not None:
                require(verification.get("generation_provenance")
                        == expected_generation_provenance[role],
                        f"{generator_path}: verifier generation provenance")
            for field in ("source_factory_verified", "canonical_transport_verified",
                          "canonical_pending_action_verified", "hash_manifest_verified"):
                require(verification.get(field) is True,
                        f"{generator_path}: verifier field {field}")
        computed_chain = run_retained_verifier(
            binary,
            ("verify-chain", primary_argument, independent_argument),
            repository_root,
        )
        require(computed_chain == chain_report,
                f"{generator_path}: independently computed chain report differs")


def verify_manifest(
    manifest_path: Path | None = None,
    *,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    repo = (repository_root if repository_root is not None else discover_repository_root()).resolve()
    expected_manifest_path = repo / Path(MANIFEST_PATH.as_posix())
    supplied_path = manifest_path if manifest_path is not None else expected_manifest_path
    if not supplied_path.is_absolute():
        supplied_path = repo / supplied_path
    require(supplied_path == expected_manifest_path,
            "manifest must use the fixed repository-relative pointer path")
    ensure_no_symlink_path(repo, MANIFEST_PATH, "fixed retained manifest")
    require(supplied_path.resolve() == expected_manifest_path,
            "fixed retained manifest canonical path mismatch")
    manifest_metadata = os.lstat(supplied_path)
    require(stat.S_ISREG(manifest_metadata.st_mode), "fixed retained manifest is not regular")
    require(manifest_metadata.st_nlink == 1, "fixed retained manifest hardlink forbidden")
    manifest_file_identity = (manifest_metadata.st_dev, manifest_metadata.st_ino)
    manifest, manifest_raw = load_json_exact(supplied_path, canonical=True)
    require(set(manifest) == {"artifact_root", "authority", "chain_verification",
                              "common_payload", "files", "generator_binaries", "identity",
                              "payload_file_count", "payload_inventory_sha512",
                              "payload_total_bytes", "proofs", "schema", "source_inventory"},
            "manifest top-level fields")
    require(manifest["schema"] == MANIFEST_SCHEMA, "manifest schema")
    require(manifest["authority"] == AUTHORITY, "manifest authority must remain empty and false")
    identity = manifest["identity"]
    require(identity == {
        "inner_magic": INNER_MAGIC.decode(), "network_id": NETWORK_ID,
        "relation_digest_hex": RELATION_DIGEST_HEX, "relation_magic": RELATION_MAGIC.decode(),
        "relation_program_bytes": RELATION_BYTES, "relation_program_sha512": RELATION_SHA512,
        "route": ROUTE, "semantic_relation": RELATION_NAME,
    }, "manifest identity")

    source_inventory = manifest["source_inventory"]
    require(isinstance(source_inventory, dict), "manifest source inventory")
    require(set(source_inventory) == {"file_count", "root_sha512", "schema", "total_bytes"},
            "manifest source inventory fields")
    require(source_inventory["schema"] == SOURCE_INVENTORY_SCHEMA,
            "manifest source inventory schema")
    source_root = require_lower_hex(source_inventory["root_sha512"], 64,
                                    "manifest source inventory root")
    require(source_root != "0" * 128, "manifest source inventory root must be nonzero")
    require(isinstance(source_inventory["file_count"], int)
            and source_inventory["file_count"] > 0, "manifest source inventory count")
    require(isinstance(source_inventory["total_bytes"], int)
            and source_inventory["total_bytes"] > 0, "manifest source inventory bytes")
    live_source_inventory = recompute_source_inventory(repo)
    live_source_summary = {
        key: live_source_inventory[key]
        for key in ("file_count", "root_sha512", "schema", "total_bytes")
    }
    require(source_inventory == live_source_summary,
            "manifest source inventory differs from the frozen release source")

    artifact_root = relative_path(manifest["artifact_root"], "manifest artifact root")
    require(artifact_root.parent == ARTIFACT_PARENT,
            "manifest artifact root must be a direct child of the fixed artifact parent")
    require(artifact_root.name == f"hgv8rp03-{source_root[:16]}",
            "manifest artifact root does not bind the source inventory root")
    root = ensure_no_symlink_path(repo, artifact_root, "retained artifact root")
    require(root.resolve() == repo / Path(artifact_root.as_posix()),
            "retained artifact canonical path mismatch")

    file_entries = manifest["files"]
    require(isinstance(file_entries, list) and file_entries, "manifest files")
    require(file_entries == sorted(file_entries, key=lambda entry: entry.get("path", "")),
            "manifest files must be path sorted")
    expected_files: set[PurePosixPath] = set()
    retained_file_identities: set[tuple[int, int]] = {manifest_file_identity}
    total_bytes = 0
    for index, entry in enumerate(file_entries):
        require(isinstance(entry, dict)
                and set(entry) == {"bytes", "executable", "path", "sha512"},
                f"manifest file entry {index} fields")
        relative = relative_path(entry["path"], f"manifest file entry {index}")
        require(relative not in expected_files, f"duplicate manifest file {relative}")
        expected_files.add(relative)
        file_path = ensure_no_symlink_path(root, relative, f"retained file {relative}")
        file_metadata = os.lstat(file_path)
        mode = file_metadata.st_mode
        require(stat.S_ISREG(mode), f"retained file is not regular {relative}")
        require(file_metadata.st_nlink == 1, f"retained hardlink forbidden: {relative}")
        file_identity = (file_metadata.st_dev, file_metadata.st_ino)
        require(file_identity not in retained_file_identities,
                f"retained filesystem alias forbidden: {relative}")
        retained_file_identities.add(file_identity)
        raw = file_path.read_bytes()
        require(isinstance(entry["bytes"], int) and entry["bytes"] == len(raw),
                f"retained byte length {relative}")
        require(require_lower_hex(entry["sha512"], 64, f"retained SHA-512 {relative}")
                == sha512_bytes(raw), f"retained SHA-512 {relative}")
        require(type(entry["executable"]) is bool
                and entry["executable"] is bool(mode & 0o111),
                f"retained executable bit {relative}")
        total_bytes += len(raw)
    actual_files, actual_directories = walk_exact(root)
    require(actual_files == expected_files, "retained root file set differs from manifest")
    expected_directories = {parent for path_item in expected_files for parent in path_item.parents
                            if str(parent) != "."}
    require(actual_directories == expected_directories,
            "retained root directory set differs from manifest")
    require(manifest["payload_file_count"] == len(file_entries), "payload file count")
    require(manifest["payload_total_bytes"] == total_bytes, "payload total bytes")
    require(manifest["payload_inventory_sha512"] == inventory_sha512(file_entries),
            "payload inventory hash")

    generator = manifest["generator_binaries"]
    require(isinstance(generator, dict)
            and set(generator) == {"byte_identical", "bytes", "paths", "sha512",
                                   "source_path", "source_sha512"},
            "generator binary record fields")
    require(generator["byte_identical"] is True, "generator binaries not marked identical")
    require(generator["bytes"] == GENERATOR_BINARY_BYTES,
            "generator binary bytes differ from frozen identity")
    require(generator["sha512"] == GENERATOR_BINARY_SHA512,
            "generator binary SHA-512 differs from frozen identity")
    require(generator["source_path"] == GENERATOR_SOURCE, "generator source path")
    require_lower_hex(generator["source_sha512"], 64, "generator source SHA-512")
    expected_generator_paths = list(GENERATOR_PATHS)
    require(generator["paths"] == [str(path) for path in expected_generator_paths],
            "generator binary paths")
    generator_source_path = ensure_no_symlink_path(
        repo, PurePosixPath(GENERATOR_SOURCE), "generator source"
    )
    generator_source_metadata = os.lstat(generator_source_path)
    require(stat.S_ISREG(generator_source_metadata.st_mode), "generator source is not regular")
    require(generator_source_metadata.st_nlink == 1, "generator source hardlink forbidden")
    require((generator_source_metadata.st_dev, generator_source_metadata.st_ino)
            not in retained_file_identities, "generator source aliases a retained payload")
    generator_source_payload = generator_source_path.read_bytes()
    require(sha512_bytes(generator_source_payload) == GENERATOR_SOURCE_SHA512,
            "live generator source SHA-512 differs from the frozen generator source")
    require(generator["source_sha512"] == GENERATOR_SOURCE_SHA512,
            "generator record source SHA-512")
    source_entries = live_source_inventory.get("entries")
    require(isinstance(source_entries, list), "live source inventory entries")
    generator_source_entries = [
        entry for entry in source_entries
        if isinstance(entry, dict) and entry.get("path") == GENERATOR_SOURCE
    ]
    require(generator_source_entries == [{
        "bytes": len(generator_source_payload),
        "path": GENERATOR_SOURCE,
        "sha512": GENERATOR_SOURCE_SHA512,
    }], "generator source is not exactly bound by the live source inventory")
    generator_payloads = [(root / Path(path.as_posix())).read_bytes()
                          for path in expected_generator_paths]
    require(generator_payloads[0] == generator_payloads[1],
            "generator binaries are not byte identical")
    require(all(len(payload) == generator["bytes"]
                and sha512_bytes(payload) == generator["sha512"]
                for payload in generator_payloads), "generator binary digest")

    proof_records = manifest["proofs"]
    require(isinstance(proof_records, list) and len(proof_records) == 2,
            "manifest proof records")
    require([entry.get("artifact_role") for entry in proof_records] == list(ROLE_ORDER),
            "manifest proof record order")
    require(proof_records == [EXPECTED_PROOF_RECORDS[role] for role in ROLE_ORDER],
            "manifest proof records differ from the exact frozen proof identities")
    roles: dict[str, PurePosixPath] = {}
    for record in proof_records:
        role = record["artifact_role"]
        require(set(record) == {"artifact_role", "decs_transcript_root_hex", "directory",
                                "generation_run_id_hex", "proof", "wire_salt_hex"},
                f"{role}: manifest proof fields")
        directory = relative_path(record["directory"], f"{role}: manifest directory")
        require(directory.parent == PurePosixPath(role),
                f"{role}: proof directory must be a direct child of its role")
        proof_record = record["proof"]
        require(isinstance(proof_record, dict) and set(proof_record) == {"bytes", "sha512"},
                f"{role}: proof record fields")
        proof_sha512 = require_lower_hex(proof_record["sha512"], 64,
                                         f"{role}: proof SHA-512")
        require(isinstance(proof_record["bytes"], int) and proof_record["bytes"] > 0,
                f"{role}: proof bytes")
        require(directory.name == f"smz9-{proof_sha512[:24]}",
                f"{role}: proof directory does not bind its proof hash")
        require_lower_hex(record["generation_run_id_hex"], 32, f"{role}: generation run id")
        require_lower_hex(record["wire_salt_hex"], 32, f"{role}: wire salt")
        require_lower_hex(record["decs_transcript_root_hex"], 64,
                          f"{role}: transcript root")
        roles[role] = directory

    allowed_payload_files = {
        *expected_generator_paths,
        PurePosixPath("retained-chain-verification.json"),
    }
    for role in ROLE_ORDER:
        allowed_payload_files.update(roles[role] / name for name in ARTIFACT_FILES)
    require(len(allowed_payload_files) == 29, "internal retained payload allowlist length")
    require(expected_files == allowed_payload_files,
            "retained manifest payload path allowlist")

    common_record = manifest["common_payload"]
    require(set(common_record) == set(COMMON_FILES), "common payload file names")
    for name in COMMON_FILES:
        primary_payload = (root / Path(roles[ROLE_ORDER[0]].as_posix()) / name).read_bytes()
        independent_payload = (root / Path(roles[ROLE_ORDER[1]].as_posix()) / name).read_bytes()
        require(primary_payload == independent_payload, f"common payload differs: {name}")
        require(common_record[name] == {"bytes": len(primary_payload),
                                        "sha512": sha512_bytes(primary_payload)},
                f"common payload manifest record: {name}")
    relation_program = (root / Path(roles[ROLE_ORDER[0]].as_posix())
                        / "relation-program.bin").read_bytes()
    require(len(relation_program) == RELATION_BYTES and relation_program.startswith(RELATION_MAGIC)
            and sha512_bytes(relation_program) == RELATION_SHA512,
            "relation program payload")

    reports: dict[str, dict[str, Any]] = {}
    proof_hashes: list[str] = []
    salts: list[str] = []
    transcript_roots: list[str] = []
    source_inventories: list[dict[str, Any]] = []
    for record in proof_records:
        role = record["artifact_role"]
        bundle = root / Path(roles[role].as_posix())
        require({item.name for item in bundle.iterdir()} == ARTIFACT_FILES,
                f"{role}: artifact bundle file set")
        native = parse_native_leaf(bundle)
        transport = parse_rpc_and_scale(bundle, native)
        proof = native["proof"]
        assert isinstance(proof, bytes)
        parse_pending_action(bundle, transport, proof)
        report = check_report(bundle, role, record, native, transport,
                              live_source_inventory, generator)
        reports[role] = report
        proof_hashes.append(sha512_bytes(proof))
        salts.append(record["wire_salt_hex"])
        transcript_roots.append(record["decs_transcript_root_hex"])
        source_inventories.append(report["proof_source_inventory"])
    require(len(set(proof_hashes)) == 2, "retained proof hashes are not distinct")
    require(len(set(salts)) == 2, "retained proof salts are not distinct")
    require(len(set(transcript_roots)) == 2, "retained transcript roots are not distinct")
    require(len({record["generation_run_id_hex"] for record in proof_records}) == 2,
            "retained generation run ids are not distinct")
    require(source_inventories[0] == source_inventories[1],
            "retained proof source inventories differ")
    chain_report = check_chain_report(root, artifact_root, roles, manifest, reports)
    run_frozen_verifiers(root, artifact_root, roles, proof_records, chain_report, repo)
    for entry in file_entries:
        relative = PurePosixPath(entry["path"])
        payload = (root / Path(relative.as_posix())).read_bytes()
        require(len(payload) == entry["bytes"] and sha512_bytes(payload) == entry["sha512"],
                f"retained payload changed during verification: {relative}")
    require(recompute_source_inventory(repo) == live_source_inventory,
            "release source inventory changed during retained artifact verification")
    require(sha512_bytes(manifest_raw) == EXPECTED_MANIFEST_SHA512,
            "fixed retained manifest differs from the exact frozen manifest SHA-512")

    return {
        "artifact_root": str(artifact_root),
        "generator_binary_sha512": generator["sha512"],
        "manifest_sha512": sha512_bytes(manifest_raw),
        "payload_file_count": len(file_entries),
        "payload_inventory_sha512": manifest["payload_inventory_sha512"],
        "payload_total_bytes": total_bytes,
        "production_capability_enabled": False,
        "proofs": [
            {"artifact_role": record["artifact_role"], "bytes": record["proof"]["bytes"],
             "sha512": record["proof"]["sha512"]}
            for record in proof_records
        ],
        "relation_program_sha512": RELATION_SHA512,
        "schema": "hegemon-smallwood-poseidon2-v8-retained-manifest-check-v2",
        "source_inventory_root_sha512": source_root,
        "verified": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, help="manifest path; defaults to the frozen source path")
    args = parser.parse_args(argv)
    try:
        summary = verify_manifest(args.manifest)
    except (OSError, RetainedArtifactError, KeyError, TypeError, ValueError) as error:
        print(f"retained artifact verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
