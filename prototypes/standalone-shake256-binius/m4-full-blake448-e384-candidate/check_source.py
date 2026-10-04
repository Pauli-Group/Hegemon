#!/usr/bin/env python3
"""Dependency-free, source-only contract for the disk-gated M4 candidate."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STANDALONE = ROOT.parent
REPO = ROOT.parents[2]
BINIUS = STANDALONE / "binius64"
MIXED = (ROOT / "src" / "mixed_candidate.rs").read_text()
LIB = (ROOT / "src" / "lib.rs").read_text()
MAIN = (ROOT / "src" / "main.rs").read_text()
README = (ROOT / "README.md").read_text()
CARGO = (ROOT / "Cargo.toml").read_text()
TX_CARGO = (REPO / "circuits" / "transaction" / "Cargo.toml").read_text()
KERNEL_CARGO = (REPO / "protocol" / "kernel" / "Cargo.toml").read_text()
CARGO_LOCK = (REPO / "Cargo.lock").read_text()
SCALAR = (REPO / "circuits" / "transaction" / "src" / "full_blake2b448_relation.rs").read_text()
MANIFEST = (REPO / "protocol" / "kernel" / "src" / "manifest.rs").read_text()
MANIFEST_STATE_V1 = (
    REPO / "protocol" / "kernel" / "src" / "stablecoin_manifest_commitment_v1.rs"
).read_text()
HASH384 = (REPO / "crypto" / "hash384" / "src" / "lib.rs").read_text()


def require(fragment: str, source: str = MIXED) -> None:
    if fragment not in source:
        raise AssertionError(f"missing source contract: {fragment}")


def canonical_binius_inventory() -> list[Path]:
    roots = [BINIUS / "Cargo.toml", BINIUS / "Cargo.lock", BINIUS / "rust-toolchain.toml"]
    roots.extend(path for path in (BINIUS / "crates").rglob("*") if path.is_file())
    return sorted(roots, key=lambda path: path.relative_to(BINIUS).as_posix())


def canonical_binius_tree_digest() -> tuple[int, str]:
    hasher = hashlib.sha512(b"hegemon.binius64.local-tree.v1\0")
    inventory = canonical_binius_inventory()
    for path in inventory:
        relative = path.relative_to(BINIUS).as_posix().encode("utf-8")
        payload = path.read_bytes()
        hasher.update(len(relative).to_bytes(4, "big"))
        hasher.update(relative)
        hasher.update(len(payload).to_bytes(8, "big"))
        hasher.update(payload)
    return len(inventory), hasher.hexdigest()


def source_constant(name: str) -> str:
    match = re.search(rf'{name}: &str =\s*\n?\s*"([0-9a-f]+)"', MIXED)
    if match is None:
        raise AssertionError(f"missing hexadecimal source constant {name}")
    return match.group(1)


def main() -> None:
    for fragment in (
        "CANDIDATE_STATEMENT_BYTES: usize = scalar_candidate::CANDIDATE_STATEMENT_BYTES",
        "CANDIDATE_STATEMENT_WORDS",
        "CANDIDATE_CONSENSUS_STATE_WORDS: usize = 50",
        "CANDIDATE_STATEMENT_WORDS + CANDIDATE_CONSENSUS_STATE_WORDS",
        "CANDIDATE_PRIVATE_WORDS",
        "V6_CANONICAL_CIPHERTEXT_BYTES",
        "scalar_candidate::CANDIDATE_STATEMENT_MAGIC",
        "scalar_candidate::CANDIDATE_STATEMENT_GRAMMAR",
        "scalar_candidate::CANDIDATE_PROFILE_TAG",
        "scalar_candidate::candidate_statement_bytes",
        "scalar_candidate::decode_candidate_statement_bytes",
        "SecretHashProfile::Blake2b448Mixed",
        "SecretHashProfile::Sha3_512SplitControl",
        "mux_one_hot_blake2b448",
        "mux_one_hot_sha3_512_truncated448",
        "counter_lo",
        "counter_hi",
        "final_mask",
        "intent_frame",
        "balance_tag_frame",
        "ciphertext_frame",
        "candidate_dummy_frame(builder, role, slot_index, lane)",
        "payload = [0u8; 117]",
        "constrain_auth_non_hash(builder, &wires.base, &modes, &policy, false)",
        "auth.init_or_lock.input_nonempty",
        "pub const WINNER: Option<SecretHashProfile> = None",
        "pub const PRODUCTION_AUTHORIZED: bool = false",
        "pub const E384_PCS_CHANNEL_INTEGRATED: bool = false",
        "*b\"HGF6ST02\"",
        "*b\"HGF6HR02\"",
        "*b\"HGR6RM02\"",
        "*b\"HGV6PB02\"",
        "79_128",
        "90_600",
        "10_752",
        "16_128",
        "raw_hash_and_words",
        "raw_blake_addition_linear_words",
        "source_static_constraint_ledger",
        "265_963",
        "327_437",
        "bmul_constraints: 452",
        "bmul_constraints: 444",
        "hash_invocation_registry",
        "hash_invocation_registry_is_exact",
        "CandidateFrameWidth::AuthorizationMux",
        "ACTIVE_STABLECOIN_POLICY_TUPLE_SCALE_BYTES: usize = 61",
        "ACTIVE_STABLECOIN_POLICY_HASH_BYTES: usize = 48",
        "ACTIVE_STABLECOIN_MANIFEST_COMMITMENT_BYTES: usize =",
        "STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_WORDS",
        "hegemon.kernel.stablecoin-manifest-state.v1",
        "hegemon.kernel.stablecoin-policy.v2",
        "LIVE_STABLECOIN_BINDING_WORDS",
        "candidate_public_words_at::<LIVE_STABLECOIN_BINDING_WORDS>",
        "ACTIVE_STABLECOIN_MANIFEST_ADAPTER_INTEGRATED: bool = true",
        "ACTIVE_STABLECOIN_LIFECYCLE_CONSTRAINTS_COMPILED: bool = false",
        "ACTIVE_STABLECOIN_MANIFEST_MEMBERSHIP_GRAPH_COMPILED: bool = false",
        "STRICT_STABLECOIN_PQ_MARGIN: bool = false",
        "M4_AGGREGATE_RELATION_ARTIFACT_VERIFIED: bool = false",
        'include_bytes!("../../../../protocol/kernel/src/manifest.rs")',
        '"../../../../protocol/kernel/src/stablecoin_manifest_commitment_v1.rs"',
        'include_bytes!("../../../../crypto/hash384/src/lib.rs")',
        "bind_invocation_kind",
        "bind_output_binding",
        "bind_frame_width",
        "HashLoweringAudit",
        "HashLoweringCoverage",
        "hash_lowering_coverage",
        "lowering.lower_ordinary",
        "lowering.lower_authorization_mux",
        "lowering.finish()",
        "scalar_vs_m4_all_83_calls_all_modes_all_masks_and_mutations",
        "scalar_and_m4_reject_all_47_invalid_mask_mode_pairs_per_profile",
        "compile_full_blake2b448_candidate",
        "ActivityFlagsMismatch",
        "ConsensusStateRequired",
        "generate_witness_with_consensus_state",
        "constrain_candidate_stablecoin_consensus_state",
        "stable.state.manifest_commitment",
        "stable.state.height",
        "stable.state.lifecycle_started",
        "stable.state.lifecycle_not_retired",
        "stable.state.oracle_fresh",
        "stable.state.issuance_within_limit",
        "LOCAL_NON_HASH_CONSTRAINT_GROUPS: [&str; 20]",
        "HASH_LINK_CONSTRAINT_GROUPS: [&str; 7]",
        "CONSENSUS_STATE_SEAM_CONSTRAINT_GROUPS: [&str; 9]",
        "HOST_ORACLE_ONLY_GROUPS: [&str; 4]",
        "COUNTERFEIT_MUTATION_MATRIX: [CounterfeitMutationCase; 20]",
        "consensus_state_seam_counterfeit_matrix_is_fail_closed_at_its_exact_boundary",
    ):
        require(fragment)

    for scalar_fragment in (
        '*b"HX448C02"',
        '*b"HX448C01"',
        '*b"nt.b4481"',
        '*b"nf.b4481"',
        '*b"mk.s4481"',
        '*b"sk.b44a1"',
        '*b"sk.b44b1"',
        '*b"pl.b4481"',
        '*b"au.b44a1"',
        '*b"au.b44b1"',
        '*b"in.s4481"',
        '*b"bl.s4481"',
        '*b"ct.s4481"',
        '*b"lane.A01"',
        '*b"lane.B01"',
        "pub fn hash_calls(&self) -> &[ExecutableHashCall]",
        "pub fn exact_call_spec(",
        "pub fn verify_against_spec(&self, spec: &CallSpec)",
        "FULL_BLAKE2B448_AGGREGATE_CONSTRAINT_RELATION_COMPILED: bool = false",
        "FULL_BLAKE2B448_STRICT_STABLECOIN_PQ_MARGIN: bool = false",
        "CANDIDATE_STATEMENT_BYTES: usize = 869",
        "LIVE_STABLECOIN_BINDING_BYTES: usize = 48",
        "live_stablecoin_policy_tuple_scale_bytes",
        "compile_full_blake2b448_candidate_with_stablecoin_protocol_manifest",
        "StablecoinProtocolManifestView",
        "validate_stablecoin_protocol_manifest_view",
        "StablecoinConsensusStateSeam",
        "validate_stablecoin_consensus_state_seam",
        "stablecoin_consensus_state_seam_from_protocol_manifest",
        "STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES",
        "manifest.stablecoin_policies",
        "Call 74 remains the private accumulator-authorization policy hash",
    ):
        require(scalar_fragment, SCALAR)

    if 'git = "https://github.com/binius-zk/binius64.git"' in CARGO:
        raise AssertionError("candidate must resolve Binius from the exact local tree")
    for crate in (
        "circuits",
        "core",
        "frontend",
        "hash",
        "m4-prover",
        "m4-verifier",
        "prover",
        "transcript",
        "verifier",
    ):
        require(f'path = "../binius64/crates/{crate}"', CARGO)
    require('protocol-kernel = { path = "../../protocol/kernel" }', TX_CARGO)
    if "transaction-circuit" in KERNEL_CARGO:
        raise AssertionError("transaction-to-kernel stablecoin adapter introduces a dependency cycle")
    transaction_lock = CARGO_LOCK.split(
        '[[package]]\nname = "transaction-circuit"', 1
    )[1].split("[[package]]", 1)[0]
    require('"protocol-kernel"', transaction_lock)

    count, digest = canonical_binius_tree_digest()
    expected = source_constant("PINNED_BINIUS_TREE_SHA512")
    if count != 688 or digest != expected:
        raise AssertionError(
            f"local Binius tree drift: files={count} digest={digest} expected_files=688 expected={expected}"
        )

    if "M4MXST00" in MIXED or "M4MIXC00" in MIXED:
        raise AssertionError("candidate compiler must match scalar HX448C02 framing")
    if "raw_hash_nonlinear_words" in MIXED or "raw_hash_nonlinear_words" in MAIN:
        raise AssertionError("raw native AND projections must not be labeled generic nonlinear")
    if re.search(r"scalar\.hash_calls(?!\()", MIXED):
        raise AssertionError("candidate must consume the scalar relation through read-only accessors")
    if '"ciphertext[{index}].active_nonzero"' in MIXED:
        raise AssertionError("candidate must not add an active ciphertext-hash live predicate")
    if '"input[{index}].commitment_nonzero"' in MIXED:
        raise AssertionError("candidate must not add an input-note-commitment live predicate")
    if '"output[{index}].commitment_nonzero"' not in MIXED:
        raise AssertionError("composed admission requires the active public output commitment gate")
    if "keccak_f1600(builder" not in MIXED or "blake2b_compress(" not in MIXED:
        raise AssertionError("both direct Boolean primitive compilers must be present")
    lowering_body = MIXED.split("fn constrain_candidate_hashes", 1)[1].split(
        "fn candidate_note_frame", 1
    )[0]
    if "secret_hash56(" in lowering_body or "shake256_448_words(" in lowering_body:
        raise AssertionError("all 83 relation calls must pass through the exact typed lowering audit")
    if "lowering.finish()" not in lowering_body:
        raise AssertionError("the exact typed lowering audit must close all 83 call indices")
    if MIXED.count("authorization_mux_hash(") != 5:
        raise AssertionError("expected four call sites plus one auth-mux definition")
    if "--compile-geometry" not in MAIN or "HEGEMON_M4_ALLOW_COMPILE_GEOMETRY" not in MAIN:
        raise AssertionError("compiled geometry must stay explicitly disk-gated")
    if "not compiled, measured, proved" not in README:
        raise AssertionError("README must preserve the source-only claim boundary")

    exact_offsets = {
        "OFFSET_STABLE_POLICY": 485,
        "OFFSET_STABLE_ORACLE": 533,
        "OFFSET_STABLE_ATTESTATION": 581,
        "OFFSET_BALANCE_TAG": 629,
        "OFFSET_ACTIVATION": 685,
        "OFFSET_PROFILE": 698,
        "OFFSET_DOMAIN_SET": 699,
        "OFFSET_CHAIN_ID": 701,
        "OFFSET_GENESIS_ID": 757,
        "OFFSET_RULES_HASH": 813,
    }
    for name, value in exact_offsets.items():
        require(f"pub const {name}: usize = {value};")
        require(f"pub const {name}: usize = {value};", SCALAR)
    if "pub const CANDIDATE_STATEMENT_GRAMMAR: u16 = 2;" not in SCALAR:
        raise AssertionError("mixed-width scalar grammar must be exactly two")
    if "pub const CANDIDATE_STATEMENT_MAGIC: [u8; 8] = *b\"HX448C02\";" not in SCALAR:
        raise AssertionError("mixed-width scalar must use the fresh diagnostic magic")
    if "pub const RETIRED_DIAGNOSTIC_STATEMENT_MAGIC: [u8; 8] = *b\"HX448C01\";" not in SCALAR:
        raise AssertionError("the 56-byte diagnostic magic must remain explicitly retired")
    for field in ("policy_hash", "oracle_commitment", "attestation_commitment"):
        if f"pub {field}: Digest384" not in SCALAR:
            raise AssertionError(f"scalar {field} is not an exact 48-byte field")
    if MIXED.count("candidate_public_words_at::<LIVE_STABLECOIN_BINDING_WORDS>") != 3:
        raise AssertionError("M4 must bind exactly three direct six-word stablecoin fields")
    state_layout_fragments = (
        "STATE_SEAM_VERSION_WORD: usize = 0",
        "STATE_EXPECTED_HEIGHT_WORD: usize = 1",
        "STATE_PROVIDED_HEIGHT_WORD: usize = 2",
        "STATE_ENTRY_INDEX_WORD: usize = 3",
        "STATE_ENTRY_PRESENT_WORD: usize = 4",
        "STATE_MIN_COLLATERAL_WORDS: std::ops::Range<usize> = 8..10",
        "STATE_MAX_MINT_WORDS: std::ops::Range<usize> = 10..12",
        "STATE_POLICY_HASH_WORDS: std::ops::Range<usize> = 19..25",
        "STATE_ORACLE_COMMITMENT_WORDS: std::ops::Range<usize> = 25..31",
        "STATE_ATTESTATION_COMMITMENT_WORDS: std::ops::Range<usize> = 31..37",
        "STATE_EXPECTED_MANIFEST_COMMITMENT_WORDS: std::ops::Range<usize> = 38..44",
        "STATE_PROVIDED_MANIFEST_COMMITMENT_WORDS: std::ops::Range<usize> = 44..50",
    )
    for fragment in state_layout_fragments:
        require(fragment)
    state_body = MIXED.split(
        "fn constrain_candidate_stablecoin_consensus_state(", 1
    )[1].split("fn constrain_candidate_balance(", 1)[0]
    for label in (
        "stable.state.disabled",
        "stable.state.version",
        "stable.state.entry_present.enabled",
        "stable.state.manifest_commitment",
        "stable.state.expected_manifest_commitment_nonzero",
        "stable.state.provided_manifest_commitment_nonzero",
        "stable.state.height",
        "stable.state.asset",
        "stable.state.policy_version",
        "stable.state.policy_hash",
        "stable.state.oracle_commitment",
        "stable.state.attestation_commitment",
        "stable.state.active",
        "stable.state.attestation_not_disputed",
        "stable.state.retired_absent_zero",
        "stable.state.lifecycle_started",
        "stable.state.lifecycle_not_retired",
        "stable.state.oracle_not_future",
        "stable.state.oracle_fresh",
        "stable.state.issuance_nonzero",
        "stable.state.issuance_within_limit",
    ):
        require(label, state_body)
    for forbidden in (
        "blake2b384",
        "stablecoin_manifest_state_commitment_v1(",
        "stablecoin_manifest_state_entry_v1_bytes(",
    ):
        if forbidden in state_body:
            raise AssertionError(
                f"uncompiled manifest hash/membership graph leaked into non-hash seam: {forbidden}"
            )
    if "if decoded.stablecoin.enabled" not in MIXED or "ConsensusStateRequired" not in MIXED:
        raise AssertionError("enabled stablecoin witness generation must require the typed state seam")
    for name, expected in (
        ("LOCAL_NON_HASH_CONSTRAINT_GROUPS", 20),
        ("HASH_LINK_CONSTRAINT_GROUPS", 7),
        ("CONSENSUS_STATE_SEAM_CONSTRAINT_GROUPS", 9),
        ("HOST_ORACLE_ONLY_GROUPS", 4),
    ):
        body = MIXED.split(f"pub const {name}", 1)[1].split("];", 1)[0]
        actual = len(re.findall(r'^\s*"[^"]+",$', body, flags=re.MULTILINE))
        if actual != expected:
            raise AssertionError(f"{name} entry-count drift: {actual} != {expected}")
    matrix_body = MIXED.split("pub const COUNTERFEIT_MUTATION_MATRIX", 1)[1].split("];", 1)[0]
    m4_rejects = matrix_body.count("disposition: CounterfeitDisposition::M4Reject")
    host_only = matrix_body.count("disposition: CounterfeitDisposition::HostOracleOnly")
    if (m4_rejects, host_only) != (16, 4):
        raise AssertionError(
            f"counterfeit disposition drift: M4={m4_rejects} host={host_only}"
        )
    scalar_intent_spec = SCALAR.split("INTENT_CALL => call_spec_from_role(", 1)[1].split(
        "BALANCE_CALL => call_spec_from_role(", 1
    )[0]
    if "\n            720,\n" not in scalar_intent_spec:
        raise AssertionError("scalar call 79 must freeze the exact 720-byte grammar-two intent frame")
    if MIXED.count("CandidateFrameWidth::Exact(720)") < 2:
        raise AssertionError("M4 registries must freeze the exact 720-byte grammar-two intent frame")
    scalar_shape = SCALAR.split("fn validate_authorization_activity_shape(", 1)[1].split(
        "fn resolve_authorization(", 1
    )[0]
    if "let nonempty =" not in scalar_shape or "if !nonempty || !valid" not in scalar_shape:
        raise AssertionError("scalar authorization shape helper must reject the all-empty mask")
    for rejection in (
        "PolicyMissing",
        "PolicyInactive",
        "PolicyNotLive",
        "AssetMismatch",
        "PolicyHashMismatch",
        "PolicyVersionMismatch",
        "OracleCommitmentMismatch",
        "AttestationCommitmentMismatch",
        "AttestationDisputed",
        "OracleStale",
        "IssuanceZero",
        "IssuanceOverLimit",
    ):
        require(f"LiveStablecoinPolicyRejection::{rejection}", SCALAR)
    for branch in ("ordinary_statement", "burn_manifest", "mint_manifest"):
        require(branch)
    for manifest_search_fragment in (
        "for entry in &view.manifest.stablecoin_policies",
        "u64::from(entry.asset_id) == asset_id || entry.policy_hash() == policy_hash",
        "native admission accepts when any plausible manifest member passes",
    ):
        require(manifest_search_fragment, SCALAR)

    tuple61 = bytes.fromhex(
        "e9030000010000000100000000000000"
        "60e31600000000000000000000000000"
        "00ca9a3b000000000000000000000000"
        "ffffffffffffffff0100000000"
    )
    domain = b"hegemon.kernel.stablecoin-policy.v2"
    transcript = (
        b"hegemon.blake2b-384.frame-v1"
        + len(domain).to_bytes(8, "little")
        + domain
        + len(tuple61).to_bytes(8, "little")
        + tuple61
    )
    digest384 = hashlib.blake2b(transcript, digest_size=48).hexdigest()
    expected384 = "4e36d2e5728b9b3a1eb473aac318800434bf3947817410a281d04e8ea6b68ed133bc48c3570db5c3935126aa76be2100"
    if len(tuple61) != 61 or len(transcript) != 140 or digest384 != expected384:
        raise AssertionError(
            f"live stablecoin KAT drift: tuple={len(tuple61)} transcript={len(transcript)} digest={digest384}"
        )
    require(expected384, SCALAR)
    require("Blake2b::<U48>::new()", HASH384)
    require("KERNEL_STABLECOIN_POLICY_V2", MANIFEST)
    require("blake2b_384_domain_hash(domains::KERNEL_STABLECOIN_POLICY_V2", MANIFEST)

    for kernel_state_fragment in (
        "pub struct StablecoinManifestStateCommitmentV1",
        "STABLECOIN_MANIFEST_STATE_V1_VERSION: u32 = 1",
        "STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES: usize = 48",
        "STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_WORDS",
        "STABLECOIN_MANIFEST_STATE_V1_ENTRY_BYTES: usize = 183",
        "hegemon.kernel.stablecoin-manifest-state.v1",
        "STABLECOIN_MANIFEST_STATE_V1_KERNEL_GLOBAL_ROOT_INTEGRATED: bool = false",
        "STABLECOIN_MANIFEST_STATE_V1_PRODUCTION_AUTHORIZED: bool = false",
        "stablecoin_manifest_state_entry_v1_bytes",
        "stablecoin_manifest_state_commitment_v1",
        "protocol_manifest_stablecoin_state_commitment_v1",
        "pub fn from_le_words",
        "pub fn to_le_words",
    ):
        require(kernel_state_fragment, MANIFEST_STATE_V1)
    commitment_body = MANIFEST_STATE_V1.split(
        "pub fn stablecoin_manifest_state_commitment_v1(", 1
    )[1].split("pub fn protocol_manifest_stablecoin_state_commitment_v1(", 1)[0]
    if ".sort" in commitment_body:
        raise AssertionError("manifest-state v1 must bind exact ProtocolManifest vector order")

    entry183 = b"".join(
        (
            (1001).to_bytes(4, "little"),
            (7).to_bytes(4, "little"),
            (0x0102030405060708).to_bytes(8, "little"),
            (1_500_000).to_bytes(16, "little"),
            (1_000_000_000).to_bytes(16, "little"),
            (120).to_bytes(8, "little"),
            (42).to_bytes(8, "little"),
            (10).to_bytes(8, "little"),
            b"\x01",
            (1000).to_bytes(8, "little"),
            (3).to_bytes(4, "little"),
            b"\x01",
            bytes([0x11]) * 48,
            bytes([0x22]) * 48,
            b"\x00",
        )
    )
    manifest_domain = b"hegemon.kernel.stablecoin-manifest-state.v1"
    manifest_transcript = (
        b"hegemon.blake2b-384.frame-v1"
        + len(manifest_domain).to_bytes(8, "little")
        + manifest_domain
        + (4).to_bytes(8, "little")
        + (1).to_bytes(4, "little")
        + (4).to_bytes(8, "little")
        + (1).to_bytes(4, "little")
        + len(entry183).to_bytes(8, "little")
        + entry183
    )
    manifest_digest = hashlib.blake2b(manifest_transcript, digest_size=48).hexdigest()
    expected_manifest_digest = (
        "c7101239692a8743b4f55073f16eddd3c54f3618f79d78ede2b4a2469d0fea6"
        "fa16503bf6f74cc3ae53d6f674d9b27a1"
    )
    if len(entry183) != 183 or manifest_digest != expected_manifest_digest:
        raise AssertionError(
            "manifest-state v1 KAT drift: "
            f"entry={len(entry183)} digest={manifest_digest}"
        )
    for prose in (
        "79,128",
        "90,600",
        "11,472",
        "10,752",
        "16,128",
        "265,963",
        "327,437",
        "452 BMUL",
        "444 BMUL",
        "61,474",
        "8 BMUL",
        "HX448C02",
        "HX448C01",
        "WINNER=None",
        "61-byte SCALE tuple",
        "48-byte RFC 7693 BLAKE2b-384",
        "six public 64-bit words",
        "50-word typed consensus-state seam",
        "total M4 public input",
        "20 local non-hash groups",
        "seven transaction hash",
        "nine consensus-state seam groups",
        "20-case counterfeit matrix",
        "host-oracle-only",
        "hegemon.kernel.stablecoin-manifest-state.v1",
        "Hash call 74 remains the private accumulator",
        "current source manifest's sole stablecoin entry is `active=false`",
        "STRICT_STABLECOIN_PQ_MARGIN",
        "M4_AGGREGATE_RELATION_ARTIFACT_VERIFIED=false",
        "machine-enforced aggregate source/digest",
    ):
        require(prose, README)
    for stale in (
        "89,880",
        "only 720",
        "0.795%",
        "one-AND Shift",
        "960 nonlinear",
        "M4MXST00",
        "M4MIXC00",
        "auth.kA1",
        "auth.nB1",
    ):
        if stale in README or stale in (ROOT / "EXECPLAN.md").read_text():
            raise AssertionError(f"stale candidate prose: {stale}")
    for stale in ("same exact 893-byte", "three 56-byte values"):
        if stale in README:
            raise AssertionError(f"stale candidate README prose: {stale}")

    external_api = [line for line in LIB.splitlines() if line.startswith("pub ")]
    if external_api != ["pub mod mixed_candidate;"]:
        raise AssertionError(f"stale F4 authority remains public: {external_api}")

    print(
        "mixed M4 source contract: pass "
        "(statement_words=109 state_words=50 public_words=159 "
        "constraint_groups=20+7+9 host_only=4 mutations=16+4 "
        f"binius_files={count} binius_tree_sha512={digest})"
    )


if __name__ == "__main__":
    main()
