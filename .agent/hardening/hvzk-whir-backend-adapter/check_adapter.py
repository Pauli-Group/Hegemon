#!/usr/bin/env python3
"""Dependency-free source gate for the fail-closed WHIR backend adapter.

This checker performs no build, proof generation, dependency fetch, or proof
size estimate. It pins source identities, independently recomputes the
odd-field relation identity and candidate equal-half geometry, exercises the
wire/hash facade with mutations, and requires every production authority bit
to remain false.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PLONKY3 = Path("/Users/pldd/.cargo/git/checkouts/plonky3-7d8a3b21a665a86f/5df89ee")

WIRE_MAGIC = b"HGWAWH01"
STATEMENT_MAGIC = b"HGWAST01"
WIRE_VERSION = 1
STATEMENT_VERSION = 1
DOMAIN_SET_VERSION = 1
HASH_SUITE_ID = 2
WIRE_HEADER_BYTES = 168
STATEMENT_HEADER_BYTES = 92
SECTION_HEADER_BYTES = 8
HX_STATEMENT_BYTES = 869
STATE_BYTES = 400
PUBLIC_BYTES = 1_269
PRIVATE_BYTES = 9_672
MAX_BODY = 16 * 1024 * 1024
MAX_SECTION = 8 * 1024 * 1024
MAX_SECTIONS = 4_096
MAX_ENVELOPE = 17 * 1024 * 1024
GOLDILOCKS = 0xFFFF_FFFF_0000_0001
MAX_SIGNED = (1 << 61) - 1

EXPECTED_CIRCUIT = 17_537
EXPECTED_SUITE = 17_538
EXPECTED_FAMILY = 17_539
EXPECTED_ACTION = 17_540
EXPECTED_NETWORK = 0x0102_0304
EXPECTED_BACKEND = 69
EXPECTED_PROFILE = 70
EXPECTED_HX_DOMAIN = 17_543

RELATION_DIGEST = bytes.fromhex(
    "81f88eb0afd355bbd50d90d0760b65e341b4b490a29af3d5e0a8acf1721e4279"
    "2bd547fd62559263f1c70edf365fb482fde2f88117c3ae98b2360934a3c75254"
)
PROFILE_RECORD = (
    b"hegemon.hvzk-whir-backend-adapter.source.v1\0"
    b"plonky3=5df89eeadae18d6935bb874f8a92808dcc200c9d\0"
    b"relation=81f88eb0afd355bbd50d90d0760b65e341b4b490a29af3d5e0a8acf1721e4279"
    b"2bd547fd62559263f1c70edf365fb482fde2f88117c3ae98b2360934a3c75254\0"
    b"field=goldilocks\0public_bits=10152\0private_bits=77376\0"
    b"wire=HGWAWH01/HGWAST01/v1\0hash=SHA-512+SHAKE256-512\0"
    b"goldilocks_extension=degree5-source-feasible-security-unselected\0production=false"
)
HASH_MAGIC = b"HGWAHS01"
HASH_DOMAIN = b"hegemon.hvzk-whir.backend-adapter.source.v1"

ROLES = {
    0x0101,
    0x0102,
    0x0103,
    0x0201,
    0x0202,
    0x0203,
    0x0204,
    0x0205,
    0x0206,
    0x0207,
    0x0208,
    0x0209,
    0x020A,
    0x020B,
}
ROLE_INDEX = {role: index for index, role in enumerate(sorted(ROLES))}


class GateFailure(RuntimeError):
    pass


class WireFailure(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise GateFailure(detail)


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def frame(role: int, parts: Iterable[bytes]) -> bytes:
    parts = tuple(parts)
    return (
        HASH_MAGIC
        + len(HASH_DOMAIN).to_bytes(2, "little")
        + HASH_DOMAIN
        + role.to_bytes(2, "little")
        + len(parts).to_bytes(2, "little")
        + b"".join(len(part).to_bytes(8, "little") + part for part in parts)
    )


def shake_role(role: int, *parts: bytes) -> bytes:
    return hashlib.shake_256(frame(role, parts)).digest(64)


def shake_xof_role(role: int, output_bytes: int, *parts: bytes) -> bytes:
    if not 1 <= output_bytes <= 4_096:
        raise WireFailure("security_salt_output_too_large")
    return hashlib.shake_256(frame(role, parts)).digest(output_bytes)


def sha512_role(role: int, *parts: bytes) -> bytes:
    return hashlib.sha512(frame(role, parts)).digest()


PROFILE_DIGEST = shake_role(1, PROFILE_RECORD)
SOURCE_ATTESTATION = sha512_role(
    2,
    b"5df89eeadae18d6935bb874f8a92808dcc200c9d",
    RELATION_DIGEST,
    PROFILE_RECORD,
)


def check_source_pins() -> None:
    pins = json.loads((HERE / "source_pins.json").read_text())
    result = subprocess.run(
        ["git", "-C", str(PLONKY3), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    require(result.stdout.strip() == pins["plonky3_checkout_head"], "Plonky3 HEAD drift")
    for entry in pins["plonky3_files"]:
        path = PLONKY3 / entry["path"]
        require(path.is_file(), f"missing pinned Plonky3 source {entry['path']}")
        require(path.stat().st_size == entry["bytes"], f"Plonky3 byte-size drift: {entry['path']}")
        require(sha512_file(path) == entry["sha512"], f"Plonky3 SHA-512 drift: {entry['path']}")
    for entry in pins["repository_files"]:
        path = REPO / entry["path"]
        require(path.is_file(), f"missing pinned repository source {entry['path']}")
        require(path.stat().st_size == entry["bytes"], f"repository byte-size drift: {entry['path']}")
        require(sha512_file(path) == entry["sha512"], f"repository SHA-512 drift: {entry['path']}")


def relation_digest(manifest_bytes: bytes) -> bytes:
    domain = b"hegemon.hx448c02.odd-field-r1cs.relation-manifest.v1\0"
    return hashlib.shake_256(domain + len(manifest_bytes).to_bytes(8, "big") + manifest_bytes).digest(64)


def check_relation_contract() -> None:
    manifest_bytes = (REPO / ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    certificate = json.loads(
        (REPO / ".agent/hardening/hvzk-whir-odd-field-r1cs/certificate.json").read_text()
    )
    require(relation_digest(manifest_bytes) == RELATION_DIGEST, "odd-field relation digest drift")
    require(
        certificate["relation_manifest_digest_shake256_512"] == RELATION_DIGEST.hex(),
        "odd-field certificate relation digest drift",
    )
    require(manifest["public_input_grammar"]["l_public_bits"] == 10_152, "public bit contract drift")
    require(manifest["public_input_grammar"]["statement"]["bytes"] == 869, "HX statement width drift")
    require(manifest["public_input_grammar"]["consensus_state_seam"]["words"] == 50, "state seam width drift")
    require(manifest["private_input_grammar"]["bytes"] == PRIVATE_BYTES, "private byte contract drift")
    require(manifest["private_input_grammar"]["private_bits"] == 77_376, "private bit contract drift")
    require(manifest["public_input_grammar"]["bit_order_within_byte"] == "least-significant-bit first", "public bit order drift")
    require(manifest["public_input_grammar"]["statement"]["public_bit_indices"] == [0, 6_951], "statement public-bit interval drift")
    require(manifest["public_input_grammar"]["consensus_state_seam"]["public_bit_indices"] == [6_952, 10_151], "state public-bit interval drift")
    expected_private_sections = [
        {"name": "input[0]", "offset_words": 0, "words": 261},
        {"name": "input[1]", "offset_words": 261, "words": 261},
        {"name": "output[0]", "offset_words": 522, "words": 30},
        {"name": "output[1]", "offset_words": 552, "words": 30},
        {"name": "authorization", "offset_words": 582, "words": 89},
        {"name": "ciphertext[0]", "offset_words": 671, "semantic_bytes": 2_147, "words": 269, "zero_pad_bytes": 5},
        {"name": "ciphertext[1]", "offset_words": 940, "semantic_bytes": 2_147, "words": 269, "zero_pad_bytes": 5},
    ]
    require(manifest["private_input_grammar"]["sections"] == expected_private_sections, "private section layout drift")
    state_fields = manifest["public_input_grammar"]["consensus_state_seam"]["fields"]
    expected_state_layout = [
        ("seam_version", 0, 1),
        ("expected_current_height", 1, 1),
        ("provided_current_height", 2, 1),
        ("selected_entry_index", 3, 1),
        ("selected_entry_present", 4, 1),
        ("asset_id", 5, 1),
        ("oracle_feed", 6, 1),
        ("attestation_id", 7, 1),
        ("min_collateral_ratio_ppm", 8, 2),
        ("max_mint_per_epoch", 10, 2),
        ("oracle_max_age", 12, 1),
        ("oracle_submitted_at", 13, 1),
        ("enabled_at", 14, 1),
        ("retired_present", 15, 1),
        ("retired_at", 16, 1),
        ("policy_version", 17, 1),
        ("active", 18, 1),
        ("policy_hash", 19, 6),
        ("oracle_commitment", 25, 6),
        ("attestation_commitment", 31, 6),
        ("attestation_disputed", 37, 1),
        ("expected_manifest_state_commitment_v1", 38, 6),
        ("provided_manifest_state_commitment_v1", 44, 6),
    ]
    require(
        [(field["name"], field["offset_words"], field["words"]) for field in state_fields]
        == expected_state_layout,
        "consensus-state field layout drift",
    )
    statement_fields = manifest["public_input_grammar"]["statement"]["fields"]
    cursor = 0
    for field in statement_fields:
        require(field["offset_bytes"] == cursor, f"statement field gap/overlap: {field['name']}")
        cursor += field["bytes"]
    require(cursor == HX_STATEMENT_BYTES, "statement field layout does not consume exactly 869 bytes")
    activation = manifest["screen_activation"]
    require(activation["circuit_version"] == EXPECTED_CIRCUIT, "activation circuit drift")
    require(activation["crypto_suite"] == EXPECTED_SUITE, "activation suite drift")
    require(activation["family_id"] == EXPECTED_FAMILY, "activation family drift")
    require(activation["action_id"] == EXPECTED_ACTION, "activation action drift")
    require(activation["network_id"] == EXPECTED_NETWORK, "activation network drift")
    require(activation["backend_id"] == EXPECTED_BACKEND, "activation backend drift")
    require(activation["proof_profile"] == EXPECTED_PROFILE, "activation profile drift")
    require(activation["domain_set"] == EXPECTED_HX_DOMAIN, "activation domain drift")
    require(manifest["host_only_boundary"]["compiled_rows"] == 0, "host-only boundary unexpectedly changed")
    require(manifest["host_only_boundary"]["disqualifies_full_production_relation"] is True, "host gate opened")
    require(manifest["authority"]["production_authorized"] is False, "odd-field production authority opened")

    geometry = manifest["hash_profiles"]["blake2b448-mixed"]["geometry"]
    expected = {
        "m_constraints": 20_457_227,
        "n_nonconstant_variables": 19_311_555,
        "l_public_variables": 10_152,
        "auxiliary_variables_total": 19_301_403,
        "derived_auxiliary_variables": 19_224_027,
        "private_transport_variables": 77_376,
        "matrix_nonzeros_total": 94_551_238,
        "z_vector_length_including_constant_one": 19_311_556,
    }
    for key, value in expected.items():
        require(geometry[key] == value, f"mixed R1CS geometry drift: {key}")

    # Derive the equal-half candidate; this is arithmetic identity only. The
    # paper ambiguity keeps authoritative_theorem_binding false.
    limit = max(
        geometry["l_public_variables"] + 1,
        geometry["auxiliary_variables_total"],
        (geometry["m_constraints"] + 1) // 2,
    )
    ell = 1 << (limit - 1).bit_length()
    require(ell == 1 << 25, "candidate equal-half ell drift")
    witness_padding = ell - geometry["auxiliary_variables_total"]
    public_padding = ell - (geometry["l_public_variables"] + 1)
    row_padding = 2 * ell - geometry["m_constraints"] - witness_padding
    embedded_nonzeros = geometry["matrix_nonzeros_total"] + 2 * witness_padding
    adapter = json.loads((HERE / "adapter_manifest.json").read_text())
    shape = adapter["cfw26_section11_candidate_shape"]
    derived = {
        "ell_equal_half": ell,
        "ell_log2": 25,
        "rows": 2 * ell,
        "columns": 2 * ell,
        "public_zero_padding": public_padding,
        "witness_zero_padding": witness_padding,
        "row_zero_padding": row_padding,
        "embedded_matrix_nonzeros": embedded_nonzeros,
        "one_base_field_half_raw_bytes": ell * 8,
        "total_assignment_base_field_raw_bytes": 2 * ell * 8,
        "one_e320_half_raw_bytes": ell * 40,
        "total_assignment_e320_raw_bytes": 2 * ell * 40,
    }
    for key, value in derived.items():
        require(shape[key] == value, f"adapter carrier source shape drift: {key}")
    require(shape["authoritative_theorem_binding"] is False, "candidate embedding promoted")
    require(shape["selected_pcs_polynomial_count"] is None, "hidden PCS polynomial-count assumption")

    retained = manifest["hash_profiles"]["blake2b448-mixed"]["cfw26_section11_candidate_embedding"]
    require(retained["candidate_embedding_present"] is True, "retained carrier candidate absent")
    require(retained["authoritative_cfw26_theorem_binding"] is False, "retained carrier promoted")
    require(retained["ell"] == ell and retained["n0"] == ell, "retained carrier ell drift")
    require(retained["embedded_geometry"]["rows"] == 2 * ell, "retained carrier rows drift")
    require(retained["embedded_geometry"]["columns_including_v_constant"] == 2 * ell, "retained carrier columns drift")
    require(retained["padding"]["public_parser_zero_elements"] == public_padding, "retained public padding drift")
    require(retained["padding"]["witness_zero_elements_and_rows"] == witness_padding, "retained witness padding drift")
    require(retained["padding"]["row_zero_padding"] == row_padding, "retained row padding drift")
    require(retained["embedded_geometry"]["matrix_nonzeros_total"] == embedded_nonzeros, "retained embedded nonzero drift")

    paper_shape = shape["paper_communication_shape"]
    expected_paper_shape = {
        "inner_mask_oracles": 3 * (25 + 1),
        "outer_mask_oracles": 25 + 1,
        "witness_oracles": 1,
        "encoded_oracles": 105,
        "zk_union_multiplier": 4 * 25 + 5,
        "step9_typing_defects": 2,
        "theorem_inherited": False,
        "plonky3_pcs_mapping_complete": False,
        "printed_endpoint_state_selects_s_at_one": False,
        "typed_main_form_row_defined": False,
        "printed_theorem_carrier_compatible": False,
        "required_endpoint_state": "pow(1)=(1,1,...)",
        "required_main_form_typing": "row_M(M,alpha)[b]=Mhat(alpha,b,1)",
    }
    require(paper_shape == expected_paper_shape, "CFW26 paper communication shape drift")


def check_plonky3_api_map() -> None:
    adapter = (PLONKY3 / "whir/src/pcs/zk/adapter.rs").read_text()
    config = (PLONKY3 / "whir/src/pcs/zk/config.rs").read_text()
    multilinear = (PLONKY3 / "commit/src/pcs/multilinear.rs").read_text()
    extensions = (PLONKY3 / "goldilocks/src/extension.rs").read_text()
    binomial = (PLONKY3 / "field/src/extension/binomial_extension.rs").read_text()
    hash_challenger = (PLONKY3 / "challenger/src/hash_challenger.rs").read_text()
    serializing_challenger = (PLONKY3 / "challenger/src/serializing_challenger.rs").read_text()
    serializing_hasher = (PLONKY3 / "symmetric/src/serializing_hasher.rs").read_text()
    compression = (PLONKY3 / "symmetric/src/compression.rs").read_text()
    mmcs = (PLONKY3 / "merkle-tree/src/mmcs/mod.rs").read_text()
    security_assumption = (PLONKY3 / "security/src/assumption.rs").read_text()
    protocol_parameters = (PLONKY3 / "whir/src/parameters/mod.rs").read_text()

    for token in (
        "pub struct HidingWhirPcs<EF, F, Dft, MT, Challenger, R>",
        "type Witness = Poly<F>;",
        "type OpeningProtocol = Vec<Point<EF>>;",
        "type Proof = ZkWhirProof<F, EF, MT>;",
        "fn commit(",
        "fn open(",
        "fn verify(",
    ):
        require(token in adapter, f"Plonky3 HidingWhirPcs API drift: {token}")
    require("pub fn new(" in config and "num_variables: usize" in config, "ZkWhirConfig API drift")
    require("pub trait MultilinearPcs" in multilinear, "MultilinearPcs trait drift")
    require("R1CS" not in adapter, "unexpected R1CS carrier appeared; review required")

    require("impl HasTwoAdicBinomialExtension<5> for Goldilocks" in extensions, "Goldilocks degree-5 route absent")
    require("impl BinomiallyExtendable<5> for Goldilocks" in extensions, "Goldilocks degree-5 field absent")
    require("const EXT_TWO_ADICITY: usize = 32" in extensions, "Goldilocks E320 two-adicity drift")
    require("HasTwoAdicBinomialExtension<6> for Goldilocks" not in extensions, "degree-6 route appeared; review required")
    require("HasTwoAdicBinomialExtension<8> for Goldilocks" not in extensions, "degree-8 route appeared; review required")
    require("impl<F: Field + HasTwoAdicBinomialExtension<D>, const D: usize> TwoAdicField" in binomial, "binomial TwoAdicField bound drift")

    require("pub struct HashChallenger<T, H, const OUT_LEN: usize>" in hash_challenger, "generic hash challenger drift")
    require("pub const fn new(initial_state: Vec<T>, hasher: H)" in hash_challenger, "hash challenger constructor drift")
    require("impl<F: PrimeField64, Inner: CanObserve<u8>> SerializingChallenger64" in serializing_challenger, "serializing challenger generic constructor drift")
    require("pub const fn new(inner: Inner)" in serializing_challenger, "serializing challenger new drift")
    require("HashChallenger<u8, H, 32>" in serializing_challenger, "32-byte convenience specialization drift")
    require("impl<F, Inner, const N: usize> CryptographicHasher<F, [u8; N]>" in serializing_hasher, "generic serializing hasher drift")
    require("pub struct CompressionFunctionFromHasher<H, const N: usize, const CHUNK: usize>" in compression, "generic compression map drift")
    require("pub struct MerkleTreeMmcs<P, PW, H, C, const N: usize, const DIGEST_ELEMS: usize>" in mmcs, "generic MMCS digest map drift")
    require("pub security_level: usize" in protocol_parameters, "local security target field drift")
    require("conjecturing capacity-rate list decodability" in security_assumption, "capacity conjecture boundary drift")
    require("Only the dominant term" in security_assumption, "Johnson dominant-term boundary drift")
    require("fn jb_prox_gaps_dominant_term_bits" in security_assumption, "Johnson f64 helper drift")

    local_map = (HERE / "src/plonky3_api.rs").read_text()
    for token in (
        "HashChallenger<u8,HegemonSha512Hasher,64>",
        "SerializingChallenger64<Goldilocks,HashChallenger<u8,HegemonSha512Hasher,64>>",
        "CompressionFunctionFromHasher<HegemonSha512Hasher,2,64>",
        "MerkleTreeMmcs<Goldilocks,u8",
        "LOCAL_KECCAK256_FALLBACK_ALLOWED: bool = false",
        "GOLDILOCKS_E320_SECURITY_SELECTED: bool = false",
        "GOLDILOCKS_E320_PCS_POLYNOMIAL_COUNT_SELECTED: Option<usize> = None",
        "PLONKY3_LOCAL_SECURITY_LEVEL_IS_STRICT_AUTHORITY: bool = false",
        "PLONKY3_CAPACITY_BOUND_PRODUCTION_ALLOWED: bool = false",
        "PLONKY3_JOHNSON_DOMINANT_TERM_PRODUCTION_ALLOWED: bool = false",
        "IndependentExactUniqueDecoding",
        "IndependentExactFullJohnson",
        "Plonky3JohnsonDominantTermF64Diagnostic",
        "validate_independent_security_certificate",
    ):
        require(token in local_map, f"local Plonky3 API map missing: {token}")


def parse_hx(raw: bytes) -> bool:
    if len(raw) != HX_STATEMENT_BYTES:
        raise WireFailure("public_argument_length")
    if raw[:8] != b"HX448C02":
        raise WireFailure("bad_hx_magic")
    if int.from_bytes(raw[8:10], "big") != 2:
        raise WireFailure("bad_hx_grammar")
    flags = raw[10:14]
    if any(flag not in (0, 1) for flag in flags):
        raise WireFailure("noncanonical_boolean")
    if not any(flags):
        raise WireFailure("all_empty_activity")
    for sign, magnitude_offset in ((raw[454], 455), (raw[476], 477)):
        if sign not in (0, 1) or raw[463] not in (0, 1):
            raise WireFailure("noncanonical_boolean")
        magnitude = int.from_bytes(raw[magnitude_offset : magnitude_offset + 8], "big")
        if magnitude > MAX_SIGNED or sign == 1 and magnitude == 0:
            raise WireFailure("signed_magnitude_range")
    expected = (
        int.from_bytes(raw[685:687], "big") == EXPECTED_CIRCUIT
        and int.from_bytes(raw[687:689], "big") == EXPECTED_SUITE
        and int.from_bytes(raw[689:691], "big") == EXPECTED_FAMILY
        and int.from_bytes(raw[691:693], "big") == EXPECTED_ACTION
        and int.from_bytes(raw[693:697], "big") == EXPECTED_NETWORK
        and raw[697] == EXPECTED_BACKEND
        and raw[698] == EXPECTED_PROFILE
        and int.from_bytes(raw[699:701], "big") == EXPECTED_HX_DOMAIN
        and any(raw[701:757])
        and any(raw[757:813])
        and any(raw[813:869])
    )
    if not expected:
        raise WireFailure("activation_mismatch")
    return raw[463] == 1


def parse_consensus_state(raw: bytes, stable_enabled: bool) -> None:
    if len(raw) != STATE_BYTES:
        raise WireFailure("public_argument_length")
    if not stable_enabled:
        if any(raw):
            raise WireFailure("disabled_state_seam_nonzero")
        return
    words = tuple(int.from_bytes(raw[offset : offset + 8], "little") for offset in range(0, STATE_BYTES, 8))
    if any(words[index] > 0xFFFF_FFFF for index in (0, 3, 5, 6, 17)):
        raise WireFailure("state_seam_noncanonical_u32")
    if any(words[index] not in (0, 1) for index in (4, 15, 18, 37)):
        raise WireFailure("state_seam_noncanonical_boolean")
    if words[15] == 0 and words[16] != 0:
        raise WireFailure("state_seam_noncanonical_retirement")


def parse_public(raw: bytes) -> None:
    if len(raw) != PUBLIC_BYTES:
        raise WireFailure("public_argument_length")
    stable_enabled = parse_hx(raw[:HX_STATEMENT_BYTES])
    parse_consensus_state(raw[HX_STATEMENT_BYTES:], stable_enabled)


def private_padding_offsets() -> tuple[int, ...]:
    return tuple(range(671 * 8 + 2_147, 940 * 8)) + tuple(
        range(940 * 8 + 2_147, PRIVATE_BYTES)
    )


def parse_private(raw: bytes) -> None:
    if len(raw) != PRIVATE_BYTES:
        raise WireFailure("private_transport_length")
    if any(raw[offset] for offset in private_padding_offsets()):
        raise WireFailure("nonzero_private_padding")


def derive_unselected_security_salt(
    transcript_state: bytes, statement_digest: bytes, lambda_bits: int
) -> bytes:
    if len(transcript_state) != 64:
        raise WireFailure("security_salt_state_length")
    if len(statement_digest) != 64:
        raise WireFailure("security_salt_statement_length")
    if lambda_bits < 656:
        raise WireFailure("security_salt_lambda_below_known_e320_floor")
    if lambda_bits % 8:
        raise WireFailure("security_salt_lambda_not_byte_aligned")
    output_bytes = lambda_bits // 8
    if output_bytes > 4_096:
        raise WireFailure("security_salt_output_too_large")
    return shake_xof_role(
        12,
        output_bytes,
        PROFILE_DIGEST,
        RELATION_DIGEST,
        transcript_state,
        statement_digest,
        lambda_bits.to_bytes(8, "little"),
    )


def make_public() -> bytes:
    raw = bytearray(PUBLIC_BYTES)
    raw[:8] = b"HX448C02"
    raw[8:10] = (2).to_bytes(2, "big")
    raw[10:14] = bytes((1, 1, 1, 1))
    raw[685:687] = EXPECTED_CIRCUIT.to_bytes(2, "big")
    raw[687:689] = EXPECTED_SUITE.to_bytes(2, "big")
    raw[689:691] = EXPECTED_FAMILY.to_bytes(2, "big")
    raw[691:693] = EXPECTED_ACTION.to_bytes(2, "big")
    raw[693:697] = EXPECTED_NETWORK.to_bytes(4, "big")
    raw[697] = EXPECTED_BACKEND
    raw[698] = EXPECTED_PROFILE
    raw[699:701] = EXPECTED_HX_DOMAIN.to_bytes(2, "big")
    raw[701] = 1
    raw[757] = 2
    raw[813] = 3
    return bytes(raw)


def encode_statement(public: bytes) -> bytes:
    parse_public(public)
    return struct.pack(
        "<8sHHIHHHH64sI",
        STATEMENT_MAGIC,
        STATEMENT_VERSION,
        STATEMENT_HEADER_BYTES,
        EXPECTED_NETWORK,
        EXPECTED_ACTION,
        EXPECTED_CIRCUIT,
        DOMAIN_SET_VERSION,
        HASH_SUITE_ID,
        RELATION_DIGEST,
        PUBLIC_BYTES,
    ) + public


def parse_statement(raw: bytes) -> dict[str, object]:
    if len(raw) < STATEMENT_HEADER_BYTES:
        raise WireFailure("truncated_statement_header")
    fields = struct.unpack_from("<8sHHIHHHH64sI", raw)
    magic, version, header, network, action, action_version, domain, suite, relation, public_len = fields
    if magic != STATEMENT_MAGIC:
        raise WireFailure("bad_statement_magic")
    if version != STATEMENT_VERSION:
        raise WireFailure("bad_statement_version")
    if header != STATEMENT_HEADER_BYTES:
        raise WireFailure("bad_statement_header_length")
    if domain != DOMAIN_SET_VERSION:
        raise WireFailure("bad_statement_domain_version")
    if suite != HASH_SUITE_ID:
        raise WireFailure("bad_statement_hash_suite")
    if relation != RELATION_DIGEST:
        raise WireFailure("statement_relation_binding_mismatch")
    if public_len != PUBLIC_BYTES:
        raise WireFailure("public_argument_length")
    expected = STATEMENT_HEADER_BYTES + public_len
    if len(raw) < expected:
        raise WireFailure("truncated_public_arguments")
    if len(raw) > expected:
        raise WireFailure("statement_trailing_bytes")
    if network != EXPECTED_NETWORK:
        raise WireFailure("network_binding_mismatch")
    if action != EXPECTED_ACTION:
        raise WireFailure("action_binding_mismatch")
    if action_version != EXPECTED_CIRCUIT:
        raise WireFailure("action_version_binding_mismatch")
    parse_public(raw[STATEMENT_HEADER_BYTES:])
    return {
        "network": network,
        "action": action,
        "action_version": action_version,
        "relation": relation,
        "public": raw[STATEMENT_HEADER_BYTES:],
    }


def encode_envelope(public: bytes, sections: tuple[tuple[int, int, bytes], ...]) -> bytes:
    statement = encode_statement(public)
    if not 1 <= len(sections) <= MAX_SECTIONS:
        raise WireFailure("section_count")
    next_instances = [0] * len(ROLES)
    body = bytearray()
    for role, instance, payload in sections:
        if role not in ROLES:
            raise WireFailure("unknown_section_role")
        index = ROLE_INDEX[role]
        if instance != next_instances[index]:
            raise WireFailure("noncanonical_section_instance")
        next_instances[index] += 1
        if not payload:
            raise WireFailure("empty_section_payload")
        if len(payload) > MAX_SECTION:
            raise WireFailure("section_too_large")
        body += struct.pack("<HHI", role, instance, len(payload)) + payload
    if len(body) > MAX_BODY:
        raise WireFailure("proof_body_too_large")
    total = WIRE_HEADER_BYTES + len(statement) + len(body)
    header = struct.pack(
        "<8sHHHH64sIHH64sIHHII",
        WIRE_MAGIC,
        WIRE_VERSION,
        WIRE_HEADER_BYTES,
        DOMAIN_SET_VERSION,
        HASH_SUITE_ID,
        PROFILE_DIGEST,
        EXPECTED_NETWORK,
        EXPECTED_ACTION,
        EXPECTED_CIRCUIT,
        RELATION_DIGEST,
        len(statement),
        len(sections),
        0,
        len(body),
        total,
    )
    return header + statement + body


def parse_envelope(raw: bytes) -> dict[str, object]:
    if len(raw) < WIRE_HEADER_BYTES:
        raise WireFailure("truncated_header")
    if len(raw) > MAX_ENVELOPE:
        raise WireFailure("envelope_too_large")
    fields = struct.unpack_from("<8sHHHH64sIHH64sIHHII", raw)
    (
        magic,
        version,
        header,
        domain,
        suite,
        profile,
        network,
        action,
        action_version,
        relation,
        statement_len,
        section_count,
        flags,
        body_len,
        total_len,
    ) = fields
    if magic != WIRE_MAGIC:
        raise WireFailure("bad_magic")
    if version != WIRE_VERSION:
        raise WireFailure("bad_wire_version")
    if header != WIRE_HEADER_BYTES:
        raise WireFailure("bad_header_length")
    if domain != DOMAIN_SET_VERSION:
        raise WireFailure("bad_domain_version")
    if suite != HASH_SUITE_ID:
        raise WireFailure("bad_hash_suite")
    if profile != PROFILE_DIGEST:
        raise WireFailure("profile_digest_mismatch")
    if relation != RELATION_DIGEST:
        raise WireFailure("relation_digest_mismatch")
    if flags:
        raise WireFailure("nonzero_reserved_flags")
    if statement_len != STATEMENT_HEADER_BYTES + PUBLIC_BYTES:
        raise WireFailure("statement_length")
    if not 1 <= section_count <= MAX_SECTIONS:
        raise WireFailure("section_count")
    if body_len > MAX_BODY:
        raise WireFailure("proof_body_too_large")
    expected_total = WIRE_HEADER_BYTES + statement_len + body_len
    if total_len != expected_total:
        raise WireFailure("declared_total_mismatch")
    if total_len > MAX_ENVELOPE:
        raise WireFailure("envelope_too_large")
    if len(raw) < total_len:
        raise WireFailure("truncated_envelope")
    if len(raw) > total_len:
        raise WireFailure("trailing_bytes")
    statement_end = WIRE_HEADER_BYTES + statement_len
    statement = parse_statement(raw[WIRE_HEADER_BYTES:statement_end])
    if network != statement["network"]:
        raise WireFailure("network_binding_mismatch")
    if action != statement["action"]:
        raise WireFailure("action_binding_mismatch")
    if action_version != statement["action_version"]:
        raise WireFailure("action_version_binding_mismatch")
    if relation != statement["relation"]:
        raise WireFailure("statement_relation_binding_mismatch")
    cursor = statement_end
    body_end = cursor + body_len
    next_instances = [0] * len(ROLES)
    sections: list[tuple[int, int, bytes]] = []
    for _ in range(section_count):
        if body_end - cursor < SECTION_HEADER_BYTES:
            raise WireFailure("truncated_section_header")
        role, instance, payload_len = struct.unpack_from("<HHI", raw, cursor)
        cursor += SECTION_HEADER_BYTES
        if role not in ROLES:
            raise WireFailure("unknown_section_role")
        index = ROLE_INDEX[role]
        if instance != next_instances[index]:
            raise WireFailure("noncanonical_section_instance")
        next_instances[index] += 1
        if payload_len == 0:
            raise WireFailure("empty_section_payload")
        if payload_len > MAX_SECTION:
            raise WireFailure("section_too_large")
        if body_end - cursor < payload_len:
            raise WireFailure("truncated_section_payload")
        sections.append((role, instance, raw[cursor : cursor + payload_len]))
        cursor += payload_len
    if cursor != body_end:
        raise WireFailure("proof_body_trailing_bytes")
    if encode_envelope(statement["public"], tuple(sections)) != raw:
        raise WireFailure("noncanonical_reencoding")
    return {"statement": statement, "sections": sections, "raw": raw}


@dataclass(frozen=True)
class Mutation:
    name: str
    expected: str
    apply: Callable[[bytes], bytes]


def set_bytes(offset: int, value: bytes) -> Callable[[bytes], bytes]:
    def mutate(raw: bytes) -> bytes:
        output = bytearray(raw)
        output[offset : offset + len(value)] = value
        return bytes(output)

    return mutate


def flip(offset: int) -> Callable[[bytes], bytes]:
    def mutate(raw: bytes) -> bytes:
        output = bytearray(raw)
        output[offset] ^= 1
        return bytes(output)

    return mutate


def set_many(*patches: tuple[int, bytes]) -> Callable[[bytes], bytes]:
    def mutate(raw: bytes) -> bytes:
        output = bytearray(raw)
        for offset, value in patches:
            output[offset : offset + len(value)] = value
        return bytes(output)

    return mutate


def mutation_suite(fixture: bytes) -> tuple[Mutation, ...]:
    statement = WIRE_HEADER_BYTES
    public = statement + STATEMENT_HEADER_BYTES
    state = public + HX_STATEMENT_BYTES
    body = statement + STATEMENT_HEADER_BYTES + PUBLIC_BYTES
    first_payload_len = int.from_bytes(fixture[body + 4 : body + 8], "little")
    second = body + SECTION_HEADER_BYTES + first_payload_len
    return (
        Mutation("truncate-header", "truncated_header", lambda raw: raw[: WIRE_HEADER_BYTES - 1]),
        Mutation("bad-magic", "bad_magic", flip(0)),
        Mutation("bad-wire-version", "bad_wire_version", set_bytes(8, (2).to_bytes(2, "little"))),
        Mutation("bad-header-length", "bad_header_length", set_bytes(10, (167).to_bytes(2, "little"))),
        Mutation("bad-domain", "bad_domain_version", set_bytes(12, (2).to_bytes(2, "little"))),
        Mutation("bad-hash-suite", "bad_hash_suite", set_bytes(14, (1).to_bytes(2, "little"))),
        Mutation("profile-digest", "profile_digest_mismatch", flip(16)),
        Mutation("relation-digest", "relation_digest_mismatch", flip(88)),
        Mutation("reserved-flags", "nonzero_reserved_flags", set_bytes(158, (1).to_bytes(2, "little"))),
        Mutation("statement-length", "statement_length", set_bytes(152, (1360).to_bytes(4, "little"))),
        Mutation("zero-sections", "section_count", set_bytes(156, (0).to_bytes(2, "little"))),
        Mutation("body-too-large", "proof_body_too_large", set_bytes(160, (MAX_BODY + 1).to_bytes(4, "little"))),
        Mutation("declared-total", "declared_total_mismatch", flip(164)),
        Mutation("truncate-envelope", "truncated_envelope", lambda raw: raw[:-1]),
        Mutation("trailing-envelope", "trailing_bytes", lambda raw: raw + b"x"),
        Mutation("outer-network", "network_binding_mismatch", flip(80)),
        Mutation("outer-action", "action_binding_mismatch", flip(84)),
        Mutation("outer-action-version", "action_version_binding_mismatch", flip(86)),
        Mutation("statement-magic", "bad_statement_magic", flip(statement)),
        Mutation("statement-version", "bad_statement_version", set_bytes(statement + 8, (2).to_bytes(2, "little"))),
        Mutation("statement-header-length", "bad_statement_header_length", set_bytes(statement + 10, (91).to_bytes(2, "little"))),
        Mutation("statement-domain", "bad_statement_domain_version", set_bytes(statement + 20, (2).to_bytes(2, "little"))),
        Mutation("statement-hash-suite", "bad_statement_hash_suite", set_bytes(statement + 22, (1).to_bytes(2, "little"))),
        Mutation("statement-relation", "statement_relation_binding_mismatch", flip(statement + 24)),
        Mutation("statement-public-length", "public_argument_length", set_bytes(statement + 88, (PUBLIC_BYTES - 1).to_bytes(4, "little"))),
        Mutation("hx-magic", "bad_hx_magic", flip(public)),
        Mutation("hx-grammar", "bad_hx_grammar", set_bytes(public + 8, (1).to_bytes(2, "big"))),
        Mutation("hx-nonboolean", "noncanonical_boolean", set_bytes(public + 10, b"\x02")),
        Mutation("hx-all-empty", "all_empty_activity", set_bytes(public + 10, b"\0\0\0\0")),
        Mutation("hx-negative-zero", "signed_magnitude_range", set_bytes(public + 454, b"\x01")),
        Mutation("hx-activation", "activation_mismatch", flip(public + 685)),
        Mutation("hx-zero-chain", "activation_mismatch", set_bytes(public + 701, bytes(56))),
        Mutation("state-disabled-nonzero", "disabled_state_seam_nonzero", flip(state)),
        Mutation("state-u32-high", "state_seam_noncanonical_u32", set_many((public + 463, b"\x01"), (state + 4, b"\x01"))),
        Mutation("state-bool-noncanonical", "state_seam_noncanonical_boolean", set_many((public + 463, b"\x01"), (state + 4 * 8, b"\x02"))),
        Mutation("state-retirement-noncanonical", "state_seam_noncanonical_retirement", set_many((public + 463, b"\x01"), (state + 16 * 8, b"\x01"))),
        Mutation("unknown-role", "unknown_section_role", set_bytes(body, (0x7777).to_bytes(2, "little"))),
        Mutation("instance-gap", "noncanonical_section_instance", set_bytes(body + 2, (1).to_bytes(2, "little"))),
        Mutation("empty-section", "empty_section_payload", set_bytes(body + 4, (0).to_bytes(4, "little"))),
        Mutation("oversize-section", "section_too_large", set_bytes(body + 4, (MAX_SECTION + 1).to_bytes(4, "little"))),
        Mutation("truncated-section-payload", "truncated_section_payload", set_bytes(second + 4, (0x1000).to_bytes(4, "little"))),
        Mutation("body-trailing-section", "proof_body_trailing_bytes", set_bytes(156, (1).to_bytes(2, "little"))),
    )


def check_hashes_and_wire() -> int:
    require(
        hashlib.sha512(b"abc").hexdigest()
        == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "SHA-512 KAT failed",
    )
    require(
        hashlib.shake_256(b"abc").digest(64).hex()
        == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
        "SHAKE256 KAT failed",
    )
    manifest = json.loads((HERE / "adapter_manifest.json").read_text())
    require(manifest["hash_facade"]["profile_digest_shake256_512"] == PROFILE_DIGEST.hex(), "profile KAT drift")
    require(manifest["hash_facade"]["source_attestation_sha512"] == SOURCE_ATTESTATION.hex(), "source attestation drift")
    salt_profile = manifest["hash_facade"]["candidate_security_salt"]
    require(salt_profile["actual_minimum_lambda_bits"] is None, "actual hiding lambda invented")
    require(salt_profile["ell_only_byte_aligned_absolute_floor_bits"] == 624, "ell-only byte-aligned lambda floor drift")
    require(salt_profile["ell_only_byte_aligned_absolute_floor_bytes"] == 78, "ell-only salt floor byte width drift")
    require(salt_profile["ell_only_floor_accepted_by_security_salt_api"] is False, "ell-only salt floor admitted")
    require(salt_profile["e320_rate_one_byte_aligned_floor_bits"] == 656, "E320 byte-aligned lambda floor drift")
    require(salt_profile["e320_rate_one_byte_aligned_floor_bytes"] == 82, "E320 salt floor byte width drift")
    require(salt_profile["per_salt_delta_over_64_bytes_at_e320_rate_one_floor"] == 18, "E320 salt floor delta drift")
    require(salt_profile["profile_selected"] is False, "floor salt selected without total p")
    require(salt_profile["canonical_wire_location_assigned"] is False, "salt wire location invented")
    require(salt_profile["total_wire_delta_bytes"] is None, "total salt wire delta invented")
    floor_salt = derive_unselected_security_salt(bytes(64), bytes(64), 656)
    require(len(floor_salt) == 82, "SHAKE256 E320 floor salt width drift")
    require(
        hashlib.sha512(floor_salt).hexdigest()
        == salt_profile["zero_transcript_statement_floor_salt_sha512"],
        "SHAKE256 E320 floor salt KAT drift",
    )
    require(
        floor_salt != derive_unselected_security_salt(bytes(64), b"\x01" + bytes(63), 656),
        "salt statement separation failed",
    )
    for state, statement, lambda_bits, expected in (
        (bytes(63), bytes(64), 656, "security_salt_state_length"),
        (bytes(64), bytes(63), 656, "security_salt_statement_length"),
        (bytes(64), bytes(64), 512, "security_salt_lambda_below_known_e320_floor"),
        (bytes(64), bytes(64), 624, "security_salt_lambda_below_known_e320_floor"),
        (bytes(64), bytes(64), 657, "security_salt_lambda_not_byte_aligned"),
        (bytes(64), bytes(64), 32_776, "security_salt_output_too_large"),
    ):
        try:
            derive_unselected_security_salt(state, statement, lambda_bits)
        except WireFailure as error:
            require(error.code == expected, f"security salt mutation mismatch: {error.code}")
        else:
            raise GateFailure(f"security salt mutation accepted: {expected}")

    public = make_public()
    sections = (
        (0x0101, 0, b"unimplemented-section11-carrier"),
        (0x0201, 0, b"opaque-not-a-plonky3-proof"),
    )
    fixture = encode_envelope(public, sections)
    parsed = parse_envelope(fixture)
    require(parsed["statement"]["public"] == public, "wire round trip public drift")
    require(encode_envelope(public, sections) == fixture, "wire encoding nondeterministic")

    mutations = mutation_suite(fixture)
    corpus = json.loads((HERE / "mutation_corpus.json").read_text())
    require(
        corpus == [{"expected_error": mutation.expected, "name": mutation.name} for mutation in mutations],
        "mutation corpus drift",
    )
    for mutation in mutations:
        try:
            parse_envelope(mutation.apply(fixture))
        except WireFailure as error:
            require(error.code == mutation.expected, f"{mutation.name}: got {error.code}, expected {mutation.expected}")
        else:
            raise GateFailure(f"mutation accepted: {mutation.name}")

    private = bytearray(PRIVATE_BYTES)
    pads = private_padding_offsets()
    require(len(pads) == 10, "private padding geometry drift")
    parse_private(private)
    try:
        parse_private(private[:-1])
    except WireFailure as error:
        require(error.code == "private_transport_length", "private length mutation mismatch")
    else:
        raise GateFailure("private length mutation accepted")
    for offset in pads:
        mutated = private.copy()
        mutated[offset] = 1
        try:
            parse_private(mutated)
        except WireFailure as error:
            require(error.code == "nonzero_private_padding", f"private pad {offset} mutation mismatch")
        else:
            raise GateFailure(f"private padding mutation accepted at {offset}")
    require(int.from_bytes(GOLDILOCKS.to_bytes(8, "little"), "little") >= GOLDILOCKS, "Goldilocks rejection KAT failed")
    return len(mutations)


def check_local_source() -> None:
    cargo = (HERE / "Cargo.toml").read_text()
    lib = (HERE / "src/lib.rs").read_text()
    hash_source = (HERE / "src/hash.rs").read_text()
    api = (HERE / "src/plonky3_api.rs").read_text()
    require("[dependencies]" not in cargo, "adapter gained dependencies")
    require("[workspace]" in cargo, "adapter is not detached from production workspace")
    for token in (
        "PRODUCTION_AUTHORIZED: bool = false",
        "PROOF_BYTES: Option<usize> = None",
        "COMPOSED_PQ_SECURITY_BITS: Option<f64> = None",
        "COMPLETE_ZERO_KNOWLEDGE_PROVED: bool = false",
        "PLONKY3_IS_PCS_ONLY: bool = true",
        "CFW26_SECTION11_SPECIFICATION_UNAMBIGUOUS: bool = false",
        "Err(AdapterError::ProductionBlocked(ALL_PRODUCTION_BLOCKERS))",
        "PCS_POLYNOMIAL_COUNT_SELECTED: Option<usize> = None",
        "CFW26_PAPER_ENCODED_ORACLES: usize",
        "CFW26_STEP9_TYPING_DEFECTS: usize = 2",
        "CFW26_THEOREM_INHERITED: bool = false",
        "CFW26_ORACLES_MAPPED_TO_PLONKY3_PCS: bool = false",
        "CFW26_PRINTED_ENDPOINT_STATE_SELECTS_S_AT_ONE: bool = false",
        "CFW26_TYPED_MAIN_FORM_ROW_DEFINED: bool = false",
        "CFW26_PRINTED_THEOREM_CARRIER_COMPATIBLE: bool = false",
        "IndependentExactSecurityCertificateAbsent",
        "ModifiedBcsHidingBoundUnproved",
        "CanonicalSecuritySaltWireBindingAbsent",
        "MODIFIED_BCS_LAMBDA_512_FLOOR_TERM_LOG2: i16 = -101",
        "CFW26_E320_RATE_ONE_P_FIELD_ELEMENTS_FLOOR: u64",
        "CFW26_E320_RATE_ONE_P_BITS_FLOOR: u64",
        "E320_CANONICAL_ELEMENT_BYTES: usize",
        "MODIFIED_BCS_E320_RATE_ONE_INTEGER_LAMBDA_FLOOR_BITS: usize = 654",
        "MODIFIED_BCS_E320_RATE_ONE_BYTE_ALIGNED_LAMBDA_FLOOR_BITS: usize = 656",
        "MODIFIED_BCS_ACTUAL_MINIMUM_LAMBDA_BITS: Option<usize> = None",
        "MODIFIED_BCS_SECURITY_SALT_SELECTED: bool = false",
        "MODIFIED_BCS_TOTAL_WIRE_DELTA_BYTES: Option<usize> = None",
        "derive_unselected_security_salt",
        "PRIVATE_TRANSPORT_SECTIONS: [TransportSectionLayout; 7]",
        "CONSENSUS_STATE_FIELDS: [ConsensusFieldLayout; 23]",
        "DisabledStateSeamNonzero",
        "StateSeamNoncanonicalU32",
        "StateSeamNoncanonicalBoolean",
        "StateSeamNoncanonicalRetirement",
    ):
        require(token in lib, f"fail-closed Rust token missing: {token}")
    require("pub fn sha512" in hash_source and "pub fn shake256" in hash_source, "conventional hash facade absent")
    require("pub fn framed_shake256" in hash_source, "parameterized framed SHAKE256 absent")
    require("SHA512_ROUND_CONSTANTS: [u64; 80]" in hash_source, "SHA-512 reference incomplete")
    require("KECCAK_ROUND_CONSTANTS: [u64; 24]" in hash_source, "SHAKE256 reference incomplete")
    require("map_r1cs_to_hiding_whir_pcs" in api, "R1CS/PCS mismatch API missing")
    for token in (
        "total_iop_proof_length_p_exact: Option<u64>",
        "all_105_oracle_code_lengths_fixed: bool",
        "field_encoding_fixed: bool",
        "modified_bcs_term_strictly_below_target_proved: bool",
        "ModifiedBcsLambdaBelowKnownE320Floor",
    ):
        require(token in api, f"security-certificate boundary missing: {token}")
    for source in (lib, hash_source, api):
        require("Keccak256Hash" not in source, "Keccak-256 fallback introduced")
        require("Poseidon" not in source, "Poseidon authority introduced")
    manifest = json.loads((HERE / "adapter_manifest.json").read_text())
    require(manifest["status"] == "SOURCE_ONLY_FAIL_CLOSED", "adapter status drift")
    require(manifest["proof"]["bytes"] is None, "proof-byte claim introduced")
    require(manifest["proof"]["artifact"] is None, "unverified proof artifact introduced")
    require(all(value is False for value in manifest["authority"].values()), "authority flag opened")
    require(manifest["field_route"]["challenge_field_selected"] is False, "E320 selected without ledger")
    require(manifest["field_route"]["composed_security_bits"] is None, "unsupported security claim")
    require(manifest["field_route"]["candidate_base_coefficient_bytes"] == 8, "E320 coefficient width drift")
    require(manifest["field_route"]["candidate_extension_element_bytes"] == 40, "E320 element width drift")
    require(manifest["hash_facade"]["local_keccak256_fallback_allowed"] is False, "Keccak-256 fallback opened")
    parameter_source = manifest["security_parameter_source"]
    require(parameter_source["production_parameter_source"] is None, "security parameter source promoted")
    require(parameter_source["independent_certificate_present"] is False, "unverified security certificate admitted")
    require(parameter_source["local_protocol_security_level_is_strict_authority"] is False, "local security target promoted")
    require(parameter_source["capacity_bound_status"] == "diagnostic-conjectural-only", "capacity boundary drift")
    require(parameter_source["johnson_bound_status"] == "diagnostic-dominant-term-f64-only", "Johnson boundary drift")
    hiding = parameter_source["modified_bcs_hiding_term"]
    require(hiding["p_is_total_iop_proof_length"] is True, "modified-BCS p meaning drift")
    require(hiding["p_lower_bound_log2"] == 25, "modified-BCS p floor drift")
    require(hiding["lambda_512_absolute_floor_term_log2"] == -101, "modified-BCS lambda512 term drift")
    require(hiding["integer_lambda_absolute_floor_bits"] == 621, "modified-BCS integer floor drift")
    p_field = (1 << 25) + 78 * 4 + 26 * 8 + 26 * 9 + 4
    p_bits = p_field * 320
    require(p_field == 33_555_190, "E320 rate-one field-element floor drift")
    require(p_bits == 10_737_660_800, "E320 rate-one bit floor drift")
    require(hiding["e320_rate_one_p_field_elements_floor"] == p_field, "manifest E320 field-element floor drift")
    require(hiding["e320_rate_one_p_bits_floor"] == p_bits, "manifest E320 bit floor drift")
    integer_lambda_floor = next(
        value for value in range(521, 1_024) if p_bits**4 < 1 << (value - 520)
    )
    require(integer_lambda_floor == 654, "E320 rate-one integer lambda floor drift")
    require(hiding["e320_rate_one_integer_lambda_floor_bits"] == 654, "manifest E320 integer lambda floor drift")
    require(not (p_bits**4 < 1 << (648 - 520)), "lambda648 unexpectedly passes E320 floor")
    require(p_bits**4 < 1 << (656 - 520), "lambda656 fails E320 floor")
    require(hiding["lambda_648_passes_e320_rate_one_floor"] is False, "manifest lambda648 result drift")
    require(hiding["lambda_656_passes_e320_rate_one_floor"] is True, "manifest lambda656 result drift")
    require(hiding["actual_minimum_lambda_bits"] is None, "modified-BCS actual lambda invented")
    require(hiding["total_iop_proof_length_p"] is None, "modified-BCS total p invented")
    require(hiding["all_105_oracle_code_lengths_fixed"] is False, "oracle code lengths invented")
    require(hiding["candidate_e320_element_width_fixed"] is True, "candidate E320 width not pinned")
    require(hiding["production_field_encoding_fixed"] is False, "production field encoding invented")


def main() -> int:
    try:
        check_source_pins()
        check_relation_contract()
        check_plonky3_api_map()
        mutation_count = check_hashes_and_wire()
        check_local_source()
    except (GateFailure, KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL hvzk-whir-backend-adapter: {error}", file=sys.stderr)
        return 1
    print(
        "PASS hvzk-whir-backend-adapter "
        f"plonky3=5df89ee relation={RELATION_DIGEST.hex()} "
        f"mutations={mutation_count} ell=2^25 carrier=2^26 "
        "e320=source-feasible/security-unselected production=false proof_bytes=null"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
