#!/usr/bin/env python3
"""Dependency-free checker for the HVZK-WHIR source wire profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import hvzk_whir_profile as profile


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PROFILE_PATH = HERE / "profile.json"
MUTATION_PATH = HERE / "mutation_corpus.json"
SOURCE_EVIDENCE_PATH = HERE / "source_evidence.json"
CHALLENGER_REPORT = REPO / ".agent/hardening/pq-architecture-challenger-screen/REPORT.md"
CHALLENGER_LEDGER = REPO / ".agent/hardening/pq-architecture-challenger-screen/ledger.json"

EXPECTED_CHALLENGER_SHA512 = {
    "REPORT.md": "b5817f07fd5371f323c30cff2649e071825ffcdaa5f8aab1de827e5c968279a707bb1687f4afa5537b8bebb0ab35b6e1381014a29985248b0b16d1c57a8c7eff",
    "ledger.json": "e3f89344fcbe5abecb7b1ac2bded611a0954edf5120977967130e8288d04875f76c0dde3aad2e8e7fbdf2b487f4f3d2e87bf0a778b4b8d13e2fee48855d37553",
}

LOCAL_SOURCE_HASHES = {
    "whir/Cargo.toml": "00a1077f09f730062d0670b7a14da35b67d69cc189ca996135d9a2e1b14bf3f50de2f3464a6c3ce4db818b2cc81a9071f1768b2ddb77de2328c57f0b74d0ddb7",
    "whir/README.md": "6758abb4935a05e8eb107bf97d9d6ab9e170fad44fc314022af9d1b70e926d00c0081fd21eb845fe382a3eafec34695437e7c7f29659c2e31add5b7758dab60d",
    "whir/src/fiat_shamir/domain_separator.rs": "edd05c8ab324836f5ae5a2aded02eca825278f5cb542b781a78f740bd3dec32a06e0053c3560c4ec0a8c8f5b77a5d559dc2fffffdce0ed582bdfb19855f2625b",
    "whir/src/fiat_shamir/pattern.rs": "6807ae5c0b3340cac635aa34fd6ad7994c5fdec14da34ef0fdf6294f475119747a844a110606db0f2390f3ac2e749795da1e730c744fc00cd7fb57d884f33175",
    "whir/src/pcs/zk/adapter.rs": "cbffc7b9330e857ed76562d9ea32be3d50b5a004102844f5325c456b7076276c9dba18e4ceac1c4275075a2ab2ca468bc363124f1c635dfbbbf943f7c2fd0e40",
    "whir/src/pcs/zk/proof.rs": "d4010520d1963fec4ba82912fd887f2e62cb1797b9b9384cd27005b003e179bae0656ff35d497037db09c845fc0a0e954c2875f7b39b04104cf09f5ab04b4ccc",
    "whir/src/pcs/zk/verifier/mod.rs": "a0cbb208f6b38689258e5406a7e5f74dbf924807b52fbca163fa0e315a000b2482f0ef642e28bdac413b0f51d980844cff4ed72f0eb87fe15e22591d446be12f",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def read_bounded(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    require(path.exists(), f"missing file: {path}")
    require(not path.is_symlink(), f"symlink rejected: {path}")
    size = path.stat().st_size
    require(0 < size <= maximum, f"file size outside bound: {path}: {size}")
    payload = path.read_bytes()
    require(len(payload) == size, f"short read: {path}")
    return payload


def load_json(path: Path) -> Any:
    return json.loads(read_bounded(path).decode("utf-8"))


def load_canonical_json(path: Path) -> Any:
    payload = read_bounded(path)
    value = json.loads(payload.decode("ascii"))
    require(payload == profile.canonical_json_bytes(value), f"noncanonical JSON: {path}")
    return value


def expected_retained_profile() -> dict[str, Any]:
    report = profile.profile_report()
    return {
        "schema": profile.SCHEMA,
        "status": profile.PROFILE_STATUS,
        "profile_digest_hex": report["profile_digest_hex"],
        "recorded_plonky3_pcs_pin": profile.RECORDED_PLONKY3_PCS_PIN,
        "local_later_evidence_pin": profile.LOCAL_PLONKY3_EVIDENCE_PIN,
        "hash_profile": "FIPS 202 SHAKE256-512 with HGWHASH1 length framing",
        "wire": {
            "magic": profile.WIRE_MAGIC.decode("ascii"),
            "version": profile.WIRE_VERSION,
            "domain_set_version": profile.DOMAIN_SET_VERSION,
            "hash_suite_id": profile.HASH_SUITE_ID,
            "header_bytes": profile.HEADER_BYTES,
            "statement_header_bytes": profile.STATEMENT_HEADER_BYTES,
            "section_header_bytes": profile.SECTION_HEADER_BYTES,
        },
        "limits": profile.profile_core()["limits"],
        "known_answer_tests": report["known_answer_tests"],
        "security_term_ids": [term_id for term_id, _ in profile.REQUIRED_SECURITY_TERMS],
        "security_overall_total": None,
        "composed_pq_security_bits": None,
        "proof_bytes": None,
        "winner": None,
        "production_authorized": False,
    }


def expected_source_evidence() -> dict[str, Any]:
    return {
        "schema": "hegemon.hvzk-whir-source-evidence.v1",
        "recorded_tournament_pin": {
            "revision": profile.RECORDED_PLONKY3_PCS_PIN,
            "scope": "PCS-only pin recorded by the sealed challenger screen",
            "present_in_local_checkout": False,
            "ancestry_to_local_pin_verified": False,
        },
        "local_later_snapshot": {
            "revision": profile.LOCAL_PLONKY3_EVIDENCE_PIN,
            "commit_date": "2026-07-27",
            "subject": "feat(multi-stark): support periodic columns in the multilinear AIR prover (#1939)",
            "tracked_files_clean": True,
            "untracked_bootstrap_marker": ".cargo-ok",
            "source_sha512": LOCAL_SOURCE_HASHES,
        },
        "findings": {
            "hiding_whir_pcs_present": True,
            "cryptographic_rng_trait_required": True,
            "base_field_requires_two_adic": True,
            "extension_field_requires_two_adic": True,
            "challenger_and_mmcs_generic": True,
            "point_evaluation_pcs_api_only": True,
            "r1cs_ior_api_present": False,
            "generic_serde_vec_proof_is_bounded_consensus_wire": False,
            "sha512_or_shake256_512_profile_present": False,
            "complete_hg_transaction_proof_present": False,
            "native_verifier_refinement_present": False,
            "cfw26_section11_specification_unambiguous": False,
            "cfw26_section11_author_erratum_found": False,
            "cfw26_section11_repair_selected": False,
        },
        "claim_boundary": "The local snapshot is later read-only PCS evidence, not the recorded pin, not the CFW26 Section 11 R1CS IOR, and not a production verifier.",
    }


def _write_u16(blob: bytes, offset: int, value: int) -> bytes:
    out = bytearray(blob)
    out[offset : offset + 2] = struct.pack("<H", value)
    return bytes(out)


def _write_u32(blob: bytes, offset: int, value: int) -> bytes:
    out = bytearray(blob)
    out[offset : offset + 4] = struct.pack("<I", value)
    return bytes(out)


def _flip(blob: bytes, offset: int) -> bytes:
    out = bytearray(blob)
    out[offset] ^= 1
    return bytes(out)


def _zero(blob: bytes, offset: int, length: int) -> bytes:
    out = bytearray(blob)
    out[offset : offset + length] = bytes(length)
    return bytes(out)


def _section_offsets(valid: bytes) -> tuple[int, int, int]:
    statement_len = struct.unpack_from("<I", valid, 152)[0]
    first = profile.HEADER_BYTES + statement_len
    first_len = struct.unpack_from("<I", valid, first + 4)[0]
    second = first + profile.SECTION_HEADER_BYTES + first_len
    return first, first_len, second


def mutation_operators(valid: bytes) -> dict[str, Callable[[bytes], bytes]]:
    first, first_len, second = _section_offsets(valid)
    statement_end = first

    def statement_trailing(blob: bytes) -> bytes:
        out = bytearray(blob[:statement_end] + b"\x00" + blob[statement_end:])
        statement_len = struct.unpack_from("<I", out, 152)[0] + 1
        total_len = struct.unpack_from("<I", out, 164)[0] + 1
        struct.pack_into("<I", out, 152, statement_len)
        struct.pack_into("<I", out, 164, total_len)
        return bytes(out)

    def duplicate_section_instance(blob: bytes) -> bytes:
        out = bytearray(blob)
        first_role = struct.unpack_from("<H", out, first)[0]
        struct.pack_into("<H", out, second, first_role)
        struct.pack_into("<H", out, second + 2, 0)
        return bytes(out)

    return {
        "empty": lambda _blob: b"",
        "truncated_header": lambda blob: blob[: profile.HEADER_BYTES - 1],
        "bad_magic": lambda blob: _flip(blob, 0),
        "bad_wire_version": lambda blob: _write_u16(blob, 8, 2),
        "bad_header_length": lambda blob: _write_u16(blob, 10, profile.HEADER_BYTES - 1),
        "bad_domain_version": lambda blob: _write_u16(blob, 12, 2),
        "bad_hash_suite": lambda blob: _write_u16(blob, 14, 2),
        "profile_digest_mismatch": lambda blob: _flip(blob, 16),
        "zero_relation_digest": lambda blob: _zero(blob, 88, profile.DIGEST_BYTES),
        "nonzero_reserved_flags": lambda blob: _write_u16(blob, 158, 1),
        "statement_length_too_small": lambda blob: _write_u32(blob, 152, profile.STATEMENT_HEADER_BYTES),
        "zero_sections": lambda blob: _write_u16(blob, 156, 0),
        "proof_body_too_large": lambda blob: _write_u32(blob, 160, profile.MAX_PROOF_BODY_BYTES + 1),
        "declared_total_mismatch": lambda blob: _write_u32(blob, 164, len(blob) - 1),
        "trailing_envelope_byte": lambda blob: blob + b"\x00",
        "truncated_envelope": lambda blob: blob[:-1],
        "bad_statement_magic": lambda blob: _flip(blob, profile.HEADER_BYTES),
        "bad_statement_version": lambda blob: _write_u16(blob, profile.HEADER_BYTES + 8, 2),
        "bad_statement_header_length": lambda blob: _write_u16(blob, profile.HEADER_BYTES + 10, 0),
        "network_binding_mismatch": lambda blob: _flip(blob, profile.HEADER_BYTES + 12),
        "action_kind_binding_mismatch": lambda blob: _flip(blob, profile.HEADER_BYTES + 16),
        "action_version_binding_mismatch": lambda blob: _flip(blob, profile.HEADER_BYTES + 18),
        "bad_statement_domain_version": lambda blob: _write_u16(blob, profile.HEADER_BYTES + 20, 2),
        "bad_statement_hash_suite": lambda blob: _write_u16(blob, profile.HEADER_BYTES + 22, 2),
        "relation_binding_mismatch": lambda blob: _flip(blob, profile.HEADER_BYTES + 24),
        "truncated_public_args": lambda blob: _write_u32(
            blob,
            profile.HEADER_BYTES + profile.STATEMENT_HEADER_BYTES - 4,
            struct.unpack_from("<I", blob, profile.HEADER_BYTES + profile.STATEMENT_HEADER_BYTES - 4)[0] + 1,
        ),
        "statement_trailing_bytes": statement_trailing,
        "unknown_section_role": lambda blob: _write_u16(blob, first, 0xFFFF),
        "section_instance_gap": lambda blob: _write_u16(blob, first + 2, 1),
        "empty_section_payload": lambda blob: _write_u32(blob, first + 4, 0),
        "section_too_large": lambda blob: _write_u32(blob, first + 4, profile.MAX_SECTION_BYTES + 1),
        "truncated_section_payload": lambda blob: _write_u32(blob, first + 4, len(blob)),
        "proof_body_trailing_bytes": lambda blob: _write_u16(blob, 156, 1),
        "duplicate_section_instance": duplicate_section_instance,
        "first_payload_bit_flip": lambda blob: _flip(blob, first + profile.SECTION_HEADER_BYTES),
    }


def run_mutation_corpus() -> dict[str, int]:
    corpus = load_canonical_json(MUTATION_PATH)
    require(corpus.get("schema") == "hegemon.hvzk-whir-wire-mutations.v1", "mutation schema")
    valid, parsed = profile.fixture()
    operators = mutation_operators(valid)
    entries = corpus.get("mutations")
    require(isinstance(entries, list) and entries, "mutation entries missing")
    require({entry["operation"] for entry in entries} == set(operators), "mutation operation inventory drift")
    rejected = 0
    accepted_integrity_mutations = 0
    original_digest = profile.transcript_digest(parsed)
    for entry in entries:
        mutation = operators[entry["operation"]](valid)
        parsed_mutation, error = profile.parse_envelope_safe(mutation)
        expected = entry["expected"]
        if expected == "accepted_but_transcript_changes":
            require(error is None and parsed_mutation is not None, f"{entry['id']} unexpectedly rejected: {error}")
            require(profile.transcript_digest(parsed_mutation) != original_digest, f"{entry['id']} digest unchanged")
            accepted_integrity_mutations += 1
        else:
            require(parsed_mutation is None, f"{entry['id']} unexpectedly accepted")
            require(error == expected, f"{entry['id']}: expected {expected}, got {error}")
            require(error != "internal_parser_error", f"{entry['id']} reached internal parser error")
            rejected += 1
    return {"rejected": rejected, "accepted_integrity_mutations": accepted_integrity_mutations}


def run_nonpanic_corpus() -> int:
    checked = 0
    for length in range(0, 768):
        blob = hashlib.shake_256(struct.pack("<I", length) + b"hegemon-hvzk-whir-parser-corpus").digest(length)
        _parsed, error = profile.parse_envelope_safe(blob)
        require(error != "internal_parser_error", f"internal parser error at generated length {length}")
        checked += 1
    valid, _ = profile.fixture()
    for cut in range(len(valid)):
        _parsed, error = profile.parse_envelope_safe(valid[:cut])
        require(error != "internal_parser_error", f"internal parser error at truncation {cut}")
        checked += 1
    return checked


def check_challenger_sources() -> None:
    for path in (CHALLENGER_REPORT, CHALLENGER_LEDGER):
        payload = read_bounded(path)
        expected = EXPECTED_CHALLENGER_SHA512[path.name]
        require(hashlib.sha512(payload).hexdigest() == expected, f"sealed challenger source drift: {path}")
    report = read_bounded(CHALLENGER_REPORT).decode("utf-8")
    require(profile.RECORDED_PLONKY3_PCS_PIN in report, "recorded Plonky3 pin absent from report")
    ledger = load_json(CHALLENGER_LEDGER)
    require(ledger.get("winner") is None, "challenger ledger selected a winner")
    require(ledger.get("production_authorized") is False, "challenger ledger authorized production")
    challenger = ledger.get("complete_zk_topology_challenger")
    require(isinstance(challenger, dict), "missing complete-ZK topology challenger")
    require(challenger.get("id") == "hvzk_whir_cfw26_plonky3", "wrong complete-ZK challenger")
    require(challenger.get("plonky3_source_revision") == profile.RECORDED_PLONKY3_PCS_PIN, "pin mismatch")
    require(challenger["implementation"]["hiding_whir_pcs_implemented"] is True, "PCS evidence lost")
    require(challenger["implementation"]["r1cs_reduction_implemented"] is False, "R1CS falsely implemented")
    require(challenger.get("same_relation_proof_bytes") is None, "proof bytes fabricated")


def check_local_plonky3(root: Path) -> dict[str, Any]:
    root = root.resolve()
    require(root.is_dir(), f"local Plonky3 root missing: {root}")
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    require(head == profile.LOCAL_PLONKY3_EVIDENCE_PIN, f"local Plonky3 revision mismatch: {head}")
    for relative, expected in LOCAL_SOURCE_HASHES.items():
        payload = read_bounded(root / relative)
        require(hashlib.sha512(payload).hexdigest() == expected, f"local source drift: {relative}")
    adapter = read_bounded(root / "whir/src/pcs/zk/adapter.rs").decode("utf-8")
    proof = read_bounded(root / "whir/src/pcs/zk/proof.rs").decode("utf-8")
    for needle in (
        "pub struct HidingWhirPcs",
        "F: TwoAdicField",
        "EF: ExtensionField<F> + TwoAdicField",
        "R: CryptoRng + Send + Sync",
        "type Witness = Poly<F>",
        "type OpeningProtocol = Vec<Point<EF>>",
    ):
        require(needle in adapter, f"missing local adapter evidence: {needle}")
    require("pub struct ZkWhirProof" in proof and "pub evals: Vec<EF>" in proof, "generic proof evidence drift")
    r1cs_hits: list[str] = []
    for path in (root / "whir").rglob("*.rs"):
        text = read_bounded(path).decode("utf-8")
        if "R1CS" in text or "r1cs" in text:
            r1cs_hits.append(str(path.relative_to(root)))
    require(not r1cs_hits, f"unexpected R1CS source appeared: {r1cs_hits}")
    return {"revision": head, "files_checked": len(LOCAL_SOURCE_HASHES), "r1cs_source_hits": 0}


def run(local_plonky3: Path | None) -> dict[str, Any]:
    require(load_canonical_json(PROFILE_PATH) == expected_retained_profile(), "retained profile drift")
    require(load_canonical_json(SOURCE_EVIDENCE_PATH) == expected_source_evidence(), "source evidence drift")
    check_challenger_sources()
    valid, parsed = profile.fixture()
    require(profile.encode_envelope(parsed.statement, parsed.sections) == valid, "roundtrip mismatch")
    report = profile.profile_report()
    require(report["profile_digest_hex"] == profile.profile_digest().hex(), "profile digest mismatch")
    require(report["proof_bytes"] is None, "fixture promoted to proof bytes")
    require(report["production_authorized"] is False, "production authorization opened")
    require(all(term["exact_value"] is None for term in report["security_ledger"]["terms"]), "security placeholder filled without review")
    mutation_counts = run_mutation_corpus()
    nonpanic_cases = run_nonpanic_corpus()
    try:
        profile.require_production_authority()
    except profile.ProductionAuthorizationError:
        pass
    else:
        raise AssertionError("production authority did not fail closed")
    local = check_local_plonky3(local_plonky3) if local_plonky3 is not None else None
    return {
        "status": "PASS",
        "profile_digest_hex": profile.profile_digest().hex(),
        "parser_fixture_bytes_not_a_proof": len(valid),
        "mutation_counts": mutation_counts,
        "nonpanic_cases": nonpanic_cases,
        "security_terms_missing": len(profile.REQUIRED_SECURITY_TERMS),
        "proof_bytes": None,
        "winner": None,
        "production_authorized": False,
        "local_plonky3": local,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-plonky3", type=Path)
    args = parser.parse_args()
    try:
        result = run(args.local_plonky3)
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
