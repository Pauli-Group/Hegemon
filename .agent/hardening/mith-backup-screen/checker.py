#!/usr/bin/env python3
"""Fail-closed source screen for generic MiTH/VOLEitH Hegemon proofs.

This is deliberately dependency-free and source-only.  It does not implement,
build, benchmark, or authorize a proof system.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CERTIFICATE = HERE / "source_certificate.json"
MUTATIONS = HERE / "mutation_corpus.json"
HASHES = HERE / "ARTIFACT_SHA256SUMS"

P = 0xFFFFFFFF00000001
M_CONSTRAINTS = 20_457_227
N_VARIABLES = 19_311_555
L_PUBLIC = 10_152
PRIVATE_VARIABLES = N_VARIABLES - L_PUBLIC
FIELD_BYTES = 8
TARGET_BITS = 128
OUTER_CAP_BYTES = 512 * 1024

RELATION_MANIFEST = ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json"
RELATION_MANIFEST_SHA256 = "be11569ade3a422c557ea9d971c0a5a8b7ed57eee673b61d57df96701d77406c"
MANIFEST_LEDGER = ".agent/hardening/manifest-authority-closure/capability_ledger.json"
MANIFEST_LEDGER_SHA256 = "0c9667fd197e9c311feb8177be160e5bf685575afca4794bd4180a42e0d273d9"


SOURCE_PINS = [
    {
        "id": "quicksilver-2021-076",
        "title": "QuickSilver: Efficient and Affordable Zero-Knowledge Proofs for Circuits and Polynomials over Any Field",
        "url": "https://eprint.iacr.org/2021/076.pdf",
        "sha256": "223067c1dc1b39148b41e99a531b8aca21569c4f1b7b92a9cfccb5dd9425037f",
        "bytes": 407_168,
        "local_cache_name": "quicksilver-2021-076.pdf",
        "pin": "ePrint 2021/076 PDF fetched 2026-08-22; PDF creation date 2021-09-11; 31 pages",
        "anchors": ["Section 4.2, Theorem 2", "Section 5, Theorem 3", "page 15 non-interactive online phase"],
    },
    {
        "id": "voleith-2023-996",
        "title": "Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures From VOLE-in-the-Head",
        "url": "https://eprint.iacr.org/2023/996.pdf",
        "sha256": "23cbfc539ec88cde0ad6e9162da469a332264cd0e539b0a83fad245b99196d48",
        "bytes": 842_448,
        "local_cache_name": "voleith-2023-996.pdf",
        "pin": "ePrint 2023/996 conference/full-version PDF fetched 2026-08-22; PDF creation date 2023-06-26; 47 pages",
        "anchors": ["Table 1", "Section 2.1", "Lemma 4", "Theorem 3", "Theorem 5"],
    },
    {
        "id": "zkboo-2016-163",
        "title": "ZKBoo: Faster Zero-Knowledge for Boolean Circuits",
        "url": "https://eprint.iacr.org/2016/163.pdf",
        "sha256": "d0037cfc721e9a4566f055eb46d222f362828805818f0231f843474cdc51509f",
        "bytes": 500_171,
        "local_cache_name": "zkboo-2016-163.pdf",
        "pin": "ePrint 2016/163 PDF fetched 2026-08-22; PDF creation date 2016-08-12; 24 pages",
        "anchors": ["Definition 2", "Proposition 2", "Section 4.2 Efficiency", "Section 5.2"],
    },
    {
        "id": "faest-spec-v2.0",
        "title": "FAEST v2: Algorithm Specifications",
        "url": "https://faest.info/faest-spec-v2.0.pdf",
        "sha256": "37ab53a919b1aca9ac90771519a0caa08592eb4cb2a0e3bc118b5e3014b52dad",
        "bytes": 1_237_694,
        "local_cache_name": "faest-spec-v2.0.pdf",
        "pin": "FAEST specification v2.0 PDF fetched 2026-08-22; PDF modified 2025-02-20; 111 pages",
        "anchors": ["Section 9.7", "Lemma 9.39", "Lemma 9.40", "Corollary 9.43", "Remark 9.44"],
    },
    {
        "id": "aurora-2018-828-control",
        "title": "Aurora: Transparent Succinct Arguments for R1CS",
        "url": "https://eprint.iacr.org/2018/828.pdf",
        "sha256": "ab0e83fde47a15ae269c6318db79b47c1d469a12770fc76217be27c92eb49710",
        "bytes": 1_215_146,
        "local_cache_name": "aurora-2018-828.pdf",
        "pin": "ePrint 2018/828 PDF fetched 2026-08-22; version dated 2019-05-08; 64 pages",
        "anchors": ["Theorem 1.2", "Definition 4.4", "Theorem 9.2"],
    },
    {
        "id": "cms-qrom-2019-834-control",
        "title": "Succinct Arguments in the Quantum Random Oracle Model",
        "url": "https://eprint.iacr.org/2019/834.pdf",
        "sha256": "c3258e2faa339bdc441403d73aba9fee7d03687121c3369ef007ccce71cd2b41",
        "bytes": 653_660,
        "local_cache_name": "cms-qrom-2019-834.pdf",
        "pin": "ePrint 2019/834 PDF fetched 2026-08-22; version dated 2020-01-14; 56 pages",
        "anchors": ["QROM lifting theorem for Micali/BCS", "zero-knowledge and proof-of-knowledge inheritance"],
    },
]


AUTHORITY_KEYS = [
    "architecture_selected",
    "exact_all_w64_relation_compiled",
    "complete_zk_established_for_concrete_nizk",
    "adaptive_multi_theorem_zk_established",
    "finite_qrom_soundness_established",
    "conventional_hash_instantiation_authorized",
    "composed_pq128_established",
    "proof_artifact_built",
    "proof_bytes_measured",
    "native_verifier_refinement_established",
    "consensus_integration_authorized",
    "production_authorized",
]


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def minimum_extension_degree() -> int:
    numerator = M_CONSTRAINTS + 3
    r = 1
    while numerator * (1 << TARGET_BITS) > P**r:
        r += 1
    return r


def soundness_bits(r: int) -> float:
    return r * math.log2(P) - math.log2(M_CONSTRAINTS + 3)


def zkb_repetitions() -> int:
    # Exact check for (2/3)^repetitions <= 2^-128.
    r = 1
    while (1 << (r + TARGET_BITS)) > 3**r:
        r += 1
    return r


def build_certificate() -> dict[str, Any]:
    extension_degree = minimum_extension_degree()
    quicksilver_base_correction_bytes = M_CONSTRAINTS * FIELD_BYTES
    voleith_table_field_elements_per_gate = 3
    voleith_projected_payload_bytes = (
        M_CONSTRAINTS * voleith_table_field_elements_per_gate * FIELD_BYTES
    )
    repetitions = zkb_repetitions()
    zkb_bits = repetitions * 2 * (
        FIELD_BYTES * 8 * (PRIVATE_VARIABLES + M_CONSTRAINTS + 1) + TARGET_BITS
    )
    zkb_bytes = (zkb_bits + 7) // 8

    authority = {key: False for key in AUTHORITY_KEYS}
    return {
        "artifact_schema": "hegemon.mith-backup-source-screen.v1",
        "generated_utc_date": "2026-08-22",
        "canonical_json": "UTF-8; recursively sorted keys; separators ',' and ':'; exactly one trailing LF",
        "task_boundary": {
            "source_only": True,
            "no_builds_run": True,
            "no_proofs_generated": True,
            "no_production_edits": True,
            "screen_kind": "bounded backup architecture screen, explicitly reauthorized despite the standing replacement-backend stop",
        },
        "authority": authority,
        "all_authority_false": all(not value for value in authority.values()),
        "relation_geometry": {
            "field": "Goldilocks",
            "modulus_decimal": str(P),
            "canonical_field_element_bytes": FIELD_BYTES,
            "m_constraints_lower_bound": M_CONSTRAINTS,
            "n_nonconstant_variables_lower_bound": N_VARIABLES,
            "l_public_variables": L_PUBLIC,
            "private_variables_for_size_screen": PRIVATE_VARIABLES,
            "relation_manifest_path": RELATION_MANIFEST,
            "relation_manifest_sha256": RELATION_MANIFEST_SHA256,
            "manifest_authority_ledger_path": MANIFEST_LEDGER,
            "manifest_authority_ledger_sha256": MANIFEST_LEDGER_SHA256,
            "geometry_scope": "exact checked-in BLAKE2b448-mixed odd-field R1CS geometry used only as a monotone lower bound",
            "fresh_all_w64_manifest_closure_compiled": False,
            "growth_rule": "the all-W64 row215 manifest closure is not compiled into this R1CS; any added constraints or variables only increase the linear MiTH/VOLEitH screens",
        },
        "security_arithmetic": {
            "target_bits": TARGET_BITS,
            "quicksilver_circuit_theorem_error": "(t+3)/p^r in the F_ext-sVOLE hybrid",
            "quicksilver_t": M_CONSTRAINTS,
            "minimum_extension_degree_r": extension_degree,
            "r2_soundness_bits": soundness_bits(2),
            "r2_meets_128": False,
            "r3_soundness_bits": soundness_bits(3),
            "r3_meets_128": True,
            "qrom_composition_included": False,
            "reason_qrom_composition_absent": "neither QuickSilver nor ePrint 2023/996 supplies an applicable finite-QROM generic NIZK theorem",
        },
        "size_screen": {
            "outer_consensus_envelope_cap_bytes": OUTER_CAP_BYTES,
            "quicksilver_designated_verifier_correction_floor": {
                "field_elements_per_multiplication_gate": 1,
                "bytes": quicksilver_base_correction_bytes,
                "derivation": "20,457,227 gates * 1 Goldilocks element/gate * 8 bytes",
                "scope": "online correction vector alone; ideal VOLE setup and all framing omitted",
                "exceeds_cap": quicksilver_base_correction_bytes > OUTER_CAP_BYTES,
            },
            "voleith_large_odd_field_source_profile": {
                "source": "ePrint 2023/996 Table 1, Fp row, p approximately 2^64, error at most 2^-128, source circuit 2^20 multiplication gates",
                "average_field_elements_per_gate": voleith_table_field_elements_per_gate,
                "projected_payload_bytes": voleith_projected_payload_bytes,
                "derivation": "20,457,227 gates * 3 source-profile field elements/gate * 8 bytes = 490,973,448",
                "classification": "exact arithmetic projection from the pinned source profile, not a measured Hegemon proof and not a universal theorem lower bound",
                "omits": ["commitment/startup payload", "Fiat-Shamir framing", "statement", "serialization", "all-W64 geometry growth"],
                "exceeds_cap": voleith_projected_payload_bytes > OUTER_CAP_BYTES,
            },
            "zkboo_direct_arithmetic_view_screen": {
                "repetitions_for_classical_128_soundness": repetitions,
                "formula": "r*2*(64*(private_variables+multiplication_gates+one_output)+128) bits",
                "bits": zkb_bits,
                "bytes": zkb_bytes,
                "classification": "optimistic direct-ring instantiation of Proposition 2/Section 4.2; commitments, statement framing, complete-ZK transform, and QROM repair omitted",
                "exceeds_cap": zkb_bytes > OUTER_CAP_BYTES,
            },
        },
        "candidates": [
            {
                "id": "quicksilver-designated-verifier",
                "status": "disqualified",
                "relation_scope": "arithmetic-circuit satisfiability over any field",
                "zk_scope": "Theorem 2 UC-realizes F_ZK with information-theoretic security against malicious prover and verifier, but only in the F_ext-sVOLE hybrid; the malicious-verifier simulated view is identically distributed",
                "whole_view_complete_zk": "yes only in the ideal hybrid interactive theorem",
                "adaptive_multi_theorem": "UC hybrid composability, not a concrete self-contained NIZK instantiation",
                "soundness": "(t+3)/p^r; r=3 is the first extension degree meeting 2^-128 for the pinned t",
                "fiat_shamir": "paper describes a classical random-oracle noninteractive online phase and a q/2^kappa+4/p^r variant; no QROM theorem",
                "hash_transcript": "abstract random oracle in the optional optimization; no exact Hegemon transcript or conventional-hash instantiation",
                "finite_qrom_theorem_applicable": False,
                "self_contained": False,
                "reason": "ideal VOLE authority is external and the one-element/gate correction floor is 163,657,816 bytes before self-containment",
            },
            {
                "id": "vole-in-the-head-large-odd-field",
                "status": "disqualified",
                "relation_scope": "Theorem 3 covers arbitrary degree-2 relations over a large field in an F_sVOLE hybrid",
                "zk_scope": "Theorem 3 is SHVZKPoK; Lemma 4 compiles qualifying protocols to classical programmable-ROM NIZK zero knowledge",
                "whole_view_complete_zk": "classical ROM only after all Lemma 4 premises; not established in QROM",
                "adaptive_multi_theorem": "paper defines sequentially composable multi-use ZK and Lemma 4 bounds adaptive simulations by delta*(Q_FS+Q_S)*Q_S plus underlying SHVZK advantage",
                "soundness": "Theorem 3: 3/p + 2*|S_Delta'|^-d_C in the hybrid; Lemma 4 adds mu*(Q_FS+Q_Verify)*kappa and vector-commitment terms",
                "fiat_shamir": "Lemma 4 is explicitly in the programmable classical ROM",
                "hash_transcript": "independent abstract H_FS and H_O2C random oracles plus vector-commitment assumptions; no exact SHA-512/SHAKE transcript theorem",
                "finite_qrom_theorem_applicable": False,
                "self_contained": "conceptually public after O2C/VOLEitH compilation, but no exact Hegemon serializer or verifier exists",
                "reason": "no applicable finite-QROM NIZK theorem and the pinned 128-bit Fp source profile projects to 490,973,448 payload bytes",
            },
            {
                "id": "zkboo-picnic-style-generic",
                "status": "disqualified",
                "relation_scope": "generic finite-ring circuit via a (2,3)-decomposition",
                "zk_scope": "Proposition 2 proves a Sigma protocol with 3-special soundness and special honest-verifier ZK, not malicious-verifier whole-view NIZK ZK",
                "whole_view_complete_zk": False,
                "adaptive_multi_theorem": False,
                "soundness": "base error 2/3; 219 repetitions are required for <=2^-128 before Fiat-Shamir loss",
                "fiat_shamir": "described as the Fiat-Shamir heuristic/classical RO; no finite-QROM theorem in the pinned paper",
                "hash_transcript": "SHA-256 commitment/PRF assumptions, SHA-256 RO, and AES-CTR tape generation in the implementation",
                "finite_qrom_theorem_applicable": False,
                "self_contained": True,
                "reason": "the optimistic view payload is 139,314,250,032 bytes and theorem scope still lacks complete NIZK ZK and QROM",
            },
            {
                "id": "faest-v2-fixed-relation-control",
                "status": "disqualified-for-generic-r1cs",
                "relation_scope": "fixed AES/Rijndael one-way-function signature relation, not arbitrary Hegemon R1CS",
                "zk_scope": "the QROM result is signature EUF-CMA/soundness, not a generic complete-ZK theorem",
                "whole_view_complete_zk": False,
                "adaptive_multi_theorem": "EUF-CMA signing-oracle scope only",
                "soundness": "Lemma 9.39 gives explicit Q-dependent QROM soundness for FAEST; Corollary 9.43 composes FAEST EUF-CMA terms",
                "fiat_shamir": "finite QROM proof exists for the exact non-standard 7-challenge FAEST transform",
                "hash_transcript": "domain-separated SHA3 random oracles plus AES-based OWF/PRG/PRF assumptions",
                "finite_qrom_theorem_applicable": False,
                "self_contained": True,
                "reason": "the finite QROM theorem is relation- and signature-specific and cannot be transferred to arbitrary R1CS or complete ZK",
            },
            {
                "id": "aurora-cms19-iop-control",
                "status": "separate-existing-iop-track-not-admitted-here",
                "relation_scope": "R1CS IOP/SNARG, transparent hash-based",
                "zk_scope": "Aurora gives bounded-query perfect malicious-verifier IOP ZK; CMS19 proves QROM security and ZK/PoK inheritance for qualifying round-by-round IOP SNARGs",
                "whole_view_complete_zk": "potentially applicable theorem path; not instantiated for the all-W64 Hegemon relation in this screen",
                "adaptive_multi_theorem": "not audited to Hegemon's exact deployment/composition here",
                "soundness": "requires exact Aurora/BCS round-by-round parameters and concrete QROM query accounting",
                "fiat_shamir": "CMS19 is a genuine QROM control, so this candidate is not dismissed for lack of a theorem",
                "hash_transcript": "random-oracle/Merkle compiler; no concrete Hegemon hash transcript certified here",
                "finite_qrom_theorem_applicable": "requires separate exact instantiation",
                "self_contained": "architecturally yes; implementation absent here",
                "reason": "owned by the existing odd-field IOP/WHIR track; no exact all-W64 compile, proof bytes, or composition certificate in this bounded MiTH screen",
            },
        ],
        "primary_sources": SOURCE_PINS,
        "verdict": {
            "mith_or_voleith_winner": None,
            "backup_authorized": False,
            "decisive_screen": "QuickSilver correction floor and the VOLEitH 128-bit Fp source-profile projection exceed the 512-KiB envelope by orders of magnitude",
            "qrom_gate": "no generic MiTH/VOLEitH candidate has an applicable finite-QROM complete-ZK NIZK theorem",
            "production_effect": "none; production remains fail-closed",
        },
    }


def build_mutations() -> list[dict[str, Any]]:
    mutations: list[dict[str, Any]] = [
        {"id": "schema", "path": ["artifact_schema"], "replacement": "forged"},
        {"id": "constraints", "path": ["relation_geometry", "m_constraints_lower_bound"], "replacement": M_CONSTRAINTS - 1},
        {"id": "variables", "path": ["relation_geometry", "n_nonconstant_variables_lower_bound"], "replacement": N_VARIABLES - 1},
        {"id": "public", "path": ["relation_geometry", "l_public_variables"], "replacement": L_PUBLIC - 1},
        {"id": "field-width", "path": ["relation_geometry", "canonical_field_element_bytes"], "replacement": 7},
        {"id": "modulus", "path": ["relation_geometry", "modulus_decimal"], "replacement": str(P - 1)},
        {"id": "relation-pin", "path": ["relation_geometry", "relation_manifest_sha256"], "replacement": "00" * 32},
        {"id": "manifest-pin", "path": ["relation_geometry", "manifest_authority_ledger_sha256"], "replacement": "00" * 32},
        {"id": "extension-degree", "path": ["security_arithmetic", "minimum_extension_degree_r"], "replacement": 2},
        {"id": "r2-admit", "path": ["security_arithmetic", "r2_meets_128"], "replacement": True},
        {"id": "qrom-composed", "path": ["security_arithmetic", "qrom_composition_included"], "replacement": True},
        {"id": "dv-floor", "path": ["size_screen", "quicksilver_designated_verifier_correction_floor", "bytes"], "replacement": 1},
        {"id": "voleith-elements", "path": ["size_screen", "voleith_large_odd_field_source_profile", "average_field_elements_per_gate"], "replacement": 2},
        {"id": "voleith-bytes", "path": ["size_screen", "voleith_large_odd_field_source_profile", "projected_payload_bytes"], "replacement": 490_973_447},
        {"id": "zkboo-rounds", "path": ["size_screen", "zkboo_direct_arithmetic_view_screen", "repetitions_for_classical_128_soundness"], "replacement": 218},
        {"id": "zkboo-bytes", "path": ["size_screen", "zkboo_direct_arithmetic_view_screen", "bytes"], "replacement": 1},
        {"id": "quicksilver-qrom", "path": ["candidates", 0, "finite_qrom_theorem_applicable"], "replacement": True},
        {"id": "voleith-qrom", "path": ["candidates", 1, "finite_qrom_theorem_applicable"], "replacement": True},
        {"id": "zkboo-complete-zk", "path": ["candidates", 2, "whole_view_complete_zk"], "replacement": True},
        {"id": "faest-generic", "path": ["candidates", 3, "relation_scope"], "replacement": "arbitrary R1CS"},
        {"id": "aurora-admit", "path": ["candidates", 4, "status"], "replacement": "authorized"},
        {"id": "source-url", "path": ["primary_sources", 0, "url"], "replacement": "https://example.invalid"},
        {"id": "source-hash", "path": ["primary_sources", 1, "sha256"], "replacement": "ff" * 32},
        {"id": "winner", "path": ["verdict", "mith_or_voleith_winner"], "replacement": "forged"},
        {"id": "backup-authority", "path": ["verdict", "backup_authorized"], "replacement": True},
        {"id": "aggregate-authority", "path": ["all_authority_false"], "replacement": False},
    ]
    for key in AUTHORITY_KEYS:
        mutations.append({
            "id": "authority-" + key,
            "path": ["authority", key],
            "replacement": True,
        })
    return mutations


def set_path(value: Any, path: list[Any], replacement: Any) -> None:
    cursor = value
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement


def verify_certificate(value: Any) -> list[str]:
    errors: list[str] = []
    expected = build_certificate()
    if not isinstance(value, dict):
        return ["certificate is not an object"]
    if value != expected:
        errors.append("certificate differs from the canonical source screen")
    authority = value.get("authority", {})
    if set(authority) != set(AUTHORITY_KEYS) or any(authority.values()):
        errors.append("authority ledger is not exact and all-false")
    if value.get("all_authority_false") is not True:
        errors.append("all_authority_false must be true")
    if minimum_extension_degree() != 3:
        errors.append("QuickSilver extension-degree arithmetic drift")
    if (M_CONSTRAINTS + 3) * (1 << TARGET_BITS) <= P**2:
        errors.append("r=2 unexpectedly meets target")
    if (M_CONSTRAINTS + 3) * (1 << TARGET_BITS) > P**3:
        errors.append("r=3 unexpectedly misses target")
    if M_CONSTRAINTS * 3 * FIELD_BYTES != 490_973_448:
        errors.append("VOLEitH source-profile byte projection drift")
    if M_CONSTRAINTS * FIELD_BYTES != 163_657_816:
        errors.append("QuickSilver correction floor drift")
    if zkb_repetitions() != 219:
        errors.append("ZKBoo repetition arithmetic drift")
    return errors


def verify_repo_pins() -> list[str]:
    errors: list[str] = []
    for relative, expected in [
        (RELATION_MANIFEST, RELATION_MANIFEST_SHA256),
        (MANIFEST_LEDGER, MANIFEST_LEDGER_SHA256),
    ]:
        path = REPO / relative
        if not path.is_file():
            errors.append(f"missing pinned repository source: {relative}")
        elif sha256_file(path) != expected:
            errors.append(f"pinned repository source drift: {relative}")
    return errors


def verify_primary_cache(directory: Path) -> list[str]:
    errors: list[str] = []
    for source in SOURCE_PINS:
        path = directory / source["local_cache_name"]
        if not path.is_file():
            errors.append(f"missing primary PDF: {path.name}")
            continue
        if path.stat().st_size != source["bytes"]:
            errors.append(f"primary PDF byte length drift: {path.name}")
        if sha256_file(path) != source["sha256"]:
            errors.append(f"primary PDF digest drift: {path.name}")
    return errors


def run_mutations() -> list[str]:
    errors: list[str] = []
    baseline = build_certificate()
    for mutation in build_mutations():
        changed = copy.deepcopy(baseline)
        set_path(changed, mutation["path"], mutation["replacement"])
        if not verify_certificate(changed):
            errors.append(f"mutation escaped: {mutation['id']}")
    return errors


def artifact_files() -> list[str]:
    return [
        "EXECPLAN.md",
        "README.md",
        "checker.py",
        "test_checker.py",
        "source_certificate.json",
        "mutation_corpus.json",
    ]


def render_hash_manifest() -> bytes:
    lines = []
    for name in artifact_files():
        path = HERE / name
        if not path.is_file():
            raise FileNotFoundError(path)
        lines.append(f"{sha256_file(path)}  {name}")
    return ("\n".join(lines) + "\n").encode()


def verify_artifact_hashes() -> list[str]:
    if not HASHES.is_file():
        return ["missing ARTIFACT_SHA256SUMS"]
    expected = render_hash_manifest()
    if HASHES.read_bytes() != expected:
        return ["artifact hash manifest drift"]
    return []


def write_generated() -> None:
    CERTIFICATE.write_bytes(canonical_bytes(build_certificate()))
    MUTATIONS.write_bytes(canonical_bytes(build_mutations()))
    HASHES.write_bytes(render_hash_manifest())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write canonical generated artifacts")
    parser.add_argument("--verify-primary-dir", type=Path)
    args = parser.parse_args()
    if args.write:
        write_generated()
    errors: list[str] = []
    if not CERTIFICATE.is_file():
        errors.append("missing source_certificate.json")
    else:
        raw = CERTIFICATE.read_bytes()
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"certificate parse failure: {exc}")
        else:
            errors.extend(verify_certificate(parsed))
            if raw != canonical_bytes(parsed):
                errors.append("certificate is not canonical JSON")
    if not MUTATIONS.is_file() or MUTATIONS.read_bytes() != canonical_bytes(build_mutations()):
        errors.append("mutation corpus drift")
    errors.extend(verify_repo_pins())
    errors.extend(run_mutations())
    errors.extend(verify_artifact_hashes())
    if args.verify_primary_dir is not None:
        errors.extend(verify_primary_cache(args.verify_primary_dir))
    result = {
        "ok": not errors,
        "errors": errors,
        "authority": "all false",
        "mutations_checked": len(build_mutations()),
        "quicksilver_correction_floor_bytes": M_CONSTRAINTS * FIELD_BYTES,
        "voleith_source_profile_projection_bytes": M_CONSTRAINTS * 3 * FIELD_BYTES,
        "minimum_extension_degree": minimum_extension_degree(),
        "certificate_sha256": sha256_file(CERTIFICATE) if CERTIFICATE.is_file() else None,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
