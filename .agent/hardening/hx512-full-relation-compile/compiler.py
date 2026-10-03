#!/usr/bin/env python3
"""Inactive executable semantics and cost projection for HX512B01.

The compiler reuses the frozen odd-field primitive library, widens the
HX448C02 diagnostic schedule to the current 512-bit semantic suite, and checks
the former manifest/state host-only predicates in the diagnostic interpreter
using the frozen all-W64 authority grammar.  It retains that interpreter, a
streaming Boolean BLAKE2b evaluator, and a compact projected macro ledger.  It
does not assign all intermediate R1CS wire IDs or emit sparse A/B/C
coordinates; it never builds a proof or authorizes production.
"""

from __future__ import annotations

import argparse
import dataclasses
import functools
import hashlib
import importlib.util
import json
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE_PATH = ROOT / ".agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py"
BASE_MANIFEST_PATH = ROOT / ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json"
BASE_TEST_PATH = ROOT / ".agent/hardening/hvzk-whir-odd-field-r1cs/test_compiler.py"
SUITE_PATH = ROOT / ".agent/hardening/hx512-semantic-suite/hx512_suite.py"
SUITE_SECURITY_PATH = ROOT / ".agent/hardening/hx512-semantic-suite/security_ledgers.json"
AUTHORITY_PATH = ROOT / ".agent/hardening/manifest-authority-closure/manifest_authority.py"
AUTHORITY_REPORT_PATH = ROOT / ".agent/hardening/manifest-authority-closure/cost_report.json"
AUTHORITY_LEDGER_PATH = ROOT / ".agent/hardening/manifest-authority-closure/capability_ledger.json"
AUTHORITY_MUTATION_PATH = ROOT / ".agent/hardening/manifest-authority-closure/mutation_corpus.json"
KERNEL_V2_PATH = ROOT / "protocol/kernel/src/stablecoin_manifest_authority_v2.rs"
KERNEL_V2_CHECKER_PATH = ROOT / "protocol/kernel/check_stablecoin_manifest_authority_v2.py"
KERNEL_V2_TEST_PATH = ROOT / "protocol/kernel/test_check_stablecoin_manifest_authority_v2.py"
KERNEL_LIB_PATH = ROOT / "protocol/kernel/src/lib.rs"
KERNEL_V2_EXPORT_LINE = "pub mod stablecoin_manifest_authority_v2;"
LIVE_ADMISSION_PATH = ROOT / "node/src/native/admission.rs"
LIVE_ADMISSION_EXACT_LINES = (
    ("nullifiers_nonempty", "if action.nullifiers.is_empty() {"),
    (
        "nullifiers_at_most_two",
        "if action.nullifiers.len() > transaction_core::constants::MAX_INPUTS {",
    ),
    ("commitments_nonempty", "if action.commitments.is_empty() {"),
    (
        "commitments_at_most_two",
        "if action.commitments.len() > transaction_core::constants::MAX_OUTPUTS {",
    ),
    ("binding_value_balance_zero", "value_balance: 0,"),
)
SCALAR_PATH = ROOT / "circuits/transaction/src/full_blake2b448_relation.rs"
M4_PATH = ROOT / "prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs"
M4_LIB_PATH = M4_PATH.with_name("lib.rs")
TEST_PATH = HERE / "test_compiler.py"
MANIFEST_PATH = HERE / "relation_manifest.json"
CERTIFICATE_PATH = HERE / "certificate.json"
MUTATION_PATH = HERE / "mutation_corpus.json"
EXECUTABLE_PATH = HERE / "executable_relation.py"
BOOLEAN_BLAKE_PATH = HERE / "blake2b_boolean.py"
PROFILE_PATH = HERE / "verifier_profile.py"

EXPECTED_DEPENDENCY_SHA512 = {
    rel_path: digest
    for rel_path, digest in {
        ".agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py": "62bd836c41fac8691e2ff97414c33d3bb955ae2b5cb833721e811e3e52b43c1793676a98178007fc3727bad825545cd8075d06b44c467d4d54b6a3cdf70226b5",
        ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json": "dae278e46a5d2ed2c58fae4443db8b73967f2b1190336520081a6f3791c04fad63d182cc61c0e1fb75f66bdb70e9ff40d4b1b975d9295fcf3a93bf189c76607e",
        ".agent/hardening/hvzk-whir-odd-field-r1cs/test_compiler.py": "e5e4eb4a5b2b3ff8f54160d5f498e7908b4166f14e867eeff5710c0b958643a4f0961718792a7efe8bdfeba7524d77fe04bb08c5dfc1a9c2ccdf0aa6e98e0069",
        ".agent/hardening/hx512-semantic-suite/hx512_suite.py": "0c8dc25ebea3a4850b6b487b977bd229b340622f9610d3d7306db6b3b355767dab69005c208bd31995605a560688ed59d0953157b2e7452518f631a1f676257c",
        ".agent/hardening/hx512-semantic-suite/security_ledgers.json": "2b988530dd42d8f32cf6c4e2102d04b30700654720917ef668168d7874de4b76df4b545942a88aff442fbc06e3c2e76692795f449ab9499980cf5b14de5d2d1e",
        ".agent/hardening/manifest-authority-closure/manifest_authority.py": "b225d5dbb832f985f5a78c570b5531b31c2cc6175d6aa19ce4e5955d0774e9bf9dc614a24cec60d207b7b23c1d94bfe93e58277c9ec70690330d313b6f6f824f",
        ".agent/hardening/manifest-authority-closure/cost_report.json": "d199125742082ad92973d81c4b970eef0f37e57d8e6f47716dd5bbacdbe9338183eb79056b5123f0a7fd527f512032d3af6444167df8571617825e601f483a4f",
        ".agent/hardening/manifest-authority-closure/capability_ledger.json": "60b3933fc2b674aafbb4c1889d3dc438dceebd5216e82f7d311f80b04a00a6292d843f5d553fdc2a6b1b6308cb191e389992b5e3744b99f879cc63ddb272d312",
        ".agent/hardening/manifest-authority-closure/mutation_corpus.json": "075f5d6c48cf093c68ce36f66cfb1af255ff1d081fa3742d95802ba6617e95a1a0c6b17a8e2fff95ee993cef2e604449d04c22b44c2dd249d998f36e56e08889",
        "protocol/kernel/src/stablecoin_manifest_authority_v2.rs": "99268907680ebff599f992e64f15cc9730f451eebd08b6e92776e66ee9afe567d6bf19eb1c1ff2482a3ea4a737a43e941cd04b7cb18f8e533239abdd474d395f",
        "protocol/kernel/check_stablecoin_manifest_authority_v2.py": "fe6228df9fce18ea13278ff034f1107d5b5b96408bbaadcfcd63c4fee1ccf95cb72a07e3c6ea8ec0f267fe494250366c54c02d3858a4429ddd6a5f926668e12e",
        "protocol/kernel/test_check_stablecoin_manifest_authority_v2.py": "4c5d29d02ea629b2d30aa9bc8b12ed93713d9d84fa16f5a8874d1906fb1351fba28aaa01670f1d94948c5bc92eed12ae6b7db885ca8092092250ef30e0c5b431",
        "circuits/transaction/src/full_blake2b448_relation.rs": "93fc32ebf9dbf36235caaedae41c93fe2868720a4938af9e9238914783c569eacd6aee7bc982a50c82267711657e20b2a90d76e66e0e4ee9595662aa0c05bb51",
        "prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs": "0cd45615489f2f84bfc803e7d94f0c7309c24a2ef37c8df4fdde0c651d0a81ba63502fe4fdfe41f7e6e3f68477797a951a878da42540a2d2b4e4f1eca624179c",
        "prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/lib.rs": "05ff6dc75e382f12e4e1893546e4ee018a5696d0ea3081981fc9e11fe59a62d1a0aeb58381b049747573b0cc756790827e0384bf8e39c031bc5a7b49fd00c9a1",
    }.items()
}


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BASE = _load("hegemon_hx512_base_r1cs", BASE_PATH)
SUITE = _load("hegemon_hx512_semantic_suite", SUITE_PATH)
AUTHORITY = _load("hegemon_hx512_manifest_authority", AUTHORITY_PATH)
EXECUTABLE = _load("hegemon_hx512_executable_relation", EXECUTABLE_PATH)
BOOLEAN_BLAKE = _load("hegemon_hx512_boolean_blake", BOOLEAN_BLAKE_PATH)
PROFILE = _load("hegemon_hx512_verifier_profile_compiler", PROFILE_PATH)

P = BASE.P
FIELD_BYTES = 8
DIGEST_BITS = 512
DIGEST_BYTES = 64
STATEMENT_BYTES = 1141
CONTEXT_BYTES = 72
PRIVATE_BYTES = 11_000
PUBLIC_BITS = (STATEMENT_BYTES + CONTEXT_BYTES) * 8
PRIVATE_BITS = PRIVATE_BYTES * 8
MANIFEST_WITNESS_BYTES = 480
MANIFEST_SEMANTIC_BYTES = 475
MANIFEST_OFFSET = PRIVATE_BYTES - MANIFEST_WITNESS_BYTES
CANONICAL_CIPHERTEXT_BYTES = 2147

IDENTITY_NAME = "blake2b512_rfc"
MAGIC = b"HX512B01"
GRAMMAR = 1

# The transaction prefix is a widened but position-stable version of the
# frozen private grammar.  The added policy-master section makes the two
# 512-bit authorization masters explicit instead of aliasing accumulator data.
WITNESS_SECTIONS = (
    ("input[0]", 0, 298 * 8),
    ("input[1]", 298 * 8, 298 * 8),
    ("output[0]", 596 * 8, 33 * 8),
    ("output[1]", 629 * 8, 33 * 8),
    ("authorization", 662 * 8, 99 * 8),
    ("policy_masters", 761 * 8, 16 * 8),
    ("ciphertext[0]", 777 * 8, 269 * 8),
    ("ciphertext[1]", 1046 * 8, 269 * 8),
    ("manifest_membership", 1315 * 8, 60 * 8),
)

CORE_TRANSACTION_GROUPS = tuple(BASE.LOCAL_GROUPS) + tuple(BASE.HASH_LINK_GROUPS)
AUTHORITY_GROUPS = (
    "all-W64 manifest transport and selected-row canonicality",
    "all-W64 selected row to statement equality",
    "all-W64 policy identity output equality",
    "all-W64 selected leaf and depth-four root recomputation",
    "all-W64 selected lifecycle oracle dispute and cap",
    "all-W64 snapshot reconstruction and verifier context equality",
)

FORMER_HOST_FORGERIES = (
    "forged_policy_hash_derivation",
    "forged_selected_entry_membership",
    "forged_whole_manifest_or_path_root",
    "forged_consensus_expected_root_or_height",
)


class Reject(ValueError):
    """Canonical parser or semantic-gate rejection."""


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def sha512_file(path: Path) -> str:
    return hashlib.sha512(path.read_bytes()).hexdigest()


def shake_digest(domain: bytes, payload: bytes) -> str:
    return hashlib.shake_256(
        domain + len(payload).to_bytes(8, "big") + payload
    ).hexdigest(64)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def source_contracts() -> None:
    for path_name, expected in EXPECTED_DEPENDENCY_SHA512.items():
        path = ROOT / path_name
        if not path.is_file() or sha512_file(path) != expected:
            raise Reject(f"frozen dependency SHA-512 drift: {path_name}")
    try:
        AUTHORITY.check()
    except Exception as error:
        raise Reject(f"upstream retained authority artifact drift: {error}") from error
    identity = SUITE.IDENTITIES[IDENTITY_NAME]
    required_identity = {
        "statement_magic": MAGIC.decode(),
        "frame_profile": MAGIC.decode(),
        "statement_grammar": GRAMMAR,
        "circuit_version": 0x5121,
        "crypto_suite": 0x512B,
        "family_id": 0x5123,
        "action_id": 0x5124,
        "network_id": 0x48583531,
        "backend_id": 0x51,
        "proof_profile": 0x52,
        "domain_set": 0x5127,
    }
    if identity != required_identity:
        raise Reject("HX512B01 identity drift")
    if (
        SUITE.STATEMENT_BYTES,
        SUITE.VERIFIER_CONTEXT_BYTES,
        SUITE.PRIVATE_BYTES,
        SUITE.MANIFEST_ROW_BYTES,
        SUITE.MANIFEST_CAP,
        SUITE.MANIFEST_DEPTH,
    ) != (STATEMENT_BYTES, CONTEXT_BYTES, PRIVATE_BYTES, 215, 16, 4):
        raise Reject("semantic-suite geometry drift")
    if list(SUITE.OFFSETS.items()) != list(statement_offsets().items()):
        raise Reject("semantic-suite statement offsets drift")
    verifier_profile = PROFILE.descriptor()
    profile_identity = verifier_profile["diagnostic_relation_identity"]
    if (
        profile_identity["statement_magic_ascii"],
        profile_identity["statement_grammar_u16be"],
        profile_identity["circuit_version_u16be"],
        profile_identity["crypto_suite_u16be"],
        profile_identity["family_id_u16be"],
        profile_identity["action_id_u16be"],
        profile_identity["network_id_u32be"],
        profile_identity["backend_id_u8"],
        profile_identity["proof_profile_u8"],
        profile_identity["domain_set_u16be"],
    ) != (
        "HX512B01", 1, 0x5121, 0x512B, 0x5123, 0x5124,
        0x48583531, 0x51, 0x52, 0x5127,
    ):
        raise Reject("canonical verifier-profile identity drift")
    if len(PROFILE.DIAGNOSTIC_RULES_HASH) != 64 or PROFILE.DIAGNOSTIC_RULES_HASH in (
        bytes(64), bytes([0x33]) * 64
    ):
        raise Reject("non-self-referential diagnostic relation rules hash drift")
    if (
        profile_identity["production_identity_allocated"]
        or profile_identity["final_consensus_rules_hash_frozen"]
        or profile_identity["final_consensus_rules_hash_hex"] is not None
    ):
        raise Reject("diagnostic relation profile allocated consensus authority")
    proof_profile = verifier_profile["proof_system_required_but_unallocated"]
    if proof_profile["final_profile_frozen"] or proof_profile["engine_adapter_integrated"]:
        raise Reject("diagnostic profile allocated a proof backend")
    required_unallocated = (
        "fresh_arithmetization_identity",
        "packing_factor",
        "pcs_parameters",
        "piop_parameters",
        "decs_parameters",
        "complete_zk_mask_width_and_tape_grammar",
        "fiat_shamir_transcript",
        "transcript_domain_registry",
        "inner_wire_magic",
        "outer_envelope_magic",
        "outer_envelope_version",
        "statement_and_context_binding_preamble",
    )
    if any(proof_profile[key] is not None for key in required_unallocated):
        raise Reject("diagnostic profile proof identity is not fully unallocated")
    costs = SUITE.r1cs_costs()
    if (
        costs["fresh_shared"]["manifest_and_state_non_bitness_rows"],
        costs["blake2b512_rfc"]["m_constraints_source_static"],
        costs["blake2b512_rfc"]["delta_vs_frozen_hx448c02"],
    ) != (11_592, 29_510_157, 9_052_930):
        raise Reject("semantic-suite exact source projection drift")
    counts = SUITE.profile_counts(IDENTITY_NAME)
    if (
        counts["core_physical_calls"],
        counts["authority_physical_calls"],
        counts["core_blake2b512_compressions"],
        counts["authority_blake2b512_compressions"],
        counts["relation_blake2b512_compressions"],
    ) != (83, 7, 205, 8, 213):
        raise Reject("semantic-suite composite hash schedule drift")
    report = json.loads(AUTHORITY_REPORT_PATH.read_text())
    profile = report["profiles"]["fresh-v2-all-w64-merkle-w64"]
    if (
        profile["entry_bytes"],
        profile["cap"],
        profile["depth"],
        profile["semantic_witness_bytes"],
        profile["m4_source_static"]["private_witness_transport_bytes"],
        profile["hash_schedule"]["total_relation_compressions"],
    ) != (215, 16, 4, 475, 480, 7):
        raise Reject("frozen all-W64 authority profile drift")
    structural = profile["r1cs"]["structural_rows"]
    authority_local_non_bitness = profile["r1cs"]["structural_rows_total"] - (
        structural["new_private_bitness"] + structural["new_public_bitness"]
    )
    if authority_local_non_bitness != 6_237:
        raise Reject("frozen authority-local non-bitness decomposition drift")
    if AUTHORITY.identity_personalization(
        AUTHORITY.IDENTITY_ROLE_POLICY, 64
    ) != b"HGMAIDV2\x01\x02\x40" + bytes(5):
        raise Reject("all-W64 policy personalization drift")
    if AUTHORITY.personalization(
        AUTHORITY.ROLE_LEAF, 64, 16, profile=AUTHORITY.FRESH_V2_AUTHORITY_PROFILE
    ) != b"HGMAROOT\x02\x02\x40\x04\x00" + bytes(3):
        raise Reject("all-W64 leaf personalization drift")
    if AUTHORITY.personalization(
        AUTHORITY.ROLE_SNAPSHOT,
        64,
        16,
        profile=AUTHORITY.FRESH_V2_AUTHORITY_PROFILE,
    ) != b"HGMAROOT\x04\x02\x40\x04\x00" + bytes(3):
        raise Reject("all-W64 snapshot personalization drift")
    if KERNEL_LIB_PATH.read_text().splitlines().count(KERNEL_V2_EXPORT_LINE) != 1:
        raise Reject("inactive kernel V2 export line absent or duplicated")
    live_lines = [line.strip() for line in LIVE_ADMISSION_PATH.read_text().splitlines()]
    for name, exact_line in LIVE_ADMISSION_EXACT_LINES:
        if live_lines.count(exact_line) != 1:
            raise Reject(f"live route exact-line contract drift: {name}")
    executable = EXECUTABLE.executable_ir_certificate()
    matrix = executable["activity_stablecoin_matrix"]
    if (
        executable["physical_hash_calls"],
        executable["fixed_blake2b512_compressions"],
        executable["all_33_accepted_mask_mode_pairs_evaluated"],
        executable["all_33_stablecoin_enabled_mask_mode_pairs_evaluated"],
        executable["policy_version_zero_evaluated"],
        executable["semantic_source_operands_named"],
        executable["numeric_r1cs_operand_ids_assigned"],
        executable["sparse_r1cs_rows_emitted"],
        matrix["total_cells"],
        matrix["positive_cells"],
        matrix["negative_cells"],
        matrix["all_negative_cells_reach_activity_mask_mode"],
    ) != (90, 213, True, True, True, True, False, False, 160, 66, 94, True):
        raise Reject("executable relation IR contract drift")
    if any(
        executable[key]
        for key in (
            "exact_full_production_relation",
            "stablecoin_issuer_or_collateral_capability_enforced",
            "stablecoin_minimum_collateral_ratio_evaluated",
            "stablecoin_epoch_cap_cumulative_and_atomic",
            "no_input_anchor_canonical_or_authenticated",
            "activity_mask_mode_grammar_matches_active_native_route",
            "live_route_value_balance_zero_enforced",
        )
    ) or not executable["known_accepted_production_counterexamples"]:
        raise Reject("diagnostic semantic blocker boundary drift")
    if len(EXECUTABLE.mutation_residuals()) < 37:
        raise Reject("executable mutation residual coverage drift")
    live_route = live_route_semantics_audit()
    if (
        live_route["diagnostic_accepted_pairs"],
        live_route["live_route_accepted_pairs"],
        live_route["diagnostic_only_pairs"],
        live_route["live_route_accepted_by_mode"],
        live_route["binding_value_balance_is_fixed_zero"],
    ) != (33, 26, 7, [9, 6, 2, 6, 3], True):
        raise Reject("diagnostic/live route semantic divergence audit drift")
    boolean_trace = boolean_hash_trace_certificate()
    if (
        boolean_trace["physical_calls"],
        boolean_trace["total_compressions"],
        boolean_trace["total_boolean_hash_rows_per_fixture"],
        boolean_trace["all_fixture_call_records"],
        boolean_trace["all_fixture_fixed_compressions"],
        boolean_trace["all_66_call_digests_equal_independent_hashlib"],
        boolean_trace["selected_exhaustive_bit_rows"],
        boolean_trace["selected_exhaustive_planned_rows"],
        boolean_trace["selected_exhaustive_trace_executed"],
        boolean_trace["frame_role_swap_rejects"],
        boolean_trace["personalization_bit_swap_rejects"],
    ) != (90, 213, 29_049_792, 5_940, 14_058, True, 0, 87_149_376, False, True, True):
        raise Reject("streaming Boolean BLAKE2b trace drift")


@functools.lru_cache(maxsize=1)
def boolean_hash_trace_certificate() -> dict[str, Any]:
    fixed_personalizations = PROFILE.expected_personalization_hex_by_call()
    fixtures = (
        *EXECUTABLE.all_accepted_fixtures(),
        *EXECUTABLE.all_stablecoin_accepted_fixtures(),
    )
    streams = []
    total_calls = 0
    total_compressions = 0
    for fixture in fixtures:
        evaluation = EXECUTABLE.evaluate(
            fixture.statement, fixture.context, fixture.witness
        )
        trace = BOOLEAN_BLAKE.trace_relation(
            evaluation.hash_calls,
            expected_personalization_hex_by_call=fixed_personalizations,
            exhaustive_bits=False,
        )
        total_calls += trace["physical_calls"]
        total_compressions += trace["total_compressions"]
        streams.append(
            {
                "mode": fixture.mode,
                "mask": fixture.mask,
                "stable_enabled": fixture.stable_enabled,
                "physical_calls": trace["physical_calls"],
                "fixed_compressions": trace["total_compressions"],
                "call_stream_digest_sha512": hashlib.sha512(
                    canonical_json(trace["calls"])
                ).hexdigest(),
                "every_call_digest_equals_independent_hashlib": trace[
                    "every_call_digest_equals_independent_hashlib"
                ],
            }
        )

    # The language is disqualified by accepted production counterexamples.
    # Evaluating the planned 87,149,376 selected bit rows would spend resources
    # after a semantic gate has already failed, so the expensive run is
    # intentionally not performed or claimed.
    selected: list[dict[str, Any]] = []

    baseline = EXECUTABLE.evaluate(
        fixtures[-1].statement, fixtures[-1].context, fixtures[-1].witness
    )
    frame_swap_rejects = False
    parameter_swap_rejects = False
    first = baseline.hash_calls[0]
    changed_message = bytearray.fromhex(first.message_hex)
    changed_message[8] ^= 1
    try:
        BOOLEAN_BLAKE.trace_call(
            dataclasses.replace(first, message_hex=bytes(changed_message).hex()),
            expected_personalization_hex=fixed_personalizations[0],
        )
    except BOOLEAN_BLAKE.BooleanTraceError:
        frame_swap_rejects = True
    authority_call = baseline.hash_calls[83]
    changed_person = bytearray.fromhex(authority_call.personalization_hex or "")
    changed_person[0] ^= 1
    try:
        BOOLEAN_BLAKE.trace_call(
            dataclasses.replace(
                authority_call, personalization_hex=bytes(changed_person).hex()
            ),
            expected_personalization_hex=fixed_personalizations[83],
        )
    except BOOLEAN_BLAKE.BooleanTraceError:
        parameter_swap_rejects = True

    kats = BOOLEAN_BLAKE.parameter_state_kats(fixed_personalizations)
    if kats["profiles"] != [
        {
            "personalization_hex": item["personalization_hex"],
            "parameter_block_hex": item["parameter_block_hex"],
            "constant_folded_initial_state_u64le_hex": item[
                "constant_folded_initial_state_u64le_hex"
            ],
        }
        for item in PROFILE.parameter_profiles()
    ]:
        raise Reject("constant-folded BLAKE2b initial-state KAT drift")
    return {
        "artifact_schema": "hegemon.hx512b01.blake2b-boolean-coverage.v2",
        "fixture_streams": streams,
        "fixtures": len(fixtures),
        "physical_calls": 90,
        "total_compressions": 213,
        "all_fixture_call_records": total_calls,
        "all_fixture_fixed_compressions": total_compressions,
        "compression_rows_per_fixture": 29_049_792,
        "parameter_not_rows_per_fixture": 0,
        "total_boolean_hash_rows_per_fixture": 29_049_792,
        "all_66_call_digests_equal_independent_hashlib": all(
            item["every_call_digest_equals_independent_hashlib"] for item in streams
        ),
        "all_66_every_bit_row_evaluated": False,
        "selected_exhaustive_traces": selected,
        "selected_exhaustive_bit_rows": 0,
        "selected_exhaustive_planned_rows": 87_149_376,
        "selected_exhaustive_trace_executed": False,
        "semantic_gate_failed_before_expensive_trace": True,
        "semantic_gate_failure": "three accepted production counterexamples",
        "constant_folded_parameter_state_kats": kats,
        "frame_role_swap_rejects": frame_swap_rejects,
        "personalization_bit_swap_rejects": parameter_swap_rejects,
        "caller_supplied_parameters_accepted": False,
        "expanded_sparse_rows_retained": False,
    }


def statement_offsets() -> OrderedDict[str, int]:
    return OrderedDict(
        magic=0,
        grammar=8,
        flags=10,
        anchor=14,
        nullifiers=78,
        commitments=206,
        ciphertext_hashes=334,
        ciphertext_sizes=462,
        assets=470,
        fee=502,
        value_balance_sign=510,
        value_balance_magnitude=511,
        stable_enabled=519,
        stable_asset=520,
        stable_version=528,
        stable_issuance_sign=532,
        stable_issuance_magnitude=533,
        stable_policy=541,
        stable_oracle=605,
        stable_attestation=669,
        manifest_root=733,
        state_root=797,
        state_height=861,
        balance_tag=869,
        activation=933,
        network=941,
        backend=945,
        profile=946,
        domain_set=947,
        chain_id=949,
        genesis_id=1013,
        rules_hash=1077,
        end=1141,
    )


def _field(raw: bytes, name: str) -> bytes:
    offsets = statement_offsets()
    names = list(offsets)
    index = names.index(name)
    return raw[offsets[name] : offsets[names[index + 1]]]


def parse_statement(raw: bytes) -> dict[str, bytes]:
    try:
        EXECUTABLE.Statement.decode(raw)
    except Exception as error:
        raise Reject(str(error)) from error
    parsed = {
        item["name"]: raw[item["offset"] : item["offset"] + item["bytes"]]
        for item in SUITE.statement_layout()
    }
    flags = tuple(bool(value) for value in parsed["flags"])
    signs = (raw[510], raw[532])
    if any(value not in (0, 1) for value in signs):
        raise Reject("signed-magnitude sign is noncanonical")
    if raw[510] == 1 and raw[511:519] == bytes(8):
        raise Reject("value-balance negative zero is noncanonical")
    if raw[532] == 1 and raw[533:541] == bytes(8):
        raise Reject("stablecoin issuance negative zero is noncanonical")
    sizes = (
        int.from_bytes(parsed["ciphertext_sizes"][:4], "big"),
        int.from_bytes(parsed["ciphertext_sizes"][4:], "big"),
    )
    for index, active in enumerate(flags[2:]):
        expected = CANONICAL_CIPHERTEXT_BYTES if active else 0
        if sizes[index] != expected:
            raise Reject("ciphertext size does not match output activity")
    assets = [
        int.from_bytes(parsed["assets"][index * 8 : (index + 1) * 8], "big")
        for index in range(4)
    ]
    if assets[0] != 0:
        raise Reject("asset slot zero is not native")
    padding = (1 << 64) - 1
    seen_padding = False
    last = 0
    for asset in assets[1:]:
        if asset == padding:
            seen_padding = True
            continue
        if seen_padding or asset == 0 or asset >= P or asset <= last:
            raise Reject("non-native asset slots are not canonical")
        last = asset
    stable = raw[519]
    if stable not in (0, 1):
        raise Reject("stablecoin enable byte is noncanonical")
    if stable:
        asset = int.from_bytes(raw[520:528], "big")
        magnitude = int.from_bytes(raw[533:541], "big")
        if asset == 0 or asset not in assets[1:] or magnitude == 0:
            raise Reject("enabled stablecoin surface is not canonical")
        if not any(raw[733:797]):
            raise Reject("enabled manifest root must be nonzero")
    else:
        if any(raw[520:869]):
            raise Reject("disabled stablecoin/state surface is not uniquely zero")
    return parsed


@dataclass(frozen=True)
class VerifierContext:
    manifest_root: bytes
    parent_height: int

    def encode(self) -> bytes:
        if len(self.manifest_root) != 64 or not 0 <= self.parent_height < 1 << 64:
            raise Reject("invalid verifier context")
        # The context follows the frozen authority grammar, hence u64le.
        return self.manifest_root + self.parent_height.to_bytes(8, "little")

    @classmethod
    def decode(cls, raw: bytes) -> "VerifierContext":
        if type(raw) is not bytes or len(raw) != CONTEXT_BYTES:
            raise Reject("verifier context must be exactly 72 bytes")
        value = cls(raw[:64], int.from_bytes(raw[64:], "little"))
        if value.encode() != raw:
            raise Reject("verifier context is noncanonical")
        return value


@dataclass(frozen=True)
class ParsedWitness:
    raw: bytes
    sections: dict[str, bytes]
    manifest: Any | None
    ciphertexts: tuple[bytes, bytes]
    auth_mode: int


def parse_witness(raw: bytes, stable_enabled: bool) -> ParsedWitness:
    if type(raw) is not bytes or len(raw) != PRIVATE_BYTES:
        raise Reject("private witness must be exactly 11000 bytes")
    sections = {
        name: raw[offset : offset + width]
        for name, offset, width in WITNESS_SECTIONS
    }
    if any(offset + width > PRIVATE_BYTES for _, offset, width in WITNESS_SECTIONS):
        raise AssertionError("witness section outside transport")
    for name in ("ciphertext[0]", "ciphertext[1]"):
        if sections[name][CANONICAL_CIPHERTEXT_BYTES:] != bytes(5):
            raise Reject("ciphertext transport padding is nonzero")
    manifest_raw = sections["manifest_membership"]
    if manifest_raw[MANIFEST_SEMANTIC_BYTES:] != bytes(5):
        raise Reject("manifest transport padding is nonzero")
    if stable_enabled:
        try:
            manifest = AUTHORITY.FreshMerkleWitnessV2W64.decode(
                manifest_raw[:MANIFEST_SEMANTIC_BYTES]
            )
        except Exception as error:
            raise Reject(str(error)) from error
    else:
        if manifest_raw != bytes(MANIFEST_WITNESS_BYTES):
            raise Reject("disabled manifest witness must be uniquely zero")
        manifest = None
    mode = int.from_bytes(sections["authorization"][:8], "big")
    if mode >= 5:
        raise Reject("authorization mode is outside 0..4")
    return ParsedWitness(
        raw,
        sections,
        manifest,
        (
            sections["ciphertext[0]"][:CANONICAL_CIPHERTEXT_BYTES],
            sections["ciphertext[1]"][:CANONICAL_CIPHERTEXT_BYTES],
        ),
        mode,
    )


def activity_shape_accepts(mode: int, flags: Sequence[bool]) -> bool:
    if len(flags) != 4 or mode not in range(5):
        return False
    i0, i1, o0, o1 = flags
    if not any(flags):
        return False
    if mode == 0:
        return True
    if mode in (1, 3):
        return (i0 or i1) and o0
    if mode == 2:
        return i0 and i1 and o0
    return i0 and i1


def ciphertext_digest(index: int, ciphertext: bytes) -> bytes:
    if index not in (0, 1):
        raise Reject("ciphertext output index")
    if len(ciphertext) != CANONICAL_CIPHERTEXT_BYTES:
        raise Reject("ciphertext semantic width")
    message = SUITE.frame(
        MAGIC,
        SUITE.ROLE_CIPHERTEXT,
        [
            bytes([0x52]),
            (0x5127).to_bytes(2, "big"),
            bytes([index]),
            CANONICAL_CIPHERTEXT_BYTES.to_bytes(4, "big"),
            ciphertext,
        ],
    )
    if len(message) != 2182:
        raise AssertionError("ciphertext frame drift")
    return hashlib.blake2b(message, digest_size=64).digest()


def verify_reference(statement: bytes, context_raw: bytes, witness_raw: bytes) -> None:
    try:
        EXECUTABLE.evaluate(statement, context_raw, witness_raw)
    except EXECUTABLE.RelationFailure as error:
        raise Reject(str(error)) from error


def sample_valid_case() -> tuple[bytes, bytes, bytes]:
    fixture = EXECUTABLE.build_fixture(
        mode=0,
        mask=0b1111,
        stable_enabled=True,
        policy_version=0,
    )
    return fixture.statement, fixture.context, fixture.witness


def _configure_base() -> None:
    BASE.DIGEST_BITS = DIGEST_BITS
    BASE.STABLE_DIGEST_BITS = DIGEST_BITS
    BASE.PUBLIC_BITS = PUBLIC_BITS
    BASE.PRIVATE_BITS = PRIVATE_BITS
    original_eq = getattr(BASE, "_hx512_original_eq_constant_bytes", None)
    if original_eq is None:
        original_eq = BASE.eq_constant_bytes
        BASE._hx512_original_eq_constant_bytes = original_eq

    def bound_constants(program: Any, payload: bytes, label: str) -> None:
        if label == "magic and grammar":
            payload = MAGIC + GRAMMAR.to_bytes(2, "big")
        original_eq(program, payload, label)

    BASE.eq_constant_bytes = bound_constants
    BASE.activation_bytes = lambda: SUITE.activation_bytes(IDENTITY_NAME)


def emit_shared_transaction(program: Any) -> None:
    BASE.emit_local_relation(program)
    # Exact widening deltas from 261/30/89-word HX448 layouts to the explicit
    # 298/33/99+16-word HX512 layouts. These supplement, never replace, the
    # inherited semantic constraints.
    program.group(BASE.LOCAL_GROUPS[6])
    program.invoke("cond_zero", 2, 37 * 64, "inactive widened input suffixes")
    program.group(BASE.LOCAL_GROUPS[8])
    program.invoke("cond_zero", 2, 3 * 64, "inactive widened output suffixes")
    program.group(BASE.LOCAL_GROUPS[13])
    program.invoke("cond_zero", 1, 16 * 64, "single-key policy-master extension")
    program.invoke("cond_zero", 1, 46 * 64, "mode-specific widened authorization lanes")
    program.group(BASE.LOCAL_GROUPS[14])
    program.invoke("select", 1, 2 * 64, "widened accumulator digest selection")
    program.invoke("cond_zero", 1, 8 * 64, "inactive policy-master structure")
    program.invoke(
        "select",
        1,
        DIGEST_BITS,
        "five-mode current-or-next policy-master selection for policy call",
    )
    program.group(BASE.LOCAL_GROUPS[15])
    program.invoke("cond_eq", 1, 8 * 64, "widened approval policy/intent equality")
    program.invoke(
        "cond_eq",
        1,
        DIGEST_BITS,
        "approval current and next policy masters are identical",
    )
    BASE.emit_hash_links(program)


def emit_authority_relation(program: Any) -> None:
    program.group(AUTHORITY_GROUPS[0])
    program.invoke("eq_zero", 28, note="u32le selected index is below cap16")
    program.invoke("eq_zero", 40, note="five manifest transport pad bytes")
    program.invoke(
        "eq_zero",
        3,
        7,
        "high bits of retired-present active and disputed Boolean bytes",
    )
    program.invoke("cond_zero", 1, 64, "absent retired_at has zero payload")
    program.invoke("eq_zero", 32, note="public stable asset fits selected u32 asset id")
    program.invoke(
        "cond_eq",
        1,
        1,
        "selected manifest leaf presence equals stable-enabled flag",
    )

    program.group(AUTHORITY_GROUPS[1])
    program.invoke(
        "cond_eq",
        1,
        32 + 32 + 2 * DIGEST_BITS,
        "selected asset/version/oracle/attestation equal statement",
    )

    program.group(AUTHORITY_GROUPS[2])
    program.invoke("cond_eq", 1, DIGEST_BITS, "61-byte policy constructor output")

    program.group(AUTHORITY_GROUPS[3])
    program.invoke("select", 8, DIGEST_BITS, "four left/right path pairs")
    program.invoke("nonzero", 1, DIGEST_BITS, "manifest root nonzero")
    program.invoke("implies", 1, note="enabled manifest root is nonzero")
    program.invoke("cond_eq", 1, DIGEST_BITS, "depth-four root equals statement")
    program.invoke(
        "cond_zero",
        1,
        DIGEST_BITS + 64,
        "disabled manifest root and height are uniquely zero",
    )

    program.group(AUTHORITY_GROUPS[4])
    program.invoke("cond_eq", 1, 1, "selected row active")
    program.invoke("le", 1, 64, "enabled_at <= parent height")
    program.invoke("implies", 1, note="lifecycle opened")
    program.invoke("implies", 1, note="retired_at zero when absent")
    program.invoke("and", 1, note="enabled and retirement-present")
    program.invoke("lt", 1, 64, "parent height < retired_at")
    program.invoke("implies", 1, note="retirement bound")
    program.invoke("le", 2, 64, "oracle nonfuture and freshness deadline")
    program.invoke("add64", 1, note="oracle submitted_at + max_age")
    program.invoke("or", 1, note="freshness saturation")
    program.invoke("implies", 2, note="oracle time predicates")
    program.invoke("cond_eq", 1, 1, "attestation undisputed")
    program.invoke("nonzero", 1, 64, "issuance nonzero")
    program.invoke("implies", 1, note="issuance nonzero when enabled")
    program.invoke("nonzero", 1, 64, "u128 cap high limb")
    program.invoke("le", 1, 64, "issuance <= low cap")
    program.invoke("or", 1, note="high cap limb or low comparison")
    program.invoke("implies", 1, note="issuance cap")

    program.group(AUTHORITY_GROUPS[5])
    program.invoke("cond_eq", 1, DIGEST_BITS, "snapshot output equals statement state root")
    program.invoke("cond_eq", 1, DIGEST_BITS, "statement manifest root equals verifier context")
    program.invoke("cond_eq", 1, 64, "statement height equals verifier context")
    program.invoke(
        "cond_zero",
        1,
        2 * DIGEST_BITS + 64,
        "disabled state root and verifier context uniquely zero",
    )


def emit_blake2b512(program: Any) -> None:
    program.group("HX512B01 core frame source wiring")
    program.invoke("alias", 1, note="83 exact typed core frame views")

    program.group("RFC7693 BLAKE2b-512 core Boolean ARX")
    program.invoke("add64", 205 * 576, note="205 core compressions, 576 additions each")
    program.invoke("xor", 205 * 403, 64, "205 core compressions, 403 word XORs each")

    program.group("authorization select-before-BLAKE2b-512")
    program.invoke("onehot_select5", 4, 3 * 128 * 8, "three padded message blocks")
    program.invoke("onehot_select5", 12, 64, "per-block cumulative counters")
    program.invoke("onehot_select5", 12, 1, "per-block final flags")
    program.invoke("select", 4, DIGEST_BITS, "two-versus-three compression digest")

    program.group("HGMAIDV2/HGMAROOT BLAKE2b-512 Boolean ARX")
    program.invoke(
        "add64",
        8 * 576,
        "policy1 + leaf2 + four nodes + snapshot1 compressions",
    )
    program.invoke("xor", 8 * 403, 64, "eight authority compression XOR schedules")


def compile_relation() -> Any:
    source_contracts()
    _configure_base()
    program = BASE.Program("hx512b01-blake2b512-all-w64")
    emit_shared_transaction(program)
    emit_authority_relation(program)
    emit_blake2b512(program)
    return program


def next_power_of_two(value: int) -> int:
    if value <= 0:
        raise Reject("power-of-two input")
    return 1 << (value - 1).bit_length()


def section11_projection(geometry: dict[str, int]) -> dict[str, Any]:
    public_with_constant = geometry["l_public_variables"] + 1
    witness_used = geometry["auxiliary_variables_total"]
    ell = next_power_of_two(
        max(public_with_constant, witness_used, (geometry["m_constraints"] + 1) // 2)
    )
    witness_padding = ell - witness_used
    witness_zero_end = geometry["m_constraints"] + witness_padding
    if witness_zero_end > 2 * ell:
        raise Reject("Section 11 carrier row capacity")
    log2_ell = ell.bit_length() - 1
    inner_masks = 3 * (log2_ell + 1)
    outer_masks = log2_ell + 1
    return {
        "ell": ell,
        "n0": ell,
        "log2_ell": log2_ell,
        "sumcheck_boolean_variables_log2_2ell": log2_ell + 1,
        "matrix_shape": [2 * ell, 2 * ell],
        "source_rows": geometry["m_constraints"],
        "source_nonzeros": geometry["matrix_nonzeros_total"],
        "public_zero_padding": ell - public_with_constant,
        "witness_zero_padding": witness_padding,
        "row_zero_padding": 2 * ell - witness_zero_end,
        "carrier_nonzeros": geometry["matrix_nonzeros_total"] + 2 * witness_padding,
        "encoded_oracles": {
            "witness": 1,
            "inner_mask_oracles_3_times_log2_ell_plus_1": inner_masks,
            "outer_mask_oracles_log2_ell_plus_1": outer_masks,
            "total": 1 + inner_masks + outer_masks,
        },
        "projection_defined_source_only": True,
        "section11_theorem_instantiated": False,
        "complete_hvzk_proved": False,
    }


def source_entries() -> list[dict[str, Any]]:
    paths = [
        Path(__file__).resolve(),
        EXECUTABLE_PATH,
        BOOLEAN_BLAKE_PATH,
        PROFILE_PATH,
        TEST_PATH,
        BASE_PATH,
        BASE_MANIFEST_PATH,
        BASE_TEST_PATH,
        SUITE_PATH,
        SUITE_SECURITY_PATH,
        AUTHORITY_PATH,
        AUTHORITY_REPORT_PATH,
        AUTHORITY_LEDGER_PATH,
        AUTHORITY_MUTATION_PATH,
        KERNEL_V2_PATH,
        KERNEL_V2_CHECKER_PATH,
        KERNEL_V2_TEST_PATH,
        SCALAR_PATH,
        M4_PATH,
        M4_LIB_PATH,
    ]
    roles = {
        Path(__file__).resolve(): "inactive HX512 macro compiler and checker",
        EXECUTABLE_PATH: "typed source-level semantic schema and executable interpreter",
        BOOLEAN_BLAKE_PATH: "streaming exact RFC7693 Boolean ARX row evaluator",
        PROFILE_PATH: "canonical non-self-referential diagnostic relation profile and test-only rules hash",
        TEST_PATH: "dependency-free parser geometry and forgery tests",
        BASE_PATH: "frozen odd-field primitive and HX448 source schedule",
        BASE_MANIFEST_PATH: "frozen HX448 negative-baseline geometry",
        BASE_TEST_PATH: "frozen odd-field primitive and macro tests",
        SUITE_PATH: "fresh HX512 identity core frames witness widths and KATs",
        SUITE_SECURITY_PATH: "fail-closed semantic security ledgers",
        AUTHORITY_PATH: "frozen specialized all-W64 constructors and membership",
        AUTHORITY_REPORT_PATH: "frozen all-W64 exact source-static cost profile",
        AUTHORITY_LEDGER_PATH: "frozen authority capability boundary",
        AUTHORITY_MUTATION_PATH: "frozen all-W64 exhaustive mutation corpus",
        KERNEL_V2_PATH: "inactive source-exact all-W64 kernel authority",
        KERNEL_V2_CHECKER_PATH: "inactive kernel authority source checker",
        KERNEL_V2_TEST_PATH: "inactive kernel authority dependency-free tests",
        SCALAR_PATH: "frozen scalar semantic source",
        M4_PATH: "frozen full relation-family source",
        M4_LIB_PATH: "frozen private witness and authorization semantics",
    }
    entries = [
        {
            "bytes": path.stat().st_size,
            "path": rel(path),
            "role": roles[path],
            "sha512": sha512_file(path),
        }
        for path in paths
        if path.is_file()
    ]
    # `lib.rs` is a shared integration surface and is intentionally not pinned as
    # a whole file: unrelated modules can legitimately land concurrently.  The
    # inactive V2 seam is nevertheless source-bound by requiring exactly one
    # byte-exact export line above and retaining this canonical line contract in
    # the source-set digest.
    export_bytes = KERNEL_V2_EXPORT_LINE.encode("utf-8")
    entries.append(
        {
            "bytes": len(export_bytes),
            "contract": "byte-exact line occurs once; enclosing shared file intentionally unpinned",
            "occurrences": 1,
            "path": rel(KERNEL_LIB_PATH) + "#exact-export-line",
            "role": "inactive kernel V2 exact export-line contract",
            "sha512": hashlib.sha512(export_bytes).hexdigest(),
        }
    )
    for name, exact_line in LIVE_ADMISSION_EXACT_LINES:
        encoded = exact_line.encode("utf-8")
        entries.append(
            {
                "bytes": len(encoded),
                "contract": "byte-exact stripped source line occurs once; enclosing active route file intentionally unpinned",
                "occurrences": 1,
                "path": rel(LIVE_ADMISSION_PATH) + f"#exact-line::{name}",
                "role": "active native route diagnostic-divergence contract",
                "sha512": hashlib.sha512(encoded).hexdigest(),
            }
        )
    return entries


def source_set_digest(entries: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha512(b"hegemon.hx512b01.diagnostic-relation.sources.v2\0")
    for entry in sorted(entries, key=lambda item: item["path"]):
        path = entry["path"].encode()
        digest.update(len(path).to_bytes(4, "big"))
        digest.update(path)
        digest.update(entry["bytes"].to_bytes(8, "big"))
        digest.update(bytes.fromhex(entry["sha512"]))
    return digest.hexdigest()


def relation_descriptor(program: Any) -> dict[str, Any]:
    """Security-relevant source relation input to the stable relation digest."""

    return {
        "artifact_schema": "hegemon.hx512b01.diagnostic-relation.descriptor.v2",
        "field_modulus_decimal": str(P),
        "identity": SUITE.IDENTITIES[IDENTITY_NAME],
        "verifier_profile": PROFILE.descriptor(),
        "diagnostic_statement_rules_hash_sha512": PROFILE.DIAGNOSTIC_RULES_HASH.hex(),
        "domain_registries": {
            "core": SUITE.DOMAIN_REGISTRIES[IDENTITY_NAME],
            "authority": SUITE.authority_schedule(IDENTITY_NAME),
        },
        "public": {
            "statement_bytes": STATEMENT_BYTES,
            "verifier_context_bytes": CONTEXT_BYTES,
            "statement_offsets": statement_offsets(),
            "context": "manifest_root64 || parent_height:u64le",
        },
        "private": {
            "bytes": PRIVATE_BYTES,
            "sections": [list(section) for section in WITNESS_SECTIONS],
            "manifest_membership": "index:u32le || row215 || sibling64[4] || zero5",
        },
        "groups": program.export_groups(),
        "geometry": program.geometry(),
        "geometry_status": "source cost projection only; no sparse A/B/C row coordinates",
        "executable_symbolic_ir": EXECUTABLE.executable_ir_certificate(),
        "boolean_hash_trace": boolean_hash_trace_certificate(),
        "production_blocking_accepted_counterexamples": blocking_accepted_counterexamples(),
        "active_native_route_semantics_audit": live_route_semantics_audit(),
        "primitive_shapes": BASE.primitive_manifest(),
        "macro_shapes": BASE.macro_manifest(),
        "kats": kats(),
        "external_dependency_sha512": EXPECTED_DEPENDENCY_SHA512,
    }


def relation_descriptor_digest(program: Any) -> str:
    return shake_digest(
        b"hegemon.hx512b01.diagnostic-relation.descriptor.v2\0",
        canonical_json(relation_descriptor(program)),
    )


def kats() -> dict[str, str]:
    entries = [AUTHORITY.sample_fresh_entry_v2_w64(1001 + index, 3)[0] for index in range(16)]
    first, oracle, attestation = AUTHORITY.sample_fresh_entry_v2_w64(1001, 3)
    root = AUTHORITY.fresh_v2_w64_merkle_root(entries)
    values = {
        **SUITE.kats(),
        "all_w64_policy": AUTHORITY.policy_hash64_v2(first).hex(),
        "all_w64_oracle": AUTHORITY.oracle_hash64_v2(oracle).hex(),
        "all_w64_attestation": AUTHORITY.attestation_hash64_v2(attestation).hex(),
        "all_w64_root_cap16": root.hex(),
        "all_w64_snapshot_height50": AUTHORITY.snapshot_commitment(
            root, 50, 64, profile=AUTHORITY.FRESH_V2_AUTHORITY_PROFILE
        ).hex(),
    }
    expected = json.loads(AUTHORITY_REPORT_PATH.read_text())["self_test_evidence"]
    comparisons = {
        "all_w64_policy": "fresh_v2_all_w64_policy_hash_kat",
        "all_w64_oracle": "fresh_v2_all_w64_oracle_hash_kat",
        "all_w64_attestation": "fresh_v2_all_w64_attestation_hash_kat",
        "all_w64_root_cap16": "fresh_v2_all_w64_merkle_root_cap16_kat",
    }
    for ours, frozen in comparisons.items():
        if values[ours] != expected[frozen]:
            raise Reject(f"frozen KAT mismatch: {ours}")
    return values


@functools.lru_cache(maxsize=1)
def live_route_semantics_audit() -> dict[str, Any]:
    """Compare the diagnostic mask language to active native route admission."""

    mode_names = (
        "single_key",
        "accumulator_init",
        "approval_step",
        "value_lock_creation",
        "final_threshold_spend",
    )
    rows = []
    live_by_mode = [0] * 5
    diagnostic_count = 0
    live_count = 0
    diagnostic_only = []
    for mode, mode_name in enumerate(mode_names):
        for mask in range(16):
            flags = tuple(bool(mask & (1 << bit)) for bit in range(4))
            diagnostic = activity_shape_accepts(mode, flags)
            live_route = diagnostic and any(flags[:2]) and any(flags[2:])
            diagnostic_count += int(diagnostic)
            live_count += int(live_route)
            live_by_mode[mode] += int(live_route)
            if diagnostic and not live_route:
                diagnostic_only.append({"mode": mode_name, "mode_index": mode, "mask": mask})
            rows.append(
                {
                    "mode": mode_name,
                    "mode_index": mode,
                    "mask": mask,
                    "flags_i0_i1_o0_o1": list(flags),
                    "diagnostic_accept": diagnostic,
                    "active_native_route_accept": live_route,
                }
            )
    if (diagnostic_count, live_count, len(diagnostic_only), live_by_mode) != (
        33,
        26,
        7,
        [9, 6, 2, 6, 3],
    ):
        raise AssertionError("live route mask/mode recount drift")
    return {
        "artifact_schema": "hegemon.hx512b01.diagnostic-live-route-diff.v1",
        "bit_order": ["input0", "input1", "output0", "output1"],
        "mask_formula": "sum(flag[bit] << bit for bit in 0..3)",
        "diagnostic_accepted_pairs": diagnostic_count,
        "live_route_accepted_pairs": live_count,
        "diagnostic_only_pairs": len(diagnostic_only),
        "live_route_rejected_pairs": 80 - live_count,
        "live_route_accepted_by_mode": live_by_mode,
        "diagnostic_only_rows": diagnostic_only,
        "rows": rows,
        "active_route_requires_input_count": "1..=2 nullifiers",
        "active_route_requires_output_count": "1..=2 commitments",
        "binding_value_balance_is_fixed_zero": True,
        "diagnostic_relation_allows_nonzero_value_balance": True,
        "diagnostic_grammar_matches_active_route": False,
        "exact_full_production_relation": False,
        "source_contract": {
            "path": rel(LIVE_ADMISSION_PATH),
            "exact_lines": [line for _, line in LIVE_ADMISSION_EXACT_LINES],
        },
    }


def mutation_corpus() -> dict[str, Any]:
    cases = [
        "wrong_magic",
        "wrong_grammar",
        "legacy_hx448_identity",
        "wrong_circuit_version",
        "wrong_crypto_suite",
        "wrong_family",
        "wrong_action",
        "wrong_network",
        "wrong_backend",
        "wrong_profile",
        "wrong_domain_set",
        "wrong_chain",
        "wrong_genesis",
        "wrong_rules",
        "frame_role_bit_swap",
        "authority_personalization_bit_swap",
        "all_empty_mask",
        "non_boolean_flag",
        "invalid_mode_shape",
        "noncanonical_asset_slots",
        "negative_zero",
        "wrong_ciphertext_size",
        "ciphertext_byte_mutation",
        "ciphertext_hash_mutation",
        "manifest_witness_truncated",
        "manifest_witness_trailing",
        "manifest_transport_pad_nonzero",
        "manifest_index_high_bit",
        "manifest_row_byte_mutation",
        "manifest_sibling_mutation",
        "manifest_root_mutation",
        "policy_tuple_mutation",
        "policy_digest_mutation",
        "oracle_digest_mutation",
        "attestation_digest_mutation",
        "retired_absent_payload_nonzero",
        "inactive_selected_row",
        "future_oracle",
        "stale_oracle",
        "disputed_attestation",
        "zero_issuance",
        "over_cap_issuance",
        "snapshot_root_mutation",
        "statement_height_mutation",
        "verifier_context_root_mutation",
        "verifier_context_height_mutation",
        "disabled_authority_nonzero",
        "legacy_48_policy_padding",
        "legacy_56_authority_rehash",
        "noncanonical_goldilocks_element",
        "relation_manifest_byte_mutation",
        "source_pin_mutation",
        "authority_flag_true",
        "zk_flag_true",
        "qrom_flag_true",
        "refinement_flag_true",
        "proof_bytes_fabricated",
    ]
    if len(cases) != len(set(cases)):
        raise AssertionError("duplicate mutation name")
    matrix = SUITE.activity_mode_matrix()
    if len(matrix) != 80 or sum(row["accept"] for row in matrix) != 33:
        raise AssertionError("mask/mode matrix drift")
    return {
        "artifact_schema": "hegemon.hx512b01.diagnostic-relation.mutations.v2",
        "cases": [{"name": name, "expected": "reject_or_fail_closed"} for name in cases],
        "all_sixteen_masks_all_five_authorization_modes": matrix,
        "all_160_activity_mode_stablecoin_cells": EXECUTABLE.activity_stablecoin_matrix_certificate(),
        "accepted_mask_mode_pairs": 33,
        "rejected_mask_mode_pairs": 47,
        "former_host_only_rejected_by_diagnostic_interpreter": list(FORMER_HOST_FORGERIES),
        "executed_reference_mutations": executed_reference_mutations(),
        "executable_relation_mutation_residuals": list(EXECUTABLE.mutation_residuals()),
        "production_blocking_accepted_counterexamples": blocking_accepted_counterexamples(),
        "active_native_route_semantics_audit": live_route_semantics_audit(),
        "exact_full_production_relation": False,
        "fixed_hash_parameter_mutations": {
            "frame_role_swap_rejects": boolean_hash_trace_certificate()[
                "frame_role_swap_rejects"
            ],
            "personalization_bit_swap_rejects": boolean_hash_trace_certificate()[
                "personalization_bit_swap_rejects"
            ],
        },
        "retained_mutations": len(cases),
    }


def executed_reference_mutations() -> list[dict[str, str]]:
    statement, context, witness = sample_valid_case()

    def changed(raw: bytes, offset: int, mask: int = 1) -> bytes:
        out = bytearray(raw)
        out[offset] ^= mask
        return bytes(out)

    mutations = (
        (
            "forged_policy_hash_derivation",
            changed(statement, statement_offsets()["stable_policy"]),
            context,
            witness,
        ),
        (
            "forged_selected_entry_membership",
            statement,
            context,
            changed(witness, MANIFEST_OFFSET),
        ),
        (
            "forged_whole_manifest_or_path_root",
            statement,
            context,
            changed(witness, MANIFEST_OFFSET + 4 + 215),
        ),
        (
            "forged_consensus_expected_root",
            statement,
            changed(context, 0),
            witness,
        ),
        (
            "forged_consensus_expected_height",
            statement,
            changed(context, 64),
            witness,
        ),
        (
            "ciphertext_byte_mutation",
            statement,
            context,
            changed(witness, 777 * 8),
        ),
    )
    evidence = []
    for name, mutated_statement, mutated_context, mutated_witness in mutations:
        try:
            verify_reference(mutated_statement, mutated_context, mutated_witness)
        except Reject as error:
            evidence.append(
                {
                    "name": name,
                    "observed": "reject",
                    "reason": str(error),
                }
            )
        else:
            raise AssertionError(f"mutation unexpectedly accepted: {name}")
    return evidence


def _sha512_bytes(raw: bytes) -> str:
    return hashlib.sha512(raw).hexdigest()


def _active_route_permissionless_mint_fixture(
    mask: int,
) -> tuple[bytes, bytes, bytes, Any]:
    """Construct a positive issuance accepted inside the live 1x2 shape."""

    if mask not in (0b1101, 0b1110):
        raise AssertionError("active-route counterfeit mask")
    fixture = EXECUTABLE.build_fixture(
        mode=0, mask=mask, stable_enabled=True, policy_version=0
    )
    decoded = EXECUTABLE.Witness.decode(fixture.witness, True)
    active_input = 0 if mask & 1 else 1
    statement = bytearray(fixture.statement)
    witness = bytearray(fixture.witness)

    old_input = decoded.inputs[active_input].note
    input_note = EXECUTABLE._encode_note(
        old_input.kind,
        1,
        0,
        old_input.recipient,
        old_input.rho,
        old_input.blinding,
        old_input.authorization,
    )
    input_base = active_input * 2_384
    witness[input_base + 64 : input_base + 296] = input_note
    witness[input_base + 2_352 : input_base + 2_384] = b"".join(
        int(slot == 0).to_bytes(8, "big") for slot in range(4)
    )
    note_digest = EXECUTABLE._note_digest(
        input_note, f"active-route-counterfeit.input[{active_input}]"
    )
    root = EXECUTABLE._core_merkle_root(
        note_digest,
        decoded.inputs[active_input].position,
        decoded.inputs[active_input].siblings,
    )
    statement[14:78] = root

    for output_index, (value, asset, slot) in enumerate(((1, 0, 0), (1, 1001, 1))):
        old_output = decoded.outputs[output_index].note
        output_note = EXECUTABLE._encode_note(
            old_output.kind,
            value,
            asset,
            old_output.recipient,
            old_output.rho,
            old_output.blinding,
            old_output.authorization,
        )
        output_base = 4_768 + output_index * 264
        witness[output_base : output_base + 232] = output_note
        witness[output_base + 232 : output_base + 264] = b"".join(
            int(candidate == slot).to_bytes(8, "big")
            for candidate in range(4)
        )
        statement[206 + output_index * 64 : 270 + output_index * 64] = (
            EXECUTABLE._note_digest(
                output_note, f"active-route-counterfeit.output[{output_index}]"
            )
        )

    statement[532] = 1
    statement[869:933] = EXECUTABLE._blake(
        EXECUTABLE._balance_message(EXECUTABLE.Statement.decode(bytes(statement)))
    )
    evaluation = EXECUTABLE.evaluate(
        bytes(statement), fixture.context, bytes(witness)
    )
    return bytes(statement), fixture.context, bytes(witness), evaluation


def _cap_limited_diagnostic_fixture(mask: int) -> tuple[bytes, bytes, bytes, Any]:
    """Rebuild a current-grammar fixture whose selected per-tx cap is one.

    This deliberately does not add cumulative epoch state. It retains the
    accepted counterfeit showing that two independently valid transactions can
    each consume the same nominal ``max_mint_per_epoch``.
    """

    base_statement, _base_context, base_witness, _ = (
        _active_route_permissionless_mint_fixture(mask)
    )
    entries = [
        AUTHORITY.sample_fresh_entry_v2_w64(1001 + index, 0)[0]
        for index in range(16)
    ]
    entries[0] = dataclasses.replace(entries[0], max_mint_per_epoch=1)
    path = AUTHORITY.prove_fresh_v2_w64_merkle(entries, 0)
    entry = path.entry
    height = 50
    root = AUTHORITY.fresh_v2_w64_merkle_root(entries)
    snapshot = AUTHORITY.snapshot_commitment(
        root,
        height,
        64,
        profile=AUTHORITY.FRESH_V2_AUTHORITY_PROFILE,
    )
    statement = bytearray(base_statement)
    statement[541:605] = AUTHORITY.policy_hash64_v2(entry)
    statement[605:669] = entry.oracle_commitment
    statement[669:733] = entry.attestation_commitment
    statement[733:797] = root
    statement[797:861] = snapshot
    statement[861:869] = height.to_bytes(8, "big")
    context = root + height.to_bytes(8, "little")
    witness = bytearray(base_witness)
    witness[MANIFEST_OFFSET:] = path.encode() + bytes(5)
    evaluation = EXECUTABLE.evaluate(bytes(statement), context, bytes(witness))
    return bytes(statement), context, bytes(witness), evaluation


@functools.lru_cache(maxsize=1)
def blocking_accepted_counterexamples() -> dict[str, Any]:
    """Retain production-blocking acceptances of the diagnostic grammar."""

    (
        permissionless_statement,
        permissionless_context,
        permissionless_witness,
        permissionless_eval,
    ) = _active_route_permissionless_mint_fixture(0b1101)

    cap_cases = []
    cap_contexts = []
    for mask in (0b1101, 0b1110):
        statement, context, witness, evaluation = _cap_limited_diagnostic_fixture(mask)
        cap_contexts.append(context)
        cap_cases.append(
            {
                "mode": 0,
                "mask": mask,
                "stable_issuance_magnitude": 1,
                "selected_max_mint_per_epoch": 1,
                "observed": "accept",
                "statement_sha512": _sha512_bytes(statement),
                "verifier_context_sha512": _sha512_bytes(context),
                "private_witness_sha512": _sha512_bytes(witness),
                "trace_digest_shake256_512": evaluation.trace_digest_shake256_512,
            }
        )
    if cap_contexts[0] != cap_contexts[1]:
        raise AssertionError("epoch-cap counterexamples do not share parent state")

    anchor_fixture = EXECUTABLE.build_fixture(mode=0, mask=0b0100)
    anchor_statement = bytearray(anchor_fixture.statement)
    anchor_statement[14] ^= 1
    anchor_eval = EXECUTABLE.evaluate(
        bytes(anchor_statement), anchor_fixture.context, anchor_fixture.witness
    )

    cases = [
        {
            "name": "permissionless_positive_stablecoin_issuance",
            "observed": "accept",
            "mode": 0,
            "mask": 13,
            "flags": [True, False, True, True],
            "stable_issuance_sign": "mint",
            "stable_issuance_magnitude": 1,
            "active_inputs": 1,
            "active_outputs": 2,
            "active_native_route_shape": True,
            "issuer_or_collateral_capability_opening_bytes": 0,
            "minimum_collateral_ratio_from_selected_row": 1_500_000,
            "minimum_collateral_ratio_evaluated": False,
            "statement_sha512": _sha512_bytes(permissionless_statement),
            "verifier_context_sha512": _sha512_bytes(permissionless_context),
            "private_witness_sha512": _sha512_bytes(permissionless_witness),
            "trace_digest_shake256_512": permissionless_eval.trace_digest_shake256_512,
        },
        {
            "name": "noncumulative_max_mint_per_epoch",
            "observed": "both_transactions_accept",
            "shared_parent_state": True,
            "transactions": cap_cases,
            "cumulative_issuance": 2,
            "selected_max_mint_per_epoch": 1,
            "cumulative_cap_enforced": False,
        },
        {
            "name": "arbitrary_anchor_when_no_inputs_are_active",
            "observed": "accept",
            "mode": 0,
            "mask": 4,
            "active_inputs": 0,
            "mutation": "statement.anchor[0] xor 0x01",
            "statement_sha512": _sha512_bytes(bytes(anchor_statement)),
            "verifier_context_sha512": _sha512_bytes(anchor_fixture.context),
            "private_witness_sha512": _sha512_bytes(anchor_fixture.witness),
            "trace_digest_shake256_512": anchor_eval.trace_digest_shake256_512,
        },
    ]
    return {
        "artifact_schema": "hegemon.hx512b01.production-blocking-counterexamples.v1",
        "cases": cases,
        "all_three_reproduced_as_accepted": all(
            item["observed"] in ("accept", "both_transactions_accept")
            for item in cases
        ),
        "exact_full_production_relation": False,
        "smallest_repair_requires_fresh_grammar_profile_and_state_transition": True,
        "missing_fields": [
            "intent-bound issuer or collateral capability and replay-preventing nullifier",
            "canonical oracle and attestation openings with price units decimals collateral and issuer data",
            "verifier-owned epoch id and authenticated per-policy minted-before/minted-after state",
            "specified no-input anchor value or verifier-authenticated current anchor",
        ],
        "claim_boundary": (
            "The current source interpreter exactly reproduces these acceptances. "
            "No production relation, security, refinement, or authorization claim survives them."
        ),
    }


def build_manifest() -> dict[str, Any]:
    program = compile_relation()
    geometry = program.geometry()
    sources = source_entries()
    statement_layout = SUITE.statement_layout()
    return {
        "artifact": "inactive HX512B01 diagnostic transaction semantics plus R1CS cost projection",
        "artifact_schema": "hegemon.hx512b01.diagnostic-relation.executable.v2",
        "status": "executable current diagnostic semantics with accepted production counterexamples; numeric sparse-R1CS lowering, final proof profile, proof backend, and production route absent",
        "authority": {
            "source_macro_full_relation_compiled": False,
            "source_cost_projection_complete_for_current_diagnostic_schedule": True,
            "executable_current_diagnostic_interpreter_complete": True,
            "exact_full_production_relation": False,
            "known_accepted_production_counterexamples": True,
            "stablecoin_issuer_or_collateral_capability_enforced": False,
            "stablecoin_minimum_collateral_ratio_evaluated": False,
            "stablecoin_epoch_cap_cumulative_and_atomic": False,
            "no_input_anchor_canonical_or_authenticated": False,
            "activity_mask_mode_grammar_matches_active_native_route": False,
            "live_route_value_balance_zero_enforced": False,
            "exact_blake2b_boolean_trace_executable": True,
            "four_former_host_predicates_rejected_by_diagnostic_interpreter": True,
            "all_four_former_host_predicates_emitted_as_sparse_r1cs": False,
            "expanded_sparse_matrix_retained": False,
            "scalar_to_macro_refinement_proved": False,
            "complete_zero_knowledge_proved": False,
            "composed_qrom_pq128_proved": False,
            "exact_native_verifier_refinement_proved": False,
            "consensus_parent_state_authentication_refined": False,
            "production_authorized": False,
            "release_manifest_authorized": False,
        },
        "canonical_json": "UTF-8 sorted-key minified JSON with exactly one trailing LF",
        "verifier_profile": {
            "descriptor": PROFILE.descriptor(),
            "canonical_descriptor_bytes": len(PROFILE.descriptor_bytes()),
            "diagnostic_statement_rules_hash_sha512": PROFILE.DIAGNOSTIC_RULES_HASH.hex(),
            "statement_value_is_test_only": True,
            "final_consensus_rules_hash_frozen": False,
            "final_consensus_rules_hash_hex": None,
            "python_statement_comparison_implemented": True,
            "native_compiled_consensus_constant_implemented": False,
            "manifest_or_registry_is_validity_authority": False,
            "source_set_is_supply_chain_evidence_only": True,
            "rules_hash_self_referential": False,
        },
        "relation_descriptor_digest_shake256_512": relation_descriptor_digest(program),
        "executable_symbolic_ir": EXECUTABLE.executable_ir_certificate(),
        "boolean_hash_trace": boolean_hash_trace_certificate(),
        "field": {
            "name": "Goldilocks",
            "modulus_decimal": str(P),
            "characteristic_is_odd": True,
            "canonical_element_bytes": 8,
            "canonical_element_endianness": "little",
            "decode": "reject unsigned value >= p; never reduce transport words",
        },
        "identity": SUITE.IDENTITIES[IDENTITY_NAME],
        "identity_composition": {
            "core_semantic_registry": "HX512B01 8-byte profile plus 8-byte roles and framed fields",
            "authority_registry": "frozen all-W64 HGMAIDV2/HGMAROOT RFC7693 personalization",
            "mixed_registry_aliasing_allowed": False,
            "legacy_identity_reinterpretation_allowed": False,
            "domain_set_0x5127_binds_both_registries": True,
        },
        "public_grammar": {
            "statement_bytes": STATEMENT_BYTES,
            "statement_layout": statement_layout,
            "statement_offsets": statement_offsets(),
            "verifier_context_bytes": CONTEXT_BYTES,
            "verifier_context": "manifest_root64 || parent_height:u64le",
            "statement_integer_endianness": "big except opaque byte strings",
            "statement_hash_and_identifier_bytes": "preserve canonical byte order",
            "verifier_context_height_endianness": "little",
            "l_public_bits": PUBLIC_BITS,
            "bit_order_within_byte": "least-significant-bit first",
            "parser_exact_consumption": True,
            "m4_statement_words": 143,
            "m4_statement_zero_pad_bytes": 3,
            "m4_context_words": 9,
        },
        "private_grammar": {
            "bytes": PRIVATE_BYTES,
            "bits": PRIVATE_BITS,
            "words": PRIVATE_BYTES // 8,
            "sections": [
                {"name": name, "offset_bytes": offset, "bytes": width}
                for name, offset, width in WITNESS_SECTIONS
            ],
            "input_words_each": 298,
            "output_words_each": 33,
            "authorization_words": 99,
            "policy_master_words": 16,
            "ciphertext_words_each": 269,
            "ciphertext_semantic_bytes_each": 2147,
            "ciphertext_zero_pad_bytes_each": 5,
            "manifest_membership": {
                "offset_bytes": MANIFEST_OFFSET,
                "semantic_bytes": MANIFEST_SEMANTIC_BYTES,
                "transport_bytes": MANIFEST_WITNESS_BYTES,
                "grammar": "index:u32le || row215 || sibling64[4] || zero_pad[5]",
                "row_integer_endianness": "little",
                "row_boolean_bytes": ["retired_present", "active", "attestation_disputed"],
                "row_boolean_high_bits_constrained_zero": True,
            },
        },
        "relation_coverage": {
            "inputs": 2,
            "outputs": 2,
            "activity_masks": 16,
            "authorization_modes": [
                "single_key",
                "accumulator_init",
                "approval_step",
                "value_lock_creation",
                "final_threshold_spend",
            ],
            "accepted_mask_mode_pairs": 33,
            "rejected_mask_mode_pairs": 47,
            "stablecoin_axis_cells": 160,
            "executed_positive_cells": 66,
            "executed_structural_negative_cells": 94,
            "stablecoin_all_w64": True,
            "ciphertext_bytes_to_hash": True,
            "transaction_groups": list(CORE_TRANSACTION_GROUPS),
            "authority_groups": list(AUTHORITY_GROUPS),
            "former_host_only_boundary_in_sparse_r1cs": list(FORMER_HOST_FORGERIES),
            "exact_full_production_relation": False,
        },
        "hash_program": {
            "core_calls": 83,
            "core_blake2b512_compressions": 205,
            "authority_calls": 7,
            "authority_blake2b512_compressions": 8,
            "total_calls": 90,
            "total_blake2b512_compressions": 213,
            "core_schedule": SUITE.core_frame_schedule(MAGIC),
            "authority_schedule": {
                **SUITE.authority_schedule(IDENTITY_NAME),
            },
            "exact_call_source_ir": list(EXECUTABLE.hash_call_source_ir()),
            "fixed_parameter_profiles": list(PROFILE.parameter_profiles()),
            "fixed_parameters_constant_folded": True,
            "parameter_constraint_rows": 0,
            "authorization_select_rows": 80_456,
            "authorization_select_rows_decomposition": SUITE.r1cs_costs()[
                "macro_contract"
            ]["authorization_blake_rows_decomposition"],
            "proof_backend_required_but_unallocated": PROFILE.descriptor()[
                "proof_system_required_but_unallocated"
            ],
        },
        "r1cs": {
            "equation": "(A*z)*(B*z)=C*z",
            "status": "source cost projection; exact sparse A/B/C coordinates not emitted",
            "variable_order": "constant one, exact public bits, exact private transport bits, derived variables by group/invocation/primitive order",
            "geometry": geometry,
            "group_ledger": program.export_groups(),
            "primitive_multiplicities": dict(sorted(program.primitives.items())),
            "primitives": BASE.primitive_manifest(),
            "macros": BASE.macro_manifest(),
            "section11_projection": section11_projection(geometry),
            "semantic_suite_prefold_projection_input": SUITE.r1cs_costs()["blake2b512_rfc"],
            "local_fixed_parameter_constant_fold_delta": {
                "rows": -270,
                "auxiliary_variables": -270,
                "matrix_nonzeros": -1080,
            },
        },
        "parent_state_boundary": {
            "relation_checks_recomputed_manifest_root_and_height_equal_verifier_context": True,
            "relation_checks_snapshot_equals_statement_state_root": True,
            "native_verifier_derives_context_from_authenticated_parent": False,
            "mempool_mining_block_sync_restart_reorg_refinement": False,
            "production_effect": "fail closed",
        },
        "production_blocking_accepted_counterexamples": blocking_accepted_counterexamples(),
        "active_native_route_semantics_audit": live_route_semantics_audit(),
        "kats": kats(),
        "sources": sources,
        "frozen_external_dependency_sha512": EXPECTED_DEPENDENCY_SHA512,
        "source_set_digest_sha512": source_set_digest(sources),
        "proof": {
            "artifact": None,
            "bytes": None,
            "measured": False,
            "complete_zero_knowledge": False,
            "composed_strict_gt_128": False,
        },
    }


def build_certificate(manifest: dict[str, Any]) -> dict[str, Any]:
    manifest_bytes = canonical_json(manifest)
    return {
        "artifact_schema": "hegemon.hx512b01.diagnostic-relation.certificate.v2",
        "relation_manifest_file": MANIFEST_PATH.name,
        "canonical_relation_manifest_bytes": len(manifest_bytes),
        "relation_manifest_digest_shake256_512": shake_digest(
            b"hegemon.hx512b01.diagnostic-relation.executable.v2\0", manifest_bytes
        ),
        "relation_descriptor_digest_shake256_512": manifest[
            "relation_descriptor_digest_shake256_512"
        ],
        "source_set_digest_sha512": manifest["source_set_digest_sha512"],
        "diagnostic_statement_rules_hash_sha512": manifest["verifier_profile"][
            "diagnostic_statement_rules_hash_sha512"
        ],
        "native_compiled_consensus_rules_hash": False,
        "manifest_or_registry_is_validity_authority": False,
        "geometry": manifest["r1cs"]["geometry"],
        "section11_projection": manifest["r1cs"]["section11_projection"],
        "former_host_only_rejected_by_diagnostic_interpreter": list(FORMER_HOST_FORGERIES),
        "source_macro_full_relation_compiled": False,
        "source_cost_projection_complete_for_current_diagnostic_schedule": True,
        "executable_current_diagnostic_interpreter_complete": True,
        "exact_full_production_relation": False,
        "known_accepted_production_counterexamples": True,
        "activity_mask_mode_grammar_matches_active_native_route": False,
        "live_route_value_balance_zero_enforced": False,
        "exact_blake2b_boolean_trace_executable": True,
        "sparse_r1cs_rows_emitted": False,
        "expanded_sparse_matrix_retained": False,
        "scalar_to_macro_refinement_proved": False,
        "complete_zero_knowledge_proved": False,
        "composed_qrom_pq128_proved": False,
        "exact_native_verifier_refinement_proved": False,
        "consensus_parent_state_authentication_refined": False,
        "proof_built": False,
        "proof_bytes": None,
        "production_authorized": False,
        "verdict": "DIAGNOSTIC_SEMANTICS_EXECUTABLE_FULL_PRODUCTION_RELATION_R1CS_LOWERING_SECURITY_REFINEMENT_PROOF_AND_PRODUCTION_AUTHORITY_FAIL_CLOSED",
    }


def outputs() -> dict[Path, bytes]:
    manifest = build_manifest()
    return {
        MANIFEST_PATH: canonical_json(manifest),
        CERTIFICATE_PATH: canonical_json(build_certificate(manifest)),
        MUTATION_PATH: canonical_json(mutation_corpus()),
    }


def write_outputs() -> None:
    for path, payload in outputs().items():
        path.write_bytes(payload)


def check_outputs() -> None:
    for path, expected in outputs().items():
        if not path.is_file() or path.read_bytes() != expected:
            raise Reject(f"stale or missing artifact: {path.name}")


def summary() -> str:
    manifest = build_manifest()
    geometry = manifest["r1cs"]["geometry"]
    projection = manifest["r1cs"]["section11_projection"]
    return (
        "PASS identity=HX512B01 "
        f"m={geometry['m_constraints']} n={geometry['n_nonconstant_variables']} "
        f"l={geometry['l_public_variables']} nnz={geometry['matrix_nonzeros_total']} "
        f"ell={projection['ell']} diagnostic_semantics=true "
        "exact_full_production_relation=false sparse_r1cs=false "
        "production=false proof_bytes=null"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)
    if sum((args.write, args.check, args.summary)) != 1:
        parser.error("select exactly one mode")
    if args.write:
        write_outputs()
    elif args.check:
        check_outputs()
    else:
        print(summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
