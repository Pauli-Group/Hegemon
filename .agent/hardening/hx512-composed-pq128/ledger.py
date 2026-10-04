#!/usr/bin/env python3
"""Exact, fail-closed HX512 SmallWood composition ledger.

Only Python's standard library is used.  All probability arithmetic uses
``fractions.Fraction`` and all retained JSON is canonical UTF-8 with sorted
keys, compact separators, and exactly one trailing LF.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import stat
import sys
from functools import lru_cache
from fractions import Fraction
from pathlib import Path
from typing import Any, NoReturn


INPUT_SCHEMA = "hegemon.hx512.composed-pq128.input.v1"
REPORT_SCHEMA = "hegemon.hx512.composed-pq128.report.v1"
GOLDILOCKS_ORDER = 0xFFFF_FFFF_0000_0001
K = 1024
RHO = 5
ETA = 5
BETA = 2
DECS_DOMAIN_SIZE = 1 << 20
DECS_QUERY_COUNT = 48
GLOBAL_QUANTUM_QUERY_CAP = 1 << 64
CMS_HASH_BITS = 512
TARGET_BITS = 128
TARGET = Fraction(1, 1 << TARGET_BITS)
SEMANTIC_CALL_COUNT = 95
ACTIVITY_MASKS = 16
AUTHORIZATION_MODES = 5
ACCEPTED_MODE_MASK_PAIRS = 26
REJECTED_MODE_MASK_PAIRS = 54
LIFECYCLE_STAGES = (
    "wallet",
    "rpc",
    "relay",
    "mempool",
    "mining",
    "block",
    "sync",
    "reorg",
    "fresh-node",
)
MAX_JSON_BYTES = 8 * 1024 * 1024
FINAL_ROW_COUNT_SOURCE = "pinned-smallwood-hx512-adapter.executable-relation-rows"

GRAMMAR_SHA512 = (
    "e9cdaa4adcdd21427a61b566e0f8ac3d1dcd750a9d92e630cf935d298e9e4460"
    "ee87bb473cd94fcd3bc647c93117093430657b416ac510c6c8a28075c7a1d8bf"
)
STABLE_TRANSITION_SHA256 = (
    "c533ff732b68b02a2ded89770f20385ad570ad7c5653f42580635d0fb50a4df9"
)
STABLE_SOURCE_SHA256 = (
    "53c7f957d8729a60be84e648e00bf49ac36c381554f1f496bdda011e5e4c1400"
)

SOURCE_LAYOUT = {
    "grammar": (
        "circuits/transaction/src/hx512_production_relation.rs",
        "sha512",
        GRAMMAR_SHA512,
    ),
    "stable_transition": (
        "protocol/kernel/src/stablecoin_transition_v3.rs",
        "sha256",
        STABLE_TRANSITION_SHA256,
    ),
    "stable_source": (
        "protocol/kernel/src/stablecoin_source_v3.rs",
        "sha256",
        STABLE_SOURCE_SHA256,
    ),
    "engine": ("circuits/transaction/src/smallwood_engine.rs", "sha512", None),
    "transcript": (
        "circuits/transaction/src/smallwood_hx512_transcript.rs",
        "sha512",
        None,
    ),
    "topology": (
        "circuits/transaction/src/smallwood_hx512_topology.rs",
        "sha512",
        None,
    ),
    "adapter": (
        "circuits/transaction/src/smallwood_hx512_adapter.rs",
        "sha512",
        None,
    ),
}

# Scope is checker-owned.  A profile may not relabel a per-proof loss as a
# global one in order to erase a history union.
EXTERNAL_TERM_SCOPES = {
    "lppc_pcs_binding_residual": "global",
    "lppc_decs_proximity_residual": "global",
    "lppc_list_decoding_residual": "global",
    "piop_rbr_knowledge_residual": "global",
    "cms_fiat_shamir_applicability_residual": "global",
    "smallwood_classical_complete_zk": "per-proof",
    "ghcm_proposition2_and_whole_view_residual": "global",
    "sha512_qro_instantiation": "global",
    "shake_qro_instantiation": "global",
    "blake2b512_collision_instantiation": "global",
    "blake2b512_preimage_instantiation": "global",
    "blake2b512_secret_role_prf_kdf_instantiation": "global",
    "challenge_rejection_conditioning": "per-proof",
    "os_rng_failure": "per-proof",
    "os_rng_reuse": "global",
    "canonical_parser_refinement": "per-lifecycle-stage",
    "exact_relation_compiler_refinement": "global",
    "formal_relation_refinement": "global",
    "rust_verifier_refinement": "global",
    "consensus_lifecycle_refinement": "per-lifecycle-stage",
    "release_manifest_and_artifact_refinement": "global",
    "proof_block_union_residual": "per-block",
    "history_union_residual": "global",
    "mode_mask_uniformity_residual": "global",
    "stablecoin_lifecycle_residual": "per-lifecycle-stage",
    "independent_cryptographic_review_residual": "global",
}

SEMANTIC_ROLE_FAMILIES = (
    ("note_commitment", 4, ("collision", "preimage-hiding")),
    ("nullifier", 2, ("collision", "secret-role-prf")),
    ("merkle_node", 64, ("collision",)),
    ("spend_key", 4, ("collision", "secret-role-kdf")),
    (
        "authorization_policy",
        1,
        ("collision", "preimage-hiding", "secret-role-kdf"),
    ),
    (
        "authorization_state",
        4,
        ("collision", "preimage-hiding", "secret-role-kdf"),
    ),
    ("action_intent", 1, ("collision",)),
    ("spend_plan", 1, ("collision",)),
    ("ciphertext", 2, ("collision",)),
    ("stable_leaf", 2, ("collision",)),
    ("stable_node", 8, ("collision",)),
    (
        "stable_issuer_commitment",
        1,
        ("collision", "preimage-hiding", "secret-role-kdf"),
    ),
    ("stable_issuer_authorization", 1, ("collision", "secret-role-prf")),
)


class LedgerInputError(ValueError):
    """Malformed or unsafe ledger input."""


def _fail(message: str) -> NoReturn:
    raise LedgerInputError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_float(value: str) -> NoReturn:
    _fail(f"floating-point JSON number is forbidden: {value}")


def canonical_json_bytes(document: Any) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def load_canonical_json(path: Path) -> Any:
    try:
        info = path.lstat()
    except OSError as exc:
        raise LedgerInputError(f"cannot stat {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        _fail(f"JSON input must be a non-symlink regular file: {path}")
    if info.st_size > MAX_JSON_BYTES:
        _fail(f"JSON input exceeds {MAX_JSON_BYTES} bytes")
    try:
        raw = path.read_bytes()
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LedgerInputError(f"cannot read canonical JSON from {path}: {exc}") from exc
    if raw != canonical_json_bytes(document):
        _fail(f"JSON is not canonical: {path}")
    return document


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        _fail(
            f"{label} keys mismatch; missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def _integer_or_null(value: Any, label: str, minimum: int = 1) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be null or an integer >= {minimum}")
    return value


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{label} must be Boolean")
    return value


def _hex_or_null(value: Any, length: int, label: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) != length
        or value != value.lower()
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        _fail(f"{label} must be null or {length} lowercase hexadecimal characters")
    return value


def fraction_from_json(value: Any, label: str) -> Fraction | None:
    if value is None:
        return None
    item = _object(value, label)
    _exact_keys(item, {"numerator", "denominator"}, label)
    numerator = item["numerator"]
    denominator = item["denominator"]
    if not isinstance(numerator, str) or not numerator.isdecimal():
        _fail(f"{label}.numerator must be an unsigned decimal string")
    if not isinstance(denominator, str) or not denominator.isdecimal():
        _fail(f"{label}.denominator must be an unsigned decimal string")
    numerator_i = int(numerator)
    denominator_i = int(denominator)
    if denominator_i == 0 or numerator_i > denominator_i:
        _fail(f"{label} must encode a probability in [0,1]")
    return Fraction(numerator_i, denominator_i)


def fraction_json(value: Fraction) -> dict[str, str]:
    if value < 0:
        raise ValueError("negative security term")
    return {"denominator": str(value.denominator), "numerator": str(value.numerator)}


def security_bits_floor(value: Fraction) -> int | None:
    """Largest b such that value <= 2^-b; zero has no finite floor."""

    if value == 0:
        return None
    candidate = max(0, value.denominator.bit_length() - value.numerator.bit_length() - 1)
    while value <= Fraction(1, 1 << (candidate + 1)):
        candidate += 1
    while candidate and value > Fraction(1, 1 << candidate):
        candidate -= 1
    return candidate


def fraction_report(value: Fraction) -> dict[str, Any]:
    return {
        "exact": fraction_json(value),
        "security_bits_floor": security_bits_floor(value),
        "strictly_below_2^-128": value < TARGET,
    }


def falling(value: int, count: int) -> int:
    if value < 0 or count < 0 or count > value:
        raise ValueError("invalid falling factorial")
    product = 1
    for offset in range(count):
        product *= value - offset
    return product


@lru_cache(maxsize=None)
def stirling_second(value: int, blocks: int) -> int:
    if value < 0 or blocks < 0 or blocks > value:
        return 0
    if value == 0:
        return int(blocks == 0)
    if blocks == 0:
        return 0
    return stirling_second(value - 1, blocks - 1) + blocks * stirling_second(
        value - 1, blocks
    )


@lru_cache(maxsize=None)
def piop_sampler_exhaustion_probability(openings: int, trials: int) -> Fraction:
    valid_one = Fraction(
        falling(GOLDILOCKS_ORDER - K, openings),
        GOLDILOCKS_ORDER**openings,
    )
    return (1 - valid_one) ** trials


@lru_cache(maxsize=None)
def decs_sampler_exhaustion_probability(candidates: int) -> Fraction:
    if GOLDILOCKS_ORDER % DECS_DOMAIN_SIZE != 1:
        raise AssertionError("Goldilocks must be one modulo the DECS domain")
    bucket = (GOLDILOCKS_ORDER - 1) // DECS_DOMAIN_SIZE
    bad_raw_streams = 0
    for accepted_count in range(candidates + 1):
        bad_index_sequences = 0
        for distinct in range(min(DECS_QUERY_COUNT - 1, accepted_count) + 1):
            bad_index_sequences += (
                falling(DECS_DOMAIN_SIZE, distinct)
                * stirling_second(accepted_count, distinct)
            )
        bad_raw_streams += (
            math.comb(candidates, accepted_count)
            * bad_index_sequences
            * bucket**accepted_count
        )
    return Fraction(bad_raw_streams, GOLDILOCKS_ORDER**candidates)


def interactive_terms(
    *, openings: int, constraint_degree: int, lvcs_columns: int | None
) -> dict[str, Fraction | None]:
    witness_degree = K + openings - 1
    masking_polynomial_degree = constraint_degree * witness_degree - K
    discrepancy_bound = masking_polynomial_degree + K
    epsilon3 = Fraction(
        falling(discrepancy_bound, openings),
        falling(GOLDILOCKS_ORDER - K, openings),
    )
    epsilon4 = None
    if lvcs_columns is not None:
        epsilon4 = Fraction(
            falling(lvcs_columns + DECS_QUERY_COUNT - 1, DECS_QUERY_COUNT),
            falling(DECS_DOMAIN_SIZE, DECS_QUERY_COUNT),
        )
    return {
        "epsilon1_decs_uniform_matrix": Fraction(1, GOLDILOCKS_ORDER**ETA),
        "epsilon2_piop_constraint_batching": Fraction(1, GOLDILOCKS_ORDER**RHO),
        "epsilon3_piop_opening_without_replacement": epsilon3,
        "epsilon4_decs_opening_without_replacement": epsilon4,
    }


def cms_terms(interactive_error: Fraction) -> dict[str, Fraction]:
    return {
        "cms_interactive_amplification": 12
        * GLOBAL_QUANTUM_QUERY_CAP**2
        * interactive_error,
        "cms_sha512_instability": Fraction(
            48 * GLOBAL_QUANTUM_QUERY_CAP**3, 1 << CMS_HASH_BITS
        ),
        "cms_oracle_database_bridge": Fraction(2 * K**2, 1 << CMS_HASH_BITS),
    }


def cms_expanded_terms(
    interactive_errors: dict[str, Fraction],
) -> dict[str, Fraction]:
    """Apply the CMS multiplier to each interactive error separately.

    Keeping the four products separate is both auditable and material for the
    s6/s7 comparison: at fixed rho=eta=5, epsilon1/epsilon2 eventually dominate
    the aggregate even though epsilon3 continues to improve with s.
    """

    terms = {
        f"cms_12Q2_times_{name}": 12 * GLOBAL_QUANTUM_QUERY_CAP**2 * value
        for name, value in interactive_errors.items()
    }
    terms["cms_sha512_instability_48Q3_over_2^512"] = Fraction(
        48 * GLOBAL_QUANTUM_QUERY_CAP**3, 1 << CMS_HASH_BITS
    )
    terms["cms_oracle_database_bridge_2K2_over_2^512"] = Fraction(
        2 * K**2, 1 << CMS_HASH_BITS
    )
    return terms


def ghcm_term(*, events: int, entropy_bits: int) -> Fraction:
    query_bits = GLOBAL_QUANTUM_QUERY_CAP.bit_length() - 1
    if GLOBAL_QUANTUM_QUERY_CAP != 1 << query_bits:
        raise AssertionError("GHCM exact dyadic path requires power-of-two Q")
    gap = entropy_bits - query_bits
    if gap <= 0 or gap % 2:
        raise ValueError("GHCM entropy/query gap must be positive and even")
    return Fraction(3 * events, 1 << (1 + gap // 2))


def ghcm_history_terms(proof_epoch_cap: int) -> dict[str, Fraction]:
    return {
        "ghcm_leaf_adaptive_programming": ghcm_term(
            events=2 * DECS_DOMAIN_SIZE * proof_epoch_cap,
            entropy_bits=576,
        ),
        "ghcm_chain_adaptive_programming": ghcm_term(
            events=8 * proof_epoch_cap,
            entropy_bits=512,
        ),
    }


def semantic_hash_screens() -> dict[str, Fraction]:
    return {
        "blake2b512_global_collision_screen": Fraction(
            4 * GLOBAL_QUANTUM_QUERY_CAP**3, 1 << 512
        ),
        "blake2b512_global_preimage_screen": Fraction(
            GLOBAL_QUANTUM_QUERY_CAP**2, 1 << 512
        ),
    }


def strict_target_pass(value: Fraction) -> bool:
    return value < TARGET


def _role_registry_document() -> list[dict[str, Any]]:
    return [
        {"calls": calls, "family": family, "properties": list(properties)}
        for family, calls, properties in SEMANTIC_ROLE_FAMILIES
    ]


def _external_terms_document() -> dict[str, dict[str, Any]]:
    return {
        name: {"loss": None, "premise_retained": False, "scope": scope}
        for name, scope in EXTERNAL_TERM_SCOPES.items()
    }


def default_input() -> dict[str, Any]:
    return {
        "candidates": [
            {
                "engine_geometry_digest_sha512": None,
                "id": "q48-s6",
                "measured_proof_bytes": None,
                "physical_sha512_calls_per_proof": None,
                "physical_shake_calls_per_proof": None,
                "piop_openings": 6,
            },
            {
                "engine_geometry_digest_sha512": None,
                "id": "q48-s7",
                "measured_proof_bytes": None,
                "physical_sha512_calls_per_proof": None,
                "physical_shake_calls_per_proof": None,
                "piop_openings": 7,
            },
        ],
        "consensus_history": {
            "block_epoch_cap": None,
            "block_epoch_cap_consensus_enforced": False,
            "epoch_identifier_bound_to_statement": False,
            "global_query_cap_includes_adversary_and_all_honest_calls": False,
            "max_proofs_per_block": None,
            "max_proofs_per_block_consensus_enforced": False,
            "proof_epoch_cap": None,
            "proof_epoch_cap_consensus_enforced": False,
            "reorg_restart_counter_refinement": False,
        },
        "external_terms": _external_terms_document(),
        "fixed_parameters": {
            "activity_masks": ACTIVITY_MASKS,
            "authorization_modes": AUTHORIZATION_MODES,
            "beta": BETA,
            "cms_base_game_arity": K,
            "cms_hash_bits": CMS_HASH_BITS,
            "constraint_degree": 6,
            "decs_domain_size": DECS_DOMAIN_SIZE,
            "decs_queries": DECS_QUERY_COUNT,
            "eta": ETA,
            "field": "Goldilocks",
            "field_order": str(GOLDILOCKS_ORDER),
            "global_quantum_queries": str(GLOBAL_QUANTUM_QUERY_CAP),
            "packing_factor": K,
            "rho": RHO,
            "security_comparison": "strictly-less-than-2^-128",
            "target_bits": TARGET_BITS,
        },
        "geometry": {
            "final_relation_row_count": None,
            "final_relation_row_count_source": None,
        },
        "protocol_controls": {
            "decs_candidate_count": None,
            "grinding_bits": 0,
            "piop_nonce_trials": None,
            "prover_retries": 0,
            "sampler_caps_consensus_enforced": False,
            "verifier_retries": 0,
            "zero_grinding_and_retries_consensus_enforced": False,
        },
        "relation_surface": {
            "accepted_mode_mask_pairs": ACCEPTED_MODE_MASK_PAIRS,
            "all_pairs_uniform_single_relation_premise_retained": False,
            "lifecycle_stages": list(LIFECYCLE_STAGES),
            "rejected_mode_mask_pairs": REJECTED_MODE_MASK_PAIRS,
        },
        "schema": INPUT_SCHEMA,
        "semantic_hash_registry": {
            "call_count": SEMANTIC_CALL_COUNT,
            "global_oracle_union_multiplier": 1,
            "registry_frozen": True,
            "role_families": _role_registry_document(),
        },
        "source_pins": {
            role: {"algorithm": algorithm, "digest": digest, "path": path}
            for role, (path, algorithm, digest) in SOURCE_LAYOUT.items()
        },
    }


def _validate_fixed(document: dict[str, Any]) -> None:
    expected_top = {
        "candidates",
        "consensus_history",
        "external_terms",
        "fixed_parameters",
        "geometry",
        "protocol_controls",
        "relation_surface",
        "schema",
        "semantic_hash_registry",
        "source_pins",
    }
    _exact_keys(document, expected_top, "input")
    if document["schema"] != INPUT_SCHEMA:
        _fail(f"schema must equal {INPUT_SCHEMA}")

    fixed = _object(document["fixed_parameters"], "fixed_parameters")
    expected_fixed = {
        "activity_masks": ACTIVITY_MASKS,
        "authorization_modes": AUTHORIZATION_MODES,
        "beta": BETA,
        "cms_base_game_arity": K,
        "cms_hash_bits": CMS_HASH_BITS,
        "constraint_degree": 6,
        "decs_domain_size": DECS_DOMAIN_SIZE,
        "decs_queries": DECS_QUERY_COUNT,
        "eta": ETA,
        "field": "Goldilocks",
        "field_order": str(GOLDILOCKS_ORDER),
        "global_quantum_queries": str(GLOBAL_QUANTUM_QUERY_CAP),
        "packing_factor": K,
        "rho": RHO,
        "security_comparison": "strictly-less-than-2^-128",
        "target_bits": TARGET_BITS,
    }
    _exact_keys(fixed, set(expected_fixed), "fixed_parameters")
    if fixed != expected_fixed:
        _fail("fixed HX512 q48 composition parameters were mutated")

    candidates = _array(document["candidates"], "candidates")
    if len(candidates) != 2:
        _fail("candidates must contain exactly q48-s6 and q48-s7")
    candidate_keys = {
        "engine_geometry_digest_sha512",
        "id",
        "measured_proof_bytes",
        "physical_sha512_calls_per_proof",
        "physical_shake_calls_per_proof",
        "piop_openings",
    }
    for index, (expected_id, expected_s) in enumerate((("q48-s6", 6), ("q48-s7", 7))):
        candidate = _object(candidates[index], f"candidates[{index}]")
        _exact_keys(candidate, candidate_keys, f"candidates[{index}]")
        if candidate["id"] != expected_id or candidate["piop_openings"] != expected_s:
            _fail("candidate order/identity must be q48-s6 then q48-s7")
        _hex_or_null(
            candidate["engine_geometry_digest_sha512"],
            128,
            f"candidates[{index}].engine_geometry_digest_sha512",
        )
        _integer_or_null(
            candidate["measured_proof_bytes"],
            f"candidates[{index}].measured_proof_bytes",
        )
        _integer_or_null(
            candidate["physical_sha512_calls_per_proof"],
            f"candidates[{index}].physical_sha512_calls_per_proof",
            minimum=0,
        )
        _integer_or_null(
            candidate["physical_shake_calls_per_proof"],
            f"candidates[{index}].physical_shake_calls_per_proof",
            minimum=0,
        )

    registry = _object(document["semantic_hash_registry"], "semantic_hash_registry")
    _exact_keys(
        registry,
        {"call_count", "global_oracle_union_multiplier", "registry_frozen", "role_families"},
        "semantic_hash_registry",
    )
    if (
        registry["call_count"] != SEMANTIC_CALL_COUNT
        or registry["global_oracle_union_multiplier"] != 1
        or registry["registry_frozen"] is not True
        or registry["role_families"] != _role_registry_document()
    ):
        _fail("semantic hash registry must be the exact frozen 95-call inventory")
    if sum(item[1] for item in SEMANTIC_ROLE_FAMILIES) != SEMANTIC_CALL_COUNT:
        raise AssertionError("checker-owned semantic role counts do not sum to 95")

    surface = _object(document["relation_surface"], "relation_surface")
    _exact_keys(
        surface,
        {
            "accepted_mode_mask_pairs",
            "all_pairs_uniform_single_relation_premise_retained",
            "lifecycle_stages",
            "rejected_mode_mask_pairs",
        },
        "relation_surface",
    )
    if (
        surface["accepted_mode_mask_pairs"] != ACCEPTED_MODE_MASK_PAIRS
        or surface["rejected_mode_mask_pairs"] != REJECTED_MODE_MASK_PAIRS
        or surface["lifecycle_stages"] != list(LIFECYCLE_STAGES)
    ):
        _fail("mode/mask or lifecycle surface was mutated")
    _bool(
        surface["all_pairs_uniform_single_relation_premise_retained"],
        "relation_surface.all_pairs_uniform_single_relation_premise_retained",
    )


def _source_pin_report(
    document: dict[str, Any], repo_root: Path
) -> tuple[dict[str, Any], list[str]]:
    pins = _object(document["source_pins"], "source_pins")
    _exact_keys(pins, set(SOURCE_LAYOUT), "source_pins")
    report: dict[str, Any] = {}
    blockers: list[str] = []
    for role, (expected_path, expected_algorithm, required_digest) in SOURCE_LAYOUT.items():
        pin = _object(pins[role], f"source_pins.{role}")
        _exact_keys(pin, {"algorithm", "digest", "path"}, f"source_pins.{role}")
        if pin["path"] != expected_path or pin["algorithm"] != expected_algorithm:
            _fail(f"source_pins.{role} path/algorithm mismatch")
        expected_length = 128 if expected_algorithm == "sha512" else 64
        claimed = _hex_or_null(pin["digest"], expected_length, f"source_pins.{role}.digest")
        if required_digest is not None and claimed != required_digest:
            _fail(f"source_pins.{role}.digest must equal the frozen checkpoint")
        source = repo_root / expected_path
        actual: str | None = None
        error: str | None = None
        try:
            info = source.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                error = "source is not a non-symlink regular file"
            else:
                hasher = hashlib.new(expected_algorithm)
                hasher.update(source.read_bytes())
                actual = hasher.hexdigest()
        except OSError as exc:
            error = str(exc)
        matched = claimed is not None and actual == claimed and error is None
        if claimed is None:
            blockers.append(f"source pin missing: {role}")
        elif not matched:
            blockers.append(f"source pin mismatch: {role}")
        report[role] = {
            "actual_digest": actual,
            "algorithm": expected_algorithm,
            "claimed_digest": claimed,
            "error": error,
            "matched": matched,
            "path": expected_path,
        }
    return report, blockers


def _geometry_report(document: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    geometry = _object(document["geometry"], "geometry")
    _exact_keys(
        geometry,
        {"final_relation_row_count", "final_relation_row_count_source"},
        "geometry",
    )
    rows = _integer_or_null(
        geometry["final_relation_row_count"], "geometry.final_relation_row_count"
    )
    source = geometry["final_relation_row_count_source"]
    if source is not None and (not isinstance(source, str) or not source):
        _fail("geometry.final_relation_row_count_source must be null or nonempty text")
    if source is not None and source != FINAL_ROW_COUNT_SOURCE:
        _fail(
            "geometry.final_relation_row_count_source must identify the pinned "
            "executable adapter row-count field"
        )
    blockers: list[str] = []
    if rows is None:
        blockers.append("final full adapter relation row count is missing")
    if source is None:
        blockers.append("final relation row-count source is missing")
    return {"final_relation_row_count": rows, "source": source}, blockers


def _consensus_report(
    document: dict[str, Any]
) -> tuple[dict[str, Any], list[str], int | None, int | None]:
    history = _object(document["consensus_history"], "consensus_history")
    expected = {
        "block_epoch_cap",
        "block_epoch_cap_consensus_enforced",
        "epoch_identifier_bound_to_statement",
        "global_query_cap_includes_adversary_and_all_honest_calls",
        "max_proofs_per_block",
        "max_proofs_per_block_consensus_enforced",
        "proof_epoch_cap",
        "proof_epoch_cap_consensus_enforced",
        "reorg_restart_counter_refinement",
    }
    _exact_keys(history, expected, "consensus_history")
    proof_cap = _integer_or_null(history["proof_epoch_cap"], "proof_epoch_cap")
    block_cap = _integer_or_null(history["block_epoch_cap"], "block_epoch_cap")
    max_per_block = _integer_or_null(
        history["max_proofs_per_block"], "max_proofs_per_block"
    )
    bool_fields = expected - {"proof_epoch_cap", "block_epoch_cap", "max_proofs_per_block"}
    for field in bool_fields:
        _bool(history[field], f"consensus_history.{field}")
    blockers: list[str] = []
    required_true = (
        "proof_epoch_cap_consensus_enforced",
        "block_epoch_cap_consensus_enforced",
        "max_proofs_per_block_consensus_enforced",
        "epoch_identifier_bound_to_statement",
        "reorg_restart_counter_refinement",
        "global_query_cap_includes_adversary_and_all_honest_calls",
    )
    if proof_cap is None:
        blockers.append("exact proof-epoch cap is missing")
    if block_cap is None:
        blockers.append("exact block-epoch cap is missing")
    if max_per_block is None:
        blockers.append("max proofs per block is missing")
    for field in required_true:
        if history[field] is not True:
            blockers.append(f"consensus history premise is false: {field}")
    if (
        proof_cap is not None
        and block_cap is not None
        and max_per_block is not None
        and proof_cap > block_cap * max_per_block
    ):
        blockers.append("proof-epoch cap exceeds block cap times max proofs per block")
    return dict(history), blockers, proof_cap, block_cap


def _protocol_controls_report(
    document: dict[str, Any], proof_cap: int | None
) -> tuple[dict[str, Any], list[str], Fraction | None, Fraction | None]:
    controls = _object(document["protocol_controls"], "protocol_controls")
    expected = {
        "decs_candidate_count",
        "grinding_bits",
        "piop_nonce_trials",
        "prover_retries",
        "sampler_caps_consensus_enforced",
        "verifier_retries",
        "zero_grinding_and_retries_consensus_enforced",
    }
    _exact_keys(controls, expected, "protocol_controls")
    decs_candidates = _integer_or_null(
        controls["decs_candidate_count"], "protocol_controls.decs_candidate_count"
    )
    piop_trials = _integer_or_null(
        controls["piop_nonce_trials"], "protocol_controls.piop_nonce_trials"
    )
    for field in ("grinding_bits", "prover_retries", "verifier_retries"):
        value = controls[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _fail(f"protocol_controls.{field} must be a nonnegative integer")
    for field in (
        "sampler_caps_consensus_enforced",
        "zero_grinding_and_retries_consensus_enforced",
    ):
        _bool(controls[field], f"protocol_controls.{field}")

    blockers: list[str] = []
    if decs_candidates is None:
        blockers.append("exact DECS sampler candidate cap is missing")
    if piop_trials is None:
        blockers.append("exact PIOP sampler nonce-trial cap is missing")
    if controls["sampler_caps_consensus_enforced"] is not True:
        blockers.append("sampler candidate/trial caps are not consensus enforced")
    if controls["grinding_bits"] != 0:
        blockers.append("grinding must be exactly zero")
    if controls["prover_retries"] != 0:
        blockers.append("prover retries must be exactly zero")
    if controls["verifier_retries"] != 0:
        blockers.append("verifier retries must be exactly zero")
    if controls["zero_grinding_and_retries_consensus_enforced"] is not True:
        blockers.append("zero grinding/retries are not consensus enforced")

    # PIOP exhaustion depends on s and is computed per candidate below.  The
    # DECS sampler is common to q48-s6 and q48-s7.
    decs_one = (
        None
        if decs_candidates is None
        else decs_sampler_exhaustion_probability(decs_candidates)
    )
    decs_epoch = (
        None
        if decs_one is None or proof_cap is None
        else proof_cap * decs_one
    )
    report = dict(controls)
    report["decs_exhaustion_per_proof"] = (
        None if decs_one is None else fraction_report(decs_one)
    )
    report["decs_exhaustion_epoch_union"] = (
        None if decs_epoch is None else fraction_report(decs_epoch)
    )
    report["grinding_retry_advantage"] = fraction_report(Fraction(0))
    return report, blockers, decs_one, decs_epoch


def _external_terms_report(
    document: dict[str, Any], proof_cap: int | None, block_cap: int | None
) -> tuple[dict[str, Any], list[str], Fraction | None]:
    supplied = _object(document["external_terms"], "external_terms")
    _exact_keys(supplied, set(EXTERNAL_TERM_SCOPES), "external_terms")
    blockers: list[str] = []
    report: dict[str, Any] = {}
    total = Fraction(0)
    complete = True
    for name, checker_scope in EXTERNAL_TERM_SCOPES.items():
        item = _object(supplied[name], f"external_terms.{name}")
        _exact_keys(
            item,
            {"loss", "premise_retained", "scope"},
            f"external_terms.{name}",
        )
        if item["scope"] != checker_scope:
            _fail(
                f"external_terms.{name}.scope must be checker-owned {checker_scope!r}"
            )
        retained = _bool(
            item["premise_retained"],
            f"external_terms.{name}.premise_retained",
        )
        loss = fraction_from_json(item["loss"], f"external_terms.{name}.loss")
        if not retained:
            blockers.append(f"theorem/refinement premise is not retained: {name}")
            complete = False
        if loss is None:
            blockers.append(f"quantitative loss is missing: {name}")
            complete = False

        if checker_scope == "global":
            multiplier: int | None = 1
        elif checker_scope == "per-proof":
            multiplier = proof_cap
        elif checker_scope == "per-block":
            multiplier = block_cap
        elif checker_scope == "per-lifecycle-stage":
            multiplier = (
                None if proof_cap is None else proof_cap * len(LIFECYCLE_STAGES)
            )
        else:  # pragma: no cover - checker-owned exhaustive table
            raise AssertionError(f"unknown external-term scope {checker_scope}")
        if multiplier is None:
            blockers.append(f"union multiplier is unavailable: {name}")
            complete = False
        union = None if loss is None or multiplier is None else multiplier * loss
        if union is not None:
            total += union
        report[name] = {
            "input_loss": None if loss is None else fraction_report(loss),
            "premise_retained": retained,
            "scope": checker_scope,
            "union_loss": None if union is None else fraction_report(union),
            "union_multiplier": multiplier,
        }
    return report, blockers, total if complete else None


def _candidate_geometry(rows: int | None, openings: int) -> dict[str, int | None]:
    witness_degree = K + openings - 1
    masking_polynomial_degree = 6 * witness_degree - K
    discrepancy_bound = masking_polynomial_degree + K
    if rows is None:
        return {
            "discrepancy_bound_D": discrepancy_bound,
            "final_relation_rows": None,
            "interpolation_points": None,
            "lvcs_columns": None,
            "lvcs_rows": None,
            "masking_polynomial_degree": masking_polynomial_degree,
            "n_polynomials": None,
            "opened_combinations": BETA * openings,
            "unstacked_columns": None,
            "unstacked_rows": K + openings,
            "witness_degree": witness_degree,
        }
    n_polynomials = rows + 2 * RHO
    unstacked_columns = n_polynomials + RHO * openings
    lvcs_columns = (unstacked_columns + BETA - 1) // BETA
    return {
        "discrepancy_bound_D": discrepancy_bound,
        "final_relation_rows": rows,
        "interpolation_points": lvcs_columns + DECS_QUERY_COUNT,
        "lvcs_columns": lvcs_columns,
        "lvcs_rows": BETA * (K + openings),
        "masking_polynomial_degree": masking_polynomial_degree,
        "n_polynomials": n_polynomials,
        "opened_combinations": BETA * openings,
        "unstacked_columns": unstacked_columns,
        "unstacked_rows": K + openings,
        "witness_degree": witness_degree,
    }


def _terms_report(terms: dict[str, Fraction]) -> dict[str, dict[str, Any]]:
    return {name: fraction_report(value) for name, value in terms.items()}


def _candidate_report(
    candidate: dict[str, Any],
    *,
    rows: int | None,
    proof_cap: int | None,
    consensus_blockers: list[str],
    geometry_blockers: list[str],
    controls: dict[str, Any],
    control_blockers: list[str],
    decs_epoch: Fraction | None,
    external_union: Fraction | None,
    external_blockers: list[str],
    source_blockers: list[str],
    comparison_blockers: list[str],
    uniform_relation: bool,
) -> dict[str, Any]:
    candidate_id = candidate["id"]
    openings = candidate["piop_openings"]
    geometry = _candidate_geometry(rows, openings)
    interactive = interactive_terms(
        openings=openings,
        constraint_degree=6,
        lvcs_columns=geometry["lvcs_columns"],
    )
    interactive_report = {
        name: None if value is None else fraction_report(value)
        for name, value in interactive.items()
    }
    present_interactive = {
        name: value for name, value in interactive.items() if value is not None
    }
    complete_interactive = all(value is not None for value in interactive.values())
    optimistic_cms = cms_expanded_terms(present_interactive)
    optimistic_cms_total = sum(optimistic_cms.values(), Fraction(0))
    cms: dict[str, Fraction] | None = None
    cms_total: Fraction | None = None
    if complete_interactive:
        cms = cms_expanded_terms(present_interactive)
        cms_total = sum(cms.values(), Fraction(0))

    ghcm: dict[str, Fraction] | None = None
    if proof_cap is not None:
        ghcm = ghcm_history_terms(proof_cap)
    hash_screens = semantic_hash_screens()

    piop_trials = controls["piop_nonce_trials"]
    piop_one: Fraction | None = None
    piop_epoch: Fraction | None = None
    if piop_trials is not None:
        piop_one = piop_sampler_exhaustion_probability(openings, piop_trials)
        if proof_cap is not None:
            piop_epoch = proof_cap * piop_one

    known_terms: dict[str, Fraction] | None = None
    known_total: Fraction | None = None
    if (
        cms_total is not None
        and ghcm is not None
        and piop_epoch is not None
        and decs_epoch is not None
    ):
        known_terms = {}
        known_terms.update({f"cms::{name}": value for name, value in cms.items()})
        known_terms.update(ghcm)
        known_terms.update(hash_screens)
        known_terms["piop_sampler_exhaustion_epoch_union"] = piop_epoch
        known_terms["decs_sampler_exhaustion_epoch_union"] = decs_epoch
        known_terms["grinding_and_retry_advantage"] = Fraction(0)
        known_total = sum(known_terms.values(), Fraction(0))

    total = (
        None
        if known_total is None or external_union is None
        else known_total + external_union
    )
    total_strict = total is not None and strict_target_pass(total)

    blockers = (
        list(source_blockers)
        + list(geometry_blockers)
        + list(consensus_blockers)
        + list(control_blockers)
        + list(external_blockers)
        + list(comparison_blockers)
    )
    if not uniform_relation:
        blockers.append("all 80 mode/mask pairs lack one uniform relation premise")

    digest = _hex_or_null(
        candidate["engine_geometry_digest_sha512"],
        128,
        f"candidate {candidate_id} geometry digest",
    )
    proof_bytes = _integer_or_null(
        candidate["measured_proof_bytes"],
        f"candidate {candidate_id} measured proof bytes",
    )
    sha_calls = _integer_or_null(
        candidate["physical_sha512_calls_per_proof"],
        f"candidate {candidate_id} SHA-512 calls",
        minimum=0,
    )
    shake_calls = _integer_or_null(
        candidate["physical_shake_calls_per_proof"],
        f"candidate {candidate_id} SHAKE calls",
        minimum=0,
    )
    if digest is None:
        blockers.append(f"{candidate_id} engine geometry digest is missing")
    if proof_bytes is None:
        blockers.append(f"{candidate_id} measured proof bytes are missing")
    if sha_calls is None:
        blockers.append(f"{candidate_id} physical SHA-512 call count is missing")
    if shake_calls is None:
        blockers.append(f"{candidate_id} physical SHAKE call count is missing")

    physical_calls_per_proof = (
        None
        if sha_calls is None or shake_calls is None
        else SEMANTIC_CALL_COUNT + sha_calls + shake_calls
    )
    physical_epoch_queries = (
        None
        if physical_calls_per_proof is None or proof_cap is None
        else physical_calls_per_proof * proof_cap
    )
    query_cap_pass = (
        physical_epoch_queries is not None
        and physical_epoch_queries <= GLOBAL_QUANTUM_QUERY_CAP
    )
    if physical_epoch_queries is not None and not query_cap_pass:
        blockers.append(f"{candidate_id} honest physical calls exceed global Q")
    if total is None:
        blockers.append(f"{candidate_id} composed loss is incomplete")
    elif not total_strict:
        blockers.append(f"{candidate_id} composed loss is not strictly below 2^-128")

    eligible = not blockers and total_strict and query_cap_pass
    return {
        "candidate_id": candidate_id,
        "cms": {
            "counterfactual_per_proof_union_not_selected": (
                None
                if cms_total is None or proof_cap is None
                else fraction_report(proof_cap * cms_total)
            ),
            "exact_terms": None if cms is None else _terms_report(cms),
            "global_query_multiplier": 1,
            "optimistic_without_epsilon4_not_selectable": {
                "terms": _terms_report(optimistic_cms),
                "total": fraction_report(optimistic_cms_total),
            },
            "total": None if cms_total is None else fraction_report(cms_total),
        },
        "composition": {
            "external_union": (
                None if external_union is None else fraction_report(external_union)
            ),
            "known_terms": None if known_terms is None else _terms_report(known_terms),
            "known_total": None if known_total is None else fraction_report(known_total),
            "strict_target_pass": total_strict,
            "total": None if total is None else fraction_report(total),
        },
        "conditional_admissible": eligible,
        "eligibility_blockers": sorted(set(blockers)),
        "geometry": geometry,
        "ghcm": None if ghcm is None else _terms_report(ghcm),
        "interactive_errors": interactive_report,
        "physical_query_accounting": {
            "blake2b512_semantic_calls_per_proof": SEMANTIC_CALL_COUNT,
            "global_epoch_calls": physical_epoch_queries,
            "global_query_cap": str(GLOBAL_QUANTUM_QUERY_CAP),
            "global_query_cap_pass": query_cap_pass,
            "sha512_calls_per_proof": sha_calls,
            "shake_calls_per_proof": shake_calls,
            "total_honest_calls_per_proof": physical_calls_per_proof,
        },
        "piop_openings": openings,
        "proof_artifact": {
            "engine_geometry_digest_sha512": digest,
            "measured_proof_bytes": proof_bytes,
        },
        "samplers": {
            "decs_exhaustion_epoch_union": (
                None if decs_epoch is None else fraction_report(decs_epoch)
            ),
            "piop_exhaustion_epoch_union": (
                None if piop_epoch is None else fraction_report(piop_epoch)
            ),
            "piop_exhaustion_per_proof": (
                None if piop_one is None else fraction_report(piop_one)
            ),
        },
        "semantic_hash_screens": _terms_report(hash_screens),
    }


def build_report(document: Any, repo_root: Path) -> dict[str, Any]:
    input_document = _object(document, "input")
    _validate_fixed(input_document)
    source_report, source_blockers = _source_pin_report(input_document, repo_root)
    geometry_report, geometry_blockers = _geometry_report(input_document)
    consensus_report, consensus_blockers, proof_cap, block_cap = _consensus_report(
        input_document
    )
    controls_report, control_blockers, _decs_one, decs_epoch = (
        _protocol_controls_report(input_document, proof_cap)
    )
    external_report, external_blockers, external_union = _external_terms_report(
        input_document, proof_cap, block_cap
    )
    surface = input_document["relation_surface"]
    uniform_relation = surface["all_pairs_uniform_single_relation_premise_retained"]
    rows = geometry_report["final_relation_row_count"]
    comparison_blockers: list[str] = []
    for candidate in input_document["candidates"]:
        for field in (
            "engine_geometry_digest_sha512",
            "measured_proof_bytes",
            "physical_sha512_calls_per_proof",
            "physical_shake_calls_per_proof",
        ):
            if candidate[field] is None:
                comparison_blockers.append(
                    f"candidate comparison input is missing: {candidate['id']}.{field}"
                )
    candidate_reports = [
        _candidate_report(
            candidate,
            rows=rows,
            proof_cap=proof_cap,
            consensus_blockers=consensus_blockers,
            geometry_blockers=geometry_blockers,
            controls=controls_report,
            control_blockers=control_blockers,
            decs_epoch=decs_epoch,
            external_union=external_union,
            external_blockers=external_blockers,
            source_blockers=source_blockers,
            comparison_blockers=comparison_blockers,
            uniform_relation=uniform_relation,
        )
        for candidate in input_document["candidates"]
    ]
    eligible = [item for item in candidate_reports if item["conditional_admissible"]]
    selected = min(eligible, key=lambda item: item["piop_openings"]) if eligible else None

    s5_geometry = _candidate_geometry(None, 5)
    s5_interactive = interactive_terms(
        openings=5, constraint_degree=6, lvcs_columns=None
    )
    s5_present = {
        name: value for name, value in s5_interactive.items() if value is not None
    }
    s5_cms = cms_expanded_terms(s5_present)
    s5_total = sum(s5_cms.values(), Fraction(0))
    s5_epsilon3_cms = s5_cms[
        "cms_12Q2_times_epsilon3_piop_opening_without_replacement"
    ]
    global_blockers = sorted(
        set(
            source_blockers
            + geometry_blockers
            + consensus_blockers
            + control_blockers
            + external_blockers
            + comparison_blockers
            + ([] if uniform_relation else ["uniform 80-pair relation premise is false"])
        )
    )
    input_digest = hashlib.sha512(canonical_json_bytes(input_document)).hexdigest()
    return {
        "authorities": {
            "composed_pq128": False,
            "consensus_authorized": False,
            "production_authorized": False,
            "release_authorized": False,
        },
        "candidates": candidate_reports,
        "conditional_selection": {
            "history_cap_pair": (
                None
                if selected is None
                else {
                    "piop_openings": selected["piop_openings"],
                    "proof_epoch_cap": proof_cap,
                }
            ),
            "selected_candidate_id": (
                None if selected is None else selected["candidate_id"]
            ),
            "status": (
                "fail-closed-no-admissible-profile"
                if selected is None
                else "conditional-arithmetic-screen-only-no-authority"
            ),
        },
        "consensus_history": consensus_report,
        "external_terms": external_report,
        "fixed_parameters": dict(input_document["fixed_parameters"]),
        "geometry": geometry_report,
        "global_blockers": global_blockers,
        "input_sha512": input_digest,
        "protocol_controls": controls_report,
        "query_accounting": {
            "cms_and_global_hash_multiplier": 1,
            "global_oracle_budget": str(GLOBAL_QUANTUM_QUERY_CAP),
            "global_vs_per_proof": (
                "Q is one global tagged-product-oracle cap for the modeled proof "
                "epoch. It is not reset or unioned once per proof. Per-proof "
                "terms use the exact consensus proof-epoch cap separately."
            ),
            "semantic_blake2b_call_inventory": SEMANTIC_CALL_COUNT,
            "semantic_blake2b_collision_multiplier": 1,
        },
        "relation_surface": dict(surface),
        "schema": REPORT_SCHEMA,
        "semantic_hash_registry": dict(input_document["semantic_hash_registry"]),
        "sensitivity_only": {
            "q48_s5_disqualified": {
                "cms_terms_without_epsilon4": _terms_report(s5_cms),
                "cms_total_without_epsilon4": fraction_report(s5_total),
                "discrepancy_bound_D": s5_geometry["discrepancy_bound_D"],
                "epsilon3_post_cms": fraction_report(s5_epsilon3_cms),
                "reason": (
                    "The epsilon3 term alone after exact 12*Q^2 CMS "
                    "amplification is not strictly below 2^-128; s5 is excluded."
                ),
                "strict_target_pass": strict_target_pass(s5_epsilon3_cms),
            },
            "topology_base_rows_11892_not_final": {
                "final_geometry_claim": False,
                "reason": (
                    "11892 counts hash-topology rows only; executable non-hash "
                    "adapter rows are not frozen."
                ),
            },
        },
        "source_pins": source_report,
    }


def _write_canonical(path: Path, document: Any) -> None:
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            _fail(f"refusing to overwrite non-regular output {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(document))
    if load_canonical_json(path) != document:
        raise AssertionError(f"canonical write/readback mismatch for {path}")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write-default", type=Path)
    args = parser.parse_args(argv)
    if args.write_default is not None:
        if args.input is not None or args.output is not None or args.check:
            parser.error("--write-default is exclusive")
    elif args.input is None or args.output is None:
        parser.error("--input and --output are required")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.write_default is not None:
            _write_canonical(args.write_default, default_input())
            return 0
        input_document = load_canonical_json(args.input)
        report = build_report(input_document, args.repo_root.resolve())
        if args.check:
            retained = load_canonical_json(args.output)
            if retained != report:
                print("retained report does not match exact regeneration", file=sys.stderr)
                return 1
        else:
            _write_canonical(args.output, report)
        return 0
    except LedgerInputError as exc:
        print(f"hx512 composition ledger rejected input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
