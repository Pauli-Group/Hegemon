#!/usr/bin/env python3
"""Exact, fail-closed strict-QROM profile screen.

This module evaluates a deliberately conditional one-level Ligerito source
screen under Hegemon's local conservative CMS envelope.  All admission
comparisons use ``fractions.Fraction``.  The primary theorems do not state the
numeric constants 12/48/2K^2 verbatim, and the current M4 source is not an IOP;
therefore the module never turns a passing arithmetic screen into a production
profile.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
from functools import lru_cache
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
MANIFEST_PATH = HERE / "profile_manifest.json"
THEOREM_MAP_PATH = HERE / "theorem_premise_map.json"

LOG_RELATION_SIZE = 16
SOURCE_SYMBOLS = 1 << LOG_RELATION_SIZE
BASE_FIELD_BYTES = 16
RO_BITS = 512
POLICY_AUGMENTED_T = 1 << 64
STRICT_TARGET = Fraction(1, 1 << 128)
ORACLE_CAP_BYTES = 512 * 1024 * 1024
MAX_LOG_INV_RATE = 9
QUERY_SEARCH_CAP = 512
UNION_MULTIPLIERS = (1, 2, 8, 16, 64)


@dataclass(frozen=True)
class Profile:
    field_name: str
    field_bits: int
    field_bytes: int
    extension_degree_over_b128: int
    fold_variables: int
    data_columns: int
    message_rows: int
    log_inv_rate: int
    codeword_rows: int
    query_count: int
    equal_source_error_union_terms: int
    encoded_oracle_bytes: int
    frontier_sha512_nodes: int
    proof_bytes: int
    envelope_bits_approx: str


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def max_frontier_nodes(log_leaves: int, opened: int) -> int:
    """Maximum compact Merkle frontier for any ``opened`` leaves.

    At tree depth d the number of occupied nodes is at most min(2^d, q),
    and all of these maxima are simultaneously attainable by spreading the
    leaves.  Summing unary siblings gives the exact closed form below.
    """

    leaves = 1 << log_leaves
    if opened < 0 or opened > leaves:
        raise ValueError("invalid Merkle geometry")
    if opened == 0:
        return 0
    return 2 + sum(min(1 << depth, opened) for depth in range(1, log_leaves)) - opened


def source_error_terms(*, field_bits: int, p: int, r: int, m: int, q: int) -> dict[str, Fraction]:
    """Ligerito Eq. (15), separated into proximity and algebraic terms."""

    if not (0 < p < LOG_RELATION_SIZE and 0 < r < m and 0 < q <= m):
        raise ValueError("invalid source-error geometry")
    query_base = Fraction(m - r - 1, 2 * m)
    if not Fraction(0, 1) <= query_base < Fraction(1, 2):
        raise AssertionError("rate screen requires a query base in [0,1/2)")
    proximity = query_base**q
    algebraic = Fraction(p * (m + 2), 1 << field_bits)
    return {
        "proximity_query": proximity,
        "algebraic_reduction": algebraic,
        "source_total": proximity + algebraic,
    }


def cms_policy_terms(source_error: Fraction, *, union_terms: int, k_cap: int) -> dict[str, Fraction]:
    """Hegemon's exact local policy corollary, not a verbatim CMS theorem."""

    if source_error < 0 or union_terms < 1 or k_cap < 1:
        raise ValueError("invalid CMS policy inputs")
    lifted = 12 * POLICY_AUGMENTED_T**2 * union_terms * source_error
    database_collision = Fraction(48 * POLICY_AUGMENTED_T**3, 1 << RO_BITS)
    oracle_bridge = Fraction(2 * k_cap**2, 1 << RO_BITS)
    return {
        "lifted_source": lifted,
        "ideal_ro_collision_path": database_collision,
        "local_k_cap_bridge": oracle_bridge,
        "conditional_total": lifted + database_collision + oracle_bridge,
    }


def strictly_below_target(value: Fraction) -> bool:
    """The admission comparison is intentionally strict; equality rejects."""

    if not isinstance(value, Fraction):
        raise TypeError("security comparisons require an exact Fraction")
    return value < STRICT_TARGET


def wire_ledger(*, field_bytes: int, p: int, r: int, m: int, q: int) -> dict[str, int]:
    columns = 1 << p
    log_m = m.bit_length() - 1
    if 1 << log_m != m:
        raise ValueError("codeword row count must be a power of two")
    frontier = max_frontier_nodes(log_m, q)
    ledger = {
        "header": 128,
        "statement_id": 64,
        "commitment_root": 64,
        "claimed_value": field_bytes,
        "sumcheck": 2 * p * field_bytes,
        "terminal": r * field_bytes,
        "opened_rows": q * columns * BASE_FIELD_BYTES,
        "authentication": frontier * 64,
    }
    ledger["total"] = sum(ledger.values())
    return ledger


def _negative_log2_display(value: Fraction) -> str:
    """Presentation-only decimal; no security decision consumes this value."""

    if value <= 0:
        raise ValueError("logarithm input must be positive")
    with localcontext() as context:
        context.prec = 50
        bits = (Decimal(value.denominator).ln() - Decimal(value.numerator).ln()) / Decimal(2).ln()
        return format(bits, ".12f")


def _geometry_first_q(*, field_bits: int, p: int, log_inv_rate: int, union_terms: int) -> int | None:
    columns = 1 << p
    r = SOURCE_SYMBOLS // columns
    m = r << log_inv_rate
    limit = min(QUERY_SEARCH_CAP, m)
    for q in range(1, limit + 1):
        source = source_error_terms(field_bits=field_bits, p=p, r=r, m=m, q=q)["source_total"]
        if strictly_below_target(
            cms_policy_terms(source, union_terms=union_terms, k_cap=m)["conditional_total"]
        ):
            return q
    return None


@lru_cache(maxsize=None)
def select_conditional_profile(field_bits: int, union_terms: int = 1) -> Profile:
    """Find the exact smallest fixed-grammar source screen under the oracle cap."""

    if field_bits not in (384, 512):
        raise ValueError("only E384 and E512 are screened")
    if union_terms not in UNION_MULTIPLIERS:
        raise ValueError("unsupported union sensitivity")
    field_bytes = field_bits // 8
    field_name = f"E{field_bits}"
    degree = field_bits // 128
    geometries: list[tuple[int, int, int, int, int]] = []
    for p in range(1, LOG_RELATION_SIZE):
        columns = 1 << p
        r = SOURCE_SYMBOLS // columns
        for log_inv_rate in range(1, MAX_LOG_INV_RATE + 1):
            m = r << log_inv_rate
            oracle_bytes = m * columns * BASE_FIELD_BYTES
            if oracle_bytes > ORACLE_CAP_BYTES:
                continue
            first_q = _geometry_first_q(
                field_bits=field_bits,
                p=p,
                log_inv_rate=log_inv_rate,
                union_terms=union_terms,
            )
            if first_q is not None:
                geometries.append((p, log_inv_rate, r, m, first_q))
    if not geometries:
        raise AssertionError("no conditional profile passes the local arithmetic screen")

    # First passing q supplies a finite ceiling.  We then exhaust every later q
    # whose opening-only lower bound can still beat that ceiling, so the wire
    # minimum does not assume frontier monotonicity.
    best_wire = min(
        wire_ledger(field_bytes=field_bytes, p=p, r=r, m=m, q=q)["total"]
        for p, _rate, r, m, q in geometries
    )
    best: tuple[int, int, int, int, int, dict[str, int]] | None = None
    for p, log_inv_rate, r, m, first_q in geometries:
        columns = 1 << p
        fixed_without_opening_or_auth = (
            128 + 64 + 64 + field_bytes + 2 * p * field_bytes + r * field_bytes
        )
        max_q_by_lower_bound = (best_wire - fixed_without_opening_or_auth - 1) // (
            columns * BASE_FIELD_BYTES
        )
        for q in range(first_q, min(m, max_q_by_lower_bound) + 1):
            ledger = wire_ledger(field_bytes=field_bytes, p=p, r=r, m=m, q=q)
            candidate_key = (ledger["total"], p, log_inv_rate, q)
            if best is None or candidate_key < (best[5]["total"], best[0], best[1], best[4]):
                best = (p, log_inv_rate, r, m, q, ledger)
                best_wire = ledger["total"]
    if best is None:
        raise AssertionError("conditional profile minimization failed")
    p, log_inv_rate, r, m, q, ledger = best
    source = source_error_terms(field_bits=field_bits, p=p, r=r, m=m, q=q)["source_total"]
    envelope = cms_policy_terms(source, union_terms=union_terms, k_cap=m)["conditional_total"]
    if not strictly_below_target(envelope):
        raise AssertionError("selected conditional profile does not pass strictly")
    return Profile(
        field_name=field_name,
        field_bits=field_bits,
        field_bytes=field_bytes,
        extension_degree_over_b128=degree,
        fold_variables=p,
        data_columns=1 << p,
        message_rows=r,
        log_inv_rate=log_inv_rate,
        codeword_rows=m,
        query_count=q,
        equal_source_error_union_terms=union_terms,
        encoded_oracle_bytes=m * (1 << p) * BASE_FIELD_BYTES,
        frontier_sha512_nodes=max_frontier_nodes(m.bit_length() - 1, q),
        proof_bytes=ledger["total"],
        envelope_bits_approx=_negative_log2_display(envelope),
    )


def profile_exact_terms(profile: Profile) -> dict[str, Fraction]:
    source = source_error_terms(
        field_bits=profile.field_bits,
        p=profile.fold_variables,
        r=profile.message_rows,
        m=profile.codeword_rows,
        q=profile.query_count,
    )
    return source | cms_policy_terms(
        source["source_total"],
        union_terms=profile.equal_source_error_union_terms,
        k_cap=profile.codeword_rows,
    )


def fraction_factored(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def bcs_direct_zk_bound(*, committed_units: int, lambda_bits: int) -> Fraction:
    """BCS Lemma 3.4/Lemma 7.5 direct salted-Merkle term for byte-aligned lambda."""

    if committed_units < 1 or lambda_bits % 4:
        raise ValueError("exact rational BCS screen requires positive units and lambda divisible by four")
    exponent = lambda_bits // 4 - 2
    return Fraction(committed_units, 1 << exponent)


def _profile_record(profile: Profile) -> dict[str, Any]:
    record = asdict(profile)
    record["strict_comparison"] = "conditional_total < 2^-128"
    record["source_screen_only"] = True
    record["zero_knowledge_cost_included"] = False
    record["exact_factored_terms"] = {
        "proximity_query": {
            "base_numerator": profile.codeword_rows - profile.message_rows - 1,
            "base_denominator": 2 * profile.codeword_rows,
            "exponent": profile.query_count,
        },
        "algebraic_reduction": {
            "numerator": profile.fold_variables * (profile.codeword_rows + 2),
            "denominator_power_of_two": profile.field_bits,
        },
        "lifted_source": {
            "coefficient": 12,
            "t": POLICY_AUGMENTED_T,
            "t_power": 2,
            "equal_source_error_union_terms": profile.equal_source_error_union_terms,
        },
        "ideal_ro_collision_path": {
            "coefficient": 48,
            "t": POLICY_AUGMENTED_T,
            "t_power": 3,
            "denominator_power_of_two": RO_BITS,
        },
        "local_k_cap_bridge": {
            "coefficient": 2,
            "K": profile.codeword_rows,
            "K_power": 2,
            "denominator_power_of_two": RO_BITS,
        },
    }
    record["exact_fraction_comparison_verified"] = True
    return record


def expected_screen_records() -> dict[str, Any]:
    return {
        f"E{bits}": _profile_record(select_conditional_profile(bits, 1))
        for bits in (384, 512)
    }


def expected_union_records() -> dict[str, Any]:
    return {
        f"E{bits}": [
            {
                "equal_source_error_union_terms": union_terms,
                "query_count": (profile := select_conditional_profile(bits, union_terms)).query_count,
                "proof_bytes": profile.proof_bytes,
                "envelope_bits_approx": profile.envelope_bits_approx,
            }
            for union_terms in UNION_MULTIPLIERS
        ]
        for bits in (384, 512)
    }


PINNED_INPUTS = {
    ".agent/hardening/ligerito-e384-core/ligerito_e384_core.py": "54faaaddef4d366da5ad24cd363ea237796da29204f680b7f946337e94d972c028cffd290eb78896b3cb8b8a7ea0e25bebe15ec0434e7fff0392168403296a6f",
    ".agent/hardening/ligerito-e384-core/source_screen.json": "a260e6c77f6562399c76ed1deb67d1e4b87d423e837c44d01b4e3805d3248974551cae99eca6b81e655ee04ce82e90ba4fb41a7b87394f7791073c44a88b9631",
    ".agent/hardening/binius-pq128-proof-size/salted-bcs-zk-audit/README.md": "bc82cedb303ee955be406729c5826b0bad16980c39af6f733f4c6a4488354bf4743cc3c2f397f8cd3164862d8eba777f371675002cb2861f4bf9ba943da20a62",
    "formal/crypto/HegemonCrypto/CmsLifting.lean": "7eedfceefadd9988fcd43fcf3bf7e67a2bd3ee845d9d7ec53e099d3575268b86bb2c9eac1acfa2f2f3af89e71d54342eb9846c0c76d0217c2b95c70dcb93aeb3",
    "formal/crypto/HegemonCrypto/CmsLocalOperator.lean": "3521d39fff4c17d182125d15c8a3abde7948d350eeb2b81ccfa653ec82608a4b08ff47ec081c8af9fffb2f838494c49bdac90745509392eff389f219bf50d761",
    "formal/crypto/HegemonCrypto/CmsOracleDatabaseBridge.lean": "763ef176d43cf5ce35f2783d5e18924c4cf96ca1ac97c0944ff6b77ab5b16621b0afee6dea46b8e5dfa0a7aa01ebdce51fd6ee05cb4ceed7e539d85ce6250ab6",
    "formal/crypto/HegemonCrypto/SmallWoodBcsQrom.lean": "841f52540846815cfcf91be2ea8063432c8d2525dfd510cd88990957e38cecccc6f3a9df2170959f5b803124421767b2f06ddd56bbca56e5c4432f38d3f5b442",
}

MUTABLE_DEPENDENCIES = (
    "prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs",
    "circuits/transaction/src/full_blake2b448_relation.rs",
    "prototypes/standalone-shake256-binius/strict-mixed-field/src/complete_zk.rs",
    "prototypes/standalone-shake256-binius/binius64",
)


def validate_source_binding(manifest: dict[str, Any]) -> None:
    binding = manifest["source_binding"]
    if binding["retained_source_closure"] is not False:
        raise AssertionError("live mutable dependencies prohibit retained source closure")
    if binding["live_mutable_dependency"] is not True:
        raise AssertionError("mutable dependency must remain explicit")
    if binding["pinned_sha512"] != PINNED_INPUTS:
        raise AssertionError("isolated input pin set drift")
    if tuple(binding["mutable_unpinned_paths"]) != MUTABLE_DEPENDENCIES:
        raise AssertionError("mutable dependency inventory drift")
    for relative, expected in PINNED_INPUTS.items():
        actual = hashlib.sha512((REPO / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise AssertionError(f"pinned isolated ledger input drift: {relative}")
    for relative in MUTABLE_DEPENDENCIES:
        if not (REPO / relative).exists():
            raise AssertionError(f"mutable dependency disappeared: {relative}")
    if not (REPO / "prototypes/standalone-shake256-binius/binius64").is_symlink():
        raise AssertionError("Binius dependency is expected to remain an unretained symlink")


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema") != "hegemon.strict-qrom-profile-selection.v1":
        raise AssertionError("manifest schema drift")
    policy = manifest["local_policy_envelope"]
    required_policy = {
        "formula": "12*t^2*epsilon + 48*t^3/2^512 + 2*K^2/2^512",
        "t_augmented": POLICY_AUGMENTED_T,
        "lambda_bits": RO_BITS,
        "strict_target_denominator_power": 128,
        "K_screen_choice": "codeword_rows_M",
        "verbatim_primary_theorem": False,
        "exact_local_policy_corollary": True,
        "cms_base_game_arity_a_exact": None,
        "external_adversary_queries_supported": None,
    }
    for key, expected in required_policy.items():
        if policy.get(key) != expected:
            raise AssertionError(f"local policy field drift: {key}")
    if manifest["conditional_source_screens"] != expected_screen_records():
        raise AssertionError("conditional source screen drift")
    if manifest["equal_source_error_union_sensitivity"] != expected_union_records():
        raise AssertionError("union sensitivity drift")

    if manifest["production_profile"] is not None or manifest["selected_query_count"] is not None:
        raise AssertionError("no production profile or q may be selected")
    ledger = manifest["full_composed_ledger"]
    if ledger["overall_total"] is not None or ledger["strict_pq_bits"] is not None:
        raise AssertionError("incomplete composition must remain null")
    required_null = {
        "proved_exact_m4_iop_source_error",
        "proved_generalized_special_soundness_or_cms_rbr",
        "exact_cms_modified_bcs_transcript",
        "exact_augmented_t_overhead",
        "concrete_sha512_qro_bridge",
        "complete_zk_bound",
        "commitment_and_semantic_hash_union",
        "grinding_and_retry_union",
        "multi_proof_action_consensus_union",
        "parser_verifier_refinement_union",
    }
    entries = {entry["id"]: entry["value"] for entry in ledger["terms"]}
    if not required_null.issubset(entries) or any(entries[name] is not None for name in required_null):
        raise AssertionError("missing full-ledger terms must remain explicit nulls")

    zk = manifest["bcs_statistical_zk"]
    if zk["lambda512_e384_committed_units_bound_bits"] != 114:
        raise AssertionError("E384 BCS direct bound drift")
    if zk["lambda512_e512_committed_units_bound_bits"] != 115:
        raise AssertionError("E512 BCS direct bound drift")
    if zk["direct_theorem_strict_128"] is not False:
        raise AssertionError("BCS lambda=512 cannot certify strict 128-bit ZK")
    if zk["e384_min_integer_lambda"] != 569 or zk["e384_min_byte_aligned_lambda"] != 576:
        raise AssertionError("E384 BCS lambda threshold drift")
    if zk["e512_min_integer_lambda"] != 565 or zk["e512_min_byte_aligned_lambda"] != 568:
        raise AssertionError("E512 BCS lambda threshold drift")

    whir = manifest["hvzk_whir_conditional_lane"]
    for key in ("exact_epsilon", "exact_profile", "m4_relation_lowering", "cms_knowledge_applicable"):
        if whir.get(key) is not None:
            raise AssertionError(f"HVZK-WHIR conditional field must remain null: {key}")
    if whir["cms_soundness_shape_applicable"] != "conditional" or whir["cms_zk_shape_applicable"] != "conditional":
        raise AssertionError("HVZK-WHIR theorem-shape classification drift")
    if whir["rbr_notion_matches_cms_definition_8_5"] is not False:
        raise AssertionError("relaxed WHIR RBR knowledge must not be relabeled as CMS RBR knowledge")

    for gate, value in manifest["capabilities"].items():
        if value is not False:
            raise AssertionError(f"capability must remain false: {gate}")
    validate_source_binding(manifest)


def validate_theorem_map(theorem_map: dict[str, Any]) -> None:
    if theorem_map.get("schema") != "hegemon.strict-qrom-theorem-premise-map.v1":
        raise AssertionError("theorem map schema drift")
    entries = {entry["id"]: entry for entry in theorem_map["premises"]}
    required = {
        "cms19_big_o_theorem",
        "cms_local_constant_derivation",
        "block_special_to_rbr_soundness",
        "block_no_knowledge_implication",
        "bcs_statistical_zk",
        "ligerito_equation15_ordinary_soundness",
        "hvzk_whir_rbr_and_hvzk",
        "bcfw_relaxed_rbr_mismatch",
        "plonky3_hiding_whir_implementation",
        "sha512_concrete_qro_bridge",
    }
    if not required.issubset(entries):
        raise AssertionError("theorem map premise missing")
    if entries["cms19_big_o_theorem"]["exact_constant_bound_provided"] is not False:
        raise AssertionError("CMS big-O theorem must not be called an exact constant theorem")
    if entries["block_no_knowledge_implication"]["satisfied"] is not False:
        raise AssertionError("special soundness must not authorize QROM knowledge")
    if entries["bcfw_relaxed_rbr_mismatch"]["satisfied"] is not False:
        raise AssertionError("WHIR relaxed RBR mismatch must remain blocking")
    if entries["sha512_concrete_qro_bridge"]["satisfied"] is not False:
        raise AssertionError("concrete SHA-512 QRO bridge is absent")


def run_check() -> None:
    manifest_text = MANIFEST_PATH.read_text()
    theorem_text = THEOREM_MAP_PATH.read_text()
    manifest = json.loads(manifest_text)
    theorem_map = json.loads(theorem_text)
    if manifest_text != canonical_json(manifest):
        raise AssertionError("profile manifest is not canonical JSON")
    if theorem_text != canonical_json(theorem_map):
        raise AssertionError("theorem map is not canonical JSON")
    validate_manifest(manifest)
    validate_theorem_map(theorem_map)


def report() -> None:
    for bits in (384, 512):
        profile = select_conditional_profile(bits, 1)
        print(
            f"conditional_{profile.field_name.lower()}_q={profile.query_count} "
            f"bytes={profile.proof_bytes} bits={profile.envelope_bits_approx}"
        )
    print("union_sensitivity=" + ",".join(str(value) for value in UNION_MULTIPLIERS))
    print("overall_composed_bound=null")
    print("selected_query_count=null")
    print("strict_pq128=false")
    print("production_authorized=false")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    if not args.check and not args.report:
        parser.error("choose --check and/or --report")
    if args.check:
        run_check()
        print("STRICT_QROM_PROFILE_SELECTION_CHECK_PASS")
    if args.report:
        report()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
