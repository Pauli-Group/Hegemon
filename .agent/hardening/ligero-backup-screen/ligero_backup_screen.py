#!/usr/bin/env python3
"""Canonical fail-closed Ligero-family backup architecture screen.

Only Python's standard library is used.  The size routine evaluates the exact
expression printed in Ligero Section 5.3 under an explicitly conditional
padding map.  It must never be presented as serialized or measured proof bytes.
"""

from __future__ import annotations

import hashlib
import json
import math
from fractions import Fraction
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LEDGER_PATH = HERE / "ledger.json"

RELATION_PATH = REPO / ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json"
RELATION_SHA512 = "dae278e46a5d2ed2c58fae4443db8b73967f2b1190336520081a6f3791c04fad63d182cc61c0e1fb75f66bdb70e9ff40d4b1b975d9295fcf3a93bf189c76607e"
FIELD_MODULUS = 18_446_744_069_414_584_321
M_CONSTRAINTS = 20_457_227
N_NONCONSTANT = 19_311_555
L_PUBLIC = 10_152
PRIVATE_TRANSPORT = 77_376
DERIVED_AUXILIARY = 19_224_027
NNZ = 94_551_238
RELATION_CAPACITY = max(M_CONSTRAINTS, N_NONCONSTANT)
GLOBAL_QROM_QUERY_FLOOR = 1 << 64

LOCAL_PRIMARY_SOURCES = (
    {
        "id": "ligero_2022_1608",
        "title": "Ligero: Lightweight Sublinear Arguments Without a Trusted Setup",
        "url": "https://eprint.iacr.org/2022/1608.pdf",
        "local_path": "/private/tmp/ligero-2022-1608.pdf",
        "sha512": "04ddcdfc4f95ba68c3149e0d8efab8f3818eb8b5966b15f3f3917a21ff7d22e91c06bd2bad9406c5bc169091b437eb8005aa5cd63b98f297d6cb6de36428d054",
        "anchors": ["Theorem 4.7", "Sections 5.1-5.3", "PDF pages 26-30"],
    },
    {
        "id": "booligero_2021_121",
        "title": "BooLigero: Improved Sublinear Zero Knowledge Proofs for Boolean Circuits",
        "url": "https://eprint.iacr.org/2021/121.pdf",
        "local_path": "/private/tmp/hegemon-pq-booligero.pdf",
        "sha512": "6149d110b32346f835cafe1bb285d96d738a99b6f56d720d390b1c328b78f3ca510fe74f23e4c082136a7f2b49d25243d0801e94bf89c59dbb38403ac41c48fd",
        "anchors": ["perfect HVZK definition", "modified ZKIOP", "PDF pages 3, 9, 11"],
    },
    {
        "id": "ligerito_2025_1187",
        "title": "Ligerito: A Small and Concretely Fast Polynomial Commitment Scheme",
        "url": "https://eprint.iacr.org/2025/1187.pdf",
        "local_path": "/private/tmp/ligerito-2025.pdf",
        "sha512": "3e367c3dc68e5939c63baa2bfdd7089b97c3cdf2fd8f6425ef0b7e09003ab26287db2033d177cf32b298f7ed4dd053644b6fe5bd48a0208e71b995589ad24d54",
        "anchors": ["Equation 15", "Equation 19", "PDF pages 11, 16"],
    },
    {
        "id": "cms19_834",
        "title": "Succinct Arguments in the Quantum Random Oracle Model",
        "url": "https://eprint.iacr.org/2019/834.pdf",
        "local_path": "/private/tmp/cms19-834.pdf",
        "sha512": "1fc3a6cfce5c1ab2e9e0352581f6725c48ee1b52fa6773d456614d4137cb541443010c127a9fbdfd642ebf5249c05503c4ff531f2995e2918ad1190df334367f",
        "anchors": ["Theorem 8.6", "Sections 8.2 and 8.5", "Lemma 4.9"],
    },
    {
        "id": "block_2023_1256",
        "title": "On Soundness Notions for Interactive Oracle Proofs",
        "url": "https://eprint.iacr.org/2023/1256.pdf",
        "local_path": "/private/tmp/block-2023-1256.pdf",
        "sha512": "24feff318b5ead17f0747e389fdbb03b2257b4c671b92fde8496b689871551ca6585264935c5078bffb75bc18300b6eb0ee463ed09edd0e6229b182eba5cc23d",
        "anchors": ["Theorem 1.1", "Corollary 1.6", "Theorem 1.3", "Remark 1.7"],
    },
    {
        "id": "flock_2026",
        "title": "Flock: Fast Proving for Batch Boolean Computations",
        "url": "https://eprint.iacr.org/2026/1329.pdf",
        "local_path": "/private/tmp/paper/flock-paper.pdf",
        "sha512": "c8efbbc6c6ca764930e622e848a340a4ed7bab13bbd13e52f270282a9e89d910c5613bdab7545dcd3fb049ebb7373f35b89c135a5dadc1f175db3470a0f725b8",
        "anchors": ["explicit non-ZK scope", "100/120-bit SHA-256 profiles", "PDF pages 6, 23"],
    },
)

LOCAL_REPO_SOURCES = {
    ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json": RELATION_SHA512,
    ".agent/hardening/cfw26-section11-carrier-compiler/carrier_manifest.json": "888f4a42f6d5b37aab132e2ba60318a5ee08d6b71f69046ade2ce206e5af99ab479c6555b9635e8750afa2d68ea7f3da12ecb2d47ac3882834a33b76c03bb730",
    ".agent/hardening/cfw26-section11-carrier-compiler/certificate.json": "c8a170acfde05345512b2ca23485fb3ff3b7a4b1d6e71a344b7c777ed6c091d9635d30723712d00a9d30ba16c8c02189bb485b8e2e6f1109903fa7211375756c",
    ".agent/hardening/strict-odd-field-composition/ledger.json": "881bafb101fc4f4c9e9c95612e5ec4914432b8ae34023b5aa2c84e4fb7eb03a6fa892ab40d3e99584ab0bfaa5c2e04ee7af28aaf2ff4e0173fbe54e61ad70f13",
    ".agent/hardening/provekit-architecture-screen/ledger.json": "c46eb3de05021270d9c90835242a78d918c68c12f300b1a992d6cd0045f18a1d0a4d7626807cdd651641185752cd81370664b014213372a3dee083fd59ce1566",
    ".agent/hardening/provekit-architecture-screen/REPORT.md": "676a71e6f17853d04a6ef48d34b35cba4c6df982b24dfb9eb9464ed86164f0675ba87d9eb580d310980c77ca90f5dfc662c93b61c91bf390ee6ff04cabb1d131",
    ".agent/hardening/strict-qrom-profile-selection/profile_manifest.json": "9fce9c878b4814318c5fee0a03be61366fb09c2416240d07f6a0ed51e07cd500b35c9fa4822578b6ad379792e79c7bd62197701e00543a2f58c492187ed616dd",
    ".agent/hardening/strict-qrom-profile-selection/theorem_premise_map.json": "43aa3a028b14316184604f06da4d6c7ec4d9eb65a5bc9603e4b078b3f4a0a5c8450b42d96334fb7b6c0018fd04863dda908088f2e896fdf774efefd01c151fd5",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fraction_record(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def security_bits_display(value: Fraction) -> float:
    return round(-math.log2(float(value)), 12)


def strict_target(bits: int) -> Fraction:
    return Fraction(1, 1 << bits)


def ligero_source_error(*, k: int, sigma: int, t: int) -> Fraction:
    """Improved Ligero Section 5.3 error for e=k and n_code=3k."""

    return 3 * Fraction(2, 3) ** t + Fraction(3 * k + 4, FIELD_MODULUS**sigma)


def minimum_t(*, k: int, sigma: int, source_bits: int) -> int | None:
    target = strict_target(source_bits)
    if Fraction(3 * k + 4, FIELD_MODULUS**sigma) >= target:
        return None
    low, high = 0, 1
    while ligero_source_error(k=k, sigma=sigma, t=high) > target:
        high *= 2
    while low + 1 < high:
        middle = (low + high) // 2
        if ligero_source_error(k=k, sigma=sigma, t=middle) <= target:
            high = middle
        else:
            low = middle
    return high


def quotient_interval_starts(limit: int) -> Iterable[int]:
    """Yield all ell values that can minimize sigma*ell+4*t*floor(N/ell).

    For each constant-quotient interval the objective increases with ell, so
    only the first ell is needed.  This is exact and O(sqrt(N)).
    """

    ell = 1
    while ell <= limit:
        yield ell
        quotient = RELATION_CAPACITY // ell
        if quotient == 0:
            return
        ell = min(limit, RELATION_CAPACITY // quotient) + 1


@lru_cache(maxsize=None)
def _best_conditional_params(
    source_bits: int, hash_bits: int
) -> tuple[int, int, int, int, int, int, int, int, int]:
    if hash_bits % 8:
        raise ValueError("hash_bits must be byte aligned")
    best: tuple[int, int, int, int, int, int, int, int, int] | None = None
    for sigma in range(1, 10):
        for log_k in range(8, 26):
            k = 1 << log_k
            t = minimum_t(k=k, sigma=sigma, source_bits=source_bits)
            if t is None:
                continue
            maximum_ell = k - t - 1  # strict k > ell+t
            if maximum_ell < 1:
                continue
            n_code = 3 * k
            depth = (n_code - 1).bit_length()
            for ell in quotient_interval_starts(maximum_ell):
                rows = RELATION_CAPACITY // ell + 1  # strict rows*ell>N
                direct = k * sigma + (k + ell - 1) * sigma + (2 * k - 1) * sigma
                opened = t * (4 * rows + 3 * sigma)
                merkle_bytes = t * depth * (hash_bits // 8)
                expression_bytes = (direct + opened) * 8 + merkle_bytes
                candidate = (
                    expression_bytes,
                    k,
                    ell,
                    rows,
                    sigma,
                    t,
                    depth,
                    direct,
                    opened,
                )
                if best is None or candidate < best:
                    best = candidate
    if best is None:
        raise AssertionError("parameter search found no admissible Ligero screen")
    return best


def conditional_ligero_screen(*, source_bits: int, hash_bits: int) -> dict[str, Any]:
    best = _best_conditional_params(source_bits, hash_bits)
    expression_bytes, k, ell, rows, sigma, t, depth, direct, opened = best
    error = ligero_source_error(k=k, sigma=sigma, t=t)
    field_transcript_bytes = (direct + opened) * 8
    return {
        "status": "conditional_paper_expression_only",
        "source_security_target_bits": source_bits,
        "hash_output_bits": hash_bits,
        "field_modulus": str(FIELD_MODULUS),
        "relation_capacity_max_m_n": RELATION_CAPACITY,
        "k": k,
        "ell": ell,
        "rows": rows,
        "sigma": sigma,
        "t": t,
        "e": k,
        "n_code": 3 * k,
        "tree_depth": depth,
        "tree_leaves": 1 << depth,
        "packing_slack": rows * ell - RELATION_CAPACITY,
        "k_strict_slack": k - ell - t,
        "source_error": fraction_record(error),
        "source_security_bits_display": security_bits_display(error),
        "source_error_authority": "exact evaluation of the Section 5.3 simplification supported by the later Appendix C refined analysis; not an implemented or composed theorem certificate",
        "printed_theorem_4_7_direct_parameter_conditions_satisfied": False,
        "printed_theorem_4_7_direct_condition_conflict": "e=k and n_code=3k do not satisfy printed e<(n-k)/4; the screen instead follows the paper's later e<d/2 Appendix C refinement",
        "appendix_c_refined_analysis_used": True,
        "appendix_c_general_query_bound": "(1-e/n_code)^t+((k+ell)/n_code)^t+(2k/n_code)^t+(n_code+3)/|F|^sigma",
        "section_5_3_simplified_bound": "3*(2/3)^t+(n_code+4)/|F|^sigma",
        "direct_test_field_elements": direct,
        "opened_view_field_elements": opened,
        "field_transcript_bytes": field_transcript_bytes,
        "merkle_decommitment_bytes": t * depth * (hash_bits // 8),
        "paper_core_expression_bytes": expression_bytes,
        "paper_expression": "8*(k*sigma+(k+ell-1)*sigma+(2*k-1)*sigma+t*(4*rows+3*sigma))+t*ceil_log2(3*k)*(hash_bits/8)",
        "proof_bytes": None,
        "proof_bytes_lower_bound": None,
        "proof_bytes_upper_bound": None,
        "not_a_proof_bound_reason": "paper expression lacks an exact Hegemon adapter, canonical BCS/CMS wire, fixed commitment/root/salt/domain framing, parser, and retained artifact",
    }


def bcs_zk_floor(*, p_floor_bits: int, lambda_bits: int) -> Fraction:
    if lambda_bits % 4:
        raise ValueError("BCS lambda must be divisible by four")
    return Fraction(4 * p_floor_bits, 1 << (lambda_bits // 4))


def first_lambda_for_floor(*, p_floor_bits: int, alignment: int) -> int:
    for value in range(alignment, 4097, alignment):
        if value % 4 == 0 and bcs_zk_floor(p_floor_bits=p_floor_bits, lambda_bits=value) < strict_target(128):
            return value
    raise AssertionError("lambda search exhausted")


def conditional_qrom_floor(screen: dict[str, Any], lambda_bits: int) -> dict[str, Any]:
    error = ligero_source_error(k=screen["k"], sigma=screen["sigma"], t=screen["t"])
    p_floor_bits = screen["field_transcript_bytes"] * 8
    bcs = bcs_zk_floor(p_floor_bits=p_floor_bits, lambda_bits=lambda_bits)
    cms_iop = 12 * GLOBAL_QROM_QUERY_FLOOR**2 * error
    cms_ro = Fraction(48 * GLOBAL_QROM_QUERY_FLOOR**3, 1 << lambda_bits)
    partial_floor = bcs + cms_iop + cms_ro
    return {
        "lambda_bits": lambda_bits,
        "global_augmented_game_query_budget": str(GLOBAL_QROM_QUERY_FLOOR),
        "p_floor_bits": p_floor_bits,
        "p_floor_basis": "optimistic lower bound from screened prover field messages and opened field views; actual total IOP proof length p(x) is unknown and larger or equal",
        "bcs_direct_zk_floor": fraction_record(bcs),
        "bcs_direct_zk_floor_security_bits_display": security_bits_display(bcs),
        "cms_local_policy_iop_term": fraction_record(cms_iop),
        "cms_local_policy_iop_security_bits_display": security_bits_display(cms_iop),
        "cms_local_policy_random_oracle_term": fraction_record(cms_ro),
        "cms_local_policy_random_oracle_security_bits_display": security_bits_display(cms_ro),
        "partial_error_floor": fraction_record(partial_floor),
        "partial_error_floor_security_bits_display": security_bits_display(partial_floor),
        "partial_floor_strictly_below_2^-128": partial_floor < strict_target(128),
        "authoritative_composed_bound": False,
        "authority_blockers": [
            "actual total IOP proof length p(x) is unknown",
            "CMS theorem is big-O; 12/48 constants are a local conservative corollary only",
            "exact base-game arity a and BCSExpand O(q log ell) overhead are unknown",
            "concrete SHA-512/SHAKE ideal-to-QRO reduction is absent",
            "grinding, retry, sampling, hash-role, multi-proof, and consensus-history union terms are absent",
        ],
    }


def _candidate(
    candidate_id: str,
    *,
    positive_evidence: list[str],
    blockers: list[str],
    interactive_perfect_view_zk: bool = False,
    rbr_source_premise: bool = False,
) -> dict[str, Any]:
    return {
        "id": candidate_id,
        "positive_evidence": positive_evidence,
        "blockers": blockers,
        "transparent_hash_based": True,
        "uses_ecc_pairings_or_rsa": False,
        "interactive_perfect_view_zk_source_theorem": interactive_perfect_view_zk,
        "applicable_rbr_source_premise": rbr_source_premise,
        "exact_frozen_odd_field_relation_adapter": False,
        "complete_whole_view_noninteractive_zk_instantiated": False,
        "finite_qrom_fiat_shamir_composed": False,
        "conventional_hash_at_least_512_instantiated": False,
        "one_canonical_self_contained_proof": False,
        "native_verifier_refinement": False,
        "same_relation_proof_bytes": None,
        "eligible": False,
        "production_candidate": False,
    }


def composition_terms() -> list[dict[str, Any]]:
    ids = (
        ("relation", "exact_frozen_relation_and_host_boundary"),
        ("adapter", "goldilocks_r1cs_to_ligero_refinement"),
        ("pcs", "salted_merkle_binding_and_selective_opening_hiding"),
        ("iop", "ligero_rbr_soundness_for_instantiated_relation"),
        ("iop", "knowledge_or_argument_of_knowledge_notion"),
        ("zero-knowledge", "whole_view_noninteractive_simulator"),
        ("zero-knowledge", "bcs_total_iop_proof_length_p"),
        ("fiat-shamir", "cms_finite_qrom_compiler_applicability"),
        ("fiat-shamir", "cms_augmented_query_expansion"),
        ("fiat-shamir", "base_game_arity"),
        ("hash", "sha512_or_shake_ideal_to_concrete_qrom"),
        ("hash", "merkle_collision_second_preimage_prf_union"),
        ("sampling", "challenge_rejection_bias_and_abort"),
        ("grinding", "grinding_and_prover_retry_failure"),
        ("rng", "prover_randomness_failure_and_reuse"),
        ("union", "semantic_hash_roles_and_physical_calls"),
        ("union", "activity_masks_authorization_modes_and_actions"),
        ("union", "block_epoch_history_and_multi_proof_union"),
        ("refinement", "canonical_parser_and_native_verifier"),
        ("production", "unchanged_wallet_rpc_relay_mempool_block_sync_reorg_bytes"),
        ("release", "retained_artifact_mutation_restart_and_manifest"),
    )
    return [
        {"category": category, "id": term_id, "advantage": None, "authority": "missing"}
        for category, term_id in ids
    ]


def build_ledger() -> dict[str, Any]:
    source128_512 = conditional_ligero_screen(source_bits=128, hash_bits=512)
    source128_640 = conditional_ligero_screen(source_bits=128, hash_bits=640)
    source264_512 = conditional_ligero_screen(source_bits=264, hash_bits=512)
    source264_632 = conditional_ligero_screen(source_bits=264, hash_bits=632)
    source264_640 = conditional_ligero_screen(source_bits=264, hash_bits=640)
    p_floor = source264_512["field_transcript_bytes"] * 8
    candidates = [
        _candidate(
            "original_ligero",
            interactive_perfect_view_zk=True,
            rbr_source_premise=True,
            positive_evidence=[
                "Theorem 4.7 gives perfect completeness, explicit soundness, and an identical-view ZK claim; Lemma 4.15 gives a simulator",
                "Section 5.2 gives a protocol-specific round-by-round classical-ROM analysis",
                "Section 5.3 gives an explicit communication expression",
            ],
            blockers=[
                "no implemented/refined exact frozen R1CS adapter",
                "the e=k,n=3k size profile is not a direct instantiation of printed Theorem 4.7; it relies on the later Appendix C refined e<d/2 analysis",
                "paper implementation uses a 30-bit field and SHA-256, not this relation or a wide-hash QROM profile",
                "no exact CMS augmented-query/arity instantiation or concrete hash QRO bridge",
                "no canonical proof wire or retained same-relation artifact",
            ],
        ),
        _candidate(
            "booligero",
            interactive_perfect_view_zk=True,
            positive_evidence=["paper supplies a modified public-coin perfect-HVZK Boolean-circuit IOP"],
            blockers=[
                "construction is over GF(2^w), not the frozen Goldilocks odd-field R1CS",
                "a new field/compiler refinement would be required",
                "no exact finite-QROM and wide-hash implementation ledger",
            ],
        ),
        _candidate(
            "ligero_plus_plus",
            positive_evidence=["official bibliographic abstract reports an optimized Ligero-family R1CS/FRI construction"],
            blockers=[
                "pinned full primary construction/source unavailable in this bounded lane",
                "abstract cannot establish complete whole-view ZK, exact finite-QROM composition, or same-relation bytes",
            ],
        ),
        _candidate(
            "ligerito",
            positive_evidence=["paper gives a transparent hash-based polynomial commitment and inner-product scheme with exact ordinary error and communication expressions"],
            blockers=[
                "paper construction is not zero knowledge",
                "no applicable generalized-special or RBR premise for the exact one-level core",
                "existing local 136,048/208,400-byte screens cover only 65,536 source symbols and are not this relation",
            ],
        ),
        _candidate(
            "flock",
            positive_evidence=["paper and official source implement fast hash-based batch Boolean R1CS proving"],
            blockers=[
                "paper explicitly does not provide zero knowledge",
                "evaluated profiles target 100/120 bits and SHA-256",
                "batch binary-field construction is not an exact frozen Goldilocks adapter",
            ],
        ),
    ]
    return {
        "schema": "hegemon.ligero-backup-screen.v1",
        "canonical_json": "UTF-8, recursively sorted keys, separators comma/colon, no insignificant whitespace, exactly one trailing LF",
        "status": "fail_closed",
        "verdict": "no_qualifying_ligero_family_architecture",
        "architecture_winner": None,
        "production_authorized": False,
        "scope": {
            "source_only": True,
            "heavy_build_or_dependency_fetch_performed": False,
            "owned_directory_only": True,
            "screen_date": "2026-08-22",
        },
        "exact_frozen_relation": {
            "profile": "blake2b448-mixed",
            "field": "Goldilocks",
            "field_modulus": str(FIELD_MODULUS),
            "m_constraints": M_CONSTRAINTS,
            "n_nonconstant_variables": N_NONCONSTANT,
            "l_public_variables": L_PUBLIC,
            "private_transport_variables": PRIVATE_TRANSPORT,
            "derived_auxiliary_variables": DERIVED_AUXILIARY,
            "matrix_nonzeros_total": NNZ,
            "relation_manifest_sha512": RELATION_SHA512,
            "source_only_macro_program": True,
            "host_only_predicate_count": 4,
            "host_only_boundary_closed": False,
            "exact_full_relation_authorized": False,
        },
        "sources": {
            "primary_pdfs": list(LOCAL_PRIMARY_SOURCES),
            "additional_primary_urls": [
                {
                    "id": "bcs16_116",
                    "url": "https://eprint.iacr.org/2016/116.pdf",
                    "anchors": ["Lemma 3.4", "Lemma 7.5"],
                },
                {
                    "id": "ligero_plus_plus_ccs2020",
                    "url": "https://doi.org/10.1145/3372297.3417893",
                    "content_pinned": False,
                },
                {
                    "id": "ligero_prover_official",
                    "url": "https://github.com/ligeroinc/ligero-prover",
                    "head_observed_2026_08_22": "a40868f6045ddf27a488f65498a9f17832c1cda0",
                },
                {
                    "id": "flock_official",
                    "url": "https://github.com/succinctlabs/flock",
                    "head_observed_2026_08_22": "e636760f8dae78306f804554fb4244993758b011",
                },
            ],
            "local_repo_sha512": LOCAL_REPO_SOURCES,
            "retained_source_closure": False,
            "source_closure_blocker": "Ligero++ full primary construction/source and a retained local BCS PDF were not closed in this bounded lane",
        },
        "candidate_matrix": candidates,
        "conditional_ligero_paper_screens": {
            "source128_hash512": source128_512,
            "source128_hash640": source128_640,
            "source264_hash512": source264_512,
            "source264_hash632": source264_632,
            "source264_hash640": source264_640,
            "mapping": "paper-level R1CS assignment z with x=A*z, y=B*z, c=C*z, padded so rows*ell>max(m,n); no implementation/refinement authority",
        },
        "bcs_complete_zk_floor": {
            "source_expression": "p(x)*2^(-lambda/4+2)",
            "p_meaning": "total IOP proof length in bits, not Merkle leaf count and not serialized NIZK bytes",
            "source264_optimistic_p_floor_bits": p_floor,
            "minimum_multiple_of_four_lambda_from_floor_only": first_lambda_for_floor(p_floor_bits=p_floor, alignment=4),
            "minimum_byte_aligned_lambda_from_floor_only": first_lambda_for_floor(p_floor_bits=p_floor, alignment=8),
            "exact_p_bits": None,
            "exact_required_lambda_bits": None,
            "lambda512": conditional_qrom_floor(source264_512, 512),
            "lambda632": conditional_qrom_floor(source264_632, 632),
            "lambda640": conditional_qrom_floor(source264_640, 640),
        },
        "composition": {
            "cms_primary_theorem_shape": "O(T^2*epsilon_iop + T^3/2^lambda) under exact RBR premises; constants and augmented-query expansion must be instantiated",
            "local_non_authoritative_corollary": "12*T^2*epsilon_iop + 48*T^3/2^lambda + 2*a/2^lambda",
            "required_terms": composition_terms(),
            "all_required_terms_present": False,
            "pcs_advantage": None,
            "iop_advantage": None,
            "fiat_shamir_advantage": None,
            "concrete_hash_advantage": None,
            "grinding_advantage": None,
            "union_advantage": None,
            "overall_advantage": None,
            "composed_security_bits": None,
            "strict_pq_qrom_at_least_128": False,
        },
        "wide_hash_screen": {
            "384_bit_generic_quantum_preimage_ceiling_bits": 192,
            "384_bit_generic_quantum_collision_ceiling_bits": 128,
            "512_bit_generic_quantum_preimage_ceiling_bits": 256,
            "512_bit_generic_quantum_collision_ceiling_bits": 512 / 3,
            "384_has_no_strict_collision_margin_before_composition": True,
            "concrete_sha512_or_shake_qrom_bridge_present": False,
        },
        "comparators": {
            "cfw26_105_oracle_carrier": {
                "carrier_present": True,
                "encoded_oracles": {"witness": 1, "inner_masks": 78, "outer_masks": 26, "total": 105},
                "printed_theorem_inheritance": False,
                "defects": [
                    "coefficient mismatch",
                    "Step 9/main linear form does not typecheck without explicit row_M(M,alpha)",
                    "printed st2=(0,1,0,...) checks coefficient one rather than s(1); honest s=X^2-X fails",
                ],
                "required_endpoint_repair": "st2=pow(1)=(1,1,...,1)",
                "proof_bytes": None,
                "eligible": False,
            },
            "provekit": {
                "generic_r1cs_stack_present": True,
                "one_logical_proof_object": True,
                "whole_view_complete_zk_proved": False,
                "finite_qrom_composition_present": False,
                "minimum_binding_hash_bits": 256,
                "generic_quantum_collision_ceiling_bits": 256 / 3,
                "same_relation_proof_bytes": None,
                "eligible": False,
            },
        },
        "proof_artifact": {
            "same_relation_proof_bytes": None,
            "proof_bytes_lower_bound": None,
            "proof_bytes_upper_bound": None,
            "retained_qualifying_proof": None,
            "measured": False,
        },
        "authority": {
            "exact_full_relation": False,
            "complete_whole_view_zero_knowledge": False,
            "composed_finite_qrom_pq128": False,
            "conventional_wide_hash_instantiation": False,
            "one_canonical_self_contained_proof": False,
            "exact_verifier_consensus_binding": False,
            "same_relation_measured_proof_bytes": False,
            "mutation_restart_verification": False,
            "formal_refinement": False,
            "release_manifest": False,
            "production_authorized": False,
        },
        "claim_boundary": "Source-grounded negative architecture screen and exact conditional paper-expression arithmetic only; no winner, proof byte claim, composed security, verifier authority, or production integration",
    }


def validate_ledger(ledger: dict[str, Any]) -> None:
    if ledger != build_ledger():
        raise AssertionError("ledger differs from canonical generated value")
    if ledger["status"] != "fail_closed" or ledger["architecture_winner"] is not None:
        raise AssertionError("architecture screen must remain fail-closed with no winner")
    if ledger["production_authorized"] is not False:
        raise AssertionError("production authority must remain false")
    for gate, value in ledger["authority"].items():
        if value is not False:
            raise AssertionError(f"authority.{gate} must remain false")
    artifact = ledger["proof_artifact"]
    for key in ("same_relation_proof_bytes", "proof_bytes_lower_bound", "proof_bytes_upper_bound", "retained_qualifying_proof"):
        if artifact[key] is not None:
            raise AssertionError(f"proof_artifact.{key} must remain null")
    for candidate in ledger["candidate_matrix"]:
        if candidate["eligible"] or candidate["production_candidate"]:
            raise AssertionError(f"candidate {candidate['id']} must remain ineligible")
        if candidate["same_relation_proof_bytes"] is not None:
            raise AssertionError(f"candidate {candidate['id']} must not claim proof bytes")
    composition = ledger["composition"]
    if composition["all_required_terms_present"] or composition["strict_pq_qrom_at_least_128"]:
        raise AssertionError("composition must remain incomplete")
    if composition["composed_security_bits"] is not None or composition["overall_advantage"] is not None:
        raise AssertionError("composed result must remain null")
    categories = {term["category"] for term in composition["required_terms"]}
    for required in ("pcs", "iop", "fiat-shamir", "hash", "grinding", "union"):
        if required not in categories:
            raise AssertionError(f"missing composition category {required}")
    if any(term["authority"] != "missing" or term["advantage"] is not None for term in composition["required_terms"]):
        raise AssertionError("composition term was silently promoted")
    cfw = ledger["comparators"]["cfw26_105_oracle_carrier"]
    if cfw["encoded_oracles"]["total"] != 105 or cfw["printed_theorem_inheritance"]:
        raise AssertionError("CFW comparator drift")
    if "s=X^2-X" not in cfw["defects"][2]:
        raise AssertionError("CFW endpoint counterexample missing")
    provekit = ledger["comparators"]["provekit"]
    if not math.isclose(provekit["generic_quantum_collision_ceiling_bits"], 256 / 3):
        raise AssertionError("ProveKit collision ceiling drift")
    if provekit["eligible"] or provekit["whole_view_complete_zk_proved"]:
        raise AssertionError("ProveKit must remain ineligible")


def validate_relation_source() -> None:
    if sha512_file(RELATION_PATH) != RELATION_SHA512:
        raise AssertionError("frozen relation manifest SHA-512 drift")
    manifest = json.loads(RELATION_PATH.read_text(encoding="utf-8"))
    geometry = manifest["hash_profiles"]["blake2b448-mixed"]["geometry"]
    expected = {
        "m_constraints": M_CONSTRAINTS,
        "n_nonconstant_variables": N_NONCONSTANT,
        "l_public_variables": L_PUBLIC,
        "private_transport_variables": PRIVATE_TRANSPORT,
        "derived_auxiliary_variables": DERIVED_AUXILIARY,
        "matrix_nonzeros_total": NNZ,
    }
    for key, value in expected.items():
        if geometry[key] != value:
            raise AssertionError(f"relation geometry drift at {key}")
    if manifest["host_only_boundary"]["groups"] != [
        "61-byte policy-identity BLAKE2b-384 recomputation",
        "whole-manifest v1 BLAKE2b-384 recomputation",
        "selected-entry index membership in the committed vector",
        "consensus authentication of expected root and height",
    ]:
        raise AssertionError("host-only boundary drift")


def validate_repo_sources() -> None:
    for relative, expected in LOCAL_REPO_SOURCES.items():
        actual = sha512_file(REPO / relative)
        if actual != expected:
            raise AssertionError(f"local source drift: {relative}")


def validate_primary_pdfs(*, require_present: bool) -> None:
    for source in LOCAL_PRIMARY_SOURCES:
        path = Path(source["local_path"])
        if not path.exists():
            if require_present:
                raise AssertionError(f"local primary PDF missing: {path}")
            continue
        if sha512_file(path) != source["sha512"]:
            raise AssertionError(f"local primary PDF drift: {path}")


if __name__ == "__main__":
    value = build_ledger()
    validate_ledger(value)
    validate_relation_source()
    validate_repo_sources()
    validate_primary_pdfs(require_present=False)
    print(canonical_json(value), end="")
