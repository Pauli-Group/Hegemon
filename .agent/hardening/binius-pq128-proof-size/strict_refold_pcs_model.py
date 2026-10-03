#!/usr/bin/env python3
"""Exact wire screen for a strict mixed-field Ligerito/refold PCS.

This is a size and parameter model, not a PCS implementation or a security
proof.  It deliberately distinguishes the implemented, non-ZK Ligerito core
from the still-unmeasured complete-ZK wrapper.  In particular, a result is
never strict-admitted merely because the non-ZK core fits the byte cap.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import math
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator, Optional


LOG_RELATION_SIZE = 14
# Unfrozen Pay1x2 sizing assumption. This is not emitted by the current M4
# compiler and must never be reused as a production-relation statistic.
PAY1X2_MODELED_ACTIVE_SYMBOLS = 14_658 + 325 + 512
STRICT_CLASSICAL_BITS = 264
EXTENSION_FIELD_BITS = 384
SOURCE_ELEMENT_BYTES = 16
EXTENSION_ELEMENT_BYTES = 48
DIGEST_BYTES = 64
PROOF_HEADER_BYTES = 64
ENVELOPE_HEADER_BYTES = 12
ENVELOPE_CAP_BYTES = 124_080
PROOF_CAP_BYTES = ENVELOPE_CAP_BYTES - ENVELOPE_HEADER_BYTES

# Frozen M4 relation-reduction material outside the replacement PCS.
M4_WIDE_RECEIVES = 113
M4_WIDE_RECEIVE_BYTES = M4_WIDE_RECEIVES * EXTENSION_ELEMENT_BYTES

# A rational, exactly serializable distance from the Johnson radius.
JOHNSON_ETA_NUMERATOR = 1
JOHNSON_ETA_DENOMINATOR = 256
JOHNSON_ETA = JOHNSON_ETA_NUMERATOR / JOHNSON_ETA_DENOMINATOR


@functools.lru_cache(maxsize=None)
def max_compact_merkle_frontier_nodes(log_leaves: int, opened: int) -> int:
    """Maximum canonical multiproof frontier for `opened` distinct leaves.

    At every internal node, an empty sibling of a non-empty queried subtree
    contributes one digest.  The recurrence maximizes over every split of the
    queried leaves and is exact for a complete binary tree.  Using the maximum,
    rather than one lucky Fiat-Shamir sample, makes the byte cap deterministic.
    """

    if log_leaves < 0 or opened < 0 or opened > (1 << log_leaves):
        raise ValueError("invalid Merkle geometry")
    if opened == 0 or (log_leaves == 0 and opened == 1):
        return 0
    if log_leaves == 0:
        raise ValueError("invalid leaf count")

    child_capacity = 1 << (log_leaves - 1)
    best = -1
    left_min = max(0, opened - child_capacity)
    left_max = min(opened, child_capacity)
    for left in range(left_min, left_max + 1):
        right = opened - left
        if left == 0:
            candidate = 1 + max_compact_merkle_frontier_nodes(log_leaves - 1, right)
        elif right == 0:
            candidate = 1 + max_compact_merkle_frontier_nodes(log_leaves - 1, left)
        else:
            candidate = (
                max_compact_merkle_frontier_nodes(log_leaves - 1, left)
                + max_compact_merkle_frontier_nodes(log_leaves - 1, right)
            )
        best = max(best, candidate)
    return best


def _per_query_bits(log_inv_rate: int, eta: float = JOHNSON_ETA) -> float:
    rho_sqrt = math.exp2(-log_inv_rate / 2)
    if not 0 < eta < 1 - rho_sqrt:
        raise ValueError("eta must put gamma strictly inside the Johnson radius")
    return -math.log2(rho_sqrt + eta)


def johnson_query_count(
    log_inv_rate: int,
    target_bits: int = STRICT_CLASSICAL_BITS,
    eta: float = JOHNSON_ETA,
) -> int:
    """Queries closing `(sqrt(rho)+eta)^q <= 2^-target_bits`."""

    return math.ceil(target_bits / _per_query_bits(log_inv_rate, eta))


@dataclass(frozen=True)
class JohnsonSecurity:
    query_bits: float
    mca_bits: float
    ood_binding_bits: float
    list_log2_bound: float

    @property
    def minimum_bits(self) -> float:
        return min(self.query_bits, self.mca_bits, self.ood_binding_bits)


def johnson_security(
    *,
    log_inv_rate: int,
    log_message_columns: int,
    log_interleaving: int,
    level_variables: int,
    query_count: int,
    explicit_ood_samples: int,
    eta: float = JOHNSON_ETA,
) -> JohnsonSecurity:
    """Flock App. C/BCHKS Johnson-OOD error terms over GF(2^384).

    `mca_bits` includes the full `(2^ell)-1` nonempty-fold event union.  L0 uses
    its post-commit random evaluation claim as the implicit OOD sample; deeper
    levels require at least one explicit sample and use the pairwise list union.
    """

    rho = math.exp2(-log_inv_rate)
    rho_sqrt = math.sqrt(rho)
    gamma = 1 - rho_sqrt - eta
    if gamma <= 0:
        raise ValueError("non-positive Johnson proximity radius")

    # BCHKS/Flock Appendix C uses ceil(sqrt(rho) / eta), without a factor 2.
    m_param = max(math.ceil(rho_sqrt / eta), 3)
    half = m_param + 0.5
    codeword_length = math.exp2(log_message_columns + log_inv_rate)
    a = (
        (2 * half**5 + 3 * half * gamma * rho)
        / (3 * rho**1.5)
        * codeword_length
        + half / rho_sqrt
    )
    # Every nonempty subset of the interleaved rows can be the first bad fold;
    # charge the complete event union, rather than only the largest round.
    row_events = max((1 << log_interleaving) - 1, 1)
    log_a_with_rows = math.log2(a) + math.log2(row_events)
    mca_bits = EXTENSION_FIELD_BITS - log_a_with_rows

    list_log2 = math.log2(1 / (2 * eta * rho_sqrt))
    log_mu = math.log2(level_variables)
    if explicit_ood_samples == 0:
        # The post-commit evaluation claim selects one element from the list.
        ood_bits = EXTENSION_FIELD_BITS - list_log2 - log_mu
    else:
        # Pairwise union over list elements agreeing at all sampled points.
        ood_bits = (
            explicit_ood_samples * (EXTENSION_FIELD_BITS - log_mu)
            - (2 * list_log2 - 1)
        )

    return JohnsonSecurity(
        query_bits=query_count * _per_query_bits(log_inv_rate, eta),
        mca_bits=mca_bits,
        ood_binding_bits=ood_bits,
        list_log2_bound=list_log2,
    )


@dataclass(frozen=True)
class LevelBytes:
    level: int
    input_variables: int
    fold_variables: int
    residual_variables: int
    log_inv_rate: int
    log_codeword_leaves: int
    query_count: int
    row_lanes: int
    row_element_bytes: int
    opened_row_bytes: int
    frontier_nodes: int
    authentication_bytes: int
    encoded_oracle_bytes: int
    explicit_ood_samples: int
    security: Optional[JohnsonSecurity]


@dataclass(frozen=True)
class WirePlan:
    name: str
    log_relation_size: int
    active_symbols: int
    folds: tuple[int, ...]
    terminal_variables: int
    levels: tuple[LevelBytes, ...]
    header_bytes: int
    m4_wide_receive_bytes: int
    roots_bytes: int
    sumcheck_messages: int
    sumcheck_bytes: int
    ood_value_bytes: int
    terminal_bytes: int
    opened_row_bytes: int
    authentication_bytes: int
    proof_bytes: int
    envelope_bytes: int
    headroom_bytes: int
    complete_zero_knowledge: bool
    strict_admitted: bool
    blocking_reason: str


def _assemble_plan(
    *,
    name: str,
    log_relation_size: int,
    active_symbols: int,
    folds: tuple[int, ...],
    levels: tuple[LevelBytes, ...],
    complete_zero_knowledge: bool,
    blocking_reason: str,
    charge_authentication: bool = True,
    elide_terminal_checksum: bool = False,
) -> WirePlan:
    if not 0 < active_symbols <= (1 << log_relation_size):
        raise ValueError("active symbols must fit the committed bucket")
    terminal_variables = log_relation_size - sum(folds)
    if terminal_variables < 0:
        raise ValueError("folds exceed relation dimension")
    root_bytes = len(levels) * DIGEST_BYTES
    # Charge the conservative generic grammar by default. The executable
    # one-level/no-OOD grammar reconstructs its final checksum from the
    # authenticated terminal vector, observes it at the same FS position, and
    # removes exactly one two-element message from the wire.
    explicit_ood_samples = sum(level.explicit_ood_samples for level in levels)
    if elide_terminal_checksum and (len(levels) != 1 or explicit_ood_samples != 0):
        raise ValueError(
            "terminal-checksum elision is proved only for the one-level no-OOD grammar"
        )
    sumcheck_messages = (
        log_relation_size - terminal_variables + len(levels) + explicit_ood_samples
        - int(elide_terminal_checksum)
    )
    sumcheck_bytes = sumcheck_messages * 2 * EXTENSION_ELEMENT_BYTES
    ood_value_bytes = explicit_ood_samples * EXTENSION_ELEMENT_BYTES
    terminal_bytes = (1 << terminal_variables) * EXTENSION_ELEMENT_BYTES
    opened_row_bytes = sum(level.opened_row_bytes for level in levels)
    authentication_bytes = (
        sum(level.authentication_bytes for level in levels) if charge_authentication else 0
    )
    proof_bytes = (
        PROOF_HEADER_BYTES
        + M4_WIDE_RECEIVE_BYTES
        + root_bytes
        + sumcheck_bytes
        + ood_value_bytes
        + terminal_bytes
        + opened_row_bytes
        + authentication_bytes
    )
    envelope_bytes = ENVELOPE_HEADER_BYTES + proof_bytes
    # Component inequalities are not a composed union/QROM theorem.  Admission
    # stays fail-closed until an independently verified composition evidence
    # object is supplied; this model intentionally has no such input.
    strict_admitted = False
    return WirePlan(
        name=name,
        log_relation_size=log_relation_size,
        active_symbols=active_symbols,
        folds=folds,
        terminal_variables=terminal_variables,
        levels=levels,
        header_bytes=PROOF_HEADER_BYTES,
        m4_wide_receive_bytes=M4_WIDE_RECEIVE_BYTES,
        roots_bytes=root_bytes,
        sumcheck_messages=sumcheck_messages,
        sumcheck_bytes=sumcheck_bytes,
        ood_value_bytes=ood_value_bytes,
        terminal_bytes=terminal_bytes,
        opened_row_bytes=opened_row_bytes,
        authentication_bytes=authentication_bytes,
        proof_bytes=proof_bytes,
        envelope_bytes=envelope_bytes,
        headroom_bytes=PROOF_CAP_BYTES - proof_bytes,
        complete_zero_knowledge=complete_zero_knowledge,
        strict_admitted=strict_admitted,
        blocking_reason=blocking_reason,
    )


def _ordered_fold_partitions(
    remaining: int,
    prefix: tuple[int, ...] = (),
) -> Iterator[tuple[int, ...]]:
    if prefix:
        yield prefix
    for fold in range(1, remaining + 1):
        yield from _ordered_fold_partitions(remaining - fold, prefix + (fold,))


def fixed_q_plan(
    folds: tuple[int, ...],
    *,
    log_relation_size: int = LOG_RELATION_SIZE,
    active_symbols: int = PAY1X2_MODELED_ACTIVE_SYMBOLS,
    query_count: int = 319,
    charge_authentication: bool = True,
) -> WirePlan:
    """Rectangular refold screen using the frozen strict BaseFold `q=319`."""

    current_variables = log_relation_size
    levels: list[LevelBytes] = []
    min_log_leaves = math.ceil(math.log2(query_count))
    for level_index, fold in enumerate(folds):
        if not 1 <= fold <= current_variables:
            raise ValueError("invalid fold partition")
        residual = current_variables - fold
        log_inv_rate = max(1, min_log_leaves - residual)
        log_leaves = residual + log_inv_rate
        lanes = 1 << fold
        element_bytes = SOURCE_ELEMENT_BYTES if level_index == 0 else EXTENSION_ELEMENT_BYTES
        opened_bytes = query_count * lanes * element_bytes
        frontier_nodes = max_compact_merkle_frontier_nodes(log_leaves, query_count)
        levels.append(
            LevelBytes(
                level=level_index,
                input_variables=current_variables,
                fold_variables=fold,
                residual_variables=residual,
                log_inv_rate=log_inv_rate,
                log_codeword_leaves=log_leaves,
                query_count=query_count,
                row_lanes=lanes,
                row_element_bytes=element_bytes,
                opened_row_bytes=opened_bytes,
                frontier_nodes=frontier_nodes,
                authentication_bytes=frontier_nodes * DIGEST_BYTES,
                encoded_oracle_bytes=(1 << log_leaves) * lanes * element_bytes,
                explicit_ood_samples=0,
                security=None,
            )
        )
        current_variables = residual
    return _assemble_plan(
        name="fixed-q319-rectangular-refold",
        log_relation_size=log_relation_size,
        active_symbols=active_symbols,
        folds=folds,
        levels=tuple(levels),
        complete_zero_knowledge=False,
        blocking_reason="fixed-q refold is oversized even before complete-ZK",
        charge_authentication=charge_authentication,
    )


def best_fixed_q_plan(
    *,
    charge_authentication: bool,
    log_relation_size: int = LOG_RELATION_SIZE,
    active_symbols: int = PAY1X2_MODELED_ACTIVE_SYMBOLS,
) -> WirePlan:
    return min(
        (
            fixed_q_plan(
                folds,
                log_relation_size=log_relation_size,
                active_symbols=active_symbols,
                charge_authentication=charge_authentication,
            )
            for folds in _ordered_fold_partitions(log_relation_size)
        ),
        key=lambda plan: plan.proof_bytes,
    )


def johnson_ligerito_core_candidate() -> WirePlan:
    """Concrete one-level hash-only core: k=5, rate=1/256, q=68.

    This is the smallest practical-rate candidate found by the executable
    screen that leaves useful ZK headroom while keeping the encoded L0 oracle
    to 64 MiB.  It is *not* complete-ZK; VEIL (or another proved wrapper) must
    earn that remaining byte budget with a measured SHAKE512/E384 artifact.
    """

    fold = 5
    residual = LOG_RELATION_SIZE - fold
    log_inv_rate = 8
    query_count = johnson_query_count(log_inv_rate)
    log_leaves = residual + log_inv_rate
    lanes = 1 << fold
    frontier_nodes = max_compact_merkle_frontier_nodes(log_leaves, query_count)
    security = johnson_security(
        log_inv_rate=log_inv_rate,
        log_message_columns=residual,
        log_interleaving=fold,
        level_variables=LOG_RELATION_SIZE,
        query_count=query_count,
        explicit_ood_samples=0,
    )
    level = LevelBytes(
        level=0,
        input_variables=LOG_RELATION_SIZE,
        fold_variables=fold,
        residual_variables=residual,
        log_inv_rate=log_inv_rate,
        log_codeword_leaves=log_leaves,
        query_count=query_count,
        row_lanes=lanes,
        row_element_bytes=SOURCE_ELEMENT_BYTES,
        opened_row_bytes=query_count * lanes * SOURCE_ELEMENT_BYTES,
        frontier_nodes=frontier_nodes,
        authentication_bytes=frontier_nodes * DIGEST_BYTES,
        encoded_oracle_bytes=(1 << log_leaves) * lanes * SOURCE_ELEMENT_BYTES,
        explicit_ood_samples=0,
        security=security,
    )
    return _assemble_plan(
        name="veil-target-mixed-field-ligerito-core",
        log_relation_size=LOG_RELATION_SIZE,
        active_symbols=PAY1X2_MODELED_ACTIVE_SYMBOLS,
        folds=(fold,),
        levels=(level,),
        complete_zero_knowledge=False,
        blocking_reason=(
            "the authenticated Johnson-Ligerito core fits, but Flock is non-ZK; "
            "the VEIL wrapper has no measured SHAKE256-512/GF(2^384) wire artifact"
        ),
        elide_terminal_checksum=True,
    )


def one_level_johnson_plan(
    *,
    log_relation_size: int,
    active_symbols: int,
    fold_variables: int,
    log_inv_rate: int,
) -> WirePlan:
    """Build one exact authenticated Johnson-Ligerito core screen."""

    if not 1 <= fold_variables <= log_relation_size:
        raise ValueError("invalid fold count")
    residual = log_relation_size - fold_variables
    query_count = johnson_query_count(log_inv_rate)
    log_leaves = residual + log_inv_rate
    if query_count > (1 << log_leaves):
        raise ValueError("codeword has fewer leaves than distinct queries")
    lanes = 1 << fold_variables
    frontier_nodes = max_compact_merkle_frontier_nodes(log_leaves, query_count)
    security = johnson_security(
        log_inv_rate=log_inv_rate,
        log_message_columns=residual,
        log_interleaving=fold_variables,
        level_variables=log_relation_size,
        query_count=query_count,
        explicit_ood_samples=0,
    )
    level = LevelBytes(
        level=0,
        input_variables=log_relation_size,
        fold_variables=fold_variables,
        residual_variables=residual,
        log_inv_rate=log_inv_rate,
        log_codeword_leaves=log_leaves,
        query_count=query_count,
        row_lanes=lanes,
        row_element_bytes=SOURCE_ELEMENT_BYTES,
        opened_row_bytes=query_count * lanes * SOURCE_ELEMENT_BYTES,
        frontier_nodes=frontier_nodes,
        authentication_bytes=frontier_nodes * DIGEST_BYTES,
        encoded_oracle_bytes=(1 << log_leaves) * lanes * SOURCE_ELEMENT_BYTES,
        explicit_ood_samples=0,
        security=security,
    )
    return _assemble_plan(
        name=f"one-level-johnson-ligerito-n{log_relation_size}",
        log_relation_size=log_relation_size,
        active_symbols=active_symbols,
        folds=(fold_variables,),
        levels=(level,),
        complete_zero_knowledge=False,
        blocking_reason=(
            "authenticated core only; production relation size is not frozen and "
            "the complete-ZK wrapper is absent"
        ),
        elide_terminal_checksum=True,
    )


def best_one_level_johnson_plan(
    *,
    log_relation_size: int,
    active_symbols: int,
    max_log_inv_rate: int = 16,
    max_encoded_oracle_bytes: Optional[int] = None,
) -> Optional[WirePlan]:
    candidates: list[WirePlan] = []
    for fold in range(1, log_relation_size + 1):
        for rate in range(1, max_log_inv_rate + 1):
            try:
                plan = one_level_johnson_plan(
                    log_relation_size=log_relation_size,
                    active_symbols=active_symbols,
                    fold_variables=fold,
                    log_inv_rate=rate,
                )
            except ValueError:
                continue
            level = plan.levels[0]
            if level.security is None or level.security.minimum_bits < STRICT_CLASSICAL_BITS:
                continue
            if (
                max_encoded_oracle_bytes is not None
                and level.encoded_oracle_bytes > max_encoded_oracle_bytes
            ):
                continue
            candidates.append(plan)
    return min(candidates, key=lambda plan: plan.proof_bytes) if candidates else None


def serialize_size_fixture(plan: WirePlan) -> bytes:
    """Serialize a canonical all-zero *size fixture*, never a valid proof."""

    if len(plan.levels) != 1:
        raise ValueError("the size fixture currently fixes the one-level candidate")
    level = plan.levels[0]
    profile = (
        b"Hegemon strict refold PCS v1|SHAKE256-512 framed-v1|"
        b"B128:x128+x7+x2+x+1:LE16|E384:Y3+Y+1:3xLE16|"
        b"layout:f[lane+2^k*column]:LSB-first-fold|"
        + f"n{plan.log_relation_size}|active{plan.active_symbols}|".encode()
        + f"k{level.fold_variables}|rate{1 << level.log_inv_rate}|".encode()
        + f"q{level.query_count}|eta1/256|M4-wide{M4_WIDE_RECEIVES}|".encode()
        + f"security{STRICT_CLASSICAL_BITS}".encode()
    )
    profile_id = hashlib.shake_256(profile).digest(32)
    header = struct.pack(
        ">8sHH32s4B4H2I",
        b"HGRFPCS1",
        2,
        0,  # flags: zero because this fixture is explicitly non-ZK
        profile_id,
        plan.log_relation_size,
        level.fold_variables,
        level.log_inv_rate,
        SOURCE_ELEMENT_BYTES,
        level.query_count,
        M4_WIDE_RECEIVES,
        1 << plan.terminal_variables,
        plan.sumcheck_messages,
        level.frontier_nodes,
        plan.active_symbols,
    )
    if len(header) != PROOF_HEADER_BYTES:
        raise AssertionError("canonical header size drift")
    fixture = b"".join(
        (
            header,
            bytes(plan.roots_bytes),
            bytes(plan.m4_wide_receive_bytes),
            bytes(plan.sumcheck_bytes),
            bytes(plan.ood_value_bytes),
            bytes(plan.terminal_bytes),
            bytes(plan.opened_row_bytes),
            bytes(plan.authentication_bytes),
        )
    )
    if len(fixture) != plan.proof_bytes:
        raise AssertionError("fixture byte formula disagrees with serializer")
    return fixture


def report() -> dict[str, object]:
    fixed_full = best_fixed_q_plan(charge_authentication=True)
    fixed_free_auth = best_fixed_q_plan(charge_authentication=False)
    candidate = johnson_ligerito_core_candidate()
    production_screens: dict[str, object] = {}
    for log_n in (15, 16):
        # Active counts are deliberately conservative full buckets until the
        # full-auth circuit compiler emits an independently checked count.
        active = 1 << log_n
        unconstrained = best_one_level_johnson_plan(
            log_relation_size=log_n,
            active_symbols=active,
        )
        disk_bounded = best_one_level_johnson_plan(
            log_relation_size=log_n,
            active_symbols=active,
            max_encoded_oracle_bytes=512 * 1024 * 1024,
        )
        production_screens[f"n{log_n}"] = {
            "active_symbols_assumption": active,
            "relation_stats_frozen": False,
            "best_rate_at_most_16": asdict(unconstrained) if unconstrained else None,
            "best_with_512_mib_oracle_cap": asdict(disk_bounded) if disk_bounded else None,
        }
    veil_reference_overhead = 892_725 - 765_180
    return {
        "claim_ceiling": (
            "wire/soundness model and size fixture only; no PCS implementation, "
            "complete-ZK theorem, QROM proof, or strict artifact"
        ),
        "caps": {
            "proof_bytes": PROOF_CAP_BYTES,
            "envelope_bytes": ENVELOPE_CAP_BYTES,
        },
        "fixed_q319": {
            "best_authenticated": asdict(fixed_full),
            "authentication_free_lower_bound": asdict(fixed_free_auth),
            "no_go": fixed_free_auth.proof_bytes > PROOF_CAP_BYTES,
            "no_go_margin_bytes": fixed_free_auth.proof_bytes - PROOF_CAP_BYTES,
        },
        "johnson_ligerito_core": asdict(candidate),
        "unfrozen_full_auth_screens": production_screens,
        "complete_zk_gate": {
            "remaining_budget_bytes": candidate.headroom_bytes,
            "veil_poc_reference_overhead_bytes": veil_reference_overhead,
            "reference_is_not_a_transferable_lower_bound": True,
            "strict_candidate_exists": False,
            "reason": candidate.blocking_reason,
        },
    }


def run_self_check() -> None:
    fixed_full = best_fixed_q_plan(charge_authentication=True)
    fixed_free_auth = best_fixed_q_plan(charge_authentication=False)
    candidate = johnson_ligerito_core_candidate()
    assert fixed_full.proof_bytes == 190_032
    assert fixed_free_auth.proof_bytes == 126_800
    assert fixed_free_auth.folds == (3, 1)
    assert fixed_free_auth.proof_bytes > PROOF_CAP_BYTES
    assert johnson_query_count(8) == 68
    assert candidate.proof_bytes == 112_784
    assert candidate.envelope_bytes == 112_796
    assert candidate.headroom_bytes == 11_284
    assert candidate.levels[0].frontier_nodes == 740
    assert candidate.levels[0].encoded_oracle_bytes == 64 * 1024 * 1024
    assert candidate.levels[0].security is not None
    assert candidate.levels[0].security.minimum_bits >= STRICT_CLASSICAL_BITS
    assert math.isclose(
        candidate.levels[0].security.mca_bits,
        330.4087954870661,
        rel_tol=0,
        abs_tol=1e-12,
    )
    assert len(serialize_size_fixture(candidate)) == candidate.proof_bytes
    assert not candidate.strict_admitted
    n15 = best_one_level_johnson_plan(
        log_relation_size=15,
        active_symbols=1 << 15,
    )
    n16 = best_one_level_johnson_plan(
        log_relation_size=16,
        active_symbols=1 << 16,
    )
    assert n15 is not None and n15.proof_bytes == 117_488
    assert n15.folds == (6,) and n15.levels[0].log_inv_rate == 16
    assert n15.levels[0].encoded_oracle_bytes == 32 * 1024**3
    assert n16 is not None and n16.proof_bytes == 144_496
    assert n16.folds == (6,) and n16.levels[0].log_inv_rate == 16
    assert n16.levels[0].encoded_oracle_bytes == 64 * 1024**3


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write-size-fixture", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.check:
        run_self_check()
    data = report()
    if args.write_size_fixture is not None:
        fixture = serialize_size_fixture(johnson_ligerito_core_candidate())
        args.write_size_fixture.write_bytes(fixture)
        data["size_fixture"] = {
            "path": str(args.write_size_fixture.resolve()),
            "bytes": len(fixture),
            "shake256_512": hashlib.shake_256(fixture).hexdigest(64),
            "valid_proof": False,
        }
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
