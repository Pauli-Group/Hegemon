"""Exact source-level wire terms for the Diamond/DP24 feasibility map.

This models declared serializer fields only. It does not model a proof that has
not been implemented and must not be used as frontier evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Iterable


def ceil_log2(value: int) -> int:
    if value <= 0:
        raise ValueError("value must be positive")
    return (value - 1).bit_length()


def query_count(security_bits: int, log_inv_rate: int) -> int:
    """DP24 query count for query-phase error at most 2^-security_bits."""

    if security_bits <= 0:
        raise ValueError("security_bits must be positive")
    if log_inv_rate <= 0:
        raise ValueError("log_inv_rate must be positive")
    rate = 2.0 ** (-log_inv_rate)
    per_query_error = 0.5 * (1.0 + rate)
    return math.ceil(security_bits / -math.log2(per_query_error))


def merkle_auth_bytes(
    tree_depth: int,
    n_queries: int,
    digest_bytes: int = 64,
    cap_height: int | None = None,
) -> int:
    """Pinned BinaryMerkleTreeScheme layer plus branch digest bytes."""

    if tree_depth < 0:
        raise ValueError("tree_depth must be nonnegative")
    if n_queries <= 0 or digest_bytes <= 0:
        raise ValueError("n_queries and digest_bytes must be positive")
    if cap_height is None:
        cap_height = min(ceil_log2(n_queries), tree_depth)
    if not 0 <= cap_height <= tree_depth:
        raise ValueError("cap_height must be within the tree")
    return ((tree_depth - cap_height) * n_queries + (1 << cap_height)) * digest_bytes


def salted_tree_opening_bytes(
    tree_depth: int,
    n_queries: int,
    leaf_field_elements: int,
    field_bytes: int = 32,
    digest_bytes: int = 64,
    salt_bytes: int = 32,
    cap_height: int | None = None,
) -> int:
    """Authentication, opened leaf values, and one BCS salt per opened leaf."""

    if leaf_field_elements <= 0 or field_bytes <= 0 or salt_bytes <= 0:
        raise ValueError("leaf and byte sizes must be positive")
    return merkle_auth_bytes(
        tree_depth, n_queries, digest_bytes, cap_height
    ) + n_queries * (leaf_field_elements * field_bytes + salt_bytes)


def ring_switch_standalone_bytes(
    packed_variables: int,
    extension_degree: int = 2,
    field_bytes: int = 32,
) -> int:
    """Generic DP24 Construction 3.1 messages outside the underlying PCS.

    The degree-two sumcheck sends two coefficients per packed variable; the
    verifier recovers the third from the running claim.
    """

    if packed_variables < 0:
        raise ValueError("packed_variables must be nonnegative")
    if extension_degree <= 0 or field_bytes <= 0:
        raise ValueError("degree and field_bytes must be positive")
    return field_bytes * (extension_degree + 2 * packed_variables + 1)


@dataclass(frozen=True)
class DiamondDelta:
    root: int
    clear: int
    blind_values: int
    authentication: int
    salts: int

    @property
    def total(self) -> int:
        return self.root + self.clear + self.blind_values + self.authentication + self.salts


def diamond_zk_delta(
    existing_tree_depths: Iterable[int],
    n_queries: int,
    fold_arity: int,
    field_bytes: int = 32,
    digest_bytes: int = 64,
    salt_bytes: int = 32,
) -> DiamondDelta:
    """Diamond ZK delta for a fixed unchanged BaseFold tree schedule.

    `existing_tree_depths[0]` is the initial tree. Every existing tree gains one
    depth level and a new blind initial tree is added at the enlarged initial
    depth. The comparison baseline is an unsalted non-ZK opening.
    """

    depths = tuple(existing_tree_depths)
    if not depths:
        raise ValueError("at least the initial tree depth is required")
    if fold_arity < 0:
        raise ValueError("fold_arity must be nonnegative")

    auth_existing = sum(
        merkle_auth_bytes(depth + 1, n_queries, digest_bytes)
        - merkle_auth_bytes(depth, n_queries, digest_bytes)
        for depth in depths
    )
    auth_blind = merkle_auth_bytes(depths[0] + 1, n_queries, digest_bytes)

    return DiamondDelta(
        root=digest_bytes,
        clear=2 * field_bytes,
        blind_values=n_queries * (1 << fold_arity) * field_bytes,
        authentication=auth_existing + auth_blind,
        salts=(len(depths) + 1) * n_queries * salt_bytes,
    )


def shared_input_two_branch_opening_bytes(
    tree_depth: int,
    queries_per_branch: int,
    leaf_field_elements: int,
    field_bytes: int = 32,
    digest_bytes: int = 64,
    salt_bytes: int = 32,
) -> int:
    """One input-tree opening over a serialized 2*q query union.

    This deliberately charges the full union and assumes no query collisions or
    deduplication. It does not model any challenge-dependent branch tree.
    """

    return salted_tree_opening_bytes(
        tree_depth=tree_depth,
        n_queries=2 * queries_per_branch,
        leaf_field_elements=leaf_field_elements,
        field_bytes=field_bytes,
        digest_bytes=digest_bytes,
        salt_bytes=salt_bytes,
    )


def n15_two_branch_wire_report() -> dict[str, int]:
    """Exact declared-wire skeleton for the paper-valid n15 / E256x2 case.

    `n15` means 15 variables over B128.  Degree-two packing leaves 14 E256
    variables.  We select R=3 and theta=2, which satisfies theta | 14 in the
    cited constructions.  The serializer is the pinned Merkle layout extended
    with one 32-byte BCS salt per queried leaf.  It intentionally repeats leaf
    values and paths for repeated indices, exactly as pinned `send_openings`
    does; the shared-input call merely concatenates two independently sampled
    160-index lists and sends their common layer once.

    This is a wire skeleton, not an implemented or security-admitted proof.
    """

    original_b128_variables = 15
    extension_log_degree = 1
    packed_e256_variables = original_b128_variables - extension_log_degree
    log_inv_rate = 3
    fold_arity = 2
    queries_per_branch = query_count(132, log_inv_rate)
    field_bytes = 32
    digest_bytes = 64
    salt_bytes = 32
    leaf_field_elements = 1 << fold_arity

    # Diamond runs DP24 setup on ell+1, so the initial evaluation domain has
    # log size ell+R+1.  Grouping a 2^theta fold coset into each leaf subtracts
    # theta from the binary Merkle depth.
    initial_tree_depth = (
        packed_e256_variables + log_inv_rate + 1 - fold_arity
    )
    later_tree_depths = tuple(
        initial_tree_depth - i
        for i in range(fold_arity, packed_e256_variables, fold_arity)
    )

    shared_input_authentication = merkle_auth_bytes(
        initial_tree_depth, 2 * queries_per_branch, digest_bytes
    )
    separate_input_authentication = 2 * merkle_auth_bytes(
        initial_tree_depth, queries_per_branch, digest_bytes
    )
    shared_input_values = (
        2 * queries_per_branch * leaf_field_elements * field_bytes
    )
    shared_input_salts = 2 * queries_per_branch * salt_bytes
    shared_input_total = (
        digest_bytes
        + shared_input_authentication
        + shared_input_values
        + shared_input_salts
    )
    separate_openings_shared_root_total = (
        digest_bytes
        + separate_input_authentication
        + shared_input_values
        + shared_input_salts
    )
    separate_commitments_total = (
        2 * digest_bytes
        + separate_input_authentication
        + shared_input_values
        + shared_input_salts
    )

    def tree_with_root(tree_depth: int, query_count_: int) -> int:
        return digest_bytes + salted_tree_opening_bytes(
            tree_depth=tree_depth,
            n_queries=query_count_,
            leaf_field_elements=leaf_field_elements,
            field_bytes=field_bytes,
            digest_bytes=digest_bytes,
            salt_bytes=salt_bytes,
        )

    branch_blind_tree = tree_with_root(initial_tree_depth, queries_per_branch)
    branch_later_trees = sum(
        tree_with_root(depth, queries_per_branch) for depth in later_tree_depths
    )

    # Per branch: two E256 elements for the DP24 tensor element s_hat, two
    # coefficients for each of 14 degree-two sumcheck rounds, one clear blind
    # evaluation, and Diamond's final (c0,c1).
    branch_clear_algebra = field_bytes * (
        2 + 2 * packed_e256_variables + 1 + 2
    )
    full_shared_wire_skeleton = shared_input_total + 2 * (
        branch_blind_tree + branch_later_trees + branch_clear_algebra
    )
    full_separate_openings_shared_root = separate_openings_shared_root_total + 2 * (
        branch_blind_tree + branch_later_trees + branch_clear_algebra
    )

    return {
        "original_b128_variables": original_b128_variables,
        "packed_e256_variables": packed_e256_variables,
        "log_inv_rate": log_inv_rate,
        "fold_arity": fold_arity,
        "queries_per_branch": queries_per_branch,
        "initial_tree_depth": initial_tree_depth,
        "later_tree_count_per_branch": len(later_tree_depths),
        "diamond_high_coefficients_per_branch": (
            queries_per_branch * leaf_field_elements
        ),
        "diamond_shared_input_high_coefficients": (
            2 * queries_per_branch * leaf_field_elements
        ),
        "shared_input_authentication_bytes": shared_input_authentication,
        "separate_input_authentication_bytes": separate_input_authentication,
        "input_authentication_savings_bytes": (
            separate_input_authentication - shared_input_authentication
        ),
        "shared_input_values_bytes": shared_input_values,
        "shared_input_salts_bytes": shared_input_salts,
        "shared_input_root_bytes": digest_bytes,
        "shared_input_total_bytes": shared_input_total,
        "separate_openings_shared_root_total_bytes": (
            separate_openings_shared_root_total
        ),
        "separate_commitments_total_bytes": separate_commitments_total,
        "branch_blind_tree_bytes": branch_blind_tree,
        "branch_later_trees_bytes": branch_later_trees,
        "branch_clear_algebra_bytes": branch_clear_algebra,
        "full_shared_wire_skeleton_bytes": full_shared_wire_skeleton,
        "full_separate_openings_shared_root_bytes": (
            full_separate_openings_shared_root
        ),
        "full_shared_savings_bytes": (
            full_separate_openings_shared_root - full_shared_wire_skeleton
        ),
    }


if __name__ == "__main__":
    for bits in (132, 264):
        print(f"bits={bits} rate_log=3 queries={query_count(bits, 3)}")
    print(
        "degree2_ring_switch_n14_bytes="
        f"{ring_switch_standalone_bytes(packed_variables=14)}"
    )
    report = n15_two_branch_wire_report()
    print(
        "n15_e256x2_shared_wire_skeleton_bytes="
        f"{report['full_shared_wire_skeleton_bytes']}"
    )
