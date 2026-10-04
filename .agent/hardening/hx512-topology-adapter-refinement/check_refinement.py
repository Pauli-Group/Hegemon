#!/usr/bin/env python3
"""Fail-closed HX512 topology-to-adapter refinement gate.

This checker is deliberately independent of the topology and adapter owners.  It pins the
frozen grammar/topology inputs, verifies the immutable K=1024 geometry, and refuses to issue a
refinement certificate until the adapter exposes enough public data for an external checker to
replay every topology cell, operation, dependency, source binding, and digest target.

The current expected result is ``qualified=false``.  Copying a topology digest into adapter
metadata is not refinement evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CONTRACT_PATH = HERE / "contract.json"
EVIDENCE_PATH = HERE / "refinement_evidence.json"
GRAMMAR_PATH = ROOT / "circuits/transaction/src/hx512_production_relation.rs"
TOPOLOGY_PATH = ROOT / "circuits/transaction/src/smallwood_hx512_topology.rs"
ADAPTER_PATH = ROOT / "circuits/transaction/src/smallwood_hx512_adapter.rs"
CARGO_PATH = ROOT / "circuits/transaction/Cargo.toml"
STABLE_SOURCE_PATH = ROOT / "protocol/kernel/src/stablecoin_source_v3.rs"
STABLE_TRANSITION_PATH = ROOT / "protocol/kernel/src/stablecoin_transition_v3.rs"


class RefinementError(RuntimeError):
    pass


LIVE_REPLAY_SCHEMA = "hegemon-hx512-public-iterator-replay-v1"


@dataclass(frozen=True)
class Sources:
    grammar: str
    topology: str
    adapter: str
    cargo: str
    grammar_bytes: bytes
    topology_bytes: bytes
    adapter_bytes: bytes
    cargo_bytes: bytes
    stable_source_bytes: bytes
    stable_transition_bytes: bytes


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha512(raw: bytes) -> str:
    return hashlib.sha512(raw).hexdigest()


def _stream_record_bytes(record: dict[str, Any]) -> bytes:
    raw = canonical_json(record)
    return len(raw).to_bytes(8, "big") + raw


def concrete_record_stream(
    records: Iterable[dict[str, Any]], *, key_field: str = "key"
) -> dict[str, Any]:
    """Commit to an ordered concrete record stream and detect duplicate keys."""

    digest = hashlib.sha512()
    count = 0
    duplicate_keys: list[Any] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise RefinementError("record stream contains a non-object")
        if key_field not in record:
            raise RefinementError(f"record stream omits `{key_field}`")
        serialized_key = json.dumps(record[key_field], sort_keys=True, separators=(",", ":"))
        if serialized_key in seen:
            duplicate_keys.append(record[key_field])
        seen.add(serialized_key)
        digest.update(_stream_record_bytes(record))
        count += 1
    return {
        "count": count,
        "duplicate_keys": duplicate_keys,
        "sha512": digest.hexdigest(),
    }


def compare_concrete_record_streams(
    kind: str,
    topology_records: Iterable[dict[str, Any]],
    adapter_records: Iterable[dict[str, Any]],
    expected_count: int,
) -> list[dict[str, str]]:
    """Compare concrete normalized records, not caller-supplied bijection booleans."""

    topology = concrete_record_stream(topology_records)
    adapter = concrete_record_stream(adapter_records)
    result: list[dict[str, str]] = []
    for side, stream in (("topology", topology), ("adapter", adapter)):
        if stream["count"] != expected_count:
            result.append(
                blocker(
                    "record_stream_count_mismatch",
                    f"{kind}/{side}: expected {expected_count}, got {stream['count']}",
                )
            )
        if stream["duplicate_keys"]:
            result.append(
                blocker(
                    "record_stream_duplicate",
                    f"{kind}/{side}: duplicate keys {stream['duplicate_keys'][:4]}",
                )
            )
    if topology["sha512"] != adapter["sha512"]:
        result.append(
            blocker(
                "record_stream_mismatch",
                f"{kind}: topology {topology['sha512']} != adapter {adapter['sha512']}",
            )
        )
    return result


def oracle_observation_stream_sha512(cases: list[dict[str, Any]]) -> str:
    """Bind every retained message/personalization/digest observation in canonical order."""

    digest = hashlib.sha512()
    ordered = sorted(
        cases,
        key=lambda case: (
            case.get("mode", -1),
            case.get("stable_direction", ""),
            case.get("secret_variant", -1),
        ),
    )
    for case in ordered:
        calls = case.get("calls")
        if not isinstance(calls, list):
            raise RefinementError("oracle case calls are not an array")
        for call in sorted(calls, key=lambda item: item.get("call_index", -1)):
            record = {
                "adapter_digest_hex": call.get("adapter_digest_hex"),
                "adapter_shape_digest_sha512": case.get("adapter_shape_digest_sha512"),
                "call_index": call.get("call_index"),
                "message_hex": call.get("message_hex"),
                "mode": case.get("mode"),
                "personalization_hex": call.get("personalization_hex"),
                "secret_fingerprint_sha512": case.get("secret_fingerprint_sha512"),
                "secret_variant": case.get("secret_variant"),
                "stable_direction": case.get("stable_direction"),
            }
            digest.update(_stream_record_bytes(record))
    return digest.hexdigest()


def load_contract() -> dict[str, Any]:
    raw = CONTRACT_PATH.read_bytes()
    value = json.loads(raw)
    if value.get("schema") != "hegemon-hx512-topology-adapter-refinement-v1":
        raise RefinementError("unsupported refinement contract schema")
    return value


def _safe_file(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise RefinementError(f"missing regular non-symlink source: {path}")
    resolved = path.resolve()
    if not resolved.is_relative_to(ROOT):
        raise RefinementError(f"source escapes repository: {path}")
    return path.read_bytes()


def load_sources() -> Sources:
    grammar = _safe_file(GRAMMAR_PATH)
    topology = _safe_file(TOPOLOGY_PATH)
    adapter = _safe_file(ADAPTER_PATH)
    cargo = _safe_file(CARGO_PATH)
    return Sources(
        grammar=grammar.decode(),
        topology=topology.decode(),
        adapter=adapter.decode(),
        cargo=cargo.decode(),
        grammar_bytes=grammar,
        topology_bytes=topology,
        adapter_bytes=adapter,
        cargo_bytes=cargo,
        stable_source_bytes=_safe_file(STABLE_SOURCE_PATH),
        stable_transition_bytes=_safe_file(STABLE_TRANSITION_PATH),
    )


def normalized(source: str) -> str:
    return " ".join(source.split())


def parse_integer_constant(source: str, name: str) -> int | None:
    match = re.search(
        rf"pub\s+const\s+{re.escape(name)}\s*:\s*[^=]+?=\s*([0-9][0-9_]*)\s*;",
        source,
    )
    if match is None:
        return None
    return int(match.group(1).replace("_", ""))


def blocker(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def topological_call_order(
    call_count: int, dependencies: dict[int, set[int]]
) -> list[int]:
    """Return a deterministic producer-before-consumer order.

    Call identifiers are canonical labels and are deliberately not treated as an execution
    order.  ``dependencies[consumer]`` contains producer call identifiers.  The helper is used
    by the independent tests to retain a concrete forward-edge and cycle oracle even if an
    implementation tries to regress to numeric call order.
    """

    if call_count < 0:
        raise RefinementError("negative call count")
    consumers: dict[int, set[int]] = {call: set() for call in range(call_count)}
    indegree = [0] * call_count
    for consumer, producers in dependencies.items():
        if consumer not in consumers:
            raise RefinementError(f"dependency consumer {consumer} is outside registry")
        for producer in producers:
            if producer not in consumers:
                raise RefinementError(f"dependency producer {producer} is outside registry")
            if producer == consumer:
                raise RefinementError(f"self-cycle at call {consumer}")
            if consumer not in consumers[producer]:
                consumers[producer].add(consumer)
                indegree[consumer] += 1

    ready = list(call for call, degree in enumerate(indegree) if degree == 0)
    heapq.heapify(ready)
    order: list[int] = []
    while ready:
        producer = heapq.heappop(ready)
        order.append(producer)
        for consumer in sorted(consumers[producer]):
            indegree[consumer] -= 1
            if indegree[consumer] == 0:
                heapq.heappush(ready, consumer)
    if len(order) != call_count:
        cyclic = [call for call, degree in enumerate(indegree) if degree != 0]
        raise RefinementError(f"cyclic call dependency graph: {cyclic}")
    return order


def audit_known_forward_dependencies(contract: dict[str, Any]) -> list[dict[str, str]]:
    raw = contract.get("known_forward_call_dependencies")
    if not isinstance(raw, dict):
        return [blocker("invalid_forward_dependency_contract", "dependency map is absent")]
    try:
        dependencies = {
            int(consumer): {int(producer) for producer in producers}
            for consumer, producers in raw.items()
        }
        order = topological_call_order(
            int(contract["geometry"]["hash_call_slots"]), dependencies
        )
    except (KeyError, TypeError, ValueError, RefinementError) as error:
        return [blocker("invalid_forward_dependency_contract", str(error))]

    positions = {call: index for index, call in enumerate(order)}
    for consumer, producers in dependencies.items():
        for producer in producers:
            if positions[producer] >= positions[consumer]:
                return [
                    blocker(
                        "invalid_forward_dependency_contract",
                        f"producer {producer} does not precede consumer {consumer}",
                    )
                ]
    if not any(producer > consumer for consumer, producers in dependencies.items() for producer in producers):
        return [
            blocker(
                "invalid_forward_dependency_contract",
                "fixture contains no forward canonical-call edge",
            )
        ]
    return []


def audit_test_evidence_contract(contract: dict[str, Any]) -> list[dict[str, str]]:
    expected = {
        "name": "hx512-refinement-evidence",
        "default_enabled": False,
        "production_release_forbidden": True,
        "deterministic_case_count": 30,
        "fixture_constructor": "hx512_refinement_fixtures",
        "verifier_context_accessor": "verifier_context",
    }
    result: list[dict[str, str]] = []
    if contract.get("test_evidence_feature") != expected:
        result.append(
            blocker(
                "invalid_test_evidence_contract",
                "deterministic evidence support must be off by default and release-forbidden",
            )
        )
    expected_mask_replay = {
        "fixture_constructor": "hx512_mode_mask_classification_fixtures",
        "mode_count": 5,
        "mask_count_per_mode": 16,
        "deterministic_case_count": 80,
        "accepted_case_count": 26,
        "rejected_case_count": 54,
        "grammar_owned": True,
        "live_adapter_replay_required": True,
        "static_table_sufficient": False,
    }
    if contract.get("authorization_mask_replay") != expected_mask_replay:
        result.append(
            blocker(
                "invalid_authorization_mask_replay_contract",
                "authorization replay must cover live grammar/adapter outcomes for all 80 mode-mask pairs",
            )
        )
    return result


def audit_test_evidence_source(
    contract: dict[str, Any], sources: Sources
) -> list[dict[str, str]]:
    """Verify that the deterministic replay seam is narrow and fail-closed.

    This is only a source-shape guard.  The future Rust replay must still construct and consume
    all 30 live fixtures.  In particular, finding the constructor name here is not evidence that
    any fixture or adapter assignment was evaluated.
    """

    result: list[dict[str, str]] = []
    feature = contract["test_evidence_feature"]
    feature_name = feature["name"]
    cargo = normalized(sources.cargo)
    grammar = normalized(sources.grammar)

    _require_fragment(
        result,
        sources.cargo,
        f"{feature_name} = []",
        "missing_test_evidence_feature",
    )
    if normalized(f'default = ["{feature_name}"]') in cargo:
        result.append(
            blocker(
                "test_evidence_feature_default_enabled",
                f"`{feature_name}` must not be a default feature",
            )
        )
    _require_fragment(
        result,
        sources.cargo,
        "default = []",
        "test_evidence_feature_default_enabled",
    )
    for fragment in (
        f'#[cfg(all(feature = "{feature_name}", not(debug_assertions)))]',
        "compile_error!",
        f'#[cfg(feature = "{feature_name}")] pub fn {feature["fixture_constructor"]}',
        f'pub fn {feature["verifier_context_accessor"]}(&self)',
        "ensure_hx512_refinement_evidence_not_production",
        "RefinementEvidenceFeatureEnabled",
        f'#[cfg(any(test, feature = "{feature_name}"))] pub(crate) mod tests',
    ):
        _require_fragment(
            result,
            sources.grammar,
            fragment,
            "missing_test_evidence_source_guard",
        )
    mask_constructor = contract["authorization_mask_replay"]["fixture_constructor"]
    _require_fragment(
        result,
        sources.grammar,
        f'#[cfg(feature = "{feature_name}")] pub fn {mask_constructor}',
        "missing_authorization_mask_replay_api",
    )
    if "HX512_REFINEMENT_FIXTURE_COUNT: usize = 5 * 3 * 2" not in grammar:
        result.append(
            blocker(
                "missing_test_evidence_source_guard",
                "grammar does not freeze the 30-case fixture cardinality",
            )
        )
    return result


def audit_source_pins(contract: dict[str, Any], sources: Sources) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    frozen = contract["frozen_sources"]
    observed = {
        "circuits/transaction/src/hx512_production_relation.rs": sha512(
            sources.grammar_bytes
        ),
        "circuits/transaction/src/smallwood_hx512_topology.rs": sha512(
            sources.topology_bytes
        ),
        "circuits/transaction/Cargo.toml": sha512(sources.cargo_bytes),
    }
    for path, digest in observed.items():
        expected = frozen[path]["sha512"]
        if digest != expected:
            result.append(
                blocker("frozen_source_drift", f"{path}: expected {expected}, got {digest}")
            )
    grammar_pin = frozen["circuits/transaction/src/hx512_production_relation.rs"]
    prefix_bytes = grammar_pin.get("production_prefix_bytes")
    if not isinstance(prefix_bytes, int) or prefix_bytes < 0:
        result.append(blocker("invalid_grammar_region_pin", "prefix byte boundary is absent"))
    else:
        marker = grammar_pin.get("production_suffix_marker")
        if not isinstance(marker, str) or not marker:
            result.append(
                blocker("invalid_grammar_region_pin", "suffix marker is absent")
            )
            marker_bytes = b""
        else:
            marker_bytes = marker.encode()
        boundary = sources.grammar_bytes.find(marker_bytes) if marker_bytes else -1
        if boundary != prefix_bytes:
            result.append(
                blocker(
                    "grammar_region_boundary_drift",
                    f"expected test-support byte {prefix_bytes}, got {boundary}",
                )
            )
        prefix_digest = sha512(sources.grammar_bytes[:prefix_bytes])
        suffix_digest = sha512(sources.grammar_bytes[prefix_bytes:])
        if prefix_digest != grammar_pin.get("production_prefix_sha512"):
            result.append(
                blocker(
                    "grammar_production_prefix_drift",
                    f"expected {grammar_pin.get('production_prefix_sha512')}, got {prefix_digest}",
                )
            )
        if suffix_digest != grammar_pin.get("test_suffix_sha512"):
            result.append(
                blocker(
                    "grammar_test_suffix_drift",
                    f"expected {grammar_pin.get('test_suffix_sha512')}, got {suffix_digest}",
                )
            )
    stable_observed = {
        "protocol/kernel/src/stablecoin_source_v3.rs": sha256(sources.stable_source_bytes),
        "protocol/kernel/src/stablecoin_transition_v3.rs": sha256(
            sources.stable_transition_bytes
        ),
    }
    for path, digest in stable_observed.items():
        expected = contract["stable_source_sha256"][path]
        if digest != expected:
            result.append(
                blocker("stable_source_drift", f"{path}: expected {expected}, got {digest}")
            )
    return result


def _require_fragment(
    result: list[dict[str, str]], source: str, fragment: str, code: str
) -> None:
    if normalized(fragment) not in normalized(source):
        result.append(blocker(code, f"missing source contract: {fragment}"))


def audit_topology_api(contract: dict[str, Any], source: str) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    geometry = contract["geometry"]
    constants = {
        "HX512_RADIX4_PACKING_FACTOR": geometry["packing_factor"],
        "HX512_FROZEN_HASH_TOPOLOGY_ROW_COUNT": geometry["hash_base_rows"],
        "HX512_FROZEN_HASH_TOPOLOGY_CELL_COUNT": geometry["hash_base_cells"],
        "HX512_FROZEN_HASH_TOPOLOGY_EXPLICIT_PADDING_CELLS": geometry[
            "explicit_padding_cells"
        ],
        "HX512_FROZEN_HASH_TOPOLOGY_OPERATION_COUNT": geometry["operation_count"],
    }
    for name, expected in constants.items():
        actual = parse_integer_constant(source, name)
        if actual != expected:
            result.append(
                blocker("topology_geometry_mismatch", f"{name}: expected {expected}, got {actual}")
            )
    for fragment in (
        "pub fn typed_call_registry_from_relation",
        "pub fn compile_hx512_radix4_topology",
        "pub struct OperationRecord",
        "pub fn dependencies(&self)",
        "pub const fn addition_carry_output(&self)",
        "pub const fn addition_final_carry_output(&self)",
        "pub fn compiled_message_digit_binding",
        "pub fn public_target_cell_binding",
        "pub fn row_zero_padding_cells",
        "for call_id in topological_call_order(registry)?",
        "audit_earlier_consumers(self)?;",
    ):
        _require_fragment(result, source, fragment, "missing_topology_api")
    return result


def audit_adapter_surface(contract: dict[str, Any], source: str) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    geometry = contract["geometry"]
    packing = parse_integer_constant(source, "HX512_ADAPTER_PACKING_FACTOR")
    if packing is None and normalized(
        "pub const HX512_ADAPTER_PACKING_FACTOR: usize = HX512_RADIX4_PACKING_FACTOR as usize;"
    ) in normalized(source):
        packing = geometry["packing_factor"]
    if packing != geometry["packing_factor"]:
        result.append(
            blocker(
                "adapter_packing_factor",
                f"expected K={geometry['packing_factor']}, got {packing}",
            )
        )
    degree = parse_integer_constant(source, "HX512_ADAPTER_MAX_DEGREE")
    if degree != geometry["maximum_degree"]:
        result.append(
            blocker(
                "adapter_maximum_degree",
                f"expected degree {geometry['maximum_degree']}, got {degree}",
            )
        )

    compact = normalized(source)
    prior_index_assumption = (
        normalized("for call in &registry.calls") in compact
        and normalized("call.index != per_call_mode_digests.len()") in compact
    )
    if prior_index_assumption:
        result.append(
            blocker(
                "adapter_prior_index_assumption",
                "a retained compiler path treats canonical call IDs as execution order; calls 4/5 depend on later IDs",
            )
        )
    if "topology.operations" not in source:
        result.append(
            blocker(
                "missing_operation_stream_consumption",
                "adapter never iterates CompiledHx512Topology.operations",
            )
        )
    if ".dependencies()" not in source:
        result.append(
            blocker(
                "missing_dependency_stream_consumption",
                "adapter never consumes OperationRecord::dependencies()",
            )
        )
    if "compiled_message_digit_binding" not in source:
        result.append(
            blocker(
                "missing_source_binding_consumption",
                "adapter does not consume topology message/source cell bindings",
            )
        )
    if "public_target_cell_binding" not in source:
        result.append(
            blocker(
                "missing_digest_target_consumption",
                "adapter does not consume topology public digest-target cells",
            )
        )
    if "row_zero_padding_cells" not in source:
        result.append(
            blocker(
                "missing_zero_padding_consumption",
                "adapter does not consume explicit topology row-zero padding cells",
            )
        )

    capability_fragments = {
        "topology_refinement_certificate": ("pub fn topology_refinement_certificate",),
        "topology_operation_assignments": (
            "pub operations: Vec<Hx512OperationRefinementRecord>",
        ),
        "topology_cell_assignments": ("pub fn cells(",),
        "topology_dependency_assignments": ("pub dependencies: Vec<TopologyValueRef>",),
        "topology_source_bindings": (
            "pub messages: Vec<Hx512MessageRefinementRecord>",
            "pub sources: Vec<Hx512SourceRefinementRecord>",
        ),
        "topology_digest_export_bindings": (
            "pub digest_exports: Vec<Hx512DigestExportRefinementRecord>",
            "pub struct Hx512DigestExportDigitRefinementRecord",
        ),
        "topology_digest_target_bindings": (
            "pub public_targets: Vec<Hx512PublicTargetRefinementRecord>",
        ),
        "topology_zero_padding_assignments": ("pub zero_padding_cells: Vec<u32>",),
        "topology_nonhash_row_range": (
            "pub nonhash_first_row:",
            "pub nonhash_end_row:",
            "pub nonhash_ranges: Vec<Hx512NonhashRangeRefinementRecord>",
        ),
        "topology_constant_provenance": (
            "pub constant_provenance:",
            "pub struct Hx512ConstantRefinementRecord",
            "pub constant_wires: Vec<Hx512ConstantWireRefinementRecord>",
        ),
        "topology_identity_templates": (
            "pub identity_templates: Vec<Hx512IdentityTemplateRefinementRecord>",
            "pub polynomial: Hx512PolynomialTemplate",
        ),
        "topology_logical_identities": (
            "pub fn logical_identity(",
            "pub fn logical_identities(",
        ),
        "topology_linear_identities": (
            "pub fn semantic_linear_identity(",
            "pub fn semantic_linear_identities(",
            "pub semantic_linear_identities: Vec<Hx512SemanticLinearRefinementRecord>",
        ),
        "topology_public_bit_bindings": (
            "pub public_bit_bindings: Vec<Hx512PublicBitBinding>",
        ),
        "topology_packed_row_ownership": (
            "pub packed_row_ownership: Vec<Hx512PackedRowOwnershipRecord>",
            "pub struct Hx512PackedRowOwnershipRecord",
        ),
        "topology_csr_constraints": (
            "pub fn csr_constraint_refinements(",
            "pub struct Hx512CsrConstraintRefinementRecord",
        ),
        "topology_constraint_partitions": (
            "pub enum Hx512ConstraintPartition",
            "TopologyHash",
            "NonhashPrefix",
            "NonhashAuthorizationAndStable",
        ),
    }
    compact_source = normalized(source)
    for capability in contract["required_public_capabilities"]:
        fragments = capability_fragments.get(
            capability,
            (f"pub fn {capability}", f"pub const fn {capability}"),
        )
        # Multi-part capabilities deliberately require every listed public surface.  Other
        # capabilities accept any equivalent public spelling listed above.
        require_all = capability in {
            "topology_source_bindings",
            "topology_digest_export_bindings",
            "topology_identity_templates",
            "topology_packed_row_ownership",
            "topology_csr_constraints",
            "topology_constraint_partitions",
        }
        found = (
            all(normalized(fragment) in compact_source for fragment in fragments)
            if require_all
            else any(normalized(fragment) in compact_source for fragment in fragments)
        )
        if not found:
            result.append(
                blocker("missing_public_refinement_api", f"missing public API `{capability}`")
            )

    if "pub public_targets: Vec<Hx512PublicTargetRefinementRecord>" in source and not re.search(
        r"\.public_targets\s*\.push\s*\(", source
    ):
        result.append(
            blocker(
                "missing_public_target_record_emission",
                "certificate declares public-target records but never emits one",
            )
        )
    if (
        "pub digest_sha512: [u8; 64]" in source
        and "pub fn logical_identity(" not in source
        and "pub fn logical_identities(" not in source
    ):
        result.append(
            blocker(
                "digest_only_identity_metadata",
                "template digests/emission ranges do not expose polynomial terms and operand wires",
            )
        )
    if "pub nonhash_first_wire:" in source and "pub nonhash_first_row:" not in source:
        result.append(
            blocker(
                "missing_nonhash_row_partition",
                "certificate exposes a wire boundary but not an explicit disjoint row range",
            )
        )
    if "pub protocol_constant_wires:" in source and "Hx512ConstantRefinementRecord" not in source:
        result.append(
            blocker(
                "incomplete_constant_provenance",
                "allocated digit constants do not cover constants folded into linear targets",
            )
        )
    for fragment in (
        '#[cfg(feature = "hx512-refinement-evidence")] let topology_refinement = Some',
        '#[cfg(not(feature = "hx512-refinement-evidence"))] let topology_refinement = None',
        "// Debug refinement metadata is never accepted from or retained by a verifier. topology_refinement: None",
    ):
        _require_fragment(
            result,
            source,
            fragment,
            "refinement_metadata_not_feature_gated",
        )
    identity_group = re.search(r"struct\s+Hx512IdentityGroup\s*\{(?P<body>.*?)\n\}", source, re.S)
    coalesces_by_family_and_template = normalized(
        "group.family == family && &group.template == polynomial"
    ) in compact_source
    if (
        identity_group is not None
        and "partition" not in identity_group.group("body")
        and coalesces_by_family_and_template
    ):
        result.append(
            blocker(
                "mixed_hash_nonhash_identity_groups",
                "identity groups lack an origin tag, so hash/non-hash identities can share occurrence rows",
            )
        )

    copied_only = all(
        fragment in source
        for fragment in (
            "builder.audited_topology_rows = topology.geometry.direct_base_rows",
            "builder.audited_topology_cells = topology.geometry.direct_base_cells",
            "builder.audited_topology_digest_sha512 = topology.shape_digest_sha512",
        )
    )
    if copied_only and "topology.operations" not in source:
        result.append(
            blocker(
                "metadata_is_not_refinement",
                "adapter copies topology geometry/digest but exposes no operation/cell lowering",
            )
        )
    return result


def _is_sha512_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 128
        and all(character in "0123456789abcdef" for character in value)
    )


def audit_authorization_mask_live_replay(
    contract: dict[str, Any], replay: dict[str, Any]
) -> list[dict[str, str]]:
    """Check live grammar/adapter outcomes for every authorization mode and mask.

    The records are accepted only as part of the in-process Rust replay.  They are never loaded
    from retained caller JSON, so this function does not turn outcome booleans into authority.
    """

    result: list[dict[str, str]] = []
    mask_contract = contract["authorization_mask_replay"]
    cases = replay.get("authorization_mask_cases")
    if not isinstance(cases, list):
        return [
            blocker(
                "invalid_live_authorization_mask_replay",
                "live grammar/adapter mode-mask records are absent",
            )
        ]

    expected_keys = {
        (mode, mask)
        for mode in range(mask_contract["mode_count"])
        for mask in range(mask_contract["mask_count_per_mode"])
    }
    observed_keys: set[tuple[int, int]] = set()
    accepted = 0
    rejected = 0
    stream = hashlib.sha512()
    for case in sorted(cases, key=lambda item: (item.get("mode", -1), item.get("mask", -1))):
        if not isinstance(case, dict):
            result.append(
                blocker("invalid_live_authorization_mask_replay", "case is not an object")
            )
            continue
        key = (case.get("mode"), case.get("mask"))
        if not isinstance(key[0], int) or not isinstance(key[1], int):
            result.append(
                blocker("invalid_live_authorization_mask_replay", f"invalid case key {key}")
            )
            continue
        if key in observed_keys:
            result.append(
                blocker("invalid_live_authorization_mask_replay", f"duplicate case {key}")
            )
        observed_keys.add(key)
        grammar_result = case.get("grammar_result")
        adapter_result = case.get("adapter_result")
        if grammar_result not in {"accept", "reject"} or adapter_result not in {
            "accept",
            "reject",
        }:
            result.append(
                blocker(
                    "invalid_live_authorization_mask_replay",
                    f"case {key} lacks live result discriminants",
                )
            )
            continue
        if grammar_result != adapter_result:
            result.append(
                blocker(
                    "authorization_mask_refinement_mismatch",
                    f"grammar {grammar_result} != adapter {adapter_result} at {key}",
                )
            )
        if grammar_result == "accept":
            accepted += 1
            if case.get("adapter_zero_residuals") is not True:
                result.append(
                    blocker(
                        "authorization_mask_refinement_mismatch",
                        f"accepted adapter assignment has a nonzero residual at {key}",
                    )
                )
        else:
            rejected += 1
            if not isinstance(case.get("grammar_error_class"), str) or not isinstance(
                case.get("adapter_error_class"), str
            ):
                result.append(
                    blocker(
                        "invalid_live_authorization_mask_replay",
                        f"rejected case {key} lacks observed error classes",
                    )
                )
        stream.update(_stream_record_bytes(case))

    if observed_keys != expected_keys or len(cases) != mask_contract["deterministic_case_count"]:
        result.append(
            blocker(
                "invalid_live_authorization_mask_replay",
                f"expected all {len(expected_keys)} mode-mask pairs, got {len(observed_keys)}",
            )
        )
    if accepted != mask_contract["accepted_case_count"] or rejected != mask_contract[
        "rejected_case_count"
    ]:
        result.append(
            blocker(
                "authorization_mask_classification_count_mismatch",
                f"expected {mask_contract['accepted_case_count']}/{mask_contract['rejected_case_count']} accept/reject, got {accepted}/{rejected}",
            )
        )
    if replay.get("authorization_mask_stream_sha512") != stream.hexdigest():
        result.append(
            blocker(
                "invalid_live_authorization_mask_replay",
                "mode-mask record stream commitment mismatch",
            )
        )
    return result


def audit_live_public_iterator_replay(
    contract: dict[str, Any],
    evidence: dict[str, Any],
    replay: dict[str, Any],
    *,
    adapter_sha512: str,
) -> list[dict[str, str]]:
    """Validate output produced in-process by the independent Rust iterator replay.

    This function is not a loader for an arbitrary replay JSON file.  The command-line gate must
    pass a value returned by the owned Rust harness after that process directly enumerates the
    live topology and adapter public iterators.  Until that harness exists, the caller passes
    ``None`` and qualification is impossible.
    """

    result: list[dict[str, str]] = []
    geometry = contract["geometry"]
    if replay.get("schema") != LIVE_REPLAY_SCHEMA:
        result.append(blocker("invalid_live_replay", "unsupported live replay schema"))
    if replay.get("adapter_sha512") != adapter_sha512:
        result.append(blocker("invalid_live_replay", "adapter source hash mismatch"))
    for name, expected in (
        (
            "grammar_sha512",
            contract["frozen_sources"][
                "circuits/transaction/src/hx512_production_relation.rs"
            ]["sha512"],
        ),
        (
            "topology_sha512",
            contract["frozen_sources"][
                "circuits/transaction/src/smallwood_hx512_topology.rs"
            ]["sha512"],
        ),
        ("packing_factor", geometry["packing_factor"]),
        ("maximum_degree", geometry["maximum_degree"]),
        ("auxiliary_words", geometry["auxiliary_words"]),
        ("hash_base_rows", geometry["hash_base_rows"]),
        ("hash_base_cells", geometry["hash_base_cells"]),
        ("operation_count", geometry["operation_count"]),
        ("nonzero_operation_constraint_set_count", geometry["operation_count"]),
        ("operation_witness_assignment_count", geometry["operation_count"]),
        ("cell_witness_assignment_count", geometry["hash_base_cells"]),
        ("private_constant_count", 0),
        ("extra_topology_identity_count", 0),
        ("unmapped_dependency_count", 0),
        ("unconsumed_cell_count", 0),
        ("duplicate_cell_count", 0),
        ("duplicate_operation_count", 0),
        ("operation_with_empty_identity_set_count", 0),
        ("operation_identity_residual_nonzero_count", 0),
        ("logical_identity_residual_nonzero_count", 0),
        ("semantic_linear_residual_nonzero_count", 0),
        ("csr_residual_nonzero_count", 0),
        ("unclassified_topology_identity_count", 0),
        ("duplicate_topology_identity_classification_count", 0),
        ("unclassified_topology_linear_identity_count", 0),
        ("duplicate_topology_linear_identity_classification_count", 0),
        ("topology_identity_in_nonhash_partition_count", 0),
        ("nonhash_identity_in_topology_partition_count", 0),
    ):
        if replay.get(name) != expected:
            result.append(
                blocker(
                    "invalid_live_replay",
                    f"{name}: expected {expected}, got {replay.get(name)}",
                )
            )

    streams = replay.get("streams")
    expected_stream_counts: dict[str, int | None] = {
        "operation_mapping": geometry["operation_count"],
        "cell_assignment": geometry["hash_base_cells"],
        "zero_padding": geometry["explicit_padding_cells"],
        "dependency_mapping": None,
        "message_binding": None,
        "source_binding": None,
        "digest_target_binding": None,
    }
    if not isinstance(streams, dict):
        result.append(blocker("invalid_live_replay", "streams are absent"))
    else:
        for kind, exact_count in expected_stream_counts.items():
            stream = streams.get(kind)
            if not isinstance(stream, dict):
                result.append(blocker("invalid_live_replay", f"missing stream `{kind}`"))
                continue
            topology_count = stream.get("topology_count")
            adapter_count = stream.get("adapter_count")
            if exact_count is not None and (
                topology_count != exact_count or adapter_count != exact_count
            ):
                result.append(
                    blocker(
                        "invalid_live_replay",
                        f"{kind} count expected {exact_count}, got {topology_count}/{adapter_count}",
                    )
                )
            if exact_count is None and (
                not isinstance(topology_count, int)
                or topology_count <= 0
                or adapter_count != topology_count
            ):
                result.append(
                    blocker(
                        "invalid_live_replay",
                        f"{kind} must contain equal nonzero topology/adapter counts",
                    )
                )
            topology_root = stream.get("topology_sha512")
            adapter_root = stream.get("adapter_sha512")
            if (
                not _is_sha512_hex(topology_root)
                or not _is_sha512_hex(adapter_root)
                or topology_root != adapter_root
            ):
                result.append(
                    blocker("invalid_live_replay", f"{kind} stream commitments differ")
                )
            for count_name in (
                "topology_duplicate_key_count",
                "adapter_duplicate_key_count",
                "unmapped_count",
                "unconsumed_count",
            ):
                if stream.get(count_name) != 0:
                    result.append(
                        blocker(
                            "invalid_live_replay",
                            f"{kind}.{count_name} must be zero",
                        )
                    )

    adapter_streams = replay.get("adapter_streams")
    required_adapter_streams = (
        "operation_identity_sets",
        "digest_export_bindings",
        "logical_identity_classification",
        "semantic_linear_identity_classification",
        "constant_provenance",
        "packed_row_ownership",
        "csr_constraints",
    )
    if not isinstance(adapter_streams, dict):
        result.append(blocker("invalid_live_replay", "adapter streams are absent"))
    else:
        for kind in required_adapter_streams:
            stream = adapter_streams.get(kind)
            if not isinstance(stream, dict):
                result.append(blocker("invalid_live_replay", f"missing adapter stream `{kind}`"))
                continue
            count = stream.get("count")
            if not isinstance(count, int) or count <= 0:
                result.append(
                    blocker("invalid_live_replay", f"{kind} must contain concrete records")
                )
            if not _is_sha512_hex(stream.get("sha512")):
                result.append(blocker("invalid_live_replay", f"{kind} has no stream commitment"))
            for count_name in (
                "duplicate_key_count",
                "unmapped_count",
                "unconsumed_count",
            ):
                if stream.get(count_name) != 0:
                    result.append(
                        blocker(
                            "invalid_live_replay",
                            f"{kind}.{count_name} must be zero",
                        )
                    )

        operation_identity_stream = adapter_streams.get("operation_identity_sets")
        if isinstance(operation_identity_stream, dict) and operation_identity_stream.get(
            "count"
        ) != geometry["operation_count"]:
            result.append(
                blocker(
                    "invalid_live_replay",
                    "operation identity-set stream is not one record per topology operation",
                )
            )

    order = replay.get("execution_call_order")
    if not isinstance(order, list) or len(order) != geometry["hash_call_slots"] or set(
        order
    ) != set(range(geometry["hash_call_slots"])):
        result.append(blocker("invalid_live_replay", "execution call order is not a permutation"))
    else:
        positions = {call: index for index, call in enumerate(order)}
        for consumer, producers in contract["known_forward_call_dependencies"].items():
            consumer_id = int(consumer)
            for producer in producers:
                if positions[producer] >= positions[consumer_id]:
                    result.append(
                        blocker(
                            "invalid_live_replay",
                            f"producer {producer} executes after consumer {consumer_id}",
                        )
                    )

    nonhash = replay.get("nonhash_row_range")
    if (
        not isinstance(nonhash, dict)
        or not isinstance(nonhash.get("start"), int)
        or not isinstance(nonhash.get("end"), int)
        or nonhash["start"] < geometry["hash_base_rows"]
        or nonhash["end"] <= nonhash["start"]
    ):
        result.append(blocker("invalid_live_replay", "non-hash row range is absent or overlaps"))

    cases = evidence.get("rfc_oracle_cases")
    if isinstance(cases, list):
        observed_oracle_root = oracle_observation_stream_sha512(cases)
        if replay.get("oracle_observation_stream_sha512") != observed_oracle_root:
            result.append(
                blocker(
                    "invalid_live_replay",
                    "retained RFC observations are not bound to the live iterator replay",
                )
            )
    if replay.get("same_shape_for_secret_variants") is not True:
        result.append(blocker("invalid_live_replay", "live shapes vary with secret assignments"))
    result.extend(audit_authorization_mask_live_replay(contract, replay))
    return result


def audit_evidence(
    contract: dict[str, Any],
    evidence_path: Path = EVIDENCE_PATH,
    *,
    live_replay: dict[str, Any] | None = None,
    adapter_sha512: str | None = None,
) -> list[dict[str, str]]:
    if not evidence_path.is_file():
        return [
            blocker(
                "missing_refinement_evidence",
                "refinement_evidence.json has not been emitted from the public adapter API",
            ),
            blocker(
                "independent_public_iterator_replay_unavailable",
                "retained JSON cannot substitute for live public operation/cell iterator replay",
            ),
        ]
    if evidence_path.is_symlink():
        return [blocker("invalid_refinement_evidence", "evidence must not be a symlink")]
    raw = evidence_path.read_bytes()
    try:
        evidence = json.loads(raw)
    except json.JSONDecodeError as error:
        return [blocker("invalid_refinement_evidence", str(error))]
    if canonical_json(evidence) != raw:
        return [blocker("invalid_refinement_evidence", "evidence is not canonical JSON")]

    result: list[dict[str, str]] = []
    geometry = contract["geometry"]
    expected_scalars = {
        "packing_factor": geometry["packing_factor"],
        "hash_base_rows": geometry["hash_base_rows"],
        "hash_base_cells": geometry["hash_base_cells"],
        "operation_count": geometry["operation_count"],
        "auxiliary_words": geometry["auxiliary_words"],
    }
    for field, expected in expected_scalars.items():
        actual = evidence.get(field)
        if actual != expected:
            result.append(
                blocker("evidence_mismatch", f"{field}: expected {expected}, got {actual}")
            )
    if evidence.get("grammar_sha512") != contract["frozen_sources"][
        "circuits/transaction/src/hx512_production_relation.rs"
    ]["sha512"]:
        result.append(blocker("evidence_mismatch", "grammar SHA-512 is not frozen value"))
    if evidence.get("topology_sha512") != contract["frozen_sources"][
        "circuits/transaction/src/smallwood_hx512_topology.rs"
    ]["sha512"]:
        result.append(blocker("evidence_mismatch", "topology SHA-512 is not frozen value"))
    if evidence.get("test_identity_shape_digest_sha512") != contract[
        "test_identity_shape_digest_sha512"
    ]:
        result.append(blocker("evidence_mismatch", "test-identity shape digest mismatch"))

    cases = evidence.get("rfc_oracle_cases")
    expected_case_keys = {
        (mode, direction, secret_variant)
        for mode in range(5)
        for direction in ("disabled", "mint", "burn")
        for secret_variant in (0, 1)
    }
    observed_case_keys: set[tuple[int, str, int]] = set()
    observed_shape_digests: set[str] = set()
    secret_fingerprints: dict[tuple[int, str], set[str]] = {}
    if not isinstance(cases, list):
        result.append(blocker("evidence_mismatch", "rfc_oracle_cases is not an array"))
    else:
        for case in cases:
            if not isinstance(case, dict):
                result.append(blocker("evidence_mismatch", "oracle case is not an object"))
                continue
            key = (case.get("mode"), case.get("stable_direction"), case.get("secret_variant"))
            if key in observed_case_keys:
                result.append(blocker("evidence_mismatch", f"duplicate oracle case {key}"))
            observed_case_keys.add(key)  # type: ignore[arg-type]
            shape_digest = case.get("adapter_shape_digest_sha512")
            if not isinstance(shape_digest, str) or len(shape_digest) != 128:
                result.append(blocker("evidence_mismatch", f"invalid shape digest at {key}"))
            else:
                observed_shape_digests.add(shape_digest)
            fingerprint = case.get("secret_fingerprint_sha512")
            if not isinstance(fingerprint, str) or len(fingerprint) != 128:
                result.append(blocker("evidence_mismatch", f"invalid secret fingerprint at {key}"))
            elif isinstance(key[0], int) and isinstance(key[1], str):
                secret_fingerprints.setdefault((key[0], key[1]), set()).add(fingerprint)
            calls = case.get("calls")
            if case.get("call_count") != geometry["hash_call_slots"] or not isinstance(
                calls, list
            ) or len(calls) != geometry["hash_call_slots"]:
                result.append(blocker("evidence_mismatch", f"oracle call count mismatch at {key}"))
                continue
            observed_call_indices: set[int] = set()
            rfc_parity = True
            for call in calls:
                if not isinstance(call, dict):
                    rfc_parity = False
                    continue
                try:
                    call_index = int(call["call_index"])
                    message = bytes.fromhex(call["message_hex"])
                    personalization = bytes.fromhex(call["personalization_hex"])
                    adapter_digest = bytes.fromhex(call["adapter_digest_hex"])
                except (KeyError, TypeError, ValueError):
                    rfc_parity = False
                    continue
                if call_index in observed_call_indices or not 0 <= call_index < geometry[
                    "hash_call_slots"
                ]:
                    rfc_parity = False
                observed_call_indices.add(call_index)
                if len(personalization) != 16 or len(adapter_digest) != 64:
                    rfc_parity = False
                    continue
                expected_digest = hashlib.blake2b(
                    message, digest_size=64, person=personalization
                ).digest()
                if adapter_digest != expected_digest:
                    rfc_parity = False
            if observed_call_indices != set(range(geometry["hash_call_slots"])):
                rfc_parity = False
            if case.get("all_digests_match_rfc") is not True or not rfc_parity:
                result.append(blocker("evidence_mismatch", f"RFC parity failed at {key}"))
        if observed_case_keys != expected_case_keys:
            result.append(
                blocker(
                    "evidence_mismatch",
                    f"oracle matrix keys differ: expected {len(expected_case_keys)}, got {len(observed_case_keys)}",
                )
            )
    if len(observed_shape_digests) != 1:
        result.append(blocker("evidence_mismatch", "adapter shape varies across secrets/modes"))
    if len(secret_fingerprints) != 15 or any(
        len(fingerprints) != 2 for fingerprints in secret_fingerprints.values()
    ):
        result.append(
            blocker("evidence_mismatch", "secret variants are absent or not independently distinct")
        )
    if isinstance(cases, list):
        observed_root = oracle_observation_stream_sha512(cases)
        if evidence.get("oracle_observation_stream_sha512") != observed_root:
            result.append(
                blocker("evidence_mismatch", "RFC observation stream commitment mismatch")
            )

    if live_replay is None or adapter_sha512 is None:
        result.append(
            blocker(
                "independent_public_iterator_replay_unavailable",
                "retained JSON cannot substitute for live public operation/cell iterator replay",
            )
        )
    else:
        result.extend(
            audit_live_public_iterator_replay(
                contract,
                evidence,
                live_replay,
                adapter_sha512=adapter_sha512,
            )
        )
    return result


def audit(
    contract: dict[str, Any] | None = None,
    sources: Sources | None = None,
    *,
    include_evidence: bool = True,
) -> dict[str, Any]:
    contract = load_contract() if contract is None else contract
    sources = load_sources() if sources is None else sources
    blockers = []
    blockers.extend(audit_source_pins(contract, sources))
    blockers.extend(audit_known_forward_dependencies(contract))
    blockers.extend(audit_test_evidence_contract(contract))
    blockers.extend(audit_test_evidence_source(contract, sources))
    if contract.get("post_fixture_topology_replay_complete") is not True:
        blockers.append(
            blocker(
                "post_fixture_topology_replay_pending",
                "topology has not been recompiled/replayed after the 30-case evidence seam",
            )
        )
    blockers.extend(audit_topology_api(contract, sources.topology))
    blockers.extend(audit_adapter_surface(contract, sources.adapter))
    if include_evidence:
        blockers.extend(audit_evidence(contract))
    blockers.sort(key=lambda item: (item["code"], item["detail"]))
    grammar_pin = contract["frozen_sources"][
        "circuits/transaction/src/hx512_production_relation.rs"
    ]
    suffix_marker = grammar_pin["production_suffix_marker"].encode()
    grammar_boundary = sources.grammar_bytes.find(suffix_marker)
    return {
        "schema": contract["schema"],
        "qualified": not blockers,
        "production_authorized": False,
        "observed_source_sha512": {
            "adapter": sha512(sources.adapter_bytes),
            "cargo_manifest": sha512(sources.cargo_bytes),
            "grammar": sha512(sources.grammar_bytes),
            "grammar_production_prefix": sha512(
                sources.grammar_bytes[:grammar_boundary]
                if grammar_boundary >= 0
                else sources.grammar_bytes
            ),
            "grammar_test_suffix": sha512(
                sources.grammar_bytes[grammar_boundary:] if grammar_boundary >= 0 else b""
            ),
            "topology": sha512(sources.topology_bytes),
        },
        "geometry": contract["geometry"],
        "known_forward_call_dependencies": contract["known_forward_call_dependencies"],
        "blockers": blockers,
    }


def blocker_codes(report: dict[str, Any]) -> set[str]:
    return {item["code"] for item in report["blockers"]}


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--expect-blocked",
        action="store_true",
        help="return success only when the gate remains closed (for the retained negative test)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        report = audit()
    except (OSError, ValueError, RefinementError) as error:
        print(json.dumps({"qualified": False, "fatal": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    if args.expect_blocked:
        return 0 if not report["qualified"] else 1
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    sys.exit(main())
