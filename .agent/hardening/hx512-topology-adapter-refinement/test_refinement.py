#!/usr/bin/env python3
"""Adversarial tests for the independent HX512 topology/adapter gate."""

from __future__ import annotations

import dataclasses
import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
CHECKER_PATH = HERE / "check_refinement.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("hx512_topology_adapter_checker", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


C = load_checker()


class Hx512TopologyAdapterRefinementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = C.load_contract()
        self.sources = C.load_sources()

    def test_frozen_sources_and_topology_api_are_exact(self) -> None:
        self.assertEqual(C.audit_source_pins(self.contract, self.sources), [])
        self.assertEqual(C.audit_topology_api(self.contract, self.sources.topology), [])
        self.assertEqual(C.audit_test_evidence_contract(self.contract), [])
        self.assertEqual(
            self.contract["geometry"],
            {
                "packing_factor": 1024,
                "maximum_degree": 6,
                "auxiliary_words": 0,
                "hash_call_slots": 95,
                "maximum_compressions": 226,
                "hash_base_rows": 11892,
                "hash_base_cells": 12177408,
                "explicit_padding_cells": 2500,
                "operation_count": 285744,
                "rfc_zero_bytes_by_mode": [8748, 8494, 8240, 8570, 8316],
                "selected_control_positions": 8,
                "selected_digest_calls": 4,
            },
        )

    def test_frozen_source_mutations_fail_before_adapter_evidence(self) -> None:
        changed = self.sources.topology_bytes.replace(b"1_024", b"1_025", 1)
        mutated = dataclasses.replace(
            self.sources,
            topology=changed.decode(),
            topology_bytes=changed,
        )
        codes = {item["code"] for item in C.audit_source_pins(self.contract, mutated)}
        self.assertIn("frozen_source_drift", codes)
        codes = {item["code"] for item in C.audit_topology_api(self.contract, mutated.topology)}
        self.assertIn("topology_geometry_mismatch", codes)

    def test_known_forward_dependencies_forbid_call_index_execution(self) -> None:
        self.assertEqual(
            self.contract["known_forward_call_dependencies"],
            {"4": [72, 77, 78], "5": [73, 77]},
        )
        synthetic = """
        pub const HX512_ADAPTER_PACKING_FACTOR: usize = 1024;
        pub const HX512_ADAPTER_MAX_DEGREE: usize = 6;
        for call in &registry.calls {
            if call.index != per_call_mode_digests.len() { return Err(()); }
        }
        """
        blockers = C.audit_adapter_surface(self.contract, synthetic)
        self.assertIn("adapter_prior_index_assumption", {item["code"] for item in blockers})

        dependencies = {
            int(consumer): set(producers)
            for consumer, producers in self.contract[
                "known_forward_call_dependencies"
            ].items()
        }
        order = C.topological_call_order(95, dependencies)
        positions = {call: index for index, call in enumerate(order)}
        self.assertNotEqual(order, list(range(95)))
        for consumer, producers in dependencies.items():
            for producer in producers:
                self.assertGreater(producer, consumer)
                self.assertLess(positions[producer], positions[consumer])
        self.assertEqual(C.audit_known_forward_dependencies(self.contract), [])

    def test_dependency_cycle_and_out_of_range_edges_fail_closed(self) -> None:
        with self.assertRaisesRegex(C.RefinementError, "cyclic call dependency graph"):
            C.topological_call_order(95, {4: {72}, 72: {4}})
        with self.assertRaisesRegex(C.RefinementError, "outside registry"):
            C.topological_call_order(95, {4: {95}})

    def test_current_adapter_must_remain_blocked_without_live_replay(self) -> None:
        report = C.audit(self.contract, self.sources)
        self.assertFalse(report["qualified"])
        self.assertFalse(report["production_authorized"])
        codes = C.blocker_codes(report)
        self.assertIn("missing_refinement_evidence", codes)
        self.assertIn("independent_public_iterator_replay_unavailable", codes)
        self.assertIn("post_fixture_topology_replay_pending", codes)
        self.assertIn("missing_authorization_mask_replay_api", codes)

    def test_static_mode_mask_table_cannot_replace_live_80_case_replay(self) -> None:
        self.assertIn("exact_26_accept_54_reject_mode_mask_table", self.sources.grammar)
        source_codes = {
            item["code"]
            for item in C.audit_test_evidence_source(self.contract, self.sources)
        }
        self.assertEqual(source_codes, {"missing_authorization_mask_replay_api"})

        cases = []
        for mode in range(5):
            for mask in range(16):
                accepted = len(cases) < 26
                cases.append(
                    {
                        "adapter_error_class": None if accepted else "RejectedModeMask",
                        "adapter_result": "accept" if accepted else "reject",
                        "adapter_zero_residuals": accepted,
                        "grammar_error_class": None if accepted else "RejectedModeMask",
                        "grammar_result": "accept" if accepted else "reject",
                        "mask": mask,
                        "mode": mode,
                    }
                )
        replay = {"authorization_mask_cases": cases}
        replay["authorization_mask_stream_sha512"] = hashlib.sha512(
            b"".join(C._stream_record_bytes(case) for case in cases)
        ).hexdigest()
        self.assertEqual(
            C.audit_authorization_mask_live_replay(self.contract, replay), []
        )

        mutated = copy.deepcopy(replay)
        mutated_cases = mutated["authorization_mask_cases"]
        assert isinstance(mutated_cases, list)
        mutated_cases[0]["adapter_result"] = "reject"
        mutation_codes = {
            item["code"]
            for item in C.audit_authorization_mask_live_replay(self.contract, mutated)
        }
        self.assertIn("authorization_mask_refinement_mismatch", mutation_codes)
        self.assertIn("invalid_live_authorization_mask_replay", mutation_codes)

    def good_evidence(self) -> dict[str, object]:
        geometry = self.contract["geometry"]
        personalization = bytes(16)
        message = b""
        digest = hashlib.blake2b(message, digest_size=64, person=personalization).hexdigest()
        calls = [
            {
                "adapter_digest_hex": digest,
                "call_index": call,
                "message_hex": message.hex(),
                "personalization_hex": personalization.hex(),
            }
            for call in range(geometry["hash_call_slots"])
        ]
        shape = "42" * 64
        cases = []
        for mode in range(5):
            for direction in ("disabled", "mint", "burn"):
                for secret_variant in (0, 1):
                    fingerprint = hashlib.sha512(
                        f"{mode}:{direction}:{secret_variant}".encode()
                    ).hexdigest()
                    cases.append(
                        {
                            "adapter_shape_digest_sha512": shape,
                            "all_digests_match_rfc": True,
                            "call_count": geometry["hash_call_slots"],
                            "calls": calls,
                            "mode": mode,
                            "secret_fingerprint_sha512": fingerprint,
                            "secret_variant": secret_variant,
                            "stable_direction": direction,
                        }
                    )
        evidence = {
            "adapter_shape_digest_sha512": shape,
            "auxiliary_words": 0,
            "cell_assignment_bijection": True,
            "duplicate_cell_count": 0,
            "grammar_sha512": self.contract["frozen_sources"][
                "circuits/transaction/src/hx512_production_relation.rs"
            ]["sha512"],
            "hash_base_cells": geometry["hash_base_cells"],
            "hash_base_rows": geometry["hash_base_rows"],
            "nonhash_rows_disjoint": True,
            "operation_assignment_bijection": True,
            "operation_count": geometry["operation_count"],
            "packing_factor": geometry["packing_factor"],
            "private_constant_count": 0,
            "rfc_oracle_cases": cases,
            "same_shape_for_secret_variants": True,
            "test_identity_shape_digest_sha512": self.contract[
                "test_identity_shape_digest_sha512"
            ],
            "topology_sha512": self.contract["frozen_sources"][
                "circuits/transaction/src/smallwood_hx512_topology.rs"
            ]["sha512"],
            "unconsumed_cell_count": 0,
            "unmapped_dependency_count": 0,
        }
        evidence["oracle_observation_stream_sha512"] = C.oracle_observation_stream_sha512(
            cases
        )
        return evidence

    def audit_temp_evidence(self, evidence: dict[str, object]) -> list[dict[str, str]]:
        with tempfile.TemporaryDirectory(prefix="hx512-refinement-") as directory:
            path = Path(directory) / "evidence.json"
            path.write_bytes(C.canonical_json(evidence))
            return C.audit_evidence(self.contract, path)

    def test_evidence_schema_recomputes_every_rfc_digest(self) -> None:
        evidence = self.good_evidence()
        blockers = self.audit_temp_evidence(evidence)
        self.assertEqual(
            {item["code"] for item in blockers},
            {"independent_public_iterator_replay_unavailable"},
        )
        cases = evidence["rfc_oracle_cases"]
        assert isinstance(cases, list)
        calls = cases[0]["calls"]
        assert isinstance(calls, list)
        calls[4] = dict(calls[4])
        calls[4]["adapter_digest_hex"] = "00" * 64
        blockers = self.audit_temp_evidence(evidence)
        self.assertTrue(
            any(
                item["code"] == "evidence_mismatch" and "RFC parity failed" in item["detail"]
                for item in blockers
            )
        )

    def test_secret_shape_and_self_reported_bijections_cannot_close_gate(self) -> None:
        evidence = self.good_evidence()
        cases = evidence["rfc_oracle_cases"]
        assert isinstance(cases, list)
        cases[0] = dict(cases[0])
        cases[0]["adapter_shape_digest_sha512"] = "43" * 64
        cases[1] = dict(cases[1])
        cases[1]["secret_fingerprint_sha512"] = cases[0]["secret_fingerprint_sha512"]
        evidence["oracle_observation_stream_sha512"] = C.oracle_observation_stream_sha512(cases)
        details = "\n".join(item["detail"] for item in self.audit_temp_evidence(evidence))
        self.assertIn("adapter shape varies", details)
        self.assertIn("secret variants are absent", details)
        self.assertIn("retained JSON cannot substitute", details)

    def test_concrete_map_flip_drop_and_duplicate_records_reject(self) -> None:
        topology = [
            {
                "dependencies": [] if index == 0 else [index - 1],
                "identity_set": [f"poly-{index}"],
                "key": index,
                "output_cells": [index * 32 + digit for digit in range(32)],
                "witness_assignment": f"assignment-{index}",
            }
            for index in range(4)
        ]
        self.assertEqual(
            C.compare_concrete_record_streams(
                "operation_mapping", topology, copy.deepcopy(topology), 4
            ),
            [],
        )

        flipped = copy.deepcopy(topology)
        flipped[2]["identity_set"] = ["wrong-polynomial"]
        self.assertIn(
            "record_stream_mismatch",
            {
                item["code"]
                for item in C.compare_concrete_record_streams(
                    "operation_mapping", topology, flipped, 4
                )
            },
        )

        dropped = copy.deepcopy(topology[:-1])
        self.assertIn(
            "record_stream_count_mismatch",
            {
                item["code"]
                for item in C.compare_concrete_record_streams(
                    "operation_mapping", topology, dropped, 4
                )
            },
        )

        duplicated = copy.deepcopy(topology)
        duplicated[-1] = copy.deepcopy(duplicated[-2])
        duplicate_codes = {
            item["code"]
            for item in C.compare_concrete_record_streams(
                "operation_mapping", topology, duplicated, 4
            )
        }
        self.assertIn("record_stream_duplicate", duplicate_codes)
        self.assertIn("record_stream_mismatch", duplicate_codes)


if __name__ == "__main__":
    unittest.main()
