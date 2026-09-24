#!/usr/bin/env python3
"""Adversarial tests for the exact HX512 composition ledger."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path

import ledger


REPO_ROOT = Path(__file__).resolve().parents[3]


def report_fraction(item: dict[str, object]) -> Fraction:
    exact = item["exact"]
    assert isinstance(exact, dict)
    return Fraction(int(exact["numerator"]), int(exact["denominator"]))


def set_path(document: dict[str, object], path: tuple[object, ...], value: object) -> None:
    cursor: object = document
    for component in path[:-1]:
        if isinstance(component, int):
            assert isinstance(cursor, list)
            cursor = cursor[component]
        else:
            assert isinstance(cursor, dict)
            cursor = cursor[component]
    final = path[-1]
    if isinstance(final, int):
        assert isinstance(cursor, list)
        cursor[final] = value
    else:
        assert isinstance(cursor, dict)
        cursor[final] = value


class PopulatedFixture:
    """A TEST_ONLY arithmetic screen in an isolated source-pin tree."""

    def __init__(self, history_cap: int = 1) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo_root = Path(self.temporary.name)
        self.document = ledger.default_input()
        for role, (relative, algorithm, required) in ledger.SOURCE_LAYOUT.items():
            destination = self.repo_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if required is not None:
                source = REPO_ROOT / relative
                payload = source.read_bytes()
                digest = hashlib.new(algorithm, payload).hexdigest()
                if digest != required:
                    raise AssertionError(f"frozen TEST_ONLY source drifted: {role}")
            else:
                payload = f"TEST_ONLY::{role}::pinned-source\n".encode("ascii")
                digest = hashlib.new(algorithm, payload).hexdigest()
                self.document["source_pins"][role]["digest"] = digest
            destination.write_bytes(payload)

        self.document["geometry"] = {
            "final_relation_row_count": 11892,
            "final_relation_row_count_source": ledger.FINAL_ROW_COUNT_SOURCE,
        }
        self.document["consensus_history"] = {
            "block_epoch_cap": history_cap,
            "block_epoch_cap_consensus_enforced": True,
            "epoch_identifier_bound_to_statement": True,
            "global_query_cap_includes_adversary_and_all_honest_calls": True,
            "max_proofs_per_block": 1,
            "max_proofs_per_block_consensus_enforced": True,
            "proof_epoch_cap": history_cap,
            "proof_epoch_cap_consensus_enforced": True,
            "reorg_restart_counter_refinement": True,
        }
        self.document["protocol_controls"] = {
            "decs_candidate_count": 96,
            "grinding_bits": 0,
            "piop_nonce_trials": 4,
            "prover_retries": 0,
            "sampler_caps_consensus_enforced": True,
            "verifier_retries": 0,
            "zero_grinding_and_retries_consensus_enforced": True,
        }
        self.document["relation_surface"][
            "all_pairs_uniform_single_relation_premise_retained"
        ] = True
        zero = ledger.fraction_json(Fraction(0))
        for item in self.document["external_terms"].values():
            item["loss"] = zero
            item["premise_retained"] = True
        for index, candidate in enumerate(self.document["candidates"]):
            candidate["engine_geometry_digest_sha512"] = hashlib.sha512(
                f"TEST_ONLY::geometry::{index}".encode("ascii")
            ).hexdigest()
            candidate["measured_proof_bytes"] = 120000 + index
            candidate["physical_sha512_calls_per_proof"] = 100
            candidate["physical_shake_calls_per_proof"] = 100

    def close(self) -> None:
        self.temporary.cleanup()


class Hx512CompositionLedgerTests(unittest.TestCase):
    def test_retained_default_is_source_pinned_and_fail_closed(self) -> None:
        document = ledger.default_input()
        report = ledger.build_report(document, REPO_ROOT)
        self.assertTrue(report["source_pins"]["grammar"]["matched"])
        self.assertTrue(report["source_pins"]["stable_transition"]["matched"])
        self.assertTrue(report["source_pins"]["stable_source"]["matched"])
        self.assertIsNone(report["conditional_selection"]["selected_candidate_id"])
        self.assertEqual(
            report["conditional_selection"]["status"],
            "fail-closed-no-admissible-profile",
        )
        self.assertTrue(all(value is False for value in report["authorities"].values()))

    def test_exact_s5_reject_and_s6_s7_epsilon3_ordering(self) -> None:
        amplified: dict[int, Fraction] = {}
        for openings, expected_d, expected_floor in (
            (5, 6168, 125),
            (6, 6174, 176),
            (7, 6180, 228),
        ):
            geometry = ledger._candidate_geometry(None, openings)
            self.assertEqual(geometry["discrepancy_bound_D"], expected_d)
            epsilon3 = ledger.interactive_terms(
                openings=openings, constraint_degree=6, lvcs_columns=None
            )["epsilon3_piop_opening_without_replacement"]
            assert epsilon3 is not None
            amplified[openings] = 12 * ledger.GLOBAL_QUANTUM_QUERY_CAP**2 * epsilon3
            self.assertEqual(
                ledger.security_bits_floor(amplified[openings]), expected_floor
            )
        self.assertFalse(ledger.strict_target_pass(amplified[5]))
        self.assertTrue(ledger.strict_target_pass(amplified[6]))
        self.assertLess(amplified[7], amplified[6])

    def test_ghcm_history_terms_match_exact_dyadic_checkpoint(self) -> None:
        terms = ledger.ghcm_history_terms(1 << 64)
        self.assertEqual(
            terms["ghcm_leaf_adaptive_programming"], Fraction(3, 1 << 172)
        )
        self.assertEqual(
            terms["ghcm_chain_adaptive_programming"], Fraction(3, 1 << 158)
        )
        self.assertEqual(sum(terms.values()), Fraction(49155, 1 << 172))

    def test_equality_at_target_is_rejected(self) -> None:
        self.assertFalse(ledger.strict_target_pass(Fraction(1, 1 << 128)))
        self.assertTrue(ledger.strict_target_pass(Fraction(1, (1 << 128) + 1)))

    def test_unenforced_or_missing_history_cap_prevents_selection(self) -> None:
        fixture = PopulatedFixture()
        self.addCleanup(fixture.close)
        for field, value in (
            ("proof_epoch_cap", None),
            ("proof_epoch_cap_consensus_enforced", False),
            ("epoch_identifier_bound_to_statement", False),
            ("reorg_restart_counter_refinement", False),
        ):
            mutated = copy.deepcopy(fixture.document)
            mutated["consensus_history"][field] = value
            report = ledger.build_report(mutated, fixture.repo_root)
            self.assertIsNone(report["conditional_selection"]["selected_candidate_id"])

    def test_every_nullable_gate_fails_closed(self) -> None:
        fixture = PopulatedFixture()
        self.addCleanup(fixture.close)
        nullable_paths: list[tuple[object, ...]] = [
            ("geometry", "final_relation_row_count"),
            ("geometry", "final_relation_row_count_source"),
            ("consensus_history", "proof_epoch_cap"),
            ("consensus_history", "block_epoch_cap"),
            ("consensus_history", "max_proofs_per_block"),
            ("protocol_controls", "decs_candidate_count"),
            ("protocol_controls", "piop_nonce_trials"),
        ]
        for role, (_path, _algorithm, required) in ledger.SOURCE_LAYOUT.items():
            if required is None:
                nullable_paths.append(("source_pins", role, "digest"))
        for index in range(2):
            for field in (
                "engine_geometry_digest_sha512",
                "measured_proof_bytes",
                "physical_sha512_calls_per_proof",
                "physical_shake_calls_per_proof",
            ):
                nullable_paths.append(("candidates", index, field))
        for name in ledger.EXTERNAL_TERM_SCOPES:
            nullable_paths.append(("external_terms", name, "loss"))

        for path in nullable_paths:
            with self.subTest(path=path):
                mutated = copy.deepcopy(fixture.document)
                set_path(mutated, path, None)
                report = ledger.build_report(mutated, fixture.repo_root)
                self.assertIsNone(
                    report["conditional_selection"]["selected_candidate_id"]
                )

    def test_nonzero_grinding_and_retries_are_blocked(self) -> None:
        fixture = PopulatedFixture()
        self.addCleanup(fixture.close)
        for field in ("grinding_bits", "prover_retries", "verifier_retries"):
            mutated = copy.deepcopy(fixture.document)
            mutated["protocol_controls"][field] = 1
            report = ledger.build_report(mutated, fixture.repo_root)
            self.assertIsNone(report["conditional_selection"]["selected_candidate_id"])
            blockers = report["candidates"][0]["eligibility_blockers"]
            self.assertTrue(any(field.split("_")[0] in item for item in blockers))

    def test_global_q_is_not_multiplied_by_history(self) -> None:
        fixture = PopulatedFixture(history_cap=3)
        self.addCleanup(fixture.close)
        report = ledger.build_report(fixture.document, fixture.repo_root)
        candidate = report["candidates"][0]
        self.assertEqual(report["query_accounting"]["cms_and_global_hash_multiplier"], 1)
        exact_terms = candidate["cms"]["exact_terms"]
        assert isinstance(exact_terms, dict)
        cms_total = sum(report_fraction(item) for item in exact_terms.values())
        counterfactual = report_fraction(
            candidate["cms"]["counterfactual_per_proof_union_not_selected"]
        )
        self.assertEqual(counterfactual, 3 * cms_total)
        known_terms = candidate["composition"]["known_terms"]
        assert isinstance(known_terms, dict)
        selected_cms_total = sum(
            report_fraction(item)
            for name, item in known_terms.items()
            if name.startswith("cms::")
        )
        self.assertEqual(selected_cms_total, cms_total)

    def test_exact_role_mask_and_mode_inventory(self) -> None:
        document = ledger.default_input()
        registry = document["semantic_hash_registry"]
        self.assertEqual(sum(item["calls"] for item in registry["role_families"]), 95)
        self.assertEqual(registry["global_oracle_union_multiplier"], 1)
        surface = document["relation_surface"]
        self.assertEqual(surface["accepted_mode_mask_pairs"], 26)
        self.assertEqual(surface["rejected_mode_mask_pairs"], 54)
        self.assertEqual(26 + 54, 16 * 5)
        self.assertEqual(len(surface["lifecycle_stages"]), 9)

    def test_canonical_json_rejects_duplicates_floats_and_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_bytes(b'{"a":1,"a":2}\n')
            with self.assertRaises(ledger.LedgerInputError):
                ledger.load_canonical_json(path)
            path.write_bytes(b'{"a":0.5}\n')
            with self.assertRaises(ledger.LedgerInputError):
                ledger.load_canonical_json(path)
            path.write_text(json.dumps({"a": 1}, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(ledger.LedgerInputError):
                ledger.load_canonical_json(path)
            path.write_bytes(ledger.canonical_json_bytes({"a": 1}))
            self.assertEqual(ledger.load_canonical_json(path), {"a": 1})

    def test_exact_sampler_exhaustion_is_nonzero_and_bounded(self) -> None:
        piop = ledger.piop_sampler_exhaustion_probability(6, 4)
        decs = ledger.decs_sampler_exhaustion_probability(96)
        self.assertGreater(piop, 0)
        self.assertLess(piop, 1)
        self.assertGreater(decs, 0)
        self.assertLess(decs, 1)

    def test_fully_populated_screen_selects_smallest_s_but_never_authority(self) -> None:
        fixture = PopulatedFixture()
        self.addCleanup(fixture.close)
        report = ledger.build_report(fixture.document, fixture.repo_root)
        self.assertEqual(
            report["conditional_selection"]["selected_candidate_id"], "q48-s6"
        )
        self.assertEqual(
            report["conditional_selection"]["history_cap_pair"],
            {"piop_openings": 6, "proof_epoch_cap": 1},
        )
        self.assertTrue(report["candidates"][0]["conditional_admissible"])
        self.assertTrue(report["candidates"][1]["conditional_admissible"])
        self.assertTrue(all(value is False for value in report["authorities"].values()))
        self.assertFalse(
            report["sensitivity_only"]["topology_base_rows_11892_not_final"][
                "final_geometry_claim"
            ]
        )

    def test_each_external_term_and_premise_is_mandatory(self) -> None:
        fixture = PopulatedFixture()
        self.addCleanup(fixture.close)
        for name in ledger.EXTERNAL_TERM_SCOPES:
            for field, value in (("loss", None), ("premise_retained", False)):
                with self.subTest(name=name, field=field):
                    mutated = copy.deepcopy(fixture.document)
                    mutated["external_terms"][name][field] = value
                    report = ledger.build_report(mutated, fixture.repo_root)
                    self.assertIsNone(
                        report["conditional_selection"]["selected_candidate_id"]
                    )


if __name__ == "__main__":
    unittest.main()
