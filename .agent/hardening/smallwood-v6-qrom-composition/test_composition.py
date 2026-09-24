from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import itertools
import json
import subprocess
import sys
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("composition.py")
PROFILE_PATH = Path(__file__).with_name("profile.json")
SPEC = importlib.util.spec_from_file_location("smallwood_v6_composition", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import composition.py")
composition = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(composition)


def load_profile() -> dict[str, object]:
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def probability(numerator: int, denominator: int) -> dict[str, str]:
    return {"numerator": str(numerator), "denominator": str(denominator)}


def complete_geometry(profile: dict[str, object]) -> None:
    profile["geometry"] = {
        "row_count": 699,
        "nonlinear_constraint_count": 890,
        "linear_constraint_count": 18_342,
        "effective_constraint_degree": 8,
        "witness_polynomial_degree": 68,
        "consistency_discrepancy_degree": 544,
        "lvcs_column_count": 375,
        "base_game_arity_upper_bound": 1_048_576,
    }
    budgets = profile["budgets"]
    assert isinstance(budgets, dict)
    budgets["history_cap_consensus_enforced"] = True
    budgets["physical_sha512_call_cap_per_proof"] = 4_500_000
    budgets["physical_sha512_call_cap_enforced"] = True


def complete_external_losses(profile: dict[str, object]) -> None:
    losses = profile["external_losses"]
    assert isinstance(losses, dict)
    for name in losses:
        losses[name] = {
            "at_2pow64": probability(1, 2**300),
            "at_2pow128": probability(1, 2**20),
        }


def create_and_pin_sources(profile: dict[str, object], repo_root: Path) -> None:
    payloads: dict[str, bytes] = {
        role: f"// isolated fixture for {role}\n".encode()
        for role in composition.EXPECTED_SOURCE_ROLES
    }
    payloads["statement_owner"] += (
        b'pub const MAGIC: [u8; 8] = *b"HGF6ST02";\n'
        b'pub const PROFILE: [u8; 8] = *b"HEG-F6V2";\n'
        b'pub const HASH_REGISTRY: [u8; 8] = *b"HGF6HR02";\n'
    )
    payloads["m4_mixed_candidate"] += (
        b'pub const PINNED_BINIUS_TREE_SHA512: &str = "'
        + composition.PINNED_M4_BINIUS_TREE_SHA512.encode("ascii")
        + b'";\n'
    )
    for hash_role in composition.EXPECTED_HASH_ROLES:
        constant = hash_role["domain_constant"]
        domain = hash_role["domain_ascii"]
        if constant is None or domain is None:
            continue
        owner = str(hash_role["domain_owner"])
        source_literal = str(domain).replace("\\", "\\\\").replace("\0", "\\0")
        if owner == "composition_checker":
            definition = f'{constant} = b"{source_literal}"\n'
        else:
            definition = f'pub const {constant}: &[u8] = b"{source_literal}";\n'
        payloads[owner] += definition.encode()
    binding = profile["source_binding"]
    assert isinstance(binding, dict)
    entries = binding["files"]
    assert isinstance(entries, list)
    for entry in entries:
        assert isinstance(entry, dict)
        role = str(entry["role"])
        relative = Path(str(entry["path"]))
        path = repo_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = payloads[role]
        path.write_bytes(payload)
        entry["sha512"] = hashlib.sha512(payload).hexdigest()
    report, _ = composition._source_binding_report(profile, repo_root)
    binding["relation_manifest_sha512"] = report[
        "observed_relation_manifest_sha512"
    ]


def full_fixture(repo_root: Path) -> dict[str, object]:
    profile = load_profile()
    complete_geometry(profile)
    complete_external_losses(profile)
    create_and_pin_sources(profile, repo_root)
    return profile


class CompositionTests(unittest.TestCase):
    maxDiff = None

    def test_checked_in_profile_fails_closed(self) -> None:
        repo_root = MODULE_PATH.resolve().parents[3]
        report = composition.evaluate(
            composition.load_json_strict(PROFILE_PATH), repo_root
        )
        self.assertFalse(report["geometry_available"])
        self.assertEqual(
            report["capabilities"],
            {
                "conditional_integer_accounting_complete": False,
                "composed_pq128": False,
                "production_authorized": False,
            },
        )
        self.assertIn(
            "exact V6 geometry is not measured: row_count",
            report["blocking_reasons"],
        )
        self.assertIn(
            "physical SHA-512 calls per proof have no hard cap",
            report["blocking_reasons"],
        )
        self.assertIn(
            "quantitative external loss missing: decs_leaf_tape_qrom_hiding",
            report["blocking_reasons"],
        )
        self.assertEqual(
            report["relation_identity"]["semantic_shake_invocations"], 79
        )
        self.assertEqual(
            report["relation_identity"]["semantic_keccak_permutations"], 145
        )
        self.assertFalse(report["numeric_gates"]["hash_role_strict_margin_pass"])
        self.assertEqual(
            report["hash_role_gate"][
                "selected_nonstandard_wide_xof_preimage_or_prf_roles"
            ],
            [
                "semantic.note_commitment",
                "semantic.nullifier",
                "semantic.spend_key_xof",
                "semantic.authorization_policy",
                "semantic.authorization_accumulator",
                "semantic.authorization_value_lock",
            ],
        )

    def test_exact_interactive_and_cms_reference_arithmetic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = composition.evaluate(full_fixture(root), root)
        low = report["low_advantage_accounting"]
        work = report["work_factor_accounting"]
        self.assertIsInstance(low, dict)
        self.assertIsInstance(work, dict)
        terms = low["interactive_terms"]
        q = composition.GOLDILOCKS_ORDER
        self.assertEqual(terms["decs_uniform_matrix"]["denominator"], str(q**5))
        self.assertEqual(
            terms["piop_constraint_batching"]["denominator"], str(q**5)
        )
        piop = terms["piop_opening_without_replacement"]
        self.assertEqual(
            Fraction(int(piop["numerator"]), int(piop["denominator"])),
            Fraction(
                composition.falling_product(544, 5),
                composition.falling_product(q - 64, 5),
            ),
        )
        decs = terms["decs_opening_without_replacement"]
        self.assertEqual(
            Fraction(int(decs["numerator"]), int(decs["denominator"])),
            Fraction(
                composition.falling_product(397, 23),
                composition.falling_product(2**20, 23),
            ),
        )
        self.assertTrue(report["numeric_gates"]["low_advantage_pass"])
        self.assertTrue(report["numeric_gates"]["work_factor_pass"])
        self.assertFalse(report["capabilities"]["composed_pq128"])

    def test_semantic_hash_uses_one_term_per_property_not_call_unions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = composition.evaluate(full_fixture(root), root)
        low = report["low_advantage_accounting"]
        screen = low["semantic_shake256_collision_screen"]
        wide_xof_collision = low[
            "semantic_nonstandard_keccak_c1024_xof_collision_screen"
        ]
        self.assertEqual(screen["semantic_shake_invocations"], 79)
        self.assertEqual(screen["semantic_keccak_permutations"], 145)
        self.assertEqual(screen["global_primitive_terms"], 1)
        self.assertEqual(screen["per_invocation_or_permutation_union_multiplier"], 1)
        self.assertEqual(
            report["relation_identity"]["global_semantic_primitive_terms"], 3
        )
        expected = Fraction(4 * (2**64) ** 3, 2**448)
        self.assertEqual(Fraction(int(screen["numerator"]), int(screen["denominator"])), expected)
        cms = low["ideal_shared_history_cms_total"]
        abort = low["sampler_terms"]["aggregate"]
        preimage = low[
            "semantic_nonstandard_keccak_c1024_xof_preimage_prf_screen"
        ]
        leaf_hiding = low["sha512_decs_leaf_hiding_screen"]
        aggregate = low["ideal_global_arithmetic_total"]
        self.assertEqual(
            Fraction(int(aggregate["numerator"]), int(aggregate["denominator"])),
            Fraction(int(cms["numerator"]), int(cms["denominator"]))
            + Fraction(int(abort["numerator"]), int(abort["denominator"]))
            + expected
            + Fraction(
                int(wide_xof_collision["numerator"]),
                int(wide_xof_collision["denominator"]),
            )
            + Fraction(int(preimage["numerator"]), int(preimage["denominator"]))
            + Fraction(
                int(leaf_hiding["numerator"]), int(leaf_hiding["denominator"])
            ),
        )

    def test_rejected_wide_xof_screen_has_margin_and_uniform_shake256_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = composition.evaluate(full_fixture(root), root)
        low = report["low_advantage_accounting"][
            "semantic_nonstandard_keccak_c1024_xof_preimage_prf_screen"
        ]
        work = report["work_factor_accounting"][
            "semantic_nonstandard_keccak_c1024_xof_preimage_prf_screen"
        ]
        self.assertEqual(
            Fraction(int(low["numerator"]), int(low["denominator"])),
            Fraction(1, 2**320),
        )
        self.assertEqual(
            Fraction(int(work["numerator"]), int(work["denominator"])),
            Fraction(1, 2**192),
        )
        self.assertEqual(
            Fraction(
                int(low["uniform_shake256_counterfactual"]["numerator"]),
                int(low["uniform_shake256_counterfactual"]["denominator"]),
            ),
            Fraction(1, 2**128),
        )
        self.assertTrue(report["numeric_gates"]["low_advantage_pass"])
        self.assertTrue(report["numeric_gates"]["work_factor_pass"])
        self.assertFalse(
            report["hash_role_gate"]["disqualified_uniform_shake256_counterfactual"]
            ["strictly_greater_than_128"]
        )

    def test_role_registry_classifies_consensus_proof_and_opaque_authorities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = composition.evaluate(full_fixture(root), root)
        roles = {role["id"]: role for role in report["hash_role_gate"]["roles"]}
        self.assertEqual(
            roles["consensus.action_id"]["required_properties"],
            ["collision-binding"],
        )
        self.assertEqual(
            roles["consensus.action_id"]["second_preimage_mode"],
            "reduced-to-collision",
        )
        self.assertIn(
            "fiat-shamir-qrom",
            roles["proof.piop_transcript"]["required_properties"],
        )
        self.assertEqual(
            roles["proof.merkle_leaf"]["property_pq_cap_bits"][
                "commitment-hiding-preimage"
            ],
            256,
        )
        self.assertEqual(
            report["hash_role_gate"]["unbound_opaque_statement_authorities"],
            [
                "statement.stablecoin_policy_hash",
                "statement.stablecoin_oracle_commitment",
                "statement.stablecoin_attestation_commitment",
            ],
        )
        self.assertFalse(
            report["hash_role_gate"]["bound_role_primitive_margin_pass"]
        )
        self.assertTrue(
            report["hash_role_gate"]["bound_role_numeric_margin_pass"]
        )
        self.assertFalse(
            report["hash_role_gate"]["conventional_hash_authority_pass"]
        )
        self.assertFalse(
            report["hash_role_gate"]["strict_primitive_margin_pass"]
        )
        self.assertEqual(
            roles["semantic.merkle_node"]["property_pq_cap_bits"][
                "collision-binding"
            ],
            149,
        )
        self.assertEqual(
            roles["semantic.note_commitment"]["property_pq_cap_bits"][
                "preimage-hiding"
            ],
            224,
        )

    def test_exact_hgf6hr02_registry_encoding_is_source_digest_bound(self) -> None:
        encoded = composition._encode_relation_hash_role_registry()
        self.assertEqual(len(encoded), 214)
        self.assertEqual(encoded[:8], b"HGF6HR02")
        self.assertEqual(
            hashlib.sha512(encoded).hexdigest(),
            "840e4426ab9b8b74e6400f4573109db0b2324df6b2fd81a81f24c2cc801dd0767b8caaa2a58e219db3f0e90494d2312e39fc83642d21b81a6becdf3373a19631",
        )
        self.assertEqual(
            sum(
                int(family["invocations"])
                for family in composition.EXPECTED_SEMANTIC_CALL_FAMILIES
            ),
            79,
        )
        self.assertEqual(
            sum(
                int(family["invocations"])
                * int(family["permutations_each"])
                for family in composition.EXPECTED_SEMANTIC_CALL_FAMILIES
            ),
            145,
        )

    def test_conventional_successor_tournament_does_not_preselect_identity(self) -> None:
        tournament = composition._conventional_successor_tournament()
        self.assertFalse(tournament["identity_rotation_authorized"])
        self.assertIsNone(tournament["winner"])
        sha3 = tournament["sha3_512_split"]
        self.assertEqual(sha3["primitive_invocations"], 83)
        self.assertEqual(sha3["total_relation_keccak_permutations"], 151)
        self.assertEqual(sha3["generic_quantum_output_preimage_cap_bits"], 224)
        self.assertEqual(sha3["spend_seed_grover_cap_bits"], 192)
        self.assertFalse(sha3["raw_domain_hash_prf_kdf_authority"])
        self.assertFalse(sha3["hmac_or_hkdf_unavoidable"])
        self.assertTrue(
            sha3["keyed_construction_and_reduction_unavoidable_for_prf_roles"]
        )
        self.assertFalse(sha3["concrete_keccak_sponge_qrom_bridge_present"])
        blake = tournament["rfc7693_blake2b_448"]
        self.assertEqual(blake["primitive_invocations"], 83)
        self.assertEqual(blake["unkeyed_mixed_secret_compressions"], 28)
        self.assertEqual(blake["unkeyed_mixed_total_heterogeneous_cores"], 133)
        self.assertFalse(blake["unkeyed_domain_hash_prf_kdf_authority"])
        self.assertEqual(blake["keyed_personalized_secret_compressions"], 32)
        self.assertEqual(blake["keyed_personalized_total_heterogeneous_cores"], 137)
        self.assertFalse(blake["keyed_mode_qrom_prf_reduction_executed"])
        self.assertFalse(blake["concrete_blake2b_qro_bridge_present"])
        self.assertFalse(blake["bounded_multi_user_qrom_loss_present"])
        self.assertIsNone(blake["authorization_key_entropy_bound"])
        self.assertEqual(
            blake["frozen_scalar_source_sha512"],
            composition.PINNED_CONVENTIONAL_SCALAR_SHA512,
        )
        self.assertEqual(
            blake["frozen_m4_source_sha512"],
            composition.PINNED_M4_MIXED_CANDIDATE_SHA512,
        )
        self.assertEqual(
            blake["frozen_m4_source_checker_sha512"],
            composition.PINNED_M4_SOURCE_CHECKER_SHA512,
        )
        self.assertFalse(blake["source_pins_are_security_reductions"])

    def test_unavoidable_exact_128_bit_preimage_role_is_rejected(self) -> None:
        profile = load_profile()
        mutated_roles = deepcopy(composition.EXPECTED_HASH_ROLES)
        note = next(
            role
            for role in mutated_roles
            if role["id"] == "semantic.note_commitment"
        )
        note["primitive"] = "SHAKE256"
        payload = composition._canonical_json(
            {
                "registry_id": composition.HASH_ROLE_REGISTRY_ID,
                "semantic_call_families": list(
                    composition.EXPECTED_SEMANTIC_CALL_FAMILIES
                ),
                "roles": list(mutated_roles),
            }
        )
        profile["hash_role_registry"]["audit_registry_sha512"] = hashlib.sha512(
            composition.HASH_ROLE_REGISTRY_DOMAIN
            + len(payload).to_bytes(8, "little")
            + payload
        ).hexdigest()
        with patch.object(
            composition, "EXPECTED_HASH_ROLES", tuple(mutated_roles)
        ):
            report, failures = composition._hash_role_gate(profile)
        self.assertTrue(report["registry_matches_checker"])
        self.assertFalse(report["strict_primitive_margin_pass"])
        self.assertIn("semantic.note_commitment", report["primitive_migration_required_roles"])
        self.assertIn(
            "hash role semantic.note_commitment has preimage-hiding PQ cap 128, not strictly greater than 128",
            failures,
        )

    def test_role_registry_digest_and_fresh_profile_migration_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = full_fixture(root)
            profile["hash_role_registry"]["audit_registry_sha512"] = "00" * 64
            report = composition.evaluate(profile, root)
        self.assertFalse(report["hash_role_gate"]["registry_matches_checker"])
        self.assertIn(
            "hash-role registry digest differs from the checker-owned property/domain inventory",
            report["blocking_reasons"],
        )

    def test_repinning_a_mutated_domain_does_not_waive_domain_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = full_fixture(root)
            statement = root / composition.EXPECTED_SOURCE_ROLES["statement_owner"]
            statement.write_bytes(statement.read_bytes().replace(b"note.cm3", b"note.cmX"))
            binding = profile["source_binding"]
            for entry in binding["files"]:
                if entry["role"] == "statement_owner":
                    entry["sha512"] = hashlib.sha512(statement.read_bytes()).hexdigest()
            interim, _ = composition._source_binding_report(profile, root)
            binding["relation_manifest_sha512"] = interim[
                "observed_relation_manifest_sha512"
            ]
            report = composition.evaluate(profile, root)
        self.assertIn(
            "hash role semantic.note_commitment domain ROLE_NOTE_COMMITMENT='note.cm3' is not defined by statement_owner",
            report["blocking_reasons"],
        )

    def test_shared_history_and_rejected_per_proof_union_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = composition.evaluate(full_fixture(root), root)
        work = report["work_factor_accounting"]
        shared = work["ideal_shared_history_cms_total"]
        union = work["history_composition"]["counterfactual_per_proof_ideal_union"]
        shared_fraction = Fraction(int(shared["numerator"]), int(shared["denominator"]))
        union_fraction = Fraction(int(union["numerator"]), int(union["denominator"]))
        self.assertLess(shared_fraction, Fraction(1, 2))
        self.assertGreater(union_fraction, 1)
        self.assertEqual(work["history_composition"]["selected_ideal_multiplier"], 1)
        self.assertFalse(work["history_composition"]["counterfactual_union_is_authorized"])

    def test_fixed_decs_sampler_formula_matches_small_exhaustive_model(self) -> None:
        exact = composition.decs_sampler_exhaustion_probability(
            field_order=5, domain_size=2, openings=2, candidates=3
        )
        failures = 0
        total = 0
        for stream in itertools.product(range(5), repeat=3):
            total += 1
            seen: set[int] = set()
            for candidate in stream:
                if candidate >= 4:
                    continue
                seen.add(candidate % 2)
                if len(seen) == 2:
                    break
            if len(seen) < 2:
                failures += 1
        self.assertEqual(exact, Fraction(failures, total))

    def test_piop_sampler_formula_matches_small_exhaustive_model(self) -> None:
        exact = composition.piop_sampler_exhaustion_probability(
            field_order=5, packing_points=1, openings=2, trials=2
        )
        valid = 0
        for pair in itertools.product(range(5), repeat=2):
            if 0 not in pair and pair[0] != pair[1]:
                valid += 1
        invalid_one = Fraction(25 - valid, 25)
        self.assertEqual(exact, invalid_one**2)

    def test_physical_sha512_inventory_includes_linear_matrix_and_merkle_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = composition.evaluate(full_fixture(root), root)
        inventory = report["physical_hash_inventory"]
        self.assertEqual(
            inventory["field_xof_minimum_sha512_blocks"]["piop_constraint_matrix"],
            11_464,
        )
        self.assertEqual(
            inventory["field_xof_minimum_sha512_blocks"]["first_valid_canonical_piop_nonce"],
            2,
        )
        self.assertEqual(
            inventory["field_xof_minimum_sha512_blocks"]["worst_canonical_piop_nonce"],
            17,
        )
        self.assertEqual(
            inventory["prover_merkle_hash_requests"],
            {
                "leaf_hashes": 1_048_576,
                "internal_hashes": 1_048_575,
                "root_binding_hashes": 2,
            },
        )
        self.assertFalse(inventory["exact_executed_calls_available"])
        history = report["history_query_inventory"]
        self.assertEqual(
            history["semantic_shake_history_invocations"], str(79 * 2**32)
        )
        self.assertTrue(history["honest_history_fits_low_advantage_envelope"])

    def test_physical_history_cap_must_fit_global_query_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = full_fixture(root)
            profile["budgets"]["physical_sha512_call_cap_per_proof"] = 2**40
            report = composition.evaluate(profile, root)
            self.assertIn(
                "honest history hash calls exceed the 2^64 global low-advantage query envelope",
                report["blocking_reasons"],
            )

    def test_v5_and_stale_public_projections_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = full_fixture(root)
            profile["identity"]["circuit"] = 5
            report = composition.evaluate(profile, root)
            self.assertIn(
                "identity is not the fresh V6 circuit6/crypto5/family1/action8 tuple",
                report["blocking_reasons"],
            )

            profile = full_fixture(root)
            for stale_width in (122, 130):
                profile = full_fixture(root)
                profile["statement"]["public_field_count"] = stale_width
                report = composition.evaluate(profile, root)
                self.assertTrue(
                    any("128 lossless limbs" in reason for reason in report["blocking_reasons"])
                )

            profile = full_fixture(root)
            profile["statement"]["canonical_bytes"] = 853
            report = composition.evaluate(profile, root)
            self.assertTrue(
                any("893 bytes" in reason for reason in report["blocking_reasons"])
            )

    def test_ciphertext_hash_externalization_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for stale_calls, stale_permutations in ((75, 83), (77, 90)):
                profile = full_fixture(root)
                profile["relation_projection"]["semantic_shake_invocations"] = stale_calls
                profile["relation_projection"]["semantic_keccak_permutations"] = stale_permutations
                report = composition.evaluate(profile, root)
                self.assertTrue(
                    any("79 typed SHAKE invocations and 145 permutations" in reason for reason in report["blocking_reasons"])
                )

    def test_intent_frame_width_is_relation_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = full_fixture(root)
            profile["relation_projection"]["intent_frame_bytes"] = 743
            report = composition.evaluate(profile, root)
            self.assertTrue(
                any("79 typed SHAKE invocations and 145 permutations" in reason for reason in report["blocking_reasons"])
            )

    def test_radix2_or_unbound_opened_leaf_cannot_match_strict_decs_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = full_fixture(root)
            profile["proof_system"]["decs_evaluation_domain"] = "radix2-subgroup"
            report = composition.evaluate(profile, root)
            self.assertIn(
                "proof-system tuple does not match the reviewed no-grinding Level-5 core",
                report["blocking_reasons"],
            )

            profile = full_fixture(root)
            profile["proof_system"]["opened_leaf_random_tape_index_binding"] = False
            report = composition.evaluate(profile, root)
            self.assertIn(
                "proof-system tuple does not match the reviewed no-grinding Level-5 core",
                report["blocking_reasons"],
            )

            profile = full_fixture(root)
            profile["proof_system"]["opened_leaf_random_tape_bytes"] = 32
            profile["proof_system"]["opened_leaf_opening_tape_bytes"] = 736
            report = composition.evaluate(profile, root)
            self.assertIn(
                "proof-system tuple does not match the reviewed no-grinding Level-5 core",
                report["blocking_reasons"],
            )

    def test_source_mutation_breaks_pinned_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = full_fixture(root)
            pristine = composition.evaluate(profile, root)
            self.assertTrue(pristine["source_binding"]["binding_pass"])
            engine = root / composition.EXPECTED_SOURCE_ROLES["smallwood_engine"]
            engine.write_bytes(engine.read_bytes() + b"// mutation\n")
            mutated = composition.evaluate(profile, root)
            self.assertFalse(mutated["source_binding"]["binding_pass"])
            self.assertIn(
                "source digest mismatch for role smallwood_engine",
                mutated["blocking_reasons"],
            )

    def test_duplicate_statement_literals_outside_owner_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = full_fixture(root)
            engine = root / composition.EXPECTED_SOURCE_ROLES["smallwood_engine"]
            engine.write_bytes(
                engine.read_bytes()
                + b'const LOCAL_MAGIC: [u8; 8] = *b"HGF6ST02";\n'
                + b'const LOCAL_PROFILE: [u8; 8] = *b"HEG-F6V2";\n'
            )
            binding = profile["source_binding"]
            for entry in binding["files"]:
                if entry["role"] == "smallwood_engine":
                    entry["sha512"] = hashlib.sha512(engine.read_bytes()).hexdigest()
            interim, _ = composition._source_binding_report(profile, root)
            binding["relation_manifest_sha512"] = interim[
                "observed_relation_manifest_sha512"
            ]
            report = composition.evaluate(profile, root)
            self.assertTrue(
                any("duplicated outside statement owner" in reason for reason in report["blocking_reasons"])
            )

    def test_missing_external_loss_keeps_numeric_gates_false(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = full_fixture(root)
            profile["external_losses"]["global_history_product_oracle_transfer"] = None
            report = composition.evaluate(profile, root)
            self.assertFalse(report["numeric_gates"]["low_advantage_pass"])
            self.assertFalse(report["numeric_gates"]["work_factor_pass"])
            self.assertIn(
                "quantitative external loss missing: global_history_product_oracle_transfer",
                report["blocking_reasons"],
            )

    def test_geometry_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = full_fixture(root)
            profile["geometry"]["consistency_discrepancy_degree"] = 543
            report = composition.evaluate(profile, root)
            self.assertIn(
                "consistency_discrepancy_degree must equal effective degree times witness degree",
                report["blocking_reasons"],
            )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema": "a", "schema": "b"}', encoding="utf-8")
            with self.assertRaisesRegex(composition.CompositionInputError, "duplicate JSON key"):
                composition.load_json_strict(path)

    def test_cli_checked_profile_exits_two_and_never_authorizes(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--profile",
                str(PROFILE_PATH),
                "--repo-root",
                str(MODULE_PATH.resolve().parents[3]),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertFalse(report["capabilities"]["composed_pq128"])
        self.assertFalse(report["capabilities"]["production_authorized"])


if __name__ == "__main__":
    unittest.main()
