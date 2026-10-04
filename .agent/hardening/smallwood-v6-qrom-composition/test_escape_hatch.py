import json
import os
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path

from escape_hatch import (
    COLLISION_ALPHA,
    CURRENT_FIXED_SECRET_BYTES,
    KMAC_1568_SECRET_BYTES,
    LOW_QUERIES,
    ROLE_SPECS,
    SHA2_TYPED_QRO_SECRET_BYTES,
    WORK_QUERIES,
    additive_compatibility_statement_bytes,
    additive_compatibility_statement_limbs,
    blake2b400_schedule,
    full_sha512_schedule,
    hmac_sha512_schedule,
    ideal_qro_collision_passes,
    kmac_tuplehash_schedule,
    maximum_passing_collision_power_of_two_query_exponent,
    maximum_passing_power_of_two_query_exponent,
    measure_reprogram_best_case_multiplier,
    minimum_byte_aligned_collision_output_bits,
    minimum_collision_output_bits,
    minimum_denominator_bits,
    fixed_target_compatibility_statement_bytes,
    replacement_statement_bytes,
    redesigned_statement_limbs,
    report,
    role_registry_digest,
    role_registry_is_valid,
    secret_prefix_qprf_passes,
    sha512_left400_schedule,
    split_sha3_shake_schedule,
)


class EscapeHatchTests(unittest.TestCase):
    def test_collision_width_gate_is_exact_integer_arithmetic(self):
        self.assertEqual(COLLISION_ALPHA, 648)
        self.assertEqual(minimum_collision_output_bits(WORK_QUERIES, 1), 395)
        self.assertEqual(
            minimum_byte_aligned_collision_output_bits(WORK_QUERIES, 1), 400
        )
        self.assertFalse(ideal_qro_collision_passes(392, WORK_QUERIES, 1))
        self.assertTrue(ideal_qro_collision_passes(400, WORK_QUERIES, 1))
        self.assertTrue(ideal_qro_collision_passes(400, LOW_QUERIES, 128))

    def test_mixed_width_statement_geometry_distinguishes_migration(self):
        self.assertEqual(replacement_statement_bytes(50), 809)
        self.assertEqual(redesigned_statement_limbs(50), 116)
        self.assertEqual(fixed_target_compatibility_statement_bytes(50), 803)
        self.assertEqual(additive_compatibility_statement_bytes(50), 953)
        self.assertEqual(additive_compatibility_statement_limbs(50), 137)
        self.assertEqual(replacement_statement_bytes(56), 893)

    def test_typed_sha512_left400_source_schedule(self):
        schedule = sha512_left400_schedule()
        self.assertEqual(schedule["logical_invocations"], 79)
        self.assertEqual(schedule["physical_calls"], 83)
        self.assertEqual(schedule["compressions"], 204)
        self.assertEqual(schedule["compressions_by_role"]["intent"], 7)
        terms = report()["sha512_left400_typed_qro_candidate"][
            "idealized_low_budget_terms"
        ]
        self.assertEqual(terms["epoch_secret_prefix_numerator"], 15)
        self.assertEqual(terms["epoch_secret_prefix_denominator"], 1 << 159)
        self.assertFalse(terms["full_15_role_hash_composition_available"])

    def test_fifteen_role_registry_is_domain_separated_and_fail_closed(self):
        self.assertEqual(len(ROLE_SPECS), 15)
        self.assertTrue(role_registry_is_valid())
        self.assertEqual(len(role_registry_digest()), 128)
        mutated = list(ROLE_SPECS)
        mutated[1] = replace(mutated[1], domains=mutated[0].domains)
        self.assertFalse(role_registry_is_valid(tuple(mutated)))
        self.assertNotEqual(role_registry_digest(tuple(mutated)), role_registry_digest())

    def test_split_sha3_shake_schedule(self):
        schedule = split_sha3_shake_schedule()
        self.assertEqual(schedule["sha3_512_permutations"], 50)
        self.assertEqual(schedule["shake256_permutations"], 106)
        self.assertEqual(schedule["permutations"], 156)

    def test_hmac_hkdf_lower_bound_schedule(self):
        schedule = hmac_sha512_schedule()
        self.assertEqual(schedule["raw_sha512_compressions"], 188)
        self.assertEqual(schedule["hmac_sha512_compressions"], 44)
        self.assertEqual(schedule["compressions"], 232)

    def test_kmac_tuplehash_preserves_intent_header_binding(self):
        schedule = kmac_tuplehash_schedule()
        self.assertEqual(schedule["secret_kmac_permutations"], 52)
        self.assertEqual(schedule["public_tuplehash_permutations"], 174)
        self.assertEqual(schedule["permutations"], 226)
        self.assertEqual(
            schedule["public_tuplehash_permutations_by_role"]["intent"], 8
        )

    def test_blake2b400_source_schedule(self):
        schedule = blake2b400_schedule()
        self.assertEqual(schedule["keyed_compressions"], 40)
        self.assertEqual(schedule["public_compressions"], 108)
        self.assertEqual(schedule["compressions"], 148)

    def test_full_sha512_costs_more_wire_and_compressions(self):
        self.assertEqual(additive_compatibility_statement_bytes(64), 1_149)
        self.assertEqual(full_sha512_schedule()["compressions"], 210)

    def test_key_material_deltas_are_exact(self):
        self.assertEqual(CURRENT_FIXED_SECRET_BYTES, 288)
        self.assertEqual(SHA2_TYPED_QRO_SECRET_BYTES, 512)
        self.assertEqual(SHA2_TYPED_QRO_SECRET_BYTES - CURRENT_FIXED_SECRET_BYTES, 224)
        self.assertEqual(KMAC_1568_SECRET_BYTES, 1_568)
        self.assertEqual(KMAC_1568_SECRET_BYTES - CURRENT_FIXED_SECRET_BYTES, 1_280)

    def test_lower_physical_query_caps_do_not_change_the_claim(self):
        self.assertEqual(
            maximum_passing_collision_power_of_two_query_exponent(384, 128), 82
        )
        self.assertEqual(
            maximum_passing_collision_power_of_two_query_exponent(384, 1), 124
        )
        self.assertFalse(secret_prefix_qprf_passes(384, 1, 1 << 63))
        self.assertTrue(secret_prefix_qprf_passes(384, 1, 1 << 62))
        self.assertEqual(maximum_passing_power_of_two_query_exponent(384, 1), 62)
        self.assertEqual(
            maximum_passing_power_of_two_query_exponent(384, 1 << 33), 29
        )
        self.assertEqual(
            maximum_passing_power_of_two_query_exponent(384, 15 * (1 << 32)), 27
        )
        self.assertEqual(
            maximum_passing_power_of_two_query_exponent(448, 1 << 33), 61
        )
        self.assertEqual(
            maximum_passing_power_of_two_query_exponent(448, 15 * (1 << 32)), 59
        )

    def test_lnp_lite_leading_term_needs_131_bits(self):
        self.assertEqual(minimum_denominator_bits(5), 131)
        self.assertEqual(minimum_denominator_bits(5 * WORK_QUERIES), 259)
        multiplier = measure_reprogram_best_case_multiplier(LOW_QUERIES)
        self.assertEqual(multiplier, (2 * LOW_QUERIES + 2) ** 2)
        self.assertEqual(minimum_denominator_bits(5 * multiplier), 261)
        self.assertEqual(minimum_denominator_bits(3 * multiplier), 260)

    def test_report_is_valid_negative_and_all_authority_false(self):
        result = report()
        self.assertEqual(result["status"], "valid-negative")
        self.assertTrue(result["role_registry"]["valid"])
        self.assertEqual(
            result["lazer_pack_lnp_lite"][
                "shake128_generic_quantum_preimage_cap_bits"
            ],
            64,
        )
        self.assertTrue(result["conditional_query_caps"]["definition_changed"] is False)
        self.assertTrue(result["conditional_query_caps"]["consensus_enforceable"] is False)
        self.assertTrue(all(value is False for value in result["capabilities"].values()))

    def test_cli_emits_report_and_exits_two(self):
        script = Path(__file__).with_name("escape_hatch.py")
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, str(script)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(completed.returncode, 2)
        parsed = json.loads(completed.stdout)
        self.assertEqual(parsed["status"], "valid-negative")
        self.assertFalse(parsed["capabilities"]["production_authorized"])


if __name__ == "__main__":
    unittest.main()
