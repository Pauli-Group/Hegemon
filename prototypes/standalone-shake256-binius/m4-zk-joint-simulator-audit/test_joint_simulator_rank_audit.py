import importlib.util
import json
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("joint_simulator_rank_audit.py")
SPEC = importlib.util.spec_from_file_location("joint_simulator_rank_audit", MODULE_PATH)
audit = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class FieldTests(unittest.TestCase):
    def test_ghash_field_identities_and_inverses(self):
        values = [1, 2, 0x87, audit.deterministic_field("field:a")]
        for value in values:
            self.assertEqual(audit.gf_mul(value, 1), value)
            self.assertEqual(audit.gf_mul(value, 0), 0)
            if value:
                self.assertEqual(audit.gf_mul(value, audit.gf_inv(value)), 1)

    def test_ghash_reduction_polynomial(self):
        self.assertEqual(audit.gf_mul(1 << 127, 2), audit.GHASH_REDUCTION)


class RankTests(unittest.TestCase):
    def setUp(self):
        _, self.c = audit.accepted_coefficient("tests")
        self.transparent = audit.transparent_coefficients("tests", 5, self.c)

    def test_ideal_joint_view_closes_for_nonzero_c(self):
        view = audit.build_joint_view(self.transparent, self.c, 3)
        self.assertTrue(view.containment()[0])

    def test_constructive_mask_for_arbitrary_delta(self):
        trace_delta = [audit.deterministic_field(f"dt:{i}") for i in range(5)]
        message_delta = [audit.deterministic_field(f"dm:{i}") for i in range(3)]
        self.assertTrue(
            audit.constructive_joint_mask_check(
                self.transparent, self.c, trace_delta, message_delta
            )
        )

    def test_current_clear_precommit_claim_leaks(self):
        key_row = [1, 2, 3, 4]
        view = audit.build_joint_view(
            self.transparent,
            self.c,
            3,
            clear_claim_key_rows=[key_row],
            claim_blinder_rows=[[]],
        )
        self.assertFalse(view.containment()[0])

    def test_one_unused_blinder_repairs_exactly_rank_one(self):
        key_row = [1, 2, 3, 4]
        view = audit.build_joint_view(
            self.transparent,
            self.c,
            3,
            clear_claim_key_rows=[key_row],
            claim_blinder_rows=[[5]],
        )
        self.assertTrue(view.containment()[0])

    def test_zero_repair_coefficient_fails(self):
        view = audit.build_joint_view(
            self.transparent,
            self.c,
            3,
            clear_claim_key_rows=[[1, 2, 3, 4]],
            claim_blinder_rows=[[0]],
        )
        self.assertFalse(view.containment()[0])

    def test_two_independent_claims_need_blinder_rank_two(self):
        key_rows = [[1, 0, 0, 0], [0, 1, 0, 0]]
        one = audit.build_joint_view(
            self.transparent,
            self.c,
            3,
            clear_claim_key_rows=key_rows,
            claim_blinder_rows=[[1], [1]],
        )
        two = audit.build_joint_view(
            self.transparent,
            self.c,
            3,
            clear_claim_key_rows=key_rows,
            claim_blinder_rows=[[1, 0], [0, 1]],
        )
        self.assertFalse(one.containment()[0])
        self.assertTrue(two.containment()[0])

    def test_grouped_relation_removes_component_leak(self):
        # No component precommit row is emitted; the total claim is already verifier-derived.
        grouped = audit.build_joint_view(self.transparent, self.c, 3)
        self.assertTrue(grouped.containment()[0])

    def test_zero_c_missing_vector_mask_and_key_reuse_fail(self):
        zero_c = audit.build_joint_view([1, 1], 0, 1)
        missing_vector_mask = audit.build_joint_view(
            self.transparent, self.c, 3, include_oracle_masks=False
        )
        self.assertFalse(zero_c.containment()[0])
        self.assertFalse(missing_vector_mask.containment()[0])
        self.assertFalse(audit.build_key_reuse_view().containment()[0])

    def test_basefold_mask_inner_product_degeneracies_are_visible(self):
        relation = [1, 0, 1]
        independent = [0, 1, 1]
        generic = audit.build_basefold_scalar_view(relation, independent, 7)
        gamma_zero = audit.build_basefold_scalar_view(relation, independent, 0)
        dependent = audit.build_basefold_scalar_view(relation, relation, 7)
        self.assertTrue(generic.containment()[0])
        self.assertFalse(gamma_zero.containment()[0])
        self.assertFalse(dependent.containment()[0])


class CertificateTests(unittest.TestCase):
    def test_frozen_certificate_matches_executable_audit(self):
        frozen = json.loads(Path(__file__).with_name("certificate.json").read_text())
        self.assertEqual(frozen, audit.run_audit())

    def test_live_source_bound_fail_closed_certificate(self):
        certificate = audit.run_audit()
        self.assertTrue(certificate["source_checks"]["all_passed"])
        self.assertFalse(certificate["claims"]["complete_zk"])
        self.assertFalse(certificate["rank_audit"]["current_patch_clear_rank_closed"])
        self.assertTrue(
            certificate["rank_audit"]["conditional_grouped_relation_clear_rank_closed"]
        )
        self.assertEqual(
            certificate["rank_audit"]["grouped_relation_feasibility"][
                "predicted_serialized_delta_bytes"
            ],
            -16,
        )

    def test_validator_rejects_reward_hacked_complete_zk(self):
        certificate = audit.run_audit()
        certificate = json.loads(json.dumps(certificate))
        certificate["claims"]["complete_zk"] = True
        with self.assertRaisesRegex(ValueError, "complete_zk"):
            audit.validate_certificate(certificate)

    def test_validator_rejects_frontier_without_complete_zk(self):
        certificate = audit.run_audit()
        certificate = json.loads(json.dumps(certificate))
        certificate["decision"]["frontier_eligible"] = True
        with self.assertRaisesRegex(ValueError, "frontier"):
            audit.validate_certificate(certificate)


if __name__ == "__main__":
    unittest.main()
