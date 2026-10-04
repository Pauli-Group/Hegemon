import importlib.util
import json
import sys
import unittest
from fractions import Fraction
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("outer_spartan_distribution_audit.py")
SPEC = importlib.util.spec_from_file_location("outer_spartan_distribution_audit", MODULE_PATH)
audit = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class EndpointDistributionTests(unittest.TestCase):
    def test_all_conditional_shapes_and_translation_formulas(self):
        for field in (audit.GF4, audit.GF8):
            for u, v in ((1, 2), (1, 1), (1, 0), (0, 0)):
                self.assertTrue(audit.endpoint_mass_shape_holds(field, u, v))
                counts = audit.endpoint_distribution(field, u, v)
                for delta in ((0, 0, 1), (1, 0, 0)):
                    self.assertEqual(
                        audit.translated_distance(field, counts, delta),
                        audit.predicted_endpoint_distance(field, u, v, delta),
                    )

    def test_generic_and_degenerate_exact_distances(self):
        q = audit.GF8.order
        generic = audit.endpoint_distribution(audit.GF8, 1, 2)
        equal = audit.endpoint_distribution(audit.GF8, 1, 1)
        one_zero = audit.endpoint_distribution(audit.GF8, 1, 0)
        self.assertEqual(audit.translated_distance(audit.GF8, generic, (0, 0, 1)), Fraction(1, q))
        self.assertEqual(audit.translated_distance(audit.GF8, equal, (1, 0, 0)), Fraction(2 * (q - 1), q**3))
        self.assertEqual(audit.translated_distance(audit.GF8, one_zero, (0, 0, 1)), Fraction(1))

    def test_eq_weight_event_formulas(self):
        self.assertTrue(audit.verify_eq_weight_event_formulas(audit.GF4))
        self.assertTrue(audit.verify_eq_weight_event_formulas(audit.GF8))

    def test_two_base_field_weights_cannot_hide_degree_three_extension_endpoint(self):
        result = audit.mixed_extension_two_weight_counterexample(audit.GF4)
        self.assertEqual(result["maximum_two_weight_span_dimension"], 2)
        self.assertEqual(result["extension_degree"], 3)
        self.assertEqual(result["translation_outside_span_tv"], "1/1")
        self.assertTrue(result["passed"])


class LibraRankTests(unittest.TestCase):
    def test_nonzero_beta_rank_and_zero_beta_collapse(self):
        field = audit.GF8
        z = [0, 1, 2]
        r = [3, 2, 1]
        self.assertEqual(audit.matrix_rank(field, audit.libra_mask_matrix(field, z, r, 2)), 7)
        self.assertLessEqual(audit.matrix_rank(field, audit.libra_mask_matrix(field, z, r, 0)), 2)

    def test_exhaustive_small_field_rank_formula(self):
        self.assertTrue(audit.verify_libra_rank_formula(audit.GF4, 2))


class CertificateTests(unittest.TestCase):
    def test_frozen_certificate_matches(self):
        frozen = json.loads(Path(__file__).with_name("certificate.json").read_text())
        self.assertEqual(frozen, audit.run_audit())

    def test_fail_closed_claims(self):
        certificate = audit.run_audit()
        self.assertFalse(certificate["claims"]["complete_zk"])
        self.assertFalse(certificate["claims"]["strict_pq128"])
        self.assertFalse(certificate["dummy_wire_openings"]["sufficient_rank_proved"])
        self.assertFalse(
            certificate["endpoint_distribution"]["strict_mixed_field_endpoint"]
            ["current_two_rows_strict_statistical_zk"]
        )
        self.assertFalse(certificate["decision"]["frontier_eligible"])

    def test_validator_rejects_reward_hacks(self):
        certificate = json.loads(json.dumps(audit.run_audit()))
        certificate["claims"]["complete_zk"] = True
        with self.assertRaisesRegex(ValueError, "reward hack"):
            audit.validate_certificate(certificate)

        certificate = json.loads(json.dumps(audit.run_audit()))
        certificate["dummy_wire_openings"]["sufficient_rank_proved"] = True
        with self.assertRaisesRegex(ValueError, "not proved"):
            audit.validate_certificate(certificate)


if __name__ == "__main__":
    unittest.main()
