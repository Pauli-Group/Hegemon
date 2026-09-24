import copy
import importlib.util
import json
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("mith_backup_checker", HERE / "checker.py")
checker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(checker)


class MithBackupScreenTests(unittest.TestCase):
    def test_certificate_is_canonical_and_exact(self):
        raw = (HERE / "source_certificate.json").read_bytes()
        parsed = json.loads(raw)
        self.assertEqual(parsed, checker.build_certificate())
        self.assertEqual(raw, checker.canonical_bytes(parsed))
        self.assertEqual(checker.verify_certificate(parsed), [])

    def test_all_authority_is_false(self):
        cert = checker.build_certificate()
        self.assertTrue(cert["all_authority_false"])
        self.assertEqual(set(cert["authority"]), set(checker.AUTHORITY_KEYS))
        self.assertFalse(any(cert["authority"].values()))
        self.assertFalse(cert["verdict"]["backup_authorized"])
        self.assertIsNone(cert["verdict"]["mith_or_voleith_winner"])

    def test_relation_geometry_is_only_a_lower_bound(self):
        geometry = checker.build_certificate()["relation_geometry"]
        self.assertEqual(geometry["m_constraints_lower_bound"], 20_457_227)
        self.assertEqual(geometry["n_nonconstant_variables_lower_bound"], 19_311_555)
        self.assertEqual(geometry["l_public_variables"], 10_152)
        self.assertFalse(geometry["fresh_all_w64_manifest_closure_compiled"])

    def test_quicksilver_extension_degree_is_exact(self):
        self.assertEqual(checker.minimum_extension_degree(), 3)
        self.assertGreater((checker.M_CONSTRAINTS + 3) * (1 << 128), checker.P**2)
        self.assertLessEqual((checker.M_CONSTRAINTS + 3) * (1 << 128), checker.P**3)

    def test_exact_size_arithmetic(self):
        size = checker.build_certificate()["size_screen"]
        self.assertEqual(size["quicksilver_designated_verifier_correction_floor"]["bytes"], 163_657_816)
        self.assertEqual(size["voleith_large_odd_field_source_profile"]["projected_payload_bytes"], 490_973_448)
        self.assertEqual(size["zkboo_direct_arithmetic_view_screen"]["repetitions_for_classical_128_soundness"], 219)
        self.assertEqual(size["zkboo_direct_arithmetic_view_screen"]["bytes"], 139_314_250_032)
        self.assertTrue(all(item["exceeds_cap"] for item in size.values() if isinstance(item, dict) and "exceeds_cap" in item))

    def test_generic_qrom_is_not_claimed(self):
        candidates = {candidate["id"]: candidate for candidate in checker.build_certificate()["candidates"]}
        self.assertFalse(candidates["quicksilver-designated-verifier"]["finite_qrom_theorem_applicable"])
        self.assertFalse(candidates["vole-in-the-head-large-odd-field"]["finite_qrom_theorem_applicable"])
        self.assertFalse(candidates["zkboo-picnic-style-generic"]["finite_qrom_theorem_applicable"])
        self.assertFalse(candidates["faest-v2-fixed-relation-control"]["finite_qrom_theorem_applicable"])
        self.assertEqual(candidates["aurora-cms19-iop-control"]["status"], "separate-existing-iop-track-not-admitted-here")

    def test_every_declared_mutation_is_rejected(self):
        self.assertEqual(checker.run_mutations(), [])
        self.assertGreaterEqual(len(checker.build_mutations()), 35)

    def test_individual_authority_flip_is_rejected(self):
        for key in checker.AUTHORITY_KEYS:
            changed = copy.deepcopy(checker.build_certificate())
            changed["authority"][key] = True
            self.assertTrue(checker.verify_certificate(changed), key)

    def test_source_pins_are_unique_and_well_formed(self):
        ids = [source["id"] for source in checker.SOURCE_PINS]
        self.assertEqual(len(ids), len(set(ids)))
        for source in checker.SOURCE_PINS:
            self.assertEqual(len(source["sha256"]), 64)
            int(source["sha256"], 16)
            self.assertTrue(source["url"].startswith("https://"))
            self.assertGreater(source["bytes"], 0)

    def test_checked_in_source_pins_match(self):
        self.assertEqual(checker.verify_repo_pins(), [])

    def test_mutation_file_is_canonical(self):
        raw = (HERE / "mutation_corpus.json").read_bytes()
        parsed = json.loads(raw)
        self.assertEqual(parsed, checker.build_mutations())
        self.assertEqual(raw, checker.canonical_bytes(parsed))

    def test_retained_artifact_hashes_match(self):
        self.assertEqual(checker.verify_artifact_hashes(), [])


if __name__ == "__main__":
    unittest.main()
