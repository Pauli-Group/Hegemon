from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("check_candidate", HERE / "check_candidate.py")
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class CandidateCheckerTests(unittest.TestCase):
    def base(self) -> dict:
        return json.loads((HERE / "candidate.json").read_text())

    def write(self, value: object) -> Path:
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with temporary:
            json.dump(value, temporary)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return Path(temporary.name)

    def test_valid_negative_certificate(self) -> None:
        result = CHECK.validate_candidate()
        self.assertTrue(result["candidate_valid"])
        self.assertFalse(result["complete_zk"])
        self.assertFalse(result["production_authorized"])

    def test_rejects_complete_zk_flip(self) -> None:
        value = self.base()
        value["capabilities"]["complete_zk"] = True
        with self.assertRaisesRegex(CHECK.CandidateError, "complete_zk"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_assumption_flip_without_authority(self) -> None:
        value = self.base()
        value["assumptions"]["joint_simulator_implemented"] = True
        with self.assertRaisesRegex(CHECK.CandidateError, "assumption"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_fabricated_total_for_unfrozen_geometry(self) -> None:
        value = self.base()
        value["overhead"]["total_bytes"] = 12345
        with self.assertRaisesRegex(CHECK.CandidateError, "total_bytes"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_source_digest_mismatch(self) -> None:
        value = self.base()
        value["source_sha256"] = "00" * 32
        with self.assertRaisesRegex(CHECK.CandidateError, "source_sha256"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_endpoint_rank_rewrite(self) -> None:
        value = self.base()
        value["endpoint"]["rejected_augmented_rank"] = 2
        with self.assertRaisesRegex(CHECK.CandidateError, "augmented rank"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_systematic_leaf_invariant_rewrite(self) -> None:
        value = self.base()
        value["provisional_live_encoder_no_go"]["leaf_zero_equals_message_zero"] = False
        with self.assertRaisesRegex(CHECK.CandidateError, "leaf_zero_equals_message_zero"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_pair_sampling_probability_rewrite(self) -> None:
        value = self.base()
        value["provisional_live_encoder_no_go"]["leaf_zero_event_probability"] = "q/2^26"
        with self.assertRaisesRegex(CHECK.CandidateError, "event probability"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_raw_pi_omega_combination_claim(self) -> None:
        value = self.base()
        value["provisional_live_encoder_no_go"]["wire_exposure"][
            "affine_combined_before_serialization"
        ] = True
        with self.assertRaisesRegex(CHECK.CandidateError, "wire exposure"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_nominal_query_count_as_mask_degree(self) -> None:
        value = self.base()
        value["masked_codeword_repair"]["required_b128_mask_coefficients"] = "query_count"
        with self.assertRaisesRegex(CHECK.CandidateError, "full opening inventory"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_diamond_dimension_doubling_rewrite(self) -> None:
        value = self.base()
        value["preferred_complete_zk_repair"]["setup_code_dimension_multiplier"] = 1
        with self.assertRaisesRegex(CHECK.CandidateError, "dimension_multiplier"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_diamond_backend_match_promotion(self) -> None:
        value = self.base()
        value["preferred_complete_zk_repair"][
            "current_mixed_b128_e384_backend_matches"
        ] = True
        with self.assertRaisesRegex(CHECK.CandidateError, "current_mixed_b128_e384"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_ad_hoc_repair_authority_flip(self) -> None:
        value = self.base()
        value["masked_codeword_repair"]["selected_implementation_authority"] = True
        with self.assertRaisesRegex(CHECK.CandidateError, "selected authority"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_unimplemented_repair_promotion(self) -> None:
        value = self.base()
        value["masked_codeword_repair"]["implemented_in_live_backend"] = True
        with self.assertRaisesRegex(CHECK.CandidateError, "implemented_in_live_backend"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_unproved_relation_free_tail_promotion(self) -> None:
        value = self.base()
        value["masked_codeword_repair"]["relation_free_tail_refinement_proved"] = True
        value["masked_codeword_repair"]["spare_degree_fit_established"] = True
        with self.assertRaisesRegex(CHECK.CandidateError, "relation_free_tail_refinement_proved"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_provisional_encoder_digest_rewrite(self) -> None:
        value = self.base()
        value["provisional_live_encoder_no_go"]["encoder_source_sha256"] = "00" * 32
        with self.assertRaisesRegex(CHECK.CandidateError, "encoder_source_sha256"):
            CHECK.validate_candidate(self.write(value))

    def test_rejects_duplicate_json_key(self) -> None:
        raw = (HERE / "candidate.json").read_text()
        duplicate = raw.replace(
            '"complete_zk": false,',
            '"complete_zk": false, "complete_zk": false,',
            1,
        )
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with temporary:
            temporary.write(duplicate)
        path = Path(temporary.name)
        self.addCleanup(path.unlink, missing_ok=True)
        with self.assertRaisesRegex(CHECK.CandidateError, "duplicate JSON key"):
            CHECK.validate_candidate(path)

    def test_recorded_digest_is_exact_current_source(self) -> None:
        value = self.base()
        source = CHECK.REPO_ROOT / value["source"]
        self.assertEqual(value["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
