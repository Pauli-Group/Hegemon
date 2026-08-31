#!/usr/bin/env python3
"""Dependency-free regression suite for the HX448C02 macro-R1CS screen."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("hegemon_hx448c02_odd_field_compiler", HERE / "compiler.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load compiler.py")
compiler = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compiler
SPEC.loader.exec_module(compiler)


class CompilerTests(unittest.TestCase):
    def test_01_exact_transport_geometry(self) -> None:
        self.assertEqual(compiler.STATEMENT_BYTES, 869)
        self.assertEqual(compiler.STATEMENT_BITS, 6_952)
        self.assertEqual(compiler.STATE_WORDS, 50)
        self.assertEqual(compiler.STATE_BITS, 3_200)
        self.assertEqual(compiler.PUBLIC_BITS, 10_152)
        self.assertEqual(compiler.PRIVATE_WORDS, 1_209)
        self.assertEqual(compiler.PRIVATE_BYTES, 9_672)
        self.assertEqual(compiler.PRIVATE_BITS, 77_376)

    def test_02_source_contracts_and_hashes(self) -> None:
        sources = compiler.require_source_contracts()
        self.assertEqual(set(sources), {"scalar", "m4", "m4_lib"})
        manifest = compiler.build_manifest()
        paths = {entry["path"] for entry in manifest["sources"]}
        self.assertIn(compiler.rel(compiler.SCALAR), paths)
        self.assertIn(compiler.rel(compiler.M4), paths)
        self.assertEqual(manifest["source_set_digest_sha512"], compiler.source_set_digest(manifest["sources"]))

    def test_03_source_inventory_mutation_is_detected(self) -> None:
        m4 = compiler.M4.read_text()
        parsed = compiler.rust_counterfeit_matrix(m4)
        self.assertEqual(parsed[:16], [(name, "M4Reject") for name in compiler.MUTATIONS_R1CS])
        self.assertEqual(parsed[16:], [(name, "HostOracleOnly") for name in compiler.MUTATIONS_HOST])
        altered = m4.replace("all_empty_activity", "all_empty_activity_drift", 1)
        self.assertNotEqual(compiler.rust_counterfeit_matrix(altered), parsed)

    def test_04_field_and_sparse_row_canonicality(self) -> None:
        compiler.check_field_encoding()
        for row in compiler.primitive_rows().values():
            compiler.validate_sparse_row(row, 15)
        with self.assertRaises(ValueError):
            compiler.validate_sparse_row(([(1, 1), (1, 2)], [(0, 1)], []), 15)
        with self.assertRaises(ValueError):
            compiler.validate_sparse_row(([(1, compiler.P)], [(0, 1)], []), 15)

    def test_05_every_primitive_row(self) -> None:
        compiler.check_primitive_rows()
        self.assertEqual(set(compiler.primitive_rows()), set(compiler.PRIMITIVES))
        for name, row in compiler.primitive_rows().items():
            self.assertEqual(sum(len(side) for side in row), compiler.PRIMITIVES[name].nonzeros)

    def test_06_hash_reference_kats(self) -> None:
        kats = compiler.check_hash_kats()
        self.assertEqual(len(kats), 6)
        self.assertEqual(len(bytes.fromhex(kats["blake2b448_abc"])), 56)
        self.assertEqual(len(bytes.fromhex(kats["sha3_512_truncate448_abc"])), 56)
        self.assertEqual(len(bytes.fromhex(kats["shake256_448_abc"])), 56)

    def test_07_all_masks_and_modes(self) -> None:
        matrix = compiler.check_activity_matrix()
        self.assertEqual(matrix, {"accepted": 33, "rejected": 47})
        for mask in range(1, 16):
            self.assertTrue(any(compiler.activity_shape_accepts(mode, mask) for mode in range(5)))
        for mode in range(5):
            self.assertTrue(any(compiler.activity_shape_accepts(mode, mask) for mask in range(16)))

    def test_08_counterfeit_matrix_and_host_boundary(self) -> None:
        result = compiler.check_counterfeit_matrix()
        self.assertEqual(result["r1cs_rejected"], 16)
        self.assertEqual(result["host_only_indistinguishable_to_r1cs"], 4)

    def test_09_profile_call_grammar(self) -> None:
        for profile in ("blake2b448-mixed", "sha3-512-split-control"):
            calls = compiler.hash_calls(profile)
            self.assertEqual(len(calls), 83)
            self.assertEqual([call["index"] for call in calls], list(range(83)))
            self.assertEqual(sum(5 if call["select_before_hash"] else 1 for call in calls), 99)

    def test_10_deterministic_geometry(self) -> None:
        for profile in ("blake2b448-mixed", "sha3-512-split-control"):
            left, left_calls = compiler.compile_profile(profile)
            right, right_calls = compiler.compile_profile(profile)
            self.assertEqual(left.geometry(), right.geometry())
            self.assertEqual(left.export_groups(), right.export_groups())
            self.assertEqual(left_calls, right_calls)
            self.assertEqual(left.geometry()["l_public_variables"], 10_152)
            self.assertEqual(left.geometry()["private_transport_variables"], 77_376)

    def test_11_exact_relation_family_coverage(self) -> None:
        manifest = compiler.build_manifest()
        summary = compiler.check_grammars_and_ledgers(manifest)
        self.assertEqual(set(summary), {"blake2b448-mixed", "sha3-512-split-control"})
        for profile in summary.values():
            self.assertEqual(profile["relation_groups"], 36)
            self.assertEqual(profile["hash_calls"], 83)

    def test_12_statement_and_state_grammars(self) -> None:
        compiler.check_statement_parser()
        self.assertEqual(sum(field["bytes"] for field in compiler.STATEMENT_LAYOUT), 869)
        self.assertEqual(sum(field["words"] for field in compiler.STATE_LAYOUT), 50)
        self.assertEqual(compiler.STATEMENT_LAYOUT[-1]["offset_bytes"] + compiler.STATEMENT_LAYOUT[-1]["bytes"], 869)
        self.assertEqual(compiler.STATE_LAYOUT[-1]["offset_words"] + compiler.STATE_LAYOUT[-1]["words"], 50)

    def test_13_all_authority_flags_fail_closed(self) -> None:
        manifest = compiler.build_manifest()
        certificate = compiler.build_certificate(manifest)
        self.assertFalse(any(manifest["authority"].values()))
        self.assertFalse(certificate["production_authorized"])
        self.assertFalse(certificate["full_production_relation_compiled"])
        self.assertFalse(certificate["complete_zero_knowledge_proved"])
        self.assertFalse(certificate["composed_qrom_pq128_proved"])
        self.assertIsNone(certificate["measured_proof_bytes"])
        self.assertEqual(manifest["host_only_boundary"]["compiled_rows"], 0)
        self.assertEqual(manifest["host_only_boundary"]["groups"], compiler.HOST_GROUPS)

    def test_14_canonical_json_rule(self) -> None:
        for path in (compiler.MANIFEST_PATH, compiler.CERTIFICATE_PATH):
            raw = path.read_bytes()
            self.assertTrue(raw.endswith(b"\n"))
            self.assertFalse(raw.endswith(b"\n\n"))
            decoded = json.loads(raw)
            self.assertEqual(raw, compiler.canonical_bytes(decoded))

    def test_15_retained_artifacts_verify(self) -> None:
        result = compiler.verify_artifacts(verbose=False)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["counterfeit_matrix"]["r1cs_rejected"], 16)


if __name__ == "__main__":
    unittest.main(verbosity=2)
