#!/usr/bin/env python3
"""Dependency-free tests for the CFW26 equal-half carrier map."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace

import compiler as cc


class CarrierCompilerTests(unittest.TestCase):
    def test_upstream_pins_and_canonical_artifacts(self) -> None:
        manifest, certificate = cc.load_upstream()
        self.assertEqual(manifest["hash_profiles"][cc.PROFILE]["geometry"]["m_constraints"], cc.SOURCE_M)
        self.assertEqual(certificate["relation_manifest_digest_shake256_512"], cc.RELATION_DIGEST)

    def test_production_geometry_exact(self) -> None:
        spec = cc.PRODUCTION_SPEC
        spec.validate()
        self.assertEqual(spec.witness_used, 19_301_403)
        self.assertEqual(spec.public_padding, 33_544_279)
        self.assertEqual(spec.witness_padding, 14_253_029)
        self.assertEqual(spec.zero_rows, 32_398_608)
        self.assertEqual(cc.EMBEDDED_NNZ, 123_057_296)

    def test_parameterized_projection_rederives_frozen_geometry(self) -> None:
        projection = cc.parameterized_projection(
            m=cc.SOURCE_M,
            n=cc.SOURCE_N,
            l=cc.SOURCE_L,
            nnz=cc.SOURCE_NNZ,
            source_relation_digest=cc.RELATION_DIGEST,
        )
        self.assertEqual(projection["carrier"]["ell"], cc.ELL)
        self.assertEqual(projection["carrier"]["matrix_nonzeros_total"], cc.EMBEDDED_NNZ)
        self.assertFalse(any(projection["authority"].values()))
        alternate = cc.parameterized_projection(
            m=cc.SOURCE_M,
            n=cc.SOURCE_N,
            l=cc.SOURCE_L,
            nnz=cc.SOURCE_NNZ,
            source_relation_digest="01" + "00" * 63,
        )
        self.assertNotEqual(projection["projection_digest_shake256_512"], alternate["projection_digest_shake256_512"])

    def test_parameterized_projection_digest_and_capacity_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            cc.parameterized_projection(m=1, n=1, l=0, nnz=1, source_relation_digest="AA" * 64)
        with self.assertRaises(ValueError):
            cc.parameterized_projection(m=1, n=1, l=0, nnz=1, source_relation_digest="00" * 64)
        spec = cc.derive_equal_half_spec(m=31, n=10, l=2, nnz=7)
        self.assertGreaterEqual(spec.side, spec.source_m + spec.witness_padding)

    def test_closed_form_bijection_boundaries(self) -> None:
        result = cc.check_closed_form_bijection()
        self.assertEqual(result["column_domain"], cc.SOURCE_N + 1)
        for column in (0, 1, cc.SOURCE_L, cc.SOURCE_L + 1, cc.SOURCE_N):
            self.assertEqual(cc.unmap_source_column(cc.map_source_column(column)), column)

    def test_padding_columns_have_no_source_preimage(self) -> None:
        for column in (cc.SOURCE_L + 1, cc.ELL - 1, cc.ELL + cc.SOURCE_WITNESS, cc.CARRIER_SIDE - 1):
            with self.assertRaises(ValueError):
                cc.unmap_source_column(column)

    def test_entry_map_preserves_lane_row_coefficient(self) -> None:
        source = cc.SparseEntry("C", cc.SOURCE_M - 1, cc.SOURCE_N, cc.P - 1)
        mapped = cc.map_source_entry(source)
        self.assertEqual((mapped.matrix, mapped.row, mapped.coefficient), (source.matrix, source.row, source.coefficient))
        self.assertEqual(mapped.column, cc.ELL + cc.SOURCE_WITNESS - 1)
        cc.validate_mapped_pair(source, mapped)

    def test_exact_padding_entry_pair(self) -> None:
        first = cc.witness_padding_entries(0)
        last = cc.witness_padding_entries(cc.WITNESS_PADDING - 1)
        self.assertEqual(first[0], cc.SparseEntry("A", cc.SOURCE_M, cc.ELL + cc.SOURCE_WITNESS, 1))
        self.assertEqual(first[1], cc.SparseEntry("B", cc.SOURCE_M, 0, 1))
        self.assertEqual(last[0].row, cc.WITNESS_ZERO_ROW_END - 1)
        self.assertEqual(last[0].column, cc.CARRIER_SIDE - 1)

    def test_tiny_fixture_strict_parser(self) -> None:
        spec, entries = cc.parse_fixture(cc.fixture_bytes())
        self.assertEqual((spec.source_m, spec.source_n, spec.source_l, spec.source_nnz, spec.ell), (3, 5, 2, 8, 4))
        self.assertEqual(len(entries), 8)

    def test_tiny_fixture_positive_parity(self) -> None:
        result = cc.check_fixture_parity()
        self.assertEqual(result, {
            "carrier_side": 8,
            "mapped_source_nonzeros": 8,
            "source_rows": 3,
            "witness_zero_rows": 1,
            "zero_rows": 4,
        })

    def test_stream_rejects_missing_nnz(self) -> None:
        spec, entries = cc.parse_fixture(cc.fixture_bytes())
        with self.assertRaises(ValueError):
            list(cc.source_stream_to_carrier(entries[:-1], spec))

    def test_stream_rejects_duplicate_nnz(self) -> None:
        spec, entries = cc.parse_fixture(cc.fixture_bytes())
        with self.assertRaises(ValueError):
            list(cc.source_stream_to_carrier([entries[0], entries[0], *entries[1:]], spec))

    def test_index_shift_mutation_rejects(self) -> None:
        spec, entries = cc.parse_fixture(cc.fixture_bytes())
        source = entries[2]
        mapped = cc.map_source_entry(source, spec)
        with self.assertRaises(ValueError):
            cc.validate_mapped_pair(source, replace(mapped, column=mapped.column + 1), spec)

    def test_constant_slot_mutation_rejects(self) -> None:
        spec, _entries = cc.parse_fixture(cc.fixture_bytes())
        a, b = cc.witness_padding_entries(0, spec)
        with self.assertRaises(ValueError):
            cc.validate_padding_entry_pair(0, (a, replace(b, column=1)), spec)

    def test_public_padding_mutation_rejects(self) -> None:
        spec, _entries = cc.parse_fixture(cc.fixture_bytes())
        assignment = cc.embed_source_assignment([1, 3, 3, 4, 12, 0], spec)
        v = assignment[: spec.ell]
        v[spec.source_l + 1] = 1
        with self.assertRaises(ValueError):
            cc.validate_public_half(v, spec)

    def test_witness_padding_mutation_rejects(self) -> None:
        spec, _entries = cc.parse_fixture(cc.fixture_bytes())
        assignment = cc.embed_source_assignment([1, 3, 3, 4, 12, 0], spec)
        w = assignment[spec.ell :]
        w[spec.witness_used] = 1
        with self.assertRaises(ValueError):
            cc.validate_witness_padding(w, spec)

    def test_row_matrix_and_coefficient_mutations_reject(self) -> None:
        spec, entries = cc.parse_fixture(cc.fixture_bytes())
        source = entries[0]
        mapped = cc.map_source_entry(source, spec)
        for mutation in (
            replace(mapped, row=mapped.row + 1),
            replace(mapped, matrix="B"),
            replace(mapped, coefficient=2),
        ):
            with self.assertRaises(ValueError):
                cc.validate_mapped_pair(source, mutation, spec)

    def test_fixture_duplicate_missing_and_digest_mutations_reject(self) -> None:
        body = cc.fixture_payload()
        duplicate = json.loads(json.dumps(body))
        duplicate["entries"].insert(1, duplicate["entries"][0])
        duplicate["geometry"]["matrix_nonzeros_total"] += 1
        with self.assertRaises(ValueError):
            cc.parse_fixture(cc.fixture_bytes(duplicate))
        missing = json.loads(json.dumps(body))
        missing["entries"].pop()
        with self.assertRaises(ValueError):
            cc.parse_fixture(cc.fixture_bytes(missing))
        mutated = json.loads(cc.fixture_bytes())
        mutated["relation_digest_shake256_512"] = "00" * 64
        with self.assertRaises(ValueError):
            cc.parse_fixture(cc.canonical_bytes(mutated))

    def test_strict_json_duplicate_key_and_whitespace_reject(self) -> None:
        with self.assertRaises(ValueError):
            cc.parse_canonical_json_bytes(b'{"a":1,"a":1}\n', max_bytes=100)
        with self.assertRaises(ValueError):
            cc.parse_canonical_json_bytes(b'{"a":1} \n', max_bytes=100)

    def test_coefficient_encoding_rejects_zero_modulus_and_uppercase(self) -> None:
        for encoded in ("00" * 8, cc.P.to_bytes(8, "little").hex(), "AA" * 8):
            with self.assertRaises(ValueError):
                cc.decode_coefficient(encoded)

    def test_printed_st2_counterexample(self) -> None:
        result = cc.check_st2_counterexample()
        self.assertEqual(result["s_at_0"], 0)
        self.assertEqual(result["s_at_1"], 0)
        self.assertEqual(result["printed_dot"], cc.P - 1)
        self.assertEqual(result["repaired_pow1_dot"], 0)

    def test_oracle_accounting_is_exact_but_uninstantiated(self) -> None:
        manifest = cc.build_manifest()
        ledger = manifest["section11_encoded_oracles"]
        self.assertEqual((ledger["witness_oracles"], ledger["inner_mask_oracles_3_times_log2_ell_plus_1"], ledger["outer_mask_oracles_log2_ell_plus_1"]), (1, 78, 26))
        self.assertEqual(ledger["total_encoded_oracles"], 105)
        self.assertIsNone(ledger["proof_bytes"])
        self.assertFalse(ledger["pcs_mapping_defined"])

    def test_every_authority_flag_remains_false(self) -> None:
        manifest = cc.build_manifest()
        self.assertTrue(manifest["authority"])
        self.assertFalse(any(manifest["authority"].values()))
        self.assertTrue(manifest["refinement_boundary"]["retained_certificate_stale_on_source_relation_digest_change"])
        self.assertIn("negative baseline", manifest["source_relation"]["status"])

    def test_retained_artifacts_reconstruct_byte_for_byte(self) -> None:
        result = cc.verify_artifacts(verbose=False)
        self.assertEqual(len(result["mutations_rejected"]), 13)
        self.assertEqual(result["section11_encoded_oracles"], 105)


if __name__ == "__main__":
    unittest.main(verbosity=2)
