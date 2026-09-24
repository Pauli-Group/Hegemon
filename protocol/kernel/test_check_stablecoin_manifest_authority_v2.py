#!/usr/bin/env python3
"""Adversarial tests for the inactive all-W64 manifest V2 source gate."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
CHECKER_PATH = HERE / "check_stablecoin_manifest_authority_v2.py"
SPEC = importlib.util.spec_from_file_location("manifest_v2_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load V2 checker")
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


class StablecoinManifestAuthorityV2CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = checker.MODULE.read_text(encoding="utf-8")
        cls.lib = checker.LIB.read_text(encoding="utf-8")
        cls.live_manifest = checker.LIVE_MANIFEST.read_text(encoding="utf-8")
        cls.legacy = checker.LEGACY_MODULE.read_text(encoding="utf-8")
        cls.successor_gate = checker.SUCCESSOR_GATE.read_text(encoding="utf-8")
        cls.selection = json.loads(checker.SUCCESSOR_SELECTION.read_text(encoding="utf-8"))

    def source_check(self, **overrides: object) -> None:
        checker.source_checks_text(
            overrides.get("module", self.module),
            overrides.get("lib", self.lib),
            overrides.get("live_manifest", self.live_manifest),
            overrides.get("legacy", self.legacy),
            overrides.get("successor_gate", self.successor_gate),
            overrides.get("selection", self.selection),
        )

    def test_live_checker_passes(self) -> None:
        result = checker.check()
        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["production_authorized"])
        self.assertEqual(result["authority_flags_false"], 12)
        self.assertEqual(result["mutations"]["row_byte_mutations"], 215)
        self.assertEqual(result["mutations"]["path_byte_mutations"], 256)

    def test_each_authority_flag_true_rejects(self) -> None:
        for name in checker.AUTHORITY_FLAGS:
            marker = (
                f"pub const STABLECOIN_MANIFEST_AUTHORITY_V2_{name}: bool = false;"
            )
            with self.subTest(name=name):
                self.assertIn(marker, self.module)
                with self.assertRaises(checker.Reject):
                    self.source_check(module=self.module.replace(marker, marker[:-6] + "true;", 1))

    def test_module_promotion_or_live_root_integration_rejects(self) -> None:
        with self.assertRaises(checker.Reject):
            self.source_check(
                lib=self.lib
                + "\npub use stablecoin_manifest_authority_v2::StablecoinManifestRootV2;\n"
            )
        marker = "compute_kernel_global_root(vec![(FAMILY_SHIELDED_POOL, shielded_family_root())])"
        self.assertIn(marker, self.live_manifest)
        with self.assertRaises(checker.Reject):
            self.source_check(
                live_manifest=self.live_manifest.replace(
                    marker,
                    marker + ".map(|_| stablecoin_manifest_authority_v2)",
                    1,
                )
            )

    def test_successor_registry_or_selection_activation_rejects(self) -> None:
        marker = "AUTHORIZED_PROFILES: dict[str, AuthorizedProfile] = {}"
        self.assertIn(marker, self.successor_gate)
        with self.assertRaises(checker.Reject):
            self.source_check(
                successor_gate=self.successor_gate.replace(marker, marker[:-2] + '{"v2": None}', 1)
            )
        activated = dict(self.selection)
        activated["selection"] = "selected"
        activated["profile_id"] = "forged-v2"
        with self.assertRaises(checker.Reject):
            self.source_check(selection=activated)

    def test_rust_kat_mutation_rejects_cross_language_gate(self) -> None:
        marker = "0x86, 0x6d, 0x20, 0x13"
        self.assertIn(marker, self.module)
        changed = self.module.replace(marker, "0x87, 0x6d, 0x20, 0x13", 1)
        with self.assertRaises(checker.Reject):
            checker.semantic_checks(changed)

    def test_exact_witness_and_row_decoders_reject_malformed_bytes(self) -> None:
        entries = [checker.sample_entry(1001 + index) for index in range(checker.CAP)]
        proof = checker.witness(entries, 7)
        for changed in (proof[:-1], proof + b"\x00"):
            with self.assertRaises(checker.Reject):
                checker.root_from_witness(changed)
        row = bytearray(entries[0].encode())
        row[72] = 2
        with self.assertRaises(checker.Reject):
            checker.Entry.decode(bytes(row))
        row = bytearray(entries[0].encode())
        row[72] = 0
        with self.assertRaises(checker.Reject):
            checker.Entry.decode(bytes(row))

    def test_constructor_width_conversion_has_no_source_api(self) -> None:
        lowered = self.module.lower()
        self.assertNotIn("legacy48_to", lowered)
        self.assertNotIn("fresh56_to", lowered)
        self.assertNotIn("w64_to_fresh56", lowered)
        self.assertNotIn("[u8; 56]", self.module)


if __name__ == "__main__":
    unittest.main()
