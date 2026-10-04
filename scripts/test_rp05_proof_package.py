#!/usr/bin/env python3
"""Unit tests for the RP05 proof-package DAG handling."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rp05_proof_package as package


class ProofPackageDagTests(unittest.TestCase):
    def test_lake_adoption_is_limited_to_the_257_original_formal_modules(self) -> None:
        records = []
        for index in range(package.LAKE_FORMAL_COUNT):
            root = "formal/crypto/" if index < 227 else "formal/lean/"
            module = f"HegemonCrypto.Original{index}" if index < 227 else f"Hegemon.Original{index}"
            records.append({"module": module, "source": root + package.module_path(module).as_posix()})
        records.extend({"module": f"Rp05.New{i}", "source": f"formal/rp05/Rp05/New{i}.lean"}
                       for i in range(5))
        self.assertEqual(len(package.lake_formal_records({"sources": records})), 257)
        with self.assertRaisesRegex(RuntimeError, "exactly 257"):
            package.lake_formal_records({"sources": records[:-5] + [
                {"module": "HegemonCrypto.Extra", "source": "formal/crypto/HegemonCrypto/Extra.lean"}
            ]})

    def test_lake_rehash_batches_bisect_stale_targets_and_fail_closed(self) -> None:
        calls = []
        def lake_result(command, **kwargs):
            calls.append(command)
            status = 1 if any("+Stale:" in arg for arg in command) else 0
            return package.subprocess.CompletedProcess(command, status, "", "stale" if status else "")

        with patch.object(package.subprocess, "run", side_effect=lake_result):
            validated = package.lake_rehash_groups(["A", "Stale", "B", "C"], "lake")
        self.assertEqual(set(validated), {"A", "B", "C"})
        self.assertEqual(calls[0][1:5], ["--rehash", "--no-build", "--no-cache", "build"])
        self.assertGreater(len(calls), 1)
        with patch.object(package.subprocess, "run", return_value=
                          package.subprocess.CompletedProcess([], 3, "", "stale")):
            rejected = package.lake_rehash_groups(["A", "B", "C"], "lake")
        self.assertEqual(rejected, {})

    def test_lake_trace_accepts_only_the_pinned_implicit_core_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            core = root / "toolchain/lib/lean"
            lean = root / "toolchain/bin/lean"
            expected = [root / "project", root / "formal", core]
            lake_path = os.pathsep.join(str(path) for path in expected)
            saved = os.pathsep.join(str(path) for path in expected[:-1])
            self.assertTrue(package.lake_trace_path_matches(
                f".> LEAN_PATH={saved} {lean} Main.lean", lake_path, str(lean)))
            reordered = os.pathsep.join(str(path) for path in reversed(expected[:-1]))
            self.assertFalse(package.lake_trace_path_matches(
                f".> LEAN_PATH={reordered} {lean} Main.lean", lake_path, str(lean)))
            wrong_core = os.pathsep.join([*(str(path) for path in expected[:-1]),
                                          str(root / "other/lib/lean")])
            self.assertFalse(package.lake_trace_path_matches(
                f".> LEAN_PATH={wrong_core} {lean} Main.lean", lake_path, str(lean)))

    def test_lake_trace_records_actual_options_and_requires_output_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "formal/crypto/M.lean"
            source.parent.mkdir(parents=True)
            source.write_text("-- source\n")
            target = root / "lake/lib/lean/M.olean"
            target.parent.mkdir(parents=True)
            lean = root / "toolchain/bin/lean"
            core = root / "toolchain/lib/lean"
            lake_path = os.pathsep.join((str(root / "lake/lib/lean"), str(core)))
            version = "Lean (version 4.32.2, arm64, commit abcdef012345, Release)"
            trace = {
                "synthetic": False,
                "schemaVersion": "test-v1",
                "outputs": {"o": ["0123456789abcdef.olean"]},
                "inputs": [
                    ["Lean 4.32.2, commit abcdef0", "a" * 16],
                    [str(source.resolve()), "b" * 16],
                    ["Module.name: M", "c" * 16],
                    ["options", [["-DwarningAsError=true", "d" * 16],
                                 ["-DautoImplicit=false", "e" * 16]]],
                ],
                "log": [{"message": f".> LEAN_PATH={lake_path} {lean} {source.resolve()} -o {target}"}],
            }
            trace_path = target.with_suffix(".trace")
            trace_path.write_text(json.dumps(trace))
            self.assertIsNotNone(package.lake_trace_pins(
                "M", source, target, str(lean), version, lake_path))
            trace["inputs"][3][1][0][0] = "-DwarningAsError=false"
            trace_path.write_text(json.dumps(trace))
            changed_options = package.lake_trace_pins(
                "M", source, target, str(lean), version, lake_path)
            self.assertIsNotNone(changed_options)
            self.assertEqual(changed_options["lake_options"]["value"][0][0],
                             "-DwarningAsError=false")
            trace["inputs"][3][1][0][0] = "-DwarningAsError=true"
            trace["outputs"]["o"] = ["not-an-output"]
            trace_path.write_text(json.dumps(trace))
            self.assertIsNone(package.lake_trace_pins(
                "M", source, target, str(lean), version, lake_path))

    def test_lake_trace_accepts_and_pins_original_default_option_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "formal/lean/Hegemon/Bytes.lean"
            source.parent.mkdir(parents=True)
            source.write_text("-- source\n")
            target = root / "formal/lean/.lake/build/lib/lean/Hegemon/Bytes.olean"
            target.parent.mkdir(parents=True)
            lean = root / "toolchain/bin/lean"
            core = root / "toolchain/lib/lean"
            formal_lean = root / "formal/lean/.lake/build/lib/lean"
            lake_path = os.pathsep.join((str(formal_lean), str(core)))
            crypto_path = os.pathsep.join((
                str(root / "formal/crypto/.lake/packages/Cli/.lake/build/lib/lean"),
                str(formal_lean),
                str(root / "formal/crypto/.lake/packages/mathlib/.lake/build/lib/lean"),
                str(root / "formal/crypto/.lake/build/lib/lean"),
                str(core),
            ))
            version = "Lean (version 4.32.2, arm64, commit abcdef012345, Release)"
            trace = {
                "synthetic": False,
                "schemaVersion": "2025-09-10",
                "outputs": {"o": ["fdea864ababae660.olean"]},
                "inputs": [
                    ["Lean 4.32.2, commit abcdef0", "aaaaaaaaaaaaaaaa"],
                    [str(source.resolve()), "bbbbbbbbbbbbbbbb"],
                    ["Module.name: Hegemon.Bytes", "cccccccccccccccc"],
                    ["options", "00000000000006bb"],
                ],
                "log": [{"message":
                         f".> LEAN_PATH={formal_lean} {lean} {source.resolve()} -o {target}"}],
            }
            trace_path = target.with_suffix(".trace")
            trace_path.write_text(json.dumps(trace))
            with patch.object(package, "REPO", root):
                pins = package.lake_trace_pins(
                    "Hegemon.Bytes", source, target, str(lean), version, lake_path)
            self.assertIsNotNone(pins)
            self.assertEqual(pins["lake_options"]["form"], "opaque-default-options-hash")
            self.assertEqual(pins["lake_options"]["value"], "00000000000006bb")
            self.assertEqual(pins["lake_options"]["sha256"],
                             package.sha256_bytes(b'"00000000000006bb"'))
            self.assertEqual(pins["sha256"], package.sha256_file(trace_path))
            trace["log"][0]["message"] = (
                f".> LEAN_PATH={crypto_path.removesuffix(os.pathsep + str(core))} "
                f"{lean} {source.resolve()} -o {target}")
            trace_path.write_text(json.dumps(trace))
            with patch.object(package, "REPO", root):
                crypto_pins = package.lake_trace_pins(
                    "Hegemon.Bytes", source, target, str(lean), version, crypto_path)
            self.assertIsNotNone(crypto_pins)
            self.assertEqual(crypto_pins["lake_options"]["value"], "00000000000006bb")
            trace["log"][0]["message"] = (
                f".> LEAN_PATH={root / 'unqualified/lib/lean'} "
                f"{lean} {source.resolve()} -o {target}")
            trace_path.write_text(json.dumps(trace))
            with patch.object(package, "REPO", root):
                unqualified_pins = package.lake_trace_pins(
                    "Hegemon.Bytes", source, target, str(lean), version, crypto_path)
            self.assertIsNone(unqualified_pins)

    def test_package_build_lock_rejects_a_second_process_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package_root = Path(tmp)
            helper_dir = Path(package.__file__).resolve().parent
            child_code = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import rp05_proof_package as p
p.BUILD_ROOT = Path(sys.argv[2])
try:
    with p.package_build_lock():
        print("UNEXPECTED")
except RuntimeError as exc:
    print(exc)
    sys.exit(23)
"""
            with patch.object(package, "BUILD_ROOT", package_root):
                with package.package_build_lock():
                    child = subprocess.run(
                        [sys.executable, "-c", child_code, str(helper_dir), str(package_root)],
                        text=True, capture_output=True, check=False, timeout=10)
            self.assertEqual(child.returncode, 23, child.stdout + child.stderr)
            self.assertIn("another RP05 package build is already active", child.stdout)

    def test_reachability_excludes_unrelated_sources_and_keeps_external_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Public.lean").write_text("import Internal.Helper\nimport Mathlib.Data.Nat.Basic\n")
            (root / "Internal.Helper.lean").write_text("import Internal.Leaf\n")
            (root / "Internal.Leaf.lean").write_text("-- retained leaf\n")
            (root / "Unrelated.lean").write_text("-- must not enter the package\n")
            index = {
                "Public": root / "Public.lean",
                "Internal.Helper": root / "Internal.Helper.lean",
                "Internal.Leaf": root / "Internal.Leaf.lean",
                "Unrelated": root / "Unrelated.lean",
            }

            graph, external = package.reachable(["Public"], index)

            self.assertEqual(set(graph), {"Public", "Internal.Helper", "Internal.Leaf"})
            self.assertEqual(external, ["Mathlib.Data.Nat.Basic"])
            self.assertEqual(package.topological(graph, ["Public"]),
                             ["Internal.Leaf", "Internal.Helper", "Public"])

    def test_topological_sort_rejects_import_cycles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "A.lean").write_text("import B\n")
            (root / "B.lean").write_text("import A\n")
            with self.assertRaisesRegex(RuntimeError, "cycle"):
                package.topological({"A": root / "A.lean", "B": root / "B.lean"}, ["A"])

    def test_unresolved_project_import_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Public.lean").write_text("import MissingProjectModule\n")
            with self.assertRaisesRegex(RuntimeError, "non-core/non-Mathlib"):
                package.reachable(["Public"], {"Public": root / "Public.lean"},
                                  package.EXTERNAL_ROOTS)

    def test_staged_source_hash_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package_root = Path(tmp)
            source = package_root / "generated/Sources/A.lean"
            source.parent.mkdir(parents=True)
            source.write_text("-- pinned\n")
            manifest = {"sources": [{"module": "A", "staged": "generated/Sources/A.lean",
                                      "sha256": package.sha256_file(source)}]}
            with (patch.object(package, "PACKAGE", package_root),
                  patch.object(package, "SOURCE_ROOT", package_root / "generated/Sources")):
                package.checked_graph(manifest)
                source.write_text("-- changed\n")
                with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                    package.checked_graph(manifest)

    def test_retained_endpoint_source_pin_drift_is_rejected(self) -> None:
        manifest = {
            "sources": [{"source": "retained/Endpoint.lean", "sha256": "source-hash"}],
            "endpoint_source_pins": [{"path": "retained/Endpoint.lean", "sha256": "source-hash"}],
        }
        package.validate_source_pins(manifest)
        manifest["endpoint_source_pins"][0]["sha256"] = "stale-hash"
        with self.assertRaisesRegex(RuntimeError, "pin is missing"):
            package.validate_source_pins(manifest)

    def test_cache_requires_unchanged_direct_import_hashes(self) -> None:
        entry = {"source_sha256": "s", "imports": {"A": "1"},
                 "lean_version": "Lean v", "lean_sha256": "l", "olean_sha256": "o"}
        self.assertTrue(package.cache_state_matches(entry, "s", {"A": "1"}, "Lean v", "l", "o"))
        self.assertFalse(package.cache_state_matches(entry, "s", {"A": "2"}, "Lean v", "l", "o"))

    def test_cache_requires_unchanged_compiler_hash(self) -> None:
        entry = {"source_sha256": "s", "imports": {"A": "1"},
                 "lean_version": "Lean v", "lean_sha256": "l", "olean_sha256": "o"}
        self.assertFalse(package.cache_state_matches(entry, "s", {"A": "1"}, "Lean v", "new-l", "o"))

    def test_verified_receipt_precedes_a_valid_package_local_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "retained/A.lean"
            source.parent.mkdir()
            source.write_text("-- source\n")
            lean = root / "bin/lean"
            lean.parent.mkdir()
            lean.write_bytes(b"lean binary")
            retained = root / "retained/A.olean"
            retained.write_bytes(b"receipt object")
            build_root = root / "package-build"
            target = build_root / "lib/lean/A.olean"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"valid local cache")
            source_hash = package.sha256_file(source)
            lean_hash = package.sha256_file(lean)
            local_hash = package.sha256_file(target)
            retained_hash = package.sha256_file(retained)
            state_path = build_root / "state.json"
            state_path.write_text(json.dumps({"modules": {"A": {
                "source_sha256": source_hash, "imports": {},
                "lean_version": "Lean v", "lean_sha256": lean_hash,
                "olean_sha256": local_hash,
            }}}))
            provenance = {"argv": [str(lean), "-j1", "-M8192",
                                    "-DwarningAsError=true", "-DautoImplicit=false"],
                          "output_sha256": retained_hash,
                          "receipt_sha256": "receipt-pin"}
            receipt = {"path": retained, "provenance": provenance}
            manifest = {
                "public_roots": [{"module": "A"}],
                "sources": [{"module": "A", "source": "retained/A.lean",
                             "sha256": source_hash}],
            }
            with (patch.object(package, "BUILD_ROOT", build_root),
                  patch.object(package, "verify_sources", return_value=manifest),
                  patch.object(package, "checked_graph",
                               return_value=({"A": source}, {"A": source_hash})),
                  patch.object(package, "topological", return_value=["A"]),
                  patch.object(package, "lake_environment",
                               return_value=(str(lean), "", "Lean v")),
                  patch.object(package, "resolved_lake_paths", return_value=[]),
                  patch.object(package, "retained_receipts", return_value={"A": [{}]}),
                  patch.object(package, "validate_lake_originals", return_value={}),
                  patch.object(package, "imports", return_value=[]),
                  patch.object(package, "receipt_object", return_value=receipt),
                  patch.object(package, "copy_verified_object",
                               return_value=retained_hash) as copy_object):
                package._build_locked()
            self.assertEqual(copy_object.call_count, 1)
            state = json.loads(state_path.read_text())["modules"]["A"]
            self.assertEqual(state["olean_sha256"], retained_hash)
            self.assertEqual(state["retained_receipt_reuse"], provenance)

    def test_verified_object_copy_checks_source_and_installed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.olean"
            target = root / "package/target.olean"
            source.write_bytes(b"pinned object")
            target.parent.mkdir()
            target.write_bytes(b"old object")
            expected = package.sha256_file(source)
            installed = package.copy_verified_object(source, target, expected, "test object")
            self.assertEqual(installed, expected)
            self.assertEqual(package.sha256_file(target), expected)
            source.write_bytes(b"changed object")
            with self.assertRaisesRegex(RuntimeError, "source hash mismatch"):
                package.copy_verified_object(source, target, expected, "test object")

    def test_retained_receipt_requires_unchanged_imports_and_accepts_output_addition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "retained/A.lean"
            source.parent.mkdir()
            source.write_text("-- source\n")
            dependency = repo / "build/B.olean"
            dependency.parent.mkdir()
            dependency.write_bytes(b"dependency olean")
            lean = repo / "bin/lean"
            lean.parent.mkdir()
            lean.write_bytes(b"lean binary")
            output = repo / "build/A.olean"
            output.write_bytes(b"target olean")
            source_hash = package.sha256_file(source)
            dependency_hash = package.sha256_file(dependency)
            lean_hash = package.sha256_file(lean)
            output_hash = package.sha256_file(output)
            argv = [str(lean), "-j1", "-M8192",
                    "-DwarningAsError=true", "-DautoImplicit=false",
                    "-DmaxHeartbeats=4000000", "-o", str(output), str(source)]
            before = {str(source.resolve()): source_hash, str(lean.resolve()): lean_hash,
                      str(dependency.resolve()): dependency_hash}
            receipt = {
                "module": "A", "exit_code": 0, "source": str(source.resolve()),
                "source_sha256_pre": source_hash, "source_sha256_post": source_hash,
                "lean": str(lean.resolve()), "lean_sha256": lean_hash, "argv": argv,
                "dependency_hashes_pre_post": {"pre": before,
                                                "post": {**before, str(output): output_hash}},
                "output_sha256": output_hash,
            }
            source_record = {"source": "retained/A.lean", "sha256": source_hash}
            with patch.object(package, "REPO", repo.resolve()):
                accepted = package.receipt_object("A", source_record, {"B": dependency_hash},
                                                  lean_hash, {"A": [receipt]})
                self.assertEqual(accepted["path"], output)
                self.assertEqual(accepted["provenance"]["argv"], argv)
                self.assertEqual(accepted["provenance"]["imports"], {"B": dependency_hash})
                self.assertEqual(accepted["provenance"]["output_sha256"], output_hash)
                self.assertTrue(accepted["provenance"]["receipt_sha256"])
                receipt["argv"][2] = "-M16385"
                over_budget = package.receipt_object("A", source_record, {"B": dependency_hash},
                                                     lean_hash, {"A": [receipt]})
                self.assertIsNone(over_budget)
                receipt["argv"][2] = "-M8192"
                receipt["argv"].remove("-DwarningAsError=true")
                missing_warning = package.receipt_object(
                    "A", source_record, {"B": dependency_hash}, lean_hash, {"A": [receipt]})
                self.assertIsNone(missing_warning)
                receipt["argv"].insert(3, "-DwarningAsError=true")
                receipt["argv"].remove("-DautoImplicit=false")
                missing_implicit = package.receipt_object(
                    "A", source_record, {"B": dependency_hash}, lean_hash, {"A": [receipt]})
                self.assertIsNone(missing_implicit)
                receipt["argv"].insert(4, "-DautoImplicit=false")
                receipt["dependency_hashes_pre_post"]["post"][str(dependency)] = "changed"
                rejected = package.receipt_object("A", source_record, {"B": dependency_hash},
                                                  lean_hash, {"A": [receipt]})
                self.assertIsNone(rejected)


if __name__ == "__main__":
    unittest.main()
