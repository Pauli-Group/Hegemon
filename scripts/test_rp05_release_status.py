from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import rp05_release_status as status


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EndpointFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "endpoint.lean"
        self.olean = self.root / "Endpoint.olean"
        self.object_path = self.olean
        self.audit_source = self.root / "audit.lean"
        self.dependency = self.root / "dependency.olean"
        self.lean = self.root / "bin" / "lean"
        self.strict = self.root / "strict.json"
        self.fingerprint = self.root / "fingerprint.json"
        self.log = self.root / "audit.log"
        self.lean.parent.mkdir()
        for path, content in ((self.source, b"theorem source"), (self.olean, b"olean"),
                              (self.audit_source, b"audit source"), (self.dependency, b"dep"),
                              (self.lean, b"lean toolchain")):
            path.write_bytes(content)
        shared_dep_map = {str(self.dependency): digest(self.dependency)}
        pre_map = {**shared_dep_map, str(self.lean): digest(self.lean)}
        post_map = {**shared_dep_map, str(self.olean): digest(self.olean)}
        receipt = {
            "source": str(self.source), "module": "Endpoint", "exit_code": 0,
            "source_sha256_pre": digest(self.source), "source_sha256_post": digest(self.source),
            "output_sha256": digest(self.olean),
            "dependency_hashes_pre_post": {"pre": pre_map, "post": post_map},
        }
        self.strict.write_text(json.dumps(receipt), encoding="utf-8")
        fingerprint = {
            "module": "Endpoint", "root": "Example.endpoint", "exit_code": 0,
            "all_search_path_objects_stable": True,
            "target_source_sha256": digest(self.source), "target_olean_sha256": digest(self.olean),
            "audit_source_sha256": digest(self.audit_source),
            "target_receipt_sha256": digest(self.strict),
            "input_hashes_pre": shared_dep_map, "input_hashes_post": shared_dep_map,
            "input_fingerprint_sha256_pre": "1" * 64,
            "input_fingerprint_sha256_post": "1" * 64,
        }
        self.fingerprint.write_text(json.dumps(fingerprint), encoding="utf-8")
        self.log.write_text(
            "declarations traversed: 4\naxioms: Quot.sound, Classical.choice, propext\n"
            "nonstandard axioms: \nmissing kernel constants: \nmissing theorem/opaque bodies: \nresult: PASS\n",
            encoding="utf-8")
        self.item = {
            "module": "Endpoint", "theorem": "Example.endpoint",
            "source": {}, "object": {}, "strict_receipt": {},
            "body_fingerprint": {}, "body_log": {},
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def descriptor(self, path: Path) -> dict[str, str]:
        return {"path": path.relative_to(self.root).as_posix(), "sha256": digest(path)}

    def set_module_output(self, module: str, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(b"nested module olean")
        self.object_path = output_path
        self.item["module"] = module
        receipt = json.loads(self.strict.read_text(encoding="utf-8"))
        maps = receipt["dependency_hashes_pre_post"]
        post = maps["post"]
        post.pop(str(self.olean.resolve()), None)
        post[str(output_path.resolve())] = digest(output_path)
        receipt["module"] = module
        receipt["output_sha256"] = digest(output_path)
        self.strict.write_text(json.dumps(receipt), encoding="utf-8")
        fingerprint = json.loads(self.fingerprint.read_text(encoding="utf-8"))
        fingerprint["module"] = module
        fingerprint["target_olean_sha256"] = digest(output_path)
        fingerprint["target_receipt_sha256"] = digest(self.strict)
        self.fingerprint.write_text(json.dumps(fingerprint), encoding="utf-8")

    def run_endpoint(self) -> tuple[str, list[str]]:
        # Endpoint file pins are repository-relative; dependency map paths are absolute.
        for field in ("source", "object", "strict_receipt", "body_fingerprint", "body_log"):
            path = {
                "source": self.source, "object": self.object_path, "strict_receipt": self.strict,
                "body_fingerprint": self.fingerprint, "body_log": self.log,
            }[field]
            self.item[field] = self.descriptor(path)
        stale: list[str] = []
        result, _ = status._check_endpoint(
            self.root, "S", self.item, digest(self.audit_source), status.sha256_file,
            stale, {})
        return result, stale

    def test_clean_receipt_and_dependency_closure_is_checked(self) -> None:
        result, stale = self.run_endpoint()
        self.assertEqual(result, "checked")
        self.assertEqual(stale, [])

    def test_nested_module_output_is_bound_to_manifest_object_path(self) -> None:
        nested = self.root / "build" / "Rp05" / "Authorization.olean"
        self.set_module_output("Rp05.Authorization", nested)
        result, stale = self.run_endpoint()
        self.assertEqual(result, "checked")
        self.assertEqual(stale, [])

    def test_same_basename_at_wrong_path_is_rejected(self) -> None:
        nested = self.root / "build" / "Rp05" / "Authorization.olean"
        wrong = self.root / "elsewhere" / "Authorization.olean"
        self.set_module_output("Rp05.Authorization", nested)
        wrong.parent.mkdir(parents=True, exist_ok=True)
        wrong.write_bytes(nested.read_bytes())
        receipt = json.loads(self.strict.read_text(encoding="utf-8"))
        post = receipt["dependency_hashes_pre_post"]["post"]
        post.pop(str(nested.resolve()))
        post[str(wrong.resolve())] = digest(wrong)
        self.strict.write_text(json.dumps(receipt), encoding="utf-8")
        fingerprint = json.loads(self.fingerprint.read_text(encoding="utf-8"))
        fingerprint["target_receipt_sha256"] = digest(self.strict)
        self.fingerprint.write_text(json.dumps(fingerprint), encoding="utf-8")
        result, stale = self.run_endpoint()
        self.assertEqual(result, "changed")
        self.assertTrue(any("strict dependency hashes changed" in item for item in stale))

    def test_changed_dependency_invalidates_endpoint(self) -> None:
        self.dependency.write_bytes(b"changed")
        result, stale = self.run_endpoint()
        self.assertEqual(result, "changed")
        self.assertTrue(any("dependency changed" in item for item in stale))

    def test_changed_source_invalidates_endpoint(self) -> None:
        self.source.write_bytes(b"edited theorem")
        result, stale = self.run_endpoint()
        self.assertEqual(result, "changed")
        self.assertTrue(any("source changed" in item for item in stale))

    def test_nonpassing_body_log_invalidates_endpoint(self) -> None:
        self.log.write_text("result: FAIL\n", encoding="utf-8")
        self.item["body_log"] = self.descriptor(self.log)
        result, stale = self.run_endpoint()
        self.assertEqual(result, "changed")
        self.assertTrue(any("body audit log lacks a clean PASS" in item for item in stale))

    def test_malformed_body_log_fails_closed(self) -> None:
        self.log.write_text(
            "declarations traversed: many\naxioms: Quot.sound, Classical.choice, propext\n"
            "result: PASS\n", encoding="utf-8")
        self.item["body_log"] = self.descriptor(self.log)
        result, stale = self.run_endpoint()
        self.assertEqual(result, "changed")
        self.assertTrue(any("body audit log lacks a clean PASS" in item for item in stale))


class ReportTests(unittest.TestCase):
    def test_report_fingerprint_binds_status_inputs(self) -> None:
        first = status._report(Path("/repo"), "a" * 64, "a" * 64, [], {})
        second = status._report(Path("/repo"), "a" * 64, "a" * 64, ["source changed"], {})
        self.assertNotEqual(first["fingerprint_sha256"], second["fingerprint_sha256"])
        self.assertFalse(first["production_authorized"])
        self.assertEqual(first["chart"]["release_gates"]["R5"]["status"], "open")

    def test_verified_delta_is_annotation_not_gate_promotion(self) -> None:
        delta = {"status": "reused_test_only_delta", "path": "record.json", "sha256": "b" * 64}
        report = status._report(Path("/repo"), "a" * 64, "a" * 64, [], {},
                                release_gates={"R1": {"status": "changed", "note": "source differs", "receipt": None}},
                                test_only_evidence_delta=delta)
        self.assertEqual(report["test_only_evidence_delta"]["status"], "reused_test_only_delta")
        self.assertEqual(report["release_gates"]["R1"]["status"], "changed")
        self.assertFalse(report["production_authorized"])

    def test_bad_delta_path_fails_closed(self) -> None:
        stale: list[str] = []
        result = status._verify_test_only_delta(Path("/repo"), {"path": "../record.json", "sha256": "a" * 64}, status.sha256_file, stale)
        self.assertEqual(result["status"], "changed")
        self.assertTrue(any("test-only delta record rejected" in item for item in stale))

    def test_manifest_delta_pin_is_required_and_exact(self) -> None:
        stale: list[str] = []
        result = status._verify_test_only_delta(Path("/repo"), {"path": "record.json"}, status.sha256_file, stale)
        self.assertEqual(result["status"], "changed")
        self.assertTrue(any("exact path/SHA-256 pin" in item for item in stale))

    def test_reused_delta_notes_do_not_claim_a_new_run(self) -> None:
        packet = {"technical_status": "PASS_PR_ONLY", "q38_recorded_status": "PASS_SOURCE_PINNED_AND_SEMANTICALLY_VALIDATED",
                  "lifecycle_review": {"path": "receipt"}, "reuse_status": "reused_test_only_delta",
                  "reuse_note": "retained pass plus verified test-only delta; not a new run"}
        gates = status._release_gates({"status": "checked", "current_root_sha512": "a" * 128}, packet, "checked", [])
        self.assertEqual(gates["R2"]["status"], "checked")
        self.assertIn("not a new run", gates["R2"]["note"])
        self.assertIn("not a new run", gates["R4"]["note"])

    def test_pinned_pr_readback_distinguishes_publication_from_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            readback_path = root / "readback.json"
            content = {"number": 205, "url": "https://github.com/Reflexivity/Hegemon/pull/205",
                       "head_sha": "a" * 40, "production_authorized": False}
            readback_path.write_text(json.dumps(content), encoding="utf-8")
            descriptor = {"status": "published_for_review", "url": content["url"],
                          "head_sha": content["head_sha"],
                          "readback": {"path": "readback.json", "sha256": digest(readback_path)}}
            stale: list[str] = []
            publication = status._check_publication(root, descriptor, status.sha256_file, stale)
            self.assertEqual(stale, [])
            gates = status._release_gates({}, {}, "changed", [], publication)
            self.assertEqual(gates["R5"]["status"], "open")
            self.assertIn("published for review", gates["R5"]["note"])
            content["production_authorized"] = True
            readback_path.write_text(json.dumps(content), encoding="utf-8")
            stale = []
            publication = status._check_publication(root, descriptor, status.sha256_file, stale)
            self.assertEqual(publication["status"], "changed")


if __name__ == "__main__":
    unittest.main()
