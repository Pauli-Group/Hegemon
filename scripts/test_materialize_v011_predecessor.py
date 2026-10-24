#!/usr/bin/env python3
"""Adversarial transport controls; these fixtures grant no release authority."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "materialize_v011_predecessor", Path(__file__).with_name("materialize_v011_predecessor.py"))
materializer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(materializer)

DATA = b"retained public evidence\n"
NAME = "safe/data.bin"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class MaterializerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.destination = self.root / "restored"

    def tearDown(self):
        self.temporary.cleanup()

    def bundle_for(self, entries=None, *, expected=None, tail=b"", tar_bytes=None):
        if entries is None:
            entries = [(NAME, DATA, tarfile.REGTYPE, "", {}, 0o644)]
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, body, kind, link, pax, mode in entries:
                info = tarfile.TarInfo(name)
                info.type, info.linkname, info.pax_headers, info.mode = kind, link, pax, mode
                info.size = len(body) if kind == tarfile.REGTYPE else 0
                archive.addfile(info, io.BytesIO(body) if info.size else None)
        raw = stream.getvalue() + tail
        compressed = gzip.compress(raw, mtime=0)
        part = self.bundle / "part-0000.tar.gz.part"
        part.write_bytes(compressed)
        files = expected if expected is not None else [
            {"path": NAME, "bytes": len(DATA), "sha256": digest(DATA), "mode": 0o644}]
        manifest = {"schema": materializer.SCHEMA, "scope": "TEST_FIXTURE_NO_AUTHORITY",
                    "source_checker_sha256": "0" * 64, "source_registry_sha256": "0" * 64,
                    "closure_inventory_sha256": "0" * 64, "files": files,
                    "file_count": len(files), "total_file_bytes": sum(row["bytes"] for row in files),
                    "tar_bytes": len(raw) if tar_bytes is None else tar_bytes,
                    "compressed_bytes": len(compressed), "archive_sha256": digest(compressed),
                    "parts": [{"path": part.name, "bytes": len(compressed), "sha256": digest(compressed)}]}
        self.write_manifest(manifest)
        return manifest

    def write_manifest(self, manifest):
        self.manifest_file = self.bundle / "manifest.json"
        self.manifest_file.write_text(json.dumps(manifest))

    def restore(self):
        return materializer.materialize(self.manifest_file, self.destination, reserve_bytes=0, expected_manifest_sha256=None)

    def reject(self):
        with self.assertRaises((materializer.Rejected, OSError, tarfile.TarError, EOFError)):
            self.restore()
        self.assertFalse(list(self.root.glob(".v011-predecessor-partial-*")))

    def test_cli_default_rejects_a_self_nominated_manifest(self):
        self.bundle_for()
        with self.assertRaisesRegex(materializer.Rejected, "source-reviewed manifest"):
            materializer.materialize(self.manifest_file, self.destination, reserve_bytes=0)
        self.assertFalse(self.destination.exists())

    def test_valid_bundle_and_existing_exact_tree_reuse(self):
        self.bundle_for()
        _, reused = self.restore()
        self.assertFalse(reused)
        self.assertEqual((self.destination / NAME).read_bytes(), DATA)
        _, reused = self.restore()
        self.assertTrue(reused)

    def test_mismatched_existing_data_is_preserved(self):
        self.bundle_for()
        self.restore()
        file = self.destination / NAME
        file.write_bytes(b"existing data must stay")
        self.reject()
        self.assertEqual(file.read_bytes(), b"existing data must stay")

    def test_extra_existing_file_is_preserved_and_rejected(self):
        self.bundle_for()
        self.restore()
        extra = self.destination / "existing.txt"
        extra.write_text("keep")
        self.reject()
        self.assertEqual(extra.read_text(), "keep")

    def test_corrupt_part_fails_before_extraction(self):
        self.bundle_for()
        part = self.bundle / "part-0000.tar.gz.part"
        blob = bytearray(part.read_bytes()); blob[15] ^= 1; part.write_bytes(blob)
        self.reject()
        self.assertFalse(self.destination.exists())

    def test_missing_part_fails(self):
        self.bundle_for()
        (self.bundle / "part-0000.tar.gz.part").unlink()
        self.reject()

    def test_manifest_duplicate_json_keys_fail(self):
        self.bundle_for()
        self.manifest_file.write_text('{"schema":"first","schema":"second"}')
        self.reject()

    def test_manifest_duplicate_file_records_fail(self):
        manifest = self.bundle_for()
        manifest["files"].append(copy.deepcopy(manifest["files"][0]))
        manifest["file_count"] += 1
        manifest["total_file_bytes"] *= 2
        self.write_manifest(manifest)
        self.reject()

    def test_manifest_extra_keys_fail(self):
        manifest = self.bundle_for()
        manifest["unreviewed_authority"] = True
        self.write_manifest(manifest)
        self.reject()

    def test_manifest_unsafe_paths_fail(self):
        for name in ("/absolute", "../escape", "safe/../escape", "safe\\escape", "./file",
                     "C:/escape", "safe/CON", "safe/NUL.bin", "safe/name.", "safe/name "):
            with self.subTest(name=name):
                manifest = self.bundle_for()
                manifest["files"][0]["path"] = name
                self.write_manifest(manifest)
                self.reject()

    def test_tar_unsafe_paths_fail(self):
        for name in ("/absolute", "../escape", "safe/../escape", "safe\\escape", "./file",
                     "C:/escape", "safe/CON", "safe/NUL.bin", "safe/name.", "safe/name "):
            with self.subTest(name=name):
                self.bundle_for([(name, DATA, tarfile.REGTYPE, "", {}, 0o644)])
                self.reject()
        self.assertFalse((self.root / "escape").exists())

    def test_symlink_hardlink_directory_and_fifo_fail(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                self.bundle_for([(NAME, DATA, kind, "../../escape", {}, 0o644)])
                self.reject()

    def test_duplicate_tar_entry_fails(self):
        entry = (NAME, DATA, tarfile.REGTYPE, "", {}, 0o644)
        self.bundle_for([entry, entry])
        self.reject()

    def test_extra_tar_entry_fails(self):
        self.bundle_for([(NAME, DATA, tarfile.REGTYPE, "", {}, 0o644),
                         ("extra", b"not retained", tarfile.REGTYPE, "", {}, 0o644)])
        self.reject()

    def test_missing_expected_entry_fails(self):
        self.bundle_for([])
        self.reject()

    def test_file_content_hash_fails_even_with_valid_part_hash(self):
        self.bundle_for([(NAME, b"wrong evidence same size", tarfile.REGTYPE, "", {}, 0o644)])
        self.reject()

    def test_file_mode_mismatch_fails(self):
        self.bundle_for([(NAME, DATA, tarfile.REGTYPE, "", {}, 0o755)])
        self.reject()

    def test_unexpected_pax_metadata_fails(self):
        self.bundle_for([(NAME, DATA, tarfile.REGTYPE, "", {"comment": "unapproved"}, 0o644)])
        self.reject()

    def test_expansion_beyond_declared_bound_fails(self):
        self.bundle_for(tail=b"\0" * 32768, tar_bytes=10240)
        self.reject()

    def test_nonzero_trailing_data_fails(self):
        self.bundle_for(tail=b"not another archive")
        self.reject()

    def test_part_larger_than_cap_fails(self):
        manifest = self.bundle_for()
        manifest["parts"][0]["bytes"] = materializer.MAX_PART_BYTES + 1
        self.write_manifest(manifest)
        self.reject()

    def test_symlink_part_is_rejected(self):
        self.bundle_for()
        part = self.bundle / "part-0000.tar.gz.part"
        moved = self.bundle / "original"
        part.rename(moved); part.symlink_to(moved)
        self.reject()

    def test_symlink_manifest_is_rejected(self):
        self.bundle_for()
        moved = self.bundle / "original.json"
        self.manifest_file.rename(moved); self.manifest_file.symlink_to(moved)
        self.reject()

    def test_symlink_destination_is_rejected_without_changes(self):
        self.bundle_for()
        existing = self.root / "existing"
        existing.mkdir(); (existing / "keep").write_text("keep")
        self.destination.symlink_to(existing, target_is_directory=True)
        self.reject()
        self.assertEqual((existing / "keep").read_text(), "keep")

    def test_extra_existing_directory_is_rejected(self):
        self.bundle_for(); self.restore()
        (self.destination / "extra-directory").mkdir()
        self.reject()
        self.assertTrue((self.destination / "extra-directory").is_dir())

    def test_long_valid_path_uses_bounded_pax(self):
        name = "safe/" + "a" * 110 + "/data.bin"
        expected = [{"path": name, "bytes": len(DATA), "sha256": digest(DATA), "mode": 0o644}]
        self.bundle_for([(name, DATA, tarfile.REGTYPE, "", {}, 0o644)], expected=expected)
        self.restore()
        self.assertEqual((self.destination / name).read_bytes(), DATA)

    def test_oversized_pax_header_fails_before_parsing(self):
        self.bundle_for([(NAME, DATA, tarfile.REGTYPE, "", {"comment": "x" * 32768}, 0o644)])
        self.reject()

    def test_multiple_compressed_parts_reassemble(self):
        manifest = self.bundle_for()
        original = self.bundle / "part-0000.tar.gz.part"
        compressed = original.read_bytes()
        original.unlink()
        parts = []
        for offset in range(0, len(compressed), 7):
            block = compressed[offset:offset + 7]
            name = f"part-{len(parts):04d}.tar.gz.part"
            (self.bundle / name).write_bytes(block)
            parts.append({"path": name, "bytes": len(block), "sha256": digest(block)})
        manifest["parts"] = parts
        self.write_manifest(manifest)
        self.restore()
        self.assertEqual((self.destination / NAME).read_bytes(), DATA)

    def test_hardlinked_archive_part_fails(self):
        self.bundle_for()
        import os
        os.link(self.bundle / "part-0000.tar.gz.part", self.root / "outside-hardlink")
        self.reject()

    def test_case_insensitive_manifest_collisions_fail(self):
        manifest = self.bundle_for()
        duplicate = copy.deepcopy(manifest["files"][0])
        duplicate["path"] = NAME.upper()
        manifest["files"].append(duplicate)
        manifest["files"].sort(key=lambda row: row["path"])
        manifest["file_count"] += 1
        manifest["total_file_bytes"] *= 2
        self.write_manifest(manifest)
        self.reject()

    def test_insufficient_disk_preserves_destination_absence(self):
        self.bundle_for()
        with self.assertRaisesRegex(materializer.Rejected, "disk space"):
            materializer.materialize(self.manifest_file, self.destination, reserve_bytes=1 << 70, expected_manifest_sha256=None)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
