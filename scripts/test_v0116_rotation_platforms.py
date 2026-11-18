#!/usr/bin/env python3
"""Target selection and archive parsing for the mixed-version rehearsal."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v0116_rotation_compatibility as rehearsal
from package_v011_release import write_archive
from test_package_v0116_candidate import native_header

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive(base, selected, binary_arch=None, wrong_checksum=False):
    root = "hegemon-v0.11.6-local-candidate-" + selected
    windows = selected.startswith("windows")
    result = base / (root + (".zip" if windows else ".tar.gz"))
    entries = {}
    binaries = {}
    for name in ("hegemon-node", "wallet", "private-spend"):
        member = "bin/" + rehearsal.executable_name(name, selected)
        data = native_header(binary_arch or selected) + name.encode()
        entries[member] = (data, 0o755)
        binaries[member] = {"sha256": sha(data)}
    entries[rehearsal.MANIFEST_PATH] = ((ROOT / rehearsal.MANIFEST_PATH).read_bytes(), 0o644)
    record = {"platform": selected, "software_version": "0.11.6", "build_channel": "local-candidate",
              "binary_build_source_head": "a" * 40, "binaries": binaries}
    entries["bundle.json"] = (json.dumps(record).encode(), 0o644)
    sums = "".join(f"{sha(data)}  {name}\n" for name, (data, _) in entries.items())
    if wrong_checksum:
        sums = "f" * 64 + sums[64:]
    entries["SHA256SUMS"] = (sums.encode(), 0o644)
    write_archive(result, root, entries, windows)
    return result


class RotationPlatforms(unittest.TestCase):
    def test_extract_executed_binaries_for_every_release_format(self):
        for selected in rehearsal.PREVIOUS_SHA:
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                package = archive(base, selected)
                out = base / "unpacked"
                members, source = rehearsal.unpack(package, out, rehearsal.io.sha(package), selected)
                self.assertEqual("a" * 40, source)
                self.assertEqual(5, len(members))
                for name, digest in members.items():
                    self.assertEqual(digest, sha((out / name).read_bytes()))

    def test_reject_mislabeled_isa_and_bad_member_checksum(self):
        for opts in [dict(binary_arch="macos-x86_64"), dict(wrong_checksum=True)]:
            with self.subTest(opts=opts), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                package = archive(base, "windows-x86_64", **opts)
                with self.assertRaises((ValueError, RuntimeError)):
                    rehearsal.unpack(package, base / "unpacked", rehearsal.io.sha(package), "windows-x86_64")

    def test_host_matrix(self):
        for os_name, machine, expected in [("win32", "AMD64", "windows-x86_64"),
                                           ("linux", "x86_64", "linux-x86_64"),
                                           ("darwin", "arm64", "macos-arm64"),
                                           ("darwin", "x86_64", "macos-x86_64")]:
            with patch.object(sys, "platform", os_name), patch.object(rehearsal.platform, "machine", return_value=machine):
                self.assertEqual(expected, rehearsal.host_platform())


if __name__ == "__main__":
    unittest.main()
