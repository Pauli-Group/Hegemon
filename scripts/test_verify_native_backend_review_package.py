#!/usr/bin/env python3
from __future__ import annotations

import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import native_backend_review_package as review


PACKAGE = (
    ROOT
    / "audits/native-backend-128b/native-backend-128b-review-package.tar.gz"
)
PACKAGE_SHA = ROOT / "audits/native-backend-128b/package.sha256"
HELPER = ROOT / "scripts/native_backend_review_package.py"


def write_archive(path: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for info, body in members:
            archive.addfile(info, io.BytesIO(body) if info.isfile() else None)


def regular_member(name: str, body: bytes) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(body)
    info.mode = 0o644
    return info, body


def expect_extract_rejection(
    archive: Path, destination: Path, expected_message: str
) -> None:
    try:
        review.safe_extract(archive, destination)
    except review.ReviewPackageError as exc:
        if expected_message not in str(exc):
            raise SystemExit(
                f"archive rejected for wrong reason: {exc}; "
                f"expected {expected_message!r}"
            ) from exc
    else:
        raise SystemExit(f"unsafe archive unexpectedly extracted: {archive}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="hegemon-native-review-package-") as raw:
        temp = Path(raw)
        review.verify_archive_hash(PACKAGE, PACKAGE_SHA)
        package_root = review.safe_extract(PACKAGE, temp / "current")
        review.verify_source_snapshot(ROOT, package_root)

        mutation = (
            package_root
            / "source/circuits/superneo-backend-lattice/src/lib.rs"
        )
        original_mutation = mutation.read_bytes()
        original_mode = mutation.stat().st_mode
        mutation.write_bytes(original_mutation + b"\n// parity mutation\n")
        try:
            review.verify_source_snapshot(ROOT, package_root)
        except review.ReviewPackageError as exc:
            if "Git/package source content mismatch" not in str(exc):
                raise SystemExit(f"source mutation rejected for wrong reason: {exc}") from exc
        else:
            raise SystemExit("mutated package source unexpectedly matched Git HEAD")

        mutation.write_bytes(original_mutation)
        mutation.chmod(original_mode | 0o111)
        try:
            review.verify_source_snapshot(ROOT, package_root)
        except review.ReviewPackageError as exc:
            if "executable-mode mismatch" not in str(exc):
                raise SystemExit(f"mode mutation rejected for wrong reason: {exc}") from exc
        else:
            raise SystemExit("mode-mutated package source unexpectedly matched Git HEAD")
        mutation.chmod(original_mode)
        mutation.write_bytes(original_mutation + b"\n// parity mutation\n")

        traversal = temp / "traversal.tar.gz"
        write_archive(traversal, [regular_member("../escape", b"x")])
        expect_extract_rejection(traversal, temp / "traversal", "unsafe package member path")

        duplicate = temp / "duplicate.tar.gz"
        duplicate_name = f"{review.PACKAGE_ROOT_NAME}/duplicate"
        write_archive(
            duplicate,
            [
                regular_member(duplicate_name, b"a"),
                regular_member(duplicate_name, b"b"),
            ],
        )
        expect_extract_rejection(duplicate, temp / "duplicate", "duplicate package member")

        symlink = temp / "symlink.tar.gz"
        link = tarfile.TarInfo(f"{review.PACKAGE_ROOT_NAME}/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../escape"
        write_archive(symlink, [(link, b"")])
        expect_extract_rejection(symlink, temp / "symlink", "unsupported package member type")

        bounded = temp / "bounded.tar.gz"
        write_archive(
            bounded,
            [
                regular_member(f"{review.PACKAGE_ROOT_NAME}/one", b"1"),
                regular_member(f"{review.PACKAGE_ROOT_NAME}/two", b"2"),
            ],
        )
        original_limit = review.MAX_MEMBER_COUNT
        review.MAX_MEMBER_COUNT = 1
        try:
            expect_extract_rejection(
                bounded, temp / "bounded", "package member count"
            )
        finally:
            review.MAX_MEMBER_COUNT = original_limit

        optimized = subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "verify-source",
                "--checkout",
                str(ROOT),
                "--package-root",
                str(package_root),
            ],
            cwd=ROOT,
            env={**os.environ, "PYTHONOPTIMIZE": "1"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if optimized.returncode == 0:
            raise SystemExit(
                "optimized source verifier unexpectedly accepted the deliberate mutation"
            )
        if "Git/package source content mismatch" not in optimized.stdout:
            raise SystemExit(
                "optimized source verifier rejected for the wrong reason:\n"
                + optimized.stdout
            )

    print("native backend review package safety and Git-parity mutations rejected")


if __name__ == "__main__":
    main()
