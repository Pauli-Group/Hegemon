#!/usr/bin/env python3
from __future__ import annotations

import io
import os
from pathlib import Path
import shutil
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
VERIFY_WRAPPER = ROOT / "scripts/verify_native_backend_review_package.sh"
PACKAGE_WRAPPER = ROOT / "scripts/package_native_backend_review.sh"
POSTURE_WRAPPER = ROOT / "scripts/check_native_backend_release_posture.sh"


def write_archive(path: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for info, body in members:
            archive.addfile(info, io.BytesIO(body) if info.isfile() else None)


def write_pax_metadata_archive(path: Path, metadata_size: int) -> None:
    with tarfile.open(
        path,
        "w:gz",
        format=tarfile.PAX_FORMAT,
        pax_headers={"comment": "x" * metadata_size},
    ) as archive:
        info, body = regular_member(f"{review.PACKAGE_ROOT_NAME}/pax", b"")
        archive.addfile(info, io.BytesIO(body))


def write_gnu_longname_archive(path: Path, name_size: int) -> None:
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        info, body = regular_member(
            f"{review.PACKAGE_ROOT_NAME}/" + ("a" * name_size),
            b"",
        )
        archive.addfile(info, io.BytesIO(body))


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


def expect_generated_evidence_rejection(
    package_root: Path, regenerated_root: Path, expected_path: str
) -> None:
    try:
        review.verify_generated_evidence(package_root, regenerated_root)
    except review.ReviewPackageError as exc:
        if expected_path not in str(exc):
            raise SystemExit(
                f"generated evidence rejected for wrong reason: {exc}; "
                f"expected path {expected_path!r}"
            ) from exc
    else:
        raise SystemExit(
            f"mutated generated evidence unexpectedly matched: {expected_path}"
        )


def expect_layout_rejection(package_root: Path, expected_message: str) -> None:
    try:
        review.verify_package_layout(package_root)
    except review.ReviewPackageError as exc:
        if expected_message not in str(exc):
            raise SystemExit(
                f"package layout rejected for wrong reason: {exc}; "
                f"expected {expected_message!r}"
            ) from exc
    else:
        raise SystemExit("invalid package layout unexpectedly accepted")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="hegemon-native-review-package-") as raw:
        temp = Path(raw)
        review.verify_archive_hash(PACKAGE, PACKAGE_SHA)
        package_root = review.safe_extract(PACKAGE, temp / "current")
        review.verify_source_snapshot(ROOT, package_root)
        review.verify_package_layout(package_root)

        cargo_config = package_root / ".cargo/config.toml"
        cargo_config.parent.mkdir(parents=True)
        cargo_config.write_text("[build]\nrustc-wrapper = 'false'\n", encoding="utf-8")
        expect_layout_rejection(package_root, "package non-source file-set mismatch")
        cargo_config.unlink()
        cargo_config.parent.rmdir()
        review.verify_package_layout(package_root)

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

        immutable_checkout = temp / "immutable-git-checkout"
        immutable_checkout.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=immutable_checkout, check=True)
        subprocess.run(
            ["git", "config", "user.email", "review-package-test@invalid"],
            cwd=immutable_checkout,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Review Package Test"],
            cwd=immutable_checkout,
            check=True,
        )
        tracked = immutable_checkout / "tracked.txt"
        tracked.write_bytes(b"committed\n")
        subprocess.run(["git", "add", "tracked.txt"], cwd=immutable_checkout, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "fixture"],
            cwd=immutable_checkout,
            check=True,
        )
        subprocess.run(
            ["git", "update-index", "--assume-unchanged", "tracked.txt"],
            cwd=immutable_checkout,
            check=True,
        )
        tracked.write_bytes(b"forged but hidden from git diff\n")
        immutable_package = temp / "immutable-package"
        immutable_source = immutable_package / "source"
        immutable_source.mkdir(parents=True)
        (immutable_source / "tracked.txt").write_bytes(tracked.read_bytes())
        try:
            review.verify_source_snapshot(immutable_checkout, immutable_package)
        except review.ReviewPackageError as exc:
            if "Git/package source content mismatch" not in str(exc):
                raise SystemExit(
                    f"assume-unchanged source forgery rejected for wrong reason: {exc}"
                ) from exc
        else:
            raise SystemExit(
                "assume-unchanged source forgery unexpectedly matched immutable Git HEAD"
            )

        traversal = temp / "traversal.tar.gz"
        write_archive(traversal, [regular_member("../escape", b"x")])
        expect_extract_rejection(traversal, temp / "traversal", "unsafe package member path")

        for label, name in [
            (
                "windows-drive",
                f"{review.PACKAGE_ROOT_NAME}/C:\\outside\\escape.txt",
            ),
            (
                "windows-unc",
                f"{review.PACKAGE_ROOT_NAME}/\\\\server\\share\\escape.txt",
            ),
            (
                "windows-parent",
                f"{review.PACKAGE_ROOT_NAME}/..\\escape.txt",
            ),
            (
                "windows-ads",
                f"{review.PACKAGE_ROOT_NAME}/evidence.txt:stream",
            ),
        ]:
            cross_flavor = temp / f"{label}.tar.gz"
            write_archive(cross_flavor, [regular_member(name, b"x")])
            expect_extract_rejection(
                cross_flavor,
                temp / label,
                "non-portable package member path",
            )

        for label, component in [
            ("windows-reserved-nul", "NUL"),
            ("windows-reserved-com", "COM1.txt"),
            ("windows-reserved-com-superscript", "COM\u00b9.txt"),
            ("windows-reserved-space-before-extension", "CON .txt"),
            ("windows-trailing-dot", "claim.json."),
            ("windows-trailing-space", "claim.json "),
            ("windows-wildcard", "claim?.json"),
            ("windows-pipe", "claim|json"),
        ]:
            non_portable = temp / f"{label}.tar.gz"
            write_archive(
                non_portable,
                [regular_member(f"{review.PACKAGE_ROOT_NAME}/{component}", b"x")],
            )
            expect_extract_rejection(
                non_portable,
                temp / label,
                "non-portable package member path",
            )

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

        portable_alias = temp / "portable-alias.tar.gz"
        write_archive(
            portable_alias,
            [
                regular_member(
                    f"{review.PACKAGE_ROOT_NAME}/current_claim.json", b"a"
                ),
                regular_member(
                    f"{review.PACKAGE_ROOT_NAME}/CURRENT_CLAIM.JSON", b"b"
                ),
            ],
        )
        expect_extract_rejection(
            portable_alias,
            temp / "portable-alias",
            "duplicate package member",
        )

        unicode_alias = temp / "unicode-alias.tar.gz"
        write_archive(
            unicode_alias,
            [
                regular_member(
                    f"{review.PACKAGE_ROOT_NAME}/caf\u00e9.json", b"a"
                ),
                regular_member(
                    f"{review.PACKAGE_ROOT_NAME}/cafe\u0301.json", b"b"
                ),
            ],
        )
        expect_extract_rejection(
            unicode_alias,
            temp / "unicode-alias",
            "duplicate package member",
        )

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

        original_expanded_limit = review.MAX_EXPANDED_BYTES
        review.MAX_EXPANDED_BYTES = 2 * 1024
        try:
            pax_metadata = temp / "pax-metadata.tar.gz"
            write_pax_metadata_archive(pax_metadata, 16 * 1024)
            expect_extract_rejection(
                pax_metadata,
                temp / "pax-metadata",
                "package decompressed tar stream",
            )

            gnu_longname = temp / "gnu-longname.tar.gz"
            write_gnu_longname_archive(gnu_longname, 16 * 1024)
            expect_extract_rejection(
                gnu_longname,
                temp / "gnu-longname",
                "package decompressed tar stream",
            )
        finally:
            review.MAX_EXPANDED_BYTES = original_expanded_limit

        getmembers = tarfile.TarFile.getmembers
        tarfile.TarFile.getmembers = lambda _archive: (_ for _ in ()).throw(
            AssertionError("streaming extraction must not call getmembers")
        )
        try:
            streamed_root = review.safe_extract(bounded, temp / "streamed")
            if not streamed_root.is_dir():
                raise SystemExit("streamed archive did not create its package root")
        finally:
            tarfile.TarFile.getmembers = getmembers

        original_compressed_limit = review.MAX_COMPRESSED_BYTES
        sha256_file = review.sha256_file
        hash_called = False

        def unexpected_hash(_path: Path) -> str:
            nonlocal hash_called
            hash_called = True
            raise AssertionError("oversized archives must reject before hashing")

        review.MAX_COMPRESSED_BYTES = 1
        review.sha256_file = unexpected_hash
        try:
            try:
                review.verify_archive_hash(PACKAGE, PACKAGE_SHA)
            except review.ReviewPackageError as exc:
                if "package compressed size" not in str(exc):
                    raise SystemExit(
                        f"oversized package rejected for wrong reason: {exc}"
                    ) from exc
            else:
                raise SystemExit("oversized package unexpectedly reached hashing")
            if hash_called:
                raise SystemExit("oversized package was hashed before size rejection")
        finally:
            review.MAX_COMPRESSED_BYTES = original_compressed_limit
            review.sha256_file = sha256_file

        packaged_generated = temp / "packaged-generated"
        regenerated = temp / "regenerated"
        for relative in review.GENERATED_EVIDENCE_PATHS:
            body = f"generated:{relative}\n".encode()
            for root in (packaged_generated, regenerated):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
        review.verify_generated_evidence(packaged_generated, regenerated)
        matrix_relative = "structured_lattice/flat_commitment_matrix_u64_le.bin"
        (packaged_generated / matrix_relative).write_bytes(b"forged matrix\n")
        expect_generated_evidence_rejection(
            packaged_generated, regenerated, matrix_relative
        )
        shutil.copyfile(
            regenerated / matrix_relative, packaged_generated / matrix_relative
        )
        spikes_relative = "reduced_cryptanalysis_spikes.json"
        (packaged_generated / spikes_relative).write_text(
            '{"forged": true}\n', encoding="utf-8"
        )
        expect_generated_evidence_rejection(
            packaged_generated, regenerated, spikes_relative
        )

        isolated = temp / "isolated-helper"
        isolated.mkdir()
        isolated_helper = isolated / HELPER.name
        shutil.copyfile(HELPER, isolated_helper)
        marker = isolated / "shadow-imported"
        (isolated / "tarfile.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
            encoding="utf-8",
        )
        unisolated = subprocess.run(
            [sys.executable, str(isolated_helper), "--help"],
            cwd=isolated,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if unisolated.returncode != 0 or not marker.is_file():
            raise SystemExit(
                "shadow-import control did not establish the unisolated vulnerability:\n"
                + unisolated.stdout
            )
        marker.unlink()
        isolated_run = subprocess.run(
            [sys.executable, "-I", str(isolated_helper), "--help"],
            cwd=isolated,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if isolated_run.returncode != 0 or marker.exists():
            raise SystemExit(
                "isolated helper execution imported an untracked sibling module:\n"
                + isolated_run.stdout
            )

        isolated_invocations = {
            VERIFY_WRAPPER: (
                'python3 -I "$PACKAGE_HELPER" extract',
                'python3 -I "$PACKAGE_HELPER" verify-source',
                'python3 -I "$PACKAGE_HELPER" verify-package-layout',
                'python3 -I "$PACKAGE_HELPER" source-digest',
                'python3 -I "$PACKAGE_HELPER" normalize-json-reports',
                'python3 -I "$PACKAGE_HELPER" verify-generated-evidence',
            ),
            PACKAGE_WRAPPER: (
                'python3 -I "$PACKAGE_HELPER" source-digest',
                'python3 -I "$PACKAGE_HELPER" normalize-json-reports',
            ),
            POSTURE_WRAPPER: (
                'python3 -I "$ROOT/scripts/native_backend_review_package.py" extract',
            ),
        }
        for wrapper, invocations in isolated_invocations.items():
            wrapper_text = wrapper.read_text(encoding="utf-8")
            for invocation in invocations:
                if invocation not in wrapper_text:
                    raise SystemExit(
                        f"review helper invocation is not isolated in {wrapper}: "
                        f"missing {invocation!r}"
                    )

        optimized = subprocess.run(
            [
                sys.executable,
                "-I",
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
