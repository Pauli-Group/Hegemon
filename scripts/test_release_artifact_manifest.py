#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import release_artifact_manifest as manifest


def expect_rejection(action, expected: str) -> None:
    try:
        action()
    except manifest.ManifestError as exc:
        if expected not in str(exc):
            raise SystemExit(
                f"manifest rejected for wrong reason: {exc}; expected {expected!r}"
            ) from exc
    else:
        raise SystemExit(f"invalid release artifact fixture unexpectedly passed: {expected}")


def host_triple() -> str:
    output = subprocess.check_output(["rustc", "-vV"], text=True)
    return next(line.removeprefix("host: ") for line in output.splitlines() if line.startswith("host: "))


def test_binary_output_modes() -> None:
    # Model O_BINARY on Unix too, so this regression runs in the Linux gate.
    binary_flag = getattr(os, "O_BINARY", 1 << 29)
    native_binary_flag = getattr(os, "O_BINARY", 0)
    original_open = os.open
    opened_flags = []
    def checked_open(path, flags, mode=0o777, **kwargs):
        opened_flags.append(flags)
        assert flags & binary_flag, "release file opened without binary mode"
        forwarded = (flags & ~binary_flag) | native_binary_flag
        return original_open(path, forwarded, mode, **kwargs)

    data = b"release\nbytes\r\nwith\x1aWindows EOF\x00"
    with tempfile.TemporaryDirectory(prefix="release-binary-mode-") as raw:
        root = Path(raw)
        source = root / "source"
        source.write_bytes(data)
        source_fd = original_open(source, os.O_RDONLY | native_binary_flag)
        directory_fd = None
        if manifest._descriptor_relative_io_available():
            directory_fd = original_open(root, manifest._directory_open_flags())
        try:
            # Both the descriptor-relative and Windows path fallback go through
            # _open_at; check exact bytes for direct writes and audited copies.
            handles = [manifest._DirectoryHandle(root, None)]
            if directory_fd is not None:
                handles.append(manifest._DirectoryHandle(root, directory_fd))
            with patch.object(os, "O_BINARY", binary_flag, create=True), patch.object(os, "open", checked_open):
                for index, handle in enumerate(handles):
                    manifest._write_exclusive_at(handle, f"direct-{index}", data, 0o644)
                    manifest._copy_verified_fd_at(source_fd, handle, f"copy-{index}", hashlib.sha256(data).hexdigest(), len(data))
            for index in range(len(handles)):
                assert (root / f"direct-{index}").read_bytes() == data
                assert (root / f"copy-{index}").read_bytes() == data
            assert len(opened_flags) == 2 * len(handles)
            # The standalone format reader must not translate binary headers.
            with patch.object(os, "O_BINARY", binary_flag, create=True), patch.object(os, "open", checked_open):
                assert manifest.detect_native_format(source) == "unknown"
        finally:
            os.close(source_fd)
            if directory_fd is not None:
                os.close(directory_fd)
    print("release binary-mode and exact-byte output tests passed")


def test_path_fd_identity() -> None:
    original_lstat, original_fstat = os.lstat, os.fstat
    data = b"\x7fELFrelease\nbytes\r\nwith\x1aEOF\x00"
    with tempfile.TemporaryDirectory(prefix="release-path-fd-") as raw:
        root = Path(raw)
        source = root / "artifact"
        source.write_bytes(data)
        def metadata(value, **changes):
            fields = {name: getattr(value, name) for name in (
                "st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"
            )}
            fields.update(st_file_attributes=getattr(value, "st_file_attributes", 0), st_birthtime_ns=100)
            fields.update(changes)
            return SimpleNamespace(**fields)
        def by_path(path, *args, **kwargs):
            value = original_lstat(path, *args, **kwargs)
            return metadata(value, st_ctime_ns=100) if Path(path) == source else value
        def by_fd(fd, **changes):
            return metadata(original_fstat(fd), st_ctime_ns=200, **changes)
        def open_source():
            return manifest._open_regular_beneath(root, "artifact", "fixture")
        with patch.object(manifest, "_descriptor_relative_io_available", return_value=False), patch.object(sys, "platform", "win32"), patch.object(os, "lstat", by_path):
            with patch.object(os, "fstat", by_fd):
                fd = open_source()
                try:
                    assert os.read(fd, len(data) + 1) == data
                finally:
                    os.close(fd)
            # Every stable object/byte metadata field remains mandatory.
            baseline_fd = os.open(source, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                baseline = by_fd(baseline_fd)
            finally:
                os.close(baseline_fd)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns"):
                with patch.object(os, "fstat", lambda fd, field=field: by_fd(fd, **{field: getattr(baseline, field) + 1})):
                    expect_rejection(open_source, "changed while being opened")
            legacy = SimpleNamespace(**{name: value for name, value in vars(baseline).items() if name != "st_birthtime_ns"})
            assert manifest._path_fd_identity(legacy) == manifest._file_identity(legacy)
            with patch.object(sys, "platform", "linux"), patch.object(os, "fstat", by_fd):
                expect_rejection(open_source, "changed while being opened")
            # Cross-API normalization must not hide a ChangeTime-only change
            # between two observations of the same open descriptor.
            calls = 0
            def changing_fd(fd):
                nonlocal calls
                calls += 1
                value = by_fd(fd)
                if calls >= 3:
                    value.st_ctime_ns += 1
                return value
            with patch.object(os, "fstat", changing_fd):
                expect_rejection(lambda: manifest.inspect_artifact(root, "hegemon-node", "hegemon-node", source, "artifact", "x86_64-unknown-linux-gnu"), "changed while being inspected")
            import package_testnet_downloads as downloads
            calls = 0
            with patch.object(downloads, "manifest", manifest), patch.object(os, "fstat", changing_fd):
                expect_rejection(lambda: downloads.read_regular(root, source, "fixture"), "changed during read")
            fd = os.open(source, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                calls = 0
                def changing_copy_fd(value):
                    nonlocal calls
                    calls += 1
                    result = by_fd(value)
                    if calls >= 2:
                        result.st_ctime_ns += 1
                    return result
                with patch.object(os, "fstat", changing_copy_fd):
                    expect_rejection(lambda: manifest._copy_verified_fd_at(fd, manifest._DirectoryHandle(root, None), "copy", hashlib.sha256(data).hexdigest(), len(data)), "changed during packaging")
            finally:
                os.close(fd)
    print("Windows path/fd timestamp compatibility and metadata mutation tests passed")


def test_native_fallback_file_io() -> None:
    data = b"release\nbytes\r\nwith\x1aWindows EOF\x00"
    with tempfile.TemporaryDirectory(prefix="release-native-fallback-") as raw:
        root = Path(raw)
        source = root / "rewritten-file"
        source.write_bytes(b"initial bytes")
        source.write_bytes(data)
        with patch.object(manifest, "_descriptor_relative_io_available", return_value=False):
            fd = manifest._open_regular_beneath(root, source.name, "native fixture")
            try:
                assert manifest._read_fd(fd) == data
                manifest._copy_verified_fd_at(fd, manifest._DirectoryHandle(root, None), "copied-file", hashlib.sha256(data).hexdigest(), len(data))
            finally:
                os.close(fd)
        assert (root / "copied-file").read_bytes() == data
    print("native rewritten-file fallback open/read/copy exact-byte test passed")


def test_portable_source_modes() -> None:
    with tempfile.TemporaryDirectory(prefix="release-source-modes-") as raw:
        root = Path(raw)
        def git(*args: str) -> bytes:
            return subprocess.check_output(
                ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL
            )
        git("init", "-q")
        git("config", "user.name", "Release fixture")
        git("config", "user.email", "release-fixture@example.invalid")
        git("config", "core.autocrlf", "false")
        (root / ".gitignore").write_text("target/\n")
        (root / "Cargo.lock").write_bytes(b"version = 4\n")
        script = root / "source.sh"
        original_script = b"#!/bin/sh\nprintf fixture\n"
        script.write_bytes(original_script)
        script.chmod(0o755)
        link = root / "source-link"
        link.symlink_to("source.sh")
        git("add", ".")
        git("update-index", "--chmod=+x", "source.sh")
        git("commit", "-qm", "fixture")
        target = root / "target"
        target.mkdir()
        specs = []
        for source, (package, binary) in zip(
            (Path("/bin/echo"), Path("/bin/ls"), Path("/bin/cat")),
            manifest.EXPECTED_ARTIFACTS, strict=True
        ):
            destination = target / binary
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
            specs.append(f"{package}:{binary}:{destination}")
        manifest_path = target / "manifest.json"
        payload = manifest.create_manifest(root, manifest_path, host_triple(), specs)
        baseline = payload["source_tree_sha256"]

        # Model Windows writable files, where .sh/Cargo.lock stat as 0666.
        script.chmod(0o666)
        (root / "Cargo.lock").chmod(0o666)
        assert manifest.source_tree_sha256(root) == baseline
        manifest.verify_manifest(root, manifest_path, specs)
        script.write_bytes(original_script + b"# changed working bytes\n")
        expect_rejection(
            lambda: manifest.verify_manifest(root, manifest_path, specs),
            "source_tree_sha256 does not match current source",
        )
        script.write_bytes(original_script)
        git("update-index", "--chmod=-x", "source.sh")
        assert manifest.source_tree_sha256(root) != baseline
        expect_rejection(
            lambda: manifest.verify_manifest(root, manifest_path, specs),
            "source_index_tree does not match current source",
        )
        git("update-index", "--chmod=+x", "source.sh")

        # An index regular file must not become a symlink with unchanged index.
        script.unlink()
        script.symlink_to("Cargo.lock")
        expect_rejection(lambda: manifest.source_tree_sha256(root), "source index/file type mismatch")
        script.unlink()
        script.write_bytes(original_script)
        link.unlink()
        link.symlink_to("Cargo.lock")
        expect_rejection(
            lambda: manifest.verify_manifest(root, manifest_path, specs),
            "source_tree_sha256 does not match current source",
        )
        link.unlink()
        link.symlink_to("source.sh")

        untracked = root / "extra-source.txt"
        untracked.write_bytes(b"included untracked source\n")
        payload = manifest.create_manifest(root, manifest_path, host_triple(), specs)
        untracked.chmod(0o666)
        assert manifest.source_tree_sha256(root) == payload["source_tree_sha256"]
        manifest.verify_manifest(root, manifest_path, specs)
        untracked.write_bytes(b"changed untracked bytes\n")
        expect_rejection(
            lambda: manifest.verify_manifest(root, manifest_path, specs),
            "source_tree_sha256 does not match current source",
        )

        # A gitlink retains the actual checked-out submodule HEAD binding.
        nested = root / "nested-source"
        nested.mkdir()
        def nested_git(*args: str) -> bytes:
            return subprocess.check_output(
                ["git", "-C", str(nested), *args], stderr=subprocess.DEVNULL
            )
        nested_git("init", "-q")
        nested_git("config", "user.name", "Release fixture")
        nested_git("config", "user.email", "release-fixture@example.invalid")
        (nested / "source.txt").write_bytes(b"submodule one\n")
        nested_git("add", ".")
        nested_git("commit", "-qm", "one")
        submodule_head = nested_git("rev-parse", "HEAD").decode().strip()
        git("update-index", "--add", "--cacheinfo", f"160000,{submodule_head},nested-source")
        manifest.create_manifest(root, manifest_path, host_triple(), specs)
        manifest.verify_manifest(root, manifest_path, specs)
        (nested / "source.txt").write_bytes(b"submodule two\n")
        nested_git("add", ".")
        nested_git("commit", "-qm", "two")
        expect_rejection(
            lambda: manifest.verify_manifest(root, manifest_path, specs),
            "source_tree_sha256 does not match current source",
        )

    print("portable source mode, byte, Git mode, type and submodule tests passed")


def main() -> None:
    if sys.argv[1:] not in ([], ["--portable-file-io-only"]):
        raise SystemExit("usage: test_release_artifact_manifest.py [--portable-file-io-only]")
    test_binary_output_modes()
    test_path_fd_identity()
    test_native_fallback_file_io()
    if sys.argv[1:] == ["--portable-file-io-only"]:
        return
    test_portable_source_modes()
    target_root = ROOT / "target"
    target_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="release-manifest-test-", dir=target_root) as raw:
        temp = Path(raw)
        sources = [Path("/bin/echo"), Path("/bin/ls"), Path("/bin/cat")]
        if not all(source.is_file() for source in sources):
            raise SystemExit("release artifact manifest test requires standard host executables")
        binaries = [temp / "hegemon-node", temp / "wallet", temp / "walletd"]
        for source, destination in zip(sources, binaries, strict=True):
            shutil.copyfile(source, destination)
            destination.chmod(0o755)

        specs = [
            f"hegemon-node:hegemon-node:{binaries[0]}",
            f"wallet:wallet:{binaries[1]}",
            f"walletd:walletd:{binaries[2]}",
        ]
        manifest_path = temp / "manifest.json"
        manifest.create_manifest(ROOT, manifest_path, host_triple(), specs)
        manifest.verify_manifest(ROOT, manifest_path, specs)

        symlink = temp / "hegemon-node-link"
        symlink.symlink_to(binaries[0])
        symlink_specs = [
            f"hegemon-node:hegemon-node:{symlink}",
            specs[1],
            specs[2],
        ]
        expect_rejection(
            lambda: manifest.create_manifest(
                ROOT, temp / "symlink.json", host_triple(), symlink_specs
            ),
            "non-symlink",
        )

        descriptor_probe = manifest._descriptor_relative_io_available
        manifest._descriptor_relative_io_available = lambda: False
        try:
            fallback_manifest = temp / "fallback-manifest.json"
            manifest.create_manifest(ROOT, fallback_manifest, host_triple(), specs)
            manifest.verify_manifest(ROOT, fallback_manifest, specs)
            fallback_bundle = temp / "fallback-bundle"
            manifest.package_artifacts(
                ROOT,
                fallback_manifest,
                specs,
                [
                    "hegemon-node:hegemon-node:hegemon-node-fallback",
                    "wallet:wallet:wallet-fallback",
                    "walletd:walletd:walletd-fallback",
                ],
                fallback_bundle,
                "hegemon-release-assets-fallback.json",
            )
            fallback_assembled = temp / "fallback-assembled"
            manifest.assemble_release_assets(
                ROOT,
                [fallback_bundle / "hegemon-release-assets-fallback.json"],
                fallback_assembled,
            )
        finally:
            manifest._descriptor_relative_io_available = descriptor_probe

        asset_specs = [
            "hegemon-node:hegemon-node:hegemon-node-test",
            "wallet:wallet:wallet-test",
            "walletd:walletd:walletd-test",
        ]
        bundle_dir = temp / "bundle"
        asset_manifest_name = "hegemon-release-assets-test.json"
        manifest.package_artifacts(
            ROOT,
            manifest_path,
            specs,
            asset_specs,
            bundle_dir,
            asset_manifest_name,
        )
        assembled_dir = temp / "assembled"
        assembled = manifest.assemble_release_assets(
            ROOT, [bundle_dir / asset_manifest_name], assembled_dir
        )
        if len(assembled["files"]) != 7:
            raise SystemExit(f"assembled release file count mismatch: {assembled}")
        for source, name in zip(binaries, ("hegemon-node-test", "wallet-test", "walletd-test"), strict=True):
            if (assembled_dir / name).read_bytes() != source.read_bytes():
                raise SystemExit(f"assembled release asset mismatch: {name}")

        packaged_node = bundle_dir / "hegemon-node-test"
        packaged_node.write_bytes(packaged_node.read_bytes() + b"tampered")
        expect_rejection(
            lambda: manifest.assemble_release_assets(
                ROOT, [bundle_dir / asset_manifest_name], temp / "tampered-assembly"
            ),
            "does not match its manifest",
        )

        original_node = binaries[0].read_bytes()
        binaries[0].write_text("not a native executable\n", encoding="utf-8")
        expect_rejection(
            lambda: manifest.verify_manifest(ROOT, manifest_path, specs),
            "format 'unknown'",
        )
        binaries[0].write_bytes(original_node)

        duplicate_specs = [specs[0], f"wallet:wallet:{binaries[0]}", specs[2]]
        expect_rejection(
            lambda: manifest.create_manifest(
                ROOT, temp / "duplicate.json", host_triple(), duplicate_specs
            ),
            "paths must be distinct",
        )

        original_wallet = binaries[1].read_bytes()
        shutil.copyfile(sources[0], binaries[1])
        binaries[1].chmod(0o755)
        expect_rejection(
            lambda: manifest.verify_manifest(ROOT, manifest_path, specs),
            "digest/metadata mismatch",
        )
        binaries[1].write_bytes(original_wallet)

        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["artifacts"][2]["sha256"] = "00" * 32
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        expect_rejection(
            lambda: manifest.verify_manifest(ROOT, manifest_path, specs),
            "digest/metadata mismatch",
        )

    print("release artifact manifest negative tests passed")


if __name__ == "__main__":
    main()
