#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


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


def main() -> None:
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
