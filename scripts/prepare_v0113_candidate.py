#!/usr/bin/env python3
"""Inventory a locally built v0.11.3 candidate; grant no release or proof authority."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

try:
    from . import release_artifact_manifest as artifacts
except ImportError:
    import release_artifact_manifest as artifacts

VERSION = "0.11.3"
# Cargo.lock is a literal input to PrivateSpend relation_digest. Product release
# labels must not bump these internal package versions or regenerate that lock.
PACKAGE_VERSIONS = {
    "node/Cargo.toml": "0.10.0",
    "wallet/Cargo.toml": "0.10.0",
    "walletd/Cargo.toml": "0.10.0",
    "protocol/versioning/Cargo.toml": "0.1.0",
}
PACKAGE_FILES = tuple(PACKAGE_VERSIONS)
FROZEN_CARGO_LOCK_SHA256 = "1c243bf3858f4ee22fa4441c7a2ee6d49b16d264147b0f3a2de845e760821719"
OPEN_GATES = (
    "exact-source proof authorization and unchanged-proof lifecycle",
    "public HTTP positive transfer and concurrent admission qualification",
    "formal-core and formal-crypto release gates",
    "dependency and linked-binary security audits",
    "all release platform builds and package verification",
    "independent review and release approval",
    "publication approval",
    "operator deployment approval",
)


def require_candidate_versions(root):
    for relative, expected in PACKAGE_VERSIONS.items():
        package = (root / relative).read_text(encoding="utf-8").split("[dependencies]", 1)[0]
        match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', package, re.M)
        if not match or match[1] != expected:
            raise ValueError(f"preserve relation-bound internal package version {expected}: {relative}")
    if artifacts.sha256_file(root / "Cargo.lock") != FROZEN_CARGO_LOCK_SHA256:
        raise ValueError("preserve exact relation-bound Cargo.lock; software release labels must not change proof identity")
    source = (root / "protocol/versioning/src/lib.rs").read_text(encoding="utf-8")
    if not re.search(r'pub const RELEASE_VERSION: &str = "0\.11\.3";', source):
        raise ValueError("candidate product release version must be 0.11.3")


def prepare(root: Path, manifest_path: Path, expected_specs: list[str]):
    require_candidate_versions(root)
    manifest = artifacts.verify_manifest(root, manifest_path, expected_specs)
    historical = json.loads((root / "config/v0112-release-artifacts.json").read_text(encoding="utf-8"))
    comparisons = {"source_head": "build_source_head", "source_index_tree": "build_index_tree", "source_tree_sha256": "source_tree_sha256"}
    if any(manifest.get(new) == historical.get(old) for new, old in comparisons.items()):
        raise ValueError("v0.11.2 build provenance cannot be relabeled as a v0.11.3 candidate")
    # The existing verifier checks current source/index/lock identity and actual
    # native binary hashes. This inventory does not attest compiler execution or
    # satisfy the separate exact-source proof authorization gate.
    return {
        "schema": "hegemon.v0113.local-candidate.v1",
        "status": "candidate_unqualified",
        "software_release": "v0.11.3",
        "software_version": VERSION,
        "network_release": "v0.11",
        "internal_package_versions": dict(PACKAGE_VERSIONS),
        "frozen_cargo_lock_sha256": FROZEN_CARGO_LOCK_SHA256,
        "production_authority": False,
        "publication_authorized": False,
        "deployment_authorized": False,
        "artifact_manifest_sha256": artifacts.sha256_file(manifest_path),
        "artifact_manifest": manifest,
        "remaining_release_gates": list(OPEN_GATES),
    }


def write_record(path: Path, record):
    # Exclusive creation also rejects an existing symlink; retained records are
    # never replaced. Keep output under ignored target/ or outside the checkout
    # so writing a record does not change the source identity it describes.
    with path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True, help="new four-binary manifest from scripts/build_release_artifacts.sh")
    parser.add_argument("--expect", action="append", required=True, help="package:binary:path; all four actual candidate binaries in manifest order")
    parser.add_argument("--output", type=Path, required=True, help="new local candidate record; never an accepted-release profile")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
        record = prepare(root, manifest, args.expect)
        write_record(args.output, record)
        print(f"Prepared unqualified v0.11.3 candidate: {args.output}")
        return 0
    except (ValueError, OSError, artifacts.ManifestError, subprocess.CalledProcessError) as error:
        print(f"v0.11.3 candidate: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
