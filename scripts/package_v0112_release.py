#!/usr/bin/env python3
"""Package v0.11.2 only after its fixed, committed CI artifact profile is accepted."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import re
import subprocess
import sys

try:
    from . import package_v011_release as base
except ImportError:
    import package_v011_release as base

PROFILE_PATH = "config/v0112-release-artifacts.json"
WRAPPER_PATH = "scripts/package_v0112_release.py"
FIELDS = {"schema", "status", "network_release", "software_release", "software_version", "release_source_head", "build_source_head", "build_index_tree", "source_tree_sha256", "cargo_lock_sha256", "platform_manifests_sha256"}


def validate_profile(profile):
    if not isinstance(profile, dict) or set(profile) != FIELDS:
        base.join.fail("v0.11.2 profile must contain exactly the reviewed fields")
    labels = {"schema": "hegemon.v0112.release-artifacts.v1", "status": "accepted", "network_release": "v0.11", "software_release": "v0.11.2", "software_version": "0.11.2"}
    if any(profile[key] != value for key, value in labels.items()):
        base.join.fail("v0.11.2 CI artifact profile is not accepted")
    for key in ("release_source_head", "build_source_head", "build_index_tree", "source_tree_sha256", "cargo_lock_sha256"):
        length = 40 if key in ("release_source_head", "build_source_head", "build_index_tree") else 64
        if not isinstance(profile[key], str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", profile[key]):
            base.join.fail(f"missing exact v0.11.2 artifact pin: {key}")
    pins = profile["platform_manifests_sha256"]
    if not isinstance(pins, dict) or set(pins) != set(base.PLATFORMS) or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in pins.values()):
        base.join.fail("v0.11.2 requires all four exact platform manifest digests")
    if profile["build_source_head"] == base.BUILD_SOURCE or profile["build_index_tree"] == base.BUILD_TREE or profile["source_tree_sha256"] == base.SOURCE_TREE_SHA256 or any(pins[key] == base.APPROVED_MANIFESTS[key] for key in pins):
        base.join.fail("the original v0.11 build cannot be relabeled as v0.11.2")
    return profile


def load_profile(source):
    return validate_profile(base.join.read_json(source, PROFILE_PATH))


@contextmanager
def artifact_profile(profile):
    """Apply a validated fixed profile for one call; restore the historical API."""
    validate_profile(profile)
    replacements = {"SOFTWARE_RELEASE": profile["software_release"], "SOFTWARE_VERSION": profile["software_version"], "RELEASE_SOURCE": profile["release_source_head"], "BUILD_SOURCE": profile["build_source_head"], "BUILD_TREE": profile["build_index_tree"], "SOURCE_TREE_SHA256": profile["source_tree_sha256"], "CARGO_LOCK_SHA256": profile["cargo_lock_sha256"], "APPROVED_MANIFESTS": dict(profile["platform_manifests_sha256"]), "SOURCE_FILES": base.SOURCE_FILES + (WRAPPER_PATH, PROFILE_PATH)}
    original = {key: getattr(base, key) for key in replacements}
    try:
        for key, value in replacements.items():
            setattr(base, key, value)
        yield
    finally:
        for key, value in original.items():
            setattr(base, key, value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--packaging-commit", required=True)
    args = parser.parse_args(argv)
    # No caller-selected profile/source path: these bytes belong to this checkout.
    source = Path(__file__).absolute().parent.parent
    try:
        profile = load_profile(source)
        with artifact_profile(profile):
            base.require_committed_source(source, args.packaging_commit)
            sums = base.package(source, args.assets, args.output, args.packaging_commit)
        print("".join(sums), end="")
        return 0
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"v0.11.2 packaging: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
