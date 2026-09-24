#!/usr/bin/env python3
"""Canonical checker for the CFW26 code/profile disqualification artifact."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
MODULE_PATH = HERE / "cfw26_code_profile.py"
SPEC = importlib.util.spec_from_file_location("cfw26_code_profile_checked", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
profile_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = profile_module
SPEC.loader.exec_module(profile_module)


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def set_path(document: Any, path: str, value: Any) -> None:
    pieces = path.split("/")
    current = document
    for piece in pieces[:-1]:
        current = current[int(piece)] if isinstance(current, list) else current[piece]
    final = pieces[-1]
    if isinstance(current, list):
        current[int(final)] = value
    else:
        current[final] = value


def check_sources(profile: dict[str, Any]) -> None:
    for relative, expected in profile["source"]["local_sha512"].items():
        actual = sha512_file(REPO / relative)
        if actual != expected:
            raise AssertionError(f"source hash drift: {relative}: {actual}")
    optional_pdfs = (
        (Path("/private/tmp/cfw26-391.pdf"), profile["source"]["cfw26_pdf_sha512"]),
        (Path("/private/tmp/bcs-2016-116.pdf"), profile["source"]["bcs16_pdf_sha512"]),
    )
    for path, expected in optional_pdfs:
        if path.exists() and sha512_file(path) != expected:
            raise AssertionError(f"primary PDF hash drift: {path}")


def check_small_field_executable() -> None:
    first = profile_module.toy_simulator_distribution((3, 7), (0, 3))
    second = profile_module.toy_simulator_distribution((4, 12), (0, 3))
    if first != second or len(first) != 17**2 or set(first.values()) != {1}:
        raise AssertionError("toy RS two-query perfect simulator distribution failed")

    modulus = 257
    domain = tuple(range(1, 9))
    f = profile_module.rs_encode((9, 4, 2), (7, 11), domain, modulus)
    g = profile_module.rs_encode((8, 1, 5), (3, 6), domain, modulus)
    gamma = 19
    combined = tuple((left + gamma * right) % modulus for left, right in zip(g, f, strict=True))
    if not profile_module.verify_linear_combination_queries(g, f, combined, gamma, (0, 2, 7), modulus):
        raise AssertionError("honest toy linear-combination queries rejected")
    forged = list(combined)
    forged[2] = (forged[2] + 1) % modulus
    if profile_module.verify_linear_combination_queries(g, f, forged, gamma, (0, 2, 7), modulus):
        raise AssertionError("mutated toy linear-combination query accepted")

    encoded = profile_module.encode_e320((0, 1, 2, 3, profile_module.GOLDILOCKS_MODULUS - 1))
    if profile_module.decode_e320(encoded) != (0, 1, 2, 3, profile_module.GOLDILOCKS_MODULUS - 1):
        raise AssertionError("E320 canonical round trip failed")


def check_mutations(profile: dict[str, Any]) -> int:
    corpus = json.loads((HERE / "mutation_corpus.json").read_text(encoding="utf-8"))
    rejected = 0
    for mutation in corpus["mutations"]:
        candidate = copy.deepcopy(profile)
        set_path(candidate, mutation["path"], mutation["replacement"])
        profile_module.refresh_profile_digest(candidate)
        try:
            profile_module.validate_profile(candidate)
        except profile_module.ProfileError:
            rejected += 1
        else:
            raise AssertionError(f"mutation accepted: {mutation['id']}")
    return rejected


def check_manifest() -> None:
    manifest_path = HERE / "ARTIFACT_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for relative, expected in manifest["sha512"].items():
        actual = sha512_file(HERE / relative)
        if actual != expected:
            raise AssertionError(f"artifact hash drift: {relative}: {actual}")


def main() -> None:
    raw = (HERE / "profile.json").read_bytes()
    profile = json.loads(raw)
    if raw != profile_module.canonical_json_bytes(profile):
        raise AssertionError("profile.json is not canonical JSON")
    expected = profile_module.build_profile()
    if profile != expected:
        raise AssertionError("profile.json differs from deterministic generator")
    profile_module.validate_profile(profile)
    check_sources(profile)
    check_small_field_executable()
    rejected = check_mutations(profile)
    check_manifest()
    print(
        "PASS cfw26-code-profile "
        f"oracles={profile['section11_oracles']['count']} "
        f"p_bits={profile['interactive_proof']['bits_p_of_x']} "
        f"lambda={profile['bcs_classical_privacy']['minimum_byte_aligned_lambda']} "
        f"bit_wire={profile['bcs_bit_leaf_wire_projection']['projected_wire_bytes']} "
        f"mutations={rejected} proof_bytes=null production=false"
    )


if __name__ == "__main__":
    main()
