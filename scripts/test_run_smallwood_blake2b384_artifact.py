#!/usr/bin/env python3
"""Disk-light tests for the SmallWood BLAKE2b artifact byte harness."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_smallwood_blake2b384_artifact import (  # noqa: E402
    ACTION_ID,
    BACKEND_WIRE_ID,
    BALANCE_TAG_BYTES,
    CIRCUIT_VERSION,
    CRYPTO_SUITE,
    ENVELOPE_VERSION,
    FAMILY_ID,
    HEADER_BYTES,
    MAGIC,
    MUTATIONS,
    PROFILE_WIRE_ID,
    PUBLIC_VALUE_COUNT,
    STATEMENT_BYTES,
    ArtifactError,
    _mutate,
    _manifest,
    parse_envelope,
    verify_manifest,
    write_manifest,
)


def fixture() -> bytes:
    statement = b"".join((index + 1).to_bytes(8, "little") for index in range(PUBLIC_VALUE_COUNT))
    statement += bytes(range(BALANCE_TAG_BYTES))
    proof = bytes(range(251))
    header = bytearray(HEADER_BYTES)
    header[0:4] = MAGIC
    header[4:6] = ENVELOPE_VERSION.to_bytes(2, "little")
    header[6:8] = CIRCUIT_VERSION.to_bytes(2, "little")
    header[8:10] = CRYPTO_SUITE.to_bytes(2, "little")
    header[10] = BACKEND_WIRE_ID
    header[11] = PROFILE_WIRE_ID
    header[12] = 1
    header[16:20] = (0x4847_4D35).to_bytes(4, "little")
    header[20:22] = FAMILY_ID.to_bytes(2, "little")
    header[22:24] = ACTION_ID.to_bytes(2, "little")
    header[24:28] = STATEMENT_BYTES.to_bytes(4, "little")
    header[28:32] = len(proof).to_bytes(4, "little")
    header[32:80] = bytes([0xA5]) * 48
    return bytes(header) + statement + proof


def expect_reject(data: bytes) -> None:
    try:
        parse_envelope(data)
    except ArtifactError:
        return
    raise AssertionError("mutated envelope unexpectedly parsed")


def main() -> None:
    canonical = fixture()
    decoded = parse_envelope(canonical)
    assert len(decoded.statement) == STATEMENT_BYTES
    assert len(decoded.proof) == 251
    parser_expected = dict(MUTATIONS)
    for name, parser_accepts in MUTATIONS:
        mutated = _mutate(name, canonical)
        try:
            parse_envelope(mutated)
        except ArtifactError:
            observed = False
        else:
            observed = True
        assert observed == parser_accepts, (name, observed, parser_accepts)
        if not parser_accepts:
            expect_reject(mutated)
    assert parser_expected["statement"] is True
    assert parser_expected["proof"] is True
    with tempfile.TemporaryDirectory(prefix="smallwood-artifact-test-") as temp:
        root = Path(temp)
        artifact = root / "artifact.swv5"
        artifact.write_bytes(canonical)
        marker = {
            "profile_id": "smallwood-v5-conventional-hash-blake2b384-inline-v1",
            "boolean_relation_compiled": True,
            "profile_integrated": True,
            "relation_hash_output_bits": 384,
        }
        manifest = _manifest(root, artifact, decoded, marker, dict(MUTATIONS), "mock")
        manifest_path = root / "manifest.json"
        write_manifest(manifest_path, manifest)
        verify_manifest(root, manifest_path)
    print(f"SmallWood BLAKE2b artifact harness tests passed: {len(MUTATIONS)} mutations")


if __name__ == "__main__":
    main()
