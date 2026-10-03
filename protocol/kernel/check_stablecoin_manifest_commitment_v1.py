#!/usr/bin/env python3
"""Dependency-free source/KAT gate for the inactive stablecoin manifest v1 seam."""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass, replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "protocol/kernel/src/stablecoin_manifest_commitment_v1.rs"
LIB = ROOT / "protocol/kernel/src/lib.rs"
MANIFEST = ROOT / "protocol/kernel/src/manifest.rs"

FRAME = b"hegemon.blake2b-384.frame-v1"
DOMAIN = b"hegemon.kernel.stablecoin-manifest-state.v1"
VERSION = 1
COMMITMENT_BYTES = 48
COMMITMENT_WORDS = 6
ENTRY_BYTES = 183
KAT_HEX = (
    "c7101239692a8743b4f55073f16eddd3c54f3618f79d78ede2b4a2469d0fea6f"
    "a16503bf6f74cc3ae53d6f674d9b27a1"
)


@dataclass(frozen=True)
class Entry:
    asset_id: int = 1001
    oracle_feed: int = 7
    attestation_id: int = 0x0102030405060708
    min_collateral_ratio_ppm: int = 1_500_000
    max_mint_per_epoch: int = 1_000_000_000
    oracle_max_age: int = 120
    oracle_submitted_at: int = 42
    enabled_at: int = 10
    retired_at: int | None = 1000
    policy_version: int = 3
    active: bool = True
    oracle_commitment: bytes = bytes([0x11]) * 48
    attestation_commitment: bytes = bytes([0x22]) * 48
    attestation_disputed: bool = False


def encode_entry(entry: Entry) -> bytes:
    encoded = bytearray(ENTRY_BYTES)
    encoded[0:4] = struct.pack("<I", entry.asset_id)
    encoded[4:8] = struct.pack("<I", entry.oracle_feed)
    encoded[8:16] = struct.pack("<Q", entry.attestation_id)
    encoded[16:32] = entry.min_collateral_ratio_ppm.to_bytes(16, "little")
    encoded[32:48] = entry.max_mint_per_epoch.to_bytes(16, "little")
    encoded[48:56] = struct.pack("<Q", entry.oracle_max_age)
    encoded[56:64] = struct.pack("<Q", entry.oracle_submitted_at)
    encoded[64:72] = struct.pack("<Q", entry.enabled_at)
    if entry.retired_at is not None:
        encoded[72] = 1
        encoded[73:81] = struct.pack("<Q", entry.retired_at)
    encoded[81:85] = struct.pack("<I", entry.policy_version)
    encoded[85] = int(entry.active)
    encoded[86:134] = entry.oracle_commitment
    encoded[134:182] = entry.attestation_commitment
    encoded[182] = int(entry.attestation_disputed)
    return bytes(encoded)


def commitment(entries: list[Entry]) -> bytes:
    parts = [struct.pack("<I", VERSION), struct.pack("<I", len(entries))]
    parts.extend(encode_entry(entry) for entry in entries)
    hasher = hashlib.blake2b(digest_size=COMMITMENT_BYTES)
    hasher.update(FRAME)
    hasher.update(struct.pack("<Q", len(DOMAIN)))
    hasher.update(DOMAIN)
    for part in parts:
        hasher.update(struct.pack("<Q", len(part)))
        hasher.update(part)
    return hasher.digest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def source_checks() -> tuple[str, str, str]:
    source = MODULE.read_text(encoding="utf-8")
    lib = LIB.read_text(encoding="utf-8")
    manifest = MANIFEST.read_text(encoding="utf-8")

    required = [
        "pub const STABLECOIN_MANIFEST_STATE_V1_VERSION: u32 = 1;",
        "pub const STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES: usize = 48;",
        "pub const STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_WORDS: usize =",
        "pub const STABLECOIN_MANIFEST_STATE_V1_ENTRY_BYTES: usize = 183;",
        'b"hegemon.kernel.stablecoin-manifest-state.v1"',
        "pub const STABLECOIN_MANIFEST_STATE_V1_KERNEL_GLOBAL_ROOT_INTEGRATED: bool = false;",
        "pub const STABLECOIN_MANIFEST_STATE_V1_PRODUCTION_AUTHORIZED: bool = false;",
        "Blake2b384DomainHasher::new(STABLECOIN_MANIFEST_STATE_V1_DOMAIN)",
        "hasher.update_part(&encoded);",
    ]
    for marker in required:
        require(marker in source, f"missing source invariant: {marker}")

    for field in Entry.__dataclass_fields__:
        require(f"entry.{field}" in source, f"entry field is not encoded: {field}")

    entry_struct = re.search(
        r"pub struct StablecoinPolicyManifestEntry \{(?P<body>.*?)\n\}",
        manifest,
        flags=re.DOTALL,
    )
    require(entry_struct is not None, "kernel stablecoin entry struct was not found")
    rust_entry_fields = re.findall(r"pub ([a-z0-9_]+):", entry_struct.group("body"))
    expected_entry_fields = list(Entry.__dataclass_fields__)
    require(
        rust_entry_fields == expected_entry_fields,
        "kernel stablecoin entry field inventory/order drifted: "
        f"expected {expected_entry_fields}, got {rust_entry_fields}",
    )

    expected_offsets = {
        "ASSET_ID": 0,
        "ORACLE_FEED": 4,
        "ATTESTATION_ID": 8,
        "MIN_COLLATERAL_RATIO_PPM": 16,
        "MAX_MINT_PER_EPOCH": 32,
        "ORACLE_MAX_AGE": 48,
        "ORACLE_SUBMITTED_AT": 56,
        "ENABLED_AT": 64,
        "RETIRED_PRESENT": 72,
        "RETIRED_AT": 73,
        "POLICY_VERSION": 81,
        "ACTIVE": 85,
        "ORACLE_COMMITMENT": 86,
        "ATTESTATION_COMMITMENT": 134,
        "ATTESTATION_DISPUTED": 182,
    }
    for name, expected in expected_offsets.items():
        match = re.search(
            rf"pub const STABLECOIN_ENTRY_V1_{name}_OFFSET: usize = (\d+);",
            source,
        )
        require(match is not None, f"missing offset constant: {name}")
        require(int(match.group(1)) == expected, f"offset drift for {name}")

    require(
        "pub mod stablecoin_manifest_commitment_v1;" in lib,
        "kernel crate does not export the inactive commitment module",
    )
    global_root = re.search(
        r"pub fn kernel_global_root\(\) -> \[u8; 48\] \{(?P<body>.*?)\n\}",
        manifest,
        flags=re.DOTALL,
    )
    require(global_root is not None, "kernel_global_root source body was not found")
    root_body = global_root.group("body")
    require("stablecoin" not in root_body.lower(), "kernel_global_root now includes stablecoin state")
    require(
        "compute_kernel_global_root(vec![(FAMILY_SHIELDED_POOL, shielded_family_root())])"
        in root_body,
        "kernel_global_root legacy family list drifted",
    )

    kat_match = re.search(
        r"const KAT: \[u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES\] = \[(?P<body>.*?)\];",
        source,
        flags=re.DOTALL,
    )
    require(kat_match is not None, "Rust KAT array was not found")
    rust_kat = bytes(int(token, 16) for token in re.findall(r"0x([0-9a-f]{2})", kat_match.group("body")))
    require(rust_kat.hex() == KAT_HEX, "Rust KAT bytes drifted from the independent KAT")

    return (
        hashlib.sha512(source.encode()).hexdigest(),
        hashlib.sha512(lib.encode()).hexdigest(),
        hashlib.sha512(manifest.encode()).hexdigest(),
    )


def semantic_checks() -> int:
    canonical = Entry()
    encoded = encode_entry(canonical)
    require(len(encoded) == ENTRY_BYTES, "entry encoding width drifted")
    require(encoded[72] == 1, "present retirement tag is not one")
    require(encoded[73:81] == struct.pack("<Q", 1000), "retirement height encoding drifted")
    absent = encode_entry(replace(canonical, retired_at=None))
    require(absent[72:81] == bytes(9), "absent retirement is not tag-zero plus payload-zero")
    require(commitment([canonical]).hex() == KAT_HEX, "independent BLAKE2b-384 KAT failed")

    second = replace(canonical, asset_id=canonical.asset_id + 1)
    require(
        commitment([canonical, second]) != commitment([second, canonical]),
        "manifest vector order is not bound",
    )
    require(
        commitment([canonical, second]) != commitment([canonical, canonical]),
        "entry multiplicity is not bound",
    )

    mutations = [
        replace(canonical, asset_id=canonical.asset_id ^ 1),
        replace(canonical, oracle_feed=canonical.oracle_feed ^ 1),
        replace(canonical, attestation_id=canonical.attestation_id ^ 1),
        replace(
            canonical,
            min_collateral_ratio_ppm=canonical.min_collateral_ratio_ppm ^ 1,
        ),
        replace(canonical, max_mint_per_epoch=canonical.max_mint_per_epoch ^ 1),
        replace(canonical, oracle_max_age=canonical.oracle_max_age ^ 1),
        replace(canonical, oracle_submitted_at=canonical.oracle_submitted_at ^ 1),
        replace(canonical, enabled_at=canonical.enabled_at ^ 1),
        replace(canonical, retired_at=None),
        replace(canonical, policy_version=canonical.policy_version ^ 1),
        replace(canonical, active=not canonical.active),
        replace(
            canonical,
            oracle_commitment=bytes([canonical.oracle_commitment[0] ^ 1])
            + canonical.oracle_commitment[1:],
        ),
        replace(
            canonical,
            attestation_commitment=bytes([canonical.attestation_commitment[0] ^ 1])
            + canonical.attestation_commitment[1:],
        ),
        replace(canonical, attestation_disputed=not canonical.attestation_disputed),
    ]
    expected = commitment([canonical])
    for index, changed in enumerate(mutations):
        require(commitment([changed]) != expected, f"field mutation {index} was not bound")
    return len(mutations)


def main() -> None:
    module_sha512, lib_sha512, manifest_sha512 = source_checks()
    mutation_count = semantic_checks()
    print(
        json.dumps(
            {
                "status": "pass",
                "profile": "inactive-source-only",
                "version": VERSION,
                "digest": "RFC7693-BLAKE2b-384",
                "commitment_bytes": COMMITMENT_BYTES,
                "commitment_words": COMMITMENT_WORDS,
                "entry_bytes": ENTRY_BYTES,
                "entry_fields_bound": mutation_count,
                "kat": KAT_HEX,
                "kernel_global_root_integrated": False,
                "production_authorized": False,
                "module_sha512": module_sha512,
                "lib_sha512": lib_sha512,
                "manifest_sha512": manifest_sha512,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
