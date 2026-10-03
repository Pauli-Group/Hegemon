#!/usr/bin/env python3
"""Dependency-free reference for closing HX448C02 manifest authority.

This is a source-only, inactive design artifact.  It defines successor root
screens over the kernel's exact 183-byte stablecoin entry row, a prospective
199-byte W56 V2 row, and a 215-byte all-W64 V2 row:

* a fixed-cap, full-vector BLAKE2b root; and
* a fixed-cap, ordered Merkle BLAKE2b root.

The 183-byte route retains live 48-byte policy/oracle/attestation authority
exactly and is only a compatibility closure.  It receives no fresh collision
security credit.  V2 identities are independently constructed and cannot be
produced from legacy digests.  W56 is a disqualified cost screen; all-W64 is
only the minimum width surviving the current screen, not production authority.
Parent-state authentication remains a verifier-input operation and is
deliberately separate from in-relation membership.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import struct
from pathlib import Path
from typing import Any, Iterable, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
REPORT = HERE / "cost_report.json"
LEDGER = HERE / "capability_ledger.json"
CORPUS = HERE / "mutation_corpus.json"

SCALAR = ROOT / "circuits/transaction/src/full_blake2b448_relation.rs"
M4 = (
    ROOT
    / "prototypes/standalone-shake256-binius"
    / "m4-full-blake448-e384-candidate/src/mixed_candidate.rs"
)
KERNEL_COMMITMENT = ROOT / "protocol/kernel/src/stablecoin_manifest_commitment_v1.rs"
KERNEL_MANIFEST = ROOT / "protocol/kernel/src/manifest.rs"
NATIVE_ADMISSION = ROOT / "node/src/native/admission.rs"

CAP = 16
CAP_LOG2 = 4
ENTRY_BYTES = 183
FRESH_V2_ENTRY_BYTES = 199
FRESH_V2_W64_ENTRY_BYTES = 215
POLICY_TUPLE_BYTES = 61
LIVE_BYTES = 48
WIDTHS = (56, 64)
FRESH_V2_WIDTH = 56
FRESH_V2_W64_WIDTH = 64
AUTHORITY_SOURCE_PAYLOAD_MAX = 4096

BLAKE_BLOCK_BYTES = 128
BLAKE_FRAME_V1 = b"hegemon.blake2b-384.frame-v1"
POLICY_DOMAIN_V2 = b"hegemon.kernel.stablecoin-policy.v2"
MANIFEST_DOMAIN_V1 = b"hegemon.kernel.stablecoin-manifest-state.v1"

ENTRY_OFFSETS = {
    "asset_id": 0,
    "oracle_feed": 4,
    "attestation_id": 8,
    "min_collateral_ratio_ppm": 16,
    "max_mint_per_epoch": 32,
    "oracle_max_age": 48,
    "oracle_submitted_at": 56,
    "enabled_at": 64,
    "retired_present": 72,
    "retired_at": 73,
    "policy_version": 81,
    "active": 85,
    "oracle_commitment": 86,
    "attestation_commitment": 134,
    "attestation_disputed": 182,
}

FRESH_V2_ENTRY_OFFSETS = {
    **{name: offset for name, offset in ENTRY_OFFSETS.items() if offset < 86},
    "oracle_commitment": 86,
    "attestation_commitment": 142,
    "attestation_disputed": 198,
}

FRESH_V2_W64_ENTRY_OFFSETS = {
    **{name: offset for name, offset in ENTRY_OFFSETS.items() if offset < 86},
    "oracle_commitment": 86,
    "attestation_commitment": 150,
    "attestation_disputed": 214,
}

ROLE_FULL = 1
ROLE_LEAF = 2
ROLE_NODE = 3
ROLE_SNAPSHOT = 4
COMPAT_AUTHORITY_PROFILE = 1
FRESH_V2_AUTHORITY_PROFILE = 2

IDENTITY_ROLE_POLICY = 1
IDENTITY_ROLE_ORACLE = 2
IDENTITY_ROLE_ATTESTATION = 3

# Exact existing kernel KAT for one canonical 183-byte row.
MANIFEST_V1_KAT = bytes.fromhex(
    "c7101239692a8743b4f55073f16eddd3c54f3618f79d78ede2b4a2469d0fea6f"
    "a16503bf6f74cc3ae53d6f674d9b27a1"
)


class Reject(ValueError):
    """Canonical parser or authority rejection."""


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def _require_uint(name: str, value: int, bits: int) -> None:
    if type(value) is not int or not (0 <= value < (1 << bits)):
        raise Reject(f"{name} is not a canonical u{bits}")


def _require_bytes(name: str, value: bytes, width: int) -> None:
    if type(value) is not bytes or len(value) != width:
        raise Reject(f"{name} must be exactly {width} bytes")


@dataclasses.dataclass(frozen=True)
class Entry:
    asset_id: int
    oracle_feed: int
    attestation_id: int
    min_collateral_ratio_ppm: int
    max_mint_per_epoch: int
    oracle_max_age: int
    oracle_submitted_at: int
    enabled_at: int
    retired_at: int | None
    policy_version: int
    active: bool
    oracle_commitment: bytes
    attestation_commitment: bytes
    attestation_disputed: bool

    def validate(self) -> None:
        _require_uint("asset_id", self.asset_id, 32)
        _require_uint("oracle_feed", self.oracle_feed, 32)
        _require_uint("attestation_id", self.attestation_id, 64)
        _require_uint(
            "min_collateral_ratio_ppm", self.min_collateral_ratio_ppm, 128
        )
        _require_uint("max_mint_per_epoch", self.max_mint_per_epoch, 128)
        _require_uint("oracle_max_age", self.oracle_max_age, 64)
        _require_uint("oracle_submitted_at", self.oracle_submitted_at, 64)
        _require_uint("enabled_at", self.enabled_at, 64)
        if self.retired_at is not None:
            _require_uint("retired_at", self.retired_at, 64)
        _require_uint("policy_version", self.policy_version, 32)
        if type(self.active) is not bool:
            raise Reject("active must be a canonical bool")
        _require_bytes("oracle_commitment", self.oracle_commitment, LIVE_BYTES)
        _require_bytes(
            "attestation_commitment", self.attestation_commitment, LIVE_BYTES
        )
        if type(self.attestation_disputed) is not bool:
            raise Reject("attestation_disputed must be a canonical bool")

    @property
    def key(self) -> tuple[int, int]:
        return (self.asset_id, self.policy_version)

    def encode(self) -> bytes:
        self.validate()
        out = bytearray(ENTRY_BYTES)
        out[0:4] = self.asset_id.to_bytes(4, "little")
        out[4:8] = self.oracle_feed.to_bytes(4, "little")
        out[8:16] = self.attestation_id.to_bytes(8, "little")
        out[16:32] = self.min_collateral_ratio_ppm.to_bytes(16, "little")
        out[32:48] = self.max_mint_per_epoch.to_bytes(16, "little")
        out[48:56] = self.oracle_max_age.to_bytes(8, "little")
        out[56:64] = self.oracle_submitted_at.to_bytes(8, "little")
        out[64:72] = self.enabled_at.to_bytes(8, "little")
        if self.retired_at is not None:
            out[72] = 1
            out[73:81] = self.retired_at.to_bytes(8, "little")
        out[81:85] = self.policy_version.to_bytes(4, "little")
        out[85] = int(self.active)
        out[86:134] = self.oracle_commitment
        out[134:182] = self.attestation_commitment
        out[182] = int(self.attestation_disputed)
        assert len(out) == ENTRY_BYTES
        return bytes(out)

    @classmethod
    def decode(cls, raw: bytes) -> "Entry":
        _require_bytes("entry", raw, ENTRY_BYTES)
        if raw[72] not in (0, 1):
            raise Reject("retired_present is not canonical")
        if raw[72] == 0 and raw[73:81] != bytes(8):
            raise Reject("absent retirement has a nonzero payload")
        if raw[85] not in (0, 1):
            raise Reject("active is not canonical")
        if raw[182] not in (0, 1):
            raise Reject("attestation_disputed is not canonical")
        entry = cls(
            asset_id=int.from_bytes(raw[0:4], "little"),
            oracle_feed=int.from_bytes(raw[4:8], "little"),
            attestation_id=int.from_bytes(raw[8:16], "little"),
            min_collateral_ratio_ppm=int.from_bytes(raw[16:32], "little"),
            max_mint_per_epoch=int.from_bytes(raw[32:48], "little"),
            oracle_max_age=int.from_bytes(raw[48:56], "little"),
            oracle_submitted_at=int.from_bytes(raw[56:64], "little"),
            enabled_at=int.from_bytes(raw[64:72], "little"),
            retired_at=(int.from_bytes(raw[73:81], "little") if raw[72] else None),
            policy_version=int.from_bytes(raw[81:85], "little"),
            active=bool(raw[85]),
            oracle_commitment=raw[86:134],
            attestation_commitment=raw[134:182],
            attestation_disputed=bool(raw[182]),
        )
        entry.validate()
        if entry.encode() != raw:
            raise Reject("entry does not canonically round trip")
        return entry


def sample_entry(asset_id: int = 1001, policy_version: int = 3) -> Entry:
    return Entry(
        asset_id=asset_id,
        oracle_feed=7 + (asset_id - 1001),
        attestation_id=0x0102_0304_0506_0708 + (asset_id - 1001),
        min_collateral_ratio_ppm=1_500_000,
        max_mint_per_epoch=1_000_000_000,
        oracle_max_age=120,
        oracle_submitted_at=42,
        enabled_at=10,
        retired_at=1000,
        policy_version=policy_version,
        active=True,
        oracle_commitment=bytes([0x11 + (asset_id - 1001) % 31]) * LIVE_BYTES,
        attestation_commitment=bytes([0x22 + (asset_id - 1001) % 31]) * LIVE_BYTES,
        attestation_disputed=False,
    )


@dataclasses.dataclass(frozen=True)
class OracleAuthoritySourceV2:
    """Prospective raw oracle identity source; never a legacy digest wrapper.

    Exact grammar is `asset_id:u32le || policy_version:u32le ||
    oracle_feed:u32le || submitted_at:u64le || source_id:[u8;32] ||
    payload_len:u16le || canonical_observation_payload[payload_len]`.
    The payload cap is part of this prospective profile.  It does not make the
    grammar authoritative in the current oracle subsystem.
    """

    asset_id: int
    policy_version: int
    oracle_feed: int
    submitted_at: int
    source_id: bytes
    payload: bytes

    def validate(self) -> None:
        _require_uint("oracle source asset_id", self.asset_id, 32)
        _require_uint("oracle source policy_version", self.policy_version, 32)
        _require_uint("oracle source feed", self.oracle_feed, 32)
        _require_uint("oracle source submitted_at", self.submitted_at, 64)
        _require_bytes("oracle source id", self.source_id, 32)
        if type(self.payload) is not bytes or not (
            1 <= len(self.payload) <= AUTHORITY_SOURCE_PAYLOAD_MAX
        ):
            raise Reject("oracle source payload length is outside 1..=4096")

    def encode(self) -> bytes:
        self.validate()
        return (
            self.asset_id.to_bytes(4, "little")
            + self.policy_version.to_bytes(4, "little")
            + self.oracle_feed.to_bytes(4, "little")
            + self.submitted_at.to_bytes(8, "little")
            + self.source_id
            + len(self.payload).to_bytes(2, "little")
            + self.payload
        )

    @classmethod
    def decode(cls, raw: bytes) -> "OracleAuthoritySourceV2":
        if type(raw) is not bytes or len(raw) < 55:
            raise Reject("truncated oracle V2 authority source")
        payload_len = int.from_bytes(raw[52:54], "little")
        if len(raw) != 54 + payload_len:
            raise Reject("oracle V2 source length is not exact")
        value = cls(
            asset_id=int.from_bytes(raw[0:4], "little"),
            policy_version=int.from_bytes(raw[4:8], "little"),
            oracle_feed=int.from_bytes(raw[8:12], "little"),
            submitted_at=int.from_bytes(raw[12:20], "little"),
            source_id=raw[20:52],
            payload=raw[54:],
        )
        value.validate()
        if value.encode() != raw:
            raise Reject("oracle V2 source does not canonically round trip")
        return value


@dataclasses.dataclass(frozen=True)
class AttestationAuthoritySourceV2:
    """Prospective raw attestation identity source.

    Exact grammar is `asset_id:u32le || policy_version:u32le ||
    attestation_id:u64le || created_at:u64le || issuer_id:[u8;32] ||
    payload_len:u16le || canonical_attestation_payload[payload_len]`.
    Mutable dispute status deliberately remains outside this immutable source.
    """

    asset_id: int
    policy_version: int
    attestation_id: int
    created_at: int
    issuer_id: bytes
    payload: bytes

    def validate(self) -> None:
        _require_uint("attestation source asset_id", self.asset_id, 32)
        _require_uint(
            "attestation source policy_version", self.policy_version, 32
        )
        _require_uint("attestation source id", self.attestation_id, 64)
        _require_uint("attestation source created_at", self.created_at, 64)
        _require_bytes("attestation issuer id", self.issuer_id, 32)
        if type(self.payload) is not bytes or not (
            1 <= len(self.payload) <= AUTHORITY_SOURCE_PAYLOAD_MAX
        ):
            raise Reject("attestation source payload length is outside 1..=4096")

    def encode(self) -> bytes:
        self.validate()
        return (
            self.asset_id.to_bytes(4, "little")
            + self.policy_version.to_bytes(4, "little")
            + self.attestation_id.to_bytes(8, "little")
            + self.created_at.to_bytes(8, "little")
            + self.issuer_id
            + len(self.payload).to_bytes(2, "little")
            + self.payload
        )

    @classmethod
    def decode(cls, raw: bytes) -> "AttestationAuthoritySourceV2":
        if type(raw) is not bytes or len(raw) < 59:
            raise Reject("truncated attestation V2 authority source")
        payload_len = int.from_bytes(raw[56:58], "little")
        if len(raw) != 58 + payload_len:
            raise Reject("attestation V2 source length is not exact")
        value = cls(
            asset_id=int.from_bytes(raw[0:4], "little"),
            policy_version=int.from_bytes(raw[4:8], "little"),
            attestation_id=int.from_bytes(raw[8:16], "little"),
            created_at=int.from_bytes(raw[16:24], "little"),
            issuer_id=raw[24:56],
            payload=raw[58:],
        )
        value.validate()
        if value.encode() != raw:
            raise Reject("attestation V2 source does not canonically round trip")
        return value


@dataclasses.dataclass(frozen=True)
class FreshEntryV2:
    """Prospective 199-byte row with two fresh 56-byte commitments."""

    asset_id: int
    oracle_feed: int
    attestation_id: int
    min_collateral_ratio_ppm: int
    max_mint_per_epoch: int
    oracle_max_age: int
    oracle_submitted_at: int
    enabled_at: int
    retired_at: int | None
    policy_version: int
    active: bool
    oracle_commitment: bytes
    attestation_commitment: bytes
    attestation_disputed: bool

    def validate(self) -> None:
        _require_uint("asset_id", self.asset_id, 32)
        _require_uint("oracle_feed", self.oracle_feed, 32)
        _require_uint("attestation_id", self.attestation_id, 64)
        _require_uint(
            "min_collateral_ratio_ppm", self.min_collateral_ratio_ppm, 128
        )
        _require_uint("max_mint_per_epoch", self.max_mint_per_epoch, 128)
        _require_uint("oracle_max_age", self.oracle_max_age, 64)
        _require_uint("oracle_submitted_at", self.oracle_submitted_at, 64)
        _require_uint("enabled_at", self.enabled_at, 64)
        if self.retired_at is not None:
            _require_uint("retired_at", self.retired_at, 64)
        _require_uint("policy_version", self.policy_version, 32)
        if type(self.active) is not bool:
            raise Reject("active must be a canonical bool")
        _require_bytes(
            "fresh oracle commitment", self.oracle_commitment, FRESH_V2_WIDTH
        )
        _require_bytes(
            "fresh attestation commitment",
            self.attestation_commitment,
            FRESH_V2_WIDTH,
        )
        if type(self.attestation_disputed) is not bool:
            raise Reject("attestation_disputed must be a canonical bool")

    @property
    def key(self) -> tuple[int, int]:
        return (self.asset_id, self.policy_version)

    def encode(self) -> bytes:
        self.validate()
        out = bytearray(FRESH_V2_ENTRY_BYTES)
        out[0:4] = self.asset_id.to_bytes(4, "little")
        out[4:8] = self.oracle_feed.to_bytes(4, "little")
        out[8:16] = self.attestation_id.to_bytes(8, "little")
        out[16:32] = self.min_collateral_ratio_ppm.to_bytes(16, "little")
        out[32:48] = self.max_mint_per_epoch.to_bytes(16, "little")
        out[48:56] = self.oracle_max_age.to_bytes(8, "little")
        out[56:64] = self.oracle_submitted_at.to_bytes(8, "little")
        out[64:72] = self.enabled_at.to_bytes(8, "little")
        if self.retired_at is not None:
            out[72] = 1
            out[73:81] = self.retired_at.to_bytes(8, "little")
        out[81:85] = self.policy_version.to_bytes(4, "little")
        out[85] = int(self.active)
        out[86:142] = self.oracle_commitment
        out[142:198] = self.attestation_commitment
        out[198] = int(self.attestation_disputed)
        if len(out) != FRESH_V2_ENTRY_BYTES:
            raise AssertionError(len(out))
        return bytes(out)

    @classmethod
    def decode(cls, raw: bytes) -> "FreshEntryV2":
        _require_bytes("fresh V2 entry", raw, FRESH_V2_ENTRY_BYTES)
        if raw[72] not in (0, 1):
            raise Reject("retired_present is not canonical")
        if raw[72] == 0 and raw[73:81] != bytes(8):
            raise Reject("absent retirement has a nonzero payload")
        if raw[85] not in (0, 1):
            raise Reject("active is not canonical")
        if raw[198] not in (0, 1):
            raise Reject("attestation_disputed is not canonical")
        value = cls(
            asset_id=int.from_bytes(raw[0:4], "little"),
            oracle_feed=int.from_bytes(raw[4:8], "little"),
            attestation_id=int.from_bytes(raw[8:16], "little"),
            min_collateral_ratio_ppm=int.from_bytes(raw[16:32], "little"),
            max_mint_per_epoch=int.from_bytes(raw[32:48], "little"),
            oracle_max_age=int.from_bytes(raw[48:56], "little"),
            oracle_submitted_at=int.from_bytes(raw[56:64], "little"),
            enabled_at=int.from_bytes(raw[64:72], "little"),
            retired_at=(int.from_bytes(raw[73:81], "little") if raw[72] else None),
            policy_version=int.from_bytes(raw[81:85], "little"),
            active=bool(raw[85]),
            oracle_commitment=raw[86:142],
            attestation_commitment=raw[142:198],
            attestation_disputed=bool(raw[198]),
        )
        value.validate()
        if value.encode() != raw:
            raise Reject("fresh V2 entry does not canonically round trip")
        return value


class FreshEntryV2W64(FreshEntryV2):
    """Prospective 215-byte all-W64 row; still conditional, not authorized."""

    def validate(self) -> None:
        _require_uint("asset_id", self.asset_id, 32)
        _require_uint("oracle_feed", self.oracle_feed, 32)
        _require_uint("attestation_id", self.attestation_id, 64)
        _require_uint(
            "min_collateral_ratio_ppm", self.min_collateral_ratio_ppm, 128
        )
        _require_uint("max_mint_per_epoch", self.max_mint_per_epoch, 128)
        _require_uint("oracle_max_age", self.oracle_max_age, 64)
        _require_uint("oracle_submitted_at", self.oracle_submitted_at, 64)
        _require_uint("enabled_at", self.enabled_at, 64)
        if self.retired_at is not None:
            _require_uint("retired_at", self.retired_at, 64)
        _require_uint("policy_version", self.policy_version, 32)
        if type(self.active) is not bool:
            raise Reject("active must be a canonical bool")
        _require_bytes(
            "W64 oracle commitment", self.oracle_commitment, FRESH_V2_W64_WIDTH
        )
        _require_bytes(
            "W64 attestation commitment",
            self.attestation_commitment,
            FRESH_V2_W64_WIDTH,
        )
        if type(self.attestation_disputed) is not bool:
            raise Reject("attestation_disputed must be a canonical bool")

    def encode(self) -> bytes:
        self.validate()
        out = bytearray(FRESH_V2_W64_ENTRY_BYTES)
        out[0:4] = self.asset_id.to_bytes(4, "little")
        out[4:8] = self.oracle_feed.to_bytes(4, "little")
        out[8:16] = self.attestation_id.to_bytes(8, "little")
        out[16:32] = self.min_collateral_ratio_ppm.to_bytes(16, "little")
        out[32:48] = self.max_mint_per_epoch.to_bytes(16, "little")
        out[48:56] = self.oracle_max_age.to_bytes(8, "little")
        out[56:64] = self.oracle_submitted_at.to_bytes(8, "little")
        out[64:72] = self.enabled_at.to_bytes(8, "little")
        if self.retired_at is not None:
            out[72] = 1
            out[73:81] = self.retired_at.to_bytes(8, "little")
        out[81:85] = self.policy_version.to_bytes(4, "little")
        out[85] = int(self.active)
        out[86:150] = self.oracle_commitment
        out[150:214] = self.attestation_commitment
        out[214] = int(self.attestation_disputed)
        if len(out) != FRESH_V2_W64_ENTRY_BYTES:
            raise AssertionError(len(out))
        return bytes(out)

    @classmethod
    def decode(cls, raw: bytes) -> "FreshEntryV2W64":
        _require_bytes("fresh V2 W64 entry", raw, FRESH_V2_W64_ENTRY_BYTES)
        if raw[72] not in (0, 1):
            raise Reject("retired_present is not canonical")
        if raw[72] == 0 and raw[73:81] != bytes(8):
            raise Reject("absent retirement has a nonzero payload")
        if raw[85] not in (0, 1):
            raise Reject("active is not canonical")
        if raw[214] not in (0, 1):
            raise Reject("attestation_disputed is not canonical")
        value = cls(
            asset_id=int.from_bytes(raw[0:4], "little"),
            oracle_feed=int.from_bytes(raw[4:8], "little"),
            attestation_id=int.from_bytes(raw[8:16], "little"),
            min_collateral_ratio_ppm=int.from_bytes(raw[16:32], "little"),
            max_mint_per_epoch=int.from_bytes(raw[32:48], "little"),
            oracle_max_age=int.from_bytes(raw[48:56], "little"),
            oracle_submitted_at=int.from_bytes(raw[56:64], "little"),
            enabled_at=int.from_bytes(raw[64:72], "little"),
            retired_at=(int.from_bytes(raw[73:81], "little") if raw[72] else None),
            policy_version=int.from_bytes(raw[81:85], "little"),
            active=bool(raw[85]),
            oracle_commitment=raw[86:150],
            attestation_commitment=raw[150:214],
            attestation_disputed=bool(raw[214]),
        )
        value.validate()
        if value.encode() != raw:
            raise Reject("fresh V2 W64 entry does not canonically round trip")
        return value


def policy_tuple(entry: Entry | FreshEntryV2) -> bytes:
    entry.validate()
    out = bytearray()
    out += entry.asset_id.to_bytes(4, "little")
    out += entry.oracle_feed.to_bytes(4, "little")
    out += entry.attestation_id.to_bytes(8, "little")
    out += entry.min_collateral_ratio_ppm.to_bytes(16, "little")
    out += entry.max_mint_per_epoch.to_bytes(16, "little")
    out += entry.oracle_max_age.to_bytes(8, "little")
    out += entry.policy_version.to_bytes(4, "little")
    out += bytes([int(entry.active)])
    if len(out) != POLICY_TUPLE_BYTES:
        raise AssertionError(len(out))
    return bytes(out)


def legacy_frame(domain: bytes, parts: Iterable[bytes]) -> bytes:
    out = bytearray(BLAKE_FRAME_V1)
    out += len(domain).to_bytes(8, "little")
    out += domain
    for part in parts:
        out += len(part).to_bytes(8, "little")
        out += part
    return bytes(out)


def policy_hash48(entry: Entry) -> bytes:
    message = legacy_frame(POLICY_DOMAIN_V2, [policy_tuple(entry)])
    if len(message) != 140:
        raise AssertionError(len(message))
    return hashlib.blake2b(message, digest_size=LIVE_BYTES).digest()


def manifest_v1_commitment48(entries: Sequence[Entry]) -> bytes:
    if len(entries) >= 1 << 32:
        raise Reject("manifest v1 entry count does not fit u32")
    parts = [
        (1).to_bytes(4, "little"),
        len(entries).to_bytes(4, "little"),
        *(entry.encode() for entry in entries),
    ]
    return hashlib.blake2b(
        legacy_frame(MANIFEST_DOMAIN_V1, parts), digest_size=LIVE_BYTES
    ).digest()


def _check_profile(width: int, cap: int) -> int:
    if width not in WIDTHS:
        raise Reject("fresh authority width must be exactly 56 or 64 bytes")
    if cap <= 0 or cap > 128 or cap & (cap - 1):
        raise Reject("manifest cap must be a power of two in 1..=128")
    return cap.bit_length() - 1


def personalization(
    role: int,
    width: int,
    cap: int,
    level: int = 0,
    profile: int = COMPAT_AUTHORITY_PROFILE,
) -> bytes:
    """Exact 16-byte RFC 7693 personalization.

    Layout: magic[8] || role:u8 || profile:u8 || width:u8 || log2cap:u8 ||
    level:u8 || reserved[3].  Node level zero hashes leaves; higher levels
    count upward.  Distinct roles and levels cannot alias.
    """

    depth = _check_profile(width, cap)
    _require_uint("role", role, 8)
    if profile not in (COMPAT_AUTHORITY_PROFILE, FRESH_V2_AUTHORITY_PROFILE):
        raise Reject("unknown authority row profile")
    _require_uint("level", level, 8)
    if role != ROLE_NODE and level != 0:
        raise Reject("only node personalization may carry a nonzero level")
    if role == ROLE_NODE and not (0 <= level < depth):
        raise Reject("node level is outside the fixed tree depth")
    out = b"HGMAROOT" + bytes(
        [role, profile, width, depth, level, 0, 0, 0]
    )
    if len(out) != 16:
        raise AssertionError(len(out))
    return out


def _blake(message: bytes, width: int, person: bytes) -> bytes:
    _require_bytes("personalization", person, 16)
    return hashlib.blake2b(message, digest_size=width, person=person).digest()


def identity_personalization(role: int, width: int = FRESH_V2_WIDTH) -> bytes:
    if role not in (
        IDENTITY_ROLE_POLICY,
        IDENTITY_ROLE_ORACLE,
        IDENTITY_ROLE_ATTESTATION,
    ):
        raise Reject("unknown fresh V2 identity role")
    if width not in WIDTHS:
        raise Reject("fresh V2 identity width must be 56 or 64")
    out = (
        b"HGMAIDV2"
        + bytes([role, FRESH_V2_AUTHORITY_PROFILE, width])
        + bytes(5)
    )
    if len(out) != 16:
        raise AssertionError(len(out))
    return out


def policy_hash56_v2(entry: FreshEntryV2) -> bytes:
    """One-compression fresh policy identity over the exact 61-byte tuple."""

    return _blake(
        policy_tuple(entry),
        FRESH_V2_WIDTH,
        identity_personalization(IDENTITY_ROLE_POLICY),
    )


def oracle_hash56_v2(source: OracleAuthoritySourceV2) -> bytes:
    encoded = source.encode()
    return _blake(
        encoded,
        FRESH_V2_WIDTH,
        identity_personalization(IDENTITY_ROLE_ORACLE),
    )


def attestation_hash56_v2(source: AttestationAuthoritySourceV2) -> bytes:
    encoded = source.encode()
    return _blake(
        encoded,
        FRESH_V2_WIDTH,
        identity_personalization(IDENTITY_ROLE_ATTESTATION),
    )


def policy_hash64_v2(entry: FreshEntryV2W64) -> bytes:
    return _blake(
        policy_tuple(entry),
        FRESH_V2_W64_WIDTH,
        identity_personalization(IDENTITY_ROLE_POLICY, FRESH_V2_W64_WIDTH),
    )


def oracle_hash64_v2(source: OracleAuthoritySourceV2) -> bytes:
    return _blake(
        source.encode(),
        FRESH_V2_W64_WIDTH,
        identity_personalization(IDENTITY_ROLE_ORACLE, FRESH_V2_W64_WIDTH),
    )


def attestation_hash64_v2(source: AttestationAuthoritySourceV2) -> bytes:
    return _blake(
        source.encode(),
        FRESH_V2_W64_WIDTH,
        identity_personalization(IDENTITY_ROLE_ATTESTATION, FRESH_V2_W64_WIDTH),
    )


def sample_fresh_entry_v2(
    asset_id: int = 1001, policy_version: int = 3
) -> tuple[FreshEntryV2, OracleAuthoritySourceV2, AttestationAuthoritySourceV2]:
    delta = asset_id - 1001
    oracle = OracleAuthoritySourceV2(
        asset_id=asset_id,
        policy_version=policy_version,
        oracle_feed=7 + delta,
        submitted_at=42,
        source_id=bytes([0x31 + delta % 31]) * 32,
        payload=b"price:i128le=" + (123_456 + delta).to_bytes(16, "little"),
    )
    attestation = AttestationAuthoritySourceV2(
        asset_id=asset_id,
        policy_version=policy_version,
        attestation_id=0x0102_0304_0506_0708 + delta,
        created_at=9,
        issuer_id=bytes([0x51 + delta % 31]) * 32,
        payload=b"eligible:true",
    )
    entry = FreshEntryV2(
        asset_id=asset_id,
        oracle_feed=oracle.oracle_feed,
        attestation_id=attestation.attestation_id,
        min_collateral_ratio_ppm=1_500_000,
        max_mint_per_epoch=1_000_000_000,
        oracle_max_age=120,
        oracle_submitted_at=oracle.submitted_at,
        enabled_at=10,
        retired_at=1000,
        policy_version=policy_version,
        active=True,
        oracle_commitment=oracle_hash56_v2(oracle),
        attestation_commitment=attestation_hash56_v2(attestation),
        attestation_disputed=False,
    )
    return entry, oracle, attestation


def sample_fresh_entry_v2_w64(
    asset_id: int = 1001, policy_version: int = 3
) -> tuple[
    FreshEntryV2W64,
    OracleAuthoritySourceV2,
    AttestationAuthoritySourceV2,
]:
    _, oracle, attestation = sample_fresh_entry_v2(asset_id, policy_version)
    entry = FreshEntryV2W64(
        asset_id=asset_id,
        oracle_feed=oracle.oracle_feed,
        attestation_id=attestation.attestation_id,
        min_collateral_ratio_ppm=1_500_000,
        max_mint_per_epoch=1_000_000_000,
        oracle_max_age=120,
        oracle_submitted_at=oracle.submitted_at,
        enabled_at=10,
        retired_at=1000,
        policy_version=policy_version,
        active=True,
        oracle_commitment=oracle_hash64_v2(oracle),
        attestation_commitment=attestation_hash64_v2(attestation),
        attestation_disputed=False,
    )
    return entry, oracle, attestation


def reject_legacy48_to_fresh56(legacy: bytes) -> bytes:
    """There is intentionally no migration constructor for an old digest."""

    _require_bytes("legacy authority", legacy, LIVE_BYTES)
    raise Reject(
        "legacy 48-byte authority cannot be padded, truncated, or rehashed "
        "into a fresh 56-byte identity; supply the canonical V2 source"
    )


def reject_fresh56_to_legacy48(fresh: bytes) -> bytes:
    _require_bytes("fresh authority", fresh, FRESH_V2_WIDTH)
    raise Reject("fresh 56-byte authority cannot be truncated to legacy48")


def reject_fresh56_to_w64(fresh: bytes) -> bytes:
    _require_bytes("fresh W56 authority", fresh, FRESH_V2_WIDTH)
    raise Reject(
        "W56 authority cannot be padded or rehashed into W64; rerun the W64 "
        "constructor over the canonical source"
    )


def reject_w64_to_fresh56(fresh: bytes) -> bytes:
    _require_bytes("fresh W64 authority", fresh, FRESH_V2_W64_WIDTH)
    raise Reject("W64 authority cannot be truncated into W56")


def canonical_entries(
    entries: Sequence[Entry | FreshEntryV2], cap: int = CAP
) -> tuple[Entry | FreshEntryV2, ...]:
    _check_profile(56, cap)
    if len(entries) > cap:
        raise Reject("manifest exceeds its consensus cap")
    out = tuple(entries)
    for entry in out:
        entry.validate()
    for left, right in zip(out, out[1:]):
        if not left.key < right.key:
            raise Reject(
                "manifest keys must be strictly increasing by numeric "
                "(asset_id, policy_version); duplicate keys reject"
            )
    return out


def slots(entries: Sequence[Entry], cap: int = CAP) -> tuple[bytes, ...]:
    ordered = canonical_entries(entries, cap)
    if not all(isinstance(entry, Entry) for entry in ordered):
        raise Reject("compatibility manifest contains a fresh V2 row")
    present = tuple(b"\x01" + entry.encode() for entry in ordered)
    empty = b"\x00" + bytes(ENTRY_BYTES)
    out = present + (empty,) * (cap - len(present))
    if len(out) != cap or any(len(slot) != ENTRY_BYTES + 1 for slot in out):
        raise AssertionError("fixed slot encoding drift")
    return out


def full_root(entries: Sequence[Entry], width: int, cap: int = CAP) -> bytes:
    payload = b"".join(slots(entries, cap))
    if len(payload) != cap * (ENTRY_BYTES + 1):
        raise AssertionError(len(payload))
    return _blake(payload, width, personalization(ROLE_FULL, width, cap))


def leaf_hash(slot: bytes, width: int, cap: int = CAP) -> bytes:
    _require_bytes("manifest leaf slot", slot, ENTRY_BYTES + 1)
    if slot[0] not in (0, 1):
        raise Reject("leaf presence byte is not canonical")
    if slot[0] == 0 and slot[1:] != bytes(ENTRY_BYTES):
        raise Reject("empty leaf carries nonzero padding")
    if slot[0] == 1:
        Entry.decode(slot[1:])
    return _blake(slot, width, personalization(ROLE_LEAF, width, cap))


def node_hash(left: bytes, right: bytes, width: int, cap: int, level: int) -> bytes:
    _require_bytes("left child", left, width)
    _require_bytes("right child", right, width)
    return _blake(
        left + right,
        width,
        personalization(ROLE_NODE, width, cap, level),
    )


def merkle_levels(entries: Sequence[Entry], width: int, cap: int = CAP) -> list[list[bytes]]:
    depth = _check_profile(width, cap)
    levels = [[leaf_hash(slot, width, cap) for slot in slots(entries, cap)]]
    for level in range(depth):
        prior = levels[-1]
        levels.append(
            [
                node_hash(prior[i], prior[i + 1], width, cap, level)
                for i in range(0, len(prior), 2)
            ]
        )
    if len(levels[-1]) != 1:
        raise AssertionError("Merkle tree did not reduce to one root")
    return levels


def merkle_root(entries: Sequence[Entry], width: int, cap: int = CAP) -> bytes:
    return merkle_levels(entries, width, cap)[-1][0]


@dataclasses.dataclass(frozen=True)
class MerkleWitness:
    index: int
    entry: Entry
    siblings: tuple[bytes, ...]

    def encode(self, width: int, cap: int = CAP) -> bytes:
        depth = _check_profile(width, cap)
        _require_uint("selected index", self.index, 32)
        if self.index >= cap or len(self.siblings) != depth:
            raise Reject("membership path shape mismatch")
        for sibling in self.siblings:
            _require_bytes("membership sibling", sibling, width)
        return (
            self.index.to_bytes(4, "little")
            + self.entry.encode()
            + b"".join(self.siblings)
        )

    @classmethod
    def decode(cls, raw: bytes, width: int, cap: int = CAP) -> "MerkleWitness":
        depth = _check_profile(width, cap)
        expected = 4 + ENTRY_BYTES + depth * width
        _require_bytes("Merkle witness", raw, expected)
        index = int.from_bytes(raw[:4], "little")
        if index >= cap:
            raise Reject("selected index exceeds the fixed cap")
        entry = Entry.decode(raw[4 : 4 + ENTRY_BYTES])
        cursor = 4 + ENTRY_BYTES
        siblings = tuple(
            raw[cursor + level * width : cursor + (level + 1) * width]
            for level in range(depth)
        )
        witness = cls(index, entry, siblings)
        if witness.encode(width, cap) != raw:
            raise Reject("Merkle witness does not canonically round trip")
        return witness


def prove_merkle(
    entries: Sequence[Entry], index: int, width: int, cap: int = CAP
) -> MerkleWitness:
    ordered = canonical_entries(entries, cap)
    if not (0 <= index < len(ordered)):
        raise Reject("selected index is not a present manifest member")
    levels = merkle_levels(ordered, width, cap)
    cursor = index
    siblings = []
    for level in range(_check_profile(width, cap)):
        siblings.append(levels[level][cursor ^ 1])
        cursor //= 2
    return MerkleWitness(index, ordered[index], tuple(siblings))


def root_from_witness(witness: MerkleWitness, width: int, cap: int = CAP) -> bytes:
    depth = _check_profile(width, cap)
    if not (0 <= witness.index < cap) or len(witness.siblings) != depth:
        raise Reject("membership path shape mismatch")
    current = leaf_hash(b"\x01" + witness.entry.encode(), width, cap)
    cursor = witness.index
    for level, sibling in enumerate(witness.siblings):
        _require_bytes("membership sibling", sibling, width)
        if cursor & 1:
            current = node_hash(sibling, current, width, cap, level)
        else:
            current = node_hash(current, sibling, width, cap, level)
        cursor >>= 1
    if cursor != 0:
        raise Reject("membership index has nonzero bits above the tree depth")
    return current


def fresh_v2_slots(
    entries: Sequence[FreshEntryV2], cap: int = CAP
) -> tuple[bytes, ...]:
    ordered = canonical_entries(entries, cap)
    if not all(isinstance(entry, FreshEntryV2) for entry in ordered):
        raise Reject("fresh V2 manifest contains a compatibility row")
    present = tuple(b"\x01" + entry.encode() for entry in ordered)
    empty = bytes(FRESH_V2_ENTRY_BYTES + 1)
    out = present + (empty,) * (cap - len(present))
    if len(out) != cap or any(
        len(slot) != FRESH_V2_ENTRY_BYTES + 1 for slot in out
    ):
        raise AssertionError("fresh V2 fixed-slot geometry drift")
    return out


def fresh_v2_full_root(
    entries: Sequence[FreshEntryV2], width: int = FRESH_V2_WIDTH, cap: int = CAP
) -> bytes:
    payload = b"".join(fresh_v2_slots(entries, cap))
    return _blake(
        payload,
        width,
        personalization(
            ROLE_FULL,
            width,
            cap,
            profile=FRESH_V2_AUTHORITY_PROFILE,
        ),
    )


def fresh_v2_leaf_hash(
    slot: bytes, width: int = FRESH_V2_WIDTH, cap: int = CAP
) -> bytes:
    _require_bytes("fresh V2 leaf slot", slot, FRESH_V2_ENTRY_BYTES + 1)
    if slot[0] not in (0, 1):
        raise Reject("fresh V2 leaf presence byte is not canonical")
    if slot[0] == 0 and slot[1:] != bytes(FRESH_V2_ENTRY_BYTES):
        raise Reject("fresh V2 empty leaf carries nonzero padding")
    if slot[0] == 1:
        FreshEntryV2.decode(slot[1:])
    return _blake(
        slot,
        width,
        personalization(
            ROLE_LEAF,
            width,
            cap,
            profile=FRESH_V2_AUTHORITY_PROFILE,
        ),
    )


def fresh_v2_node_hash(
    left: bytes,
    right: bytes,
    width: int,
    cap: int,
    level: int,
) -> bytes:
    _require_bytes("fresh V2 left child", left, width)
    _require_bytes("fresh V2 right child", right, width)
    return _blake(
        left + right,
        width,
        personalization(
            ROLE_NODE,
            width,
            cap,
            level,
            FRESH_V2_AUTHORITY_PROFILE,
        ),
    )


def fresh_v2_merkle_levels(
    entries: Sequence[FreshEntryV2],
    width: int = FRESH_V2_WIDTH,
    cap: int = CAP,
) -> list[list[bytes]]:
    depth = _check_profile(width, cap)
    levels = [
        [fresh_v2_leaf_hash(slot, width, cap) for slot in fresh_v2_slots(entries, cap)]
    ]
    for level in range(depth):
        prior = levels[-1]
        levels.append(
            [
                fresh_v2_node_hash(prior[i], prior[i + 1], width, cap, level)
                for i in range(0, len(prior), 2)
            ]
        )
    if len(levels[-1]) != 1:
        raise AssertionError("fresh V2 Merkle tree did not reduce to one root")
    return levels


def fresh_v2_merkle_root(
    entries: Sequence[FreshEntryV2],
    width: int = FRESH_V2_WIDTH,
    cap: int = CAP,
) -> bytes:
    return fresh_v2_merkle_levels(entries, width, cap)[-1][0]


@dataclasses.dataclass(frozen=True)
class FreshMerkleWitnessV2:
    index: int
    entry: FreshEntryV2
    siblings: tuple[bytes, ...]

    def encode(self, width: int = FRESH_V2_WIDTH, cap: int = CAP) -> bytes:
        depth = _check_profile(width, cap)
        _require_uint("fresh V2 selected index", self.index, 32)
        if self.index >= cap or len(self.siblings) != depth:
            raise Reject("fresh V2 membership path shape mismatch")
        for sibling in self.siblings:
            _require_bytes("fresh V2 membership sibling", sibling, width)
        return (
            self.index.to_bytes(4, "little")
            + self.entry.encode()
            + b"".join(self.siblings)
        )

    @classmethod
    def decode(
        cls, raw: bytes, width: int = FRESH_V2_WIDTH, cap: int = CAP
    ) -> "FreshMerkleWitnessV2":
        depth = _check_profile(width, cap)
        expected = 4 + FRESH_V2_ENTRY_BYTES + depth * width
        _require_bytes("fresh V2 Merkle witness", raw, expected)
        index = int.from_bytes(raw[:4], "little")
        if index >= cap:
            raise Reject("fresh V2 selected index exceeds the fixed cap")
        entry = FreshEntryV2.decode(raw[4 : 4 + FRESH_V2_ENTRY_BYTES])
        cursor = 4 + FRESH_V2_ENTRY_BYTES
        siblings = tuple(
            raw[cursor + level * width : cursor + (level + 1) * width]
            for level in range(depth)
        )
        value = cls(index, entry, siblings)
        if value.encode(width, cap) != raw:
            raise Reject("fresh V2 membership witness is noncanonical")
        return value


def prove_fresh_v2_merkle(
    entries: Sequence[FreshEntryV2],
    index: int,
    width: int = FRESH_V2_WIDTH,
    cap: int = CAP,
) -> FreshMerkleWitnessV2:
    ordered = canonical_entries(entries, cap)
    if not all(isinstance(entry, FreshEntryV2) for entry in ordered):
        raise Reject("fresh V2 manifest contains a compatibility row")
    if not (0 <= index < len(ordered)):
        raise Reject("fresh V2 selected index is not present")
    levels = fresh_v2_merkle_levels(entries, width, cap)
    cursor = index
    siblings = []
    for level in range(_check_profile(width, cap)):
        siblings.append(levels[level][cursor ^ 1])
        cursor //= 2
    return FreshMerkleWitnessV2(index, ordered[index], tuple(siblings))


def fresh_v2_root_from_witness(
    witness: FreshMerkleWitnessV2,
    width: int = FRESH_V2_WIDTH,
    cap: int = CAP,
) -> bytes:
    depth = _check_profile(width, cap)
    if not (0 <= witness.index < cap) or len(witness.siblings) != depth:
        raise Reject("fresh V2 membership path shape mismatch")
    current = fresh_v2_leaf_hash(
        b"\x01" + witness.entry.encode(), width, cap
    )
    cursor = witness.index
    for level, sibling in enumerate(witness.siblings):
        _require_bytes("fresh V2 membership sibling", sibling, width)
        if cursor & 1:
            current = fresh_v2_node_hash(sibling, current, width, cap, level)
        else:
            current = fresh_v2_node_hash(current, sibling, width, cap, level)
        cursor >>= 1
    if cursor != 0:
        raise Reject("fresh V2 membership index has high bits")
    return current


def fresh_v2_w64_slots(
    entries: Sequence[FreshEntryV2W64], cap: int = CAP
) -> tuple[bytes, ...]:
    ordered = canonical_entries(entries, cap)
    if not all(type(entry) is FreshEntryV2W64 for entry in ordered):
        raise Reject("fresh V2 W64 manifest contains a different row grammar")
    present = tuple(b"\x01" + entry.encode() for entry in ordered)
    empty = bytes(FRESH_V2_W64_ENTRY_BYTES + 1)
    out = present + (empty,) * (cap - len(present))
    if len(out) != cap or any(
        len(slot) != FRESH_V2_W64_ENTRY_BYTES + 1 for slot in out
    ):
        raise AssertionError("fresh V2 W64 fixed-slot geometry drift")
    return out


def fresh_v2_w64_full_root(
    entries: Sequence[FreshEntryV2W64], cap: int = CAP
) -> bytes:
    return _blake(
        b"".join(fresh_v2_w64_slots(entries, cap)),
        FRESH_V2_W64_WIDTH,
        personalization(
            ROLE_FULL,
            FRESH_V2_W64_WIDTH,
            cap,
            profile=FRESH_V2_AUTHORITY_PROFILE,
        ),
    )


def fresh_v2_w64_leaf_hash(slot: bytes, cap: int = CAP) -> bytes:
    _require_bytes(
        "fresh V2 W64 leaf slot", slot, FRESH_V2_W64_ENTRY_BYTES + 1
    )
    if slot[0] not in (0, 1):
        raise Reject("fresh V2 W64 leaf presence byte is not canonical")
    if slot[0] == 0 and slot[1:] != bytes(FRESH_V2_W64_ENTRY_BYTES):
        raise Reject("fresh V2 W64 empty leaf carries nonzero padding")
    if slot[0] == 1:
        FreshEntryV2W64.decode(slot[1:])
    return _blake(
        slot,
        FRESH_V2_W64_WIDTH,
        personalization(
            ROLE_LEAF,
            FRESH_V2_W64_WIDTH,
            cap,
            profile=FRESH_V2_AUTHORITY_PROFILE,
        ),
    )


def fresh_v2_w64_merkle_levels(
    entries: Sequence[FreshEntryV2W64], cap: int = CAP
) -> list[list[bytes]]:
    depth = _check_profile(FRESH_V2_W64_WIDTH, cap)
    levels = [
        [fresh_v2_w64_leaf_hash(slot, cap) for slot in fresh_v2_w64_slots(entries, cap)]
    ]
    for level in range(depth):
        prior = levels[-1]
        levels.append(
            [
                fresh_v2_node_hash(
                    prior[i],
                    prior[i + 1],
                    FRESH_V2_W64_WIDTH,
                    cap,
                    level,
                )
                for i in range(0, len(prior), 2)
            ]
        )
    return levels


def fresh_v2_w64_merkle_root(
    entries: Sequence[FreshEntryV2W64], cap: int = CAP
) -> bytes:
    return fresh_v2_w64_merkle_levels(entries, cap)[-1][0]


@dataclasses.dataclass(frozen=True)
class FreshMerkleWitnessV2W64:
    index: int
    entry: FreshEntryV2W64
    siblings: tuple[bytes, ...]

    def encode(self, cap: int = CAP) -> bytes:
        depth = _check_profile(FRESH_V2_W64_WIDTH, cap)
        _require_uint("fresh V2 W64 selected index", self.index, 32)
        if self.index >= cap or len(self.siblings) != depth:
            raise Reject("fresh V2 W64 membership path shape mismatch")
        for sibling in self.siblings:
            _require_bytes(
                "fresh V2 W64 membership sibling", sibling, FRESH_V2_W64_WIDTH
            )
        return (
            self.index.to_bytes(4, "little")
            + self.entry.encode()
            + b"".join(self.siblings)
        )

    @classmethod
    def decode(cls, raw: bytes, cap: int = CAP) -> "FreshMerkleWitnessV2W64":
        depth = _check_profile(FRESH_V2_W64_WIDTH, cap)
        expected = (
            4 + FRESH_V2_W64_ENTRY_BYTES + depth * FRESH_V2_W64_WIDTH
        )
        _require_bytes("fresh V2 W64 Merkle witness", raw, expected)
        index = int.from_bytes(raw[:4], "little")
        if index >= cap:
            raise Reject("fresh V2 W64 selected index exceeds cap")
        entry = FreshEntryV2W64.decode(
            raw[4 : 4 + FRESH_V2_W64_ENTRY_BYTES]
        )
        cursor = 4 + FRESH_V2_W64_ENTRY_BYTES
        siblings = tuple(
            raw[
                cursor + level * FRESH_V2_W64_WIDTH : cursor
                + (level + 1) * FRESH_V2_W64_WIDTH
            ]
            for level in range(depth)
        )
        value = cls(index, entry, siblings)
        if value.encode(cap) != raw:
            raise Reject("fresh V2 W64 witness is noncanonical")
        return value


def prove_fresh_v2_w64_merkle(
    entries: Sequence[FreshEntryV2W64], index: int, cap: int = CAP
) -> FreshMerkleWitnessV2W64:
    ordered = canonical_entries(entries, cap)
    if not all(type(entry) is FreshEntryV2W64 for entry in ordered):
        raise Reject("fresh V2 W64 manifest contains a different row grammar")
    if not (0 <= index < len(ordered)):
        raise Reject("fresh V2 W64 selected index is absent")
    levels = fresh_v2_w64_merkle_levels(entries, cap)
    cursor = index
    siblings = []
    for level in range(_check_profile(FRESH_V2_W64_WIDTH, cap)):
        siblings.append(levels[level][cursor ^ 1])
        cursor //= 2
    return FreshMerkleWitnessV2W64(index, ordered[index], tuple(siblings))


def fresh_v2_w64_root_from_witness(
    witness: FreshMerkleWitnessV2W64, cap: int = CAP
) -> bytes:
    depth = _check_profile(FRESH_V2_W64_WIDTH, cap)
    if not (0 <= witness.index < cap) or len(witness.siblings) != depth:
        raise Reject("fresh V2 W64 membership path shape mismatch")
    current = fresh_v2_w64_leaf_hash(b"\x01" + witness.entry.encode(), cap)
    cursor = witness.index
    for level, sibling in enumerate(witness.siblings):
        _require_bytes(
            "fresh V2 W64 membership sibling", sibling, FRESH_V2_W64_WIDTH
        )
        if cursor & 1:
            current = fresh_v2_node_hash(
                sibling,
                current,
                FRESH_V2_W64_WIDTH,
                cap,
                level,
            )
        else:
            current = fresh_v2_node_hash(
                current,
                sibling,
                FRESH_V2_W64_WIDTH,
                cap,
                level,
            )
        cursor >>= 1
    if cursor != 0:
        raise Reject("fresh V2 W64 index has high bits")
    return current


def snapshot_commitment(
    root: bytes,
    parent_height: int,
    width: int,
    cap: int = CAP,
    profile: int = COMPAT_AUTHORITY_PROFILE,
) -> bytes:
    _require_bytes("manifest authority root", root, width)
    _require_uint("parent_height", parent_height, 64)
    return _blake(
        parent_height.to_bytes(8, "little") + root,
        width,
        personalization(ROLE_SNAPSHOT, width, cap, profile=profile),
    )


@dataclasses.dataclass(frozen=True)
class PublicAuthority:
    """Proof-public root and parent height; profile is fixed by transaction identity."""

    root: bytes
    parent_height: int

    def encode(self, width: int) -> bytes:
        _require_bytes("public authority root", self.root, width)
        _require_uint("public parent height", self.parent_height, 64)
        return self.root + self.parent_height.to_bytes(8, "little")

    @classmethod
    def decode(cls, raw: bytes, width: int) -> "PublicAuthority":
        _require_bytes("public authority", raw, width + 8)
        return cls(raw[:width], int.from_bytes(raw[width:], "little"))


@dataclasses.dataclass(frozen=True)
class ParentStateAuthority:
    """Verifier-owned consensus input, never a prover-controlled witness."""

    root: bytes
    parent_height: int
    snapshot: bytes

    @classmethod
    def from_state(
        cls,
        root: bytes,
        parent_height: int,
        width: int,
        cap: int = CAP,
        profile: int = COMPAT_AUTHORITY_PROFILE,
    ) -> "ParentStateAuthority":
        return cls(
            root,
            parent_height,
            snapshot_commitment(root, parent_height, width, cap, profile),
        )

    def validate(
        self,
        width: int,
        cap: int = CAP,
        profile: int = COMPAT_AUTHORITY_PROFILE,
    ) -> None:
        _require_bytes("parent-state root", self.root, width)
        _require_bytes("parent-state snapshot", self.snapshot, width)
        _require_uint("parent-state height", self.parent_height, 64)
        if self.snapshot != snapshot_commitment(
            self.root, self.parent_height, width, cap, profile
        ):
            raise Reject("parent-state snapshot authentication failed")


@dataclasses.dataclass(frozen=True)
class StablecoinBinding:
    asset_id: int
    policy_version: int
    issuance_magnitude: int
    policy_hash: bytes
    oracle_commitment: bytes
    attestation_commitment: bytes

    def validate(self) -> None:
        _require_uint("binding asset_id", self.asset_id, 64)
        _require_uint("binding policy_version", self.policy_version, 32)
        _require_uint("binding issuance_magnitude", self.issuance_magnitude, 64)
        _require_bytes("binding policy_hash", self.policy_hash, LIVE_BYTES)
        _require_bytes(
            "binding oracle_commitment", self.oracle_commitment, LIVE_BYTES
        )
        _require_bytes(
            "binding attestation_commitment",
            self.attestation_commitment,
            LIVE_BYTES,
        )


def binding_for(entry: Entry, issuance_magnitude: int = 1) -> StablecoinBinding:
    return StablecoinBinding(
        asset_id=entry.asset_id,
        policy_version=entry.policy_version,
        issuance_magnitude=issuance_magnitude,
        policy_hash=policy_hash48(entry),
        oracle_commitment=entry.oracle_commitment,
        attestation_commitment=entry.attestation_commitment,
    )


@dataclasses.dataclass(frozen=True)
class FreshStablecoinBindingV2:
    asset_id: int
    policy_version: int
    issuance_magnitude: int
    policy_hash: bytes
    oracle_commitment: bytes
    attestation_commitment: bytes

    def validate(self) -> None:
        _require_uint("fresh binding asset_id", self.asset_id, 64)
        _require_uint("fresh binding policy_version", self.policy_version, 32)
        _require_uint("fresh binding issuance_magnitude", self.issuance_magnitude, 64)
        _require_bytes("fresh binding policy hash", self.policy_hash, FRESH_V2_WIDTH)
        _require_bytes(
            "fresh binding oracle commitment",
            self.oracle_commitment,
            FRESH_V2_WIDTH,
        )
        _require_bytes(
            "fresh binding attestation commitment",
            self.attestation_commitment,
            FRESH_V2_WIDTH,
        )


def fresh_binding_for(
    entry: FreshEntryV2, issuance_magnitude: int = 1
) -> FreshStablecoinBindingV2:
    return FreshStablecoinBindingV2(
        asset_id=entry.asset_id,
        policy_version=entry.policy_version,
        issuance_magnitude=issuance_magnitude,
        policy_hash=policy_hash56_v2(entry),
        oracle_commitment=entry.oracle_commitment,
        attestation_commitment=entry.attestation_commitment,
    )


def validate_fresh_v2_constructor_sources(
    entry: FreshEntryV2,
    oracle: OracleAuthoritySourceV2,
    attestation: AttestationAuthoritySourceV2,
) -> None:
    """Prospective state-writer constructor check, not current authority."""

    entry.validate()
    oracle.validate()
    attestation.validate()
    if (
        oracle.asset_id != entry.asset_id
        or oracle.policy_version != entry.policy_version
        or oracle.oracle_feed != entry.oracle_feed
        or oracle.submitted_at != entry.oracle_submitted_at
    ):
        raise Reject("oracle V2 source metadata does not match its manifest row")
    if (
        attestation.asset_id != entry.asset_id
        or attestation.policy_version != entry.policy_version
        or attestation.attestation_id != entry.attestation_id
    ):
        raise Reject(
            "attestation V2 source metadata does not match its manifest row"
        )
    if entry.oracle_commitment != oracle_hash56_v2(oracle):
        raise Reject("fresh oracle constructor output mismatch")
    if entry.attestation_commitment != attestation_hash56_v2(attestation):
        raise Reject("fresh attestation constructor output mismatch")


@dataclasses.dataclass(frozen=True)
class FreshStablecoinBindingV2W64:
    asset_id: int
    policy_version: int
    issuance_magnitude: int
    policy_hash: bytes
    oracle_commitment: bytes
    attestation_commitment: bytes

    def validate(self) -> None:
        _require_uint("W64 binding asset_id", self.asset_id, 64)
        _require_uint("W64 binding policy_version", self.policy_version, 32)
        _require_uint("W64 binding issuance_magnitude", self.issuance_magnitude, 64)
        _require_bytes("W64 binding policy hash", self.policy_hash, 64)
        _require_bytes("W64 binding oracle commitment", self.oracle_commitment, 64)
        _require_bytes(
            "W64 binding attestation commitment",
            self.attestation_commitment,
            64,
        )


def fresh_w64_binding_for(
    entry: FreshEntryV2W64, issuance_magnitude: int = 1
) -> FreshStablecoinBindingV2W64:
    return FreshStablecoinBindingV2W64(
        asset_id=entry.asset_id,
        policy_version=entry.policy_version,
        issuance_magnitude=issuance_magnitude,
        policy_hash=policy_hash64_v2(entry),
        oracle_commitment=entry.oracle_commitment,
        attestation_commitment=entry.attestation_commitment,
    )


def validate_fresh_v2_w64_constructor_sources(
    entry: FreshEntryV2W64,
    oracle: OracleAuthoritySourceV2,
    attestation: AttestationAuthoritySourceV2,
) -> None:
    entry.validate()
    oracle.validate()
    attestation.validate()
    if (
        oracle.asset_id != entry.asset_id
        or oracle.policy_version != entry.policy_version
        or oracle.oracle_feed != entry.oracle_feed
        or oracle.submitted_at != entry.oracle_submitted_at
    ):
        raise Reject("W64 oracle source metadata does not match its row")
    if (
        attestation.asset_id != entry.asset_id
        or attestation.policy_version != entry.policy_version
        or attestation.attestation_id != entry.attestation_id
    ):
        raise Reject("W64 attestation source metadata does not match its row")
    if entry.oracle_commitment != oracle_hash64_v2(oracle):
        raise Reject("W64 oracle constructor output mismatch")
    if entry.attestation_commitment != attestation_hash64_v2(attestation):
        raise Reject("W64 attestation constructor output mismatch")


def verify_entry(binding: StablecoinBinding, entry: Entry, parent_height: int) -> None:
    binding.validate()
    entry.validate()
    if policy_hash48(entry) != binding.policy_hash:
        raise Reject("exact 61-byte policy-identity recomputation failed")
    if entry.asset_id != binding.asset_id:
        raise Reject("selected entry asset mismatch")
    if entry.policy_version != binding.policy_version:
        raise Reject("selected entry policy version mismatch")
    if entry.oracle_commitment != binding.oracle_commitment:
        raise Reject("selected entry oracle commitment mismatch")
    if entry.attestation_commitment != binding.attestation_commitment:
        raise Reject("selected entry attestation commitment mismatch")
    if not entry.active:
        raise Reject("selected entry is inactive")
    if parent_height < entry.enabled_at:
        raise Reject("selected entry is not enabled at parent height")
    if entry.retired_at is not None and parent_height >= entry.retired_at:
        raise Reject("selected entry is retired at parent height")
    if entry.attestation_disputed:
        raise Reject("selected entry attestation is disputed")
    if entry.oracle_submitted_at > parent_height:
        raise Reject("oracle submission is from the future")
    if parent_height - entry.oracle_submitted_at > entry.oracle_max_age:
        raise Reject("oracle is stale")
    if binding.issuance_magnitude == 0:
        raise Reject("issuance magnitude is zero")
    if binding.issuance_magnitude > entry.max_mint_per_epoch:
        raise Reject("issuance exceeds the selected entry cap")


def verify_parent_public(
    public: PublicAuthority,
    parent: ParentStateAuthority,
    width: int,
    cap: int = CAP,
    profile: int = COMPAT_AUTHORITY_PROFILE,
) -> None:
    """Exact outer verifier comparison, not an in-relation membership row."""

    parent.validate(width, cap, profile)
    public.encode(width)
    if public.root != parent.root or public.parent_height != parent.parent_height:
        raise Reject("proof-public root/height do not equal verifier parent state")


def verify_merkle_authority(
    binding: StablecoinBinding,
    public: PublicAuthority,
    witness: MerkleWitness,
    parent: ParentStateAuthority,
    width: int,
    cap: int = CAP,
) -> None:
    # This comparison belongs to the node/verifier boundary.
    verify_parent_public(public, parent, width, cap)
    # These predicates belong to the proof relation.
    if root_from_witness(witness, width, cap) != public.root:
        raise Reject("selected entry/path is not a member of the public root")
    verify_entry(binding, witness.entry, public.parent_height)


def verify_full_authority(
    binding: StablecoinBinding,
    public: PublicAuthority,
    entries: Sequence[Entry],
    selected_index: int,
    parent: ParentStateAuthority,
    width: int,
    cap: int = CAP,
) -> None:
    verify_parent_public(public, parent, width, cap)
    ordered = canonical_entries(entries, cap)
    if not (0 <= selected_index < len(ordered)):
        raise Reject("selected full-vector index is absent")
    if full_root(ordered, width, cap) != public.root:
        raise Reject("full manifest does not recompute the public root")
    verify_entry(binding, ordered[selected_index], public.parent_height)


def verify_fresh_entry_v2(
    binding: FreshStablecoinBindingV2,
    entry: FreshEntryV2,
    parent_height: int,
) -> None:
    binding.validate()
    entry.validate()
    if policy_hash56_v2(entry) != binding.policy_hash:
        raise Reject("fresh 61-byte policy-identity recomputation failed")
    if entry.asset_id != binding.asset_id:
        raise Reject("fresh selected entry asset mismatch")
    if entry.policy_version != binding.policy_version:
        raise Reject("fresh selected entry policy version mismatch")
    if entry.oracle_commitment != binding.oracle_commitment:
        raise Reject("fresh selected entry oracle commitment mismatch")
    if entry.attestation_commitment != binding.attestation_commitment:
        raise Reject("fresh selected entry attestation commitment mismatch")
    if not entry.active:
        raise Reject("fresh selected entry is inactive")
    if parent_height < entry.enabled_at:
        raise Reject("fresh selected entry is not enabled at parent height")
    if entry.retired_at is not None and parent_height >= entry.retired_at:
        raise Reject("fresh selected entry is retired at parent height")
    if entry.attestation_disputed:
        raise Reject("fresh selected entry attestation is disputed")
    if entry.oracle_submitted_at > parent_height:
        raise Reject("fresh oracle submission is from the future")
    if parent_height - entry.oracle_submitted_at > entry.oracle_max_age:
        raise Reject("fresh oracle is stale")
    if binding.issuance_magnitude == 0:
        raise Reject("fresh issuance magnitude is zero")
    if binding.issuance_magnitude > entry.max_mint_per_epoch:
        raise Reject("fresh issuance exceeds the selected entry cap")


def verify_fresh_v2_merkle_authority(
    binding: FreshStablecoinBindingV2,
    public: PublicAuthority,
    witness: FreshMerkleWitnessV2,
    parent: ParentStateAuthority,
    width: int = FRESH_V2_WIDTH,
    cap: int = CAP,
) -> None:
    # Parent-state authentication/equality remains an outer verifier action.
    verify_parent_public(
        public,
        parent,
        width,
        cap,
        FRESH_V2_AUTHORITY_PROFILE,
    )
    # Only membership and stablecoin semantics are in the prospective relation.
    if fresh_v2_root_from_witness(witness, width, cap) != public.root:
        raise Reject("fresh V2 entry/path is not a member of the public root")
    verify_fresh_entry_v2(binding, witness.entry, public.parent_height)


def verify_fresh_v2_w64_entry(
    binding: FreshStablecoinBindingV2W64,
    entry: FreshEntryV2W64,
    parent_height: int,
) -> None:
    binding.validate()
    entry.validate()
    if policy_hash64_v2(entry) != binding.policy_hash:
        raise Reject("W64 policy-identity recomputation failed")
    if entry.asset_id != binding.asset_id:
        raise Reject("W64 selected entry asset mismatch")
    if entry.policy_version != binding.policy_version:
        raise Reject("W64 selected entry policy version mismatch")
    if entry.oracle_commitment != binding.oracle_commitment:
        raise Reject("W64 selected entry oracle commitment mismatch")
    if entry.attestation_commitment != binding.attestation_commitment:
        raise Reject("W64 selected entry attestation commitment mismatch")
    if not entry.active:
        raise Reject("W64 selected entry is inactive")
    if parent_height < entry.enabled_at:
        raise Reject("W64 selected entry is not enabled")
    if entry.retired_at is not None and parent_height >= entry.retired_at:
        raise Reject("W64 selected entry is retired")
    if entry.attestation_disputed:
        raise Reject("W64 selected entry attestation is disputed")
    if entry.oracle_submitted_at > parent_height:
        raise Reject("W64 oracle submission is from the future")
    if parent_height - entry.oracle_submitted_at > entry.oracle_max_age:
        raise Reject("W64 oracle is stale")
    if binding.issuance_magnitude == 0:
        raise Reject("W64 issuance magnitude is zero")
    if binding.issuance_magnitude > entry.max_mint_per_epoch:
        raise Reject("W64 issuance exceeds the selected entry cap")


def verify_fresh_v2_w64_merkle_authority(
    binding: FreshStablecoinBindingV2W64,
    public: PublicAuthority,
    witness: FreshMerkleWitnessV2W64,
    parent: ParentStateAuthority,
    cap: int = CAP,
) -> None:
    verify_parent_public(
        public,
        parent,
        FRESH_V2_W64_WIDTH,
        cap,
        FRESH_V2_AUTHORITY_PROFILE,
    )
    if fresh_v2_w64_root_from_witness(witness, cap) != public.root:
        raise Reject("W64 entry/path is not a member of the public root")
    verify_fresh_v2_w64_entry(binding, witness.entry, public.parent_height)


def compression_count(message_bytes: int) -> int:
    if message_bytes < 0:
        raise Reject("negative message length")
    return max(1, (message_bytes + BLAKE_BLOCK_BYTES - 1) // BLAKE_BLOCK_BYTES)


def per_compression_cost() -> dict[str, int]:
    # Same explicit Boolean/R1CS schedule as the frozen odd-field compiler:
    # 576 add64 macros and 403 word XORs per compression.
    add64 = 576
    xor_words = 384 + 16 + 3
    full_adder_bits = add64 * 64
    xor_bits = xor_words * 64
    r1cs_rows = add64 * (2 * 64 + 64) + xor_bits
    r1cs_aux = add64 * (2 * 64) + xor_bits
    r1cs_nonzeros = add64 * (2 * 64 * 3 + 5 + 63 * 6) + xor_bits * 5
    return {
        "add64_word_operations": add64,
        "full_adder_bit_positions": full_adder_bits,
        "xor_word_operations": xor_words,
        "xor_bit_operations": xor_bits,
        "boolean_primitive_positions": full_adder_bits + xor_bits,
        "r1cs_rows": r1cs_rows,
        "r1cs_derived_variables": r1cs_aux,
        "r1cs_matrix_nonzeros": r1cs_nonzeros,
        "m4_iadd_opcodes": add64,
        "m4_bxor_opcodes": xor_words,
        "m4_rotr_opcodes": 384,
        "m4_iadd_and_constraints_source_static": add64,
        "m4_iadd_linear_constraints_source_static": add64,
        "m4_bxor_linear_constraints_source_static": xor_words,
        "m4_shift_constraints_source_static": 384,
    }


def cost_profile(
    mode: str,
    width: int,
    row_profile: str = "compat183",
    cap: int = CAP,
) -> dict[str, Any]:
    depth = _check_profile(width, cap)
    if mode not in ("full", "merkle"):
        raise Reject("unknown authority mode")
    if row_profile == "compat183":
        entry_bytes = ENTRY_BYTES
        policy_message_bytes = len(
            legacy_frame(POLICY_DOMAIN_V2, [bytes(POLICY_TUPLE_BYTES)])
        )
        policy_output_bytes = LIVE_BYTES
        authority_profile = COMPAT_AUTHORITY_PROFILE
        policy_label = "legacy_framed_blake2b384"
    elif row_profile == "fresh-v2":
        entry_bytes = FRESH_V2_ENTRY_BYTES
        policy_message_bytes = POLICY_TUPLE_BYTES
        policy_output_bytes = FRESH_V2_WIDTH
        authority_profile = FRESH_V2_AUTHORITY_PROFILE
        policy_label = "fresh_personalized_blake2b448"
    elif row_profile == "fresh-v2-all-w64":
        if width != FRESH_V2_W64_WIDTH:
            raise Reject("the all-W64 row requires a 64-byte manifest root")
        entry_bytes = FRESH_V2_W64_ENTRY_BYTES
        policy_message_bytes = POLICY_TUPLE_BYTES
        policy_output_bytes = FRESH_V2_W64_WIDTH
        authority_profile = FRESH_V2_AUTHORITY_PROFILE
        policy_label = "fresh_personalized_blake2b512"
    else:
        raise Reject("unknown manifest row profile")
    width_bits = width * 8
    entry_bits = entry_bytes * 8
    policy_compressions = compression_count(policy_message_bytes)
    if row_profile == "compat183" and (
        policy_message_bytes != 140 or policy_compressions != 2
    ):
        raise AssertionError("compatibility policy schedule drift")
    if row_profile in ("fresh-v2", "fresh-v2-all-w64") and (
        policy_message_bytes != 61 or policy_compressions != 1
    ):
        raise AssertionError("fresh V2 policy schedule drift")

    if mode == "full":
        root_message_bytes = cap * (entry_bytes + 1)
        root_compressions = compression_count(root_message_bytes)
        semantic_witness_bytes = 4 + root_message_bytes
        slot_words = math.ceil((entry_bytes + 1) / 8)
        m4_witness_words = 1 + cap * slot_words
        routing_selects = (cap - 1) * math.ceil(entry_bytes / 8)
        # Exact bit-R1CS macros selected for this design.
        structural = {
            "new_public_bitness": (width + 8) * 8,
            "new_private_bitness": semantic_witness_bytes * 8,
            "policy_output_conditional_equality": policy_output_bytes * 8,
            "root_output_conditional_equality": width_bits,
            "root_nonzero_reduction_and_implication": width_bits,
            "disabled_public_root_height_zero": width_bits + 64,
            "presence_byte_high_zero": cap * 7,
            "presence_prefix": cap - 1,
            "strict_key_order": (cap - 1) * (320 + 1),
            "zero_unused_entry_rows": cap * entry_bits,
            "binary_selected_entry_mux": (cap - 1) * entry_bits,
            "selected_present": 1,
            "selected_index_high_zero": 32 - depth,
        }
        m4_structure = {
            "private_witness_words": m4_witness_words,
            "private_witness_semantic_bytes": semantic_witness_bytes,
            "private_witness_transport_bytes": m4_witness_words * 8,
            "private_witness_transport_zero_pad_bytes": m4_witness_words * 8
            - semantic_witness_bytes,
            "selected_entry_mux_select_opcodes": routing_selects,
            "unsigned_key_compare_opcodes": cap - 1,
            "conditional_order_assertions": cap - 1,
            "conditional_unused_word_zero_assertions": cap
            * math.ceil(entry_bytes / 8),
            "root_word_conditional_equalities": width // 8,
            "policy_word_conditional_equalities": math.ceil(
                policy_output_bytes / 8
            ),
            "post_compiler_dce_counts": None,
        }
    else:
        leaf_message_bytes = entry_bytes + 1
        node_message_bytes = 2 * width
        leaf_compressions = compression_count(leaf_message_bytes)
        node_compressions = compression_count(node_message_bytes)
        if leaf_compressions != 2 or node_compressions != 1:
            raise AssertionError("fresh Merkle hash schedule drift")
        root_message_bytes = None
        root_compressions = leaf_compressions + depth * node_compressions
        semantic_witness_bytes = 4 + entry_bytes + depth * width
        m4_witness_words = 1 + math.ceil(entry_bytes / 8) + depth * (width // 8)
        routing_selects = 2 * depth * (width // 8)
        structural = {
            "new_public_bitness": (width + 8) * 8,
            "new_private_bitness": semantic_witness_bytes * 8,
            "policy_output_conditional_equality": policy_output_bytes * 8,
            "root_output_conditional_equality": width_bits,
            "root_nonzero_reduction_and_implication": width_bits,
            "disabled_public_root_height_zero": width_bits + 64,
            "selected_index_high_zero": 32 - depth,
            "path_left_right_selects": 2 * depth * width_bits,
            "selected_present": 1,
        }
        m4_structure = {
            "private_witness_words": m4_witness_words,
            "private_witness_semantic_bytes": semantic_witness_bytes,
            "private_witness_transport_bytes": m4_witness_words * 8,
            "private_witness_transport_zero_pad_bytes": m4_witness_words * 8
            - semantic_witness_bytes,
            "entry_transport_zero_pad_bytes": math.ceil(entry_bytes / 8) * 8
            - entry_bytes,
            "path_left_right_select_opcodes": routing_selects,
            "root_word_conditional_equalities": width // 8,
            "policy_word_conditional_equalities": math.ceil(
                policy_output_bytes / 8
            ),
            "post_compiler_dce_counts": None,
        }

    compressions = policy_compressions + root_compressions
    per = per_compression_cost()
    hash_rows = compressions * per["r1cs_rows"]
    hash_aux = compressions * per["r1cs_derived_variables"]
    hash_nnz = compressions * per["r1cs_matrix_nonzeros"]
    structural_rows = sum(structural.values())
    result = {
        "mode": mode,
        "row_profile": row_profile,
        "authority_profile": authority_profile,
        "entry_bytes": entry_bytes,
        "slot_bytes": entry_bytes + 1,
        "width_bytes": width,
        "cap": cap,
        "depth": depth,
        "public_delta_bytes": width + 8,
        "semantic_witness_bytes": semantic_witness_bytes,
        "hash_schedule": {
            "policy_constructor": policy_label,
            "policy_message_bytes": policy_message_bytes,
            "policy_compressions": policy_compressions,
            "fresh_root_message_bytes": root_message_bytes,
            "fresh_root_compressions": root_compressions,
            "total_relation_compressions": compressions,
            "snapshot_state_writer_message_bytes": width + 8,
            "snapshot_state_writer_compressions": 1,
            "merkle_state_full_build_compressions": (
                cap * compression_count(entry_bytes + 1) + (cap - 1)
            ),
            "merkle_state_incremental_update_compressions": (
                compression_count(entry_bytes + 1) + depth
            ),
        },
        "boolean": {
            "hash_full_adder_bit_positions": compressions
            * per["full_adder_bit_positions"],
            "hash_xor_bit_operations": compressions * per["xor_bit_operations"],
            "hash_primitive_positions": compressions
            * per["boolean_primitive_positions"],
            "structural_boolean_r1cs_rows": structural_rows,
        },
        "r1cs": {
            "hash_rows": hash_rows,
            "hash_derived_variables": hash_aux,
            "hash_matrix_nonzeros": hash_nnz,
            "structural_rows": structural,
            "structural_rows_total": structural_rows,
            "delta_rows_total": hash_rows + structural_rows,
            "formal_refinement_complete": False,
        },
        "m4_source_static": {
            **m4_structure,
            "hash_iadd_opcodes": compressions * per["m4_iadd_opcodes"],
            "hash_bxor_opcodes": compressions * per["m4_bxor_opcodes"],
            "hash_rotr_opcodes": compressions * per["m4_rotr_opcodes"],
            "hash_iadd_and_constraints": compressions
            * per["m4_iadd_and_constraints_source_static"],
            "hash_iadd_linear_constraints": compressions
            * per["m4_iadd_linear_constraints_source_static"],
            "hash_bxor_linear_constraints": compressions
            * per["m4_bxor_linear_constraints_source_static"],
            "hash_shift_constraints_separate": compressions
            * per["m4_shift_constraints_source_static"],
            "compiled_geometry_verified": False,
        },
    }
    return result


def cost_report() -> dict[str, Any]:
    profiles = {
        f"{row_profile}-{mode}-w{width}": cost_profile(
            mode, width, row_profile
        )
        for row_profile in ("compat183", "fresh-v2")
        for mode in ("full", "merkle")
        for width in WIDTHS
    }
    profiles.update(
        {
            f"fresh-v2-all-w64-{mode}-w64": cost_profile(
                mode, FRESH_V2_W64_WIDTH, "fresh-v2-all-w64"
            )
            for mode in ("full", "merkle")
        }
    )
    cf56 = profiles["compat183-full-w56"]
    cm56 = profiles["compat183-merkle-w56"]
    cf64 = profiles["compat183-full-w64"]
    cm64 = profiles["compat183-merkle-w64"]
    vf56 = profiles["fresh-v2-full-w56"]
    vm56 = profiles["fresh-v2-merkle-w56"]
    vf64 = profiles["fresh-v2-full-w64"]
    vm64 = profiles["fresh-v2-merkle-w64"]
    af64 = profiles["fresh-v2-all-w64-full-w64"]
    am64 = profiles["fresh-v2-all-w64-merkle-w64"]

    def delta(left: dict[str, Any], right: dict[str, Any]) -> dict[str, int]:
        return {
            "relation_compressions": left["hash_schedule"]
            ["total_relation_compressions"]
            - right["hash_schedule"]["total_relation_compressions"],
            "entry_bytes": left["entry_bytes"] - right["entry_bytes"],
            "slot_bytes": left["slot_bytes"] - right["slot_bytes"],
            "public_bytes": left["public_delta_bytes"]
            - right["public_delta_bytes"],
            "semantic_witness_bytes": left["semantic_witness_bytes"]
            - right["semantic_witness_bytes"],
            "r1cs_rows": left["r1cs"]["delta_rows_total"]
            - right["r1cs"]["delta_rows_total"],
            "m4_witness_words": left["m4_source_static"]["private_witness_words"]
            - right["m4_source_static"]["private_witness_words"],
        }

    return {
        "artifact_schema": "hegemon.manifest-authority-cost-report.v1",
        "authority_profiles": {
            "compat183": COMPAT_AUTHORITY_PROFILE,
            "fresh-v2": FRESH_V2_AUTHORITY_PROFILE,
        },
        "cap": CAP,
        "depth": CAP_LOG2,
        "entry_layout_bytes": {
            "compat183": ENTRY_BYTES,
            "fresh-v2-w56": FRESH_V2_ENTRY_BYTES,
            "fresh-v2-all-w64": FRESH_V2_W64_ENTRY_BYTES,
        },
        "per_compression": per_compression_cost(),
        "fresh_v2_constructor_costs_outside_transaction_relation": {
            "policy_source_bytes": POLICY_TUPLE_BYTES,
            "policy_compressions": 1,
            "oracle_source_header_bytes": 54,
            "oracle_source_payload_bytes": {
                "min": 1,
                "max": AUTHORITY_SOURCE_PAYLOAD_MAX,
            },
            "oracle_compressions": {
                "min": compression_count(55),
                "max": compression_count(54 + AUTHORITY_SOURCE_PAYLOAD_MAX),
                "formula": "ceil((54 + payload_bytes) / 128)",
            },
            "attestation_source_header_bytes": 58,
            "attestation_source_payload_bytes": {
                "min": 1,
                "max": AUTHORITY_SOURCE_PAYLOAD_MAX,
            },
            "attestation_compressions": {
                "min": compression_count(59),
                "max": compression_count(58 + AUTHORITY_SOURCE_PAYLOAD_MAX),
                "formula": "ceil((58 + payload_bytes) / 128)",
            },
            "current_consensus_state_writer_implements_these": False,
        },
        "profiles": profiles,
        "deltas": {
            "compat183_w56_merkle_minus_full": delta(cm56, cf56),
            "compat183_merkle_w64_minus_w56": delta(cm64, cm56),
            "compat183_full_w64_minus_w56": delta(cf64, cf56),
            "fresh_v2_w56_merkle_minus_full": delta(vm56, vf56),
            "fresh_v2_merkle_root_w64_minus_w56": delta(vm64, vm56),
            "fresh_v2_full_root_w64_minus_w56": delta(vf64, vf56),
            "fresh_v2_merkle_w56_minus_compat183": delta(vm56, cm56),
            "fresh_v2_full_w56_minus_compat183": delta(vf56, cf56),
            "all_w64_merkle_minus_fresh_v2_w56": delta(am64, vm56),
            "all_w64_full_minus_fresh_v2_w56": delta(af64, vf56),
            "all_w64_merkle_minus_compat183_w56": delta(am64, cm56),
            "stablecoin_binding_fresh56_minus_live48_bytes": 3
            * (FRESH_V2_WIDTH - LIVE_BYTES),
            "stablecoin_binding_all_w64_minus_fresh56_bytes": 3
            * (FRESH_V2_W64_WIDTH - FRESH_V2_WIDTH),
        },
        "decision": {
            "smallest_compatibility_closure": "compat183-merkle-w56",
            "smallest_source_exact_boundary": "fresh-v2-merkle-w56",
            "w56_disqualified_by_strict_composition": True,
            "w56_composed_epoch_failure_probability": "2^-126",
            "minimum_width_surviving_current_screen": (
                "fresh-v2-all-w64-merkle-w64"
            ),
            "minimum_surviving_width_status": (
                "conditional on explicit BLAKE2b-512 QRO instantiation and "
                "all other fail-closed gates"
            ),
            "production_winner": None,
            "reason": (
                "The exact live-row compatibility route uses 8 relation "
                "compressions and 411 witness bytes but its 48-byte opaque "
                "authorities receive no fresh security credit. The prospective "
                "199-byte V2 row uses 7 relation compressions and 427 witness "
                "bytes, but W56 is disqualified by the conservative 2^-126 "
                "epoch composition. W64 is the minimum width surviving that "
                "screen; a fully widened row is 215 bytes and its Merkle "
                "witness is 475 bytes. Its QRO instantiation, constructor "
                "authority, consensus integration, and proof evidence remain "
                "absent."
            ),
        },
    }


def capability_ledger() -> dict[str, Any]:
    return {
        "artifact_schema": "hegemon.manifest-authority-capability.v1",
        "compatibility_candidate": "compat183-cap16-merkle-blake2b448-profile1",
        "w56_cost_screen": "fresh-v2-row199-cap16-merkle-blake2b448",
        "minimum_surviving_width_candidate": (
            "fresh-v2-row215-cap16-merkle-blake2b512"
        ),
        "compatibility_relation_predicates": {
            "live_policy_identity_blake2b384_exact": True,
            "root_over_exact_183_byte_rows": True,
            "selected_entry_membership_exact": True,
            "root_height_equality_to_verifier_input_exact": True,
            "live48_oracle_attestation_are_equality_only": True,
            "fully_qualified_security_closure": False,
        },
        "fresh_v2_w56_cost_screen_predicates": {
            "policy_identity_blake2b448_exact": True,
            "root_over_exact_199_byte_rows": True,
            "selected_entry_membership_exact": True,
            "root_height_equality_to_verifier_input_exact": True,
            "fresh56_oracle_attestation_are_row_equalities": True,
            "parent_state_authentication_in_relation": False,
            "w56_profile_production_eligible": False,
        },
        "fresh_v2_all_w64_candidate_predicates": {
            "policy_identity_blake2b512_exact": True,
            "root_over_exact_215_byte_rows": True,
            "selected_entry_membership_exact": True,
            "root_height_equality_to_verifier_input_exact": True,
            "fresh64_oracle_attestation_are_row_equalities": True,
            "parent_state_authentication_in_relation": False,
            "all_w64_profile_production_eligible": False,
        },
        "consensus_boundary": {
            "parent_state_authentication_owner": "native verifier before proof verification",
            "compatibility_snapshot_formula": (
                "BLAKE2b-W(person=HGMAROOT||snapshot||profile1||W||log2cap, "
                "u64le(parent_height)||manifest_root_W)"
            ),
            "fresh_v2_snapshot_formula": (
                "BLAKE2b-W(person=HGMAROOT||snapshot||profile2||W||log2cap, "
                "u64le(parent_height)||manifest_root_W)"
            ),
            "current_kernel_global_root_integrated": False,
            "fresh_node_sync_refinement": False,
            "reorg_revalidation_refinement": False,
        },
        "width_migration": {
            "live_policy_hash_bytes": 48,
            "live_oracle_commitment_bytes": 48,
            "live_attestation_commitment_bytes": 48,
            "w56_baseline_manifest_authority_root_bytes": FRESH_V2_WIDTH,
            "minimum_surviving_manifest_authority_root_bytes": (
                FRESH_V2_W64_WIDTH
            ),
            "prospective_fresh_v2_row_bytes": FRESH_V2_ENTRY_BYTES,
            "prospective_fresh_v2_policy_hash_bytes": FRESH_V2_WIDTH,
            "prospective_fresh_v2_oracle_commitment_bytes": FRESH_V2_WIDTH,
            "prospective_fresh_v2_attestation_commitment_bytes": FRESH_V2_WIDTH,
            "minimum_surviving_width_row_bytes": FRESH_V2_W64_ENTRY_BYTES,
            "minimum_surviving_policy_hash_bytes": FRESH_V2_W64_WIDTH,
            "minimum_surviving_oracle_commitment_bytes": FRESH_V2_W64_WIDTH,
            "minimum_surviving_attestation_commitment_bytes": FRESH_V2_W64_WIDTH,
            "legacy_values_padded_or_truncated": False,
            "direct_legacy_row_migration_allowed": False,
            "migration_rule": (
                "reject every legacy48-to-fresh conversion and every W56/W64 "
                "width conversion; rerun the selected-width constructors over "
                "canonical policy/oracle/attestation sources at a fresh "
                "genesis or explicitly activated state transition"
            ),
            "legacy_manifest_v1_validity_retained": False,
            "compatibility_wider_root_note": (
                "inactive v1 remains a separately recomputable compatibility "
                "KAT; the compatibility root is recomputed from exact 183-byte "
                "source rows, never from the 48-byte v1 digest"
            ),
            "fresh_v2_root_note": (
                "the W56 baseline root is recomputed from exact 199-byte rows; "
                "the minimum-surviving W64 root is recomputed from exact "
                "215-byte rows"
            ),
            "prospective_policy_constructor_grammar_specified": True,
            "prospective_oracle_constructor_grammar_specified": True,
            "prospective_attestation_constructor_grammar_specified": True,
            "current_oracle_subsystem_implements_fresh_constructor": False,
            "current_attestation_subsystem_implements_fresh_constructor": False,
            "fresh_oracle_constructor_authority": False,
            "fresh_attestation_constructor_authority": False,
            "constructor_refinement_complete": False,
        },
        "security": {
            "generic_w56_collision_width_screen_bits": 448 / 3,
            "w56_conservative_composed_epoch_failure_probability": "2^-126",
            "w56_strict_pq128_candidate": False,
            "w64_minimum_width_survives_current_screen": True,
            "w64_status": "conditional; no explicit QRO instantiation",
            "concrete_blake2b_qrom_bridge": False,
            "oracle_attestation_composed_margin": False,
            "composed_pq128_proved": False,
            "complete_zero_knowledge_proved": False,
        },
        "artifacts": {
            "compiled_r1cs": False,
            "compiled_m4": False,
            "post_dce_geometry": False,
            "proof_built": False,
            "proof_bytes_measured": False,
            "formal_refinement": False,
            "release_manifest_authorized": False,
        },
        "current_authority": {
            "compatibility_relation_integrated": False,
            "fresh_v2_w56_relation_integrated": False,
            "fresh_v2_all_w64_relation_integrated": False,
            "canonical_state_writer_integrated": False,
            "oracle_constructor_authorized": False,
            "attestation_constructor_authorized": False,
            "concrete_qro_authorized": False,
            "consensus_route_authorized": False,
            "release_authorized": False,
        },
        "production_authorized": False,
    }


MUTATION_NAMES = [
    "policy_hash_bit",
    "manifest_root_bit",
    "selected_entry_byte_each_0_through_182",
    "fresh_v2_entry_byte_each_0_through_198",
    "fresh_v2_all_w64_entry_byte_each_0_through_214",
    "selected_index_each_of_16_paths",
    "path_sibling_each_level",
    "path_direction_index_bit",
    "parent_root_bit",
    "parent_height_bit",
    "parent_snapshot_bit",
    "public_root_bit",
    "public_height_bit",
    "reversed_manifest_order",
    "duplicate_exact_key",
    "duplicate_key_different_row",
    "nonzero_empty_leaf_padding",
    "invalid_presence_byte",
    "W56_root_as_W64",
    "full_root_as_merkle_root",
    "legacy48_padded_to_W56",
    "legacy48_truncated_from_W56",
    "fresh56_padded_or_rehashed_to_W64",
    "freshW64_truncated_to_W56",
    "oracle_v2_source_payload_bit",
    "attestation_v2_source_payload_bit",
    "fresh_v2_profile_as_compat_profile",
    "trailing_witness_byte",
    "truncated_witness_byte",
]


def mutation_corpus() -> dict[str, Any]:
    return {
        "artifact_schema": "hegemon.manifest-authority-mutations.v1",
        "expected_rejection_count": len(MUTATION_NAMES),
        "mutations": [
            {"name": name, "expected": "reject"} for name in MUTATION_NAMES
        ],
        "coverage": {
            "all_cap16_indices": list(range(CAP)),
            "every_entry_byte": list(range(ENTRY_BYTES)),
            "every_fresh_v2_entry_byte": list(range(FRESH_V2_ENTRY_BYTES)),
            "every_fresh_v2_all_w64_entry_byte": list(
                range(FRESH_V2_W64_ENTRY_BYTES)
            ),
            "path_levels": list(range(CAP_LOG2)),
            "widths": list(WIDTHS),
        },
    }


def _expect_reject(fn: Any, label: str) -> None:
    try:
        fn()
    except (Reject, ValueError):
        return
    raise AssertionError(f"mutation accepted: {label}")


def _flip(raw: bytes, index: int, mask: int = 1) -> bytes:
    changed = bytearray(raw)
    changed[index] ^= mask
    return bytes(changed)


def source_checks() -> dict[str, str]:
    scalar = SCALAR.read_text()
    m4 = M4.read_text()
    kernel = KERNEL_COMMITMENT.read_text()
    manifest = KERNEL_MANIFEST.read_text()
    native = NATIVE_ADMISSION.read_text()
    required = {
        "scalar": [
            "pub const LIVE_STABLECOIN_POLICY_TUPLE_SCALE_BYTES: usize = 61;",
            "pub const LIVE_STABLECOIN_BINDING_BYTES: usize = 48;",
            "validate_stablecoin_consensus_state_seam",
            "live_stablecoin_policy_hash",
        ],
        "m4": [
            '"61-byte policy-identity BLAKE2b-384 recomputation"',
            '"whole-manifest v1 BLAKE2b-384 recomputation"',
            '"selected-entry index membership in the committed vector"',
            '"consensus authentication of expected root and height"',
            "pub const ACTIVE_STABLECOIN_MANIFEST_MEMBERSHIP_GRAPH_COMPILED: bool = false;",
            "pub const PRODUCTION_AUTHORIZED: bool = false;",
        ],
        "kernel": [
            "pub const STABLECOIN_MANIFEST_STATE_V1_ENTRY_BYTES: usize = 183;",
            'b"hegemon.kernel.stablecoin-manifest-state.v1"',
            "STABLECOIN_MANIFEST_STATE_V1_KERNEL_GLOBAL_ROOT_INTEGRATED: bool = false",
            "STABLECOIN_MANIFEST_STATE_V1_PRODUCTION_AUTHORIZED: bool = false",
        ],
        "manifest": [
            "pub stablecoin_policies: Vec<StablecoinPolicyManifestEntry>",
            "pub oracle_commitment: [u8; 48]",
            "pub attestation_commitment: [u8; 48]",
        ],
        "native": [
            "native_stablecoin_policy_binding_authorized_by_entries",
            "for entry in entries",
            "entry.policy_hash() == binding.policy_hash",
            "state.best.height",
        ],
    }
    texts = {
        "scalar": scalar,
        "m4": m4,
        "kernel": kernel,
        "manifest": manifest,
        "native": native,
    }
    for owner, snippets in required.items():
        for snippet in snippets:
            if snippet not in texts[owner]:
                raise AssertionError(f"source contract drift in {owner}: {snippet}")
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha512(path.read_bytes()).hexdigest()
        for path in (SCALAR, M4, KERNEL_COMMITMENT, KERNEL_MANIFEST, NATIVE_ADMISSION)
    }


def self_test() -> dict[str, Any]:
    source_hashes = source_checks()
    entry = sample_entry()
    encoded = entry.encode()
    assert len(encoded) == ENTRY_BYTES
    assert Entry.decode(encoded) == entry
    assert manifest_v1_commitment48([entry]) == MANIFEST_V1_KAT
    assert len(policy_tuple(entry)) == POLICY_TUPLE_BYTES
    assert len(policy_hash48(entry)) == LIVE_BYTES

    # Cap, slot padding, empty-leaf encoding, and all role/level domains.
    one_slots = slots([entry])
    assert len(one_slots) == CAP
    assert one_slots[0] == b"\x01" + encoded
    assert all(slot == bytes(ENTRY_BYTES + 1) for slot in one_slots[1:])
    assert len({personalization(role, 56, CAP) for role in (1, 2, 4)}) == 3
    assert len(
        {personalization(ROLE_NODE, 56, CAP, level) for level in range(CAP_LOG2)}
    ) == CAP_LOG2
    assert personalization(ROLE_LEAF, 56, CAP) != personalization(
        ROLE_LEAF, 64, CAP
    )
    assert personalization(ROLE_LEAF, 56, CAP) == (
        b"HGMAROOT" + bytes([ROLE_LEAF, 1, 56, 4, 0, 0, 0, 0])
    )
    assert personalization(
        ROLE_LEAF,
        56,
        CAP,
        profile=FRESH_V2_AUTHORITY_PROFILE,
    ) == b"HGMAROOT" + bytes([ROLE_LEAF, 2, 56, 4, 0, 0, 0, 0])
    assert len(
        {
            identity_personalization(role)
            for role in (
                IDENTITY_ROLE_POLICY,
                IDENTITY_ROLE_ORACLE,
                IDENTITY_ROLE_ATTESTATION,
            )
        }
    ) == 3
    assert identity_personalization(
        IDENTITY_ROLE_POLICY, 56
    ) != identity_personalization(IDENTITY_ROLE_POLICY, 64)
    _expect_reject(
        lambda: leaf_hash(b"\x00" + b"\x01" + bytes(ENTRY_BYTES - 1), 56),
        "nonzero empty-leaf padding",
    )
    _expect_reject(
        lambda: leaf_hash(b"\x02" + bytes(ENTRY_BYTES), 56),
        "invalid leaf presence",
    )

    entries16 = tuple(sample_entry(1001 + i, 3) for i in range(CAP))
    for width in WIDTHS:
        root = merkle_root(entries16, width)
        public = PublicAuthority(root, 50)
        parent = ParentStateAuthority.from_state(root, 50, width)
        # Every one of the 16 directions/index paths must verify.
        for index, member in enumerate(entries16):
            witness = prove_merkle(entries16, index, width)
            raw = witness.encode(width)
            assert len(raw) == 4 + ENTRY_BYTES + CAP_LOG2 * width
            assert MerkleWitness.decode(raw, width) == witness
            verify_merkle_authority(
                binding_for(member), public, witness, parent, width
            )

        witness = prove_merkle(entries16, 7, width)
        binding = binding_for(entries16[7])
        # Every byte in the exact 183-byte row is bound.  Some mutations are
        # noncanonical and fail parsing; all others fail membership or semantics.
        raw = witness.encode(width)
        for byte_index in range(ENTRY_BYTES):
            changed = _flip(raw, 4 + byte_index)
            _expect_reject(
                lambda changed=changed: verify_merkle_authority(
                    binding,
                    public,
                    MerkleWitness.decode(changed, width),
                    parent,
                    width,
                ),
                f"entry byte {byte_index} width {width}",
            )

        for level in range(CAP_LOG2):
            offset = 4 + ENTRY_BYTES + level * width
            changed = _flip(raw, offset)
            _expect_reject(
                lambda changed=changed: verify_merkle_authority(
                    binding,
                    public,
                    MerkleWitness.decode(changed, width),
                    parent,
                    width,
                ),
                f"path sibling level {level}",
            )

        changed_index = bytearray(raw)
        changed_index[0] ^= 1
        _expect_reject(
            lambda: verify_merkle_authority(
                binding,
                public,
                MerkleWitness.decode(bytes(changed_index), width),
                parent,
                width,
            ),
            "path direction/index",
        )
        _expect_reject(lambda: MerkleWitness.decode(raw + b"\x00", width), "trailing")
        _expect_reject(lambda: MerkleWitness.decode(raw[:-1], width), "truncated")

        bad_binding = dataclasses.replace(
            binding, policy_hash=_flip(binding.policy_hash, 0)
        )
        _expect_reject(
            lambda: verify_merkle_authority(
                bad_binding, public, witness, parent, width
            ),
            "policy hash",
        )
        _expect_reject(
            lambda: verify_merkle_authority(
                binding,
                PublicAuthority(_flip(public.root, 0), public.parent_height),
                witness,
                parent,
                width,
            ),
            "public root",
        )
        _expect_reject(
            lambda: verify_merkle_authority(
                binding,
                PublicAuthority(public.root, public.parent_height ^ 1),
                witness,
                parent,
                width,
            ),
            "public height",
        )
        _expect_reject(
            lambda: verify_merkle_authority(
                binding,
                public,
                witness,
                ParentStateAuthority(
                    _flip(parent.root, 0), parent.parent_height, parent.snapshot
                ),
                width,
            ),
            "parent root",
        )
        _expect_reject(
            lambda: verify_merkle_authority(
                binding,
                public,
                witness,
                ParentStateAuthority(
                    parent.root, parent.parent_height ^ 1, parent.snapshot
                ),
                width,
            ),
            "parent height",
        )
        _expect_reject(
            lambda: verify_merkle_authority(
                binding,
                public,
                witness,
                ParentStateAuthority(
                    parent.root, parent.parent_height, _flip(parent.snapshot, 0)
                ),
                width,
            ),
            "parent snapshot",
        )

        # Full-vector positive path and domain separation from Merkle.
        full = full_root(entries16, width)
        assert full != root
        full_public = PublicAuthority(full, 50)
        full_parent = ParentStateAuthority.from_state(full, 50, width)
        verify_full_authority(
            binding_for(entries16[7]),
            full_public,
            entries16,
            7,
            full_parent,
            width,
        )

    # The prospective V2 destination is a separate row/profile.  Its source
    # grammars are executable proposals, while current subsystem authority and
    # refinement deliberately remain false in the capability ledger.
    fresh_fixtures = tuple(sample_fresh_entry_v2(1001 + i, 3) for i in range(CAP))
    fresh_entries16 = tuple(fixture[0] for fixture in fresh_fixtures)
    for fresh_entry, oracle_source, attestation_source in fresh_fixtures:
        assert len(fresh_entry.encode()) == FRESH_V2_ENTRY_BYTES
        assert FreshEntryV2.decode(fresh_entry.encode()) == fresh_entry
        assert OracleAuthoritySourceV2.decode(oracle_source.encode()) == oracle_source
        assert (
            AttestationAuthoritySourceV2.decode(attestation_source.encode())
            == attestation_source
        )
        validate_fresh_v2_constructor_sources(
            fresh_entry, oracle_source, attestation_source
        )
        assert len(policy_hash56_v2(fresh_entry)) == FRESH_V2_WIDTH

    fresh_root56 = fresh_v2_merkle_root(fresh_entries16, 56)
    fresh_parent56 = ParentStateAuthority.from_state(
        fresh_root56,
        50,
        56,
        profile=FRESH_V2_AUTHORITY_PROFILE,
    )
    fresh_public56 = PublicAuthority(fresh_root56, 50)
    for index, fresh_entry in enumerate(fresh_entries16):
        fresh_witness = prove_fresh_v2_merkle(fresh_entries16, index, 56)
        assert FreshMerkleWitnessV2.decode(
            fresh_witness.encode(56), 56
        ) == fresh_witness
        verify_fresh_v2_merkle_authority(
            fresh_binding_for(fresh_entry),
            fresh_public56,
            fresh_witness,
            fresh_parent56,
            56,
        )

    fresh_witness = prove_fresh_v2_merkle(fresh_entries16, 7, 56)
    fresh_binding = fresh_binding_for(fresh_entries16[7])
    fresh_raw = fresh_witness.encode(56)
    for byte_index in range(FRESH_V2_ENTRY_BYTES):
        changed = _flip(fresh_raw, 4 + byte_index)
        _expect_reject(
            lambda changed=changed: verify_fresh_v2_merkle_authority(
                fresh_binding,
                fresh_public56,
                FreshMerkleWitnessV2.decode(changed, 56),
                fresh_parent56,
                56,
            ),
            f"fresh V2 entry byte {byte_index}",
        )

    oracle7 = fresh_fixtures[7][1]
    attestation7 = fresh_fixtures[7][2]
    mutated_oracle = dataclasses.replace(
        oracle7, payload=_flip(oracle7.payload, 0)
    )
    mutated_attestation = dataclasses.replace(
        attestation7, payload=_flip(attestation7.payload, 0)
    )
    assert oracle_hash56_v2(mutated_oracle) != oracle_hash56_v2(oracle7)
    assert attestation_hash56_v2(mutated_attestation) != attestation_hash56_v2(
        attestation7
    )
    _expect_reject(
        lambda: validate_fresh_v2_constructor_sources(
            fresh_entries16[7], mutated_oracle, attestation7
        ),
        "fresh oracle source payload mutation",
    )
    _expect_reject(
        lambda: validate_fresh_v2_constructor_sources(
            fresh_entries16[7], oracle7, mutated_attestation
        ),
        "fresh attestation source payload mutation",
    )
    _expect_reject(
        lambda: OracleAuthoritySourceV2.decode(oracle7.encode() + b"\x00"),
        "oracle source trailing byte",
    )
    _expect_reject(
        lambda: AttestationAuthoritySourceV2.decode(attestation7.encode()[:-1]),
        "attestation source truncation",
    )
    assert fresh_v2_full_root(fresh_entries16, 56) != fresh_root56
    assert fresh_v2_merkle_root(fresh_entries16, 64)[:56] != fresh_root56
    assert fresh_v2_leaf_hash(
        b"\x01" + fresh_entries16[0].encode(), 56
    ) != _blake(
        b"\x01" + fresh_entries16[0].encode(),
        56,
        personalization(ROLE_LEAF, 56, CAP),
    )

    _expect_reject(
        lambda: fresh_v2_merkle_root(tuple(reversed(fresh_entries16)), 56),
        "fresh V2 reversed order",
    )
    _expect_reject(
        lambda: fresh_v2_merkle_root(
            (fresh_entries16[0], fresh_entries16[0]), 56
        ),
        "fresh V2 duplicate key",
    )

    # The all-W64 row is the minimum width surviving the current composition
    # screen.  It is still only conditional because QRO and subsystem
    # constructor authority are absent.
    w64_fixtures = tuple(
        sample_fresh_entry_v2_w64(1001 + i, 3) for i in range(CAP)
    )
    w64_entries16 = tuple(fixture[0] for fixture in w64_fixtures)
    w64_one_slots = fresh_v2_w64_slots((w64_entries16[0],))
    assert w64_one_slots[0] == b"\x01" + w64_entries16[0].encode()
    assert all(
        slot == bytes(FRESH_V2_W64_ENTRY_BYTES + 1)
        for slot in w64_one_slots[1:]
    )
    _expect_reject(
        lambda: fresh_v2_w64_leaf_hash(
            b"\x00\x01" + bytes(FRESH_V2_W64_ENTRY_BYTES - 1)
        ),
        "all-W64 nonzero empty-leaf padding",
    )
    _expect_reject(
        lambda: fresh_v2_w64_leaf_hash(
            b"\x02" + bytes(FRESH_V2_W64_ENTRY_BYTES)
        ),
        "all-W64 invalid presence byte",
    )
    for w64_entry, oracle_source, attestation_source in w64_fixtures:
        assert len(w64_entry.encode()) == FRESH_V2_W64_ENTRY_BYTES
        assert FreshEntryV2W64.decode(w64_entry.encode()) == w64_entry
        validate_fresh_v2_w64_constructor_sources(
            w64_entry, oracle_source, attestation_source
        )
        assert len(policy_hash64_v2(w64_entry)) == FRESH_V2_W64_WIDTH

    all_w64_root = fresh_v2_w64_merkle_root(w64_entries16)
    all_w64_public = PublicAuthority(all_w64_root, 50)
    all_w64_parent = ParentStateAuthority.from_state(
        all_w64_root,
        50,
        FRESH_V2_W64_WIDTH,
        profile=FRESH_V2_AUTHORITY_PROFILE,
    )
    for index, w64_entry in enumerate(w64_entries16):
        w64_witness = prove_fresh_v2_w64_merkle(w64_entries16, index)
        assert FreshMerkleWitnessV2W64.decode(w64_witness.encode()) == w64_witness
        verify_fresh_v2_w64_merkle_authority(
            fresh_w64_binding_for(w64_entry),
            all_w64_public,
            w64_witness,
            all_w64_parent,
        )

    w64_witness = prove_fresh_v2_w64_merkle(w64_entries16, 7)
    w64_binding = fresh_w64_binding_for(w64_entries16[7])
    w64_raw = w64_witness.encode()
    for byte_index in range(FRESH_V2_W64_ENTRY_BYTES):
        changed = _flip(w64_raw, 4 + byte_index)
        _expect_reject(
            lambda changed=changed: verify_fresh_v2_w64_merkle_authority(
                w64_binding,
                all_w64_public,
                FreshMerkleWitnessV2W64.decode(changed),
                all_w64_parent,
            ),
            f"fresh V2 all-W64 entry byte {byte_index}",
        )
    for level in range(CAP_LOG2):
        offset = 4 + FRESH_V2_W64_ENTRY_BYTES + level * FRESH_V2_W64_WIDTH
        changed = _flip(w64_raw, offset)
        _expect_reject(
            lambda changed=changed: verify_fresh_v2_w64_merkle_authority(
                w64_binding,
                all_w64_public,
                FreshMerkleWitnessV2W64.decode(changed),
                all_w64_parent,
            ),
            f"all-W64 path sibling level {level}",
        )
    changed_w64_index = _flip(w64_raw, 0)
    _expect_reject(
        lambda: verify_fresh_v2_w64_merkle_authority(
            w64_binding,
            all_w64_public,
            FreshMerkleWitnessV2W64.decode(changed_w64_index),
            all_w64_parent,
        ),
        "all-W64 path direction/index",
    )
    _expect_reject(
        lambda: FreshMerkleWitnessV2W64.decode(w64_raw + b"\x00"),
        "all-W64 trailing witness byte",
    )
    _expect_reject(
        lambda: FreshMerkleWitnessV2W64.decode(w64_raw[:-1]),
        "all-W64 truncated witness byte",
    )
    _expect_reject(
        lambda: verify_fresh_v2_w64_merkle_authority(
            w64_binding,
            PublicAuthority(_flip(all_w64_root, 0), 50),
            w64_witness,
            all_w64_parent,
        ),
        "all-W64 public root mutation",
    )
    _expect_reject(
        lambda: verify_fresh_v2_w64_merkle_authority(
            w64_binding,
            PublicAuthority(all_w64_root, 51),
            w64_witness,
            all_w64_parent,
        ),
        "all-W64 public height mutation",
    )
    _expect_reject(
        lambda: verify_fresh_v2_w64_merkle_authority(
            w64_binding,
            all_w64_public,
            w64_witness,
            ParentStateAuthority(
                _flip(all_w64_parent.root, 0),
                all_w64_parent.parent_height,
                all_w64_parent.snapshot,
            ),
        ),
        "all-W64 parent root mutation",
    )
    _expect_reject(
        lambda: verify_fresh_v2_w64_merkle_authority(
            w64_binding,
            all_w64_public,
            w64_witness,
            ParentStateAuthority(
                all_w64_parent.root,
                all_w64_parent.parent_height ^ 1,
                all_w64_parent.snapshot,
            ),
        ),
        "all-W64 parent height mutation",
    )
    _expect_reject(
        lambda: verify_fresh_v2_w64_merkle_authority(
            w64_binding,
            all_w64_public,
            w64_witness,
            ParentStateAuthority(
                all_w64_parent.root,
                all_w64_parent.parent_height,
                _flip(all_w64_parent.snapshot, 0),
            ),
        ),
        "all-W64 parent snapshot mutation",
    )
    assert fresh_v2_w64_full_root(w64_entries16) != all_w64_root
    _expect_reject(
        lambda: fresh_v2_w64_merkle_root(tuple(reversed(w64_entries16))),
        "fresh V2 all-W64 reversed order",
    )
    _expect_reject(
        lambda: fresh_v2_w64_merkle_root(
            (w64_entries16[0], w64_entries16[0])
        ),
        "fresh V2 all-W64 duplicate key",
    )
    _expect_reject(
        lambda: reject_fresh56_to_w64(fresh_entries16[0].oracle_commitment),
        "fresh W56 padded/rehashed into W64",
    )
    _expect_reject(
        lambda: reject_w64_to_fresh56(w64_entries16[0].oracle_commitment),
        "fresh W64 truncated into W56",
    )

    reversed_entries = tuple(reversed(entries16))
    _expect_reject(lambda: merkle_root(reversed_entries, 56), "reversed order")
    _expect_reject(
        lambda: merkle_root((entries16[0], entries16[0]), 56),
        "exact duplicate key",
    )
    duplicate_key_different_row = dataclasses.replace(
        entries16[0], oracle_feed=entries16[0].oracle_feed + 1
    )
    _expect_reject(
        lambda: merkle_root((entries16[0], duplicate_key_different_row), 56),
        "duplicate key with different row",
    )

    root56 = merkle_root(entries16, 56)
    root64 = merkle_root(entries16, 64)
    assert len(root56) == 56 and len(root64) == 64
    _expect_reject(lambda: _require_bytes("W64", root56, 64), "W56 as W64")
    _expect_reject(
        lambda: reject_legacy48_to_fresh56(MANIFEST_V1_KAT),
        "legacy root padded",
    )
    _expect_reject(
        lambda: reject_fresh56_to_legacy48(root56),
        "fresh root truncated",
    )
    # Width is a type/constructor choice, not a truncation equivalence.
    assert root56 != root64[:56]

    report = cost_report()
    assert report["profiles"]["compat183-merkle-w56"]["hash_schedule"][
        "total_relation_compressions"
    ] == 8
    assert report["profiles"]["compat183-full-w56"]["hash_schedule"][
        "total_relation_compressions"
    ] == 25
    assert report["profiles"]["fresh-v2-merkle-w56"]["hash_schedule"][
        "total_relation_compressions"
    ] == 7
    assert report["profiles"]["fresh-v2-full-w56"]["hash_schedule"][
        "total_relation_compressions"
    ] == 26
    assert report["deltas"]["compat183_merkle_w64_minus_w56"] == {
        "relation_compressions": 0,
        "entry_bytes": 0,
        "slot_bytes": 0,
        "public_bytes": 8,
        "semantic_witness_bytes": 32,
        "r1cs_rows": 1024,
        "m4_witness_words": 4,
    }
    assert report["deltas"]["compat183_full_w64_minus_w56"] == {
        "relation_compressions": 0,
        "entry_bytes": 0,
        "slot_bytes": 0,
        "public_bytes": 8,
        "semantic_witness_bytes": 0,
        "r1cs_rows": 256,
        "m4_witness_words": 0,
    }
    assert report["deltas"]["compat183_w56_merkle_minus_full"] == {
        "relation_compressions": -17,
        "entry_bytes": 0,
        "slot_bytes": 0,
        "public_bytes": 0,
        "semantic_witness_bytes": -2537,
        "r1cs_rows": -2385566,
        "m4_witness_words": -317,
    }
    assert report["deltas"]["fresh_v2_merkle_w56_minus_compat183"] == {
        "relation_compressions": -1,
        "entry_bytes": 16,
        "slot_bytes": 16,
        "public_bytes": 0,
        "semantic_witness_bytes": 16,
        "r1cs_rows": -136192,
        "m4_witness_words": 2,
    }
    assert report["deltas"]["fresh_v2_full_w56_minus_compat183"] == {
        "relation_compressions": 1,
        "entry_bytes": 16,
        "slot_bytes": 16,
        "public_bytes": 0,
        "semantic_witness_bytes": 256,
        "r1cs_rows": 142464,
        "m4_witness_words": 32,
    }
    assert report["deltas"]["fresh_v2_merkle_root_w64_minus_w56"] == {
        "relation_compressions": 0,
        "entry_bytes": 0,
        "slot_bytes": 0,
        "public_bytes": 8,
        "semantic_witness_bytes": 32,
        "r1cs_rows": 1024,
        "m4_witness_words": 4,
    }
    assert report["deltas"]["all_w64_merkle_minus_fresh_v2_w56"] == {
        "relation_compressions": 0,
        "entry_bytes": 16,
        "slot_bytes": 16,
        "public_bytes": 8,
        "semantic_witness_bytes": 48,
        "r1cs_rows": 1216,
        "m4_witness_words": 6,
    }
    assert report["profiles"]["fresh-v2-all-w64-merkle-w64"][
        "semantic_witness_bytes"
    ] == 475
    assert report["profiles"]["fresh-v2-all-w64-merkle-w64"]["r1cs"][
        "delta_rows_total"
    ] == 965301

    ledger = capability_ledger()
    assert ledger["production_authorized"] is False
    assert ledger["security"]["concrete_blake2b_qrom_bridge"] is False
    assert ledger["security"]["w56_strict_pq128_candidate"] is False
    assert ledger["fresh_v2_all_w64_candidate_predicates"][
        "all_w64_profile_production_eligible"
    ] is False
    assert ledger["width_migration"][
        "w56_baseline_manifest_authority_root_bytes"
    ] == 56
    assert ledger["width_migration"][
        "minimum_surviving_manifest_authority_root_bytes"
    ] == 64
    assert all(value is False for value in ledger["current_authority"].values())
    assert (
        ledger["width_migration"]["fresh_oracle_constructor_authority"]
        is False
    )
    assert (
        ledger["width_migration"]["fresh_attestation_constructor_authority"]
        is False
    )
    return {
        "source_sha512": source_hashes,
        "manifest_v1_kat": MANIFEST_V1_KAT.hex(),
        "policy_hash48_kat": policy_hash48(entry).hex(),
        "full_root56_cap16_kat": full_root(entries16, 56).hex(),
        "merkle_root56_cap16_kat": root56.hex(),
        "snapshot56_height50_kat": snapshot_commitment(root56, 50, 56).hex(),
        "fresh_v2_policy_hash56_kat": policy_hash56_v2(fresh_entries16[0]).hex(),
        "fresh_v2_oracle_hash56_kat": oracle_hash56_v2(
            fresh_fixtures[0][1]
        ).hex(),
        "fresh_v2_attestation_hash56_kat": attestation_hash56_v2(
            fresh_fixtures[0][2]
        ).hex(),
        "fresh_v2_merkle_root56_cap16_kat": fresh_root56.hex(),
        "fresh_v2_snapshot56_height50_kat": snapshot_commitment(
            fresh_root56,
            50,
            56,
            profile=FRESH_V2_AUTHORITY_PROFILE,
        ).hex(),
        "fresh_v2_all_w64_policy_hash_kat": policy_hash64_v2(
            w64_entries16[0]
        ).hex(),
        "fresh_v2_all_w64_oracle_hash_kat": oracle_hash64_v2(
            w64_fixtures[0][1]
        ).hex(),
        "fresh_v2_all_w64_attestation_hash_kat": attestation_hash64_v2(
            w64_fixtures[0][2]
        ).hex(),
        "fresh_v2_all_w64_merkle_root_cap16_kat": all_w64_root.hex(),
        "mutations": mutation_corpus()["expected_rejection_count"],
        "entry_bytes_exhaustively_mutated": ENTRY_BYTES,
        "fresh_v2_entry_bytes_exhaustively_mutated": FRESH_V2_ENTRY_BYTES,
        "fresh_v2_all_w64_entry_bytes_exhaustively_mutated": (
            FRESH_V2_W64_ENTRY_BYTES
        ),
        "index_paths_verified": CAP,
        "fresh_v2_all_w64_index_paths_verified": CAP,
    }


def emit() -> None:
    evidence = self_test()
    report = cost_report()
    report["self_test_evidence"] = evidence
    REPORT.write_bytes(_canonical_json(report))
    LEDGER.write_bytes(_canonical_json(capability_ledger()))
    CORPUS.write_bytes(_canonical_json(mutation_corpus()))


def check() -> dict[str, Any]:
    evidence = self_test()
    expected_report = cost_report()
    expected_report["self_test_evidence"] = evidence
    expected = {
        REPORT: _canonical_json(expected_report),
        LEDGER: _canonical_json(capability_ledger()),
        CORPUS: _canonical_json(mutation_corpus()),
    }
    for path, canonical in expected.items():
        if not path.is_file():
            raise AssertionError(f"missing retained artifact: {path.name}")
        if path.read_bytes() != canonical:
            raise AssertionError(f"retained artifact drift: {path.name}")
    return evidence


def summary() -> dict[str, Any]:
    report = json.loads(REPORT.read_text())
    ledger = json.loads(LEDGER.read_text())
    return {
        "compatibility_winner": report["decision"]["smallest_compatibility_closure"],
        "w56_source_exact_boundary": report["decision"][
            "smallest_source_exact_boundary"
        ],
        "minimum_surviving_width_candidate": report["decision"][
            "minimum_width_surviving_current_screen"
        ],
        "production_winner": report["decision"]["production_winner"],
        "compat_merkle_w56_compressions": report["profiles"]
        ["compat183-merkle-w56"]
        ["hash_schedule"]["total_relation_compressions"],
        "compat_merkle_w56_witness_bytes": report["profiles"]
        ["compat183-merkle-w56"]
        ["semantic_witness_bytes"],
        "compat_merkle_w56_r1cs_rows": report["profiles"]
        ["compat183-merkle-w56"]["r1cs"]
        ["delta_rows_total"],
        "compat_full_w56_compressions": report["profiles"]
        ["compat183-full-w56"]
        ["hash_schedule"]["total_relation_compressions"],
        "fresh_v2_merkle_w56_compressions": report["profiles"]
        ["fresh-v2-merkle-w56"]["hash_schedule"]["total_relation_compressions"],
        "fresh_v2_merkle_w56_witness_bytes": report["profiles"]
        ["fresh-v2-merkle-w56"]["semantic_witness_bytes"],
        "fresh_v2_all_w64_merkle_compressions": report["profiles"]
        ["fresh-v2-all-w64-merkle-w64"]["hash_schedule"]
        ["total_relation_compressions"],
        "fresh_v2_all_w64_merkle_witness_bytes": report["profiles"]
        ["fresh-v2-all-w64-merkle-w64"]["semantic_witness_bytes"],
        "w56_composed_epoch_failure_probability": report["decision"]
        ["w56_composed_epoch_failure_probability"],
        "production_authorized": ledger["production_authorized"],
        "concrete_qrom": ledger["security"]["concrete_blake2b_qrom_bridge"],
        "oracle_constructor_authority": ledger["width_migration"]
        ["fresh_oracle_constructor_authority"],
        "attestation_constructor_authority": ledger["width_migration"]
        ["fresh_attestation_constructor_authority"],
        "artifact_sha512": {
            path.name: hashlib.sha512(path.read_bytes()).hexdigest()
            for path in (REPORT, LEDGER, CORPUS)
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("emit", "check", "summary"))
    args = parser.parse_args()
    if args.command == "emit":
        emit()
        print(json.dumps(summary(), sort_keys=True))
    elif args.command == "check":
        evidence = check()
        print(json.dumps({"ok": True, **evidence}, sort_keys=True))
    else:
        print(json.dumps(summary(), sort_keys=True))


if __name__ == "__main__":
    main()
