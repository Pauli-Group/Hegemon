#!/usr/bin/env python3
"""Dependency-free executable semantics for the inactive HX512B01 diagnostic.

This module is intentionally not a proof backend.  It is a byte-exact,
operand-bound interpreter for the proposed 1,141-byte statement, 72-byte
verifier context, and 11,000-byte private witness.  It constructs all 83 core
and seven manifest-authority hash calls and evaluates every non-hash semantic
family.  The emitted trace is a compact executable equivalent, not a retained
29-million-row sparse R1CS matrix. The grammar retains known accepted
stablecoin and no-input-anchor counterexamples, so successful evaluation is
not evidence of an exact full production relation.
"""

from __future__ import annotations

import dataclasses
import functools
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUITE_PATH = ROOT / ".agent/hardening/hx512-semantic-suite/hx512_suite.py"
AUTHORITY_PATH = ROOT / ".agent/hardening/manifest-authority-closure/manifest_authority.py"
PROFILE_PATH = Path(__file__).resolve().with_name("verifier_profile.py")


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SUITE = _load("hegemon_hx512_exec_suite", SUITE_PATH)
AUTHORITY = _load("hegemon_hx512_exec_authority", AUTHORITY_PATH)
PROFILE = _load("hegemon_hx512_verifier_profile", PROFILE_PATH)

P = 0xFFFFFFFF00000001
MAX_VALUE = (1 << 61) - 1
PADDING_ASSET = (1 << 64) - 1
RESERVED_REDUCED_PADDING_ASSET = PADDING_ASSET % P
STATEMENT_BYTES = 1141
CONTEXT_BYTES = 72
PRIVATE_BYTES = 11_000
CIPHERTEXT_BYTES = 2147
MANIFEST_OFFSET = 10_520
MANIFEST_SEMANTIC_BYTES = 475
MANIFEST_TRANSPORT_BYTES = 480
MAGIC = b"HX512B01"
PROFILE_NAME = "blake2b512_rfc"
LANES = (SUITE.LANE_A, SUITE.LANE_B)
AUTH_ROLES = (SUITE.ROLE_AUTH_A, SUITE.ROLE_AUTH_B)


class RelationFailure(ValueError):
    """One executable relation predicate evaluated to false."""

    def __init__(self, constraint_id: str, family: str, detail: str):
        self.constraint_id = constraint_id
        self.family = family
        self.detail = detail
        super().__init__(f"{constraint_id}: {detail}")


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def digest_json(domain: bytes, value: Any) -> str:
    payload = canonical_json(value)
    return hashlib.shake_256(domain + len(payload).to_bytes(8, "big") + payload).hexdigest(64)


def _u64be(raw: bytes, label: str) -> int:
    if len(raw) != 8:
        raise RelationFailure(f"decode.{label}", "canonical private grammar", "not one u64be word")
    return int.from_bytes(raw, "big")


def _bool_word(raw: bytes, label: str) -> bool:
    value = _u64be(raw, label)
    if value not in (0, 1):
        raise RelationFailure(f"decode.{label}", "canonical private grammar", "Boolean word is not 0 or 1")
    return bool(value)


@dataclasses.dataclass(frozen=True)
class Note:
    raw: bytes
    kind: int
    value: int
    asset: int
    recipient: bytes
    rho: bytes
    blinding: bytes
    authorization: bytes

    @classmethod
    def decode(cls, raw: bytes, label: str) -> "Note":
        if len(raw) != 232:
            raise RelationFailure(f"decode.{label}", "canonical private grammar", "note width")
        return cls(
            raw=raw,
            kind=_u64be(raw[0:8], f"{label}.kind"),
            value=_u64be(raw[8:16], f"{label}.value"),
            asset=_u64be(raw[16:24], f"{label}.asset"),
            recipient=raw[24:56],
            rho=raw[56:104],
            blinding=raw[104:168],
            authorization=raw[168:232],
        )

    def frame(self) -> bytes:
        return SUITE.frame(
            MAGIC,
            SUITE.ROLE_NOTE,
            [
                self.blinding,
                bytes([self.kind]) if self.kind < 256 else b"",
                self.value.to_bytes(8, "big"),
                self.asset.to_bytes(8, "big"),
                self.recipient,
                self.rho,
                self.authorization,
            ],
        )


@dataclasses.dataclass(frozen=True)
class Input:
    raw: bytes
    spend_master: bytes
    note: Note
    position: int
    siblings: tuple[bytes, ...]
    selectors: tuple[bool, ...]

    @classmethod
    def decode(cls, raw: bytes, label: str) -> "Input":
        if len(raw) != 2384:
            raise RelationFailure(f"decode.{label}", "canonical private grammar", "input width")
        siblings = tuple(raw[304 + 64 * i : 304 + 64 * (i + 1)] for i in range(32))
        selectors = tuple(
            _bool_word(raw[2352 + 8 * i : 2360 + 8 * i], f"{label}.selector[{i}]")
            for i in range(4)
        )
        return cls(
            raw=raw,
            spend_master=raw[:64],
            note=Note.decode(raw[64:296], f"{label}.note"),
            position=_u64be(raw[296:304], f"{label}.position"),
            siblings=siblings,
            selectors=selectors,
        )


@dataclasses.dataclass(frozen=True)
class Output:
    raw: bytes
    note: Note
    selectors: tuple[bool, ...]
    ciphertext: bytes
    ciphertext_padding: bytes

    @classmethod
    def decode(cls, raw: bytes, ciphertext: bytes, label: str) -> "Output":
        if len(raw) != 264 or len(ciphertext) != 2152:
            raise RelationFailure(f"decode.{label}", "canonical private grammar", "output width")
        selectors = tuple(
            _bool_word(raw[232 + 8 * i : 240 + 8 * i], f"{label}.selector[{i}]")
            for i in range(4)
        )
        return cls(
            raw=raw,
            note=Note.decode(raw[:232], f"{label}.note"),
            selectors=selectors,
            ciphertext=ciphertext[:CIPHERTEXT_BYTES],
            ciphertext_padding=ciphertext[CIPHERTEXT_BYTES:],
        )


@dataclasses.dataclass(frozen=True)
class Accumulator:
    raw: bytes
    policy_root: bytes
    intent: bytes
    threshold: int
    signer_count: int
    approval_count: int
    approved: tuple[bool, ...]

    @classmethod
    def decode(cls, raw: bytes, label: str) -> "Accumulator":
        if len(raw) != 200:
            raise RelationFailure(f"decode.{label}", "canonical private grammar", "accumulator width")
        return cls(
            raw=raw,
            policy_root=raw[:64],
            intent=raw[64:128],
            threshold=_u64be(raw[128:136], f"{label}.threshold"),
            signer_count=_u64be(raw[136:144], f"{label}.signer_count"),
            approval_count=_u64be(raw[144:152], f"{label}.approval_count"),
            approved=tuple(
                _bool_word(raw[152 + 8 * i : 160 + 8 * i], f"{label}.approved[{i}]")
                for i in range(6)
            ),
        )

    def is_zero(self) -> bool:
        return self.raw == bytes(200)


@dataclasses.dataclass(frozen=True)
class Authorization:
    raw: bytes
    mode: int
    current: Accumulator
    next: Accumulator
    signer_tags: tuple[bytes, ...]
    policy_masters: tuple[bytes, bytes]

    @classmethod
    def decode(cls, raw: bytes, masters: bytes) -> "Authorization":
        if len(raw) != 792 or len(masters) != 128:
            raise RelationFailure("decode.authorization", "canonical private grammar", "authorization width")
        mode = _u64be(raw[:8], "authorization.mode")
        if mode not in range(5):
            raise RelationFailure("authorization.mode.range", "five authorization modes", "mode outside 0..4")
        return cls(
            raw=raw,
            mode=mode,
            current=Accumulator.decode(raw[8:208], "authorization.current"),
            next=Accumulator.decode(raw[208:408], "authorization.next"),
            signer_tags=tuple(raw[408 + 64 * i : 472 + 64 * i] for i in range(6)),
            policy_masters=(masters[:64], masters[64:]),
        )


@dataclasses.dataclass(frozen=True)
class Statement:
    raw: bytes
    flags: tuple[bool, bool, bool, bool]
    anchor: bytes
    nullifiers: tuple[bytes, bytes]
    commitments: tuple[bytes, bytes]
    ciphertext_hashes: tuple[bytes, bytes]
    ciphertext_sizes: tuple[int, int]
    assets: tuple[int, int, int, int]
    fee: int
    value_sign: bool
    value_magnitude: int
    stable_enabled: bool
    stable_asset: int
    stable_version: int
    stable_sign: bool
    stable_magnitude: int
    stable_policy: bytes
    stable_oracle: bytes
    stable_attestation: bytes
    manifest_root: bytes
    state_root: bytes
    state_height: int
    balance_tag: bytes

    @classmethod
    def decode(cls, raw: bytes) -> "Statement":
        if type(raw) is not bytes or len(raw) != STATEMENT_BYTES:
            raise RelationFailure("statement.width", "canonical statement grammar", "statement is not exactly 1141 bytes")
        identity = SUITE.IDENTITIES[PROFILE_NAME]
        expected_activation = SUITE.activation_bytes(PROFILE_NAME)
        if raw[:8] != identity["statement_magic"].encode():
            raise RelationFailure("statement.identity.magic", "canonical statement grammar", "wrong statement magic")
        if int.from_bytes(raw[8:10], "big") != SUITE.STATEMENT_GRAMMAR:
            raise RelationFailure("statement.identity.grammar", "canonical statement grammar", "wrong statement grammar")
        if any(flag not in (0, 1) for flag in raw[10:14]):
            raise RelationFailure("statement.flags.boolean", "canonical statement grammar", "noncanonical activity flag")
        if raw[933:1077] != expected_activation[:144]:
            raise RelationFailure("statement.identity.activation", "canonical statement grammar", "activation/network/domain identity mismatch")
        if raw[1077:1141] != PROFILE.DIAGNOSTIC_RULES_HASH:
            raise RelationFailure("statement.identity.rules_hash", "canonical statement grammar", "verifier-profile rules hash mismatch")
        parsed = {
            item["name"]: raw[item["offset"] : item["offset"] + item["bytes"]]
            for item in SUITE.statement_layout()
        }
        if raw[510] not in (0, 1) or raw[532] not in (0, 1) or raw[519] not in (0, 1):
            raise RelationFailure("statement.boolean_bytes", "canonical statement grammar", "noncanonical Boolean byte")
        value_magnitude = int.from_bytes(raw[511:519], "big")
        stable_magnitude = int.from_bytes(raw[533:541], "big")
        if raw[510] and value_magnitude == 0:
            raise RelationFailure("statement.value_negative_zero", "signed-magnitude ranges", "negative zero")
        if raw[532] and stable_magnitude == 0:
            raise RelationFailure("statement.stable_negative_zero", "signed-magnitude ranges", "negative zero")
        if max(int.from_bytes(raw[502:510], "big"), value_magnitude, stable_magnitude) > MAX_VALUE:
            raise RelationFailure("statement.magnitude.range", "signed-magnitude ranges", "magnitude exceeds 2^61-1")
        assets = tuple(int.from_bytes(raw[470 + 8 * i : 478 + 8 * i], "big") for i in range(4))
        if assets[0] != 0:
            raise RelationFailure("statement.assets.native", "canonical asset slots", "slot zero is not native")
        last = 0
        padding = False
        for index, asset in enumerate(assets[1:], 1):
            if asset == PADDING_ASSET:
                padding = True
                continue
            if padding or asset in (0, RESERVED_REDUCED_PADDING_ASSET) or asset >= P or asset <= last:
                raise RelationFailure(f"statement.assets[{index}]", "canonical asset slots", "slot order or range")
            last = asset
        sizes = tuple(int.from_bytes(raw[462 + 4 * i : 466 + 4 * i], "big") for i in range(2))
        flags = tuple(bool(value) for value in raw[10:14])
        for index, active in enumerate(flags[2:]):
            if sizes[index] != (CIPHERTEXT_BYTES if active else 0):
                raise RelationFailure(f"statement.ciphertext_size[{index}]", "ciphertext binding", "activity/size mismatch")
        stable = bool(raw[519])
        if stable:
            stable_asset = int.from_bytes(raw[520:528], "big")
            if stable_asset == 0 or stable_asset not in assets[1:] or stable_magnitude == 0:
                raise RelationFailure("statement.stable.surface", "stablecoin relation", "enabled surface is noncanonical")
            if raw[733:797] == bytes(64):
                raise RelationFailure("statement.manifest.nonzero", "stablecoin relation", "enabled manifest root is zero")
        elif raw[520:869] != bytes(349):
            raise RelationFailure("statement.stable.disabled_zero", "stablecoin relation", "disabled surface is nonzero")
        return cls(
            raw=raw,
            flags=flags,  # type: ignore[arg-type]
            anchor=parsed["anchor"],
            nullifiers=(parsed["nullifiers"][:64], parsed["nullifiers"][64:]),
            commitments=(parsed["commitments"][:64], parsed["commitments"][64:]),
            ciphertext_hashes=(parsed["ciphertext_hashes"][:64], parsed["ciphertext_hashes"][64:]),
            ciphertext_sizes=sizes,  # type: ignore[arg-type]
            assets=assets,  # type: ignore[arg-type]
            fee=int.from_bytes(raw[502:510], "big"),
            value_sign=bool(raw[510]),
            value_magnitude=value_magnitude,
            stable_enabled=stable,
            stable_asset=int.from_bytes(raw[520:528], "big"),
            stable_version=int.from_bytes(raw[528:532], "big"),
            stable_sign=bool(raw[532]),
            stable_magnitude=stable_magnitude,
            stable_policy=raw[541:605],
            stable_oracle=raw[605:669],
            stable_attestation=raw[669:733],
            manifest_root=raw[733:797],
            state_root=raw[797:861],
            state_height=int.from_bytes(raw[861:869], "big"),
            balance_tag=raw[869:933],
        )


@dataclasses.dataclass(frozen=True)
class Witness:
    raw: bytes
    inputs: tuple[Input, Input]
    outputs: tuple[Output, Output]
    authorization: Authorization
    manifest: Any | None

    @classmethod
    def decode(cls, raw: bytes, stable_enabled: bool) -> "Witness":
        if type(raw) is not bytes or len(raw) != PRIVATE_BYTES:
            raise RelationFailure("witness.width", "canonical private grammar", "witness is not exactly 11000 bytes")
        ciphers = (raw[6216:8368], raw[8368:10520])
        outputs = (
            Output.decode(raw[4768:5032], ciphers[0], "output[0]"),
            Output.decode(raw[5032:5296], ciphers[1], "output[1]"),
        )
        if any(output.ciphertext_padding != bytes(5) for output in outputs):
            raise RelationFailure("witness.ciphertext_padding", "canonical private grammar", "ciphertext padding is nonzero")
        manifest_raw = raw[MANIFEST_OFFSET:]
        if manifest_raw[MANIFEST_SEMANTIC_BYTES:] != bytes(5):
            raise RelationFailure("witness.manifest_padding", "canonical private grammar", "manifest padding is nonzero")
        if stable_enabled:
            try:
                manifest = AUTHORITY.FreshMerkleWitnessV2W64.decode(manifest_raw[:MANIFEST_SEMANTIC_BYTES])
            except Exception as error:
                raise RelationFailure("witness.manifest", "canonical private grammar", str(error)) from error
        else:
            if manifest_raw != bytes(MANIFEST_TRANSPORT_BYTES):
                raise RelationFailure("witness.manifest.disabled_zero", "stablecoin relation", "disabled witness is nonzero")
            manifest = None
        return cls(
            raw=raw,
            inputs=(Input.decode(raw[:2384], "input[0]"), Input.decode(raw[2384:4768], "input[1]")),
            outputs=outputs,
            authorization=Authorization.decode(raw[5296:6088], raw[6088:6216]),
            manifest=manifest,
        )


@dataclasses.dataclass(frozen=True)
class HashCall:
    index: int
    registry: str
    family: str
    role_hex: str
    message_bytes: int
    message_hex: str
    message_sha512: str
    digest_hex: str
    rfc7693_compressions: int
    fixed_compressions: int
    counters: tuple[int, ...]
    final_flags: tuple[bool, ...]
    selected_digest_state_after_compression: int
    personalization_hex: str | None = None

    @classmethod
    def core(
        cls,
        index: int,
        family: str,
        role: bytes,
        message: bytes,
        *,
        fixed_compressions: int | None = None,
    ) -> "HashCall":
        actual = max(1, (len(message) + 127) // 128)
        fixed = actual if fixed_compressions is None else fixed_compressions
        counters = tuple(
            min((block + 1) * 128, len(message)) if block < actual else len(message)
            for block in range(fixed)
        )
        flags = tuple(block + 1 == actual for block in range(fixed))
        return cls(
            index=index,
            registry="HX512B01",
            family=family,
            role_hex=role.hex(),
            message_bytes=len(message),
            message_hex=message.hex(),
            message_sha512=hashlib.sha512(message).hexdigest(),
            digest_hex=hashlib.blake2b(message, digest_size=64).hexdigest(),
            rfc7693_compressions=actual,
            fixed_compressions=fixed,
            counters=counters,
            final_flags=flags,
            selected_digest_state_after_compression=actual,
            personalization_hex=bytes(16).hex(),
        )

    @classmethod
    def authority(
        cls,
        index: int,
        family: str,
        message: bytes,
        person: bytes,
    ) -> "HashCall":
        actual = max(1, (len(message) + 127) // 128)
        counters = tuple(min((block + 1) * 128, len(message)) for block in range(actual))
        flags = tuple(block + 1 == actual for block in range(actual))
        return cls(
            index=index,
            registry="HGMAIDV2/HGMAROOT",
            family=family,
            role_hex=person[8:9].hex(),
            message_bytes=len(message),
            message_hex=message.hex(),
            message_sha512=hashlib.sha512(message).hexdigest(),
            digest_hex=hashlib.blake2b(message, digest_size=64, person=person).hexdigest(),
            rfc7693_compressions=actual,
            fixed_compressions=actual,
            counters=counters,
            final_flags=flags,
            selected_digest_state_after_compression=actual,
            personalization_hex=person.hex(),
        )


@dataclasses.dataclass(frozen=True)
class Check:
    constraint_id: str
    family: str
    kind: str
    operands: tuple[str, ...]


class Checks:
    def __init__(self) -> None:
        self.items: list[Check] = []

    def require(
        self,
        condition: bool,
        constraint_id: str,
        family: str,
        kind: str,
        *operands: str,
        detail: str,
    ) -> None:
        self.items.append(Check(constraint_id, family, kind, tuple(operands)))
        if not condition:
            raise RelationFailure(constraint_id, family, detail)


@dataclasses.dataclass(frozen=True)
class Evaluation:
    accepted: bool
    checks: tuple[Check, ...]
    hash_calls: tuple[HashCall, ...]
    derived: dict[str, Any]
    trace_digest_shake256_512: str


def _blake(message: bytes) -> bytes:
    return hashlib.blake2b(message, digest_size=64).digest()


def _signed(sign: bool, magnitude: int) -> int:
    return -magnitude if sign else magnitude


def _note_message(note: Note) -> bytes:
    if note.kind >= 256:
        # The semantic range check reports the precise failure before this is
        # reachable on an accepted evaluation.
        return b""
    return note.frame()


def _spend_message(master: bytes, lane: int) -> bytes:
    return SUITE.frame(MAGIC, (SUITE.ROLE_SPEND_A, SUITE.ROLE_SPEND_B)[lane], [LANES[lane], master])


def _policy_message(master: bytes, opening: Accumulator, tags: Sequence[bytes]) -> bytes:
    return SUITE.frame(
        MAGIC,
        SUITE.ROLE_AUTH_POLICY,
        [
            master,
            opening.threshold.to_bytes(8, "big"),
            opening.signer_count.to_bytes(8, "big"),
            *tags,
        ],
    )


def _accumulator_message(master: bytes, lane: int, opening: Accumulator) -> bytes:
    return SUITE.frame(
        MAGIC,
        AUTH_ROLES[lane],
        [
            master,
            LANES[lane],
            opening.policy_root,
            opening.intent,
            opening.threshold.to_bytes(8, "big"),
            opening.signer_count.to_bytes(8, "big"),
            opening.approval_count.to_bytes(8, "big"),
            bytes(int(value) for value in opening.approved),
        ],
    )


def _value_lock_message(master: bytes, lane: int, opening: Accumulator) -> bytes:
    return SUITE.frame(
        MAGIC,
        AUTH_ROLES[lane],
        [master, LANES[lane], opening.policy_root, opening.intent],
    )


def _dummy_message(lane: int, slot: int) -> bytes:
    payload = bytearray(117)
    payload[0] = slot
    payload[1] = lane
    return SUITE.frame(MAGIC, AUTH_ROLES[lane], [bytes(payload)])


def _authorization_message(auth: Authorization, lane: int, slot: int) -> bytes:
    mode = auth.mode
    current_master, next_master = auth.policy_masters
    if mode == 0:
        return _dummy_message(lane, slot)
    if slot == 0:
        if mode == 1:
            return _accumulator_message(next_master, lane, auth.next)
        if mode in (2, 4):
            return _accumulator_message(current_master, lane, auth.current)
        return _value_lock_message(current_master, lane, auth.current)
    if mode == 2:
        return _accumulator_message(next_master, lane, auth.next)
    if mode == 4:
        return _value_lock_message(current_master, lane, auth.current)
    return _dummy_message(lane, slot)


def _selected_policy(auth: Authorization) -> tuple[Accumulator, bytes]:
    return (auth.next, auth.policy_masters[1]) if auth.mode == 1 else (auth.current, auth.policy_masters[0])


def _intent_message(statement: bytes) -> bytes:
    return SUITE.frame(MAGIC, SUITE.ROLE_INTENT, [statement[:14] + statement[206:]])


def _balance_message(statement: Statement) -> bytes:
    return SUITE.frame(
        MAGIC,
        SUITE.ROLE_BALANCE,
        [
            statement.fee.to_bytes(8, "big"),
            bytes([int(statement.value_sign)]),
            statement.value_magnitude.to_bytes(8, "big"),
            b"".join(asset.to_bytes(8, "big") for asset in statement.assets),
            bytes([int(statement.stable_enabled)]),
            statement.stable_asset.to_bytes(8, "big"),
            bytes([int(statement.stable_sign)]),
            statement.stable_magnitude.to_bytes(8, "big"),
        ],
    )


def _ciphertext_message(index: int, ciphertext: bytes) -> bytes:
    return SUITE.frame(
        MAGIC,
        SUITE.ROLE_CIPHERTEXT,
        [b"\x52", (0x5127).to_bytes(2, "big"), bytes([index]), CIPHERTEXT_BYTES.to_bytes(4, "big"), ciphertext],
    )


def _merkle_message(left: bytes, right: bytes) -> bytes:
    return SUITE.frame(MAGIC, SUITE.ROLE_MERKLE, [left, right])


def _nullifier_message(key: bytes, position: int, rho: bytes) -> bytes:
    return SUITE.frame(MAGIC, SUITE.ROLE_NULLIFIER, [key, position.to_bytes(8, "big"), rho])


def activity_shape_accepts(mode: int, flags: Sequence[bool]) -> bool:
    if len(flags) != 4 or mode not in range(5) or not any(flags):
        return False
    i0, i1, o0, _ = flags
    if mode == 0:
        return True
    if mode in (1, 3):
        return (i0 or i1) and o0
    if mode == 2:
        return i0 and i1 and o0
    return i0 and i1


def _validate_accumulator(
    checks: Checks,
    label: str,
    opening: Accumulator,
    tags: Sequence[bytes],
    policy_digest: bytes,
    expected_intent: bytes | None,
) -> None:
    checks.require(
        1 <= opening.signer_count <= 6,
        f"{label}.signer_count",
        "accumulator threshold signer and approval metadata",
        "range",
        f"{label}.signer_count",
        detail="signer count outside 1..6",
    )
    checks.require(
        1 <= opening.threshold <= opening.signer_count,
        f"{label}.threshold",
        "accumulator threshold signer and approval metadata",
        "range",
        f"{label}.threshold",
        f"{label}.signer_count",
        detail="threshold outside 1..signer_count",
    )
    checks.require(
        opening.approval_count <= opening.signer_count,
        f"{label}.approval_count",
        "accumulator threshold signer and approval metadata",
        "le",
        f"{label}.approval_count",
        f"{label}.signer_count",
        detail="approval count exceeds signer count",
    )
    checks.require(
        sum(opening.approved) == opening.approval_count,
        f"{label}.approval_popcount",
        "accumulator threshold signer and approval metadata",
        "eq",
        f"{label}.approved[0..6]",
        f"{label}.approval_count",
        detail="approval popcount mismatch",
    )
    checks.require(
        opening.policy_root == policy_digest,
        f"{label}.policy_root",
        "policy and four authorization-lane digest links",
        "digest_eq",
        f"{label}.policy_root",
        "digest.authorization.policy",
        detail="policy root mismatch",
    )
    if expected_intent is not None:
        checks.require(
            opening.intent == expected_intent,
            f"{label}.intent",
            "final-spend intent equality",
            "digest_eq",
            f"{label}.intent",
            "digest.intent",
            detail="final-spend intent mismatch",
        )
    for slot in range(6):
        if slot < opening.signer_count:
            checks.require(
                tags[slot] not in tags[:slot],
                f"{label}.signer_unique[{slot}]",
                "accumulator threshold signer and approval metadata",
                "digest_neq",
                f"authorization.signer_tags[{slot}]",
                f"authorization.signer_tags[0..{slot}]",
                detail="duplicate active signer tag",
            )
        else:
            checks.require(
                tags[slot] == bytes(64) and not opening.approved[slot],
                f"{label}.inactive_signer[{slot}]",
                "accumulator threshold signer and approval metadata",
                "eq_zero",
                f"authorization.signer_tags[{slot}]",
                f"{label}.approved[{slot}]",
                detail="inactive signer slot is nonzero",
            )


def _check_zero(checks: Checks, condition: bool, cid: str, family: str, operand: str, detail: str) -> None:
    checks.require(condition, cid, family, "eq_zero", operand, detail=detail)


def _validate_authorization(
    statement: Statement,
    witness: Witness,
    checks: Checks,
    spend: tuple[tuple[bytes, bytes], tuple[bytes, bytes]],
    policy_digest: bytes,
    auth_digests: tuple[tuple[bytes, bytes], tuple[bytes, bytes]],
    intent: bytes,
) -> tuple[tuple[bytes, bytes], tuple[bytes, bytes], bytes | None]:
    auth = witness.authorization
    inputs = witness.inputs
    outputs = witness.outputs
    flags = statement.flags
    checks.require(
        activity_shape_accepts(auth.mode, flags),
        "authorization.activity_shape",
        "mode-specific 2-in 2-out activity shapes",
        "mux_shape",
        "statement.flags",
        "authorization.mode",
        detail="activity mask incompatible with mode",
    )
    current_master, next_master = auth.policy_masters
    if auth.mode == 0:
        _check_zero(checks, auth.current.is_zero() and auth.next.is_zero() and all(tag == bytes(64) for tag in auth.signer_tags) and current_master == bytes(64) and next_master == bytes(64), "authorization.single.unused_zero", "mode-specific note typing and unused-lane zeroing", "authorization.auxiliary", "single-key auxiliary witness is nonzero")
        for index, active in enumerate(flags[:2]):
            checks.require(not active or inputs[index].note.kind == 0, f"authorization.single.input_kind[{index}]", "mode-specific note typing and unused-lane zeroing", "conditional_eq", f"input[{index}].note.kind", detail="single-key input is not ordinary")
        for index, active in enumerate(flags[2:]):
            checks.require(not active or outputs[index].note.kind == 0, f"authorization.single.output_kind[{index}]", "mode-specific note typing and unused-lane zeroing", "conditional_eq", f"output[{index}].note.kind", detail="single-key output is not ordinary")
        return ((spend[0][0], spend[1][0]), (spend[0][1], spend[1][1]), None)
    if auth.mode == 1:
        _check_zero(checks, auth.current.is_zero() and current_master == bytes(64), "authorization.init.current_zero", "mode-specific note typing and unused-lane zeroing", "authorization.current/master", "init current state/master is nonzero")
        for index, active in enumerate(flags[:2]):
            checks.require(not active or inputs[index].note.kind == 0, f"authorization.init.input_kind[{index}]", "mode-specific note typing and unused-lane zeroing", "conditional_eq", f"input[{index}].note.kind", detail="init input is not ordinary")
        checks.require(outputs[0].note.kind == 1 and outputs[0].note.value == 0 and outputs[0].note.asset == 0, "authorization.init.output0", "mode-specific note typing and unused-lane zeroing", "tuple_eq", "output[0].note", detail="init output zero is not zero-native accumulator")
        checks.require(not flags[3] or outputs[1].note.kind == 0, "authorization.init.output1", "mode-specific note typing and unused-lane zeroing", "conditional_eq", "output[1].note.kind", detail="init optional output one is not ordinary")
        _validate_accumulator(checks, "authorization.next", auth.next, auth.signer_tags, policy_digest, None)
        checks.require(auth.next.approval_count == 0 and not any(auth.next.approved), "authorization.init.approvals_zero", "accumulator threshold signer and approval metadata", "eq_zero", "authorization.next.approvals", detail="init approvals are nonzero")
        return ((spend[0][0], spend[1][0]), (spend[0][1], spend[1][1]), auth_digests[0][0])
    if auth.mode == 2:
        checks.require(
            current_master == next_master,
            "authorization.approval.policy_master_continuity",
            "approval increment no-clear one-change and signer membership",
            "digest_eq",
            "authorization.policy_masters.current",
            "authorization.policy_masters.next",
            detail="approval transition changes the policy master",
        )
        checks.require(inputs[0].note.kind == 1 and inputs[0].note.value == 0 and inputs[0].note.asset == 0 and inputs[0].spend_master == bytes(64), "authorization.approval.input0", "mode-specific note typing and unused-lane zeroing", "tuple_eq", "input[0]", detail="approval input zero is not zero-native accumulator with zero spend master")
        checks.require(inputs[1].note.kind == 0, "authorization.approval.input1", "mode-specific note typing and unused-lane zeroing", "eq", "input[1].note.kind", detail="approval signer input is not ordinary")
        checks.require(outputs[0].note.kind == 1 and outputs[0].note.value == 0 and outputs[0].note.asset == 0, "authorization.approval.output0", "mode-specific note typing and unused-lane zeroing", "tuple_eq", "output[0].note", detail="approval output zero is not zero-native accumulator")
        checks.require(not flags[3] or outputs[1].note.kind == 0, "authorization.approval.output1", "mode-specific note typing and unused-lane zeroing", "conditional_eq", "output[1].note.kind", detail="approval optional output one is not ordinary")
        _validate_accumulator(checks, "authorization.current", auth.current, auth.signer_tags, policy_digest, None)
        _validate_accumulator(checks, "authorization.next", auth.next, auth.signer_tags, policy_digest, None)
        checks.require(auth.current.policy_root == auth.next.policy_root and auth.current.intent == auth.next.intent and auth.current.threshold == auth.next.threshold and auth.current.signer_count == auth.next.signer_count and auth.next.approval_count == auth.current.approval_count + 1, "authorization.approval.metadata", "approval increment no-clear one-change and signer membership", "transition", "authorization.current", "authorization.next", detail="approval transition metadata mismatch")
        signer = spend[1][0]
        matches = [slot for slot in range(auth.current.signer_count) if auth.signer_tags[slot] == signer]
        checks.require(len(matches) == 1 and not auth.current.approved[matches[0]], "authorization.approval.signer", "approval increment no-clear one-change and signer membership", "onehot_membership", "digest.spend[1].lane_a", "authorization.signer_tags", detail="approval signer membership mismatch")
        selected = matches[0]
        checks.require(all(auth.next.approved[slot] == (auth.current.approved[slot] or slot == selected) for slot in range(6)), "authorization.approval.bits", "approval increment no-clear one-change and signer membership", "bit_transition", "authorization.current.approved", "authorization.next.approved", detail="approval bit transition mismatch")
        return ((auth_digests[0][0], spend[1][0]), (auth_digests[0][1], spend[1][1]), auth_digests[1][0])
    if auth.mode == 3:
        _check_zero(checks, auth.next.is_zero() and next_master == bytes(64), "authorization.lock.next_zero", "mode-specific note typing and unused-lane zeroing", "authorization.next/master", "value-lock next state/master is nonzero")
        for index, active in enumerate(flags[:2]):
            checks.require(not active or inputs[index].note.kind == 0, f"authorization.lock.input_kind[{index}]", "mode-specific note typing and unused-lane zeroing", "conditional_eq", f"input[{index}].note.kind", detail="value-lock input is not ordinary")
        checks.require(outputs[0].note.kind == 2, "authorization.lock.output0", "mode-specific note typing and unused-lane zeroing", "eq", "output[0].note.kind", detail="value-lock output zero kind")
        checks.require(not flags[3] or outputs[1].note.kind == 0, "authorization.lock.output1", "mode-specific note typing and unused-lane zeroing", "conditional_eq", "output[1].note.kind", detail="value-lock optional output one is not ordinary")
        _validate_accumulator(checks, "authorization.current", auth.current, auth.signer_tags, policy_digest, None)
        checks.require(auth.current.approval_count == 0 and not any(auth.current.approved), "authorization.lock.approvals_zero", "accumulator threshold signer and approval metadata", "eq_zero", "authorization.current.approvals", detail="value-lock approvals are nonzero")
        return ((spend[0][0], spend[1][0]), (spend[0][1], spend[1][1]), auth_digests[0][0])
    _check_zero(checks, auth.next.is_zero() and next_master == bytes(64), "authorization.final.next_zero", "mode-specific note typing and unused-lane zeroing", "authorization.next/master", "final next state/master is nonzero")
    checks.require(inputs[0].note.kind == 2 and inputs[1].note.kind == 1, "authorization.final.input_kinds", "mode-specific note typing and unused-lane zeroing", "tuple_eq", "input[0].note.kind", "input[1].note.kind", detail="final input note kinds")
    checks.require(inputs[1].note.value == 0 and inputs[1].note.asset == 0 and inputs[0].spend_master == bytes(64) and inputs[1].spend_master == bytes(64), "authorization.final.input_structure", "mode-specific note typing and unused-lane zeroing", "tuple_eq", "inputs", detail="final accumulator/spend structure")
    for index, active in enumerate(flags[2:]):
        checks.require(not active or outputs[index].note.kind == 0, f"authorization.final.output_kind[{index}]", "mode-specific note typing and unused-lane zeroing", "conditional_eq", f"output[{index}].note.kind", detail="final output is not ordinary")
    _validate_accumulator(checks, "authorization.current", auth.current, auth.signer_tags, policy_digest, intent)
    checks.require(auth.current.approval_count >= auth.current.threshold, "authorization.final.threshold", "accumulator threshold signer and approval metadata", "ge", "authorization.current.approval_count", "authorization.current.threshold", detail="threshold not reached")
    return ((auth_digests[1][0], auth_digests[0][0]), (auth_digests[1][1], auth_digests[0][1]), None)


def _selected_slot(
    checks: Checks,
    label: str,
    selectors: Sequence[bool],
    assets: Sequence[int],
    asset: int,
) -> int:
    selected = [index for index, value in enumerate(selectors) if value]
    checks.require(
        len(selected) == 1,
        f"{label}.selector_onehot",
        "active selector one-hot and selected-asset equality",
        "onehot",
        f"{label}.selectors",
        detail="active note does not select exactly one asset slot",
    )
    slot = selected[0]
    checks.require(
        assets[slot] == asset and asset != PADDING_ASSET,
        f"{label}.selected_asset[{slot}]",
        "active selector one-hot and selected-asset equality",
        "eq",
        f"{label}.note.asset",
        f"statement.assets[{slot}]",
        detail="selected asset does not match note asset",
    )
    return slot


def _authority_calls_and_checks(
    statement: Statement,
    context_raw: bytes,
    witness: Witness,
    checks: Checks,
) -> tuple[list[HashCall], bytes]:
    if type(context_raw) is not bytes or len(context_raw) != CONTEXT_BYTES:
        raise RelationFailure("context.width", "canonical verifier context", "context is not exactly 72 bytes")
    context_root = context_raw[:64]
    context_height = int.from_bytes(context_raw[64:], "little")
    if not statement.stable_enabled:
        checks.require(
            context_raw == bytes(CONTEXT_BYTES),
            "authority.disabled.context_zero",
            "all-W64 snapshot reconstruction and verifier context equality",
            "eq_zero",
            "verifier_context",
            detail="disabled verifier context is nonzero",
        )
        policy_raw = bytes(61)
        row = bytes(215)
        leaf_raw = b"\0" + row
        index = 0
        siblings = (bytes(64),) * 4
        height = 0
    else:
        if witness.manifest is None:
            raise RelationFailure("authority.witness.present", "all-W64 manifest transport", "enabled manifest witness absent")
        entry = witness.manifest.entry
        index = witness.manifest.index
        siblings = witness.manifest.siblings
        row = entry.encode()
        leaf_raw = b"\1" + row
        height = statement.state_height
        policy_raw = AUTHORITY.policy_tuple(entry)
        checks.require(
            context_height == height,
            "authority.context.height",
            "all-W64 snapshot reconstruction and verifier context equality",
            "eq",
            "statement.state_height",
            "verifier_context.parent_height",
            detail="verifier parent height mismatch",
        )
        binding = AUTHORITY.FreshStablecoinBindingV2W64(
            asset_id=statement.stable_asset,
            policy_version=statement.stable_version,
            issuance_magnitude=statement.stable_magnitude,
            policy_hash=statement.stable_policy,
            oracle_commitment=statement.stable_oracle,
            attestation_commitment=statement.stable_attestation,
        )
        try:
            AUTHORITY.verify_fresh_v2_w64_entry(binding, entry, height)
        except Exception as error:
            raise RelationFailure(
                "authority.selected_entry",
                "all-W64 selected lifecycle oracle dispute and cap",
                str(error),
            ) from error
    calls: list[HashCall] = []
    policy_person = AUTHORITY.identity_personalization(
        AUTHORITY.IDENTITY_ROLE_POLICY, 64
    )
    policy_call = HashCall.authority(83, "stablecoin_policy_constructor", policy_raw, policy_person)
    calls.append(policy_call)
    leaf_person = AUTHORITY.personalization(
        AUTHORITY.ROLE_LEAF,
        64,
        16,
        profile=AUTHORITY.FRESH_V2_AUTHORITY_PROFILE,
    )
    leaf_call = HashCall.authority(84, "manifest_leaf", leaf_raw, leaf_person)
    calls.append(leaf_call)
    current = bytes.fromhex(leaf_call.digest_hex)
    cursor = index
    for level, sibling in enumerate(siblings):
        left, right = (sibling, current) if cursor & 1 else (current, sibling)
        person = AUTHORITY.personalization(
            AUTHORITY.ROLE_NODE,
            64,
            16,
            level,
            profile=AUTHORITY.FRESH_V2_AUTHORITY_PROFILE,
        )
        call = HashCall.authority(85 + level, f"manifest_node[{level}]", left + right, person)
        calls.append(call)
        current = bytes.fromhex(call.digest_hex)
        cursor >>= 1
    if cursor:
        raise RelationFailure("authority.index.high", "all-W64 manifest transport", "selected index has high bits")
    snapshot_raw = height.to_bytes(8, "little") + current
    snapshot_person = AUTHORITY.personalization(
        AUTHORITY.ROLE_SNAPSHOT,
        64,
        16,
        profile=AUTHORITY.FRESH_V2_AUTHORITY_PROFILE,
    )
    snapshot_call = HashCall.authority(89, "state_snapshot", snapshot_raw, snapshot_person)
    calls.append(snapshot_call)
    if statement.stable_enabled:
        checks.require(
            bytes.fromhex(policy_call.digest_hex) == statement.stable_policy,
            "authority.policy.output",
            "all-W64 policy identity output equality",
            "digest_eq",
            "digest.authority.policy",
            "statement.stable_policy",
            detail="selected policy identity mismatch",
        )
        checks.require(
            current == statement.manifest_root,
            "authority.path.root_statement",
            "all-W64 selected leaf and depth-four root recomputation",
            "digest_eq",
            "digest.authority.node[3]",
            "statement.manifest_root",
            detail="selected row/path does not recompute statement manifest root",
        )
        checks.require(
            current == context_root,
            "authority.path.root_context",
            "all-W64 snapshot reconstruction and verifier context equality",
            "digest_eq",
            "digest.authority.node[3]",
            "verifier_context.manifest_root",
            detail="recomputed manifest root does not equal verifier context",
        )
        checks.require(
            bytes.fromhex(snapshot_call.digest_hex) == statement.state_root,
            "authority.snapshot.output",
            "all-W64 snapshot reconstruction and verifier context equality",
            "digest_eq",
            "digest.authority.snapshot",
            "statement.state_root",
            detail="snapshot does not equal statement state root",
        )
    return calls, current


def evaluate(statement_raw: bytes, context_raw: bytes, witness_raw: bytes) -> Evaluation:
    """Decode and evaluate one exact HX512 relation instance.

    A successful return certifies only this source interpreter and its concrete
    byte/hash semantics.  It does not certify a sparse-R1CS lowering or proof.
    """

    statement = Statement.decode(statement_raw)
    witness = Witness.decode(witness_raw, statement.stable_enabled)
    checks = Checks()
    flags = statement.flags

    checks.require(
        activity_shape_accepts(witness.authorization.mode, flags),
        "activity.mask_mode",
        "all sixteen activity masks with all-empty rejection",
        "lookup",
        "statement.flags",
        "authorization.mode",
        detail="mask/mode pair is rejected",
    )
    for index, active in enumerate(flags[:2]):
        input_value = witness.inputs[index]
        if active:
            checks.require(
                input_value.note.kind in range(3),
                f"input[{index}].note.kind",
                "active note kind value and asset ranges",
                "range",
                f"input[{index}].note.kind",
                detail="active input note kind outside 0..2",
            )
            checks.require(
                input_value.note.value <= MAX_VALUE,
                f"input[{index}].note.value",
                "active note kind value and asset ranges",
                "range",
                f"input[{index}].note.value",
                detail="active input note value exceeds 2^61-1",
            )
            checks.require(
                input_value.note.asset < P and input_value.note.asset != RESERVED_REDUCED_PADDING_ASSET,
                f"input[{index}].note.asset",
                "active note kind value and asset ranges",
                "range",
                f"input[{index}].note.asset",
                detail="active input note asset is noncanonical",
            )
            checks.require(
                input_value.position < 1 << 32,
                f"input[{index}].position",
                "active input 32-bit Merkle position",
                "range",
                f"input[{index}].position",
                detail="active input position exceeds 32 bits",
            )
            checks.require(
                statement.nullifiers[index] != bytes(64),
                f"input[{index}].public_nullifier_nonzero",
                "nullifier derivation and active public equality",
                "nonzero",
                f"statement.nullifiers[{index}]",
                detail="active public nullifier is zero",
            )
        else:
            checks.require(
                input_value.raw == bytes(2384) and statement.nullifiers[index] == bytes(64),
                f"input[{index}].inactive_zero",
                "inactive input witness and public nullifier zero",
                "conditional_zero",
                f"input[{index}]",
                f"statement.nullifiers[{index}]",
                detail="inactive input surface is nonzero",
            )
    for index, active in enumerate(flags[2:]):
        output = witness.outputs[index]
        if active:
            checks.require(
                output.note.kind in range(3),
                f"output[{index}].note.kind",
                "active note kind value and asset ranges",
                "range",
                f"output[{index}].note.kind",
                detail="active output note kind outside 0..2",
            )
            checks.require(
                output.note.value <= MAX_VALUE,
                f"output[{index}].note.value",
                "active note kind value and asset ranges",
                "range",
                f"output[{index}].note.value",
                detail="active output note value exceeds 2^61-1",
            )
            checks.require(
                output.note.asset < P and output.note.asset != RESERVED_REDUCED_PADDING_ASSET,
                f"output[{index}].note.asset",
                "active note kind value and asset ranges",
                "range",
                f"output[{index}].note.asset",
                detail="active output note asset is noncanonical",
            )
            checks.require(
                statement.commitments[index] != bytes(64),
                f"output[{index}].public_commitment_nonzero",
                "note commitments and resolved authorization keys",
                "nonzero",
                f"statement.commitments[{index}]",
                detail="active public commitment is zero",
            )
        else:
            checks.require(
                output.raw == bytes(264)
                and output.ciphertext == bytes(CIPHERTEXT_BYTES)
                and statement.commitments[index] == bytes(64)
                and statement.ciphertext_hashes[index] == bytes(64)
                and statement.ciphertext_sizes[index] == 0,
                f"output[{index}].inactive_zero",
                "inactive output witness ciphertext and public bindings zero",
                "conditional_zero",
                f"output[{index}]",
                f"ciphertext[{index}]",
                f"statement.output_bindings[{index}]",
                detail="inactive output surface is nonzero",
            )
    checks.require(
        not (flags[0] and flags[1]) or statement.nullifiers[0] != statement.nullifiers[1],
        "input.nullifiers.distinct",
        "duplicate active nullifier rejection",
        "conditional_digest_neq",
        "statement.nullifiers[0]",
        "statement.nullifiers[1]",
        detail="duplicate active nullifiers",
    )

    core_calls: dict[int, HashCall] = {}
    note_digests: list[bytes] = []
    notes: tuple[Note, Note, Note, Note] = (
        witness.inputs[0].note,
        witness.inputs[1].note,
        witness.outputs[0].note,
        witness.outputs[1].note,
    )
    for index, note in enumerate(notes):
        message = _note_message(note)
        if len(message) != 256:
            raise RelationFailure(f"hash.note[{index}].frame", "HX512B01 core frame wiring", "note frame is not 256 bytes")
        call = HashCall.core(index, f"note_commitment[{index}]", SUITE.ROLE_NOTE, message)
        core_calls[index] = call
        note_digests.append(bytes.fromhex(call.digest_hex))

    spend: list[tuple[bytes, bytes]] = []
    for index, input_value in enumerate(witness.inputs):
        lanes = []
        for lane in range(2):
            message = _spend_message(input_value.spend_master, lane)
            call_index = 70 + index if lane == 0 else 72 + index
            call = HashCall.core(call_index, f"spend_key[{index}].lane[{lane}]", (SUITE.ROLE_SPEND_A, SUITE.ROLE_SPEND_B)[lane], message)
            core_calls[call_index] = call
            lanes.append(bytes.fromhex(call.digest_hex))
        spend.append((lanes[0], lanes[1]))

    selected_opening, selected_master = _selected_policy(witness.authorization)
    policy_message = _policy_message(selected_master, selected_opening, witness.authorization.signer_tags)
    if len(policy_message) != 499:
        raise RelationFailure("hash.policy.frame", "HX512B01 core frame wiring", "policy frame is not 499 bytes")
    policy_call = HashCall.core(74, "authorization_policy", SUITE.ROLE_AUTH_POLICY, policy_message)
    core_calls[74] = policy_call
    policy_digest = bytes.fromhex(policy_call.digest_hex)

    auth_digests_mut: list[list[bytes]] = [[bytes(64), bytes(64)] for _ in range(2)]
    for lane in range(2):
        for slot in range(2):
            message = _authorization_message(witness.authorization, lane, slot)
            if len(message) not in (136, 225, 263):
                raise RelationFailure(f"hash.authorization[{slot}][{lane}].frame", "HX512B01 core frame wiring", "authorization arm width")
            call_index = (75 if lane == 0 else 77) + slot
            call = HashCall.core(call_index, f"authorization[{slot}].lane[{lane}]", AUTH_ROLES[lane], message, fixed_compressions=3)
            core_calls[call_index] = call
            auth_digests_mut[slot][lane] = bytes.fromhex(call.digest_hex)
    auth_digests = (
        (auth_digests_mut[0][0], auth_digests_mut[0][1]),
        (auth_digests_mut[1][0], auth_digests_mut[1][1]),
    )

    intent_message = _intent_message(statement.raw)
    if len(intent_message) != 968:
        raise RelationFailure("hash.intent.frame", "HX512B01 core frame wiring", "intent frame is not 968 bytes")
    intent_call = HashCall.core(79, "intent", SUITE.ROLE_INTENT, intent_message)
    core_calls[79] = intent_call
    intent = bytes.fromhex(intent_call.digest_hex)
    balance_message = _balance_message(statement)
    if len(balance_message) != 100:
        raise RelationFailure("hash.balance.frame", "HX512B01 core frame wiring", "balance frame is not 100 bytes")
    balance_call = HashCall.core(80, "balance_tag", SUITE.ROLE_BALANCE, balance_message)
    core_calls[80] = balance_call
    checks.require(
        bytes.fromhex(balance_call.digest_hex) == statement.balance_tag,
        "balance_tag.public",
        "public balance-tag equality",
        "digest_eq",
        "digest.balance_tag",
        "statement.balance_tag",
        detail="balance tag mismatch",
    )
    for index, output in enumerate(witness.outputs):
        message = _ciphertext_message(index, output.ciphertext)
        if len(message) != 2182:
            raise RelationFailure(f"hash.ciphertext[{index}].frame", "HX512B01 core frame wiring", "ciphertext frame is not 2182 bytes")
        call = HashCall.core(81 + index, f"ciphertext_hash[{index}]", SUITE.ROLE_CIPHERTEXT, message)
        core_calls[81 + index] = call
        if flags[2 + index]:
            checks.require(
                bytes.fromhex(call.digest_hex) == statement.ciphertext_hashes[index],
                f"ciphertext[{index}].public_hash",
                "canonical ciphertext hash equality",
                "digest_eq",
                f"digest.ciphertext[{index}]",
                f"statement.ciphertext_hashes[{index}]",
                detail="ciphertext bytes do not match public hash",
            )

    resolved_auth, resolved_nullifier, output0_auth = _validate_authorization(
        statement,
        witness,
        checks,
        (spend[0], spend[1]),
        policy_digest,
        auth_digests,
        intent,
    )

    input_values = [[0, 0, 0, 0] for _ in range(2)]
    output_values = [[0, 0, 0, 0] for _ in range(2)]
    roots: list[bytes] = []
    nullifier_digests: list[bytes] = []
    for index, input_value in enumerate(witness.inputs):
        active = flags[index]
        if active:
            slot = _selected_slot(checks, f"input[{index}]", input_value.selectors, statement.assets, input_value.note.asset)
            input_values[index][slot] = input_value.note.value
            checks.require(
                input_value.note.authorization == resolved_auth[index],
                f"input[{index}].authorization",
                "note commitments and resolved authorization keys",
                "digest_eq",
                f"input[{index}].note.authorization",
                f"resolved.input_auth[{index}]",
                detail="input note authorization key mismatch",
            )
        null_message = _nullifier_message(resolved_nullifier[index], input_value.position, input_value.note.rho)
        if len(null_message) != 143:
            raise RelationFailure(f"hash.nullifier[{index}].frame", "HX512B01 core frame wiring", "nullifier frame is not 143 bytes")
        null_call = HashCall.core(4 + index, f"nullifier[{index}]", SUITE.ROLE_NULLIFIER, null_message)
        core_calls[4 + index] = null_call
        nullifier = bytes.fromhex(null_call.digest_hex)
        nullifier_digests.append(nullifier)
        if active:
            checks.require(
                nullifier == statement.nullifiers[index],
                f"input[{index}].nullifier_public",
                "nullifier derivation and active public equality",
                "digest_eq",
                f"digest.nullifier[{index}]",
                f"statement.nullifiers[{index}]",
                detail="public nullifier mismatch",
            )
        current = note_digests[index]
        for level, sibling in enumerate(input_value.siblings):
            left, right = (sibling, current) if (input_value.position >> level) & 1 else (current, sibling)
            message = _merkle_message(left, right)
            call_index = 6 + index * 32 + level
            call = HashCall.core(call_index, f"merkle[{index}][{level}]", SUITE.ROLE_MERKLE, message)
            core_calls[call_index] = call
            current = bytes.fromhex(call.digest_hex)
        roots.append(current)
        if active:
            checks.require(
                current == statement.anchor,
                f"input[{index}].anchor",
                "32-level Merkle direction selection and anchor equality",
                "digest_eq",
                f"digest.merkle[{index}][31]",
                "statement.anchor",
                detail="input Merkle root does not equal anchor",
            )

    commitment_digests = note_digests[2:]
    for index, output in enumerate(witness.outputs):
        if flags[2 + index]:
            slot = _selected_slot(checks, f"output[{index}]", output.selectors, statement.assets, output.note.asset)
            output_values[index][slot] = output.note.value
            checks.require(
                commitment_digests[index] == statement.commitments[index],
                f"output[{index}].commitment_public",
                "note commitments and resolved authorization keys",
                "digest_eq",
                f"digest.note.output[{index}]",
                f"statement.commitments[{index}]",
                detail="public output commitment mismatch",
            )
    if output0_auth is not None:
        checks.require(
            flags[2] and witness.outputs[0].note.authorization == output0_auth,
            "authorization.output0_key",
            "note commitments and resolved authorization keys",
            "digest_eq",
            "output[0].note.authorization",
            "resolved.output0_auth",
            detail="mode-specific output-zero authorization mismatch",
        )

    for slot, asset in enumerate(statement.assets):
        inputs_total = sum(row[slot] for row in input_values)
        outputs_total = sum(row[slot] for row in output_values)
        if asset == PADDING_ASSET:
            expected = 0
            family = "ordinary non-native conservation"
        elif asset == 0:
            expected = statement.fee - _signed(statement.value_sign, statement.value_magnitude)
            family = "signed native balance including fee"
        elif statement.stable_enabled and asset == statement.stable_asset:
            expected = _signed(statement.stable_sign, statement.stable_magnitude)
            family = "stablecoin mint and burn signed balance"
        else:
            expected = 0
            family = "ordinary non-native conservation"
        checks.require(
            inputs_total - outputs_total == expected,
            f"balance.{family.replace(' ', '_').replace('-', '_')}.slot[{slot}]",
            family,
            "signed_balance",
            f"input_values.slot[{slot}]",
            f"output_values.slot[{slot}]",
            f"statement.assets[{slot}]",
            detail=f"asset {asset} balance mismatch",
        )

    authority_calls, manifest_root = _authority_calls_and_checks(
        statement, context_raw, witness, checks
    )
    ordered_core = tuple(core_calls[index] for index in range(83))
    all_calls = ordered_core + tuple(authority_calls)
    if len(all_calls) != 90:
        raise AssertionError(len(all_calls))
    if sum(call.fixed_compressions for call in ordered_core) != 205:
        raise AssertionError("core fixed compression schedule drift")
    if sum(call.fixed_compressions for call in authority_calls) != 8:
        raise AssertionError("authority compression schedule drift")
    derived = {
        "anchor": [root.hex() for root in roots],
        "nullifiers": [value.hex() for value in nullifier_digests],
        "commitments": [value.hex() for value in commitment_digests],
        "ciphertext_hashes": [core_calls[81 + i].digest_hex for i in range(2)],
        "policy_digest": policy_digest.hex(),
        "authorization_digests": [[value.hex() for value in pair] for pair in auth_digests],
        "intent": intent.hex(),
        "balance_tag": balance_call.digest_hex,
        "manifest_root": manifest_root.hex(),
        "state_snapshot": authority_calls[-1].digest_hex,
        "core_calls": 83,
        "authority_calls": 7,
        "fixed_blake2b512_compressions": 213,
    }
    trace = {
        "schema": "hegemon.hx512b01.executable-trace.v1",
        "checks": [dataclasses.asdict(item) for item in checks.items],
        "hash_calls": [dataclasses.asdict(item) for item in all_calls],
        "derived": derived,
    }
    return Evaluation(
        accepted=True,
        checks=tuple(checks.items),
        hash_calls=all_calls,
        derived=derived,
        trace_digest_shake256_512=digest_json(
            b"hegemon.hx512b01.executable-trace.v1\0", trace
        ),
    )


def _fill(label: str, width: int) -> bytes:
    return hashlib.shake_256(b"hegemon.hx512b01.fixture.v1\0" + label.encode()).digest(width)


def _encode_note(
    kind: int,
    value: int,
    asset: int,
    recipient: bytes,
    rho: bytes,
    blinding: bytes,
    authorization: bytes,
) -> bytes:
    values = (recipient, rho, blinding, authorization)
    if tuple(map(len, values)) != (32, 48, 64, 64):
        raise AssertionError("note component width")
    return (
        kind.to_bytes(8, "big")
        + value.to_bytes(8, "big")
        + asset.to_bytes(8, "big")
        + recipient
        + rho
        + blinding
        + authorization
    )


def _encode_accumulator(
    policy_root: bytes = bytes(64),
    intent: bytes = bytes(64),
    threshold: int = 0,
    signer_count: int = 0,
    approval_count: int = 0,
    approved: Sequence[bool] = (False,) * 6,
) -> bytes:
    if len(policy_root) != 64 or len(intent) != 64 or len(approved) != 6:
        raise AssertionError("accumulator component width")
    return (
        policy_root
        + intent
        + threshold.to_bytes(8, "big")
        + signer_count.to_bytes(8, "big")
        + approval_count.to_bytes(8, "big")
        + b"".join(int(value).to_bytes(8, "big") for value in approved)
    )


def _encode_authorization(
    mode: int,
    current: bytes,
    next_value: bytes,
    tags: Sequence[bytes],
) -> bytes:
    if len(current) != 200 or len(next_value) != 200 or len(tags) != 6 or any(len(tag) != 64 for tag in tags):
        raise AssertionError("authorization component width")
    value = mode.to_bytes(8, "big") + current + next_value + b"".join(tags)
    if len(value) != 792:
        raise AssertionError(len(value))
    return value


def _auth_hashes(auth: Authorization) -> tuple[bytes, tuple[tuple[bytes, bytes], tuple[bytes, bytes]]]:
    selected, master = _selected_policy(auth)
    policy = _blake(_policy_message(master, selected, auth.signer_tags))
    pairs: list[tuple[bytes, bytes]] = []
    for slot in range(2):
        pairs.append(
            (
                _blake(_authorization_message(auth, 0, slot)),
                _blake(_authorization_message(auth, 1, slot)),
            )
        )
    return policy, (pairs[0], pairs[1])


def _note_digest(raw: bytes, label: str) -> bytes:
    return _blake(Note.decode(raw, label).frame())


def _core_merkle_root(note_digest: bytes, position: int, siblings: Sequence[bytes]) -> bytes:
    current = note_digest
    for level, sibling in enumerate(siblings):
        left, right = (sibling, current) if (position >> level) & 1 else (current, sibling)
        current = _blake(_merkle_message(left, right))
    return current


@dataclasses.dataclass(frozen=True)
class Fixture:
    mode: int
    mask: int
    stable_enabled: bool
    statement: bytes
    context: bytes
    witness: bytes
    evaluation_trace_digest_shake256_512: str


def build_fixture(mode: int = 0, mask: int = 0b1111, *, stable_enabled: bool = False, policy_version: int = 0) -> Fixture:
    """Build one deterministic acceptance for the diagnostic grammar."""

    flags = tuple(bool(mask & (1 << bit)) for bit in range(4))
    if not activity_shape_accepts(mode, flags):
        raise RelationFailure("fixture.mask_mode", "fixture builder", "requested pair is rejected")
    stable_input_index: int | None = None
    stable_output_index: int | None = None
    if stable_enabled:
        eligible_inputs = [
            index
            for index, active in enumerate(flags[:2])
            if active
            and not (mode == 2 and index == 0)
            and not (mode == 4 and index == 1)
        ]
        eligible_outputs = [
            index
            for index, active in enumerate(flags[2:])
            if active and not (index == 0 and mode in (1, 2))
        ]
        if eligible_inputs:
            stable_input_index = eligible_inputs[0]
        elif eligible_outputs:
            stable_output_index = eligible_outputs[0]
        else:
            raise RelationFailure("fixture.stable_shape", "fixture builder", "no note may carry the stablecoin delta")

    statement = bytearray(SUITE.sample_statement(PROFILE_NAME))
    statement[1077:1141] = PROFILE.DIAGNOSTIC_RULES_HASH
    statement[10:14] = bytes(int(value) for value in flags)
    statement[14:470] = bytes(456)
    statement[470:502] = (
        (0).to_bytes(8, "big")
        + ((1001).to_bytes(8, "big") if stable_enabled else PADDING_ASSET.to_bytes(8, "big"))
        + PADDING_ASSET.to_bytes(8, "big")
        + PADDING_ASSET.to_bytes(8, "big")
    )
    statement[502:933] = bytes(431)
    context = bytes(CONTEXT_BYTES)
    manifest_transport = bytes(MANIFEST_TRANSPORT_BYTES)
    if stable_enabled:
        entries = [
            AUTHORITY.sample_fresh_entry_v2_w64(1001 + index, policy_version)[0]
            for index in range(16)
        ]
        path = AUTHORITY.prove_fresh_v2_w64_merkle(entries, 0)
        entry = path.entry
        height = 50
        root = AUTHORITY.fresh_v2_w64_merkle_root(entries)
        snapshot = AUTHORITY.snapshot_commitment(
            root,
            height,
            64,
            profile=AUTHORITY.FRESH_V2_AUTHORITY_PROFILE,
        )
        statement[519] = 1
        statement[520:528] = entry.asset_id.to_bytes(8, "big")
        statement[528:532] = entry.policy_version.to_bytes(4, "big")
        statement[532] = int(stable_output_index is not None)
        statement[533:541] = (1).to_bytes(8, "big")
        statement[541:605] = AUTHORITY.policy_hash64_v2(entry)
        statement[605:669] = entry.oracle_commitment
        statement[669:733] = entry.attestation_commitment
        statement[733:797] = root
        statement[797:861] = snapshot
        statement[861:869] = height.to_bytes(8, "big")
        context = root + height.to_bytes(8, "little")
        manifest_transport = path.encode() + bytes(5)

    # Ciphertexts and their statement bindings are independent of note/auth
    # construction and are fixed before the intent digest is derived.
    ciphertexts: list[bytes] = []
    for index, active in enumerate(flags[2:]):
        ciphertext = _fill(f"ciphertext[{mode}][{mask}][{index}]", CIPHERTEXT_BYTES) if active else bytes(CIPHERTEXT_BYTES)
        ciphertexts.append(ciphertext)
        if active:
            statement[462 + 4 * index : 466 + 4 * index] = CIPHERTEXT_BYTES.to_bytes(4, "big")
            statement[334 + 64 * index : 398 + 64 * index] = _blake(_ciphertext_message(index, ciphertext))

    spend_masters: list[bytes] = []
    for index, active in enumerate(flags[:2]):
        forced_zero = mode == 4 or (mode == 2 and index == 0)
        spend_masters.append(
            _fill(f"spend-master[{mode}][{mask}][{index}]", 64)
            if active and not forced_zero
            else bytes(64)
        )
    spend = tuple(
        (
            _blake(_spend_message(spend_masters[index], 0)),
            _blake(_spend_message(spend_masters[index], 1)),
        )
        for index in range(2)
    )

    if mode == 0:
        current_master = next_master = bytes(64)
    elif mode == 1:
        current_master = bytes(64)
        next_master = _fill(f"policy-master.next[{mask}]", 64)
    elif mode == 2:
        # The current and next state retain the same master across an approval
        # transition; both transport slots are explicit and equality is tested
        # by the executable fixtures.
        current_master = next_master = _fill(f"policy-master.approval[{mask}]", 64)
    else:
        current_master = _fill(f"policy-master.current[{mode}][{mask}]", 64)
        next_master = bytes(64)
    masters = current_master + next_master

    tags = [bytes(64) for _ in range(6)]
    if mode != 0:
        tags[0] = spend[1][0] if mode == 2 else _fill(f"signer-tag[{mode}][{mask}]", 64)
    zero_acc = _encode_accumulator()
    current = zero_acc
    next_value = zero_acc
    if mode == 1:
        next_value = _encode_accumulator(threshold=1, signer_count=1)
    elif mode == 2:
        current = _encode_accumulator(threshold=1, signer_count=1)
        next_value = _encode_accumulator(threshold=1, signer_count=1, approval_count=1, approved=(True, False, False, False, False, False))
    elif mode == 3:
        current = _encode_accumulator(threshold=1, signer_count=1)
    elif mode == 4:
        current = _encode_accumulator(threshold=1, signer_count=1, approval_count=1, approved=(True, False, False, False, False, False))

    initial_auth = Authorization.decode(_encode_authorization(mode, current, next_value, tags), masters)
    policy_digest, _ = _auth_hashes(initial_auth)
    if mode == 1:
        next_value = _encode_accumulator(policy_root=policy_digest, threshold=1, signer_count=1)
    elif mode == 2:
        current = _encode_accumulator(policy_root=policy_digest, threshold=1, signer_count=1)
        next_value = _encode_accumulator(policy_root=policy_digest, threshold=1, signer_count=1, approval_count=1, approved=(True, False, False, False, False, False))
    elif mode == 3:
        current = _encode_accumulator(policy_root=policy_digest, threshold=1, signer_count=1)
    elif mode == 4:
        current = _encode_accumulator(policy_root=policy_digest, threshold=1, signer_count=1, approval_count=1, approved=(True, False, False, False, False, False))
    auth = Authorization.decode(_encode_authorization(mode, current, next_value, tags), masters)
    _, auth_pairs = _auth_hashes(auth)

    def note_components(role: str, index: int, kind: int, authorization: bytes, asset: int = 0, value: int = 0) -> bytes:
        return _encode_note(
            kind,
            value,
            asset,
            _fill(f"{role}[{mode}][{mask}][{index}].recipient", 32),
            _fill(f"{role}[{mode}][{mask}][{index}].rho", 48),
            _fill(f"{role}[{mode}][{mask}][{index}].blinding", 64),
            authorization,
        )

    output_notes = [bytes(232), bytes(232)]
    for index, active in enumerate(flags[2:]):
        if not active:
            continue
        kind = 1 if index == 0 and mode in (1, 2) else 2 if index == 0 and mode == 3 else 0
        authorization = (
            auth_pairs[0][0]
            if index == 0 and mode in (1, 3)
            else auth_pairs[1][0]
            if index == 0 and mode == 2
            else bytes(64)
        )
        asset = 1001 if stable_output_index == index else 0
        value = 1 if stable_output_index == index else 0
        output_notes[index] = note_components("output", index, kind, authorization, asset, value)
        statement[206 + 64 * index : 270 + 64 * index] = _note_digest(output_notes[index], f"fixture.output[{index}]")

    # The balance tag is committed before intent.  The balance frame excludes
    # the tag itself, so this assignment is acyclic.
    parsed_for_balance = Statement.decode(bytes(statement))
    statement[869:933] = _blake(_balance_message(parsed_for_balance))
    intent = _blake(_intent_message(bytes(statement)))
    if mode == 4:
        current = _encode_accumulator(policy_root=policy_digest, intent=intent, threshold=1, signer_count=1, approval_count=1, approved=(True, False, False, False, False, False))
        auth = Authorization.decode(_encode_authorization(mode, current, next_value, tags), masters)
        _, auth_pairs = _auth_hashes(auth)

    if mode == 0:
        resolved_auth = (spend[0][0], spend[1][0])
        resolved_null = (spend[0][1], spend[1][1])
    elif mode in (1, 3):
        resolved_auth = (spend[0][0], spend[1][0])
        resolved_null = (spend[0][1], spend[1][1])
    elif mode == 2:
        resolved_auth = (auth_pairs[0][0], spend[1][0])
        resolved_null = (auth_pairs[0][1], spend[1][1])
    else:
        resolved_auth = (auth_pairs[1][0], auth_pairs[0][0])
        resolved_null = (auth_pairs[1][1], auth_pairs[0][1])

    input_notes = [bytes(232), bytes(232)]
    positions = [0, 0]
    selectors_in = [[False] * 4 for _ in range(2)]
    selectors_out = [[False] * 4 for _ in range(2)]
    for index, active in enumerate(flags[:2]):
        if not active:
            continue
        kind = 1 if mode == 2 and index == 0 else 2 if mode == 4 and index == 0 else 1 if mode == 4 and index == 1 else 0
        asset = 1001 if stable_input_index == index else 0
        value = 1 if stable_input_index == index else 0
        selectors_in[index][1 if asset == 1001 else 0] = True
        input_notes[index] = note_components("input", index, kind, resolved_auth[index], asset, value)
    for index, active in enumerate(flags[2:]):
        if active:
            selectors_out[index][1 if stable_output_index == index else 0] = True

    input_note_digests = [_note_digest(raw, f"fixture.input[{index}]") for index, raw in enumerate(input_notes)]
    siblings = [[bytes(64) for _ in range(32)] for _ in range(2)]
    active_inputs = [index for index, active in enumerate(flags[:2]) if active]
    if len(active_inputs) == 2:
        positions = [0, 1]
        siblings[0][0] = input_note_digests[1]
        siblings[1][0] = input_note_digests[0]
    roots = [
        _core_merkle_root(input_note_digests[index], positions[index], siblings[index])
        for index in active_inputs
    ]
    if roots:
        if any(root != roots[0] for root in roots):
            raise AssertionError("fixture Merkle roots diverged")
        statement[14:78] = roots[0]
    for index in active_inputs:
        nullifier = _blake(
            _nullifier_message(
                resolved_null[index], positions[index], Note.decode(input_notes[index], f"fixture.input[{index}]").rho
            )
        )
        statement[78 + 64 * index : 142 + 64 * index] = nullifier

    inputs_raw: list[bytes] = []
    for index, active in enumerate(flags[:2]):
        if not active:
            inputs_raw.append(bytes(2384))
            continue
        value = (
            spend_masters[index]
            + input_notes[index]
            + positions[index].to_bytes(8, "big")
            + b"".join(siblings[index])
            + b"".join(int(value).to_bytes(8, "big") for value in selectors_in[index])
        )
        if len(value) != 2384:
            raise AssertionError(len(value))
        inputs_raw.append(value)
    outputs_raw: list[bytes] = []
    for index, active in enumerate(flags[2:]):
        if not active:
            outputs_raw.append(bytes(264))
            continue
        value = output_notes[index] + b"".join(int(item).to_bytes(8, "big") for item in selectors_out[index])
        if len(value) != 264:
            raise AssertionError(len(value))
        outputs_raw.append(value)
    witness = (
        b"".join(inputs_raw)
        + b"".join(outputs_raw)
        + auth.raw
        + masters
        + ciphertexts[0]
        + bytes(5)
        + ciphertexts[1]
        + bytes(5)
        + manifest_transport
    )
    if len(witness) != PRIVATE_BYTES:
        raise AssertionError(len(witness))
    evaluation = evaluate(bytes(statement), context, witness)
    return Fixture(
        mode=mode,
        mask=mask,
        stable_enabled=stable_enabled,
        statement=bytes(statement),
        context=context,
        witness=witness,
        evaluation_trace_digest_shake256_512=evaluation.trace_digest_shake256_512,
    )


@functools.lru_cache(maxsize=1)
def all_accepted_fixtures() -> tuple[Fixture, ...]:
    result = []
    for mode in range(5):
        for mask in range(16):
            flags = tuple(bool(mask & (1 << bit)) for bit in range(4))
            if activity_shape_accepts(mode, flags):
                result.append(build_fixture(mode, mask))
    if len(result) != 33:
        raise AssertionError(len(result))
    return tuple(result)


@functools.lru_cache(maxsize=1)
def all_stablecoin_accepted_fixtures() -> tuple[Fixture, ...]:
    result = []
    for mode in range(5):
        for mask in range(16):
            flags = tuple(bool(mask & (1 << bit)) for bit in range(4))
            if activity_shape_accepts(mode, flags):
                result.append(build_fixture(mode, mask, stable_enabled=True, policy_version=0))
    if len(result) != 33:
        raise AssertionError(len(result))
    return tuple(result)


@functools.lru_cache(maxsize=1)
def activity_stablecoin_matrix_certificate() -> dict[str, Any]:
    """Execute all 16 masks x 5 modes x two stablecoin branches.

    The 94 structurally invalid cells are passed through the real decoder and
    evaluator and must reach the named ``activity.mask_mode`` predicate.  They
    are not classified by the helper alone. The 66 positive cells demonstrate
    diagnostic branch execution, not production-safe issuance semantics.
    """

    positives = {
        (fixture.stable_enabled, fixture.mode, fixture.mask): fixture
        for fixture in (*all_accepted_fixtures(), *all_stablecoin_accepted_fixtures())
    }
    bases = {
        stable_enabled: build_fixture(0, 0b1111, stable_enabled=stable_enabled, policy_version=0)
        for stable_enabled in (False, True)
    }
    cells: list[dict[str, Any]] = []
    for stable_enabled in (False, True):
        for mode in range(5):
            for mask in range(16):
                expected = activity_shape_accepts(
                    mode, tuple(bool(mask & (1 << bit)) for bit in range(4))
                )
                key = (stable_enabled, mode, mask)
                if expected:
                    fixture = positives[key]
                    evaluation = evaluate(fixture.statement, fixture.context, fixture.witness)
                    cells.append(
                        {
                            "stable_enabled": stable_enabled,
                            "mode": mode,
                            "mask": mask,
                            "expected": "accept",
                            "observed": "accept",
                            "constraint_id": None,
                            "trace_digest_shake256_512": evaluation.trace_digest_shake256_512,
                        }
                    )
                    continue

                base = bases[stable_enabled]
                statement = bytearray(base.statement)
                statement[10:14] = bytes(
                    int(bool(mask & (1 << bit))) for bit in range(4)
                )
                for output_index in range(2):
                    active = bool(mask & (1 << (2 + output_index)))
                    statement[462 + 4 * output_index : 466 + 4 * output_index] = (
                        CIPHERTEXT_BYTES if active else 0
                    ).to_bytes(4, "big")
                witness = bytearray(base.witness)
                witness[5_296:5_304] = mode.to_bytes(8, "big")
                try:
                    evaluate(bytes(statement), base.context, bytes(witness))
                except RelationFailure as error:
                    if error.constraint_id != "activity.mask_mode":
                        raise AssertionError(
                            f"cell stable={stable_enabled} mode={mode} mask={mask} "
                            f"rejected at {error.constraint_id}, not activity.mask_mode"
                        ) from error
                    cells.append(
                        {
                            "stable_enabled": stable_enabled,
                            "mode": mode,
                            "mask": mask,
                            "expected": "reject",
                            "observed": "reject",
                            "constraint_id": error.constraint_id,
                            "trace_digest_shake256_512": None,
                        }
                    )
                else:
                    raise AssertionError(
                        f"invalid cell accepted: stable={stable_enabled} mode={mode} mask={mask}"
                    )
    accepted = sum(item["observed"] == "accept" for item in cells)
    rejected = sum(item["observed"] == "reject" for item in cells)
    if (len(cells), accepted, rejected) != (160, 66, 94):
        raise AssertionError((len(cells), accepted, rejected))
    return {
        "cells": cells,
        "total_cells": 160,
        "positive_cells": 66,
        "negative_cells": 94,
        "all_negative_cells_reach_activity_mask_mode": all(
            item["constraint_id"] == "activity.mask_mode"
            for item in cells
            if item["expected"] == "reject"
        ),
        "stablecoin_changes_structural_validity": False,
        "stablecoin_enabled_positive_policy_version": 0,
    }


def hash_call_source_ir() -> tuple[dict[str, Any], ...]:
    """Return the stable typed source graph for all ninety physical calls."""

    calls: list[dict[str, Any]] = []
    for index in range(4):
        role = "input" if index < 2 else "output"
        slot = index if index < 2 else index - 2
        base = f"witness.{role}[{slot}].note"
        calls.append(
            {
                "index": index,
                "registry": "HX512B01",
                "family": "note_commitment",
                "role": SUITE.ROLE_NOTE.hex(),
                "fields": [
                    f"{base}.blinding64",
                    f"{base}.kind:u8",
                    f"{base}.value:u64be",
                    f"{base}.asset:u64be",
                    f"{base}.recipient32",
                    f"{base}.rho48",
                    f"{base}.authorization64",
                ],
                "message_bytes": 256,
                "output": f"derived.note_digest[{index}]:512",
            }
        )
    for index in range(2):
        calls.append(
            {
                "index": 4 + index,
                "registry": "HX512B01",
                "family": "nullifier",
                "role": SUITE.ROLE_NULLIFIER.hex(),
                "fields": [
                    f"derived.resolved_nullifier_key[{index}]:512",
                    f"witness.input[{index}].position:u64be",
                    f"witness.input[{index}].note.rho48",
                ],
                "message_bytes": 143,
                "output": f"derived.nullifier[{index}]:512",
            }
        )
    for input_index in range(2):
        for level in range(32):
            current_source = (
                f"derived.note_digest[{input_index}]"
                if level == 0
                else f"derived.merkle[{input_index}][{level - 1}]"
            )
            calls.append(
                {
                    "index": 6 + input_index * 32 + level,
                    "registry": "HX512B01",
                    "family": "merkle_node",
                    "role": SUITE.ROLE_MERKLE.hex(),
                    "fields": [
                        (
                            f"select(position[{level}],witness.input[{input_index}].siblings[{level}],"
                            f"{current_source})"
                        ),
                        (
                            f"select(position[{level}],{current_source},"
                            f"witness.input[{input_index}].siblings[{level}])"
                        ),
                    ],
                    "message_bytes": 149,
                    "output": f"derived.merkle[{input_index}][{level}]:512",
                }
            )
    for lane, role in enumerate((SUITE.ROLE_SPEND_A, SUITE.ROLE_SPEND_B)):
        for index in range(2):
            calls.append(
                {
                    "index": (70 if lane == 0 else 72) + index,
                    "registry": "HX512B01",
                    "family": "spend_key",
                    "role": role.hex(),
                    "fields": [LANES[lane].hex(), f"witness.input[{index}].spend_master64"],
                    "message_bytes": 93,
                    "output": f"derived.spend[{index}].lane[{lane}]:512",
                }
            )
    calls.append(
        {
            "index": 74,
            "registry": "HX512B01",
            "family": "authorization_policy",
            "role": SUITE.ROLE_AUTH_POLICY.hex(),
            "fields": [
                "mux(mode==init,next_policy_master64,current_policy_master64)",
                "selected_accumulator.threshold:u64be",
                "selected_accumulator.signer_count:u64be",
                "witness.authorization.signer_tags[0..6]:512",
            ],
            "message_bytes": 499,
            "output": "derived.authorization.policy:512",
        }
    )
    arm_map = {
        "single_key": ["dummy", "dummy"],
        "accumulator_init": ["next_accumulator", "dummy"],
        "approval_step": ["current_accumulator", "next_accumulator"],
        "value_lock_creation": ["current_value_lock", "dummy"],
        "final_threshold_spend": ["current_accumulator", "current_value_lock"],
    }
    for lane, role in enumerate(AUTH_ROLES):
        for slot in range(2):
            calls.append(
                {
                    "index": (75 if lane == 0 else 77) + slot,
                    "registry": "HX512B01",
                    "family": "authorization_mux",
                    "role": role.hex(),
                    "fields": {
                        mode: arms[slot]
                        for mode, arms in arm_map.items()
                    },
                    "master_mapping": "current arms use current master; next arms use next master; dummy has no master",
                    "message_bytes_by_arm": {
                        "dummy": 136,
                        "accumulator": 263,
                        "value_lock": 225,
                    },
                    "fixed_compressions": 3,
                    "counter_slots": 3,
                    "final_flag_slots": 3,
                    "two_block_arm_control": {
                        "counters": "[128,message_len,message_len]",
                        "final_flags": [False, True, False],
                        "selected_digest_state_after_compression": 2,
                    },
                    "three_block_arm_control": {
                        "counters": "[128,256,message_len]",
                        "final_flags": [False, False, True],
                        "selected_digest_state_after_compression": 3,
                    },
                    "output": f"derived.authorization[{slot}].lane[{lane}]:512",
                }
            )
    calls.extend(
        [
            {
                "index": 79,
                "registry": "HX512B01",
                "family": "intent",
                "role": SUITE.ROLE_INTENT.hex(),
                "fields": ["statement[0:14] || statement[206:1141]"],
                "message_bytes": 968,
                "output": "derived.intent:512",
            },
            {
                "index": 80,
                "registry": "HX512B01",
                "family": "balance_tag",
                "role": SUITE.ROLE_BALANCE.hex(),
                "fields": [
                    "statement.fee:u64be",
                    "statement.value_sign:u8",
                    "statement.value_magnitude:u64be",
                    "statement.assets[4]:u64be",
                    "statement.stable_enabled:u8",
                    "statement.stable_asset:u64be",
                    "statement.stable_sign:u8",
                    "statement.stable_magnitude:u64be",
                ],
                "message_bytes": 100,
                "output": "derived.balance_tag:512",
            },
        ]
    )
    for index in range(2):
        calls.append(
            {
                "index": 81 + index,
                "registry": "HX512B01",
                "family": "ciphertext_hash",
                "role": SUITE.ROLE_CIPHERTEXT.hex(),
                "fields": [
                    "constant proof_profile:u8=0x52",
                    "constant domain_set:u16be=0x5127",
                    f"constant output_slot:u8={index}",
                    "constant ciphertext_length:u32be=2147",
                    f"witness.ciphertext[{index}][2147]",
                ],
                "message_bytes": 2182,
                "output": f"derived.ciphertext_hash[{index}]:512",
            }
        )
    authority = [
        (83, "stablecoin_policy_constructor", "HGMAIDV2 role01", ["selected_manifest_row.policy_tuple61"], 61),
        (84, "manifest_leaf", "HGMAROOT role02", ["present:u8 || selected_manifest_row215"], 216),
    ]
    for level in range(4):
        authority.append(
            (
                85 + level,
                f"manifest_node[{level}]",
                f"HGMAROOT role03 level{level}",
                [f"index_bit[{level}] left/right select of current64 and sibling[{level}]64"],
                128,
            )
        )
    authority.append(
        (89, "state_snapshot", "HGMAROOT role04", ["statement.state_height:u64le", "recomputed_manifest_root64"], 72)
    )
    for index, family, role, fields, width in authority:
        calls.append(
            {
                "index": index,
                "registry": "HGMAIDV2/HGMAROOT",
                "family": family,
                "role": role,
                "fields": fields,
                "message_bytes": width,
                "output": f"derived.authority[{index - 83}]:512",
            }
        )
    calls.sort(key=lambda item: item["index"])
    if [item["index"] for item in calls] != list(range(90)):
        raise AssertionError("hash source IR index coverage")
    fixed_profiles = {item["name"]: item for item in PROFILE.parameter_profiles()}
    for item, fixed in zip(calls, PROFILE.hash_call_profiles(), strict=True):
        if item["index"] != fixed["index"]:
            raise AssertionError("hash source IR/profile index drift")
        parameter = fixed_profiles[fixed["parameter_profile"]]
        item["parameter_profile"] = fixed["parameter_profile"]
        item["personalization_hex"] = parameter["personalization_hex"]
        item["parameter_block_hex"] = parameter["parameter_block_hex"]
        item["constant_folded_initial_state_u64le_hex"] = parameter[
            "constant_folded_initial_state_u64le_hex"
        ]
        item["fixed_compressions"] = fixed["fixed_compressions"]
    return tuple(calls)


@functools.lru_cache(maxsize=1)
def executable_ir_certificate() -> dict[str, Any]:
    fixtures = all_accepted_fixtures()
    stable_fixtures = all_stablecoin_accepted_fixtures()
    evaluations = [evaluate(item.statement, item.context, item.witness) for item in (*fixtures, *stable_fixtures)]
    check_schemas: dict[str, dict[str, Any]] = {}
    for evaluation in evaluations:
        for item in evaluation.checks:
            encoded = dataclasses.asdict(item)
            prior = check_schemas.setdefault(item.constraint_id, encoded)
            if prior != encoded:
                raise AssertionError(f"constraint schema collision: {item.constraint_id}")
    source_ir = hash_call_source_ir()
    variable_ranges = {
        "constant_one": {"first_id": 0, "count": 1},
        "statement_bits_lsb0": {"first_id": 1, "count": STATEMENT_BYTES * 8},
        "verifier_context_bits_lsb0": {"first_id": 1 + STATEMENT_BYTES * 8, "count": CONTEXT_BYTES * 8},
        "private_witness_bits_lsb0": {"first_id": 1 + (STATEMENT_BYTES + CONTEXT_BYTES) * 8, "count": PRIVATE_BYTES * 8},
        "hash_output_bits_by_call_then_lsb0": {"first_id": 1 + (STATEMENT_BYTES + CONTEXT_BYTES + PRIVATE_BYTES) * 8, "count": 90 * 512},
    }
    payload = {
        "schema": "hegemon.hx512b01.executable-symbolic-ir.v1",
        "diagnostic_relation_rules_hash_sha512": PROFILE.DIAGNOSTIC_RULES_HASH.hex(),
        "variable_ranges": variable_ranges,
        "checks": [check_schemas[key] for key in sorted(check_schemas)],
        "hash_calls": list(source_ir),
        "accepted_fixtures": [
            {
                "mode": item.mode,
                "mask": item.mask,
                "stable_enabled": item.stable_enabled,
                "trace_digest_shake256_512": item.evaluation_trace_digest_shake256_512,
            }
            for item in (*fixtures, *stable_fixtures)
        ],
    }
    return {
        **payload,
        "transport_variable_id_rule": "first_id + byte_offset*8 + bit_index_lsb0",
        "hash_output_variable_id_rule": "hash_output_first_id + call_index*512 + digest_bit_lsb0",
        "semantic_source_operands_named": True,
        "numeric_r1cs_operand_ids_assigned": False,
        "intermediate_r1cs_variables_allocated": False,
        "executable_evaluator": True,
        "reference_witness_builder": True,
        "interpreter_scope": "current incomplete diagnostic grammar",
        "exact_full_production_relation": False,
        "known_accepted_production_counterexamples": True,
        "stablecoin_issuer_or_collateral_capability_enforced": False,
        "stablecoin_minimum_collateral_ratio_evaluated": False,
        "stablecoin_epoch_cap_cumulative_and_atomic": False,
        "no_input_anchor_canonical_or_authenticated": False,
        "activity_mask_mode_grammar_matches_active_native_route": False,
        "live_route_value_balance_zero_enforced": False,
        "all_33_accepted_mask_mode_pairs_evaluated": True,
        "all_33_stablecoin_enabled_mask_mode_pairs_evaluated": True,
        "activity_stablecoin_matrix": activity_stablecoin_matrix_certificate(),
        "policy_version_zero_evaluated": True,
        "physical_hash_calls": 90,
        "fixed_blake2b512_compressions": 213,
        "expanded_boolean_hash_trace_variables_allocated": False,
        "sparse_r1cs_rows_emitted": False,
        "r1cs_lowering_refined": False,
        "symbolic_ir_digest_shake256_512": digest_json(
            b"hegemon.hx512b01.executable-symbolic-ir.v1\0", payload
        ),
    }


@functools.lru_cache(maxsize=1)
def mutation_residuals() -> tuple[dict[str, str], ...]:
    """Execute representative counterfeits across every semantic family."""

    stable = build_fixture(0, 0b1111, stable_enabled=True, policy_version=0)
    cases: list[tuple[str, bytes, bytes, bytes]] = []

    def add(name: str, fixture: Fixture, target: str, offset: int, mask: int = 1) -> None:
        statement, context, witness = fixture.statement, fixture.context, fixture.witness
        values = {"statement": statement, "context": context, "witness": witness}
        changed = bytearray(values[target])
        changed[offset] ^= mask
        values[target] = bytes(changed)
        cases.append((name, values["statement"], values["context"], values["witness"]))

    for name, target, offset in (
        ("statement_anchor", "statement", 14),
        ("statement_nullifier", "statement", 78),
        ("statement_commitment", "statement", 206),
        ("statement_ciphertext_hash", "statement", 334),
        ("statement_fee", "statement", 509),
        ("statement_value_balance", "statement", 518),
        ("statement_stable_sign", "statement", 532),
        ("statement_balance_tag", "statement", 869),
        ("statement_activity_flag", "statement", 10),
        ("statement_rules_hash", "statement", 1077),
        ("input_spend_master", "witness", 0),
        ("input_note_kind", "witness", 64),
        ("input_note_value", "witness", 79),
        ("input_note_asset", "witness", 87),
        ("input_note_recipient", "witness", 88),
        ("input_note_rho", "witness", 120),
        ("input_note_blinding", "witness", 168),
        ("input_note_authorization", "witness", 232),
        ("input_position", "witness", 303),
        ("input_merkle_sibling", "witness", 304),
        ("input_balance_selector", "witness", 2359),
        ("second_input_payload", "witness", 2384),
        ("output_note", "witness", 4768),
        ("output_balance_selector", "witness", 5007),
        ("authorization_auxiliary", "witness", 5304),
        ("policy_master", "witness", 6088),
        ("ciphertext_byte", "witness", 6216),
        ("manifest_row", "witness", MANIFEST_OFFSET + 4),
        ("manifest_path", "witness", MANIFEST_OFFSET + 4 + 215),
        ("verifier_manifest_root", "context", 0),
        ("verifier_height", "context", 64),
    ):
        add(name, stable, target, offset)

    mode_cases = {
        "init_current_master": (build_fixture(1, 0b0101), 6088),
        "approval_master_continuity": (build_fixture(2, 0b0111), 6152),
        "approval_metadata": (build_fixture(2, 0b0111), 5504 + 151),
        "approval_signer_membership": (build_fixture(2, 0b0111), 5704),
        "lock_next_master": (build_fixture(3, 0b0101), 6152),
        "final_intent": (build_fixture(4, 0b0011), 5368),
        "final_threshold": (build_fixture(4, 0b0011), 5439),
    }
    for name, (fixture, offset) in mode_cases.items():
        add(name, fixture, "witness", offset)

    residuals = []
    for name, statement, context, witness in cases:
        try:
            evaluate(statement, context, witness)
        except RelationFailure as error:
            residuals.append(
                {
                    "name": name,
                    "observed": "reject",
                    "constraint_id": error.constraint_id,
                    "family": error.family,
                }
            )
        else:
            raise AssertionError(f"mutation unexpectedly accepted: {name}")
    return tuple(residuals)
