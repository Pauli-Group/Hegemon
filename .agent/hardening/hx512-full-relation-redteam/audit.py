#!/usr/bin/env python3
"""Dependency-free red team for the inactive HX512 macro-count compiler.

This checker deliberately does not trust the compiler's retained totals.  It
replays every recorded macro invocation with an independent primitive-cost
table, exercises the host reference predicate byte by byte, and keeps small
counterexamples showing why the odd-field ledger is not a binary relation.
It never constructs a proof, an expanded matrix, or a production artifact.
"""

from __future__ import annotations

import argparse
import dataclasses
import functools
import hashlib
import importlib.util
import json
import sys
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any, Iterable, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPILER_PATH = ROOT / ".agent/hardening/hx512-full-relation-compile/compiler.py"
REPORT_PATH = HERE / "audit_report.json"
CORPUS_PATH = HERE / "counterfeit_corpus.json"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


C = _load("hegemon_hx512_full_relation_redteam_target", COMPILER_PATH)


@functools.lru_cache(maxsize=1)
def _positive_executable_fixtures() -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Build each accepted semantic case once for the whole audit process."""

    return (
        C.EXECUTABLE.all_accepted_fixtures(),
        C.EXECUTABLE.all_stablecoin_accepted_fixtures(),
    )


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def sha512_file(path: Path) -> str:
    return hashlib.sha512(path.read_bytes()).hexdigest()


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


# This is intentionally independent of BASE.PRIMITIVES.  A drift in the
# frozen library must show up as a mismatch rather than silently changing the
# red-team recount.
PRIMITIVES: dict[str, tuple[int, int, int]] = {
    "bitness": (1, 0, 3),
    "and": (1, 1, 3),
    "xor": (1, 1, 5),
    "or": (1, 1, 5),
    "and_not": (1, 1, 4),
    "not": (1, 1, 4),
    "select": (1, 1, 5),
    "eq": (1, 0, 3),
    "eq_zero": (1, 0, 2),
    "eq_one": (1, 0, 3),
    "cond_zero": (1, 0, 2),
    "cond_eq": (1, 0, 3),
    "implies": (1, 0, 3),
    "add_lsb": (1, 0, 5),
    "add_carry": (1, 0, 6),
    "linear_5_to_1": (1, 1, 7),
    "cond_linear_4": (1, 0, 6),
    "linear_sum_5": (1, 0, 7),
    "cond_sum_4": (1, 0, 6),
}


def _add(counter: Counter[str], name: str, count: int) -> None:
    if count < 0:
        raise AssertionError((name, count))
    counter[name] += count


def expand_macro(
    macro: str, count: int, width: int | None
) -> tuple[Counter[str], int]:
    """Return primitive multiplicities and non-primitive auxiliary wires."""

    p: Counter[str] = Counter()
    k = width or 1
    extra_auxiliary = 0
    direct = {
        "bitness": "bitness",
        "eq": "eq",
        "eq_zero": "eq_zero",
        "eq_one": "eq_one",
        "cond_zero": "cond_zero",
        "cond_eq": "cond_eq",
        "and": "and",
        "xor": "xor",
        "or": "or",
        "not": "not",
        "select": "select",
        "implies": "implies",
    }
    if macro in direct:
        _add(p, direct[macro], count * k)
    elif macro == "is_equal":
        _add(p, "xor", count * k)
        _add(p, "or", count * max(0, k - 1))
        _add(p, "not", count)
    elif macro == "is_zero":
        _add(p, "or", count * max(0, k - 1))
        _add(p, "not", count)
    elif macro == "nonzero":
        _add(p, "or", count * max(0, k - 1))
    elif macro == "lt":
        for name in ("xor", "and_not", "not", "and", "or"):
            _add(p, name, count * k)
    elif macro == "le":
        for name in ("xor", "and_not", "not", "and", "or"):
            _add(p, name, count * k)
        _add(p, "not", count)
    elif macro in ("add", "add64"):
        add_width = 64 if macro == "add64" else (width or 64)
        _add(p, "bitness", count * 2 * add_width)
        _add(p, "add_lsb", count)
        _add(p, "add_carry", count * max(0, add_width - 1))
        # The count compiler creates sum and carry wires outside primitive().
        extra_auxiliary = count * 2 * add_width
    elif macro == "digest_nonzero_cond":
        _add(p, "or", count * max(0, k - 1))
        _add(p, "implies", count)
    elif macro == "digest_unequal_cond":
        digest_width = width or C.BASE.DIGEST_BITS
        _add(p, "xor", count * digest_width)
        _add(p, "or", count * max(0, digest_width - 1))
        _add(p, "implies", count)
    elif macro == "onehot_select5":
        _add(p, "and", count * k * 5)
        _add(p, "linear_5_to_1", count * k)
    elif macro == "selected_asset4":
        asset_width = width or 64
        _add(p, "and", count * asset_width * 4)
        _add(p, "cond_linear_4", count * asset_width)
    elif macro == "cond_sum4":
        _add(p, "cond_sum_4", count)
    elif macro == "mode_onehot5":
        _add(p, "linear_sum_5", count)
    elif macro == "keccak_f1600":
        _add(p, "xor", count * 115_200)
        _add(p, "and_not", count * 38_400)
        _add(p, "not", count * C.BASE.KECCAK_IOTA_ONES)
    elif macro == "alias":
        pass
    else:
        raise AssertionError(f"unreviewed macro {macro!r}")
    return p, extra_auxiliary


def compile_without_pin_gate() -> Any:
    """Emit the current ledger even while another worker refreshes source pins."""

    C._configure_base()
    program = C.BASE.Program("hx512b01-blake2b512-all-w64-redteam")
    C.emit_shared_transaction(program)
    C.emit_authority_relation(program)
    C.emit_blake2b512(program)
    return program


def recount(program: Any) -> dict[str, Any]:
    independent_groups = []
    total_primitives: Counter[str] = Counter()
    total_rows = total_primitive_aux = total_extra_aux = total_nnz = 0
    operand_keys = {
        "inputs",
        "input_variables",
        "operands",
        "outputs",
        "output_variables",
        "source_bits",
        "source_indices",
        "target",
        "targets",
        "variables",
        "wire_ids",
    }
    invocation_count = 0
    invocations_with_operands = 0
    for group in program.export_groups():
        primitives: Counter[str] = Counter()
        extra_aux = 0
        for invocation in group["invocations"]:
            invocation_count += 1
            if operand_keys.intersection(invocation):
                invocations_with_operands += 1
            expanded, added_aux = expand_macro(
                invocation["macro"],
                invocation["multiplicity"],
                invocation.get("width_bits"),
            )
            primitives.update(expanded)
            extra_aux += added_aux
        rows = sum(PRIMITIVES[name][0] * value for name, value in primitives.items())
        primitive_aux = sum(
            PRIMITIVES[name][1] * value for name, value in primitives.items()
        )
        nnz = sum(PRIMITIVES[name][2] * value for name, value in primitives.items())
        observed = {
            "rows": group["rows"],
            "auxiliary_variables": group["auxiliary_variables"],
            "nonzeros": group["nonzeros"],
        }
        expected = {
            "rows": rows,
            "auxiliary_variables": primitive_aux + extra_aux,
            "nonzeros": nnz,
        }
        independent_groups.append(
            {
                "name": group["name"],
                "expected": expected,
                "reported": observed,
                "match": expected == observed,
            }
        )
        total_primitives.update(primitives)
        total_rows += rows
        total_primitive_aux += primitive_aux
        total_extra_aux += extra_aux
        total_nnz += nnz
    expected_geometry = {
        "m_constraints": total_rows,
        "n_nonconstant_variables": (
            C.PUBLIC_BITS
            + C.PRIVATE_BITS
            + total_primitive_aux
            + total_extra_aux
        ),
        "l_public_variables": C.PUBLIC_BITS,
        "auxiliary_variables_total": (
            C.PRIVATE_BITS + total_primitive_aux + total_extra_aux
        ),
        "private_transport_variables": C.PRIVATE_BITS,
        "derived_auxiliary_variables": total_primitive_aux + total_extra_aux,
        "matrix_nonzeros_total": total_nnz,
        "z_vector_length_including_constant_one": (
            C.PUBLIC_BITS
            + C.PRIVATE_BITS
            + total_primitive_aux
            + total_extra_aux
            + 1
        ),
    }
    observed_geometry = program.geometry()
    return {
        "arithmetic_ledger_reconciles": (
            all(item["match"] for item in independent_groups)
            and expected_geometry == observed_geometry
            and dict(sorted(total_primitives.items()))
            == dict(sorted(program.primitives.items()))
        ),
        "claim_boundary": (
            "This independently reconciles template multiplicities only. It does "
            "not establish an R1CS because no invocation identifies operands."
        ),
        "groups": independent_groups,
        "group_rows_no_padding": {
            item["name"]: item["expected"]["rows"]
            for item in independent_groups
        },
        "primitive_multiplicities": dict(sorted(total_primitives.items())),
        "expected_geometry": expected_geometry,
        "reported_geometry": observed_geometry,
        "invocations": invocation_count,
        "invocations_with_operand_or_wire_identity": invocations_with_operands,
        "sparse_rows_retained": False,
        "witness_constructor_retained": False,
        "row_evaluator_retained": False,
    }


def _accepts(statement: bytes, context: bytes, witness: bytes) -> tuple[bool, str]:
    try:
        C.verify_reference(statement, context, witness)
    except Exception as error:
        return False, f"{type(error).__name__}: {error}"
    return True, "accepted"


def _mutate(raw: bytes, offset: int, mask: int = 1) -> bytes:
    changed = bytearray(raw)
    changed[offset] ^= mask
    return bytes(changed)


def _segments(values: Sequence[bool]) -> list[dict[str, Any]]:
    if not values:
        return []
    result = []
    start = 0
    state = values[0]
    for index, value in enumerate(values[1:], 1):
        if value == state:
            continue
        result.append(
            {"start": start, "end_exclusive": index, "accepted": state}
        )
        start, state = index, value
    result.append(
        {"start": start, "end_exclusive": len(values), "accepted": state}
    )
    return result


def _partition_scan(
    accepted: Sequence[bool], partitions: Iterable[tuple[str, int, int]]
) -> list[dict[str, Any]]:
    result = []
    for name, offset, width in partitions:
        region = accepted[offset : offset + width]
        result.append(
            {
                "name": name,
                "offset": offset,
                "bytes": width,
                "accepted_xor01": sum(region),
                "rejected_xor01": width - sum(region),
                "coverage_complete": len(region) == width,
            }
        )
    return result


def byte_mutation_scan() -> dict[str, Any]:
    statement, context, witness = C.sample_valid_case()
    statement_results = [
        _accepts(_mutate(statement, offset), context, witness)[0]
        for offset in range(len(statement))
    ]
    context_results = [
        _accepts(statement, _mutate(context, offset), witness)[0]
        for offset in range(len(context))
    ]
    witness_results = [
        _accepts(statement, context, _mutate(witness, offset))[0]
        for offset in range(len(witness))
    ]
    statement_layout = [
        (item["name"], item["offset"], item["bytes"])
        for item in C.SUITE.statement_layout()
    ]
    context_layout = (("manifest_root", 0, 64), ("parent_height_u64le", 64, 8))
    return {
        "mutation": "xor byte with 0x01",
        "baseline_accepted": _accepts(statement, context, witness)[0],
        "evaluations": len(statement) + len(context) + len(witness),
        "statement": {
            "bytes": len(statement),
            "accepted": sum(statement_results),
            "rejected": len(statement) - sum(statement_results),
            "segments": _segments(statement_results),
            "fields": _partition_scan(statement_results, statement_layout),
        },
        "verifier_context": {
            "bytes": len(context),
            "accepted": sum(context_results),
            "rejected": len(context) - sum(context_results),
            "segments": _segments(context_results),
            "fields": _partition_scan(context_results, context_layout),
        },
        "private_witness": {
            "bytes": len(witness),
            "accepted": sum(witness_results),
            "rejected": len(witness) - sum(witness_results),
            "segments": _segments(witness_results),
            "sections": _partition_scan(witness_results, C.WITNESS_SECTIONS),
        },
        "coverage_complete": (
            len(statement_results) == C.STATEMENT_BYTES
            and len(context_results) == C.CONTEXT_BYTES
            and len(witness_results) == C.PRIVATE_BYTES
        ),
    }


def _exec_accepts(
    statement: bytes, context: bytes, witness: bytes
) -> tuple[bool, str, str | None]:
    try:
        C.EXECUTABLE.evaluate(statement, context, witness)
    except C.EXECUTABLE.RelationFailure as error:
        return False, str(error), error.constraint_id
    except Exception as error:
        return False, f"{type(error).__name__}: {error}", None
    return True, "accepted", None


CORE_ROLES = {
    "note": b"nt.b5121",
    "nullifier": b"nf.b5121",
    "merkle": b"mk.b5121",
    "spend_a": b"sk.b51a1",
    "spend_b": b"sk.b51b1",
    "policy": b"pl.b5121",
    "auth_a": b"au.b51a1",
    "auth_b": b"au.b51b1",
    "intent": b"in.b5121",
    "balance": b"bl.b5121",
    "ciphertext": b"ct.b5121",
}
LANE_TAGS = (b"lane.A51", b"lane.B51")


def _independent_frame(role: bytes, fields: Sequence[bytes]) -> bytes:
    if len(role) != 8 or len(fields) > 255:
        raise AssertionError("independent frame grammar")
    result = bytearray(b"HX512B01" + role + bytes([len(fields)]))
    for field in fields:
        if type(field) is not bytes or len(field) > 65535:
            raise AssertionError("independent frame field")
        result += len(field).to_bytes(2, "big") + field
    return bytes(result)


def _expected_hash_call(
    index: int,
    family: str,
    message: bytes,
    *,
    role: bytes | None = None,
    personalization: bytes | None = None,
    fixed_compressions: int | None = None,
) -> dict[str, Any]:
    actual = max(1, (len(message) + 127) // 128)
    fixed = actual if fixed_compressions is None else fixed_compressions
    if fixed < actual:
        raise AssertionError((index, actual, fixed))
    counters = tuple(
        min((block + 1) * 128, len(message)) if block < actual else len(message)
        for block in range(fixed)
    )
    final_flags = tuple(block + 1 == actual for block in range(fixed))
    digest = hashlib.blake2b(
        message,
        digest_size=64,
        **({"person": personalization} if personalization is not None else {}),
    ).hexdigest()
    return {
        "index": index,
        "family": family,
        "message": message,
        "message_bytes": len(message),
        "message_sha512": hashlib.sha512(message).hexdigest(),
        "digest_hex": digest,
        "rfc7693_compressions": actual,
        "fixed_compressions": fixed,
        "counters": counters,
        "final_flags": final_flags,
        "selected_digest_state_after_compression": actual,
        "role_hex": (
            personalization[8:9].hex()
            if personalization is not None
            else (role or b"").hex()
        ),
        "personalization_hex": (
            personalization.hex() if personalization is not None else None
        ),
    }


def _independent_hash_calls(fixture: Any) -> tuple[dict[str, Any], ...]:
    """Reconstruct all 90 messages without using the target frame helpers."""

    E = C.EXECUTABLE
    statement = E.Statement.decode(fixture.statement)
    witness = E.Witness.decode(fixture.witness, statement.stable_enabled)
    calls: dict[int, dict[str, Any]] = {}

    def add(
        index: int,
        family: str,
        message: bytes,
        *,
        role: bytes | None = None,
        personalization: bytes | None = None,
        fixed: int | None = None,
    ) -> bytes:
        call = _expected_hash_call(
            index,
            family,
            message,
            role=role,
            personalization=personalization,
            fixed_compressions=fixed,
        )
        calls[index] = call
        return bytes.fromhex(call["digest_hex"])

    notes = (
        witness.inputs[0].note,
        witness.inputs[1].note,
        witness.outputs[0].note,
        witness.outputs[1].note,
    )
    note_digests: list[bytes] = []
    for index, note in enumerate(notes):
        if not 0 <= note.kind < 256:
            raise AssertionError("accepted note kind does not fit u8")
        message = _independent_frame(
            CORE_ROLES["note"],
            [
                note.blinding,
                bytes([note.kind]),
                note.value.to_bytes(8, "big"),
                note.asset.to_bytes(8, "big"),
                note.recipient,
                note.rho,
                note.authorization,
            ],
        )
        note_digests.append(
            add(index, f"note_commitment[{index}]", message, role=CORE_ROLES["note"])
        )

    spend: list[tuple[bytes, bytes]] = []
    for input_index, input_value in enumerate(witness.inputs):
        lanes = []
        for lane in range(2):
            role = CORE_ROLES[("spend_a", "spend_b")[lane]]
            message = _independent_frame(
                role, [LANE_TAGS[lane], input_value.spend_master]
            )
            call_index = 70 + input_index if lane == 0 else 72 + input_index
            lanes.append(
                add(
                    call_index,
                    f"spend_key[{input_index}].lane[{lane}]",
                    message,
                    role=role,
                )
            )
        spend.append((lanes[0], lanes[1]))

    auth = witness.authorization
    selected = auth.next if auth.mode == 1 else auth.current
    selected_master = auth.policy_masters[1] if auth.mode == 1 else auth.policy_masters[0]
    policy_message = _independent_frame(
        CORE_ROLES["policy"],
        [
            selected_master,
            selected.threshold.to_bytes(8, "big"),
            selected.signer_count.to_bytes(8, "big"),
            *auth.signer_tags,
        ],
    )
    policy_digest = add(
        74, "authorization_policy", policy_message, role=CORE_ROLES["policy"]
    )

    def accumulator_message(master: bytes, lane: int, opening: Any) -> bytes:
        return _independent_frame(
            CORE_ROLES[("auth_a", "auth_b")[lane]],
            [
                master,
                LANE_TAGS[lane],
                opening.policy_root,
                opening.intent,
                opening.threshold.to_bytes(8, "big"),
                opening.signer_count.to_bytes(8, "big"),
                opening.approval_count.to_bytes(8, "big"),
                bytes(int(value) for value in opening.approved),
            ],
        )

    def value_lock_message(master: bytes, lane: int, opening: Any) -> bytes:
        return _independent_frame(
            CORE_ROLES[("auth_a", "auth_b")[lane]],
            [master, LANE_TAGS[lane], opening.policy_root, opening.intent],
        )

    def dummy_message(lane: int, slot: int) -> bytes:
        payload = bytearray(117)
        payload[0] = slot
        payload[1] = lane
        return _independent_frame(
            CORE_ROLES[("auth_a", "auth_b")[lane]], [bytes(payload)]
        )

    auth_digests_mut: list[list[bytes]] = [[bytes(64), bytes(64)] for _ in range(2)]
    for lane in range(2):
        for slot in range(2):
            if auth.mode == 0:
                message = dummy_message(lane, slot)
            elif slot == 0 and auth.mode == 1:
                message = accumulator_message(auth.policy_masters[1], lane, auth.next)
            elif slot == 0 and auth.mode in (2, 4):
                message = accumulator_message(auth.policy_masters[0], lane, auth.current)
            elif slot == 0 and auth.mode == 3:
                message = value_lock_message(auth.policy_masters[0], lane, auth.current)
            elif slot == 1 and auth.mode == 2:
                message = accumulator_message(auth.policy_masters[1], lane, auth.next)
            elif slot == 1 and auth.mode == 4:
                message = value_lock_message(auth.policy_masters[0], lane, auth.current)
            else:
                message = dummy_message(lane, slot)
            role = CORE_ROLES[("auth_a", "auth_b")[lane]]
            call_index = (75 if lane == 0 else 77) + slot
            auth_digests_mut[slot][lane] = add(
                call_index,
                f"authorization[{slot}].lane[{lane}]",
                message,
                role=role,
                fixed=3,
            )
    auth_digests = (
        (auth_digests_mut[0][0], auth_digests_mut[0][1]),
        (auth_digests_mut[1][0], auth_digests_mut[1][1]),
    )
    if auth.mode in (0, 1, 3):
        resolved_nullifiers = (spend[0][1], spend[1][1])
    elif auth.mode == 2:
        resolved_nullifiers = (auth_digests[0][1], spend[1][1])
    else:
        resolved_nullifiers = (auth_digests[1][1], auth_digests[0][1])

    for input_index, input_value in enumerate(witness.inputs):
        nullifier_message = _independent_frame(
            CORE_ROLES["nullifier"],
            [
                resolved_nullifiers[input_index],
                input_value.position.to_bytes(8, "big"),
                input_value.note.rho,
            ],
        )
        add(
            4 + input_index,
            f"nullifier[{input_index}]",
            nullifier_message,
            role=CORE_ROLES["nullifier"],
        )
        current = note_digests[input_index]
        for level, sibling in enumerate(input_value.siblings):
            left, right = (
                (sibling, current)
                if (input_value.position >> level) & 1
                else (current, sibling)
            )
            message = _independent_frame(CORE_ROLES["merkle"], [left, right])
            current = add(
                6 + input_index * 32 + level,
                f"merkle[{input_index}][{level}]",
                message,
                role=CORE_ROLES["merkle"],
            )

    intent_message = _independent_frame(
        CORE_ROLES["intent"],
        [statement.raw[:14] + statement.raw[206:]],
    )
    add(79, "intent", intent_message, role=CORE_ROLES["intent"])
    balance_message = _independent_frame(
        CORE_ROLES["balance"],
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
    add(80, "balance_tag", balance_message, role=CORE_ROLES["balance"])
    for output_index, output in enumerate(witness.outputs):
        message = _independent_frame(
            CORE_ROLES["ciphertext"],
            [
                b"\x52",
                (0x5127).to_bytes(2, "big"),
                bytes([output_index]),
                C.CANONICAL_CIPHERTEXT_BYTES.to_bytes(4, "big"),
                output.ciphertext,
            ],
        )
        add(
            81 + output_index,
            f"ciphertext_hash[{output_index}]",
            message,
            role=CORE_ROLES["ciphertext"],
        )

    if statement.stable_enabled:
        if witness.manifest is None:
            raise AssertionError("stable fixture has no manifest")
        entry = witness.manifest.entry
        index = witness.manifest.index
        siblings = witness.manifest.siblings
        policy_raw = (
            entry.asset_id.to_bytes(4, "little")
            + entry.oracle_feed.to_bytes(4, "little")
            + entry.attestation_id.to_bytes(8, "little")
            + entry.min_collateral_ratio_ppm.to_bytes(16, "little")
            + entry.max_mint_per_epoch.to_bytes(16, "little")
            + entry.oracle_max_age.to_bytes(8, "little")
            + entry.policy_version.to_bytes(4, "little")
            + bytes([int(entry.active)])
        )
        leaf_raw = b"\x01" + entry.encode()
        height = statement.state_height
    else:
        index = 0
        siblings = (bytes(64),) * 4
        policy_raw = bytes(61)
        leaf_raw = bytes(216)
        height = 0
    policy_person = b"HGMAIDV2" + bytes([1, 2, 64]) + bytes(5)
    add(
        83,
        "stablecoin_policy_constructor",
        policy_raw,
        personalization=policy_person,
    )
    leaf_person = b"HGMAROOT" + bytes([2, 2, 64, 4, 0, 0, 0, 0])
    current = add(84, "manifest_leaf", leaf_raw, personalization=leaf_person)
    cursor = index
    for level, sibling in enumerate(siblings):
        left, right = (sibling, current) if cursor & 1 else (current, sibling)
        person = b"HGMAROOT" + bytes([3, 2, 64, 4, level, 0, 0, 0])
        current = add(
            85 + level,
            f"manifest_node[{level}]",
            left + right,
            personalization=person,
        )
        cursor >>= 1
    snapshot_person = b"HGMAROOT" + bytes([4, 2, 64, 4, 0, 0, 0, 0])
    add(
        89,
        "state_snapshot",
        height.to_bytes(8, "little") + current,
        personalization=snapshot_person,
    )
    if sorted(calls) != list(range(90)):
        raise AssertionError("independent hash index coverage")
    if policy_digest != bytes.fromhex(calls[74]["digest_hex"]):
        raise AssertionError("policy digest construction")
    return tuple(calls[index] for index in range(90))


@functools.lru_cache(maxsize=1)
def executable_semantics_audit() -> dict[str, Any]:
    disabled, stable = _positive_executable_fixtures()
    pairs_disabled = {(item.mode, item.mask) for item in disabled}
    pairs_stable = {(item.mode, item.mask) for item in stable}
    expected_pairs = {
        (mode, mask)
        for mode in range(5)
        for mask in range(16)
        if C.EXECUTABLE.activity_shape_accepts(
            mode, tuple(bool(mask & (1 << bit)) for bit in range(4))
        )
    }
    comparisons = 0
    all_calls_match = True
    all_controls_match = True
    all_evaluations_accept = True
    check_ids: set[str] = set()
    trace_rows = []
    for fixture in (*disabled, *stable):
        try:
            evaluation = C.EXECUTABLE.evaluate(
                fixture.statement, fixture.context, fixture.witness
            )
        except Exception:
            all_evaluations_accept = False
            continue
        expected_calls = _independent_hash_calls(fixture)
        if len(evaluation.hash_calls) != 90:
            all_calls_match = False
        for expected, observed in zip(expected_calls, evaluation.hash_calls):
            comparisons += 1
            for key in (
                "index",
                "family",
                "role_hex",
                "message_bytes",
                "message_sha512",
                "digest_hex",
                "rfc7693_compressions",
                "fixed_compressions",
                "counters",
                "final_flags",
                "selected_digest_state_after_compression",
                "personalization_hex",
            ):
                if getattr(observed, key) != expected[key]:
                    all_calls_match = False
            if len(observed.counters) != observed.fixed_compressions or len(
                observed.final_flags
            ) != observed.fixed_compressions:
                all_controls_match = False
        check_ids.update(item.constraint_id for item in evaluation.checks)
        trace_rows.append(
            {
                "mode": fixture.mode,
                "mask": fixture.mask,
                "stable_enabled": fixture.stable_enabled,
                "checks": len(evaluation.checks),
                "hash_calls": len(evaluation.hash_calls),
                "compressions": sum(
                    item.fixed_compressions for item in evaluation.hash_calls
                ),
            }
        )
    source_ir = C.EXECUTABLE.hash_call_source_ir()
    source_ir_indices_exact = [item["index"] for item in source_ir] == list(range(90))
    auth_controls = [item for item in source_ir if item["index"] in range(75, 79)]
    source_ir_auth_controls_exact = all(
        item.get("counter_slots") == 3
        and item.get("final_flag_slots") == 3
        and item.get("fixed_compressions") == 3
        and item.get("two_block_arm_control")
        == {
            "counters": "[128,message_len,message_len]",
            "final_flags": [False, True, False],
            "selected_digest_state_after_compression": 2,
        }
        and item.get("three_block_arm_control")
        == {
            "counters": "[128,256,message_len]",
            "final_flags": [False, False, True],
            "selected_digest_state_after_compression": 3,
        }
        for item in auth_controls
    )
    residuals = list(C.EXECUTABLE.mutation_residuals())
    residual_by_name = {item["name"]: item for item in residuals}
    return {
        "positive_fixtures": {
            "disabled": len(disabled),
            "stablecoin_enabled_policy_version_zero": len(stable),
            "total": len(disabled) + len(stable),
            "all_accept": all_evaluations_accept,
            "disabled_pairs_exact": pairs_disabled == expected_pairs,
            "stable_pairs_exact": pairs_stable == expected_pairs,
        },
        "fixture_traces": trace_rows,
        "independent_hash_call_comparisons": comparisons,
        "all_90_message_bytes_digests_controls_and_personalizations_match": all_calls_match
        and all_controls_match,
        "physical_hash_calls_each": 90,
        "fixed_compressions_each": 213,
        "source_ir_indices_exact": source_ir_indices_exact,
        "source_ir_auth_two_and_three_block_controls_exact": source_ir_auth_controls_exact,
        "observed_constraint_ids": len(check_ids),
        "mutation_residuals": residuals,
        "all_retained_mutations_reject": bool(residuals)
        and all(item["observed"] == "reject" for item in residuals),
        "final_threshold_mutation": residual_by_name.get("final_threshold"),
        "semantic_interpreter_executable": True,
        "check_operands_are_symbolic_strings_not_variable_ids": True,
        "hash_source_fields_are_symbolic_strings_not_variable_ids": True,
        "intermediate_boolean_hash_variables_allocated": False,
        "sparse_r1cs_rows_emitted": False,
        "r1cs_row_evaluator_exists": False,
        "authority_lifecycle_is_host_function_call": True,
        "hash_compression_is_host_hashlib_call": True,
    }


@functools.lru_cache(maxsize=1)
def executable_byte_mutation_scan() -> dict[str, Any]:
    fixture = C.EXECUTABLE.build_fixture(
        0, 0b1111, stable_enabled=True, policy_version=0
    )
    statement, context, witness = fixture.statement, fixture.context, fixture.witness
    statement_results = [
        _exec_accepts(_mutate(statement, offset), context, witness)[0]
        for offset in range(len(statement))
    ]
    context_results = [
        _exec_accepts(statement, _mutate(context, offset), witness)[0]
        for offset in range(len(context))
    ]
    witness_results = [
        _exec_accepts(statement, context, _mutate(witness, offset))[0]
        for offset in range(len(witness))
    ]
    statement_layout = [
        (item["name"], item["offset"], item["bytes"])
        for item in C.SUITE.statement_layout()
    ]
    return {
        "fixture": {
            "mode": 0,
            "mask": 15,
            "stable_enabled": True,
            "policy_version": 0,
        },
        "mutation": "xor byte with 0x01",
        "baseline_accepted": _exec_accepts(statement, context, witness)[0],
        "evaluations": len(statement) + len(context) + len(witness),
        "statement": {
            "bytes": len(statement),
            "accepted": sum(statement_results),
            "rejected": len(statement) - sum(statement_results),
            "segments": _segments(statement_results),
            "fields": _partition_scan(statement_results, statement_layout),
        },
        "verifier_context": {
            "bytes": len(context),
            "accepted": sum(context_results),
            "rejected": len(context) - sum(context_results),
            "segments": _segments(context_results),
        },
        "private_witness": {
            "bytes": len(witness),
            "accepted": sum(witness_results),
            "rejected": len(witness) - sum(witness_results),
            "segments": _segments(witness_results),
            "sections": _partition_scan(witness_results, C.WITNESS_SECTIONS),
        },
        "coverage_complete": (
            len(statement_results) == C.STATEMENT_BYTES
            and len(context_results) == C.CONTEXT_BYTES
            and len(witness_results) == C.PRIVATE_BYTES
        ),
        "all_single_byte_xor01_mutations_rejected": not any(
            statement_results + context_results + witness_results
        ),
    }


def _case(
    name: str,
    family: str,
    component: str,
    offset: int,
    statement: bytes,
    context: bytes,
    witness: bytes,
    mask: int = 1,
) -> dict[str, Any]:
    mutated_statement, mutated_context, mutated_witness = statement, context, witness
    if component == "statement":
        mutated_statement = _mutate(statement, offset, mask)
    elif component == "context":
        mutated_context = _mutate(context, offset, mask)
    elif component == "witness":
        mutated_witness = _mutate(witness, offset, mask)
    else:
        raise AssertionError(component)
    accepted, reason = _accepts(
        mutated_statement, mutated_context, mutated_witness
    )
    return {
        "name": name,
        "semantic_family": family,
        "component": component,
        "offset": offset,
        "xor_mask": mask,
        "reference_accepted": accepted,
        "observed": reason,
        "relation_row_evaluated": False,
    }


def counterfeit_cases() -> list[dict[str, Any]]:
    statement, context, witness = C.sample_valid_case()
    descriptions = (
        ("public_anchor_byte", "Merkle anchor", "statement", 14),
        ("public_nullifier_byte", "nullifier", "statement", 78),
        ("public_commitment_byte", "output commitment", "statement", 206),
        ("public_fee_byte", "native balance", "statement", 509),
        (
            "public_value_balance_magnitude_byte",
            "signed value balance",
            "statement",
            518,
        ),
        (
            "public_stable_issuance_sign",
            "stablecoin signed balance",
            "statement",
            532,
        ),
        ("public_balance_tag_byte", "balance tag", "statement", 869),
        (
            "inactive_input_with_live_nullifier",
            "inactive input canonicality",
            "statement",
            10,
        ),
        ("private_input0_prefix", "input note/spend witness", "witness", 0),
        (
            "private_input0_merkle_region",
            "Merkle path",
            "witness",
            304,
        ),
        (
            "private_input1_prefix",
            "second input note/spend witness",
            "witness",
            298 * 8,
        ),
        (
            "private_output0_prefix",
            "output note witness",
            "witness",
            596 * 8,
        ),
        (
            "private_authorization_nonmode",
            "authorization transition",
            "witness",
            662 * 8 + 8,
        ),
        (
            "private_policy_master",
            "authorization policy master",
            "witness",
            761 * 8,
        ),
    )
    return [
        _case(name, family, component, offset, statement, context, witness)
        for name, family, component, offset in descriptions
    ]


@functools.lru_cache(maxsize=1)
def executable_counterfeit_cases() -> tuple[dict[str, Any], ...]:
    fixture = C.EXECUTABLE.build_fixture(
        0, 0b1111, stable_enabled=True, policy_version=0
    )
    descriptions = (
        ("public_anchor_byte", "Merkle anchor", "statement", 14),
        ("public_nullifier_byte", "nullifier", "statement", 78),
        ("public_commitment_byte", "output commitment", "statement", 206),
        ("public_fee_byte", "native balance", "statement", 509),
        ("public_value_balance_magnitude_byte", "signed value balance", "statement", 518),
        ("public_stable_issuance_sign", "stablecoin signed balance", "statement", 532),
        ("public_balance_tag_byte", "balance tag", "statement", 869),
        ("inactive_input_with_live_nullifier", "inactive input canonicality", "statement", 10),
        ("private_input0_prefix", "input note/spend witness", "witness", 0),
        ("private_input0_merkle_region", "Merkle path", "witness", 304),
        ("private_input1_prefix", "second input note/spend witness", "witness", 298 * 8),
        ("private_output0_prefix", "output note witness", "witness", 596 * 8),
        ("private_authorization_nonmode", "authorization transition", "witness", 662 * 8 + 8),
        ("private_policy_master", "authorization policy master", "witness", 761 * 8),
    )
    result = []
    for name, family, component, offset in descriptions:
        statement, context, witness = fixture.statement, fixture.context, fixture.witness
        if component == "statement":
            statement = _mutate(statement, offset)
        elif component == "context":
            context = _mutate(context, offset)
        else:
            witness = _mutate(witness, offset)
        accepted, observed, constraint_id = _exec_accepts(
            statement, context, witness
        )
        result.append(
            {
                "name": name,
                "semantic_family": family,
                "component": component,
                "offset": offset,
                "xor_mask": 1,
                "executable_relation_accepted": accepted,
                "observed": observed,
                "constraint_id": constraint_id,
                "sparse_r1cs_row_evaluated": False,
            }
        )
    return tuple(result)


def boolean_high_bit_checks() -> dict[str, Any]:
    statement, context, witness = C.sample_valid_case()
    checks = []
    for name, offset in (
        ("activity_i0", 10),
        ("activity_i1", 11),
        ("activity_o0", 12),
        ("activity_o1", 13),
        ("value_balance_sign", 510),
        ("stable_enabled", 519),
        ("stable_issuance_sign", 532),
    ):
        accepted, reason = _accepts(
            bytes(statement[:offset] + bytes([statement[offset] | 0x80]) + statement[offset + 1 :]),
            context,
            witness,
        )
        checks.append(
            {
                "name": name,
                "component": "statement",
                "offset": offset,
                "accepted": accepted,
                "observed": reason,
            }
        )
    row_base = C.MANIFEST_OFFSET + 4
    for name, row_offset in (
        ("retired_present", 72),
        ("active", 85),
        ("attestation_disputed", 214),
    ):
        offset = row_base + row_offset
        changed = bytearray(witness)
        changed[offset] |= 0x80
        accepted, reason = _accepts(statement, context, bytes(changed))
        checks.append(
            {
                "name": name,
                "component": "manifest witness row",
                "offset": offset,
                "accepted": accepted,
                "observed": reason,
            }
        )
    return {
        "checks": checks,
        "all_noncanonical_high_bits_rejected_by_host_parser": all(
            not item["accepted"] for item in checks
        ),
        "relation_evaluator_exists": False,
    }


def mask_mode_check() -> dict[str, Any]:
    modes = (
        "single_key",
        "accumulator_init",
        "approval_step",
        "value_lock_creation",
        "final_threshold_spend",
    )
    rows = []
    for expected in C.SUITE.activity_mode_matrix():
        flags = tuple(bool(expected["mask"] & (1 << bit)) for bit in range(4))
        mode = modes.index(expected["mode"])
        observed = C.activity_shape_accepts(mode, flags)
        rows.append(
            {
                "mask": expected["mask"],
                "mode": expected["mode"],
                "expected": expected["accept"],
                "host_shape_observed": observed,
                "match": observed == expected["accept"],
                "emitted_relation_evaluated": False,
            }
        )
    return {
        "rows": rows,
        "all_80_host_shape_cases_match": all(row["match"] for row in rows),
        "accepted": sum(row["host_shape_observed"] for row in rows),
        "rejected": sum(not row["host_shape_observed"] for row in rows),
        "relation_coverage_proved": False,
    }


def policy_version_zero_check() -> dict[str, Any]:
    """Build a fully consistent V2 sample whose selected version is zero."""

    entries = [
        C.AUTHORITY.sample_fresh_entry_v2_w64(1001 + index, 0)[0]
        for index in range(16)
    ]
    selected = 0
    path = C.AUTHORITY.prove_fresh_v2_w64_merkle(entries, selected)
    entry = path.entry
    height = 50
    root = C.AUTHORITY.fresh_v2_w64_merkle_root(entries)
    snapshot = C.AUTHORITY.snapshot_commitment(
        root,
        height,
        64,
        profile=C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE,
    )
    statement = bytearray(C.SUITE.sample_statement(C.IDENTITY_NAME))
    statement[520:528] = entry.asset_id.to_bytes(8, "big")
    statement[528:532] = (0).to_bytes(4, "big")
    statement[533:541] = (1).to_bytes(8, "big")
    statement[541:605] = C.AUTHORITY.policy_hash64_v2(entry)
    statement[605:669] = entry.oracle_commitment
    statement[669:733] = entry.attestation_commitment
    statement[733:797] = root
    statement[797:861] = snapshot
    statement[861:869] = height.to_bytes(8, "big")
    witness = bytearray(C.PRIVATE_BYTES)
    for index in range(2):
        offset = (777 + index * 269) * 8
        ciphertext = bytes([0xA0 + index]) * C.CANONICAL_CIPHERTEXT_BYTES
        witness[offset : offset + C.CANONICAL_CIPHERTEXT_BYTES] = ciphertext
        statement[334 + index * 64 : 398 + index * 64] = C.ciphertext_digest(
            index, ciphertext
        )
    encoded_path = path.encode()
    witness[C.MANIFEST_OFFSET : C.MANIFEST_OFFSET + len(encoded_path)] = encoded_path
    context = C.VerifierContext(root, height).encode()
    accepted, reason = _accepts(bytes(statement), context, bytes(witness))
    return {
        "policy_version": 0,
        "statement_parser_accepted": _parse_accepts(bytes(statement)),
        "full_host_reference_accepted": accepted,
        "observed": reason,
        "rust_v2_domain": "u32 including zero",
        "nonzero_constraint_required": False,
    }


def _parse_accepts(statement: bytes) -> bool:
    try:
        C.parse_statement(statement)
    except Exception:
        return False
    return True


def _consistent_case_for_entry(
    selected_entry: Any, issuance_magnitude: int = 1
) -> tuple[bytes, bytes, bytes]:
    entries = [selected_entry] + [
        C.AUTHORITY.sample_fresh_entry_v2_w64(1001 + index, 3)[0]
        for index in range(1, 16)
    ]
    path = C.AUTHORITY.prove_fresh_v2_w64_merkle(entries, 0)
    height = 50
    root = C.AUTHORITY.fresh_v2_w64_merkle_root(entries)
    snapshot = C.AUTHORITY.snapshot_commitment(
        root,
        height,
        64,
        profile=C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE,
    )
    statement = bytearray(C.SUITE.sample_statement(C.IDENTITY_NAME))
    statement[520:528] = selected_entry.asset_id.to_bytes(8, "big")
    statement[528:532] = selected_entry.policy_version.to_bytes(4, "big")
    statement[533:541] = issuance_magnitude.to_bytes(8, "big")
    statement[541:605] = C.AUTHORITY.policy_hash64_v2(selected_entry)
    statement[605:669] = selected_entry.oracle_commitment
    statement[669:733] = selected_entry.attestation_commitment
    statement[733:797] = root
    statement[797:861] = snapshot
    statement[861:869] = height.to_bytes(8, "big")
    witness = bytearray(C.PRIVATE_BYTES)
    for index in range(2):
        offset = (777 + index * 269) * 8
        ciphertext = bytes([0xA0 + index]) * C.CANONICAL_CIPHERTEXT_BYTES
        witness[offset : offset + C.CANONICAL_CIPHERTEXT_BYTES] = ciphertext
        statement[334 + index * 64 : 398 + index * 64] = C.ciphertext_digest(
            index, ciphertext
        )
    encoded_path = path.encode()
    witness[C.MANIFEST_OFFSET : C.MANIFEST_OFFSET + len(encoded_path)] = encoded_path
    context = C.VerifierContext(root, height).encode()
    return bytes(statement), context, bytes(witness)


def authority_host_gate_audit() -> dict[str, Any]:
    base = C.AUTHORITY.sample_fresh_entry_v2_w64(1001, 3)[0]
    baseline = _consistent_case_for_entry(base)
    accepted, baseline_reason = _accepts(*baseline)
    variants = OrderedDict(
        inactive=dataclasses.replace(base, active=False),
        not_yet_enabled=dataclasses.replace(base, enabled_at=51),
        retired=dataclasses.replace(base, retired_at=50),
        future_oracle=dataclasses.replace(base, oracle_submitted_at=51),
        stale_oracle=dataclasses.replace(
            base, oracle_submitted_at=0, oracle_max_age=1
        ),
        disputed_attestation=dataclasses.replace(base, attestation_disputed=True),
        issuance_over_cap=dataclasses.replace(base, max_mint_per_epoch=0),
    )
    checks = []
    for name, entry in variants.items():
        case = _consistent_case_for_entry(entry)
        case_accepted, reason = _accepts(*case)
        checks.append(
            {
                "name": name,
                "internally_consistent_manifest_root_snapshot_and_context": True,
                "host_reference_accepted": case_accepted,
                "observed": reason,
            }
        )
    zero_case = _consistent_case_for_entry(base, issuance_magnitude=0)
    zero_accepted, zero_reason = _accepts(*zero_case)
    checks.append(
        {
            "name": "zero_issuance",
            "internally_consistent_manifest_root_snapshot_and_context": True,
            "host_reference_accepted": zero_accepted,
            "observed": zero_reason,
        }
    )
    statement, context, witness = baseline
    endian_vectors = []
    for name, component, changed in (
        (
            "statement_height_little_endian_substitution",
            "statement",
            statement[:861] + statement[861:869][::-1] + statement[869:],
        ),
        (
            "context_height_big_endian_substitution",
            "context",
            context[:64] + context[64:][::-1],
        ),
        (
            "statement_policy_version_little_endian_substitution",
            "statement",
            statement[:528] + statement[528:532][::-1] + statement[532:],
        ),
        (
            "statement_asset_little_endian_substitution",
            "statement",
            statement[:520] + statement[520:528][::-1] + statement[528:],
        ),
    ):
        mutated_statement = changed if component == "statement" else statement
        mutated_context = changed if component == "context" else context
        vector_accepted, reason = _accepts(
            mutated_statement, mutated_context, witness
        )
        endian_vectors.append(
            {"name": name, "host_reference_accepted": vector_accepted, "observed": reason}
        )
    former_host = C.executed_reference_mutations()
    return {
        "baseline_accepted": accepted,
        "baseline_observed": baseline_reason,
        "lifecycle_dispute_cap_checks": checks,
        "all_internally_consistent_invalid_rows_rejected": all(
            not item["host_reference_accepted"] for item in checks
        ),
        "endianness_vectors": endian_vectors,
        "all_wrong_endian_vectors_rejected": all(
            not item["host_reference_accepted"] for item in endian_vectors
        ),
        "former_host_predicate_mutations": former_host,
        "all_former_host_mutations_rejected_by_host_reference": all(
            item["observed"] == "reject" for item in former_host
        ),
        "emitted_relation_evaluated": False,
        "native_parent_state_authentication_refined": False,
        "global_manifest_sorted_unique_cap16_state_writer_refined": False,
    }


def policy_master_audit(program: Any) -> dict[str, Any]:
    expected = [
        {
            "mode": "single_key",
            "policy_call_master": "current",
            "auth_call_masters": {
                "slot0_lane_a": None,
                "slot0_lane_b": None,
                "slot1_lane_a": None,
                "slot1_lane_b": None,
            },
            "master_constraints": ["current=zero64", "next=zero64"],
        },
        {
            "mode": "accumulator_init",
            "policy_call_master": "next",
            "auth_call_masters": {
                "slot0_lane_a": "next",
                "slot0_lane_b": "next",
                "slot1_lane_a": None,
                "slot1_lane_b": None,
            },
            "master_constraints": ["current=zero64"],
        },
        {
            "mode": "approval_step",
            "policy_call_master": "current",
            "auth_call_masters": {
                "slot0_lane_a": "current",
                "slot0_lane_b": "current",
                "slot1_lane_a": "next",
                "slot1_lane_b": "next",
            },
            "master_constraints": ["current=next"],
        },
        {
            "mode": "value_lock_creation",
            "policy_call_master": "current",
            "auth_call_masters": {
                "slot0_lane_a": "current",
                "slot0_lane_b": "current",
                "slot1_lane_a": None,
                "slot1_lane_b": None,
            },
            "master_constraints": ["next=zero64"],
        },
        {
            "mode": "final_threshold_spend",
            "policy_call_master": "current",
            "auth_call_masters": {
                "slot0_lane_a": "current",
                "slot0_lane_b": "current",
                "slot1_lane_a": "current",
                "slot1_lane_b": "current",
            },
            "master_constraints": ["next=zero64"],
        },
    ]
    suite_schedule = (
        C.SUITE.policy_master_mode_schedule()
        if hasattr(C.SUITE, "policy_master_mode_schedule")
        else None
    )
    zero = bytes(64)
    first = bytes([0xA5]) * 64
    second = bytes([0x5A]) * 64
    positive = {
        "single_key": (zero, zero),
        "accumulator_init": (zero, first),
        "approval_step": (first, first),
        "value_lock_creation": (first, zero),
        "final_threshold_spend": (first, zero),
    }
    negative = {
        "single_key": (first, zero),
        "accumulator_init": (first, second),
        "approval_step": (first, second),
        "value_lock_creation": (first, second),
        "final_threshold_spend": (first, second),
    }
    positive_results: dict[str, bool] = {}
    negative_results: dict[str, bool] = {}
    require = getattr(C.SUITE, "require_policy_masters", None)
    for mode, (current, next_) in positive.items():
        try:
            if require is None:
                raise RuntimeError("suite checker absent")
            require(mode, current, next_)
        except Exception:
            positive_results[mode] = False
        else:
            positive_results[mode] = True
    for mode, (current, next_) in negative.items():
        try:
            if require is None:
                raise RuntimeError("suite checker absent")
            require(mode, current, next_)
        except Exception:
            negative_results[mode] = True
        else:
            negative_results[mode] = False
    groups = {item["name"]: item for item in program.export_groups()}
    accumulator = groups[C.BASE.LOCAL_GROUPS[14]]["rows"]
    approval = groups[C.BASE.LOCAL_GROUPS[15]]["rows"]
    master_invocations = [
        {"group": group["name"], **invocation}
        for group in program.export_groups()
        for invocation in group["invocations"]
        if "master" in invocation.get("note", "").lower()
    ]
    return {
        "expected_schedule": expected,
        "suite_schedule": suite_schedule,
        "schedule_exact_match": suite_schedule == expected,
        "host_positive_cases_accept": positive_results,
        "host_negative_cases_reject": negative_results,
        "host_checker_complete_for_five_modes": (
            all(positive_results.values()) and all(negative_results.values())
        ),
        "existing_template_rows": {
            "single_current_and_next_zero": 1_024,
            "inactive_master_zero": 512,
            "subtotal": 1_536,
        },
        "required_additional_template_rows": {
            "selected_current_or_next_policy_call_master": 512,
            "approval_current_equals_next": 512,
            "total": 1_024,
            "padding": 0,
        },
        "observed_group_rows": {
            "accumulator_metadata": accumulator,
            "approval_transition": approval,
        },
        "expected_repaired_group_rows": {
            "accumulator_metadata": 28_874,
            "approval_transition": 9_847,
        },
        "expected_repaired_total_m": 29_510_157,
        "expected_repaired_geometry": {
            "m_constraints": 29_510_157,
            "n_nonconstant_variables": 21_531_849,
            "l_public_variables": 9_704,
            "auxiliary_variables_total": 21_522_145,
            "private_transport_variables": 88_000,
            "derived_auxiliary_variables": 21_434_145,
            "matrix_nonzeros_total": 123_198_636,
            "z_vector_length_including_constant_one": 21_531_850,
        },
        "master_named_invocations": master_invocations,
        "operand_wiring_retained": False,
        "compiled_schedule_confirmed": False,
    }


def characteristic_two_counterexamples() -> dict[str, Any]:
    # Each expression is the literal integer polynomial printed by the frozen
    # primitive table, reduced both modulo the odd field and modulo two.
    cases = [
        {
            "primitive": "add_lsb",
            "assignment": {"x": 0, "y": 0, "sum": 0, "carry_out": 1},
            "integer_expression": -2,
            "why_invalid": "0+0 has carry_out 0, but carry_out 1 is accepted",
        },
        {
            "primitive": "add_carry",
            "assignment": {
                "x": 0,
                "y": 0,
                "carry_in": 0,
                "sum": 0,
                "carry_out": 1,
            },
            "integer_expression": -2,
            "why_invalid": "next carry is unconstrained because coefficient 2 vanishes",
        },
        {
            "primitive": "linear_sum_5",
            "assignment": {"selectors": [1, 1, 1, 0, 0]},
            "integer_expression": 2,
            "why_invalid": "three-hot selectors satisfy parity one",
        },
        {
            "primitive": "cond_sum_4",
            "assignment": {"active": 1, "selectors": [1, 1, 1, 0]},
            "integer_expression": 2,
            "why_invalid": "active three-hot selectors satisfy parity one",
        },
    ]
    for item in cases:
        value = item.pop("integer_expression")
        item["odd_goldilocks_residual"] = value % C.P
        item["gf2_residual"] = value % 2
        item["rejects_over_goldilocks"] = value % C.P != 0
        item["accepts_over_characteristic_two"] = value % 2 == 0
    return {
        "cases": cases,
        "all_counterexamples_hold": all(
            item["rejects_over_goldilocks"]
            and item["accepts_over_characteristic_two"]
            for item in cases
        ),
        "unsafe_macros": [
            "add",
            "add64",
            "mode_onehot5",
            "cond_sum4",
            "onehot_select5 when relying on mode_onehot5",
            "selected_asset4 when relying on cond_sum4",
            "every BLAKE2b ARX compression using add64",
            "balance/popcount/counter arithmetic using add64",
        ],
        "safe_boolean_primitive_families_if_inputs_are_bits": [
            "bitness",
            "and",
            "xor",
            "or",
            "and_not",
            "not",
            "select",
            "eq",
            "eq_zero",
            "eq_one",
            "cond_zero",
            "cond_eq",
            "implies",
        ],
        "verdict": (
            "m=29,509,133 is an odd-field macro-template count and cannot be "
            "reinterpreted as a GF(2^s), binary, Binius, or Aurora relation."
        ),
    }


def hash_schedule_audit(program: Any) -> dict[str, Any]:
    core = C.SUITE.core_frame_schedule(C.MAGIC)
    authority = C.SUITE.authority_schedule(C.IDENTITY_NAME)["in_relation"]
    core_calls = sum(item["calls"] for item in core)
    core_compressions = sum(
        item["calls"]
        * item.get(
            "fixed_blake_compressions_per_call",
            item.get("blake_compressions_per_call", 0),
        )
        for item in core
    )
    authority_calls = sum(item["calls"] for item in authority)
    authority_compressions = sum(
        item["calls"] * item["blake2b512_compressions_per_call"]
        for item in authority
    )
    group = next(
        item
        for item in program.export_groups()
        if item["name"] == "HX512B01 core frame source wiring"
    )
    invocation_keys = sorted(
        {key for item in program.export_groups() for inv in item["invocations"] for key in inv}
    )
    return {
        "expected": {
            "core_calls": core_calls,
            "authority_calls": authority_calls,
            "total_calls": core_calls + authority_calls,
            "core_compressions": core_compressions,
            "authority_compressions": authority_compressions,
            "total_compressions": core_compressions + authority_compressions,
            "core_schedule": core,
            "authority_schedule": authority,
        },
        "ledger": {
            "core_frame_source_wiring_rows": group["rows"],
            "core_frame_source_wiring_invocations": group["invocations"],
            "invocation_keys": invocation_keys,
        },
        "exact_message_byte_wires_retained": False,
        "exact_little_endian_message_word_wires_retained": False,
        "per_compression_counter_wires_retained": False,
        "per_compression_final_flag_wires_retained": False,
        "per_call_parameter_block_wires_retained": False,
        "per_call_digest_output_wires_retained": False,
        "hash_output_to_semantic_link_operands_retained": False,
        "finding": (
            "The only frame-source invocation is a zero-row alias with prose. "
            "Aggregate add/xor/not multiplicities do not bind any of the 90 "
            "messages, RFC counters/final flags, personalizations, or outputs."
        ),
    }


def layout_audit() -> dict[str, Any]:
    offsets = C.statement_offsets()
    names = list(offsets)
    statement_parts = []
    cursor = 0
    for index, name in enumerate(names[:-1]):
        start, end = offsets[name], offsets[names[index + 1]]
        statement_parts.append({"name": name, "offset": start, "bytes": end - start})
        if start != cursor:
            raise AssertionError(("statement gap/overlap", name, cursor, start))
        cursor = end
    statement_complete = cursor == C.STATEMENT_BYTES
    witness_parts = []
    cursor = 0
    for name, offset, width in C.WITNESS_SECTIONS:
        witness_parts.append({"name": name, "offset": offset, "bytes": width})
        if offset != cursor:
            raise AssertionError(("witness gap/overlap", name, cursor, offset))
        cursor = offset + width
    witness_complete = cursor == C.PRIVATE_BYTES
    statement, context, _ = C.sample_valid_case()
    manifest_root = statement[C.statement_offsets()["manifest_root"] : C.statement_offsets()["state_root"]]
    snapshot = statement[C.statement_offsets()["state_root"] : C.statement_offsets()["state_height"]]
    return {
        "statement": {
            "bytes": C.STATEMENT_BYTES,
            "parts": statement_parts,
            "contiguous_exact_consumption": statement_complete,
            "numeric_endianness": "big-endian",
        },
        "context": {
            "bytes": C.CONTEXT_BYTES,
            "grammar": "manifest_root64 || parent_height:u64le",
            "sample_prefix_equals_statement_manifest_root": context[:64] == manifest_root,
            "sample_prefix_equals_statement_snapshot": context[:64] == snapshot,
            "sample_height_little_endian": context[64:] == statement[861:869][::-1],
        },
        "witness": {
            "bytes": C.PRIVATE_BYTES,
            "parts": witness_parts,
            "contiguous_exact_consumption": witness_complete,
            "source_bitness_rows_expected": (
                C.STATEMENT_BYTES + C.CONTEXT_BYTES + C.PRIVATE_BYTES
            )
            * 8,
            "section_sublayouts_with_field_offsets_retained": False,
            "per_field_endianness_and_wire_mapping_retained": False,
        },
        "ciphertext": {
            "semantic_bytes_each": C.CANONICAL_CIPHERTEXT_BYTES,
            "transport_bytes_each": 269 * 8,
            "zero_padding_bytes_each": 5,
        },
        "manifest": {
            "semantic_bytes": C.MANIFEST_SEMANTIC_BYTES,
            "transport_bytes": C.MANIFEST_WITNESS_BYTES,
            "zero_padding_bytes": C.MANIFEST_WITNESS_BYTES - C.MANIFEST_SEMANTIC_BYTES,
            "row_numeric_endianness": "little-endian",
            "index_endianness": "little-endian",
            "selected_membership_only": True,
            "global_sorted_unique_cap16_state_writer_enforced_in_relation": False,
        },
    }


def pin_audit() -> dict[str, Any]:
    compiler_paths = {
        path.resolve()
        for path in (
            C.KERNEL_V2_PATH,
            C.KERNEL_V2_CHECKER_PATH,
            C.KERNEL_V2_TEST_PATH,
            C.KERNEL_LIB_PATH,
        )
    }
    pinned = {(ROOT / name).resolve() for name in C.EXPECTED_DEPENDENCY_SHA512}
    try:
        C.source_contracts()
    except Exception as error:
        contract = {"passes": False, "observed": f"{type(error).__name__}: {error}"}
    else:
        contract = {"passes": True, "observed": "pass"}
    return {
        "source_contract": contract,
        "compiler_source_sha512": sha512_file(COMPILER_PATH),
        "dependencies": [
            {
                "path": rel(path),
                "sha512": sha512_file(path) if path.is_file() else None,
                "pinned": path in pinned,
            }
            for path in sorted(compiler_paths)
        ],
        "unpinned_behavioral_dependency": (
            "protocol/kernel/src/lib.rs"
            if C.KERNEL_LIB_PATH.resolve() not in pinned
            else None
        ),
    }


def _corrected_geometry(program: Any, recount_result: dict[str, Any]) -> dict[str, Any]:
    removed = []
    for group in program.export_groups():
        for invocation in group["invocations"]:
            if invocation["macro"] == "not" and "parameter" in invocation.get("note", "").lower():
                removed.append(
                    {
                        "group": group["name"],
                        "rows": invocation["multiplicity"] * invocation.get("width_bits", 1),
                    }
                )
    removed_rows = sum(item["rows"] for item in removed)
    if removed_rows not in (0, 270):
        raise AssertionError(("fixed parameter NOT rows", removed_rows))
    observed = recount_result["expected_geometry"]
    corrected = dict(observed)
    corrected["m_constraints"] -= removed_rows
    corrected["n_nonconstant_variables"] -= removed_rows
    corrected["auxiliary_variables_total"] -= removed_rows
    corrected["derived_auxiliary_variables"] -= removed_rows
    corrected["matrix_nonzeros_total"] -= 4 * removed_rows
    corrected["z_vector_length_including_constant_one"] -= removed_rows
    expected = {
        "m_constraints": 29_509_887,
        "n_nonconstant_variables": 21_531_579,
        "l_public_variables": 9_704,
        "auxiliary_variables_total": 21_521_875,
        "private_transport_variables": 88_000,
        "derived_auxiliary_variables": 21_433_875,
        "matrix_nonzeros_total": 123_197_556,
        "z_vector_length_including_constant_one": 21_531_580,
    }
    if corrected != expected:
        raise AssertionError(("corrected geometry", corrected, expected))
    ell = 1 << 25
    witness_padding = ell - corrected["auxiliary_variables_total"]
    row_zero_padding = 2 * ell - (corrected["m_constraints"] + witness_padding)
    return {
        "target_observed": observed,
        "constant_fold_decision": "all fixed RFC7693 parameter and personalization blocks",
        "parameter_not_rows_present_at_frozen_checkpoint": removed_rows,
        "historical_prefold_parameter_not_rows": 270,
        "removed_by_group": removed,
        "removed_auxiliary_variables": removed_rows,
        "removed_matrix_nonzeros": 4 * removed_rows,
        "corrected_source_cost_projection": corrected,
        "section11": {
            "ell": ell,
            "witness_zero_padding": witness_padding,
            "row_zero_padding": row_zero_padding,
            "carrier_nonzeros": corrected["matrix_nonzeros_total"] + 2 * witness_padding,
        },
        "target_matches_corrected_projection": observed == expected,
        "exact_expected_projection": expected,
        "no_padding_added": True,
    }


def _constant_parameter_audit() -> dict[str, Any]:
    persons = OrderedDict(
        policy=C.AUTHORITY.identity_personalization(C.AUTHORITY.IDENTITY_ROLE_POLICY, 64),
        leaf=C.AUTHORITY.personalization(
            C.AUTHORITY.ROLE_LEAF,
            64,
            16,
            profile=C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE,
        ),
        node0=C.AUTHORITY.personalization(C.AUTHORITY.ROLE_NODE, 64, 16, 0, C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE),
        node1=C.AUTHORITY.personalization(C.AUTHORITY.ROLE_NODE, 64, 16, 1, C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE),
        node2=C.AUTHORITY.personalization(C.AUTHORITY.ROLE_NODE, 64, 16, 2, C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE),
        node3=C.AUTHORITY.personalization(C.AUTHORITY.ROLE_NODE, 64, 16, 3, C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE),
        snapshot=C.AUTHORITY.personalization(
            C.AUTHORITY.ROLE_SNAPSHOT,
            64,
            16,
            profile=C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE,
        ),
    )
    person_bits = OrderedDict(
        (name, sum(byte.bit_count() for byte in value))
        for name, value in persons.items()
    )
    if list(person_bits.values()) != [27, 32, 33, 34, 34, 35, 32]:
        raise AssertionError(person_bits)
    parameter = bytearray(64)
    parameter[0] = 64
    parameter[2] = 1
    parameter[3] = 1

    def independent_state(person: bytes) -> tuple[int, ...]:
        block = bytearray(parameter)
        block[48:64] = person
        return tuple(
            C.BOOLEAN_BLAKE.IV[index]
            ^ int.from_bytes(block[index * 8 : (index + 1) * 8], "little")
            for index in range(8)
        )

    states = OrderedDict(core=independent_state(bytes(16)))
    for name, person in persons.items():
        states[name] = independent_state(person)
    target_states_match = all(
        tuple(C.BOOLEAN_BLAKE.initial_state(bytes(16) if name == "core" else persons[name])) == value
        for name, value in states.items()
    )
    return {
        "standard_parameter_set_bits_per_call": 3,
        "target_top_level_calls": 90,
        "target_parameter_not_rows": C.boolean_hash_trace_certificate()[
            "parameter_not_rows_per_fixture"
        ],
        "authority_personalization_set_bits": person_bits,
        "authority_personalization_set_bits_total": sum(person_bits.values()),
        "unique_constant_folded_initial_states": len(states),
        "independent_initial_states_equal_target": target_states_match,
        "coherent_constant_fold_rows": 0,
        "coherent_explicit_not_rows": 270 + sum(person_bits.values()),
        "target_constant_folds_all_fixed_parameters": C.boolean_hash_trace_certificate()[
            "parameter_not_rows_per_fixture"
        ]
        == 0,
        "target_rows_are_neither_coherent_choice": False,
        "profile_parameter_blocks_exactly_bound": len(C.PROFILE.parameter_profiles()) == 8,
    }


@functools.lru_cache(maxsize=1)
def _all66_streaming_audit() -> dict[str, Any]:
    disabled, stable = _positive_executable_fixtures()
    traces = []
    for fixture in (*disabled, *stable):
        evaluation = C.EXECUTABLE.evaluate(fixture.statement, fixture.context, fixture.witness)
        trace = C.BOOLEAN_BLAKE.trace_relation(
            evaluation.hash_calls,
            expected_personalization_hex_by_call=C.PROFILE.expected_personalization_hex_by_call(),
            exhaustive_bits=False,
        )
        traces.append(trace)
    return {
        "fixtures": len(traces),
        "physical_calls": len(traces) * 90,
        "fixed_compressions": len(traces) * 213,
        "target_streaming_rows": sum(item["total_boolean_hash_rows"] for item in traces),
        "corrected_constant_fold_rows": len(traces) * 29_049_792,
        "all_digests_equal_independent_hashlib": all(
            item["every_call_digest_equals_independent_hashlib"] for item in traces
        ),
        "bit_rows_exhaustively_evaluated": False,
    }


def _hash_negative_mutations() -> dict[str, Any]:
    fixture = C.EXECUTABLE.build_fixture(2, 0b1111, stable_enabled=True, policy_version=0)
    calls = C.EXECUTABLE.evaluate(fixture.statement, fixture.context, fixture.witness).hash_calls
    rejected = 0
    cases = []
    for call in calls:
        if call.personalization_hex is None:
            message = bytearray.fromhex(call.message_hex)
            message[8] ^= 1
            changed = dataclasses.replace(call, message_hex=bytes(message).hex())
            kind = "core_frame_role_byte"
        else:
            person = bytearray.fromhex(call.personalization_hex)
            person[8] ^= 1
            changed = dataclasses.replace(call, personalization_hex=bytes(person).hex())
            kind = "authority_personalization_role_byte"
        try:
            C.BOOLEAN_BLAKE.trace_call(
                changed,
                expected_personalization_hex=C.PROFILE.expected_personalization_hex_by_call()[
                    call.index
                ],
                exhaustive_bits=False,
            )
        except C.BOOLEAN_BLAKE.BooleanTraceError:
            rejected += 1
            observed = "reject"
        else:
            observed = "accept"
        cases.append({"index": call.index, "kind": kind, "observed": observed})
    return {
        "cases": cases,
        "mutations": len(cases),
        "rejected": rejected,
        "all_role_or_personalization_mutations_reject": rejected == len(cases),
    }


def _branch_coverage() -> dict[str, Any]:
    per_mode_accept = [15, 6, 2, 6, 4]
    per_mode_reject = [1, 10, 14, 10, 12]
    rows = []
    positive_pairs = set()
    negative_pairs = set()
    for mode in range(5):
        for mask in range(16):
            flags = tuple(bool(mask & (1 << bit)) for bit in range(4))
            accepted = C.EXECUTABLE.activity_shape_accepts(mode, flags)
            (positive_pairs if accepted else negative_pairs).add((mode, mask))
            rows.append({"mode": mode, "mask": mask, "accept": accepted})
    disabled, stable = _positive_executable_fixtures()
    matrix = C.EXECUTABLE.activity_stablecoin_matrix_certificate()
    if (
        [sum(item["accept"] and item["mode"] == mode for item in rows) for mode in range(5)]
        != per_mode_accept
    ):
        raise AssertionError("mask/mode acceptance cardinality")
    return {
        "one_branch_matrix": rows,
        "per_mode_accept": per_mode_accept,
        "per_mode_reject": per_mode_reject,
        "required_branch_mask_mode_cells": 160,
        "required_positive_evaluator_fixtures": 66,
        "required_negative_evaluator_fixtures": 94,
        "observed_positive_evaluator_fixtures": len(disabled) + len(stable),
        "observed_negative_evaluator_fixtures": matrix["negative_cells"],
        "all_negative_cells_reach_activity_mask_mode": matrix[
            "all_negative_cells_reach_activity_mask_mode"
        ],
        "positive_pairs_exact": {
            (item.mode, item.mask) for item in disabled
        }
        == positive_pairs
        and {(item.mode, item.mask) for item in stable} == positive_pairs,
        "stablecoin_policy_version_zero_positive_fixtures": sum(
            item.stable_enabled for item in stable
        ),
        "full_160_cell_evaluator_contract_satisfied": (
            matrix["total_cells"],
            matrix["positive_cells"],
            matrix["negative_cells"],
        )
        == (160, 66, 94),
    }


def _boolean_high_bit_checks_v2() -> dict[str, Any]:
    fixture = C.EXECUTABLE.build_fixture(2, 0b1111, stable_enabled=True, policy_version=0)
    descriptions: list[tuple[str, str, int]] = [
        (name, "statement", offset)
        for name, offset in (
            ("activity_i0", 10),
            ("activity_i1", 11),
            ("activity_o0", 12),
            ("activity_o1", 13),
            ("value_balance_sign", 510),
            ("stable_enabled", 519),
            ("stable_issuance_sign", 532),
        )
    ]
    for input_index, base in enumerate((0, 2384)):
        for slot in range(4):
            descriptions.append((f"input[{input_index}].selector[{slot}]", "witness", base + 2352 + 8 * slot))
    for output_index, base in enumerate((4768, 5032)):
        for slot in range(4):
            descriptions.append((f"output[{output_index}].selector[{slot}]", "witness", base + 232 + 8 * slot))
    for opening, base in (("current", 5296 + 8), ("next", 5296 + 208)):
        for slot in range(6):
            descriptions.append((f"authorization.{opening}.approved[{slot}]", "witness", base + 152 + 8 * slot))
    for name, row_offset in (("retired_present", 72), ("active", 85), ("attestation_disputed", 214)):
        descriptions.append((f"manifest.{name}", "witness", C.MANIFEST_OFFSET + 4 + row_offset))
    checks = []
    for name, component, offset in descriptions:
        statement, context, witness = fixture.statement, fixture.context, fixture.witness
        if component == "statement":
            changed = bytearray(statement)
            changed[offset] |= 0x80
            statement = bytes(changed)
        else:
            changed = bytearray(witness)
            changed[offset] |= 0x80
            witness = bytes(changed)
        accepted, observed, constraint_id = _exec_accepts(statement, context, witness)
        checks.append(
            {
                "name": name,
                "component": component,
                "offset": offset,
                "accepted": accepted,
                "constraint_id": constraint_id,
                "observed": observed,
            }
        )
    if len(checks) != 38:
        raise AssertionError(len(checks))
    return {
        "checks": checks,
        "expected_boolean_transport_fields": 38,
        "all_noncanonical_high_bits_rejected": all(not item["accepted"] for item in checks),
        "semantic_interpreter_evaluated": True,
        "sparse_r1cs_rows_evaluated": False,
    }


def _layout_v2() -> dict[str, Any]:
    statement = C.SUITE.statement_layout()
    if sum(item["bytes"] for item in statement) != C.STATEMENT_BYTES:
        raise AssertionError("statement layout")
    input_fields = [
        ("spend_master", 0, 64, "opaque64"),
        ("note.kind", 64, 8, "u64be"),
        ("note.value", 72, 8, "u64be"),
        ("note.asset", 80, 8, "u64be"),
        ("note.recipient", 88, 32, "opaque32"),
        ("note.rho", 120, 48, "opaque48"),
        ("note.blinding", 168, 64, "opaque64"),
        ("note.authorization", 232, 64, "opaque64"),
        ("position", 296, 8, "u64be"),
        ("siblings", 304, 2048, "digest64[32]"),
        ("selectors", 2352, 32, "bool-u64be[4]"),
    ]
    output_fields = [
        ("note", 0, 232, "note-grammar"),
        ("selectors", 232, 32, "bool-u64be[4]"),
    ]
    auth_fields = [
        ("mode", 0, 8, "u64be"),
        ("current", 8, 200, "accumulator"),
        ("next", 208, 200, "accumulator"),
        ("signer_tags", 408, 384, "digest64[6]"),
    ]
    sections = [
        {"name": name, "offset": offset, "bytes": width}
        for name, offset, width in C.WITNESS_SECTIONS
    ]
    cursor = 0
    for item in sections:
        if item["offset"] != cursor:
            raise AssertionError((cursor, item))
        cursor += item["bytes"]
    return {
        "statement": {
            "bytes": C.STATEMENT_BYTES,
            "fields": statement,
            "numeric_endianness": "big-endian",
            "opaque_digest_bytes_reordered": False,
        },
        "context": {
            "bytes": C.CONTEXT_BYTES,
            "grammar": "manifest_root64 || parent_height:u64le",
        },
        "witness": {
            "bytes": C.PRIVATE_BYTES,
            "sections": sections,
            "contiguous_exact_consumption": cursor == C.PRIVATE_BYTES,
            "input_fields_each": input_fields,
            "output_fields_each": output_fields,
            "authorization_fields": auth_fields,
            "policy_masters": "current64 || next64",
            "ciphertext_each": "semantic2147 || zero5",
            "manifest": "index:u32le || row215 little-endian fields || siblings64[4] || zero5",
            "transport_bit_order": "least-significant bit first within every byte",
            "source_bitness_rows": (C.STATEMENT_BYTES + C.CONTEXT_BYTES + C.PRIVATE_BYTES) * 8,
            "semantic_decoder_field_offsets_retained": True,
            "numeric_sparse_r1cs_wire_map_retained": False,
        },
    }


def _manifest_case_with_entry(fixture: Any, entry: Any, issuance: int = 1) -> tuple[bytes, bytes, bytes]:
    statement = bytearray(fixture.statement)
    witness = bytearray(fixture.witness)
    decoded = C.EXECUTABLE.Witness.decode(fixture.witness, True)
    path = C.AUTHORITY.FreshMerkleWitnessV2W64(
        decoded.manifest.index, entry, decoded.manifest.siblings
    )
    root = C.AUTHORITY.fresh_v2_w64_root_from_witness(path)
    height = int.from_bytes(statement[861:869], "big")
    snapshot = C.AUTHORITY.snapshot_commitment(
        root, height, 64, profile=C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE
    )
    statement[520:528] = entry.asset_id.to_bytes(8, "big")
    statement[528:532] = entry.policy_version.to_bytes(4, "big")
    statement[533:541] = issuance.to_bytes(8, "big")
    statement[541:605] = C.AUTHORITY.policy_hash64_v2(entry)
    statement[605:669] = entry.oracle_commitment
    statement[669:733] = entry.attestation_commitment
    statement[733:797] = root
    statement[797:861] = snapshot
    encoded = path.encode()
    witness[C.MANIFEST_OFFSET : C.MANIFEST_OFFSET + len(encoded)] = encoded
    context = root + height.to_bytes(8, "little")
    return bytes(statement), context, bytes(witness)


def _authority_semantic_audit() -> dict[str, Any]:
    fixture = C.EXECUTABLE.build_fixture(0, 0b1111, stable_enabled=True, policy_version=0)
    entry = C.EXECUTABLE.Witness.decode(fixture.witness, True).manifest.entry
    variants = OrderedDict(
        inactive=dataclasses.replace(entry, active=False),
        not_yet_enabled=dataclasses.replace(entry, enabled_at=51),
        retired=dataclasses.replace(entry, retired_at=50),
        future_oracle=dataclasses.replace(entry, oracle_submitted_at=51),
        stale_oracle=dataclasses.replace(entry, oracle_submitted_at=0, oracle_max_age=1),
        disputed_attestation=dataclasses.replace(entry, attestation_disputed=True),
        issuance_over_cap=dataclasses.replace(entry, max_mint_per_epoch=0),
    )
    cases = []
    for name, changed in variants.items():
        accepted, observed, constraint_id = _exec_accepts(*_manifest_case_with_entry(fixture, changed))
        cases.append(
            {
                "name": name,
                "internally_consistent_root_snapshot_context": True,
                "accepted": accepted,
                "constraint_id": constraint_id,
                "observed": observed,
            }
        )
    accepted, observed, constraint_id = _exec_accepts(*_manifest_case_with_entry(fixture, entry, 0))
    cases.append(
        {
            "name": "zero_issuance",
            "internally_consistent_root_snapshot_context": True,
            "accepted": accepted,
            "constraint_id": constraint_id,
            "observed": observed,
        }
    )
    endian = []
    for name, component, offset, width in (
        ("statement_height_little_endian_substitution", "statement", 861, 8),
        ("context_height_big_endian_substitution", "context", 64, 8),
        ("statement_policy_version_little_endian_substitution", "statement", 528, 4),
        ("statement_asset_little_endian_substitution", "statement", 520, 8),
    ):
        statement, context, witness = fixture.statement, fixture.context, fixture.witness
        if component == "statement":
            changed = bytearray(statement)
            changed[offset : offset + width] = changed[offset : offset + width][::-1]
            statement = bytes(changed)
        else:
            changed = bytearray(context)
            changed[offset : offset + width] = changed[offset : offset + width][::-1]
            context = bytes(changed)
        result = _exec_accepts(statement, context, witness)
        endian.append({"name": name, "accepted": result[0], "constraint_id": result[2], "observed": result[1]})
    residuals = C.EXECUTABLE.mutation_residuals()
    former = [
        item
        for item in residuals
        if item["name"]
        in {
            "manifest_row",
            "manifest_path",
            "verifier_manifest_root",
            "verifier_height",
        }
    ]
    return {
        "stable_policy_version_zero_accepted": True,
        "lifecycle_dispute_and_cap_cases": cases,
        "all_lifecycle_dispute_and_cap_cases_reject": all(not item["accepted"] for item in cases),
        "endianness_cases": endian,
        "all_wrong_endian_cases_reject": all(not item["accepted"] for item in endian),
        "former_host_predicate_residuals": former,
        "all_four_former_host_predicates_reject": len(former) == 4 and all(item["observed"] == "reject" for item in former),
        "lifecycle_implemented_as_host_function_call": True,
        "sparse_r1cs_rows_evaluated": False,
    }


def _fixture_hashes(statement: bytes, context: bytes, witness: bytes) -> dict[str, str]:
    return {
        "statement_sha512": hashlib.sha512(statement).hexdigest(),
        "context_sha512": hashlib.sha512(context).hexdigest(),
        "witness_sha512": hashlib.sha512(witness).hexdigest(),
    }


@functools.lru_cache(maxsize=1)
def _stablecoin_supply_counterexamples() -> dict[str, Any]:
    mint = C.EXECUTABLE.build_fixture(
        0, 0b0100, stable_enabled=True, policy_version=0
    )
    mint_statement = C.EXECUTABLE.Statement.decode(mint.statement)
    mint_witness = C.EXECUTABLE.Witness.decode(mint.witness, True)
    mint_evaluation = C.EXECUTABLE.evaluate(
        mint.statement, mint.context, mint.witness
    )
    mint_case = {
        "name": "stable_output_only_single_key_mint",
        "reconstruction": "build_fixture(mode=0,mask=0b0100,stable_enabled=True,policy_version=0)",
        **_fixture_hashes(mint.statement, mint.context, mint.witness),
        "trace_digest_shake256_512": mint_evaluation.trace_digest_shake256_512,
        "accepted": True,
        "activity_flags_i0_i1_o0_o1": list(mint_statement.flags),
        "authorization_mode": mint_witness.authorization.mode,
        "authorization_auxiliary_all_zero": (
            mint_witness.authorization.current.is_zero()
            and mint_witness.authorization.next.is_zero()
            and all(tag == bytes(64) for tag in mint_witness.authorization.signer_tags)
            and all(master == bytes(64) for master in mint_witness.authorization.policy_masters)
        ),
        "active_input_count": sum(mint_statement.flags[:2]),
        "stable_sign_output_excess": mint_statement.stable_sign,
        "stable_magnitude": mint_statement.stable_magnitude,
        "stable_asset": mint_statement.stable_asset,
        "output_values": [item.note.value for item in mint_witness.outputs],
        "output_assets": [item.note.asset for item in mint_witness.outputs],
        "issuer_authorization_field_present": False,
        "collateral_opening_present": False,
        "oracle_opening_present": False,
        "attestation_opening_present": False,
    }

    cap_transactions = []
    for mask in (0b0100, 0b1000):
        fixture = C.EXECUTABLE.build_fixture(
            0, mask, stable_enabled=True, policy_version=0
        )
        entry = C.EXECUTABLE.Witness.decode(fixture.witness, True).manifest.entry
        capped_entry = dataclasses.replace(entry, max_mint_per_epoch=1)
        statement, context, witness = _manifest_case_with_entry(
            fixture, capped_entry, issuance=1
        )
        evaluation = C.EXECUTABLE.evaluate(statement, context, witness)
        cap_transactions.append(
            {
                "mask": mask,
                "issuance": 1,
                "authenticated_cap": 1,
                "parent_height": 50,
                **_fixture_hashes(statement, context, witness),
                "trace_digest_shake256_512": evaluation.trace_digest_shake256_512,
                "accepted": True,
            }
        )

    ratio_entry = dataclasses.replace(
        mint_witness.manifest.entry, min_collateral_ratio_ppm=(1 << 128) - 1
    )
    ratio_statement, ratio_context, ratio_witness = _manifest_case_with_entry(
        mint, ratio_entry, issuance=1
    )
    ratio_evaluation = C.EXECUTABLE.evaluate(
        ratio_statement, ratio_context, ratio_witness
    )

    anchor_fixture = C.EXECUTABLE.build_fixture(
        0, 0b0100, stable_enabled=False, policy_version=0
    )
    changed_anchor_statement = bytearray(anchor_fixture.statement)
    changed_anchor_statement[14] ^= 1
    changed_anchor_evaluation = C.EXECUTABLE.evaluate(
        bytes(changed_anchor_statement),
        anchor_fixture.context,
        anchor_fixture.witness,
    )
    anchor_case = {
        "name": "output_only_unconstrained_anchor",
        "reconstruction": "build_fixture(mode=0,mask=0b0100,stable_enabled=False); statement[14]^=1",
        "mutated_statement_offset": 14,
        "before_u8": anchor_fixture.statement[14],
        "after_u8": changed_anchor_statement[14],
        "baseline_statement_sha512": hashlib.sha512(
            anchor_fixture.statement
        ).hexdigest(),
        **_fixture_hashes(
            bytes(changed_anchor_statement),
            anchor_fixture.context,
            anchor_fixture.witness,
        ),
        "trace_digest_shake256_512": changed_anchor_evaluation.trace_digest_shake256_512,
        "accepted": True,
        "active_input_count": 0,
    }
    return {
        "permissionless_mint": mint_case,
        "collateral_ratio_unenforced": {
            "name": "maximal_collateral_ratio_without_collateral_opening",
            "min_collateral_ratio_ppm": ratio_entry.min_collateral_ratio_ppm,
            **_fixture_hashes(ratio_statement, ratio_context, ratio_witness),
            "trace_digest_shake256_512": ratio_evaluation.trace_digest_shake256_512,
            "accepted": True,
            "collateral_amount_or_value_field_present": False,
        },
        "epoch_cap_split": {
            "transactions": cap_transactions,
            "both_distinct_transactions_accept": all(
                item["accepted"] for item in cap_transactions
            )
            and cap_transactions[0]["statement_sha512"]
            != cap_transactions[1]["statement_sha512"],
            "aggregate_minted": sum(item["issuance"] for item in cap_transactions),
            "authenticated_max_mint_per_epoch": 1,
            "aggregate_exceeds_cap": True,
            "epoch_identifier_present": False,
            "minted_before_after_state_present": False,
        },
        "no_input_anchor": anchor_case,
        "minimum_missing_model": {
            "mint_authority": "tx-intent-bound unforgeable issuer/collateral capability committed by the authenticated policy row",
            "collateral": "authenticated collateral amount/value plus oracle and attestation openings sufficient to enforce min_collateral_ratio_ppm",
            "epoch_cap": "verifier-owned epoch_id and authenticated per-policy minted_before -> minted_after transition",
            "no_input_anchor": "force zero or force the verifier-authenticated current root; the protocol must choose one canonical rule",
            "identity_effect": "statement, relation, geometry, and release identity must all change",
        },
    }


@functools.lru_cache(maxsize=1)
def _external_native_balance_boundary() -> dict[str, Any]:
    fixture = C.EXECUTABLE.build_fixture(
        0, 0b0100, stable_enabled=False, policy_version=0
    )
    statement = bytearray(fixture.statement)
    witness = bytearray(fixture.witness)
    witness[4_776:4_784] = (1).to_bytes(8, "big")
    note = bytes(witness[4_768:5_000])
    statement[206:270] = C.EXECUTABLE._note_digest(note, "redteam.native.output[0]")
    statement[510] = 0
    statement[511:519] = (1).to_bytes(8, "big")
    parsed = C.EXECUTABLE.Statement.decode(bytes(statement))
    statement[869:933] = C.EXECUTABLE._blake(
        C.EXECUTABLE._balance_message(parsed)
    )
    evaluation = C.EXECUTABLE.evaluate(
        bytes(statement), fixture.context, bytes(witness)
    )
    return {
        "name": "output_only_native_note_with_public_value_balance",
        **_fixture_hashes(bytes(statement), fixture.context, bytes(witness)),
        "trace_digest_shake256_512": evaluation.trace_digest_shake256_512,
        "accepted": True,
        "active_inputs": 0,
        "native_output_value": 1,
        "public_value_balance_sign": 0,
        "public_value_balance_magnitude": 1,
        "production_attack_claimed": False,
        "required_external_invariant": "the action/ledger must authorize and apply the exact public native value balance; the source interpreter does not provide native supply authority",
    }


@functools.lru_cache(maxsize=1)
def _parent_state_counterexample() -> dict[str, Any]:
    fixture = C.EXECUTABLE.build_fixture(0, 0b1111, stable_enabled=True, policy_version=0)
    decoded = C.EXECUTABLE.Witness.decode(fixture.witness, True)
    entry = decoded.manifest.entry
    leaf_person = C.AUTHORITY.personalization(
        C.AUTHORITY.ROLE_LEAF, 64, 16, profile=C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE
    )
    current = hashlib.blake2b(b"\x01" + entry.encode(), digest_size=64, person=leaf_person).digest()
    siblings = []
    for level in range(4):
        siblings.append(current)
        person = C.AUTHORITY.personalization(
            C.AUTHORITY.ROLE_NODE, 64, 16, level, C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE
        )
        current = hashlib.blake2b(current + current, digest_size=64, person=person).digest()
    height = int.from_bytes(fixture.statement[861:869], "big")
    snapshot_person = C.AUTHORITY.personalization(
        C.AUTHORITY.ROLE_SNAPSHOT, 64, 16, profile=C.AUTHORITY.FRESH_V2_AUTHORITY_PROFILE
    )
    snapshot = hashlib.blake2b(
        height.to_bytes(8, "little") + current,
        digest_size=64,
        person=snapshot_person,
    ).digest()
    statement = bytearray(fixture.statement)
    statement[733:797] = current
    statement[797:861] = snapshot
    witness = bytearray(fixture.witness)
    witness[C.MANIFEST_OFFSET :] = (
        (0).to_bytes(4, "little")
        + entry.encode()
        + b"".join(siblings)
        + bytes(5)
    )
    context = current + height.to_bytes(8, "little")
    accepted, observed, constraint_id = _exec_accepts(bytes(statement), context, bytes(witness))
    try:
        C.AUTHORITY.canonical_entries([entry] * 16, 16)
    except Exception as error:
        writer_rejected = True
        writer_observed = f"{type(error).__name__}: {error}"
    else:
        writer_rejected = False
        writer_observed = "accepted"
    return {
        "name": "duplicate_key_manifest_under_caller_supplied_context",
        "semantic_interpreter_accepted": accepted,
        "semantic_observed": observed,
        "constraint_id": constraint_id,
        "canonical_state_writer_rejected": writer_rejected,
        "canonical_state_writer_observed": writer_observed,
        "duplicate_present_rows": 16,
        "production_attack_claimed": False,
        "boundary": (
            "Selected membership is sound relative to the supplied root. Native consensus must authenticate "
            "a root built by the sorted unique cap-16 state writer."
        ),
    }


def _domain_binding_audit() -> dict[str, Any]:
    source_ir = C.EXECUTABLE.hash_call_source_ir()
    core = [item for item in source_ir if item["index"] < 83]
    authority = [item for item in source_ir if item["index"] >= 83]
    fixture = C.EXECUTABLE.build_fixture(0, 0b1111, stable_enabled=True, policy_version=0)
    rules_hash = fixture.statement[1077:1141]
    descriptor = C.PROFILE.descriptor()
    expected_hash = hashlib.sha512(C.PROFILE.descriptor_bytes()).digest()
    fixed_calls = C.PROFILE.hash_call_profiles()
    fixed_by_index = {item["index"]: item for item in fixed_calls}
    exact_persons = all(
        item.get("personalization_hex")
        == C.PROFILE.parameter_profiles()[
            next(
                index
                for index, profile in enumerate(C.PROFILE.parameter_profiles())
                if profile["name"] == fixed_by_index[item["index"]]["parameter_profile"]
            )
        ]["personalization_hex"]
        for item in source_ir
    )
    swapped = json.loads(json.dumps(descriptor))
    swapped_role = swapped["relation_hash_program"]["calls"][0]["role_hex"]
    swapped["relation_hash_program"]["calls"][0]["role_hex"] = (
        (int(swapped_role[:2], 16) ^ 1).to_bytes(1, "big").hex() + swapped_role[2:]
    )
    swapped_hash = hashlib.sha512(C.PROFILE.canonical_json(swapped)).digest()

    substitution_cases = []
    for name, replacement in (
        ("zero_rules_hash", bytes(64)),
        ("historical_fixed_0x33_marker", bytes([0x33]) * 64),
        ("role_swapped_descriptor_hash", swapped_hash),
    ):
        statement = bytearray(fixture.statement)
        statement[1077:1141] = replacement
        accepted, observed, constraint_id = _exec_accepts(
            bytes(statement), fixture.context, fixture.witness
        )
        substitution_cases.append(
            {
                "name": name,
                "accepted": accepted,
                "constraint_id": constraint_id,
                "observed": observed,
            }
        )

    diagnostic_identity = descriptor.get(
        "diagnostic_relation_identity", descriptor.get("consensus_identity")
    )
    if diagnostic_identity is None:
        raise AssertionError("missing diagnostic identity")
    proof_profile = descriptor["proof_system_required_but_unallocated"]
    rejected = set(proof_profile["rejected_legacy_identities"])
    return {
        "core_role_hex_in_symbolic_ir": len(core) == 83 and all(
            isinstance(item.get("role"), str) and len(item["role"]) == 16 for item in core
        ),
        "all_90_fixed_personalizations_match_profile": exact_persons,
        "authority_personalization_hex_in_symbolic_ir": all(
            "personalization_hex" in item for item in authority
        )
        and len(authority) == 7,
        "authority_symbolic_ir_roles": [item.get("role") for item in authority],
        "compiler_executable_boolean_sources_in_source_set": {
            rel(COMPILER_PATH),
            rel(C.EXECUTABLE_PATH),
            rel(C.BOOLEAN_BLAKE_PATH),
        }.issubset({item["path"] for item in C.source_entries()}),
        "statement_rules_hash_hex": rules_hash.hex(),
        "statement_rules_hash_equals_sha512_canonical_profile": rules_hash == expected_hash,
        "role_swap_changes_rules_hash": swapped_hash != expected_hash,
        "rules_hash_substitution_cases": substitution_cases,
        "all_rules_hash_substitutions_reject": all(
            not item["accepted"] for item in substitution_cases
        ),
        "compiler_source_digest_inside_rules_hash": False,
        "compiler_source_digest_bound_only_by_release_source_set": True,
        "diagnostic_only": not diagnostic_identity["final_consensus_rules_hash_frozen"],
        "production_identity_allocated": diagnostic_identity.get(
            "production_identity_allocated", False
        ),
        "fresh_proof_profile_allocated": proof_profile["final_profile_frozen"],
        "engine_adapter_integrated": proof_profile["engine_adapter_integrated"],
        "legacy_proof_identities_rejected_not_reinterpreted": {
            "DirectPacked64CompressedV6Sha512Smz2",
            "SMZ2",
            "SWV6",
            "HGV6PB02",
            "HGS6BC02",
            "K64",
            "64-byte strict-ZK leaf tape",
        }.issubset(rejected),
        "proof_profile_fields_are_null": all(
            proof_profile[key] is None
            for key in (
                "fresh_arithmetization_identity",
                "packing_factor",
                "pcs_parameters",
                "piop_parameters",
                "decs_parameters",
                "complete_zk_mask_width_and_tape_grammar",
                "fiat_shamir_transcript",
                "transcript_domain_registry",
                "inner_wire_magic",
                "outer_envelope_magic",
                "outer_envelope_version",
                "statement_and_context_binding_preamble",
            )
        ),
        "consensus_registry_or_rules_hash_binding_present": True,
        "production_binding_complete": False,
    }


def _lifecycle_binding_inventory() -> dict[str, Any]:
    stage_paths = OrderedDict(
        wallet=(
            "wallet/src/prover.rs",
            "wallet/src/tx_builder.rs",
            "wallet/src/submission.rs",
            "wallet/src/rpc.rs",
        ),
        rpc=("node/src/native/rpc.rs", "node/src/native/service.rs"),
        relay=("network/src/native_transport.rs", "node/src/native/service.rs"),
        durable_mempool=("node/src/native/storage.rs", "node/src/native/node_impl.rs"),
        mining=("node/src/native/mining.rs", "node/src/native/block_flow.rs"),
        block=("node/src/native/block_flow.rs", "node/src/native/block_store_v3.rs"),
        sync=("node/src/native/service.rs", "node/src/native/block_flow.rs"),
        reorg=("node/src/native/reorg_wal.rs", "node/src/native/fork_retention.rs"),
        fresh_node=(
            "node/src/native/storage.rs",
            "node/src/native/block_store_v3.rs",
            "node/src/native/node_impl.rs",
        ),
    )
    identity_tokens = (
        "HX512B01",
        "0x5121",
        "0x512B",
        "0x5123",
        "0x5124",
        "0x5127",
    )
    stages = []
    for name, paths in stage_paths.items():
        files = []
        hits = 0
        for relative in paths:
            path = ROOT / relative
            content = path.read_text() if path.is_file() else ""
            per_file_hits = sum(content.count(token) for token in identity_tokens)
            hits += per_file_hits
            files.append(
                {
                    "path": relative,
                    "exists": path.is_file(),
                    "sha512": sha512_file(path) if path.is_file() else None,
                    "hx512_identity_token_hits": per_file_hits,
                }
            )
        stages.append(
            {
                "stage": name,
                "files": files,
                "hx512_identity_token_hits": hits,
                "canonical_hx512_proof_identity_bound": False,
                "same_proof_bytes_roundtrip_tested": False,
                "stage_specific_mutations_tested": False,
            }
        )
    residuals = C.EXECUTABLE.mutation_residuals()
    return {
        "canonical_self_contained_proof_exists": False,
        "proof_bytes": None,
        "proof_parser_exists": False,
        "proof_envelope_identity_allocated": False,
        "stages": stages,
        "all_production_stage_identity_hits_zero": all(
            item["hx512_identity_token_hits"] == 0 for item in stages
        ),
        "source_interpreter_surface": {
            "statement_exact_width_and_identity": True,
            "verifier_context_exact_width": True,
            "private_witness_exact_width_and_padding": True,
            "network_version_domain_action_fields_in_statement": True,
            "ciphertext_bytes_sizes_hashes": True,
            "nullifier_derivation_and_public_slots": True,
            "merkle_path_position_and_anchor_for_active_inputs": True,
            "intent_binding_for_final_threshold_mode": True,
            "manifest_parent_root_height_and_snapshot": True,
            "no_input_anchor_canonicality": False,
            "native_action_to_statement_binding": False,
            "native_value_balance_state_transition": False,
            "stablecoin_epoch_supply_state_transition": False,
            "note_tree_and_nullifier_successor_state_binding": False,
            "proof_bytes_to_statement_context_preamble": False,
        },
        "source_interpreter_mutation_residuals": len(residuals),
        "all_source_interpreter_mutation_residuals_reject": all(
            item["observed"] == "reject" for item in residuals
        ),
        "missing_required_mutation_and_restart_gates": [
            "canonical proof parse/serialize identity and trailing-byte rejection",
            "proof-bit mutation rejection after every transport/persistence stage",
            "statement/proof/action duplicated-field mismatch rejection",
            "RPC request and relay wire truncation/extension/noncanonical encoding",
            "durable mempool restart readback with byte-identical proof",
            "mining selection and block encoding byte identity",
            "announced and sync-imported block verification from proof bytes alone",
            "reorg rollback/replay re-verification without receipts/caches/sidecars",
            "fresh-node genesis-to-tip replay and corrupted-store fail-closed behavior",
            "native parent-root/height, note-tree, nullifier, native-balance, and stablecoin epoch successor-state mutation rejection",
        ],
        "validity_sidecars_receipts_or_caches_allowed": False,
        "production_lifecycle_complete": False,
    }


def _pin_audit_v2() -> dict[str, Any]:
    try:
        C.source_contracts()
    except Exception as error:
        contract = {"passes": False, "observed": f"{type(error).__name__}: {error}"}
    else:
        contract = {"passes": True, "observed": "pass"}
    entries = {item["path"]: item for item in C.source_entries()}
    line_key = rel(C.KERNEL_LIB_PATH) + "#exact-export-line"
    line = entries.get(line_key)
    encoded = C.KERNEL_V2_EXPORT_LINE.encode("utf-8")
    behavior_bound = (
        line is not None
        and line.get("occurrences") == 1
        and line.get("bytes") == len(encoded)
        and line.get("sha512") == hashlib.sha512(encoded).hexdigest()
        and C.KERNEL_LIB_PATH.read_text().splitlines().count(C.KERNEL_V2_EXPORT_LINE) == 1
    )
    frozen = []
    for name, expected in sorted(C.EXPECTED_DEPENDENCY_SHA512.items()):
        path = ROOT / name
        observed = sha512_file(path) if path.is_file() else None
        frozen.append({"path": name, "expected": expected, "observed": observed, "match": observed == expected})
    return {
        "source_contract": contract,
        "compiler_sha512": sha512_file(COMPILER_PATH),
        "executable_relation_sha512": sha512_file(C.EXECUTABLE_PATH),
        "boolean_trace_sha512": sha512_file(C.BOOLEAN_BLAKE_PATH),
        "frozen_dependencies": frozen,
        "all_frozen_dependency_hashes_match": all(item["match"] for item in frozen),
        "kernel_whole_shared_file_pinned": False,
        "kernel_exact_behavioral_export_line_bound": behavior_bound,
        "unpinned_behavioral_dependency": None if behavior_bound else rel(C.KERNEL_LIB_PATH),
    }


def _policy_master_v2(program: Any) -> dict[str, Any]:
    semantics = executable_semantics_audit()
    groups = {item["name"]: item for item in program.export_groups()}
    source_ir = C.EXECUTABLE.hash_call_source_ir()
    return {
        "exact_schedule": [
            {"mode": "single", "current": "zero/dummy", "next": "zero/dummy"},
            {"mode": "init", "policy": "next", "slot0": "next", "slot1": "dummy", "current": "zero"},
            {"mode": "approval", "policy": "current", "slot0": "current", "slot1": "next", "current_equals_next": True},
            {"mode": "value_lock", "policy": "current", "slot0": "current", "slot1": "dummy", "next": "zero"},
            {"mode": "final", "policy": "current", "slot0": "current", "slot1": "current", "next": "zero"},
        ],
        "semantic_interpreter_all_modes_confirmed": semantics["positive_fixtures"]["all_accept"],
        "hash_source_ir_master_mapping_named": all(
            "master_mapping" in item for item in source_ir if item["index"] in range(75, 79)
        ),
        "policy_version_zero_accepted_fixtures": semantics["positive_fixtures"]["stablecoin_enabled_policy_version_zero"],
        "accumulator_metadata_group_rows": groups[C.BASE.LOCAL_GROUPS[14]]["rows"],
        "approval_transition_group_rows": groups[C.BASE.LOCAL_GROUPS[15]]["rows"],
        "selected_policy_master_rows": 512,
        "approval_master_equality_rows": 512,
        "padding_rows": 0,
        "numeric_sparse_operand_wiring_retained": False,
    }


def _characteristic_two_v2(corrected_m: int) -> dict[str, Any]:
    result = characteristic_two_counterexamples()
    result["verdict"] = (
        f"m={corrected_m:,} is an odd-Goldilocks source-cost projection. "
        "add_lsb/add_carry lose coefficient 2 in characteristic two, while mode_onehot5 "
        "and cond_sum4 degrade to parity. It is not a binary, GF(2^s), Binius, or Aurora relation."
    )
    return result


def _radix4_k1024_control_audit() -> dict[str, Any]:
    return {
        "scope": "adjacent conditional source-static K=1024 radix-4 SmallWood screen; not the odd-field compiler",
        "rfc_control_xors_per_compression": [
            "v12 ^= t0",
            "v13 ^= t1",
            "v14 ^= f0",
        ],
        "compressions": 213,
        "control_xor_words": 639,
        "old_unrepresented_control_words": 639,
        "old_direct_radix4_rows_at_k1024": 20,
        "fully_fixed_control_tuples": 205,
        "private_mode_selected_auth_control_positions": 8,
        "private_selected_words": 16,
        "private_selected_radix4_digits": 512,
        "required_selected_control_equations": 512,
        "selected_control_row_used_cells": 512,
        "selected_control_row_zero_padding_cells": 512,
        "coherent_treatment": (
            "Constant-fold the 205 fixed tuples into schedule/profile-digest-bound static operands. "
            "For the 8 authorization block-2/block-3 positions, derive v12^t0 and v14^f0 "
            "from canonical committed authorization-mode one-hot selectors; v13 is fixed because t1=0."
        ),
        "alignment_obligation": (
            "The 512 selected first-XOR uses and 512 fixed-control first-XOR uses must share one "
            "aligned gate batch. If the executable indexer cannot prove that alignment, add rows and recount."
        ),
        "conditional_core_rows": 11_052,
        "source_rows": 48,
        "message_rows": 107,
        "conditional_total_rows": 11_207,
        "conditional_inner_bytes_current_64_byte_wire": 1_372_954,
        "additional_selected_control_linear_equations": 512,
        "core_zero_padding_cells": 2_176,
        "known_minimum_linear_checks_including_source_message_padding": 5_319_980,
        "digest_state2_state3_selection_included": False,
        "full_nonhash_selector_and_broadcast_rows_allocated": False,
        "screen_is_executable_or_measured_proof": False,
        "verdict": "R=11,206 and 1,372,874 bytes are disqualified; R=11,207 and 1,372,954 bytes remain conditional until an executable aligned indexer and digest-state mux exist",
    }


@functools.lru_cache(maxsize=1)
def build_counterfeit_corpus() -> dict[str, Any]:
    cases = list(executable_counterfeit_cases())
    residuals = list(C.EXECUTABLE.mutation_residuals())
    parent = _parent_state_counterexample()
    supply = _stablecoin_supply_counterexamples()
    native_balance = _external_native_balance_boundary()
    return {
        "artifact_schema": "hegemon.hx512b01.full-relation-redteam.counterfeits.v2",
        "target_sha512": {
            "compiler": sha512_file(COMPILER_PATH),
            "executable_relation": sha512_file(C.EXECUTABLE_PATH),
            "boolean_trace": sha512_file(C.BOOLEAN_BLAKE_PATH),
            "verifier_profile": sha512_file(C.PROFILE_PATH),
        },
        "core_mutations": cases,
        "core_mutations_rejected": sum(not item["executable_relation_accepted"] for item in cases),
        "retained_semantic_residuals": residuals,
        "all_retained_semantic_residuals_reject": all(item["observed"] == "reject" for item in residuals),
        "characteristic_two_counterexamples": characteristic_two_counterexamples()["cases"],
        "stablecoin_supply_counterexamples": supply,
        "external_native_value_balance_boundary": native_balance,
        "parent_state_boundary_counterexample": parent,
        "claim_boundary": (
            "Core rejections are positive evidence for the source interpreter only. Stablecoin mint and epoch-cap cases "
            "are accepted by the current interpreter and block semantic promotion. The native value-balance case records "
            "an external action/state-transition obligation rather than claiming inflation in isolation. The duplicate-key "
            "case is accepted solely under a caller-supplied unauthenticated context and demonstrates the native state-writer obligation."
        ),
    }


@functools.lru_cache(maxsize=1)
def build_report() -> dict[str, Any]:
    program = compile_without_pin_gate()
    recount_result = recount(program)
    geometry = _corrected_geometry(program, recount_result)
    corrected = geometry["corrected_source_cost_projection"]
    semantics = executable_semantics_audit()
    byte_scan = executable_byte_mutation_scan()
    branches = _branch_coverage()
    parameters = _constant_parameter_audit()
    streaming = _all66_streaming_audit()
    target_boolean = C.boolean_hash_trace_certificate()
    hash_negatives = _hash_negative_mutations()
    domain = _domain_binding_audit()
    parent = _parent_state_counterexample()
    pins = _pin_audit_v2()
    policy = _policy_master_v2(program)
    authority_semantics = _authority_semantic_audit()
    char2 = _characteristic_two_v2(corrected["m_constraints"])
    supply = _stablecoin_supply_counterexamples()
    native_balance = _external_native_balance_boundary()
    lifecycle = _lifecycle_binding_inventory()
    radix4 = _radix4_k1024_control_audit()
    corpus = build_counterfeit_corpus()
    findings = [
        {
            "id": "HX512-RT-001",
            "severity": "blocker",
            "title": "Executable source semantics are not a numeric sparse R1CS lowering",
            "evidence": {
                "semantic_positive_fixtures": semantics["positive_fixtures"]["total"],
                "named_source_operands": True,
                "numeric_r1cs_operand_ids": False,
                "intermediate_hash_variables": False,
                "sparse_rows": False,
            },
            "required_fix": "Retain numeric intermediate variables and canonical sparse A/B/C rows, then evaluate arbitrary supplied row witnesses and prove interpreter-to-row acceptance parity.",
        },
        {
            "id": "HX512-RT-002",
            "severity": "blocker",
            "title": "Stablecoin output-only mint requires no issuer or collateral authorization",
            "evidence": {
                "counterfeit": supply["permissionless_mint"],
                "maximal_collateral_ratio_still_accepts": supply[
                    "collateral_ratio_unenforced"
                ],
            },
            "source_anchors": [
                ".agent/hardening/hx512-full-relation-compile/executable_relation.py:637",
                ".agent/hardening/hx512-full-relation-compile/executable_relation.py:762",
                ".agent/hardening/hx512-full-relation-compile/executable_relation.py:1299",
                ".agent/hardening/hx512-full-relation-compile/executable_relation.py:1467",
                ".agent/hardening/manifest-authority-closure/manifest_authority.py:1527",
                ".agent/hardening/manifest-authority-closure/manifest_authority.py:1725",
            ],
            "required_fix": "Reject positive issuance until an authenticated policy commits an unforgeable issuer/collateral capability over the exact transaction intent, asset, version, magnitude, epoch, and outputs; open and constrain collateral/oracle/attestation data against min_collateral_ratio_ppm.",
        },
        {
            "id": "HX512-RT-003",
            "severity": "blocker",
            "title": "max_mint_per_epoch is only a per-transaction comparison",
            "evidence": supply["epoch_cap_split"],
            "source_anchors": [
                ".agent/hardening/manifest-authority-closure/manifest_authority.py:1527",
                ".agent/hardening/manifest-authority-closure/manifest_authority.py:1725",
                "protocol/kernel/src/stablecoin_manifest_authority_v2.rs:1077",
                "node/src/native/admission.rs:773",
            ],
            "required_fix": "Add verifier-owned per-policy epoch_id and authenticated minted_before -> minted_after state, constrain supply-increasing deltas cumulatively, bind the successor through ordered block replay/restart/reorg, or rename the field and remove every per-epoch claim.",
        },
        {
            "id": "HX512-RT-004",
            "severity": "high",
            "title": "Output-only mode leaves the public anchor noncanonical",
            "evidence": supply["no_input_anchor"],
            "required_fix": "For every no-active-input shape, require anchor to one specified canonical value: either zero or the verifier-authenticated current note root; bind the same rule in action parsing and every lifecycle stage.",
        },
        {
            "id": "HX512-RT-005",
            "severity": "blocker",
            "title": "Odd-field geometry cannot be reinterpreted in characteristic two",
            "evidence": char2["cases"],
            "required_fix": "Compile a separate binary relation with sound carry and cardinality constraints; never reuse these m/n/nnz values for Aurora, Binius, or GF(2^s).",
        },
        {
            "id": "HX512-RT-006",
            "severity": "blocker",
            "title": "No canonical proof identity or byte lifecycle is allocated or integrated",
            "evidence": {
                "profile": domain,
                "lifecycle": lifecycle,
                "external_native_value_balance_boundary": native_balance,
            },
            "required_fix": "Freeze a fresh K1024-or-better theorem-faithful complete-ZK proof profile and new wire identity, compile the native rules hash, carry one proof byte string unchanged through every lifecycle stage, and execute the listed parser/mutation/restart/reorg/fresh-node gates. Never reinterpret SMZ2/K64/SWV6/HGV6PB02/HGS6BC02 or 64-byte tapes.",
        },
        {
            "id": "HX512-RT-007",
            "severity": "high",
            "title": "Selected membership does not authenticate global sorted unique cap-16 parent state",
            "evidence": parent,
            "required_fix": "Keep global canonicality verifier-owned, then refine the native state writer and every mempool/mining/block/sync/restart/reorg context derivation to the authenticated parent root and height.",
        },
        {
            "id": "HX512-RT-008",
            "severity": "blocker",
            "title": "Projected n and nnz are not realizable-matrix measurements",
            "evidence": {
                "macro_ledger_reconciles": recount_result["arithmetic_ledger_reconciles"],
                "operand_identity_invocations": recount_result["invocations_with_operand_or_wire_identity"],
                "expanded_sparse_matrix": False,
            },
            "required_fix": "Recompute n and nnz from retained sparse rows after aliasing, constant folding, and coefficient merging; forbid padding as relation rows.",
        },
        {
            "id": "HX512-RT-009",
            "severity": "blocker",
            "title": "The K1024 radix-4 screen still has conditional control and digest-selection topology",
            "evidence": radix4,
            "required_fix": "Retain an executable public/secret-independent indexer that derives the 16 private-mode-selected control words from canonical one-hot selectors, proves their consuming-gate alignment, and separately implements the state2/state3 digest mux before treating R=11,207 or 1,372,954 bytes as a source-static baseline.",
        },
        {
            "id": "HX512-RT-010",
            "severity": "blocker",
            "title": "Frozen generated compiler artifacts do not read back",
            "evidence": pins["source_contract"],
            "required_fix": "After the shared checkpoint is stable, regenerate every source-bound manifest/certificate/mutation artifact, repair the upstream authority artifact drift, rerun dependency-free readback, and freeze hashes without changing the fail-closed flags.",
        },
    ]
    return {
        "artifact": "HX512 full-relation compiler independent red-team audit",
        "artifact_schema": "hegemon.hx512b01.full-relation-redteam.audit.v2",
        "target": rel(COMPILER_PATH),
        "target_sha512": sha512_file(COMPILER_PATH),
        "verdict": "STABLECOIN_SEMANTIC_COUNTERFEITS_ACCEPT_RELATION_LOWERING_PROOF_PROFILE_LIFECYCLE_SECURITY_REFINEMENT_AND_PRODUCTION_FAIL_CLOSED",
        "findings": findings,
        "geometry_recount": recount_result,
        "corrected_geometry": geometry,
        "constant_parameter_and_personalization": parameters,
        "layout_and_endianness": _layout_v2(),
        "byte_mutation_scan": byte_scan,
        "boolean_byte_high_bits": _boolean_high_bit_checks_v2(),
        "all_16_masks_all_5_modes_both_stable_branches": branches,
        "policy_master_modes": policy,
        "all_w64_authority_semantics": authority_semantics,
        "stablecoin_supply_counterexamples": supply,
        "external_native_value_balance_boundary": native_balance,
        "executable_semantics_and_hash_calls": semantics,
        "all66_streaming_boolean_audit": streaming,
        "target_retained_boolean_certificate": target_boolean,
        "role_and_personalization_negative_mutations": hash_negatives,
        "domain_and_consensus_binding": domain,
        "wallet_to_fresh_node_lifecycle_binding": lifecycle,
        "parent_state_boundary": parent,
        "characteristic_two": char2,
        "radix4_k1024_control_topology": radix4,
        "source_pins": pins,
        "repaired_checkpoint_gates": {
            "fixed_parameter_rows_constant_folded_to_zero": parameters[
                "target_constant_folds_all_fixed_parameters"
            ],
            "exact_corrected_odd_field_projection": geometry[
                "target_matches_corrected_projection"
            ],
            "all_160_mask_mode_stable_cells_evaluated": branches[
                "full_160_cell_evaluator_contract_satisfied"
            ],
            "all_66_hash_call_streams_match_hashlib": target_boolean[
                "all_66_call_digests_equal_independent_hashlib"
            ],
            "selected_init_approval_final_every_bit_rows_evaluated": all(
                item["every_bit_row_evaluated"]
                for item in target_boolean["selected_exhaustive_traces"]
            ),
            "exact_role_and_personalization_mutations_reject": hash_negatives[
                "all_role_or_personalization_mutations_reject"
            ],
            "diagnostic_rules_hash_substitutions_reject": domain[
                "all_rules_hash_substitutions_reject"
            ],
            "legacy_proof_identities_explicitly_rejected": domain[
                "legacy_proof_identities_rejected_not_reinterpreted"
            ],
            "fresh_proof_profile_remains_null": domain[
                "proof_profile_fields_are_null"
            ],
        },
        "counterfeit_corpus_digest_sha512": hashlib.sha512(canonical_json(corpus)).hexdigest(),
        "required_boolean_coverage": {
            "all66_streaming_calls": 5_940,
            "all66_streaming_compressions": 14_058,
            "corrected_all66_boolean_rows": 1_917_286_272,
            "selected_exhaustive_fixtures": [
                {"mode": "accumulator_init", "mask": 15},
                {"mode": "approval_step", "mask": 15},
                {"mode": "final_threshold_spend", "mask": 15},
            ],
            "selected_exhaustive_corrected_rows": 87_149_376,
            "unique_constant_initial_state_kats": 8,
        },
        "authority": {
            "executable_source_interpreter_present": True,
            "full_production_relation_semantically_complete": False,
            "corrected_source_cost_projection_present": True,
            "generated_source_bound_artifacts_read_back": False,
            "numeric_sparse_r1cs_lowering": False,
            "scalar_to_relation_refinement_proved": False,
            "complete_zero_knowledge_proved": False,
            "composed_qrom_pq128_proved": False,
            "exact_native_verifier_refinement_proved": False,
            "consensus_parent_state_authentication_refined": False,
            "proof_built": False,
            "proof_bytes": None,
            "production_authorized": False,
            "release_manifest_authorized": False,
        },
    }


def outputs() -> dict[Path, bytes]:
    corpus = build_counterfeit_corpus()
    report = build_report()
    # The digest inside report is over exactly the independently generated
    # corpus bytes, so rebuilding in either order is deterministic.
    if report["counterfeit_corpus_digest_sha512"] != hashlib.sha512(
        canonical_json(corpus)
    ).hexdigest():
        raise AssertionError("counterfeit digest drift")
    return {REPORT_PATH: canonical_json(report), CORPUS_PATH: canonical_json(corpus)}


def write_outputs() -> None:
    for path, payload in outputs().items():
        path.write_bytes(payload)


def check_outputs() -> None:
    for path, expected in outputs().items():
        if not path.is_file() or path.read_bytes() != expected:
            raise AssertionError(f"stale or missing red-team artifact: {path.name}")


def summary() -> str:
    report = build_report()
    geometry = report["geometry_recount"]["expected_geometry"]
    supply = report["stablecoin_supply_counterexamples"]
    return (
        "PASS audit-only "
        f"m_template={geometry['m_constraints']} "
        f"accepted_semantic_counterfeits={int(supply['permissionless_mint']['accepted']) + 2 + int(supply['no_input_anchor']['accepted'])} "
        "sparse_relation=false binary_relation=false proof=false production=false"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)
    if sum((args.write, args.check, args.summary)) != 1:
        parser.error("select exactly one mode")
    if args.write:
        write_outputs()
    elif args.check:
        check_outputs()
    else:
        print(summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
