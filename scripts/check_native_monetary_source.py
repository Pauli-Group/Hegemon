#!/usr/bin/env python3
"""Compare selected Rust monetary source execution with pinned Lean JSON.

The caller must run this under its resource/quota guard. This is finite source
conformance, not a complete node refinement, circulating-supply or absence proof.
All generated files remain in a fresh caller-selected scratch directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


CONSTANT_NAMES = (
    "COIN", "T_YEAR", "T_BLOCK_SECONDS", "Y_EPOCH", "BLOCKS_PER_EPOCH",
    "T_EPOCH_SECONDS", "MAX_SUPPLY", "INITIAL_SUBSIDY", "HALVING_INTERVAL",
)
LEAN_CONSTANT_NAMES = {
    "COIN": "coin", "T_YEAR": "year_seconds",
    "T_BLOCK_SECONDS": "target_block_seconds", "Y_EPOCH": "epoch_years",
    "T_EPOCH_SECONDS": "epoch_seconds",
    "HALVING_INTERVAL": "halving_interval", "MAX_SUPPLY": "max_monetary_supply",
    "INITIAL_SUBSIDY": "initial_subsidy",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned_bytes(path: Path, expected: str, label: str) -> bytes:
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
            f"{label}: SHA256 must be 64 lowercase hex characters")
    data = path.read_bytes()
    require(digest(data) == expected, f"{label}: SHA256 mismatch")
    return data


def natural(value: object, label: str, maximum: int | None = None) -> int:
    if isinstance(value, str):
        require(re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
                f"{label}: expected canonical decimal integer")
        value = int(value)
    require(type(value) is int and value >= 0, f"{label}: expected natural integer")
    require(maximum is None or value <= maximum, f"{label}: out of range")
    return value


def rust_code_mask(source: str) -> str:
    """Preserve offsets/braces in Rust code; mask comments and string literals."""
    chars = list(source)
    i = 0
    while i < len(source):
        start = i
        if source.startswith("//", i):
            i = source.find("\n", i)
            if i < 0:
                i = len(source)
        elif source.startswith("/*", i):
            depth = 1
            i += 2
            while depth and i < len(source):
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            require(depth == 0, "unterminated Rust block comment")
        elif source[i] == '"':
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise ValueError("unterminated Rust string")
        else:
            i += 1
            continue
        for j in range(start, min(i, len(source))):
            if chars[j] != "\n":
                chars[j] = " "
    return "".join(chars)


def function_slice(source: str, name: str) -> tuple[str, int, int]:
    masked = rust_code_mask(source)
    pattern = rf"(?m)^\s*pub(?:\([^\n)]*\))?\s+(?:const\s+)?fn\s+{re.escape(name)}\s*\("
    matches = list(re.finditer(pattern, masked))
    require(len(matches) == 1, f"expected exactly one function {name}")
    # Leading whitespace in the mask may include documentation comments.
    # Begin at the declaration token in the mask, preserving source offsets.
    start = masked.index("pub", matches[0].start(), matches[0].end())
    opening = masked.find("{", matches[0].end())
    require(opening >= 0, f"{name}: missing body")
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1], start, index + 1
    raise ValueError(f"{name}: unterminated body")


def monetary_slices(source: str) -> tuple[str, str, list[dict]]:
    masked = rust_code_mask(source)
    starts = list(re.finditer(r"(?m)^pub const COIN\s*:", masked))
    ends = list(re.finditer(r"(?m)^pub const HALVING_INTERVAL\s*:[^;]*;", masked))
    require(len(starts) == len(ends) == 1, "monetary constant segment is ambiguous")
    start, end = starts[0].start(), ends[0].end()
    require(start < end, "monetary constant segment is reversed")
    segment = source[start:end]
    names = tuple(re.findall(r"\bpub const ([A-Z_]+)\s*:", rust_code_mask(segment)))
    require(names == CONSTANT_NAMES, "unexpected monetary constants or source order")
    pieces = [("constants", segment, start, end)]
    functions = []
    for name, argument in (("block_subsidy", "height"),
                           ("remaining_subsidy_budget", "epoch"),
                           ("epoch_subsidy_budget", "epoch"),
                           ("scheduled_subsidy", "height")):
        function, lo, hi = function_slice(source, name)
        pattern = (rf"pub\s+(?:const\s+)?fn\s+{name}\s*\(\s*{argument}:\s*u64\s*\)"
                   r"\s*->\s*u64\s*\{[\s\S]*\}")
        require(re.fullmatch(pattern, function) is not None, f"{name} signature changed")
        functions.append(function)
        pieces.append((name, function, lo, hi))
    slices = []
    for label, text, lo, hi in pieces:
        slices.append({"name": label, "sha256": digest(text.encode()),
                       "start_byte": len(source[:lo].encode()),
                       "end_byte_exclusive": len(source[:hi].encode()),
                       "start_line": source.count("\n", 0, lo) + 1,
                       "end_line": source.count("\n", 0, hi) + 1})
    return segment, "\n\n".join(functions), slices


def static_genesis(root: Path, genesis_json: dict) -> dict:
    path = root / "node/src/native/storage.rs"
    data = path.read_bytes()
    source = data.decode("utf-8")
    function_name = "genesis_meta_for_network" if re.search(r"\bfn genesis_meta_for_network\b", source) else "genesis_meta"
    text, start, end = function_slice(source, function_name)
    code = re.sub(r"\s+", "", rust_code_mask(text))
    required = (
        "letstate_root=CommitmentTreeState::default().root();",
        "letnullifier_root=NullifierAccumulator::new().root();",
        "native_da_params_for_transactions(&[])?",
        "consensus::encode_da_blob(&[],da_params)",
        "height:0,", "supply_digest:0,", "tx_count:0,",
        "action_bytes:Vec::new(),", "message_count:0,",
        "letextrinsics_root=empty_extrinsics_root(0);",
        "letmessage_root=empty_bridge_message_root();",
    )
    for literal in required:
        require(literal in code, f"static genesis shape missing {literal}")
    require(re.search(r"\.(?:append|insert|extend|push)\(", code) is None,
            "static genesis has a state insertion or append")
    require(re.search(r"\b(?:mint|coinbase|allocation|balance)\w*\s*\(",
                      rust_code_mask(text), re.I) is None,
            "static genesis has a possible issuance function call")
    require(type(genesis_json.get("schema_version")) is int
            and genesis_json["schema_version"] == 1, "unsupported Lean genesis schema")
    require(genesis_json.get("boundary") ==
            "fresh-native-genesis-monetary-projection-not-universal-rust-refinement",
            "Lean genesis artifact boundary mismatch")
    cases = genesis_json.get("genesis_monetary_policy_cases")
    require(isinstance(cases, list) and bool(cases), "missing actual Lean genesis cases")
    expected_fields = (
        "expected_height", "expected_supply_digest", "expected_tx_count",
        "expected_message_count", "expected_action_bytes_len",
        "expected_funded_native_note_count", "expected_nullifier_count",
        "expected_coinbase_allocation", "expected_genesis_subsidy",
    )
    names = set()
    for case in cases:
        require(isinstance(case, dict), "invalid Lean genesis case")
        name = case.get("name")
        require(isinstance(name, str) and name and name not in names,
                "missing or duplicate Lean genesis case name")
        names.add(name)
        for context_field in ("pow_bits", "network_tag", "timestamp_ms"):
            natural(case.get(context_field), f"{name}.{context_field}")
        for field in expected_fields:
            require(natural(case.get(field), f"{name}.{field}") == 0,
                    f"Lean genesis projection is nonzero: {name}.{field}")
    require(names == {"native-default-pow", "easier-valid-compact-pow",
                      "bitcoin-style-compact-pow"},
            "actual Lean genesis generator case set mismatch")
    return {"status": "STATIC_SOURCE_SHAPE_PASS", "path": str(path),
            "source_sha256": digest(data), "function": function_name,
            "slice_sha256": digest(text.encode()),
            "lean_genesis_case_names": sorted(names),
            "lean_genesis_zero_fields": list(expected_fields),
            "start_line": source.count("\n", 0, start) + 1,
            "end_line": source.count("\n", 0, end) + 1,
            "rust_genesis_executed": False, "whole_code_no_allocation_proved": False}


MODE = "epoch-budget-prefix-differences-v1"
MAX_U64 = (1 << 64) - 1
APPROVED_CONSTANTS = {
    "COIN": 100_000_000, "T_YEAR": 31_536_000, "T_BLOCK_SECONDS": 60,
    "Y_EPOCH": 4, "BLOCKS_PER_EPOCH": 2_100_000,
    "T_EPOCH_SECONDS": 126_000_000, "MAX_SUPPLY": 2_100_000_000_000_000,
    "INITIAL_SUBSIDY": 500_000_000, "HALVING_INTERVAL": 2_100_000,
}


def vector_requests(supply: dict, cap: dict) -> dict:
    for artifact in (supply, cap):
        require(type(artifact.get("schema_version")) is int
                and artifact["schema_version"] == 2, "schema2 emission vectors required")
    require(supply.get("emission_model") == cap.get("schedule_mode") == MODE,
            "exact emission model identity required")
    require(natural(cap.get("subsidy_bucket_count"), "positive budgets") == 51,
            "expected 51 positive-budget epochs")
    require(natural(cap.get("max_schedule_epoch"), "shift bound") == 64,
            "expected explicit 64-epoch shift bound")
    exact_total = natural(cap.get("exact_total_subsidy_base_units"), "exact total", MAX_U64)
    require(exact_total == APPROVED_CONSTANTS["MAX_SUPPLY"], "exact cap total mismatch")
    lean_constants = supply.get("monetary_constants")
    require(isinstance(lean_constants, dict), "missing Lean monetary constants")
    for rust_name, lean_name in LEAN_CONSTANT_NAMES.items():
        require(natural(lean_constants.get(lean_name), lean_name) == APPROVED_CONSTANTS[rust_name],
                f"unapproved constant {lean_name}")
    for key, value in (("coin", APPROVED_CONSTANTS["COIN"]),
                       ("halving_interval", APPROVED_CONSTANTS["HALVING_INTERVAL"]),
                       ("max_monetary_supply", exact_total),
                       ("initial_subsidy_base_units", APPROVED_CONSTANTS["INITIAL_SUBSIDY"]),
                       ("last_positive_height", 107_100_000), ("cutoff_height", 107_100_001)):
        require(natural(cap.get(key), key) == value, f"cap constant mismatch {key}")
    heights, epochs, slots, families = {}, {}, {}, {}
    interval = APPROVED_CONSTANTS["HALVING_INTERVAL"]

    def merge(target: dict, key: object, fields: dict, label: str) -> None:
        row = target.setdefault(key, {})
        for field, value in fields.items():
            value = natural(value, f"{label}.{field}", MAX_U64)
            require(field not in row or row[field] == value, f"conflicting vector {label}.{field}")
            row[field] = value

    def cases(artifact: dict, field: str, named: bool = True) -> list:
        rows = artifact.get(field)
        require(isinstance(rows, list) and rows, f"missing actual vector cases {field}")
        names = set()
        for row in rows:
            require(isinstance(row, dict), f"invalid vector case {field}")
            if named:
                name = row.get("name")
                require(isinstance(name, str) and name and name not in names,
                        f"missing or duplicate case name {field}")
                names.add(name)
        families[("supply." if artifact is supply else "cap.") + field] = {
            "count": len(rows), "names": sorted(names)}
        return rows

    for row in cases(supply, "subsidy_schedule_cases"):
        height = natural(row.get("height"), row["name"], MAX_U64)
        merge(heights, height, {"epoch": row.get("expected_halving_epoch"),
                               "budget": row.get("expected_epoch_budget"),
                               "subsidy": row.get("expected_subsidy"),
                               "prefix": row.get("expected_scheduled_subsidy")}, row["name"])
    for row in cases(supply, "epoch_budget_cases"):
        epoch = natural(row.get("epoch"), row["name"], MAX_U64)
        merge(epochs, epoch, {"remaining": row.get("expected_remaining_budget"),
                             "budget": row.get("expected_epoch_budget")}, row["name"])
    for row in cases(supply, "slot_subsidy_cases"):
        epoch, slot = natural(row.get("epoch"), row["name"], MAX_U64), natural(row.get("slot"), row["name"])
        require(slot < interval and epoch * interval + slot + 1 <= MAX_U64,
                "supply slot must name an actual u64 height")
        merge(slots, (epoch, slot), {"next_subsidy": row.get("expected_subsidy")}, row["name"])
    cap_epochs = cases(cap, "epoch_budget_cases", False)
    require(len(cap_epochs) == 64 and {natural(x.get("epoch"), "cap epoch") for x in cap_epochs}
            == set(range(64)), "all64 cap epoch cases required exactly once")
    for row in cap_epochs:
        epoch = natural(row["epoch"], "epoch")
        first, last = epoch * interval + 1, (epoch + 1) * interval
        require(natural(row.get("first_height"), "first height") == first
                and natural(row.get("last_height"), "last height") == last,
                "cap epoch boundary height mismatch")
        merge(epochs, epoch, {"remaining": row.get("remaining_budget"),
                             "budget": row.get("epoch_budget")}, f"epoch{epoch}")
        merge(epochs, epoch + 1, {"remaining": row.get("next_remaining_budget")}, f"next{epoch}")
        merge(heights, first, {"subsidy": row.get("first_subsidy")}, f"first{epoch}")
        merge(heights, last, {"subsidy": row.get("last_subsidy"),
                              "prefix": row.get("scheduled_prefix_after")}, f"last{epoch}")
        merge(heights, first - 1, {"prefix": row.get("scheduled_prefix_before")}, f"before{epoch}")
    cap_slots = cases(cap, "slot_prefix_cases", False)
    wanted_slots = {(e, n) for e in range(64) for n in (0, 1, interval // 2, interval - 1, interval)}
    require(len(cap_slots) == 320 and {(natural(x.get("epoch"), "slot epoch"),
                                     natural(x.get("slots"), "slot count")) for x in cap_slots}
            == wanted_slots, "all320 cap slot-prefix cases required exactly once")
    for row in cap_slots:
        epoch, count = natural(row["epoch"], "epoch"), natural(row["slots"], "slots")
        height = epoch * interval + count
        require(natural(row.get("height_after_slots"), "slot height") == height
                and natural(row.get("next_height"), "next height") == height + 1,
                "cap slot height mismatch")
        merge(slots, (epoch, count), {"slot_prefix": row.get("slot_prefix_subsidy"),
                                    "prefix": row.get("scheduled_prefix"),
                                    "next_subsidy": row.get("next_subsidy")}, f"slot{epoch}:{count}")
    for row in cases(cap, "height_cases"):
        merge(heights, natural(row.get("height"), row["name"], MAX_U64),
              {"subsidy": row.get("expected_subsidy"), "prefix": row.get("scheduled_prefix")}, row["name"])
    # Fixed transition cases supplement, never replace, every generated case.
    for height, subsidy, prefix in ((0, 0, 0), (1, 500_000_000, 500_000_000),
                                    (60_900_001, 0, None), (60_900_002, 1, None),
                                    (107_099_999, 0, exact_total - 1),
                                    (107_100_000, 1, exact_total),
                                    (107_100_001, 0, exact_total), (MAX_U64, 0, exact_total)):
        fields = {"subsidy": subsidy}
        if prefix is not None:
            fields["prefix"] = prefix
        merge(heights, height, fields, f"fixed{height}")
    merge(epochs, MAX_U64, {"remaining": 0, "budget": 0}, "u64 epoch")
    return {"heights": heights, "epochs": epochs, "slots": slots,
            "families": families, "exact_total": exact_total, "lean_constants": lean_constants}


def harness(constants: str, functions: str, requests: dict) -> str:
    heights = ", ".join(f"{x}u64" for x in sorted(requests["heights"]))
    epochs = ", ".join(f"{x}u64" for x in sorted(requests["epochs"]))
    slots = ", ".join(f"({e}u64, {n}u64)" for e, n in sorted(requests["slots"]))
    print_constants = "\n".join(f'    println!("constant {name} {{}}", {name});' for name in CONSTANT_NAMES)
    return f'''#![deny(warnings)]
{constants}

{functions}

fn main() {{
{print_constants}
    for height in [{heights}] {{
        let epoch = if height == 0 {{ 0 }} else {{ (height - 1) / HALVING_INTERVAL }};
        println!("case {{}} {{}} {{}} {{}} {{}}", height, epoch,
            epoch_subsidy_budget(epoch), block_subsidy(height), scheduled_subsidy(height));
    }}
    for epoch in [{epochs}] {{
        println!("epoch {{}} {{}} {{}}", epoch, remaining_subsidy_budget(epoch), epoch_subsidy_budget(epoch));
    }}
    for (epoch, slots) in [{slots}] {{
        let start = epoch.checked_mul(HALVING_INTERVAL).unwrap();
        let height = start.checked_add(slots).unwrap();
        println!("slot {{}} {{}} {{}} {{}} {{}}", epoch, slots,
            scheduled_subsidy(height).checked_sub(scheduled_subsidy(start)).unwrap(),
            scheduled_subsidy(height), block_subsidy(height.checked_add(1).unwrap()));
    }}
    let mut total = 0u128;
    let mut funding = 0u128;
    for epoch in 0..64u64 {{
        let budget = u128::from(epoch_subsidy_budget(epoch));
        let interval = u128::from(HALVING_INTERVAL);
        let quotient = budget / interval;
        let remainder = budget % interval;
        let epoch_funding = (interval - remainder) * (quotient / 5)
            + remainder * ((quotient + 1) / 5);
        let start = epoch.checked_mul(HALVING_INTERVAL).unwrap();
        let end = start.checked_add(HALVING_INTERVAL).unwrap();
        println!("budget {{}} {{}} {{}} {{}}", epoch, budget,
            scheduled_subsidy(end).checked_sub(scheduled_subsidy(start)).unwrap(), epoch_funding);
        total = total.checked_add(budget).unwrap();
        funding = funding.checked_add(epoch_funding).unwrap();
    }}
    println!("total {{}}", total);
    println!("funding {{}}", funding);
    println!("funding_dust {{}}", u128::from(MAX_SUPPLY) / 5 - funding);
}}
'''


def parse_output(output: str, requests: dict) -> dict:
    result = {"constants": {}, "heights": {}, "epochs": {}, "slots": {}, "budgets": {}}
    scalars = {}
    shapes = {"case": (6, "heights", ("epoch", "budget", "subsidy", "prefix")),
              "epoch": (4, "epochs", ("remaining", "budget")),
              "slot": (6, "slots", ("slot_prefix", "prefix", "next_subsidy")),
              "budget": (5, "budgets", ("budget", "prefix_difference", "funding"))}
    for line in output.splitlines():
        parts = line.split()
        require(parts, "blank runtime output line")
        kind = parts[0]
        if kind == "constant":
            require(len(parts) == 3 and parts[1] not in result["constants"], "invalid runtime constant")
            result["constants"][parts[1]] = natural(parts[2], parts[1], MAX_U64)
        elif kind in shapes:
            count, family, fields = shapes[kind]
            require(len(parts) == count, f"invalid runtime {kind}")
            key = tuple(natural(x, kind, MAX_U64) for x in parts[1:3]) if kind == "slot" else natural(parts[1], kind, MAX_U64)
            offset = 3 if kind == "slot" else 2
            require(key not in result[family], f"duplicate runtime {kind}")
            result[family][key] = {name: natural(value, name, MAX_U64)
                                  for name, value in zip(fields, parts[offset:])}
        elif kind in ("total", "funding", "funding_dust"):
            require(len(parts) == 2 and kind not in scalars, "invalid runtime scalar")
            scalars[kind] = natural(parts[1], kind, MAX_U64)
        else:
            raise ValueError(f"unknown runtime record {kind}")
    require(set(result["constants"]) == set(CONSTANT_NAMES), "runtime constants incomplete")
    for family in ("heights", "epochs", "slots"):
        require(set(result[family]) == set(requests[family]), f"runtime {family} incomplete")
    require(set(result["budgets"]) == set(range(64)), "all64 runtime budgets required")
    require(set(scalars) == {"total", "funding", "funding_dust"}, "runtime totals incomplete")
    result.update(scalars)
    return result


def check_observed(observed: dict, requests: dict) -> None:
    require(observed["constants"] == APPROVED_CONSTANTS, "actual Rust monetary constants mismatch")
    for family in ("heights", "epochs", "slots"):
        for key, fields in requests[family].items():
            for field, expected in fields.items():
                require(observed[family][key][field] == expected,
                        f"Lean/Rust mismatch {family}:{key}:{field}")
    supply, interval = APPROVED_CONSTANTS["MAX_SUPPLY"], APPROVED_CONSTANTS["HALVING_INTERVAL"]
    for epoch, row in observed["budgets"].items():
        remaining = supply >> epoch
        next_remaining = supply >> (epoch + 1) if epoch + 1 < 64 else 0
        budget = remaining - next_remaining
        quotient, remainder = divmod(budget, interval)
        funding = (interval - remainder) * (quotient // 5) + remainder * ((quotient + 1) // 5)
        require(row == {"budget": budget, "prefix_difference": budget, "funding": funding},
                f"full epoch algebra mismatch {epoch}")
    require(observed["total"] == requests["exact_total"] == supply,
            "all64 actual epoch budgets must total the exact supply")
    require(observed["funding"] == 419_999_982_379_352
            and observed["funding_dust"] == 17_620_648,
            "per-block funding floor aggregate mismatch")


def main() -> int:
    checker_path = Path(__file__).resolve()
    checker_bytes = checker_path.read_bytes()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--reward-source-sha256", required=True)
    parser.add_argument("--lean-supply-json", required=True, type=Path)
    parser.add_argument("--lean-supply-sha256", required=True)
    parser.add_argument("--lean-cap-json", required=True, type=Path)
    parser.add_argument("--lean-cap-sha256", required=True)
    parser.add_argument("--lean-genesis-json", type=Path)
    parser.add_argument("--lean-genesis-sha256")
    parser.add_argument("--rustc", required=True, type=Path)
    parser.add_argument("--rustc-sha256", required=True)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--static-genesis-check", action="store_true")
    args = parser.parse_args()
    root = args.source_root.resolve(strict=True)
    reward_path = root / "consensus/src/reward.rs"
    reward = pinned_bytes(reward_path, args.reward_source_sha256, "reward source")
    supply_bytes = pinned_bytes(args.lean_supply_json, args.lean_supply_sha256, "Lean supply JSON")
    cap_bytes = pinned_bytes(args.lean_cap_json, args.lean_cap_sha256, "Lean cap JSON")
    supply, cap = json.loads(supply_bytes), json.loads(cap_bytes)
    requests = vector_requests(supply, cap)
    segment, functions, slices = monetary_slices(reward.decode("utf-8"))
    require(bool(args.lean_genesis_json) == bool(args.lean_genesis_sha256),
            "Lean genesis JSON path and SHA256 must be supplied together")
    require(not args.static_genesis_check or args.lean_genesis_json is not None,
            "--static-genesis-check requires actual --lean-genesis-json and SHA256")
    genesis_bytes = (pinned_bytes(args.lean_genesis_json, args.lean_genesis_sha256,
                                  "Lean genesis JSON")
                     if args.lean_genesis_json is not None else None)
    genesis = (static_genesis(root, json.loads(genesis_bytes))
               if args.static_genesis_check else None)
    rustc = args.rustc.resolve(strict=True)
    rustc_bytes = pinned_bytes(rustc, args.rustc_sha256, "rustc")
    require(os.access(rustc, os.X_OK), "rustc is not executable")
    scratch = args.scratch.absolute()
    require(not scratch.exists(), "scratch must be a fresh nonexistent directory")
    scratch.mkdir(parents=False, mode=0o700)
    harness_path, executable = scratch / "monetary.rs", scratch / "monetary"
    harness_source = harness(segment, functions, requests).encode()
    harness_path.write_bytes(harness_source)
    env = dict(os.environ)
    for key in ("RUSTC_BOOTSTRAP", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(key, None)
    argv = [str(rustc), "--edition=2021", "--crate-name", "native_monetary_source",
            "-Dwarnings", "-C", "opt-level=0", "-C", "overflow-checks=yes",
            str(harness_path), "-o", str(executable)]
    compile_result = subprocess.run(argv, cwd=scratch, env=env, capture_output=True)
    (scratch / "compile.stdout").write_bytes(compile_result.stdout)
    (scratch / "compile.stderr").write_bytes(compile_result.stderr)
    require(compile_result.returncode == 0, "rustc failed; retained compile logs in scratch")
    executable_bytes = executable.read_bytes()
    run_result = subprocess.run([str(executable)], cwd=scratch, env=env, capture_output=True)
    (scratch / "runtime.stdout").write_bytes(run_result.stdout)
    (scratch / "runtime.stderr").write_bytes(run_result.stderr)
    require(run_result.returncode == 0 and not run_result.stderr, "harness failed or emitted stderr")
    observed = parse_output(run_result.stdout.decode("utf-8"), requests)
    check_observed(observed, requests)
    # Recheck all selected input bytes after compilation/execution.
    pinned_bytes(reward_path, args.reward_source_sha256, "reward source after")
    pinned_bytes(args.lean_supply_json, args.lean_supply_sha256, "Lean supply JSON after")
    pinned_bytes(args.lean_cap_json, args.lean_cap_sha256, "Lean cap JSON after")
    pinned_bytes(rustc, digest(rustc_bytes), "rustc after")
    if genesis_bytes is not None:
        pinned_bytes(args.lean_genesis_json, args.lean_genesis_sha256, "Lean genesis JSON after")
    if genesis:
        pinned_bytes(Path(genesis["path"]), genesis["source_sha256"], "genesis source after")
    pinned_bytes(checker_path, digest(checker_bytes), "checker source after")
    receipt = {
        "schema_version": 2, "schedule_mode": MODE, "status": "PASS_SELECTED_SOURCE_FINITE_CONFORMANCE",
        "checker_sha256": digest(checker_bytes), "source_root": str(root),
        "reward_source_sha256": digest(reward), "source_slices": slices,
        "lean_supply_json": {"path": str(args.lean_supply_json.resolve()), "sha256": digest(supply_bytes)},
        "lean_cap_json": {"path": str(args.lean_cap_json.resolve()), "sha256": digest(cap_bytes)},
        "lean_genesis_json": ({"path": str(args.lean_genesis_json.resolve()),
                                "sha256": digest(genesis_bytes)}
                               if genesis_bytes is not None else None),
        "rustc": {"path": str(rustc), "sha256": digest(rustc_bytes)},
        "compile_argv": argv, "compile_exit_code": compile_result.returncode,
        "harness_source_sha256": digest(harness_source),
        "compiled_harness_sha256": digest(executable_bytes),
        "compile_stdout_sha256": digest(compile_result.stdout),
        "compile_stderr_sha256": digest(compile_result.stderr),
        "runtime_stdout_sha256": digest(run_result.stdout),
        "runtime_stderr_sha256": digest(run_result.stderr),
        "runtime_exit_code": run_result.returncode,
         "observed": dict(observed, slots=[{"epoch": e, "slots": n, **row}
                                          for (e, n), row in sorted(observed["slots"].items())]),
         "verified_vector_case_families": requests["families"],
        "static_genesis": genesis,
         "fee_split": "ALGEBRAIC_PER_BLOCK_SUBSIDY_FLOOR_AGGREGATE_ACTIVE_PAYOUT_SOURCE_NOT_EXECUTED",
         "all64_epoch_budget_total_checked": True,
         "entire_slot_population_iterated": False,
         "consensus_and_native_supply_digest_cases_executed": False,
        "lean_proof_receipt_authenticated_by_checker": False,
        "full_node_refinement": False, "whole_code_no_allocation_proof": False,
        "circulating_wealth_or_gross_supply_digest_cap_proved": False,
    }
    receipt_path = scratch / "receipt.json"
    temporary_receipt = scratch / "receipt.json.tmp"
    with temporary_receipt.open("x") as handle:
        handle.write(json.dumps(receipt, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary_receipt, receipt_path)
    print(json.dumps({"status": receipt["status"], "receipt": str(receipt_path),
                      "receipt_sha256": digest(receipt_path.read_bytes())}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
