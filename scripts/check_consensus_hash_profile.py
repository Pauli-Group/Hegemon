#!/usr/bin/env python3
"""Fail closed on the centralized V3 consensus-hash profile.

The default foundation check is green while the coordinated V3 migration is in
progress. `--enforce-v3` additionally rejects every known active narrow-hash
call site and duplicated domain literal; that mode intentionally remains red
until all schema owners have migrated atomically.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re


CENTRAL = Path("crypto/hash384/src/lib.rs")
ACTIVE_V3_ROOTS = (
    Path("crypto/src/hashes.rs"),
    Path("consensus-light-client/src"),
    Path("consensus/src"),
    Path("node/src"),
    Path("state/da/src"),
    Path("protocol/kernel/src"),
    Path("protocol/shielded-pool/src"),
    Path("circuits/transaction-core/src"),
    Path("circuits/transaction/src"),
    Path("circuits/superneo-backend-lattice/src"),
    Path("circuits/superneo-ccs/src"),
    Path("circuits/superneo-core/src"),
    Path("circuits/superneo-hegemon/src"),
    Path("circuits/superneo-ring/src"),
    Path("tools/native-backend-ref/src"),
    Path("zk/cashvm-bridge/src"),
)
FORBIDDEN_ACTIVE = {
    r"(?i)\bblake3[A-Za-z0-9_]*\b": "BLAKE3",
    # The central `hegemon_hash384::{blake2b_384, ...}` API is approved.  A
    # direct RustCrypto type import/construction or a second raw helper is not.
    r"\bBlake2b\b|\bfn\s+blake2b_384\s*\(": "raw/direct BLAKE2b",
    r"(?i)\bsha(?:2[_-]?)?256[A-Za-z0-9_]*\b": "SHA-256/SHA256d",
    r"(?i)\bdouble[_-]?sha[_-]?256[A-Za-z0-9_]*\b": "SHA256d",
    r"\bPoseidonDigest56\b": "forbidden active PoseidonDigest56 wire",
    # SHA-512 is wide enough for the Level-5 proof transcript, but remains an
    # exact reviewed exception so it cannot spread into consensus identities.
    r"\bSha512\b": "SHA-512 proof transcript",
}
# Any final line exception is an exact source-line ratchet with a non-empty
# justification. Function exceptions are additionally constrained to the exact
# parsed Rust function body, never the rest of a file or everything after a
# `#[cfg(test)]` marker.
V3_NARROW_HASH_LINE_ALLOWLIST: dict[tuple[str, int, str], str] = {
    (
        "crypto/src/hashes.rs",
        2,
        "SHA-256/SHA256d",
    ): "import used by the fixed-input Poseidon NUMS derivation; other uses remain findings",
    (
        "circuits/transaction/src/smallwood_engine.rs",
        13,
        "SHA-512 proof transcript",
    ): "exact import for the reviewed Level-5 SHA-512 proof transcript",
}

# These approved functions may execute in production, so they are limited to
# wide proof transcripts or fixed-input parameter derivation rather than legacy
# collision-binding compatibility.
V3_APPROVED_HASH_FUNCTION_ALLOWLIST: dict[tuple[str, str, str], str] = {
    (
        "crypto/src/hashes.rs",
        "hash_to_field",
        "SHA-256/SHA256d",
    ): "fixed Poseidon NUMS constants only; runtime/adversary bytes cannot reach its arguments",
    (
        "circuits/transaction/src/smallwood_engine.rs",
        "sha512_raw_domain_digest",
        "SHA-512 proof transcript",
    ): "exact active 512-bit Level-5 proof transcript implementation with an independent known-answer test",
    (
        "circuits/transaction/src/smallwood_engine.rs",
        "hash_merkle_leave_from_tables",
        "SHA-512 proof transcript",
    ): "allocation-free specialization of the same 512-bit Level-5 proof transcript",
}

# A fixed-input exception can silently become adversary controlled if a new
# caller appears.  Every production reference must remain in this exact set.
V3_APPROVED_FUNCTION_CALLERS: dict[tuple[str, str], frozenset[str]] = {
    (
        "crypto/src/hashes.rs",
        "hash_to_field",
    ): frozenset({"poseidon_round_constants", "poseidon_mds_matrix"}),
}

# Legacy hash implementations may be retained only as private, production-
# unreachable diagnostics. The checker proves that no production reference to
# an entry exists. This stays empty until a schema owner demonstrates a real
# identify-and-reject need; active V1 verification is never eligible.
V3_UNREACHABLE_LEGACY_FUNCTION_ALLOWLIST: dict[tuple[str, str, str], str] = {}
V3_DOMAIN_LITERAL_ALLOWLIST: dict[tuple[str, int, str], str] = {}
TEST_ONLY_V3_MODULES = {
    Path("node/src/native/tests.rs"),
    Path("node/src/native/transport_tests.rs"),
    Path("node/src/native/pending_action_canonicality_tests.rs"),
}
RAW_STRING = re.compile(r"(?:br|rb|r)(?P<hashes>#{0,255})\"")
REQUIRED_TYPES = {
    "HeaderPrecommit48",
    "WorkHash48",
    "BlockId48",
    "Target48",
    "RulesHash48",
    "ActionId48",
    "ActionSemanticId48",
    "ActionRoot48",
    "HeaderMmrHash48",
    "StateRoot48",
    "NoteCommitment48",
    "Nullifier48",
    "TransactionMerkleHash48",
    "Anchor48",
    "BalanceTag48",
    "KernelRoot48",
    "NullifierAccumulatorRoot48",
    "DaRoot48",
    "ProofCommitment48",
    "TransactionStatementsCommitment48",
    "VersionCommitment48",
    "FeeCommitment48",
    "BodyHash48",
    "ActionBodyHash48",
    "CheckpointDigest48",
    "ReorgWalValueHash48",
    "LightClientVerifierHash48",
    "BridgeCheckpointOutputDigest48",
    "TransactionId48",
    "BridgePayloadHash48",
    "BridgeMessageHash48",
    "BridgeMessageRoot48",
    "BridgeReplayKey48",
    "Work64",
}


def fail(message: str) -> None:
    raise SystemExit(f"consensus hash profile rejected: {message}")


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def rust_sources(root: Path) -> list[Path]:
    sources: list[Path] = []
    for top in ("crypto", "consensus", "consensus-light-client", "node", "state", "protocol", "circuits"):
        directory = root / top
        if directory.exists():
            sources.extend(
                path
                for path in directory.rglob("*.rs")
                if not {"target", "examples", "tests", "benches"}.intersection(path.parts)
            )
    return sources


def blank(chars: list[str], start: int, end: int) -> None:
    for index in range(start, min(end, len(chars))):
        if chars[index] != "\n":
            chars[index] = " "


def lexical_code(source: str) -> str:
    """Mask Rust comments and literals while preserving byte offsets/lines."""
    chars = list(source)
    length = len(source)
    index = 0
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end < 0 else end
            blank(chars, index, end)
            index = end
            continue
        if source.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            blank(chars, index, end)
            index = end
            continue

        raw = RAW_STRING.match(source, index)
        if raw is not None:
            hashes = raw.group("hashes")
            terminator = '"' + hashes
            content = raw.end()
            close = source.find(terminator, content)
            end = length if close < 0 else close + len(terminator)
            blank(chars, index, end)
            index = end
            continue

        prefix = 2 if source.startswith('b"', index) else 1 if source[index] == '"' else 0
        if prefix:
            end = index + prefix
            escaped = False
            while end < length:
                character = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    break
            blank(chars, index, end)
            index = end
            continue

        char_prefix = 2 if source.startswith("b'", index) else 1 if source[index] == "'" else 0
        if char_prefix:
            end = index + char_prefix
            escaped = False
            found = False
            while end < min(length, index + 16) and source[end] != "\n":
                character = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == "'":
                    found = True
                    break
            if found:
                blank(chars, index, end)
                index = end
                continue
        index += 1
    return "".join(chars)


def mask_comments(source: str) -> str:
    """Mask Rust comments but retain literals for exact-domain checks."""
    chars = list(source)
    length = len(source)
    index = 0
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end < 0 else end
            blank(chars, index, end)
            index = end
            continue
        if source.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            blank(chars, index, end)
            index = end
            continue

        raw = RAW_STRING.match(source, index)
        if raw is not None:
            terminator = '"' + raw.group("hashes")
            close = source.find(terminator, raw.end())
            index = length if close < 0 else close + len(terminator)
            continue
        if source.startswith('b"', index) or source[index] == '"':
            index += 2 if source.startswith('b"', index) else 1
            escaped = False
            while index < length:
                character = source[index]
                index += 1
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    break
            continue
        if source.startswith("b'", index) or source[index] == "'":
            start = index
            index += 2 if source.startswith("b'", index) else 1
            escaped = False
            while index < min(length, start + 16) and source[index] != "\n":
                character = source[index]
                index += 1
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == "'":
                    break
            continue
        index += 1
    return "".join(chars)


def production_source(source: str) -> str:
    """Mask exact `#[cfg(test)]` items using balanced Rust-code braces."""
    code = lexical_code(source)
    ranges: list[tuple[int, int]] = []
    attribute = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    for match in attribute.finditer(code):
        cursor = match.end()
        while cursor < len(code) and code[cursor].isspace():
            cursor += 1
        brace = code.find("{", cursor)
        semicolon = code.find(";", cursor)
        if semicolon >= 0 and (brace < 0 or semicolon < brace):
            ranges.append((match.start(), semicolon + 1))
            continue
        if brace < 0:
            ranges.append((match.start(), len(source)))
            continue
        depth = 1
        end = brace + 1
        while end < len(code) and depth:
            if code[end] == "{":
                depth += 1
            elif code[end] == "}":
                depth -= 1
            end += 1
        ranges.append((match.start(), end))

    chars = list(source)
    for start, end in ranges:
        blank(chars, start, end)
    return "".join(chars)


def rust_function_spans(code: str) -> list[tuple[str, int, int, int]]:
    """Return `(name, declaration_start, body_start, body_end)` spans.

    `code` must already have comments, literals, and test-only items masked.
    Balanced braces make a match local to the exact function even when a test
    module appears before later production code.
    """
    spans: list[tuple[str, int, int, int]] = []
    declaration = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\b")
    for match in declaration.finditer(code):
        cursor = match.end()
        paren_depth = 0
        angle_depth = 0
        bracket_depth = 0
        body_start = -1
        while cursor < len(code):
            character = code[cursor]
            if character == "(" and angle_depth == 0:
                paren_depth += 1
            elif character == ")" and paren_depth:
                paren_depth -= 1
            elif character == "<" and paren_depth == 0:
                angle_depth += 1
            elif character == ">" and paren_depth == 0 and angle_depth:
                angle_depth -= 1
            elif character == "[":
                bracket_depth += 1
            elif character == "]" and bracket_depth:
                bracket_depth -= 1
            elif character == ";" and paren_depth == angle_depth == bracket_depth == 0:
                break
            elif character == "{" and paren_depth == angle_depth == bracket_depth == 0:
                body_start = cursor
                break
            cursor += 1
        if body_start < 0:
            continue
        depth = 1
        body_end = body_start + 1
        while body_end < len(code) and depth:
            if code[body_end] == "{":
                depth += 1
            elif code[body_end] == "}":
                depth -= 1
            body_end += 1
        if depth == 0:
            spans.append((match.group(1), match.start(), body_start, body_end))
    return spans


def enclosing_function(
    spans: list[tuple[str, int, int, int]], offset: int
) -> tuple[str, int, int, int] | None:
    candidates = [span for span in spans if span[1] <= offset < span[3]]
    if not candidates:
        return None
    return min(candidates, key=lambda span: span[3] - span[1])


def active_v3_sources(root: Path) -> list[Path]:
    sources: set[Path] = set()
    for relative in ACTIVE_V3_ROOTS:
        path = root / relative
        if path.is_file() and path.suffix == ".rs":
            sources.add(path)
        elif path.is_dir():
            sources.update(
                child
                for child in path.rglob("*.rs")
                if not {"tests", "examples", "benches"}.intersection(child.parts)
                and child.relative_to(root) not in TEST_ONLY_V3_MODULES
            )
    return sorted(sources)


def check_foundation(root: Path) -> tuple[set[str], set[str]]:
    central_path = root / CENTRAL
    if not central_path.is_file():
        fail(f"missing central implementation {CENTRAL}")
    central = central_path.read_text(encoding="utf-8")

    for definition in (
        "pub fn blake2b_384(",
        "pub fn blake2b_384_domain_hash",
        "pub struct PowWorkContextV3",
    ):
        owners = []
        for path in rust_sources(root):
            source = path.read_text(encoding="utf-8")
            if definition not in source:
                continue
            source = production_source(source)
            if definition in source:
                owners.append(path.relative_to(root))
        if owners != [CENTRAL]:
            fail(f"{definition!r} must be defined only in {CENTRAL}, found {owners}")

    direct = re.compile(r"Blake2b\s*::<\s*U48")
    for path in rust_sources(root):
        relative = path.relative_to(root)
        if relative == CENTRAL:
            continue
        source = path.read_text(encoding="utf-8")
        if "Blake2b" not in source or "U48" not in source:
            continue
        source = production_source(source)
        code = lexical_code(source)
        for match in direct.finditer(code):
            fail(
                f"direct BLAKE2b-384 implementation outside central crate at "
                f"{relative}:{line_number(source, match.start())}"
            )

    domain_start = central.index("pub mod domains {")
    domain_end = central.index("\n}\n\n#[cfg(test)]", domain_start)
    registry = central[domain_start:domain_end]
    constants = dict(
        re.findall(
            r"pub const ([A-Z0-9_]+):\s*&\[u8\]\s*=\s*b\"([^\"]+)\";",
            registry,
            flags=re.MULTILINE,
        )
    )
    if not constants:
        fail("domain registry is empty or unparsable")
    values = list(constants.values())
    if len(values) != len(set(values)):
        duplicates = sorted({value for value in values if values.count(value) > 1})
        fail(f"duplicate domain bytes in central registry: {duplicates}")
    if constants.get("POW_WORK_V3", "").endswith(r"\0") is not True:
        fail("POW_WORK_V3 must retain its explicit trailing NUL")

    all_match = re.search(
        r"pub const ALL:\s*&\[&\[u8\]\]\s*=\s*&\[(.*?)\];",
        registry,
        flags=re.DOTALL,
    )
    if all_match is None:
        fail("domains::ALL is absent or unparsable")
    all_names = re.findall(r"\b[A-Z][A-Z0-9_]+\b", all_match.group(1))
    if set(all_names) != set(constants) or len(all_names) != len(constants):
        missing = sorted(set(constants) - set(all_names))
        repeated = sorted({name for name in all_names if all_names.count(name) > 1})
        fail(f"domains::ALL mismatch; missing={missing}, repeated={repeated}")

    types = set(re.findall(r"fixed_bytes_type!\(([A-Za-z0-9_]+),", central))
    types.update(re.findall(r"pub struct ([A-Za-z0-9_]+)\b", central))
    if not REQUIRED_TYPES.issubset(types):
        fail(f"missing semantic wrappers: {sorted(REQUIRED_TYPES - types)}")
    if "serializer.serialize_bytes" in central or "deserialize_bytes" in central:
        fail("semantic wrappers must use fixed-width serde, not length-prefixed bytes")
    if "serializer.serialize_tuple($length)" not in central:
        fail("fixed-width serde tuple grammar is not pinned")

    direct_central = list(re.finditer(r"Blake2b\s*::<\s*U48", lexical_code(central)))
    if len(direct_central) != 3:
        fail(
            "central crate must contain exactly three reviewed direct BLAKE2b-384 "
            f"constructors (raw KAT helper, generic framed helper, fixed PoW context), got "
            f"{len(direct_central)}"
        )
    required_pow_fragments = (
        "pub const POW_WORK_TRANSCRIPT_BYTES_V3: usize = domains::POW_WORK_V3.len() + 48 + 32;",
        "preinitialized.update(domains::POW_WORK_V3);",
        "preinitialized.update(precommit.as_bytes());",
        "hasher.update(nonce);",
        "5560947641df7a240d60f63c1c4f49b7551ff10a5ac4f4696d0662d2ecf7b4e7aa8edbc098d0a63fe21f2d71c1764f42",
    )
    missing_pow = [fragment for fragment in required_pow_fragments if fragment not in central]
    if missing_pow:
        fail(f"raw 112-byte PoW transcript/KAT drifted; missing {missing_pow}")
    if re.search(r"impl\s+PowWorkContextV3.*?pub\s+fn\s+update", central, re.DOTALL):
        fail("PowWorkContextV3 must not expose a generic update method")

    return set(constants), set(values)


def enforce_v3(root: Path, domain_values: set[str]) -> None:
    findings: list[str] = []
    used_line_allowlist: set[tuple[str, int, str]] = set()
    used_function_allowlist: set[tuple[str, str, str]] = set()
    used_legacy_allowlist: set[tuple[str, str, str]] = set()
    used_domain_allowlist: set[tuple[str, int, str]] = set()
    parsed_sources: dict[str, tuple[str, str, list[tuple[str, int, int, int]]]] = {}
    for path in active_v3_sources(root):
        relative = path.relative_to(root)
        source = path.read_text(encoding="utf-8")
        lowered = source.lower()
        if not any(
            token in lowered
            for token in (
                "blake3",
                "blake2b",
                "sha256",
                "sha_256",
                "sha2",
                "double_sha",
                "hegemon.",
                "poseidondigest56",
            )
        ):
            continue
        source = production_source(source)
        code = lexical_code(source)
        spans = rust_function_spans(code)
        parsed_sources[str(relative)] = (source, code, spans)
        for pattern, label in FORBIDDEN_ACTIVE.items():
            for match in re.finditer(pattern, code):
                line = line_number(source, match.start())
                key = (str(relative), line, label)
                rationale = V3_NARROW_HASH_LINE_ALLOWLIST.get(key)
                if rationale:
                    used_line_allowlist.add(key)
                    continue

                function = enclosing_function(spans, match.start())
                if function is not None:
                    function_key = (str(relative), function[0], label)
                    rationale = V3_APPROVED_HASH_FUNCTION_ALLOWLIST.get(function_key)
                    if rationale:
                        used_function_allowlist.add(function_key)
                        continue
                    rationale = V3_UNREACHABLE_LEGACY_FUNCTION_ALLOWLIST.get(function_key)
                    if rationale:
                        used_legacy_allowlist.add(function_key)
                        continue
                findings.append(f"{relative}:{line}: active {label} token")

        comments_masked = mask_comments(source)
        for match in re.finditer(r'b\"([^\"]+)\"', comments_masked):
            if match.group(1) in domain_values:
                line = line_number(source, match.start())
                key = (str(relative), line, match.group(1))
                rationale = V3_DOMAIN_LITERAL_ALLOWLIST.get(key)
                if rationale:
                    used_domain_allowlist.add(key)
                else:
                    findings.append(f"{relative}:{line}: duplicated central domain literal")

    # Fixed-input exceptions are valid only while every production reference is
    # inside an explicitly reviewed caller. This is a small static call-graph
    # ratchet, not a name-based assertion.
    for (relative, function_name), allowed_callers in V3_APPROVED_FUNCTION_CALLERS.items():
        parsed = parsed_sources.get(relative)
        if parsed is None:
            findings.append(f"approved function caller policy source missing: {relative}")
            continue
        source, code, spans = parsed
        definitions = [span for span in spans if span[0] == function_name]
        if len(definitions) != 1:
            findings.append(
                f"approved function {relative}::{function_name} must have one definition, "
                f"found {len(definitions)}"
            )
            continue
        definition = definitions[0]
        references = list(re.finditer(rf"\b{re.escape(function_name)}\b", code))
        actual_callers: set[str] = set()
        for reference in references:
            if definition[1] <= reference.start() < definition[2]:
                continue
            caller = enclosing_function(spans, reference.start())
            if caller is None:
                findings.append(
                    f"{relative}:{line_number(source, reference.start())}: "
                    f"{function_name} reference outside a reviewed function"
                )
                continue
            actual_callers.add(caller[0])
        unexpected = actual_callers - set(allowed_callers)
        missing = set(allowed_callers) - actual_callers
        if unexpected or missing:
            findings.append(
                f"{relative}::{function_name} caller drift; "
                f"unexpected={sorted(unexpected)}, missing={sorted(missing)}"
            )

    # An allowlisted legacy implementation must be private and have zero
    # production references. Test-only callers were masked above. This permits
    # byte-era diagnostics without leaving a callable acceptance primitive.
    for key in V3_UNREACHABLE_LEGACY_FUNCTION_ALLOWLIST:
        relative, function_name, _ = key
        parsed = parsed_sources.get(relative)
        if parsed is None:
            findings.append(f"legacy function policy source missing: {relative}")
            continue
        source, code, spans = parsed
        definitions = [span for span in spans if span[0] == function_name]
        if len(definitions) != 1:
            findings.append(
                f"legacy function {relative}::{function_name} must have one definition, "
                f"found {len(definitions)}"
            )
            continue
        definition = definitions[0]
        declaration_prefix = code[max(0, definition[1] - 24) : definition[1]]
        if re.search(r"\bpub(?:\s*\([^)]*\))?\s*$", declaration_prefix):
            findings.append(f"legacy function {relative}::{function_name} must be private")
        references = list(re.finditer(rf"\b{re.escape(function_name)}\b", code))
        production_calls = [
            reference
            for reference in references
            if not (definition[1] <= reference.start() < definition[2])
        ]
        for reference in production_calls:
            caller = enclosing_function(spans, reference.start())
            caller_name = "module scope" if caller is None else caller[0]
            findings.append(
                f"{relative}:{line_number(source, reference.start())}: unreachable legacy "
                f"function {function_name} called by {caller_name}"
            )

    stale_lines = set(V3_NARROW_HASH_LINE_ALLOWLIST) - used_line_allowlist
    stale_functions = set(V3_APPROVED_HASH_FUNCTION_ALLOWLIST) - used_function_allowlist
    stale_legacy = set(V3_UNREACHABLE_LEGACY_FUNCTION_ALLOWLIST) - used_legacy_allowlist
    stale_domains = set(V3_DOMAIN_LITERAL_ALLOWLIST) - used_domain_allowlist
    if stale_lines or stale_functions or stale_legacy or stale_domains:
        findings.append(
            f"stale V3 allowlist entries: lines={sorted(stale_lines)}, "
            f"functions={sorted(stale_functions)}, legacy={sorted(stale_legacy)}, "
            f"domains={sorted(stale_domains)}"
        )
    if findings:
        fail("V3 enforcement findings:\n  " + "\n  ".join(findings))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--enforce-v3",
        action="store_true",
        help="reject active narrow hashes and duplicated registered domain literals",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    _, domain_values = check_foundation(root)
    if args.enforce_v3:
        enforce_v3(root, domain_values)
    print("consensus hash foundation policy: PASS")


if __name__ == "__main__":
    main()
