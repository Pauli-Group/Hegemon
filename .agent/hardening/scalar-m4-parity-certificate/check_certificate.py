#!/usr/bin/env python3
"""Fail-closed source certificate for the HX448C02 scalar/M4 relation.

This checker deliberately performs no Rust compilation and no proof work.  It binds
the exact source bytes and recomputes the finite source-refinement inventory recorded
in certificate.json and corpus.json.  Executed aggregate parity remains a separately
counted zero until the disk-gated Rust corpus is run.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CERTIFICATE_PATH = HERE / "certificate.json"
CORPUS_PATH = HERE / "corpus.json"
BINIUS_LOGICAL_ROOT = Path(
    "prototypes/standalone-shake256-binius/binius64"
)
CERTIFIED_RELATION_INVENTORY_SHA256 = (
    "2fcad6179d306ccb484a569703a79f609664625f9c3fb2b1fb231b8a74c5b968"
)
CERTIFIED_SEMANTIC_INVENTORY_SHA256 = (
    "d41d94aca3f93fc63dd20c3d8f045e4df0a659e989bcb9c067f2a537c58f7733"
)
CERTIFIED_CORPUS_SHA256 = (
    "4f479f8ea0bac5386830a00ec1f876c55fdda840375b8e0eda353a93227f7527"
)


class CertificateError(RuntimeError):
    """Raised whenever a source or certificate invariant drifts."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CertificateError(message)


def require_keys(value: Mapping[str, Any], keys: Iterable[str], where: str) -> None:
    missing = sorted(set(keys) - set(value))
    require(not missing, f"{where}: missing keys {missing}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CertificateError(f"cannot load {path}: {error}") from error
    require(isinstance(value, dict), f"{path}: top level must be an object")
    return value


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha512(payload: bytes) -> str:
    return hashlib.sha512(payload).hexdigest()


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return sha256(encoded)


def framed_digest(domain: bytes, entries: Mapping[str, bytes]) -> str:
    hasher = hashlib.sha512(domain)
    for name in sorted(entries):
        encoded_name = name.encode("utf-8")
        payload = entries[name]
        hasher.update(len(encoded_name).to_bytes(4, "big"))
        hasher.update(encoded_name)
        hasher.update(len(payload).to_bytes(8, "big"))
        hasher.update(payload)
    return hasher.hexdigest()


def logical_path(path: str) -> Path:
    require(path and not path.startswith("/"), f"unsafe absolute source path: {path!r}")
    parts = Path(path).parts
    require(".." not in parts, f"unsafe parent traversal in source path: {path!r}")
    logical = REPO / path
    try:
        logical.resolve().relative_to(REPO.resolve())
    except ValueError:
        require(
            path == BINIUS_LOGICAL_ROOT.as_posix()
            or path.startswith(BINIUS_LOGICAL_ROOT.as_posix() + "/"),
            f"source path escapes the repository outside the disclosed Binius tree: {path!r}",
        )
    return logical


def canonical_binius_inventory() -> list[Path]:
    root = logical_path(BINIUS_LOGICAL_ROOT.as_posix())
    inventory = [root / "Cargo.toml", root / "Cargo.lock", root / "rust-toolchain.toml"]
    inventory.extend(path for path in (root / "crates").rglob("*") if path.is_file())
    return sorted(inventory, key=lambda path: path.relative_to(root).as_posix())


def canonical_binius_tree_digest() -> tuple[int, str]:
    root = logical_path(BINIUS_LOGICAL_ROOT.as_posix())
    hasher = hashlib.sha512(b"hegemon.binius64.local-tree.v1\0")
    inventory = canonical_binius_inventory()
    for path in inventory:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        hasher.update(len(relative).to_bytes(4, "big"))
        hasher.update(relative)
        hasher.update(len(payload).to_bytes(8, "big"))
        hasher.update(payload)
    return len(inventory), hasher.hexdigest()


@dataclass(frozen=True)
class SourceContext:
    payloads: dict[str, bytes]
    texts: dict[str, str]
    binius_files: int
    binius_tree_sha512: str


def collect_source_context(certificate: Mapping[str, Any]) -> SourceContext:
    sources = certificate.get("source_pins")
    require(isinstance(sources, dict) and sources, "source_pins must be a nonempty object")
    payloads: dict[str, bytes] = {}
    texts: dict[str, str] = {}
    for path in sources:
        require(isinstance(path, str), "source pin paths must be strings")
        source_path = logical_path(path)
        require(source_path.is_file(), f"pinned source is missing: {path}")
        payload = source_path.read_bytes()
        payloads[path] = payload
        try:
            texts[path] = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CertificateError(f"pinned source is not UTF-8: {path}") from error
    binius_files, binius_digest = canonical_binius_tree_digest()
    return SourceContext(payloads, texts, binius_files, binius_digest)


def validate_source_pins(
    certificate: Mapping[str, Any], context: SourceContext
) -> None:
    pins = certificate["source_pins"]
    require(set(pins) == set(context.payloads), "source context does not match source_pins")
    for path, expected in pins.items():
        require(isinstance(expected, dict), f"source pin must be an object: {path}")
        require_keys(expected, ("bytes", "sha256", "sha512"), f"source pin {path}")
        payload = context.payloads[path]
        require(expected["bytes"] == len(payload), f"source byte length drift: {path}")
        require(expected["sha256"] == sha256(payload), f"source SHA-256 drift: {path}")
        require(expected["sha512"] == sha512(payload), f"source SHA-512 drift: {path}")

    source_manifest = certificate["source_manifest"]
    require(
        source_manifest["files"] == len(context.payloads),
        "canonical source-manifest file count drift",
    )
    require(
        source_manifest["domain"] == "hegemon.hx448c02.scalar-m4-parity.sources.v1",
        "unexpected canonical source-manifest domain",
    )
    composite = framed_digest(
        source_manifest["domain"].encode("ascii") + b"\0", context.payloads
    )
    require(
        composite == source_manifest["framed_sha512"],
        "canonical framed source SHA-512 drift",
    )
    dependency = certificate["binius_dependency"]
    binius_root = logical_path(BINIUS_LOGICAL_ROOT.as_posix())
    require(dependency["logical_root_kind"] == "symlink", "Binius root disclosure drift")
    require(binius_root.is_symlink(), "Binius logical root is no longer the disclosed symlink")
    require(not dependency["retained_self_contained"], "symlinked Binius tree is not self-contained")
    require(context.binius_files == dependency["files"], "Binius file count drift")
    require(
        context.binius_tree_sha512 == dependency["tree_sha512"],
        "Binius tree SHA-512 drift",
    )


def validate_anchors(certificate: Mapping[str, Any], context: SourceContext) -> None:
    anchors = certificate["source_anchors"]
    require(isinstance(anchors, dict) and anchors, "source_anchors must be nonempty")
    for path, fragments in anchors.items():
        require(path in context.texts, f"anchor path is not source-pinned: {path}")
        require(isinstance(fragments, list) and fragments, f"empty anchor list: {path}")
        source = context.texts[path]
        for fragment in fragments:
            require(isinstance(fragment, str) and fragment, f"invalid anchor in {path}")
            require(fragment in source, f"missing source anchor {fragment!r} in {path}")
    for item in certificate.get("forbidden_source_anchors", []):
        require_keys(item, ("path", "fragment"), "forbidden source anchor")
        source = context.texts.get(item["path"])
        require(source is not None, f"forbidden-anchor path is not pinned: {item['path']}")
        require(
            item["fragment"] not in source,
            f"forbidden source anchor present: {item['fragment']!r} in {item['path']}",
        )


def validate_codec(certificate: Mapping[str, Any]) -> None:
    codec = certificate["codec"]
    require(codec["magic_ascii"] == "HX448C02", "fresh diagnostic magic must be HX448C02")
    require(codec["retired_magic_ascii"] == "HX448C01", "retired diagnostic magic drift")
    require(codec["grammar"] == 2, "diagnostic grammar must be two")
    require(codec["bytes"] == 869, "diagnostic statement must be 869 bytes")
    fields = codec["fields"]
    require(isinstance(fields, list) and fields, "codec fields must be nonempty")
    cursor = 0
    names: set[str] = set()
    for field in fields:
        require_keys(field, ("name", "offset", "bytes", "class"), "codec field")
        require(field["name"] not in names, f"duplicate codec field {field['name']}")
        names.add(field["name"])
        require(field["offset"] == cursor, f"codec gap/overlap before {field['name']}")
        require(isinstance(field["bytes"], int) and field["bytes"] > 0, "invalid field width")
        cursor += field["bytes"]
    require(cursor == codec["bytes"], "codec fields do not exactly cover the statement")

    exact_widths = {
        "stable_policy_hash": 48,
        "stable_oracle_commitment": 48,
        "stable_attestation_commitment": 48,
    }
    by_name = {field["name"]: field for field in fields}
    for name, width in exact_widths.items():
        require(by_name[name]["bytes"] == width, f"{name} is not exactly 48 bytes")
        require(by_name[name]["class"] == "live-authority-384", f"{name} class drift")
    for field in fields:
        if field["class"] == "pq-digest-448":
            require(field["bytes"] % 56 == 0, f"448-bit digest field width drift: {field['name']}")

    scalar = codec["scalar_projection"]
    require(scalar["limb_bytes"] == 7, "scalar limb width drift")
    require(
        scalar["limbs"] == (codec["bytes"] + scalar["limb_bytes"] - 1) // scalar["limb_bytes"],
        "scalar limb count drift",
    )
    require(
        scalar["final_payload_bytes"] == codec["bytes"] % scalar["limb_bytes"],
        "scalar final payload drift",
    )
    require(
        scalar["final_zero_high_bytes"] == 8 - scalar["final_payload_bytes"],
        "scalar final high-zero width drift",
    )
    m4 = codec["m4_projection"]
    require(m4["word_bytes"] == 8, "M4 word width drift")
    require(
        m4["words"] == (codec["bytes"] + 7) // 8,
        "M4 public word count drift",
    )
    require(m4["final_payload_bytes"] == codec["bytes"] % 8, "M4 final payload drift")
    require(m4["final_zero_high_bytes"] == 8 - m4["final_payload_bytes"], "M4 padding drift")
    require(codec["stablecoin_words_per_digest"] == 6, "stablecoin digest must use six M4 words")
    require(codec["stablecoin_total_words"] == 18, "three stablecoin digests must use 18 words")

    intent = codec["intent_projection"]
    expected_payload = by_name["magic"]["bytes"] + by_name["grammar"]["bytes"]
    expected_payload += by_name["input_flags"]["bytes"] + by_name["output_flags"]["bytes"]
    expected_payload += codec["bytes"] - by_name["commitments"]["offset"]
    require(intent["payload_bytes"] == expected_payload == 701, "intent source-slice width drift")
    require(intent["frame_bytes"] == intent["payload_bytes"] + 19 == 720, "intent frame drift")


def expand_call_families(certificate: Mapping[str, Any], profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for family in certificate["call_families"]:
        count = family["count"]
        for relative in range(count):
            index = family["start"] + relative
            kind_tag = family["kind_tag"]
            coordinates: list[int] = []
            coordinate_rule = family.get("coordinate_rule", "none")
            if coordinate_rule == "relative":
                coordinates = [relative]
            elif coordinate_rule == "merkle":
                coordinates = [relative // 32, relative % 32]
            elif coordinate_rule == "spend_a":
                coordinates = [relative, 0]
            elif coordinate_rule == "spend_b":
                coordinates = [relative, 1]
            elif coordinate_rule == "authorization_a":
                coordinates = [relative, 0]
            elif coordinate_rule == "authorization_b":
                coordinates = [relative, 1]
            elif coordinate_rule == "explicit":
                coordinates = list(family["coordinates"])
            elif coordinate_rule != "none":
                raise CertificateError(f"unknown coordinate rule {coordinate_rule}")

            if family["algorithm_class"] == "secret":
                algorithm_id = profile["secret_algorithm_id"]
                primitive_cores = family["cores"][profile["name"]]
            else:
                algorithm_id = 2
                primitive_cores = family["cores"]["fixed"]
            binding = copy.deepcopy(family["binding"])
            if binding.get("index_rule") == "relative":
                binding["index"] = relative
            calls.append(
                {
                    "index": index,
                    "family": family["id"],
                    "kind_tag": kind_tag,
                    "coordinates": coordinates,
                    "role": family["role"],
                    "algorithm_id": algorithm_id,
                    "purpose_id": family["purpose_id"],
                    "frame": copy.deepcopy(family["frame"]),
                    "maximum_frame_bytes": family["maximum_frame_bytes"],
                    "output_bytes": 56,
                    "primitive_cores": primitive_cores,
                    "binding": binding,
                    "source_bound": True,
                    "output_bound": True,
                }
            )
    return sorted(calls, key=lambda call: call["index"])


def validate_call_graph(certificate: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    profiles = certificate["profiles"]
    require(len(profiles) == 2, "exactly two diagnostic profiles are required")
    expanded: dict[str, list[dict[str, Any]]] = {}
    for profile in profiles:
        calls = expand_call_families(certificate, profile)
        require(len(calls) == 83, f"{profile['name']}: call count drift")
        require([call["index"] for call in calls] == list(range(83)), "call indices are not 0..82")
        require(sum(call["primitive_cores"] for call in calls) == profile["total_cores"], "core total drift")
        require(
            sum(call["algorithm_id"] != 2 for call in calls) == profile["secret_calls"] == 15,
            "secret-call count drift",
        )
        require(
            sum(call["algorithm_id"] == 2 for call in calls) == profile["collision_calls"] == 68,
            "collision-call count drift",
        )
        require(all(call["source_bound"] and call["output_bound"] for call in calls), "unbound call")
        policy = calls[74]
        require(policy["family"] == "private_auth_policy", "call 74 must be private auth policy")
        require(policy["role"] == "pl.b4481", "call 74 role drift")
        require("stable" not in policy["family"], "call 74 must not be stablecoin policy")
        expanded[profile["name"]] = calls

    graph = certificate["hash_graph"]
    require(graph["physical_calls"] == 83, "physical hash-call total drift")
    require(graph["output_bytes"] == 83 * 56 == 4648, "hash-output bytes drift")
    require(graph["output_bits"] == graph["output_bytes"] * 8, "hash-output bits drift")
    require(graph["merkle_hash_to_hash_edges"] == 64, "Merkle chain-edge total drift")
    require(graph["terminal_merkle_to_anchor_edges"] == 2, "Merkle anchor-edge total drift")
    public_edges = sum(
        call["binding"]["tag"] != 0 for call in expanded[profiles[0]["name"]]
    )
    require(public_edges == graph["public_digest_edges"] == 7, "public digest-edge total drift")
    return expanded


def validate_frame_layouts(certificate: Mapping[str, Any]) -> None:
    spec = certificate["frame_layouts"]
    prefix = spec["common_prefix"]
    require(
        prefix
        == {
            "candidate_profile_tag_bytes": 8,
            "role_tag_bytes": 8,
            "field_count_bytes": 1,
            "field_length_bytes_per_field": 2,
            "field_lengths_endianness": "big",
        },
        "canonical frame prefix drift",
    )
    fixed_prefix_bytes = 17
    layouts = spec["layouts"]
    require(isinstance(layouts, list) and layouts, "frame layouts must be nonempty")
    by_id = {layout["id"]: layout for layout in layouts}
    require(len(by_id) == len(layouts), "duplicate frame layout id")
    frames = {frame["id"]: frame for frame in certificate["frames"]}
    require(set(by_id) == set(frames), "frame layouts do not exactly cover frame inventory")
    for layout in layouts:
        fields = layout["fields"]
        require(isinstance(fields, list) and fields, f"empty frame layout {layout['id']}")
        names = [field["name"] for field in fields]
        require(len(names) == len(set(names)), f"duplicate field in frame layout {layout['id']}")
        require(
            all(isinstance(field["bytes"], int) and field["bytes"] > 0 for field in fields),
            f"invalid field width in frame layout {layout['id']}",
        )
        derived_bytes = fixed_prefix_bytes + 2 * len(fields) + sum(
            field["bytes"] for field in fields
        )
        require(derived_bytes == layout["frame_bytes"], f"frame layout width drift {layout['id']}")
        frame = frames[layout["id"]]
        require(frame["bytes"] == layout["frame_bytes"], f"frame/layout mismatch {layout['id']}")

        totals = {"constant": fixed_prefix_bytes + 2 * len(fields), "statement": 0, "private": 0, "internal_digest": 0}
        directional_bytes = 0
        for field in fields:
            source_class = field["accounting_class"]
            if source_class == "directional-current-or-sibling":
                directional_bytes += field["bytes"]
            else:
                require(source_class in totals, f"unknown frame source class {source_class}")
                totals[source_class] += field["bytes"]
            if "source_ranges" in field:
                ranges = field["source_ranges"]
                require(
                    sum(end - start for start, end in ranges) == field["bytes"],
                    f"source-range width drift {layout['id']}:{field['name']}",
                )
                require(
                    all(0 <= start < end <= certificate["codec"]["bytes"] for start, end in ranges),
                    f"source range outside statement {layout['id']}:{field['name']}",
                )
        if directional_bytes:
            directional = layout.get("accounting_payload_totals", {})
            require(sum(directional.values()) == directional_bytes, f"directional source total drift {layout['id']}")
            for source_class, width in directional.items():
                require(source_class in totals, f"unknown directional source class {source_class}")
                totals[source_class] += width
        for source_class, width in totals.items():
            require(frame[source_class] == width, f"frame source slice drift {layout['id']}:{source_class}")


def validate_frames(certificate: Mapping[str, Any]) -> None:
    validate_frame_layouts(certificate)
    frames = certificate["frames"]
    totals = {key: 0 for key in ("constant", "statement", "private", "internal_digest", "bytes")}
    nodes = 0
    for frame in frames:
        require_keys(
            frame,
            ("id", "bytes", "static_nodes", "constant", "statement", "private", "internal_digest"),
            "frame",
        )
        breakdown = frame["constant"] + frame["statement"] + frame["private"] + frame["internal_digest"]
        require(breakdown == frame["bytes"], f"frame source partition drift: {frame['id']}")
        nodes += frame["static_nodes"]
        totals["bytes"] += frame["bytes"] * frame["static_nodes"]
        for key in ("constant", "statement", "private", "internal_digest"):
            totals[key] += frame[key] * frame["static_nodes"]
    expected = certificate["frame_graph_totals"]
    require(nodes == expected["static_frame_nodes"] == 99, "static frame-node total drift")
    require(totals["bytes"] == expected["static_frame_bytes"] == 18695, "static frame-byte total drift")
    require(expected["static_frame_bits"] == totals["bytes"] * 8, "static frame-bit total drift")
    for key in ("constant", "statement", "private", "internal_digest"):
        require(totals[key] == expected[f"{key}_bytes"], f"{key} frame-byte total drift")
    require(expected["ordinary_frame_nodes"] == 79, "ordinary frame-node total drift")
    require(expected["authorization_arm_frame_nodes"] == 20, "authorization-arm total drift")


def mode_accepts(mask: int, mode: str) -> bool:
    inputs = [bool(mask & 1), bool(mask & 2)]
    outputs = [bool(mask & 4), bool(mask & 8)]
    nonempty = any(inputs + outputs)
    if mode == "single":
        shape = True
    elif mode in ("init", "lock"):
        shape = any(inputs) and outputs[0]
    elif mode == "approval":
        shape = all(inputs) and outputs[0]
    elif mode == "final":
        shape = all(inputs)
    else:
        raise CertificateError(f"unknown mode {mode!r}")
    return nonempty and shape


def parse_case(value: str) -> tuple[int, str]:
    require(isinstance(value, str) and value.count(":") == 1, f"invalid mask/mode case {value!r}")
    mask_text, mode = value.split(":")
    require(re.fullmatch(r"[01]{4}", mask_text) is not None, f"invalid mask {mask_text!r}")
    return int(mask_text, 2), mode


def validate_corpus(certificate: Mapping[str, Any], corpus: Mapping[str, Any]) -> None:
    require(corpus["schema"] == "hegemon.hx448c02.scalar-m4-parity-corpus.v1", "corpus schema drift")
    modes = corpus["modes"]
    require(modes == ["single", "init", "approval", "lock", "final"], "mode order drift")
    universe = {(mask, mode) for mask in range(16) for mode in modes}
    expected_accepted = {case for case in universe if mode_accepts(*case)}
    expected_rejected = universe - expected_accepted
    accepted = {parse_case(case) for case in corpus["accepted_mask_mode_cases_per_profile"]}
    rejected = {parse_case(case) for case in corpus["rejected_mask_mode_cases_per_profile"]}
    require(accepted == expected_accepted, "accepted mask/mode corpus is not exact")
    require(rejected == expected_rejected, "rejected mask/mode corpus is not exact")
    require(len(accepted) == 33 and len(rejected) == 47, "mask/mode cardinality drift")
    require(accepted.isdisjoint(rejected) and accepted | rejected == universe, "mask partition drift")

    stable = corpus["stablecoin_cases"]
    ids = [case["id"] for case in stable]
    require(len(ids) == len(set(ids)), "duplicate stablecoin case id")
    required_stable = {
        "disabled-canonical-zero-no-view",
        "enabled-exact-live-view-mint",
        "enabled-exact-live-view-burn",
        "enabled-policy-missing",
        "enabled-policy-hash-mismatch",
        "enabled-policy-inactive",
        "enabled-policy-before-height",
        "enabled-policy-at-retirement",
        "enabled-asset-mismatch",
        "enabled-version-mismatch",
        "enabled-oracle-mismatch",
        "enabled-attestation-mismatch",
        "enabled-attestation-disputed",
        "enabled-oracle-future",
        "enabled-oracle-stale",
        "enabled-issuance-zero",
        "enabled-issuance-over-limit",
    }
    require(required_stable <= set(ids), "stablecoin corpus is missing a live-policy edge")
    for required in (
        "enabled-empty-manifest",
        "enabled-no-plausible-candidate",
        "enabled-irrelevant-entry-before-valid",
        "enabled-first-plausible-fails-later-plausible-succeeds",
        "enabled-all-plausible-candidates-fail",
        "retained-whole-manifest-entry-mutation",
        "retained-current-height-mutation",
        "direct-six-word-policy-mapping",
        "direct-six-word-oracle-mapping",
        "direct-six-word-attestation-mapping",
    ):
        require(required in ids, f"stablecoin corpus is missing whole-view/direct-word case {required}")
    mutation_classes = corpus["mutation_classes"]
    require(len(mutation_classes) == len(set(mutation_classes)), "duplicate mutation class")
    for required in (
        "retired-hx448c01-magic",
        "statement-truncation",
        "statement-trailing-byte",
        "scalar-final-limb-high-byte",
        "m4-final-word-high-24-bits",
        "stablecoin-48-to-56-padding",
        "stablecoin-56-to-48-truncation",
        "call-74-relabelled-stablecoin-policy",
        "merkle-chain-digest-byte",
        "public-output-binding-byte",
        "authorization-unselected-arm-byte",
        "manifest-policy-tuple-byte",
        "manifest-current-height",
    ):
        require(required in mutation_classes, f"missing mutation class {required}")

    execution = certificate["missing_executed_graph"]
    profile_count = len(certificate["profiles"])
    accepted_total = profile_count * len(accepted)
    rejected_total = profile_count * len(rejected)
    derived = {
        "compiled_constraint_systems_required": profile_count,
        "accepted_shape_witnesses_required": accepted_total,
        "rejected_shape_witnesses_required": rejected_total,
        "per_call_frame_digest_comparisons_required": accepted_total * 83,
        "authorization_arm_frame_comparisons_required": accepted_total * 20,
        "unique_static_frame_comparisons_required": accepted_total * 99,
        "static_frame_byte_mappings_required": accepted_total
        * certificate["frame_graph_totals"]["static_frame_bytes"],
        "hash_output_byte_mappings_required": accepted_total
        * certificate["hash_graph"]["output_bytes"],
        "merkle_hash_chain_edges_required": accepted_total * 64,
        "terminal_anchor_edges_required": accepted_total * 2,
        "public_digest_edges_required": accepted_total * 7,
        "selected_frame_mutations_required": accepted_total * 83,
        "primitive_core_executions_required": sum(
            len(accepted) * profile["total_cores"] for profile in certificate["profiles"]
        ),
        "stablecoin_cases_required": len(stable),
        "stablecoin_direct_word_mappings_required": profile_count * 18,
        "positive_semantic_class_profile_cases_required": profile_count
        * len(corpus["positive_semantic_cases_per_profile"]),
        "semantic_negative_class_profile_cases_required": profile_count
        * len(corpus["negative_semantic_cases_per_profile"]),
        "semantic_edge_profile_mappings_required": profile_count
        * certificate["semantic_mapping_totals"]["source_edges"],
        "mutation_classes_required": len(mutation_classes),
        "codec_byte_mutations_required": certificate["codec"]["bytes"],
    }
    for key, expected in derived.items():
        require(execution[key] == expected, f"missing-execution denominator drift: {key}")
    for key, value in execution.items():
        if key.endswith("_executed"):
            require(value == 0, f"source-only certificate cannot claim executed evidence: {key}")


def validate_stablecoin_boundary(certificate: Mapping[str, Any]) -> None:
    stable = certificate["stablecoin_boundary"]
    require(stable["statement_authority_bytes"] == 48, "stablecoin authority width drift")
    require(stable["m4_words_per_authority"] == 6, "stablecoin word width drift")
    require(stable["policy_tuple_scale_bytes"] == 61, "stablecoin tuple width drift")
    require(
        stable["policy_tuple_component_bytes"] == [4, 4, 8, 16, 16, 8, 4, 1],
        "stablecoin SCALE component widths drift",
    )
    require(sum(stable["policy_tuple_component_bytes"]) == 61, "stablecoin tuple sum drift")
    require(stable["domain"] == "hegemon.kernel.stablecoin-policy.v2", "stablecoin domain drift")
    require(stable["no_padding_or_truncation"], "stablecoin adapter must prohibit conversions")
    require(stable["diagnostic_compatibility_evidence"], "stablecoin compatibility evidence missing")
    require(stable["manifest_view"] == "whole ProtocolManifest snapshot", "manifest-view scope drift")
    require(
        stable["candidate_selection"]
        == "existential over entries plausible by asset_id OR kernel policy_hash",
        "manifest candidate-selection rule drift",
    )
    require(stable["current_height_external"], "current height must remain an external fact")
    require(not stable["manifest_view_consensus_authenticated"], "diagnostic view is not state-authenticated")
    require(not stable["lifecycle_constraints_compiled"], "lifecycle is not an M4 constraint")
    require(not stable["strict_stablecoin_pq_margin"], "384-bit authorities have no strict margin")
    require(not stable["production_authorized"], "stablecoin diagnostic cannot authorize production")
    require(stable["generic_quantum_collision_bits"] == 128, "384-bit collision screen drift")
    require(
        stable["required_production_migration"]
        == "fresh wider bindings rederived from authoritative policy/oracle/attestation preimages",
        "stablecoin production migration boundary drift",
    )

    tuple_bytes = bytes.fromhex(stable["kat"]["tuple_hex"])
    require(len(tuple_bytes) == 61, "stablecoin KAT tuple is not 61 bytes")
    domain = stable["domain"].encode("ascii")
    transcript = (
        b"hegemon.blake2b-384.frame-v1"
        + len(domain).to_bytes(8, "little")
        + domain
        + len(tuple_bytes).to_bytes(8, "little")
        + tuple_bytes
    )
    digest = hashlib.blake2b(transcript, digest_size=48).hexdigest()
    require(len(transcript) == stable["kat"]["framed_preimage_bytes"] == 140, "KAT frame length drift")
    require(digest == stable["kat"]["policy_hash_hex"], "stablecoin RFC 7693 KAT drift")


def validate_semantic_mappings(certificate: Mapping[str, Any], context: SourceContext) -> None:
    mappings = certificate["semantic_mappings"]
    require(isinstance(mappings, list) and mappings, "semantic mappings must be nonempty")
    ids: set[str] = set()
    enforcement_counts = {"aggregate-m4": 0, "external-admission": 0, "source-projection": 0}
    edge_count = 0
    for mapping in mappings:
        require_keys(
            mapping,
            ("id", "edges", "edge_count", "enforcement", "scalar", "m4", "executed"),
            "semantic mapping",
        )
        require(mapping["id"] not in ids, f"duplicate semantic mapping {mapping['id']}")
        ids.add(mapping["id"])
        require(mapping["enforcement"] in enforcement_counts, f"unknown enforcement class")
        edges = mapping["edges"]
        require(isinstance(edges, list) and edges, f"empty semantic edge list {mapping['id']}")
        require(all(isinstance(edge, str) and edge for edge in edges), "bad semantic edge label")
        require(len(edges) == len(set(edges)), f"duplicate semantic edge in {mapping['id']}")
        require(mapping["edge_count"] == len(edges), f"semantic edge count drift {mapping['id']}")
        require(mapping["executed"] is False, "source-only semantic mapping cannot be executed")
        edge_count += mapping["edge_count"]
        enforcement_counts[mapping["enforcement"]] += mapping["edge_count"]
        sides = ["scalar", "m4"] + (["native"] if "native" in mapping else [])
        for side in sides:
            anchor = mapping[side]
            require_keys(anchor, ("path", "anchors"), f"semantic mapping {mapping['id']} {side}")
            require(anchor["path"] in context.texts, f"unbound semantic path {anchor['path']}")
            source = context.texts[anchor["path"]]
            require(anchor["anchors"], f"empty semantic anchors for {mapping['id']} {side}")
            for fragment in anchor["anchors"]:
                require(fragment in source, f"missing {side} semantic anchor {mapping['id']}: {fragment!r}")
    totals = certificate["semantic_mapping_totals"]
    require(totals["mapping_groups"] == len(mappings), "semantic mapping-group total drift")
    require(totals["source_edges"] == edge_count, "semantic edge total drift")
    for key, value in enforcement_counts.items():
        require(totals[f"{key}_edges"] == value, f"{key} semantic edge total drift")
    required_ids = {
        "codec-byte-authority",
        "stablecoin-direct-48-byte-fields",
        "stablecoin-live-manifest-external-admission",
        "activity-and-nonempty-shape",
        "inactive-input-zero-padding",
        "inactive-output-and-ciphertext-zero-padding",
        "note-ranges-and-asset-selectors",
        "asset-slot-canonical-order",
        "nullifier-uniqueness-and-public-admission",
        "authorization-shapes-and-five-mode-one-hot",
        "single-key-transition",
        "accumulator-init-transition",
        "approval-transition",
        "value-lock-transition",
        "final-threshold-transition",
        "authorization-digest-resolution",
        "native-and-multi-asset-balance",
        "stablecoin-issuance-balance",
        "ciphertext-size-and-padding",
        "merkle-position-orientation-and-anchor",
    }
    require(required_ids <= ids, "semantic map omits a required family")


def rust_source_digest(certificate: Mapping[str, Any], context: SourceContext) -> bytes:
    spec = certificate["rust_source_digest"]
    hasher = hashlib.sha512(spec["domain"].encode("ascii") + b"\0")
    for path in spec["ordered_files"]:
        require(path in context.payloads, f"Rust source digest file is not pinned: {path}")
        hasher.update(context.payloads[path])
    hasher.update(certificate["binius_dependency"]["tree_sha512"].encode("ascii"))
    digest = hasher.digest()
    require(digest.hex() == spec["sha512"], "Rust source_digest() rederivation drift")
    return digest


def activation_bytes(activation: Mapping[str, Any]) -> bytes:
    output = bytearray()
    for key in ("circuit_version", "crypto_suite", "family_id", "action_id"):
        output.extend(activation[key].to_bytes(2, "big"))
    output.extend(activation["network_id"].to_bytes(4, "big"))
    output.extend(bytes((activation["backend_id"], activation["proof_profile"])))
    output.extend(activation["domain_set"].to_bytes(2, "big"))
    for key in ("chain_id", "genesis_id", "rules_hash"):
        value = bytes.fromhex(activation[key])
        require(len(value) == 56 and any(value), f"activation {key} must be nonzero 56 bytes")
        output.extend(value)
    require(len(output) == 184, "activation byte width drift")
    return bytes(output)


def role_registry_entry(role: Mapping[str, Any], profile: Mapping[str, Any]) -> bytes:
    algorithm_id = profile["secret_algorithm_id"] if role["algorithm_class"] == "secret" else 2
    cores = role["cores"][profile["name"]] if role["algorithm_class"] == "secret" else role["cores"]["fixed"]
    encoded_role = role["role"].encode("ascii")
    require(len(encoded_role) == 8, f"role is not eight bytes: {role['role']}")
    return (
        encoded_role
        + bytes((algorithm_id, role["purpose_id"]))
        + role["calls"].to_bytes(2, "big")
        + role["maximum_frame_bytes"].to_bytes(4, "big")
        + (56).to_bytes(2, "big")
        + cores.to_bytes(2, "big")
    )


def bind_call(call: Mapping[str, Any]) -> bytes:
    role = call["role"].encode("ascii")
    require(len(role) == 8, f"call role is not eight bytes: {call['role']}")
    frame = call["frame"]
    if frame["type"] == "exact":
        bound_frame = b"\x00" + frame["bytes"].to_bytes(4, "big")
    elif frame["type"] == "authorization-mux":
        require(len(frame["arm_bytes"]) == 5, "authorization frame needs five arms")
        bound_frame = b"\x01" + b"".join(value.to_bytes(4, "big") for value in frame["arm_bytes"])
    else:
        raise CertificateError(f"unknown frame type {frame['type']}")
    kind = bytes((call["kind_tag"], *call["coordinates"]))
    binding = bytes((call["binding"]["tag"],))
    if call["binding"].get("index") is not None:
        binding += bytes((call["binding"]["index"],))
    return (
        call["index"].to_bytes(2, "big")
        + role
        + bytes((call["algorithm_id"], call["purpose_id"]))
        + call["maximum_frame_bytes"].to_bytes(4, "big")
        + bound_frame
        + call["output_bytes"].to_bytes(2, "big")
        + call["primitive_cores"].to_bytes(2, "big")
        + bytes((int(call["source_bound"]), int(call["output_bound"])))
        + kind
        + binding
    )


def validate_program_digests(
    certificate: Mapping[str, Any],
    context: SourceContext,
    expanded: Mapping[str, Sequence[Mapping[str, Any]]],
) -> None:
    source = rust_source_digest(certificate, context)
    activation = activation_bytes(certificate["diagnostic_activation"])
    dependency = certificate["binius_dependency"]
    codec = certificate["codec"]
    stable = certificate["stablecoin_boundary"]
    for profile in certificate["profiles"]:
        hasher = hashlib.sha512(b"hegemon.m4-mixed-candidate.program.v2\0")
        hasher.update(codec["magic_ascii"].encode("ascii"))
        hasher.update(codec["magic_ascii"].encode("ascii"))
        hasher.update(codec["grammar"].to_bytes(2, "big"))
        hasher.update(bytes((profile["profile_id"],)))
        hasher.update(dependency["revision"].encode("ascii"))
        hasher.update(dependency["tree_sha512"].encode("ascii"))
        hasher.update(activation)
        hasher.update(stable["domain"].encode("ascii"))
        hasher.update(stable["policy_tuple_scale_bytes"].to_bytes(2, "big"))
        hasher.update(bytes((48, 48, 1, 0, 0)))
        hasher.update(codec["bytes"].to_bytes(4, "big"))
        hasher.update(certificate["private_transport"]["total_words"].to_bytes(4, "big"))
        for role in certificate["role_registry"]:
            hasher.update(role_registry_entry(role, profile))
        for call in expanded[profile["name"]]:
            hasher.update(bind_call(call))
        hasher.update(source)
        actual = hasher.hexdigest()
        require(actual == profile["program_sha512"], f"{profile['name']}: program digest drift")


def validate_authority(certificate: Mapping[str, Any]) -> None:
    authority = certificate["authority"]
    for key in (
        "winner_selected",
        "identity_frozen",
        "aggregate_relation_artifact_verified",
        "compiled_geometry_verified",
        "executed_scalar_m4_parity",
        "complete_zero_knowledge",
        "composed_qrom_pq128",
        "strict_stablecoin_pq_margin",
        "production_authorized",
    ):
        require(authority[key] is False, f"source-only certificate must keep {key}=false")
    require(authority["winner"] is None, "source-only certificate cannot select a winner")
    require(certificate["claim_level"] == "source-only exact refinement map", "claim-level drift")


def validate_private_transport(certificate: Mapping[str, Any]) -> None:
    transport = certificate["private_transport"]
    require(transport["base_words"] == 671, "base private transport drift")
    require(transport["ciphertext_semantic_bytes_per_output"] == 2147, "ciphertext width drift")
    required_words = (transport["ciphertext_semantic_bytes_per_output"] + 7) // 8
    require(transport["ciphertext_words_per_output"] == required_words == 269, "ciphertext words drift")
    require(transport["ciphertext_padding_zero_bytes_per_output"] == 5, "ciphertext padding drift")
    require(
        transport["total_words"] == transport["base_words"] + 2 * required_words == 1209,
        "private word total drift",
    )
    require(transport["total_bytes"] == transport["total_words"] * 8 == 9672, "private bytes drift")


def validate_frozen_inventories(
    certificate: Mapping[str, Any], corpus: Mapping[str, Any]
) -> None:
    relation_keys = (
        "codec",
        "private_transport",
        "profiles",
        "role_registry",
        "call_families",
        "frame_layouts",
        "frames",
        "frame_graph_totals",
        "hash_graph",
        "stablecoin_boundary",
        "diagnostic_activation",
        "rust_source_digest",
        "binius_dependency",
    )
    relation = {key: certificate[key] for key in relation_keys}
    require(
        canonical_json_sha256(relation) == CERTIFIED_RELATION_INVENTORY_SHA256,
        "frozen relation inventory drift",
    )
    semantic = {
        "semantic_mappings": certificate["semantic_mappings"],
        "semantic_mapping_totals": certificate["semantic_mapping_totals"],
    }
    require(
        canonical_json_sha256(semantic) == CERTIFIED_SEMANTIC_INVENTORY_SHA256,
        "frozen semantic-edge inventory drift",
    )
    require(
        canonical_json_sha256(corpus) == CERTIFIED_CORPUS_SHA256,
        "frozen mutation/witness corpus drift",
    )


def validate_all(
    certificate: Mapping[str, Any],
    corpus: Mapping[str, Any],
    context: SourceContext | None = None,
) -> dict[str, Any]:
    require(certificate["schema"] == "hegemon.hx448c02.scalar-m4-source-parity.v1", "schema drift")
    require_keys(
        certificate,
        (
            "claim_level",
            "authority",
            "source_pins",
            "source_manifest",
            "binius_dependency",
            "source_anchors",
            "codec",
            "private_transport",
            "profiles",
            "role_registry",
            "call_families",
            "frame_layouts",
            "frames",
            "frame_graph_totals",
            "hash_graph",
            "stablecoin_boundary",
            "semantic_mappings",
            "semantic_mapping_totals",
            "missing_executed_graph",
            "rust_source_digest",
            "diagnostic_activation",
        ),
        "certificate",
    )
    if context is None:
        context = collect_source_context(certificate)
    validate_authority(certificate)
    validate_frozen_inventories(certificate, corpus)
    validate_source_pins(certificate, context)
    validate_anchors(certificate, context)
    validate_codec(certificate)
    validate_private_transport(certificate)
    expanded = validate_call_graph(certificate)
    validate_frames(certificate)
    validate_stablecoin_boundary(certificate)
    validate_semantic_mappings(certificate, context)
    validate_corpus(certificate, corpus)
    validate_program_digests(certificate, context, expanded)
    evidence_files = {
        path.name: path.read_bytes()
        for path in (
            CERTIFICATE_PATH,
            CORPUS_PATH,
            HERE / "README.md",
            HERE / "EXECPLAN.md",
            Path(__file__),
            HERE / "test_check_certificate.py",
        )
        if path.is_file()
    }
    return {
        "framed_source_sha512": certificate["source_manifest"]["framed_sha512"],
        "rust_source_sha512": certificate["rust_source_digest"]["sha512"],
        "program_sha512": {profile["name"]: profile["program_sha512"] for profile in certificate["profiles"]},
        "evidence_sha512": framed_digest(b"hegemon.hx448c02.scalar-m4-parity.evidence.v1\0", evidence_files),
        "source_files": len(context.payloads),
        "binius_files": context.binius_files,
        "calls": 83,
        "frame_layouts": len(certificate["frame_layouts"]["layouts"]),
        "static_frame_nodes": certificate["frame_graph_totals"]["static_frame_nodes"],
        "static_frame_bytes": certificate["frame_graph_totals"]["static_frame_bytes"],
        "accepted_mask_mode_cases_per_profile": len(
            corpus["accepted_mask_mode_cases_per_profile"]
        ),
        "rejected_mask_mode_cases_per_profile": len(
            corpus["rejected_mask_mode_cases_per_profile"]
        ),
        "semantic_mapping_groups": len(certificate["semantic_mappings"]),
        "semantic_source_edges": certificate["semantic_mapping_totals"]["source_edges"],
        "executed_scalar_m4_parity": False,
        "production_authorized": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the pass result as JSON")
    arguments = parser.parse_args(argv)
    try:
        certificate = load_json(CERTIFICATE_PATH)
        corpus = load_json(CORPUS_PATH)
        result = validate_all(certificate, corpus)
    except CertificateError as error:
        print(f"HX448C02 scalar/M4 source parity: FAIL: {error}", file=sys.stderr)
        return 1
    if arguments.json:
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print(
            "HX448C02 scalar/M4 source parity: PASS "
            f"(calls={result['calls']} semantic_groups={result['semantic_mapping_groups']} "
            f"source_sha512={result['framed_source_sha512']} "
            "executed=0 production_authorized=false)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
