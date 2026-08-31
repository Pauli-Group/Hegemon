#!/usr/bin/env python3
"""Fail-closed mutations for check.py; no Rust build or external package."""

from __future__ import annotations

import copy
import json
import sys

import check


def mutated(source: str, before: str, after: str) -> str:
    if source.count(before) != 1:
        raise RuntimeError(f"mutation target count is not one: {before}")
    return source.replace(before, after, 1)


def main() -> int:
    baseline = check.safe_sources()
    check.audit_sources(baseline, check_certificate=False)
    mutations = [
        (
            "gadget_iv",
            "gadget",
            "0x6a09_e667_f3bc_c908",
            "0x6a09_e667_f3bc_c909",
        ),
        (
            "gadget_counter_high",
            "gadget",
            "builder.constant_word((counter >> 64) as u64)",
            "builder.constant_word((counter >> 63) as u64)",
        ),
        (
            "gadget_final_flag",
            "gadget",
            "work[14] = builder.not_word(work[14]);",
            "work[14] = work[14];",
        ),
        (
            "gadget_host_shortcut",
            "gadget",
            "use serde::{Deserialize, Serialize};",
            "use serde::{Deserialize, Serialize};\nfn forbidden(x: &[u8]) { let _ = blake2b_384(x); }",
        ),
        (
            "semantic_source_binding",
            "semantics",
            "trace\n            .verify_input_bindings(&[], &call.framed_message)",
            "trace\n            /* removed */ .verify_input_bindings(&[], b\"\")",
        ),
        (
            "frontend_compiled_flag",
            "frontend",
            "pub const fn smallwood_blake2b384_boolean_relation_is_compiled() -> bool {\n    false\n}",
            "pub const fn smallwood_blake2b384_boolean_relation_is_compiled() -> bool {\n    true\n}",
        ),
        (
            "hx_scalar_source_binding",
            "full_hx_scalar",
            "trace.verify_input_bindings(&[], &frame.bytes)?;",
            "/* source binding removed */",
        ),
        (
            "hx_scalar_authority",
            "full_hx_scalar",
            "pub const FULL_BLAKE2B448_PRODUCTION_AUTHORIZED: bool = false;",
            "pub const FULL_BLAKE2B448_PRODUCTION_AUTHORIZED: bool = true;",
        ),
        (
            "m4_parameter_block",
            "hx_m4",
            "builder.add_constant_64(0x0101_0038)",
            "builder.add_constant_64(0x0101_0030)",
        ),
        (
            "m4_final_mask",
            "hx_m4",
            "final_mask: [zero, builder.add_constant_64(u64::MAX)]",
            "final_mask: [zero, zero]",
        ),
    ]
    rejected = []
    for name, source_name, before, after in mutations:
        candidate = copy.deepcopy(baseline)
        candidate[source_name] = mutated(candidate[source_name], before, after)
        try:
            check.audit_sources(candidate, check_certificate=False)
        except check.AuditError:
            rejected.append(name)
        else:
            print(json.dumps({"status": "fail", "accepted_mutation": name}, sort_keys=True))
            return 1
    print(json.dumps({"status": "pass", "rejected_mutations": rejected}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
