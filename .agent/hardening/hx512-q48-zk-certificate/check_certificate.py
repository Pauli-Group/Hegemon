#!/usr/bin/env python3
"""Dependency-free readback for the retained HX512 q48/s6 certificate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = Path(__file__).with_name("certificate_manifest.json")


def sha512(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for key in ("module", "exec_plan"):
        item = manifest[key]
        path = ROOT / item["path"]
        require(path.is_file(), f"missing {key}: {path}")
        require(sha512(path) == item["sha512"], f"{key} SHA-512 drift")

    export = manifest["module_export"]
    export_source = (ROOT / export["path"]).read_text(encoding="utf-8")
    require(
        export_source.splitlines().count(export["exact_line"]) == 1,
        "certificate module export is absent or duplicated",
    )

    module_source = (ROOT / manifest["module"]["path"]).read_text(encoding="utf-8")
    required_tokens = (
        "pub const HX512_Q48_PIOP_OPENINGS: usize = 6;",
        "pub const HX512_Q48_DECS_OPENINGS: usize = 48;",
        "pub const HX512_Q48_DECS_ETA: usize = 5;",
        "pub const HX512_CMS_QROM_QUERY_BOUND_LOG2: u32 = 64;",
        "pub const HX512_CMS_QROM_LOSS_FACTOR: u32 = 12;",
        "pub const HX512_COMPOSED_SECURITY_TARGET_BITS: u32 = 128;",
        "decs_committed_leaf_tape_count: 1 << 20,",
        "pub const HX512_ALL_VERIFIER_VIEW_FIELDS: [Hx512VerifierViewField; 33]",
        "classical_rom_joint_simulator_proved: false,",
        "adaptive_qrom_lift_proved: false,",
        "complete_zero_knowledge: false,",
        "compiled_refinement: false,",
        "production_authorized: false,",
        "measured_proof_bytes: None,",
    )
    for token in required_tokens:
        require(token in module_source, f"required fail-closed token missing: {token}")
    require(
        "use crate::smallwood_engine" not in module_source,
        "certificate imported mutable legacy engine authority",
    )

    authority = manifest["authority"]
    require(
        all(authority[key] is False for key in (
            "classical_rom_joint_simulator_proved",
            "adaptive_qrom_lift_proved",
            "complete_zero_knowledge",
            "compiled_refinement",
            "production_authorized",
        )),
        "manifest authority changed from fail closed",
    )
    require(authority["measured_proof_bytes"] is None, "unmeasured bytes gained authority")

    print(json.dumps({
        "artifact": manifest["artifact"],
        "module_sha512": manifest["module"]["sha512"],
        "exec_plan_sha512": manifest["exec_plan"]["sha512"],
        "view_field_count": 33,
        "focused_tests_passed": manifest["focused_test"]["passed"],
        "complete_zero_knowledge": False,
        "production_authorized": False,
        "readback": "PASS",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
