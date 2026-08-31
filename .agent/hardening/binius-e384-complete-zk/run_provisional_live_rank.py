#!/usr/bin/env python3
"""Direct-rustc runner for the exact provisional mixed-BaseFold rank screen."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE = REPO_ROOT / "prototypes/standalone-shake256-binius/strict-mixed-field/src/lib.rs"
COMPLETE_ZK = SOURCE.with_name("complete_zk.rs")
AUTHENTICATED_BASEFOLD = SOURCE.with_name("authenticated_basefold.rs")
MIXED_BASEFOLD_PCS = SOURCE.with_name("mixed_basefold_pcs.rs")
SCREEN = Path(__file__).with_name("provisional_live_rank.rs")
HARNESS = Path("/tmp/hegemon-e384-provisional-live-rank.rs")
BINARY = Path("/tmp/hegemon-e384-provisional-live-rank")


def main() -> int:
    lines = [
        line
        for line in SOURCE.read_text().splitlines()
        if line.strip()
        not in {
            "pub mod authenticated_basefold;",
            "pub mod mixed_basefold_pcs;",
            "pub mod complete_zk;",
            "pub mod provisional_live_rank;",
        }
    ]
    lines.extend(
        (
            "",
            f"#[path = {json.dumps(str(AUTHENTICATED_BASEFOLD))}]",
            "pub mod authenticated_basefold;",
            f"#[path = {json.dumps(str(MIXED_BASEFOLD_PCS))}]",
            "pub mod mixed_basefold_pcs;",
            f"#[path = {json.dumps(str(COMPLETE_ZK))}]",
            "pub mod complete_zk;",
            f"#[path = {json.dumps(str(SCREEN))}]",
            "pub mod provisional_live_rank;",
            "fn main() { provisional_live_rank::run().expect(\"rank screen\"); }",
        )
    )
    HARNESS.write_text("\n".join(lines) + "\n")
    subprocess.run(
        ["rustc", "--edition", "2024", "-Dwarnings", str(HARNESS), "-o", str(BINARY)],
        cwd=REPO_ROOT,
        check=True,
    )
    subprocess.run([str(BINARY)], cwd=REPO_ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
