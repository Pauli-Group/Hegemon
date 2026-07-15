#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_release_crypto_profile.py"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="release-profile-test-") as raw:
        temp = Path(raw)
        binary = temp / "hegemon-node"
        binary.write_text(
            "prefix\n"
            "HEGEMON_PRODUCTION_CRYPTO_PROFILE:CIRCUIT=3:CRYPTO=2:"
            "BACKEND=smallwood_candidate:ARITH=direct-packed64-committed-bindings-"
            "inline-merkle-skip-initial-mds-v2:RHO=3:OPENINGS=3:DECS_EVALS=32768:"
            "DECS_OPENINGS=24:FLOOR=128\n",
            encoding="utf-8",
        )
        manifest = temp / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "target_triple": "non-native-security-test-target",
                    "artifacts": [{"binary": "hegemon-node", "path": "hegemon-node"}],
                }
            ),
            encoding="utf-8",
        )

        static = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(manifest),
                "--root",
                str(temp),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if static.returncode != 0 or '"mode": "static-cross-target"' not in static.stdout:
            raise SystemExit("static cross-target diagnostic mode unexpectedly failed")

        required = subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--manifest",
                str(manifest),
                "--root",
                str(temp),
                "--require-executed",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if required.returncode == 0:
            raise SystemExit("required release attestation accepted marker-only inspection")
        if "must execute target binaries natively" not in required.stdout:
            raise SystemExit(
                "required release attestation rejected for the wrong reason:\n"
                + required.stdout
            )
    print("release crypto profile execution-mode negative test passed")


if __name__ == "__main__":
    main()
