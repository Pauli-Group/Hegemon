#!/usr/bin/env python3
"""Fail if native 0.10 launch surfaces depend on legacy JSON chain specs."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CHECKS = {
    "start.sh": ("--chain", "dev-chainspec.json", "testnet-spec.json", "mainnet-spec.json"),
    "hegemon-app/package.json": (
        "dev-chainspec.json",
        "testnet-spec.json",
        "mainnet-spec.json",
    ),
    "hegemon-app/electron/nodeManager.ts": (
        "--chain",
        "chainSpecPath",
        "dev-chainspec.json",
        "testnet-spec.json",
        "mainnet-spec.json",
    ),
    "hegemon-app/src/App.tsx": (
        "chainSpecPath",
        "dev-chainspec.json",
        "testnet-spec.json",
        "mainnet-spec.json",
    ),
    "hegemon-app/src/types.ts": (
        "chainSpecPath",
        "dev-chainspec.json",
        "testnet-spec.json",
        "mainnet-spec.json",
    ),
}


def main() -> int:
    violations: list[str] = []
    for relative, forbidden_terms in CHECKS.items():
        path = ROOT / relative
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            violations.append(f"{relative}: file missing")
            continue

        for term in forbidden_terms:
            if term in text:
                violations.append(f"{relative}: forbidden native startup term {term!r}")

    if violations:
        print("native startup policy violations:", file=sys.stderr)
        for violation in violations:
            print(f" - {violation}", file=sys.stderr)
        return 1

    print("native startup policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
