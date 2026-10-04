#!/usr/bin/env python3
"""Dependency-free entrypoint for the strict odd-field composition gate."""

from composition_ledger import run_check


def main() -> int:
    run_check()
    print("STRICT_ODD_FIELD_COMPOSITION_CHECK_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
