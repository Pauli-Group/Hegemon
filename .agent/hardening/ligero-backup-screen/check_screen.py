#!/usr/bin/env python3
"""Dependency-free canonical checker for the Ligero backup screen."""

from __future__ import annotations

import argparse
import json

import ligero_backup_screen as screen


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-local-pdfs",
        action="store_true",
        help="also require every inspected /private/tmp primary PDF to remain present",
    )
    args = parser.parse_args()
    ledger = json.loads(screen.LEDGER_PATH.read_text(encoding="utf-8"))
    screen.validate_ledger(ledger)
    if screen.LEDGER_PATH.read_text(encoding="utf-8") != screen.canonical_json(ledger):
        raise AssertionError("ledger.json is not canonical JSON with one trailing LF")
    screen.validate_relation_source()
    screen.validate_repo_sources()
    screen.validate_primary_pdfs(require_present=args.require_local_pdfs)
    print("PASS: Ligero backup screen remains canonical and fail-closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

