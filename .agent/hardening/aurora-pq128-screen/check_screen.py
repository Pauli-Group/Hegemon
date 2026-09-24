#!/usr/bin/env python3
"""Dependency-free release gate for the Aurora PQ128 screen."""

from __future__ import annotations

import argparse
import json

import aurora_pq128_screen as screen


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-local-sources",
        action="store_true",
        help="require inspected primary PDFs and pinned raw libiop files in /private/tmp",
    )
    args = parser.parse_args()
    raw = screen.CERTIFICATE_PATH.read_text(encoding="utf-8")
    document = json.loads(raw)
    screen.validate_certificate(document)
    if raw != screen.canonical_json(document):
        raise AssertionError("certificate.json is not canonical JSON with one trailing LF")
    screen.validate_repo_sources()
    screen.validate_primary_sources(require_present=args.require_local_sources)
    screen.validate_libiop_sources(require_present=args.require_local_sources)
    print("PASS: Aurora PQ128 screen remains canonical and fail-closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
