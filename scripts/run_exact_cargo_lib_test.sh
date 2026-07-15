#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <package> <fully-qualified-test-name> [cargo-options...]" >&2
  exit 2
fi

PACKAGE="$1"
TEST_NAME="$2"
shift 2

LISTED="$(cargo test -p "$PACKAGE" "$@" --lib -- --list)"
MATCH_COUNT="$(awk -v expected="${TEST_NAME}: test" \
  '$0 == expected { count += 1 } END { print count + 0 }' <<<"$LISTED")"
if [[ "$MATCH_COUNT" -ne 1 ]]; then
  printf 'expected exactly one Rust lib test named %s in package %s, found %s\n' \
    "$TEST_NAME" "$PACKAGE" "$MATCH_COUNT" >&2
  exit 97
fi

IGNORED="$(cargo test -p "$PACKAGE" "$@" --lib -- --ignored --list)"
IGNORED_COUNT="$(awk -v expected="${TEST_NAME}: test" \
  '$0 == expected { count += 1 } END { print count + 0 }' <<<"$IGNORED")"
if [[ "$IGNORED_COUNT" -ne 0 ]]; then
  printf 'required Rust lib test %s in package %s is ignored\n' \
    "$TEST_NAME" "$PACKAGE" >&2
  exit 97
fi

if ! OUTPUT="$(CARGO_TERM_COLOR=never cargo test -p "$PACKAGE" "$@" --lib "$TEST_NAME" \
    -- --exact --nocapture 2>&1)"; then
  printf '%s\n' "$OUTPUT" >&2
  exit 1
fi
printf '%s\n' "$OUTPUT"
if ! grep -Eq 'test result: ok\. 1 passed; 0 failed; 0 ignored;' <<<"$OUTPUT"; then
  printf 'required Rust lib test %s in package %s did not execute exactly once\n' \
    "$TEST_NAME" "$PACKAGE" >&2
  exit 97
fi
