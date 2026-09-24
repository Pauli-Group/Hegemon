#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED="$ROOT/formal/crypto/HegemonCrypto/SmallWoodV8Smz9RelationProgramComponentsGenerated.lean"
SOURCE="$ROOT/testdata/formal_core_vectors/poseidon2_v8_relation_program.bin"
GENERATED="$(mktemp)"
trap 'rm -f "$GENERATED"' EXIT

python3 "$ROOT/scripts/generate_poseidon2_v8_relation_program_components_lean.py" \
  --self-test "$SOURCE"
python3 "$ROOT/scripts/generate_poseidon2_v8_relation_program_components_lean.py" \
  "$SOURCE" > "$GENERATED"

if ! cmp -s "$EXPECTED" "$GENERATED"; then
  printf 'generated HGV8RP03 Lean component value is stale\n' >&2
  diff -u "$EXPECTED" "$GENERATED" | sed -n '1,200p' >&2 || true
  exit 1
fi

printf 'HGV8RP03 Lean component value matches the exact source artifact\n'

python3 "$ROOT/scripts/generate_poseidon2_v8_program_canonicality_lean.py" \
  --input "$SOURCE" --check
