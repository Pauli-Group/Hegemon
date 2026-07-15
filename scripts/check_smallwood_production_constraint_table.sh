#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED="$ROOT/formal/lean/Hegemon/Transaction/SmallWoodProductionConstraintTableGenerated.lean"
EXPECTED_RUNTIME_CONTRACT="$ROOT/circuits/transaction/src/smallwood_production_constraint_contract_generated.rs"
GENERATED="$(mktemp)"
GENERATED_RUNTIME_CONTRACT="$(mktemp)"
trap 'rm -f "$GENERATED" "$GENERATED_RUNTIME_CONTRACT"' EXIT

(
  cd "$ROOT"
  CARGO_INCREMENTAL=0 cargo run --locked --quiet -p transaction-circuit \
    --features formal-generator \
    --bin gen_smallwood_production_constraint_lean > "$GENERATED"
  CARGO_INCREMENTAL=0 cargo run --locked --quiet -p transaction-circuit \
    --features formal-generator \
    --bin gen_smallwood_production_constraint_lean -- --rust-runtime-contract \
    > "$GENERATED_RUNTIME_CONTRACT"
  rustfmt --edition 2021 "$GENERATED_RUNTIME_CONTRACT"
)

if ! cmp -s "$EXPECTED" "$GENERATED"; then
  printf 'generated SmallWood production constraint table is stale\n' >&2
  diff -u "$EXPECTED" "$GENERATED" | sed -n '1,200p' >&2 || true
  exit 1
fi

if ! cmp -s "$EXPECTED_RUNTIME_CONTRACT" "$GENERATED_RUNTIME_CONTRACT"; then
  printf 'generated SmallWood production runtime contract is stale\n' >&2
  diff -u "$EXPECTED_RUNTIME_CONTRACT" "$GENERATED_RUNTIME_CONTRACT" | sed -n '1,200p' >&2 || true
  exit 1
fi

printf 'SmallWood production constraint table and runtime contract drift gate passed\n'
