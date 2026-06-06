#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORMAL_MANIFEST="$ROOT/scripts/hegemon_formal_core/Cargo.toml"
if [ -d "${HOME:-}/.cargo/bin" ]; then
  export PATH="${HOME}/.cargo/bin:$PATH"
fi
if [ -d "${HOME:-}/.elan/bin" ]; then
  export PATH="${HOME}/.elan/bin:$PATH"
fi

run_formal_core() {
  cargo run --quiet --manifest-path "$FORMAL_MANIFEST" -- "$@"
}

printf '=== Hegemon formal-core gate ===\n'

printf '\n[1/11] Checking formal-core checker formatting\n'
cargo fmt --manifest-path "$FORMAL_MANIFEST" -- --check

printf '\n[2/11] Running formal-core checker tests\n'
cargo test --quiet --manifest-path "$FORMAL_MANIFEST"

printf '\n[3/11] Checking Lean formal proof kernel\n'
bash "$ROOT/scripts/check_lean_formal.sh"

printf '\n[4/11] Verifying Lean-generated Rust conformance vectors\n'
LEAN_BRIDGE_VECTORS="$(mktemp)"
LEAN_SHIELDED_VECTORS="$(mktemp)"
trap 'rm -f "$LEAN_BRIDGE_VECTORS" "$LEAN_SHIELDED_VECTORS"' EXIT
(
  cd "$ROOT/formal/lean"
  lake exe gen_bridge_vectors > "$LEAN_BRIDGE_VECTORS"
  lake exe gen_shielded_vectors > "$LEAN_SHIELDED_VECTORS"
)
HEGEMON_LEAN_BRIDGE_VECTORS="$LEAN_BRIDGE_VECTORS" \
  cargo test -p protocol-kernel lean_generated_bridge_vectors_match_production -- --nocapture
HEGEMON_LEAN_SHIELDED_VECTORS="$LEAN_SHIELDED_VECTORS" \
  cargo test -p protocol-shielded-pool lean_generated_nullifier_vectors_match_production -- --nocapture

printf '\n[5/11] Auditing formal-core checker dependencies\n'
if ! command -v cargo-audit >/dev/null 2>&1; then
  printf 'cargo-audit is not installed. Install with: cargo install cargo-audit --locked\n' >&2
  exit 2
fi
(
  cd "$ROOT/scripts/hegemon_formal_core"
  cargo audit --color never
)

printf '\n[6/11] Checking formal inventory\n'
run_formal_core check-formal-inventory --root "$ROOT"

printf '\n[7/11] Checking formal security claims ledger\n'
run_formal_core check-claims "$ROOT/config/formal-security-claims.json"

printf '\n[8/11] Checking formal security blueprint DAG\n'
run_formal_core check-blueprint "$ROOT/config/formal-security-blueprint.json" --claims "$ROOT/config/formal-security-claims.json"

printf '\n[9/11] Verifying independent bridge vectors\n'
run_formal_core verify-bridge-vectors "$ROOT/testdata/formal_core_vectors/bridge_messages.json"

printf '\n[10/11] Verifying native backend reference vectors\n'
cargo run --quiet -p native-backend-ref -- verify-vectors "$ROOT/testdata/native_backend_vectors"

printf '\n[11/11] Optional model checker pass\n'
if [ "${HEGEMON_FORMAL_RUN_MODEL_CHECKERS:-0}" = "1" ]; then
  if command -v tlc >/dev/null 2>&1; then
    (
      cd "$ROOT/circuits/formal"
      tlc -deadlock transaction_balance.tla -config transaction_balance.cfg
    )
    (
      cd "$ROOT/consensus/spec/formal"
      tlc -deadlock pow_longest_chain.tla -config pow_longest_chain.cfg
    )
  else
    printf 'tlc not found; skipping TLC because no pinned local binary is available\n'
  fi

  if command -v apalache-mc >/dev/null 2>&1; then
    (
      cd "$ROOT/circuits/formal"
      apalache-mc check --max-steps=20 --inv=BalanceInvariant transaction_balance.tla
    )
    (
      cd "$ROOT/consensus/spec/formal"
      apalache-mc check --max-steps=20 --inv=ForkChoiceInvariant pow_longest_chain.tla
    )
  else
    printf 'apalache-mc not found; skipping Apalache because no pinned local binary is available\n'
  fi
else
  printf 'set HEGEMON_FORMAL_RUN_MODEL_CHECKERS=1 to run installed TLC/Apalache binaries\n'
fi

printf '\n=== Hegemon formal-core gate passed ===\n'
