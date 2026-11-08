#!/usr/bin/env bash
# Independent ASERT arithmetic/schedule model and finite Rust conformance.
# No general Rust refinement, liveness proof, or release authority is asserted.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
if [[ "$MODE" != "" && "$MODE" != "--lean-only" ]]; then
  echo "usage: scripts/check_asert_formal.sh [--lean-only]" >&2
  exit 2
fi
if [[ -d "${HOME:-}/.elan/bin" ]]; then
  export PATH="${HOME}/.elan/bin:$PATH"
fi
OUTPUT="${HEGEMON_ASERT_FORMAL_OUTPUT:-$(mktemp -d "${TMPDIR:-/tmp}/hegemon-asert-formal.XXXXXX")}"
mkdir -p "$OUTPUT/Hegemon/Consensus"
OUTPUT="$(cd "$OUTPUT" && pwd)"
(
  cd "$ROOT/formal/asert"
  lean -o "$OUTPUT/Hegemon/Consensus/Asert.olean" Hegemon/Consensus/Asert.lean
  LEAN_PATH="$OUTPUT" lean --run Hegemon/Consensus/GenerateAsertVectors.lean > "$OUTPUT/asert-v1.json"
  cmp fixtures/asert-v1.json "$OUTPUT/asert-v1.json"
  LEAN_PATH="$OUTPUT" lean --run "$ROOT/scripts/lean_axiom_audit.lean" \
    Hegemon/Consensus/Asert.roots Hegemon.Consensus.Asert > "$OUTPUT/axioms.json"
)
python3 - "$OUTPUT/axioms.json" <<'PY'
import json,sys
rows=json.load(open(sys.argv[1]))
allowed={"propext","Quot.sound","Classical.choice"}
assert len(rows)==14, len(rows)
for row in rows:
    assert set(row['axioms']) <= allowed, row
print(f"ASERT Lean model checked; {len(rows)} roots use only standard Lean axioms.")
PY
if [[ "$MODE" != "--lean-only" ]]; then
  cd "$ROOT"
  HEGEMON_ASERT_FORMAL_VECTORS="$OUTPUT/asert-v1.json" \
    cargo test --locked -p consensus-light-client --test asert_formal
fi
printf 'ASERT formal evidence: %s\n' "$OUTPUT"
