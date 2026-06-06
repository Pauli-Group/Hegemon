#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEAN_ROOT="$ROOT/formal/lean"

if [ -d "${HOME:-}/.elan/bin" ]; then
  export PATH="${HOME}/.elan/bin:$PATH"
fi

if ! command -v lake >/dev/null 2>&1; then
  printf 'lake is not installed. Install Lean tooling with:\n' >&2
  printf '  curl https://elan.lean-lang.org/elan-init.sh -sSf | sh -s -- -y --default-toolchain none\n' >&2
  exit 2
fi

if find "$LEAN_ROOT" -name '*.lean' -print0 \
  | xargs -0 grep -nE '\b(sorry|admit)\b|^[[:space:]]*axiom[[:space:]]' >/tmp/hegemon-lean-forbidden.$$ 2>/dev/null; then
  printf 'Lean formal sources contain forbidden proof placeholders or declared axioms:\n' >&2
  cat /tmp/hegemon-lean-forbidden.$$ >&2
  rm -f /tmp/hegemon-lean-forbidden.$$
  exit 1
fi
rm -f /tmp/hegemon-lean-forbidden.$$

(
  cd "$LEAN_ROOT"
  lake build Hegemon
  lake env lean Hegemon/Bridge/Replay.lean
)
