#!/bin/bash
set -euo pipefail

# Deprecated: recursive *block* proofs are no longer the default validity path.
# This wrapper keeps the historical entrypoint working.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT_DIR/scripts/commitment_proof_da_e2e_tmux.sh" "$@"
