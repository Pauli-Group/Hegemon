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
  lake build Hegemon gen_bridge_vectors gen_shielded_vectors gen_consensus_vectors gen_pow_vectors gen_proof_policy_vectors gen_supply_vectors gen_action_order_vectors gen_native_tx_leaf_artifact_vectors gen_native_receipt_root_vectors gen_transaction_vectors gen_merkle_vectors gen_public_input_vectors gen_public_input_binding_vectors gen_statement_hash_vectors
  lake env lean Hegemon/Bytes.lean
  lake env lean Hegemon/Bridge/Encoding.lean
  lake env lean Hegemon/Bridge/MessageRoot.lean
  lake env lean Hegemon/Bridge/Replay.lean
  lake env lean Hegemon/Bridge/GenerateVectors.lean
  lake env lean Hegemon/Consensus/ForkChoice.lean
  lake env lean Hegemon/Consensus/GenerateVectors.lean
  lake env lean Hegemon/Consensus/PowRules.lean
  lake env lean Hegemon/Consensus/GeneratePowVectors.lean
  lake env lean Hegemon/Consensus/ProofPolicy.lean
  lake env lean Hegemon/Consensus/GenerateProofPolicyVectors.lean
  lake env lean Hegemon/Consensus/Supply.lean
  lake env lean Hegemon/Consensus/GenerateSupplyVectors.lean
  lake env lean Hegemon/Native/ActionOrder.lean
  lake env lean Hegemon/Native/GenerateActionOrderVectors.lean
  lake env lean Hegemon/Native/TxLeafArtifact.lean
  lake env lean Hegemon/Native/GenerateTxLeafArtifactVectors.lean
  lake env lean Hegemon/Native/ReceiptRoot.lean
  lake env lean Hegemon/Native/GenerateReceiptRootVectors.lean
  lake env lean Hegemon/Shielded/Nullifier.lean
  lake env lean Hegemon/Shielded/GenerateVectors.lean
  lake env lean Hegemon/Transaction/Balance.lean
  lake env lean Hegemon/Transaction/GenerateVectors.lean
  lake env lean Hegemon/Transaction/MerklePath.lean
  lake env lean Hegemon/Transaction/GenerateMerkleVectors.lean
  lake env lean Hegemon/Transaction/PublicInputs.lean
  lake env lean Hegemon/Transaction/GeneratePublicInputVectors.lean
  lake env lean Hegemon/Transaction/PublicInputBinding.lean
  lake env lean Hegemon/Transaction/GeneratePublicInputBindingVectors.lean
  lake env lean Hegemon/Transaction/StatementHash.lean
  lake env lean Hegemon/Transaction/GenerateStatementHashVectors.lean
)
