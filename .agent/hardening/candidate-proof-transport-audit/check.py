#!/usr/bin/env python3
"""Source-topology checks for the fail-closed candidate proof transport.

This is deliberately not an integration or cryptographic test.  It pins the
current byte-carrying seams and the absence of candidate production authority
without compiling the 18-GiB checkout.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise AssertionError(f"missing {label}: {needle!r}")


def between(text: str, start: str, end: str) -> str:
    start_at = text.index(start)
    end_at = text.index(end, start_at)
    return text[start_at:end_at]


versioning = source("protocol/versioning/src/lib.rs")
backend_dispatch = between(
    versioning,
    "pub const fn tx_proof_backend_for_version",
    "pub const fn tx_fri_profile_for_version",
)
require(
    versioning,
    "SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING",
    "reserved V5 identity",
)
require(
    versioning,
    "SMALLWOOD_V6_SHAKE448_VERSION_BINDING",
    "reserved V6 identity",
)
assert "CIRCUIT_V5" not in backend_dispatch
assert "CIRCUIT_V6" not in backend_dispatch

manifest = source("protocol/kernel/src/manifest.rs")
require(
    manifest,
    "let version_bindings = vec![DEFAULT_VERSION_BINDING];",
    "single active version binding",
)
assert "ACTION_SMALLWOOD_V5_CONVENTIONAL_HASH_INLINE" not in manifest
assert "V6_ACTION_ID" not in manifest

v5 = source("circuits/transaction/src/smallwood_v5_envelope.rs")
require(v5, "proof_system_implemented: false", "V5 proof-system lock")
require(v5, "verified_max_proof_bytes: 0", "V5 measured proof bound")
require(
    v5,
    "if sources.sidecar_proof.is_some()",
    "V5 sidecar-substitution rejection",
)
require(
    v5,
    "if sources.cached_acceptance.is_some()",
    "V5 cache-substitution rejection",
)

v6 = source("circuits/transaction/src/smallwood_v6_envelope.rs")
require(v6, "version_mapping_enabled: false", "V6 version lock")
require(v6, "kernel_route_enabled: false", "V6 route lock")
require(v6, "verified_max_proof_bytes: 0", "V6 measured proof bound")
require(
    v6,
    "if sources.sidecar_proof.is_some()",
    "V6 sidecar-substitution rejection",
)
require(
    v6,
    "if sources.cached_acceptance.is_some()",
    "V6 cache-substitution rejection",
)

family = source("protocol/shielded-pool/src/family.rs")
wallet_rpc = source("wallet/src/node_rpc.rs")
native_mod = source("node/src/native/mod.rs")
native_impl = source("node/src/native/node_impl.rs")
native_service = source("node/src/native/service.rs")
native_storage = source("node/src/native/storage.rs")
native_flow = source("node/src/native/block_flow.rs")

require(family, "pub proof: Vec<u8>", "opaque inline proof vector")
require(
    wallet_rpc,
    "proof: bundle.proof_bytes.clone()",
    "wallet-to-RPC byte copy",
)
require(native_mod, "public_args: Vec<u8>", "opaque pending action payload")
require(native_impl, "let action_bytes = action.encode();", "relay action encoding")
require(
    native_impl,
    "NativeSyncMessage::PendingAction {\n            action: action_bytes,",
    "relay payload ownership",
)
require(
    native_service,
    'decode_pending_action_v3_exact(action, "native pending action relay")',
    "exact relay decoding",
)
require(
    native_storage,
    'decode_pending_action_v3_exact(&value, "persisted pending action")',
    "exact durable-mempool decoding",
)
require(
    native_storage,
    "if action.encode().as_slice() != value.as_ref()",
    "durable canonical-byte readback",
)
require(
    native_impl,
    "action_bytes: actions.iter().map(Encode::encode).collect(),",
    "mined block action-byte carry",
)
require(
    native_flow,
    'decode_pending_action_v3_exact(raw, "native V3 block action")',
    "exact block/sync action decoding",
)
require(native_flow, "if action.encode() != *raw", "block canonical-byte readback")
require(native_flow, "Ok(args.proof)", "opaque proof extraction")

require(
    native_impl,
    "self.preflight_pending_transfer_proof_against_parent(",
    "ingress and template verifier preflight",
)
require(
    native_flow,
    "verify_block_with_backend(",
    "block verifier invocation",
)
require(
    native_impl,
    "node.sanitize_persisted_pending_smallwood_actions()?;",
    "fresh-process pending proof verification",
)
require(
    native_impl,
    "self.replay_stored_block_into_state(&mut state, meta.clone(), expected_pow_bits)?;",
    "reorg/startup block replay",
)
require(
    native_impl,
    "Every restart and every reorg replay re-verifies",
    "non-authoritative cache contract",
)

active_route = between(
    source("node/src/native/admission.rs"),
    "pub(crate) fn ensure_native_v3_active_action_route_ids",
    "pub(crate) fn is_coinbase_action",
)
require(
    active_route,
    "ACTION_SHIELDED_TRANSFER_SIDECAR",
    "explicit sidecar route handling",
)
require(
    active_route,
    "shielded sidecar transfer route is decode-compatible but inactive",
    "inactive sidecar authority",
)

print("candidate transport source audit: 35 checks passed")
print("authority: V5/V6 inactive; compiled verified proof bound = 0")
print("evidence class: source topology only (not lifecycle integration)")
