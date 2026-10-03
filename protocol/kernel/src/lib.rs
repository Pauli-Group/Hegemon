#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod bridge;
pub mod manifest;
pub mod router;
pub mod stablecoin_manifest_authority_v2;
pub mod stablecoin_manifest_commitment_v1;
pub mod stablecoin_source_v3;
pub mod stablecoin_transition_v3;
pub mod traits;
pub mod types;

pub use bridge::{
    bridge_message_root, bridge_message_root_v2, bridge_message_root_v2_from_hashes,
    bridge_message_wire_era, bridge_mint_payload_wire_era, bridge_payload_hash,
    bridge_payload_hash_v2, bridge_verifier_registration_wire_era, empty_bridge_message_root,
    empty_bridge_message_root_v2, inbound_bridge_args_wire_era, inbound_replay_key,
    inbound_replay_key_v2, outbound_bridge_args_wire_era, BridgeMessageV1, BridgeMessageV2,
    BridgeMintPayloadV1, BridgeMintPayloadV2, BridgeSchemaV2, BridgeVerifierRegistrationV1,
    BridgeVerifierRegistrationV2, BridgeWireEra, ChainId, InboundBridgeArgsV1, InboundBridgeArgsV2,
    InboundReplayReject, InboundReplayState, InboundReplayStateV2, MessageHash, MessageRoot,
    OutboundBridgeArgsV1, OutboundBridgeArgsV2, ACTION_BRIDGE_INBOUND, ACTION_BRIDGE_INBOUND_V2,
    ACTION_BRIDGE_OUTBOUND, ACTION_BRIDGE_OUTBOUND_V2, ACTION_REGISTER_BRIDGE_VERIFIER,
    ACTION_REGISTER_BRIDGE_VERIFIER_V2, BRIDGE_MINT_APP_FAMILY_ID_V1,
    BRIDGE_MINT_PAYLOAD_VERSION_V1, BRIDGE_WIRE_MAGIC_V2, BRIDGE_WIRE_VERSION_V2, FAMILY_BRIDGE,
    MAX_BRIDGE_MESSAGE_PAYLOAD_BYTES_V2, MAX_BRIDGE_PROOF_RECEIPT_BYTES_V2,
};
pub use manifest::{FamilySpec, KernelManifest};
pub use router::FamilyRouter;
pub use traits::{
    ActionSourceClass, ApplyOutcome, KernelError, KernelFamily, KernelStateView, KernelStateWrite,
    ManifestProvider, ValidActionMeta,
};
pub use types::{
    compute_kernel_global_root, compute_native_action_root_v1, ActionEnvelope, ActionId,
    AuthorizationBundle, Commitment, FamilyId, FamilyRoot, GlobalRoot, NativeActionId48,
    NativeActionRoot32, Nullifier, ObjectId, ObjectRef, SignatureEnvelope, StatementHash,
};
