#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod bridge;
pub mod manifest;
pub mod router;
pub mod traits;
pub mod types;

pub use bridge::{
    bridge_message_root, bridge_payload_hash, empty_bridge_message_root, inbound_replay_key,
    BridgeMessageV1, BridgeVerifierRegistrationV1, ChainId, InboundBridgeArgsV1, MessageHash,
    MessageRoot, OutboundBridgeArgsV1, ACTION_BRIDGE_INBOUND, ACTION_BRIDGE_OUTBOUND,
    ACTION_REGISTER_BRIDGE_VERIFIER, FAMILY_BRIDGE,
};
pub use manifest::{FamilySpec, KernelManifest};
pub use router::FamilyRouter;
pub use traits::{
    ActionSourceClass, ApplyOutcome, KernelError, KernelFamily, KernelStateView, KernelStateWrite,
    ManifestProvider, ValidActionMeta,
};
pub use types::{
    compute_kernel_global_root, ActionEnvelope, ActionId, AuthorizationBundle, Commitment,
    FamilyId, FamilyRoot, GlobalRoot, Nullifier, ObjectId, ObjectRef, SignatureEnvelope,
    StatementHash,
};
