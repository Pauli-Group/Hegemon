use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::types::{ActionId, FamilyId};

pub const FAMILY_BRIDGE: FamilyId = 5;

pub const ACTION_BRIDGE_OUTBOUND: ActionId = 1;
pub const ACTION_BRIDGE_INBOUND: ActionId = 2;
pub const ACTION_REGISTER_BRIDGE_VERIFIER: ActionId = 3;

pub type ChainId = [u8; 32];
pub type MessageRoot = [u8; 48];
pub type MessageHash = [u8; 48];

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct BridgeMessageV1 {
    pub source_chain_id: ChainId,
    pub destination_chain_id: ChainId,
    pub app_family_id: FamilyId,
    pub message_nonce: u128,
    pub source_height: u64,
    pub payload_hash: MessageHash,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct OutboundBridgeArgsV1 {
    pub destination_chain_id: ChainId,
    pub app_family_id: FamilyId,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct InboundBridgeArgsV1 {
    pub source_chain_id: ChainId,
    pub source_message_nonce: u128,
    pub verifier_program_hash: [u8; 32],
    pub proof_receipt: Vec<u8>,
    pub message: BridgeMessageV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct BridgeVerifierRegistrationV1 {
    pub source_chain_id: ChainId,
    pub verifier_program_hash: [u8; 32],
    pub rules_hash: [u8; 32],
    pub enabled_at_height: u64,
}

impl DecodeWithMemTracking for BridgeMessageV1 {}
impl DecodeWithMemTracking for OutboundBridgeArgsV1 {}
impl DecodeWithMemTracking for InboundBridgeArgsV1 {}
impl DecodeWithMemTracking for BridgeVerifierRegistrationV1 {}

impl BridgeMessageV1 {
    pub fn message_hash(&self) -> MessageHash {
        let encoded = self.encode();
        hash48_with_domain(b"hegemon.bridge.message-v1", &[&encoded])
    }
}

pub fn bridge_payload_hash(payload: &[u8]) -> MessageHash {
    hash48_with_domain(b"hegemon.bridge.payload-v1", &[payload])
}

pub fn empty_bridge_message_root() -> MessageRoot {
    bridge_message_root(&[])
}

pub fn bridge_message_root(messages: &[BridgeMessageV1]) -> MessageRoot {
    let mut chunks = Vec::with_capacity(messages.len() + 1);
    let count = (messages.len() as u32).to_le_bytes();
    chunks.push(count.as_slice());
    let hashes = messages
        .iter()
        .map(BridgeMessageV1::message_hash)
        .collect::<Vec<_>>();
    for hash in &hashes {
        chunks.push(hash.as_slice());
    }
    hash48_with_domain(b"hegemon.bridge.message-root-v1", &chunks)
}

pub fn inbound_replay_key(source_chain_id: ChainId, source_message_nonce: u128) -> MessageHash {
    hash48_with_domain(
        b"hegemon.bridge.inbound-replay-v1",
        &[&source_chain_id, &source_message_nonce.to_le_bytes()],
    )
}

fn hash48_with_domain(domain: &[u8], chunks: &[&[u8]]) -> MessageHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for chunk in chunks {
        hasher.update(&(chunk.len() as u32).to_le_bytes());
        hasher.update(chunk);
    }
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(nonce: u128) -> BridgeMessageV1 {
        let payload = vec![nonce as u8, 7, 9];
        BridgeMessageV1 {
            source_chain_id: [1u8; 32],
            destination_chain_id: [2u8; 32],
            app_family_id: 42,
            message_nonce: nonce,
            source_height: 11,
            payload_hash: bridge_payload_hash(&payload),
            payload,
        }
    }

    #[test]
    fn bridge_message_root_is_ordered() {
        let a = message(1);
        let b = message(2);
        assert_ne!(
            bridge_message_root(&[a.clone(), b.clone()]),
            bridge_message_root(&[b, a])
        );
    }

    #[test]
    fn inbound_replay_key_binds_chain_and_nonce() {
        assert_ne!(
            inbound_replay_key([1u8; 32], 7),
            inbound_replay_key([2u8; 32], 7)
        );
        assert_ne!(
            inbound_replay_key([1u8; 32], 7),
            inbound_replay_key([1u8; 32], 8)
        );
    }
}
