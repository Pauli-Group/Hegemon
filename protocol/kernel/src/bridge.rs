use alloc::{collections::BTreeSet, vec::Vec};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundReplayReject {
    AlreadyConsumed,
    AlreadyPending,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InboundReplayState {
    consumed: BTreeSet<MessageHash>,
    pending: BTreeSet<MessageHash>,
}

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

impl InboundReplayState {
    pub fn new(consumed: BTreeSet<MessageHash>, pending: BTreeSet<MessageHash>) -> Self {
        Self { consumed, pending }
    }

    pub fn consumed(&self) -> &BTreeSet<MessageHash> {
        &self.consumed
    }

    pub fn pending(&self) -> &BTreeSet<MessageHash> {
        &self.pending
    }

    pub fn can_stage(&self, key: &MessageHash) -> Result<(), InboundReplayReject> {
        if self.consumed.contains(key) {
            return Err(InboundReplayReject::AlreadyConsumed);
        }
        if self.pending.contains(key) {
            return Err(InboundReplayReject::AlreadyPending);
        }
        Ok(())
    }

    pub fn stage(&mut self, key: MessageHash) -> Result<(), InboundReplayReject> {
        self.can_stage(&key)?;
        self.pending.insert(key);
        Ok(())
    }

    pub fn import_one(&mut self, key: MessageHash) -> Result<(), InboundReplayReject> {
        if self.consumed.contains(&key) {
            return Err(InboundReplayReject::AlreadyConsumed);
        }
        self.pending.remove(&key);
        self.consumed.insert(key);
        Ok(())
    }
}

impl BridgeMessageV1 {
    pub fn message_hash(&self) -> MessageHash {
        let encoded = bridge_message_encoded_v1(self);
        hash48_with_domain(b"hegemon.bridge.message-v1", &[&encoded])
    }
}

pub fn bridge_message_encoded_v1(message: &BridgeMessageV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(170 + message.payload.len());
    encoded.extend_from_slice(&message.source_chain_id);
    encoded.extend_from_slice(&message.destination_chain_id);
    encoded.extend_from_slice(&message.app_family_id.to_le_bytes());
    encoded.extend_from_slice(&message.message_nonce.to_le_bytes());
    encoded.extend_from_slice(&message.source_height.to_le_bytes());
    encoded.extend_from_slice(&message.payload_hash);
    push_scale_compact_len(&mut encoded, message.payload.len() as u64);
    encoded.extend_from_slice(&message.payload);
    encoded
}

pub fn bridge_payload_hash(payload: &[u8]) -> MessageHash {
    hash48_with_domain(b"hegemon.bridge.payload-v1", &[payload])
}

pub fn empty_bridge_message_root() -> MessageRoot {
    bridge_message_root(&[])
}

pub fn bridge_message_root(messages: &[BridgeMessageV1]) -> MessageRoot {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.bridge.message-root-v1");
    let count = (messages.len() as u32).to_le_bytes();
    hasher.update(&(count.len() as u32).to_le_bytes());
    hasher.update(&count);
    for message in messages {
        let hash = message.message_hash();
        hasher.update(&(hash.len() as u32).to_le_bytes());
        hasher.update(&hash);
    }
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
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

fn push_scale_compact_len(out: &mut Vec<u8>, value: u64) {
    if value < 1 << 6 {
        out.push((value as u8) << 2);
    } else if value < 1 << 14 {
        let encoded = ((value as u16) << 2) | 0b01;
        out.extend_from_slice(&encoded.to_le_bytes());
    } else if value < 1 << 30 {
        let encoded = ((value as u32) << 2) | 0b10;
        out.extend_from_slice(&encoded.to_le_bytes());
    } else {
        let value_bytes = value.to_le_bytes();
        let mut used = value_bytes.len();
        while used > 4 && value_bytes[used - 1] == 0 {
            used -= 1;
        }
        out.push((((used - 4) as u8) << 2) | 0b11);
        out.extend_from_slice(&value_bytes[..used]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::BTreeSet;

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
    fn bridge_message_manual_encoding_matches_scale() {
        let message = message(7);
        assert_eq!(bridge_message_encoded_v1(&message), message.encode());
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

    #[test]
    fn inbound_replay_state_blocks_pending_and_consumed_duplicates() {
        let key = [7u8; 48];
        let mut state = InboundReplayState::default();
        assert_eq!(state.stage(key), Ok(()));
        assert_eq!(state.stage(key), Err(InboundReplayReject::AlreadyPending));
        assert_eq!(state.import_one(key), Ok(()));
        assert_eq!(state.stage(key), Err(InboundReplayReject::AlreadyConsumed));
        assert_eq!(
            state.import_one(key),
            Err(InboundReplayReject::AlreadyConsumed)
        );
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeVectorFile {
        schema_version: u32,
        bridge_encoding_cases: Vec<LeanBridgeEncodingCase>,
        replay_cases: Vec<LeanReplayCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeEncodingCase {
        name: String,
        source_chain_id: String,
        destination_chain_id: String,
        app_family_id: u16,
        message_nonce: String,
        source_height: u64,
        payload_hash: String,
        payload_hex: String,
        expected_encoded_hex: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanReplayCase {
        name: String,
        initial_consumed: Vec<String>,
        initial_pending: Vec<String>,
        key: String,
        stage: bool,
        stage_then_import: bool,
        stage_after_import: bool,
        import: bool,
    }

    #[test]
    fn lean_generated_bridge_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_VECTORS") else {
            eprintln!("HEGEMON_LEAN_BRIDGE_VECTORS not set; skipping generated Lean vector check");
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean bridge vectors");
        let vectors: LeanBridgeVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean bridge vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.bridge_encoding_cases.is_empty(),
            "Lean bridge encoding cases must not be empty"
        );
        assert!(
            !vectors.replay_cases.is_empty(),
            "Lean replay cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.bridge_encoding_cases {
            assert!(names.insert(format!("encoding:{}", case.name)));
            verify_lean_bridge_encoding_case(case);
        }
        for case in &vectors.replay_cases {
            assert!(names.insert(format!("replay:{}", case.name)));
            verify_lean_replay_case(case);
        }
    }

    fn verify_lean_bridge_encoding_case(case: &LeanBridgeEncodingCase) {
        let message_nonce = case
            .message_nonce
            .parse::<u128>()
            .expect("parse Lean message nonce");
        let message = BridgeMessageV1 {
            source_chain_id: parse_hash32(&case.source_chain_id),
            destination_chain_id: parse_hash32(&case.destination_chain_id),
            app_family_id: case.app_family_id,
            message_nonce,
            source_height: case.source_height,
            payload_hash: parse_hash48(&case.payload_hash),
            payload: parse_hex_vec(&case.payload_hex),
        };
        let encoded = bridge_message_encoded_v1(&message);
        let expected_encoded = parse_hex_vec(&case.expected_encoded_hex);
        assert_eq!(
            encoded, expected_encoded,
            "{} production bridge encoding drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_replay_case(case: &LeanReplayCase) {
        let state = InboundReplayState::new(
            parse_replay_key_set(&case.initial_consumed),
            parse_replay_key_set(&case.initial_pending),
        );
        let key = parse_hash48(&case.key);

        let mut stage_state = state.clone();
        assert_eq!(
            stage_state.stage(key).is_ok(),
            case.stage,
            "{} stage result drifted from Lean spec",
            case.name
        );

        let mut stage_then_import_state = state.clone();
        let stage_then_import = if stage_then_import_state.stage(key).is_ok() {
            stage_then_import_state.import_one(key).is_ok()
        } else {
            false
        };
        assert_eq!(
            stage_then_import, case.stage_then_import,
            "{} stage_then_import result drifted from Lean spec",
            case.name
        );

        let mut stage_after_import_state = state.clone();
        let stage_after_import = if stage_after_import_state.import_one(key).is_ok() {
            stage_after_import_state.stage(key).is_ok()
        } else {
            false
        };
        assert_eq!(
            stage_after_import, case.stage_after_import,
            "{} stage_after_import result drifted from Lean spec",
            case.name
        );

        let mut import_state = state;
        assert_eq!(
            import_state.import_one(key).is_ok(),
            case.import,
            "{} import result drifted from Lean spec",
            case.name
        );
    }

    fn parse_replay_key_set(values: &[String]) -> BTreeSet<MessageHash> {
        let mut out = BTreeSet::new();
        for value in values {
            assert!(
                out.insert(parse_hash48(value)),
                "duplicate replay key {value}"
            );
        }
        out
    }

    fn parse_hash32(value: &str) -> ChainId {
        let bytes = parse_hex_vec(value);
        assert_eq!(bytes.len(), 32, "expected 32-byte hash");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn parse_hash48(value: &str) -> MessageHash {
        let bytes = parse_hex_vec(value);
        assert_eq!(bytes.len(), 48, "expected 48-byte hash");
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        out
    }

    fn parse_hex_vec(value: &str) -> Vec<u8> {
        let stripped = value.strip_prefix("0x").unwrap_or(value);
        hex::decode(stripped).expect("decode hex")
    }
}
