use alloc::{vec, vec::Vec};
use codec::{Decode, DecodeWithMemTracking, Encode, Input, MaxEncodedLen, Output};
use hegemon_hash384::{
    blake2b_384_domain_hash, domains, Blake2b384DomainHasher, BridgeMessageHash48,
    BridgeMessageRoot48, BridgePayloadHash48, BridgeReplayKey48, RulesHash48,
};
use protocol_shielded_pool::PersistentKeySet48;
use scale_info::TypeInfo;

use crate::types::{ActionId, FamilyId};

pub const FAMILY_BRIDGE: FamilyId = 5;
pub const BRIDGE_MINT_APP_FAMILY_ID_V1: FamilyId = FAMILY_BRIDGE;

pub const ACTION_BRIDGE_OUTBOUND: ActionId = 1;
pub const ACTION_BRIDGE_INBOUND: ActionId = 2;
pub const ACTION_REGISTER_BRIDGE_VERIFIER: ActionId = 3;
pub const BRIDGE_MINT_PAYLOAD_VERSION_V1: u16 = 1;

pub const ACTION_BRIDGE_OUTBOUND_V2: ActionId = 0x0201;
pub const ACTION_BRIDGE_INBOUND_V2: ActionId = 0x0202;
pub const ACTION_REGISTER_BRIDGE_VERIFIER_V2: ActionId = 0x0203;
pub const BRIDGE_WIRE_MAGIC_V2: [u8; 8] = *b"HEGBRGV2";
pub const BRIDGE_WIRE_VERSION_V2: u16 = 2;
pub const MAX_BRIDGE_MESSAGE_PAYLOAD_BYTES_V2: usize = 65_536;
pub const MAX_BRIDGE_PROOF_RECEIPT_BYTES_V2: usize = 512 * 1024;

pub type ChainId = [u8; 32];
pub type MessageRoot = [u8; 48];
pub type MessageHash = [u8; 48];

/// A zero-sized canonical marker whose SCALE wire is exactly
/// `HEGBRGV2 || u16le(2)`. Decode rejects any other marker before a dynamic
/// bridge field is read or allocated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, TypeInfo)]
pub struct BridgeSchemaV2;

impl Encode for BridgeSchemaV2 {
    fn size_hint(&self) -> usize {
        BRIDGE_WIRE_MAGIC_V2.len() + 2
    }

    fn encode_to<T: Output + ?Sized>(&self, destination: &mut T) {
        destination.write(&BRIDGE_WIRE_MAGIC_V2);
        BRIDGE_WIRE_VERSION_V2.encode_to(destination);
    }
}

impl Decode for BridgeSchemaV2 {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let magic = <[u8; 8]>::decode(input)?;
        let version = u16::decode(input)?;
        if magic != BRIDGE_WIRE_MAGIC_V2 || version != BRIDGE_WIRE_VERSION_V2 {
            return Err("legacy or invalid bridge schema marker".into());
        }
        Ok(Self)
    }
}

impl DecodeWithMemTracking for BridgeSchemaV2 {}

#[derive(Clone, Debug, PartialEq, Eq, Encode, TypeInfo)]
pub struct BridgeMessageV2 {
    pub schema: BridgeSchemaV2,
    pub rules_hash: RulesHash48,
    pub source_chain_id: ChainId,
    pub destination_chain_id: ChainId,
    pub app_family_id: FamilyId,
    pub message_nonce: u128,
    pub source_height: u64,
    pub payload_hash: BridgePayloadHash48,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, TypeInfo)]
pub struct OutboundBridgeArgsV2 {
    pub schema: BridgeSchemaV2,
    pub rules_hash: RulesHash48,
    pub destination_chain_id: ChainId,
    pub app_family_id: FamilyId,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, TypeInfo)]
pub struct InboundBridgeArgsV2 {
    pub schema: BridgeSchemaV2,
    pub rules_hash: RulesHash48,
    pub source_chain_id: ChainId,
    pub source_message_nonce: u128,
    pub verifier_program_hash: [u8; 32],
    pub proof_receipt: Vec<u8>,
    pub message: BridgeMessageV2,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, TypeInfo)]
pub struct BridgeMintPayloadV2 {
    pub schema: BridgeSchemaV2,
    pub rules_hash: RulesHash48,
    pub destination_chain_id: ChainId,
    pub recipient_commitment: [u8; 48],
    pub asset_id: u64,
    pub amount: u64,
    pub mint_nonce: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, TypeInfo)]
pub struct BridgeVerifierRegistrationV2 {
    pub schema: BridgeSchemaV2,
    pub source_chain_id: ChainId,
    pub verifier_program_hash: [u8; 32],
    pub rules_hash: RulesHash48,
    pub enabled_at_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundReplayReject {
    AlreadyConsumed,
    AlreadyPending,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InboundReplayState {
    consumed: PersistentKeySet48,
    pending: PersistentKeySet48,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InboundReplayStateV2 {
    consumed: PersistentKeySet48,
    pending: PersistentKeySet48,
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

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct BridgeMintPayloadV1 {
    pub version: u16,
    pub destination_chain_id: ChainId,
    pub recipient_commitment: MessageHash,
    pub asset_id: u64,
    pub amount: u64,
    pub mint_nonce: u128,
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
impl DecodeWithMemTracking for BridgeMintPayloadV1 {}
impl DecodeWithMemTracking for BridgeVerifierRegistrationV1 {}

impl Decode for BridgeMessageV2 {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let message = Self {
            schema: BridgeSchemaV2::decode(input)?,
            rules_hash: RulesHash48::decode(input)?,
            source_chain_id: <[u8; 32]>::decode(input)?,
            destination_chain_id: <[u8; 32]>::decode(input)?,
            app_family_id: FamilyId::decode(input)?,
            message_nonce: u128::decode(input)?,
            source_height: u64::decode(input)?,
            payload_hash: BridgePayloadHash48::decode(input)?,
            payload: decode_bounded_bytes(
                input,
                MAX_BRIDGE_MESSAGE_PAYLOAD_BYTES_V2,
                "bridge message payload",
            )?,
        };
        message.validate_payload_binding()?;
        Ok(message)
    }
}

impl Decode for OutboundBridgeArgsV2 {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        Ok(Self {
            schema: BridgeSchemaV2::decode(input)?,
            rules_hash: RulesHash48::decode(input)?,
            destination_chain_id: <[u8; 32]>::decode(input)?,
            app_family_id: FamilyId::decode(input)?,
            payload: decode_bounded_bytes(
                input,
                MAX_BRIDGE_MESSAGE_PAYLOAD_BYTES_V2,
                "outbound bridge payload",
            )?,
        })
    }
}

impl Decode for InboundBridgeArgsV2 {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let arguments = Self {
            schema: BridgeSchemaV2::decode(input)?,
            rules_hash: RulesHash48::decode(input)?,
            source_chain_id: <[u8; 32]>::decode(input)?,
            source_message_nonce: u128::decode(input)?,
            verifier_program_hash: <[u8; 32]>::decode(input)?,
            proof_receipt: decode_bounded_bytes(
                input,
                MAX_BRIDGE_PROOF_RECEIPT_BYTES_V2,
                "inbound bridge proof receipt",
            )?,
            message: BridgeMessageV2::decode(input)?,
        };
        arguments.validate_message_binding()?;
        Ok(arguments)
    }
}

impl Decode for BridgeMintPayloadV2 {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        Ok(Self {
            schema: BridgeSchemaV2::decode(input)?,
            rules_hash: RulesHash48::decode(input)?,
            destination_chain_id: <[u8; 32]>::decode(input)?,
            recipient_commitment: <[u8; 48]>::decode(input)?,
            asset_id: u64::decode(input)?,
            amount: u64::decode(input)?,
            mint_nonce: u128::decode(input)?,
        })
    }
}

impl Decode for BridgeVerifierRegistrationV2 {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        Ok(Self {
            schema: BridgeSchemaV2::decode(input)?,
            source_chain_id: <[u8; 32]>::decode(input)?,
            verifier_program_hash: <[u8; 32]>::decode(input)?,
            rules_hash: RulesHash48::decode(input)?,
            enabled_at_height: u64::decode(input)?,
        })
    }
}

impl DecodeWithMemTracking for BridgeMessageV2 {}
impl DecodeWithMemTracking for OutboundBridgeArgsV2 {}
impl DecodeWithMemTracking for InboundBridgeArgsV2 {}
impl DecodeWithMemTracking for BridgeMintPayloadV2 {}
impl DecodeWithMemTracking for BridgeVerifierRegistrationV2 {}

fn decode_bounded_bytes<I: Input>(
    input: &mut I,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>, codec::Error> {
    let length = decode_canonical_compact_u32(input)? as usize;
    if length > maximum {
        return Err(label.into());
    }
    let mut bytes = vec![0u8; length];
    input.read(&mut bytes)?;
    Ok(bytes)
}

fn decode_canonical_compact_u32<I: Input>(input: &mut I) -> Result<u32, codec::Error> {
    let first = input.read_byte()?;
    match first & 0b11 {
        0 => Ok((first >> 2) as u32),
        1 => {
            let second = input.read_byte()?;
            let value = u16::from_le_bytes([first, second]) as u32 >> 2;
            if value < 1 << 6 {
                return Err("noncanonical two-byte compact length".into());
            }
            Ok(value)
        }
        2 => {
            let mut encoded = [0u8; 4];
            encoded[0] = first;
            input.read(&mut encoded[1..])?;
            let value = u32::from_le_bytes(encoded) >> 2;
            if value < 1 << 14 {
                return Err("noncanonical four-byte compact length".into());
            }
            Ok(value)
        }
        _ => Err("bridge byte length exceeds the bounded u30 profile".into()),
    }
}

impl InboundReplayState {
    pub fn new(
        consumed: impl Into<PersistentKeySet48>,
        pending: impl Into<PersistentKeySet48>,
    ) -> Self {
        Self {
            consumed: consumed.into(),
            pending: pending.into(),
        }
    }

    pub fn consumed(&self) -> &PersistentKeySet48 {
        &self.consumed
    }

    pub fn pending(&self) -> &PersistentKeySet48 {
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

impl InboundReplayStateV2 {
    pub fn new(
        consumed: impl Into<PersistentKeySet48>,
        pending: impl Into<PersistentKeySet48>,
    ) -> Self {
        Self {
            consumed: consumed.into(),
            pending: pending.into(),
        }
    }

    pub fn consumed(&self) -> &PersistentKeySet48 {
        &self.consumed
    }

    pub fn pending(&self) -> &PersistentKeySet48 {
        &self.pending
    }

    pub fn can_stage(&self, key: &BridgeReplayKey48) -> Result<(), InboundReplayReject> {
        if self.consumed.contains(key.as_bytes()) {
            return Err(InboundReplayReject::AlreadyConsumed);
        }
        if self.pending.contains(key.as_bytes()) {
            return Err(InboundReplayReject::AlreadyPending);
        }
        Ok(())
    }

    pub fn stage(&mut self, key: BridgeReplayKey48) -> Result<(), InboundReplayReject> {
        self.can_stage(&key)?;
        self.pending.insert(key.into_bytes());
        Ok(())
    }

    pub fn import_one(&mut self, key: BridgeReplayKey48) -> Result<(), InboundReplayReject> {
        if self.consumed.contains(key.as_bytes()) {
            return Err(InboundReplayReject::AlreadyConsumed);
        }
        self.pending.remove(key.as_bytes());
        self.consumed.insert(key.into_bytes());
        Ok(())
    }
}

impl BridgeMessageV2 {
    pub fn validate_payload_binding(&self) -> Result<(), codec::Error> {
        if self.payload_hash != bridge_payload_hash_v2(&self.payload) {
            return Err("bridge V2 payload hash mismatch".into());
        }
        Ok(())
    }

    pub fn message_hash(&self) -> Result<BridgeMessageHash48, codec::Error> {
        self.validate_payload_binding()?;
        Ok(BridgeMessageHash48::new(blake2b_384_domain_hash(
            domains::BRIDGE_MESSAGE_V2,
            [self.encode().as_slice()],
        )))
    }
}

impl InboundBridgeArgsV2 {
    pub fn validate_message_binding(&self) -> Result<(), codec::Error> {
        if self.rules_hash != self.message.rules_hash {
            return Err("bridge V2 inbound/message rules hash mismatch".into());
        }
        if self.source_chain_id != self.message.source_chain_id {
            return Err("bridge V2 inbound/message source chain mismatch".into());
        }
        if self.source_message_nonce != self.message.message_nonce {
            return Err("bridge V2 inbound/message nonce mismatch".into());
        }
        Ok(())
    }
}

pub fn bridge_payload_hash_v2(payload: &[u8]) -> BridgePayloadHash48 {
    BridgePayloadHash48::new(blake2b_384_domain_hash(
        domains::BRIDGE_PAYLOAD_V2,
        [payload],
    ))
}

pub fn empty_bridge_message_root_v2() -> BridgeMessageRoot48 {
    bridge_message_root_v2_from_hashes(&[])
}

pub fn bridge_message_root_v2(
    messages: &[BridgeMessageV2],
) -> Result<BridgeMessageRoot48, codec::Error> {
    let count = u32::try_from(messages.len())
        .expect("bridge message count fits the canonical u32 wire")
        .to_le_bytes();
    let mut hasher = Blake2b384DomainHasher::new(domains::BRIDGE_MESSAGE_ROOT_V2);
    hasher.update_part(&count);
    for message in messages {
        let message_hash = message.message_hash()?;
        hasher.update_part(message_hash.as_bytes());
    }
    Ok(BridgeMessageRoot48::new(hasher.finalize()))
}

pub fn bridge_message_root_v2_from_hashes(
    message_hashes: &[BridgeMessageHash48],
) -> BridgeMessageRoot48 {
    let count = u32::try_from(message_hashes.len())
        .expect("bridge message count fits the canonical u32 wire")
        .to_le_bytes();
    let mut hasher = Blake2b384DomainHasher::new(domains::BRIDGE_MESSAGE_ROOT_V2);
    hasher.update_part(&count);
    for message_hash in message_hashes {
        hasher.update_part(message_hash.as_bytes());
    }
    BridgeMessageRoot48::new(hasher.finalize())
}

pub fn inbound_replay_key_v2(
    source_chain_id: ChainId,
    source_message_nonce: u128,
) -> BridgeReplayKey48 {
    let nonce = source_message_nonce.to_le_bytes();
    BridgeReplayKey48::new(blake2b_384_domain_hash(
        domains::BRIDGE_INBOUND_REPLAY_V2,
        [source_chain_id.as_slice(), nonce.as_slice()],
    ))
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
    let hashes = messages
        .iter()
        .map(BridgeMessageV1::message_hash)
        .collect::<Vec<_>>();
    bridge_message_root_from_hashes(&hashes)
}

pub fn bridge_message_root_from_hashes(message_hashes: &[MessageHash]) -> MessageRoot {
    let preimage = bridge_message_root_preimage_v1_from_hashes(message_hashes);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&preimage);
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

pub fn bridge_message_root_preimage_v1_from_hashes(message_hashes: &[MessageHash]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 8 + message_hashes.len().saturating_mul(52));
    out.extend_from_slice(b"hegemon.bridge.message-root-v1");
    let count = u32::try_from(message_hashes.len())
        .expect("bridge message count exceeds u32::MAX")
        .to_le_bytes();
    push_len_prefixed_bytes(&mut out, &count);
    for hash in message_hashes {
        push_len_prefixed_bytes(&mut out, hash);
    }
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

fn push_len_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeWireEra {
    V2,
    LegacyV1,
    Invalid,
}

pub fn bridge_message_wire_era(bytes: &[u8]) -> BridgeWireEra {
    classify_bridge_wire::<BridgeMessageV2>(bytes, legacy_bridge_message_v1_is_exact)
}

pub fn outbound_bridge_args_wire_era(bytes: &[u8]) -> BridgeWireEra {
    classify_bridge_wire::<OutboundBridgeArgsV2>(bytes, legacy_outbound_args_v1_is_exact)
}

pub fn inbound_bridge_args_wire_era(bytes: &[u8]) -> BridgeWireEra {
    classify_bridge_wire::<InboundBridgeArgsV2>(bytes, legacy_inbound_args_v1_is_exact)
}

pub fn bridge_mint_payload_wire_era(bytes: &[u8]) -> BridgeWireEra {
    classify_bridge_wire::<BridgeMintPayloadV2>(bytes, legacy_mint_payload_v1_is_exact)
}

pub fn bridge_verifier_registration_wire_era(bytes: &[u8]) -> BridgeWireEra {
    classify_bridge_wire::<BridgeVerifierRegistrationV2>(
        bytes,
        legacy_verifier_registration_v1_is_exact,
    )
}

fn classify_bridge_wire<T: Decode>(
    bytes: &[u8],
    legacy_is_exact: fn(&[u8]) -> bool,
) -> BridgeWireEra {
    if has_v2_magic_prefix(bytes) {
        let mut input = bytes;
        return match T::decode(&mut input) {
            Ok(_) if input.is_empty() => BridgeWireEra::V2,
            _ => BridgeWireEra::Invalid,
        };
    }
    if legacy_is_exact(bytes) {
        BridgeWireEra::LegacyV1
    } else {
        BridgeWireEra::Invalid
    }
}

fn has_v2_magic_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= BRIDGE_WIRE_MAGIC_V2.len() && bytes[..8] == BRIDGE_WIRE_MAGIC_V2
}

fn legacy_bridge_message_v1_is_exact(bytes: &[u8]) -> bool {
    legacy_bridge_message_v1_end(bytes, 0) == Some(bytes.len())
}

fn legacy_bridge_message_v1_end(bytes: &[u8], start: usize) -> Option<usize> {
    let payload_prefix = start.checked_add(138)?;
    let (payload_len, payload_start) = compact_u30_at(bytes, payload_prefix)?;
    if payload_len > MAX_BRIDGE_MESSAGE_PAYLOAD_BYTES_V2 {
        return None;
    }
    payload_start
        .checked_add(payload_len)
        .filter(|end| *end <= bytes.len())
}

fn legacy_outbound_args_v1_is_exact(bytes: &[u8]) -> bool {
    let Some((payload_len, payload_start)) = compact_u30_at(bytes, 34) else {
        return false;
    };
    payload_len <= MAX_BRIDGE_MESSAGE_PAYLOAD_BYTES_V2
        && payload_start.checked_add(payload_len) == Some(bytes.len())
}

fn legacy_inbound_args_v1_is_exact(bytes: &[u8]) -> bool {
    let Some((receipt_len, receipt_start)) = compact_u30_at(bytes, 80) else {
        return false;
    };
    if receipt_len > MAX_BRIDGE_PROOF_RECEIPT_BYTES_V2 {
        return false;
    }
    let Some(message_start) = receipt_start.checked_add(receipt_len) else {
        return false;
    };
    legacy_bridge_message_v1_end(bytes, message_start) == Some(bytes.len())
}

fn legacy_mint_payload_v1_is_exact(bytes: &[u8]) -> bool {
    bytes.len() == 114 && bytes[..2] == BRIDGE_MINT_PAYLOAD_VERSION_V1.to_le_bytes()
}

fn legacy_verifier_registration_v1_is_exact(bytes: &[u8]) -> bool {
    bytes.len() == 104
}

fn compact_u30_at(bytes: &[u8], offset: usize) -> Option<(usize, usize)> {
    let first = *bytes.get(offset)?;
    match first & 0b11 {
        0 => Some(((first >> 2) as usize, offset + 1)),
        1 => {
            let second = *bytes.get(offset + 1)?;
            let value = (u16::from_le_bytes([first, second]) >> 2) as usize;
            (value >= 1 << 6).then_some((value, offset + 2))
        }
        2 => {
            let encoded = [
                first,
                *bytes.get(offset + 1)?,
                *bytes.get(offset + 2)?,
                *bytes.get(offset + 3)?,
            ];
            let value = (u32::from_le_bytes(encoded) >> 2) as usize;
            (value >= 1 << 14).then_some((value, offset + 4))
        }
        _ => None,
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

    fn message_v2(nonce: u128) -> BridgeMessageV2 {
        let payload = vec![nonce as u8, 7, 9];
        BridgeMessageV2 {
            schema: BridgeSchemaV2,
            rules_hash: RulesHash48::new([0x33; 48]),
            source_chain_id: [1u8; 32],
            destination_chain_id: [2u8; 32],
            app_family_id: 42,
            message_nonce: nonce,
            source_height: 11,
            payload_hash: bridge_payload_hash_v2(&payload),
            payload,
        }
    }

    #[test]
    fn bridge_v2_kats_and_semantic_domains_are_fixed() {
        let message = message_v2(7);
        assert_eq!(message.encode().len(), 200);
        assert_eq!(
            hex::encode(message.payload_hash.as_bytes()),
            "04986a844383cf23ddacdb6aa1dffce0bc3d47692a4ca8fbd228aab0d9005a55a06d24d1b74fbc66fdcbfccf6c91c66f"
        );
        assert_eq!(
            hex::encode(message.message_hash().unwrap().as_bytes()),
            "69c8f2bac8be902909c47a0a203b6bd22905d1ba1eead62b67e1449e5c94ae8d90ff9ff8a376f6c49a84af8527c0fbad"
        );
        assert_eq!(
            hex::encode(
                bridge_message_root_v2(&[message.clone()])
                    .unwrap()
                    .as_bytes()
            ),
            "d3c5c40d9706d6fc904ade4228cd3a927f77cc2e75043ad967b5eb7d76931c6f0486a841b863dca1bdea9d7088b09d69"
        );
        assert_eq!(
            hex::encode(inbound_replay_key_v2([1u8; 32], 7).as_bytes()),
            "ef7f2ab69a5e0ecafe9c3a71fcf11157d546b807a4adbab1d70d42f3f2eed02fffd3f346bfcd329f6f00eb1438a5b509"
        );

        let mut changed_rules = message.clone();
        changed_rules.rules_hash = RulesHash48::new([0x34; 48]);
        assert_ne!(
            message.message_hash().unwrap(),
            changed_rules.message_hash().unwrap()
        );
        assert_ne!(
            bridge_payload_hash_v2(&message.payload).as_bytes(),
            message.message_hash().unwrap().as_bytes(),
            "payload and message domains must not alias"
        );
        assert_ne!(
            bridge_message_root_v2(&[message.clone()]).unwrap(),
            bridge_message_root_v2(&[changed_rules]).unwrap()
        );
    }

    #[test]
    fn bridge_v2_wire_deltas_and_legacy_classification_are_exact() {
        let v1_message = message(7);
        let v2_message = message_v2(7);
        assert_eq!(v2_message.encode().len(), v1_message.encode().len() + 58);

        let v1_outbound = OutboundBridgeArgsV1 {
            destination_chain_id: [2u8; 32],
            app_family_id: 42,
            payload: vec![1, 2, 3],
        };
        let v2_outbound = OutboundBridgeArgsV2 {
            schema: BridgeSchemaV2,
            rules_hash: RulesHash48::new([0x33; 48]),
            destination_chain_id: [2u8; 32],
            app_family_id: 42,
            payload: vec![1, 2, 3],
        };
        assert_eq!(v2_outbound.encode().len(), v1_outbound.encode().len() + 58);

        let v1_inbound = InboundBridgeArgsV1 {
            source_chain_id: [1u8; 32],
            source_message_nonce: 7,
            verifier_program_hash: [4u8; 32],
            proof_receipt: vec![5, 6],
            message: v1_message.clone(),
        };
        let v2_inbound = InboundBridgeArgsV2 {
            schema: BridgeSchemaV2,
            rules_hash: RulesHash48::new([0x33; 48]),
            source_chain_id: [1u8; 32],
            source_message_nonce: 7,
            verifier_program_hash: [4u8; 32],
            proof_receipt: vec![5, 6],
            message: v2_message.clone(),
        };
        assert_eq!(v2_inbound.encode().len(), v1_inbound.encode().len() + 116);

        let v1_mint = BridgeMintPayloadV1 {
            version: BRIDGE_MINT_PAYLOAD_VERSION_V1,
            destination_chain_id: [2u8; 32],
            recipient_commitment: [6u8; 48],
            asset_id: 8,
            amount: 9,
            mint_nonce: 10,
        };
        let v2_mint = BridgeMintPayloadV2 {
            schema: BridgeSchemaV2,
            rules_hash: RulesHash48::new([0x33; 48]),
            destination_chain_id: [2u8; 32],
            recipient_commitment: [6u8; 48],
            asset_id: 8,
            amount: 9,
            mint_nonce: 10,
        };
        assert_eq!(v2_mint.encode().len(), v1_mint.encode().len() + 56);

        let v1_registration = BridgeVerifierRegistrationV1 {
            source_chain_id: [1u8; 32],
            verifier_program_hash: [4u8; 32],
            rules_hash: [5u8; 32],
            enabled_at_height: 11,
        };
        let v2_registration = BridgeVerifierRegistrationV2 {
            schema: BridgeSchemaV2,
            source_chain_id: [1u8; 32],
            verifier_program_hash: [4u8; 32],
            rules_hash: RulesHash48::new([5u8; 48]),
            enabled_at_height: 11,
        };
        assert_eq!(
            v2_registration.encode().len(),
            v1_registration.encode().len() + 26
        );

        assert_eq!(
            bridge_message_wire_era(&v1_message.encode()),
            BridgeWireEra::LegacyV1
        );
        assert_eq!(
            bridge_message_wire_era(&v2_message.encode()),
            BridgeWireEra::V2
        );
        assert_eq!(
            outbound_bridge_args_wire_era(&v1_outbound.encode()),
            BridgeWireEra::LegacyV1
        );
        assert_eq!(
            outbound_bridge_args_wire_era(&v2_outbound.encode()),
            BridgeWireEra::V2
        );
        assert_eq!(
            inbound_bridge_args_wire_era(&v1_inbound.encode()),
            BridgeWireEra::LegacyV1
        );
        assert_eq!(
            inbound_bridge_args_wire_era(&v2_inbound.encode()),
            BridgeWireEra::V2
        );
        assert_eq!(
            bridge_mint_payload_wire_era(&v1_mint.encode()),
            BridgeWireEra::LegacyV1
        );
        assert_eq!(
            bridge_mint_payload_wire_era(&v2_mint.encode()),
            BridgeWireEra::V2
        );
        assert_eq!(
            bridge_verifier_registration_wire_era(&v1_registration.encode()),
            BridgeWireEra::LegacyV1
        );
        assert_eq!(
            bridge_verifier_registration_wire_era(&v2_registration.encode()),
            BridgeWireEra::V2
        );
    }

    #[test]
    fn bridge_v2_decode_rejects_marker_lengths_bindings_and_noncanonical_compact() {
        let message = message_v2(7);
        let mut wrong_marker = message.encode();
        wrong_marker[0] ^= 1;
        assert_eq!(
            bridge_message_wire_era(&wrong_marker),
            BridgeWireEra::Invalid
        );

        let mut noncanonical = message.encode();
        let payload_prefix = 196;
        assert_eq!(noncanonical[payload_prefix], 3 << 2);
        noncanonical.splice(
            payload_prefix..=payload_prefix,
            [((3u16 << 2) | 1) as u8, 0],
        );
        assert_eq!(
            bridge_message_wire_era(&noncanonical),
            BridgeWireEra::Invalid
        );

        let mut oversized = message.encode();
        let encoded_len = (((MAX_BRIDGE_MESSAGE_PAYLOAD_BYTES_V2 + 1) as u32) << 2) | 0b10;
        oversized.splice(payload_prefix..=payload_prefix, encoded_len.to_le_bytes());
        oversized.truncate(payload_prefix + 4);
        assert_eq!(bridge_message_wire_era(&oversized), BridgeWireEra::Invalid);

        let mut mismatched_payload = message.encode();
        *mismatched_payload.last_mut().unwrap() ^= 1;
        assert_eq!(
            bridge_message_wire_era(&mismatched_payload),
            BridgeWireEra::Invalid
        );

        let inbound = InboundBridgeArgsV2 {
            schema: BridgeSchemaV2,
            rules_hash: message.rules_hash,
            source_chain_id: message.source_chain_id,
            source_message_nonce: message.message_nonce,
            verifier_program_hash: [4u8; 32],
            proof_receipt: vec![5, 6],
            message: message.clone(),
        };
        assert_eq!(
            inbound_bridge_args_wire_era(&inbound.encode()),
            BridgeWireEra::V2
        );
        let mut mismatched_rules = inbound.clone();
        mismatched_rules.rules_hash = RulesHash48::new([0x34; 48]);
        assert_eq!(
            inbound_bridge_args_wire_era(&mismatched_rules.encode()),
            BridgeWireEra::Invalid
        );
        let mut mismatched_chain = inbound.clone();
        mismatched_chain.source_chain_id[0] ^= 1;
        assert_eq!(
            inbound_bridge_args_wire_era(&mismatched_chain.encode()),
            BridgeWireEra::Invalid
        );
        let mut mismatched_nonce = inbound;
        mismatched_nonce.source_message_nonce += 1;
        assert_eq!(
            inbound_bridge_args_wire_era(&mismatched_nonce.encode()),
            BridgeWireEra::Invalid
        );

        let replay_key = inbound_replay_key_v2([1u8; 32], 7);
        let mut replay = InboundReplayStateV2::default();
        assert_eq!(replay.stage(replay_key), Ok(()));
        let before = replay.clone();
        assert_eq!(
            bridge_message_wire_era(&wrong_marker),
            BridgeWireEra::Invalid
        );
        assert_eq!(
            replay, before,
            "wire rejection must not mutate replay state"
        );
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
        message_root_cases: Vec<LeanBridgeMessageRootCase>,
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
    struct LeanBridgeMessageRootCase {
        name: String,
        message_hashes: Vec<String>,
        expected_valid: bool,
        expected_transcript_hex: String,
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
            !vectors.message_root_cases.is_empty(),
            "Lean bridge message-root cases must not be empty"
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
        for case in &vectors.message_root_cases {
            assert!(names.insert(format!("message-root:{}", case.name)));
            verify_lean_bridge_message_root_case(case);
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

    fn verify_lean_bridge_message_root_case(case: &LeanBridgeMessageRootCase) {
        let hashes = case
            .message_hashes
            .iter()
            .map(|hash| parse_hash48_result(hash))
            .collect::<Result<Vec<_>, _>>();
        assert_eq!(
            hashes.is_ok(),
            case.expected_valid,
            "{} message-root validity drifted from Lean spec",
            case.name
        );
        if let Ok(hashes) = hashes {
            let expected_transcript = parse_hex_vec(&case.expected_transcript_hex);
            assert_eq!(
                bridge_message_root_preimage_v1_from_hashes(&hashes),
                expected_transcript,
                "{} bridge message-root transcript drifted from Lean spec",
                case.name
            );
        }
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
        parse_hash48_result(value).expect("expected 48-byte hash")
    }

    fn parse_hash48_result(value: &str) -> Result<MessageHash, String> {
        let bytes = parse_hex_vec(value);
        if bytes.len() != 48 {
            return Err(format!("expected 48-byte hash, got {}", bytes.len()));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn parse_hex_vec(value: &str) -> Vec<u8> {
        let stripped = value.strip_prefix("0x").unwrap_or(value);
        hex::decode(stripped).expect("decode hex")
    }
}
