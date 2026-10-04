//! Canonical, fail-closed transport for the compact Poseidon2/SmallWood V8 leaf.
//!
//! The active V8 successor has a self-contained native leaf and inner proof
//! identity. The leaf is `HGV8TX02`, exactly 120 canonical Goldilocks public words,
//! exactly seven canonical relation/balance-binding limbs, one exact 2,147-byte
//! ciphertext for each active output in slot order, and one unchanged `SMZ9`
//! proof. Each ciphertext's conventional BLAKE2b-384 hash must match its six
//! public statement words. The outer `SWP8LC02` header and canonical SCALE
//! vector carry that self-contained leaf byte-for-byte through every native
//! lifecycle boundary.
//! The additive q38 SMZA helpers preserve this grammar under `HGV8TX03` /
//! `SWP8LC03`, profile 9 and domain set 5, with independent larger byte caps.
//! Selecting one profile never accepts another profile's bytes or parameters.
//!
//! This module is transport only. A source-owned V8 relation module must supply
//! the one expected nonzero relation digest and network id to contextual decode.
//! Shape-only preflight is allocation-free but is never proof or consensus
//! authority. Historical wires, lattice receipts, caches, and sidecars have no
//! conversion into this grammar. Explicitly named historical helpers exist
//! only to construct SMZ8 rejection fixtures; no unsuffixed historical encoder
//! is exposed as a production-looking API.

use alloc::vec::Vec;
use core::fmt;

use crate::family::{ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE, FAMILY_SHIELDED_POOL};
use protocol_versioning::{
    CIRCUIT_V8, CRYPTO_SUITE_ETA, SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
};
use transaction_core::hashing_pq::ciphertext_hash_bytes;

pub const POSEIDON2_PRODUCTION_TRANSPORT_MAGIC: [u8; 8] = *b"SWP8LC01";
pub const POSEIDON2_PRODUCTION_TRANSPORT_GRAMMAR: u16 = 1;
pub const POSEIDON2_PRODUCTION_NATIVE_LEAF_MAGIC: [u8; 8] = *b"HGV8TX01";
pub const POSEIDON2_PRODUCTION_NATIVE_LEAF_GRAMMAR: u16 = 1;
pub const POSEIDON2_PRODUCTION_INNER_PROOF_MAGIC: [u8; 4] = *b"SMZ8";
/// Additive profile-6 successor identities.  The historical `*01`/SMZ8
/// constants above remain decode-only and are never reinterpreted.
pub const POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_MAGIC: [u8; 8] = *b"SWP8LC02";
pub const POSEIDON2_PRODUCTION_SMZ9_NATIVE_LEAF_MAGIC: [u8; 8] = *b"HGV8TX02";
pub const POSEIDON2_PRODUCTION_SMZ9_INNER_PROOF_MAGIC: [u8; 4] = *b"SMZ9";
/// Additive q38 full-SHA-512 transport. These identities do not authorize proofs.
pub const POSEIDON2_PRODUCTION_SMZA_TRANSPORT_MAGIC: [u8; 8] = *b"SWP8LC03";
pub const POSEIDON2_PRODUCTION_SMZA_NATIVE_LEAF_MAGIC: [u8; 8] = *b"HGV8TX03";
pub const POSEIDON2_PRODUCTION_SMZA_INNER_PROOF_MAGIC: [u8; 4] = *b"SMZA";
pub const POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID: u8 = 9;
pub const POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET: u16 = 5;
pub const POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES: usize = 164_113;
pub const POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES: usize = 169_547;
pub const POSEIDON2_PRODUCTION_SMZA_MAX_ENVELOPE_BYTES: usize = 169_543;
pub const POSEIDON2_PRODUCTION_SMZA_MAX_NATIVE_LEAF_BYTES: usize = 169_511;
pub const POSEIDON2_PRODUCTION_SMZA_MAX_ROUTED_NATIVE_LEAF_BYTES: usize = 169_511;

pub const POSEIDON2_PRODUCTION_TRANSPORT_CIRCUIT: u16 = CIRCUIT_V8;
pub const POSEIDON2_PRODUCTION_TRANSPORT_CRYPTO_SUITE: u16 = CRYPTO_SUITE_ETA;
pub const POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID: u16 = FAMILY_SHIELDED_POOL;
pub const POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID: u16 =
    ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE;
pub const POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID: u8 = 2;
pub const POSEIDON2_PRODUCTION_TRANSPORT_PROFILE_ID: u8 = 5;
pub const POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID: u8 = 6;
pub const POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET: u16 = 4;
pub const POSEIDON2_PRODUCTION_TRANSPORT_INLINE_MODE: u8 = 1;

#[derive(Clone, Copy)]
struct Poseidon2ProductionWireProfile {
    transport_magic: [u8; 8],
    native_leaf_magic: [u8; 8],
    inner_proof_magic: [u8; 4],
    profile_id: u8,
    domain_set: u16,
    max_proof_bytes: usize,
    max_native_leaf_bytes: usize,
    max_routed_native_leaf_bytes: usize,
    max_envelope_bytes: usize,
    max_action_bytes: usize,
}

const POSEIDON2_PRODUCTION_SMZ8_WIRE_PROFILE: Poseidon2ProductionWireProfile =
    Poseidon2ProductionWireProfile {
        transport_magic: POSEIDON2_PRODUCTION_TRANSPORT_MAGIC,
        native_leaf_magic: POSEIDON2_PRODUCTION_NATIVE_LEAF_MAGIC,
        inner_proof_magic: POSEIDON2_PRODUCTION_INNER_PROOF_MAGIC,
        profile_id: POSEIDON2_PRODUCTION_TRANSPORT_PROFILE_ID,
        domain_set: POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET,
        max_proof_bytes: POSEIDON2_PRODUCTION_MAX_PROOF_BYTES,
        max_native_leaf_bytes: POSEIDON2_PRODUCTION_MAX_NATIVE_LEAF_BYTES,
        max_routed_native_leaf_bytes: POSEIDON2_PRODUCTION_MAX_ROUTED_NATIVE_LEAF_BYTES,
        max_envelope_bytes: POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES,
        max_action_bytes: POSEIDON2_PRODUCTION_MAX_ACTION_BYTES,
    };

const POSEIDON2_PRODUCTION_SMZ9_WIRE_PROFILE: Poseidon2ProductionWireProfile =
    Poseidon2ProductionWireProfile {
        transport_magic: POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_MAGIC,
        native_leaf_magic: POSEIDON2_PRODUCTION_SMZ9_NATIVE_LEAF_MAGIC,
        inner_proof_magic: POSEIDON2_PRODUCTION_SMZ9_INNER_PROOF_MAGIC,
        profile_id: POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID,
        ..POSEIDON2_PRODUCTION_SMZ8_WIRE_PROFILE
    };

const POSEIDON2_PRODUCTION_SMZA_WIRE_PROFILE: Poseidon2ProductionWireProfile =
    Poseidon2ProductionWireProfile {
        transport_magic: POSEIDON2_PRODUCTION_SMZA_TRANSPORT_MAGIC,
        native_leaf_magic: POSEIDON2_PRODUCTION_SMZA_NATIVE_LEAF_MAGIC,
        inner_proof_magic: POSEIDON2_PRODUCTION_SMZA_INNER_PROOF_MAGIC,
        profile_id: POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
        domain_set: POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
        max_proof_bytes: POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES,
        max_native_leaf_bytes: POSEIDON2_PRODUCTION_SMZA_MAX_NATIVE_LEAF_BYTES,
        max_routed_native_leaf_bytes: POSEIDON2_PRODUCTION_SMZA_MAX_ROUTED_NATIVE_LEAF_BYTES,
        max_envelope_bytes: POSEIDON2_PRODUCTION_SMZA_MAX_ENVELOPE_BYTES,
        max_action_bytes: POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES,
    };

pub const POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS: usize = 120;
pub const POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS: usize = 7;
pub const POSEIDON2_PRODUCTION_RELATION_DIGEST_BYTES: usize = 48;
pub const POSEIDON2_PRODUCTION_FIELD_WORD_BYTES: usize = 8;
pub const POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_BYTES: usize =
    POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS * POSEIDON2_PRODUCTION_FIELD_WORD_BYTES;
pub const POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_BYTES: usize =
    POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS * POSEIDON2_PRODUCTION_FIELD_WORD_BYTES;
pub const POSEIDON2_PRODUCTION_GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
pub const POSEIDON2_PRODUCTION_MAX_OUTPUTS: usize = 2;
pub const POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES: usize = crate::types::MAX_CIPHERTEXT_BYTES;
pub const POSEIDON2_PRODUCTION_MAX_CIPHERTEXT_SECTION_BYTES: usize =
    POSEIDON2_PRODUCTION_MAX_OUTPUTS * POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES;
pub const POSEIDON2_PRODUCTION_OUTPUT_FLAG_WORD: usize = 2;
pub const POSEIDON2_PRODUCTION_CIPHERTEXT_HASH_WORD: usize = 32;
pub const POSEIDON2_PRODUCTION_CIPHERTEXT_HASH_LIMBS: usize = 6;

pub const POSEIDON2_PRODUCTION_NATIVE_LEAF_HEADER_BYTES: usize = 88;
pub const POSEIDON2_PRODUCTION_NATIVE_LEAF_FIXED_BYTES: usize =
    POSEIDON2_PRODUCTION_NATIVE_LEAF_HEADER_BYTES
        + POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_BYTES
        + POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_BYTES;
pub const POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES: usize = 32;
pub const POSEIDON2_PRODUCTION_SCALE_PREFIX_BYTES: usize = 4;

pub const POSEIDON2_PRODUCTION_MAX_PROOF_BYTES: usize = 131_072;
pub const POSEIDON2_PRODUCTION_MAX_NATIVE_LEAF_BYTES: usize = 131_072;
pub const POSEIDON2_PRODUCTION_MAX_ACTION_BYTES: usize = 131_072;
pub const POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES: usize =
    POSEIDON2_PRODUCTION_MAX_ACTION_BYTES - POSEIDON2_PRODUCTION_SCALE_PREFIX_BYTES;
pub const POSEIDON2_PRODUCTION_MAX_ROUTED_NATIVE_LEAF_BYTES: usize =
    POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES - POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES;
pub const POSEIDON2_PRODUCTION_MAX_ROUTED_PROOF_BYTES_NO_OUTPUTS: usize =
    POSEIDON2_PRODUCTION_MAX_ROUTED_NATIVE_LEAF_BYTES
        - POSEIDON2_PRODUCTION_NATIVE_LEAF_FIXED_BYTES;
pub const POSEIDON2_PRODUCTION_MAX_ROUTED_PROOF_BYTES_AT_MAX_OUTPUTS: usize =
    POSEIDON2_PRODUCTION_MAX_ROUTED_PROOF_BYTES_NO_OUTPUTS
        - POSEIDON2_PRODUCTION_MAX_CIPHERTEXT_SECTION_BYTES;
/// Fixed framing above the proof, excluding exact output ciphertext payloads.
pub const POSEIDON2_PRODUCTION_TOTAL_OVERHEAD_BYTES: usize =
    POSEIDON2_PRODUCTION_NATIVE_LEAF_FIXED_BYTES
        + POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES
        + POSEIDON2_PRODUCTION_SCALE_PREFIX_BYTES;
pub const POSEIDON2_PRODUCTION_MAX_FRAMING_OVERHEAD_BYTES: usize = 1_500;
pub const POSEIDON2_PRODUCTION_MAX_INLINE_NON_PROOF_BYTES: usize =
    POSEIDON2_PRODUCTION_TOTAL_OVERHEAD_BYTES + POSEIDON2_PRODUCTION_MAX_CIPHERTEXT_SECTION_BYTES;
/// Historical zero-output pre-freeze screen retained as a framing regression.
///
/// It cannot coexist with any inline ciphertext and is not the canonical
/// accepted-proof maximum. The executable relation adapter, exact projector,
/// and retained maximum-shape artifact must freeze that value together.
pub const POSEIDON2_PRODUCTION_CONSERVATIVE_SCREEN_PROOF_BYTES: usize = 128_358;
pub const POSEIDON2_PRODUCTION_CONSERVATIVE_SCREEN_ACTION_BYTES: usize =
    POSEIDON2_PRODUCTION_CONSERVATIVE_SCREEN_PROOF_BYTES
        + POSEIDON2_PRODUCTION_TOTAL_OVERHEAD_BYTES;

pub const fn poseidon2_production_max_routed_proof_bytes(active_outputs: usize) -> Option<usize> {
    if active_outputs > POSEIDON2_PRODUCTION_MAX_OUTPUTS {
        return None;
    }
    POSEIDON2_PRODUCTION_MAX_ROUTED_PROOF_BYTES_NO_OUTPUTS
        .checked_sub(active_outputs * POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES)
}

/// SMZA's independent inner-proof cap still applies when outputs are inactive.
pub const fn poseidon2_production_smza_max_routed_proof_bytes(
    active_outputs: usize,
) -> Option<usize> {
    if active_outputs > POSEIDON2_PRODUCTION_MAX_OUTPUTS {
        return None;
    }
    Some(POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES)
}

pub const fn poseidon2_production_action_overhead_bytes(active_outputs: usize) -> Option<usize> {
    if active_outputs > POSEIDON2_PRODUCTION_MAX_OUTPUTS {
        return None;
    }
    Some(
        POSEIDON2_PRODUCTION_TOTAL_OVERHEAD_BYTES
            + active_outputs * POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES,
    )
}

const LEAF_OFFSET_GRAMMAR: usize = 8;
const LEAF_OFFSET_CIRCUIT: usize = 10;
const LEAF_OFFSET_CRYPTO_SUITE: usize = 12;
const LEAF_OFFSET_FAMILY: usize = 14;
const LEAF_OFFSET_ACTION: usize = 16;
const LEAF_OFFSET_BACKEND: usize = 18;
const LEAF_OFFSET_PROFILE: usize = 19;
const LEAF_OFFSET_DOMAIN_SET: usize = 20;
const LEAF_OFFSET_STATEMENT_WORDS: usize = 22;
const LEAF_OFFSET_BINDING_LIMBS: usize = 24;
const LEAF_OFFSET_RESERVED: usize = 26;
const LEAF_OFFSET_NETWORK: usize = 28;
const LEAF_OFFSET_PROOF_LEN: usize = 32;
const LEAF_OFFSET_RELATION_DIGEST: usize = 36;
const LEAF_OFFSET_NATIVE_LEAF_LEN: usize = 84;
const LEAF_OFFSET_STATEMENT: usize = POSEIDON2_PRODUCTION_NATIVE_LEAF_HEADER_BYTES;
const LEAF_OFFSET_BINDING: usize =
    LEAF_OFFSET_STATEMENT + POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_BYTES;
const LEAF_OFFSET_CIPHERTEXTS: usize =
    LEAF_OFFSET_BINDING + POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_BYTES;

const TRANSPORT_OFFSET_GRAMMAR: usize = 8;
const TRANSPORT_OFFSET_CIRCUIT: usize = 10;
const TRANSPORT_OFFSET_CRYPTO_SUITE: usize = 12;
const TRANSPORT_OFFSET_FAMILY: usize = 14;
const TRANSPORT_OFFSET_ACTION: usize = 16;
const TRANSPORT_OFFSET_BACKEND: usize = 18;
const TRANSPORT_OFFSET_PROFILE: usize = 19;
const TRANSPORT_OFFSET_DOMAIN_SET: usize = 20;
const TRANSPORT_OFFSET_MODE: usize = 22;
const TRANSPORT_OFFSET_RESERVED: usize = 23;
const TRANSPORT_OFFSET_PROOF_LEN: usize = 24;
const TRANSPORT_OFFSET_NATIVE_LEAF_LEN: usize = 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poseidon2ProductionExpectedContext {
    network_id: u32,
    relation_digest: [u8; POSEIDON2_PRODUCTION_RELATION_DIGEST_BYTES],
}

impl Poseidon2ProductionExpectedContext {
    /// Construct context from the source-owned V8 relation manifest digest.
    /// Caller-selected or zero digests are not production authority.
    pub fn new(
        network_id: u32,
        relation_digest: [u8; POSEIDON2_PRODUCTION_RELATION_DIGEST_BYTES],
    ) -> Result<Self, Poseidon2ProductionTransportError> {
        if relation_digest == [0; POSEIDON2_PRODUCTION_RELATION_DIGEST_BYTES] {
            return Err(Poseidon2ProductionTransportError::ZeroExpectedRelationDigest);
        }
        Ok(Self {
            network_id,
            relation_digest,
        })
    }

    pub const fn network_id(self) -> u32 {
        self.network_id
    }

    pub const fn relation_digest(self) -> [u8; POSEIDON2_PRODUCTION_RELATION_DIGEST_BYTES] {
        self.relation_digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedPoseidon2ProductionNativeLeaf<'a> {
    raw: &'a [u8],
    network_id: u32,
    relation_digest: [u8; POSEIDON2_PRODUCTION_RELATION_DIGEST_BYTES],
    statement_bytes: &'a [u8; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_BYTES],
    relation_balance_binding_bytes: &'a [u8; POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_BYTES],
    ciphertexts:
        [Option<&'a [u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]>; POSEIDON2_PRODUCTION_MAX_OUTPUTS],
    proof: &'a [u8],
}

impl<'a> DecodedPoseidon2ProductionNativeLeaf<'a> {
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub const fn network_id(self) -> u32 {
        self.network_id
    }

    pub const fn relation_digest(self) -> [u8; POSEIDON2_PRODUCTION_RELATION_DIGEST_BYTES] {
        self.relation_digest
    }

    pub const fn statement_bytes(self) -> &'a [u8; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_BYTES] {
        self.statement_bytes
    }

    pub const fn relation_balance_binding_bytes(
        self,
    ) -> &'a [u8; POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_BYTES] {
        self.relation_balance_binding_bytes
    }

    pub fn statement_word(self, index: usize) -> Option<u64> {
        read_field_word(self.statement_bytes, index)
    }

    pub fn relation_balance_binding_limb(self, index: usize) -> Option<u64> {
        read_field_word(self.relation_balance_binding_bytes, index)
    }

    pub const fn ciphertext(
        self,
        output_slot: usize,
    ) -> Option<&'a [u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]> {
        if output_slot >= POSEIDON2_PRODUCTION_MAX_OUTPUTS {
            return None;
        }
        self.ciphertexts[output_slot]
    }

    pub fn active_output_count(self) -> usize {
        self.ciphertexts.iter().flatten().count()
    }

    pub const fn proof(self) -> &'a [u8] {
        self.proof
    }

    fn ensure_context(
        self,
        expected: Poseidon2ProductionExpectedContext,
    ) -> Result<Self, Poseidon2ProductionTransportError> {
        if self.network_id != expected.network_id {
            return Err(Poseidon2ProductionTransportError::NetworkMismatch {
                expected: expected.network_id,
                observed: self.network_id,
            });
        }
        if self.relation_digest != expected.relation_digest {
            return Err(Poseidon2ProductionTransportError::RelationDigestMismatch);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedPoseidon2ProductionEnvelope<'a> {
    raw: &'a [u8],
    native_leaf: DecodedPoseidon2ProductionNativeLeaf<'a>,
}

impl<'a> DecodedPoseidon2ProductionEnvelope<'a> {
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub const fn declared_proof_len(self) -> usize {
        self.native_leaf.proof.len()
    }

    pub const fn native_leaf(self) -> &'a [u8] {
        self.native_leaf.raw
    }

    pub const fn decoded_native_leaf(self) -> DecodedPoseidon2ProductionNativeLeaf<'a> {
        self.native_leaf
    }

    fn ensure_context(
        self,
        expected: Poseidon2ProductionExpectedContext,
    ) -> Result<Self, Poseidon2ProductionTransportError> {
        self.native_leaf.ensure_context(expected)?;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedPoseidon2ProductionInlineArgs<'a> {
    raw: &'a [u8],
    envelope: DecodedPoseidon2ProductionEnvelope<'a>,
}

impl<'a> DecodedPoseidon2ProductionInlineArgs<'a> {
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub const fn envelope(self) -> DecodedPoseidon2ProductionEnvelope<'a> {
        self.envelope
    }

    fn ensure_context(
        self,
        expected: Poseidon2ProductionExpectedContext,
    ) -> Result<Self, Poseidon2ProductionTransportError> {
        self.envelope.ensure_context(expected)?;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poseidon2ProductionTransportStage {
    Wallet,
    Rpc,
    Relay,
    Mempool,
    Mining,
    Block,
    Restart,
    Sync,
    Reorg,
    FreshNodeVerify,
}

impl Poseidon2ProductionTransportStage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Rpc => "rpc",
            Self::Relay => "relay",
            Self::Mempool => "mempool",
            Self::Mining => "mining",
            Self::Block => "block",
            Self::Restart => "restart",
            Self::Sync => "sync",
            Self::Reorg => "reorg",
            Self::FreshNodeVerify => "fresh_node_verify",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Poseidon2ProductionTransportError {
    ZeroExpectedRelationDigest,
    ZeroEncodedRelationDigest,
    NetworkMismatch {
        expected: u32,
        observed: u32,
    },
    RelationDigestMismatch,
    EmptyProof,
    InnerProofTooShort(usize),
    UnsupportedInnerProofMagic([u8; 4]),
    ProofTooLarge {
        observed: usize,
        maximum: usize,
    },
    ProofExceedsInlineBudget {
        observed: usize,
        maximum: usize,
    },
    NativeLeafTooLarge {
        observed: usize,
        maximum: usize,
    },
    NativeLeafExceedsInlineBudget {
        observed: usize,
        maximum: usize,
    },
    EnvelopeTooLarge {
        observed: usize,
        maximum: usize,
    },
    ActionBytesTooLarge {
        observed: usize,
        maximum: usize,
    },
    HeaderTooShort {
        observed: usize,
        required: usize,
    },
    InvalidNativeLeafMagic([u8; 8]),
    InvalidTransportMagic([u8; 8]),
    UnsupportedNativeLeafGrammar(u16),
    UnsupportedTransportGrammar(u16),
    UnsupportedCircuit(u16),
    UnsupportedCryptoSuite(u16),
    UnsupportedFamily(u16),
    UnsupportedAction(u16),
    UnsupportedBackend(u8),
    UnsupportedProfile(u8),
    UnsupportedDomainSet(u16),
    UnsupportedMode(u8),
    InvalidStatementWordCount(u16),
    InvalidBindingLimbCount(u16),
    NonZeroReserved(u16),
    NonZeroTransportReserved(u8),
    NonCanonicalFieldWord {
        section: &'static str,
        index: usize,
        value: u64,
    },
    NonBooleanOutputFlag {
        output_slot: usize,
        value: u64,
    },
    CiphertextPresenceMismatch {
        output_slot: usize,
        active: bool,
        present: bool,
    },
    InactiveCiphertextHashNonZero {
        output_slot: usize,
        limb: usize,
        value: u64,
    },
    CiphertextHashMismatch {
        output_slot: usize,
    },
    CrossLayerProofLengthMismatch {
        outer: usize,
        inner: usize,
    },
    LengthOverflow,
    Truncated {
        declared: usize,
        observed: usize,
    },
    TrailingBytes {
        trailing: usize,
    },
    CompactLengthTruncated,
    CompactLengthOverflow,
    NonCanonicalCompactLength,
    AllocationFailed(usize),
    StageMismatch {
        stage: Poseidon2ProductionTransportStage,
        expected: usize,
        observed: usize,
        first_difference: Option<usize>,
    },
}

impl fmt::Display for Poseidon2ProductionTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Poseidon2ProductionTransportError {}

/// Construct an SMZ8/HGV8TX01 rejection fixture. Never use for live routing.
pub fn encode_historical_poseidon2_v8_smz8_native_leaf(
    expected: Poseidon2ProductionExpectedContext,
    public_statement: &[u64; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS],
    relation_balance_binding: &[u64; POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS],
    ciphertexts: [Option<&[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]>;
        POSEIDON2_PRODUCTION_MAX_OUTPUTS],
    proof: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    encode_poseidon2_production_native_leaf_with_profile(
        POSEIDON2_PRODUCTION_SMZ8_WIRE_PROFILE,
        expected,
        public_statement,
        relation_balance_binding,
        ciphertexts,
        proof,
    )
}

pub fn encode_poseidon2_production_smz9_native_leaf(
    expected: Poseidon2ProductionExpectedContext,
    public_statement: &[u64; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS],
    relation_balance_binding: &[u64; POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS],
    ciphertexts: [Option<&[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]>;
        POSEIDON2_PRODUCTION_MAX_OUTPUTS],
    proof: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    encode_poseidon2_production_native_leaf_with_profile(
        POSEIDON2_PRODUCTION_SMZ9_WIRE_PROFILE,
        expected,
        public_statement,
        relation_balance_binding,
        ciphertexts,
        proof,
    )
}

pub fn encode_poseidon2_production_smza_native_leaf(
    expected: Poseidon2ProductionExpectedContext,
    public_statement: &[u64; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS],
    relation_balance_binding: &[u64; POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS],
    ciphertexts: [Option<&[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]>;
        POSEIDON2_PRODUCTION_MAX_OUTPUTS],
    proof: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    encode_poseidon2_production_native_leaf_with_profile(
        POSEIDON2_PRODUCTION_SMZA_WIRE_PROFILE,
        expected,
        public_statement,
        relation_balance_binding,
        ciphertexts,
        proof,
    )
}

pub fn preflight_poseidon2_production_smza_native_leaf_exact(
    leaf: &[u8],
) -> Result<DecodedPoseidon2ProductionNativeLeaf<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_native_leaf_with_profile_exact(
        leaf,
        POSEIDON2_PRODUCTION_SMZA_WIRE_PROFILE,
    )
}

pub fn decode_poseidon2_production_smza_native_leaf_exact(
    expected: Poseidon2ProductionExpectedContext,
    leaf: &[u8],
) -> Result<DecodedPoseidon2ProductionNativeLeaf<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_smza_native_leaf_exact(leaf)?.ensure_context(expected)
}

pub fn encode_poseidon2_production_smza_envelope(
    expected: Poseidon2ProductionExpectedContext,
    native_leaf: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    encode_poseidon2_production_envelope_with_profile(
        POSEIDON2_PRODUCTION_SMZA_WIRE_PROFILE,
        expected,
        native_leaf,
    )
}

pub fn preflight_poseidon2_production_smza_envelope_exact(
    envelope: &[u8],
) -> Result<DecodedPoseidon2ProductionEnvelope<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_envelope_with_profile_exact(
        envelope,
        POSEIDON2_PRODUCTION_SMZA_WIRE_PROFILE,
    )
}

pub fn decode_poseidon2_production_smza_envelope_exact(
    expected: Poseidon2ProductionExpectedContext,
    envelope: &[u8],
) -> Result<DecodedPoseidon2ProductionEnvelope<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_smza_envelope_exact(envelope)?.ensure_context(expected)
}

pub fn encode_poseidon2_production_smza_inline_args(
    expected: Poseidon2ProductionExpectedContext,
    envelope: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    encode_poseidon2_production_inline_args_with_profile(
        POSEIDON2_PRODUCTION_SMZA_WIRE_PROFILE,
        expected,
        envelope,
    )
}

pub fn preflight_poseidon2_production_smza_inline_args_exact(
    encoded: &[u8],
) -> Result<DecodedPoseidon2ProductionInlineArgs<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_inline_args_with_profile_exact(
        encoded,
        POSEIDON2_PRODUCTION_SMZA_WIRE_PROFILE,
    )
}

pub fn decode_poseidon2_production_smza_inline_args_exact(
    expected: Poseidon2ProductionExpectedContext,
    encoded: &[u8],
) -> Result<DecodedPoseidon2ProductionInlineArgs<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_smza_inline_args_exact(encoded)?.ensure_context(expected)
}

pub fn ensure_poseidon2_production_smza_stage_bytes(
    expected: Poseidon2ProductionExpectedContext,
    canonical_envelope: &[u8],
    observed_action_args: &[u8],
    stage: Poseidon2ProductionTransportStage,
) -> Result<(), Poseidon2ProductionTransportError> {
    ensure_poseidon2_production_stage_bytes_with_profile(
        POSEIDON2_PRODUCTION_SMZA_WIRE_PROFILE,
        expected,
        canonical_envelope,
        observed_action_args,
        stage,
    )
}

fn encode_poseidon2_production_native_leaf_with_profile(
    wire: Poseidon2ProductionWireProfile,
    expected: Poseidon2ProductionExpectedContext,
    public_statement: &[u64; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS],
    relation_balance_binding: &[u64; POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS],
    ciphertexts: [Option<&[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]>;
        POSEIDON2_PRODUCTION_MAX_OUTPUTS],
    proof: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    validate_field_words("public_statement", public_statement)?;
    validate_field_words("relation_balance_binding", relation_balance_binding)?;
    let active_outputs = validate_ciphertext_bindings(public_statement, ciphertexts)?;
    validate_proof(proof, active_outputs, wire)?;
    let ciphertext_bytes = active_outputs
        .checked_mul(POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES)
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
    let native_leaf_len = POSEIDON2_PRODUCTION_NATIVE_LEAF_FIXED_BYTES
        .checked_add(ciphertext_bytes)
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?
        .checked_add(proof.len())
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
    validate_native_leaf_len(native_leaf_len, wire)?;
    let proof_len = u32::try_from(proof.len())
        .map_err(|_| Poseidon2ProductionTransportError::LengthOverflow)?;
    let leaf_len = u32::try_from(native_leaf_len)
        .map_err(|_| Poseidon2ProductionTransportError::LengthOverflow)?;

    let mut leaf = Vec::new();
    leaf.try_reserve_exact(native_leaf_len)
        .map_err(|_| Poseidon2ProductionTransportError::AllocationFailed(native_leaf_len))?;
    leaf.extend_from_slice(&wire.native_leaf_magic);
    leaf.extend_from_slice(&POSEIDON2_PRODUCTION_NATIVE_LEAF_GRAMMAR.to_le_bytes());
    leaf.extend_from_slice(&POSEIDON2_PRODUCTION_TRANSPORT_CIRCUIT.to_le_bytes());
    leaf.extend_from_slice(&POSEIDON2_PRODUCTION_TRANSPORT_CRYPTO_SUITE.to_le_bytes());
    leaf.extend_from_slice(&POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID.to_le_bytes());
    leaf.extend_from_slice(&POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID.to_le_bytes());
    leaf.push(POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID);
    leaf.push(wire.profile_id);
    leaf.extend_from_slice(&wire.domain_set.to_le_bytes());
    leaf.extend_from_slice(&(POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS as u16).to_le_bytes());
    leaf.extend_from_slice(
        &(POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS as u16).to_le_bytes(),
    );
    leaf.extend_from_slice(&0u16.to_le_bytes());
    leaf.extend_from_slice(&expected.network_id.to_le_bytes());
    leaf.extend_from_slice(&proof_len.to_le_bytes());
    leaf.extend_from_slice(&expected.relation_digest);
    leaf.extend_from_slice(&leaf_len.to_le_bytes());
    debug_assert_eq!(leaf.len(), POSEIDON2_PRODUCTION_NATIVE_LEAF_HEADER_BYTES);
    for word in public_statement {
        leaf.extend_from_slice(&word.to_le_bytes());
    }
    for limb in relation_balance_binding {
        leaf.extend_from_slice(&limb.to_le_bytes());
    }
    for ciphertext in ciphertexts.into_iter().flatten() {
        leaf.extend_from_slice(ciphertext);
    }
    leaf.extend_from_slice(proof);
    debug_assert_eq!(leaf.len(), native_leaf_len);
    Ok(leaf)
}

/// Parse historical SMZ8 bytes for migration and rejection tests only.
pub fn preflight_historical_poseidon2_v8_smz8_native_leaf_exact(
    leaf: &[u8],
) -> Result<DecodedPoseidon2ProductionNativeLeaf<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_native_leaf_with_profile_exact(
        leaf,
        POSEIDON2_PRODUCTION_SMZ8_WIRE_PROFILE,
    )
}

pub fn preflight_poseidon2_production_smz9_native_leaf_exact(
    leaf: &[u8],
) -> Result<DecodedPoseidon2ProductionNativeLeaf<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_native_leaf_with_profile_exact(
        leaf,
        POSEIDON2_PRODUCTION_SMZ9_WIRE_PROFILE,
    )
}

fn preflight_poseidon2_production_native_leaf_with_profile_exact(
    leaf: &[u8],
    wire: Poseidon2ProductionWireProfile,
) -> Result<DecodedPoseidon2ProductionNativeLeaf<'_>, Poseidon2ProductionTransportError> {
    if leaf.len() > wire.max_native_leaf_bytes {
        return Err(Poseidon2ProductionTransportError::NativeLeafTooLarge {
            observed: leaf.len(),
            maximum: wire.max_native_leaf_bytes,
        });
    }
    if leaf.len() > wire.max_routed_native_leaf_bytes {
        return Err(
            Poseidon2ProductionTransportError::NativeLeafExceedsInlineBudget {
                observed: leaf.len(),
                maximum: wire.max_routed_native_leaf_bytes,
            },
        );
    }
    if leaf.len() < POSEIDON2_PRODUCTION_NATIVE_LEAF_HEADER_BYTES {
        return Err(Poseidon2ProductionTransportError::HeaderTooShort {
            observed: leaf.len(),
            required: POSEIDON2_PRODUCTION_NATIVE_LEAF_HEADER_BYTES,
        });
    }
    let magic = read_array::<8>(leaf, 0);
    if magic != wire.native_leaf_magic {
        return Err(Poseidon2ProductionTransportError::InvalidNativeLeafMagic(
            magic,
        ));
    }
    expect_u16(
        leaf,
        LEAF_OFFSET_GRAMMAR,
        POSEIDON2_PRODUCTION_NATIVE_LEAF_GRAMMAR,
        Poseidon2ProductionTransportError::UnsupportedNativeLeafGrammar,
    )?;
    validate_route_fields(leaf, true, wire)?;
    let statement_words = read_u16_le(leaf, LEAF_OFFSET_STATEMENT_WORDS);
    if statement_words != POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS as u16 {
        return Err(Poseidon2ProductionTransportError::InvalidStatementWordCount(statement_words));
    }
    let binding_limbs = read_u16_le(leaf, LEAF_OFFSET_BINDING_LIMBS);
    if binding_limbs != POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS as u16 {
        return Err(Poseidon2ProductionTransportError::InvalidBindingLimbCount(
            binding_limbs,
        ));
    }
    let reserved = read_u16_le(leaf, LEAF_OFFSET_RESERVED);
    if reserved != 0 {
        return Err(Poseidon2ProductionTransportError::NonZeroReserved(reserved));
    }
    let proof_len = read_u32_le(leaf, LEAF_OFFSET_PROOF_LEN) as usize;
    validate_hard_proof_len(proof_len, wire)?;
    let declared_leaf_len = read_u32_le(leaf, LEAF_OFFSET_NATIVE_LEAF_LEN) as usize;
    validate_native_leaf_len(declared_leaf_len, wire)?;
    if declared_leaf_len < POSEIDON2_PRODUCTION_NATIVE_LEAF_FIXED_BYTES {
        return Err(Poseidon2ProductionTransportError::Truncated {
            declared: POSEIDON2_PRODUCTION_NATIVE_LEAF_FIXED_BYTES,
            observed: declared_leaf_len,
        });
    }
    if leaf.len() < declared_leaf_len {
        return Err(Poseidon2ProductionTransportError::Truncated {
            declared: declared_leaf_len,
            observed: leaf.len(),
        });
    }
    if leaf.len() > declared_leaf_len {
        return Err(Poseidon2ProductionTransportError::TrailingBytes {
            trailing: leaf.len() - declared_leaf_len,
        });
    }
    let relation_digest =
        read_array::<POSEIDON2_PRODUCTION_RELATION_DIGEST_BYTES>(leaf, LEAF_OFFSET_RELATION_DIGEST);
    if relation_digest == [0; POSEIDON2_PRODUCTION_RELATION_DIGEST_BYTES] {
        return Err(Poseidon2ProductionTransportError::ZeroEncodedRelationDigest);
    }
    let statement_bytes = leaf[LEAF_OFFSET_STATEMENT..LEAF_OFFSET_BINDING]
        .try_into()
        .expect("fixed statement range");
    let relation_balance_binding_bytes = leaf[LEAF_OFFSET_BINDING..LEAF_OFFSET_CIPHERTEXTS]
        .try_into()
        .expect("fixed relation/balance range");
    validate_encoded_field_words("public_statement", statement_bytes)?;
    validate_encoded_field_words("relation_balance_binding", relation_balance_binding_bytes)?;
    let statement_words = core::array::from_fn(|index| {
        read_field_word(statement_bytes, index).expect("validated fixed statement word")
    });
    let active_slots = output_activity(&statement_words)?;
    let active_outputs = active_slots.iter().filter(|active| **active).count();
    validate_routed_proof_len(proof_len, active_outputs, wire)?;
    let ciphertext_bytes = active_outputs
        .checked_mul(POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES)
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
    let expected_leaf_len = POSEIDON2_PRODUCTION_NATIVE_LEAF_FIXED_BYTES
        .checked_add(ciphertext_bytes)
        .and_then(|bytes| bytes.checked_add(proof_len))
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
    if declared_leaf_len != expected_leaf_len {
        return if declared_leaf_len > expected_leaf_len {
            Err(Poseidon2ProductionTransportError::TrailingBytes {
                trailing: declared_leaf_len - expected_leaf_len,
            })
        } else {
            Err(Poseidon2ProductionTransportError::Truncated {
                declared: expected_leaf_len,
                observed: declared_leaf_len,
            })
        };
    }
    let mut ciphertexts = [None; POSEIDON2_PRODUCTION_MAX_OUTPUTS];
    let mut cursor = LEAF_OFFSET_CIPHERTEXTS;
    for (output_slot, active) in active_slots.into_iter().enumerate() {
        if active {
            let end = cursor
                .checked_add(POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES)
                .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
            ciphertexts[output_slot] = Some(
                leaf[cursor..end]
                    .try_into()
                    .expect("declared ciphertext range was checked"),
            );
            cursor = end;
        }
    }
    validate_ciphertext_bindings(&statement_words, ciphertexts)?;
    let proof = &leaf[cursor..declared_leaf_len];
    validate_proof(proof, active_outputs, wire)?;
    Ok(DecodedPoseidon2ProductionNativeLeaf {
        raw: leaf,
        network_id: read_u32_le(leaf, LEAF_OFFSET_NETWORK),
        relation_digest,
        statement_bytes,
        relation_balance_binding_bytes,
        ciphertexts,
        proof,
    })
}

/// Decode historical SMZ8 bytes for migration and rejection tests only.
pub fn decode_historical_poseidon2_v8_smz8_native_leaf_exact(
    expected: Poseidon2ProductionExpectedContext,
    leaf: &[u8],
) -> Result<DecodedPoseidon2ProductionNativeLeaf<'_>, Poseidon2ProductionTransportError> {
    preflight_historical_poseidon2_v8_smz8_native_leaf_exact(leaf)?.ensure_context(expected)
}

pub fn decode_poseidon2_production_smz9_native_leaf_exact(
    expected: Poseidon2ProductionExpectedContext,
    leaf: &[u8],
) -> Result<DecodedPoseidon2ProductionNativeLeaf<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_smz9_native_leaf_exact(leaf)?.ensure_context(expected)
}

/// Construct an SMZ8/SWP8LC01 rejection fixture. Never use for live routing.
pub fn encode_historical_poseidon2_v8_smz8_envelope(
    expected: Poseidon2ProductionExpectedContext,
    native_leaf: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    encode_poseidon2_production_envelope_with_profile(
        POSEIDON2_PRODUCTION_SMZ8_WIRE_PROFILE,
        expected,
        native_leaf,
    )
}

pub fn encode_poseidon2_production_smz9_envelope(
    expected: Poseidon2ProductionExpectedContext,
    native_leaf: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    encode_poseidon2_production_envelope_with_profile(
        POSEIDON2_PRODUCTION_SMZ9_WIRE_PROFILE,
        expected,
        native_leaf,
    )
}

fn encode_poseidon2_production_envelope_with_profile(
    wire: Poseidon2ProductionWireProfile,
    expected: Poseidon2ProductionExpectedContext,
    native_leaf: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    let decoded_leaf =
        preflight_poseidon2_production_native_leaf_with_profile_exact(native_leaf, wire)?
            .ensure_context(expected)?;
    let envelope_len = POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES
        .checked_add(native_leaf.len())
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
    if envelope_len > wire.max_envelope_bytes {
        return Err(Poseidon2ProductionTransportError::EnvelopeTooLarge {
            observed: envelope_len,
            maximum: wire.max_envelope_bytes,
        });
    }
    let proof_len = u32::try_from(decoded_leaf.proof.len())
        .map_err(|_| Poseidon2ProductionTransportError::LengthOverflow)?;
    let leaf_len = u32::try_from(native_leaf.len())
        .map_err(|_| Poseidon2ProductionTransportError::LengthOverflow)?;
    let mut envelope = Vec::new();
    envelope
        .try_reserve_exact(envelope_len)
        .map_err(|_| Poseidon2ProductionTransportError::AllocationFailed(envelope_len))?;
    envelope.extend_from_slice(&wire.transport_magic);
    envelope.extend_from_slice(&POSEIDON2_PRODUCTION_TRANSPORT_GRAMMAR.to_le_bytes());
    envelope.extend_from_slice(&POSEIDON2_PRODUCTION_TRANSPORT_CIRCUIT.to_le_bytes());
    envelope.extend_from_slice(&POSEIDON2_PRODUCTION_TRANSPORT_CRYPTO_SUITE.to_le_bytes());
    envelope.extend_from_slice(&POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID.to_le_bytes());
    envelope.extend_from_slice(&POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID.to_le_bytes());
    envelope.push(POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID);
    envelope.push(wire.profile_id);
    envelope.extend_from_slice(&wire.domain_set.to_le_bytes());
    envelope.push(POSEIDON2_PRODUCTION_TRANSPORT_INLINE_MODE);
    envelope.push(0);
    envelope.extend_from_slice(&proof_len.to_le_bytes());
    envelope.extend_from_slice(&leaf_len.to_le_bytes());
    debug_assert_eq!(envelope.len(), POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES);
    envelope.extend_from_slice(native_leaf);
    Ok(envelope)
}

/// Parse a historical SMZ8 envelope for migration and rejection tests only.
pub fn preflight_historical_poseidon2_v8_smz8_envelope_exact(
    envelope: &[u8],
) -> Result<DecodedPoseidon2ProductionEnvelope<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_envelope_with_profile_exact(
        envelope,
        POSEIDON2_PRODUCTION_SMZ8_WIRE_PROFILE,
    )
}

pub fn preflight_poseidon2_production_smz9_envelope_exact(
    envelope: &[u8],
) -> Result<DecodedPoseidon2ProductionEnvelope<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_envelope_with_profile_exact(
        envelope,
        POSEIDON2_PRODUCTION_SMZ9_WIRE_PROFILE,
    )
}

fn preflight_poseidon2_production_envelope_with_profile_exact(
    envelope: &[u8],
    wire: Poseidon2ProductionWireProfile,
) -> Result<DecodedPoseidon2ProductionEnvelope<'_>, Poseidon2ProductionTransportError> {
    if envelope.len() > wire.max_envelope_bytes {
        return Err(Poseidon2ProductionTransportError::EnvelopeTooLarge {
            observed: envelope.len(),
            maximum: wire.max_envelope_bytes,
        });
    }
    if envelope.len() < POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES {
        return Err(Poseidon2ProductionTransportError::HeaderTooShort {
            observed: envelope.len(),
            required: POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES,
        });
    }
    let magic = read_array::<8>(envelope, 0);
    if magic != wire.transport_magic {
        return Err(Poseidon2ProductionTransportError::InvalidTransportMagic(
            magic,
        ));
    }
    expect_u16(
        envelope,
        TRANSPORT_OFFSET_GRAMMAR,
        POSEIDON2_PRODUCTION_TRANSPORT_GRAMMAR,
        Poseidon2ProductionTransportError::UnsupportedTransportGrammar,
    )?;
    validate_route_fields(envelope, false, wire)?;
    if envelope[TRANSPORT_OFFSET_MODE] != POSEIDON2_PRODUCTION_TRANSPORT_INLINE_MODE {
        return Err(Poseidon2ProductionTransportError::UnsupportedMode(
            envelope[TRANSPORT_OFFSET_MODE],
        ));
    }
    if envelope[TRANSPORT_OFFSET_RESERVED] != 0 {
        return Err(Poseidon2ProductionTransportError::NonZeroTransportReserved(
            envelope[TRANSPORT_OFFSET_RESERVED],
        ));
    }
    let proof_len = read_u32_le(envelope, TRANSPORT_OFFSET_PROOF_LEN) as usize;
    validate_hard_proof_len(proof_len, wire)?;
    let native_leaf_len = read_u32_le(envelope, TRANSPORT_OFFSET_NATIVE_LEAF_LEN) as usize;
    validate_native_leaf_len(native_leaf_len, wire)?;
    let declared_total = POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES
        .checked_add(native_leaf_len)
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
    if envelope.len() < declared_total {
        return Err(Poseidon2ProductionTransportError::Truncated {
            declared: declared_total,
            observed: envelope.len(),
        });
    }
    if envelope.len() > declared_total {
        return Err(Poseidon2ProductionTransportError::TrailingBytes {
            trailing: envelope.len() - declared_total,
        });
    }
    let native_leaf = preflight_poseidon2_production_native_leaf_with_profile_exact(
        &envelope[POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES..declared_total],
        wire,
    )?;
    if proof_len != native_leaf.proof.len() {
        return Err(
            Poseidon2ProductionTransportError::CrossLayerProofLengthMismatch {
                outer: proof_len,
                inner: native_leaf.proof.len(),
            },
        );
    }
    Ok(DecodedPoseidon2ProductionEnvelope {
        raw: envelope,
        native_leaf,
    })
}

/// Decode a historical SMZ8 envelope for migration and rejection tests only.
pub fn decode_historical_poseidon2_v8_smz8_envelope_exact(
    expected: Poseidon2ProductionExpectedContext,
    envelope: &[u8],
) -> Result<DecodedPoseidon2ProductionEnvelope<'_>, Poseidon2ProductionTransportError> {
    preflight_historical_poseidon2_v8_smz8_envelope_exact(envelope)?.ensure_context(expected)
}

pub fn decode_poseidon2_production_smz9_envelope_exact(
    expected: Poseidon2ProductionExpectedContext,
    envelope: &[u8],
) -> Result<DecodedPoseidon2ProductionEnvelope<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_smz9_envelope_exact(envelope)?.ensure_context(expected)
}

/// Construct historical SMZ8 SCALE args for rejection tests only.
pub fn encode_historical_poseidon2_v8_smz8_inline_args(
    expected: Poseidon2ProductionExpectedContext,
    envelope: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    encode_poseidon2_production_inline_args_with_profile(
        POSEIDON2_PRODUCTION_SMZ8_WIRE_PROFILE,
        expected,
        envelope,
    )
}

pub fn encode_poseidon2_production_smz9_inline_args(
    expected: Poseidon2ProductionExpectedContext,
    envelope: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    encode_poseidon2_production_inline_args_with_profile(
        POSEIDON2_PRODUCTION_SMZ9_WIRE_PROFILE,
        expected,
        envelope,
    )
}

fn encode_poseidon2_production_inline_args_with_profile(
    wire: Poseidon2ProductionWireProfile,
    expected: Poseidon2ProductionExpectedContext,
    envelope: &[u8],
) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_envelope_with_profile_exact(envelope, wire)?
        .ensure_context(expected)?;
    let prefix_len = compact_u32_encoded_len(envelope.len());
    let total_len = prefix_len
        .checked_add(envelope.len())
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
    if total_len > wire.max_action_bytes {
        return Err(Poseidon2ProductionTransportError::ActionBytesTooLarge {
            observed: total_len,
            maximum: wire.max_action_bytes,
        });
    }
    let mut action = Vec::new();
    action
        .try_reserve_exact(total_len)
        .map_err(|_| Poseidon2ProductionTransportError::AllocationFailed(total_len))?;
    encode_compact_u32(envelope.len() as u32, &mut action);
    action.extend_from_slice(envelope);
    Ok(action)
}

/// Parse historical SMZ8 SCALE args for migration and rejection tests only.
pub fn preflight_historical_poseidon2_v8_smz8_inline_args_exact(
    encoded: &[u8],
) -> Result<DecodedPoseidon2ProductionInlineArgs<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_inline_args_with_profile_exact(
        encoded,
        POSEIDON2_PRODUCTION_SMZ8_WIRE_PROFILE,
    )
}

pub fn preflight_poseidon2_production_smz9_inline_args_exact(
    encoded: &[u8],
) -> Result<DecodedPoseidon2ProductionInlineArgs<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_inline_args_with_profile_exact(
        encoded,
        POSEIDON2_PRODUCTION_SMZ9_WIRE_PROFILE,
    )
}

fn preflight_poseidon2_production_inline_args_with_profile_exact(
    encoded: &[u8],
    wire: Poseidon2ProductionWireProfile,
) -> Result<DecodedPoseidon2ProductionInlineArgs<'_>, Poseidon2ProductionTransportError> {
    if encoded.len() > wire.max_action_bytes {
        return Err(Poseidon2ProductionTransportError::ActionBytesTooLarge {
            observed: encoded.len(),
            maximum: wire.max_action_bytes,
        });
    }
    let (declared_len, payload_offset) = decode_compact_u32(encoded)?;
    let declared_len = usize::try_from(declared_len)
        .map_err(|_| Poseidon2ProductionTransportError::CompactLengthOverflow)?;
    if declared_len > wire.max_envelope_bytes {
        return Err(Poseidon2ProductionTransportError::EnvelopeTooLarge {
            observed: declared_len,
            maximum: wire.max_envelope_bytes,
        });
    }
    let payload_end = payload_offset
        .checked_add(declared_len)
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
    if encoded.len() < payload_end {
        return Err(Poseidon2ProductionTransportError::Truncated {
            declared: payload_end,
            observed: encoded.len(),
        });
    }
    if encoded.len() > payload_end {
        return Err(Poseidon2ProductionTransportError::TrailingBytes {
            trailing: encoded.len() - payload_end,
        });
    }
    let envelope = preflight_poseidon2_production_envelope_with_profile_exact(
        &encoded[payload_offset..payload_end],
        wire,
    )?;
    Ok(DecodedPoseidon2ProductionInlineArgs {
        raw: encoded,
        envelope,
    })
}

/// Decode historical SMZ8 SCALE args for migration and rejection tests only.
pub fn decode_historical_poseidon2_v8_smz8_inline_args_exact(
    expected: Poseidon2ProductionExpectedContext,
    encoded: &[u8],
) -> Result<DecodedPoseidon2ProductionInlineArgs<'_>, Poseidon2ProductionTransportError> {
    preflight_historical_poseidon2_v8_smz8_inline_args_exact(encoded)?.ensure_context(expected)
}

pub fn decode_poseidon2_production_smz9_inline_args_exact(
    expected: Poseidon2ProductionExpectedContext,
    encoded: &[u8],
) -> Result<DecodedPoseidon2ProductionInlineArgs<'_>, Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_smz9_inline_args_exact(encoded)?.ensure_context(expected)
}

/// Compare historical SMZ8 lifecycle bytes for rejection tests only.
pub fn ensure_historical_poseidon2_v8_smz8_stage_bytes(
    expected: Poseidon2ProductionExpectedContext,
    canonical_envelope: &[u8],
    observed_action_args: &[u8],
    stage: Poseidon2ProductionTransportStage,
) -> Result<(), Poseidon2ProductionTransportError> {
    ensure_poseidon2_production_stage_bytes_with_profile(
        POSEIDON2_PRODUCTION_SMZ8_WIRE_PROFILE,
        expected,
        canonical_envelope,
        observed_action_args,
        stage,
    )
}

pub fn ensure_poseidon2_production_smz9_stage_bytes(
    expected: Poseidon2ProductionExpectedContext,
    canonical_envelope: &[u8],
    observed_action_args: &[u8],
    stage: Poseidon2ProductionTransportStage,
) -> Result<(), Poseidon2ProductionTransportError> {
    ensure_poseidon2_production_stage_bytes_with_profile(
        POSEIDON2_PRODUCTION_SMZ9_WIRE_PROFILE,
        expected,
        canonical_envelope,
        observed_action_args,
        stage,
    )
}

fn ensure_poseidon2_production_stage_bytes_with_profile(
    wire: Poseidon2ProductionWireProfile,
    expected: Poseidon2ProductionExpectedContext,
    canonical_envelope: &[u8],
    observed_action_args: &[u8],
    stage: Poseidon2ProductionTransportStage,
) -> Result<(), Poseidon2ProductionTransportError> {
    preflight_poseidon2_production_envelope_with_profile_exact(canonical_envelope, wire)?
        .ensure_context(expected)?;
    let observed =
        preflight_poseidon2_production_inline_args_with_profile_exact(observed_action_args, wire)?
            .ensure_context(expected)?;
    if observed.envelope.raw == canonical_envelope {
        return Ok(());
    }
    let observed_envelope = observed.envelope.raw;
    let first_difference = canonical_envelope
        .iter()
        .zip(observed_envelope)
        .position(|(expected, observed)| expected != observed)
        .or_else(|| {
            (canonical_envelope.len() != observed_envelope.len())
                .then_some(canonical_envelope.len().min(observed_envelope.len()))
        });
    Err(Poseidon2ProductionTransportError::StageMismatch {
        stage,
        expected: canonical_envelope.len(),
        observed: observed_envelope.len(),
        first_difference,
    })
}

fn validate_route_fields(
    bytes: &[u8],
    native_leaf: bool,
    wire: Poseidon2ProductionWireProfile,
) -> Result<(), Poseidon2ProductionTransportError> {
    let offsets = if native_leaf {
        (
            LEAF_OFFSET_CIRCUIT,
            LEAF_OFFSET_CRYPTO_SUITE,
            LEAF_OFFSET_FAMILY,
            LEAF_OFFSET_ACTION,
            LEAF_OFFSET_BACKEND,
            LEAF_OFFSET_PROFILE,
            LEAF_OFFSET_DOMAIN_SET,
        )
    } else {
        (
            TRANSPORT_OFFSET_CIRCUIT,
            TRANSPORT_OFFSET_CRYPTO_SUITE,
            TRANSPORT_OFFSET_FAMILY,
            TRANSPORT_OFFSET_ACTION,
            TRANSPORT_OFFSET_BACKEND,
            TRANSPORT_OFFSET_PROFILE,
            TRANSPORT_OFFSET_DOMAIN_SET,
        )
    };
    expect_u16(
        bytes,
        offsets.0,
        POSEIDON2_PRODUCTION_TRANSPORT_CIRCUIT,
        Poseidon2ProductionTransportError::UnsupportedCircuit,
    )?;
    expect_u16(
        bytes,
        offsets.1,
        POSEIDON2_PRODUCTION_TRANSPORT_CRYPTO_SUITE,
        Poseidon2ProductionTransportError::UnsupportedCryptoSuite,
    )?;
    expect_u16(
        bytes,
        offsets.2,
        POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID,
        Poseidon2ProductionTransportError::UnsupportedFamily,
    )?;
    expect_u16(
        bytes,
        offsets.3,
        POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID,
        Poseidon2ProductionTransportError::UnsupportedAction,
    )?;
    if bytes[offsets.4] != POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID {
        return Err(Poseidon2ProductionTransportError::UnsupportedBackend(
            bytes[offsets.4],
        ));
    }
    if bytes[offsets.5] != wire.profile_id {
        return Err(Poseidon2ProductionTransportError::UnsupportedProfile(
            bytes[offsets.5],
        ));
    }
    expect_u16(
        bytes,
        offsets.6,
        wire.domain_set,
        Poseidon2ProductionTransportError::UnsupportedDomainSet,
    )
}

fn expect_u16(
    bytes: &[u8],
    offset: usize,
    expected: u16,
    error: fn(u16) -> Poseidon2ProductionTransportError,
) -> Result<(), Poseidon2ProductionTransportError> {
    let observed = read_u16_le(bytes, offset);
    if observed != expected {
        return Err(error(observed));
    }
    Ok(())
}

fn validate_proof(
    proof: &[u8],
    active_outputs: usize,
    wire: Poseidon2ProductionWireProfile,
) -> Result<(), Poseidon2ProductionTransportError> {
    validate_hard_proof_len(proof.len(), wire)?;
    validate_routed_proof_len(proof.len(), active_outputs, wire)?;
    if proof.len() < wire.inner_proof_magic.len() {
        return Err(Poseidon2ProductionTransportError::InnerProofTooShort(
            proof.len(),
        ));
    }
    let magic = proof[..4].try_into().expect("four-byte proof magic");
    if magic != wire.inner_proof_magic {
        return Err(Poseidon2ProductionTransportError::UnsupportedInnerProofMagic(magic));
    }
    Ok(())
}

fn validate_hard_proof_len(
    proof_len: usize,
    wire: Poseidon2ProductionWireProfile,
) -> Result<(), Poseidon2ProductionTransportError> {
    if proof_len == 0 {
        return Err(Poseidon2ProductionTransportError::EmptyProof);
    }
    if proof_len > wire.max_proof_bytes {
        return Err(Poseidon2ProductionTransportError::ProofTooLarge {
            observed: proof_len,
            maximum: wire.max_proof_bytes,
        });
    }
    Ok(())
}

fn validate_routed_proof_len(
    proof_len: usize,
    active_outputs: usize,
    wire: Poseidon2ProductionWireProfile,
) -> Result<(), Poseidon2ProductionTransportError> {
    let overhead = poseidon2_production_action_overhead_bytes(active_outputs)
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
    let maximum = wire
        .max_action_bytes
        .checked_sub(overhead)
        .ok_or(Poseidon2ProductionTransportError::LengthOverflow)?;
    if proof_len > maximum {
        return Err(
            Poseidon2ProductionTransportError::ProofExceedsInlineBudget {
                observed: proof_len,
                maximum,
            },
        );
    }
    Ok(())
}

fn output_activity(
    public_statement: &[u64; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS],
) -> Result<[bool; POSEIDON2_PRODUCTION_MAX_OUTPUTS], Poseidon2ProductionTransportError> {
    let mut active = [false; POSEIDON2_PRODUCTION_MAX_OUTPUTS];
    for (output_slot, is_active) in active.iter_mut().enumerate() {
        let value = public_statement[POSEIDON2_PRODUCTION_OUTPUT_FLAG_WORD + output_slot];
        *is_active = match value {
            0 => false,
            1 => true,
            _ => {
                return Err(Poseidon2ProductionTransportError::NonBooleanOutputFlag {
                    output_slot,
                    value,
                })
            }
        };
    }
    Ok(active)
}

fn validate_ciphertext_bindings(
    public_statement: &[u64; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS],
    ciphertexts: [Option<&[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]>;
        POSEIDON2_PRODUCTION_MAX_OUTPUTS],
) -> Result<usize, Poseidon2ProductionTransportError> {
    let active = output_activity(public_statement)?;
    for output_slot in 0..POSEIDON2_PRODUCTION_MAX_OUTPUTS {
        let present = ciphertexts[output_slot].is_some();
        if active[output_slot] != present {
            return Err(
                Poseidon2ProductionTransportError::CiphertextPresenceMismatch {
                    output_slot,
                    active: active[output_slot],
                    present,
                },
            );
        }
        let hash_start = POSEIDON2_PRODUCTION_CIPHERTEXT_HASH_WORD
            + output_slot * POSEIDON2_PRODUCTION_CIPHERTEXT_HASH_LIMBS;
        if let Some(ciphertext) = ciphertexts[output_slot] {
            let digest = ciphertext_hash_bytes(ciphertext);
            let matches = digest.chunks_exact(8).enumerate().all(|(limb, bytes)| {
                public_statement[hash_start + limb]
                    == u64::from_be_bytes(bytes.try_into().expect("eight-byte digest limb"))
            });
            if !matches {
                return Err(Poseidon2ProductionTransportError::CiphertextHashMismatch {
                    output_slot,
                });
            }
        } else {
            for limb in 0..POSEIDON2_PRODUCTION_CIPHERTEXT_HASH_LIMBS {
                let value = public_statement[hash_start + limb];
                if value != 0 {
                    return Err(
                        Poseidon2ProductionTransportError::InactiveCiphertextHashNonZero {
                            output_slot,
                            limb,
                            value,
                        },
                    );
                }
            }
        }
    }
    Ok(active.iter().filter(|is_active| **is_active).count())
}

fn validate_native_leaf_len(
    native_leaf_len: usize,
    wire: Poseidon2ProductionWireProfile,
) -> Result<(), Poseidon2ProductionTransportError> {
    if native_leaf_len > wire.max_native_leaf_bytes {
        return Err(Poseidon2ProductionTransportError::NativeLeafTooLarge {
            observed: native_leaf_len,
            maximum: wire.max_native_leaf_bytes,
        });
    }
    if native_leaf_len > wire.max_routed_native_leaf_bytes {
        return Err(
            Poseidon2ProductionTransportError::NativeLeafExceedsInlineBudget {
                observed: native_leaf_len,
                maximum: wire.max_routed_native_leaf_bytes,
            },
        );
    }
    Ok(())
}

fn validate_field_words<const N: usize>(
    section: &'static str,
    words: &[u64; N],
) -> Result<(), Poseidon2ProductionTransportError> {
    for (index, value) in words.iter().copied().enumerate() {
        if value >= POSEIDON2_PRODUCTION_GOLDILOCKS_MODULUS {
            return Err(Poseidon2ProductionTransportError::NonCanonicalFieldWord {
                section,
                index,
                value,
            });
        }
    }
    Ok(())
}

fn validate_encoded_field_words<const N: usize>(
    section: &'static str,
    bytes: &[u8; N],
) -> Result<(), Poseidon2ProductionTransportError> {
    debug_assert_eq!(N % POSEIDON2_PRODUCTION_FIELD_WORD_BYTES, 0);
    for (index, chunk) in bytes
        .chunks_exact(POSEIDON2_PRODUCTION_FIELD_WORD_BYTES)
        .enumerate()
    {
        let value = u64::from_le_bytes(chunk.try_into().expect("eight-byte field word"));
        if value >= POSEIDON2_PRODUCTION_GOLDILOCKS_MODULUS {
            return Err(Poseidon2ProductionTransportError::NonCanonicalFieldWord {
                section,
                index,
                value,
            });
        }
    }
    Ok(())
}

fn read_field_word(bytes: &[u8], index: usize) -> Option<u64> {
    let offset = index.checked_mul(POSEIDON2_PRODUCTION_FIELD_WORD_BYTES)?;
    let end = offset.checked_add(POSEIDON2_PRODUCTION_FIELD_WORD_BYTES)?;
    Some(u64::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("fixed header was checked")
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(read_array(bytes, offset))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(read_array(bytes, offset))
}

const fn compact_u32_encoded_len(value: usize) -> usize {
    if value < 1 << 6 {
        1
    } else if value < 1 << 14 {
        2
    } else if value < 1 << 30 {
        4
    } else {
        5
    }
}

fn encode_compact_u32(value: u32, output: &mut Vec<u8>) {
    match value {
        value if value < 1 << 6 => output.push((value as u8) << 2),
        value if value < 1 << 14 => {
            let encoded = ((value << 2) | 1) as u16;
            output.extend_from_slice(&encoded.to_le_bytes());
        }
        value if value < 1 << 30 => {
            let encoded = (value << 2) | 2;
            output.extend_from_slice(&encoded.to_le_bytes());
        }
        value => {
            output.push(0b11);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn decode_compact_u32(encoded: &[u8]) -> Result<(u32, usize), Poseidon2ProductionTransportError> {
    let first = *encoded
        .first()
        .ok_or(Poseidon2ProductionTransportError::CompactLengthTruncated)?;
    match first & 0b11 {
        0 => Ok(((first >> 2) as u32, 1)),
        1 => {
            if encoded.len() < 2 {
                return Err(Poseidon2ProductionTransportError::CompactLengthTruncated);
            }
            let value = u16::from_le_bytes([encoded[0], encoded[1]]) >> 2;
            if value < 1 << 6 {
                return Err(Poseidon2ProductionTransportError::NonCanonicalCompactLength);
            }
            Ok((u32::from(value), 2))
        }
        2 => {
            if encoded.len() < 4 {
                return Err(Poseidon2ProductionTransportError::CompactLengthTruncated);
            }
            let value = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) >> 2;
            if value < 1 << 14 {
                return Err(Poseidon2ProductionTransportError::NonCanonicalCompactLength);
            }
            Ok((value, 4))
        }
        3 => {
            let byte_count = usize::from(first >> 2) + 4;
            if byte_count > 4 {
                return Err(Poseidon2ProductionTransportError::CompactLengthOverflow);
            }
            let encoded_len = byte_count
                .checked_add(1)
                .ok_or(Poseidon2ProductionTransportError::CompactLengthOverflow)?;
            if encoded.len() < encoded_len {
                return Err(Poseidon2ProductionTransportError::CompactLengthTruncated);
            }
            let mut bytes = [0u8; 4];
            bytes[..byte_count].copy_from_slice(&encoded[1..encoded_len]);
            let value = u32::from_le_bytes(bytes);
            if value < 1 << 30 {
                return Err(Poseidon2ProductionTransportError::NonCanonicalCompactLength);
            }
            Ok((value, encoded_len))
        }
        _ => unreachable!("two-bit SCALE mode is exhaustive"),
    }
}

const _: [(); 4] = [(); compact_u32_encoded_len(POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES)];
const _: [(); 4] = [(); compact_u32_encoded_len(POSEIDON2_PRODUCTION_SMZA_MAX_ENVELOPE_BYTES)];
const _: [(); POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES] = [();
    POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES + POSEIDON2_PRODUCTION_MAX_INLINE_NON_PROOF_BYTES];
const _: [(); POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES] =
    [(); POSEIDON2_PRODUCTION_SMZA_MAX_ENVELOPE_BYTES + POSEIDON2_PRODUCTION_SCALE_PREFIX_BYTES];
const _: [(); POSEIDON2_PRODUCTION_SMZA_MAX_ENVELOPE_BYTES] = [();
    POSEIDON2_PRODUCTION_SMZA_MAX_ROUTED_NATIVE_LEAF_BYTES
        + POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES];
const _: [(); POSEIDON2_PRODUCTION_TRANSPORT_CIRCUIT as usize] =
    [(); SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.circuit as usize];
const _: [(); POSEIDON2_PRODUCTION_TRANSPORT_CRYPTO_SUITE as usize] =
    [(); SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.crypto as usize];
const _: [(); POSEIDON2_PRODUCTION_NATIVE_LEAF_FIXED_BYTES] = [(); 1_104];
const _: [(); POSEIDON2_PRODUCTION_TOTAL_OVERHEAD_BYTES] = [(); 1_140];
const _: [(); POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES] = [(); 2_147];
const _: [(); POSEIDON2_PRODUCTION_MAX_INLINE_NON_PROOF_BYTES] = [(); 5_434];
const _: [(); POSEIDON2_PRODUCTION_MAX_ROUTED_PROOF_BYTES_AT_MAX_OUTPUTS] = [(); 125_638];
const _: [(); POSEIDON2_PRODUCTION_CONSERVATIVE_SCREEN_ACTION_BYTES] = [(); 129_498];

#[cfg(test)]
mod tests {
    use super::*;
    // Test-local compatibility spellings only. The public SMZ8 construction
    // API is explicitly historical and cannot be mistaken for the live path.
    use super::{
        decode_historical_poseidon2_v8_smz8_inline_args_exact as historical_smz8_decode_inline_args_fixture,
        decode_historical_poseidon2_v8_smz8_native_leaf_exact as historical_smz8_decode_native_leaf_fixture,
        encode_historical_poseidon2_v8_smz8_envelope as historical_smz8_envelope_fixture,
        encode_historical_poseidon2_v8_smz8_inline_args as historical_smz8_inline_args_fixture,
        encode_historical_poseidon2_v8_smz8_native_leaf as historical_smz8_native_leaf_fixture,
        ensure_historical_poseidon2_v8_smz8_stage_bytes as historical_smz8_ensure_stage_fixture,
        preflight_historical_poseidon2_v8_smz8_inline_args_exact as historical_smz8_preflight_inline_args_fixture,
        preflight_historical_poseidon2_v8_smz8_native_leaf_exact as historical_smz8_preflight_native_leaf_fixture,
    };
    use crate::inactive_smallwood_v7::{
        INACTIVE_SMALLWOOD_V7_ACTION_ID, INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION,
        INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA, INACTIVE_SMALLWOOD_V7_ENVELOPE_MAGIC,
    };
    use protocol_versioning::smallwood_poseidon2_production_authorized;

    fn context() -> Poseidon2ProductionExpectedContext {
        Poseidon2ProductionExpectedContext::new(17, [0x42; 48]).unwrap()
    }

    fn statement() -> [u64; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS] {
        let mut statement = [0; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS];
        statement[119] = 119;
        statement
    }

    fn ciphertexts() -> [[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]; 2] {
        [
            [0x41; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
            [0x42; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
        ]
    }

    fn statement_with_outputs(
        ciphertexts: &[[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]; 2],
        active_outputs: usize,
    ) -> [u64; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS] {
        assert!(active_outputs <= POSEIDON2_PRODUCTION_MAX_OUTPUTS);
        statement_with_output_mask(ciphertexts, (1u8 << active_outputs) - 1)
    }

    fn statement_with_output_mask(
        ciphertexts: &[[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]; 2],
        output_mask: u8,
    ) -> [u64; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS] {
        assert!(output_mask < 1 << POSEIDON2_PRODUCTION_MAX_OUTPUTS);
        let mut statement = statement();
        for output_slot in 0..POSEIDON2_PRODUCTION_MAX_OUTPUTS {
            if output_mask & (1 << output_slot) == 0 {
                continue;
            }
            statement[POSEIDON2_PRODUCTION_OUTPUT_FLAG_WORD + output_slot] = 1;
            let digest = ciphertext_hash_bytes(&ciphertexts[output_slot]);
            let hash_start = POSEIDON2_PRODUCTION_CIPHERTEXT_HASH_WORD
                + output_slot * POSEIDON2_PRODUCTION_CIPHERTEXT_HASH_LIMBS;
            for (limb, bytes) in digest.chunks_exact(8).enumerate() {
                statement[hash_start + limb] =
                    u64::from_be_bytes(bytes.try_into().expect("eight-byte digest limb"));
            }
        }
        statement
    }

    fn binding() -> [u64; POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS] {
        core::array::from_fn(|index| 1_000 + index as u64)
    }

    fn proof(len: usize) -> Vec<u8> {
        assert!(len >= 4);
        let mut proof = vec![0xa5; len];
        proof[..4].copy_from_slice(&POSEIDON2_PRODUCTION_INNER_PROOF_MAGIC);
        proof
    }

    fn smz9_proof(len: usize) -> Vec<u8> {
        assert!(len >= 4);
        let mut proof = vec![0xb6; len];
        proof[..4].copy_from_slice(&POSEIDON2_PRODUCTION_SMZ9_INNER_PROOF_MAGIC);
        proof
    }

    fn leaf(proof_len: usize) -> Vec<u8> {
        historical_smz8_native_leaf_fixture(
            context(),
            &statement(),
            &binding(),
            [None, None],
            &proof(proof_len),
        )
        .unwrap()
    }

    fn leaf_with_outputs(proof_len: usize, active_outputs: usize) -> Vec<u8> {
        let ciphertexts = ciphertexts();
        let statement = statement_with_outputs(&ciphertexts, active_outputs);
        let ciphertext_refs = [
            (active_outputs > 0).then_some(&ciphertexts[0]),
            (active_outputs > 1).then_some(&ciphertexts[1]),
        ];
        historical_smz8_native_leaf_fixture(
            context(),
            &statement,
            &binding(),
            ciphertext_refs,
            &proof(proof_len),
        )
        .unwrap()
    }

    fn leaf_with_output_mask(proof_len: usize, output_mask: u8) -> Vec<u8> {
        let ciphertexts = ciphertexts();
        let statement = statement_with_output_mask(&ciphertexts, output_mask);
        let ciphertext_refs = [
            (output_mask & 1 != 0).then_some(&ciphertexts[0]),
            (output_mask & 2 != 0).then_some(&ciphertexts[1]),
        ];
        historical_smz8_native_leaf_fixture(
            context(),
            &statement,
            &binding(),
            ciphertext_refs,
            &proof(proof_len),
        )
        .unwrap()
    }

    fn envelope_with_outputs(proof_len: usize, active_outputs: usize) -> Vec<u8> {
        historical_smz8_envelope_fixture(context(), &leaf_with_outputs(proof_len, active_outputs))
            .unwrap()
    }

    #[test]
    fn poseidon2_production_transport_identity_is_fresh_smz8_only_and_inactive() {
        assert_eq!(POSEIDON2_PRODUCTION_TRANSPORT_CIRCUIT, 8);
        assert_eq!(POSEIDON2_PRODUCTION_TRANSPORT_CRYPTO_SUITE, 7);
        assert_eq!(POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID, 10);
        assert_eq!(POSEIDON2_PRODUCTION_TRANSPORT_MAGIC, *b"SWP8LC01");
        assert_eq!(POSEIDON2_PRODUCTION_NATIVE_LEAF_MAGIC, *b"HGV8TX01");
        assert_eq!(POSEIDON2_PRODUCTION_INNER_PROOF_MAGIC, *b"SMZ8");
        for legacy in [b"SMZ1", b"SMZ2", b"SWV5", b"SWV6"] {
            assert_ne!(&POSEIDON2_PRODUCTION_INNER_PROOF_MAGIC, legacy);
        }
        assert_ne!(
            POSEIDON2_PRODUCTION_TRANSPORT_MAGIC,
            INACTIVE_SMALLWOOD_V7_ENVELOPE_MAGIC
        );
        assert_ne!(
            POSEIDON2_PRODUCTION_TRANSPORT_CIRCUIT,
            INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION
        );
        assert_ne!(
            POSEIDON2_PRODUCTION_TRANSPORT_CRYPTO_SUITE,
            INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA
        );
        assert_ne!(
            POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID,
            INACTIVE_SMALLWOOD_V7_ACTION_ID
        );
        assert!(!smallwood_poseidon2_production_authorized());
    }

    #[test]
    fn poseidon2_production_transport_roundtrip_preserves_exact_smz8_proof() {
        let proof = proof(211);
        let ciphertexts = ciphertexts();
        let statement = statement_with_outputs(&ciphertexts, 2);
        let leaf = historical_smz8_native_leaf_fixture(
            context(),
            &statement,
            &binding(),
            [Some(&ciphertexts[0]), Some(&ciphertexts[1])],
            &proof,
        )
        .unwrap();
        let decoded_leaf = historical_smz8_decode_native_leaf_fixture(context(), &leaf).unwrap();
        assert_eq!(decoded_leaf.raw(), leaf.as_slice());
        assert_eq!(decoded_leaf.proof(), proof.as_slice());
        assert_eq!(decoded_leaf.active_output_count(), 2);
        assert_eq!(decoded_leaf.ciphertext(0), Some(&ciphertexts[0]));
        assert_eq!(decoded_leaf.ciphertext(1), Some(&ciphertexts[1]));
        assert_eq!(decoded_leaf.statement_word(119), Some(119));
        assert_eq!(decoded_leaf.relation_balance_binding_limb(6), Some(1_006));
        let envelope = historical_smz8_envelope_fixture(context(), &leaf).unwrap();
        let action = historical_smz8_inline_args_fixture(context(), &envelope).unwrap();
        let decoded = historical_smz8_decode_inline_args_fixture(context(), &action).unwrap();
        assert_eq!(decoded.raw(), action.as_slice());
        assert_eq!(decoded.envelope().raw(), envelope.as_slice());
        assert_eq!(decoded.envelope().native_leaf(), leaf.as_slice());
        assert_eq!(
            decoded.envelope().decoded_native_leaf().proof(),
            proof.as_slice()
        );
    }

    #[test]
    fn smza_framing_roundtrip_maximum_all_activity_masks() {
        // Fake proof bytes exercise transport only, never cryptographic verification.
        let mut proof = vec![0xa7; POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES];
        proof[..4].copy_from_slice(b"SMZA");
        let ciphertexts = ciphertexts();
        for mask in 0u8..4 {
            let statement = statement_with_output_mask(&ciphertexts, mask);
            let outputs = core::array::from_fn(|slot| {
                (mask & (1 << slot) != 0).then_some(&ciphertexts[slot])
            });
            let leaf = encode_poseidon2_production_smza_native_leaf(
                context(),
                &statement,
                &binding(),
                outputs,
                &proof,
            )
            .unwrap();
            let envelope = encode_poseidon2_production_smza_envelope(context(), &leaf).unwrap();
            let action =
                encode_poseidon2_production_smza_inline_args(context(), &envelope).unwrap();
            let decoded =
                decode_poseidon2_production_smza_inline_args_exact(context(), &action).unwrap();
            assert_eq!(decoded.envelope().decoded_native_leaf().proof(), proof);
            assert_eq!(decoded.envelope().native_leaf(), leaf);
            assert_eq!(
                action.len(),
                164_113 + 1_140 + mask.count_ones() as usize * 2_147
            );
            if mask == 3 {
                assert_eq!(leaf.len(), 169_511);
                assert_eq!(envelope.len(), 169_543);
                assert_eq!(action.len(), 169_547);
            }
            ensure_poseidon2_production_smza_stage_bytes(
                context(),
                &envelope,
                &action,
                Poseidon2ProductionTransportStage::FreshNodeVerify,
            )
            .unwrap();
            let mut over_proof = proof.clone();
            over_proof.push(0);
            assert!(matches!(
                encode_poseidon2_production_smza_native_leaf(
                    context(),
                    &statement,
                    &binding(),
                    outputs,
                    &over_proof,
                ),
                Err(Poseidon2ProductionTransportError::ProofTooLarge {
                    maximum: 164_113,
                    ..
                })
            ));
        }
        assert_eq!(POSEIDON2_PRODUCTION_MAX_ACTION_BYTES, 131_072);
        assert_eq!(poseidon2_production_smza_max_routed_proof_bytes(3), None);
    }

    #[test]
    fn smza_framing_rejects_cross_profile_context_and_noncanonical_fields() {
        let mut proof = smz9_proof(211);
        proof[..4].copy_from_slice(b"SMZA");
        let ciphertexts = ciphertexts();
        let statement = statement_with_outputs(&ciphertexts, 2);
        let leaf = encode_poseidon2_production_smza_native_leaf(
            context(),
            &statement,
            &binding(),
            [Some(&ciphertexts[0]), Some(&ciphertexts[1])],
            &proof,
        )
        .unwrap();
        let envelope = encode_poseidon2_production_smza_envelope(context(), &leaf).unwrap();
        let action = encode_poseidon2_production_smza_inline_args(context(), &envelope).unwrap();
        assert!(decode_poseidon2_production_smz9_native_leaf_exact(context(), &leaf).is_err());
        assert!(decode_poseidon2_production_smz9_envelope_exact(context(), &envelope).is_err());
        assert!(decode_poseidon2_production_smz9_inline_args_exact(context(), &action).is_err());
        assert!(decode_historical_poseidon2_v8_smz8_inline_args_exact(context(), &action).is_err());
        for old_wire in [
            POSEIDON2_PRODUCTION_SMZ8_WIRE_PROFILE,
            POSEIDON2_PRODUCTION_SMZ9_WIRE_PROFILE,
        ] {
            let mut old_proof = proof.clone();
            old_proof[..4].copy_from_slice(&old_wire.inner_proof_magic);
            let old_leaf = encode_poseidon2_production_native_leaf_with_profile(
                old_wire,
                context(),
                &statement,
                &binding(),
                [Some(&ciphertexts[0]), Some(&ciphertexts[1])],
                &old_proof,
            )
            .unwrap();
            let old_envelope =
                encode_poseidon2_production_envelope_with_profile(old_wire, context(), &old_leaf)
                    .unwrap();
            let old_action = encode_poseidon2_production_inline_args_with_profile(
                old_wire,
                context(),
                &old_envelope,
            )
            .unwrap();
            assert!(preflight_poseidon2_production_smza_native_leaf_exact(&old_leaf).is_err());
            assert!(preflight_poseidon2_production_smza_envelope_exact(&old_envelope).is_err());
            assert!(preflight_poseidon2_production_smza_inline_args_exact(&old_action).is_err());
            assert!(encode_poseidon2_production_smza_envelope(context(), &old_leaf).is_err());
        }
        for offset in [
            0,
            LEAF_OFFSET_PROFILE,
            LEAF_OFFSET_DOMAIN_SET,
            LEAF_OFFSET_RESERVED,
            LEAF_OFFSET_CIPHERTEXTS,
            leaf.len() - proof.len(),
        ] {
            let mut bad = leaf.clone();
            bad[offset] ^= 1;
            assert!(
                preflight_poseidon2_production_smza_native_leaf_exact(&bad).is_err(),
                "offset {offset}"
            );
        }
        for offset in [
            0,
            TRANSPORT_OFFSET_PROFILE,
            TRANSPORT_OFFSET_DOMAIN_SET,
            POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES + LEAF_OFFSET_PROFILE,
        ] {
            let mut bad = envelope.clone();
            bad[offset] ^= 1;
            assert!(preflight_poseidon2_production_smza_envelope_exact(&bad).is_err());
        }
        let mut bad_field = leaf.clone();
        bad_field[LEAF_OFFSET_STATEMENT..LEAF_OFFSET_STATEMENT + 8]
            .copy_from_slice(&POSEIDON2_PRODUCTION_GOLDILOCKS_MODULUS.to_le_bytes());
        assert!(preflight_poseidon2_production_smza_native_leaf_exact(&bad_field).is_err());
        for wrong in [
            Poseidon2ProductionExpectedContext::new(18, [0x42; 48]).unwrap(),
            Poseidon2ProductionExpectedContext::new(17, [0x43; 48]).unwrap(),
        ] {
            assert!(decode_poseidon2_production_smza_inline_args_exact(wrong, &action).is_err());
        }
    }

    #[test]
    fn smza_framing_rejects_actual_and_declared_caps_before_payload() {
        assert!(matches!(
            preflight_poseidon2_production_smza_native_leaf_exact(&vec![0; 169_512]),
            Err(Poseidon2ProductionTransportError::NativeLeafTooLarge { .. })
        ));
        assert!(matches!(
            preflight_poseidon2_production_smza_envelope_exact(&vec![0; 169_544]),
            Err(Poseidon2ProductionTransportError::EnvelopeTooLarge { .. })
        ));
        assert!(matches!(
            preflight_poseidon2_production_smza_inline_args_exact(&vec![0; 169_548]),
            Err(Poseidon2ProductionTransportError::ActionBytesTooLarge { .. })
        ));
        let mut prefix = Vec::new();
        encode_compact_u32(169_544, &mut prefix);
        assert!(matches!(
            preflight_poseidon2_production_smza_inline_args_exact(&prefix),
            Err(Poseidon2ProductionTransportError::EnvelopeTooLarge { .. })
        ));
        let leaf = encode_poseidon2_production_smza_native_leaf(
            context(),
            &statement(),
            &binding(),
            [None, None],
            b"SMZA",
        )
        .unwrap();
        let mut leaf_header = leaf[..POSEIDON2_PRODUCTION_NATIVE_LEAF_HEADER_BYTES].to_vec();
        leaf_header[LEAF_OFFSET_PROOF_LEN..LEAF_OFFSET_PROOF_LEN + 4]
            .copy_from_slice(&164_114u32.to_le_bytes());
        assert!(matches!(
            preflight_poseidon2_production_smza_native_leaf_exact(&leaf_header),
            Err(Poseidon2ProductionTransportError::ProofTooLarge { .. })
        ));
        let envelope = encode_poseidon2_production_smza_envelope(context(), &leaf).unwrap();
        let mut header = envelope[..POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES].to_vec();
        header[TRANSPORT_OFFSET_NATIVE_LEAF_LEN..TRANSPORT_OFFSET_NATIVE_LEAF_LEN + 4]
            .copy_from_slice(&169_512u32.to_le_bytes());
        assert!(matches!(
            preflight_poseidon2_production_smza_envelope_exact(&header),
            Err(Poseidon2ProductionTransportError::NativeLeafTooLarge { .. })
        ));
    }

    #[test]
    fn smz9_profile6_roundtrip_is_additive_exact_and_rejects_smz8_everywhere() {
        const PROJECTED_SMZ9_PROOF_BYTES: usize = 122_863;
        const PROJECTED_SMZ9_ACTION_BYTES: usize = 128_297;
        let smz9_bytes = smz9_proof(PROJECTED_SMZ9_PROOF_BYTES);
        let ciphertexts = ciphertexts();
        let statement = statement_with_outputs(&ciphertexts, 2);
        let leaf = encode_poseidon2_production_smz9_native_leaf(
            context(),
            &statement,
            &binding(),
            [Some(&ciphertexts[0]), Some(&ciphertexts[1])],
            &smz9_bytes,
        )
        .expect("encode exact SMZ9 native leaf");
        assert_eq!(&leaf[..8], b"HGV8TX02");
        assert_eq!(leaf[LEAF_OFFSET_PROFILE], 6);
        let decoded_leaf = decode_poseidon2_production_smz9_native_leaf_exact(context(), &leaf)
            .expect("decode exact SMZ9 native leaf");
        assert_eq!(decoded_leaf.raw(), leaf.as_slice());
        assert_eq!(decoded_leaf.proof(), smz9_bytes.as_slice());
        assert!(historical_smz8_decode_native_leaf_fixture(context(), &leaf).is_err());

        let envelope = encode_poseidon2_production_smz9_envelope(context(), &leaf)
            .expect("encode exact SMZ9 envelope");
        assert_eq!(&envelope[..8], b"SWP8LC02");
        assert_eq!(envelope[TRANSPORT_OFFSET_PROFILE], 6);
        let action = encode_poseidon2_production_smz9_inline_args(context(), &envelope)
            .expect("encode exact SMZ9 SCALE action");
        assert_eq!(leaf.len(), PROJECTED_SMZ9_PROOF_BYTES + 1_104 + 4_294);
        assert_eq!(envelope.len(), leaf.len() + 32);
        assert_eq!(action.len(), PROJECTED_SMZ9_ACTION_BYTES);
        let decoded = decode_poseidon2_production_smz9_inline_args_exact(context(), &action)
            .expect("decode exact SMZ9 SCALE action");
        assert_eq!(
            decoded.envelope().decoded_native_leaf().proof(),
            smz9_bytes.as_slice()
        );
        assert!(historical_smz8_decode_inline_args_fixture(context(), &action).is_err());
        ensure_poseidon2_production_smz9_stage_bytes(
            context(),
            &envelope,
            &action,
            Poseidon2ProductionTransportStage::FreshNodeVerify,
        )
        .expect("preserve exact SMZ9 bytes through lifecycle stage");

        let old_proof = proof(211);
        assert!(encode_poseidon2_production_smz9_native_leaf(
            context(),
            &statement,
            &binding(),
            [Some(&ciphertexts[0]), Some(&ciphertexts[1])],
            &old_proof,
        )
        .is_err());
        let old_leaf = historical_smz8_native_leaf_fixture(
            context(),
            &statement,
            &binding(),
            [Some(&ciphertexts[0]), Some(&ciphertexts[1])],
            &old_proof,
        )
        .expect("encode historical SMZ8 leaf");
        assert!(decode_poseidon2_production_smz9_native_leaf_exact(context(), &old_leaf).is_err());

        let mut wrong_profile = leaf;
        wrong_profile[LEAF_OFFSET_PROFILE] = POSEIDON2_PRODUCTION_TRANSPORT_PROFILE_ID;
        assert!(preflight_poseidon2_production_smz9_native_leaf_exact(&wrong_profile).is_err());
    }

    #[test]
    fn poseidon2_production_historical_zero_output_129498_screen_fits_action_cap() {
        assert_eq!(POSEIDON2_PRODUCTION_NATIVE_LEAF_FIXED_BYTES, 1_104);
        assert_eq!(POSEIDON2_PRODUCTION_TOTAL_OVERHEAD_BYTES, 1_140);
        assert!(
            POSEIDON2_PRODUCTION_TOTAL_OVERHEAD_BYTES
                <= POSEIDON2_PRODUCTION_MAX_FRAMING_OVERHEAD_BYTES
        );
        let leaf = leaf(POSEIDON2_PRODUCTION_CONSERVATIVE_SCREEN_PROOF_BYTES);
        let envelope = historical_smz8_envelope_fixture(context(), &leaf).unwrap();
        let action = historical_smz8_inline_args_fixture(context(), &envelope).unwrap();
        assert_eq!(leaf.len(), 129_462);
        assert_eq!(envelope.len(), 129_494);
        assert_eq!(action.len(), 129_498);
        assert_eq!(
            action.len(),
            POSEIDON2_PRODUCTION_CONSERVATIVE_SCREEN_ACTION_BYTES
        );
        assert!(
            POSEIDON2_PRODUCTION_CONSERVATIVE_SCREEN_PROOF_BYTES
                > POSEIDON2_PRODUCTION_MAX_ROUTED_PROOF_BYTES_AT_MAX_OUTPUTS,
            "the historical zero-output screen must never be treated as a two-output proof budget"
        );
        assert!(action.len() <= POSEIDON2_PRODUCTION_MAX_ACTION_BYTES);
        assert_eq!(
            historical_smz8_decode_inline_args_fixture(context(), &action)
                .unwrap()
                .envelope()
                .decoded_native_leaf()
                .proof()
                .len(),
            POSEIDON2_PRODUCTION_CONSERVATIVE_SCREEN_PROOF_BYTES
        );
    }

    #[test]
    fn poseidon2_production_two_output_r686_screen_is_119512_action_bytes() {
        // Current static R686/compress14 projection only. The retained proof
        // artifact and executable adapter must freeze the accepted maximum.
        const UNFROZEN_R686_SCREEN_INNER_BYTES: usize = 114_078;
        let leaf = leaf_with_outputs(UNFROZEN_R686_SCREEN_INNER_BYTES, 2);
        let envelope = historical_smz8_envelope_fixture(context(), &leaf).unwrap();
        let action = historical_smz8_inline_args_fixture(context(), &envelope).unwrap();
        assert_eq!(POSEIDON2_PRODUCTION_MAX_INLINE_NON_PROOF_BYTES, 5_434);
        assert_eq!(leaf.len(), 119_476);
        assert_eq!(envelope.len(), 119_508);
        assert_eq!(action.len(), 119_512);
        assert!(action.len() <= POSEIDON2_PRODUCTION_MAX_ACTION_BYTES);
        assert_eq!(
            poseidon2_production_max_routed_proof_bytes(2),
            Some(125_638)
        );
    }

    #[test]
    fn poseidon2_production_ciphertexts_are_exact_hash_bound_and_cap_before_allocation() {
        let ciphertexts = ciphertexts();
        let statement = statement_with_outputs(&ciphertexts, 2);
        let proof_bytes = proof(64);
        let leaf = historical_smz8_native_leaf_fixture(
            context(),
            &statement,
            &binding(),
            [Some(&ciphertexts[0]), Some(&ciphertexts[1])],
            &proof_bytes,
        )
        .unwrap();
        let mut mutated = leaf.clone();
        mutated[LEAF_OFFSET_CIPHERTEXTS] ^= 1;
        assert_eq!(
            historical_smz8_preflight_native_leaf_fixture(&mutated),
            Err(Poseidon2ProductionTransportError::CiphertextHashMismatch { output_slot: 0 })
        );
        assert_eq!(
            historical_smz8_native_leaf_fixture(
                context(),
                &statement,
                &binding(),
                [Some(&ciphertexts[0]), None],
                &proof_bytes,
            ),
            Err(
                Poseidon2ProductionTransportError::CiphertextPresenceMismatch {
                    output_slot: 1,
                    active: true,
                    present: false,
                }
            )
        );
        let too_large = proof(POSEIDON2_PRODUCTION_MAX_ROUTED_PROOF_BYTES_AT_MAX_OUTPUTS + 1);
        assert!(matches!(
            historical_smz8_native_leaf_fixture(
                context(),
                &statement,
                &binding(),
                [Some(&ciphertexts[0]), Some(&ciphertexts[1])],
                &too_large,
            ),
            Err(
                Poseidon2ProductionTransportError::ProofExceedsInlineBudget {
                    maximum: POSEIDON2_PRODUCTION_MAX_ROUTED_PROOF_BYTES_AT_MAX_OUTPUTS,
                    ..
                }
            )
        ));

        for output_slot in 0..POSEIDON2_PRODUCTION_MAX_OUTPUTS {
            for byte_index in 0..POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES {
                let mut mutated = leaf.clone();
                mutated[LEAF_OFFSET_CIPHERTEXTS
                    + output_slot * POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES
                    + byte_index] ^= 1;
                assert_eq!(
                    historical_smz8_preflight_native_leaf_fixture(&mutated),
                    Err(Poseidon2ProductionTransportError::CiphertextHashMismatch { output_slot }),
                    "ciphertext byte mutation survived at slot {output_slot}, byte {byte_index}"
                );
            }
        }
    }

    #[test]
    fn poseidon2_production_all_output_masks_have_unique_canonical_ciphertext_parse() {
        let ciphertexts = ciphertexts();
        for output_mask in 0u8..4 {
            let leaf = leaf_with_output_mask(64, output_mask);
            let decoded = historical_smz8_decode_native_leaf_fixture(context(), &leaf).unwrap();
            let active_outputs = output_mask.count_ones() as usize;
            assert_eq!(decoded.active_output_count(), active_outputs);
            assert_eq!(
                leaf.len(),
                POSEIDON2_PRODUCTION_NATIVE_LEAF_FIXED_BYTES
                    + active_outputs * POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES
                    + 64
            );
            for output_slot in 0..POSEIDON2_PRODUCTION_MAX_OUTPUTS {
                let expected =
                    (output_mask & (1 << output_slot) != 0).then_some(&ciphertexts[output_slot]);
                assert_eq!(decoded.ciphertext(output_slot), expected);
            }
        }
    }

    #[test]
    fn poseidon2_production_transport_rejects_caps_context_and_legacy_wires() {
        let mut hard_oversize = leaf(64);
        hard_oversize[LEAF_OFFSET_PROOF_LEN..LEAF_OFFSET_PROOF_LEN + 4].copy_from_slice(
            &u32::try_from(POSEIDON2_PRODUCTION_MAX_PROOF_BYTES + 1)
                .unwrap()
                .to_le_bytes(),
        );
        assert!(matches!(
            historical_smz8_preflight_native_leaf_fixture(&hard_oversize),
            Err(Poseidon2ProductionTransportError::ProofTooLarge { .. })
        ));

        let mut action_declaration = Vec::new();
        encode_compact_u32(
            u32::try_from(POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES + 1).unwrap(),
            &mut action_declaration,
        );
        assert!(matches!(
            historical_smz8_preflight_inline_args_fixture(&action_declaration),
            Err(Poseidon2ProductionTransportError::EnvelopeTooLarge { .. })
        ));
        assert_eq!(
            Poseidon2ProductionExpectedContext::new(17, [0; 48]),
            Err(Poseidon2ProductionTransportError::ZeroExpectedRelationDigest)
        );
        let leaf = leaf(64);
        let wrong_network = Poseidon2ProductionExpectedContext::new(18, [0x42; 48]).unwrap();
        assert!(matches!(
            historical_smz8_decode_native_leaf_fixture(wrong_network, &leaf),
            Err(Poseidon2ProductionTransportError::NetworkMismatch { .. })
        ));
        let wrong_relation = Poseidon2ProductionExpectedContext::new(17, [0x43; 48]).unwrap();
        assert_eq!(
            historical_smz8_decode_native_leaf_fixture(wrong_relation, &leaf),
            Err(Poseidon2ProductionTransportError::RelationDigestMismatch)
        );

        for legacy in [*b"SMZ1", *b"SMZ2"] {
            let mut proof = proof(64);
            proof[..4].copy_from_slice(&legacy);
            assert_eq!(
                historical_smz8_native_leaf_fixture(
                    context(),
                    &statement(),
                    &binding(),
                    [None, None],
                    &proof,
                ),
                Err(Poseidon2ProductionTransportError::UnsupportedInnerProofMagic(legacy))
            );
        }
    }

    #[test]
    fn poseidon2_production_transport_preserves_bytes_across_every_lifecycle_stage() {
        let envelope = envelope_with_outputs(211, 2);
        let action = historical_smz8_inline_args_fixture(context(), &envelope).unwrap();
        for stage in [
            Poseidon2ProductionTransportStage::Wallet,
            Poseidon2ProductionTransportStage::Rpc,
            Poseidon2ProductionTransportStage::Relay,
            Poseidon2ProductionTransportStage::Mempool,
            Poseidon2ProductionTransportStage::Mining,
            Poseidon2ProductionTransportStage::Block,
            Poseidon2ProductionTransportStage::Restart,
            Poseidon2ProductionTransportStage::Sync,
            Poseidon2ProductionTransportStage::Reorg,
            Poseidon2ProductionTransportStage::FreshNodeVerify,
        ] {
            historical_smz8_ensure_stage_fixture(context(), &envelope, &action, stage)
                .unwrap_or_else(|error| panic!("{} changed bytes: {error}", stage.label()));
        }

        let mut mutated_leaf = leaf_with_outputs(211, 2);
        let offset_in_leaf = mutated_leaf.len() - 1;
        mutated_leaf[offset_in_leaf] ^= 1;
        let mutated_envelope = historical_smz8_envelope_fixture(context(), &mutated_leaf).unwrap();
        let mutated_action =
            historical_smz8_inline_args_fixture(context(), &mutated_envelope).unwrap();
        assert_eq!(
            historical_smz8_ensure_stage_fixture(
                context(),
                &envelope,
                &mutated_action,
                Poseidon2ProductionTransportStage::Sync,
            ),
            Err(Poseidon2ProductionTransportError::StageMismatch {
                stage: Poseidon2ProductionTransportStage::Sync,
                expected: envelope.len(),
                observed: mutated_envelope.len(),
                first_difference: Some(
                    POSEIDON2_PRODUCTION_TRANSPORT_HEADER_BYTES + offset_in_leaf
                ),
            })
        );
    }
}
