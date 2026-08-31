//! Inactive transport boundary for a fresh 56-byte SmallWood successor.
//!
//! This module reserves a new identity and defines the byte grammar needed to
//! exercise wallet, RPC, relay, durable-mempool, block, import, and restart
//! lifecycles without making that identity admissible. It is intentionally not
//! listed in the kernel manifest, version/backend dispatch, or native action
//! router. The existing 48-byte action types have no conversion into these
//! types.
//!
//! The policy, oracle, and attestation fields below are prospective 56-byte
//! statement fields. Live stablecoin authorities are 48-byte values. No
//! refinement or conversion exists between them, so enabled stablecoin
//! statements are rejected by this codec and cannot satisfy live admission.

use alloc::vec::Vec;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use codec::{Decode, Encode};

pub const INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION: u16 = 7;
pub const INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA: u16 = 6;
pub const INACTIVE_SMALLWOOD_V7_FAMILY_ID: u16 = 1;
pub const INACTIVE_SMALLWOOD_V7_ACTION_ID: u16 = 9;
pub const INACTIVE_SMALLWOOD_V7_BACKEND_ID: u8 = 3;
pub const INACTIVE_SMALLWOOD_V7_PROOF_PROFILE: u8 = 4;
pub const INACTIVE_SMALLWOOD_V7_DOMAIN_SET: u16 = 3;

pub const INACTIVE_SMALLWOOD_V7_STATEMENT_MAGIC: [u8; 8] = *b"HGF7ST01";
pub const INACTIVE_SMALLWOOD_V7_STATEMENT_GRAMMAR: u16 = 1;
pub const INACTIVE_SMALLWOOD_V7_ENVELOPE_MAGIC: [u8; 8] = *b"SWV7LC01";
pub const INACTIVE_SMALLWOOD_V7_ENVELOPE_GRAMMAR: u16 = 1;

pub const INACTIVE_SMALLWOOD_V7_DIGEST_BYTES: usize = 56;
pub const INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES: usize = 893;
pub const INACTIVE_SMALLWOOD_V7_STATEMENT_LIMB_BYTES: usize = 7;
pub const INACTIVE_SMALLWOOD_V7_STATEMENT_LIMBS: usize =
    INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES.div_ceil(INACTIVE_SMALLWOOD_V7_STATEMENT_LIMB_BYTES);
pub const INACTIVE_SMALLWOOD_V7_MAX_INPUTS: usize = 2;
pub const INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS: usize = 2;
pub const INACTIVE_SMALLWOOD_V7_BALANCE_SLOTS: usize = 4;
pub const INACTIVE_SMALLWOOD_V7_MAX_NOTE_VALUE: u64 = (1u64 << 61) - 1;
pub const INACTIVE_SMALLWOOD_V7_MAX_CIPHERTEXT_BYTES: usize = 2_147;
pub const INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES: usize = 30;
/// Diagnostic byte budget copied from the generic RPC transport ceiling.
///
/// This is not a measured proof-size result, a proof-profile limit, or a
/// production consensus cap. It only bounds source-level lifecycle fixtures
/// while the proof winner and profile remain unset.
pub const INACTIVE_SMALLWOOD_V7_DIAGNOSTIC_TRANSPORT_BUDGET_BYTES: usize = 2 * 1024 * 1024;
const INACTIVE_SMALLWOOD_V7_SCALE_AND_STAGE_HEADROOM_BYTES: usize = 128;
pub const INACTIVE_SMALLWOOD_V7_MAX_OPAQUE_PROOF_TRANSPORT_BYTES: usize =
    INACTIVE_SMALLWOOD_V7_DIAGNOSTIC_TRANSPORT_BUDGET_BYTES
        - INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES
        - INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES
        - (2 * INACTIVE_SMALLWOOD_V7_MAX_CIPHERTEXT_BYTES)
        - INACTIVE_SMALLWOOD_V7_SCALE_AND_STAGE_HEADROOM_BYTES;
pub const INACTIVE_SMALLWOOD_V7_MAX_ENVELOPE_BYTES: usize =
    INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES
        + INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES
        + INACTIVE_SMALLWOOD_V7_MAX_OPAQUE_PROOF_TRANSPORT_BYTES;
pub const INACTIVE_SMALLWOOD_V7_MAX_PUBLIC_ARGS_BYTES: usize =
    INACTIVE_SMALLWOOD_V7_DIAGNOSTIC_TRANSPORT_BUDGET_BYTES;

/// These flags are declarations, not feature switches. They must remain false
/// until a fresh-genesis manifest, verifier, and independent proof profile are
/// approved together.
pub const INACTIVE_SMALLWOOD_V7_PRODUCTION_ENABLED: bool = false;
pub const INACTIVE_SMALLWOOD_V7_ADMISSION_ENABLED: bool = false;
pub const INACTIVE_SMALLWOOD_V7_LIVE_STABLECOIN_REFINEMENT_AVAILABLE: bool = false;
pub const INACTIVE_SMALLWOOD_V7_PROSPECTIVE_ACTION_ID_ENABLED: bool = false;
pub const INACTIVE_SMALLWOOD_V7_LIVE_ACTION_ID48_REFINEMENT_AVAILABLE: bool = false;

pub const INACTIVE_SMALLWOOD_V7_OFFSET_ANCHOR: usize = 14;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_NULLIFIERS: usize = 70;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_COMMITMENTS: usize = 182;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_CIPHERTEXT_HASHES: usize = 294;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_ACTIVATION: usize = 709;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_NETWORK: usize = 717;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_BACKEND: usize = 721;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_PROFILE: usize = 722;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_DOMAIN_SET: usize = 723;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_CHAIN_ID: usize = 725;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_GENESIS_ID: usize = 781;
pub const INACTIVE_SMALLWOOD_V7_OFFSET_RULES_HASH: usize = 837;

const INACTIVE_SMALLWOOD_V7_CIPHERTEXT_HASH_DOMAIN: &[u8] =
    b"hegemon.smallwood.v7-zeta.ciphertext-hash.blake2b-448.v1";
const INACTIVE_SMALLWOOD_V7_PROSPECTIVE_ACTION_ID_DOMAIN: &[u8] =
    b"hegemon.smallwood.v7-zeta.prospective-consensus-action-id.blake2b-448.v1";

macro_rules! fixed_56_type {
    ($name:ident) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
        pub struct $name([u8; INACTIVE_SMALLWOOD_V7_DIGEST_BYTES]);

        impl Default for $name {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl $name {
            pub const ZERO: Self = Self([0; INACTIVE_SMALLWOOD_V7_DIGEST_BYTES]);

            pub const fn new(bytes: [u8; INACTIVE_SMALLWOOD_V7_DIGEST_BYTES]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; INACTIVE_SMALLWOOD_V7_DIGEST_BYTES] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; INACTIVE_SMALLWOOD_V7_DIGEST_BYTES] {
                self.0
            }
        }
    };
}

// Exact prospective content key for a future V7 consensus grammar. It remains
// inactive and has no conversion to the live 48-byte `ActionId48`. A
// fresh-genesis action index must adopt this exact 56-byte type atomically;
// truncation, padding, and hash-again adapters are forbidden.
fixed_56_type!(InactiveSmallwoodV7ProspectiveActionId56);
fixed_56_type!(InactiveSmallwoodV7Anchor56);
fixed_56_type!(InactiveSmallwoodV7Nullifier56);
fixed_56_type!(InactiveSmallwoodV7Commitment56);
fixed_56_type!(InactiveSmallwoodV7CiphertextHash56);
fixed_56_type!(InactiveSmallwoodV7PolicyHash56);
fixed_56_type!(InactiveSmallwoodV7OracleCommitment56);
fixed_56_type!(InactiveSmallwoodV7AttestationCommitment56);
fixed_56_type!(InactiveSmallwoodV7BalanceTag56);
fixed_56_type!(InactiveSmallwoodV7ChainId56);
fixed_56_type!(InactiveSmallwoodV7GenesisId56);
fixed_56_type!(InactiveSmallwoodV7RulesHash56);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InactiveSmallwoodV7SignedMagnitude {
    pub negative: bool,
    pub magnitude: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InactiveSmallwoodV7StablecoinBinding {
    pub enabled: bool,
    pub asset_id: u64,
    pub policy_version: u32,
    pub issuance_delta: InactiveSmallwoodV7SignedMagnitude,
    pub policy_hash: InactiveSmallwoodV7PolicyHash56,
    pub oracle_commitment: InactiveSmallwoodV7OracleCommitment56,
    pub attestation_commitment: InactiveSmallwoodV7AttestationCommitment56,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InactiveSmallwoodV7ActivationBinding {
    pub circuit_version: u16,
    pub crypto_suite: u16,
    pub family_id: u16,
    pub action_id: u16,
    pub network_id: u32,
    pub backend_id: u8,
    pub proof_profile: u8,
    pub domain_set: u16,
    pub chain_id: InactiveSmallwoodV7ChainId56,
    pub genesis_id: InactiveSmallwoodV7GenesisId56,
    pub rules_hash: InactiveSmallwoodV7RulesHash56,
}

/// Consensus context supplied by the caller, never inferred from an untrusted
/// statement. Every decode boundary compares all four fields byte-for-byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InactiveSmallwoodV7ExpectedActivationContext {
    pub network_id: u32,
    pub chain_id: InactiveSmallwoodV7ChainId56,
    pub genesis_id: InactiveSmallwoodV7GenesisId56,
    pub rules_hash: InactiveSmallwoodV7RulesHash56,
}

impl InactiveSmallwoodV7ActivationBinding {
    pub const fn reserved_route() -> Self {
        Self {
            circuit_version: INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION,
            crypto_suite: INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA,
            family_id: INACTIVE_SMALLWOOD_V7_FAMILY_ID,
            action_id: INACTIVE_SMALLWOOD_V7_ACTION_ID,
            network_id: 0,
            backend_id: INACTIVE_SMALLWOOD_V7_BACKEND_ID,
            proof_profile: INACTIVE_SMALLWOOD_V7_PROOF_PROFILE,
            domain_set: INACTIVE_SMALLWOOD_V7_DOMAIN_SET,
            chain_id: InactiveSmallwoodV7ChainId56::ZERO,
            genesis_id: InactiveSmallwoodV7GenesisId56::ZERO,
            rules_hash: InactiveSmallwoodV7RulesHash56::ZERO,
        }
    }

    pub const fn has_reserved_route(self) -> bool {
        self.circuit_version == INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION
            && self.crypto_suite == INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA
            && self.family_id == INACTIVE_SMALLWOOD_V7_FAMILY_ID
            && self.action_id == INACTIVE_SMALLWOOD_V7_ACTION_ID
            && self.backend_id == INACTIVE_SMALLWOOD_V7_BACKEND_ID
            && self.proof_profile == INACTIVE_SMALLWOOD_V7_PROOF_PROFILE
            && self.domain_set == INACTIVE_SMALLWOOD_V7_DOMAIN_SET
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InactiveSmallwoodV7Statement {
    pub input_flags: [bool; INACTIVE_SMALLWOOD_V7_MAX_INPUTS],
    pub output_flags: [bool; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
    pub anchor: InactiveSmallwoodV7Anchor56,
    pub nullifiers: [InactiveSmallwoodV7Nullifier56; INACTIVE_SMALLWOOD_V7_MAX_INPUTS],
    pub commitments: [InactiveSmallwoodV7Commitment56; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
    pub ciphertext_hashes: [InactiveSmallwoodV7CiphertextHash56; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
    pub ciphertext_sizes: [u32; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
    pub balance_asset_ids: [u64; INACTIVE_SMALLWOOD_V7_BALANCE_SLOTS],
    pub fee: u64,
    pub value_balance: InactiveSmallwoodV7SignedMagnitude,
    pub stablecoin: InactiveSmallwoodV7StablecoinBinding,
    pub balance_tag: InactiveSmallwoodV7BalanceTag56,
    pub activation: InactiveSmallwoodV7ActivationBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InactiveSmallwoodV7PublicProjection {
    pub anchor: InactiveSmallwoodV7Anchor56,
    pub nullifiers: [InactiveSmallwoodV7Nullifier56; INACTIVE_SMALLWOOD_V7_MAX_INPUTS],
    pub commitments: [InactiveSmallwoodV7Commitment56; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
    pub ciphertext_hashes: [InactiveSmallwoodV7CiphertextHash56; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InactiveSmallwoodV7StatementProjection {
    limbs: [u64; INACTIVE_SMALLWOOD_V7_STATEMENT_LIMBS],
    public: InactiveSmallwoodV7PublicProjection,
}

impl InactiveSmallwoodV7StatementProjection {
    pub const fn limbs(&self) -> &[u64; INACTIVE_SMALLWOOD_V7_STATEMENT_LIMBS] {
        &self.limbs
    }

    pub const fn public(&self) -> &InactiveSmallwoodV7PublicProjection {
        &self.public
    }

    pub fn reconstruct(&self) -> [u8; INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES] {
        let mut bytes = [0u8; INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES];
        for (index, value) in self.limbs.iter().copied().enumerate() {
            let offset = index * INACTIVE_SMALLWOOD_V7_STATEMENT_LIMB_BYTES;
            let take = (INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES - offset)
                .min(INACTIVE_SMALLWOOD_V7_STATEMENT_LIMB_BYTES);
            bytes[offset..offset + take].copy_from_slice(&value.to_le_bytes()[..take]);
        }
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InactiveSmallwoodV7CodecError {
    StatementLength(usize),
    StatementMagic,
    StatementGrammar(u16),
    NonBoolean(&'static str),
    NegativeZero(&'static str),
    SignedMagnitudeOutOfRange(&'static str, u64),
    UnsupportedRoute,
    ZeroActivation(&'static str),
    NonCanonicalInactiveSlot(&'static str, usize),
    LiveStablecoinRefinementUnavailable,
    ActivationContextMismatch(&'static str),
    EnvelopeLength(usize),
    EnvelopeMagic,
    EnvelopeGrammar(u16),
    EnvelopeStatementLength(u32),
    EmptyProof,
    ProofTooLarge(usize),
    LengthOverflow,
    TrailingBytes,
    ActionTooLarge(usize),
    ActionDecode,
    NonCanonicalAction,
    CiphertextSlot(usize),
    CiphertextSize {
        slot: usize,
        declared: u32,
        observed: usize,
    },
    CiphertextHashMismatch(usize),
    LiveActionId48AliasingForbidden,
}

#[cfg(feature = "std")]
impl std::error::Error for InactiveSmallwoodV7CodecError {}

impl core::fmt::Display for InactiveSmallwoodV7CodecError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "inactive SmallWood V7 lifecycle codec rejection: {self:?}"
        )
    }
}

pub fn encode_inactive_smallwood_v7_statement(
    statement: &InactiveSmallwoodV7Statement,
) -> Result<[u8; INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES], InactiveSmallwoodV7CodecError> {
    validate_statement(statement)?;
    let mut bytes = Vec::with_capacity(INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES);
    bytes.extend_from_slice(&INACTIVE_SMALLWOOD_V7_STATEMENT_MAGIC);
    bytes.extend_from_slice(&INACTIVE_SMALLWOOD_V7_STATEMENT_GRAMMAR.to_be_bytes());
    bytes.extend(statement.input_flags.map(u8::from));
    bytes.extend(statement.output_flags.map(u8::from));
    bytes.extend_from_slice(statement.anchor.as_bytes());
    for value in statement.nullifiers {
        bytes.extend_from_slice(value.as_bytes());
    }
    for value in statement.commitments {
        bytes.extend_from_slice(value.as_bytes());
    }
    for value in statement.ciphertext_hashes {
        bytes.extend_from_slice(value.as_bytes());
    }
    for value in statement.ciphertext_sizes {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for value in statement.balance_asset_ids {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&statement.fee.to_be_bytes());
    push_signed(&mut bytes, statement.value_balance);
    bytes.push(u8::from(statement.stablecoin.enabled));
    bytes.extend_from_slice(&statement.stablecoin.asset_id.to_be_bytes());
    bytes.extend_from_slice(&statement.stablecoin.policy_version.to_be_bytes());
    push_signed(&mut bytes, statement.stablecoin.issuance_delta);
    bytes.extend_from_slice(statement.stablecoin.policy_hash.as_bytes());
    bytes.extend_from_slice(statement.stablecoin.oracle_commitment.as_bytes());
    bytes.extend_from_slice(statement.stablecoin.attestation_commitment.as_bytes());
    bytes.extend_from_slice(statement.balance_tag.as_bytes());
    push_activation(&mut bytes, statement.activation);
    debug_assert_eq!(bytes.len(), INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES);
    Ok(bytes
        .try_into()
        .expect("the inactive V7 statement table has a fixed compile-time width"))
}

pub fn decode_inactive_smallwood_v7_statement(
    bytes: &[u8],
) -> Result<InactiveSmallwoodV7Statement, InactiveSmallwoodV7CodecError> {
    if bytes.len() != INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES {
        return Err(InactiveSmallwoodV7CodecError::StatementLength(bytes.len()));
    }
    let mut cursor = StatementCursor { bytes, offset: 0 };
    if cursor.array::<8>() != INACTIVE_SMALLWOOD_V7_STATEMENT_MAGIC {
        return Err(InactiveSmallwoodV7CodecError::StatementMagic);
    }
    let grammar = cursor.u16();
    if grammar != INACTIVE_SMALLWOOD_V7_STATEMENT_GRAMMAR {
        return Err(InactiveSmallwoodV7CodecError::StatementGrammar(grammar));
    }
    let input_flags = [
        cursor.boolean("input_flags[0]")?,
        cursor.boolean("input_flags[1]")?,
    ];
    let output_flags = [
        cursor.boolean("output_flags[0]")?,
        cursor.boolean("output_flags[1]")?,
    ];
    let anchor = InactiveSmallwoodV7Anchor56::new(cursor.array());
    let nullifiers = core::array::from_fn(|_| InactiveSmallwoodV7Nullifier56::new(cursor.array()));
    let commitments =
        core::array::from_fn(|_| InactiveSmallwoodV7Commitment56::new(cursor.array()));
    let ciphertext_hashes =
        core::array::from_fn(|_| InactiveSmallwoodV7CiphertextHash56::new(cursor.array()));
    let ciphertext_sizes = core::array::from_fn(|_| cursor.u32());
    let balance_asset_ids = core::array::from_fn(|_| cursor.u64());
    let fee = cursor.u64();
    let value_balance = cursor.signed("value_balance")?;
    let stablecoin = InactiveSmallwoodV7StablecoinBinding {
        enabled: cursor.boolean("stable.enabled")?,
        asset_id: cursor.u64(),
        policy_version: cursor.u32(),
        issuance_delta: cursor.signed("stable.issuance")?,
        policy_hash: InactiveSmallwoodV7PolicyHash56::new(cursor.array()),
        oracle_commitment: InactiveSmallwoodV7OracleCommitment56::new(cursor.array()),
        attestation_commitment: InactiveSmallwoodV7AttestationCommitment56::new(cursor.array()),
    };
    let balance_tag = InactiveSmallwoodV7BalanceTag56::new(cursor.array());
    let activation = InactiveSmallwoodV7ActivationBinding {
        circuit_version: cursor.u16(),
        crypto_suite: cursor.u16(),
        family_id: cursor.u16(),
        action_id: cursor.u16(),
        network_id: cursor.u32(),
        backend_id: cursor.byte(),
        proof_profile: cursor.byte(),
        domain_set: cursor.u16(),
        chain_id: InactiveSmallwoodV7ChainId56::new(cursor.array()),
        genesis_id: InactiveSmallwoodV7GenesisId56::new(cursor.array()),
        rules_hash: InactiveSmallwoodV7RulesHash56::new(cursor.array()),
    };
    debug_assert_eq!(cursor.offset, INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES);
    let statement = InactiveSmallwoodV7Statement {
        input_flags,
        output_flags,
        anchor,
        nullifiers,
        commitments,
        ciphertext_hashes,
        ciphertext_sizes,
        balance_asset_ids,
        fee,
        value_balance,
        stablecoin,
        balance_tag,
        activation,
    };
    validate_statement(&statement)?;
    Ok(statement)
}

pub fn validate_inactive_smallwood_v7_activation_context(
    statement: &InactiveSmallwoodV7Statement,
    expected: &InactiveSmallwoodV7ExpectedActivationContext,
) -> Result<(), InactiveSmallwoodV7CodecError> {
    if statement.activation.network_id != expected.network_id {
        return Err(InactiveSmallwoodV7CodecError::ActivationContextMismatch(
            "network_id",
        ));
    }
    if statement.activation.chain_id != expected.chain_id {
        return Err(InactiveSmallwoodV7CodecError::ActivationContextMismatch(
            "chain_id",
        ));
    }
    if statement.activation.genesis_id != expected.genesis_id {
        return Err(InactiveSmallwoodV7CodecError::ActivationContextMismatch(
            "genesis_id",
        ));
    }
    if statement.activation.rules_hash != expected.rules_hash {
        return Err(InactiveSmallwoodV7CodecError::ActivationContextMismatch(
            "rules_hash",
        ));
    }
    Ok(())
}

pub fn decode_inactive_smallwood_v7_statement_for_context(
    bytes: &[u8],
    expected: &InactiveSmallwoodV7ExpectedActivationContext,
) -> Result<InactiveSmallwoodV7Statement, InactiveSmallwoodV7CodecError> {
    let statement = decode_inactive_smallwood_v7_statement(bytes)?;
    validate_inactive_smallwood_v7_activation_context(&statement, expected)?;
    Ok(statement)
}

pub fn project_inactive_smallwood_v7_statement(
    statement_bytes: &[u8],
) -> Result<InactiveSmallwoodV7StatementProjection, InactiveSmallwoodV7CodecError> {
    let statement = decode_inactive_smallwood_v7_statement(statement_bytes)?;
    let mut limbs = [0u64; INACTIVE_SMALLWOOD_V7_STATEMENT_LIMBS];
    for (index, chunk) in statement_bytes
        .chunks(INACTIVE_SMALLWOOD_V7_STATEMENT_LIMB_BYTES)
        .enumerate()
    {
        let mut encoded = [0u8; 8];
        encoded[..chunk.len()].copy_from_slice(chunk);
        limbs[index] = u64::from_le_bytes(encoded);
    }
    Ok(InactiveSmallwoodV7StatementProjection {
        limbs,
        public: InactiveSmallwoodV7PublicProjection {
            anchor: statement.anchor,
            nullifiers: statement.nullifiers,
            commitments: statement.commitments,
            ciphertext_hashes: statement.ciphertext_hashes,
        },
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InactiveSmallwoodV7Envelope {
    canonical_bytes: Vec<u8>,
}

impl InactiveSmallwoodV7Envelope {
    pub fn from_parts(
        statement: [u8; INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES],
        proof: &[u8],
    ) -> Result<Self, InactiveSmallwoodV7CodecError> {
        decode_inactive_smallwood_v7_statement(&statement)?;
        if proof.is_empty() {
            return Err(InactiveSmallwoodV7CodecError::EmptyProof);
        }
        if proof.len() > INACTIVE_SMALLWOOD_V7_MAX_OPAQUE_PROOF_TRANSPORT_BYTES {
            return Err(InactiveSmallwoodV7CodecError::ProofTooLarge(proof.len()));
        }
        let mut bytes = Vec::with_capacity(
            INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES + statement.len() + proof.len(),
        );
        bytes.extend_from_slice(&INACTIVE_SMALLWOOD_V7_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&INACTIVE_SMALLWOOD_V7_ENVELOPE_GRAMMAR.to_be_bytes());
        bytes.extend_from_slice(&INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA.to_be_bytes());
        bytes.extend_from_slice(&INACTIVE_SMALLWOOD_V7_FAMILY_ID.to_be_bytes());
        bytes.extend_from_slice(&INACTIVE_SMALLWOOD_V7_ACTION_ID.to_be_bytes());
        bytes.push(INACTIVE_SMALLWOOD_V7_BACKEND_ID);
        bytes.push(INACTIVE_SMALLWOOD_V7_PROOF_PROFILE);
        bytes.extend_from_slice(&INACTIVE_SMALLWOOD_V7_DOMAIN_SET.to_be_bytes());
        bytes.extend_from_slice(&(INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES as u32).to_be_bytes());
        bytes.extend_from_slice(&(proof.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&statement);
        bytes.extend_from_slice(proof);
        Self::parse(&bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, InactiveSmallwoodV7CodecError> {
        if bytes.len() < INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES {
            return Err(InactiveSmallwoodV7CodecError::EnvelopeLength(bytes.len()));
        }
        if bytes.len() > INACTIVE_SMALLWOOD_V7_MAX_ENVELOPE_BYTES {
            return Err(InactiveSmallwoodV7CodecError::EnvelopeLength(bytes.len()));
        }
        if bytes[..8] != INACTIVE_SMALLWOOD_V7_ENVELOPE_MAGIC {
            return Err(InactiveSmallwoodV7CodecError::EnvelopeMagic);
        }
        let grammar = u16::from_be_bytes(bytes[8..10].try_into().expect("fixed envelope header"));
        if grammar != INACTIVE_SMALLWOOD_V7_ENVELOPE_GRAMMAR {
            return Err(InactiveSmallwoodV7CodecError::EnvelopeGrammar(grammar));
        }
        let route_matches =
            u16::from_be_bytes(bytes[10..12].try_into().expect("fixed envelope header"))
                == INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION
                && u16::from_be_bytes(bytes[12..14].try_into().expect("fixed envelope header"))
                    == INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA
                && u16::from_be_bytes(bytes[14..16].try_into().expect("fixed envelope header"))
                    == INACTIVE_SMALLWOOD_V7_FAMILY_ID
                && u16::from_be_bytes(bytes[16..18].try_into().expect("fixed envelope header"))
                    == INACTIVE_SMALLWOOD_V7_ACTION_ID
                && bytes[18] == INACTIVE_SMALLWOOD_V7_BACKEND_ID
                && bytes[19] == INACTIVE_SMALLWOOD_V7_PROOF_PROFILE
                && u16::from_be_bytes(bytes[20..22].try_into().expect("fixed envelope header"))
                    == INACTIVE_SMALLWOOD_V7_DOMAIN_SET;
        if !route_matches {
            return Err(InactiveSmallwoodV7CodecError::UnsupportedRoute);
        }
        let statement_len =
            u32::from_be_bytes(bytes[22..26].try_into().expect("fixed envelope header"));
        if statement_len as usize != INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES {
            return Err(InactiveSmallwoodV7CodecError::EnvelopeStatementLength(
                statement_len,
            ));
        }
        let proof_len =
            u32::from_be_bytes(bytes[26..30].try_into().expect("fixed envelope header")) as usize;
        if proof_len == 0 {
            return Err(InactiveSmallwoodV7CodecError::EmptyProof);
        }
        if proof_len > INACTIVE_SMALLWOOD_V7_MAX_OPAQUE_PROOF_TRANSPORT_BYTES {
            return Err(InactiveSmallwoodV7CodecError::ProofTooLarge(proof_len));
        }
        let required = INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES
            .checked_add(INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES)
            .and_then(|value| value.checked_add(proof_len))
            .ok_or(InactiveSmallwoodV7CodecError::LengthOverflow)?;
        if bytes.len() != required {
            return Err(if bytes.len() > required {
                InactiveSmallwoodV7CodecError::TrailingBytes
            } else {
                InactiveSmallwoodV7CodecError::EnvelopeLength(bytes.len())
            });
        }
        let statement_start = INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES;
        let statement_end = statement_start + INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES;
        decode_inactive_smallwood_v7_statement(&bytes[statement_start..statement_end])?;
        Ok(Self {
            canonical_bytes: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }

    pub fn statement_bytes(&self) -> &[u8; INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES] {
        let start = INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES;
        self.canonical_bytes[start..start + INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES]
            .try_into()
            .expect("validated envelope owns one exact-width statement")
    }

    pub fn proof_bytes(&self) -> &[u8] {
        &self.canonical_bytes
            [INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES + INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES..]
    }
}

/// RFC 7693 BLAKE2b-448 over one canonical, route- and slot-bound ciphertext
/// frame. This is the sole V7 ciphertext byte-to-statement bridge.
pub fn inactive_smallwood_v7_ciphertext_hash(
    slot: usize,
    ciphertext: &[u8],
) -> Result<InactiveSmallwoodV7CiphertextHash56, InactiveSmallwoodV7CodecError> {
    if slot >= INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS {
        return Err(InactiveSmallwoodV7CodecError::CiphertextSlot(slot));
    }
    if ciphertext.is_empty() || ciphertext.len() > INACTIVE_SMALLWOOD_V7_MAX_CIPHERTEXT_BYTES {
        return Err(InactiveSmallwoodV7CodecError::CiphertextSize {
            slot,
            declared: 0,
            observed: ciphertext.len(),
        });
    }
    let ciphertext_len = u32::try_from(ciphertext.len())
        .map_err(|_| InactiveSmallwoodV7CodecError::LengthOverflow)?;
    let mut hasher = Blake2bVar::new(INACTIVE_SMALLWOOD_V7_DIGEST_BYTES)
        .expect("BLAKE2b supports a fixed 56-byte ciphertext digest");
    hasher.update(&(INACTIVE_SMALLWOOD_V7_CIPHERTEXT_HASH_DOMAIN.len() as u16).to_be_bytes());
    hasher.update(INACTIVE_SMALLWOOD_V7_CIPHERTEXT_HASH_DOMAIN);
    hasher.update(&INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION.to_be_bytes());
    hasher.update(&INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA.to_be_bytes());
    hasher.update(&INACTIVE_SMALLWOOD_V7_FAMILY_ID.to_be_bytes());
    hasher.update(&INACTIVE_SMALLWOOD_V7_ACTION_ID.to_be_bytes());
    hasher.update(&[INACTIVE_SMALLWOOD_V7_BACKEND_ID]);
    hasher.update(&[INACTIVE_SMALLWOOD_V7_PROOF_PROFILE]);
    hasher.update(&INACTIVE_SMALLWOOD_V7_DOMAIN_SET.to_be_bytes());
    hasher.update(&[slot as u8]);
    hasher.update(&ciphertext_len.to_be_bytes());
    hasher.update(ciphertext);
    let mut output = [0u8; INACTIVE_SMALLWOOD_V7_DIGEST_BYTES];
    hasher
        .finalize_variable(&mut output)
        .expect("the output buffer has the configured fixed length");
    Ok(InactiveSmallwoodV7CiphertextHash56::new(output))
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct InactiveSmallwoodV7InlineArgs {
    /// Exact `SWV7LC01` bytes. No stage may decode and reconstitute the proof.
    pub envelope: Vec<u8>,
    /// Exact ciphertext bytes in fixed relation slots. Their 56-byte hashes are
    /// projected from the statement rather than translated from V3 fields.
    pub ciphertexts: [Vec<u8>; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
}

impl InactiveSmallwoodV7InlineArgs {
    pub fn new(
        envelope: InactiveSmallwoodV7Envelope,
        ciphertexts: [Vec<u8>; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
    ) -> Result<Self, InactiveSmallwoodV7CodecError> {
        let action = Self {
            envelope: envelope.into_bytes(),
            ciphertexts,
        };
        action.validate()?;
        Ok(action)
    }

    pub fn envelope(&self) -> Result<InactiveSmallwoodV7Envelope, InactiveSmallwoodV7CodecError> {
        InactiveSmallwoodV7Envelope::parse(&self.envelope)
    }

    pub fn validate(&self) -> Result<(), InactiveSmallwoodV7CodecError> {
        let envelope = self.envelope()?;
        let statement = decode_inactive_smallwood_v7_statement(envelope.statement_bytes())?;
        for slot in 0..INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS {
            let declared = statement.ciphertext_sizes[slot];
            let observed = self.ciphertexts[slot].len();
            let valid = if statement.output_flags[slot] {
                observed > 0
                    && observed <= INACTIVE_SMALLWOOD_V7_MAX_CIPHERTEXT_BYTES
                    && declared as usize == observed
            } else {
                declared == 0 && observed == 0
            };
            if !valid {
                return Err(InactiveSmallwoodV7CodecError::CiphertextSize {
                    slot,
                    declared,
                    observed,
                });
            }
            if statement.output_flags[slot]
                && statement.ciphertext_hashes[slot]
                    != inactive_smallwood_v7_ciphertext_hash(slot, &self.ciphertexts[slot])?
            {
                return Err(InactiveSmallwoodV7CodecError::CiphertextHashMismatch(slot));
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InactiveSmallwoodV7CodecError> {
        self.validate()?;
        let bytes = self.encode();
        if bytes.len() > INACTIVE_SMALLWOOD_V7_MAX_PUBLIC_ARGS_BYTES {
            return Err(InactiveSmallwoodV7CodecError::ActionTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    pub fn prospective_action_id(
        &self,
    ) -> Result<InactiveSmallwoodV7ProspectiveActionId56, InactiveSmallwoodV7CodecError> {
        inactive_smallwood_v7_prospective_action_id(&self.canonical_bytes()?)
    }
}

pub fn decode_inactive_smallwood_v7_inline_args(
    bytes: &[u8],
) -> Result<InactiveSmallwoodV7InlineArgs, InactiveSmallwoodV7CodecError> {
    if bytes.len() > INACTIVE_SMALLWOOD_V7_MAX_PUBLIC_ARGS_BYTES {
        return Err(InactiveSmallwoodV7CodecError::ActionTooLarge(bytes.len()));
    }
    let mut cursor = bytes;
    let action = InactiveSmallwoodV7InlineArgs::decode(&mut cursor)
        .map_err(|_| InactiveSmallwoodV7CodecError::ActionDecode)?;
    if !cursor.is_empty() {
        return Err(InactiveSmallwoodV7CodecError::TrailingBytes);
    }
    action.validate()?;
    if action.encode() != bytes {
        return Err(InactiveSmallwoodV7CodecError::NonCanonicalAction);
    }
    Ok(action)
}

pub fn inactive_smallwood_v7_prospective_action_id(
    canonical_public_args: &[u8],
) -> Result<InactiveSmallwoodV7ProspectiveActionId56, InactiveSmallwoodV7CodecError> {
    decode_inactive_smallwood_v7_inline_args(canonical_public_args)?;
    let mut hasher = Blake2bVar::new(INACTIVE_SMALLWOOD_V7_DIGEST_BYTES)
        .expect("BLAKE2b supports a fixed 56-byte prospective action id");
    hasher.update(&(INACTIVE_SMALLWOOD_V7_PROSPECTIVE_ACTION_ID_DOMAIN.len() as u16).to_be_bytes());
    hasher.update(INACTIVE_SMALLWOOD_V7_PROSPECTIVE_ACTION_ID_DOMAIN);
    hasher.update(&(canonical_public_args.len() as u64).to_be_bytes());
    hasher.update(canonical_public_args);
    let mut output = [0u8; INACTIVE_SMALLWOOD_V7_DIGEST_BYTES];
    hasher
        .finalize_variable(&mut output)
        .expect("the output buffer has the configured fixed length");
    Ok(InactiveSmallwoodV7ProspectiveActionId56::new(output))
}

/// Explicit boundary against accidentally truncating or padding the new 56-byte
/// identity into the live 48-byte action index.
pub fn inactive_smallwood_v7_reject_live_action_id48_alias(
    _action_id: InactiveSmallwoodV7ProspectiveActionId56,
) -> Result<[u8; 48], InactiveSmallwoodV7CodecError> {
    Err(InactiveSmallwoodV7CodecError::LiveActionId48AliasingForbidden)
}

fn validate_statement(
    statement: &InactiveSmallwoodV7Statement,
) -> Result<(), InactiveSmallwoodV7CodecError> {
    validate_signed(statement.value_balance, "value_balance")?;
    validate_signed(statement.stablecoin.issuance_delta, "stable.issuance")?;
    if !statement.activation.has_reserved_route() {
        return Err(InactiveSmallwoodV7CodecError::UnsupportedRoute);
    }
    if statement.activation.chain_id == InactiveSmallwoodV7ChainId56::ZERO {
        return Err(InactiveSmallwoodV7CodecError::ZeroActivation("chain_id"));
    }
    if statement.activation.genesis_id == InactiveSmallwoodV7GenesisId56::ZERO {
        return Err(InactiveSmallwoodV7CodecError::ZeroActivation("genesis_id"));
    }
    if statement.activation.rules_hash == InactiveSmallwoodV7RulesHash56::ZERO {
        return Err(InactiveSmallwoodV7CodecError::ZeroActivation("rules_hash"));
    }
    if statement.stablecoin.enabled {
        return Err(InactiveSmallwoodV7CodecError::LiveStablecoinRefinementUnavailable);
    }
    if statement.stablecoin.asset_id != 0
        || statement.stablecoin.policy_version != 0
        || statement.stablecoin.issuance_delta != InactiveSmallwoodV7SignedMagnitude::default()
        || statement.stablecoin.policy_hash != InactiveSmallwoodV7PolicyHash56::ZERO
        || statement.stablecoin.oracle_commitment != InactiveSmallwoodV7OracleCommitment56::ZERO
        || statement.stablecoin.attestation_commitment
            != InactiveSmallwoodV7AttestationCommitment56::ZERO
    {
        return Err(InactiveSmallwoodV7CodecError::NonCanonicalInactiveSlot(
            "stablecoin",
            0,
        ));
    }
    for (slot, enabled) in statement.input_flags.iter().copied().enumerate() {
        if !enabled && statement.nullifiers[slot] != InactiveSmallwoodV7Nullifier56::ZERO {
            return Err(InactiveSmallwoodV7CodecError::NonCanonicalInactiveSlot(
                "nullifier",
                slot,
            ));
        }
    }
    for (slot, enabled) in statement.output_flags.iter().copied().enumerate() {
        if !enabled
            && (statement.commitments[slot] != InactiveSmallwoodV7Commitment56::ZERO
                || statement.ciphertext_hashes[slot] != InactiveSmallwoodV7CiphertextHash56::ZERO
                || statement.ciphertext_sizes[slot] != 0)
        {
            return Err(InactiveSmallwoodV7CodecError::NonCanonicalInactiveSlot(
                "output", slot,
            ));
        }
    }
    Ok(())
}

fn validate_signed(
    value: InactiveSmallwoodV7SignedMagnitude,
    field: &'static str,
) -> Result<(), InactiveSmallwoodV7CodecError> {
    if value.magnitude > INACTIVE_SMALLWOOD_V7_MAX_NOTE_VALUE {
        return Err(InactiveSmallwoodV7CodecError::SignedMagnitudeOutOfRange(
            field,
            value.magnitude,
        ));
    }
    if value.negative && value.magnitude == 0 {
        return Err(InactiveSmallwoodV7CodecError::NegativeZero(field));
    }
    Ok(())
}

fn push_signed(bytes: &mut Vec<u8>, value: InactiveSmallwoodV7SignedMagnitude) {
    bytes.push(u8::from(value.negative));
    bytes.extend_from_slice(&value.magnitude.to_be_bytes());
}

fn push_activation(bytes: &mut Vec<u8>, activation: InactiveSmallwoodV7ActivationBinding) {
    bytes.extend_from_slice(&activation.circuit_version.to_be_bytes());
    bytes.extend_from_slice(&activation.crypto_suite.to_be_bytes());
    bytes.extend_from_slice(&activation.family_id.to_be_bytes());
    bytes.extend_from_slice(&activation.action_id.to_be_bytes());
    bytes.extend_from_slice(&activation.network_id.to_be_bytes());
    bytes.push(activation.backend_id);
    bytes.push(activation.proof_profile);
    bytes.extend_from_slice(&activation.domain_set.to_be_bytes());
    bytes.extend_from_slice(activation.chain_id.as_bytes());
    bytes.extend_from_slice(activation.genesis_id.as_bytes());
    bytes.extend_from_slice(activation.rules_hash.as_bytes());
}

struct StatementCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl StatementCursor<'_> {
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let output = self.bytes[self.offset..self.offset + N]
            .try_into()
            .expect("the exact inactive V7 statement width was checked");
        self.offset += N;
        output
    }

    fn byte(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    fn boolean(&mut self, field: &'static str) -> Result<bool, InactiveSmallwoodV7CodecError> {
        match self.byte() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(InactiveSmallwoodV7CodecError::NonBoolean(field)),
        }
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
    }

    fn signed(
        &mut self,
        field: &'static str,
    ) -> Result<InactiveSmallwoodV7SignedMagnitude, InactiveSmallwoodV7CodecError> {
        let value = InactiveSmallwoodV7SignedMagnitude {
            negative: self.boolean(field)?,
            magnitude: self.u64(),
        };
        validate_signed(value, field)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn fixture_context() -> InactiveSmallwoodV7ExpectedActivationContext {
        InactiveSmallwoodV7ExpectedActivationContext {
            network_id: 41,
            chain_id: InactiveSmallwoodV7ChainId56::new([11; 56]),
            genesis_id: InactiveSmallwoodV7GenesisId56::new([12; 56]),
            rules_hash: InactiveSmallwoodV7RulesHash56::new([13; 56]),
        }
    }

    fn fixture_statement(
        mask: u8,
        ciphertexts: &[Vec<u8>; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
    ) -> InactiveSmallwoodV7Statement {
        let input_flags = [mask & 1 != 0, mask & 2 != 0];
        let output_flags = [mask & 4 != 0, mask & 8 != 0];
        let mut activation = InactiveSmallwoodV7ActivationBinding::reserved_route();
        let context = fixture_context();
        activation.network_id = context.network_id;
        activation.chain_id = context.chain_id;
        activation.genesis_id = context.genesis_id;
        activation.rules_hash = context.rules_hash;
        InactiveSmallwoodV7Statement {
            input_flags,
            output_flags,
            anchor: InactiveSmallwoodV7Anchor56::new([1; 56]),
            nullifiers: core::array::from_fn(|slot| {
                input_flags[slot]
                    .then(|| InactiveSmallwoodV7Nullifier56::new([2 + slot as u8; 56]))
                    .unwrap_or(InactiveSmallwoodV7Nullifier56::ZERO)
            }),
            commitments: core::array::from_fn(|slot| {
                output_flags[slot]
                    .then(|| InactiveSmallwoodV7Commitment56::new([4 + slot as u8; 56]))
                    .unwrap_or(InactiveSmallwoodV7Commitment56::ZERO)
            }),
            ciphertext_hashes: core::array::from_fn(|slot| {
                output_flags[slot]
                    .then(|| {
                        inactive_smallwood_v7_ciphertext_hash(slot, &ciphertexts[slot]).unwrap()
                    })
                    .unwrap_or(InactiveSmallwoodV7CiphertextHash56::ZERO)
            }),
            ciphertext_sizes: core::array::from_fn(|slot| {
                output_flags[slot]
                    .then_some(ciphertexts[slot].len() as u32)
                    .unwrap_or(0)
            }),
            balance_asset_ids: [0, 1, 2, 3],
            fee: 7,
            value_balance: InactiveSmallwoodV7SignedMagnitude::default(),
            stablecoin: InactiveSmallwoodV7StablecoinBinding {
                enabled: false,
                asset_id: 0,
                policy_version: 0,
                issuance_delta: InactiveSmallwoodV7SignedMagnitude::default(),
                policy_hash: InactiveSmallwoodV7PolicyHash56::ZERO,
                oracle_commitment: InactiveSmallwoodV7OracleCommitment56::ZERO,
                attestation_commitment: InactiveSmallwoodV7AttestationCommitment56::ZERO,
            },
            balance_tag: InactiveSmallwoodV7BalanceTag56::new([5; 56]),
            activation,
        }
    }

    #[test]
    fn statement_and_limb_projection_are_exact() {
        let ciphertexts = [vec![1, 2, 3], Vec::new()];
        let bytes =
            encode_inactive_smallwood_v7_statement(&fixture_statement(0b0101, &ciphertexts))
                .unwrap();
        assert_eq!(bytes.len(), 893);
        let projected = project_inactive_smallwood_v7_statement(&bytes).unwrap();
        assert_eq!(projected.reconstruct(), bytes);
        assert_eq!(projected.public().anchor.as_bytes(), &[1; 56]);
        assert_eq!(projected.public().nullifiers[0].as_bytes(), &[2; 56]);
        assert_eq!(projected.public().commitments[0].as_bytes(), &[4; 56]);
        assert_eq!(
            projected.public().ciphertext_hashes[0],
            inactive_smallwood_v7_ciphertext_hash(0, &ciphertexts[0]).unwrap()
        );
        decode_inactive_smallwood_v7_statement_for_context(&bytes, &fixture_context()).unwrap();
    }

    #[test]
    fn ciphertext_hash_has_rfc7693_kats_and_rejects_same_length_mutation() {
        assert_eq!(
            hex::encode(
                inactive_smallwood_v7_ciphertext_hash(0, &[1, 2, 3])
                    .unwrap()
                    .as_bytes()
            ),
            "ab43a16e1a4065c19ea17b28c3d11dcf9490d3233d42f6dd84e0e1df3d9ebbc733cced56ef46acbe09cd0bdadd1883048164fd34e89d93fd"
        );
        assert_eq!(
            hex::encode(
                inactive_smallwood_v7_ciphertext_hash(1, &[4, 5, 6, 7])
                    .unwrap()
                    .as_bytes()
            ),
            "05d199e09eb96fa9a7d0faa485bd3d8baabaf762b733e1f77718b223294cf81c6ec0fcb63d155226205f5511a3595c0ec310cb6838a938b2"
        );

        for slot in 0..INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS {
            let ciphertexts = if slot == 0 {
                [vec![1, 2, 3], Vec::new()]
            } else {
                [Vec::new(), vec![4, 5, 6, 7]]
            };
            let mask = if slot == 0 { 0b0100 } else { 0b1000 };
            let statement =
                encode_inactive_smallwood_v7_statement(&fixture_statement(mask, &ciphertexts))
                    .unwrap();
            let envelope = InactiveSmallwoodV7Envelope::from_parts(statement, &[9]).unwrap();
            let mut action = InactiveSmallwoodV7InlineArgs::new(envelope, ciphertexts).unwrap();
            action.ciphertexts[slot][0] ^= 1;
            assert_eq!(
                action.validate(),
                Err(InactiveSmallwoodV7CodecError::CiphertextHashMismatch(slot))
            );
        }
    }

    #[test]
    fn envelope_and_action_preserve_proof_bytes_and_bind_prospective_action_id() {
        let ciphertexts = [vec![1, 2, 3], Vec::new()];
        let statement =
            encode_inactive_smallwood_v7_statement(&fixture_statement(0b0101, &ciphertexts))
                .unwrap();
        let proof = [9, 8, 7, 6];
        let envelope = InactiveSmallwoodV7Envelope::from_parts(statement, &proof).unwrap();
        assert_eq!(envelope.proof_bytes(), proof);
        let action = InactiveSmallwoodV7InlineArgs::new(envelope, ciphertexts).unwrap();
        let canonical = action.canonical_bytes().unwrap();
        let decoded = decode_inactive_smallwood_v7_inline_args(&canonical).unwrap();
        assert_eq!(decoded.envelope().unwrap().proof_bytes(), proof);
        assert_eq!(decoded.canonical_bytes().unwrap(), canonical);

        let original_id = decoded.prospective_action_id().unwrap();
        assert_eq!(
            hex::encode(original_id.as_bytes()),
            "89f518fd94c52815f6f8a7504718bdc3ee27c77b1361ebbedae2819d2077d70c7c00270a33d8409ef25a88247ee24c8d889023944fe66017"
        );
        let mut mutated = decoded.clone();
        let proof_offset =
            INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES + INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES;
        mutated.envelope[proof_offset] ^= 1;
        assert_ne!(mutated.prospective_action_id().unwrap(), original_id);
        assert_eq!(
            inactive_smallwood_v7_reject_live_action_id48_alias(original_id),
            Err(InactiveSmallwoodV7CodecError::LiveActionId48AliasingForbidden)
        );
    }

    #[test]
    fn identity_is_reserved_and_not_an_activation_flag() {
        assert_eq!(INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION, 7);
        assert_eq!(INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA, 6);
        assert_eq!(INACTIVE_SMALLWOOD_V7_ACTION_ID, 9);
        assert_eq!(INACTIVE_SMALLWOOD_V7_BACKEND_ID, 3);
        assert_eq!(INACTIVE_SMALLWOOD_V7_PROOF_PROFILE, 4);
        assert!(!INACTIVE_SMALLWOOD_V7_PRODUCTION_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_ADMISSION_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_LIVE_STABLECOIN_REFINEMENT_AVAILABLE);
        assert!(!INACTIVE_SMALLWOOD_V7_PROSPECTIVE_ACTION_ID_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_LIVE_ACTION_ID48_REFINEMENT_AVAILABLE);
        assert!(
            INACTIVE_SMALLWOOD_V7_MAX_OPAQUE_PROOF_TRANSPORT_BYTES > 512 * 1024,
            "the diagnostic transport bound must not masquerade as the old proof cap"
        );
    }

    #[test]
    fn prospective_56_byte_stablecoin_fields_do_not_refine_live_48_byte_authorities() {
        let ciphertexts = [vec![1, 2, 3], Vec::new()];
        let mut statement = fixture_statement(0b0101, &ciphertexts);
        statement.stablecoin.enabled = true;
        statement.stablecoin.asset_id = 1;
        statement.stablecoin.policy_hash = InactiveSmallwoodV7PolicyHash56::new([21; 56]);
        statement.stablecoin.oracle_commitment =
            InactiveSmallwoodV7OracleCommitment56::new([22; 56]);
        statement.stablecoin.attestation_commitment =
            InactiveSmallwoodV7AttestationCommitment56::new([23; 56]);
        assert_eq!(
            encode_inactive_smallwood_v7_statement(&statement),
            Err(InactiveSmallwoodV7CodecError::LiveStablecoinRefinementUnavailable)
        );
    }

    #[test]
    fn all_activation_context_fields_are_exact() {
        let ciphertexts = [vec![1, 2, 3], Vec::new()];
        let statement = fixture_statement(0b0101, &ciphertexts);
        let expected = fixture_context();
        validate_inactive_smallwood_v7_activation_context(&statement, &expected).unwrap();

        let mut mismatches = [expected; 4];
        mismatches[0].network_id ^= 1;
        mismatches[1].chain_id = InactiveSmallwoodV7ChainId56::new([31; 56]);
        mismatches[2].genesis_id = InactiveSmallwoodV7GenesisId56::new([32; 56]);
        mismatches[3].rules_hash = InactiveSmallwoodV7RulesHash56::new([33; 56]);
        for mismatch in mismatches {
            assert!(
                validate_inactive_smallwood_v7_activation_context(&statement, &mismatch).is_err()
            );
        }
    }
}
