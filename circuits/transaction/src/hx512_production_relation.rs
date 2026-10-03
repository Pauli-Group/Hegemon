//! Inactive, byte-exact W64 transaction relation grammar.
//!
//! This module is deliberately a parser, semantic materializer, and typed
//! hash-source registry only.  It allocates no production identity, proof
//! profile, compiler authority, consensus route, or release authority.  The
//! caller must supply the exact still-unallocated identity and chain binding
//! expected by its test or review context.
//!
//! The action-intent dependency graph is intentionally acyclic:
//!
//! 1. hash the canonical statement while omitting the two derived nullifiers,
//!    the action-intent field itself, and the mint issuer-authorization tag;
//! 2. copy that digest into the verifier-owned context and, when stablecoin is
//!    enabled, the V3 stablecoin public suffix;
//! 3. derive the V3 mint issuer authorization over its exact 251-byte public
//!    prefix (which now contains the resolved intent) and the issuer secret;
//! 4. bind the complete canonical statement and proof at the outer action and
//!    transcript layers.  Those outer layers are not implemented here.

use protocol_kernel::stablecoin_manifest_authority_v2::blake2b512_personalized_v2;
use protocol_kernel::stablecoin_transition_v3::{
    verify_stablecoin_transition_v3, StablecoinTransitionDirectionV3, StablecoinTransitionPublicV3,
    StablecoinTransitionRootV3, StablecoinTransitionV3Error, StablecoinTransitionVerifierContextV3,
    StablecoinTransitionWitnessV3, STABLECOIN_TRANSITION_V3_ASSET_ID_OFFSET,
    STABLECOIN_TRANSITION_V3_BURN_COMPRESSIONS, STABLECOIN_TRANSITION_V3_BURN_HASH_CALLS,
    STABLECOIN_TRANSITION_V3_DEPTH, STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
    STABLECOIN_TRANSITION_V3_ISSUER_AUTHORIZATION_PREIMAGE_BYTES,
    STABLECOIN_TRANSITION_V3_MINT_COMPRESSIONS, STABLECOIN_TRANSITION_V3_MINT_HASH_CALLS,
    STABLECOIN_TRANSITION_V3_POLICY_VERSION_OFFSET,
    STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_DEBT_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_EPOCH_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_MINTED_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_SEQUENCE_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE, STABLECOIN_TRANSITION_V3_PUBLIC_BYTES,
    STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC_RANGE, STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_VERSION_RANGE, STABLECOIN_TRANSITION_V3_ROW_BYTES,
    STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE,
    STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE, STABLECOIN_TRANSITION_V3_WITNESS_BYTES,
    STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE,
    STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE,
    STABLECOIN_TRANSITION_V3_WITNESS_MAGIC_RANGE, STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE,
    STABLECOIN_TRANSITION_V3_WITNESS_VERSION_RANGE,
};

#[cfg(all(
    feature = "hx512-refinement-evidence",
    not(feature = "hx512-working-proof-runner"),
    not(debug_assertions)
))]
compile_error!(
    "the hx512-refinement-evidence feature is test/debug evidence and is forbidden in release builds"
);

/// Exact proof-public statement width.
pub const HX512_STATEMENT_BYTES: usize = 668 + STABLECOIN_TRANSITION_V3_PUBLIC_BYTES;
/// Exact verifier-owned context: current stable root, parent height, action intent.
pub const HX512_VERIFIER_CONTEXT_BYTES: usize = 64 + 8 + 64;
/// Exact private witness width, parameterized by the frozen V3 codec.
pub const HX512_WITNESS_BYTES: usize =
    HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_BYTES;
pub const HX512_DIGEST_BYTES: usize = 64;
pub const HX512_INPUT_BYTES: usize = 2_384;
pub const HX512_OUTPUT_BYTES: usize = 264;
pub const HX512_AUTHORIZATION_BYTES: usize = 792;
pub const HX512_POLICY_MASTERS_BYTES: usize = 128;
pub const HX512_CIPHERTEXT_BYTES: usize = 2_147;
pub const HX512_CIPHERTEXT_TRANSPORT_BYTES: usize = 2_152;
pub const HX512_CIPHERTEXT_PADDING_BYTES: usize = 5;
pub const HX512_MAX_VALUE: u64 = (1u64 << 61) - 1;
pub const HX512_PADDING_ASSET: u64 = u64::MAX;
pub const HX512_ODD_FIELD_MODULUS: u64 = 0xffff_ffff_0000_0001;
pub const HX512_RESERVED_REDUCED_PADDING_ASSET: u64 = HX512_PADDING_ASSET % HX512_ODD_FIELD_MODULUS;

pub const HX512_INPUT_0_OFFSET: usize = 0;
pub const HX512_INPUT_1_OFFSET: usize = 2_384;
pub const HX512_OUTPUT_0_OFFSET: usize = 4_768;
pub const HX512_OUTPUT_1_OFFSET: usize = 5_032;
pub const HX512_AUTHORIZATION_OFFSET: usize = 5_296;
pub const HX512_POLICY_MASTERS_OFFSET: usize = 6_088;
pub const HX512_CIPHERTEXT_0_OFFSET: usize = 6_216;
pub const HX512_CIPHERTEXT_1_OFFSET: usize = 8_368;
pub const HX512_STABLE_WITNESS_OFFSET: usize = 10_520;

pub const HX512_STATEMENT_IDENTITY_OFFSET: usize = 0;
pub const HX512_STATEMENT_IDENTITY_BYTES: usize = 26;
pub const HX512_STATEMENT_CHAIN_ID_OFFSET: usize = 26;
pub const HX512_STATEMENT_GENESIS_ID_OFFSET: usize = 58;
pub const HX512_STATEMENT_RULES_HASH_OFFSET: usize = 122;
pub const HX512_STATEMENT_ACTIVITY_MASK_OFFSET: usize = 186;
pub const HX512_STATEMENT_ANCHOR_OFFSET: usize = 187;
pub const HX512_STATEMENT_NULLIFIERS_OFFSET: usize = 251;
pub const HX512_STATEMENT_COMMITMENTS_OFFSET: usize = 379;
pub const HX512_STATEMENT_CIPHERTEXT_HASHES_OFFSET: usize = 507;
pub const HX512_STATEMENT_ASSET_SLOTS_OFFSET: usize = 635;
pub const HX512_STATEMENT_FEE_OFFSET: usize = 659;
pub const HX512_STATEMENT_VALUE_BALANCE_ZERO_OFFSET: usize = 667;
pub const HX512_STATEMENT_STABLE_PUBLIC_OFFSET: usize = 668;
pub const HX512_STATEMENT_ACTION_INTENT_OFFSET: usize = HX512_STATEMENT_STABLE_PUBLIC_OFFSET
    + STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE.start;
pub const HX512_STATEMENT_ISSUER_AUTHORIZATION_OFFSET: usize = HX512_STATEMENT_STABLE_PUBLIC_OFFSET
    + STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start;
pub const HX512_ACTION_INTENT_MESSAGE_BYTES: usize = HX512_STATEMENT_NULLIFIERS_OFFSET
    + (HX512_STATEMENT_ACTION_INTENT_OFFSET - HX512_STATEMENT_COMMITMENTS_OFFSET)
    + (HX512_STATEMENT_ISSUER_AUTHORIZATION_OFFSET
        - HX512_STATEMENT_ACTION_INTENT_OFFSET
        - STABLECOIN_TRANSITION_V3_DIGEST_BYTES);
pub const HX512_SPEND_PLAN_MESSAGE_BYTES: usize = HX512_STATEMENT_ANCHOR_OFFSET
    + (HX512_STATEMENT_ACTION_INTENT_OFFSET - HX512_STATEMENT_COMMITMENTS_OFFSET);
pub const HX512_STABLE_LEAF_MESSAGE_BYTES: usize = (STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE
    .end
    - STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.start)
    + STABLECOIN_TRANSITION_V3_ROW_BYTES;
pub const HX512_STABLE_ISSUER_COMMITMENT_MESSAGE_BYTES: usize =
    (STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.end
        - STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.start)
        + (STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.end
            - STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.start)
        + STABLECOIN_TRANSITION_V3_DIGEST_BYTES;

/// No public identifier has been allocated for this candidate.
pub const HX512_PRODUCTION_IDENTITY_ALLOCATED: bool = false;
/// Stable V3 was replayed at the exact frozen kernel codec checkpoint.
pub const HX512_STABLE_SURFACE_FROZEN: bool = true;
/// Semantic call counts and byte-source KATs are frozen; proof-profile
/// parameters are intentionally outside this registry.
pub const HX512_HASH_REGISTRY_FROZEN: bool = true;
/// The overall grammar has not received a release freeze.
pub const HX512_RELATION_GRAMMAR_FROZEN: bool = false;
/// The parser is not a proof-system compiler.
pub const HX512_RELATION_COMPILER_COMPLETE: bool = false;
/// Rust/materializer to algebraic-verifier refinement remains open.
pub const HX512_RUST_VERIFIER_REFINEMENT_COMPLETE: bool = false;
/// No complete-ZK certificate is attached to this grammar.
pub const HX512_COMPLETE_ZK_AUTHORIZED: bool = false;
/// No composed PQ/QROM certificate is attached to this grammar.
pub const HX512_PQ_QROM_AUTHORIZED: bool = false;
/// No native consensus path may accept this candidate.
pub const HX512_CONSENSUS_ROUTE_AUTHORIZED: bool = false;
/// This module can never authorize production by itself.
pub const HX512_PRODUCTION_AUTHORIZED: bool = false;
/// The fixture feature is deliberately outside every production build and
/// admission path.  It exposes deterministic private witness material only to
/// independent refinement harnesses.
pub const HX512_REFINEMENT_EVIDENCE_FEATURE_ENABLED: bool =
    cfg!(feature = "hx512-refinement-evidence");
pub const HX512_REFINEMENT_EVIDENCE_PRODUCTION_FORBIDDEN: bool = true;
pub const HX512_REFINEMENT_FIXTURE_COUNT: usize = 5 * 3 * 2;
pub const HX512_MODE_MASK_REFINEMENT_CASE_COUNT: usize = 5 * 16;
pub const HX512_MODE_MASK_REFINEMENT_ACCEPTED_COUNT: usize = 26;
pub const HX512_MODE_MASK_REFINEMENT_REJECTED_COUNT: usize = 54;

const _: [(); 983] = [(); HX512_STATEMENT_BYTES];
const _: [(); 136] = [(); HX512_VERIFIER_CONTEXT_BYTES];
const _: [(); STABLECOIN_TRANSITION_V3_PUBLIC_BYTES] =
    [(); STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.end];
const _: [(); STABLECOIN_TRANSITION_V3_WITNESS_BYTES] =
    [(); STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.end];
const _: [(); STABLECOIN_TRANSITION_V3_DIGEST_BYTES] = [(); HX512_DIGEST_BYTES];
const _: [(); STABLECOIN_TRANSITION_V3_DIGEST_BYTES] = [();
    STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE.end
        - STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE.start];
const _: [(); STABLECOIN_TRANSITION_V3_DIGEST_BYTES] = [();
    STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE.end
        - STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE.start];
const _: [(); STABLECOIN_TRANSITION_V3_DIGEST_BYTES] = [();
    STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE.end
        - STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE.start];
const _: [(); STABLECOIN_TRANSITION_V3_DIGEST_BYTES] = [();
    STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.end
        - STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start];
const _: [(); STABLECOIN_TRANSITION_V3_ROW_BYTES] = [();
    STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.end
        - STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.start];
const _: [(); STABLECOIN_TRANSITION_V3_ROW_BYTES] = [();
    STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.end
        - STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.start];
const _: [(); STABLECOIN_TRANSITION_V3_DEPTH * STABLECOIN_TRANSITION_V3_DIGEST_BYTES] = [();
    STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.end
        - STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.start];
const _: [(); STABLECOIN_TRANSITION_V3_DIGEST_BYTES] = [();
    STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.end
        - STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.start];
const _: [(); 727] = [(); HX512_ACTION_INTENT_MESSAGE_BYTES];
const _: [(); 503] = [(); HX512_SPEND_PLAN_MESSAGE_BYTES];
const _: [(); 4 + STABLECOIN_TRANSITION_V3_ROW_BYTES] = [(); HX512_STABLE_LEAF_MESSAGE_BYTES];
const _: [(); 72] = [(); HX512_STABLE_ISSUER_COMMITMENT_MESSAGE_BYTES];
const _: () = {
    assert!(STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC_RANGE.start == 0);
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_VERSION_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_VERSION_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_EPOCH_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_MINTED_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_EPOCH_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_DEBT_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_MINTED_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_SEQUENCE_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_DEBT_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start
            == STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_SEQUENCE_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.end
            == STABLECOIN_TRANSITION_V3_PUBLIC_BYTES
    );
    assert!(STABLECOIN_TRANSITION_V3_WITNESS_MAGIC_RANGE.start == 0);
    assert!(
        STABLECOIN_TRANSITION_V3_WITNESS_VERSION_RANGE.start
            == STABLECOIN_TRANSITION_V3_WITNESS_MAGIC_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.start
            == STABLECOIN_TRANSITION_V3_WITNESS_VERSION_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.start
            == STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.start
            == STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.start
            == STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.start
            == STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.end
    );
    assert!(
        STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.end
            == STABLECOIN_TRANSITION_V3_WITNESS_BYTES
    );
    assert!(STABLECOIN_TRANSITION_V3_ASSET_ID_OFFSET == 0);
    assert!(
        STABLECOIN_TRANSITION_V3_POLICY_VERSION_OFFSET
            == STABLECOIN_TRANSITION_V3_ASSET_ID_OFFSET
                + (STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.end
                    - STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.start)
    );
    assert!(
        STABLECOIN_TRANSITION_V3_POLICY_VERSION_OFFSET
            + (STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.end
                - STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.start)
            <= STABLECOIN_TRANSITION_V3_ROW_BYTES
    );
};

const ROLE_NOTE: [u8; 8] = *b"nt.b5121";
const ROLE_NULLIFIER: [u8; 8] = *b"nf.b5121";
const ROLE_MERKLE: [u8; 8] = *b"mk.b5121";
const ROLE_SPEND_A: [u8; 8] = *b"sk.b51a1";
const ROLE_SPEND_B: [u8; 8] = *b"sk.b51b1";
const ROLE_AUTH_POLICY: [u8; 8] = *b"pl.b5121";
const ROLE_AUTH_A: [u8; 8] = *b"au.b51a1";
const ROLE_AUTH_B: [u8; 8] = *b"au.b51b1";
const ROLE_CIPHERTEXT: [u8; 8] = *b"ct.b5121";
const LANE_A: [u8; 8] = *b"lane.A51";
const LANE_B: [u8; 8] = *b"lane.B51";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512UnallocatedIdentity {
    pub magic: [u8; 8],
    pub statement_grammar: u16,
    pub circuit_version: u16,
    pub crypto_suite: u16,
    pub family_id: u16,
    pub action_id: u16,
    pub backend_id: u8,
    pub proof_profile: u8,
    pub domain_set: u16,
    pub network_id: u32,
}

impl Hx512UnallocatedIdentity {
    pub fn encode_exact(self) -> [u8; HX512_STATEMENT_IDENTITY_BYTES] {
        let mut out = [0u8; HX512_STATEMENT_IDENTITY_BYTES];
        out[..8].copy_from_slice(&self.magic);
        out[8..10].copy_from_slice(&self.statement_grammar.to_be_bytes());
        out[10..12].copy_from_slice(&self.circuit_version.to_be_bytes());
        out[12..14].copy_from_slice(&self.crypto_suite.to_be_bytes());
        out[14..16].copy_from_slice(&self.family_id.to_be_bytes());
        out[16..18].copy_from_slice(&self.action_id.to_be_bytes());
        out[18] = self.backend_id;
        out[19] = self.proof_profile;
        out[20..22].copy_from_slice(&self.domain_set.to_be_bytes());
        out[22..26].copy_from_slice(&self.network_id.to_be_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512ExpectedStatementBinding {
    pub identity: Hx512UnallocatedIdentity,
    pub chain_id: [u8; 32],
    pub genesis_id: [u8; 64],
    pub rules_hash: [u8; 64],
}

/// Grammar-owned raw evidence for independent materializer/compiler replay.
///
/// This type exists only under the off-by-default evidence feature.  Its
/// bytes are deterministic test values, never production secrets or validity
/// authority.
#[cfg(feature = "hx512-refinement-evidence")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512RefinementFixture {
    pub mode: Hx512AuthorizationMode,
    pub stable_direction: StablecoinTransitionDirectionV3,
    pub secret_variant: u8,
    pub statement: Vec<u8>,
    pub context: Vec<u8>,
    pub witness: Vec<u8>,
    pub expected_binding: Hx512ExpectedStatementBinding,
}

#[cfg(feature = "hx512-refinement-evidence")]
impl Hx512RefinementFixture {
    /// Read-only spelling used by verifier/refinement consumers while the
    /// stored field preserves the grammar's canonical `context` name.
    pub fn verifier_context(&self) -> &[u8] {
        &self.context
    }
}

/// One production-grammar classification in the exact five-mode by
/// sixteen-mask refinement matrix.
///
/// Accepted cases carry canonical raw material that the independent compiler
/// can replay. Rejected cases deliberately carry no substitute witness: their
/// exact `RejectedModeMask` error is produced by the same grammar predicate
/// called by the production materializer.
#[cfg(feature = "hx512-refinement-evidence")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ModeMaskRefinementCase {
    pub mode: Hx512AuthorizationMode,
    pub activity_mask: u8,
    pub classification: Hx512ModeMaskRefinementClassification,
}

#[cfg(feature = "hx512-refinement-evidence")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hx512ModeMaskRefinementClassification {
    Accepted {
        statement: Vec<u8>,
        context: Vec<u8>,
        witness: Vec<u8>,
        expected_binding: Hx512ExpectedStatementBinding,
    },
    RejectedModeMask {
        error: Hx512RelationError,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Hx512AuthorizationMode {
    SingleKey = 0,
    AccumulatorInit = 1,
    ApprovalStep = 2,
    ValueLockCreation = 3,
    FinalThresholdSpend = 4,
}

pub const HX512_AUTHORIZATION_MODES: [Hx512AuthorizationMode; 5] = [
    Hx512AuthorizationMode::SingleKey,
    Hx512AuthorizationMode::AccumulatorInit,
    Hx512AuthorizationMode::ApprovalStep,
    Hx512AuthorizationMode::ValueLockCreation,
    Hx512AuthorizationMode::FinalThresholdSpend,
];

impl TryFrom<u64> for Hx512AuthorizationMode {
    type Error = Hx512RelationError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SingleKey),
            1 => Ok(Self::AccumulatorInit),
            2 => Ok(Self::ApprovalStep),
            3 => Ok(Self::ValueLockCreation),
            4 => Ok(Self::FinalThresholdSpend),
            _ => Err(Hx512RelationError::NonCanonical(
                "authorization mode is outside 0..4",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512HashGate {
    Always,
    StableEnabled,
    StableMint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512HashRole {
    NoteCommitment { slot: u8 },
    Nullifier { slot: u8 },
    MerkleNode { input: u8, level: u8 },
    SpendKey { input: u8, lane: u8 },
    AuthorizationPolicy,
    AuthorizationState { slot: u8, lane: u8 },
    ActionIntent,
    SpendPlan,
    Ciphertext { output: u8 },
    StableBeforeLeaf,
    StableBeforeNode { level: u8 },
    StableAfterLeaf,
    StableAfterNode { level: u8 },
    StableIssuerCommitment,
    StableIssuerAuthorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512WireSurface {
    Statement,
    VerifierContext,
    Witness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512ByteRange {
    pub surface: Hx512WireSurface,
    pub offset: usize,
    pub bytes: usize,
}

impl Hx512ByteRange {
    const fn statement(offset: usize, bytes: usize) -> Self {
        Self {
            surface: Hx512WireSurface::Statement,
            offset,
            bytes,
        }
    }

    const fn witness(offset: usize, bytes: usize) -> Self {
        Self {
            surface: Hx512WireSurface::Witness,
            offset,
            bytes,
        }
    }

    const fn context(offset: usize, bytes: usize) -> Self {
        Self {
            surface: Hx512WireSurface::VerifierContext,
            offset,
            bytes,
        }
    }
}

/// Typed source operands for one hash-call slot.
///
/// Each variant names the canonical decoder/selection recipe; byte ranges are
/// included wherever the source is a direct wire range.  `Note` applies the
/// documented note-field reordering, `Nullifier` uses the mode-resolved lane-B
/// key, `Merkle` orders its child and sibling with the selected position bit,
/// and authorization variants use the five-mode mux before hashing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hx512HashSourceRecipe {
    Note {
        slot: u8,
        note_wire: Hx512ByteRange,
    },
    Nullifier {
        input: u8,
        position: Hx512ByteRange,
        rho: Hx512ByteRange,
    },
    Merkle {
        input: u8,
        level: u8,
        position: Hx512ByteRange,
        sibling: Hx512ByteRange,
        child_call_index: usize,
    },
    SpendKey {
        input: u8,
        lane: u8,
        master: Hx512ByteRange,
    },
    AuthorizationPolicy {
        authorization: Hx512ByteRange,
        policy_masters: Hx512ByteRange,
    },
    AuthorizationState {
        slot: u8,
        lane: u8,
        authorization: Hx512ByteRange,
        policy_masters: Hx512ByteRange,
    },
    ActionIntent {
        statement_ranges: [Hx512ByteRange; 3],
    },
    SpendPlan {
        statement_ranges: [Hx512ByteRange; 2],
    },
    Ciphertext {
        output: u8,
        ciphertext: Hx512ByteRange,
    },
    StableLeaf {
        before: bool,
        index: Hx512ByteRange,
        row: Hx512ByteRange,
    },
    StableNode {
        before: bool,
        level: u8,
        index: Hx512ByteRange,
        sibling: Hx512ByteRange,
        child_call_index: usize,
    },
    StableIssuerCommitment {
        asset_id: Hx512ByteRange,
        policy_version: Hx512ByteRange,
        issuer_secret: Hx512ByteRange,
    },
    StableIssuerAuthorization {
        public_prefix: Hx512ByteRange,
        issuer_secret: Hx512ByteRange,
    },
}

/// One exact byte source used to build a hash-call message.  A literal is
/// candidate/test-context data supplied to the registry constructor, never an
/// allocated production identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hx512HashAtomSource {
    Literal(Vec<u8>),
    Surface(Hx512ByteRange),
    PriorDigest { call_index: usize },
}

impl Hx512HashAtomSource {
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Literal(bytes) => bytes.len(),
            Self::Surface(range) => range.bytes,
            Self::PriorDigest { .. } => HX512_DIGEST_BYTES,
        }
    }
}

/// Exact selector bit for a source-order or mode-independent byte mux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512HashBitSource {
    pub byte: Hx512ByteRange,
    /// Least-significant-bit numbering within `byte`.
    pub bit_in_byte: u8,
}

/// One ordered atom of an exact hash message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hx512HashMessageAtom {
    Copy(Hx512HashAtomSource),
    /// Copy the low byte of a canonical u64be Boolean/small-enum word.
    LowByte(Hx512ByteRange),
    /// Copy one of two equally-sized sources according to one committed bit.
    Select {
        selector: Hx512HashBitSource,
        when_zero: Hx512HashAtomSource,
        when_one: Hx512HashAtomSource,
    },
}

impl Hx512HashMessageAtom {
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Copy(source) => source.byte_len(),
            Self::LowByte(_) => 1,
            Self::Select {
                when_zero,
                when_one,
                ..
            } => {
                debug_assert_eq!(when_zero.byte_len(), when_one.byte_len());
                when_zero.byte_len()
            }
        }
    }
}

/// Fully expanded, byte-ordered message recipe for one call and one
/// authorization mode.  Concatenating `atoms` is the complete BLAKE2b message;
/// no host-computed or unnamed source bytes remain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ExactHashMessageRecipe {
    pub call_index: usize,
    pub mode: Hx512AuthorizationMode,
    pub atoms: Vec<Hx512HashMessageAtom>,
    pub message_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512HashTargetCondition {
    Always,
    InputActive(u8),
    OutputActive(u8),
    StableEnabled,
    StableMint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512HashDigestTarget {
    pub range: Hx512ByteRange,
    pub condition: Hx512HashTargetCondition,
}

impl Hx512ExactHashMessageRecipe {
    pub fn derived_message_bytes(&self) -> usize {
        self.atoms.iter().map(Hx512HashMessageAtom::byte_len).sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512CompressionSchedule {
    pub message_bytes: usize,
    pub counters: Vec<u64>,
    pub final_flags: Vec<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512HashCallRecipe {
    pub index: usize,
    pub role: Hx512HashRole,
    pub gate: Hx512HashGate,
    pub source: Hx512HashSourceRecipe,
    pub personalization: [u8; 16],
    /// One schedule for fixed calls; all selectable schedules for a mux call.
    pub schedules: Vec<Hx512CompressionSchedule>,
    /// Exact selected message width for modes
    /// `[SingleKey, Init, Approval, ValueLock, Final]`.
    pub message_bytes_by_authorization_mode: Option<[usize; 5]>,
    /// Shape allocation, independent of the selected message bytes.
    pub max_compressions: usize,
    /// Exact proof-public/verifier-context digest copies owned by this call.
    pub public_digest_targets: Vec<Hx512HashDigestTarget>,
}

/// Full typed registry surface consumed by a topology/compiler adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512TypedHashCallRegistry {
    pub statement_bytes: usize,
    pub verifier_context_bytes: usize,
    pub witness_bytes: usize,
    pub authorization_mode_source: Hx512ByteRange,
    pub calls: Vec<Hx512HashCallRecipe>,
    pub frozen: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512RelationShape {
    pub statement_bytes: usize,
    pub verifier_context_bytes: usize,
    pub witness_bytes: usize,
    pub accepted_mode_mask_pairs: usize,
    pub rejected_mode_mask_pairs: usize,
    pub hash_call_slots: usize,
    pub max_blake2b512_compressions: usize,
    pub predicate_families: usize,
    pub registry_frozen: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512ActiveHashAccounting {
    pub active_calls: usize,
    pub active_compressions: usize,
    pub provisional: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hx512PredicateFamily {
    ExactIdentityAndChainBinding,
    CanonicalStatementAndContext,
    CanonicalWitness,
    ActivityModeLookup,
    InactiveSlotZeroing,
    AssetSlotCanonicality,
    NoteRangesAndSelectors,
    NoteCommitments,
    NullifiersAndDistinctness,
    MerkleAnchor,
    AuthorizationModes,
    ActionIntentDag,
    SpendPlanDag,
    CiphertextBinding,
    DirectValueBalanceZero,
    PerAssetBalance,
    StablePublicRefinement,
    StableWitnessRefinement,
    StableVerifierContext,
    StableTransition,
}

pub const HX512_PREDICATE_FAMILIES: [Hx512PredicateFamily; 20] = [
    Hx512PredicateFamily::ExactIdentityAndChainBinding,
    Hx512PredicateFamily::CanonicalStatementAndContext,
    Hx512PredicateFamily::CanonicalWitness,
    Hx512PredicateFamily::ActivityModeLookup,
    Hx512PredicateFamily::InactiveSlotZeroing,
    Hx512PredicateFamily::AssetSlotCanonicality,
    Hx512PredicateFamily::NoteRangesAndSelectors,
    Hx512PredicateFamily::NoteCommitments,
    Hx512PredicateFamily::NullifiersAndDistinctness,
    Hx512PredicateFamily::MerkleAnchor,
    Hx512PredicateFamily::AuthorizationModes,
    Hx512PredicateFamily::ActionIntentDag,
    Hx512PredicateFamily::SpendPlanDag,
    Hx512PredicateFamily::CiphertextBinding,
    Hx512PredicateFamily::DirectValueBalanceZero,
    Hx512PredicateFamily::PerAssetBalance,
    Hx512PredicateFamily::StablePublicRefinement,
    Hx512PredicateFamily::StableWitnessRefinement,
    Hx512PredicateFamily::StableVerifierContext,
    Hx512PredicateFamily::StableTransition,
];

/// Audit-only lowering classification for one host predicate family.
///
/// `fixed_vector_expressible` answers only whether the predicate over already
/// allocated fixed-size public/witness bit vectors admits the existing
/// SmallWood polynomial interface.  It does not claim that the current
/// V6-specific builder can instantiate this candidate.  In particular, raw
/// byte-buffer length/cap checks are native parser obligations and every row
/// remains uncompiled while the identity, V3 surface, hash registry, and
/// dedicated HX512 adapter are unfrozen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512CompilerCoverageEntry {
    pub family: Hx512PredicateFamily,
    pub host_predicates: &'static str,
    pub scalar_strategy: &'static str,
    pub reuse_seam: &'static str,
    pub maximum_local_degree: u8,
    pub fixed_vector_expressible: bool,
    pub requires_blake2b512_trace: bool,
    pub requires_dynamic_select_circuit: bool,
    pub has_external_parser_obligation: bool,
    pub current_v6_adapter_instantiable: bool,
    pub hx512_compiled: bool,
}

/// Exact compiler-coverage audit for every host predicate family in this
/// materializer.  All Boolean, comparison, mux, addition, subtraction, and
/// wide-product recipes decompose to degree-two R1CS identities.  The existing
/// row-polynomial engine accepts degree up to eight, so none of the fixed-vector
/// semantic predicates is intrinsically outside its polynomial language.
///
/// The reusable seams are the `R1csBuilder` bit gadgets in
/// `full_shake448_relation` and the polynomial-template/occurrence-copy packer
/// in `smallwood_v6_adapter`.  The concrete V6 builder itself is not reusable
/// as-is: it is private and hard-codes the V6 893-byte statement projection,
/// 128 public values, raw-bit count, arithmetization, and hash coverage type.
pub const HX512_COMPILER_COVERAGE_MATRIX: [Hx512CompilerCoverageEntry; 20] = [
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::ExactIdentityAndChainBinding,
        host_predicates: "statement[0..26], chain_id[26..58], genesis_id[58..122], and rules_hash[122..186] equal verifier-selected values byte-for-byte",
        scalar_strategy: "bind every public bit; enforce each expected bit with a linear identity after identity/profile allocation",
        reuse_seam: "V6PublicBitBinding plus LinearConstraintBuilder::push",
        maximum_local_degree: 1,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: false,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::CanonicalStatementAndContext,
        host_predicates: "exact 983/136-byte native decode; mask high nibble zero; activity-conditioned anchor/nullifier/commitment/ciphertext nonzero or zero; stable public canonical codec",
        scalar_strategy: "fixed public-bit projection; linear zero/equality; XOR/OR nonzero trees; Boolean enum/optional-field checks",
        reuse_seam: "ensure_symbol_bytes, any_bits, equals_bits, zero_if, equal_if",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: true,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::CanonicalWitness,
        host_predicates: "exact witness width; stable magic/version/enum/optional encoding; Boolean u64be selectors and approvals; five ciphertext padding bytes zero",
        scalar_strategy: "fixed private-bit allocation; constant-bit equality; Boolean identities; high-byte zeroing for Boolean u64 words",
        reuse_seam: "ensure_symbol_bytes, R1csBuilder::assert_constant/assert_false",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: false,
        has_external_parser_obligation: true,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::ActivityModeLookup,
        host_predicates: "five canonical authorization modes crossed with sixteen masks; exactly the listed 26 pairs accept and the other 54 reject",
        scalar_strategy: "one-hot 5-mode and 16-mask selectors; 80 quadratic pair products; accepted-pair sum equals one and rejected-pair sum equals zero",
        reuse_seam: "OneHot5/one-hot linear sum, R1csBuilder::and, assert_linear_zero",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::InactiveSlotZeroing,
        host_predicates: "inactive input/output public fields, complete private slots, ciphertext bytes, and no-input anchor are zero; active digest surfaces are nonzero",
        scalar_strategy: "selector times each bit equals zero; active nonzero is a balanced OR tree followed by implication",
        reuse_seam: "zero_if, nonzero_if, R1csBuilder::imply/and/or",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::AssetSlotCanonicality,
        host_predicates: "implicit native slot zero; three nonnative slots form a strict ascending nonzero field-injective prefix then u64::MAX padding; reserved reduced-padding representative rejected",
        scalar_strategy: "presence/padding selectors, bitwise equality and unsigned less-than, prefix implications, and conditional strict-order identities",
        reuse_seam: "equals_bits, less_than_bits, equal_if, imply, asset-order QIR",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::NoteRangesAndSelectors,
        host_predicates: "active kind in 0..2, value at most 61 bits, asset below Goldilocks and not the reserved reduced-padding value; four selectors Boolean/one-hot and selected slot equals note asset",
        scalar_strategy: "high-bit zeroing, constant comparison, four selector one-hot, and selector-gated 64-bit equality",
        reuse_seam: "less_than_bits, equals_bits, OneHot mux, assert_eq_if",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::NoteCommitments,
        host_predicates: "four exact 256-byte framed note preimages; output digests equal active public commitments",
        scalar_strategy: "linear source-copy identities into an RFC 7693 BLAKE2b-512 Boolean trace, then conditional digest-bit equality",
        reuse_seam: "mixed-hash aggregate seam plus identity_from_shake_constraint_for_mixed and pack_mixed_executable_relation",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: true,
        requires_dynamic_select_circuit: false,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::NullifiersAndDistinctness,
        host_predicates: "mode-resolved lane-B authorization key, position and rho form each 143-byte preimage; active digest equals public nullifier; two active nullifiers are distinct",
        scalar_strategy: "five-mode digest mux; BLAKE2b trace; gated output equality; XOR/OR equality tree with active-pair implication",
        reuse_seam: "OneHotMux5, equals_bits, any_bits, assert_eq_if",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: true,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::MerkleAnchor,
        host_predicates: "active position is 32-bit; each of 32 position bits orders child/sibling in the exact 149-byte node frame; active final roots equal the common anchor",
        scalar_strategy: "high-bit zeroing; bit-select source muxes; 64 BLAKE2b node traces; conditional final digest equality",
        reuse_seam: "R1csBuilder::select, zero_if, hash prior-output dependency wiring",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: true,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::AuthorizationModes,
        host_predicates: "mode-specific zero/ordinary/value-lock note shapes; policy/opening selection; signer prefix nonzero/distinct; threshold/count/popcount bounds; Approval exact-one signer transition; Final threshold and plan check; digest/key routing",
        scalar_strategy: "five one-hot mode selectors; gated zero/equality; 1..6 comparators; approval popcount adders; pairwise tag equality trees; exact-one membership selectors; current/next field muxes; authorization BLAKE2b traces",
        reuse_seam: "authorization QIR families, OneHotMux5, add_bits, less_than_bits, equals_bits, zero_if/equal_if",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: true,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::ActionIntentDag,
        host_predicates: "hash statement[0..251] || statement[379..695] || statement[759..919], excluding derived nullifiers, its own field, and issuer tag; digest nonzero and equals verifier context plus enabled stable suffix",
        scalar_strategy: "linear source-copy projection into the exact 727-byte personalized BLAKE2b trace; digest OR and equality identities",
        reuse_seam: "public source_wire_index, hash source/output equality audit, any_bits/equal_if",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: true,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::SpendPlanDag,
        host_predicates: "hash statement[0..187] || statement[379..695] as the exact 503-byte personalized preimage; compare only in FinalThresholdSpend",
        scalar_strategy: "linear source-copy projection into BLAKE2b; final-mode-gated digest equality",
        reuse_seam: "hash source equality plus R1csBuilder::assert_eq_if",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: true,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::CiphertextBinding,
        host_predicates: "each transport allocates exactly 2152 bytes, its final five bytes are zero, and the exact 2147-byte ciphertext plus family/domain/output/width frame hashes to the active public digest",
        scalar_strategy: "fixed-vector geometry and padding zero identities; exact 2182-byte source copy; BLAKE2b trace; output-active digest equality",
        reuse_seam: "fixed QIR byte sources, zero_if, hash trace output binding",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: true,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: true,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::DirectValueBalanceZero,
        host_predicates: "statement byte 667 is the unique zero sentinel",
        scalar_strategy: "eight public-bit linear zero identities",
        reuse_seam: "V6PublicBitBinding plus LinearConstraintBuilder::push",
        maximum_local_degree: 1,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: false,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::PerAssetBalance,
        host_predicates: "for each of four slots: native inputs=outputs+fee; Mint stable inputs+magnitude=outputs; Burn stable inputs=outputs+magnitude; every other asset inputs=outputs",
        scalar_strategy: "selector-gated 61-bit values, direction/asset equality selectors, 63-bit ripple-carry additions, and equality including final carries to exclude field wrap",
        reuse_seam: "add_bits, equals_bits, select, Balance QIR family",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::StablePublicRefinement,
        host_predicates: "exact V3 magic/version/direction codec; disabled suffix unique ZERO; enabled u32 asset zero-extends to exactly one nonnative slot; magnitude range; action intent and public after-state fields map exactly",
        scalar_strategy: "constant/equality identities, three-way direction one-hot, equality-count one, gated zeroing, high-bit zeroing, and public field-copy identities",
        reuse_seam: "Stablecoin QIR family, OneHot mux, equals_bits, zero_if/equal_if",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: true,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::StableWitnessRefinement,
        host_predicates: "exact V3 witness magic/version/index, two 453-byte rows, four siblings and issuer secret; canonical row booleans and optional retirement; disabled witness unique ZERO",
        scalar_strategy: "fixed private-bit allocation, constants, Boolean identities, 4-bit index range, optional-presence-gated zeroing, and disabled-direction zeroing",
        reuse_seam: "ensure_symbol_bytes, zero_if/equal_if, less_than_bits",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: true,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::StableVerifierContext,
        host_predicates: "enabled current root equals public before root; parent height directly drives epoch/lifecycle freshness; expected intent equals recomputed outer action; disabled root/height are zero",
        scalar_strategy: "public context bit bindings, direction-gated equality/zeroing, and bit extraction for parent_height >> 12",
        reuse_seam: "public raw-bit bindings, equal_if, zero_if, select",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: false,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
    Hx512CompilerCoverageEntry {
        family: Hx512PredicateFamily::StableTransition,
        host_predicates: "policy-slot index; before/after membership; static-row equality; common ranges, nonzero pairwise-distinct authority/custody commitments, and decimal scale; Mint lifecycle/oracle/attestation freshness, issuer hashes, cap/debt/sequence and collateral ratio; Burn zero issuer material and debt subtraction; exact public successor",
        scalar_strategy: "4-bit slot equality; bit-selected Merkle traces; gated field equality; Boolean/range/comparator gadgets; checked add/sub with carry/borrow; decimal-scale 19-way lookup; schoolbook 32/64/128-bit products with carry bounds and unsigned comparison; gated issuer BLAKE2b traces",
        reuse_seam: "Stablecoin QIR family, add_bits/less_than_bits/equals_bits/select, mixed-hash prior-output dependencies",
        maximum_local_degree: 2,
        fixed_vector_expressible: true,
        requires_blake2b512_trace: true,
        requires_dynamic_select_circuit: true,
        has_external_parser_obligation: false,
        current_v6_adapter_instantiable: false,
        hx512_compiled: false,
    },
];

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Hx512RelationError {
    #[error("{surface} must be exactly {expected} bytes, got {actual}")]
    WrongLength {
        surface: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("statement identity or consensus binding mismatch: {0}")]
    Binding(&'static str),
    #[error("noncanonical HX512 encoding: {0}")]
    NonCanonical(&'static str),
    #[error("authorization mode {mode:?} rejects activity mask {mask:#04x}")]
    RejectedModeMask {
        mode: Hx512AuthorizationMode,
        mask: u8,
    },
    #[error("semantic binding mismatch: {0}")]
    Semantic(&'static str),
    #[error("stablecoin V3 rejected: {0:?}")]
    Stablecoin(StablecoinTransitionV3Error),
    #[error("hx512-refinement-evidence is forbidden as production authority")]
    RefinementEvidenceFeatureEnabled,
}

impl From<StablecoinTransitionV3Error> for Hx512RelationError {
    fn from(value: StablecoinTransitionV3Error) -> Self {
        Self::Stablecoin(value)
    }
}

fn schedule(message_bytes: usize) -> Hx512CompressionSchedule {
    let blocks = core::cmp::max(1, message_bytes.div_ceil(128));
    Hx512CompressionSchedule {
        message_bytes,
        counters: (0..blocks)
            .map(|block| core::cmp::min((block + 1) * 128, message_bytes) as u64)
            .collect(),
        final_flags: (0..blocks).map(|block| block + 1 == blocks).collect(),
    }
}

fn intent_personalization(identity: Hx512UnallocatedIdentity, label: [u8; 6]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&identity.magic);
    out[8..14].copy_from_slice(&label);
    out[14..].copy_from_slice(&identity.domain_set.to_be_bytes());
    out
}

fn stable_personalization(role: u8, level: u8) -> [u8; 16] {
    [
        b'H', b'G', b'S', b'C', b'T', b'R', b'V', b'3', role, 3, 64, 4, level, 0, 0, 0,
    ]
}

fn hx512_hash_source_recipe(role: Hx512HashRole) -> Hx512HashSourceRecipe {
    let input_offset = |input: u8| usize::from(input) * HX512_INPUT_BYTES;
    let stable_index = Hx512ByteRange::witness(
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.start,
        STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.len(),
    );
    let stable_before_row =
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.start;
    let stable_after_row =
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.start;
    let stable_siblings =
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.start;
    let stable_secret =
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.start;
    match role {
        Hx512HashRole::NoteCommitment { slot } => {
            let offset = match slot {
                0 => HX512_INPUT_0_OFFSET + 64,
                1 => HX512_INPUT_1_OFFSET + 64,
                2 => HX512_OUTPUT_0_OFFSET,
                3 => HX512_OUTPUT_1_OFFSET,
                _ => unreachable!("registry constructs four note slots"),
            };
            Hx512HashSourceRecipe::Note {
                slot,
                note_wire: Hx512ByteRange::witness(offset, 232),
            }
        }
        Hx512HashRole::Nullifier { slot } => {
            let base = input_offset(slot);
            Hx512HashSourceRecipe::Nullifier {
                input: slot,
                position: Hx512ByteRange::witness(base + 296, 8),
                rho: Hx512ByteRange::witness(base + 120, 48),
            }
        }
        Hx512HashRole::MerkleNode { input, level } => {
            let base = input_offset(input);
            let child_call_index = if level == 0 {
                usize::from(input)
            } else {
                6 + usize::from(input) * 32 + usize::from(level) - 1
            };
            Hx512HashSourceRecipe::Merkle {
                input,
                level,
                position: Hx512ByteRange::witness(base + 296, 8),
                sibling: Hx512ByteRange::witness(base + 304 + usize::from(level) * 64, 64),
                child_call_index,
            }
        }
        Hx512HashRole::SpendKey { input, lane } => Hx512HashSourceRecipe::SpendKey {
            input,
            lane,
            master: Hx512ByteRange::witness(input_offset(input), 64),
        },
        Hx512HashRole::AuthorizationPolicy => Hx512HashSourceRecipe::AuthorizationPolicy {
            authorization: Hx512ByteRange::witness(
                HX512_AUTHORIZATION_OFFSET,
                HX512_AUTHORIZATION_BYTES,
            ),
            policy_masters: Hx512ByteRange::witness(
                HX512_POLICY_MASTERS_OFFSET,
                HX512_POLICY_MASTERS_BYTES,
            ),
        },
        Hx512HashRole::AuthorizationState { slot, lane } => {
            Hx512HashSourceRecipe::AuthorizationState {
                slot,
                lane,
                authorization: Hx512ByteRange::witness(
                    HX512_AUTHORIZATION_OFFSET,
                    HX512_AUTHORIZATION_BYTES,
                ),
                policy_masters: Hx512ByteRange::witness(
                    HX512_POLICY_MASTERS_OFFSET,
                    HX512_POLICY_MASTERS_BYTES,
                ),
            }
        }
        Hx512HashRole::ActionIntent => Hx512HashSourceRecipe::ActionIntent {
            statement_ranges: [
                Hx512ByteRange::statement(0, HX512_STATEMENT_NULLIFIERS_OFFSET),
                Hx512ByteRange::statement(
                    HX512_STATEMENT_COMMITMENTS_OFFSET,
                    HX512_STATEMENT_ACTION_INTENT_OFFSET - HX512_STATEMENT_COMMITMENTS_OFFSET,
                ),
                Hx512ByteRange::statement(
                    HX512_STATEMENT_ACTION_INTENT_OFFSET + STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
                    HX512_STATEMENT_ISSUER_AUTHORIZATION_OFFSET
                        - HX512_STATEMENT_ACTION_INTENT_OFFSET
                        - STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
                ),
            ],
        },
        Hx512HashRole::SpendPlan => Hx512HashSourceRecipe::SpendPlan {
            statement_ranges: [
                Hx512ByteRange::statement(0, HX512_STATEMENT_ANCHOR_OFFSET),
                Hx512ByteRange::statement(
                    HX512_STATEMENT_COMMITMENTS_OFFSET,
                    HX512_STATEMENT_ACTION_INTENT_OFFSET - HX512_STATEMENT_COMMITMENTS_OFFSET,
                ),
            ],
        },
        Hx512HashRole::Ciphertext { output } => Hx512HashSourceRecipe::Ciphertext {
            output,
            ciphertext: Hx512ByteRange::witness(
                HX512_CIPHERTEXT_0_OFFSET + usize::from(output) * HX512_CIPHERTEXT_TRANSPORT_BYTES,
                HX512_CIPHERTEXT_BYTES,
            ),
        },
        Hx512HashRole::StableBeforeLeaf => Hx512HashSourceRecipe::StableLeaf {
            before: true,
            index: stable_index,
            row: Hx512ByteRange::witness(stable_before_row, STABLECOIN_TRANSITION_V3_ROW_BYTES),
        },
        Hx512HashRole::StableAfterLeaf => Hx512HashSourceRecipe::StableLeaf {
            before: false,
            index: stable_index,
            row: Hx512ByteRange::witness(stable_after_row, STABLECOIN_TRANSITION_V3_ROW_BYTES),
        },
        Hx512HashRole::StableBeforeNode { level } => Hx512HashSourceRecipe::StableNode {
            before: true,
            level,
            index: stable_index,
            sibling: Hx512ByteRange::witness(
                stable_siblings + usize::from(level) * STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
                STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
            ),
            child_call_index: if level == 0 {
                83
            } else {
                83 + usize::from(level)
            },
        },
        Hx512HashRole::StableAfterNode { level } => Hx512HashSourceRecipe::StableNode {
            before: false,
            level,
            index: stable_index,
            sibling: Hx512ByteRange::witness(
                stable_siblings + usize::from(level) * STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
                STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
            ),
            child_call_index: if level == 0 {
                88
            } else {
                88 + usize::from(level)
            },
        },
        Hx512HashRole::StableIssuerCommitment => Hx512HashSourceRecipe::StableIssuerCommitment {
            asset_id: Hx512ByteRange::witness(
                stable_before_row + STABLECOIN_TRANSITION_V3_ASSET_ID_OFFSET,
                STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.len(),
            ),
            policy_version: Hx512ByteRange::witness(
                stable_before_row + STABLECOIN_TRANSITION_V3_POLICY_VERSION_OFFSET,
                STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.len(),
            ),
            issuer_secret: Hx512ByteRange::witness(
                stable_secret,
                STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.len(),
            ),
        },
        Hx512HashRole::StableIssuerAuthorization => {
            Hx512HashSourceRecipe::StableIssuerAuthorization {
                public_prefix: Hx512ByteRange::statement(
                    HX512_STATEMENT_STABLE_PUBLIC_OFFSET,
                    STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start,
                ),
                issuer_secret: Hx512ByteRange::witness(
                    stable_secret,
                    STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.len(),
                ),
            }
        }
    }
}

fn hx512_hash_public_targets(role: Hx512HashRole) -> Vec<Hx512HashDigestTarget> {
    let statement = |offset, condition| Hx512HashDigestTarget {
        range: Hx512ByteRange::statement(offset, HX512_DIGEST_BYTES),
        condition,
    };
    let context = |offset, condition| Hx512HashDigestTarget {
        range: Hx512ByteRange::context(offset, HX512_DIGEST_BYTES),
        condition,
    };
    match role {
        Hx512HashRole::NoteCommitment {
            slot: slot @ (2 | 3),
        } => vec![statement(
            HX512_STATEMENT_COMMITMENTS_OFFSET + (usize::from(slot) - 2) * HX512_DIGEST_BYTES,
            Hx512HashTargetCondition::OutputActive(slot - 2),
        )],
        Hx512HashRole::Nullifier { slot } => vec![statement(
            HX512_STATEMENT_NULLIFIERS_OFFSET + usize::from(slot) * HX512_DIGEST_BYTES,
            Hx512HashTargetCondition::InputActive(slot),
        )],
        Hx512HashRole::MerkleNode { input, level: 31 } => vec![statement(
            HX512_STATEMENT_ANCHOR_OFFSET,
            Hx512HashTargetCondition::InputActive(input),
        )],
        Hx512HashRole::ActionIntent => vec![
            context(72, Hx512HashTargetCondition::Always),
            statement(
                HX512_STATEMENT_ACTION_INTENT_OFFSET,
                Hx512HashTargetCondition::StableEnabled,
            ),
        ],
        Hx512HashRole::Ciphertext { output } => vec![statement(
            HX512_STATEMENT_CIPHERTEXT_HASHES_OFFSET + usize::from(output) * HX512_DIGEST_BYTES,
            Hx512HashTargetCondition::OutputActive(output),
        )],
        Hx512HashRole::StableBeforeNode { level: 3 } => vec![
            statement(
                HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                    + STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE.start,
                Hx512HashTargetCondition::StableEnabled,
            ),
            context(0, Hx512HashTargetCondition::StableEnabled),
        ],
        Hx512HashRole::StableAfterNode { level: 3 } => vec![statement(
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE.start,
            Hx512HashTargetCondition::StableEnabled,
        )],
        Hx512HashRole::StableIssuerAuthorization => vec![statement(
            HX512_STATEMENT_ISSUER_AUTHORIZATION_OFFSET,
            Hx512HashTargetCondition::StableMint,
        )],
        _ => Vec::new(),
    }
}

fn push_recipe(
    recipes: &mut Vec<Hx512HashCallRecipe>,
    role: Hx512HashRole,
    gate: Hx512HashGate,
    personalization: [u8; 16],
    message_lengths: &[usize],
) {
    let source = hx512_hash_source_recipe(role);
    let public_digest_targets = hx512_hash_public_targets(role);
    let message_bytes_by_authorization_mode = match role {
        Hx512HashRole::AuthorizationState { slot: 0, .. } => Some([136, 263, 263, 225, 263]),
        Hx512HashRole::AuthorizationState { slot: 1, .. } => Some([136, 136, 263, 136, 225]),
        _ => None,
    };
    let schedules: Vec<_> = message_lengths.iter().copied().map(schedule).collect();
    let max_compressions = schedules
        .iter()
        .map(|item| item.counters.len())
        .max()
        .unwrap_or(0);
    recipes.push(Hx512HashCallRecipe {
        index: recipes.len(),
        role,
        gate,
        source,
        personalization,
        schedules,
        message_bytes_by_authorization_mode,
        max_compressions,
        public_digest_targets,
    });
}

/// Return the fixed, secret-independent hash-source shape.
///
/// Stable issuer calls are present as Mint-gated slots even for Burn and
/// Disabled instances, so the allocated topology never depends on witness
/// bytes.  Authorization slots similarly carry all three possible source
/// lengths and allocate their three-compression maximum.
pub fn hx512_hash_call_recipe_registry(
    identity: Hx512UnallocatedIdentity,
) -> Vec<Hx512HashCallRecipe> {
    let mut recipes = Vec::with_capacity(95);
    for slot in 0..4 {
        push_recipe(
            &mut recipes,
            Hx512HashRole::NoteCommitment { slot },
            Hx512HashGate::Always,
            [0u8; 16],
            &[256],
        );
    }
    for slot in 0..2 {
        push_recipe(
            &mut recipes,
            Hx512HashRole::Nullifier { slot },
            Hx512HashGate::Always,
            [0u8; 16],
            &[143],
        );
    }
    for input in 0..2 {
        for level in 0..32 {
            push_recipe(
                &mut recipes,
                Hx512HashRole::MerkleNode { input, level },
                Hx512HashGate::Always,
                [0u8; 16],
                &[149],
            );
        }
    }
    for lane in 0..2 {
        for input in 0..2 {
            push_recipe(
                &mut recipes,
                Hx512HashRole::SpendKey { input, lane },
                Hx512HashGate::Always,
                [0u8; 16],
                &[93],
            );
        }
    }
    push_recipe(
        &mut recipes,
        Hx512HashRole::AuthorizationPolicy,
        Hx512HashGate::Always,
        [0u8; 16],
        &[499],
    );
    for lane in 0..2 {
        for slot in 0..2 {
            push_recipe(
                &mut recipes,
                Hx512HashRole::AuthorizationState { slot, lane },
                Hx512HashGate::Always,
                [0u8; 16],
                &[136, 225, 263],
            );
        }
    }
    push_recipe(
        &mut recipes,
        Hx512HashRole::ActionIntent,
        Hx512HashGate::Always,
        intent_personalization(identity, *b"ACTINT"),
        &[HX512_ACTION_INTENT_MESSAGE_BYTES],
    );
    push_recipe(
        &mut recipes,
        Hx512HashRole::SpendPlan,
        Hx512HashGate::Always,
        intent_personalization(identity, *b"SPPLAN"),
        &[HX512_SPEND_PLAN_MESSAGE_BYTES],
    );
    for output in 0..2 {
        push_recipe(
            &mut recipes,
            Hx512HashRole::Ciphertext { output },
            Hx512HashGate::Always,
            [0u8; 16],
            &[2_182],
        );
    }
    push_recipe(
        &mut recipes,
        Hx512HashRole::StableBeforeLeaf,
        Hx512HashGate::StableEnabled,
        stable_personalization(2, 0),
        &[HX512_STABLE_LEAF_MESSAGE_BYTES],
    );
    for level in 0..4 {
        push_recipe(
            &mut recipes,
            Hx512HashRole::StableBeforeNode { level },
            Hx512HashGate::StableEnabled,
            stable_personalization(3, level),
            &[128],
        );
    }
    push_recipe(
        &mut recipes,
        Hx512HashRole::StableAfterLeaf,
        Hx512HashGate::StableEnabled,
        stable_personalization(2, 0),
        &[HX512_STABLE_LEAF_MESSAGE_BYTES],
    );
    for level in 0..4 {
        push_recipe(
            &mut recipes,
            Hx512HashRole::StableAfterNode { level },
            Hx512HashGate::StableEnabled,
            stable_personalization(3, level),
            &[128],
        );
    }
    push_recipe(
        &mut recipes,
        Hx512HashRole::StableIssuerCommitment,
        Hx512HashGate::StableMint,
        stable_personalization(1, 0),
        &[HX512_STABLE_ISSUER_COMMITMENT_MESSAGE_BYTES],
    );
    push_recipe(
        &mut recipes,
        Hx512HashRole::StableIssuerAuthorization,
        Hx512HashGate::StableMint,
        stable_personalization(4, 0),
        &[STABLECOIN_TRANSITION_V3_ISSUER_AUTHORIZATION_PREIMAGE_BYTES],
    );
    debug_assert_eq!(recipes.len(), 95);
    recipes
}

/// Return the complete semantic compiler input, including the exact
/// private selector source used by every five-mode authorization call.
pub fn hx512_typed_hash_call_registry(
    identity: Hx512UnallocatedIdentity,
) -> Hx512TypedHashCallRegistry {
    Hx512TypedHashCallRegistry {
        statement_bytes: HX512_STATEMENT_BYTES,
        verifier_context_bytes: HX512_VERIFIER_CONTEXT_BYTES,
        witness_bytes: HX512_WITNESS_BYTES,
        authorization_mode_source: Hx512ByteRange::witness(HX512_AUTHORIZATION_OFFSET, 8),
        calls: hx512_hash_call_recipe_registry(identity),
        frozen: HX512_HASH_REGISTRY_FROZEN,
    }
}

fn atom_literal(bytes: impl Into<Vec<u8>>) -> Hx512HashMessageAtom {
    Hx512HashMessageAtom::Copy(Hx512HashAtomSource::Literal(bytes.into()))
}

fn atom_surface(range: Hx512ByteRange) -> Hx512HashMessageAtom {
    Hx512HashMessageAtom::Copy(Hx512HashAtomSource::Surface(range))
}

fn atom_digest(call_index: usize) -> Hx512HashMessageAtom {
    Hx512HashMessageAtom::Copy(Hx512HashAtomSource::PriorDigest { call_index })
}

fn framed_message_atoms(
    role: [u8; 8],
    fields: Vec<Vec<Hx512HashMessageAtom>>,
) -> Result<Vec<Hx512HashMessageAtom>, Hx512RelationError> {
    let field_count = u8::try_from(fields.len())
        .map_err(|_| Hx512RelationError::NonCanonical("hash frame has more than 255 fields"))?;
    // The magic is a committed statement source, not a private constant.
    let mut atoms = vec![
        atom_surface(Hx512ByteRange::statement(0, 8)),
        atom_literal(role),
        atom_literal(vec![field_count]),
    ];
    for field in fields {
        let field_bytes = field
            .iter()
            .map(Hx512HashMessageAtom::byte_len)
            .sum::<usize>();
        let field_bytes = u16::try_from(field_bytes).map_err(|_| {
            Hx512RelationError::NonCanonical("hash frame field exceeds u16 length grammar")
        })?;
        atoms.push(atom_literal(field_bytes.to_be_bytes()));
        atoms.extend(field);
    }
    Ok(atoms)
}

fn auth_opening_start(next: bool) -> usize {
    HX512_AUTHORIZATION_OFFSET + if next { 208 } else { 8 }
}

fn auth_master_start(next: bool) -> usize {
    HX512_POLICY_MASTERS_OFFSET + usize::from(next) * 64
}

fn accumulator_message_fields(next: bool, lane: u8) -> Vec<Vec<Hx512HashMessageAtom>> {
    let opening = auth_opening_start(next);
    let lane_tag = if lane == 0 { LANE_A } else { LANE_B };
    vec![
        vec![atom_surface(Hx512ByteRange::witness(
            auth_master_start(next),
            64,
        ))],
        vec![atom_literal(lane_tag)],
        vec![atom_surface(Hx512ByteRange::witness(opening, 64))],
        vec![atom_surface(Hx512ByteRange::witness(opening + 64, 64))],
        vec![atom_surface(Hx512ByteRange::witness(opening + 128, 8))],
        vec![atom_surface(Hx512ByteRange::witness(opening + 136, 8))],
        vec![atom_surface(Hx512ByteRange::witness(opening + 144, 8))],
        (0..6)
            .map(|slot| {
                Hx512HashMessageAtom::LowByte(Hx512ByteRange::witness(opening + 152 + slot * 8, 8))
            })
            .collect(),
    ]
}

fn value_lock_message_fields(next: bool, lane: u8) -> Vec<Vec<Hx512HashMessageAtom>> {
    let opening = auth_opening_start(next);
    let lane_tag = if lane == 0 { LANE_A } else { LANE_B };
    vec![
        vec![atom_surface(Hx512ByteRange::witness(
            auth_master_start(next),
            64,
        ))],
        vec![atom_literal(lane_tag)],
        vec![atom_surface(Hx512ByteRange::witness(opening, 64))],
        vec![atom_surface(Hx512ByteRange::witness(opening + 64, 64))],
    ]
}

fn dummy_authorization_message_fields(slot: u8, lane: u8) -> Vec<Vec<Hx512HashMessageAtom>> {
    let mut payload = vec![0u8; 117];
    payload[0] = slot;
    payload[1] = lane;
    vec![vec![atom_literal(payload)]]
}

fn authorization_message_fields(
    mode: Hx512AuthorizationMode,
    slot: u8,
    lane: u8,
) -> Vec<Vec<Hx512HashMessageAtom>> {
    match (mode, slot) {
        (Hx512AuthorizationMode::SingleKey, _) => dummy_authorization_message_fields(slot, lane),
        (Hx512AuthorizationMode::AccumulatorInit, 0) => accumulator_message_fields(true, lane),
        (Hx512AuthorizationMode::ApprovalStep, 0)
        | (Hx512AuthorizationMode::FinalThresholdSpend, 0) => {
            accumulator_message_fields(false, lane)
        }
        (Hx512AuthorizationMode::ValueLockCreation, 0) => value_lock_message_fields(false, lane),
        (Hx512AuthorizationMode::ApprovalStep, 1) => accumulator_message_fields(true, lane),
        (Hx512AuthorizationMode::FinalThresholdSpend, 1) => value_lock_message_fields(false, lane),
        _ => dummy_authorization_message_fields(slot, lane),
    }
}

fn selected_pair_atoms(
    selector: Hx512HashBitSource,
    child_call_index: usize,
    sibling: Hx512ByteRange,
) -> [Hx512HashMessageAtom; 2] {
    let child = Hx512HashAtomSource::PriorDigest {
        call_index: child_call_index,
    };
    let sibling = Hx512HashAtomSource::Surface(sibling);
    [
        Hx512HashMessageAtom::Select {
            selector,
            when_zero: child.clone(),
            when_one: sibling.clone(),
        },
        Hx512HashMessageAtom::Select {
            selector,
            when_zero: sibling,
            when_one: child,
        },
    ]
}

/// Expand one typed call slot into the exact byte concatenation compiled for a
/// particular authorization mode.  Fixed calls return the same atoms for all
/// five modes.  Every atom is a literal, committed public/private range, prior
/// hash digest, low-byte extraction, or explicit one-bit source mux.
pub fn hx512_exact_hash_message_recipe(
    identity: Hx512UnallocatedIdentity,
    call_index: usize,
    mode: Hx512AuthorizationMode,
) -> Result<Hx512ExactHashMessageRecipe, Hx512RelationError> {
    let registry = hx512_hash_call_recipe_registry(identity);
    let call = registry
        .get(call_index)
        .ok_or(Hx512RelationError::NonCanonical(
            "hash call index is outside registry",
        ))?;
    let atoms = match call.role {
        Hx512HashRole::NoteCommitment { slot } => {
            let note = match slot {
                0 => HX512_INPUT_0_OFFSET + 64,
                1 => HX512_INPUT_1_OFFSET + 64,
                2 => HX512_OUTPUT_0_OFFSET,
                3 => HX512_OUTPUT_1_OFFSET,
                _ => return Err(Hx512RelationError::NonCanonical("note slot exceeds four")),
            };
            framed_message_atoms(
                ROLE_NOTE,
                vec![
                    vec![atom_surface(Hx512ByteRange::witness(note + 104, 64))],
                    vec![Hx512HashMessageAtom::LowByte(Hx512ByteRange::witness(
                        note, 8,
                    ))],
                    vec![atom_surface(Hx512ByteRange::witness(note + 8, 8))],
                    vec![atom_surface(Hx512ByteRange::witness(note + 16, 8))],
                    vec![atom_surface(Hx512ByteRange::witness(note + 24, 32))],
                    vec![atom_surface(Hx512ByteRange::witness(note + 56, 48))],
                    vec![atom_surface(Hx512ByteRange::witness(note + 168, 64))],
                ],
            )?
        }
        Hx512HashRole::Nullifier { slot } => {
            let input = usize::from(slot);
            let key_call = match (input, mode) {
                (0, Hx512AuthorizationMode::SingleKey)
                | (0, Hx512AuthorizationMode::AccumulatorInit)
                | (0, Hx512AuthorizationMode::ValueLockCreation) => 72,
                (0, Hx512AuthorizationMode::ApprovalStep) => 77,
                (0, Hx512AuthorizationMode::FinalThresholdSpend) => 78,
                (1, Hx512AuthorizationMode::SingleKey)
                | (1, Hx512AuthorizationMode::AccumulatorInit)
                | (1, Hx512AuthorizationMode::ApprovalStep)
                | (1, Hx512AuthorizationMode::ValueLockCreation) => 73,
                (1, Hx512AuthorizationMode::FinalThresholdSpend) => 77,
                _ => {
                    return Err(Hx512RelationError::NonCanonical(
                        "nullifier input exceeds two",
                    ));
                }
            };
            let input_start = input * HX512_INPUT_BYTES;
            framed_message_atoms(
                ROLE_NULLIFIER,
                vec![
                    vec![atom_digest(key_call)],
                    vec![atom_surface(Hx512ByteRange::witness(input_start + 296, 8))],
                    vec![atom_surface(Hx512ByteRange::witness(input_start + 120, 48))],
                ],
            )?
        }
        Hx512HashRole::MerkleNode { input, level } => {
            let input_start = usize::from(input) * HX512_INPUT_BYTES;
            let child_call_index = if level == 0 {
                usize::from(input)
            } else {
                6 + usize::from(input) * 32 + usize::from(level) - 1
            };
            let selector = Hx512HashBitSource {
                byte: Hx512ByteRange::witness(input_start + 296 + 7 - usize::from(level) / 8, 1),
                bit_in_byte: level % 8,
            };
            let pair = selected_pair_atoms(
                selector,
                child_call_index,
                Hx512ByteRange::witness(input_start + 304 + usize::from(level) * 64, 64),
            );
            framed_message_atoms(
                ROLE_MERKLE,
                vec![vec![pair[0].clone()], vec![pair[1].clone()]],
            )?
        }
        Hx512HashRole::SpendKey { input, lane } => {
            let lane_tag = if lane == 0 { LANE_A } else { LANE_B };
            let role = if lane == 0 {
                ROLE_SPEND_A
            } else {
                ROLE_SPEND_B
            };
            framed_message_atoms(
                role,
                vec![
                    vec![atom_literal(lane_tag)],
                    vec![atom_surface(Hx512ByteRange::witness(
                        usize::from(input) * HX512_INPUT_BYTES,
                        64,
                    ))],
                ],
            )?
        }
        Hx512HashRole::AuthorizationPolicy => {
            let next = mode == Hx512AuthorizationMode::AccumulatorInit;
            let opening = auth_opening_start(next);
            let mut fields = vec![
                vec![atom_surface(Hx512ByteRange::witness(
                    auth_master_start(next),
                    64,
                ))],
                vec![atom_surface(Hx512ByteRange::witness(opening + 128, 8))],
                vec![atom_surface(Hx512ByteRange::witness(opening + 136, 8))],
            ];
            fields.extend((0..6).map(|slot| {
                vec![atom_surface(Hx512ByteRange::witness(
                    HX512_AUTHORIZATION_OFFSET + 408 + slot * 64,
                    64,
                ))]
            }));
            framed_message_atoms(ROLE_AUTH_POLICY, fields)?
        }
        Hx512HashRole::AuthorizationState { slot, lane } => {
            let role = if lane == 0 { ROLE_AUTH_A } else { ROLE_AUTH_B };
            framed_message_atoms(role, authorization_message_fields(mode, slot, lane))?
        }
        Hx512HashRole::ActionIntent => vec![
            atom_surface(Hx512ByteRange::statement(
                0,
                HX512_STATEMENT_NULLIFIERS_OFFSET,
            )),
            atom_surface(Hx512ByteRange::statement(
                HX512_STATEMENT_COMMITMENTS_OFFSET,
                HX512_STATEMENT_ACTION_INTENT_OFFSET - HX512_STATEMENT_COMMITMENTS_OFFSET,
            )),
            atom_surface(Hx512ByteRange::statement(
                HX512_STATEMENT_ACTION_INTENT_OFFSET + STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
                HX512_STATEMENT_ISSUER_AUTHORIZATION_OFFSET
                    - HX512_STATEMENT_ACTION_INTENT_OFFSET
                    - STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
            )),
        ],
        Hx512HashRole::SpendPlan => vec![
            atom_surface(Hx512ByteRange::statement(0, HX512_STATEMENT_ANCHOR_OFFSET)),
            atom_surface(Hx512ByteRange::statement(
                HX512_STATEMENT_COMMITMENTS_OFFSET,
                HX512_STATEMENT_ACTION_INTENT_OFFSET - HX512_STATEMENT_COMMITMENTS_OFFSET,
            )),
        ],
        Hx512HashRole::Ciphertext { output } => framed_message_atoms(
            ROLE_CIPHERTEXT,
            vec![
                vec![atom_literal(vec![0x52])],
                vec![atom_surface(Hx512ByteRange::statement(20, 2))],
                vec![atom_literal(vec![output])],
                vec![atom_literal((HX512_CIPHERTEXT_BYTES as u32).to_be_bytes())],
                vec![atom_surface(Hx512ByteRange::witness(
                    HX512_CIPHERTEXT_0_OFFSET
                        + usize::from(output) * HX512_CIPHERTEXT_TRANSPORT_BYTES,
                    HX512_CIPHERTEXT_BYTES,
                ))],
            ],
        )?,
        Hx512HashRole::StableBeforeLeaf | Hx512HashRole::StableAfterLeaf => {
            let before = matches!(call.role, Hx512HashRole::StableBeforeLeaf);
            let row = if before {
                HX512_STABLE_WITNESS_OFFSET
                    + STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.start
            } else {
                HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.start
            };
            vec![
                atom_surface(Hx512ByteRange::witness(
                    HX512_STABLE_WITNESS_OFFSET
                        + STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.start,
                    STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.len(),
                )),
                atom_surface(Hx512ByteRange::witness(
                    row,
                    STABLECOIN_TRANSITION_V3_ROW_BYTES,
                )),
            ]
        }
        Hx512HashRole::StableBeforeNode { level } | Hx512HashRole::StableAfterNode { level } => {
            let before = matches!(call.role, Hx512HashRole::StableBeforeNode { .. });
            let child_call_index = if before {
                if level == 0 {
                    83
                } else {
                    83 + usize::from(level)
                }
            } else if level == 0 {
                88
            } else {
                88 + usize::from(level)
            };
            let siblings =
                HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.start;
            let selector = Hx512HashBitSource {
                byte: Hx512ByteRange::witness(
                    HX512_STABLE_WITNESS_OFFSET
                        + STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.start
                        + usize::from(level) / 8,
                    1,
                ),
                bit_in_byte: level % 8,
            };
            selected_pair_atoms(
                selector,
                child_call_index,
                Hx512ByteRange::witness(
                    siblings + usize::from(level) * STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
                    STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
                ),
            )
            .into_iter()
            .collect()
        }
        Hx512HashRole::StableIssuerCommitment => {
            let before_row = HX512_STABLE_WITNESS_OFFSET
                + STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.start;
            let secret = HX512_STABLE_WITNESS_OFFSET
                + STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.start;
            vec![
                atom_surface(Hx512ByteRange::witness(
                    before_row + STABLECOIN_TRANSITION_V3_ASSET_ID_OFFSET,
                    STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.len(),
                )),
                atom_surface(Hx512ByteRange::witness(
                    before_row + STABLECOIN_TRANSITION_V3_POLICY_VERSION_OFFSET,
                    STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.len(),
                )),
                atom_surface(Hx512ByteRange::witness(
                    secret,
                    STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.len(),
                )),
            ]
        }
        Hx512HashRole::StableIssuerAuthorization => {
            let secret = HX512_STABLE_WITNESS_OFFSET
                + STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.start;
            vec![
                atom_surface(Hx512ByteRange::statement(
                    HX512_STATEMENT_STABLE_PUBLIC_OFFSET,
                    STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start,
                )),
                atom_surface(Hx512ByteRange::witness(
                    secret,
                    STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.len(),
                )),
            ]
        }
    };
    let message_bytes = call
        .message_bytes_by_authorization_mode
        .map(|lengths| lengths[mode as usize])
        .unwrap_or_else(|| call.schedules[0].message_bytes);
    let expanded = Hx512ExactHashMessageRecipe {
        call_index,
        mode,
        atoms,
        message_bytes,
    };
    if expanded.derived_message_bytes() != expanded.message_bytes {
        return Err(Hx512RelationError::Semantic(
            "expanded hash source recipe length differs from compression schedule",
        ));
    }
    Ok(expanded)
}

pub fn hx512_relation_shape(identity: Hx512UnallocatedIdentity) -> Hx512RelationShape {
    let recipes = hx512_hash_call_recipe_registry(identity);
    Hx512RelationShape {
        statement_bytes: HX512_STATEMENT_BYTES,
        verifier_context_bytes: HX512_VERIFIER_CONTEXT_BYTES,
        witness_bytes: HX512_WITNESS_BYTES,
        accepted_mode_mask_pairs: 26,
        rejected_mode_mask_pairs: 54,
        hash_call_slots: recipes.len(),
        max_blake2b512_compressions: recipes.iter().map(|recipe| recipe.max_compressions).sum(),
        predicate_families: HX512_PREDICATE_FAMILIES.len(),
        registry_frozen: HX512_HASH_REGISTRY_FROZEN,
    }
}

/// Current active-call accounting.  The 95-slot compiler shape is fixed for
/// all directions, but semantic gates activate only the V3 branch named here.
/// Counts are exact for the frozen semantic registry.  They make no proof
/// profile or production-security claim.
pub fn hx512_active_hash_accounting(
    direction: StablecoinTransitionDirectionV3,
) -> Hx512ActiveHashAccounting {
    let (stable_calls, stable_compressions) = match direction {
        StablecoinTransitionDirectionV3::Disabled => (0, 0),
        StablecoinTransitionDirectionV3::Mint => (
            STABLECOIN_TRANSITION_V3_MINT_HASH_CALLS,
            STABLECOIN_TRANSITION_V3_MINT_COMPRESSIONS,
        ),
        StablecoinTransitionDirectionV3::Burn => (
            STABLECOIN_TRANSITION_V3_BURN_HASH_CALLS,
            STABLECOIN_TRANSITION_V3_BURN_COMPRESSIONS,
        ),
    };
    Hx512ActiveHashAccounting {
        active_calls: 83 + stable_calls,
        active_compressions: 206 + stable_compressions,
        provisional: !HX512_HASH_REGISTRY_FROZEN,
    }
}

pub fn hx512_activity_mode_accepts(mode: Hx512AuthorizationMode, mask: u8) -> bool {
    if mask & 0xf0 != 0 {
        return false;
    }
    match mode {
        Hx512AuthorizationMode::SingleKey => {
            matches!(
                mask,
                0x05 | 0x06 | 0x07 | 0x09 | 0x0a | 0x0b | 0x0d | 0x0e | 0x0f
            )
        }
        Hx512AuthorizationMode::AccumulatorInit | Hx512AuthorizationMode::ValueLockCreation => {
            matches!(mask, 0x05 | 0x06 | 0x07 | 0x0d | 0x0e | 0x0f)
        }
        Hx512AuthorizationMode::ApprovalStep => matches!(mask, 0x07 | 0x0f),
        Hx512AuthorizationMode::FinalThresholdSpend => matches!(mask, 0x07 | 0x0b | 0x0f),
    }
}

/// Apply the canonical production-grammar mode/mask predicate and preserve its
/// exact rejection classification for refinement consumers.
pub fn ensure_hx512_activity_mode_accepted(
    mode: Hx512AuthorizationMode,
    mask: u8,
) -> Result<(), Hx512RelationError> {
    if hx512_activity_mode_accepts(mode, mask) {
        Ok(())
    } else {
        Err(Hx512RelationError::RejectedModeMask { mode, mask })
    }
}

fn exact_array<const N: usize>(raw: &[u8]) -> [u8; N] {
    raw.try_into()
        .expect("caller supplies an exact fixed slice")
}

fn read_u64be(raw: &[u8]) -> u64 {
    u64::from_be_bytes(exact_array(raw))
}

fn is_zero(raw: &[u8]) -> bool {
    raw.iter().all(|byte| *byte == 0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ProductionStatement {
    raw: [u8; HX512_STATEMENT_BYTES],
    pub identity: Hx512UnallocatedIdentity,
    pub chain_id: [u8; 32],
    pub genesis_id: [u8; 64],
    pub rules_hash: [u8; 64],
    pub activity_mask: u8,
    pub anchor: [u8; 64],
    pub nullifiers: [[u8; 64]; 2],
    pub commitments: [[u8; 64]; 2],
    pub ciphertext_hashes: [[u8; 64]; 2],
    /// Slot zero is the implicit native asset; the statement carries slots 1..3.
    pub asset_slots: [u64; 4],
    pub fee: u64,
    pub stable_public: StablecoinTransitionPublicV3,
}

impl Hx512ProductionStatement {
    pub fn decode_exact(
        raw: &[u8],
        expected: &Hx512ExpectedStatementBinding,
    ) -> Result<Self, Hx512RelationError> {
        if raw.len() != HX512_STATEMENT_BYTES {
            return Err(Hx512RelationError::WrongLength {
                surface: "HX512 statement",
                expected: HX512_STATEMENT_BYTES,
                actual: raw.len(),
            });
        }
        if raw[..HX512_STATEMENT_IDENTITY_BYTES] != expected.identity.encode_exact() {
            return Err(Hx512RelationError::Binding("first 26 identity bytes"));
        }
        if raw[HX512_STATEMENT_CHAIN_ID_OFFSET..HX512_STATEMENT_GENESIS_ID_OFFSET]
            != expected.chain_id
        {
            return Err(Hx512RelationError::Binding("chain id"));
        }
        if raw[HX512_STATEMENT_GENESIS_ID_OFFSET..HX512_STATEMENT_RULES_HASH_OFFSET]
            != expected.genesis_id
        {
            return Err(Hx512RelationError::Binding("genesis id"));
        }
        if raw[HX512_STATEMENT_RULES_HASH_OFFSET..HX512_STATEMENT_ACTIVITY_MASK_OFFSET]
            != expected.rules_hash
        {
            return Err(Hx512RelationError::Binding("rules/release manifest hash"));
        }
        let activity_mask = raw[HX512_STATEMENT_ACTIVITY_MASK_OFFSET];
        if activity_mask & 0xf0 != 0 {
            return Err(Hx512RelationError::NonCanonical(
                "activity-mask high nibble is nonzero",
            ));
        }
        let anchor =
            exact_array(&raw[HX512_STATEMENT_ANCHOR_OFFSET..HX512_STATEMENT_NULLIFIERS_OFFSET]);
        let nullifiers = core::array::from_fn(|index| {
            let start = HX512_STATEMENT_NULLIFIERS_OFFSET + index * HX512_DIGEST_BYTES;
            exact_array(&raw[start..start + HX512_DIGEST_BYTES])
        });
        let commitments = core::array::from_fn(|index| {
            let start = HX512_STATEMENT_COMMITMENTS_OFFSET + index * HX512_DIGEST_BYTES;
            exact_array(&raw[start..start + HX512_DIGEST_BYTES])
        });
        let ciphertext_hashes = core::array::from_fn(|index| {
            let start = HX512_STATEMENT_CIPHERTEXT_HASHES_OFFSET + index * HX512_DIGEST_BYTES;
            exact_array(&raw[start..start + HX512_DIGEST_BYTES])
        });
        let mut asset_slots = [0u64; 4];
        for (index, slot) in asset_slots[1..].iter_mut().enumerate() {
            let start = HX512_STATEMENT_ASSET_SLOTS_OFFSET + index * 8;
            *slot = read_u64be(&raw[start..start + 8]);
        }
        let mut saw_padding = false;
        let mut previous = 0u64;
        for asset in asset_slots[1..].iter().copied() {
            if asset == HX512_PADDING_ASSET {
                saw_padding = true;
                continue;
            }
            if saw_padding
                || asset == 0
                || asset == HX512_RESERVED_REDUCED_PADDING_ASSET
                || asset >= HX512_ODD_FIELD_MODULUS
                || asset <= previous
            {
                return Err(Hx512RelationError::NonCanonical(
                    "non-native asset slots are not a strict sorted prefix followed by u64::MAX padding",
                ));
            }
            previous = asset;
        }
        let fee =
            read_u64be(&raw[HX512_STATEMENT_FEE_OFFSET..HX512_STATEMENT_VALUE_BALANCE_ZERO_OFFSET]);
        if fee > HX512_MAX_VALUE {
            return Err(Hx512RelationError::NonCanonical("fee exceeds 61 bits"));
        }
        if raw[HX512_STATEMENT_VALUE_BALANCE_ZERO_OFFSET] != 0 {
            return Err(Hx512RelationError::NonCanonical(
                "direct value-balance-zero sentinel is nonzero",
            ));
        }
        let stable_raw = &raw[HX512_STATEMENT_STABLE_PUBLIC_OFFSET..];
        let stable_public = StablecoinTransitionPublicV3::decode_canonical(stable_raw)?;
        if stable_public.encode_canonical() != stable_raw {
            return Err(Hx512RelationError::NonCanonical(
                "stablecoin public suffix does not round trip byte-for-byte",
            ));
        }
        if stable_public.direction == StablecoinTransitionDirectionV3::Disabled {
            if stable_public != StablecoinTransitionPublicV3::ZERO {
                return Err(Hx512RelationError::NonCanonical(
                    "disabled stablecoin public suffix is not the canonical V3 ZERO encoding",
                ));
            }
        } else {
            let stable_asset = u64::from(stable_public.asset_id);
            if stable_asset == 0
                || asset_slots[1..]
                    .iter()
                    .filter(|slot| **slot == stable_asset)
                    .count()
                    != 1
            {
                return Err(Hx512RelationError::Semantic(
                    "enabled V3 asset is not the zero-extended unique non-native asset slot",
                ));
            }
        }
        let statement = Self {
            raw: exact_array(raw),
            identity: expected.identity,
            chain_id: expected.chain_id,
            genesis_id: expected.genesis_id,
            rules_hash: expected.rules_hash,
            activity_mask,
            anchor,
            nullifiers,
            commitments,
            ciphertext_hashes,
            asset_slots,
            fee,
            stable_public,
        };
        statement.validate_public_activity_surface()?;
        if statement.stable_public.direction != StablecoinTransitionDirectionV3::Disabled
            && statement.stable_public.action_intent != statement.action_intent_digest()
        {
            return Err(Hx512RelationError::Semantic(
                "stablecoin V3 action intent is not the consensus-owned outer digest",
            ));
        }
        Ok(statement)
    }

    fn validate_public_activity_surface(&self) -> Result<(), Hx512RelationError> {
        let flags = self.activity_flags();
        if flags[0] || flags[1] {
            if is_zero(&self.anchor) {
                return Err(Hx512RelationError::NonCanonical(
                    "active input anchor is zero",
                ));
            }
        } else if !is_zero(&self.anchor) {
            return Err(Hx512RelationError::NonCanonical(
                "no-input activity mask carries a nonzero anchor",
            ));
        }
        for index in 0..2 {
            if flags[index] {
                if is_zero(&self.nullifiers[index]) {
                    return Err(Hx512RelationError::NonCanonical(
                        "active input nullifier is zero",
                    ));
                }
            } else if !is_zero(&self.nullifiers[index]) {
                return Err(Hx512RelationError::NonCanonical(
                    "inactive input nullifier is nonzero",
                ));
            }
            if flags[2 + index] {
                if is_zero(&self.commitments[index]) || is_zero(&self.ciphertext_hashes[index]) {
                    return Err(Hx512RelationError::NonCanonical(
                        "active output commitment or ciphertext hash is zero",
                    ));
                }
            } else if !is_zero(&self.commitments[index]) || !is_zero(&self.ciphertext_hashes[index])
            {
                return Err(Hx512RelationError::NonCanonical(
                    "inactive output public surface is nonzero",
                ));
            }
        }
        if flags[0] && flags[1] && self.nullifiers[0] == self.nullifiers[1] {
            return Err(Hx512RelationError::Semantic(
                "two active inputs carry the same nullifier",
            ));
        }
        Ok(())
    }

    pub fn encode_exact(&self) -> [u8; HX512_STATEMENT_BYTES] {
        self.raw
    }

    pub fn as_bytes(&self) -> &[u8; HX512_STATEMENT_BYTES] {
        &self.raw
    }

    pub fn activity_flags(&self) -> [bool; 4] {
        core::array::from_fn(|index| self.activity_mask & (1 << index) != 0)
    }

    /// BLAKE2b-512 over the exact acyclic outer statement projection.
    pub fn action_intent_digest(&self) -> [u8; 64] {
        let mut message = Vec::with_capacity(HX512_ACTION_INTENT_MESSAGE_BYTES);
        message.extend_from_slice(&self.raw[..HX512_STATEMENT_NULLIFIERS_OFFSET]);
        message.extend_from_slice(
            &self.raw[HX512_STATEMENT_COMMITMENTS_OFFSET..HX512_STATEMENT_ACTION_INTENT_OFFSET],
        );
        message.extend_from_slice(
            &self.raw[HX512_STATEMENT_ACTION_INTENT_OFFSET + STABLECOIN_TRANSITION_V3_DIGEST_BYTES
                ..HX512_STATEMENT_ISSUER_AUTHORIZATION_OFFSET],
        );
        debug_assert_eq!(message.len(), HX512_ACTION_INTENT_MESSAGE_BYTES);
        blake2b512_personalized_v2(&message, intent_personalization(self.identity, *b"ACTINT"))
    }

    /// Stable approval target.  It excludes the anchor and all derived input
    /// nullifiers while binding identity, mask, outputs, fee, and the exact V3
    /// direction/asset/version/magnitude prefix.
    pub fn spend_plan_digest(&self) -> [u8; 64] {
        let mut message = Vec::with_capacity(HX512_SPEND_PLAN_MESSAGE_BYTES);
        message.extend_from_slice(&self.raw[..HX512_STATEMENT_ANCHOR_OFFSET]);
        message.extend_from_slice(
            &self.raw[HX512_STATEMENT_COMMITMENTS_OFFSET..HX512_STATEMENT_ACTION_INTENT_OFFSET],
        );
        debug_assert_eq!(message.len(), HX512_SPEND_PLAN_MESSAGE_BYTES);
        blake2b512_personalized_v2(&message, intent_personalization(self.identity, *b"SPPLAN"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512VerifierContext {
    raw: [u8; HX512_VERIFIER_CONTEXT_BYTES],
    pub stable_current_root: [u8; 64],
    pub parent_height: u64,
    pub expected_action_intent: [u8; 64],
}

impl Hx512VerifierContext {
    pub fn decode_exact(raw: &[u8]) -> Result<Self, Hx512RelationError> {
        if raw.len() != HX512_VERIFIER_CONTEXT_BYTES {
            return Err(Hx512RelationError::WrongLength {
                surface: "HX512 verifier context",
                expected: HX512_VERIFIER_CONTEXT_BYTES,
                actual: raw.len(),
            });
        }
        Ok(Self {
            raw: exact_array(raw),
            stable_current_root: exact_array(&raw[..64]),
            parent_height: u64::from_le_bytes(exact_array(&raw[64..72])),
            expected_action_intent: exact_array(&raw[72..136]),
        })
    }

    pub fn encode_exact(&self) -> [u8; HX512_VERIFIER_CONTEXT_BYTES] {
        self.raw
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512Note {
    pub raw: [u8; 232],
    pub kind: u64,
    pub value: u64,
    pub asset: u64,
    pub recipient: [u8; 32],
    pub rho: [u8; 48],
    pub blinding: [u8; 64],
    pub authorization: [u8; 64],
}

impl Hx512Note {
    fn decode(raw: &[u8]) -> Self {
        Self {
            raw: exact_array(raw),
            kind: read_u64be(&raw[0..8]),
            value: read_u64be(&raw[8..16]),
            asset: read_u64be(&raw[16..24]),
            recipient: exact_array(&raw[24..56]),
            rho: exact_array(&raw[56..104]),
            blinding: exact_array(&raw[104..168]),
            authorization: exact_array(&raw[168..232]),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512Input {
    pub raw: [u8; HX512_INPUT_BYTES],
    pub spend_master: [u8; 64],
    pub note: Hx512Note,
    pub position: u64,
    pub siblings: [[u8; 64]; 32],
    pub selectors: [u64; 4],
}

impl Hx512Input {
    fn decode(raw: &[u8]) -> Result<Self, Hx512RelationError> {
        let selectors =
            core::array::from_fn(|index| read_u64be(&raw[2_352 + index * 8..2_360 + index * 8]));
        if selectors.iter().any(|value| *value > 1) {
            return Err(Hx512RelationError::NonCanonical(
                "input asset selector is not a Boolean u64be word",
            ));
        }
        Ok(Self {
            raw: exact_array(raw),
            spend_master: exact_array(&raw[..64]),
            note: Hx512Note::decode(&raw[64..296]),
            position: read_u64be(&raw[296..304]),
            siblings: core::array::from_fn(|index| {
                exact_array(&raw[304 + index * 64..368 + index * 64])
            }),
            selectors,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512Output {
    pub raw: [u8; HX512_OUTPUT_BYTES],
    pub note: Hx512Note,
    pub selectors: [u64; 4],
    pub ciphertext: [u8; HX512_CIPHERTEXT_BYTES],
}

impl Hx512Output {
    fn decode(raw: &[u8], ciphertext_transport: &[u8]) -> Result<Self, Hx512RelationError> {
        if !is_zero(&ciphertext_transport[HX512_CIPHERTEXT_BYTES..]) {
            return Err(Hx512RelationError::NonCanonical(
                "ciphertext transport five-byte padding is nonzero",
            ));
        }
        let selectors =
            core::array::from_fn(|index| read_u64be(&raw[232 + index * 8..240 + index * 8]));
        if selectors.iter().any(|value| *value > 1) {
            return Err(Hx512RelationError::NonCanonical(
                "output asset selector is not a Boolean u64be word",
            ));
        }
        Ok(Self {
            raw: exact_array(raw),
            note: Hx512Note::decode(&raw[..232]),
            selectors,
            ciphertext: exact_array(&ciphertext_transport[..HX512_CIPHERTEXT_BYTES]),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512Accumulator {
    pub raw: [u8; 200],
    pub policy_root: [u8; 64],
    pub spend_plan: [u8; 64],
    pub threshold: u64,
    pub signer_count: u64,
    pub approval_count: u64,
    pub approved: [u64; 6],
}

impl Hx512Accumulator {
    fn decode(raw: &[u8]) -> Result<Self, Hx512RelationError> {
        let approved =
            core::array::from_fn(|index| read_u64be(&raw[152 + index * 8..160 + index * 8]));
        if approved.iter().any(|value| *value > 1) {
            return Err(Hx512RelationError::NonCanonical(
                "accumulator approval is not a Boolean u64be word",
            ));
        }
        Ok(Self {
            raw: exact_array(raw),
            policy_root: exact_array(&raw[..64]),
            spend_plan: exact_array(&raw[64..128]),
            threshold: read_u64be(&raw[128..136]),
            signer_count: read_u64be(&raw[136..144]),
            approval_count: read_u64be(&raw[144..152]),
            approved,
        })
    }

    fn is_zero(&self) -> bool {
        is_zero(&self.raw)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512Authorization {
    pub raw: [u8; HX512_AUTHORIZATION_BYTES],
    pub mode: Hx512AuthorizationMode,
    pub current: Hx512Accumulator,
    pub next: Hx512Accumulator,
    pub signer_tags: [[u8; 64]; 6],
    pub policy_masters: [[u8; 64]; 2],
}

impl Hx512Authorization {
    fn decode(raw: &[u8], masters: &[u8]) -> Result<Self, Hx512RelationError> {
        let mode = Hx512AuthorizationMode::try_from(read_u64be(&raw[..8]))?;
        Ok(Self {
            raw: exact_array(raw),
            mode,
            current: Hx512Accumulator::decode(&raw[8..208])?,
            next: Hx512Accumulator::decode(&raw[208..408])?,
            signer_tags: core::array::from_fn(|index| {
                exact_array(&raw[408 + index * 64..472 + index * 64])
            }),
            policy_masters: [exact_array(&masters[..64]), exact_array(&masters[64..])],
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ProductionWitness {
    raw: [u8; HX512_WITNESS_BYTES],
    pub inputs: [Hx512Input; 2],
    pub outputs: [Hx512Output; 2],
    pub authorization: Hx512Authorization,
    pub stable_witness: StablecoinTransitionWitnessV3,
}

impl Hx512ProductionWitness {
    pub fn decode_exact(raw: &[u8]) -> Result<Self, Hx512RelationError> {
        if raw.len() != HX512_WITNESS_BYTES {
            return Err(Hx512RelationError::WrongLength {
                surface: "HX512 witness",
                expected: HX512_WITNESS_BYTES,
                actual: raw.len(),
            });
        }
        let stable_raw = &raw[HX512_STABLE_WITNESS_OFFSET..];
        let stable_witness = StablecoinTransitionWitnessV3::decode_canonical(stable_raw)?;
        if stable_witness.encode_canonical()? != stable_raw {
            return Err(Hx512RelationError::NonCanonical(
                "stablecoin witness suffix does not round trip byte-for-byte",
            ));
        }
        let outputs = [
            Hx512Output::decode(
                &raw[HX512_OUTPUT_0_OFFSET..HX512_OUTPUT_1_OFFSET],
                &raw[HX512_CIPHERTEXT_0_OFFSET..HX512_CIPHERTEXT_1_OFFSET],
            )?,
            Hx512Output::decode(
                &raw[HX512_OUTPUT_1_OFFSET..HX512_AUTHORIZATION_OFFSET],
                &raw[HX512_CIPHERTEXT_1_OFFSET..HX512_STABLE_WITNESS_OFFSET],
            )?,
        ];
        Ok(Self {
            raw: exact_array(raw),
            inputs: [
                Hx512Input::decode(&raw[HX512_INPUT_0_OFFSET..HX512_INPUT_1_OFFSET])?,
                Hx512Input::decode(&raw[HX512_INPUT_1_OFFSET..HX512_OUTPUT_0_OFFSET])?,
            ],
            outputs,
            authorization: Hx512Authorization::decode(
                &raw[HX512_AUTHORIZATION_OFFSET..HX512_POLICY_MASTERS_OFFSET],
                &raw[HX512_POLICY_MASTERS_OFFSET..HX512_CIPHERTEXT_0_OFFSET],
            )?,
            stable_witness,
        })
    }

    pub fn encode_exact(&self) -> [u8; HX512_WITNESS_BYTES] {
        self.raw
    }
}

fn core_frame(
    identity: Hx512UnallocatedIdentity,
    role: [u8; 8],
    fields: &[&[u8]],
) -> Result<Vec<u8>, Hx512RelationError> {
    let field_count = u8::try_from(fields.len())
        .map_err(|_| Hx512RelationError::NonCanonical("hash frame has more than 255 fields"))?;
    let payload_bytes = fields.iter().map(|field| field.len()).sum::<usize>();
    let mut out = Vec::with_capacity(17 + 2 * fields.len() + payload_bytes);
    out.extend_from_slice(&identity.magic);
    out.extend_from_slice(&role);
    out.push(field_count);
    for field in fields {
        let len = u16::try_from(field.len()).map_err(|_| {
            Hx512RelationError::NonCanonical("hash frame field exceeds u16 length grammar")
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    Ok(out)
}

fn core_hash(
    identity: Hx512UnallocatedIdentity,
    role: [u8; 8],
    fields: &[&[u8]],
) -> Result<[u8; 64], Hx512RelationError> {
    Ok(blake2b512_personalized_v2(
        &core_frame(identity, role, fields)?,
        [0u8; 16],
    ))
}

fn note_digest(
    identity: Hx512UnallocatedIdentity,
    note: &Hx512Note,
) -> Result<[u8; 64], Hx512RelationError> {
    let kind = u8::try_from(note.kind)
        .map_err(|_| Hx512RelationError::NonCanonical("note kind does not fit one byte"))?;
    let kind_bytes = [kind];
    let value = note.value.to_be_bytes();
    let asset = note.asset.to_be_bytes();
    core_hash(
        identity,
        ROLE_NOTE,
        &[
            &note.blinding,
            &kind_bytes,
            &value,
            &asset,
            &note.recipient,
            &note.rho,
            &note.authorization,
        ],
    )
}

fn spend_digest(
    identity: Hx512UnallocatedIdentity,
    master: &[u8; 64],
    lane: usize,
) -> Result<[u8; 64], Hx512RelationError> {
    let (role, lane_tag) = if lane == 0 {
        (ROLE_SPEND_A, LANE_A)
    } else {
        (ROLE_SPEND_B, LANE_B)
    };
    core_hash(identity, role, &[&lane_tag, master])
}

fn policy_digest(
    identity: Hx512UnallocatedIdentity,
    master: &[u8; 64],
    opening: &Hx512Accumulator,
    tags: &[[u8; 64]; 6],
) -> Result<[u8; 64], Hx512RelationError> {
    let threshold = opening.threshold.to_be_bytes();
    let signer_count = opening.signer_count.to_be_bytes();
    core_hash(
        identity,
        ROLE_AUTH_POLICY,
        &[
            master,
            &threshold,
            &signer_count,
            &tags[0],
            &tags[1],
            &tags[2],
            &tags[3],
            &tags[4],
            &tags[5],
        ],
    )
}

fn accumulator_digest(
    identity: Hx512UnallocatedIdentity,
    master: &[u8; 64],
    opening: &Hx512Accumulator,
    lane: usize,
) -> Result<[u8; 64], Hx512RelationError> {
    let (role, lane_tag) = if lane == 0 {
        (ROLE_AUTH_A, LANE_A)
    } else {
        (ROLE_AUTH_B, LANE_B)
    };
    let threshold = opening.threshold.to_be_bytes();
    let signer_count = opening.signer_count.to_be_bytes();
    let approval_count = opening.approval_count.to_be_bytes();
    let approvals: [u8; 6] = opening.approved.map(|value| value as u8);
    core_hash(
        identity,
        role,
        &[
            master,
            &lane_tag,
            &opening.policy_root,
            &opening.spend_plan,
            &threshold,
            &signer_count,
            &approval_count,
            &approvals,
        ],
    )
}

fn value_lock_digest(
    identity: Hx512UnallocatedIdentity,
    master: &[u8; 64],
    opening: &Hx512Accumulator,
    lane: usize,
) -> Result<[u8; 64], Hx512RelationError> {
    let (role, lane_tag) = if lane == 0 {
        (ROLE_AUTH_A, LANE_A)
    } else {
        (ROLE_AUTH_B, LANE_B)
    };
    core_hash(
        identity,
        role,
        &[master, &lane_tag, &opening.policy_root, &opening.spend_plan],
    )
}

fn dummy_authorization_digest(
    identity: Hx512UnallocatedIdentity,
    lane: usize,
    slot: usize,
) -> Result<[u8; 64], Hx512RelationError> {
    let role = if lane == 0 { ROLE_AUTH_A } else { ROLE_AUTH_B };
    let mut payload = [0u8; 117];
    payload[0] = slot as u8;
    payload[1] = lane as u8;
    core_hash(identity, role, &[&payload])
}

fn authorization_digest(
    identity: Hx512UnallocatedIdentity,
    authorization: &Hx512Authorization,
    lane: usize,
    slot: usize,
) -> Result<[u8; 64], Hx512RelationError> {
    let current_master = &authorization.policy_masters[0];
    let next_master = &authorization.policy_masters[1];
    match (authorization.mode, slot) {
        (Hx512AuthorizationMode::SingleKey, _) => dummy_authorization_digest(identity, lane, slot),
        (Hx512AuthorizationMode::AccumulatorInit, 0) => {
            accumulator_digest(identity, next_master, &authorization.next, lane)
        }
        (Hx512AuthorizationMode::ApprovalStep, 0)
        | (Hx512AuthorizationMode::FinalThresholdSpend, 0) => {
            accumulator_digest(identity, current_master, &authorization.current, lane)
        }
        (Hx512AuthorizationMode::ValueLockCreation, 0) => {
            value_lock_digest(identity, current_master, &authorization.current, lane)
        }
        (Hx512AuthorizationMode::ApprovalStep, 1) => {
            accumulator_digest(identity, next_master, &authorization.next, lane)
        }
        (Hx512AuthorizationMode::FinalThresholdSpend, 1) => {
            value_lock_digest(identity, current_master, &authorization.current, lane)
        }
        _ => dummy_authorization_digest(identity, lane, slot),
    }
}

fn nullifier_digest(
    identity: Hx512UnallocatedIdentity,
    key: &[u8; 64],
    input: &Hx512Input,
) -> Result<[u8; 64], Hx512RelationError> {
    let position = input.position.to_be_bytes();
    core_hash(identity, ROLE_NULLIFIER, &[key, &position, &input.note.rho])
}

fn merkle_digest(
    identity: Hx512UnallocatedIdentity,
    left: &[u8; 64],
    right: &[u8; 64],
) -> Result<[u8; 64], Hx512RelationError> {
    core_hash(identity, ROLE_MERKLE, &[left, right])
}

fn ciphertext_digest(
    statement: &Hx512ProductionStatement,
    index: usize,
    ciphertext: &[u8; HX512_CIPHERTEXT_BYTES],
) -> Result<[u8; 64], Hx512RelationError> {
    let family = [0x52];
    let domain_set = statement.identity.domain_set.to_be_bytes();
    let index = [index as u8];
    let width = (HX512_CIPHERTEXT_BYTES as u32).to_be_bytes();
    core_hash(
        statement.identity,
        ROLE_CIPHERTEXT,
        &[&family, &domain_set, &index, &width, ciphertext],
    )
}

fn selected_asset_slot(
    selectors: &[u64; 4],
    assets: &[u64; 4],
    note_asset: u64,
) -> Result<usize, Hx512RelationError> {
    let mut selected = None;
    for (index, selector) in selectors.iter().copied().enumerate() {
        if selector == 1 {
            if selected.replace(index).is_some() {
                return Err(Hx512RelationError::Semantic(
                    "active note asset selectors are not one-hot",
                ));
            }
        }
    }
    let selected = selected.ok_or(Hx512RelationError::Semantic(
        "active note has no selected asset slot",
    ))?;
    if assets[selected] != note_asset || note_asset == HX512_PADDING_ASSET {
        return Err(Hx512RelationError::Semantic(
            "selected statement asset does not equal the note asset",
        ));
    }
    Ok(selected)
}

fn validate_active_note(note: &Hx512Note) -> Result<(), Hx512RelationError> {
    if note.kind > 2 {
        return Err(Hx512RelationError::NonCanonical(
            "active note kind exceeds 2",
        ));
    }
    if note.value > HX512_MAX_VALUE {
        return Err(Hx512RelationError::NonCanonical(
            "active note value exceeds 61 bits",
        ));
    }
    if note.asset >= HX512_ODD_FIELD_MODULUS || note.asset == HX512_RESERVED_REDUCED_PADDING_ASSET {
        return Err(Hx512RelationError::NonCanonical(
            "active note asset is not an injective odd-field representative",
        ));
    }
    Ok(())
}

fn validate_accumulator(
    opening: &Hx512Accumulator,
    tags: &[[u8; 64]; 6],
    expected_policy: &[u8; 64],
    expected_plan: Option<&[u8; 64]>,
) -> Result<(), Hx512RelationError> {
    if !(1..=6).contains(&opening.signer_count)
        || opening.threshold == 0
        || opening.threshold > opening.signer_count
        || opening.approval_count > opening.signer_count
        || opening.approved.iter().sum::<u64>() != opening.approval_count
    {
        return Err(Hx512RelationError::Semantic(
            "accumulator threshold/signer/approval metadata is invalid",
        ));
    }
    if &opening.policy_root != expected_policy
        || expected_plan.is_some_and(|plan| &opening.spend_plan != plan)
    {
        return Err(Hx512RelationError::Semantic(
            "accumulator policy root or spend-plan digest mismatch",
        ));
    }
    for slot in 0..6 {
        if slot < opening.signer_count as usize {
            if is_zero(&tags[slot]) || tags[..slot].contains(&tags[slot]) {
                return Err(Hx512RelationError::Semantic(
                    "active signer tag is zero or duplicated",
                ));
            }
        } else if !is_zero(&tags[slot]) || opening.approved[slot] != 0 {
            return Err(Hx512RelationError::Semantic(
                "inactive signer tag/approval slot is nonzero",
            ));
        }
    }
    Ok(())
}

struct AuthorizationResolution {
    input_authorization: [[u8; 64]; 2],
    nullifier_key: [[u8; 64]; 2],
    output_zero_authorization: Option<[u8; 64]>,
    policy_digest: [u8; 64],
}

fn validate_authorization(
    statement: &Hx512ProductionStatement,
    witness: &Hx512ProductionWitness,
    spend_plan: &[u8; 64],
) -> Result<AuthorizationResolution, Hx512RelationError> {
    let authorization = &witness.authorization;
    let flags = statement.activity_flags();
    ensure_hx512_activity_mode_accepted(authorization.mode, statement.activity_mask)?;
    let spend: [[[u8; 64]; 2]; 2] = [
        [
            spend_digest(statement.identity, &witness.inputs[0].spend_master, 0)?,
            spend_digest(statement.identity, &witness.inputs[0].spend_master, 1)?,
        ],
        [
            spend_digest(statement.identity, &witness.inputs[1].spend_master, 0)?,
            spend_digest(statement.identity, &witness.inputs[1].spend_master, 1)?,
        ],
    ];
    let (selected_opening, selected_master) =
        if authorization.mode == Hx512AuthorizationMode::AccumulatorInit {
            (&authorization.next, &authorization.policy_masters[1])
        } else {
            (&authorization.current, &authorization.policy_masters[0])
        };
    let policy = policy_digest(
        statement.identity,
        selected_master,
        selected_opening,
        &authorization.signer_tags,
    )?;
    let auth_digests: [[[u8; 64]; 2]; 2] = [
        [
            authorization_digest(statement.identity, authorization, 0, 0)?,
            authorization_digest(statement.identity, authorization, 1, 0)?,
        ],
        [
            authorization_digest(statement.identity, authorization, 0, 1)?,
            authorization_digest(statement.identity, authorization, 1, 1)?,
        ],
    ];
    let zero64 = [0u8; 64];
    let all_tags_zero = authorization.signer_tags.iter().all(|tag| is_zero(tag));
    let result = match authorization.mode {
        Hx512AuthorizationMode::SingleKey => {
            if !authorization.current.is_zero()
                || !authorization.next.is_zero()
                || !all_tags_zero
                || authorization.policy_masters != [zero64; 2]
            {
                return Err(Hx512RelationError::Semantic(
                    "SingleKey auxiliary authorization witness is nonzero",
                ));
            }
            for index in 0..2 {
                if flags[index] && witness.inputs[index].note.kind != 0 {
                    return Err(Hx512RelationError::Semantic(
                        "SingleKey active input is not an ordinary note",
                    ));
                }
                if flags[2 + index] && witness.outputs[index].note.kind != 0 {
                    return Err(Hx512RelationError::Semantic(
                        "SingleKey active output is not an ordinary note",
                    ));
                }
            }
            AuthorizationResolution {
                input_authorization: [spend[0][0], spend[1][0]],
                nullifier_key: [spend[0][1], spend[1][1]],
                output_zero_authorization: None,
                policy_digest: policy,
            }
        }
        Hx512AuthorizationMode::AccumulatorInit => {
            if !authorization.current.is_zero() || !is_zero(&authorization.policy_masters[0]) {
                return Err(Hx512RelationError::Semantic(
                    "AccumulatorInit current state/master is nonzero",
                ));
            }
            // The initialized accumulator can target a future transaction.
            // Comparing its hidden plan to this initialization transaction
            // would introduce a commitment fixed point.
            validate_accumulator(
                &authorization.next,
                &authorization.signer_tags,
                &policy,
                None,
            )?;
            if authorization.next.approval_count != 0
                || authorization.next.approved.iter().any(|value| *value != 0)
                || witness.outputs[0].note.kind != 1
                || witness.outputs[0].note.value != 0
                || witness.outputs[0].note.asset != 0
            {
                return Err(Hx512RelationError::Semantic(
                    "AccumulatorInit state/output-zero shape mismatch",
                ));
            }
            for index in 0..2 {
                if flags[index] && witness.inputs[index].note.kind != 0 {
                    return Err(Hx512RelationError::Semantic(
                        "AccumulatorInit input is not ordinary",
                    ));
                }
            }
            if flags[3] && witness.outputs[1].note.kind != 0 {
                return Err(Hx512RelationError::Semantic(
                    "AccumulatorInit optional output is not ordinary",
                ));
            }
            AuthorizationResolution {
                input_authorization: [spend[0][0], spend[1][0]],
                nullifier_key: [spend[0][1], spend[1][1]],
                output_zero_authorization: Some(auth_digests[0][0]),
                policy_digest: policy,
            }
        }
        Hx512AuthorizationMode::ApprovalStep => {
            if authorization.policy_masters[0] != authorization.policy_masters[1] {
                return Err(Hx512RelationError::Semantic(
                    "ApprovalStep changes the policy master",
                ));
            }
            validate_accumulator(
                &authorization.current,
                &authorization.signer_tags,
                &policy,
                None,
            )?;
            validate_accumulator(
                &authorization.next,
                &authorization.signer_tags,
                &policy,
                None,
            )?;
            if witness.inputs[0].note.kind != 1
                || witness.inputs[0].note.value != 0
                || witness.inputs[0].note.asset != 0
                || !is_zero(&witness.inputs[0].spend_master)
                || witness.inputs[1].note.kind != 0
                || witness.outputs[0].note.kind != 1
                || witness.outputs[0].note.value != 0
                || witness.outputs[0].note.asset != 0
                || (flags[3] && witness.outputs[1].note.kind != 0)
            {
                return Err(Hx512RelationError::Semantic(
                    "ApprovalStep note typing/zero structure mismatch",
                ));
            }
            if authorization.current.policy_root != authorization.next.policy_root
                || authorization.current.spend_plan != authorization.next.spend_plan
                || authorization.current.threshold != authorization.next.threshold
                || authorization.current.signer_count != authorization.next.signer_count
                || authorization.next.approval_count != authorization.current.approval_count + 1
            {
                return Err(Hx512RelationError::Semantic(
                    "ApprovalStep accumulator metadata transition mismatch",
                ));
            }
            let matching: Vec<_> = (0..authorization.current.signer_count as usize)
                .filter(|slot| authorization.signer_tags[*slot] == spend[1][0])
                .collect();
            if matching.len() != 1
                || authorization.current.approved[matching[0]] != 0
                || (0..6).any(|slot| {
                    authorization.next.approved[slot]
                        != u64::from(
                            authorization.current.approved[slot] == 1 || slot == matching[0],
                        )
                })
            {
                return Err(Hx512RelationError::Semantic(
                    "ApprovalStep signer membership or one-bit transition mismatch",
                ));
            }
            AuthorizationResolution {
                input_authorization: [auth_digests[0][0], spend[1][0]],
                nullifier_key: [auth_digests[0][1], spend[1][1]],
                output_zero_authorization: Some(auth_digests[1][0]),
                policy_digest: policy,
            }
        }
        Hx512AuthorizationMode::ValueLockCreation => {
            if !authorization.next.is_zero() || !is_zero(&authorization.policy_masters[1]) {
                return Err(Hx512RelationError::Semantic(
                    "ValueLockCreation next state/master is nonzero",
                ));
            }
            validate_accumulator(
                &authorization.current,
                &authorization.signer_tags,
                &policy,
                None,
            )?;
            if authorization.current.approval_count != 0
                || authorization
                    .current
                    .approved
                    .iter()
                    .any(|value| *value != 0)
                || witness.outputs[0].note.kind != 2
                || (flags[3] && witness.outputs[1].note.kind != 0)
            {
                return Err(Hx512RelationError::Semantic(
                    "ValueLockCreation state/output shape mismatch",
                ));
            }
            for index in 0..2 {
                if flags[index] && witness.inputs[index].note.kind != 0 {
                    return Err(Hx512RelationError::Semantic(
                        "ValueLockCreation input is not ordinary",
                    ));
                }
            }
            AuthorizationResolution {
                input_authorization: [spend[0][0], spend[1][0]],
                nullifier_key: [spend[0][1], spend[1][1]],
                output_zero_authorization: Some(auth_digests[0][0]),
                policy_digest: policy,
            }
        }
        Hx512AuthorizationMode::FinalThresholdSpend => {
            if !authorization.next.is_zero() || !is_zero(&authorization.policy_masters[1]) {
                return Err(Hx512RelationError::Semantic(
                    "FinalThresholdSpend next state/master is nonzero",
                ));
            }
            // Only the final spend compares the preserved accumulator target
            // to the independently derived, non-circular spend-plan digest.
            validate_accumulator(
                &authorization.current,
                &authorization.signer_tags,
                &policy,
                Some(spend_plan),
            )?;
            if authorization.current.approval_count < authorization.current.threshold
                || witness.inputs[0].note.kind != 2
                || witness.inputs[1].note.kind != 1
                || witness.inputs[1].note.value != 0
                || witness.inputs[1].note.asset != 0
                || !is_zero(&witness.inputs[0].spend_master)
                || !is_zero(&witness.inputs[1].spend_master)
            {
                return Err(Hx512RelationError::Semantic(
                    "FinalThresholdSpend input/state structure mismatch",
                ));
            }
            for index in 0..2 {
                if flags[2 + index] && witness.outputs[index].note.kind != 0 {
                    return Err(Hx512RelationError::Semantic(
                        "FinalThresholdSpend output is not ordinary",
                    ));
                }
            }
            AuthorizationResolution {
                input_authorization: [auth_digests[1][0], auth_digests[0][0]],
                nullifier_key: [auth_digests[1][1], auth_digests[0][1]],
                output_zero_authorization: None,
                policy_digest: policy,
            }
        }
    };
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512DerivedBindings {
    pub action_intent: [u8; 64],
    pub spend_plan: [u8; 64],
    pub note_commitments: [[u8; 64]; 4],
    pub nullifiers: [[u8; 64]; 2],
    pub merkle_roots: [[u8; 64]; 2],
    pub ciphertext_hashes: [[u8; 64]; 2],
    pub authorization_policy: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512MaterializedRelation {
    pub statement: Hx512ProductionStatement,
    pub verifier_context: Hx512VerifierContext,
    pub witness: Hx512ProductionWitness,
    pub derived: Hx512DerivedBindings,
    pub shape: Hx512RelationShape,
    pub hash_recipes: Vec<Hx512HashCallRecipe>,
}

/// Parse and execute the exact inactive semantic materializer.
///
/// A successful result is not a proof, algebraic compiler, refinement result,
/// or production authorization.  It is the concrete byte/hash/reference
/// semantics that a later compiler must refine exactly.
pub fn materialize_hx512_production_relation(
    statement_raw: &[u8],
    verifier_context_raw: &[u8],
    witness_raw: &[u8],
    expected: &Hx512ExpectedStatementBinding,
) -> Result<Hx512MaterializedRelation, Hx512RelationError> {
    let statement = Hx512ProductionStatement::decode_exact(statement_raw, expected)?;
    let verifier_context = Hx512VerifierContext::decode_exact(verifier_context_raw)?;
    let witness = Hx512ProductionWitness::decode_exact(witness_raw)?;
    let flags = statement.activity_flags();
    let mode = witness.authorization.mode;
    ensure_hx512_activity_mode_accepted(mode, statement.activity_mask)?;

    let action_intent = statement.action_intent_digest();
    if is_zero(&action_intent) || verifier_context.expected_action_intent != action_intent {
        return Err(Hx512RelationError::Semantic(
            "verifier context does not equal the recomputed action intent",
        ));
    }
    let spend_plan = statement.spend_plan_digest();

    let notes = [
        &witness.inputs[0].note,
        &witness.inputs[1].note,
        &witness.outputs[0].note,
        &witness.outputs[1].note,
    ];
    let mut note_commitments = [[0u8; 64]; 4];
    for (index, note) in notes.into_iter().enumerate() {
        note_commitments[index] = note_digest(statement.identity, note)?;
    }

    for index in 0..2 {
        if flags[index] {
            validate_active_note(&witness.inputs[index].note)?;
            if witness.inputs[index].position >= 1 << 32 {
                return Err(Hx512RelationError::NonCanonical(
                    "active input Merkle position exceeds 32 bits",
                ));
            }
        } else if !is_zero(&witness.inputs[index].raw) {
            return Err(Hx512RelationError::NonCanonical(
                "inactive input witness slot is not all zero",
            ));
        }
        if flags[2 + index] {
            validate_active_note(&witness.outputs[index].note)?;
        } else if !is_zero(&witness.outputs[index].raw)
            || !is_zero(&witness.outputs[index].ciphertext)
        {
            return Err(Hx512RelationError::NonCanonical(
                "inactive output witness/ciphertext slot is not all zero",
            ));
        }
    }

    let authorization = validate_authorization(&statement, &witness, &spend_plan)?;
    let mut input_values = [[0u64; 4]; 2];
    let mut output_values = [[0u64; 4]; 2];
    let mut nullifiers = [[0u8; 64]; 2];
    let mut merkle_roots = [[0u8; 64]; 2];

    for index in 0..2 {
        let input = &witness.inputs[index];
        nullifiers[index] = nullifier_digest(
            statement.identity,
            &authorization.nullifier_key[index],
            input,
        )?;
        let mut current = note_commitments[index];
        for level in 0..32 {
            let sibling = &input.siblings[level];
            current = if (input.position >> level) & 1 == 0 {
                merkle_digest(statement.identity, &current, sibling)?
            } else {
                merkle_digest(statement.identity, sibling, &current)?
            };
        }
        merkle_roots[index] = current;
        if flags[index] {
            let slot =
                selected_asset_slot(&input.selectors, &statement.asset_slots, input.note.asset)?;
            input_values[index][slot] = input.note.value;
            if input.note.authorization != authorization.input_authorization[index] {
                return Err(Hx512RelationError::Semantic(
                    "input note authorization key mismatch",
                ));
            }
            if nullifiers[index] != statement.nullifiers[index] {
                return Err(Hx512RelationError::Semantic(
                    "derived input nullifier does not equal the public nullifier",
                ));
            }
            if current != statement.anchor {
                return Err(Hx512RelationError::Semantic(
                    "input Merkle path does not equal the public anchor",
                ));
            }
        }
    }

    let mut ciphertext_hashes = [[0u8; 64]; 2];
    for index in 0..2 {
        let output = &witness.outputs[index];
        ciphertext_hashes[index] = ciphertext_digest(&statement, index, &output.ciphertext)?;
        if flags[2 + index] {
            let slot =
                selected_asset_slot(&output.selectors, &statement.asset_slots, output.note.asset)?;
            output_values[index][slot] = output.note.value;
            if note_commitments[2 + index] != statement.commitments[index] {
                return Err(Hx512RelationError::Semantic(
                    "derived output note commitment does not equal the public commitment",
                ));
            }
            if ciphertext_hashes[index] != statement.ciphertext_hashes[index] {
                return Err(Hx512RelationError::Semantic(
                    "fixed 2147-byte ciphertext does not equal the public hash",
                ));
            }
        }
    }
    if let Some(expected_output_zero) = authorization.output_zero_authorization {
        if !flags[2] || witness.outputs[0].note.authorization != expected_output_zero {
            return Err(Hx512RelationError::Semantic(
                "mode-specific output-zero authorization key mismatch",
            ));
        }
    }

    for slot in 0..4 {
        let inputs = i128::from(input_values[0][slot]) + i128::from(input_values[1][slot]);
        let outputs = i128::from(output_values[0][slot]) + i128::from(output_values[1][slot]);
        let asset = statement.asset_slots[slot];
        let expected_delta = if asset == 0 {
            i128::from(statement.fee)
        } else if statement.stable_public.direction != StablecoinTransitionDirectionV3::Disabled
            && asset == u64::from(statement.stable_public.asset_id)
        {
            match statement.stable_public.direction {
                StablecoinTransitionDirectionV3::Disabled => 0,
                StablecoinTransitionDirectionV3::Mint => {
                    -i128::from(statement.stable_public.magnitude)
                }
                StablecoinTransitionDirectionV3::Burn => {
                    i128::from(statement.stable_public.magnitude)
                }
            }
        } else {
            0
        };
        if inputs - outputs != expected_delta {
            return Err(Hx512RelationError::Semantic(
                "per-asset input/output balance, fee, or stablecoin delta mismatch",
            ));
        }
    }

    let stable_disabled =
        statement.stable_public.direction == StablecoinTransitionDirectionV3::Disabled;
    if stable_disabled {
        if verifier_context.stable_current_root != [0u8; 64]
            || verifier_context.parent_height != 0
            || witness.stable_witness != StablecoinTransitionWitnessV3::ZERO
        {
            return Err(Hx512RelationError::NonCanonical(
                "disabled stablecoin context/witness is not the unique V3 encoding",
            ));
        }
    } else if verifier_context.stable_current_root
        != *statement.stable_public.before_root.as_bytes()
    {
        return Err(Hx512RelationError::Semantic(
            "authenticated stablecoin context root does not equal the public before root",
        ));
    }
    verify_stablecoin_transition_v3(
        StablecoinTransitionVerifierContextV3 {
            current_root: StablecoinTransitionRootV3::new(verifier_context.stable_current_root),
            parent_height: verifier_context.parent_height,
            expected_action_intent: action_intent,
        },
        statement.stable_public,
        witness.stable_witness,
    )?;

    let hash_recipes = hx512_hash_call_recipe_registry(statement.identity);
    let shape = hx512_relation_shape(statement.identity);
    Ok(Hx512MaterializedRelation {
        statement,
        verifier_context,
        witness,
        derived: Hx512DerivedBindings {
            action_intent,
            spend_plan,
            note_commitments,
            nullifiers,
            merkle_roots,
            ciphertext_hashes,
            authorization_policy: authorization.policy_digest,
        },
        shape,
        hash_recipes,
    })
}

/// Fail closed until a proof compiler, refinement proof, complete-ZK proof,
/// composed PQ/QROM certificate, release manifest, and native lifecycle all
/// exist and agree on this exact grammar.
pub fn ensure_hx512_production_authorized() -> Result<(), Hx512RelationError> {
    #[cfg(feature = "hx512-refinement-evidence")]
    return Err(Hx512RelationError::RefinementEvidenceFeatureEnabled);

    #[cfg(not(feature = "hx512-refinement-evidence"))]
    Err(Hx512RelationError::Semantic(
        "HX512 production identity/compiler/refinement/security/release gates are false",
    ))
}

/// Independently useful evidence must never be confused with an authorization
/// gate, even in a debug build where the fixture feature is available.
pub fn ensure_hx512_refinement_evidence_not_production() -> Result<(), Hx512RelationError> {
    if HX512_REFINEMENT_EVIDENCE_FEATURE_ENABLED {
        Err(Hx512RelationError::RefinementEvidenceFeatureEnabled)
    } else {
        Ok(())
    }
}

/// Return the exact 5-mode x 3-direction x 2-secret refinement matrix.
///
/// The constructor replays the production materializer before returning any
/// bytes.  It is unavailable unless the off-by-default evidence feature is
/// explicitly enabled, and release builds with that feature fail at compile
/// time above.
#[cfg(feature = "hx512-refinement-evidence")]
pub fn hx512_refinement_fixtures() -> Result<Vec<Hx512RefinementFixture>, Hx512RelationError> {
    tests::build_refinement_fixtures()
}

/// Return every authorization-mode/activity-mask production-grammar case.
///
/// Ordering is deterministic: `HX512_AUTHORIZATION_MODES` order first, then
/// masks `0x00..=0x0f`. Exactly 26 entries contain canonical raw material and
/// exactly 54 contain the grammar's `RejectedModeMask` classification. This
/// evidence API is absent from normal builds and forbidden in release builds.
#[cfg(feature = "hx512-refinement-evidence")]
pub fn hx512_mode_mask_refinement_cases(
) -> Result<Vec<Hx512ModeMaskRefinementCase>, Hx512RelationError> {
    tests::build_mode_mask_refinement_cases()
}

#[cfg(any(test, feature = "hx512-refinement-evidence"))]
pub(crate) mod tests {
    use super::*;

    const TEST_ONLY_IDENTITY: Hx512UnallocatedIdentity = Hx512UnallocatedIdentity {
        magic: *b"TSTW64A1",
        statement_grammar: 7,
        circuit_version: 0x7101,
        crypto_suite: 0x7102,
        family_id: 0x7103,
        action_id: 0x7104,
        backend_id: 0x71,
        proof_profile: 0x72,
        domain_set: 0x7105,
        network_id: 0x7465_7374,
    };

    const TEST_ONLY_BINDING: Hx512ExpectedStatementBinding = Hx512ExpectedStatementBinding {
        identity: TEST_ONLY_IDENTITY,
        chain_id: [0x31; 32],
        genesis_id: [0x32; 64],
        rules_hash: [0x33; 64],
    };
    const TEST_ONLY_ACTION_INTENT_RANGES: [Hx512ByteRange; 3] = [
        Hx512ByteRange::statement(0, 251),
        Hx512ByteRange::statement(379, 316),
        Hx512ByteRange::statement(759, 160),
    ];
    const TEST_ONLY_SPEND_PLAN_RANGES: [Hx512ByteRange; 2] = [
        Hx512ByteRange::statement(0, 187),
        Hx512ByteRange::statement(379, 316),
    ];

    pub(crate) struct Fixture {
        pub(crate) statement: [u8; HX512_STATEMENT_BYTES],
        pub(crate) context: [u8; HX512_VERIFIER_CONTEXT_BYTES],
        pub(crate) witness: [u8; HX512_WITNESS_BYTES],
    }

    fn encode_typed_note(
        kind: u64,
        value: u64,
        asset: u64,
        recipient_marker: u8,
        rho_marker: u8,
        blinding_marker: u8,
        authorization: [u8; 64],
    ) -> [u8; 232] {
        let mut out = [0u8; 232];
        out[..8].copy_from_slice(&kind.to_be_bytes());
        out[8..16].copy_from_slice(&value.to_be_bytes());
        out[16..24].copy_from_slice(&asset.to_be_bytes());
        out[24..56].fill(recipient_marker);
        out[56..104].fill(rho_marker);
        out[104..168].fill(blinding_marker);
        out[168..232].copy_from_slice(&authorization);
        out
    }

    fn encode_note(
        value: u64,
        recipient_marker: u8,
        rho_marker: u8,
        blinding_marker: u8,
        authorization: [u8; 64],
    ) -> [u8; 232] {
        encode_typed_note(
            0,
            value,
            0,
            recipient_marker,
            rho_marker,
            blinding_marker,
            authorization,
        )
    }

    fn note_hash(raw: &[u8; 232]) -> [u8; 64] {
        note_digest(TEST_ONLY_IDENTITY, &Hx512Note::decode(raw)).unwrap()
    }

    fn root_for(digest: [u8; 64], position: u64, siblings: &[[u8; 64]; 32]) -> [u8; 64] {
        let mut current = digest;
        for (level, sibling) in siblings.iter().enumerate() {
            current = if (position >> level) & 1 == 0 {
                merkle_digest(TEST_ONLY_IDENTITY, &current, sibling).unwrap()
            } else {
                merkle_digest(TEST_ONLY_IDENTITY, sibling, &current).unwrap()
            };
        }
        current
    }

    fn build_single_key_fixture(mask: u8) -> Fixture {
        assert!(hx512_activity_mode_accepts(
            Hx512AuthorizationMode::SingleKey,
            mask
        ));
        let flags: [bool; 4] = core::array::from_fn(|index| mask & (1 << index) != 0);
        let mut statement = [0u8; HX512_STATEMENT_BYTES];
        statement[..26].copy_from_slice(&TEST_ONLY_IDENTITY.encode_exact());
        statement[26..58].copy_from_slice(&TEST_ONLY_BINDING.chain_id);
        statement[58..122].copy_from_slice(&TEST_ONLY_BINDING.genesis_id);
        statement[122..186].copy_from_slice(&TEST_ONLY_BINDING.rules_hash);
        statement[186] = mask;
        for index in 0..3 {
            statement[635 + index * 8..643 + index * 8]
                .copy_from_slice(&HX512_PADDING_ASSET.to_be_bytes());
        }
        statement[659..667].copy_from_slice(&7u64.to_be_bytes());
        statement[668..].copy_from_slice(&StablecoinTransitionPublicV3::ZERO.encode_canonical());

        let mut witness = [0u8; HX512_WITNESS_BYTES];
        let mut input_notes = [[0u8; 232]; 2];
        let mut spend_masters = [[0u8; 64]; 2];
        let active_inputs: Vec<_> = (0..2).filter(|index| flags[*index]).collect();
        for index in active_inputs.iter().copied() {
            spend_masters[index].fill(0x40 + index as u8);
            let auth = spend_digest(TEST_ONLY_IDENTITY, &spend_masters[index], 0).unwrap();
            let value = if index == active_inputs[0] { 7 } else { 0 };
            input_notes[index] = encode_note(
                value,
                0x50 + index as u8,
                0x60 + index as u8,
                0x70 + index as u8,
                auth,
            );
        }
        let input_digests = [note_hash(&input_notes[0]), note_hash(&input_notes[1])];
        let mut siblings = [[[0u8; 64]; 32]; 2];
        let mut positions = [0u64; 2];
        if active_inputs.len() == 2 {
            positions = [0, 1];
            siblings[0][0] = input_digests[1];
            siblings[1][0] = input_digests[0];
        }
        let anchor = root_for(
            input_digests[active_inputs[0]],
            positions[active_inputs[0]],
            &siblings[active_inputs[0]],
        );
        statement[187..251].copy_from_slice(&anchor);
        for index in active_inputs.iter().copied() {
            assert_eq!(
                root_for(input_digests[index], positions[index], &siblings[index]),
                anchor
            );
            let input_offset = index * HX512_INPUT_BYTES;
            witness[input_offset..input_offset + 64].copy_from_slice(&spend_masters[index]);
            witness[input_offset + 64..input_offset + 296].copy_from_slice(&input_notes[index]);
            witness[input_offset + 296..input_offset + 304]
                .copy_from_slice(&positions[index].to_be_bytes());
            let mut cursor = input_offset + 304;
            for sibling in siblings[index] {
                witness[cursor..cursor + 64].copy_from_slice(&sibling);
                cursor += 64;
            }
            witness[input_offset + 2_352..input_offset + 2_360]
                .copy_from_slice(&1u64.to_be_bytes());
            let parsed_input =
                Hx512Input::decode(&witness[input_offset..input_offset + HX512_INPUT_BYTES])
                    .unwrap();
            let nullifier_key = spend_digest(TEST_ONLY_IDENTITY, &spend_masters[index], 1).unwrap();
            let nullifier =
                nullifier_digest(TEST_ONLY_IDENTITY, &nullifier_key, &parsed_input).unwrap();
            statement[251 + index * 64..315 + index * 64].copy_from_slice(&nullifier);
        }

        for index in 0..2 {
            if !flags[2 + index] {
                continue;
            }
            let output_note = encode_note(
                0,
                0x80 + index as u8,
                0x90 + index as u8,
                0xa0 + index as u8,
                [0u8; 64],
            );
            let output_offset = HX512_OUTPUT_0_OFFSET + index * HX512_OUTPUT_BYTES;
            witness[output_offset..output_offset + 232].copy_from_slice(&output_note);
            witness[output_offset + 232..output_offset + 240].copy_from_slice(&1u64.to_be_bytes());
            let commitment = note_hash(&output_note);
            statement[379 + index * 64..443 + index * 64].copy_from_slice(&commitment);

            let ciphertext_offset =
                HX512_CIPHERTEXT_0_OFFSET + index * HX512_CIPHERTEXT_TRANSPORT_BYTES;
            witness[ciphertext_offset..ciphertext_offset + HX512_CIPHERTEXT_BYTES]
                .fill(0xb0 + index as u8);
            let family = [0x52];
            let domain = TEST_ONLY_IDENTITY.domain_set.to_be_bytes();
            let output_index = [index as u8];
            let width = (HX512_CIPHERTEXT_BYTES as u32).to_be_bytes();
            let digest = core_hash(
                TEST_ONLY_IDENTITY,
                ROLE_CIPHERTEXT,
                &[
                    &family,
                    &domain,
                    &output_index,
                    &width,
                    &witness[ciphertext_offset..ciphertext_offset + HX512_CIPHERTEXT_BYTES],
                ],
            )
            .unwrap();
            statement[507 + index * 64..571 + index * 64].copy_from_slice(&digest);
        }
        witness[HX512_STABLE_WITNESS_OFFSET..].copy_from_slice(
            &StablecoinTransitionWitnessV3::ZERO
                .encode_canonical()
                .unwrap(),
        );
        let parsed =
            Hx512ProductionStatement::decode_exact(&statement, &TEST_ONLY_BINDING).unwrap();
        let mut context = [0u8; HX512_VERIFIER_CONTEXT_BYTES];
        context[72..].copy_from_slice(&parsed.action_intent_digest());
        Fixture {
            statement,
            context,
            witness,
        }
    }

    /// Minimal crate-visible, test-only fixture seam for the executable
    /// adapter's end-to-end refinement tests.  It allocates no public identity
    /// and is absent from non-test builds.
    pub(crate) fn build_single_key_adapter_fixture() -> (Fixture, Hx512ExpectedStatementBinding) {
        (build_single_key_fixture(0x0f), TEST_ONLY_BINDING)
    }

    fn raw_action_intent_digest(statement: &[u8; HX512_STATEMENT_BYTES]) -> [u8; 64] {
        let mut message = Vec::with_capacity(HX512_ACTION_INTENT_MESSAGE_BYTES);
        message.extend_from_slice(&statement[..HX512_STATEMENT_NULLIFIERS_OFFSET]);
        message.extend_from_slice(
            &statement[HX512_STATEMENT_COMMITMENTS_OFFSET..HX512_STATEMENT_ACTION_INTENT_OFFSET],
        );
        message.extend_from_slice(
            &statement[HX512_STATEMENT_ACTION_INTENT_OFFSET + STABLECOIN_TRANSITION_V3_DIGEST_BYTES
                ..HX512_STATEMENT_ISSUER_AUTHORIZATION_OFFSET],
        );
        assert_eq!(message.len(), HX512_ACTION_INTENT_MESSAGE_BYTES);
        blake2b512_personalized_v2(
            &message,
            intent_personalization(TEST_ONLY_IDENTITY, *b"ACTINT"),
        )
    }

    fn raw_spend_plan_digest(statement: &[u8; HX512_STATEMENT_BYTES]) -> [u8; 64] {
        let mut message = Vec::with_capacity(HX512_SPEND_PLAN_MESSAGE_BYTES);
        message.extend_from_slice(&statement[..HX512_STATEMENT_ANCHOR_OFFSET]);
        message.extend_from_slice(
            &statement[HX512_STATEMENT_COMMITMENTS_OFFSET..HX512_STATEMENT_ACTION_INTENT_OFFSET],
        );
        assert_eq!(message.len(), HX512_SPEND_PLAN_MESSAGE_BYTES);
        blake2b512_personalized_v2(
            &message,
            intent_personalization(TEST_ONLY_IDENTITY, *b"SPPLAN"),
        )
    }

    fn encode_accumulator(
        policy_root: [u8; 64],
        spend_plan: [u8; 64],
        threshold: u64,
        signer_count: u64,
        approved: [u64; 6],
    ) -> [u8; 200] {
        let mut raw = [0u8; 200];
        raw[..64].copy_from_slice(&policy_root);
        raw[64..128].copy_from_slice(&spend_plan);
        raw[128..136].copy_from_slice(&threshold.to_be_bytes());
        raw[136..144].copy_from_slice(&signer_count.to_be_bytes());
        raw[144..152].copy_from_slice(&approved.iter().sum::<u64>().to_be_bytes());
        for (slot, value) in approved.into_iter().enumerate() {
            raw[152 + slot * 8..160 + slot * 8].copy_from_slice(&value.to_be_bytes());
        }
        raw
    }

    fn write_test_authorization(
        witness: &mut [u8; HX512_WITNESS_BYTES],
        mode: Hx512AuthorizationMode,
        current: [u8; 200],
        next: [u8; 200],
        signer_tags: [[u8; 64]; 6],
        policy_masters: [[u8; 64]; 2],
    ) {
        witness[HX512_AUTHORIZATION_OFFSET..HX512_AUTHORIZATION_OFFSET + 8]
            .copy_from_slice(&(mode as u64).to_be_bytes());
        witness[HX512_AUTHORIZATION_OFFSET + 8..HX512_AUTHORIZATION_OFFSET + 208]
            .copy_from_slice(&current);
        witness[HX512_AUTHORIZATION_OFFSET + 208..HX512_AUTHORIZATION_OFFSET + 408]
            .copy_from_slice(&next);
        for (slot, tag) in signer_tags.into_iter().enumerate() {
            let start = HX512_AUTHORIZATION_OFFSET + 408 + slot * 64;
            witness[start..start + 64].copy_from_slice(&tag);
        }
        witness[HX512_POLICY_MASTERS_OFFSET..HX512_POLICY_MASTERS_OFFSET + 64]
            .copy_from_slice(&policy_masters[0]);
        witness[HX512_POLICY_MASTERS_OFFSET + 64..HX512_CIPHERTEXT_0_OFFSET]
            .copy_from_slice(&policy_masters[1]);
    }

    fn write_test_output(
        statement: &mut [u8; HX512_STATEMENT_BYTES],
        witness: &mut [u8; HX512_WITNESS_BYTES],
        index: usize,
        note: [u8; 232],
        asset_slot: usize,
        ciphertext_marker: u8,
    ) {
        let output_offset = HX512_OUTPUT_0_OFFSET + index * HX512_OUTPUT_BYTES;
        witness[output_offset..output_offset + 232].copy_from_slice(&note);
        witness[output_offset + 232 + asset_slot * 8..output_offset + 240 + asset_slot * 8]
            .copy_from_slice(&1u64.to_be_bytes());
        let commitment = note_hash(&note);
        let commitment_offset = HX512_STATEMENT_COMMITMENTS_OFFSET + index * HX512_DIGEST_BYTES;
        statement[commitment_offset..commitment_offset + HX512_DIGEST_BYTES]
            .copy_from_slice(&commitment);

        let ciphertext_offset =
            HX512_CIPHERTEXT_0_OFFSET + index * HX512_CIPHERTEXT_TRANSPORT_BYTES;
        witness[ciphertext_offset..ciphertext_offset + HX512_CIPHERTEXT_BYTES]
            .fill(ciphertext_marker);
        let family = [0x52];
        let domain = TEST_ONLY_IDENTITY.domain_set.to_be_bytes();
        let output_index = [index as u8];
        let width = (HX512_CIPHERTEXT_BYTES as u32).to_be_bytes();
        let digest = core_hash(
            TEST_ONLY_IDENTITY,
            ROLE_CIPHERTEXT,
            &[
                &family,
                &domain,
                &output_index,
                &width,
                &witness[ciphertext_offset..ciphertext_offset + HX512_CIPHERTEXT_BYTES],
            ],
        )
        .unwrap();
        let digest_offset = HX512_STATEMENT_CIPHERTEXT_HASHES_OFFSET + index * HX512_DIGEST_BYTES;
        statement[digest_offset..digest_offset + HX512_DIGEST_BYTES].copy_from_slice(&digest);
    }

    fn write_test_input(
        witness: &mut [u8; HX512_WITNESS_BYTES],
        index: usize,
        spend_master: [u8; 64],
        note: [u8; 232],
        position: u64,
        siblings: [[u8; 64]; 32],
        asset_slot: usize,
    ) {
        let input_offset = HX512_INPUT_0_OFFSET + index * HX512_INPUT_BYTES;
        witness[input_offset..input_offset + 64].copy_from_slice(&spend_master);
        witness[input_offset + 64..input_offset + 296].copy_from_slice(&note);
        witness[input_offset + 296..input_offset + 304].copy_from_slice(&position.to_be_bytes());
        for (level, sibling) in siblings.into_iter().enumerate() {
            let start = input_offset + 304 + level * 64;
            witness[start..start + 64].copy_from_slice(&sibling);
        }
        witness[input_offset + 2_352 + asset_slot * 8..input_offset + 2_360 + asset_slot * 8]
            .copy_from_slice(&1u64.to_be_bytes());
    }

    fn build_authorization_fixture(mode: Hx512AuthorizationMode, mask: u8) -> Fixture {
        assert_ne!(mode, Hx512AuthorizationMode::SingleKey);
        assert!(hx512_activity_mode_accepts(mode, mask));
        let flags: [bool; 4] = core::array::from_fn(|index| mask & (1 << index) != 0);
        let mut statement = [0u8; HX512_STATEMENT_BYTES];
        statement[..HX512_STATEMENT_IDENTITY_BYTES]
            .copy_from_slice(&TEST_ONLY_IDENTITY.encode_exact());
        statement[HX512_STATEMENT_CHAIN_ID_OFFSET..HX512_STATEMENT_GENESIS_ID_OFFSET]
            .copy_from_slice(&TEST_ONLY_BINDING.chain_id);
        statement[HX512_STATEMENT_GENESIS_ID_OFFSET..HX512_STATEMENT_RULES_HASH_OFFSET]
            .copy_from_slice(&TEST_ONLY_BINDING.genesis_id);
        statement[HX512_STATEMENT_RULES_HASH_OFFSET..HX512_STATEMENT_ACTIVITY_MASK_OFFSET]
            .copy_from_slice(&TEST_ONLY_BINDING.rules_hash);
        statement[HX512_STATEMENT_ACTIVITY_MASK_OFFSET] = mask;
        for index in 0..3 {
            let start = HX512_STATEMENT_ASSET_SLOTS_OFFSET + index * 8;
            statement[start..start + 8].copy_from_slice(&HX512_PADDING_ASSET.to_be_bytes());
        }
        statement[HX512_STATEMENT_FEE_OFFSET..HX512_STATEMENT_VALUE_BALANCE_ZERO_OFFSET]
            .copy_from_slice(&7u64.to_be_bytes());
        statement[HX512_STATEMENT_STABLE_PUBLIC_OFFSET..]
            .copy_from_slice(&StablecoinTransitionPublicV3::ZERO.encode_canonical());

        let mut witness = [0u8; HX512_WITNESS_BYTES];
        witness[HX512_STABLE_WITNESS_OFFSET..].copy_from_slice(
            &StablecoinTransitionWitnessV3::ZERO
                .encode_canonical()
                .unwrap(),
        );
        let mut spend_masters = [[0u8; 64]; 2];
        match mode {
            Hx512AuthorizationMode::AccumulatorInit | Hx512AuthorizationMode::ValueLockCreation => {
                for index in 0..2 {
                    if flags[index] {
                        spend_masters[index].fill(0x40 + index as u8);
                    }
                }
            }
            Hx512AuthorizationMode::ApprovalStep => spend_masters[1].fill(0x41),
            Hx512AuthorizationMode::FinalThresholdSpend => {}
            Hx512AuthorizationMode::SingleKey => unreachable!(),
        }

        let mut signer_tags = [[0u8; 64]; 6];
        signer_tags[0] = if mode == Hx512AuthorizationMode::ApprovalStep {
            spend_digest(TEST_ONLY_IDENTITY, &spend_masters[1], 0).unwrap()
        } else {
            [0xd1; 64]
        };
        signer_tags[1] = [0xd2; 64];
        assert_ne!(signer_tags[0], signer_tags[1]);
        let policy_master = [0xc0 + mode as u8; 64];
        let policy_masters = match mode {
            Hx512AuthorizationMode::AccumulatorInit => [[0u8; 64], policy_master],
            Hx512AuthorizationMode::ApprovalStep => [policy_master; 2],
            Hx512AuthorizationMode::ValueLockCreation
            | Hx512AuthorizationMode::FinalThresholdSpend => [policy_master, [0u8; 64]],
            Hx512AuthorizationMode::SingleKey => unreachable!(),
        };
        let policy_probe_raw = encode_accumulator([0u8; 64], [0u8; 64], 1, 2, [0u64; 6]);
        let policy_probe = Hx512Accumulator::decode(&policy_probe_raw).unwrap();
        let selected_master = if mode == Hx512AuthorizationMode::AccumulatorInit {
            &policy_masters[1]
        } else {
            &policy_masters[0]
        };
        let policy = policy_digest(
            TEST_ONLY_IDENTITY,
            selected_master,
            &policy_probe,
            &signer_tags,
        )
        .unwrap();

        // FinalThresholdSpend's preserved state commits the independently
        // derived transaction plan, so its ordinary outputs must be fixed
        // before the accumulator is encoded.  Other modes use future-plan
        // test markers and construct output zero from the resulting state.
        if mode == Hx512AuthorizationMode::FinalThresholdSpend {
            let active_outputs: Vec<_> = (0..2).filter(|index| flags[2 + *index]).collect();
            for index in active_outputs.iter().copied() {
                let value = if index == active_outputs[0] { 3 } else { 0 };
                let note = encode_typed_note(
                    0,
                    value,
                    0,
                    0x80 + index as u8,
                    0x90 + index as u8,
                    0xa0 + index as u8,
                    [0u8; 64],
                );
                write_test_output(
                    &mut statement,
                    &mut witness,
                    index,
                    note,
                    0,
                    0xb0 + mode as u8 * 4 + index as u8,
                );
            }
        }

        let (current_raw, next_raw) = match mode {
            Hx512AuthorizationMode::AccumulatorInit => (
                [0u8; 200],
                encode_accumulator(policy, [0xa1; 64], 1, 2, [0u64; 6]),
            ),
            Hx512AuthorizationMode::ApprovalStep => {
                let current = encode_accumulator(policy, [0xa2; 64], 1, 2, [0u64; 6]);
                let mut next_approved = [0u64; 6];
                next_approved[0] = 1;
                let next = encode_accumulator(policy, [0xa2; 64], 1, 2, next_approved);
                (current, next)
            }
            Hx512AuthorizationMode::ValueLockCreation => (
                encode_accumulator(policy, [0xa3; 64], 1, 2, [0u64; 6]),
                [0u8; 200],
            ),
            Hx512AuthorizationMode::FinalThresholdSpend => {
                let mut approved = [0u64; 6];
                approved[0] = 1;
                (
                    encode_accumulator(policy, raw_spend_plan_digest(&statement), 1, 2, approved),
                    [0u8; 200],
                )
            }
            Hx512AuthorizationMode::SingleKey => unreachable!(),
        };
        write_test_authorization(
            &mut witness,
            mode,
            current_raw,
            next_raw,
            signer_tags,
            policy_masters,
        );
        let authorization = Hx512Authorization::decode(
            &witness[HX512_AUTHORIZATION_OFFSET..HX512_POLICY_MASTERS_OFFSET],
            &witness[HX512_POLICY_MASTERS_OFFSET..HX512_CIPHERTEXT_0_OFFSET],
        )
        .unwrap();

        if mode != Hx512AuthorizationMode::FinalThresholdSpend {
            for index in 0..2 {
                if !flags[2 + index] {
                    continue;
                }
                let (kind, value, authorization_key) = if index == 0 {
                    match mode {
                        Hx512AuthorizationMode::AccumulatorInit => (
                            1,
                            0,
                            authorization_digest(TEST_ONLY_IDENTITY, &authorization, 0, 0).unwrap(),
                        ),
                        Hx512AuthorizationMode::ApprovalStep => (
                            1,
                            0,
                            authorization_digest(TEST_ONLY_IDENTITY, &authorization, 0, 1).unwrap(),
                        ),
                        Hx512AuthorizationMode::ValueLockCreation => (
                            2,
                            10,
                            authorization_digest(TEST_ONLY_IDENTITY, &authorization, 0, 0).unwrap(),
                        ),
                        _ => unreachable!(),
                    }
                } else {
                    (0, 0, [0u8; 64])
                };
                let note = encode_typed_note(
                    kind,
                    value,
                    0,
                    0x80 + mode as u8 * 4 + index as u8,
                    0x90 + mode as u8 * 4 + index as u8,
                    0xa0 + mode as u8 * 4 + index as u8,
                    authorization_key,
                );
                write_test_output(
                    &mut statement,
                    &mut witness,
                    index,
                    note,
                    0,
                    0xb0 + mode as u8 * 4 + index as u8,
                );
            }
        }

        let active_inputs: Vec<_> = (0..2).filter(|index| flags[*index]).collect();
        let spend_a: [[u8; 64]; 2] = core::array::from_fn(|index| {
            spend_digest(TEST_ONLY_IDENTITY, &spend_masters[index], 0).unwrap()
        });
        let spend_b: [[u8; 64]; 2] = core::array::from_fn(|index| {
            spend_digest(TEST_ONLY_IDENTITY, &spend_masters[index], 1).unwrap()
        });
        let (input_authorization, nullifier_keys) = match mode {
            Hx512AuthorizationMode::AccumulatorInit | Hx512AuthorizationMode::ValueLockCreation => {
                (spend_a, spend_b)
            }
            Hx512AuthorizationMode::ApprovalStep => (
                [
                    authorization_digest(TEST_ONLY_IDENTITY, &authorization, 0, 0).unwrap(),
                    spend_a[1],
                ],
                [
                    authorization_digest(TEST_ONLY_IDENTITY, &authorization, 1, 0).unwrap(),
                    spend_b[1],
                ],
            ),
            Hx512AuthorizationMode::FinalThresholdSpend => (
                [
                    authorization_digest(TEST_ONLY_IDENTITY, &authorization, 0, 1).unwrap(),
                    authorization_digest(TEST_ONLY_IDENTITY, &authorization, 0, 0).unwrap(),
                ],
                [
                    authorization_digest(TEST_ONLY_IDENTITY, &authorization, 1, 1).unwrap(),
                    authorization_digest(TEST_ONLY_IDENTITY, &authorization, 1, 0).unwrap(),
                ],
            ),
            Hx512AuthorizationMode::SingleKey => unreachable!(),
        };
        let mut notes = [[0u8; 232]; 2];
        for index in active_inputs.iter().copied() {
            let (kind, value) = match mode {
                Hx512AuthorizationMode::AccumulatorInit => {
                    (0, if index == active_inputs[0] { 7 } else { 0 })
                }
                Hx512AuthorizationMode::ApprovalStep => {
                    if index == 0 {
                        (1, 0)
                    } else {
                        (0, 7)
                    }
                }
                Hx512AuthorizationMode::ValueLockCreation => {
                    (0, if index == active_inputs[0] { 17 } else { 0 })
                }
                Hx512AuthorizationMode::FinalThresholdSpend => {
                    if index == 0 {
                        (2, 10)
                    } else {
                        (1, 0)
                    }
                }
                Hx512AuthorizationMode::SingleKey => unreachable!(),
            };
            notes[index] = encode_typed_note(
                kind,
                value,
                0,
                0x50 + mode as u8 * 4 + index as u8,
                0x60 + mode as u8 * 4 + index as u8,
                0x70 + mode as u8 * 4 + index as u8,
                input_authorization[index],
            );
        }
        let digests = [note_hash(&notes[0]), note_hash(&notes[1])];
        let mut positions = [0u64; 2];
        let mut siblings = [[[0u8; 64]; 32]; 2];
        if active_inputs.len() == 2 {
            positions = [0, 1];
            siblings[0][0] = digests[1];
            siblings[1][0] = digests[0];
        }
        let anchor = root_for(
            digests[active_inputs[0]],
            positions[active_inputs[0]],
            &siblings[active_inputs[0]],
        );
        statement[HX512_STATEMENT_ANCHOR_OFFSET..HX512_STATEMENT_NULLIFIERS_OFFSET]
            .copy_from_slice(&anchor);
        for index in active_inputs.iter().copied() {
            assert_eq!(
                root_for(digests[index], positions[index], &siblings[index]),
                anchor
            );
            write_test_input(
                &mut witness,
                index,
                spend_masters[index],
                notes[index],
                positions[index],
                siblings[index],
                0,
            );
            let input_offset = HX512_INPUT_0_OFFSET + index * HX512_INPUT_BYTES;
            let parsed_input =
                Hx512Input::decode(&witness[input_offset..input_offset + HX512_INPUT_BYTES])
                    .unwrap();
            let nullifier =
                nullifier_digest(TEST_ONLY_IDENTITY, &nullifier_keys[index], &parsed_input)
                    .unwrap();
            let public_offset = HX512_STATEMENT_NULLIFIERS_OFFSET + index * HX512_DIGEST_BYTES;
            statement[public_offset..public_offset + HX512_DIGEST_BYTES]
                .copy_from_slice(&nullifier);
        }

        let parsed =
            Hx512ProductionStatement::decode_exact(&statement, &TEST_ONLY_BINDING).unwrap();
        let mut context = [0u8; HX512_VERIFIER_CONTEXT_BYTES];
        context[72..].copy_from_slice(&parsed.action_intent_digest());
        Fixture {
            statement,
            context,
            witness,
        }
    }

    fn build_stable_fixture(direction: StablecoinTransitionDirectionV3) -> Fixture {
        use protocol_kernel::stablecoin_transition_v3::{
            stablecoin_current_epoch_from_parent_v3, stablecoin_issuer_authorization_v3,
            stablecoin_issuer_commitment_v3, stablecoin_policy_slot_v3,
            stablecoin_transition_root_from_membership_v3, StablecoinStateRowV3,
        };

        assert!(matches!(
            direction,
            StablecoinTransitionDirectionV3::Mint | StablecoinTransitionDirectionV3::Burn
        ));
        const PARENT_HEIGHT: u64 = (3 << 12) + 100;
        const MAGNITUDE: u64 = 25;
        const ISSUER_SECRET: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] =
            [0x42; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        let asset_id = 1_001u32;
        let policy_version = 7u32;
        let before = StablecoinStateRowV3 {
            asset_id,
            policy_version,
            active: true,
            enabled_at: 10,
            retired_at: Some(PARENT_HEIGHT + 1_000),
            issuer_commitment: stablecoin_issuer_commitment_v3(
                asset_id,
                policy_version,
                &ISSUER_SECRET,
            ),
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000,
            oracle_submitted_at: PARENT_HEIGHT - 10,
            oracle_max_age: 100,
            oracle_price_numerator: 3,
            oracle_price_denominator: 2,
            collateral_amount: 1_000,
            attestation_created_at: PARENT_HEIGHT - 20,
            attestation_disputed: false,
            attestation_present: true,
            attestation_max_age: 100,
            policy_admin_commitment: [0x11; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
            oracle_authority_commitment: [0x22; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
            attestation_authority_commitment: [0x33; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
            collateral_asset_id: 0,
            collateral_decimals: 8,
            collateral_scale: 100_000_000,
            locked_collateral_commitment: [0x44; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
            epoch_id: stablecoin_current_epoch_from_parent_v3(PARENT_HEIGHT),
            minted_in_epoch: 100,
            total_debt: 500,
            sequence: 7,
        };
        let mut after = before;
        after.sequence += 1;
        match direction {
            StablecoinTransitionDirectionV3::Mint => {
                after.minted_in_epoch += MAGNITUDE;
                after.total_debt += MAGNITUDE;
            }
            StablecoinTransitionDirectionV3::Burn => after.total_debt -= MAGNITUDE,
            StablecoinTransitionDirectionV3::Disabled => unreachable!(),
        }
        let stable_siblings: [StablecoinTransitionRootV3; STABLECOIN_TRANSITION_V3_DEPTH] =
            core::array::from_fn(|level| {
                let mut bytes = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
                for (offset, byte) in bytes.iter_mut().enumerate() {
                    *byte = (17 * (level + 1) + offset) as u8;
                }
                StablecoinTransitionRootV3::new(bytes)
            });
        let stable_witness = StablecoinTransitionWitnessV3 {
            index: stablecoin_policy_slot_v3(asset_id),
            before,
            after,
            siblings: stable_siblings,
            issuer_secret: if direction == StablecoinTransitionDirectionV3::Mint {
                ISSUER_SECRET
            } else {
                [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES]
            },
        };
        let before_root =
            stablecoin_transition_root_from_membership_v3(stable_witness.before_membership())
                .unwrap();
        let after_root =
            stablecoin_transition_root_from_membership_v3(stable_witness.after_membership())
                .unwrap();
        let mut stable_public = StablecoinTransitionPublicV3 {
            direction,
            asset_id,
            policy_version,
            magnitude: MAGNITUDE,
            action_intent: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
            before_root,
            after_root,
            after_epoch_id: after.epoch_id,
            after_minted_in_epoch: after.minted_in_epoch,
            after_total_debt: after.total_debt,
            after_sequence: after.sequence,
            issuer_authorization: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
        };

        let mut fixture = build_single_key_fixture(0x0f);
        fixture.statement
            [HX512_STATEMENT_ASSET_SLOTS_OFFSET..HX512_STATEMENT_ASSET_SLOTS_OFFSET + 8]
            .copy_from_slice(&u64::from(asset_id).to_be_bytes());
        let (stable_input, stable_output) = match direction {
            StablecoinTransitionDirectionV3::Mint => (0u64, MAGNITUDE),
            StablecoinTransitionDirectionV3::Burn => (MAGNITUDE, 0u64),
            StablecoinTransitionDirectionV3::Disabled => unreachable!(),
        };
        let input_1_note = HX512_INPUT_1_OFFSET + 64;
        fixture.witness[input_1_note + 8..input_1_note + 16]
            .copy_from_slice(&stable_input.to_be_bytes());
        fixture.witness[input_1_note + 16..input_1_note + 24]
            .copy_from_slice(&u64::from(asset_id).to_be_bytes());
        fixture.witness[HX512_INPUT_1_OFFSET + 2_352..HX512_INPUT_1_OFFSET + 2_384].fill(0);
        fixture.witness[HX512_INPUT_1_OFFSET + 2_360..HX512_INPUT_1_OFFSET + 2_368]
            .copy_from_slice(&1u64.to_be_bytes());

        let output_1_note = HX512_OUTPUT_1_OFFSET;
        fixture.witness[output_1_note + 8..output_1_note + 16]
            .copy_from_slice(&stable_output.to_be_bytes());
        fixture.witness[output_1_note + 16..output_1_note + 24]
            .copy_from_slice(&u64::from(asset_id).to_be_bytes());
        fixture.witness[HX512_OUTPUT_1_OFFSET + 232..HX512_OUTPUT_1_OFFSET + 264].fill(0);
        fixture.witness[HX512_OUTPUT_1_OFFSET + 240..HX512_OUTPUT_1_OFFSET + 248]
            .copy_from_slice(&1u64.to_be_bytes());

        let input_notes: [[u8; 232]; 2] = [
            exact_array(&fixture.witness[HX512_INPUT_0_OFFSET + 64..HX512_INPUT_0_OFFSET + 296]),
            exact_array(&fixture.witness[HX512_INPUT_1_OFFSET + 64..HX512_INPUT_1_OFFSET + 296]),
        ];
        let input_digests = [note_hash(&input_notes[0]), note_hash(&input_notes[1])];
        fixture.witness[HX512_INPUT_0_OFFSET + 304..HX512_INPUT_0_OFFSET + 368]
            .copy_from_slice(&input_digests[1]);
        fixture.witness[HX512_INPUT_1_OFFSET + 304..HX512_INPUT_1_OFFSET + 368]
            .copy_from_slice(&input_digests[0]);
        let parsed_inputs = [
            Hx512Input::decode(&fixture.witness[HX512_INPUT_0_OFFSET..HX512_INPUT_1_OFFSET])
                .unwrap(),
            Hx512Input::decode(&fixture.witness[HX512_INPUT_1_OFFSET..HX512_OUTPUT_0_OFFSET])
                .unwrap(),
        ];
        let anchor = root_for(
            input_digests[0],
            parsed_inputs[0].position,
            &parsed_inputs[0].siblings,
        );
        assert_eq!(
            root_for(
                input_digests[1],
                parsed_inputs[1].position,
                &parsed_inputs[1].siblings,
            ),
            anchor
        );
        fixture.statement[HX512_STATEMENT_ANCHOR_OFFSET..HX512_STATEMENT_NULLIFIERS_OFFSET]
            .copy_from_slice(&anchor);
        for (index, input) in parsed_inputs.iter().enumerate() {
            let key = spend_digest(TEST_ONLY_IDENTITY, &input.spend_master, 1).unwrap();
            let nullifier = nullifier_digest(TEST_ONLY_IDENTITY, &key, input).unwrap();
            let start = HX512_STATEMENT_NULLIFIERS_OFFSET + index * HX512_DIGEST_BYTES;
            fixture.statement[start..start + HX512_DIGEST_BYTES].copy_from_slice(&nullifier);
        }
        let output_1_raw: [u8; 232] =
            exact_array(&fixture.witness[HX512_OUTPUT_1_OFFSET..HX512_OUTPUT_1_OFFSET + 232]);
        fixture.statement[HX512_STATEMENT_COMMITMENTS_OFFSET + HX512_DIGEST_BYTES
            ..HX512_STATEMENT_CIPHERTEXT_HASHES_OFFSET]
            .copy_from_slice(&note_hash(&output_1_raw));

        fixture.witness[HX512_STABLE_WITNESS_OFFSET..]
            .copy_from_slice(&stable_witness.encode_canonical().unwrap());
        fixture.statement[HX512_STATEMENT_STABLE_PUBLIC_OFFSET..]
            .copy_from_slice(&stable_public.encode_canonical());
        stable_public.action_intent = raw_action_intent_digest(&fixture.statement);
        if direction == StablecoinTransitionDirectionV3::Mint {
            stable_public.issuer_authorization =
                stablecoin_issuer_authorization_v3(stable_public, &ISSUER_SECRET);
        }
        fixture.statement[HX512_STATEMENT_STABLE_PUBLIC_OFFSET..]
            .copy_from_slice(&stable_public.encode_canonical());
        assert_eq!(
            raw_action_intent_digest(&fixture.statement),
            stable_public.action_intent
        );
        fixture.context[..64].copy_from_slice(before_root.as_bytes());
        fixture.context[64..72].copy_from_slice(&PARENT_HEIGHT.to_le_bytes());
        fixture.context[72..].copy_from_slice(&stable_public.action_intent);
        fixture
    }

    struct RefinementStableContext {
        public: StablecoinTransitionPublicV3,
        issuer_secret: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
        before_root: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
        parent_height: u64,
    }

    fn refinement_base_fixture(mode: Hx512AuthorizationMode) -> Fixture {
        match mode {
            Hx512AuthorizationMode::SingleKey => build_single_key_fixture(0x0f),
            Hx512AuthorizationMode::AccumulatorInit
            | Hx512AuthorizationMode::ApprovalStep
            | Hx512AuthorizationMode::ValueLockCreation
            | Hx512AuthorizationMode::FinalThresholdSpend => {
                build_authorization_fixture(mode, 0x0f)
            }
        }
    }

    fn write_refinement_note_asset(
        fixture: &mut Fixture,
        input: bool,
        index: usize,
        value: u64,
        asset: u64,
        asset_slot: usize,
    ) {
        let (note_start, selector_start) = if input {
            let base = HX512_INPUT_0_OFFSET + index * HX512_INPUT_BYTES;
            (base + 64, base + 2_352)
        } else {
            let base = HX512_OUTPUT_0_OFFSET + index * HX512_OUTPUT_BYTES;
            (base, base + 232)
        };
        fixture.witness[note_start + 8..note_start + 16].copy_from_slice(&value.to_be_bytes());
        fixture.witness[note_start + 16..note_start + 24].copy_from_slice(&asset.to_be_bytes());
        fixture.witness[selector_start..selector_start + 32].fill(0);
        fixture.witness[selector_start + asset_slot * 8..selector_start + (asset_slot + 1) * 8]
            .copy_from_slice(&1u64.to_be_bytes());
    }

    fn refresh_refinement_output_commitment(fixture: &mut Fixture, index: usize) {
        let output_start = HX512_OUTPUT_0_OFFSET + index * HX512_OUTPUT_BYTES;
        let raw: [u8; 232] = exact_array(&fixture.witness[output_start..output_start + 232]);
        let commitment = note_hash(&raw);
        let public_start = HX512_STATEMENT_COMMITMENTS_OFFSET + index * HX512_DIGEST_BYTES;
        fixture.statement[public_start..public_start + HX512_DIGEST_BYTES]
            .copy_from_slice(&commitment);
    }

    fn refresh_final_threshold_plan(fixture: &mut Fixture) -> Result<(), Hx512RelationError> {
        let spend_plan = raw_spend_plan_digest(&fixture.statement);
        let current_spend_plan = HX512_AUTHORIZATION_OFFSET + 8 + 64;
        fixture.witness[current_spend_plan..current_spend_plan + HX512_DIGEST_BYTES]
            .copy_from_slice(&spend_plan);
        let authorization = Hx512Authorization::decode(
            &fixture.witness[HX512_AUTHORIZATION_OFFSET..HX512_POLICY_MASTERS_OFFSET],
            &fixture.witness[HX512_POLICY_MASTERS_OFFSET..HX512_CIPHERTEXT_0_OFFSET],
        )?;
        for (input, authorization_slot) in [(0usize, 1usize), (1usize, 0usize)] {
            let digest =
                authorization_digest(TEST_ONLY_IDENTITY, &authorization, 0, authorization_slot)?;
            let note_authorization = HX512_INPUT_0_OFFSET + input * HX512_INPUT_BYTES + 64 + 168;
            fixture.witness[note_authorization..note_authorization + HX512_DIGEST_BYTES]
                .copy_from_slice(&digest);
        }
        Ok(())
    }

    fn install_refinement_stable_transition(
        fixture: &mut Fixture,
        mode: Hx512AuthorizationMode,
        direction: StablecoinTransitionDirectionV3,
    ) -> Result<RefinementStableContext, Hx512RelationError> {
        let donor = build_stable_fixture(direction);
        let stable_raw =
            &donor.statement[HX512_STATEMENT_STABLE_PUBLIC_OFFSET..HX512_STATEMENT_BYTES];
        let mut public = StablecoinTransitionPublicV3::decode_canonical(stable_raw)?;
        let stable_witness = StablecoinTransitionWitnessV3::decode_canonical(
            &donor.witness[HX512_STABLE_WITNESS_OFFSET..HX512_WITNESS_BYTES],
        )?;
        let issuer_secret = stable_witness.issuer_secret;
        let before_root = exact_array(&donor.context[..64]);
        let parent_height = u64::from_le_bytes(exact_array(&donor.context[64..72]));

        public.action_intent = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        public.issuer_authorization = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        fixture.statement[HX512_STATEMENT_STABLE_PUBLIC_OFFSET..]
            .copy_from_slice(&public.encode_canonical());
        fixture.witness[HX512_STABLE_WITNESS_OFFSET..]
            .copy_from_slice(&stable_witness.encode_canonical()?);
        fixture.statement
            [HX512_STATEMENT_ASSET_SLOTS_OFFSET..HX512_STATEMENT_ASSET_SLOTS_OFFSET + 8]
            .copy_from_slice(&u64::from(public.asset_id).to_be_bytes());

        match direction {
            StablecoinTransitionDirectionV3::Disabled => {
                return Err(Hx512RelationError::Semantic(
                    "disabled direction cannot install an enabled stablecoin fixture",
                ));
            }
            StablecoinTransitionDirectionV3::Mint => {
                write_refinement_note_asset(
                    fixture,
                    false,
                    1,
                    public.magnitude,
                    u64::from(public.asset_id),
                    1,
                );
                refresh_refinement_output_commitment(fixture, 1);
            }
            StablecoinTransitionDirectionV3::Burn => {
                let input = if mode == Hx512AuthorizationMode::FinalThresholdSpend {
                    0
                } else {
                    1
                };
                write_refinement_note_asset(
                    fixture,
                    true,
                    input,
                    public.magnitude,
                    u64::from(public.asset_id),
                    1,
                );
                if mode == Hx512AuthorizationMode::ApprovalStep {
                    fixture.statement
                        [HX512_STATEMENT_FEE_OFFSET..HX512_STATEMENT_VALUE_BALANCE_ZERO_OFFSET]
                        .copy_from_slice(&0u64.to_be_bytes());
                } else if mode == Hx512AuthorizationMode::FinalThresholdSpend {
                    fixture.statement
                        [HX512_STATEMENT_FEE_OFFSET..HX512_STATEMENT_VALUE_BALANCE_ZERO_OFFSET]
                        .copy_from_slice(&0u64.to_be_bytes());
                    write_refinement_note_asset(fixture, false, 0, 0, 0, 0);
                    refresh_refinement_output_commitment(fixture, 0);
                }
            }
        }

        if mode == Hx512AuthorizationMode::FinalThresholdSpend {
            refresh_final_threshold_plan(fixture)?;
        }
        Ok(RefinementStableContext {
            public,
            issuer_secret,
            before_root,
            parent_height,
        })
    }

    fn apply_refinement_secret_variant(
        fixture: &mut Fixture,
        mode: Hx512AuthorizationMode,
        secret_variant: u8,
    ) -> Result<(), Hx512RelationError> {
        if secret_variant > 1 {
            return Err(Hx512RelationError::NonCanonical(
                "refinement secret variant is outside 0..1",
            ));
        }
        for input in 0..2 {
            let marker = 0xe0u8
                .checked_add((mode as u8) * 4)
                .and_then(|value| value.checked_add(secret_variant * 2))
                .and_then(|value| value.checked_add(input as u8))
                .ok_or(Hx512RelationError::NonCanonical(
                    "refinement secret marker overflow",
                ))?;
            let rho_start = HX512_INPUT_0_OFFSET + input * HX512_INPUT_BYTES + 64 + 56;
            fixture.witness[rho_start..rho_start + 48].fill(marker);
        }
        Ok(())
    }

    fn refinement_nullifier_keys(
        fixture: &Fixture,
        mode: Hx512AuthorizationMode,
    ) -> Result<[[u8; HX512_DIGEST_BYTES]; 2], Hx512RelationError> {
        let authorization = Hx512Authorization::decode(
            &fixture.witness[HX512_AUTHORIZATION_OFFSET..HX512_POLICY_MASTERS_OFFSET],
            &fixture.witness[HX512_POLICY_MASTERS_OFFSET..HX512_CIPHERTEXT_0_OFFSET],
        )?;
        let masters: [[u8; HX512_DIGEST_BYTES]; 2] = core::array::from_fn(|input| {
            let start = HX512_INPUT_0_OFFSET + input * HX512_INPUT_BYTES;
            exact_array(&fixture.witness[start..start + HX512_DIGEST_BYTES])
        });
        match mode {
            Hx512AuthorizationMode::SingleKey
            | Hx512AuthorizationMode::AccumulatorInit
            | Hx512AuthorizationMode::ValueLockCreation => Ok([
                spend_digest(TEST_ONLY_IDENTITY, &masters[0], 1)?,
                spend_digest(TEST_ONLY_IDENTITY, &masters[1], 1)?,
            ]),
            Hx512AuthorizationMode::ApprovalStep => Ok([
                authorization_digest(TEST_ONLY_IDENTITY, &authorization, 1, 0)?,
                spend_digest(TEST_ONLY_IDENTITY, &masters[1], 1)?,
            ]),
            Hx512AuthorizationMode::FinalThresholdSpend => Ok([
                authorization_digest(TEST_ONLY_IDENTITY, &authorization, 1, 1)?,
                authorization_digest(TEST_ONLY_IDENTITY, &authorization, 1, 0)?,
            ]),
        }
    }

    fn refresh_refinement_input_bindings(
        fixture: &mut Fixture,
        mode: Hx512AuthorizationMode,
    ) -> Result<(), Hx512RelationError> {
        let notes: [[u8; 232]; 2] = core::array::from_fn(|input| {
            let start = HX512_INPUT_0_OFFSET + input * HX512_INPUT_BYTES + 64;
            exact_array(&fixture.witness[start..start + 232])
        });
        let digests = [note_hash(&notes[0]), note_hash(&notes[1])];
        for input in 0..2 {
            let base = HX512_INPUT_0_OFFSET + input * HX512_INPUT_BYTES;
            fixture.witness[base + 296..base + 304].copy_from_slice(&(input as u64).to_be_bytes());
            fixture.witness[base + 304..base + 2_352].fill(0);
            fixture.witness[base + 304..base + 368].copy_from_slice(&digests[1 - input]);
        }
        let parsed_inputs = [
            Hx512Input::decode(&fixture.witness[HX512_INPUT_0_OFFSET..HX512_INPUT_1_OFFSET])?,
            Hx512Input::decode(&fixture.witness[HX512_INPUT_1_OFFSET..HX512_OUTPUT_0_OFFSET])?,
        ];
        let anchor = root_for(
            digests[0],
            parsed_inputs[0].position,
            &parsed_inputs[0].siblings,
        );
        if root_for(
            digests[1],
            parsed_inputs[1].position,
            &parsed_inputs[1].siblings,
        ) != anchor
        {
            return Err(Hx512RelationError::Semantic(
                "refinement fixture input roots diverge",
            ));
        }
        fixture.statement[HX512_STATEMENT_ANCHOR_OFFSET..HX512_STATEMENT_NULLIFIERS_OFFSET]
            .copy_from_slice(&anchor);
        let nullifier_keys = refinement_nullifier_keys(fixture, mode)?;
        for input in 0..2 {
            let nullifier = nullifier_digest(
                TEST_ONLY_IDENTITY,
                &nullifier_keys[input],
                &parsed_inputs[input],
            )?;
            let start = HX512_STATEMENT_NULLIFIERS_OFFSET + input * HX512_DIGEST_BYTES;
            fixture.statement[start..start + HX512_DIGEST_BYTES].copy_from_slice(&nullifier);
        }
        Ok(())
    }

    fn finish_refinement_context(
        fixture: &mut Fixture,
        stable: Option<RefinementStableContext>,
    ) -> Result<(), Hx512RelationError> {
        let action_intent = raw_action_intent_digest(&fixture.statement);
        fixture.context.fill(0);
        match stable {
            None => {
                fixture.context[72..].copy_from_slice(&action_intent);
            }
            Some(mut stable) => {
                stable.public.action_intent = action_intent;
                if stable.public.direction == StablecoinTransitionDirectionV3::Mint {
                    stable.public.issuer_authorization =
                        protocol_kernel::stablecoin_transition_v3::stablecoin_issuer_authorization_v3(
                            stable.public,
                            &stable.issuer_secret,
                        );
                }
                fixture.statement[HX512_STATEMENT_STABLE_PUBLIC_OFFSET..]
                    .copy_from_slice(&stable.public.encode_canonical());
                if raw_action_intent_digest(&fixture.statement) != action_intent {
                    return Err(Hx512RelationError::Semantic(
                        "refinement action-intent finalization is cyclic",
                    ));
                }
                fixture.context[..64].copy_from_slice(&stable.before_root);
                fixture.context[64..72].copy_from_slice(&stable.parent_height.to_le_bytes());
                fixture.context[72..].copy_from_slice(&action_intent);
            }
        }
        Ok(())
    }

    fn build_refinement_fixture(
        mode: Hx512AuthorizationMode,
        direction: StablecoinTransitionDirectionV3,
        secret_variant: u8,
    ) -> Result<Fixture, Hx512RelationError> {
        let mut fixture = refinement_base_fixture(mode);
        let stable = match direction {
            StablecoinTransitionDirectionV3::Disabled => None,
            StablecoinTransitionDirectionV3::Mint | StablecoinTransitionDirectionV3::Burn => Some(
                install_refinement_stable_transition(&mut fixture, mode, direction)?,
            ),
        };
        apply_refinement_secret_variant(&mut fixture, mode, secret_variant)?;
        refresh_refinement_input_bindings(&mut fixture, mode)?;
        finish_refinement_context(&mut fixture, stable)?;
        Ok(fixture)
    }

    #[cfg(feature = "hx512-refinement-evidence")]
    pub(super) fn build_mode_mask_refinement_cases(
    ) -> Result<Vec<Hx512ModeMaskRefinementCase>, Hx512RelationError> {
        let mut cases = Vec::with_capacity(HX512_MODE_MASK_REFINEMENT_CASE_COUNT);
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for mode in HX512_AUTHORIZATION_MODES {
            for activity_mask in 0u8..16 {
                let classification = match ensure_hx512_activity_mode_accepted(mode, activity_mask)
                {
                    Ok(()) => {
                        let fixture = match mode {
                            Hx512AuthorizationMode::SingleKey => {
                                build_single_key_fixture(activity_mask)
                            }
                            Hx512AuthorizationMode::AccumulatorInit
                            | Hx512AuthorizationMode::ApprovalStep
                            | Hx512AuthorizationMode::ValueLockCreation
                            | Hx512AuthorizationMode::FinalThresholdSpend => {
                                build_authorization_fixture(mode, activity_mask)
                            }
                        };
                        let materialized = materialize_hx512_production_relation(
                            &fixture.statement,
                            &fixture.context,
                            &fixture.witness,
                            &TEST_ONLY_BINDING,
                        )?;
                        if materialized.witness.authorization.mode != mode
                            || materialized.statement.activity_mask != activity_mask
                            || materialized.statement.stable_public.direction
                                != StablecoinTransitionDirectionV3::Disabled
                            || materialized.statement.encode_exact() != fixture.statement
                            || materialized.verifier_context.encode_exact() != fixture.context
                            || materialized.witness.encode_exact() != fixture.witness
                        {
                            return Err(Hx512RelationError::Semantic(
                                "mode/mask refinement fixture is not a canonical round trip",
                            ));
                        }
                        accepted += 1;
                        Hx512ModeMaskRefinementClassification::Accepted {
                            statement: fixture.statement.to_vec(),
                            context: fixture.context.to_vec(),
                            witness: fixture.witness.to_vec(),
                            expected_binding: TEST_ONLY_BINDING,
                        }
                    }
                    Err(
                        error @ Hx512RelationError::RejectedModeMask {
                            mode: rejected_mode,
                            mask: rejected_mask,
                        },
                    ) => {
                        if rejected_mode != mode || rejected_mask != activity_mask {
                            return Err(Hx512RelationError::Semantic(
                                "mode/mask refinement rejection label drift",
                            ));
                        }
                        rejected += 1;
                        Hx512ModeMaskRefinementClassification::RejectedModeMask { error }
                    }
                    Err(_) => {
                        return Err(Hx512RelationError::Semantic(
                            "mode/mask grammar returned an unexpected classification",
                        ));
                    }
                };
                cases.push(Hx512ModeMaskRefinementCase {
                    mode,
                    activity_mask,
                    classification,
                });
            }
        }
        if cases.len() != HX512_MODE_MASK_REFINEMENT_CASE_COUNT
            || accepted != HX512_MODE_MASK_REFINEMENT_ACCEPTED_COUNT
            || rejected != HX512_MODE_MASK_REFINEMENT_REJECTED_COUNT
        {
            return Err(Hx512RelationError::Semantic(
                "mode/mask refinement matrix cardinality drift",
            ));
        }
        Ok(cases)
    }

    #[cfg(feature = "hx512-refinement-evidence")]
    pub(super) fn build_refinement_fixtures(
    ) -> Result<Vec<Hx512RefinementFixture>, Hx512RelationError> {
        let modes = [
            Hx512AuthorizationMode::SingleKey,
            Hx512AuthorizationMode::AccumulatorInit,
            Hx512AuthorizationMode::ApprovalStep,
            Hx512AuthorizationMode::ValueLockCreation,
            Hx512AuthorizationMode::FinalThresholdSpend,
        ];
        let directions = [
            StablecoinTransitionDirectionV3::Disabled,
            StablecoinTransitionDirectionV3::Mint,
            StablecoinTransitionDirectionV3::Burn,
        ];
        let mut fixtures = Vec::with_capacity(HX512_REFINEMENT_FIXTURE_COUNT);
        for mode in modes {
            for stable_direction in directions {
                let mut first_secret_witness = None;
                for secret_variant in 0..=1 {
                    let fixture = build_refinement_fixture(mode, stable_direction, secret_variant)?;
                    let materialized = materialize_hx512_production_relation(
                        &fixture.statement,
                        &fixture.context,
                        &fixture.witness,
                        &TEST_ONLY_BINDING,
                    )?;
                    if materialized.witness.authorization.mode != mode
                        || materialized.statement.stable_public.direction != stable_direction
                    {
                        return Err(Hx512RelationError::Semantic(
                            "refinement fixture labels do not match materialized bytes",
                        ));
                    }
                    if let Some(first) = &first_secret_witness {
                        if first == &fixture.witness {
                            return Err(Hx512RelationError::Semantic(
                                "refinement secret pair has identical witness bytes",
                            ));
                        }
                    } else {
                        first_secret_witness = Some(fixture.witness);
                    }
                    let candidate = Hx512RefinementFixture {
                        mode,
                        stable_direction,
                        secret_variant,
                        statement: fixture.statement.to_vec(),
                        context: fixture.context.to_vec(),
                        witness: fixture.witness.to_vec(),
                        expected_binding: TEST_ONLY_BINDING,
                    };
                    if fixtures.iter().any(|prior: &Hx512RefinementFixture| {
                        prior.statement == candidate.statement
                            && prior.context == candidate.context
                            && prior.witness == candidate.witness
                    }) {
                        return Err(Hx512RelationError::Semantic(
                            "refinement fixture matrix contains duplicate raw surfaces",
                        ));
                    }
                    fixtures.push(candidate);
                }
            }
        }
        if fixtures.len() != HX512_REFINEMENT_FIXTURE_COUNT {
            return Err(Hx512RelationError::Semantic(
                "refinement fixture matrix cardinality is not 30",
            ));
        }
        Ok(fixtures)
    }

    fn fixture_surface<'a>(fixture: &'a Fixture, range: Hx512ByteRange) -> &'a [u8] {
        let surface = match range.surface {
            Hx512WireSurface::Statement => &fixture.statement[..],
            Hx512WireSurface::VerifierContext => &fixture.context[..],
            Hx512WireSurface::Witness => &fixture.witness[..],
        };
        &surface[range.offset..range.offset + range.bytes]
    }

    fn exact_recipe_digest_for_mode(
        fixture: &Fixture,
        registry: &[Hx512HashCallRecipe],
        mode: Hx512AuthorizationMode,
        call_index: usize,
        memo: &mut [Option<[u8; 64]>],
        visiting: &mut [bool],
    ) -> [u8; 64] {
        if let Some(digest) = memo[call_index] {
            return digest;
        }
        assert!(
            !visiting[call_index],
            "hash recipe dependency cycle at {call_index}"
        );
        visiting[call_index] = true;
        let expanded =
            hx512_exact_hash_message_recipe(TEST_ONLY_IDENTITY, call_index, mode).unwrap();
        let mut message = Vec::with_capacity(expanded.message_bytes);
        let mut append_source = |source: &Hx512HashAtomSource, message: &mut Vec<u8>| match source {
            Hx512HashAtomSource::Literal(bytes) => message.extend_from_slice(bytes),
            Hx512HashAtomSource::Surface(range) => {
                message.extend_from_slice(fixture_surface(fixture, *range))
            }
            Hx512HashAtomSource::PriorDigest { call_index } => {
                let digest = exact_recipe_digest_for_mode(
                    fixture,
                    registry,
                    mode,
                    *call_index,
                    memo,
                    visiting,
                );
                message.extend_from_slice(&digest);
            }
        };
        for atom in &expanded.atoms {
            match atom {
                Hx512HashMessageAtom::Copy(source) => append_source(source, &mut message),
                Hx512HashMessageAtom::LowByte(range) => {
                    message.push(*fixture_surface(fixture, *range).last().unwrap());
                }
                Hx512HashMessageAtom::Select {
                    selector,
                    when_zero,
                    when_one,
                } => {
                    let bit =
                        (fixture_surface(fixture, selector.byte)[0] >> selector.bit_in_byte) & 1;
                    append_source(if bit == 0 { when_zero } else { when_one }, &mut message);
                }
            }
        }
        assert_eq!(message.len(), expanded.message_bytes);
        let digest = blake2b512_personalized_v2(&message, registry[call_index].personalization);
        visiting[call_index] = false;
        memo[call_index] = Some(digest);
        digest
    }

    fn exact_recipe_digest(
        fixture: &Fixture,
        registry: &[Hx512HashCallRecipe],
        call_index: usize,
        memo: &mut [Option<[u8; 64]>],
        visiting: &mut [bool],
    ) -> [u8; 64] {
        exact_recipe_digest_for_mode(
            fixture,
            registry,
            Hx512AuthorizationMode::SingleKey,
            call_index,
            memo,
            visiting,
        )
    }

    fn fixture_kat(fixture: &Fixture) -> [u8; 64] {
        let mut bytes = Vec::with_capacity(
            HX512_STATEMENT_BYTES + HX512_VERIFIER_CONTEXT_BYTES + HX512_WITNESS_BYTES,
        );
        bytes.extend_from_slice(&fixture.statement);
        bytes.extend_from_slice(&fixture.context);
        bytes.extend_from_slice(&fixture.witness);
        blake2b512_personalized_v2(&bytes, *b"HX512FIXTUREKAT!")
    }

    fn assert_full_fixture_and_registry(
        fixture: &Fixture,
        expected_mode: Hx512AuthorizationMode,
    ) -> [u8; 64] {
        let materialized = materialize_hx512_production_relation(
            &fixture.statement,
            &fixture.context,
            &fixture.witness,
            &TEST_ONLY_BINDING,
        )
        .unwrap();
        assert_eq!(materialized.statement.encode_exact(), fixture.statement);
        assert_eq!(
            materialized.verifier_context.encode_exact(),
            fixture.context
        );
        assert_eq!(materialized.witness.encode_exact(), fixture.witness);
        assert_eq!(materialized.witness.authorization.mode, expected_mode);
        assert_eq!(materialized.shape, hx512_relation_shape(TEST_ONLY_IDENTITY));

        let registry = hx512_hash_call_recipe_registry(TEST_ONLY_IDENTITY);
        assert_eq!(registry.len(), 95);
        assert_eq!(materialized.hash_recipes, registry);
        let mut memo = vec![None; registry.len()];
        let mut visiting = vec![false; registry.len()];
        for call_index in 0..registry.len() {
            let _ = exact_recipe_digest_for_mode(
                fixture,
                &registry,
                expected_mode,
                call_index,
                &mut memo,
                &mut visiting,
            );
        }
        for (index, expected) in materialized.derived.note_commitments.iter().enumerate() {
            assert_eq!(memo[index].unwrap(), *expected);
        }
        for (index, expected) in materialized.derived.nullifiers.iter().enumerate() {
            assert_eq!(memo[4 + index].unwrap(), *expected);
        }
        for input in 0..2 {
            assert_eq!(
                memo[6 + input * 32 + 31].unwrap(),
                materialized.derived.merkle_roots[input]
            );
        }
        for lane in 0..2 {
            for input in 0..2 {
                assert_eq!(
                    memo[70 + lane * 2 + input].unwrap(),
                    spend_digest(
                        TEST_ONLY_IDENTITY,
                        &materialized.witness.inputs[input].spend_master,
                        lane,
                    )
                    .unwrap()
                );
            }
        }
        assert_eq!(memo[74].unwrap(), materialized.derived.authorization_policy);
        for lane in 0..2 {
            for slot in 0..2 {
                assert_eq!(
                    memo[75 + lane * 2 + slot].unwrap(),
                    authorization_digest(
                        TEST_ONLY_IDENTITY,
                        &materialized.witness.authorization,
                        lane,
                        slot,
                    )
                    .unwrap()
                );
            }
        }
        assert_eq!(memo[79].unwrap(), materialized.derived.action_intent);
        assert_eq!(memo[80].unwrap(), materialized.derived.spend_plan);
        for output in 0..2 {
            assert_eq!(
                memo[81 + output].unwrap(),
                materialized.derived.ciphertext_hashes[output]
            );
        }

        let direction = materialized.statement.stable_public.direction;
        let flags = materialized.statement.activity_flags();
        for (call_index, call) in registry.iter().enumerate() {
            for target in &call.public_digest_targets {
                let active = match target.condition {
                    Hx512HashTargetCondition::Always => true,
                    Hx512HashTargetCondition::InputActive(input) => flags[usize::from(input)],
                    Hx512HashTargetCondition::OutputActive(output) => {
                        flags[2 + usize::from(output)]
                    }
                    Hx512HashTargetCondition::StableEnabled => {
                        direction != StablecoinTransitionDirectionV3::Disabled
                    }
                    Hx512HashTargetCondition::StableMint => {
                        direction == StablecoinTransitionDirectionV3::Mint
                    }
                };
                if active {
                    assert_eq!(
                        fixture_surface(fixture, target.range),
                        &memo[call_index].unwrap(),
                        "public digest target mismatch for call {call_index}"
                    );
                }
            }
        }
        fixture_kat(fixture)
    }

    #[cfg(feature = "hx512-refinement-evidence")]
    #[test]
    fn refinement_evidence_matrix_is_exact_ordered_distinct_and_fail_closed() {
        let fixtures = hx512_refinement_fixtures().unwrap();
        assert_eq!(fixtures.len(), HX512_REFINEMENT_FIXTURE_COUNT);
        assert!(HX512_REFINEMENT_EVIDENCE_FEATURE_ENABLED);
        assert!(HX512_REFINEMENT_EVIDENCE_PRODUCTION_FORBIDDEN);
        assert!(matches!(
            ensure_hx512_production_authorized(),
            Err(Hx512RelationError::RefinementEvidenceFeatureEnabled)
        ));
        assert!(matches!(
            ensure_hx512_refinement_evidence_not_production(),
            Err(Hx512RelationError::RefinementEvidenceFeatureEnabled)
        ));

        let modes = [
            Hx512AuthorizationMode::SingleKey,
            Hx512AuthorizationMode::AccumulatorInit,
            Hx512AuthorizationMode::ApprovalStep,
            Hx512AuthorizationMode::ValueLockCreation,
            Hx512AuthorizationMode::FinalThresholdSpend,
        ];
        let directions = [
            StablecoinTransitionDirectionV3::Disabled,
            StablecoinTransitionDirectionV3::Mint,
            StablecoinTransitionDirectionV3::Burn,
        ];
        for (mode_index, mode) in modes.into_iter().enumerate() {
            for (direction_index, direction) in directions.into_iter().enumerate() {
                let pair_start = mode_index * 6 + direction_index * 2;
                let first = &fixtures[pair_start];
                let second = &fixtures[pair_start + 1];
                for (secret_variant, fixture) in [(0u8, first), (1u8, second)] {
                    assert_eq!(fixture.mode, mode);
                    assert_eq!(fixture.stable_direction, direction);
                    assert_eq!(fixture.secret_variant, secret_variant);
                    assert_eq!(fixture.statement.len(), HX512_STATEMENT_BYTES);
                    assert_eq!(
                        fixture.verifier_context().len(),
                        HX512_VERIFIER_CONTEXT_BYTES
                    );
                    assert_eq!(fixture.witness.len(), HX512_WITNESS_BYTES);
                    materialize_hx512_production_relation(
                        &fixture.statement,
                        fixture.verifier_context(),
                        &fixture.witness,
                        &fixture.expected_binding,
                    )
                    .unwrap();
                }
                assert_ne!(first.witness, second.witness);
                assert_eq!(first.statement.len(), second.statement.len());
                assert_eq!(first.context.len(), second.context.len());
            }
        }
    }

    #[cfg(feature = "hx512-refinement-evidence")]
    #[test]
    fn all_mode_mask_refinement_cases_are_grammar_owned_exact_and_fail_closed() {
        let cases = hx512_mode_mask_refinement_cases().unwrap();
        assert_eq!(cases.len(), HX512_MODE_MASK_REFINEMENT_CASE_COUNT);
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for (index, case) in cases.iter().enumerate() {
            assert_eq!(case.mode, HX512_AUTHORIZATION_MODES[index / 16]);
            assert_eq!(case.activity_mask, (index % 16) as u8);
            match &case.classification {
                Hx512ModeMaskRefinementClassification::Accepted {
                    statement,
                    context,
                    witness,
                    expected_binding,
                } => {
                    accepted += 1;
                    ensure_hx512_activity_mode_accepted(case.mode, case.activity_mask).unwrap();
                    assert_eq!(statement.len(), HX512_STATEMENT_BYTES);
                    assert_eq!(context.len(), HX512_VERIFIER_CONTEXT_BYTES);
                    assert_eq!(witness.len(), HX512_WITNESS_BYTES);
                    assert_eq!(
                        statement[HX512_STATEMENT_ACTIVITY_MASK_OFFSET],
                        case.activity_mask
                    );
                    let materialized = materialize_hx512_production_relation(
                        statement,
                        context,
                        witness,
                        expected_binding,
                    )
                    .unwrap();
                    assert_eq!(materialized.witness.authorization.mode, case.mode);
                    assert_eq!(materialized.statement.activity_mask, case.activity_mask);
                    assert_eq!(materialized.statement.encode_exact().as_slice(), statement);
                    assert_eq!(
                        materialized.verifier_context.encode_exact().as_slice(),
                        context
                    );
                    assert_eq!(materialized.witness.encode_exact().as_slice(), witness);
                }
                Hx512ModeMaskRefinementClassification::RejectedModeMask { error } => {
                    rejected += 1;
                    assert_eq!(
                        error,
                        &Hx512RelationError::RejectedModeMask {
                            mode: case.mode,
                            mask: case.activity_mask,
                        }
                    );
                    assert_eq!(
                        ensure_hx512_activity_mode_accepted(case.mode, case.activity_mask),
                        Err(error.clone())
                    );
                }
            }
        }
        assert_eq!(accepted, HX512_MODE_MASK_REFINEMENT_ACCEPTED_COUNT);
        assert_eq!(rejected, HX512_MODE_MASK_REFINEMENT_REJECTED_COUNT);

        let accepted_surfaces = cases
            .iter()
            .filter_map(|case| match &case.classification {
                Hx512ModeMaskRefinementClassification::Accepted {
                    statement,
                    context,
                    witness,
                    ..
                } => Some((statement, context, witness)),
                Hx512ModeMaskRefinementClassification::RejectedModeMask { .. } => None,
            })
            .collect::<Vec<_>>();
        for left in 0..accepted_surfaces.len() {
            for right in left + 1..accepted_surfaces.len() {
                assert_ne!(accepted_surfaces[left], accepted_surfaces[right]);
            }
        }

        assert!(HX512_REFINEMENT_EVIDENCE_FEATURE_ENABLED);
        assert!(HX512_REFINEMENT_EVIDENCE_PRODUCTION_FORBIDDEN);
        assert!(!HX512_PRODUCTION_IDENTITY_ALLOCATED);
        assert!(!HX512_RELATION_GRAMMAR_FROZEN);
        assert!(!HX512_RELATION_COMPILER_COMPLETE);
        assert!(!HX512_RUST_VERIFIER_REFINEMENT_COMPLETE);
        assert!(!HX512_COMPLETE_ZK_AUTHORIZED);
        assert!(!HX512_PQ_QROM_AUTHORIZED);
        assert!(!HX512_CONSENSUS_ROUTE_AUTHORIZED);
        assert!(!HX512_PRODUCTION_AUTHORIZED);
        assert!(matches!(
            ensure_hx512_production_authorized(),
            Err(Hx512RelationError::RefinementEvidenceFeatureEnabled)
        ));
    }

    #[test]
    fn exact_geometry_registry_and_all_fail_closed_flags() {
        assert_eq!(HX512_STATEMENT_BYTES, 983);
        assert_eq!(HX512_VERIFIER_CONTEXT_BYTES, 136);
        assert_eq!(
            HX512_COMPILER_COVERAGE_MATRIX.len(),
            HX512_PREDICATE_FAMILIES.len()
        );
        for (expected_family, coverage) in HX512_PREDICATE_FAMILIES
            .iter()
            .zip(HX512_COMPILER_COVERAGE_MATRIX.iter())
        {
            assert_eq!(*expected_family, coverage.family);
            assert!(coverage.fixed_vector_expressible);
            assert!(coverage.maximum_local_degree <= 2);
            assert!(!coverage.current_v6_adapter_instantiable);
            assert!(!coverage.hx512_compiled);
        }
        assert_eq!(
            HX512_COMPILER_COVERAGE_MATRIX
                .iter()
                .filter(|coverage| coverage.has_external_parser_obligation)
                .map(|coverage| coverage.family)
                .collect::<Vec<_>>(),
            vec![
                Hx512PredicateFamily::CanonicalStatementAndContext,
                Hx512PredicateFamily::CanonicalWitness,
                Hx512PredicateFamily::CiphertextBinding,
                Hx512PredicateFamily::StablePublicRefinement,
                Hx512PredicateFamily::StableWitnessRefinement,
            ]
        );
        let recipes = hx512_hash_call_recipe_registry(TEST_ONLY_IDENTITY);
        assert_eq!(recipes.len(), 95);
        assert_eq!(
            recipes[79].source,
            Hx512HashSourceRecipe::ActionIntent {
                statement_ranges: TEST_ONLY_ACTION_INTENT_RANGES,
            }
        );
        assert_eq!(
            hx512_exact_hash_message_recipe(
                TEST_ONLY_IDENTITY,
                79,
                Hx512AuthorizationMode::SingleKey,
            )
            .unwrap()
            .atoms,
            TEST_ONLY_ACTION_INTENT_RANGES
                .into_iter()
                .map(atom_surface)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            recipes[80].source,
            Hx512HashSourceRecipe::SpendPlan {
                statement_ranges: TEST_ONLY_SPEND_PLAN_RANGES,
            }
        );
        assert_eq!(
            hx512_exact_hash_message_recipe(
                TEST_ONLY_IDENTITY,
                80,
                Hx512AuthorizationMode::SingleKey,
            )
            .unwrap()
            .atoms,
            TEST_ONLY_SPEND_PLAN_RANGES
                .into_iter()
                .map(atom_surface)
                .collect::<Vec<_>>()
        );
        let typed = hx512_typed_hash_call_registry(TEST_ONLY_IDENTITY);
        assert_eq!(
            typed.authorization_mode_source,
            Hx512ByteRange::witness(5_296, 8)
        );
        assert!(typed.frozen);
        for recipe in &recipes {
            for mode in [
                Hx512AuthorizationMode::SingleKey,
                Hx512AuthorizationMode::AccumulatorInit,
                Hx512AuthorizationMode::ApprovalStep,
                Hx512AuthorizationMode::ValueLockCreation,
                Hx512AuthorizationMode::FinalThresholdSpend,
            ] {
                let expanded =
                    hx512_exact_hash_message_recipe(TEST_ONLY_IDENTITY, recipe.index, mode)
                        .unwrap();
                assert_eq!(expanded.derived_message_bytes(), expanded.message_bytes);
            }
        }
        assert_eq!(
            recipes
                .iter()
                .take(83)
                .map(|item| item.max_compressions)
                .sum::<usize>(),
            206
        );
        assert_eq!(
            recipes
                .iter()
                .map(|item| item.max_compressions)
                .sum::<usize>(),
            hx512_relation_shape(TEST_ONLY_IDENTITY).max_blake2b512_compressions
        );
        assert!(!HX512_PRODUCTION_IDENTITY_ALLOCATED);
        assert!(HX512_STABLE_SURFACE_FROZEN);
        assert!(HX512_HASH_REGISTRY_FROZEN);
        assert!(!HX512_RELATION_GRAMMAR_FROZEN);
        assert!(!HX512_RELATION_COMPILER_COMPLETE);
        assert!(!HX512_RUST_VERIFIER_REFINEMENT_COMPLETE);
        assert!(!HX512_COMPLETE_ZK_AUTHORIZED);
        assert!(!HX512_PQ_QROM_AUTHORIZED);
        assert!(!HX512_CONSENSUS_ROUTE_AUTHORIZED);
        assert!(!HX512_PRODUCTION_AUTHORIZED);
        assert!(ensure_hx512_production_authorized().is_err());
        assert_eq!(
            hx512_active_hash_accounting(StablecoinTransitionDirectionV3::Disabled),
            Hx512ActiveHashAccounting {
                active_calls: 83,
                active_compressions: 206,
                provisional: false,
            }
        );
        assert_eq!(
            hx512_active_hash_accounting(StablecoinTransitionDirectionV3::Mint).active_calls,
            83 + STABLECOIN_TRANSITION_V3_MINT_HASH_CALLS
        );
        assert_eq!(
            hx512_active_hash_accounting(StablecoinTransitionDirectionV3::Burn).active_compressions,
            206 + STABLECOIN_TRANSITION_V3_BURN_COMPRESSIONS
        );
    }

    #[test]
    fn exact_26_accept_54_reject_mode_mask_table() {
        let expected = [
            (
                Hx512AuthorizationMode::SingleKey,
                &[0x05, 0x06, 0x07, 0x09, 0x0a, 0x0b, 0x0d, 0x0e, 0x0f][..],
            ),
            (
                Hx512AuthorizationMode::AccumulatorInit,
                &[0x05, 0x06, 0x07, 0x0d, 0x0e, 0x0f][..],
            ),
            (Hx512AuthorizationMode::ApprovalStep, &[0x07, 0x0f][..]),
            (
                Hx512AuthorizationMode::ValueLockCreation,
                &[0x05, 0x06, 0x07, 0x0d, 0x0e, 0x0f][..],
            ),
            (
                Hx512AuthorizationMode::FinalThresholdSpend,
                &[0x07, 0x0b, 0x0f][..],
            ),
        ];
        let mut accepted = 0;
        let mut rejected = 0;
        for (mode, masks) in expected {
            for mask in 0..16 {
                let actual = hx512_activity_mode_accepts(mode, mask);
                assert_eq!(
                    actual,
                    masks.contains(&mask),
                    "mode={mode:?} mask={mask:#x}"
                );
                accepted += usize::from(actual);
                rejected += usize::from(!actual);
            }
        }
        assert_eq!((accepted, rejected), (26, 54));
    }

    #[test]
    fn parse_materialize_and_round_trip_single_key() {
        let (adapter_fixture, adapter_binding) = build_single_key_adapter_fixture();
        assert_eq!(adapter_binding, TEST_ONLY_BINDING);
        assert!(materialize_hx512_production_relation(
            &adapter_fixture.statement,
            &adapter_fixture.context,
            &adapter_fixture.witness,
            &adapter_binding,
        )
        .is_ok());
        for mask in [0x05, 0x06, 0x07, 0x09, 0x0a, 0x0b, 0x0d, 0x0e, 0x0f] {
            let fixture = build_single_key_fixture(mask);
            let materialized = materialize_hx512_production_relation(
                &fixture.statement,
                &fixture.context,
                &fixture.witness,
                &TEST_ONLY_BINDING,
            )
            .unwrap();
            assert_eq!(materialized.statement.encode_exact(), fixture.statement);
            assert_eq!(
                materialized.verifier_context.encode_exact(),
                fixture.context
            );
            assert_eq!(materialized.witness.encode_exact(), fixture.witness);
            assert_eq!(materialized.shape, hx512_relation_shape(TEST_ONLY_IDENTITY));
        }
    }

    #[test]
    fn every_non_single_key_accept_pair_materializes_round_trips_and_replays_95_calls() {
        let cases: &[(Hx512AuthorizationMode, &[u8])] = &[
            (
                Hx512AuthorizationMode::AccumulatorInit,
                &[0x05, 0x06, 0x07, 0x0d, 0x0e, 0x0f],
            ),
            (Hx512AuthorizationMode::ApprovalStep, &[0x07, 0x0f]),
            (
                Hx512AuthorizationMode::ValueLockCreation,
                &[0x05, 0x06, 0x07, 0x0d, 0x0e, 0x0f],
            ),
            (
                Hx512AuthorizationMode::FinalThresholdSpend,
                &[0x07, 0x0b, 0x0f],
            ),
        ];
        let expected_kats = [
            "4401ed96346ca3e9ac46ab62227be32871b643ef0871bd211a08909125f83b3dbc3d0f7d49913d0d02c4623535765b30c3995fc6d0f658cf6c1bd9e40f52e3cc",
            "eb9c98681ff3e533eacaf670d1e82d3f997be25fc839251bc267a757ae80c7a37531569952ff06ddc1329cd1dcaf426ed1a90415c3d5f61ab4fc30a6b8664625",
            "3cbe9fb206940a2c4c3aa456fd8d473243bb3376c5a0f0426d594e46b19ea54c594a8a3eca37fbcb8dd2bde491c5ced8ce08d5045ad3bcf703773cd5c1c7c4b1",
            "8030043c3d9866e306b0e4e7ec2da31e28b8ea2156e7fd83d491e302de7cb2c045cef3a9a1578bc3f732eebed3f19f28f334e94ab878670857555fe47e70794f",
            "fe6effcdc97eb79e695a9dd72c37dce15e8402d830c99d66a44537cf9c03f3ced3ec99ec15bff2cabca90692ab9639a608152e55b386ef0df5fb37bee0f4cc04",
            "69d9fce4f9b202e981ea87f244304e7cf4de4761bdba8e69b1dc893164a0a1403c4eec8888ec4366253a45344d3082961716f84d7b56c51ed4b4fae586caea31",
            "a278eb1fdfe70fcde5ca10ff4d1c919f2bb9e39b9bde2ccc4a6c082ce664f9b8c7afc9eb82c478af8de1889f68423de46e0282c922f1a7ad04e1e4323ea3a40a",
            "42e70781b90c5802b4066c9083b5de6d3da05b62fee5e38c7175fbba3ed6c5beb3b2973674581734f5ad7710d06cd2bc97934f29ccb04b46dfbf9cb70abe10bd",
            "ca609aa9ce8c4f37742513f15340d1b5d3df38d34b9ce25e201da83a15441e68bbbef023eb186c35876fb297c28e89db4403d0bfe46fa6fb3109784638766dc3",
            "b44084588bbed8169af2e4439c4373c6a72d4ac86dc329376888c464dd408383b5078775ca9d384585541904cf33c4686dacf3cb0092ba296ebc0906963e9eda",
            "690dc3d6f9d950718b1ef63a8d5815db0eb6c7550510260efda48f805ac0f3558d7886226f7f6ceff4d2edda1ca502207dfbf459bdd7a84f21f99c1e19b71a0a",
            "21c96cc22c1cffd8978669cc7ef1b5f09882586eb09d67727fbfeb455a4f54604e69886adba75c4807f20b6b22c380579ee7461e5d04c9b21511088c7d8e3119",
            "b7b9d2f89e4c8d862d47cd05730e34a22c2ff066e4c88f0c356a909b87fd957434b544a51911cb548e6f5d02428354e9b7703d0326a30abdae5d84ef956d1729",
            "1ac1614bb0d8155c9621f4ba9a0c1a34e3cac671e72a50d98bcf697952d75f119fbbf64e011a73ce2a2d4dfa155cb6c1fe6336b76f06cc0e033370890cc75c3c",
            "ad17d0b1c0e7613e12d09f1b5f2292072490fd692cb56a3f9ef1f38dfc641122a99ed9dbb5aea6ee3ac300ff4f9e41f3933a5401c2bc4400a28ab2566cbca4f4",
            "2349857b4bb069bba624bbcdfc1f31b77a1010adcf3d573683a5a5ba7f41ac39e28bc9a1e54238e25fee0dc780483e27359221f86b8cfff478527c14896b1473",
            "a4dc8373389471dec32e24e8f3b2f35cbc5f29ff183e6ae4ab77394aa999f6df14b1d8a7416242c2e3987983138f5f11b121b6ad1d66683600d1b567ab77c7a6",
        ];
        let mut kats = Vec::new();
        for (mode, masks) in cases {
            for mask in *masks {
                let fixture = build_authorization_fixture(*mode, *mask);
                let kat = assert_full_fixture_and_registry(&fixture, *mode);
                assert_eq!(hex::encode(kat), expected_kats[kats.len()]);
                assert!(!kats.contains(&kat), "fixture KAT collision");
                kats.push(kat);
            }
        }
        assert_eq!(kats.len(), 17);

        // Retain one mode-specific counterfeit for every state-transition
        // family in addition to the generic every-field mutation corpus.
        for (mode, offset) in [
            (
                Hx512AuthorizationMode::AccumulatorInit,
                HX512_AUTHORIZATION_OFFSET + 8,
            ),
            (
                Hx512AuthorizationMode::ApprovalStep,
                HX512_AUTHORIZATION_OFFSET + 208 + 152,
            ),
            (
                Hx512AuthorizationMode::ValueLockCreation,
                HX512_AUTHORIZATION_OFFSET + 208,
            ),
            (
                Hx512AuthorizationMode::FinalThresholdSpend,
                HX512_AUTHORIZATION_OFFSET + 8 + 64,
            ),
        ] {
            let mut fixture = build_authorization_fixture(mode, 0x0f);
            fixture.witness[offset] ^= 1;
            assert!(materialize_hx512_production_relation(
                &fixture.statement,
                &fixture.context,
                &fixture.witness,
                &TEST_ONLY_BINDING,
            )
            .is_err());
        }
    }

    #[test]
    fn outer_stable_mint_and_burn_materialize_round_trip_and_replay_95_calls() {
        for (direction, expected, expected_kat) in [
            (
                StablecoinTransitionDirectionV3::Mint,
                Hx512ActiveHashAccounting {
                    active_calls: 95,
                    active_compressions: 226,
                    provisional: false,
                },
                "5961047b8659663599f65e53e20353b47a220966855307dd54296cb764028ab9a4b2e6b5a778c4dd71919c437566ebab742fb824c033baaf0c8230418661c0e1",
            ),
            (
                StablecoinTransitionDirectionV3::Burn,
                Hx512ActiveHashAccounting {
                    active_calls: 93,
                    active_compressions: 222,
                    provisional: false,
                },
                "0a5c802de1c8fc277aff0c0ee00e6979260e9ac6cc38d655bf52586853b5e42c1b11f636145b2da291e1c0626da242ec54b31ee5d2c01381e080defa6dd69e33",
            ),
        ] {
            let fixture = build_stable_fixture(direction);
            let kat = assert_full_fixture_and_registry(&fixture, Hx512AuthorizationMode::SingleKey);
            assert_eq!(hex::encode(kat), expected_kat);
            assert_eq!(hx512_active_hash_accounting(direction), expected);

            let mut forged_action = fixture.statement;
            forged_action[HX512_STATEMENT_ACTION_INTENT_OFFSET] ^= 1;
            assert!(
                materialize_hx512_production_relation(
                    &forged_action,
                    &fixture.context,
                    &fixture.witness,
                    &TEST_ONLY_BINDING,
                )
                .is_err()
            );
            let mut forged_witness = fixture.witness;
            forged_witness[HX512_STABLE_WITNESS_OFFSET
                + STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.start
                + STABLECOIN_TRANSITION_V3_ROW_BYTES
                - 1] ^= 1;
            assert!(
                materialize_hx512_production_relation(
                    &fixture.statement,
                    &fixture.context,
                    &forged_witness,
                    &TEST_ONLY_BINDING,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn action_intent_and_spend_plan_are_distinct_non_circular_kats() {
        let fixture = build_single_key_fixture(0x0f);
        let parsed =
            Hx512ProductionStatement::decode_exact(&fixture.statement, &TEST_ONLY_BINDING).unwrap();
        let witness = Hx512ProductionWitness::decode_exact(&fixture.witness).unwrap();
        let action = parsed.action_intent_digest();
        let plan = parsed.spend_plan_digest();
        assert_ne!(action, plan);
        assert!(!is_zero(&action));
        assert!(!is_zero(&plan));
        assert_eq!(
            hex::encode(action),
            "847aa77c3f02f7c65e478f22b1ea609d9365274aff70a59838322a6e6b8e1b295c3040ffd273f15ea67d502b473aeeaa0e2dc3b6cd561f34c2141081e117841c"
        );
        assert_eq!(
            hex::encode(plan),
            "9a8944b6e821aa51cae33bd3c89416f2660fc7e31ebd9afa93f98069b00074e97da3828110ec52de5024f4ea77f2647b66fa2d45b5dfd2f938fddd06f543a0e2"
        );

        // The typed compiler registry reconstructs the host oracle exactly;
        // length equality alone would not detect reordered/private-constant
        // source atoms.
        let registry = hx512_hash_call_recipe_registry(TEST_ONLY_IDENTITY);
        let mut memo = vec![None; registry.len()];
        let mut visiting = vec![false; registry.len()];
        for call_index in 0..registry.len() {
            let _ = exact_recipe_digest(&fixture, &registry, call_index, &mut memo, &mut visiting);
        }
        let notes = [
            &witness.inputs[0].note,
            &witness.inputs[1].note,
            &witness.outputs[0].note,
            &witness.outputs[1].note,
        ];
        for (call, note) in notes.into_iter().enumerate() {
            assert_eq!(
                memo[call].unwrap(),
                note_digest(TEST_ONLY_IDENTITY, note).unwrap()
            );
        }
        let authorization = validate_authorization(&parsed, &witness, &plan).unwrap();
        for input in 0..2 {
            assert_eq!(
                memo[4 + input].unwrap(),
                nullifier_digest(
                    TEST_ONLY_IDENTITY,
                    &authorization.nullifier_key[input],
                    &witness.inputs[input],
                )
                .unwrap()
            );
            let mut current = memo[input].unwrap();
            for level in 0..32 {
                current = if (witness.inputs[input].position >> level) & 1 == 0 {
                    merkle_digest(
                        TEST_ONLY_IDENTITY,
                        &current,
                        &witness.inputs[input].siblings[level],
                    )
                    .unwrap()
                } else {
                    merkle_digest(
                        TEST_ONLY_IDENTITY,
                        &witness.inputs[input].siblings[level],
                        &current,
                    )
                    .unwrap()
                };
                assert_eq!(memo[6 + input * 32 + level].unwrap(), current);
            }
        }
        for lane in 0..2 {
            for input in 0..2 {
                assert_eq!(
                    memo[70 + lane * 2 + input].unwrap(),
                    spend_digest(
                        TEST_ONLY_IDENTITY,
                        &witness.inputs[input].spend_master,
                        lane,
                    )
                    .unwrap()
                );
            }
        }
        assert_eq!(memo[74].unwrap(), authorization.policy_digest);
        for lane in 0..2 {
            for slot in 0..2 {
                assert_eq!(
                    memo[75 + lane * 2 + slot].unwrap(),
                    authorization_digest(TEST_ONLY_IDENTITY, &witness.authorization, lane, slot,)
                        .unwrap()
                );
            }
        }
        assert_eq!(memo[79].unwrap(), action);
        assert_eq!(memo[80].unwrap(), plan);
        for output in 0..2 {
            assert_eq!(
                memo[81 + output].unwrap(),
                ciphertext_digest(&parsed, output, &witness.outputs[output].ciphertext).unwrap()
            );
        }
        for (call_index, call) in registry.iter().enumerate() {
            for target in &call.public_digest_targets {
                let condition = match target.condition {
                    Hx512HashTargetCondition::Always => true,
                    Hx512HashTargetCondition::InputActive(input) => {
                        parsed.activity_flags()[usize::from(input)]
                    }
                    Hx512HashTargetCondition::OutputActive(output) => {
                        parsed.activity_flags()[2 + usize::from(output)]
                    }
                    Hx512HashTargetCondition::StableEnabled => false,
                    Hx512HashTargetCondition::StableMint => false,
                };
                if condition {
                    assert_eq!(
                        fixture_surface(&fixture, target.range),
                        &memo[call_index].unwrap()
                    );
                }
            }
        }

        // Replay the final V3 suffix with nonzero, position-distinguishing
        // bytes.  This catches a stable Range that is the right length but
        // starts at the wrong codec field, as well as wrong Merkle ordering or
        // issuer-prefix truncation.
        use protocol_kernel::stablecoin_transition_v3::{
            stablecoin_issuer_authorization_v3, stablecoin_issuer_commitment_v3,
            stablecoin_transition_leaf_v3, stablecoin_transition_node_v3, StablecoinStateRowV3,
        };
        let stable_asset_id = 0x0102_0304;
        let stable_policy_version = 0x1112_1314;
        let issuer_secret = [0xd3; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        let issuer_commitment =
            stablecoin_issuer_commitment_v3(stable_asset_id, stable_policy_version, &issuer_secret);
        let before = StablecoinStateRowV3 {
            asset_id: stable_asset_id,
            policy_version: stable_policy_version,
            active: true,
            enabled_at: 0x2122_2324_2526_2728,
            retired_at: Some(0x3132_3334_3536_3738),
            issuer_commitment,
            min_collateral_ratio_ppm: 0x4142_4344,
            max_mint_per_epoch: 0x5152_5354_5556_5758,
            oracle_submitted_at: 0x6162_6364_6566_6768,
            oracle_max_age: 0x7172_7374_7576_7778,
            oracle_price_numerator: 0x8182_8384,
            oracle_price_denominator: 0x9192_9394,
            collateral_amount: 0xa1a2_a3a4_a5a6_a7a8,
            attestation_created_at: 0xb1b2_b3b4_b5b6_b7b8,
            attestation_disputed: true,
            attestation_present: true,
            attestation_max_age: 0xc1c2_c3c4_c5c6_c7c8,
            policy_admin_commitment: [0x41; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
            oracle_authority_commitment: [0x42; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
            attestation_authority_commitment: [0x43; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
            collateral_asset_id: 0xd1d2_d3d4,
            collateral_decimals: 7,
            collateral_scale: 10_000_000,
            locked_collateral_commitment: [0x44; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
            epoch_id: 0xe1e2_e3e4_e5e6_e7e8,
            minted_in_epoch: 0xf1f2_f3f4_f5f6_f7f8,
            total_debt: 0x0101_0202_0303_0404,
            sequence: 0x1111_1212_1313_1414,
        };
        let after = StablecoinStateRowV3 {
            minted_in_epoch: before.minted_in_epoch.wrapping_add(0x101),
            total_debt: before.total_debt.wrapping_add(0x202),
            sequence: before.sequence.wrapping_add(1),
            ..before
        };
        let stable_index = 11u32;
        let stable_siblings: [StablecoinTransitionRootV3; STABLECOIN_TRANSITION_V3_DEPTH] =
            core::array::from_fn(|level| {
                StablecoinTransitionRootV3::new(
                    [0x51 + level as u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
                )
            });
        let stable_witness = StablecoinTransitionWitnessV3 {
            index: stable_index,
            before,
            after,
            siblings: stable_siblings,
            issuer_secret,
        };
        let mut expected_before = stablecoin_transition_leaf_v3(stable_index, before).unwrap();
        let mut expected_after = stablecoin_transition_leaf_v3(stable_index, after).unwrap();
        for (level, sibling) in stable_siblings.into_iter().enumerate() {
            if (stable_index >> level) & 1 == 0 {
                expected_before =
                    stablecoin_transition_node_v3(expected_before, sibling, level).unwrap();
                expected_after =
                    stablecoin_transition_node_v3(expected_after, sibling, level).unwrap();
            } else {
                expected_before =
                    stablecoin_transition_node_v3(sibling, expected_before, level).unwrap();
                expected_after =
                    stablecoin_transition_node_v3(sibling, expected_after, level).unwrap();
            }
        }
        let stable_public = StablecoinTransitionPublicV3 {
            direction: StablecoinTransitionDirectionV3::Mint,
            asset_id: stable_asset_id,
            policy_version: stable_policy_version,
            magnitude: 0x2122_2324_2526_2728,
            action_intent: [0x61; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
            before_root: expected_before,
            after_root: expected_after,
            after_epoch_id: after.epoch_id,
            after_minted_in_epoch: after.minted_in_epoch,
            after_total_debt: after.total_debt,
            after_sequence: after.sequence,
            issuer_authorization: [0x62; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
        };
        let mut stable_fixture = build_single_key_fixture(0x0f);
        stable_fixture.statement[HX512_STATEMENT_STABLE_PUBLIC_OFFSET..]
            .copy_from_slice(&stable_public.encode_canonical());
        stable_fixture.witness[HX512_STABLE_WITNESS_OFFSET..]
            .copy_from_slice(&stable_witness.encode_canonical().unwrap());
        let mut stable_memo = vec![None; registry.len()];
        let mut stable_visiting = vec![false; registry.len()];
        for call_index in 83..registry.len() {
            let _ = exact_recipe_digest(
                &stable_fixture,
                &registry,
                call_index,
                &mut stable_memo,
                &mut stable_visiting,
            );
        }
        let mut before_path = stablecoin_transition_leaf_v3(stable_index, before).unwrap();
        let mut after_path = stablecoin_transition_leaf_v3(stable_index, after).unwrap();
        assert_eq!(stable_memo[83].unwrap(), before_path.into_bytes());
        assert_eq!(stable_memo[88].unwrap(), after_path.into_bytes());
        for (level, sibling) in stable_siblings.into_iter().enumerate() {
            if (stable_index >> level) & 1 == 0 {
                before_path = stablecoin_transition_node_v3(before_path, sibling, level).unwrap();
                after_path = stablecoin_transition_node_v3(after_path, sibling, level).unwrap();
            } else {
                before_path = stablecoin_transition_node_v3(sibling, before_path, level).unwrap();
                after_path = stablecoin_transition_node_v3(sibling, after_path, level).unwrap();
            }
            assert_eq!(stable_memo[84 + level].unwrap(), before_path.into_bytes());
            assert_eq!(stable_memo[89 + level].unwrap(), after_path.into_bytes());
        }
        assert_eq!(stable_memo[87].unwrap(), expected_before.into_bytes());
        assert_eq!(stable_memo[92].unwrap(), expected_after.into_bytes());
        assert_eq!(stable_memo[93].unwrap(), issuer_commitment);
        assert_eq!(
            stable_memo[94].unwrap(),
            stablecoin_issuer_authorization_v3(stable_public, &issuer_secret)
        );
    }

    #[test]
    fn every_statement_and_context_field_group_mutation_rejects() {
        let fixture = build_single_key_fixture(0x0f);
        let statement_offsets = vec![
            0usize,
            8,
            10,
            12,
            14,
            16,
            18,
            19,
            20,
            22,
            HX512_STATEMENT_CHAIN_ID_OFFSET,
            HX512_STATEMENT_GENESIS_ID_OFFSET,
            HX512_STATEMENT_RULES_HASH_OFFSET,
            HX512_STATEMENT_ACTIVITY_MASK_OFFSET,
            HX512_STATEMENT_ANCHOR_OFFSET,
            HX512_STATEMENT_NULLIFIERS_OFFSET,
            HX512_STATEMENT_NULLIFIERS_OFFSET + HX512_DIGEST_BYTES,
            HX512_STATEMENT_COMMITMENTS_OFFSET,
            HX512_STATEMENT_COMMITMENTS_OFFSET + HX512_DIGEST_BYTES,
            HX512_STATEMENT_CIPHERTEXT_HASHES_OFFSET,
            HX512_STATEMENT_CIPHERTEXT_HASHES_OFFSET + HX512_DIGEST_BYTES,
            HX512_STATEMENT_ASSET_SLOTS_OFFSET,
            HX512_STATEMENT_ASSET_SLOTS_OFFSET + 8,
            HX512_STATEMENT_ASSET_SLOTS_OFFSET + 16,
            HX512_STATEMENT_FEE_OFFSET,
            HX512_STATEMENT_VALUE_BALANCE_ZERO_OFFSET,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_VERSION_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_EPOCH_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_MINTED_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_DEBT_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_SEQUENCE_RANGE.start,
            HX512_STATEMENT_STABLE_PUBLIC_OFFSET
                + STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start,
        ];
        for offset in statement_offsets {
            let mut changed = fixture.statement;
            changed[offset] ^= 1;
            assert!(
                materialize_hx512_production_relation(
                    &changed,
                    &fixture.context,
                    &fixture.witness,
                    &TEST_ONLY_BINDING,
                )
                .is_err(),
                "statement mutation survived at {offset}"
            );
        }
        for offset in [0usize, 64, 72] {
            let mut changed = fixture.context;
            changed[offset] ^= 1;
            assert!(
                materialize_hx512_production_relation(
                    &fixture.statement,
                    &changed,
                    &fixture.witness,
                    &TEST_ONLY_BINDING,
                )
                .is_err(),
                "context mutation survived at {offset}"
            );
        }
    }

    #[test]
    fn every_witness_field_group_and_mode_mutation_rejects() {
        use protocol_kernel::stablecoin_transition_v3::{
            STABLECOIN_TRANSITION_V3_ACTIVE_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_AUTHORITY_COMMITMENT_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_CREATED_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_DISPUTED_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_MAX_AGE_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_PRESENT_OFFSET,
            STABLECOIN_TRANSITION_V3_COLLATERAL_ASSET_ID_OFFSET,
            STABLECOIN_TRANSITION_V3_COLLATERAL_DECIMALS_OFFSET,
            STABLECOIN_TRANSITION_V3_COLLATERAL_OFFSET,
            STABLECOIN_TRANSITION_V3_COLLATERAL_SCALE_OFFSET,
            STABLECOIN_TRANSITION_V3_ENABLED_AT_OFFSET, STABLECOIN_TRANSITION_V3_EPOCH_ID_OFFSET,
            STABLECOIN_TRANSITION_V3_ISSUER_COMMITMENT_OFFSET,
            STABLECOIN_TRANSITION_V3_LOCKED_COLLATERAL_COMMITMENT_OFFSET,
            STABLECOIN_TRANSITION_V3_MAX_MINT_OFFSET, STABLECOIN_TRANSITION_V3_MINTED_OFFSET,
            STABLECOIN_TRANSITION_V3_MIN_RATIO_OFFSET,
            STABLECOIN_TRANSITION_V3_ORACLE_AUTHORITY_COMMITMENT_OFFSET,
            STABLECOIN_TRANSITION_V3_ORACLE_MAX_AGE_OFFSET,
            STABLECOIN_TRANSITION_V3_ORACLE_PRICE_DENOMINATOR_OFFSET,
            STABLECOIN_TRANSITION_V3_ORACLE_PRICE_NUMERATOR_OFFSET,
            STABLECOIN_TRANSITION_V3_ORACLE_SUBMITTED_OFFSET,
            STABLECOIN_TRANSITION_V3_POLICY_ADMIN_COMMITMENT_OFFSET,
            STABLECOIN_TRANSITION_V3_RETIRED_AT_OFFSET,
            STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET,
            STABLECOIN_TRANSITION_V3_SEQUENCE_OFFSET, STABLECOIN_TRANSITION_V3_TOTAL_DEBT_OFFSET,
        };
        let fixture = build_single_key_fixture(0x0f);
        let mut offsets = vec![
            0usize, 64, 72, 80, 88, 112, 144, 208, 232, 296, 304, 2_352, 2_384, 2_448, 2_456,
            2_464, 2_472, 2_496, 2_528, 2_592, 2_616, 2_680, 2_688, 4_736, 4_768, 4_776, 4_784,
            4_792, 4_816, 4_848, 4_912, 4_936, 5_000, 5_032, 5_040, 5_048, 5_056, 5_080, 5_112,
            5_176, 5_200, 5_264, 5_296, 5_304, 5_504, 5_704, 6_088, 6_152, 6_216, 8_363, 8_368,
            10_515,
        ];
        offsets.extend([
            HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_MAGIC_RANGE.start,
            HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_VERSION_RANGE.start,
            HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.start,
            HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.start,
            HX512_STABLE_WITNESS_OFFSET
                + STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.start
                + STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
            HX512_STABLE_WITNESS_OFFSET
                + STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.start
                + 2 * STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
            HX512_STABLE_WITNESS_OFFSET
                + STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.start
                + 3 * STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
            HX512_STABLE_WITNESS_OFFSET
                + STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.start,
        ]);
        let stable_row_field_offsets = [
            STABLECOIN_TRANSITION_V3_ASSET_ID_OFFSET,
            STABLECOIN_TRANSITION_V3_POLICY_VERSION_OFFSET,
            STABLECOIN_TRANSITION_V3_ACTIVE_OFFSET,
            STABLECOIN_TRANSITION_V3_ENABLED_AT_OFFSET,
            STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET,
            STABLECOIN_TRANSITION_V3_RETIRED_AT_OFFSET,
            STABLECOIN_TRANSITION_V3_ISSUER_COMMITMENT_OFFSET,
            STABLECOIN_TRANSITION_V3_MIN_RATIO_OFFSET,
            STABLECOIN_TRANSITION_V3_MAX_MINT_OFFSET,
            STABLECOIN_TRANSITION_V3_ORACLE_SUBMITTED_OFFSET,
            STABLECOIN_TRANSITION_V3_ORACLE_MAX_AGE_OFFSET,
            STABLECOIN_TRANSITION_V3_ORACLE_PRICE_NUMERATOR_OFFSET,
            STABLECOIN_TRANSITION_V3_ORACLE_PRICE_DENOMINATOR_OFFSET,
            STABLECOIN_TRANSITION_V3_COLLATERAL_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_CREATED_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_DISPUTED_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_PRESENT_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_MAX_AGE_OFFSET,
            STABLECOIN_TRANSITION_V3_POLICY_ADMIN_COMMITMENT_OFFSET,
            STABLECOIN_TRANSITION_V3_ORACLE_AUTHORITY_COMMITMENT_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_AUTHORITY_COMMITMENT_OFFSET,
            STABLECOIN_TRANSITION_V3_COLLATERAL_ASSET_ID_OFFSET,
            STABLECOIN_TRANSITION_V3_COLLATERAL_DECIMALS_OFFSET,
            STABLECOIN_TRANSITION_V3_COLLATERAL_SCALE_OFFSET,
            STABLECOIN_TRANSITION_V3_LOCKED_COLLATERAL_COMMITMENT_OFFSET,
            STABLECOIN_TRANSITION_V3_EPOCH_ID_OFFSET,
            STABLECOIN_TRANSITION_V3_MINTED_OFFSET,
            STABLECOIN_TRANSITION_V3_TOTAL_DEBT_OFFSET,
            STABLECOIN_TRANSITION_V3_SEQUENCE_OFFSET,
        ];
        for row_start in [
            STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.start,
            STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.start,
        ] {
            offsets.extend(
                stable_row_field_offsets
                    .iter()
                    .map(|field| HX512_STABLE_WITNESS_OFFSET + row_start + field),
            );
        }
        for offset in offsets {
            let mut changed = fixture.witness;
            changed[offset] ^= 1;
            assert!(
                materialize_hx512_production_relation(
                    &fixture.statement,
                    &fixture.context,
                    &changed,
                    &TEST_ONLY_BINDING,
                )
                .is_err(),
                "witness mutation survived at {offset}"
            );
        }
        for mode in 1u64..=4 {
            let mut changed = fixture.witness;
            changed[HX512_AUTHORIZATION_OFFSET..HX512_AUTHORIZATION_OFFSET + 8]
                .copy_from_slice(&mode.to_be_bytes());
            assert!(materialize_hx512_production_relation(
                &fixture.statement,
                &fixture.context,
                &changed,
                &TEST_ONLY_BINDING,
            )
            .is_err());
        }
    }

    #[test]
    fn retained_nullifier_ciphertext_and_balance_counterfeits_reject() {
        let fixture = build_single_key_fixture(0x0f);

        let mut forged_nullifier = fixture.statement;
        forged_nullifier[251] ^= 1;
        assert!(materialize_hx512_production_relation(
            &forged_nullifier,
            &fixture.context,
            &fixture.witness,
            &TEST_ONLY_BINDING,
        )
        .is_err());

        let mut forged_ciphertext = fixture.witness;
        forged_ciphertext[HX512_CIPHERTEXT_0_OFFSET] ^= 1;
        assert!(materialize_hx512_production_relation(
            &fixture.statement,
            &fixture.context,
            &forged_ciphertext,
            &TEST_ONLY_BINDING,
        )
        .is_err());

        // A caller echo is never action-intent authority.
        let mut forged_economics = fixture.statement;
        forged_economics[666] ^= 1;
        assert!(materialize_hx512_production_relation(
            &forged_economics,
            &fixture.context,
            &fixture.witness,
            &TEST_ONLY_BINDING,
        )
        .is_err());
    }
}
