//! Exact frontend for the compact Poseidon2 V8 SmallWood relation.
//!
//! This module is the only generic-engine entrypoint for the fresh V8/Eta
//! relation.  It binds the source-owned relation digest, complete ordered
//! 120-word public statement, verifier-recomputed seven-limb intent digest,
//! network, action, version, backend, profile, and domain-set identity before
//! the SmallWood transcript samples any challenge.  It never constructs a
//! legacy width-12 statement and it never accepts a host semantic check as a
//! substitute for an executable [`SmallwoodConstraintAdapter`].
//!
//! Candidate proving and verification are deliberately usable before release
//! authorization so the retained maximum-shape artifact can be produced and
//! audited.  Consensus authorization remains owned by
//! `protocol_versioning::smallwood_poseidon2_production_authorized`, which this
//! module does not modify.

#![forbid(unsafe_code)]

use crate::smallwood_engine::{
    projected_poseidon2_v8_compact448_inner_proof_bytes,
    projected_poseidon2_v8_compact448_q20_inner_proof_bytes,
    projected_poseidon2_v8_smz9_inner_proof_bytes,
    prove_statement_with_transcript_backend_profile_and_domain,
    report_smallwood_backend_opening_surface_with_profile_and_domain_v1,
    verify_statement_with_transcript_backend_profile_and_domain, SmallwoodArithmetization,
    SmallwoodBackendOpeningSurfaceReportV1, SmallwoodDecsEvaluationDomain,
    SmallwoodTranscriptBackend, POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE,
    POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE,
    POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
    SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES,
    SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES,
    SMALLWOOD_POSEIDON2_V8_MAX_INNER_PROOF_BYTES,
    SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_Q20_SMC8,
    SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_SMC7,
    SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9,
};
use crate::smallwood_poseidon2_v8_program::smallwood_poseidon2_v8_program_digest_matches;
use crate::smallwood_poseidon2_v8_semantics::{
    compile_smallwood_poseidon2_v8_relation, SmallwoodPoseidon2V8ConstraintAdapter,
    SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST,
};
use crate::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8PublicStatement;
use crate::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8Witness;
use crate::smallwood_poseidon2_v8_zk_refinement::validate_accepted_smallwood_poseidon2_v8_smz9_refinement_v1;
use crate::smallwood_semantics::SmallwoodConstraintAdapter;
use crate::TransactionCircuitError;
use protocol_versioning::{TxProofBackend, SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING};

pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS: usize = 120;
pub const SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS: usize = 7;
pub const SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES: usize = 48;
pub const SMALLWOOD_POSEIDON2_V8_GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

pub const SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_MAGIC: [u8; 8] = *b"HGV8PB02";
pub const SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_GRAMMAR: u16 = 2;
pub const SMALLWOOD_POSEIDON2_V8_FAMILY_ID: u16 = 1;
pub const SMALLWOOD_POSEIDON2_V8_ACTION_ID: u16 = 10;
pub const SMALLWOOD_POSEIDON2_V8_BACKEND_ID: u8 = TxProofBackend::SmallwoodCandidate as u8;
pub const SMALLWOOD_POSEIDON2_V8_PROFILE_ID: u8 = 6;
/// Inactive compact measurement profile. It is not present in versioning,
/// capability, manifest, admission, or frontend routing tables.
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_PROFILE_ID: u8 = 7;
/// Inactive q=20/448-bit measurement profile.
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_PROFILE_ID: u8 = 8;
pub const SMALLWOOD_POSEIDON2_V8_DOMAIN_SET: u16 = 4;
pub const SMALLWOOD_POSEIDON2_V8_INLINE_MODE: u8 = 1;

/// The exact fixed transcript preamble is 138 little-endian words.  The last
/// four bytes are canonical zero padding; the engine rejects non-word-aligned
/// bindings.
pub const SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_BYTES: usize = 1_104;
pub const SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_WORDS: usize =
    SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_BYTES / 8;

pub const SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR: usize = 64;
pub const SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE: usize = 8;

/// The outer inline action uses 1,140 fixed bytes, followed by one exact
/// 2,147-byte ciphertext for each active output.  The maximum-shape 2-output
/// action therefore leaves 125,638 bytes for the unchanged SMZ9 inner proof.
pub const SMALLWOOD_POSEIDON2_V8_INLINE_ACTION_BYTES: usize = 131_072;
pub const SMALLWOOD_POSEIDON2_V8_INLINE_FIXED_BYTES: usize = 1_140;
pub const SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES_PER_ACTIVE_OUTPUT: usize =
    crate::smallwood_poseidon2_v8_types::SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES;
pub const SMALLWOOD_POSEIDON2_V8_MAX_INLINE_CIPHERTEXT_BYTES: usize =
    crate::smallwood_poseidon2_v8_types::SMALLWOOD_POSEIDON2_V8_MAX_INLINE_CIPHERTEXT_BYTES;
pub const SMALLWOOD_POSEIDON2_V8_MAX_ROUTED_PROOF_BYTES: usize =
    SMALLWOOD_POSEIDON2_V8_INLINE_ACTION_BYTES
        - SMALLWOOD_POSEIDON2_V8_INLINE_FIXED_BYTES
        - SMALLWOOD_POSEIDON2_V8_MAX_INLINE_CIPHERTEXT_BYTES;

// Exact public statement layout.  The five additions to the historical
// 78-word surface are the seventh limb of each input nullifier, output
// commitment, and the Merkle root.  Ciphertext hashes remain six-limb
// conventional 48-byte values.  The retired policy/oracle/attestation slots
// are fixed zero; only the authenticated V8 seven-limb state transition is
// authority.
pub const V8_PUBLIC_INPUT_FLAGS: core::ops::Range<usize> = 0..2;
pub const V8_PUBLIC_OUTPUT_FLAGS: core::ops::Range<usize> = 2..4;
pub const V8_PUBLIC_NULLIFIERS: core::ops::Range<usize> = 4..18;
pub const V8_PUBLIC_OUTPUT_COMMITMENTS: core::ops::Range<usize> = 18..32;
pub const V8_PUBLIC_CIPHERTEXT_HASHES: core::ops::Range<usize> = 32..44;
pub const V8_PUBLIC_FEE: usize = 44;
pub const V8_PUBLIC_BALANCE_SIGN: usize = 45;
pub const V8_PUBLIC_BALANCE_MAGNITUDE: usize = 46;
pub const V8_PUBLIC_MERKLE_ROOT: core::ops::Range<usize> = 47..54;
pub const V8_PUBLIC_BALANCE_ASSETS: core::ops::Range<usize> = 54..58;
pub const V8_PUBLIC_STABLE_ENABLED: usize = 58;
pub const V8_PUBLIC_STABLE_ASSET: usize = 59;
pub const V8_PUBLIC_STABLE_POLICY_VERSION: usize = 60;
pub const V8_PUBLIC_STABLE_ISSUANCE_SIGN: usize = 61;
pub const V8_PUBLIC_STABLE_ISSUANCE_MAGNITUDE: usize = 62;
pub const V8_PUBLIC_RESERVED_LEGACY_STABLECOIN_COMMITMENTS: core::ops::Range<usize> = 63..81;
/// Reserved-zero compatibility subranges.  These names describe their old
/// positions only; they carry no V8 policy, oracle, or attestation authority.
pub const V8_PUBLIC_STABLE_POLICY_HASH: core::ops::Range<usize> = 63..69;
pub const V8_PUBLIC_STABLE_ORACLE: core::ops::Range<usize> = 69..75;
pub const V8_PUBLIC_STABLE_ATTESTATION: core::ops::Range<usize> = 75..81;
pub const V8_PUBLIC_CIRCUIT_VERSION: usize = 81;
pub const V8_PUBLIC_CRYPTO_SUITE: usize = 82;
pub const V8_PUBLIC_STABLE_DIRECTION: usize = 83;
pub const V8_PUBLIC_V8_STABLE_ASSET: usize = 84;
pub const V8_PUBLIC_V8_STABLE_POLICY_VERSION: usize = 85;
pub const V8_PUBLIC_V8_STABLE_MAGNITUDE: usize = 86;
pub const V8_PUBLIC_ACTION_INTENT: core::ops::Range<usize> = 87..94;
pub const V8_PUBLIC_PARENT_HEIGHT: usize = 94;
pub const V8_PUBLIC_BEFORE_ROOT: core::ops::Range<usize> = 95..102;
pub const V8_PUBLIC_AFTER_ROOT: core::ops::Range<usize> = 102..109;
pub const V8_PUBLIC_AFTER_COUNTERS: core::ops::Range<usize> = 109..113;
pub const V8_PUBLIC_ISSUER_AUTHORIZATION: core::ops::Range<usize> = 113..120;

const PREAMBLE_OFFSET_GRAMMAR: usize = 8;
const PREAMBLE_OFFSET_CIRCUIT: usize = 10;
const PREAMBLE_OFFSET_CRYPTO: usize = 12;
const PREAMBLE_OFFSET_FAMILY: usize = 14;
const PREAMBLE_OFFSET_ACTION: usize = 16;
const PREAMBLE_OFFSET_BACKEND: usize = 18;
const PREAMBLE_OFFSET_PROFILE: usize = 19;
const PREAMBLE_OFFSET_DOMAIN_SET: usize = 20;
const PREAMBLE_OFFSET_MODE: usize = 22;
const PREAMBLE_OFFSET_RESERVED: usize = 23;
const PREAMBLE_OFFSET_NETWORK: usize = 24;
const PREAMBLE_OFFSET_STATEMENT_WORDS: usize = 28;
const PREAMBLE_OFFSET_BINDING_LIMBS: usize = 30;
const PREAMBLE_OFFSET_INNER_MAGIC: usize = 32;
const PREAMBLE_OFFSET_RELATION_DIGEST: usize = 36;
const PREAMBLE_OFFSET_PUBLIC_VALUES: usize = 84;
const PREAMBLE_OFFSET_RELATION_BINDING: usize =
    PREAMBLE_OFFSET_PUBLIC_VALUES + SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS * 8;
const PREAMBLE_OFFSET_ZERO_PADDING: usize =
    PREAMBLE_OFFSET_RELATION_BINDING + SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS * 8;

/// An executable V8 relation accepted by this frontend.
///
/// The relation compiler, not a caller, owns all four values.  In particular,
/// `relation_balance_binding` is the verifier-recomputed seven-limb final V8
/// intent digest.  Its relation constrains the digest to the authorization rows
/// while zeroing public nullifiers `4..18`, the Merkle root `47..54`, self
/// intent `87..94`, and issuer authorization `113..120` in the fixed intent
/// preimage.  The transcript still binds the public root independently.
pub trait SmallwoodPoseidon2V8FrontendRelation: SmallwoodConstraintAdapter {
    fn public_values(&self) -> &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS];
    fn relation_balance_binding(&self) -> &[u64; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS];
    fn relation_digest(&self) -> &[u8; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES];
    fn compiler_complete(&self) -> bool;
}

/// Rebuild the verifier relation from exact leaf public data.
///
/// The production implementation must call the fixed-topology,
/// statement-only V8 adapter constructor. It must not accept private witness
/// data, prover-supplied constraint tables, or a verifier callback.
pub trait SmallwoodPoseidon2V8VerifierRelationFactory {
    type Relation: SmallwoodPoseidon2V8FrontendRelation + Sync;

    /// Source-owned digest for the one retained V8 compiler/topology.
    fn expected_relation_digest(&self) -> &[u8; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES];

    fn build_verifier_relation(
        &self,
        input: &SmallwoodPoseidon2V8VerifierInput,
    ) -> Result<Self::Relation, TransactionCircuitError>;
}

/// The one verifier factory used by the native V8 route.  It has no fields and
/// therefore cannot carry caller-selected topology or witness data.
#[derive(Clone, Copy, Debug, Default)]
pub struct SmallwoodPoseidon2V8SourceRelationFactory;

impl SmallwoodPoseidon2V8VerifierRelationFactory for SmallwoodPoseidon2V8SourceRelationFactory {
    type Relation = SmallwoodPoseidon2V8ConstraintAdapter;

    fn expected_relation_digest(&self) -> &[u8; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES] {
        &SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST
    }

    fn build_verifier_relation(
        &self,
        input: &SmallwoodPoseidon2V8VerifierInput,
    ) -> Result<Self::Relation, TransactionCircuitError> {
        if !smallwood_poseidon2_v8_program_digest_matches() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "SmallWood Poseidon2 V8 HGV8RP03 program digest mismatch",
            ));
        }
        let statement =
            SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&input.public_values)
                .map_err(|error| {
                    TransactionCircuitError::ConstraintViolationOwned(format!(
                        "SmallWood Poseidon2 V8 verifier statement reconstruction failed: {error:?}"
                    ))
                })?;
        SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement).map_err(|error| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "SmallWood Poseidon2 V8 verifier relation reconstruction failed: {error}"
            ))
        })
    }
}

/// Verifier-owned values decoded from the canonical V8 native leaf.
///
/// Native code must construct this from exact transport bytes.  Verification
/// compares every value with the independently reconstructed relation before
/// entering the proof engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8VerifierInput {
    pub network_id: u32,
    pub relation_digest: [u8; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES],
    pub public_values: [u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    pub relation_balance_binding: [u64; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS],
}

impl SmallwoodPoseidon2V8VerifierInput {
    pub fn from_relation(
        network_id: u32,
        relation: &impl SmallwoodPoseidon2V8FrontendRelation,
    ) -> Self {
        Self {
            network_id,
            relation_digest: *relation.relation_digest(),
            public_values: *relation.public_values(),
            relation_balance_binding: *relation.relation_balance_binding(),
        }
    }

    pub fn transcript_preamble(
        &self,
    ) -> Result<SmallwoodPoseidon2V8BindingPreamble, TransactionCircuitError> {
        SmallwoodPoseidon2V8BindingPreamble::from_verifier_input(self)
    }

    /// Build the distinct inactive profile-7 binding. HGV8RP03's relation
    /// digest and all outer statement fields remain byte-for-byte unchanged.
    pub fn compact448_candidate_transcript_preamble_v1(
        &self,
    ) -> Result<SmallwoodPoseidon2V8BindingPreamble, TransactionCircuitError> {
        SmallwoodPoseidon2V8BindingPreamble::from_verifier_input_with_profile(
            self,
            SMALLWOOD_POSEIDON2_V8_COMPACT448_PROFILE_ID,
            SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_SMC7,
        )
    }

    /// Build the distinct inactive q=20/profile-8 binding. HGV8RP03 and the
    /// complete outer V8 statement remain unchanged.
    pub fn compact448_q20_candidate_transcript_preamble_v1(
        &self,
    ) -> Result<SmallwoodPoseidon2V8BindingPreamble, TransactionCircuitError> {
        SmallwoodPoseidon2V8BindingPreamble::from_verifier_input_with_profile(
            self,
            SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_PROFILE_ID,
            SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_Q20_SMC8,
        )
    }
}

/// Canonical word-aligned transcript binding.  This is reconstructed on both
/// sides and is never accepted as an opaque caller-selected byte string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8BindingPreamble {
    bytes: [u8; SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_BYTES],
}

impl SmallwoodPoseidon2V8BindingPreamble {
    pub fn from_verifier_input(
        input: &SmallwoodPoseidon2V8VerifierInput,
    ) -> Result<Self, TransactionCircuitError> {
        Self::from_verifier_input_with_profile(
            input,
            SMALLWOOD_POSEIDON2_V8_PROFILE_ID,
            SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9,
        )
    }

    fn from_verifier_input_with_profile(
        input: &SmallwoodPoseidon2V8VerifierInput,
        profile_id: u8,
        inner_magic: [u8; 4],
    ) -> Result<Self, TransactionCircuitError> {
        validate_verifier_input(input)?;
        let mut bytes = [0u8; SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_BYTES];
        bytes[..8].copy_from_slice(&SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_MAGIC);
        write_u16(
            &mut bytes,
            PREAMBLE_OFFSET_GRAMMAR,
            SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_GRAMMAR,
        );
        write_u16(
            &mut bytes,
            PREAMBLE_OFFSET_CIRCUIT,
            SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.circuit,
        );
        write_u16(
            &mut bytes,
            PREAMBLE_OFFSET_CRYPTO,
            SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.crypto,
        );
        write_u16(
            &mut bytes,
            PREAMBLE_OFFSET_FAMILY,
            SMALLWOOD_POSEIDON2_V8_FAMILY_ID,
        );
        write_u16(
            &mut bytes,
            PREAMBLE_OFFSET_ACTION,
            SMALLWOOD_POSEIDON2_V8_ACTION_ID,
        );
        bytes[PREAMBLE_OFFSET_BACKEND] = SMALLWOOD_POSEIDON2_V8_BACKEND_ID;
        bytes[PREAMBLE_OFFSET_PROFILE] = profile_id;
        write_u16(
            &mut bytes,
            PREAMBLE_OFFSET_DOMAIN_SET,
            SMALLWOOD_POSEIDON2_V8_DOMAIN_SET,
        );
        bytes[PREAMBLE_OFFSET_MODE] = SMALLWOOD_POSEIDON2_V8_INLINE_MODE;
        bytes[PREAMBLE_OFFSET_RESERVED] = 0;
        write_u32(&mut bytes, PREAMBLE_OFFSET_NETWORK, input.network_id);
        write_u16(
            &mut bytes,
            PREAMBLE_OFFSET_STATEMENT_WORDS,
            SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS as u16,
        );
        write_u16(
            &mut bytes,
            PREAMBLE_OFFSET_BINDING_LIMBS,
            SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS as u16,
        );
        bytes[PREAMBLE_OFFSET_INNER_MAGIC..PREAMBLE_OFFSET_RELATION_DIGEST]
            .copy_from_slice(&inner_magic);
        bytes[PREAMBLE_OFFSET_RELATION_DIGEST..PREAMBLE_OFFSET_PUBLIC_VALUES]
            .copy_from_slice(&input.relation_digest);
        encode_words(
            &mut bytes[PREAMBLE_OFFSET_PUBLIC_VALUES..PREAMBLE_OFFSET_RELATION_BINDING],
            &input.public_values,
        );
        encode_words(
            &mut bytes[PREAMBLE_OFFSET_RELATION_BINDING..PREAMBLE_OFFSET_ZERO_PADDING],
            &input.relation_balance_binding,
        );
        debug_assert_eq!(PREAMBLE_OFFSET_ZERO_PADDING, 1_100);
        debug_assert!(bytes[PREAMBLE_OFFSET_ZERO_PADDING..]
            .iter()
            .all(|byte| *byte == 0));
        Ok(Self { bytes })
    }

    pub const fn as_bytes(&self) -> &[u8; SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_BYTES] {
        &self.bytes
    }

    pub fn as_words(&self) -> [u64; SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_WORDS] {
        core::array::from_fn(|index| {
            let offset = index * 8;
            u64::from_le_bytes(
                self.bytes[offset..offset + 8]
                    .try_into()
                    .expect("fixed eight-byte transcript word"),
            )
        })
    }
}

/// One self-verified candidate proof ready for the canonical native leaf.
/// `proof_bytes` begin with `SMZ9` and are passed to transport unchanged.
#[derive(Clone, Debug)]
pub struct SmallwoodPoseidon2V8CandidateProof {
    verifier_input: SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: Vec<u8>,
    projected_max_proof_bytes: usize,
    projected_action_bytes: usize,
    measured_action_bytes: usize,
}

impl SmallwoodPoseidon2V8CandidateProof {
    pub const fn verifier_input(&self) -> &SmallwoodPoseidon2V8VerifierInput {
        &self.verifier_input
    }

    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }

    pub fn into_proof_bytes(self) -> Vec<u8> {
        self.proof_bytes
    }

    pub const fn projected_max_proof_bytes(&self) -> usize {
        self.projected_max_proof_bytes
    }

    pub const fn projected_action_bytes(&self) -> usize {
        self.projected_action_bytes
    }

    pub const fn measured_action_bytes(&self) -> usize {
        self.measured_action_bytes
    }
}

/// Self-verified inactive compact profile-7 proof. This type is intentionally
/// separate from [`SmallwoodPoseidon2V8CandidateProof`], so an SMC7 byte string
/// cannot enter the existing SMZ9 wallet/native route by type confusion.
#[derive(Clone, Debug)]
pub struct SmallwoodPoseidon2V8Compact448CandidateProofV1 {
    verifier_input: SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: Vec<u8>,
    projected_max_proof_bytes: usize,
    projected_action_bytes: usize,
    measured_action_bytes: usize,
}

impl SmallwoodPoseidon2V8Compact448CandidateProofV1 {
    pub const fn verifier_input(&self) -> &SmallwoodPoseidon2V8VerifierInput {
        &self.verifier_input
    }

    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }

    pub fn into_proof_bytes(self) -> Vec<u8> {
        self.proof_bytes
    }

    pub const fn projected_max_proof_bytes(&self) -> usize {
        self.projected_max_proof_bytes
    }

    pub const fn projected_action_bytes(&self) -> usize {
        self.projected_action_bytes
    }

    pub const fn measured_action_bytes(&self) -> usize {
        self.measured_action_bytes
    }
}

/// Self-verified inactive q=20/profile-8 proof. Its separate type prevents
/// accidental use by either the active SMZ9 route or the q=19 SMC7 API.
#[derive(Clone, Debug)]
pub struct SmallwoodPoseidon2V8Compact448Q20CandidateProofV1 {
    verifier_input: SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: Vec<u8>,
    projected_max_proof_bytes: usize,
    projected_action_bytes: usize,
    measured_action_bytes: usize,
}

impl SmallwoodPoseidon2V8Compact448Q20CandidateProofV1 {
    pub const fn verifier_input(&self) -> &SmallwoodPoseidon2V8VerifierInput {
        &self.verifier_input
    }

    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }

    pub fn into_proof_bytes(self) -> Vec<u8> {
        self.proof_bytes
    }

    pub const fn projected_max_proof_bytes(&self) -> usize {
        self.projected_max_proof_bytes
    }

    pub const fn projected_action_bytes(&self) -> usize {
        self.projected_action_bytes
    }

    pub const fn measured_action_bytes(&self) -> usize {
        self.measured_action_bytes
    }
}

/// Exact proof budget for this activity mask. Ciphertexts are part of the
/// canonical action even though they are not repeated inside the SMZ9 proof.
pub fn smallwood_poseidon2_v8_routed_proof_budget(
    public_values: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
) -> Result<usize, TransactionCircuitError> {
    let mut active_outputs = 0usize;
    for index in V8_PUBLIC_OUTPUT_FLAGS {
        match public_values[index] {
            0 => {}
            1 => active_outputs += 1,
            _ => {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "SmallWood Poseidon2 V8 output activity flag {index} is not Boolean"
                )));
            }
        }
    }
    let ciphertext_bytes = active_outputs
        .checked_mul(SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES_PER_ACTIVE_OUTPUT)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 ciphertext byte accounting overflow",
        ))?;
    SMALLWOOD_POSEIDON2_V8_INLINE_ACTION_BYTES
        .checked_sub(SMALLWOOD_POSEIDON2_V8_INLINE_FIXED_BYTES)
        .and_then(|budget| budget.checked_sub(ciphertext_bytes))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 routed proof budget underflow",
        ))
}

pub fn smallwood_poseidon2_v8_exact_action_bytes(
    public_values: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    proof_bytes: usize,
) -> Result<usize, TransactionCircuitError> {
    let proof_budget = smallwood_poseidon2_v8_routed_proof_budget(public_values)?;
    let ciphertext_bytes = SMALLWOOD_POSEIDON2_V8_INLINE_ACTION_BYTES
        .checked_sub(SMALLWOOD_POSEIDON2_V8_INLINE_FIXED_BYTES)
        .and_then(|available| available.checked_sub(proof_budget))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 action byte accounting underflow",
        ))?;
    SMALLWOOD_POSEIDON2_V8_INLINE_FIXED_BYTES
        .checked_add(ciphertext_bytes)
        .and_then(|bytes| bytes.checked_add(proof_bytes))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 action byte accounting overflow",
        ))
}

pub fn project_smallwood_poseidon2_v8_candidate_bytes(
    relation: &(impl SmallwoodPoseidon2V8FrontendRelation + Sync),
) -> Result<usize, TransactionCircuitError> {
    ensure_relation_contract(relation)?;
    let projected = projected_poseidon2_v8_smz9_inner_proof_bytes(relation)?;
    ensure_routed_size(projected, relation.public_values(), "projected")?;
    Ok(projected)
}

/// Exact inactive profile-7 projection for the unchanged HGV8RP03 relation.
/// This API is measurement-only and is not called by wallet or consensus
/// routing. The source adapter must continue to project to the pinned maximum.
pub fn project_smallwood_poseidon2_v8_compact448_candidate_bytes_v1(
    relation: &(impl SmallwoodPoseidon2V8FrontendRelation + Sync),
) -> Result<usize, TransactionCircuitError> {
    ensure_relation_contract(relation)?;
    let projected = projected_poseidon2_v8_compact448_inner_proof_bytes(relation)?;
    if relation.relation_digest() == &SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST
        && projected != SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES
    {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 SMC7 source projection drift: actual={projected} expected={SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES}"
        )));
    }
    ensure_routed_size(projected, relation.public_values(), "compact projected")?;
    Ok(projected)
}

/// Exact inactive q=20/profile-8 projection for unchanged HGV8RP03.
pub fn project_smallwood_poseidon2_v8_compact448_q20_candidate_bytes_v1(
    relation: &(impl SmallwoodPoseidon2V8FrontendRelation + Sync),
) -> Result<usize, TransactionCircuitError> {
    ensure_relation_contract(relation)?;
    let projected = projected_poseidon2_v8_compact448_q20_inner_proof_bytes(relation)?;
    if relation.relation_digest() == &SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST
        && projected != SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES
    {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 SMC8 source projection drift: actual={projected} expected={SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES}"
        )));
    }
    ensure_routed_size(projected, relation.public_values(), "q20 compact projected")?;
    Ok(projected)
}

/// Produce and immediately replay-verify one exact V8 proof.
pub(crate) fn prove_smallwood_poseidon2_v8_candidate(
    relation: &(impl SmallwoodPoseidon2V8FrontendRelation + Sync),
    witness_values: &[u64],
    network_id: u32,
) -> Result<SmallwoodPoseidon2V8CandidateProof, TransactionCircuitError> {
    ensure_relation_contract(relation)?;
    let expected_witness_words = relation
        .row_count()
        .checked_mul(relation.packing_factor())
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 compiler geometry overflows witness length",
        ))?;
    if witness_values.len() != expected_witness_words {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 witness length mismatch: actual={} expected={expected_witness_words}",
            witness_values.len()
        )));
    }
    for (index, value) in witness_values.iter().copied().enumerate() {
        if value >= SMALLWOOD_POSEIDON2_V8_GOLDILOCKS_MODULUS {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "SmallWood Poseidon2 V8 witness word {index} is not canonical Goldilocks"
            )));
        }
    }
    let verifier_input = SmallwoodPoseidon2V8VerifierInput::from_relation(network_id, relation);
    let preamble = verifier_input.transcript_preamble()?;
    let projected_max_proof_bytes = project_smallwood_poseidon2_v8_candidate_bytes(relation)?;
    let proof_bytes = prove_statement_with_transcript_backend_profile_and_domain(
        relation,
        witness_values,
        preamble.as_bytes(),
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    ensure_smz9_bytes(&proof_bytes)?;
    ensure_routed_size(proof_bytes.len(), relation.public_values(), "measured")?;
    if proof_bytes.len() > projected_max_proof_bytes {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 measured proof {} exceeds compiler projection {projected_max_proof_bytes}",
            proof_bytes.len()
        )));
    }
    verify_smallwood_poseidon2_v8_candidate_with_relation(relation, &verifier_input, &proof_bytes)?;
    Ok(SmallwoodPoseidon2V8CandidateProof {
        measured_action_bytes: smallwood_poseidon2_v8_exact_action_bytes(
            relation.public_values(),
            proof_bytes.len(),
        )?,
        projected_action_bytes: smallwood_poseidon2_v8_exact_action_bytes(
            relation.public_values(),
            projected_max_proof_bytes,
        )?,
        verifier_input,
        proof_bytes,
        projected_max_proof_bytes,
    })
}

/// Canonical wallet prover seam. The source compiler creates both the
/// executable adapter and its packed assignment; callers cannot substitute a
/// different relation or hand-pack witness rows.
pub fn compile_and_prove_smallwood_poseidon2_v8_candidate(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
    network_id: u32,
) -> Result<SmallwoodPoseidon2V8CandidateProof, TransactionCircuitError> {
    let lowered = compile_smallwood_poseidon2_v8_relation(statement, witness).map_err(|error| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 relation compilation failed: {error}"
        ))
    })?;
    let candidate = prove_smallwood_poseidon2_v8_candidate(
        &lowered.adapter,
        &lowered.witness_values,
        network_id,
    )?;
    verify_smallwood_poseidon2_v8_candidate(candidate.verifier_input(), candidate.proof_bytes())?;
    Ok(candidate)
}

/// Produce and immediately replay-verify the inactive compact profile-7 proof.
/// HGV8RP03 compilation is shared with SMZ9, but the preamble, transcript,
/// proof profile, observed digest width, and wire identity are all SMC7-only.
pub fn compile_and_prove_smallwood_poseidon2_v8_compact448_candidate_v1(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
    network_id: u32,
) -> Result<SmallwoodPoseidon2V8Compact448CandidateProofV1, TransactionCircuitError> {
    let lowered = compile_smallwood_poseidon2_v8_relation(statement, witness).map_err(|error| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 compact relation compilation failed: {error}"
        ))
    })?;
    let candidate = prove_smallwood_poseidon2_v8_compact448_candidate_with_relation_v1(
        &lowered.adapter,
        &lowered.witness_values,
        network_id,
    )?;
    verify_smallwood_poseidon2_v8_compact448_candidate_v1(
        candidate.verifier_input(),
        candidate.proof_bytes(),
    )?;
    Ok(candidate)
}

fn prove_smallwood_poseidon2_v8_compact448_candidate_with_relation_v1(
    relation: &(impl SmallwoodPoseidon2V8FrontendRelation + Sync),
    witness_values: &[u64],
    network_id: u32,
) -> Result<SmallwoodPoseidon2V8Compact448CandidateProofV1, TransactionCircuitError> {
    ensure_relation_contract(relation)?;
    if relation.relation_digest() != &SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 compact prover requires exact HGV8RP03 relation identity",
        ));
    }
    let expected_witness_words = relation
        .row_count()
        .checked_mul(relation.packing_factor())
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 compact compiler geometry overflows witness length",
        ))?;
    if witness_values.len() != expected_witness_words {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 compact witness length mismatch: actual={} expected={expected_witness_words}",
            witness_values.len()
        )));
    }
    for (index, value) in witness_values.iter().copied().enumerate() {
        if value >= SMALLWOOD_POSEIDON2_V8_GOLDILOCKS_MODULUS {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "SmallWood Poseidon2 V8 compact witness word {index} is not canonical Goldilocks"
            )));
        }
    }
    let verifier_input = SmallwoodPoseidon2V8VerifierInput::from_relation(network_id, relation);
    let preamble = verifier_input.compact448_candidate_transcript_preamble_v1()?;
    let projected_max_proof_bytes =
        project_smallwood_poseidon2_v8_compact448_candidate_bytes_v1(relation)?;
    let proof_bytes = prove_statement_with_transcript_backend_profile_and_domain(
        relation,
        witness_values,
        preamble.as_bytes(),
        POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    ensure_smc7_bytes(&proof_bytes)?;
    ensure_routed_size(
        proof_bytes.len(),
        relation.public_values(),
        "compact measured",
    )?;
    if proof_bytes.len() > projected_max_proof_bytes {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 compact measured proof {} exceeds compiler projection {projected_max_proof_bytes}",
            proof_bytes.len()
        )));
    }
    verify_smallwood_poseidon2_v8_compact448_candidate_with_relation_v1(
        relation,
        &verifier_input,
        &proof_bytes,
    )?;
    Ok(SmallwoodPoseidon2V8Compact448CandidateProofV1 {
        measured_action_bytes: smallwood_poseidon2_v8_exact_action_bytes(
            relation.public_values(),
            proof_bytes.len(),
        )?,
        projected_action_bytes: smallwood_poseidon2_v8_exact_action_bytes(
            relation.public_values(),
            projected_max_proof_bytes,
        )?,
        verifier_input,
        proof_bytes,
        projected_max_proof_bytes,
    })
}

fn verify_smallwood_poseidon2_v8_compact448_candidate_with_relation_v1(
    relation: &(impl SmallwoodPoseidon2V8FrontendRelation + Sync),
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    ensure_relation_contract(relation)?;
    ensure_relation_matches_input(relation, input)?;
    if relation.relation_digest() != &SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 compact verifier requires exact HGV8RP03 relation identity",
        ));
    }
    ensure_smc7_bytes(proof_bytes)?;
    ensure_routed_size(proof_bytes.len(), &input.public_values, "compact received")?;
    let preamble = input.compact448_candidate_transcript_preamble_v1()?;
    verify_statement_with_transcript_backend_profile_and_domain(
        relation,
        preamble.as_bytes(),
        proof_bytes,
        POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// Reconstruct HGV8RP03 from the statement and verify only the inactive SMC7
/// candidate. No production caller references this function.
pub fn verify_smallwood_poseidon2_v8_compact448_candidate_v1(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    let factory = SmallwoodPoseidon2V8SourceRelationFactory;
    validate_verifier_input(input)?;
    ensure_factory_matches_input(&factory, input)?;
    let relation = factory.build_verifier_relation(input)?;
    verify_smallwood_poseidon2_v8_compact448_candidate_with_relation_v1(
        &relation,
        input,
        proof_bytes,
    )
}

pub fn report_smallwood_poseidon2_v8_compact448_candidate_v1(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<SmallwoodBackendOpeningSurfaceReportV1, TransactionCircuitError> {
    let factory = SmallwoodPoseidon2V8SourceRelationFactory;
    validate_verifier_input(input)?;
    ensure_factory_matches_input(&factory, input)?;
    let relation = factory.build_verifier_relation(input)?;
    verify_smallwood_poseidon2_v8_compact448_candidate_with_relation_v1(
        &relation,
        input,
        proof_bytes,
    )?;
    let preamble = input.compact448_candidate_transcript_preamble_v1()?;
    report_smallwood_backend_opening_surface_with_profile_and_domain_v1(
        &relation,
        preamble.as_bytes(),
        proof_bytes,
        POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// Compile HGV8RP03 and produce the inactive q=20/profile-8 SMC8 candidate.
pub fn compile_and_prove_smallwood_poseidon2_v8_compact448_q20_candidate_v1(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
    network_id: u32,
) -> Result<SmallwoodPoseidon2V8Compact448Q20CandidateProofV1, TransactionCircuitError> {
    let lowered = compile_smallwood_poseidon2_v8_relation(statement, witness).map_err(|error| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 q20 compact relation compilation failed: {error}"
        ))
    })?;
    let candidate = prove_smallwood_poseidon2_v8_compact448_q20_candidate_with_relation_v1(
        &lowered.adapter,
        &lowered.witness_values,
        network_id,
    )?;
    verify_smallwood_poseidon2_v8_compact448_q20_candidate_v1(
        candidate.verifier_input(),
        candidate.proof_bytes(),
    )?;
    Ok(candidate)
}

fn prove_smallwood_poseidon2_v8_compact448_q20_candidate_with_relation_v1(
    relation: &(impl SmallwoodPoseidon2V8FrontendRelation + Sync),
    witness_values: &[u64],
    network_id: u32,
) -> Result<SmallwoodPoseidon2V8Compact448Q20CandidateProofV1, TransactionCircuitError> {
    ensure_relation_contract(relation)?;
    if relation.relation_digest() != &SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 SMC8 prover requires exact HGV8RP03 relation identity",
        ));
    }
    let expected_witness_words = relation
        .row_count()
        .checked_mul(relation.packing_factor())
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 SMC8 compiler geometry overflows witness length",
        ))?;
    if witness_values.len() != expected_witness_words {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 SMC8 witness length mismatch: actual={} expected={expected_witness_words}",
            witness_values.len()
        )));
    }
    for (index, value) in witness_values.iter().copied().enumerate() {
        if value >= SMALLWOOD_POSEIDON2_V8_GOLDILOCKS_MODULUS {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "SmallWood Poseidon2 V8 SMC8 witness word {index} is not canonical Goldilocks"
            )));
        }
    }
    let verifier_input = SmallwoodPoseidon2V8VerifierInput::from_relation(network_id, relation);
    let preamble = verifier_input.compact448_q20_candidate_transcript_preamble_v1()?;
    let projected_max_proof_bytes =
        project_smallwood_poseidon2_v8_compact448_q20_candidate_bytes_v1(relation)?;
    let proof_bytes = prove_statement_with_transcript_backend_profile_and_domain(
        relation,
        witness_values,
        preamble.as_bytes(),
        POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    ensure_smc8_bytes(&proof_bytes)?;
    ensure_routed_size(
        proof_bytes.len(),
        relation.public_values(),
        "q20 compact measured",
    )?;
    if proof_bytes.len() > projected_max_proof_bytes {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 SMC8 measured proof {} exceeds compiler projection {projected_max_proof_bytes}",
            proof_bytes.len()
        )));
    }
    verify_smallwood_poseidon2_v8_compact448_q20_candidate_with_relation_v1(
        relation,
        &verifier_input,
        &proof_bytes,
    )?;
    Ok(SmallwoodPoseidon2V8Compact448Q20CandidateProofV1 {
        measured_action_bytes: smallwood_poseidon2_v8_exact_action_bytes(
            relation.public_values(),
            proof_bytes.len(),
        )?,
        projected_action_bytes: smallwood_poseidon2_v8_exact_action_bytes(
            relation.public_values(),
            projected_max_proof_bytes,
        )?,
        verifier_input,
        proof_bytes,
        projected_max_proof_bytes,
    })
}

fn verify_smallwood_poseidon2_v8_compact448_q20_candidate_with_relation_v1(
    relation: &(impl SmallwoodPoseidon2V8FrontendRelation + Sync),
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    ensure_relation_contract(relation)?;
    ensure_relation_matches_input(relation, input)?;
    if relation.relation_digest() != &SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 SMC8 verifier requires exact HGV8RP03 relation identity",
        ));
    }
    ensure_smc8_bytes(proof_bytes)?;
    ensure_routed_size(
        proof_bytes.len(),
        &input.public_values,
        "q20 compact received",
    )?;
    let preamble = input.compact448_q20_candidate_transcript_preamble_v1()?;
    verify_statement_with_transcript_backend_profile_and_domain(
        relation,
        preamble.as_bytes(),
        proof_bytes,
        POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// Reconstruct HGV8RP03 from the statement and verify only inactive SMC8.
pub fn verify_smallwood_poseidon2_v8_compact448_q20_candidate_v1(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    let factory = SmallwoodPoseidon2V8SourceRelationFactory;
    validate_verifier_input(input)?;
    ensure_factory_matches_input(&factory, input)?;
    let relation = factory.build_verifier_relation(input)?;
    verify_smallwood_poseidon2_v8_compact448_q20_candidate_with_relation_v1(
        &relation,
        input,
        proof_bytes,
    )
}

pub fn report_smallwood_poseidon2_v8_compact448_q20_candidate_v1(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<SmallwoodBackendOpeningSurfaceReportV1, TransactionCircuitError> {
    let factory = SmallwoodPoseidon2V8SourceRelationFactory;
    validate_verifier_input(input)?;
    ensure_factory_matches_input(&factory, input)?;
    let relation = factory.build_verifier_relation(input)?;
    verify_smallwood_poseidon2_v8_compact448_q20_candidate_with_relation_v1(
        &relation,
        input,
        proof_bytes,
    )?;
    let preamble = input.compact448_q20_candidate_transcript_preamble_v1()?;
    report_smallwood_backend_opening_surface_with_profile_and_domain_v1(
        &relation,
        preamble.as_bytes(),
        proof_bytes,
        POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// Verify the exact leaf-owned statement/context against an independently
/// reconstructed executable relation and then replay the SMZ9 verifier.
pub(crate) fn verify_smallwood_poseidon2_v8_candidate_with_relation(
    relation: &(impl SmallwoodPoseidon2V8FrontendRelation + Sync),
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    ensure_relation_contract(relation)?;
    ensure_relation_matches_input(relation, input)?;
    ensure_smz9_bytes(proof_bytes)?;
    ensure_routed_size(proof_bytes.len(), &input.public_values, "received")?;
    let preamble = input.transcript_preamble()?;
    // The refinement constructor owns the one production-verifier call.  Keep
    // it on the acceptance path instead of first verifying here and then
    // repeating the same expensive SMZ9 computation.
    validate_accepted_smallwood_poseidon2_v8_smz9_refinement_v1(
        relation,
        preamble.as_bytes(),
        proof_bytes,
    )?;
    Ok(())
}

/// Public native/wallet verifier seam. The relation is reconstructed from the
/// leaf on every call so a prover-owned adapter can never become verification
/// authority.
fn verify_smallwood_poseidon2_v8_candidate_with_factory(
    factory: &impl SmallwoodPoseidon2V8VerifierRelationFactory,
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    validate_verifier_input(input)?;
    ensure_factory_matches_input(factory, input)?;
    let relation = factory.build_verifier_relation(input)?;
    verify_smallwood_poseidon2_v8_candidate_with_relation(&relation, input, proof_bytes)
}

/// Consensus verifier seam. This always uses the source-owned statement-only
/// factory; neither the wallet nor native callers can provide a relation.
pub fn verify_smallwood_poseidon2_v8_candidate(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    verify_smallwood_poseidon2_v8_candidate_with_factory(
        &SmallwoodPoseidon2V8SourceRelationFactory,
        input,
        proof_bytes,
    )
}

pub fn report_smallwood_poseidon2_v8_candidate(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<SmallwoodBackendOpeningSurfaceReportV1, TransactionCircuitError> {
    let factory = SmallwoodPoseidon2V8SourceRelationFactory;
    validate_verifier_input(input)?;
    ensure_factory_matches_input(&factory, input)?;
    let relation = factory.build_verifier_relation(input)?;
    verify_smallwood_poseidon2_v8_candidate_with_relation(&relation, input, proof_bytes)?;
    let preamble = input.transcript_preamble()?;
    report_smallwood_backend_opening_surface_with_profile_and_domain_v1(
        &relation,
        preamble.as_bytes(),
        proof_bytes,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

fn ensure_relation_contract(
    relation: &(impl SmallwoodPoseidon2V8FrontendRelation + Sync),
) -> Result<(), TransactionCircuitError> {
    if !relation.compiler_complete() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 executable full-relation compiler is incomplete",
        ));
    }
    if relation.arithmetization() != SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 frontend rejects non-V8 arithmetization",
        ));
    }
    if relation.row_count() == 0
        || relation.packing_factor() != SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
        || relation.constraint_degree() == 0
        || relation.constraint_degree() > SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE
    {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 relation geometry mismatch: rows={} packing={} degree={}",
            relation.row_count(),
            relation.packing_factor(),
            relation.constraint_degree()
        )));
    }
    if relation.constraint_count() == 0 || relation.linear_constraint_count() == 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 relation must contain executable linear and nonlinear constraints",
        ));
    }
    if !relation.auxiliary_witness_words().is_empty()
        || relation.auxiliary_witness_limb_count() != Some(0)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 forbids clear auxiliary witness words",
        ));
    }
    validate_verifier_input(&SmallwoodPoseidon2V8VerifierInput::from_relation(
        0, relation,
    ))
}

fn ensure_relation_matches_input(
    relation: &impl SmallwoodPoseidon2V8FrontendRelation,
    input: &SmallwoodPoseidon2V8VerifierInput,
) -> Result<(), TransactionCircuitError> {
    validate_verifier_input(input)?;
    if relation.relation_digest() != &input.relation_digest {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 relation digest does not match leaf context",
        ));
    }
    if relation.public_values() != &input.public_values {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 compiled public statement does not match leaf words",
        ));
    }
    if relation.relation_balance_binding() != &input.relation_balance_binding {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 recomputed intent binding does not match leaf limbs",
        ));
    }
    Ok(())
}

fn ensure_factory_matches_input(
    factory: &impl SmallwoodPoseidon2V8VerifierRelationFactory,
    input: &SmallwoodPoseidon2V8VerifierInput,
) -> Result<(), TransactionCircuitError> {
    if factory.expected_relation_digest() != &input.relation_digest {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 leaf relation digest is not the verifier-owned compiler digest",
        ));
    }
    Ok(())
}

fn validate_verifier_input(
    input: &SmallwoodPoseidon2V8VerifierInput,
) -> Result<(), TransactionCircuitError> {
    if input.relation_digest == [0; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES] {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 relation digest must be source-owned and nonzero",
        ));
    }
    validate_field_words("relation/balance binding", &input.relation_balance_binding)?;
    let statement = SmallwoodPoseidon2V8PublicStatement::try_from_public_words(
        &input.public_values,
    )
    .map_err(|error| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 public statement is invalid: {error:?}"
        ))
    })?;
    let expected_action_intent = statement.expected_action_intent().map_err(|error| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 action intent recomputation failed: {error:?}"
        ))
    })?;
    if input.relation_balance_binding != expected_action_intent {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 relation/balance limbs do not equal the verifier-recomputed 15-call action intent",
        ));
    }
    if input.public_values[V8_PUBLIC_STABLE_DIRECTION] != 0
        && input.public_values[V8_PUBLIC_ACTION_INTENT] != input.relation_balance_binding
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 active stablecoin intent, relation binding, and recomputed intent differ",
        ));
    }
    Ok(())
}

fn validate_field_words<const N: usize>(
    label: &str,
    words: &[u64; N],
) -> Result<(), TransactionCircuitError> {
    for (index, value) in words.iter().copied().enumerate() {
        if value >= SMALLWOOD_POSEIDON2_V8_GOLDILOCKS_MODULUS {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "SmallWood Poseidon2 V8 {label} word {index} is not canonical Goldilocks"
            )));
        }
    }
    Ok(())
}

fn ensure_smz9_bytes(proof_bytes: &[u8]) -> Result<(), TransactionCircuitError> {
    if proof_bytes.len() < SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9.len()
        || proof_bytes[..SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9.len()]
            != SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 frontend accepts only the fresh SMZ9 proof wire",
        ));
    }
    if proof_bytes.len() > SMALLWOOD_POSEIDON2_V8_MAX_INNER_PROOF_BYTES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 proof exceeds the inner parser cap",
        ));
    }
    Ok(())
}

fn ensure_smc7_bytes(proof_bytes: &[u8]) -> Result<(), TransactionCircuitError> {
    if proof_bytes.len() < SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_SMC7.len()
        || proof_bytes[..SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_SMC7.len()]
            != SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_SMC7
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 compact candidate accepts only the fresh SMC7 proof wire",
        ));
    }
    if proof_bytes.len() > SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 compact proof exceeds the exact SMC7 parser cap",
        ));
    }
    Ok(())
}

fn ensure_smc8_bytes(proof_bytes: &[u8]) -> Result<(), TransactionCircuitError> {
    if proof_bytes.len() < SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_Q20_SMC8.len()
        || proof_bytes[..SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_Q20_SMC8.len()]
            != SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_Q20_SMC8
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 q20 compact candidate accepts only the fresh SMC8 proof wire",
        ));
    }
    if proof_bytes.len() > SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 q20 compact proof exceeds the exact SMC8 parser cap",
        ));
    }
    Ok(())
}

fn ensure_routed_size(
    size: usize,
    public_values: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    kind: &str,
) -> Result<(), TransactionCircuitError> {
    let proof_budget = smallwood_poseidon2_v8_routed_proof_budget(public_values)?;
    if size > proof_budget {
        let action_bytes = smallwood_poseidon2_v8_exact_action_bytes(public_values, size)?;
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "SmallWood Poseidon2 V8 {kind} proof size {size} exceeds this activity mask's {proof_budget}-byte proof budget (action bytes={action_bytes}, cap={SMALLWOOD_POSEIDON2_V8_INLINE_ACTION_BYTES})"
        )));
    }
    Ok(())
}

fn encode_words<const N: usize>(output: &mut [u8], words: &[u64; N]) {
    debug_assert_eq!(output.len(), N * 8);
    for (chunk, value) in output.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

const _: [(); SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_BYTES] = [(); 1_104];
const _: [(); SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_WORDS] = [(); 138];
const _: [(); SMALLWOOD_POSEIDON2_V8_MAX_ROUTED_PROOF_BYTES] = [(); 125_638];
const _: [(); SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.circuit as usize] = [(); 8];
const _: [(); SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.crypto as usize] = [(); 7];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smallwood_semantics::{SmallwoodLinearConstraintForm, SmallwoodNonlinearEvalView};

    #[derive(Clone)]
    struct TestRelation {
        public: [u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
        binding: [u64; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS],
        digest: [u8; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES],
        offsets: [u32; 2],
        indices: [u32; 1],
        coefficients: [u64; 1],
        targets: [u64; 1],
    }

    impl TestRelation {
        fn new() -> Self {
            let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
            statement.input_flags[0] = true;
            statement.nullifiers[0] = [11, 12, 13, 14, 15, 16, 17];
            statement.output_flags[0] = true;
            statement.commitments[0] = [21, 22, 23, 24, 25, 26, 27];
            statement.ciphertext_commitments[0] = [31, 32, 33, 34, 35, 36];
            statement.merkle_root = [41, 42, 43, 44, 45, 46, 47];
            let public = statement.to_public_words();
            let binding = statement
                .expected_action_intent()
                .expect("valid typed fixture intent");
            Self {
                public,
                binding,
                digest: [0x5a; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES],
                offsets: [0, 1],
                indices: [0],
                coefficients: [1],
                targets: [0],
            }
        }
    }

    impl SmallwoodConstraintAdapter for TestRelation {
        fn arithmetization(&self) -> SmallwoodArithmetization {
            SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9
        }

        fn row_count(&self) -> usize {
            1
        }

        fn packing_factor(&self) -> usize {
            SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
        }

        fn constraint_degree(&self) -> usize {
            SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE
        }

        fn linear_constraint_count(&self) -> usize {
            1
        }

        fn constraint_count(&self) -> usize {
            1
        }

        fn linear_constraint_offsets(&self) -> &[u32] {
            &self.offsets
        }

        fn linear_constraint_indices(&self) -> &[u32] {
            &self.indices
        }

        fn linear_constraint_coefficients(&self) -> &[u64] {
            &self.coefficients
        }

        fn linear_targets(&self) -> &[u64] {
            &self.targets
        }

        fn auxiliary_witness_words(&self) -> &[u64] {
            &[]
        }

        fn auxiliary_witness_limb_count(&self) -> Option<usize> {
            Some(0)
        }

        fn linear_constraint_form(&self) -> SmallwoodLinearConstraintForm {
            SmallwoodLinearConstraintForm::Generic
        }

        fn nonlinear_eval_view<'a>(
            &self,
            eval_point: u64,
            rows: &'a [u64],
            auxiliary_words: &'a [u64],
        ) -> SmallwoodNonlinearEvalView<'a> {
            SmallwoodNonlinearEvalView::RowScalars {
                eval_point,
                rows,
                auxiliary_words,
            }
        }

        fn compute_constraints_u64(
            &self,
            _view: SmallwoodNonlinearEvalView<'_>,
            out: &mut [u64],
        ) -> Result<(), TransactionCircuitError> {
            out.fill(0);
            Ok(())
        }
    }

    impl SmallwoodPoseidon2V8FrontendRelation for TestRelation {
        fn public_values(&self) -> &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS] {
            &self.public
        }

        fn relation_balance_binding(
            &self,
        ) -> &[u64; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS] {
            &self.binding
        }

        fn relation_digest(&self) -> &[u8; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES] {
            &self.digest
        }

        fn compiler_complete(&self) -> bool {
            true
        }
    }

    #[test]
    fn v8_binding_preamble_is_exact_word_aligned_and_carries_every_surface() {
        let relation = TestRelation::new();
        let input = SmallwoodPoseidon2V8VerifierInput::from_relation(0x1122_3344, &relation);
        let preamble = input.transcript_preamble().unwrap();
        let bytes = preamble.as_bytes();
        assert_eq!(bytes.len(), 1_104);
        assert_eq!(&bytes[..8], b"HGV8PB02");
        assert_eq!(&bytes[32..36], b"SMZ9");
        assert_eq!(&bytes[36..84], relation.digest.as_slice());
        assert_eq!(
            u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            0x1122_3344
        );
        for index in 0..SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS {
            let offset = PREAMBLE_OFFSET_PUBLIC_VALUES + index * 8;
            assert_eq!(
                u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                relation.public[index]
            );
        }
        for index in 0..SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS {
            let offset = PREAMBLE_OFFSET_RELATION_BINDING + index * 8;
            assert_eq!(
                u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                relation.binding[index]
            );
        }
        assert!(bytes[1_100..].iter().all(|byte| *byte == 0));
        assert_eq!(preamble.as_words().len(), 138);
    }

    #[test]
    fn v8_binding_mutations_change_the_engine_owned_transcript_input() {
        let relation = TestRelation::new();
        let input = SmallwoodPoseidon2V8VerifierInput::from_relation(17, &relation);
        let expected = input.transcript_preamble().unwrap();

        let mut network = input.clone();
        network.network_id ^= 1;
        assert_ne!(network.transcript_preamble().unwrap(), expected);

        let mut digest = input.clone();
        digest.relation_digest[0] ^= 1;
        assert_ne!(digest.transcript_preamble().unwrap(), expected);

        for index in [
            V8_PUBLIC_INPUT_FLAGS.start,
            V8_PUBLIC_NULLIFIERS.start,
            V8_PUBLIC_OUTPUT_COMMITMENTS.start,
            V8_PUBLIC_CIPHERTEXT_HASHES.start,
            V8_PUBLIC_FEE,
            V8_PUBLIC_MERKLE_ROOT.start,
            V8_PUBLIC_STABLE_ENABLED,
            V8_PUBLIC_CIRCUIT_VERSION,
            V8_PUBLIC_STABLE_DIRECTION,
            V8_PUBLIC_ACTION_INTENT.start,
            V8_PUBLIC_PARENT_HEIGHT,
            V8_PUBLIC_BEFORE_ROOT.start,
            V8_PUBLIC_AFTER_ROOT.start,
            V8_PUBLIC_AFTER_COUNTERS.start,
            V8_PUBLIC_ISSUER_AUTHORIZATION.start,
        ] {
            let mut changed = input.clone();
            changed.public_values[index] ^= 1;
            if validate_verifier_input(&changed).is_ok() {
                assert_ne!(
                    changed.transcript_preamble().unwrap(),
                    expected,
                    "index {index}"
                );
            }
        }

        let mut reserved = input.clone();
        reserved.public_values[V8_PUBLIC_STABLE_POLICY_HASH.start] = 1;
        assert!(reserved.transcript_preamble().is_err());

        for index in 0..SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS {
            let mut changed = input.clone();
            changed.relation_balance_binding[index] ^= 1;
            assert!(changed.transcript_preamble().is_err(), "binding {index}");
        }
    }

    #[test]
    fn v8_leaf_mutations_fail_before_proof_parsing_against_reconstructed_relation() {
        let relation = TestRelation::new();
        let input = SmallwoodPoseidon2V8VerifierInput::from_relation(17, &relation);
        let malformed_proof = b"SMZ9";

        let mut relation_digest = input.clone();
        relation_digest.relation_digest[0] ^= 1;
        assert!(verify_smallwood_poseidon2_v8_candidate_with_relation(
            &relation,
            &relation_digest,
            malformed_proof
        )
        .is_err());

        let mut statement = input.clone();
        for index in [
            V8_PUBLIC_INPUT_FLAGS.start,
            V8_PUBLIC_NULLIFIERS.start,
            V8_PUBLIC_OUTPUT_COMMITMENTS.start,
            V8_PUBLIC_CIPHERTEXT_HASHES.start,
            V8_PUBLIC_FEE,
            V8_PUBLIC_MERKLE_ROOT.start,
            V8_PUBLIC_STABLE_ENABLED,
            V8_PUBLIC_CIRCUIT_VERSION,
            V8_PUBLIC_STABLE_DIRECTION,
            V8_PUBLIC_ACTION_INTENT.start,
            V8_PUBLIC_PARENT_HEIGHT,
            V8_PUBLIC_BEFORE_ROOT.start,
            V8_PUBLIC_AFTER_ROOT.start,
            V8_PUBLIC_AFTER_COUNTERS.start,
            V8_PUBLIC_ISSUER_AUTHORIZATION.start,
        ] {
            statement.public_values[index] ^= 1;
            assert!(
                verify_smallwood_poseidon2_v8_candidate_with_relation(
                    &relation,
                    &statement,
                    malformed_proof,
                )
                .is_err(),
                "public family index {index}"
            );
            statement = input.clone();
        }

        let mut binding = input.clone();
        binding.relation_balance_binding[0] ^= 1;
        assert!(verify_smallwood_poseidon2_v8_candidate_with_relation(
            &relation,
            &binding,
            malformed_proof,
        )
        .is_err());

        let mut wrong_magic = malformed_proof.to_vec();
        wrong_magic[..4].copy_from_slice(b"SMZ1");
        assert!(verify_smallwood_poseidon2_v8_candidate_with_relation(
            &relation,
            &input,
            &wrong_magic,
        )
        .is_err());

        let mut caller_selected_digest = input.clone();
        caller_selected_digest.relation_digest[0] ^= 1;
        assert!(
            verify_smallwood_poseidon2_v8_candidate(&caller_selected_digest, malformed_proof,)
                .is_err()
        );
    }

    #[test]
    fn v8_canonicality_and_identity_checks_fail_closed() {
        let relation = TestRelation::new();
        let mut input = SmallwoodPoseidon2V8VerifierInput::from_relation(17, &relation);
        input.public_values[V8_PUBLIC_FEE] = SMALLWOOD_POSEIDON2_V8_GOLDILOCKS_MODULUS;
        assert!(input.transcript_preamble().is_err());

        let mut input = SmallwoodPoseidon2V8VerifierInput::from_relation(17, &relation);
        input.public_values[V8_PUBLIC_CIRCUIT_VERSION] = 4;
        assert!(input.transcript_preamble().is_err());

        let mut input = SmallwoodPoseidon2V8VerifierInput::from_relation(17, &relation);
        input.relation_digest = [0; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES];
        assert!(input.transcript_preamble().is_err());

        assert_eq!(SMALLWOOD_POSEIDON2_V8_MAX_ROUTED_PROOF_BYTES, 125_638);
        assert!(
            SMALLWOOD_POSEIDON2_V8_MAX_ROUTED_PROOF_BYTES
                < SMALLWOOD_POSEIDON2_V8_MAX_INNER_PROOF_BYTES
        );

        let mut max_shape = SmallwoodPoseidon2V8PublicStatement::default();
        max_shape.output_flags = [true, true];
        max_shape.commitments = [[1, 2, 3, 4, 5, 6, 7], [8, 9, 10, 11, 12, 13, 14]];
        max_shape.ciphertext_commitments = [[15, 16, 17, 18, 19, 20], [21, 22, 23, 24, 25, 26]];
        let max_shape_words = max_shape.to_public_words();
        assert_eq!(
            smallwood_poseidon2_v8_routed_proof_budget(&max_shape_words).unwrap(),
            125_638
        );
        assert_eq!(
            smallwood_poseidon2_v8_exact_action_bytes(&max_shape_words, 122_863).unwrap(),
            128_297
        );
    }

    #[test]
    fn compact448_profile7_preamble_projection_and_inactive_routing_are_exact() {
        let relation = TestRelation::new();
        let input = SmallwoodPoseidon2V8VerifierInput::from_relation(0x1122_3344, &relation);
        let smz9 = input.transcript_preamble().unwrap();
        let smc7 = input.compact448_candidate_transcript_preamble_v1().unwrap();
        assert_eq!(smz9.as_bytes()[PREAMBLE_OFFSET_PROFILE], 6);
        assert_eq!(smc7.as_bytes()[PREAMBLE_OFFSET_PROFILE], 7);
        assert_eq!(
            &smz9.as_bytes()[PREAMBLE_OFFSET_INNER_MAGIC..PREAMBLE_OFFSET_RELATION_DIGEST],
            b"SMZ9",
        );
        assert_eq!(
            &smc7.as_bytes()[PREAMBLE_OFFSET_INNER_MAGIC..PREAMBLE_OFFSET_RELATION_DIGEST],
            b"SMC7",
        );
        assert_eq!(
            &smc7.as_bytes()[PREAMBLE_OFFSET_RELATION_DIGEST..],
            &smz9.as_bytes()[PREAMBLE_OFFSET_RELATION_DIGEST..],
        );
        for index in 0..SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_BYTES {
            if index == PREAMBLE_OFFSET_PROFILE
                || (PREAMBLE_OFFSET_INNER_MAGIC..PREAMBLE_OFFSET_RELATION_DIGEST).contains(&index)
            {
                continue;
            }
            assert_eq!(
                smc7.as_bytes()[index],
                smz9.as_bytes()[index],
                "byte {index}"
            );
        }
        assert!(ensure_smz9_bytes(b"SMC7").is_err());
        assert!(ensure_smc7_bytes(b"SMZ9").is_err());

        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let source_relation =
            SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement)
                .expect("construct exact HGV8RP03 source relation");
        assert_eq!(
            project_smallwood_poseidon2_v8_compact448_candidate_bytes_v1(&source_relation)
                .expect("project exact inactive compact candidate"),
            SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES,
        );
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES,
            117_702,
        );

        let mut max_shape = SmallwoodPoseidon2V8PublicStatement::default();
        max_shape.output_flags = [true, true];
        max_shape.commitments = [[1, 2, 3, 4, 5, 6, 7], [8, 9, 10, 11, 12, 13, 14]];
        max_shape.ciphertext_commitments = [[15, 16, 17, 18, 19, 20], [21, 22, 23, 24, 25, 26]];
        assert_eq!(
            smallwood_poseidon2_v8_exact_action_bytes(
                &max_shape.to_public_words(),
                SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES,
            )
            .unwrap(),
            123_136,
        );
    }

    #[test]
    fn compact448_q20_profile8_preamble_projection_and_inactive_routing_are_exact() {
        let relation = TestRelation::new();
        let input = SmallwoodPoseidon2V8VerifierInput::from_relation(0x1122_3344, &relation);
        let smz9 = input.transcript_preamble().unwrap();
        let smc7 = input.compact448_candidate_transcript_preamble_v1().unwrap();
        let smc8 = input
            .compact448_q20_candidate_transcript_preamble_v1()
            .unwrap();
        assert_eq!(smz9.as_bytes()[PREAMBLE_OFFSET_PROFILE], 6);
        assert_eq!(smc7.as_bytes()[PREAMBLE_OFFSET_PROFILE], 7);
        assert_eq!(smc8.as_bytes()[PREAMBLE_OFFSET_PROFILE], 8);
        assert_eq!(
            &smc8.as_bytes()[PREAMBLE_OFFSET_INNER_MAGIC..PREAMBLE_OFFSET_RELATION_DIGEST],
            b"SMC8",
        );
        assert_eq!(
            &smc8.as_bytes()[PREAMBLE_OFFSET_RELATION_DIGEST..],
            &smz9.as_bytes()[PREAMBLE_OFFSET_RELATION_DIGEST..],
        );
        for index in 0..SMALLWOOD_POSEIDON2_V8_BINDING_PREAMBLE_BYTES {
            if index == PREAMBLE_OFFSET_PROFILE
                || (PREAMBLE_OFFSET_INNER_MAGIC..PREAMBLE_OFFSET_RELATION_DIGEST).contains(&index)
            {
                continue;
            }
            assert_eq!(
                smc8.as_bytes()[index],
                smz9.as_bytes()[index],
                "byte {index}"
            );
        }
        assert!(ensure_smz9_bytes(b"SMC8").is_err());
        assert!(ensure_smc7_bytes(b"SMC8").is_err());
        assert!(ensure_smc8_bytes(b"SMZ9").is_err());
        assert!(ensure_smc8_bytes(b"SMC7").is_err());

        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let source_relation =
            SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement)
                .expect("construct exact HGV8RP03 source relation");
        assert_eq!(
            project_smallwood_poseidon2_v8_compact448_q20_candidate_bytes_v1(&source_relation)
                .expect("project exact inactive q20 compact candidate"),
            SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES,
        );
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES,
            119_879,
        );
        assert_eq!(
            smallwood_poseidon2_v8_exact_action_bytes(
                &statement.to_public_words(),
                SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES,
            )
            .unwrap(),
            121_019,
        );

        let mut max_shape = SmallwoodPoseidon2V8PublicStatement::default();
        max_shape.output_flags = [true, true];
        max_shape.commitments = [[1, 2, 3, 4, 5, 6, 7], [8, 9, 10, 11, 12, 13, 14]];
        max_shape.ciphertext_commitments = [[15, 16, 17, 18, 19, 20], [21, 22, 23, 24, 25, 26]];
        assert_eq!(
            smallwood_poseidon2_v8_exact_action_bytes(
                &max_shape.to_public_words(),
                SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES,
            )
            .unwrap(),
            125_313,
        );
    }

    #[test]
    #[ignore = "exact N=2^23 HGV8RP03 compact proof generation is a bounded measurement run"]
    fn compact448_hgv8rp03_prover_verifier_roundtrip_and_mutation_rejection() {
        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let witness = SmallwoodPoseidon2V8Witness::default();
        let candidate = compile_and_prove_smallwood_poseidon2_v8_compact448_candidate_v1(
            &statement, &witness, 17,
        )
        .expect("produce and self-verify exact inactive SMC7 proof");
        let measured_inner = candidate.proof_bytes().len();
        let zero_output_action = candidate.measured_action_bytes();
        let max_output_action = smallwood_poseidon2_v8_exact_action_bytes(
            &{
                let mut words = candidate.verifier_input().public_values;
                words[V8_PUBLIC_OUTPUT_FLAGS.start] = 1;
                words[V8_PUBLIC_OUTPUT_FLAGS.start + 1] = 1;
                words
            },
            measured_inner,
        )
        .expect("derive unchanged two-output V8 carrier length");
        eprintln!(
            "SMC7_MEASUREMENT inner={measured_inner} zero_output_leaf={} zero_output_envelope={} zero_output_action={zero_output_action} max_output_leaf={} max_output_envelope={} max_output_action={max_output_action}",
            zero_output_action - 36,
            zero_output_action - 4,
            max_output_action - 36,
            max_output_action - 4,
        );
        assert_eq!(&candidate.proof_bytes()[..4], b"SMC7");
        assert!(
            candidate.proof_bytes().len()
                <= SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES
        );
        verify_smallwood_poseidon2_v8_compact448_candidate_v1(
            candidate.verifier_input(),
            candidate.proof_bytes(),
        )
        .expect("replay exact inactive SMC7 proof");

        let mut mutated = candidate.proof_bytes().to_vec();
        mutated[4] ^= 1;
        assert!(verify_smallwood_poseidon2_v8_compact448_candidate_v1(
            candidate.verifier_input(),
            &mutated,
        )
        .is_err());
        assert!(verify_smallwood_poseidon2_v8_candidate(
            candidate.verifier_input(),
            candidate.proof_bytes(),
        )
        .is_err());
    }

    #[test]
    #[ignore = "exact N=2^23 HGV8RP03 q20 compact proof generation is a bounded measurement run"]
    fn compact448_q20_hgv8rp03_prover_verifier_roundtrip_and_mutation_rejection() {
        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let witness = SmallwoodPoseidon2V8Witness::default();
        let candidate = compile_and_prove_smallwood_poseidon2_v8_compact448_q20_candidate_v1(
            &statement, &witness, 17,
        )
        .expect("produce and self-verify exact inactive SMC8 proof");
        let measured_inner = candidate.proof_bytes().len();
        let zero_output_action = candidate.measured_action_bytes();
        let max_output_action = smallwood_poseidon2_v8_exact_action_bytes(
            &{
                let mut words = candidate.verifier_input().public_values;
                words[V8_PUBLIC_OUTPUT_FLAGS.start] = 1;
                words[V8_PUBLIC_OUTPUT_FLAGS.start + 1] = 1;
                words
            },
            measured_inner,
        )
        .expect("derive unchanged two-output V8 carrier length");
        eprintln!(
            "SMC8_MEASUREMENT inner={measured_inner} zero_output_leaf={} zero_output_envelope={} zero_output_action={zero_output_action} max_output_leaf={} max_output_envelope={} max_output_action={max_output_action}",
            zero_output_action - 36,
            zero_output_action - 4,
            max_output_action - 36,
            max_output_action - 4,
        );
        assert_eq!(&candidate.proof_bytes()[..4], b"SMC8");
        assert_eq!(
            candidate.projected_max_proof_bytes(),
            SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES,
        );
        assert!(
            candidate.proof_bytes().len()
                <= SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES
        );
        verify_smallwood_poseidon2_v8_compact448_q20_candidate_v1(
            candidate.verifier_input(),
            candidate.proof_bytes(),
        )
        .expect("replay exact inactive SMC8 proof through reconstructed HGV8RP03 verifier");

        let mut mutated = candidate.proof_bytes().to_vec();
        mutated[4] ^= 1;
        assert!(verify_smallwood_poseidon2_v8_compact448_q20_candidate_v1(
            candidate.verifier_input(),
            &mutated,
        )
        .is_err());
        assert!(verify_smallwood_poseidon2_v8_candidate(
            candidate.verifier_input(),
            candidate.proof_bytes(),
        )
        .is_err());
        assert!(verify_smallwood_poseidon2_v8_compact448_candidate_v1(
            candidate.verifier_input(),
            candidate.proof_bytes(),
        )
        .is_err());
    }
}
