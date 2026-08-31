//! Scalar oracle and deterministic QIR map for the full V6/Epsilon relation.
//!
//! This module is deliberately not reachable from production proof dispatch.  It defines the
//! complete fixed two-input/two-output transaction relation, validates its scalar semantics, and
//! emits a deterministic program/instance map.  The currently executable diagnostic oracle lowers
//! every slot through the exact Boolean SHAKE256 relation in
//! [`crate::smallwood_shake256_full_relation`]; it is explicitly rejected because the authoritative
//! `HGF6HR02` registry requires SHAKE512 for secret-derived roles.  No Poseidon value and no
//! host-computed digest is accepted as authority.
//!
//! Every activity mask requires the same mixed 79 SHAKE invocations and 145 Keccak-f[1600]
//! permutations.  The retained uniform-SHAKE256 oracle has 124 permutations and cannot satisfy
//! successor or production verification.
//! In particular, each output owns a fixed 2,147-byte ciphertext witness and a 2,182-byte
//! `ct.hash1` frame.  An inactive output constrains all 2,147 bytes to zero and gates the public
//! ciphertext length and digest to zero; the seventeen-permutation SHAKE trace remains present.
//!
//! The returned digest bytes are honest witness assignments extracted only after the Boolean
//! trace verifies.  They are not verifier authority: [`FullShake448QirInstance::materialize_hash`]
//! reconstructs the same trace, and the named scalar bindings describe the required conditional
//! equalities between trace outputs, private wires, and the canonical public statement.  The
//! SmallWood aggregate/rebasing layer must compile those bindings into one committed relation
//! before production authorization can change from false.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::full_shake448_statement::{
    decode_v6_statement, encode_v6_ciphertext_hash_frame, encode_v6_semantic_frame,
    encode_v6_statement, project_v6_statement, Digest448, FullShake448Statement,
    FullShake448StatementError, SignedMagnitude, V6ActivationBinding, V6StatementProjection,
    GOLDILOCKS_MODULUS, KEY_OUTPUT_ORDER_TAG, ROLE_ACCUMULATOR, ROLE_BALANCE_TAG, ROLE_INTENT,
    ROLE_MERKLE_NODE, ROLE_NOTE_COMMITMENT, ROLE_NULLIFIER, ROLE_POLICY, ROLE_SPEND_KEYS,
    ROLE_VALUE_LOCK, V6_BALANCE_SLOTS, V6_CANONICAL_CIPHERTEXT_BYTES, V6_DIGEST_BYTES,
    V6_DOMAIN_SET, V6_MAX_INPUTS, V6_MAX_NOTE_VALUE, V6_MAX_OUTPUTS, V6_PROOF_PROFILE,
    V6_STATEMENT_BYTES, V6_STATEMENT_LIMBS,
};
use crate::smallwood_shake256_full_relation::{
    fixed_authorization_mux_relation, shake256_relation, verify_constraint_system,
    FixedAuthorizationMuxBindingCoverage, FixedAuthorizationMuxSlot, FixedAuthorizationMuxTrace,
    Shake256Constraint, Shake256ConstraintTrace, Shake256RelationError,
    Shake256TraceBindingCoverage, Shake256Wire, AUTHORIZATION_MODE_COUNT, BALANCE_TAG_FRAME_BYTES,
    CIPHERTEXT_HASH_FRAME_BYTES, FULL_RELATION_AUTHORITY_KECCAK_PERMUTATIONS,
    FULL_RELATION_SHAKE256_INVOCATIONS, INTENT_FRAME_BYTES, SHAKE256_448_OUTPUT_BYTES,
    SHAKE256_RATE_BYTES,
};

pub const MAX_INPUTS: usize = V6_MAX_INPUTS;
pub const MAX_OUTPUTS: usize = V6_MAX_OUTPUTS;
pub const BALANCE_SLOTS: usize = V6_BALANCE_SLOTS;
pub const DIGEST_BYTES: usize = V6_DIGEST_BYTES;
pub const MERKLE_DEPTH: usize = 32;
pub const MAX_SIGNERS: usize = 6;
pub const SPEND_KEY_BYTES: usize = 48;
pub const NATIVE_ASSET_ID: u64 = 0;
pub const PADDING_ASSET_ID: u64 = u64::MAX;
pub const RESERVED_REDUCED_PADDING_ASSET_ID: u64 = u32::MAX as u64 - 1;

pub const NOTE_HASH_START: usize = 0;
pub const NULLIFIER_HASH_START: usize = 4;
pub const MERKLE_HASH_START: usize = 6;
pub const SPEND_KEY_HASH_START: usize = 70;
pub const POLICY_HASH_SLOT: usize = 72;
pub const AUTHORIZATION_HASH_START: usize = 73;
pub const INTENT_HASH_SLOT: usize = 75;
pub const BALANCE_TAG_HASH_SLOT: usize = 76;
pub const CIPHERTEXT_HASH_START: usize = 77;
pub const REJECTED_UNIFORM_SHAKE256_INVOCATIONS: usize = 79;
pub const REJECTED_UNIFORM_SHAKE256_KECCAK_PERMUTATIONS: usize = 124;

pub type V6SemanticHashAlgorithm = crate::full_shake448_statement::V6HashAlgorithm;
pub type V6HashSecurityPurpose = crate::full_shake448_statement::V6HashPurpose;
pub type V6SemanticHashRoleProfile = crate::full_shake448_statement::V6HashRoleSpec;

pub const V6_SUCCESSOR_HASH_INVOCATIONS: usize =
    crate::full_shake448_statement::V6_FULL_RELATION_SHAKE_INVOCATIONS;
pub const V6_SUCCESSOR_HASH_KECCAK_PERMUTATIONS: usize =
    crate::full_shake448_statement::V6_FULL_RELATION_KECCAK_PERMUTATIONS;

pub fn v6_successor_hash_registry_bytes() -> Vec<u8> {
    crate::full_shake448_statement::encode_v6_hash_role_registry().to_vec()
}

pub const fn v6_successor_hash_registry_digest() -> [u8; 64] {
    crate::full_shake448_statement::V6_HASH_ROLE_REGISTRY_DIGEST
}

pub fn validate_v6_successor_hash_registry() -> Result<(), FullShake448RelationError> {
    let registry = crate::full_shake448_statement::V6_HASH_ROLE_REGISTRY;
    let invocations = registry
        .iter()
        .map(|entry| usize::from(entry.invocations))
        .sum::<usize>();
    let permutations = registry
        .iter()
        .map(|entry| usize::from(entry.invocations) * usize::from(entry.permutations_per_call))
        .sum::<usize>();
    let geometry_invalid = registry.iter().any(|entry| {
        let absorb = usize::try_from(entry.max_frame_bytes).expect("u32 fits usize")
            / usize::from(entry.rate_bytes)
            + 1;
        let squeeze =
            usize::from(entry.output_bytes.saturating_sub(1)) / usize::from(entry.rate_bytes);
        usize::from(entry.permutations_per_call) != absorb + squeeze
    });
    if invocations != V6_SUCCESSOR_HASH_INVOCATIONS
        || permutations != V6_SUCCESSOR_HASH_KECCAK_PERMUTATIONS
        || geometry_invalid
        || crate::full_shake448_statement::recompute_v6_hash_role_registry_digest()
            != v6_successor_hash_registry_digest()
    {
        return Err(FullShake448RelationError::SuccessorHashRegistry);
    }
    Ok(())
}

/// HGF6HR02's rate-72 `SHAKE512` label is not a FIPS-202 algorithm.  Keep this
/// separate from structural registry validation so historical descriptors can
/// still be parsed and diagnosed without ever becoming production authority.
pub fn ensure_v6_successor_registry_uses_conventional_hashes(
) -> Result<(), FullShake448RelationError> {
    Err(FullShake448RelationError::NonConventionalHashRegistry)
}

pub const fn v6_successor_profile_for_hash_slot(slot: usize) -> Option<V6SemanticHashRoleProfile> {
    let registry = crate::full_shake448_statement::V6_HASH_ROLE_REGISTRY;
    let profile = match slot {
        NOTE_HASH_START..=3 => registry[0],
        NULLIFIER_HASH_START..=5 => registry[1],
        MERKLE_HASH_START..=69 => registry[2],
        SPEND_KEY_HASH_START..=71 => registry[3],
        POLICY_HASH_SLOT => registry[4],
        AUTHORIZATION_HASH_START..=74 => registry[5],
        INTENT_HASH_SLOT => registry[6],
        BALANCE_TAG_HASH_SLOT => registry[7],
        CIPHERTEXT_HASH_START..=78 => registry[8],
        _ => return None,
    };
    Some(profile)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V6HashInvocationCoverage {
    pub slot: usize,
    pub name: String,
    pub registry_role: [u8; 8],
    pub security_purpose: V6HashSecurityPurpose,
    pub required_algorithm: V6SemanticHashAlgorithm,
    pub required_rate_bytes: usize,
    pub required_permutations: usize,
    pub lowered_algorithm: V6SemanticHashAlgorithm,
    pub lowered_rate_bytes: usize,
    pub lowered_permutations: usize,
    pub fully_bound: bool,
}

impl V6HashInvocationCoverage {
    pub const fn satisfies_successor_registry(&self) -> bool {
        self.fully_bound
            && self.required_algorithm as u8 == self.lowered_algorithm as u8
            && self.required_rate_bytes == self.lowered_rate_bytes
            && self.required_permutations == self.lowered_permutations
    }
}

pub type Digest = Digest448;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NoteKind {
    #[default]
    Ordinary,
    Accumulator,
    ValueLock,
}

impl NoteKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Ordinary => 0,
            Self::Accumulator => 1,
            Self::ValueLock => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteOpening {
    pub kind: NoteKind,
    pub value: u64,
    pub asset_id: u64,
    pub pk_recipient: [u8; 32],
    pub rho: [u8; 48],
    pub randomness: [u8; 48],
    pub pk_auth: Digest,
}

impl NoteOpening {
    pub const fn zero() -> Self {
        Self {
            kind: NoteKind::Ordinary,
            value: 0,
            asset_id: 0,
            pk_recipient: [0; 32],
            rho: [0; 48],
            randomness: [0; 48],
            pk_auth: [0; DIGEST_BYTES],
        }
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputWitness {
    pub active: bool,
    pub spend_key: [u8; SPEND_KEY_BYTES],
    pub note: NoteOpening,
    pub position: u64,
    pub siblings: [Digest; MERKLE_DEPTH],
    pub balance_slot_selectors: [bool; BALANCE_SLOTS],
}

impl InputWitness {
    pub const fn zero() -> Self {
        Self {
            active: false,
            spend_key: [0; SPEND_KEY_BYTES],
            note: NoteOpening::zero(),
            position: 0,
            siblings: [[0; DIGEST_BYTES]; MERKLE_DEPTH],
            balance_slot_selectors: [false; BALANCE_SLOTS],
        }
    }

    fn inactive_payload_is_zero(&self) -> bool {
        self.spend_key == [0; SPEND_KEY_BYTES]
            && self.note.is_zero()
            && self.position == 0
            && self.siblings == [[0; DIGEST_BYTES]; MERKLE_DEPTH]
            && self.balance_slot_selectors == [false; BALANCE_SLOTS]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputWitness {
    pub active: bool,
    pub note: NoteOpening,
    pub balance_slot_selectors: [bool; BALANCE_SLOTS],
    /// Fixed-size canonical ciphertext bytes.  Inactive slots must be all zero.
    pub canonical_ciphertext: [u8; V6_CANONICAL_CIPHERTEXT_BYTES],
}

impl OutputWitness {
    pub const fn zero() -> Self {
        Self {
            active: false,
            note: NoteOpening::zero(),
            balance_slot_selectors: [false; BALANCE_SLOTS],
            canonical_ciphertext: [0; V6_CANONICAL_CIPHERTEXT_BYTES],
        }
    }

    fn inactive_payload_is_zero(&self) -> bool {
        self.note.is_zero()
            && self.balance_slot_selectors == [false; BALANCE_SLOTS]
            && self.canonical_ciphertext == [0; V6_CANONICAL_CIPHERTEXT_BYTES]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateAuthMode {
    SingleKey,
    AccumulatorInit,
    ApprovalStep,
    ValueLockCreation,
    FinalThresholdSpend,
}

impl PrivateAuthMode {
    pub const fn selectors(self) -> [bool; 5] {
        match self {
            Self::SingleKey => [true, false, false, false, false],
            Self::AccumulatorInit => [false, true, false, false, false],
            Self::ApprovalStep => [false, false, true, false, false],
            Self::ValueLockCreation => [false, false, false, true, false],
            Self::FinalThresholdSpend => [false, false, false, false, true],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccumulatorOpening {
    pub policy_root: Digest,
    pub intent_digest: Digest,
    pub threshold: u64,
    pub signer_count: u64,
    pub approval_count: u64,
    pub approved_slots: [bool; MAX_SIGNERS],
}

impl AccumulatorOpening {
    pub const fn zero() -> Self {
        Self {
            policy_root: [0; DIGEST_BYTES],
            intent_digest: [0; DIGEST_BYTES],
            threshold: 0,
            signer_count: 0,
            approval_count: 0,
            approved_slots: [false; MAX_SIGNERS],
        }
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateAuthWitness {
    pub mode: PrivateAuthMode,
    pub current: AccumulatorOpening,
    pub next: AccumulatorOpening,
    pub signer_tags: [Digest; MAX_SIGNERS],
}

impl Default for PrivateAuthWitness {
    fn default() -> Self {
        Self {
            mode: PrivateAuthMode::SingleKey,
            current: AccumulatorOpening::zero(),
            next: AccumulatorOpening::zero(),
            signer_tags: [[0; DIGEST_BYTES]; MAX_SIGNERS],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullShake448Witness {
    pub inputs: [InputWitness; MAX_INPUTS],
    pub outputs: [OutputWitness; MAX_OUTPUTS],
    pub auth: PrivateAuthWitness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QirHashBinding {
    Internal,
    PublicWhenInputActive(usize),
    PublicWhenOutputActive(usize),
    PublicAlways,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QirHashSlotSpec {
    pub index: usize,
    pub name: String,
    pub role: [u8; 8],
    pub maximum_frame_bytes: usize,
    pub output_bytes: usize,
    pub permutations: usize,
    pub binding: QirHashBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QirScalarConstraintKind {
    CanonicalStatement,
    Boolean,
    Equality,
    ConditionalEquality,
    ZeroPadding,
    Range,
    NonZero,
    Distinct,
    OneHot,
    Ordered,
    IntegerBalance,
    AuthorizationTransition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QirScalarConstraintSpec {
    pub index: usize,
    pub name: String,
    pub kind: QirScalarConstraintKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullShake448QirProgram {
    pub hash_slots: Vec<QirHashSlotSpec>,
    pub scalar_constraints: Vec<QirScalarConstraintSpec>,
}

impl FullShake448QirProgram {
    pub fn canonical() -> Self {
        let mut hash_slots = Vec::with_capacity(REJECTED_UNIFORM_SHAKE256_INVOCATIONS);
        let mut push_hash = |name: String,
                             role: [u8; 8],
                             maximum_frame_bytes: usize,
                             output_bytes: usize,
                             permutations: usize,
                             binding: QirHashBinding| {
            let index = hash_slots.len();
            hash_slots.push(QirHashSlotSpec {
                index,
                name,
                role,
                maximum_frame_bytes,
                output_bytes,
                permutations,
                binding,
            });
        };
        for index in 0..MAX_INPUTS {
            push_hash(
                format!("note.input[{index}]"),
                ROLE_NOTE_COMMITMENT,
                232,
                DIGEST_BYTES,
                2,
                QirHashBinding::Internal,
            );
        }
        for index in 0..MAX_OUTPUTS {
            push_hash(
                format!("note.output[{index}]"),
                ROLE_NOTE_COMMITMENT,
                232,
                DIGEST_BYTES,
                2,
                QirHashBinding::PublicWhenOutputActive(index),
            );
        }
        for index in 0..MAX_INPUTS {
            push_hash(
                format!("nullifier.input[{index}]"),
                ROLE_NULLIFIER,
                135,
                DIGEST_BYTES,
                1,
                QirHashBinding::PublicWhenInputActive(index),
            );
        }
        for input in 0..MAX_INPUTS {
            for level in 0..MERKLE_DEPTH {
                push_hash(
                    format!("merkle.input[{input}].level[{level}]"),
                    ROLE_MERKLE_NODE,
                    133,
                    DIGEST_BYTES,
                    1,
                    QirHashBinding::Internal,
                );
            }
        }
        for index in 0..MAX_INPUTS {
            push_hash(
                format!("spend_keys.input[{index}]"),
                ROLE_SPEND_KEYS,
                77,
                DIGEST_BYTES * 2,
                1,
                QirHashBinding::Internal,
            );
        }
        push_hash(
            "authorization.policy".to_owned(),
            ROLE_POLICY,
            385,
            DIGEST_BYTES,
            3,
            QirHashBinding::Internal,
        );
        for index in 0..2 {
            push_hash(
                format!("authorization.mux[{index}]"),
                ROLE_ACCUMULATOR,
                181,
                DIGEST_BYTES * 2,
                2,
                QirHashBinding::Internal,
            );
        }
        push_hash(
            "intent.statement".to_owned(),
            ROLE_INTENT,
            INTENT_FRAME_BYTES,
            DIGEST_BYTES,
            6,
            QirHashBinding::Internal,
        );
        push_hash(
            "balance.tag".to_owned(),
            ROLE_BALANCE_TAG,
            BALANCE_TAG_FRAME_BYTES,
            DIGEST_BYTES,
            1,
            QirHashBinding::PublicAlways,
        );
        for index in 0..MAX_OUTPUTS {
            push_hash(
                format!("ciphertext.output[{index}]"),
                *b"ct.hash1",
                CIPHERTEXT_HASH_FRAME_BYTES,
                DIGEST_BYTES,
                17,
                QirHashBinding::PublicWhenOutputActive(index),
            );
        }

        let mut scalar_constraints = Vec::new();
        let mut push = |name: String, kind: QirScalarConstraintKind| {
            let index = scalar_constraints.len();
            scalar_constraints.push(QirScalarConstraintSpec { index, name, kind });
        };
        for (name, kind) in [
            (
                "statement.exact_893_bytes",
                QirScalarConstraintKind::CanonicalStatement,
            ),
            (
                "statement.lossless_128_limb_projection",
                QirScalarConstraintKind::CanonicalStatement,
            ),
            (
                "statement.activation_exact",
                QirScalarConstraintKind::Equality,
            ),
            ("shape.action_nonempty", QirScalarConstraintKind::NonZero),
            (
                "nullifiers.active_distinct",
                QirScalarConstraintKind::Distinct,
            ),
            (
                "value_balance.signed_native_equation",
                QirScalarConstraintKind::IntegerBalance,
            ),
            ("assets.native_slot_zero", QirScalarConstraintKind::Equality),
            (
                "assets.strict_order_padding_suffix",
                QirScalarConstraintKind::Ordered,
            ),
            (
                "stablecoin.canonical",
                QirScalarConstraintKind::AuthorizationTransition,
            ),
            (
                "authorization.mode_one_hot",
                QirScalarConstraintKind::OneHot,
            ),
            (
                "authorization.typed_transition",
                QirScalarConstraintKind::AuthorizationTransition,
            ),
            (
                "balance.four_slots",
                QirScalarConstraintKind::IntegerBalance,
            ),
            (
                "balance.tag.public_binding",
                QirScalarConstraintKind::Equality,
            ),
            (
                "intent.final_binding",
                QirScalarConstraintKind::ConditionalEquality,
            ),
        ] {
            push(name.to_owned(), kind);
        }
        for index in 0..MAX_INPUTS {
            for (suffix, kind) in [
                ("flag", QirScalarConstraintKind::Boolean),
                ("inactive_padding", QirScalarConstraintKind::ZeroPadding),
                ("value_range", QirScalarConstraintKind::Range),
                ("asset_selector", QirScalarConstraintKind::OneHot),
                (
                    "authorization",
                    QirScalarConstraintKind::ConditionalEquality,
                ),
                ("nullifier", QirScalarConstraintKind::ConditionalEquality),
                ("membership", QirScalarConstraintKind::ConditionalEquality),
            ] {
                push(format!("input[{index}].{suffix}"), kind);
            }
        }
        for index in 0..MAX_OUTPUTS {
            for (suffix, kind) in [
                ("flag", QirScalarConstraintKind::Boolean),
                ("inactive_padding", QirScalarConstraintKind::ZeroPadding),
                ("value_range", QirScalarConstraintKind::Range),
                ("asset_selector", QirScalarConstraintKind::OneHot),
                ("commitment", QirScalarConstraintKind::ConditionalEquality),
                (
                    "ciphertext_size",
                    QirScalarConstraintKind::ConditionalEquality,
                ),
                (
                    "ciphertext_hash",
                    QirScalarConstraintKind::ConditionalEquality,
                ),
            ] {
                push(format!("output[{index}].{suffix}"), kind);
            }
        }
        Self {
            hash_slots,
            scalar_constraints,
        }
    }

    pub fn validate_shape(&self) -> Result<(), FullShake448RelationError> {
        if self.hash_slots.len() != REJECTED_UNIFORM_SHAKE256_INVOCATIONS
            || self
                .hash_slots
                .iter()
                .map(|slot| slot.permutations)
                .sum::<usize>()
                != REJECTED_UNIFORM_SHAKE256_KECCAK_PERMUTATIONS
            || self
                .hash_slots
                .iter()
                .enumerate()
                .any(|(index, slot)| slot.index != index)
        {
            return Err(FullShake448RelationError::QirProgramShape);
        }
        let mut names = BTreeSet::new();
        if self
            .hash_slots
            .iter()
            .any(|slot| !names.insert(slot.name.as_str()))
        {
            return Err(FullShake448RelationError::DuplicateQirName);
        }
        for constraint in &self.scalar_constraints {
            if !names.insert(constraint.name.as_str()) {
                return Err(FullShake448RelationError::DuplicateQirName);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct QirHashInstance {
    pub slot: QirHashSlotSpec,
    /// Ordinary SHAKE frame.  For fixed authorization slots this is the
    /// honestly selected arm and is retained only for scalar diagnostics; the
    /// executable lowering uses `authorization_mux` and never specializes the
    /// constraint shape to this value.
    pub frame: Vec<u8>,
    /// One typed upstream source for every byte of `frame`; there are no free
    /// message bytes at the SHAKE boundary.
    pub frame_sources: Vec<QirByteSource>,
    /// Stable symbolic value produced by this trace.  Consumers name the same
    /// value in their frame-source maps, so aggregate lowering can equality-link
    /// every bit without consulting host digest bytes.
    pub output_symbol: String,
    /// Honest output assignment; never accepted without materializing the trace.
    pub output_assignment: Vec<u8>,
    /// Present only for slots 73 and 74.  All five arms are carried so the
    /// relation has identical wires in Single/Init/Approval/Lock/Final modes.
    pub authorization_mux: Option<QirFixedAuthorizationMuxInstance>,
}

#[derive(Clone, Debug)]
pub struct QirFixedAuthorizationMuxInstance {
    pub slot: FixedAuthorizationMuxSlot,
    pub mode_selectors: [bool; AUTHORIZATION_MODE_COUNT],
    pub arms: [QirAuthorizationMuxArm; AUTHORIZATION_MODE_COUNT],
}

#[derive(Clone, Debug)]
pub struct QirAuthorizationMuxArm {
    pub frame: Vec<u8>,
    /// One typed source per raw frame byte for non-dummy arms.  Dummy arms are
    /// internally constant-constrained by the fixed mux and expose no sources.
    pub frame_sources: Vec<QirByteSource>,
}

pub enum MaterializedQirHashTrace {
    Ordinary(Shake256ConstraintTrace),
    FixedAuthorization(FixedAuthorizationMuxTrace),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QirByteSourceKind {
    Constant,
    CanonicalStatement,
    PrivateWitness,
    InternalDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QirByteSource {
    pub kind: QirByteSourceKind,
    pub symbol: String,
    pub byte_index: usize,
    pub value: u8,
}

#[derive(Clone, Debug)]
struct SourcedFrame {
    bytes: Vec<u8>,
    sources: Vec<QirByteSource>,
}

#[derive(Clone, Debug)]
struct SourcedField {
    kind: QirByteSourceKind,
    symbol: String,
    byte_indices: Vec<usize>,
    bytes: Vec<u8>,
}

impl SourcedField {
    fn contiguous(kind: QirByteSourceKind, symbol: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            kind,
            symbol: symbol.into(),
            byte_indices: (0..bytes.len()).collect(),
            bytes: bytes.to_vec(),
        }
    }

    fn indexed(
        kind: QirByteSourceKind,
        symbol: impl Into<String>,
        bytes: Vec<u8>,
        byte_indices: Vec<usize>,
    ) -> Self {
        debug_assert_eq!(bytes.len(), byte_indices.len());
        Self {
            kind,
            symbol: symbol.into(),
            byte_indices,
            bytes,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FullShake448QirInstance {
    pub program: FullShake448QirProgram,
    pub statement_bytes: [u8; V6_STATEMENT_BYTES],
    pub public_limbs: [u64; V6_STATEMENT_LIMBS],
    pub hash_instances: Vec<QirHashInstance>,
}

#[derive(Clone, Debug)]
pub struct FullShake448HashConstraintSystem {
    pub witness: Vec<u64>,
    pub constraints: Vec<Shake256Constraint>,
    pub source_bit_wires: BTreeMap<String, Vec<Shake256Wire>>,
    pub source_wire_index: BTreeMap<(String, usize, usize), Shake256Wire>,
    pub output_bit_wires: BTreeMap<String, Vec<Shake256Wire>>,
    pub invocation_coverages: Vec<Shake256TraceBindingCoverage>,
    pub authorization_mux_coverages: Vec<FixedAuthorizationMuxBindingCoverage>,
    pub hash_invocation_coverages: Vec<V6HashInvocationCoverage>,
}

impl FullShake448HashConstraintSystem {
    /// Verify only the retained uniform-SHAKE256 diagnostic oracle.  Success
    /// here is not successor-profile or production acceptance.
    pub fn verify_rejected_uniform_sha256(&self) -> Result<(), FullShake448RelationError> {
        verify_constraint_system(&self.witness, &self.constraints)?;
        if self.invocation_coverages.len() + self.authorization_mux_coverages.len()
            != REJECTED_UNIFORM_SHAKE256_INVOCATIONS
            || self
                .invocation_coverages
                .iter()
                .any(|coverage| !coverage.is_complete())
            || self
                .authorization_mux_coverages
                .iter()
                .any(|coverage| !coverage.is_complete())
        {
            return Err(FullShake448RelationError::FrameSourceCoverage(
                "aggregate SHAKE boundary".to_owned(),
            ));
        }
        if self.hash_invocation_coverages.len() != REJECTED_UNIFORM_SHAKE256_INVOCATIONS
            || self
                .hash_invocation_coverages
                .iter()
                .any(|coverage| !coverage.fully_bound)
        {
            return Err(FullShake448RelationError::FrameSourceCoverage(
                "typed mixed-successor hash registry".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QirLinearTerm {
    pub wire: Shake256Wire,
    pub coefficient: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QirLinearCombination {
    pub constant: u64,
    pub terms: Vec<QirLinearTerm>,
}

impl QirLinearCombination {
    fn constant(value: u64) -> Self {
        Self {
            constant: value % GOLDILOCKS_MODULUS,
            terms: Vec::new(),
        }
    }

    fn wire(wire: Shake256Wire) -> Self {
        Self {
            constant: 0,
            terms: vec![QirLinearTerm {
                wire,
                coefficient: 1,
            }],
        }
    }

    fn plus_wire(mut self, wire: Shake256Wire, coefficient: u64) -> Self {
        self.terms.push(QirLinearTerm {
            wire,
            coefficient: coefficient % GOLDILOCKS_MODULUS,
        });
        self
    }

    fn minus_wire(self, wire: Shake256Wire) -> Self {
        self.plus_wire(wire, GOLDILOCKS_MODULUS - 1)
    }

    fn eval(&self, witness: &[u64]) -> Result<u64, FullShake448RelationError> {
        let mut value = self.constant as u128;
        for term in &self.terms {
            let wire = witness.get(term.wire.index()).copied().ok_or(
                FullShake448RelationError::NonHashWireOutOfBounds {
                    wire: term.wire.index(),
                    witness_len: witness.len(),
                },
            )?;
            value += u128::from(wire) * u128::from(term.coefficient);
            value %= u128::from(GOLDILOCKS_MODULUS);
        }
        Ok(value as u64)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QirR1csConstraint {
    pub name: String,
    pub family: QirConstraintFamily,
    pub left: QirLinearCombination,
    pub right: QirLinearCombination,
    pub output: QirLinearCombination,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QirConstraintFamily {
    StatementActivation = 1,
    CanonicalEncoding = 2,
    ActivityMask = 3,
    InactivePadding = 4,
    ValueRange = 5,
    AssetSlotSelection = 6,
    AssetOrder = 7,
    Balance = 8,
    Stablecoin = 9,
    MerklePath = 10,
    NullifierBinding = 11,
    SpendAuthorization = 12,
    AuthorizationMode = 13,
    AuthorizationTransition = 14,
    OutputCommitmentBinding = 15,
    CiphertextBinding = 16,
    IntentBinding = 17,
    BalanceTagBinding = 18,
}

pub const REQUIRED_QIR_CONSTRAINT_FAMILIES: [QirConstraintFamily; 18] = [
    QirConstraintFamily::StatementActivation,
    QirConstraintFamily::CanonicalEncoding,
    QirConstraintFamily::ActivityMask,
    QirConstraintFamily::InactivePadding,
    QirConstraintFamily::ValueRange,
    QirConstraintFamily::AssetSlotSelection,
    QirConstraintFamily::AssetOrder,
    QirConstraintFamily::Balance,
    QirConstraintFamily::Stablecoin,
    QirConstraintFamily::MerklePath,
    QirConstraintFamily::NullifierBinding,
    QirConstraintFamily::SpendAuthorization,
    QirConstraintFamily::AuthorizationMode,
    QirConstraintFamily::AuthorizationTransition,
    QirConstraintFamily::OutputCommitmentBinding,
    QirConstraintFamily::CiphertextBinding,
    QirConstraintFamily::IntentBinding,
    QirConstraintFamily::BalanceTagBinding,
];

impl QirR1csConstraint {
    fn residual(&self, witness: &[u64]) -> Result<u64, FullShake448RelationError> {
        let left = u128::from(self.left.eval(witness)?);
        let right = u128::from(self.right.eval(witness)?);
        let output = u128::from(self.output.eval(witness)?);
        let modulus = u128::from(GOLDILOCKS_MODULUS);
        Ok(((left * right + modulus - output) % modulus) as u64)
    }
}

#[derive(Clone, Debug)]
pub struct FullShake448ConstraintSystem {
    pub witness: Vec<u64>,
    pub shake_constraints: Vec<Shake256Constraint>,
    pub non_hash_constraints: Vec<QirR1csConstraint>,
    pub source_wire_index: BTreeMap<(String, usize, usize), Shake256Wire>,
    pub output_bit_wires: BTreeMap<String, Vec<Shake256Wire>>,
    pub invocation_coverages: Vec<Shake256TraceBindingCoverage>,
    pub authorization_mux_coverages: Vec<FixedAuthorizationMuxBindingCoverage>,
    pub hash_invocation_coverages: Vec<V6HashInvocationCoverage>,
    pub public_raw_bit_bindings: Vec<(Shake256Wire, usize)>,
    pub constraint_family_coverage: BTreeSet<String>,
    pub executable_family_coverage: BTreeMap<QirConstraintFamily, usize>,
    /// Missing executable identities inside the 79-call semantic relation.
    pub missing_lowering: Vec<String>,
    /// External consensus/proof-system gates which do not make a completed
    /// semantic relation incomplete, but still forbid production admission.
    pub production_blockers: Vec<String>,
    /// This remains false until every registry role uses its required
    /// SHAKE512/SHAKE256 relation and the aggregate has exactly 145 Keccak
    /// permutations.  A verified 124-permutation oracle cannot set this flag.
    pub mixed_successor_145_relation_compiled: bool,
}

impl FullShake448ConstraintSystem {
    /// Verify the executable identities of the rejected uniform-SHAKE256
    /// diagnostic oracle.  This deliberately does not imply that the mixed
    /// successor relation is compiled.
    pub fn verify_rejected_uniform_sha256(&self) -> Result<(), FullShake448RelationError> {
        verify_constraint_system(&self.witness, &self.shake_constraints)?;
        if self.hash_invocation_coverages.len() != REJECTED_UNIFORM_SHAKE256_INVOCATIONS
            || self
                .hash_invocation_coverages
                .iter()
                .any(|coverage| !coverage.fully_bound)
        {
            return Err(FullShake448RelationError::FrameSourceCoverage(
                "typed mixed-successor hash registry".to_owned(),
            ));
        }
        for (index, constraint) in self.non_hash_constraints.iter().enumerate() {
            let residual = constraint.residual(&self.witness)?;
            if residual != 0 {
                return Err(FullShake448RelationError::NonHashConstraintViolation {
                    index,
                    name: constraint.name.clone(),
                    residual,
                });
            }
        }
        let mut actual = BTreeMap::new();
        for constraint in &self.non_hash_constraints {
            *actual.entry(constraint.family).or_insert(0usize) += 1;
        }
        if actual != self.executable_family_coverage {
            return Err(FullShake448RelationError::ConstraintFamilyCoverage);
        }
        for family in REQUIRED_QIR_CONSTRAINT_FAMILIES {
            if actual.get(&family).copied().unwrap_or(0) == 0 {
                return Err(FullShake448RelationError::MissingConstraintFamily(family));
            }
        }
        Ok(())
    }

    pub fn verify_mixed_successor_relation(&self) -> Result<(), FullShake448RelationError> {
        ensure_v6_successor_registry_uses_conventional_hashes()?;
        if !self.mixed_successor_145_relation_compiled
            || !self.missing_lowering.is_empty()
            || self
                .hash_invocation_coverages
                .iter()
                .any(|coverage| !coverage.satisfies_successor_registry())
        {
            return Err(FullShake448RelationError::SuccessorHashRelationUnavailable);
        }
        self.verify_rejected_uniform_sha256()
    }
}

struct R1csBuilder<'a> {
    witness: &'a mut Vec<u64>,
    constraints: &'a mut Vec<QirR1csConstraint>,
    counter: usize,
    family: QirConstraintFamily,
    zero: Shake256Wire,
    one: Shake256Wire,
}

fn ensure_symbol_bytes(
    witness: &mut Vec<u64>,
    shake_constraints: &mut Vec<Shake256Constraint>,
    index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    symbol: &str,
    bytes: &[u8],
    kind: QirByteSourceKind,
) -> Result<Vec<Shake256Wire>, FullShake448RelationError> {
    let mut wires = Vec::with_capacity(bytes.len() * 8);
    for (byte_index, byte) in bytes.iter().copied().enumerate() {
        for bit_index in 0..8 {
            let value = (byte >> bit_index) & 1;
            let key = (symbol.to_owned(), byte_index, bit_index);
            let wire = if let Some(wire) = index.get(&key).copied() {
                if witness[wire.index()] != u64::from(value) {
                    return Err(FullShake448RelationError::SourceSymbolConflict {
                        symbol: symbol.to_owned(),
                        byte_index,
                    });
                }
                wire
            } else {
                let wire = Shake256Wire::from_index(witness.len());
                witness.push(u64::from(value));
                shake_constraints.push(match kind {
                    QirByteSourceKind::Constant => Shake256Constraint::Constant {
                        output: wire,
                        value: value != 0,
                    },
                    QirByteSourceKind::CanonicalStatement => {
                        Shake256Constraint::PublicBoolean { wire }
                    }
                    QirByteSourceKind::PrivateWitness | QirByteSourceKind::InternalDigest => {
                        Shake256Constraint::Boolean { wire }
                    }
                });
                index.insert(key, wire);
                wire
            };
            wires.push(wire);
        }
    }
    Ok(wires)
}

fn statement_bits(
    index: &BTreeMap<(String, usize, usize), Shake256Wire>,
    offset: usize,
    bytes: usize,
) -> Result<Vec<Shake256Wire>, FullShake448RelationError> {
    let mut wires = Vec::with_capacity(bytes * 8);
    for byte_index in offset..offset + bytes {
        for bit_index in 0..8 {
            wires.push(
                *index
                    .get(&("statement.bytes".to_owned(), byte_index, bit_index))
                    .ok_or_else(|| {
                        FullShake448RelationError::FrameSourceCoverage(format!(
                            "statement.bytes[{byte_index}].bit[{bit_index}]"
                        ))
                    })?,
            );
        }
    }
    Ok(wires)
}

fn bytes_be_to_bits_le(byte_order_bits: &[Shake256Wire]) -> Vec<Shake256Wire> {
    debug_assert_eq!(byte_order_bits.len() % 8, 0);
    byte_order_bits
        .chunks_exact(8)
        .rev()
        .flat_map(|byte| byte.iter().copied())
        .collect()
}

fn u64_source_bits(
    witness: &mut Vec<u64>,
    shake_constraints: &mut Vec<Shake256Constraint>,
    index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    symbol: &str,
    value: u64,
    kind: QirByteSourceKind,
) -> Result<Vec<Shake256Wire>, FullShake448RelationError> {
    Ok(bytes_be_to_bits_le(&ensure_symbol_bytes(
        witness,
        shake_constraints,
        index,
        symbol,
        &value.to_be_bytes(),
        kind,
    )?))
}

fn u32_source_bits(
    witness: &mut Vec<u64>,
    shake_constraints: &mut Vec<Shake256Constraint>,
    index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    symbol: &str,
    value: u32,
    kind: QirByteSourceKind,
) -> Result<Vec<Shake256Wire>, FullShake448RelationError> {
    Ok(bytes_be_to_bits_le(&ensure_symbol_bytes(
        witness,
        shake_constraints,
        index,
        symbol,
        &value.to_be_bytes(),
        kind,
    )?))
}

fn digest_source_bits(
    witness: &mut Vec<u64>,
    shake_constraints: &mut Vec<Shake256Constraint>,
    index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    symbol: &str,
    value: &Digest,
    kind: QirByteSourceKind,
) -> Result<Vec<Shake256Wire>, FullShake448RelationError> {
    ensure_symbol_bytes(witness, shake_constraints, index, symbol, value, kind)
}

fn zero_if(
    builder: &mut R1csBuilder<'_>,
    prefix: &str,
    selector: Shake256Wire,
    wires: &[Shake256Wire],
) {
    let zero = builder.zero;
    for (index, wire) in wires.iter().copied().enumerate() {
        builder.assert_eq_if(&format!("{prefix}[{index}]"), selector, wire, zero);
    }
}

fn equal_if(
    builder: &mut R1csBuilder<'_>,
    prefix: &str,
    selector: Shake256Wire,
    left: &[Shake256Wire],
    right: &[Shake256Wire],
) {
    debug_assert_eq!(left.len(), right.len());
    for (index, (left, right)) in left.iter().copied().zip(right.iter().copied()).enumerate() {
        builder.assert_eq_if(&format!("{prefix}[{index}]"), selector, left, right);
    }
}

fn equal_always(
    builder: &mut R1csBuilder<'_>,
    prefix: &str,
    left: &[Shake256Wire],
    right: &[Shake256Wire],
) {
    debug_assert_eq!(left.len(), right.len());
    for (index, (left, right)) in left.iter().copied().zip(right.iter().copied()).enumerate() {
        builder.assert_eq(&format!("{prefix}[{index}]"), left, right);
    }
}

fn nonzero_if(
    builder: &mut R1csBuilder<'_>,
    prefix: &str,
    selector: Shake256Wire,
    bits: &[Shake256Wire],
) {
    let any = builder.any_bits(&format!("{prefix}.any"), bits);
    builder.imply(prefix, selector, any);
}

fn constant_u64_bits(
    witness: &mut Vec<u64>,
    shake_constraints: &mut Vec<Shake256Constraint>,
    index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    name: &str,
    value: u64,
) -> Result<Vec<Shake256Wire>, FullShake448RelationError> {
    u64_source_bits(
        witness,
        shake_constraints,
        index,
        &format!("constant.{name}"),
        value,
        QirByteSourceKind::Constant,
    )
}

#[derive(Clone)]
struct NoteQirWires {
    kind: Vec<Shake256Wire>,
    value: Vec<Shake256Wire>,
    asset: Vec<Shake256Wire>,
    auth: Vec<Shake256Wire>,
    all: Vec<Shake256Wire>,
}

#[derive(Clone)]
struct InputQirWires {
    spend_key: Vec<Shake256Wire>,
    note: NoteQirWires,
    position: Vec<Shake256Wire>,
    siblings: Vec<Vec<Shake256Wire>>,
    selectors: [Shake256Wire; BALANCE_SLOTS],
    selector_byte_bits: Vec<Shake256Wire>,
    all: Vec<Shake256Wire>,
}

#[derive(Clone)]
struct OutputQirWires {
    note: NoteQirWires,
    selectors: [Shake256Wire; BALANCE_SLOTS],
    selector_byte_bits: Vec<Shake256Wire>,
    ciphertext: Vec<Shake256Wire>,
    all: Vec<Shake256Wire>,
}

#[derive(Clone)]
struct AccumulatorQirWires {
    policy_root: Vec<Shake256Wire>,
    intent: Vec<Shake256Wire>,
    threshold: Vec<Shake256Wire>,
    signer_count: Vec<Shake256Wire>,
    approval_count: Vec<Shake256Wire>,
    approved: [Shake256Wire; MAX_SIGNERS],
    approved_byte_bits: Vec<Shake256Wire>,
    all: Vec<Shake256Wire>,
}

fn allocate_note_qir_wires(
    witness_values: &mut Vec<u64>,
    shake_constraints: &mut Vec<Shake256Constraint>,
    index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    symbol: &str,
    note: &NoteOpening,
) -> Result<NoteQirWires, FullShake448RelationError> {
    let kind = ensure_symbol_bytes(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.kind"),
        &[note.kind.tag()],
        QirByteSourceKind::PrivateWitness,
    )?;
    let value = u64_source_bits(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.value_u64be"),
        note.value,
        QirByteSourceKind::PrivateWitness,
    )?;
    let asset = u64_source_bits(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.asset_u64be"),
        note.asset_id,
        QirByteSourceKind::PrivateWitness,
    )?;
    let recipient = ensure_symbol_bytes(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.pk_recipient"),
        &note.pk_recipient,
        QirByteSourceKind::PrivateWitness,
    )?;
    let rho = ensure_symbol_bytes(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.rho"),
        &note.rho,
        QirByteSourceKind::PrivateWitness,
    )?;
    let randomness = ensure_symbol_bytes(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.randomness"),
        &note.randomness,
        QirByteSourceKind::PrivateWitness,
    )?;
    let auth = digest_source_bits(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.pk_auth"),
        &note.pk_auth,
        QirByteSourceKind::PrivateWitness,
    )?;
    let mut all = Vec::new();
    all.extend(&kind);
    all.extend(&value);
    all.extend(&asset);
    all.extend(recipient);
    all.extend(rho);
    all.extend(randomness);
    all.extend(&auth);
    Ok(NoteQirWires {
        kind,
        value,
        asset,
        auth,
        all,
    })
}

fn allocate_accumulator_qir_wires(
    witness_values: &mut Vec<u64>,
    shake_constraints: &mut Vec<Shake256Constraint>,
    index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    symbol: &str,
    opening: &AccumulatorOpening,
) -> Result<AccumulatorQirWires, FullShake448RelationError> {
    let policy_root = digest_source_bits(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.policy_root"),
        &opening.policy_root,
        QirByteSourceKind::PrivateWitness,
    )?;
    let intent = digest_source_bits(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.intent_digest"),
        &opening.intent_digest,
        QirByteSourceKind::PrivateWitness,
    )?;
    let threshold = u64_source_bits(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.threshold_u64be"),
        opening.threshold,
        QirByteSourceKind::PrivateWitness,
    )?;
    let signer_count = u64_source_bits(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.signer_count_u64be"),
        opening.signer_count,
        QirByteSourceKind::PrivateWitness,
    )?;
    let approval_count = u64_source_bits(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.approval_count_u64be"),
        opening.approval_count,
        QirByteSourceKind::PrivateWitness,
    )?;
    let approved_bytes = opening.approved_slots.map(u8::from);
    let approved_bits = ensure_symbol_bytes(
        witness_values,
        shake_constraints,
        index,
        &format!("{symbol}.approved_slots"),
        &approved_bytes,
        QirByteSourceKind::PrivateWitness,
    )?;
    let approved = core::array::from_fn(|slot| approved_bits[slot * 8]);
    let mut all = Vec::new();
    all.extend(&policy_root);
    all.extend(&intent);
    all.extend(&threshold);
    all.extend(&signer_count);
    all.extend(&approval_count);
    all.extend(&approved_bits);
    Ok(AccumulatorQirWires {
        policy_root,
        intent,
        threshold,
        signer_count,
        approval_count,
        approved,
        approved_byte_bits: approved_bits,
        all,
    })
}

fn constrain_accumulator_structure(
    builder: &mut R1csBuilder<'_>,
    prefix: &str,
    gate: Shake256Wire,
    opening: &AccumulatorQirWires,
    signer_tags: &[Vec<Shake256Wire>; MAX_SIGNERS],
    seven_bits: &[Shake256Wire],
    signer_slot_constants: &[Vec<Shake256Wire>; MAX_SIGNERS],
) {
    let zero = builder.zero;
    let threshold_nonzero =
        builder.any_bits(&format!("{prefix}.threshold_nonzero"), &opening.threshold);
    builder.imply(
        &format!("{prefix}.threshold_nonzero.assert"),
        gate,
        threshold_nonzero,
    );
    let signer_nonzero = builder.any_bits(
        &format!("{prefix}.signer_count_nonzero"),
        &opening.signer_count,
    );
    builder.imply(
        &format!("{prefix}.signer_count_nonzero.assert"),
        gate,
        signer_nonzero,
    );
    let signer_below_seven = builder.less_than_bits(
        &format!("{prefix}.signer_count_below_seven"),
        &opening.signer_count,
        seven_bits,
    );
    builder.imply(
        &format!("{prefix}.signer_count_below_seven.assert"),
        gate,
        signer_below_seven,
    );
    let signer_below_threshold = builder.less_than_bits(
        &format!("{prefix}.signer_below_threshold"),
        &opening.signer_count,
        &opening.threshold,
    );
    builder.assert_eq_if(
        &format!("{prefix}.threshold_at_most_signers"),
        gate,
        signer_below_threshold,
        zero,
    );
    let signer_below_approvals = builder.less_than_bits(
        &format!("{prefix}.signer_below_approvals"),
        &opening.signer_count,
        &opening.approval_count,
    );
    builder.assert_eq_if(
        &format!("{prefix}.approvals_at_most_signers"),
        gate,
        signer_below_approvals,
        zero,
    );
    nonzero_if(
        builder,
        &format!("{prefix}.intent_nonzero"),
        gate,
        &opening.intent,
    );

    let mut approval_sum = QirLinearCombination::constant(0);
    for approved in opening.approved {
        approval_sum = approval_sum.plus_wire(approved, 1);
    }
    let mut coefficient = 1u64;
    for bit in &opening.approval_count {
        approval_sum = approval_sum.plus_wire(*bit, GOLDILOCKS_MODULUS - coefficient);
        coefficient = ((u128::from(coefficient) * 2) % u128::from(GOLDILOCKS_MODULUS)) as u64;
    }
    let family = builder.family;
    builder.constraints.push(QirR1csConstraint {
        name: format!("{prefix}.approval_count_matches_slots"),
        family,
        left: QirLinearCombination::wire(gate),
        right: approval_sum,
        output: QirLinearCombination::constant(0),
    });

    let mut active_slots = Vec::with_capacity(MAX_SIGNERS);
    for slot in 0..MAX_SIGNERS {
        let active = builder.less_than_bits(
            &format!("{prefix}.slot[{slot}].active"),
            &signer_slot_constants[slot],
            &opening.signer_count,
        );
        active_slots.push(active);
        let gated_active =
            builder.and(&format!("{prefix}.slot[{slot}].gated_active"), gate, active);
        nonzero_if(
            builder,
            &format!("{prefix}.slot[{slot}].tag_nonzero"),
            gated_active,
            &signer_tags[slot],
        );
        let inactive = builder.not(&format!("{prefix}.slot[{slot}].inactive"), active);
        let gated_inactive = builder.and(
            &format!("{prefix}.slot[{slot}].gated_inactive"),
            gate,
            inactive,
        );
        zero_if(
            builder,
            &format!("{prefix}.slot[{slot}].tag_zero"),
            gated_inactive,
            &signer_tags[slot],
        );
        builder.assert_eq_if(
            &format!("{prefix}.slot[{slot}].approved_zero"),
            gated_inactive,
            opening.approved[slot],
            zero,
        );
    }
    for left in 0..MAX_SIGNERS {
        for right in left + 1..MAX_SIGNERS {
            let both_active = builder.and(
                &format!("{prefix}.distinct[{left},{right}].both_active"),
                active_slots[left],
                active_slots[right],
            );
            let gated = builder.and(
                &format!("{prefix}.distinct[{left},{right}].gated"),
                gate,
                both_active,
            );
            let equal = builder.equals_bits(
                &format!("{prefix}.distinct[{left},{right}].equal"),
                &signer_tags[left],
                &signer_tags[right],
            );
            builder.assert_eq_if(
                &format!("{prefix}.distinct[{left},{right}].reject"),
                gated,
                equal,
                zero,
            );
        }
    }
}

impl<'a> R1csBuilder<'a> {
    fn new(witness: &'a mut Vec<u64>, constraints: &'a mut Vec<QirR1csConstraint>) -> Self {
        let zero = Shake256Wire::from_index(witness.len());
        witness.push(0);
        let one = Shake256Wire::from_index(witness.len());
        witness.push(1);
        let mut builder = Self {
            witness,
            constraints,
            counter: 0,
            family: QirConstraintFamily::CanonicalEncoding,
            zero,
            one,
        };
        builder.assert_constant("r1cs.constant.zero", zero, 0);
        builder.assert_constant("r1cs.constant.one", one, 1);
        builder
    }

    fn unique(&mut self, prefix: &str) -> String {
        let name = format!("{prefix}#{}", self.counter);
        self.counter += 1;
        name
    }

    fn set_family(&mut self, family: QirConstraintFamily) {
        self.family = family;
    }

    fn value(&self, wire: Shake256Wire) -> bool {
        self.witness[wire.index()] == 1
    }

    fn alloc(&mut self, value: u64) -> Shake256Wire {
        let wire = Shake256Wire::from_index(self.witness.len());
        self.witness.push(value);
        wire
    }

    fn alloc_bit(&mut self, prefix: &str, value: bool) -> Shake256Wire {
        let wire = self.alloc(u64::from(value));
        let name = self.unique(&format!("{prefix}.boolean"));
        let family = self.family;
        self.constraints.push(QirR1csConstraint {
            name,
            family,
            left: QirLinearCombination::wire(wire),
            right: QirLinearCombination::wire(wire).plus_wire(self.one, GOLDILOCKS_MODULUS - 1),
            output: QirLinearCombination::constant(0),
        });
        wire
    }

    fn assert_constant(&mut self, name: &str, wire: Shake256Wire, value: u64) {
        let family = self.family;
        self.constraints.push(QirR1csConstraint {
            name: name.to_owned(),
            family,
            left: QirLinearCombination::wire(wire)
                .plus_wire(self.one, GOLDILOCKS_MODULUS - (value % GOLDILOCKS_MODULUS)),
            right: QirLinearCombination::wire(self.one),
            output: QirLinearCombination::constant(0),
        });
    }

    fn assert_eq(&mut self, name: &str, left: Shake256Wire, right: Shake256Wire) {
        let family = self.family;
        self.constraints.push(QirR1csConstraint {
            name: name.to_owned(),
            family,
            left: QirLinearCombination::wire(left).minus_wire(right),
            right: QirLinearCombination::wire(self.one),
            output: QirLinearCombination::constant(0),
        });
    }

    fn assert_eq_if(
        &mut self,
        name: &str,
        selector: Shake256Wire,
        left: Shake256Wire,
        right: Shake256Wire,
    ) {
        let family = self.family;
        self.constraints.push(QirR1csConstraint {
            name: name.to_owned(),
            family,
            left: QirLinearCombination::wire(selector),
            right: QirLinearCombination::wire(left).minus_wire(right),
            output: QirLinearCombination::constant(0),
        });
    }

    fn assert_linear_zero(&mut self, name: &str, expression: QirLinearCombination) {
        let family = self.family;
        self.constraints.push(QirR1csConstraint {
            name: name.to_owned(),
            family,
            left: expression,
            right: QirLinearCombination::wire(self.one),
            output: QirLinearCombination::constant(0),
        });
    }

    fn assert_true(&mut self, name: &str, bit: Shake256Wire) {
        self.assert_eq(name, bit, self.one);
    }

    fn assert_false(&mut self, name: &str, bit: Shake256Wire) {
        self.assert_eq(name, bit, self.zero);
    }

    fn imply(&mut self, name: &str, premise: Shake256Wire, conclusion: Shake256Wire) {
        self.assert_eq_if(name, premise, conclusion, self.one);
    }

    fn not(&mut self, prefix: &str, input: Shake256Wire) -> Shake256Wire {
        let output = self.alloc_bit(prefix, !self.value(input));
        let name = self.unique(&format!("{prefix}.not"));
        let family = self.family;
        self.constraints.push(QirR1csConstraint {
            name,
            family,
            left: QirLinearCombination::wire(input)
                .plus_wire(output, 1)
                .minus_wire(self.one),
            right: QirLinearCombination::wire(self.one),
            output: QirLinearCombination::constant(0),
        });
        output
    }

    fn and(&mut self, prefix: &str, left: Shake256Wire, right: Shake256Wire) -> Shake256Wire {
        let output = self.alloc_bit(prefix, self.value(left) & self.value(right));
        let name = self.unique(&format!("{prefix}.and"));
        let family = self.family;
        self.constraints.push(QirR1csConstraint {
            name,
            family,
            left: QirLinearCombination::wire(left),
            right: QirLinearCombination::wire(right),
            output: QirLinearCombination::wire(output),
        });
        output
    }

    fn or(&mut self, prefix: &str, left: Shake256Wire, right: Shake256Wire) -> Shake256Wire {
        let product = self.and(&format!("{prefix}.product"), left, right);
        let output = self.alloc_bit(prefix, self.value(left) | self.value(right));
        let name = self.unique(&format!("{prefix}.or"));
        let family = self.family;
        self.constraints.push(QirR1csConstraint {
            name,
            family,
            left: QirLinearCombination::wire(left)
                .plus_wire(right, 1)
                .minus_wire(product)
                .minus_wire(output),
            right: QirLinearCombination::wire(self.one),
            output: QirLinearCombination::constant(0),
        });
        output
    }

    fn xor(&mut self, prefix: &str, left: Shake256Wire, right: Shake256Wire) -> Shake256Wire {
        let product = self.and(&format!("{prefix}.product"), left, right);
        let output = self.alloc_bit(prefix, self.value(left) ^ self.value(right));
        let name = self.unique(&format!("{prefix}.xor"));
        let family = self.family;
        self.constraints.push(QirR1csConstraint {
            name,
            family,
            left: QirLinearCombination::wire(left)
                .plus_wire(right, 1)
                .plus_wire(product, GOLDILOCKS_MODULUS - 2)
                .minus_wire(output),
            right: QirLinearCombination::wire(self.one),
            output: QirLinearCombination::constant(0),
        });
        output
    }

    fn select(
        &mut self,
        prefix: &str,
        selector: Shake256Wire,
        when_true: Shake256Wire,
        when_false: Shake256Wire,
    ) -> Shake256Wire {
        let value = if self.value(selector) {
            self.value(when_true)
        } else {
            self.value(when_false)
        };
        let output = self.alloc_bit(prefix, value);
        let name = self.unique(&format!("{prefix}.select"));
        let family = self.family;
        self.constraints.push(QirR1csConstraint {
            name,
            family,
            left: QirLinearCombination::wire(selector),
            right: QirLinearCombination::wire(when_true).minus_wire(when_false),
            output: QirLinearCombination::wire(output).minus_wire(when_false),
        });
        output
    }

    fn equals_bits(
        &mut self,
        prefix: &str,
        left: &[Shake256Wire],
        right: &[Shake256Wire],
    ) -> Shake256Wire {
        debug_assert_eq!(left.len(), right.len());
        let mut equal = self.one;
        for (index, (left, right)) in left.iter().copied().zip(right.iter().copied()).enumerate() {
            let different = self.xor(&format!("{prefix}.bit[{index}].different"), left, right);
            let same = self.not(&format!("{prefix}.bit[{index}].same"), different);
            equal = self.and(&format!("{prefix}.through[{index}]"), equal, same);
        }
        equal
    }

    fn any_bits(&mut self, prefix: &str, bits: &[Shake256Wire]) -> Shake256Wire {
        bits.iter()
            .copied()
            .enumerate()
            .fold(self.zero, |any, (index, bit)| {
                self.or(&format!("{prefix}.through[{index}]"), any, bit)
            })
    }

    fn less_than_bits(
        &mut self,
        prefix: &str,
        left_le: &[Shake256Wire],
        right_le: &[Shake256Wire],
    ) -> Shake256Wire {
        debug_assert_eq!(left_le.len(), right_le.len());
        let mut equal = self.one;
        let mut less = self.zero;
        for index in (0..left_le.len()).rev() {
            let not_left = self.not(&format!("{prefix}.bit[{index}].not_left"), left_le[index]);
            let left_zero_right_one = self.and(
                &format!("{prefix}.bit[{index}].zero_one"),
                not_left,
                right_le[index],
            );
            let newly_less = self.and(
                &format!("{prefix}.bit[{index}].new_less"),
                equal,
                left_zero_right_one,
            );
            less = self.or(&format!("{prefix}.bit[{index}].less"), less, newly_less);
            let different = self.xor(
                &format!("{prefix}.bit[{index}].different"),
                left_le[index],
                right_le[index],
            );
            let same = self.not(&format!("{prefix}.bit[{index}].same"), different);
            equal = self.and(&format!("{prefix}.bit[{index}].equal"), equal, same);
        }
        less
    }

    fn add_bits(
        &mut self,
        prefix: &str,
        left: &[Shake256Wire],
        right: &[Shake256Wire],
    ) -> Vec<Shake256Wire> {
        debug_assert_eq!(left.len(), right.len());
        let mut carry = self.zero;
        let mut output = Vec::with_capacity(left.len() + 1);
        for index in 0..left.len() {
            let partial = self.xor(
                &format!("{prefix}.bit[{index}].partial"),
                left[index],
                right[index],
            );
            let sum = self.xor(&format!("{prefix}.bit[{index}].sum"), partial, carry);
            let left_right = self.and(
                &format!("{prefix}.bit[{index}].left_right"),
                left[index],
                right[index],
            );
            let carry_partial = self.and(
                &format!("{prefix}.bit[{index}].carry_partial"),
                carry,
                partial,
            );
            carry = self.or(
                &format!("{prefix}.bit[{index}].carry"),
                left_right,
                carry_partial,
            );
            output.push(sum);
        }
        output.push(carry);
        output
    }
}

type QirSourceWireKey = (QirByteSourceKind, String, usize, usize);

fn allocate_qir_source_byte_bits(
    source: &QirByteSource,
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_by_key: &mut BTreeMap<QirSourceWireKey, Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
) -> Result<Vec<Shake256Wire>, FullShake448RelationError> {
    let mut wires = Vec::with_capacity(8);
    for bit_index in 0..8 {
        let key = (
            source.kind,
            source.symbol.clone(),
            source.byte_index,
            bit_index,
        );
        let value = ((source.value >> bit_index) & 1) != 0;
        let wire = if let Some(wire) = source_wire_by_key.get(&key).copied() {
            if witness[wire.index()] != u64::from(value) {
                return Err(FullShake448RelationError::SourceSymbolConflict {
                    symbol: source.symbol.clone(),
                    byte_index: source.byte_index,
                });
            }
            wire
        } else {
            let wire = Shake256Wire::from_index(witness.len());
            witness.push(u64::from(value));
            constraints.push(match source.kind {
                QirByteSourceKind::Constant => Shake256Constraint::Constant {
                    output: wire,
                    value,
                },
                QirByteSourceKind::CanonicalStatement => Shake256Constraint::PublicBoolean { wire },
                QirByteSourceKind::PrivateWitness | QirByteSourceKind::InternalDigest => {
                    Shake256Constraint::Boolean { wire }
                }
            });
            source_wire_by_key.insert(key, wire);
            source_bit_wires
                .entry(source.symbol.clone())
                .or_default()
                .push(wire);
            wire
        };
        let untyped_key = (source.symbol.clone(), source.byte_index, bit_index);
        if let Some(previous) = source_wire_index.insert(untyped_key, wire) {
            if previous != wire {
                return Err(FullShake448RelationError::SourceSymbolConflict {
                    symbol: source.symbol.clone(),
                    byte_index: source.byte_index,
                });
            }
        }
        wires.push(wire);
    }
    Ok(wires)
}

fn allocate_qir_digest_target_bits(
    instance: &QirHashInstance,
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_by_key: &mut BTreeMap<QirSourceWireKey, Shake256Wire>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
) -> Result<Vec<Shake256Wire>, FullShake448RelationError> {
    let mut digest_targets = Vec::with_capacity(instance.output_assignment.len() * 8);
    for (byte_index, byte) in instance.output_assignment.iter().copied().enumerate() {
        for bit_index in 0..8 {
            let value = (byte >> bit_index) & 1;
            let key = (
                QirByteSourceKind::InternalDigest,
                instance.output_symbol.clone(),
                byte_index,
                bit_index,
            );
            let wire = if let Some(wire) = source_wire_by_key.get(&key).copied() {
                if witness[wire.index()] != u64::from(value) {
                    return Err(FullShake448RelationError::SourceSymbolConflict {
                        symbol: instance.output_symbol.clone(),
                        byte_index,
                    });
                }
                wire
            } else {
                let wire = Shake256Wire::from_index(witness.len());
                witness.push(u64::from(value));
                constraints.push(Shake256Constraint::Boolean { wire });
                source_wire_by_key.insert(key, wire);
                wire
            };
            let untyped_key = (instance.output_symbol.clone(), byte_index, bit_index);
            if let Some(previous) = source_wire_index.insert(untyped_key, wire) {
                if previous != wire {
                    return Err(FullShake448RelationError::SourceSymbolConflict {
                        symbol: instance.output_symbol.clone(),
                        byte_index,
                    });
                }
            }
            digest_targets.push(wire);
        }
    }
    Ok(digest_targets)
}

fn allocate_authorization_mode_source_wires(
    selectors: [bool; AUTHORIZATION_MODE_COUNT],
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_by_key: &mut BTreeMap<QirSourceWireKey, Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
) -> Result<[Shake256Wire; AUTHORIZATION_MODE_COUNT], FullShake448RelationError> {
    let mut selector_wires = Vec::with_capacity(AUTHORIZATION_MODE_COUNT);
    for (mode, selected) in selectors.into_iter().enumerate() {
        let source = QirByteSource {
            kind: QirByteSourceKind::PrivateWitness,
            symbol: "authorization.mode_selectors".to_owned(),
            byte_index: mode,
            value: u8::from(selected),
        };
        let wires = allocate_qir_source_byte_bits(
            &source,
            witness,
            constraints,
            source_wire_by_key,
            source_bit_wires,
            source_wire_index,
        )?;
        selector_wires.push(wires[0]);
        for bit_index in 1..8 {
            constraints.push(Shake256Constraint::Constant {
                output: wires[bit_index],
                value: false,
            });
        }
    }
    selector_wires
        .try_into()
        .map_err(|_| FullShake448RelationError::QirProgramShape)
}

impl FullShake448QirInstance {
    pub fn materialize_hash(
        &self,
        index: usize,
    ) -> Result<MaterializedQirHashTrace, FullShake448RelationError> {
        let instance = self
            .hash_instances
            .get(index)
            .ok_or(FullShake448RelationError::HashSlot(index))?;
        if let Some(mux) = &instance.authorization_mux {
            let frames = [
                mux.arms[0].frame.as_slice(),
                mux.arms[1].frame.as_slice(),
                mux.arms[2].frame.as_slice(),
                mux.arms[3].frame.as_slice(),
                mux.arms[4].frame.as_slice(),
            ];
            let trace = fixed_authorization_mux_relation(mux.slot, mux.mode_selectors, frames)?;
            if trace.permutations().len() != instance.slot.permutations {
                return Err(FullShake448RelationError::HashGeometry {
                    name: instance.slot.name.clone(),
                    expected_frame_max: instance.slot.maximum_frame_bytes,
                    actual_frame: mux
                        .arms
                        .iter()
                        .map(|arm| arm.frame.len())
                        .max()
                        .unwrap_or(0),
                    expected_permutations: instance.slot.permutations,
                    actual_permutations: trace.permutations().len(),
                });
            }
            trace.verify_constraints()?;
            if trace.digest() != instance.output_assignment {
                return Err(FullShake448RelationError::TraceAssignment(
                    instance.slot.name.clone(),
                ));
            }
            return Ok(MaterializedQirHashTrace::FixedAuthorization(trace));
        }
        let trace = shake256_relation(&instance.frame, instance.slot.output_bytes)?;
        if trace.permutations().len() != instance.slot.permutations {
            return Err(FullShake448RelationError::HashGeometry {
                name: instance.slot.name.clone(),
                expected_frame_max: instance.slot.maximum_frame_bytes,
                actual_frame: instance.frame.len(),
                expected_permutations: instance.slot.permutations,
                actual_permutations: trace.permutations().len(),
            });
        }
        trace.verify_constraints()?;
        if trace.digest() != instance.output_assignment {
            return Err(FullShake448RelationError::TraceAssignment(
                instance.slot.name.clone(),
            ));
        }
        Ok(MaterializedQirHashTrace::Ordinary(trace))
    }

    pub fn verify_source_coverage(&self) -> Result<(), FullShake448RelationError> {
        for instance in &self.hash_instances {
            if let Some(mux) = &instance.authorization_mux {
                let selected_mode = mux
                    .mode_selectors
                    .iter()
                    .position(|selected| *selected)
                    .ok_or(FullShake448RelationError::FrameSourceCoverage(
                        instance.slot.name.clone(),
                    ))?;
                if mux
                    .mode_selectors
                    .iter()
                    .enumerate()
                    .any(|(mode, selected)| mode != selected_mode && *selected)
                    || instance.frame != mux.arms[selected_mode].frame
                    || instance.frame_sources != mux.arms[selected_mode].frame_sources
                {
                    return Err(FullShake448RelationError::FrameSourceCoverage(
                        instance.slot.name.clone(),
                    ));
                }
                for arm in &mux.arms {
                    let dummy = arm.frame.len() == SHAKE256_RATE_BYTES
                        && arm.frame.iter().all(|byte| *byte == 0);
                    if (dummy && !arm.frame_sources.is_empty())
                        || (!dummy && arm.frame.len() != arm.frame_sources.len())
                        || arm
                            .frame
                            .iter()
                            .zip(&arm.frame_sources)
                            .any(|(byte, source)| *byte != source.value || source.symbol.is_empty())
                    {
                        return Err(FullShake448RelationError::FrameSourceCoverage(
                            instance.slot.name.clone(),
                        ));
                    }
                }
                continue;
            }
            if instance.frame.len() != instance.frame_sources.len() {
                return Err(FullShake448RelationError::FrameSourceCoverage(
                    instance.slot.name.clone(),
                ));
            }
            for (byte, source) in instance.frame.iter().zip(&instance.frame_sources) {
                if *byte != source.value || source.symbol.is_empty() {
                    return Err(FullShake448RelationError::FrameSourceCoverage(
                        instance.slot.name.clone(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Materialize all SHAKE traces into one aggregate polynomial system.  Every
    /// message bit is equality-linked to one typed source wire, and every digest
    /// bit is equality-linked to one stable symbolic output wire.  Repeated
    /// `(kind, symbol, byte_index, bit_index)` sources reuse the exact same wire.
    /// Non-hash lowering consumes these maps to implement selectors, balances,
    /// ranges, authorization transitions, and public-statement equalities.
    pub fn materialize_hash_constraint_system(
        &self,
    ) -> Result<FullShake448HashConstraintSystem, FullShake448RelationError> {
        validate_v6_successor_hash_registry()?;
        self.verify_source_coverage()?;
        let mut witness = Vec::new();
        let mut constraints = Vec::new();
        let mut source_wire_by_key: BTreeMap<
            (QirByteSourceKind, String, usize, usize),
            Shake256Wire,
        > = BTreeMap::new();
        let mut source_bit_wires: BTreeMap<String, Vec<Shake256Wire>> = BTreeMap::new();
        let mut source_wire_index = BTreeMap::new();
        let mut output_bit_wires = BTreeMap::new();
        let mut invocation_coverages =
            Vec::with_capacity(self.hash_instances.len().saturating_sub(2));
        let mut authorization_mux_coverages = Vec::with_capacity(2);
        let mut hash_invocation_coverages = Vec::with_capacity(self.hash_instances.len());

        // The raw 893 bytes are the sole public authority.  Allocate one
        // canonical public bit wire for every byte before any trace is added;
        // all statement-fed frames and non-hash constraints reuse these wires.
        for (byte_index, byte) in self.statement_bytes.iter().copied().enumerate() {
            for bit_index in 0..8 {
                let wire = Shake256Wire::from_index(witness.len());
                witness.push(u64::from((byte >> bit_index) & 1));
                constraints.push(Shake256Constraint::PublicBoolean { wire });
                source_wire_by_key.insert(
                    (
                        QirByteSourceKind::CanonicalStatement,
                        "statement.bytes".to_owned(),
                        byte_index,
                        bit_index,
                    ),
                    wire,
                );
                source_wire_index
                    .insert(("statement.bytes".to_owned(), byte_index, bit_index), wire);
                source_bit_wires
                    .entry("statement.bytes".to_owned())
                    .or_default()
                    .push(wire);
            }
        }

        for instance in &self.hash_instances {
            let digest_targets = allocate_qir_digest_target_bits(
                instance,
                &mut witness,
                &mut constraints,
                &mut source_wire_by_key,
                &mut source_wire_index,
            )?;
            if let Some(mux) = &instance.authorization_mux {
                let frames = [
                    mux.arms[0].frame.as_slice(),
                    mux.arms[1].frame.as_slice(),
                    mux.arms[2].frame.as_slice(),
                    mux.arms[3].frame.as_slice(),
                    mux.arms[4].frame.as_slice(),
                ];
                let trace = fixed_authorization_mux_relation(mux.slot, mux.mode_selectors, frames)?;
                let mut embedding = trace.append_to(&mut witness, &mut constraints)?;
                let selector_sources = allocate_authorization_mode_source_wires(
                    mux.mode_selectors,
                    &mut witness,
                    &mut constraints,
                    &mut source_wire_by_key,
                    &mut source_bit_wires,
                    &mut source_wire_index,
                )?;
                embedding.bind_selector_sources(&selector_sources, &mut constraints)?;
                for (mode, arm) in mux.arms.iter().enumerate() {
                    let mut arm_sources = Vec::with_capacity(arm.frame_sources.len() * 8);
                    for source in &arm.frame_sources {
                        arm_sources.extend(allocate_qir_source_byte_bits(
                            source,
                            &mut witness,
                            &mut constraints,
                            &mut source_wire_by_key,
                            &mut source_bit_wires,
                            &mut source_wire_index,
                        )?);
                    }
                    embedding.bind_arm_sources(mode, &arm_sources, &mut constraints)?;
                }
                embedding.bind_digest_targets(&digest_targets, &mut constraints)?;
                embedding.ensure_fully_bound()?;
                authorization_mux_coverages.push(embedding.binding_coverage());
            } else {
                let trace = shake256_relation(&instance.frame, instance.slot.output_bytes)?;
                let mut embedding = trace.append_to(&mut witness, &mut constraints)?;
                let mut message_sources = Vec::with_capacity(instance.frame.len() * 8);
                for source in &instance.frame_sources {
                    message_sources.extend(allocate_qir_source_byte_bits(
                        source,
                        &mut witness,
                        &mut constraints,
                        &mut source_wire_by_key,
                        &mut source_bit_wires,
                        &mut source_wire_index,
                    )?);
                }
                embedding.bind_message_sources(&message_sources, &mut constraints)?;
                embedding.bind_digest_targets(&digest_targets, &mut constraints)?;
                embedding.ensure_fully_bound()?;
                invocation_coverages.push(embedding.binding_coverage());
            }
            let required = v6_successor_profile_for_hash_slot(instance.slot.index)
                .ok_or(FullShake448RelationError::SuccessorHashRegistry)?;
            hash_invocation_coverages.push(V6HashInvocationCoverage {
                slot: instance.slot.index,
                name: instance.slot.name.clone(),
                registry_role: required.role,
                security_purpose: required.purpose,
                required_algorithm: required.algorithm,
                required_rate_bytes: usize::from(required.rate_bytes),
                required_permutations: usize::from(required.permutations_per_call),
                lowered_algorithm: V6SemanticHashAlgorithm::Shake256Output448,
                lowered_rate_bytes: SHAKE256_RATE_BYTES,
                lowered_permutations: instance.slot.permutations,
                fully_bound: true,
            });
            output_bit_wires.insert(instance.output_symbol.clone(), digest_targets);
        }

        let system = FullShake448HashConstraintSystem {
            witness,
            constraints,
            source_bit_wires,
            source_wire_index,
            output_bit_wires,
            invocation_coverages,
            authorization_mux_coverages,
            hash_invocation_coverages,
        };
        system.verify_rejected_uniform_sha256()?;
        Ok(system)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelationStats {
    pub active_inputs: usize,
    pub active_outputs: usize,
    /// Actual geometry of the retained, rejected uniform-SHAKE256 oracle.
    pub hash_invocations: usize,
    pub keccak_permutations: usize,
    /// Required geometry of the mixed SHAKE512/SHAKE256 successor registry.
    pub successor_hash_invocations: usize,
    pub successor_keccak_permutations: usize,
    pub successor_registry_digest: [u8; 64],
    pub successor_hash_relation_compiled: bool,
    pub public_values: usize,
    pub production_authorized: bool,
}

#[derive(Clone, Debug)]
pub struct ValidatedFullShake448Relation {
    pub statement: FullShake448Statement,
    pub witness: FullShake448Witness,
    pub qir: FullShake448QirInstance,
    pub stats: RelationStats,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FullShake448RelationError {
    #[error(transparent)]
    Statement(#[from] FullShake448StatementError),
    #[error(transparent)]
    Shake(#[from] Shake256RelationError),
    #[error("statement activation does not equal the verifier's expected V6 activation")]
    ActivationBinding,
    #[error("relation shape violation: {0}")]
    Shape(&'static str),
    #[error("inactive {role} slot {index} contains non-canonical private or public data")]
    InactivePayload { index: usize, role: &'static str },
    #[error("public field mismatch: {0}")]
    PublicMismatch(&'static str),
    #[error("value is outside its canonical range: {0}")]
    ValueOutOfRange(&'static str),
    #[error("signed magnitude is non-canonical")]
    NonCanonicalSignedMagnitude,
    #[error("the four asset slots are not canonical")]
    InvalidAssetSlots,
    #[error("{role} {index} does not select exactly its canonical asset slot")]
    AssetSelector { index: usize, role: &'static str },
    #[error("required digest is zero: {0}")]
    ZeroDigest(&'static str),
    #[error("the two active nullifiers are equal")]
    DuplicateNullifier,
    #[error("input {0} does not authenticate to the public Merkle anchor")]
    Membership(usize),
    #[error("input {0} authorization key does not match its note opening")]
    Authorization(usize),
    #[error("asset {0} does not balance")]
    Balance(u64),
    #[error("stablecoin binding is invalid: {0}")]
    Stablecoin(&'static str),
    #[error("private authorization transition is invalid: {0}")]
    PrivateAuthorization(&'static str),
    #[error("ciphertext slot {0} is not the exact fixed canonical width")]
    CiphertextSize(usize),
    #[error(
        "mixed-capacity successor hash registry is not the exact 79-call/145-permutation schedule"
    )]
    SuccessorHashRegistry,
    #[error("mixed 79-call/145-permutation successor hash relation is not compiled")]
    SuccessorHashRelationUnavailable,
    #[error(
        "HGF6HR02 names a non-FIPS rate-72 SHAKE512 XOF and is not conventional-hash authority"
    )]
    NonConventionalHashRegistry,
    #[error(
        "rejected uniform-SHAKE256 QIR does not have its exact 79-call/124-permutation geometry"
    )]
    QirProgramShape,
    #[error("QIR contains a duplicate named hash or scalar constraint")]
    DuplicateQirName,
    #[error("QIR hash slot {0} does not exist")]
    HashSlot(usize),
    #[error(
        "QIR hash {name} has frame {actual_frame}/{expected_frame_max} bytes and {actual_permutations}/{expected_permutations} permutations"
    )]
    HashGeometry {
        name: String,
        expected_frame_max: usize,
        actual_frame: usize,
        expected_permutations: usize,
        actual_permutations: usize,
    },
    #[error("QIR hash trace output assignment differs at {0}")]
    TraceAssignment(String),
    #[error("QIR SHAKE frame lacks exact typed byte-source coverage at {0}")]
    FrameSourceCoverage(String),
    #[error("typed SHAKE source {symbol}[{byte_index}] has conflicting assignments")]
    SourceSymbolConflict { symbol: String, byte_index: usize },
    #[error("non-hash wire {wire} is outside witness length {witness_len}")]
    NonHashWireOutOfBounds { wire: usize, witness_len: usize },
    #[error("non-hash constraint {index} ({name}) failed with residual {residual}")]
    NonHashConstraintViolation {
        index: usize,
        name: String,
        residual: u64,
    },
    #[error("executable QIR constraint-family coverage does not match its declared map")]
    ConstraintFamilyCoverage,
    #[error("required executable QIR constraint family {0:?} is absent")]
    MissingConstraintFamily(QirConstraintFamily),
    #[error("the full V6 relation is intentionally not production-authorized")]
    ProductionAuthorizationUnavailable,
}

/// Production remains fail-closed until this QIR is lowered into the repaired complete-ZK
/// SmallWood engine and all security, refinement, mutation, restart, and release gates pass.
pub fn ensure_full_shake448_relation_production_authorized() -> Result<(), FullShake448RelationError>
{
    Err(FullShake448RelationError::ProductionAuthorizationUnavailable)
}

fn constant_sources(symbol: &str, bytes: &[u8]) -> Vec<QirByteSource> {
    bytes
        .iter()
        .copied()
        .enumerate()
        .map(|(byte_index, value)| QirByteSource {
            kind: QirByteSourceKind::Constant,
            symbol: symbol.to_owned(),
            byte_index,
            value,
        })
        .collect()
}

fn sourced_semantic_frame(
    role: [u8; 8],
    fields: Vec<SourcedField>,
) -> Result<SourcedFrame, FullShake448RelationError> {
    let field_views = fields
        .iter()
        .map(|field| field.bytes.as_slice())
        .collect::<Vec<_>>();
    let bytes = encode_v6_semantic_frame(role, field_views.iter().copied())?;
    let mut sources = Vec::with_capacity(bytes.len());
    sources.extend(constant_sources("domain.profile", &bytes[..8]));
    sources.extend(constant_sources("domain.role", &bytes[8..16]));
    sources.push(QirByteSource {
        kind: QirByteSourceKind::Constant,
        symbol: "frame.field_count".to_owned(),
        byte_index: 0,
        value: bytes[16],
    });
    for (field_index, field) in fields.iter().enumerate() {
        let length = (field.bytes.len() as u16).to_be_bytes();
        sources.extend(
            length
                .iter()
                .copied()
                .enumerate()
                .map(|(byte_index, value)| QirByteSource {
                    kind: QirByteSourceKind::Constant,
                    symbol: format!("frame.field[{field_index}].length_u16be"),
                    byte_index,
                    value,
                }),
        );
        sources.extend(
            field
                .bytes
                .iter()
                .copied()
                .zip(field.byte_indices.iter().copied())
                .map(|(value, byte_index)| QirByteSource {
                    kind: field.kind,
                    symbol: field.symbol.clone(),
                    byte_index,
                    value,
                }),
        );
    }
    if sources.len() != bytes.len()
        || sources
            .iter()
            .zip(&bytes)
            .any(|(source, byte)| source.value != *byte)
    {
        return Err(FullShake448RelationError::QirProgramShape);
    }
    Ok(SourcedFrame { bytes, sources })
}

fn note_frame(symbol: &str, note: &NoteOpening) -> Result<SourcedFrame, FullShake448RelationError> {
    let kind = [note.kind.tag()];
    sourced_semantic_frame(
        ROLE_NOTE_COMMITMENT,
        vec![
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.kind"),
                &kind,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.value_u64be"),
                &note.value.to_be_bytes(),
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.asset_u64be"),
                &note.asset_id.to_be_bytes(),
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.pk_recipient"),
                &note.pk_recipient,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.rho"),
                &note.rho,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.randomness"),
                &note.randomness,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.pk_auth"),
                &note.pk_auth,
            ),
        ],
    )
}

fn spend_key_frame(
    index: usize,
    spend_key: &[u8; SPEND_KEY_BYTES],
) -> Result<SourcedFrame, FullShake448RelationError> {
    sourced_semantic_frame(
        ROLE_SPEND_KEYS,
        vec![
            SourcedField::contiguous(
                QirByteSourceKind::Constant,
                "domain.key_output_order",
                &KEY_OUTPUT_ORDER_TAG,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("input[{index}].spend_key"),
                spend_key,
            ),
        ],
    )
}

fn nullifier_frame(
    index: usize,
    key: &Digest,
    position: u64,
    rho: &[u8; 48],
) -> Result<SourcedFrame, FullShake448RelationError> {
    sourced_semantic_frame(
        ROLE_NULLIFIER,
        vec![
            SourcedField::contiguous(
                QirByteSourceKind::InternalDigest,
                format!("resolved_nullifier_key[{index}]"),
                key,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("input[{index}].position_u64be"),
                &position.to_be_bytes(),
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("input[{index}].note.rho"),
                rho,
            ),
        ],
    )
}

fn merkle_frame(
    input: usize,
    level: usize,
    left: &Digest,
    right: &Digest,
) -> Result<SourcedFrame, FullShake448RelationError> {
    sourced_semantic_frame(
        ROLE_MERKLE_NODE,
        vec![
            SourcedField::contiguous(
                QirByteSourceKind::InternalDigest,
                format!("merkle.input[{input}].level[{level}].left"),
                left,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::InternalDigest,
                format!("merkle.input[{input}].level[{level}].right"),
                right,
            ),
        ],
    )
}

fn policy_frame(
    opening: &AccumulatorOpening,
    signer_tags: &[Digest; MAX_SIGNERS],
) -> Result<SourcedFrame, FullShake448RelationError> {
    let threshold = opening.threshold.to_be_bytes();
    let signer_count = opening.signer_count.to_be_bytes();
    let mut fields = vec![
        SourcedField::contiguous(
            QirByteSourceKind::PrivateWitness,
            "authorization.selected_policy.threshold_u64be",
            &threshold,
        ),
        SourcedField::contiguous(
            QirByteSourceKind::PrivateWitness,
            "authorization.selected_policy.signer_count_u64be",
            &signer_count,
        ),
    ];
    fields.extend(signer_tags.iter().enumerate().map(|(index, tag)| {
        SourcedField::contiguous(
            QirByteSourceKind::PrivateWitness,
            format!("authorization.signer_tags[{index}]"),
            tag,
        )
    }));
    sourced_semantic_frame(ROLE_POLICY, fields)
}

fn accumulator_frame(
    symbol: &str,
    opening: &AccumulatorOpening,
) -> Result<SourcedFrame, FullShake448RelationError> {
    let approved = opening.approved_slots.map(u8::from);
    sourced_semantic_frame(
        ROLE_ACCUMULATOR,
        vec![
            SourcedField::contiguous(
                QirByteSourceKind::Constant,
                "domain.key_output_order",
                &KEY_OUTPUT_ORDER_TAG,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.policy_root"),
                &opening.policy_root,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.intent_digest"),
                &opening.intent_digest,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.threshold_u64be"),
                &opening.threshold.to_be_bytes(),
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.signer_count_u64be"),
                &opening.signer_count.to_be_bytes(),
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.approval_count_u64be"),
                &opening.approval_count.to_be_bytes(),
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("{symbol}.approved_slots"),
                &approved,
            ),
        ],
    )
}

fn value_lock_frame(
    policy_root: &Digest,
    intent: &Digest,
) -> Result<SourcedFrame, FullShake448RelationError> {
    sourced_semantic_frame(
        ROLE_VALUE_LOCK,
        vec![
            SourcedField::contiguous(
                QirByteSourceKind::Constant,
                "domain.key_output_order",
                &KEY_OUTPUT_ORDER_TAG,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                "authorization.current.policy_root",
                policy_root,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                "authorization.current.intent_digest",
                intent,
            ),
        ],
    )
}

fn statement_for_intent(
    encoded: &[u8; V6_STATEMENT_BYTES],
) -> Result<Vec<u8>, FullShake448RelationError> {
    // Keep magic, grammar, and four activity flags.  Omit exactly the 56-byte
    // anchor and two 56-byte nullifiers; bind every remaining statement byte.
    let mut payload = Vec::with_capacity(725);
    payload.extend_from_slice(&encoded[..14]);
    payload.extend_from_slice(&encoded[182..]);
    if payload.len() != 725 {
        return Err(FullShake448RelationError::QirProgramShape);
    }
    Ok(payload)
}

fn intent_frame(
    encoded: &[u8; V6_STATEMENT_BYTES],
) -> Result<SourcedFrame, FullShake448RelationError> {
    let payload = statement_for_intent(encoded)?;
    let mut indices = (0..14).collect::<Vec<_>>();
    indices.extend(182..V6_STATEMENT_BYTES);
    sourced_semantic_frame(
        ROLE_INTENT,
        vec![SourcedField::indexed(
            QirByteSourceKind::CanonicalStatement,
            "statement.bytes",
            payload,
            indices,
        )],
    )
}

fn balance_tag_frame(
    statement: &FullShake448Statement,
) -> Result<SourcedFrame, FullShake448RelationError> {
    let value_sign = [u8::from(statement.value_balance.negative)];
    let stable_enabled = [u8::from(statement.stablecoin.enabled)];
    let issuance_sign = [u8::from(statement.stablecoin.issuance_delta.negative)];
    let mut assets = [0u8; BALANCE_SLOTS * 8];
    for (index, asset) in statement.balance_asset_ids.iter().enumerate() {
        assets[index * 8..index * 8 + 8].copy_from_slice(&asset.to_be_bytes());
    }
    sourced_semantic_frame(
        ROLE_BALANCE_TAG,
        vec![
            SourcedField::indexed(
                QirByteSourceKind::CanonicalStatement,
                "statement.bytes",
                statement.fee.to_be_bytes().to_vec(),
                (446..454).collect(),
            ),
            SourcedField::indexed(
                QirByteSourceKind::CanonicalStatement,
                "statement.bytes",
                value_sign.to_vec(),
                vec![454],
            ),
            SourcedField::indexed(
                QirByteSourceKind::CanonicalStatement,
                "statement.bytes",
                statement.value_balance.magnitude.to_be_bytes().to_vec(),
                (455..463).collect(),
            ),
            SourcedField::indexed(
                QirByteSourceKind::CanonicalStatement,
                "statement.bytes",
                assets.to_vec(),
                (414..446).collect(),
            ),
            SourcedField::indexed(
                QirByteSourceKind::CanonicalStatement,
                "statement.bytes",
                stable_enabled.to_vec(),
                vec![463],
            ),
            SourcedField::indexed(
                QirByteSourceKind::CanonicalStatement,
                "statement.bytes",
                statement.stablecoin.asset_id.to_be_bytes().to_vec(),
                (464..472).collect(),
            ),
            SourcedField::indexed(
                QirByteSourceKind::CanonicalStatement,
                "statement.bytes",
                issuance_sign.to_vec(),
                vec![476],
            ),
            SourcedField::indexed(
                QirByteSourceKind::CanonicalStatement,
                "statement.bytes",
                statement
                    .stablecoin
                    .issuance_delta
                    .magnitude
                    .to_be_bytes()
                    .to_vec(),
                (477..485).collect(),
            ),
        ],
    )
}

fn ciphertext_frame(
    index: usize,
    ciphertext: &[u8; V6_CANONICAL_CIPHERTEXT_BYTES],
) -> Result<SourcedFrame, FullShake448RelationError> {
    let profile = [V6_PROOF_PROFILE];
    let domain_set = V6_DOMAIN_SET.to_be_bytes();
    let slot = [index as u8];
    let length = (V6_CANONICAL_CIPHERTEXT_BYTES as u32).to_be_bytes();
    let frame = sourced_semantic_frame(
        *b"ct.hash1",
        vec![
            SourcedField::contiguous(QirByteSourceKind::Constant, "ciphertext.profile", &profile),
            SourcedField::contiguous(
                QirByteSourceKind::Constant,
                "ciphertext.domain_set_u16be",
                &domain_set,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::Constant,
                format!("ciphertext.output[{index}].slot"),
                &slot,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::Constant,
                "ciphertext.fixed_length_u32be",
                &length,
            ),
            SourcedField::contiguous(
                QirByteSourceKind::PrivateWitness,
                format!("output[{index}].canonical_ciphertext"),
                ciphertext,
            ),
        ],
    )?;
    let shared = encode_v6_ciphertext_hash_frame(index, ciphertext)?;
    if frame.bytes != shared || frame.bytes.len() != CIPHERTEXT_HASH_FRAME_BYTES {
        return Err(FullShake448RelationError::QirProgramShape);
    }
    Ok(frame)
}

fn dummy_authorization_frame(slot: usize) -> SourcedFrame {
    // This is the inactive arm used by the fixed two-permutation authorization
    // mux.  Its output is never selected.  Exactly 136 bytes force two SHAKE
    // permutations because SHAKE always appends a fresh padded block.
    let bytes = vec![0; SHAKE256_RATE_BYTES];
    let _ = slot;
    SourcedFrame {
        bytes,
        sources: Vec::new(),
    }
}

fn split_kdf(output: &[u8]) -> Result<(Digest, Digest), FullShake448RelationError> {
    if output.len() != DIGEST_BYTES * 2 {
        return Err(FullShake448RelationError::QirProgramShape);
    }
    let mut auth = [0; DIGEST_BYTES];
    let mut nullifier = [0; DIGEST_BYTES];
    auth.copy_from_slice(&output[..DIGEST_BYTES]);
    nullifier.copy_from_slice(&output[DIGEST_BYTES..]);
    Ok((auth, nullifier))
}

fn digest448(output: &[u8]) -> Result<Digest, FullShake448RelationError> {
    output
        .try_into()
        .map_err(|_| FullShake448RelationError::QirProgramShape)
}

fn signed_i128(value: SignedMagnitude) -> Result<i128, FullShake448RelationError> {
    if value.magnitude > V6_MAX_NOTE_VALUE || (value.negative && value.magnitude == 0) {
        return Err(FullShake448RelationError::NonCanonicalSignedMagnitude);
    }
    Ok(if value.negative {
        -i128::from(value.magnitude)
    } else {
        i128::from(value.magnitude)
    })
}

fn validate_activity_shape(
    input_flags: [bool; MAX_INPUTS],
    output_flags: [bool; MAX_OUTPUTS],
) -> Result<(usize, usize), FullShake448RelationError> {
    let active_inputs = input_flags.into_iter().filter(|active| *active).count();
    let active_outputs = output_flags.into_iter().filter(|active| *active).count();
    if active_inputs == 0 && active_outputs == 0 {
        return Err(FullShake448RelationError::Shape(
            "transaction requires at least one active input or output",
        ));
    }
    Ok((active_inputs, active_outputs))
}

fn validate_native_balance_equation(
    inputs: u128,
    outputs: u128,
    fee: u64,
    value_balance: SignedMagnitude,
) -> Result<(), FullShake448RelationError> {
    let signed_value_balance = signed_i128(value_balance)?;
    let inputs = i128::try_from(inputs)
        .map_err(|_| FullShake448RelationError::ValueOutOfRange("native input sum"))?;
    let outputs = i128::try_from(outputs)
        .map_err(|_| FullShake448RelationError::ValueOutOfRange("native output sum"))?;
    let expected_delta = i128::from(fee) - signed_value_balance;
    if inputs - outputs != expected_delta {
        return Err(FullShake448RelationError::Balance(NATIVE_ASSET_ID));
    }
    Ok(())
}

fn compile_hash_slot(
    program: &FullShake448QirProgram,
    instances: &mut [Option<QirHashInstance>],
    index: usize,
    frame: SourcedFrame,
    output_symbol: impl Into<String>,
) -> Result<Vec<u8>, FullShake448RelationError> {
    let slot = program
        .hash_slots
        .get(index)
        .cloned()
        .ok_or(FullShake448RelationError::HashSlot(index))?;
    if frame.bytes.len() != frame.sources.len()
        || frame
            .bytes
            .iter()
            .zip(&frame.sources)
            .any(|(byte, source)| *byte != source.value)
    {
        return Err(FullShake448RelationError::FrameSourceCoverage(slot.name));
    }
    let trace = shake256_relation(&frame.bytes, slot.output_bytes)?;
    let actual_permutations = trace.permutations().len();
    if frame.bytes.len() > slot.maximum_frame_bytes || actual_permutations != slot.permutations {
        return Err(FullShake448RelationError::HashGeometry {
            name: slot.name,
            expected_frame_max: slot.maximum_frame_bytes,
            actual_frame: frame.bytes.len(),
            expected_permutations: slot.permutations,
            actual_permutations,
        });
    }
    trace.verify_constraints()?;
    let output_assignment = trace.digest();
    instances[index] = Some(QirHashInstance {
        output_symbol: output_symbol.into(),
        slot,
        frame: frame.bytes,
        frame_sources: frame.sources,
        output_assignment: output_assignment.clone(),
        authorization_mux: None,
    });
    Ok(output_assignment)
}

fn compile_authorization_mux_slot(
    program: &FullShake448QirProgram,
    instances: &mut [Option<QirHashInstance>],
    index: usize,
    mux_slot: FixedAuthorizationMuxSlot,
    mode_selectors: [bool; AUTHORIZATION_MODE_COUNT],
    arms: [SourcedFrame; AUTHORIZATION_MODE_COUNT],
    output_symbol: impl Into<String>,
) -> Result<Vec<u8>, FullShake448RelationError> {
    let slot = program
        .hash_slots
        .get(index)
        .cloned()
        .ok_or(FullShake448RelationError::HashSlot(index))?;
    let selected_mode = mode_selectors.iter().position(|selected| *selected).ok_or(
        FullShake448RelationError::Shape("authorization mode selector is not one-hot"),
    )?;
    if mode_selectors
        .iter()
        .enumerate()
        .any(|(mode, selected)| mode != selected_mode && *selected)
    {
        return Err(FullShake448RelationError::Shape(
            "authorization mode selector is not one-hot",
        ));
    }

    for arm in &arms {
        let dummy =
            arm.bytes.len() == SHAKE256_RATE_BYTES && arm.bytes.iter().all(|byte| *byte == 0);
        if (!dummy && arm.bytes.len() != arm.sources.len())
            || arm
                .bytes
                .iter()
                .zip(&arm.sources)
                .any(|(byte, source)| *byte != source.value || source.symbol.is_empty())
            || (dummy && !arm.sources.is_empty())
        {
            return Err(FullShake448RelationError::FrameSourceCoverage(
                slot.name.clone(),
            ));
        }
    }

    let frame_refs = [
        arms[0].bytes.as_slice(),
        arms[1].bytes.as_slice(),
        arms[2].bytes.as_slice(),
        arms[3].bytes.as_slice(),
        arms[4].bytes.as_slice(),
    ];
    let trace = fixed_authorization_mux_relation(mux_slot, mode_selectors, frame_refs)?;
    if trace.permutations().len() != slot.permutations
        || trace.digest().len() != slot.output_bytes
        || arms.iter().map(|arm| arm.bytes.len()).max().unwrap_or(0) > slot.maximum_frame_bytes
    {
        return Err(FullShake448RelationError::HashGeometry {
            name: slot.name,
            expected_frame_max: slot.maximum_frame_bytes,
            actual_frame: arms.iter().map(|arm| arm.bytes.len()).max().unwrap_or(0),
            expected_permutations: slot.permutations,
            actual_permutations: trace.permutations().len(),
        });
    }
    trace.verify_constraints()?;
    let output_assignment = trace.digest();
    let selected_frame = arms[selected_mode].bytes.clone();
    let selected_sources = arms[selected_mode].sources.clone();
    let authorization_mux = QirFixedAuthorizationMuxInstance {
        slot: mux_slot,
        mode_selectors,
        arms: arms.map(|arm| QirAuthorizationMuxArm {
            frame: arm.bytes,
            frame_sources: arm.sources,
        }),
    };
    instances[index] = Some(QirHashInstance {
        output_symbol: output_symbol.into(),
        slot,
        frame: selected_frame,
        frame_sources: selected_sources,
        output_assignment: output_assignment.clone(),
        authorization_mux: Some(authorization_mux),
    });
    Ok(output_assignment)
}

fn require_nonzero(value: Digest, field: &'static str) -> Result<(), FullShake448RelationError> {
    if value == [0; DIGEST_BYTES] {
        Err(FullShake448RelationError::ZeroDigest(field))
    } else {
        Ok(())
    }
}

fn is_canonical_asset(asset: u64) -> bool {
    asset < GOLDILOCKS_MODULUS && asset != RESERVED_REDUCED_PADDING_ASSET_ID
}

fn validate_note(note: &NoteOpening) -> Result<(), FullShake448RelationError> {
    if note.value > V6_MAX_NOTE_VALUE {
        return Err(FullShake448RelationError::ValueOutOfRange("note value"));
    }
    if !is_canonical_asset(note.asset_id) {
        return Err(FullShake448RelationError::InvalidAssetSlots);
    }
    Ok(())
}

fn validate_slots(slots: [u64; BALANCE_SLOTS]) -> Result<(), FullShake448RelationError> {
    if slots[0] != NATIVE_ASSET_ID {
        return Err(FullShake448RelationError::InvalidAssetSlots);
    }
    let mut padding = false;
    let mut previous = NATIVE_ASSET_ID;
    for asset in slots.into_iter().skip(1) {
        if asset == PADDING_ASSET_ID {
            padding = true;
        } else if padding || !is_canonical_asset(asset) || asset == 0 || asset <= previous {
            return Err(FullShake448RelationError::InvalidAssetSlots);
        } else {
            previous = asset;
        }
    }
    Ok(())
}

fn validate_stablecoin(statement: &FullShake448Statement) -> Result<(), FullShake448RelationError> {
    let stable = statement.stablecoin;
    if !stable.enabled {
        if stable.asset_id != 0
            || stable.policy_version != 0
            || stable.issuance_delta != SignedMagnitude::default()
            || stable.policy_hash != [0; DIGEST_BYTES]
            || stable.oracle_commitment != [0; DIGEST_BYTES]
            || stable.attestation_commitment != [0; DIGEST_BYTES]
        {
            return Err(FullShake448RelationError::Stablecoin(
                "disabled binding is nonzero",
            ));
        }
        return Ok(());
    }
    signed_i128(stable.issuance_delta)?;
    if stable.asset_id == NATIVE_ASSET_ID
        || !is_canonical_asset(stable.asset_id)
        || !statement.balance_asset_ids.contains(&stable.asset_id)
    {
        return Err(FullShake448RelationError::Stablecoin(
            "enabled asset is not canonical, non-native, and slotted",
        ));
    }
    Ok(())
}

fn selected_slot(
    selectors: [bool; BALANCE_SLOTS],
    slots: [u64; BALANCE_SLOTS],
    asset: u64,
    index: usize,
    role: &'static str,
) -> Result<usize, FullShake448RelationError> {
    let mut selected = None;
    for (slot, bit) in selectors.into_iter().enumerate() {
        if bit {
            if selected.is_some() {
                return Err(FullShake448RelationError::AssetSelector { index, role });
            }
            selected = Some(slot);
        }
    }
    let selected = selected.ok_or(FullShake448RelationError::AssetSelector { index, role })?;
    if slots[selected] != asset || asset == PADDING_ASSET_ID {
        return Err(FullShake448RelationError::AssetSelector { index, role });
    }
    Ok(selected)
}

#[derive(Clone, Debug)]
struct ResolvedAuthorization {
    input_auth_keys: [Digest; MAX_INPUTS],
    input_nullifier_keys: [Digest; MAX_INPUTS],
    output0_auth_key: Option<Digest>,
}

fn require_note_kind(
    note: &NoteOpening,
    expected: NoteKind,
    error: &'static str,
) -> Result<(), FullShake448RelationError> {
    if note.kind != expected {
        return Err(FullShake448RelationError::PrivateAuthorization(error));
    }
    Ok(())
}

fn require_active_inputs_kind(
    witness: &FullShake448Witness,
    expected: NoteKind,
    error: &'static str,
) -> Result<(), FullShake448RelationError> {
    if witness
        .inputs
        .iter()
        .any(|input| input.active && input.note.kind != expected)
    {
        return Err(FullShake448RelationError::PrivateAuthorization(error));
    }
    Ok(())
}

fn require_active_outputs_kind(
    witness: &FullShake448Witness,
    expected: NoteKind,
    error: &'static str,
) -> Result<(), FullShake448RelationError> {
    if witness
        .outputs
        .iter()
        .any(|output| output.active && output.note.kind != expected)
    {
        return Err(FullShake448RelationError::PrivateAuthorization(error));
    }
    Ok(())
}

fn require_optional_ordinary_output1(
    witness: &FullShake448Witness,
) -> Result<(), FullShake448RelationError> {
    if witness.outputs[1].active && witness.outputs[1].note.kind != NoteKind::Ordinary {
        return Err(FullShake448RelationError::PrivateAuthorization(
            "optional output one must be an ordinary note",
        ));
    }
    Ok(())
}

fn require_zero_native_accumulator_note(
    note: &NoteOpening,
    error: &'static str,
) -> Result<(), FullShake448RelationError> {
    if note.value != 0 || note.asset_id != NATIVE_ASSET_ID {
        return Err(FullShake448RelationError::PrivateAuthorization(error));
    }
    Ok(())
}

fn validate_accumulator(
    opening: &AccumulatorOpening,
    signer_tags: &[Digest; MAX_SIGNERS],
    expected_policy_root: Digest,
    expected_intent: Option<Digest>,
) -> Result<(), FullShake448RelationError> {
    if !(1..=MAX_SIGNERS as u64).contains(&opening.signer_count)
        || !(1..=opening.signer_count).contains(&opening.threshold)
        || opening.approval_count > opening.signer_count
        || expected_intent.is_some_and(|intent| opening.intent_digest != intent)
    {
        return Err(FullShake448RelationError::PrivateAuthorization(
            "invalid accumulator counts or intent",
        ));
    }
    require_nonzero(opening.intent_digest, "accumulator intent")?;
    if opening.approved_slots.iter().filter(|&&bit| bit).count() as u64 != opening.approval_count {
        return Err(FullShake448RelationError::PrivateAuthorization(
            "approval count does not equal approved slots",
        ));
    }
    for slot in 0..MAX_SIGNERS {
        if slot < opening.signer_count as usize {
            require_nonzero(signer_tags[slot], "active signer tag")?;
            if signer_tags[..slot].contains(&signer_tags[slot]) {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "duplicate active signer tag",
                ));
            }
        } else if signer_tags[slot] != [0; DIGEST_BYTES] || opening.approved_slots[slot] {
            return Err(FullShake448RelationError::PrivateAuthorization(
                "inactive policy slot is nonzero",
            ));
        }
    }
    if opening.policy_root != expected_policy_root {
        return Err(FullShake448RelationError::PrivateAuthorization(
            "policy root mismatch",
        ));
    }
    Ok(())
}

fn validate_authorization_activity_shape(
    mode: PrivateAuthMode,
    input_flags: [bool; MAX_INPUTS],
    output_flags: [bool; MAX_OUTPUTS],
) -> Result<(), FullShake448RelationError> {
    let input_nonempty = input_flags.into_iter().any(|active| active);
    let both_inputs = input_flags.into_iter().all(|active| active);
    let output_zero = output_flags[0];
    let valid = match mode {
        PrivateAuthMode::SingleKey => true,
        PrivateAuthMode::AccumulatorInit | PrivateAuthMode::ValueLockCreation => {
            input_nonempty && output_zero
        }
        PrivateAuthMode::ApprovalStep => both_inputs && output_zero,
        PrivateAuthMode::FinalThresholdSpend => both_inputs,
    };
    if !valid {
        return Err(FullShake448RelationError::PrivateAuthorization(
            "activity mask is incompatible with authorization mode",
        ));
    }
    Ok(())
}

fn validate_and_resolve_authorization(
    witness: &FullShake448Witness,
    spend_material: [(Digest, Digest); MAX_INPUTS],
    policy_digest: Digest,
    authorization_a: (Digest, Digest),
    authorization_b: (Digest, Digest),
    intent: Digest,
) -> Result<ResolvedAuthorization, FullShake448RelationError> {
    validate_authorization_activity_shape(
        witness.auth.mode,
        core::array::from_fn(|index| witness.inputs[index].active),
        core::array::from_fn(|index| witness.outputs[index].active),
    )?;
    match witness.auth.mode {
        PrivateAuthMode::SingleKey => {
            if !witness.auth.current.is_zero()
                || !witness.auth.next.is_zero()
                || witness.auth.signer_tags != [[0; DIGEST_BYTES]; MAX_SIGNERS]
            {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "single-key mode has nonzero auxiliary authorization witness",
                ));
            }
            require_active_inputs_kind(
                witness,
                NoteKind::Ordinary,
                "single-key inputs must be ordinary notes",
            )?;
            require_active_outputs_kind(
                witness,
                NoteKind::Ordinary,
                "single-key outputs must be ordinary notes",
            )?;
            Ok(ResolvedAuthorization {
                input_auth_keys: [spend_material[0].0, spend_material[1].0],
                input_nullifier_keys: [spend_material[0].1, spend_material[1].1],
                output0_auth_key: None,
            })
        }
        PrivateAuthMode::AccumulatorInit => {
            if !witness.auth.current.is_zero() {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "accumulator initialization has nonzero current state",
                ));
            }
            require_active_inputs_kind(
                witness,
                NoteKind::Ordinary,
                "accumulator initialization inputs must be ordinary notes",
            )?;
            require_note_kind(
                &witness.outputs[0].note,
                NoteKind::Accumulator,
                "accumulator initialization output zero has the wrong note kind",
            )?;
            require_optional_ordinary_output1(witness)?;
            require_zero_native_accumulator_note(
                &witness.outputs[0].note,
                "initialized accumulator must be a zero-value native note",
            )?;
            validate_accumulator(
                &witness.auth.next,
                &witness.auth.signer_tags,
                policy_digest,
                None,
            )?;
            if witness.auth.next.approval_count != 0
                || witness.auth.next.approved_slots != [false; MAX_SIGNERS]
            {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "initialized accumulator must have zero approvals",
                ));
            }
            Ok(ResolvedAuthorization {
                input_auth_keys: [spend_material[0].0, spend_material[1].0],
                input_nullifier_keys: [spend_material[0].1, spend_material[1].1],
                output0_auth_key: Some(authorization_a.0),
            })
        }
        PrivateAuthMode::ApprovalStep => {
            require_note_kind(
                &witness.inputs[0].note,
                NoteKind::Accumulator,
                "approval input zero is not an accumulator note",
            )?;
            require_note_kind(
                &witness.inputs[1].note,
                NoteKind::Ordinary,
                "approval signer input is not an ordinary note",
            )?;
            require_note_kind(
                &witness.outputs[0].note,
                NoteKind::Accumulator,
                "approval output zero is not an accumulator note",
            )?;
            require_optional_ordinary_output1(witness)?;
            require_zero_native_accumulator_note(
                &witness.inputs[0].note,
                "approval current accumulator must be a zero-value native note",
            )?;
            require_zero_native_accumulator_note(
                &witness.outputs[0].note,
                "approval next accumulator must be a zero-value native note",
            )?;
            if witness.inputs[0].spend_key != [0; SPEND_KEY_BYTES] {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "approval accumulator input has a nonzero unused spend key",
                ));
            }
            validate_accumulator(
                &witness.auth.current,
                &witness.auth.signer_tags,
                policy_digest,
                None,
            )?;
            validate_accumulator(
                &witness.auth.next,
                &witness.auth.signer_tags,
                policy_digest,
                None,
            )?;
            if witness.auth.current.policy_root != witness.auth.next.policy_root
                || witness.auth.current.intent_digest != witness.auth.next.intent_digest
                || witness.auth.current.threshold != witness.auth.next.threshold
                || witness.auth.current.signer_count != witness.auth.next.signer_count
                || witness.auth.next.approval_count
                    != witness.auth.current.approval_count.saturating_add(1)
            {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "approval accumulator transition metadata mismatch",
                ));
            }
            let signer_tag = spend_material[1].0;
            let matches = (0..witness.auth.current.signer_count as usize)
                .filter(|&slot| witness.auth.signer_tags[slot] == signer_tag)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "approval signer is not a unique active policy member",
                ));
            }
            let chosen = matches[0];
            if witness.auth.current.approved_slots[chosen] {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "duplicate approval",
                ));
            }
            for slot in 0..MAX_SIGNERS {
                let expected = witness.auth.current.approved_slots[slot] || slot == chosen;
                if witness.auth.next.approved_slots[slot] != expected {
                    return Err(FullShake448RelationError::PrivateAuthorization(
                        "next approved-slot vector mismatch",
                    ));
                }
            }
            Ok(ResolvedAuthorization {
                input_auth_keys: [authorization_a.0, spend_material[1].0],
                input_nullifier_keys: [authorization_a.1, spend_material[1].1],
                output0_auth_key: Some(authorization_b.0),
            })
        }
        PrivateAuthMode::ValueLockCreation => {
            if !witness.auth.next.is_zero() {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "value-lock creation has nonzero next state",
                ));
            }
            require_active_inputs_kind(
                witness,
                NoteKind::Ordinary,
                "value-lock creation inputs must be ordinary notes",
            )?;
            require_note_kind(
                &witness.outputs[0].note,
                NoteKind::ValueLock,
                "value-lock output zero has the wrong note kind",
            )?;
            require_optional_ordinary_output1(witness)?;
            validate_accumulator(
                &witness.auth.current,
                &witness.auth.signer_tags,
                policy_digest,
                None,
            )?;
            if witness.auth.current.approval_count != 0
                || witness.auth.current.approved_slots != [false; MAX_SIGNERS]
            {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "value-lock policy descriptor must have zero approvals",
                ));
            }
            Ok(ResolvedAuthorization {
                input_auth_keys: [spend_material[0].0, spend_material[1].0],
                input_nullifier_keys: [spend_material[0].1, spend_material[1].1],
                output0_auth_key: Some(authorization_a.0),
            })
        }
        PrivateAuthMode::FinalThresholdSpend => {
            if !witness.auth.next.is_zero() {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "final spend requires a zero next accumulator",
                ));
            }
            require_note_kind(
                &witness.inputs[0].note,
                NoteKind::ValueLock,
                "final input zero is not a value-lock note",
            )?;
            require_note_kind(
                &witness.inputs[1].note,
                NoteKind::Accumulator,
                "final input one is not an accumulator note",
            )?;
            require_active_outputs_kind(
                witness,
                NoteKind::Ordinary,
                "final outputs must be ordinary notes",
            )?;
            if witness
                .inputs
                .iter()
                .any(|input| input.spend_key != [0; SPEND_KEY_BYTES])
            {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "final spend has a nonzero unused spend key",
                ));
            }
            require_zero_native_accumulator_note(
                &witness.inputs[1].note,
                "final threshold accumulator must be a zero-value native note",
            )?;
            validate_accumulator(
                &witness.auth.current,
                &witness.auth.signer_tags,
                policy_digest,
                Some(intent),
            )?;
            if witness.auth.current.approval_count < witness.auth.current.threshold {
                return Err(FullShake448RelationError::PrivateAuthorization(
                    "approval threshold not reached",
                ));
            }
            Ok(ResolvedAuthorization {
                input_auth_keys: [authorization_b.0, authorization_a.0],
                input_nullifier_keys: [authorization_b.1, authorization_a.1],
                output0_auth_key: None,
            })
        }
    }
}

/// Compile and scalar-check the rejected uniform-SHAKE256 diagnostic oracle
/// against an authoritative activation selected by the verifier.  The canonical
/// 893 statement bytes are parsed once, projected losslessly to 128 Goldilocks
/// limbs, and retained unchanged.  This never claims the `HGF6HR02` mixed
/// SHAKE512/SHAKE256 relation is compiled.
pub fn compile_rejected_uniform_shake256_oracle(
    statement_bytes: &[u8],
    witness: &FullShake448Witness,
    expected_activation: V6ActivationBinding,
) -> Result<ValidatedFullShake448Relation, FullShake448RelationError> {
    let statement = decode_v6_statement(statement_bytes)?;
    if statement.activation != expected_activation {
        return Err(FullShake448RelationError::ActivationBinding);
    }
    let encoded = encode_v6_statement(&statement)?;
    if encoded.as_slice() != statement_bytes {
        return Err(FullShake448RelationError::PublicMismatch(
            "canonical statement roundtrip",
        ));
    }
    let projection = project_v6_statement(&encoded)?;
    let public_limbs = *projection.limbs();
    let program = FullShake448QirProgram::canonical();
    program.validate_shape()?;
    validate_v6_successor_hash_registry()?;

    if witness
        .inputs
        .iter()
        .map(|input| input.active)
        .collect::<Vec<_>>()
        != statement.input_flags
    {
        return Err(FullShake448RelationError::PublicMismatch("activity flags"));
    }
    if witness
        .outputs
        .iter()
        .map(|output| output.active)
        .collect::<Vec<_>>()
        != statement.output_flags
    {
        return Err(FullShake448RelationError::PublicMismatch("activity flags"));
    }
    let (active_inputs, active_outputs) =
        validate_activity_shape(statement.input_flags, statement.output_flags)?;
    if statement.fee > V6_MAX_NOTE_VALUE {
        return Err(FullShake448RelationError::ValueOutOfRange("fee"));
    }
    validate_slots(statement.balance_asset_ids)?;
    validate_stablecoin(&statement)?;
    if statement.input_flags == [true, true] && statement.nullifiers[0] == statement.nullifiers[1] {
        return Err(FullShake448RelationError::DuplicateNullifier);
    }

    for (index, input) in witness.inputs.iter().enumerate() {
        if !input.active {
            if !input.inactive_payload_is_zero() || statement.nullifiers[index] != [0; DIGEST_BYTES]
            {
                return Err(FullShake448RelationError::InactivePayload {
                    index,
                    role: "input",
                });
            }
        } else {
            validate_note(&input.note)?;
            if input.position >> MERKLE_DEPTH != 0 {
                return Err(FullShake448RelationError::Membership(index));
            }
        }
    }
    for (index, output) in witness.outputs.iter().enumerate() {
        if !output.active {
            if !output.inactive_payload_is_zero()
                || statement.commitments[index] != [0; DIGEST_BYTES]
                || statement.ciphertext_hashes[index] != [0; DIGEST_BYTES]
                || statement.ciphertext_sizes[index] != 0
            {
                return Err(FullShake448RelationError::InactivePayload {
                    index,
                    role: "output",
                });
            }
        } else {
            validate_note(&output.note)?;
            if statement.ciphertext_sizes[index] as usize != V6_CANONICAL_CIPHERTEXT_BYTES {
                return Err(FullShake448RelationError::CiphertextSize(index));
            }
        }
    }

    let mut instances = vec![None; REJECTED_UNIFORM_SHAKE256_INVOCATIONS];

    let mut note_commitments = [[0; DIGEST_BYTES]; MAX_INPUTS + MAX_OUTPUTS];
    for index in 0..MAX_INPUTS {
        note_commitments[index] = digest448(&compile_hash_slot(
            &program,
            &mut instances,
            NOTE_HASH_START + index,
            note_frame(&format!("input[{index}].note"), &witness.inputs[index].note)?,
            format!("digest.note.input[{index}]"),
        )?)?;
    }
    for index in 0..MAX_OUTPUTS {
        note_commitments[MAX_INPUTS + index] = digest448(&compile_hash_slot(
            &program,
            &mut instances,
            NOTE_HASH_START + MAX_INPUTS + index,
            note_frame(
                &format!("output[{index}].note"),
                &witness.outputs[index].note,
            )?,
            format!("digest.note.output[{index}]"),
        )?)?;
    }

    let mut spend_material = [([0; DIGEST_BYTES], [0; DIGEST_BYTES]); MAX_INPUTS];
    for index in 0..MAX_INPUTS {
        let output = compile_hash_slot(
            &program,
            &mut instances,
            SPEND_KEY_HASH_START + index,
            spend_key_frame(index, &witness.inputs[index].spend_key)?,
            format!("digest.spend_keys[{index}]"),
        )?;
        spend_material[index] = split_kdf(&output)?;
    }

    let selected_policy = if witness.auth.mode == PrivateAuthMode::AccumulatorInit {
        &witness.auth.next
    } else {
        &witness.auth.current
    };
    let policy_digest = digest448(&compile_hash_slot(
        &program,
        &mut instances,
        POLICY_HASH_SLOT,
        policy_frame(selected_policy, &witness.auth.signer_tags)?,
        "digest.authorization.policy",
    )?)?;

    let mode_selectors = witness.auth.mode.selectors();
    let authorization_a_arms = [
        dummy_authorization_frame(0),
        accumulator_frame("authorization.next", &witness.auth.next)?,
        accumulator_frame("authorization.current", &witness.auth.current)?,
        value_lock_frame(
            &witness.auth.current.policy_root,
            &witness.auth.current.intent_digest,
        )?,
        accumulator_frame("authorization.current", &witness.auth.current)?,
    ];
    let authorization_b_arms = [
        dummy_authorization_frame(1),
        dummy_authorization_frame(1),
        accumulator_frame("authorization.next", &witness.auth.next)?,
        dummy_authorization_frame(1),
        value_lock_frame(
            &witness.auth.current.policy_root,
            &witness.auth.current.intent_digest,
        )?,
    ];
    let authorization_a = split_kdf(&compile_authorization_mux_slot(
        &program,
        &mut instances,
        AUTHORIZATION_HASH_START,
        FixedAuthorizationMuxSlot::A,
        mode_selectors,
        authorization_a_arms,
        "digest.authorization.mux[0]",
    )?)?;
    let authorization_b = split_kdf(&compile_authorization_mux_slot(
        &program,
        &mut instances,
        AUTHORIZATION_HASH_START + 1,
        FixedAuthorizationMuxSlot::B,
        mode_selectors,
        authorization_b_arms,
        "digest.authorization.mux[1]",
    )?)?;

    let intent = digest448(&compile_hash_slot(
        &program,
        &mut instances,
        INTENT_HASH_SLOT,
        intent_frame(&encoded)?,
        "digest.intent",
    )?)?;
    let resolved = validate_and_resolve_authorization(
        witness,
        spend_material,
        policy_digest,
        authorization_a,
        authorization_b,
        intent,
    )?;

    let mut input_values = [[0u128; BALANCE_SLOTS]; MAX_INPUTS];
    let mut output_values = [[0u128; BALANCE_SLOTS]; MAX_OUTPUTS];
    for index in 0..MAX_INPUTS {
        let input = &witness.inputs[index];
        if input.active {
            let slot = selected_slot(
                input.balance_slot_selectors,
                statement.balance_asset_ids,
                input.note.asset_id,
                index,
                "input",
            )?;
            input_values[index][slot] = u128::from(input.note.value);
            require_nonzero(note_commitments[index], "input commitment")?;
            if input.note.pk_auth != resolved.input_auth_keys[index] {
                return Err(FullShake448RelationError::Authorization(index));
            }
        }

        let nullifier = digest448(&compile_hash_slot(
            &program,
            &mut instances,
            NULLIFIER_HASH_START + index,
            nullifier_frame(
                index,
                &resolved.input_nullifier_keys[index],
                input.position,
                &input.note.rho,
            )?,
            format!("digest.nullifier[{index}]"),
        )?)?;
        if input.active {
            require_nonzero(nullifier, "nullifier")?;
            if nullifier != statement.nullifiers[index] {
                return Err(FullShake448RelationError::PublicMismatch("nullifier"));
            }
        }

        let mut current = note_commitments[index];
        for level in 0..MERKLE_DEPTH {
            let sibling = input.siblings[level];
            let (left, right) = if (input.position >> level) & 1 == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            current = digest448(&compile_hash_slot(
                &program,
                &mut instances,
                MERKLE_HASH_START + index * MERKLE_DEPTH + level,
                merkle_frame(index, level, &left, &right)?,
                format!("digest.merkle.input[{index}].level[{level}]"),
            )?)?;
        }
        if input.active && current != statement.anchor {
            return Err(FullShake448RelationError::Membership(index));
        }
    }

    for index in 0..MAX_OUTPUTS {
        let output = &witness.outputs[index];
        if output.active {
            let slot = selected_slot(
                output.balance_slot_selectors,
                statement.balance_asset_ids,
                output.note.asset_id,
                index,
                "output",
            )?;
            output_values[index][slot] = u128::from(output.note.value);
            let commitment = note_commitments[MAX_INPUTS + index];
            require_nonzero(commitment, "output commitment")?;
            if commitment != statement.commitments[index] {
                return Err(FullShake448RelationError::PublicMismatch(
                    "output commitment",
                ));
            }
        }

        let ciphertext_digest = digest448(&compile_hash_slot(
            &program,
            &mut instances,
            CIPHERTEXT_HASH_START + index,
            ciphertext_frame(index, &output.canonical_ciphertext)?,
            format!("digest.ciphertext[{index}]"),
        )?)?;
        if output.active {
            require_nonzero(ciphertext_digest, "ciphertext hash")?;
            if ciphertext_digest != statement.ciphertext_hashes[index] {
                return Err(FullShake448RelationError::PublicMismatch("ciphertext hash"));
            }
        }
    }

    if let Some(expected) = resolved.output0_auth_key {
        if !witness.outputs[0].active || witness.outputs[0].note.pk_auth != expected {
            return Err(FullShake448RelationError::PrivateAuthorization(
                "mode-specific output zero authorization mismatch",
            ));
        }
    }

    for slot in 0..BALANCE_SLOTS {
        let inputs = input_values.iter().map(|values| values[slot]).sum::<u128>();
        let outputs = output_values
            .iter()
            .map(|values| values[slot])
            .sum::<u128>();
        let asset = statement.balance_asset_ids[slot];
        if asset == PADDING_ASSET_ID {
            if inputs != 0 || outputs != 0 {
                return Err(FullShake448RelationError::Balance(asset));
            }
            continue;
        }
        if asset == NATIVE_ASSET_ID {
            validate_native_balance_equation(
                inputs,
                outputs,
                statement.fee,
                statement.value_balance,
            )?;
            continue;
        }
        let expected_delta =
            if statement.stablecoin.enabled && asset == statement.stablecoin.asset_id {
                signed_i128(statement.stablecoin.issuance_delta)?
            } else {
                0
            };
        if inputs as i128 - outputs as i128 != expected_delta {
            return Err(FullShake448RelationError::Balance(asset));
        }
    }

    let balance_tag = digest448(&compile_hash_slot(
        &program,
        &mut instances,
        BALANCE_TAG_HASH_SLOT,
        balance_tag_frame(&statement)?,
        "digest.balance_tag",
    )?)?;
    if balance_tag != statement.balance_tag {
        return Err(FullShake448RelationError::PublicMismatch("balance tag"));
    }

    let hash_instances = instances
        .into_iter()
        .enumerate()
        .map(|(index, instance)| instance.ok_or(FullShake448RelationError::HashSlot(index)))
        .collect::<Result<Vec<_>, _>>()?;
    let qir = FullShake448QirInstance {
        program,
        statement_bytes: encoded,
        public_limbs,
        hash_instances,
    };
    qir.verify_source_coverage()?;
    debug_assert_eq!(FULL_RELATION_SHAKE256_INVOCATIONS, 79);
    debug_assert_eq!(FULL_RELATION_AUTHORITY_KECCAK_PERMUTATIONS, 124);
    debug_assert_eq!(SHAKE256_448_OUTPUT_BYTES, DIGEST_BYTES);
    Ok(ValidatedFullShake448Relation {
        statement,
        witness: witness.clone(),
        qir,
        stats: RelationStats {
            active_inputs,
            active_outputs,
            hash_invocations: REJECTED_UNIFORM_SHAKE256_INVOCATIONS,
            keccak_permutations: REJECTED_UNIFORM_SHAKE256_KECCAK_PERMUTATIONS,
            successor_hash_invocations: V6_SUCCESSOR_HASH_INVOCATIONS,
            successor_keccak_permutations: V6_SUCCESSOR_HASH_KECCAK_PERMUTATIONS,
            successor_registry_digest: v6_successor_hash_registry_digest(),
            successor_hash_relation_compiled: false,
            public_values: V6_STATEMENT_LIMBS,
            production_authorized: false,
        },
    })
}

impl ValidatedFullShake448Relation {
    /// Materialize the concrete polynomial identities currently available for
    /// the complete relation.  The method is intentionally separate from the
    /// scalar oracle because the aggregate SHAKE witness is large.  Callers
    /// must inspect `missing_lowering` and
    /// `mixed_successor_145_relation_compiled`; production code rejects unless
    /// the former is empty and the latter is true.  Until then this method only
    /// materializes the explicitly rejected uniform-SHAKE256 oracle.
    pub fn materialize_constraint_system(
        &self,
    ) -> Result<FullShake448ConstraintSystem, FullShake448RelationError> {
        let hash = self.qir.materialize_hash_constraint_system()?;
        let output_assignments = self
            .qir
            .hash_instances
            .iter()
            .map(|instance| instance.output_assignment.clone())
            .collect::<Vec<_>>();
        self.materialize_constraint_system_from_hash_system(
            hash,
            self.qir.statement_bytes,
            &output_assignments,
        )
    }

    /// Materialize the complete non-hash R1CS compiler against a caller-supplied
    /// hash aggregate.  The ordinary method above supplies the rejected uniform
    /// SHAKE256 aggregate.  This seam is intentionally diagnostic-only: a mixed
    /// conventional-hash caller must provide every converted hash trace, output
    /// assignment, and statement wire itself, while the complete semantic compiler
    /// remains shared here.
    pub fn materialize_constraint_system_from_hash_system(
        &self,
        hash: FullShake448HashConstraintSystem,
        statement_bytes: [u8; V6_STATEMENT_BYTES],
        output_assignments: &[Vec<u8>],
    ) -> Result<FullShake448ConstraintSystem, FullShake448RelationError> {
        if output_assignments.len() != REJECTED_UNIFORM_SHAKE256_INVOCATIONS {
            return Err(FullShake448RelationError::QirProgramShape);
        }
        let FullShake448HashConstraintSystem {
            mut witness,
            constraints: mut shake_constraints,
            source_bit_wires: _,
            mut source_wire_index,
            output_bit_wires,
            invocation_coverages,
            authorization_mux_coverages,
            hash_invocation_coverages,
        } = hash;
        let mut non_hash_constraints = Vec::new();
        let mut coverage = BTreeSet::new();
        let missing_lowering = vec![
            "semantic_hash.secret_roles.shake512_boolean_relation".to_owned(),
            "semantic_hash.authorization.fixed_shake512_mux".to_owned(),
        ];
        let production_blockers = vec![
            "semantic_hash.registry.HGF6HR02_non_fips_shake512".to_owned(),
            "transcript.sha512_v6_backend".to_owned(),
            "relation_manifest.executable_constraint_digest".to_owned(),
        ];

        let public_raw_bit_bindings = (0..V6_STATEMENT_BYTES)
            .flat_map(|byte_index| {
                let source_wire_index = &source_wire_index;
                (0..8).map(move |bit_index| {
                    let wire =
                        source_wire_index[&("statement.bytes".to_owned(), byte_index, bit_index)];
                    (wire, byte_index * 8 + bit_index)
                })
            })
            .collect::<Vec<_>>();

        let input_flags = [
            statement_bits(&source_wire_index, 10, 1)?[0],
            statement_bits(&source_wire_index, 11, 1)?[0],
        ];
        let output_flags = [
            statement_bits(&source_wire_index, 12, 1)?[0],
            statement_bits(&source_wire_index, 13, 1)?[0],
        ];
        let value_balance_sign = statement_bits(&source_wire_index, 454, 1)?[0];
        let stable_enabled = statement_bits(&source_wire_index, 463, 1)?[0];
        let stable_issuance_sign = statement_bits(&source_wire_index, 476, 1)?[0];
        let anchor = statement_bits(&source_wire_index, 14, DIGEST_BYTES)?;
        let public_nullifiers = [
            statement_bits(&source_wire_index, 70, DIGEST_BYTES)?,
            statement_bits(&source_wire_index, 126, DIGEST_BYTES)?,
        ];
        let public_commitments = [
            statement_bits(&source_wire_index, 182, DIGEST_BYTES)?,
            statement_bits(&source_wire_index, 238, DIGEST_BYTES)?,
        ];
        let public_ciphertext_hashes = [
            statement_bits(&source_wire_index, 294, DIGEST_BYTES)?,
            statement_bits(&source_wire_index, 350, DIGEST_BYTES)?,
        ];
        let ciphertext_sizes = [
            bytes_be_to_bits_le(&statement_bits(&source_wire_index, 406, 4)?),
            bytes_be_to_bits_le(&statement_bits(&source_wire_index, 410, 4)?),
        ];
        let statement_assets: [Vec<Shake256Wire>; BALANCE_SLOTS] = core::array::from_fn(|slot| {
            bytes_be_to_bits_le(
                &statement_bits(&source_wire_index, 414 + slot * 8, 8)
                    .expect("canonical statement wires exist"),
            )
        });
        let fee = bytes_be_to_bits_le(&statement_bits(&source_wire_index, 446, 8)?);
        let value_balance_magnitude =
            bytes_be_to_bits_le(&statement_bits(&source_wire_index, 455, 8)?);
        let stable_asset = bytes_be_to_bits_le(&statement_bits(&source_wire_index, 464, 8)?);
        let stable_version = bytes_be_to_bits_le(&statement_bits(&source_wire_index, 472, 4)?);
        let stable_issuance_magnitude =
            bytes_be_to_bits_le(&statement_bits(&source_wire_index, 477, 8)?);
        let stable_policy = statement_bits(&source_wire_index, 485, DIGEST_BYTES)?;
        let stable_oracle = statement_bits(&source_wire_index, 541, DIGEST_BYTES)?;
        let stable_attestation = statement_bits(&source_wire_index, 597, DIGEST_BYTES)?;
        let public_balance_tag = statement_bits(&source_wire_index, 653, DIGEST_BYTES)?;

        let mut inputs = Vec::with_capacity(MAX_INPUTS);
        for index in 0..MAX_INPUTS {
            let input = &self.witness.inputs[index];
            let spend_key = ensure_symbol_bytes(
                &mut witness,
                &mut shake_constraints,
                &mut source_wire_index,
                &format!("input[{index}].spend_key"),
                &input.spend_key,
                QirByteSourceKind::PrivateWitness,
            )?;
            let note = allocate_note_qir_wires(
                &mut witness,
                &mut shake_constraints,
                &mut source_wire_index,
                &format!("input[{index}].note"),
                &input.note,
            )?;
            let position = u64_source_bits(
                &mut witness,
                &mut shake_constraints,
                &mut source_wire_index,
                &format!("input[{index}].position_u64be"),
                input.position,
                QirByteSourceKind::PrivateWitness,
            )?;
            let mut siblings = Vec::with_capacity(MERKLE_DEPTH);
            for level in 0..MERKLE_DEPTH {
                siblings.push(digest_source_bits(
                    &mut witness,
                    &mut shake_constraints,
                    &mut source_wire_index,
                    &format!("input[{index}].siblings[{level}]"),
                    &input.siblings[level],
                    QirByteSourceKind::PrivateWitness,
                )?);
            }
            let selector_bytes = input.balance_slot_selectors.map(u8::from);
            let selector_bits = ensure_symbol_bytes(
                &mut witness,
                &mut shake_constraints,
                &mut source_wire_index,
                &format!("input[{index}].balance_slot_selectors"),
                &selector_bytes,
                QirByteSourceKind::PrivateWitness,
            )?;
            let selectors = core::array::from_fn(|slot| selector_bits[slot * 8]);
            let mut all = Vec::new();
            all.extend(&spend_key);
            all.extend(&note.all);
            all.extend(&position);
            all.extend(siblings.iter().flatten().copied());
            all.extend(&selector_bits);
            inputs.push(InputQirWires {
                spend_key,
                note,
                position,
                siblings,
                selectors,
                selector_byte_bits: selector_bits,
                all,
            });
        }
        let inputs: [InputQirWires; MAX_INPUTS] = inputs
            .try_into()
            .map_err(|_| FullShake448RelationError::QirProgramShape)?;

        let mut outputs = Vec::with_capacity(MAX_OUTPUTS);
        for index in 0..MAX_OUTPUTS {
            let output = &self.witness.outputs[index];
            let note = allocate_note_qir_wires(
                &mut witness,
                &mut shake_constraints,
                &mut source_wire_index,
                &format!("output[{index}].note"),
                &output.note,
            )?;
            let selector_bytes = output.balance_slot_selectors.map(u8::from);
            let selector_bits = ensure_symbol_bytes(
                &mut witness,
                &mut shake_constraints,
                &mut source_wire_index,
                &format!("output[{index}].balance_slot_selectors"),
                &selector_bytes,
                QirByteSourceKind::PrivateWitness,
            )?;
            let selectors = core::array::from_fn(|slot| selector_bits[slot * 8]);
            let ciphertext = ensure_symbol_bytes(
                &mut witness,
                &mut shake_constraints,
                &mut source_wire_index,
                &format!("output[{index}].canonical_ciphertext"),
                &output.canonical_ciphertext,
                QirByteSourceKind::PrivateWitness,
            )?;
            let mut all = note.all.clone();
            all.extend(&selector_bits);
            all.extend(&ciphertext);
            outputs.push(OutputQirWires {
                note,
                selectors,
                selector_byte_bits: selector_bits,
                ciphertext,
                all,
            });
        }
        let outputs: [OutputQirWires; MAX_OUTPUTS] = outputs
            .try_into()
            .map_err(|_| FullShake448RelationError::QirProgramShape)?;

        let current = allocate_accumulator_qir_wires(
            &mut witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "authorization.current",
            &self.witness.auth.current,
        )?;
        let next = allocate_accumulator_qir_wires(
            &mut witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "authorization.next",
            &self.witness.auth.next,
        )?;
        let signer_tags: [Vec<Shake256Wire>; MAX_SIGNERS] = core::array::from_fn(|slot| {
            digest_source_bits(
                &mut witness,
                &mut shake_constraints,
                &mut source_wire_index,
                &format!("authorization.signer_tags[{slot}]"),
                &self.witness.auth.signer_tags[slot],
                QirByteSourceKind::PrivateWitness,
            )
            .expect("fixed signer tag allocation cannot fail")
        });
        let mode_bytes = self.witness.auth.mode.selectors().map(u8::from);
        let mode_bits = ensure_symbol_bytes(
            &mut witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "authorization.mode_selectors",
            &mode_bytes,
            QirByteSourceKind::PrivateWitness,
        )?;
        let modes: [Shake256Wire; 5] = core::array::from_fn(|mode| mode_bits[mode * 8]);

        let mut builder = R1csBuilder::new(&mut witness, &mut non_hash_constraints);
        let zero = builder.zero;
        let one = builder.one;

        // Exact statement constants and verifier-selected activation are
        // polynomial constraints over the sole raw public-bit authority.
        let mut fixed_statement = Vec::new();
        fixed_statement.extend(0..10);
        fixed_statement.extend(709..717);
        fixed_statement.extend(721..725);
        for byte_index in fixed_statement {
            builder.set_family(
                if (709..717).contains(&byte_index) || (721..725).contains(&byte_index) {
                    QirConstraintFamily::StatementActivation
                } else {
                    QirConstraintFamily::CanonicalEncoding
                },
            );
            let expected = statement_bytes[byte_index];
            for bit_index in 0..8 {
                let wire =
                    source_wire_index[&("statement.bytes".to_owned(), byte_index, bit_index)];
                builder.assert_constant(
                    &format!("statement.fixed[{byte_index}].bit[{bit_index}]"),
                    wire,
                    u64::from((expected >> bit_index) & 1),
                );
            }
        }
        builder.set_family(QirConstraintFamily::StatementActivation);
        for (offset, name) in [(725, "chain_id"), (781, "genesis_id"), (837, "rules_hash")] {
            let bits = statement_bits(&source_wire_index, offset, DIGEST_BYTES)?;
            let nonzero = builder.any_bits(&format!("statement.activation.{name}.nonzero"), &bits);
            builder.assert_true(
                &format!("statement.activation.{name}.nonzero.assert"),
                nonzero,
            );
        }
        coverage.insert("statement_and_activation".to_owned());

        builder.set_family(QirConstraintFamily::CanonicalEncoding);
        for (offset, name) in [
            (10, "input_flags[0]"),
            (11, "input_flags[1]"),
            (12, "output_flags[0]"),
            (13, "output_flags[1]"),
            (454, "value_balance.sign"),
            (463, "stable.enabled"),
            (476, "stable.issuance.sign"),
        ] {
            let byte = statement_bits(&source_wire_index, offset, 1)?;
            for (bit, wire) in byte.iter().copied().enumerate().skip(1) {
                builder.assert_false(&format!("statement.{name}.high_bit[{bit}]"), wire);
            }
        }
        builder.set_family(QirConstraintFamily::ActivityMask);
        let input_nonempty = builder.or("shape.input_nonempty", input_flags[0], input_flags[1]);
        let output_nonempty = builder.or("shape.output_nonempty", output_flags[0], output_flags[1]);
        let action_nonempty = builder.or("shape.action_nonempty", input_nonempty, output_nonempty);
        builder.assert_true("shape.action_nonempty.assert", action_nonempty);
        builder.set_family(QirConstraintFamily::ValueRange);
        for bit in 61..64 {
            builder.assert_false(
                &format!("value_balance.magnitude.range.bit[{bit}]"),
                value_balance_magnitude[bit],
            );
        }
        let value_balance_nonzero =
            builder.any_bits("value_balance.magnitude.nonzero", &value_balance_magnitude);
        builder.imply(
            "value_balance.no_negative_zero",
            value_balance_sign,
            value_balance_nonzero,
        );
        coverage.insert("activity_and_value_balance".to_owned());

        builder.set_family(QirConstraintFamily::AuthorizationMode);
        let mut mode_sum = QirLinearCombination::constant(GOLDILOCKS_MODULUS - 1);
        for mode in modes {
            mode_sum = mode_sum.plus_wire(mode, 1);
        }
        builder.assert_linear_zero("authorization.mode_one_hot", mode_sum);

        builder.set_family(QirConstraintFamily::CanonicalEncoding);
        for (symbol, bytes) in [
            ("authorization.mode_selectors", mode_bits.as_slice()),
            (
                "authorization.current.approved_slots",
                current.approved_byte_bits.as_slice(),
            ),
            (
                "authorization.next.approved_slots",
                next.approved_byte_bits.as_slice(),
            ),
        ] {
            for (byte, bits) in bytes.chunks_exact(8).enumerate() {
                for (bit, wire) in bits.iter().copied().enumerate().skip(1) {
                    builder.assert_false(&format!("{symbol}[{byte}].high_bit[{bit}]"), wire);
                }
            }
        }
        for (role, slots) in [
            (
                "input",
                inputs
                    .each_ref()
                    .map(|input| input.selector_byte_bits.as_slice()),
            ),
            (
                "output",
                outputs
                    .each_ref()
                    .map(|output| output.selector_byte_bits.as_slice()),
            ),
        ] {
            for (index, bytes) in slots.into_iter().enumerate() {
                for (slot, bits) in bytes.chunks_exact(8).enumerate() {
                    for (bit, wire) in bits.iter().copied().enumerate().skip(1) {
                        builder.assert_false(
                            &format!("{role}[{index}].selector[{slot}].high_bit[{bit}]"),
                            wire,
                        );
                    }
                }
            }
        }

        for index in 0..MAX_INPUTS {
            builder.set_family(QirConstraintFamily::InactivePadding);
            let inactive = builder.not(&format!("input[{index}].inactive"), input_flags[index]);
            zero_if(
                &mut builder,
                &format!("input[{index}].inactive_payload"),
                inactive,
                &inputs[index].all,
            );
            zero_if(
                &mut builder,
                &format!("input[{index}].inactive_nullifier"),
                inactive,
                &public_nullifiers[index],
            );
            builder.set_family(QirConstraintFamily::ValueRange);
            for bit in 61..64 {
                builder.assert_false(
                    &format!("input[{index}].value.range.bit[{bit}]"),
                    inputs[index].note.value[bit],
                );
            }
            for bit in 32..64 {
                builder.assert_false(
                    &format!("input[{index}].position.range.bit[{bit}]"),
                    inputs[index].position[bit],
                );
            }
            builder.set_family(QirConstraintFamily::AssetSlotSelection);
            let selector_expression = inputs[index].selectors.iter().copied().fold(
                QirLinearCombination::wire(input_flags[index])
                    .plus_wire(one, GOLDILOCKS_MODULUS - 1),
                |expression, selector| expression.plus_wire(selector, 1),
            );
            builder.assert_linear_zero(
                &format!("input[{index}].selectors.equal_active"),
                selector_expression,
            );
            for slot in 0..BALANCE_SLOTS {
                let selected = builder.and(
                    &format!("input[{index}].selector[{slot}].active"),
                    input_flags[index],
                    inputs[index].selectors[slot],
                );
                equal_if(
                    &mut builder,
                    &format!("input[{index}].selector[{slot}].asset"),
                    selected,
                    &inputs[index].note.asset,
                    &statement_assets[slot],
                );
            }
        }
        for index in 0..MAX_OUTPUTS {
            builder.set_family(QirConstraintFamily::InactivePadding);
            let inactive = builder.not(&format!("output[{index}].inactive"), output_flags[index]);
            zero_if(
                &mut builder,
                &format!("output[{index}].inactive_payload"),
                inactive,
                &outputs[index].all,
            );
            zero_if(
                &mut builder,
                &format!("output[{index}].inactive_commitment"),
                inactive,
                &public_commitments[index],
            );
            zero_if(
                &mut builder,
                &format!("output[{index}].inactive_ciphertext_hash"),
                inactive,
                &public_ciphertext_hashes[index],
            );
            zero_if(
                &mut builder,
                &format!("output[{index}].inactive_ciphertext_size"),
                inactive,
                &ciphertext_sizes[index],
            );
            builder.set_family(QirConstraintFamily::ValueRange);
            for bit in 61..64 {
                builder.assert_false(
                    &format!("output[{index}].value.range.bit[{bit}]"),
                    outputs[index].note.value[bit],
                );
            }
            builder.set_family(QirConstraintFamily::AssetSlotSelection);
            let selector_expression = outputs[index].selectors.iter().copied().fold(
                QirLinearCombination::wire(output_flags[index])
                    .plus_wire(one, GOLDILOCKS_MODULUS - 1),
                |expression, selector| expression.plus_wire(selector, 1),
            );
            builder.assert_linear_zero(
                &format!("output[{index}].selectors.equal_active"),
                selector_expression,
            );
            for slot in 0..BALANCE_SLOTS {
                let selected = builder.and(
                    &format!("output[{index}].selector[{slot}].active"),
                    output_flags[index],
                    outputs[index].selectors[slot],
                );
                equal_if(
                    &mut builder,
                    &format!("output[{index}].selector[{slot}].asset"),
                    selected,
                    &outputs[index].note.asset,
                    &statement_assets[slot],
                );
            }
            builder.set_family(QirConstraintFamily::CiphertextBinding);
            let active_size = constant_u64_bits(
                builder.witness,
                &mut shake_constraints,
                &mut source_wire_index,
                "ciphertext_size_2147",
                V6_CANONICAL_CIPHERTEXT_BYTES as u64,
            )?;
            equal_if(
                &mut builder,
                &format!("output[{index}].active_ciphertext_size"),
                output_flags[index],
                &ciphertext_sizes[index],
                &active_size[..32],
            );
        }
        coverage.insert("canonical_inactivity_ranges_and_selectors".to_owned());

        builder.set_family(QirConstraintFamily::ValueRange);
        for bit in 61..64 {
            builder.assert_false(&format!("fee.range.bit[{bit}]"), fee[bit]);
            builder.assert_false(
                &format!("stable.issuance.range.bit[{bit}]"),
                stable_issuance_magnitude[bit],
            );
        }
        let issuance_nonzero =
            builder.any_bits("stable.issuance.nonzero", &stable_issuance_magnitude);
        let issuance_zero = builder.not("stable.issuance.zero", issuance_nonzero);
        builder.assert_eq_if(
            "stable.issuance.no_negative_zero",
            issuance_zero,
            stable_issuance_sign,
            zero,
        );

        // Public digest links from constrained SHAKE outputs.
        for index in 0..MAX_OUTPUTS {
            let note_digest = &output_bit_wires[&format!("digest.note.output[{index}]")];
            builder.set_family(QirConstraintFamily::OutputCommitmentBinding);
            equal_if(
                &mut builder,
                &format!("output[{index}].commitment_hash"),
                output_flags[index],
                note_digest,
                &public_commitments[index],
            );
            nonzero_if(
                &mut builder,
                &format!("output[{index}].commitment_nonzero"),
                output_flags[index],
                note_digest,
            );
            let ciphertext = &output_bit_wires[&format!("digest.ciphertext[{index}]")];
            builder.set_family(QirConstraintFamily::CiphertextBinding);
            equal_if(
                &mut builder,
                &format!("output[{index}].ciphertext_hash"),
                output_flags[index],
                ciphertext,
                &public_ciphertext_hashes[index],
            );
            nonzero_if(
                &mut builder,
                &format!("output[{index}].ciphertext_nonzero"),
                output_flags[index],
                ciphertext,
            );
        }
        for index in 0..MAX_INPUTS {
            let nullifier = &output_bit_wires[&format!("digest.nullifier[{index}]")];
            builder.set_family(QirConstraintFamily::NullifierBinding);
            equal_if(
                &mut builder,
                &format!("input[{index}].nullifier_hash"),
                input_flags[index],
                nullifier,
                &public_nullifiers[index],
            );
            nonzero_if(
                &mut builder,
                &format!("input[{index}].nullifier_nonzero"),
                input_flags[index],
                nullifier,
            );
            let note_digest = &output_bit_wires[&format!("digest.note.input[{index}]")];
            builder.set_family(QirConstraintFamily::MerklePath);
            nonzero_if(
                &mut builder,
                &format!("input[{index}].commitment_nonzero"),
                input_flags[index],
                note_digest,
            );
            let mut current_digest = note_digest.clone();
            for level in 0..MERKLE_DEPTH {
                let left_value = if (self.witness.inputs[index].position >> level) & 1 == 0 {
                    if level == 0 {
                        digest448(&output_assignments[NOTE_HASH_START + index])?
                    } else {
                        digest448(
                            &output_assignments
                                [MERKLE_HASH_START + index * MERKLE_DEPTH + level - 1],
                        )?
                    }
                } else {
                    self.witness.inputs[index].siblings[level]
                };
                let right_value = if (self.witness.inputs[index].position >> level) & 1 == 0 {
                    self.witness.inputs[index].siblings[level]
                } else if level == 0 {
                    digest448(&output_assignments[NOTE_HASH_START + index])?
                } else {
                    digest448(
                        &output_assignments[MERKLE_HASH_START + index * MERKLE_DEPTH + level - 1],
                    )?
                };
                let left = digest_source_bits(
                    builder.witness,
                    &mut shake_constraints,
                    &mut source_wire_index,
                    &format!("merkle.input[{index}].level[{level}].left"),
                    &left_value,
                    QirByteSourceKind::InternalDigest,
                )?;
                let right = digest_source_bits(
                    builder.witness,
                    &mut shake_constraints,
                    &mut source_wire_index,
                    &format!("merkle.input[{index}].level[{level}].right"),
                    &right_value,
                    QirByteSourceKind::InternalDigest,
                )?;
                for bit in 0..DIGEST_BYTES * 8 {
                    let expected_left = builder.select(
                        &format!("merkle.input[{index}].level[{level}].left[{bit}]"),
                        inputs[index].position[level],
                        inputs[index].siblings[level][bit],
                        current_digest[bit],
                    );
                    let expected_right = builder.select(
                        &format!("merkle.input[{index}].level[{level}].right[{bit}]"),
                        inputs[index].position[level],
                        current_digest[bit],
                        inputs[index].siblings[level][bit],
                    );
                    builder.assert_eq(
                        &format!("merkle.input[{index}].level[{level}].left_source[{bit}]"),
                        left[bit],
                        expected_left,
                    );
                    builder.assert_eq(
                        &format!("merkle.input[{index}].level[{level}].right_source[{bit}]"),
                        right[bit],
                        expected_right,
                    );
                }
                current_digest = output_bit_wires
                    [&format!("digest.merkle.input[{index}].level[{level}]")]
                    .clone();
            }
            equal_if(
                &mut builder,
                &format!("input[{index}].anchor"),
                input_flags[index],
                &current_digest,
                &anchor,
            );
        }
        builder.set_family(QirConstraintFamily::NullifierBinding);
        let both_inputs = builder.and("nullifiers.both_active", input_flags[0], input_flags[1]);
        let nullifiers_equal = builder.equals_bits(
            "nullifiers.equal",
            &public_nullifiers[0],
            &public_nullifiers[1],
        );
        builder.assert_eq_if(
            "nullifiers.active_distinct",
            both_inputs,
            nullifiers_equal,
            zero,
        );
        builder.set_family(QirConstraintFamily::BalanceTagBinding);
        equal_always(
            &mut builder,
            "balance_tag.hash",
            &output_bit_wires["digest.balance_tag"],
            &public_balance_tag,
        );
        coverage.insert("hash_output_and_merkle_links".to_owned());

        builder.set_family(QirConstraintFamily::CanonicalEncoding);
        let field_modulus_bits = constant_u64_bits(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "goldilocks_modulus",
            GOLDILOCKS_MODULUS,
        )?;
        let padding_asset_bits = constant_u64_bits(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "padding_asset",
            PADDING_ASSET_ID,
        )?;
        let reduced_padding_bits = constant_u64_bits(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "reduced_padding_alias",
            RESERVED_REDUCED_PADDING_ASSET_ID,
        )?;
        let three_bits = constant_u64_bits(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "three",
            3,
        )?;

        builder.set_family(QirConstraintFamily::AssetOrder);
        zero_if(&mut builder, "assets[0].native", one, &statement_assets[0]);
        let mut slot_is_padding = Vec::with_capacity(BALANCE_SLOTS);
        slot_is_padding.push(builder.equals_bits(
            "assets[0].is_padding",
            &statement_assets[0],
            &padding_asset_bits,
        ));
        for slot in 1..BALANCE_SLOTS {
            let is_padding = builder.equals_bits(
                &format!("assets[{slot}].is_padding"),
                &statement_assets[slot],
                &padding_asset_bits,
            );
            let nonpadding = builder.not(&format!("assets[{slot}].nonpadding"), is_padding);
            let in_field = builder.less_than_bits(
                &format!("assets[{slot}].field_range"),
                &statement_assets[slot],
                &field_modulus_bits,
            );
            builder.imply(
                &format!("assets[{slot}].field_range.assert"),
                nonpadding,
                in_field,
            );
            let alias = builder.equals_bits(
                &format!("assets[{slot}].reduced_padding_alias"),
                &statement_assets[slot],
                &reduced_padding_bits,
            );
            builder.assert_eq_if(
                &format!("assets[{slot}].reduced_padding_alias.reject"),
                nonpadding,
                alias,
                zero,
            );
            let asset_nonzero =
                builder.any_bits(&format!("assets[{slot}].nonzero"), &statement_assets[slot]);
            builder.imply(
                &format!("assets[{slot}].nonnative"),
                nonpadding,
                asset_nonzero,
            );
            builder.imply(
                &format!("assets[{slot}].padding_suffix"),
                slot_is_padding[slot - 1],
                is_padding,
            );
            let previous_nonpadding = builder.not(
                &format!("assets[{slot}].previous_nonpadding"),
                slot_is_padding[slot - 1],
            );
            let both_nonpadding = builder.and(
                &format!("assets[{slot}].both_nonpadding"),
                previous_nonpadding,
                nonpadding,
            );
            let ordered = builder.less_than_bits(
                &format!("assets[{slot}].strict_order"),
                &statement_assets[slot - 1],
                &statement_assets[slot],
            );
            builder.imply(
                &format!("assets[{slot}].strict_order.assert"),
                both_nonpadding,
                ordered,
            );
            slot_is_padding.push(is_padding);
        }
        coverage.insert("asset_slot_canonicality".to_owned());

        builder.set_family(QirConstraintFamily::ValueRange);
        for index in 0..MAX_INPUTS {
            let kind_le = inputs[index].note.kind.clone();
            let mut kind_padded = vec![zero; 64];
            kind_padded[..kind_le.len()].copy_from_slice(&kind_le);
            let kind_valid = builder.less_than_bits(
                &format!("input[{index}].note.kind_range"),
                &kind_padded,
                &three_bits,
            );
            builder.imply(
                &format!("input[{index}].note.kind_range.assert"),
                input_flags[index],
                kind_valid,
            );
            let asset_in_field = builder.less_than_bits(
                &format!("input[{index}].note.asset_range"),
                &inputs[index].note.asset,
                &field_modulus_bits,
            );
            builder.imply(
                &format!("input[{index}].note.asset_range.assert"),
                input_flags[index],
                asset_in_field,
            );
            let alias = builder.equals_bits(
                &format!("input[{index}].note.asset_alias"),
                &inputs[index].note.asset,
                &reduced_padding_bits,
            );
            builder.assert_eq_if(
                &format!("input[{index}].note.asset_alias.reject"),
                input_flags[index],
                alias,
                zero,
            );
        }
        for index in 0..MAX_OUTPUTS {
            let kind_le = outputs[index].note.kind.clone();
            let mut kind_padded = vec![zero; 64];
            kind_padded[..kind_le.len()].copy_from_slice(&kind_le);
            let kind_valid = builder.less_than_bits(
                &format!("output[{index}].note.kind_range"),
                &kind_padded,
                &three_bits,
            );
            builder.imply(
                &format!("output[{index}].note.kind_range.assert"),
                output_flags[index],
                kind_valid,
            );
            let asset_in_field = builder.less_than_bits(
                &format!("output[{index}].note.asset_range"),
                &outputs[index].note.asset,
                &field_modulus_bits,
            );
            builder.imply(
                &format!("output[{index}].note.asset_range.assert"),
                output_flags[index],
                asset_in_field,
            );
            let alias = builder.equals_bits(
                &format!("output[{index}].note.asset_alias"),
                &outputs[index].note.asset,
                &reduced_padding_bits,
            );
            builder.assert_eq_if(
                &format!("output[{index}].note.asset_alias.reject"),
                output_flags[index],
                alias,
                zero,
            );
        }
        coverage.insert("note_kind_value_asset_ranges".to_owned());

        builder.set_family(QirConstraintFamily::Stablecoin);
        let stable_disabled = builder.not("stable.disabled", stable_enabled);
        zero_if(
            &mut builder,
            "stable.disabled.asset",
            stable_disabled,
            &stable_asset,
        );
        zero_if(
            &mut builder,
            "stable.disabled.version",
            stable_disabled,
            &stable_version,
        );
        builder.assert_eq_if(
            "stable.disabled.issuance_sign",
            stable_disabled,
            stable_issuance_sign,
            zero,
        );
        zero_if(
            &mut builder,
            "stable.disabled.issuance_magnitude",
            stable_disabled,
            &stable_issuance_magnitude,
        );
        zero_if(
            &mut builder,
            "stable.disabled.policy",
            stable_disabled,
            &stable_policy,
        );
        zero_if(
            &mut builder,
            "stable.disabled.oracle",
            stable_disabled,
            &stable_oracle,
        );
        zero_if(
            &mut builder,
            "stable.disabled.attestation",
            stable_disabled,
            &stable_attestation,
        );
        let stable_asset_nonzero = builder.any_bits("stable.asset.nonzero", &stable_asset);
        builder.imply(
            "stable.enabled.asset_nonzero",
            stable_enabled,
            stable_asset_nonzero,
        );
        let stable_asset_in_field = builder.less_than_bits(
            "stable.asset.field_range",
            &stable_asset,
            &field_modulus_bits,
        );
        builder.imply(
            "stable.enabled.asset_field_range",
            stable_enabled,
            stable_asset_in_field,
        );
        let stable_alias = builder.equals_bits(
            "stable.asset.reduced_padding_alias",
            &stable_asset,
            &reduced_padding_bits,
        );
        builder.assert_eq_if(
            "stable.enabled.asset_alias.reject",
            stable_enabled,
            stable_alias,
            zero,
        );
        let mut stable_matches_slot = zero;
        for slot in 0..BALANCE_SLOTS {
            let matches = builder.equals_bits(
                &format!("stable.asset.matches_slot[{slot}]"),
                &stable_asset,
                &statement_assets[slot],
            );
            stable_matches_slot = builder.or(
                &format!("stable.asset.matches_slot_through[{slot}]"),
                stable_matches_slot,
                matches,
            );
        }
        builder.imply(
            "stable.enabled.slotted_asset",
            stable_enabled,
            stable_matches_slot,
        );
        coverage.insert("stablecoin_statement".to_owned());

        builder.set_family(QirConstraintFamily::Balance);
        for slot in 0..BALANCE_SLOTS {
            let input_contributions: [Vec<Shake256Wire>; MAX_INPUTS] =
                core::array::from_fn(|input| {
                    (0..64)
                        .map(|bit| {
                            builder.and(
                                &format!("balance[{slot}].input[{input}].bit[{bit}]"),
                                inputs[input].selectors[slot],
                                inputs[input].note.value[bit],
                            )
                        })
                        .collect()
                });
            let output_contributions: [Vec<Shake256Wire>; MAX_OUTPUTS] =
                core::array::from_fn(|output| {
                    (0..64)
                        .map(|bit| {
                            builder.and(
                                &format!("balance[{slot}].output[{output}].bit[{bit}]"),
                                outputs[output].selectors[slot],
                                outputs[output].note.value[bit],
                            )
                        })
                        .collect()
                });
            let input_sum = builder.add_bits(
                &format!("balance[{slot}].input_sum"),
                &input_contributions[0],
                &input_contributions[1],
            );
            let output_sum = builder.add_bits(
                &format!("balance[{slot}].output_sum"),
                &output_contributions[0],
                &output_contributions[1],
            );
            let mut input_low = input_sum[..64].to_vec();
            let mut output_low = output_sum[..64].to_vec();
            let inputs_plus_issuance = builder.add_bits(
                &format!("balance[{slot}].inputs_plus_issuance"),
                &input_low,
                &stable_issuance_magnitude,
            );
            let outputs_plus_issuance = builder.add_bits(
                &format!("balance[{slot}].outputs_plus_issuance"),
                &output_low,
                &stable_issuance_magnitude,
            );
            if slot == 0 {
                let mut magnitude_65 = value_balance_magnitude.clone();
                magnitude_65.push(zero);
                let mut fee_65 = fee.clone();
                fee_65.push(zero);
                let inputs_plus_magnitude = builder.add_bits(
                    "balance.native.inputs_plus_positive_value_balance",
                    &input_sum,
                    &magnitude_65,
                );
                let outputs_plus_fee =
                    builder.add_bits("balance.native.outputs_plus_fee", &output_sum, &fee_65);
                let nonnegative_value_balance = builder.not(
                    "balance.native.value_balance_nonnegative",
                    value_balance_sign,
                );
                equal_if(
                    &mut builder,
                    "balance.native.nonnegative_equation",
                    nonnegative_value_balance,
                    &inputs_plus_magnitude,
                    &outputs_plus_fee,
                );

                let mut magnitude_66 = magnitude_65;
                magnitude_66.push(zero);
                let outputs_plus_fee_plus_magnitude = builder.add_bits(
                    "balance.native.outputs_plus_fee_plus_negative_value_balance",
                    &outputs_plus_fee,
                    &magnitude_66,
                );
                let mut input_sum_67 = input_sum.clone();
                input_sum_67.resize(outputs_plus_fee_plus_magnitude.len(), zero);
                equal_if(
                    &mut builder,
                    "balance.native.negative_equation",
                    value_balance_sign,
                    &input_sum_67,
                    &outputs_plus_fee_plus_magnitude,
                );
                continue;
            }

            zero_if(
                &mut builder,
                &format!("balance[{slot}].padding.inputs"),
                slot_is_padding[slot],
                &input_sum,
            );
            zero_if(
                &mut builder,
                &format!("balance[{slot}].padding.outputs"),
                slot_is_padding[slot],
                &output_sum,
            );
            let asset_matches_stable = builder.equals_bits(
                &format!("balance[{slot}].stable_asset"),
                &statement_assets[slot],
                &stable_asset,
            );
            let stable_slot = builder.and(
                &format!("balance[{slot}].stable_slot"),
                stable_enabled,
                asset_matches_stable,
            );
            let mint = builder.and(
                &format!("balance[{slot}].mint"),
                stable_slot,
                stable_issuance_sign,
            );
            let not_issuance_sign = builder.not(
                &format!("balance[{slot}].not_issuance_sign"),
                stable_issuance_sign,
            );
            let burn = builder.and(
                &format!("balance[{slot}].burn"),
                stable_slot,
                not_issuance_sign,
            );
            equal_if(
                &mut builder,
                &format!("balance[{slot}].mint_equation"),
                mint,
                &output_sum,
                &inputs_plus_issuance,
            );
            equal_if(
                &mut builder,
                &format!("balance[{slot}].burn_equation"),
                burn,
                &input_sum,
                &outputs_plus_issuance,
            );
            let not_padding = builder.not(
                &format!("balance[{slot}].not_padding"),
                slot_is_padding[slot],
            );
            let not_stable_slot =
                builder.not(&format!("balance[{slot}].not_stable_slot"), stable_slot);
            let ordinary = builder.and(
                &format!("balance[{slot}].ordinary"),
                not_padding,
                not_stable_slot,
            );
            equal_if(
                &mut builder,
                &format!("balance[{slot}].ordinary_equation"),
                ordinary,
                &input_sum,
                &output_sum,
            );
        }
        coverage.insert("four_slot_integer_balance".to_owned());

        builder.set_family(QirConstraintFamily::SpendAuthorization);
        let spend_hashes = [
            output_bit_wires["digest.spend_keys[0]"].clone(),
            output_bit_wires["digest.spend_keys[1]"].clone(),
        ];
        let spend_auth = [
            spend_hashes[0][..DIGEST_BYTES * 8].to_vec(),
            spend_hashes[1][..DIGEST_BYTES * 8].to_vec(),
        ];
        let spend_nf = [
            spend_hashes[0][DIGEST_BYTES * 8..].to_vec(),
            spend_hashes[1][DIGEST_BYTES * 8..].to_vec(),
        ];
        let authorization_a_bits = output_bit_wires["digest.authorization.mux[0]"].clone();
        let authorization_b_bits = output_bit_wires["digest.authorization.mux[1]"].clone();
        let auth_a = authorization_a_bits[..DIGEST_BYTES * 8].to_vec();
        let nf_a = authorization_a_bits[DIGEST_BYTES * 8..].to_vec();
        let auth_b = authorization_b_bits[..DIGEST_BYTES * 8].to_vec();
        let nf_b = authorization_b_bits[DIGEST_BYTES * 8..].to_vec();

        let spend_material_scalar = [
            split_kdf(&output_assignments[SPEND_KEY_HASH_START])?,
            split_kdf(&output_assignments[SPEND_KEY_HASH_START + 1])?,
        ];
        let policy_scalar = digest448(&output_assignments[POLICY_HASH_SLOT])?;
        let authorization_a_scalar = split_kdf(&output_assignments[AUTHORIZATION_HASH_START])?;
        let authorization_b_scalar = split_kdf(&output_assignments[AUTHORIZATION_HASH_START + 1])?;
        let intent_scalar = digest448(&output_assignments[INTENT_HASH_SLOT])?;
        let resolved_scalar = validate_and_resolve_authorization(
            &self.witness,
            spend_material_scalar,
            policy_scalar,
            authorization_a_scalar,
            authorization_b_scalar,
            intent_scalar,
        )?;
        let resolved_auth: [Vec<Shake256Wire>; MAX_INPUTS] = core::array::from_fn(|input| {
            digest_source_bits(
                builder.witness,
                &mut shake_constraints,
                &mut source_wire_index,
                &format!("resolved_auth_key[{input}]"),
                &resolved_scalar.input_auth_keys[input],
                QirByteSourceKind::InternalDigest,
            )
            .expect("resolved authorization key has fixed width")
        });
        let resolved_nf: [Vec<Shake256Wire>; MAX_INPUTS] = core::array::from_fn(|input| {
            digest_source_bits(
                builder.witness,
                &mut shake_constraints,
                &mut source_wire_index,
                &format!("resolved_nullifier_key[{input}]"),
                &resolved_scalar.input_nullifier_keys[input],
                QirByteSourceKind::InternalDigest,
            )
            .expect("resolved nullifier key has fixed width")
        });

        let single = modes[0];
        let init = modes[1];
        let approval = modes[2];
        let lock = modes[3];
        let final_spend = modes[4];
        let init_or_lock = builder.or("authorization.init_or_lock", init, lock);
        let approval_or_final =
            builder.or("authorization.approval_or_final", approval, final_spend);
        let current_policy_a = builder.or("authorization.current_policy_a", approval, lock);
        let current_policy = builder.or(
            "authorization.current_policy",
            current_policy_a,
            final_spend,
        );
        let non_single_a = builder.or("authorization.non_single_a", init, approval);
        let non_single_b = builder.or("authorization.non_single_b", lock, final_spend);
        let non_single = builder.or("authorization.non_single", non_single_a, non_single_b);

        for bit in 0..DIGEST_BYTES * 8 {
            for mode in [single, init, lock] {
                builder.assert_eq_if(
                    &format!("authorization.resolved.input0.spend[{bit}]"),
                    mode,
                    resolved_auth[0][bit],
                    spend_auth[0][bit],
                );
                builder.assert_eq_if(
                    &format!("authorization.resolved_nf.input0.spend[{bit}]"),
                    mode,
                    resolved_nf[0][bit],
                    spend_nf[0][bit],
                );
            }
            for mode in [single, init, approval, lock] {
                builder.assert_eq_if(
                    &format!("authorization.resolved.input1.spend[{bit}]"),
                    mode,
                    resolved_auth[1][bit],
                    spend_auth[1][bit],
                );
                builder.assert_eq_if(
                    &format!("authorization.resolved_nf.input1.spend[{bit}]"),
                    mode,
                    resolved_nf[1][bit],
                    spend_nf[1][bit],
                );
            }
            builder.assert_eq_if(
                &format!("authorization.resolved.input0.approval[{bit}]"),
                approval,
                resolved_auth[0][bit],
                auth_a[bit],
            );
            builder.assert_eq_if(
                &format!("authorization.resolved_nf.input0.approval[{bit}]"),
                approval,
                resolved_nf[0][bit],
                nf_a[bit],
            );
            builder.assert_eq_if(
                &format!("authorization.resolved.input0.final[{bit}]"),
                final_spend,
                resolved_auth[0][bit],
                auth_b[bit],
            );
            builder.assert_eq_if(
                &format!("authorization.resolved_nf.input0.final[{bit}]"),
                final_spend,
                resolved_nf[0][bit],
                nf_b[bit],
            );
            builder.assert_eq_if(
                &format!("authorization.resolved.input1.final[{bit}]"),
                final_spend,
                resolved_auth[1][bit],
                auth_a[bit],
            );
            builder.assert_eq_if(
                &format!("authorization.resolved_nf.input1.final[{bit}]"),
                final_spend,
                resolved_nf[1][bit],
                nf_a[bit],
            );
        }
        for input in 0..MAX_INPUTS {
            equal_if(
                &mut builder,
                &format!("authorization.input[{input}].note_auth"),
                input_flags[input],
                &inputs[input].note.auth,
                &resolved_auth[input],
            );
        }
        equal_if(
            &mut builder,
            "authorization.output0.init_or_lock",
            init_or_lock,
            &outputs[0].note.auth,
            &auth_a,
        );
        equal_if(
            &mut builder,
            "authorization.output0.approval",
            approval,
            &outputs[0].note.auth,
            &auth_b,
        );
        coverage.insert("authorization_key_resolution".to_owned());

        builder.set_family(QirConstraintFamily::AuthorizationTransition);
        let selected_policy = if self.witness.auth.mode == PrivateAuthMode::AccumulatorInit {
            &self.witness.auth.next
        } else {
            &self.witness.auth.current
        };
        let selected_threshold = u64_source_bits(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "authorization.selected_policy.threshold_u64be",
            selected_policy.threshold,
            QirByteSourceKind::PrivateWitness,
        )?;
        let selected_signer_count = u64_source_bits(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "authorization.selected_policy.signer_count_u64be",
            selected_policy.signer_count,
            QirByteSourceKind::PrivateWitness,
        )?;
        equal_if(
            &mut builder,
            "authorization.selected_policy.init.threshold",
            init,
            &selected_threshold,
            &next.threshold,
        );
        equal_if(
            &mut builder,
            "authorization.selected_policy.init.signer_count",
            init,
            &selected_signer_count,
            &next.signer_count,
        );
        let current_or_single = builder.or(
            "authorization.selected_policy.current_or_single",
            current_policy,
            single,
        );
        equal_if(
            &mut builder,
            "authorization.selected_policy.current.threshold",
            current_or_single,
            &selected_threshold,
            &current.threshold,
        );
        equal_if(
            &mut builder,
            "authorization.selected_policy.current.signer_count",
            current_or_single,
            &selected_signer_count,
            &current.signer_count,
        );
        let policy_hash_bits = &output_bit_wires["digest.authorization.policy"];
        equal_if(
            &mut builder,
            "authorization.policy_hash.init",
            init,
            policy_hash_bits,
            &next.policy_root,
        );
        equal_if(
            &mut builder,
            "authorization.policy_hash.current",
            current_policy,
            policy_hash_bits,
            &current.policy_root,
        );

        let seven_bits = constant_u64_bits(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "seven",
            7,
        )?;
        let signer_slot_constants: [Vec<Shake256Wire>; MAX_SIGNERS] =
            core::array::from_fn(|slot| {
                constant_u64_bits(
                    builder.witness,
                    &mut shake_constraints,
                    &mut source_wire_index,
                    &format!("signer_slot_{slot}"),
                    slot as u64,
                )
                .expect("fixed slot constant allocation")
            });
        constrain_accumulator_structure(
            &mut builder,
            "authorization.current",
            current_policy,
            &current,
            &signer_tags,
            &seven_bits,
            &signer_slot_constants,
        );
        let next_policy = builder.or("authorization.next_policy", init, approval);
        constrain_accumulator_structure(
            &mut builder,
            "authorization.next",
            next_policy,
            &next,
            &signer_tags,
            &seven_bits,
            &signer_slot_constants,
        );
        coverage.insert("authorization_policy_structure".to_owned());

        let ordinary_kind = ensure_symbol_bytes(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "constant.note_kind.ordinary",
            &[0],
            QirByteSourceKind::Constant,
        )?;
        let accumulator_kind = ensure_symbol_bytes(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "constant.note_kind.accumulator",
            &[1],
            QirByteSourceKind::Constant,
        )?;
        let value_lock_kind = ensure_symbol_bytes(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "constant.note_kind.value_lock",
            &[2],
            QirByteSourceKind::Constant,
        )?;

        zero_if(
            &mut builder,
            "authorization.single.current_zero",
            single,
            &current.all,
        );
        zero_if(
            &mut builder,
            "authorization.single.next_zero",
            single,
            &next.all,
        );
        for slot in 0..MAX_SIGNERS {
            zero_if(
                &mut builder,
                &format!("authorization.single.signer_tag[{slot}]"),
                single,
                &signer_tags[slot],
            );
        }
        for input in 0..MAX_INPUTS {
            let gate = builder.and(
                &format!("authorization.single.input[{input}].active"),
                single,
                input_flags[input],
            );
            equal_if(
                &mut builder,
                &format!("authorization.single.input[{input}].ordinary"),
                gate,
                &inputs[input].note.kind,
                &ordinary_kind,
            );
        }
        for output in 0..MAX_OUTPUTS {
            let gate = builder.and(
                &format!("authorization.single.output[{output}].active"),
                single,
                output_flags[output],
            );
            equal_if(
                &mut builder,
                &format!("authorization.single.output[{output}].ordinary"),
                gate,
                &outputs[output].note.kind,
                &ordinary_kind,
            );
        }

        builder.imply("authorization.init.input_nonempty", init, input_nonempty);
        builder.imply("authorization.init.output0_active", init, output_flags[0]);
        zero_if(
            &mut builder,
            "authorization.init.current_zero",
            init,
            &current.all,
        );
        for input in 0..MAX_INPUTS {
            let gate = builder.and(
                &format!("authorization.init.input[{input}].active"),
                init,
                input_flags[input],
            );
            equal_if(
                &mut builder,
                &format!("authorization.init.input[{input}].ordinary"),
                gate,
                &inputs[input].note.kind,
                &ordinary_kind,
            );
        }
        equal_if(
            &mut builder,
            "authorization.init.output0.accumulator",
            init,
            &outputs[0].note.kind,
            &accumulator_kind,
        );
        zero_if(
            &mut builder,
            "authorization.init.output0.value_zero",
            init,
            &outputs[0].note.value,
        );
        zero_if(
            &mut builder,
            "authorization.init.output0.asset_native",
            init,
            &outputs[0].note.asset,
        );
        zero_if(
            &mut builder,
            "authorization.init.approval_count_zero",
            init,
            &next.approval_count,
        );
        zero_if(
            &mut builder,
            "authorization.init.approved_zero",
            init,
            &next.approved,
        );
        let init_output1 = builder.and("authorization.init.output1.active", init, output_flags[1]);
        equal_if(
            &mut builder,
            "authorization.init.output1.ordinary",
            init_output1,
            &outputs[1].note.kind,
            &ordinary_kind,
        );

        builder.imply(
            "authorization.approval.input0_active",
            approval,
            input_flags[0],
        );
        builder.imply(
            "authorization.approval.input1_active",
            approval,
            input_flags[1],
        );
        builder.imply(
            "authorization.approval.output0_active",
            approval,
            output_flags[0],
        );
        equal_if(
            &mut builder,
            "authorization.approval.input0.accumulator",
            approval,
            &inputs[0].note.kind,
            &accumulator_kind,
        );
        equal_if(
            &mut builder,
            "authorization.approval.input1.ordinary",
            approval,
            &inputs[1].note.kind,
            &ordinary_kind,
        );
        equal_if(
            &mut builder,
            "authorization.approval.output0.accumulator",
            approval,
            &outputs[0].note.kind,
            &accumulator_kind,
        );
        for (name, bits) in [
            ("input0.value_zero", &inputs[0].note.value),
            ("input0.asset_native", &inputs[0].note.asset),
            ("output0.value_zero", &outputs[0].note.value),
            ("output0.asset_native", &outputs[0].note.asset),
            ("input0.spend_key_zero", &inputs[0].spend_key),
        ] {
            zero_if(
                &mut builder,
                &format!("authorization.approval.{name}"),
                approval,
                bits,
            );
        }
        let approval_output1 = builder.and(
            "authorization.approval.output1.active",
            approval,
            output_flags[1],
        );
        equal_if(
            &mut builder,
            "authorization.approval.output1.ordinary",
            approval_output1,
            &outputs[1].note.kind,
            &ordinary_kind,
        );
        for (name, left, right) in [
            ("policy_root", &current.policy_root, &next.policy_root),
            ("intent", &current.intent, &next.intent),
            ("threshold", &current.threshold, &next.threshold),
            ("signer_count", &current.signer_count, &next.signer_count),
        ] {
            equal_if(
                &mut builder,
                &format!("authorization.approval.metadata.{name}"),
                approval,
                left,
                right,
            );
        }
        let one_u64 = constant_u64_bits(
            builder.witness,
            &mut shake_constraints,
            &mut source_wire_index,
            "one_u64",
            1,
        )?;
        let current_approvals_plus_one = builder.add_bits(
            "authorization.approval.count_plus_one",
            &current.approval_count,
            &one_u64,
        );
        equal_if(
            &mut builder,
            "authorization.approval.count_increment",
            approval,
            &next.approval_count,
            &current_approvals_plus_one[..64],
        );
        builder.assert_eq_if(
            "authorization.approval.count_increment_no_overflow",
            approval,
            current_approvals_plus_one[64],
            zero,
        );
        let mut changed_sum = QirLinearCombination::constant(GOLDILOCKS_MODULUS - 1);
        for slot in 0..MAX_SIGNERS {
            let changed = builder.xor(
                &format!("authorization.approval.changed[{slot}]"),
                current.approved[slot],
                next.approved[slot],
            );
            changed_sum = changed_sum.plus_wire(changed, 1);
            let no_clear_gate = builder.and(
                &format!("authorization.approval.no_clear_gate[{slot}]"),
                approval,
                current.approved[slot],
            );
            builder.imply(
                &format!("authorization.approval.no_clear[{slot}]"),
                no_clear_gate,
                next.approved[slot],
            );
            let tag_matches = builder.equals_bits(
                &format!("authorization.approval.tag_matches[{slot}]"),
                &spend_auth[1],
                &signer_tags[slot],
            );
            let slot_active = builder.less_than_bits(
                &format!("authorization.approval.slot_active[{slot}]"),
                &signer_slot_constants[slot],
                &current.signer_count,
            );
            let changed_gate = builder.and(
                &format!("authorization.approval.changed_gate[{slot}]"),
                approval,
                changed,
            );
            builder.imply(
                &format!("authorization.approval.changed_tag[{slot}]"),
                changed_gate,
                tag_matches,
            );
            let member_match = builder.and(
                &format!("authorization.approval.member_match[{slot}]"),
                slot_active,
                tag_matches,
            );
            let member_gate = builder.and(
                &format!("authorization.approval.member_gate[{slot}]"),
                approval,
                member_match,
            );
            builder.imply(
                &format!("authorization.approval.member_changed[{slot}]"),
                member_gate,
                changed,
            );
        }
        let family = builder.family;
        builder.constraints.push(QirR1csConstraint {
            name: "authorization.approval.exactly_one_changed".to_owned(),
            family,
            left: QirLinearCombination::wire(approval),
            right: changed_sum,
            output: QirLinearCombination::constant(0),
        });

        builder.imply("authorization.lock.input_nonempty", lock, input_nonempty);
        builder.imply("authorization.lock.output0_active", lock, output_flags[0]);
        for input in 0..MAX_INPUTS {
            let gate = builder.and(
                &format!("authorization.lock.input[{input}].active"),
                lock,
                input_flags[input],
            );
            equal_if(
                &mut builder,
                &format!("authorization.lock.input[{input}].ordinary"),
                gate,
                &inputs[input].note.kind,
                &ordinary_kind,
            );
        }
        equal_if(
            &mut builder,
            "authorization.lock.output0.value_lock",
            lock,
            &outputs[0].note.kind,
            &value_lock_kind,
        );
        zero_if(
            &mut builder,
            "authorization.lock.next_zero",
            lock,
            &next.all,
        );
        zero_if(
            &mut builder,
            "authorization.lock.approval_count_zero",
            lock,
            &current.approval_count,
        );
        zero_if(
            &mut builder,
            "authorization.lock.approved_zero",
            lock,
            &current.approved,
        );
        let lock_output1 = builder.and("authorization.lock.output1.active", lock, output_flags[1]);
        equal_if(
            &mut builder,
            "authorization.lock.output1.ordinary",
            lock_output1,
            &outputs[1].note.kind,
            &ordinary_kind,
        );

        builder.imply(
            "authorization.final.input0_active",
            final_spend,
            input_flags[0],
        );
        builder.imply(
            "authorization.final.input1_active",
            final_spend,
            input_flags[1],
        );
        equal_if(
            &mut builder,
            "authorization.final.input0.value_lock",
            final_spend,
            &inputs[0].note.kind,
            &value_lock_kind,
        );
        equal_if(
            &mut builder,
            "authorization.final.input1.accumulator",
            final_spend,
            &inputs[1].note.kind,
            &accumulator_kind,
        );
        zero_if(
            &mut builder,
            "authorization.final.input1.value_zero",
            final_spend,
            &inputs[1].note.value,
        );
        zero_if(
            &mut builder,
            "authorization.final.input1.asset_native",
            final_spend,
            &inputs[1].note.asset,
        );
        for input in 0..MAX_INPUTS {
            zero_if(
                &mut builder,
                &format!("authorization.final.input[{input}].spend_key_zero"),
                final_spend,
                &inputs[input].spend_key,
            );
        }
        zero_if(
            &mut builder,
            "authorization.final.next_zero",
            final_spend,
            &next.all,
        );
        for output in 0..MAX_OUTPUTS {
            let gate = builder.and(
                &format!("authorization.final.output[{output}].active"),
                final_spend,
                output_flags[output],
            );
            equal_if(
                &mut builder,
                &format!("authorization.final.output[{output}].ordinary"),
                gate,
                &outputs[output].note.kind,
                &ordinary_kind,
            );
        }
        let approvals_below_threshold = builder.less_than_bits(
            "authorization.final.approvals_below_threshold",
            &current.approval_count,
            &current.threshold,
        );
        builder.assert_eq_if(
            "authorization.final.threshold_reached",
            final_spend,
            approvals_below_threshold,
            zero,
        );
        builder.set_family(QirConstraintFamily::IntentBinding);
        equal_if(
            &mut builder,
            "authorization.final.intent",
            final_spend,
            &current.intent,
            &output_bit_wires["digest.intent"],
        );
        coverage.insert("five_mode_authorization_transitions".to_owned());

        // The fixed SHAKE256 mux is concrete, but it belongs only to the
        // rejected uniform oracle.  The machine-readable missing list prevents
        // the adapter from mistaking that oracle for a conventional mixed
        // successor relation.
        drop(builder);
        let mut executable_family_coverage = BTreeMap::new();
        for constraint in &non_hash_constraints {
            *executable_family_coverage
                .entry(constraint.family)
                .or_insert(0usize) += 1;
        }
        let mut system = FullShake448ConstraintSystem {
            witness,
            shake_constraints,
            non_hash_constraints,
            source_wire_index,
            output_bit_wires,
            invocation_coverages,
            authorization_mux_coverages,
            hash_invocation_coverages,
            public_raw_bit_bindings,
            constraint_family_coverage: coverage,
            executable_family_coverage,
            missing_lowering,
            production_blockers,
            mixed_successor_145_relation_compiled: false,
        };
        system.verify_rejected_uniform_sha256()?;
        Ok(system)
    }
}

#[cfg(test)]
mod source_level_tests {
    use super::*;
    use crate::full_shake448_statement::{
        StablecoinStatementBinding, V6_ACTION_ID, V6_BACKEND_ID, V6_CIRCUIT_VERSION,
        V6_CRYPTO_SUITE, V6_FAMILY_ID,
    };

    fn statement_for_scalar_vectors() -> FullShake448Statement {
        FullShake448Statement {
            input_flags: [true, false],
            output_flags: [true, false],
            anchor: [0; DIGEST_BYTES],
            nullifiers: [[0; DIGEST_BYTES]; MAX_INPUTS],
            commitments: [[0; DIGEST_BYTES]; MAX_OUTPUTS],
            ciphertext_hashes: [[0; DIGEST_BYTES]; MAX_OUTPUTS],
            ciphertext_sizes: [0; MAX_OUTPUTS],
            balance_asset_ids: [NATIVE_ASSET_ID, 7, PADDING_ASSET_ID, PADDING_ASSET_ID],
            fee: 0,
            value_balance: SignedMagnitude::default(),
            stablecoin: StablecoinStatementBinding {
                enabled: false,
                asset_id: 0,
                policy_version: 0,
                issuance_delta: SignedMagnitude::default(),
                policy_hash: [0; DIGEST_BYTES],
                oracle_commitment: [0; DIGEST_BYTES],
                attestation_commitment: [0; DIGEST_BYTES],
            },
            balance_tag: [0; DIGEST_BYTES],
            activation: V6ActivationBinding {
                circuit_version: V6_CIRCUIT_VERSION,
                crypto_suite: V6_CRYPTO_SUITE,
                family_id: V6_FAMILY_ID,
                action_id: V6_ACTION_ID,
                backend_id: V6_BACKEND_ID,
                proof_profile: V6_PROOF_PROFILE,
                domain_set: V6_DOMAIN_SET,
                network_id: 1,
                chain_id: [1; DIGEST_BYTES],
                genesis_id: [2; DIGEST_BYTES],
                rules_hash: [3; DIGEST_BYTES],
            },
        }
    }

    #[test]
    fn signed_value_balance_matches_live_native_delta_equation() {
        for (inputs, outputs, fee, value_balance) in [
            (10, 5, 5, SignedMagnitude::default()),
            (
                10,
                7,
                5,
                SignedMagnitude {
                    negative: false,
                    magnitude: 2,
                },
            ),
            (
                12,
                5,
                3,
                SignedMagnitude {
                    negative: true,
                    magnitude: 4,
                },
            ),
            (
                100,
                0,
                0,
                SignedMagnitude {
                    negative: true,
                    magnitude: 100,
                },
            ),
            (
                0,
                100,
                0,
                SignedMagnitude {
                    negative: false,
                    magnitude: 100,
                },
            ),
        ] {
            let signed = if value_balance.negative {
                -i128::from(value_balance.magnitude)
            } else {
                i128::from(value_balance.magnitude)
            };
            assert_eq!(
                i128::try_from(inputs).unwrap() - i128::try_from(outputs).unwrap(),
                i128::from(fee) - signed,
            );
            validate_native_balance_equation(inputs, outputs, fee, value_balance).unwrap();
        }

        assert!(validate_native_balance_equation(
            10,
            7,
            5,
            SignedMagnitude {
                negative: false,
                magnitude: 3,
            },
        )
        .is_err());
        assert!(signed_i128(SignedMagnitude {
            negative: true,
            magnitude: 0,
        })
        .is_err());
        assert!(signed_i128(SignedMagnitude {
            negative: false,
            magnitude: V6_MAX_NOTE_VALUE + 1,
        })
        .is_err());
        assert!(
            validate_native_balance_equation(u128::MAX, 0, 0, SignedMagnitude::default(),).is_err()
        );
    }

    #[test]
    fn all_fifteen_nonempty_masks_pass_global_shape_and_zero_mask_fails() {
        for mask in 0u8..16 {
            let inputs = [mask & 1 != 0, mask & 2 != 0];
            let outputs = [mask & 4 != 0, mask & 8 != 0];
            assert_eq!(
                validate_activity_shape(inputs, outputs).is_ok(),
                mask != 0,
                "mask {mask:04b}",
            );
        }
    }

    #[test]
    fn input_only_burn_and_output_only_mint_follow_live_balance_signs() {
        validate_activity_shape([true, false], [false, false]).unwrap();
        validate_native_balance_equation(
            100,
            0,
            0,
            SignedMagnitude {
                negative: true,
                magnitude: 100,
            },
        )
        .unwrap();

        validate_activity_shape([false, false], [true, false]).unwrap();
        validate_native_balance_equation(
            0,
            100,
            0,
            SignedMagnitude {
                negative: false,
                magnitude: 100,
            },
        )
        .unwrap();

        assert!(validate_activity_shape([false, false], [false, false]).is_err());
    }

    #[test]
    fn authorization_mode_mask_matrix_matches_live_shape_rules() {
        let modes = [
            PrivateAuthMode::SingleKey,
            PrivateAuthMode::AccumulatorInit,
            PrivateAuthMode::ApprovalStep,
            PrivateAuthMode::ValueLockCreation,
            PrivateAuthMode::FinalThresholdSpend,
        ];
        for mode in modes {
            for mask in 1u8..16 {
                let inputs = [mask & 1 != 0, mask & 2 != 0];
                let outputs = [mask & 4 != 0, mask & 8 != 0];
                let expected = match mode {
                    PrivateAuthMode::SingleKey => true,
                    PrivateAuthMode::AccumulatorInit | PrivateAuthMode::ValueLockCreation => {
                        (inputs[0] || inputs[1]) && outputs[0]
                    }
                    PrivateAuthMode::ApprovalStep => inputs[0] && inputs[1] && outputs[0],
                    PrivateAuthMode::FinalThresholdSpend => inputs[0] && inputs[1],
                };
                assert_eq!(
                    validate_authorization_activity_shape(mode, inputs, outputs).is_ok(),
                    expected,
                    "mode={mode:?} mask={mask:04b}",
                );
            }
        }
    }

    #[test]
    fn enabled_stablecoin_accepts_zero_metadata_but_disabled_must_be_zero() {
        let mut statement = statement_for_scalar_vectors();
        statement.stablecoin.enabled = true;
        statement.stablecoin.asset_id = 7;
        validate_stablecoin(&statement).unwrap();

        statement.stablecoin.issuance_delta = SignedMagnitude {
            negative: true,
            magnitude: 0,
        };
        assert!(validate_stablecoin(&statement).is_err());

        statement.stablecoin.issuance_delta = SignedMagnitude::default();
        statement.stablecoin.enabled = false;
        statement.stablecoin.policy_version = 1;
        assert!(validate_stablecoin(&statement).is_err());
    }

    #[test]
    fn rejected_nonconventional_successor_registry_is_statement_owned_and_exact() {
        validate_v6_successor_hash_registry().unwrap();
        assert!(ensure_v6_successor_registry_uses_conventional_hashes().is_err());
        assert_eq!(v6_successor_hash_registry_bytes().len(), 214);
        assert_eq!(V6_SUCCESSOR_HASH_INVOCATIONS, 79);
        assert_eq!(V6_SUCCESSOR_HASH_KECCAK_PERMUTATIONS, 145);
        assert_eq!(
            v6_successor_hash_registry_digest(),
            crate::full_shake448_statement::V6_HASH_ROLE_REGISTRY_DIGEST,
        );
        for slot in 0..V6_SUCCESSOR_HASH_INVOCATIONS {
            assert!(v6_successor_profile_for_hash_slot(slot).is_some());
        }
    }

    #[test]
    fn rejected_uniform_oracle_uses_fixed_five_arm_authorization_shape() {
        let program = FullShake448QirProgram::canonical();
        for mode in [
            PrivateAuthMode::SingleKey,
            PrivateAuthMode::AccumulatorInit,
            PrivateAuthMode::ApprovalStep,
            PrivateAuthMode::ValueLockCreation,
            PrivateAuthMode::FinalThresholdSpend,
        ] {
            let current = AccumulatorOpening::zero();
            let next = AccumulatorOpening::zero();
            let arms = [
                dummy_authorization_frame(0),
                accumulator_frame("authorization.next", &next).unwrap(),
                accumulator_frame("authorization.current", &current).unwrap(),
                value_lock_frame(&current.policy_root, &current.intent_digest).unwrap(),
                accumulator_frame("authorization.current", &current).unwrap(),
            ];
            let mut instances = vec![None; REJECTED_UNIFORM_SHAKE256_INVOCATIONS];
            compile_authorization_mux_slot(
                &program,
                &mut instances,
                AUTHORIZATION_HASH_START,
                FixedAuthorizationMuxSlot::A,
                mode.selectors(),
                arms,
                "digest.authorization.mux[0]",
            )
            .unwrap();
            let instance = instances[AUTHORIZATION_HASH_START].as_ref().unwrap();
            let mux = instance.authorization_mux.as_ref().unwrap();
            assert_eq!(
                mux.arms.each_ref().map(|arm| arm.frame.len()),
                [136, 181, 181, 143, 181],
            );
            assert!(mux.arms[0].frame_sources.is_empty());
            assert!(mux.arms[1..]
                .iter()
                .all(|arm| arm.frame_sources.len() == arm.frame.len()));
        }
    }
}
