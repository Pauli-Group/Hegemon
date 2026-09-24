//! Scalar oracle for the complete prospective SHAKE256 shielded-spend relation.
//!
//! This is deliberately isolated from consensus. It replaces the Pay1x2-only
//! research relation with the full two-input/two-output production shape and
//! is the reference consumed by the native-word M4 prototype.

#![forbid(unsafe_code)]

pub mod action_adapter;
pub mod composed_envelope;

use core::fmt;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_INPUTS: usize = 2;
pub const MAX_OUTPUTS: usize = 2;
pub const BALANCE_SLOTS: usize = 4;
pub const MERKLE_DEPTH: usize = 32;
pub const MAX_SIGNERS: usize = 6;
pub const DIGEST_BYTES: usize = 56;
pub const MAX_NOTE_VALUE: u64 = (1u64 << 61) - 1;
pub const FIELD_MODULUS: u64 = 0xffff_ffff_0000_0001;
pub const NATIVE_ASSET_ID: u64 = 0;
pub const PADDING_ASSET_ID: u64 = u64::MAX;
pub const RESERVED_REDUCED_PADDING_ASSET_ID: u64 = u32::MAX as u64 - 1;
pub const PROFILE_TAG: [u8; 8] = *b"HEG-F4V1";
pub const TARGET_CIRCUIT_VERSION: u16 = 5;
pub const TARGET_CRYPTO_SUITE: u16 = 4;
pub const SHIELDED_POOL_FAMILY_ID: u16 = 1;
pub const TARGET_ACTION_ID: u16 = 7;
pub const TARGET_BACKEND_ID: [u8; 8] = *b"binm4v1\0";
pub const TARGET_PROOF_PROFILE: [u8; 8] = *b"pq128v1\0";
pub const STATEMENT_MAGIC: [u8; 8] = *b"HGF4ST02";
pub const STATEMENT_GRAMMAR_VERSION: u16 = 2;
pub const CANONICAL_STATEMENT_BYTES: usize = 853;
/// The composed M4 verifier appends the exact 56-byte `intent.1` digest as
/// seven verifier-derived public words; it is not added to the action wire.
pub const M4_DERIVED_INTENT_WORDS: usize = DIGEST_BYTES / 8;
/// Full fixed geometry after externalizing the two public-only hashes while
/// retaining two independent depth-32 Merkle paths for exact scalar parity.
pub const M4_FIXED_KECCAK_PERMUTATIONS: usize = 83;

pub type Digest = [u8; DIGEST_BYTES];

const ROLE_NOTE: [u8; 8] = *b"note.cm3";
const ROLE_NULLIFIER: [u8; 8] = *b"nullif.2";
const ROLE_MERKLE: [u8; 8] = *b"merk.nd2";
const ROLE_SPEND_KEYS: [u8; 8] = *b"sp.keys2";
const ROLE_POLICY: [u8; 8] = *b"policy.1";
const ROLE_ACCUMULATOR: [u8; 8] = *b"accum.01";
const ROLE_VALUE_LOCK: [u8; 8] = *b"val.lock";
const ROLE_INTENT: [u8; 8] = *b"intent.1";
const ROLE_BALANCE_TAG: [u8; 8] = *b"bal.tag1";
/// Defines the semantic order of every 112-byte key-derivation output:
/// bytes 0..56 authorize a note and bytes 56..112 derive its nullifier.
const KEY_OUTPUT_ORDER_TAG: [u8; 8] = *b"auth.nf1";

/// A covenanted note type. The tag is private but is committed by `note.cm3`,
/// so an ordinary output cannot later be reinterpreted as authorization state.
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

    pub fn commitment(&self) -> Digest {
        let kind = [self.kind.tag()];
        hash_fields(
            ROLE_NOTE,
            &[
                &kind,
                &self.value.to_be_bytes(),
                &self.asset_id.to_be_bytes(),
                &self.pk_recipient,
                &self.rho,
                &self.randomness,
                &self.pk_auth,
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputWitness {
    pub active: bool,
    pub spend_key: [u8; 48],
    pub note: NoteOpening,
    pub position: u64,
    pub siblings: [Digest; MERKLE_DEPTH],
    pub balance_slot_selectors: [bool; BALANCE_SLOTS],
}

impl InputWitness {
    pub const fn zero() -> Self {
        Self {
            active: false,
            spend_key: [0; 48],
            note: NoteOpening::zero(),
            position: 0,
            siblings: [[0; DIGEST_BYTES]; MERKLE_DEPTH],
            balance_slot_selectors: [false; BALANCE_SLOTS],
        }
    }

    fn inactive_payload_is_zero(&self) -> bool {
        self.spend_key == [0; 48]
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
}

impl OutputWitness {
    pub const fn zero() -> Self {
        Self {
            active: false,
            note: NoteOpening::zero(),
            balance_slot_selectors: [false; BALANCE_SLOTS],
        }
    }

    fn inactive_payload_is_zero(&self) -> bool {
        self.note.is_zero() && self.balance_slot_selectors == [false; BALANCE_SLOTS]
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignedAmount {
    pub negative: bool,
    pub magnitude: u64,
}

impl SignedAmount {
    pub fn from_i128(value: i128) -> Result<Self, RelationError> {
        let magnitude = value.unsigned_abs();
        if magnitude > u128::from(MAX_NOTE_VALUE) {
            return Err(RelationError::ValueOutOfRange("signed amount"));
        }
        Ok(Self {
            negative: value < 0,
            magnitude: magnitude as u64,
        })
    }

    pub fn as_i128(self) -> Result<i128, RelationError> {
        if self.magnitude > MAX_NOTE_VALUE || (self.magnitude == 0 && self.negative) {
            return Err(RelationError::NonCanonicalSignedAmount);
        }
        Ok(if self.negative {
            -i128::from(self.magnitude)
        } else {
            i128::from(self.magnitude)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinBinding {
    pub enabled: bool,
    pub asset_id: u64,
    pub policy_version: u32,
    pub issuance_delta: SignedAmount,
    pub policy_hash: Digest,
    pub oracle_commitment: Digest,
    pub attestation_commitment: Digest,
}

impl Default for StablecoinBinding {
    fn default() -> Self {
        Self {
            enabled: false,
            asset_id: 0,
            policy_version: 0,
            issuance_delta: SignedAmount::default(),
            policy_hash: [0; DIGEST_BYTES],
            oracle_commitment: [0; DIGEST_BYTES],
            attestation_commitment: [0; DIGEST_BYTES],
        }
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
pub struct FullWitness {
    pub inputs: [InputWitness; MAX_INPUTS],
    pub outputs: [OutputWitness; MAX_OUTPUTS],
    pub auth: PrivateAuthWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationBinding {
    pub circuit_version: u16,
    pub crypto_suite: u16,
    pub family_id: u16,
    pub action_id: u16,
    pub backend_id: [u8; 8],
    pub proof_profile: [u8; 8],
    pub chain_id: [u8; 32],
    pub genesis_block_id: [u8; 48],
    pub rules_hash: [u8; 48],
}

impl ActivationBinding {
    pub const fn canonical_fixture() -> Self {
        Self {
            circuit_version: TARGET_CIRCUIT_VERSION,
            crypto_suite: TARGET_CRYPTO_SUITE,
            family_id: SHIELDED_POOL_FAMILY_ID,
            action_id: TARGET_ACTION_ID,
            backend_id: TARGET_BACKEND_ID,
            proof_profile: TARGET_PROOF_PROFILE,
            chain_id: [0x91; 32],
            genesis_block_id: [0x92; 48],
            rules_hash: [0x93; 48],
        }
    }

    fn is_target_profile(&self) -> bool {
        self.circuit_version == TARGET_CIRCUIT_VERSION
            && self.crypto_suite == TARGET_CRYPTO_SUITE
            && self.family_id == SHIELDED_POOL_FAMILY_ID
            && self.action_id == TARGET_ACTION_ID
            && self.backend_id == TARGET_BACKEND_ID
            && self.proof_profile == TARGET_PROOF_PROFILE
            && self.chain_id != [0; 32]
            && self.genesis_block_id != [0; 48]
            && self.rules_hash != [0; 48]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullStatement {
    pub input_flags: [bool; MAX_INPUTS],
    pub output_flags: [bool; MAX_OUTPUTS],
    pub anchor: Digest,
    pub nullifiers: [Digest; MAX_INPUTS],
    pub commitments: [Digest; MAX_OUTPUTS],
    pub ciphertext_hashes: [Digest; MAX_OUTPUTS],
    pub balance_slot_asset_ids: [u64; BALANCE_SLOTS],
    pub fee: u64,
    pub value_balance: SignedAmount,
    pub stablecoin: StablecoinBinding,
    pub balance_tag: Digest,
    pub activation: ActivationBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationStats {
    pub active_inputs: usize,
    pub active_outputs: usize,
    pub note_hashes: usize,
    pub nullifier_hashes: usize,
    pub merkle_hashes: usize,
    pub scalar_public_only_hashes: usize,
    pub m4_derived_intent_words: usize,
    pub m4_fixed_keccak_permutations: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelationError {
    Shape(&'static str),
    InactivePayload(usize, &'static str),
    PublicMismatch(&'static str),
    ValueOutOfRange(&'static str),
    NonCanonicalSignedAmount,
    InvalidAssetSlots,
    AssetSelector(usize, &'static str),
    ZeroDigest(&'static str),
    DuplicateNullifier,
    Membership(usize),
    Authorization(usize),
    Balance(u64),
    Stablecoin(&'static str),
    PrivateAuthorization(&'static str),
    ActivationBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementDecodeError {
    Length { expected: usize, actual: usize },
    Magic,
    GrammarVersion(u16),
    NonBoolean(&'static str),
    NonCanonicalSignedAmount(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementEncodeError {
    NonCanonicalSignedAmount(&'static str),
}

impl fmt::Display for RelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RelationError {}

impl fmt::Display for StatementDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StatementDecodeError {}

impl fmt::Display for StatementEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StatementEncodeError {}

fn verify_relation_unbound(
    statement: &FullStatement,
    witness: &FullWitness,
) -> Result<RelationStats, RelationError> {
    if !statement.activation.is_target_profile() {
        return Err(RelationError::ActivationBinding);
    }
    if statement.fee > MAX_NOTE_VALUE {
        return Err(RelationError::ValueOutOfRange("fee"));
    }
    let value_balance = statement.value_balance.as_i128()?;
    if value_balance != 0 {
        return Err(RelationError::PublicMismatch(
            "active transfer action requires zero value balance",
        ));
    }
    validate_slots(statement.balance_slot_asset_ids)?;
    validate_stablecoin(statement)?;

    let active_inputs = witness.inputs.iter().filter(|input| input.active).count();
    let active_outputs = witness
        .outputs
        .iter()
        .filter(|output| output.active)
        .count();
    // Active native transfer admission requires at least one nullifier and at
    // least one commitment. Other masks remain explicit negative cases.
    if active_inputs == 0 || active_outputs == 0 {
        return Err(RelationError::Shape(
            "active transfer requires input and output",
        ));
    }
    if statement.input_flags != core::array::from_fn(|index| witness.inputs[index].active)
        || statement.output_flags != core::array::from_fn(|index| witness.outputs[index].active)
    {
        return Err(RelationError::PublicMismatch("activity flags"));
    }
    if statement.input_flags == [true, true] && statement.nullifiers[0] == statement.nullifiers[1] {
        return Err(RelationError::DuplicateNullifier);
    }

    let intent = intent_digest(statement);
    let auth_material = validate_private_auth(witness, intent)?;
    let mut input_values = [[0u128; BALANCE_SLOTS]; MAX_INPUTS];
    let mut output_values = [[0u128; BALANCE_SLOTS]; MAX_OUTPUTS];

    for (index, input) in witness.inputs.iter().enumerate() {
        if !input.active {
            if !input.inactive_payload_is_zero() || statement.nullifiers[index] != [0; DIGEST_BYTES]
            {
                return Err(RelationError::InactivePayload(index, "input"));
            }
            continue;
        }
        validate_note(&input.note)?;
        if input.position >> MERKLE_DEPTH != 0 {
            return Err(RelationError::Membership(index));
        }
        let slot = selected_slot(
            input.balance_slot_selectors,
            statement.balance_slot_asset_ids,
            input.note.asset_id,
            index,
            "input",
        )?;
        input_values[index][slot] = u128::from(input.note.value);
        let commitment = input.note.commitment();
        require_nonzero(commitment, "input commitment")?;
        if fold_path(commitment, input.position, &input.siblings) != statement.anchor {
            return Err(RelationError::Membership(index));
        }
        let nullifier = nullifier(
            auth_material.input_nullifier_keys[index],
            input.position,
            input.note.rho,
        );
        require_nonzero(nullifier, "nullifier")?;
        if nullifier != statement.nullifiers[index] {
            return Err(RelationError::PublicMismatch("nullifier"));
        }
        if input.note.pk_auth != auth_material.input_auth_keys[index] {
            return Err(RelationError::Authorization(index));
        }
    }

    for (index, output) in witness.outputs.iter().enumerate() {
        if !output.active {
            if !output.inactive_payload_is_zero()
                || statement.commitments[index] != [0; DIGEST_BYTES]
                || statement.ciphertext_hashes[index] != [0; DIGEST_BYTES]
            {
                return Err(RelationError::InactivePayload(index, "output"));
            }
            continue;
        }
        validate_note(&output.note)?;
        let slot = selected_slot(
            output.balance_slot_selectors,
            statement.balance_slot_asset_ids,
            output.note.asset_id,
            index,
            "output",
        )?;
        output_values[index][slot] = u128::from(output.note.value);
        let commitment = output.note.commitment();
        require_nonzero(commitment, "output commitment")?;
        require_nonzero(statement.ciphertext_hashes[index], "ciphertext hash")?;
        if commitment != statement.commitments[index] {
            return Err(RelationError::PublicMismatch("output commitment"));
        }
    }

    if let Some(expected_output0_auth) = auth_material.output0_auth_key
        && (!witness.outputs[0].active || witness.outputs[0].note.pk_auth != expected_output0_auth)
    {
        return Err(RelationError::PrivateAuthorization(
            "mode-specific output zero authorization mismatch",
        ));
    }

    for slot in 0..BALANCE_SLOTS {
        let inputs: u128 = input_values.iter().map(|values| values[slot]).sum();
        let outputs: u128 = output_values.iter().map(|values| values[slot]).sum();
        let asset = statement.balance_slot_asset_ids[slot];
        if asset == PADDING_ASSET_ID {
            if inputs != 0 || outputs != 0 {
                return Err(RelationError::Balance(asset));
            }
            continue;
        }
        let expected_delta = if asset == NATIVE_ASSET_ID {
            i128::from(statement.fee) - value_balance
        } else if statement.stablecoin.enabled && asset == statement.stablecoin.asset_id {
            statement.stablecoin.issuance_delta.as_i128()?
        } else {
            0
        };
        if inputs as i128 - outputs as i128 != expected_delta {
            return Err(RelationError::Balance(asset));
        }
    }
    if statement.balance_tag != expected_balance_tag(statement) {
        return Err(RelationError::PublicMismatch("balance tag"));
    }

    Ok(RelationStats {
        active_inputs,
        active_outputs,
        note_hashes: active_inputs + active_outputs,
        nullifier_hashes: active_inputs,
        merkle_hashes: active_inputs * MERKLE_DEPTH,
        scalar_public_only_hashes: 2,
        m4_derived_intent_words: M4_DERIVED_INTENT_WORDS,
        m4_fixed_keccak_permutations: M4_FIXED_KECCAK_PERMUTATIONS,
    })
}

/// Verify the relation and require the complete activation/network tuple to
/// equal an authoritative value supplied by the caller. Production admission
/// must use this entry point; comparing a statement to itself is not network
/// binding.
pub fn verify_relation_with_expected_activation(
    statement: &FullStatement,
    witness: &FullWitness,
    expected: &ActivationBinding,
) -> Result<RelationStats, RelationError> {
    if &statement.activation != expected {
        return Err(RelationError::ActivationBinding);
    }
    verify_relation_unbound(statement, witness)
}

// Unit tests exercise individual semantic failures without manufacturing a
// second authoritative activation tuple. This alias is deliberately absent
// from non-test builds so production callers cannot bypass exact binding.
#[cfg(test)]
fn verify_relation(
    statement: &FullStatement,
    witness: &FullWitness,
) -> Result<RelationStats, RelationError> {
    verify_relation_unbound(statement, witness)
}

#[derive(Clone, Debug)]
struct ResolvedAuth {
    input_auth_keys: [Digest; MAX_INPUTS],
    input_nullifier_keys: [Digest; MAX_INPUTS],
    output0_auth_key: Option<Digest>,
}

fn validate_private_auth(
    witness: &FullWitness,
    intent: Digest,
) -> Result<ResolvedAuth, RelationError> {
    let spend_material: [(Digest, Digest); MAX_INPUTS] =
        core::array::from_fn(|index| spend_keys(&witness.inputs[index].spend_key));
    match witness.auth.mode {
        PrivateAuthMode::SingleKey => {
            if !witness.auth.current.is_zero()
                || !witness.auth.next.is_zero()
                || witness.auth.signer_tags != [[0; DIGEST_BYTES]; MAX_SIGNERS]
            {
                return Err(RelationError::PrivateAuthorization(
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
            Ok(ResolvedAuth {
                input_auth_keys: [spend_material[0].0, spend_material[1].0],
                input_nullifier_keys: [spend_material[0].1, spend_material[1].1],
                output0_auth_key: None,
            })
        }
        PrivateAuthMode::AccumulatorInit => {
            if !witness.inputs.iter().any(|input| input.active) || !witness.outputs[0].active {
                return Err(RelationError::PrivateAuthorization(
                    "accumulator initialization requires an ordinary input and output zero",
                ));
            }
            if !witness.auth.current.is_zero() {
                return Err(RelationError::PrivateAuthorization(
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
            validate_accumulator(&witness.auth.next, &witness.auth.signer_tags, None)?;
            if witness.auth.next.approval_count != 0
                || witness.auth.next.approved_slots != [false; MAX_SIGNERS]
            {
                return Err(RelationError::PrivateAuthorization(
                    "initialized accumulator must have zero approvals",
                ));
            }
            Ok(ResolvedAuth {
                input_auth_keys: [spend_material[0].0, spend_material[1].0],
                input_nullifier_keys: [spend_material[0].1, spend_material[1].1],
                output0_auth_key: Some(accumulator_digest(&witness.auth.next)),
            })
        }
        PrivateAuthMode::ApprovalStep => {
            if !witness.inputs.iter().all(|input| input.active) || !witness.outputs[0].active {
                return Err(RelationError::PrivateAuthorization(
                    "approval requires two inputs and output zero",
                ));
            }
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
            if witness.inputs[0].spend_key != [0; 48] {
                return Err(RelationError::PrivateAuthorization(
                    "approval accumulator input has a nonzero unused spend key",
                ));
            }
            // Approval transactions advance an already chosen private intent.
            // Requiring that stored intent to equal the approval transaction's
            // own output commitment would create a circular fixed point because
            // output zero is keyed by the next accumulator digest.
            validate_accumulator(&witness.auth.current, &witness.auth.signer_tags, None)?;
            validate_accumulator(&witness.auth.next, &witness.auth.signer_tags, None)?;
            if witness.auth.current.policy_root != witness.auth.next.policy_root
                || witness.auth.current.intent_digest != witness.auth.next.intent_digest
                || witness.auth.current.threshold != witness.auth.next.threshold
                || witness.auth.current.signer_count != witness.auth.next.signer_count
                || witness.auth.next.approval_count != witness.auth.current.approval_count + 1
            {
                return Err(RelationError::PrivateAuthorization(
                    "approval accumulator transition metadata mismatch",
                ));
            }
            let signer_tag = spend_material[1].0;
            let matches = (0..witness.auth.current.signer_count as usize)
                .filter(|&slot| witness.auth.signer_tags[slot] == signer_tag)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(RelationError::PrivateAuthorization(
                    "approval signer is not a unique active policy member",
                ));
            }
            let chosen = matches[0];
            if witness.auth.current.approved_slots[chosen] {
                return Err(RelationError::PrivateAuthorization("duplicate approval"));
            }
            for slot in 0..MAX_SIGNERS {
                let expected = witness.auth.current.approved_slots[slot] || slot == chosen;
                if witness.auth.next.approved_slots[slot] != expected {
                    return Err(RelationError::PrivateAuthorization(
                        "next approved-slot vector mismatch",
                    ));
                }
            }
            let current_keys = accumulator_keys(&witness.auth.current);
            let next_key = accumulator_digest(&witness.auth.next);
            Ok(ResolvedAuth {
                input_auth_keys: [current_keys.0, spend_material[1].0],
                input_nullifier_keys: [current_keys.1, spend_material[1].1],
                output0_auth_key: Some(next_key),
            })
        }
        PrivateAuthMode::ValueLockCreation => {
            if !witness.inputs.iter().any(|input| input.active) || !witness.outputs[0].active {
                return Err(RelationError::PrivateAuthorization(
                    "value-lock creation requires an ordinary input and output zero",
                ));
            }
            if !witness.auth.next.is_zero() {
                return Err(RelationError::PrivateAuthorization(
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
            validate_accumulator(&witness.auth.current, &witness.auth.signer_tags, None)?;
            if witness.auth.current.approval_count != 0
                || witness.auth.current.approved_slots != [false; MAX_SIGNERS]
            {
                return Err(RelationError::PrivateAuthorization(
                    "value-lock policy descriptor must have zero approvals",
                ));
            }
            let value_lock = value_lock_keys(
                witness.auth.current.policy_root,
                witness.auth.current.intent_digest,
            );
            Ok(ResolvedAuth {
                input_auth_keys: [spend_material[0].0, spend_material[1].0],
                input_nullifier_keys: [spend_material[0].1, spend_material[1].1],
                output0_auth_key: Some(value_lock.0),
            })
        }
        PrivateAuthMode::FinalThresholdSpend => {
            if !witness.inputs.iter().all(|input| input.active) || !witness.auth.next.is_zero() {
                return Err(RelationError::PrivateAuthorization(
                    "final spend requires two inputs and zero next accumulator",
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
                .any(|input| input.spend_key != [0; 48])
            {
                return Err(RelationError::PrivateAuthorization(
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
                Some(intent),
            )?;
            if witness.auth.current.approval_count < witness.auth.current.threshold {
                return Err(RelationError::PrivateAuthorization(
                    "approval threshold not reached",
                ));
            }
            let accumulator = accumulator_keys(&witness.auth.current);
            let value_lock = value_lock_keys(
                witness.auth.current.policy_root,
                witness.auth.current.intent_digest,
            );
            Ok(ResolvedAuth {
                input_auth_keys: [value_lock.0, accumulator.0],
                input_nullifier_keys: [value_lock.1, accumulator.1],
                output0_auth_key: None,
            })
        }
    }
}

fn require_note_kind(
    note: &NoteOpening,
    expected: NoteKind,
    error: &'static str,
) -> Result<(), RelationError> {
    if note.kind != expected {
        return Err(RelationError::PrivateAuthorization(error));
    }
    Ok(())
}

fn require_active_inputs_kind(
    witness: &FullWitness,
    expected: NoteKind,
    error: &'static str,
) -> Result<(), RelationError> {
    if witness
        .inputs
        .iter()
        .any(|input| input.active && input.note.kind != expected)
    {
        return Err(RelationError::PrivateAuthorization(error));
    }
    Ok(())
}

fn require_active_outputs_kind(
    witness: &FullWitness,
    expected: NoteKind,
    error: &'static str,
) -> Result<(), RelationError> {
    if witness
        .outputs
        .iter()
        .any(|output| output.active && output.note.kind != expected)
    {
        return Err(RelationError::PrivateAuthorization(error));
    }
    Ok(())
}

fn require_optional_ordinary_output1(witness: &FullWitness) -> Result<(), RelationError> {
    if witness.outputs[1].active && witness.outputs[1].note.kind != NoteKind::Ordinary {
        return Err(RelationError::PrivateAuthorization(
            "optional output one must be an ordinary note",
        ));
    }
    Ok(())
}

fn require_zero_native_accumulator_note(
    note: &NoteOpening,
    error: &'static str,
) -> Result<(), RelationError> {
    if note.value != 0 || note.asset_id != NATIVE_ASSET_ID {
        return Err(RelationError::PrivateAuthorization(error));
    }
    Ok(())
}

fn validate_accumulator(
    opening: &AccumulatorOpening,
    signer_tags: &[Digest; MAX_SIGNERS],
    expected_intent: Option<Digest>,
) -> Result<(), RelationError> {
    if !(1..=MAX_SIGNERS as u64).contains(&opening.signer_count)
        || !(1..=opening.signer_count).contains(&opening.threshold)
        || opening.approval_count > opening.signer_count
        || expected_intent.is_some_and(|intent| opening.intent_digest != intent)
    {
        return Err(RelationError::PrivateAuthorization(
            "invalid accumulator counts or intent",
        ));
    }
    require_nonzero(opening.intent_digest, "accumulator intent")?;
    if opening.approved_slots.iter().filter(|&&bit| bit).count() as u64 != opening.approval_count {
        return Err(RelationError::PrivateAuthorization(
            "approval count does not equal approved slots",
        ));
    }
    for slot in 0..MAX_SIGNERS {
        if slot < opening.signer_count as usize {
            require_nonzero(signer_tags[slot], "active signer tag")?;
            if signer_tags[..slot].contains(&signer_tags[slot]) {
                return Err(RelationError::PrivateAuthorization(
                    "duplicate active signer tag",
                ));
            }
        } else if signer_tags[slot] != [0; DIGEST_BYTES] || opening.approved_slots[slot] {
            return Err(RelationError::PrivateAuthorization(
                "inactive policy slot is nonzero",
            ));
        }
    }
    if opening.policy_root != policy_root(opening.threshold, opening.signer_count, signer_tags) {
        return Err(RelationError::PrivateAuthorization("policy root mismatch"));
    }
    Ok(())
}

/// Resolve the state committed by the inactive next-accumulator lane. Final
/// spends preserve policy/intent metadata and consume all approvals; other
/// modes use the witness-provided next state verbatim.
pub fn effective_next_accumulator(auth: &PrivateAuthWitness) -> AccumulatorOpening {
    match auth.mode {
        PrivateAuthMode::FinalThresholdSpend => AccumulatorOpening {
            policy_root: auth.current.policy_root,
            intent_digest: auth.current.intent_digest,
            threshold: auth.current.threshold,
            signer_count: auth.current.signer_count,
            approval_count: 0,
            approved_slots: [false; MAX_SIGNERS],
        },
        _ => auth.next.clone(),
    }
}

fn validate_note(note: &NoteOpening) -> Result<(), RelationError> {
    if note.value > MAX_NOTE_VALUE {
        return Err(RelationError::ValueOutOfRange("note value"));
    }
    if !is_canonical_asset(note.asset_id) {
        return Err(RelationError::InvalidAssetSlots);
    }
    Ok(())
}

fn validate_slots(slots: [u64; BALANCE_SLOTS]) -> Result<(), RelationError> {
    if slots[0] != NATIVE_ASSET_ID {
        return Err(RelationError::InvalidAssetSlots);
    }
    let mut padding = false;
    let mut previous = NATIVE_ASSET_ID;
    for asset in slots.into_iter().skip(1) {
        if asset == PADDING_ASSET_ID {
            padding = true;
        } else if padding || !is_canonical_asset(asset) || asset <= previous {
            return Err(RelationError::InvalidAssetSlots);
        } else {
            previous = asset;
        }
    }
    Ok(())
}

fn validate_stablecoin(statement: &FullStatement) -> Result<(), RelationError> {
    let stable = &statement.stablecoin;
    if !stable.enabled {
        if stable != &StablecoinBinding::default() {
            return Err(RelationError::Stablecoin("disabled binding is nonzero"));
        }
        return Ok(());
    }
    stable.issuance_delta.as_i128()?;
    if stable.asset_id == NATIVE_ASSET_ID
        || !is_canonical_asset(stable.asset_id)
        || !statement.balance_slot_asset_ids.contains(&stable.asset_id)
        || stable.policy_version == 0
    {
        return Err(RelationError::Stablecoin(
            "invalid stablecoin asset or version",
        ));
    }
    if stable.issuance_delta.magnitude == 0 {
        return Err(RelationError::Stablecoin(
            "enabled stablecoin issuance must be nonzero",
        ));
    }
    for (name, digest) in [
        ("policy", stable.policy_hash),
        ("oracle", stable.oracle_commitment),
        ("attestation", stable.attestation_commitment),
    ] {
        require_nonzero(digest, name)?;
    }
    Ok(())
}

fn selected_slot(
    selectors: [bool; BALANCE_SLOTS],
    slots: [u64; BALANCE_SLOTS],
    asset: u64,
    index: usize,
    role: &'static str,
) -> Result<usize, RelationError> {
    let selected = selectors
        .iter()
        .enumerate()
        .filter_map(|(slot, &bit)| bit.then_some(slot))
        .collect::<Vec<_>>();
    if selected.len() != 1 || slots[selected[0]] != asset || asset == PADDING_ASSET_ID {
        return Err(RelationError::AssetSelector(index, role));
    }
    Ok(selected[0])
}

fn is_canonical_asset(asset: u64) -> bool {
    asset < FIELD_MODULUS && asset != RESERVED_REDUCED_PADDING_ASSET_ID
}

fn require_nonzero(value: Digest, field: &'static str) -> Result<(), RelationError> {
    if value == [0; DIGEST_BYTES] {
        Err(RelationError::ZeroDigest(field))
    } else {
        Ok(())
    }
}

fn spend_keys(spend_key: &[u8; 48]) -> (Digest, Digest) {
    let output = shake_frame::<{ DIGEST_BYTES * 2 }>(&frame(
        ROLE_SPEND_KEYS,
        &[&KEY_OUTPUT_ORDER_TAG, spend_key],
    ));
    let mut auth = [0; DIGEST_BYTES];
    let mut nf = [0; DIGEST_BYTES];
    auth.copy_from_slice(&output[..DIGEST_BYTES]);
    nf.copy_from_slice(&output[DIGEST_BYTES..]);
    (auth, nf)
}

fn nullifier(key: Digest, position: u64, rho: [u8; 48]) -> Digest {
    hash_fields(ROLE_NULLIFIER, &[&key, &position.to_be_bytes(), &rho])
}

fn merkle_parent(left: Digest, right: Digest) -> Digest {
    hash_fields(ROLE_MERKLE, &[&left, &right])
}

fn fold_path(mut current: Digest, position: u64, siblings: &[Digest; MERKLE_DEPTH]) -> Digest {
    for (level, sibling) in siblings.iter().enumerate() {
        current = if (position >> level) & 1 == 0 {
            merkle_parent(current, *sibling)
        } else {
            merkle_parent(*sibling, current)
        };
    }
    current
}

pub fn policy_root(threshold: u64, signer_count: u64, tags: &[Digest; MAX_SIGNERS]) -> Digest {
    let threshold_bytes = threshold.to_be_bytes();
    let signer_count_bytes = signer_count.to_be_bytes();
    let mut fields: Vec<&[u8]> = vec![&threshold_bytes, &signer_count_bytes];
    fields.extend(tags.iter().map(|tag| tag.as_slice()));
    hash_fields(ROLE_POLICY, &fields)
}

fn accumulator_keys(opening: &AccumulatorOpening) -> (Digest, Digest) {
    let approved = opening.approved_slots.map(u8::from);
    split_key_output(shake_frame::<{ DIGEST_BYTES * 2 }>(&frame(
        ROLE_ACCUMULATOR,
        &[
            &KEY_OUTPUT_ORDER_TAG,
            &opening.policy_root,
            &opening.intent_digest,
            &opening.threshold.to_be_bytes(),
            &opening.signer_count.to_be_bytes(),
            &opening.approval_count.to_be_bytes(),
            &approved,
        ],
    )))
}

pub fn accumulator_digest(opening: &AccumulatorOpening) -> Digest {
    accumulator_keys(opening).0
}

pub fn value_lock_digest(policy_root: Digest, intent: Digest) -> Digest {
    value_lock_keys(policy_root, intent).0
}

fn value_lock_keys(policy_root: Digest, intent: Digest) -> (Digest, Digest) {
    split_key_output(shake_frame::<{ DIGEST_BYTES * 2 }>(&frame(
        ROLE_VALUE_LOCK,
        &[&KEY_OUTPUT_ORDER_TAG, &policy_root, &intent],
    )))
}

fn split_key_output(output: [u8; DIGEST_BYTES * 2]) -> (Digest, Digest) {
    let mut auth = [0; DIGEST_BYTES];
    let mut nf = [0; DIGEST_BYTES];
    auth.copy_from_slice(&output[..DIGEST_BYTES]);
    nf.copy_from_slice(&output[DIGEST_BYTES..]);
    (auth, nf)
}

pub fn intent_digest(statement: &FullStatement) -> Digest {
    let bytes = encode_statement_for_intent(statement);
    hash_fields(ROLE_INTENT, &[&bytes])
}

/// Deterministic V5/Delta balance identity. This replaces the incompatible
/// 48-byte SmallWood balance commitment; no truncation or field reduction is
/// permitted at the action/state boundary.
pub fn expected_balance_tag(statement: &FullStatement) -> Digest {
    let value_balance_sign = [u8::from(statement.value_balance.negative)];
    let stable_enabled = [u8::from(statement.stablecoin.enabled)];
    let stable_issuance_sign = [u8::from(statement.stablecoin.issuance_delta.negative)];
    let mut assets = [0u8; BALANCE_SLOTS * 8];
    for (index, asset) in statement.balance_slot_asset_ids.iter().enumerate() {
        assets[index * 8..index * 8 + 8].copy_from_slice(&asset.to_be_bytes());
    }
    hash_fields(
        ROLE_BALANCE_TAG,
        &[
            &statement.fee.to_be_bytes(),
            &value_balance_sign,
            &statement.value_balance.magnitude.to_be_bytes(),
            &assets,
            &stable_enabled,
            &statement.stablecoin.asset_id.to_be_bytes(),
            &stable_issuance_sign,
            &statement.stablecoin.issuance_delta.magnitude.to_be_bytes(),
        ],
    )
}

fn frame(role: [u8; 8], fields: &[&[u8]]) -> Vec<u8> {
    let mut output =
        Vec::with_capacity(17 + fields.iter().map(|field| 2 + field.len()).sum::<usize>());
    output.extend_from_slice(&PROFILE_TAG);
    output.extend_from_slice(&role);
    output.push(fields.len() as u8);
    for field in fields {
        output.extend_from_slice(&(field.len() as u16).to_be_bytes());
        output.extend_from_slice(field);
    }
    output
}

fn hash_fields(role: [u8; 8], fields: &[&[u8]]) -> Digest {
    shake_frame::<DIGEST_BYTES>(&frame(role, fields))
}

fn shake_frame<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut hasher = Shake256::default();
    hasher.update(bytes);
    let mut reader = hasher.finalize_xof();
    let mut output = [0; N];
    reader.read(&mut output);
    output
}

pub fn encode_statement_for_intent(statement: &FullStatement) -> Vec<u8> {
    let mut bytes = Vec::new();
    // Bind the reusable private intent to this exact statement language even
    // though the anchor and nullifiers are intentionally omitted below.
    bytes.extend_from_slice(&STATEMENT_MAGIC);
    bytes.extend_from_slice(&STATEMENT_GRAMMAR_VERSION.to_be_bytes());
    bytes.extend(statement.input_flags.map(u8::from));
    bytes.extend(statement.output_flags.map(u8::from));
    // Anchor and nullifiers intentionally do not enter the reusable private
    // authorization intent; every other spend choice does.
    for commitment in statement.commitments {
        bytes.extend_from_slice(&commitment);
    }
    for hash in statement.ciphertext_hashes {
        bytes.extend_from_slice(&hash);
    }
    for asset in statement.balance_slot_asset_ids {
        bytes.extend_from_slice(&asset.to_be_bytes());
    }
    bytes.extend_from_slice(&statement.fee.to_be_bytes());
    push_signed(&mut bytes, statement.value_balance);
    bytes.push(u8::from(statement.stablecoin.enabled));
    bytes.extend_from_slice(&statement.stablecoin.asset_id.to_be_bytes());
    bytes.extend_from_slice(&statement.stablecoin.policy_version.to_be_bytes());
    push_signed(&mut bytes, statement.stablecoin.issuance_delta);
    bytes.extend_from_slice(&statement.stablecoin.policy_hash);
    bytes.extend_from_slice(&statement.stablecoin.oracle_commitment);
    bytes.extend_from_slice(&statement.stablecoin.attestation_commitment);
    bytes.extend_from_slice(&statement.balance_tag);
    push_activation(&mut bytes, &statement.activation);
    bytes
}

fn push_signed(bytes: &mut Vec<u8>, value: SignedAmount) {
    bytes.push(u8::from(value.negative));
    bytes.extend_from_slice(&value.magnitude.to_be_bytes());
}

fn push_activation(bytes: &mut Vec<u8>, activation: &ActivationBinding) {
    bytes.extend_from_slice(&activation.circuit_version.to_be_bytes());
    bytes.extend_from_slice(&activation.crypto_suite.to_be_bytes());
    bytes.extend_from_slice(&activation.family_id.to_be_bytes());
    bytes.extend_from_slice(&activation.action_id.to_be_bytes());
    bytes.extend_from_slice(&activation.backend_id);
    bytes.extend_from_slice(&activation.proof_profile);
    bytes.extend_from_slice(&activation.chain_id);
    bytes.extend_from_slice(&activation.genesis_block_id);
    bytes.extend_from_slice(&activation.rules_hash);
}

/// Encode the complete public statement in one fixed, byte-exact grammar.
/// All integers are big-endian and there are no optional, variable-length, or
/// ignored trailing fields.
pub fn encode_canonical_statement(
    statement: &FullStatement,
) -> Result<[u8; CANONICAL_STATEMENT_BYTES], StatementEncodeError> {
    require_canonical_signed_encoding(statement.value_balance, "value_balance")?;
    require_canonical_signed_encoding(
        statement.stablecoin.issuance_delta,
        "stablecoin.issuance_delta",
    )?;
    let mut bytes = Vec::with_capacity(CANONICAL_STATEMENT_BYTES);
    bytes.extend_from_slice(&STATEMENT_MAGIC);
    bytes.extend_from_slice(&STATEMENT_GRAMMAR_VERSION.to_be_bytes());
    bytes.extend(statement.input_flags.map(u8::from));
    bytes.extend(statement.output_flags.map(u8::from));
    bytes.extend_from_slice(&statement.anchor);
    for digest in statement.nullifiers {
        bytes.extend_from_slice(&digest);
    }
    for digest in statement.commitments {
        bytes.extend_from_slice(&digest);
    }
    for digest in statement.ciphertext_hashes {
        bytes.extend_from_slice(&digest);
    }
    for asset in statement.balance_slot_asset_ids {
        bytes.extend_from_slice(&asset.to_be_bytes());
    }
    bytes.extend_from_slice(&statement.fee.to_be_bytes());
    push_signed(&mut bytes, statement.value_balance);
    bytes.push(u8::from(statement.stablecoin.enabled));
    bytes.extend_from_slice(&statement.stablecoin.asset_id.to_be_bytes());
    bytes.extend_from_slice(&statement.stablecoin.policy_version.to_be_bytes());
    push_signed(&mut bytes, statement.stablecoin.issuance_delta);
    bytes.extend_from_slice(&statement.stablecoin.policy_hash);
    bytes.extend_from_slice(&statement.stablecoin.oracle_commitment);
    bytes.extend_from_slice(&statement.stablecoin.attestation_commitment);
    bytes.extend_from_slice(&statement.balance_tag);
    push_activation(&mut bytes, &statement.activation);
    Ok(bytes
        .try_into()
        .expect("the full statement grammar length is a compile-time constant"))
}

fn require_canonical_signed_encoding(
    value: SignedAmount,
    field: &'static str,
) -> Result<(), StatementEncodeError> {
    if value.magnitude > MAX_NOTE_VALUE || (value.negative && value.magnitude == 0) {
        Err(StatementEncodeError::NonCanonicalSignedAmount(field))
    } else {
        Ok(())
    }
}

/// Decode exactly one canonical full statement. Short input, trailing input,
/// alternate magic/version, non-binary flags, and negative zero all fail
/// closed before any circuit or proof parser is entered.
pub fn decode_canonical_statement(bytes: &[u8]) -> Result<FullStatement, StatementDecodeError> {
    if bytes.len() != CANONICAL_STATEMENT_BYTES {
        return Err(StatementDecodeError::Length {
            expected: CANONICAL_STATEMENT_BYTES,
            actual: bytes.len(),
        });
    }
    let mut cursor = StatementCursor { bytes, offset: 0 };
    if cursor.array::<8>() != STATEMENT_MAGIC {
        return Err(StatementDecodeError::Magic);
    }
    let grammar_version = cursor.u16();
    if grammar_version != STATEMENT_GRAMMAR_VERSION {
        return Err(StatementDecodeError::GrammarVersion(grammar_version));
    }
    let input_flags = [
        cursor.boolean("input_flags[0]")?,
        cursor.boolean("input_flags[1]")?,
    ];
    let output_flags = [
        cursor.boolean("output_flags[0]")?,
        cursor.boolean("output_flags[1]")?,
    ];
    let anchor = cursor.array();
    let nullifiers = core::array::from_fn(|_| cursor.array());
    let commitments = core::array::from_fn(|_| cursor.array());
    let ciphertext_hashes = core::array::from_fn(|_| cursor.array());
    let balance_slot_asset_ids = core::array::from_fn(|_| cursor.u64());
    let fee = cursor.u64();
    let value_balance = cursor.signed("value_balance")?;
    let stablecoin = StablecoinBinding {
        enabled: cursor.boolean("stablecoin.enabled")?,
        asset_id: cursor.u64(),
        policy_version: cursor.u32(),
        issuance_delta: cursor.signed("stablecoin.issuance_delta")?,
        policy_hash: cursor.array(),
        oracle_commitment: cursor.array(),
        attestation_commitment: cursor.array(),
    };
    let balance_tag = cursor.array();
    let activation = ActivationBinding {
        circuit_version: cursor.u16(),
        crypto_suite: cursor.u16(),
        family_id: cursor.u16(),
        action_id: cursor.u16(),
        backend_id: cursor.array(),
        proof_profile: cursor.array(),
        chain_id: cursor.array(),
        genesis_block_id: cursor.array(),
        rules_hash: cursor.array(),
    };
    debug_assert_eq!(cursor.offset, CANONICAL_STATEMENT_BYTES);
    Ok(FullStatement {
        input_flags,
        output_flags,
        anchor,
        nullifiers,
        commitments,
        ciphertext_hashes,
        balance_slot_asset_ids,
        fee,
        value_balance,
        stablecoin,
        balance_tag,
        activation,
    })
}

pub fn verify_canonical_statement(
    bytes: &[u8],
    witness: &FullWitness,
    expected_activation: &ActivationBinding,
) -> Result<RelationStats, CanonicalVerificationError> {
    let statement =
        decode_canonical_statement(bytes).map_err(CanonicalVerificationError::Decode)?;
    verify_relation_with_expected_activation(&statement, witness, expected_activation)
        .map_err(CanonicalVerificationError::Relation)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalVerificationError {
    Decode(StatementDecodeError),
    Relation(RelationError),
}

impl fmt::Display for CanonicalVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CanonicalVerificationError {}

struct StatementCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl StatementCursor<'_> {
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let value = self.bytes[self.offset..self.offset + N]
            .try_into()
            .expect("the statement length was checked before decoding");
        self.offset += N;
        value
    }

    fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
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

    fn boolean(&mut self, field: &'static str) -> Result<bool, StatementDecodeError> {
        match self.u8() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StatementDecodeError::NonBoolean(field)),
        }
    }

    fn signed(&mut self, field: &'static str) -> Result<SignedAmount, StatementDecodeError> {
        let negative = self.boolean(field)?;
        let magnitude = self.u64();
        if magnitude > MAX_NOTE_VALUE || (negative && magnitude == 0) {
            return Err(StatementDecodeError::NonCanonicalSignedAmount(field));
        }
        Ok(SignedAmount {
            negative,
            magnitude,
        })
    }
}

pub fn mask_fixture(mask: u8) -> (FullStatement, FullWitness) {
    assert!(mask < 16);
    let input_flags = [mask & 1 != 0, mask & 2 != 0];
    let output_flags = [mask & 4 != 0, mask & 8 != 0];
    let mut inputs = [InputWitness::zero(), InputWitness::zero()];
    let mut outputs = [OutputWitness::zero(), OutputWitness::zero()];
    let total_inputs = input_flags.iter().filter(|&&bit| bit).count() as u64 * 100;
    let active_outputs = output_flags.iter().filter(|&&bit| bit).count() as u64;
    let fee = u64::from(total_inputs > 0 && active_outputs > 0);
    let distributable = total_inputs.saturating_sub(fee);
    for index in 0..MAX_INPUTS {
        if input_flags[index] {
            let spend_key = [0x10 + index as u8; 48];
            let auth = spend_keys(&spend_key).0;
            inputs[index] = InputWitness {
                active: true,
                spend_key,
                note: NoteOpening {
                    kind: NoteKind::Ordinary,
                    value: 100,
                    asset_id: 0,
                    pk_recipient: [0x20 + index as u8; 32],
                    rho: [0x30 + index as u8; 48],
                    randomness: [0x40 + index as u8; 48],
                    pk_auth: auth,
                },
                position: [5, 11][index],
                siblings: [[0; DIGEST_BYTES]; MERKLE_DEPTH],
                balance_slot_selectors: [true, false, false, false],
            };
        }
    }
    let mut remaining = distributable;
    for index in 0..MAX_OUTPUTS {
        if output_flags[index] {
            let value = if index == MAX_OUTPUTS - 1 || output_flags[index + 1..].iter().all(|&v| !v)
            {
                remaining
            } else {
                distributable / active_outputs
            };
            remaining -= value;
            outputs[index] = OutputWitness {
                active: true,
                note: NoteOpening {
                    kind: NoteKind::Ordinary,
                    value,
                    asset_id: 0,
                    pk_recipient: [0x50 + index as u8; 32],
                    rho: [0x60 + index as u8; 48],
                    randomness: [0x70 + index as u8; 48],
                    pk_auth: [0x80 + index as u8; DIGEST_BYTES],
                },
                balance_slot_selectors: [true, false, false, false],
            };
        }
    }
    let commitments = inputs.clone().map(|input| {
        if input.active {
            input.note.commitment()
        } else {
            [0; DIGEST_BYTES]
        }
    });
    let (anchor, paths) = sparse_paths(&commitments, [5, 11]);
    for index in 0..MAX_INPUTS {
        if inputs[index].active {
            inputs[index].siblings = paths[index];
        }
    }
    let witness = FullWitness {
        inputs,
        outputs,
        auth: PrivateAuthWitness::default(),
    };
    let mut statement = FullStatement {
        input_flags,
        output_flags,
        anchor,
        nullifiers: [[0; DIGEST_BYTES]; MAX_INPUTS],
        commitments: [[0; DIGEST_BYTES]; MAX_OUTPUTS],
        ciphertext_hashes: core::array::from_fn(|index| {
            if output_flags[index] {
                [0xa0 + index as u8; DIGEST_BYTES]
            } else {
                [0; DIGEST_BYTES]
            }
        }),
        balance_slot_asset_ids: [0, PADDING_ASSET_ID, PADDING_ASSET_ID, PADDING_ASSET_ID],
        fee,
        value_balance: SignedAmount::default(),
        stablecoin: StablecoinBinding::default(),
        balance_tag: [0; DIGEST_BYTES],
        activation: ActivationBinding::canonical_fixture(),
    };
    for index in 0..MAX_INPUTS {
        if witness.inputs[index].active {
            let (_, key) = spend_keys(&witness.inputs[index].spend_key);
            statement.nullifiers[index] = nullifier(
                key,
                witness.inputs[index].position,
                witness.inputs[index].note.rho,
            );
        }
    }
    for index in 0..MAX_OUTPUTS {
        if witness.outputs[index].active {
            statement.commitments[index] = witness.outputs[index].note.commitment();
        }
    }
    statement.balance_tag = expected_balance_tag(&statement);
    (statement, witness)
}

/// Recompute every public value derived solely from the witness and refresh
/// active input Merkle paths in place. Inactive private payloads are never
/// normalized or erased: malformed fixtures remain malformed and therefore
/// fail the canonical-inactivity gate when verified.
pub fn refresh_derived_statement(statement: &mut FullStatement, witness: &mut FullWitness) {
    statement.input_flags = core::array::from_fn(|index| witness.inputs[index].active);
    statement.output_flags = core::array::from_fn(|index| witness.outputs[index].active);
    let input_commitments = core::array::from_fn(|index| {
        if witness.inputs[index].active {
            witness.inputs[index].note.commitment()
        } else {
            [0; DIGEST_BYTES]
        }
    });
    let positions = core::array::from_fn(|index| witness.inputs[index].position);
    let (anchor, paths) = sparse_paths(&input_commitments, positions);
    statement.anchor = anchor;
    for index in 0..MAX_INPUTS {
        if witness.inputs[index].active {
            witness.inputs[index].siblings = paths[index];
            statement.nullifiers[index] = nullifier(
                unchecked_input_nullifier_key(witness, index),
                witness.inputs[index].position,
                witness.inputs[index].note.rho,
            );
        } else {
            statement.nullifiers[index] = [0; DIGEST_BYTES];
        }
    }
    for index in 0..MAX_OUTPUTS {
        if witness.outputs[index].active {
            statement.commitments[index] = witness.outputs[index].note.commitment();
        } else {
            statement.commitments[index] = [0; DIGEST_BYTES];
            statement.ciphertext_hashes[index] = [0; DIGEST_BYTES];
        }
    }
    statement.balance_tag = expected_balance_tag(statement);
}

fn unchecked_input_nullifier_key(witness: &FullWitness, index: usize) -> Digest {
    match witness.auth.mode {
        PrivateAuthMode::SingleKey
        | PrivateAuthMode::AccumulatorInit
        | PrivateAuthMode::ValueLockCreation => spend_keys(&witness.inputs[index].spend_key).1,
        PrivateAuthMode::ApprovalStep if index == 0 => accumulator_keys(&witness.auth.current).1,
        PrivateAuthMode::ApprovalStep => spend_keys(&witness.inputs[index].spend_key).1,
        PrivateAuthMode::FinalThresholdSpend if index == 0 => {
            value_lock_keys(
                witness.auth.current.policy_root,
                witness.auth.current.intent_digest,
            )
            .1
        }
        PrivateAuthMode::FinalThresholdSpend => accumulator_keys(&witness.auth.current).1,
    }
}

fn sparse_paths(
    commitments: &[Digest; MAX_INPUTS],
    positions: [u64; MAX_INPUTS],
) -> (Digest, [[Digest; MERKLE_DEPTH]; MAX_INPUTS]) {
    use std::collections::BTreeMap;
    let mut defaults = [[0; DIGEST_BYTES]; MERKLE_DEPTH + 1];
    for level in 1..=MERKLE_DEPTH {
        defaults[level] = merkle_parent(defaults[level - 1], defaults[level - 1]);
    }
    let mut nodes = BTreeMap::new();
    for index in 0..MAX_INPUTS {
        if commitments[index] != [0; DIGEST_BYTES] {
            nodes.insert(positions[index], commitments[index]);
        }
    }
    let mut paths = [[[0; DIGEST_BYTES]; MERKLE_DEPTH]; MAX_INPUTS];
    for level in 0..MERKLE_DEPTH {
        for index in 0..MAX_INPUTS {
            if commitments[index] != [0; DIGEST_BYTES] {
                paths[index][level] = nodes
                    .get(&((positions[index] >> level) ^ 1))
                    .copied()
                    .unwrap_or(defaults[level]);
            }
        }
        let mut parents = BTreeMap::new();
        for &node_index in nodes.keys() {
            let parent = node_index >> 1;
            if parents.contains_key(&parent) {
                continue;
            }
            let left = nodes
                .get(&(parent << 1))
                .copied()
                .unwrap_or(defaults[level]);
            let right = nodes
                .get(&((parent << 1) | 1))
                .copied()
                .unwrap_or(defaults[level]);
            parents.insert(parent, merkle_parent(left, right));
        }
        nodes = parents;
    }
    (
        nodes.get(&0).copied().unwrap_or(defaults[MERKLE_DEPTH]),
        paths,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        core::array::from_fn(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap()
        })
    }

    fn kat_statement() -> FullStatement {
        let mut statement = FullStatement {
            input_flags: [true, false],
            output_flags: [true, true],
            anchor: [0xaa; DIGEST_BYTES],
            nullifiers: [[0xbb; DIGEST_BYTES], [0xcc; DIGEST_BYTES]],
            commitments: [[1; DIGEST_BYTES], [2; DIGEST_BYTES]],
            ciphertext_hashes: [[3; DIGEST_BYTES], [4; DIGEST_BYTES]],
            balance_slot_asset_ids: [0, 7, PADDING_ASSET_ID, PADDING_ASSET_ID],
            fee: 9,
            value_balance: SignedAmount {
                negative: false,
                magnitude: 2,
            },
            stablecoin: StablecoinBinding {
                enabled: true,
                asset_id: 7,
                policy_version: 3,
                issuance_delta: SignedAmount {
                    negative: true,
                    magnitude: 4,
                },
                policy_hash: [5; DIGEST_BYTES],
                oracle_commitment: [6; DIGEST_BYTES],
                attestation_commitment: [7; DIGEST_BYTES],
            },
            balance_tag: [0; DIGEST_BYTES],
            activation: ActivationBinding::canonical_fixture(),
        };
        statement.balance_tag = expected_balance_tag(&statement);
        statement
    }

    fn stablecoin_fixture() -> (FullStatement, FullWitness) {
        let (mut statement, mut witness) = mask_fixture(0b1111);
        statement.balance_slot_asset_ids = [0, 7, PADDING_ASSET_ID, PADDING_ASSET_ID];
        witness.inputs[0].note.value = 100;
        witness.inputs[0].balance_slot_selectors = [true, false, false, false];
        witness.inputs[1].note.asset_id = 7;
        witness.inputs[1].note.value = 50;
        witness.inputs[1].balance_slot_selectors = [false, true, false, false];
        witness.outputs[0].note.value = 99;
        witness.outputs[0].balance_slot_selectors = [true, false, false, false];
        witness.outputs[1].note.asset_id = 7;
        witness.outputs[1].note.value = 60;
        witness.outputs[1].balance_slot_selectors = [false, true, false, false];
        statement.fee = 1;
        statement.stablecoin = StablecoinBinding {
            enabled: true,
            asset_id: 7,
            policy_version: 1,
            issuance_delta: SignedAmount {
                negative: true,
                magnitude: 10,
            },
            policy_hash: [0xb1; DIGEST_BYTES],
            oracle_commitment: [0xb2; DIGEST_BYTES],
            attestation_commitment: [0xb3; DIGEST_BYTES],
        };
        refresh_derived_statement(&mut statement, &mut witness);
        (statement, witness)
    }

    fn signer_tags_with_member(member: Digest) -> [Digest; MAX_SIGNERS] {
        [
            spend_keys(&[0x91; 48]).0,
            member,
            spend_keys(&[0x93; 48]).0,
            [0; DIGEST_BYTES],
            [0; DIGEST_BYTES],
            [0; DIGEST_BYTES],
        ]
    }

    fn approval_fixture() -> (FullStatement, FullWitness) {
        let (mut statement, mut witness) = mask_fixture(0b1111);
        // Accumulator notes are state tokens, not value-bearing notes.  The
        // signer input alone funds the approval fee and signer change.
        witness.inputs[0].note.kind = NoteKind::Accumulator;
        witness.outputs[0].note.kind = NoteKind::Accumulator;
        witness.inputs[0].note.value = 0;
        witness.outputs[0].note.value = 0;
        witness.outputs[1].note.value = 99;
        let member = spend_keys(&witness.inputs[1].spend_key).0;
        let tags = signer_tags_with_member(member);
        let chosen = tags
            .iter()
            .position(|tag| *tag == member)
            .expect("fixture member is in the active policy");
        let already_approved = (chosen + 1) % 3;
        let mut current_slots = [false; MAX_SIGNERS];
        current_slots[already_approved] = true;
        let mut next_slots = current_slots;
        next_slots[chosen] = true;
        let root = policy_root(2, 3, &tags);
        let current = AccumulatorOpening {
            policy_root: root,
            intent_digest: [0xc1; DIGEST_BYTES],
            threshold: 2,
            signer_count: 3,
            approval_count: 1,
            approved_slots: current_slots,
        };
        let next = AccumulatorOpening {
            policy_root: root,
            intent_digest: current.intent_digest,
            threshold: 2,
            signer_count: 3,
            approval_count: 2,
            approved_slots: next_slots,
        };
        witness.auth = PrivateAuthWitness {
            mode: PrivateAuthMode::ApprovalStep,
            current,
            next,
            signer_tags: tags,
        };
        witness.inputs[0].spend_key = [0; 48];
        witness.inputs[0].note.pk_auth = accumulator_digest(&witness.auth.current);
        witness.inputs[1].note.pk_auth = member;
        witness.outputs[0].note.pk_auth = accumulator_digest(&witness.auth.next);
        refresh_derived_statement(&mut statement, &mut witness);
        (statement, witness)
    }

    fn accumulator_init_fixture() -> (FullStatement, FullWitness) {
        let (mut statement, mut witness) = mask_fixture(0b1111);
        witness.outputs[0].note.kind = NoteKind::Accumulator;
        witness.outputs[0].note.value = 0;
        witness.outputs[1].note.value = 199;
        let member = spend_keys(&witness.inputs[0].spend_key).0;
        let tags = signer_tags_with_member(member);
        let next = AccumulatorOpening {
            policy_root: policy_root(2, 3, &tags),
            intent_digest: [0xd1; DIGEST_BYTES],
            threshold: 2,
            signer_count: 3,
            approval_count: 0,
            approved_slots: [false; MAX_SIGNERS],
        };
        witness.auth = PrivateAuthWitness {
            mode: PrivateAuthMode::AccumulatorInit,
            current: AccumulatorOpening::zero(),
            next,
            signer_tags: tags,
        };
        witness.outputs[0].note.pk_auth = accumulator_digest(&witness.auth.next);
        refresh_derived_statement(&mut statement, &mut witness);
        (statement, witness)
    }

    fn value_lock_creation_fixture() -> (FullStatement, FullWitness) {
        let (mut statement, mut witness) = mask_fixture(0b1111);
        witness.outputs[0].note.kind = NoteKind::ValueLock;
        witness.outputs[0].note.value = 100;
        witness.outputs[1].note.value = 99;
        let member = spend_keys(&witness.inputs[0].spend_key).0;
        let tags = signer_tags_with_member(member);
        let current = AccumulatorOpening {
            policy_root: policy_root(2, 3, &tags),
            intent_digest: [0xd2; DIGEST_BYTES],
            threshold: 2,
            signer_count: 3,
            approval_count: 0,
            approved_slots: [false; MAX_SIGNERS],
        };
        witness.auth = PrivateAuthWitness {
            mode: PrivateAuthMode::ValueLockCreation,
            current,
            next: AccumulatorOpening::zero(),
            signer_tags: tags,
        };
        witness.outputs[0].note.pk_auth = value_lock_digest(
            witness.auth.current.policy_root,
            witness.auth.current.intent_digest,
        );
        refresh_derived_statement(&mut statement, &mut witness);
        (statement, witness)
    }

    fn final_fixture() -> (FullStatement, FullWitness) {
        let (mut statement, mut witness) = mask_fixture(0b1111);
        // Input one is the zero-value accumulator state token.  Input zero is
        // the value-lock note and alone funds both outputs plus the fee.
        witness.inputs[0].note.kind = NoteKind::ValueLock;
        witness.inputs[1].note.kind = NoteKind::Accumulator;
        witness.inputs[1].note.value = 0;
        witness.outputs[0].note.value = 49;
        witness.outputs[1].note.value = 50;
        // The final authorization intent commits to output commitments, so
        // refresh those commitments before deriving the intent. A second
        // refresh below incorporates the mode-resolved input authorization.
        refresh_derived_statement(&mut statement, &mut witness);
        let member = spend_keys(&witness.inputs[1].spend_key).0;
        let tags = signer_tags_with_member(member);
        let root = policy_root(2, 3, &tags);
        let intent = intent_digest(&statement);
        witness.auth = PrivateAuthWitness {
            mode: PrivateAuthMode::FinalThresholdSpend,
            current: AccumulatorOpening {
                policy_root: root,
                intent_digest: intent,
                threshold: 2,
                signer_count: 3,
                approval_count: 2,
                approved_slots: [true, true, false, false, false, false],
            },
            next: AccumulatorOpening::zero(),
            signer_tags: tags,
        };
        witness.inputs[0].spend_key = [0; 48];
        witness.inputs[1].spend_key = [0; 48];
        witness.inputs[0].note.pk_auth = value_lock_digest(root, intent);
        witness.inputs[1].note.pk_auth = accumulator_digest(&witness.auth.current);
        refresh_derived_statement(&mut statement, &mut witness);
        assert_eq!(intent_digest(&statement), intent);
        (statement, witness)
    }

    #[test]
    fn all_sixteen_activity_masks_match_the_full_shape_rule() {
        for mask in 0u8..16 {
            let (statement, witness) = mask_fixture(mask);
            let expected = mask & 0b0011 != 0 && mask & 0b1100 != 0;
            assert_eq!(
                verify_relation(&statement, &witness).is_ok(),
                expected,
                "mask {mask:04b}"
            );
        }
    }

    #[test]
    fn stablecoin_and_four_slot_conservation_is_real() {
        let (mut statement, witness) = stablecoin_fixture();
        assert!(verify_relation(&statement, &witness).is_ok());
        statement.stablecoin.issuance_delta.magnitude = 9;
        assert!(matches!(
            verify_relation(&statement, &witness),
            Err(RelationError::Balance(7))
        ));
    }

    #[test]
    fn every_shake_role_has_an_independent_fixed_kat() {
        let mut note = NoteOpening {
            kind: NoteKind::Ordinary,
            value: 17,
            asset_id: 7,
            pk_recipient: [0x11; 32],
            rho: [0x22; 48],
            randomness: [0x33; 48],
            pk_auth: [0x44; DIGEST_BYTES],
        };
        assert_eq!(
            note.commitment(),
            decode_hex(
                "6eb2bd1067e1d2c3a025ed983d92f0194fef74f07177d56331cf502860d9af0ce4a8e86f6851d0a2566aa29751473b0f471c107a8592bbf2"
            )
        );
        note.kind = NoteKind::Accumulator;
        assert_eq!(
            note.commitment(),
            decode_hex(
                "eb616cf612578e2578aaa971078a76bd86852031d5e80f32d26cf10019c539d8a03a17e4ba72a78de8cf637f86e75a356beced26948b3941"
            )
        );
        note.kind = NoteKind::ValueLock;
        assert_eq!(
            note.commitment(),
            decode_hex(
                "e3ec9a93ccb3b6e7c699cf27f96dd681e4885bca1bb3e69d9225907633a04499ea7792aedc9651a4bdbd2699500dda0f441ff9926eb36785"
            )
        );
        assert_eq!(
            nullifier([0x55; DIGEST_BYTES], 9, [0x22; 48]),
            decode_hex(
                "7597847f10b4877bf154f7bd489c02d8c852791fb063d6c5f962570dc2053fc99edd57752fe710ae8e6fd0719e007e71cb0b534c8cbe8b19"
            )
        );
        assert_eq!(
            merkle_parent([0x66; DIGEST_BYTES], [0x77; DIGEST_BYTES]),
            decode_hex(
                "fefbaa863bba92fe058815cd609669766cbed4733814495094f87d7dbf35d6cc6b9e5d289b1c54792d264d86f99cbd9114eb69038da7c758"
            )
        );
        let (auth, nf) = spend_keys(&[0x88; 48]);
        let mut kdf = [0u8; DIGEST_BYTES * 2];
        kdf[..DIGEST_BYTES].copy_from_slice(&auth);
        kdf[DIGEST_BYTES..].copy_from_slice(&nf);
        assert_eq!(
            kdf,
            decode_hex(
                "498e532e38962760529ddb0a108842e4d232356919356005d7e5e408721d160e5bca0e6d3982967e1a515a6c3fa752115257c5f7190869e7116241d00a2eff61684db7696ffcd9631dbc2893fdbcd4c1522428548b919238480a93e145dae8b177423d3b6569b401842104366b57cfd0"
            )
        );
        let tags = core::array::from_fn(|index| [0x10 + index as u8; DIGEST_BYTES]);
        assert_eq!(
            policy_root(2, 3, &tags),
            decode_hex(
                "15e9d0a39780d9447f3b6df956de1933c433dbed59770dc72893d221f18b3162a5e9df23ca9cb9fe3e1290e4be65221571b2bb2c0951e976"
            )
        );
        let opening = AccumulatorOpening {
            policy_root: [0x90; DIGEST_BYTES],
            intent_digest: [0x91; DIGEST_BYTES],
            threshold: 2,
            signer_count: 3,
            approval_count: 2,
            approved_slots: [true, false, true, false, false, false],
        };
        let (accumulator_auth, accumulator_nf) = accumulator_keys(&opening);
        let mut accumulator_output = [0; DIGEST_BYTES * 2];
        accumulator_output[..DIGEST_BYTES].copy_from_slice(&accumulator_auth);
        accumulator_output[DIGEST_BYTES..].copy_from_slice(&accumulator_nf);
        assert_eq!(
            accumulator_output,
            decode_hex(
                "96f621447fbbf161e8387facc8deedb2d8f231f9ce14e3e1639328ad491994598411fa4e60bb2bb1d07ab5ffd4e9e362ce943477ac477596d362c67720ffb032dc3d3d92061fae1c69c9f35bf05d852d2d50555df8bb163f413527f2f62ca94e8768083a831c98102218548bac05cb87"
            )
        );
        let (value_lock_auth, value_lock_nf) =
            value_lock_keys([0x90; DIGEST_BYTES], [0x91; DIGEST_BYTES]);
        let mut value_lock_output = [0; DIGEST_BYTES * 2];
        value_lock_output[..DIGEST_BYTES].copy_from_slice(&value_lock_auth);
        value_lock_output[DIGEST_BYTES..].copy_from_slice(&value_lock_nf);
        assert_eq!(
            value_lock_output,
            decode_hex(
                "baaffee9346836070537b0b79baa3c1e4916ceeb166bb5b9dd7bea39a02ebf4d7588bed358c54a8900c973ec49b6bd0a86f14eaec06bb700980fe4249647514fd88733a7fbba2fe914a6156d918176853fe09c9413bc098895e4844956b5a0ada06773a0016f269c2a8930398fc965dc"
            )
        );
        assert_eq!(
            expected_balance_tag(&kat_statement()),
            decode_hex(
                "f74e0c1d260b87a29027b64348db9c7c7a1f032727e88df30b492e95c963c652a3ebbaa8e8e1a245ef0edee8be25444027fc5b24c53558fa"
            )
        );
        assert_eq!(
            intent_digest(&kat_statement()),
            decode_hex(
                "0028238ffe2d548222998b0b20dc8940d7b04d04828865094bf098b420cf3ca60231aafe59d3a683532c0613b0e23bcf128e79bf22964fa5"
            )
        );
    }

    #[test]
    fn refresh_recomputes_paths_instead_of_checking_stale_paths() {
        let (mut statement, mut witness) = mask_fixture(0b1111);
        witness.inputs[0].note.randomness[0] ^= 1;
        refresh_derived_statement(&mut statement, &mut witness);
        verify_relation(&statement, &witness).unwrap();
    }

    #[test]
    fn accumulator_init_and_value_lock_creation_are_explicit_transitions() {
        let (statement, witness) = accumulator_init_fixture();
        verify_relation(&statement, &witness).unwrap();

        let (statement, witness) = value_lock_creation_fixture();
        verify_relation(&statement, &witness).unwrap();
    }

    #[test]
    fn special_note_lineage_blocks_fake_threshold_seed() {
        let (mut statement, mut witness) = mask_fixture(0b1111);
        let tags = signer_tags_with_member(spend_keys(&witness.inputs[0].spend_key).0);
        let forged = AccumulatorOpening {
            policy_root: policy_root(2, 3, &tags),
            intent_digest: [0xe1; DIGEST_BYTES],
            threshold: 2,
            signer_count: 3,
            approval_count: 2,
            approved_slots: [true, true, false, false, false, false],
        };
        // This was the old exploit seed: an ordinary SingleKey transfer could
        // emit both self-chosen special authorization notes, then attempt a
        // FinalThresholdSpend against a forged threshold-satisfied opening.
        witness.outputs[0].note.kind = NoteKind::Accumulator;
        witness.outputs[0].note.value = 0;
        witness.outputs[0].note.pk_auth = accumulator_digest(&forged);
        witness.outputs[1].note.kind = NoteKind::ValueLock;
        witness.outputs[1].note.value = 199;
        witness.outputs[1].note.pk_auth =
            value_lock_digest(forged.policy_root, forged.intent_digest);
        refresh_derived_statement(&mut statement, &mut witness);
        assert!(matches!(
            verify_relation(&statement, &witness),
            Err(RelationError::PrivateAuthorization(
                "single-key outputs must be ordinary notes"
            ))
        ));
    }

    #[test]
    fn lineage_transition_mutations_fail_closed() {
        let (statement, witness) = accumulator_init_fixture();
        let mut changed = witness.clone();
        changed.auth.next.approval_count = 1;
        changed.auth.next.approved_slots[0] = true;
        changed.outputs[0].note.pk_auth = accumulator_digest(&changed.auth.next);
        let mut changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "initialized accumulator must have zero approvals"
            ))
        ));

        changed = witness.clone();
        changed.outputs[0].note.kind = NoteKind::Ordinary;
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "accumulator initialization output zero has the wrong note kind"
            ))
        ));

        let (statement, witness) = value_lock_creation_fixture();
        changed = witness.clone();
        changed.auth.next = changed.auth.current.clone();
        assert!(matches!(
            verify_relation(&statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "value-lock creation has nonzero next state"
            ))
        ));

        changed = witness.clone();
        changed.outputs[0].note.kind = NoteKind::Ordinary;
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "value-lock output zero has the wrong note kind"
            ))
        ));
    }

    #[test]
    fn approval_step_positive_and_failure_matrix() {
        let (statement, witness) = approval_fixture();
        verify_relation(&statement, &witness).unwrap();

        let mut changed = witness.clone();
        changed.inputs[0].note.kind = NoteKind::Ordinary;
        let mut changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "approval input zero is not an accumulator note"
            ))
        ));

        changed = witness.clone();
        changed.inputs[0].note.value = 1;
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "approval current accumulator must be a zero-value native note"
            ))
        ));

        changed = witness.clone();
        changed.outputs[0].note.value = 1;
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "approval next accumulator must be a zero-value native note"
            ))
        ));

        changed = witness.clone();
        changed.auth.current.threshold = 0;
        assert!(matches!(
            verify_relation(&statement, &changed),
            Err(RelationError::PrivateAuthorization(_))
        ));

        changed = witness.clone();
        changed.inputs[0].spend_key[0] = 1;
        assert!(matches!(
            verify_relation(&statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "approval accumulator input has a nonzero unused spend key"
            ))
        ));

        changed = witness.clone();
        changed.auth.signer_tags[2] = changed.auth.signer_tags[0];
        let root = policy_root(2, 3, &changed.auth.signer_tags);
        changed.auth.current.policy_root = root;
        changed.auth.next.policy_root = root;
        changed.inputs[0].note.pk_auth = accumulator_digest(&changed.auth.current);
        changed.outputs[0].note.pk_auth = accumulator_digest(&changed.auth.next);
        let mut changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(_))
        ));

        changed = witness.clone();
        changed.auth.signer_tags[1] = spend_keys(&[0x95; 48]).0;
        let root = policy_root(2, 3, &changed.auth.signer_tags);
        changed.auth.current.policy_root = root;
        changed.auth.next.policy_root = root;
        changed.inputs[0].note.pk_auth = accumulator_digest(&changed.auth.current);
        changed.outputs[0].note.pk_auth = accumulator_digest(&changed.auth.next);
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(_))
        ));

        changed = witness.clone();
        let member = spend_keys(&changed.inputs[1].spend_key).0;
        let chosen = changed
            .auth
            .signer_tags
            .iter()
            .position(|tag| *tag == member)
            .expect("fixture member remains in the policy");
        changed.auth.current.approved_slots[chosen] = true;
        changed.auth.current.approval_count = 2;
        changed.auth.next.approval_count = 3;
        changed.auth.next.approved_slots = [true, true, true, false, false, false];
        changed.inputs[0].note.pk_auth = accumulator_digest(&changed.auth.current);
        changed.outputs[0].note.pk_auth = accumulator_digest(&changed.auth.next);
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization("duplicate approval"))
        ));

        changed = witness.clone();
        changed.auth.next.approval_count = changed.auth.current.approval_count;
        assert!(matches!(
            verify_relation(&statement, &changed),
            Err(RelationError::PrivateAuthorization(_))
        ));

        changed = witness.clone();
        changed.auth.next.intent_digest[0] ^= 1;
        changed.outputs[0].note.pk_auth = accumulator_digest(&changed.auth.next);
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(_))
        ));

        changed = witness.clone();
        changed.auth.current.approval_count = 4;
        assert!(matches!(
            verify_relation(&statement, &changed),
            Err(RelationError::PrivateAuthorization(_))
        ));

        changed = witness.clone();
        changed.outputs[0].note.pk_auth[0] ^= 1;
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "mode-specific output zero authorization mismatch"
            ))
        ));
    }

    #[test]
    fn final_threshold_positive_effective_next_and_failure_matrix() {
        let (statement, witness) = final_fixture();
        verify_relation(&statement, &witness).unwrap();
        let effective = effective_next_accumulator(&witness.auth);
        assert_eq!(effective.policy_root, witness.auth.current.policy_root);
        assert_eq!(effective.intent_digest, witness.auth.current.intent_digest);
        assert_eq!(effective.threshold, witness.auth.current.threshold);
        assert_eq!(effective.signer_count, witness.auth.current.signer_count);
        assert_eq!(effective.approval_count, 0);
        assert_eq!(effective.approved_slots, [false; MAX_SIGNERS]);

        let mut changed = witness.clone();
        changed.inputs[0].note.kind = NoteKind::Ordinary;
        let mut changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "final input zero is not a value-lock note"
            ))
        ));

        changed = witness.clone();
        changed.outputs[0].note.kind = NoteKind::ValueLock;
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "final outputs must be ordinary notes"
            ))
        ));

        changed = witness.clone();
        changed.inputs[1].note.value = 1;
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "final threshold accumulator must be a zero-value native note"
            ))
        ));

        changed = witness.clone();
        changed.auth.current.threshold = 3;
        changed.auth.current.policy_root = policy_root(3, 3, &changed.auth.signer_tags);
        changed.inputs[0].note.pk_auth = value_lock_digest(
            changed.auth.current.policy_root,
            changed.auth.current.intent_digest,
        );
        changed.inputs[1].note.pk_auth = accumulator_digest(&changed.auth.current);
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "approval threshold not reached"
            ))
        ));

        changed = witness.clone();
        changed.auth.current.intent_digest[0] ^= 1;
        changed.inputs[0].note.pk_auth = value_lock_digest(
            changed.auth.current.policy_root,
            changed.auth.current.intent_digest,
        );
        changed.inputs[1].note.pk_auth = accumulator_digest(&changed.auth.current);
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(_))
        ));

        changed = witness.clone();
        changed.auth.next.policy_root[0] = 1;
        assert!(matches!(
            verify_relation(&statement, &changed),
            Err(RelationError::PrivateAuthorization(_))
        ));

        // The former effective-next digest was observationally dead. Removing
        // that hash does not remove the Final lane's canonical zero-next gate:
        // every representable next-state field must still reject independently.
        for mutation in 0..5 {
            changed = witness.clone();
            match mutation {
                0 => changed.auth.next.intent_digest[0] = 1,
                1 => changed.auth.next.threshold = 1,
                2 => changed.auth.next.signer_count = 1,
                3 => changed.auth.next.approval_count = 1,
                4 => changed.auth.next.approved_slots[0] = true,
                _ => unreachable!(),
            }
            assert!(matches!(
                verify_relation(&statement, &changed),
                Err(RelationError::PrivateAuthorization(_))
            ));
        }

        changed = witness.clone();
        changed.inputs[1].spend_key[0] = 1;
        assert!(matches!(
            verify_relation(&statement, &changed),
            Err(RelationError::PrivateAuthorization(
                "final spend has a nonzero unused spend key"
            ))
        ));

        changed = witness.clone();
        changed.auth.signer_tags[2] = changed.auth.signer_tags[0];
        let root = policy_root(2, 3, &changed.auth.signer_tags);
        changed.auth.current.policy_root = root;
        changed.inputs[0].note.pk_auth =
            value_lock_digest(root, changed.auth.current.intent_digest);
        changed.inputs[1].note.pk_auth = accumulator_digest(&changed.auth.current);
        changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed);
        assert!(matches!(
            verify_relation(&changed_statement, &changed),
            Err(RelationError::PrivateAuthorization(_))
        ));
    }

    #[test]
    fn canonical_statement_roundtrip_and_exact_consumption() {
        let (statement, witness) = stablecoin_fixture();
        let expected = statement.activation.clone();
        let encoded = encode_canonical_statement(&statement).unwrap();
        assert_eq!(encoded.len(), CANONICAL_STATEMENT_BYTES);
        assert_eq!(decode_canonical_statement(&encoded).unwrap(), statement);
        verify_canonical_statement(&encoded, &witness, &expected).unwrap();
        assert!(matches!(
            decode_canonical_statement(&encoded[..encoded.len() - 1]),
            Err(StatementDecodeError::Length { .. })
        ));
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(matches!(
            decode_canonical_statement(&trailing),
            Err(StatementDecodeError::Length { .. })
        ));
        let mut changed = encoded;
        changed[0] ^= 1;
        assert!(matches!(
            decode_canonical_statement(&changed),
            Err(StatementDecodeError::Magic)
        ));
        changed = encoded;
        changed[9] ^= 1;
        assert!(matches!(
            decode_canonical_statement(&changed),
            Err(StatementDecodeError::GrammarVersion(_))
        ));
        changed = encoded;
        changed[10] = 2;
        assert!(matches!(
            decode_canonical_statement(&changed),
            Err(StatementDecodeError::NonBoolean("input_flags[0]"))
        ));
        changed = encoded;
        changed[446] = 1;
        assert!(matches!(
            decode_canonical_statement(&changed),
            Err(StatementDecodeError::NonCanonicalSignedAmount(
                "value_balance"
            ))
        ));
        changed = encoded;
        changed[455] = 2;
        assert!(matches!(
            decode_canonical_statement(&changed),
            Err(StatementDecodeError::NonBoolean("stablecoin.enabled"))
        ));
        changed = encoded;
        changed[468] = 2;
        assert!(matches!(
            decode_canonical_statement(&changed),
            Err(StatementDecodeError::NonBoolean(
                "stablecoin.issuance_delta"
            ))
        ));
        changed = encoded;
        changed[469..477].fill(0);
        assert!(matches!(
            decode_canonical_statement(&changed),
            Err(StatementDecodeError::NonCanonicalSignedAmount(
                "stablecoin.issuance_delta"
            ))
        ));
    }

    #[test]
    fn every_activation_and_network_byte_is_exactly_bound() {
        let (statement, witness) = mask_fixture(0b1111);
        let expected = statement.activation.clone();
        let encoded = encode_canonical_statement(&statement).unwrap();
        // The 56-byte V5 balance tag precedes the final 152 activation bytes.
        for offset in 701..CANONICAL_STATEMENT_BYTES {
            let mut changed = encoded;
            changed[offset] ^= 1;
            let decoded = decode_canonical_statement(&changed).unwrap();
            assert_ne!(decoded.activation, expected, "activation byte {offset}");
            assert_ne!(intent_digest(&decoded), intent_digest(&statement));
            assert!(matches!(
                verify_canonical_statement(&changed, &witness, &expected),
                Err(CanonicalVerificationError::Relation(
                    RelationError::ActivationBinding
                ))
            ));
        }
        for clear in 0..3 {
            let mut changed = statement.clone();
            match clear {
                0 => changed.activation.chain_id = [0; 32],
                1 => changed.activation.genesis_block_id = [0; 48],
                _ => changed.activation.rules_hash = [0; 48],
            }
            assert!(matches!(
                verify_relation(&changed, &witness),
                Err(RelationError::ActivationBinding)
            ));
        }
    }

    #[test]
    fn relation_derived_public_fields_and_ciphertext_intent_are_bound() {
        let (statement, witness) = mask_fixture(0b1111);
        let mut changed = statement.clone();
        changed.input_flags[0] = false;
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::PublicMismatch("activity flags"))
        ));
        for index in 0..MAX_INPUTS {
            changed = statement.clone();
            changed.nullifiers[index][0] ^= 1;
            assert!(matches!(
                verify_relation(&changed, &witness),
                Err(RelationError::PublicMismatch("nullifier"))
            ));
        }
        changed = statement.clone();
        changed.anchor[0] ^= 1;
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::Membership(_))
        ));
        for index in 0..MAX_OUTPUTS {
            changed = statement.clone();
            changed.commitments[index][0] ^= 1;
            assert!(matches!(
                verify_relation(&changed, &witness),
                Err(RelationError::PublicMismatch("output commitment"))
            ));
            changed = statement.clone();
            changed.ciphertext_hashes[index][0] ^= 1;
            assert_ne!(intent_digest(&changed), intent_digest(&statement));
            assert_ne!(
                encode_canonical_statement(&changed).unwrap(),
                encode_canonical_statement(&statement).unwrap()
            );
        }
        changed = statement.clone();
        changed.balance_tag[0] ^= 1;
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::PublicMismatch("balance tag"))
        ));
    }

    #[test]
    fn stablecoin_public_fields_are_bound_and_invalid_variants_reject() {
        let (statement, witness) = stablecoin_fixture();
        let baseline_intent = intent_digest(&statement);
        let baseline_bytes = encode_canonical_statement(&statement).unwrap();
        let mutations: [fn(&mut StablecoinBinding); 4] = [
            |stable: &mut StablecoinBinding| stable.policy_hash[0] ^= 1,
            |stable: &mut StablecoinBinding| stable.oracle_commitment[0] ^= 1,
            |stable: &mut StablecoinBinding| stable.attestation_commitment[0] ^= 1,
            |stable: &mut StablecoinBinding| stable.policy_version += 1,
        ];
        for mutate in mutations {
            let mut changed = statement.clone();
            mutate(&mut changed.stablecoin);
            assert_ne!(
                encode_canonical_statement(&changed).unwrap(),
                baseline_bytes
            );
            assert_ne!(intent_digest(&changed), baseline_intent);
        }

        let mut changed = statement.clone();
        changed.stablecoin.policy_version = 0;
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::Stablecoin(_))
        ));
        for digest in 0..3 {
            changed = statement.clone();
            match digest {
                0 => changed.stablecoin.policy_hash = [0; DIGEST_BYTES],
                1 => changed.stablecoin.oracle_commitment = [0; DIGEST_BYTES],
                _ => changed.stablecoin.attestation_commitment = [0; DIGEST_BYTES],
            }
            assert!(matches!(
                verify_relation(&changed, &witness),
                Err(RelationError::ZeroDigest(_))
            ));
        }
        changed = statement.clone();
        changed.stablecoin.issuance_delta.negative = false;
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::Balance(7))
        ));
        changed = statement.clone();
        changed.stablecoin.issuance_delta.magnitude = 9;
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::Balance(7))
        ));
        changed = statement.clone();
        changed.stablecoin.issuance_delta = SignedAmount::default();
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::Stablecoin(
                "enabled stablecoin issuance must be nonzero"
            ))
        ));
        changed = statement.clone();
        changed.stablecoin.issuance_delta = SignedAmount {
            negative: true,
            magnitude: 0,
        };
        assert!(matches!(
            encode_canonical_statement(&changed),
            Err(StatementEncodeError::NonCanonicalSignedAmount(
                "stablecoin.issuance_delta"
            ))
        ));
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::NonCanonicalSignedAmount)
        ));
    }

    #[test]
    fn four_slot_order_padding_alias_and_selector_gates() {
        let (mut statement, mut witness) = mask_fixture(0b1111);
        statement.balance_slot_asset_ids = [0, 7, 9, PADDING_ASSET_ID];
        verify_relation(&statement, &witness).unwrap();
        for slots in [
            [0, 7, 7, PADDING_ASSET_ID],
            [0, 9, 7, PADDING_ASSET_ID],
            [0, PADDING_ASSET_ID, 9, PADDING_ASSET_ID],
            [
                0,
                RESERVED_REDUCED_PADDING_ASSET_ID,
                PADDING_ASSET_ID,
                PADDING_ASSET_ID,
            ],
        ] {
            let mut changed = statement.clone();
            changed.balance_slot_asset_ids = slots;
            assert!(matches!(
                verify_relation(&changed, &witness),
                Err(RelationError::InvalidAssetSlots)
            ));
        }
        witness.inputs[0].balance_slot_selectors = [false, false, false, true];
        assert!(matches!(
            verify_relation(&statement, &witness),
            Err(RelationError::AssetSelector(0, "input"))
        ));
    }

    #[test]
    fn signed_negative_zero_and_61_bit_boundaries_fail_closed() {
        let (statement, witness) = mask_fixture(0b1111);
        let mut changed = statement.clone();
        changed.value_balance = SignedAmount {
            negative: true,
            magnitude: 0,
        };
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::NonCanonicalSignedAmount)
        ));
        changed = statement.clone();
        changed.value_balance = SignedAmount {
            negative: false,
            magnitude: 1,
        };
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::PublicMismatch(
                "active transfer action requires zero value balance"
            ))
        ));
        changed = statement.clone();
        changed.fee = MAX_NOTE_VALUE + 1;
        assert!(matches!(
            verify_relation(&changed, &witness),
            Err(RelationError::ValueOutOfRange("fee"))
        ));
        let mut changed_witness = witness.clone();
        changed_witness.inputs[0].note.value = MAX_NOTE_VALUE + 1;
        let mut changed_statement = statement.clone();
        refresh_derived_statement(&mut changed_statement, &mut changed_witness);
        assert!(matches!(
            verify_relation(&changed_statement, &changed_witness),
            Err(RelationError::ValueOutOfRange("note value"))
        ));

        let (mut max_statement, mut max_witness) = mask_fixture(0b1111);
        for input in &mut max_witness.inputs {
            input.note.value = MAX_NOTE_VALUE;
        }
        max_witness.outputs[0].note.value = MAX_NOTE_VALUE;
        max_witness.outputs[1].note.value = MAX_NOTE_VALUE - 1;
        max_statement.fee = 1;
        refresh_derived_statement(&mut max_statement, &mut max_witness);
        verify_relation(&max_statement, &max_witness).unwrap();
        max_witness.outputs[1].note.value = MAX_NOTE_VALUE;
        refresh_derived_statement(&mut max_statement, &mut max_witness);
        assert!(matches!(
            verify_relation(&max_statement, &max_witness),
            Err(RelationError::Balance(NATIVE_ASSET_ID))
        ));
    }

    #[test]
    fn duplicate_active_note_cannot_be_counted_twice() {
        let (mut statement, mut witness) = mask_fixture(0b1111);
        witness.inputs[1] = witness.inputs[0].clone();
        refresh_derived_statement(&mut statement, &mut witness);
        assert_eq!(statement.nullifiers[0], statement.nullifiers[1]);
        assert!(matches!(
            verify_relation(&statement, &witness),
            Err(RelationError::DuplicateNullifier)
        ));
    }

    #[test]
    fn accumulator_intent_must_be_nonzero() {
        let (mut statement, mut witness) = approval_fixture();
        witness.auth.current.intent_digest = [0; DIGEST_BYTES];
        witness.auth.next.intent_digest = [0; DIGEST_BYTES];
        witness.inputs[0].note.pk_auth = accumulator_digest(&witness.auth.current);
        witness.outputs[0].note.pk_auth = accumulator_digest(&witness.auth.next);
        refresh_derived_statement(&mut statement, &mut witness);
        assert!(matches!(
            verify_relation(&statement, &witness),
            Err(RelationError::ZeroDigest("accumulator intent"))
        ));
    }

    #[test]
    fn refresh_never_sanitizes_inactive_private_payloads() {
        let (mut statement, mut witness) = mask_fixture(0b0101);
        witness.inputs[1].spend_key[0] = 1;
        refresh_derived_statement(&mut statement, &mut witness);
        assert_eq!(witness.inputs[1].spend_key[0], 1);
        assert!(matches!(
            verify_relation(&statement, &witness),
            Err(RelationError::InactivePayload(1, "input"))
        ));

        let (mut statement, mut witness) = mask_fixture(0b0101);
        witness.outputs[1].note.randomness[0] = 1;
        refresh_derived_statement(&mut statement, &mut witness);
        assert_eq!(witness.outputs[1].note.randomness[0], 1);
        assert!(matches!(
            verify_relation(&statement, &witness),
            Err(RelationError::InactivePayload(1, "output"))
        ));
    }

    #[test]
    fn intent_bytes_bind_the_exact_statement_language() {
        let bytes = encode_statement_for_intent(&kat_statement());
        assert_eq!(&bytes[..8], &STATEMENT_MAGIC);
        assert_eq!(&bytes[8..10], &STATEMENT_GRAMMAR_VERSION.to_be_bytes());
    }
}
