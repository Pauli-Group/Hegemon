//! Typed semantic surface for the compact Poseidon2 V8 SmallWood relation.
//!
//! This module owns the canonical 120-word public statement and the padded
//! two-input/two-output witness shape consumed by the V8 relation compiler.
//! Seven-word values are fresh width-16 Poseidon2 digests.  The three six-word
//! legacy stablecoin positions are reserved and must be zero in V8; this module
//! never computes, truncates, maps, or treats them as authority.
//!
//! The module is deliberately authority-neutral.  It supplies typed parsing,
//! serialization, and structural checks, but does not activate a proof route.

use protocol_versioning::{CIRCUIT_V8, CRYPTO_SUITE_ETA};
use transaction_core::{
    constants::{
        BALANCE_SLOT_PADDING_FIELD_ID, FIELD_MODULUS_U64, MAX_IN_CIRCUIT_VALUE, NATIVE_ASSET_ID,
    },
    hashing_pq::{bytes48_to_felts, ciphertext_hash_bytes},
    poseidon2_width16::{
        poseidon2_width16_sponge, Felt, POSEIDON2_WIDTH16_DIGEST, POSEIDON2_WIDTH16_RATE,
    },
    stablecoin_poseidon2_v8::{
        verify_stablecoin_transition_v8, StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Context,
        StablecoinPoseidon2V8Counters, StablecoinPoseidon2V8Direction, StablecoinPoseidon2V8Error,
        StablecoinPoseidon2V8Public, StablecoinPoseidon2V8Witness,
        STABLECOIN_POSEIDON2_V8_AUTHORIZED_PUBLIC_FIELDS, STABLECOIN_POSEIDON2_V8_DEPTH,
        STABLECOIN_POSEIDON2_V8_MAX_SCALAR, STABLECOIN_POSEIDON2_V8_MAX_VALUE,
    },
};

use crate::smallwood_frontend::{
    SmallwoodPrivateAuthMode, SMALLWOOD_MULTISIG_MAX_SIGNERS, SMALLWOOD_SIGNER_TAG_WORDS,
};

pub const SMALLWOOD_POSEIDON2_V8_INPUTS: usize = 2;
pub const SMALLWOOD_POSEIDON2_V8_OUTPUTS: usize = 2;
pub const SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS: usize = 4;
pub const SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH: usize = 32;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS: usize = 120;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_BYTES: usize = SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS * 8;
pub const SMALLWOOD_POSEIDON2_V8_BASE_PUBLIC_WORDS: usize = 83;
pub const SMALLWOOD_POSEIDON2_V8_STABLE_PUBLIC_WORDS: usize = 37;
pub const SMALLWOOD_POSEIDON2_V8_CONTEXT_WORDS: usize = 15;
/// Exact wallet V3 ciphertext container (579 bytes) plus its canonical
/// ML-KEM-1024 ciphertext (1,568 bytes).  Every active output carries this
/// byte string inline in the canonical action; it is never a sidecar.
pub const SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES: usize = 2_147;
pub const SMALLWOOD_POSEIDON2_V8_MAX_INLINE_CIPHERTEXT_BYTES: usize =
    SMALLWOOD_POSEIDON2_V8_OUTPUTS * SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES;

pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_INPUT_FLAGS: usize = 0;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_OUTPUT_FLAGS: usize = 2;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_NULLIFIERS: usize = 4;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_COMMITMENTS: usize = 18;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_CIPHERTEXT_COMMITMENTS: usize = 32;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_FEE: usize = 44;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_VALUE_BALANCE_SIGN: usize = 45;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_VALUE_BALANCE_MAGNITUDE: usize = 46;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_MERKLE_ROOT: usize = 47;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_BALANCE_ASSETS: usize = 54;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ENABLED: usize = 58;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ASSET: usize = 59;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_POLICY_VERSION: usize = 60;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ISSUANCE_SIGN: usize = 61;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ISSUANCE_MAGNITUDE: usize = 62;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_POLICY_COMMITMENT: usize = 63;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ORACLE_COMMITMENT: usize = 69;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ATTESTATION_COMMITMENT: usize = 75;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_CIRCUIT_VERSION: usize = 81;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_CRYPTO_SUITE: usize = 82;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_DIRECTION: usize = 83;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ASSET: usize = 84;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_POLICY_VERSION: usize = 85;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_MAGNITUDE: usize = 86;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ACTION_INTENT: usize = 87;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_PARENT_HEIGHT: usize = 94;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_BEFORE_ROOT: usize = 95;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_ROOT: usize = 102;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_EPOCH: usize = 109;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_MINTED: usize = 110;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_DEBT: usize = 111;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_SEQUENCE: usize = 112;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ISSUER_AUTHORIZATION: usize = 113;

pub const SMALLWOOD_POSEIDON2_V8_INTENT_ZERO_NULLIFIERS: core::ops::Range<usize> = 4..18;
pub const SMALLWOOD_POSEIDON2_V8_INTENT_ZERO_MERKLE_ROOT: core::ops::Range<usize> = 47..54;
pub const SMALLWOOD_POSEIDON2_V8_INTENT_ZERO_ACTION_INTENT: core::ops::Range<usize> = 87..94;
pub const SMALLWOOD_POSEIDON2_V8_INTENT_ZERO_ISSUER_AUTHORIZATION: core::ops::Range<usize> =
    113..120;
pub const SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN: u64 = 0x4854_5838_494e_5400;
pub const SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_PERMUTATIONS: usize =
    SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS.div_ceil(POSEIDON2_WIDTH16_RATE);

pub type SmallwoodPoseidon2V8Digest = [u64; POSEIDON2_WIDTH16_DIGEST];
pub type SmallwoodPoseidon2V8CiphertextCommitment = [u64; 6];
pub type SmallwoodPoseidon2V8CompatibilityCommitment = [u64; 6];
pub type SmallwoodPoseidon2V8SignerTag = [u64; SMALLWOOD_SIGNER_TAG_WORDS];

const _: () = assert!(SMALLWOOD_POSEIDON2_V8_INPUTS == 2);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_OUTPUTS == 2);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS == 4);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS == 120);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES == 579 + 1_568);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_MAX_INLINE_CIPHERTEXT_BYTES == 4_294);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_BASE_PUBLIC_WORDS == 83);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_STABLE_PUBLIC_WORDS == 37);
const _: () = assert!(STABLECOIN_POSEIDON2_V8_AUTHORIZED_PUBLIC_FIELDS == 120);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_PERMUTATIONS == 15);
const _: () = assert!(SMALLWOOD_MULTISIG_MAX_SIGNERS == 6);
const _: () = assert!(SMALLWOOD_SIGNER_TAG_WORDS == 5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8SurfaceError {
    WrongPublicLength,
    WrongWitnessLength,
    WrongContextLength,
    WrongCiphertextLength,
    NonCanonicalField,
    NonBoolean,
    UnsupportedDirection,
    UnsupportedCircuit,
    UnsupportedCryptoSuite,
    NegativeZeroValueBalance,
    ValueOutOfRange,
    ScalarOutOfRange,
    InvalidAssetLayout,
    InactivePublicSlotNonzero,
    ActivePublicSlotZero,
    DuplicateNullifier,
    InactiveWitnessSlotNonzero,
    ActivityMismatch,
    SpendKeyMismatch,
    CiphertextActivityMismatch,
    CiphertextCommitmentMismatch,
    InvalidBalanceSelector,
    BalanceMismatch,
    NonCanonicalStablecoinCompatibility,
    StablecoinSurfaceMismatch,
    ActionIntentMismatch,
    InvalidAuthorizationShape,
    InvalidAuthorizationOpening,
    Stablecoin(StablecoinPoseidon2V8Error),
}

impl From<StablecoinPoseidon2V8Error> for SmallwoodPoseidon2V8SurfaceError {
    fn from(value: StablecoinPoseidon2V8Error) -> Self {
        Self::Stablecoin(value)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8CompatibilityStablecoin {
    pub enabled: bool,
    pub asset_id: u64,
    pub policy_version: u32,
    pub issuance_sign: bool,
    pub issuance_magnitude: u64,
    pub reserved_legacy_stablecoin_commitments: [SmallwoodPoseidon2V8CompatibilityCommitment; 3],
}

impl SmallwoodPoseidon2V8CompatibilityStablecoin {
    pub const ZERO: Self = Self {
        enabled: false,
        asset_id: 0,
        policy_version: 0,
        issuance_sign: false,
        issuance_magnitude: 0,
        reserved_legacy_stablecoin_commitments: [[0; 6]; 3],
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8PublicStatement {
    pub input_flags: [bool; SMALLWOOD_POSEIDON2_V8_INPUTS],
    pub output_flags: [bool; SMALLWOOD_POSEIDON2_V8_OUTPUTS],
    pub nullifiers: [SmallwoodPoseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_INPUTS],
    pub commitments: [SmallwoodPoseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_OUTPUTS],
    pub ciphertext_commitments:
        [SmallwoodPoseidon2V8CiphertextCommitment; SMALLWOOD_POSEIDON2_V8_OUTPUTS],
    pub fee: u64,
    pub value_balance_sign: bool,
    pub value_balance_magnitude: u64,
    pub merkle_root: SmallwoodPoseidon2V8Digest,
    /// Canonical field words. Padding is `BALANCE_SLOT_PADDING_FIELD_ID`, not
    /// the external `u64::MAX` sentinel.
    pub balance_assets: [u64; SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS],
    pub compatibility_stablecoin: SmallwoodPoseidon2V8CompatibilityStablecoin,
    pub circuit_version: u64,
    pub crypto_suite: u64,
    pub stablecoin: StablecoinPoseidon2V8Public,
}

impl Default for SmallwoodPoseidon2V8PublicStatement {
    fn default() -> Self {
        Self {
            input_flags: [false; 2],
            output_flags: [false; 2],
            nullifiers: [[0; 7]; 2],
            commitments: [[0; 7]; 2],
            ciphertext_commitments: [[0; 6]; 2],
            fee: 0,
            value_balance_sign: false,
            value_balance_magnitude: 0,
            merkle_root: [0; 7],
            balance_assets: [
                NATIVE_ASSET_ID,
                BALANCE_SLOT_PADDING_FIELD_ID,
                BALANCE_SLOT_PADDING_FIELD_ID,
                BALANCE_SLOT_PADDING_FIELD_ID,
            ],
            compatibility_stablecoin: SmallwoodPoseidon2V8CompatibilityStablecoin::ZERO,
            circuit_version: u64::from(CIRCUIT_V8),
            crypto_suite: u64::from(CRYPTO_SUITE_ETA),
            stablecoin: StablecoinPoseidon2V8Public::ZERO,
        }
    }
}

#[inline]
fn is_zero<const N: usize>(words: &[u64; N]) -> bool {
    words.iter().all(|word| *word == 0)
}

#[inline]
fn ensure_canonical_word(word: u64) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
    if word < FIELD_MODULUS_U64 {
        Ok(())
    } else {
        Err(SmallwoodPoseidon2V8SurfaceError::NonCanonicalField)
    }
}

fn ensure_canonical_words(words: &[u64]) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
    for word in words {
        ensure_canonical_word(*word)?;
    }
    Ok(())
}

#[inline]
fn parse_bool(word: u64) -> Result<bool, SmallwoodPoseidon2V8SurfaceError> {
    match word {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SmallwoodPoseidon2V8SurfaceError::NonBoolean),
    }
}

#[inline]
fn direction_word(direction: StablecoinPoseidon2V8Direction) -> u64 {
    match direction {
        StablecoinPoseidon2V8Direction::Disabled => 0,
        StablecoinPoseidon2V8Direction::Mint => 1,
        StablecoinPoseidon2V8Direction::Burn => 2,
    }
}

fn parse_direction(
    word: u64,
) -> Result<StablecoinPoseidon2V8Direction, SmallwoodPoseidon2V8SurfaceError> {
    match word {
        0 => Ok(StablecoinPoseidon2V8Direction::Disabled),
        1 => Ok(StablecoinPoseidon2V8Direction::Mint),
        2 => Ok(StablecoinPoseidon2V8Direction::Burn),
        _ => Err(SmallwoodPoseidon2V8SurfaceError::UnsupportedDirection),
    }
}

fn felt_digest_to_words(values: [Felt; 7]) -> SmallwoodPoseidon2V8Digest {
    values.map(|value| value.as_canonical_u64())
}

fn words_to_felt_digest(
    values: SmallwoodPoseidon2V8Digest,
) -> Result<[Felt; 7], SmallwoodPoseidon2V8SurfaceError> {
    ensure_canonical_words(&values)?;
    Ok(values.map(Felt::from_u64))
}

fn copy_array<const N: usize>(words: &[u64], start: usize) -> [u64; N] {
    let mut out = [0u64; N];
    out.copy_from_slice(&words[start..start + N]);
    out
}

impl SmallwoodPoseidon2V8PublicStatement {
    pub fn to_public_words(self) -> [u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS] {
        let mut words = [0u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS];
        words[0] = u64::from(self.input_flags[0]);
        words[1] = u64::from(self.input_flags[1]);
        words[2] = u64::from(self.output_flags[0]);
        words[3] = u64::from(self.output_flags[1]);
        for slot in 0..2 {
            let start = SMALLWOOD_POSEIDON2_V8_PUBLIC_NULLIFIERS + slot * 7;
            words[start..start + 7].copy_from_slice(&self.nullifiers[slot]);
            let start = SMALLWOOD_POSEIDON2_V8_PUBLIC_COMMITMENTS + slot * 7;
            words[start..start + 7].copy_from_slice(&self.commitments[slot]);
            let start = SMALLWOOD_POSEIDON2_V8_PUBLIC_CIPHERTEXT_COMMITMENTS + slot * 6;
            words[start..start + 6].copy_from_slice(&self.ciphertext_commitments[slot]);
        }
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_FEE] = self.fee;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_VALUE_BALANCE_SIGN] =
            u64::from(self.value_balance_sign);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_VALUE_BALANCE_MAGNITUDE] = self.value_balance_magnitude;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_MERKLE_ROOT
            ..SMALLWOOD_POSEIDON2_V8_PUBLIC_MERKLE_ROOT + 7]
            .copy_from_slice(&self.merkle_root);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_BALANCE_ASSETS
            ..SMALLWOOD_POSEIDON2_V8_PUBLIC_BALANCE_ASSETS + 4]
            .copy_from_slice(&self.balance_assets);
        let compatibility = self.compatibility_stablecoin;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ENABLED] = u64::from(compatibility.enabled);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ASSET] = compatibility.asset_id;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_POLICY_VERSION] =
            u64::from(compatibility.policy_version);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ISSUANCE_SIGN] =
            u64::from(compatibility.issuance_sign);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ISSUANCE_MAGNITUDE] =
            compatibility.issuance_magnitude;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_POLICY_COMMITMENT
            ..SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_POLICY_COMMITMENT + 6]
            .copy_from_slice(&compatibility.reserved_legacy_stablecoin_commitments[0]);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ORACLE_COMMITMENT
            ..SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ORACLE_COMMITMENT + 6]
            .copy_from_slice(&compatibility.reserved_legacy_stablecoin_commitments[1]);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ATTESTATION_COMMITMENT
            ..SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ATTESTATION_COMMITMENT + 6]
            .copy_from_slice(&compatibility.reserved_legacy_stablecoin_commitments[2]);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_CIRCUIT_VERSION] = self.circuit_version;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_CRYPTO_SUITE] = self.crypto_suite;

        let stable = self.stablecoin;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_DIRECTION] = direction_word(stable.direction);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ASSET] = u64::from(stable.asset_id);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_POLICY_VERSION] =
            u64::from(stable.policy_version);
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_MAGNITUDE] = stable.magnitude;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ACTION_INTENT
            ..SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ACTION_INTENT + 7]
            .copy_from_slice(&felt_digest_to_words(stable.action_intent));
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_PARENT_HEIGHT] = stable.parent_height;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_BEFORE_ROOT
            ..SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_BEFORE_ROOT + 7]
            .copy_from_slice(&felt_digest_to_words(stable.before_root));
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_ROOT
            ..SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_ROOT + 7]
            .copy_from_slice(&felt_digest_to_words(stable.after_root));
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_EPOCH] = stable.after.epoch_id;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_MINTED] = stable.after.minted_in_epoch;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_DEBT] = stable.after.total_debt;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_SEQUENCE] = stable.after.sequence;
        words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ISSUER_AUTHORIZATION
            ..SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ISSUER_AUTHORIZATION + 7]
            .copy_from_slice(&felt_digest_to_words(stable.issuer_authorization));
        words
    }

    pub fn try_from_public_words(words: &[u64]) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        if words.len() != SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS {
            return Err(SmallwoodPoseidon2V8SurfaceError::WrongPublicLength);
        }
        ensure_canonical_words(words)?;
        let statement = Self {
            input_flags: [parse_bool(words[0])?, parse_bool(words[1])?],
            output_flags: [parse_bool(words[2])?, parse_bool(words[3])?],
            nullifiers: [
                copy_array(words, SMALLWOOD_POSEIDON2_V8_PUBLIC_NULLIFIERS),
                copy_array(words, SMALLWOOD_POSEIDON2_V8_PUBLIC_NULLIFIERS + 7),
            ],
            commitments: [
                copy_array(words, SMALLWOOD_POSEIDON2_V8_PUBLIC_COMMITMENTS),
                copy_array(words, SMALLWOOD_POSEIDON2_V8_PUBLIC_COMMITMENTS + 7),
            ],
            ciphertext_commitments: [
                copy_array(words, SMALLWOOD_POSEIDON2_V8_PUBLIC_CIPHERTEXT_COMMITMENTS),
                copy_array(
                    words,
                    SMALLWOOD_POSEIDON2_V8_PUBLIC_CIPHERTEXT_COMMITMENTS + 6,
                ),
            ],
            fee: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_FEE],
            value_balance_sign: parse_bool(
                words[SMALLWOOD_POSEIDON2_V8_PUBLIC_VALUE_BALANCE_SIGN],
            )?,
            value_balance_magnitude: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_VALUE_BALANCE_MAGNITUDE],
            merkle_root: copy_array(words, SMALLWOOD_POSEIDON2_V8_PUBLIC_MERKLE_ROOT),
            balance_assets: copy_array(words, SMALLWOOD_POSEIDON2_V8_PUBLIC_BALANCE_ASSETS),
            compatibility_stablecoin: SmallwoodPoseidon2V8CompatibilityStablecoin {
                enabled: parse_bool(words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ENABLED])?,
                asset_id: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ASSET],
                policy_version: u32::try_from(
                    words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_POLICY_VERSION],
                )
                .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)?,
                issuance_sign: parse_bool(
                    words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ISSUANCE_SIGN],
                )?,
                issuance_magnitude: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ISSUANCE_MAGNITUDE],
                reserved_legacy_stablecoin_commitments: [
                    copy_array(
                        words,
                        SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_POLICY_COMMITMENT,
                    ),
                    copy_array(
                        words,
                        SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ORACLE_COMMITMENT,
                    ),
                    copy_array(
                        words,
                        SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_ATTESTATION_COMMITMENT,
                    ),
                ],
            },
            circuit_version: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_CIRCUIT_VERSION],
            crypto_suite: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_CRYPTO_SUITE],
            stablecoin: StablecoinPoseidon2V8Public {
                direction: parse_direction(words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_DIRECTION])?,
                asset_id: u32::try_from(words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ASSET])
                    .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)?,
                policy_version: u32::try_from(
                    words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_POLICY_VERSION],
                )
                .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)?,
                magnitude: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_MAGNITUDE],
                action_intent: words_to_felt_digest(copy_array(
                    words,
                    SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ACTION_INTENT,
                ))?,
                parent_height: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_PARENT_HEIGHT],
                before_root: words_to_felt_digest(copy_array(
                    words,
                    SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_BEFORE_ROOT,
                ))?,
                after_root: words_to_felt_digest(copy_array(
                    words,
                    SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_ROOT,
                ))?,
                after: StablecoinPoseidon2V8Counters {
                    epoch_id: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_EPOCH],
                    minted_in_epoch: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_MINTED],
                    total_debt: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_DEBT],
                    sequence: words[SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_AFTER_SEQUENCE],
                },
                issuer_authorization: words_to_felt_digest(copy_array(
                    words,
                    SMALLWOOD_POSEIDON2_V8_PUBLIC_STABLE_V8_ISSUER_AUTHORIZATION,
                ))?,
            },
        };
        statement.validate_public_structure()?;
        Ok(statement)
    }

    pub fn to_public_bytes(self) -> [u8; SMALLWOOD_POSEIDON2_V8_PUBLIC_BYTES] {
        let mut bytes = [0u8; SMALLWOOD_POSEIDON2_V8_PUBLIC_BYTES];
        for (index, word) in self.to_public_words().iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    pub fn try_from_public_bytes(bytes: &[u8]) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        if bytes.len() != SMALLWOOD_POSEIDON2_V8_PUBLIC_BYTES {
            return Err(SmallwoodPoseidon2V8SurfaceError::WrongPublicLength);
        }
        let mut words = [0u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS];
        for (index, chunk) in bytes.chunks_exact(8).enumerate() {
            words[index] = u64::from_le_bytes(chunk.try_into().expect("exact eight-byte chunk"));
        }
        Self::try_from_public_words(&words)
    }

    /// Return the exact 120-word action-intent preimage.  Nullifiers are
    /// excluded so approval intent can be fixed before spend nullifiers exist.
    /// The Merkle root is excluded because FinalThresholdSpend derives its note
    /// authorization key from this intent, and that note determines the root.
    /// The action-intent and issuer-authorization fields are also excluded to
    /// avoid self-reference.  The proof transcript binds the public root
    /// separately, so it remains part of the verified statement.
    pub fn action_intent_projection_words(self) -> [u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS] {
        let mut words = self.to_public_words();
        words[SMALLWOOD_POSEIDON2_V8_INTENT_ZERO_NULLIFIERS].fill(0);
        words[SMALLWOOD_POSEIDON2_V8_INTENT_ZERO_MERKLE_ROOT].fill(0);
        words[SMALLWOOD_POSEIDON2_V8_INTENT_ZERO_ACTION_INTENT].fill(0);
        words[SMALLWOOD_POSEIDON2_V8_INTENT_ZERO_ISSUER_AUTHORIZATION].fill(0);
        words
    }

    pub fn expected_action_intent(
        self,
    ) -> Result<SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8SurfaceError> {
        let words = self.action_intent_projection_words();
        ensure_canonical_words(&words)?;
        let felts = words.map(Felt::from_u64);
        let digest = poseidon2_width16_sponge(SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN, &felts)
            .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ActionIntentMismatch)?;
        Ok(felt_digest_to_words(digest))
    }

    pub const fn activity_mask(self) -> u8 {
        (self.input_flags[0] as u8)
            | ((self.input_flags[1] as u8) << 1)
            | ((self.output_flags[0] as u8) << 2)
            | ((self.output_flags[1] as u8) << 3)
    }

    pub fn validate_public_structure(&self) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
        let words = self.to_public_words();
        ensure_canonical_words(&words)?;
        if self.circuit_version != u64::from(CIRCUIT_V8) {
            return Err(SmallwoodPoseidon2V8SurfaceError::UnsupportedCircuit);
        }
        if self.crypto_suite != u64::from(CRYPTO_SUITE_ETA) {
            return Err(SmallwoodPoseidon2V8SurfaceError::UnsupportedCryptoSuite);
        }
        if u128::from(self.fee) > MAX_IN_CIRCUIT_VALUE
            || u128::from(self.value_balance_magnitude) > MAX_IN_CIRCUIT_VALUE
        {
            return Err(SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange);
        }
        if self.value_balance_sign && self.value_balance_magnitude == 0 {
            return Err(SmallwoodPoseidon2V8SurfaceError::NegativeZeroValueBalance);
        }
        // Hegemon has no transparent value pool.  The V8 public value-balance
        // slots are retained for the fixed statement grammar, but production
        // semantics require their unique canonical zero encoding.
        if self.value_balance_sign || self.value_balance_magnitude != 0 {
            return Err(SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange);
        }
        validate_balance_assets(self.balance_assets)?;
        for slot in 0..2 {
            if self.input_flags[slot] {
                if is_zero(&self.nullifiers[slot]) {
                    return Err(SmallwoodPoseidon2V8SurfaceError::ActivePublicSlotZero);
                }
            } else if !is_zero(&self.nullifiers[slot]) {
                return Err(SmallwoodPoseidon2V8SurfaceError::InactivePublicSlotNonzero);
            }
            if self.output_flags[slot] {
                if is_zero(&self.commitments[slot]) || is_zero(&self.ciphertext_commitments[slot]) {
                    return Err(SmallwoodPoseidon2V8SurfaceError::ActivePublicSlotZero);
                }
            } else if !is_zero(&self.commitments[slot])
                || !is_zero(&self.ciphertext_commitments[slot])
            {
                return Err(SmallwoodPoseidon2V8SurfaceError::InactivePublicSlotNonzero);
            }
        }
        if self.input_flags[0] && self.input_flags[1] && self.nullifiers[0] == self.nullifiers[1] {
            return Err(SmallwoodPoseidon2V8SurfaceError::DuplicateNullifier);
        }
        validate_compatibility_stablecoin(self)?;
        if self.stablecoin.parent_height > STABLECOIN_POSEIDON2_V8_MAX_SCALAR {
            return Err(SmallwoodPoseidon2V8SurfaceError::ScalarOutOfRange);
        }
        if self.stablecoin.direction != StablecoinPoseidon2V8Direction::Disabled {
            let expected = self.expected_action_intent()?;
            if felt_digest_to_words(self.stablecoin.action_intent) != expected {
                return Err(SmallwoodPoseidon2V8SurfaceError::ActionIntentMismatch);
            }
        }
        Ok(())
    }
}

fn validate_balance_assets(
    assets: [u64; SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS],
) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
    if assets[0] != NATIVE_ASSET_ID {
        return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAssetLayout);
    }
    let mut padding = false;
    let mut previous = NATIVE_ASSET_ID;
    for asset in assets.into_iter().skip(1) {
        if asset == BALANCE_SLOT_PADDING_FIELD_ID {
            padding = true;
            continue;
        }
        if padding || asset <= previous || asset >= FIELD_MODULUS_U64 {
            return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAssetLayout);
        }
        previous = asset;
    }
    Ok(())
}

fn validate_compatibility_stablecoin(
    statement: &SmallwoodPoseidon2V8PublicStatement,
) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
    let compatibility = statement.compatibility_stablecoin;
    let stable = statement.stablecoin;
    if stable.direction == StablecoinPoseidon2V8Direction::Disabled {
        if compatibility != SmallwoodPoseidon2V8CompatibilityStablecoin::ZERO
            || stable
                != StablecoinPoseidon2V8Public::disabled_at_context(
                    stable.parent_height,
                    stable.before_root,
                )
        {
            return Err(SmallwoodPoseidon2V8SurfaceError::NonCanonicalStablecoinCompatibility);
        }
        return Ok(());
    }
    if !compatibility.enabled
        || compatibility.asset_id != u64::from(stable.asset_id)
        || compatibility.policy_version != stable.policy_version
        || compatibility.issuance_magnitude != stable.magnitude
        || compatibility.issuance_sign != (stable.direction == StablecoinPoseidon2V8Direction::Mint)
        || compatibility.asset_id == NATIVE_ASSET_ID
        || compatibility.asset_id == BALANCE_SLOT_PADDING_FIELD_ID
        || compatibility.issuance_magnitude > STABLECOIN_POSEIDON2_V8_MAX_VALUE
        || compatibility.reserved_legacy_stablecoin_commitments != [[0; 6]; 3]
        || (stable.direction == StablecoinPoseidon2V8Direction::Burn
            && !is_zero(&felt_digest_to_words(stable.issuer_authorization)))
    {
        return Err(SmallwoodPoseidon2V8SurfaceError::StablecoinSurfaceMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8NoteOpening {
    pub value: u64,
    pub asset_id: u64,
    pub recipient_key: [u64; 4],
    pub authorization_key: [u64; 4],
    pub rho: [u64; 4],
    pub randomness: [u64; 4],
}

impl SmallwoodPoseidon2V8NoteOpening {
    pub const ZERO: Self = Self {
        value: 0,
        asset_id: 0,
        recipient_key: [0; 4],
        authorization_key: [0; 4],
        rho: [0; 4],
        randomness: [0; 4],
    };

    fn push_words(self, words: &mut Vec<u64>) {
        words.push(self.value);
        words.push(self.asset_id);
        words.extend_from_slice(&self.recipient_key);
        words.extend_from_slice(&self.authorization_key);
        words.extend_from_slice(&self.rho);
        words.extend_from_slice(&self.randomness);
    }

    fn parse(cursor: &mut WordCursor<'_>) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        Ok(Self {
            value: cursor.word()?,
            asset_id: cursor.word()?,
            recipient_key: cursor.array()?,
            authorization_key: cursor.array()?,
            rho: cursor.array()?,
            randomness: cursor.array()?,
        })
    }

    fn validate_active(self) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
        if u128::from(self.value) > MAX_IN_CIRCUIT_VALUE {
            return Err(SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange);
        }
        if self.asset_id >= FIELD_MODULUS_U64 || self.asset_id == BALANCE_SLOT_PADDING_FIELD_ID {
            return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAssetLayout);
        }
        ensure_canonical_words(&self.recipient_key)?;
        ensure_canonical_words(&self.authorization_key)?;
        ensure_canonical_words(&self.rho)?;
        ensure_canonical_words(&self.randomness)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8InputWitness {
    pub active: bool,
    pub spend_key: [u64; 4],
    pub note: SmallwoodPoseidon2V8NoteOpening,
    pub position: u64,
    pub siblings: [SmallwoodPoseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH],
    pub balance_slot_selectors: [bool; SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS],
}

impl SmallwoodPoseidon2V8InputWitness {
    pub const ZERO: Self = Self {
        active: false,
        spend_key: [0; 4],
        note: SmallwoodPoseidon2V8NoteOpening::ZERO,
        position: 0,
        siblings: [[0; 7]; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH],
        balance_slot_selectors: [false; SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS],
    };

    fn push_words(self, words: &mut Vec<u64>) {
        words.push(u64::from(self.active));
        words.extend_from_slice(&self.spend_key);
        self.note.push_words(words);
        words.push(self.position);
        for sibling in self.siblings {
            words.extend_from_slice(&sibling);
        }
        words.extend(self.balance_slot_selectors.map(u64::from));
    }

    fn parse(cursor: &mut WordCursor<'_>) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        let active = cursor.boolean()?;
        let spend_key = cursor.array()?;
        let note = SmallwoodPoseidon2V8NoteOpening::parse(cursor)?;
        let position = cursor.word()?;
        let mut siblings = [[0u64; 7]; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH];
        for sibling in &mut siblings {
            *sibling = cursor.array()?;
        }
        let mut balance_slot_selectors = [false; SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS];
        for selector in &mut balance_slot_selectors {
            *selector = cursor.boolean()?;
        }
        Ok(Self {
            active,
            spend_key,
            note,
            position,
            siblings,
            balance_slot_selectors,
        })
    }
}

impl Default for SmallwoodPoseidon2V8InputWitness {
    fn default() -> Self {
        Self::ZERO
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8OutputWitness {
    pub active: bool,
    pub note: SmallwoodPoseidon2V8NoteOpening,
    pub balance_slot_selectors: [bool; SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS],
}

impl SmallwoodPoseidon2V8OutputWitness {
    pub const ZERO: Self = Self {
        active: false,
        note: SmallwoodPoseidon2V8NoteOpening::ZERO,
        balance_slot_selectors: [false; SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS],
    };

    fn push_words(self, words: &mut Vec<u64>) {
        words.push(u64::from(self.active));
        self.note.push_words(words);
        words.extend(self.balance_slot_selectors.map(u64::from));
    }

    fn parse(cursor: &mut WordCursor<'_>) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        let active = cursor.boolean()?;
        let note = SmallwoodPoseidon2V8NoteOpening::parse(cursor)?;
        let mut balance_slot_selectors = [false; SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS];
        for selector in &mut balance_slot_selectors {
            *selector = cursor.boolean()?;
        }
        Ok(Self {
            active,
            note,
            balance_slot_selectors,
        })
    }
}

impl Default for SmallwoodPoseidon2V8OutputWitness {
    fn default() -> Self {
        Self::ZERO
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8AccumulatorOpening {
    pub policy_root: SmallwoodPoseidon2V8Digest,
    pub intent_digest: SmallwoodPoseidon2V8Digest,
    pub threshold: u64,
    pub signer_count: u64,
    pub approval_count: u64,
    pub approved_slots: [bool; SMALLWOOD_MULTISIG_MAX_SIGNERS],
}

impl SmallwoodPoseidon2V8AccumulatorOpening {
    pub const ZERO: Self = Self {
        policy_root: [0; 7],
        intent_digest: [0; 7],
        threshold: 0,
        signer_count: 0,
        approval_count: 0,
        approved_slots: [false; SMALLWOOD_MULTISIG_MAX_SIGNERS],
    };

    fn push_words(self, words: &mut Vec<u64>) {
        words.extend_from_slice(&self.policy_root);
        words.extend_from_slice(&self.intent_digest);
        words.push(self.threshold);
        words.push(self.signer_count);
        words.push(self.approval_count);
        words.extend(self.approved_slots.map(u64::from));
    }

    fn parse(cursor: &mut WordCursor<'_>) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        let policy_root = cursor.array()?;
        let intent_digest = cursor.array()?;
        let threshold = cursor.word()?;
        let signer_count = cursor.word()?;
        let approval_count = cursor.word()?;
        let mut approved_slots = [false; SMALLWOOD_MULTISIG_MAX_SIGNERS];
        for slot in &mut approved_slots {
            *slot = cursor.boolean()?;
        }
        Ok(Self {
            policy_root,
            intent_digest,
            threshold,
            signer_count,
            approval_count,
            approved_slots,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8PrivateAuthWitness {
    pub mode: SmallwoodPrivateAuthMode,
    pub current: SmallwoodPoseidon2V8AccumulatorOpening,
    pub next: SmallwoodPoseidon2V8AccumulatorOpening,
    pub policy_signer_tags: [SmallwoodPoseidon2V8SignerTag; SMALLWOOD_MULTISIG_MAX_SIGNERS],
}

impl Default for SmallwoodPoseidon2V8PrivateAuthWitness {
    fn default() -> Self {
        Self {
            mode: SmallwoodPrivateAuthMode::SingleKey,
            current: SmallwoodPoseidon2V8AccumulatorOpening::ZERO,
            next: SmallwoodPoseidon2V8AccumulatorOpening::ZERO,
            policy_signer_tags: [[0; SMALLWOOD_SIGNER_TAG_WORDS]; SMALLWOOD_MULTISIG_MAX_SIGNERS],
        }
    }
}

impl SmallwoodPoseidon2V8PrivateAuthWitness {
    fn mode_word(self) -> u64 {
        match self.mode {
            SmallwoodPrivateAuthMode::SingleKey => 0,
            SmallwoodPrivateAuthMode::ApprovalStep => 1,
            SmallwoodPrivateAuthMode::FinalThresholdSpend => 2,
        }
    }

    fn push_words(self, words: &mut Vec<u64>) {
        words.push(self.mode_word());
        self.current.push_words(words);
        self.next.push_words(words);
        for tag in self.policy_signer_tags {
            words.extend_from_slice(&tag);
        }
    }

    fn parse(cursor: &mut WordCursor<'_>) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        let mode = match cursor.word()? {
            0 => SmallwoodPrivateAuthMode::SingleKey,
            1 => SmallwoodPrivateAuthMode::ApprovalStep,
            2 => SmallwoodPrivateAuthMode::FinalThresholdSpend,
            _ => return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationShape),
        };
        let current = SmallwoodPoseidon2V8AccumulatorOpening::parse(cursor)?;
        let next = SmallwoodPoseidon2V8AccumulatorOpening::parse(cursor)?;
        let mut policy_signer_tags =
            [[0u64; SMALLWOOD_SIGNER_TAG_WORDS]; SMALLWOOD_MULTISIG_MAX_SIGNERS];
        for tag in &mut policy_signer_tags {
            *tag = cursor.array()?;
        }
        Ok(Self {
            mode,
            current,
            next,
            policy_signer_tags,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8Witness {
    pub inputs: [SmallwoodPoseidon2V8InputWitness; SMALLWOOD_POSEIDON2_V8_INPUTS],
    pub outputs: [SmallwoodPoseidon2V8OutputWitness; SMALLWOOD_POSEIDON2_V8_OUTPUTS],
    pub auth: SmallwoodPoseidon2V8PrivateAuthWitness,
    pub stablecoin: StablecoinPoseidon2V8Witness,
}

impl Default for SmallwoodPoseidon2V8Witness {
    fn default() -> Self {
        Self {
            inputs: [SmallwoodPoseidon2V8InputWitness::ZERO; 2],
            outputs: [SmallwoodPoseidon2V8OutputWitness::ZERO; 2],
            auth: SmallwoodPoseidon2V8PrivateAuthWitness::default(),
            stablecoin: StablecoinPoseidon2V8Witness::ZERO,
        }
    }
}

pub const SMALLWOOD_POSEIDON2_V8_NOTE_WORDS: usize = 18;
pub const SMALLWOOD_POSEIDON2_V8_INPUT_WITNESS_WORDS: usize =
    1 + 4 + SMALLWOOD_POSEIDON2_V8_NOTE_WORDS + 1 + 32 * 7 + 4;
pub const SMALLWOOD_POSEIDON2_V8_OUTPUT_WITNESS_WORDS: usize =
    1 + SMALLWOOD_POSEIDON2_V8_NOTE_WORDS + 4;
pub const SMALLWOOD_POSEIDON2_V8_ACCUMULATOR_WORDS: usize = 7 + 7 + 3 + 6;
pub const SMALLWOOD_POSEIDON2_V8_AUTH_WITNESS_WORDS: usize = 1
    + 2 * SMALLWOOD_POSEIDON2_V8_ACCUMULATOR_WORDS
    + SMALLWOOD_MULTISIG_MAX_SIGNERS * SMALLWOOD_SIGNER_TAG_WORDS;
pub const SMALLWOOD_POSEIDON2_V8_STABLE_WITNESS_WORDS: usize = 55 + 4 + 4 * 7 + 7;
pub const SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS: usize = 2
    * SMALLWOOD_POSEIDON2_V8_INPUT_WITNESS_WORDS
    + 2 * SMALLWOOD_POSEIDON2_V8_OUTPUT_WITNESS_WORDS
    + SMALLWOOD_POSEIDON2_V8_AUTH_WITNESS_WORDS
    + SMALLWOOD_POSEIDON2_V8_STABLE_WITNESS_WORDS;
pub const SMALLWOOD_POSEIDON2_V8_WITNESS_BYTES: usize = SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS * 8;

const _: () = assert!(SMALLWOOD_POSEIDON2_V8_NOTE_WORDS == 18);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_INPUT_WITNESS_WORDS == 252);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_OUTPUT_WITNESS_WORDS == 23);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_ACCUMULATOR_WORDS == 23);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_AUTH_WITNESS_WORDS == 77);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_STABLE_WITNESS_WORDS == 94);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS == 721);

impl SmallwoodPoseidon2V8Witness {
    pub fn to_witness_words(self) -> [u64; SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS] {
        let mut words = Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS);
        for input in self.inputs {
            input.push_words(&mut words);
        }
        for output in self.outputs {
            output.push_words(&mut words);
        }
        self.auth.push_words(&mut words);
        push_stablecoin_witness_words(self.stablecoin, &mut words);
        words
            .try_into()
            .expect("V8 witness serializer emits the fixed 721-word grammar")
    }

    pub fn try_from_witness_words(words: &[u64]) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        if words.len() != SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS {
            return Err(SmallwoodPoseidon2V8SurfaceError::WrongWitnessLength);
        }
        ensure_canonical_words(words)?;
        let mut cursor = WordCursor::new(words);
        let inputs = [
            SmallwoodPoseidon2V8InputWitness::parse(&mut cursor)?,
            SmallwoodPoseidon2V8InputWitness::parse(&mut cursor)?,
        ];
        let outputs = [
            SmallwoodPoseidon2V8OutputWitness::parse(&mut cursor)?,
            SmallwoodPoseidon2V8OutputWitness::parse(&mut cursor)?,
        ];
        let auth = SmallwoodPoseidon2V8PrivateAuthWitness::parse(&mut cursor)?;
        let stablecoin = parse_stablecoin_witness(&mut cursor)?;
        if !cursor.exhausted() {
            return Err(SmallwoodPoseidon2V8SurfaceError::WrongWitnessLength);
        }
        Ok(Self {
            inputs,
            outputs,
            auth,
            stablecoin,
        })
    }

    pub fn to_witness_bytes(self) -> [u8; SMALLWOOD_POSEIDON2_V8_WITNESS_BYTES] {
        let mut bytes = [0u8; SMALLWOOD_POSEIDON2_V8_WITNESS_BYTES];
        for (index, word) in self.to_witness_words().iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    pub fn try_from_witness_bytes(bytes: &[u8]) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        if bytes.len() != SMALLWOOD_POSEIDON2_V8_WITNESS_BYTES {
            return Err(SmallwoodPoseidon2V8SurfaceError::WrongWitnessLength);
        }
        let mut words = [0u64; SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS];
        for (index, chunk) in bytes.chunks_exact(8).enumerate() {
            words[index] = u64::from_le_bytes(chunk.try_into().expect("exact eight-byte chunk"));
        }
        Self::try_from_witness_words(&words)
    }
}

struct WordCursor<'a> {
    words: &'a [u64],
    offset: usize,
}

impl<'a> WordCursor<'a> {
    const fn new(words: &'a [u64]) -> Self {
        Self { words, offset: 0 }
    }

    fn word(&mut self) -> Result<u64, SmallwoodPoseidon2V8SurfaceError> {
        let word = self
            .words
            .get(self.offset)
            .copied()
            .ok_or(SmallwoodPoseidon2V8SurfaceError::WrongWitnessLength)?;
        self.offset += 1;
        Ok(word)
    }

    fn boolean(&mut self) -> Result<bool, SmallwoodPoseidon2V8SurfaceError> {
        parse_bool(self.word()?)
    }

    fn array<const N: usize>(&mut self) -> Result<[u64; N], SmallwoodPoseidon2V8SurfaceError> {
        if self.offset + N > self.words.len() {
            return Err(SmallwoodPoseidon2V8SurfaceError::WrongWitnessLength);
        }
        let result = copy_array(self.words, self.offset);
        self.offset += N;
        Ok(result)
    }

    const fn exhausted(&self) -> bool {
        self.offset == self.words.len()
    }
}

fn push_stablecoin_witness_words(witness: StablecoinPoseidon2V8Witness, words: &mut Vec<u64>) {
    words.extend(stablecoin_config_words(witness.config));
    words.extend([
        witness.before.epoch_id,
        witness.before.minted_in_epoch,
        witness.before.total_debt,
        witness.before.sequence,
    ]);
    for sibling in witness.siblings {
        words.extend(sibling.map(|value| value.as_canonical_u64()));
    }
    words.extend(witness.issuer_secret.map(|value| value.as_canonical_u64()));
}

fn stablecoin_config_words(config: StablecoinPoseidon2V8Config) -> [u64; 55] {
    let mut words = [0u64; 55];
    let mut cursor = 0usize;
    let mut push = |word: u64| {
        words[cursor] = word;
        cursor += 1;
    };
    push(u64::from(config.asset_id));
    push(u64::from(config.policy_version));
    push(u64::from(config.active));
    push(config.enabled_at);
    push(u64::from(config.retired_at.is_some()));
    push(config.retired_at.unwrap_or(0));
    for word in felt_digest_to_words(config.issuer_commitment) {
        push(word);
    }
    push(u64::from(config.min_collateral_ratio_ppm));
    push(config.max_mint_per_epoch);
    push(config.oracle_submitted_at);
    push(config.oracle_max_age);
    push(u64::from(config.oracle_price_numerator));
    push(u64::from(config.oracle_price_denominator));
    push(config.collateral_amount);
    push(config.attestation_created_at);
    push(u64::from(config.attestation_disputed));
    push(u64::from(config.attestation_present));
    push(config.attestation_max_age);
    for digest in [
        config.policy_admin_commitment,
        config.oracle_authority_commitment,
        config.attestation_authority_commitment,
    ] {
        for word in felt_digest_to_words(digest) {
            push(word);
        }
    }
    push(u64::from(config.collateral_asset_id));
    push(u64::from(config.collateral_decimals));
    push(config.collateral_scale);
    for word in felt_digest_to_words(config.locked_collateral_commitment) {
        push(word);
    }
    debug_assert_eq!(cursor, words.len());
    words
}

fn parse_stablecoin_witness(
    cursor: &mut WordCursor<'_>,
) -> Result<StablecoinPoseidon2V8Witness, SmallwoodPoseidon2V8SurfaceError> {
    let asset_id = u32::try_from(cursor.word()?)
        .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)?;
    let policy_version = u32::try_from(cursor.word()?)
        .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)?;
    let active = cursor.boolean()?;
    let enabled_at = cursor.word()?;
    let retired_present = cursor.boolean()?;
    let retired_value = cursor.word()?;
    if !retired_present && retired_value != 0 {
        return Err(SmallwoodPoseidon2V8SurfaceError::NonCanonicalStablecoinCompatibility);
    }
    let issuer_commitment = words_to_felt_digest(cursor.array()?)?;
    let min_collateral_ratio_ppm = u32::try_from(cursor.word()?)
        .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)?;
    let max_mint_per_epoch = cursor.word()?;
    let oracle_submitted_at = cursor.word()?;
    let oracle_max_age = cursor.word()?;
    let oracle_price_numerator = u32::try_from(cursor.word()?)
        .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)?;
    let oracle_price_denominator = u32::try_from(cursor.word()?)
        .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)?;
    let collateral_amount = cursor.word()?;
    let attestation_created_at = cursor.word()?;
    let attestation_disputed = cursor.boolean()?;
    let attestation_present = cursor.boolean()?;
    let attestation_max_age = cursor.word()?;
    let policy_admin_commitment = words_to_felt_digest(cursor.array()?)?;
    let oracle_authority_commitment = words_to_felt_digest(cursor.array()?)?;
    let attestation_authority_commitment = words_to_felt_digest(cursor.array()?)?;
    let collateral_asset_id = u32::try_from(cursor.word()?)
        .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)?;
    let collateral_decimals = u8::try_from(cursor.word()?)
        .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)?;
    let collateral_scale = cursor.word()?;
    let locked_collateral_commitment = words_to_felt_digest(cursor.array()?)?;
    let before = StablecoinPoseidon2V8Counters {
        epoch_id: cursor.word()?,
        minted_in_epoch: cursor.word()?,
        total_debt: cursor.word()?,
        sequence: cursor.word()?,
    };
    let mut siblings = [[Felt::ZERO; 7]; STABLECOIN_POSEIDON2_V8_DEPTH];
    for sibling in &mut siblings {
        *sibling = words_to_felt_digest(cursor.array()?)?;
    }
    let issuer_secret = words_to_felt_digest(cursor.array()?)?;
    Ok(StablecoinPoseidon2V8Witness {
        config: StablecoinPoseidon2V8Config {
            asset_id,
            policy_version,
            active,
            enabled_at,
            retired_at: retired_present.then_some(retired_value),
            issuer_commitment,
            min_collateral_ratio_ppm,
            max_mint_per_epoch,
            oracle_submitted_at,
            oracle_max_age,
            oracle_price_numerator,
            oracle_price_denominator,
            collateral_amount,
            attestation_created_at,
            attestation_disputed,
            attestation_present,
            attestation_max_age,
            policy_admin_commitment,
            oracle_authority_commitment,
            attestation_authority_commitment,
            collateral_asset_id,
            collateral_decimals,
            collateral_scale,
            locked_collateral_commitment,
        },
        before,
        siblings,
        issuer_secret,
    })
}

pub fn smallwood_poseidon2_v8_context_words(
    context: StablecoinPoseidon2V8Context,
) -> [u64; SMALLWOOD_POSEIDON2_V8_CONTEXT_WORDS] {
    let mut words = [0u64; SMALLWOOD_POSEIDON2_V8_CONTEXT_WORDS];
    words[..7].copy_from_slice(&felt_digest_to_words(context.current_root));
    words[7] = context.parent_height;
    words[8..].copy_from_slice(&felt_digest_to_words(context.expected_action_intent));
    words
}

pub fn try_smallwood_poseidon2_v8_context_from_words(
    words: &[u64],
) -> Result<StablecoinPoseidon2V8Context, SmallwoodPoseidon2V8SurfaceError> {
    if words.len() != SMALLWOOD_POSEIDON2_V8_CONTEXT_WORDS {
        return Err(SmallwoodPoseidon2V8SurfaceError::WrongContextLength);
    }
    ensure_canonical_words(words)?;
    if words[7] > STABLECOIN_POSEIDON2_V8_MAX_SCALAR {
        return Err(SmallwoodPoseidon2V8SurfaceError::ScalarOutOfRange);
    }
    Ok(StablecoinPoseidon2V8Context {
        current_root: words_to_felt_digest(copy_array(words, 0))?,
        parent_height: words[7],
        expected_action_intent: words_to_felt_digest(copy_array(words, 8))?,
    })
}

fn validate_note_selector(
    active: bool,
    note: SmallwoodPoseidon2V8NoteOpening,
    selectors: [bool; SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS],
    assets: [u64; SMALLWOOD_POSEIDON2_V8_BALANCE_SLOTS],
) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
    if !active {
        if note != SmallwoodPoseidon2V8NoteOpening::ZERO || selectors != [false; 4] {
            return Err(SmallwoodPoseidon2V8SurfaceError::InactiveWitnessSlotNonzero);
        }
        return Ok(());
    }
    note.validate_active()?;
    let selected = selectors.iter().filter(|selected| **selected).count();
    if selected != 1 {
        return Err(SmallwoodPoseidon2V8SurfaceError::InvalidBalanceSelector);
    }
    let selected_index = selectors
        .iter()
        .position(|selected| *selected)
        .expect("one selector is set");
    if assets[selected_index] != note.asset_id {
        return Err(SmallwoodPoseidon2V8SurfaceError::InvalidBalanceSelector);
    }
    Ok(())
}

fn validate_accumulator_opening(
    opening: SmallwoodPoseidon2V8AccumulatorOpening,
) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
    ensure_canonical_words(&opening.policy_root)?;
    ensure_canonical_words(&opening.intent_digest)?;
    if is_zero(&opening.policy_root)
        || is_zero(&opening.intent_digest)
        || opening.signer_count == 0
        || opening.signer_count > SMALLWOOD_MULTISIG_MAX_SIGNERS as u64
        || opening.threshold == 0
        || opening.threshold > opening.signer_count
        || opening.approval_count > opening.signer_count
    {
        return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
    }
    let count = opening
        .approved_slots
        .iter()
        .filter(|approved| **approved)
        .count() as u64;
    if count != opening.approval_count
        || opening.approved_slots[opening.signer_count as usize..]
            .iter()
            .any(|approved| *approved)
    {
        return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
    }
    Ok(())
}

fn validate_signer_tags(
    signer_count: usize,
    tags: [SmallwoodPoseidon2V8SignerTag; SMALLWOOD_MULTISIG_MAX_SIGNERS],
) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
    for (index, tag) in tags.iter().enumerate() {
        ensure_canonical_words(tag)?;
        if index < signer_count {
            if is_zero(tag) {
                return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
            }
            if tags[..index].iter().any(|previous| previous[0] == tag[0]) {
                return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
            }
        } else if !is_zero(tag) {
            return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
        }
    }
    Ok(())
}

fn validate_authorization(
    auth: SmallwoodPoseidon2V8PrivateAuthWitness,
    inputs: [bool; 2],
    outputs: [bool; 2],
) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
    match auth.mode {
        SmallwoodPrivateAuthMode::SingleKey => {
            if auth.current != SmallwoodPoseidon2V8AccumulatorOpening::ZERO
                || auth.next != SmallwoodPoseidon2V8AccumulatorOpening::ZERO
                || auth.policy_signer_tags != [[0; SMALLWOOD_SIGNER_TAG_WORDS]; 6]
            {
                return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationShape);
            }
        }
        SmallwoodPrivateAuthMode::ApprovalStep => {
            // The compact accumulator update has one canonical next-note slot: output zero.
            if inputs != [true, true] || !outputs[0] {
                return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationShape);
            }
            validate_accumulator_opening(auth.current)?;
            validate_accumulator_opening(auth.next)?;
            validate_signer_tags(auth.current.signer_count as usize, auth.policy_signer_tags)?;
            if auth.current.policy_root != auth.next.policy_root
                || auth.current.intent_digest != auth.next.intent_digest
                || auth.current.threshold != auth.next.threshold
                || auth.current.signer_count != auth.next.signer_count
                || auth.next.approval_count != auth.current.approval_count + 1
            {
                return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
            }
            let changes = auth
                .current
                .approved_slots
                .iter()
                .zip(auth.next.approved_slots)
                .filter(|(before, after)| before != &after)
                .count();
            let cleared = auth
                .current
                .approved_slots
                .iter()
                .zip(auth.next.approved_slots)
                .any(|(before, after)| *before && !after);
            if changes != 1 || cleared {
                return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
            }
        }
        SmallwoodPrivateAuthMode::FinalThresholdSpend => {
            if inputs != [true, true] {
                return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationShape);
            }
            validate_accumulator_opening(auth.current)?;
            validate_signer_tags(auth.current.signer_count as usize, auth.policy_signer_tags)?;
            if auth.next != SmallwoodPoseidon2V8AccumulatorOpening::ZERO
                || auth.current.approval_count < auth.current.threshold
            {
                return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
            }
        }
    }
    Ok(())
}

fn signed_magnitude(sign: bool, magnitude: u64) -> i128 {
    if sign {
        -i128::from(magnitude)
    } else {
        i128::from(magnitude)
    }
}

fn validate_balances(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
    let value_balance = signed_magnitude(
        statement.value_balance_sign,
        statement.value_balance_magnitude,
    );
    let stable_delta = signed_magnitude(
        statement.compatibility_stablecoin.issuance_sign,
        statement.compatibility_stablecoin.issuance_magnitude,
    );
    for (slot, asset) in statement.balance_assets.iter().copied().enumerate() {
        if asset == BALANCE_SLOT_PADDING_FIELD_ID {
            continue;
        }
        let mut delta = 0i128;
        for input in witness.inputs {
            if input.active && input.balance_slot_selectors[slot] {
                delta = delta
                    .checked_add(i128::from(input.note.value))
                    .ok_or(SmallwoodPoseidon2V8SurfaceError::BalanceMismatch)?;
            }
        }
        for output in witness.outputs {
            if output.active && output.balance_slot_selectors[slot] {
                delta = delta
                    .checked_sub(i128::from(output.note.value))
                    .ok_or(SmallwoodPoseidon2V8SurfaceError::BalanceMismatch)?;
            }
        }
        let expected = if asset == NATIVE_ASSET_ID {
            i128::from(statement.fee) - value_balance
        } else if statement.compatibility_stablecoin.enabled
            && asset == statement.compatibility_stablecoin.asset_id
        {
            stable_delta
        } else {
            0
        };
        if delta != expected {
            return Err(SmallwoodPoseidon2V8SurfaceError::BalanceMismatch);
        }
    }
    Ok(())
}

impl SmallwoodPoseidon2V8Witness {
    pub fn validate_against_statement(
        &self,
        statement: &SmallwoodPoseidon2V8PublicStatement,
    ) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
        statement.validate_public_structure()?;
        ensure_canonical_words(&self.to_witness_words())?;
        for slot in 0..2 {
            let input = self.inputs[slot];
            if input.active != statement.input_flags[slot] {
                return Err(SmallwoodPoseidon2V8SurfaceError::ActivityMismatch);
            }
            if !input.active {
                if input != SmallwoodPoseidon2V8InputWitness::ZERO {
                    return Err(SmallwoodPoseidon2V8SurfaceError::InactiveWitnessSlotNonzero);
                }
            } else {
                input.note.validate_active()?;
                ensure_canonical_words(&input.spend_key)?;
                if is_zero(&input.spend_key) || input.position >> 32 != 0 {
                    return Err(SmallwoodPoseidon2V8SurfaceError::ScalarOutOfRange);
                }
                for sibling in input.siblings {
                    ensure_canonical_words(&sibling)?;
                }
            }
            validate_note_selector(
                input.active,
                input.note,
                input.balance_slot_selectors,
                statement.balance_assets,
            )?;

            let output = self.outputs[slot];
            if output.active != statement.output_flags[slot] {
                return Err(SmallwoodPoseidon2V8SurfaceError::ActivityMismatch);
            }
            if !output.active && output != SmallwoodPoseidon2V8OutputWitness::ZERO {
                return Err(SmallwoodPoseidon2V8SurfaceError::InactiveWitnessSlotNonzero);
            }
            validate_note_selector(
                output.active,
                output.note,
                output.balance_slot_selectors,
                statement.balance_assets,
            )?;
        }
        if self.inputs[0].active
            && self.inputs[1].active
            && self.inputs[0].spend_key != self.inputs[1].spend_key
        {
            return Err(SmallwoodPoseidon2V8SurfaceError::SpendKeyMismatch);
        }
        validate_authorization(self.auth, statement.input_flags, statement.output_flags)?;
        validate_balances(statement, self)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8SemanticSurface {
    pub statement: SmallwoodPoseidon2V8PublicStatement,
    pub witness: SmallwoodPoseidon2V8Witness,
    pub stablecoin_context: StablecoinPoseidon2V8Context,
}

impl SmallwoodPoseidon2V8SemanticSurface {
    pub fn validate(&self) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
        self.statement.validate_public_structure()?;
        self.witness.validate_against_statement(&self.statement)?;
        let context_words = smallwood_poseidon2_v8_context_words(self.stablecoin_context);
        ensure_canonical_words(&context_words)?;
        if self.stablecoin_context.parent_height > STABLECOIN_POSEIDON2_V8_MAX_SCALAR {
            return Err(SmallwoodPoseidon2V8SurfaceError::ScalarOutOfRange);
        }
        verify_stablecoin_transition_v8(
            self.stablecoin_context,
            self.statement.stablecoin,
            self.witness.stablecoin,
        )?;
        Ok(())
    }

    /// Validate the proof relation inputs and the exact ciphertext bytes that
    /// the self-contained action carries.  Ciphertexts are public action data,
    /// not private proof-witness words, but their BLAKE2b-384 commitments are
    /// part of the 120-word proof statement.
    pub fn validate_with_inline_ciphertexts(
        &self,
        inline_ciphertexts: &SmallwoodPoseidon2V8InlineCiphertexts,
    ) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
        self.validate()?;
        inline_ciphertexts.validate_against_statement(&self.statement)
    }
}

pub type SmallwoodPoseidon2V8Ciphertext = [u8; SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES];

/// Exact active-output ciphertexts carried inline by one canonical action.
///
/// `None` is the only encoding for an inactive output.  An active output is
/// always exactly 2,147 bytes.  The canonical byte projection concatenates
/// active slots in slot order; output flags in the 120-word statement make the
/// projection uniquely decodable without lengths or a second activity mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8InlineCiphertexts {
    pub ciphertexts: [Option<SmallwoodPoseidon2V8Ciphertext>; SMALLWOOD_POSEIDON2_V8_OUTPUTS],
}

impl Default for SmallwoodPoseidon2V8InlineCiphertexts {
    fn default() -> Self {
        Self {
            ciphertexts: [None; SMALLWOOD_POSEIDON2_V8_OUTPUTS],
        }
    }
}

/// Compute the exact six public words committed at `[32,44)` for an active
/// output.  `ciphertext_hash_bytes` is the repository's conventional RFC 7693
/// BLAKE2b-384 transaction-ciphertext domain frame; `bytes48_to_felts` merely
/// reads its canonical six-word public encoding.
pub fn smallwood_poseidon2_v8_ciphertext_commitment(
    ciphertext: &SmallwoodPoseidon2V8Ciphertext,
) -> SmallwoodPoseidon2V8CiphertextCommitment {
    bytes48_to_felts(&ciphertext_hash_bytes(ciphertext))
        .expect("ciphertext_hash_bytes always returns six canonical field words")
        .map(|word| word.as_canonical_u64())
}

impl SmallwoodPoseidon2V8InlineCiphertexts {
    pub fn encoded_len_for_output_flags(
        output_flags: [bool; SMALLWOOD_POSEIDON2_V8_OUTPUTS],
    ) -> usize {
        output_flags.iter().filter(|active| **active).count()
            * SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES
    }

    pub fn encoded_len(&self) -> usize {
        self.ciphertexts
            .iter()
            .filter(|ciphertext| ciphertext.is_some())
            .count()
            * SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES
    }

    pub fn to_inline_ciphertext_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        for ciphertext in self.ciphertexts.iter().flatten() {
            bytes.extend_from_slice(ciphertext);
        }
        bytes
    }

    /// Parse only after checking the exact statement-derived byte count.  The
    /// parser allocates no attacker-sized buffer: the result owns two fixed
    /// arrays and inactive slots remain `None`.
    pub fn try_from_inline_ciphertext_bytes(
        statement: &SmallwoodPoseidon2V8PublicStatement,
        bytes: &[u8],
    ) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        statement.validate_public_structure()?;
        let expected = Self::encoded_len_for_output_flags(statement.output_flags);
        if bytes.len() != expected {
            return Err(SmallwoodPoseidon2V8SurfaceError::WrongCiphertextLength);
        }

        let mut ciphertexts = [None; SMALLWOOD_POSEIDON2_V8_OUTPUTS];
        let mut offset = 0usize;
        for (slot, active) in statement.output_flags.iter().copied().enumerate() {
            if active {
                let end = offset + SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES;
                let mut ciphertext = [0u8; SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES];
                ciphertext.copy_from_slice(&bytes[offset..end]);
                ciphertexts[slot] = Some(ciphertext);
                offset = end;
            }
        }
        debug_assert_eq!(offset, bytes.len());
        let result = Self { ciphertexts };
        result.validate_against_statement(statement)?;
        Ok(result)
    }

    pub fn validate_against_statement(
        &self,
        statement: &SmallwoodPoseidon2V8PublicStatement,
    ) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
        statement.validate_public_structure()?;
        for slot in 0..SMALLWOOD_POSEIDON2_V8_OUTPUTS {
            match (
                statement.output_flags[slot],
                self.ciphertexts[slot].as_ref(),
            ) {
                (false, None) => {}
                (true, Some(ciphertext)) => {
                    if smallwood_poseidon2_v8_ciphertext_commitment(ciphertext)
                        != statement.ciphertext_commitments[slot]
                    {
                        return Err(SmallwoodPoseidon2V8SurfaceError::CiphertextCommitmentMismatch);
                    }
                }
                _ => {
                    return Err(SmallwoodPoseidon2V8SurfaceError::CiphertextActivityMismatch);
                }
            }
        }
        Ok(())
    }
}

/// Consensus-visible public/action projection.  This is deliberately separate
/// from the private witness surface so ciphertext bytes are carried once, in
/// the canonical action itself, and are rebound before proof verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8ActionSurface {
    pub statement: SmallwoodPoseidon2V8PublicStatement,
    pub inline_ciphertexts: SmallwoodPoseidon2V8InlineCiphertexts,
}

impl SmallwoodPoseidon2V8ActionSurface {
    pub fn validate(&self) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
        self.inline_ciphertexts
            .validate_against_statement(&self.statement)
    }

    pub fn to_inline_ciphertext_bytes(&self) -> Vec<u8> {
        self.inline_ciphertexts.to_inline_ciphertext_bytes()
    }

    pub fn try_from_inline_ciphertext_bytes(
        statement: SmallwoodPoseidon2V8PublicStatement,
        bytes: &[u8],
    ) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        let inline_ciphertexts =
            SmallwoodPoseidon2V8InlineCiphertexts::try_from_inline_ciphertext_bytes(
                &statement, bytes,
            )?;
        Ok(Self {
            statement,
            inline_ciphertexts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transaction_core::stablecoin_poseidon2_v8::{
        stablecoin_poseidon2_v8_config_digest, stablecoin_poseidon2_v8_issuer_authorization,
        stablecoin_poseidon2_v8_issuer_commitment, stablecoin_poseidon2_v8_root,
    };

    fn digest(tag: u64) -> SmallwoodPoseidon2V8Digest {
        core::array::from_fn(|index| tag + index as u64)
    }

    fn felt_digest(tag: u64) -> [Felt; 7] {
        digest(tag).map(Felt::from_u64)
    }

    fn active_input(tag: u64) -> SmallwoodPoseidon2V8InputWitness {
        SmallwoodPoseidon2V8InputWitness {
            active: true,
            spend_key: [tag; 4],
            note: SmallwoodPoseidon2V8NoteOpening {
                value: 0,
                asset_id: NATIVE_ASSET_ID,
                recipient_key: [tag + 1; 4],
                authorization_key: [tag + 2; 4],
                rho: [tag + 3; 4],
                randomness: [tag + 4; 4],
            },
            position: tag,
            siblings: core::array::from_fn(|level| digest(tag + 10 + level as u64 * 8)),
            balance_slot_selectors: [true, false, false, false],
        }
    }

    fn active_output(tag: u64) -> SmallwoodPoseidon2V8OutputWitness {
        SmallwoodPoseidon2V8OutputWitness {
            active: true,
            note: SmallwoodPoseidon2V8NoteOpening {
                value: 0,
                asset_id: NATIVE_ASSET_ID,
                recipient_key: [tag + 1; 4],
                authorization_key: [tag + 2; 4],
                rho: [tag + 3; 4],
                randomness: [tag + 4; 4],
            },
            balance_slot_selectors: [true, false, false, false],
        }
    }

    fn ciphertext(tag: u8) -> SmallwoodPoseidon2V8Ciphertext {
        core::array::from_fn(|index| tag.wrapping_add(index as u8))
    }

    fn opening(approval_count: u64, slots: &[usize]) -> SmallwoodPoseidon2V8AccumulatorOpening {
        let mut approved_slots = [false; 6];
        for slot in slots {
            approved_slots[*slot] = true;
        }
        SmallwoodPoseidon2V8AccumulatorOpening {
            policy_root: digest(700),
            intent_digest: digest(800),
            threshold: 1,
            signer_count: 2,
            approval_count,
            approved_slots,
        }
    }

    fn auth(mode: SmallwoodPrivateAuthMode) -> SmallwoodPoseidon2V8PrivateAuthWitness {
        match mode {
            SmallwoodPrivateAuthMode::SingleKey => {
                SmallwoodPoseidon2V8PrivateAuthWitness::default()
            }
            SmallwoodPrivateAuthMode::ApprovalStep => {
                let mut tags = [[0u64; 5]; 6];
                tags[0] = [1, 2, 3, 4, 5];
                tags[1] = [6, 7, 8, 9, 10];
                SmallwoodPoseidon2V8PrivateAuthWitness {
                    mode,
                    current: opening(0, &[]),
                    next: opening(1, &[0]),
                    policy_signer_tags: tags,
                }
            }
            SmallwoodPrivateAuthMode::FinalThresholdSpend => {
                let mut tags = [[0u64; 5]; 6];
                tags[0] = [1, 2, 3, 4, 5];
                tags[1] = [6, 7, 8, 9, 10];
                SmallwoodPoseidon2V8PrivateAuthWitness {
                    mode,
                    current: opening(1, &[0]),
                    next: SmallwoodPoseidon2V8AccumulatorOpening::ZERO,
                    policy_signer_tags: tags,
                }
            }
        }
    }

    fn mask_surface(
        mask: u8,
        mode: SmallwoodPrivateAuthMode,
    ) -> SmallwoodPoseidon2V8SemanticSurface {
        let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
        let mut witness = SmallwoodPoseidon2V8Witness::default();
        for slot in 0..2 {
            let input_active = mask & (1 << slot) != 0;
            statement.input_flags[slot] = input_active;
            if input_active {
                statement.nullifiers[slot] = digest(10 + slot as u64 * 10);
                let mut input = active_input(100 + slot as u64 * 100);
                input.spend_key = [777; 4];
                witness.inputs[slot] = input;
            }
            let output_active = mask & (1 << (slot + 2)) != 0;
            statement.output_flags[slot] = output_active;
            if output_active {
                statement.commitments[slot] = digest(30 + slot as u64 * 10);
                statement.ciphertext_commitments[slot] =
                    core::array::from_fn(|index| 50 + slot as u64 * 10 + index as u64);
                witness.outputs[slot] = active_output(300 + slot as u64 * 100);
            }
        }
        if statement.input_flags.iter().any(|active| *active) {
            statement.merkle_root = digest(900);
        }
        witness.auth = auth(mode);
        SmallwoodPoseidon2V8SemanticSurface {
            statement,
            witness,
            stablecoin_context: StablecoinPoseidon2V8Context {
                current_root: [Felt::ZERO; 7],
                parent_height: 0,
                expected_action_intent: [Felt::ZERO; 7],
            },
        }
    }

    fn mask_action_surface(
        mask: u8,
    ) -> (
        SmallwoodPoseidon2V8SemanticSurface,
        SmallwoodPoseidon2V8ActionSurface,
    ) {
        let mut semantic = mask_surface(mask, SmallwoodPrivateAuthMode::SingleKey);
        let mut inline_ciphertexts = SmallwoodPoseidon2V8InlineCiphertexts::default();
        for slot in 0..SMALLWOOD_POSEIDON2_V8_OUTPUTS {
            if semantic.statement.output_flags[slot] {
                let bytes = ciphertext(0x40 + slot as u8);
                semantic.statement.ciphertext_commitments[slot] =
                    smallwood_poseidon2_v8_ciphertext_commitment(&bytes);
                inline_ciphertexts.ciphertexts[slot] = Some(bytes);
            }
        }
        let action = SmallwoodPoseidon2V8ActionSurface {
            statement: semantic.statement,
            inline_ciphertexts,
        };
        (semantic, action)
    }

    #[test]
    fn inline_ciphertexts_roundtrip_and_bind_all_sixteen_masks() {
        for mask in 0..16u8 {
            let (semantic, action) = mask_action_surface(mask);
            action.validate().unwrap();
            semantic
                .validate_with_inline_ciphertexts(&action.inline_ciphertexts)
                .unwrap();

            let encoded = action.to_inline_ciphertext_bytes();
            assert_eq!(
                encoded.len(),
                (mask & 0b1100).count_ones() as usize * SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES
            );
            assert_eq!(
                SmallwoodPoseidon2V8ActionSurface::try_from_inline_ciphertext_bytes(
                    action.statement,
                    &encoded,
                )
                .unwrap(),
                action
            );

            for slot in 0..SMALLWOOD_POSEIDON2_V8_OUTPUTS {
                if action.statement.output_flags[slot] {
                    let mut mutated = action;
                    mutated.inline_ciphertexts.ciphertexts[slot]
                        .as_mut()
                        .expect("active slot")[slot] ^= 1;
                    assert_eq!(
                        mutated.validate(),
                        Err(SmallwoodPoseidon2V8SurfaceError::CiphertextCommitmentMismatch)
                    );
                }
            }
        }
    }

    #[test]
    fn inline_ciphertext_shape_and_length_mutations_fail_closed() {
        let (_, action) = mask_action_surface(0b1100);
        let encoded = action.to_inline_ciphertext_bytes();
        assert_eq!(
            encoded.len(),
            SMALLWOOD_POSEIDON2_V8_MAX_INLINE_CIPHERTEXT_BYTES
        );
        assert_eq!(
            SmallwoodPoseidon2V8ActionSurface::try_from_inline_ciphertext_bytes(
                action.statement,
                &encoded[..encoded.len() - 1],
            ),
            Err(SmallwoodPoseidon2V8SurfaceError::WrongCiphertextLength)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            SmallwoodPoseidon2V8ActionSurface::try_from_inline_ciphertext_bytes(
                action.statement,
                &trailing,
            ),
            Err(SmallwoodPoseidon2V8SurfaceError::WrongCiphertextLength)
        );

        let mut missing = action;
        missing.inline_ciphertexts.ciphertexts[0] = None;
        assert_eq!(
            missing.validate(),
            Err(SmallwoodPoseidon2V8SurfaceError::CiphertextActivityMismatch)
        );

        let (_, mut inactive) = mask_action_surface(0);
        inactive.inline_ciphertexts.ciphertexts[1] = Some(ciphertext(0x55));
        assert_eq!(
            inactive.validate(),
            Err(SmallwoodPoseidon2V8SurfaceError::CiphertextActivityMismatch)
        );
    }

    #[test]
    fn exact_public_offsets_roundtrip_all_sixteen_masks() {
        for mask in 0..16u8 {
            let surface = mask_surface(mask, SmallwoodPrivateAuthMode::SingleKey);
            let words = surface.statement.to_public_words();
            assert_eq!(words.len(), 120);
            assert_eq!(surface.statement.activity_mask(), mask);
            assert_eq!(
                SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&words).unwrap(),
                surface.statement
            );
            assert_eq!(
                SmallwoodPoseidon2V8PublicStatement::try_from_public_bytes(
                    &surface.statement.to_public_bytes()
                )
                .unwrap(),
                surface.statement
            );
            surface.validate().unwrap();
        }
    }

    #[test]
    fn all_masks_and_all_compact_auth_modes_have_exact_shape_results() {
        for mask in 0..16u8 {
            for mode in [
                SmallwoodPrivateAuthMode::SingleKey,
                SmallwoodPrivateAuthMode::ApprovalStep,
                SmallwoodPrivateAuthMode::FinalThresholdSpend,
            ] {
                let surface = mask_surface(mask, mode);
                let words = surface.witness.to_witness_words();
                assert_eq!(words.len(), 721);
                assert_eq!(
                    SmallwoodPoseidon2V8Witness::try_from_witness_words(&words).unwrap(),
                    surface.witness
                );
                assert_eq!(
                    SmallwoodPoseidon2V8Witness::try_from_witness_bytes(
                        &surface.witness.to_witness_bytes()
                    )
                    .unwrap(),
                    surface.witness
                );
                let expected_valid = match mode {
                    SmallwoodPrivateAuthMode::SingleKey => true,
                    SmallwoodPrivateAuthMode::ApprovalStep => {
                        mask & 0b0011 == 0b0011 && mask & 0b0100 != 0
                    }
                    SmallwoodPrivateAuthMode::FinalThresholdSpend => mask & 0b0011 == 0b0011,
                };
                assert_eq!(
                    surface.validate().is_ok(),
                    expected_valid,
                    "mask={mask} {mode:?}"
                );
            }
        }
    }

    #[test]
    fn intent_projection_zeroes_four_half_open_ranges_including_root() {
        let mut statement = mask_surface(0b0101, SmallwoodPrivateAuthMode::SingleKey).statement;
        statement.stablecoin.action_intent = felt_digest(1_000);
        statement.stablecoin.issuer_authorization = felt_digest(2_000);
        let projection = statement.action_intent_projection_words();
        assert_eq!(&projection[4..18], &[0; 14]);
        assert_eq!(&projection[47..54], &[0; 7]);
        assert_eq!(&projection[87..94], &[0; 7]);
        assert_eq!(&projection[113..120], &[0; 7]);

        let digest_before = statement.expected_action_intent().unwrap();
        statement.nullifiers[0][0] += 1;
        assert_eq!(statement.expected_action_intent().unwrap(), digest_before);
        statement.stablecoin.action_intent[0] += Felt::ONE;
        assert_eq!(statement.expected_action_intent().unwrap(), digest_before);
        statement.stablecoin.issuer_authorization[0] += Felt::ONE;
        assert_eq!(statement.expected_action_intent().unwrap(), digest_before);
        statement.merkle_root[0] += 1;
        assert_eq!(statement.expected_action_intent().unwrap(), digest_before);
    }

    #[test]
    fn malformed_public_and_witness_encodings_fail_closed() {
        let surface = mask_surface(0b0101, SmallwoodPrivateAuthMode::SingleKey);
        let mut public = surface.statement.to_public_words();
        public[63] = 1;
        assert_eq!(
            SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&public),
            Err(SmallwoodPoseidon2V8SurfaceError::NonCanonicalStablecoinCompatibility)
        );
        let mut public = surface.statement.to_public_words();
        public[4] = FIELD_MODULUS_U64;
        assert_eq!(
            SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&public),
            Err(SmallwoodPoseidon2V8SurfaceError::NonCanonicalField)
        );
        assert_eq!(
            SmallwoodPoseidon2V8PublicStatement::try_from_public_bytes(
                &surface.statement.to_public_bytes()[..959]
            ),
            Err(SmallwoodPoseidon2V8SurfaceError::WrongPublicLength)
        );

        let mut negative_zero = surface.statement;
        negative_zero.value_balance_sign = true;
        negative_zero.value_balance_magnitude = 0;
        let negative_zero_words = negative_zero.to_public_words();
        assert_eq!(negative_zero_words[45], 1);
        assert_eq!(negative_zero_words[46], 0);
        assert_eq!(
            negative_zero.validate_public_structure(),
            Err(SmallwoodPoseidon2V8SurfaceError::NegativeZeroValueBalance)
        );
        assert_eq!(
            SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&negative_zero_words),
            Err(SmallwoodPoseidon2V8SurfaceError::NegativeZeroValueBalance)
        );
        assert_eq!(
            SmallwoodPoseidon2V8PublicStatement::try_from_public_bytes(
                &negative_zero.to_public_bytes()
            ),
            Err(SmallwoodPoseidon2V8SurfaceError::NegativeZeroValueBalance)
        );

        let mut witness = surface.witness.to_witness_words();
        witness[248] = 2;
        assert_eq!(
            SmallwoodPoseidon2V8Witness::try_from_witness_words(&witness),
            Err(SmallwoodPoseidon2V8SurfaceError::NonBoolean)
        );
        assert_eq!(
            SmallwoodPoseidon2V8Witness::try_from_witness_words(
                &surface.witness.to_witness_words()[..720]
            ),
            Err(SmallwoodPoseidon2V8SurfaceError::WrongWitnessLength)
        );
        let mut mutated = surface;
        mutated.witness.inputs[1].spend_key[0] = 1;
        assert_eq!(
            mutated.validate(),
            Err(SmallwoodPoseidon2V8SurfaceError::InactiveWitnessSlotNonzero)
        );

        let mut unequal_keys = mask_surface(0b0011, SmallwoodPrivateAuthMode::SingleKey);
        unequal_keys.witness.inputs[1].spend_key[0] += 1;
        assert_eq!(
            unequal_keys.validate(),
            Err(SmallwoodPoseidon2V8SurfaceError::SpendKeyMismatch)
        );

        let mut first_limb_collision = mask_surface(0b0111, SmallwoodPrivateAuthMode::ApprovalStep);
        first_limb_collision.witness.auth.policy_signer_tags[1] = [1, 90, 91, 92, 93];
        assert_eq!(
            first_limb_collision.validate(),
            Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening)
        );
    }

    fn stablecoin_surface() -> SmallwoodPoseidon2V8SemanticSurface {
        const HEIGHT: u64 = 9_000;
        let issuer_secret = felt_digest(11);
        let asset_id = 1_001;
        let policy_version = 7;
        let config = StablecoinPoseidon2V8Config {
            asset_id,
            policy_version,
            active: true,
            enabled_at: 1,
            retired_at: Some(20_000),
            issuer_commitment: stablecoin_poseidon2_v8_issuer_commitment(
                asset_id,
                policy_version,
                &issuer_secret,
            ),
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000,
            oracle_submitted_at: 8_900,
            oracle_max_age: 500,
            oracle_price_numerator: 2,
            oracle_price_denominator: 1,
            collateral_amount: 10_000,
            attestation_created_at: 8_800,
            attestation_disputed: false,
            attestation_present: true,
            attestation_max_age: 500,
            policy_admin_commitment: felt_digest(101),
            oracle_authority_commitment: felt_digest(201),
            attestation_authority_commitment: felt_digest(301),
            collateral_asset_id: 0,
            collateral_decimals: 6,
            collateral_scale: 1_000_000,
            locked_collateral_commitment: felt_digest(401),
        };
        let before = StablecoinPoseidon2V8Counters {
            epoch_id: HEIGHT >> 12,
            minted_in_epoch: 100,
            total_debt: 1_000,
            sequence: 9,
        };
        let after = StablecoinPoseidon2V8Counters {
            epoch_id: HEIGHT >> 12,
            minted_in_epoch: 125,
            total_debt: 1_025,
            sequence: 10,
        };
        let siblings = [
            felt_digest(501),
            felt_digest(601),
            felt_digest(701),
            felt_digest(801),
        ];
        let config_digest = stablecoin_poseidon2_v8_config_digest(config);
        let before_root =
            stablecoin_poseidon2_v8_root(asset_id, config_digest, before, &siblings).unwrap();
        let after_root =
            stablecoin_poseidon2_v8_root(asset_id, config_digest, after, &siblings).unwrap();

        let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
        statement.output_flags[0] = true;
        statement.commitments[0] = digest(30);
        statement.ciphertext_commitments[0] = [41, 42, 43, 44, 45, 46];
        statement.balance_assets = [
            NATIVE_ASSET_ID,
            u64::from(asset_id),
            BALANCE_SLOT_PADDING_FIELD_ID,
            BALANCE_SLOT_PADDING_FIELD_ID,
        ];
        statement.compatibility_stablecoin = SmallwoodPoseidon2V8CompatibilityStablecoin {
            enabled: true,
            asset_id: u64::from(asset_id),
            policy_version,
            issuance_sign: true,
            issuance_magnitude: 25,
            reserved_legacy_stablecoin_commitments: [[0; 6]; 3],
        };
        statement.stablecoin = StablecoinPoseidon2V8Public {
            direction: StablecoinPoseidon2V8Direction::Mint,
            asset_id,
            policy_version,
            magnitude: 25,
            action_intent: [Felt::ZERO; 7],
            parent_height: HEIGHT,
            before_root,
            after_root,
            after,
            issuer_authorization: [Felt::ZERO; 7],
        };
        let intent = statement
            .expected_action_intent()
            .unwrap()
            .map(Felt::from_u64);
        statement.stablecoin.action_intent = intent;
        statement.stablecoin.issuer_authorization =
            stablecoin_poseidon2_v8_issuer_authorization(&intent, &issuer_secret);

        let mut witness = SmallwoodPoseidon2V8Witness::default();
        witness.outputs[0] = SmallwoodPoseidon2V8OutputWitness {
            active: true,
            note: SmallwoodPoseidon2V8NoteOpening {
                value: 25,
                asset_id: u64::from(asset_id),
                recipient_key: [1; 4],
                authorization_key: [2; 4],
                rho: [3; 4],
                randomness: [4; 4],
            },
            balance_slot_selectors: [false, true, false, false],
        };
        witness.stablecoin = StablecoinPoseidon2V8Witness {
            config,
            before,
            siblings,
            issuer_secret,
        };
        SmallwoodPoseidon2V8SemanticSurface {
            statement,
            witness,
            stablecoin_context: StablecoinPoseidon2V8Context {
                current_root: before_root,
                parent_height: HEIGHT,
                expected_action_intent: intent,
            },
        }
    }

    #[test]
    fn enabled_stablecoin_context_and_private_h7_roles_roundtrip_and_mutate_closed() {
        let surface = stablecoin_surface();
        surface.validate().unwrap();
        let public = surface.statement.to_public_words();
        assert_eq!(&public[63..81], &[0u64; 18]);
        assert_eq!(
            SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&public).unwrap(),
            surface.statement
        );
        let witness = surface.witness.to_witness_words();
        assert_eq!(
            SmallwoodPoseidon2V8Witness::try_from_witness_words(&witness).unwrap(),
            surface.witness
        );
        let context = smallwood_poseidon2_v8_context_words(surface.stablecoin_context);
        assert_eq!(
            try_smallwood_poseidon2_v8_context_from_words(&context).unwrap(),
            surface.stablecoin_context
        );

        let mut reserved = public;
        reserved[80] = 1;
        assert_eq!(
            SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&reserved),
            Err(SmallwoodPoseidon2V8SurfaceError::StablecoinSurfaceMismatch)
        );
        let mut mutated = surface;
        mutated.witness.stablecoin.before.total_debt += 1;
        assert!(mutated.validate().is_err());
        let mut mutated = surface;
        mutated.statement.stablecoin.parent_height += 1;
        assert_eq!(
            mutated.validate(),
            Err(SmallwoodPoseidon2V8SurfaceError::ActionIntentMismatch)
        );
    }

    #[test]
    fn burn_public_statement_requires_zero_issuer_authorization_words() {
        let mut burn = stablecoin_surface().statement;
        burn.compatibility_stablecoin.issuance_sign = false;
        burn.stablecoin.direction = StablecoinPoseidon2V8Direction::Burn;
        burn.stablecoin.issuer_authorization = [Felt::ZERO; 7];
        burn.stablecoin.action_intent = burn.expected_action_intent().unwrap().map(Felt::from_u64);

        burn.validate_public_structure().unwrap();
        let words = burn.to_public_words();
        assert_eq!(&words[113..120], &[0; 7]);
        assert_eq!(
            SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&words).unwrap(),
            burn
        );

        for issuer_word in 113..120 {
            let mut malformed = words;
            malformed[issuer_word] = 1;
            assert_eq!(
                SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&malformed),
                Err(SmallwoodPoseidon2V8SurfaceError::StablecoinSurfaceMismatch),
                "burn issuer authorization word {issuer_word} was accepted"
            );
        }
    }

    #[test]
    fn mint_public_statement_accepts_its_bound_issuer_authorization() {
        let mint = stablecoin_surface().statement;
        assert!(!is_zero(&felt_digest_to_words(
            mint.stablecoin.issuer_authorization
        )));
        mint.validate_public_structure().unwrap();
        assert_eq!(
            SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&mint.to_public_words())
                .unwrap(),
            mint
        );
    }
}
