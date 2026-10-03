//! Canonical Poseidon2 V8 stablecoin state transition.
//!
//! This module is the semantic source for the fresh V8 transaction relation.
//! It deliberately does not reuse the prospective BLAKE2b V3 wire identity.
//! The relation compiler must constrain every check performed by
//! [`verify_stablecoin_transition_v8`].

use crate::poseidon2_width16::{
    poseidon2_width16_compress14, Felt, Poseidon2Width16Digest, POSEIDON2_WIDTH16_DIGEST,
};

pub const STABLECOIN_POSEIDON2_V8_DEPTH: usize = 4;
pub const STABLECOIN_POSEIDON2_V8_CAP: usize = 1 << STABLECOIN_POSEIDON2_V8_DEPTH;
pub const STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT: u32 = 12;
pub const STABLECOIN_POSEIDON2_V8_RATIO_SCALE_PPM: u64 = 1_000_000;
pub const STABLECOIN_POSEIDON2_V8_MAX_VALUE: u64 = (1u64 << 56) - 1;
/// Fresh V8 consensus/source admission cap for every otherwise-unrestricted
/// scalar encoded in one Goldilocks element. This is strictly below the field
/// modulus, so the field projection is injective.
pub const STABLECOIN_POSEIDON2_V8_MAX_SCALAR: u64 = (1u64 << 63) - 1;

/// The exact transition schedule consumes nineteen width-16 permutations.
///
/// The V8 transaction statement grows from 83 to 120 authorized field
/// elements. Its action-intent sponge therefore grows from eleven to fifteen
/// permutations. The private config is authenticated by the before/after
/// leaves and is not disclosed in the statement.
pub const STABLECOIN_POSEIDON2_V8_CONFIG_PERMUTATIONS: usize = 7;
pub const STABLECOIN_POSEIDON2_V8_LEAF_PERMUTATIONS: usize = 2;
pub const STABLECOIN_POSEIDON2_V8_PATH_PERMUTATIONS: usize = 2 * STABLECOIN_POSEIDON2_V8_DEPTH;
pub const STABLECOIN_POSEIDON2_V8_ISSUER_PERMUTATIONS: usize = 2;
pub const STABLECOIN_POSEIDON2_V8_TRANSITION_PERMUTATIONS: usize =
    STABLECOIN_POSEIDON2_V8_CONFIG_PERMUTATIONS
        + STABLECOIN_POSEIDON2_V8_LEAF_PERMUTATIONS
        + STABLECOIN_POSEIDON2_V8_PATH_PERMUTATIONS
        + STABLECOIN_POSEIDON2_V8_ISSUER_PERMUTATIONS;
pub const STABLECOIN_POSEIDON2_V8_BASE_PUBLIC_FIELDS: usize = 83;
pub const STABLECOIN_POSEIDON2_V8_PUBLIC_FIELD_DELTA: usize = 37;
pub const STABLECOIN_POSEIDON2_V8_AUTHORIZED_PUBLIC_FIELDS: usize =
    STABLECOIN_POSEIDON2_V8_BASE_PUBLIC_FIELDS + STABLECOIN_POSEIDON2_V8_PUBLIC_FIELD_DELTA;
pub const STABLECOIN_POSEIDON2_V8_BASE_INTENT_PERMUTATIONS: usize =
    STABLECOIN_POSEIDON2_V8_BASE_PUBLIC_FIELDS.div_ceil(8);
pub const STABLECOIN_POSEIDON2_V8_INTENT_PERMUTATIONS: usize =
    STABLECOIN_POSEIDON2_V8_AUTHORIZED_PUBLIC_FIELDS.div_ceil(8);
pub const STABLECOIN_POSEIDON2_V8_TOTAL_ADDED_PERMUTATIONS: usize =
    STABLECOIN_POSEIDON2_V8_TRANSITION_PERMUTATIONS + STABLECOIN_POSEIDON2_V8_INTENT_PERMUTATIONS
        - STABLECOIN_POSEIDON2_V8_BASE_INTENT_PERMUTATIONS;

pub const STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_0: u64 = 0x4853_4338_4346_3000;
pub const STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_1: u64 = 0x4853_4338_4346_3100;
pub const STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_2: u64 = 0x4853_4338_4346_3200;
pub const STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_3: u64 = 0x4853_4338_4346_3300;
pub const STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_0: u64 = 0x4853_4338_434e_3000;
pub const STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_1: u64 = 0x4853_4338_434e_3100;
pub const STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_ROOT: u64 = 0x4853_4338_4346_5200;
pub const STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF: u64 = 0x4853_4338_4c45_4146;
pub const STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_NODE_0: u64 = 0x4853_4338_4e4f_4400;
pub const STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT: u64 = 0x4853_4338_4953_434d;
pub const STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_AUTHORIZATION: u64 = 0x4853_4338_4953_4155;

const DOMAIN_CONFIG_CHUNK_0: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_0;
const DOMAIN_CONFIG_CHUNK_1: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_1;
const DOMAIN_CONFIG_CHUNK_2: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_2;
const DOMAIN_CONFIG_CHUNK_3: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_3;
const DOMAIN_CONFIG_NODE_0: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_0;
const DOMAIN_CONFIG_NODE_1: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_1;
const DOMAIN_CONFIG_ROOT: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_ROOT;
const DOMAIN_STATE_LEAF: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF;
const DOMAIN_STATE_NODE_0: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_NODE_0;
const DOMAIN_ISSUER_COMMITMENT: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT;
const DOMAIN_ISSUER_AUTHORIZATION: u64 = STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_AUTHORIZATION;

pub type StablecoinPoseidon2V8Digest = Poseidon2Width16Digest;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum StablecoinPoseidon2V8Direction {
    #[default]
    Disabled = 0,
    Mint = 1,
    Burn = 2,
}

/// Every static field in the authenticated stablecoin row.
///
/// The four mutable counters are carried separately in
/// [`StablecoinPoseidon2V8Counters`]. Keeping one config in the witness model
/// makes before/after static equality structural rather than a host-only
/// comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinPoseidon2V8Config {
    pub asset_id: u32,
    pub policy_version: u32,
    pub active: bool,
    pub enabled_at: u64,
    pub retired_at: Option<u64>,
    pub issuer_commitment: StablecoinPoseidon2V8Digest,
    pub min_collateral_ratio_ppm: u32,
    pub max_mint_per_epoch: u64,
    pub oracle_submitted_at: u64,
    pub oracle_max_age: u64,
    pub oracle_price_numerator: u32,
    pub oracle_price_denominator: u32,
    pub collateral_amount: u64,
    pub attestation_created_at: u64,
    pub attestation_disputed: bool,
    pub attestation_present: bool,
    pub attestation_max_age: u64,
    pub policy_admin_commitment: StablecoinPoseidon2V8Digest,
    pub oracle_authority_commitment: StablecoinPoseidon2V8Digest,
    pub attestation_authority_commitment: StablecoinPoseidon2V8Digest,
    pub collateral_asset_id: u32,
    pub collateral_decimals: u8,
    pub collateral_scale: u64,
    pub locked_collateral_commitment: StablecoinPoseidon2V8Digest,
}

impl StablecoinPoseidon2V8Config {
    pub const ZERO: Self = Self {
        asset_id: 0,
        policy_version: 0,
        active: false,
        enabled_at: 0,
        retired_at: None,
        issuer_commitment: [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST],
        min_collateral_ratio_ppm: 0,
        max_mint_per_epoch: 0,
        oracle_submitted_at: 0,
        oracle_max_age: 0,
        oracle_price_numerator: 0,
        oracle_price_denominator: 0,
        collateral_amount: 0,
        attestation_created_at: 0,
        attestation_disputed: false,
        attestation_present: false,
        attestation_max_age: 0,
        policy_admin_commitment: [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST],
        oracle_authority_commitment: [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST],
        attestation_authority_commitment: [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST],
        collateral_asset_id: 0,
        collateral_decimals: 0,
        collateral_scale: 0,
        locked_collateral_commitment: [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST],
    };

    /// Canonical 55-field projection hashed by the V8 relation.
    pub fn to_fields(self) -> [Felt; 55] {
        let mut fields = [Felt::ZERO; 55];
        let mut cursor = 0usize;
        let mut push = |value: Felt| {
            fields[cursor] = value;
            cursor += 1;
        };
        push(Felt::from_u64(self.asset_id as u64));
        push(Felt::from_u64(self.policy_version as u64));
        push(Felt::from_u64(u64::from(self.active)));
        push(Felt::from_u64(self.enabled_at));
        push(Felt::from_u64(u64::from(self.retired_at.is_some())));
        push(Felt::from_u64(self.retired_at.unwrap_or(0)));
        for value in self.issuer_commitment {
            push(value);
        }
        push(Felt::from_u64(self.min_collateral_ratio_ppm as u64));
        push(Felt::from_u64(self.max_mint_per_epoch));
        push(Felt::from_u64(self.oracle_submitted_at));
        push(Felt::from_u64(self.oracle_max_age));
        push(Felt::from_u64(self.oracle_price_numerator as u64));
        push(Felt::from_u64(self.oracle_price_denominator as u64));
        push(Felt::from_u64(self.collateral_amount));
        push(Felt::from_u64(self.attestation_created_at));
        push(Felt::from_u64(u64::from(self.attestation_disputed)));
        push(Felt::from_u64(u64::from(self.attestation_present)));
        push(Felt::from_u64(self.attestation_max_age));
        for commitment in [
            self.policy_admin_commitment,
            self.oracle_authority_commitment,
            self.attestation_authority_commitment,
        ] {
            for value in commitment {
                push(value);
            }
        }
        push(Felt::from_u64(self.collateral_asset_id as u64));
        push(Felt::from_u64(self.collateral_decimals as u64));
        push(Felt::from_u64(self.collateral_scale));
        for value in self.locked_collateral_commitment {
            push(value);
        }
        debug_assert_eq!(cursor, fields.len());
        fields
    }
}

impl Default for StablecoinPoseidon2V8Config {
    fn default() -> Self {
        Self::ZERO
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StablecoinPoseidon2V8Counters {
    pub epoch_id: u64,
    pub minted_in_epoch: u64,
    pub total_debt: u64,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinPoseidon2V8Public {
    pub direction: StablecoinPoseidon2V8Direction,
    pub asset_id: u32,
    pub policy_version: u32,
    pub magnitude: u64,
    pub action_intent: StablecoinPoseidon2V8Digest,
    pub parent_height: u64,
    pub before_root: StablecoinPoseidon2V8Digest,
    pub after_root: StablecoinPoseidon2V8Digest,
    pub after: StablecoinPoseidon2V8Counters,
    pub issuer_authorization: StablecoinPoseidon2V8Digest,
}

impl StablecoinPoseidon2V8Public {
    pub const ZERO: Self = Self {
        direction: StablecoinPoseidon2V8Direction::Disabled,
        asset_id: 0,
        policy_version: 0,
        magnitude: 0,
        action_intent: [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST],
        parent_height: 0,
        before_root: [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST],
        after_root: [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST],
        after: StablecoinPoseidon2V8Counters {
            epoch_id: 0,
            minted_in_epoch: 0,
            total_debt: 0,
            sequence: 0,
        },
        issuer_authorization: [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST],
    };

    /// Canonical disabled stablecoin surface at one consensus parent height.
    ///
    /// Disabled shielded transfers do not read or write stablecoin state, but
    /// they must still bind the block parent height carried by the transaction
    /// statement.  Every other stablecoin field remains canonically absent.
    pub const fn disabled_at_context(
        parent_height: u64,
        current_root: StablecoinPoseidon2V8Digest,
    ) -> Self {
        Self {
            parent_height,
            before_root: current_root,
            after_root: current_root,
            ..Self::ZERO
        }
    }
}

impl Default for StablecoinPoseidon2V8Public {
    fn default() -> Self {
        Self::ZERO
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinPoseidon2V8Witness {
    pub config: StablecoinPoseidon2V8Config,
    pub before: StablecoinPoseidon2V8Counters,
    pub siblings: [StablecoinPoseidon2V8Digest; STABLECOIN_POSEIDON2_V8_DEPTH],
    pub issuer_secret: StablecoinPoseidon2V8Digest,
}

impl StablecoinPoseidon2V8Witness {
    pub const ZERO: Self = Self {
        config: StablecoinPoseidon2V8Config::ZERO,
        before: StablecoinPoseidon2V8Counters {
            epoch_id: 0,
            minted_in_epoch: 0,
            total_debt: 0,
            sequence: 0,
        },
        siblings: [[Felt::ZERO; POSEIDON2_WIDTH16_DIGEST]; STABLECOIN_POSEIDON2_V8_DEPTH],
        issuer_secret: [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST],
    };
}

impl Default for StablecoinPoseidon2V8Witness {
    fn default() -> Self {
        Self::ZERO
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinPoseidon2V8Context {
    pub current_root: StablecoinPoseidon2V8Digest,
    pub parent_height: u64,
    pub expected_action_intent: StablecoinPoseidon2V8Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedStablecoinPoseidon2V8Transition {
    pub before_root: StablecoinPoseidon2V8Digest,
    pub after_root: StablecoinPoseidon2V8Digest,
    pub current_epoch: u64,
    pub changed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StablecoinPoseidon2V8Error {
    NonCanonicalDisabled,
    ZeroOrNativeAsset,
    ValueOutOfRange,
    ScalarOutOfRange,
    CommitmentZero,
    CommitmentRoleReuse,
    InvalidCollateralDecimals,
    InvalidCollateralScale,
    ContextHeightMismatch,
    ContextRootMismatch,
    ActionIntentMismatch,
    ZeroActionIntent,
    BeforeMembershipRootMismatch,
    AfterMembershipRootMismatch,
    InactivePolicy,
    PolicyNotEnabled,
    InvalidLifecycle,
    PolicyRetired,
    OracleFromFuture,
    OracleStale,
    AttestationFromFuture,
    AttestationAbsent,
    AttestationStale,
    AttestationDisputed,
    ZeroOraclePrice,
    CollateralRatioViolation,
    FutureEpoch,
    ZeroMagnitude,
    ArithmeticOverflow,
    DebtUnderflow,
    MintCapExceeded,
    AfterStateMismatch,
    IssuerSecretZero,
    IssuerSecretMustBeZero,
    IssuerCommitmentMismatch,
    IssuerAuthorizationMismatch,
    IssuerAuthorizationMustBeZero,
}

#[inline]
fn digest_is_zero(digest: &StablecoinPoseidon2V8Digest) -> bool {
    digest.iter().all(|value| *value == Felt::ZERO)
}

pub fn stablecoin_poseidon2_v8_config_digest(
    config: StablecoinPoseidon2V8Config,
) -> StablecoinPoseidon2V8Digest {
    let fields = config.to_fields();
    let mut chunks = [[Felt::ZERO; 14]; 4];
    for (index, value) in fields.into_iter().enumerate() {
        chunks[index / 14][index % 14] = value;
    }
    let chunk_domains = [
        DOMAIN_CONFIG_CHUNK_0,
        DOMAIN_CONFIG_CHUNK_1,
        DOMAIN_CONFIG_CHUNK_2,
        DOMAIN_CONFIG_CHUNK_3,
    ];
    let digests = core::array::from_fn::<_, 4, _>(|index| {
        let mut left = [Felt::ZERO; 7];
        let mut right = [Felt::ZERO; 7];
        left.copy_from_slice(&chunks[index][..7]);
        right.copy_from_slice(&chunks[index][7..]);
        poseidon2_width16_compress14(chunk_domains[index], &left, &right)
    });
    let left = poseidon2_width16_compress14(DOMAIN_CONFIG_NODE_0, &digests[0], &digests[1]);
    let right = poseidon2_width16_compress14(DOMAIN_CONFIG_NODE_1, &digests[2], &digests[3]);
    poseidon2_width16_compress14(DOMAIN_CONFIG_ROOT, &left, &right)
}

pub fn stablecoin_poseidon2_v8_leaf(
    index: u32,
    config_digest: StablecoinPoseidon2V8Digest,
    counters: StablecoinPoseidon2V8Counters,
) -> StablecoinPoseidon2V8Digest {
    let right = [
        Felt::from_u64(counters.epoch_id),
        Felt::from_u64(counters.minted_in_epoch),
        Felt::from_u64(counters.total_debt),
        Felt::from_u64(counters.sequence),
        Felt::from_u64(index as u64),
        Felt::ZERO,
        Felt::ZERO,
    ];
    poseidon2_width16_compress14(DOMAIN_STATE_LEAF, &config_digest, &right)
}

pub fn stablecoin_poseidon2_v8_node(
    level: usize,
    left: &StablecoinPoseidon2V8Digest,
    right: &StablecoinPoseidon2V8Digest,
) -> Result<StablecoinPoseidon2V8Digest, StablecoinPoseidon2V8Error> {
    if level >= STABLECOIN_POSEIDON2_V8_DEPTH {
        return Err(StablecoinPoseidon2V8Error::BeforeMembershipRootMismatch);
    }
    Ok(poseidon2_width16_compress14(
        DOMAIN_STATE_NODE_0 + level as u64,
        left,
        right,
    ))
}

pub fn stablecoin_poseidon2_v8_root(
    asset_id: u32,
    config_digest: StablecoinPoseidon2V8Digest,
    counters: StablecoinPoseidon2V8Counters,
    siblings: &[StablecoinPoseidon2V8Digest; STABLECOIN_POSEIDON2_V8_DEPTH],
) -> Result<StablecoinPoseidon2V8Digest, StablecoinPoseidon2V8Error> {
    let index = asset_id & (STABLECOIN_POSEIDON2_V8_CAP as u32 - 1);
    let mut current = stablecoin_poseidon2_v8_leaf(index, config_digest, counters);
    let mut cursor = index as usize;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if cursor & 1 == 0 {
            stablecoin_poseidon2_v8_node(level, &current, sibling)?
        } else {
            stablecoin_poseidon2_v8_node(level, sibling, &current)?
        };
        cursor >>= 1;
    }
    Ok(current)
}

pub fn stablecoin_poseidon2_v8_issuer_commitment(
    asset_id: u32,
    policy_version: u32,
    issuer_secret: &StablecoinPoseidon2V8Digest,
) -> StablecoinPoseidon2V8Digest {
    let right = [
        Felt::from_u64(asset_id as u64),
        Felt::from_u64(policy_version as u64),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    poseidon2_width16_compress14(DOMAIN_ISSUER_COMMITMENT, issuer_secret, &right)
}

pub fn stablecoin_poseidon2_v8_issuer_authorization(
    action_intent: &StablecoinPoseidon2V8Digest,
    issuer_secret: &StablecoinPoseidon2V8Digest,
) -> StablecoinPoseidon2V8Digest {
    poseidon2_width16_compress14(DOMAIN_ISSUER_AUTHORIZATION, issuer_secret, action_intent)
}

fn validate_common(
    config: StablecoinPoseidon2V8Config,
    before: StablecoinPoseidon2V8Counters,
) -> Result<(), StablecoinPoseidon2V8Error> {
    if config.asset_id == 0 {
        return Err(StablecoinPoseidon2V8Error::ZeroOrNativeAsset);
    }
    for value in [
        config.max_mint_per_epoch,
        config.collateral_amount,
        before.minted_in_epoch,
        before.total_debt,
    ] {
        if value > STABLECOIN_POSEIDON2_V8_MAX_VALUE {
            return Err(StablecoinPoseidon2V8Error::ValueOutOfRange);
        }
    }
    for value in [
        config.enabled_at,
        config.retired_at.unwrap_or(0),
        config.oracle_submitted_at,
        config.oracle_max_age,
        config.attestation_created_at,
        config.attestation_max_age,
        config.collateral_scale,
        before.epoch_id,
        before.sequence,
    ] {
        if value > STABLECOIN_POSEIDON2_V8_MAX_SCALAR {
            return Err(StablecoinPoseidon2V8Error::ScalarOutOfRange);
        }
    }
    if before.minted_in_epoch > config.max_mint_per_epoch {
        return Err(StablecoinPoseidon2V8Error::MintCapExceeded);
    }
    let commitments = [
        config.issuer_commitment,
        config.policy_admin_commitment,
        config.oracle_authority_commitment,
        config.attestation_authority_commitment,
        config.locked_collateral_commitment,
    ];
    if commitments.iter().any(digest_is_zero) {
        return Err(StablecoinPoseidon2V8Error::CommitmentZero);
    }
    for left in 0..commitments.len() {
        for right in left + 1..commitments.len() {
            if commitments[left] == commitments[right] {
                return Err(StablecoinPoseidon2V8Error::CommitmentRoleReuse);
            }
        }
    }
    if config.collateral_decimals > 18 {
        return Err(StablecoinPoseidon2V8Error::InvalidCollateralDecimals);
    }
    let mut expected_scale = 1u64;
    for _ in 0..config.collateral_decimals {
        expected_scale = expected_scale
            .checked_mul(10)
            .ok_or(StablecoinPoseidon2V8Error::InvalidCollateralScale)?;
    }
    if config.collateral_scale != expected_scale {
        return Err(StablecoinPoseidon2V8Error::InvalidCollateralScale);
    }
    Ok(())
}

fn validate_mint_policy(
    config: StablecoinPoseidon2V8Config,
    parent_height: u64,
) -> Result<(), StablecoinPoseidon2V8Error> {
    if !config.active {
        return Err(StablecoinPoseidon2V8Error::InactivePolicy);
    }
    if config.enabled_at > parent_height {
        return Err(StablecoinPoseidon2V8Error::PolicyNotEnabled);
    }
    if let Some(retired_at) = config.retired_at {
        if retired_at <= config.enabled_at {
            return Err(StablecoinPoseidon2V8Error::InvalidLifecycle);
        }
        if parent_height >= retired_at {
            return Err(StablecoinPoseidon2V8Error::PolicyRetired);
        }
    }
    if config.min_collateral_ratio_ppm < STABLECOIN_POSEIDON2_V8_RATIO_SCALE_PPM as u32 {
        return Err(StablecoinPoseidon2V8Error::CollateralRatioViolation);
    }
    if config.oracle_price_numerator == 0 || config.oracle_price_denominator == 0 {
        return Err(StablecoinPoseidon2V8Error::ZeroOraclePrice);
    }
    if config.oracle_submitted_at > parent_height {
        return Err(StablecoinPoseidon2V8Error::OracleFromFuture);
    }
    if parent_height - config.oracle_submitted_at > config.oracle_max_age {
        return Err(StablecoinPoseidon2V8Error::OracleStale);
    }
    if config.attestation_created_at > parent_height {
        return Err(StablecoinPoseidon2V8Error::AttestationFromFuture);
    }
    if !config.attestation_present {
        return Err(StablecoinPoseidon2V8Error::AttestationAbsent);
    }
    if parent_height - config.attestation_created_at > config.attestation_max_age {
        return Err(StablecoinPoseidon2V8Error::AttestationStale);
    }
    if config.attestation_disputed {
        return Err(StablecoinPoseidon2V8Error::AttestationDisputed);
    }
    Ok(())
}

fn validate_collateral(
    config: StablecoinPoseidon2V8Config,
    debt: u64,
) -> Result<(), StablecoinPoseidon2V8Error> {
    let left = u128::from(config.collateral_amount)
        .checked_mul(u128::from(config.oracle_price_numerator))
        .and_then(|value| value.checked_mul(u128::from(STABLECOIN_POSEIDON2_V8_RATIO_SCALE_PPM)))
        .ok_or(StablecoinPoseidon2V8Error::ArithmeticOverflow)?;
    let right = u128::from(debt)
        .checked_mul(u128::from(config.oracle_price_denominator))
        .and_then(|value| value.checked_mul(u128::from(config.min_collateral_ratio_ppm)))
        .ok_or(StablecoinPoseidon2V8Error::ArithmeticOverflow)?;
    if left < right {
        return Err(StablecoinPoseidon2V8Error::CollateralRatioViolation);
    }
    Ok(())
}

pub fn verify_stablecoin_transition_v8(
    context: StablecoinPoseidon2V8Context,
    public: StablecoinPoseidon2V8Public,
    witness: StablecoinPoseidon2V8Witness,
) -> Result<VerifiedStablecoinPoseidon2V8Transition, StablecoinPoseidon2V8Error> {
    if public.direction == StablecoinPoseidon2V8Direction::Disabled {
        if public.parent_height != context.parent_height {
            return Err(StablecoinPoseidon2V8Error::ContextHeightMismatch);
        }
        if public.parent_height > STABLECOIN_POSEIDON2_V8_MAX_SCALAR {
            return Err(StablecoinPoseidon2V8Error::ScalarOutOfRange);
        }
        if public
            != StablecoinPoseidon2V8Public::disabled_at_context(
                context.parent_height,
                context.current_root,
            )
            || witness != StablecoinPoseidon2V8Witness::ZERO
        {
            return Err(StablecoinPoseidon2V8Error::NonCanonicalDisabled);
        }
        return Ok(VerifiedStablecoinPoseidon2V8Transition {
            before_root: context.current_root,
            after_root: context.current_root,
            current_epoch: context.parent_height >> STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT,
            changed: false,
        });
    }
    if public.parent_height != context.parent_height {
        return Err(StablecoinPoseidon2V8Error::ContextHeightMismatch);
    }
    for value in [
        public.parent_height,
        public.after.epoch_id,
        public.after.sequence,
    ] {
        if value > STABLECOIN_POSEIDON2_V8_MAX_SCALAR {
            return Err(StablecoinPoseidon2V8Error::ScalarOutOfRange);
        }
    }
    if public.before_root != context.current_root {
        return Err(StablecoinPoseidon2V8Error::ContextRootMismatch);
    }
    if digest_is_zero(&public.action_intent) {
        return Err(StablecoinPoseidon2V8Error::ZeroActionIntent);
    }
    if public.action_intent != context.expected_action_intent {
        return Err(StablecoinPoseidon2V8Error::ActionIntentMismatch);
    }
    if public.magnitude == 0 {
        return Err(StablecoinPoseidon2V8Error::ZeroMagnitude);
    }
    if public.magnitude > STABLECOIN_POSEIDON2_V8_MAX_VALUE {
        return Err(StablecoinPoseidon2V8Error::ValueOutOfRange);
    }
    if public.asset_id != witness.config.asset_id
        || public.policy_version != witness.config.policy_version
    {
        return Err(StablecoinPoseidon2V8Error::AfterStateMismatch);
    }
    validate_common(witness.config, witness.before)?;
    let config_digest = stablecoin_poseidon2_v8_config_digest(witness.config);
    let before_root = stablecoin_poseidon2_v8_root(
        public.asset_id,
        config_digest,
        witness.before,
        &witness.siblings,
    )?;
    if before_root != public.before_root {
        return Err(StablecoinPoseidon2V8Error::BeforeMembershipRootMismatch);
    }

    let current_epoch = public.parent_height >> STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT;
    if witness.before.epoch_id > current_epoch {
        return Err(StablecoinPoseidon2V8Error::FutureEpoch);
    }
    let mint_base = if witness.before.epoch_id == current_epoch {
        witness.before.minted_in_epoch
    } else {
        0
    };
    let mut expected = witness.before;
    expected.epoch_id = current_epoch;
    expected.sequence = expected
        .sequence
        .checked_add(1)
        .ok_or(StablecoinPoseidon2V8Error::ArithmeticOverflow)?;

    match public.direction {
        StablecoinPoseidon2V8Direction::Disabled => unreachable!("handled above"),
        StablecoinPoseidon2V8Direction::Mint => {
            validate_mint_policy(witness.config, public.parent_height)?;
            if digest_is_zero(&witness.issuer_secret) {
                return Err(StablecoinPoseidon2V8Error::IssuerSecretZero);
            }
            if stablecoin_poseidon2_v8_issuer_commitment(
                public.asset_id,
                public.policy_version,
                &witness.issuer_secret,
            ) != witness.config.issuer_commitment
            {
                return Err(StablecoinPoseidon2V8Error::IssuerCommitmentMismatch);
            }
            if stablecoin_poseidon2_v8_issuer_authorization(
                &public.action_intent,
                &witness.issuer_secret,
            ) != public.issuer_authorization
            {
                return Err(StablecoinPoseidon2V8Error::IssuerAuthorizationMismatch);
            }
            expected.minted_in_epoch = mint_base
                .checked_add(public.magnitude)
                .ok_or(StablecoinPoseidon2V8Error::ArithmeticOverflow)?;
            if expected.minted_in_epoch > witness.config.max_mint_per_epoch {
                return Err(StablecoinPoseidon2V8Error::MintCapExceeded);
            }
            expected.total_debt = expected
                .total_debt
                .checked_add(public.magnitude)
                .ok_or(StablecoinPoseidon2V8Error::ArithmeticOverflow)?;
            if expected.total_debt > STABLECOIN_POSEIDON2_V8_MAX_VALUE {
                return Err(StablecoinPoseidon2V8Error::ValueOutOfRange);
            }
            validate_collateral(witness.config, expected.total_debt)?;
        }
        StablecoinPoseidon2V8Direction::Burn => {
            if !digest_is_zero(&witness.issuer_secret) {
                return Err(StablecoinPoseidon2V8Error::IssuerSecretMustBeZero);
            }
            if !digest_is_zero(&public.issuer_authorization) {
                return Err(StablecoinPoseidon2V8Error::IssuerAuthorizationMustBeZero);
            }
            expected.minted_in_epoch = mint_base;
            expected.total_debt = expected
                .total_debt
                .checked_sub(public.magnitude)
                .ok_or(StablecoinPoseidon2V8Error::DebtUnderflow)?;
        }
    }
    if expected != public.after {
        return Err(StablecoinPoseidon2V8Error::AfterStateMismatch);
    }
    let after_root = stablecoin_poseidon2_v8_root(
        public.asset_id,
        config_digest,
        public.after,
        &witness.siblings,
    )?;
    if after_root != public.after_root {
        return Err(StablecoinPoseidon2V8Error::AfterMembershipRootMismatch);
    }
    Ok(VerifiedStablecoinPoseidon2V8Transition {
        before_root,
        after_root,
        current_epoch,
        changed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEIGHT: u64 = 9_000;
    const SECRET: [Felt; 7] = [
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
    ];
    const INTENT: [Felt; 7] = [
        Felt::new(11),
        Felt::new(12),
        Felt::new(13),
        Felt::new(14),
        Felt::new(15),
        Felt::new(16),
        Felt::new(17),
    ];

    fn tagged(tag: u64) -> [Felt; 7] {
        core::array::from_fn(|index| Felt::from_u64(tag + index as u64))
    }

    fn fixture(
        direction: StablecoinPoseidon2V8Direction,
    ) -> (
        StablecoinPoseidon2V8Context,
        StablecoinPoseidon2V8Public,
        StablecoinPoseidon2V8Witness,
    ) {
        let asset_id = 1001;
        let policy_version = 7;
        let before = StablecoinPoseidon2V8Counters {
            epoch_id: HEIGHT >> STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT,
            minted_in_epoch: 100,
            total_debt: 1_000,
            sequence: 9,
        };
        let mut config = StablecoinPoseidon2V8Config {
            asset_id,
            policy_version,
            active: true,
            enabled_at: 1,
            retired_at: Some(20_000),
            issuer_commitment: stablecoin_poseidon2_v8_issuer_commitment(
                asset_id,
                policy_version,
                &SECRET,
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
            policy_admin_commitment: tagged(101),
            oracle_authority_commitment: tagged(201),
            attestation_authority_commitment: tagged(301),
            collateral_asset_id: 0,
            collateral_decimals: 6,
            collateral_scale: 1_000_000,
            locked_collateral_commitment: tagged(401),
        };
        if config.issuer_commitment == config.policy_admin_commitment {
            config.policy_admin_commitment = tagged(501);
        }
        let siblings = [tagged(601), tagged(701), tagged(801), tagged(901)];
        let magnitude = 25;
        let mut after = before;
        after.epoch_id = HEIGHT >> STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT;
        after.sequence += 1;
        match direction {
            StablecoinPoseidon2V8Direction::Mint => {
                after.minted_in_epoch += magnitude;
                after.total_debt += magnitude;
            }
            StablecoinPoseidon2V8Direction::Burn => {
                after.total_debt -= magnitude;
            }
            StablecoinPoseidon2V8Direction::Disabled => unreachable!(),
        }
        let config_digest = stablecoin_poseidon2_v8_config_digest(config);
        let before_root =
            stablecoin_poseidon2_v8_root(asset_id, config_digest, before, &siblings).unwrap();
        let after_root =
            stablecoin_poseidon2_v8_root(asset_id, config_digest, after, &siblings).unwrap();
        let issuer_secret = if direction == StablecoinPoseidon2V8Direction::Mint {
            SECRET
        } else {
            [Felt::ZERO; 7]
        };
        let issuer_authorization = if direction == StablecoinPoseidon2V8Direction::Mint {
            stablecoin_poseidon2_v8_issuer_authorization(&INTENT, &issuer_secret)
        } else {
            [Felt::ZERO; 7]
        };
        (
            StablecoinPoseidon2V8Context {
                current_root: before_root,
                parent_height: HEIGHT,
                expected_action_intent: INTENT,
            },
            StablecoinPoseidon2V8Public {
                direction,
                asset_id,
                policy_version,
                magnitude,
                action_intent: INTENT,
                parent_height: HEIGHT,
                before_root,
                after_root,
                after,
                issuer_authorization,
            },
            StablecoinPoseidon2V8Witness {
                config,
                before,
                siblings,
                issuer_secret,
            },
        )
    }

    #[test]
    fn exact_hash_and_public_geometry_stays_in_three_groups() {
        assert_eq!(STABLECOIN_POSEIDON2_V8_TRANSITION_PERMUTATIONS, 19);
        assert_eq!(STABLECOIN_POSEIDON2_V8_BASE_INTENT_PERMUTATIONS, 11);
        assert_eq!(STABLECOIN_POSEIDON2_V8_INTENT_PERMUTATIONS, 15);
        assert_eq!(STABLECOIN_POSEIDON2_V8_TOTAL_ADDED_PERMUTATIONS, 23);
        assert_eq!(STABLECOIN_POSEIDON2_V8_AUTHORIZED_PUBLIC_FIELDS, 120);
    }

    #[test]
    fn mint_and_burn_verify() {
        for direction in [
            StablecoinPoseidon2V8Direction::Mint,
            StablecoinPoseidon2V8Direction::Burn,
        ] {
            let (context, public, witness) = fixture(direction);
            let verified = verify_stablecoin_transition_v8(context, public, witness).unwrap();
            assert!(verified.changed);
            assert_eq!(verified.before_root, public.before_root);
            assert_eq!(verified.after_root, public.after_root);
        }
    }

    #[test]
    fn disabled_binds_nonzero_parent_height_and_zeroes_every_other_stablecoin_field() {
        let context = StablecoinPoseidon2V8Context {
            current_root: tagged(801),
            parent_height: HEIGHT,
            expected_action_intent: tagged(901),
        };
        let public = StablecoinPoseidon2V8Public::disabled_at_context(HEIGHT, context.current_root);
        let verified =
            verify_stablecoin_transition_v8(context, public, StablecoinPoseidon2V8Witness::ZERO)
                .expect("canonical disabled transition at a nonzero height verifies");
        assert_eq!(verified.before_root, context.current_root);
        assert_eq!(verified.after_root, context.current_root);
        assert_eq!(
            verified.current_epoch,
            HEIGHT >> STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT
        );
        assert!(!verified.changed);

        let mut wrong_height = public;
        wrong_height.parent_height += 1;
        assert_eq!(
            verify_stablecoin_transition_v8(
                context,
                wrong_height,
                StablecoinPoseidon2V8Witness::ZERO
            ),
            Err(StablecoinPoseidon2V8Error::ContextHeightMismatch)
        );

        let mut nonzero_state = public;
        nonzero_state.after.sequence = 1;
        assert_eq!(
            verify_stablecoin_transition_v8(
                context,
                nonzero_state,
                StablecoinPoseidon2V8Witness::ZERO
            ),
            Err(StablecoinPoseidon2V8Error::NonCanonicalDisabled)
        );

        let too_high = STABLECOIN_POSEIDON2_V8_MAX_SCALAR + 1;
        let too_high_context = StablecoinPoseidon2V8Context {
            parent_height: too_high,
            ..context
        };
        assert_eq!(
            verify_stablecoin_transition_v8(
                too_high_context,
                StablecoinPoseidon2V8Public::disabled_at_context(
                    too_high,
                    too_high_context.current_root,
                ),
                StablecoinPoseidon2V8Witness::ZERO,
            ),
            Err(StablecoinPoseidon2V8Error::ScalarOutOfRange)
        );
    }

    #[test]
    fn anchor_path_intent_issuer_and_reuse_mutations_reject() {
        let (context, public, witness) = fixture(StablecoinPoseidon2V8Direction::Mint);

        let mut mutated = public;
        mutated.before_root[0] += Felt::ONE;
        assert_eq!(
            verify_stablecoin_transition_v8(context, mutated, witness),
            Err(StablecoinPoseidon2V8Error::ContextRootMismatch)
        );

        let mut mutated_witness = witness;
        mutated_witness.siblings[2][3] += Felt::ONE;
        assert_eq!(
            verify_stablecoin_transition_v8(context, public, mutated_witness),
            Err(StablecoinPoseidon2V8Error::BeforeMembershipRootMismatch)
        );

        let mut mutated_context = context;
        mutated_context.expected_action_intent[0] += Felt::ONE;
        assert_eq!(
            verify_stablecoin_transition_v8(mutated_context, public, witness),
            Err(StablecoinPoseidon2V8Error::ActionIntentMismatch)
        );

        let mut mutated_witness = witness;
        mutated_witness.issuer_secret[0] += Felt::ONE;
        assert_eq!(
            verify_stablecoin_transition_v8(context, public, mutated_witness),
            Err(StablecoinPoseidon2V8Error::IssuerCommitmentMismatch)
        );

        let mut mutated_witness = witness;
        mutated_witness.config.oracle_authority_commitment =
            mutated_witness.config.policy_admin_commitment;
        assert_eq!(
            verify_stablecoin_transition_v8(context, public, mutated_witness),
            Err(StablecoinPoseidon2V8Error::CommitmentRoleReuse)
        );
    }

    #[test]
    fn mint_risk_rules_reject_but_burn_remains_available() {
        let (mint_context, mut mint_public, mut mint_witness) =
            fixture(StablecoinPoseidon2V8Direction::Mint);
        mint_witness.config.attestation_disputed = true;
        let digest = stablecoin_poseidon2_v8_config_digest(mint_witness.config);
        mint_public.before_root = stablecoin_poseidon2_v8_root(
            mint_public.asset_id,
            digest,
            mint_witness.before,
            &mint_witness.siblings,
        )
        .unwrap();
        mint_public.after_root = stablecoin_poseidon2_v8_root(
            mint_public.asset_id,
            digest,
            mint_public.after,
            &mint_witness.siblings,
        )
        .unwrap();
        let mint_context = StablecoinPoseidon2V8Context {
            current_root: mint_public.before_root,
            ..mint_context
        };
        assert_eq!(
            verify_stablecoin_transition_v8(mint_context, mint_public, mint_witness),
            Err(StablecoinPoseidon2V8Error::AttestationDisputed)
        );

        let (burn_context, mut burn_public, mut burn_witness) =
            fixture(StablecoinPoseidon2V8Direction::Burn);
        burn_witness.config.attestation_disputed = true;
        let digest = stablecoin_poseidon2_v8_config_digest(burn_witness.config);
        burn_public.before_root = stablecoin_poseidon2_v8_root(
            burn_public.asset_id,
            digest,
            burn_witness.before,
            &burn_witness.siblings,
        )
        .unwrap();
        burn_public.after_root = stablecoin_poseidon2_v8_root(
            burn_public.asset_id,
            digest,
            burn_public.after,
            &burn_witness.siblings,
        )
        .unwrap();
        let context = StablecoinPoseidon2V8Context {
            current_root: burn_public.before_root,
            ..burn_context
        };
        assert!(verify_stablecoin_transition_v8(context, burn_public, burn_witness).is_ok());
    }

    #[test]
    fn scalar_cap_rejects_goldilocks_aliases_and_accepts_boundary_sequence() {
        let (context, public, mut witness) = fixture(StablecoinPoseidon2V8Direction::Mint);
        assert_eq!(
            Felt::from_u64(hegemon_field::GOLDILOCKS_MODULUS),
            Felt::ZERO
        );
        witness.config.enabled_at = hegemon_field::GOLDILOCKS_MODULUS;
        assert_eq!(
            verify_stablecoin_transition_v8(context, public, witness),
            Err(StablecoinPoseidon2V8Error::ScalarOutOfRange)
        );

        let (mut context, mut public, mut witness) = fixture(StablecoinPoseidon2V8Direction::Mint);
        witness.before.sequence = STABLECOIN_POSEIDON2_V8_MAX_SCALAR - 1;
        public.after.sequence = STABLECOIN_POSEIDON2_V8_MAX_SCALAR;
        let config_digest = stablecoin_poseidon2_v8_config_digest(witness.config);
        public.before_root = stablecoin_poseidon2_v8_root(
            public.asset_id,
            config_digest,
            witness.before,
            &witness.siblings,
        )
        .unwrap();
        public.after_root = stablecoin_poseidon2_v8_root(
            public.asset_id,
            config_digest,
            public.after,
            &witness.siblings,
        )
        .unwrap();
        context.current_root = public.before_root;
        assert!(verify_stablecoin_transition_v8(context, public, witness).is_ok());
    }
}
