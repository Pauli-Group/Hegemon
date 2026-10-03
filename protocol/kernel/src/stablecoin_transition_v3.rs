//! Prospective fixed-width stablecoin state transition.
//!
//! This module is deliberately inactive.  It defines one executable V3 state
//! transition and canonical wire so the policy, Merkle, epoch, issuer, debt,
//! and collateral rules can be reviewed together.  It does not authorize a
//! source writer, transaction compiler, proof relation, consensus route, or
//! production release.
//!
//! A future transaction compiler must derive `action_intent` from the exact
//! network/version/action/statement/output/ciphertext/authorization surface,
//! excluding the `action_intent` field itself, the issuer authorization tag,
//! and separately bound derived nullifiers.  The verifier context must obtain
//! that digest from an authenticated outer parser; echoing the public field is
//! not authority.  That compiler does not exist, so the integration flags below
//! remain false even though this local transition oracle is executable.

use crate::stablecoin_manifest_authority_v2::blake2b512_personalized_v2;

/// Fresh prospective wire/profile version.  This is not a consensus version.
pub const STABLECOIN_TRANSITION_V3_VERSION: u16 = 3;
/// Exactly sixteen leaves are addressable by the prospective state root.
pub const STABLECOIN_TRANSITION_V3_CAP: usize = 16;
/// A sixteen-leaf binary tree has exactly four sibling levels.
pub const STABLECOIN_TRANSITION_V3_DEPTH: usize = 4;
/// Every issuer commitment, leaf, node, and root is 64-byte BLAKE2b-512.
pub const STABLECOIN_TRANSITION_V3_DIGEST_BYTES: usize = 64;
/// Epochs contain exactly 2^12 parent heights.
pub const STABLECOIN_TRANSITION_V3_EPOCH_HEIGHT_SHIFT: u32 = 12;
/// All amount-like values are restricted to 61 bits.
pub const STABLECOIN_TRANSITION_V3_MAX_VALUE: u64 = (1u64 << 61) - 1;
/// One whole unit of collateral ratio in parts per million.
pub const STABLECOIN_TRANSITION_V3_RATIO_SCALE_PPM: u32 = 1_000_000;

/// Exact canonical byte width of one authority- and custody-bound state row.
pub const STABLECOIN_TRANSITION_V3_ROW_BYTES: usize = 453;
/// Exact fixed membership proof: `index || row || sibling[0..4]`.
pub const STABLECOIN_TRANSITION_V3_MEMBERSHIP_PROOF_BYTES: usize = 4
    + STABLECOIN_TRANSITION_V3_ROW_BYTES
    + STABLECOIN_TRANSITION_V3_DEPTH * STABLECOIN_TRANSITION_V3_DIGEST_BYTES;
/// Exact public wire including fresh magic, version, action intent, and issuer
/// authorization tag.
pub const STABLECOIN_TRANSITION_V3_PUBLIC_BYTES: usize =
    STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.end;
/// Exact transition witness wire.  The before and after rows share one path.
pub const STABLECOIN_TRANSITION_V3_WITNESS_BYTES: usize =
    STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.end;
/// Canonical public prefix (251 bytes) plus one 64-byte issuer secret.
pub const STABLECOIN_TRANSITION_V3_ISSUER_AUTHORIZATION_PREIMAGE_BYTES: usize =
    STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start
        + STABLECOIN_TRANSITION_V3_DIGEST_BYTES;

pub const STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC: [u8; 8] = *b"HGSTP3\0\0";
pub const STABLECOIN_TRANSITION_V3_WITNESS_MAGIC: [u8; 8] = *b"HGSTW3\0\0";

pub const STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC_RANGE: core::ops::Range<usize> = 0..8;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_VERSION_RANGE: core::ops::Range<usize> = 8..10;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE: core::ops::Range<usize> = 10..11;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE: core::ops::Range<usize> = 11..15;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE: core::ops::Range<usize> = 15..19;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE: core::ops::Range<usize> = 19..27;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE: core::ops::Range<usize> = 27..91;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE: core::ops::Range<usize> = 91..155;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE: core::ops::Range<usize> = 155..219;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_EPOCH_RANGE: core::ops::Range<usize> = 219..227;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_MINTED_RANGE: core::ops::Range<usize> = 227..235;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_DEBT_RANGE: core::ops::Range<usize> = 235..243;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_SEQUENCE_RANGE: core::ops::Range<usize> = 243..251;
pub const STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE: core::ops::Range<usize> =
    251..315;

pub const STABLECOIN_TRANSITION_V3_WITNESS_MAGIC_RANGE: core::ops::Range<usize> = 0..8;
pub const STABLECOIN_TRANSITION_V3_WITNESS_VERSION_RANGE: core::ops::Range<usize> = 8..10;
pub const STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE: core::ops::Range<usize> = 10..14;
pub const STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE: core::ops::Range<usize> =
    14..14 + STABLECOIN_TRANSITION_V3_ROW_BYTES;
pub const STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE: core::ops::Range<usize> =
    STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.end
        ..STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.end
            + STABLECOIN_TRANSITION_V3_ROW_BYTES;
pub const STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE: core::ops::Range<usize> =
    STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.end
        ..STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.end
            + STABLECOIN_TRANSITION_V3_DEPTH * STABLECOIN_TRANSITION_V3_DIGEST_BYTES;
pub const STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE: core::ops::Range<usize> =
    STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.end
        ..STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.end + STABLECOIN_TRANSITION_V3_DIGEST_BYTES;

/// This prospective state transition is not active.
pub const STABLECOIN_TRANSITION_V3_ACTIVE: bool = false;
/// No mempool, mining, import, sync, restart, or reorg route accepts V3.
pub const STABLECOIN_TRANSITION_V3_CONSENSUS_ROUTE_AUTHORIZED: bool = false;
/// No transaction proof relation has compiled this state transition.
pub const STABLECOIN_TRANSITION_V3_RELATION_INTEGRATED: bool = false;
/// No reviewed QROM instantiation certificate is attached to this module.
pub const STABLECOIN_TRANSITION_V3_QROM_AUTHORIZED: bool = false;
/// No whole-proof simulator or complete-ZK certificate is attached.
pub const STABLECOIN_TRANSITION_V3_COMPLETE_ZK_AUTHORIZED: bool = false;
/// Rust/compiler/verifier formal refinement remains open.
pub const STABLECOIN_TRANSITION_V3_FORMAL_REFINEMENT_COMPLETE: bool = false;
/// This module cannot authorize production in this revision.
pub const STABLECOIN_TRANSITION_V3_PRODUCTION_AUTHORIZED: bool = false;
/// Canonical policy/oracle/attestation source writers remain unassigned.
pub const STABLECOIN_TRANSITION_V3_SOURCE_WRITER_AUTHORIZED: bool = false;
/// Governance has not adopted the prospective row or transition policy.
pub const STABLECOIN_TRANSITION_V3_GOVERNANCE_AUTHORIZED: bool = false;
/// No transaction compiler emits this public or witness wire.
pub const STABLECOIN_TRANSITION_V3_TRANSACTION_COMPILER_INTEGRATED: bool = false;
/// No root genesis/update/reorg writer has been specified or authorized.
pub const STABLECOIN_TRANSITION_V3_ROOT_LIFECYCLE_AUTHORIZED: bool = false;
/// The selected-row transaction transition keeps policy/source fields static.
/// `stablecoin_source_v3` is an executable prospective refresh model, but no
/// root lifecycle, governance route, compiler, or proof relation integrates it.
pub const STABLECOIN_TRANSITION_V3_STATIC_SOURCE_REFRESH_INTEGRATED: bool = false;
/// The fixed policy slot rule prevents parallel live versions of one asset.
pub const STABLECOIN_TRANSITION_V3_UNIQUE_POLICY_SLOT_ENFORCED: bool = true;
/// A future compiler must explicitly map V3 Mint/Burn to any legacy signed
/// magnitude convention; no such adapter exists here.
pub const STABLECOIN_TRANSITION_V3_LEGACY_SIGN_ADAPTER_INTEGRATED: bool = false;

/// One before/after membership computation uses two leaves and eight nodes.
pub const STABLECOIN_TRANSITION_V3_ENABLED_MEMBERSHIP_HASH_CALLS: usize = 10;
/// Each 457-byte leaf takes four RFC 7693 compressions; each 128-byte node one.
pub const STABLECOIN_TRANSITION_V3_ENABLED_MEMBERSHIP_COMPRESSIONS: usize = 16;
/// Mint additionally hashes the 72-byte issuer commitment opening and the
/// 315-byte exact action authorization preimage.
pub const STABLECOIN_TRANSITION_V3_MINT_HASH_CALLS: usize = 12;
pub const STABLECOIN_TRANSITION_V3_MINT_COMPRESSIONS: usize = 20;
/// Burn requires a zero secret and performs no issuer hash.
pub const STABLECOIN_TRANSITION_V3_BURN_HASH_CALLS: usize = 10;
pub const STABLECOIN_TRANSITION_V3_BURN_COMPRESSIONS: usize = 16;

const ROLE_ISSUER: u8 = 1;
const ROLE_LEAF: u8 = 2;
const ROLE_NODE: u8 = 3;
const ROLE_ISSUER_AUTHORIZATION: u8 = 4;

pub const STABLECOIN_TRANSITION_V3_ASSET_ID_OFFSET: usize = 0;
pub const STABLECOIN_TRANSITION_V3_POLICY_VERSION_OFFSET: usize = 4;
pub const STABLECOIN_TRANSITION_V3_ACTIVE_OFFSET: usize = 8;
pub const STABLECOIN_TRANSITION_V3_ENABLED_AT_OFFSET: usize = 9;
pub const STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET: usize = 17;
pub const STABLECOIN_TRANSITION_V3_RETIRED_AT_OFFSET: usize = 18;
pub const STABLECOIN_TRANSITION_V3_ISSUER_COMMITMENT_OFFSET: usize = 26;
pub const STABLECOIN_TRANSITION_V3_MIN_RATIO_OFFSET: usize = 90;
pub const STABLECOIN_TRANSITION_V3_MAX_MINT_OFFSET: usize = 94;
pub const STABLECOIN_TRANSITION_V3_ORACLE_SUBMITTED_OFFSET: usize = 102;
pub const STABLECOIN_TRANSITION_V3_ORACLE_MAX_AGE_OFFSET: usize = 110;
pub const STABLECOIN_TRANSITION_V3_ORACLE_PRICE_NUMERATOR_OFFSET: usize = 118;
pub const STABLECOIN_TRANSITION_V3_ORACLE_PRICE_DENOMINATOR_OFFSET: usize = 122;
pub const STABLECOIN_TRANSITION_V3_COLLATERAL_OFFSET: usize = 126;
pub const STABLECOIN_TRANSITION_V3_ATTESTATION_CREATED_OFFSET: usize = 134;
pub const STABLECOIN_TRANSITION_V3_ATTESTATION_DISPUTED_OFFSET: usize = 142;
pub const STABLECOIN_TRANSITION_V3_ATTESTATION_PRESENT_OFFSET: usize = 143;
pub const STABLECOIN_TRANSITION_V3_ATTESTATION_MAX_AGE_OFFSET: usize = 144;
pub const STABLECOIN_TRANSITION_V3_POLICY_ADMIN_COMMITMENT_OFFSET: usize = 152;
pub const STABLECOIN_TRANSITION_V3_ORACLE_AUTHORITY_COMMITMENT_OFFSET: usize = 216;
pub const STABLECOIN_TRANSITION_V3_ATTESTATION_AUTHORITY_COMMITMENT_OFFSET: usize = 280;
pub const STABLECOIN_TRANSITION_V3_COLLATERAL_ASSET_ID_OFFSET: usize = 344;
pub const STABLECOIN_TRANSITION_V3_COLLATERAL_DECIMALS_OFFSET: usize = 348;
pub const STABLECOIN_TRANSITION_V3_COLLATERAL_SCALE_OFFSET: usize = 349;
pub const STABLECOIN_TRANSITION_V3_LOCKED_COLLATERAL_COMMITMENT_OFFSET: usize = 357;
pub const STABLECOIN_TRANSITION_V3_EPOCH_ID_OFFSET: usize = 421;
pub const STABLECOIN_TRANSITION_V3_MINTED_OFFSET: usize = 429;
pub const STABLECOIN_TRANSITION_V3_TOTAL_DEBT_OFFSET: usize = 437;
pub const STABLECOIN_TRANSITION_V3_SEQUENCE_OFFSET: usize = 445;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StablecoinTransitionV3Error {
    WrongLength,
    WrongMagic,
    WrongVersion,
    InvalidDirection,
    NonCanonicalBoolean,
    NonCanonicalRetirement,
    IndexOutOfRange,
    NonCanonicalDisabledPublic,
    NonCanonicalDisabledWitness,
    ContextRootMismatch,
    BeforeMembershipRootMismatch,
    AfterMembershipRootMismatch,
    PublicAssetMismatch,
    PublicPolicyVersionMismatch,
    NonCanonicalPolicyIndex,
    ZeroActionIntent,
    ActionIntentMismatch,
    IssuerAuthorizationMismatch,
    IssuerAuthorizationMustBeZero,
    AfterPublicStateMismatch,
    StaticRowMutation,
    ZeroOrNativeAsset,
    InactivePolicy,
    PolicyNotEnabled,
    InvalidLifecycle,
    PolicyRetired,
    ZeroOraclePrice,
    OracleFromFuture,
    OracleStale,
    AttestationFromFuture,
    AttestationAbsent,
    AttestationStale,
    AttestationDisputed,
    ZeroAuthorityCommitment,
    AuthorityCommitmentsNotDistinct,
    ZeroLockedCollateralCommitment,
    InvalidCollateralDecimals,
    InvalidCollateralScale,
    ValueOutOfRange,
    MintedExceedsCap,
    FutureEpoch,
    ZeroMint,
    ZeroBurn,
    IssuerSecretZero,
    IssuerSecretMustBeZero,
    IssuerCommitmentMismatch,
    ArithmeticOverflow,
    MintCapExceeded,
    DebtUnderflow,
    CollateralRatioViolation,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StablecoinTransitionRootV3([u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES]);

impl StablecoinTransitionRootV3 {
    pub const ZERO: Self = Self([0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES]);

    pub const fn new(bytes: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] {
        self.0
    }
}

impl Default for StablecoinTransitionRootV3 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl AsRef<[u8]> for StablecoinTransitionRootV3 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum StablecoinTransitionDirectionV3 {
    #[default]
    Disabled = 0,
    Mint = 1,
    Burn = 2,
}

impl TryFrom<u8> for StablecoinTransitionDirectionV3 {
    type Error = StablecoinTransitionV3Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::Mint),
            2 => Ok(Self::Burn),
            _ => Err(StablecoinTransitionV3Error::InvalidDirection),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinStateRowV3 {
    pub asset_id: u32,
    pub policy_version: u32,
    pub active: bool,
    pub enabled_at: u64,
    pub retired_at: Option<u64>,
    pub issuer_commitment: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
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
    pub policy_admin_commitment: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
    pub oracle_authority_commitment: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
    pub attestation_authority_commitment: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
    /// Collateral asset identifier; zero is permitted when zero denotes the
    /// native collateral asset in the outer asset registry.
    pub collateral_asset_id: u32,
    pub collateral_decimals: u8,
    /// Canonical `10^collateral_decimals` metadata.  Price numerator and
    /// denominator are debt atoms per collateral base atom.
    pub collateral_scale: u64,
    pub locked_collateral_commitment: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
    pub epoch_id: u64,
    pub minted_in_epoch: u64,
    pub total_debt: u64,
    pub sequence: u64,
}

impl StablecoinStateRowV3 {
    pub const ZERO: Self = Self {
        asset_id: 0,
        policy_version: 0,
        active: false,
        enabled_at: 0,
        retired_at: None,
        issuer_commitment: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
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
        policy_admin_commitment: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
        oracle_authority_commitment: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
        attestation_authority_commitment: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
        collateral_asset_id: 0,
        collateral_decimals: 0,
        collateral_scale: 0,
        locked_collateral_commitment: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
        epoch_id: 0,
        minted_in_epoch: 0,
        total_debt: 0,
        sequence: 0,
    };

    pub fn encode_canonical(self) -> [u8; STABLECOIN_TRANSITION_V3_ROW_BYTES] {
        let mut output = [0u8; STABLECOIN_TRANSITION_V3_ROW_BYTES];
        output[0..4].copy_from_slice(&self.asset_id.to_le_bytes());
        output[4..8].copy_from_slice(&self.policy_version.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_ACTIVE_OFFSET] = u8::from(self.active);
        output[9..17].copy_from_slice(&self.enabled_at.to_le_bytes());
        if let Some(retired_at) = self.retired_at {
            output[STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET] = 1;
            output[18..26].copy_from_slice(&retired_at.to_le_bytes());
        }
        output[26..90].copy_from_slice(&self.issuer_commitment);
        output[90..94].copy_from_slice(&self.min_collateral_ratio_ppm.to_le_bytes());
        output[94..102].copy_from_slice(&self.max_mint_per_epoch.to_le_bytes());
        output[102..110].copy_from_slice(&self.oracle_submitted_at.to_le_bytes());
        output[110..118].copy_from_slice(&self.oracle_max_age.to_le_bytes());
        output[118..122].copy_from_slice(&self.oracle_price_numerator.to_le_bytes());
        output[122..126].copy_from_slice(&self.oracle_price_denominator.to_le_bytes());
        output[126..134].copy_from_slice(&self.collateral_amount.to_le_bytes());
        output[134..142].copy_from_slice(&self.attestation_created_at.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_ATTESTATION_DISPUTED_OFFSET] =
            u8::from(self.attestation_disputed);
        output[STABLECOIN_TRANSITION_V3_ATTESTATION_PRESENT_OFFSET] =
            u8::from(self.attestation_present);
        output[144..152].copy_from_slice(&self.attestation_max_age.to_le_bytes());
        output[152..216].copy_from_slice(&self.policy_admin_commitment);
        output[216..280].copy_from_slice(&self.oracle_authority_commitment);
        output[280..344].copy_from_slice(&self.attestation_authority_commitment);
        output[344..348].copy_from_slice(&self.collateral_asset_id.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_COLLATERAL_DECIMALS_OFFSET] = self.collateral_decimals;
        output[349..357].copy_from_slice(&self.collateral_scale.to_le_bytes());
        output[357..421].copy_from_slice(&self.locked_collateral_commitment);
        output[421..429].copy_from_slice(&self.epoch_id.to_le_bytes());
        output[429..437].copy_from_slice(&self.minted_in_epoch.to_le_bytes());
        output[437..445].copy_from_slice(&self.total_debt.to_le_bytes());
        output[445..453].copy_from_slice(&self.sequence.to_le_bytes());
        output
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinTransitionV3Error> {
        let raw: &[u8; STABLECOIN_TRANSITION_V3_ROW_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinTransitionV3Error::WrongLength)?;
        if raw[STABLECOIN_TRANSITION_V3_ACTIVE_OFFSET] > 1
            || raw[STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET] > 1
            || raw[STABLECOIN_TRANSITION_V3_ATTESTATION_DISPUTED_OFFSET] > 1
            || raw[STABLECOIN_TRANSITION_V3_ATTESTATION_PRESENT_OFFSET] > 1
        {
            return Err(StablecoinTransitionV3Error::NonCanonicalBoolean);
        }
        if raw[STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET] == 0 && raw[18..26] != [0u8; 8] {
            return Err(StablecoinTransitionV3Error::NonCanonicalRetirement);
        }
        let mut issuer_commitment = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        issuer_commitment.copy_from_slice(&raw[26..90]);
        let mut policy_admin_commitment = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        policy_admin_commitment.copy_from_slice(&raw[152..216]);
        let mut oracle_authority_commitment = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        oracle_authority_commitment.copy_from_slice(&raw[216..280]);
        let mut attestation_authority_commitment = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        attestation_authority_commitment.copy_from_slice(&raw[280..344]);
        let mut locked_collateral_commitment = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        locked_collateral_commitment.copy_from_slice(&raw[357..421]);
        let decoded = Self {
            asset_id: u32::from_le_bytes(raw[0..4].try_into().expect("fixed slice")),
            policy_version: u32::from_le_bytes(raw[4..8].try_into().expect("fixed slice")),
            active: raw[STABLECOIN_TRANSITION_V3_ACTIVE_OFFSET] == 1,
            enabled_at: u64::from_le_bytes(raw[9..17].try_into().expect("fixed slice")),
            retired_at: (raw[STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET] == 1)
                .then(|| u64::from_le_bytes(raw[18..26].try_into().expect("fixed slice"))),
            issuer_commitment,
            min_collateral_ratio_ppm: u32::from_le_bytes(
                raw[90..94].try_into().expect("fixed slice"),
            ),
            max_mint_per_epoch: u64::from_le_bytes(raw[94..102].try_into().expect("fixed slice")),
            oracle_submitted_at: u64::from_le_bytes(raw[102..110].try_into().expect("fixed slice")),
            oracle_max_age: u64::from_le_bytes(raw[110..118].try_into().expect("fixed slice")),
            oracle_price_numerator: u32::from_le_bytes(
                raw[118..122].try_into().expect("fixed slice"),
            ),
            oracle_price_denominator: u32::from_le_bytes(
                raw[122..126].try_into().expect("fixed slice"),
            ),
            collateral_amount: u64::from_le_bytes(raw[126..134].try_into().expect("fixed slice")),
            attestation_created_at: u64::from_le_bytes(
                raw[134..142].try_into().expect("fixed slice"),
            ),
            attestation_disputed: raw[STABLECOIN_TRANSITION_V3_ATTESTATION_DISPUTED_OFFSET] == 1,
            attestation_present: raw[STABLECOIN_TRANSITION_V3_ATTESTATION_PRESENT_OFFSET] == 1,
            attestation_max_age: u64::from_le_bytes(raw[144..152].try_into().expect("fixed slice")),
            policy_admin_commitment,
            oracle_authority_commitment,
            attestation_authority_commitment,
            collateral_asset_id: u32::from_le_bytes(raw[344..348].try_into().expect("fixed slice")),
            collateral_decimals: raw[STABLECOIN_TRANSITION_V3_COLLATERAL_DECIMALS_OFFSET],
            collateral_scale: u64::from_le_bytes(raw[349..357].try_into().expect("fixed slice")),
            locked_collateral_commitment,
            epoch_id: u64::from_le_bytes(raw[421..429].try_into().expect("fixed slice")),
            minted_in_epoch: u64::from_le_bytes(raw[429..437].try_into().expect("fixed slice")),
            total_debt: u64::from_le_bytes(raw[437..445].try_into().expect("fixed slice")),
            sequence: u64::from_le_bytes(raw[445..453].try_into().expect("fixed slice")),
        };
        if decoded.encode_canonical() != *raw {
            return Err(StablecoinTransitionV3Error::NonCanonicalRetirement);
        }
        Ok(decoded)
    }

    fn static_fields_equal(self, other: Self) -> bool {
        self.encode_canonical()[..STABLECOIN_TRANSITION_V3_EPOCH_ID_OFFSET]
            == other.encode_canonical()[..STABLECOIN_TRANSITION_V3_EPOCH_ID_OFFSET]
    }
}

impl Default for StablecoinStateRowV3 {
    fn default() -> Self {
        Self::ZERO
    }
}

/// One fixed selected-row membership proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinStateMembershipProofV3 {
    pub index: u32,
    pub row: StablecoinStateRowV3,
    pub siblings: [StablecoinTransitionRootV3; STABLECOIN_TRANSITION_V3_DEPTH],
}

impl StablecoinStateMembershipProofV3 {
    pub const ZERO: Self = Self {
        index: 0,
        row: StablecoinStateRowV3::ZERO,
        siblings: [StablecoinTransitionRootV3::ZERO; STABLECOIN_TRANSITION_V3_DEPTH],
    };

    pub fn encode_canonical(
        self,
    ) -> Result<[u8; STABLECOIN_TRANSITION_V3_MEMBERSHIP_PROOF_BYTES], StablecoinTransitionV3Error>
    {
        if self.index as usize >= STABLECOIN_TRANSITION_V3_CAP {
            return Err(StablecoinTransitionV3Error::IndexOutOfRange);
        }
        let mut output = [0u8; STABLECOIN_TRANSITION_V3_MEMBERSHIP_PROOF_BYTES];
        output[..4].copy_from_slice(&self.index.to_le_bytes());
        output[4..4 + STABLECOIN_TRANSITION_V3_ROW_BYTES]
            .copy_from_slice(&self.row.encode_canonical());
        let mut cursor = 4 + STABLECOIN_TRANSITION_V3_ROW_BYTES;
        for sibling in self.siblings {
            output[cursor..cursor + STABLECOIN_TRANSITION_V3_DIGEST_BYTES]
                .copy_from_slice(sibling.as_bytes());
            cursor += STABLECOIN_TRANSITION_V3_DIGEST_BYTES;
        }
        Ok(output)
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinTransitionV3Error> {
        let raw: &[u8; STABLECOIN_TRANSITION_V3_MEMBERSHIP_PROOF_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinTransitionV3Error::WrongLength)?;
        let index = u32::from_le_bytes(raw[..4].try_into().expect("fixed slice"));
        if index as usize >= STABLECOIN_TRANSITION_V3_CAP {
            return Err(StablecoinTransitionV3Error::IndexOutOfRange);
        }
        let row = StablecoinStateRowV3::decode_canonical(
            &raw[4..4 + STABLECOIN_TRANSITION_V3_ROW_BYTES],
        )?;
        let mut siblings = [StablecoinTransitionRootV3::ZERO; STABLECOIN_TRANSITION_V3_DEPTH];
        let mut cursor = 4 + STABLECOIN_TRANSITION_V3_ROW_BYTES;
        for sibling in &mut siblings {
            let mut bytes = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
            bytes.copy_from_slice(&raw[cursor..cursor + STABLECOIN_TRANSITION_V3_DIGEST_BYTES]);
            *sibling = StablecoinTransitionRootV3::new(bytes);
            cursor += STABLECOIN_TRANSITION_V3_DIGEST_BYTES;
        }
        let decoded = Self {
            index,
            row,
            siblings,
        };
        if decoded.encode_canonical()? != *raw {
            return Err(StablecoinTransitionV3Error::WrongLength);
        }
        Ok(decoded)
    }
}

impl Default for StablecoinStateMembershipProofV3 {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Compact transition witness: one shared membership path, two rows, and the
/// mint-only issuer secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinTransitionWitnessV3 {
    pub index: u32,
    pub before: StablecoinStateRowV3,
    pub after: StablecoinStateRowV3,
    pub siblings: [StablecoinTransitionRootV3; STABLECOIN_TRANSITION_V3_DEPTH],
    pub issuer_secret: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
}

impl StablecoinTransitionWitnessV3 {
    pub const ZERO: Self = Self {
        index: 0,
        before: StablecoinStateRowV3::ZERO,
        after: StablecoinStateRowV3::ZERO,
        siblings: [StablecoinTransitionRootV3::ZERO; STABLECOIN_TRANSITION_V3_DEPTH],
        issuer_secret: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
    };

    pub fn before_membership(self) -> StablecoinStateMembershipProofV3 {
        StablecoinStateMembershipProofV3 {
            index: self.index,
            row: self.before,
            siblings: self.siblings,
        }
    }

    pub fn after_membership(self) -> StablecoinStateMembershipProofV3 {
        StablecoinStateMembershipProofV3 {
            index: self.index,
            row: self.after,
            siblings: self.siblings,
        }
    }

    pub fn encode_canonical(
        self,
    ) -> Result<[u8; STABLECOIN_TRANSITION_V3_WITNESS_BYTES], StablecoinTransitionV3Error> {
        if self.index as usize >= STABLECOIN_TRANSITION_V3_CAP {
            return Err(StablecoinTransitionV3Error::IndexOutOfRange);
        }
        let mut output = [0u8; STABLECOIN_TRANSITION_V3_WITNESS_BYTES];
        output[STABLECOIN_TRANSITION_V3_WITNESS_MAGIC_RANGE]
            .copy_from_slice(&STABLECOIN_TRANSITION_V3_WITNESS_MAGIC);
        output[STABLECOIN_TRANSITION_V3_WITNESS_VERSION_RANGE]
            .copy_from_slice(&STABLECOIN_TRANSITION_V3_VERSION.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE]
            .copy_from_slice(&self.index.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE]
            .copy_from_slice(&self.before.encode_canonical());
        output[STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE]
            .copy_from_slice(&self.after.encode_canonical());
        let mut cursor = STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.start;
        for sibling in self.siblings {
            output[cursor..cursor + STABLECOIN_TRANSITION_V3_DIGEST_BYTES]
                .copy_from_slice(sibling.as_bytes());
            cursor += STABLECOIN_TRANSITION_V3_DIGEST_BYTES;
        }
        debug_assert_eq!(cursor, STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.end);
        output[STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE]
            .copy_from_slice(&self.issuer_secret);
        Ok(output)
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinTransitionV3Error> {
        let raw: &[u8; STABLECOIN_TRANSITION_V3_WITNESS_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinTransitionV3Error::WrongLength)?;
        if raw[STABLECOIN_TRANSITION_V3_WITNESS_MAGIC_RANGE]
            != STABLECOIN_TRANSITION_V3_WITNESS_MAGIC
        {
            return Err(StablecoinTransitionV3Error::WrongMagic);
        }
        if u16::from_le_bytes(
            raw[STABLECOIN_TRANSITION_V3_WITNESS_VERSION_RANGE]
                .try_into()
                .expect("fixed slice"),
        ) != STABLECOIN_TRANSITION_V3_VERSION
        {
            return Err(StablecoinTransitionV3Error::WrongVersion);
        }
        let index = u32::from_le_bytes(
            raw[STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE]
                .try_into()
                .expect("fixed slice"),
        );
        if index as usize >= STABLECOIN_TRANSITION_V3_CAP {
            return Err(StablecoinTransitionV3Error::IndexOutOfRange);
        }
        let before = StablecoinStateRowV3::decode_canonical(
            &raw[STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE],
        )?;
        let after = StablecoinStateRowV3::decode_canonical(
            &raw[STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE],
        )?;
        let mut siblings = [StablecoinTransitionRootV3::ZERO; STABLECOIN_TRANSITION_V3_DEPTH];
        let mut cursor = STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.start;
        for sibling in &mut siblings {
            let mut bytes = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
            bytes.copy_from_slice(&raw[cursor..cursor + STABLECOIN_TRANSITION_V3_DIGEST_BYTES]);
            *sibling = StablecoinTransitionRootV3::new(bytes);
            cursor += STABLECOIN_TRANSITION_V3_DIGEST_BYTES;
        }
        let mut issuer_secret = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        if cursor != STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.end {
            return Err(StablecoinTransitionV3Error::WrongLength);
        }
        issuer_secret.copy_from_slice(&raw[STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE]);
        let decoded = Self {
            index,
            before,
            after,
            siblings,
            issuer_secret,
        };
        if decoded.encode_canonical()? != *raw {
            return Err(StablecoinTransitionV3Error::WrongLength);
        }
        Ok(decoded)
    }
}

impl Default for StablecoinTransitionWitnessV3 {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Exact proof-public stablecoin suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinTransitionPublicV3 {
    pub direction: StablecoinTransitionDirectionV3,
    pub asset_id: u32,
    pub policy_version: u32,
    pub magnitude: u64,
    /// Exact outer transaction/action identity supplied by the verifier.
    pub action_intent: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
    pub before_root: StablecoinTransitionRootV3,
    pub after_root: StablecoinTransitionRootV3,
    pub after_epoch_id: u64,
    pub after_minted_in_epoch: u64,
    pub after_total_debt: u64,
    pub after_sequence: u64,
    /// Mint-only tag over this exact public transition and the issuer secret.
    pub issuer_authorization: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
}

impl StablecoinTransitionPublicV3 {
    pub const ZERO: Self = Self {
        direction: StablecoinTransitionDirectionV3::Disabled,
        asset_id: 0,
        policy_version: 0,
        magnitude: 0,
        action_intent: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
        before_root: StablecoinTransitionRootV3::ZERO,
        after_root: StablecoinTransitionRootV3::ZERO,
        after_epoch_id: 0,
        after_minted_in_epoch: 0,
        after_total_debt: 0,
        after_sequence: 0,
        issuer_authorization: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
    };

    pub fn encode_canonical(self) -> [u8; STABLECOIN_TRANSITION_V3_PUBLIC_BYTES] {
        let mut output = [0u8; STABLECOIN_TRANSITION_V3_PUBLIC_BYTES];
        output[STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC_RANGE]
            .copy_from_slice(&STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC);
        output[STABLECOIN_TRANSITION_V3_PUBLIC_VERSION_RANGE]
            .copy_from_slice(&STABLECOIN_TRANSITION_V3_VERSION.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE.start] = self.direction as u8;
        output[STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE]
            .copy_from_slice(&self.asset_id.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE]
            .copy_from_slice(&self.policy_version.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE]
            .copy_from_slice(&self.magnitude.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE]
            .copy_from_slice(&self.action_intent);
        output[STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE]
            .copy_from_slice(self.before_root.as_bytes());
        output[STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE]
            .copy_from_slice(self.after_root.as_bytes());
        output[STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_EPOCH_RANGE]
            .copy_from_slice(&self.after_epoch_id.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_MINTED_RANGE]
            .copy_from_slice(&self.after_minted_in_epoch.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_DEBT_RANGE]
            .copy_from_slice(&self.after_total_debt.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_SEQUENCE_RANGE]
            .copy_from_slice(&self.after_sequence.to_le_bytes());
        output[STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE]
            .copy_from_slice(&self.issuer_authorization);
        output
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinTransitionV3Error> {
        let raw: &[u8; STABLECOIN_TRANSITION_V3_PUBLIC_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinTransitionV3Error::WrongLength)?;
        if raw[STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC_RANGE] != STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC
        {
            return Err(StablecoinTransitionV3Error::WrongMagic);
        }
        if u16::from_le_bytes(
            raw[STABLECOIN_TRANSITION_V3_PUBLIC_VERSION_RANGE]
                .try_into()
                .expect("fixed slice"),
        ) != STABLECOIN_TRANSITION_V3_VERSION
        {
            return Err(StablecoinTransitionV3Error::WrongVersion);
        }
        let mut before_root = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        let mut action_intent = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        action_intent.copy_from_slice(&raw[STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE]);
        before_root.copy_from_slice(&raw[STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE]);
        let mut after_root = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        after_root.copy_from_slice(&raw[STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE]);
        let mut issuer_authorization = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
        issuer_authorization
            .copy_from_slice(&raw[STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE]);
        Ok(Self {
            direction: StablecoinTransitionDirectionV3::try_from(
                raw[STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE.start],
            )?,
            asset_id: u32::from_le_bytes(
                raw[STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE]
                    .try_into()
                    .expect("fixed slice"),
            ),
            policy_version: u32::from_le_bytes(
                raw[STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE]
                    .try_into()
                    .expect("fixed slice"),
            ),
            magnitude: u64::from_le_bytes(
                raw[STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE]
                    .try_into()
                    .expect("fixed slice"),
            ),
            action_intent,
            before_root: StablecoinTransitionRootV3::new(before_root),
            after_root: StablecoinTransitionRootV3::new(after_root),
            after_epoch_id: u64::from_le_bytes(
                raw[STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_EPOCH_RANGE]
                    .try_into()
                    .expect("fixed slice"),
            ),
            after_minted_in_epoch: u64::from_le_bytes(
                raw[STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_MINTED_RANGE]
                    .try_into()
                    .expect("fixed slice"),
            ),
            after_total_debt: u64::from_le_bytes(
                raw[STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_DEBT_RANGE]
                    .try_into()
                    .expect("fixed slice"),
            ),
            after_sequence: u64::from_le_bytes(
                raw[STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_SEQUENCE_RANGE]
                    .try_into()
                    .expect("fixed slice"),
            ),
            issuer_authorization,
        })
    }
}

impl Default for StablecoinTransitionPublicV3 {
    fn default() -> Self {
        Self::ZERO
    }
}

fn transition_personalization(role: u8, level: u8) -> [u8; 16] {
    [
        b'H', b'G', b'S', b'C', b'T', b'R', b'V', b'3', role, 3, 64, 4, level, 0, 0, 0,
    ]
}

/// Commit the exact issuer tuple `asset_id:u32le || policy_version:u32le || secret64`.
pub fn stablecoin_issuer_commitment_v3(
    asset_id: u32,
    policy_version: u32,
    issuer_secret: &[u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
) -> [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] {
    let mut preimage = [0u8; 8 + STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
    preimage[..4].copy_from_slice(&asset_id.to_le_bytes());
    preimage[4..8].copy_from_slice(&policy_version.to_le_bytes());
    preimage[8..].copy_from_slice(issuer_secret);
    blake2b512_personalized_v2(&preimage, transition_personalization(ROLE_ISSUER, 0))
}

/// Bind issuer knowledge to the exact canonical action identity and transition.
///
/// The preimage is the first 251 bytes of the canonical public wire (everything
/// except this tag) followed by the 64-byte issuer secret.  This avoids a
/// state-only authorization that could be transplanted between outer actions.
pub fn stablecoin_issuer_authorization_v3(
    public: StablecoinTransitionPublicV3,
    issuer_secret: &[u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
) -> [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] {
    let public_wire = public.encode_canonical();
    let mut preimage = [0u8; STABLECOIN_TRANSITION_V3_ISSUER_AUTHORIZATION_PREIMAGE_BYTES];
    preimage[..STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start].copy_from_slice(
        &public_wire[..STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start],
    );
    preimage[STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start..]
        .copy_from_slice(issuer_secret);
    blake2b512_personalized_v2(
        &preimage,
        transition_personalization(ROLE_ISSUER_AUTHORIZATION, 0),
    )
}

/// Map every asset to exactly one of the sixteen policy slots.  Consequently,
/// two live policy versions for the same asset cannot occupy distinct leaves.
/// Distinct assets that collide on the low nibble cannot coexist in this
/// deliberately small prospective registry.
pub const fn stablecoin_policy_slot_v3(asset_id: u32) -> u32 {
    asset_id & ((STABLECOIN_TRANSITION_V3_CAP as u32) - 1)
}

/// Epoch rule required by V3: the epoch is the floor of the authenticated
/// parent height divided by 4096.  Thus a child built on parent 4095 still
/// evaluates in epoch 0; epoch 1 begins once the authenticated parent is 4096.
pub const fn stablecoin_current_epoch_from_parent_v3(parent_height: u64) -> u64 {
    parent_height >> STABLECOIN_TRANSITION_V3_EPOCH_HEIGHT_SHIFT
}

/// Hash one position-bound canonical row.
pub fn stablecoin_transition_leaf_v3(
    index: u32,
    row: StablecoinStateRowV3,
) -> Result<StablecoinTransitionRootV3, StablecoinTransitionV3Error> {
    if index as usize >= STABLECOIN_TRANSITION_V3_CAP {
        return Err(StablecoinTransitionV3Error::IndexOutOfRange);
    }
    let mut preimage = [0u8; 4 + STABLECOIN_TRANSITION_V3_ROW_BYTES];
    preimage[..4].copy_from_slice(&index.to_le_bytes());
    preimage[4..].copy_from_slice(&row.encode_canonical());
    Ok(StablecoinTransitionRootV3::new(blake2b512_personalized_v2(
        &preimage,
        transition_personalization(ROLE_LEAF, 0),
    )))
}

/// Hash one ordered node pair at its exact level.
pub fn stablecoin_transition_node_v3(
    left: StablecoinTransitionRootV3,
    right: StablecoinTransitionRootV3,
    level: usize,
) -> Result<StablecoinTransitionRootV3, StablecoinTransitionV3Error> {
    if level >= STABLECOIN_TRANSITION_V3_DEPTH {
        return Err(StablecoinTransitionV3Error::IndexOutOfRange);
    }
    let mut preimage = [0u8; 2 * STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
    preimage[..STABLECOIN_TRANSITION_V3_DIGEST_BYTES].copy_from_slice(left.as_bytes());
    preimage[STABLECOIN_TRANSITION_V3_DIGEST_BYTES..].copy_from_slice(right.as_bytes());
    Ok(StablecoinTransitionRootV3::new(blake2b512_personalized_v2(
        &preimage,
        transition_personalization(ROLE_NODE, level as u8),
    )))
}

/// Recompute the depth-four root of one fixed selected row.
pub fn stablecoin_transition_root_from_membership_v3(
    proof: StablecoinStateMembershipProofV3,
) -> Result<StablecoinTransitionRootV3, StablecoinTransitionV3Error> {
    if proof.index as usize >= STABLECOIN_TRANSITION_V3_CAP {
        return Err(StablecoinTransitionV3Error::IndexOutOfRange);
    }
    let mut current = stablecoin_transition_leaf_v3(proof.index, proof.row)?;
    let mut cursor = proof.index as usize;
    for (level, sibling) in proof.siblings.into_iter().enumerate() {
        current = if cursor & 1 == 0 {
            stablecoin_transition_node_v3(current, sibling, level)?
        } else {
            stablecoin_transition_node_v3(sibling, current, level)?
        };
        cursor >>= 1;
    }
    if cursor != 0 {
        return Err(StablecoinTransitionV3Error::IndexOutOfRange);
    }
    Ok(current)
}

fn validate_common_row_v3(row: StablecoinStateRowV3) -> Result<(), StablecoinTransitionV3Error> {
    if row.asset_id == 0 {
        return Err(StablecoinTransitionV3Error::ZeroOrNativeAsset);
    }
    if row.max_mint_per_epoch > STABLECOIN_TRANSITION_V3_MAX_VALUE
        || row.collateral_amount > STABLECOIN_TRANSITION_V3_MAX_VALUE
        || row.minted_in_epoch > STABLECOIN_TRANSITION_V3_MAX_VALUE
        || row.total_debt > STABLECOIN_TRANSITION_V3_MAX_VALUE
    {
        return Err(StablecoinTransitionV3Error::ValueOutOfRange);
    }
    if row.minted_in_epoch > row.max_mint_per_epoch {
        return Err(StablecoinTransitionV3Error::MintedExceedsCap);
    }
    if row.issuer_commitment == [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES]
        || row.policy_admin_commitment == [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES]
        || row.oracle_authority_commitment == [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES]
        || row.attestation_authority_commitment == [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES]
    {
        return Err(StablecoinTransitionV3Error::ZeroAuthorityCommitment);
    }
    if row.locked_collateral_commitment == [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] {
        return Err(StablecoinTransitionV3Error::ZeroLockedCollateralCommitment);
    }
    let commitments = [
        row.issuer_commitment,
        row.policy_admin_commitment,
        row.oracle_authority_commitment,
        row.attestation_authority_commitment,
        row.locked_collateral_commitment,
    ];
    for left in 0..commitments.len() {
        for right in left + 1..commitments.len() {
            if commitments[left] == commitments[right] {
                return Err(StablecoinTransitionV3Error::AuthorityCommitmentsNotDistinct);
            }
        }
    }
    if row.collateral_decimals > 18 {
        return Err(StablecoinTransitionV3Error::InvalidCollateralDecimals);
    }
    let mut expected_scale = 1u64;
    for _ in 0..row.collateral_decimals {
        expected_scale = expected_scale
            .checked_mul(10)
            .ok_or(StablecoinTransitionV3Error::InvalidCollateralScale)?;
    }
    if row.collateral_scale != expected_scale {
        return Err(StablecoinTransitionV3Error::InvalidCollateralScale);
    }
    Ok(())
}

fn validate_mint_row_v3(
    row: StablecoinStateRowV3,
    parent_height: u64,
) -> Result<(), StablecoinTransitionV3Error> {
    validate_common_row_v3(row)?;
    if row.min_collateral_ratio_ppm < STABLECOIN_TRANSITION_V3_RATIO_SCALE_PPM {
        return Err(StablecoinTransitionV3Error::CollateralRatioViolation);
    }
    if row.oracle_price_numerator == 0 || row.oracle_price_denominator == 0 {
        return Err(StablecoinTransitionV3Error::ZeroOraclePrice);
    }
    if !row.active {
        return Err(StablecoinTransitionV3Error::InactivePolicy);
    }
    if row.enabled_at > parent_height {
        return Err(StablecoinTransitionV3Error::PolicyNotEnabled);
    }
    if let Some(retired_at) = row.retired_at {
        if retired_at <= row.enabled_at {
            return Err(StablecoinTransitionV3Error::InvalidLifecycle);
        }
        if parent_height >= retired_at {
            return Err(StablecoinTransitionV3Error::PolicyRetired);
        }
    }
    if row.oracle_submitted_at > parent_height {
        return Err(StablecoinTransitionV3Error::OracleFromFuture);
    }
    if parent_height - row.oracle_submitted_at > row.oracle_max_age {
        return Err(StablecoinTransitionV3Error::OracleStale);
    }
    if row.attestation_created_at > parent_height {
        return Err(StablecoinTransitionV3Error::AttestationFromFuture);
    }
    if !row.attestation_present {
        return Err(StablecoinTransitionV3Error::AttestationAbsent);
    }
    if parent_height - row.attestation_created_at > row.attestation_max_age {
        return Err(StablecoinTransitionV3Error::AttestationStale);
    }
    if row.attestation_disputed {
        return Err(StablecoinTransitionV3Error::AttestationDisputed);
    }
    Ok(())
}

fn validate_collateral_ratio_v3(
    row: StablecoinStateRowV3,
) -> Result<(), StablecoinTransitionV3Error> {
    let left = u128::from(row.collateral_amount)
        .checked_mul(u128::from(row.oracle_price_numerator))
        .and_then(|value| value.checked_mul(u128::from(STABLECOIN_TRANSITION_V3_RATIO_SCALE_PPM)))
        .ok_or(StablecoinTransitionV3Error::ArithmeticOverflow)?;
    let right = u128::from(row.total_debt)
        .checked_mul(u128::from(row.oracle_price_denominator))
        .and_then(|value| value.checked_mul(u128::from(row.min_collateral_ratio_ppm)))
        .ok_or(StablecoinTransitionV3Error::ArithmeticOverflow)?;
    if left < right {
        return Err(StablecoinTransitionV3Error::CollateralRatioViolation);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinTransitionVerifierContextV3 {
    pub current_root: StablecoinTransitionRootV3,
    pub parent_height: u64,
    /// Nonzero full outer transaction/action intent digest.  A future caller
    /// must derive this from the exact network, version, action, statement,
    /// output, ciphertext, and authorization surface.
    pub expected_action_intent: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedStablecoinTransitionV3 {
    pub direction: StablecoinTransitionDirectionV3,
    pub before_root: StablecoinTransitionRootV3,
    pub after_root: StablecoinTransitionRootV3,
    pub current_epoch: u64,
    pub changed: bool,
}

/// Verify the exact V3 transition without mutating caller state.
///
/// Mint applies active/lifecycle/oracle/attestation and collateral gates.  Burn
/// deliberately bypasses those temporal/risk gates so retirement, a stale or
/// disputed source, or undercollateralization cannot freeze debt reduction;
/// it still requires the authenticated canonical row and exact successor.
pub fn verify_stablecoin_transition_v3(
    context: StablecoinTransitionVerifierContextV3,
    public: StablecoinTransitionPublicV3,
    witness: StablecoinTransitionWitnessV3,
) -> Result<VerifiedStablecoinTransitionV3, StablecoinTransitionV3Error> {
    if public.direction == StablecoinTransitionDirectionV3::Disabled {
        if public != StablecoinTransitionPublicV3::ZERO {
            return Err(StablecoinTransitionV3Error::NonCanonicalDisabledPublic);
        }
        if witness != StablecoinTransitionWitnessV3::ZERO {
            return Err(StablecoinTransitionV3Error::NonCanonicalDisabledWitness);
        }
        return Ok(VerifiedStablecoinTransitionV3 {
            direction: StablecoinTransitionDirectionV3::Disabled,
            before_root: context.current_root,
            after_root: context.current_root,
            current_epoch: stablecoin_current_epoch_from_parent_v3(context.parent_height),
            changed: false,
        });
    }
    if public.magnitude > STABLECOIN_TRANSITION_V3_MAX_VALUE {
        return Err(StablecoinTransitionV3Error::ValueOutOfRange);
    }
    if witness.index as usize >= STABLECOIN_TRANSITION_V3_CAP {
        return Err(StablecoinTransitionV3Error::IndexOutOfRange);
    }
    if witness.index != stablecoin_policy_slot_v3(witness.before.asset_id) {
        return Err(StablecoinTransitionV3Error::NonCanonicalPolicyIndex);
    }
    if public.action_intent == [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] {
        return Err(StablecoinTransitionV3Error::ZeroActionIntent);
    }
    if public.action_intent != context.expected_action_intent {
        return Err(StablecoinTransitionV3Error::ActionIntentMismatch);
    }
    if public.before_root != context.current_root {
        return Err(StablecoinTransitionV3Error::ContextRootMismatch);
    }
    let before_root = stablecoin_transition_root_from_membership_v3(witness.before_membership())?;
    if before_root != public.before_root {
        return Err(StablecoinTransitionV3Error::BeforeMembershipRootMismatch);
    }
    let after_root = stablecoin_transition_root_from_membership_v3(witness.after_membership())?;
    if after_root != public.after_root {
        return Err(StablecoinTransitionV3Error::AfterMembershipRootMismatch);
    }
    if !witness.before.static_fields_equal(witness.after) {
        return Err(StablecoinTransitionV3Error::StaticRowMutation);
    }
    match public.direction {
        StablecoinTransitionDirectionV3::Disabled => unreachable!("handled above"),
        StablecoinTransitionDirectionV3::Mint => {
            validate_mint_row_v3(witness.before, context.parent_height)?
        }
        StablecoinTransitionDirectionV3::Burn => validate_common_row_v3(witness.before)?,
    }
    if public.asset_id != witness.before.asset_id || public.asset_id != witness.after.asset_id {
        return Err(StablecoinTransitionV3Error::PublicAssetMismatch);
    }
    if public.policy_version != witness.before.policy_version
        || public.policy_version != witness.after.policy_version
    {
        return Err(StablecoinTransitionV3Error::PublicPolicyVersionMismatch);
    }
    let current_epoch = stablecoin_current_epoch_from_parent_v3(context.parent_height);
    if witness.before.epoch_id > current_epoch {
        return Err(StablecoinTransitionV3Error::FutureEpoch);
    }
    let mint_base = if witness.before.epoch_id == current_epoch {
        witness.before.minted_in_epoch
    } else {
        0
    };
    let expected_minted;
    let expected_debt;
    match public.direction {
        StablecoinTransitionDirectionV3::Disabled => unreachable!("handled above"),
        StablecoinTransitionDirectionV3::Mint => {
            if public.magnitude == 0 {
                return Err(StablecoinTransitionV3Error::ZeroMint);
            }
            if witness.issuer_secret == [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] {
                return Err(StablecoinTransitionV3Error::IssuerSecretZero);
            }
            if stablecoin_issuer_commitment_v3(
                witness.before.asset_id,
                witness.before.policy_version,
                &witness.issuer_secret,
            ) != witness.before.issuer_commitment
            {
                return Err(StablecoinTransitionV3Error::IssuerCommitmentMismatch);
            }
            expected_minted = mint_base
                .checked_add(public.magnitude)
                .ok_or(StablecoinTransitionV3Error::ArithmeticOverflow)?;
            if expected_minted > witness.before.max_mint_per_epoch {
                return Err(StablecoinTransitionV3Error::MintCapExceeded);
            }
            expected_debt = witness
                .before
                .total_debt
                .checked_add(public.magnitude)
                .ok_or(StablecoinTransitionV3Error::ArithmeticOverflow)?;
        }
        StablecoinTransitionDirectionV3::Burn => {
            if public.magnitude == 0 {
                return Err(StablecoinTransitionV3Error::ZeroBurn);
            }
            if witness.issuer_secret != [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] {
                return Err(StablecoinTransitionV3Error::IssuerSecretMustBeZero);
            }
            if public.issuer_authorization != [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] {
                return Err(StablecoinTransitionV3Error::IssuerAuthorizationMustBeZero);
            }
            expected_minted = mint_base;
            expected_debt = witness
                .before
                .total_debt
                .checked_sub(public.magnitude)
                .ok_or(StablecoinTransitionV3Error::DebtUnderflow)?;
        }
    }
    if expected_minted > STABLECOIN_TRANSITION_V3_MAX_VALUE
        || expected_debt > STABLECOIN_TRANSITION_V3_MAX_VALUE
    {
        return Err(StablecoinTransitionV3Error::ValueOutOfRange);
    }
    let expected_sequence = witness
        .before
        .sequence
        .checked_add(1)
        .ok_or(StablecoinTransitionV3Error::ArithmeticOverflow)?;
    if witness.after.epoch_id != current_epoch
        || witness.after.minted_in_epoch != expected_minted
        || witness.after.total_debt != expected_debt
        || witness.after.sequence != expected_sequence
    {
        return Err(StablecoinTransitionV3Error::AfterPublicStateMismatch);
    }
    if public.after_epoch_id != witness.after.epoch_id
        || public.after_minted_in_epoch != witness.after.minted_in_epoch
        || public.after_total_debt != witness.after.total_debt
        || public.after_sequence != witness.after.sequence
    {
        return Err(StablecoinTransitionV3Error::AfterPublicStateMismatch);
    }
    if public.direction == StablecoinTransitionDirectionV3::Mint
        && stablecoin_issuer_authorization_v3(public, &witness.issuer_secret)
            != public.issuer_authorization
    {
        return Err(StablecoinTransitionV3Error::IssuerAuthorizationMismatch);
    }
    if public.direction == StablecoinTransitionDirectionV3::Mint {
        validate_collateral_ratio_v3(witness.after)?;
    }
    Ok(VerifiedStablecoinTransitionV3 {
        direction: public.direction,
        before_root,
        after_root,
        current_epoch,
        changed: true,
    })
}

/// Minimal prospective root state.  `parent_height` is verifier-owned and is
/// not changed by applying one transition at that parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinTransitionStateV3 {
    pub current_root: StablecoinTransitionRootV3,
    pub parent_height: u64,
}

/// Verify first, then atomically replace the root.  Every error returns before
/// mutation, so two transitions built against the same parent cannot both
/// apply sequentially.
pub fn apply_stablecoin_transition_v3(
    state: &mut StablecoinTransitionStateV3,
    expected_action_intent: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
    public: StablecoinTransitionPublicV3,
    witness: StablecoinTransitionWitnessV3,
) -> Result<VerifiedStablecoinTransitionV3, StablecoinTransitionV3Error> {
    let verified = verify_stablecoin_transition_v3(
        StablecoinTransitionVerifierContextV3 {
            current_root: state.current_root,
            parent_height: state.parent_height,
            expected_action_intent,
        },
        public,
        witness,
    )?;
    if verified.changed {
        state.current_root = verified.after_root;
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARENT_HEIGHT: u64 = (3 << STABLECOIN_TRANSITION_V3_EPOCH_HEIGHT_SHIFT) + 100;
    const SECRET: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] =
        [0x42; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
    const ACTION_INTENT: [u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES] =
        [0xa5; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];

    fn base_row() -> StablecoinStateRowV3 {
        let asset_id = 1_001;
        let policy_version = 7;
        StablecoinStateRowV3 {
            asset_id,
            policy_version,
            active: true,
            enabled_at: 10,
            retired_at: Some(PARENT_HEIGHT + 1_000),
            issuer_commitment: stablecoin_issuer_commitment_v3(asset_id, policy_version, &SECRET),
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
        }
    }

    fn siblings() -> [StablecoinTransitionRootV3; STABLECOIN_TRANSITION_V3_DEPTH] {
        core::array::from_fn(|level| {
            let mut bytes = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
            for (offset, byte) in bytes.iter_mut().enumerate() {
                *byte = (17 * (level + 1) + offset) as u8;
            }
            StablecoinTransitionRootV3::new(bytes)
        })
    }

    fn transition_fixture(
        direction: StablecoinTransitionDirectionV3,
        magnitude: u64,
        before: StablecoinStateRowV3,
    ) -> (
        StablecoinTransitionVerifierContextV3,
        StablecoinTransitionPublicV3,
        StablecoinTransitionWitnessV3,
    ) {
        let current_epoch = stablecoin_current_epoch_from_parent_v3(PARENT_HEIGHT);
        let mint_base = if before.epoch_id == current_epoch {
            before.minted_in_epoch
        } else {
            0
        };
        let mut after = before;
        after.epoch_id = current_epoch;
        after.sequence = before.sequence.wrapping_add(1);
        let issuer_secret;
        match direction {
            StablecoinTransitionDirectionV3::Mint => {
                after.minted_in_epoch = mint_base.saturating_add(magnitude);
                after.total_debt = before.total_debt.saturating_add(magnitude);
                issuer_secret = SECRET;
            }
            StablecoinTransitionDirectionV3::Burn => {
                after.minted_in_epoch = mint_base;
                after.total_debt = before.total_debt.saturating_sub(magnitude);
                issuer_secret = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
            }
            StablecoinTransitionDirectionV3::Disabled => {
                after = before;
                issuer_secret = [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES];
            }
        }
        let witness = StablecoinTransitionWitnessV3 {
            index: stablecoin_policy_slot_v3(before.asset_id),
            before,
            after,
            siblings: siblings(),
            issuer_secret,
        };
        public_for(direction, magnitude, witness)
    }

    fn public_for(
        direction: StablecoinTransitionDirectionV3,
        magnitude: u64,
        witness: StablecoinTransitionWitnessV3,
    ) -> (
        StablecoinTransitionVerifierContextV3,
        StablecoinTransitionPublicV3,
        StablecoinTransitionWitnessV3,
    ) {
        let before_root =
            stablecoin_transition_root_from_membership_v3(witness.before_membership()).unwrap();
        let after_root =
            stablecoin_transition_root_from_membership_v3(witness.after_membership()).unwrap();
        let mut public = StablecoinTransitionPublicV3 {
            direction,
            asset_id: witness.before.asset_id,
            policy_version: witness.before.policy_version,
            magnitude,
            action_intent: ACTION_INTENT,
            before_root,
            after_root,
            after_epoch_id: witness.after.epoch_id,
            after_minted_in_epoch: witness.after.minted_in_epoch,
            after_total_debt: witness.after.total_debt,
            after_sequence: witness.after.sequence,
            issuer_authorization: [0u8; STABLECOIN_TRANSITION_V3_DIGEST_BYTES],
        };
        if direction == StablecoinTransitionDirectionV3::Mint {
            public.issuer_authorization =
                stablecoin_issuer_authorization_v3(public, &witness.issuer_secret);
        }
        (
            StablecoinTransitionVerifierContextV3 {
                current_root: before_root,
                parent_height: PARENT_HEIGHT,
                expected_action_intent: ACTION_INTENT,
            },
            public,
            witness,
        )
    }

    fn verify_fixture(
        direction: StablecoinTransitionDirectionV3,
        magnitude: u64,
        before: StablecoinStateRowV3,
    ) -> Result<VerifiedStablecoinTransitionV3, StablecoinTransitionV3Error> {
        let (context, public, witness) = transition_fixture(direction, magnitude, before);
        verify_stablecoin_transition_v3(context, public, witness)
    }

    #[test]
    fn canonical_kat_and_roundtrip() {
        let (context, public, witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Mint, 25, base_row());
        let row_wire = witness.before.encode_canonical();
        let membership_wire = witness.before_membership().encode_canonical().unwrap();
        let public_wire = public.encode_canonical();
        let witness_wire = witness.encode_canonical().unwrap();

        assert_eq!(row_wire.len(), 453);
        assert_eq!(membership_wire.len(), 713);
        assert_eq!(public_wire.len(), 315);
        assert_eq!(witness_wire.len(), 1_240);
        assert_eq!(
            StablecoinStateRowV3::decode_canonical(&row_wire),
            Ok(witness.before)
        );
        assert_eq!(
            StablecoinStateMembershipProofV3::decode_canonical(&membership_wire),
            Ok(witness.before_membership())
        );
        assert_eq!(
            StablecoinTransitionPublicV3::decode_canonical(&public_wire),
            Ok(public)
        );
        assert_eq!(
            StablecoinTransitionWitnessV3::decode_canonical(&witness_wire),
            Ok(witness)
        );

        assert_eq!(
            hex::encode(witness.before.issuer_commitment),
            "f680bd285547b3ff298e804f83174b92e1bd7f6e544a4223e245cb2156b6460e337b0da234fe1824f7befd1264b9b99994fb630e509bbbb48aa19ae40d902651"
        );
        assert_eq!(
            hex::encode(context.current_root.as_bytes()),
            "eb63ca2a44f012ce06118f0d7870599f5001cd32df1680177f63fc5271a0a0fea4eb5f7af2855f6e76ffceed9888d96c891b840f26287689995d4c2ad37acd2e"
        );
        assert_eq!(
            hex::encode(public.after_root.as_bytes()),
            "5e7b5ea4c7afd06e787aaf2d2360bf12fc949b9ed7b31d74d83456134be8613b704d07a33a4a7d5f8af9a4a58e9b3be91564edffcafb6aae2ee636a0acaefb50"
        );
        assert_eq!(
            hex::encode(public.issuer_authorization),
            "d4dd6f0ebe561555d6eeb4d82b0f188f87b38d0df7d8be2d0aabcee77f9059415eeb721a508e04840519b4b74169e7069dc456b2d1830ded2c9a19b591ade4e0"
        );
    }

    #[test]
    fn mint_burn_and_epoch_reset_are_exact() {
        let mint = verify_fixture(StablecoinTransitionDirectionV3::Mint, 25, base_row()).unwrap();
        assert!(mint.changed);
        assert_eq!(mint.current_epoch, 3);

        let (_, burn_public, burn_witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Burn, 25, base_row());
        assert_eq!(burn_witness.after.minted_in_epoch, 100);
        assert_eq!(burn_witness.after.total_debt, 475);
        assert_eq!(burn_public.issuer_authorization, [0u8; 64]);
        verify_stablecoin_transition_v3(
            StablecoinTransitionVerifierContextV3 {
                current_root: burn_public.before_root,
                parent_height: PARENT_HEIGHT,
                expected_action_intent: ACTION_INTENT,
            },
            burn_public,
            burn_witness,
        )
        .unwrap();

        let mut old_epoch = base_row();
        old_epoch.epoch_id = 2;
        old_epoch.minted_in_epoch = 999;
        let (_, reset_public, reset_witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Mint, 25, old_epoch);
        assert_eq!(reset_witness.after.epoch_id, 3);
        assert_eq!(reset_witness.after.minted_in_epoch, 25);
        verify_stablecoin_transition_v3(
            StablecoinTransitionVerifierContextV3 {
                current_root: reset_public.before_root,
                parent_height: PARENT_HEIGHT,
                expected_action_intent: ACTION_INTENT,
            },
            reset_public,
            reset_witness,
        )
        .unwrap();

        let mut future_epoch = base_row();
        future_epoch.epoch_id = 4;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, future_epoch),
            Err(StablecoinTransitionV3Error::FutureEpoch)
        );
    }

    #[test]
    fn cap_debt_issuer_and_intent_fail_closed() {
        let mut cap = base_row();
        cap.minted_in_epoch = 999;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 2, cap),
            Err(StablecoinTransitionV3Error::MintCapExceeded)
        );
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Burn, 501, base_row()),
            Err(StablecoinTransitionV3Error::DebtUnderflow)
        );
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 0, base_row()),
            Err(StablecoinTransitionV3Error::ZeroMint)
        );
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Burn, 0, base_row()),
            Err(StablecoinTransitionV3Error::ZeroBurn)
        );
        assert_eq!(
            verify_fixture(
                StablecoinTransitionDirectionV3::Mint,
                STABLECOIN_TRANSITION_V3_MAX_VALUE + 1,
                base_row(),
            ),
            Err(StablecoinTransitionV3Error::ValueOutOfRange)
        );
        let mut oversized_cap = base_row();
        oversized_cap.max_mint_per_epoch = STABLECOIN_TRANSITION_V3_MAX_VALUE + 1;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, oversized_cap),
            Err(StablecoinTransitionV3Error::ValueOutOfRange)
        );
        let mut oversized_debt = base_row();
        oversized_debt.total_debt = STABLECOIN_TRANSITION_V3_MAX_VALUE;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, oversized_debt),
            Err(StablecoinTransitionV3Error::ValueOutOfRange)
        );
        let mut reused_role_commitment = base_row();
        reused_role_commitment.oracle_authority_commitment =
            reused_role_commitment.policy_admin_commitment;
        assert_eq!(
            verify_fixture(
                StablecoinTransitionDirectionV3::Burn,
                1,
                reused_role_commitment,
            ),
            Err(StablecoinTransitionV3Error::AuthorityCommitmentsNotDistinct)
        );
        let mut sequence_overflow = base_row();
        sequence_overflow.sequence = u64::MAX;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, sequence_overflow),
            Err(StablecoinTransitionV3Error::ArithmeticOverflow)
        );

        let (context, public, mut witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Mint, 25, base_row());
        witness.issuer_secret[0] ^= 1;
        assert_eq!(
            verify_stablecoin_transition_v3(context, public, witness),
            Err(StablecoinTransitionV3Error::IssuerCommitmentMismatch)
        );

        let (context, mut public, witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Mint, 25, base_row());
        public.issuer_authorization[0] ^= 1;
        assert_eq!(
            verify_stablecoin_transition_v3(context, public, witness),
            Err(StablecoinTransitionV3Error::IssuerAuthorizationMismatch)
        );

        let (mut context, public, witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Mint, 25, base_row());
        context.expected_action_intent[0] ^= 1;
        assert_eq!(
            verify_stablecoin_transition_v3(context, public, witness),
            Err(StablecoinTransitionV3Error::ActionIntentMismatch)
        );

        let (context, mut public, witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Mint, 25, base_row());
        public.action_intent = [0u8; 64];
        assert_eq!(
            verify_stablecoin_transition_v3(context, public, witness),
            Err(StablecoinTransitionV3Error::ZeroActionIntent)
        );

        let (context, public, mut burn_witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Burn, 25, base_row());
        burn_witness.issuer_secret[0] = 1;
        assert_eq!(
            verify_stablecoin_transition_v3(context, public, burn_witness),
            Err(StablecoinTransitionV3Error::IssuerSecretMustBeZero)
        );
        let (context, mut burn_public, burn_witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Burn, 25, base_row());
        burn_public.issuer_authorization[0] = 1;
        assert_eq!(
            verify_stablecoin_transition_v3(context, burn_public, burn_witness),
            Err(StablecoinTransitionV3Error::IssuerAuthorizationMustBeZero)
        );
    }

    #[test]
    fn lifecycle_oracle_attestation_and_ratio_gates_are_exact() {
        let mut row = base_row();
        row.enabled_at = PARENT_HEIGHT;
        verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row).unwrap();

        row = base_row();
        row.enabled_at = PARENT_HEIGHT + 1;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::PolicyNotEnabled)
        );
        row = base_row();
        row.retired_at = Some(PARENT_HEIGHT);
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::PolicyRetired)
        );
        row = base_row();
        row.retired_at = Some(row.enabled_at);
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::InvalidLifecycle)
        );
        row = base_row();
        row.active = false;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::InactivePolicy)
        );

        row = base_row();
        row.oracle_submitted_at = PARENT_HEIGHT - row.oracle_max_age;
        verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row).unwrap();
        row.oracle_submitted_at -= 1;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::OracleStale)
        );
        row = base_row();
        row.oracle_submitted_at = PARENT_HEIGHT + 1;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::OracleFromFuture)
        );
        row = base_row();
        row.attestation_created_at = PARENT_HEIGHT + 1;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::AttestationFromFuture)
        );
        row = base_row();
        row.attestation_created_at = PARENT_HEIGHT - row.attestation_max_age;
        verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row).unwrap();
        row.attestation_created_at -= 1;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::AttestationStale)
        );
        row = base_row();
        row.attestation_present = false;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::AttestationAbsent)
        );
        row = base_row();
        row.attestation_disputed = true;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::AttestationDisputed)
        );
        row = base_row();
        row.oracle_price_numerator = 0;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::ZeroOraclePrice)
        );
        row = base_row();
        row.min_collateral_ratio_ppm = STABLECOIN_TRANSITION_V3_RATIO_SCALE_PPM - 1;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::CollateralRatioViolation)
        );

        row = base_row();
        row.collateral_amount = 1;
        row.oracle_price_numerator = 3;
        row.oracle_price_denominator = 1;
        row.min_collateral_ratio_ppm = 1_500_000;
        row.total_debt = 1;
        verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row).unwrap();
        row.min_collateral_ratio_ppm = 1_500_001;
        assert_eq!(
            verify_fixture(StablecoinTransitionDirectionV3::Mint, 1, row),
            Err(StablecoinTransitionV3Error::CollateralRatioViolation)
        );
    }

    #[test]
    fn burn_remains_available_across_risk_and_lifecycle_failures() {
        let mut retired = base_row();
        retired.retired_at = Some(PARENT_HEIGHT);
        verify_fixture(StablecoinTransitionDirectionV3::Burn, 1, retired).unwrap();
        let mut stale = base_row();
        stale.oracle_submitted_at = 0;
        stale.oracle_max_age = 1;
        verify_fixture(StablecoinTransitionDirectionV3::Burn, 1, stale).unwrap();
        let mut disputed = base_row();
        disputed.attestation_disputed = true;
        verify_fixture(StablecoinTransitionDirectionV3::Burn, 1, disputed).unwrap();
        let mut inactive = base_row();
        inactive.active = false;
        verify_fixture(StablecoinTransitionDirectionV3::Burn, 1, inactive).unwrap();
        let mut undercollateralized = base_row();
        undercollateralized.collateral_amount = 1;
        verify_fixture(
            StablecoinTransitionDirectionV3::Burn,
            1,
            undercollateralized,
        )
        .unwrap();
        let mut unavailable_sources = base_row();
        unavailable_sources.oracle_price_numerator = 0;
        unavailable_sources.oracle_price_denominator = 0;
        unavailable_sources.min_collateral_ratio_ppm = 0;
        unavailable_sources.oracle_submitted_at = PARENT_HEIGHT + 1;
        unavailable_sources.attestation_created_at = PARENT_HEIGHT + 1;
        verify_fixture(
            StablecoinTransitionDirectionV3::Burn,
            1,
            unavailable_sources,
        )
        .unwrap();
    }

    #[test]
    fn path_index_roots_static_and_public_mutations_reject() {
        let (context, public, witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Mint, 25, base_row());

        let mut changed = witness;
        changed.siblings[2].0[3] ^= 1;
        assert_eq!(
            verify_stablecoin_transition_v3(context, public, changed),
            Err(StablecoinTransitionV3Error::BeforeMembershipRootMismatch)
        );
        changed = witness;
        changed.index ^= 1;
        assert_eq!(
            verify_stablecoin_transition_v3(context, public, changed),
            Err(StablecoinTransitionV3Error::NonCanonicalPolicyIndex)
        );

        let mut changed_public = public;
        changed_public.before_root.0[0] ^= 1;
        assert_eq!(
            verify_stablecoin_transition_v3(context, changed_public, witness),
            Err(StablecoinTransitionV3Error::ContextRootMismatch)
        );
        changed_public = public;
        changed_public.after_root.0[0] ^= 1;
        assert_eq!(
            verify_stablecoin_transition_v3(context, changed_public, witness),
            Err(StablecoinTransitionV3Error::AfterMembershipRootMismatch)
        );

        let mut static_witness = witness;
        static_witness.after.oracle_max_age += 1;
        let (static_context, static_public, static_witness) =
            public_for(StablecoinTransitionDirectionV3::Mint, 25, static_witness);
        assert_eq!(
            verify_stablecoin_transition_v3(static_context, static_public, static_witness),
            Err(StablecoinTransitionV3Error::StaticRowMutation)
        );

        let mut dynamic_witness = witness;
        dynamic_witness.after.total_debt += 1;
        let (dynamic_context, dynamic_public, dynamic_witness) =
            public_for(StablecoinTransitionDirectionV3::Mint, 25, dynamic_witness);
        assert_eq!(
            verify_stablecoin_transition_v3(dynamic_context, dynamic_public, dynamic_witness),
            Err(StablecoinTransitionV3Error::AfterPublicStateMismatch)
        );

        let mut after_public = public;
        after_public.after_sequence += 1;
        assert_eq!(
            verify_stablecoin_transition_v3(context, after_public, witness),
            Err(StablecoinTransitionV3Error::AfterPublicStateMismatch)
        );

        let mut colliding_public = public;
        colliding_public.asset_id += 16;
        assert_eq!(
            stablecoin_policy_slot_v3(public.asset_id),
            stablecoin_policy_slot_v3(colliding_public.asset_id)
        );
        assert_eq!(
            verify_stablecoin_transition_v3(context, colliding_public, witness),
            Err(StablecoinTransitionV3Error::PublicAssetMismatch)
        );
    }

    #[test]
    fn every_enabled_public_and_witness_byte_mutation_rejects() {
        let (context, public, witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Mint, 25, base_row());
        let public_wire = public.encode_canonical();
        for offset in 0..public_wire.len() {
            let mut mutated = public_wire;
            mutated[offset] ^= 1;
            if let Ok(mutated_public) = StablecoinTransitionPublicV3::decode_canonical(&mutated) {
                assert!(
                    verify_stablecoin_transition_v3(context, mutated_public, witness).is_err(),
                    "public mutation at byte {offset} was accepted"
                );
            }
        }

        let witness_wire = witness.encode_canonical().unwrap();
        for offset in 0..witness_wire.len() {
            let mut mutated = witness_wire;
            mutated[offset] ^= 1;
            if let Ok(mutated_witness) = StablecoinTransitionWitnessV3::decode_canonical(&mutated) {
                assert!(
                    verify_stablecoin_transition_v3(context, public, mutated_witness).is_err(),
                    "witness mutation at byte {offset} was accepted"
                );
            }
        }
    }

    #[test]
    fn disabled_is_unique_and_never_mutates_state() {
        let context = StablecoinTransitionVerifierContextV3 {
            current_root: StablecoinTransitionRootV3::new([0x77; 64]),
            parent_height: PARENT_HEIGHT,
            expected_action_intent: [0u8; 64],
        };
        let verified = verify_stablecoin_transition_v3(
            context,
            StablecoinTransitionPublicV3::ZERO,
            StablecoinTransitionWitnessV3::ZERO,
        )
        .unwrap();
        assert!(!verified.changed);
        assert_eq!(verified.before_root, context.current_root);
        assert_eq!(verified.after_root, context.current_root);

        let public_wire = StablecoinTransitionPublicV3::ZERO.encode_canonical();
        for offset in 0..public_wire.len() {
            let mut mutated = public_wire;
            mutated[offset] ^= 1;
            if let Ok(public) = StablecoinTransitionPublicV3::decode_canonical(&mutated) {
                assert!(
                    verify_stablecoin_transition_v3(
                        context,
                        public,
                        StablecoinTransitionWitnessV3::ZERO,
                    )
                    .is_err(),
                    "disabled public mutation at byte {offset} was accepted"
                );
            }
        }
        let witness_wire = StablecoinTransitionWitnessV3::ZERO
            .encode_canonical()
            .unwrap();
        for offset in 0..witness_wire.len() {
            let mut mutated = witness_wire;
            mutated[offset] ^= 1;
            if let Ok(witness) = StablecoinTransitionWitnessV3::decode_canonical(&mutated) {
                assert!(
                    verify_stablecoin_transition_v3(
                        context,
                        StablecoinTransitionPublicV3::ZERO,
                        witness,
                    )
                    .is_err(),
                    "disabled witness mutation at byte {offset} was accepted"
                );
            }
        }
    }

    #[test]
    fn apply_is_atomic_and_rejects_same_parent_twice() {
        let (context, public, witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Mint, 25, base_row());
        let mut state = StablecoinTransitionStateV3 {
            current_root: context.current_root,
            parent_height: context.parent_height,
        };
        let initial = state;
        let mut invalid_public = public;
        invalid_public.after_total_debt += 1;
        assert_eq!(
            apply_stablecoin_transition_v3(&mut state, ACTION_INTENT, invalid_public, witness),
            Err(StablecoinTransitionV3Error::AfterPublicStateMismatch)
        );
        assert_eq!(state, initial);

        let accepted =
            apply_stablecoin_transition_v3(&mut state, ACTION_INTENT, public, witness).unwrap();
        assert_eq!(state.current_root, accepted.after_root);
        let after_first = state;
        assert_eq!(
            apply_stablecoin_transition_v3(&mut state, ACTION_INTENT, public, witness),
            Err(StablecoinTransitionV3Error::ContextRootMismatch)
        );
        assert_eq!(state, after_first);

        let disabled_before = state;
        apply_stablecoin_transition_v3(
            &mut state,
            [0u8; 64],
            StablecoinTransitionPublicV3::ZERO,
            StablecoinTransitionWitnessV3::ZERO,
        )
        .unwrap();
        assert_eq!(state, disabled_before);
    }

    #[test]
    fn canonical_parsers_and_all_membership_positions_are_strict() {
        let row = base_row();
        let mut raw = row.encode_canonical();
        raw[STABLECOIN_TRANSITION_V3_ACTIVE_OFFSET] = 2;
        assert_eq!(
            StablecoinStateRowV3::decode_canonical(&raw),
            Err(StablecoinTransitionV3Error::NonCanonicalBoolean)
        );
        raw = row.encode_canonical();
        raw[STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET] = 0;
        assert_eq!(
            StablecoinStateRowV3::decode_canonical(&raw),
            Err(StablecoinTransitionV3Error::NonCanonicalRetirement)
        );
        raw = row.encode_canonical();
        raw[STABLECOIN_TRANSITION_V3_ATTESTATION_PRESENT_OFFSET] = 2;
        assert_eq!(
            StablecoinStateRowV3::decode_canonical(&raw),
            Err(StablecoinTransitionV3Error::NonCanonicalBoolean)
        );

        let (_, public, witness) =
            transition_fixture(StablecoinTransitionDirectionV3::Mint, 25, row);
        let mut public_raw = public.encode_canonical();
        public_raw[STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE.start] = 3;
        assert_eq!(
            StablecoinTransitionPublicV3::decode_canonical(&public_raw),
            Err(StablecoinTransitionV3Error::InvalidDirection)
        );
        assert_eq!(
            StablecoinTransitionPublicV3::decode_canonical(&public_raw[..314]),
            Err(StablecoinTransitionV3Error::WrongLength)
        );
        assert_eq!(
            StablecoinTransitionWitnessV3::decode_canonical(
                &witness.encode_canonical().unwrap()[..1_239]
            ),
            Err(StablecoinTransitionV3Error::WrongLength)
        );

        let mut roots = [StablecoinTransitionRootV3::ZERO; STABLECOIN_TRANSITION_V3_CAP];
        for (index, root) in roots.iter_mut().enumerate() {
            *root =
                stablecoin_transition_root_from_membership_v3(StablecoinStateMembershipProofV3 {
                    index: index as u32,
                    row,
                    siblings: siblings(),
                })
                .unwrap();
        }
        for left in 0..roots.len() {
            for right in left + 1..roots.len() {
                assert_ne!(roots[left], roots[right]);
            }
        }
    }

    #[test]
    fn public_and_witness_codec_ranges_are_contiguous_and_total() {
        fn assert_layout(ranges: &[core::ops::Range<usize>], total: usize) {
            let mut cursor = 0;
            for range in ranges {
                assert_eq!(range.start, cursor);
                assert!(range.start < range.end);
                cursor = range.end;
            }
            assert_eq!(cursor, total);
        }

        let public = [
            STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_VERSION_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_EPOCH_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_MINTED_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_DEBT_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_SEQUENCE_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE,
        ];
        assert_layout(&public, STABLECOIN_TRANSITION_V3_PUBLIC_BYTES);
        assert_eq!(
            STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE.len(),
            STABLECOIN_TRANSITION_V3_DIGEST_BYTES
        );
        assert_eq!(
            STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE.len(),
            STABLECOIN_TRANSITION_V3_DIGEST_BYTES
        );
        assert_eq!(
            STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_ROOT_RANGE.len(),
            STABLECOIN_TRANSITION_V3_DIGEST_BYTES
        );
        assert_eq!(
            STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.len(),
            STABLECOIN_TRANSITION_V3_DIGEST_BYTES
        );

        let witness = [
            STABLECOIN_TRANSITION_V3_WITNESS_MAGIC_RANGE,
            STABLECOIN_TRANSITION_V3_WITNESS_VERSION_RANGE,
            STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE,
            STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE,
            STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE,
            STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE,
            STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE,
        ];
        assert_layout(&witness, STABLECOIN_TRANSITION_V3_WITNESS_BYTES);
        assert_eq!(
            STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.len(),
            STABLECOIN_TRANSITION_V3_ROW_BYTES
        );
        assert_eq!(
            STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.len(),
            STABLECOIN_TRANSITION_V3_ROW_BYTES
        );
        assert_eq!(
            STABLECOIN_TRANSITION_V3_WITNESS_PATH_RANGE.len(),
            STABLECOIN_TRANSITION_V3_DEPTH * STABLECOIN_TRANSITION_V3_DIGEST_BYTES
        );
        assert_eq!(
            STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.len(),
            STABLECOIN_TRANSITION_V3_DIGEST_BYTES
        );
    }

    #[test]
    fn epoch_boundaries_accounting_and_authorization_flags_are_exact() {
        assert_eq!(stablecoin_current_epoch_from_parent_v3(4_095), 0);
        assert_eq!(stablecoin_current_epoch_from_parent_v3(4_096), 1);
        assert_eq!(stablecoin_current_epoch_from_parent_v3(8_191), 1);
        assert_eq!(stablecoin_current_epoch_from_parent_v3(8_192), 2);
        assert_eq!(
            stablecoin_current_epoch_from_parent_v3(u64::MAX),
            u64::MAX >> 12
        );
        assert_eq!(STABLECOIN_TRANSITION_V3_ENABLED_MEMBERSHIP_HASH_CALLS, 10);
        assert_eq!(STABLECOIN_TRANSITION_V3_ENABLED_MEMBERSHIP_COMPRESSIONS, 16);
        assert_eq!(STABLECOIN_TRANSITION_V3_MINT_HASH_CALLS, 12);
        assert_eq!(STABLECOIN_TRANSITION_V3_MINT_COMPRESSIONS, 20);
        assert_eq!(STABLECOIN_TRANSITION_V3_BURN_HASH_CALLS, 10);
        assert_eq!(STABLECOIN_TRANSITION_V3_BURN_COMPRESSIONS, 16);
        assert_eq!(
            STABLECOIN_TRANSITION_V3_ISSUER_AUTHORIZATION_PREIMAGE_BYTES,
            315
        );

        assert!(!STABLECOIN_TRANSITION_V3_ACTIVE);
        assert!(!STABLECOIN_TRANSITION_V3_CONSENSUS_ROUTE_AUTHORIZED);
        assert!(!STABLECOIN_TRANSITION_V3_RELATION_INTEGRATED);
        assert!(!STABLECOIN_TRANSITION_V3_QROM_AUTHORIZED);
        assert!(!STABLECOIN_TRANSITION_V3_COMPLETE_ZK_AUTHORIZED);
        assert!(!STABLECOIN_TRANSITION_V3_FORMAL_REFINEMENT_COMPLETE);
        assert!(!STABLECOIN_TRANSITION_V3_PRODUCTION_AUTHORIZED);
        assert!(!STABLECOIN_TRANSITION_V3_SOURCE_WRITER_AUTHORIZED);
        assert!(!STABLECOIN_TRANSITION_V3_GOVERNANCE_AUTHORIZED);
        assert!(!STABLECOIN_TRANSITION_V3_TRANSACTION_COMPILER_INTEGRATED);
        assert!(!STABLECOIN_TRANSITION_V3_ROOT_LIFECYCLE_AUTHORIZED);
        assert!(!STABLECOIN_TRANSITION_V3_STATIC_SOURCE_REFRESH_INTEGRATED);
        assert!(STABLECOIN_TRANSITION_V3_UNIQUE_POLICY_SLOT_ENFORCED);
        assert!(!STABLECOIN_TRANSITION_V3_LEGACY_SIGN_ADAPTER_INTEGRATED);
    }
}
