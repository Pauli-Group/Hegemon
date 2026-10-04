//! Prospective authenticated source and genesis state machine for stablecoin V3.
//!
//! This module is executable for review but deliberately inactive.  It owns no
//! consensus route, governance decision, database writer, proof relation,
//! receipt, cache, or production authority.  Its only purpose is to make the
//! missing all-slot genesis and authenticated static-source refresh semantics
//! exact and testable without changing the frozen transaction transition.
//!
//! Each row binds distinct policy-admin, mint-issuer, oracle, attestation, and
//! collateral-custody authorities.  A source update proves knowledge of the
//! old policy-admin secret plus exactly the old/new authority openings required
//! by its update kind, and authenticates the exact intent, parent height,
//! allocation, before row/root, after row/root, and any key rotation.  The
//! witness wire is private relation input and must never be carried as a public
//! authorization artifact.
//!
//! Genesis admission opens all five authority secrets per row and checks them
//! pairwise distinct. Ordinary updates preserve every authority secret;
//! `AuthorityRotation` opens all old/new roles, rotates exactly the selected
//! subset, and rechecks pairwise separation. This is an inductive state-machine
//! invariant and does not itself authorize a production genesis or state writer.

use crate::stablecoin_manifest_authority_v2::blake2b512_personalized_v2;
use crate::stablecoin_transition_v3::{
    stablecoin_current_epoch_from_parent_v3, stablecoin_issuer_commitment_v3,
    stablecoin_policy_slot_v3, stablecoin_transition_leaf_v3, stablecoin_transition_node_v3,
    stablecoin_transition_root_from_membership_v3, StablecoinStateMembershipProofV3,
    StablecoinStateRowV3, StablecoinTransitionRootV3, STABLECOIN_TRANSITION_V3_CAP,
    STABLECOIN_TRANSITION_V3_DEPTH, STABLECOIN_TRANSITION_V3_DIGEST_BYTES,
    STABLECOIN_TRANSITION_V3_MAX_VALUE, STABLECOIN_TRANSITION_V3_RATIO_SCALE_PPM,
    STABLECOIN_TRANSITION_V3_ROW_BYTES,
};

pub const STABLECOIN_SOURCE_V3_VERSION: u16 = 3;
pub const STABLECOIN_SOURCE_V3_CAP: usize = STABLECOIN_TRANSITION_V3_CAP;
pub const STABLECOIN_SOURCE_V3_DEPTH: usize = STABLECOIN_TRANSITION_V3_DEPTH;
pub const STABLECOIN_SOURCE_V3_DIGEST_BYTES: usize = STABLECOIN_TRANSITION_V3_DIGEST_BYTES;

pub const STABLECOIN_SOURCE_V3_ALLOCATION_BYTES: usize = 8 + 2 + 4 * STABLECOIN_SOURCE_V3_CAP;
pub const STABLECOIN_SOURCE_V3_GENESIS_BYTES: usize = 8
    + 2
    + 8
    + 4 * STABLECOIN_SOURCE_V3_CAP
    + STABLECOIN_SOURCE_V3_CAP * STABLECOIN_TRANSITION_V3_ROW_BYTES
    + 2 * STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_WITNESS_BYTES: usize =
    8 + 2 + STABLECOIN_SOURCE_V3_CAP * 5 * STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_UPDATE_PUBLIC_BYTES: usize =
    36 + STABLECOIN_TRANSITION_V3_ROW_BYTES + 5 * STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_UPDATE_WITNESS_BYTES: usize = 14
    + STABLECOIN_TRANSITION_V3_ROW_BYTES
    + (STABLECOIN_SOURCE_V3_DEPTH + 10) * STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_ADMIN_AUTHORIZATION_PREIMAGE_BYTES: usize =
    STABLECOIN_SOURCE_V3_UPDATE_PUBLIC_BYTES + STABLECOIN_TRANSITION_V3_ROW_BYTES;

pub const STABLECOIN_SOURCE_V3_ALLOCATION_MAGIC: [u8; 8] = *b"HGSAM3\0\0";
pub const STABLECOIN_SOURCE_V3_GENESIS_MAGIC: [u8; 8] = *b"HGSGN3\0\0";
pub const STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_WITNESS_MAGIC: [u8; 8] = *b"HGSGW3\0\0";
pub const STABLECOIN_SOURCE_V3_UPDATE_PUBLIC_MAGIC: [u8; 8] = *b"HGSSP3\0\0";
pub const STABLECOIN_SOURCE_V3_UPDATE_WITNESS_MAGIC: [u8; 8] = *b"HGSSW3\0\0";

pub const STABLECOIN_SOURCE_V3_GENESIS_PARENT_HEIGHT_OFFSET: usize = 10;
pub const STABLECOIN_SOURCE_V3_GENESIS_ALLOCATION_OFFSET: usize = 18;
pub const STABLECOIN_SOURCE_V3_GENESIS_ROWS_OFFSET: usize = 82;
pub const STABLECOIN_SOURCE_V3_GENESIS_ALLOCATION_COMMITMENT_OFFSET: usize =
    STABLECOIN_SOURCE_V3_GENESIS_ROWS_OFFSET
        + STABLECOIN_SOURCE_V3_CAP * STABLECOIN_TRANSITION_V3_ROW_BYTES;
pub const STABLECOIN_SOURCE_V3_GENESIS_ROOT_OFFSET: usize =
    STABLECOIN_SOURCE_V3_GENESIS_ALLOCATION_COMMITMENT_OFFSET + STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_SECRETS_OFFSET: usize = 10;

pub const STABLECOIN_SOURCE_V3_UPDATE_KIND_OFFSET: usize = 10;
pub const STABLECOIN_SOURCE_V3_UPDATE_AUXILIARY_AUTHORITY_MASK_OFFSET: usize = 11;
pub const STABLECOIN_SOURCE_V3_UPDATE_SLOT_OFFSET: usize = 12;
pub const STABLECOIN_SOURCE_V3_UPDATE_ASSET_ID_OFFSET: usize = 16;
pub const STABLECOIN_SOURCE_V3_UPDATE_BEFORE_POLICY_VERSION_OFFSET: usize = 20;
pub const STABLECOIN_SOURCE_V3_UPDATE_AFTER_POLICY_VERSION_OFFSET: usize = 24;
pub const STABLECOIN_SOURCE_V3_UPDATE_PARENT_HEIGHT_OFFSET: usize = 28;
pub const STABLECOIN_SOURCE_V3_UPDATE_INTENT_OFFSET: usize = 36;
pub const STABLECOIN_SOURCE_V3_UPDATE_ALLOCATION_COMMITMENT_OFFSET: usize = 100;
pub const STABLECOIN_SOURCE_V3_UPDATE_BEFORE_ROOT_OFFSET: usize = 164;
pub const STABLECOIN_SOURCE_V3_UPDATE_AFTER_ROOT_OFFSET: usize = 228;
pub const STABLECOIN_SOURCE_V3_UPDATE_AFTER_ROW_OFFSET: usize = 292;
pub const STABLECOIN_SOURCE_V3_UPDATE_ADMIN_AUTHORIZATION_OFFSET: usize =
    STABLECOIN_SOURCE_V3_UPDATE_AFTER_ROW_OFFSET + STABLECOIN_TRANSITION_V3_ROW_BYTES;

pub const STABLECOIN_SOURCE_V3_WITNESS_SLOT_OFFSET: usize = 10;
pub const STABLECOIN_SOURCE_V3_WITNESS_BEFORE_ROW_OFFSET: usize = 14;
pub const STABLECOIN_SOURCE_V3_WITNESS_SIBLINGS_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_BEFORE_ROW_OFFSET + STABLECOIN_TRANSITION_V3_ROW_BYTES;
pub const STABLECOIN_SOURCE_V3_WITNESS_SECRETS_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_SIBLINGS_OFFSET
        + STABLECOIN_SOURCE_V3_DEPTH * STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_WITNESS_OLD_ADMIN_SECRET_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_SECRETS_OFFSET;
pub const STABLECOIN_SOURCE_V3_WITNESS_NEW_ADMIN_SECRET_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_OLD_ADMIN_SECRET_OFFSET + STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_WITNESS_OLD_ISSUER_SECRET_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_NEW_ADMIN_SECRET_OFFSET + STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_WITNESS_NEW_ISSUER_SECRET_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_OLD_ISSUER_SECRET_OFFSET + STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_WITNESS_OLD_ORACLE_SECRET_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_NEW_ISSUER_SECRET_OFFSET + STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_WITNESS_NEW_ORACLE_SECRET_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_OLD_ORACLE_SECRET_OFFSET + STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_WITNESS_OLD_ATTESTATION_SECRET_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_NEW_ORACLE_SECRET_OFFSET + STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_WITNESS_NEW_ATTESTATION_SECRET_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_OLD_ATTESTATION_SECRET_OFFSET + STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_WITNESS_OLD_COLLATERAL_SECRET_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_NEW_ATTESTATION_SECRET_OFFSET + STABLECOIN_SOURCE_V3_DIGEST_BYTES;
pub const STABLECOIN_SOURCE_V3_WITNESS_NEW_COLLATERAL_SECRET_OFFSET: usize =
    STABLECOIN_SOURCE_V3_WITNESS_OLD_COLLATERAL_SECRET_OFFSET + STABLECOIN_SOURCE_V3_DIGEST_BYTES;

pub const STABLECOIN_SOURCE_V3_ACTIVE: bool = false;
pub const STABLECOIN_SOURCE_V3_KERNEL_GLOBAL_ROOT_INTEGRATED: bool = false;
pub const STABLECOIN_SOURCE_V3_GENESIS_ROUTE_AUTHORIZED: bool = false;
pub const STABLECOIN_SOURCE_V3_STATE_WRITER_INTEGRATED: bool = false;
pub const STABLECOIN_SOURCE_V3_GOVERNANCE_AUTHORIZED: bool = false;
pub const STABLECOIN_SOURCE_V3_TRANSACTION_COMPILER_INTEGRATED: bool = false;
pub const STABLECOIN_SOURCE_V3_RELATION_INTEGRATED: bool = false;
pub const STABLECOIN_SOURCE_V3_CONSENSUS_ROUTE_AUTHORIZED: bool = false;
pub const STABLECOIN_SOURCE_V3_QROM_AUTHORIZED: bool = false;
pub const STABLECOIN_SOURCE_V3_COMPLETE_ZK_AUTHORIZED: bool = false;
pub const STABLECOIN_SOURCE_V3_FORMAL_REFINEMENT_COMPLETE: bool = false;
pub const STABLECOIN_SOURCE_V3_CACHE_AUTHORITY: bool = false;
pub const STABLECOIN_SOURCE_V3_RECEIPT_AUTHORITY: bool = false;
pub const STABLECOIN_SOURCE_V3_PRODUCTION_AUTHORIZED: bool = false;

/// Full genesis: 16 four-compression leaves and 15 one-compression nodes.
pub const STABLECOIN_SOURCE_V3_GENESIS_ROOT_HASH_CALLS: usize = 31;
pub const STABLECOIN_SOURCE_V3_GENESIS_ROOT_COMPRESSIONS: usize = 79;
/// Allocation commitment adds one 74-byte call/compression to root building.
pub const STABLECOIN_SOURCE_V3_GENESIS_TOTAL_HASH_CALLS: usize = 32;
pub const STABLECOIN_SOURCE_V3_GENESIS_TOTAL_COMPRESSIONS: usize = 80;
/// Admission additionally opens five pairwise-distinct authority secrets for
/// every row. Each commitment preimage fits one BLAKE2b compression.
pub const STABLECOIN_SOURCE_V3_GENESIS_VERIFICATION_HASH_CALLS: usize = 112;
pub const STABLECOIN_SOURCE_V3_GENESIS_VERIFICATION_COMPRESSIONS: usize = 160;
/// Minimum retire/activate update: allocation, two paths, old/new admin
/// commitment checks, and the admin authorization tag.
pub const STABLECOIN_SOURCE_V3_UPDATE_MIN_HASH_CALLS: usize = 14;
pub const STABLECOIN_SOURCE_V3_UPDATE_MIN_COMPRESSIONS: usize = 29;
/// Oracle, attestation, collateral, and policy refreshes additionally check one
/// old/new authority-opening pair.
pub const STABLECOIN_SOURCE_V3_ORDINARY_UPDATE_HASH_CALLS: usize = 16;
pub const STABLECOIN_SOURCE_V3_ORDINARY_UPDATE_COMPRESSIONS: usize = 31;
/// Every authority rotation opens all five old/new role secrets to preserve
/// the genesis pairwise-separation invariant across selected key changes.
pub const STABLECOIN_SOURCE_V3_AUTHORITY_ROTATION_HASH_CALLS: usize = 22;
pub const STABLECOIN_SOURCE_V3_AUTHORITY_ROTATION_COMPRESSIONS: usize = 37;
/// Global update maximum; currently identical to authority rotation.
pub const STABLECOIN_SOURCE_V3_UPDATE_MAX_HASH_CALLS: usize = 22;
pub const STABLECOIN_SOURCE_V3_UPDATE_MAX_COMPRESSIONS: usize = 37;
pub const STABLECOIN_SOURCE_V3_INTENT_FRAME_HASH_CALLS: usize = 1;
pub const STABLECOIN_SOURCE_V3_INTENT_FRAME_COMPRESSIONS: usize = 1;

const SOURCE_PROFILE_V3: u8 = 3;
const SOURCE_WIDTH_V3: u8 = 64;
const SOURCE_CAP_LOG2_V3: u8 = 4;
const ROLE_ALLOCATION: u8 = 1;
const ROLE_ADMIN_AUTHORIZATION: u8 = 2;
const ROLE_POLICY_ADMIN: u8 = 3;
const ROLE_ORACLE_AUTHORITY: u8 = 4;
const ROLE_ATTESTATION_AUTHORITY: u8 = 5;
const ROLE_COLLATERAL_CUSTODY: u8 = 6;
const ROLE_UPDATE_INTENT: u8 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StablecoinSourceV3Error {
    WrongLength,
    WrongMagic,
    WrongVersion,
    InvalidUpdateKind,
    InvalidAuthorityMask,
    IndexOutOfRange,
    ZeroAllocationAsset,
    AllocationSlotMismatch,
    DuplicateAllocationAsset,
    AllocationCommitmentMismatch,
    GenesisAssetMismatch,
    GenesisParentHeightMismatch,
    GenesisAllocationMismatch,
    GenesisPolicyVersionMismatch,
    GenesisDynamicStateNonzero,
    GenesisEpochMismatch,
    GenesisRootMismatch,
    ParentHeightMismatch,
    ContextRootMismatch,
    ZeroUpdateIntent,
    UpdateIntentMismatch,
    PublicSlotMismatch,
    PublicAssetMismatch,
    PublicPolicyVersionMismatch,
    BeforeMembershipRootMismatch,
    AfterMembershipRootMismatch,
    ImmutableAssetMutation,
    ForbiddenFieldMutation,
    RequiredFieldUnchanged,
    DynamicAccountingMutation,
    PolicyVersionOverflow,
    PolicyVersionSuccessorMismatch,
    SequenceOverflow,
    SequenceSuccessorMismatch,
    OracleTimestampRegression,
    AttestationTimestampRegression,
    RetirementMutation,
    InvalidActivation,
    InvalidRetirement,
    NonCanonicalAuthorityWitness,
    ZeroAdminSecret,
    ZeroNewAdminSecret,
    OldAdminCommitmentMismatch,
    NewAdminCommitmentMismatch,
    ZeroIssuerSecret,
    IssuerCommitmentMismatch,
    ZeroOracleSecret,
    OracleAuthorityCommitmentMismatch,
    ZeroAttestationSecret,
    AttestationAuthorityCommitmentMismatch,
    ZeroCollateralSecret,
    CollateralCustodyCommitmentMismatch,
    AdminAuthorizationMismatch,
    ZeroOrNativeAsset,
    ZeroPolicyVersion,
    ZeroIssuerCommitment,
    InvalidLifecycle,
    PolicyNotEnabled,
    PolicyRetired,
    ZeroOraclePrice,
    OracleFromFuture,
    OracleStale,
    AttestationFromFuture,
    AttestationStale,
    AttestationAbsent,
    ZeroAuthorityCommitment,
    AuthorityCommitmentsNotDistinct,
    AuthoritySecretsNotDistinct,
    InvalidCollateralDecimals,
    InvalidCollateralScale,
    ValueOutOfRange,
    MintedExceedsCap,
    FutureEpoch,
    ArithmeticOverflow,
    CollateralRatioViolation,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StablecoinSourceDigestV3([u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]);

impl StablecoinSourceDigestV3 {
    pub const ZERO: Self = Self([0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]);

    pub const fn new(bytes: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for StablecoinSourceDigestV3 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for StablecoinSourceDigestV3 {
    fn default() -> Self {
        Self::ZERO
    }
}

fn source_personalization(role: u8, level: u8) -> [u8; 16] {
    [
        b'H',
        b'G',
        b'S',
        b'C',
        b'S',
        b'R',
        b'V',
        b'3',
        role,
        SOURCE_PROFILE_V3,
        SOURCE_WIDTH_V3,
        SOURCE_CAP_LOG2_V3,
        level,
        0,
        0,
        0,
    ]
}

/// The old policy-admin authorization is mandatory for every enabled update
/// and is therefore implicit.  For ordinary updates this mask names the exact
/// auxiliary authority opening; for `AuthorityRotation` it names the exact
/// set of keys that rotate (including admin when selected).
pub const STABLECOIN_SOURCE_V3_AUTHORITY_ADMIN: u8 = 1 << 0;
pub const STABLECOIN_SOURCE_V3_AUTHORITY_ISSUER: u8 = 1 << 1;
pub const STABLECOIN_SOURCE_V3_AUTHORITY_ORACLE: u8 = 1 << 2;
pub const STABLECOIN_SOURCE_V3_AUTHORITY_ATTESTATION: u8 = 1 << 3;
pub const STABLECOIN_SOURCE_V3_AUTHORITY_COLLATERAL: u8 = 1 << 4;
pub const STABLECOIN_SOURCE_V3_AUTHORITY_ALL: u8 = STABLECOIN_SOURCE_V3_AUTHORITY_ADMIN
    | STABLECOIN_SOURCE_V3_AUTHORITY_ISSUER
    | STABLECOIN_SOURCE_V3_AUTHORITY_ORACLE
    | STABLECOIN_SOURCE_V3_AUTHORITY_ATTESTATION
    | STABLECOIN_SOURCE_V3_AUTHORITY_COLLATERAL;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StablecoinSourceUpdateKindV3 {
    OracleRefresh = 1,
    AttestationRefresh = 2,
    CollateralSync = 3,
    PolicyUpgrade = 4,
    AuthorityRotation = 5,
    Retire = 6,
    Activate = 7,
}

impl TryFrom<u8> for StablecoinSourceUpdateKindV3 {
    type Error = StablecoinSourceV3Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::OracleRefresh),
            2 => Ok(Self::AttestationRefresh),
            3 => Ok(Self::CollateralSync),
            4 => Ok(Self::PolicyUpgrade),
            5 => Ok(Self::AuthorityRotation),
            6 => Ok(Self::Retire),
            7 => Ok(Self::Activate),
            _ => Err(StablecoinSourceV3Error::InvalidUpdateKind),
        }
    }
}

pub fn stablecoin_policy_admin_commitment_v3(
    asset_id: u32,
    secret: &[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
) -> [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] {
    let mut message = [0u8; 4 + STABLECOIN_SOURCE_V3_DIGEST_BYTES];
    message[..4].copy_from_slice(&asset_id.to_le_bytes());
    message[4..].copy_from_slice(secret);
    blake2b512_personalized_v2(&message, source_personalization(ROLE_POLICY_ADMIN, 0))
}

pub fn stablecoin_oracle_authority_commitment_v3(
    row: StablecoinStateRowV3,
    secret: &[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
) -> [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] {
    let mut message = [0u8; 4 + STABLECOIN_SOURCE_V3_DIGEST_BYTES];
    message[..4].copy_from_slice(&row.asset_id.to_le_bytes());
    message[4..].copy_from_slice(secret);
    blake2b512_personalized_v2(&message, source_personalization(ROLE_ORACLE_AUTHORITY, 0))
}

pub fn stablecoin_attestation_authority_commitment_v3(
    row: StablecoinStateRowV3,
    secret: &[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
) -> [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] {
    let mut message = [0u8; 4 + STABLECOIN_SOURCE_V3_DIGEST_BYTES];
    message[..4].copy_from_slice(&row.asset_id.to_le_bytes());
    message[4..].copy_from_slice(secret);
    blake2b512_personalized_v2(
        &message,
        source_personalization(ROLE_ATTESTATION_AUTHORITY, 0),
    )
}

pub fn stablecoin_collateral_custody_commitment_v3(
    row: StablecoinStateRowV3,
    secret: &[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
) -> [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] {
    let mut message = [0u8; 4 + 4 + 1 + 8 + 8 + STABLECOIN_SOURCE_V3_DIGEST_BYTES];
    message[..4].copy_from_slice(&row.asset_id.to_le_bytes());
    message[4..8].copy_from_slice(&row.collateral_asset_id.to_le_bytes());
    message[8] = row.collateral_decimals;
    message[9..17].copy_from_slice(&row.collateral_scale.to_le_bytes());
    message[17..25].copy_from_slice(&row.collateral_amount.to_le_bytes());
    message[25..].copy_from_slice(secret);
    blake2b512_personalized_v2(&message, source_personalization(ROLE_COLLATERAL_CUSTODY, 0))
}

/// Frame an authenticated 64-byte outer action digest into the distinct source
/// update-intent domain.  The outer digest must exclude this framed field and
/// all authorization tags, while the outer parser separately binds every
/// derived nullifier and transaction field.  A caller echo is not authority.
pub fn stablecoin_source_update_intent_v3(
    outer_action_digest: &[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
) -> [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] {
    let mut message = [0u8; 8 + 2 + STABLECOIN_SOURCE_V3_DIGEST_BYTES];
    message[..8].copy_from_slice(b"HGSI3\0\0\0");
    message[8..10].copy_from_slice(&STABLECOIN_SOURCE_V3_VERSION.to_le_bytes());
    message[10..].copy_from_slice(outer_action_digest);
    blake2b512_personalized_v2(&message, source_personalization(ROLE_UPDATE_INTENT, 0))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinSourceAllocationV3 {
    pub asset_ids: [u32; STABLECOIN_SOURCE_V3_CAP],
}

impl StablecoinSourceAllocationV3 {
    pub const ZERO: Self = Self {
        asset_ids: [0u32; STABLECOIN_SOURCE_V3_CAP],
    };

    pub fn validate(self) -> Result<(), StablecoinSourceV3Error> {
        for slot in 0..STABLECOIN_SOURCE_V3_CAP {
            let asset_id = self.asset_ids[slot];
            if asset_id == 0 {
                return Err(StablecoinSourceV3Error::ZeroAllocationAsset);
            }
            if stablecoin_policy_slot_v3(asset_id) as usize != slot {
                return Err(StablecoinSourceV3Error::AllocationSlotMismatch);
            }
            for previous in 0..slot {
                if self.asset_ids[previous] == asset_id {
                    return Err(StablecoinSourceV3Error::DuplicateAllocationAsset);
                }
            }
        }
        Ok(())
    }

    pub fn encode_canonical(self) -> [u8; STABLECOIN_SOURCE_V3_ALLOCATION_BYTES] {
        let mut output = [0u8; STABLECOIN_SOURCE_V3_ALLOCATION_BYTES];
        output[..8].copy_from_slice(&STABLECOIN_SOURCE_V3_ALLOCATION_MAGIC);
        output[8..10].copy_from_slice(&STABLECOIN_SOURCE_V3_VERSION.to_le_bytes());
        for (slot, asset_id) in self.asset_ids.into_iter().enumerate() {
            let start = 10 + 4 * slot;
            output[start..start + 4].copy_from_slice(&asset_id.to_le_bytes());
        }
        output
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinSourceV3Error> {
        let raw: &[u8; STABLECOIN_SOURCE_V3_ALLOCATION_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinSourceV3Error::WrongLength)?;
        if raw[..8] != STABLECOIN_SOURCE_V3_ALLOCATION_MAGIC {
            return Err(StablecoinSourceV3Error::WrongMagic);
        }
        if u16::from_le_bytes(raw[8..10].try_into().expect("fixed slice"))
            != STABLECOIN_SOURCE_V3_VERSION
        {
            return Err(StablecoinSourceV3Error::WrongVersion);
        }
        let mut asset_ids = [0u32; STABLECOIN_SOURCE_V3_CAP];
        for (slot, asset_id) in asset_ids.iter_mut().enumerate() {
            let start = 10 + 4 * slot;
            *asset_id = u32::from_le_bytes(raw[start..start + 4].try_into().expect("fixed slice"));
        }
        let decoded = Self { asset_ids };
        decoded.validate()?;
        if decoded.encode_canonical() != *raw {
            return Err(StablecoinSourceV3Error::WrongLength);
        }
        Ok(decoded)
    }
}

impl Default for StablecoinSourceAllocationV3 {
    fn default() -> Self {
        Self::ZERO
    }
}

pub fn stablecoin_source_allocation_commitment_v3(
    allocation: StablecoinSourceAllocationV3,
) -> Result<StablecoinSourceDigestV3, StablecoinSourceV3Error> {
    allocation.validate()?;
    Ok(StablecoinSourceDigestV3::new(blake2b512_personalized_v2(
        &allocation.encode_canonical(),
        source_personalization(ROLE_ALLOCATION, 0),
    )))
}

pub fn stablecoin_source_root_from_rows_v3(
    rows: &[StablecoinStateRowV3; STABLECOIN_SOURCE_V3_CAP],
) -> Result<StablecoinTransitionRootV3, StablecoinSourceV3Error> {
    let mut layer = [StablecoinTransitionRootV3::ZERO; STABLECOIN_SOURCE_V3_CAP];
    for (slot, row) in rows.iter().copied().enumerate() {
        layer[slot] = stablecoin_transition_leaf_v3(slot as u32, row)
            .map_err(|_| StablecoinSourceV3Error::IndexOutOfRange)?;
    }
    let mut width = STABLECOIN_SOURCE_V3_CAP;
    for level in 0..STABLECOIN_SOURCE_V3_DEPTH {
        for parent in 0..width / 2 {
            layer[parent] =
                stablecoin_transition_node_v3(layer[2 * parent], layer[2 * parent + 1], level)
                    .map_err(|_| StablecoinSourceV3Error::IndexOutOfRange)?;
        }
        width /= 2;
    }
    Ok(layer[0])
}

pub fn stablecoin_source_membership_from_rows_v3(
    rows: &[StablecoinStateRowV3; STABLECOIN_SOURCE_V3_CAP],
    index: u32,
) -> Result<StablecoinStateMembershipProofV3, StablecoinSourceV3Error> {
    if index as usize >= STABLECOIN_SOURCE_V3_CAP {
        return Err(StablecoinSourceV3Error::IndexOutOfRange);
    }
    let mut layer = [StablecoinTransitionRootV3::ZERO; STABLECOIN_SOURCE_V3_CAP];
    for (slot, row) in rows.iter().copied().enumerate() {
        layer[slot] = stablecoin_transition_leaf_v3(slot as u32, row)
            .map_err(|_| StablecoinSourceV3Error::IndexOutOfRange)?;
    }
    let mut siblings = [StablecoinTransitionRootV3::ZERO; STABLECOIN_SOURCE_V3_DEPTH];
    let mut cursor = index as usize;
    let mut width = STABLECOIN_SOURCE_V3_CAP;
    for (level, sibling) in siblings.iter_mut().enumerate() {
        *sibling = layer[cursor ^ 1];
        for parent in 0..width / 2 {
            layer[parent] =
                stablecoin_transition_node_v3(layer[2 * parent], layer[2 * parent + 1], level)
                    .map_err(|_| StablecoinSourceV3Error::IndexOutOfRange)?;
        }
        cursor >>= 1;
        width /= 2;
    }
    Ok(StablecoinStateMembershipProofV3 {
        index,
        row: rows[index as usize],
        siblings,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinSourceGenesisV3 {
    pub parent_height: u64,
    pub allocation: StablecoinSourceAllocationV3,
    pub rows: [StablecoinStateRowV3; STABLECOIN_SOURCE_V3_CAP],
    pub allocation_commitment: StablecoinSourceDigestV3,
    pub root: StablecoinTransitionRootV3,
}

impl StablecoinSourceGenesisV3 {
    pub fn encode_canonical(self) -> [u8; STABLECOIN_SOURCE_V3_GENESIS_BYTES] {
        let mut output = [0u8; STABLECOIN_SOURCE_V3_GENESIS_BYTES];
        output[..8].copy_from_slice(&STABLECOIN_SOURCE_V3_GENESIS_MAGIC);
        output[8..10].copy_from_slice(&STABLECOIN_SOURCE_V3_VERSION.to_le_bytes());
        output[10..18].copy_from_slice(&self.parent_height.to_le_bytes());
        let mut cursor = 18;
        for asset_id in self.allocation.asset_ids {
            output[cursor..cursor + 4].copy_from_slice(&asset_id.to_le_bytes());
            cursor += 4;
        }
        for row in self.rows {
            output[cursor..cursor + STABLECOIN_TRANSITION_V3_ROW_BYTES]
                .copy_from_slice(&row.encode_canonical());
            cursor += STABLECOIN_TRANSITION_V3_ROW_BYTES;
        }
        output[cursor..cursor + STABLECOIN_SOURCE_V3_DIGEST_BYTES]
            .copy_from_slice(self.allocation_commitment.as_bytes());
        cursor += STABLECOIN_SOURCE_V3_DIGEST_BYTES;
        output[cursor..cursor + STABLECOIN_SOURCE_V3_DIGEST_BYTES]
            .copy_from_slice(self.root.as_bytes());
        output
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinSourceV3Error> {
        let raw: &[u8; STABLECOIN_SOURCE_V3_GENESIS_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinSourceV3Error::WrongLength)?;
        if raw[..8] != STABLECOIN_SOURCE_V3_GENESIS_MAGIC {
            return Err(StablecoinSourceV3Error::WrongMagic);
        }
        if u16::from_le_bytes(raw[8..10].try_into().expect("fixed slice"))
            != STABLECOIN_SOURCE_V3_VERSION
        {
            return Err(StablecoinSourceV3Error::WrongVersion);
        }
        let parent_height = u64::from_le_bytes(raw[10..18].try_into().expect("fixed slice"));
        let mut cursor = 18;
        let mut asset_ids = [0u32; STABLECOIN_SOURCE_V3_CAP];
        for asset_id in &mut asset_ids {
            *asset_id =
                u32::from_le_bytes(raw[cursor..cursor + 4].try_into().expect("fixed slice"));
            cursor += 4;
        }
        let allocation = StablecoinSourceAllocationV3 { asset_ids };
        allocation.validate()?;
        let mut rows = [StablecoinStateRowV3::ZERO; STABLECOIN_SOURCE_V3_CAP];
        for row in &mut rows {
            *row = StablecoinStateRowV3::decode_canonical(
                &raw[cursor..cursor + STABLECOIN_TRANSITION_V3_ROW_BYTES],
            )
            .map_err(|_| StablecoinSourceV3Error::WrongLength)?;
            cursor += STABLECOIN_TRANSITION_V3_ROW_BYTES;
        }
        let mut allocation_commitment = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
        allocation_commitment
            .copy_from_slice(&raw[cursor..cursor + STABLECOIN_SOURCE_V3_DIGEST_BYTES]);
        cursor += STABLECOIN_SOURCE_V3_DIGEST_BYTES;
        let mut root = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
        root.copy_from_slice(&raw[cursor..cursor + STABLECOIN_SOURCE_V3_DIGEST_BYTES]);
        let decoded = Self {
            parent_height,
            allocation,
            rows,
            allocation_commitment: StablecoinSourceDigestV3::new(allocation_commitment),
            root: StablecoinTransitionRootV3::new(root),
        };
        if decoded.encode_canonical() != *raw {
            return Err(StablecoinSourceV3Error::WrongLength);
        }
        Ok(decoded)
    }
}

/// Private genesis-opening witness. Secret order on the fixed wire is
/// slot-major: policy admin, mint issuer, oracle, attestation, collateral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinSourceGenesisAuthorityWitnessV3 {
    pub policy_admin_secrets: [[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; STABLECOIN_SOURCE_V3_CAP],
    pub issuer_secrets: [[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; STABLECOIN_SOURCE_V3_CAP],
    pub oracle_secrets: [[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; STABLECOIN_SOURCE_V3_CAP],
    pub attestation_secrets: [[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; STABLECOIN_SOURCE_V3_CAP],
    pub collateral_secrets: [[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; STABLECOIN_SOURCE_V3_CAP],
}

impl StablecoinSourceGenesisAuthorityWitnessV3 {
    pub const ZERO: Self = Self {
        policy_admin_secrets: [[0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; STABLECOIN_SOURCE_V3_CAP],
        issuer_secrets: [[0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; STABLECOIN_SOURCE_V3_CAP],
        oracle_secrets: [[0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; STABLECOIN_SOURCE_V3_CAP],
        attestation_secrets: [[0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; STABLECOIN_SOURCE_V3_CAP],
        collateral_secrets: [[0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; STABLECOIN_SOURCE_V3_CAP],
    };

    pub fn encode_canonical(self) -> [u8; STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_WITNESS_BYTES] {
        let mut output = [0u8; STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_WITNESS_BYTES];
        output[..8].copy_from_slice(&STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_WITNESS_MAGIC);
        output[8..10].copy_from_slice(&STABLECOIN_SOURCE_V3_VERSION.to_le_bytes());
        let mut cursor = STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_SECRETS_OFFSET;
        for slot in 0..STABLECOIN_SOURCE_V3_CAP {
            for secret in [
                self.policy_admin_secrets[slot],
                self.issuer_secrets[slot],
                self.oracle_secrets[slot],
                self.attestation_secrets[slot],
                self.collateral_secrets[slot],
            ] {
                output[cursor..cursor + STABLECOIN_SOURCE_V3_DIGEST_BYTES].copy_from_slice(&secret);
                cursor += STABLECOIN_SOURCE_V3_DIGEST_BYTES;
            }
        }
        output
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinSourceV3Error> {
        let raw: &[u8; STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_WITNESS_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinSourceV3Error::WrongLength)?;
        if raw[..8] != STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_WITNESS_MAGIC {
            return Err(StablecoinSourceV3Error::WrongMagic);
        }
        if u16::from_le_bytes(raw[8..10].try_into().expect("fixed slice"))
            != STABLECOIN_SOURCE_V3_VERSION
        {
            return Err(StablecoinSourceV3Error::WrongVersion);
        }
        let mut decoded = Self::ZERO;
        let mut cursor = STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_SECRETS_OFFSET;
        for slot in 0..STABLECOIN_SOURCE_V3_CAP {
            for destination in [
                &mut decoded.policy_admin_secrets[slot],
                &mut decoded.issuer_secrets[slot],
                &mut decoded.oracle_secrets[slot],
                &mut decoded.attestation_secrets[slot],
                &mut decoded.collateral_secrets[slot],
            ] {
                destination
                    .copy_from_slice(&raw[cursor..cursor + STABLECOIN_SOURCE_V3_DIGEST_BYTES]);
                cursor += STABLECOIN_SOURCE_V3_DIGEST_BYTES;
            }
        }
        if decoded.encode_canonical() != *raw {
            return Err(StablecoinSourceV3Error::WrongLength);
        }
        Ok(decoded)
    }
}

impl Default for StablecoinSourceGenesisAuthorityWitnessV3 {
    fn default() -> Self {
        Self::ZERO
    }
}

fn validate_collateral_ratio_v3(row: StablecoinStateRowV3) -> Result<(), StablecoinSourceV3Error> {
    let left = u128::from(row.collateral_amount)
        .checked_mul(u128::from(row.oracle_price_numerator))
        .and_then(|value| value.checked_mul(u128::from(STABLECOIN_TRANSITION_V3_RATIO_SCALE_PPM)))
        .ok_or(StablecoinSourceV3Error::ArithmeticOverflow)?;
    let right = u128::from(row.total_debt)
        .checked_mul(u128::from(row.oracle_price_denominator))
        .and_then(|value| value.checked_mul(u128::from(row.min_collateral_ratio_ppm)))
        .ok_or(StablecoinSourceV3Error::ArithmeticOverflow)?;
    if left < right {
        return Err(StablecoinSourceV3Error::CollateralRatioViolation);
    }
    Ok(())
}

fn validate_source_row_v3(
    row: StablecoinStateRowV3,
    parent_height: u64,
) -> Result<(), StablecoinSourceV3Error> {
    if row.asset_id == 0 {
        return Err(StablecoinSourceV3Error::ZeroOrNativeAsset);
    }
    if row.policy_version == 0 {
        return Err(StablecoinSourceV3Error::ZeroPolicyVersion);
    }
    if row.issuer_commitment == [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] {
        return Err(StablecoinSourceV3Error::ZeroIssuerCommitment);
    }
    if row.policy_admin_commitment == [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]
        || row.oracle_authority_commitment == [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]
        || row.attestation_authority_commitment == [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]
        || row.locked_collateral_commitment == [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]
    {
        return Err(StablecoinSourceV3Error::ZeroAuthorityCommitment);
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
                return Err(StablecoinSourceV3Error::AuthorityCommitmentsNotDistinct);
            }
        }
    }
    if row.collateral_decimals > 18 {
        return Err(StablecoinSourceV3Error::InvalidCollateralDecimals);
    }
    let mut expected_scale = 1u64;
    for _ in 0..row.collateral_decimals {
        expected_scale = expected_scale
            .checked_mul(10)
            .ok_or(StablecoinSourceV3Error::InvalidCollateralScale)?;
    }
    if row.collateral_scale != expected_scale {
        return Err(StablecoinSourceV3Error::InvalidCollateralScale);
    }
    if row.min_collateral_ratio_ppm < STABLECOIN_TRANSITION_V3_RATIO_SCALE_PPM {
        return Err(StablecoinSourceV3Error::CollateralRatioViolation);
    }
    if row.oracle_price_numerator == 0 || row.oracle_price_denominator == 0 {
        return Err(StablecoinSourceV3Error::ZeroOraclePrice);
    }
    if row.max_mint_per_epoch > STABLECOIN_TRANSITION_V3_MAX_VALUE
        || row.collateral_amount > STABLECOIN_TRANSITION_V3_MAX_VALUE
        || row.minted_in_epoch > STABLECOIN_TRANSITION_V3_MAX_VALUE
        || row.total_debt > STABLECOIN_TRANSITION_V3_MAX_VALUE
    {
        return Err(StablecoinSourceV3Error::ValueOutOfRange);
    }
    if row.minted_in_epoch > row.max_mint_per_epoch {
        return Err(StablecoinSourceV3Error::MintedExceedsCap);
    }
    if row.epoch_id > stablecoin_current_epoch_from_parent_v3(parent_height) {
        return Err(StablecoinSourceV3Error::FutureEpoch);
    }
    if let Some(retired_at) = row.retired_at {
        if retired_at <= row.enabled_at {
            return Err(StablecoinSourceV3Error::InvalidLifecycle);
        }
        if row.active && parent_height >= retired_at {
            return Err(StablecoinSourceV3Error::PolicyRetired);
        }
    }
    if row.active && row.enabled_at > parent_height {
        return Err(StablecoinSourceV3Error::PolicyNotEnabled);
    }
    if row.oracle_submitted_at > parent_height {
        return Err(StablecoinSourceV3Error::OracleFromFuture);
    }
    if row.attestation_created_at > parent_height {
        return Err(StablecoinSourceV3Error::AttestationFromFuture);
    }
    if row.active && !row.attestation_disputed {
        if parent_height - row.oracle_submitted_at > row.oracle_max_age {
            return Err(StablecoinSourceV3Error::OracleStale);
        }
        if !row.attestation_present {
            return Err(StablecoinSourceV3Error::AttestationAbsent);
        }
        if parent_height - row.attestation_created_at > row.attestation_max_age {
            return Err(StablecoinSourceV3Error::AttestationStale);
        }
        validate_collateral_ratio_v3(row)?;
    }
    Ok(())
}

pub fn build_stablecoin_source_genesis_v3(
    parent_height: u64,
    allocation: StablecoinSourceAllocationV3,
    rows: [StablecoinStateRowV3; STABLECOIN_SOURCE_V3_CAP],
) -> Result<StablecoinSourceGenesisV3, StablecoinSourceV3Error> {
    allocation.validate()?;
    let mut canonical_rows = [StablecoinStateRowV3::ZERO; STABLECOIN_SOURCE_V3_CAP];
    let mut occupied = [false; STABLECOIN_SOURCE_V3_CAP];
    for row in rows {
        let slot = stablecoin_policy_slot_v3(row.asset_id) as usize;
        if slot >= STABLECOIN_SOURCE_V3_CAP || occupied[slot] {
            return Err(StablecoinSourceV3Error::AllocationSlotMismatch);
        }
        if row.asset_id != allocation.asset_ids[slot] {
            return Err(StablecoinSourceV3Error::GenesisAssetMismatch);
        }
        occupied[slot] = true;
        canonical_rows[slot] = row;
    }
    for (slot, row) in canonical_rows.iter().copied().enumerate() {
        if !occupied[slot] {
            return Err(StablecoinSourceV3Error::GenesisAssetMismatch);
        }
        if row.policy_version != 1 {
            return Err(StablecoinSourceV3Error::GenesisPolicyVersionMismatch);
        }
        if row.epoch_id != stablecoin_current_epoch_from_parent_v3(parent_height) {
            return Err(StablecoinSourceV3Error::GenesisEpochMismatch);
        }
        if row.minted_in_epoch != 0 || row.total_debt != 0 || row.sequence != 0 {
            return Err(StablecoinSourceV3Error::GenesisDynamicStateNonzero);
        }
        validate_source_row_v3(row, parent_height)?;
    }
    Ok(StablecoinSourceGenesisV3 {
        parent_height,
        allocation,
        rows: canonical_rows,
        allocation_commitment: stablecoin_source_allocation_commitment_v3(allocation)?,
        root: stablecoin_source_root_from_rows_v3(&canonical_rows)?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinSourceStateV3 {
    pub current_root: StablecoinTransitionRootV3,
    pub parent_height: u64,
    pub allocation: StablecoinSourceAllocationV3,
    pub allocation_commitment: StablecoinSourceDigestV3,
}

/// Consensus/deployment-owned genesis authority.  None of these fields may be
/// learned from the untrusted genesis wire being checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinSourceGenesisVerifierContextV3 {
    pub parent_height: u64,
    pub allocation: StablecoinSourceAllocationV3,
    pub expected_root: StablecoinTransitionRootV3,
}

fn require_pairwise_distinct_secrets_v3(
    secrets: [[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; 5],
) -> Result<(), StablecoinSourceV3Error> {
    for left in 0..secrets.len() {
        for right in left + 1..secrets.len() {
            if secrets[left] == secrets[right] {
                return Err(StablecoinSourceV3Error::AuthoritySecretsNotDistinct);
            }
        }
    }
    Ok(())
}

fn verify_genesis_authority_witness_v3(
    rows: &[StablecoinStateRowV3; STABLECOIN_SOURCE_V3_CAP],
    witness: StablecoinSourceGenesisAuthorityWitnessV3,
) -> Result<(), StablecoinSourceV3Error> {
    let zero = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
    for (slot, row) in rows.iter().copied().enumerate() {
        let admin = witness.policy_admin_secrets[slot];
        let issuer = witness.issuer_secrets[slot];
        let oracle = witness.oracle_secrets[slot];
        let attestation = witness.attestation_secrets[slot];
        let collateral = witness.collateral_secrets[slot];
        if admin == zero {
            return Err(StablecoinSourceV3Error::ZeroAdminSecret);
        }
        if issuer == zero {
            return Err(StablecoinSourceV3Error::ZeroIssuerSecret);
        }
        if oracle == zero {
            return Err(StablecoinSourceV3Error::ZeroOracleSecret);
        }
        if attestation == zero {
            return Err(StablecoinSourceV3Error::ZeroAttestationSecret);
        }
        if collateral == zero {
            return Err(StablecoinSourceV3Error::ZeroCollateralSecret);
        }
        require_pairwise_distinct_secrets_v3([admin, issuer, oracle, attestation, collateral])?;
        if stablecoin_policy_admin_commitment_v3(row.asset_id, &admin)
            != row.policy_admin_commitment
        {
            return Err(StablecoinSourceV3Error::OldAdminCommitmentMismatch);
        }
        if stablecoin_issuer_commitment_v3(row.asset_id, row.policy_version, &issuer)
            != row.issuer_commitment
        {
            return Err(StablecoinSourceV3Error::IssuerCommitmentMismatch);
        }
        if stablecoin_oracle_authority_commitment_v3(row, &oracle)
            != row.oracle_authority_commitment
        {
            return Err(StablecoinSourceV3Error::OracleAuthorityCommitmentMismatch);
        }
        if stablecoin_attestation_authority_commitment_v3(row, &attestation)
            != row.attestation_authority_commitment
        {
            return Err(StablecoinSourceV3Error::AttestationAuthorityCommitmentMismatch);
        }
        if stablecoin_collateral_custody_commitment_v3(row, &collateral)
            != row.locked_collateral_commitment
        {
            return Err(StablecoinSourceV3Error::CollateralCustodyCommitmentMismatch);
        }
    }
    Ok(())
}

pub fn verify_stablecoin_source_genesis_v3(
    context: StablecoinSourceGenesisVerifierContextV3,
    genesis: StablecoinSourceGenesisV3,
    authority_witness: StablecoinSourceGenesisAuthorityWitnessV3,
) -> Result<StablecoinSourceStateV3, StablecoinSourceV3Error> {
    context.allocation.validate()?;
    if genesis.parent_height != context.parent_height {
        return Err(StablecoinSourceV3Error::GenesisParentHeightMismatch);
    }
    if genesis.allocation != context.allocation {
        return Err(StablecoinSourceV3Error::GenesisAllocationMismatch);
    }
    let expected = build_stablecoin_source_genesis_v3(
        context.parent_height,
        context.allocation,
        genesis.rows,
    )?;
    if genesis.allocation_commitment != expected.allocation_commitment {
        return Err(StablecoinSourceV3Error::AllocationCommitmentMismatch);
    }
    if genesis.root != expected.root || genesis.root != context.expected_root {
        return Err(StablecoinSourceV3Error::GenesisRootMismatch);
    }
    verify_genesis_authority_witness_v3(&genesis.rows, authority_witness)?;
    Ok(StablecoinSourceStateV3 {
        current_root: genesis.root,
        parent_height: genesis.parent_height,
        allocation: genesis.allocation,
        allocation_commitment: genesis.allocation_commitment,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinSourceUpdatePublicV3 {
    pub kind: StablecoinSourceUpdateKindV3,
    /// Not a participant set: old policy-admin authentication is unconditional.
    /// See the authority-bit constants for the exact auxiliary/rotation meaning.
    pub auxiliary_authority_mask: u8,
    pub slot: u32,
    pub asset_id: u32,
    pub before_policy_version: u32,
    pub after_policy_version: u32,
    pub parent_height: u64,
    pub update_intent: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    pub allocation_commitment: StablecoinSourceDigestV3,
    pub before_root: StablecoinTransitionRootV3,
    pub after_root: StablecoinTransitionRootV3,
    pub after_row: StablecoinStateRowV3,
    pub admin_authorization: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
}

impl StablecoinSourceUpdatePublicV3 {
    pub fn encode_canonical(self) -> [u8; STABLECOIN_SOURCE_V3_UPDATE_PUBLIC_BYTES] {
        let mut output = [0u8; STABLECOIN_SOURCE_V3_UPDATE_PUBLIC_BYTES];
        output[..8].copy_from_slice(&STABLECOIN_SOURCE_V3_UPDATE_PUBLIC_MAGIC);
        output[8..10].copy_from_slice(&STABLECOIN_SOURCE_V3_VERSION.to_le_bytes());
        output[10] = self.kind as u8;
        output[11] = self.auxiliary_authority_mask;
        output[12..16].copy_from_slice(&self.slot.to_le_bytes());
        output[16..20].copy_from_slice(&self.asset_id.to_le_bytes());
        output[20..24].copy_from_slice(&self.before_policy_version.to_le_bytes());
        output[24..28].copy_from_slice(&self.after_policy_version.to_le_bytes());
        output[28..36].copy_from_slice(&self.parent_height.to_le_bytes());
        output[36..100].copy_from_slice(&self.update_intent);
        output[100..164].copy_from_slice(self.allocation_commitment.as_bytes());
        output[164..228].copy_from_slice(self.before_root.as_bytes());
        output[228..292].copy_from_slice(self.after_root.as_bytes());
        output[292..745].copy_from_slice(&self.after_row.encode_canonical());
        output[745..809].copy_from_slice(&self.admin_authorization);
        output
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinSourceV3Error> {
        let raw: &[u8; STABLECOIN_SOURCE_V3_UPDATE_PUBLIC_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinSourceV3Error::WrongLength)?;
        if raw[..8] != STABLECOIN_SOURCE_V3_UPDATE_PUBLIC_MAGIC {
            return Err(StablecoinSourceV3Error::WrongMagic);
        }
        if u16::from_le_bytes(raw[8..10].try_into().expect("fixed slice"))
            != STABLECOIN_SOURCE_V3_VERSION
        {
            return Err(StablecoinSourceV3Error::WrongVersion);
        }
        let kind = StablecoinSourceUpdateKindV3::try_from(raw[10])?;
        let slot = u32::from_le_bytes(raw[12..16].try_into().expect("fixed slice"));
        if slot as usize >= STABLECOIN_SOURCE_V3_CAP {
            return Err(StablecoinSourceV3Error::IndexOutOfRange);
        }
        let mut update_intent = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
        update_intent.copy_from_slice(&raw[36..100]);
        let mut allocation_commitment = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
        allocation_commitment.copy_from_slice(&raw[100..164]);
        let mut before_root = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
        before_root.copy_from_slice(&raw[164..228]);
        let mut after_root = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
        after_root.copy_from_slice(&raw[228..292]);
        let after_row = StablecoinStateRowV3::decode_canonical(&raw[292..745])
            .map_err(|_| StablecoinSourceV3Error::WrongLength)?;
        let mut admin_authorization = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
        admin_authorization.copy_from_slice(&raw[745..809]);
        let decoded = Self {
            kind,
            auxiliary_authority_mask: raw[11],
            slot,
            asset_id: u32::from_le_bytes(raw[16..20].try_into().expect("fixed slice")),
            before_policy_version: u32::from_le_bytes(raw[20..24].try_into().expect("fixed slice")),
            after_policy_version: u32::from_le_bytes(raw[24..28].try_into().expect("fixed slice")),
            parent_height: u64::from_le_bytes(raw[28..36].try_into().expect("fixed slice")),
            update_intent,
            allocation_commitment: StablecoinSourceDigestV3::new(allocation_commitment),
            before_root: StablecoinTransitionRootV3::new(before_root),
            after_root: StablecoinTransitionRootV3::new(after_root),
            after_row,
            admin_authorization,
        };
        validate_update_mask_v3(decoded.kind, decoded.auxiliary_authority_mask)?;
        if decoded.encode_canonical() != *raw {
            return Err(StablecoinSourceV3Error::WrongLength);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinSourceUpdateWitnessV3 {
    pub slot: u32,
    pub before_row: StablecoinStateRowV3,
    pub siblings: [StablecoinTransitionRootV3; STABLECOIN_SOURCE_V3_DEPTH],
    pub old_admin_secret: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    pub new_admin_secret: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    pub old_issuer_secret: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    pub new_issuer_secret: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    pub old_oracle_secret: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    pub new_oracle_secret: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    pub old_attestation_secret: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    pub new_attestation_secret: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    pub old_collateral_secret: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    pub new_collateral_secret: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
}

impl StablecoinSourceUpdateWitnessV3 {
    pub fn before_membership(self) -> StablecoinStateMembershipProofV3 {
        StablecoinStateMembershipProofV3 {
            index: self.slot,
            row: self.before_row,
            siblings: self.siblings,
        }
    }

    pub fn after_membership(
        self,
        after_row: StablecoinStateRowV3,
    ) -> StablecoinStateMembershipProofV3 {
        StablecoinStateMembershipProofV3 {
            index: self.slot,
            row: after_row,
            siblings: self.siblings,
        }
    }

    pub fn encode_canonical(
        self,
    ) -> Result<[u8; STABLECOIN_SOURCE_V3_UPDATE_WITNESS_BYTES], StablecoinSourceV3Error> {
        if self.slot as usize >= STABLECOIN_SOURCE_V3_CAP {
            return Err(StablecoinSourceV3Error::IndexOutOfRange);
        }
        let mut output = [0u8; STABLECOIN_SOURCE_V3_UPDATE_WITNESS_BYTES];
        output[..8].copy_from_slice(&STABLECOIN_SOURCE_V3_UPDATE_WITNESS_MAGIC);
        output[8..10].copy_from_slice(&STABLECOIN_SOURCE_V3_VERSION.to_le_bytes());
        output[10..14].copy_from_slice(&self.slot.to_le_bytes());
        output[14..14 + STABLECOIN_TRANSITION_V3_ROW_BYTES]
            .copy_from_slice(&self.before_row.encode_canonical());
        let mut cursor = 14 + STABLECOIN_TRANSITION_V3_ROW_BYTES;
        for sibling in self.siblings {
            output[cursor..cursor + STABLECOIN_SOURCE_V3_DIGEST_BYTES]
                .copy_from_slice(sibling.as_bytes());
            cursor += STABLECOIN_SOURCE_V3_DIGEST_BYTES;
        }
        for secret in [
            self.old_admin_secret,
            self.new_admin_secret,
            self.old_issuer_secret,
            self.new_issuer_secret,
            self.old_oracle_secret,
            self.new_oracle_secret,
            self.old_attestation_secret,
            self.new_attestation_secret,
            self.old_collateral_secret,
            self.new_collateral_secret,
        ] {
            output[cursor..cursor + STABLECOIN_SOURCE_V3_DIGEST_BYTES].copy_from_slice(&secret);
            cursor += STABLECOIN_SOURCE_V3_DIGEST_BYTES;
        }
        Ok(output)
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinSourceV3Error> {
        let raw: &[u8; STABLECOIN_SOURCE_V3_UPDATE_WITNESS_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinSourceV3Error::WrongLength)?;
        if raw[..8] != STABLECOIN_SOURCE_V3_UPDATE_WITNESS_MAGIC {
            return Err(StablecoinSourceV3Error::WrongMagic);
        }
        if u16::from_le_bytes(raw[8..10].try_into().expect("fixed slice"))
            != STABLECOIN_SOURCE_V3_VERSION
        {
            return Err(StablecoinSourceV3Error::WrongVersion);
        }
        let slot = u32::from_le_bytes(raw[10..14].try_into().expect("fixed slice"));
        if slot as usize >= STABLECOIN_SOURCE_V3_CAP {
            return Err(StablecoinSourceV3Error::IndexOutOfRange);
        }
        let before_row = StablecoinStateRowV3::decode_canonical(
            &raw[14..14 + STABLECOIN_TRANSITION_V3_ROW_BYTES],
        )
        .map_err(|_| StablecoinSourceV3Error::WrongLength)?;
        let mut cursor = 14 + STABLECOIN_TRANSITION_V3_ROW_BYTES;
        let mut siblings = [StablecoinTransitionRootV3::ZERO; STABLECOIN_SOURCE_V3_DEPTH];
        for sibling in &mut siblings {
            let mut bytes = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
            bytes.copy_from_slice(&raw[cursor..cursor + STABLECOIN_SOURCE_V3_DIGEST_BYTES]);
            *sibling = StablecoinTransitionRootV3::new(bytes);
            cursor += STABLECOIN_SOURCE_V3_DIGEST_BYTES;
        }
        let mut secrets = [[0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]; 10];
        for secret in &mut secrets {
            secret.copy_from_slice(&raw[cursor..cursor + STABLECOIN_SOURCE_V3_DIGEST_BYTES]);
            cursor += STABLECOIN_SOURCE_V3_DIGEST_BYTES;
        }
        let decoded = Self {
            slot,
            before_row,
            siblings,
            old_admin_secret: secrets[0],
            new_admin_secret: secrets[1],
            old_issuer_secret: secrets[2],
            new_issuer_secret: secrets[3],
            old_oracle_secret: secrets[4],
            new_oracle_secret: secrets[5],
            old_attestation_secret: secrets[6],
            new_attestation_secret: secrets[7],
            old_collateral_secret: secrets[8],
            new_collateral_secret: secrets[9],
        };
        if decoded.encode_canonical()? != *raw {
            return Err(StablecoinSourceV3Error::WrongLength);
        }
        Ok(decoded)
    }
}

/// Validate the auxiliary/update mask. The old policy-admin role is not encoded
/// here because its opening and exact authorization tag are mandatory for every
/// kind; for example, PolicyUpgrade's exact auxiliary mask is ISSUER, meaning
/// the actual participating roles are policy admin plus issuer.
fn validate_update_mask_v3(
    kind: StablecoinSourceUpdateKindV3,
    auxiliary_authority_mask: u8,
) -> Result<(), StablecoinSourceV3Error> {
    if auxiliary_authority_mask & !STABLECOIN_SOURCE_V3_AUTHORITY_ALL != 0 {
        return Err(StablecoinSourceV3Error::InvalidAuthorityMask);
    }
    let valid = match kind {
        StablecoinSourceUpdateKindV3::OracleRefresh => {
            auxiliary_authority_mask == STABLECOIN_SOURCE_V3_AUTHORITY_ORACLE
        }
        StablecoinSourceUpdateKindV3::AttestationRefresh => {
            auxiliary_authority_mask == STABLECOIN_SOURCE_V3_AUTHORITY_ATTESTATION
        }
        StablecoinSourceUpdateKindV3::CollateralSync => {
            auxiliary_authority_mask == STABLECOIN_SOURCE_V3_AUTHORITY_COLLATERAL
        }
        StablecoinSourceUpdateKindV3::PolicyUpgrade => {
            auxiliary_authority_mask == STABLECOIN_SOURCE_V3_AUTHORITY_ISSUER
        }
        StablecoinSourceUpdateKindV3::AuthorityRotation => auxiliary_authority_mask != 0,
        StablecoinSourceUpdateKindV3::Retire | StablecoinSourceUpdateKindV3::Activate => {
            auxiliary_authority_mask == 0
        }
    };
    if !valid {
        return Err(StablecoinSourceV3Error::InvalidAuthorityMask);
    }
    Ok(())
}

pub fn stablecoin_source_admin_authorization_v3(
    public: StablecoinSourceUpdatePublicV3,
    before_row: StablecoinStateRowV3,
    old_admin_secret: &[u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
) -> [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] {
    let public_wire = public.encode_canonical();
    let mut preimage = [0u8; STABLECOIN_SOURCE_V3_ADMIN_AUTHORIZATION_PREIMAGE_BYTES];
    preimage[..745].copy_from_slice(&public_wire[..745]);
    preimage[745..745 + STABLECOIN_TRANSITION_V3_ROW_BYTES]
        .copy_from_slice(&before_row.encode_canonical());
    preimage[745 + STABLECOIN_TRANSITION_V3_ROW_BYTES..].copy_from_slice(old_admin_secret);
    blake2b512_personalized_v2(
        &preimage,
        source_personalization(ROLE_ADMIN_AUTHORIZATION, 0),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinSourceVerifierContextV3 {
    pub current_root: StablecoinTransitionRootV3,
    pub parent_height: u64,
    pub allocation: StablecoinSourceAllocationV3,
    /// Must be obtained from a separately framed, authenticated outer parser.
    pub expected_update_intent: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedStablecoinSourceUpdateV3 {
    pub kind: StablecoinSourceUpdateKindV3,
    pub slot: u32,
    pub asset_id: u32,
    pub before_root: StablecoinTransitionRootV3,
    pub after_root: StablecoinTransitionRootV3,
    pub after_policy_version: u32,
    pub after_sequence: u64,
}

fn require_zero_pair_v3(
    old: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    new: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
) -> Result<(), StablecoinSourceV3Error> {
    if old != [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]
        || new != [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES]
    {
        return Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness);
    }
    Ok(())
}

fn validate_exact_delta_v3(
    kind: StablecoinSourceUpdateKindV3,
    auxiliary_authority_mask: u8,
    parent_height: u64,
    before: StablecoinStateRowV3,
    after: StablecoinStateRowV3,
) -> Result<(), StablecoinSourceV3Error> {
    if before.asset_id != after.asset_id {
        return Err(StablecoinSourceV3Error::ImmutableAssetMutation);
    }
    if before.epoch_id != after.epoch_id
        || before.minted_in_epoch != after.minted_in_epoch
        || before.total_debt != after.total_debt
    {
        return Err(StablecoinSourceV3Error::DynamicAccountingMutation);
    }
    let expected_sequence = before
        .sequence
        .checked_add(1)
        .ok_or(StablecoinSourceV3Error::SequenceOverflow)?;
    if after.sequence != expected_sequence {
        return Err(StablecoinSourceV3Error::SequenceSuccessorMismatch);
    }
    let version_increments = matches!(
        kind,
        StablecoinSourceUpdateKindV3::PolicyUpgrade
            | StablecoinSourceUpdateKindV3::AuthorityRotation
    );
    let expected_version = if version_increments {
        before
            .policy_version
            .checked_add(1)
            .ok_or(StablecoinSourceV3Error::PolicyVersionOverflow)?
    } else {
        before.policy_version
    };
    if after.policy_version != expected_version {
        return Err(StablecoinSourceV3Error::PolicyVersionSuccessorMismatch);
    }

    let mut allowed = before;
    allowed.sequence = after.sequence;
    allowed.policy_version = after.policy_version;
    match kind {
        StablecoinSourceUpdateKindV3::OracleRefresh => {
            if after.oracle_submitted_at <= before.oracle_submitted_at {
                return Err(StablecoinSourceV3Error::OracleTimestampRegression);
            }
            allowed.oracle_submitted_at = after.oracle_submitted_at;
            allowed.oracle_price_numerator = after.oracle_price_numerator;
            allowed.oracle_price_denominator = after.oracle_price_denominator;
            if before.oracle_price_numerator == after.oracle_price_numerator
                && before.oracle_price_denominator == after.oracle_price_denominator
            {
                return Err(StablecoinSourceV3Error::RequiredFieldUnchanged);
            }
        }
        StablecoinSourceUpdateKindV3::AttestationRefresh => {
            if after.attestation_created_at < before.attestation_created_at {
                return Err(StablecoinSourceV3Error::AttestationTimestampRegression);
            }
            allowed.attestation_created_at = after.attestation_created_at;
            allowed.attestation_present = after.attestation_present;
            allowed.attestation_disputed = after.attestation_disputed;
            if before.attestation_created_at == after.attestation_created_at
                && before.attestation_present == after.attestation_present
                && before.attestation_disputed == after.attestation_disputed
            {
                return Err(StablecoinSourceV3Error::RequiredFieldUnchanged);
            }
        }
        StablecoinSourceUpdateKindV3::CollateralSync => {
            allowed.collateral_asset_id = after.collateral_asset_id;
            allowed.collateral_decimals = after.collateral_decimals;
            allowed.collateral_scale = after.collateral_scale;
            allowed.collateral_amount = after.collateral_amount;
            allowed.locked_collateral_commitment = after.locked_collateral_commitment;
            if before.collateral_asset_id == after.collateral_asset_id
                && before.collateral_decimals == after.collateral_decimals
                && before.collateral_scale == after.collateral_scale
                && before.collateral_amount == after.collateral_amount
                && before.locked_collateral_commitment == after.locked_collateral_commitment
            {
                return Err(StablecoinSourceV3Error::RequiredFieldUnchanged);
            }
        }
        StablecoinSourceUpdateKindV3::PolicyUpgrade => {
            allowed.min_collateral_ratio_ppm = after.min_collateral_ratio_ppm;
            allowed.max_mint_per_epoch = after.max_mint_per_epoch;
            allowed.oracle_max_age = after.oracle_max_age;
            allowed.attestation_max_age = after.attestation_max_age;
            allowed.issuer_commitment = after.issuer_commitment;
            if before.min_collateral_ratio_ppm == after.min_collateral_ratio_ppm
                && before.max_mint_per_epoch == after.max_mint_per_epoch
                && before.oracle_max_age == after.oracle_max_age
                && before.attestation_max_age == after.attestation_max_age
            {
                return Err(StablecoinSourceV3Error::RequiredFieldUnchanged);
            }
        }
        StablecoinSourceUpdateKindV3::AuthorityRotation => {
            // The issuer commitment is version-bound, so every rotation must
            // rebind it under the successor version even when the issuer key
            // itself is not selected for rotation.
            allowed.issuer_commitment = after.issuer_commitment;
            if auxiliary_authority_mask & STABLECOIN_SOURCE_V3_AUTHORITY_ADMIN != 0 {
                allowed.policy_admin_commitment = after.policy_admin_commitment;
            }
            if auxiliary_authority_mask & STABLECOIN_SOURCE_V3_AUTHORITY_ORACLE != 0 {
                allowed.oracle_authority_commitment = after.oracle_authority_commitment;
            }
            if auxiliary_authority_mask & STABLECOIN_SOURCE_V3_AUTHORITY_ATTESTATION != 0 {
                allowed.attestation_authority_commitment = after.attestation_authority_commitment;
            }
            if auxiliary_authority_mask & STABLECOIN_SOURCE_V3_AUTHORITY_COLLATERAL != 0 {
                allowed.locked_collateral_commitment = after.locked_collateral_commitment;
            }
        }
        StablecoinSourceUpdateKindV3::Retire => {
            if !before.active {
                return Err(StablecoinSourceV3Error::InvalidRetirement);
            }
            allowed.active = false;
            allowed.retired_at = match before.retired_at {
                None => Some(parent_height),
                Some(retired_at) if parent_height >= retired_at => Some(retired_at),
                Some(_) => return Err(StablecoinSourceV3Error::InvalidRetirement),
            };
        }
        StablecoinSourceUpdateKindV3::Activate => {
            if before.active || before.retired_at.is_some() {
                return Err(StablecoinSourceV3Error::InvalidActivation);
            }
            allowed.active = true;
            allowed.enabled_at = parent_height;
        }
    }
    if allowed != after {
        return Err(StablecoinSourceV3Error::ForbiddenFieldMutation);
    }
    Ok(())
}

fn validate_opened_secret_distinctness_v3(
    public: StablecoinSourceUpdatePublicV3,
    witness: StablecoinSourceUpdateWitnessV3,
) -> Result<(), StablecoinSourceV3Error> {
    let zero = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
    let issuer_opened = public.kind == StablecoinSourceUpdateKindV3::PolicyUpgrade
        || public.kind == StablecoinSourceUpdateKindV3::AuthorityRotation;
    let oracle_opened = public.kind == StablecoinSourceUpdateKindV3::OracleRefresh
        || public.kind == StablecoinSourceUpdateKindV3::AuthorityRotation;
    let attestation_opened = public.kind == StablecoinSourceUpdateKindV3::AttestationRefresh
        || public.kind == StablecoinSourceUpdateKindV3::AuthorityRotation;
    let collateral_opened = public.kind == StablecoinSourceUpdateKindV3::CollateralSync
        || public.kind == StablecoinSourceUpdateKindV3::AuthorityRotation;
    let old = [
        witness.old_admin_secret,
        if issuer_opened {
            witness.old_issuer_secret
        } else {
            zero
        },
        if oracle_opened {
            witness.old_oracle_secret
        } else {
            zero
        },
        if attestation_opened {
            witness.old_attestation_secret
        } else {
            zero
        },
        if collateral_opened {
            witness.old_collateral_secret
        } else {
            zero
        },
    ];
    let new = [
        witness.new_admin_secret,
        if issuer_opened {
            witness.new_issuer_secret
        } else {
            zero
        },
        if oracle_opened {
            witness.new_oracle_secret
        } else {
            zero
        },
        if attestation_opened {
            witness.new_attestation_secret
        } else {
            zero
        },
        if collateral_opened {
            witness.new_collateral_secret
        } else {
            zero
        },
    ];
    for secrets in [old, new] {
        for left in 0..secrets.len() {
            if secrets[left] == zero {
                continue;
            }
            for right in left + 1..secrets.len() {
                if secrets[right] != zero && secrets[left] == secrets[right] {
                    return Err(StablecoinSourceV3Error::AuthoritySecretsNotDistinct);
                }
            }
        }
    }
    Ok(())
}

fn validate_authority_openings_v3(
    public: StablecoinSourceUpdatePublicV3,
    witness: StablecoinSourceUpdateWitnessV3,
) -> Result<(), StablecoinSourceV3Error> {
    let zero = [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES];
    validate_opened_secret_distinctness_v3(public, witness)?;
    if witness.old_admin_secret == zero {
        return Err(StablecoinSourceV3Error::ZeroAdminSecret);
    }
    if witness.new_admin_secret == zero {
        return Err(StablecoinSourceV3Error::ZeroNewAdminSecret);
    }
    if stablecoin_policy_admin_commitment_v3(witness.before_row.asset_id, &witness.old_admin_secret)
        != witness.before_row.policy_admin_commitment
    {
        return Err(StablecoinSourceV3Error::OldAdminCommitmentMismatch);
    }
    if stablecoin_policy_admin_commitment_v3(public.after_row.asset_id, &witness.new_admin_secret)
        != public.after_row.policy_admin_commitment
    {
        return Err(StablecoinSourceV3Error::NewAdminCommitmentMismatch);
    }
    let admin_rotates = public.kind == StablecoinSourceUpdateKindV3::AuthorityRotation
        && public.auxiliary_authority_mask & STABLECOIN_SOURCE_V3_AUTHORITY_ADMIN != 0;
    if admin_rotates {
        if witness.old_admin_secret == witness.new_admin_secret
            || witness.before_row.policy_admin_commitment
                == public.after_row.policy_admin_commitment
        {
            return Err(StablecoinSourceV3Error::RequiredFieldUnchanged);
        }
    } else if witness.old_admin_secret != witness.new_admin_secret
        || witness.before_row.policy_admin_commitment != public.after_row.policy_admin_commitment
    {
        return Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness);
    }

    let issuer_required = public.kind == StablecoinSourceUpdateKindV3::PolicyUpgrade
        || public.kind == StablecoinSourceUpdateKindV3::AuthorityRotation;
    if issuer_required {
        if witness.old_issuer_secret == zero || witness.new_issuer_secret == zero {
            return Err(StablecoinSourceV3Error::ZeroIssuerSecret);
        }
        if stablecoin_issuer_commitment_v3(
            witness.before_row.asset_id,
            witness.before_row.policy_version,
            &witness.old_issuer_secret,
        ) != witness.before_row.issuer_commitment
            || stablecoin_issuer_commitment_v3(
                public.after_row.asset_id,
                public.after_row.policy_version,
                &witness.new_issuer_secret,
            ) != public.after_row.issuer_commitment
        {
            return Err(StablecoinSourceV3Error::IssuerCommitmentMismatch);
        }
        match public.kind {
            StablecoinSourceUpdateKindV3::PolicyUpgrade
                if witness.old_issuer_secret != witness.new_issuer_secret =>
            {
                return Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness);
            }
            StablecoinSourceUpdateKindV3::AuthorityRotation => {
                let issuer_rotates =
                    public.auxiliary_authority_mask & STABLECOIN_SOURCE_V3_AUTHORITY_ISSUER != 0;
                if issuer_rotates && witness.old_issuer_secret == witness.new_issuer_secret {
                    return Err(StablecoinSourceV3Error::RequiredFieldUnchanged);
                }
                if !issuer_rotates && witness.old_issuer_secret != witness.new_issuer_secret {
                    return Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness);
                }
            }
            _ => {}
        }
    } else {
        require_zero_pair_v3(witness.old_issuer_secret, witness.new_issuer_secret)?;
    }

    let oracle_required = public.kind == StablecoinSourceUpdateKindV3::OracleRefresh
        || public.kind == StablecoinSourceUpdateKindV3::AuthorityRotation;
    if oracle_required {
        if witness.old_oracle_secret == zero || witness.new_oracle_secret == zero {
            return Err(StablecoinSourceV3Error::ZeroOracleSecret);
        }
        if stablecoin_oracle_authority_commitment_v3(witness.before_row, &witness.old_oracle_secret)
            != witness.before_row.oracle_authority_commitment
            || stablecoin_oracle_authority_commitment_v3(
                public.after_row,
                &witness.new_oracle_secret,
            ) != public.after_row.oracle_authority_commitment
        {
            return Err(StablecoinSourceV3Error::OracleAuthorityCommitmentMismatch);
        }
        match public.kind {
            StablecoinSourceUpdateKindV3::OracleRefresh
                if witness.old_oracle_secret != witness.new_oracle_secret =>
            {
                return Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness);
            }
            StablecoinSourceUpdateKindV3::AuthorityRotation => {
                let rotates =
                    public.auxiliary_authority_mask & STABLECOIN_SOURCE_V3_AUTHORITY_ORACLE != 0;
                let secret_changed = witness.old_oracle_secret != witness.new_oracle_secret;
                let commitment_changed = witness.before_row.oracle_authority_commitment
                    != public.after_row.oracle_authority_commitment;
                if rotates && (!secret_changed || !commitment_changed) {
                    return Err(StablecoinSourceV3Error::RequiredFieldUnchanged);
                }
                if !rotates && (secret_changed || commitment_changed) {
                    return Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness);
                }
            }
            _ => {}
        }
    } else {
        require_zero_pair_v3(witness.old_oracle_secret, witness.new_oracle_secret)?;
    }

    let attestation_required = public.kind == StablecoinSourceUpdateKindV3::AttestationRefresh
        || public.kind == StablecoinSourceUpdateKindV3::AuthorityRotation;
    if attestation_required {
        if witness.old_attestation_secret == zero || witness.new_attestation_secret == zero {
            return Err(StablecoinSourceV3Error::ZeroAttestationSecret);
        }
        if stablecoin_attestation_authority_commitment_v3(
            witness.before_row,
            &witness.old_attestation_secret,
        ) != witness.before_row.attestation_authority_commitment
            || stablecoin_attestation_authority_commitment_v3(
                public.after_row,
                &witness.new_attestation_secret,
            ) != public.after_row.attestation_authority_commitment
        {
            return Err(StablecoinSourceV3Error::AttestationAuthorityCommitmentMismatch);
        }
        match public.kind {
            StablecoinSourceUpdateKindV3::AttestationRefresh
                if witness.old_attestation_secret != witness.new_attestation_secret =>
            {
                return Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness);
            }
            StablecoinSourceUpdateKindV3::AuthorityRotation => {
                let rotates = public.auxiliary_authority_mask
                    & STABLECOIN_SOURCE_V3_AUTHORITY_ATTESTATION
                    != 0;
                let secret_changed =
                    witness.old_attestation_secret != witness.new_attestation_secret;
                let commitment_changed = witness.before_row.attestation_authority_commitment
                    != public.after_row.attestation_authority_commitment;
                if rotates && (!secret_changed || !commitment_changed) {
                    return Err(StablecoinSourceV3Error::RequiredFieldUnchanged);
                }
                if !rotates && (secret_changed || commitment_changed) {
                    return Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness);
                }
            }
            _ => {}
        }
    } else {
        require_zero_pair_v3(
            witness.old_attestation_secret,
            witness.new_attestation_secret,
        )?;
    }

    let collateral_required = public.kind == StablecoinSourceUpdateKindV3::CollateralSync
        || public.kind == StablecoinSourceUpdateKindV3::AuthorityRotation;
    if collateral_required {
        if witness.old_collateral_secret == zero || witness.new_collateral_secret == zero {
            return Err(StablecoinSourceV3Error::ZeroCollateralSecret);
        }
        if stablecoin_collateral_custody_commitment_v3(
            witness.before_row,
            &witness.old_collateral_secret,
        ) != witness.before_row.locked_collateral_commitment
            || stablecoin_collateral_custody_commitment_v3(
                public.after_row,
                &witness.new_collateral_secret,
            ) != public.after_row.locked_collateral_commitment
        {
            return Err(StablecoinSourceV3Error::CollateralCustodyCommitmentMismatch);
        }
        match public.kind {
            StablecoinSourceUpdateKindV3::CollateralSync
                if witness.old_collateral_secret != witness.new_collateral_secret =>
            {
                return Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness);
            }
            StablecoinSourceUpdateKindV3::AuthorityRotation => {
                let rotates = public.auxiliary_authority_mask
                    & STABLECOIN_SOURCE_V3_AUTHORITY_COLLATERAL
                    != 0;
                let secret_changed = witness.old_collateral_secret != witness.new_collateral_secret;
                let commitment_changed = witness.before_row.locked_collateral_commitment
                    != public.after_row.locked_collateral_commitment;
                if rotates && (!secret_changed || !commitment_changed) {
                    return Err(StablecoinSourceV3Error::RequiredFieldUnchanged);
                }
                if !rotates && (secret_changed || commitment_changed) {
                    return Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness);
                }
            }
            _ => {}
        }
    } else {
        require_zero_pair_v3(witness.old_collateral_secret, witness.new_collateral_secret)?;
    }
    Ok(())
}

pub fn verify_stablecoin_source_update_v3(
    context: StablecoinSourceVerifierContextV3,
    public: StablecoinSourceUpdatePublicV3,
    witness: StablecoinSourceUpdateWitnessV3,
) -> Result<VerifiedStablecoinSourceUpdateV3, StablecoinSourceV3Error> {
    context.allocation.validate()?;
    validate_update_mask_v3(public.kind, public.auxiliary_authority_mask)?;
    if public.parent_height != context.parent_height {
        return Err(StablecoinSourceV3Error::ParentHeightMismatch);
    }
    if public.update_intent == [0u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] {
        return Err(StablecoinSourceV3Error::ZeroUpdateIntent);
    }
    if public.update_intent != context.expected_update_intent {
        return Err(StablecoinSourceV3Error::UpdateIntentMismatch);
    }
    let allocation_commitment = stablecoin_source_allocation_commitment_v3(context.allocation)?;
    if public.allocation_commitment != allocation_commitment {
        return Err(StablecoinSourceV3Error::AllocationCommitmentMismatch);
    }
    if public.slot as usize >= STABLECOIN_SOURCE_V3_CAP
        || witness.slot as usize >= STABLECOIN_SOURCE_V3_CAP
    {
        return Err(StablecoinSourceV3Error::IndexOutOfRange);
    }
    if public.slot != witness.slot {
        return Err(StablecoinSourceV3Error::PublicSlotMismatch);
    }
    let allocated_asset = context.allocation.asset_ids[public.slot as usize];
    if public.asset_id != allocated_asset
        || public.asset_id != witness.before_row.asset_id
        || public.asset_id != public.after_row.asset_id
    {
        return Err(StablecoinSourceV3Error::PublicAssetMismatch);
    }
    if stablecoin_policy_slot_v3(public.asset_id) != public.slot {
        return Err(StablecoinSourceV3Error::AllocationSlotMismatch);
    }
    if public.before_policy_version != witness.before_row.policy_version
        || public.after_policy_version != public.after_row.policy_version
    {
        return Err(StablecoinSourceV3Error::PublicPolicyVersionMismatch);
    }
    if public.before_root != context.current_root {
        return Err(StablecoinSourceV3Error::ContextRootMismatch);
    }
    let before_root = stablecoin_transition_root_from_membership_v3(witness.before_membership())
        .map_err(|_| StablecoinSourceV3Error::IndexOutOfRange)?;
    if before_root != public.before_root {
        return Err(StablecoinSourceV3Error::BeforeMembershipRootMismatch);
    }
    let after_root =
        stablecoin_transition_root_from_membership_v3(witness.after_membership(public.after_row))
            .map_err(|_| StablecoinSourceV3Error::IndexOutOfRange)?;
    if after_root != public.after_root {
        return Err(StablecoinSourceV3Error::AfterMembershipRootMismatch);
    }
    validate_exact_delta_v3(
        public.kind,
        public.auxiliary_authority_mask,
        context.parent_height,
        witness.before_row,
        public.after_row,
    )?;
    validate_authority_openings_v3(public, witness)?;
    validate_source_row_v3(public.after_row, context.parent_height)?;
    if stablecoin_source_admin_authorization_v3(
        public,
        witness.before_row,
        &witness.old_admin_secret,
    ) != public.admin_authorization
    {
        return Err(StablecoinSourceV3Error::AdminAuthorizationMismatch);
    }
    Ok(VerifiedStablecoinSourceUpdateV3 {
        kind: public.kind,
        slot: public.slot,
        asset_id: public.asset_id,
        before_root,
        after_root,
        after_policy_version: public.after_policy_version,
        after_sequence: public.after_row.sequence,
    })
}

pub fn apply_stablecoin_source_update_v3(
    state: &mut StablecoinSourceStateV3,
    expected_update_intent: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES],
    public: StablecoinSourceUpdatePublicV3,
    witness: StablecoinSourceUpdateWitnessV3,
) -> Result<VerifiedStablecoinSourceUpdateV3, StablecoinSourceV3Error> {
    let verified = verify_stablecoin_source_update_v3(
        StablecoinSourceVerifierContextV3 {
            current_root: state.current_root,
            parent_height: state.parent_height,
            allocation: state.allocation,
            expected_update_intent,
        },
        public,
        witness,
    )?;
    state.current_root = verified.after_root;
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARENT_HEIGHT: u64 = (5 << 12) + 77;
    const OUTER_INTENT: [u8; STABLECOIN_SOURCE_V3_DIGEST_BYTES] =
        [0xa7; STABLECOIN_SOURCE_V3_DIGEST_BYTES];

    #[derive(Clone, Copy)]
    struct AuthoritySecrets {
        admin: [u8; 64],
        issuer: [u8; 64],
        oracle: [u8; 64],
        attestation: [u8; 64],
        collateral: [u8; 64],
    }

    #[derive(Clone, Copy)]
    struct OpeningPairs {
        old_admin: [u8; 64],
        new_admin: [u8; 64],
        old_issuer: [u8; 64],
        new_issuer: [u8; 64],
        old_oracle: [u8; 64],
        new_oracle: [u8; 64],
        old_attestation: [u8; 64],
        new_attestation: [u8; 64],
        old_collateral: [u8; 64],
        new_collateral: [u8; 64],
    }

    impl OpeningPairs {
        fn admin_only(admin: [u8; 64]) -> Self {
            Self {
                old_admin: admin,
                new_admin: admin,
                old_issuer: [0u8; 64],
                new_issuer: [0u8; 64],
                old_oracle: [0u8; 64],
                new_oracle: [0u8; 64],
                old_attestation: [0u8; 64],
                new_attestation: [0u8; 64],
                old_collateral: [0u8; 64],
                new_collateral: [0u8; 64],
            }
        }
    }

    fn authority_secrets(slot: usize) -> AuthoritySecrets {
        AuthoritySecrets {
            admin: [(0x10 + slot) as u8; 64],
            issuer: [(0x30 + slot) as u8; 64],
            oracle: [(0x50 + slot) as u8; 64],
            attestation: [(0x70 + slot) as u8; 64],
            collateral: [(0x90 + slot) as u8; 64],
        }
    }

    fn allocation() -> StablecoinSourceAllocationV3 {
        StablecoinSourceAllocationV3 {
            asset_ids: core::array::from_fn(|slot| 16 + slot as u32),
        }
    }

    fn row_for_slot(slot: usize, active: bool) -> StablecoinStateRowV3 {
        let asset_id = allocation().asset_ids[slot];
        let secrets = authority_secrets(slot);
        let mut row = StablecoinStateRowV3 {
            asset_id,
            policy_version: 1,
            active,
            enabled_at: 0,
            retired_at: None,
            issuer_commitment: stablecoin_issuer_commitment_v3(asset_id, 1, &secrets.issuer),
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000,
            oracle_submitted_at: PARENT_HEIGHT - 5,
            oracle_max_age: 100,
            oracle_price_numerator: 3,
            oracle_price_denominator: 2,
            collateral_amount: 1_000,
            attestation_created_at: PARENT_HEIGHT - 5,
            attestation_disputed: false,
            attestation_present: true,
            attestation_max_age: 100,
            policy_admin_commitment: stablecoin_policy_admin_commitment_v3(
                asset_id,
                &secrets.admin,
            ),
            oracle_authority_commitment: [0u8; 64],
            attestation_authority_commitment: [0u8; 64],
            collateral_asset_id: 0,
            collateral_decimals: 8,
            collateral_scale: 100_000_000,
            locked_collateral_commitment: [0u8; 64],
            epoch_id: stablecoin_current_epoch_from_parent_v3(PARENT_HEIGHT),
            minted_in_epoch: 0,
            total_debt: 0,
            sequence: 0,
        };
        row.oracle_authority_commitment =
            stablecoin_oracle_authority_commitment_v3(row, &secrets.oracle);
        row.attestation_authority_commitment =
            stablecoin_attestation_authority_commitment_v3(row, &secrets.attestation);
        row.locked_collateral_commitment =
            stablecoin_collateral_custody_commitment_v3(row, &secrets.collateral);
        row
    }

    fn genesis_rows() -> [StablecoinStateRowV3; STABLECOIN_SOURCE_V3_CAP] {
        core::array::from_fn(|slot| row_for_slot(slot, true))
    }

    fn genesis_authority_witness() -> StablecoinSourceGenesisAuthorityWitnessV3 {
        StablecoinSourceGenesisAuthorityWitnessV3 {
            policy_admin_secrets: core::array::from_fn(|slot| authority_secrets(slot).admin),
            issuer_secrets: core::array::from_fn(|slot| authority_secrets(slot).issuer),
            oracle_secrets: core::array::from_fn(|slot| authority_secrets(slot).oracle),
            attestation_secrets: core::array::from_fn(|slot| authority_secrets(slot).attestation),
            collateral_secrets: core::array::from_fn(|slot| authority_secrets(slot).collateral),
        }
    }

    fn genesis_fixture() -> (
        StablecoinSourceGenesisV3,
        StablecoinSourceStateV3,
        [StablecoinStateRowV3; STABLECOIN_SOURCE_V3_CAP],
    ) {
        let rows = genesis_rows();
        let genesis =
            build_stablecoin_source_genesis_v3(PARENT_HEIGHT, allocation(), rows).unwrap();
        let state = verify_stablecoin_source_genesis_v3(
            StablecoinSourceGenesisVerifierContextV3 {
                parent_height: PARENT_HEIGHT,
                allocation: allocation(),
                expected_root: genesis.root,
            },
            genesis,
            genesis_authority_witness(),
        )
        .unwrap();
        (genesis, state, rows)
    }

    fn bind_update(
        state: StablecoinSourceStateV3,
        rows: &[StablecoinStateRowV3; STABLECOIN_SOURCE_V3_CAP],
        slot: usize,
        kind: StablecoinSourceUpdateKindV3,
        auxiliary_authority_mask: u8,
        after_row: StablecoinStateRowV3,
        openings: OpeningPairs,
    ) -> (
        StablecoinSourceVerifierContextV3,
        StablecoinSourceUpdatePublicV3,
        StablecoinSourceUpdateWitnessV3,
    ) {
        let membership = stablecoin_source_membership_from_rows_v3(rows, slot as u32).unwrap();
        let witness = StablecoinSourceUpdateWitnessV3 {
            slot: slot as u32,
            before_row: membership.row,
            siblings: membership.siblings,
            old_admin_secret: openings.old_admin,
            new_admin_secret: openings.new_admin,
            old_issuer_secret: openings.old_issuer,
            new_issuer_secret: openings.new_issuer,
            old_oracle_secret: openings.old_oracle,
            new_oracle_secret: openings.new_oracle,
            old_attestation_secret: openings.old_attestation,
            new_attestation_secret: openings.new_attestation,
            old_collateral_secret: openings.old_collateral,
            new_collateral_secret: openings.new_collateral,
        };
        let before_root =
            stablecoin_transition_root_from_membership_v3(witness.before_membership()).unwrap();
        let after_root =
            stablecoin_transition_root_from_membership_v3(witness.after_membership(after_row))
                .unwrap();
        let update_intent = stablecoin_source_update_intent_v3(&OUTER_INTENT);
        let mut public = StablecoinSourceUpdatePublicV3 {
            kind,
            auxiliary_authority_mask,
            slot: slot as u32,
            asset_id: witness.before_row.asset_id,
            before_policy_version: witness.before_row.policy_version,
            after_policy_version: after_row.policy_version,
            parent_height: state.parent_height,
            update_intent,
            allocation_commitment: state.allocation_commitment,
            before_root,
            after_root,
            after_row,
            admin_authorization: [0u8; 64],
        };
        public.admin_authorization = stablecoin_source_admin_authorization_v3(
            public,
            witness.before_row,
            &witness.old_admin_secret,
        );
        (
            StablecoinSourceVerifierContextV3 {
                current_root: state.current_root,
                parent_height: state.parent_height,
                allocation: state.allocation,
                expected_update_intent: update_intent,
            },
            public,
            witness,
        )
    }

    fn oracle_refresh(
        state: StablecoinSourceStateV3,
        rows: &[StablecoinStateRowV3; 16],
        slot: usize,
    ) -> (
        StablecoinSourceVerifierContextV3,
        StablecoinSourceUpdatePublicV3,
        StablecoinSourceUpdateWitnessV3,
    ) {
        let before = rows[slot];
        let secrets = authority_secrets(slot);
        let mut after = before;
        after.sequence += 1;
        after.oracle_submitted_at = PARENT_HEIGHT;
        after.oracle_price_numerator += 1;
        let mut openings = OpeningPairs::admin_only(secrets.admin);
        openings.old_oracle = secrets.oracle;
        openings.new_oracle = secrets.oracle;
        bind_update(
            state,
            rows,
            slot,
            StablecoinSourceUpdateKindV3::OracleRefresh,
            STABLECOIN_SOURCE_V3_AUTHORITY_ORACLE,
            after,
            openings,
        )
    }

    #[test]
    fn canonical_genesis_allocation_and_order_kat() {
        let (genesis, state, rows) = genesis_fixture();
        let allocation_wire = genesis.allocation.encode_canonical();
        let genesis_wire = genesis.encode_canonical();
        let authority_witness = genesis_authority_witness();
        let authority_wire = authority_witness.encode_canonical();
        assert_eq!(allocation_wire.len(), 74);
        assert_eq!(genesis_wire.len(), 7_458);
        assert_eq!(authority_wire.len(), 5_130);
        assert_eq!(
            StablecoinSourceAllocationV3::decode_canonical(&allocation_wire),
            Ok(genesis.allocation)
        );
        assert_eq!(
            StablecoinSourceGenesisV3::decode_canonical(&genesis_wire),
            Ok(genesis)
        );
        assert_eq!(
            StablecoinSourceGenesisAuthorityWitnessV3::decode_canonical(&authority_wire),
            Ok(authority_witness)
        );
        assert_eq!(
            verify_stablecoin_source_genesis_v3(
                StablecoinSourceGenesisVerifierContextV3 {
                    parent_height: PARENT_HEIGHT,
                    allocation: genesis.allocation,
                    expected_root: genesis.root,
                },
                genesis,
                genesis_authority_witness(),
            ),
            Ok(state)
        );
        let mut wrong_context = StablecoinSourceGenesisVerifierContextV3 {
            parent_height: PARENT_HEIGHT,
            allocation: genesis.allocation,
            expected_root: genesis.root,
        };
        wrong_context.parent_height += 1;
        assert_eq!(
            verify_stablecoin_source_genesis_v3(
                wrong_context,
                genesis,
                genesis_authority_witness(),
            ),
            Err(StablecoinSourceV3Error::GenesisParentHeightMismatch)
        );
        wrong_context.parent_height = PARENT_HEIGHT;
        wrong_context.expected_root = StablecoinTransitionRootV3::ZERO;
        assert_eq!(
            verify_stablecoin_source_genesis_v3(
                wrong_context,
                genesis,
                genesis_authority_witness(),
            ),
            Err(StablecoinSourceV3Error::GenesisRootMismatch)
        );
        wrong_context.expected_root = genesis.root;
        for asset_id in &mut wrong_context.allocation.asset_ids {
            *asset_id += 16;
        }
        assert_eq!(
            verify_stablecoin_source_genesis_v3(
                wrong_context,
                genesis,
                genesis_authority_witness(),
            ),
            Err(StablecoinSourceV3Error::GenesisAllocationMismatch)
        );

        let mut reversed = rows;
        reversed.reverse();
        let reordered =
            build_stablecoin_source_genesis_v3(PARENT_HEIGHT, allocation(), reversed).unwrap();
        assert_eq!(reordered, genesis);

        for slot in 0..16 {
            let membership = stablecoin_source_membership_from_rows_v3(&rows, slot as u32).unwrap();
            assert_eq!(
                stablecoin_transition_root_from_membership_v3(membership).unwrap(),
                genesis.root
            );
        }

        assert_eq!(
            hex::encode(genesis.allocation_commitment.as_bytes()),
            "5348194d9a47d265a08b01a7d3373573230d589c366b4e91c18000c0e0f5aeb61760384182825c68573ec841293b4fd6b4bff1fb59c50fcab2832d4fecd0a626"
        );
        assert_eq!(
            hex::encode(genesis.root.as_bytes()),
            "f58c69104702c17ad46aeb4eb5071ab8cda0ce0ac83e51b71ce4190133e1b734b2f3eb3441764ef11473815e6a44b0332da9fe46582fcf1b2b3d5f178a7e5807"
        );
    }

    #[test]
    fn all_slot_collisions_and_genesis_mutations_reject() {
        let valid = allocation();
        for slot in 0..16 {
            let mut wrong = valid;
            wrong.asset_ids[slot] = wrong.asset_ids[slot].wrapping_add(1);
            assert_eq!(
                wrong.validate(),
                Err(StablecoinSourceV3Error::AllocationSlotMismatch)
            );
        }
        let mut duplicate = valid;
        duplicate.asset_ids[2] = duplicate.asset_ids[1];
        assert!(duplicate.validate().is_err());

        let mut duplicate_commitment_rows = genesis_rows();
        duplicate_commitment_rows[0].oracle_authority_commitment =
            duplicate_commitment_rows[0].policy_admin_commitment;
        assert_eq!(
            build_stablecoin_source_genesis_v3(
                PARENT_HEIGHT,
                allocation(),
                duplicate_commitment_rows,
            ),
            Err(StablecoinSourceV3Error::AuthorityCommitmentsNotDistinct)
        );

        let (genesis, _, _) = genesis_fixture();
        let wire = genesis.encode_canonical();
        for offset in 0..wire.len() {
            let mut mutated = wire;
            mutated[offset] ^= 1;
            if let Ok(decoded) = StablecoinSourceGenesisV3::decode_canonical(&mutated) {
                assert!(
                    verify_stablecoin_source_genesis_v3(
                        StablecoinSourceGenesisVerifierContextV3 {
                            parent_height: PARENT_HEIGHT,
                            allocation: genesis.allocation,
                            expected_root: genesis.root,
                        },
                        decoded,
                        genesis_authority_witness(),
                    )
                    .is_err(),
                    "genesis mutation at byte {offset} was accepted"
                );
            }
        }

        let witness = genesis_authority_witness();
        let witness_wire = witness.encode_canonical();
        for offset in 0..witness_wire.len() {
            let mut mutated = witness_wire;
            mutated[offset] ^= 1;
            if let Ok(decoded) =
                StablecoinSourceGenesisAuthorityWitnessV3::decode_canonical(&mutated)
            {
                assert!(
                    verify_stablecoin_source_genesis_v3(
                        StablecoinSourceGenesisVerifierContextV3 {
                            parent_height: PARENT_HEIGHT,
                            allocation: genesis.allocation,
                            expected_root: genesis.root,
                        },
                        genesis,
                        decoded,
                    )
                    .is_err(),
                    "genesis authority mutation at byte {offset} was accepted"
                );
            }
        }
        let mut reused_secret = witness;
        reused_secret.oracle_secrets[0] = reused_secret.policy_admin_secrets[0];
        assert_eq!(
            verify_stablecoin_source_genesis_v3(
                StablecoinSourceGenesisVerifierContextV3 {
                    parent_height: PARENT_HEIGHT,
                    allocation: genesis.allocation,
                    expected_root: genesis.root,
                },
                genesis,
                reused_secret,
            ),
            Err(StablecoinSourceV3Error::AuthoritySecretsNotDistinct)
        );
    }

    #[test]
    fn oracle_refresh_roundtrip_kat_and_every_byte_mutation() {
        let (_, state, rows) = genesis_fixture();
        let (context, public, witness) = oracle_refresh(state, &rows, 5);
        verify_stablecoin_source_update_v3(context, public, witness).unwrap();
        let public_wire = public.encode_canonical();
        let witness_wire = witness.encode_canonical().unwrap();
        assert_eq!(public_wire.len(), 809);
        assert_eq!(witness_wire.len(), 1_363);
        assert_eq!(
            StablecoinSourceUpdatePublicV3::decode_canonical(&public_wire),
            Ok(public)
        );
        assert_eq!(
            StablecoinSourceUpdateWitnessV3::decode_canonical(&witness_wire),
            Ok(witness)
        );
        assert_eq!(witness.old_oracle_secret, witness.new_oracle_secret);
        assert_eq!(
            witness.before_row.oracle_authority_commitment,
            public.after_row.oracle_authority_commitment
        );
        assert_eq!(
            hex::encode(public.before_root.as_bytes()),
            "f58c69104702c17ad46aeb4eb5071ab8cda0ce0ac83e51b71ce4190133e1b734b2f3eb3441764ef11473815e6a44b0332da9fe46582fcf1b2b3d5f178a7e5807"
        );
        assert_eq!(
            hex::encode(public.after_root.as_bytes()),
            "13f0e98c05095b4f7bc45da848c7d227396bb9eb9e122aea60bfc4ae72811ea149103116c16ae330063d614157695c5ee22deda7e6a3a6e2ca8216a25963c5ea"
        );
        assert_eq!(
            hex::encode(public.admin_authorization),
            "ddd280f774da2a49db2eaff908cd0ad9d4e3b7bf3c9c4a24091338373e63c64ab151ba7780aa39c1bab50cf5a92fb8d4c2ace531327c74ae97b3fed1cb5309fc"
        );

        for offset in 0..public_wire.len() {
            let mut mutated = public_wire;
            mutated[offset] ^= 1;
            if let Ok(public) = StablecoinSourceUpdatePublicV3::decode_canonical(&mutated) {
                assert!(
                    verify_stablecoin_source_update_v3(context, public, witness).is_err(),
                    "public mutation at byte {offset} was accepted"
                );
            }
        }
        for offset in 0..witness_wire.len() {
            let mut mutated = witness_wire;
            mutated[offset] ^= 1;
            if let Ok(witness) = StablecoinSourceUpdateWitnessV3::decode_canonical(&mutated) {
                assert!(
                    verify_stablecoin_source_update_v3(context, public, witness).is_err(),
                    "witness mutation at byte {offset} was accepted"
                );
            }
        }
    }

    #[test]
    fn exact_refresh_upgrade_rotation_retire_and_activate_masks() {
        let (_, state, rows) = genesis_fixture();
        let slot = 4;
        let before = rows[slot];
        let secrets = authority_secrets(slot);

        let mut after = before;
        after.sequence += 1;
        after.attestation_created_at = PARENT_HEIGHT;
        after.attestation_disputed = true;
        let mut openings = OpeningPairs::admin_only(secrets.admin);
        openings.old_attestation = secrets.attestation;
        openings.new_attestation = secrets.attestation;
        let (context, public, witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::AttestationRefresh,
            STABLECOIN_SOURCE_V3_AUTHORITY_ATTESTATION,
            after,
            openings,
        );
        verify_stablecoin_source_update_v3(context, public, witness).unwrap();
        assert_eq!(
            witness.old_attestation_secret,
            witness.new_attestation_secret
        );
        assert_eq!(
            witness.before_row.attestation_authority_commitment,
            public.after_row.attestation_authority_commitment
        );

        after = before;
        after.sequence += 1;
        after.collateral_amount += 100;
        let new_collateral = secrets.collateral;
        after.locked_collateral_commitment =
            stablecoin_collateral_custody_commitment_v3(after, &new_collateral);
        openings = OpeningPairs::admin_only(secrets.admin);
        openings.old_collateral = secrets.collateral;
        openings.new_collateral = new_collateral;
        let (context, public, witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::CollateralSync,
            STABLECOIN_SOURCE_V3_AUTHORITY_COLLATERAL,
            after,
            openings,
        );
        verify_stablecoin_source_update_v3(context, public, witness).unwrap();
        assert_eq!(witness.old_collateral_secret, witness.new_collateral_secret);

        after = before;
        after.sequence += 1;
        after.policy_version += 1;
        after.max_mint_per_epoch += 100;
        let new_issuer = secrets.issuer;
        after.issuer_commitment =
            stablecoin_issuer_commitment_v3(after.asset_id, after.policy_version, &new_issuer);
        openings = OpeningPairs::admin_only(secrets.admin);
        openings.old_issuer = secrets.issuer;
        openings.new_issuer = new_issuer;
        let (context, public, witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::PolicyUpgrade,
            STABLECOIN_SOURCE_V3_AUTHORITY_ISSUER,
            after,
            openings,
        );
        verify_stablecoin_source_update_v3(context, public, witness).unwrap();
        assert_eq!(witness.old_issuer_secret, witness.new_issuer_secret);

        after = before;
        after.sequence += 1;
        after.policy_version += 1;
        let rotated = AuthoritySecrets {
            admin: [0xe4; 64],
            issuer: [0xe5; 64],
            oracle: [0xe6; 64],
            attestation: [0xe7; 64],
            collateral: [0xe8; 64],
        };
        after.policy_admin_commitment =
            stablecoin_policy_admin_commitment_v3(after.asset_id, &rotated.admin);
        after.issuer_commitment =
            stablecoin_issuer_commitment_v3(after.asset_id, after.policy_version, &rotated.issuer);
        after.oracle_authority_commitment =
            stablecoin_oracle_authority_commitment_v3(after, &rotated.oracle);
        after.attestation_authority_commitment =
            stablecoin_attestation_authority_commitment_v3(after, &rotated.attestation);
        after.locked_collateral_commitment =
            stablecoin_collateral_custody_commitment_v3(after, &rotated.collateral);
        openings = OpeningPairs {
            old_admin: secrets.admin,
            new_admin: rotated.admin,
            old_issuer: secrets.issuer,
            new_issuer: rotated.issuer,
            old_oracle: secrets.oracle,
            new_oracle: rotated.oracle,
            old_attestation: secrets.attestation,
            new_attestation: rotated.attestation,
            old_collateral: secrets.collateral,
            new_collateral: rotated.collateral,
        };
        let (context, public, witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::AuthorityRotation,
            STABLECOIN_SOURCE_V3_AUTHORITY_ALL,
            after,
            openings,
        );
        verify_stablecoin_source_update_v3(context, public, witness).unwrap();
        let mut wrong_selected_old = witness;
        wrong_selected_old.old_oracle_secret[0] ^= 1;
        assert_eq!(
            verify_stablecoin_source_update_v3(context, public, wrong_selected_old),
            Err(StablecoinSourceV3Error::OracleAuthorityCommitmentMismatch)
        );

        after = before;
        after.sequence += 1;
        after.policy_version += 1;
        let new_admin = [0xe9; 64];
        after.policy_admin_commitment =
            stablecoin_policy_admin_commitment_v3(after.asset_id, &new_admin);
        after.issuer_commitment =
            stablecoin_issuer_commitment_v3(after.asset_id, after.policy_version, &secrets.issuer);
        openings = OpeningPairs::admin_only(secrets.admin);
        openings.new_admin = new_admin;
        openings.old_issuer = secrets.issuer;
        openings.new_issuer = secrets.issuer;
        openings.old_oracle = secrets.oracle;
        openings.new_oracle = secrets.oracle;
        openings.old_attestation = secrets.attestation;
        openings.new_attestation = secrets.attestation;
        openings.old_collateral = secrets.collateral;
        openings.new_collateral = secrets.collateral;
        let (context, public, witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::AuthorityRotation,
            STABLECOIN_SOURCE_V3_AUTHORITY_ADMIN,
            after,
            openings,
        );
        verify_stablecoin_source_update_v3(context, public, witness).unwrap();
        let mut wrong_unselected_secret = witness;
        wrong_unselected_secret.new_oracle_secret[0] ^= 1;
        assert!(
            verify_stablecoin_source_update_v3(context, public, wrong_unselected_secret).is_err()
        );
        let mut wrong_unselected_row = public.after_row;
        wrong_unselected_row.oracle_authority_commitment[0] ^= 1;
        let (_, wrong_unselected_public, wrong_unselected_witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::AuthorityRotation,
            STABLECOIN_SOURCE_V3_AUTHORITY_ADMIN,
            wrong_unselected_row,
            openings,
        );
        assert_eq!(
            verify_stablecoin_source_update_v3(
                context,
                wrong_unselected_public,
                wrong_unselected_witness,
            ),
            Err(StablecoinSourceV3Error::ForbiddenFieldMutation)
        );

        after = before;
        after.sequence += 1;
        after.active = false;
        after.retired_at = Some(PARENT_HEIGHT);
        let (context, public, witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::Retire,
            0,
            after,
            OpeningPairs::admin_only(secrets.admin),
        );
        verify_stablecoin_source_update_v3(context, public, witness).unwrap();

        let mut inactive_rows = rows;
        inactive_rows[slot].active = false;
        let inactive_state = StablecoinSourceStateV3 {
            current_root: stablecoin_source_root_from_rows_v3(&inactive_rows).unwrap(),
            ..state
        };
        after = inactive_rows[slot];
        after.sequence += 1;
        after.active = true;
        after.enabled_at = PARENT_HEIGHT;
        let (context, public, witness) = bind_update(
            inactive_state,
            &inactive_rows,
            slot,
            StablecoinSourceUpdateKindV3::Activate,
            0,
            after,
            OpeningPairs::admin_only(secrets.admin),
        );
        verify_stablecoin_source_update_v3(context, public, witness).unwrap();
    }

    #[test]
    fn mixed_fields_wrong_authorities_and_stale_sources_reject() {
        let (_, state, rows) = genesis_fixture();
        let slot = 5;
        let (context, public, witness) = oracle_refresh(state, &rows, slot);

        let mut mixed_after = public.after_row;
        mixed_after.max_mint_per_epoch += 1;
        let (_, mixed_public, mixed_witness) = bind_update(
            state,
            &rows,
            slot,
            public.kind,
            public.auxiliary_authority_mask,
            mixed_after,
            OpeningPairs {
                old_admin: witness.old_admin_secret,
                new_admin: witness.new_admin_secret,
                old_issuer: witness.old_issuer_secret,
                new_issuer: witness.new_issuer_secret,
                old_oracle: witness.old_oracle_secret,
                new_oracle: witness.new_oracle_secret,
                old_attestation: witness.old_attestation_secret,
                new_attestation: witness.new_attestation_secret,
                old_collateral: witness.old_collateral_secret,
                new_collateral: witness.new_collateral_secret,
            },
        );
        assert_eq!(
            verify_stablecoin_source_update_v3(context, mixed_public, mixed_witness),
            Err(StablecoinSourceV3Error::ForbiddenFieldMutation)
        );

        let mut wrong_admin = witness;
        wrong_admin.old_admin_secret[0] ^= 1;
        assert_eq!(
            verify_stablecoin_source_update_v3(context, public, wrong_admin),
            Err(StablecoinSourceV3Error::OldAdminCommitmentMismatch)
        );
        let mut wrong_oracle = witness;
        wrong_oracle.old_oracle_secret[0] ^= 1;
        assert_eq!(
            verify_stablecoin_source_update_v3(context, public, wrong_oracle),
            Err(StablecoinSourceV3Error::OracleAuthorityCommitmentMismatch)
        );
        let mut reused_role_secret = witness;
        reused_role_secret.old_oracle_secret = reused_role_secret.old_admin_secret;
        reused_role_secret.new_oracle_secret = reused_role_secret.new_admin_secret;
        assert_eq!(
            verify_stablecoin_source_update_v3(context, public, reused_role_secret),
            Err(StablecoinSourceV3Error::AuthoritySecretsNotDistinct)
        );

        let before = rows[slot];
        let mut rotated_collateral = before;
        rotated_collateral.sequence += 1;
        rotated_collateral.collateral_amount += 1;
        let disguised_rotation = [0xd8; 64];
        rotated_collateral.locked_collateral_commitment =
            stablecoin_collateral_custody_commitment_v3(rotated_collateral, &disguised_rotation);
        let mut openings = OpeningPairs::admin_only(authority_secrets(slot).admin);
        openings.old_collateral = authority_secrets(slot).collateral;
        openings.new_collateral = disguised_rotation;
        let (rotation_context, rotation_public, rotation_witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::CollateralSync,
            STABLECOIN_SOURCE_V3_AUTHORITY_COLLATERAL,
            rotated_collateral,
            openings,
        );
        assert_eq!(
            verify_stablecoin_source_update_v3(rotation_context, rotation_public, rotation_witness,),
            Err(StablecoinSourceV3Error::NonCanonicalAuthorityWitness)
        );
        let mut wrong_context = context;
        wrong_context.expected_update_intent[0] ^= 1;
        assert_eq!(
            verify_stablecoin_source_update_v3(wrong_context, public, witness),
            Err(StablecoinSourceV3Error::UpdateIntentMismatch)
        );
        let mut wrong_height = public;
        wrong_height.parent_height += 1;
        assert_eq!(
            verify_stablecoin_source_update_v3(context, wrong_height, witness),
            Err(StablecoinSourceV3Error::ParentHeightMismatch)
        );

        let mut stale_rows = rows;
        stale_rows[slot].oracle_submitted_at = PARENT_HEIGHT - 200;
        stale_rows[slot].oracle_authority_commitment = stablecoin_oracle_authority_commitment_v3(
            stale_rows[slot],
            &authority_secrets(slot).oracle,
        );
        let stale_state = StablecoinSourceStateV3 {
            current_root: stablecoin_source_root_from_rows_v3(&stale_rows).unwrap(),
            ..state
        };
        let before = stale_rows[slot];
        let mut after = before;
        after.sequence += 1;
        after.oracle_submitted_at = PARENT_HEIGHT - 101;
        after.oracle_price_numerator += 1;
        let mut openings = OpeningPairs::admin_only(authority_secrets(slot).admin);
        openings.old_oracle = authority_secrets(slot).oracle;
        openings.new_oracle = authority_secrets(slot).oracle;
        let (context, public, witness) = bind_update(
            stale_state,
            &stale_rows,
            slot,
            StablecoinSourceUpdateKindV3::OracleRefresh,
            STABLECOIN_SOURCE_V3_AUTHORITY_ORACLE,
            after,
            openings,
        );
        assert_eq!(
            verify_stablecoin_source_update_v3(context, public, witness),
            Err(StablecoinSourceV3Error::OracleStale)
        );
    }

    #[test]
    fn atomic_apply_replay_rotation_and_rollback() {
        let (_, mut state, mut rows) = genesis_fixture();
        let slot = 5;
        let (context, public, witness) = oracle_refresh(state, &rows, slot);
        let initial = state;
        let mut invalid = public;
        invalid.after_row.sequence += 1;
        assert!(apply_stablecoin_source_update_v3(
            &mut state,
            context.expected_update_intent,
            invalid,
            witness,
        )
        .is_err());
        assert_eq!(state, initial);
        let accepted = apply_stablecoin_source_update_v3(
            &mut state,
            context.expected_update_intent,
            public,
            witness,
        )
        .unwrap();
        rows[slot] = public.after_row;
        assert_eq!(state.current_root, accepted.after_root);
        let after_first = state;
        assert_eq!(
            apply_stablecoin_source_update_v3(
                &mut state,
                context.expected_update_intent,
                public,
                witness,
            ),
            Err(StablecoinSourceV3Error::ContextRootMismatch)
        );
        assert_eq!(state, after_first);

        let original = authority_secrets(slot);
        let rotated = AuthoritySecrets {
            admin: [0xe4; 64],
            issuer: [0xe5; 64],
            oracle: [0xe6; 64],
            attestation: [0xe7; 64],
            collateral: [0xe8; 64],
        };
        let mut rotated_row = rows[slot];
        rotated_row.sequence += 1;
        rotated_row.policy_version += 1;
        rotated_row.policy_admin_commitment =
            stablecoin_policy_admin_commitment_v3(rotated_row.asset_id, &rotated.admin);
        rotated_row.issuer_commitment = stablecoin_issuer_commitment_v3(
            rotated_row.asset_id,
            rotated_row.policy_version,
            &rotated.issuer,
        );
        rotated_row.oracle_authority_commitment =
            stablecoin_oracle_authority_commitment_v3(rotated_row, &rotated.oracle);
        rotated_row.attestation_authority_commitment =
            stablecoin_attestation_authority_commitment_v3(rotated_row, &rotated.attestation);
        rotated_row.locked_collateral_commitment =
            stablecoin_collateral_custody_commitment_v3(rotated_row, &rotated.collateral);
        let (rotation_context, rotation_public, rotation_witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::AuthorityRotation,
            STABLECOIN_SOURCE_V3_AUTHORITY_ALL,
            rotated_row,
            OpeningPairs {
                old_admin: original.admin,
                new_admin: rotated.admin,
                old_issuer: original.issuer,
                new_issuer: rotated.issuer,
                old_oracle: original.oracle,
                new_oracle: rotated.oracle,
                old_attestation: original.attestation,
                new_attestation: rotated.attestation,
                old_collateral: original.collateral,
                new_collateral: rotated.collateral,
            },
        );
        apply_stablecoin_source_update_v3(
            &mut state,
            rotation_context.expected_update_intent,
            rotation_public,
            rotation_witness,
        )
        .unwrap();
        rows[slot] = rotated_row;

        let mut collateral_after = rotated_row;
        collateral_after.sequence += 1;
        collateral_after.collateral_amount += 1;
        collateral_after.locked_collateral_commitment =
            stablecoin_collateral_custody_commitment_v3(collateral_after, &rotated.collateral);
        let mut rotated_openings = OpeningPairs::admin_only(rotated.admin);
        rotated_openings.old_collateral = rotated.collateral;
        rotated_openings.new_collateral = rotated.collateral;
        let (new_context, new_public, new_witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::CollateralSync,
            STABLECOIN_SOURCE_V3_AUTHORITY_COLLATERAL,
            collateral_after,
            rotated_openings,
        );
        let mut old_admin_witness = new_witness;
        old_admin_witness.old_admin_secret = original.admin;
        old_admin_witness.new_admin_secret = original.admin;
        assert_eq!(
            verify_stablecoin_source_update_v3(new_context, new_public, old_admin_witness),
            Err(StablecoinSourceV3Error::OldAdminCommitmentMismatch)
        );
        apply_stablecoin_source_update_v3(
            &mut state,
            new_context.expected_update_intent,
            new_public,
            new_witness,
        )
        .unwrap();
        rows[slot] = collateral_after;

        let after_valid_updates = state;
        let current_admin = rotated.admin;
        let current_oracle = rotated.oracle;
        let mut after = rows[slot];
        after.sequence += 1;
        after.oracle_submitted_at = PARENT_HEIGHT + 1;
        after.oracle_price_numerator += 1;
        let mut openings = OpeningPairs::admin_only(current_admin);
        openings.old_oracle = current_oracle;
        openings.new_oracle = current_oracle;
        let (context, public, witness) = bind_update(
            state,
            &rows,
            slot,
            StablecoinSourceUpdateKindV3::OracleRefresh,
            STABLECOIN_SOURCE_V3_AUTHORITY_ORACLE,
            after,
            openings,
        );
        assert_eq!(
            verify_stablecoin_source_update_v3(context, public, witness),
            Err(StablecoinSourceV3Error::OracleFromFuture)
        );
        assert_eq!(state, after_valid_updates);
    }

    #[test]
    fn flags_sizes_and_hash_accounting_remain_inactive() {
        assert_eq!(STABLECOIN_SOURCE_V3_ALLOCATION_BYTES, 74);
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_BYTES, 7_458);
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_WITNESS_BYTES, 5_130);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_PUBLIC_BYTES, 809);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_WITNESS_BYTES, 1_363);
        assert_eq!(
            STABLECOIN_SOURCE_V3_ADMIN_AUTHORIZATION_PREIMAGE_BYTES,
            1_262
        );
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_PARENT_HEIGHT_OFFSET, 10);
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_ALLOCATION_OFFSET, 18);
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_ROWS_OFFSET, 82);
        assert_eq!(
            STABLECOIN_SOURCE_V3_GENESIS_ALLOCATION_COMMITMENT_OFFSET,
            7_330
        );
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_ROOT_OFFSET, 7_394);
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_AUTHORITY_SECRETS_OFFSET, 10);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_KIND_OFFSET, 10);
        assert_eq!(
            STABLECOIN_SOURCE_V3_UPDATE_AUXILIARY_AUTHORITY_MASK_OFFSET,
            11
        );
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_SLOT_OFFSET, 12);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_ASSET_ID_OFFSET, 16);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_BEFORE_POLICY_VERSION_OFFSET, 20);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_AFTER_POLICY_VERSION_OFFSET, 24);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_PARENT_HEIGHT_OFFSET, 28);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_INTENT_OFFSET, 36);
        assert_eq!(
            STABLECOIN_SOURCE_V3_UPDATE_ALLOCATION_COMMITMENT_OFFSET,
            100
        );
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_BEFORE_ROOT_OFFSET, 164);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_AFTER_ROOT_OFFSET, 228);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_AFTER_ROW_OFFSET, 292);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_ADMIN_AUTHORIZATION_OFFSET, 745);
        assert_eq!(STABLECOIN_SOURCE_V3_WITNESS_SLOT_OFFSET, 10);
        assert_eq!(STABLECOIN_SOURCE_V3_WITNESS_BEFORE_ROW_OFFSET, 14);
        assert_eq!(STABLECOIN_SOURCE_V3_WITNESS_SIBLINGS_OFFSET, 467);
        assert_eq!(STABLECOIN_SOURCE_V3_WITNESS_SECRETS_OFFSET, 723);
        assert_eq!(
            STABLECOIN_SOURCE_V3_WITNESS_NEW_COLLATERAL_SECRET_OFFSET,
            1_299
        );
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_ROOT_HASH_CALLS, 31);
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_ROOT_COMPRESSIONS, 79);
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_TOTAL_HASH_CALLS, 32);
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_TOTAL_COMPRESSIONS, 80);
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_VERIFICATION_HASH_CALLS, 112);
        assert_eq!(STABLECOIN_SOURCE_V3_GENESIS_VERIFICATION_COMPRESSIONS, 160);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_MIN_HASH_CALLS, 14);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_MIN_COMPRESSIONS, 29);
        assert_eq!(STABLECOIN_SOURCE_V3_ORDINARY_UPDATE_HASH_CALLS, 16);
        assert_eq!(STABLECOIN_SOURCE_V3_ORDINARY_UPDATE_COMPRESSIONS, 31);
        assert_eq!(STABLECOIN_SOURCE_V3_AUTHORITY_ROTATION_HASH_CALLS, 22);
        assert_eq!(STABLECOIN_SOURCE_V3_AUTHORITY_ROTATION_COMPRESSIONS, 37);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_MAX_HASH_CALLS, 22);
        assert_eq!(STABLECOIN_SOURCE_V3_UPDATE_MAX_COMPRESSIONS, 37);
        assert!(!STABLECOIN_SOURCE_V3_ACTIVE);
        assert!(!STABLECOIN_SOURCE_V3_KERNEL_GLOBAL_ROOT_INTEGRATED);
        assert!(!STABLECOIN_SOURCE_V3_GENESIS_ROUTE_AUTHORIZED);
        assert!(!STABLECOIN_SOURCE_V3_STATE_WRITER_INTEGRATED);
        assert!(!STABLECOIN_SOURCE_V3_GOVERNANCE_AUTHORIZED);
        assert!(!STABLECOIN_SOURCE_V3_TRANSACTION_COMPILER_INTEGRATED);
        assert!(!STABLECOIN_SOURCE_V3_RELATION_INTEGRATED);
        assert!(!STABLECOIN_SOURCE_V3_CONSENSUS_ROUTE_AUTHORIZED);
        assert!(!STABLECOIN_SOURCE_V3_QROM_AUTHORIZED);
        assert!(!STABLECOIN_SOURCE_V3_COMPLETE_ZK_AUTHORIZED);
        assert!(!STABLECOIN_SOURCE_V3_FORMAL_REFINEMENT_COMPLETE);
        assert!(!STABLECOIN_SOURCE_V3_CACHE_AUTHORITY);
        assert!(!STABLECOIN_SOURCE_V3_RECEIPT_AUTHORITY);
        assert!(!STABLECOIN_SOURCE_V3_PRODUCTION_AUTHORIZED);
    }
}
