//! Candidate controlled-asset registry and public supply accounting.
//!
//! This module is a pure state helper, not an issuer signature or ZK verifier.
//! A prepared transition is deliberately named **prepared**, never verified.
//! A caller must verify a proof which binds the exact chain, reference parent,
//! registry root, row, operation, magnitude, intent, current credentials and
//! resulting counters before applying it. It must also enforce note/nullifier
//! conservation, native fees and mandatory credentials on every spend route.
//! These functions create no consensus route or production authority.
//!
//! The full V8 configuration and its role commitments are retained. Issuance
//! disablement/retirement affects minting; only `frozen` stops existing value
//! transfers and owner-authorized burns. Native HGN (asset zero) cannot be a row.

use crate::poseidon2_width16::{poseidon2_width16_compress14, Felt};
use crate::stablecoin_poseidon2_v8::{
    stablecoin_poseidon2_v8_config_digest, StablecoinPoseidon2V8Config,
    StablecoinPoseidon2V8Counters, StablecoinPoseidon2V8Digest, StablecoinPoseidon2V8Error,
    STABLECOIN_POSEIDON2_V8_CAP, STABLECOIN_POSEIDON2_V8_DEPTH,
    STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT, STABLECOIN_POSEIDON2_V8_MAX_SCALAR,
    STABLECOIN_POSEIDON2_V8_MAX_VALUE, STABLECOIN_POSEIDON2_V8_RATIO_SCALE_PPM,
};

pub type AssetRegistryDigestV1 = StablecoinPoseidon2V8Digest;
pub const ASSET_REGISTRY_CAP_V1: usize = STABLECOIN_POSEIDON2_V8_CAP;
pub const ASSET_REGISTRY_DEPTH_V1: usize = STABLECOIN_POSEIDON2_V8_DEPTH;
pub const ASSET_REGISTRY_ID_V1: &str = "hegemon.controlled-asset-registry.poseidon2.v1";
pub const ASSET_REGISTRY_STATE_DOMAIN_V1: u64 = 0x4841_5231_5354_4154;
pub const ASSET_REGISTRY_CREDENTIAL_DOMAIN_V1: u64 = 0x4841_5231_4352_4544;
pub const ASSET_REGISTRY_LEAF_DOMAIN_V1: u64 = 0x4841_5231_4c45_4146;
pub const ASSET_REGISTRY_EMPTY_DOMAIN_V1: u64 = 0x4841_5231_454d_5054;
pub const ASSET_REGISTRY_NODE_DOMAIN_V1: u64 = 0x4841_5231_4e4f_4400;

/// Public authenticated policy row. Changing any field changes the registry root.
/// Credential leaves and their interpretation belong to the proof relation;
/// this helper checks that the relation uses the latest authenticated root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetPolicyV1 {
    pub config: StablecoinPoseidon2V8Config,
    pub counters: StablecoinPoseidon2V8Counters,
    pub credential_root: AssetRegistryDigestV1,
    pub credential_depth: u8,
    pub frozen: bool,
    pub mint_enabled: bool,
}

/// Controls owned by the separate policy administrator. Changing these fields
/// does not rotate the issuer, oracle, attestation or collateral credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetControlsV1 {
    pub credential_root: AssetRegistryDigestV1,
    pub credential_depth: u8,
    pub frozen: bool,
    pub mint_enabled: bool,
}

impl AssetPolicyV1 {
    pub const fn controls(&self) -> AssetControlsV1 {
        AssetControlsV1 {
            credential_root: self.credential_root,
            credential_depth: self.credential_depth,
            frozen: self.frozen,
            mint_enabled: self.mint_enabled,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetOperationV1 {
    Transfer,
    Mint,
    Burn,
}

/// Exact public state context. A proof-aware caller additionally binds the
/// reference parent hash and note tree; a height alone is not fork identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetRegistryContextV1 {
    pub chain_id: [u8; 32],
    pub parent_height: u64,
    pub registry_root: AssetRegistryDigestV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetRegistryErrorV1 {
    ChainIdZero,
    ChainMismatch,
    ParentMismatch,
    RootMismatch,
    UnknownAsset,
    AssetSlotCollision,
    PolicyVersionMismatch,
    CredentialRootMismatch,
    CredentialDepth,
    CredentialRootZero,
    Frozen,
    MintDisabled,
    TransferMagnitude,
    ReplacementAssetMismatch,
    ReplacementCountersMismatch,
    ReplacementVersionMismatch,
    InvalidTreeLevel,
    Stablecoin(StablecoinPoseidon2V8Error),
}

impl From<StablecoinPoseidon2V8Error> for AssetRegistryErrorV1 {
    fn from(error: StablecoinPoseidon2V8Error) -> Self {
        Self::Stablecoin(error)
    }
}

impl core::fmt::Display for AssetRegistryErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "candidate asset registry: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AssetRegistryErrorV1 {}

fn is_zero(digest: &AssetRegistryDigestV1) -> bool {
    digest.iter().all(|word| *word == Felt::ZERO)
}

const fn slot(asset_id: u32) -> usize {
    (asset_id as usize) & (ASSET_REGISTRY_CAP_V1 - 1)
}

/// Validate the injective field projection and static V8 role separation.
/// This duplicates the private V8 common validator without changing its source;
/// focused parity tests below compare the actual V8 acceptance path.
pub fn validate_asset_policy_v1(policy: &AssetPolicyV1) -> Result<(), AssetRegistryErrorV1> {
    let config = policy.config;
    let before = policy.counters;
    if config.asset_id == 0 {
        return Err(StablecoinPoseidon2V8Error::ZeroOrNativeAsset.into());
    }
    for value in [
        config.max_mint_per_epoch,
        config.collateral_amount,
        before.minted_in_epoch,
        before.total_debt,
    ] {
        if value > STABLECOIN_POSEIDON2_V8_MAX_VALUE {
            return Err(StablecoinPoseidon2V8Error::ValueOutOfRange.into());
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
            return Err(StablecoinPoseidon2V8Error::ScalarOutOfRange.into());
        }
    }
    if before.minted_in_epoch > config.max_mint_per_epoch {
        return Err(StablecoinPoseidon2V8Error::MintCapExceeded.into());
    }
    let commitments = [
        config.issuer_commitment,
        config.policy_admin_commitment,
        config.oracle_authority_commitment,
        config.attestation_authority_commitment,
        config.locked_collateral_commitment,
    ];
    if commitments.iter().any(is_zero) {
        return Err(StablecoinPoseidon2V8Error::CommitmentZero.into());
    }
    for left in 0..commitments.len() {
        for right in left + 1..commitments.len() {
            if commitments[left] == commitments[right] {
                return Err(StablecoinPoseidon2V8Error::CommitmentRoleReuse.into());
            }
        }
    }
    if config.collateral_decimals > 18 {
        return Err(StablecoinPoseidon2V8Error::InvalidCollateralDecimals.into());
    }
    let expected_scale = 10u64
        .checked_pow(u32::from(config.collateral_decimals))
        .ok_or(StablecoinPoseidon2V8Error::InvalidCollateralScale)?;
    if config.collateral_scale != expected_scale {
        return Err(StablecoinPoseidon2V8Error::InvalidCollateralScale.into());
    }
    if !matches!(policy.credential_depth, 4 | 8 | 16) {
        return Err(AssetRegistryErrorV1::CredentialDepth);
    }
    if is_zero(&policy.credential_root) {
        return Err(AssetRegistryErrorV1::CredentialRootZero);
    }
    Ok(())
}

/// Fresh leaf hash: V8 config digest and counters, followed by current
/// credential root/depth and the independent freeze/mint controls.
pub fn asset_policy_leaf_v1(policy: &AssetPolicyV1) -> AssetRegistryDigestV1 {
    let counters = policy.counters;
    let state = poseidon2_width16_compress14(
        ASSET_REGISTRY_STATE_DOMAIN_V1,
        &stablecoin_poseidon2_v8_config_digest(policy.config),
        &[
            Felt::from_u64(counters.epoch_id),
            Felt::from_u64(counters.minted_in_epoch),
            Felt::from_u64(counters.total_debt),
            Felt::from_u64(counters.sequence),
            Felt::from_u64(slot(policy.config.asset_id) as u64),
            Felt::ZERO,
            Felt::ZERO,
        ],
    );
    let credentials = poseidon2_width16_compress14(
        ASSET_REGISTRY_CREDENTIAL_DOMAIN_V1,
        &policy.credential_root,
        &[
            Felt::from_u64(u64::from(policy.credential_depth)),
            Felt::from_u64(u64::from(policy.frozen)),
            Felt::from_u64(u64::from(policy.mint_enabled)),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ],
    );
    poseidon2_width16_compress14(ASSET_REGISTRY_LEAF_DOMAIN_V1, &state, &credentials)
}

pub fn asset_registry_node_v1(
    level: usize,
    left: &AssetRegistryDigestV1,
    right: &AssetRegistryDigestV1,
) -> Result<AssetRegistryDigestV1, AssetRegistryErrorV1> {
    if level >= ASSET_REGISTRY_DEPTH_V1 {
        return Err(AssetRegistryErrorV1::InvalidTreeLevel);
    }
    Ok(poseidon2_width16_compress14(
        ASSET_REGISTRY_NODE_DOMAIN_V1 + level as u64,
        left,
        right,
    ))
}

/// Recompute membership for a complete row, including its full asset id.
pub fn asset_registry_membership_root_v1(
    policy: &AssetPolicyV1,
    siblings: &[AssetRegistryDigestV1; ASSET_REGISTRY_DEPTH_V1],
) -> Result<AssetRegistryDigestV1, AssetRegistryErrorV1> {
    validate_asset_policy_v1(policy)?;
    let mut cursor = slot(policy.config.asset_id);
    let mut root = asset_policy_leaf_v1(policy);
    for (level, sibling) in siblings.iter().enumerate() {
        root = if cursor & 1 == 0 {
            asset_registry_node_v1(level, &root, sibling)?
        } else {
            asset_registry_node_v1(level, sibling, &root)?
        };
        cursor >>= 1;
    }
    Ok(root)
}

/// Immutable input/output plan. Private fields prevent callers constructing a
/// plan without the accounting checks, but do **not** certify a proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAssetAccountingV1 {
    context: AssetRegistryContextV1,
    before: AssetPolicyV1,
    after: AssetPolicyV1,
    operation: AssetOperationV1,
    magnitude: u64,
    after_root: AssetRegistryDigestV1,
}

impl PreparedAssetAccountingV1 {
    pub const fn context(&self) -> AssetRegistryContextV1 {
        self.context
    }
    pub const fn before(&self) -> &AssetPolicyV1 {
        &self.before
    }
    pub const fn after(&self) -> &AssetPolicyV1 {
        &self.after
    }
    pub const fn operation(&self) -> AssetOperationV1 {
        self.operation
    }
    pub const fn magnitude(&self) -> u64 {
        self.magnitude
    }
    pub const fn after_root(&self) -> AssetRegistryDigestV1 {
        self.after_root
    }
}

/// Public proposed administrative replacement, without authority. Counters and
/// asset id are immutable through this path, and version must advance exactly
/// once. A proof-aware caller must separately authenticate the specific old
/// role(s) allowed to change each field; this helper cannot confer those roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAssetPolicyUpdateV1 {
    context: AssetRegistryContextV1,
    before: AssetPolicyV1,
    after: AssetPolicyV1,
    after_root: AssetRegistryDigestV1,
}

impl PreparedAssetPolicyUpdateV1 {
    pub const fn context(&self) -> AssetRegistryContextV1 {
        self.context
    }
    pub const fn before(&self) -> &AssetPolicyV1 {
        &self.before
    }
    pub const fn after(&self) -> &AssetPolicyV1 {
        &self.after
    }
    pub const fn after_root(&self) -> AssetRegistryDigestV1 {
        self.after_root
    }
}

/// Prepared freeze/revocation/mint controls update. The complete V8 config,
/// including every administrative role, issuer key and policy version, and all
/// supply counters remain unchanged. This is not administrative authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAssetControlsV1 {
    context: AssetRegistryContextV1,
    before: AssetPolicyV1,
    after: AssetPolicyV1,
    after_root: AssetRegistryDigestV1,
}

impl PreparedAssetControlsV1 {
    pub const fn context(&self) -> AssetRegistryContextV1 {
        self.context
    }
    pub const fn before(&self) -> &AssetPolicyV1 {
        &self.before
    }
    pub const fn after(&self) -> &AssetPolicyV1 {
        &self.after
    }
    pub const fn after_root(&self) -> AssetRegistryDigestV1 {
        self.after_root
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRegistryV1 {
    chain_id: [u8; 32],
    parent_height: u64,
    rows: [Option<AssetPolicyV1>; ASSET_REGISTRY_CAP_V1],
}

impl AssetRegistryV1 {
    /// Construct candidate state from explicitly supplied public rows. This is
    /// not a network registration/issuance action. Never replace authenticated
    /// live state with arbitrary rows using this constructor.
    pub fn from_rows(
        chain_id: [u8; 32],
        parent_height: u64,
        rows: &[AssetPolicyV1],
    ) -> Result<Self, AssetRegistryErrorV1> {
        if chain_id == [0; 32] {
            return Err(AssetRegistryErrorV1::ChainIdZero);
        }
        if parent_height > STABLECOIN_POSEIDON2_V8_MAX_SCALAR {
            return Err(StablecoinPoseidon2V8Error::ScalarOutOfRange.into());
        }
        let mut registry = Self {
            chain_id,
            parent_height,
            rows: [None; ASSET_REGISTRY_CAP_V1],
        };
        for row in rows {
            validate_asset_policy_v1(row)?;
            if row.counters.epoch_id > parent_height >> STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT {
                return Err(StablecoinPoseidon2V8Error::FutureEpoch.into());
            }
            let entry = &mut registry.rows[slot(row.config.asset_id)];
            if entry.is_some() {
                return Err(AssetRegistryErrorV1::AssetSlotCollision);
            }
            *entry = Some(*row);
        }
        Ok(registry)
    }

    pub fn row(&self, asset_id: u32) -> Result<&AssetPolicyV1, AssetRegistryErrorV1> {
        if asset_id == 0 {
            return Err(StablecoinPoseidon2V8Error::ZeroOrNativeAsset.into());
        }
        self.rows[slot(asset_id)]
            .as_ref()
            .filter(|row| row.config.asset_id == asset_id)
            .ok_or(AssetRegistryErrorV1::UnknownAsset)
    }

    fn leaves(&self) -> [AssetRegistryDigestV1; ASSET_REGISTRY_CAP_V1] {
        core::array::from_fn(|index| match self.rows[index] {
            Some(row) => asset_policy_leaf_v1(&row),
            None => poseidon2_width16_compress14(
                ASSET_REGISTRY_EMPTY_DOMAIN_V1,
                &[Felt::ZERO; 7],
                &[
                    Felt::from_u64(index as u64),
                    Felt::ZERO,
                    Felt::ZERO,
                    Felt::ZERO,
                    Felt::ZERO,
                    Felt::ZERO,
                    Felt::ZERO,
                ],
            ),
        })
    }

    pub fn root(&self) -> AssetRegistryDigestV1 {
        let mut nodes = self.leaves();
        let mut width = ASSET_REGISTRY_CAP_V1;
        for level in 0..ASSET_REGISTRY_DEPTH_V1 {
            for index in 0..width / 2 {
                nodes[index] = poseidon2_width16_compress14(
                    ASSET_REGISTRY_NODE_DOMAIN_V1 + level as u64,
                    &nodes[index * 2],
                    &nodes[index * 2 + 1],
                );
            }
            width /= 2;
        }
        nodes[0]
    }

    pub fn context(&self) -> AssetRegistryContextV1 {
        AssetRegistryContextV1 {
            chain_id: self.chain_id,
            parent_height: self.parent_height,
            registry_root: self.root(),
        }
    }

    pub fn membership(
        &self,
        asset_id: u32,
    ) -> Result<[AssetRegistryDigestV1; ASSET_REGISTRY_DEPTH_V1], AssetRegistryErrorV1> {
        self.row(asset_id)?;
        let mut nodes = self.leaves();
        let mut cursor = slot(asset_id);
        let mut width = ASSET_REGISTRY_CAP_V1;
        let mut siblings = [[Felt::ZERO; 7]; ASSET_REGISTRY_DEPTH_V1];
        for (level, sibling) in siblings.iter_mut().enumerate() {
            *sibling = nodes[cursor ^ 1];
            for index in 0..width / 2 {
                nodes[index] =
                    asset_registry_node_v1(level, &nodes[index * 2], &nodes[index * 2 + 1])?;
            }
            cursor >>= 1;
            width /= 2;
        }
        Ok(siblings)
    }

    fn check_context(&self, context: AssetRegistryContextV1) -> Result<(), AssetRegistryErrorV1> {
        if context.chain_id != self.chain_id {
            return Err(AssetRegistryErrorV1::ChainMismatch);
        }
        if context.parent_height != self.parent_height {
            return Err(AssetRegistryErrorV1::ParentMismatch);
        }
        if context.registry_root != self.root() {
            return Err(AssetRegistryErrorV1::RootMismatch);
        }
        Ok(())
    }

    /// Supply delta uses `magnitude = 0` for a transfer, positive magnitude for
    /// mint/burn. Transfer value and native fees remain the proof's obligation.
    /// No issuer secret is accepted or fabricated by this public state helper.
    pub fn prepare_accounting(
        &self,
        context: AssetRegistryContextV1,
        asset_id: u32,
        policy_version: u32,
        credential_root: AssetRegistryDigestV1,
        operation: AssetOperationV1,
        magnitude: u64,
    ) -> Result<PreparedAssetAccountingV1, AssetRegistryErrorV1> {
        self.check_context(context)?;
        let before = *self.row(asset_id)?;
        if policy_version != before.config.policy_version {
            return Err(AssetRegistryErrorV1::PolicyVersionMismatch);
        }
        if credential_root != before.credential_root {
            return Err(AssetRegistryErrorV1::CredentialRootMismatch);
        }
        if before.frozen {
            return Err(AssetRegistryErrorV1::Frozen);
        }
        let mut after = before;
        after.counters = prepare_counters(&before, operation, magnitude, self.parent_height)?;
        let mut next = self.clone();
        next.rows[slot(asset_id)] = Some(after);
        Ok(PreparedAssetAccountingV1 {
            context,
            before,
            after,
            operation,
            magnitude,
            after_root: next.root(),
        })
    }

    /// Apply only AFTER verifying the exact prepared proof. This performs no
    /// cryptographic authorization. Root/row/context rechecks reject stale
    /// mint/burn plans; ordinary spend replay must also consume nullifiers.
    pub fn apply_accounting_after_proof(
        &mut self,
        prepared: PreparedAssetAccountingV1,
    ) -> Result<(), AssetRegistryErrorV1> {
        self.check_context(prepared.context)?;
        if *self.row(prepared.before.config.asset_id)? != prepared.before {
            return Err(AssetRegistryErrorV1::RootMismatch);
        }
        self.rows[slot(prepared.before.config.asset_id)] = Some(prepared.after);
        Ok(())
    }

    /// Prepare a public update without granting administrative authority.
    /// Policy, oracle, attestation and recovery governance remain distinct
    /// external proof obligations; there is no network setter in this module.
    pub fn prepare_policy_replacement(
        &self,
        context: AssetRegistryContextV1,
        asset_id: u32,
        replacement: AssetPolicyV1,
    ) -> Result<PreparedAssetPolicyUpdateV1, AssetRegistryErrorV1> {
        self.check_context(context)?;
        let before = *self.row(asset_id)?;
        if replacement.config.asset_id != asset_id {
            return Err(AssetRegistryErrorV1::ReplacementAssetMismatch);
        }
        if replacement.counters != before.counters {
            return Err(AssetRegistryErrorV1::ReplacementCountersMismatch);
        }
        if before.config.policy_version.checked_add(1) != Some(replacement.config.policy_version) {
            return Err(AssetRegistryErrorV1::ReplacementVersionMismatch);
        }
        validate_asset_policy_v1(&replacement)?;
        let mut next = self.clone();
        next.rows[slot(asset_id)] = Some(replacement);
        Ok(PreparedAssetPolicyUpdateV1 {
            context,
            before,
            after: replacement,
            after_root: next.root(),
        })
    }

    /// Pure state mutation, callable only after the integrating caller verifies
    /// old-role authority for every changed field of this exact replacement.
    pub fn apply_policy_replacement_after_authorization(
        &mut self,
        prepared: PreparedAssetPolicyUpdateV1,
    ) -> Result<(), AssetRegistryErrorV1> {
        self.check_context(prepared.context)?;
        if *self.row(prepared.before.config.asset_id)? != prepared.before {
            return Err(AssetRegistryErrorV1::RootMismatch);
        }
        self.rows[slot(prepared.before.config.asset_id)] = Some(prepared.after);
        Ok(())
    }

    /// Prepare an exact controls update, without changing issuance policy or
    /// granting any authority. The proof-aware caller must prove knowledge of
    /// the OLD row's distinct policy-admin credential, bound to this exact
    /// chain, reference parent, old/new registry roots and new controls. Freeze
    /// and credential updates therefore do not require rotating the issuer's
    /// version-bound key. An update may unfreeze a row, but it never spends it.
    pub fn prepare_controls_update(
        &self,
        context: AssetRegistryContextV1,
        asset_id: u32,
        controls: AssetControlsV1,
    ) -> Result<PreparedAssetControlsV1, AssetRegistryErrorV1> {
        self.check_context(context)?;
        let before = *self.row(asset_id)?;
        let after = AssetPolicyV1 {
            credential_root: controls.credential_root,
            credential_depth: controls.credential_depth,
            frozen: controls.frozen,
            mint_enabled: controls.mint_enabled,
            ..before
        };
        validate_asset_policy_v1(&after)?;
        let mut next = self.clone();
        next.rows[slot(asset_id)] = Some(after);
        Ok(PreparedAssetControlsV1 {
            context,
            before,
            after,
            after_root: next.root(),
        })
    }

    /// Apply only after checking the real administrator proof for the exact
    /// prepared controls. This helper verifies neither a proof nor authority.
    pub fn apply_controls_update_after_authorization(
        &mut self,
        prepared: PreparedAssetControlsV1,
    ) -> Result<(), AssetRegistryErrorV1> {
        self.check_context(prepared.context)?;
        if *self.row(prepared.before.config.asset_id)? != prepared.before {
            return Err(AssetRegistryErrorV1::RootMismatch);
        }
        self.rows[slot(prepared.before.config.asset_id)] = Some(prepared.after);
        Ok(())
    }

    /// Advance candidate parent context after external canonical-chain
    /// verification. Restore a previously authenticated clone for a reorg;
    /// this method refuses backwards height and never changes supply/rows.
    pub fn advance_parent_after_chain_verification(
        &mut self,
        expected: AssetRegistryContextV1,
        next_parent_height: u64,
    ) -> Result<(), AssetRegistryErrorV1> {
        self.check_context(expected)?;
        if next_parent_height < self.parent_height {
            return Err(AssetRegistryErrorV1::ParentMismatch);
        }
        if next_parent_height > STABLECOIN_POSEIDON2_V8_MAX_SCALAR {
            return Err(StablecoinPoseidon2V8Error::ScalarOutOfRange.into());
        }
        self.parent_height = next_parent_height;
        Ok(())
    }
}

/// Public accounting portion of V8. Issuer ownership/intent authorization and
/// note ownership remain in the ZK relation, not this arithmetic helper.
fn prepare_counters(
    policy: &AssetPolicyV1,
    operation: AssetOperationV1,
    magnitude: u64,
    parent_height: u64,
) -> Result<StablecoinPoseidon2V8Counters, AssetRegistryErrorV1> {
    validate_asset_policy_v1(policy)?;
    let config = policy.config;
    let before = policy.counters;
    let epoch = parent_height >> STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT;
    if before.epoch_id > epoch {
        return Err(StablecoinPoseidon2V8Error::FutureEpoch.into());
    }
    if operation == AssetOperationV1::Transfer {
        if magnitude != 0 {
            return Err(AssetRegistryErrorV1::TransferMagnitude);
        }
        return Ok(before);
    }
    if magnitude == 0 {
        return Err(StablecoinPoseidon2V8Error::ZeroMagnitude.into());
    }
    if magnitude > STABLECOIN_POSEIDON2_V8_MAX_VALUE {
        return Err(StablecoinPoseidon2V8Error::ValueOutOfRange.into());
    }
    let mint_base = if before.epoch_id == epoch {
        before.minted_in_epoch
    } else {
        0
    };
    let mut after = before;
    after.epoch_id = epoch;
    after.sequence = before
        .sequence
        .checked_add(1)
        .ok_or(StablecoinPoseidon2V8Error::ArithmeticOverflow)?;
    if after.sequence > STABLECOIN_POSEIDON2_V8_MAX_SCALAR {
        return Err(StablecoinPoseidon2V8Error::ScalarOutOfRange.into());
    }
    match operation {
        AssetOperationV1::Transfer => unreachable!("handled above"),
        AssetOperationV1::Mint => {
            if !policy.mint_enabled {
                return Err(AssetRegistryErrorV1::MintDisabled);
            }
            validate_mint_policy(config, parent_height)?;
            after.minted_in_epoch = mint_base
                .checked_add(magnitude)
                .ok_or(StablecoinPoseidon2V8Error::ArithmeticOverflow)?;
            if after.minted_in_epoch > config.max_mint_per_epoch {
                return Err(StablecoinPoseidon2V8Error::MintCapExceeded.into());
            }
            after.total_debt = before
                .total_debt
                .checked_add(magnitude)
                .ok_or(StablecoinPoseidon2V8Error::ArithmeticOverflow)?;
            if after.total_debt > STABLECOIN_POSEIDON2_V8_MAX_VALUE {
                return Err(StablecoinPoseidon2V8Error::ValueOutOfRange.into());
            }
            let left = u128::from(config.collateral_amount)
                .checked_mul(u128::from(config.oracle_price_numerator))
                .and_then(|v| v.checked_mul(u128::from(STABLECOIN_POSEIDON2_V8_RATIO_SCALE_PPM)))
                .ok_or(StablecoinPoseidon2V8Error::ArithmeticOverflow)?;
            let right = u128::from(after.total_debt)
                .checked_mul(u128::from(config.oracle_price_denominator))
                .and_then(|v| v.checked_mul(u128::from(config.min_collateral_ratio_ppm)))
                .ok_or(StablecoinPoseidon2V8Error::ArithmeticOverflow)?;
            if left < right {
                return Err(StablecoinPoseidon2V8Error::CollateralRatioViolation.into());
            }
        }
        AssetOperationV1::Burn => {
            after.minted_in_epoch = mint_base;
            after.total_debt = before
                .total_debt
                .checked_sub(magnitude)
                .ok_or(StablecoinPoseidon2V8Error::DebtUnderflow)?;
        }
    }
    Ok(after)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stablecoin_poseidon2_v8::{
        stablecoin_poseidon2_v8_issuer_authorization, stablecoin_poseidon2_v8_issuer_commitment,
        stablecoin_poseidon2_v8_root, verify_stablecoin_transition_v8,
        StablecoinPoseidon2V8Context, StablecoinPoseidon2V8Direction, StablecoinPoseidon2V8Public,
        StablecoinPoseidon2V8Witness,
    };

    const HEIGHT: u64 = 9_000;
    const CHAIN: [u8; 32] = [17; 32];
    const SECRET: [Felt; 7] = [
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
    ];

    fn tagged(tag: u64) -> AssetRegistryDigestV1 {
        core::array::from_fn(|index| Felt::from_u64(tag + index as u64))
    }

    fn fixture() -> AssetPolicyV1 {
        AssetPolicyV1 {
            config: StablecoinPoseidon2V8Config {
                asset_id: 1001,
                policy_version: 7,
                active: true,
                enabled_at: 1,
                retired_at: Some(20_000),
                issuer_commitment: stablecoin_poseidon2_v8_issuer_commitment(1001, 7, &SECRET),
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
            },
            counters: StablecoinPoseidon2V8Counters {
                epoch_id: HEIGHT >> STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT,
                minted_in_epoch: 100,
                total_debt: 1_000,
                sequence: 9,
            },
            credential_root: tagged(701),
            credential_depth: 8,
            frozen: false,
            mint_enabled: true,
        }
    }

    fn registry(row: AssetPolicyV1) -> AssetRegistryV1 {
        AssetRegistryV1::from_rows(CHAIN, HEIGHT, &[row]).unwrap()
    }

    fn prepare(
        registry: &AssetRegistryV1,
        operation: AssetOperationV1,
        magnitude: u64,
    ) -> Result<PreparedAssetAccountingV1, AssetRegistryErrorV1> {
        let row = registry.row(1001)?;
        registry.prepare_accounting(
            registry.context(),
            1001,
            row.config.policy_version,
            row.credential_root,
            operation,
            magnitude,
        )
    }

    /// Independent expected-state construction; the original V8 function
    /// performs its actual issuer-secret, policy and accounting checks. Public
    /// disposable secrets are confined to tests, never fabricated in the helper.
    fn original_v8(
        row: AssetPolicyV1,
        operation: AssetOperationV1,
        magnitude: u64,
        height: u64,
    ) -> Result<StablecoinPoseidon2V8Counters, StablecoinPoseidon2V8Error> {
        let direction = match operation {
            AssetOperationV1::Mint => StablecoinPoseidon2V8Direction::Mint,
            AssetOperationV1::Burn => StablecoinPoseidon2V8Direction::Burn,
            AssetOperationV1::Transfer => panic!("no V8 supply transition for transfer"),
        };
        let epoch = height >> STABLECOIN_POSEIDON2_V8_EPOCH_HEIGHT_SHIFT;
        let mut after = row.counters;
        after.epoch_id = epoch;
        after.sequence = after.sequence.saturating_add(1);
        after.minted_in_epoch = if row.counters.epoch_id == epoch {
            row.counters.minted_in_epoch
        } else {
            0
        };
        match operation {
            AssetOperationV1::Mint => {
                after.minted_in_epoch = after.minted_in_epoch.saturating_add(magnitude);
                after.total_debt = after.total_debt.saturating_add(magnitude);
            }
            AssetOperationV1::Burn => after.total_debt = after.total_debt.saturating_sub(magnitude),
            AssetOperationV1::Transfer => unreachable!(),
        }
        let digest = stablecoin_poseidon2_v8_config_digest(row.config);
        let siblings = [[Felt::ZERO; 7]; STABLECOIN_POSEIDON2_V8_DEPTH];
        let before_root =
            stablecoin_poseidon2_v8_root(row.config.asset_id, digest, row.counters, &siblings)?;
        let after_root =
            stablecoin_poseidon2_v8_root(row.config.asset_id, digest, after, &siblings)?;
        let intent = tagged(901);
        let issuer_secret = if operation == AssetOperationV1::Mint {
            SECRET
        } else {
            [Felt::ZERO; 7]
        };
        let public = StablecoinPoseidon2V8Public {
            direction,
            asset_id: row.config.asset_id,
            policy_version: row.config.policy_version,
            magnitude,
            action_intent: intent,
            parent_height: height,
            before_root,
            after_root,
            after,
            issuer_authorization: if operation == AssetOperationV1::Mint {
                stablecoin_poseidon2_v8_issuer_authorization(&intent, &issuer_secret)
            } else {
                [Felt::ZERO; 7]
            },
        };
        verify_stablecoin_transition_v8(
            StablecoinPoseidon2V8Context {
                current_root: before_root,
                parent_height: height,
                expected_action_intent: intent,
            },
            public,
            StablecoinPoseidon2V8Witness {
                config: row.config,
                before: row.counters,
                siblings,
                issuer_secret,
            },
        )?;
        Ok(after)
    }

    fn assert_parity(label: &str, row: AssetPolicyV1, operation: AssetOperationV1, magnitude: u64) {
        let actual = prepare_counters(&row, operation, magnitude, HEIGHT);
        let expected = original_v8(row, operation, magnitude, HEIGHT)
            .map_err(AssetRegistryErrorV1::Stablecoin);
        assert_eq!(actual, expected, "public V8 accounting parity: {label}");
    }

    #[test]
    fn mint_and_burn_positive_epoch_and_boundaries_match_original_v8() {
        for operation in [AssetOperationV1::Mint, AssetOperationV1::Burn] {
            for magnitude in [1, 25, 100, 1_000] {
                assert_parity("current epoch", fixture(), operation, magnitude);
                let mut old = fixture();
                old.counters.epoch_id -= 1;
                assert_parity("epoch reset", old, operation, magnitude);
            }
        }
        let mut exact_cap = fixture();
        exact_cap.config.max_mint_per_epoch = 125;
        assert_parity("exact mint cap", exact_cap, AssetOperationV1::Mint, 25);
        let mut exact_collateral = fixture();
        exact_collateral.config.collateral_amount = 1_025;
        exact_collateral.config.oracle_price_numerator = 1;
        exact_collateral.config.min_collateral_ratio_ppm = 1_000_000;
        assert_parity(
            "exact collateral",
            exact_collateral,
            AssetOperationV1::Mint,
            25,
        );
        let mut exact_debt = fixture();
        exact_debt.config.collateral_amount = STABLECOIN_POSEIDON2_V8_MAX_VALUE;
        exact_debt.counters.total_debt = STABLECOIN_POSEIDON2_V8_MAX_VALUE - 25;
        assert_parity("exact debt bound", exact_debt, AssetOperationV1::Mint, 25);
        let mut sequence = fixture();
        sequence.counters.sequence = STABLECOIN_POSEIDON2_V8_MAX_SCALAR - 1;
        assert_parity("exact sequence bound", sequence, AssetOperationV1::Mint, 25);
        sequence.counters.sequence += 1;
        assert_parity("sequence over bound", sequence, AssetOperationV1::Mint, 25);
    }

    #[test]
    fn mint_policy_rejection_matrix_matches_original_v8() {
        let mutations: &[(&str, fn(&mut AssetPolicyV1))] = &[
            ("inactive", |r| r.config.active = false),
            ("not enabled", |r| r.config.enabled_at = HEIGHT + 1),
            ("invalid lifecycle", |r| {
                r.config.retired_at = Some(r.config.enabled_at)
            }),
            ("retired", |r| r.config.retired_at = Some(HEIGHT)),
            ("under minimum ratio", |r| {
                r.config.min_collateral_ratio_ppm = 999_999
            }),
            ("zero numerator", |r| r.config.oracle_price_numerator = 0),
            ("zero denominator", |r| {
                r.config.oracle_price_denominator = 0
            }),
            ("future oracle", |r| {
                r.config.oracle_submitted_at = HEIGHT + 1
            }),
            ("stale oracle", |r| r.config.oracle_max_age = 99),
            ("future attestation", |r| {
                r.config.attestation_created_at = HEIGHT + 1
            }),
            ("missing attestation", |r| {
                r.config.attestation_present = false
            }),
            ("stale attestation", |r| r.config.attestation_max_age = 199),
            ("disputed attestation", |r| {
                r.config.attestation_disputed = true
            }),
            ("insufficient collateral", |r| {
                r.config.collateral_amount = 1
            }),
            ("mint cap exceeded", |r| r.config.max_mint_per_epoch = 124),
            ("debt over bound", |r| {
                r.counters.total_debt = STABLECOIN_POSEIDON2_V8_MAX_VALUE
            }),
            ("future epoch", |r| r.counters.epoch_id += 1),
        ];
        for (label, mutate) in mutations {
            let mut row = fixture();
            mutate(&mut row);
            assert_parity(label, row, AssetOperationV1::Mint, 25);
        }
        for magnitude in [0, STABLECOIN_POSEIDON2_V8_MAX_VALUE + 1] {
            assert_parity(
                "magnitude rejected",
                fixture(),
                AssetOperationV1::Mint,
                magnitude,
            );
            assert_parity(
                "burn magnitude rejected",
                fixture(),
                AssetOperationV1::Burn,
                magnitude,
            );
        }
        assert_parity(
            "burn debt underflow",
            fixture(),
            AssetOperationV1::Burn,
            1_001,
        );
        let mut expired = fixture();
        expired.config.active = false;
        expired.config.retired_at = Some(HEIGHT);
        expired.config.attestation_present = false;
        expired.config.oracle_price_numerator = 0;
        assert_parity(
            "burn independent of mint policy",
            expired,
            AssetOperationV1::Burn,
            25,
        );
    }

    #[test]
    fn static_configuration_rejection_matrix_matches_original_v8() {
        let mutations: &[(&str, fn(&mut AssetPolicyV1))] = &[
            ("native asset", |r| r.config.asset_id = 0),
            ("max mint value bound", |r| {
                r.config.max_mint_per_epoch = STABLECOIN_POSEIDON2_V8_MAX_VALUE + 1
            }),
            ("collateral value bound", |r| {
                r.config.collateral_amount = STABLECOIN_POSEIDON2_V8_MAX_VALUE + 1
            }),
            ("minted value bound", |r| {
                r.counters.minted_in_epoch = STABLECOIN_POSEIDON2_V8_MAX_VALUE + 1
            }),
            ("debt value bound", |r| {
                r.counters.total_debt = STABLECOIN_POSEIDON2_V8_MAX_VALUE + 1
            }),
            ("enabled scalar bound", |r| {
                r.config.enabled_at = STABLECOIN_POSEIDON2_V8_MAX_SCALAR + 1
            }),
            ("retirement scalar bound", |r| {
                r.config.retired_at = Some(STABLECOIN_POSEIDON2_V8_MAX_SCALAR + 1)
            }),
            ("oracle submitted scalar bound", |r| {
                r.config.oracle_submitted_at = STABLECOIN_POSEIDON2_V8_MAX_SCALAR + 1
            }),
            ("oracle age scalar bound", |r| {
                r.config.oracle_max_age = STABLECOIN_POSEIDON2_V8_MAX_SCALAR + 1
            }),
            ("attestation created scalar bound", |r| {
                r.config.attestation_created_at = STABLECOIN_POSEIDON2_V8_MAX_SCALAR + 1
            }),
            ("attestation age scalar bound", |r| {
                r.config.attestation_max_age = STABLECOIN_POSEIDON2_V8_MAX_SCALAR + 1
            }),
            ("collateral scale scalar bound", |r| {
                r.config.collateral_scale = STABLECOIN_POSEIDON2_V8_MAX_SCALAR + 1
            }),
            ("epoch scalar bound", |r| {
                r.counters.epoch_id = STABLECOIN_POSEIDON2_V8_MAX_SCALAR + 1
            }),
            ("sequence scalar bound", |r| {
                r.counters.sequence = STABLECOIN_POSEIDON2_V8_MAX_SCALAR + 1
            }),
            ("minted above cap", |r| r.config.max_mint_per_epoch = 99),
            ("issuer absent", |r| {
                r.config.issuer_commitment = [Felt::ZERO; 7]
            }),
            ("admin absent", |r| {
                r.config.policy_admin_commitment = [Felt::ZERO; 7]
            }),
            ("oracle authority absent", |r| {
                r.config.oracle_authority_commitment = [Felt::ZERO; 7]
            }),
            ("attestation authority absent", |r| {
                r.config.attestation_authority_commitment = [Felt::ZERO; 7]
            }),
            ("collateral binding absent", |r| {
                r.config.locked_collateral_commitment = [Felt::ZERO; 7]
            }),
            ("role reuse", |r| {
                r.config.policy_admin_commitment = r.config.issuer_commitment
            }),
            ("decimals", |r| r.config.collateral_decimals = 19),
            ("scale", |r| r.config.collateral_scale += 1),
        ];
        for (label, mutate) in mutations {
            let mut row = fixture();
            mutate(&mut row);
            assert_parity(label, row, AssetOperationV1::Mint, 25);
            assert_parity(label, row, AssetOperationV1::Burn, 25);
        }
    }

    #[test]
    fn transfer_mint_and_burn_obey_independent_freeze_and_mint_controls() {
        let mut row = fixture();
        row.config.active = false;
        row.config.retired_at = Some(HEIGHT);
        row.mint_enabled = false;
        let state = registry(row);
        let transfer = prepare(&state, AssetOperationV1::Transfer, 0).unwrap();
        assert_eq!(transfer.before(), transfer.after());
        assert_eq!(transfer.after_root(), state.root());
        assert!(prepare(&state, AssetOperationV1::Burn, 25).is_ok());
        assert_eq!(
            prepare(&state, AssetOperationV1::Mint, 25),
            Err(AssetRegistryErrorV1::MintDisabled)
        );
        assert_eq!(
            prepare(&state, AssetOperationV1::Transfer, 1),
            Err(AssetRegistryErrorV1::TransferMagnitude)
        );
        row.frozen = true;
        let frozen = registry(row);
        for (operation, amount) in [
            (AssetOperationV1::Transfer, 0),
            (AssetOperationV1::Mint, 25),
            (AssetOperationV1::Burn, 25),
        ] {
            assert_eq!(
                prepare(&frozen, operation, amount),
                Err(AssetRegistryErrorV1::Frozen)
            );
        }
    }

    #[test]
    fn current_chain_parent_policy_and_credentials_are_mandatory() {
        let state = registry(fixture());
        let row = fixture();
        let call = |context, asset, version, credentials| {
            state.prepare_accounting(
                context,
                asset,
                version,
                credentials,
                AssetOperationV1::Transfer,
                0,
            )
        };
        let context = state.context();
        let mut bad = context;
        bad.chain_id[0] ^= 1;
        assert_eq!(
            call(bad, 1001, 7, row.credential_root),
            Err(AssetRegistryErrorV1::ChainMismatch)
        );
        bad = context;
        bad.parent_height += 1;
        assert_eq!(
            call(bad, 1001, 7, row.credential_root),
            Err(AssetRegistryErrorV1::ParentMismatch)
        );
        bad = context;
        bad.registry_root[0] += Felt::ONE;
        assert_eq!(
            call(bad, 1001, 7, row.credential_root),
            Err(AssetRegistryErrorV1::RootMismatch)
        );
        assert_eq!(
            call(context, 1001, 6, row.credential_root),
            Err(AssetRegistryErrorV1::PolicyVersionMismatch)
        );
        assert_eq!(
            call(context, 1001, 7, tagged(801)),
            Err(AssetRegistryErrorV1::CredentialRootMismatch)
        );
        assert_eq!(
            call(context, 1017, 7, row.credential_root),
            Err(AssetRegistryErrorV1::UnknownAsset)
        );
        assert_eq!(
            call(context, 0, 7, row.credential_root),
            Err(StablecoinPoseidon2V8Error::ZeroOrNativeAsset.into())
        );
    }

    #[test]
    fn accounting_updates_counters_atomically_and_rejects_stale_plans() {
        let mut state = registry(fixture());
        let original = state.clone();
        let mint = prepare(&state, AssetOperationV1::Mint, 25).unwrap();
        let burn = prepare(&state, AssetOperationV1::Burn, 25).unwrap();
        let replay = mint.clone();
        let next_root = mint.after_root();
        assert_eq!(state, original, "preparation must not mutate");
        state.apply_accounting_after_proof(mint).unwrap();
        assert_eq!(state.root(), next_root);
        assert_eq!(state.row(1001).unwrap().counters.total_debt, 1_025);
        assert_eq!(state.row(1001).unwrap().counters.minted_in_epoch, 125);
        assert_eq!(state.row(1001).unwrap().counters.sequence, 10);
        let after = state.clone();
        assert_eq!(
            state.apply_accounting_after_proof(replay),
            Err(AssetRegistryErrorV1::RootMismatch)
        );
        assert_eq!(
            state.apply_accounting_after_proof(burn),
            Err(AssetRegistryErrorV1::RootMismatch)
        );
        assert_eq!(state, after, "failed mutation must leave state intact");
        let burn = prepare(&state, AssetOperationV1::Burn, 25).unwrap();
        state.apply_accounting_after_proof(burn).unwrap();
        assert_eq!(state.row(1001).unwrap().counters.total_debt, 1_000);
        assert_eq!(
            state.row(1001).unwrap().counters.minted_in_epoch,
            125,
            "burn does not refund epoch mint cap"
        );
    }

    #[test]
    fn full_config_counters_credentials_and_controls_are_authenticated() {
        let before = fixture();
        let leaf = asset_policy_leaf_v1(&before);
        let mutations: &[fn(&mut AssetPolicyV1)] = &[
            |r| r.config.asset_id += 16,
            |r| r.config.policy_version += 1,
            |r| r.config.policy_admin_commitment[0] += Felt::ONE,
            |r| r.config.oracle_authority_commitment[0] += Felt::ONE,
            |r| r.config.attestation_authority_commitment[0] += Felt::ONE,
            |r| r.config.locked_collateral_commitment[0] += Felt::ONE,
            |r| r.config.collateral_amount += 1,
            |r| r.config.collateral_asset_id += 1,
            |r| r.config.oracle_submitted_at += 1,
            |r| r.config.attestation_created_at += 1,
            |r| r.counters.total_debt += 1,
            |r| r.counters.minted_in_epoch += 1,
            |r| r.counters.epoch_id += 1,
            |r| r.counters.sequence += 1,
            |r| r.credential_root[0] += Felt::ONE,
            |r| r.credential_depth = 16,
            |r| r.frozen = true,
            |r| r.mint_enabled = false,
        ];
        for mutate in mutations {
            let mut row = before;
            mutate(&mut row);
            assert_ne!(asset_policy_leaf_v1(&row), leaf);
        }
        for depth in [4, 8, 16] {
            let mut row = fixture();
            row.credential_depth = depth;
            let state = registry(row);
            assert_eq!(
                asset_registry_membership_root_v1(&row, &state.membership(1001).unwrap()).unwrap(),
                state.root()
            );
        }
        let mut wrong = registry(before).membership(1001).unwrap();
        wrong[2][0] += Felt::ONE;
        assert_ne!(
            asset_registry_membership_root_v1(&before, &wrong).unwrap(),
            registry(before).root()
        );
    }

    #[test]
    fn rows_reject_native_aliases_collisions_and_invalid_credentials() {
        assert_eq!(
            AssetRegistryV1::from_rows([0; 32], HEIGHT, &[]),
            Err(AssetRegistryErrorV1::ChainIdZero)
        );
        let mut row = fixture();
        row.config.asset_id = 0;
        assert_eq!(
            AssetRegistryV1::from_rows(CHAIN, HEIGHT, &[row]),
            Err(StablecoinPoseidon2V8Error::ZeroOrNativeAsset.into())
        );
        row = fixture();
        row.config.asset_id += 16;
        assert_eq!(
            AssetRegistryV1::from_rows(CHAIN, HEIGHT, &[fixture(), row]),
            Err(AssetRegistryErrorV1::AssetSlotCollision)
        );
        assert_eq!(
            AssetRegistryV1::from_rows(CHAIN, HEIGHT, &[fixture(), fixture()]),
            Err(AssetRegistryErrorV1::AssetSlotCollision)
        );
        for depth in [0, 1, 3, 5, 9, 15, 17, 32] {
            row = fixture();
            row.credential_depth = depth;
            assert_eq!(
                validate_asset_policy_v1(&row),
                Err(AssetRegistryErrorV1::CredentialDepth)
            );
        }
        row = fixture();
        row.credential_root = [Felt::ZERO; 7];
        assert_eq!(
            validate_asset_policy_v1(&row),
            Err(AssetRegistryErrorV1::CredentialRootZero)
        );
        row = fixture();
        row.counters.epoch_id += 1;
        assert_eq!(
            AssetRegistryV1::from_rows(CHAIN, HEIGHT, &[row]),
            Err(StablecoinPoseidon2V8Error::FutureEpoch.into())
        );
        assert_eq!(
            asset_registry_node_v1(4, &tagged(1), &tagged(2)),
            Err(AssetRegistryErrorV1::InvalidTreeLevel)
        );
    }

    #[test]
    fn all_sixteen_asset_slots_support_exact_membership_without_native() {
        let rows: [AssetPolicyV1; ASSET_REGISTRY_CAP_V1] = core::array::from_fn(|index| {
            let mut row = fixture();
            row.config.asset_id = 16 + index as u32;
            row
        });
        let state = AssetRegistryV1::from_rows(CHAIN, HEIGHT, &rows).unwrap();
        for row in &rows {
            assert_eq!(
                asset_registry_membership_root_v1(
                    row,
                    &state.membership(row.config.asset_id).unwrap()
                )
                .unwrap(),
                state.root()
            );
        }
        assert!(state.row(0).is_err());
    }

    #[test]
    fn policy_updates_require_current_context_next_version_and_unchanged_supply() {
        let mut state = registry(fixture());
        let ordinary = prepare(&state, AssetOperationV1::Transfer, 0).unwrap();
        let mut next = fixture();
        next.config.policy_version += 1;
        next.credential_root = tagged(801);
        next.frozen = true;
        let update = state
            .prepare_policy_replacement(state.context(), 1001, next)
            .unwrap();
        let replay = update.clone();
        let next_root = update.after_root();
        state
            .apply_policy_replacement_after_authorization(update)
            .unwrap();
        assert_eq!(state.root(), next_root);
        assert_eq!(state.row(1001).unwrap().counters, fixture().counters);
        assert_eq!(
            state.apply_policy_replacement_after_authorization(replay),
            Err(AssetRegistryErrorV1::RootMismatch)
        );
        assert_eq!(
            state.apply_accounting_after_proof(ordinary),
            Err(AssetRegistryErrorV1::RootMismatch)
        );
        assert_eq!(
            prepare(&state, AssetOperationV1::Transfer, 0),
            Err(AssetRegistryErrorV1::Frozen)
        );
        let state = registry(fixture());
        next = fixture();
        assert_eq!(
            state.prepare_policy_replacement(state.context(), 1001, next),
            Err(AssetRegistryErrorV1::ReplacementVersionMismatch)
        );
        next.config.policy_version += 2;
        assert_eq!(
            state.prepare_policy_replacement(state.context(), 1001, next),
            Err(AssetRegistryErrorV1::ReplacementVersionMismatch)
        );
        next.config.policy_version -= 1;
        next.counters.total_debt += 1;
        assert_eq!(
            state.prepare_policy_replacement(state.context(), 1001, next),
            Err(AssetRegistryErrorV1::ReplacementCountersMismatch)
        );
        next = fixture();
        next.config.policy_version += 1;
        next.config.asset_id += 16;
        assert_eq!(
            state.prepare_policy_replacement(state.context(), 1001, next),
            Err(AssetRegistryErrorV1::ReplacementAssetMismatch)
        );
    }

    #[test]
    fn controls_updates_preserve_issuer_roles_version_and_supply_and_stale_proofs_fail() {
        let mut state = registry(fixture());
        let transfer = prepare(&state, AssetOperationV1::Transfer, 0).unwrap();
        let update = state
            .prepare_controls_update(
                state.context(),
                1001,
                AssetControlsV1 {
                    credential_root: tagged(801),
                    credential_depth: 16,
                    frozen: true,
                    mint_enabled: false,
                },
            )
            .unwrap();
        assert_eq!(update.after().config, fixture().config);
        assert_eq!(update.after().counters, fixture().counters);
        let expected_root = update.after_root();
        let replay = update.clone();
        state
            .apply_controls_update_after_authorization(update)
            .unwrap();
        assert_eq!(state.root(), expected_root);
        assert_eq!(
            prepare(&state, AssetOperationV1::Transfer, 0),
            Err(AssetRegistryErrorV1::Frozen)
        );
        assert_eq!(
            state.apply_controls_update_after_authorization(replay),
            Err(AssetRegistryErrorV1::RootMismatch)
        );
        assert_eq!(
            state.apply_accounting_after_proof(transfer),
            Err(AssetRegistryErrorV1::RootMismatch)
        );
        let thaw = state
            .prepare_controls_update(
                state.context(),
                1001,
                AssetControlsV1 {
                    credential_root: tagged(801),
                    credential_depth: 16,
                    frozen: false,
                    mint_enabled: true,
                },
            )
            .unwrap();
        state
            .apply_controls_update_after_authorization(thaw)
            .unwrap();
        assert!(prepare(&state, AssetOperationV1::Transfer, 0).is_ok());
        assert!(prepare(&state, AssetOperationV1::Mint, 25).is_ok());
        assert_eq!(state.row(1001).unwrap().config, fixture().config);
        assert_eq!(state.row(1001).unwrap().counters, fixture().counters);
        assert_eq!(
            state.prepare_controls_update(
                state.context(),
                1001,
                AssetControlsV1 {
                    credential_root: [Felt::ZERO; 7],
                    ..fixture().controls()
                }
            ),
            Err(AssetRegistryErrorV1::CredentialRootZero)
        );
        assert_eq!(
            state.prepare_controls_update(
                state.context(),
                1001,
                AssetControlsV1 {
                    credential_depth: 3,
                    ..fixture().controls()
                }
            ),
            Err(AssetRegistryErrorV1::CredentialDepth)
        );
        assert_eq!(
            state.prepare_controls_update(state.context(), 0, fixture().controls()),
            Err(StablecoinPoseidon2V8Error::ZeroOrNativeAsset.into())
        );
    }

    #[test]
    fn advancing_parent_expires_prepared_plans_and_resets_epoch_cap() {
        let mut state = registry(fixture());
        let pending = prepare(&state, AssetOperationV1::Mint, 25).unwrap();
        let context = state.context();
        let root = state.root();
        state
            .advance_parent_after_chain_verification(context, HEIGHT + 1)
            .unwrap();
        assert_eq!(state.root(), root);
        assert_eq!(
            state.apply_accounting_after_proof(pending),
            Err(AssetRegistryErrorV1::ParentMismatch)
        );
        assert_eq!(
            state.advance_parent_after_chain_verification(context, HEIGHT + 2),
            Err(AssetRegistryErrorV1::ParentMismatch)
        );
        let mut row = fixture();
        row.config.oracle_max_age = 10_000;
        row.config.attestation_max_age = 10_000;
        row.config.max_mint_per_epoch = 100;
        let mut state = registry(row);
        state
            .advance_parent_after_chain_verification(state.context(), 12_288)
            .unwrap();
        let mint = prepare(&state, AssetOperationV1::Mint, 25).unwrap();
        assert_eq!(mint.after().counters.minted_in_epoch, 25);
        assert_eq!(mint.after().counters.total_debt, 1_025);
        assert_eq!(mint.after().counters.epoch_id, 3);
    }
}
