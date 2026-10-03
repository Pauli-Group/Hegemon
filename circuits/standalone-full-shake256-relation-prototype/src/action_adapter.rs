//! Fail-closed fixed-slot V5/Delta action adapter.
//!
//! This is prospective source, not a production route. It deliberately has no
//! compatibility path for the deployed 48-byte compact-list action: V5/Delta
//! carries the exact 853-byte statement with fixed ordered 2x56-byte slots.

use core::fmt;

use super::{
    ActivationBinding, CANONICAL_STATEMENT_BYTES, DIGEST_BYTES, FIELD_MODULUS, FullStatement,
    MAX_INPUTS, MAX_NOTE_VALUE, MAX_OUTPUTS, NATIVE_ASSET_ID, PADDING_ASSET_ID,
    RESERVED_REDUCED_PADDING_ASSET_ID, StablecoinBinding, StatementDecodeError,
    decode_canonical_statement, expected_balance_tag,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablePolicyAuthority {
    pub manifest_generation: u64,
    pub asset_id: u64,
    pub policy_version: u32,
    pub policy_hash: [u8; DIGEST_BYTES],
    pub oracle_commitment: [u8; DIGEST_BYTES],
    pub attestation_commitment: [u8; DIGEST_BYTES],
    pub active_from_epoch: u64,
    pub retired_at_epoch: Option<u64>,
    pub accounted_epoch: u64,
    pub minted_in_epoch: u64,
    pub max_mint_per_epoch: u64,
}

impl StablePolicyAuthority {
    fn matches(&self, binding: &StablecoinBinding, epoch: u64) -> bool {
        self.asset_id == binding.asset_id
            && self.policy_version == binding.policy_version
            && self.policy_hash == binding.policy_hash
            && self.oracle_commitment == binding.oracle_commitment
            && self.attestation_commitment == binding.attestation_commitment
            && self.active_from_epoch <= epoch
            && self.retired_at_epoch.is_none_or(|retired| epoch < retired)
    }

    fn identity(&self) -> StablePolicyIdentity {
        StablePolicyIdentity {
            manifest_generation: self.manifest_generation,
            asset_id: self.asset_id,
            policy_version: self.policy_version,
            policy_hash: self.policy_hash,
            oracle_commitment: self.oracle_commitment,
            attestation_commitment: self.attestation_commitment,
            active_from_epoch: self.active_from_epoch,
            retired_at_epoch: self.retired_at_epoch,
            max_mint_per_epoch: self.max_mint_per_epoch,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StablePolicyIdentity {
    manifest_generation: u64,
    asset_id: u64,
    policy_version: u32,
    policy_hash: [u8; DIGEST_BYTES],
    oracle_commitment: [u8; DIGEST_BYTES],
    attestation_commitment: [u8; DIGEST_BYTES],
    active_from_epoch: u64,
    retired_at_epoch: Option<u64>,
    max_mint_per_epoch: u64,
}

/// An authenticated snapshot containing only policies live in `current_epoch`.
/// The state transition that rolls an epoch must reset every included counter
/// before this value can be constructed.
#[derive(Clone, Debug)]
pub struct RouteAuthority<'a> {
    activation: &'a ActivationBinding,
    current_epoch: u64,
    manifest_generation: u64,
    active_stable_policies: &'a [StablePolicyAuthority],
}

impl<'a> RouteAuthority<'a> {
    pub fn from_active_snapshot(
        activation: &'a ActivationBinding,
        current_epoch: u64,
        manifest_generation: u64,
        active_stable_policies: &'a [StablePolicyAuthority],
    ) -> Result<Self, ActionAdapterError> {
        let authority = Self {
            activation,
            current_epoch,
            manifest_generation,
            active_stable_policies,
        };
        validate_route_authority(&authority)?;
        Ok(authority)
    }
}

/// Apply this update atomically only after the proof and every other action
/// gate accept. Reorg rollback must restore `minted_before` for the same epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableMintUpdate {
    /// Non-authoritative lookup hint. Commit/rollback searches and compares
    /// the full identity; manifest reordering cannot redirect the update.
    policy_index_hint: usize,
    policy: StablePolicyIdentity,
    epoch: u64,
    minted_before: u64,
    minted_delta: u64,
    minted_after: u64,
}

impl StableMintUpdate {
    pub const fn policy_index_hint(&self) -> usize {
        self.policy_index_hint
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn minted_before(&self) -> u64 {
        self.minted_before
    }

    pub const fn minted_after(&self) -> u64 {
        self.minted_after
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptedAction {
    statement: FullStatement,
    stable_mint_update: Option<StableMintUpdate>,
}

impl AdaptedAction {
    pub const fn statement(&self) -> &FullStatement {
        &self.statement
    }
}

/// Receipt produced only after the canonical stable-policy transition is
/// applied. Persist this alongside action acceptance so a reorg can perform
/// the inverse compare-and-swap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedAction {
    statement: FullStatement,
    stable_mint_update: Option<StableMintUpdate>,
}

impl CommittedAction {
    pub const fn statement(&self) -> &FullStatement {
        &self.statement
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionAdapterError {
    Decode(StatementDecodeError),
    AuthorityConfiguration,
    Activation,
    Shape,
    InactiveSlot(&'static str, usize),
    ActiveSlot(&'static str, usize),
    DuplicateNullifier,
    Fee,
    AssetSlots,
    ValueBalance,
    BalanceTag,
    StablecoinCanonicality,
    StablecoinUnauthorized,
    StablecoinEpochState,
    StablecoinMintOverflow,
    StablecoinEpochCap,
    StablecoinCas,
}

impl fmt::Display for ActionAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ActionAdapterError {}

/// Decode and authorize the complete fixed-slot action before parsing or
/// verifying its proof. Exact proof parsing remains a separate hard gate.
pub fn adapt_fixed_slot_action(
    payload: &[u8],
    authority: &RouteAuthority<'_>,
) -> Result<AdaptedAction, ActionAdapterError> {
    validate_route_authority(authority)?;
    if payload.len() != CANONICAL_STATEMENT_BYTES {
        return Err(ActionAdapterError::Decode(StatementDecodeError::Length {
            expected: CANONICAL_STATEMENT_BYTES,
            actual: payload.len(),
        }));
    }
    let statement = decode_canonical_statement(payload).map_err(ActionAdapterError::Decode)?;
    if !authority.activation.is_target_profile() {
        return Err(ActionAdapterError::AuthorityConfiguration);
    }
    if &statement.activation != authority.activation {
        return Err(ActionAdapterError::Activation);
    }

    if !statement.input_flags.iter().any(|active| *active)
        || !statement.output_flags.iter().any(|active| *active)
    {
        return Err(ActionAdapterError::Shape);
    }
    for index in 0..MAX_INPUTS {
        if statement.input_flags[index] {
            if statement.nullifiers[index] == [0; DIGEST_BYTES] {
                return Err(ActionAdapterError::ActiveSlot("nullifier", index));
            }
        } else if statement.nullifiers[index] != [0; DIGEST_BYTES] {
            return Err(ActionAdapterError::InactiveSlot("nullifier", index));
        }
    }
    for index in 0..MAX_OUTPUTS {
        if statement.output_flags[index] {
            if statement.commitments[index] == [0; DIGEST_BYTES] {
                return Err(ActionAdapterError::ActiveSlot("commitment", index));
            }
            if statement.ciphertext_hashes[index] == [0; DIGEST_BYTES] {
                return Err(ActionAdapterError::ActiveSlot("ciphertext", index));
            }
        } else {
            if statement.commitments[index] != [0; DIGEST_BYTES] {
                return Err(ActionAdapterError::InactiveSlot("commitment", index));
            }
            if statement.ciphertext_hashes[index] != [0; DIGEST_BYTES] {
                return Err(ActionAdapterError::InactiveSlot("ciphertext", index));
            }
        }
    }
    if statement.input_flags == [true, true] && statement.nullifiers[0] == statement.nullifiers[1] {
        return Err(ActionAdapterError::DuplicateNullifier);
    }
    if statement.value_balance.negative || statement.value_balance.magnitude != 0 {
        return Err(ActionAdapterError::ValueBalance);
    }
    if statement.fee > MAX_NOTE_VALUE {
        return Err(ActionAdapterError::Fee);
    }
    validate_asset_slots(&statement)?;
    if statement.balance_tag != expected_balance_tag(&statement) {
        return Err(ActionAdapterError::BalanceTag);
    }

    let stable_mint_update = authorize_stablecoin(&statement, authority)?;
    Ok(AdaptedAction {
        statement,
        stable_mint_update,
    })
}

fn authorize_stablecoin(
    statement: &FullStatement,
    authority: &RouteAuthority<'_>,
) -> Result<Option<StableMintUpdate>, ActionAdapterError> {
    let stable = &statement.stablecoin;
    if !stable.enabled {
        if stable != &StablecoinBinding::default() {
            return Err(ActionAdapterError::StablecoinCanonicality);
        }
        return Ok(None);
    }
    if stable.issuance_delta.magnitude == 0 || stable.policy_version == 0 {
        return Err(ActionAdapterError::StablecoinCanonicality);
    }
    let (policy_index, policy) = authority
        .active_stable_policies
        .iter()
        .enumerate()
        .find(|(_, policy)| policy.matches(stable, authority.current_epoch))
        .ok_or(ActionAdapterError::StablecoinUnauthorized)?;
    if policy.accounted_epoch != authority.current_epoch {
        return Err(ActionAdapterError::StablecoinEpochState);
    }

    // `inputs - outputs` is the proved issuance delta. A negative delta mints;
    // a positive delta burns. Burns still carry an opaque zero-delta snapshot
    // transition so commit rechecks policy identity/generation/epoch under the
    // same state lock and cannot race manifest retirement.
    let minted_delta = if stable.issuance_delta.negative {
        stable.issuance_delta.magnitude
    } else {
        0
    };
    let minted_after = policy
        .minted_in_epoch
        .checked_add(minted_delta)
        .ok_or(ActionAdapterError::StablecoinMintOverflow)?;
    if minted_after > policy.max_mint_per_epoch {
        return Err(ActionAdapterError::StablecoinEpochCap);
    }
    Ok(Some(StableMintUpdate {
        policy_index_hint: policy_index,
        policy: policy.identity(),
        epoch: authority.current_epoch,
        minted_before: policy.minted_in_epoch,
        minted_delta,
        minted_after,
    }))
}

fn validate_route_authority(authority: &RouteAuthority<'_>) -> Result<(), ActionAdapterError> {
    if !authority.activation.is_target_profile() {
        return Err(ActionAdapterError::AuthorityConfiguration);
    }
    if authority.manifest_generation == 0 {
        return Err(ActionAdapterError::AuthorityConfiguration);
    }
    for (index, policy) in authority.active_stable_policies.iter().enumerate() {
        if policy.manifest_generation != authority.manifest_generation
            || policy.policy_version == 0
            || policy.policy_hash == [0; DIGEST_BYTES]
            || policy.oracle_commitment == [0; DIGEST_BYTES]
            || policy.attestation_commitment == [0; DIGEST_BYTES]
            || policy.accounted_epoch != authority.current_epoch
            || policy.minted_in_epoch > policy.max_mint_per_epoch
            || policy.active_from_epoch > authority.current_epoch
            || policy
                .retired_at_epoch
                .is_some_and(|retired| authority.current_epoch >= retired)
        {
            return Err(ActionAdapterError::AuthorityConfiguration);
        }
        if authority.active_stable_policies[..index]
            .iter()
            .any(|other| {
                (other.asset_id, other.policy_version) == (policy.asset_id, policy.policy_version)
                    || other.identity() == policy.identity()
            })
        {
            return Err(ActionAdapterError::AuthorityConfiguration);
        }
    }
    Ok(())
}

/// Compare-and-swap a mint update against live canonical state. Callers must
/// invoke updates sequentially in canonical action order inside the same state
/// transaction that records proof/action acceptance.
fn apply_stable_mint_update(
    policies: &mut [StablePolicyAuthority],
    update: &StableMintUpdate,
) -> Result<(), ActionAdapterError> {
    let policy = policies
        .iter_mut()
        .find(|policy| policy.identity() == update.policy)
        .ok_or(ActionAdapterError::StablecoinCas)?;
    if policy.accounted_epoch != update.epoch
        || policy.minted_in_epoch != update.minted_before
        || update.minted_before.checked_add(update.minted_delta) != Some(update.minted_after)
        || update.minted_after > policy.max_mint_per_epoch
    {
        return Err(ActionAdapterError::StablecoinCas);
    }
    policy.minted_in_epoch = update.minted_after;
    Ok(())
}

/// Reorg rollback is also a CAS: it cannot erase later canonical mints.
fn rollback_stable_mint_update(
    policies: &mut [StablePolicyAuthority],
    update: &StableMintUpdate,
) -> Result<(), ActionAdapterError> {
    let policy = policies
        .iter_mut()
        .find(|policy| policy.identity() == update.policy)
        .ok_or(ActionAdapterError::StablecoinCas)?;
    if policy.accounted_epoch != update.epoch
        || policy.minted_in_epoch != update.minted_after
        || update.minted_before.checked_add(update.minted_delta) != Some(update.minted_after)
    {
        return Err(ActionAdapterError::StablecoinCas);
    }
    policy.minted_in_epoch = update.minted_before;
    Ok(())
}

/// Consume an adapted action and obligatorily apply its mint transition before
/// returning a receipt. The production state transaction must make this call
/// atomic with proof/action acceptance.
pub fn commit_adapted_action(
    policies: &mut [StablePolicyAuthority],
    action: AdaptedAction,
) -> Result<CommittedAction, ActionAdapterError> {
    match (&action.statement.stablecoin, &action.stable_mint_update) {
        (stable, None) if stable.enabled => return Err(ActionAdapterError::StablecoinCas),
        (stable, Some(_)) if !stable.enabled => return Err(ActionAdapterError::StablecoinCas),
        (stable, Some(update)) => {
            let expected_delta = if stable.issuance_delta.negative {
                stable.issuance_delta.magnitude
            } else {
                0
            };
            if update.minted_delta != expected_delta
                || update.policy.asset_id != stable.asset_id
                || update.policy.policy_version != stable.policy_version
                || update.policy.policy_hash != stable.policy_hash
                || update.policy.oracle_commitment != stable.oracle_commitment
                || update.policy.attestation_commitment != stable.attestation_commitment
            {
                return Err(ActionAdapterError::StablecoinCas);
            }
        }
        (_, None) => {}
    }
    if let Some(update) = &action.stable_mint_update {
        apply_stable_mint_update(policies, update)?;
    }
    Ok(CommittedAction {
        statement: action.statement,
        stable_mint_update: action.stable_mint_update,
    })
}

/// Consume a persisted receipt and reverse exactly its authenticated mint
/// transition. Later canonical mints make this fail rather than erase state.
pub fn rollback_committed_action(
    policies: &mut [StablePolicyAuthority],
    action: CommittedAction,
) -> Result<FullStatement, ActionAdapterError> {
    if let Some(update) = &action.stable_mint_update {
        rollback_stable_mint_update(policies, update)?;
    }
    Ok(action.statement)
}

fn validate_asset_slots(statement: &FullStatement) -> Result<(), ActionAdapterError> {
    let slots = statement.balance_slot_asset_ids;
    if slots[0] != NATIVE_ASSET_ID {
        return Err(ActionAdapterError::AssetSlots);
    }
    let mut padding_started = false;
    let mut previous = NATIVE_ASSET_ID;
    for asset in slots.into_iter().skip(1) {
        if asset == PADDING_ASSET_ID {
            padding_started = true;
            continue;
        }
        if padding_started
            || asset == NATIVE_ASSET_ID
            || asset >= FIELD_MODULUS
            || asset == RESERVED_REDUCED_PADDING_ASSET_ID
            || asset <= previous
        {
            return Err(ActionAdapterError::AssetSlots);
        }
        previous = asset;
    }
    if statement.stablecoin.enabled
        && !statement
            .balance_slot_asset_ids
            .contains(&statement.stablecoin.asset_id)
    {
        return Err(ActionAdapterError::StablecoinCanonicality);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PADDING_ASSET_ID, SignedAmount, encode_canonical_statement, mask_fixture};

    fn authority<'a>(
        activation: &'a ActivationBinding,
        policies: &'a [StablePolicyAuthority],
    ) -> RouteAuthority<'a> {
        RouteAuthority::from_active_snapshot(
            activation,
            7,
            policies
                .first()
                .map_or(11, |policy| policy.manifest_generation),
            policies,
        )
        .unwrap()
    }

    #[test]
    fn all_masks_use_fixed_ordered_slots_without_prefix_compaction() {
        for mask in 0u8..16 {
            let (statement, _) = mask_fixture(mask);
            let activation = statement.activation.clone();
            let bytes = encode_canonical_statement(&statement).unwrap();
            let accepted = adapt_fixed_slot_action(&bytes, &authority(&activation, &[])).is_ok();
            let expected = mask & 0b0011 != 0 && mask & 0b1100 != 0;
            assert_eq!(accepted, expected, "mask {mask:04b}");
        }
    }

    #[test]
    fn inactive_fixed_slots_and_full_activation_are_exact() {
        let (statement, _) = mask_fixture(0b0101);
        let activation = statement.activation.clone();
        let expected = authority(&activation, &[]);
        let bytes = encode_canonical_statement(&statement).unwrap();
        adapt_fixed_slot_action(&bytes, &expected).unwrap();

        for range in [126..182, 238..294, 350..406] {
            let mut changed = bytes;
            changed[range.start] ^= 1;
            assert!(matches!(
                adapt_fixed_slot_action(&changed, &expected),
                Err(ActionAdapterError::InactiveSlot(_, 1))
            ));
        }
        for offset in 701..CANONICAL_STATEMENT_BYTES {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(matches!(
                adapt_fixed_slot_action(&changed, &expected),
                Err(ActionAdapterError::Activation)
            ));
        }
        let mut changed = bytes;
        changed[645] ^= 1;
        assert!(matches!(
            adapt_fixed_slot_action(&changed, &expected),
            Err(ActionAdapterError::BalanceTag)
        ));
    }

    fn stable_action() -> (FullStatement, StablePolicyAuthority) {
        let (mut statement, _) = mask_fixture(0b1111);
        statement.balance_slot_asset_ids = [0, 7, PADDING_ASSET_ID, PADDING_ASSET_ID];
        statement.stablecoin = StablecoinBinding {
            enabled: true,
            asset_id: 7,
            policy_version: 3,
            issuance_delta: SignedAmount {
                negative: true,
                magnitude: 10,
            },
            policy_hash: [0xb1; DIGEST_BYTES],
            oracle_commitment: [0xb2; DIGEST_BYTES],
            attestation_commitment: [0xb3; DIGEST_BYTES],
        };
        statement.balance_tag = expected_balance_tag(&statement);
        let policy = StablePolicyAuthority {
            manifest_generation: 11,
            asset_id: statement.stablecoin.asset_id,
            policy_version: statement.stablecoin.policy_version,
            policy_hash: statement.stablecoin.policy_hash,
            oracle_commitment: statement.stablecoin.oracle_commitment,
            attestation_commitment: statement.stablecoin.attestation_commitment,
            active_from_epoch: 2,
            retired_at_epoch: None,
            accounted_epoch: 7,
            minted_in_epoch: 90,
            max_mint_per_epoch: 100,
        };
        (statement, policy)
    }

    #[test]
    fn stable_policy_is_authoritative_and_epoch_minting_is_cumulative() {
        let (mut statement, policy) = stable_action();
        let activation = statement.activation.clone();
        let policies = [policy.clone()];
        let adapted = adapt_fixed_slot_action(
            &encode_canonical_statement(&statement).unwrap(),
            &authority(&activation, &policies),
        )
        .unwrap();
        let update = adapted.stable_mint_update.clone().unwrap();
        assert_eq!(update.minted_after(), 100);
        let mut live = [policy.clone()];
        let committed = commit_adapted_action(&mut live, adapted).unwrap();
        assert!(matches!(
            apply_stable_mint_update(&mut live, &update),
            Err(ActionAdapterError::StablecoinCas)
        ));
        rollback_committed_action(&mut live, committed).unwrap();
        assert_eq!(live[0].minted_in_epoch, 90);

        let mut over_cap = policy.clone();
        over_cap.minted_in_epoch = 91;
        assert!(matches!(
            adapt_fixed_slot_action(
                &encode_canonical_statement(&statement).unwrap(),
                &authority(&activation, &[over_cap]),
            ),
            Err(ActionAdapterError::StablecoinEpochCap)
        ));

        statement.stablecoin.issuance_delta.negative = false;
        statement.balance_tag = expected_balance_tag(&statement);
        let adapted = adapt_fixed_slot_action(
            &encode_canonical_statement(&statement).unwrap(),
            &authority(&activation, &[policy.clone()]),
        )
        .unwrap();
        assert!(adapted.stable_mint_update.is_some());
        let stale_burn = adapted.clone();
        let mut stale_live = [policy.clone()];
        stale_live[0].oracle_commitment[0] ^= 1;
        assert!(matches!(
            commit_adapted_action(&mut stale_live, stale_burn),
            Err(ActionAdapterError::StablecoinCas)
        ));
        let mut live = [policy];
        let committed = commit_adapted_action(&mut live, adapted).unwrap();
        assert_eq!(live[0].minted_in_epoch, 90);
        rollback_committed_action(&mut live, committed).unwrap();
        assert_eq!(live[0].minted_in_epoch, 90);
    }

    #[test]
    fn update_capability_and_manifest_snapshot_fail_closed() {
        let (statement, policy) = stable_action();
        let activation = statement.activation.clone();
        let policies = [policy.clone()];
        let adapted = adapt_fixed_slot_action(
            &encode_canonical_statement(&statement).unwrap(),
            &authority(&activation, &policies),
        )
        .unwrap();
        let update = adapted.stable_mint_update.clone().unwrap();

        let mut forged = update.clone();
        forged.minted_after = forged.minted_before;
        let mut live = [policy.clone()];
        assert!(matches!(
            apply_stable_mint_update(&mut live, &forged),
            Err(ActionAdapterError::StablecoinCas)
        ));

        forged = update;
        forged.minted_delta = 1;
        assert!(matches!(
            apply_stable_mint_update(&mut live, &forged),
            Err(ActionAdapterError::StablecoinCas)
        ));

        let mut wrong_generation = policy.clone();
        wrong_generation.manifest_generation += 1;
        assert!(matches!(
            RouteAuthority::from_active_snapshot(
                &activation,
                7,
                policy.manifest_generation,
                &[policy, wrong_generation],
            ),
            Err(ActionAdapterError::AuthorityConfiguration)
        ));
    }
}
