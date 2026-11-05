//! Deterministic account transitions. Proof verification is mandatory at the
//! account/pool boundary; the integrating node must also validate its shared
//! nullifiers, note references, action identity and full block commitments.
use crate::account_tree::AccountTree;
use crate::*;
use codec::{Decode, Encode};
use crypto::hash384::{ProofCommitment48, RulesHash48};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const MAX_REWARD_PROOF_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_REWARD_CARRIER_BYTES: usize = MAX_REWARD_PROOF_BYTES + 8192;
pub const MAX_RECIPIENT_BYTES: usize = 2_500;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AccountChainContext {
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub genesis_config_hash: RulesHash48,
}
impl AccountChainContext {
    pub fn validate(&self, genesis: &RewardAccountsGenesis) -> Result<(), RewardAccountsError> {
        if self.chain_id == [0; 32]
            || self.genesis_hash == [0; 32]
            || self.genesis_config_hash.as_bytes() != &genesis.commitment()?
        {
            return Err(RewardAccountsError::InvalidContext);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AccountClaim {
    pub context: AccountChainContext,
    pub account: AccountPolicyId48,
    pub policy_generation: u64,
    pub sequence: u64,
    pub amount: u64,
    /// Includes a transaction tip exactly once, if supplied.
    pub fee: u64,
    /// Complete network-aware shielded recipient envelope, never just an HRP.
    pub recipient: BoundedVec<u8, MAX_RECIPIENT_BYTES>,
    /// Hash of the exact payout statement and encrypted-output binding.
    pub payout_binding: ProofCommitment48,
}
impl AccountClaim {
    /// Pre-output operation binding; payout_binding is filled after creating
    /// the output statement, so hashing it here would create a cycle.
    pub fn operation_binding(&self) -> [u8; 48] {
        let mut intent = self.clone();
        intent.payout_binding = ProofCommitment48::ZERO;
        hash48(
            b"hegemon.reward-account.claim-operation.v1",
            &intent.encode(),
        )
    }
    pub fn authorization_digest(&self) -> [u8; 48] {
        hash48(
            b"hegemon.reward-account.claim-authorization.v1",
            &self.encode(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TreasuryDonation {
    pub context: AccountChainContext,
    pub amount: u64,
    pub fee: u64,
    pub memo: BoundedVec<u8, MAX_PUBLIC_MEMO_BYTES>,
}
impl TreasuryDonation {
    pub fn operation_binding(&self) -> [u8; 48] {
        hash48(
            b"hegemon.reward-account.donation-operation.v1",
            &self.encode(),
        )
    }
    pub fn memo_hash(&self) -> [u8; 48] {
        hash48(
            b"hegemon.reward-account.public-memo.v1",
            &self.memo.encode(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum RewardAccountAction {
    TreasuryFork {
        certificate: TreasuryForkCertificate,
    },
    Claim {
        claim: AccountClaim,
        policy: AccountPolicy,
        approvals: BoundedVec<AccountApproval, MAX_ACCOUNT_SIGNERS>,
        proof: BoundedVec<u8, MAX_REWARD_CARRIER_BYTES>,
    },
    Donation {
        donation: TreasuryDonation,
        proof: BoundedVec<u8, MAX_REWARD_CARRIER_BYTES>,
    },
    /// Existing shielded action, whose accepted carrier proves its miner fee.
    PrivateFee {
        fee: u64,
        carrier: BoundedVec<u8, MAX_REWARD_CARRIER_BYTES>,
    },
}

/// Implemented by actual circuit admission in the node. There is deliberately
/// no unchecked production implementation or `verified: bool` argument.
pub trait RewardAccountProofVerifier {
    fn verify_claim(&self, claim: &AccountClaim, proof: &[u8]) -> Result<(), RewardAccountsError>;
    fn verify_donation(
        &self,
        donation: &TreasuryDonation,
        proof: &[u8],
    ) -> Result<(), RewardAccountsError>;
    fn verify_private_fee(
        &self,
        context: &AccountChainContext,
        fee: u64,
        carrier: &[u8],
    ) -> Result<(), RewardAccountsError>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct RewardAccount {
    pub(crate) available: u64,
    pub(crate) pending: BTreeMap<u64, u64>,
    pub(crate) next_sequence: u64,
}
impl RewardAccount {
    fn release(
        &mut self,
        epochs: RewardEpochSchedule,
        height: u64,
    ) -> Result<(), RewardAccountsError> {
        let mut due = Vec::new();
        for (&epoch, &amount) in &self.pending {
            if epochs.release_height(epoch)? <= height {
                due.push((epoch, amount));
            }
        }
        for (epoch, amount) in due {
            self.available = self
                .available
                .checked_add(amount)
                .ok_or(RewardAccountsError::Overflow)?;
            self.pending.remove(&epoch);
        }
        Ok(())
    }
    pub fn available(&self) -> u64 {
        self.available
    }
    pub fn pending(&self) -> &BTreeMap<u64, u64> {
        &self.pending
    }
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub fn total(&self) -> Result<u64, RewardAccountsError> {
        self.pending.values().try_fold(self.available, |s, v| {
            s.checked_add(*v).ok_or(RewardAccountsError::Overflow)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RewardAccountLedger {
    genesis: Arc<RewardAccountsGenesis>,
    genesis_allocation: u64,
    genesis_commitment: RulesHash48,
    context: AccountChainContext,
    height: u64,
    issued: u64,
    shielded_value: u64,
    available_total: u64,
    pending_epoch_totals: BTreeMap<u64, u64>,
    treasury: AccountPolicyId48,
    treasury_policy: AccountPolicy,
    policy_generation: u64,
    pending_fork: Option<Arc<TreasuryForkCertificate>>,
    retired_treasuries: Arc<BTreeSet<AccountPolicyId48>>,
    accounts: AccountTree,
}
impl RewardAccountLedger {
    pub fn new(
        genesis: RewardAccountsGenesis,
        context: AccountChainContext,
    ) -> Result<Self, RewardAccountsError> {
        context.validate(&genesis)?;
        let genesis_allocation = genesis.validate()?;
        let treasury = genesis.treasury_account()?;
        let mut accounts = AccountTree::default();
        for row in genesis.allocations.iter() {
            accounts.insert(
                row.account,
                RewardAccount {
                    available: row.amount,
                    ..Default::default()
                },
            )?;
        }
        let result = Self {
            treasury_policy: genesis.treasury_policy.clone(),
            genesis_allocation,
            genesis_commitment: RulesHash48::new(genesis.commitment()?),
            genesis: Arc::new(genesis),
            context,
            height: 0,
            issued: 0,
            shielded_value: 0,
            available_total: genesis_allocation,
            pending_epoch_totals: BTreeMap::new(),
            treasury,
            policy_generation: 0,
            pending_fork: None,
            retired_treasuries: Arc::new(BTreeSet::new()),
            accounts,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn context(&self) -> &AccountChainContext {
        &self.context
    }
    pub fn treasury(&self) -> AccountPolicyId48 {
        self.treasury
    }
    pub fn policy_generation(&self) -> u64 {
        self.policy_generation
    }
    pub fn treasury_policy(&self) -> &AccountPolicy {
        &self.treasury_policy
    }
    pub fn pending_fork(&self) -> Option<&TreasuryForkCertificate> {
        self.pending_fork.as_deref()
    }
    pub fn issued(&self) -> u64 {
        self.issued
    }
    pub fn shielded_value(&self) -> u64 {
        self.shielded_value
    }
    pub fn available_total(&self) -> u64 {
        self.available_total
    }
    pub fn pending_epoch_totals(&self) -> &BTreeMap<u64, u64> {
        &self.pending_epoch_totals
    }
    pub fn genesis(&self) -> &RewardAccountsGenesis {
        &self.genesis
    }
    /// View eligibility for a candidate inclusion height. Does not mutate state.
    pub fn account_at(
        &self,
        account: AccountPolicyId48,
        height: u64,
    ) -> Result<RewardAccount, RewardAccountsError> {
        if height < self.height {
            return Err(RewardAccountsError::InvalidContext);
        }
        let mut result = self.accounts.get(&account).cloned().unwrap_or_default();
        result.release(
            RewardEpochSchedule::new(self.genesis.reward_epoch_blocks)?,
            height,
        )?;
        Ok(result)
    }
    pub fn state_root(&self) -> RewardAccountsRoot48 {
        RewardAccountsRoot48::new(hash48(
            b"hegemon.reward-accounts.authenticated-state.v1",
            &(
                self.genesis_commitment,
                &self.context,
                self.height,
                self.issued,
                self.shielded_value,
                self.available_total,
                &self.pending_epoch_totals,
                self.treasury,
                &self.treasury_policy,
                self.policy_generation,
                &self.pending_fork,
                &self.retired_treasuries,
                self.accounts.root_hash(),
            )
                .encode(),
        ))
    }
    /// Build a full candidate, leaving self untouched on *any* error. Integration
    /// persists this candidate only with the corresponding shared note state.
    pub fn apply_block<V: RewardAccountProofVerifier>(
        &self,
        height: u64,
        miner: AccountPolicyId48,
        actions: &[RewardAccountAction],
        verifier: &V,
    ) -> Result<Self, RewardAccountsError> {
        self.apply_block_with_fork(height, miner, actions, verifier, None)
    }
    pub fn apply_block_with_fork<V: RewardAccountProofVerifier>(
        &self,
        height: u64,
        miner: AccountPolicyId48,
        actions: &[RewardAccountAction],
        verifier: &V,
        compiled_fork: Option<&CompiledTreasuryFork>,
    ) -> Result<Self, RewardAccountsError> {
        if self.height.checked_add(1) != Some(height) || miner == AccountPolicyId48::ZERO {
            return Err(RewardAccountsError::InvalidContext);
        }
        let epochs = RewardEpochSchedule::new(self.genesis.reward_epoch_blocks)?;
        let earning_epoch = epochs.epoch_at(height)?;
        epochs.release_height(earning_epoch)?;
        let mut next = self.clone();
        // Global availability changes before any transaction. Individual
        // leaves normalize lazily when accessed, using this same height rule.
        let mut due = Vec::new();
        for (&epoch, &amount) in &next.pending_epoch_totals {
            if epochs.release_height(epoch)? <= height {
                due.push((epoch, amount));
            }
        }
        for (epoch, amount) in due {
            next.available_total = next
                .available_total
                .checked_add(amount)
                .ok_or(RewardAccountsError::Overflow)?;
            next.pending_epoch_totals.remove(&epoch);
        }
        next.activate_fork(height, compiled_fork)?;
        if next.retired_treasuries.contains(&miner)
            || next
                .pending_fork
                .as_ref()
                .is_some_and(|c| c.intent.successor_policy.identifier().ok() == Some(miner))
        {
            return Err(RewardAccountsError::InvalidTreasuryFork);
        }
        let mut fee_total = 0u64;
        let mut donation_total = 0u64;
        for action in actions {
            let fee = match action {
                RewardAccountAction::TreasuryFork { certificate } => {
                    next.schedule_fork(height, miner, certificate, compiled_fork)?;
                    0
                }
                RewardAccountAction::Claim {
                    claim,
                    policy,
                    approvals,
                    proof,
                } => {
                    if claim.context != self.context
                        || claim.amount == 0
                        || claim.payout_binding == ProofCommitment48::ZERO
                        || policy.identifier()? != claim.account
                    {
                        return Err(RewardAccountsError::InvalidContext);
                    }
                    decode_address_bytes(
                        &claim.recipient,
                        AddressKind::Shielded,
                        self.genesis.network,
                    )?;
                    if next.retired_treasuries.contains(&claim.account)
                        || next.pending_fork.as_ref().is_some_and(|c| {
                            c.intent.successor_policy.identifier().ok() == Some(claim.account)
                        })
                    {
                        return Err(RewardAccountsError::InvalidTreasuryFork);
                    }
                    let generation = if claim.account == next.treasury {
                        next.policy_generation
                    } else {
                        0
                    };
                    if claim.policy_generation != generation
                        || (claim.account == next.treasury && policy != &next.treasury_policy)
                    {
                        return Err(RewardAccountsError::StaleClaim);
                    }
                    let mut account = next
                        .accounts
                        .get(&claim.account)
                        .cloned()
                        .unwrap_or_default();
                    account.release(epochs, height)?;
                    if claim.sequence != account.next_sequence {
                        return Err(RewardAccountsError::StaleClaim);
                    }
                    let debit = claim
                        .amount
                        .checked_add(claim.fee)
                        .ok_or(RewardAccountsError::Overflow)?;
                    if debit > account.available {
                        return Err(RewardAccountsError::InsufficientBalance);
                    }
                    let sequence = account
                        .next_sequence
                        .checked_add(1)
                        .ok_or(RewardAccountsError::Overflow)?;
                    policy.verify(&claim.authorization_digest(), approvals)?;
                    verifier.verify_claim(claim, proof)?;
                    account.available -= debit;
                    account.next_sequence = sequence;
                    next.accounts.insert(claim.account, account)?;
                    next.available_total = next
                        .available_total
                        .checked_sub(debit)
                        .ok_or(RewardAccountsError::InvalidState)?;
                    next.shielded_value = next
                        .shielded_value
                        .checked_add(claim.amount)
                        .ok_or(RewardAccountsError::Overflow)?;
                    claim.fee
                }
                RewardAccountAction::Donation { donation, proof } => {
                    if donation.context != self.context
                        || donation.amount == 0
                        || std::str::from_utf8(&donation.memo).is_err()
                    {
                        return Err(RewardAccountsError::InvalidContext);
                    }
                    verifier.verify_donation(donation, proof)?;
                    let debit = donation
                        .amount
                        .checked_add(donation.fee)
                        .ok_or(RewardAccountsError::Overflow)?;
                    next.shielded_value = next
                        .shielded_value
                        .checked_sub(debit)
                        .ok_or(RewardAccountsError::InsufficientBalance)?;
                    donation_total = donation_total
                        .checked_add(donation.amount)
                        .ok_or(RewardAccountsError::Overflow)?;
                    donation.fee
                }
                RewardAccountAction::PrivateFee { fee, carrier } => {
                    verifier.verify_private_fee(&self.context, *fee, carrier)?;
                    next.shielded_value = next
                        .shielded_value
                        .checked_sub(*fee)
                        .ok_or(RewardAccountsError::InsufficientBalance)?;
                    *fee
                }
            };
            fee_total = fee_total
                .checked_add(fee)
                .ok_or(RewardAccountsError::Overflow)?;
        }
        if donation_total != 0 {
            next.available_total = next
                .available_total
                .checked_add(donation_total)
                .ok_or(RewardAccountsError::Overflow)?;
            let mut treasury = next
                .accounts
                .get(&next.treasury)
                .cloned()
                .unwrap_or_default();
            treasury.release(epochs, height)?;
            treasury.available = treasury
                .available
                .checked_add(donation_total)
                .ok_or(RewardAccountsError::Overflow)?;
            next.accounts.insert(next.treasury, treasury)?;
        }
        let subsidy = IssuanceSchedule::new(self.genesis_allocation)?.subsidy(height);
        let (miner_amount, treasury_amount) = reward_split(subsidy, fee_total)?;
        let reward_total = miner_amount
            .checked_add(treasury_amount)
            .ok_or(RewardAccountsError::Overflow)?;
        if reward_total != 0 {
            let aggregate = next.pending_epoch_totals.entry(earning_epoch).or_default();
            *aggregate = aggregate
                .checked_add(reward_total)
                .ok_or(RewardAccountsError::Overflow)?;
        }
        for (id, amount) in [(miner, miner_amount), (next.treasury, treasury_amount)] {
            if amount == 0 {
                continue;
            }
            let mut account = next.accounts.get(&id).cloned().unwrap_or_default();
            account.release(epochs, height)?;
            let pending = account.pending.entry(earning_epoch).or_default();
            *pending = pending
                .checked_add(amount)
                .ok_or(RewardAccountsError::Overflow)?;
            next.accounts.insert(id, account)?;
        }
        next.height = height;
        next.issued = next
            .issued
            .checked_add(subsidy)
            .ok_or(RewardAccountsError::Overflow)?;
        next.validate_conservation()?;
        Ok(next)
    }
    fn schedule_fork(
        &mut self,
        height: u64,
        miner: AccountPolicyId48,
        certificate: &TreasuryForkCertificate,
        compiled: Option<&CompiledTreasuryFork>,
    ) -> Result<(), RewardAccountsError> {
        if self.pending_fork.is_some() {
            return Err(RewardAccountsError::InvalidTreasuryFork);
        }
        self.validate_fork(certificate, height)?;
        let target = certificate.intent.successor_policy.identifier()?;
        let expected = CompiledTreasuryFork {
            activation_height: certificate.intent.activation_height,
            successor_rules: certificate.intent.successor_rules,
            successor_policy: target,
        };
        // Unknown certificates must not create a future halt/pause power.
        // Adoption is necessary at scheduling, as well as at activation.
        if target == miner || compiled != Some(&expected) {
            return Err(RewardAccountsError::InvalidTreasuryFork);
        }
        self.pending_fork = Some(Arc::new(certificate.clone()));
        Ok(())
    }
    fn validate_fork(
        &self,
        certificate: &TreasuryForkCertificate,
        height: u64,
    ) -> Result<(), RewardAccountsError> {
        let intent = &certificate.intent;
        let target = intent.successor_policy.identifier()?;
        if intent.context != self.context
            || intent.current_generation != self.policy_generation
            || intent.activation_height <= height
            || intent.successor_rules == RulesHash48::ZERO
            || intent.successor_policy.required() != self.treasury_policy.required()
            || intent.successor_policy.signer_hashes().len()
                != self.treasury_policy.signer_hashes().len()
            || target == self.treasury
            || self.accounts.contains_key(&target)
            || self.retired_treasuries.contains(&target)
        {
            return Err(RewardAccountsError::InvalidTreasuryFork);
        }
        self.treasury_policy
            .verify(&intent.authorization_digest(), &certificate.approvals)
    }
    fn activate_fork(
        &mut self,
        height: u64,
        compiled: Option<&CompiledTreasuryFork>,
    ) -> Result<(), RewardAccountsError> {
        let Some(certificate) = self.pending_fork.as_ref() else {
            if compiled.is_some_and(|f| f.activation_height == height) {
                return Err(RewardAccountsError::InvalidTreasuryFork);
            }
            return Ok(());
        };
        if certificate.intent.activation_height > height {
            if compiled.is_some_and(|f| f.activation_height == height) {
                return Err(RewardAccountsError::InvalidTreasuryFork);
            }
            return Ok(());
        }
        let intent = certificate.intent.clone();
        let target = intent.successor_policy.identifier()?;
        let expected = CompiledTreasuryFork {
            activation_height: height,
            successor_rules: intent.successor_rules,
            successor_policy: target,
        };
        if intent.activation_height != height || compiled != Some(&expected) {
            return Err(RewardAccountsError::InvalidTreasuryFork);
        }
        // validate() has already authenticated the pending certificate when
        // persisted or created. Recheck before moving ownership as well.
        self.validate_fork(certificate, self.height)?;
        let generation = self
            .policy_generation
            .checked_add(1)
            .ok_or(RewardAccountsError::Overflow)?;
        let balance = self.accounts.remove(&self.treasury).unwrap_or_default();
        Arc::make_mut(&mut self.retired_treasuries).insert(self.treasury);
        self.accounts.insert(target, balance)?;
        self.treasury = target;
        self.treasury_policy = intent.successor_policy;
        self.policy_generation = generation;
        self.pending_fork = None;
        Ok(())
    }
    pub fn validate(&self) -> Result<(), RewardAccountsError> {
        let g = self.genesis.validate()?;
        self.context.validate(&self.genesis)?;
        if g != self.genesis_allocation
            || self.genesis_commitment.as_bytes() != &self.genesis.commitment()?
        {
            return Err(RewardAccountsError::InvalidState);
        }
        self.treasury_policy.validate()?;
        if self.treasury_policy.identifier()? != self.treasury
            || self.treasury_policy.required() != self.genesis.treasury_policy.required()
            || self.treasury_policy.signer_hashes().len()
                != self.genesis.treasury_policy.signer_hashes().len()
            || (self.policy_generation == 0 && self.treasury != self.genesis.treasury_account()?)
            || (self.policy_generation != 0
                && !self
                    .retired_treasuries
                    .contains(&self.genesis.treasury_account()?))
            || self.issued != self.genesis.issuance()?.issued_through(self.height)
            || self.retired_treasuries.contains(&self.treasury)
            || self.retired_treasuries.len() as u64 != self.policy_generation
            || self
                .retired_treasuries
                .iter()
                .any(|id| self.accounts.contains_key(id))
        {
            return Err(RewardAccountsError::InvalidState);
        }
        if let Some(certificate) = &self.pending_fork {
            self.validate_fork(certificate, self.height)?;
        }
        let epochs = self.genesis.epochs()?;
        let current = if self.height == 0 {
            None
        } else {
            Some(epochs.epoch_at(self.height)?)
        };
        let mut total = self.shielded_value;
        let mut available_total = 0u64;
        let mut pending_epoch_totals = BTreeMap::<u64, u64>::new();
        for (id, account) in self.accounts.iter() {
            if *id == AccountPolicyId48::ZERO || account.pending.len() > 2 {
                return Err(RewardAccountsError::InvalidState);
            }
            for (&epoch, &amount) in &account.pending {
                if amount == 0 || current.is_none_or(|now| epoch > now) {
                    return Err(RewardAccountsError::InvalidState);
                }
                epochs.release_height(epoch)?;
            }
            total = total
                .checked_add(account.total()?)
                .ok_or(RewardAccountsError::Overflow)?;
            let mut normalized = account.clone();
            normalized.release(epochs, self.height)?;
            available_total = available_total
                .checked_add(normalized.available)
                .ok_or(RewardAccountsError::Overflow)?;
            for (epoch, amount) in normalized.pending {
                let sum = pending_epoch_totals.entry(epoch).or_default();
                *sum = sum
                    .checked_add(amount)
                    .ok_or(RewardAccountsError::Overflow)?;
            }
        }
        if available_total != self.available_total
            || pending_epoch_totals != self.pending_epoch_totals
        {
            return Err(RewardAccountsError::InvalidState);
        }
        if total
            != g.checked_add(self.issued)
                .ok_or(RewardAccountsError::Overflow)?
            || total > MAX_SUPPLY
        {
            return Err(RewardAccountsError::InvalidState);
        }
        self.validate_conservation()
    }
    /// Snapshot recovery requires the authenticated root from the enclosing
    /// canonical block, not a root supplied beside the untrusted snapshot.
    pub fn decode_exact(
        bytes: &[u8],
        expected: RewardAccountsRoot48,
    ) -> Result<Self, RewardAccountsError> {
        let mut cursor = bytes;
        let ledger = Self::decode(&mut cursor).map_err(|_| RewardAccountsError::InvalidState)?;
        if !cursor.is_empty() || ledger.encode() != bytes {
            return Err(RewardAccountsError::InvalidState);
        }
        ledger.validate()?;
        if ledger.state_root() != expected {
            return Err(RewardAccountsError::InvalidState);
        }
        Ok(ledger)
    }
    fn validate_conservation(&self) -> Result<(), RewardAccountsError> {
        let mut aggregate = self.available_total;
        if self.pending_epoch_totals.len() > 2 {
            return Err(RewardAccountsError::InvalidState);
        }
        for amount in self.pending_epoch_totals.values() {
            if *amount == 0 {
                return Err(RewardAccountsError::InvalidState);
            }
            aggregate = aggregate
                .checked_add(*amount)
                .ok_or(RewardAccountsError::Overflow)?;
        }
        if aggregate != self.accounts.total() {
            return Err(RewardAccountsError::InvalidState);
        }
        let total = self
            .shielded_value
            .checked_add(self.accounts.total())
            .ok_or(RewardAccountsError::Overflow)?;
        let expected = self
            .genesis_allocation
            .checked_add(self.issued)
            .ok_or(RewardAccountsError::Overflow)?;
        if total != expected
            || total > MAX_SUPPLY
            || self.issued
                != IssuanceSchedule::new(self.genesis_allocation)?.issued_through(self.height)
        {
            return Err(RewardAccountsError::InvalidState);
        }
        Ok(())
    }
}

/// Persisted metadata excludes the account table and immutable genesis rows.
/// This is a recovery/checkpoint codec, never an authorized transaction.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RewardAccountCheckpoint {
    schema: u16,
    genesis_commitment: RulesHash48,
    context: AccountChainContext,
    height: u64,
    issued: u64,
    shielded_value: u64,
    available_total: u64,
    pending_epoch_totals: BTreeMap<u64, u64>,
    treasury: AccountPolicyId48,
    treasury_policy: AccountPolicy,
    policy_generation: u64,
    pending_fork: Option<Arc<TreasuryForkCertificate>>,
    retired_treasuries: Arc<BTreeSet<AccountPolicyId48>>,
}
impl RewardAccountCheckpoint {
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn context(&self) -> &AccountChainContext {
        &self.context
    }
}

pub const MAX_REWARD_ACCOUNT_JOURNAL_CHANGES: usize =
    protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_MAX_PROOF_ACTIONS_PER_BLOCK as usize + 3;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RewardAccountRowMutation {
    pub account: AccountPolicyId48,
    pub before: Option<RewardAccount>,
    pub after: Option<RewardAccount>,
}
/// Produced alongside a verified block transition. Disk decoding alone does
/// not authenticate it; replay requires the enclosing canonical block roots.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RewardAccountJournal {
    before_root: RewardAccountsRoot48,
    after_root: RewardAccountsRoot48,
    before: RewardAccountCheckpoint,
    after: RewardAccountCheckpoint,
    rows: BoundedVec<RewardAccountRowMutation, MAX_REWARD_ACCOUNT_JOURNAL_CHANGES>,
}
impl RewardAccountJournal {
    pub fn before_root(&self) -> RewardAccountsRoot48 {
        self.before_root
    }
    pub fn after_root(&self) -> RewardAccountsRoot48 {
        self.after_root
    }
    pub fn before(&self) -> &RewardAccountCheckpoint {
        &self.before
    }
    pub fn after(&self) -> &RewardAccountCheckpoint {
        &self.after
    }
    pub fn rows(&self) -> &[RewardAccountRowMutation] {
        &self.rows
    }
    pub fn validate_shape(&self) -> Result<(), RewardAccountsError> {
        if self.before.schema != 1
            || self.after.schema != 1
            || self.before.context != self.after.context
            || self.before.genesis_commitment != self.after.genesis_commitment
            || self.before.height.checked_add(1) != Some(self.after.height)
            || self.rows.windows(2).any(|p| p[0].account >= p[1].account)
            || self
                .rows
                .iter()
                .any(|r| r.account == AccountPolicyId48::ZERO || r.before == r.after)
        {
            return Err(RewardAccountsError::InvalidState);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewardJournalDirection {
    Forward,
    Reverse,
}

impl RewardAccountLedger {
    pub fn checkpoint(&self) -> RewardAccountCheckpoint {
        RewardAccountCheckpoint {
            schema: 1,
            genesis_commitment: self.genesis_commitment,
            context: self.context.clone(),
            height: self.height,
            issued: self.issued,
            shielded_value: self.shielded_value,
            available_total: self.available_total,
            pending_epoch_totals: self.pending_epoch_totals.clone(),
            treasury: self.treasury,
            treasury_policy: self.treasury_policy.clone(),
            policy_generation: self.policy_generation,
            pending_fork: self.pending_fork.clone(),
            retired_treasuries: self.retired_treasuries.clone(),
        }
    }
    /// Stream table rows at genesis or startup; normal blocks use journals.
    pub fn checkpoint_rows(&self) -> impl Iterator<Item = (AccountPolicyId48, &RewardAccount)> {
        self.accounts.iter().map(|(key, row)| (*key, row))
    }
    fn install_checkpoint(
        &mut self,
        c: RewardAccountCheckpoint,
    ) -> Result<(), RewardAccountsError> {
        if c.schema != 1
            || c.genesis_commitment != self.genesis_commitment
            || c.context != self.context
        {
            return Err(RewardAccountsError::InvalidContext);
        }
        self.height = c.height;
        self.issued = c.issued;
        self.shielded_value = c.shielded_value;
        self.available_total = c.available_total;
        self.pending_epoch_totals = c.pending_epoch_totals;
        self.treasury = c.treasury;
        self.treasury_policy = c.treasury_policy;
        self.policy_generation = c.policy_generation;
        self.pending_fork = c.pending_fork;
        self.retired_treasuries = c.retired_treasuries;
        Ok(())
    }
    /// Recovery only: the expected root must come from a verified canonical
    /// block record. All rows and cached aggregates are reconstructed/audited.
    pub fn restore_checkpoint(
        genesis: RewardAccountsGenesis,
        checkpoint: RewardAccountCheckpoint,
        rows: impl IntoIterator<Item = (AccountPolicyId48, RewardAccount)>,
        expected: RewardAccountsRoot48,
    ) -> Result<Self, RewardAccountsError> {
        let mut ledger = Self::new(genesis, checkpoint.context.clone())?;
        ledger.accounts = AccountTree::default();
        let mut previous = None;
        for (id, row) in rows {
            if previous.is_some_and(|p| p >= id) {
                return Err(RewardAccountsError::InvalidState);
            }
            ledger.accounts.insert(id, row)?;
            previous = Some(id);
        }
        ledger.install_checkpoint(checkpoint)?;
        ledger.validate()?;
        if ledger.state_root() != expected {
            return Err(RewardAccountsError::InvalidState);
        }
        Ok(ledger)
    }
    /// The same real proof/signature checks as apply_block_with_fork, with a
    /// bounded changed-row journal for the node's shared atomic transaction.
    pub fn apply_block_journaled<V: RewardAccountProofVerifier>(
        &self,
        height: u64,
        miner: AccountPolicyId48,
        actions: &[RewardAccountAction],
        verifier: &V,
        compiled_fork: Option<&CompiledTreasuryFork>,
    ) -> Result<(Self, RewardAccountJournal), RewardAccountsError> {
        let next = self.apply_block_with_fork(height, miner, actions, verifier, compiled_fork)?;
        let mut touched = BTreeSet::from([miner, self.treasury, next.treasury]);
        for action in actions {
            if let RewardAccountAction::Claim { claim, .. } = action {
                touched.insert(claim.account);
            }
        }
        let mut rows = Vec::new();
        for account in touched {
            let before = self.accounts.get(&account).cloned();
            let after = next.accounts.get(&account).cloned();
            if before != after {
                rows.push(RewardAccountRowMutation {
                    account,
                    before,
                    after,
                });
            }
        }
        let journal = RewardAccountJournal {
            before_root: self.state_root(),
            after_root: next.state_root(),
            before: self.checkpoint(),
            after: next.checkpoint(),
            rows: BoundedVec::new(rows).map_err(|_| RewardAccountsError::InvalidState)?,
        };
        journal.validate_shape()?;
        // No scan: applying the bounded changed paths must recreate exactly
        // the resulting authenticated trie. This also catches omitted rows.
        let rebuilt = self.replay_journal(
            &journal,
            RewardJournalDirection::Forward,
            journal.after_root,
        )?;
        if rebuilt.state_root() != next.state_root() {
            return Err(RewardAccountsError::InvalidState);
        }
        Ok((next, journal))
    }
    /// Replays only a previously verified, canonically authenticated journal.
    /// This does not establish proof authority for an unverified network block.
    pub fn replay_journal(
        &self,
        journal: &RewardAccountJournal,
        direction: RewardJournalDirection,
        canonical_destination_root: RewardAccountsRoot48,
    ) -> Result<Self, RewardAccountsError> {
        journal.validate_shape()?;
        let forward = direction == RewardJournalDirection::Forward;
        let (source, destination, source_root, destination_root) = if forward {
            (
                &journal.before,
                &journal.after,
                journal.before_root,
                journal.after_root,
            )
        } else {
            (
                &journal.after,
                &journal.before,
                journal.after_root,
                journal.before_root,
            )
        };
        if self.checkpoint() != *source
            || self.state_root() != source_root
            || canonical_destination_root != destination_root
        {
            return Err(RewardAccountsError::InvalidState);
        }
        let mut next = self.clone();
        for mutation in journal.rows.iter() {
            let (before, after) = if forward {
                (&mutation.before, &mutation.after)
            } else {
                (&mutation.after, &mutation.before)
            };
            if next.accounts.get(&mutation.account) != before.as_ref() {
                return Err(RewardAccountsError::InvalidState);
            }
            match after {
                Some(row) => next.accounts.insert(mutation.account, row.clone())?,
                None => {
                    next.accounts.remove(&mutation.account);
                }
            }
        }
        next.install_checkpoint(destination.clone())?;
        next.validate_conservation()?;
        if next.state_root() != canonical_destination_root {
            return Err(RewardAccountsError::InvalidState);
        }
        Ok(next)
    }
}
