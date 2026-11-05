//! Deterministic account transitions. Proof verification is mandatory at the
//! account/pool boundary; the integrating node must also validate its shared
//! nullifiers, note references, action identity and full block commitments.
use crate::*;
use codec::{Decode, Encode};
use crypto::hash384::{ProofCommitment48, RulesHash48};
use std::collections::BTreeMap;

pub const MAX_REWARD_PROOF_BYTES: usize = 2 * 1024 * 1024;
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
    pub fn memo_hash(&self) -> [u8; 48] {
        hash48(
            b"hegemon.reward-account.public-memo.v1",
            &self.memo.encode(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum RewardAccountAction {
    Claim {
        claim: AccountClaim,
        policy: AccountPolicy,
        approvals: BoundedVec<AccountApproval, MAX_ACCOUNT_SIGNERS>,
        proof: BoundedVec<u8, MAX_REWARD_PROOF_BYTES>,
    },
    Donation {
        donation: TreasuryDonation,
        proof: BoundedVec<u8, MAX_REWARD_PROOF_BYTES>,
    },
    /// Existing shielded action, whose accepted carrier proves its miner fee.
    PrivateFee {
        fee: u64,
        carrier: BoundedVec<u8, MAX_REWARD_PROOF_BYTES>,
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
    available: u64,
    pending: BTreeMap<u64, u64>,
    next_sequence: u64,
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
    genesis: RewardAccountsGenesis,
    context: AccountChainContext,
    height: u64,
    issued: u64,
    shielded_value: u64,
    treasury: AccountPolicyId48,
    treasury_policy: AccountPolicy,
    policy_generation: u64,
    accounts: BTreeMap<AccountPolicyId48, RewardAccount>,
}
impl RewardAccountLedger {
    pub fn new(
        genesis: RewardAccountsGenesis,
        context: AccountChainContext,
    ) -> Result<Self, RewardAccountsError> {
        context.validate(&genesis)?;
        let treasury = genesis.treasury_account()?;
        let accounts = genesis
            .allocations
            .iter()
            .map(|row| {
                (
                    row.account,
                    RewardAccount {
                        available: row.amount,
                        ..Default::default()
                    },
                )
            })
            .collect();
        let result = Self {
            treasury_policy: genesis.treasury_policy.clone(),
            genesis,
            context,
            height: 0,
            issued: 0,
            shielded_value: 0,
            treasury,
            policy_generation: 0,
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
    pub fn issued(&self) -> u64 {
        self.issued
    }
    pub fn shielded_value(&self) -> u64 {
        self.shielded_value
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
        result.release(self.genesis.epochs()?, height)?;
        Ok(result)
    }
    pub fn state_root(&self) -> RewardAccountsRoot48 {
        RewardAccountsRoot48::new(hash48(
            b"hegemon.reward-accounts.state-snapshot.v1",
            &self.encode(),
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
        if self.height.checked_add(1) != Some(height) || miner == AccountPolicyId48::ZERO {
            return Err(RewardAccountsError::InvalidContext);
        }
        let epochs = self.genesis.epochs()?;
        let earning_epoch = epochs.epoch_at(height)?;
        epochs.release_height(earning_epoch)?;
        let mut next = self.clone();
        let mut fee_total = 0u64;
        let mut donation_total = 0u64;
        for action in actions {
            let fee = match action {
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
                    let generation = if claim.account == self.treasury {
                        self.policy_generation
                    } else {
                        0
                    };
                    if claim.policy_generation != generation
                        || (claim.account == self.treasury && policy != &self.treasury_policy)
                    {
                        return Err(RewardAccountsError::StaleClaim);
                    }
                    let account = next.accounts.entry(claim.account).or_default();
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
            let treasury = next.accounts.entry(self.treasury).or_default();
            treasury.release(epochs, height)?;
            treasury.available = treasury
                .available
                .checked_add(donation_total)
                .ok_or(RewardAccountsError::Overflow)?;
        }
        let subsidy = self.genesis.issuance()?.subsidy(height);
        let (miner_amount, treasury_amount) = reward_split(subsidy, fee_total)?;
        for (id, amount) in [(miner, miner_amount), (self.treasury, treasury_amount)] {
            if amount == 0 {
                continue;
            }
            let account = next.accounts.entry(id).or_default();
            account.release(epochs, height)?;
            let pending = account.pending.entry(earning_epoch).or_default();
            *pending = pending
                .checked_add(amount)
                .ok_or(RewardAccountsError::Overflow)?;
        }
        next.height = height;
        next.issued = next
            .issued
            .checked_add(subsidy)
            .ok_or(RewardAccountsError::Overflow)?;
        next.validate()?;
        Ok(next)
    }
    pub fn validate(&self) -> Result<(), RewardAccountsError> {
        let g = self.genesis.validate()?;
        self.context.validate(&self.genesis)?;
        self.treasury_policy.validate()?;
        if self.treasury_policy.identifier()? != self.treasury
            || self.issued != self.genesis.issuance()?.issued_through(self.height)
        {
            return Err(RewardAccountsError::InvalidState);
        }
        let epochs = self.genesis.epochs()?;
        let current = if self.height == 0 {
            None
        } else {
            Some(epochs.epoch_at(self.height)?)
        };
        let mut total = self.shielded_value;
        for (id, account) in &self.accounts {
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
        }
        if total
            != g.checked_add(self.issued)
                .ok_or(RewardAccountsError::Overflow)?
            || total > MAX_SUPPLY
        {
            return Err(RewardAccountsError::InvalidState);
        }
        Ok(())
    }
}
