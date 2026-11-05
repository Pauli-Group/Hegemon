//! Pure accounting tests. FixtureProofs is NOT a cryptographic proof verifier;
//! real-proof and shared-note integration acceptance is a separate milestone.
use codec::{Decode, Encode};
use crypto::{
    hash384::{ProofCommitment48, RulesHash48},
    ml_dsa::MlDsaSecretKey,
    traits::SigningKey,
};
use protocol_reward_accounts::*;

struct FixtureProofs;
impl RewardAccountProofVerifier for FixtureProofs {
    fn verify_claim(&self, _: &AccountClaim, p: &[u8]) -> Result<(), RewardAccountsError> {
        fixture(p)
    }
    fn verify_donation(&self, _: &TreasuryDonation, p: &[u8]) -> Result<(), RewardAccountsError> {
        fixture(p)
    }
    fn verify_private_fee(
        &self,
        _: &AccountChainContext,
        _: u64,
        p: &[u8],
    ) -> Result<(), RewardAccountsError> {
        fixture(p)
    }
}
fn fixture(p: &[u8]) -> Result<(), RewardAccountsError> {
    if p == b"accounting-unit-fixture" {
        Ok(())
    } else {
        Err(RewardAccountsError::InvalidProof)
    }
}
fn proof() -> BoundedVec<u8, MAX_REWARD_CARRIER_BYTES> {
    BoundedVec::new(b"accounting-unit-fixture".to_vec()).unwrap()
}
fn setup() -> (
    RewardAccountLedger,
    MlDsaSecretKey,
    AccountPolicy,
    MlDsaSecretKey,
    AccountPolicy,
) {
    let miner = MlDsaSecretKey::generate_deterministic(b"disposable miner ledger fixture");
    let treasury = MlDsaSecretKey::generate_deterministic(b"disposable treasury ledger fixture");
    let mp = AccountPolicy::single(&miner.verify_key());
    let tp = AccountPolicy::single(&treasury.verify_key());
    let genesis = RewardAccountsGenesis {
        network: AddressNetwork {
            class: NetworkClass::Testnet,
            discriminator: [8; 32],
        },
        reward_epoch_blocks: 2,
        treasury_policy: tp.clone(),
        allocations: BoundedVec::new(vec![GenesisAllocation {
            account: mp.identifier().unwrap(),
            amount: 100 * COIN,
        }])
        .unwrap(),
    };
    let context = AccountChainContext {
        chain_id: [1; 32],
        genesis_hash: [2; 32],
        genesis_config_hash: RulesHash48::new(genesis.commitment().unwrap()),
    };
    (
        RewardAccountLedger::new(genesis, context).unwrap(),
        miner,
        mp,
        treasury,
        tp,
    )
}
fn claim(
    ledger: &RewardAccountLedger,
    key: &MlDsaSecretKey,
    policy: &AccountPolicy,
    amount: u64,
    fee: u64,
    sequence: u64,
) -> RewardAccountAction {
    let recipient =
        encode_address_bytes(AddressKind::Shielded, ledger.genesis().network, &[1; 32]).unwrap();
    let claim = AccountClaim {
        context: ledger.context().clone(),
        account: if policy == ledger.treasury_policy() {
            ledger.treasury()
        } else {
            policy.identifier().unwrap()
        },
        policy_generation: 0,
        sequence,
        amount,
        fee,
        recipient: BoundedVec::new(recipient).unwrap(),
        payout_binding: ProofCommitment48::new([3; 48]),
    };
    let approval = AccountApproval::sign(0, key, &claim.authorization_digest());
    RewardAccountAction::Claim {
        claim,
        policy: policy.clone(),
        approvals: BoundedVec::new(vec![approval]).unwrap(),
        proof: proof(),
    }
}
#[test]
fn reward_accounts_pending_cannot_mix_with_available_and_partial_claims_work() {
    let (l, key, p, _, _) = setup();
    let id = p.identifier().unwrap();
    let l = l
        .apply_block(
            1,
            id,
            &[claim(&l, &key, &p, 10 * COIN, 100, 0)],
            &FixtureProofs,
        )
        .unwrap();
    assert_eq!(l.shielded_value(), 10 * COIN);
    let a = l.account_at(id, 2).unwrap();
    assert_eq!(a.available(), 90 * COIN - 100);
    assert_eq!(a.next_sequence(), 1);
    assert_eq!(a.pending().len(), 1);
    let too_much = claim(&l, &key, &p, 91 * COIN, 0, 1);
    assert_eq!(
        l.apply_block(2, id, &[too_much], &FixtureProofs)
            .unwrap_err(),
        RewardAccountsError::InsufficientBalance
    );
    let before = l.clone();
    let l = l.apply_block(2, id, &[], &FixtureProofs).unwrap();
    let l = l.apply_block(3, id, &[], &FixtureProofs).unwrap();
    let l = l.apply_block(4, id, &[], &FixtureProofs).unwrap();
    assert_eq!(l.account_at(id, 4).unwrap().available(), 90 * COIN - 100);
    let releasing = l.account_at(id, 5).unwrap();
    assert!(releasing.available() > 90 * COIN - 100);
    let l = l
        .apply_block(5, id, &[claim(&l, &key, &p, COIN, 0, 1)], &FixtureProofs)
        .unwrap();
    assert_eq!(l.account_at(id, 5).unwrap().next_sequence(), 2);
    assert!(before.account_at(id, 2).unwrap().available() < releasing.available());
    // Replaying from the retained ancestor reproduces the exact candidate.
    let replay = before
        .apply_block(2, id, &[], &FixtureProofs)
        .unwrap()
        .apply_block(3, id, &[], &FixtureProofs)
        .unwrap()
        .apply_block(4, id, &[], &FixtureProofs)
        .unwrap();
    let replay = replay
        .apply_block(
            5,
            id,
            &[claim(&replay, &key, &p, COIN, 0, 1)],
            &FixtureProofs,
        )
        .unwrap();
    assert_eq!(replay, l);
    assert_eq!(
        RewardAccountLedger::decode(&mut l.encode().as_slice()).unwrap(),
        l
    );
    l.validate().unwrap();
}
#[test]
fn reward_accounts_donations_deferred_and_fees_count_once() {
    let (l, key, p, tk, tp) = setup();
    let id = p.identifier().unwrap();
    let l = l
        .apply_block(
            1,
            id,
            &[claim(&l, &key, &p, 20 * COIN, 0, 0)],
            &FixtureProofs,
        )
        .unwrap();
    let donation = TreasuryDonation {
        context: l.context().clone(),
        amount: 2 * COIN,
        fee: 7,
        memo: BoundedVec::new(b"public donation".to_vec()).unwrap(),
    };
    let action = RewardAccountAction::Donation {
        donation,
        proof: proof(),
    };
    let old = l.clone();
    let same_block = claim(&l, &tk, &tp, COIN, 0, 0);
    assert!(l
        .apply_block(2, id, &[action.clone(), same_block], &FixtureProofs)
        .is_err());
    assert_eq!(l, old);
    let l = l.apply_block(2, id, &[action], &FixtureProofs).unwrap();
    assert_eq!(l.account_at(l.treasury(), 3).unwrap().available(), 2 * COIN);
    assert_eq!(l.shielded_value(), 18 * COIN - 7);
    let l = l
        .apply_block(3, id, &[claim(&l, &tk, &tp, COIN, 11, 0)], &FixtureProofs)
        .unwrap();
    assert_eq!(l.shielded_value(), 19 * COIN - 7);
    let treasury = l.account_at(l.treasury(), 3).unwrap();
    assert_eq!(treasury.available(), COIN - 11);
    l.validate().unwrap();
}
#[test]
fn reward_accounts_bad_proof_signature_context_and_replay_leave_parent_unchanged() {
    let (l, key, p, _, _) = setup();
    let id = p.identifier().unwrap();
    let root = l.state_root();
    let mut bad = claim(&l, &key, &p, COIN, 0, 0);
    if let RewardAccountAction::Claim { proof, .. } = &mut bad {
        *proof = BoundedVec::default();
    }
    assert_eq!(
        l.apply_block(1, id, &[bad], &FixtureProofs).unwrap_err(),
        RewardAccountsError::InvalidProof
    );
    let mut bad = claim(&l, &key, &p, COIN, 0, 0);
    if let RewardAccountAction::Claim { claim, .. } = &mut bad {
        claim.amount += 1;
    }
    assert!(l.apply_block(1, id, &[bad], &FixtureProofs).is_err());
    assert_eq!(l.state_root(), root);
    let action = claim(&l, &key, &p, COIN, 0, 0);
    assert!(l
        .apply_block(1, id, &[action.clone(), action.clone()], &FixtureProofs)
        .is_err());
    let l = l
        .apply_block(1, id, std::slice::from_ref(&action), &FixtureProofs)
        .unwrap();
    assert!(l.apply_block(2, id, &[action], &FixtureProofs).is_err());
    assert!(l.apply_block(3, id, &[], &FixtureProofs).is_err());
}

#[test]
fn reward_accounts_treasury_fork_needs_certificate_and_compiled_adoption() {
    use crypto::hash384::RulesHash48;
    let (l, _, miner_policy, old_key, old_policy) = setup();
    let miner = miner_policy.identifier().unwrap();
    let successor_key = MlDsaSecretKey::generate_deterministic(b"successor treasury fixture");
    let successor = AccountPolicy::single(&successor_key.verify_key());
    let target = successor.identifier().unwrap();
    let intent = TreasuryForkIntent {
        context: l.context().clone(),
        current_generation: 0,
        activation_height: 5,
        successor_rules: RulesHash48::new([27; 48]),
        successor_policy: successor.clone(),
    };
    let certificate = TreasuryForkCertificate {
        approvals: BoundedVec::new(vec![AccountApproval::sign(
            0,
            &old_key,
            &intent.authorization_digest(),
        )])
        .unwrap(),
        intent,
    };
    let action = RewardAccountAction::TreasuryFork {
        certificate: certificate.clone(),
    };
    let compiled = CompiledTreasuryFork {
        activation_height: 5,
        successor_rules: certificate.intent.successor_rules,
        successor_policy: target,
    };
    assert!(l
        .apply_block(1, miner, std::slice::from_ref(&action), &FixtureProofs)
        .is_err());
    // Unadopted certificates grant neither a reservation nor a future halt.
    let mut ordinary = l.clone();
    for h in 1..=6 {
        ordinary = ordinary.apply_block(h, miner, &[], &FixtureProofs).unwrap();
    }
    assert_eq!(ordinary.treasury(), protocol_treasury_account_id());
    assert_eq!(ordinary.treasury_policy(), &old_policy);
    let scheduled = l
        .apply_block_with_fork(
            1,
            miner,
            std::slice::from_ref(&action),
            &FixtureProofs,
            Some(&compiled),
        )
        .unwrap();
    assert!(scheduled
        .apply_block(2, target, &[], &FixtureProofs)
        .is_ok());
    assert!(scheduled
        .apply_block(2, miner, &[action], &FixtureProofs)
        .is_err());
    let scheduled = (2..=4).fold(scheduled, |s, h| {
        s.apply_block(h, miner, &[], &FixtureProofs).unwrap()
    });
    let root_before = scheduled.state_root();
    assert_eq!(
        scheduled
            .apply_block(5, miner, &[], &FixtureProofs)
            .unwrap_err(),
        RewardAccountsError::InvalidTreasuryFork
    );
    let mut wrong = compiled.clone();
    wrong.successor_rules = RulesHash48::new([28; 48]);
    assert!(scheduled
        .apply_block_with_fork(5, miner, &[], &FixtureProofs, Some(&wrong))
        .is_err());
    assert_eq!(scheduled.state_root(), root_before);
    let prior = scheduled.account_at(scheduled.treasury(), 5).unwrap();
    let activated = scheduled
        .apply_block_with_fork(5, miner, &[], &FixtureProofs, Some(&compiled))
        .unwrap();
    assert_eq!(activated.treasury(), protocol_treasury_account_id());
    assert_eq!(activated.treasury_policy().identifier().unwrap(), target);
    assert_eq!(activated.policy_generation(), 1);
    assert_eq!(
        activated
            .account_at(activated.treasury(), 5)
            .unwrap()
            .available(),
        prior.available()
    );
    assert!(
        activated
            .account_at(activated.treasury(), 5)
            .unwrap()
            .total()
            .unwrap()
            > prior.total().unwrap()
    );
    assert!(activated.pending_fork().is_none());
    let mut fresh_claim = claim(&activated, &successor_key, &successor, 1, 0, 0);
    if let RewardAccountAction::Claim {
        claim, approvals, ..
    } = &mut fresh_claim
    {
        claim.policy_generation = 1;
        *approvals = BoundedVec::new(vec![AccountApproval::sign(
            0,
            &successor_key,
            &claim.authorization_digest(),
        )])
        .unwrap();
    }
    let spent = activated
        .apply_block(6, miner, &[fresh_claim], &FixtureProofs)
        .unwrap();
    assert_eq!(
        spent
            .account_at(spent.treasury(), 6)
            .unwrap()
            .next_sequence(),
        1
    );
    let stale = claim(&scheduled, &old_key, &old_policy, 1, 0, 0);
    assert!(activated
        .apply_block(6, miner, &[stale], &FixtureProofs)
        .is_err());
    assert!(activated
        .apply_block(6, old_policy.identifier().unwrap(), &[], &FixtureProofs)
        .is_ok());
    let bytes = activated.encode();
    let restored = RewardAccountLedger::decode(&mut bytes.as_slice()).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored.state_root(), activated.state_root());
    // Replaying the competing branch from the retained parent restores the old
    // policy and its exact pending epoch buckets; no activation is irreversible.
    let alternate = l.apply_block(1, miner, &[], &FixtureProofs).unwrap();
    assert_eq!(alternate.treasury(), protocol_treasury_account_id());
    assert_eq!(alternate.treasury_policy(), &old_policy);
    assert_eq!(alternate.policy_generation(), 0);
    assert!(alternate.pending_fork().is_none());
}

#[test]
fn reward_accounts_fork_rejects_same_policy_changed_quorum_and_altered_intent() {
    let (l, _, miner_policy, old_key, _) = setup();
    let miner = miner_policy.identifier().unwrap();
    let next_key = MlDsaSecretKey::generate_deterministic(b"fork rejection next key");
    let mut intent = TreasuryForkIntent {
        context: l.context().clone(),
        current_generation: 0,
        activation_height: 2,
        successor_rules: RulesHash48::new([19; 48]),
        successor_policy: l.treasury_policy().clone(),
    };
    let schedule = |i: TreasuryForkIntent, signature_for: &TreasuryForkIntent| {
        RewardAccountAction::TreasuryFork {
            certificate: TreasuryForkCertificate {
                intent: i,
                approvals: BoundedVec::new(vec![AccountApproval::sign(
                    0,
                    &old_key,
                    &signature_for.authorization_digest(),
                )])
                .unwrap(),
            },
        }
    };
    let rejected = |i: TreasuryForkIntent, signed_for: &TreasuryForkIntent| {
        let compiled = CompiledTreasuryFork {
            activation_height: i.activation_height,
            successor_rules: i.successor_rules,
            successor_policy: i.successor_policy.identifier().unwrap(),
        };
        l.apply_block_with_fork(
            1,
            miner,
            &[schedule(i, signed_for)],
            &FixtureProofs,
            Some(&compiled),
        )
        .is_err()
    };
    assert!(rejected(intent.clone(), &intent));
    intent.successor_policy = AccountPolicy::threshold(
        1,
        vec![
            account_key_hash(&next_key.verify_key()),
            account_key_hash(&old_key.verify_key()),
        ],
    )
    .unwrap();
    assert!(rejected(intent.clone(), &intent));
    intent.successor_policy = AccountPolicy::single(&next_key.verify_key());
    let signed = intent.clone();
    intent.activation_height += 1;
    assert!(rejected(intent.clone(), &signed));
    intent.activation_height = 1;
    assert!(rejected(intent.clone(), &intent));
}

#[test]
fn reward_accounts_five_of_seven_fork_activates_at_release_boundary() {
    let keys: Vec<_> = (0..14u8)
        .map(|i| MlDsaSecretKey::generate_deterministic(&[i + 70; 32]))
        .collect();
    let policy = |keys: &[MlDsaSecretKey]| {
        AccountPolicy::threshold(
            5,
            keys.iter()
                .map(|k| account_key_hash(&k.verify_key()))
                .collect(),
        )
        .unwrap()
    };
    let old = policy(&keys[..7]);
    let new = policy(&keys[7..]);
    let genesis = RewardAccountsGenesis {
        network: AddressNetwork {
            class: NetworkClass::Testnet,
            discriminator: [8; 32],
        },
        reward_epoch_blocks: 1,
        treasury_policy: old.clone(),
        allocations: BoundedVec::default(),
    };
    let context = AccountChainContext {
        chain_id: [1; 32],
        genesis_hash: [2; 32],
        genesis_config_hash: RulesHash48::new(genesis.commitment().unwrap()),
    };
    let l = RewardAccountLedger::new(genesis, context).unwrap();
    let miner = AccountPolicyId48::new([8; 48]);
    let intent = TreasuryForkIntent {
        context: l.context().clone(),
        current_generation: 0,
        activation_height: 3,
        successor_rules: RulesHash48::new([27; 48]),
        successor_policy: new.clone(),
    };
    let approve = |policy: &AccountPolicy, keys: &[MlDsaSecretKey], digest: &[u8; 48]| {
        let mut approvals: Vec<_> = keys
            .iter()
            .take(5)
            .map(|k| {
                let index = policy
                    .signer_hashes()
                    .iter()
                    .position(|h| *h == account_key_hash(&k.verify_key()))
                    .unwrap();
                AccountApproval::sign(index as u8, k, digest)
            })
            .collect();
        approvals.sort_by_key(|a| a.signer_index);
        approvals
    };
    let approvals = approve(&old, &keys[..7], &intent.authorization_digest());
    let mut certificate = TreasuryForkCertificate {
        intent,
        approvals: BoundedVec::new(approvals[..4].to_vec()).unwrap(),
    };
    let compiled = CompiledTreasuryFork {
        activation_height: 3,
        successor_rules: certificate.intent.successor_rules,
        successor_policy: new.identifier().unwrap(),
    };
    assert!(l
        .apply_block_with_fork(
            1,
            miner,
            &[RewardAccountAction::TreasuryFork {
                certificate: certificate.clone()
            }],
            &FixtureProofs,
            Some(&compiled)
        )
        .is_err());
    certificate.approvals = BoundedVec::new(approvals).unwrap();
    let l = l
        .apply_block_with_fork(
            1,
            miner,
            &[RewardAccountAction::TreasuryFork {
                certificate: certificate.clone(),
            }],
            &FixtureProofs,
            Some(&compiled),
        )
        .unwrap();
    let l = l.apply_block(2, miner, &[], &FixtureProofs).unwrap();
    let recipient =
        encode_address_bytes(AddressKind::Shielded, l.genesis().network, &[1; 32]).unwrap();
    let claim = AccountClaim {
        context: l.context().clone(),
        account: protocol_treasury_account_id(),
        policy_generation: 1,
        sequence: 0,
        amount: 1,
        fee: 2,
        recipient: BoundedVec::new(recipient).unwrap(),
        payout_binding: ProofCommitment48::new([3; 48]),
    };
    let action = RewardAccountAction::Claim {
        approvals: BoundedVec::new(approve(&new, &keys[7..], &claim.authorization_digest()))
            .unwrap(),
        claim,
        policy: new.clone(),
        proof: proof(),
    };
    let l = l
        .apply_block_with_fork(3, miner, &[action], &FixtureProofs, Some(&compiled))
        .unwrap();
    l.validate().unwrap();
    assert_eq!(l.policy_generation(), 1);
    assert_eq!(l.shielded_value(), 1);
    assert_eq!(l.account_at(l.treasury(), 3).unwrap().next_sequence(), 1);
    let snapshot = l.encode();
    assert_eq!(
        RewardAccountLedger::decode_exact(&snapshot, l.state_root()).unwrap(),
        l
    );
    assert!(
        RewardAccountLedger::decode_exact(&snapshot, RewardAccountsRoot48::new([7; 48])).is_err()
    );
    let mut suffix = snapshot;
    suffix.push(0);
    assert!(RewardAccountLedger::decode_exact(&suffix, l.state_root()).is_err());
}

#[test]
fn reward_accounts_global_epoch_totals_match_independent_replay_and_boundary_forks() {
    let (initial, _, miner, _, _) = setup();
    let main_miner = miner.identifier().unwrap();
    let mut chain = vec![initial.clone()];
    let mut rewards = std::collections::BTreeMap::<u64, u64>::new();
    for height in 1..=30 {
        let parent = chain.last().unwrap();
        let epoch = parent.genesis().epochs().unwrap().epoch_at(height).unwrap();
        let subsidy = parent.genesis().issuance().unwrap().subsidy(height);
        *rewards.entry(epoch).or_default() += subsidy;
        let next = parent
            .apply_block(height, main_miner, &[], &FixtureProofs)
            .unwrap();
        let pending: u64 = rewards
            .iter()
            .filter(|(e, _)| {
                initial
                    .genesis()
                    .epochs()
                    .unwrap()
                    .release_height(**e)
                    .unwrap()
                    > height
            })
            .map(|(_, a)| *a)
            .sum();
        assert_eq!(next.pending_epoch_totals().values().sum::<u64>(), pending);
        assert_eq!(next.available_total() + pending, 100 * COIN + next.issued());
        next.validate().unwrap();
        chain.push(next);
    }
    let mut replay = initial;
    for height in 1..=30 {
        replay = replay
            .apply_block(height, main_miner, &[], &FixtureProofs)
            .unwrap();
        assert_eq!(replay.state_root(), chain[height as usize].state_root());
    }
    let alternate_miner = AccountPolicyId48::new([7; 48]);
    let mut fork = chain[3].clone();
    for height in 4..=8 {
        fork = fork
            .apply_block(height, alternate_miner, &[], &FixtureProofs)
            .unwrap();
        fork.validate().unwrap();
    }
    assert_ne!(fork.state_root(), chain[8].state_root());
    assert_eq!(fork.available_total(), chain[8].available_total());
    assert_eq!(fork.pending_epoch_totals(), chain[8].pending_epoch_totals());
    assert_eq!(fork.issued(), chain[8].issued());
    assert_eq!(chain[3].height(), 3);
}

#[test]
fn reward_accounts_bounded_journals_recover_and_reverse_epoch_claim_histories() {
    let (initial, key, policy, _, _) = setup();
    let miner = policy.identifier().unwrap();
    let mut state = initial.clone();
    let mut journals = Vec::new();
    for height in 1..=7 {
        let actions = match height {
            1 => vec![claim(&state, &key, &policy, 10 * COIN, 2, 0)],
            2 => vec![RewardAccountAction::Donation {
                donation: TreasuryDonation {
                    context: state.context().clone(),
                    amount: COIN,
                    fee: 2,
                    memo: BoundedVec::new(b"journal donation".to_vec()).unwrap(),
                },
                proof: proof(),
            }],
            5 => vec![claim(&state, &key, &policy, COIN, 3, 1)],
            _ => vec![],
        };
        let (next, journal) = state
            .apply_block_journaled(height, miner, &actions, &FixtureProofs, None)
            .unwrap();
        assert!(journal.rows().len() <= 2);
        assert_eq!(
            state
                .apply_block(height, miner, &actions, &FixtureProofs)
                .unwrap()
                .state_root(),
            next.state_root()
        );
        let replayed = state
            .replay_journal(&journal, RewardJournalDirection::Forward, next.state_root())
            .unwrap();
        replayed.validate().unwrap();
        assert_eq!(replayed, next);
        let rows = next
            .checkpoint_rows()
            .map(|(id, a)| (id, a.clone()))
            .collect::<Vec<_>>();
        let recovered = RewardAccountLedger::restore_checkpoint(
            next.genesis().clone(),
            next.checkpoint(),
            rows.clone(),
            next.state_root(),
        )
        .unwrap();
        assert_eq!(recovered, next);
        assert!(RewardAccountLedger::restore_checkpoint(
            next.genesis().clone(),
            next.checkpoint(),
            rows.into_iter().skip(1),
            next.state_root()
        )
        .is_err());
        let mut bytes = journal.encode();
        let end = bytes.len() - 1;
        bytes[end] ^= 1;
        if let Ok(mutated) = RewardAccountJournal::decode(&mut bytes.as_slice()) {
            assert!(state
                .replay_journal(&mutated, RewardJournalDirection::Forward, next.state_root())
                .is_err());
        }
        assert!(state
            .replay_journal(
                &journal,
                RewardJournalDirection::Forward,
                RewardAccountsRoot48::ZERO
            )
            .is_err());
        journals.push(journal);
        state = next;
    }
    for journal in journals.iter().rev() {
        state = state
            .replay_journal(
                journal,
                RewardJournalDirection::Reverse,
                journal.before_root(),
            )
            .unwrap();
        state.validate().unwrap();
    }
    assert_eq!(state, initial);
}

#[test]
fn reward_accounts_fixed_treasury_prefunded_successor_cannot_block_rotation() {
    let (initial, miner_key, miner_policy, old_key, old_policy) = setup();
    let pot = protocol_treasury_account_id();
    let miner = miner_policy.identifier().unwrap();
    let mut genesis = initial.genesis().clone();
    let mut rows = genesis.allocations.clone().into_inner();
    rows.push(GenesisAllocation {
        account: pot,
        amount: 10 * COIN,
    });
    rows.sort_by_key(|r| r.account);
    genesis.allocations = BoundedVec::new(rows).unwrap();
    let mut context = initial.context().clone();
    context.genesis_config_hash = RulesHash48::new(genesis.commitment().unwrap());
    let initial = RewardAccountLedger::new(genesis, context).unwrap();
    let intent = TreasuryForkIntent {
        context: initial.context().clone(),
        current_generation: 0,
        activation_height: 3,
        successor_rules: RulesHash48::new([39; 48]),
        successor_policy: miner_policy.clone(),
    };
    let certificate = TreasuryForkCertificate {
        approvals: BoundedVec::new(vec![AccountApproval::sign(
            0,
            &old_key,
            &intent.authorization_digest(),
        )])
        .unwrap(),
        intent,
    };
    let compiled = CompiledTreasuryFork {
        activation_height: 3,
        successor_rules: certificate.intent.successor_rules,
        successor_policy: miner,
    };
    // The proposed signer policy already owns an ordinary account funded at
    // genesis. Both that account and the logical pot advance their own nonce.
    let ordinary = claim(&initial, &miner_key, &miner_policy, 5 * COIN, 1, 0);
    let treasury = claim(&initial, &old_key, &old_policy, COIN, 2, 0);
    let state = initial
        .apply_block_with_fork(
            1,
            miner,
            &[
                ordinary,
                treasury,
                RewardAccountAction::TreasuryFork { certificate },
            ],
            &FixtureProofs,
            Some(&compiled),
        )
        .unwrap();
    let state = state.apply_block(2, miner, &[], &FixtureProofs).unwrap();
    assert_eq!(state.account_at(miner, 3).unwrap().next_sequence(), 1);
    assert_eq!(state.account_at(pot, 3).unwrap().next_sequence(), 1);
    let old_claim = claim(&state, &old_key, &old_policy, COIN, 0, 1);
    let ordinary_claim = claim(&state, &miner_key, &miner_policy, COIN, 1, 1);
    let mut treasury_claim = claim(&state, &miner_key, &miner_policy, 2 * COIN, 1, 1);
    if let RewardAccountAction::Claim {
        claim, approvals, ..
    } = &mut treasury_claim
    {
        claim.account = pot;
        claim.policy_generation = 1;
        *approvals = BoundedVec::new(vec![AccountApproval::sign(
            0,
            &miner_key,
            &claim.authorization_digest(),
        )])
        .unwrap();
    }
    assert!(state
        .apply_block_with_fork(3, miner, &[old_claim], &FixtureProofs, Some(&compiled))
        .is_err());
    let (after, journal) = state
        .apply_block_journaled(
            3,
            miner,
            &[treasury_claim, ordinary_claim],
            &FixtureProofs,
            Some(&compiled),
        )
        .unwrap();
    assert_eq!(after.treasury(), pot);
    assert_eq!(after.treasury_policy(), &miner_policy);
    assert_eq!(after.policy_generation(), 1);
    assert_eq!(after.account_at(pot, 3).unwrap().available(), 7 * COIN - 3);
    assert_eq!(
        after.account_at(miner, 3).unwrap().available(),
        94 * COIN - 2
    );
    assert_eq!(after.account_at(pot, 3).unwrap().next_sequence(), 2);
    assert_eq!(after.account_at(miner, 3).unwrap().next_sequence(), 2);
    after.validate().unwrap();
    let reversed = after
        .replay_journal(
            &journal,
            RewardJournalDirection::Reverse,
            state.state_root(),
        )
        .unwrap();
    assert_eq!(reversed, state);
    assert!(after
        .apply_block(4, old_policy.identifier().unwrap(), &[], &FixtureProofs)
        .is_ok());
}
