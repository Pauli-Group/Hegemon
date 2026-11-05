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
fn proof() -> BoundedVec<u8, MAX_REWARD_PROOF_BYTES> {
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
        account: policy.identifier().unwrap(),
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
