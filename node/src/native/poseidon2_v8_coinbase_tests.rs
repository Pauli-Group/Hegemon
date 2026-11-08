use super::*;

use rand::{rngs::StdRng, SeedableRng};
use wallet::keys::RootSecret;

fn coinbase_fixture(
    amount: u64,
) -> (
    PendingAction,
    MintPoseidon2V8CoinbaseArgs,
    wallet::keys::AddressKeyMaterial,
) {
    let keys = RootSecret::from_bytes([0x51; 32]).derive();
    let material = keys.poseidon2_v8_address(9).unwrap();
    let mut rng = StdRng::seed_from_u64(11);
    let args = wallet::poseidon2_v8_coinbase::build_poseidon2_v8_coinbase_args(
        &material.shielded_address(),
        amount,
        &mut rng,
    )
    .unwrap();
    let (_, metadata) = coinbase_ciphertext_metadata(&args.miner_note.encrypted_note);
    let (ciphertext_hash, ciphertext_size) = metadata.unwrap();
    let mut action = PendingAction {
        tx_hash: ActionId48::ZERO,
        binding: protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_MINT_POSEIDON2_V8_COINBASE,
        anchor: [0; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: vec![ciphertext_hash],
        ciphertext_sizes: vec![ciphertext_size],
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
    };
    action.tx_hash = pending_action_hash(&action);
    (action, args, material)
}

#[test]
fn exact_v8_coinbase_wire_is_small_spendable_and_fail_closed_at_ingress() {
    let amount = consensus::reward::block_subsidy(1);
    let (action, args, material) = coinbase_fixture(amount);
    validate_coinbase_action_payload(&action).unwrap();
    let commitment = admitted_poseidon2_v8_coinbase_commitment(&action).unwrap();
    assert_eq!(commitment.limbs(), args.miner_note.commitment);
    assert_eq!(coinbase_action_amount(&action).unwrap(), amount);
    assert_eq!(action.encoded_size(), 2_520);
    assert_eq!(canonical_ciphertext_count_for_action(&action).unwrap(), 0);
    assert!(is_coinbase_action(&action));
    assert!(is_poseidon2_v8_coinbase_action(&action));
    assert!(!owns_legacy_ciphertext_da_rows(&action));

    let recovered =
        wallet::poseidon2_v8_coinbase::decrypt_poseidon2_v8_coinbase_opening(&args, &material)
            .unwrap();
    assert_eq!(recovered.value, amount);
    assert_eq!(
        recovered.authorization_key,
        args.miner_note.opening.authorization_key
    );

    let ingress_error = ensure_native_v3_active_action_route_ids(
        FAMILY_SHIELDED_POOL,
        ACTION_MINT_POSEIDON2_V8_COINBASE,
        false,
    )
    .expect_err("V8 coinbase must remain closed at external ingress");
    assert!(ingress_error.to_string().contains("miner-local outputs"));
    validate_coinbase_route_at_height(std::slice::from_ref(&action), 1)
        .expect("V8 coinbase route validation is structural, not production authority");
}

#[test]
fn v8_coinbase_mutations_reject_before_state_append() {
    let (baseline, _, _) = coinbase_fixture(consensus::reward::block_subsidy(1));

    let mutate_args = |mutator: fn(&mut MintPoseidon2V8CoinbaseArgs)| {
        let mut action = baseline.clone();
        let mut args: MintPoseidon2V8CoinbaseArgs =
            decode_scale_exact(&action.public_args, "test V8 coinbase args").unwrap();
        mutator(&mut args);
        action.public_args = args.encode();
        assert!(validate_coinbase_action_payload(&action).is_err());
    };
    mutate_args(|args| args.miner_note.opening.value = 0);
    mutate_args(|args| args.miner_note.opening.asset_id = 1);
    mutate_args(|args| args.miner_note.opening.authorization_key = [0; 4]);
    mutate_args(|args| args.miner_note.commitment[0] ^= 1);
    mutate_args(|args| args.miner_note.encrypted_note.ciphertext[0] ^= 1);

    let mut wrong_hash = baseline.clone();
    wrong_hash.ciphertext_hashes[0][0] ^= 1;
    assert!(validate_coinbase_action_payload(&wrong_hash).is_err());

    let mut wrong_size = baseline.clone();
    wrong_size.ciphertext_sizes[0] -= 1;
    assert!(validate_coinbase_action_payload(&wrong_size).is_err());

    let mut legacy_commitment_seam = baseline;
    legacy_commitment_seam.commitments.push([7; 48]);
    assert!(validate_coinbase_action_payload(&legacy_commitment_seam).is_err());
}

fn rewards_fixture(
    height: u64,
    miner_delta: i64,
    funding_delta: i64,
) -> (PendingAction, ShieldedAddress) {
    let funding = RootSecret::from_bytes([0x61; 32])
        .derive()
        .poseidon2_v8_address(8)
        .unwrap()
        .shielded_address();
    let miner = RootSecret::from_bytes([0x51; 32])
        .derive()
        .poseidon2_v8_address(9)
        .unwrap()
        .shielded_address();
    let (miner_amount, funding_amount) =
        poseidon2_v8_reward_split(consensus::reward::block_subsidy(height), 0).unwrap();
    let args = wallet::poseidon2_v8_coinbase::build_poseidon2_v8_rewards_args(
        &miner,
        miner_amount.checked_add_signed(miner_delta).unwrap(),
        &funding,
        funding_amount.checked_add_signed(funding_delta).unwrap(),
        &mut StdRng::seed_from_u64(41),
    )
    .unwrap();
    let metadata = core::iter::once(&args.miner_note)
        .chain(args.funding_note.iter())
        .map(|note| {
            coinbase_ciphertext_metadata(&note.encrypted_note)
                .1
                .unwrap()
        })
        .collect::<Vec<_>>();
    let mut action = PendingAction {
        tx_hash: ActionId48::ZERO,
        binding: protocol_versioning::launch_candidate::RP06_VERSION_BINDING.into(),
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_MINT_POSEIDON2_V8_REWARDS,
        anchor: [0; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: metadata.iter().map(|(hash, _)| *hash).collect(),
        ciphertext_sizes: metadata.iter().map(|(_, size)| *size).collect(),
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
    };
    action.tx_hash = pending_action_hash(&action);
    (action, funding)
}

#[test]
fn exact_rewards_reject_tax_diversion_legacy_bypass_and_partial_issuance() {
    let height = 1;
    let (action, funding) = rewards_fixture(height, 0, 0);
    validate_coinbase_action_payload(&action).unwrap();
    validate_coinbase_funding_accounting(std::slice::from_ref(&action), height, Some(&funding))
        .unwrap();
    assert!(admitted_poseidon2_v8_coinbase_commitments(&action)
        .unwrap()
        .iter()
        .all(Option::is_some));
    assert_eq!(canonical_ciphertext_count_for_action(&action).unwrap(), 0);
    assert!(!owns_legacy_ciphertext_da_rows(&action));
    assert!(!pending_action_peer_relayable(&action));
    assert!(ensure_native_v3_active_action_route_ids(
        FAMILY_SHIELDED_POOL,
        ACTION_MINT_POSEIDON2_V8_REWARDS,
        false
    )
    .is_err());
    assert!(
        validate_coinbase_funding_accounting(std::slice::from_ref(&action), height, None).is_err()
    );
    // Preserve total while diverting one funding unit back to the miner.
    let (diverted, _) = rewards_fixture(height, 1, -1);
    assert!(validate_coinbase_accounting(&[diverted], height)
        .unwrap_err()
        .to_string()
        .contains("allocation mismatch"));
    let (legacy, _, _) = coinbase_fixture(consensus::reward::block_subsidy(height));
    assert!(validate_coinbase_funding_accounting(&[legacy], height, Some(&funding)).is_err());
    let wrong_address = RootSecret::from_bytes([0x71; 32])
        .derive()
        .poseidon2_v8_address(8)
        .unwrap()
        .shielded_address();
    assert!(validate_coinbase_funding_accounting(
        std::slice::from_ref(&action),
        height,
        Some(&wrong_address)
    )
    .is_err());
    let mut wrong_extension = funding.clone();
    wrong_extension.pk_auth_extension[0] ^= 1;
    assert!(validate_coinbase_funding_accounting(
        std::slice::from_ref(&action),
        height,
        Some(&wrong_extension)
    )
    .is_err());
    // Both shares may be forfeited together; no partial issuance occurs.
    validate_coinbase_funding_accounting(&[], height, Some(&funding)).unwrap();
    let mut malformed = action.clone();
    malformed.public_args.push(0);
    assert!(validate_coinbase_action_payload(&malformed).is_err());
    let mut missing = action;
    missing.ciphertext_hashes.pop();
    missing.ciphertext_sizes.pop();
    assert!(validate_coinbase_action_payload(&missing).is_err());
}

#[test]
fn late_subsidy_canonically_omits_only_zero_funding() {
    let height = 27 * consensus::reward::HALVING_INTERVAL + 1;
    let subsidy = consensus::reward::block_subsidy(height);
    assert!((1..5).contains(&subsidy));
    let (action, funding) = rewards_fixture(height, 0, 0);
    validate_coinbase_funding_accounting(std::slice::from_ref(&action), height, Some(&funding))
        .unwrap();
    let args: MintPoseidon2V8RewardsArgs =
        decode_scale_exact(&action.public_args, "late rewards").unwrap();
    assert!(args.funding_note.is_none());
    assert_eq!(args.miner_note.opening.value, subsidy);
    assert_eq!(
        admitted_poseidon2_v8_coinbase_commitments(&action).unwrap()[1],
        None
    );
}

fn treasury_batch_fixture(
    primary_amount: u64,
    secondary_amount: u64,
    primary_is_treasury: bool,
) -> (PendingAction, ShieldedAddress) {
    let treasury = RootSecret::from_bytes([0xa1; 32])
        .derive()
        .poseidon2_v8_address(0)
        .unwrap()
        .shielded_address();
    let miner = RootSecret::from_bytes([0xa2; 32])
        .derive()
        .poseidon2_v8_address(0)
        .unwrap()
        .shielded_address();
    let args = wallet::poseidon2_v8_coinbase::build_poseidon2_v8_rewards_args(
        if primary_is_treasury {
            &treasury
        } else {
            &miner
        },
        primary_amount,
        &treasury,
        secondary_amount,
        &mut StdRng::seed_from_u64(primary_amount + secondary_amount + 901),
    )
    .unwrap();
    (treasury_action_from_args(args), treasury)
}

fn treasury_action_from_args(args: MintPoseidon2V8RewardsArgs) -> PendingAction {
    let metadata = core::iter::once(&args.miner_note)
        .chain(args.funding_note.iter())
        .map(|note| {
            coinbase_ciphertext_metadata(&note.encrypted_note)
                .1
                .unwrap()
        })
        .collect::<Vec<_>>();
    let mut action = PendingAction {
        tx_hash: ActionId48::ZERO,
        binding: protocol_versioning::launch_candidate::RP06_VERSION_BINDING.into(),
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_MINT_POSEIDON2_V8_REWARDS,
        anchor: [0; 48],
        nullifiers: vec![],
        commitments: vec![],
        ciphertext_hashes: metadata.iter().map(|(hash, _)| *hash).collect(),
        ciphertext_sizes: metadata.iter().map(|(_, size)| *size).collect(),
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
    };
    action.tx_hash = pending_action_hash(&action);
    action
}

#[test]
fn treasury_cadence_activation_is_exact_and_legacy_history_stays_valid() {
    let policy = consensus::treasury::TreasuryRewardPolicy::at(120).unwrap();
    let (historical, treasury) = rewards_fixture(119, 0, 0);
    validate_coinbase_funding_accounting_with_policy(
        &[historical.clone()],
        119,
        Some(&treasury),
        policy,
    )
    .unwrap();
    assert!(validate_coinbase_funding_accounting_with_policy(
        &[historical],
        120,
        Some(&treasury),
        policy
    )
    .is_err());
    for height in [120, 178, 180] {
        let (action, treasury) = treasury_batch_fixture(400_000_000, 0, false);
        validate_coinbase_funding_accounting_with_policy(
            &[action.clone()],
            height,
            Some(&treasury),
            policy,
        )
        .unwrap();
        validate_coinbase_funding_accounting_with_policy(&[], height, Some(&treasury), policy)
            .unwrap();
        assert_eq!(
            native_supply_composition_projection_with_policy(&[action], height, policy)
                .unwrap()
                .supply_delta,
            400_000_000
        );
    }
    let (boundary, treasury) = treasury_batch_fixture(400_000_000, 6_000_000_000, false);
    validate_coinbase_funding_accounting_with_policy(
        &[boundary.clone()],
        179,
        Some(&treasury),
        policy,
    )
    .unwrap();
    assert_eq!(
        advance_native_supply_digest_with_policy(23, &[boundary.clone()], 179, policy).unwrap(),
        6_400_000_023
    );
    assert!(validate_coinbase_funding_accounting(&[boundary], 179, Some(&treasury)).is_err());
    let fresh = consensus::treasury::TreasuryRewardPolicy::from_genesis();
    for height in [1, 59, 61] {
        let (action, treasury) = treasury_batch_fixture(400_000_000, 0, false);
        validate_coinbase_funding_accounting_with_policy(&[action], height, Some(&treasury), fresh)
            .unwrap();
    }
    for height in [60, 120] {
        let (action, treasury) = treasury_batch_fixture(400_000_000, 6_000_000_000, false);
        validate_coinbase_funding_accounting_with_policy(&[action], height, Some(&treasury), fresh)
            .unwrap();
    }
}

#[test]
fn treasury_cadence_rejects_early_missing_duplicate_zero_wrong_value_and_policy() {
    let policy = consensus::treasury::TreasuryRewardPolicy::from_genesis();
    let (valid, treasury) = treasury_batch_fixture(400_000_000, 6_000_000_000, false);
    let check = |actions: &[PendingAction], height| {
        validate_coinbase_funding_accounting_with_policy(actions, height, Some(&treasury), policy)
    };
    assert!(check(&[valid.clone()], 59).is_err());
    assert!(check(&[], 60).is_err());
    assert!(check(&[valid.clone(), valid.clone()], 60).is_err());
    let (miner_only, _) = treasury_batch_fixture(400_000_000, 0, false);
    assert!(check(&[miner_only.clone()], 60).is_err());
    for (miner, funding) in [
        (400_000_001, 6_000_000_000),
        (400_000_000, 5_999_999_999),
        (400_000_000, 6_000_000_001),
    ] {
        let (action, _) = treasury_batch_fixture(miner, funding, false);
        assert!(check(&[action], 60).is_err());
    }
    let (treasury_only, _) = treasury_batch_fixture(6_000_000_000, 0, true);
    check(&[treasury_only.clone()], 60).unwrap();
    let (wrong_recipient, _) = treasury_batch_fixture(6_000_000_000, 0, false);
    assert!(check(&[wrong_recipient], 60).is_err());
    assert!(
        validate_coinbase_funding_accounting_with_policy(&[treasury_only], 60, None, policy)
            .is_err()
    );
    let mut args: MintPoseidon2V8RewardsArgs =
        decode_scale_exact(&valid.public_args, "treasury mutation").unwrap();
    args.funding_note = Some(args.miner_note.clone());
    assert!(check(&[treasury_action_from_args(args)], 60).is_err());
    let mut args: MintPoseidon2V8RewardsArgs =
        decode_scale_exact(&valid.public_args, "treasury mutation").unwrap();
    args.funding_note.as_mut().unwrap().opening.value = 0;
    assert!(check(&[treasury_action_from_args(args)], 60).is_err());
    // A valid exact-amount note with a different authorization extension cannot
    // redirect the mandatory payout even when recipient_key is unchanged.
    let mut wrong_policy = treasury.clone();
    wrong_policy.pk_auth_extension[0] ^= 1;
    assert!(validate_coinbase_funding_accounting_with_policy(
        &[valid.clone()],
        60,
        Some(&wrong_policy),
        policy
    )
    .is_err());
    let mut trailing = miner_only;
    trailing.action_id = ACTION_SHIELDED_TRANSFER_INLINE;
    trailing.family_id = FAMILY_SHIELDED_POOL;
    trailing.tx_hash = pending_action_hash(&trailing);
    assert!(check(&[valid, trailing], 60).is_err());
}

#[test]
fn treasury_cadence_miner_forfeiture_fees_and_actual_supply_are_independent() {
    let policy = consensus::treasury::TreasuryRewardPolicy::from_genesis();
    let (paired, treasury) = treasury_batch_fixture(400_000_017, 6_000_000_000, false);
    let mut fee = paired.clone();
    fee.action_id = ACTION_SHIELDED_TRANSFER_INLINE;
    fee.fee = 17;
    fee.tx_hash = pending_action_hash(&fee);
    let actions = vec![fee.clone(), paired];
    validate_coinbase_funding_accounting_with_policy(&actions, 60, Some(&treasury), policy)
        .unwrap();
    assert_eq!(
        native_supply_composition_projection_with_policy(&actions, 60, policy)
            .unwrap()
            .supply_delta,
        6_400_000_017
    );
    let (treasury_only, _) = treasury_batch_fixture(6_000_000_000, 0, true);
    let forfeited = vec![fee, treasury_only];
    validate_coinbase_funding_accounting_with_policy(&forfeited, 60, Some(&treasury), policy)
        .unwrap();
    assert_eq!(
        native_supply_composition_projection_with_policy(&forfeited, 60, policy)
            .unwrap()
            .supply_delta,
        6_000_000_000
    );
    assert!(advance_native_supply_digest_with_policy(u128::MAX, &forfeited, 60, policy).is_err());
    // Omission at every intermediate height never modifies scheduled accrual.
    for height in 1..60 {
        validate_coinbase_funding_accounting_with_policy(&[], height, Some(&treasury), policy)
            .unwrap();
    }
    assert_eq!(policy.entitlement(60).unwrap().payout, 6_000_000_000);
}

#[test]
fn treasury_cadence_zero_batches_and_final_exhaustion_residual() {
    let height = 64 * consensus::reward::HALVING_INTERVAL + 60;
    let policy = consensus::treasury::TreasuryRewardPolicy::from_genesis();
    assert_eq!(consensus::reward::block_subsidy(height), 0);
    assert_eq!(policy.entitlement(height).unwrap().payout, 0);
    let (_, treasury) = treasury_batch_fixture(1, 0, true);
    validate_coinbase_funding_accounting_with_policy(&[], height, Some(&treasury), policy).unwrap();
    let (forbidden, _) = treasury_batch_fixture(1, 0, true);
    assert!(validate_coinbase_funding_accounting_with_policy(
        &[forbidden],
        height,
        Some(&treasury),
        policy
    )
    .is_err());
    // The last positive treasury share may occur before the final subsidy atom.
    // Choose a batch beginning at a positive entitlement and ending after its
    // source epoch, then independently sum every rounded scheduled share.
    let mut last_positive = 0;
    for epoch in 0..64 {
        let end = (epoch + 1) * consensus::reward::HALVING_INTERVAL;
        if consensus::reward::block_subsidy(end) >= 5 {
            last_positive = end;
        }
    }
    assert!(last_positive > 0);
    let residual_policy =
        consensus::treasury::TreasuryRewardPolicy::at(last_positive - 19).unwrap();
    let payout_height = last_positive + 40;
    let exact: u64 = (last_positive - 19..=payout_height)
        .map(|h| consensus::reward::block_subsidy(h) / 5)
        .sum();
    assert!(exact > 0);
    assert_eq!(
        residual_policy.entitlement(payout_height).unwrap().payout,
        exact
    );
}
