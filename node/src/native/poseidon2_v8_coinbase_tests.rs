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

fn premainnet_combined_network() -> NativeNetworkIdentity {
    let manifest = serde_json::from_str(include_str!(
        "../../../config/testnet/0.11/network-manifest.json"
    ))
    .unwrap();
    let network = NativeNetworkIdentity::from_manifest(manifest).unwrap();
    assert_eq!(
        network.chain_id(),
        consensus_light_client::PREMAINNET_CHAIN_ID
    );
    assert_eq!(
        consensus_light_client::native_combined_upgrade_activation_height(&network.chain_id()),
        Some(18_660)
    );
    network
}

fn premainnet_combined_reseal(parent: &NativeBlockMeta, meta: &mut NativeBlockMeta) {
    meta.cumulative_work = cumulative_work_after(&parent.cumulative_work, meta.pow_bits).unwrap();
    for counter in 0..4_096u64 {
        meta.nonce = nonce_from_counter(counter);
        let hash = pow_header_from_meta(meta).pow_hash();
        if native_seal_meets_target(&hash, meta.pow_bits) {
            meta.hash = hash;
            meta.work_hash = hash;
            return;
        }
    }
    panic!("bounded easy-target production-boundary fixture did not find a seal");
}

#[test]
fn premainnet_combined_native_target_and_mining_payload() {
    use consensus_light_client::{
        native_rules_hash, AsertAnchor, BITCOIN80_VERSION,
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC,
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED,
    };

    let network = premainnet_combined_network();
    let genesis = genesis_meta_for_network(network.pow_bits(0x207f_ffff), &network).unwrap();
    assert_eq!(
        genesis.rules_hash,
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC
    );
    // A trusted ancestor suffix tests production height selection without
    // claiming an independently imported 18,000-block history. Only its first
    // checkpoint is injected; every following row has a real bounded seal.
    let mut checkpoint = genesis;
    checkpoint.height = 18_650;
    checkpoint.header_mmr_len = checkpoint.height;
    checkpoint.timestamp_ms += checkpoint.height * 60_000;
    checkpoint.pow_bits = 0x2070_ffff;
    checkpoint.hash = [0x18; 32];
    checkpoint.work_hash = checkpoint.hash;
    let mut chain = vec![checkpoint];
    for height in 18_651..=18_661 {
        let parent = chain.last().unwrap();
        let expected = native_expected_child_pow_bits_from_chain(&chain, 0x207f_ffff).unwrap();
        let mut child = parent.clone();
        child.height = height;
        child.header_mmr_len = height;
        child.parent_hash = parent.hash;
        child.timestamp_ms += if height == 18_660 { 1_000 } else { 60_000 };
        child.rules_hash = native_rules_hash(&network.chain_id(), height);
        child.mining_version = native_mining_version_rolling_active(&network.chain_id(), height)
            .then_some(BITCOIN80_VERSION | 0x20);
        child.pow_bits = expected;
        premainnet_combined_reseal(parent, &mut child);
        verify_native_pow_meta(parent, &child, expected).unwrap();
        chain.push(child);
    }
    let at = |height| chain.iter().find(|meta| meta.height == height).unwrap();
    let before = at(18_659);
    let activated = at(18_660);
    let after = at(18_661);
    assert_eq!(
        before.rules_hash,
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC
    );
    assert_eq!(before.mining_version, None);
    for meta in [activated, after] {
        assert_eq!(
            meta.rules_hash,
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED
        );
        assert_eq!(meta.mining_version, Some(BITCOIN80_VERSION | 0x20));
        validate_native_mining_payload(meta).unwrap();
    }
    let anchor = AsertAnchor {
        height: 18_659,
        parent_timestamp_ms: at(18_658).timestamp_ms,
        pow_bits: before.pow_bits,
    };
    for (parent, child) in [(before, activated), (activated, after)] {
        assert_eq!(
            child.pow_bits,
            consensus_light_client::asert_next_bits(
                anchor,
                parent.height,
                parent.timestamp_ms,
                60_000,
                3_600_000
            )
            .unwrap()
        );
    }
    assert_eq!(activated.pow_bits, before.pow_bits);
    assert_ne!(after.pow_bits, activated.pow_bits);
    let legacy_boundary_bits = native_asic_expected_pow_bits_from_schedule(
        0x207f_ffff,
        before.pow_bits,
        before.height,
        activated.height,
        before.timestamp_ms,
        Some(at(18_650).timestamp_ms),
    )
    .unwrap();
    assert_ne!(activated.pow_bits, legacy_boundary_bits);
    let mut stale_target = activated.clone();
    stale_target.pow_bits = legacy_boundary_bits;
    premainnet_combined_reseal(before, &mut stale_target);
    let error = verify_native_pow_meta(before, &stale_target, activated.pow_bits).unwrap_err();
    assert!(error.to_string().contains("PoW bits mismatch"), "{error:#}");

    for (parent, original, wrong_rules) in [
        (
            at(18_658),
            before,
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED,
        ),
        (
            before,
            activated,
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC,
        ),
    ] {
        let mut wrong = original.clone();
        wrong.rules_hash = wrong_rules;
        premainnet_combined_reseal(parent, &mut wrong);
        let error = verify_native_pow_meta(parent, &wrong, original.pow_bits).unwrap_err();
        assert!(error.to_string().contains("RulesHashMismatch"), "{error:#}");
    }
    let mut early_payload = before.clone();
    early_payload.mining_version = Some(BITCOIN80_VERSION);
    assert!(validate_native_mining_payload(&early_payload).is_err());
    let mut missing_payload = activated.clone();
    missing_payload.mining_version = None;
    assert!(validate_native_mining_payload(&missing_payload).is_err());
    for invalid_version in [BITCOIN80_VERSION | 1, BITCOIN80_VERSION ^ 0x2000_0000] {
        let mut invalid = activated.clone();
        invalid.mining_version = Some(invalid_version);
        let error = validate_native_mining_payload(&invalid).unwrap_err();
        assert!(
            error.to_string().contains("mining version invalid"),
            "{error:#}"
        );
    }
    let mut rolled = activated.clone();
    rolled.mining_version = Some(BITCOIN80_VERSION | 0x40);
    premainnet_combined_reseal(before, &mut rolled);
    verify_native_pow_meta(before, &rolled, activated.pow_bits).unwrap();
    assert_eq!(
        pow_header_from_meta(activated).pre_hash(),
        pow_header_from_meta(&rolled).pre_hash()
    );
    assert_ne!(rolled.hash, activated.hash);

    let prefix = &chain[..chain.iter().position(|meta| meta.height == 18_660).unwrap()];
    let mut wrong_anchor = prefix.to_vec();
    let anchor_index = wrong_anchor.len() - 1;
    wrong_anchor[anchor_index].parent_hash[0] ^= 1;
    assert!(native_expected_child_pow_bits_from_chain(&wrong_anchor, 0x207f_ffff).is_err());
    assert!(
        native_expected_child_pow_bits_from_chain(&prefix[prefix.len() - 1..], 0x207f_ffff)
            .is_err()
    );
}

fn premainnet_combined_reward_action(
    miner_amount: u64,
    funding_amount: u64,
    funding: &ShieldedAddress,
    treasury_only: bool,
) -> PendingAction {
    let miner = RootSecret::from_bytes([0xc4; 32])
        .derive()
        .poseidon2_v8_address(0)
        .unwrap()
        .shielded_address();
    let args = wallet::poseidon2_v8_coinbase::build_poseidon2_v8_rewards_args(
        if treasury_only { funding } else { &miner },
        miner_amount,
        funding,
        funding_amount,
        &mut StdRng::seed_from_u64(18_660 + miner_amount + funding_amount),
    )
    .unwrap();
    treasury_action_from_args(args)
}

#[test]
fn premainnet_combined_treasury_selection_admission_and_maturity() {
    let network = premainnet_combined_network();
    let funding = ShieldedAddress::decode(network.funding_address().unwrap()).unwrap();
    // Use the exact production network selector, never the test policy seam.
    let policy = treasury_reward_policy_for_network(&network);
    assert_eq!(policy.activation_height(), Some(18_660));
    assert!(policy.entitlement(18_659).is_none());
    assert_eq!(
        policy.entitlement(18_660).unwrap().pending_after,
        100_000_000
    );
    assert_eq!(
        policy.entitlement(18_661).unwrap().pending_after,
        200_000_000
    );
    let check = |actions: &[PendingAction], height| {
        validate_coinbase_funding_accounting_with_policy(actions, height, Some(&funding), policy)
    };
    let historical = premainnet_combined_reward_action(400_000_000, 100_000_000, &funding, false);
    validate_coinbase_action_payload(&historical).unwrap();
    check(std::slice::from_ref(&historical), 18_659).unwrap();
    assert!(check(std::slice::from_ref(&historical), 18_660).is_err());
    assert_eq!(
        native_supply_composition_projection_with_policy(&[historical], 18_659, policy)
            .unwrap()
            .supply_delta,
        500_000_000
    );
    let miner_only = premainnet_combined_reward_action(400_000_000, 0, &funding, false);
    for height in [18_660, 18_661, 18_718] {
        check(std::slice::from_ref(&miner_only), height).unwrap();
        check(&[], height).unwrap();
        assert_eq!(
            native_supply_composition_projection_with_policy(
                std::slice::from_ref(&miner_only),
                height,
                policy
            )
            .unwrap()
            .supply_delta,
            400_000_000
        );
    }
    let expected_payout: u64 = (18_660..=18_719)
        .map(|height| consensus::reward::block_subsidy(height) / 5)
        .sum();
    assert_eq!(expected_payout, 6_000_000_000);
    assert_eq!(
        policy.entitlement(18_718).unwrap().pending_after,
        5_900_000_000
    );
    let due = policy.entitlement(18_719).unwrap();
    assert_eq!(due.batch_start, 18_660);
    assert_eq!(due.payout_height, Some(18_719));
    assert_eq!(due.payout, expected_payout);
    assert_eq!(due.pending_after, 0);
    let payout = premainnet_combined_reward_action(400_000_000, expected_payout, &funding, false);
    validate_coinbase_action_payload(&payout).unwrap();
    check(std::slice::from_ref(&payout), 18_719).unwrap();
    assert_eq!(
        advance_native_supply_digest_with_policy(23, std::slice::from_ref(&payout), 18_719, policy)
            .unwrap(),
        6_400_000_023
    );
    assert!(check(std::slice::from_ref(&payout), 18_718).is_err());
    assert!(check(&[], 18_719).is_err());
    assert!(check(std::slice::from_ref(&miner_only), 18_719).is_err());
    assert!(check(&[payout.clone(), payout.clone()], 18_719).is_err());
    let wrong_amount =
        premainnet_combined_reward_action(400_000_000, expected_payout - 1, &funding, false);
    assert!(check(&[wrong_amount], 18_719).is_err());
    let (wrong_recipient, _) = treasury_batch_fixture(400_000_000, expected_payout, false);
    assert!(check(&[wrong_recipient], 18_719).is_err());
    let treasury_only = premainnet_combined_reward_action(expected_payout, 0, &funding, true);
    check(std::slice::from_ref(&treasury_only), 18_719).unwrap();
    assert_eq!(
        native_supply_composition_projection_with_policy(&[treasury_only], 18_719, policy)
            .unwrap()
            .supply_delta,
        u128::from(expected_payout)
    );

    assert_eq!(
        consensus::reward::coinbase_release_height(18_719),
        Some(18_838)
    );
    assert_eq!(
        consensus::reward::coinbase_maturity_height(18_719),
        Some(18_839)
    );
    assert!(!consensus::reward::coinbase_mature_in_block(18_719, 18_838));
    assert!(consensus::reward::coinbase_mature_in_block(18_719, 18_839));
    let mut meta = genesis_meta_for_network(network.pow_bits(0x207f_ffff), &network).unwrap();
    meta.height = 18_719;
    for (parent_height, canonical, eligible) in [
        (18_837, true, false),
        (18_838, true, true),
        (18_839, false, false),
    ] {
        let observation = reward_observation_with_policy(
            &meta,
            std::slice::from_ref(&payout),
            canonical,
            parent_height,
            meta.hash,
            policy,
        )
        .unwrap();
        assert_eq!(observation["maturity_height"], 18_839);
        assert_eq!(observation["height_eligible_for_next_block"], eligible);
        assert_eq!(
            observation["treasury_amount_atoms"],
            expected_payout.to_string()
        );
    }
}
