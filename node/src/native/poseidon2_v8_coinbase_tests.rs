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
