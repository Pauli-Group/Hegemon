use frame_support::sp_runtime::BuildStorage;
use frame_support::{assert_ok, BoundedVec};
use runtime::{
    chain_spec, Attestations, Identity, Pow, PowDifficulty, Runtime, RuntimeOrigin, Settlement,
    System, Timestamp,
};
use sp_core::H256;
use sp_io::TestExternalities;

fn account(seed: u8) -> runtime::AccountId {
    runtime::AccountId::new([seed; 32])
}

fn new_ext() -> TestExternalities {
    let spec = chain_spec::development_config();
    spec.genesis.build_storage().unwrap().into()
}

fn compact_to_target(bits: u32) -> Option<sp_core::U256> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 {
        return None;
    }
    if exponent > 32 {
        return Some(sp_core::U256::MAX);
    }
    let mut target = sp_core::U256::from(mantissa);
    if exponent > 3 {
        target <<= 8 * (exponent - 3);
    } else {
        target >>= 8 * (3 - exponent);
    }
    Some(target)
}

fn seal_meets_target(pre_hash: H256, nonce: u64, pow_bits: u32) -> bool {
    let mut data = pre_hash.as_bytes().to_vec();
    data.extend_from_slice(&nonce.to_le_bytes());
    let hash = sp_io::hashing::blake2_256(&data);
    let hash_u256 = sp_core::U256::from_big_endian(&hash);
    if let Some(target) = compact_to_target(pow_bits) {
        hash_u256 <= target
    } else {
        false
    }
}

fn valid_nonce(pre_hash: H256, pow_bits: u32) -> u64 {
    (0u64..)
        .find(|candidate| seal_meets_target(pre_hash, *candidate, pow_bits))
        .expect("nonce available for easy difficulty")
}

#[test]
fn chain_specs_cover_pow_and_telemetry_defaults() {
    let dev = chain_spec::development_config();
    assert_eq!(dev.pow_bits, PowDifficulty::get());
    assert!(dev
        .telemetry_endpoints
        .iter()
        .any(|url| url.contains("telemetry")));
    // No pre-mine in development config - all issuance from mining rewards
    assert!(dev.genesis.balances.balances.is_empty());

    let testnet = chain_spec::testnet_config();
    assert_eq!(testnet.pow_bits, PowDifficulty::get());
    assert!(!testnet.bootnodes.is_empty());
    assert!(testnet
        .telemetry_endpoints
        .iter()
        .any(|url| url.contains("testnet")));
}

#[test]
fn pow_identity_attestation_settlement_flow() {
    let alice = account(1);
    let bob = account(2);
    let carol = account(3);
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(0);

        let pow_bits = PowDifficulty::get();
        let pre_hash = chain_spec::genesis_pre_hash();
        let nonce = valid_nonce(pre_hash, pow_bits);
        assert_ok!(Pow::submit_work(
            RuntimeOrigin::signed(alice.clone()),
            pre_hash,
            nonce,
            pow_bits,
            0,
        ));
        assert_eq!(
            runtime::pow::Validators::<Runtime>::get(),
            vec![alice.clone()]
        );

        assert_ok!(Identity::store_schema(
            RuntimeOrigin::root(),
            1u32,
            b"kyc-basic".to_vec(),
            true,
        ));
        assert_ok!(Identity::issue_credential(
            RuntimeOrigin::signed(alice.clone()),
            1u32,
            bob.clone(),
            None,
            b"attestation".to_vec(),
            vec![7u32],
        ));
        assert!(Identity::has_role(&bob, &7u32));

        let root: BoundedVec<_, runtime::MaxRootSize> = b"commitment-root"
            .to_vec()
            .try_into()
            .expect("fits max root");
        assert_ok!(Attestations::submit_commitment(
            RuntimeOrigin::signed(bob.clone()),
            1u64,
            pallet_attestations::RootKind::Merkle,
            root.clone(),
        ));
        let stored =
            pallet_attestations::Commitments::<Runtime>::get(1u64).expect("commitment recorded");
        assert_eq!(stored.root, root);

        // Settlement instruction submission (no proof required yet)
        let legs: BoundedVec<_, runtime::MaxLegs> = vec![pallet_settlement::Leg {
            from: bob.clone(),
            to: carol.clone(),
            asset: 0u32,
            amount: 10u128,
        }]
        .try_into()
        .expect("leg within limit");
        let memo: BoundedVec<_, runtime::MaxMemo> =
            b"settle".to_vec().try_into().expect("memo within limit");
        assert_ok!(Settlement::submit_instruction(
            RuntimeOrigin::signed(bob.clone()),
            legs,
            pallet_settlement::NettingKind::Bilateral,
            memo,
        ));

        // Verify instruction was queued
        assert!(!pallet_settlement::PendingQueue::<Runtime>::get().is_empty());
    });
}
