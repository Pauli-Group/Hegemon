use frame_support::{assert_noop, assert_ok};
use sp_core::H256;
use sp_io::TestExternalities;
use sp_runtime::BuildStorage;

use runtime::{
    chain_spec, pow, Pow, PowDifficulty, Runtime, RuntimeEvent, RuntimeOrigin, System, Timestamp,
};

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
fn development_chain_spec_matches_runtime_pow_difficulty() {
    let spec = chain_spec::development_config();
    assert_eq!(spec.pow_bits, PowDifficulty::get());
}

#[test]
fn pow_block_imports_with_valid_seal() {
    new_ext().execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(0);
        let pow_bits = PowDifficulty::get();
        let pre_hash = H256::repeat_byte(7);
        let nonce = valid_nonce(pre_hash, pow_bits);

        assert_ok!(Pow::submit_work(
            RuntimeOrigin::signed(runtime::AccountId::new([1u8; 32])),
            pre_hash,
            nonce,
            pow_bits,
            0,
        ));

        let events = System::events();
        assert!(events.iter().any(|evt| matches!(
            evt.event,
            RuntimeEvent::Pow(pow::Event::PowBlockImported { pow_bits: b, nonce: n, .. }) if b == pow_bits && n == nonce
        )));
        assert_eq!(pow::Difficulty::<Runtime>::get(), pow_bits);
    });
}

#[test]
fn pow_rejects_invalid_seal() {
    new_ext().execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(0);
        // The dev difficulty expands to the maximum target, so every nonce is
        // valid there. Use a finite easy target for the negative-path check.
        let pow_bits = 0x207fffff;
        pow::Difficulty::<Runtime>::put(pow_bits);
        let pre_hash = H256::repeat_byte(9);
        let bad_nonce = (0u64..)
            .find(|candidate| !seal_meets_target(pre_hash, *candidate, pow_bits))
            .expect("non-matching nonce exists");

        assert_noop!(
            Pow::submit_work(
                RuntimeOrigin::signed(runtime::AccountId::new([1u8; 32])),
                pre_hash,
                bad_nonce,
                pow_bits,
                0
            ),
            pow::Error::<Runtime>::InsufficientWork
        );
    });
}
