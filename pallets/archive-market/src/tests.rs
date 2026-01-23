use super::*;
use crate::mock::{new_test_ext, ArchiveMarket, Balances, RuntimeOrigin, Test};
use frame_support::{assert_noop, assert_ok, BoundedVec};
use sp_std::vec::Vec;

fn endpoint(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

fn da_hash_leaf(index: u32, data: &[u8]) -> [u8; 48] {
    let mut input = Vec::new();
    input.extend_from_slice(b"da-leaf");
    input.extend_from_slice(&index.to_le_bytes());
    input.extend_from_slice(data);
    crypto::hashes::blake3_384(&input)
}

#[test]
fn register_provider_reserves_bond_and_stores_info() {
    new_test_ext().execute_with(|| {
        let bond = 500u128;
        let price = 2u128;
        let min_duration = 12u64;

        assert_ok!(ArchiveMarket::register_provider(
            RuntimeOrigin::signed(1),
            price,
            min_duration,
            endpoint(b"https://archive.example"),
            bond
        ));

        let info = Providers::<Test>::get(1).expect("provider stored");
        assert_eq!(info.bond, bond);
        assert_eq!(info.price_per_byte_block, price);
        assert_eq!(info.min_duration_blocks, min_duration);
        assert_eq!(info.endpoint, endpoint(b"https://archive.example"));
        assert_eq!(ProviderCount::<Test>::get(), 1);
        assert_eq!(Balances::reserved_balance(1), bond);
    });
}

#[test]
fn register_provider_rejects_low_bond() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ArchiveMarket::register_provider(
                RuntimeOrigin::signed(1),
                1,
                10,
                endpoint(b"https://archive.example"),
                10
            ),
            Error::<Test>::ProviderBondTooLow
        );
    });
}

#[test]
fn register_provider_rejects_duplicates() {
    new_test_ext().execute_with(|| {
        let bond = 200u128;
        assert_ok!(ArchiveMarket::register_provider(
            RuntimeOrigin::signed(1),
            3,
            10,
            endpoint(b"https://archive.example"),
            bond
        ));

        assert_noop!(
            ArchiveMarket::register_provider(
                RuntimeOrigin::signed(1),
                3,
                10,
                endpoint(b"https://archive.example"),
                bond
            ),
            Error::<Test>::ProviderAlreadyRegistered
        );
    });
}

#[test]
fn register_provider_enforces_limit() {
    new_test_ext().execute_with(|| {
        for account in 1..=8 {
            assert_ok!(ArchiveMarket::register_provider(
                RuntimeOrigin::signed(account),
                1,
                5,
                endpoint(b"https://archive.example"),
                150
            ));
        }

        assert_noop!(
            ArchiveMarket::register_provider(
                RuntimeOrigin::signed(9),
                1,
                5,
                endpoint(b"https://archive.example"),
                150
            ),
            Error::<Test>::ProviderLimitReached
        );
    });
}

#[test]
fn update_provider_changes_fields() {
    new_test_ext().execute_with(|| {
        assert_ok!(ArchiveMarket::register_provider(
            RuntimeOrigin::signed(1),
            2,
            10,
            endpoint(b"https://archive.example"),
            150
        ));

        assert_ok!(ArchiveMarket::update_provider(
            RuntimeOrigin::signed(1),
            9,
            99,
            endpoint(b"https://archive.next")
        ));

        let info = Providers::<Test>::get(1).expect("provider stored");
        assert_eq!(info.price_per_byte_block, 9);
        assert_eq!(info.min_duration_blocks, 99);
        assert_eq!(info.endpoint, endpoint(b"https://archive.next"));
        assert_eq!(Balances::reserved_balance(1), 150);
    });
}

#[test]
fn unregister_provider_requires_no_active_contracts() {
    new_test_ext().execute_with(|| {
        assert_ok!(ArchiveMarket::register_provider(
            RuntimeOrigin::signed(1),
            2,
            10,
            endpoint(b"https://archive.example"),
            150
        ));

        ActiveContracts::<Test>::insert(1, 1u32);
        assert_noop!(
            ArchiveMarket::unregister_provider(RuntimeOrigin::signed(1)),
            Error::<Test>::ActiveContractsRemaining
        );

        ActiveContracts::<Test>::insert(1, 0u32);
        assert_ok!(ArchiveMarket::unregister_provider(RuntimeOrigin::signed(1)));
        assert!(Providers::<Test>::get(1).is_none());
        assert_eq!(ProviderCount::<Test>::get(), 0);
        assert_eq!(Balances::reserved_balance(1), 0);
    });
}

#[test]
fn buy_contract_records_state_and_pays_provider() {
    new_test_ext().execute_with(|| {
        assert_ok!(ArchiveMarket::register_provider(
            RuntimeOrigin::signed(1),
            2,
            5,
            endpoint(b"https://archive.example"),
            200
        ));

        frame_system::Pallet::<Test>::set_block_number(10);
        let buyer_before = Balances::free_balance(2);
        let provider_before = Balances::free_balance(1);

        assert_ok!(ArchiveMarket::buy_contract(
            RuntimeOrigin::signed(2),
            1,
            10,
            20,
            10,
            1_000,
            50,
            30_000
        ));

        let contract = Contracts::<Test>::get(0).expect("contract stored");
        assert_eq!(contract.provider, 1);
        assert_eq!(contract.buyer, 2);
        assert_eq!(contract.start_block, 10);
        assert_eq!(contract.end_block, 20);
        assert_eq!(contract.retention_blocks, 10);
        assert_eq!(contract.expires_at, 30);
        assert_eq!(contract.byte_count, 1_000);
        assert_eq!(contract.price_per_byte_block, 2);
        assert_eq!(contract.total_cost, 20_000);
        assert_eq!(contract.bond_stake, 50);
        assert_eq!(contract.status, ContractStatus::Active);
        assert_eq!(ActiveContracts::<Test>::get(1), 1);
        assert_eq!(BondCommitted::<Test>::get(1), 50);
        assert_eq!(ProviderContracts::<Test>::get(1).into_inner(), vec![0]);

        assert_eq!(Balances::free_balance(2), buyer_before - 20_000);
        assert_eq!(Balances::free_balance(1), provider_before + 20_000);
    });
}

#[test]
fn renew_contract_extends_expiry_and_cost() {
    new_test_ext().execute_with(|| {
        assert_ok!(ArchiveMarket::register_provider(
            RuntimeOrigin::signed(1),
            3,
            5,
            endpoint(b"https://archive.example"),
            200
        ));

        frame_system::Pallet::<Test>::set_block_number(10);
        assert_ok!(ArchiveMarket::buy_contract(
            RuntimeOrigin::signed(2),
            1,
            10,
            20,
            10,
            100,
            50,
            10_000
        ));

        let buyer_before = Balances::free_balance(2);
        assert_ok!(ArchiveMarket::renew_contract(
            RuntimeOrigin::signed(2),
            0,
            5,
            2_000
        ));

        let contract = Contracts::<Test>::get(0).expect("contract stored");
        assert_eq!(contract.retention_blocks, 15);
        assert_eq!(contract.expires_at, 35);
        assert_eq!(contract.total_cost, 4_500);
        assert_eq!(contract.status, ContractStatus::Active);
        assert_eq!(Balances::free_balance(2), buyer_before - 1_500);
    });
}

#[test]
fn expire_contract_clears_state() {
    new_test_ext().execute_with(|| {
        assert_ok!(ArchiveMarket::register_provider(
            RuntimeOrigin::signed(1),
            1,
            3,
            endpoint(b"https://archive.example"),
            200
        ));

        frame_system::Pallet::<Test>::set_block_number(10);
        assert_ok!(ArchiveMarket::buy_contract(
            RuntimeOrigin::signed(2),
            1,
            10,
            12,
            5,
            100,
            40,
            1_000
        ));

        frame_system::Pallet::<Test>::set_block_number(17);
        assert_ok!(ArchiveMarket::expire_contract(
            RuntimeOrigin::signed(3),
            0
        ));

        assert!(Contracts::<Test>::get(0).is_none());
        assert_eq!(ActiveContracts::<Test>::get(1), 0);
        assert_eq!(BondCommitted::<Test>::get(1), 0);
        assert!(ProviderContracts::<Test>::get(1).is_empty());
    });
}

#[test]
fn respond_to_challenge_clears_pending() {
    new_test_ext().execute_with(|| {
        assert_ok!(ArchiveMarket::register_provider(
            RuntimeOrigin::signed(1),
            1,
            3,
            endpoint(b"https://archive.example"),
            200
        ));

        let contract_id = 0u64;
        let challenge_id = 7u64;
        let chunk_data: Vec<u8> = b"hello".to_vec();
        let page_root = da_hash_leaf(0, &chunk_data);
        let da_root = da_hash_leaf(0, &page_root);

        let challenge = ArchiveChallenge::<Test> {
            challenge_id,
            provider: 1,
            contract_id,
            block_number: 10,
            da_root,
            global_chunk_index: 0,
            deadline: 20,
        };
        Challenges::<Test>::insert(challenge_id, challenge);
        ChallengeQueue::<Test>::put(BoundedVec::try_from(vec![challenge_id]).unwrap());

        let chunk = DaChunk {
            index: 0,
            data: chunk_data,
        };
        let page_proof = DaChunkProof {
            chunk,
            merkle_path: Vec::new(),
        };
        let proof = DaMultiChunkProof {
            page_index: 0,
            page_root,
            page_proof,
            page_merkle_path: Vec::new(),
        };

        assert_ok!(ArchiveMarket::respond_to_challenge(
            RuntimeOrigin::signed(1),
            challenge_id,
            proof
        ));

        assert!(Challenges::<Test>::get(challenge_id).is_none());
        assert!(ChallengeQueue::<Test>::get().is_empty());
    });
}

#[test]
fn expired_challenge_slashes_and_marks_failed() {
    new_test_ext().execute_with(|| {
        assert_ok!(ArchiveMarket::register_provider(
            RuntimeOrigin::signed(1),
            1,
            2,
            endpoint(b"https://archive.example"),
            200
        ));

        frame_system::Pallet::<Test>::set_block_number(1);
        assert_ok!(ArchiveMarket::buy_contract(
            RuntimeOrigin::signed(2),
            1,
            1,
            2,
            5,
            50,
            40,
            10_000
        ));

        let contract = Contracts::<Test>::get(0).expect("contract stored");
        let challenge_id = 1u64;
        let challenge = ArchiveChallenge::<Test> {
            challenge_id,
            provider: 1,
            contract_id: contract.contract_id,
            block_number: 1,
            da_root: [0u8; 48],
            global_chunk_index: 0,
            deadline: 2,
        };
        Challenges::<Test>::insert(challenge_id, challenge);
        ChallengeQueue::<Test>::put(BoundedVec::try_from(vec![challenge_id]).unwrap());

        frame_system::Pallet::<Test>::set_block_number(6);
        ArchiveMarket::on_initialize(6);

        let updated = Contracts::<Test>::get(0).expect("contract stored");
        assert_eq!(updated.status, ContractStatus::Failed);
        assert_eq!(updated.bond_stake, 0);
        assert_eq!(BondCommitted::<Test>::get(1), 0);
        assert_eq!(Balances::reserved_balance(1), 160);
        assert!(Challenges::<Test>::get(challenge_id).is_none());
        assert!(ChallengeQueue::<Test>::get().is_empty());
    });
}
