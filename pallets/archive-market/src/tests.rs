use super::*;
use crate::mock::{new_test_ext, ArchiveMarket, Balances, RuntimeOrigin, Test};
use frame_support::{assert_noop, assert_ok};

fn endpoint(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
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
