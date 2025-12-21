use crate::pallet::{Policies, PolicyHashes};
use crate::Error;
use crate::StablecoinPolicyProvider;
use frame_support::{assert_noop, assert_ok};

use super::mock::{new_test_ext, sample_policy, RuntimeOrigin, StablecoinPolicy as Pallet, Test};

#[test]
fn set_policy_requires_admin_role() {
    new_test_ext().execute_with(|| {
        let policy = sample_policy(true, 1);
        assert_noop!(
            Pallet::set_policy(RuntimeOrigin::signed(2), policy),
            Error::<Test>::Unauthorized
        );
    });
}

#[test]
fn set_policy_requires_existing_asset() {
    new_test_ext().execute_with(|| {
        let policy = sample_policy(true, 99);
        assert_noop!(
            Pallet::set_policy(RuntimeOrigin::signed(1), policy),
            Error::<Test>::AssetMissing
        );
    });
}

#[test]
fn set_policy_stores_policy_and_hash() {
    new_test_ext().execute_with(|| {
        let policy = sample_policy(true, 1);
        let expected_hash = policy.policy_hash();

        assert_ok!(Pallet::set_policy(
            RuntimeOrigin::signed(1),
            policy.clone()
        ));

        let stored = Policies::<Test>::get(1).expect("policy stored");
        assert!(stored == policy);
        assert!(PolicyHashes::<Test>::get(1) == Some(expected_hash));
    });
}

#[test]
fn set_policy_active_updates_hash() {
    new_test_ext().execute_with(|| {
        let mut policy = sample_policy(false, 1);
        let original_hash = policy.policy_hash();
        assert_ok!(Pallet::set_policy(
            RuntimeOrigin::signed(1),
            policy.clone()
        ));

        assert_ok!(Pallet::set_policy_active(
            RuntimeOrigin::signed(1),
            1,
            true
        ));

        let updated = Policies::<Test>::get(1).expect("policy stored");
        assert!(updated.active);
        let updated_hash = PolicyHashes::<Test>::get(1).expect("policy hash stored");
        assert!(original_hash != updated_hash);
        policy.active = true;
        assert_eq!(updated_hash, policy.policy_hash());
    });
}

#[test]
fn policy_provider_falls_back_to_computed_hash() {
    new_test_ext().execute_with(|| {
        let policy = sample_policy(true, 1);
        assert_ok!(Pallet::set_policy(
            RuntimeOrigin::signed(1),
            policy.clone()
        ));

        PolicyHashes::<Test>::remove(1);
        let fetched = <Pallet as StablecoinPolicyProvider<u32>>::policy_hash(&1)
            .expect("hash computed");
        assert_eq!(fetched, policy.policy_hash());
    });
}
