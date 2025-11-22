use super::*;
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::RawOrigin;

benchmarks! {
    set_quota {
        let actor: T::AccountId = whitelisted_caller();
        let max_usage: u128 = 1_000;
        let rate_hint: u64 = 10;
    }: _(RawOrigin::Root, actor.clone(), max_usage, rate_hint)
    verify {
        assert!(Quotas::<T>::contains_key(&actor));
    }

    record_self_usage {
        let actor: T::AccountId = whitelisted_caller();
        let amount: u64 = 5;
    }: _(RawOrigin::Signed(actor.clone()), amount)
    verify {
        let usage = UsageCounters::<T>::get(&actor).expect("usage stored");
        assert!(usage.total_usage >= amount as u128);
    }

    emit_snapshot {
        let actor: T::AccountId = whitelisted_caller();
        Quotas::<T>::insert(&actor, Quota { max_usage: 50, rate_limit_per_block: 5 });
        UsageCounters::<T>::insert(&actor, UsageCounter::new(20, 20, Default::default()));
    }: _(RawOrigin::Signed(actor.clone()))
    verify {
        assert!(UsageCounters::<T>::contains_key(&actor));
    }
}

impl_benchmark_test_suite!(
    Pallet,
    crate::tests::new_test_ext(),
    crate::tests::TestRuntime
);
