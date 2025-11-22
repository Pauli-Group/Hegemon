use super::*;
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::RawOrigin;

benchmarks! {
    submit_commitment {
        let caller: T::AccountId = whitelisted_caller();
        let commitment_id = Default::default();
        let root: BoundedVec<u8, T::MaxRootSize> = BoundedVec::try_from(vec![0u8; T::MaxRootSize::get() as usize / 2]).unwrap_or_default();
    }: _(RawOrigin::Signed(caller), commitment_id, RootKind::Hash, root)

    link_issuer {
        let caller: T::AccountId = whitelisted_caller();
        let commitment_id = Default::default();
        let root: BoundedVec<u8, T::MaxRootSize> = BoundedVec::try_from(vec![1u8; 4]).unwrap();
        Pallet::<T>::submit_commitment(RawOrigin::Signed(caller.clone()).into(), commitment_id, RootKind::Hash, root)?;
        let issuer: T::IssuerId = Default::default();
    }: _(RawOrigin::Signed(caller), commitment_id, issuer, None)

    start_dispute {
        let caller: T::AccountId = whitelisted_caller();
        let commitment_id = Default::default();
        let root: BoundedVec<u8, T::MaxRootSize> = BoundedVec::try_from(vec![2u8; 4]).unwrap();
        Pallet::<T>::submit_commitment(RawOrigin::Signed(caller.clone()).into(), commitment_id, RootKind::Hash, root)?;
    }: _(RawOrigin::Signed(caller), commitment_id)

    rollback {
        let caller: T::AccountId = whitelisted_caller();
        let commitment_id = Default::default();
        let root: BoundedVec<u8, T::MaxRootSize> = BoundedVec::try_from(vec![3u8; 4]).unwrap();
        Pallet::<T>::submit_commitment(RawOrigin::Signed(caller.clone()).into(), commitment_id, RootKind::Hash, root.clone())?;
        Pallet::<T>::start_dispute(RawOrigin::Signed(caller.clone()).into(), commitment_id)?;
    }: _(RawOrigin::Signed(caller), commitment_id)
}

impl_benchmark_test_suite!(
    Pallet,
    crate::tests::new_test_ext(),
    crate::tests::TestRuntime
);
