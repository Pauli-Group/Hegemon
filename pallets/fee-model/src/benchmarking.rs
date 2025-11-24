use super::*;
use frame_benchmarking::v2::*;

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn on_charge_transaction() {
        let caller: T::AccountId = whitelisted_caller();

        #[block]
        {
            // Exercise the weight path without mutating storage.
            let _ = <T as Config>::WeightInfo::on_charge_transaction();
            drop(caller);
        }
    }
}
