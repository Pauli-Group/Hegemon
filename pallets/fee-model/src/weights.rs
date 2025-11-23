use frame_support::weights::{constants::RocksDbWeight, Weight};
use sp_std::marker::PhantomData;

pub trait WeightInfo {
    fn on_charge_transaction() -> Weight;
}

/// Weight values for the fee model generated from the Substrate reference weights.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn on_charge_transaction() -> Weight {
        // The fee model adjusts fees in-memory and emits events without touching storage,
        // so the weight is limited to the fixed dispatch cost.
        Weight::from_parts(10_000, 0)
            .saturating_add(RocksDbWeight::get().reads(0))
            .saturating_add(RocksDbWeight::get().writes(0))
    }
}

impl WeightInfo for () {
    fn on_charge_transaction() -> Weight {
        Weight::zero()
    }
}
