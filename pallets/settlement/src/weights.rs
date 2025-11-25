use frame_support::weights::Weight;
use sp_std::marker::PhantomData;

pub trait WeightInfo {
    fn submit_instruction() -> Weight;
    fn submit_batch() -> Weight;
    fn register_key() -> Weight;
    fn set_verifier_params() -> Weight;
    fn commit_state_channel() -> Weight;
    fn dispute_state_channel() -> Weight;
    fn escalate_dispute() -> Weight;
    fn resolve_dispute() -> Weight;
    fn rollback_batch() -> Weight;
    fn migrate() -> Weight;
}

pub struct DefaultWeightInfo<T>(PhantomData<T>);

impl<T> WeightInfo for DefaultWeightInfo<T> {
    fn submit_instruction() -> Weight {
        Weight::from_parts(70_000, 0)
    }

    fn submit_batch() -> Weight {
        Weight::from_parts(80_000, 0)
    }

    fn register_key() -> Weight {
        Weight::from_parts(30_000, 0)
    }

    fn set_verifier_params() -> Weight {
        Weight::from_parts(20_000, 0)
    }

    fn commit_state_channel() -> Weight {
        Weight::from_parts(60_000, 0)
    }

    fn dispute_state_channel() -> Weight {
        Weight::from_parts(50_000, 0)
    }

    fn escalate_dispute() -> Weight {
        Weight::from_parts(40_000, 0)
    }

    fn resolve_dispute() -> Weight {
        Weight::from_parts(45_000, 0)
    }

    fn rollback_batch() -> Weight {
        Weight::from_parts(55_000, 0)
    }

    fn migrate() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

impl WeightInfo for () {
    fn submit_instruction() -> Weight {
        DefaultWeightInfo::<()>::submit_instruction()
    }

    fn submit_batch() -> Weight {
        DefaultWeightInfo::<()>::submit_batch()
    }

    fn register_key() -> Weight {
        DefaultWeightInfo::<()>::register_key()
    }

    fn set_verifier_params() -> Weight {
        DefaultWeightInfo::<()>::set_verifier_params()
    }

    fn commit_state_channel() -> Weight {
        DefaultWeightInfo::<()>::commit_state_channel()
    }

    fn dispute_state_channel() -> Weight {
        DefaultWeightInfo::<()>::dispute_state_channel()
    }

    fn escalate_dispute() -> Weight {
        DefaultWeightInfo::<()>::escalate_dispute()
    }

    fn resolve_dispute() -> Weight {
        DefaultWeightInfo::<()>::resolve_dispute()
    }

    fn rollback_batch() -> Weight {
        DefaultWeightInfo::<()>::rollback_batch()
    }

    fn migrate() -> Weight {
        DefaultWeightInfo::<()>::migrate()
    }
}
