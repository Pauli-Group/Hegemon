pub mod error;
pub mod proof;

pub use error::BlockError;
pub use proof::{
    prove_block, verify_block, BlockProof, BlockVerificationReport, RecursiveAggregation,
};
