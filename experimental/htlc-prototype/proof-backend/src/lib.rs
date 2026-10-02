//! Isolated facade around unchanged Hegemon source for one private hashlock
//! component proof. This crate is never linked to the production node.

include!(concat!(env!("OUT_DIR"), "/transaction_facade.rs"));

pub mod hashlock_claim;
pub mod measurement;
pub mod projection;
