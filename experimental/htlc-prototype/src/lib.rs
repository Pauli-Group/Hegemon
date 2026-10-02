//! Isolated executable HTLC reference semantics and SHA-256 Boolean constraints.
//!
//! No proof backend, production relation, consensus admission or activation is
//! connected. Authorization and authenticated chain state are explicit external
//! trust boundaries. The host reference relation is not itself a ZK circuit.
#![forbid(unsafe_code)]

pub mod hashlock;
pub mod relation;
