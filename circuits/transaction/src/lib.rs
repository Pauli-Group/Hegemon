pub mod air;
pub mod constants;
pub mod error;
pub mod hashing;
pub mod keys;
pub mod note;
pub mod proof;
pub mod public_inputs;
pub mod trace;
pub mod witness;

// Real STARK implementation using winterfell 0.13
pub mod stark_air;
pub mod stark_prover;
pub mod stark_verifier;

pub use air::{check_constraints, TransactionAir};
pub use error::TransactionCircuitError;
pub use keys::{generate_keys, ProvingKey, VerifyingKey};
pub use note::{InputNoteWitness, OutputNoteWitness};
pub use proof::{TransactionProof, VerificationReport};
pub use public_inputs::TransactionPublicInputs;
pub use witness::TransactionWitness;

// Re-export real STARK types
pub use stark_air::{TransactionAirStark, TransactionPublicInputsStark, TRACE_WIDTH, MIN_TRACE_LENGTH};
pub use stark_prover::{TransactionProverStark, default_proof_options, fast_proof_options};
pub use stark_verifier::{verify_transaction_proof, verify_transaction_proof_bytes, TransactionVerifyError};

// Re-export circuit versioning and AIR identification
pub use constants::{CIRCUIT_VERSION, compute_air_hash, expected_air_hash};
