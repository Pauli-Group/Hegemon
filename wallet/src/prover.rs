//! STARK Proof Generation for Shielded Transactions
//!
//! This module provides the STARK prover for generating zero-knowledge proofs
//! for shielded transactions. Unlike Groth16, STARK proofs require NO trusted setup
//! and are post-quantum secure.
//!
//! ## Design
//!
//! - **Transparent Setup**: No ceremony or trusted parameters needed
//! - **Post-Quantum Security**: Based on hash functions only (Poseidon/Blake3)
//! - **FRI-based IOP**: Uses Fast Reed-Solomon Interactive Oracle Proofs
//!
//! ## Usage
//!
//! ```ignore
//! use wallet::prover::{StarkProver, StarkProverConfig};
//!
//! let config = StarkProverConfig::default();
//! let prover = StarkProver::new(config);
//!
//! let witness = build_transaction_witness(...);
//! let proof = prover.prove(&witness)?;
//! ```
//!
//! ## Security
//!
//! STARK proofs rely only on collision-resistant hash functions, making them
//! resistant to quantum attacks. The trade-off is larger proof sizes (~20-50KB)
//! compared to Groth16 (~200 bytes), but this is acceptable for quantum resistance.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use transaction_circuit::{
    default_proof_options, fast_proof_options,
    hashing::{felt_to_bytes32, Felt},
    witness::TransactionWitness, TransactionProverStark,
};

use crate::error::WalletError;

/// Configuration for the STARK prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkProverConfig {
    /// FRI blowup factor (higher = more security, larger proofs).
    /// Default: 8 (128-bit security).
    pub blowup_factor: usize,
    /// Number of FRI query rounds.
    /// Default: 30 (128-bit security).
    pub num_queries: usize,
    /// Enable proof grinding (PoW on proof for size reduction).
    /// Default: false (not needed for transactions).
    pub enable_grinding: bool,
    /// Grinding bits (if enabled).
    pub grinding_bits: u8,
    /// Maximum proving time before timeout.
    pub max_proving_time: Duration,
}

impl Default for StarkProverConfig {
    fn default() -> Self {
        Self {
            blowup_factor: 8,
            num_queries: 30,
            enable_grinding: false,
            grinding_bits: 0,
            max_proving_time: Duration::from_secs(60),
        }
    }
}

impl StarkProverConfig {
    /// Create a config optimized for fast proving (lower security margin).
    pub fn fast() -> Self {
        Self {
            blowup_factor: 4,
            num_queries: 20,
            enable_grinding: false,
            grinding_bits: 0,
            max_proving_time: Duration::from_secs(30),
        }
    }

    /// Create a config optimized for smaller proofs.
    pub fn compact() -> Self {
        Self {
            blowup_factor: 16,
            num_queries: 40,
            enable_grinding: true,
            grinding_bits: 16,
            max_proving_time: Duration::from_secs(120),
        }
    }

    /// Create a config for maximum security.
    pub fn high_security() -> Self {
        Self {
            blowup_factor: 16,
            num_queries: 50,
            enable_grinding: false,
            grinding_bits: 0,
            max_proving_time: Duration::from_secs(180),
        }
    }
}

/// STARK prover for shielded transactions.
///
/// Generates zero-knowledge proofs using FRI-based STARKs.
/// The proving system is transparent (no trusted setup) and post-quantum secure.
pub struct StarkProver {
    /// Prover configuration.
    config: StarkProverConfig,
    /// The actual winterfell STARK prover.
    inner: TransactionProverStark,
}

impl StarkProver {
    /// Create a new STARK prover with the given configuration.
    ///
    /// Note: Key generation is deterministic and requires no trusted setup.
    pub fn new(config: StarkProverConfig) -> Self {
        let options = if config.blowup_factor <= 4 {
            fast_proof_options()
        } else {
            default_proof_options()
        };
        let inner = TransactionProverStark::new(options);
        Self { config, inner }
    }

    /// Create a prover with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(StarkProverConfig::default())
    }

    /// Get the prover configuration.
    pub fn config(&self) -> &StarkProverConfig {
        &self.config
    }

    /// Generate a STARK proof for a transaction witness.
    ///
    /// # Arguments
    ///
    /// * `witness` - The transaction witness containing inputs, outputs, and secrets
    ///
    /// # Returns
    ///
    /// A `ProofResult` containing the proof and metadata, or an error.
    pub fn prove(&self, witness: &TransactionWitness) -> Result<ProofResult, WalletError> {
        // Validate witness before proving
        witness
            .validate()
            .map_err(|e| WalletError::InvalidArgument(Box::leak(e.to_string().into_boxed_str())))?;

        let start = Instant::now();

        // Get public inputs from witness
        let pub_inputs = self.inner.get_public_inputs(witness).map_err(|e| {
            WalletError::InvalidArgument(Box::leak(e.to_string().into_boxed_str()))
        })?;

        // DEBUG: Print balance info
        let total_input: u64 = witness.inputs.iter().map(|i| i.note.value).sum();
        let total_output: u64 = witness.outputs.iter().map(|o| o.note.value).sum();
        // eprintln!("DEBUG prover: inputs.len()={} outputs.len()={}", witness.inputs.len(), witness.outputs.len());
        // eprintln!("DEBUG prover: total_input={} total_output={} fee={}", total_input, total_output, witness.fee);
        // eprintln!("DEBUG prover: balance check: total_input ({}) = total_output ({}) + fee ({})?",
        //     total_input, total_output, witness.fee);
        if total_input != total_output + witness.fee {
            // eprintln!("DEBUG prover: BALANCE MISMATCH! {} != {} + {}", total_input, total_output, witness.fee);
        }

        // Generate the real STARK proof
        let proof = self.inner.prove_transaction(witness).map_err(|e| {
            WalletError::Serialization(format!("STARK proof generation failed: {}", e))
        })?;

        let proving_time = start.elapsed();

        // Check if we exceeded the timeout
        if proving_time > self.config.max_proving_time {
            return Err(WalletError::InvalidState("Proof generation timed out"));
        }

        // Serialize the proof for transmission
        let proof_bytes = proof.to_bytes();

        // Verify proof locally before returning (development check)
        match transaction_circuit::verify_transaction_proof_bytes(&proof_bytes, &pub_inputs) {
            Ok(()) => {
                #[cfg(debug_assertions)]
                eprintln!("DEBUG prover: Local verification PASSED");
            }
            Err(e) => {
                #[cfg(debug_assertions)]
                eprintln!("DEBUG prover: Local verification FAILED: {:?}", e);
                return Err(WalletError::Serialization(format!(
                    "Proof verification failed: {:?}",
                    e
                )));
            }
        }

        // Convert field elements to 32-byte arrays for active slots only.
        let nullifiers: Vec<[u8; 32]> = pub_inputs
            .nullifiers
            .iter()
            .zip(pub_inputs.input_flags.iter())
            .filter(|(_, flag)| **flag == Felt::ONE)
            .map(|(f, _)| felt_to_bytes32(*f))
            .collect();
        let commitments: Vec<[u8; 32]> = pub_inputs
            .commitments
            .iter()
            .zip(pub_inputs.output_flags.iter())
            .filter(|(_, flag)| **flag == Felt::ONE)
            .map(|(f, _)| felt_to_bytes32(*f))
            .collect();
        let anchor = felt_to_bytes32(pub_inputs.merkle_root);

        Ok(ProofResult {
            proof_bytes,
            nullifiers,
            commitments,
            anchor,
            proving_time,
            fee: witness.fee,
            value_balance: witness.value_balance,
        })
    }

    /// Verify a STARK proof locally.
    ///
    /// This is useful for testing and validation before submission.
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        witness: &TransactionWitness,
    ) -> Result<bool, WalletError> {
        use transaction_circuit::verify_transaction_proof_bytes;

        let pub_inputs = self.inner.get_public_inputs(witness).map_err(|e| {
            WalletError::InvalidArgument(Box::leak(e.to_string().into_boxed_str()))
        })?;
        match verify_transaction_proof_bytes(proof_bytes, &pub_inputs) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl Default for StarkProver {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Result of proof generation.
#[derive(Clone, Debug)]
pub struct ProofResult {
    /// Serialized STARK proof bytes (winterfell proof format).
    pub proof_bytes: Vec<u8>,
    /// Nullifiers from the transaction (32-byte arrays).
    pub nullifiers: Vec<[u8; 32]>,
    /// Commitments from the transaction (32-byte arrays).
    pub commitments: Vec<[u8; 32]>,
    /// Merkle root anchor (32-byte array).
    pub anchor: [u8; 32],
    /// Time taken to generate the proof.
    pub proving_time: Duration,
    /// Native fee encoded in the proof.
    pub fee: u64,
    /// Value balance (transparent delta).
    pub value_balance: i128,
}

impl ProofResult {
    /// Get the proof size in bytes.
    pub fn proof_size(&self) -> usize {
        self.proof_bytes.len()
    }

    /// Get nullifiers as bytes (already in correct format).
    pub fn nullifiers_bytes(&self) -> &[[u8; 32]] {
        &self.nullifiers
    }

    /// Get commitments as bytes (already in correct format).
    pub fn commitments_bytes(&self) -> &[[u8; 32]] {
        &self.commitments
    }
}

/// Proof generation statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProverStats {
    /// Total proofs generated.
    pub proofs_generated: u64,
    /// Total proving time.
    pub total_proving_time: Duration,
    /// Average proving time.
    pub average_proving_time: Duration,
    /// Total proof bytes generated.
    pub total_proof_bytes: u64,
    /// Average proof size.
    pub average_proof_size: u64,
}

impl ProverStats {
    /// Update stats with a new proof result.
    pub fn record(&mut self, result: &ProofResult) {
        self.proofs_generated += 1;
        self.total_proving_time += result.proving_time;
        self.total_proof_bytes += result.proof_size() as u64;

        if self.proofs_generated > 0 {
            self.average_proving_time = self.total_proving_time / self.proofs_generated as u32;
            self.average_proof_size = self.total_proof_bytes / self.proofs_generated;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = StarkProverConfig::default();
        assert_eq!(config.blowup_factor, 8);
        assert_eq!(config.num_queries, 30);
        assert!(!config.enable_grinding);
    }

    #[test]
    fn test_config_fast() {
        let config = StarkProverConfig::fast();
        assert_eq!(config.blowup_factor, 4);
        assert_eq!(config.num_queries, 20);
    }

    #[test]
    fn test_config_compact() {
        let config = StarkProverConfig::compact();
        assert!(config.enable_grinding);
        assert_eq!(config.grinding_bits, 16);
    }

    #[test]
    fn test_prover_creation() {
        let prover = StarkProver::with_defaults();
        assert_eq!(prover.config().blowup_factor, 8);
    }

    #[test]
    fn test_prover_stats() {
        let mut stats = ProverStats::default();
        assert_eq!(stats.proofs_generated, 0);

        // Simulate recording a proof
        let fake_result = ProofResult {
            proof_bytes: vec![0u8; 1000],
            nullifiers: vec![],
            commitments: vec![],
            anchor: [0u8; 32],
            proving_time: Duration::from_millis(500),
            fee: 0,
            value_balance: 0,
        };

        stats.record(&fake_result);
        assert_eq!(stats.proofs_generated, 1);
        assert_eq!(stats.total_proof_bytes, 1000);
    }
}
