//! STARK Proof Generation for Shielded Transactions
//!
//! This module provides the transaction prover for generating zero-knowledge proofs
//! for shielded transactions. The concrete backend is version-owned in
//! `protocol-versioning`; the current default witness path resolves to
//! `SmallwoodCandidate`, while legacy Plonky3 support remains available for
//! historical decoding and comparison work.
//!
//! ## Design
//!
//! - **Transparent Setup**: No ceremony or trusted parameters needed
//! - **Post-Quantum Security**: Based on hash functions only (Poseidon/Blake3)
//! - **Version-owned backend**: the active default is SmallWood, with legacy
//!   Plonky3/FRI support retained behind explicit version bindings.
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
//! The active transaction-proof path remains post-quantum and transparent.
//! Legacy Plonky3 proofs are still much larger than the current SmallWood
//! default, but they remain decodable for compatibility and comparison.

use std::time::{Duration, Instant};

use protocol_versioning::{tx_proof_backend_for_version, DEFAULT_TX_PROOF_BACKEND};
use serde::{Deserialize, Serialize};
use transaction_circuit::{
    keys::{generate_keys, ProvingKey, VerifyingKey},
    p3_prover::TransactionProofParams,
    proof,
    witness::TransactionWitness,
};

use crate::error::WalletError;

const PRODUCTION_MIN_BLOWUP_FACTOR: usize = 16;
const PRODUCTION_MIN_NUM_QUERIES: usize = 32;

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Local post-prove verification policy for the wallet prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalProofSelfCheckPolicy {
    /// Always verify the freshly-built proof locally before returning it.
    Always,
    /// Skip local post-prove verification and rely on downstream verification.
    Never,
}

/// Configuration for the STARK prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkProverConfig {
    /// Advisory blowup factor for legacy Plonky3/FRI paths.
    ///
    /// Note: the active default backend is SmallWood, so this field is
    /// advisory/UX-only unless the caller intentionally uses a Plonky3 binding.
    ///
    /// Default: 16 (log_blowup = 4).
    pub blowup_factor: usize,
    /// Advisory FRI query-round count for legacy Plonky3 paths.
    ///
    /// Note: the active default backend is SmallWood, so this field is
    /// advisory/UX-only unless the caller intentionally uses a Plonky3 binding.
    ///
    /// Default: 32 (128-bit engineering target at log_blowup = 4).
    pub num_queries: usize,
    /// Enable proof grinding (PoW on proof for size reduction).
    /// Default: false (not needed for transactions).
    pub enable_grinding: bool,
    /// Grinding bits (if enabled).
    pub grinding_bits: u8,
    /// Advisory proving time budget.
    ///
    /// Note: proof generation is not currently cancellable; exceeding this budget does not abort
    /// proving. The prover may emit a debug warning when the budget is exceeded.
    pub max_proving_time: Duration,
    /// Whether to emit a recursion-friendly tx proof profile instead of the
    /// heavier production tx proof profile.
    pub recursion_profile: bool,
    /// Local post-prove verification policy.
    pub local_self_check_policy: LocalProofSelfCheckPolicy,
}

impl Default for StarkProverConfig {
    fn default() -> Self {
        Self {
            blowup_factor: 16,
            num_queries: 32,
            enable_grinding: false,
            grinding_bits: 0,
            max_proving_time: if cfg!(debug_assertions) {
                Duration::from_secs(300)
            } else {
                Duration::from_secs(60)
            },
            recursion_profile: false,
            local_self_check_policy: LocalProofSelfCheckPolicy::Always,
        }
    }
}

impl StarkProverConfig {
    /// Create a config optimized for fast proving (lower security margin).
    pub fn fast() -> Self {
        Self {
            blowup_factor: 8,
            num_queries: 1,
            enable_grinding: false,
            grinding_bits: 0,
            max_proving_time: Duration::from_secs(30),
            recursion_profile: false,
            local_self_check_policy: LocalProofSelfCheckPolicy::Always,
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
            recursion_profile: false,
            local_self_check_policy: LocalProofSelfCheckPolicy::Always,
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
            recursion_profile: false,
            local_self_check_policy: LocalProofSelfCheckPolicy::Always,
        }
    }

    pub fn recursion() -> Self {
        Self {
            blowup_factor: 8,
            num_queries: 8,
            enable_grinding: false,
            grinding_bits: 0,
            max_proving_time: Duration::from_secs(60),
            recursion_profile: true,
            local_self_check_policy: LocalProofSelfCheckPolicy::Always,
        }
    }

    fn normalized_with_controls(
        &self,
        allow_fast: bool,
        allow_recursion: bool,
        enforce_production_floor: bool,
    ) -> Self {
        let mut cfg = self.clone();
        if cfg.num_queries == 0 {
            cfg.num_queries = 1;
        }
        if cfg.num_queries > 255 {
            cfg.num_queries = 255;
        }
        cfg.blowup_factor = cfg.blowup_factor.clamp(2, 128);
        if !cfg.blowup_factor.is_power_of_two() {
            cfg.blowup_factor = cfg.blowup_factor.next_power_of_two();
        }
        if cfg.grinding_bits > 32 {
            cfg.grinding_bits = 32;
        }
        if !cfg.enable_grinding {
            cfg.grinding_bits = 0;
        }

        if enforce_production_floor && !allow_fast {
            cfg.num_queries = cfg.num_queries.max(PRODUCTION_MIN_NUM_QUERIES);
            cfg.blowup_factor = cfg.blowup_factor.max(PRODUCTION_MIN_BLOWUP_FACTOR);
        }
        if allow_recursion {
            cfg.recursion_profile = true;
        }

        cfg
    }

    fn weakens_production_floor(&self) -> bool {
        self.num_queries < PRODUCTION_MIN_NUM_QUERIES
            || self.blowup_factor < PRODUCTION_MIN_BLOWUP_FACTOR
    }
}

/// Transaction prover for shielded transactions.
///
/// Generates version-owned zero-knowledge proofs.
/// The proving system remains transparent (no trusted setup) and post-quantum secure.
pub struct StarkProver {
    /// Prover configuration.
    config: StarkProverConfig,
    proving_key: ProvingKey,
    verifying_key: VerifyingKey,
}

impl StarkProver {
    /// Create a new STARK prover with the given configuration.
    ///
    /// Note: Key generation is deterministic and requires no trusted setup.
    pub fn new(config: StarkProverConfig) -> Self {
        let allow_fast = env_truthy("HEGEMON_WALLET_PROVER_FAST");
        let allow_recursion = env_truthy("HEGEMON_WALLET_PROVER_RECURSION");
        let config =
            config.normalized_with_controls(allow_fast, allow_recursion, !cfg!(debug_assertions));
        if !cfg!(debug_assertions) && allow_fast && config.weakens_production_floor() {
            eprintln!(
                "warning: HEGEMON_WALLET_PROVER_FAST enabled; wallet prover is running below the production proof-margin floor (num_queries={}, blowup_factor={})",
                config.num_queries,
                config.blowup_factor
            );
        }
        if !cfg!(debug_assertions)
            && config.local_self_check_policy == LocalProofSelfCheckPolicy::Never
        {
            eprintln!(
                "warning: wallet prover local self-check disabled; this is unsafe for production proof generation"
            );
        }
        let (proving_key, verifying_key) = generate_keys();
        Self {
            config,
            proving_key,
            verifying_key,
        }
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

        let prove_start = Instant::now();

        let params = if self.config.recursion_profile {
            TransactionProofParams::recursion()
        } else {
            TransactionProofParams::production_for_version(witness.version)
        };
        let proof = proof::prove_with_params(witness, &self.proving_key, params).map_err(|e| {
            WalletError::Serialization(format!("STARK proof generation failed: {e}"))
        })?;

        let proof_generation_time = prove_start.elapsed();
        let (local_self_check_performed, local_self_check_time) =
            match self.config.local_self_check_policy {
                LocalProofSelfCheckPolicy::Always => {
                    let self_check_start = Instant::now();
                    let report = proof::verify(&proof, &self.verifying_key).map_err(|e| {
                        WalletError::Serialization(format!("Proof verification failed: {e}"))
                    })?;
                    if !report.verified {
                        return Err(WalletError::Serialization(
                            "Proof verification failed".to_string(),
                        ));
                    }
                    (true, self_check_start.elapsed())
                }
                LocalProofSelfCheckPolicy::Never => (false, Duration::ZERO),
            };
        let proving_time = proof_generation_time + local_self_check_time;

        // Proof generation is not cancellable; treat max_proving_time as an advisory budget.
        if proving_time > self.config.max_proving_time {
            #[cfg(debug_assertions)]
            eprintln!(
                "WARN prover: proving pipeline exceeded budget (prove={:?}, self_check={:?}, total={:?}, budget={:?})",
                proof_generation_time,
                local_self_check_time,
                proving_time,
                self.config.max_proving_time
            );
        }

        let nullifiers = proof
            .nullifiers
            .iter()
            .copied()
            .filter(|nf| *nf != [0u8; 48])
            .collect();
        let commitments = proof
            .commitments
            .iter()
            .copied()
            .filter(|cm| *cm != [0u8; 48])
            .collect();

        Ok(ProofResult {
            proof_bytes: proof.stark_proof.clone(),
            nullifiers,
            commitments,
            anchor: proof.public_inputs.merkle_root,
            balance_slot_asset_ids: [
                proof.public_inputs.balance_slots[0].asset_id,
                proof.public_inputs.balance_slots[1].asset_id,
                proof.public_inputs.balance_slots[2].asset_id,
                proof.public_inputs.balance_slots[3].asset_id,
            ],
            proof_generation_time,
            local_self_check_time,
            local_self_check_performed,
            proving_time,
            fee: proof.public_inputs.native_fee,
            value_balance: proof.public_inputs.value_balance,
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
        let public_inputs = witness
            .public_inputs()
            .map_err(|e| WalletError::InvalidArgument(Box::leak(e.to_string().into_boxed_str())))?;
        let balance_slots = witness
            .balance_slots()
            .map_err(|e| WalletError::InvalidArgument(Box::leak(e.to_string().into_boxed_str())))?;
        let backend =
            tx_proof_backend_for_version(witness.version).unwrap_or(DEFAULT_TX_PROOF_BACKEND);
        let stark_public_inputs =
            proof::serialized_stark_inputs_from_witness(witness).map_err(|e| {
                WalletError::Serialization(format!("public input reconstruction failed: {e}"))
            })?;

        let proof = transaction_circuit::TransactionProof {
            nullifiers: public_inputs.nullifiers.clone(),
            commitments: public_inputs.commitments.clone(),
            balance_slots,
            public_inputs,
            backend,
            stark_proof: proof_bytes.to_vec(),
            stark_public_inputs: Some(stark_public_inputs),
        };

        Ok(proof::verify(&proof, &self.verifying_key)
            .map(|report| report.verified)
            .unwrap_or(false))
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
    /// Serialized transaction proof bytes (backend-specific format).
    pub proof_bytes: Vec<u8>,
    /// Nullifiers from the transaction (48-byte arrays).
    pub nullifiers: Vec<[u8; 48]>,
    /// Commitments from the transaction (48-byte arrays).
    pub commitments: Vec<[u8; 48]>,
    /// Merkle root anchor (48-byte array).
    pub anchor: [u8; 48],
    /// Asset ids for the fixed four balance slots.
    pub balance_slot_asset_ids: [u64; 4],
    /// Time spent generating the proof bytes before any local self-check.
    pub proof_generation_time: Duration,
    /// Time spent in the optional local post-prove verification step.
    pub local_self_check_time: Duration,
    /// Whether the local post-prove verification step ran.
    pub local_self_check_performed: bool,
    /// Time taken to generate the proof.
    ///
    /// This remains the aggregate prove pipeline time for compatibility.
    pub proving_time: Duration,
    /// Optional miner tip encoded in the proof.
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
    pub fn nullifiers_bytes(&self) -> &[[u8; 48]] {
        &self.nullifiers
    }

    /// Get commitments as bytes (already in correct format).
    pub fn commitments_bytes(&self) -> &[[u8; 48]] {
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
    use protocol_versioning::SMALLWOOD_CANDIDATE_VERSION_BINDING;
    use transaction_circuit::{
        constants::NATIVE_ASSET_ID,
        hashing_pq::{felts_to_bytes48, Felt},
        note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    };

    fn merkle_node(left: [Felt; 6], right: [Felt; 6]) -> [Felt; 6] {
        transaction_circuit::hashing_pq::merkle_node(left, right)
    }

    fn spend_auth_key_bytes(sk_spend: &[u8; 32]) -> [u8; 32] {
        transaction_circuit::hashing_pq::spend_auth_key_bytes(sk_spend)
    }

    fn sample_witness() -> TransactionWitness {
        let sk_spend = [42u8; 32];
        let pk_auth = spend_auth_key_bytes(&sk_spend);
        let input_note_native = NoteData {
            value: 8,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [2u8; 32],
            pk_auth,
            rho: [3u8; 32],
            r: [4u8; 32],
        };
        let input_note_asset = NoteData {
            value: 5,
            asset_id: 1,
            pk_recipient: [5u8; 32],
            pk_auth,
            rho: [6u8; 32],
            r: [7u8; 32],
        };
        let leaf0 = input_note_native.commitment();
        let leaf1 = input_note_asset.commitment();
        let mut siblings0 = vec![leaf1];
        let mut siblings1 = vec![leaf0];
        let mut current = merkle_node(leaf0, leaf1);
        for _ in 1..transaction_circuit::note::MERKLE_TREE_DEPTH {
            let zero = [Felt::new(0); 6];
            siblings0.push(zero);
            siblings1.push(zero);
            current = merkle_node(current, zero);
        }
        TransactionWitness {
            inputs: vec![
                InputNoteWitness {
                    note: input_note_native,
                    position: 0,
                    rho_seed: [9u8; 32],
                    merkle_path: MerklePath {
                        siblings: siblings0,
                    },
                },
                InputNoteWitness {
                    note: input_note_asset,
                    position: 1,
                    rho_seed: [8u8; 32],
                    merkle_path: MerklePath {
                        siblings: siblings1,
                    },
                },
            ],
            outputs: vec![
                OutputNoteWitness {
                    note: NoteData {
                        value: 3,
                        asset_id: NATIVE_ASSET_ID,
                        pk_recipient: [11u8; 32],
                        pk_auth: [111u8; 32],
                        rho: [12u8; 32],
                        r: [13u8; 32],
                    },
                },
                OutputNoteWitness {
                    note: NoteData {
                        value: 5,
                        asset_id: 1,
                        pk_recipient: [21u8; 32],
                        pk_auth: [121u8; 32],
                        rho: [22u8; 32],
                        r: [23u8; 32],
                    },
                },
            ],
            ciphertext_hashes: vec![[0u8; 48]; 2],
            sk_spend,
            merkle_root: felts_to_bytes48(&current),
            fee: 5,
            value_balance: 0,
            stablecoin: transaction_circuit::StablecoinPolicyBinding::default(),
            version: SMALLWOOD_CANDIDATE_VERSION_BINDING,
        }
    }

    #[test]
    fn test_config_defaults() {
        let config = StarkProverConfig::default();
        assert_eq!(config.blowup_factor, 16);
        assert_eq!(config.num_queries, 32);
        assert!(!config.enable_grinding);
        assert_eq!(
            config.local_self_check_policy,
            LocalProofSelfCheckPolicy::Always
        );
    }

    #[test]
    fn test_config_fast() {
        let config = StarkProverConfig::fast();
        assert_eq!(config.blowup_factor, 8);
        assert_eq!(config.num_queries, 1);
        assert_eq!(
            config.local_self_check_policy,
            LocalProofSelfCheckPolicy::Always
        );
    }

    #[test]
    fn test_config_compact() {
        let config = StarkProverConfig::compact();
        assert!(config.enable_grinding);
        assert_eq!(config.grinding_bits, 16);
        assert_eq!(
            config.local_self_check_policy,
            LocalProofSelfCheckPolicy::Always
        );
    }

    #[test]
    fn test_config_recursion() {
        let config = StarkProverConfig::recursion();
        assert!(config.recursion_profile);
        assert_eq!(
            config.local_self_check_policy,
            LocalProofSelfCheckPolicy::Always
        );
    }

    #[test]
    fn test_prover_creation() {
        let prover = StarkProver::with_defaults();
        assert_eq!(prover.config().blowup_factor, 16);
    }

    #[test]
    fn test_fast_config_is_clamped_without_explicit_override() {
        let config = StarkProverConfig::fast().normalized_with_controls(false, false, true);
        assert_eq!(config.blowup_factor, PRODUCTION_MIN_BLOWUP_FACTOR);
        assert_eq!(config.num_queries, PRODUCTION_MIN_NUM_QUERIES);
        assert_eq!(
            config.local_self_check_policy,
            LocalProofSelfCheckPolicy::Always
        );
    }

    #[test]
    fn test_fast_config_requires_explicit_override_to_weaken_floor() {
        let config = StarkProverConfig::fast().normalized_with_controls(true, false, true);
        assert_eq!(config.blowup_factor, 8);
        assert_eq!(config.num_queries, 1);
        assert!(config.weakens_production_floor());
        assert_eq!(
            config.local_self_check_policy,
            LocalProofSelfCheckPolicy::Always
        );
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
            anchor: [0u8; 48],
            balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
            proof_generation_time: Duration::from_millis(400),
            local_self_check_time: Duration::from_millis(100),
            local_self_check_performed: true,
            proving_time: Duration::from_millis(500),
            fee: 0,
            value_balance: 0,
        };

        stats.record(&fake_result);
        assert_eq!(stats.proofs_generated, 1);
        assert_eq!(stats.total_proof_bytes, 1000);
    }

    #[test]
    #[ignore = "proof generation is still too expensive for the default wallet unit-test lane"]
    fn prover_self_check_policy_never_still_produces_externally_verifiable_proof() {
        let prover = StarkProver::new(StarkProverConfig {
            local_self_check_policy: LocalProofSelfCheckPolicy::Never,
            ..StarkProverConfig::default()
        });
        let witness = sample_witness();
        let result = prover
            .prove(&witness)
            .expect("proof generation with no self-check");
        assert!(!result.local_self_check_performed);
        assert_eq!(result.local_self_check_time, Duration::ZERO);
        assert_eq!(result.proving_time, result.proof_generation_time);
        assert!(
            prover
                .verify(&result.proof_bytes, &witness)
                .expect("external verification for skipped self-check"),
            "proof bytes must still verify externally when local self-check is skipped"
        );
    }

    #[test]
    #[ignore = "proof generation is still too expensive for the default wallet unit-test lane"]
    fn prover_self_check_policy_always_records_local_self_check_time() {
        let prover = StarkProver::new(StarkProverConfig {
            local_self_check_policy: LocalProofSelfCheckPolicy::Always,
            ..StarkProverConfig::default()
        });
        let witness = sample_witness();
        let result = prover
            .prove(&witness)
            .expect("proof generation with local self-check");
        assert!(result.local_self_check_performed);
        assert_eq!(
            result.proving_time,
            result.proof_generation_time + result.local_self_check_time
        );
        assert!(
            prover
                .verify(&result.proof_bytes, &witness)
                .expect("external verification after local self-check"),
            "proof bytes must still verify externally after local self-check"
        );
    }
}
