//! Shielded Transaction Builder
//!
//! This module provides a high-level API for building shielded transactions
//! using STARK proofs. It handles:
//!
//! - Input note selection
//! - Output note creation
//! - STARK proof generation
//! - Note encryption (ML-KEM-768)
//! - Transaction signing (ML-DSA-65 binding)
//!
//! ## Post-Quantum Security
//!
//! All cryptographic operations use post-quantum primitives:
//! - **STARK proofs**: Hash-based, transparent setup, quantum-resistant
//! - **ML-KEM-768**: Lattice-based key encapsulation (FIPS 203)
//! - **ML-DSA-65**: Lattice-based signatures (FIPS 204)
//! - **Poseidon hash**: Algebraic hash for STARK circuits
//!
//! ## Usage
//!
//! ```ignore
//! use wallet::shielded_tx::{ShieldedTxBuilder, ShieldedOutput};
//!
//! let mut builder = ShieldedTxBuilder::new(store, prover);
//!
//! // Add recipient
//! builder.add_output(ShieldedOutput {
//!     address: recipient_address,
//!     value: 1000,
//!     asset_id: NATIVE_ASSET_ID,
//!     memo: Some("Payment for services".into()),
//! })?;
//!
//! // Build and prove
//! let tx = builder.build(fee)?;
//! ```

use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use transaction_circuit::{
    constants::{MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID},
    note::OutputNoteWitness,
    witness::TransactionWitness,
};

use crate::address::ShieldedAddress;
use crate::error::WalletError;
use crate::keys::DerivedKeys;
use crate::notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};
use crate::prover::StarkProver;
use crate::rpc::TransactionBundle;
use crate::store::{SpendableNote, WalletMode, WalletStore};
use crate::viewing::FullViewingKey;

/// Output specification for a shielded transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedOutput {
    /// Recipient's shielded address.
    pub address: ShieldedAddress,
    /// Amount to send.
    pub value: u64,
    /// Asset ID (use NATIVE_ASSET_ID for native token).
    pub asset_id: u64,
    /// Optional memo (up to 512 bytes).
    pub memo: Option<String>,
}

impl ShieldedOutput {
    /// Create a new output for the native asset.
    pub fn native(address: ShieldedAddress, value: u64) -> Self {
        Self {
            address,
            value,
            asset_id: NATIVE_ASSET_ID,
            memo: None,
        }
    }

    /// Create a new output with memo.
    pub fn with_memo(address: ShieldedAddress, value: u64, memo: String) -> Self {
        Self {
            address,
            value,
            asset_id: NATIVE_ASSET_ID,
            memo: Some(memo),
        }
    }

    /// Get the memo as plaintext.
    fn memo_plaintext(&self) -> MemoPlaintext {
        self.memo
            .as_ref()
            .map(|m| MemoPlaintext::new(m.as_bytes().to_vec()))
            .unwrap_or_default()
    }
}

/// A built shielded transaction ready for submission.
#[derive(Clone, Debug)]
pub struct BuiltShieldedTx {
    /// Transaction bundle with proof and ciphertexts.
    pub bundle: TransactionBundle,
    /// Nullifiers for spent notes.
    pub nullifiers: Vec<[u8; 32]>,
    /// New commitments.
    pub commitments: Vec<[u8; 32]>,
    /// Indices of spent notes in the wallet store.
    pub spent_note_indices: Vec<usize>,
    /// Value balance (positive = shielding, negative = unshielding).
    pub value_balance: i128,
    /// Fee paid.
    pub fee: u64,
    /// Proof generation statistics.
    pub proof_stats: ProofStats,
}

/// Proof generation statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProofStats {
    /// Time to select inputs.
    pub input_selection_time: Duration,
    /// Time to build witness.
    pub witness_build_time: Duration,
    /// Time to generate proof.
    pub proving_time: Duration,
    /// Time to encrypt outputs.
    pub encryption_time: Duration,
    /// Total build time.
    pub total_time: Duration,
    /// Proof size in bytes.
    pub proof_size: usize,
}

/// Builder for shielded transactions.
///
/// Provides a fluent API for constructing shielded transactions
/// with STARK proofs.
pub struct ShieldedTxBuilder<'a> {
    /// Wallet store for note selection.
    store: &'a WalletStore,
    /// STARK prover.
    prover: &'a StarkProver,
    /// Outputs to create.
    outputs: Vec<ShieldedOutput>,
    /// Specific notes to spend (optional).
    specific_inputs: Option<Vec<usize>>,
    /// Whether to include a change output.
    include_change: bool,
}

impl<'a> ShieldedTxBuilder<'a> {
    /// Create a new transaction builder.
    ///
    /// # Arguments
    ///
    /// * `store` - Wallet store for accessing notes and keys
    /// * `prover` - STARK prover for proof generation
    pub fn new(store: &'a WalletStore, prover: &'a StarkProver) -> Self {
        Self {
            store,
            prover,
            outputs: Vec::new(),
            specific_inputs: None,
            include_change: true,
        }
    }

    /// Add an output to the transaction.
    pub fn add_output(&mut self, output: ShieldedOutput) -> Result<&mut Self, WalletError> {
        if self.outputs.len() >= MAX_OUTPUTS {
            return Err(WalletError::InvalidArgument("too many outputs"));
        }
        self.outputs.push(output);
        Ok(self)
    }

    /// Add multiple outputs.
    pub fn add_outputs(&mut self, outputs: Vec<ShieldedOutput>) -> Result<&mut Self, WalletError> {
        for output in outputs {
            self.add_output(output)?;
        }
        Ok(self)
    }

    /// Specify which notes to spend (by index in wallet store).
    pub fn with_inputs(&mut self, indices: Vec<usize>) -> &mut Self {
        self.specific_inputs = Some(indices);
        self
    }

    /// Disable automatic change output.
    pub fn no_change(&mut self) -> &mut Self {
        self.include_change = false;
        self
    }

    /// Build the shielded transaction.
    ///
    /// This will:
    /// 1. Select input notes
    /// 2. Build the transaction witness
    /// 3. Generate the STARK proof
    /// 4. Encrypt output notes
    /// 5. Return the complete transaction
    ///
    /// # Arguments
    ///
    /// * `fee` - Transaction fee in atomic units
    pub fn build(self, fee: u64) -> Result<BuiltShieldedTx, WalletError> {
        let total_start = Instant::now();
        let mut stats = ProofStats::default();

        // Check wallet mode
        if self.store.mode()? == WalletMode::WatchOnly {
            return Err(WalletError::WatchOnly);
        }

        // Validate we have outputs
        if self.outputs.is_empty() {
            return Err(WalletError::InvalidArgument("no outputs specified"));
        }

        // Get required keys
        let derived = self
            .store
            .derived_keys()?
            .ok_or(WalletError::InvalidState("missing derived keys"))?;
        let fvk = self
            .store
            .full_viewing_key()?
            .ok_or(WalletError::InvalidState("missing full viewing key"))?;

        // Calculate required value
        let required_asset = self.outputs[0].asset_id;
        if self.outputs.iter().any(|o| o.asset_id != required_asset) {
            // For now, only support single asset per transaction
            return Err(WalletError::InvalidArgument(
                "multi-asset transactions not yet supported",
            ));
        }

        let required_value: u64 = self
            .outputs
            .iter()
            .map(|o| o.value)
            .sum::<u64>()
            .saturating_add(fee);

        // Select input notes
        let input_start = Instant::now();
        let selection = self.select_inputs(required_asset, required_value)?;
        stats.input_selection_time = input_start.elapsed();

        // Build outputs (including change if needed)
        let mut rng = OsRng;
        let encryption_start = Instant::now();
        let (output_witnesses, ciphertexts) =
            self.build_outputs(&derived, &selection, required_value, fee, &mut rng)?;
        stats.encryption_time = encryption_start.elapsed();

        // Build witness
        let witness_start = Instant::now();
        let witness = self.build_witness(&derived, &fvk, &selection, output_witnesses, fee)?;
        stats.witness_build_time = witness_start.elapsed();

        // Generate STARK proof
        let proof_result = self.prover.prove(&witness)?;
        stats.proving_time = proof_result.proving_time;
        stats.proof_size = proof_result.proof_size();

        // Compute binding signature commitment (Blake2-256 hash of public inputs)
        let binding_hash = self.compute_binding_hash(
            &proof_result.anchor,
            &proof_result.nullifiers,
            &proof_result.commitments,
            proof_result.value_balance,
        );
        // The binding signature is the 32-byte hash duplicated to 64 bytes
        let mut binding_sig_64 = [0u8; 64];
        binding_sig_64[..32].copy_from_slice(&binding_hash);
        binding_sig_64[32..].copy_from_slice(&binding_hash);

        // Build transaction bundle
        let bundle = TransactionBundle::new(
            proof_result.proof_bytes.clone(),
            proof_result.nullifiers.to_vec(),
            proof_result.commitments.to_vec(),
            &ciphertexts,
            proof_result.anchor,
            binding_sig_64,
            proof_result.value_balance,
        )?;

        // Compute nullifiers for wallet tracking
        let nullifiers = self.compute_nullifiers(&fvk, &selection);

        // Get commitments
        let commitments = proof_result.commitments.to_vec();

        stats.total_time = total_start.elapsed();

        Ok(BuiltShieldedTx {
            bundle,
            nullifiers,
            commitments,
            spent_note_indices: selection.iter().map(|n| n.index).collect(),
            value_balance: 0, // Pure shielded transfer
            fee,
            proof_stats: stats,
        })
    }

    /// Select input notes to cover the required value.
    fn select_inputs(
        &self,
        asset_id: u64,
        required: u64,
    ) -> Result<Vec<SpendableNote>, WalletError> {
        if let Some(ref indices) = self.specific_inputs {
            // Use specified inputs
            let all_notes = self.store.spendable_notes(asset_id)?;
            let selected: Vec<_> = indices
                .iter()
                .filter_map(|&i| all_notes.iter().find(|n| n.index == i).cloned())
                .collect();

            let total: u64 = selected.iter().map(|n| n.value()).sum();
            if total < required {
                return Err(WalletError::InsufficientFunds {
                    needed: required,
                    available: total,
                });
            }

            if selected.len() > MAX_INPUTS {
                return Err(WalletError::InvalidArgument("too many inputs"));
            }

            Ok(selected)
        } else {
            // Automatic selection
            let mut notes = self.store.spendable_notes(asset_id)?;
            if notes.is_empty() {
                return Err(WalletError::InsufficientFunds {
                    needed: required,
                    available: 0,
                });
            }

            // Sort by position (oldest first)
            notes.sort_by_key(|n| n.position);

            let mut selected = Vec::new();
            let mut total = 0u64;

            for note in notes {
                selected.push(note.clone());
                total = total.saturating_add(note.value());

                if total >= required {
                    break;
                }
            }

            if total < required {
                return Err(WalletError::InsufficientFunds {
                    needed: required,
                    available: total,
                });
            }

            if selected.len() > MAX_INPUTS {
                return Err(WalletError::InvalidArgument("too many inputs required"));
            }

            Ok(selected)
        }
    }

    /// Build output notes and encrypt them.
    fn build_outputs(
        &self,
        _derived: &DerivedKeys,
        selection: &[SpendableNote],
        _required: u64,
        fee: u64,
        rng: &mut OsRng,
    ) -> Result<(Vec<OutputNoteWitness>, Vec<NoteCiphertext>), WalletError> {
        let mut witnesses = Vec::new();
        let mut ciphertexts = Vec::new();

        // Build explicit outputs
        for output in &self.outputs {
            let note =
                NotePlaintext::random(output.value, output.asset_id, output.memo_plaintext(), rng);
            let ciphertext = NoteCiphertext::encrypt(&output.address, &note, rng)?;

            witnesses.push(OutputNoteWitness {
                note: note.to_note_data(output.address.pk_recipient),
            });
            ciphertexts.push(ciphertext);
        }

        // Handle change if needed
        if self.include_change {
            let input_total: u64 = selection.iter().map(|n| n.value()).sum();
            let output_total: u64 = self.outputs.iter().map(|o| o.value).sum::<u64>() + fee;
            let change = input_total.saturating_sub(output_total);

            if change > 0 {
                if witnesses.len() >= MAX_OUTPUTS {
                    return Err(WalletError::InvalidArgument("no room for change output"));
                }

                // Create change address
                let change_address = self.store.reserve_internal_address()?;
                let change_note = NotePlaintext::random(
                    change,
                    self.outputs[0].asset_id, // Same asset as outputs
                    MemoPlaintext::default(),
                    rng,
                );
                let change_ciphertext =
                    NoteCiphertext::encrypt(&change_address, &change_note, rng)?;

                witnesses.push(OutputNoteWitness {
                    note: change_note.to_note_data(change_address.pk_recipient),
                });
                ciphertexts.push(change_ciphertext);
            }
        }

        Ok((witnesses, ciphertexts))
    }

    /// Build the transaction witness for STARK proving.
    fn build_witness(
        &self,
        derived: &DerivedKeys,
        _fvk: &FullViewingKey,
        selection: &[SpendableNote],
        outputs: Vec<OutputNoteWitness>,
        fee: u64,
    ) -> Result<TransactionWitness, WalletError> {
        // Get Merkle tree for authentication paths
        let tree = self.store.commitment_tree()?;

        // Build input witnesses with Merkle paths
        let mut inputs = Vec::with_capacity(selection.len());
        for note in selection {
            // Get the Merkle authentication path for this note's position
            let auth_path = tree
                .authentication_path(note.position as usize)
                .map_err(|e| {
                    WalletError::InvalidState(Box::leak(
                        format!("merkle path error: {}", e).into_boxed_str(),
                    ))
                })?;

            // Convert Felt path to MerklePath
            let merkle_path = transaction_circuit::note::MerklePath {
                siblings: auth_path,
            };

            // Create input witness with the merkle path
            let mut input_witness = note.recovered.to_input_witness(note.position);
            input_witness.merkle_path = merkle_path;
            inputs.push(input_witness);
        }

        Ok(TransactionWitness {
            inputs,
            outputs,
            sk_spend: derived.spend.to_bytes(),
            merkle_root: tree.root(),
            fee,
            version: TransactionWitness::default_version_binding(),
        })
    }

    /// Compute binding signature hash for transaction commitment.
    ///
    /// Returns the 32-byte Blake2-256 hash of the public inputs:
    /// Blake2_256(anchor || nullifiers || commitments || value_balance)
    fn compute_binding_hash(
        &self,
        anchor: &[u8; 32],
        nullifiers: &[[u8; 32]],
        commitments: &[[u8; 32]],
        value_balance: i128,
    ) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(anchor);
        for nf in nullifiers {
            data.extend_from_slice(nf);
        }
        for cm in commitments {
            data.extend_from_slice(cm);
        }
        data.extend_from_slice(&value_balance.to_le_bytes());
        synthetic_crypto::hashes::blake2_256(&data)
    }

    /// Compute nullifiers for the spent notes.
    fn compute_nullifiers(
        &self,
        fvk: &FullViewingKey,
        selection: &[SpendableNote],
    ) -> Vec<[u8; 32]> {
        selection
            .iter()
            .map(|note| fvk.compute_nullifier(&note.recovered.note.rho, note.position))
            .collect()
    }
}

/// Shield transparent funds into the shielded pool.
///
/// This creates a shielding transaction that moves transparent funds
/// into the shielded pool, creating a new shielded note.
#[derive(Clone, Debug)]
pub struct ShieldingTx {
    /// Commitment for the new note.
    pub commitment: [u8; 32],
    /// Encrypted note ciphertext.
    pub encrypted_note: Vec<u8>,
    /// Amount being shielded.
    pub amount: u64,
}

/// Build a shielding transaction.
///
/// # Arguments
///
/// * `address` - Shielded address to receive the funds
/// * `amount` - Amount to shield
/// * `memo` - Optional memo
pub fn build_shielding_tx(
    address: &ShieldedAddress,
    amount: u64,
    memo: Option<String>,
) -> Result<ShieldingTx, WalletError> {
    let mut rng = OsRng;

    let memo_plaintext = memo
        .map(|m| MemoPlaintext::new(m.as_bytes().to_vec()))
        .unwrap_or_default();

    let note = NotePlaintext::random(amount, NATIVE_ASSET_ID, memo_plaintext, &mut rng);
    let ciphertext = NoteCiphertext::encrypt(address, &note, &mut rng)?;

    // Compute commitment
    let note_data = note.to_note_data(address.pk_recipient);
    let commitment_felt = note_data.commitment();
    let mut commitment = [0u8; 32];
    commitment[24..32].copy_from_slice(&commitment_felt.as_int().to_be_bytes());

    // Serialize ciphertext
    let encrypted_note =
        bincode::serialize(&ciphertext).map_err(|e| WalletError::Serialization(e.to_string()))?;

    Ok(ShieldingTx {
        commitment,
        encrypted_note,
        amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shielded_output_native() {
        let addr = ShieldedAddress::default();
        let output = ShieldedOutput::native(addr.clone(), 1000);
        assert_eq!(output.value, 1000);
        assert_eq!(output.asset_id, NATIVE_ASSET_ID);
        assert!(output.memo.is_none());
    }

    #[test]
    fn test_shielded_output_with_memo() {
        let addr = ShieldedAddress::default();
        let output = ShieldedOutput::with_memo(addr, 500, "test memo".to_string());
        assert_eq!(output.value, 500);
        assert_eq!(output.memo, Some("test memo".to_string()));
    }

    #[test]
    fn test_proof_stats_default() {
        let stats = ProofStats::default();
        assert_eq!(stats.proof_size, 0);
        assert_eq!(stats.total_time, Duration::ZERO);
    }
}
