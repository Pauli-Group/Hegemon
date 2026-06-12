//! Transaction proof structures and proving/verification functions.
//!
//! This module provides the main interface for creating and verifying
//! transaction proofs across the version-bound backend seam.

use protocol_versioning::{
    tx_proof_backend_for_version, TxProofBackend, VersionBinding, DEFAULT_TX_PROOF_BACKEND,
};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use synthetic_crypto::hashes::blake3_384;

use crate::smallwood_frontend::{
    decode_smallwood_candidate_proof, prove_smallwood_candidate,
    smallwood_candidate_verifier_profile_material, verify_smallwood_candidate_proof_bytes,
    verify_smallwood_candidate_transaction_proof,
};
use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing_pq::{balance_commitment_bytes, bytes48_to_felts, Commitment},
    keys::{ProvingKey, VerifyingKey},
    public_inputs::{BalanceSlot, TransactionPublicInputs},
    smallwood_engine::SmallwoodArithmetization,
    trace::TransactionTrace,
    witness::TransactionWitness,
};

use crate::p3_prover::TransactionProofParams;
use crate::p3_prover::TransactionProverP3;
use crate::p3_verifier::verify_transaction_proof_bytes_p3_for_version;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use postcard::to_allocvec;
use transaction_core::p3_air::TransactionPublicInputsP3;
use transaction_core::p3_config::release_tx_fri_profile_for_version;

/// A transaction proof containing public inputs and backend-specific proof bytes.
///
/// The `stark_proof` field is legacy wire naming and contains the actual proof bytes.
/// The other fields are public inputs that can be verified against the proof.
///
/// For backend-specific verification, use `verify()` or
/// `verify_transaction_proof_bytes_for_backend()`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionProof {
    pub public_inputs: TransactionPublicInputs,
    #[serde(with = "crate::public_inputs::serde_vec_bytes48")]
    pub nullifiers: Vec<Commitment>,
    #[serde(with = "crate::public_inputs::serde_vec_bytes48")]
    pub commitments: Vec<Commitment>,
    pub balance_slots: Vec<BalanceSlot>,
    #[serde(default = "default_tx_proof_backend")]
    pub backend: TxProofBackend,
    /// The actual proof bytes (backend-specific format).
    /// This is the cryptographic proof that the transaction is valid.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stark_proof: Vec<u8>,
    /// Serialized verifier-facing public inputs for verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stark_public_inputs: Option<SerializedStarkInputs>,
}

/// Serialized STARK public inputs for verification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerializedStarkInputs {
    pub input_flags: Vec<u8>,
    pub output_flags: Vec<u8>,
    pub fee: u64,
    pub value_balance_sign: u8,
    pub value_balance_magnitude: u64,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub merkle_root: Commitment,
    #[serde(default)]
    pub balance_slot_asset_ids: Vec<u64>,
    #[serde(default)]
    pub stablecoin_enabled: u8,
    #[serde(default)]
    pub stablecoin_asset_id: u64,
    #[serde(default)]
    pub stablecoin_policy_version: u32,
    #[serde(default)]
    pub stablecoin_issuance_sign: u8,
    #[serde(default)]
    pub stablecoin_issuance_magnitude: u64,
    #[serde(
        default = "default_bytes48",
        with = "crate::public_inputs::serde_bytes48"
    )]
    pub stablecoin_policy_hash: Commitment,
    #[serde(
        default = "default_bytes48",
        with = "crate::public_inputs::serde_bytes48"
    )]
    pub stablecoin_oracle_commitment: Commitment,
    #[serde(
        default = "default_bytes48",
        with = "crate::public_inputs::serde_bytes48"
    )]
    pub stablecoin_attestation_commitment: Commitment,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub verified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionProofWrapperAdmissionInput {
    pub exact_consumption: bool,
    pub canonical_reencode: bool,
    pub backend_supported: bool,
    pub proof_bytes_present: bool,
    pub serialized_public_inputs_present: bool,
    pub public_inputs_valid: bool,
    pub nullifier_vector_agrees: bool,
    pub commitment_vector_agrees: bool,
    pub balance_slots_agree: bool,
    pub verifier_accepts: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionProofWrapperAdmissionRejection {
    NonExactConsumption,
    NonCanonicalReencode,
    UnsupportedBackend,
    MissingProofBytes,
    MissingSerializedPublicInputs,
    InvalidPublicInputs,
    NullifierVectorMismatch,
    CommitmentVectorMismatch,
    BalanceSlotMismatch,
    VerifierRejected,
}

impl TransactionProofWrapperAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::NonExactConsumption => "non_exact_consumption",
            Self::NonCanonicalReencode => "non_canonical_reencode",
            Self::UnsupportedBackend => "unsupported_backend",
            Self::MissingProofBytes => "missing_proof_bytes",
            Self::MissingSerializedPublicInputs => "missing_serialized_public_inputs",
            Self::InvalidPublicInputs => "invalid_public_inputs",
            Self::NullifierVectorMismatch => "nullifier_vector_mismatch",
            Self::CommitmentVectorMismatch => "commitment_vector_mismatch",
            Self::BalanceSlotMismatch => "balance_slot_mismatch",
            Self::VerifierRejected => "verifier_rejected",
        }
    }
}

fn transaction_proof_wrapper_admission_error(
    rejection: TransactionProofWrapperAdmissionRejection,
) -> TransactionCircuitError {
    let label = match rejection {
        TransactionProofWrapperAdmissionRejection::NonExactConsumption => "non-exact consumption",
        TransactionProofWrapperAdmissionRejection::NonCanonicalReencode => "non-canonical reencode",
        TransactionProofWrapperAdmissionRejection::UnsupportedBackend => "unsupported backend",
        TransactionProofWrapperAdmissionRejection::MissingProofBytes => "missing proof bytes",
        TransactionProofWrapperAdmissionRejection::MissingSerializedPublicInputs => {
            "missing serialized public inputs"
        }
        TransactionProofWrapperAdmissionRejection::InvalidPublicInputs => "invalid public inputs",
        TransactionProofWrapperAdmissionRejection::NullifierVectorMismatch => {
            "nullifier vector mismatch"
        }
        TransactionProofWrapperAdmissionRejection::CommitmentVectorMismatch => {
            "commitment vector mismatch"
        }
        TransactionProofWrapperAdmissionRejection::BalanceSlotMismatch => "balance slot mismatch",
        TransactionProofWrapperAdmissionRejection::VerifierRejected => "verifier rejected",
    };
    TransactionCircuitError::ConstraintViolationOwned(format!(
        "transaction proof wrapper admission failed: {label}"
    ))
}

pub fn evaluate_transaction_proof_wrapper_admission(
    input: TransactionProofWrapperAdmissionInput,
) -> Result<(), TransactionProofWrapperAdmissionRejection> {
    if !input.exact_consumption {
        return Err(TransactionProofWrapperAdmissionRejection::NonExactConsumption);
    }
    if !input.canonical_reencode {
        return Err(TransactionProofWrapperAdmissionRejection::NonCanonicalReencode);
    }
    if !input.backend_supported {
        return Err(TransactionProofWrapperAdmissionRejection::UnsupportedBackend);
    }
    if !input.proof_bytes_present {
        return Err(TransactionProofWrapperAdmissionRejection::MissingProofBytes);
    }
    if !input.serialized_public_inputs_present {
        return Err(TransactionProofWrapperAdmissionRejection::MissingSerializedPublicInputs);
    }
    if !input.public_inputs_valid {
        return Err(TransactionProofWrapperAdmissionRejection::InvalidPublicInputs);
    }
    if !input.nullifier_vector_agrees {
        return Err(TransactionProofWrapperAdmissionRejection::NullifierVectorMismatch);
    }
    if !input.commitment_vector_agrees {
        return Err(TransactionProofWrapperAdmissionRejection::CommitmentVectorMismatch);
    }
    if !input.balance_slots_agree {
        return Err(TransactionProofWrapperAdmissionRejection::BalanceSlotMismatch);
    }
    if !input.verifier_accepts {
        return Err(TransactionProofWrapperAdmissionRejection::VerifierRejected);
    }
    Ok(())
}

pub fn admit_transaction_proof_wrapper(
    input: TransactionProofWrapperAdmissionInput,
    verifier_result: Result<(), TransactionCircuitError>,
) -> Result<(), TransactionCircuitError> {
    if let Err(rejection) = evaluate_transaction_proof_wrapper_admission(input) {
        return Err(match rejection {
            TransactionProofWrapperAdmissionRejection::VerifierRejected => verifier_result
                .err()
                .unwrap_or_else(|| transaction_proof_wrapper_admission_error(rejection)),
            other => transaction_proof_wrapper_admission_error(other),
        });
    }
    verifier_result
}

impl TransactionProof {
    pub fn version_binding(&self) -> VersionBinding {
        self.public_inputs.version_binding()
    }

    pub fn proof_backend(&self) -> TxProofBackend {
        self.backend
    }

    pub fn proof_bytes(&self) -> &[u8] {
        &self.stark_proof
    }

    /// Check if this proof has a real STARK proof attached.
    pub fn has_stark_proof(&self) -> bool {
        !self.stark_proof.is_empty()
    }
}

pub fn decode_transaction_proof_bytes_exact(
    proof_bytes: &[u8],
) -> Result<TransactionProof, TransactionCircuitError> {
    let mut cursor = Cursor::new(proof_bytes);
    let proof: TransactionProof = bincode::deserialize_from(&mut cursor).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to decode transaction proof wrapper: {err}"
        ))
    })?;
    if cursor.position() as usize != proof_bytes.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "transaction proof wrapper has trailing bytes",
        ));
    }
    let canonical = bincode::serialize(&proof).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to reserialize transaction proof wrapper: {err}"
        ))
    })?;
    if canonical != proof_bytes {
        return Err(TransactionCircuitError::ConstraintViolation(
            "transaction proof wrapper must use canonical serialization",
        ));
    }
    Ok(proof)
}

pub const TX_STATEMENT_HASH_DOMAIN: &[u8] = b"tx-statement-v1";
pub const TX_PROOF_DIGEST_DOMAIN: &[u8] = b"tx-proof-digest-v1";
pub const TX_PUBLIC_INPUTS_DIGEST_DOMAIN: &[u8] = b"tx-public-inputs-digest-v1";
pub const TX_VERIFIER_PROFILE_DOMAIN: &[u8] = b"hegemon.inline-tx-p3-profile.v1";

fn default_tx_proof_backend() -> TxProofBackend {
    DEFAULT_TX_PROOF_BACKEND
}

/// Reconstruct the Plonky3 public inputs from a transaction proof.
///
/// This is useful when callers need the STARK public inputs without re-verifying the proof.
pub fn stark_public_inputs_p3(
    proof: &TransactionProof,
) -> Result<TransactionPublicInputsP3, TransactionCircuitError> {
    ensure_plonky3_backend(proof)?;
    let stark_inputs =
        proof
            .stark_public_inputs
            .as_ref()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "missing STARK public inputs",
            ))?;

    transaction_public_inputs_p3_from_parts(&proof.public_inputs, stark_inputs)
}

pub fn transaction_proof_wrapper_public_inputs_for_admission(
    proof: &TransactionProof,
    backend_supported: bool,
) -> Result<TransactionPublicInputsP3, TransactionCircuitError> {
    let proof_bytes_present = !proof.stark_proof.is_empty();
    let serialized_public_inputs_present = proof.stark_public_inputs.is_some();
    let public_inputs_result = proof
        .stark_public_inputs
        .as_ref()
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "missing STARK public inputs",
        ))
        .and_then(|stark_inputs| {
            let p3_inputs =
                transaction_public_inputs_p3_from_parts(&proof.public_inputs, stark_inputs)?;
            p3_inputs.validate().map_err(|err| {
                TransactionCircuitError::ConstraintViolationOwned(format!(
                    "invalid STARK public inputs: {err}"
                ))
            })?;
            Ok(p3_inputs)
        });
    let nullifier_vector_result = verify_wrapper_nullifier_vector(proof);
    let commitment_vector_result = verify_wrapper_commitment_vector(proof);
    let balance_result = verify_balance_slots(proof);

    if let Err(rejection) =
        evaluate_transaction_proof_wrapper_admission(TransactionProofWrapperAdmissionInput {
            exact_consumption: true,
            canonical_reencode: true,
            backend_supported,
            proof_bytes_present,
            serialized_public_inputs_present,
            public_inputs_valid: public_inputs_result.is_ok(),
            nullifier_vector_agrees: nullifier_vector_result.is_ok(),
            commitment_vector_agrees: commitment_vector_result.is_ok(),
            balance_slots_agree: balance_result.is_ok(),
            verifier_accepts: true,
        })
    {
        return Err(match rejection {
            TransactionProofWrapperAdmissionRejection::InvalidPublicInputs => public_inputs_result
                .err()
                .unwrap_or_else(|| transaction_proof_wrapper_admission_error(rejection)),
            TransactionProofWrapperAdmissionRejection::NullifierVectorMismatch => {
                nullifier_vector_result
                    .err()
                    .unwrap_or_else(|| transaction_proof_wrapper_admission_error(rejection))
            }
            TransactionProofWrapperAdmissionRejection::CommitmentVectorMismatch => {
                commitment_vector_result
                    .err()
                    .unwrap_or_else(|| transaction_proof_wrapper_admission_error(rejection))
            }
            TransactionProofWrapperAdmissionRejection::BalanceSlotMismatch => balance_result
                .err()
                .unwrap_or_else(|| transaction_proof_wrapper_admission_error(rejection)),
            other => transaction_proof_wrapper_admission_error(other),
        });
    }

    public_inputs_result
}

fn verify_wrapper_nullifier_vector(
    proof: &TransactionProof,
) -> Result<(), TransactionCircuitError> {
    if proof.nullifiers == proof.public_inputs.nullifiers {
        Ok(())
    } else {
        Err(TransactionCircuitError::ConstraintViolation(
            "transaction proof wrapper nullifier vector mismatch",
        ))
    }
}

fn verify_wrapper_commitment_vector(
    proof: &TransactionProof,
) -> Result<(), TransactionCircuitError> {
    if proof.commitments == proof.public_inputs.commitments {
        Ok(())
    } else {
        Err(TransactionCircuitError::ConstraintViolation(
            "transaction proof wrapper commitment vector mismatch",
        ))
    }
}

pub fn transaction_statement_hash(proof: &TransactionProof) -> [u8; 48] {
    transaction_statement_hash_from_public_inputs(&proof.public_inputs)
}

pub fn transaction_statement_hash_checked(
    proof: &TransactionProof,
) -> Result<[u8; 48], TransactionCircuitError> {
    transaction_statement_hash_from_public_inputs_checked(&proof.public_inputs)
}

pub fn transaction_statement_hash_from_public_inputs(public: &TransactionPublicInputs) -> [u8; 48] {
    transaction_statement_hash_from_public_inputs_checked(public)
        .expect("validated transaction public inputs fit statement hash layout")
}

pub fn transaction_statement_hash_from_public_inputs_checked(
    public: &TransactionPublicInputs,
) -> Result<[u8; 48], TransactionCircuitError> {
    transaction_statement_hash_from_parts(
        &public.merkle_root,
        &public.nullifiers,
        &public.commitments,
        &public.ciphertext_hashes,
        public.native_fee,
        public.value_balance,
        &public.balance_tag,
        public.circuit_version,
        public.crypto_suite,
        public.stablecoin.enabled as u8,
        public.stablecoin.asset_id,
        &public.stablecoin.policy_hash,
        &public.stablecoin.oracle_commitment,
        &public.stablecoin.attestation_commitment,
        public.stablecoin.issuance_delta,
        public.stablecoin.policy_version,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn transaction_statement_hash_from_parts(
    merkle_root: &Commitment,
    nullifiers: &[Commitment],
    commitments: &[Commitment],
    ciphertext_hashes: &[Commitment],
    native_fee: u64,
    value_balance: i128,
    balance_tag: &Commitment,
    circuit_version: protocol_versioning::CircuitVersion,
    crypto_suite: protocol_versioning::CryptoSuiteId,
    stablecoin_enabled: u8,
    stablecoin_asset_id: u64,
    stablecoin_policy_hash: &Commitment,
    stablecoin_oracle_commitment: &Commitment,
    stablecoin_attestation_commitment: &Commitment,
    stablecoin_issuance_delta: i128,
    stablecoin_policy_version: u32,
) -> Result<[u8; 48], TransactionCircuitError> {
    let preimage = transaction_statement_preimage_from_parts(
        merkle_root,
        nullifiers,
        commitments,
        ciphertext_hashes,
        native_fee,
        value_balance,
        balance_tag,
        circuit_version,
        crypto_suite,
        stablecoin_enabled,
        stablecoin_asset_id,
        stablecoin_policy_hash,
        stablecoin_oracle_commitment,
        stablecoin_attestation_commitment,
        stablecoin_issuance_delta,
        stablecoin_policy_version,
    )?;
    Ok(blake3_384(&preimage))
}

#[allow(clippy::too_many_arguments)]
pub fn transaction_statement_preimage_from_parts(
    merkle_root: &Commitment,
    nullifiers: &[Commitment],
    commitments: &[Commitment],
    ciphertext_hashes: &[Commitment],
    native_fee: u64,
    value_balance: i128,
    balance_tag: &Commitment,
    circuit_version: protocol_versioning::CircuitVersion,
    crypto_suite: protocol_versioning::CryptoSuiteId,
    stablecoin_enabled: u8,
    stablecoin_asset_id: u64,
    stablecoin_policy_hash: &Commitment,
    stablecoin_oracle_commitment: &Commitment,
    stablecoin_attestation_commitment: &Commitment,
    stablecoin_issuance_delta: i128,
    stablecoin_policy_version: u32,
) -> Result<Vec<u8>, TransactionCircuitError> {
    if nullifiers.len() > MAX_INPUTS {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "transaction nullifier length {} exceeds MAX_INPUTS {MAX_INPUTS}",
            nullifiers.len()
        )));
    }
    if commitments.len() > MAX_OUTPUTS {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "transaction commitment length {} exceeds MAX_OUTPUTS {MAX_OUTPUTS}",
            commitments.len()
        )));
    }
    if ciphertext_hashes.len() > MAX_OUTPUTS {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "transaction ciphertext hash length {} exceeds MAX_OUTPUTS {MAX_OUTPUTS}",
            ciphertext_hashes.len()
        )));
    }

    let mut message = Vec::new();
    message.extend_from_slice(TX_STATEMENT_HASH_DOMAIN);
    message.extend_from_slice(merkle_root);
    for nf in nullifiers {
        message.extend_from_slice(nf);
    }
    for _ in nullifiers.len()..MAX_INPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }
    for cm in commitments {
        message.extend_from_slice(cm);
    }
    for _ in commitments.len()..MAX_OUTPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }
    for ct in ciphertext_hashes {
        message.extend_from_slice(ct);
    }
    for _ in ciphertext_hashes.len()..MAX_OUTPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }
    message.extend_from_slice(&native_fee.to_le_bytes());
    message.extend_from_slice(&value_balance.to_le_bytes());
    message.extend_from_slice(balance_tag);
    message.extend_from_slice(&circuit_version.to_le_bytes());
    message.extend_from_slice(&crypto_suite.to_le_bytes());
    message.push(stablecoin_enabled);
    message.extend_from_slice(&stablecoin_asset_id.to_le_bytes());
    message.extend_from_slice(stablecoin_policy_hash);
    message.extend_from_slice(stablecoin_oracle_commitment);
    message.extend_from_slice(stablecoin_attestation_commitment);
    message.extend_from_slice(&stablecoin_issuance_delta.to_le_bytes());
    message.extend_from_slice(&stablecoin_policy_version.to_le_bytes());
    Ok(message)
}

pub fn transaction_proof_digest(proof: &TransactionProof) -> [u8; 48] {
    transaction_proof_digest_from_parts(proof.backend, &proof.stark_proof)
}

pub fn transaction_proof_digest_from_parts(
    backend: TxProofBackend,
    proof_bytes: &[u8],
) -> [u8; 48] {
    let mut message = Vec::with_capacity(TX_PROOF_DIGEST_DOMAIN.len() + proof_bytes.len() + 1);
    message.extend_from_slice(TX_PROOF_DIGEST_DOMAIN);
    message.push(backend.wire_id());
    message.extend_from_slice(proof_bytes);
    blake3_384(&message)
}

pub fn transaction_public_inputs_digest_from_serialized(
    stark_inputs: &SerializedStarkInputs,
) -> Result<[u8; 48], TransactionCircuitError> {
    let encoded = to_allocvec(stark_inputs).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to serialize STARK public inputs: {err}"
        ))
    })?;
    let mut message = Vec::with_capacity(TX_PUBLIC_INPUTS_DIGEST_DOMAIN.len() + encoded.len());
    message.extend_from_slice(TX_PUBLIC_INPUTS_DIGEST_DOMAIN);
    message.extend_from_slice(&encoded);
    Ok(blake3_384(&message))
}

pub fn transaction_public_inputs_digest(
    proof: &TransactionProof,
) -> Result<[u8; 48], TransactionCircuitError> {
    let stark_inputs =
        proof
            .stark_public_inputs
            .as_ref()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "missing STARK public inputs",
            ))?;
    transaction_public_inputs_digest_from_serialized(stark_inputs)
}

pub fn transaction_verifier_profile_digest_for_version_and_backend(
    version: VersionBinding,
    backend: TxProofBackend,
    smallwood_arithmetization: Option<SmallwoodArithmetization>,
) -> [u8; 48] {
    let mut message = Vec::new();
    message.extend_from_slice(TX_VERIFIER_PROFILE_DOMAIN);
    message.extend_from_slice(backend.label().as_bytes());
    message.extend_from_slice(&version.circuit.to_le_bytes());
    message.extend_from_slice(&version.crypto.to_le_bytes());
    if matches!(backend, TxProofBackend::Plonky3Fri) {
        let profile = release_tx_fri_profile_for_version(version);
        message.extend_from_slice(&(profile.log_blowup as u64).to_le_bytes());
        message.extend_from_slice(&(profile.num_queries as u64).to_le_bytes());
        message.extend_from_slice(&(profile.query_pow_bits as u64).to_le_bytes());
    } else if matches!(backend, TxProofBackend::SmallwoodCandidate) {
        let arithmetization = smallwood_arithmetization.unwrap_or(
            SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
        );
        message.extend_from_slice(&smallwood_candidate_verifier_profile_material(
            version,
            arithmetization,
        ));
    }
    blake3_384(&message)
}

pub fn transaction_verifier_profile_digest_for_version(version: VersionBinding) -> [u8; 48] {
    transaction_verifier_profile_digest_for_version_and_backend(
        version,
        tx_proof_backend_for_version(version).unwrap_or(DEFAULT_TX_PROOF_BACKEND),
        Some(SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1),
    )
}

pub fn smallwood_arithmetization_from_backend_and_proof_bytes(
    backend: TxProofBackend,
    proof_bytes: &[u8],
) -> Result<Option<SmallwoodArithmetization>, TransactionCircuitError> {
    if !matches!(backend, TxProofBackend::SmallwoodCandidate) {
        return Ok(None);
    }
    let candidate = decode_smallwood_candidate_proof(proof_bytes)?;
    Ok(Some(candidate.arithmetization))
}

pub fn smallwood_arithmetization_from_proof(
    proof: &TransactionProof,
) -> Result<Option<SmallwoodArithmetization>, TransactionCircuitError> {
    smallwood_arithmetization_from_backend_and_proof_bytes(proof.backend, &proof.stark_proof)
}

pub fn transaction_verifier_profile_digest(
    proof: &TransactionProof,
) -> Result<[u8; 48], TransactionCircuitError> {
    let smallwood_arithmetization = smallwood_arithmetization_from_proof(proof)?;
    Ok(transaction_verifier_profile_digest_for_version_and_backend(
        proof.version_binding(),
        proof.backend,
        smallwood_arithmetization,
    ))
}

pub fn verify_transaction_proof_bytes_for_backend(
    backend: TxProofBackend,
    proof_bytes: &[u8],
    pub_inputs: &TransactionPublicInputsP3,
    version: VersionBinding,
) -> Result<(), TransactionCircuitError> {
    match backend {
        TxProofBackend::Plonky3Fri => {
            verify_transaction_proof_bytes_p3_for_version(proof_bytes, pub_inputs, version).map_err(
                |err| {
                    TransactionCircuitError::ConstraintViolationOwned(format!(
                        "STARK verification failed: {err}"
                    ))
                },
            )
        }
        TxProofBackend::SmallwoodCandidate => {
            verify_smallwood_candidate_proof_bytes(proof_bytes, pub_inputs, version)
        }
    }
}

/// Generate a real STARK proof for a transaction (Plonky3 backend).
pub fn prove(
    witness: &TransactionWitness,
    _proving_key: &ProvingKey,
) -> Result<TransactionProof, TransactionCircuitError> {
    prove_with_params(
        witness,
        _proving_key,
        TransactionProofParams::production_for_version(witness.version),
    )
}

pub fn prove_with_params(
    witness: &TransactionWitness,
    _proving_key: &ProvingKey,
    params: TransactionProofParams,
) -> Result<TransactionProof, TransactionCircuitError> {
    let backend = tx_proof_backend_for_version(witness.version).unwrap_or(DEFAULT_TX_PROOF_BACKEND);
    if matches!(backend, TxProofBackend::SmallwoodCandidate) {
        return prove_smallwood_candidate(witness);
    }
    witness.validate()?;

    let trace = TransactionTrace::from_witness(witness)?;
    let public_inputs = witness.public_inputs()?;

    let prover = TransactionProverP3::new();
    let stark_trace = prover.build_trace(witness).map_err(|e| {
        TransactionCircuitError::ConstraintViolationOwned(format!("Trace building failed: {}", e))
    })?;
    let stark_pub_inputs = prover.public_inputs(witness)?;
    let stark_proof = prover.prove_bytes_with_params(stark_trace, &stark_pub_inputs, params)?;

    let serialized_inputs = serialize_p3_inputs(&stark_pub_inputs);
    let nullifiers = public_inputs.nullifiers.clone();
    let commitments = public_inputs.commitments.clone();

    Ok(TransactionProof {
        nullifiers,
        commitments,
        balance_slots: trace.padded_balance_slots(),
        public_inputs,
        backend,
        stark_proof,
        stark_public_inputs: Some(serialized_inputs),
    })
}

/// Verify a transaction proof.
///
/// This performs real STARK proof verification and requires proof bytes plus public inputs.
pub fn verify(
    proof: &TransactionProof,
    _verifying_key: &VerifyingKey,
) -> Result<VerificationReport, TransactionCircuitError> {
    match proof.backend {
        TxProofBackend::Plonky3Fri => verify_with_p3(proof),
        TxProofBackend::SmallwoodCandidate => verify_smallwood_candidate_transaction_proof(proof),
    }
}

fn verify_with_p3(proof: &TransactionProof) -> Result<VerificationReport, TransactionCircuitError> {
    let stark_pub_inputs = transaction_proof_wrapper_public_inputs_p3(proof)?;

    let verifier_result = verify_transaction_proof_bytes_for_backend(
        proof.backend,
        &proof.stark_proof,
        &stark_pub_inputs,
        proof.version_binding(),
    );
    admit_transaction_proof_wrapper(
        TransactionProofWrapperAdmissionInput {
            exact_consumption: true,
            canonical_reencode: true,
            backend_supported: matches!(proof.backend, TxProofBackend::Plonky3Fri),
            proof_bytes_present: !proof.stark_proof.is_empty(),
            serialized_public_inputs_present: proof.stark_public_inputs.is_some(),
            public_inputs_valid: true,
            nullifier_vector_agrees: proof.nullifiers == proof.public_inputs.nullifiers,
            commitment_vector_agrees: proof.commitments == proof.public_inputs.commitments,
            balance_slots_agree: true,
            verifier_accepts: verifier_result.is_ok(),
        },
        verifier_result,
    )?;
    Ok(VerificationReport { verified: true })
}

pub fn transaction_proof_wrapper_public_inputs_p3(
    proof: &TransactionProof,
) -> Result<TransactionPublicInputsP3, TransactionCircuitError> {
    transaction_proof_wrapper_public_inputs_for_admission(
        proof,
        matches!(proof.backend, TxProofBackend::Plonky3Fri),
    )
}

fn ensure_plonky3_backend(proof: &TransactionProof) -> Result<(), TransactionCircuitError> {
    if matches!(proof.backend, TxProofBackend::Plonky3Fri) {
        Ok(())
    } else {
        Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "transaction proof backend {} does not expose Plonky3 public inputs",
            proof.backend.label()
        )))
    }
}

pub fn serialized_stark_inputs_from_witness(
    witness: &TransactionWitness,
) -> Result<SerializedStarkInputs, TransactionCircuitError> {
    witness.validate()?;
    let prover = TransactionProverP3::new();
    let stark_pub_inputs = prover.public_inputs(witness)?;
    Ok(serialize_p3_inputs(&stark_pub_inputs))
}

pub(crate) fn transaction_public_inputs_p3_from_parts(
    public_inputs: &TransactionPublicInputs,
    stark_inputs: &SerializedStarkInputs,
) -> Result<TransactionPublicInputsP3, TransactionCircuitError> {
    let signed_magnitude_matches = |value: i128, sign: u8, magnitude: u64| -> bool {
        let expected_sign = u8::from(value < 0);
        let expected_magnitude = value.unsigned_abs();
        expected_sign == sign && expected_magnitude == u128::from(magnitude)
    };
    let normalize_balance_slot_asset_id =
        |asset_id: u64| Goldilocks::from_u64(asset_id).as_canonical_u64();

    if public_inputs.merkle_root != stark_inputs.merkle_root {
        return Err(TransactionCircuitError::ConstraintViolation(
            "public merkle root does not match serialized public inputs",
        ));
    }
    if public_inputs.native_fee != stark_inputs.fee {
        return Err(TransactionCircuitError::ConstraintViolation(
            "public fee does not match serialized public inputs",
        ));
    }
    if !signed_magnitude_matches(
        public_inputs.value_balance,
        stark_inputs.value_balance_sign,
        stark_inputs.value_balance_magnitude,
    ) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "public value balance does not match serialized public inputs",
        ));
    }
    if !stark_inputs.balance_slot_asset_ids.is_empty()
        && public_inputs
            .balance_slots
            .iter()
            .map(|slot| normalize_balance_slot_asset_id(slot.asset_id))
            .collect::<Vec<_>>()
            != stark_inputs
                .balance_slot_asset_ids
                .iter()
                .copied()
                .map(normalize_balance_slot_asset_id)
                .collect::<Vec<_>>()
    {
        let public_assets = public_inputs
            .balance_slots
            .iter()
            .map(|slot| slot.asset_id)
            .collect::<Vec<_>>();
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "public balance slot assets do not match serialized public inputs: public={public_assets:?} serialized={:?}",
            stark_inputs.balance_slot_asset_ids
        )));
    }
    if u8::from(public_inputs.stablecoin.enabled) != stark_inputs.stablecoin_enabled
        || public_inputs.stablecoin.asset_id != stark_inputs.stablecoin_asset_id
        || public_inputs.stablecoin.policy_version != stark_inputs.stablecoin_policy_version
        || !signed_magnitude_matches(
            public_inputs.stablecoin.issuance_delta,
            stark_inputs.stablecoin_issuance_sign,
            stark_inputs.stablecoin_issuance_magnitude,
        )
        || public_inputs.stablecoin.policy_hash != stark_inputs.stablecoin_policy_hash
        || public_inputs.stablecoin.oracle_commitment != stark_inputs.stablecoin_oracle_commitment
        || public_inputs.stablecoin.attestation_commitment
            != stark_inputs.stablecoin_attestation_commitment
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "public stablecoin binding does not match serialized public inputs",
        ));
    }

    let input_flags = stark_inputs
        .input_flags
        .iter()
        .map(|flag| Goldilocks::from_u64(*flag as u64))
        .collect();
    let output_flags = stark_inputs
        .output_flags
        .iter()
        .map(|flag| Goldilocks::from_u64(*flag as u64))
        .collect();

    let nullifiers = public_inputs
        .nullifiers
        .iter()
        .map(|nf| {
            bytes48_to_felts(nf).ok_or(TransactionCircuitError::ConstraintViolation(
                "invalid PQ nullifier encoding",
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let commitments = public_inputs
        .commitments
        .iter()
        .map(|cm| {
            bytes48_to_felts(cm).ok_or(TransactionCircuitError::ConstraintViolation(
                "invalid PQ commitment encoding",
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ciphertext_hashes = public_inputs
        .ciphertext_hashes
        .iter()
        .map(|ct| {
            bytes48_to_felts(ct).ok_or(TransactionCircuitError::ConstraintViolation(
                "invalid ciphertext hash encoding",
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let merkle_root = bytes48_to_felts(&stark_inputs.merkle_root).ok_or(
        TransactionCircuitError::ConstraintViolation("invalid PQ merkle root encoding"),
    )?;
    let stablecoin_policy_hash = bytes48_to_felts(&stark_inputs.stablecoin_policy_hash).ok_or(
        TransactionCircuitError::ConstraintViolation("invalid stablecoin policy hash encoding"),
    )?;
    let stablecoin_oracle_commitment = bytes48_to_felts(&stark_inputs.stablecoin_oracle_commitment)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "invalid stablecoin oracle commitment encoding",
        ))?;
    let stablecoin_attestation_commitment = bytes48_to_felts(
        &stark_inputs.stablecoin_attestation_commitment,
    )
    .ok_or(TransactionCircuitError::ConstraintViolation(
        "invalid stablecoin attestation commitment encoding",
    ))?;
    let balance_slot_asset_ids = if stark_inputs.balance_slot_asset_ids.is_empty() {
        public_inputs
            .balance_slots
            .iter()
            .map(|slot| slot.asset_id)
            .collect()
    } else {
        stark_inputs.balance_slot_asset_ids.clone()
    };
    if balance_slot_asset_ids.len() != BALANCE_SLOTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "invalid balance slot asset count",
        ));
    }
    let balance_slot_assets = [
        Goldilocks::from_u64(balance_slot_asset_ids[0]),
        Goldilocks::from_u64(balance_slot_asset_ids[1]),
        Goldilocks::from_u64(balance_slot_asset_ids[2]),
        Goldilocks::from_u64(balance_slot_asset_ids[3]),
    ];

    Ok(TransactionPublicInputsP3 {
        input_flags,
        output_flags,
        nullifiers,
        commitments,
        ciphertext_hashes,
        fee: Goldilocks::from_u64(stark_inputs.fee),
        value_balance_sign: Goldilocks::from_u64(stark_inputs.value_balance_sign as u64),
        value_balance_magnitude: Goldilocks::from_u64(stark_inputs.value_balance_magnitude),
        merkle_root,
        balance_slot_assets,
        stablecoin_enabled: Goldilocks::from_u64(stark_inputs.stablecoin_enabled as u64),
        stablecoin_asset: Goldilocks::from_u64(stark_inputs.stablecoin_asset_id),
        stablecoin_policy_version: Goldilocks::from_u64(
            stark_inputs.stablecoin_policy_version as u64,
        ),
        stablecoin_issuance_sign: Goldilocks::from_u64(
            stark_inputs.stablecoin_issuance_sign as u64,
        ),
        stablecoin_issuance_magnitude: Goldilocks::from_u64(
            stark_inputs.stablecoin_issuance_magnitude,
        ),
        stablecoin_policy_hash,
        stablecoin_oracle_commitment,
        stablecoin_attestation_commitment,
    })
}

pub(crate) fn serialize_p3_inputs(pub_inputs: &TransactionPublicInputsP3) -> SerializedStarkInputs {
    let input_flags = pub_inputs
        .input_flags
        .iter()
        .map(|flag| flag.as_canonical_u64() as u8)
        .collect();
    let output_flags = pub_inputs
        .output_flags
        .iter()
        .map(|flag| flag.as_canonical_u64() as u8)
        .collect();

    SerializedStarkInputs {
        input_flags,
        output_flags,
        fee: pub_inputs.fee.as_canonical_u64(),
        value_balance_sign: pub_inputs.value_balance_sign.as_canonical_u64() as u8,
        value_balance_magnitude: pub_inputs.value_balance_magnitude.as_canonical_u64(),
        merkle_root: hash_to_bytes48(&pub_inputs.merkle_root),
        balance_slot_asset_ids: pub_inputs
            .balance_slot_assets
            .iter()
            .map(|asset| asset.as_canonical_u64())
            .collect(),
        stablecoin_enabled: pub_inputs.stablecoin_enabled.as_canonical_u64() as u8,
        stablecoin_asset_id: pub_inputs.stablecoin_asset.as_canonical_u64(),
        stablecoin_policy_version: pub_inputs.stablecoin_policy_version.as_canonical_u64() as u32,
        stablecoin_issuance_sign: pub_inputs.stablecoin_issuance_sign.as_canonical_u64() as u8,
        stablecoin_issuance_magnitude: pub_inputs.stablecoin_issuance_magnitude.as_canonical_u64(),
        stablecoin_policy_hash: hash_to_bytes48(&pub_inputs.stablecoin_policy_hash),
        stablecoin_oracle_commitment: hash_to_bytes48(&pub_inputs.stablecoin_oracle_commitment),
        stablecoin_attestation_commitment: hash_to_bytes48(
            &pub_inputs.stablecoin_attestation_commitment,
        ),
    }
}

fn hash_to_bytes48(hash: &[Goldilocks; 6]) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (idx, limb) in hash.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&limb.as_canonical_u64().to_be_bytes());
    }
    out
}

fn default_bytes48() -> Commitment {
    [0u8; 48]
}

/// Verify that balance_slots match public_inputs.balance_slots
pub(crate) fn verify_balance_slots(
    proof: &TransactionProof,
) -> Result<(), TransactionCircuitError> {
    use crate::constants::NATIVE_ASSET_ID;
    use crate::public_inputs::BalanceSlot;

    if proof.public_inputs.balance_slots.len() != proof.balance_slots.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "balance slot count mismatch",
        ));
    }

    let mut stablecoin_slot_seen = false;
    for (idx, expected) in proof.public_inputs.balance_slots.iter().enumerate() {
        let actual = proof
            .balance_slots
            .get(idx)
            .cloned()
            .unwrap_or(BalanceSlot {
                asset_id: u64::MAX,
                delta: 0,
            });

        if actual.asset_id != expected.asset_id || actual.delta != expected.delta {
            return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
        }

        // For native asset, verify delta equals fee
        if expected.asset_id == NATIVE_ASSET_ID {
            let expected_native =
                proof.public_inputs.native_fee as i128 - proof.public_inputs.value_balance;
            if expected.delta != expected_native {
                return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
            }
        } else if proof.public_inputs.stablecoin.enabled
            && expected.asset_id == proof.public_inputs.stablecoin.asset_id
        {
            stablecoin_slot_seen = true;
            if expected.delta != proof.public_inputs.stablecoin.issuance_delta {
                return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
            }
        } else if expected.delta != 0 {
            // Non-native assets must balance to zero
            return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
        }
    }

    if proof.public_inputs.stablecoin.enabled && !stablecoin_slot_seen {
        return Err(TransactionCircuitError::BalanceMismatch(
            proof.public_inputs.stablecoin.asset_id,
        ));
    }

    let native_delta = proof
        .public_inputs
        .balance_slots
        .iter()
        .find(|slot| slot.asset_id == NATIVE_ASSET_ID)
        .map(|slot| slot.delta)
        .unwrap_or(0);
    let expected_balance_tag =
        balance_commitment_bytes(native_delta, &proof.public_inputs.balance_slots).map_err(
            |err| TransactionCircuitError::BalanceDeltaOutOfRange(err.asset_id, err.magnitude),
        )?;
    if proof.public_inputs.balance_tag != expected_balance_tag {
        return Err(TransactionCircuitError::ConstraintViolation(
            "balance tag does not match balance slots",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_inputs::{BalanceSlot, StablecoinPolicyBinding, TransactionPublicInputs};
    use crate::SmallwoodCandidateProof;
    use protocol_versioning::LEGACY_PLONKY3_FRI_VERSION_BINDING;
    use std::collections::BTreeSet;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPublicInputVectorFile {
        schema_version: u32,
        public_input_shape_cases: Vec<LeanPublicInputShapeCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPublicInputShapeCase {
        name: String,
        input_flags: Vec<u64>,
        output_flags: Vec<u64>,
        nullifiers: Vec<u64>,
        commitments: Vec<u64>,
        ciphertext_hashes: Vec<u64>,
        balance_slot_assets: Vec<u64>,
        value_balance_sign: u64,
        stablecoin_enabled: u64,
        stablecoin_asset: u64,
        stablecoin_issuance_sign: u64,
        expected_valid: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPublicInputBindingVectorFile {
        schema_version: u32,
        public_input_binding_cases: Vec<LeanPublicInputBindingCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPublicInputBindingCase {
        name: String,
        public_merkle_root: u64,
        serialized_merkle_root: u64,
        public_fee: u64,
        serialized_fee: u64,
        public_value_balance: i64,
        serialized_value_balance_sign: u8,
        serialized_value_balance_magnitude: u64,
        public_balance_slot_assets: Vec<u64>,
        serialized_balance_slot_assets: Vec<u64>,
        public_stablecoin_enabled: u8,
        serialized_stablecoin_enabled: u8,
        public_stablecoin_asset: u64,
        serialized_stablecoin_asset: u64,
        public_stablecoin_policy_version: u32,
        serialized_stablecoin_policy_version: u32,
        public_stablecoin_issuance_delta: i64,
        serialized_stablecoin_issuance_sign: u8,
        serialized_stablecoin_issuance_magnitude: u64,
        public_stablecoin_policy_hash: u64,
        serialized_stablecoin_policy_hash: u64,
        public_stablecoin_oracle_commitment: u64,
        serialized_stablecoin_oracle_commitment: u64,
        public_stablecoin_attestation_commitment: u64,
        serialized_stablecoin_attestation_commitment: u64,
        expected_bound_balance_slot_assets: Vec<u64>,
        expected_valid: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanProofWrapperAdmissionVectorFile {
        schema_version: u32,
        proof_wrapper_admission_cases: Vec<LeanProofWrapperAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanProofWrapperAdmissionCase {
        name: String,
        exact_consumption: bool,
        canonical_reencode: bool,
        backend_supported: bool,
        proof_bytes_present: bool,
        serialized_public_inputs_present: bool,
        public_inputs_valid: bool,
        nullifier_vector_agrees: bool,
        commitment_vector_agrees: bool,
        balance_slots_agree: bool,
        verifier_accepts: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    fn dummy_serialized_inputs() -> SerializedStarkInputs {
        SerializedStarkInputs {
            input_flags: vec![0; MAX_INPUTS],
            output_flags: vec![0; MAX_OUTPUTS],
            fee: 0,
            value_balance_sign: 0,
            value_balance_magnitude: 0,
            merkle_root: [0u8; 48],
            balance_slot_asset_ids: vec![0, u64::MAX, u64::MAX, u64::MAX],
            stablecoin_enabled: 0,
            stablecoin_asset_id: 0,
            stablecoin_policy_version: 0,
            stablecoin_issuance_sign: 0,
            stablecoin_issuance_magnitude: 0,
            stablecoin_policy_hash: [0u8; 48],
            stablecoin_oracle_commitment: [0u8; 48],
            stablecoin_attestation_commitment: [0u8; 48],
        }
    }

    fn dummy_proof() -> TransactionProof {
        let mut public_inputs = TransactionPublicInputs::default();
        public_inputs.circuit_version = LEGACY_PLONKY3_FRI_VERSION_BINDING.circuit;
        public_inputs.crypto_suite = LEGACY_PLONKY3_FRI_VERSION_BINDING.crypto;
        TransactionProof {
            nullifiers: public_inputs.nullifiers.clone(),
            commitments: public_inputs.commitments.clone(),
            balance_slots: public_inputs.balance_slots.clone(),
            public_inputs,
            backend: TxProofBackend::Plonky3Fri,
            stark_proof: vec![1, 2, 3, 4],
            stark_public_inputs: Some(dummy_serialized_inputs()),
        }
    }

    fn wrapper_admissible_dummy_proof() -> TransactionProof {
        let mut public_inputs = TransactionPublicInputs::default();
        public_inputs.nullifiers = vec![bytes48(11), [0u8; 48]];
        public_inputs.commitments = vec![bytes48(22), [0u8; 48]];
        public_inputs.ciphertext_hashes = vec![bytes48(33), [0u8; 48]];
        public_inputs.balance_tag =
            balance_commitment_bytes(0, &public_inputs.balance_slots).expect("balance tag");
        public_inputs.circuit_version = LEGACY_PLONKY3_FRI_VERSION_BINDING.circuit;
        public_inputs.crypto_suite = LEGACY_PLONKY3_FRI_VERSION_BINDING.crypto;

        let mut serialized = dummy_serialized_inputs();
        serialized.input_flags = vec![1, 0];
        serialized.output_flags = vec![1, 0];

        TransactionProof {
            nullifiers: public_inputs.nullifiers.clone(),
            commitments: public_inputs.commitments.clone(),
            balance_slots: public_inputs.balance_slots.clone(),
            public_inputs,
            backend: TxProofBackend::Plonky3Fri,
            stark_proof: vec![1, 2, 3, 4],
            stark_public_inputs: Some(serialized),
        }
    }

    #[test]
    fn lean_generated_public_input_shape_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_PUBLIC_INPUT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_PUBLIC_INPUT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean public input vectors");
        let vectors: LeanPublicInputVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean public input vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.public_input_shape_cases.is_empty(),
            "Lean public input shape cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.public_input_shape_cases {
            assert!(names.insert(case.name.clone()));
            let actual = public_inputs_p3_from_lean_case(case).validate().is_ok();
            assert_eq!(
                actual, case.expected_valid,
                "{} production public input shape validation drifted from Lean spec",
                case.name
            );
        }
    }

    fn public_inputs_p3_from_lean_case(
        case: &LeanPublicInputShapeCase,
    ) -> TransactionPublicInputsP3 {
        assert_eq!(
            case.balance_slot_assets.len(),
            BALANCE_SLOTS,
            "Lean balance slot vector is fixed-width for Rust P3"
        );
        TransactionPublicInputsP3 {
            input_flags: case.input_flags.iter().copied().map(felt).collect(),
            output_flags: case.output_flags.iter().copied().map(felt).collect(),
            nullifiers: case.nullifiers.iter().copied().map(hash6).collect(),
            commitments: case.commitments.iter().copied().map(hash6).collect(),
            ciphertext_hashes: case.ciphertext_hashes.iter().copied().map(hash6).collect(),
            fee: Goldilocks::ZERO,
            value_balance_sign: felt(case.value_balance_sign),
            value_balance_magnitude: Goldilocks::ZERO,
            merkle_root: hash6(0),
            balance_slot_assets: [
                felt(case.balance_slot_assets[0]),
                felt(case.balance_slot_assets[1]),
                felt(case.balance_slot_assets[2]),
                felt(case.balance_slot_assets[3]),
            ],
            stablecoin_enabled: felt(case.stablecoin_enabled),
            stablecoin_asset: felt(case.stablecoin_asset),
            stablecoin_policy_version: Goldilocks::ZERO,
            stablecoin_issuance_sign: felt(case.stablecoin_issuance_sign),
            stablecoin_issuance_magnitude: Goldilocks::ZERO,
            stablecoin_policy_hash: hash6(0),
            stablecoin_oracle_commitment: hash6(0),
            stablecoin_attestation_commitment: hash6(0),
        }
    }

    fn felt(value: u64) -> Goldilocks {
        Goldilocks::from_u64(value)
    }

    fn hash6(value: u64) -> [Goldilocks; 6] {
        let mut out = [Goldilocks::ZERO; 6];
        out[0] = felt(value);
        out
    }

    #[test]
    fn lean_generated_public_input_binding_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_PUBLIC_INPUT_BINDING_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_PUBLIC_INPUT_BINDING_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean public input binding vectors");
        let vectors: LeanPublicInputBindingVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean public input binding vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.public_input_binding_cases.is_empty(),
            "Lean public input binding cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.public_input_binding_cases {
            assert!(names.insert(case.name.clone()));
            let public_inputs = public_inputs_from_binding_case(case);
            let serialized = serialized_inputs_from_binding_case(case);
            let actual = transaction_public_inputs_p3_from_parts(&public_inputs, &serialized);
            assert_eq!(
                actual.is_ok(),
                case.expected_valid,
                "{} production public/serialized binding drifted from Lean spec: {actual:?}",
                case.name
            );
            if case.expected_valid {
                let p3 = actual.expect("valid binding produces P3 inputs");
                p3.validate()
                    .expect("valid binding case is verifier-admissible");
                assert_eq!(
                    canonical_felts(&p3.balance_slot_assets),
                    case.expected_bound_balance_slot_assets,
                    "{} bound balance slot assets changed",
                    case.name
                );
                assert_eq!(p3.merkle_root, hash6(case.serialized_merkle_root));
                assert_eq!(p3.fee.as_canonical_u64(), case.serialized_fee);
                assert_eq!(
                    p3.value_balance_sign.as_canonical_u64(),
                    u64::from(case.serialized_value_balance_sign)
                );
                assert_eq!(
                    p3.value_balance_magnitude.as_canonical_u64(),
                    case.serialized_value_balance_magnitude
                );
                assert_eq!(
                    p3.stablecoin_enabled.as_canonical_u64(),
                    u64::from(case.serialized_stablecoin_enabled)
                );
                assert_eq!(
                    p3.stablecoin_asset.as_canonical_u64(),
                    case.serialized_stablecoin_asset
                );
                assert_eq!(
                    p3.stablecoin_policy_version.as_canonical_u64(),
                    u64::from(case.serialized_stablecoin_policy_version)
                );
                assert_eq!(
                    p3.stablecoin_issuance_sign.as_canonical_u64(),
                    u64::from(case.serialized_stablecoin_issuance_sign)
                );
                assert_eq!(
                    p3.stablecoin_issuance_magnitude.as_canonical_u64(),
                    case.serialized_stablecoin_issuance_magnitude
                );
                assert_eq!(
                    p3.stablecoin_policy_hash,
                    hash6(case.serialized_stablecoin_policy_hash)
                );
                assert_eq!(
                    p3.stablecoin_oracle_commitment,
                    hash6(case.serialized_stablecoin_oracle_commitment)
                );
                assert_eq!(
                    p3.stablecoin_attestation_commitment,
                    hash6(case.serialized_stablecoin_attestation_commitment)
                );
            }
        }
    }

    #[test]
    fn lean_generated_proof_wrapper_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_PROOF_WRAPPER_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_PROOF_WRAPPER_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean proof-wrapper admission vectors");
        let vectors: LeanProofWrapperAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean proof-wrapper vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.proof_wrapper_admission_cases.is_empty(),
            "Lean proof-wrapper admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.proof_wrapper_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_proof_wrapper_admission_case(case);
        }
    }

    fn verify_lean_proof_wrapper_admission_case(case: &LeanProofWrapperAdmissionCase) {
        let input = TransactionProofWrapperAdmissionInput {
            exact_consumption: case.exact_consumption,
            canonical_reencode: case.canonical_reencode,
            backend_supported: case.backend_supported,
            proof_bytes_present: case.proof_bytes_present,
            serialized_public_inputs_present: case.serialized_public_inputs_present,
            public_inputs_valid: case.public_inputs_valid,
            nullifier_vector_agrees: case.nullifier_vector_agrees,
            commitment_vector_agrees: case.commitment_vector_agrees,
            balance_slots_agree: case.balance_slots_agree,
            verifier_accepts: case.verifier_accepts,
        };
        let result = evaluate_transaction_proof_wrapper_admission(input);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} proof-wrapper admission validity drifted from Lean spec",
            case.name
        );
        let actual_rejection = result.err().map(|rejection| rejection.label().to_string());
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} proof-wrapper admission rejection label drifted from Lean spec",
            case.name
        );
    }

    fn public_inputs_from_binding_case(
        case: &LeanPublicInputBindingCase,
    ) -> TransactionPublicInputs {
        TransactionPublicInputs {
            merkle_root: bytes48(case.public_merkle_root),
            nullifiers: vec![bytes48(11), bytes48(0)],
            commitments: vec![bytes48(22), bytes48(0)],
            ciphertext_hashes: vec![bytes48(33), bytes48(0)],
            balance_slots: case
                .public_balance_slot_assets
                .iter()
                .copied()
                .map(|asset_id| BalanceSlot { asset_id, delta: 0 })
                .collect(),
            native_fee: case.public_fee,
            value_balance: i128::from(case.public_value_balance),
            stablecoin: StablecoinPolicyBinding {
                enabled: case.public_stablecoin_enabled != 0,
                asset_id: case.public_stablecoin_asset,
                policy_hash: bytes48(case.public_stablecoin_policy_hash),
                oracle_commitment: bytes48(case.public_stablecoin_oracle_commitment),
                attestation_commitment: bytes48(case.public_stablecoin_attestation_commitment),
                issuance_delta: i128::from(case.public_stablecoin_issuance_delta),
                policy_version: case.public_stablecoin_policy_version,
            },
            balance_tag: [0u8; 48],
            circuit_version: LEGACY_PLONKY3_FRI_VERSION_BINDING.circuit,
            crypto_suite: LEGACY_PLONKY3_FRI_VERSION_BINDING.crypto,
        }
    }

    fn serialized_inputs_from_binding_case(
        case: &LeanPublicInputBindingCase,
    ) -> SerializedStarkInputs {
        SerializedStarkInputs {
            input_flags: vec![1, 0],
            output_flags: vec![1, 0],
            fee: case.serialized_fee,
            value_balance_sign: case.serialized_value_balance_sign,
            value_balance_magnitude: case.serialized_value_balance_magnitude,
            merkle_root: bytes48(case.serialized_merkle_root),
            balance_slot_asset_ids: case.serialized_balance_slot_assets.clone(),
            stablecoin_enabled: case.serialized_stablecoin_enabled,
            stablecoin_asset_id: case.serialized_stablecoin_asset,
            stablecoin_policy_version: case.serialized_stablecoin_policy_version,
            stablecoin_issuance_sign: case.serialized_stablecoin_issuance_sign,
            stablecoin_issuance_magnitude: case.serialized_stablecoin_issuance_magnitude,
            stablecoin_policy_hash: bytes48(case.serialized_stablecoin_policy_hash),
            stablecoin_oracle_commitment: bytes48(case.serialized_stablecoin_oracle_commitment),
            stablecoin_attestation_commitment: bytes48(
                case.serialized_stablecoin_attestation_commitment,
            ),
        }
    }

    fn canonical_felts(values: &[Goldilocks]) -> Vec<u64> {
        values.iter().map(Goldilocks::as_canonical_u64).collect()
    }

    fn bytes48(value: u64) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[0..8].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn dummy_smallwood_proof(arithmetization: SmallwoodArithmetization) -> TransactionProof {
        let public_inputs = TransactionPublicInputs::default();
        let stark_proof = bincode::serialize(&SmallwoodCandidateProof {
            arithmetization,
            ark_proof: vec![1, 2, 3, 4],
            auxiliary_witness_words: Vec::new(),
        })
        .expect("encode dummy smallwood proof");
        TransactionProof {
            nullifiers: public_inputs.nullifiers.clone(),
            commitments: public_inputs.commitments.clone(),
            balance_slots: public_inputs.balance_slots.clone(),
            public_inputs,
            backend: TxProofBackend::SmallwoodCandidate,
            stark_proof,
            stark_public_inputs: Some(dummy_serialized_inputs()),
        }
    }

    fn wrapper_admissible_dummy_smallwood_proof() -> TransactionProof {
        let mut proof = wrapper_admissible_dummy_proof();
        proof.backend = TxProofBackend::SmallwoodCandidate;
        proof.stark_proof = bincode::serialize(&SmallwoodCandidateProof {
            arithmetization: SmallwoodArithmetization::DirectPacked64V1,
            ark_proof: vec![1, 2, 3, 4],
            auxiliary_witness_words: Vec::new(),
        })
        .expect("encode dummy smallwood proof");
        proof
    }

    #[test]
    fn verifier_profile_digest_matches_version_helper() {
        let proof = dummy_proof();
        assert_eq!(
            transaction_verifier_profile_digest(&proof).expect("profile digest"),
            transaction_verifier_profile_digest_for_version(proof.version_binding())
        );
    }

    #[test]
    fn smallwood_verifier_profile_digest_tracks_actual_arithmetization() {
        let proof = dummy_smallwood_proof(SmallwoodArithmetization::DirectPacked64V1);
        let direct = transaction_verifier_profile_digest(&proof).expect("profile digest");
        let bridge = transaction_verifier_profile_digest_for_version(proof.version_binding());
        assert_ne!(
            direct, bridge,
            "proof-specific verifier profile digest must bind the actual Smallwood arithmetization"
        );
        assert_eq!(
            direct,
            transaction_verifier_profile_digest_for_version_and_backend(
                proof.version_binding(),
                proof.backend,
                Some(SmallwoodArithmetization::DirectPacked64V1),
            )
        );
    }

    #[test]
    fn malformed_smallwood_wrapper_fails_closed_for_profile_digest() {
        let mut proof = dummy_smallwood_proof(SmallwoodArithmetization::Bridge64V1);
        proof.stark_proof = vec![0xff, 0x00, 0xaa];
        let err = transaction_verifier_profile_digest(&proof).expect_err("malformed wrapper fails");
        assert!(
            err.to_string()
                .contains("failed to decode smallwood candidate proof wrapper"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn trailing_bytes_in_smallwood_wrapper_fail_closed_for_profile_digest() {
        let mut proof = dummy_smallwood_proof(SmallwoodArithmetization::Bridge64V1);
        proof
            .stark_proof
            .extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let err =
            transaction_verifier_profile_digest(&proof).expect_err("trailing wrapper bytes fail");
        assert!(
            err.to_string()
                .contains("smallwood candidate proof wrapper has trailing bytes"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn decode_transaction_proof_bytes_exact_rejects_trailing_bytes() {
        let encoded = bincode::serialize(&dummy_proof()).expect("encode proof");
        let mut malformed = encoded.clone();
        malformed.extend_from_slice(&[0xaa, 0xbb]);
        let err = decode_transaction_proof_bytes_exact(&malformed)
            .expect_err("trailing bytes must be rejected");
        assert!(
            err.to_string()
                .contains("transaction proof wrapper has trailing bytes"),
            "unexpected error: {err:?}"
        );
        let decoded = decode_transaction_proof_bytes_exact(&encoded).expect("exact decode");
        assert_eq!(decoded, dummy_proof());
    }

    #[test]
    fn wrapper_public_inputs_reject_presence_and_balance_failures() {
        let mut proof = wrapper_admissible_dummy_proof();
        transaction_proof_wrapper_public_inputs_p3(&proof)
            .expect("admissible dummy wrapper reaches verifier input construction");

        proof.stark_proof.clear();
        let err =
            transaction_proof_wrapper_public_inputs_p3(&proof).expect_err("missing proof rejects");
        assert!(err.to_string().contains("missing proof bytes"));

        let mut proof = wrapper_admissible_dummy_proof();
        proof.stark_public_inputs = None;
        let err = transaction_proof_wrapper_public_inputs_p3(&proof)
            .expect_err("missing serialized inputs reject");
        assert!(err.to_string().contains("missing serialized public inputs"));

        let mut proof = wrapper_admissible_dummy_proof();
        proof.backend = TxProofBackend::SmallwoodCandidate;
        let err = transaction_proof_wrapper_public_inputs_p3(&proof)
            .expect_err("unsupported backend rejects");
        assert!(err.to_string().contains("unsupported backend"));

        let mut proof = wrapper_admissible_dummy_proof();
        proof
            .stark_public_inputs
            .as_mut()
            .expect("serialized inputs")
            .value_balance_sign = 2;
        let err = transaction_proof_wrapper_public_inputs_p3(&proof)
            .expect_err("invalid serialized public inputs reject");
        assert!(err
            .to_string()
            .contains("public value balance does not match serialized public inputs"));

        let mut proof = wrapper_admissible_dummy_proof();
        proof.nullifiers[0] = bytes48(0x4e46);
        let err = transaction_proof_wrapper_public_inputs_p3(&proof)
            .expect_err("wrapper nullifier vector drift rejects");
        assert!(
            err.to_string().contains("nullifier vector mismatch"),
            "unexpected error: {err:?}"
        );

        let mut proof = wrapper_admissible_dummy_proof();
        proof.commitments[0] = bytes48(0x434d);
        let err = transaction_proof_wrapper_public_inputs_p3(&proof)
            .expect_err("wrapper commitment vector drift rejects");
        assert!(
            err.to_string().contains("commitment vector mismatch"),
            "unexpected error: {err:?}"
        );

        let mut proof = wrapper_admissible_dummy_proof();
        proof.balance_slots[0].delta = 1;
        let err = transaction_proof_wrapper_public_inputs_p3(&proof)
            .expect_err("wrapper balance slot drift rejects");
        assert!(err.to_string().contains("balance delta"));
    }

    #[test]
    fn smallwood_verification_uses_wrapper_admission() {
        let verifying_key = VerifyingKey {
            max_inputs: MAX_INPUTS,
            max_outputs: MAX_OUTPUTS,
            balance_slots: BALANCE_SLOTS,
        };

        let mut proof = wrapper_admissible_dummy_smallwood_proof();
        proof.stark_public_inputs = None;
        let err = verify(&proof, &verifying_key)
            .expect_err("smallwood wrapper missing serialized inputs must reject");
        assert!(
            err.to_string().contains("missing serialized public inputs"),
            "unexpected error: {err:?}"
        );

        let mut proof = wrapper_admissible_dummy_smallwood_proof();
        proof.stark_proof.clear();
        let err = verify(&proof, &verifying_key)
            .expect_err("smallwood wrapper missing proof must reject");
        assert!(
            err.to_string().contains("missing proof bytes"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn statement_hash_changes_when_fee_changes() {
        let proof = dummy_proof();
        let mut changed = proof.clone();
        changed.public_inputs.native_fee = 9;
        assert_ne!(
            transaction_statement_hash(&proof),
            transaction_statement_hash(&changed)
        );
    }

    #[test]
    fn proof_digest_binds_backend() {
        let proof = dummy_proof();
        let mut changed = proof.clone();
        changed.backend = TxProofBackend::SmallwoodCandidate;
        assert_ne!(
            transaction_proof_digest(&proof),
            transaction_proof_digest(&changed)
        );
    }

    #[test]
    fn public_inputs_digest_requires_serialized_inputs() {
        let mut proof = dummy_proof();
        proof.stark_public_inputs = None;
        let error = transaction_public_inputs_digest(&proof).expect_err("missing inputs fail");
        assert!(error.to_string().contains("missing STARK public inputs"));
    }

    #[test]
    fn public_inputs_from_parts_normalizes_balance_slot_padding_sentinel() {
        let public_inputs = TransactionPublicInputs::default();
        let p3_inputs =
            transaction_public_inputs_p3_from_parts(&public_inputs, &dummy_serialized_inputs())
                .expect("balance slot padding sentinel should normalize through the field");
        assert_eq!(p3_inputs.balance_slot_assets[0].as_canonical_u64(), 0);
    }
}
