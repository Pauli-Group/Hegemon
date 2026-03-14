use blake3::Hasher as Blake3Hasher;
use p3_field::PrimeField64;
use serde::{Deserialize, Serialize};
use transaction_circuit::{
    constants::{MAX_INPUTS, MAX_OUTPUTS},
    hashing_pq::{bytes48_to_felts, Commitment},
    p3_verifier::verify_transaction_proof_bytes_p3,
    proof::{stark_public_inputs_p3, TransactionProof},
    public_inputs::TransactionPublicInputs,
};

#[derive(Debug, thiserror::Error)]
pub enum ProofBatchError {
    #[error("proof batch requires at least one transaction proof")]
    EmptyBatch,
    #[error("proof batch batch_size mismatch: expected {expected}, got {actual}")]
    BatchSizeMismatch { expected: usize, actual: usize },
    #[error("proof batch statement hash count mismatch: expected {expected}, got {actual}")]
    StatementHashCountMismatch { expected: usize, actual: usize },
    #[error("proof batch nullifier count mismatch: expected {expected}, got {actual}")]
    NullifierCountMismatch { expected: usize, actual: usize },
    #[error("proof batch commitment count mismatch: expected {expected}, got {actual}")]
    CommitmentCountMismatch { expected: usize, actual: usize },
    #[error("proof batch total fee mismatch: expected {expected}, got {actual}")]
    TotalFeeMismatch { expected: u64, actual: u64 },
    #[error("proof batch proof bytes could not be decoded: {0}")]
    ProofDecode(String),
    #[error("proof batch proof bytes could not be encoded: {0}")]
    ProofEncode(String),
    #[error("proof batch public values are malformed: {0}")]
    PublicValues(String),
    #[error("proof batch entry public inputs do not match proof bytes")]
    EntryPublicInputsMismatch,
    #[error("proof batch contains mixed transaction circuit versions")]
    MixedCircuitVersions,
    #[error("proof batch transaction proof verification failed: {0}")]
    TransactionProofVerification(String),
    #[error("proof batch contains non-canonical 48-byte value")]
    NonCanonicalBytes48,
    #[error("proof batch total fee overflowed u64")]
    TotalFeeOverflow,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofBatchWitnessEntry {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: TransactionPublicInputs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofBatchPublicInputs {
    pub batch_size: u32,
    pub statement_hashes: Vec<Commitment>,
    pub nullifiers: Vec<Commitment>,
    pub commitments: Vec<Commitment>,
    pub total_fee: u64,
    pub circuit_version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ProofBatchProof {
    entries: Vec<ProofBatchWitnessEntry>,
}

impl ProofBatchPublicInputs {
    pub fn validate(&self) -> Result<(), ProofBatchError> {
        let batch_size = self.batch_size as usize;
        if batch_size == 0 {
            return Err(ProofBatchError::EmptyBatch);
        }
        if self.statement_hashes.len() != batch_size {
            return Err(ProofBatchError::StatementHashCountMismatch {
                expected: batch_size,
                actual: self.statement_hashes.len(),
            });
        }
        let expected_nullifiers = batch_size.saturating_mul(MAX_INPUTS);
        if self.nullifiers.len() != expected_nullifiers {
            return Err(ProofBatchError::NullifierCountMismatch {
                expected: expected_nullifiers,
                actual: self.nullifiers.len(),
            });
        }
        let expected_commitments = batch_size.saturating_mul(MAX_OUTPUTS);
        if self.commitments.len() != expected_commitments {
            return Err(ProofBatchError::CommitmentCountMismatch {
                expected: expected_commitments,
                actual: self.commitments.len(),
            });
        }
        Ok(())
    }

    pub fn to_values(&self) -> Result<Vec<u64>, ProofBatchError> {
        self.validate()?;

        let mut values = Vec::with_capacity(
            3 + (self.statement_hashes.len() * 6)
                + (self.nullifiers.len() * 6)
                + (self.commitments.len() * 6),
        );
        values.push(self.batch_size as u64);
        values.push(self.total_fee);
        values.push(self.circuit_version as u64);
        encode_commitments(&self.statement_hashes, &mut values)?;
        encode_commitments(&self.nullifiers, &mut values)?;
        encode_commitments(&self.commitments, &mut values)?;
        Ok(values)
    }

    pub fn try_from_values(values: &[u64]) -> Result<Self, ProofBatchError> {
        if values.len() < 3 {
            return Err(ProofBatchError::PublicValues(
                "missing fixed proof-batch header".to_string(),
            ));
        }
        let batch_size = usize::try_from(values[0]).map_err(|_| {
            ProofBatchError::PublicValues("batch_size does not fit usize".to_string())
        })?;
        if batch_size == 0 {
            return Err(ProofBatchError::EmptyBatch);
        }
        let total_fee = values[1];
        let circuit_version = u32::try_from(values[2]).map_err(|_| {
            ProofBatchError::PublicValues("circuit_version does not fit u32".to_string())
        })?;
        let mut cursor = 3usize;
        let statement_hashes = decode_commitments(values, &mut cursor, batch_size)?;
        let nullifiers = decode_commitments(values, &mut cursor, batch_size * MAX_INPUTS)?;
        let commitments = decode_commitments(values, &mut cursor, batch_size * MAX_OUTPUTS)?;
        if cursor != values.len() {
            return Err(ProofBatchError::PublicValues(format!(
                "unexpected trailing proof-batch public values: consumed {cursor}, total {}",
                values.len()
            )));
        }
        let public_inputs = Self {
            batch_size: batch_size as u32,
            statement_hashes,
            nullifiers,
            commitments,
            total_fee,
            circuit_version,
        };
        public_inputs.validate()?;
        Ok(public_inputs)
    }
}

pub fn witness_entries_from_transaction_proofs(
    proofs: &[TransactionProof],
) -> Result<Vec<ProofBatchWitnessEntry>, ProofBatchError> {
    if proofs.is_empty() {
        return Err(ProofBatchError::EmptyBatch);
    }
    proofs
        .iter()
        .map(|proof| {
            let proof_bytes = bincode::serialize(proof)
                .map_err(|err| ProofBatchError::ProofEncode(err.to_string()))?;
            Ok(ProofBatchWitnessEntry {
                proof_bytes,
                public_inputs: proof.public_inputs.clone(),
            })
        })
        .collect()
}

pub fn prove_transaction_proof_batch(
    proofs: &[TransactionProof],
) -> Result<(Vec<u8>, ProofBatchPublicInputs), ProofBatchError> {
    let entries = witness_entries_from_transaction_proofs(proofs)?;
    prove_proof_batch(&entries)
}

pub fn prove_proof_batch(
    entries: &[ProofBatchWitnessEntry],
) -> Result<(Vec<u8>, ProofBatchPublicInputs), ProofBatchError> {
    if entries.is_empty() {
        return Err(ProofBatchError::EmptyBatch);
    }
    let public_inputs = summarize_entries(entries)?;
    let proof = ProofBatchProof {
        entries: entries.to_vec(),
    };
    let proof_bytes =
        bincode::serialize(&proof).map_err(|err| ProofBatchError::ProofEncode(err.to_string()))?;
    Ok((proof_bytes, public_inputs))
}

pub fn verify_proof_batch(
    proof_bytes: &[u8],
    public_inputs: &ProofBatchPublicInputs,
) -> Result<(), ProofBatchError> {
    public_inputs.validate()?;
    let proof: ProofBatchProof = bincode::deserialize(proof_bytes)
        .map_err(|err| ProofBatchError::ProofDecode(err.to_string()))?;
    let derived = summarize_entries(&proof.entries)?;
    if derived.batch_size as usize != proof.entries.len() {
        return Err(ProofBatchError::BatchSizeMismatch {
            expected: proof.entries.len(),
            actual: derived.batch_size as usize,
        });
    }
    if derived.statement_hashes != public_inputs.statement_hashes {
        return Err(ProofBatchError::PublicValues(
            "statement hash summary mismatch".to_string(),
        ));
    }
    if derived.nullifiers != public_inputs.nullifiers {
        return Err(ProofBatchError::PublicValues(
            "nullifier summary mismatch".to_string(),
        ));
    }
    if derived.commitments != public_inputs.commitments {
        return Err(ProofBatchError::PublicValues(
            "commitment summary mismatch".to_string(),
        ));
    }
    if derived.total_fee != public_inputs.total_fee {
        return Err(ProofBatchError::TotalFeeMismatch {
            expected: public_inputs.total_fee,
            actual: derived.total_fee,
        });
    }
    if derived.circuit_version != public_inputs.circuit_version {
        return Err(ProofBatchError::PublicValues(format!(
            "circuit_version mismatch: expected {}, got {}",
            public_inputs.circuit_version, derived.circuit_version
        )));
    }
    Ok(())
}

fn summarize_entries(
    entries: &[ProofBatchWitnessEntry],
) -> Result<ProofBatchPublicInputs, ProofBatchError> {
    if entries.is_empty() {
        return Err(ProofBatchError::EmptyBatch);
    }

    let mut statement_hashes = Vec::with_capacity(entries.len());
    let mut nullifiers = Vec::with_capacity(entries.len().saturating_mul(MAX_INPUTS));
    let mut commitments = Vec::with_capacity(entries.len().saturating_mul(MAX_OUTPUTS));
    let mut total_fee = 0u64;
    let mut circuit_version = None;

    for entry in entries {
        let proof: TransactionProof = bincode::deserialize(&entry.proof_bytes)
            .map_err(|err| ProofBatchError::ProofDecode(err.to_string()))?;
        if proof.public_inputs != entry.public_inputs {
            return Err(ProofBatchError::EntryPublicInputsMismatch);
        }
        let stark_public_inputs = stark_public_inputs_p3(&proof).map_err(|err| {
            ProofBatchError::TransactionProofVerification(format!(
                "failed to decode tx proof public inputs: {err}"
            ))
        })?;
        verify_transaction_proof_bytes_p3(&proof.stark_proof, &stark_public_inputs)
            .map_err(|err| ProofBatchError::TransactionProofVerification(err.to_string()))?;

        let version = u32::from(proof.public_inputs.circuit_version);
        match circuit_version {
            Some(expected) if expected != version => {
                return Err(ProofBatchError::MixedCircuitVersions);
            }
            None => circuit_version = Some(version),
            _ => {}
        }

        total_fee = total_fee
            .checked_add(proof.public_inputs.native_fee)
            .ok_or(ProofBatchError::TotalFeeOverflow)?;
        statement_hashes.push(statement_hash_from_public_inputs(&proof.public_inputs));
        nullifiers.extend(proof.public_inputs.nullifiers.iter().copied());
        commitments.extend(proof.public_inputs.commitments.iter().copied());
    }

    let public_inputs = ProofBatchPublicInputs {
        batch_size: entries.len() as u32,
        statement_hashes,
        nullifiers,
        commitments,
        total_fee,
        circuit_version: circuit_version.unwrap_or(0),
    };
    public_inputs.validate()?;
    Ok(public_inputs)
}

fn statement_hash_from_public_inputs(public: &TransactionPublicInputs) -> Commitment {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"tx-statement-v1");
    hasher.update(&public.merkle_root);
    for nf in &public.nullifiers {
        hasher.update(nf);
    }
    for cm in &public.commitments {
        hasher.update(cm);
    }
    for ct in &public.ciphertext_hashes {
        hasher.update(ct);
    }
    hasher.update(&public.native_fee.to_le_bytes());
    hasher.update(&public.value_balance.to_le_bytes());
    hasher.update(&public.balance_tag);
    hasher.update(&public.circuit_version.to_le_bytes());
    hasher.update(&public.crypto_suite.to_le_bytes());
    hasher.update(&[public.stablecoin.enabled as u8]);
    hasher.update(&public.stablecoin.asset_id.to_le_bytes());
    hasher.update(&public.stablecoin.policy_hash);
    hasher.update(&public.stablecoin.oracle_commitment);
    hasher.update(&public.stablecoin.attestation_commitment);
    hasher.update(&public.stablecoin.issuance_delta.to_le_bytes());
    hasher.update(&public.stablecoin.policy_version.to_le_bytes());
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn encode_commitments(
    commitments: &[Commitment],
    out: &mut Vec<u64>,
) -> Result<(), ProofBatchError> {
    for value in commitments {
        let felts = bytes48_to_felts(value).ok_or(ProofBatchError::NonCanonicalBytes48)?;
        out.extend(felts.into_iter().map(|felt| felt.as_canonical_u64()));
    }
    Ok(())
}

fn decode_commitments(
    values: &[u64],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<Commitment>, ProofBatchError> {
    let needed = count.saturating_mul(6);
    let end = cursor.saturating_add(needed);
    if end > values.len() {
        return Err(ProofBatchError::PublicValues(format!(
            "expected {needed} field elements for {count} commitments, only {} remain",
            values.len().saturating_sub(*cursor)
        )));
    }
    let mut decoded = Vec::with_capacity(count);
    for chunk in values[*cursor..end].chunks_exact(6) {
        let mut bytes = [0u8; 48];
        for (index, limb) in chunk.iter().enumerate() {
            let start = index * 8;
            bytes[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        if bytes48_to_felts(&bytes).is_none() {
            return Err(ProofBatchError::NonCanonicalBytes48);
        }
        decoded.push(bytes);
    }
    *cursor = end;
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{
        prove_transaction_proof_batch, verify_proof_batch, witness_entries_from_transaction_proofs,
        ProofBatchPublicInputs,
    };
    use transaction_circuit::{
        generate_keys,
        hashing_pq::{felts_to_bytes48, merkle_node, spend_auth_key_bytes},
        note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
        proof::{prove, TransactionProof},
        public_inputs::StablecoinPolicyBinding,
        witness::TransactionWitness,
    };

    fn sample_witness() -> TransactionWitness {
        let sk_spend = [42u8; 32];
        let pk_auth = spend_auth_key_bytes(&sk_spend);
        let input_note = NoteData {
            value: 20,
            asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
            pk_recipient: [2u8; 32],
            pk_auth,
            rho: [3u8; 32],
            r: [4u8; 32],
        };
        let output_note = OutputNoteWitness {
            note: NoteData {
                value: 15,
                asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
                pk_recipient: [5u8; 32],
                pk_auth: [6u8; 32],
                rho: [7u8; 32],
                r: [8u8; 32],
            },
        };
        let merkle_path = MerklePath::default();
        let mut merkle_root = input_note.commitment();
        for sibling in &merkle_path.siblings {
            merkle_root = merkle_node(merkle_root, *sibling);
        }
        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: 0,
                rho_seed: [9u8; 32],
                merkle_path,
            }],
            outputs: vec![output_note],
            ciphertext_hashes: vec![[0u8; 48]],
            sk_spend,
            merkle_root: felts_to_bytes48(&merkle_root),
            fee: 5,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    fn prove_sample(fee: u64) -> TransactionProof {
        let mut witness = sample_witness();
        witness.fee = fee;
        witness.outputs[0].note.value = 20 - fee;
        let (proving_key, _) = generate_keys();
        prove(&witness, &proving_key).expect("sample tx proof")
    }

    #[test]
    fn proof_batch_round_trip_verifies() {
        let proofs = vec![prove_sample(10), prove_sample(7)];
        let (proof_bytes, public_inputs) =
            prove_transaction_proof_batch(&proofs).expect("proof batch");
        verify_proof_batch(&proof_bytes, &public_inputs).expect("proof batch verify");
        let decoded = ProofBatchPublicInputs::try_from_values(
            &public_inputs.to_values().expect("public value encoding"),
        )
        .expect("public value decode");
        assert_eq!(decoded, public_inputs);
    }

    #[test]
    fn witness_entries_retain_decoded_public_inputs() {
        let proofs = vec![prove_sample(5)];
        let entries = witness_entries_from_transaction_proofs(&proofs).expect("entries");
        assert_eq!(entries.len(), 1);
        let proof: TransactionProof =
            bincode::deserialize(&entries[0].proof_bytes).expect("proof decode");
        assert_eq!(proof.public_inputs, entries[0].public_inputs);
    }

    #[test]
    fn tampered_public_values_fail_verification() {
        let proofs = vec![prove_sample(9)];
        let (proof_bytes, mut public_inputs) =
            prove_transaction_proof_batch(&proofs).expect("proof batch");
        public_inputs.total_fee = public_inputs.total_fee.saturating_add(1);
        assert!(verify_proof_batch(&proof_bytes, &public_inputs).is_err());
    }

    #[test]
    fn canonical_public_inputs_are_preserved() {
        let proofs = vec![prove_sample(11)];
        let (proof_bytes, public_inputs) =
            prove_transaction_proof_batch(&proofs).expect("proof batch");
        let decoded_values = public_inputs.to_values().expect("values");
        let round_trip = ProofBatchPublicInputs::try_from_values(&decoded_values).expect("decode");
        verify_proof_batch(&proof_bytes, &round_trip).expect("verify");
        assert_eq!(round_trip.batch_size, 1);
    }
}
