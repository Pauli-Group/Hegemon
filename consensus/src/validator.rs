use std::collections::HashMap;

use crate::error::ConsensusError;
use crate::header::BlockHeader;
use crate::types::{ValidatorId, ValidatorSetCommitment};
use crypto::hashes::{blake3_384, sha256};
use crypto::ml_dsa::{ML_DSA_PUBLIC_KEY_LEN, ML_DSA_SIGNATURE_LEN, MlDsaPublicKey, MlDsaSignature};
use crypto::traits::VerifyKey;
#[derive(Clone, Debug)]
pub struct Validator {
    pub id: ValidatorId,
    pub public_key: MlDsaPublicKey,
    pub stake: u64,
    pub slashed: bool,
}

impl Validator {
    pub fn new(public_key: MlDsaPublicKey, stake: u64) -> Self {
        let id = sha256(&public_key.to_bytes());
        Self {
            id,
            public_key,
            stake,
            slashed: false,
        }
    }

    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    index: HashMap<ValidatorId, usize>,
    total_stake: u128,
}

impl ValidatorSet {
    pub fn new(validators: Vec<Validator>) -> Self {
        let mut index = HashMap::new();
        let mut total_stake = 0u128;
        for (idx, validator) in validators.iter().enumerate() {
            index.insert(validator.id, idx);
            total_stake += validator.stake as u128;
        }
        Self {
            validators,
            index,
            total_stake,
        }
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn total_stake(&self) -> u128 {
        self.total_stake
    }

    pub fn quorum_threshold(&self) -> u128 {
        (self.total_stake * 2) / 3 + 1
    }

    pub fn validator_set_commitment(&self) -> ValidatorSetCommitment {
        let mut entries: Vec<_> = self
            .validators
            .iter()
            .map(|v| (v.id, v.stake, v.slashed))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut data = Vec::with_capacity(entries.len() * (ML_DSA_PUBLIC_KEY_LEN + 16));
        for (id, stake, slashed) in entries {
            data.extend_from_slice(&id);
            data.extend_from_slice(&stake.to_le_bytes());
            data.push(slashed as u8);
        }
        blake3_384(&data)
    }

    pub fn validator(&self, id: &ValidatorId) -> Option<&Validator> {
        self.index.get(id).map(|idx| &self.validators[*idx])
    }

    pub fn validator_mut(&mut self, id: &ValidatorId) -> Option<&mut Validator> {
        self.index.get(id).map(|idx| &mut self.validators[*idx])
    }

    pub fn verify_signatures(
        &self,
        header: &BlockHeader,
    ) -> Result<(u128, Vec<ValidatorId>), ConsensusError> {
        let bitmap = header
            .signature_bitmap
            .as_ref()
            .ok_or(ConsensusError::InvalidHeader("missing signature bitmap"))?;
        let signer_indices = parse_bitmap(bitmap, self.validators.len());
        if signer_indices.is_empty() {
            return Err(ConsensusError::InvalidHeader("no signatures"));
        }
        let expected_len = signer_indices.len() * ML_DSA_SIGNATURE_LEN;
        if header.signature_aggregate.len() != expected_len {
            return Err(ConsensusError::InvalidHeader(
                "signature aggregate length mismatch",
            ));
        }
        let signing_hash = header.signing_hash()?;
        let mut weight = 0u128;
        let mut signers = Vec::with_capacity(signer_indices.len());
        for (chunk_idx, validator_idx) in signer_indices.iter().enumerate() {
            let signature_bytes = &header.signature_aggregate
                [chunk_idx * ML_DSA_SIGNATURE_LEN..(chunk_idx + 1) * ML_DSA_SIGNATURE_LEN];
            let signature = MlDsaSignature::from_bytes(signature_bytes)
                .map_err(|_| ConsensusError::InvalidHeader("invalid signature bytes"))?;
            let validator = &self.validators[*validator_idx];
            validator
                .public_key
                .verify(&signing_hash, &signature)
                .map_err(|_| ConsensusError::SignatureVerificationFailed {
                    validator: validator.id,
                })?;
            weight += validator.stake as u128;
            signers.push(validator.id);
        }
        Ok((weight, signers))
    }

    pub fn mark_slashed(&mut self, validator: &ValidatorId) {
        if let Some(record) = self.validator_mut(validator) {
            record.slashed = true;
        }
    }
}

fn parse_bitmap(bitmap: &[u8], validator_count: usize) -> Vec<usize> {
    let mut indices = Vec::new();
    for (byte_index, byte) in bitmap.iter().enumerate() {
        for bit in 0..8 {
            if byte & (1 << bit) != 0 {
                let idx = byte_index * 8 + bit as usize;
                if idx < validator_count {
                    indices.push(idx);
                }
            }
        }
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ml_dsa::MlDsaSecretKey;
    use crypto::traits::SigningKey;

    fn make_validator(stake: u64, seed: &[u8]) -> (Validator, MlDsaSecretKey) {
        let sk = MlDsaSecretKey::generate_deterministic(seed);
        let pk = sk.verify_key();
        (Validator::new(pk, stake), sk)
    }

    #[test]
    fn bitmap_parsing_skips_out_of_range_bits() {
        let (a, _sk_a) = make_validator(10, b"a");
        let (b, _sk_b) = make_validator(10, b"b");
        let set = ValidatorSet::new(vec![a, b]);
        let bitmap = vec![0b0000_0011, 0b1000_0000];
        let indices = parse_bitmap(&bitmap, set.len());
        assert_eq!(indices, vec![0, 1]);
    }
}
