//! Substrate Extrinsic Construction for Hegemon
//!
//! This module constructs properly signed Substrate extrinsics for the
//! Hegemon runtime using ML-DSA (FIPS 204) post-quantum signatures.
//!
//! The extrinsic format matches the runtime's `UncheckedExtrinsic` type:
//! - Address: MultiAddress<AccountId32, ()>
//! - Call: RuntimeCall (encoded)
//! - Signature: pq_crypto::Signature (ML-DSA or SLH-DSA)
//! - SignedExtra: (CheckNonZeroSender, CheckSpecVersion, CheckTxVersion,
//!                 CheckGenesis, CheckEra, CheckNonce, CheckWeight,
//!                 ChargeTransactionPayment)

use crate::error::WalletError;
use crate::rpc::TransactionBundle;
use synthetic_crypto::ml_dsa::{
    MlDsaPublicKey, MlDsaSecretKey, ML_DSA_PUBLIC_KEY_LEN,
    ML_DSA_SIGNATURE_LEN,
};
use synthetic_crypto::traits::{Signature as SigTrait, SigningKey, VerifyKey};

/// Chain metadata required for extrinsic construction
#[derive(Clone, Debug)]
pub struct ChainMetadata {
    /// Genesis block hash
    pub genesis_hash: [u8; 32],
    /// Current block hash (for mortality)
    pub block_hash: [u8; 32],
    /// Current block number
    pub block_number: u64,
    /// Runtime spec version
    pub spec_version: u32,
    /// Transaction version
    pub tx_version: u32,
}

/// Account nonce for replay protection
pub type Nonce = u32;

/// Era for transaction mortality
#[derive(Clone, Debug)]
pub enum Era {
    /// Transaction is immortal
    Immortal,
    /// Transaction expires after `period` blocks from `phase`
    Mortal { period: u64, phase: u64 },
}

impl Era {
    /// Create a mortal era with the given period and current block
    pub fn mortal(period: u64, current_block: u64) -> Self {
        // Period must be power of 2 between 4 and 65536
        let period = period.clamp(4, 65536).next_power_of_two();
        let phase = current_block % period;
        Era::Mortal { period, phase }
    }

    /// SCALE encode the era
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Era::Immortal => vec![0u8],
            Era::Mortal { period, phase } => {
                // Encoded as two bytes
                let quantize_factor = (*period >> 12).max(1);
                let encoded_period = period.trailing_zeros().saturating_sub(1).min(15) as u16;
                let quantized_phase = (*phase / quantize_factor) as u16;
                let encoded = encoded_period | (quantized_phase << 4);
                encoded.to_le_bytes().to_vec()
            }
        }
    }
}

/// Shielded transfer call data
#[derive(Clone, Debug)]
pub struct ShieldedTransferCall {
    /// STARK proof bytes
    pub proof: Vec<u8>,
    /// Nullifiers (spent note identifiers)
    pub nullifiers: Vec<[u8; 32]>,
    /// New note commitments
    pub commitments: Vec<[u8; 32]>,
    /// Encrypted notes for recipients
    pub encrypted_notes: Vec<Vec<u8>>,
    /// Merkle tree anchor (root hash)
    pub anchor: [u8; 32],
    /// Binding signature
    pub binding_sig: [u8; 64],
    /// Value balance (net shielding/unshielding)
    pub value_balance: i128,
}

impl ShieldedTransferCall {
    /// Create from a TransactionBundle
    pub fn from_bundle(bundle: &TransactionBundle) -> Self {
        Self {
            proof: bundle.proof_bytes.clone(),
            nullifiers: bundle.nullifiers.clone(),
            commitments: bundle.commitments.clone(),
            encrypted_notes: bundle.ciphertexts.clone(),
            anchor: bundle.anchor,
            binding_sig: bundle.binding_sig,
            value_balance: bundle.value_balance,
        }
    }
}

/// Extrinsic builder for signed transactions
pub struct ExtrinsicBuilder {
    /// ML-DSA signing key
    signing_key: MlDsaSecretKey,
    /// ML-DSA public key (cached)
    public_key: MlDsaPublicKey,
    /// Account ID (blake2_256 hash of public key)
    account_id: [u8; 32],
}

impl ExtrinsicBuilder {
    /// Create a new extrinsic builder from a seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = MlDsaSecretKey::generate_deterministic(seed);
        let public_key = signing_key.verify_key();
        
        // Account ID is blake2_256 hash of the encoded public key
        let pk_bytes = public_key.to_bytes();
        let account_id = blake2_256_hash(&pk_bytes);
        
        Self {
            signing_key,
            public_key,
            account_id,
        }
    }

    /// Get the account ID
    pub fn account_id(&self) -> [u8; 32] {
        self.account_id
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }

    /// Build a signed extrinsic for a shielded transfer
    pub fn build_shielded_transfer(
        &self,
        call: &ShieldedTransferCall,
        nonce: Nonce,
        era: Era,
        tip: u128,
        metadata: &ChainMetadata,
    ) -> Result<Vec<u8>, WalletError> {
        // 1. Encode the call
        let encoded_call = self.encode_shielded_transfer_call(call)?;
        
        // 2. Encode SignedExtra
        let encoded_extra = self.encode_signed_extra(nonce, &era, tip, metadata);
        
        // 3. Build the payload to sign
        let payload = self.build_sign_payload(&encoded_call, &encoded_extra, metadata);
        
        // 4. Sign with ML-DSA
        let signature = self.sign_payload(&payload);
        
        // 5. Build the final extrinsic
        let extrinsic = self.build_extrinsic(&encoded_call, &signature, &encoded_extra);
        
        Ok(extrinsic)
    }

    /// Encode the shielded_transfer call
    /// 
    /// Call format:
    /// - pallet_index (1 byte) = ShieldedPool index in construct_runtime!
    /// - call_index (1 byte) = 0 for shielded_transfer
    /// - proof: StarkProof (Vec<u8> prefixed with compact length)
    /// - nullifiers: BoundedVec<[u8;32], MaxNullifiersPerTx>
    /// - commitments: BoundedVec<[u8;32], MaxCommitmentsPerTx>
    /// - ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx>
    /// - anchor: [u8; 32]
    /// - binding_sig: BindingSignature
    /// - value_balance: i128
    fn encode_shielded_transfer_call(&self, call: &ShieldedTransferCall) -> Result<Vec<u8>, WalletError> {
        let mut encoded = Vec::new();
        
        // Pallet index for ShieldedPool (from construct_runtime! ordering)
        // System=0, Timestamp=1, Pow=2, Difficulty=3, Session=4, Balances=5,
        // TransactionPayment=6, Sudo=7, Council=8, CouncilMembership=9,
        // Treasury=10, Oracles=11, Identity=12, Attestations=13, AssetRegistry=14,
        // Settlement=15, FeatureFlags=16, FeeModel=17, Observability=18, ShieldedPool=19
        const SHIELDED_POOL_INDEX: u8 = 19;
        encoded.push(SHIELDED_POOL_INDEX);
        
        // Call index for shielded_transfer (first call in pallet)
        const SHIELDED_TRANSFER_CALL_INDEX: u8 = 0;
        encoded.push(SHIELDED_TRANSFER_CALL_INDEX);
        
        // Encode proof (StarkProof is Vec<u8>)
        encode_compact_vec(&call.proof, &mut encoded);
        
        // Encode nullifiers (BoundedVec<[u8;32], _>)
        encode_compact_len(call.nullifiers.len(), &mut encoded);
        for nullifier in &call.nullifiers {
            encoded.extend_from_slice(nullifier);
        }
        
        // Encode commitments (BoundedVec<[u8;32], _>)
        encode_compact_len(call.commitments.len(), &mut encoded);
        for commitment in &call.commitments {
            encoded.extend_from_slice(commitment);
        }
        
        // Encode encrypted notes (BoundedVec<EncryptedNote, _>)
        // EncryptedNote has ciphertext: [u8; 611] and kem_ciphertext: [u8; 1088]
        encode_compact_len(call.encrypted_notes.len(), &mut encoded);
        for note in &call.encrypted_notes {
            // The encrypted note should be exactly ciphertext + kem_ciphertext
            if note.len() < 611 + 1088 {
                return Err(WalletError::Serialization(
                    format!("Encrypted note too short: {} bytes", note.len())
                ));
            }
            encoded.extend_from_slice(note);
        }
        
        // Encode anchor ([u8; 32])
        encoded.extend_from_slice(&call.anchor);
        
        // Encode binding signature (BindingSignature { data: [u8; 64] })
        encoded.extend_from_slice(&call.binding_sig);
        
        // Encode value_balance (i128, little-endian)
        encoded.extend_from_slice(&call.value_balance.to_le_bytes());
        
        Ok(encoded)
    }

    /// Encode SignedExtra tuple
    /// 
    /// SignedExtra = (
    ///     CheckNonZeroSender,      // empty
    ///     CheckSpecVersion,        // empty (implicit)
    ///     CheckTxVersion,          // empty (implicit)
    ///     CheckGenesis,            // empty (implicit)
    ///     CheckEra,                // Era
    ///     CheckNonce,              // Compact<Nonce>
    ///     CheckWeight,             // empty
    ///     ChargeTransactionPayment // Compact<Balance> (tip)
    /// )
    fn encode_signed_extra(&self, nonce: Nonce, era: &Era, tip: u128, _metadata: &ChainMetadata) -> Vec<u8> {
        let mut encoded = Vec::new();
        
        // CheckNonZeroSender: empty
        // CheckSpecVersion: empty (validated against implicit spec_version)
        // CheckTxVersion: empty (validated against implicit tx_version)
        // CheckGenesis: empty (validated against implicit genesis_hash)
        
        // CheckEra: Era encoding
        encoded.extend_from_slice(&era.encode());
        
        // CheckNonce: Compact<Nonce>
        encode_compact_u32(nonce, &mut encoded);
        
        // CheckWeight: empty
        
        // ChargeTransactionPayment: Compact<Balance> (tip)
        encode_compact_u128(tip, &mut encoded);
        
        encoded
    }

    /// Build the payload to sign
    /// 
    /// SignedPayload = (Call, Extra, Additional)
    /// where Additional = (spec_version, tx_version, genesis_hash, block_hash)
    fn build_sign_payload(
        &self,
        encoded_call: &[u8],
        encoded_extra: &[u8],
        metadata: &ChainMetadata,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        
        // Call
        payload.extend_from_slice(encoded_call);
        
        // Extra
        payload.extend_from_slice(encoded_extra);
        
        // Additional signed data (not included in extrinsic, only for signing)
        // spec_version: u32
        payload.extend_from_slice(&metadata.spec_version.to_le_bytes());
        // tx_version: u32
        payload.extend_from_slice(&metadata.tx_version.to_le_bytes());
        // genesis_hash: [u8; 32]
        payload.extend_from_slice(&metadata.genesis_hash);
        // block_hash: [u8; 32] (mortality checkpoint)
        payload.extend_from_slice(&metadata.block_hash);
        
        // If payload > 256 bytes, hash it first (Substrate convention)
        if payload.len() > 256 {
            blake2_256_hash(&payload).to_vec()
        } else {
            payload
        }
    }

    /// Sign payload with ML-DSA
    fn sign_payload(&self, payload: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(payload);
        
        // Encode as Signature::MlDsa variant
        // variant byte (0 = MlDsa) + signature + public key
        let mut encoded = Vec::with_capacity(1 + ML_DSA_SIGNATURE_LEN + ML_DSA_PUBLIC_KEY_LEN);
        encoded.push(0u8); // MlDsa variant
        encoded.extend_from_slice(signature.as_bytes());
        encoded.extend_from_slice(&self.public_key.to_bytes());
        
        encoded
    }

    /// Build the final signed extrinsic
    /// 
    /// UncheckedExtrinsic = (
    ///     version: u8 (0x84 for signed, or 0x04 for unsigned),
    ///     address: MultiAddress<AccountId32, ()>,
    ///     signature: Signature,
    ///     extra: SignedExtra,
    ///     call: Call
    /// )
    fn build_extrinsic(
        &self,
        encoded_call: &[u8],
        signature: &[u8],
        encoded_extra: &[u8],
    ) -> Vec<u8> {
        let mut extrinsic = Vec::new();
        
        // Version byte: 0x84 = signed extrinsic (0b10000100)
        // Bit 7 = 1 (signed), bits 0-6 = 4 (extrinsic format version)
        extrinsic.push(0x84);
        
        // Address: MultiAddress::Id(AccountId32)
        // Variant 0 = Id
        extrinsic.push(0x00);
        extrinsic.extend_from_slice(&self.account_id);
        
        // Signature (already encoded with variant byte)
        extrinsic.extend_from_slice(signature);
        
        // Extra
        extrinsic.extend_from_slice(encoded_extra);
        
        // Call
        extrinsic.extend_from_slice(encoded_call);
        
        // Wrap with compact length prefix (standard extrinsic encoding)
        let mut result = Vec::new();
        encode_compact_len(extrinsic.len(), &mut result);
        result.extend_from_slice(&extrinsic);
        
        result
    }
}

// ============================================================================
// SCALE Encoding Helpers
// ============================================================================

/// Encode a compact integer (SCALE compact encoding)
fn encode_compact_len(value: usize, out: &mut Vec<u8>) {
    encode_compact_u64(value as u64, out);
}

fn encode_compact_u32(value: u32, out: &mut Vec<u8>) {
    encode_compact_u64(value as u64, out);
}

fn encode_compact_u64(value: u64, out: &mut Vec<u8>) {
    if value < 0x40 {
        // Single byte mode
        out.push((value as u8) << 2);
    } else if value < 0x4000 {
        // Two byte mode
        let v = ((value as u16) << 2) | 0x01;
        out.extend_from_slice(&v.to_le_bytes());
    } else if value < 0x4000_0000 {
        // Four byte mode
        let v = ((value as u32) << 2) | 0x02;
        out.extend_from_slice(&v.to_le_bytes());
    } else {
        // Big integer mode
        let bytes_needed = ((64 - value.leading_zeros() + 7) / 8) as u8;
        out.push(((bytes_needed - 4) << 2) | 0x03);
        let value_bytes = value.to_le_bytes();
        out.extend_from_slice(&value_bytes[..bytes_needed as usize]);
    }
}

fn encode_compact_u128(value: u128, out: &mut Vec<u8>) {
    if value < 0x40 {
        out.push((value as u8) << 2);
    } else if value < 0x4000 {
        let v = ((value as u16) << 2) | 0x01;
        out.extend_from_slice(&v.to_le_bytes());
    } else if value < 0x4000_0000 {
        let v = ((value as u32) << 2) | 0x02;
        out.extend_from_slice(&v.to_le_bytes());
    } else {
        let bytes_needed = ((128 - value.leading_zeros() + 7) / 8) as u8;
        out.push(((bytes_needed - 4) << 2) | 0x03);
        let value_bytes = value.to_le_bytes();
        out.extend_from_slice(&value_bytes[..bytes_needed as usize]);
    }
}

/// Encode a Vec<u8> with compact length prefix
fn encode_compact_vec(data: &[u8], out: &mut Vec<u8>) {
    encode_compact_len(data.len(), out);
    out.extend_from_slice(data);
}

/// Blake2-256 hash
fn blake2_256_hash(data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_era_immortal() {
        let era = Era::Immortal;
        assert_eq!(era.encode(), vec![0u8]);
    }

    #[test]
    fn test_era_mortal() {
        let era = Era::mortal(64, 100);
        let encoded = era.encode();
        assert_eq!(encoded.len(), 2);
    }

    #[test]
    fn test_compact_encoding() {
        let mut out = Vec::new();
        encode_compact_u64(0, &mut out);
        assert_eq!(out, vec![0x00]);

        out.clear();
        encode_compact_u64(1, &mut out);
        assert_eq!(out, vec![0x04]);

        out.clear();
        encode_compact_u64(63, &mut out);
        assert_eq!(out, vec![0xFC]);

        out.clear();
        encode_compact_u64(64, &mut out);
        assert_eq!(out, vec![0x01, 0x01]);
    }

    #[test]
    fn test_extrinsic_builder_creation() {
        let seed = [0u8; 32];
        let builder = ExtrinsicBuilder::from_seed(&seed);
        
        // Account ID should be 32 bytes
        assert_eq!(builder.account_id().len(), 32);
        
        // Public key should be ML_DSA_PUBLIC_KEY_LEN bytes
        assert_eq!(builder.public_key_bytes().len(), ML_DSA_PUBLIC_KEY_LEN);
    }
}
