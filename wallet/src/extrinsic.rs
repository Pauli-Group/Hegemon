//! Substrate Extrinsic Construction for Hegemon
//!
//! This module constructs properly signed Substrate extrinsics for the
//! Hegemon runtime using ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) post-quantum signatures.
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
    MlDsaPublicKey, MlDsaSecretKey, ML_DSA_PUBLIC_KEY_LEN, ML_DSA_SIGNATURE_LEN,
};
use synthetic_crypto::slh_dsa::{
    SlhDsaPublicKey, SlhDsaSecretKey, SLH_DSA_PUBLIC_KEY_LEN, SLH_DSA_SIGNATURE_LEN,
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
    /// Native fee encoded in the proof.
    pub fee: u64,
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
            fee: bundle.fee,
            value_balance: bundle.value_balance,
        }
    }
}

/// Shield call data (converts transparent funds to shielded)
///
/// This is call_index(1) in pallet_shielded_pool
#[derive(Clone, Debug)]
pub struct ShieldCall {
    /// Amount to shield (in smallest units)
    pub amount: u128,
    /// Note commitment (32 bytes)
    pub commitment: [u8; 32],
    /// Encrypted note for recipient
    /// Contains ciphertext (611 bytes) + kem_ciphertext (1088 bytes)
    pub encrypted_note: EncryptedNote,
}

/// Encrypted note structure matching pallet_shielded_pool::types::EncryptedNote
#[derive(Clone, Debug)]
pub struct EncryptedNote {
    /// Encrypted ciphertext containing note data (611 bytes)
    pub ciphertext: [u8; 611],
    /// ML-KEM-768 ciphertext for key encapsulation (1088 bytes)
    pub kem_ciphertext: [u8; 1088],
}

impl Default for EncryptedNote {
    fn default() -> Self {
        Self {
            ciphertext: [0u8; 611],
            kem_ciphertext: [0u8; 1088],
        }
    }
}

impl ShieldCall {
    /// Create a new shield call
    pub fn new(amount: u128, commitment: [u8; 32], encrypted_note: EncryptedNote) -> Self {
        Self {
            amount,
            commitment,
            encrypted_note,
        }
    }
}

/// Extrinsic builder for signed transactions
pub struct ExtrinsicBuilder {
    /// ML-DSA signing key
    signing_key: MlDsaSecretKey,
    /// ML-DSA public key (cached)
    public_key: MlDsaPublicKey,
    /// Account ID (blake2_256 hash of raw public key bytes)
    account_id: [u8; 32],
}

impl ExtrinsicBuilder {
    /// Create a new extrinsic builder from a seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = MlDsaSecretKey::generate_deterministic(seed);
        let public_key = signing_key.verify_key();

        // Account ID is blake2_256 hash of the raw public key bytes
        // This matches the runtime's IdentifyAccount implementation
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

    /// Build a signed extrinsic for shielding transparent funds
    ///
    /// This converts transparent balance to shielded notes by calling
    /// `pallet_shielded_pool::shield(amount, commitment, encrypted_note)`
    pub fn build_shield(
        &self,
        call: &ShieldCall,
        nonce: Nonce,
        era: Era,
        tip: u128,
        metadata: &ChainMetadata,
    ) -> Result<Vec<u8>, WalletError> {
        // 1. Encode the call
        let encoded_call = self.encode_shield_call(call);

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

    /// Encode the shield call
    ///
    /// Call format:
    /// - pallet_index (1 byte) = ShieldedPool index in construct_runtime!
    /// - call_index (1 byte) = 1 for shield
    /// - amount: Compact<Balance>
    /// - commitment: [u8; 32]
    /// - encrypted_note: EncryptedNote
    fn encode_shield_call(&self, call: &ShieldCall) -> Vec<u8> {
        let mut encoded = Vec::new();

        // Pallet index for ShieldedPool (from construct_runtime! ordering)
        // System=0, Timestamp=1, Coinbase=2, Pow=3, Difficulty=4, Session=5, Balances=6,
        // TransactionPayment=7, Sudo=8, Council=9, CouncilMembership=10, Treasury=11,
        // Oracles=12, Identity=13, Attestations=14, AssetRegistry=15, Settlement=16,
        // FeatureFlags=17, FeeModel=18, Observability=19, ShieldedPool=20
        const SHIELDED_POOL_INDEX: u8 = 20;
        encoded.push(SHIELDED_POOL_INDEX);

        // Call index for shield (second call in pallet, after shielded_transfer)
        const SHIELD_CALL_INDEX: u8 = 1;
        encoded.push(SHIELD_CALL_INDEX);

        // Encode amount as raw u128 (NOT Compact - FRAME doesn't use compact for Balance by default)
        // u128 is 16 bytes, little-endian
        encoded.extend_from_slice(&call.amount.to_le_bytes());

        // Encode commitment ([u8; 32])
        encoded.extend_from_slice(&call.commitment);

        // Encode encrypted_note (EncryptedNote)
        // ciphertext: [u8; 611]
        encoded.extend_from_slice(&call.encrypted_note.ciphertext);
        // kem_ciphertext: [u8; 1088]
        encoded.extend_from_slice(&call.encrypted_note.kem_ciphertext);

        encoded
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
    /// - fee: u64
    /// - value_balance: i128
    fn encode_shielded_transfer_call(
        &self,
        call: &ShieldedTransferCall,
    ) -> Result<Vec<u8>, WalletError> {
        let mut encoded = Vec::new();

        // Pallet index for ShieldedPool (from construct_runtime! ordering)
        // System=0, Timestamp=1, Coinbase=2, Pow=3, Difficulty=4, Session=5, Balances=6,
        // TransactionPayment=7, Sudo=8, Council=9, CouncilMembership=10, Treasury=11,
        // Oracles=12, Identity=13, Attestations=14, AssetRegistry=15, Settlement=16,
        // FeatureFlags=17, FeeModel=18, Observability=19, ShieldedPool=20
        const SHIELDED_POOL_INDEX: u8 = 20;
        encoded.push(SHIELDED_POOL_INDEX);

        // Call index for shielded_transfer (first call in pallet)
        const SHIELDED_TRANSFER_CALL_INDEX: u8 = 0;
        encoded.push(SHIELDED_TRANSFER_CALL_INDEX);

        // Encode proof (StarkProof is Vec<u8>)
        // eprintln!("DEBUG CALL: proof size = {} bytes", call.proof.len());
        encode_compact_vec(&call.proof, &mut encoded);
        // eprintln!("DEBUG CALL: after proof, encoded size = {}", encoded.len());

        // Encode nullifiers (BoundedVec<[u8;32], _>)
        // eprintln!("DEBUG CALL: nullifiers count = {}", call.nullifiers.len());
        encode_compact_len(call.nullifiers.len(), &mut encoded);
        for nullifier in &call.nullifiers {
            encoded.extend_from_slice(nullifier);
        }
        // eprintln!("DEBUG CALL: after nullifiers, encoded size = {}", encoded.len());

        // Encode commitments (BoundedVec<[u8;32], _>)
        // eprintln!("DEBUG CALL: commitments count = {}", call.commitments.len());
        encode_compact_len(call.commitments.len(), &mut encoded);
        for commitment in &call.commitments {
            encoded.extend_from_slice(commitment);
        }
        // eprintln!("DEBUG CALL: after commitments, encoded size = {}", encoded.len());

        // Encode encrypted notes (BoundedVec<EncryptedNote, _>)
        // EncryptedNote has ciphertext: [u8; 611] and kem_ciphertext: [u8; 1088] = 1699 bytes total
        const PALLET_ENCRYPTED_NOTE_SIZE: usize = 611 + 1088;
        // eprintln!("DEBUG CALL: encrypted_notes count = {}", call.encrypted_notes.len());
        encode_compact_len(call.encrypted_notes.len(), &mut encoded);
        for note in &call.encrypted_notes {
            // The encrypted note must be exactly ciphertext + kem_ciphertext
            if note.len() != PALLET_ENCRYPTED_NOTE_SIZE {
                return Err(WalletError::Serialization(format!(
                    "Encrypted note wrong size: expected {} bytes, got {}",
                    PALLET_ENCRYPTED_NOTE_SIZE,
                    note.len()
                )));
            }
            encoded.extend_from_slice(note);
        }
        // eprintln!("DEBUG CALL: after encrypted_notes, encoded size = {}", encoded.len());

        // Encode anchor ([u8; 32])
        encoded.extend_from_slice(&call.anchor);
        // eprintln!("DEBUG CALL: after anchor, encoded size = {}", encoded.len());

        // Encode binding signature (BindingSignature { data: [u8; 64] })
        encoded.extend_from_slice(&call.binding_sig);
        // eprintln!("DEBUG CALL: after binding_sig, encoded size = {}", encoded.len());

        // Encode fee (u64, little-endian)
        encoded.extend_from_slice(&call.fee.to_le_bytes());

        // Encode value_balance (i128, little-endian)
        encoded.extend_from_slice(&call.value_balance.to_le_bytes());
        // eprintln!("DEBUG CALL: final call size = {}", encoded.len());

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
    fn encode_signed_extra(
        &self,
        nonce: Nonce,
        era: &Era,
        tip: u128,
        _metadata: &ChainMetadata,
    ) -> Vec<u8> {
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

        // eprintln!("DEBUG: Sign payload before hash: {} bytes", payload.len());
        // eprintln!("DEBUG: Sign payload first 50: {}", hex::encode(&payload[..50.min(payload.len())]));

        // If payload > 256 bytes, hash it first (Substrate convention)
        if payload.len() > 256 {
            let hashed = blake2_256_hash(&payload);
            // eprintln!("DEBUG: Sign payload hashed to: {}", hex::encode(&hashed));
            hashed.to_vec()
        } else {
            payload
        }
    }

    /// Sign payload with ML-DSA
    fn sign_payload(&self, payload: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(payload);

        // Encode as Signature::MlDsa variant
        // Format: variant_byte(0) + signature[3309] + Public::MlDsa(variant_byte(0) + pk[1952])
        //
        // The runtime's Signature enum is:
        //   enum Signature { MlDsa { signature: [u8; 3309], public: Public }, ... }
        // And Public enum is:
        //   enum Public { MlDsa([u8; 1952]), SlhDsa([u8; 64]) }
        //
        // So we need: Signature variant + signature bytes + Public variant + public key bytes
        let mut encoded = Vec::with_capacity(1 + ML_DSA_SIGNATURE_LEN + 1 + ML_DSA_PUBLIC_KEY_LEN);
        encoded.push(0u8); // Signature::MlDsa variant
        encoded.extend_from_slice(signature.as_bytes());
        encoded.push(0u8); // Public::MlDsa variant
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
        // eprintln!("DEBUG EXTRINSIC BUILD:");
        eprintln!("  call len = {} bytes", encoded_call.len());
        eprintln!("  signature len = {} bytes", signature.len());
        eprintln!("  extra len = {} bytes", encoded_extra.len());
        eprintln!("  extra hex = {}", hex::encode(encoded_extra));

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

        eprintln!("  extrinsic body = {} bytes", extrinsic.len());
        eprintln!("  breakdown: 1(version) + 1(addr variant) + 32(account) + {}(sig) + {}(extra) + {}(call) = {}",
                  signature.len(), encoded_extra.len(), encoded_call.len(),
                  1 + 1 + 32 + signature.len() + encoded_extra.len() + encoded_call.len());

        // Wrap with compact length prefix (standard extrinsic encoding)
        let mut result = Vec::new();
        encode_compact_len(extrinsic.len(), &mut result);
        eprintln!(
            "  compact prefix = {} bytes for value {}",
            result.len(),
            extrinsic.len()
        );
        result.extend_from_slice(&extrinsic);

        eprintln!("  final extrinsic = {} bytes", result.len());
        eprintln!(
            "  first 20 bytes: {}",
            hex::encode(&result[..20.min(result.len())])
        );

        result
    }
}

// ============================================================================
// SLH-DSA Extrinsic Builder (Protocol 14.2.7)
// ============================================================================

/// Extrinsic builder using SLH-DSA (SPHINCS+) signatures per FIPS 205
///
/// This provides an alternative to ML-DSA for scenarios requiring maximum
/// cryptographic conservatism. SLH-DSA is a stateless hash-based signature
/// scheme that relies only on the security of hash functions.
///
/// **Note**: SLH-DSA signatures are ~5x larger than ML-DSA (17KB vs 3.3KB),
/// which increases transaction size significantly. Use ML-DSA for routine
/// transactions and reserve SLH-DSA for long-lived trust roots or governance.
pub struct SlhDsaExtrinsicBuilder {
    /// SLH-DSA signing key
    signing_key: SlhDsaSecretKey,
    /// SLH-DSA public key (cached)
    public_key: SlhDsaPublicKey,
    /// Account ID (blake2_256 hash of raw public key bytes)
    account_id: [u8; 32],
}

impl SlhDsaExtrinsicBuilder {
    /// Create a new SLH-DSA extrinsic builder from a seed
    ///
    /// # Arguments
    /// * `seed` - 32-byte seed for deterministic key generation
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SlhDsaSecretKey::generate_deterministic(seed);
        let public_key = signing_key.verify_key();

        // Account ID is blake2_256 hash of the raw public key bytes
        // This matches the runtime's IdentifyAccount implementation
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

    /// Build a signed extrinsic for a balance transfer
    ///
    /// This is call_index(0) in pallet_balances (transfer_allow_death)
    pub fn build_transfer(
        &self,
        dest: &[u8; 32],
        amount: u128,
        nonce: Nonce,
        era: Era,
        tip: u128,
        metadata: &ChainMetadata,
    ) -> Result<Vec<u8>, WalletError> {
        // 1. Encode the call
        let encoded_call = encode_transfer_call(dest, amount);

        // 2. Encode SignedExtra
        let encoded_extra = encode_signed_extra(nonce, &era, tip);

        // 3. Build the payload to sign
        let payload = build_sign_payload(&encoded_call, &encoded_extra, metadata);

        // 4. Sign with SLH-DSA
        let signature = self.sign_payload(&payload);

        // 5. Build the final extrinsic
        let extrinsic = self.build_extrinsic(&encoded_call, &signature, &encoded_extra);

        Ok(extrinsic)
    }

    /// Build a signed extrinsic for shielding transparent funds
    pub fn build_shield(
        &self,
        call: &ShieldCall,
        nonce: Nonce,
        era: Era,
        tip: u128,
        metadata: &ChainMetadata,
    ) -> Result<Vec<u8>, WalletError> {
        // 1. Encode the call
        let encoded_call = encode_shield_call(call);

        // 2. Encode SignedExtra
        let encoded_extra = encode_signed_extra(nonce, &era, tip);

        // 3. Build the payload to sign
        let payload = build_sign_payload(&encoded_call, &encoded_extra, metadata);

        // 4. Sign with SLH-DSA
        let signature = self.sign_payload(&payload);

        // 5. Build the final extrinsic
        let extrinsic = self.build_extrinsic(&encoded_call, &signature, &encoded_extra);

        Ok(extrinsic)
    }

    /// Sign payload with SLH-DSA
    fn sign_payload(&self, payload: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(payload);

        // Encode as Signature::SlhDsa variant
        // Format: variant_byte(1) + signature[17088] + Public::SlhDsa(variant_byte(1) + pk[32])
        //
        // The runtime's Signature enum is:
        //   enum Signature { MlDsa { .. }, SlhDsa { signature: Box<[u8; 17088]>, public: Public } }
        // And Public enum is:
        //   enum Public { MlDsa([u8; 1952]), SlhDsa([u8; 32]) }
        //
        // So we need: Signature variant + signature bytes + Public variant + public key bytes
        let mut encoded =
            Vec::with_capacity(1 + SLH_DSA_SIGNATURE_LEN + 1 + SLH_DSA_PUBLIC_KEY_LEN);
        encoded.push(1u8); // Signature::SlhDsa variant
        encoded.extend_from_slice(signature.as_bytes());
        encoded.push(1u8); // Public::SlhDsa variant
        encoded.extend_from_slice(&self.public_key.to_bytes());

        encoded
    }

    /// Build the final signed extrinsic
    fn build_extrinsic(
        &self,
        encoded_call: &[u8],
        signature: &[u8],
        encoded_extra: &[u8],
    ) -> Vec<u8> {
        let mut extrinsic = Vec::new();

        // Version byte: 0x84 = signed extrinsic (0b10000100)
        extrinsic.push(0x84);

        // Address: MultiAddress::Id(AccountId32)
        extrinsic.push(0x00);
        extrinsic.extend_from_slice(&self.account_id);

        // Signature (already encoded with variant byte)
        extrinsic.extend_from_slice(signature);

        // Extra
        extrinsic.extend_from_slice(encoded_extra);

        // Call
        extrinsic.extend_from_slice(encoded_call);

        // Wrap with compact length prefix
        let mut result = Vec::new();
        encode_compact_len(extrinsic.len(), &mut result);
        result.extend_from_slice(&extrinsic);

        result
    }
}

// ============================================================================
// Shared Encoding Helpers (used by both ML-DSA and SLH-DSA builders)
// ============================================================================

/// Encode a balance transfer call (pallet_balances::transfer_allow_death)
fn encode_transfer_call(dest: &[u8; 32], amount: u128) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Pallet index for Balances (from construct_runtime! ordering)
    const BALANCES_INDEX: u8 = 5;
    encoded.push(BALANCES_INDEX);

    // Call index for transfer_allow_death (first call in pallet)
    const TRANSFER_CALL_INDEX: u8 = 0;
    encoded.push(TRANSFER_CALL_INDEX);

    // Destination as MultiAddress::Id(AccountId32)
    encoded.push(0x00); // Id variant
    encoded.extend_from_slice(dest);

    // Amount as Compact<u128>
    encode_compact_u128(amount, &mut encoded);

    encoded
}

/// Encode shield call (standalone function for reuse)
fn encode_shield_call(call: &ShieldCall) -> Vec<u8> {
    let mut encoded = Vec::new();

    // ShieldedPool pallet index (see construct_runtime! in runtime/src/lib.rs)
    const SHIELDED_POOL_INDEX: u8 = 20;
    encoded.push(SHIELDED_POOL_INDEX);

    const SHIELD_CALL_INDEX: u8 = 1;
    encoded.push(SHIELD_CALL_INDEX);

    // Amount as raw u128 (NOT Compact)
    encoded.extend_from_slice(&call.amount.to_le_bytes());

    // Commitment
    encoded.extend_from_slice(&call.commitment);

    // Encrypted note
    encoded.extend_from_slice(&call.encrypted_note.ciphertext);
    encoded.extend_from_slice(&call.encrypted_note.kem_ciphertext);

    encoded
}

/// Encode SignedExtra (standalone function for reuse)
fn encode_signed_extra(nonce: Nonce, era: &Era, tip: u128) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Era encoding
    encoded.extend_from_slice(&era.encode());

    // Nonce as Compact<u32>
    encode_compact_u32(nonce, &mut encoded);

    // Tip as Compact<u128>
    encode_compact_u128(tip, &mut encoded);

    encoded
}

/// Build sign payload (standalone function for reuse)
fn build_sign_payload(
    encoded_call: &[u8],
    encoded_extra: &[u8],
    metadata: &ChainMetadata,
) -> Vec<u8> {
    let mut payload = Vec::new();

    // Call
    payload.extend_from_slice(encoded_call);

    // Extra
    payload.extend_from_slice(encoded_extra);

    // Additional signed data
    payload.extend_from_slice(&metadata.spec_version.to_le_bytes());
    payload.extend_from_slice(&metadata.tx_version.to_le_bytes());
    payload.extend_from_slice(&metadata.genesis_hash);
    payload.extend_from_slice(&metadata.block_hash);

    // If payload > 256 bytes, hash it first (Substrate convention)
    if payload.len() > 256 {
        blake2_256_hash(&payload).to_vec()
    } else {
        payload
    }
}

// ============================================================================
// Batch Shielded Transfer Support
// ============================================================================

/// Batch shielded transfer call data (call_index 5)
#[derive(Clone, Debug)]
pub struct BatchShieldedTransferCall {
    /// Batch size (2, 4, 8, or 16)
    pub batch_size: u32,
    /// All nullifiers from all transactions
    pub nullifiers: Vec<[u8; 32]>,
    /// All commitments from all transactions
    pub commitments: Vec<[u8; 32]>,
    /// All encrypted notes from all transactions
    pub encrypted_notes: Vec<Vec<u8>>,
    /// Shared Merkle anchor
    pub anchor: [u8; 32],
    /// Total fee for entire batch
    pub total_fee: u128,
}

/// Encode a batch_shielded_transfer call (call_index 5)
///
/// This encodes multiple shielded transactions with a single batch proof.
pub fn encode_batch_shielded_transfer_call(
    call: &BatchShieldedTransferCall,
) -> Result<Vec<u8>, WalletError> {
    let mut encoded = Vec::new();

    // Pallet index for ShieldedPool
    const SHIELDED_POOL_INDEX: u8 = 20;
    encoded.push(SHIELDED_POOL_INDEX);

    // Call index for batch_shielded_transfer (call_index 5 in pallet)
    const BATCH_SHIELDED_TRANSFER_CALL_INDEX: u8 = 5;
    encoded.push(BATCH_SHIELDED_TRANSFER_CALL_INDEX);

    // Encode proof as BatchStarkProof { data: Vec<u8>, batch_size: u32 }
    // For now, we use an empty proof (AcceptAllBatchProofs verifier)
    // The batch_size tells the verifier how many transactions are in the batch
    let proof_data: Vec<u8> = Vec::new(); // TODO: actual batch proof generation
    encode_compact_vec(&proof_data, &mut encoded);
    encoded.extend_from_slice(&call.batch_size.to_le_bytes());

    // Encode nullifiers (BoundedVec<[u8;32], MaxNullifiersPerBatch>)
    encode_compact_len(call.nullifiers.len(), &mut encoded);
    for nullifier in &call.nullifiers {
        encoded.extend_from_slice(nullifier);
    }

    // Encode commitments (BoundedVec<[u8;32], MaxCommitmentsPerBatch>)
    encode_compact_len(call.commitments.len(), &mut encoded);
    for commitment in &call.commitments {
        encoded.extend_from_slice(commitment);
    }

    // Encode encrypted notes (BoundedVec<EncryptedNote, MaxCommitmentsPerBatch>)
    const PALLET_ENCRYPTED_NOTE_SIZE: usize = 611 + 1088;
    encode_compact_len(call.encrypted_notes.len(), &mut encoded);
    for note in &call.encrypted_notes {
        if note.len() != PALLET_ENCRYPTED_NOTE_SIZE {
            return Err(WalletError::Serialization(format!(
                "Encrypted note wrong size: expected {} bytes, got {}",
                PALLET_ENCRYPTED_NOTE_SIZE,
                note.len()
            )));
        }
        encoded.extend_from_slice(note);
    }

    // Encode anchor ([u8; 32])
    encoded.extend_from_slice(&call.anchor);

    // Encode total_fee (u128)
    encoded.extend_from_slice(&call.total_fee.to_le_bytes());

    Ok(encoded)
}

/// Build an unsigned extrinsic for a batch shielded transfer
pub fn build_unsigned_batch_shielded_transfer(
    call: &BatchShieldedTransferCall,
) -> Result<Vec<u8>, WalletError> {
    // Encode the call
    let encoded_call = encode_batch_shielded_transfer_call(call)?;

    let mut extrinsic = Vec::new();

    // Version byte: 0x04 = unsigned extrinsic
    extrinsic.push(0x04);

    // Call data
    extrinsic.extend_from_slice(&encoded_call);

    // Wrap with compact length prefix
    let mut result = Vec::new();
    encode_compact_len(extrinsic.len(), &mut result);
    result.extend_from_slice(&extrinsic);

    Ok(result)
}

// ============================================================================
// Unsigned Shielded Transfer Support
// ============================================================================

/// Encode an unsigned shielded_transfer_unsigned call (call_index 4)
///
/// This encodes a pure shielded-to-shielded transfer that doesn't require
/// a transparent account. The ZK proof authenticates the spend.
pub fn encode_shielded_transfer_unsigned_call(
    call: &ShieldedTransferCall,
) -> Result<Vec<u8>, WalletError> {
    let mut encoded = Vec::new();

    // Pallet index for ShieldedPool (from construct_runtime! ordering)
    const SHIELDED_POOL_INDEX: u8 = 20;
    encoded.push(SHIELDED_POOL_INDEX);

    // Call index for shielded_transfer_unsigned (call_index 4 in pallet)
    const SHIELDED_TRANSFER_UNSIGNED_CALL_INDEX: u8 = 4;
    encoded.push(SHIELDED_TRANSFER_UNSIGNED_CALL_INDEX);

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
    const PALLET_ENCRYPTED_NOTE_SIZE: usize = 611 + 1088;
    encode_compact_len(call.encrypted_notes.len(), &mut encoded);
    for note in &call.encrypted_notes {
        if note.len() != PALLET_ENCRYPTED_NOTE_SIZE {
            return Err(WalletError::Serialization(format!(
                "Encrypted note wrong size: expected {} bytes, got {}",
                PALLET_ENCRYPTED_NOTE_SIZE,
                note.len()
            )));
        }
        encoded.extend_from_slice(note);
    }

    // Encode anchor ([u8; 32])
    encoded.extend_from_slice(&call.anchor);

    // Encode binding signature (BindingSignature { data: [u8; 64] })
    encoded.extend_from_slice(&call.binding_sig);

    // Encode fee (u64, little-endian)
    encoded.extend_from_slice(&call.fee.to_le_bytes());

    // NOTE: No value_balance for unsigned transfers - it's always 0
    // The pallet hardcodes value_balance = 0 for unsigned calls

    Ok(encoded)
}

/// Build an unsigned extrinsic for a pure shielded-to-shielded transfer
///
/// Unsigned extrinsics have a simpler format:
/// - version byte: 0x04 (unsigned extrinsic, version 4)
/// - call: encoded call data
///
/// No signature, no signer address, no extra fields.
pub fn build_unsigned_shielded_transfer(
    call: &ShieldedTransferCall,
) -> Result<Vec<u8>, WalletError> {
    // Encode the call
    let encoded_call = encode_shielded_transfer_unsigned_call(call)?;

    let mut extrinsic = Vec::new();

    // Version byte: 0x04 = unsigned extrinsic
    // Bit 7 = 0 (unsigned), bits 0-6 = 4 (extrinsic format version)
    extrinsic.push(0x04);

    // Call data (no signature, no extra for unsigned)
    extrinsic.extend_from_slice(&encoded_call);

    // Wrap with compact length prefix
    let mut result = Vec::new();
    encode_compact_len(extrinsic.len(), &mut result);
    result.extend_from_slice(&extrinsic);

    // eprintln!("DEBUG: Built unsigned extrinsic: {} bytes", result.len());
    // eprintln!("DEBUG: First 20 bytes: {}", hex::encode(&result[..20.min(result.len())]));

    Ok(result)
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

/// Blake2-256 hash (Blake2b with 256-bit output, matching Substrate)
fn blake2_256_hash(data: &[u8]) -> [u8; 32] {
    sp_crypto_hashing::blake2_256(data)
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

#[cfg(test)]
mod encoding_tests {
    use super::*;

    #[test]
    fn test_shield_call_encoding_size() {
        let enc = EncryptedNote::default();
        println!("ciphertext len: {}", enc.ciphertext.len());
        println!("kem_ciphertext len: {}", enc.kem_ciphertext.len());

        let call = ShieldCall {
            amount: 1000,
            commitment: [0u8; 32],
            encrypted_note: enc,
        };

        // Create a test builder (using arbitrary seed)
        let seed = [0u8; 32];
        let builder = ExtrinsicBuilder::from_seed(&seed);

        let encoded = builder.encode_shield_call(&call);
        println!("Encoded shield call length: {}", encoded.len());

        // Expected: 1 (pallet) + 1 (call) + 16 (u128 amount) + 32 (commitment) + 611 + 1088
        let expected = 1 + 1 + 16 + 32 + 611 + 1088;
        println!("Expected length: {}", expected);

        // Print first 50 bytes as hex
        println!(
            "First 50 bytes: {}",
            hex::encode(&encoded[..50.min(encoded.len())])
        );

        // Verify the encoding
        assert_eq!(
            encoded.len(),
            expected,
            "Encoded call should be {} bytes",
            expected
        );
        assert_eq!(encoded[0], 20, "Pallet index should be 20 (ShieldedPool)");
        assert_eq!(encoded[1], 1, "Call index should be 1");

        // Verify amount encoding (1000 as u128 little-endian)
        let amount_bytes = &encoded[2..18];
        let decoded_amount = u128::from_le_bytes(amount_bytes.try_into().unwrap());
        assert_eq!(decoded_amount, 1000, "Amount should decode to 1000");
    }

    #[test]
    fn test_full_shield_extrinsic() {
        let seed = [0u8; 32];
        let builder = ExtrinsicBuilder::from_seed(&seed);

        let call = ShieldCall {
            amount: 1000,
            commitment: [0u8; 32],
            encrypted_note: EncryptedNote::default(),
        };

        let metadata = ChainMetadata {
            genesis_hash: [0u8; 32],
            block_hash: [0u8; 32],
            block_number: 100,
            spec_version: 1,
            tx_version: 1,
        };

        let extrinsic = builder
            .build_shield(&call, 0, Era::Immortal, 0, &metadata)
            .expect("build_shield should succeed");

        println!("\n=== Full Extrinsic Analysis ===");
        println!("Total extrinsic length: {} bytes", extrinsic.len());

        // Decode the compact length prefix
        let (len_prefix_size, decoded_len) = decode_compact_len(&extrinsic);
        println!(
            "Length prefix: {} bytes encoding {} bytes of data",
            len_prefix_size, decoded_len
        );

        let body = &extrinsic[len_prefix_size..];
        println!("Body length: {} bytes", body.len());

        // Version byte
        println!("Version byte: 0x{:02x} (expected 0x84 for signed)", body[0]);

        // Address: variant (1) + AccountId32 (32)
        println!("Address variant: 0x{:02x} (expected 0x00 for Id)", body[1]);
        let address_end = 1 + 1 + 32;
        println!("AccountId (first 8 bytes): {}", hex::encode(&body[2..10]));

        // Signature: variant (1) + signature (3309) + Public variant (1) + pubkey (1952)
        let sig_start = address_end;
        println!(
            "Signature variant: 0x{:02x} (expected 0x00 for MlDsa)",
            body[sig_start]
        );
        let sig_end = sig_start + 1 + 3309 + 1 + 1952;
        println!(
            "Signature total: {} bytes (expected {})",
            sig_end - sig_start,
            1 + 3309 + 1 + 1952
        );

        // Extra
        let extra_start = sig_end;
        println!("Extra starts at byte {}", extra_start);
        // Extra for immortal era is: Era(1 byte 0x00) + Nonce(compact) + Tip(compact)
        // Era::immortal = 0x00
        // Nonce 0 = 0x00 (compact)
        // Tip 0 = 0x00 (compact)
        println!(
            "Extra bytes: {}",
            hex::encode(&body[extra_start..extra_start + 3])
        );
        let extra_end = extra_start + 3; // minimal extra

        // Call
        let call_start = extra_end;
        let call_bytes = &body[call_start..];
        println!("\nCall starts at byte {} (offset from body)", call_start);
        println!("Call length: {} bytes", call_bytes.len());
        println!("Call pallet index: {} (expected 20)", call_bytes[0]);
        println!("Call index: {} (expected 1 for shield)", call_bytes[1]);

        // Amount is raw u128 (16 bytes)
        let amount_bytes = &call_bytes[2..18];
        let amount = u128::from_le_bytes(amount_bytes.try_into().unwrap());
        println!("Amount (u128): {} (expected 1000)", amount);

        // Expected call length: 1 + 1 + 16 + 32 + 611 + 1088 = 1749 bytes
        // Expected body length: version(1) + address(33) + signature(5263) + extra(3) + call(1749) = 7049
        // Plus compact length prefix (2 bytes for values 16384+)
        let expected_call = 1 + 1 + 16 + 32 + 611 + 1088;
        let expected_body = 1 + 33 + 5263 + 3 + expected_call;
        println!("\nExpected call length: {}", expected_call);
        println!("Actual call length: {}", call_bytes.len());
        println!("Expected body length: {}", expected_body);
        println!("Actual body length: {}", body.len());

        assert_eq!(call_bytes.len(), expected_call, "Call length mismatch");
        assert_eq!(
            body.len(),
            decoded_len,
            "Body length should match decoded length"
        );
    }

    #[test]
    fn test_signature_verification() {
        use synthetic_crypto::hashes::blake2_256;
        use synthetic_crypto::ml_dsa::{MlDsaPublicKey, MlDsaSignature};
        use synthetic_crypto::traits::VerifyKey;

        // Same seed as gen_dev_account for Alice
        let seed = blake2_256(b"//Alice");
        let builder = ExtrinsicBuilder::from_seed(&seed);

        // Build a test extrinsic
        let call = ShieldCall {
            amount: 1000,
            commitment: [0u8; 32],
            encrypted_note: EncryptedNote::default(),
        };

        let metadata = ChainMetadata {
            genesis_hash: [0u8; 32],
            block_hash: [0u8; 32],
            block_number: 100,
            spec_version: 2,
            tx_version: 1,
        };

        // Encode call
        let encoded_call = builder.encode_shield_call(&call);
        println!("Encoded call length: {}", encoded_call.len());

        // Encode extra
        let era = Era::Immortal;
        let encoded_extra = builder.encode_signed_extra(0, &era, 0, &metadata);
        println!("Encoded extra length: {}", encoded_extra.len());

        // Build sign payload
        let payload = builder.build_sign_payload(&encoded_call, &encoded_extra, &metadata);
        println!("Sign payload length: {}", payload.len());
        println!("Sign payload (hex): {}", hex::encode(&payload));

        // Sign it
        let signature_encoded = builder.sign_payload(&payload);
        println!("Signature encoded length: {}", signature_encoded.len());

        // Extract signature and public key from encoded signature
        // Format: variant(1) + signature(3309) + public_variant(1) + pubkey(1952)
        assert_eq!(signature_encoded[0], 0, "Should be MlDsa variant");
        let sig_bytes = &signature_encoded[1..1 + 3309];
        assert_eq!(signature_encoded[3310], 0, "Should be MlDsa public variant");
        let pk_bytes = &signature_encoded[3311..3311 + 1952];

        // Verify the signature
        let public_key = MlDsaPublicKey::from_bytes(pk_bytes).expect("valid public key");
        let signature = MlDsaSignature::from_bytes(sig_bytes).expect("valid signature");

        let result = public_key.verify(&payload, &signature);
        println!("Signature verification: {:?}", result);
        assert!(result.is_ok(), "Signature should verify correctly");

        // Check public key matches builder's
        let builder_pk_bytes = builder.public_key.to_bytes();
        println!(
            "Builder pk first 20: {}",
            hex::encode(&builder_pk_bytes[..20])
        );
        println!("Extracted pk first 20: {}", hex::encode(&pk_bytes[..20]));
        assert_eq!(&builder_pk_bytes[..], pk_bytes, "Public key should match");

        // Verify account ID matches
        let expected_account_id = blake2_256(&builder_pk_bytes);
        println!("Builder account ID: {}", hex::encode(builder.account_id()));
        println!("Expected account ID: {}", hex::encode(&expected_account_id));
        assert_eq!(
            builder.account_id(),
            expected_account_id,
            "Account ID should match"
        );
    }

    fn decode_compact_len(data: &[u8]) -> (usize, usize) {
        let first = data[0];
        match first & 0x03 {
            0 => (1, (first >> 2) as usize),
            1 => {
                let val = u16::from_le_bytes([data[0], data[1]]);
                (2, (val >> 2) as usize)
            }
            2 => {
                let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                (4, (val >> 2) as usize)
            }
            _ => {
                // Big integer mode - for simplicity assume 4 additional bytes
                let len_bytes = ((first >> 2) + 4) as usize;
                (1 + len_bytes, 0) // Not fully implemented
            }
        }
    }
}
