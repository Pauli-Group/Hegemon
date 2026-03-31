//! Shielded Pool Pallet
//!
//! This pallet implements ZCash-like shielded transactions on Substrate.
//!
//! ## Overview
//!
//! The shielded pool allows users to:
//! - Transfer shielded funds privately inside the single PQ pool
//! - Mint shielded coinbase notes as the sole issuance path
//!
//! ## Key Components
//!
//! - **Note Commitments**: Hashed representations of notes that hide their contents
//! - **Nullifiers**: Unique identifiers for spent notes that prevent double-spending
//! - **Merkle Tree**: Stores all note commitments for membership proofs
//! - **ZK Proofs**: STARK proofs that verify transaction validity without revealing details
//!
//! ## Verification Process
//!
//! Each shielded transfer goes through:
//! 1. Anchor validation (Merkle root must be historical)
//! 2. Nullifier uniqueness check (no double-spending)
//! 3. ZK proof verification (transaction is valid)
//! 4. Binding hash verification (public inputs are committed)
//! 5. State update (add nullifiers, add commitments)

#![cfg_attr(not(feature = "std"), no_std)]

pub use inherent::*;
pub use pallet::*;

pub mod commitment;
pub mod family;
pub mod inherent;
pub mod merkle;
pub mod nullifier;
pub mod types;
pub mod verifier;

use merkle::CompactMerkleTree;
use types::{
    BindingHash, EncryptedNote, StablecoinPolicyBinding, StarkProof, VerifyingKeyParams,
    MERKLE_TREE_DEPTH,
};
use verifier::{
    BatchVerifier, ProofVerifier, ShieldedTransferInputs, VerificationResult, VerifyingKey,
};

use frame_support::dispatch::{DispatchClass, DispatchResult, Pays};
use frame_support::pallet_prelude::*;
use frame_support::traits::StorageVersion;
use frame_support::weights::Weight;
use frame_system::pallet_prelude::*;
use log::{info, warn};
use protocol_kernel::traits::{ActionSourceClass, ValidActionMeta};
use protocol_versioning::VersionBinding;
use sp_runtime::traits::Saturating;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
    ValidTransaction,
};
use sp_std::vec;
use sp_std::vec::Vec;
use transaction_core::hashing_pq::{balance_commitment_bytes, ciphertext_hash_bytes};
use transaction_core::types::BalanceSlot;

/// Zero nullifier constant.
///
/// SECURITY: Zero nullifiers are INVALID and must be rejected.
///
/// Background: STARK proofs use fixed-size traces, which historically led to
/// designs where unused slots were padded with zeros. However, this creates a
/// security vulnerability: if an attacker could craft a witness that produces
/// a zero nullifier for a real note, that note could be spent multiple times
/// (since zeros would be "skipped" during double-spend checks).
///
/// Our defense-in-depth strategy:
/// 1. Circuit layer: TransactionWitness::validate() rejects zero nullifiers
/// 2. Pallet layer: shielded transfer submission rejects any zero nullifier submission
/// 3. Cryptographic: The nullifier PRF makes zero outputs computationally infeasible
///
/// This constant exists only for detection - any occurrence is an error.
const ZERO_NULLIFIER: [u8; 48] = [0u8; 48];
const ZERO_COMMITMENT: [u8; 48] = [0u8; 48];

/// Stablecoin policy snapshot used by the shielded pool verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinPolicySnapshot<AssetId, OracleFeedId, AttestationId, BlockNumber> {
    pub asset_id: AssetId,
    pub oracle_feeds: Vec<OracleFeedId>,
    pub attestation_id: AttestationId,
    pub min_collateral_ratio_ppm: u128,
    pub max_mint_per_epoch: u128,
    pub oracle_max_age: BlockNumber,
    pub policy_version: u32,
    pub active: bool,
}

/// Provider for stablecoin policy data.
pub trait StablecoinPolicyProvider<AssetId, OracleFeedId, AttestationId, BlockNumber> {
    fn policy(
        asset_id: &AssetId,
    ) -> Option<StablecoinPolicySnapshot<AssetId, OracleFeedId, AttestationId, BlockNumber>>;
    fn policy_hash(asset_id: &AssetId) -> Option<[u8; 48]>;
}

/// Oracle commitment snapshot used by the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleCommitmentSnapshot<BlockNumber> {
    pub commitment: [u8; 48],
    pub submitted_at: BlockNumber,
}

/// Provider for oracle commitments.
pub trait OracleCommitmentProvider<FeedId, BlockNumber> {
    fn latest_commitment(feed_id: &FeedId) -> Option<OracleCommitmentSnapshot<BlockNumber>>;
}

/// Attestation commitment snapshot used by the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationCommitmentSnapshot<BlockNumber> {
    pub commitment: [u8; 48],
    pub disputed: bool,
    pub created_at: BlockNumber,
}

/// Provider for attestation commitments.
pub trait AttestationCommitmentProvider<CommitmentId, BlockNumber> {
    fn commitment(
        commitment_id: &CommitmentId,
    ) -> Option<AttestationCommitmentSnapshot<BlockNumber>>;
}

/// Check if a nullifier is the zero value (which is invalid).
fn is_zero_nullifier(nf: &[u8; 48]) -> bool {
    *nf == ZERO_NULLIFIER
}

/// Check if a commitment is the zero value (which is invalid for active outputs).
fn is_zero_commitment(cm: &[u8; 48]) -> bool {
    *cm == ZERO_COMMITMENT
}

const NATIVE_TX_STATEMENT_HASH_DOMAIN: &[u8] = b"tx-statement-v1";
const NATIVE_TX_PUBLIC_INPUTS_DIGEST_DOMAIN: &[u8] = b"tx-public-inputs-digest-v1";
const NATIVE_TX_LITE_COMMITMENT_MAX_ROWS: usize = 256;
const NATIVE_TX_LITE_COMMITMENT_MAX_COLS: usize = 256;
const NATIVE_TX_CANONICAL_PADDING_ASSET_ID: u64 = 4_294_967_294;

mod native_serde_bytes48 {
    use serde::Serializer;

    pub fn serialize<S>(value: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }
}

#[derive(Clone, Debug, serde::Serialize)]
struct NativeSerializedStarkInputsDigest {
    input_flags: Vec<u8>,
    output_flags: Vec<u8>,
    fee: u64,
    value_balance_sign: u8,
    value_balance_magnitude: u64,
    #[serde(with = "native_serde_bytes48")]
    merkle_root: [u8; 48],
    balance_slot_asset_ids: Vec<u64>,
    stablecoin_enabled: u8,
    stablecoin_asset_id: u64,
    stablecoin_policy_version: u32,
    stablecoin_issuance_sign: u8,
    stablecoin_issuance_magnitude: u64,
    #[serde(with = "native_serde_bytes48")]
    stablecoin_policy_hash: [u8; 48],
    #[serde(with = "native_serde_bytes48")]
    stablecoin_oracle_commitment: [u8; 48],
    #[serde(with = "native_serde_bytes48")]
    stablecoin_attestation_commitment: [u8; 48],
}

#[derive(Clone, Debug)]
struct NativeTxLeafReceiptLite {
    statement_hash: [u8; 48],
    proof_digest: [u8; 48],
    public_inputs_digest: [u8; 48],
    verifier_profile: [u8; 48],
}

#[derive(Clone, Debug)]
struct NativeTxLeafLite {
    receipt: NativeTxLeafReceiptLite,
    stark_inputs: NativeSerializedStarkInputsDigest,
    tx: NativeTxPublicTxLite,
}

#[derive(Clone, Debug)]
struct NativeTxPublicTxLite {
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: Vec<[u8; 48]>,
    balance_tag: [u8; 48],
    version: VersionBinding,
}

fn blake3_384_digest(message: &[u8]) -> [u8; 48] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(message);
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn read_u8_checked(bytes: &[u8], cursor: &mut usize) -> Result<u8, InvalidTransaction> {
    if *cursor >= bytes.len() {
        return Err(InvalidTransaction::BadProof);
    }
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_u16_checked(bytes: &[u8], cursor: &mut usize) -> Result<u16, InvalidTransaction> {
    if bytes.len().saturating_sub(*cursor) < 2 {
        return Err(InvalidTransaction::BadProof);
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 2]);
    *cursor += 2;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32_checked(bytes: &[u8], cursor: &mut usize) -> Result<u32, InvalidTransaction> {
    if bytes.len().saturating_sub(*cursor) < 4 {
        return Err(InvalidTransaction::BadProof);
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_checked(bytes: &[u8], cursor: &mut usize) -> Result<u64, InvalidTransaction> {
    if bytes.len().saturating_sub(*cursor) < 8 {
        return Err(InvalidTransaction::BadProof);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(u64::from_le_bytes(buf))
}

fn read_array_checked<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], InvalidTransaction> {
    if bytes.len().saturating_sub(*cursor) < N {
        return Err(InvalidTransaction::BadProof);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn read_bytes_checked(
    bytes: &[u8],
    cursor: &mut usize,
    len: usize,
) -> Result<Vec<u8>, InvalidTransaction> {
    if bytes.len().saturating_sub(*cursor) < len {
        return Err(InvalidTransaction::BadProof);
    }
    let out = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

fn decode_native_tx_leaf_lite(
    proof_bytes: &[u8],
) -> Result<Option<NativeTxLeafLite>, InvalidTransaction> {
    let mut cursor = 0usize;
    let _version = read_u16_checked(proof_bytes, &mut cursor)?;
    let _params_fingerprint = read_array_checked::<48>(proof_bytes, &mut cursor)?;
    let _spec_digest = read_array_checked::<32>(proof_bytes, &mut cursor)?;
    let _relation_id = read_array_checked::<32>(proof_bytes, &mut cursor)?;
    let _shape_digest = read_array_checked::<32>(proof_bytes, &mut cursor)?;
    let _statement_digest = read_array_checked::<48>(proof_bytes, &mut cursor)?;
    let receipt = NativeTxLeafReceiptLite {
        statement_hash: read_array_checked::<48>(proof_bytes, &mut cursor)?,
        proof_digest: read_array_checked::<48>(proof_bytes, &mut cursor)?,
        public_inputs_digest: read_array_checked::<48>(proof_bytes, &mut cursor)?,
        verifier_profile: read_array_checked::<48>(proof_bytes, &mut cursor)?,
    };
    let input_flag_count = read_u32_checked(proof_bytes, &mut cursor)? as usize;
    if input_flag_count > transaction_core::constants::MAX_INPUTS {
        return Ok(None);
    }
    let input_flags = read_bytes_checked(proof_bytes, &mut cursor, input_flag_count)?;
    let output_flag_count = read_u32_checked(proof_bytes, &mut cursor)? as usize;
    if output_flag_count > transaction_core::constants::MAX_OUTPUTS {
        return Ok(None);
    }
    let output_flags = read_bytes_checked(proof_bytes, &mut cursor, output_flag_count)?;
    let fee = read_u64_checked(proof_bytes, &mut cursor)?;
    let value_balance_sign = read_u8_checked(proof_bytes, &mut cursor)?;
    let value_balance_magnitude = read_u64_checked(proof_bytes, &mut cursor)?;
    let merkle_root = read_array_checked::<48>(proof_bytes, &mut cursor)?;
    let balance_slot_count = read_u32_checked(proof_bytes, &mut cursor)? as usize;
    if balance_slot_count > transaction_core::constants::BALANCE_SLOTS {
        return Ok(None);
    }
    let mut balance_slot_asset_ids = Vec::with_capacity(balance_slot_count);
    for _ in 0..balance_slot_count {
        balance_slot_asset_ids.push(read_u64_checked(proof_bytes, &mut cursor)?);
    }
    let stark_inputs = NativeSerializedStarkInputsDigest {
        input_flags,
        output_flags,
        fee,
        value_balance_sign,
        value_balance_magnitude,
        merkle_root,
        balance_slot_asset_ids,
        stablecoin_enabled: read_u8_checked(proof_bytes, &mut cursor)?,
        stablecoin_asset_id: read_u64_checked(proof_bytes, &mut cursor)?,
        stablecoin_policy_version: read_u32_checked(proof_bytes, &mut cursor)?,
        stablecoin_issuance_sign: read_u8_checked(proof_bytes, &mut cursor)?,
        stablecoin_issuance_magnitude: read_u64_checked(proof_bytes, &mut cursor)?,
        stablecoin_policy_hash: read_array_checked::<48>(proof_bytes, &mut cursor)?,
        stablecoin_oracle_commitment: read_array_checked::<48>(proof_bytes, &mut cursor)?,
        stablecoin_attestation_commitment: read_array_checked::<48>(proof_bytes, &mut cursor)?,
    };
    let nullifier_count = read_u32_checked(proof_bytes, &mut cursor)? as usize;
    if nullifier_count > transaction_core::constants::MAX_INPUTS {
        return Ok(None);
    }
    let mut tx_nullifiers = Vec::with_capacity(nullifier_count);
    for _ in 0..nullifier_count {
        tx_nullifiers.push(read_array_checked::<48>(proof_bytes, &mut cursor)?);
    }
    let commitment_count = read_u32_checked(proof_bytes, &mut cursor)? as usize;
    if commitment_count > transaction_core::constants::MAX_OUTPUTS {
        return Ok(None);
    }
    let mut tx_commitments = Vec::with_capacity(commitment_count);
    for _ in 0..commitment_count {
        tx_commitments.push(read_array_checked::<48>(proof_bytes, &mut cursor)?);
    }
    let ciphertext_hash_count = read_u32_checked(proof_bytes, &mut cursor)? as usize;
    if ciphertext_hash_count > transaction_core::constants::MAX_OUTPUTS {
        return Ok(None);
    }
    let mut tx_ciphertext_hashes = Vec::with_capacity(ciphertext_hash_count);
    for _ in 0..ciphertext_hash_count {
        tx_ciphertext_hashes.push(read_array_checked::<48>(proof_bytes, &mut cursor)?);
    }
    let tx_balance_tag = read_array_checked::<48>(proof_bytes, &mut cursor)?;
    let tx_version = VersionBinding {
        circuit: read_u16_checked(proof_bytes, &mut cursor)?,
        crypto: read_u16_checked(proof_bytes, &mut cursor)?,
    };
    let proof_len = read_u32_checked(proof_bytes, &mut cursor)? as usize;
    if proof_len > crate::types::STARK_PROOF_MAX_SIZE {
        return Ok(None);
    }
    let _proof = read_bytes_checked(proof_bytes, &mut cursor, proof_len)?;
    let _commitment_digest = read_array_checked::<48>(proof_bytes, &mut cursor)?;
    let commitment_row_count = read_u32_checked(proof_bytes, &mut cursor)? as usize;
    if commitment_row_count > NATIVE_TX_LITE_COMMITMENT_MAX_ROWS {
        return Ok(None);
    }
    for _ in 0..commitment_row_count {
        let coeff_count = read_u32_checked(proof_bytes, &mut cursor)? as usize;
        if coeff_count > NATIVE_TX_LITE_COMMITMENT_MAX_COLS {
            return Ok(None);
        }
        for _ in 0..coeff_count {
            let _coeff = read_u64_checked(proof_bytes, &mut cursor)?;
        }
    }
    let _leaf_version = read_u16_checked(proof_bytes, &mut cursor)?;
    let _leaf_relation_id = read_array_checked::<32>(proof_bytes, &mut cursor)?;
    let _leaf_shape_digest = read_array_checked::<32>(proof_bytes, &mut cursor)?;
    let _leaf_statement_digest = read_array_checked::<48>(proof_bytes, &mut cursor)?;
    let _leaf_witness_commitment_digest = read_array_checked::<48>(proof_bytes, &mut cursor)?;
    let _leaf_proof_digest = read_array_checked::<48>(proof_bytes, &mut cursor)?;
    if cursor != proof_bytes.len() {
        return Err(InvalidTransaction::BadProof);
    }
    Ok(Some(NativeTxLeafLite {
        receipt,
        stark_inputs,
        tx: NativeTxPublicTxLite {
            nullifiers: tx_nullifiers,
            commitments: tx_commitments,
            ciphertext_hashes: tx_ciphertext_hashes,
            balance_tag: tx_balance_tag,
            version: tx_version,
        },
    }))
}

fn signed_magnitude_to_i128(sign: u8, magnitude: u64) -> Result<i128, InvalidTransaction> {
    match sign {
        0 => Ok(i128::from(magnitude)),
        1 => Ok(-i128::from(magnitude)),
        _ => Err(InvalidTransaction::BadProof),
    }
}

fn canonicalize_native_balance_slot_asset_id(asset_id: u64) -> u64 {
    if asset_id == u64::MAX {
        NATIVE_TX_CANONICAL_PADDING_ASSET_ID
    } else {
        asset_id
    }
}

fn canonical_balance_slots_from_public_args(
    balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    fee: u64,
    value_balance: i128,
    stablecoin: &Option<StablecoinPolicyBinding>,
) -> Result<Vec<BalanceSlot>, InvalidTransaction> {
    use transaction_core::constants::NATIVE_ASSET_ID;

    let canonical_asset_ids = balance_slot_asset_ids.map(canonicalize_native_balance_slot_asset_id);

    if canonical_asset_ids[0] != NATIVE_ASSET_ID {
        return Err(InvalidTransaction::BadProof);
    }

    let mut saw_padding = false;
    let mut prev_asset = NATIVE_ASSET_ID;
    for asset_id in canonical_asset_ids.iter().skip(1) {
        if *asset_id == NATIVE_TX_CANONICAL_PADDING_ASSET_ID {
            saw_padding = true;
            continue;
        }
        if saw_padding || *asset_id == NATIVE_ASSET_ID || *asset_id <= prev_asset {
            return Err(InvalidTransaction::BadProof);
        }
        prev_asset = *asset_id;
    }

    if let Some(binding) = stablecoin {
        if !canonical_asset_ids[1..].contains(&binding.asset_id) {
            return Err(InvalidTransaction::BadProof);
        }
    }

    let native_delta = i128::from(fee) - value_balance;
    Ok(canonical_asset_ids
        .into_iter()
        .map(|asset_id| {
            let delta = match stablecoin {
                Some(binding) if asset_id == binding.asset_id => binding.issuance_delta,
                _ if asset_id == NATIVE_ASSET_ID => native_delta,
                _ => 0,
            };
            BalanceSlot { asset_id, delta }
        })
        .collect())
}

fn verify_native_stark_inputs_match_public_args(
    stark_inputs: &NativeSerializedStarkInputsDigest,
    input_count: usize,
    output_count: usize,
    anchor: &[u8; 48],
    balance_slot_asset_ids: &[u64; transaction_core::constants::BALANCE_SLOTS],
    stablecoin: &Option<StablecoinPolicyBinding>,
    fee: u64,
) -> Result<(), InvalidTransaction> {
    let canonical_balance_slot_asset_ids =
        balance_slot_asset_ids.map(canonicalize_native_balance_slot_asset_id);
    if stark_inputs.input_flags.len() != transaction_core::constants::MAX_INPUTS
        || stark_inputs.output_flags.len() != transaction_core::constants::MAX_OUTPUTS
        || stark_inputs.balance_slot_asset_ids.len() != transaction_core::constants::BALANCE_SLOTS
    {
        return Err(InvalidTransaction::BadProof);
    }
    for (idx, flag) in stark_inputs.input_flags.iter().enumerate() {
        let expected = u8::from(idx < input_count);
        if *flag != expected {
            return Err(InvalidTransaction::BadProof);
        }
    }
    for (idx, flag) in stark_inputs.output_flags.iter().enumerate() {
        let expected = u8::from(idx < output_count);
        if *flag != expected {
            return Err(InvalidTransaction::BadProof);
        }
    }
    if stark_inputs.fee != fee
        || stark_inputs.value_balance_sign != 0
        || stark_inputs.value_balance_magnitude != 0
        || stark_inputs.merkle_root != *anchor
        || stark_inputs.balance_slot_asset_ids.as_slice() != canonical_balance_slot_asset_ids
    {
        return Err(InvalidTransaction::BadProof);
    }

    match stablecoin {
        Some(binding) => {
            let (issuance_sign, issuance_magnitude) = if binding.issuance_delta < 0 {
                (1u8, binding.issuance_delta.unsigned_abs() as u64)
            } else {
                (0u8, binding.issuance_delta.unsigned_abs() as u64)
            };
            if stark_inputs.stablecoin_enabled != 1
                || stark_inputs.stablecoin_asset_id != binding.asset_id
                || stark_inputs.stablecoin_policy_version != binding.policy_version
                || stark_inputs.stablecoin_issuance_sign != issuance_sign
                || stark_inputs.stablecoin_issuance_magnitude != issuance_magnitude
                || stark_inputs.stablecoin_policy_hash != binding.policy_hash
                || stark_inputs.stablecoin_oracle_commitment != binding.oracle_commitment
                || stark_inputs.stablecoin_attestation_commitment != binding.attestation_commitment
            {
                return Err(InvalidTransaction::BadProof);
            }
        }
        _ => {
            if stark_inputs.stablecoin_enabled != 0
                || stark_inputs.stablecoin_asset_id != 0
                || stark_inputs.stablecoin_policy_version != 0
                || stark_inputs.stablecoin_issuance_sign != 0
                || stark_inputs.stablecoin_issuance_magnitude != 0
                || stark_inputs.stablecoin_policy_hash != [0u8; 48]
                || stark_inputs.stablecoin_oracle_commitment != [0u8; 48]
                || stark_inputs.stablecoin_attestation_commitment != [0u8; 48]
            {
                return Err(InvalidTransaction::BadProof);
            }
        }
    }

    Ok(())
}

fn native_public_inputs_digest(
    stark_inputs: &NativeSerializedStarkInputsDigest,
) -> Result<[u8; 48], InvalidTransaction> {
    let encoded = postcard::to_allocvec(stark_inputs).map_err(|_| InvalidTransaction::BadProof)?;
    let mut message =
        Vec::with_capacity(NATIVE_TX_PUBLIC_INPUTS_DIGEST_DOMAIN.len() + encoded.len());
    message.extend_from_slice(NATIVE_TX_PUBLIC_INPUTS_DIGEST_DOMAIN);
    message.extend_from_slice(&encoded);
    Ok(blake3_384_digest(&message))
}

fn native_statement_hash_from_public_args(
    nullifiers: &[[u8; 48]],
    commitments: &[[u8; 48]],
    ciphertext_hashes: &[[u8; 48]],
    balance_tag: &[u8; 48],
    version: VersionBinding,
    stark_inputs: &NativeSerializedStarkInputsDigest,
) -> Result<[u8; 48], InvalidTransaction> {
    if nullifiers.len() > transaction_core::constants::MAX_INPUTS
        || commitments.len() > transaction_core::constants::MAX_OUTPUTS
        || ciphertext_hashes.len() > transaction_core::constants::MAX_OUTPUTS
    {
        return Err(InvalidTransaction::BadProof);
    }
    let value_balance = signed_magnitude_to_i128(
        stark_inputs.value_balance_sign,
        stark_inputs.value_balance_magnitude,
    )?;
    let stablecoin_issuance = signed_magnitude_to_i128(
        stark_inputs.stablecoin_issuance_sign,
        stark_inputs.stablecoin_issuance_magnitude,
    )?;

    let mut message = Vec::new();
    message.extend_from_slice(NATIVE_TX_STATEMENT_HASH_DOMAIN);
    message.extend_from_slice(&stark_inputs.merkle_root);
    for nf in nullifiers {
        message.extend_from_slice(nf);
    }
    for _ in nullifiers.len()..transaction_core::constants::MAX_INPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }
    for cm in commitments {
        message.extend_from_slice(cm);
    }
    for _ in commitments.len()..transaction_core::constants::MAX_OUTPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }
    for ct in ciphertext_hashes {
        message.extend_from_slice(ct);
    }
    for _ in ciphertext_hashes.len()..transaction_core::constants::MAX_OUTPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }
    message.extend_from_slice(&stark_inputs.fee.to_le_bytes());
    message.extend_from_slice(&value_balance.to_le_bytes());
    message.extend_from_slice(balance_tag);
    message.extend_from_slice(&version.circuit.to_le_bytes());
    message.extend_from_slice(&version.crypto.to_le_bytes());
    message.push(stark_inputs.stablecoin_enabled);
    message.extend_from_slice(&stark_inputs.stablecoin_asset_id.to_le_bytes());
    message.extend_from_slice(&stark_inputs.stablecoin_policy_hash);
    message.extend_from_slice(&stark_inputs.stablecoin_oracle_commitment);
    message.extend_from_slice(&stark_inputs.stablecoin_attestation_commitment);
    message.extend_from_slice(&stablecoin_issuance.to_le_bytes());
    message.extend_from_slice(&stark_inputs.stablecoin_policy_version.to_le_bytes());
    Ok(blake3_384_digest(&message))
}

fn kem_ciphertext_len_for_suite(crypto_suite: u16) -> Option<usize> {
    match crypto_suite {
        crate::types::CRYPTO_SUITE_GAMMA => Some(crate::types::MAX_KEM_CIPHERTEXT_LEN as usize),
        _ => None,
    }
}

/// Weight information for pallet extrinsics.
pub trait WeightInfo {
    fn shielded_transfer(nullifiers: u32, commitments: u32) -> Weight;
    fn mint_coinbase() -> Weight;
    fn update_verifying_key() -> Weight;
    fn set_da_policy() -> Weight;
    fn set_ciphertext_policy() -> Weight;
    fn set_proof_availability_policy() -> Weight;
}

/// Default weight implementation.
pub struct DefaultWeightInfo;

impl WeightInfo for DefaultWeightInfo {
    fn shielded_transfer(nullifiers: u32, commitments: u32) -> Weight {
        // Base weight + per-nullifier + per-commitment
        Weight::from_parts(
            100_000_000 + (nullifiers as u64 * 10_000_000) + (commitments as u64 * 10_000_000),
            0,
        )
    }

    fn mint_coinbase() -> Weight {
        Weight::from_parts(50_000_000, 0)
    }

    fn update_verifying_key() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn set_da_policy() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn set_ciphertext_policy() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn set_proof_availability_policy() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::large_enum_variant)]
#[frame_support::pallet]
pub mod pallet {
    use super::*;

    /// Current storage version.
    pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Proof verifier implementation.
        type ProofVerifier: ProofVerifier + Default;

        /// Batch proof verifier implementation.
        type BatchProofVerifier: verifier::BatchVerifier + Default;

        /// Maximum nullifiers per transaction.
        #[pallet::constant]
        type MaxNullifiersPerTx: Get<u32>;

        /// Maximum commitments per transaction.
        #[pallet::constant]
        type MaxCommitmentsPerTx: Get<u32>;

        /// Maximum encrypted notes per transaction.
        #[pallet::constant]
        type MaxEncryptedNotesPerTx: Get<u32>;

        /// Maximum nullifiers per batch (batch_size * MaxNullifiersPerTx).
        #[pallet::constant]
        type MaxNullifiersPerBatch: Get<u32>;

        /// Maximum commitments per batch (batch_size * MaxCommitmentsPerTx).
        #[pallet::constant]
        type MaxCommitmentsPerBatch: Get<u32>;

        /// Number of historical Merkle roots to keep.
        #[pallet::constant]
        type MerkleRootHistorySize: Get<u32>;

        /// Maximum shielded coinbase subsidy per block (safety cap).
        #[pallet::constant]
        type MaxCoinbaseSubsidy: Get<u64>;

        /// Asset id type for stablecoin policy lookups.
        type StablecoinAssetId: Parameter
            + Member
            + MaxEncodedLen
            + TypeInfo
            + Copy
            + Ord
            + TryFrom<u64>;

        /// Oracle feed id type for stablecoin policy lookups.
        type OracleFeedId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord;

        /// Attestation commitment id type for stablecoin policy lookups.
        type AttestationId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord;

        /// Provider for stablecoin policy data.
        type StablecoinPolicyProvider: StablecoinPolicyProvider<
            Self::StablecoinAssetId,
            Self::OracleFeedId,
            Self::AttestationId,
            BlockNumberFor<Self>,
        >;

        /// Provider for oracle commitments.
        type OracleCommitmentProvider: OracleCommitmentProvider<
            Self::OracleFeedId,
            BlockNumberFor<Self>,
        >;

        /// Provider for attestation commitments.
        type AttestationCommitmentProvider: AttestationCommitmentProvider<
            Self::AttestationId,
            BlockNumberFor<Self>,
        >;

        /// Weight information.
        type WeightInfo: WeightInfo;
    }

    /// The Merkle tree for note commitments.
    #[pallet::storage]
    #[pallet::getter(fn merkle_tree)]
    pub type MerkleTree<T: Config> = StorageValue<_, CompactMerkleTree, ValueQuery>;

    /// Historical Merkle roots (for anchor validation).
    /// Maps root hash to the block number when it was valid.
    #[pallet::storage]
    #[pallet::getter(fn merkle_roots)]
    pub type MerkleRoots<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 48], BlockNumberFor<T>, OptionQuery>;

    /// Ordered history of recent Merkle roots (bounded by MerkleRootHistorySize).
    #[pallet::storage]
    #[pallet::getter(fn merkle_root_history)]
    pub type MerkleRootHistory<T: Config> =
        StorageValue<_, BoundedVec<[u8; 48], T::MerkleRootHistorySize>, ValueQuery>;

    /// Current commitment index (number of commitments in the tree).
    #[pallet::storage]
    #[pallet::getter(fn commitment_index)]
    pub type CommitmentIndex<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Nullifier set - tracks spent notes.
    /// If a nullifier exists in this map, the note has been spent.
    #[pallet::storage]
    #[pallet::getter(fn nullifiers)]
    pub type Nullifiers<T: Config> = StorageMap<_, Blake2_128Concat, [u8; 48], (), OptionQuery>;

    /// Note commitments by index.
    #[pallet::storage]
    #[pallet::getter(fn commitments)]
    pub type Commitments<T: Config> = StorageMap<_, Blake2_128Concat, u64, [u8; 48], OptionQuery>;

    /// Encrypted notes for recipients to scan.
    #[pallet::storage]
    #[pallet::getter(fn encrypted_notes)]
    pub type EncryptedNotes<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, EncryptedNote, OptionQuery>;

    /// Current verifying key parameters.
    #[pallet::storage]
    #[pallet::getter(fn verifying_key_params)]
    pub type VerifyingKeyParamsStorage<T: Config> = StorageValue<_, VerifyingKeyParams, ValueQuery>;

    /// Verifying key data (stored separately due to size).
    #[pallet::storage]
    #[pallet::getter(fn verifying_key)]
    pub type VerifyingKeyStorage<T: Config> = StorageValue<_, VerifyingKey, ValueQuery>;

    /// Total shielded pool balance.
    #[pallet::storage]
    #[pallet::getter(fn pool_balance)]
    pub type PoolBalance<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Split shielded fee buckets accumulated in the current block.
    #[pallet::storage]
    #[pallet::getter(fn block_fee_buckets)]
    pub type BlockFeeBucketsStorage<T: Config> =
        StorageValue<_, types::BlockFeeBuckets, ValueQuery>;

    /// Total fees burned because no coinbase claimed them.
    #[pallet::storage]
    #[pallet::getter(fn total_fees_burned)]
    pub type TotalFeesBurned<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Coinbase notes indexed by commitment index (for audit purposes).
    #[pallet::storage]
    #[pallet::getter(fn coinbase_notes)]
    pub type CoinbaseNotes<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, types::BlockRewardBundle, OptionQuery>;

    /// Whether coinbase was already processed this block (prevents double-mint).
    #[pallet::storage]
    pub type CoinbaseProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Whether any shielded transfers have been processed this block.
    #[pallet::storage]
    pub type ShieldedTransfersProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Whether a proven-batch payload was already submitted this block.
    ///
    /// Reset on `on_initialize` so exactly one proven-batch payload can be attached per block.
    #[pallet::storage]
    pub type ProvenBatchProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Whether this block is operating in "aggregation required" mode.
    ///
    /// When enabled, shielded transfers may omit per-transaction proof verification in the runtime
    /// (the node is expected to verify an aggregation proof during block import).
    ///
    /// Reset on `on_initialize` so it must be explicitly enabled per block.
    #[pallet::storage]
    pub type AggregationProofRequired<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// DA commitments per block (da_root + chunk count) for archive audits.
    #[pallet::storage]
    #[pallet::getter(fn da_commitment)]
    pub type DaCommitments<T: Config> =
        StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, types::DaCommitment, OptionQuery>;

    /// DA availability policy (full fetch vs sampling).
    #[pallet::storage]
    #[pallet::getter(fn da_policy)]
    pub type DaPolicyStorage<T: Config> = StorageValue<_, types::DaAvailabilityPolicy, ValueQuery>;

    /// Ciphertext policy (inline vs sidecar-only).
    #[pallet::storage]
    #[pallet::getter(fn ciphertext_policy)]
    pub type CiphertextPolicyStorage<T: Config> =
        StorageValue<_, types::CiphertextPolicy, ValueQuery>;

    /// Proof availability policy (inline vs DA-available in aggregation mode).
    #[pallet::storage]
    #[pallet::getter(fn proof_availability_policy)]
    pub type ProofAvailabilityPolicyStorage<T: Config> =
        StorageValue<_, types::ProofAvailabilityPolicy, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A shielded transfer was executed.
        ShieldedTransfer {
            /// Number of nullifiers (spent notes).
            nullifier_count: u32,
            /// Number of new commitments.
            commitment_count: u32,
            /// Net value change (must be 0 when no transparent pool is enabled).
            value_balance: i128,
        },

        /// A new commitment was added to the tree.
        CommitmentAdded {
            /// Index of the commitment.
            index: u64,
            /// The commitment hash.
            commitment: [u8; 48],
        },

        /// A nullifier was added (note was spent).
        NullifierAdded {
            /// The nullifier hash.
            nullifier: [u8; 48],
        },

        /// Merkle root was updated.
        MerkleRootUpdated {
            /// New Merkle root.
            root: [u8; 48],
        },

        /// Coinbase reward minted directly to shielded pool.
        CoinbaseMinted {
            /// Commitment index of the new note.
            commitment_index: u64,
            /// Amount minted.
            amount: u64,
            /// Block height.
            block_number: BlockNumberFor<T>,
        },

        /// A batch shielded transfer was executed.
        BatchShieldedTransfer {
            /// Number of transactions in the batch.
            batch_size: u32,
            /// Total number of nullifiers across all transactions.
            nullifier_count: u32,
            /// Total number of new commitments.
            commitment_count: u32,
            /// Total optional miner tip across all transactions.
            total_fee: u128,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Invalid proof format.
        InvalidProofFormat,
        /// Proof verification failed.
        ProofVerificationFailed,
        /// Anchor (Merkle root) is not a valid historical root.
        InvalidAnchor,
        /// Nullifier already exists (double-spend attempt).
        NullifierAlreadyExists,
        /// Duplicate nullifier in transaction.
        DuplicateNullifierInTx,
        /// Binding signature verification failed.
        InvalidBindingHash,
        /// Merkle tree is full.
        MerkleTreeFull,
        /// Merkle root history is full (history size too small).
        MerkleRootHistoryFull,
        /// Invalid number of nullifiers.
        InvalidNullifierCount,
        /// Invalid number of commitments.
        InvalidCommitmentCount,
        /// Encrypted notes count doesn't match commitments.
        EncryptedNotesMismatch,
        /// Ciphertext hash count doesn't match commitments.
        CiphertextHashCountMismatch,
        /// Ciphertext size count doesn't match commitments.
        CiphertextSizeCountMismatch,
        /// Ciphertext size exceeds allowed bounds.
        InvalidCiphertextSize,
        /// Ciphertext hash is zero (padding only).
        ZeroCiphertextHash,
        /// Encrypted note uses an unsupported version.
        UnsupportedNoteVersion,
        /// Encrypted note uses an unsupported crypto suite.
        UnsupportedNoteCryptoSuite,
        /// Encrypted note KEM ciphertext length is invalid.
        InvalidKemCiphertextLength,
        /// Transparent pool operations are disabled (value_balance must be zero).
        TransparentPoolDisabled,
        /// Stablecoin asset id cannot be mapped into runtime AssetId.
        StablecoinAssetIdInvalid,
        /// Stablecoin policy is missing for the requested asset.
        StablecoinPolicyMissing,
        /// Stablecoin policy is inactive.
        StablecoinPolicyInactive,
        /// Stablecoin policy hash or version mismatch.
        StablecoinPolicyMismatch,
        /// Stablecoin policy oracle feed configuration is invalid.
        StablecoinPolicyInvalid,
        /// Stablecoin oracle commitment missing.
        StablecoinOracleCommitmentMissing,
        /// Stablecoin oracle commitment is stale.
        StablecoinOracleCommitmentStale,
        /// Stablecoin oracle commitment mismatch.
        StablecoinOracleCommitmentMismatch,
        /// Stablecoin attestation commitment missing.
        StablecoinAttestationMissing,
        /// Stablecoin attestation is disputed.
        StablecoinAttestationDisputed,
        /// Stablecoin attestation commitment mismatch.
        StablecoinAttestationCommitmentMismatch,
        /// Commitment bytes are not a canonical field encoding.
        InvalidCommitmentEncoding,
        /// Verifying key not found or disabled.
        VerifyingKeyNotFound,
        /// Coinbase commitment verification failed.
        InvalidCoinbaseCommitment,
        /// Coinbase already processed for this block.
        CoinbaseAlreadyProcessed,
        /// Proven batch payload already submitted for this block.
        ProvenBatchAlreadyProcessed,
        /// Aggregation proof mode was already enabled for this block.
        AggregationModeAlreadyEnabled,
        /// Aggregation proof mode must be enabled before transfers.
        AggregationModeAfterTransfers,
        /// Coinbase amount exceeds the configured safety cap.
        CoinbaseSubsidyExceedsLimit,
        /// Coinbase amount does not match the expected subsidy + fees.
        CoinbaseAmountMismatch,
        /// Fee accumulator overflowed while recording block fees.
        FeeOverflow,
        /// Shielded transfers cannot appear after coinbase in a block.
        TransfersAfterCoinbase,
        /// Zero nullifier submitted (security violation - zero nullifiers are padding only).
        /// This error indicates a malicious attempt to bypass double-spend protection.
        ZeroNullifierSubmitted,
        /// Zero commitment submitted (invalid output commitment).
        ZeroCommitmentSubmitted,
        /// Proof exceeds maximum allowed size.
        /// This prevents DoS attacks via oversized proofs that consume verification resources.
        ProofTooLarge,
        /// Proof bytes are required by policy but missing.
        ProofBytesRequired,
        /// Inline ciphertexts are disabled; sidecar-only is enforced.
        InlineCiphertextsDisabled,
        /// DA chunk count is invalid for this block.
        InvalidDaChunkCount,
        /// Invalid batch size (must be power of 2: 2, 4, 8, 16, or 32).
        InvalidBatchSize,
        // ========================================
        // EPOCH ERRORS
        // ========================================
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// Initial verifying key.
        pub verifying_key: Option<VerifyingKey>,
        /// Initial DA policy (full fetch vs sampling).
        pub da_policy: Option<types::DaAvailabilityPolicy>,
        /// Initial ciphertext policy (inline vs sidecar-only).
        pub ciphertext_policy: Option<types::CiphertextPolicy>,
        /// Initial proof availability policy.
        pub proof_availability_policy: Option<types::ProofAvailabilityPolicy>,
        /// Phantom data.
        #[serde(skip)]
        pub _phantom: PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            // Initialize Merkle tree
            let tree = CompactMerkleTree::new();
            MerkleTree::<T>::put(tree.clone());

            // Store initial root as valid
            MerkleRoots::<T>::insert(tree.root(), BlockNumberFor::<T>::from(0u32));
            if T::MerkleRootHistorySize::get() > 0 {
                let mut history: BoundedVec<[u8; 48], T::MerkleRootHistorySize> =
                    BoundedVec::default();
                let _ = history.try_push(tree.root());
                MerkleRootHistory::<T>::put(history);
            }

            // Initialize verifying key if provided
            if let Some(ref vk) = self.verifying_key {
                VerifyingKeyStorage::<T>::put(vk.clone());
                VerifyingKeyParamsStorage::<T>::put(VerifyingKeyParams {
                    key_id: vk.id,
                    active: vk.enabled,
                    activated_at: 0,
                });
            }

            DaPolicyStorage::<T>::put(self.da_policy.unwrap_or_default());
            CiphertextPolicyStorage::<T>::put(self.ciphertext_policy.unwrap_or_default());
            ProofAvailabilityPolicyStorage::<T>::put(
                self.proof_availability_policy.unwrap_or_default(),
            );
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain > STORAGE_VERSION {
                warn!(
                    target: "shielded-pool",
                    "Skipping migration: on-chain version {:?} newer than code {:?}",
                    on_chain, STORAGE_VERSION
                );
                return Weight::zero();
            }

            if on_chain < STORAGE_VERSION {
                info!(target: "shielded-pool", "Migrating from {:?} to {:?}", on_chain, STORAGE_VERSION);
                let mut weight = Weight::zero();
                let history_limit = T::MerkleRootHistorySize::get() as usize;
                if history_limit > 0 {
                    let mut roots: Vec<([u8; 48], BlockNumberFor<T>)> =
                        MerkleRoots::<T>::iter().collect();
                    roots.sort_by_key(|(_, block)| *block);
                    let keep_start = roots.len().saturating_sub(history_limit);
                    let (to_remove, to_keep) = roots.split_at(keep_start);
                    for (root, _) in to_remove {
                        MerkleRoots::<T>::remove(root);
                    }
                    let mut history: BoundedVec<[u8; 48], T::MerkleRootHistorySize> =
                        BoundedVec::default();
                    for (root, _) in to_keep {
                        let _ = history.try_push(*root);
                    }
                    MerkleRootHistory::<T>::put(history);

                    weight = weight.saturating_add(
                        T::DbWeight::get()
                            .reads_writes((roots.len() as u64) + 1, (to_remove.len() as u64) + 2),
                    );
                }
                STORAGE_VERSION.put::<Pallet<T>>();
                weight
            } else {
                Weight::zero()
            }
        }

        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            let pending_buckets = BlockFeeBucketsStorage::<T>::get();
            let pending_total = pending_buckets.miner_fees;
            if pending_total > 0 && !CoinbaseProcessed::<T>::get() {
                TotalFeesBurned::<T>::mutate(|total| *total = total.saturating_add(pending_total));
            }

            BlockFeeBucketsStorage::<T>::kill();
            // Reset coinbase processed flag at start of each block
            CoinbaseProcessed::<T>::kill();
            ShieldedTransfersProcessed::<T>::kill();
            ProvenBatchProcessed::<T>::kill();
            AggregationProofRequired::<T>::kill();
            Weight::from_parts(1_000, 0)
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Enable aggregation-required mode for this block.
        ///
        /// This is an inherent-style unsigned extrinsic (`None` origin) used to mark that
        /// shielded transfers in this block are validated by an aggregation proof verified in the
        /// node's import pipeline (not by per-transaction proof verification in the runtime).
        ///
        /// The node is responsible for ensuring the corresponding aggregation proof is present
        /// and verified during block import.
        #[pallet::call_index(13)]
        #[pallet::weight((Weight::from_parts(1_000, 0), DispatchClass::Mandatory, Pays::No))]
        pub fn enable_aggregation_mode(origin: OriginFor<T>) -> DispatchResult {
            ensure_none(origin)?;
            Self::apply_enable_aggregation_mode_action()
        }

        /// Attach the proven-batch payload for this block.
        ///
        /// This is an inherent-style unsigned extrinsic (`None` origin) used to carry all
        /// consensus proof material for a self-contained aggregation block.
        ///
        /// The runtime does **not** verify the proofs; verification is performed in the node.
        #[pallet::call_index(1)]
        #[pallet::weight((Weight::from_parts(1_000, 0), DispatchClass::Mandatory, Pays::No))]
        pub fn submit_proven_batch(
            origin: OriginFor<T>,
            payload: types::BlockProofBundle,
        ) -> DispatchResult {
            ensure_none(origin)?;
            Self::apply_submit_proven_batch_action(payload)
        }

        /// Mint coinbase reward directly to the shielded pool.
        ///
        /// This is an inherent extrinsic that creates shielded reward notes.
        /// Unlike regular shielded transfers, this creates new coins (no transparent input).
        ///
        /// # Arguments
        /// * `reward_bundle` - Miner reward note
        ///
        /// # Security
        /// - Called via inherent (None origin)
        /// - Can only be called once per block
        /// - Commitment is verified against plaintext data
        #[pallet::call_index(3)]
        #[pallet::weight((T::WeightInfo::mint_coinbase(), DispatchClass::Mandatory, Pays::No))]
        pub fn mint_coinbase(
            origin: OriginFor<T>,
            reward_bundle: types::BlockRewardBundle,
        ) -> DispatchResult {
            // Inherent extrinsics use None origin
            ensure_none(origin)?;
            Self::apply_mint_coinbase_action(reward_bundle)
        }

        /// Execute an unsigned shielded-to-shielded transfer.
        ///
        /// This is the privacy-preserving transfer function that does NOT require
        /// a transparent account. The ZK proof authenticates the spend, so no
        /// external signature is needed. This follows the Zcash model where
        /// shielded-to-shielded transfers are inherently authenticated by the proof.
        ///
        /// IMPORTANT: This call ONLY works for pure shielded transfers where
        /// value_balance = 0 (no value entering or leaving the shielded pool).
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::shielded_transfer(
            nullifiers.len() as u32,
            commitments.len() as u32
        ))]
        pub fn shielded_transfer_unsigned(
            origin: OriginFor<T>,
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertexts: BoundedVec<EncryptedNote, T::MaxEncryptedNotesPerTx>,
            anchor: [u8; 48],
            balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> DispatchResult {
            // This is an unsigned extrinsic - no signer required
            ensure_none(origin)?;
            Self::apply_shielded_transfer_unsigned_action(
                proof,
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                balance_slot_asset_ids,
                binding_hash,
                stablecoin,
                fee,
                protocol_versioning::DEFAULT_VERSION_BINDING,
            )
        }

        /// Execute an unsigned shielded transfer where ciphertext bytes live in the DA sidecar.
        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::shielded_transfer(
            nullifiers.len() as u32,
            commitments.len() as u32
        ))]
        pub fn shielded_transfer_unsigned_sidecar(
            origin: OriginFor<T>,
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_hashes: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_sizes: BoundedVec<u32, T::MaxCommitmentsPerTx>,
            anchor: [u8; 48],
            balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> DispatchResult {
            // This is an unsigned extrinsic - no signer required
            ensure_none(origin)?;
            Self::apply_shielded_transfer_unsigned_sidecar_action(
                proof,
                nullifiers,
                commitments,
                ciphertext_hashes,
                ciphertext_sizes,
                anchor,
                balance_slot_asset_ids,
                binding_hash,
                stablecoin,
                fee,
            )
        }

        /// Submit a batch of shielded transfers with a single aggregated proof.
        ///
        /// This extrinsic allows multiple shielded transfers to be submitted together
        /// with a single STARK proof that covers all transactions. This significantly
        /// reduces verification costs from O(N) to O(1).
        ///
        /// # Arguments
        /// * `proof` - The batch STARK proof covering all transactions
        /// * `nullifiers` - All nullifiers from all transactions in the batch
        /// * `commitments` - All new note commitments from all transactions
        /// * `ciphertexts` - Encrypted notes for all recipients
        /// * `anchor` - Shared Merkle root all transactions were proven against
        /// * `total_fee` - Total optional miner tip across all transactions
        ///
        /// # Security
        /// - All transactions must use the same Merkle anchor
        /// - Single batch proof verifies all transactions together
        /// - Each nullifier is checked for double-spend
        /// - Batch size must be a power of 2 (2, 4, 8, 16, or 32)
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::shielded_transfer(
            nullifiers.len() as u32,
            commitments.len() as u32
        ))]
        pub fn batch_shielded_transfer(
            origin: OriginFor<T>,
            proof: types::BatchStarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerBatch>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerBatch>,
            ciphertexts: BoundedVec<EncryptedNote, T::MaxCommitmentsPerBatch>,
            anchor: [u8; 48],
            total_fee: u128,
        ) -> DispatchResult {
            // This is an unsigned extrinsic for batch transfers
            ensure_none(origin)?;
            Self::apply_batch_shielded_transfer_action(
                proof,
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                total_fee,
            )
        }
    }

    impl<T: Config> Pallet<T> {
        fn action_meta_to_validity(
            source: TransactionSource,
            prefix: &'static str,
            meta: ValidActionMeta,
        ) -> TransactionValidity {
            match meta.source_class {
                ActionSourceClass::External => {}
                ActionSourceClass::LocalOnly => {
                    if !matches!(
                        source,
                        TransactionSource::Local | TransactionSource::InBlock
                    ) {
                        return InvalidTransaction::Call.into();
                    }
                }
                ActionSourceClass::InBlockOnly => {
                    if source != TransactionSource::InBlock {
                        return InvalidTransaction::Call.into();
                    }
                }
            }

            let mut tx = ValidTransaction::with_tag_prefix(prefix)
                .priority(meta.priority as TransactionPriority)
                .longevity(meta.longevity)
                .propagate(meta.propagate);
            for tag in meta.provides {
                tx = tx.and_provides(tag);
            }
            for tag in meta.requires {
                tx = tx.and_requires(tag);
            }
            tx.build()
        }

        fn nullifier_tags(nullifiers: &[[u8; 48]], skip_zero_padding: bool) -> Vec<Vec<u8>> {
            let mut tags = Vec::new();
            for nf in nullifiers {
                if skip_zero_padding && is_zero_nullifier(nf) {
                    continue;
                }
                let mut tag = b"shielded_nf:".to_vec();
                tag.extend_from_slice(nf);
                tags.push(tag);
            }
            if tags.is_empty() {
                tags.push(b"shielded_no_nullifiers".to_vec());
            }
            tags
        }

        pub(crate) fn validate_enable_aggregation_mode_action(
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            // `enable_aggregation_mode` is an in-block control action inserted by the authoring
            // path. Like coinbase, it may be revalidated after execution while the block is still
            // being assembled, so the unsigned path must stay stateless and source-restricted.
            // The authoritative state checks live in `apply_enable_aggregation_mode_action`.
            Ok(ValidActionMeta {
                priority: u64::from(TransactionPriority::MAX),
                longevity: 1,
                provides: vec![b"aggregation_mode".to_vec()],
                requires: Vec::new(),
                propagate: false,
                source_class: ActionSourceClass::InBlockOnly,
            })
        }

        pub(crate) fn validate_submit_candidate_artifact_action(
            payload: &types::CandidateArtifact,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            // Like coinbase and aggregation mode, candidate artifacts can be revalidated after
            // execution while the current block is still being assembled. The unsigned validator
            // must therefore stay stateless and source-restricted; the authoritative block-local
            // duplicate check lives in `apply_submit_candidate_artifact_action`.
            if payload.version != types::BLOCK_PROOF_BUNDLE_SCHEMA {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: schema mismatch version={} expected={}",
                    payload.version,
                    types::BLOCK_PROOF_BUNDLE_SCHEMA,
                );
                return Err(InvalidTransaction::BadProof);
            }
            if payload.tx_count == 0 {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: zero tx_count"
                );
                return Err(InvalidTransaction::Custom(10));
            }
            if payload.commitment_proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: commitment proof too large bytes={} limit={}",
                    payload.commitment_proof.data.len(),
                    crate::types::STARK_PROOF_MAX_SIZE,
                );
                return Err(InvalidTransaction::ExhaustsResources);
            }
            if let Err(err) = Self::validate_block_proof_bundle_mode(payload) {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: invalid proof-mode payload err={:?} proof_mode={:?} receipt_root_present={} da_chunk_count={}",
                    err,
                    payload.proof_mode,
                    payload.receipt_root.is_some(),
                    payload.da_chunk_count,
                );
                return Err(InvalidTransaction::BadProof);
            }
            if Self::total_block_proof_bytes(payload)
                > types::BLOCK_PROOF_BUNDLE_MAX_TOTAL_PROOF_BYTES
            {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: total proof bytes {} exceed limit {}",
                    Self::total_block_proof_bytes(payload),
                    types::BLOCK_PROOF_BUNDLE_MAX_TOTAL_PROOF_BYTES,
                );
                return Err(InvalidTransaction::ExhaustsResources);
            }
            if payload.da_chunk_count == 0 {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: zero da_chunk_count"
                );
                return Err(InvalidTransaction::Custom(10));
            }
            Ok(ValidActionMeta {
                priority: u64::from(TransactionPriority::MAX),
                longevity: 1,
                provides: vec![b"proven_batch".to_vec()],
                requires: Vec::new(),
                propagate: false,
                source_class: ActionSourceClass::InBlockOnly,
            })
        }

        #[allow(deprecated)]
        #[deprecated(note = "Use validate_submit_candidate_artifact_action instead.")]
        pub(crate) fn validate_submit_proven_batch_action(
            payload: &types::BlockProofBundle,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            Self::validate_submit_candidate_artifact_action(payload)
        }

        pub(crate) fn validate_shielded_transfer_unsigned_action(
            proof: &StarkProof,
            nullifiers: &BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertexts: &BoundedVec<EncryptedNote, T::MaxEncryptedNotesPerTx>,
            anchor: &[u8; 48],
            balance_slot_asset_ids: &[u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: &BindingHash,
            stablecoin: &Option<StablecoinPolicyBinding>,
            fee: u64,
            version: VersionBinding,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            if Self::ensure_stablecoin_binding(stablecoin).is_err() {
                return Err(InvalidTransaction::Custom(7));
            }
            if !matches!(
                CiphertextPolicyStorage::<T>::get(),
                types::CiphertextPolicy::InlineAllowed
            ) {
                return Err(InvalidTransaction::Call);
            }
            if proof.data.len() > crate::types::NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE {
                return Err(InvalidTransaction::ExhaustsResources);
            }
            if nullifiers.is_empty() && commitments.is_empty() {
                return Err(InvalidTransaction::Custom(1));
            }
            if !commitments.is_empty() && nullifiers.is_empty() {
                return Err(InvalidTransaction::Custom(1));
            }
            if ciphertexts.len() != commitments.len() {
                return Err(InvalidTransaction::Custom(2));
            }
            if !MerkleRoots::<T>::contains_key(anchor) {
                return Err(InvalidTransaction::Custom(3));
            }
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    return Err(InvalidTransaction::Custom(4));
                }
            }
            for cm in commitments.iter() {
                if is_zero_commitment(cm) {
                    return Err(InvalidTransaction::Custom(4));
                }
            }
            let mut seen = Vec::new();
            for nf in nullifiers.iter() {
                if seen.contains(nf) {
                    return Err(InvalidTransaction::Custom(4));
                }
                seen.push(*nf);
            }
            for nf in nullifiers.iter() {
                if Nullifiers::<T>::contains_key(nf) {
                    return Err(InvalidTransaction::Custom(5));
                }
            }

            if let Some(meta) = Self::try_validate_native_tx_leaf_unsigned_action(
                &proof.data,
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                balance_slot_asset_ids,
                binding_hash,
                stablecoin,
                fee,
                version,
            )? {
                return Ok(meta);
            }
            Err(InvalidTransaction::BadProof)
        }

        fn try_validate_native_tx_leaf_unsigned_action(
            proof_bytes: &[u8],
            nullifiers: &BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertexts: &BoundedVec<EncryptedNote, T::MaxEncryptedNotesPerTx>,
            anchor: &[u8; 48],
            balance_slot_asset_ids: &[u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: &BindingHash,
            stablecoin: &Option<StablecoinPolicyBinding>,
            fee: u64,
            version: VersionBinding,
        ) -> Result<Option<ValidActionMeta>, InvalidTransaction> {
            let Some(decoded) = decode_native_tx_leaf_lite(proof_bytes).unwrap_or_default() else {
                return Ok(None);
            };

            let ciphertext_hashes = Self::ciphertext_hashes(ciphertexts.as_slice());
            let inputs = ShieldedTransferInputs {
                anchor: *anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes: ciphertext_hashes.clone(),
                balance_slot_asset_ids: *balance_slot_asset_ids,
                fee,
                value_balance: 0,
                stablecoin: stablecoin.clone(),
            };
            let verifier = T::ProofVerifier::default();
            if !verifier.verify_binding_hash(binding_hash, &inputs) {
                return Err(InvalidTransaction::BadSigner);
            }

            verify_native_stark_inputs_match_public_args(
                &decoded.stark_inputs,
                nullifiers.len(),
                commitments.len(),
                anchor,
                balance_slot_asset_ids,
                stablecoin,
                fee,
            )?;

            let balance_slots = canonical_balance_slots_from_public_args(
                *balance_slot_asset_ids,
                fee,
                0,
                stablecoin,
            )?;
            let balance_tag = balance_commitment_bytes(i128::from(fee), &balance_slots)
                .map_err(|_| InvalidTransaction::BadProof)?;
            if decoded.tx.nullifiers.as_slice() != nullifiers.as_slice()
                || decoded.tx.commitments.as_slice() != commitments.as_slice()
                || decoded.tx.ciphertext_hashes.as_slice() != ciphertext_hashes.as_slice()
                || decoded.tx.balance_tag != balance_tag
                || decoded.tx.version != version
            {
                return Err(InvalidTransaction::BadProof);
            }
            let expected_statement_hash = native_statement_hash_from_public_args(
                nullifiers.as_slice(),
                commitments.as_slice(),
                &ciphertext_hashes,
                &balance_tag,
                version,
                &decoded.stark_inputs,
            )?;
            if decoded.receipt.statement_hash != expected_statement_hash {
                return Err(InvalidTransaction::BadProof);
            }
            let expected_public_inputs_digest = native_public_inputs_digest(&decoded.stark_inputs)?;
            if decoded.receipt.public_inputs_digest != expected_public_inputs_digest {
                return Err(InvalidTransaction::BadProof);
            }
            if decoded.receipt.proof_digest == [0u8; 48]
                || decoded.receipt.verifier_profile == [0u8; 48]
            {
                return Err(InvalidTransaction::BadProof);
            }

            Ok(Some(ValidActionMeta {
                priority: 100,
                longevity: 64,
                provides: Self::nullifier_tags(nullifiers.as_slice(), false),
                requires: Vec::new(),
                propagate: true,
                source_class: ActionSourceClass::External,
            }))
        }

        pub(crate) fn validate_shielded_transfer_unsigned_sidecar_action(
            proof: &StarkProof,
            nullifiers: &BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_hashes: &BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_sizes: &BoundedVec<u32, T::MaxCommitmentsPerTx>,
            anchor: &[u8; 48],
            balance_slot_asset_ids: &[u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: &BindingHash,
            stablecoin: &Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            if Self::ensure_stablecoin_binding(stablecoin).is_err() {
                return Err(InvalidTransaction::Custom(7));
            }
            if proof.data.len() > crate::types::NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE {
                return Err(InvalidTransaction::ExhaustsResources);
            }
            if nullifiers.is_empty() && commitments.is_empty() {
                return Err(InvalidTransaction::Custom(1));
            }
            if !commitments.is_empty() && nullifiers.is_empty() {
                return Err(InvalidTransaction::Custom(1));
            }
            if ciphertext_hashes.len() != commitments.len() {
                return Err(InvalidTransaction::Custom(2));
            }
            if ciphertext_sizes.len() != commitments.len() {
                return Err(InvalidTransaction::Custom(2));
            }
            if Self::validate_ciphertext_sizes(ciphertext_sizes.as_slice()).is_err() {
                return Err(InvalidTransaction::Custom(2));
            }
            for hash in ciphertext_hashes.iter() {
                if *hash == [0u8; 48] {
                    return Err(InvalidTransaction::Custom(4));
                }
            }
            if !MerkleRoots::<T>::contains_key(anchor) {
                return Err(InvalidTransaction::Custom(3));
            }
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    return Err(InvalidTransaction::Custom(4));
                }
            }
            for cm in commitments.iter() {
                if is_zero_commitment(cm) {
                    return Err(InvalidTransaction::Custom(4));
                }
            }
            let mut seen = Vec::new();
            for nf in nullifiers.iter() {
                if seen.contains(nf) {
                    return Err(InvalidTransaction::Custom(4));
                }
                seen.push(*nf);
            }
            for nf in nullifiers.iter() {
                if Nullifiers::<T>::contains_key(nf) {
                    return Err(InvalidTransaction::Custom(5));
                }
            }

            let vk = VerifyingKeyStorage::<T>::get();
            if !vk.enabled {
                return Err(InvalidTransaction::Custom(6));
            }

            let inputs = ShieldedTransferInputs {
                anchor: *anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes: ciphertext_hashes.clone().into_inner(),
                balance_slot_asset_ids: *balance_slot_asset_ids,
                fee,
                value_balance: 0,
                stablecoin: stablecoin.clone(),
            };

            let verifier = T::ProofVerifier::default();
            let aggregation_mode = AggregationProofRequired::<T>::get();
            let proof_policy = ProofAvailabilityPolicyStorage::<T>::get();

            if proof.data.is_empty()
                && !matches!(proof_policy, types::ProofAvailabilityPolicy::SelfContained)
            {
                return Err(InvalidTransaction::Custom(12));
            }

            if !aggregation_mode && !proof.data.is_empty() {
                match verifier.verify_stark(proof, &inputs, &vk) {
                    VerificationResult::Valid => {}
                    _ => return Err(InvalidTransaction::BadProof),
                }
            }
            if !verifier.verify_binding_hash(binding_hash, &inputs) {
                return Err(InvalidTransaction::BadSigner);
            }

            Ok(ValidActionMeta {
                priority: 100,
                longevity: 64,
                provides: Self::nullifier_tags(nullifiers.as_slice(), false),
                requires: Vec::new(),
                propagate: true,
                source_class: ActionSourceClass::External,
            })
        }

        pub(crate) fn validate_batch_shielded_transfer_action(
            proof: &types::BatchStarkProof,
            nullifiers: &BoundedVec<[u8; 48], T::MaxNullifiersPerBatch>,
            commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerBatch>,
            ciphertexts: &BoundedVec<EncryptedNote, T::MaxCommitmentsPerBatch>,
            anchor: &[u8; 48],
            total_fee: u128,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            if !matches!(
                CiphertextPolicyStorage::<T>::get(),
                types::CiphertextPolicy::InlineAllowed
            ) {
                return Err(InvalidTransaction::Call);
            }
            if proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                return Err(InvalidTransaction::ExhaustsResources);
            }
            if !proof.is_valid_batch_size() {
                return Err(InvalidTransaction::BadProof);
            }
            if nullifiers.is_empty() && commitments.is_empty() {
                return Err(InvalidTransaction::Custom(1));
            }
            if ciphertexts.len() != commitments.len() {
                return Err(InvalidTransaction::Custom(2));
            }
            for note in ciphertexts.iter() {
                if Self::validate_encrypted_note(note).is_err() {
                    return Err(InvalidTransaction::Custom(2));
                }
            }
            if !MerkleRoots::<T>::contains_key(anchor) {
                return Err(InvalidTransaction::Custom(3));
            }

            let mut seen_nullifiers = sp_std::vec::Vec::new();
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                if seen_nullifiers.contains(nf) {
                    return Err(InvalidTransaction::Custom(4));
                }
                seen_nullifiers.push(*nf);
            }
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                if Nullifiers::<T>::contains_key(nf) {
                    return Err(InvalidTransaction::Custom(5));
                }
            }

            let batch_inputs = verifier::BatchPublicInputs {
                anchor: *anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                batch_size: proof.batch_size,
                total_fee,
            };
            let vk = VerifyingKeyStorage::<T>::get();
            if !vk.enabled {
                return Err(InvalidTransaction::Custom(6));
            }
            let batch_verifier = T::BatchProofVerifier::default();
            match batch_verifier.verify_batch(proof, &batch_inputs, &vk) {
                verifier::BatchVerificationResult::Valid => {}
                verifier::BatchVerificationResult::InvalidBatchSize => {
                    return Err(InvalidTransaction::BadProof)
                }
                _ => return Err(InvalidTransaction::BadProof),
            }

            Ok(ValidActionMeta {
                priority: 100,
                longevity: 64,
                provides: Self::nullifier_tags(nullifiers.as_slice(), true),
                requires: Vec::new(),
                propagate: true,
                source_class: ActionSourceClass::External,
            })
        }

        pub(crate) fn apply_enable_aggregation_mode_action() -> DispatchResult {
            ensure!(
                !AggregationProofRequired::<T>::get(),
                Error::<T>::AggregationModeAlreadyEnabled
            );
            ensure!(
                !ShieldedTransfersProcessed::<T>::get(),
                Error::<T>::AggregationModeAfterTransfers
            );
            AggregationProofRequired::<T>::put(true);
            Ok(())
        }

        pub(crate) fn apply_submit_candidate_artifact_action(
            payload: types::CandidateArtifact,
        ) -> DispatchResult {
            ensure!(
                !ProvenBatchProcessed::<T>::get(),
                Error::<T>::ProvenBatchAlreadyProcessed
            );
            ensure!(
                payload.version == types::BLOCK_PROOF_BUNDLE_SCHEMA,
                Error::<T>::InvalidProofFormat
            );
            ensure!(payload.tx_count > 0, Error::<T>::InvalidNullifierCount);
            ensure!(
                payload.commitment_proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );
            Self::validate_block_proof_bundle_mode(&payload)?;
            ensure!(
                Self::total_block_proof_bytes(&payload)
                    <= types::BLOCK_PROOF_BUNDLE_MAX_TOTAL_PROOF_BYTES,
                Error::<T>::ProofTooLarge
            );
            ensure!(payload.da_chunk_count > 0, Error::<T>::InvalidDaChunkCount);

            let block_number = frame_system::Pallet::<T>::block_number();
            DaCommitments::<T>::insert(
                block_number,
                types::DaCommitment {
                    root: payload.da_root,
                    chunk_count: payload.da_chunk_count,
                },
            );
            ProvenBatchProcessed::<T>::put(true);
            Ok(())
        }

        #[allow(deprecated)]
        #[deprecated(note = "Use apply_submit_candidate_artifact_action instead.")]
        pub(crate) fn apply_submit_proven_batch_action(
            payload: types::BlockProofBundle,
        ) -> DispatchResult {
            Self::apply_submit_candidate_artifact_action(payload)
        }

        pub(crate) fn apply_mint_coinbase_action(
            reward_bundle: types::BlockRewardBundle,
        ) -> DispatchResult {
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::CoinbaseAlreadyProcessed
            );

            let block_number = <frame_system::Pallet<T>>::block_number();
            let height: u64 = block_number.try_into().unwrap_or(0);
            let fee_buckets = BlockFeeBucketsStorage::<T>::get();
            let expected_miner_amount =
                Self::expected_miner_reward_amount(height, fee_buckets.miner_fees)?;
            ensure!(
                reward_bundle.miner_note.amount == expected_miner_amount,
                Error::<T>::CoinbaseAmountMismatch
            );

            let expected_miner_commitment =
                Self::expected_coinbase_commitment(&reward_bundle.miner_note);
            ensure!(
                reward_bundle.miner_note.commitment == expected_miner_commitment,
                Error::<T>::InvalidCoinbaseCommitment
            );

            let mut index = CommitmentIndex::<T>::get();
            Commitments::<T>::insert(index, reward_bundle.miner_note.commitment);
            EncryptedNotes::<T>::insert(index, reward_bundle.miner_note.encrypted_note.clone());
            CoinbaseNotes::<T>::insert(index, reward_bundle.clone());
            index = index.saturating_add(1);

            CommitmentIndex::<T>::put(index);

            let commitments = BoundedVec::<[u8; 48], T::MaxCommitmentsPerTx>::try_from(vec![
                expected_miner_commitment,
            ])
            .map_err(|_| Error::<T>::InvalidCommitmentCount)?;
            Self::update_merkle_tree(&commitments)?;

            let amount = reward_bundle.miner_note.amount as u128;
            PoolBalance::<T>::mutate(|b| *b = b.saturating_add(amount));

            CoinbaseProcessed::<T>::put(true);
            ShieldedTransfersProcessed::<T>::put(true);

            Self::deposit_event(Event::CoinbaseMinted {
                commitment_index: index.saturating_sub(1),
                amount: amount as u64,
                block_number,
            });

            info!(
                target: "shielded-pool",
                "💰 Minted {} shielded coins at commitment index {}",
                amount,
                index
            );

            Ok(())
        }

        pub(crate) fn apply_shielded_transfer_unsigned_action(
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertexts: BoundedVec<EncryptedNote, T::MaxEncryptedNotesPerTx>,
            anchor: [u8; 48],
            balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
            version: VersionBinding,
        ) -> DispatchResult {
            ensure!(
                matches!(
                    CiphertextPolicyStorage::<T>::get(),
                    types::CiphertextPolicy::InlineAllowed
                ),
                Error::<T>::InlineCiphertextsDisabled
            );
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::TransfersAfterCoinbase
            );
            ensure!(
                proof.data.len() <= crate::types::NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );

            let value_balance: i128 = 0;
            Self::ensure_stablecoin_binding(&stablecoin)?;
            ensure!(
                !nullifiers.is_empty() || !commitments.is_empty(),
                Error::<T>::InvalidNullifierCount
            );
            ensure!(
                ciphertexts.len() == commitments.len(),
                Error::<T>::EncryptedNotesMismatch
            );
            for note in ciphertexts.iter() {
                Self::validate_encrypted_note(note)?;
            }
            ensure!(
                MerkleRoots::<T>::contains_key(anchor),
                Error::<T>::InvalidAnchor
            );
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    return Err(Error::<T>::ZeroNullifierSubmitted.into());
                }
            }
            for cm in commitments.iter() {
                if is_zero_commitment(cm) {
                    return Err(Error::<T>::ZeroCommitmentSubmitted.into());
                }
            }
            let mut seen_nullifiers = Vec::new();
            for nf in nullifiers.iter() {
                if seen_nullifiers.contains(nf) {
                    return Err(Error::<T>::DuplicateNullifierInTx.into());
                }
                seen_nullifiers.push(*nf);
            }
            for nf in nullifiers.iter() {
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }

            let ciphertext_hashes = Self::ciphertext_hashes(ciphertexts.as_slice());
            let inputs = ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes,
                balance_slot_asset_ids,
                fee,
                value_balance,
                stablecoin: stablecoin.clone(),
            };
            let verifier = T::ProofVerifier::default();
            ensure!(
                verifier.verify_binding_hash(&binding_hash, &inputs),
                Error::<T>::InvalidBindingHash
            );
            match Self::try_validate_native_tx_leaf_unsigned_action(
                &proof.data,
                &nullifiers,
                &commitments,
                &ciphertexts,
                &anchor,
                &balance_slot_asset_ids,
                &binding_hash,
                &stablecoin,
                fee,
                version,
            ) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    warn!(
                        target: "shielded-pool",
                        "non-native proof bytes rejected on the shipped transfer path"
                    );
                    return Err(Error::<T>::InvalidProofFormat.into());
                }
                Err(_) => {
                    warn!(
                        target: "shielded-pool",
                        "native tx-leaf verification failed for unsigned transfer"
                    );
                    return Err(Error::<T>::ProofVerificationFailed.into());
                }
            }
            Self::record_miner_tip(u128::from(fee))?;

            for nf in nullifiers.iter() {
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }
            let mut current_index = CommitmentIndex::<T>::get();
            for (cm, enc) in commitments.iter().zip(ciphertexts.iter()) {
                Commitments::<T>::insert(current_index, *cm);
                EncryptedNotes::<T>::insert(current_index, enc.clone());
                Self::deposit_event(Event::CommitmentAdded {
                    index: current_index,
                    commitment: *cm,
                });
                current_index += 1;
            }
            CommitmentIndex::<T>::put(current_index);
            Self::update_merkle_tree(&commitments)?;

            Self::deposit_event(Event::ShieldedTransfer {
                nullifier_count: nullifiers.len() as u32,
                commitment_count: commitments.len() as u32,
                value_balance,
            });

            info!(
                target: "shielded-pool",
                "🔐 Unsigned shielded transfer: {} nullifiers, {} commitments",
                nullifiers.len(),
                commitments.len()
            );
            ShieldedTransfersProcessed::<T>::put(true);
            Ok(())
        }

        pub(crate) fn apply_shielded_transfer_unsigned_sidecar_action(
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_hashes: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_sizes: BoundedVec<u32, T::MaxCommitmentsPerTx>,
            anchor: [u8; 48],
            balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> DispatchResult {
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::TransfersAfterCoinbase
            );
            ensure!(
                proof.data.len() <= crate::types::NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );
            let value_balance: i128 = 0;
            Self::ensure_stablecoin_binding(&stablecoin)?;
            let aggregation_mode = AggregationProofRequired::<T>::get();
            let proof_policy = ProofAvailabilityPolicyStorage::<T>::get();
            if proof.data.is_empty() {
                ensure!(aggregation_mode, Error::<T>::ProofBytesRequired);
                ensure!(
                    matches!(proof_policy, types::ProofAvailabilityPolicy::SelfContained),
                    Error::<T>::ProofBytesRequired
                );
            }
            ensure!(
                !nullifiers.is_empty() || !commitments.is_empty(),
                Error::<T>::InvalidNullifierCount
            );
            ensure!(
                ciphertext_hashes.len() == commitments.len(),
                Error::<T>::CiphertextHashCountMismatch
            );
            ensure!(
                ciphertext_sizes.len() == commitments.len(),
                Error::<T>::CiphertextSizeCountMismatch
            );
            Self::validate_ciphertext_sizes(ciphertext_sizes.as_slice())?;
            for hash in ciphertext_hashes.iter() {
                if *hash == [0u8; 48] {
                    return Err(Error::<T>::ZeroCiphertextHash.into());
                }
            }
            ensure!(
                MerkleRoots::<T>::contains_key(anchor),
                Error::<T>::InvalidAnchor
            );
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    return Err(Error::<T>::ZeroNullifierSubmitted.into());
                }
            }
            for cm in commitments.iter() {
                if is_zero_commitment(cm) {
                    return Err(Error::<T>::ZeroCommitmentSubmitted.into());
                }
            }
            if value_balance <= 0 && !commitments.is_empty() && nullifiers.is_empty() {
                return Err(Error::<T>::InvalidNullifierCount.into());
            }
            let mut seen_nullifiers = Vec::new();
            for nf in nullifiers.iter() {
                if seen_nullifiers.contains(nf) {
                    return Err(Error::<T>::DuplicateNullifierInTx.into());
                }
                seen_nullifiers.push(*nf);
            }
            for nf in nullifiers.iter() {
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }
            let inputs = ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes: ciphertext_hashes.clone().into_inner(),
                balance_slot_asset_ids,
                fee,
                value_balance,
                stablecoin: stablecoin.clone(),
            };
            let verifier = T::ProofVerifier::default();
            if !aggregation_mode {
                let vk = VerifyingKeyStorage::<T>::get();
                ensure!(vk.enabled, Error::<T>::VerifyingKeyNotFound);
                match verifier.verify_stark(&proof, &inputs, &vk) {
                    VerificationResult::Valid => {}
                    VerificationResult::InvalidProofFormat => {
                        return Err(Error::<T>::InvalidProofFormat.into())
                    }
                    VerificationResult::InvalidPublicInputs => {
                        return Err(Error::<T>::InvalidProofFormat.into())
                    }
                    VerificationResult::VerificationFailed => {
                        return Err(Error::<T>::ProofVerificationFailed.into())
                    }
                    VerificationResult::KeyNotFound => {
                        return Err(Error::<T>::VerifyingKeyNotFound.into())
                    }
                    _ => return Err(Error::<T>::ProofVerificationFailed.into()),
                }
            }
            ensure!(
                verifier.verify_binding_hash(&binding_hash, &inputs),
                Error::<T>::InvalidBindingHash
            );
            Self::record_miner_tip(u128::from(fee))?;

            for nf in nullifiers.iter() {
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }
            let mut current_index = CommitmentIndex::<T>::get();
            for cm in commitments.iter() {
                Commitments::<T>::insert(current_index, *cm);
                Self::deposit_event(Event::CommitmentAdded {
                    index: current_index,
                    commitment: *cm,
                });
                current_index += 1;
            }
            CommitmentIndex::<T>::put(current_index);
            Self::update_merkle_tree(&commitments)?;
            Self::deposit_event(Event::ShieldedTransfer {
                nullifier_count: nullifiers.len() as u32,
                commitment_count: commitments.len() as u32,
                value_balance,
            });
            ShieldedTransfersProcessed::<T>::put(true);
            Ok(())
        }

        pub(crate) fn apply_batch_shielded_transfer_action(
            proof: types::BatchStarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerBatch>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerBatch>,
            ciphertexts: BoundedVec<EncryptedNote, T::MaxCommitmentsPerBatch>,
            anchor: [u8; 48],
            total_fee: u128,
        ) -> DispatchResult {
            ensure!(
                matches!(
                    CiphertextPolicyStorage::<T>::get(),
                    types::CiphertextPolicy::InlineAllowed
                ),
                Error::<T>::InlineCiphertextsDisabled
            );
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::TransfersAfterCoinbase
            );
            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );
            ensure!(proof.is_valid_batch_size(), Error::<T>::InvalidBatchSize);
            ensure!(
                !nullifiers.is_empty() || !commitments.is_empty(),
                Error::<T>::InvalidNullifierCount
            );
            ensure!(
                ciphertexts.len() == commitments.len(),
                Error::<T>::EncryptedNotesMismatch
            );
            for note in ciphertexts.iter() {
                Self::validate_encrypted_note(note)?;
            }
            ensure!(
                MerkleRoots::<T>::contains_key(anchor),
                Error::<T>::InvalidAnchor
            );
            let mut seen_nullifiers = sp_std::vec::Vec::new();
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                if seen_nullifiers.contains(nf) {
                    return Err(Error::<T>::DuplicateNullifierInTx.into());
                }
                seen_nullifiers.push(*nf);
            }
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }
            let batch_inputs = verifier::BatchPublicInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                batch_size: proof.batch_size,
                total_fee,
            };
            let vk = VerifyingKeyStorage::<T>::get();
            ensure!(vk.enabled, Error::<T>::VerifyingKeyNotFound);
            let batch_verifier = T::BatchProofVerifier::default();
            match batch_verifier.verify_batch(&proof, &batch_inputs, &vk) {
                verifier::BatchVerificationResult::Valid => {}
                verifier::BatchVerificationResult::InvalidProofFormat => {
                    warn!(target: "shielded-pool", "Invalid batch proof format");
                    return Err(Error::<T>::InvalidProofFormat.into());
                }
                verifier::BatchVerificationResult::InvalidPublicInputs => {
                    warn!(target: "shielded-pool", "Invalid batch public inputs");
                    return Err(Error::<T>::InvalidProofFormat.into());
                }
                verifier::BatchVerificationResult::InvalidBatchSize => {
                    warn!(target: "shielded-pool", "Invalid batch size");
                    return Err(Error::<T>::InvalidBatchSize.into());
                }
                verifier::BatchVerificationResult::VerificationFailed => {
                    warn!(target: "shielded-pool", "Batch proof verification failed");
                    return Err(Error::<T>::ProofVerificationFailed.into());
                }
                verifier::BatchVerificationResult::KeyNotFound => {
                    return Err(Error::<T>::VerifyingKeyNotFound.into());
                }
            }
            Self::record_miner_tip(total_fee)?;

            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }
            let mut current_index = CommitmentIndex::<T>::get();
            for (cm, enc) in commitments.iter().zip(ciphertexts.iter()) {
                Commitments::<T>::insert(current_index, *cm);
                EncryptedNotes::<T>::insert(current_index, enc.clone());
                Self::deposit_event(Event::CommitmentAdded {
                    index: current_index,
                    commitment: *cm,
                });
                current_index += 1;
            }
            CommitmentIndex::<T>::put(current_index);
            Self::update_merkle_tree_batch(&commitments)?;
            Self::deposit_event(Event::BatchShieldedTransfer {
                batch_size: proof.batch_size,
                nullifier_count: nullifiers.len() as u32,
                commitment_count: commitments.len() as u32,
                total_fee,
            });
            info!(
                target: "shielded-pool",
                "🔐 Batch shielded transfer: {} txs, {} nullifiers, {} commitments",
                proof.batch_size,
                nullifiers.len(),
                commitments.len()
            );
            ShieldedTransfersProcessed::<T>::put(true);
            Ok(())
        }

        fn expected_miner_reward_amount(height: u64, miner_fees: u128) -> Result<u64, Error<T>> {
            let subsidy = pallet_coinbase::block_subsidy(height);
            let fee_u64 = u64::try_from(miner_fees).map_err(|_| Error::<T>::FeeOverflow)?;
            let amount = subsidy
                .checked_add(fee_u64)
                .ok_or(Error::<T>::FeeOverflow)?;
            if amount > T::MaxCoinbaseSubsidy::get() {
                return Err(Error::<T>::CoinbaseSubsidyExceedsLimit);
            }
            Ok(amount)
        }

        fn record_miner_tip(miner_tip: u128) -> Result<(), Error<T>> {
            if miner_tip == 0 {
                return Ok(());
            }

            BlockFeeBucketsStorage::<T>::try_mutate(|buckets| {
                buckets.miner_fees = buckets
                    .miner_fees
                    .checked_add(miner_tip)
                    .ok_or(Error::<T>::FeeOverflow)?;
                Ok::<(), Error<T>>(())
            })?;
            PoolBalance::<T>::mutate(|balance| *balance = balance.saturating_sub(miner_tip));
            Ok(())
        }

        pub(crate) fn total_block_proof_bytes(bundle: &types::BlockProofBundle) -> usize {
            let receipt_root_bytes = bundle
                .receipt_root
                .as_ref()
                .map(|receipt_root| receipt_root.root_proof.data.len())
                .unwrap_or(0);
            let aggregation_bytes = match bundle.proof_mode {
                types::BlockProofMode::InlineTx => 0,
                types::BlockProofMode::ReceiptRoot => receipt_root_bytes,
            };
            bundle.commitment_proof.data.len() + aggregation_bytes
        }

        pub(crate) fn validate_block_proof_bundle_mode(
            bundle: &types::BlockProofBundle,
        ) -> Result<(), Error<T>> {
            if bundle.proof_kind != types::proof_artifact_kind_from_mode(bundle.proof_mode) {
                return Err(Error::<T>::InvalidProofFormat);
            }
            if bundle.verifier_profile == [0u8; 48] {
                return Err(Error::<T>::InvalidProofFormat);
            }
            match bundle.proof_mode {
                types::BlockProofMode::InlineTx => {
                    if bundle.receipt_root.is_some() {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                }
                types::BlockProofMode::ReceiptRoot => {
                    let receipt_root = bundle
                        .receipt_root
                        .as_ref()
                        .ok_or(Error::<T>::InvalidProofFormat)?;
                    if receipt_root.root_proof.data.is_empty()
                        || receipt_root.root_proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE
                    {
                        return Err(Error::<T>::ProofTooLarge);
                    }
                    if receipt_root.receipts.is_empty()
                        || receipt_root.metadata.leaf_count != receipt_root.receipts.len() as u32
                    {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                    if receipt_root.metadata.fold_count == 0 && receipt_root.receipts.len() > 1 {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                    for receipt in &receipt_root.receipts {
                        if receipt.verifier_profile == [0u8; 48] {
                            return Err(Error::<T>::InvalidProofFormat);
                        }
                    }
                }
            }
            Ok(())
        }

        fn expected_coinbase_commitment(coinbase_data: &types::CoinbaseNoteData) -> [u8; 48] {
            let pk_recipient =
                commitment::pk_recipient_from_address(&coinbase_data.recipient_address);
            let pk_auth = commitment::pk_auth_from_address(&coinbase_data.recipient_address);
            commitment::circuit_coinbase_commitment(
                &pk_recipient,
                &pk_auth,
                coinbase_data.amount,
                &coinbase_data.public_seed,
                0,
            )
        }

        fn validate_encrypted_note(note: &EncryptedNote) -> Result<(), Error<T>> {
            let version = note.ciphertext[0];
            if version != crate::types::NOTE_ENCRYPTION_VERSION {
                log::info!(
                    target: "shielded-pool",
                    "Rejected encrypted note version {}; expected {}",
                    version,
                    crate::types::NOTE_ENCRYPTION_VERSION
                );
                return Err(Error::<T>::UnsupportedNoteVersion);
            }

            let crypto_suite = u16::from_le_bytes([note.ciphertext[1], note.ciphertext[2]]);
            let expected_kem_len = kem_ciphertext_len_for_suite(crypto_suite)
                .ok_or(Error::<T>::UnsupportedNoteCryptoSuite)?;

            if note.kem_ciphertext.len() != expected_kem_len {
                return Err(Error::<T>::InvalidKemCiphertextLength);
            }

            Ok(())
        }

        fn encrypted_note_bytes(note: &EncryptedNote) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(note.ciphertext.len() + note.kem_ciphertext.len());
            bytes.extend_from_slice(&note.ciphertext);
            bytes.extend_from_slice(&note.kem_ciphertext);
            bytes
        }

        fn ciphertext_hashes(ciphertexts: &[EncryptedNote]) -> Vec<[u8; 48]> {
            ciphertexts
                .iter()
                .map(|note| ciphertext_hash_bytes(&Self::encrypted_note_bytes(note)))
                .collect()
        }

        fn validate_ciphertext_sizes(sizes: &[u32]) -> Result<(), Error<T>> {
            for size in sizes {
                if *size == 0 || (*size as usize) > types::MAX_CIPHERTEXT_BYTES {
                    return Err(Error::<T>::InvalidCiphertextSize);
                }
            }
            Ok(())
        }

        fn ensure_stablecoin_binding(
            stablecoin: &Option<StablecoinPolicyBinding>,
        ) -> Result<(), Error<T>> {
            let binding = match stablecoin.as_ref() {
                Some(binding) => binding,
                None => return Ok(()),
            };

            let asset_id: T::StablecoinAssetId = binding
                .asset_id
                .try_into()
                .map_err(|_| Error::<T>::StablecoinAssetIdInvalid)?;

            let policy = T::StablecoinPolicyProvider::policy(&asset_id)
                .ok_or(Error::<T>::StablecoinPolicyMissing)?;
            let policy_hash = T::StablecoinPolicyProvider::policy_hash(&asset_id)
                .ok_or(Error::<T>::StablecoinPolicyMissing)?;

            if policy_hash != binding.policy_hash || policy.policy_version != binding.policy_version
            {
                return Err(Error::<T>::StablecoinPolicyMismatch);
            }
            if policy.asset_id != asset_id {
                return Err(Error::<T>::StablecoinPolicyMismatch);
            }
            if !policy.active {
                return Err(Error::<T>::StablecoinPolicyInactive);
            }
            if policy.oracle_feeds.len() != 1 {
                return Err(Error::<T>::StablecoinPolicyInvalid);
            }

            let oracle_feed = policy
                .oracle_feeds
                .first()
                .ok_or(Error::<T>::StablecoinPolicyInvalid)?;
            let oracle = T::OracleCommitmentProvider::latest_commitment(oracle_feed)
                .ok_or(Error::<T>::StablecoinOracleCommitmentMissing)?;
            if oracle.commitment != binding.oracle_commitment {
                return Err(Error::<T>::StablecoinOracleCommitmentMismatch);
            }

            let now = frame_system::Pallet::<T>::block_number();
            let age = now.saturating_sub(oracle.submitted_at);
            if age > policy.oracle_max_age {
                return Err(Error::<T>::StablecoinOracleCommitmentStale);
            }

            let attestation = T::AttestationCommitmentProvider::commitment(&policy.attestation_id)
                .ok_or(Error::<T>::StablecoinAttestationMissing)?;
            if attestation.commitment != binding.attestation_commitment {
                return Err(Error::<T>::StablecoinAttestationCommitmentMismatch);
            }
            if attestation.disputed {
                return Err(Error::<T>::StablecoinAttestationDisputed);
            }

            Ok(())
        }

        /// Record a new Merkle root and prune history to the configured bound.
        fn record_merkle_root(root: [u8; 48], block: BlockNumberFor<T>) -> DispatchResult {
            let history_limit = T::MerkleRootHistorySize::get() as usize;
            MerkleRoots::<T>::insert(root, block);

            if history_limit == 0 {
                return Ok(());
            }

            let mut history = MerkleRootHistory::<T>::get();
            if history.last().map(|last| *last == root).unwrap_or(false) {
                return Ok(());
            }

            if history.len() >= history_limit {
                if let Some(oldest) = history.first().copied() {
                    MerkleRoots::<T>::remove(oldest);
                }
                history.remove(0);
            }

            history
                .try_push(root)
                .map_err(|_| Error::<T>::MerkleRootHistoryFull)?;
            MerkleRootHistory::<T>::put(history);
            Ok(())
        }

        /// Update the Merkle tree with new commitments.
        fn update_merkle_tree(
            new_commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
        ) -> DispatchResult {
            // Get current compact tree state and mutate it
            let mut tree = MerkleTree::<T>::get();

            // Append each new commitment
            for cm in new_commitments.iter() {
                tree.append(*cm).map_err(|_| Error::<T>::MerkleTreeFull)?;
            }

            // Store updated tree
            let new_root = tree.root();
            MerkleTree::<T>::put(tree);

            // Store root in history
            let block = <frame_system::Pallet<T>>::block_number();
            Self::record_merkle_root(new_root, block)?;

            Self::deposit_event(Event::MerkleRootUpdated { root: new_root });

            Ok(())
        }

        /// Update the Merkle tree with new batch commitments.
        fn update_merkle_tree_batch(
            new_commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerBatch>,
        ) -> DispatchResult {
            // Get current compact tree state and mutate it
            let mut tree = MerkleTree::<T>::get();

            // Append each new commitment
            for cm in new_commitments.iter() {
                tree.append(*cm).map_err(|_| Error::<T>::MerkleTreeFull)?;
            }

            // Store updated tree
            let new_root = tree.root();
            MerkleTree::<T>::put(tree);

            // Store root in history
            let block = <frame_system::Pallet<T>>::block_number();
            Self::record_merkle_root(new_root, block)?;

            Self::deposit_event(Event::MerkleRootUpdated { root: new_root });

            Ok(())
        }

        /// Get Merkle witness for a commitment at given index.
        ///
        /// NOTE: This requires rebuilding the tree from stored commitments,
        /// which is expensive. For production, consider storing witnesses
        /// off-chain or using a different data structure.
        pub fn get_merkle_witness(index: u64) -> Option<merkle::MerkleWitness> {
            use merkle::IncrementalMerkleTree;
            const MAX_RPC_WITNESS_REBUILD_NOTES: u64 = 65_536;

            let tree = MerkleTree::<T>::get();
            if index >= tree.len() {
                return None;
            }
            if tree.len() > MAX_RPC_WITNESS_REBUILD_NOTES {
                return None;
            }

            // Build tree from stored commitments
            // This is O(n) and expensive - production should optimize
            let mut full_tree = IncrementalMerkleTree::new(MERKLE_TREE_DEPTH);
            for i in 0..tree.len() {
                if let Some(cm) = Commitments::<T>::get(i) {
                    let _ = full_tree.append(cm);
                }
            }

            full_tree.authentication_path(index).ok()
        }

        /// Check if an anchor (Merkle root) is valid.
        pub fn is_valid_anchor(anchor: &[u8; 48]) -> bool {
            MerkleRoots::<T>::contains_key(anchor)
        }

        /// Check if a nullifier has been spent.
        pub fn is_nullifier_spent(nullifier: &[u8; 48]) -> bool {
            Nullifiers::<T>::contains_key(nullifier)
        }
    }

    // =========================================================================
    // INHERENT PROVIDER IMPLEMENTATION (disabled for shielded coinbase)
    // =========================================================================
    //
    // Substrate enforces that inherents must appear first in the block.
    // Hegemon’s shielded coinbase must run *after* fee accumulation (so it can include
    // per-block fees), therefore `mint_coinbase` cannot be treated as an inherent.
    //
    // We keep a `ProvideInherent` implementation because the runtime includes `Inherent`
    // for this pallet in `construct_runtime!`, but we intentionally do not create or
    // classify any calls as inherents here.

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = sp_inherents::MakeFatalError<()>;
        const INHERENT_IDENTIFIER: [u8; 8] = *b"shldcoin";

        fn create_inherent(_data: &sp_inherents::InherentData) -> Option<Self::Call> {
            None
        }

        fn is_inherent(_call: &Self::Call) -> bool {
            false
        }

        fn check_inherent(
            _call: &Self::Call,
            _data: &sp_inherents::InherentData,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn is_inherent_required(
            _data: &sp_inherents::InherentData,
        ) -> Result<Option<Self::Error>, Self::Error> {
            Ok(None)
        }
    }

    // =========================================================================
    // VALIDATE UNSIGNED IMPLEMENTATION (for shielded-to-shielded transfers)
    // =========================================================================
    //
    // This allows pure shielded-to-shielded transfers to be submitted without
    // a transparent account. The ZK proof authenticates the spend (proving
    // knowledge of sk_spend), so no external signature is needed.
    //
    // This follows the Zcash model where shielded transfers are inherently
    // authenticated by the zero-knowledge proof itself.
    // =========================================================================

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            log::trace!(target: "shielded-pool", "ValidateUnsigned::validate_unsigned called");
            match call {
                Call::shielded_transfer_unsigned {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    balance_slot_asset_ids,
                    binding_hash,
                    stablecoin,
                    fee,
                } => {
                    match Self::validate_shielded_transfer_unsigned_action(
                        proof,
                        nullifiers,
                        commitments,
                        ciphertexts,
                        anchor,
                        balance_slot_asset_ids,
                        binding_hash,
                        stablecoin,
                        *fee,
                        protocol_versioning::DEFAULT_VERSION_BINDING,
                    ) {
                        Ok(meta) => {
                            Self::action_meta_to_validity(_source, "ShieldedPoolUnsigned", meta)
                        }
                        Err(err) => err.into(),
                    }
                }
                Call::shielded_transfer_unsigned_sidecar {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertext_hashes,
                    ciphertext_sizes,
                    anchor,
                    balance_slot_asset_ids,
                    binding_hash,
                    stablecoin,
                    fee,
                } => {
                    match Self::validate_shielded_transfer_unsigned_sidecar_action(
                        proof,
                        nullifiers,
                        commitments,
                        ciphertext_hashes,
                        ciphertext_sizes,
                        anchor,
                        balance_slot_asset_ids,
                        binding_hash,
                        stablecoin,
                        *fee,
                    ) {
                        Ok(meta) => {
                            Self::action_meta_to_validity(_source, "ShieldedPoolUnsigned", meta)
                        }
                        Err(err) => err.into(),
                    }
                }
                Call::batch_shielded_transfer {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    total_fee,
                } => {
                    match Self::validate_batch_shielded_transfer_action(
                        proof,
                        nullifiers,
                        commitments,
                        ciphertexts,
                        anchor,
                        *total_fee,
                    ) {
                        Ok(meta) => {
                            Self::action_meta_to_validity(_source, "ShieldedPoolUnsigned", meta)
                        }
                        Err(err) => err.into(),
                    }
                }
                Call::enable_aggregation_mode {} => {
                    match Self::validate_enable_aggregation_mode_action() {
                        Ok(meta) => Self::action_meta_to_validity(
                            _source,
                            "ShieldedPoolAggregationMode",
                            meta,
                        ),
                        Err(err) => err.into(),
                    }
                }
                // Inherent call: mint_coinbase
                // `mint_coinbase` is a pseudo-inherent inserted directly during block assembly
                // after fee accumulation. It still has to pass `ValidateUnsigned`, but the
                // authoritative stateful checks live in `apply_mint_coinbase_action`.
                //
                // Keeping the unsigned path source-restricted but stateless avoids a bad
                // revalidation edge: once the coinbase has executed in-block, `CoinbaseProcessed`
                // is true and a second validation pass on the same extrinsic would otherwise
                // surface a spurious `Stale`/`invalid-shielded-action` error on a valid block.
                Call::mint_coinbase { .. } => Self::action_meta_to_validity(
                    _source,
                    "ShieldedPoolCoinbase",
                    ValidActionMeta {
                        priority: u64::from(TransactionPriority::MAX),
                        longevity: 1,
                        provides: vec![b"coinbase".to_vec()],
                        requires: Vec::new(),
                        propagate: false,
                        source_class: ActionSourceClass::InBlockOnly,
                    },
                ),
                Call::submit_proven_batch { payload } => {
                    match Self::validate_submit_proven_batch_action(payload) {
                        Ok(meta) => {
                            Self::action_meta_to_validity(_source, "ShieldedPoolProvenBatch", meta)
                        }
                        Err(err) => err.into(),
                    }
                }
                // All other calls are invalid as unsigned
                _ => {
                    log::info!(target: "shielded-pool", "ValidateUnsigned: call did not match a proof-native unsigned lane");
                    InvalidTransaction::Call.into()
                }
            }
        }
    }
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{assert_ok, BoundedVec};
    use protocol_kernel::manifest::KernelManifest;
    use protocol_kernel::traits::KernelStateView;
    use sp_runtime::traits::ValidateUnsigned;
    use sp_runtime::transaction_validity::{
        InvalidTransaction, TransactionSource, TransactionValidityError,
    };
    use std::collections::BTreeMap;

    struct DummyKernelState;

    impl KernelStateView for DummyKernelState {
        fn current_height(&self) -> u64 {
            0
        }

        fn family_root(
            &self,
            _family_id: protocol_kernel::types::FamilyId,
        ) -> protocol_kernel::types::FamilyRoot {
            [0u8; 48]
        }

        fn global_root(&self) -> protocol_kernel::types::GlobalRoot {
            [0u8; 48]
        }
    }

    #[test]
    fn note_commitment_matches_types() {
        use commitment::circuit_note_commitment;

        let pk_recipient = [1u8; 32];
        let pk_auth = [9u8; 32];
        let rho = [2u8; 32];
        let r = [3u8; 32];
        let cm = circuit_note_commitment(1000, 0, &pk_recipient, &pk_auth, &rho, &r);

        assert_eq!(cm.len(), 48);
    }

    fn dummy_candidate_artifact() -> types::CandidateArtifact {
        types::CandidateArtifact {
            version: types::BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: 1,
            tx_statements_commitment: [1u8; 48],
            da_root: [2u8; 48],
            da_chunk_count: 1,
            commitment_proof: types::StarkProof::from_bytes(vec![7u8; 32]),
            proof_mode: types::BlockProofMode::ReceiptRoot,
            proof_kind: types::ProofArtifactKind::ReceiptRoot,
            verifier_profile: [3u8; 48],
            receipt_root: Some(types::ReceiptRootProofPayload {
                root_proof: types::StarkProof::from_bytes(vec![8u8; 32]),
                metadata: types::ReceiptRootMetadata {
                    relation_id: [4u8; 32],
                    shape_digest: [5u8; 32],
                    leaf_count: 1,
                    fold_count: 0,
                },
                receipts: vec![types::TxValidityReceipt {
                    statement_hash: [6u8; 48],
                    proof_digest: [7u8; 48],
                    public_inputs_digest: [8u8; 48],
                    verifier_profile: [9u8; 48],
                }],
            }),
        }
    }

    #[test]
    fn validate_unsigned_transfer_is_not_rejected_by_persisted_coinbase_flag() {
        mock::new_test_ext().execute_with(|| {
            let anchor = pallet::MerkleTree::<mock::Test>::get().root();
            pallet::CoinbaseProcessed::<mock::Test>::put(true);

            let nullifiers: BoundedVec<[u8; 48], mock::MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], mock::MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();

            let mut encrypted_note = types::EncryptedNote::default();
            encrypted_note.ciphertext[0] = types::NOTE_ENCRYPTION_VERSION;
            encrypted_note.ciphertext[1..3].copy_from_slice(&types::CRYPTO_SUITE_GAMMA.to_le_bytes());
            let ciphertexts: BoundedVec<types::EncryptedNote, mock::MaxEncryptedNotesPerTx> =
                vec![encrypted_note.clone()].try_into().unwrap();

            let ciphertext_hashes = {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&encrypted_note.ciphertext);
                bytes.extend_from_slice(&encrypted_note.kem_ciphertext);
                vec![transaction_core::hashing_pq::ciphertext_hash_bytes(&bytes)]
            };
            let inputs = verifier::ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes,
                balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
                fee: 0,
                value_balance: 0,
                stablecoin: None,
            };
            let binding_hash = verifier::StarkVerifier::compute_binding_hash(&inputs);

            let call = crate::Call::<mock::Test>::shielded_transfer_unsigned {
                proof: types::StarkProof::from_bytes(vec![1u8; 32]),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
                binding_hash,
                stablecoin: None,
                fee: 0,
            };

            let validity = pallet::Pallet::<mock::Test>::validate_unsigned(
                TransactionSource::External,
                &call,
            );
            assert!(
                !matches!(
                    validity,
                    Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))
                ),
                "persisted coinbase flag should not make next-block mempool transfers stale: {validity:?}"
            );
        });
    }

    #[test]
    fn validate_submit_candidate_artifact_is_not_rejected_by_persisted_flag() {
        mock::new_test_ext().execute_with(|| {
            pallet::ProvenBatchProcessed::<mock::Test>::put(true);

            let meta = pallet::Pallet::<mock::Test>::validate_submit_candidate_artifact_action(
                &dummy_candidate_artifact(),
            )
            .expect("candidate artifact validate path should be stateless");

            assert!(!meta.propagate);
            assert!(matches!(meta.source_class, ActionSourceClass::InBlockOnly));
        });
    }

    #[test]
    fn validate_unsigned_mint_coinbase_stays_valid_after_apply() {
        mock::new_test_ext().execute_with(|| {
            let height: u64 = frame_system::Pallet::<mock::Test>::block_number();
            let subsidy = pallet_coinbase::block_subsidy(height);
            let recipient = [7u8; types::DIVERSIFIED_ADDRESS_SIZE];
            let public_seed = sp_io::hashing::blake2_256(&height.to_le_bytes());
            let pk_recipient = commitment::pk_recipient_from_address(&recipient);
            let pk_auth = commitment::pk_auth_from_address(&recipient);
            let reward_bundle = types::BlockRewardBundle {
                miner_note: types::CoinbaseNoteData {
                    commitment: commitment::circuit_coinbase_commitment(
                        &pk_recipient,
                        &pk_auth,
                        subsidy,
                        &public_seed,
                        0,
                    ),
                    encrypted_note: types::EncryptedNote::default(),
                    recipient_address: recipient,
                    amount: subsidy,
                    public_seed,
                },
            };
            let call = crate::Call::<mock::Test>::mint_coinbase {
                reward_bundle: reward_bundle.clone(),
            };

            let validity_external =
                pallet::Pallet::<mock::Test>::validate_unsigned(TransactionSource::External, &call);
            assert!(matches!(
                validity_external,
                Err(TransactionValidityError::Invalid(InvalidTransaction::Call))
            ));

            let validity_in_block =
                pallet::Pallet::<mock::Test>::validate_unsigned(TransactionSource::InBlock, &call);
            assert!(validity_in_block.is_ok());

            assert_ok!(pallet::Pallet::<mock::Test>::mint_coinbase(
                frame_system::RawOrigin::None.into(),
                reward_bundle,
            ));

            let validity_after_apply =
                pallet::Pallet::<mock::Test>::validate_unsigned(TransactionSource::InBlock, &call);
            assert!(
                validity_after_apply.is_ok(),
                "mint_coinbase should remain valid on in-block revalidation after apply"
            );
        });
    }

    #[test]
    fn kernel_validate_mint_coinbase_stays_valid_after_apply() {
        mock::new_test_ext().execute_with(|| {
            let height: u64 = frame_system::Pallet::<mock::Test>::block_number();
            let subsidy = pallet_coinbase::block_subsidy(height);
            let recipient = [7u8; types::DIVERSIFIED_ADDRESS_SIZE];
            let public_seed = sp_io::hashing::blake2_256(&height.to_le_bytes());
            let pk_recipient = commitment::pk_recipient_from_address(&recipient);
            let pk_auth = commitment::pk_auth_from_address(&recipient);
            let reward_bundle = types::BlockRewardBundle {
                miner_note: types::CoinbaseNoteData {
                    commitment: commitment::circuit_coinbase_commitment(
                        &pk_recipient,
                        &pk_auth,
                        subsidy,
                        &public_seed,
                        0,
                    ),
                    encrypted_note: types::EncryptedNote::default(),
                    recipient_address: recipient,
                    amount: subsidy,
                    public_seed,
                },
            };
            let manifest = KernelManifest {
                manifest_version: 1,
                allowed_bindings: vec![protocol_versioning::DEFAULT_VERSION_BINDING.into()],
                families: BTreeMap::new(),
                policy_commitments: BTreeMap::new(),
            };
            let state = DummyKernelState;
            let envelope = family::build_envelope(
                protocol_versioning::DEFAULT_VERSION_BINDING,
                family::ACTION_MINT_COINBASE,
                Vec::new(),
                family::MintCoinbaseArgs {
                    reward_bundle: reward_bundle.clone(),
                }
                .encode(),
            );

            let validity_before =
                family::validate_action::<mock::Test>(&manifest, &state, &envelope);
            assert!(validity_before.is_ok());

            assert_ok!(pallet::Pallet::<mock::Test>::mint_coinbase(
                frame_system::RawOrigin::None.into(),
                reward_bundle,
            ));

            let validity_after =
                family::validate_action::<mock::Test>(&manifest, &state, &envelope);
            assert!(
                validity_after.is_ok(),
                "kernel family coinbase validation should remain valid on in-block revalidation after apply"
            );
        });
    }
}
