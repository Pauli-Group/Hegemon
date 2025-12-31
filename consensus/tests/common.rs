#![allow(dead_code)]
use consensus::BalanceTag;
use consensus::CoinbaseData;
use consensus::CoinbaseSource;
use consensus::DEFAULT_VERSION_BINDING;
use consensus::RecursiveBlockProof;
use consensus::SupplyDigest;
use consensus::VersionBinding;
use consensus::error::ConsensusError;
use consensus::header::{BlockHeader, PowSeal};
use consensus::nullifier::NullifierSet;
use consensus::reward::{block_subsidy, update_supply_digest};
use consensus::types::{
    ConsensusBlock, DaParams, Transaction, compute_fee_commitment, compute_proof_commitment,
    compute_version_commitment,
};
use consensus::validator::{Validator, ValidatorSet};
use crypto::hashes::sha256;
use crypto::ml_dsa::{ML_DSA_SIGNATURE_LEN, MlDsaSecretKey};
use crypto::traits::{SigningKey, VerifyKey};

#[derive(Clone)]
pub struct TestValidator {
    pub validator: Validator,
    pub secret: MlDsaSecretKey,
}

pub struct BftBlockParams<'a> {
    pub height: u64,
    pub view: u64,
    pub parent_hash: [u8; 32],
    pub timestamp_ms: u64,
    pub transactions: Vec<Transaction>,
    pub recursive_proof: Option<RecursiveBlockProof>,
    pub validators: &'a [TestValidator],
    pub signer_indices: &'a [usize],
    pub base_nullifiers: &'a NullifierSet,
    pub base_state_root: [u8; 32],
    pub supply_digest: SupplyDigest,
}

pub struct PowBlockParams<'a> {
    pub height: u64,
    pub parent_hash: [u8; 32],
    pub timestamp_ms: u64,
    pub transactions: Vec<Transaction>,
    pub recursive_proof: Option<RecursiveBlockProof>,
    pub miner: &'a TestValidator,
    pub base_nullifiers: &'a NullifierSet,
    pub base_state_root: [u8; 32],
    pub pow_bits: u32,
    pub nonce: [u8; 32],
    pub parent_supply: SupplyDigest,
    pub coinbase: CoinbaseData,
}

pub fn make_validators(count: usize, stake: u64) -> Vec<TestValidator> {
    (0..count)
        .map(|idx| {
            let mut seed = Vec::from(b"validator-");
            seed.extend_from_slice(idx.to_be_bytes().as_slice());
            let secret = MlDsaSecretKey::generate_deterministic(&seed);
            let validator = Validator::new(secret.verify_key(), stake);
            TestValidator { validator, secret }
        })
        .collect()
}

pub fn validator_set(validators: &[TestValidator]) -> ValidatorSet {
    ValidatorSet::new(validators.iter().map(|v| v.validator.clone()).collect())
}

#[allow(dead_code)]
pub fn dummy_transaction(tag_seed: u8) -> Transaction {
    dummy_transaction_with_version(tag_seed, DEFAULT_VERSION_BINDING)
}

pub fn dummy_transaction_with_version(tag_seed: u8, version: VersionBinding) -> Transaction {
    let nullifier = [tag_seed; 32];
    let commitment = [tag_seed.wrapping_add(1); 32];
    let balance_tag: BalanceTag = [tag_seed.wrapping_add(2); 32];
    Transaction::new(
        vec![nullifier],
        vec![commitment],
        balance_tag,
        version,
        vec![],
    )
}

pub fn dummy_coinbase(height: u64) -> CoinbaseData {
    CoinbaseData {
        minted: block_subsidy(height),
        fees: 0,
        burns: 0,
        source: CoinbaseSource::BalanceTag([0u8; 32]),
    }
}

pub fn apply_nullifiers(
    base: &NullifierSet,
    transactions: &[Transaction],
) -> Result<NullifierSet, ConsensusError> {
    let mut set = base.clone();
    for tx in transactions {
        for nf in &tx.nullifiers {
            set.insert(*nf)?;
        }
    }
    Ok(set)
}

pub fn accumulate_state(mut root: [u8; 32], transactions: &[Transaction]) -> [u8; 32] {
    for tx in transactions {
        if tx.commitments.is_empty() {
            continue;
        }
        let mut data = Vec::with_capacity(32 + tx.commitments.len() * 32);
        data.extend_from_slice(&root);
        for cm in &tx.commitments {
            data.extend_from_slice(cm);
        }
        root = sha256(&data);
    }
    root
}

pub fn assemble_bft_block(
    params: BftBlockParams<'_>,
) -> Result<(ConsensusBlock, NullifierSet, [u8; 32]), ConsensusError> {
    let BftBlockParams {
        height,
        view,
        parent_hash,
        timestamp_ms,
        transactions,
        recursive_proof,
        validators,
        signer_indices,
        base_nullifiers,
        base_state_root,
        supply_digest,
    } = params;
    let new_nullifiers = apply_nullifiers(base_nullifiers, &transactions)?;
    let nullifier_root = new_nullifiers.commitment();
    let proof_commitment = compute_proof_commitment(&transactions);
    let version_commitment = compute_version_commitment(&transactions);
    let fee_commitment = compute_fee_commitment(&transactions);
    let state_root = accumulate_state(base_state_root, &transactions);
    let recursive_proof_hash = recursive_proof
        .as_ref()
        .map(|proof| proof.recursive_proof_hash)
        .unwrap_or([0u8; 32]);
    let da_params = DaParams {
        chunk_size: 1024,
        sample_count: 4,
    };
    let validator_set = validator_set(validators);
    let mut header = BlockHeader {
        version: 1,
        height,
        view,
        timestamp_ms,
        parent_hash,
        state_root,
        nullifier_root,
        proof_commitment,
        recursive_proof_hash,
        da_root: [0u8; 32],
        da_params,
        version_commitment,
        tx_count: transactions.len() as u32,
        fee_commitment,
        supply_digest,
        validator_set_commitment: validator_set.validator_set_commitment(),
        signature_aggregate: Vec::new(),
        signature_bitmap: Some(vec![0u8; validators.len().div_ceil(8)]),
        pow: None,
    };
    let signing_hash = header.signing_hash()?;
    let mut aggregate = Vec::with_capacity(signer_indices.len() * ML_DSA_SIGNATURE_LEN);
    let mut bitmap = header.signature_bitmap.clone().expect("bitmap initialized");
    for &idx in signer_indices {
        let validator = &validators[idx];
        let signature = validator.secret.sign(&signing_hash);
        aggregate.extend_from_slice(&signature.to_bytes());
        bitmap[idx / 8] |= 1 << (idx % 8);
    }
    header.signature_aggregate = aggregate;
    header.signature_bitmap = Some(bitmap);
    Ok((
        ConsensusBlock {
            header,
            transactions,
            coinbase: None,
            recursive_proof,
        },
        new_nullifiers,
        state_root,
    ))
}

#[allow(dead_code)]
pub fn assemble_pow_block(
    params: PowBlockParams<'_>,
) -> Result<(ConsensusBlock, NullifierSet, [u8; 32]), ConsensusError> {
    let PowBlockParams {
        height,
        parent_hash,
        timestamp_ms,
        transactions,
        recursive_proof,
        miner,
        base_nullifiers,
        base_state_root,
        pow_bits,
        nonce,
        parent_supply,
        coinbase,
    } = params;
    let new_nullifiers = apply_nullifiers(base_nullifiers, &transactions)?;
    let nullifier_root = new_nullifiers.commitment();
    let proof_commitment = compute_proof_commitment(&transactions);
    let version_commitment = compute_version_commitment(&transactions);
    let fee_commitment = compute_fee_commitment(&transactions);
    let state_root = accumulate_state(base_state_root, &transactions);
    let recursive_proof_hash = recursive_proof
        .as_ref()
        .map(|proof| proof.recursive_proof_hash)
        .unwrap_or([0u8; 32]);
    let da_params = DaParams {
        chunk_size: 1024,
        sample_count: 4,
    };
    let mut header = BlockHeader {
        version: 1,
        height,
        view: height,
        timestamp_ms,
        parent_hash,
        state_root,
        nullifier_root,
        proof_commitment,
        recursive_proof_hash,
        da_root: [0u8; 32],
        da_params,
        version_commitment,
        tx_count: transactions.len() as u32,
        fee_commitment,
        supply_digest: update_supply_digest(parent_supply, coinbase.net_native_delta())
            .expect("supply digest"),
        validator_set_commitment: sha256(&miner.validator.public_key().to_bytes()),
        signature_aggregate: Vec::new(),
        signature_bitmap: None,
        pow: Some(PowSeal { nonce, pow_bits }),
    };
    let signing_hash = header.signing_hash()?;
    let signature = miner.secret.sign(&signing_hash);
    header.signature_aggregate = signature.to_bytes().to_vec();
    Ok((
        ConsensusBlock {
            header,
            transactions,
            coinbase: Some(coinbase),
            recursive_proof,
        },
        new_nullifiers,
        state_root,
    ))
}

#[allow(dead_code)]
pub fn empty_nullifier_root() -> [u8; 32] {
    NullifierSet::new().commitment()
}
