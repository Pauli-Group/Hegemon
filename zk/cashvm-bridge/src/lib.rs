use codec::Decode;
use consensus_light_client::{BridgeCheckpointOutputV1, Hash32, Work48};
use protocol_kernel::{
    bridge_payload_hash, BridgeMessageV1, BridgeMintPayloadV1, ChainId, MessageHash, MessageRoot,
    BRIDGE_MINT_APP_FAMILY_ID_V1, BRIDGE_MINT_PAYLOAD_VERSION_V1,
};
use sha2::{Digest, Sha256};

pub const CASHVM_MAX_STANDARD_TX_BYTES: usize = 100_000;
pub const CASHVM_MAX_BYTECODE_BYTES: usize = 10_000;
pub const CASHVM_MAX_STACK_ELEMENT_BYTES: usize = 10_000;
pub const CASHVM_TOKEN_COMMITMENT_BYTES_2026: usize = 128;
pub const CASHVM_SAFE_PROOF_CHUNK_BYTES: usize = 9_216;
pub const CASHVM_BRIDGE_STATE_WIRE_BYTES_V1: usize = 128;
pub const CASHVM_BRIDGE_OUTPUT_WIRE_BYTES_V1: usize = 548;
pub const CASHVM_SAFE_FRAGMENT_TX_PAYLOAD_BYTES: usize = 90_000;
pub const CASHVM_MAX_BRIDGE_MINT_AMOUNT: u64 = i64::MAX as u64;
pub const CASHVM_REPLAY_SET_DEPTH_V1: usize = 128;
pub const HEGEMON_NATIVE_ASSET_ID: u64 = 0;

const CASHVM_BRIDGE_STATE_MAGIC_V1: [u8; 4] = *b"HBC1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CashVmBridgeError {
    AmountOverflow,
    MintPayloadDecodeFailed,
    MintPayloadVersionMismatch,
    MintPayloadSourceAppFamilyMismatch,
    MintPayloadDestinationMismatch,
    MintPayloadNonceMismatch,
    MintPayloadAmountMismatch,
    MintPayloadRecipientZero,
    MintPayloadAmountZero,
    MintPayloadAmountOutOfBounds,
    MintPayloadNativeAssetNotAllowed,
    MintPayloadDestinationPolicyMismatch,
    MintPayloadAssetBindingMismatch,
    MintPayloadRecipientBindingMismatch,
    SequenceOverflow,
    PayloadHashMismatch,
    MessageHashMismatch,
    CashVmMessageHashMismatch,
    EmptyProof,
    ProofStatementMismatch,
    VerifierScriptMismatch,
    InsufficientPqSoundness,
    ProofVerificationUnavailable,
    ProofVerificationFailed,
    NextSequenceMismatch,
    NextCheckpointMismatch,
    NextPolicyMismatch,
    PreviousReplayRootMismatch,
    TrustedCheckpointMismatch,
    ReplayWitnessDepthMismatch,
    ReplayAlreadySpent,
    NextReplayRootMismatch,
    NextSupplyMismatch,
    StateCommitmentSizeMismatch,
    ProofChunkTooLarge,
    EmptyProofChunk,
    ProofChunkCountOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashVmBridgeOutputV1 {
    pub source_chain_id: ChainId,
    pub rules_hash: Hash32,
    pub trusted_checkpoint_digest: Hash32,
    pub checkpoint_height: u64,
    pub checkpoint_header_hash: Hash32,
    pub checkpoint_cumulative_work: Work48,
    pub canonical_tip_height: u64,
    pub canonical_tip_header_hash: Hash32,
    pub canonical_tip_cumulative_work: Work48,
    pub message_root: MessageRoot,
    pub hegemon_message_hash: MessageHash,
    pub cashvm_message_hash: Hash32,
    pub message_nonce: u128,
    pub destination_token_category: Hash32,
    pub recipient_locking_bytecode_hash: Hash32,
    pub amount: u128,
    pub confirmations_checked: u32,
    pub min_work_checked: Work48,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashVmBridgeStateV1 {
    pub verifier_script_hash: Hash32,
    pub expected_destination_chain_id: ChainId,
    pub bridge_instance_id: Hash32,
    pub accepted_checkpoint_digest: Hash32,
    pub replay_root: Hash32,
    pub minted_supply: u128,
    pub sequence: u64,
    pub min_pq_soundness_bits: u16,
    pub flags: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashVmProofEnvelopeV1 {
    pub proof_system_id: Hash32,
    pub verifier_script_hash: Hash32,
    pub pq_soundness_bits: u16,
    pub statement_digest: Hash32,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashVmReplaySetWitnessV1 {
    pub siblings: Vec<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashVmProofChunkV1 {
    pub proof_id: Hash32,
    pub step_index: u32,
    pub step_count: u32,
    pub previous_accumulator: Hash32,
    pub next_accumulator: Hash32,
    pub chunk_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashVmStandardnessReport {
    pub object_bytes: usize,
    pub fits_standard_tx: bool,
    pub fits_single_unlocking_bytecode: bool,
    pub fits_single_stack_element: bool,
    pub stack_elements_required: u32,
    pub fragment_transactions_required: u32,
    pub fragment_payload_bytes: usize,
    pub total_fragment_payload_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashVmBridgeSpendV1 {
    pub previous_state: CashVmBridgeStateV1,
    pub next_state: CashVmBridgeStateV1,
    pub bridge_output: CashVmBridgeOutputV1,
    pub source_message: BridgeMessageV1,
    pub replay_set_witness: CashVmReplaySetWitnessV1,
    pub proof: CashVmProofEnvelopeV1,
}

pub trait CashVmProofVerifier {
    fn verify_cashvm_proof(
        &self,
        proof: &CashVmProofEnvelopeV1,
        output: &CashVmBridgeOutputV1,
    ) -> Result<(), CashVmBridgeError>;
}

impl CashVmBridgeOutputV1 {
    pub fn wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CASHVM_BRIDGE_OUTPUT_WIRE_BYTES_V1);
        out.extend_from_slice(&self.source_chain_id);
        out.extend_from_slice(&self.rules_hash);
        out.extend_from_slice(&self.trusted_checkpoint_digest);
        out.extend_from_slice(&self.checkpoint_height.to_le_bytes());
        out.extend_from_slice(&self.checkpoint_header_hash);
        out.extend_from_slice(&self.checkpoint_cumulative_work);
        out.extend_from_slice(&self.canonical_tip_height.to_le_bytes());
        out.extend_from_slice(&self.canonical_tip_header_hash);
        out.extend_from_slice(&self.canonical_tip_cumulative_work);
        out.extend_from_slice(&self.message_root);
        out.extend_from_slice(&self.hegemon_message_hash);
        out.extend_from_slice(&self.cashvm_message_hash);
        out.extend_from_slice(&self.message_nonce.to_le_bytes());
        out.extend_from_slice(&self.destination_token_category);
        out.extend_from_slice(&self.recipient_locking_bytecode_hash);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.confirmations_checked.to_le_bytes());
        out.extend_from_slice(&self.min_work_checked);
        out
    }

    pub fn statement_digest(&self) -> Hash32 {
        hash256(b"hegemon.cashvm.bridge-output-v1", &[&self.wire_bytes()])
    }

    pub fn checkpoint_digest(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(&self.source_chain_id);
        bytes.extend_from_slice(&self.rules_hash);
        bytes.extend_from_slice(&self.checkpoint_height.to_le_bytes());
        bytes.extend_from_slice(&self.checkpoint_header_hash);
        bytes.extend_from_slice(&self.checkpoint_cumulative_work);
        bytes.extend_from_slice(&self.canonical_tip_height.to_le_bytes());
        bytes.extend_from_slice(&self.canonical_tip_header_hash);
        bytes.extend_from_slice(&self.canonical_tip_cumulative_work);
        hash256(b"hegemon.cashvm.checkpoint-digest-v1", &[&bytes])
    }
}

impl CashVmBridgeStateV1 {
    pub fn policy_hash(&self) -> Hash32 {
        hash256(
            b"hegemon.cashvm.bridge-policy-v1",
            &[
                &self.verifier_script_hash,
                &self.expected_destination_chain_id,
                &self.bridge_instance_id,
                &self.min_pq_soundness_bits.to_le_bytes(),
                &self.flags.to_le_bytes(),
            ],
        )
    }

    pub fn commitment_bytes(&self) -> [u8; CASHVM_BRIDGE_STATE_WIRE_BYTES_V1] {
        let mut out = [0u8; CASHVM_BRIDGE_STATE_WIRE_BYTES_V1];
        out[0..4].copy_from_slice(&CASHVM_BRIDGE_STATE_MAGIC_V1);
        out[4..36].copy_from_slice(&self.policy_hash());
        out[36..68].copy_from_slice(&self.accepted_checkpoint_digest);
        out[68..100].copy_from_slice(&self.replay_root);
        out[100..116].copy_from_slice(&self.minted_supply.to_le_bytes());
        out[116..124].copy_from_slice(&self.sequence.to_le_bytes());
        out[124..126].copy_from_slice(&self.min_pq_soundness_bits.to_le_bytes());
        out[126..128].copy_from_slice(&self.flags.to_le_bytes());
        out
    }

    pub fn commitment_hash(&self) -> Hash32 {
        hash256(
            b"hegemon.cashvm.bridge-state-commitment-v1",
            &[&self.commitment_bytes()],
        )
    }
}

impl CashVmProofEnvelopeV1 {
    pub fn metadata_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(98);
        out.extend_from_slice(&self.proof_system_id);
        out.extend_from_slice(&self.verifier_script_hash);
        out.extend_from_slice(&self.pq_soundness_bits.to_le_bytes());
        out.extend_from_slice(&self.statement_digest);
        out
    }

    pub fn proof_id(&self) -> Hash32 {
        hash256(
            b"hegemon.cashvm.proof-envelope-v1",
            &[&self.metadata_wire_bytes(), &self.proof_bytes],
        )
    }
}

pub fn cashvm_output_from_hegemon(
    hegemon: &BridgeCheckpointOutputV1,
    message: &BridgeMessageV1,
) -> Result<CashVmBridgeOutputV1, CashVmBridgeError> {
    cashvm_output_from_hegemon_for_bridge(hegemon, message, default_cashvm_bridge_instance_id_v1())
}

pub fn cashvm_output_from_hegemon_for_bridge(
    hegemon: &BridgeCheckpointOutputV1,
    message: &BridgeMessageV1,
    bridge_instance_id: Hash32,
) -> Result<CashVmBridgeOutputV1, CashVmBridgeError> {
    let hegemon_message_hash = message.message_hash();
    if message.payload_hash != bridge_payload_hash(&message.payload) {
        return Err(CashVmBridgeError::PayloadHashMismatch);
    }
    if hegemon_message_hash != hegemon.message_hash {
        return Err(CashVmBridgeError::MessageHashMismatch);
    }
    let mint_payload = decode_bridge_mint_payload(&message.payload)?;
    validate_bridge_mint_payload_binding(&mint_payload, message)?;
    let destination_token_category =
        cashvm_token_category_for_mint_payload_and_bridge(&mint_payload, bridge_instance_id);
    let recipient_locking_bytecode_hash =
        cashvm_recipient_locking_bytecode_hash_for_mint_payload(&mint_payload);
    Ok(CashVmBridgeOutputV1 {
        source_chain_id: hegemon.source_chain_id,
        rules_hash: hegemon.rules_hash,
        trusted_checkpoint_digest: hegemon.trusted_checkpoint_digest,
        checkpoint_height: hegemon.checkpoint_height,
        checkpoint_header_hash: hegemon.checkpoint_header_hash,
        checkpoint_cumulative_work: hegemon.checkpoint_cumulative_work,
        canonical_tip_height: hegemon.canonical_tip_height,
        canonical_tip_header_hash: hegemon.canonical_tip_header_hash,
        canonical_tip_cumulative_work: hegemon.canonical_tip_cumulative_work,
        message_root: hegemon.message_root,
        hegemon_message_hash,
        cashvm_message_hash: cashvm_message_digest(message),
        message_nonce: hegemon.message_nonce,
        destination_token_category,
        recipient_locking_bytecode_hash,
        amount: u128::from(mint_payload.amount),
        confirmations_checked: hegemon.confirmations_checked,
        min_work_checked: hegemon.min_work_checked,
    })
}

pub fn default_cashvm_bridge_instance_id_v1() -> Hash32 {
    hash256(b"hegemon.cashvm.default-bridge-instance-v1", &[])
}

fn decode_bridge_mint_payload(payload: &[u8]) -> Result<BridgeMintPayloadV1, CashVmBridgeError> {
    let mut input = payload;
    let mint_payload = BridgeMintPayloadV1::decode(&mut input)
        .map_err(|_| CashVmBridgeError::MintPayloadDecodeFailed)?;
    if !input.is_empty() {
        return Err(CashVmBridgeError::MintPayloadDecodeFailed);
    }
    Ok(mint_payload)
}

fn validate_bridge_mint_payload_binding(
    payload: &BridgeMintPayloadV1,
    message: &BridgeMessageV1,
) -> Result<(), CashVmBridgeError> {
    if payload.version != BRIDGE_MINT_PAYLOAD_VERSION_V1 {
        return Err(CashVmBridgeError::MintPayloadVersionMismatch);
    }
    if message.app_family_id != BRIDGE_MINT_APP_FAMILY_ID_V1 {
        return Err(CashVmBridgeError::MintPayloadSourceAppFamilyMismatch);
    }
    if payload.destination_chain_id != message.destination_chain_id {
        return Err(CashVmBridgeError::MintPayloadDestinationMismatch);
    }
    if payload.mint_nonce != message.message_nonce {
        return Err(CashVmBridgeError::MintPayloadNonceMismatch);
    }
    if payload.recipient_commitment == [0u8; 48] {
        return Err(CashVmBridgeError::MintPayloadRecipientZero);
    }
    if payload.amount == 0 {
        return Err(CashVmBridgeError::MintPayloadAmountZero);
    }
    if payload.amount > CASHVM_MAX_BRIDGE_MINT_AMOUNT {
        return Err(CashVmBridgeError::MintPayloadAmountOutOfBounds);
    }
    if payload.asset_id == HEGEMON_NATIVE_ASSET_ID {
        return Err(CashVmBridgeError::MintPayloadNativeAssetNotAllowed);
    }
    Ok(())
}

pub fn cashvm_token_category_for_mint_payload(payload: &BridgeMintPayloadV1) -> Hash32 {
    cashvm_token_category_for_mint_payload_and_bridge(
        payload,
        default_cashvm_bridge_instance_id_v1(),
    )
}

pub fn cashvm_token_category_for_mint_payload_and_bridge(
    payload: &BridgeMintPayloadV1,
    bridge_instance_id: Hash32,
) -> Hash32 {
    hash256(
        b"hegemon.cashvm.asset-token-category-v1",
        &[
            &bridge_instance_id,
            &payload.destination_chain_id,
            &payload.asset_id.to_le_bytes(),
        ],
    )
}

pub fn cashvm_recipient_locking_bytecode_hash_for_mint_payload(
    payload: &BridgeMintPayloadV1,
) -> Hash32 {
    hash256(
        b"hegemon.cashvm.recipient-locking-bytecode-hash-v1",
        &[&payload.destination_chain_id, &payload.recipient_commitment],
    )
}

pub fn cashvm_message_digest(message: &BridgeMessageV1) -> Hash32 {
    let app_family_id = message.app_family_id.to_le_bytes();
    let message_nonce = message.message_nonce.to_le_bytes();
    let source_height = message.source_height.to_le_bytes();
    let payload_len = (message.payload.len() as u64).to_le_bytes();
    hash256(
        b"hegemon.cashvm.message-v1",
        &[
            &message.source_chain_id,
            &message.destination_chain_id,
            &app_family_id,
            &message_nonce,
            &source_height,
            &message.payload_hash,
            &payload_len,
            &message.payload,
        ],
    )
}

pub fn empty_replay_set_root() -> Hash32 {
    replay_set_default_hashes()[CASHVM_REPLAY_SET_DEPTH_V1]
}

pub fn empty_replay_set_witness() -> CashVmReplaySetWitnessV1 {
    CashVmReplaySetWitnessV1 {
        siblings: replay_set_default_hashes()[..CASHVM_REPLAY_SET_DEPTH_V1].to_vec(),
    }
}

pub fn replay_set_consumed_root(
    source_chain_id: ChainId,
    nonce: u128,
    witness: &CashVmReplaySetWitnessV1,
) -> Result<Hash32, CashVmBridgeError> {
    replay_set_root_from_leaf(
        source_chain_id,
        nonce,
        replay_set_consumed_leaf(source_chain_id, nonce),
        &witness.siblings,
    )
}

fn replay_set_empty_leaf() -> Hash32 {
    hash256(b"hegemon.cashvm.replay-set-empty-leaf-v1", &[])
}

fn replay_set_consumed_leaf(source_chain_id: ChainId, nonce: u128) -> Hash32 {
    hash256(
        b"hegemon.cashvm.replay-set-consumed-leaf-v1",
        &[&source_chain_id, &nonce.to_le_bytes()],
    )
}

fn replay_set_default_hashes() -> [Hash32; CASHVM_REPLAY_SET_DEPTH_V1 + 1] {
    let mut defaults = [[0u8; 32]; CASHVM_REPLAY_SET_DEPTH_V1 + 1];
    defaults[0] = replay_set_empty_leaf();
    for level in 0..CASHVM_REPLAY_SET_DEPTH_V1 {
        defaults[level + 1] = replay_set_parent_hash(defaults[level], defaults[level]);
    }
    defaults
}

fn replay_set_key_bytes(source_chain_id: ChainId, nonce: u128) -> [u8; 16] {
    let digest = hash256(
        b"hegemon.cashvm.replay-set-key-v1",
        &[&source_chain_id, &nonce.to_le_bytes()],
    );
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

fn replay_set_key_bit(key: &[u8; 16], level: usize) -> bool {
    ((key[level / 8] >> (level % 8)) & 1) == 1
}

fn replay_set_parent_hash(left: Hash32, right: Hash32) -> Hash32 {
    hash256(b"hegemon.cashvm.replay-set-node-v1", &[&left, &right])
}

fn replay_set_root_from_leaf(
    source_chain_id: ChainId,
    nonce: u128,
    leaf: Hash32,
    siblings: &[Hash32],
) -> Result<Hash32, CashVmBridgeError> {
    if siblings.len() != CASHVM_REPLAY_SET_DEPTH_V1 {
        return Err(CashVmBridgeError::ReplayWitnessDepthMismatch);
    }
    let key = replay_set_key_bytes(source_chain_id, nonce);
    let mut current = leaf;
    for (level, sibling) in siblings.iter().copied().enumerate() {
        current = if replay_set_key_bit(&key, level) {
            replay_set_parent_hash(sibling, current)
        } else {
            replay_set_parent_hash(current, sibling)
        };
    }
    Ok(current)
}

pub fn verify_cashvm_bridge_spend_model(
    spend: &CashVmBridgeSpendV1,
) -> Result<(), CashVmBridgeError> {
    verify_cashvm_bridge_spend_model_checked(spend, |_proof, _output| {
        Err(CashVmBridgeError::ProofVerificationUnavailable)
    })
}

pub fn verify_cashvm_bridge_spend_model_with_verifier<V: CashVmProofVerifier + ?Sized>(
    spend: &CashVmBridgeSpendV1,
    verifier: &V,
) -> Result<(), CashVmBridgeError> {
    verify_cashvm_bridge_spend_model_checked(spend, |proof, output| {
        verifier.verify_cashvm_proof(proof, output)
    })
}

fn verify_cashvm_bridge_spend_model_checked<F>(
    spend: &CashVmBridgeSpendV1,
    verify_proof: F,
) -> Result<(), CashVmBridgeError>
where
    F: FnOnce(&CashVmProofEnvelopeV1, &CashVmBridgeOutputV1) -> Result<(), CashVmBridgeError>,
{
    if spend.source_message.payload_hash != bridge_payload_hash(&spend.source_message.payload) {
        return Err(CashVmBridgeError::PayloadHashMismatch);
    }
    if spend.bridge_output.hegemon_message_hash != spend.source_message.message_hash() {
        return Err(CashVmBridgeError::MessageHashMismatch);
    }
    if spend.bridge_output.cashvm_message_hash != cashvm_message_digest(&spend.source_message) {
        return Err(CashVmBridgeError::CashVmMessageHashMismatch);
    }
    if spend.bridge_output.trusted_checkpoint_digest
        != spend.previous_state.accepted_checkpoint_digest
    {
        return Err(CashVmBridgeError::TrustedCheckpointMismatch);
    }
    let mint_payload = decode_bridge_mint_payload(&spend.source_message.payload)?;
    validate_bridge_mint_payload_binding(&mint_payload, &spend.source_message)?;
    if mint_payload.destination_chain_id != spend.previous_state.expected_destination_chain_id {
        return Err(CashVmBridgeError::MintPayloadDestinationPolicyMismatch);
    }
    if spend.bridge_output.message_nonce != mint_payload.mint_nonce {
        return Err(CashVmBridgeError::MintPayloadNonceMismatch);
    }
    if spend.bridge_output.amount != u128::from(mint_payload.amount) {
        return Err(CashVmBridgeError::MintPayloadAmountMismatch);
    }
    if spend.bridge_output.destination_token_category
        != cashvm_token_category_for_mint_payload_and_bridge(
            &mint_payload,
            spend.previous_state.bridge_instance_id,
        )
    {
        return Err(CashVmBridgeError::MintPayloadAssetBindingMismatch);
    }
    if spend.bridge_output.recipient_locking_bytecode_hash
        != cashvm_recipient_locking_bytecode_hash_for_mint_payload(&mint_payload)
    {
        return Err(CashVmBridgeError::MintPayloadRecipientBindingMismatch);
    }
    if spend.proof.proof_bytes.is_empty() {
        return Err(CashVmBridgeError::EmptyProof);
    }
    if spend.proof.statement_digest != spend.bridge_output.statement_digest() {
        return Err(CashVmBridgeError::ProofStatementMismatch);
    }
    if spend.proof.verifier_script_hash != spend.previous_state.verifier_script_hash {
        return Err(CashVmBridgeError::VerifierScriptMismatch);
    }
    if spend.proof.pq_soundness_bits < spend.previous_state.min_pq_soundness_bits {
        return Err(CashVmBridgeError::InsufficientPqSoundness);
    }
    verify_proof(&spend.proof, &spend.bridge_output)?;
    let expected_sequence = spend
        .previous_state
        .sequence
        .checked_add(1)
        .ok_or(CashVmBridgeError::SequenceOverflow)?;
    if spend.next_state.sequence != expected_sequence {
        return Err(CashVmBridgeError::NextSequenceMismatch);
    }
    if spend.next_state.verifier_script_hash != spend.previous_state.verifier_script_hash
        || spend.next_state.expected_destination_chain_id
            != spend.previous_state.expected_destination_chain_id
        || spend.next_state.bridge_instance_id != spend.previous_state.bridge_instance_id
        || spend.next_state.min_pq_soundness_bits != spend.previous_state.min_pq_soundness_bits
        || spend.next_state.flags != spend.previous_state.flags
    {
        return Err(CashVmBridgeError::NextPolicyMismatch);
    }
    if spend.next_state.accepted_checkpoint_digest != spend.bridge_output.checkpoint_digest() {
        return Err(CashVmBridgeError::NextCheckpointMismatch);
    }
    let expected_previous_replay_root = replay_set_root_from_leaf(
        spend.bridge_output.source_chain_id,
        mint_payload.mint_nonce,
        replay_set_empty_leaf(),
        &spend.replay_set_witness.siblings,
    )?;
    if spend.previous_state.replay_root != expected_previous_replay_root {
        let spent_root = replay_set_root_from_leaf(
            spend.bridge_output.source_chain_id,
            mint_payload.mint_nonce,
            replay_set_consumed_leaf(spend.bridge_output.source_chain_id, mint_payload.mint_nonce),
            &spend.replay_set_witness.siblings,
        )?;
        if spend.previous_state.replay_root == spent_root {
            return Err(CashVmBridgeError::ReplayAlreadySpent);
        }
        return Err(CashVmBridgeError::PreviousReplayRootMismatch);
    }
    let expected_replay_root = replay_set_consumed_root(
        spend.bridge_output.source_chain_id,
        mint_payload.mint_nonce,
        &spend.replay_set_witness,
    )?;
    if spend.next_state.replay_root != expected_replay_root {
        return Err(CashVmBridgeError::NextReplayRootMismatch);
    }
    let expected_supply = spend
        .previous_state
        .minted_supply
        .checked_add(spend.bridge_output.amount)
        .ok_or(CashVmBridgeError::AmountOverflow)?;
    if spend.next_state.minted_supply != expected_supply {
        return Err(CashVmBridgeError::NextSupplyMismatch);
    }
    if spend.next_state.commitment_bytes().len() != CASHVM_TOKEN_COMMITMENT_BYTES_2026 {
        return Err(CashVmBridgeError::StateCommitmentSizeMismatch);
    }
    Ok(())
}

pub fn chunk_cashvm_proof(
    proof_bytes: &[u8],
    chunk_payload_bytes: usize,
) -> Result<Vec<CashVmProofChunkV1>, CashVmBridgeError> {
    if chunk_payload_bytes == 0 {
        return Err(CashVmBridgeError::EmptyProofChunk);
    }
    if chunk_payload_bytes > CASHVM_MAX_STACK_ELEMENT_BYTES {
        return Err(CashVmBridgeError::ProofChunkTooLarge);
    }
    if proof_bytes.is_empty() {
        return Err(CashVmBridgeError::EmptyProof);
    }
    let step_count: u32 = proof_bytes
        .len()
        .div_ceil(chunk_payload_bytes)
        .try_into()
        .map_err(|_| CashVmBridgeError::ProofChunkCountOverflow)?;
    let proof_id = hash256(b"hegemon.cashvm.proof-bytes-v1", &[proof_bytes]);
    let mut accumulator = [0u8; 32];
    let mut chunks = Vec::with_capacity(step_count as usize);
    for (idx, chunk) in proof_bytes.chunks(chunk_payload_bytes).enumerate() {
        let previous_accumulator = accumulator;
        let mut step_bytes = Vec::with_capacity(8 + chunk.len());
        step_bytes.extend_from_slice(&(idx as u32).to_le_bytes());
        step_bytes.extend_from_slice(&step_count.to_le_bytes());
        step_bytes.extend_from_slice(chunk);
        accumulator = hash256(
            b"hegemon.cashvm.proof-chunk-v1",
            &[&previous_accumulator, &proof_id, &step_bytes],
        );
        chunks.push(CashVmProofChunkV1 {
            proof_id,
            step_index: idx as u32,
            step_count,
            previous_accumulator,
            next_accumulator: accumulator,
            chunk_bytes: chunk.to_vec(),
        });
    }
    Ok(chunks)
}

pub fn cashvm_standardness_report(
    object_bytes: usize,
    fragment_payload_bytes: usize,
) -> CashVmStandardnessReport {
    let fragment_payload_bytes = fragment_payload_bytes.clamp(1, CASHVM_MAX_STANDARD_TX_BYTES);
    let fragment_transactions_required = object_bytes.div_ceil(fragment_payload_bytes) as u32;
    let stack_elements_required = object_bytes.div_ceil(CASHVM_MAX_STACK_ELEMENT_BYTES) as u32;
    CashVmStandardnessReport {
        object_bytes,
        fits_standard_tx: object_bytes <= CASHVM_MAX_STANDARD_TX_BYTES,
        fits_single_unlocking_bytecode: object_bytes <= CASHVM_MAX_BYTECODE_BYTES,
        fits_single_stack_element: object_bytes <= CASHVM_MAX_STACK_ELEMENT_BYTES,
        stack_elements_required,
        fragment_transactions_required,
        fragment_payload_bytes,
        total_fragment_payload_bytes: fragment_transactions_required as usize
            * fragment_payload_bytes,
    }
}

pub fn hash256(domain: &[u8], chunks: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u32).to_le_bytes());
    hasher.update(domain);
    for chunk in chunks {
        hasher.update((chunk.len() as u64).to_le_bytes());
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;
    use consensus_light_client::{
        BridgeCheckpointOutputV1, HEGEMON_CHAIN_ID_V1, HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
    };
    use protocol_kernel::{bridge_payload_hash, BridgeMessageV1, BRIDGE_MINT_APP_FAMILY_ID_V1};
    use serde::Deserialize;

    fn hash32(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn work48(byte: u8) -> Work48 {
        [byte; 48]
    }

    fn message_with_nonce(nonce: u128) -> BridgeMessageV1 {
        let payload = BridgeMintPayloadV1 {
            version: BRIDGE_MINT_PAYLOAD_VERSION_V1,
            destination_chain_id: hash32(0x42),
            recipient_commitment: [0x23; 48],
            asset_id: 7,
            amount: 1_000,
            mint_nonce: nonce,
        }
        .encode();
        BridgeMessageV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            destination_chain_id: hash32(0x42),
            app_family_id: BRIDGE_MINT_APP_FAMILY_ID_V1,
            message_nonce: nonce,
            source_height: 11,
            payload_hash: bridge_payload_hash(&payload),
            payload,
        }
    }

    fn message() -> BridgeMessageV1 {
        message_with_nonce(42)
    }

    fn hegemon_output(message: &BridgeMessageV1) -> BridgeCheckpointOutputV1 {
        BridgeCheckpointOutputV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
            trusted_checkpoint_digest: hash32(0x10),
            checkpoint_height: message.source_height,
            checkpoint_header_hash: hash32(0x11),
            checkpoint_cumulative_work: work48(0x12),
            canonical_tip_height: message.source_height + 2,
            canonical_tip_header_hash: hash32(0x13),
            canonical_tip_cumulative_work: work48(0x14),
            message_root: [0x15; 48],
            message_hash: message.message_hash(),
            message_nonce: message.message_nonce,
            confirmations_checked: 3,
            min_work_checked: [0u8; 48],
        }
    }

    fn cashvm_output() -> CashVmBridgeOutputV1 {
        let message = message();
        cashvm_output_from_hegemon(&hegemon_output(&message), &message).expect("cashvm output")
    }

    fn state(output: &CashVmBridgeOutputV1) -> CashVmBridgeStateV1 {
        CashVmBridgeStateV1 {
            verifier_script_hash: hash32(0x33),
            expected_destination_chain_id: hash32(0x42),
            bridge_instance_id: default_cashvm_bridge_instance_id_v1(),
            accepted_checkpoint_digest: output.trusted_checkpoint_digest,
            replay_root: empty_replay_set_root(),
            minted_supply: 10_000,
            sequence: 5,
            min_pq_soundness_bits: 96,
            flags: 0,
        }
    }

    fn spend_for(message: BridgeMessageV1) -> CashVmBridgeSpendV1 {
        let output =
            cashvm_output_from_hegemon(&hegemon_output(&message), &message).expect("output");
        let previous_state = state(&output);
        let replay_set_witness = empty_replay_set_witness();
        let next_state = CashVmBridgeStateV1 {
            accepted_checkpoint_digest: output.checkpoint_digest(),
            replay_root: replay_set_consumed_root(
                output.source_chain_id,
                output.message_nonce,
                &replay_set_witness,
            )
            .expect("replay root"),
            minted_supply: previous_state.minted_supply + output.amount,
            sequence: previous_state.sequence + 1,
            ..previous_state.clone()
        };
        let proof = CashVmProofEnvelopeV1 {
            proof_system_id: hash32(0x55),
            verifier_script_hash: previous_state.verifier_script_hash,
            pq_soundness_bits: 128,
            statement_digest: output.statement_digest(),
            proof_bytes: vec![0x99; 128],
        };
        CashVmBridgeSpendV1 {
            previous_state,
            next_state,
            bridge_output: output,
            source_message: message,
            replay_set_witness,
            proof,
        }
    }

    fn rebind_spend_message_and_statement(spend: &mut CashVmBridgeSpendV1) {
        spend.source_message.payload_hash = bridge_payload_hash(&spend.source_message.payload);
        spend.bridge_output.hegemon_message_hash = spend.source_message.message_hash();
        spend.bridge_output.cashvm_message_hash = cashvm_message_digest(&spend.source_message);
        spend.proof.statement_digest = spend.bridge_output.statement_digest();
    }

    fn rebind_spend_to_previous_state_checkpoint(spend: &mut CashVmBridgeSpendV1) {
        spend.bridge_output.trusted_checkpoint_digest =
            spend.previous_state.accepted_checkpoint_digest;
        spend.proof.statement_digest = spend.bridge_output.statement_digest();
    }

    fn singleton_replay_subtree_root(
        source_chain_id: ChainId,
        nonce: u128,
        height: usize,
    ) -> Hash32 {
        let defaults = replay_set_default_hashes();
        let key = replay_set_key_bytes(source_chain_id, nonce);
        let mut current = replay_set_consumed_leaf(source_chain_id, nonce);
        for (level, sibling) in defaults.iter().copied().enumerate().take(height) {
            current = if replay_set_key_bit(&key, level) {
                replay_set_parent_hash(sibling, current)
            } else {
                replay_set_parent_hash(current, sibling)
            };
        }
        current
    }

    fn replay_absence_witness_with_one_spent(
        target_source_chain_id: ChainId,
        target_nonce: u128,
        spent_source_chain_id: ChainId,
        spent_nonce: u128,
    ) -> CashVmReplaySetWitnessV1 {
        let defaults = replay_set_default_hashes();
        let target_key = replay_set_key_bytes(target_source_chain_id, target_nonce);
        let spent_key = replay_set_key_bytes(spent_source_chain_id, spent_nonce);
        let divergence = (0..CASHVM_REPLAY_SET_DEPTH_V1)
            .rev()
            .find(|level| {
                replay_set_key_bit(&target_key, *level) != replay_set_key_bit(&spent_key, *level)
            })
            .expect("distinct test nonces should not collide in replay path");
        let mut siblings = defaults[..CASHVM_REPLAY_SET_DEPTH_V1].to_vec();
        siblings[divergence] =
            singleton_replay_subtree_root(spent_source_chain_id, spent_nonce, divergence);
        CashVmReplaySetWitnessV1 { siblings }
    }

    struct AcceptingProofVerifier;

    impl CashVmProofVerifier for AcceptingProofVerifier {
        fn verify_cashvm_proof(
            &self,
            _proof: &CashVmProofEnvelopeV1,
            _output: &CashVmBridgeOutputV1,
        ) -> Result<(), CashVmBridgeError> {
            Ok(())
        }
    }

    struct ExactProofVerifier {
        proof_bytes: Vec<u8>,
    }

    impl CashVmProofVerifier for ExactProofVerifier {
        fn verify_cashvm_proof(
            &self,
            proof: &CashVmProofEnvelopeV1,
            _output: &CashVmBridgeOutputV1,
        ) -> Result<(), CashVmBridgeError> {
            if proof.proof_bytes == self.proof_bytes {
                Ok(())
            } else {
                Err(CashVmBridgeError::ProofVerificationFailed)
            }
        }
    }

    #[test]
    fn cashvm_bridge_output_is_deterministic_and_sha256_bound() {
        let output = cashvm_output();
        assert_eq!(
            output.wire_bytes().len(),
            CASHVM_BRIDGE_OUTPUT_WIRE_BYTES_V1
        );
        assert_eq!(output.statement_digest(), output.statement_digest());
        assert_ne!(output.statement_digest(), output.checkpoint_digest());
    }

    #[test]
    fn state_commitment_fits_2026_token_commitment() {
        let output = cashvm_output();
        let state = state(&output);
        assert_eq!(
            state.commitment_bytes().len(),
            CASHVM_TOKEN_COMMITMENT_BYTES_2026
        );
        assert_ne!(state.commitment_hash(), state.accepted_checkpoint_digest);
    }

    #[test]
    fn proof_chunking_reassembles_with_chained_accumulators() {
        let proof = vec![0x7au8; 22_001];
        let chunks = chunk_cashvm_proof(&proof, 9_000).expect("chunks");
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].step_index, 0);
        assert_eq!(chunks[2].step_count, 3);
        assert_eq!(chunks[1].previous_accumulator, chunks[0].next_accumulator);
        assert_eq!(chunks[2].previous_accumulator, chunks[1].next_accumulator);
        let reassembled = chunks
            .iter()
            .flat_map(|chunk| chunk.chunk_bytes.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(reassembled, proof);
        assert_eq!(
            chunk_cashvm_proof(&[], 9_000),
            Err(CashVmBridgeError::EmptyProof)
        );
        assert_eq!(
            chunk_cashvm_proof(&proof, CASHVM_MAX_STACK_ELEMENT_BYTES + 1),
            Err(CashVmBridgeError::ProofChunkTooLarge)
        );
    }

    #[test]
    fn standardness_report_matches_current_measured_objects() {
        let long_range = cashvm_standardness_report(9_951, CASHVM_SAFE_FRAGMENT_TX_PAYLOAD_BYTES);
        assert!(long_range.fits_standard_tx);
        assert!(long_range.fits_single_stack_element);
        assert_eq!(long_range.stack_elements_required, 1);
        assert_eq!(long_range.fragment_transactions_required, 1);

        let succinct = cashvm_standardness_report(224_508, CASHVM_SAFE_FRAGMENT_TX_PAYLOAD_BYTES);
        assert!(!succinct.fits_standard_tx);
        assert_eq!(succinct.stack_elements_required, 23);
        assert_eq!(succinct.fragment_transactions_required, 3);

        let composite = cashvm_standardness_report(492_158, CASHVM_SAFE_FRAGMENT_TX_PAYLOAD_BYTES);
        assert!(!composite.fits_standard_tx);
        assert_eq!(composite.stack_elements_required, 50);
        assert_eq!(composite.fragment_transactions_required, 6);
    }

    #[test]
    fn spend_model_requires_external_proof_verifier() {
        let spend = spend_for(message());
        assert_eq!(
            verify_cashvm_bridge_spend_model(&spend),
            Err(CashVmBridgeError::ProofVerificationUnavailable)
        );
    }

    #[test]
    fn spend_model_accepts_valid_bridge_transition_with_verifier() {
        let spend = spend_for(message());
        let verifier = ExactProofVerifier {
            proof_bytes: spend.proof.proof_bytes.clone(),
        };
        verify_cashvm_bridge_spend_model_with_verifier(&spend, &verifier).expect("valid spend");
    }

    #[test]
    fn spend_model_rejects_arbitrary_proof_bytes_when_verifier_rejects() {
        let mut spend = spend_for(message());
        let verifier = ExactProofVerifier {
            proof_bytes: spend.proof.proof_bytes.clone(),
        };
        spend.proof.proof_bytes.push(0x42);
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(&spend, &verifier),
            Err(CashVmBridgeError::ProofVerificationFailed)
        );
    }

    #[test]
    fn spend_model_rejects_tampering() {
        let base = spend_for(message());

        let mut weak = base.clone();
        weak.proof.pq_soundness_bits = 80;
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(&weak, &AcceptingProofVerifier),
            Err(CashVmBridgeError::InsufficientPqSoundness)
        );

        let mut wrong_verifier = base.clone();
        wrong_verifier.proof.verifier_script_hash = hash32(0xaa);
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &wrong_verifier,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::VerifierScriptMismatch)
        );

        let mut empty_proof = base.clone();
        empty_proof.proof.proof_bytes.clear();
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(&empty_proof, &AcceptingProofVerifier),
            Err(CashVmBridgeError::EmptyProof)
        );

        let mut wrong_statement = base.clone();
        wrong_statement.proof.statement_digest = hash32(0xcc);
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &wrong_statement,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::ProofStatementMismatch)
        );

        let mut wrong_trusted_anchor = base.clone();
        wrong_trusted_anchor
            .previous_state
            .accepted_checkpoint_digest = hash32(0xcd);
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &wrong_trusted_anchor,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::TrustedCheckpointMismatch)
        );

        let mut wrong_checkpoint = base.clone();
        wrong_checkpoint.next_state.accepted_checkpoint_digest = hash32(0xdd);
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &wrong_checkpoint,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::NextCheckpointMismatch)
        );

        let mut supply_overflow = base.clone();
        supply_overflow.previous_state.minted_supply = u128::MAX;
        supply_overflow.next_state.minted_supply = u128::MAX;
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &supply_overflow,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::AmountOverflow)
        );

        let mut wrong_replay = base.clone();
        wrong_replay.next_state.replay_root = hash32(0xbb);
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(&wrong_replay, &AcceptingProofVerifier),
            Err(CashVmBridgeError::NextReplayRootMismatch)
        );

        let mut weak_next_policy = base.clone();
        weak_next_policy.next_state.min_pq_soundness_bits = 80;
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &weak_next_policy,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::NextPolicyMismatch)
        );

        let mut wrong_message = base;
        wrong_message.source_message.payload.push(0);
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(&wrong_message, &AcceptingProofVerifier),
            Err(CashVmBridgeError::PayloadHashMismatch)
        );

        wrong_message.source_message.payload_hash =
            bridge_payload_hash(&wrong_message.source_message.payload);
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(&wrong_message, &AcceptingProofVerifier),
            Err(CashVmBridgeError::MessageHashMismatch)
        );

        let mut wrong_cashvm_digest = wrong_message;
        wrong_cashvm_digest.bridge_output.hegemon_message_hash =
            wrong_cashvm_digest.source_message.message_hash();
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &wrong_cashvm_digest,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::CashVmMessageHashMismatch)
        );
    }

    #[test]
    fn output_helper_binds_cashvm_fields_to_hegemon_mint_payload() {
        let mut message = message();
        let mut payload =
            BridgeMintPayloadV1::decode(&mut &message.payload[..]).expect("mint payload");
        payload.amount = 7_500;
        message.payload = payload.encode();
        message.payload_hash = bridge_payload_hash(&message.payload);
        let output =
            cashvm_output_from_hegemon(&hegemon_output(&message), &message).expect("output");
        assert_eq!(output.amount, 7_500);
        assert_eq!(
            output.destination_token_category,
            cashvm_token_category_for_mint_payload(&payload)
        );
        assert_eq!(
            output.recipient_locking_bytecode_hash,
            cashvm_recipient_locking_bytecode_hash_for_mint_payload(&payload)
        );

        let mut bad_family = message.clone();
        bad_family.app_family_id = BRIDGE_MINT_APP_FAMILY_ID_V1.saturating_add(1);
        assert_eq!(
            cashvm_output_from_hegemon(&hegemon_output(&bad_family), &bad_family),
            Err(CashVmBridgeError::MintPayloadSourceAppFamilyMismatch)
        );

        let mut bad_nonce = message;
        let mut payload =
            BridgeMintPayloadV1::decode(&mut &bad_nonce.payload[..]).expect("mint payload");
        payload.mint_nonce = bad_nonce.message_nonce + 1;
        bad_nonce.payload = payload.encode();
        bad_nonce.payload_hash = bridge_payload_hash(&bad_nonce.payload);
        assert_eq!(
            cashvm_output_from_hegemon(&hegemon_output(&bad_nonce), &bad_nonce),
            Err(CashVmBridgeError::MintPayloadNonceMismatch)
        );

        let mut bad_destination = bad_nonce;
        let mut payload =
            BridgeMintPayloadV1::decode(&mut &bad_destination.payload[..]).expect("mint payload");
        payload.mint_nonce = bad_destination.message_nonce;
        payload.destination_chain_id = hash32(0x99);
        bad_destination.payload = payload.encode();
        bad_destination.payload_hash = bridge_payload_hash(&bad_destination.payload);
        assert_eq!(
            cashvm_output_from_hegemon(&hegemon_output(&bad_destination), &bad_destination),
            Err(CashVmBridgeError::MintPayloadDestinationMismatch)
        );

        let mut zero_recipient = bad_destination;
        let mut payload =
            BridgeMintPayloadV1::decode(&mut &zero_recipient.payload[..]).expect("mint payload");
        payload.destination_chain_id = zero_recipient.destination_chain_id;
        payload.recipient_commitment = [0u8; 48];
        zero_recipient.payload = payload.encode();
        zero_recipient.payload_hash = bridge_payload_hash(&zero_recipient.payload);
        assert_eq!(
            cashvm_output_from_hegemon(&hegemon_output(&zero_recipient), &zero_recipient),
            Err(CashVmBridgeError::MintPayloadRecipientZero)
        );

        let mut zero_amount = zero_recipient;
        let mut payload =
            BridgeMintPayloadV1::decode(&mut &zero_amount.payload[..]).expect("mint payload");
        payload.recipient_commitment = [0x23; 48];
        payload.amount = 0;
        zero_amount.payload = payload.encode();
        zero_amount.payload_hash = bridge_payload_hash(&zero_amount.payload);
        assert_eq!(
            cashvm_output_from_hegemon(&hegemon_output(&zero_amount), &zero_amount),
            Err(CashVmBridgeError::MintPayloadAmountZero)
        );

        let mut amount_over_bound = zero_amount;
        let mut payload =
            BridgeMintPayloadV1::decode(&mut &amount_over_bound.payload[..]).expect("mint payload");
        payload.amount = CASHVM_MAX_BRIDGE_MINT_AMOUNT + 1;
        amount_over_bound.payload = payload.encode();
        amount_over_bound.payload_hash = bridge_payload_hash(&amount_over_bound.payload);
        assert_eq!(
            cashvm_output_from_hegemon(&hegemon_output(&amount_over_bound), &amount_over_bound),
            Err(CashVmBridgeError::MintPayloadAmountOutOfBounds)
        );

        let mut native_asset = amount_over_bound;
        let mut payload =
            BridgeMintPayloadV1::decode(&mut &native_asset.payload[..]).expect("mint payload");
        payload.amount = 7_500;
        payload.asset_id = HEGEMON_NATIVE_ASSET_ID;
        native_asset.payload = payload.encode();
        native_asset.payload_hash = bridge_payload_hash(&native_asset.payload);
        assert_eq!(
            cashvm_output_from_hegemon(&hegemon_output(&native_asset), &native_asset),
            Err(CashVmBridgeError::MintPayloadNativeAssetNotAllowed)
        );
    }

    #[test]
    fn spend_model_rejects_amount_replay_and_sequence_tampering() {
        let base = spend_for(message());

        let mut wrong_amount = base.clone();
        wrong_amount.bridge_output.amount += 1;
        wrong_amount.proof.statement_digest = wrong_amount.bridge_output.statement_digest();
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(&wrong_amount, &AcceptingProofVerifier),
            Err(CashVmBridgeError::MintPayloadAmountMismatch)
        );

        let mut wrong_asset_binding = base.clone();
        wrong_asset_binding.bridge_output.destination_token_category = hash32(0xee);
        wrong_asset_binding.proof.statement_digest =
            wrong_asset_binding.bridge_output.statement_digest();
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &wrong_asset_binding,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::MintPayloadAssetBindingMismatch)
        );

        let mut wrong_destination_policy = base.clone();
        wrong_destination_policy
            .previous_state
            .expected_destination_chain_id = hash32(0x77);
        wrong_destination_policy
            .next_state
            .expected_destination_chain_id = wrong_destination_policy
            .previous_state
            .expected_destination_chain_id;
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &wrong_destination_policy,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::MintPayloadDestinationPolicyMismatch)
        );

        let mut wrong_bridge_instance = base.clone();
        wrong_bridge_instance.previous_state.bridge_instance_id = hash32(0x78);
        wrong_bridge_instance.next_state.bridge_instance_id =
            wrong_bridge_instance.previous_state.bridge_instance_id;
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &wrong_bridge_instance,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::MintPayloadAssetBindingMismatch)
        );

        let mut wrong_recipient_binding = base.clone();
        wrong_recipient_binding
            .bridge_output
            .recipient_locking_bytecode_hash = hash32(0xef);
        wrong_recipient_binding.proof.statement_digest =
            wrong_recipient_binding.bridge_output.statement_digest();
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &wrong_recipient_binding,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::MintPayloadRecipientBindingMismatch)
        );

        let mut wrong_destination = base.clone();
        let mut payload =
            BridgeMintPayloadV1::decode(&mut &wrong_destination.source_message.payload[..])
                .expect("mint payload");
        payload.destination_chain_id = hash32(0x77);
        wrong_destination.source_message.payload = payload.encode();
        wrong_destination.source_message.payload_hash =
            bridge_payload_hash(&wrong_destination.source_message.payload);
        wrong_destination.bridge_output.hegemon_message_hash =
            wrong_destination.source_message.message_hash();
        wrong_destination.bridge_output.cashvm_message_hash =
            cashvm_message_digest(&wrong_destination.source_message);
        wrong_destination.proof.statement_digest =
            wrong_destination.bridge_output.statement_digest();
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &wrong_destination,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::MintPayloadDestinationMismatch)
        );

        let mut wrong_replay = base.clone();
        let mut payload =
            BridgeMintPayloadV1::decode(&mut &wrong_replay.source_message.payload[..])
                .expect("mint payload");
        payload.mint_nonce += 1;
        wrong_replay.source_message.payload = payload.encode();
        rebind_spend_message_and_statement(&mut wrong_replay);
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(&wrong_replay, &AcceptingProofVerifier),
            Err(CashVmBridgeError::MintPayloadNonceMismatch)
        );

        let mut sequence_overflow = base;
        sequence_overflow.previous_state.sequence = u64::MAX;
        sequence_overflow.next_state.sequence = u64::MAX;
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(
                &sequence_overflow,
                &AcceptingProofVerifier
            ),
            Err(CashVmBridgeError::SequenceOverflow)
        );
    }

    #[test]
    fn spend_model_rejects_duplicate_replay_from_successor_state() {
        let first = spend_for(message());
        let mut duplicate = first.clone();
        duplicate.previous_state = first.next_state.clone();
        rebind_spend_to_previous_state_checkpoint(&mut duplicate);
        duplicate.next_state.sequence = duplicate.previous_state.sequence + 1;
        duplicate.next_state.minted_supply =
            duplicate.previous_state.minted_supply + duplicate.bridge_output.amount;

        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(&duplicate, &AcceptingProofVerifier),
            Err(CashVmBridgeError::ReplayAlreadySpent)
        );

        let mut stale_witness = duplicate;
        stale_witness.previous_state.replay_root = hash32(0xab);
        assert_eq!(
            verify_cashvm_bridge_spend_model_with_verifier(&stale_witness, &AcceptingProofVerifier),
            Err(CashVmBridgeError::PreviousReplayRootMismatch)
        );
    }

    #[test]
    fn spend_model_allows_out_of_order_replay_set_updates() {
        let later = spend_for(message_with_nonce(100));
        verify_cashvm_bridge_spend_model_with_verifier(&later, &AcceptingProofVerifier)
            .expect("later nonce first spend");

        let mut earlier = spend_for(message_with_nonce(42));
        earlier.previous_state = later.next_state.clone();
        rebind_spend_to_previous_state_checkpoint(&mut earlier);
        earlier.replay_set_witness = replay_absence_witness_with_one_spent(
            earlier.bridge_output.source_chain_id,
            earlier.bridge_output.message_nonce,
            later.bridge_output.source_chain_id,
            later.bridge_output.message_nonce,
        );
        earlier.next_state.sequence = earlier.previous_state.sequence + 1;
        earlier.next_state.minted_supply =
            earlier.previous_state.minted_supply + earlier.bridge_output.amount;
        earlier.next_state.replay_root = replay_set_consumed_root(
            earlier.bridge_output.source_chain_id,
            earlier.bridge_output.message_nonce,
            &earlier.replay_set_witness,
        )
        .expect("two-leaf replay root");

        verify_cashvm_bridge_spend_model_with_verifier(&earlier, &AcceptingProofVerifier)
            .expect("earlier nonce remains spendable after later nonce");
    }

    #[derive(Debug, Deserialize)]
    struct LeanBridgeMintPayloadAdmissionVectorFile {
        schema_version: u32,
        cashvm_mint_binding_cases: Vec<LeanCashVmMintBindingCase>,
        cashvm_proof_admission_cases: Vec<LeanCashVmProofAdmissionCase>,
        cashvm_replay_update_cases: Vec<LeanCashVmReplayUpdateCase>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanCashVmMintBindingCase {
        name: String,
        version_matches: bool,
        source_app_family_matches: bool,
        destination_matches: bool,
        mint_nonce_matches: bool,
        recipient_commitment_nonzero: bool,
        amount_nonzero: bool,
        amount_within_bound: bool,
        asset_non_native: bool,
        destination_matches_bridge_policy: bool,
        bridge_instance_matches_token_category: bool,
        token_category_matches_payload_asset: bool,
        recipient_hash_matches_payload_recipient: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanCashVmProofAdmissionCase {
        name: String,
        proof_nonempty: bool,
        statement_digest_matches: bool,
        verifier_script_matches: bool,
        pq_soundness_at_least_policy: bool,
        verifier_available: bool,
        verifier_accepts: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanCashVmReplayUpdateCase {
        name: String,
        previous_root_matches: bool,
        witness_depth_valid: bool,
        replay_leaf_absent: bool,
        next_root_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    fn cashvm_error_label(err: CashVmBridgeError) -> &'static str {
        match err {
            CashVmBridgeError::MintPayloadVersionMismatch => "version_mismatch",
            CashVmBridgeError::MintPayloadSourceAppFamilyMismatch => "source_app_family_mismatch",
            CashVmBridgeError::MintPayloadDestinationMismatch => "destination_mismatch",
            CashVmBridgeError::MintPayloadNonceMismatch => "mint_nonce_mismatch",
            CashVmBridgeError::MintPayloadRecipientZero => "recipient_commitment_zero",
            CashVmBridgeError::MintPayloadAmountZero => "amount_zero",
            CashVmBridgeError::MintPayloadAmountOutOfBounds => "amount_out_of_bounds",
            CashVmBridgeError::MintPayloadNativeAssetNotAllowed => "native_asset_not_allowed",
            CashVmBridgeError::MintPayloadAssetBindingMismatch => "asset_binding_mismatch",
            CashVmBridgeError::MintPayloadRecipientBindingMismatch => "recipient_binding_mismatch",
            CashVmBridgeError::EmptyProof => "empty_proof",
            CashVmBridgeError::ProofStatementMismatch => "proof_statement_mismatch",
            CashVmBridgeError::VerifierScriptMismatch => "verifier_script_mismatch",
            CashVmBridgeError::InsufficientPqSoundness => "insufficient_pq_soundness",
            CashVmBridgeError::ProofVerificationUnavailable => "proof_verification_unavailable",
            CashVmBridgeError::ProofVerificationFailed => "proof_verification_failed",
            CashVmBridgeError::MintPayloadDestinationPolicyMismatch => {
                "destination_policy_mismatch"
            }
            CashVmBridgeError::TrustedCheckpointMismatch => "trusted_checkpoint_mismatch",
            CashVmBridgeError::PreviousReplayRootMismatch => "previous_replay_root_mismatch",
            CashVmBridgeError::ReplayWitnessDepthMismatch => "replay_witness_depth_mismatch",
            CashVmBridgeError::ReplayAlreadySpent => "replay_already_spent",
            CashVmBridgeError::NextReplayRootMismatch => "next_replay_root_mismatch",
            other => panic!("unexpected CashVM error {other:?}"),
        }
    }

    fn spend_for_cashvm_binding_case(case: &LeanCashVmMintBindingCase) -> CashVmBridgeSpendV1 {
        let mut spend = spend_for(message());
        if !case.version_matches {
            let mut payload = BridgeMintPayloadV1::decode(&mut &spend.source_message.payload[..])
                .expect("mint payload");
            payload.version = payload.version.saturating_add(1);
            spend.source_message.payload = payload.encode();
            rebind_spend_message_and_statement(&mut spend);
        } else if !case.source_app_family_matches {
            spend.source_message.app_family_id = BRIDGE_MINT_APP_FAMILY_ID_V1.saturating_add(1);
            rebind_spend_message_and_statement(&mut spend);
        } else if !case.destination_matches {
            let mut payload = BridgeMintPayloadV1::decode(&mut &spend.source_message.payload[..])
                .expect("mint payload");
            payload.destination_chain_id = hash32(0x77);
            spend.source_message.payload = payload.encode();
            rebind_spend_message_and_statement(&mut spend);
        } else if !case.mint_nonce_matches {
            let mut payload = BridgeMintPayloadV1::decode(&mut &spend.source_message.payload[..])
                .expect("mint payload");
            payload.mint_nonce = payload.mint_nonce.saturating_add(1);
            spend.source_message.payload = payload.encode();
            rebind_spend_message_and_statement(&mut spend);
        } else if !case.recipient_commitment_nonzero {
            let mut payload = BridgeMintPayloadV1::decode(&mut &spend.source_message.payload[..])
                .expect("mint payload");
            payload.recipient_commitment = [0u8; 48];
            spend.source_message.payload = payload.encode();
            rebind_spend_message_and_statement(&mut spend);
        } else if !case.amount_nonzero {
            let mut payload = BridgeMintPayloadV1::decode(&mut &spend.source_message.payload[..])
                .expect("mint payload");
            payload.amount = 0;
            spend.source_message.payload = payload.encode();
            rebind_spend_message_and_statement(&mut spend);
        } else if !case.amount_within_bound {
            let mut payload = BridgeMintPayloadV1::decode(&mut &spend.source_message.payload[..])
                .expect("mint payload");
            payload.amount = CASHVM_MAX_BRIDGE_MINT_AMOUNT + 1;
            spend.source_message.payload = payload.encode();
            rebind_spend_message_and_statement(&mut spend);
        } else if !case.asset_non_native {
            let mut payload = BridgeMintPayloadV1::decode(&mut &spend.source_message.payload[..])
                .expect("mint payload");
            payload.asset_id = HEGEMON_NATIVE_ASSET_ID;
            spend.source_message.payload = payload.encode();
            rebind_spend_message_and_statement(&mut spend);
        } else if !case.destination_matches_bridge_policy {
            spend.previous_state.expected_destination_chain_id = hash32(0x77);
            spend.next_state.expected_destination_chain_id =
                spend.previous_state.expected_destination_chain_id;
        } else if !case.bridge_instance_matches_token_category {
            spend.previous_state.bridge_instance_id = hash32(0x78);
            spend.next_state.bridge_instance_id = spend.previous_state.bridge_instance_id;
        } else if !case.token_category_matches_payload_asset {
            spend.bridge_output.destination_token_category = hash32(0xee);
            spend.proof.statement_digest = spend.bridge_output.statement_digest();
        } else if !case.recipient_hash_matches_payload_recipient {
            spend.bridge_output.recipient_locking_bytecode_hash = hash32(0xef);
            spend.proof.statement_digest = spend.bridge_output.statement_digest();
        }
        spend
    }

    fn spend_for_cashvm_replay_case(case: &LeanCashVmReplayUpdateCase) -> CashVmBridgeSpendV1 {
        let mut spend = spend_for(message());
        if !case.witness_depth_valid {
            spend.replay_set_witness.siblings.pop();
        } else if !case.replay_leaf_absent {
            spend.previous_state.replay_root = replay_set_consumed_root(
                spend.bridge_output.source_chain_id,
                spend.bridge_output.message_nonce,
                &spend.replay_set_witness,
            )
            .expect("spent replay root");
        }
        if !case.previous_root_matches {
            spend.previous_state.replay_root = hash32(0xab);
        }
        if !case.next_root_matches {
            spend.next_state.replay_root = hash32(0xac);
        }
        spend
    }

    fn spend_for_cashvm_proof_case(case: &LeanCashVmProofAdmissionCase) -> CashVmBridgeSpendV1 {
        let mut spend = spend_for(message());
        if !case.proof_nonempty {
            spend.proof.proof_bytes.clear();
        }
        if !case.statement_digest_matches {
            spend.proof.statement_digest = hash32(0xcc);
        }
        if !case.verifier_script_matches {
            spend.proof.verifier_script_hash = hash32(0xaa);
        }
        if !case.pq_soundness_at_least_policy {
            spend.proof.pq_soundness_bits =
                spend.previous_state.min_pq_soundness_bits.saturating_sub(1);
        }
        spend
    }

    struct LeanProofCaseVerifier<'a> {
        case: &'a LeanCashVmProofAdmissionCase,
    }

    impl CashVmProofVerifier for LeanProofCaseVerifier<'_> {
        fn verify_cashvm_proof(
            &self,
            _proof: &CashVmProofEnvelopeV1,
            _output: &CashVmBridgeOutputV1,
        ) -> Result<(), CashVmBridgeError> {
            if !self.case.verifier_available {
                Err(CashVmBridgeError::ProofVerificationUnavailable)
            } else if !self.case.verifier_accepts {
                Err(CashVmBridgeError::ProofVerificationFailed)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn lean_generated_cashvm_mint_binding_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_MINT_PAYLOAD_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BRIDGE_MINT_PAYLOAD_ADMISSION_VECTORS not set; skipping CashVM mint binding vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean bridge mint payload vectors");
        let vectors: LeanBridgeMintPayloadAdmissionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean CashVM binding vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.cashvm_mint_binding_cases.is_empty(),
            "Lean CashVM mint binding cases must not be empty"
        );
        assert!(
            !vectors.cashvm_proof_admission_cases.is_empty(),
            "Lean CashVM proof admission cases must not be empty"
        );
        assert!(
            !vectors.cashvm_replay_update_cases.is_empty(),
            "Lean CashVM replay update cases must not be empty"
        );
        for case in &vectors.cashvm_mint_binding_cases {
            let spend = spend_for_cashvm_binding_case(case);
            let actual_rejection =
                verify_cashvm_bridge_spend_model_with_verifier(&spend, &AcceptingProofVerifier)
                    .err()
                    .map(cashvm_error_label);
            assert_eq!(
                actual_rejection.is_none(),
                case.expected_valid,
                "{} CashVM binding validity drifted from Lean",
                case.name
            );
            assert_eq!(
                actual_rejection,
                case.expected_rejection.as_deref(),
                "{} CashVM binding rejection drifted from Lean",
                case.name
            );
        }
        for case in &vectors.cashvm_replay_update_cases {
            let spend = spend_for_cashvm_replay_case(case);
            let actual_rejection =
                verify_cashvm_bridge_spend_model_with_verifier(&spend, &AcceptingProofVerifier)
                    .err()
                    .map(cashvm_error_label);
            assert_eq!(
                actual_rejection.is_none(),
                case.expected_valid,
                "{} CashVM replay update validity drifted from Lean",
                case.name
            );
            assert_eq!(
                actual_rejection,
                case.expected_rejection.as_deref(),
                "{} CashVM replay update rejection drifted from Lean",
                case.name
            );
        }
        for case in &vectors.cashvm_proof_admission_cases {
            let spend = spend_for_cashvm_proof_case(case);
            let verifier = LeanProofCaseVerifier { case };
            let actual_rejection =
                verify_cashvm_bridge_spend_model_with_verifier(&spend, &verifier)
                    .err()
                    .map(cashvm_error_label);
            assert_eq!(
                actual_rejection.is_none(),
                case.expected_valid,
                "{} CashVM proof admission validity drifted from Lean",
                case.name
            );
            assert_eq!(
                actual_rejection,
                case.expected_rejection.as_deref(),
                "{} CashVM proof admission rejection drifted from Lean",
                case.name
            );
        }
    }
}
