use consensus_light_client::{BridgeCheckpointOutputV1, Hash32, Work48};
use protocol_kernel::{bridge_payload_hash, BridgeMessageV1, ChainId, MessageHash, MessageRoot};
use sha2::{Digest, Sha256};

pub const CASHVM_MAX_STANDARD_TX_BYTES: usize = 100_000;
pub const CASHVM_MAX_BYTECODE_BYTES: usize = 10_000;
pub const CASHVM_MAX_STACK_ELEMENT_BYTES: usize = 10_000;
pub const CASHVM_TOKEN_COMMITMENT_BYTES_2026: usize = 128;
pub const CASHVM_SAFE_PROOF_CHUNK_BYTES: usize = 9_216;
pub const CASHVM_BRIDGE_STATE_WIRE_BYTES_V1: usize = 128;
pub const CASHVM_BRIDGE_OUTPUT_WIRE_BYTES_V1: usize = 516;
pub const CASHVM_SAFE_FRAGMENT_TX_PAYLOAD_BYTES: usize = 90_000;

const CASHVM_BRIDGE_STATE_MAGIC_V1: [u8; 4] = *b"HBC1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CashVmBridgeError {
    AmountOverflow,
    PayloadHashMismatch,
    MessageHashMismatch,
    CashVmMessageHashMismatch,
    EmptyProof,
    ProofStatementMismatch,
    VerifierScriptMismatch,
    InsufficientPqSoundness,
    NextSequenceMismatch,
    NextCheckpointMismatch,
    NextPolicyMismatch,
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
    pub proof: CashVmProofEnvelopeV1,
}

impl CashVmBridgeOutputV1 {
    pub fn wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CASHVM_BRIDGE_OUTPUT_WIRE_BYTES_V1);
        out.extend_from_slice(&self.source_chain_id);
        out.extend_from_slice(&self.rules_hash);
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
    pub fn commitment_bytes(&self) -> [u8; CASHVM_BRIDGE_STATE_WIRE_BYTES_V1] {
        let mut out = [0u8; CASHVM_BRIDGE_STATE_WIRE_BYTES_V1];
        out[0..4].copy_from_slice(&CASHVM_BRIDGE_STATE_MAGIC_V1);
        out[4..36].copy_from_slice(&self.verifier_script_hash);
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
    destination_token_category: Hash32,
    recipient_locking_bytecode_hash: Hash32,
    amount: u128,
) -> Result<CashVmBridgeOutputV1, CashVmBridgeError> {
    let hegemon_message_hash = message.message_hash();
    if message.payload_hash != bridge_payload_hash(&message.payload) {
        return Err(CashVmBridgeError::PayloadHashMismatch);
    }
    if hegemon_message_hash != hegemon.message_hash {
        return Err(CashVmBridgeError::MessageHashMismatch);
    }
    Ok(CashVmBridgeOutputV1 {
        source_chain_id: hegemon.source_chain_id,
        rules_hash: hegemon.rules_hash,
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
        amount,
        confirmations_checked: hegemon.confirmations_checked,
        min_work_checked: hegemon.min_work_checked,
    })
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

pub fn replay_leaf(source_chain_id: ChainId, message_nonce: u128) -> Hash32 {
    hash256(
        b"hegemon.cashvm.replay-leaf-v1",
        &[&source_chain_id, &message_nonce.to_le_bytes()],
    )
}

pub fn append_replay_root(previous_replay_root: Hash32, leaf: Hash32) -> Hash32 {
    hash256(
        b"hegemon.cashvm.replay-root-v1",
        &[&previous_replay_root, &leaf],
    )
}

pub fn verify_cashvm_bridge_spend_model(
    spend: &CashVmBridgeSpendV1,
) -> Result<(), CashVmBridgeError> {
    if spend.source_message.payload_hash != bridge_payload_hash(&spend.source_message.payload) {
        return Err(CashVmBridgeError::PayloadHashMismatch);
    }
    if spend.bridge_output.hegemon_message_hash != spend.source_message.message_hash() {
        return Err(CashVmBridgeError::MessageHashMismatch);
    }
    if spend.bridge_output.cashvm_message_hash != cashvm_message_digest(&spend.source_message) {
        return Err(CashVmBridgeError::CashVmMessageHashMismatch);
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
    if spend.next_state.sequence != spend.previous_state.sequence.saturating_add(1) {
        return Err(CashVmBridgeError::NextSequenceMismatch);
    }
    if spend.next_state.verifier_script_hash != spend.previous_state.verifier_script_hash
        || spend.next_state.min_pq_soundness_bits != spend.previous_state.min_pq_soundness_bits
        || spend.next_state.flags != spend.previous_state.flags
    {
        return Err(CashVmBridgeError::NextPolicyMismatch);
    }
    if spend.next_state.accepted_checkpoint_digest != spend.bridge_output.checkpoint_digest() {
        return Err(CashVmBridgeError::NextCheckpointMismatch);
    }
    let expected_replay_root = append_replay_root(
        spend.previous_state.replay_root,
        replay_leaf(
            spend.bridge_output.source_chain_id,
            spend.bridge_output.message_nonce,
        ),
    );
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
    use consensus_light_client::{
        BridgeCheckpointOutputV1, HEGEMON_CHAIN_ID_V1, HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
    };
    use protocol_kernel::{bridge_payload_hash, BridgeMessageV1};

    fn hash32(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn work48(byte: u8) -> Work48 {
        [byte; 48]
    }

    fn message() -> BridgeMessageV1 {
        let payload = b"cashvm bridge payload".to_vec();
        BridgeMessageV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            destination_chain_id: hash32(0x42),
            app_family_id: 7,
            message_nonce: 42,
            source_height: 11,
            payload_hash: bridge_payload_hash(&payload),
            payload,
        }
    }

    fn hegemon_output(message: &BridgeMessageV1) -> BridgeCheckpointOutputV1 {
        BridgeCheckpointOutputV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
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
        cashvm_output_from_hegemon(
            &hegemon_output(&message),
            &message,
            hash32(0x21),
            hash32(0x22),
            1_000,
        )
        .expect("cashvm output")
    }

    fn state(output: &CashVmBridgeOutputV1) -> CashVmBridgeStateV1 {
        CashVmBridgeStateV1 {
            verifier_script_hash: hash32(0x33),
            accepted_checkpoint_digest: output.checkpoint_digest(),
            replay_root: hash32(0x44),
            minted_supply: 10_000,
            sequence: 5,
            min_pq_soundness_bits: 96,
            flags: 0,
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
    fn spend_model_accepts_valid_bridge_transition() {
        let message = message();
        let output = cashvm_output_from_hegemon(
            &hegemon_output(&message),
            &message,
            hash32(0x21),
            hash32(0x22),
            1_000,
        )
        .expect("output");
        let previous_state = state(&output);
        let next_state = CashVmBridgeStateV1 {
            accepted_checkpoint_digest: output.checkpoint_digest(),
            replay_root: append_replay_root(
                previous_state.replay_root,
                replay_leaf(output.source_chain_id, output.message_nonce),
            ),
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
        let spend = CashVmBridgeSpendV1 {
            previous_state,
            next_state,
            bridge_output: output,
            source_message: message,
            proof,
        };
        verify_cashvm_bridge_spend_model(&spend).expect("valid spend");
    }

    #[test]
    fn spend_model_rejects_tampering() {
        let message = message();
        let output = cashvm_output_from_hegemon(
            &hegemon_output(&message),
            &message,
            hash32(0x21),
            hash32(0x22),
            1_000,
        )
        .expect("output");
        let previous_state = state(&output);
        let next_state = CashVmBridgeStateV1 {
            accepted_checkpoint_digest: output.checkpoint_digest(),
            replay_root: append_replay_root(
                previous_state.replay_root,
                replay_leaf(output.source_chain_id, output.message_nonce),
            ),
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
        let base = CashVmBridgeSpendV1 {
            previous_state,
            next_state,
            bridge_output: output,
            source_message: message,
            proof,
        };

        let mut weak = base.clone();
        weak.proof.pq_soundness_bits = 80;
        assert_eq!(
            verify_cashvm_bridge_spend_model(&weak),
            Err(CashVmBridgeError::InsufficientPqSoundness)
        );

        let mut wrong_verifier = base.clone();
        wrong_verifier.proof.verifier_script_hash = hash32(0xaa);
        assert_eq!(
            verify_cashvm_bridge_spend_model(&wrong_verifier),
            Err(CashVmBridgeError::VerifierScriptMismatch)
        );

        let mut empty_proof = base.clone();
        empty_proof.proof.proof_bytes.clear();
        assert_eq!(
            verify_cashvm_bridge_spend_model(&empty_proof),
            Err(CashVmBridgeError::EmptyProof)
        );

        let mut wrong_statement = base.clone();
        wrong_statement.proof.statement_digest = hash32(0xcc);
        assert_eq!(
            verify_cashvm_bridge_spend_model(&wrong_statement),
            Err(CashVmBridgeError::ProofStatementMismatch)
        );

        let mut wrong_checkpoint = base.clone();
        wrong_checkpoint.next_state.accepted_checkpoint_digest = hash32(0xdd);
        assert_eq!(
            verify_cashvm_bridge_spend_model(&wrong_checkpoint),
            Err(CashVmBridgeError::NextCheckpointMismatch)
        );

        let mut supply_overflow = base.clone();
        supply_overflow.previous_state.minted_supply = u128::MAX;
        supply_overflow.next_state.minted_supply = u128::MAX;
        assert_eq!(
            verify_cashvm_bridge_spend_model(&supply_overflow),
            Err(CashVmBridgeError::AmountOverflow)
        );

        let mut wrong_replay = base.clone();
        wrong_replay.next_state.replay_root = hash32(0xbb);
        assert_eq!(
            verify_cashvm_bridge_spend_model(&wrong_replay),
            Err(CashVmBridgeError::NextReplayRootMismatch)
        );

        let mut weak_next_policy = base.clone();
        weak_next_policy.next_state.min_pq_soundness_bits = 80;
        assert_eq!(
            verify_cashvm_bridge_spend_model(&weak_next_policy),
            Err(CashVmBridgeError::NextPolicyMismatch)
        );

        let mut wrong_message = base;
        wrong_message.source_message.payload.push(0);
        assert_eq!(
            verify_cashvm_bridge_spend_model(&wrong_message),
            Err(CashVmBridgeError::PayloadHashMismatch)
        );

        wrong_message.source_message.payload_hash =
            bridge_payload_hash(&wrong_message.source_message.payload);
        assert_eq!(
            verify_cashvm_bridge_spend_model(&wrong_message),
            Err(CashVmBridgeError::MessageHashMismatch)
        );

        let mut wrong_cashvm_digest = wrong_message;
        wrong_cashvm_digest.bridge_output.hegemon_message_hash =
            wrong_cashvm_digest.source_message.message_hash();
        assert_eq!(
            verify_cashvm_bridge_spend_model(&wrong_cashvm_digest),
            Err(CashVmBridgeError::CashVmMessageHashMismatch)
        );
    }
}
