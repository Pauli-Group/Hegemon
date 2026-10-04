//! Source-only lifecycle seams for the inactive V7/Zeta action route.
//!
//! The codecs below model exact transport through every native stage. None is
//! called by an active RPC, gossip, mempool, mining, import, or startup path;
//! every state-mutating entrypoint at the bottom of this file returns an error.

#![allow(dead_code)]

use base64::Engine;
use codec::{Decode, Encode};
use protocol_shielded_pool::inactive_smallwood_v7::{
    decode_inactive_smallwood_v7_inline_args, decode_inactive_smallwood_v7_statement_for_context,
    inactive_smallwood_v7_prospective_action_id, InactiveSmallwoodV7CodecError,
    InactiveSmallwoodV7ExpectedActivationContext, InactiveSmallwoodV7ProspectiveActionId56,
    INACTIVE_SMALLWOOD_V7_ACTION_ID, INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION,
    INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA, INACTIVE_SMALLWOOD_V7_FAMILY_ID,
    INACTIVE_SMALLWOOD_V7_MAX_PUBLIC_ARGS_BYTES,
};

use super::SubmitActionRpcRequest;

pub(crate) const INACTIVE_SMALLWOOD_V7_NATIVE_PRODUCTION_ENABLED: bool = false;
pub(crate) const INACTIVE_SMALLWOOD_V7_RPC_ADMISSION_ENABLED: bool = false;
pub(crate) const INACTIVE_SMALLWOOD_V7_PEER_RELAY_ENABLED: bool = false;
pub(crate) const INACTIVE_SMALLWOOD_V7_DURABLE_MEMPOOL_ENABLED: bool = false;
pub(crate) const INACTIVE_SMALLWOOD_V7_MINING_ENABLED: bool = false;
pub(crate) const INACTIVE_SMALLWOOD_V7_BLOCK_IMPORT_ENABLED: bool = false;
pub(crate) const INACTIVE_SMALLWOOD_V7_SYNC_ENABLED: bool = false;
pub(crate) const INACTIVE_SMALLWOOD_V7_REORG_ENABLED: bool = false;
pub(crate) const INACTIVE_SMALLWOOD_V7_FRESH_NODE_ENABLED: bool = false;
pub(crate) const INACTIVE_SMALLWOOD_V7_RESTART_RESTORE_ENABLED: bool = false;

const INACTIVE_SMALLWOOD_V7_RECORD_SCHEMA: u16 = 1;
const INACTIVE_SMALLWOOD_V7_PENDING_KEY_PREFIX: &[u8] = b"pending_smallwood_v7_inactive_v1/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InactiveSmallwoodV7LifecycleError {
    RouteMismatch,
    LegacyKernelFieldsPresent,
    LegacyNullifierFieldPresent,
    Base64Rejected,
    Base64NonCanonical,
    PublicArgsTooLarge(usize),
    Codec(String),
    RecordDecode,
    RecordTrailingBytes,
    RecordNonCanonical,
    RecordSchema(u16),
    RecordActionIdMismatch,
    DurableKeyLength(usize),
    DurableKeyPrefix,
    DurableKeyActionIdMismatch,
    ProofBytesChanged,
    ProductionInactive(&'static str),
    VerifierUnavailable,
}

impl core::fmt::Display for InactiveSmallwoodV7LifecycleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "inactive SmallWood V7 lifecycle rejection: {self:?}"
        )
    }
}

impl std::error::Error for InactiveSmallwoodV7LifecycleError {}

impl From<InactiveSmallwoodV7CodecError> for InactiveSmallwoodV7LifecycleError {
    fn from(error: InactiveSmallwoodV7CodecError) -> Self {
        Self::Codec(error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct InactiveSmallwoodV7LifecycleRecord {
    schema: u16,
    prospective_action_id: InactiveSmallwoodV7ProspectiveActionId56,
    /// Canonical SCALE bytes of `InactiveSmallwoodV7InlineArgs`.
    canonical_public_args: Vec<u8>,
}

impl InactiveSmallwoodV7LifecycleRecord {
    fn from_public_args(
        canonical_public_args: Vec<u8>,
        expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
    ) -> Result<Self, InactiveSmallwoodV7LifecycleError> {
        if canonical_public_args.len() > INACTIVE_SMALLWOOD_V7_MAX_PUBLIC_ARGS_BYTES {
            return Err(InactiveSmallwoodV7LifecycleError::PublicArgsTooLarge(
                canonical_public_args.len(),
            ));
        }
        let action = decode_inactive_smallwood_v7_inline_args(&canonical_public_args)?;
        decode_inactive_smallwood_v7_statement_for_context(
            action.envelope()?.statement_bytes(),
            expected_activation,
        )?;
        if action.canonical_bytes()? != canonical_public_args {
            return Err(InactiveSmallwoodV7LifecycleError::RecordNonCanonical);
        }
        Ok(Self {
            schema: INACTIVE_SMALLWOOD_V7_RECORD_SCHEMA,
            prospective_action_id: inactive_smallwood_v7_prospective_action_id(
                &canonical_public_args,
            )?,
            canonical_public_args,
        })
    }

    fn validate(
        &self,
        expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
    ) -> Result<(), InactiveSmallwoodV7LifecycleError> {
        if self.schema != INACTIVE_SMALLWOOD_V7_RECORD_SCHEMA {
            return Err(InactiveSmallwoodV7LifecycleError::RecordSchema(self.schema));
        }
        let action = decode_inactive_smallwood_v7_inline_args(&self.canonical_public_args)?;
        decode_inactive_smallwood_v7_statement_for_context(
            action.envelope()?.statement_bytes(),
            expected_activation,
        )?;
        if self.prospective_action_id
            != inactive_smallwood_v7_prospective_action_id(&self.canonical_public_args)?
        {
            return Err(InactiveSmallwoodV7LifecycleError::RecordActionIdMismatch);
        }
        Ok(())
    }

    fn canonical_bytes(
        &self,
        expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
    ) -> Result<Vec<u8>, InactiveSmallwoodV7LifecycleError> {
        self.validate(expected_activation)?;
        Ok(self.encode())
    }

    fn proof_bytes(&self) -> Result<Vec<u8>, InactiveSmallwoodV7LifecycleError> {
        let action = decode_inactive_smallwood_v7_inline_args(&self.canonical_public_args)?;
        Ok(action.envelope()?.proof_bytes().to_vec())
    }
}

fn decode_record_exact(
    bytes: &[u8],
    expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
) -> Result<InactiveSmallwoodV7LifecycleRecord, InactiveSmallwoodV7LifecycleError> {
    if bytes.len() > INACTIVE_SMALLWOOD_V7_MAX_PUBLIC_ARGS_BYTES + 128 {
        return Err(InactiveSmallwoodV7LifecycleError::PublicArgsTooLarge(
            bytes.len(),
        ));
    }
    let mut cursor = bytes;
    let record = InactiveSmallwoodV7LifecycleRecord::decode(&mut cursor)
        .map_err(|_| InactiveSmallwoodV7LifecycleError::RecordDecode)?;
    if !cursor.is_empty() {
        return Err(InactiveSmallwoodV7LifecycleError::RecordTrailingBytes);
    }
    record.validate(expected_activation)?;
    if record.encode() != bytes {
        return Err(InactiveSmallwoodV7LifecycleError::RecordNonCanonical);
    }
    Ok(record)
}

macro_rules! lifecycle_stage {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(crate) struct $name {
            record: InactiveSmallwoodV7LifecycleRecord,
            expected_activation: InactiveSmallwoodV7ExpectedActivationContext,
        }

        impl $name {
            pub(crate) fn prospective_action_id(&self) -> InactiveSmallwoodV7ProspectiveActionId56 {
                self.record.prospective_action_id
            }

            pub(crate) fn canonical_public_args(&self) -> &[u8] {
                &self.record.canonical_public_args
            }

            pub(crate) fn proof_bytes(&self) -> Result<Vec<u8>, InactiveSmallwoodV7LifecycleError> {
                self.record.proof_bytes()
            }
        }
    };
}

lifecycle_stage!(InactiveSmallwoodV7RpcDecoded);
lifecycle_stage!(InactiveSmallwoodV7PeerDecoded);
lifecycle_stage!(InactiveSmallwoodV7MempoolStaged);
lifecycle_stage!(InactiveSmallwoodV7RestartDecoded);
lifecycle_stage!(InactiveSmallwoodV7MiningSelected);
lifecycle_stage!(InactiveSmallwoodV7BlockDecoded);
lifecycle_stage!(InactiveSmallwoodV7SyncDecoded);
lifecycle_stage!(InactiveSmallwoodV7ReorgDetached);
lifecycle_stage!(InactiveSmallwoodV7ReorgReattached);
lifecycle_stage!(InactiveSmallwoodV7FreshNodeDecoded);
lifecycle_stage!(InactiveSmallwoodV7ImportDecoded);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InactiveSmallwoodV7DurableRow {
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

/// Decode the RPC shape after the active router has already rejected it.
/// This function is a future-route seam and is not called by RPC dispatch.
pub(crate) fn decode_inactive_smallwood_v7_rpc_seam(
    request: &SubmitActionRpcRequest,
    expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
) -> Result<InactiveSmallwoodV7RpcDecoded, InactiveSmallwoodV7LifecycleError> {
    if request.binding_circuit != INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION
        || request.binding_crypto != INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA
        || request.family_id != INACTIVE_SMALLWOOD_V7_FAMILY_ID
        || request.action_id != INACTIVE_SMALLWOOD_V7_ACTION_ID
    {
        return Err(InactiveSmallwoodV7LifecycleError::RouteMismatch);
    }
    if !request.object_refs.is_empty()
        || request.authorization_proof.is_some()
        || !request.authorization_signatures.is_empty()
        || request.aux_data.is_some()
    {
        return Err(InactiveSmallwoodV7LifecycleError::LegacyKernelFieldsPresent);
    }
    if !request.new_nullifiers.is_empty() {
        return Err(InactiveSmallwoodV7LifecycleError::LegacyNullifierFieldPresent);
    }
    if request.public_args.len()
        > base64::encoded_len(INACTIVE_SMALLWOOD_V7_MAX_PUBLIC_ARGS_BYTES, true)
            .unwrap_or(usize::MAX)
    {
        return Err(InactiveSmallwoodV7LifecycleError::PublicArgsTooLarge(
            request.public_args.len(),
        ));
    }
    let public_args = base64::engine::general_purpose::STANDARD
        .decode(&request.public_args)
        .map_err(|_| InactiveSmallwoodV7LifecycleError::Base64Rejected)?;
    if base64::engine::general_purpose::STANDARD.encode(&public_args) != request.public_args {
        return Err(InactiveSmallwoodV7LifecycleError::Base64NonCanonical);
    }
    Ok(InactiveSmallwoodV7RpcDecoded {
        record: InactiveSmallwoodV7LifecycleRecord::from_public_args(
            public_args,
            expected_activation,
        )?,
        expected_activation: *expected_activation,
    })
}

pub(crate) fn encode_inactive_smallwood_v7_peer_seam(
    rpc: &InactiveSmallwoodV7RpcDecoded,
) -> Result<Vec<u8>, InactiveSmallwoodV7LifecycleError> {
    rpc.record.canonical_bytes(&rpc.expected_activation)
}

pub(crate) fn decode_inactive_smallwood_v7_peer_seam(
    bytes: &[u8],
    expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
) -> Result<InactiveSmallwoodV7PeerDecoded, InactiveSmallwoodV7LifecycleError> {
    Ok(InactiveSmallwoodV7PeerDecoded {
        record: decode_record_exact(bytes, expected_activation)?,
        expected_activation: *expected_activation,
    })
}

pub(crate) fn stage_inactive_smallwood_v7_mempool_seam(
    peer: &InactiveSmallwoodV7PeerDecoded,
) -> Result<InactiveSmallwoodV7MempoolStaged, InactiveSmallwoodV7LifecycleError> {
    peer.record.validate(&peer.expected_activation)?;
    Ok(InactiveSmallwoodV7MempoolStaged {
        record: peer.record.clone(),
        expected_activation: peer.expected_activation,
    })
}

pub(crate) fn encode_inactive_smallwood_v7_durable_row_seam(
    staged: &InactiveSmallwoodV7MempoolStaged,
) -> Result<InactiveSmallwoodV7DurableRow, InactiveSmallwoodV7LifecycleError> {
    let mut key = Vec::with_capacity(
        INACTIVE_SMALLWOOD_V7_PENDING_KEY_PREFIX.len()
            + protocol_shielded_pool::inactive_smallwood_v7::INACTIVE_SMALLWOOD_V7_DIGEST_BYTES,
    );
    key.extend_from_slice(INACTIVE_SMALLWOOD_V7_PENDING_KEY_PREFIX);
    key.extend_from_slice(staged.prospective_action_id().as_bytes());
    Ok(InactiveSmallwoodV7DurableRow {
        key,
        value: staged.record.canonical_bytes(&staged.expected_activation)?,
    })
}

pub(crate) fn decode_inactive_smallwood_v7_restart_seam(
    row: &InactiveSmallwoodV7DurableRow,
    expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
) -> Result<InactiveSmallwoodV7RestartDecoded, InactiveSmallwoodV7LifecycleError> {
    let required_key_len = INACTIVE_SMALLWOOD_V7_PENDING_KEY_PREFIX.len()
        + protocol_shielded_pool::inactive_smallwood_v7::INACTIVE_SMALLWOOD_V7_DIGEST_BYTES;
    if row.key.len() != required_key_len {
        return Err(InactiveSmallwoodV7LifecycleError::DurableKeyLength(
            row.key.len(),
        ));
    }
    if !row
        .key
        .starts_with(INACTIVE_SMALLWOOD_V7_PENDING_KEY_PREFIX)
    {
        return Err(InactiveSmallwoodV7LifecycleError::DurableKeyPrefix);
    }
    let record = decode_record_exact(&row.value, expected_activation)?;
    if &row.key[INACTIVE_SMALLWOOD_V7_PENDING_KEY_PREFIX.len()..]
        != record.prospective_action_id.as_bytes()
    {
        return Err(InactiveSmallwoodV7LifecycleError::DurableKeyActionIdMismatch);
    }
    Ok(InactiveSmallwoodV7RestartDecoded {
        record,
        expected_activation: *expected_activation,
    })
}

pub(crate) fn restage_inactive_smallwood_v7_mempool_after_restart_seam(
    restarted: &InactiveSmallwoodV7RestartDecoded,
) -> Result<InactiveSmallwoodV7MempoolStaged, InactiveSmallwoodV7LifecycleError> {
    restarted.record.validate(&restarted.expected_activation)?;
    Ok(InactiveSmallwoodV7MempoolStaged {
        record: restarted.record.clone(),
        expected_activation: restarted.expected_activation,
    })
}

pub(crate) fn select_inactive_smallwood_v7_for_mining_seam(
    restarted_mempool: &InactiveSmallwoodV7MempoolStaged,
) -> Result<InactiveSmallwoodV7MiningSelected, InactiveSmallwoodV7LifecycleError> {
    restarted_mempool
        .record
        .validate(&restarted_mempool.expected_activation)?;
    Ok(InactiveSmallwoodV7MiningSelected {
        record: restarted_mempool.record.clone(),
        expected_activation: restarted_mempool.expected_activation,
    })
}

pub(crate) fn encode_inactive_smallwood_v7_block_seam(
    mined: &InactiveSmallwoodV7MiningSelected,
) -> Result<Vec<u8>, InactiveSmallwoodV7LifecycleError> {
    mined.record.canonical_bytes(&mined.expected_activation)
}

pub(crate) fn decode_inactive_smallwood_v7_block_seam(
    bytes: &[u8],
    expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
) -> Result<InactiveSmallwoodV7BlockDecoded, InactiveSmallwoodV7LifecycleError> {
    Ok(InactiveSmallwoodV7BlockDecoded {
        record: decode_record_exact(bytes, expected_activation)?,
        expected_activation: *expected_activation,
    })
}

pub(crate) fn encode_inactive_smallwood_v7_sync_seam(
    block: &InactiveSmallwoodV7BlockDecoded,
) -> Result<Vec<u8>, InactiveSmallwoodV7LifecycleError> {
    block.record.canonical_bytes(&block.expected_activation)
}

pub(crate) fn decode_inactive_smallwood_v7_sync_seam(
    bytes: &[u8],
    expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
) -> Result<InactiveSmallwoodV7SyncDecoded, InactiveSmallwoodV7LifecycleError> {
    Ok(InactiveSmallwoodV7SyncDecoded {
        record: decode_record_exact(bytes, expected_activation)?,
        expected_activation: *expected_activation,
    })
}

pub(crate) fn detach_inactive_smallwood_v7_reorg_seam(
    synced: &InactiveSmallwoodV7SyncDecoded,
) -> Result<InactiveSmallwoodV7ReorgDetached, InactiveSmallwoodV7LifecycleError> {
    synced.record.validate(&synced.expected_activation)?;
    Ok(InactiveSmallwoodV7ReorgDetached {
        record: synced.record.clone(),
        expected_activation: synced.expected_activation,
    })
}

pub(crate) fn reattach_inactive_smallwood_v7_reorg_seam(
    detached: &InactiveSmallwoodV7ReorgDetached,
) -> Result<InactiveSmallwoodV7ReorgReattached, InactiveSmallwoodV7LifecycleError> {
    detached.record.validate(&detached.expected_activation)?;
    Ok(InactiveSmallwoodV7ReorgReattached {
        record: detached.record.clone(),
        expected_activation: detached.expected_activation,
    })
}

pub(crate) fn encode_inactive_smallwood_v7_fresh_node_seam(
    reattached: &InactiveSmallwoodV7ReorgReattached,
) -> Result<Vec<u8>, InactiveSmallwoodV7LifecycleError> {
    reattached
        .record
        .canonical_bytes(&reattached.expected_activation)
}

pub(crate) fn decode_inactive_smallwood_v7_fresh_node_seam(
    bytes: &[u8],
    expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
) -> Result<InactiveSmallwoodV7FreshNodeDecoded, InactiveSmallwoodV7LifecycleError> {
    Ok(InactiveSmallwoodV7FreshNodeDecoded {
        record: decode_record_exact(bytes, expected_activation)?,
        expected_activation: *expected_activation,
    })
}

pub(crate) fn validate_inactive_smallwood_v7_import_seam(
    fresh: &InactiveSmallwoodV7FreshNodeDecoded,
) -> Result<InactiveSmallwoodV7ImportDecoded, InactiveSmallwoodV7LifecycleError> {
    fresh.record.validate(&fresh.expected_activation)?;
    Ok(InactiveSmallwoodV7ImportDecoded {
        record: fresh.record.clone(),
        expected_activation: fresh.expected_activation,
    })
}

pub(crate) fn ensure_inactive_smallwood_v7_proof_bytes_unchanged(
    expected: &[u8],
    observed: &[u8],
) -> Result<(), InactiveSmallwoodV7LifecycleError> {
    if expected == observed {
        Ok(())
    } else {
        Err(InactiveSmallwoodV7LifecycleError::ProofBytesChanged)
    }
}

/// Proof verification is intentionally unavailable in this lifecycle-only
/// module. A future verifier must be owned by the fresh backend/profile rather
/// than routed through the active V3 verifier.
pub(crate) fn verify_inactive_smallwood_v7_for_production(
    _action: &InactiveSmallwoodV7ImportDecoded,
) -> Result<(), InactiveSmallwoodV7LifecycleError> {
    Err(InactiveSmallwoodV7LifecycleError::VerifierUnavailable)
}

pub(crate) fn admit_inactive_smallwood_v7_rpc_to_mempool(
    _action: &InactiveSmallwoodV7RpcDecoded,
) -> Result<(), InactiveSmallwoodV7LifecycleError> {
    Err(InactiveSmallwoodV7LifecycleError::ProductionInactive(
        "rpc_mempool_admission",
    ))
}

pub(crate) fn relay_inactive_smallwood_v7_to_peers(
    _action: &InactiveSmallwoodV7MempoolStaged,
) -> Result<(), InactiveSmallwoodV7LifecycleError> {
    Err(InactiveSmallwoodV7LifecycleError::ProductionInactive(
        "peer_relay",
    ))
}

pub(crate) fn persist_inactive_smallwood_v7_mempool(
    _row: &InactiveSmallwoodV7DurableRow,
) -> Result<(), InactiveSmallwoodV7LifecycleError> {
    Err(InactiveSmallwoodV7LifecycleError::ProductionInactive(
        "durable_mempool_write",
    ))
}

pub(crate) fn restore_inactive_smallwood_v7_mempool_after_restart(
    _action: &InactiveSmallwoodV7RestartDecoded,
) -> Result<(), InactiveSmallwoodV7LifecycleError> {
    Err(InactiveSmallwoodV7LifecycleError::ProductionInactive(
        "restart_mempool_restore",
    ))
}

pub(crate) fn import_inactive_smallwood_v7_block_to_state(
    _action: &InactiveSmallwoodV7ImportDecoded,
) -> Result<(), InactiveSmallwoodV7LifecycleError> {
    Err(InactiveSmallwoodV7LifecycleError::ProductionInactive(
        "block_state_mutation",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_shielded_pool::inactive_smallwood_v7::{
        encode_inactive_smallwood_v7_statement, inactive_smallwood_v7_ciphertext_hash,
        InactiveSmallwoodV7ActivationBinding, InactiveSmallwoodV7Anchor56,
        InactiveSmallwoodV7AttestationCommitment56, InactiveSmallwoodV7BalanceTag56,
        InactiveSmallwoodV7ChainId56, InactiveSmallwoodV7CiphertextHash56,
        InactiveSmallwoodV7Commitment56, InactiveSmallwoodV7GenesisId56,
        InactiveSmallwoodV7Nullifier56, InactiveSmallwoodV7OracleCommitment56,
        InactiveSmallwoodV7PolicyHash56, InactiveSmallwoodV7RulesHash56,
        InactiveSmallwoodV7SignedMagnitude, InactiveSmallwoodV7StablecoinBinding,
        InactiveSmallwoodV7Statement, INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES,
        INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS, INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES,
    };
    use wallet::inactive_smallwood_v7::prepare_inactive_smallwood_v7_rpc_request;

    /// Private modes are carried only by the opaque proof. These tags are test
    /// corpus bytes and never become public statement or RPC fields.
    const PRIVATE_AUTH_MODE_TEST_TAGS: [(&str, u8); 5] = [
        ("SingleKey", 0),
        ("AccumulatorInit", 1),
        ("ApprovalStep", 2),
        ("ValueLockCreation", 3),
        ("FinalThresholdSpend", 4),
    ];

    fn fixture_context() -> InactiveSmallwoodV7ExpectedActivationContext {
        InactiveSmallwoodV7ExpectedActivationContext {
            network_id: 41,
            chain_id: InactiveSmallwoodV7ChainId56::new([11; 56]),
            genesis_id: InactiveSmallwoodV7GenesisId56::new([12; 56]),
            rules_hash: InactiveSmallwoodV7RulesHash56::new([13; 56]),
        }
    }

    fn fixture_ciphertexts(mask: u8) -> [Vec<u8>; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS] {
        [
            if mask & 4 != 0 {
                vec![0x40, mask, 0]
            } else {
                Vec::new()
            },
            if mask & 8 != 0 {
                vec![0x80, mask, 1, 0xff]
            } else {
                Vec::new()
            },
        ]
    }

    fn fixture_statement(
        mask: u8,
        ciphertexts: &[Vec<u8>; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
    ) -> [u8; INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES] {
        let input_flags = [mask & 1 != 0, mask & 2 != 0];
        let output_flags = [mask & 4 != 0, mask & 8 != 0];
        let mut activation = InactiveSmallwoodV7ActivationBinding::reserved_route();
        let context = fixture_context();
        activation.network_id = context.network_id;
        activation.chain_id = context.chain_id;
        activation.genesis_id = context.genesis_id;
        activation.rules_hash = context.rules_hash;
        encode_inactive_smallwood_v7_statement(&InactiveSmallwoodV7Statement {
            input_flags,
            output_flags,
            anchor: InactiveSmallwoodV7Anchor56::new([1; 56]),
            nullifiers: core::array::from_fn(|slot| {
                input_flags[slot]
                    .then(|| InactiveSmallwoodV7Nullifier56::new([2 + slot as u8; 56]))
                    .unwrap_or(InactiveSmallwoodV7Nullifier56::ZERO)
            }),
            commitments: core::array::from_fn(|slot| {
                output_flags[slot]
                    .then(|| InactiveSmallwoodV7Commitment56::new([4 + slot as u8; 56]))
                    .unwrap_or(InactiveSmallwoodV7Commitment56::ZERO)
            }),
            ciphertext_hashes: core::array::from_fn(|slot| {
                output_flags[slot]
                    .then(|| {
                        inactive_smallwood_v7_ciphertext_hash(slot, &ciphertexts[slot]).unwrap()
                    })
                    .unwrap_or(InactiveSmallwoodV7CiphertextHash56::ZERO)
            }),
            ciphertext_sizes: core::array::from_fn(|slot| {
                output_flags[slot]
                    .then_some(ciphertexts[slot].len() as u32)
                    .unwrap_or(0)
            }),
            balance_asset_ids: [0, 1, 2, 3],
            fee: 7,
            value_balance: InactiveSmallwoodV7SignedMagnitude::default(),
            stablecoin: InactiveSmallwoodV7StablecoinBinding {
                enabled: false,
                asset_id: 0,
                policy_version: 0,
                issuance_delta: InactiveSmallwoodV7SignedMagnitude::default(),
                policy_hash: InactiveSmallwoodV7PolicyHash56::ZERO,
                oracle_commitment: InactiveSmallwoodV7OracleCommitment56::ZERO,
                attestation_commitment: InactiveSmallwoodV7AttestationCommitment56::ZERO,
            },
            balance_tag: InactiveSmallwoodV7BalanceTag56::new([5; 56]),
            activation,
        })
        .unwrap()
    }

    fn rpc_fixture(
        mask: u8,
        auth_mode_tag: u8,
        proof_suffix: &[u8],
    ) -> (
        wallet::inactive_smallwood_v7::InactiveSmallwoodV7WalletPackage,
        SubmitActionRpcRequest,
        Vec<u8>,
    ) {
        let ciphertexts = fixture_ciphertexts(mask);
        let mut proof = vec![0xa7, auth_mode_tag, mask];
        proof.extend_from_slice(proof_suffix);
        let package = prepare_inactive_smallwood_v7_rpc_request(
            fixture_statement(mask, &ciphertexts),
            &proof,
            ciphertexts,
            &fixture_context(),
        )
        .unwrap();
        let value = serde_json::to_value(&package.request).unwrap();
        let request = super::super::decode_submit_action_rpc_request(value).unwrap();
        (package, request, proof)
    }

    fn mutate_proof_in_record_wire(
        record_wire: &mut [u8],
        expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
    ) {
        let record = decode_record_exact(record_wire, expected_activation).unwrap();
        let proof_offset_in_envelope =
            INACTIVE_SMALLWOOD_V7_ENVELOPE_HEADER_BYTES + INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES;
        let mut tampered_action =
            decode_inactive_smallwood_v7_inline_args(&record.canonical_public_args).unwrap();
        tampered_action.envelope[proof_offset_in_envelope] ^= 1;
        let tampered_public_args = tampered_action.canonical_bytes().unwrap();
        let public_args_offset = record_wire
            .windows(record.canonical_public_args.len())
            .position(|window| window == record.canonical_public_args)
            .unwrap();
        record_wire[public_args_offset..public_args_offset + tampered_public_args.len()]
            .copy_from_slice(&tampered_public_args);
    }

    #[test]
    fn all_16_masks_and_5_private_auth_modes_follow_one_restart_to_fresh_node_chain() {
        let expected = fixture_context();
        let mut cases = 0usize;
        for (mode_name, auth_mode_tag) in PRIVATE_AUTH_MODE_TEST_TAGS {
            for mask in 0u8..16 {
                let (wallet, request, proof) =
                    rpc_fixture(mask, auth_mode_tag, mode_name.as_bytes());
                assert_eq!(
                    wallet.proof_bytes().unwrap(),
                    proof,
                    "wallet {mode_name} mask {mask}"
                );

                let rpc = decode_inactive_smallwood_v7_rpc_seam(&request, &expected).unwrap();
                assert_eq!(
                    rpc.canonical_public_args(),
                    wallet.canonical_public_args.as_slice()
                );
                assert_eq!(rpc.prospective_action_id(), wallet.prospective_action_id);
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &rpc.proof_bytes().unwrap(),
                )
                .unwrap();

                let peer_wire = encode_inactive_smallwood_v7_peer_seam(&rpc).unwrap();
                let peer = decode_inactive_smallwood_v7_peer_seam(&peer_wire, &expected).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &peer.proof_bytes().unwrap(),
                )
                .unwrap();

                let staged = stage_inactive_smallwood_v7_mempool_seam(&peer).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &staged.proof_bytes().unwrap(),
                )
                .unwrap();
                let row = encode_inactive_smallwood_v7_durable_row_seam(&staged).unwrap();
                let restarted = decode_inactive_smallwood_v7_restart_seam(&row, &expected).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &restarted.proof_bytes().unwrap(),
                )
                .unwrap();
                let restarted_mempool =
                    restage_inactive_smallwood_v7_mempool_after_restart_seam(&restarted).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &restarted_mempool.proof_bytes().unwrap(),
                )
                .unwrap();
                let mined =
                    select_inactive_smallwood_v7_for_mining_seam(&restarted_mempool).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &mined.proof_bytes().unwrap(),
                )
                .unwrap();
                let block_wire = encode_inactive_smallwood_v7_block_seam(&mined).unwrap();
                let block =
                    decode_inactive_smallwood_v7_block_seam(&block_wire, &expected).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &block.proof_bytes().unwrap(),
                )
                .unwrap();
                let sync_wire = encode_inactive_smallwood_v7_sync_seam(&block).unwrap();
                let synced = decode_inactive_smallwood_v7_sync_seam(&sync_wire, &expected).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &synced.proof_bytes().unwrap(),
                )
                .unwrap();
                let detached = detach_inactive_smallwood_v7_reorg_seam(&synced).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &detached.proof_bytes().unwrap(),
                )
                .unwrap();
                let reattached = reattach_inactive_smallwood_v7_reorg_seam(&detached).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &reattached.proof_bytes().unwrap(),
                )
                .unwrap();
                let fresh_wire = encode_inactive_smallwood_v7_fresh_node_seam(&reattached).unwrap();
                let fresh =
                    decode_inactive_smallwood_v7_fresh_node_seam(&fresh_wire, &expected).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &fresh.proof_bytes().unwrap(),
                )
                .unwrap();
                let imported = validate_inactive_smallwood_v7_import_seam(&fresh).unwrap();
                ensure_inactive_smallwood_v7_proof_bytes_unchanged(
                    &proof,
                    &imported.proof_bytes().unwrap(),
                )
                .unwrap();
                assert_eq!(
                    imported.prospective_action_id(),
                    wallet.prospective_action_id
                );
                cases += 1;
            }
        }
        assert_eq!(cases, 16 * 5);
    }

    #[test]
    fn durable_restart_block_sync_and_fresh_node_reject_mutated_bytes() {
        let expected = fixture_context();
        let (_, request, _) = rpc_fixture(0b1111, 0, b"mutation-sensitive-future-proof");
        let rpc = decode_inactive_smallwood_v7_rpc_seam(&request, &expected).unwrap();
        let peer = decode_inactive_smallwood_v7_peer_seam(
            &encode_inactive_smallwood_v7_peer_seam(&rpc).unwrap(),
            &expected,
        )
        .unwrap();
        let staged = stage_inactive_smallwood_v7_mempool_seam(&peer).unwrap();

        let row = encode_inactive_smallwood_v7_durable_row_seam(&staged).unwrap();
        let mut key_mutated = row.clone();
        *key_mutated.key.last_mut().unwrap() ^= 1;
        assert!(matches!(
            decode_inactive_smallwood_v7_restart_seam(&key_mutated, &expected),
            Err(InactiveSmallwoodV7LifecycleError::DurableKeyActionIdMismatch)
        ));

        let mut value_mutated = row;
        mutate_proof_in_record_wire(&mut value_mutated.value, &expected);
        assert!(matches!(
            decode_inactive_smallwood_v7_restart_seam(&value_mutated, &expected),
            Err(InactiveSmallwoodV7LifecycleError::RecordActionIdMismatch)
        ));

        let restarted = decode_inactive_smallwood_v7_restart_seam(
            &encode_inactive_smallwood_v7_durable_row_seam(&staged).unwrap(),
            &expected,
        )
        .unwrap();
        let restarted_mempool =
            restage_inactive_smallwood_v7_mempool_after_restart_seam(&restarted).unwrap();
        let mined = select_inactive_smallwood_v7_for_mining_seam(&restarted_mempool).unwrap();
        let mut block_wire = encode_inactive_smallwood_v7_block_seam(&mined).unwrap();
        mutate_proof_in_record_wire(&mut block_wire, &expected);
        assert!(matches!(
            decode_inactive_smallwood_v7_block_seam(&block_wire, &expected),
            Err(InactiveSmallwoodV7LifecycleError::RecordActionIdMismatch)
        ));

        let block = decode_inactive_smallwood_v7_block_seam(
            &encode_inactive_smallwood_v7_block_seam(&mined).unwrap(),
            &expected,
        )
        .unwrap();
        let mut sync_wire = encode_inactive_smallwood_v7_sync_seam(&block).unwrap();
        mutate_proof_in_record_wire(&mut sync_wire, &expected);
        assert!(matches!(
            decode_inactive_smallwood_v7_sync_seam(&sync_wire, &expected),
            Err(InactiveSmallwoodV7LifecycleError::RecordActionIdMismatch)
        ));

        let synced = decode_inactive_smallwood_v7_sync_seam(
            &encode_inactive_smallwood_v7_sync_seam(&block).unwrap(),
            &expected,
        )
        .unwrap();
        let detached = detach_inactive_smallwood_v7_reorg_seam(&synced).unwrap();
        let reattached = reattach_inactive_smallwood_v7_reorg_seam(&detached).unwrap();
        let mut fresh_wire = encode_inactive_smallwood_v7_fresh_node_seam(&reattached).unwrap();
        mutate_proof_in_record_wire(&mut fresh_wire, &expected);
        assert!(matches!(
            decode_inactive_smallwood_v7_fresh_node_seam(&fresh_wire, &expected),
            Err(InactiveSmallwoodV7LifecycleError::RecordActionIdMismatch)
        ));
    }

    #[test]
    fn every_decode_boundary_requires_exact_activation_context() {
        let expected = fixture_context();
        let (_, request, _) = rpc_fixture(0b0101, 0, b"context");
        let rpc = decode_inactive_smallwood_v7_rpc_seam(&request, &expected).unwrap();
        let peer_wire = encode_inactive_smallwood_v7_peer_seam(&rpc).unwrap();
        let peer = decode_inactive_smallwood_v7_peer_seam(&peer_wire, &expected).unwrap();
        let staged = stage_inactive_smallwood_v7_mempool_seam(&peer).unwrap();
        let row = encode_inactive_smallwood_v7_durable_row_seam(&staged).unwrap();
        let restarted = decode_inactive_smallwood_v7_restart_seam(&row, &expected).unwrap();
        let restarted_mempool =
            restage_inactive_smallwood_v7_mempool_after_restart_seam(&restarted).unwrap();
        let mined = select_inactive_smallwood_v7_for_mining_seam(&restarted_mempool).unwrap();
        let block_wire = encode_inactive_smallwood_v7_block_seam(&mined).unwrap();
        let block = decode_inactive_smallwood_v7_block_seam(&block_wire, &expected).unwrap();
        let sync_wire = encode_inactive_smallwood_v7_sync_seam(&block).unwrap();
        let synced = decode_inactive_smallwood_v7_sync_seam(&sync_wire, &expected).unwrap();
        let detached = detach_inactive_smallwood_v7_reorg_seam(&synced).unwrap();
        let reattached = reattach_inactive_smallwood_v7_reorg_seam(&detached).unwrap();
        let fresh_wire = encode_inactive_smallwood_v7_fresh_node_seam(&reattached).unwrap();
        let mut mismatches = [expected; 4];
        mismatches[0].network_id ^= 1;
        mismatches[1].chain_id = InactiveSmallwoodV7ChainId56::new([31; 56]);
        mismatches[2].genesis_id = InactiveSmallwoodV7GenesisId56::new([32; 56]);
        mismatches[3].rules_hash = InactiveSmallwoodV7RulesHash56::new([33; 56]);
        for mismatch in mismatches {
            assert!(decode_inactive_smallwood_v7_rpc_seam(&request, &mismatch).is_err());
            assert!(decode_inactive_smallwood_v7_peer_seam(&peer_wire, &mismatch).is_err());
            assert!(decode_inactive_smallwood_v7_restart_seam(&row, &mismatch).is_err());
            assert!(decode_inactive_smallwood_v7_block_seam(&block_wire, &mismatch).is_err());
            assert!(decode_inactive_smallwood_v7_sync_seam(&sync_wire, &mismatch).is_err());
            assert!(decode_inactive_smallwood_v7_fresh_node_seam(&fresh_wire, &mismatch).is_err());
        }
    }

    #[test]
    fn every_state_mutation_and_verifier_seam_remains_fail_closed() {
        let expected = fixture_context();
        let (_, request, _) = rpc_fixture(0b0101, 0, b"not-a-production-proof");
        let rpc = decode_inactive_smallwood_v7_rpc_seam(&request, &expected).unwrap();
        assert!(admit_inactive_smallwood_v7_rpc_to_mempool(&rpc).is_err());
        let peer = decode_inactive_smallwood_v7_peer_seam(
            &encode_inactive_smallwood_v7_peer_seam(&rpc).unwrap(),
            &expected,
        )
        .unwrap();
        let staged = stage_inactive_smallwood_v7_mempool_seam(&peer).unwrap();
        assert!(relay_inactive_smallwood_v7_to_peers(&staged).is_err());
        let row = encode_inactive_smallwood_v7_durable_row_seam(&staged).unwrap();
        assert!(persist_inactive_smallwood_v7_mempool(&row).is_err());
        let restarted = decode_inactive_smallwood_v7_restart_seam(&row, &expected).unwrap();
        assert!(restore_inactive_smallwood_v7_mempool_after_restart(&restarted).is_err());
        let restarted_mempool =
            restage_inactive_smallwood_v7_mempool_after_restart_seam(&restarted).unwrap();
        let mined = select_inactive_smallwood_v7_for_mining_seam(&restarted_mempool).unwrap();
        let block = decode_inactive_smallwood_v7_block_seam(
            &encode_inactive_smallwood_v7_block_seam(&mined).unwrap(),
            &expected,
        )
        .unwrap();
        let synced = decode_inactive_smallwood_v7_sync_seam(
            &encode_inactive_smallwood_v7_sync_seam(&block).unwrap(),
            &expected,
        )
        .unwrap();
        let detached = detach_inactive_smallwood_v7_reorg_seam(&synced).unwrap();
        let reattached = reattach_inactive_smallwood_v7_reorg_seam(&detached).unwrap();
        let fresh = decode_inactive_smallwood_v7_fresh_node_seam(
            &encode_inactive_smallwood_v7_fresh_node_seam(&reattached).unwrap(),
            &expected,
        )
        .unwrap();
        let imported = validate_inactive_smallwood_v7_import_seam(&fresh).unwrap();
        assert!(verify_inactive_smallwood_v7_for_production(&imported).is_err());
        assert!(import_inactive_smallwood_v7_block_to_state(&imported).is_err());

        assert!(!INACTIVE_SMALLWOOD_V7_NATIVE_PRODUCTION_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_RPC_ADMISSION_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_PEER_RELAY_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_DURABLE_MEMPOOL_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_MINING_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_BLOCK_IMPORT_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_SYNC_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_REORG_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_FRESH_NODE_ENABLED);
        assert!(!INACTIVE_SMALLWOOD_V7_RESTART_RESTORE_ENABLED);
    }
}
