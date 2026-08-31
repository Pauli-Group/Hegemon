//! Move-only native lifecycle seams for the unallocated HX512 inline action.
//!
//! This module is compiled but is not registered with the active RPC router,
//! peer protocol, mempool, miner, block grammar, sync protocol, or release
//! manifest.  Its purpose is to pin the future same-byte contract without
//! forcing the 64-byte HX512 state into legacy 48-byte identities.
//!
//! The raw action itself is the peer, durable-value, block, sync, reorg, and
//! fresh-node wire.  Stage transitions move its sole owned `Vec<u8>`; they do
//! not decode and rebuild the statement, extract a second proof vector, or add
//! a receipt/cache/sidecar.  Every admission or re-admission invokes the
//! supplied exact statement/ciphertext/proof verifier again.

#![allow(dead_code)]

use base64::Engine;
use protocol_shielded_pool::hx512_inline_transport::{
    project_hx512_inline_identity, validate_hx512_inline_action, Hx512InlineAction,
    Hx512InlineAdmissionVerifier, Hx512InlineIdentityProjection, Hx512InlineTransportContext,
    Hx512InlineTransportError, HX512_INLINE_IDENTITY_BYTES, HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
};
use sha2::{Digest, Sha512};
use std::path::Path;
use wallet::hx512_lifecycle::prepare_hx512_candidate_rpc_request;

use super::{native_submit_action_route_supported, SubmitActionRpcRequest};

pub(crate) const HX512_NATIVE_IDENTITY_ALLOCATED: bool = false;
pub(crate) const HX512_NATIVE_RPC_ROUTE_REGISTERED: bool = false;
pub(crate) const HX512_NATIVE_PEER_RELAY_ENABLED: bool = false;
pub(crate) const HX512_NATIVE_DURABLE_MEMPOOL_ENABLED: bool = false;
pub(crate) const HX512_NATIVE_MINING_ENABLED: bool = false;
pub(crate) const HX512_NATIVE_BLOCK_IMPORT_ENABLED: bool = false;
pub(crate) const HX512_NATIVE_SYNC_ENABLED: bool = false;
pub(crate) const HX512_NATIVE_REORG_ENABLED: bool = false;
pub(crate) const HX512_NATIVE_FRESH_NODE_ENABLED: bool = false;
pub(crate) const HX512_NATIVE_RELATION_REFINEMENT_COMPLETE: bool = false;
pub(crate) const HX512_NATIVE_COMPLETE_ZK_AUTHORIZED: bool = false;
pub(crate) const HX512_NATIVE_COMPOSED_PQ128_AUTHORIZED: bool = false;
pub(crate) const HX512_NATIVE_RETAINED_ARTIFACTS_AUTHORIZED: bool = false;
pub(crate) const HX512_NATIVE_RELEASE_MANIFEST_AUTHORIZED: bool = false;
pub(crate) const HX512_NATIVE_PRODUCTION_ENABLED: bool = false;

const HX512_DURABLE_KEY_PREFIX: &[u8] = b"pending_hx512_inactive_v1/";
const HX512_DURABLE_KEY_DOMAIN: &[u8] = b"hegemon.hx512.inactive-durable-key.sha512.v1\0";
const HX512_SHA512_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hx512LifecycleBinding {
    expected_identity: [u8; HX512_INLINE_IDENTITY_BYTES],
    max_proof_bytes: u32,
}

impl Hx512LifecycleBinding {
    pub(crate) fn new(
        expected_identity: [u8; HX512_INLINE_IDENTITY_BYTES],
        max_proof_bytes: u32,
    ) -> Result<Self, Hx512LifecycleError> {
        Hx512InlineTransportContext::new(
            &expected_identity,
            max_proof_bytes,
            HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
        )?;
        let projected = project_hx512_inline_identity(&expected_identity);
        if projected.magic.iter().all(|byte| *byte == 0) {
            return Err(Hx512LifecycleError::MalformedIdentity("magic"));
        }
        for (label, value) in [
            ("statement_grammar", projected.statement_grammar),
            ("circuit_version", projected.circuit_version),
            ("crypto_suite", projected.crypto_suite),
            ("family_id", projected.family_id),
            ("action_id", projected.action_id),
            ("domain_set", projected.domain_set),
        ] {
            if value == 0 {
                return Err(Hx512LifecycleError::MalformedIdentity(label));
            }
        }
        if projected.backend_id == 0 {
            return Err(Hx512LifecycleError::MalformedIdentity("backend_id"));
        }
        if projected.proof_profile == 0 {
            return Err(Hx512LifecycleError::MalformedIdentity("proof_profile"));
        }
        if projected.chain_id.iter().all(|byte| *byte == 0) {
            return Err(Hx512LifecycleError::MalformedIdentity("chain_id"));
        }
        if projected.genesis_id.iter().all(|byte| *byte == 0) {
            return Err(Hx512LifecycleError::MalformedIdentity("genesis_id"));
        }
        if projected.rules_hash.iter().all(|byte| *byte == 0) {
            return Err(Hx512LifecycleError::MalformedIdentity("rules_hash"));
        }
        if native_submit_action_route_supported(projected.family_id, projected.action_id) {
            return Err(Hx512LifecycleError::AllocatedRouteAlias);
        }
        Ok(Self {
            expected_identity,
            max_proof_bytes,
        })
    }

    pub(crate) fn identity(self) -> Hx512InlineIdentityProjection {
        project_hx512_inline_identity(&self.expected_identity)
    }

    fn with_transport_context<T>(
        &self,
        operation: impl FnOnce(Hx512InlineTransportContext<'_>) -> Result<T, Hx512LifecycleError>,
    ) -> Result<T, Hx512LifecycleError> {
        let context = Hx512InlineTransportContext::new(
            &self.expected_identity,
            self.max_proof_bytes,
            HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
        )?;
        operation(context)
    }

    fn maximum_action_bytes(&self) -> Result<usize, Hx512LifecycleError> {
        self.with_transport_context(|context| Ok(context.maximum_action_bytes()?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hx512LifecycleStage {
    Rpc,
    Relay,
    Mempool,
    Restart,
    Mining,
    Block,
    Sync,
    ReorgDetached,
    ReorgReattached,
    FreshNode,
    Import,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hx512LifecycleError {
    Transport(Hx512InlineTransportError),
    MalformedIdentity(&'static str),
    AllocatedRouteAlias,
    RouteMismatch(&'static str),
    LegacyKernelFieldsPresent,
    LegacyNullifierFieldPresent,
    EncodedActionTooLarge(usize),
    Base64Rejected,
    Base64NonCanonical,
    StageMismatch {
        expected: Hx512LifecycleStage,
        observed: Hx512LifecycleStage,
    },
    DurableKeyLength(usize),
    DurableKeyPrefix,
    DurableKeyDigestMismatch,
    ProductionInactive(&'static str),
}

impl core::fmt::Display for Hx512LifecycleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "inactive HX512 lifecycle rejection: {self:?}")
    }
}

impl std::error::Error for Hx512LifecycleError {}

impl From<Hx512InlineTransportError> for Hx512LifecycleError {
    fn from(error: Hx512InlineTransportError) -> Self {
        Self::Transport(error)
    }
}

/// One move-only admitted raw action at a particular lifecycle stage.
///
/// This intentionally has no `Clone` implementation.  A wire encoder consumes
/// it and returns the original owned byte vector.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Hx512LifecycleAction {
    binding: Hx512LifecycleBinding,
    stage: Hx512LifecycleStage,
    action: Hx512InlineAction,
}

impl Hx512LifecycleAction {
    pub(crate) const fn stage(&self) -> Hx512LifecycleStage {
        self.stage
    }

    pub(crate) fn canonical_action_bytes(&self) -> &[u8] {
        self.action.as_bytes()
    }

    pub(crate) fn proof_bytes(&self) -> &[u8] {
        self.action.proof()
    }

    fn require_stage(&self, expected: Hx512LifecycleStage) -> Result<(), Hx512LifecycleError> {
        if self.stage == expected {
            Ok(())
        } else {
            Err(Hx512LifecycleError::StageMismatch {
                expected,
                observed: self.stage,
            })
        }
    }

    fn reverify<V: Hx512InlineAdmissionVerifier + ?Sized>(
        &self,
        verifier: &V,
    ) -> Result<(), Hx512LifecycleError> {
        self.binding.with_transport_context(|context| {
            validate_hx512_inline_action(context, self.action.as_bytes(), verifier)?;
            Ok(())
        })
    }

    fn transition<V: Hx512InlineAdmissionVerifier + ?Sized>(
        mut self,
        expected: Hx512LifecycleStage,
        next: Hx512LifecycleStage,
        verifier: &V,
    ) -> Result<Self, Hx512LifecycleError> {
        self.require_stage(expected)?;
        self.reverify(verifier)?;
        self.stage = next;
        Ok(self)
    }

    fn into_wire<V: Hx512InlineAdmissionVerifier + ?Sized>(
        self,
        expected: Hx512LifecycleStage,
        verifier: &V,
    ) -> Result<Vec<u8>, Hx512LifecycleError> {
        self.require_stage(expected)?;
        self.reverify(verifier)?;
        Ok(self.action.into_bytes())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Hx512DurableMempoolRow {
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

fn action_digest(action: &[u8]) -> [u8; HX512_SHA512_BYTES] {
    let mut hasher = Sha512::new();
    hasher.update(HX512_DURABLE_KEY_DOMAIN);
    hasher.update(action);
    hasher.finalize().into()
}

fn durable_key(action: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(HX512_DURABLE_KEY_PREFIX.len() + HX512_SHA512_BYTES);
    key.extend_from_slice(HX512_DURABLE_KEY_PREFIX);
    key.extend_from_slice(&action_digest(action));
    key
}

fn admit_owned_at_stage<V: Hx512InlineAdmissionVerifier + ?Sized>(
    binding: Hx512LifecycleBinding,
    raw_action: Vec<u8>,
    stage: Hx512LifecycleStage,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    binding.with_transport_context(|context| {
        let action = Hx512InlineAction::admit_owned(context, raw_action, verifier)?;
        Ok(Hx512LifecycleAction {
            binding,
            stage,
            action,
        })
    })
}

/// Decode the legacy-shaped JSON object only as an inactive future-route seam.
/// The active router rejects this unallocated route before calling here.
pub(crate) fn decode_hx512_rpc_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    request: &SubmitActionRpcRequest,
    binding: Hx512LifecycleBinding,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    let identity = binding.identity();
    for (label, observed, expected) in [
        (
            "binding_circuit",
            request.binding_circuit,
            identity.circuit_version,
        ),
        (
            "binding_crypto",
            request.binding_crypto,
            identity.crypto_suite,
        ),
        ("family_id", request.family_id, identity.family_id),
        ("action_id", request.action_id, identity.action_id),
    ] {
        if observed != expected {
            return Err(Hx512LifecycleError::RouteMismatch(label));
        }
    }
    if !request.object_refs.is_empty()
        || request.authorization_proof.is_some()
        || !request.authorization_signatures.is_empty()
        || request.aux_data.is_some()
    {
        return Err(Hx512LifecycleError::LegacyKernelFieldsPresent);
    }
    if !request.new_nullifiers.is_empty() {
        return Err(Hx512LifecycleError::LegacyNullifierFieldPresent);
    }

    let maximum_action_bytes = binding.maximum_action_bytes()?;
    let maximum_encoded = base64::encoded_len(maximum_action_bytes, true).unwrap_or(usize::MAX);
    if request.public_args.len() > maximum_encoded {
        return Err(Hx512LifecycleError::EncodedActionTooLarge(
            request.public_args.len(),
        ));
    }
    let raw_action = base64::engine::general_purpose::STANDARD
        .decode(&request.public_args)
        .map_err(|_| Hx512LifecycleError::Base64Rejected)?;
    if base64::engine::general_purpose::STANDARD.encode(&raw_action) != request.public_args {
        return Err(Hx512LifecycleError::Base64NonCanonical);
    }
    admit_owned_at_stage(binding, raw_action, Hx512LifecycleStage::Rpc, verifier)
}

pub(crate) fn encode_hx512_peer_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    rpc: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Vec<u8>, Hx512LifecycleError> {
    rpc.into_wire(Hx512LifecycleStage::Rpc, verifier)
}

pub(crate) fn decode_hx512_peer_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    raw_action: Vec<u8>,
    binding: Hx512LifecycleBinding,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    admit_owned_at_stage(binding, raw_action, Hx512LifecycleStage::Relay, verifier)
}

pub(crate) fn stage_hx512_mempool_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    peer: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    peer.transition(
        Hx512LifecycleStage::Relay,
        Hx512LifecycleStage::Mempool,
        verifier,
    )
}

pub(crate) fn encode_hx512_durable_row_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    staged: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Hx512DurableMempoolRow, Hx512LifecycleError> {
    staged.require_stage(Hx512LifecycleStage::Mempool)?;
    staged.reverify(verifier)?;
    let value = staged.action.into_bytes();
    Ok(Hx512DurableMempoolRow {
        key: durable_key(&value),
        value,
    })
}

pub(crate) fn decode_hx512_restart_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    row: Hx512DurableMempoolRow,
    binding: Hx512LifecycleBinding,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    let expected_key_length = HX512_DURABLE_KEY_PREFIX.len() + HX512_SHA512_BYTES;
    if row.key.len() != expected_key_length {
        return Err(Hx512LifecycleError::DurableKeyLength(row.key.len()));
    }
    if !row.key.starts_with(HX512_DURABLE_KEY_PREFIX) {
        return Err(Hx512LifecycleError::DurableKeyPrefix);
    }
    if row.key != durable_key(&row.value) {
        return Err(Hx512LifecycleError::DurableKeyDigestMismatch);
    }
    admit_owned_at_stage(binding, row.value, Hx512LifecycleStage::Restart, verifier)
}

pub(crate) fn restage_hx512_mempool_after_restart_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    restarted: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    restarted.transition(
        Hx512LifecycleStage::Restart,
        Hx512LifecycleStage::Mempool,
        verifier,
    )
}

pub(crate) fn select_hx512_for_mining_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    staged: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    staged.transition(
        Hx512LifecycleStage::Mempool,
        Hx512LifecycleStage::Mining,
        verifier,
    )
}

pub(crate) fn encode_hx512_block_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    mined: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Vec<u8>, Hx512LifecycleError> {
    mined.into_wire(Hx512LifecycleStage::Mining, verifier)
}

pub(crate) fn decode_hx512_block_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    raw_action: Vec<u8>,
    binding: Hx512LifecycleBinding,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    admit_owned_at_stage(binding, raw_action, Hx512LifecycleStage::Block, verifier)
}

pub(crate) fn encode_hx512_sync_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    block: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Vec<u8>, Hx512LifecycleError> {
    block.into_wire(Hx512LifecycleStage::Block, verifier)
}

pub(crate) fn decode_hx512_sync_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    raw_action: Vec<u8>,
    binding: Hx512LifecycleBinding,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    admit_owned_at_stage(binding, raw_action, Hx512LifecycleStage::Sync, verifier)
}

pub(crate) fn detach_hx512_reorg_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    synced: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    synced.transition(
        Hx512LifecycleStage::Sync,
        Hx512LifecycleStage::ReorgDetached,
        verifier,
    )
}

pub(crate) fn reattach_hx512_reorg_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    detached: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    detached.transition(
        Hx512LifecycleStage::ReorgDetached,
        Hx512LifecycleStage::ReorgReattached,
        verifier,
    )
}

pub(crate) fn encode_hx512_fresh_node_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    reattached: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Vec<u8>, Hx512LifecycleError> {
    reattached.into_wire(Hx512LifecycleStage::ReorgReattached, verifier)
}

pub(crate) fn decode_hx512_fresh_node_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    raw_action: Vec<u8>,
    binding: Hx512LifecycleBinding,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    admit_owned_at_stage(
        binding,
        raw_action,
        Hx512LifecycleStage::FreshNode,
        verifier,
    )
}

pub(crate) fn validate_hx512_import_seam<V: Hx512InlineAdmissionVerifier + ?Sized>(
    fresh: Hx512LifecycleAction,
    verifier: &V,
) -> Result<Hx512LifecycleAction, Hx512LifecycleError> {
    fresh.transition(
        Hx512LifecycleStage::FreshNode,
        Hx512LifecycleStage::Import,
        verifier,
    )
}

pub(crate) fn ensure_hx512_production_authority() -> Result<(), Hx512LifecycleError> {
    Err(Hx512LifecycleError::ProductionInactive(
        "identity/relation/ZK/PQ128/refinement/artifacts/release manifest",
    ))
}

pub(crate) fn admit_hx512_rpc_to_mempool(
    _action: &Hx512LifecycleAction,
) -> Result<(), Hx512LifecycleError> {
    ensure_hx512_production_authority()
}

pub(crate) fn relay_hx512_to_peers(
    _action: &Hx512LifecycleAction,
) -> Result<(), Hx512LifecycleError> {
    ensure_hx512_production_authority()
}

pub(crate) fn persist_hx512_mempool(
    _row: &Hx512DurableMempoolRow,
) -> Result<(), Hx512LifecycleError> {
    ensure_hx512_production_authority()
}

pub(crate) fn import_hx512_block_to_state(
    _action: &Hx512LifecycleAction,
) -> Result<(), Hx512LifecycleError> {
    ensure_hx512_production_authority()
}

/// Exercise the complete move-only native lifecycle with one canonical action.
///
/// This is an executable integration seam, not production route activation.
/// Every admission and transition invokes `verifier`; the durable mempool row
/// is flushed to sled, the database is closed and reopened, and the final
/// imported bytes must equal the wallet-produced bytes exactly.
pub fn exercise_hx512_candidate_lifecycle<V: Hx512InlineAdmissionVerifier + ?Sized>(
    raw_action: Vec<u8>,
    expected_identity: [u8; HX512_INLINE_IDENTITY_BYTES],
    max_proof_bytes: u32,
    durable_database_path: &Path,
    verifier: &V,
) -> Result<Vec<u8>, Hx512LifecycleExerciseError> {
    let expected_length = raw_action.len();
    let expected_digest = action_digest(&raw_action);
    let binding = Hx512LifecycleBinding::new(expected_identity, max_proof_bytes)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let wallet_context = Hx512InlineTransportContext::new(
        &expected_identity,
        max_proof_bytes,
        HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
    )
    .map_err(Hx512LifecycleExerciseError::transport)?;
    let wallet_request = prepare_hx512_candidate_rpc_request(wallet_context, raw_action, verifier)
        .map_err(|error| Hx512LifecycleExerciseError(error.to_string()))?;
    let request = super::decode_submit_action_rpc_request(
        serde_json::to_value(wallet_request)
            .map_err(|error| Hx512LifecycleExerciseError(error.to_string()))?,
    )
    .map_err(|error| Hx512LifecycleExerciseError(error.to_string()))?;

    let rpc = decode_hx512_rpc_seam(&request, binding, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let peer_wire =
        encode_hx512_peer_seam(rpc, verifier).map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let peer = decode_hx512_peer_seam(peer_wire, binding, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let staged =
        stage_hx512_mempool_seam(peer, verifier).map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let durable = encode_hx512_durable_row_seam(staged, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let durable_key = durable.key.clone();
    {
        let database = sled::open(durable_database_path)
            .map_err(|error| Hx512LifecycleExerciseError(error.to_string()))?;
        let tree = database
            .open_tree("hx512_working_pending")
            .map_err(|error| Hx512LifecycleExerciseError(error.to_string()))?;
        tree.insert(&durable.key, durable.value.as_slice())
            .map_err(|error| Hx512LifecycleExerciseError(error.to_string()))?;
        database
            .flush()
            .map_err(|error| Hx512LifecycleExerciseError(error.to_string()))?;
    }
    let durable_value = {
        let database = sled::open(durable_database_path)
            .map_err(|error| Hx512LifecycleExerciseError(error.to_string()))?;
        let tree = database
            .open_tree("hx512_working_pending")
            .map_err(|error| Hx512LifecycleExerciseError(error.to_string()))?;
        tree.get(&durable_key)
            .map_err(|error| Hx512LifecycleExerciseError(error.to_string()))?
            .ok_or_else(|| {
                Hx512LifecycleExerciseError(
                    "durable HX512 action missing after database reopen".to_owned(),
                )
            })?
            .to_vec()
    };
    let restarted = decode_hx512_restart_seam(
        Hx512DurableMempoolRow {
            key: durable_key,
            value: durable_value,
        },
        binding,
        verifier,
    )
    .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let staged = restage_hx512_mempool_after_restart_seam(restarted, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let mined = select_hx512_for_mining_seam(staged, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let block_wire =
        encode_hx512_block_seam(mined, verifier).map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let block = decode_hx512_block_seam(block_wire, binding, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let sync_wire =
        encode_hx512_sync_seam(block, verifier).map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let synced = decode_hx512_sync_seam(sync_wire, binding, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let detached = detach_hx512_reorg_seam(synced, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let reattached = reattach_hx512_reorg_seam(detached, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let fresh_wire = encode_hx512_fresh_node_seam(reattached, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let fresh = decode_hx512_fresh_node_seam(fresh_wire, binding, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let imported = validate_hx512_import_seam(fresh, verifier)
        .map_err(Hx512LifecycleExerciseError::lifecycle)?;
    let final_bytes = imported.action.into_bytes();
    if final_bytes.len() != expected_length || action_digest(&final_bytes) != expected_digest {
        return Err(Hx512LifecycleExerciseError(
            "native HX512 lifecycle changed the canonical action bytes".to_owned(),
        ));
    }
    Ok(final_bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512LifecycleExerciseError(String);

impl Hx512LifecycleExerciseError {
    fn lifecycle(error: Hx512LifecycleError) -> Self {
        Self(error.to_string())
    }

    fn transport(error: Hx512InlineTransportError) -> Self {
        Self(error.to_string())
    }
}

impl core::fmt::Display for Hx512LifecycleExerciseError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Hx512LifecycleExerciseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_shielded_pool::hx512_inline_transport::{
        HX512_INLINE_ACTIVITY_MASK_OFFSET, HX512_INLINE_AGGREGATE_VALIDITY_ALLOWED,
        HX512_INLINE_CACHE_VALIDITY_ALLOWED, HX512_INLINE_CIPHERTEXT_BYTES,
        HX512_INLINE_PREFIX_BYTES, HX512_INLINE_PRODUCTION_ADMISSION_ENABLED,
        HX512_INLINE_RECEIPT_VALIDITY_ALLOWED, HX512_INLINE_SIDECAR_VALIDITY_ALLOWED,
        HX512_INLINE_STATEMENT_BYTES,
    };
    use wallet::hx512_lifecycle::prepare_hx512_candidate_rpc_request;

    // Opaque fixture bytes exercise lifecycle byte preservation only.  They
    // are not authorization-mode encodings and make no relation-validity
    // claim.  Of the corresponding 80-case semantic matrix, the independently
    // compiled grammar accepts 26 and rejects 54; this fixture does not
    // evaluate that grammar.
    const OPAQUE_TRANSPORT_TAGS: [u8; 5] = [0, 1, 2, 3, 4];

    struct FixtureVerifier {
        statement: [u8; HX512_INLINE_STATEMENT_BYTES],
        proof: Vec<u8>,
        ciphertexts: [[u8; HX512_INLINE_CIPHERTEXT_BYTES]; 2],
    }

    impl Hx512InlineAdmissionVerifier for FixtureVerifier {
        fn validate_statement(&self, statement: &[u8; HX512_INLINE_STATEMENT_BYTES]) -> bool {
            statement == &self.statement
        }

        fn validate_proof(
            &self,
            statement: &[u8; HX512_INLINE_STATEMENT_BYTES],
            proof: &[u8],
        ) -> bool {
            statement == &self.statement && proof == self.proof
        }

        fn validate_ciphertext(
            &self,
            output_slot: usize,
            statement: &[u8; HX512_INLINE_STATEMENT_BYTES],
            ciphertext: &[u8; HX512_INLINE_CIPHERTEXT_BYTES],
        ) -> bool {
            statement == &self.statement && self.ciphertexts.get(output_slot) == Some(ciphertext)
        }
    }

    fn fixture_identity() -> [u8; HX512_INLINE_IDENTITY_BYTES] {
        let mut identity = [0u8; HX512_INLINE_IDENTITY_BYTES];
        identity[..8].copy_from_slice(b"HXTEST01");
        identity[8..10].copy_from_slice(&1u16.to_be_bytes());
        identity[10..12].copy_from_slice(&65_000u16.to_be_bytes());
        identity[12..14].copy_from_slice(&65_001u16.to_be_bytes());
        identity[14..16].copy_from_slice(&65_002u16.to_be_bytes());
        identity[16..18].copy_from_slice(&65_003u16.to_be_bytes());
        identity[18] = 7;
        identity[19] = 8;
        identity[20..22].copy_from_slice(&9u16.to_be_bytes());
        identity[22..26].copy_from_slice(&41u32.to_be_bytes());
        identity[26..58].fill(0x31);
        identity[58..122].fill(0x32);
        identity[122..186].fill(0x33);
        identity
    }

    fn fixture(mask: u8, opaque_tag: u8) -> (Vec<u8>, FixtureVerifier) {
        let identity = fixture_identity();
        let mut statement = [0u8; HX512_INLINE_STATEMENT_BYTES];
        statement[..HX512_INLINE_IDENTITY_BYTES].copy_from_slice(&identity);
        statement[HX512_INLINE_ACTIVITY_MASK_OFFSET] = mask;
        for (index, byte) in statement[HX512_INLINE_IDENTITY_BYTES + 1..]
            .iter_mut()
            .enumerate()
        {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(mask);
        }
        let proof = vec![0xa5, opaque_tag, mask, 0x51, 0x52, 0x53];
        let ciphertexts = [
            [0x41; HX512_INLINE_CIPHERTEXT_BYTES],
            [0x42; HX512_INLINE_CIPHERTEXT_BYTES],
        ];
        let mut raw_action = Vec::new();
        raw_action.extend_from_slice(&statement);
        raw_action.extend_from_slice(&(proof.len() as u32).to_be_bytes());
        raw_action.extend_from_slice(&proof);
        if mask & 0x04 != 0 {
            raw_action.extend_from_slice(&ciphertexts[0]);
        }
        if mask & 0x08 != 0 {
            raw_action.extend_from_slice(&ciphertexts[1]);
        }
        (
            raw_action,
            FixtureVerifier {
                statement,
                proof,
                ciphertexts,
            },
        )
    }

    fn assert_action(
        action: &Hx512LifecycleAction,
        stage: Hx512LifecycleStage,
        raw_action: &[u8],
        proof: &[u8],
    ) {
        assert_eq!(action.stage(), stage);
        assert_eq!(action.canonical_action_bytes(), raw_action);
        assert_eq!(action.proof_bytes(), proof);
    }

    #[test]
    fn all_16_transport_masks_and_5_opaque_tags_preserve_one_raw_action() {
        let binding = Hx512LifecycleBinding::new(fixture_identity(), 64).unwrap();
        let mut cases = 0usize;
        for opaque_tag in OPAQUE_TRANSPORT_TAGS {
            for mask in 0u8..16 {
                let (raw_action, verifier) = fixture(mask, opaque_tag);
                let proof = verifier.proof.clone();
                let identity = fixture_identity();
                let wallet_context = Hx512InlineTransportContext::new(
                    &identity,
                    64,
                    HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
                )
                .unwrap();
                let wallet_request = prepare_hx512_candidate_rpc_request(
                    wallet_context,
                    raw_action.clone(),
                    &verifier,
                )
                .unwrap();
                assert_eq!(wallet_request.canonical_action_bytes().unwrap(), raw_action);
                let request = super::super::decode_submit_action_rpc_request(
                    serde_json::to_value(wallet_request).unwrap(),
                )
                .unwrap();

                let rpc = decode_hx512_rpc_seam(&request, binding, &verifier).unwrap();
                assert_action(&rpc, Hx512LifecycleStage::Rpc, &raw_action, &proof);
                let peer_wire = encode_hx512_peer_seam(rpc, &verifier).unwrap();
                assert_eq!(peer_wire, raw_action);
                let peer = decode_hx512_peer_seam(peer_wire, binding, &verifier).unwrap();
                assert_action(&peer, Hx512LifecycleStage::Relay, &raw_action, &proof);
                let staged = stage_hx512_mempool_seam(peer, &verifier).unwrap();
                assert_action(&staged, Hx512LifecycleStage::Mempool, &raw_action, &proof);
                let durable = encode_hx512_durable_row_seam(staged, &verifier).unwrap();
                assert_eq!(durable.value, raw_action);
                let restarted = decode_hx512_restart_seam(durable, binding, &verifier).unwrap();
                assert_action(
                    &restarted,
                    Hx512LifecycleStage::Restart,
                    &raw_action,
                    &proof,
                );
                let staged =
                    restage_hx512_mempool_after_restart_seam(restarted, &verifier).unwrap();
                let mined = select_hx512_for_mining_seam(staged, &verifier).unwrap();
                assert_action(&mined, Hx512LifecycleStage::Mining, &raw_action, &proof);
                let block_wire = encode_hx512_block_seam(mined, &verifier).unwrap();
                assert_eq!(block_wire, raw_action);
                let block = decode_hx512_block_seam(block_wire, binding, &verifier).unwrap();
                assert_action(&block, Hx512LifecycleStage::Block, &raw_action, &proof);
                let sync_wire = encode_hx512_sync_seam(block, &verifier).unwrap();
                assert_eq!(sync_wire, raw_action);
                let synced = decode_hx512_sync_seam(sync_wire, binding, &verifier).unwrap();
                assert_action(&synced, Hx512LifecycleStage::Sync, &raw_action, &proof);
                let detached = detach_hx512_reorg_seam(synced, &verifier).unwrap();
                let reattached = reattach_hx512_reorg_seam(detached, &verifier).unwrap();
                let fresh_wire = encode_hx512_fresh_node_seam(reattached, &verifier).unwrap();
                assert_eq!(fresh_wire, raw_action);
                let fresh = decode_hx512_fresh_node_seam(fresh_wire, binding, &verifier).unwrap();
                let imported = validate_hx512_import_seam(fresh, &verifier).unwrap();
                assert_action(&imported, Hx512LifecycleStage::Import, &raw_action, &proof);
                cases += 1;
            }
        }
        assert_eq!(cases, 16 * 5);
    }

    #[test]
    fn proof_mutation_with_recomputed_durable_key_still_reaches_and_fails_verifier() {
        let binding = Hx512LifecycleBinding::new(fixture_identity(), 64).unwrap();
        let (raw_action, verifier) = fixture(0x0f, 4);
        let peer = decode_hx512_peer_seam(raw_action, binding, &verifier).unwrap();
        let staged = stage_hx512_mempool_seam(peer, &verifier).unwrap();
        let mut durable = encode_hx512_durable_row_seam(staged, &verifier).unwrap();
        durable.value[HX512_INLINE_PREFIX_BYTES] ^= 1;
        durable.key = durable_key(&durable.value);
        assert!(matches!(
            decode_hx512_restart_seam(durable, binding, &verifier),
            Err(Hx512LifecycleError::Transport(
                Hx512InlineTransportError::ProofRejected
            ))
        ));
    }

    #[test]
    fn durable_key_corruption_and_wrong_stage_fail_before_state_mutation() {
        let binding = Hx512LifecycleBinding::new(fixture_identity(), 64).unwrap();
        let (raw_action, verifier) = fixture(0x05, 0);
        let peer = decode_hx512_peer_seam(raw_action, binding, &verifier).unwrap();
        let staged = stage_hx512_mempool_seam(peer, &verifier).unwrap();
        let mut durable = encode_hx512_durable_row_seam(staged, &verifier).unwrap();
        *durable.key.last_mut().unwrap() ^= 1;
        assert_eq!(
            decode_hx512_restart_seam(durable, binding, &verifier),
            Err(Hx512LifecycleError::DurableKeyDigestMismatch)
        );

        let (raw_action, verifier) = fixture(0x05, 0);
        let relay = decode_hx512_peer_seam(raw_action, binding, &verifier).unwrap();
        assert!(matches!(
            select_hx512_for_mining_seam(relay, &verifier),
            Err(Hx512LifecycleError::StageMismatch {
                expected: Hx512LifecycleStage::Mempool,
                observed: Hx512LifecycleStage::Relay,
            })
        ));
    }

    #[test]
    fn sled_flush_and_reopen_preserve_the_exact_raw_action_value() {
        let directory = tempfile::tempdir().unwrap();
        let binding = Hx512LifecycleBinding::new(fixture_identity(), 64).unwrap();
        let (raw_action, verifier) = fixture(0x0f, 3);
        let peer = decode_hx512_peer_seam(raw_action.clone(), binding, &verifier).unwrap();
        let staged = stage_hx512_mempool_seam(peer, &verifier).unwrap();
        let durable = encode_hx512_durable_row_seam(staged, &verifier).unwrap();
        let key = durable.key.clone();

        {
            let database = sled::open(directory.path()).unwrap();
            let tree = database.open_tree("hx512_inactive_pending").unwrap();
            tree.insert(&durable.key, durable.value.as_slice()).unwrap();
            database.flush().unwrap();
        }
        let database = sled::open(directory.path()).unwrap();
        let tree = database.open_tree("hx512_inactive_pending").unwrap();
        let value = tree.get(&key).unwrap().unwrap().to_vec();
        assert_eq!(value, raw_action);
        let restarted =
            decode_hx512_restart_seam(Hx512DurableMempoolRow { key, value }, binding, &verifier)
                .unwrap();
        assert_action(
            &restarted,
            Hx512LifecycleStage::Restart,
            &raw_action,
            &verifier.proof,
        );
    }

    #[test]
    fn route_context_and_noncanonical_rpc_mutations_fail_closed() {
        let binding = Hx512LifecycleBinding::new(fixture_identity(), 64).unwrap();
        let (raw_action, verifier) = fixture(0x0c, 2);
        let identity = fixture_identity();
        let context =
            Hx512InlineTransportContext::new(&identity, 64, HX512_INLINE_STABLECOIN_PUBLIC_BYTES)
                .unwrap();
        let wallet_request =
            prepare_hx512_candidate_rpc_request(context, raw_action, &verifier).unwrap();
        let value = serde_json::to_value(wallet_request).unwrap();
        let mut request = super::super::decode_submit_action_rpc_request(value).unwrap();
        request.action_id ^= 1;
        assert_eq!(
            decode_hx512_rpc_seam(&request, binding, &verifier),
            Err(Hx512LifecycleError::RouteMismatch("action_id"))
        );
        request.action_id ^= 1;
        request.public_args.push('\n');
        assert!(matches!(
            decode_hx512_rpc_seam(&request, binding, &verifier),
            Err(Hx512LifecycleError::Base64Rejected) | Err(Hx512LifecycleError::Base64NonCanonical)
        ));

        let mut wrong_identity = fixture_identity();
        wrong_identity[122] ^= 1;
        let wrong_binding = Hx512LifecycleBinding::new(wrong_identity, 64).unwrap();
        let (raw_action, verifier) = fixture(0x0c, 2);
        assert!(matches!(
            decode_hx512_block_seam(raw_action, wrong_binding, &verifier),
            Err(Hx512LifecycleError::Transport(
                Hx512InlineTransportError::IdentityMismatch { .. }
            ))
        ));
    }

    #[test]
    fn every_native_and_release_authority_remains_false() {
        let identity = project_hx512_inline_identity(&fixture_identity());
        assert!(!native_submit_action_route_supported(
            identity.family_id,
            identity.action_id
        ));
        assert!(super::super::ensure_native_v3_active_action_route_ids(
            identity.family_id,
            identity.action_id,
            false,
        )
        .is_err());
        assert!(!HX512_INLINE_PRODUCTION_ADMISSION_ENABLED);
        assert!(!HX512_INLINE_SIDECAR_VALIDITY_ALLOWED);
        assert!(!HX512_INLINE_AGGREGATE_VALIDITY_ALLOWED);
        assert!(!HX512_INLINE_RECEIPT_VALIDITY_ALLOWED);
        assert!(!HX512_INLINE_CACHE_VALIDITY_ALLOWED);
        assert!(!wallet::hx512_lifecycle::HX512_WALLET_ROUTE_ALLOCATED);
        assert!(!wallet::hx512_lifecycle::HX512_WALLET_PRODUCTION_SUBMISSION_ENABLED);
        assert!(!wallet::hx512_lifecycle::HX512_WALLET_LEGACY_ACTION_ID48_RESPONSE_ALLOWED);
        assert!(!HX512_NATIVE_IDENTITY_ALLOCATED);
        assert!(!HX512_NATIVE_RPC_ROUTE_REGISTERED);
        assert!(!HX512_NATIVE_PEER_RELAY_ENABLED);
        assert!(!HX512_NATIVE_DURABLE_MEMPOOL_ENABLED);
        assert!(!HX512_NATIVE_MINING_ENABLED);
        assert!(!HX512_NATIVE_BLOCK_IMPORT_ENABLED);
        assert!(!HX512_NATIVE_SYNC_ENABLED);
        assert!(!HX512_NATIVE_REORG_ENABLED);
        assert!(!HX512_NATIVE_FRESH_NODE_ENABLED);
        assert!(!HX512_NATIVE_RELATION_REFINEMENT_COMPLETE);
        assert!(!HX512_NATIVE_COMPLETE_ZK_AUTHORIZED);
        assert!(!HX512_NATIVE_COMPOSED_PQ128_AUTHORIZED);
        assert!(!HX512_NATIVE_RETAINED_ARTIFACTS_AUTHORIZED);
        assert!(!HX512_NATIVE_RELEASE_MANIFEST_AUTHORIZED);
        assert!(!HX512_NATIVE_PRODUCTION_ENABLED);
        assert!(matches!(
            ensure_hx512_production_authority(),
            Err(Hx512LifecycleError::ProductionInactive(_))
        ));
    }
}
