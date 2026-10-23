//! Durable wallet mirror for canonical SmallWood/Poseidon2 V8 block actions.
//!
//! The V8 lane has seven-limb commitments, roots, and nullifiers.  None of
//! these values are projected through the historical 48-byte wallet tree.

#![forbid(unsafe_code)]

use codec::{Decode, DecodeWithMemLimit, DecodeWithMemTracking, Encode};
use hegemon_hash384::{blake2b_384_domain_hash, domains};
use protocol_shielded_pool::{
    family::{
        ACTION_MINT_POSEIDON2_V8_COINBASE, ACTION_MINT_POSEIDON2_V8_REWARDS,
        ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE, FAMILY_SHIELDED_POOL,
    },
    poseidon2_production_transport::{
        decode_poseidon2_production_smz9_inline_args_exact,
        decode_poseidon2_production_smza_inline_args_exact, DecodedPoseidon2ProductionInlineArgs,
        Poseidon2ProductionExpectedContext, POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES,
        POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID, POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES,
        POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
        POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID, POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID,
        POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID, POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET,
        POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID,
    },
    poseidon2_v8_coinbase::{
        MintPoseidon2V8CoinbaseArgs, MintPoseidon2V8RewardsArgs, Poseidon2V8CoinbaseNoteData,
        POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES, POSEIDON2_V8_REWARDS_MAX_ARGS_SCALE_BYTES,
    },
    types::CandidateArtifact,
};
use serde::{Deserialize, Serialize};
use transaction_circuit::{
    constants::{FIELD_MODULUS_U64, MAX_IN_CIRCUIT_VALUE, NATIVE_ASSET_ID},
    hashing_pq::ciphertext_hash_bytes,
    smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_default_note_nodes, poseidon2_v8_note_commitment,
        poseidon2_v8_note_tree_compress, poseidon2_v8_words_from_canonical_bytes,
    },
    smallwood_poseidon2_v8_frontend::{
        SmallwoodPoseidon2V8SourceRelationFactory, SmallwoodPoseidon2V8VerifierRelationFactory,
    },
    smallwood_poseidon2_v8_hash_schedule::{
        build_smallwood_poseidon2_v8_hash_schedule, SmallwoodPoseidon2V8HashCallRole,
    },
    smallwood_poseidon2_v8_types::{
        SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8InputWitness,
        SmallwoodPoseidon2V8NoteOpening, SmallwoodPoseidon2V8PublicStatement,
        SmallwoodPoseidon2V8Witness, SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH,
    },
};

use crate::{
    error::WalletError, keys::DerivedKeys, notes::NoteCiphertext,
    poseidon2_v8_coinbase::protocol_opening_to_relation,
};

pub(crate) const RECOVERY_SPEND_ACTION_ID: u16 = 18;
pub(crate) const RECOVERY_ADMIN_ACTION_ID: u16 = 19;

const MAX_CANONICAL_ACTION_BYTES: usize = 8 * 1024 * 1024;
const NOTE_OPENING_WORDS: usize = 18;
const POSEIDON2_V8_NOTE_ROOT_HISTORY_LIMIT: usize = 100;
const POSEIDON2_V8_DEFAULT_REPLAY_REQUIRED: &str =
    "V8 wallet mirror uses an incompatible legacy note-tree default; reset wallet sync state and replay from genesis";
const PRODUCTION_DISABLED: &str = "SmallWood Poseidon2 V8 production capability is disabled";
const POSEIDON2_V8_MAX_FIELD_SCALAR_HEIGHT: u64 = (1u64 << 63) - 1;

/// An exact source-owned route, never inferred from an untrusted proof header.
/// Sync and submission consume the same profile/domain selection and caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalletProofRoute {
    Smz9,
    Smza,
}

impl WalletProofRoute {
    /// Framing alone grants no authorization; submission also checks height
    /// and the complete source capability through the selection below.
    #[cfg(feature = "rpc-client")]
    pub(crate) fn source_framing() -> Result<Self, WalletError> {
        let capability = protocol_versioning::smallwood_poseidon2_production_capability()
            .ok_or(WalletError::InvalidState(PRODUCTION_DISABLED))?;
        Self::from_source_tuple(capability.proof_profile_id(), capability.domain_set())
    }

    fn from_source_tuple(profile: u8, domain: u16) -> Result<Self, WalletError> {
        match (profile, domain) {
            (POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID, POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET) => Ok(Self::Smz9),
            (POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID, POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET) => Ok(Self::Smza),
            _ => Err(WalletError::InvalidState("SmallWood Poseidon2 V8 production capability has an unsupported profile/domain tuple")),
        }
    }

    pub(crate) fn max_inline_args_bytes(self) -> usize {
        match self {
            Self::Smz9 => transaction_circuit::smallwood_poseidon2_v8_security::SMALLWOOD_POSEIDON2_V8_MAX_ACTION_BYTES as usize,
            Self::Smza => POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES,
        }
    }

    fn decode_inline_args_exact<'a>(
        self,
        expected: Poseidon2ProductionExpectedContext,
        encoded: &'a [u8],
    ) -> Result<DecodedPoseidon2ProductionInlineArgs<'a>, WalletError> {
        if encoded.len() > self.max_inline_args_bytes() {
            return Err(WalletError::Serialization(
                "V8 transfer action exceeds selected profile limit".into(),
            ));
        }
        let decode = match self {
            Self::Smz9 => decode_poseidon2_production_smz9_inline_args_exact,
            Self::Smza => decode_poseidon2_production_smza_inline_args_exact,
        };
        decode(expected, encoded).map_err(|error| {
            WalletError::Serialization(format!("decode V8 transfer action: {error}"))
        })
    }
}

pub(crate) fn poseidon2_v8_production_selection_at(
    height: u64,
) -> Result<(Poseidon2ProductionExpectedContext, WalletProofRoute), WalletError> {
    let capability = protocol_versioning::smallwood_poseidon2_production_capability()
        .ok_or(WalletError::InvalidState(PRODUCTION_DISABLED))?;
    let source_digest = *SmallwoodPoseidon2V8SourceRelationFactory.expected_relation_digest();
    if !capability.active_at(height)
        || capability.binding()
            != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING
        || capability.network_id() != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID
        || capability.relation_digest() != source_digest
        || capability.family_id() != POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID
        || capability.action_id() != POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID
        || capability.backend_id() != POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID
        || capability.activation_height() > POSEIDON2_V8_MAX_FIELD_SCALAR_HEIGHT
        || capability
            .stablecoin_genesis_root()
            .into_iter()
            .any(|limb| limb >= FIELD_MODULUS_U64)
        || capability
            .note_genesis_root()
            .into_iter()
            .any(|limb| limb >= FIELD_MODULUS_U64)
        || capability.note_genesis_root()
            != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NOTE_GENESIS_ROOT
    {
        return Err(WalletError::InvalidState(
            "SmallWood Poseidon2 V8 production capability tuple is invalid or inactive",
        ));
    }
    let route = WalletProofRoute::from_source_tuple(
        capability.proof_profile_id(),
        capability.domain_set(),
    )?;
    Poseidon2ProductionExpectedContext::new(capability.network_id(), source_digest)
        .map(|context| (context, route))
        .map_err(|error| {
            WalletError::Serialization(format!(
                "SmallWood Poseidon2 V8 production context rejected: {error}"
            ))
        })
}

pub type Poseidon2V8Digest = SmallwoodPoseidon2V8Digest;
pub type Poseidon2V8Path = [Poseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH];

#[path = "poseidon2_v8_launch_sync.rs"]
pub(crate) mod launch_sync;
pub use launch_sync::LaunchWalletContext;
pub use launch_sync::{
    encode_private_spend_candidate_action, project_private_spend_candidate_action,
};

/// Explicit local rehearsal context. This is absent from ordinary builds,
/// does not install release authority, and cannot alter production resolution.
/// Retained block actions must already have been verified by the test node;
/// the wallet mirror checks their canonical framing and state projections.
#[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
#[derive(Clone, Copy, Debug)]
pub struct Poseidon2V8RetainedTestContext {
    expected: Poseidon2ProductionExpectedContext,
    route: WalletProofRoute,
    genesis_hash: [u8; 32],
    stablecoin_genesis_root: Poseidon2V8Digest,
    activation_height: u64,
    deactivation_height_exclusive: u64,
}

#[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
impl Poseidon2V8RetainedTestContext {
    pub fn new(
        expected: Poseidon2ProductionExpectedContext,
        proof_profile_id: u8,
        domain_set: u16,
        genesis_hash: [u8; 32],
        stablecoin_genesis_root: Poseidon2V8Digest,
        activation_height: u64,
        deactivation_height_exclusive: u64,
    ) -> Result<Self, WalletError> {
        let route = WalletProofRoute::from_source_tuple(proof_profile_id, domain_set)?;
        if expected.network_id() != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID
            || expected.relation_digest()
                != *SmallwoodPoseidon2V8SourceRelationFactory.expected_relation_digest()
            || genesis_hash == [0; 32]
            || activation_height >= deactivation_height_exclusive
            || deactivation_height_exclusive > POSEIDON2_V8_MAX_FIELD_SCALAR_HEIGHT
        {
            return Err(WalletError::InvalidState(
                "invalid V8 retained-test context",
            ));
        }
        ensure_digest(
            "V8 retained-test stablecoin genesis root",
            stablecoin_genesis_root,
        )?;
        Ok(Self {
            expected,
            route,
            genesis_hash,
            stablecoin_genesis_root,
            activation_height,
            deactivation_height_exclusive,
        })
    }
}

/// One canonical native block body fetched by hash from `chain_getBlock`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2V8CanonicalBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub action_bytes: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poseidon2V8CanonicalTip {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub anchor: Poseidon2V8Digest,
    pub stablecoin_root: Option<Poseidon2V8Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2V8OwnedNoteView {
    pub opening: SmallwoodPoseidon2V8NoteOpening,
    pub commitment: Poseidon2V8Digest,
    pub position: u64,
    pub path: Poseidon2V8Path,
    pub anchor: Poseidon2V8Digest,
    pub diversifier_index: u32,
    pub nullifier: Poseidon2V8Digest,
    pub spent: bool,
    pub created_height: u64,
    pub created_block_hash: [u8; 32],
}

/// A public commitment and its membership witness at one exact canonical
/// position. It gives membership evidence only, never spending authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2V8CanonicalNoteWitness {
    pub commitment: Poseidon2V8Digest,
    pub position: u64,
    pub path: Poseidon2V8Path,
    pub anchor: Poseidon2V8Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2V8SpendContext {
    pub tip: Poseidon2V8CanonicalTip,
    pub notes: [Poseidon2V8OwnedNoteView; 2],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Poseidon2V8SyncDelta {
    pub commitments: usize,
    pub ciphertexts: usize,
    pub recovered: usize,
    pub spent: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Poseidon2V8WalletState {
    genesis_hash: Option<[u8; 32]>,
    /// Level zero is the ordered commitment sequence. Higher levels are the
    /// current default-padded subtree roots, updated in O(depth) per append.
    tree_levels: Vec<Vec<Poseidon2V8Digest>>,
    /// Every distinct append root, including the empty root. Consensus anchor
    /// acceptance is the last 100 entries; retaining the log permits exact
    /// history restoration when a reorg reveals previously evicted roots.
    root_log: Vec<Poseidon2V8Digest>,
    stablecoin_root: Option<Poseidon2V8Digest>,
    owned_notes: Vec<StoredPoseidon2V8OwnedNote>,
    nullifiers: Vec<StoredPoseidon2V8Nullifier>,
    blocks: Vec<StoredPoseidon2V8Block>,
    /// Bounded reward queue, separate from spendable Merkle-tree leaves.
    pending_rewards: Vec<StoredPoseidon2V8PendingReward>,
    maturity_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPoseidon2V8PendingReward {
    created_height: u64,
    created_block_hash: [u8; 32],
    notes: Vec<StoredPoseidon2V8PendingRewardNote>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPoseidon2V8PendingRewardNote {
    commitment: Poseidon2V8Digest,
    owned_opening: Option<([u64; NOTE_OPENING_WORDS], u32)>,
}

impl StoredPoseidon2V8PendingReward {
    fn release_height(&self) -> Result<u64, WalletError> {
        self.created_height
            .checked_add(protocol_versioning::COINBASE_MATURITY - 1)
            .ok_or(WalletError::InvalidState(
                "V8 reward maturity height overflow",
            ))
    }

    fn validate(&self, mirror: &Poseidon2V8WalletState) -> Result<(), WalletError> {
        if self.created_height == 0
            || self.created_block_hash == [0; 32]
            || mirror.canonical_hash(self.created_height) != Some(self.created_block_hash)
            || self.notes.is_empty()
            || self.notes.len() > 2
        {
            return Err(WalletError::InvalidState(
                "invalid V8 reward origin or note count",
            ));
        }
        for (index, note) in self.notes.iter().enumerate() {
            ensure_digest("queued V8 reward commitment", note.commitment)?;
            if self.notes[..index]
                .iter()
                .any(|prior| prior.commitment == note.commitment)
            {
                return Err(WalletError::InvalidState("duplicate V8 reward commitment"));
            }
            if let Some((opening, _)) = note.owned_opening {
                if poseidon2_v8_note_commitment(words_to_opening(opening)?)
                    .map_err(|_| WalletError::InvalidState("invalid queued V8 opening"))?
                    != note.commitment
                {
                    return Err(WalletError::InvalidState(
                        "queued V8 reward opening mismatch",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPoseidon2V8OwnedNote {
    opening_words: [u64; NOTE_OPENING_WORDS],
    commitment: Poseidon2V8Digest,
    position: u64,
    diversifier_index: u32,
    nullifier: Poseidon2V8Digest,
    spent_by: Option<[u8; 32]>,
    created_height: u64,
    created_block_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPoseidon2V8Nullifier {
    value: Poseidon2V8Digest,
    block_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPoseidon2V8Block {
    height: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    leaf_count_before: u64,
    root_log_len_before: u64,
    root_after: Poseidon2V8Digest,
    stablecoin_root_before: Option<Poseidon2V8Digest>,
    stablecoin_root_after: Option<Poseidon2V8Digest>,
    introduced_nullifiers: Vec<Poseidon2V8Digest>,
    /// Exact rows removed from the queue by this block, restored on rollback.
    released_rewards: Vec<StoredPoseidon2V8PendingReward>,
}

/// Frozen mirror shape embedded in wallet V11..V17. Never deserialize an old
/// positional payload as the maturity-aware mirror.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Poseidon2V8WalletStateV17 {
    genesis_hash: Option<[u8; 32]>,
    tree_levels: Vec<Vec<Poseidon2V8Digest>>,
    root_log: Vec<Poseidon2V8Digest>,
    stablecoin_root: Option<Poseidon2V8Digest>,
    owned_notes: Vec<StoredPoseidon2V8OwnedNote>,
    nullifiers: Vec<StoredPoseidon2V8Nullifier>,
    blocks: Vec<StoredPoseidon2V8BlockV17>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPoseidon2V8BlockV17 {
    height: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    leaf_count_before: u64,
    root_log_len_before: u64,
    root_after: Poseidon2V8Digest,
    stablecoin_root_before: Option<Poseidon2V8Digest>,
    stablecoin_root_after: Option<Poseidon2V8Digest>,
    introduced_nullifiers: Vec<Poseidon2V8Digest>,
}

impl Poseidon2V8WalletStateV17 {
    /// This conversion grants read-only historical inspection, never permission
    /// to extend the old mirror under the new reward policy.
    pub(crate) fn into_legacy_read_only(self) -> Result<Poseidon2V8WalletState, WalletError> {
        let mirror = Poseidon2V8WalletState {
            genesis_hash: self.genesis_hash,
            tree_levels: self.tree_levels,
            root_log: self.root_log,
            stablecoin_root: self.stablecoin_root,
            owned_notes: self.owned_notes,
            nullifiers: self.nullifiers,
            blocks: self
                .blocks
                .into_iter()
                .map(|block| StoredPoseidon2V8Block {
                    height: block.height,
                    block_hash: block.block_hash,
                    parent_hash: block.parent_hash,
                    leaf_count_before: block.leaf_count_before,
                    root_log_len_before: block.root_log_len_before,
                    root_after: block.root_after,
                    stablecoin_root_before: block.stablecoin_root_before,
                    stablecoin_root_after: block.stablecoin_root_after,
                    introduced_nullifiers: block.introduced_nullifiers,
                    released_rewards: Vec::new(),
                })
                .collect(),
            pending_rewards: Vec::new(),
            maturity_blocks: 0,
        };
        mirror.validate_legacy_read_only()?;
        Ok(mirror)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
struct PendingVersionBinding {
    circuit: u16,
    crypto: u16,
}

impl From<protocol_versioning::VersionBinding> for PendingVersionBinding {
    fn from(value: protocol_versioning::VersionBinding) -> Self {
        Self {
            circuit: value.circuit,
            crypto: value.crypto,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
struct PendingActionWire {
    tx_hash: [u8; 48],
    binding: PendingVersionBinding,
    family_id: u16,
    action_id: u16,
    anchor: [u8; 48],
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: Vec<[u8; 48]>,
    ciphertext_sizes: Vec<u32>,
    public_args: Vec<u8>,
    fee: u64,
    candidate_artifact: Option<CandidateArtifact>,
}

#[derive(Encode)]
struct PendingActionIdentityBody<'a> {
    binding: &'a PendingVersionBinding,
    family_id: u16,
    action_id: u16,
    anchor: &'a [u8; 48],
    nullifiers: &'a Vec<[u8; 48]>,
    commitments: &'a Vec<[u8; 48]>,
    ciphertext_hashes: &'a Vec<[u8; 48]>,
    ciphertext_sizes: &'a Vec<u32>,
    public_args: &'a Vec<u8>,
    fee: u64,
    candidate_artifact: &'a Option<CandidateArtifact>,
}

enum DecodedPoseidon2V8Action {
    Launch(launch_sync::LaunchProjection),
    AssetSpend(transaction_circuit::asset_spend_v1::AssetSpendPublic),
    AssetAdmin,
    Transfer {
        statement: SmallwoodPoseidon2V8PublicStatement,
        ciphertexts: [Option<[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]>; 2],
    },
    Coinbase(Vec<Poseidon2V8CoinbaseNoteData>),
}

impl Poseidon2V8WalletState {
    /// Encode only mirrors representable by the frozen pre-maturity schema.
    /// Used by legacy read-only recovery and exact historical-codec tests.
    pub(crate) fn to_legacy_v17(&self) -> Result<Poseidon2V8WalletStateV17, WalletError> {
        if !self.pending_rewards.is_empty()
            || self
                .blocks
                .iter()
                .any(|block| !block.released_rewards.is_empty())
        {
            return Err(WalletError::InvalidState(
                "maturity-aware mirror cannot be encoded as legacy V17",
            ));
        }
        Ok(Poseidon2V8WalletStateV17 {
            genesis_hash: self.genesis_hash,
            tree_levels: self.tree_levels.clone(),
            root_log: self.root_log.clone(),
            stablecoin_root: self.stablecoin_root,
            owned_notes: self.owned_notes.clone(),
            nullifiers: self.nullifiers.clone(),
            blocks: self
                .blocks
                .iter()
                .map(|block| StoredPoseidon2V8BlockV17 {
                    height: block.height,
                    block_hash: block.block_hash,
                    parent_hash: block.parent_hash,
                    leaf_count_before: block.leaf_count_before,
                    root_log_len_before: block.root_log_len_before,
                    root_after: block.root_after,
                    stablecoin_root_before: block.stablecoin_root_before,
                    stablecoin_root_after: block.stablecoin_root_after,
                    introduced_nullifiers: block.introduced_nullifiers.clone(),
                })
                .collect(),
        })
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn ensure_genesis(&mut self, genesis_hash: [u8; 32]) -> Result<(), WalletError> {
        match self.genesis_hash {
            None => {
                let stablecoin_root = production_stablecoin_genesis(genesis_hash)?;
                self.maturity_blocks = protocol_versioning::COINBASE_MATURITY;
                self.genesis_hash = Some(genesis_hash);
                self.tree_levels = empty_tree_levels();
                self.root_log = vec![empty_note_root()];
                self.stablecoin_root = stablecoin_root;
                Ok(())
            }
            Some(existing) if existing == genesis_hash => self.validate(),
            Some(_) => Err(WalletError::InvalidState(
                "V8 wallet mirror genesis mismatch",
            )),
        }
    }

    pub(crate) fn ensure_launch_genesis(
        &mut self,
        genesis_hash: [u8; 32],
        stablecoin_root: Poseidon2V8Digest,
        note_root: Poseidon2V8Digest,
    ) -> Result<(), WalletError> {
        ensure_digest("launch stablecoin genesis root", stablecoin_root)?;
        if note_root != empty_note_root() || genesis_hash == [0; 32] {
            return Err(WalletError::InvalidState(
                "launch genesis requires canonical empty note tree",
            ));
        }
        match self.genesis_hash {
            None => {
                if !self.blocks.is_empty() || !self.root_log.is_empty() {
                    return Err(WalletError::InvalidState(
                        "launch genesis mirror is not pristine",
                    ));
                }
                self.genesis_hash = Some(genesis_hash);
                self.tree_levels = empty_tree_levels();
                self.root_log = vec![note_root];
                self.stablecoin_root = Some(stablecoin_root);
                self.maturity_blocks = protocol_versioning::COINBASE_MATURITY;
            }
            Some(existing) if existing == genesis_hash => {
                let original_stable = self
                    .blocks
                    .first()
                    .map(|block| block.stablecoin_root_before)
                    .unwrap_or(self.stablecoin_root);
                if self.root_log.first() != Some(&note_root)
                    || original_stable != Some(stablecoin_root)
                {
                    return Err(WalletError::InvalidState(
                        "launch genesis roots differ from pinned mirror",
                    ));
                }
            }
            Some(_) => {
                return Err(WalletError::InvalidState(
                    "launch wallet mirror genesis mismatch",
                ))
            }
        }
        self.validate()
    }

    #[cfg(test)]
    pub(crate) fn ensure_genesis_for_test(
        &mut self,
        genesis_hash: [u8; 32],
        stablecoin_root: Poseidon2V8Digest,
    ) -> Result<(), WalletError> {
        ensure_digest("V8 stablecoin test genesis root", stablecoin_root)?;
        self.ensure_genesis(genesis_hash)?;
        if !self.blocks.is_empty() {
            return Err(WalletError::InvalidState(
                "cannot replace V8 stablecoin test root after sync",
            ));
        }
        self.stablecoin_root = Some(stablecoin_root);
        Ok(())
    }

    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub(crate) fn ensure_genesis_for_retained_test(
        &mut self,
        context: Poseidon2V8RetainedTestContext,
    ) -> Result<(), WalletError> {
        self.ensure_genesis(context.genesis_hash)?;
        if self.blocks.is_empty() {
            if self.stablecoin_root.is_some()
                && self.stablecoin_root != Some(context.stablecoin_genesis_root)
            {
                return Err(WalletError::InvalidState(
                    "V8 retained-test genesis root mismatch",
                ));
            }
            self.stablecoin_root = Some(context.stablecoin_genesis_root);
        } else if self.blocks[0].stablecoin_root_before != Some(context.stablecoin_genesis_root) {
            return Err(WalletError::InvalidState(
                "V8 retained-test genesis root mismatch",
            ));
        }
        self.validate()
    }

    pub(crate) fn tip(&self) -> Result<Poseidon2V8CanonicalTip, WalletError> {
        let genesis = self.genesis_hash.ok_or(WalletError::InvalidState(
            "V8 wallet mirror is not initialized",
        ))?;
        self.validate_default_root()?;
        Ok(match self.blocks.last() {
            Some(block) => Poseidon2V8CanonicalTip {
                height: block.height,
                block_hash: block.block_hash,
                anchor: block.root_after,
                stablecoin_root: block.stablecoin_root_after,
            },
            None => Poseidon2V8CanonicalTip {
                height: 0,
                block_hash: genesis,
                anchor: empty_note_root(),
                stablecoin_root: self.stablecoin_root,
            },
        })
    }

    pub(crate) fn canonical_hash(&self, height: u64) -> Option<[u8; 32]> {
        if height == 0 {
            return self.genesis_hash;
        }
        self.blocks
            .get(usize::try_from(height.checked_sub(1)?).ok()?)
            .filter(|block| block.height == height)
            .map(|block| block.block_hash)
    }

    pub(crate) fn canonical_tip_at_height(&self, height: u64) -> Option<Poseidon2V8CanonicalTip> {
        if height == 0 {
            return Some(Poseidon2V8CanonicalTip {
                height: 0,
                block_hash: self.genesis_hash?,
                anchor: empty_note_root(),
                stablecoin_root: self
                    .blocks
                    .first()
                    .map(|block| block.stablecoin_root_before)
                    .unwrap_or(self.stablecoin_root),
            });
        }
        let block = self
            .blocks
            .get(usize::try_from(height.checked_sub(1)?).ok()?)?;
        if block.height != height {
            return None;
        }
        Some(Poseidon2V8CanonicalTip {
            height,
            block_hash: block.block_hash,
            anchor: block.root_after,
            stablecoin_root: block.stablecoin_root_after,
        })
    }

    /// Membership from the trusted full-node mirror, including policy-owned notes.
    pub(crate) fn canonical_note_path(
        &self,
        commitment: Poseidon2V8Digest,
        position: u64,
    ) -> Result<Poseidon2V8Path, WalletError> {
        self.validate_default_root()?;
        if self.tree_levels.first().and_then(|level| {
            usize::try_from(position)
                .ok()
                .and_then(|position| level.get(position))
        }) != Some(&commitment)
        {
            return Err(WalletError::InvalidState(
                "policy note absent from canonical mirror",
            ));
        }
        note_path_from_levels(&self.tree_levels, position)
    }

    pub(crate) fn owned_notes(&self) -> Result<Vec<Poseidon2V8OwnedNoteView>, WalletError> {
        self.validate_default_root()?;
        let anchor = current_note_root(&self.tree_levels)?;
        self.owned_notes
            .iter()
            .map(|note| {
                let path = note_path_from_levels(&self.tree_levels, note.position)?;
                stored_note_view(note, path, anchor)
            })
            .collect()
    }

    pub(crate) fn canonical_note_witness(
        &self,
        commitment: Poseidon2V8Digest,
    ) -> Result<Option<Poseidon2V8CanonicalNoteWitness>, WalletError> {
        self.validate_default_root()?;
        let leaves = self
            .tree_levels
            .first()
            .ok_or(WalletError::InvalidState("V8 commitment level missing"))?;
        let mut matching = leaves
            .iter()
            .enumerate()
            .filter(|(_, candidate)| **candidate == commitment);
        let Some((position, _)) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            return Err(WalletError::InvalidState(
                "V8 commitment has multiple canonical positions; select an exact position",
            ));
        }
        self.canonical_note_witness_at(commitment, position as u64)
    }

    /// Return every exact position occupied by a public commitment in the
    /// authenticated canonical mirror. Duplicate notes are deliberately not
    /// collapsed: callers that require one position must reject ambiguity.
    pub(crate) fn canonical_commitment_positions(
        &self,
        commitment: Poseidon2V8Digest,
    ) -> Result<Vec<u64>, WalletError> {
        self.validate_default_root()?;
        let leaves = self
            .tree_levels
            .first()
            .ok_or(WalletError::InvalidState("V8 commitment level missing"))?;
        leaves
            .iter()
            .enumerate()
            .filter_map(|(position, candidate)| (*candidate == commitment).then_some(position))
            .map(|position| {
                u64::try_from(position)
                    .map_err(|_| WalletError::InvalidState("V8 note position overflow"))
            })
            .collect()
    }

    pub(crate) fn canonical_note_witness_at(
        &self,
        commitment: Poseidon2V8Digest,
        position: u64,
    ) -> Result<Option<Poseidon2V8CanonicalNoteWitness>, WalletError> {
        self.validate_default_root()?;
        let position_index = usize::try_from(position)
            .map_err(|_| WalletError::InvalidState("V8 note position overflow"))?;
        if self
            .tree_levels
            .first()
            .and_then(|leaves| leaves.get(position_index))
            != Some(&commitment)
        {
            return Ok(None);
        }
        Ok(Some(Poseidon2V8CanonicalNoteWitness {
            commitment,
            position,
            path: note_path_from_levels(&self.tree_levels, position)?,
            anchor: current_note_root(&self.tree_levels)?,
        }))
    }

    pub(crate) fn has_canonical_nullifier(&self, value: Poseidon2V8Digest) -> bool {
        self.nullifiers.iter().any(|entry| entry.value == value)
    }

    pub(crate) fn spend_context(
        &self,
        reserved: &std::collections::HashSet<Poseidon2V8Digest>,
    ) -> Result<Poseidon2V8SpendContext, WalletError> {
        let tip = self.tip()?;
        let notes = self
            .owned_notes
            .iter()
            .filter(|note| note.spent_by.is_none() && !reserved.contains(&note.nullifier))
            .map(|note| {
                let path = note_path_from_levels(&self.tree_levels, note.position)?;
                stored_note_view(note, path, tip.anchor)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if notes.len() < 2 {
            return Err(WalletError::InsufficientFunds {
                needed: 2,
                available: notes.len() as u64,
            });
        }
        Ok(Poseidon2V8SpendContext {
            tip,
            notes: [notes[0].clone(), notes[1].clone()],
        })
    }

    pub(crate) fn rollback_to(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<(), WalletError> {
        self.validate_default_root()?;
        if self.canonical_hash(height) != Some(block_hash) {
            return Err(WalletError::InvalidState(
                "V8 rollback target is not canonical",
            ));
        }
        while self
            .blocks
            .last()
            .is_some_and(|block| block.height > height)
        {
            let detached = self
                .blocks
                .pop()
                .ok_or(WalletError::InvalidState("V8 rollback block missing"))?;
            if self.root_log.last().copied() != Some(detached.root_after)
                || self.stablecoin_root != detached.stablecoin_root_after
            {
                return Err(WalletError::InvalidState(
                    "V8 rollback journal does not match the mirror tip",
                ));
            }
            let expected_len = usize::try_from(detached.leaf_count_before)
                .map_err(|_| WalletError::InvalidState("V8 rollback leaf count overflow"))?;
            let commitments = self
                .tree_levels
                .first_mut()
                .ok_or(WalletError::InvalidState("V8 commitment level missing"))?;
            if expected_len > commitments.len() {
                return Err(WalletError::InvalidState(
                    "V8 rollback leaf count exceeds mirror",
                ));
            }
            commitments.truncate(expected_len);
            let expected_root_log_len = usize::try_from(detached.root_log_len_before)
                .map_err(|_| WalletError::InvalidState("V8 root log length overflow"))?;
            if expected_root_log_len == 0 || expected_root_log_len > self.root_log.len() {
                return Err(WalletError::InvalidState(
                    "V8 rollback root log length exceeds mirror",
                ));
            }
            self.root_log.truncate(expected_root_log_len);
            self.stablecoin_root = detached.stablecoin_root_before;
            // An owned reward retains its origin hash. Its later insertion is
            // undone by the release block's exact leaf-count boundary.
            self.owned_notes
                .retain(|note| note.position < detached.leaf_count_before);
            // Restore rows drained by this release block before the younger
            // queue, then remove rewards whose origin was itself detached.
            let mut restored = detached.released_rewards;
            restored.append(&mut self.pending_rewards);
            restored.retain(|reward| reward.created_height < detached.height);
            self.pending_rewards = restored;
            for note in &mut self.owned_notes {
                if note.spent_by == Some(detached.block_hash) {
                    note.spent_by = None;
                }
            }
            self.nullifiers
                .retain(|entry| entry.block_hash != detached.block_hash);
        }
        let commitments = self
            .tree_levels
            .first()
            .cloned()
            .ok_or(WalletError::InvalidState("V8 commitment level missing"))?;
        let expected_root_log = self.root_log.clone();
        let (tree_levels, root_log) = rebuild_note_tree(&commitments)?;
        if root_log != expected_root_log {
            return Err(WalletError::InvalidState(
                "V8 rollback root history does not match commitments",
            ));
        }
        self.tree_levels = tree_levels;
        let tip = self.tip()?;
        if tip.height != height || tip.block_hash != block_hash {
            return Err(WalletError::InvalidState("V8 rollback target mismatch"));
        }
        self.validate()
    }

    pub(crate) fn apply_block(
        &mut self,
        block: &Poseidon2V8CanonicalBlock,
        keys: Option<&DerivedKeys>,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        self.apply_block_with_transfer_decoder(block, keys, |wire| {
            let (expected, route) = poseidon2_v8_production_selection_at(block.height)?;
            decode_v8_transfer(wire, expected, route)
        })
    }

    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub(crate) fn apply_block_for_retained_test(
        &mut self,
        block: &Poseidon2V8CanonicalBlock,
        keys: Option<&DerivedKeys>,
        context: Poseidon2V8RetainedTestContext,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        if self.genesis_hash != Some(context.genesis_hash)
            || block.height < context.activation_height
            || block.height >= context.deactivation_height_exclusive
            || self
                .blocks
                .first()
                .map_or(self.stablecoin_root, |first| first.stablecoin_root_before)
                != Some(context.stablecoin_genesis_root)
        {
            return Err(WalletError::InvalidState(
                "V8 block is outside the retained-test context",
            ));
        }
        self.apply_block_with_transfer_decoder(block, keys, |wire| {
            decode_v8_transfer(wire, context.expected, context.route)
        })
    }

    fn apply_block_with_transfer_decoder(
        &mut self,
        block: &Poseidon2V8CanonicalBlock,
        keys: Option<&DerivedKeys>,
        decode_transfer: impl Fn(PendingActionWire) -> Result<DecodedPoseidon2V8Action, WalletError>,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        if self.maturity_blocks != protocol_versioning::COINBASE_MATURITY {
            return Err(WalletError::InvalidState(
                "legacy V8 reward policy cannot extend the new chain",
            ));
        }
        let tip = self.tip()?;
        let expected_height = tip
            .height
            .checked_add(1)
            .ok_or(WalletError::InvalidState("V8 block height overflow"))?;
        if block.height != expected_height || block.parent_hash != tip.block_hash {
            return Err(WalletError::InvalidState(
                "V8 block does not extend the wallet mirror tip",
            ));
        }
        if block.hash == [0; 32] {
            return Err(WalletError::InvalidState("zero V8 canonical block hash"));
        }

        let leaf_count_before = u64::try_from(commitment_count(&self.tree_levels)?)
            .map_err(|_| WalletError::InvalidState("V8 leaf count overflow"))?;
        let root_log_len_before = u64::try_from(self.root_log.len())
            .map_err(|_| WalletError::InvalidState("V8 root log length overflow"))?;
        let stablecoin_root_before = self.stablecoin_root;
        let pre_block_note_roots = accepted_note_roots(&self.root_log);
        let mut delta = Poseidon2V8SyncDelta::default();
        let mut introduced_nullifiers = Vec::new();
        for encoded in &block.action_bytes {
            let Some(action) = decode_v8_action_exact(encoded, &decode_transfer)? else {
                continue;
            };
            match action {
                DecodedPoseidon2V8Action::AssetAdmin => {}
                DecodedPoseidon2V8Action::AssetSpend(public) => {
                    // The source decoder authenticates the original H-bound
                    // statement. Recheck H against this mirror's linked history,
                    // with the actual inclusion parent P (not the inclusion
                    // block P+1 or a later sync tip) determining eligibility.
                    crate::asset_spend_rpc::require_reference_window(
                        public.parent_height,
                        tip.height,
                    )?;
                    let reference = self.canonical_tip_at_height(public.parent_height).ok_or(
                        WalletError::InvalidState("asset shared-pool canonical reference absent"),
                    )?;
                    if public.reference_parent_hash != reference.block_hash
                        || public.note_root != reference.anchor
                    {
                        return Err(WalletError::InvalidState(
                            "asset shared-pool reference differs from canonical checkpoint",
                        ));
                    }
                    for nullifier in public.nullifiers {
                        if self.has_canonical_nullifier(nullifier) {
                            return Err(WalletError::InvalidState(
                                "asset nullifier already exists in shared pool",
                            ));
                        }
                        for note in self
                            .owned_notes
                            .iter_mut()
                            .filter(|n| n.nullifier == nullifier)
                        {
                            if note.spent_by.is_some() {
                                return Err(WalletError::InvalidState(
                                    "asset native input already spent",
                                ));
                            }
                            note.spent_by = Some(block.hash);
                            delta.spent = delta.spent.saturating_add(1);
                        }
                        self.nullifiers.push(StoredPoseidon2V8Nullifier {
                            value: nullifier,
                            block_hash: block.hash,
                        });
                        introduced_nullifiers.push(nullifier);
                    }
                    for commitment in public.commitments {
                        self.append_commitment(commitment)?;
                        delta.commitments = delta.commitments.saturating_add(1);
                        delta.ciphertexts = delta.ciphertexts.saturating_add(1);
                    }
                }
                DecodedPoseidon2V8Action::Launch(projection) => {
                    self.apply_launch_projection(
                        projection,
                        block,
                        keys,
                        &mut delta,
                        &mut introduced_nullifiers,
                    )?;
                }
                DecodedPoseidon2V8Action::Coinbase(notes) => {
                    if self
                        .pending_rewards
                        .last()
                        .is_some_and(|reward| reward.created_height >= block.height)
                    {
                        return Err(WalletError::InvalidState(
                            "duplicate V8 reward origin height",
                        ));
                    }
                    let mut pending = Vec::new();
                    for note in notes {
                        let owned_opening = keys
                            .map(|keys| recover_coinbase_note(&note, keys))
                            .transpose()?
                            .flatten()
                            .map(|(opening, index)| (opening_to_words(opening), index));
                        pending.push(StoredPoseidon2V8PendingRewardNote {
                            commitment: note.commitment,
                            owned_opening,
                        });
                        delta.ciphertexts = delta.ciphertexts.saturating_add(1);
                    }
                    self.pending_rewards.push(StoredPoseidon2V8PendingReward {
                        created_height: block.height,
                        created_block_hash: block.hash,
                        notes: pending,
                    });
                }
                DecodedPoseidon2V8Action::Transfer {
                    statement,
                    ciphertexts,
                } => {
                    if !pre_block_note_roots.contains(&statement.merkle_root) {
                        return Err(WalletError::InvalidState(
                            "V8 action references a noncanonical wallet anchor",
                        ));
                    }
                    if statement.stablecoin.parent_height != tip.height {
                        return Err(WalletError::InvalidState(
                            "V8 action parent height differs from canonical block parent",
                        ));
                    }
                    let current_stablecoin_root = self
                        .stablecoin_root
                        .ok_or(WalletError::InvalidState(
                        "V8 stablecoin genesis root is unavailable while capability is disabled",
                    ))?;
                    let observed_before = felt_digest_to_words(statement.stablecoin.before_root);
                    let observed_after = felt_digest_to_words(statement.stablecoin.after_root);
                    ensure_digest("V8 stablecoin before root", observed_before)?;
                    ensure_digest("V8 stablecoin after root", observed_after)?;
                    if observed_before != current_stablecoin_root {
                        return Err(WalletError::InvalidState(
                            "V8 stablecoin before root differs from canonical wallet state",
                        ));
                    }
                    for input in 0..2 {
                        if !statement.input_flags[input] {
                            continue;
                        }
                        let nullifier = statement.nullifiers[input];
                        if self.nullifiers.iter().any(|entry| entry.value == nullifier) {
                            return Err(WalletError::InvalidState(
                                "duplicate V8 nullifier in canonical mirror",
                            ));
                        }
                        if let Some(note) = self
                            .owned_notes
                            .iter_mut()
                            .find(|note| note.nullifier == nullifier)
                        {
                            if note.spent_by.is_some() {
                                return Err(WalletError::InvalidState(
                                    "owned V8 note was already spent",
                                ));
                            }
                            note.spent_by = Some(block.hash);
                            delta.spent = delta.spent.saturating_add(1);
                        }
                        self.nullifiers.push(StoredPoseidon2V8Nullifier {
                            value: nullifier,
                            block_hash: block.hash,
                        });
                        introduced_nullifiers.push(nullifier);
                    }
                    for output in 0..2 {
                        if !statement.output_flags[output] {
                            continue;
                        }
                        let commitment = statement.commitments[output];
                        let raw = ciphertexts[output].ok_or(WalletError::InvalidState(
                            "active V8 output has no ciphertext",
                        ))?;
                        let position = self.append_commitment(commitment)?;
                        delta.commitments = delta.commitments.saturating_add(1);
                        delta.ciphertexts = delta.ciphertexts.saturating_add(1);
                        if let Some(keys) = keys {
                            if let Some((opening, diversifier_index)) =
                                recover_transfer_note(&raw, commitment, keys)?
                            {
                                self.insert_owned_note_at(
                                    opening,
                                    commitment,
                                    diversifier_index,
                                    position,
                                    block,
                                    keys,
                                )?;
                                delta.recovered = delta.recovered.saturating_add(1);
                            }
                        }
                    }
                    self.stablecoin_root = Some(observed_after);
                }
            }
        }

        // The block's actions used only pre-block roots. Appending mature
        // rewards now exposes them first to the following block's proofs.
        let mut released_rewards = Vec::new();
        while self.pending_rewards.first().is_some_and(|reward| {
            reward
                .created_height
                .checked_add(protocol_versioning::COINBASE_MATURITY - 1)
                == Some(block.height)
        }) {
            let reward = self.pending_rewards.remove(0);
            for note in &reward.notes {
                let position = self.append_commitment(note.commitment)?;
                delta.commitments = delta.commitments.saturating_add(1);
                if let (Some(keys), Some((opening, index))) = (keys, note.owned_opening) {
                    self.insert_owned_note_with_origin(
                        words_to_opening(opening)?,
                        note.commitment,
                        index,
                        position,
                        reward.created_height,
                        reward.created_block_hash,
                        keys,
                    )?;
                    delta.recovered = delta.recovered.saturating_add(1);
                }
            }
            released_rewards.push(reward);
        }
        let root_after = current_note_root(&self.tree_levels)?;
        self.blocks.push(StoredPoseidon2V8Block {
            height: block.height,
            block_hash: block.hash,
            parent_hash: block.parent_hash,
            leaf_count_before,
            root_log_len_before,
            root_after,
            stablecoin_root_before,
            stablecoin_root_after: self.stablecoin_root,
            introduced_nullifiers,
            released_rewards,
        });
        self.validate_tip()?;
        Ok(delta)
    }

    /// Journal unit fixture only: creates one validated canonical CM occurrence
    /// after an empty block. This is NOT a block/proof acceptance or authority API.
    #[cfg(test)]
    pub(crate) fn append_journal_test_commitment(
        &mut self,
        block: &Poseidon2V8CanonicalBlock,
        commitment: Poseidon2V8Digest,
    ) -> Result<u64, WalletError> {
        if !block.action_bytes.is_empty() {
            return Err(WalletError::InvalidState(
                "journal fixture requires empty block",
            ));
        }
        self.apply_block(block, None)?;
        let position = self.append_commitment(commitment)?;
        let root = current_note_root(&self.tree_levels)?;
        self.blocks
            .last_mut()
            .ok_or(WalletError::InvalidState("journal fixture block absent"))?
            .root_after = root;
        self.validate()?;
        Ok(position)
    }

    fn append_commitment(&mut self, commitment: Poseidon2V8Digest) -> Result<u64, WalletError> {
        ensure_digest("V8 commitment", commitment)?;
        let count = commitment_count(&self.tree_levels)?;
        if count >= (1usize << SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH) {
            return Err(WalletError::InvalidState("V8 wallet note tree is full"));
        }
        let position =
            u64::try_from(count).map_err(|_| WalletError::InvalidState("V8 position overflow"))?;
        let root = append_note_tree(&mut self.tree_levels, commitment)?;
        if self.root_log.last().copied() != Some(root) {
            self.root_log.push(root);
        }
        Ok(position)
    }

    fn insert_owned_note_at(
        &mut self,
        opening: SmallwoodPoseidon2V8NoteOpening,
        commitment: Poseidon2V8Digest,
        diversifier_index: u32,
        position: u64,
        block: &Poseidon2V8CanonicalBlock,
        keys: &DerivedKeys,
    ) -> Result<(), WalletError> {
        self.insert_owned_note_with_origin(
            opening,
            commitment,
            diversifier_index,
            position,
            block.height,
            block.hash,
            keys,
        )
    }

    /// Preserve the actual reward origin independently of its later leaf
    /// insertion. Ordinary outputs supply their own block as before.
    fn insert_owned_note_with_origin(
        &mut self,
        opening: SmallwoodPoseidon2V8NoteOpening,
        commitment: Poseidon2V8Digest,
        diversifier_index: u32,
        position: u64,
        created_height: u64,
        created_block_hash: [u8; 32],
        keys: &DerivedKeys,
    ) -> Result<(), WalletError> {
        if self
            .owned_notes
            .iter()
            .any(|note| note.position == position)
        {
            return Err(WalletError::InvalidState("duplicate owned V8 note"));
        }
        let nullifier = owned_note_nullifier(keys, opening, position)?;
        self.owned_notes.push(StoredPoseidon2V8OwnedNote {
            opening_words: opening_to_words(opening),
            commitment,
            position,
            diversifier_index,
            nullifier,
            spent_by: None,
            created_height,
            created_block_hash,
        });
        Ok(())
    }

    fn validate_tip(&self) -> Result<(), WalletError> {
        self.validate_default_root()?;
        let root = current_note_root(&self.tree_levels)?;
        if self.root_log.last().copied() != Some(root)
            || self.blocks.last().is_some_and(|block| {
                block.root_after != root || block.stablecoin_root_after != self.stablecoin_root
            })
        {
            return Err(WalletError::InvalidState("corrupt V8 mirror tip"));
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), WalletError> {
        self.validate_inner(false)
    }

    fn validate_legacy_read_only(&self) -> Result<(), WalletError> {
        if self.maturity_blocks != 0
            || !self.pending_rewards.is_empty()
            || self
                .blocks
                .iter()
                .any(|block| !block.released_rewards.is_empty())
        {
            return Err(WalletError::InvalidState(
                "mixed legacy and mature V8 mirror",
            ));
        }
        self.validate_inner(true)
    }

    fn validate_inner(&self, legacy_read_only: bool) -> Result<(), WalletError> {
        if self.genesis_hash.is_none()
            && (!self.blocks.is_empty()
                || !self.tree_levels.is_empty()
                || !self.root_log.is_empty()
                || self.stablecoin_root.is_some()
                || !self.owned_notes.is_empty()
                || !self.nullifiers.is_empty()
                || !self.pending_rewards.is_empty())
        {
            return Err(WalletError::InvalidState(
                "uninitialized V8 mirror contains state",
            ));
        }
        if self.genesis_hash.is_none() {
            return Ok(());
        }
        if !legacy_read_only && self.maturity_blocks != protocol_versioning::COINBASE_MATURITY {
            return Err(WalletError::InvalidState(
                "legacy V8 reward policy cannot extend the new chain",
            ));
        }
        let tip_height = self.blocks.last().map_or(0, |block| block.height);
        if self.pending_rewards.len() >= protocol_versioning::COINBASE_MATURITY as usize {
            return Err(WalletError::InvalidState(
                "oversized V8 reward maturity queue",
            ));
        }
        let mut last_origin = 0;
        for reward in &self.pending_rewards {
            reward.validate(self)?;
            if reward.created_height <= last_origin
                || reward.created_height > tip_height
                || reward.release_height()? <= tip_height
            {
                return Err(WalletError::InvalidState(
                    "invalid V8 reward maturity queue order",
                ));
            }
            last_origin = reward.created_height;
        }
        self.validate_default_root()?;
        let commitments = self
            .tree_levels
            .first()
            .ok_or(WalletError::InvalidState("V8 commitment level missing"))?;
        let (expected_levels, expected_root_log) = rebuild_note_tree(commitments)?;
        if self.tree_levels != expected_levels || self.root_log != expected_root_log {
            return Err(WalletError::InvalidState(
                "corrupt V8 note tree or root history",
            ));
        }
        let root = current_note_root(&self.tree_levels)?;
        let mut previous_height = 0u64;
        let mut previous_hash = self.genesis_hash.unwrap_or([0; 32]);
        let mut previous_leaf_count = 0u64;
        let mut previous_root_log_len = 1u64;
        let release_stablecoin_root = production_stablecoin_genesis(previous_hash)?;
        let mut previous_stablecoin_root = self
            .blocks
            .first()
            .map(|block| block.stablecoin_root_before)
            .unwrap_or(self.stablecoin_root);
        if release_stablecoin_root.is_some() && previous_stablecoin_root != release_stablecoin_root
        {
            return Err(WalletError::InvalidState(
                "V8 stablecoin genesis root differs from the release capability",
            ));
        }
        for (index, block) in self.blocks.iter().enumerate() {
            let leaf_count_after = self
                .blocks
                .get(index + 1)
                .map(|next| next.leaf_count_before)
                .unwrap_or_else(|| u64::try_from(commitments.len()).unwrap_or(u64::MAX));
            let root_log_len_after = self
                .blocks
                .get(index + 1)
                .map(|next| next.root_log_len_before)
                .unwrap_or_else(|| u64::try_from(self.root_log.len()).unwrap_or(u64::MAX));
            let prefix_len = usize::try_from(leaf_count_after)
                .map_err(|_| WalletError::InvalidState("V8 block leaf count overflow"))?;
            let expected_block_root = note_root(commitments.get(..prefix_len).ok_or(
                WalletError::InvalidState("V8 block leaf count exceeds tree"),
            )?)?;
            if block.released_rewards.len() > 1 {
                return Err(WalletError::InvalidState(
                    "multiple V8 reward release origins",
                ));
            }
            for reward in &block.released_rewards {
                reward.validate(self)?;
                if reward.release_height()? != block.height {
                    return Err(WalletError::InvalidState(
                        "V8 reward released at wrong height",
                    ));
                }
                let start =
                    prefix_len
                        .checked_sub(reward.notes.len())
                        .ok_or(WalletError::InvalidState(
                            "V8 reward release exceeds block leaves",
                        ))?;
                if start < block.leaf_count_before as usize
                    || reward.notes.iter().enumerate().any(|(offset, note)| {
                        commitments.get(start + offset) != Some(&note.commitment)
                    })
                {
                    return Err(WalletError::InvalidState(
                        "V8 reward release leaf order mismatch",
                    ));
                }
            }
            if block.height != previous_height.saturating_add(1)
                || block.parent_hash != previous_hash
                || block.leaf_count_before != previous_leaf_count
                || block.root_log_len_before != previous_root_log_len
                || block.root_after != expected_block_root
                || block.stablecoin_root_before != previous_stablecoin_root
                || block.stablecoin_root_after.is_none() != previous_stablecoin_root.is_none()
            {
                return Err(WalletError::InvalidState("corrupt V8 block journal"));
            }
            previous_height = block.height;
            previous_hash = block.block_hash;
            previous_leaf_count = leaf_count_after;
            previous_root_log_len = root_log_len_after;
            previous_stablecoin_root = block.stablecoin_root_after;
        }
        if self.blocks.last().is_some_and(|block| {
            block.root_after != root || block.stablecoin_root_after != self.stablecoin_root
        }) || previous_root_log_len != u64::try_from(self.root_log.len()).unwrap_or(u64::MAX)
        {
            return Err(WalletError::InvalidState("corrupt V8 tip root"));
        }
        for note in &self.owned_notes {
            let position = usize::try_from(note.position)
                .map_err(|_| WalletError::InvalidState("V8 note position overflow"))?;
            if commitments.get(position) != Some(&note.commitment)
                || poseidon2_v8_note_commitment(words_to_opening(note.opening_words)?)
                    .map_err(|_| WalletError::InvalidState("invalid stored V8 note opening"))?
                    != note.commitment
            {
                return Err(WalletError::InvalidState(
                    "stored V8 note does not match its commitment",
                ));
            }
            let _ = note_path_from_levels(&self.tree_levels, note.position)?;
            if note.spent_by.is_some_and(|hash| {
                !self
                    .nullifiers
                    .iter()
                    .any(|entry| entry.value == note.nullifier && entry.block_hash == hash)
            }) {
                return Err(WalletError::InvalidState(
                    "stored V8 spent note has no nullifier row",
                ));
            }
        }
        for (index, nullifier) in self.nullifiers.iter().enumerate() {
            ensure_digest("V8 nullifier", nullifier.value)?;
            if self.nullifiers[..index]
                .iter()
                .any(|prior| prior.value == nullifier.value)
            {
                return Err(WalletError::InvalidState("duplicate stored V8 nullifier"));
            }
            if !self
                .blocks
                .iter()
                .any(|block| block.block_hash == nullifier.block_hash)
            {
                return Err(WalletError::InvalidState("orphaned V8 nullifier row"));
            }
        }
        for block in &self.blocks {
            for nullifier in &block.introduced_nullifiers {
                if !self
                    .nullifiers
                    .iter()
                    .any(|entry| entry.value == *nullifier && entry.block_hash == block.block_hash)
                {
                    return Err(WalletError::InvalidState(
                        "V8 block journal nullifier is missing",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_default_root(&self) -> Result<(), WalletError> {
        // Wallet deserialization calls `validate` before exposing persisted
        // state.  Check the immutable first history entry before rebuilding so
        // a legacy zero-leaf mirror is rejected, never reinterpreted in place.
        match self.root_log.first().copied() {
            Some(root) if root == empty_note_root() => Ok(()),
            Some(_) => Err(WalletError::InvalidState(
                POSEIDON2_V8_DEFAULT_REPLAY_REQUIRED,
            )),
            None => Err(WalletError::InvalidState("V8 root history is empty")),
        }
    }
}

/// Extract exact public reward notes after canonical framing and action-ID
/// checks. This does not establish that a block is canonical or authorize a
/// spend: custody scanners must consume an independently verified node stream.
pub fn poseidon2_v8_reward_notes_from_canonical_action(
    encoded: &[u8],
) -> Result<Option<Vec<Poseidon2V8CoinbaseNoteData>>, WalletError> {
    let wire = decode_canonical_action_exact(encoded)?;
    if wire.family_id != FAMILY_SHIELDED_POOL
        || !matches!(
            wire.action_id,
            ACTION_MINT_POSEIDON2_V8_COINBASE | ACTION_MINT_POSEIDON2_V8_REWARDS
        )
    {
        return Ok(None);
    }
    match decode_v8_coinbase(wire)? {
        DecodedPoseidon2V8Action::Coinbase(notes) => Ok(Some(notes)),
        _ => unreachable!("reward decoder returns rewards only"),
    }
}

fn decode_v8_action_exact(
    encoded: &[u8],
    decode_transfer: &impl Fn(PendingActionWire) -> Result<DecodedPoseidon2V8Action, WalletError>,
) -> Result<Option<DecodedPoseidon2V8Action>, WalletError> {
    let wire = decode_canonical_action_exact(encoded)?;
    if wire.family_id != FAMILY_SHIELDED_POOL {
        return Ok(None);
    }
    match wire.action_id {
        ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE => decode_transfer(wire).map(Some),
        protocol_versioning::launch_candidate::HTLC_ACTION_ID
        | protocol_versioning::launch_candidate::RP06_ACTION_ID
        | protocol_versioning::launch_candidate::PRIVATE_SPEND_ACTION_ID => {
            decode_transfer(wire).map(Some)
        }
        transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID
        | transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID
        | RECOVERY_SPEND_ACTION_ID
        | RECOVERY_ADMIN_ACTION_ID => decode_transfer(wire).map(Some),
        ACTION_MINT_POSEIDON2_V8_COINBASE | ACTION_MINT_POSEIDON2_V8_REWARDS => {
            decode_v8_coinbase(wire).map(Some)
        }
        _ => Ok(None),
    }
}

#[cfg_attr(not(feature = "rpc-client"), allow(dead_code))]
pub(crate) fn canonical_action_id_exact(encoded: &[u8]) -> Result<[u8; 48], WalletError> {
    Ok(decode_canonical_action_exact(encoded)?.tx_hash)
}

#[cfg(test)]
pub(crate) fn canonical_test_action_bytes(marker: u8) -> Vec<u8> {
    let mut wire = PendingActionWire {
        tx_hash: [0; 48],
        binding: protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
        family_id: u16::MAX,
        action_id: u16::from(marker),
        anchor: [0; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: Vec::new(),
        ciphertext_sizes: Vec::new(),
        public_args: vec![marker],
        fee: 0,
        candidate_artifact: None,
    };
    wire.tx_hash = pending_action_hash(&wire);
    wire.encode()
}

// SCALE overhead for the exact empty-legacy-field recovery shapes, including
// the four-byte compact public_args length. Inner caps are source-owned; this
// exception never changes the ordinary eight-MiB ceiling or proof authority.
const RECOVERY_SPEND_CANONICAL_OUTER_BYTES: usize = 277;
const RECOVERY_ADMIN_CANONICAL_OUTER_BYTES: usize = 121;

/// Allocation-free outer preflight followed by the typed borrowed recovery
/// decoder. A route ID or magic prefix alone cannot grant the larger limit.
fn recovery_canonical_decode_limit(encoded: &[u8]) -> Option<usize> {
    use transaction_circuit::{asset_recovery_wire_v1 as wire, asset_spend_v1_admission as old};
    if encoded.len() > wire::MAX_SPEND_ACTION_BYTES + RECOVERY_SPEND_CANONICAL_OUTER_BYTES {
        return None;
    }
    fn take<'a>(cursor: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        let (head, tail) = cursor.split_at_checked(n)?;
        *cursor = tail;
        Some(head)
    }
    // Exact minimal SCALE compact-u32, without decoding any Vec.
    fn count(cursor: &mut &[u8]) -> Option<usize> {
        let first = *cursor.first()?;
        let value = match first & 3 {
            0 => u32::from(take(cursor, 1)?[0] >> 2),
            1 => {
                let n = u16::from_le_bytes(take(cursor, 2)?.try_into().ok()?) >> 2;
                if n < 1 << 6 {
                    return None;
                }
                u32::from(n)
            }
            2 => {
                let n = u32::from_le_bytes(take(cursor, 4)?.try_into().ok()?) >> 2;
                if n < 1 << 14 {
                    return None;
                }
                n
            }
            _ => {
                if take(cursor, 1)? != [3] {
                    return None;
                }
                let n = u32::from_le_bytes(take(cursor, 4)?.try_into().ok()?);
                if n <= 0x3fff_ffff {
                    return None;
                }
                n
            }
        };
        usize::try_from(value).ok()
    }
    let mut cursor = encoded;
    take(&mut cursor, 48)?; // Fixed ActionId48; hash is checked by the exact decoder.
    let binding = old::NATIVE_VERSION_BINDING;
    if take(&mut cursor, 2)? != binding.circuit.to_le_bytes()
        || take(&mut cursor, 2)? != binding.crypto.to_le_bytes()
        || take(&mut cursor, 2)? != FAMILY_SHIELDED_POOL.to_le_bytes()
    {
        return None;
    }
    let action = u16::from_le_bytes(take(&mut cursor, 2)?.try_into().ok()?);
    let (outputs, inner_cap, outer_cap) = match action {
        RECOVERY_SPEND_ACTION_ID => (
            3,
            wire::MAX_SPEND_ACTION_BYTES,
            RECOVERY_SPEND_CANONICAL_OUTER_BYTES,
        ),
        RECOVERY_ADMIN_ACTION_ID => (
            0,
            wire::MAX_ADMIN_ACTION_BYTES,
            RECOVERY_ADMIN_CANONICAL_OUTER_BYTES,
        ),
        _ => return None,
    };
    if take(&mut cursor, 48)? != [0; 48]
        || count(&mut cursor)? != 0
        || count(&mut cursor)? != 0
        || count(&mut cursor)? != outputs
    {
        return None;
    }
    let hashes = take(&mut cursor, outputs * 48)?;
    if count(&mut cursor)? != outputs {
        return None;
    }
    if !take(&mut cursor, outputs * 4)?
        .chunks_exact(4)
        .all(|n| n == (wire::CIPHERTEXT_BYTES as u32).to_le_bytes())
    {
        return None;
    }
    let length = count(&mut cursor)?;
    // The fixed overhead above accounts for at most four length bytes.
    if length > inner_cap || length > 0x3fff_ffff {
        return None;
    }
    let body = take(&mut cursor, length)?;
    let fee = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?);
    if take(&mut cursor, 1)? != [0] || !cursor.is_empty() {
        return None;
    }
    match action {
        RECOVERY_SPEND_ACTION_ID => {
            let decoded = wire::decode_spend_ref(body).ok()?;
            if fee != decoded.public.base.fee
                || !hashes
                    .chunks_exact(48)
                    .zip(decoded.public.base.ciphertext_commitments.iter())
                    .all(|(actual, expected)| actual == expected)
            {
                return None;
            }
        }
        RECOVERY_ADMIN_ACTION_ID => {
            wire::decode_admin_ref(body).ok()?;
            if fee != 0 {
                return None;
            }
        }
        _ => return None,
    }
    Some(inner_cap + outer_cap)
}

fn canonical_action_decode_limit(encoded: &[u8]) -> usize {
    if encoded.len() <= MAX_CANONICAL_ACTION_BYTES {
        MAX_CANONICAL_ACTION_BYTES
    } else {
        recovery_canonical_decode_limit(encoded).unwrap_or(MAX_CANONICAL_ACTION_BYTES)
    }
}

fn decode_canonical_action_exact(encoded: &[u8]) -> Result<PendingActionWire, WalletError> {
    let maximum = canonical_action_decode_limit(encoded);
    if encoded.len() > maximum {
        return Err(WalletError::Serialization(
            "canonical action exceeds wallet decode limit".into(),
        ));
    }
    let mut cursor = encoded;
    let wire = PendingActionWire::decode_with_mem_limit(&mut cursor, maximum)
        .map_err(|error| WalletError::Serialization(format!("decode canonical action: {error}")))?;
    if !cursor.is_empty() || wire.encode().as_slice() != encoded {
        return Err(WalletError::Serialization(
            "noncanonical native action encoding".into(),
        ));
    }
    if pending_action_hash(&wire) != wire.tx_hash {
        return Err(WalletError::Serialization(
            "canonical action id mismatch".into(),
        ));
    }
    Ok(wire)
}

fn decode_v8_transfer(
    wire: PendingActionWire,
    expected: Poseidon2ProductionExpectedContext,
    route: WalletProofRoute,
) -> Result<DecodedPoseidon2V8Action, WalletError> {
    let expected_binding: PendingVersionBinding =
        protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into();
    if wire.binding != expected_binding
        || wire.anchor != [0; 48]
        || !wire.nullifiers.is_empty()
        || !wire.commitments.is_empty()
        || wire.candidate_artifact.is_some()
        || wire.ciphertext_hashes.len() != wire.ciphertext_sizes.len()
        || wire.ciphertext_hashes.len() > 2
    {
        return Err(WalletError::Serialization(
            "noncanonical V8 transfer outer state".into(),
        ));
    }
    let decoded = route.decode_inline_args_exact(expected, &wire.public_args)?;
    let leaf = decoded.envelope().decoded_native_leaf();
    let statement =
        SmallwoodPoseidon2V8PublicStatement::try_from_public_bytes(leaf.statement_bytes())
            .map_err(|error| {
                WalletError::Serialization(format!("decode V8 statement: {error:?}"))
            })?;
    statement
        .validate_public_structure()
        .map_err(|error| WalletError::Serialization(format!("invalid V8 statement: {error:?}")))?;
    let expected_intent = statement.expected_action_intent().map_err(|error| {
        WalletError::Serialization(format!("derive V8 action intent: {error:?}"))
    })?;
    let observed_intent = core::array::from_fn(|limb| {
        leaf.relation_balance_binding_limb(limb)
            .expect("V8 profiles fix the seven-limb relation binding")
    });
    if observed_intent != expected_intent {
        return Err(WalletError::Serialization(
            "V8 relation/action-intent binding mismatch".into(),
        ));
    }
    if wire.fee != statement.fee {
        return Err(WalletError::Serialization(
            "V8 fee projection mismatch".into(),
        ));
    }
    let mut ciphertexts = [None; 2];
    let mut metadata_index = 0usize;
    for output in 0..2 {
        if !statement.output_flags[output] {
            continue;
        }
        let raw = leaf.ciphertext(output).ok_or_else(|| {
            WalletError::Serialization("active V8 output ciphertext missing".into())
        })?;
        let size = u32::try_from(raw.len())
            .map_err(|_| WalletError::Serialization("V8 ciphertext size overflow".into()))?;
        if wire.ciphertext_sizes.get(metadata_index) != Some(&size)
            || wire.ciphertext_hashes.get(metadata_index) != Some(&ciphertext_hash_bytes(raw))
        {
            return Err(WalletError::Serialization(
                "V8 ciphertext metadata mismatch".into(),
            ));
        }
        ciphertexts[output] = Some(*raw);
        metadata_index += 1;
    }
    if metadata_index != wire.ciphertext_hashes.len() {
        return Err(WalletError::Serialization(
            "V8 ciphertext metadata count mismatch".into(),
        ));
    }
    Ok(DecodedPoseidon2V8Action::Transfer {
        statement,
        ciphertexts,
    })
}

fn decode_v8_coinbase(wire: PendingActionWire) -> Result<DecodedPoseidon2V8Action, WalletError> {
    let is_rewards = wire.action_id == ACTION_MINT_POSEIDON2_V8_REWARDS;
    let expected_binding: PendingVersionBinding = if is_rewards {
        protocol_versioning::launch_candidate::RP06_VERSION_BINDING.into()
    } else {
        protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into()
    };
    if wire.binding != expected_binding
        || wire.anchor != [0; 48]
        || !wire.nullifiers.is_empty()
        || !wire.commitments.is_empty()
        || wire.candidate_artifact.is_some()
        || wire.fee != 0
        || wire.ciphertext_hashes.len() != wire.ciphertext_sizes.len()
        || (!is_rewards && wire.public_args.len() != POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES)
        || (is_rewards && wire.public_args.len() > POSEIDON2_V8_REWARDS_MAX_ARGS_SCALE_BYTES)
    {
        return Err(WalletError::Serialization(
            "noncanonical V8 reward outer state".into(),
        ));
    }
    let mut cursor = wire.public_args.as_slice();
    let (notes, reencoded) = if is_rewards {
        let args = MintPoseidon2V8RewardsArgs::decode(&mut cursor)
            .map_err(|error| WalletError::Serialization(format!("decode V8 rewards: {error}")))?;
        let encoded = args.encode();
        let mut notes = vec![args.miner_note];
        notes.extend(args.funding_note);
        (notes, encoded)
    } else {
        let args = MintPoseidon2V8CoinbaseArgs::decode(&mut cursor)
            .map_err(|error| WalletError::Serialization(format!("decode V8 coinbase: {error}")))?;
        let encoded = args.encode();
        (vec![args.miner_note], encoded)
    };
    if !cursor.is_empty()
        || reencoded != wire.public_args
        || notes.len() != wire.ciphertext_hashes.len()
    {
        return Err(WalletError::Serialization(
            "noncanonical V8 reward encoding/count".into(),
        ));
    }
    if notes.len() == 2 && notes[0].commitment == notes[1].commitment {
        return Err(WalletError::Serialization(
            "duplicate V8 reward commitment".into(),
        ));
    }
    for (index, note) in notes.iter().enumerate() {
        let opening = protocol_opening_to_relation(note.opening);
        if opening.value == 0
            || u128::from(opening.value) > MAX_IN_CIRCUIT_VALUE
            || opening.asset_id != NATIVE_ASSET_ID
            || opening.recipient_key == [0; 4]
            || opening.authorization_key == [0; 4]
            || opening_words(opening)
                .into_iter()
                .any(|word| word >= FIELD_MODULUS_U64)
            || poseidon2_v8_note_commitment(opening)
                .map_err(|_| WalletError::Serialization("invalid V8 reward opening".into()))?
                != note.commitment
        {
            return Err(WalletError::Serialization(
                "invalid V8 reward commitment".into(),
            ));
        }
        let ciphertext = NoteCiphertext::from_chain_bytes(&note.encrypted_note.encode())?;
        let raw = ciphertext.to_da_bytes()?;
        if wire.ciphertext_sizes[index] != u32::try_from(raw.len()).unwrap_or(u32::MAX)
            || wire.ciphertext_hashes[index] != ciphertext_hash_bytes(&raw)
        {
            return Err(WalletError::Serialization(
                "V8 reward ciphertext metadata mismatch".into(),
            ));
        }
    }
    Ok(DecodedPoseidon2V8Action::Coinbase(notes))
}

fn pending_action_hash(wire: &PendingActionWire) -> [u8; 48] {
    let body = PendingActionIdentityBody {
        binding: &wire.binding,
        family_id: wire.family_id,
        action_id: wire.action_id,
        anchor: &wire.anchor,
        nullifiers: &wire.nullifiers,
        commitments: &wire.commitments,
        ciphertext_hashes: &wire.ciphertext_hashes,
        ciphertext_sizes: &wire.ciphertext_sizes,
        public_args: &wire.public_args,
        fee: wire.fee,
        candidate_artifact: &wire.candidate_artifact,
    }
    .encode();
    blake2b_384_domain_hash(domains::ACTION_ID_V3, [body.as_slice()])
}

fn recover_coinbase_note(
    note: &Poseidon2V8CoinbaseNoteData,
    keys: &DerivedKeys,
) -> Result<Option<(SmallwoodPoseidon2V8NoteOpening, u32)>, WalletError> {
    let ciphertext = NoteCiphertext::from_chain_bytes(&note.encrypted_note.encode())?;
    // Header index is merely a hint. Always try the primary payout address as
    // well, so changing that public header cannot hide an owned primary reward.
    // Threshold scanners instead use their exact pinned policy address.
    for index in [ciphertext.diversifier_index, 0] {
        let material = keys.poseidon2_v8_address(index)?;
        if let Ok(opening) = crate::poseidon2_v8_coinbase::public_poseidon2_v8_reward_opening(
            note,
            &material.shielded_address(),
        ) {
            return Ok(Some((opening, index)));
        }
        if index == 0 {
            break;
        }
    }
    Ok(None)
}

fn recover_transfer_note(
    raw: &[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
    commitment: Poseidon2V8Digest,
    keys: &DerivedKeys,
) -> Result<Option<(SmallwoodPoseidon2V8NoteOpening, u32)>, WalletError> {
    let Ok(ciphertext) = NoteCiphertext::from_da_bytes(raw) else {
        return Ok(None);
    };
    let material = keys.poseidon2_v8_address(ciphertext.diversifier_index)?;
    let Ok(plaintext) = ciphertext.decrypt(&material) else {
        return Ok(None);
    };
    let Ok(opening) = recovered_opening(&plaintext, &material) else {
        return Ok(None);
    };
    let Ok(recomputed) = poseidon2_v8_note_commitment(opening) else {
        return Ok(None);
    };
    if recomputed != commitment {
        return Ok(None);
    }
    Ok(Some((opening, ciphertext.diversifier_index)))
}

fn recovered_opening(
    plaintext: &crate::notes::NotePlaintext,
    material: &crate::keys::AddressKeyMaterial,
) -> Result<SmallwoodPoseidon2V8NoteOpening, WalletError> {
    let opening = SmallwoodPoseidon2V8NoteOpening {
        value: plaintext.value,
        asset_id: plaintext.asset_id,
        recipient_key: poseidon2_v8_words_from_canonical_bytes(material.pk_recipient)
            .map_err(|_| WalletError::NoteMismatch("noncanonical V8 recipient key"))?,
        authorization_key: poseidon2_v8_words_from_canonical_bytes(material.pk_auth)
            .map_err(|_| WalletError::NoteMismatch("noncanonical V8 authorization key"))?,
        rho: poseidon2_v8_words_from_canonical_bytes(plaintext.rho)
            .map_err(|_| WalletError::NoteMismatch("noncanonical V8 rho"))?,
        randomness: poseidon2_v8_words_from_canonical_bytes(plaintext.r)
            .map_err(|_| WalletError::NoteMismatch("noncanonical V8 randomness"))?,
    };
    if opening.randomness[..3] != material.poseidon2_v8_authorization_extension_words()? {
        return Err(WalletError::NoteMismatch(
            "V8 note authorization extension does not match routed key material",
        ));
    }
    Ok(opening)
}

fn owned_note_nullifier(
    keys: &DerivedKeys,
    opening: SmallwoodPoseidon2V8NoteOpening,
    position: u64,
) -> Result<Poseidon2V8Digest, WalletError> {
    let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
    statement.input_flags[0] = true;
    let mut witness = SmallwoodPoseidon2V8Witness::default();
    witness.inputs[0] = SmallwoodPoseidon2V8InputWitness {
        active: true,
        spend_key: keys.spend.poseidon2_v8_words()?,
        note: opening,
        position,
        siblings: [[0; 7]; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH],
        balance_slot_selectors: [true, false, false, false],
    };
    let schedule = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)
        .map_err(|error| WalletError::Serialization(format!("derive V8 nullifier: {error:?}")))?;
    schedule
        .calls
        .iter()
        .find(|call| {
            matches!(
                call.role,
                SmallwoodPoseidon2V8HashCallRole::InputNullifier { input: 0, block: 1 }
            )
        })
        .map(|call| call.final_digest())
        .ok_or(WalletError::InvalidState("V8 nullifier hash call missing"))
}

pub(crate) fn empty_note_root() -> Poseidon2V8Digest {
    poseidon2_v8_default_note_nodes()[SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH]
}

fn production_stablecoin_genesis(
    genesis_hash: [u8; 32],
) -> Result<Option<Poseidon2V8Digest>, WalletError> {
    let Some(capability) = protocol_versioning::smallwood_poseidon2_production_capability() else {
        return Ok(None);
    };
    poseidon2_v8_production_selection_at(capability.activation_height())?;
    if !matches!(
        capability.coinbase_action_id(),
        ACTION_MINT_POSEIDON2_V8_COINBASE | ACTION_MINT_POSEIDON2_V8_REWARDS
    ) || capability.activation_genesis_hash() != genesis_hash
        || capability.note_genesis_root() != empty_note_root()
    {
        return Err(WalletError::InvalidState(
            "V8 release capability genesis tuple does not match the wallet chain",
        ));
    }
    let stablecoin_root = capability.stablecoin_genesis_root();
    ensure_digest("V8 stablecoin genesis root", stablecoin_root)?;
    Ok(Some(stablecoin_root))
}

fn felt_digest_to_words(digest: [hegemon_field::Goldilocks; 7]) -> Poseidon2V8Digest {
    digest.map(|word| word.as_canonical_u64())
}

fn empty_tree_levels() -> Vec<Vec<Poseidon2V8Digest>> {
    note_levels(&[]).expect("the fixed empty V8 note tree is valid")
}

fn commitment_count(levels: &[Vec<Poseidon2V8Digest>]) -> Result<usize, WalletError> {
    if levels.len() != SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH + 1 {
        return Err(WalletError::InvalidState("V8 note tree depth mismatch"));
    }
    levels
        .first()
        .map(Vec::len)
        .ok_or(WalletError::InvalidState("V8 commitment level missing"))
}

fn current_note_root(levels: &[Vec<Poseidon2V8Digest>]) -> Result<Poseidon2V8Digest, WalletError> {
    if levels.len() != SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH + 1 {
        return Err(WalletError::InvalidState("V8 note tree depth mismatch"));
    }
    levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .ok_or(WalletError::InvalidState("V8 note tree root missing"))
}

fn append_note_tree(
    levels: &mut [Vec<Poseidon2V8Digest>],
    commitment: Poseidon2V8Digest,
) -> Result<Poseidon2V8Digest, WalletError> {
    let position = commitment_count(levels)?;
    ensure_digest("V8 commitment", commitment)?;
    levels[0].push(commitment);
    let defaults = poseidon2_v8_default_note_nodes();
    let mut current = commitment;
    let mut node_index = position;
    for level in 0..SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH {
        let parent = if node_index & 1 == 0 {
            poseidon2_v8_note_tree_compress(current, defaults[level])
        } else {
            let left = levels[level]
                .get(node_index - 1)
                .copied()
                .ok_or(WalletError::InvalidState("V8 left sibling missing"))?;
            poseidon2_v8_note_tree_compress(left, current)
        };
        let parent_index = node_index >> 1;
        let parent_level = &mut levels[level + 1];
        if parent_index < parent_level.len() {
            parent_level[parent_index] = parent;
        } else if parent_index == parent_level.len() {
            parent_level.push(parent);
        } else {
            return Err(WalletError::InvalidState("V8 parent tree level has a gap"));
        }
        current = parent;
        node_index = parent_index;
    }
    Ok(current)
}

fn rebuild_note_tree(
    commitments: &[Poseidon2V8Digest],
) -> Result<(Vec<Vec<Poseidon2V8Digest>>, Vec<Poseidon2V8Digest>), WalletError> {
    if commitments.len() > (1usize << SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH) {
        return Err(WalletError::InvalidState("V8 wallet note tree is full"));
    }
    let mut levels = empty_tree_levels();
    let mut root_log = vec![empty_note_root()];
    for commitment in commitments {
        let root = append_note_tree(&mut levels, *commitment)?;
        if root_log.last().copied() != Some(root) {
            root_log.push(root);
        }
    }
    Ok((levels, root_log))
}

fn accepted_note_roots(root_log: &[Poseidon2V8Digest]) -> Vec<Poseidon2V8Digest> {
    let start = root_log
        .len()
        .saturating_sub(POSEIDON2_V8_NOTE_ROOT_HISTORY_LIMIT);
    root_log[start..].to_vec()
}

fn note_path_from_levels(
    levels: &[Vec<Poseidon2V8Digest>],
    position: u64,
) -> Result<Poseidon2V8Path, WalletError> {
    let position = usize::try_from(position)
        .map_err(|_| WalletError::InvalidState("V8 note position overflow"))?;
    if position >= commitment_count(levels)? {
        return Err(WalletError::InvalidState(
            "V8 note position is outside the tree",
        ));
    }
    let defaults = poseidon2_v8_default_note_nodes();
    let mut index = position;
    let mut path = [[0u64; 7]; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH];
    for level in 0..SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH {
        path[level] = levels[level]
            .get(index ^ 1)
            .copied()
            .unwrap_or(defaults[level]);
        index >>= 1;
    }
    Ok(path)
}

fn note_levels(
    commitments: &[Poseidon2V8Digest],
) -> Result<Vec<Vec<Poseidon2V8Digest>>, WalletError> {
    if commitments.len() > (1usize << SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH) {
        return Err(WalletError::InvalidState("V8 wallet note tree is full"));
    }
    for commitment in commitments {
        ensure_digest("V8 commitment", *commitment)?;
    }
    let defaults = poseidon2_v8_default_note_nodes();
    let mut levels = Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH + 1);
    levels.push(commitments.to_vec());
    for level in 0..SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH {
        let current = levels
            .last()
            .ok_or(WalletError::InvalidState("V8 tree level missing"))?;
        let mut next = Vec::with_capacity(current.len().div_ceil(2).max(1));
        if current.is_empty() {
            next.push(defaults[level + 1]);
        } else {
            for pair in current.chunks(2) {
                next.push(poseidon2_v8_note_tree_compress(
                    pair[0],
                    pair.get(1).copied().unwrap_or(defaults[level]),
                ));
            }
        }
        levels.push(next);
    }
    Ok(levels)
}

fn note_root(commitments: &[Poseidon2V8Digest]) -> Result<Poseidon2V8Digest, WalletError> {
    note_levels(commitments)?
        .last()
        .and_then(|level| level.first())
        .copied()
        .ok_or(WalletError::InvalidState("V8 root missing"))
}

fn ensure_digest(label: &'static str, digest: Poseidon2V8Digest) -> Result<(), WalletError> {
    if digest.into_iter().any(|word| word >= FIELD_MODULUS_U64) {
        return Err(WalletError::Serialization(format!(
            "{label} has a noncanonical field limb"
        )));
    }
    Ok(())
}

fn opening_words(opening: SmallwoodPoseidon2V8NoteOpening) -> [u64; NOTE_OPENING_WORDS] {
    opening_to_words(opening)
}

pub(crate) fn opening_to_words(
    opening: SmallwoodPoseidon2V8NoteOpening,
) -> [u64; NOTE_OPENING_WORDS] {
    [
        opening.value,
        opening.asset_id,
        opening.recipient_key[0],
        opening.recipient_key[1],
        opening.recipient_key[2],
        opening.recipient_key[3],
        opening.authorization_key[0],
        opening.authorization_key[1],
        opening.authorization_key[2],
        opening.authorization_key[3],
        opening.rho[0],
        opening.rho[1],
        opening.rho[2],
        opening.rho[3],
        opening.randomness[0],
        opening.randomness[1],
        opening.randomness[2],
        opening.randomness[3],
    ]
}

pub(crate) fn words_to_opening(
    words: [u64; NOTE_OPENING_WORDS],
) -> Result<SmallwoodPoseidon2V8NoteOpening, WalletError> {
    if words.into_iter().any(|word| word >= FIELD_MODULUS_U64) {
        return Err(WalletError::InvalidState(
            "stored V8 note has a noncanonical field word",
        ));
    }
    Ok(SmallwoodPoseidon2V8NoteOpening {
        value: words[0],
        asset_id: words[1],
        recipient_key: words[2..6].try_into().expect("fixed V8 recipient range"),
        authorization_key: words[6..10]
            .try_into()
            .expect("fixed V8 authorization range"),
        rho: words[10..14].try_into().expect("fixed V8 rho range"),
        randomness: words[14..18].try_into().expect("fixed V8 randomness range"),
    })
}

fn stored_note_view(
    note: &StoredPoseidon2V8OwnedNote,
    path: Poseidon2V8Path,
    anchor: Poseidon2V8Digest,
) -> Result<Poseidon2V8OwnedNoteView, WalletError> {
    Ok(Poseidon2V8OwnedNoteView {
        opening: words_to_opening(note.opening_words)?,
        commitment: note.commitment,
        position: note.position,
        path,
        anchor,
        diversifier_index: note.diversifier_index,
        nullifier: note.nullifier,
        spent: note.spent_by.is_some(),
        created_height: note.created_height,
        created_block_hash: note.created_block_hash,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use rand::{rngs::StdRng, SeedableRng};
    use tempfile::tempdir;

    use protocol_shielded_pool::poseidon2_production_transport::{
        encode_poseidon2_production_smz9_envelope, encode_poseidon2_production_smz9_inline_args,
        encode_poseidon2_production_smz9_native_leaf, encode_poseidon2_production_smza_envelope,
        encode_poseidon2_production_smza_inline_args, encode_poseidon2_production_smza_native_leaf,
    };

    use crate::{
        keys::RootSecret,
        poseidon2_v8_coinbase::{
            build_poseidon2_v8_coinbase_args, build_poseidon2_v8_wallet_self_spend,
            Poseidon2V8SpendMaterial,
        },
        store::WalletStore,
    };

    use super::*;

    const PASSPHRASE: &str = "V8 mirror restart test";
    const GENESIS: [u8; 32] = [0x10; 32];
    const BLOCK_1: [u8; 32] = [0x11; 32];
    const BLOCK_2: [u8; 32] = [0x12; 32];
    const BLOCK_3: [u8; 32] = [0x13; 32];
    const REPLACEMENT_3: [u8; 32] = [0x23; 32];
    const SOURCE_DIVERSIFIER: u32 = 9;
    const TEST_STABLECOIN_ROOT: Poseidon2V8Digest = [1, 2, 3, 4, 5, 6, 7];

    include!("poseidon2_v8_reservation_tests.rs");

    fn retained_test_context(route: WalletProofRoute) -> Poseidon2V8RetainedTestContext {
        let expected = Poseidon2ProductionExpectedContext::new(
            protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID,
            *SmallwoodPoseidon2V8SourceRelationFactory.expected_relation_digest(),
        )
        .unwrap();
        let (profile, domain) = match route {
            WalletProofRoute::Smz9 => (
                POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET,
            ),
            WalletProofRoute::Smza => (
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
            ),
        };
        Poseidon2V8RetainedTestContext::new(
            expected,
            profile,
            domain,
            GENESIS,
            TEST_STABLECOIN_ROOT,
            1,
            200,
        )
        .unwrap()
    }

    fn coinbase_args(root: &RootSecret, value: u64, seed: u64) -> MintPoseidon2V8CoinbaseArgs {
        let material = root
            .derive()
            .poseidon2_v8_address(SOURCE_DIVERSIFIER)
            .unwrap();
        build_poseidon2_v8_coinbase_args(
            &material.shielded_address(),
            value,
            &mut StdRng::seed_from_u64(seed),
        )
        .unwrap()
    }

    fn coinbase_action(args: &MintPoseidon2V8CoinbaseArgs) -> Vec<u8> {
        let ciphertext =
            NoteCiphertext::from_chain_bytes(&args.miner_note.encrypted_note.encode()).unwrap();
        let raw = ciphertext.to_da_bytes().unwrap();
        let mut wire = PendingActionWire {
            tx_hash: [0; 48],
            binding: protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
            family_id: FAMILY_SHIELDED_POOL,
            action_id: ACTION_MINT_POSEIDON2_V8_COINBASE,
            anchor: [0; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: vec![ciphertext_hash_bytes(&raw)],
            ciphertext_sizes: vec![u32::try_from(raw.len()).unwrap()],
            public_args: args.encode(),
            fee: 0,
            candidate_artifact: None,
        };
        wire.tx_hash = pending_action_hash(&wire);
        wire.encode()
    }

    fn canonical_block(
        height: u64,
        hash: [u8; 32],
        parent_hash: [u8; 32],
        action_bytes: Vec<Vec<u8>>,
    ) -> Poseidon2V8CanonicalBlock {
        Poseidon2V8CanonicalBlock {
            height,
            hash,
            parent_hash,
            action_bytes,
        }
    }

    fn transfer_inline_args(
        material: &Poseidon2V8SpendMaterial,
        relation_binding: Poseidon2V8Digest,
        route: WalletProofRoute,
    ) -> Vec<u8> {
        transfer_inline_args_with_proof_len(material, relation_binding, route, 64)
    }

    // These bytes exercise transport/readback only. They are not proof evidence.
    fn transfer_inline_args_with_proof_len(
        material: &Poseidon2V8SpendMaterial,
        relation_binding: Poseidon2V8Digest,
        route: WalletProofRoute,
        proof_len: usize,
    ) -> Vec<u8> {
        let expected = retained_test_context(route).expected;
        let ciphertexts = [
            material.inline_ciphertexts.ciphertexts[0].as_ref(),
            material.inline_ciphertexts.ciphertexts[1].as_ref(),
        ];
        let magic = match route {
            WalletProofRoute::Smz9 => b"SMZ9",
            WalletProofRoute::Smza => b"SMZA",
        };
        let encode_leaf = match route {
            WalletProofRoute::Smz9 => encode_poseidon2_production_smz9_native_leaf,
            WalletProofRoute::Smza => encode_poseidon2_production_smza_native_leaf,
        };
        let encode_envelope = match route {
            WalletProofRoute::Smz9 => encode_poseidon2_production_smz9_envelope,
            WalletProofRoute::Smza => encode_poseidon2_production_smza_envelope,
        };
        let encode_inline_args = match route {
            WalletProofRoute::Smz9 => encode_poseidon2_production_smz9_inline_args,
            WalletProofRoute::Smza => encode_poseidon2_production_smza_inline_args,
        };
        let mut proof = vec![0xa5; proof_len];
        proof[..4].copy_from_slice(magic);
        let native_leaf = encode_leaf(
            expected,
            &material.statement.to_public_words(),
            &relation_binding,
            ciphertexts,
            &proof,
        )
        .unwrap();
        let envelope = encode_envelope(expected, &native_leaf).unwrap();
        encode_inline_args(expected, &envelope).unwrap()
    }

    fn transfer_action_with_binding(
        material: &Poseidon2V8SpendMaterial,
        relation_binding: Poseidon2V8Digest,
        route: WalletProofRoute,
    ) -> Vec<u8> {
        let inline_args = transfer_inline_args(material, relation_binding, route);
        let raw_ciphertexts = material
            .inline_ciphertexts
            .ciphertexts
            .iter()
            .flatten()
            .collect::<Vec<_>>();
        let mut wire = PendingActionWire {
            tx_hash: [0; 48],
            binding: protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
            family_id: FAMILY_SHIELDED_POOL,
            action_id: ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
            anchor: [0; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: raw_ciphertexts
                .iter()
                .map(|ciphertext| ciphertext_hash_bytes(ciphertext.as_slice()))
                .collect(),
            ciphertext_sizes: raw_ciphertexts
                .iter()
                .map(|ciphertext| u32::try_from(ciphertext.len()).unwrap())
                .collect(),
            public_args: inline_args,
            fee: material.statement.fee,
            candidate_artifact: None,
        };
        wire.tx_hash = pending_action_hash(&wire);
        wire.encode()
    }

    fn transfer_action(material: &Poseidon2V8SpendMaterial, route: WalletProofRoute) -> Vec<u8> {
        transfer_action_with_binding(
            material,
            material.statement.expected_action_intent().unwrap(),
            route,
        )
    }

    pub(crate) fn seed_two_owned_coinbases(
        store: &WalletStore,
        root: &RootSecret,
    ) -> Poseidon2V8CanonicalTip {
        store
            .ensure_poseidon2_v8_genesis_for_test(GENESIS, TEST_STABLECOIN_ROOT)
            .unwrap();
        let first = coinbase_args(root, 41, 101);
        let second = coinbase_args(root, 59, 102);
        assert_eq!(
            store
                .apply_poseidon2_v8_canonical_block(&canonical_block(
                    1,
                    BLOCK_1,
                    GENESIS,
                    vec![coinbase_action(&first)],
                ))
                .unwrap(),
            Poseidon2V8SyncDelta {
                commitments: 0,
                ciphertexts: 1,
                recovered: 0,
                spent: 0,
            }
        );
        assert_eq!(
            store
                .apply_poseidon2_v8_canonical_block(&canonical_block(
                    2,
                    [0x32; 32],
                    BLOCK_1,
                    vec![coinbase_action(&second)],
                ))
                .unwrap(),
            Poseidon2V8SyncDelta {
                commitments: 0,
                ciphertexts: 1,
                recovered: 0,
                spent: 0,
            }
        );
        let mut parent = [0x32; 32];
        for height in 3u64..=121 {
            let hash = if height == 121 {
                BLOCK_2
            } else {
                let mut hash = [0x34; 32];
                hash[..8].copy_from_slice(&height.to_le_bytes());
                hash
            };
            store
                .apply_poseidon2_v8_canonical_block(&canonical_block(height, hash, parent, vec![]))
                .unwrap();
            parent = hash;
        }
        store.poseidon2_v8_tip().unwrap()
    }

    #[test]
    fn reward_maturity_delays_both_rewards_and_restores_detached_release_after_restart() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("maturity.wallet");
        let root = RootSecret::from_bytes([0x71; 32]);
        let funding_root = RootSecret::from_bytes([0x72; 32]);
        let store = WalletStore::create_from_root(&path, PASSPHRASE, root.clone()).unwrap();
        store
            .ensure_poseidon2_v8_genesis_for_test(GENESIS, TEST_STABLECOIN_ROOT)
            .unwrap();
        let args = crate::poseidon2_v8_coinbase::build_poseidon2_v8_rewards_args(
            &root
                .derive()
                .poseidon2_v8_address(SOURCE_DIVERSIFIER)
                .unwrap()
                .shielded_address(),
            80,
            &funding_root
                .derive()
                .poseidon2_v8_address(SOURCE_DIVERSIFIER)
                .unwrap()
                .shielded_address(),
            20,
            &mut StdRng::seed_from_u64(730),
        )
        .unwrap();
        let mut wire =
            decode_canonical_action_exact(&coinbase_action(&MintPoseidon2V8CoinbaseArgs {
                miner_note: args.miner_note.clone(),
            }))
            .unwrap();
        wire.action_id = ACTION_MINT_POSEIDON2_V8_REWARDS;
        wire.binding = protocol_versioning::launch_candidate::RP06_VERSION_BINDING.into();
        wire.public_args = args.encode();
        let funding = args.funding_note.as_ref().unwrap();
        let raw = NoteCiphertext::from_chain_bytes(&funding.encrypted_note.encode())
            .unwrap()
            .to_da_bytes()
            .unwrap();
        wire.ciphertext_hashes.push(ciphertext_hash_bytes(&raw));
        wire.ciphertext_sizes.push(raw.len() as u32);
        wire.tx_hash = pending_action_hash(&wire);
        let delta = store
            .apply_poseidon2_v8_canonical_block(&canonical_block(
                1,
                BLOCK_1,
                GENESIS,
                vec![wire.encode()],
            ))
            .unwrap();
        assert_eq!(
            (delta.commitments, delta.recovered, delta.ciphertexts),
            (0, 0, 2)
        );
        let hash_at = |height: u64| {
            if height == 1 {
                BLOCK_1
            } else {
                let mut hash = [0x73; 32];
                hash[..8].copy_from_slice(&height.to_le_bytes());
                hash
            }
        };
        for height in 2..=119 {
            store
                .apply_poseidon2_v8_canonical_block(&canonical_block(
                    height,
                    hash_at(height),
                    hash_at(height - 1),
                    vec![],
                ))
                .unwrap();
        }
        for commitment in [args.miner_note.commitment, funding.commitment] {
            assert!(store
                .poseidon2_v8_canonical_commitment_positions(commitment)
                .unwrap()
                .is_empty());
        }
        assert!(store.poseidon2_v8_owned_notes().unwrap().is_empty());
        drop(store);
        let reopened = WalletStore::open(&path, PASSPHRASE).unwrap();
        let release = canonical_block(120, hash_at(120), hash_at(119), vec![]);
        let delta = reopened
            .apply_poseidon2_v8_canonical_block(&release)
            .unwrap();
        assert_eq!((delta.commitments, delta.recovered), (2, 1));
        let miner_note = &reopened.poseidon2_v8_owned_notes().unwrap()[0];
        assert_eq!(
            (
                miner_note.position,
                miner_note.created_height,
                miner_note.created_block_hash
            ),
            (0, 1, BLOCK_1)
        );
        assert_eq!(
            reopened
                .poseidon2_v8_canonical_commitment_positions(funding.commitment)
                .unwrap(),
            vec![1]
        );
        let released_tip = reopened.poseidon2_v8_tip().unwrap();
        reopened
            .rollback_poseidon2_v8_to(119, hash_at(119))
            .unwrap();
        assert!(reopened.poseidon2_v8_owned_notes().unwrap().is_empty());
        assert!(reopened
            .poseidon2_v8_canonical_commitment_positions(funding.commitment)
            .unwrap()
            .is_empty());
        drop(reopened);
        let reopened = WalletStore::open(&path, PASSPHRASE).unwrap();
        reopened
            .apply_poseidon2_v8_canonical_block(&release)
            .unwrap();
        assert_eq!(reopened.poseidon2_v8_tip().unwrap(), released_tip);
        reopened.rollback_poseidon2_v8_to(0, GENESIS).unwrap();
        assert!(reopened.poseidon2_v8_owned_notes().unwrap().is_empty());
        assert_eq!(reopened.poseidon2_v8_tip().unwrap().height, 0);
    }

    #[test]
    fn rewards_both_wallets_recover_distinct_positions_restore_reorg_and_self_spend() {
        let directory = tempdir().unwrap();
        let miner_root = RootSecret::from_bytes([0x51; 32]);
        let funding_root = RootSecret::from_bytes([0x61; 32]);
        let miner_path = directory.path().join("miner.dat");
        let funding_path = directory.path().join("funding.dat");
        let miner =
            WalletStore::create_from_root(&miner_path, PASSPHRASE, miner_root.clone()).unwrap();
        let funding =
            WalletStore::create_from_root(&funding_path, PASSPHRASE, funding_root.clone()).unwrap();
        for wallet in [&miner, &funding] {
            wallet
                .ensure_poseidon2_v8_genesis_for_test(GENESIS, TEST_STABLECOIN_ROOT)
                .unwrap();
        }
        let make_reward = |seed| {
            let args = crate::poseidon2_v8_coinbase::build_poseidon2_v8_rewards_args(
                &miner_root
                    .derive()
                    .poseidon2_v8_address(SOURCE_DIVERSIFIER)
                    .unwrap()
                    .shielded_address(),
                80,
                &funding_root
                    .derive()
                    .poseidon2_v8_address(SOURCE_DIVERSIFIER)
                    .unwrap()
                    .shielded_address(),
                20,
                &mut StdRng::seed_from_u64(seed),
            )
            .unwrap();
            let mut wire =
                decode_canonical_action_exact(&coinbase_action(&MintPoseidon2V8CoinbaseArgs {
                    miner_note: args.miner_note.clone(),
                }))
                .unwrap();
            wire.action_id = ACTION_MINT_POSEIDON2_V8_REWARDS;
            wire.binding = protocol_versioning::launch_candidate::RP06_VERSION_BINDING.into();
            wire.public_args = args.encode();
            let raw = NoteCiphertext::from_chain_bytes(
                &args.funding_note.as_ref().unwrap().encrypted_note.encode(),
            )
            .unwrap()
            .to_da_bytes()
            .unwrap();
            wire.ciphertext_hashes.push(ciphertext_hash_bytes(&raw));
            wire.ciphertext_sizes.push(raw.len() as u32);
            wire.tx_hash = pending_action_hash(&wire);
            wire.encode()
        };
        let first = canonical_block(1, BLOCK_1, GENESIS, vec![make_reward(91)]);
        let second = canonical_block(2, BLOCK_2, BLOCK_1, vec![make_reward(92)]);
        for wallet in [&miner, &funding] {
            let delta = wallet.apply_poseidon2_v8_canonical_block(&first).unwrap();
            assert_eq!(delta.commitments, 0);
            assert_eq!(delta.recovered, 0);
            let delta = wallet.apply_poseidon2_v8_canonical_block(&second).unwrap();
            assert_eq!(delta.commitments, 0);
            assert_eq!(delta.recovered, 0);
        }
        let mature_hash = |height: u64| {
            let mut hash = [0x74; 32];
            hash[..8].copy_from_slice(&height.to_le_bytes());
            hash
        };
        for height in 3..=121 {
            let parent = if height == 3 {
                BLOCK_2
            } else {
                mature_hash(height - 1)
            };
            let block = canonical_block(height, mature_hash(height), parent, vec![]);
            for wallet in [&miner, &funding] {
                wallet.apply_poseidon2_v8_canonical_block(&block).unwrap();
            }
        }
        assert_eq!(
            miner.poseidon2_v8_tip().unwrap(),
            funding.poseidon2_v8_tip().unwrap()
        );
        let miner_notes = miner.poseidon2_v8_owned_notes().unwrap();
        let funding_notes = funding.poseidon2_v8_owned_notes().unwrap();
        assert_eq!(
            miner_notes.iter().map(|n| n.position).collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert_eq!(
            funding_notes.iter().map(|n| n.position).collect::<Vec<_>>(),
            vec![1, 3]
        );
        for wallet in [&miner, &funding] {
            let spend = build_poseidon2_v8_wallet_self_spend(
                wallet,
                [4, 7],
                &mut StdRng::seed_from_u64(93),
            )
            .unwrap();
            let compiled = transaction_circuit::smallwood_poseidon2_v8_semantics::compile_smallwood_poseidon2_v8_relation(&spend.material.statement,&spend.material.witness).unwrap();
            compiled
                .adapter
                .verify_packed_witness(&compiled.witness_values)
                .unwrap();
        }
        drop(miner);
        drop(funding);
        let miner = WalletStore::open(&miner_path, PASSPHRASE).unwrap();
        let funding = WalletStore::open(&funding_path, PASSPHRASE).unwrap();
        for wallet in [&miner, &funding] {
            assert_eq!(wallet.poseidon2_v8_owned_notes().unwrap().len(), 2);
            wallet
                .rollback_poseidon2_v8_to(120, mature_hash(120))
                .unwrap();
            assert_eq!(wallet.poseidon2_v8_owned_notes().unwrap().len(), 1);
            wallet
                .apply_poseidon2_v8_canonical_block(&canonical_block(
                    121,
                    mature_hash(121),
                    mature_hash(120),
                    vec![],
                ))
                .unwrap();
            assert_eq!(wallet.poseidon2_v8_owned_notes().unwrap().len(), 2);
        }
    }

    #[test]
    fn source_profile_selection_accepts_only_exact_profile_domain_pairs() {
        assert_eq!(
            WalletProofRoute::from_source_tuple(
                POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET,
            )
            .unwrap(),
            WalletProofRoute::Smz9
        );
        assert_eq!(
            WalletProofRoute::from_source_tuple(
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
            )
            .unwrap(),
            WalletProofRoute::Smza
        );
        for (profile, domain) in [
            (
                POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
            ),
            (
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET,
            ),
            (0, POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET),
            (u8::MAX, POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET),
            (POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID, 0),
            (POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID, u16::MAX),
        ] {
            assert!(WalletProofRoute::from_source_tuple(profile, domain).is_err());
        }
    }

    #[test]
    fn both_profile_sync_decoders_preserve_context_caps_fee_and_ciphertext_checks() {
        let directory = tempdir().unwrap();
        let root = RootSecret::from_bytes([0x51; 32]);
        let store = WalletStore::create_from_root(
            directory.path().join("wallet.dat"),
            PASSPHRASE,
            root.clone(),
        )
        .unwrap();
        seed_two_owned_coinbases(&store, &root);
        let spend =
            build_poseidon2_v8_wallet_self_spend(&store, [4, 7], &mut StdRng::seed_from_u64(203))
                .unwrap();
        let binding = spend.material.statement.expected_action_intent().unwrap();
        for route in [WalletProofRoute::Smz9, WalletProofRoute::Smza] {
            let context = retained_test_context(route).expected;
            let encoded = transfer_action(&spend.material, route);
            let wire = decode_canonical_action_exact(&encoded).unwrap();
            let decoded = decode_v8_transfer(wire.clone(), context, route).unwrap();
            let DecodedPoseidon2V8Action::Transfer { statement, .. } = decoded else {
                panic!("transfer decoded as coinbase");
            };
            assert_eq!(statement, spend.material.statement);
            let other_route = match route {
                WalletProofRoute::Smz9 => WalletProofRoute::Smza,
                WalletProofRoute::Smza => WalletProofRoute::Smz9,
            };
            assert!(decode_v8_transfer(wire.clone(), context, other_route).is_err());
            for wrong_context in [
                Poseidon2ProductionExpectedContext::new(
                    context.network_id() + 1,
                    context.relation_digest(),
                )
                .unwrap(),
                Poseidon2ProductionExpectedContext::new(context.network_id(), [0x42; 48]).unwrap(),
            ] {
                assert!(decode_v8_transfer(wire.clone(), wrong_context, route).is_err());
            }
            let mut bad_fee = wire.clone();
            bad_fee.fee += 1;
            assert!(decode_v8_transfer(bad_fee, context, route).is_err());
            let mut bad_hash = wire.clone();
            bad_hash.ciphertext_hashes[0][0] ^= 1;
            assert!(decode_v8_transfer(bad_hash, context, route).is_err());
            let mut bad_size = wire.clone();
            bad_size.ciphertext_sizes[0] += 1;
            assert!(decode_v8_transfer(bad_size, context, route).is_err());
            let mut missing_metadata = wire.clone();
            missing_metadata.ciphertext_hashes.pop();
            missing_metadata.ciphertext_sizes.pop();
            assert!(decode_v8_transfer(missing_metadata, context, route).is_err());
            let mut trailing = wire.clone();
            trailing.public_args.push(0);
            assert!(decode_v8_transfer(trailing, context, route).is_err());
            let over_cap = vec![0; route.max_inline_args_bytes() + 1];
            assert!(route
                .decode_inline_args_exact(context, &over_cap)
                .unwrap_err()
                .to_string()
                .contains("selected profile limit"));
        }
        let smza = transfer_inline_args_with_proof_len(
            &spend.material, binding, WalletProofRoute::Smza,
            protocol_shielded_pool::poseidon2_production_transport::POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES,
        );
        assert_eq!(smza.len(), WalletProofRoute::Smza.max_inline_args_bytes());
        let expected = retained_test_context(WalletProofRoute::Smza).expected;
        assert!(WalletProofRoute::Smza
            .decode_inline_args_exact(expected, &smza)
            .is_ok());
        assert!(WalletProofRoute::Smz9
            .decode_inline_args_exact(expected, &smza)
            .is_err());
    }

    #[test]
    fn retained_context_and_production_route_rejections_preserve_durable_state() {
        let directory = tempdir().unwrap();
        let root = RootSecret::from_bytes([0x51; 32]);
        let path = directory.path().join("wallet.dat");
        let store = WalletStore::create_from_root(&path, PASSPHRASE, root.clone()).unwrap();
        let before_tip = seed_two_owned_coinbases(&store, &root);
        let before_notes = store.poseidon2_v8_owned_notes().unwrap();
        let spend =
            build_poseidon2_v8_wallet_self_spend(&store, [4, 7], &mut StdRng::seed_from_u64(204))
                .unwrap();
        let block = canonical_block(
            122,
            BLOCK_3,
            BLOCK_2,
            vec![transfer_action(&spend.material, WalletProofRoute::Smza)],
        );
        assert!(protocol_versioning::smallwood_poseidon2_production_capability().is_none());
        assert!(store
            .apply_poseidon2_v8_canonical_block(&block)
            .unwrap_err()
            .to_string()
            .contains("capability is disabled"));
        let context = retained_test_context(WalletProofRoute::Smza);
        for wrong_context in [
            Poseidon2V8RetainedTestContext {
                genesis_hash: [0x44; 32],
                ..context
            },
            Poseidon2V8RetainedTestContext {
                stablecoin_genesis_root: [7; 7],
                ..context
            },
            Poseidon2V8RetainedTestContext {
                activation_height: 4,
                deactivation_height_exclusive: 5,
                ..context
            },
            Poseidon2V8RetainedTestContext {
                deactivation_height_exclusive: 3,
                ..context
            },
            retained_test_context(WalletProofRoute::Smz9),
        ] {
            assert!(store
                .apply_poseidon2_v8_canonical_block_for_retained_test(&block, wrong_context)
                .is_err());
            assert_eq!(store.poseidon2_v8_tip().unwrap(), before_tip);
            assert_eq!(store.poseidon2_v8_owned_notes().unwrap(), before_notes);
        }
        drop(spend);
        drop(store);
        let reopened = WalletStore::open(&path, PASSPHRASE).unwrap();
        assert_eq!(reopened.poseidon2_v8_tip().unwrap(), before_tip);
        assert_eq!(reopened.poseidon2_v8_owned_notes().unwrap(), before_notes);
        let delta = reopened
            .apply_poseidon2_v8_canonical_block_for_retained_test(&block, context)
            .unwrap();
        assert_eq!(delta.recovered, 2);
        assert_eq!(delta.spent, 2);
    }

    #[test]
    fn retained_test_context_rejects_mismatched_source_and_unbounded_height() {
        let context = retained_test_context(WalletProofRoute::Smza);
        for (expected, profile, domain, genesis, stablecoin, start, end) in [
            (
                context.expected,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET,
                GENESIS,
                TEST_STABLECOIN_ROOT,
                1,
                4,
            ),
            (
                Poseidon2ProductionExpectedContext::new(
                    context.expected.network_id() + 1,
                    context.expected.relation_digest(),
                )
                .unwrap(),
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
                GENESIS,
                TEST_STABLECOIN_ROOT,
                1,
                4,
            ),
            (
                Poseidon2ProductionExpectedContext::new(context.expected.network_id(), [0x42; 48])
                    .unwrap(),
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
                GENESIS,
                TEST_STABLECOIN_ROOT,
                1,
                4,
            ),
            (
                context.expected,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
                [0; 32],
                TEST_STABLECOIN_ROOT,
                1,
                4,
            ),
            (
                context.expected,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
                GENESIS,
                [FIELD_MODULUS_U64; 7],
                1,
                4,
            ),
            (
                context.expected,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
                GENESIS,
                TEST_STABLECOIN_ROOT,
                4,
                4,
            ),
            (
                context.expected,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
                POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
                GENESIS,
                TEST_STABLECOIN_ROOT,
                1,
                u64::MAX,
            ),
        ] {
            assert!(Poseidon2V8RetainedTestContext::new(
                expected, profile, domain, genesis, stablecoin, start, end
            )
            .is_err());
        }
    }

    #[test]
    fn fresh_wallet_mirror_uses_shared_canonical_default_nodes() {
        let defaults = poseidon2_v8_default_note_nodes();
        assert_ne!(defaults[0], [0; 7]);

        let mut state = Poseidon2V8WalletState::default();
        state
            .ensure_genesis_for_test(GENESIS, TEST_STABLECOIN_ROOT)
            .unwrap();

        assert!(state.tree_levels[0].is_empty());
        for (level, expected) in defaults.iter().copied().enumerate().skip(1) {
            assert_eq!(state.tree_levels[level], vec![expected]);
        }
        assert_eq!(
            state.root_log,
            vec![defaults[SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH]]
        );
        assert_eq!(
            state.tip().unwrap().anchor,
            defaults[SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH]
        );
        state.validate().unwrap();
    }

    #[test]
    fn legacy_zero_default_wallet_mirror_is_rejected_without_mutation() {
        let mut legacy_defaults = [[0u64; 7]; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH + 1];
        for level in 0..SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH {
            legacy_defaults[level + 1] =
                poseidon2_v8_note_tree_compress(legacy_defaults[level], legacy_defaults[level]);
        }

        let mut state = Poseidon2V8WalletState::default();
        state
            .ensure_genesis_for_test(GENESIS, TEST_STABLECOIN_ROOT)
            .unwrap();
        state.tree_levels = Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH + 1);
        state.tree_levels.push(Vec::new());
        state.tree_levels.extend(
            legacy_defaults
                .iter()
                .copied()
                .skip(1)
                .map(|node| vec![node]),
        );
        state.root_log = vec![legacy_defaults[SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH]];
        let legacy_state = state.clone();

        for error in [
            state.validate().unwrap_err(),
            state.tip().unwrap_err(),
            state.owned_notes().unwrap_err(),
            state.rollback_to(0, GENESIS).unwrap_err(),
        ] {
            match error {
                WalletError::InvalidState(message) => {
                    assert_eq!(message, POSEIDON2_V8_DEFAULT_REPLAY_REQUIRED)
                }
                other => panic!("unexpected legacy mirror error: {other}"),
            }
            assert_eq!(state, legacy_state);
        }
    }

    #[test]
    fn owned_actions_survive_restart_build_spend_and_rollback_exactly() {
        owned_actions_survive_restart_for_route(WalletProofRoute::Smz9);
    }

    #[test]
    fn smza_owned_actions_survive_restart_build_spend_and_rollback_exactly() {
        owned_actions_survive_restart_for_route(WalletProofRoute::Smza);
    }

    fn owned_actions_survive_restart_for_route(route: WalletProofRoute) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.dat");
        let root = RootSecret::from_bytes([0x51; 32]);
        let store = WalletStore::create_from_root(&path, PASSPHRASE, root.clone()).unwrap();
        let funded_tip = seed_two_owned_coinbases(&store, &root);

        let funded_notes = store.poseidon2_v8_owned_notes().unwrap();
        assert_eq!(
            funded_notes
                .iter()
                .map(|note| note.position)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(funded_notes.iter().all(|note| {
            !note.spent
                && note.anchor == funded_tip.anchor
                && note.diversifier_index == SOURCE_DIVERSIFIER
        }));

        let spend =
            build_poseidon2_v8_wallet_self_spend(&store, [4, 7], &mut StdRng::seed_from_u64(103))
                .unwrap();
        assert_eq!(spend.tip, funded_tip);
        assert_eq!(spend.material.statement.merkle_root, funded_tip.anchor);
        assert_eq!(spend.material.statement.stablecoin.parent_height, 121);
        assert_eq!(funded_tip.stablecoin_root, Some(TEST_STABLECOIN_ROOT));
        assert_eq!(
            felt_digest_to_words(spend.material.statement.stablecoin.before_root),
            TEST_STABLECOIN_ROOT
        );
        assert_eq!(
            spend.material.statement.stablecoin.before_root,
            spend.material.statement.stablecoin.after_root
        );
        for input in 0..2 {
            assert_eq!(
                spend.material.witness.inputs[input].position,
                funded_notes[input].position
            );
            assert_eq!(
                spend.material.witness.inputs[input].siblings,
                funded_notes[input].path
            );
        }

        let transfer = transfer_action(&spend.material, route);
        assert_eq!(
            store
                .apply_poseidon2_v8_canonical_block_for_retained_test(
                    &canonical_block(122, BLOCK_3, BLOCK_2, vec![transfer],),
                    retained_test_context(route)
                )
                .unwrap(),
            Poseidon2V8SyncDelta {
                commitments: 2,
                ciphertexts: 2,
                recovered: 2,
                spent: 2,
            }
        );
        let spent_tip = store.poseidon2_v8_tip().unwrap();
        let spent_notes = store.poseidon2_v8_owned_notes().unwrap();
        assert_eq!(spent_notes.len(), 4);
        assert_eq!(
            spent_notes
                .iter()
                .map(|note| note.position)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(
            spent_notes
                .iter()
                .map(|note| note.spent)
                .collect::<Vec<_>>(),
            vec![true, true, false, false]
        );
        assert!(spent_notes
            .iter()
            .all(|note| note.anchor == spent_tip.anchor));
        let detached_output_commitment = spent_notes[2].commitment;
        assert_eq!(
            store
                .poseidon2_v8_canonical_commitment_positions(detached_output_commitment)
                .unwrap(),
            vec![2]
        );

        drop(spend);
        drop(store);
        let reopened = WalletStore::open(&path, PASSPHRASE).unwrap();
        assert_eq!(reopened.poseidon2_v8_tip().unwrap(), spent_tip);
        assert_eq!(reopened.poseidon2_v8_owned_notes().unwrap(), spent_notes);

        reopened.rollback_poseidon2_v8_to(121, BLOCK_2).unwrap();
        assert_eq!(reopened.poseidon2_v8_tip().unwrap(), funded_tip);
        assert!(reopened
            .poseidon2_v8_canonical_commitment_positions(detached_output_commitment)
            .unwrap()
            .is_empty());
        let rolled_back = reopened.poseidon2_v8_owned_notes().unwrap();
        assert_eq!(rolled_back.len(), 2);
        assert!(rolled_back.iter().all(|note| !note.spent));
        assert_eq!(
            rolled_back
                .iter()
                .map(|note| note.anchor)
                .collect::<Vec<_>>(),
            vec![funded_tip.anchor; 2]
        );

        reopened
            .apply_poseidon2_v8_canonical_block(&canonical_block(
                122,
                REPLACEMENT_3,
                BLOCK_2,
                Vec::new(),
            ))
            .unwrap();
        let replacement_tip = reopened.poseidon2_v8_tip().unwrap();
        assert_eq!(replacement_tip.block_hash, REPLACEMENT_3);
        assert_eq!(replacement_tip.anchor, funded_tip.anchor);
        drop(reopened);

        let reopened_again = WalletStore::open(&path, PASSPHRASE).unwrap();
        assert_eq!(reopened_again.poseidon2_v8_tip().unwrap(), replacement_tip);
        assert_eq!(
            reopened_again.poseidon2_v8_owned_notes().unwrap(),
            rolled_back
        );
    }

    #[test]
    fn intermediate_append_roots_are_accepted_then_exactly_evicted() {
        let mut state = Poseidon2V8WalletState::default();
        state
            .ensure_genesis_for_test(GENESIS, TEST_STABLECOIN_ROOT)
            .unwrap();
        let empty = empty_note_root();
        let duplicate = [9, 8, 7, 6, 5, 4, 3];
        assert_eq!(state.append_commitment(duplicate).unwrap(), 0);
        assert_eq!(
            state.canonical_commitment_positions(duplicate).unwrap(),
            vec![0]
        );
        let first_root = current_note_root(&state.tree_levels).unwrap();
        assert_eq!(state.append_commitment(duplicate).unwrap(), 1);
        assert_eq!(
            state.canonical_commitment_positions(duplicate).unwrap(),
            vec![0, 1]
        );
        let second_root = current_note_root(&state.tree_levels).unwrap();
        assert_ne!(first_root, second_root);
        assert!(accepted_note_roots(&state.root_log).contains(&first_root));

        for index in 0..99u64 {
            state
                .append_commitment([index + 100, 1, 2, 3, 4, 5, 6])
                .unwrap();
        }
        let accepted = accepted_note_roots(&state.root_log);
        assert_eq!(accepted.len(), POSEIDON2_V8_NOTE_ROOT_HISTORY_LIMIT);
        assert!(!accepted.contains(&empty));
        assert!(!accepted.contains(&first_root));
        assert!(accepted.contains(&second_root));
        state.append_commitment([999, 1, 2, 3, 4, 5, 6]).unwrap();
        assert!(!accepted_note_roots(&state.root_log).contains(&second_root));
        assert_eq!(
            state.tree_levels,
            note_levels(&state.tree_levels[0]).unwrap()
        );
        let (rebuilt_levels, rebuilt_log) = rebuild_note_tree(&state.tree_levels[0]).unwrap();
        assert_eq!(state.tree_levels, rebuilt_levels);
        assert_eq!(state.root_log, rebuilt_log);
    }

    #[test]
    fn action_id_commitment_and_relation_binding_mutations_fail_atomically() {
        action_mutations_fail_atomically_for_route(WalletProofRoute::Smz9);
        action_mutations_fail_atomically_for_route(WalletProofRoute::Smza);
    }

    fn action_mutations_fail_atomically_for_route(route: WalletProofRoute) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.dat");
        let root = RootSecret::from_bytes([0x51; 32]);
        let store = WalletStore::create_from_root(&path, PASSPHRASE, root.clone()).unwrap();
        store.ensure_poseidon2_v8_genesis(GENESIS).unwrap();
        let args = coinbase_args(&root, 41, 201);

        let mut bad_action_id = coinbase_action(&args);
        bad_action_id[0] ^= 1;
        assert!(store
            .apply_poseidon2_v8_canonical_block(&canonical_block(
                1,
                BLOCK_1,
                GENESIS,
                vec![bad_action_id],
            ))
            .is_err());
        assert_eq!(store.poseidon2_v8_tip().unwrap().height, 0);
        assert!(store.poseidon2_v8_owned_notes().unwrap().is_empty());

        let mut bad_args = args.clone();
        bad_args.miner_note.commitment[0] ^= 1;
        assert!(store
            .apply_poseidon2_v8_canonical_block(&canonical_block(
                1,
                BLOCK_1,
                GENESIS,
                vec![coinbase_action(&bad_args)],
            ))
            .is_err());
        assert_eq!(store.poseidon2_v8_tip().unwrap().height, 0);
        assert!(store.poseidon2_v8_owned_notes().unwrap().is_empty());

        let funded_tip = seed_two_owned_coinbases(&store, &root);
        let spend =
            build_poseidon2_v8_wallet_self_spend(&store, [4, 7], &mut StdRng::seed_from_u64(202))
                .unwrap();
        let mut wrong_binding = spend.material.statement.expected_action_intent().unwrap();
        wrong_binding[0] ^= 1;
        let bad_transfer = transfer_action_with_binding(&spend.material, wrong_binding, route);
        assert!(store
            .apply_poseidon2_v8_canonical_block_for_retained_test(
                &canonical_block(122, BLOCK_3, BLOCK_2, vec![bad_transfer],),
                retained_test_context(route)
            )
            .is_err());
        assert_eq!(store.poseidon2_v8_tip().unwrap(), funded_tip);
        assert!(store
            .poseidon2_v8_owned_notes()
            .unwrap()
            .iter()
            .all(|note| !note.spent));
    }

    #[cfg(feature = "private-spend-dev-artifacts")]
    mod moving_asset_reference_tests {
        use super::*;
        use transaction_circuit::{
            asset_spend_v1::AssetSpendPublic, asset_spend_v1_admission as admission,
            asset_spend_v1_wire as transport,
        };

        fn funded_parent() -> (Poseidon2V8WalletState, DerivedKeys) {
            let root = RootSecret::from_bytes([71; 32]);
            let keys = root.derive();
            let mut mirror = Poseidon2V8WalletState::default();
            mirror
                .ensure_genesis_for_test(GENESIS, TEST_STABLECOIN_ROOT)
                .unwrap();
            for height in 1..=134 {
                // Releases at 120, 123 and 135. H122 and P134 deliberately
                // have different block-end roots; the last reward follows the
                // three asset outputs in the inclusion block.
                let actions = if matches!(height, 1 | 4 | 16) {
                    vec![coinbase_action(&coinbase_args(&root, 1000, height))]
                } else {
                    Vec::new()
                };
                let parent = mirror.tip().unwrap();
                mirror
                    .apply_block(
                        &canonical_block(
                            height,
                            [(height + 32) as u8; 32],
                            parent.block_hash,
                            actions,
                        ),
                        Some(&keys),
                    )
                    .unwrap();
            }
            (mirror, keys)
        }

        fn statement(mirror: &Poseidon2V8WalletState) -> AssetSpendPublic {
            let fixture =
                crate::asset_spend_v1_fixture::DisposableAssetFixtureV1::build(0, 4).unwrap();
            let reference = mirror.canonical_tip_at_height(122).unwrap();
            let mut public = fixture.public.clone();
            public.parent_height = reference.height;
            public.reference_parent_hash = reference.block_hash;
            public.note_root = reference.anchor;
            public.nullifiers = [[31; 7], mirror.owned_notes[0].nullifier];
            public.commitments = [[9; 7], [10; 7], [11; 7]];
            public.ciphertext_commitments =
                [[7; 2608], [8; 2608], [9; 2608]].map(|c| ciphertext_hash_bytes(&c));
            public
        }

        fn asset_block(
            mirror: &Poseidon2V8WalletState,
            public: &AssetSpendPublic,
        ) -> Poseidon2V8CanonicalBlock {
            let binding = admission::NATIVE_VERSION_BINDING;
            let mut wire = PendingActionWire {
                tx_hash: [0; 48],
                binding: PendingVersionBinding {
                    circuit: binding.circuit,
                    crypto: binding.crypto,
                },
                family_id: FAMILY_SHIELDED_POOL,
                action_id: admission::ASSET_SPEND_ACTION_ID,
                anchor: [0; 48],
                nullifiers: Vec::new(),
                commitments: Vec::new(),
                ciphertext_hashes: public.ciphertext_commitments.to_vec(),
                ciphertext_sizes: vec![2608; 3],
                // Framing only: no proof authority or proof generation. These
                // bytes cannot pass the Development block proof verifier.
                public_args: transport::encode_native_asset_spend_action_v1(
                    public,
                    &[[7; 2608], [8; 2608], [9; 2608]],
                    b"SMZE",
                )
                .unwrap(),
                fee: public.fee,
                candidate_artifact: None,
            };
            wire.tx_hash = pending_action_hash(&wire);
            let parent = mirror.tip().unwrap();
            canonical_block(
                parent.height + 1,
                [201; 32],
                parent.block_hash,
                vec![wire.encode()],
            )
        }

        #[test]
        fn age_twelve_asset_applies_three_outputs_then_reward_and_rolls_back_exactly() {
            let (mut mirror, keys) = funded_parent();
            let public = statement(&mirror);
            let context =
                LaunchWalletContext::new(public.chain_id, GENESIS, [72; 64], 1, 1000).unwrap();
            let parent = mirror.tip().unwrap();
            let reference = mirror
                .canonical_tip_at_height(public.parent_height)
                .unwrap();
            assert_eq!((reference.height, parent.height), (122, 134));
            assert_ne!(reference.anchor, parent.anchor);
            let before = mirror.clone();
            let block = asset_block(&mirror, &public);
            let references = (122..=134)
                .map(|h| mirror.canonical_tip_at_height(h).unwrap())
                .collect::<Vec<_>>();
            let apply = |mirror: &mut Poseidon2V8WalletState| {
                mirror.apply_block_with_transfer_decoder(&block, Some(&keys), |wire| {
                    decode_native_asset_launch(wire, context, parent, &references)
                })
            };
            let delta = apply(&mut mirror).unwrap();
            assert_eq!(block.height, 135);
            assert_eq!(
                (delta.commitments, delta.ciphertexts, delta.spent),
                (4, 3, 1)
            );
            assert_eq!(&mirror.tree_levels[0][2..5], &public.commitments);
            assert_eq!(mirror.tree_levels[0].len(), 6);
            assert_eq!(mirror.owned_notes[0].spent_by, Some(block.hash));
            assert!(public
                .nullifiers
                .iter()
                .all(|n| mirror.has_canonical_nullifier(*n)));
            assert_eq!(mirror.canonical_tip_at_height(122).unwrap(), reference);
            assert!(mirror
                .recover_private_spend_block(
                    &block,
                    &keys,
                    &crate::private_spend::IssuedPrivateSpendAddresses::default(),
                    context,
                )
                .unwrap()
                .is_empty());
            mirror.validate().unwrap();
            // A later otherwise eligible reference cannot spend either shared
            // nullifier again. The current global state remains authoritative.
            let mut duplicate = public.clone();
            let now = mirror.tip().unwrap();
            duplicate.parent_height = now.height;
            duplicate.reference_parent_hash = now.block_hash;
            duplicate.note_root = now.anchor;
            let mut duplicate_block = asset_block(&mirror, &duplicate);
            duplicate_block.hash = [204; 32];
            let mut rejected = mirror.clone();
            assert!(matches!(
                rejected.apply_block_with_transfer_decoder(&duplicate_block, None, |_| {
                    Ok(DecodedPoseidon2V8Action::AssetSpend(duplicate.clone()))
                }),
                Err(WalletError::InvalidState(
                    "asset nullifier already exists in shared pool"
                ))
            ));
            assert_eq!(rejected, mirror);
            // Durable mirror serialization preserves the historical reference
            // and shared effects before rollback/replay of the same exact body.
            let serialized = bincode::serialize(&mirror).unwrap();
            let mut reopened: Poseidon2V8WalletState = bincode::deserialize(&serialized).unwrap();
            reopened.validate().unwrap();
            reopened
                .rollback_to(parent.height, parent.block_hash)
                .unwrap();
            assert_eq!(reopened, before);
            apply(&mut reopened).unwrap();
            assert_eq!(reopened, mirror);
        }

        #[test]
        fn shared_apply_rejects_expired_future_orphan_and_wrong_root_before_effects() {
            let (mirror, _) = funded_parent();
            let public = statement(&mirror);
            for mutation in 0..4 {
                let mut changed = public.clone();
                match mutation {
                    0 => changed.parent_height = 121, // P134 is age 13.
                    1 => changed.parent_height = 135,
                    2 => changed.reference_parent_hash = [202; 32],
                    _ => changed.note_root = [203; 7],
                }
                let block = asset_block(&mirror, &changed);
                let mut rejected = mirror.clone();
                // Intentionally bypass the earlier native reference decoder to
                // exercise the shared mirror's independent canonical guard.
                assert!(rejected
                    .apply_block_with_transfer_decoder(&block, None, |_| {
                        Ok(DecodedPoseidon2V8Action::AssetSpend(changed.clone()))
                    })
                    .is_err());
                assert_eq!(rejected, mirror);
            }
            // A reference whose H was replaced on a fork must not be accepted
            // merely because the replacement has the same block-end note root.
            let mut fork = mirror.clone();
            let ancestor = fork.canonical_tip_at_height(121).unwrap();
            fork.rollback_to(ancestor.height, ancestor.block_hash)
                .unwrap();
            for height in 122..=134 {
                let parent = fork.tip().unwrap();
                fork.apply_block(
                    &canonical_block(height, [(height + 80) as u8; 32], parent.block_hash, vec![]),
                    None,
                )
                .unwrap();
            }
            let before = fork.clone();
            let block = asset_block(&fork, &public);
            assert!(fork
                .apply_block_with_transfer_decoder(&block, None, |_| {
                    Ok(DecodedPoseidon2V8Action::AssetSpend(public.clone()))
                })
                .is_err());
            assert_eq!(fork, before);
        }
    }
}

impl Poseidon2V8WalletState {
    /// Local canonical occurrence metadata, not authentication of a supplied
    /// block's action body to its header. That body uses the trusted-node boundary.
    pub(crate) fn canonical_block_leaf_count_before(
        &self,
        height: u64,
        hash: [u8; 32],
    ) -> Option<u64> {
        self.blocks
            .iter()
            .find(|b| b.height == height && b.block_hash == hash)
            .and_then(|b| u64::try_from(b.leaf_count_before).ok())
    }
}

/// Exact native framing projection. This authenticates the action ID and all
/// outer-to-inner fields; canonical inclusion and node consensus are separate.
pub(crate) fn canonical_asset_action_body(
    encoded: &[u8],
) -> Result<Option<([u8; 48], Vec<u8>)>, WalletError> {
    let wire = decode_canonical_action_exact(encoded)?;
    use transaction_circuit::asset_spend_v1_admission as admission;
    if wire.family_id != FAMILY_SHIELDED_POOL
        || !matches!(
            wire.action_id,
            admission::ASSET_SPEND_ACTION_ID | admission::ASSET_ADMIN_ACTION_ID
        )
    {
        return Ok(None);
    }
    validate_native_asset_outer(&wire)?;
    if wire.action_id == admission::ASSET_ADMIN_ACTION_ID {
        return Ok(None);
    }
    Ok(Some((wire.tx_hash, wire.public_args)))
}
fn validate_native_asset_outer(wire: &PendingActionWire) -> Result<(), WalletError> {
    use transaction_circuit::{
        asset_spend_v1_admission as admission, asset_spend_v1_wire as transport,
    };
    let binding = admission::NATIVE_VERSION_BINDING;
    if wire.family_id != FAMILY_SHIELDED_POOL
        || wire.binding
            != (PendingVersionBinding {
                circuit: binding.circuit,
                crypto: binding.crypto,
            })
        || wire.anchor != [0; 48]
        || !wire.nullifiers.is_empty()
        || !wire.commitments.is_empty()
        || wire.candidate_artifact.is_some()
    {
        return Err(WalletError::InvalidState(
            "native asset outer identity or legacy state fields",
        ));
    }
    match wire.action_id {
        admission::ASSET_SPEND_ACTION_ID => {
            let d = transport::decode_native_asset_spend_action_v1(&wire.public_args)
                .map_err(|_| WalletError::InvalidState("native asset spend envelope"))?;
            if wire.fee != d.public.fee
                || wire.ciphertext_hashes != d.public.ciphertext_commitments
                || wire.ciphertext_sizes != [2608; 3]
            {
                return Err(WalletError::InvalidState(
                    "native asset ciphertext or fee projection",
                ));
            }
        }
        admission::ASSET_ADMIN_ACTION_ID => {
            transport::decode_native_asset_admin_action_v1(&wire.public_args)
                .map_err(|_| WalletError::InvalidState("native asset admin envelope"))?;
            if wire.fee != 0
                || !wire.ciphertext_hashes.is_empty()
                || !wire.ciphertext_sizes.is_empty()
            {
                return Err(WalletError::InvalidState(
                    "native asset admin carries pool effects",
                ));
            }
        }
        _ => return Err(WalletError::InvalidState("native asset action ID")),
    }
    Ok(())
}
fn decode_native_asset_launch(
    wire: PendingActionWire,
    context: LaunchWalletContext,
    parent: Poseidon2V8CanonicalTip,
    references: &[Poseidon2V8CanonicalTip],
) -> Result<DecodedPoseidon2V8Action, WalletError> {
    use transaction_circuit::{
        asset_spend_v1_admission as admission, asset_spend_v1_wire as transport,
    };
    validate_native_asset_outer(&wire)?;
    if wire.action_id == admission::ASSET_SPEND_ACTION_ID {
        let d = transport::decode_native_asset_spend_action_v1(&wire.public_args)
            .map_err(|_| WalletError::InvalidState("native asset spend framing"))?;
        let reference = references
            .iter()
            .find(|r| r.height == d.public.parent_height)
            .ok_or(WalletError::InvalidState(
                "native asset reference absent from canonical window",
            ))?;
        crate::asset_spend_rpc::require_reference_window(reference.height, parent.height)?;
        context.require_canonical_parent(context.genesis_hash(), reference.height)?;
        context.require_canonical_parent(context.genesis_hash(), parent.height)?;
        if d.public.chain_id != context.chain_id()
            || d.public.reference_parent_hash != reference.block_hash
            || d.public.note_root != reference.anchor
        {
            return Err(WalletError::InvalidState(
                "native asset spend chain or parent differs",
            ));
        }
        Ok(DecodedPoseidon2V8Action::AssetSpend(d.public))
    } else {
        let d = transport::decode_native_asset_admin_action_v1(&wire.public_args)
            .map_err(|_| WalletError::InvalidState("native asset admin framing"))?;
        let reference = references
            .iter()
            .find(|r| r.height == d.public.parent_height)
            .ok_or(WalletError::InvalidState(
                "native asset reference absent from canonical window",
            ))?;
        crate::asset_spend_rpc::require_reference_window(reference.height, parent.height)?;
        context.require_canonical_parent(context.genesis_hash(), reference.height)?;
        context.require_canonical_parent(context.genesis_hash(), parent.height)?;
        if d.public.chain_id != context.chain_id()
            || d.public.reference_parent_hash != reference.block_hash
            || d.public.expires_at < parent.height
        {
            return Err(WalletError::InvalidState(
                "native asset admin chain or parent differs",
            ));
        }
        Ok(DecodedPoseidon2V8Action::AssetAdmin)
    }
}
impl Poseidon2V8WalletState {
    pub(crate) fn canonical_block_leaf_count_after(
        &self,
        height: u64,
        hash: [u8; 32],
    ) -> Option<u64> {
        let index = self
            .blocks
            .iter()
            .position(|b| b.height == height && b.block_hash == hash)?;
        if let Some(next) = self.blocks.get(index + 1) {
            Some(next.leaf_count_before)
        } else {
            u64::try_from(self.tree_levels.first()?.len()).ok()
        }
    }
}

#[cfg(all(test, feature = "private-spend-dev-artifacts"))]
mod asset_projection_tests {
    use super::*;
    #[test]
    fn native_asset_projection_binds_all_three_ciphertexts_and_never_enables_generic_route() {
        use transaction_circuit::{
            asset_spend_v1_admission as admission, asset_spend_v1_wire as transport,
        };
        let fixture = crate::asset_spend_v1_fixture::DisposableAssetFixtureV1::build(0, 4).unwrap();
        let mut public = fixture.public.clone();
        public.commitments = [[9; 7], [10; 7], [11; 7]];
        let ciphertexts = [[7; 2608], [8; 2608], [9; 2608]];
        public.ciphertext_commitments = ciphertexts.map(|c| ciphertext_hash_bytes(&c));
        // Framing-only negative tests; these bytes cannot pass proof verification.
        let body =
            transport::encode_native_asset_spend_action_v1(&public, &ciphertexts, b"SMZE").unwrap();
        let binding = admission::NATIVE_VERSION_BINDING;
        let mut wire = PendingActionWire {
            tx_hash: [0; 48],
            binding: PendingVersionBinding {
                circuit: binding.circuit,
                crypto: binding.crypto,
            },
            family_id: FAMILY_SHIELDED_POOL,
            action_id: admission::ASSET_SPEND_ACTION_ID,
            anchor: [0; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: public.ciphertext_commitments.to_vec(),
            ciphertext_sizes: vec![2608; 3],
            public_args: body.clone(),
            fee: public.fee,
            candidate_artifact: None,
        };
        wire.tx_hash = pending_action_hash(&wire);
        let context =
            LaunchWalletContext::new(public.chain_id, [91; 32], [92; 64], 1, 1000).unwrap();
        let reference = Poseidon2V8CanonicalTip {
            height: public.parent_height,
            block_hash: public.reference_parent_hash,
            anchor: public.note_root,
            stablecoin_root: None,
        };
        let parent = Poseidon2V8CanonicalTip {
            height: reference.height + 12,
            block_hash: [93; 32],
            anchor: [94; 7],
            ..reference
        };
        let retained = wire.public_args.clone();
        assert!(matches!(
            decode_native_asset_launch(wire.clone(), context, parent, &[reference]).unwrap(),
            DecodedPoseidon2V8Action::AssetSpend(_)
        ));
        assert_eq!(wire.public_args, retained);
        let expired = Poseidon2V8CanonicalTip {
            height: parent.height + 1,
            ..parent
        };
        assert!(decode_native_asset_launch(wire.clone(), context, expired, &[reference]).is_err());
        let future = Poseidon2V8CanonicalTip {
            height: reference.height - 1,
            ..parent
        };
        assert!(decode_native_asset_launch(wire.clone(), context, future, &[reference]).is_err());
        let orphan = Poseidon2V8CanonicalTip {
            block_hash: [95; 32],
            ..reference
        };
        assert!(decode_native_asset_launch(wire.clone(), context, parent, &[orphan]).is_err());
        let wrong_root = Poseidon2V8CanonicalTip {
            anchor: [96; 7],
            ..reference
        };
        assert!(decode_native_asset_launch(wire.clone(), context, parent, &[wrong_root]).is_err());
        assert_eq!(
            canonical_asset_action_body(&wire.encode()).unwrap(),
            Some((wire.tx_hash, body))
        );
        assert!(
            decode_v8_action_exact(&wire.encode(), &|_| Err(WalletError::InvalidState(
                "source route absent"
            )))
            .is_err()
        );
        for field in 0..3 {
            let mut changed = wire.clone();
            match field {
                0 => changed.ciphertext_hashes[2][0] ^= 1,
                1 => changed.fee += 1,
                _ => changed.binding.crypto ^= 1,
            }
            changed.tx_hash = pending_action_hash(&changed);
            assert!(canonical_asset_action_body(&changed.encode()).is_err());
        }
        let mut changed = wire.encode();
        changed[0] ^= 1;
        assert!(canonical_asset_action_body(&changed).is_err());
    }
}

/// Exact fresh recovery projection; structural parsing alone is not authority.
pub(crate) fn canonical_recovery_action_body(
    encoded: &[u8],
) -> Result<Option<([u8; 48], u16, Vec<u8>)>, WalletError> {
    let wire = decode_canonical_action_exact(encoded)?;
    if wire.family_id != FAMILY_SHIELDED_POOL
        || !matches!(
            wire.action_id,
            RECOVERY_SPEND_ACTION_ID | RECOVERY_ADMIN_ACTION_ID
        )
    {
        return Ok(None);
    }
    validate_native_recovery_outer(&wire)?;
    Ok(Some((wire.tx_hash, wire.action_id, wire.public_args)))
}

fn validate_native_recovery_outer(w: &PendingActionWire) -> Result<(), WalletError> {
    use transaction_circuit::{asset_recovery_wire_v1 as wire, asset_spend_v1_admission as old};
    let v = old::NATIVE_VERSION_BINDING;
    if w.family_id != FAMILY_SHIELDED_POOL
        || w.binding
            != (PendingVersionBinding {
                circuit: v.circuit,
                crypto: v.crypto,
            })
        || w.anchor != [0; 48]
        || !w.nullifiers.is_empty()
        || !w.commitments.is_empty()
        || w.candidate_artifact.is_some()
    {
        return Err(WalletError::InvalidState(
            "recovery outer binding or legacy fields",
        ));
    }
    match w.action_id {
        RECOVERY_SPEND_ACTION_ID => {
            let d = wire::decode_spend_ref(&w.public_args)
                .map_err(|_| WalletError::InvalidState("recovery spend framing"))?;
            if w.fee != d.public.base.fee
                || w.ciphertext_hashes != d.public.base.ciphertext_commitments
                || w.ciphertext_sizes != [2608; 3]
            {
                return Err(WalletError::InvalidState("recovery spend outer metadata"));
            }
        }
        RECOVERY_ADMIN_ACTION_ID => {
            wire::decode_admin_ref(&w.public_args)
                .map_err(|_| WalletError::InvalidState("recovery admin framing"))?;
            if w.fee != 0 || !w.ciphertext_hashes.is_empty() || !w.ciphertext_sizes.is_empty() {
                return Err(WalletError::InvalidState("recovery admin pool effects"));
            }
        }
        _ => return Err(WalletError::InvalidState("recovery action ID")),
    }
    Ok(())
}
fn decode_native_recovery_launch(
    wire: PendingActionWire,
    context: LaunchWalletContext,
    parent: Poseidon2V8CanonicalTip,
    references: &[Poseidon2V8CanonicalTip],
) -> Result<DecodedPoseidon2V8Action, WalletError> {
    use transaction_circuit::asset_recovery_wire_v1 as transport;
    validate_native_recovery_outer(&wire)?;
    let (chain, height, hash, note, projection) = if wire.action_id == RECOVERY_SPEND_ACTION_ID {
        let d = transport::decode_spend_ref(&wire.public_args)
            .map_err(|_| WalletError::InvalidState("recovery spend framing"))?;
        let p = d.public.base;
        (
            p.chain_id,
            p.parent_height,
            p.reference_parent_hash,
            Some(p.note_root),
            DecodedPoseidon2V8Action::AssetSpend(p),
        )
    } else {
        let d = transport::decode_admin_ref(&wire.public_args)
            .map_err(|_| WalletError::InvalidState("recovery admin framing"))?;
        if d.public.expires_at < parent.height {
            return Err(WalletError::InvalidState("recovery admin expired"));
        }
        (
            d.public.context.chain_id,
            d.public.context.parent_height,
            d.public.context.parent_hash,
            None,
            DecodedPoseidon2V8Action::AssetAdmin,
        )
    };
    crate::asset_spend_rpc::require_reference_window(height, parent.height)?;
    let reference = references
        .iter()
        .find(|r| r.height == height)
        .ok_or(WalletError::InvalidState("recovery reference absent"))?;
    if chain != context.chain_id()
        || hash != reference.block_hash
        || note.is_some_and(|note| note != reference.anchor)
    {
        return Err(WalletError::InvalidState(
            "recovery canonical reference mismatch",
        ));
    }
    Ok(projection)
}

impl Poseidon2V8WalletState {
    /// Bridge already-projected native fee change without a second append.
    pub(crate) fn import_recovery_native_fee(
        &mut self,
        p: &crate::asset_spend_v1::AssetNotePayload,
        cm: Poseidon2V8Digest,
        position: u64,
        block: &Poseidon2V8CanonicalBlock,
        keys: &DerivedKeys,
    ) -> Result<(), WalletError> {
        let n = p.as_note();
        let opening = SmallwoodPoseidon2V8NoteOpening {
            value: n.value,
            asset_id: n.asset_id,
            recipient_key: n.recipient_key,
            authorization_key: n.authorization_key,
            rho: n.rho,
            randomness: n.randomness,
        };
        if n.asset_id != NATIVE_ASSET_ID || self.canonical_note_witness_at(cm, position)?.is_none()
        {
            return Err(WalletError::InvalidState("recovery native fee occurrence"));
        }
        if let Some(existing) = self.owned_notes.iter().find(|n| n.position == position) {
            if existing.commitment != cm
                || existing.opening_words != opening_to_words(opening)
                || existing.diversifier_index != p.recipient_index
            {
                return Err(WalletError::InvalidState(
                    "recovery native fee duplicate mismatch",
                ));
            }
            return Ok(());
        }
        self.insert_owned_note_at(opening, cm, p.recipient_index, position, block, keys)
    }
}

/// Archive discovery reads mandatory public capsules from the canonical carrier;
/// it does not depend on holder decryption or grant archive/delegate authority.
pub fn recovery_archive_capsules_from_canonical_action(
    encoded: &[u8],
) -> Result<
    Option<[transaction_circuit::asset_recovery_capsule_v1::AssetRecoveryCapsulePublicV1; 2]>,
    WalletError,
> {
    let Some((_, id, body)) = canonical_recovery_action_body(encoded)? else {
        return Ok(None);
    };
    if id != RECOVERY_SPEND_ACTION_ID {
        return Ok(None);
    }
    let d = transaction_circuit::asset_recovery_wire_v1::decode_spend_ref(&body)
        .map_err(|_| WalletError::InvalidState("archive recovery body"))?;
    Ok(Some(d.capsules.map(|c| c.public)))
}

#[cfg(test)]
mod recovery_decode_cap_tests {
    use super::*;

    #[test]
    fn ordinary_and_malformed_payloads_keep_eight_mib_limit() {
        for n in [
            0,
            8,
            104,
            MAX_CANONICAL_ACTION_BYTES,
            MAX_CANONICAL_ACTION_BYTES + 1,
        ] {
            let bytes = vec![0; n];
            assert_eq!(
                canonical_action_decode_limit(&bytes),
                MAX_CANONICAL_ACTION_BYTES
            );
            assert!(recovery_canonical_decode_limit(&bytes).is_none());
        }
        let bytes = vec![0; MAX_CANONICAL_ACTION_BYTES + 1];
        assert!(decode_canonical_action_exact(&bytes).is_err());
    }

    // Pure framing fixtures. SMZR/SMRC bodies below are deliberately NOT valid
    // cryptographic proofs and are never submitted to a proof verifier.
    #[cfg(feature = "private-spend-dev-artifacts")]
    fn maximum_structural_spend() -> PendingActionWire {
        use transaction_circuit::{
            asset_recovery_capsule_v1 as capsule, asset_recovery_spend_v1 as spend,
            asset_recovery_wire_v1 as wire,
        };
        fn framed(selector: u8, source: [u8; 64]) -> Vec<u8> {
            let mut b = vec![0; wire::MAX_PROOF_BYTES];
            b[..4].copy_from_slice(b"SMZR");
            b[4..6].copy_from_slice(&1u16.to_le_bytes());
            b[6] = selector;
            b[8..72].copy_from_slice(&source);
            let inner_len = (b.len() - 80) as u32;
            b[72..76].copy_from_slice(&inner_len.to_le_bytes());
            b[80..84].copy_from_slice(b"SMZE");
            b
        }
        let (mut public, _) =
            spend::fixtures::fixture(transaction_circuit::asset_spend_v1::TRANSFER, false).unwrap();
        let ciphertexts = [
            [1; wire::CIPHERTEXT_BYTES],
            [2; wire::CIPHERTEXT_BYTES],
            [3; wire::CIPHERTEXT_BYTES],
        ];
        public.base.ciphertext_commitments =
            ciphertexts.each_ref().map(|c| ciphertext_hash_bytes(c));
        let caps: [_; 2] = core::array::from_fn(|i| capsule::AssetRecoveryCapsulePublicV1 {
            chain_id: public.base.chain_id,
            asset_id: public.base.asset_id,
            stable_policy_id: public.row.descriptor.stable_policy_id,
            archive_key_commitment: public.row.descriptor.archive_key_commitment,
            note_commitment: public.base.commitments[i],
            ciphertext: [i as u8; capsule::CIPHERTEXT_BYTES],
        });
        let mut bundle = b"SMRC".to_vec();
        bundle.extend(1u16.to_le_bytes());
        bundle.extend([2, 0]);
        for _ in 0..2 {
            bundle.extend((wire::MAX_PROOF_BYTES as u32).to_le_bytes());
        }
        for i in 0..2 {
            bundle.extend(framed(
                2,
                capsule::segment_relation_digest(capsule::relation_digest(), i).unwrap(),
            ));
        }
        let body = wire::encode_spend(
            &public,
            &ciphertexts,
            &framed(1, spend::relation_digest()),
            [(&caps[0], bundle.as_slice()), (&caps[1], bundle.as_slice())],
        )
        .unwrap();
        assert_eq!(body.len(), wire::MAX_SPEND_ACTION_BYTES);
        let mut action = PendingActionWire {
            tx_hash: [0; 48],
            binding: PendingVersionBinding {
                circuit: transaction_circuit::asset_spend_v1_admission::NATIVE_VERSION_BINDING
                    .circuit,
                crypto: transaction_circuit::asset_spend_v1_admission::NATIVE_VERSION_BINDING
                    .crypto,
            },
            family_id: FAMILY_SHIELDED_POOL,
            action_id: RECOVERY_SPEND_ACTION_ID,
            anchor: [0; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: public.base.ciphertext_commitments.to_vec(),
            ciphertext_sizes: vec![wire::CIPHERTEXT_BYTES as u32; 3],
            public_args: body,
            fee: public.base.fee,
            candidate_artifact: None,
        };
        action.tx_hash = pending_action_hash(&action);
        action
    }

    #[cfg(feature = "private-spend-dev-artifacts")]
    #[test]
    fn maximum_recovery_envelope_exact_decode_is_structural_only() {
        use transaction_circuit::asset_recovery_wire_v1 as wire;
        let action = maximum_structural_spend();
        let bytes = action.encode();
        let limit = wire::MAX_SPEND_ACTION_BYTES + RECOVERY_SPEND_CANONICAL_OUTER_BYTES;
        assert!(bytes.len() > MAX_CANONICAL_ACTION_BYTES);
        assert_eq!(bytes.len(), limit);
        assert_eq!(recovery_canonical_decode_limit(&bytes), Some(limit));
        assert_eq!(decode_canonical_action_exact(&bytes).unwrap(), action);
        for index in [
            48,
            52,
            54,
            56,
            104,
            105,
            106,
            107,
            251,
            252,
            bytes.len() - 9,
            bytes.len() - 1,
        ] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(
                recovery_canonical_decode_limit(&changed).is_none(),
                "index {index}"
            );
            assert_eq!(
                canonical_action_decode_limit(&changed),
                MAX_CANONICAL_ACTION_BYTES
            );
        }
        let mut nonminimal = bytes.clone();
        nonminimal.splice(104..105, [1, 0]); // Two-byte encoding of empty nullifiers.
        assert!(recovery_canonical_decode_limit(&nonminimal).is_none());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(recovery_canonical_decode_limit(&trailing).is_none());
        for end in [0, 55, 104, 264, bytes.len() - 1] {
            assert!(recovery_canonical_decode_limit(&bytes[..end]).is_none());
        }
        let mut bad_hash = bytes;
        bad_hash[0] ^= 1;
        assert!(decode_canonical_action_exact(&bad_hash).is_err());
    }
}
