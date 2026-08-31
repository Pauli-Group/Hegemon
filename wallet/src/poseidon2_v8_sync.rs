//! Durable wallet mirror for canonical SmallWood/Poseidon2 V8 block actions.
//!
//! The V8 lane has seven-limb commitments, roots, and nullifiers.  None of
//! these values are projected through the historical 48-byte wallet tree.

#![forbid(unsafe_code)]

use codec::{Decode, DecodeWithMemLimit, DecodeWithMemTracking, Encode};
use hegemon_hash384::{blake2b_384_domain_hash, domains};
use protocol_shielded_pool::{
    family::{
        ACTION_MINT_POSEIDON2_V8_COINBASE, ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
        FAMILY_SHIELDED_POOL,
    },
    poseidon2_production_transport::{
        decode_poseidon2_production_smz9_inline_args_exact, Poseidon2ProductionExpectedContext,
        POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES, POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID,
        POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID, POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID,
        POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET, POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID,
    },
    poseidon2_v8_coinbase::{MintPoseidon2V8CoinbaseArgs, POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES},
    types::CandidateArtifact,
};
use serde::{Deserialize, Serialize};
use transaction_circuit::{
    constants::{FIELD_MODULUS_U64, MAX_IN_CIRCUIT_VALUE, NATIVE_ASSET_ID},
    hashing_pq::ciphertext_hash_bytes,
    smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_note_commitment, poseidon2_v8_note_tree_compress,
        poseidon2_v8_words_from_canonical_bytes,
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

const MAX_CANONICAL_ACTION_BYTES: usize = 8 * 1024 * 1024;
const NOTE_OPENING_WORDS: usize = 18;
const POSEIDON2_V8_NOTE_ROOT_HISTORY_LIMIT: usize = 100;

pub type Poseidon2V8Digest = SmallwoodPoseidon2V8Digest;
pub type Poseidon2V8Path = [Poseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH];

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
    Transfer {
        statement: SmallwoodPoseidon2V8PublicStatement,
        ciphertexts: [Option<[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES]>; 2],
    },
    Coinbase(MintPoseidon2V8CoinbaseArgs),
}

impl Poseidon2V8WalletState {
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn ensure_genesis(&mut self, genesis_hash: [u8; 32]) -> Result<(), WalletError> {
        match self.genesis_hash {
            None => {
                let stablecoin_root = production_stablecoin_genesis(genesis_hash)?;
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

    pub(crate) fn tip(&self) -> Result<Poseidon2V8CanonicalTip, WalletError> {
        let genesis = self.genesis_hash.ok_or(WalletError::InvalidState(
            "V8 wallet mirror is not initialized",
        ))?;
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

    pub(crate) fn owned_notes(&self) -> Result<Vec<Poseidon2V8OwnedNoteView>, WalletError> {
        let anchor = current_note_root(&self.tree_levels)?;
        self.owned_notes
            .iter()
            .map(|note| {
                let path = note_path_from_levels(&self.tree_levels, note.position)?;
                stored_note_view(note, path, anchor)
            })
            .collect()
    }

    pub(crate) fn spend_context(&self) -> Result<Poseidon2V8SpendContext, WalletError> {
        let tip = self.tip()?;
        let notes = self
            .owned_notes
            .iter()
            .filter(|note| note.spent_by.is_none())
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
            self.owned_notes
                .retain(|note| note.created_block_hash != detached.block_hash);
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
            let Some(action) = decode_v8_action_exact(encoded)? else {
                continue;
            };
            match action {
                DecodedPoseidon2V8Action::Coinbase(args) => {
                    let commitment = args.miner_note.commitment;
                    self.append_commitment(commitment)?;
                    delta.commitments = delta.commitments.saturating_add(1);
                    delta.ciphertexts = delta.ciphertexts.saturating_add(1);
                    if let Some(keys) = keys {
                        if let Some((opening, diversifier_index)) =
                            recover_coinbase_note(&args, keys)?
                        {
                            self.insert_owned_note(
                                opening,
                                commitment,
                                diversifier_index,
                                block,
                                keys,
                            )?;
                            delta.recovered = delta.recovered.saturating_add(1);
                        }
                    }
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
        });
        self.validate_tip()?;
        Ok(delta)
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

    fn insert_owned_note(
        &mut self,
        opening: SmallwoodPoseidon2V8NoteOpening,
        commitment: Poseidon2V8Digest,
        diversifier_index: u32,
        block: &Poseidon2V8CanonicalBlock,
        keys: &DerivedKeys,
    ) -> Result<(), WalletError> {
        let position = self
            .tree_levels
            .first()
            .map(Vec::len)
            .and_then(|value| value.checked_sub(1))
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(WalletError::InvalidState("V8 owned note position missing"))?;
        self.insert_owned_note_at(
            opening,
            commitment,
            diversifier_index,
            position,
            block,
            keys,
        )
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
            created_height: block.height,
            created_block_hash: block.hash,
        });
        Ok(())
    }

    fn validate_tip(&self) -> Result<(), WalletError> {
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
        if self.genesis_hash.is_none()
            && (!self.blocks.is_empty()
                || !self.tree_levels.is_empty()
                || !self.root_log.is_empty()
                || self.stablecoin_root.is_some()
                || !self.owned_notes.is_empty()
                || !self.nullifiers.is_empty())
        {
            return Err(WalletError::InvalidState(
                "uninitialized V8 mirror contains state",
            ));
        }
        if self.genesis_hash.is_none() {
            return Ok(());
        }
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
}

fn decode_v8_action_exact(encoded: &[u8]) -> Result<Option<DecodedPoseidon2V8Action>, WalletError> {
    let wire = decode_canonical_action_exact(encoded)?;
    if wire.family_id != FAMILY_SHIELDED_POOL {
        return Ok(None);
    }
    match wire.action_id {
        ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE => decode_v8_transfer(wire).map(Some),
        ACTION_MINT_POSEIDON2_V8_COINBASE => decode_v8_coinbase(wire).map(Some),
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

fn decode_canonical_action_exact(encoded: &[u8]) -> Result<PendingActionWire, WalletError> {
    if encoded.len() > MAX_CANONICAL_ACTION_BYTES {
        return Err(WalletError::Serialization(
            "canonical action exceeds wallet decode limit".into(),
        ));
    }
    let mut cursor = encoded;
    let wire = PendingActionWire::decode_with_mem_limit(&mut cursor, MAX_CANONICAL_ACTION_BYTES)
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

fn decode_v8_transfer(wire: PendingActionWire) -> Result<DecodedPoseidon2V8Action, WalletError> {
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
    let expected = poseidon2_v8_expected_context()?;
    let decoded = decode_poseidon2_production_smz9_inline_args_exact(expected, &wire.public_args)
        .map_err(|error| {
        WalletError::Serialization(format!("decode V8 transfer action: {error}"))
    })?;
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
            .expect("SMZ9 fixes the seven-limb relation binding")
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
    let expected_binding: PendingVersionBinding =
        protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into();
    if wire.binding != expected_binding
        || wire.anchor != [0; 48]
        || !wire.nullifiers.is_empty()
        || !wire.commitments.is_empty()
        || wire.candidate_artifact.is_some()
        || wire.fee != 0
        || wire.ciphertext_hashes.len() != 1
        || wire.ciphertext_sizes.len() != 1
        || wire.public_args.len() != POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES
    {
        return Err(WalletError::Serialization(
            "noncanonical V8 coinbase outer state".into(),
        ));
    }
    let mut cursor = wire.public_args.as_slice();
    let args = MintPoseidon2V8CoinbaseArgs::decode(&mut cursor).map_err(|error| {
        WalletError::Serialization(format!("decode V8 coinbase action: {error}"))
    })?;
    if !cursor.is_empty() || args.encode() != wire.public_args {
        return Err(WalletError::Serialization(
            "noncanonical V8 coinbase action encoding".into(),
        ));
    }
    let opening = protocol_opening_to_relation(args.miner_note.opening);
    if opening.value == 0
        || u128::from(opening.value) > MAX_IN_CIRCUIT_VALUE
        || opening.asset_id != NATIVE_ASSET_ID
        || opening.recipient_key == [0; 4]
        || opening.authorization_key == [0; 4]
        || opening_words(opening)
            .into_iter()
            .any(|word| word >= FIELD_MODULUS_U64)
        || poseidon2_v8_note_commitment(opening)
            .map_err(|_| WalletError::Serialization("invalid V8 coinbase opening".into()))?
            != args.miner_note.commitment
    {
        return Err(WalletError::Serialization(
            "invalid V8 coinbase note commitment".into(),
        ));
    }
    let ciphertext = NoteCiphertext::from_chain_bytes(&args.miner_note.encrypted_note.encode())?;
    let raw = ciphertext.to_da_bytes()?;
    if wire.ciphertext_sizes[0] != u32::try_from(raw.len()).unwrap_or(u32::MAX)
        || wire.ciphertext_hashes[0] != ciphertext_hash_bytes(&raw)
    {
        return Err(WalletError::Serialization(
            "V8 coinbase ciphertext metadata mismatch".into(),
        ));
    }
    Ok(DecodedPoseidon2V8Action::Coinbase(args))
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

fn poseidon2_v8_expected_context() -> Result<Poseidon2ProductionExpectedContext, WalletError> {
    Poseidon2ProductionExpectedContext::new(
        protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID,
        *SmallwoodPoseidon2V8SourceRelationFactory.expected_relation_digest(),
    )
    .map_err(|error| WalletError::Serialization(format!("invalid V8 context: {error}")))
}

fn recover_coinbase_note(
    args: &MintPoseidon2V8CoinbaseArgs,
    keys: &DerivedKeys,
) -> Result<Option<(SmallwoodPoseidon2V8NoteOpening, u32)>, WalletError> {
    let ciphertext = NoteCiphertext::from_chain_bytes(&args.miner_note.encrypted_note.encode())?;
    let material = keys.poseidon2_v8_address(ciphertext.diversifier_index)?;
    let Ok(plaintext) = ciphertext.decrypt(&material) else {
        return Ok(None);
    };
    let opening = recovered_opening(&plaintext, &material)?;
    let Ok(recomputed) = poseidon2_v8_note_commitment(opening) else {
        return Ok(None);
    };
    if opening != protocol_opening_to_relation(args.miner_note.opening)
        || recomputed != args.miner_note.commitment
    {
        return Ok(None);
    }
    Ok(Some((opening, ciphertext.diversifier_index)))
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
    Ok(SmallwoodPoseidon2V8NoteOpening {
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
    })
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
                SmallwoodPoseidon2V8HashCallRole::InputNullifier { input: 0 }
            )
        })
        .map(|call| call.final_digest())
        .ok_or(WalletError::InvalidState("V8 nullifier hash call missing"))
}

fn default_note_nodes() -> [Poseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH + 1] {
    let mut nodes = [[0u64; 7]; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH + 1];
    for level in 0..SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH {
        nodes[level + 1] = poseidon2_v8_note_tree_compress(nodes[level], nodes[level]);
    }
    nodes
}

fn empty_note_root() -> Poseidon2V8Digest {
    default_note_nodes()[SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH]
}

fn production_stablecoin_genesis(
    genesis_hash: [u8; 32],
) -> Result<Option<Poseidon2V8Digest>, WalletError> {
    let Some(capability) = protocol_versioning::smallwood_poseidon2_production_capability() else {
        return Ok(None);
    };
    let source_digest = *SmallwoodPoseidon2V8SourceRelationFactory.expected_relation_digest();
    if !capability.active_at(capability.activation_height())
        || capability.binding()
            != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING
        || capability.network_id() != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID
        || capability.relation_digest() != source_digest
        || capability.family_id() != POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID
        || capability.action_id() != POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID
        || capability.coinbase_action_id() != ACTION_MINT_POSEIDON2_V8_COINBASE
        || capability.backend_id() != POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID
        || capability.proof_profile_id() != POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID
        || capability.domain_set() != POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET
        || capability.activation_genesis_hash() != genesis_hash
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
    let defaults = default_note_nodes();
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
    let defaults = default_note_nodes();
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
    let defaults = default_note_nodes();
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

fn opening_to_words(opening: SmallwoodPoseidon2V8NoteOpening) -> [u64; NOTE_OPENING_WORDS] {
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

fn words_to_opening(
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
mod tests {
    use rand::{rngs::StdRng, SeedableRng};
    use tempfile::tempdir;

    use protocol_shielded_pool::poseidon2_production_transport::{
        encode_poseidon2_production_smz9_envelope, encode_poseidon2_production_smz9_inline_args,
        encode_poseidon2_production_smz9_native_leaf,
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
    ) -> Vec<u8> {
        let expected = poseidon2_v8_expected_context().unwrap();
        let ciphertexts = [
            material.inline_ciphertexts.ciphertexts[0].as_ref(),
            material.inline_ciphertexts.ciphertexts[1].as_ref(),
        ];
        let mut proof = vec![0xa5; 64];
        proof[..4].copy_from_slice(b"SMZ9");
        let native_leaf = encode_poseidon2_production_smz9_native_leaf(
            expected,
            &material.statement.to_public_words(),
            &relation_binding,
            ciphertexts,
            &proof,
        )
        .unwrap();
        let envelope = encode_poseidon2_production_smz9_envelope(expected, &native_leaf).unwrap();
        encode_poseidon2_production_smz9_inline_args(expected, &envelope).unwrap()
    }

    fn transfer_action_with_binding(
        material: &Poseidon2V8SpendMaterial,
        relation_binding: Poseidon2V8Digest,
    ) -> Vec<u8> {
        let inline_args = transfer_inline_args(material, relation_binding);
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

    fn transfer_action(material: &Poseidon2V8SpendMaterial) -> Vec<u8> {
        transfer_action_with_binding(
            material,
            material.statement.expected_action_intent().unwrap(),
        )
    }

    fn seed_two_owned_coinbases(store: &WalletStore, root: &RootSecret) -> Poseidon2V8CanonicalTip {
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
                commitments: 1,
                ciphertexts: 1,
                recovered: 1,
                spent: 0,
            }
        );
        assert_eq!(
            store
                .apply_poseidon2_v8_canonical_block(&canonical_block(
                    2,
                    BLOCK_2,
                    BLOCK_1,
                    vec![coinbase_action(&second)],
                ))
                .unwrap(),
            Poseidon2V8SyncDelta {
                commitments: 1,
                ciphertexts: 1,
                recovered: 1,
                spent: 0,
            }
        );
        store.poseidon2_v8_tip().unwrap()
    }

    #[test]
    fn owned_actions_survive_restart_build_spend_and_rollback_exactly() {
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
        assert_eq!(spend.material.statement.stablecoin.parent_height, 2);
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

        let transfer = transfer_action(&spend.material);
        assert_eq!(
            store
                .apply_poseidon2_v8_canonical_block(&canonical_block(
                    3,
                    BLOCK_3,
                    BLOCK_2,
                    vec![transfer],
                ))
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

        drop(store);
        let reopened = WalletStore::open(&path, PASSPHRASE).unwrap();
        assert_eq!(reopened.poseidon2_v8_tip().unwrap(), spent_tip);
        assert_eq!(reopened.poseidon2_v8_owned_notes().unwrap(), spent_notes);

        reopened.rollback_poseidon2_v8_to(2, BLOCK_2).unwrap();
        assert_eq!(reopened.poseidon2_v8_tip().unwrap(), funded_tip);
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
                3,
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
        let first_root = current_note_root(&state.tree_levels).unwrap();
        assert_eq!(state.append_commitment(duplicate).unwrap(), 1);
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
        let bad_transfer = transfer_action_with_binding(&spend.material, wrong_binding);
        assert!(store
            .apply_poseidon2_v8_canonical_block(&canonical_block(
                3,
                BLOCK_3,
                BLOCK_2,
                vec![bad_transfer],
            ))
            .is_err());
        assert_eq!(store.poseidon2_v8_tip().unwrap(), funded_tip);
        assert!(store
            .poseidon2_v8_owned_notes()
            .unwrap()
            .iter()
            .all(|note| !note.spent));
    }
}
