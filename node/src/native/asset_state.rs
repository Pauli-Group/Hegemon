//! Candidate registry/admin replay state beside the canonical native V8 pool.
//!
//! There is deliberately no note tree or spent-nullifier database here. The
//! caller supplies the authenticated canonical parent note root and reads the
//! SAME global nullifier set used by native HGN. Verified spend effects must be
//! applied by the native pool plan in the SAME transaction as these rows and
//! the canonical block pointer. This module opens no database, flushes no rows,
//! registers no runtime issuer and grants no production authority.
#![allow(dead_code)]
#![forbid(unsafe_code)]

use super::asset_recovery_state::{RecoveryCanonicalContextV1, RecoveryLedgerStateV1};
use sha2::{Digest as _, Sha384};
use std::collections::BTreeSet;
use transaction_circuit::{
    asset_policy_admin_v1 as admin, asset_spend_v1 as spend,
    asset_spend_v1_admission::{self as admission, NativeAssetContextV1},
};
use transaction_core::{
    asset_registry_v1::{
        AssetOperationV1, AssetPolicyV1, AssetRegistryErrorV1, AssetRegistryV1,
        ASSET_REGISTRY_CAP_V1,
    },
    poseidon2_width16::{Felt, POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER},
    stablecoin_poseidon2_v8::StablecoinPoseidon2V8Counters,
};

pub(crate) use transaction_circuit::asset_spend_v1_admission::{
    decode_asset_policy_row, encode_asset_policy_row, ASSET_POLICY_ROW_BYTES_V1,
};
pub(crate) const MAX_ASSET_ADMIN_IDS_V1: usize = 65_536;
pub(crate) const MAX_ASSET_ACTIONS_PER_BLOCK_V1: usize = 512;
const MAGIC: &[u8; 8] = b"HGANST01";
const COMPOSITE_MAGIC: &[u8; 8] = b"HGANST02";
const COMPOSITE_HEADER_BYTES: usize = 144;
const MAX_RECOVERY_STATE_BYTES: usize = 128 * 1024 * 1024;
const HEADER_BYTES: usize = 196;
const MAX_STATE_BYTES: usize =
    HEADER_BYTES + ASSET_REGISTRY_CAP_V1 * ASSET_POLICY_ROW_BYTES_V1 + MAX_ASSET_ADMIN_IDS_V1 * 32;
const P: u64 = 0xffff_ffff_0000_0001;
type Digest = [u64; 7];

#[derive(Debug)]
pub(crate) enum AssetStateErrorV1 {
    Codec(&'static str),
    Registry(AssetRegistryErrorV1),
    RowCodec(admission::AssetPolicyRowCodecErrorV1),
    Proof(String),
    Context,
    PolicyFields,
    NativeNullifierSpent,
    DuplicateNullifier,
    AdminReplay,
    Limits,
    FeeOverflow,
    GenesisSupply,
    CanonicalReadback,
    Recovery(String),
}
impl From<AssetRegistryErrorV1> for AssetStateErrorV1 {
    fn from(error: AssetRegistryErrorV1) -> Self {
        Self::Registry(error)
    }
}
impl From<admission::AssetPolicyRowCodecErrorV1> for AssetStateErrorV1 {
    fn from(error: admission::AssetPolicyRowCodecErrorV1) -> Self {
        Self::RowCodec(error)
    }
}
impl core::fmt::Display for AssetStateErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native candidate asset state: {self:?}")
    }
}
impl std::error::Error for AssetStateErrorV1 {}

fn words(digest: [Felt; 7]) -> Digest {
    digest.map(|word| word.as_canonical_u64())
}
fn canonical(digest: &Digest) -> bool {
    digest.iter().all(|word| *word < P)
}
fn nonzero(digest: &Digest) -> bool {
    canonical(digest) && *digest != [0; 7]
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], AssetStateErrorV1> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or(AssetStateErrorV1::Codec("length overflow"))?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AssetStateErrorV1::Codec("truncated"))?;
        self.cursor = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], AssetStateErrorV1> {
        Ok(self.take(N)?.try_into().expect("fixed width"))
    }
    fn u32(&mut self) -> Result<u32, AssetStateErrorV1> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, AssetStateErrorV1> {
        let word = u64::from_le_bytes(self.array()?);
        if word >= P {
            return Err(AssetStateErrorV1::Codec("noncanonical field word"));
        }
        Ok(word)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AssetCanonicalContextV1 {
    pub chain_id: [u8; 32],
    pub reference_parent_hash: [u8; 32],
    pub parent_height: u64,
    /// Authenticated canonical native parent root, never an asset-owned tree.
    pub note_root: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AssetRegistryStateV1 {
    registry: AssetRegistryV1,
    assets: Vec<u32>,
    admin_action_ids: BTreeSet<[u8; 32]>,
    recovery: Option<RecoveryLedgerStateV1>,
}

pub(crate) enum AssetReplayActionV1<'a> {
    Spend(&'a [u8]),
    Controls(&'a [u8]),
}

#[derive(Clone, Debug)]
pub(crate) enum AssetVerifiedEffectV1 {
    Spend {
        nullifiers: [Digest; 2],
        commitments: [Digest; 3],
        ciphertexts: [[u8; 2608]; 3],
        native_fee: u64,
        released_secret: Option<[u8; 32]>,
    },
    Controls {
        asset_id: u32,
        admin_action_id: [u8; 32],
    },
}

/// Proof-verified staging only. Its effects MUST be incorporated into the
/// shared native pool plan before atomic application. Registry-row CAS alone
/// is never a complete block transition or native fee/nullifier authorization.
#[derive(Clone, Debug)]
pub(crate) struct AssetStatePlanV1 {
    before: Vec<u8>,
    after: Vec<u8>,
    projected: AssetRegistryStateV1,
    effects: Vec<AssetVerifiedEffectV1>,
    native_fee: u64,
}
impl AssetStatePlanV1 {
    pub(crate) fn projected_state(&self) -> &AssetRegistryStateV1 {
        &self.projected
    }
    pub(crate) fn effects(&self) -> &[AssetVerifiedEffectV1] {
        &self.effects
    }
    pub(crate) fn native_fee(&self) -> u64 {
        self.native_fee
    }
    pub(crate) fn before_bytes(&self) -> &[u8] {
        &self.before
    }
    pub(crate) fn after_bytes(&self) -> &[u8] {
        &self.after
    }
}

impl AssetRegistryStateV1 {
    /// Rows must come from the selected, authenticated Development manifest.
    /// All supply counters start at zero; this creates no funded note.
    pub(crate) fn from_genesis_rows(
        chain_id: [u8; 32],
        rows: &[AssetPolicyV1],
    ) -> Result<Self, AssetStateErrorV1> {
        if rows
            .iter()
            .any(|row| row.counters != StablecoinPoseidon2V8Counters::default())
        {
            return Err(AssetStateErrorV1::GenesisSupply);
        }
        let registry = AssetRegistryV1::from_rows(chain_id, 0, rows)?;
        let mut assets = rows
            .iter()
            .map(|row| row.config.asset_id)
            .collect::<Vec<_>>();
        assets.sort_unstable();
        Ok(Self {
            registry,
            assets,
            admin_action_ids: BTreeSet::new(),
            recovery: None,
        })
    }
    /// Authenticated fresh manifest only. There is no post-issuance opt-in API.
    pub(crate) fn from_genesis_rows_with_recovery(
        chain_id: [u8; 32],
        rows: &[AssetPolicyV1],
        initial: &[transaction_core::asset_recovery_v1::RecoveryRowV1],
    ) -> Result<Self, AssetStateErrorV1> {
        let mut state = Self::from_genesis_rows(chain_id, rows)?;
        state.recovery = Some(
            RecoveryLedgerStateV1::from_genesis_rows(&chain_id, rows, initial)
                .map_err(|e| AssetStateErrorV1::Recovery(e.to_string()))?,
        );
        state.validate_recovery_binding()?;
        Ok(state)
    }
    pub(crate) fn recovery(&self) -> Option<&RecoveryLedgerStateV1> {
        self.recovery.as_ref()
    }
    /// Registration is only for outputs already verified by the shared native
    /// transition. Recovery rows remain private to the proof-checking module.
    pub(crate) fn recovery_mut(&mut self) -> Option<&mut RecoveryLedgerStateV1> {
        self.recovery.as_mut()
    }
    pub(crate) fn require_legacy_spend_allowed(&self, asset: u32) -> Result<(), AssetStateErrorV1> {
        if self.recovery.as_ref().is_some_and(|s| s.is_opted(asset)) {
            return Err(AssetStateErrorV1::PolicyFields);
        }
        Ok(())
    }
    fn require_legacy_controls_allowed(&self, asset: u32, credential_depth: u8) -> Result<(), AssetStateErrorV1> {
        if self.recovery.as_ref().is_some_and(|s| s.is_opted(asset)) && credential_depth != 4 {
            return Err(AssetStateErrorV1::PolicyFields);
        }
        Ok(())
    }
    fn validate_recovery_binding(&self) -> Result<(), AssetStateErrorV1> {
        if let Some(recovery) = &self.recovery {
            let ctx = self.registry.context();
            if recovery.chain_id() != ctx.chain_id || recovery.parent_height() != ctx.parent_height
            {
                return Err(AssetStateErrorV1::Context);
            }
            for row in recovery.rows() {
                let current = self.registry.row(row.descriptor.asset_id)?;
                if words(current.config.policy_admin_commitment)
                    != row.descriptor.policy_admin_commitment
                {
                    return Err(AssetStateErrorV1::PolicyFields);
                }
            }
        }
        Ok(())
    }
    /// Caller has already verified the NEW recovery-spend relation, exact current
    /// policy and shared NFs. This only applies the prepared accounting delta;
    /// it does not reuse the old V3 proof planner or grant proof authority.
    pub(crate) fn apply_recovery_accounting_after_proof(
        &self,
        prepared: transaction_core::asset_registry_v1::PreparedAssetAccountingV1,
    ) -> Result<Self, AssetStateErrorV1> {
        self.validate_recovery_binding()?;
        let mut next = self.clone();
        next.registry.apply_accounting_after_proof(prepared)?;
        next.validate_recovery_binding()?;
        Ok(next)
    }
    /// Typed planner; proof checking remains inside recovery state, governance
    /// is read from the current legacy row, and no standalone DB writer exists.
    pub(crate) fn plan_recovery_admin_at_parent(
        &self,
        current: AssetCanonicalContextV1,
        public: &transaction_circuit::asset_recovery_admin_v1::Public,
        proof: &[u8],
    ) -> Result<Self, AssetStateErrorV1> {
        self.validate_recovery_binding()?;
        let ctx = self.registry.context();
        if current.chain_id != ctx.chain_id
            || current.parent_height != ctx.parent_height
            || current.reference_parent_hash == [0; 32]
            || !canonical(&current.note_root)
        {
            return Err(AssetStateErrorV1::Context);
        }
        let old = self.registry.row(public.before.descriptor.asset_id)?;
        let recovery = self
            .recovery
            .as_ref()
            .ok_or(AssetStateErrorV1::PolicyFields)?;
        let plan = recovery
            .apply_verified_admin(
                public,
                proof,
                RecoveryCanonicalContextV1 {
                    chain_id: current.chain_id,
                    parent_height: current.parent_height,
                    parent_hash: current.reference_parent_hash,
                },
                words(old.config.policy_admin_commitment),
            )
            .map_err(|e| AssetStateErrorV1::Recovery(e.to_string()))?;
        let mut next = self.clone();
        next.recovery = Some(plan.projected_state().clone());
        next.validate_recovery_binding()?;
        Ok(next)
    }
    pub(crate) fn encode_exact(&self) -> Result<Vec<u8>, AssetStateErrorV1> {
        self.validate_recovery_binding()?;
        let Some(recovery) = &self.recovery else {
            return self.encode_legacy_exact();
        };
        let legacy = self.encode_legacy_exact()?;
        let extra = recovery
            .encode_exact()
            .map_err(|e| AssetStateErrorV1::Recovery(e.to_string()))?;
        if extra.len() > MAX_RECOVERY_STATE_BYTES {
            return Err(AssetStateErrorV1::Limits);
        }
        let mut out = Vec::with_capacity(COMPOSITE_HEADER_BYTES + legacy.len() + extra.len());
        out.extend(COMPOSITE_MAGIC);
        out.extend((legacy.len() as u32).to_le_bytes());
        out.extend((extra.len() as u32).to_le_bytes());
        out.extend(transaction_circuit::asset_recovery_spend_v1::relation_digest());
        out.extend(transaction_circuit::asset_recovery_admin_v1::relation_digest());
        out.extend(legacy);
        out.extend(extra);
        Ok(out)
    }
    pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Self, AssetStateErrorV1> {
        if !bytes.starts_with(COMPOSITE_MAGIC) {
            return Self::decode_legacy_exact(bytes);
        }
        if bytes.len() < COMPOSITE_HEADER_BYTES
            || bytes.len() > COMPOSITE_HEADER_BYTES + MAX_STATE_BYTES + MAX_RECOVERY_STATE_BYTES
        {
            return Err(AssetStateErrorV1::Codec("composite state length"));
        }
        let mut r = Reader { bytes, cursor: 8 };
        let old_len = r.u32()? as usize;
        let new_len = r.u32()? as usize;
        if !(HEADER_BYTES..=MAX_STATE_BYTES).contains(&old_len)
            || new_len > MAX_RECOVERY_STATE_BYTES
            || COMPOSITE_HEADER_BYTES
                .checked_add(old_len)
                .and_then(|n| n.checked_add(new_len))
                != Some(bytes.len())
        {
            return Err(AssetStateErrorV1::Limits);
        }
        if r.take(64)? != transaction_circuit::asset_recovery_spend_v1::relation_digest()
            || r.take(64)? != transaction_circuit::asset_recovery_admin_v1::relation_digest()
        {
            return Err(AssetStateErrorV1::Codec("recovery source identity"));
        }
        let mut state = Self::decode_legacy_exact(r.take(old_len)?)?;
        state.recovery = Some(
            RecoveryLedgerStateV1::decode_exact(r.take(new_len)?)
                .map_err(|e| AssetStateErrorV1::Recovery(e.to_string()))?,
        );
        state.validate_recovery_binding()?;
        if r.cursor != bytes.len() || state.encode_exact()? != bytes {
            return Err(AssetStateErrorV1::Codec("composite reencode"));
        }
        Ok(state)
    }
    pub(crate) fn registry(&self) -> &AssetRegistryV1 {
        &self.registry
    }
    pub(crate) fn registered_asset_ids(&self) -> &[u32] {
        &self.assets
    }
    pub(crate) fn admin_action_is_consumed(&self, id: &[u8; 32]) -> bool {
        self.admin_action_ids.contains(id)
    }
    pub(crate) fn consumed_admin_actions(&self) -> usize {
        self.admin_action_ids.len()
    }
    pub(crate) fn state_digest(&self) -> Result<[u8; 48], AssetStateErrorV1> {
        let mut hash = Sha384::new();
        hash.update(b"Hegemon.Native.AssetRegistryState.v1");
        hash.update(self.encode_exact()?);
        Ok(hash.finalize().into())
    }
    fn encode_legacy_exact(&self) -> Result<Vec<u8>, AssetStateErrorV1> {
        if self.assets.len() > ASSET_REGISTRY_CAP_V1
            || self.admin_action_ids.len() > MAX_ASSET_ADMIN_IDS_V1
            || self.assets.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(AssetStateErrorV1::Limits);
        }
        let context = self.registry.context();
        let rows = self
            .assets
            .iter()
            .map(|asset| self.registry.row(*asset).copied())
            .collect::<Result<Vec<_>, _>>()?;
        if AssetRegistryV1::from_rows(context.chain_id, context.parent_height, &rows)?
            != self.registry
        {
            return Err(AssetStateErrorV1::Codec("incomplete registry rows"));
        }
        let total = HEADER_BYTES
            + rows.len() * ASSET_POLICY_ROW_BYTES_V1
            + self.admin_action_ids.len() * 32;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend(MAGIC);
        bytes.extend(POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER.to_le_bytes());
        bytes.extend(context.chain_id);
        bytes.extend(context.parent_height.to_le_bytes());
        bytes.extend(spend::relation_digest());
        bytes.extend(admin::relation_digest());
        bytes.extend((rows.len() as u32).to_le_bytes());
        bytes.extend((self.admin_action_ids.len() as u32).to_le_bytes());
        bytes.extend((total as u32).to_le_bytes());
        for row in rows {
            bytes.extend(encode_asset_policy_row(&row)?);
        }
        for id in &self.admin_action_ids {
            bytes.extend(id);
        }
        debug_assert_eq!(bytes.len(), total);
        Ok(bytes)
    }
    /// Structural decoding does not authenticate a disk row. Startup/reorg
    /// must replay source proofs from manifest genesis/an authenticated ancestor
    /// and call `verify_canonical_readback` before using loaded state.
    fn decode_legacy_exact(bytes: &[u8]) -> Result<Self, AssetStateErrorV1> {
        if !(HEADER_BYTES..=MAX_STATE_BYTES).contains(&bytes.len()) {
            return Err(AssetStateErrorV1::Codec("state length"));
        }
        let mut r = Reader { bytes, cursor: 0 };
        if r.take(8)? != MAGIC || r.u64()? != POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER {
            return Err(AssetStateErrorV1::Codec("state identity"));
        }
        let chain_id = r.array()?;
        let height = r.u64()?;
        if r.take(64)? != spend::relation_digest() || r.take(64)? != admin::relation_digest() {
            return Err(AssetStateErrorV1::Codec("source identity"));
        }
        let count = r.u32()? as usize;
        let admin_count = r.u32()? as usize;
        let total = r.u32()? as usize;
        if count > ASSET_REGISTRY_CAP_V1
            || admin_count > MAX_ASSET_ADMIN_IDS_V1
            || total != bytes.len()
            || total != HEADER_BYTES + count * ASSET_POLICY_ROW_BYTES_V1 + admin_count * 32
        {
            return Err(AssetStateErrorV1::Limits);
        }
        let mut rows = Vec::with_capacity(count);
        let mut assets = Vec::with_capacity(count);
        for _ in 0..count {
            let row = decode_asset_policy_row(r.take(ASSET_POLICY_ROW_BYTES_V1)?)?;
            if assets.last().is_some_and(|old| *old >= row.config.asset_id) {
                return Err(AssetStateErrorV1::Codec("row order"));
            }
            assets.push(row.config.asset_id);
            rows.push(row);
        }
        let mut admin_action_ids = BTreeSet::new();
        let mut previous = None;
        for _ in 0..admin_count {
            let id: [u8; 32] = r.array()?;
            if previous.is_some_and(|old| old >= id) {
                return Err(AssetStateErrorV1::Codec("admin replay order"));
            }
            admin_action_ids.insert(id);
            previous = Some(id);
        }
        let state = Self {
            registry: AssetRegistryV1::from_rows(chain_id, height, &rows)?,
            assets,
            admin_action_ids,
            recovery: None,
        };
        if r.cursor != bytes.len() || state.encode_exact()? != bytes {
            return Err(AssetStateErrorV1::Codec("state reencode"));
        }
        Ok(state)
    }
    pub(crate) fn verify_canonical_readback(
        &self,
        observed: &[u8],
    ) -> Result<(), AssetStateErrorV1> {
        if self.encode_exact()? != observed {
            return Err(AssetStateErrorV1::CanonicalReadback);
        }
        Ok(())
    }

    /// Verify actions against one authenticated canonical parent, retaining its
    /// height. Native replay can call this for each leaf so ordinary HGN and
    /// controlled-asset spends share one ordered nullifier set. Call
    /// `advance_parent` exactly once after all block leaves, including empty
    /// blocks. The registry root may change between same-parent actions.
    ///
    /// The native callback must include globally spent nullifiers and earlier
    /// native actions in this block; local asset duplicates are checked here.
    /// All proof work and state changes remain local until the returned plan is
    /// applied with the native pool and canonical pointer in one transaction.
    pub(crate) fn plan_verified_actions_at_parent<F>(
        &self,
        current: AssetCanonicalContextV1,
        actions: &[AssetReplayActionV1<'_>],
        is_spent: F,
    ) -> Result<AssetStatePlanV1, AssetStateErrorV1>
    where
        F: FnMut(&Digest) -> Result<bool, String>,
    {
        self.plan_verified_actions_at_reference(
            current,
            current,
            words(self.registry.root()),
            actions,
            is_spent,
        )
    }

    /// Reference metadata is authenticated by canonical/staged native ancestry.
    /// Authorization/accounting remain against this CURRENT parent snapshot.
    pub(crate) fn plan_verified_actions_at_reference<F>(
        &self,
        current: AssetCanonicalContextV1,
        reference: AssetCanonicalContextV1,
        reference_registry_root: Digest,
        actions: &[AssetReplayActionV1<'_>],
        mut is_spent: F,
    ) -> Result<AssetStatePlanV1, AssetStateErrorV1>
    where
        F: FnMut(&Digest) -> Result<bool, String>,
    {
        let context = self.registry.context();
        if current.chain_id != context.chain_id
            || current.parent_height != context.parent_height
            || current.reference_parent_hash == [0; 32]
            || !canonical(&current.note_root)
            || current.parent_height >= 1 << 48
            || reference.chain_id != current.chain_id
            || reference.reference_parent_hash == [0; 32]
            || !canonical(&reference.note_root)
            || !current
                .parent_height
                .checked_sub(reference.parent_height)
                .is_some_and(|age| {
                    age <= protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW
                })
            || reference_registry_root != words(self.registry.root())
        {
            return Err(AssetStateErrorV1::Context);
        }
        if actions.len() > MAX_ASSET_ACTIONS_PER_BLOCK_V1 {
            return Err(AssetStateErrorV1::Limits);
        }
        let mut staged = self.clone();
        let mut introduced = BTreeSet::new();
        let mut effects = Vec::with_capacity(actions.len());
        let mut native_fee = 0u64;
        for action in actions {
            match action {
                AssetReplayActionV1::Spend(bytes) => {
                    let action = transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(bytes).map_err(|error| AssetStateErrorV1::Proof(error.to_string()))?;
                    let public = &action.public;
                    self.require_legacy_spend_allowed(public.asset_id)?;
                    public
                        .validate_structure()
                        .map_err(|error| AssetStateErrorV1::Proof(error.to_string()))?;
                    if public.chain_id != current.chain_id
                        || public.reference_parent_hash != reference.reference_parent_hash
                        || public.parent_height != reference.parent_height
                        || public.note_root != reference.note_root
                        || public.registry_root != reference_registry_root
                        || public.registry_root != words(staged.registry.root())
                    {
                        return Err(AssetStateErrorV1::Context);
                    }
                    let row = staged.registry.row(public.asset_id)?;
                    if public.policy_version != row.config.policy_version
                        || public.credential_root != words(row.credential_root)
                        || public.credential_depth != row.credential_depth
                        || public.frozen != row.frozen
                        || public.mint_enabled != row.mint_enabled
                        || public.issuer_commitment != words(row.config.issuer_commitment)
                    {
                        return Err(AssetStateErrorV1::PolicyFields);
                    }
                    for nullifier in public.nullifiers {
                        if !nonzero(&nullifier) || !introduced.insert(nullifier) {
                            return Err(AssetStateErrorV1::DuplicateNullifier);
                        }
                        if is_spent(&nullifier).map_err(AssetStateErrorV1::Proof)? {
                            return Err(AssetStateErrorV1::NativeNullifierSpent);
                        }
                    }
                    let operation = match public.operation {
                        spend::TRANSFER => AssetOperationV1::Transfer,
                        spend::MINT => AssetOperationV1::Mint,
                        spend::BURN => AssetOperationV1::Burn,
                        _ => return Err(AssetStateErrorV1::PolicyFields),
                    };
                    let prepared = staged.registry.prepare_accounting(
                        staged.registry.context(),
                        public.asset_id,
                        public.policy_version,
                        row.credential_root,
                        operation,
                        public.magnitude,
                    )?;
                    admission::verify_spend_v1(
                        public,
                        action.proof,
                        NativeAssetContextV1 {
                            chain_id: current.chain_id,
                            reference_parent_hash: reference.reference_parent_hash,
                            parent_height: reference.parent_height,
                            note_root: reference.note_root,
                            registry_root: words(staged.registry.root()),
                        },
                    )
                    .map_err(|error| AssetStateErrorV1::Proof(error.to_string()))?;
                    native_fee = native_fee
                        .checked_add(public.fee)
                        .ok_or(AssetStateErrorV1::FeeOverflow)?;
                    staged.registry.apply_accounting_after_proof(prepared)?;
                    effects.push(AssetVerifiedEffectV1::Spend {
                        nullifiers: public.nullifiers,
                        commitments: public.commitments,
                        ciphertexts: action.ciphertexts.map(|ciphertext| *ciphertext),
                        native_fee: public.fee,
                        released_secret: (public.secret_release == 1)
                            .then_some(public.released_secret),
                    });
                }
                AssetReplayActionV1::Controls(bytes) => {
                    let action = transaction_circuit::asset_spend_v1_wire::decode_native_asset_admin_action_v1(bytes).map_err(|error| AssetStateErrorV1::Proof(error.to_string()))?;
                    let public = &action.public;
                    if public.chain_id != current.chain_id
                        || public.reference_parent_hash != reference.reference_parent_hash
                        || public.parent_height != reference.parent_height
                        || public.registry_root != reference_registry_root
                    {
                        return Err(AssetStateErrorV1::Context);
                    }
                    let id = public.action_id();
                    if staged.admin_action_ids.contains(&id) {
                        return Err(AssetStateErrorV1::AdminReplay);
                    }
                    if staged.admin_action_ids.len() >= MAX_ASSET_ADMIN_IDS_V1 {
                        return Err(AssetStateErrorV1::Limits);
                    }
                    staged.require_legacy_controls_allowed(public.asset_id, public.controls.credential_depth)?;
                    let prepared = staged.registry.prepare_controls_update(
                        staged.registry.context(),
                        public.asset_id,
                        public.controls,
                    )?;
                    // Preserve the exact original proof statement, but derive every
                    // authorized row/control/root from CURRENT state. Only its
                    // reference height/hash are historical. Expiry is public.
                    if public.expires_at < current.parent_height {
                        return Err(AssetStateErrorV1::Context);
                    }
                    let mut expected = admin::PolicyAdminPublicV1::from_prepared(
                        &prepared,
                        reference.reference_parent_hash,
                        public.expires_at,
                        public.action_intent,
                    )
                    .map_err(|error| AssetStateErrorV1::Proof(error.to_string()))?;
                    expected.parent_height = reference.parent_height;
                    if *public != expected {
                        return Err(AssetStateErrorV1::PolicyFields);
                    }
                    admission::verify_admin_v1(
                        public,
                        action.proof,
                        NativeAssetContextV1 {
                            chain_id: current.chain_id,
                            reference_parent_hash: reference.reference_parent_hash,
                            parent_height: reference.parent_height,
                            note_root: reference.note_root,
                            registry_root: words(staged.registry.root()),
                        },
                    )
                    .map_err(|error| AssetStateErrorV1::Proof(error.to_string()))?;
                    staged
                        .registry
                        .apply_controls_update_after_authorization(prepared)?;
                    staged.admin_action_ids.insert(id);
                    effects.push(AssetVerifiedEffectV1::Controls {
                        asset_id: public.asset_id,
                        admin_action_id: id,
                    });
                }
            }
        }
        Ok(AssetStatePlanV1 {
            before: self.encode_exact()?,
            after: staged.encode_exact()?,
            projected: staged,
            effects,
            native_fee,
        })
    }

    /// Pure height advancement after the native block verifier has accepted
    /// every leaf. This grants no note, fee, nullifier or policy authority.
    pub(crate) fn advance_parent(&self, block_height: u64) -> Result<Self, AssetStateErrorV1> {
        let context = self.registry.context();
        if context.parent_height.checked_add(1) != Some(block_height) || block_height >= 1 << 48 {
            return Err(AssetStateErrorV1::Context);
        }
        let mut next = self.clone();
        next.registry
            .advance_parent_after_chain_verification(context, block_height)?;
        if let Some(recovery) = &self.recovery {
            next.recovery = Some(
                recovery
                    .advance_parent(block_height)
                    .map_err(|e| AssetStateErrorV1::Recovery(e.to_string()))?,
            );
        }
        next.validate_recovery_binding()?;
        Ok(next)
    }

    /// Convenience whole-block wrapper for callers which already present the
    /// complete ordered action list and a shared native-nullifier view.
    pub(crate) fn plan_verified_block<F>(
        &self,
        current: AssetCanonicalContextV1,
        actions: &[AssetReplayActionV1<'_>],
        is_spent: F,
    ) -> Result<AssetStatePlanV1, AssetStateErrorV1>
    where
        F: FnMut(&Digest) -> Result<bool, String>,
    {
        let mut plan = self.plan_verified_actions_at_parent(current, actions, is_spent)?;
        let next_height = current
            .parent_height
            .checked_add(1)
            .ok_or(AssetStateErrorV1::Context)?;
        plan.projected = plan.projected.advance_parent(next_height)?;
        plan.after = plan.projected.encode_exact()?;
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transaction_core::stablecoin_poseidon2_v8::StablecoinPoseidon2V8Config;

    fn row(asset_id: u32) -> AssetPolicyV1 {
        let tagged = |tag| core::array::from_fn(|index| Felt::from_u64(tag + index as u64));
        AssetPolicyV1 {
            config: StablecoinPoseidon2V8Config {
                asset_id,
                policy_version: 7,
                active: true,
                enabled_at: 0,
                retired_at: Some(20_000),
                issuer_commitment: tagged(1),
                min_collateral_ratio_ppm: 1_500_000,
                max_mint_per_epoch: 1_000_000,
                oracle_submitted_at: 0,
                oracle_max_age: 500,
                oracle_price_numerator: 2,
                oracle_price_denominator: 1,
                collateral_amount: 10_000,
                attestation_created_at: 0,
                attestation_disputed: false,
                attestation_present: true,
                attestation_max_age: 500,
                policy_admin_commitment: tagged(101),
                oracle_authority_commitment: tagged(201),
                attestation_authority_commitment: tagged(301),
                collateral_asset_id: 0,
                collateral_decimals: 6,
                collateral_scale: 1_000_000,
                locked_collateral_commitment: tagged(401),
            },
            counters: StablecoinPoseidon2V8Counters::default(),
            credential_root: tagged(701),
            credential_depth: 8,
            frozen: false,
            mint_enabled: true,
        }
    }

    fn composite_fixture() -> AssetRegistryStateV1 {
        use transaction_core::asset_recovery_v1 as recovery;
        let mut old = row(1001);
        old.credential_depth = 4;
        let descriptor = recovery::RecoveryDescriptorV1 {
            asset_id: 1001,
            stable_policy_id: [7; 7],
            policy_admin_commitment: words(old.config.policy_admin_commitment),
            archive_key_commitment: [8; 7],
            maximum_powers: recovery::RecoveryPowersV1 {
                transfer: true,
                burn: true,
            },
        };
        let controls = recovery::RecoveryControlsV1 {
            epoch: 0,
            delegate_action_commitment: [9; 7],
            revoked: false,
            powers: descriptor.maximum_powers,
            note_freeze_root: recovery::freeze_defaults(&descriptor, [1; 32]).unwrap()[32],
        };
        AssetRegistryStateV1::from_genesis_rows_with_recovery(
            [1; 32],
            &[old],
            &[recovery::RecoveryRowV1 {
                descriptor,
                controls,
            }],
        )
        .unwrap()
    }
    #[test]
    fn absent_recovery_keeps_legacy_bytes_exact() {
        let state = AssetRegistryStateV1::from_genesis_rows([1; 32], &[row(1001)]).unwrap();
        assert!(state.recovery().is_none());
        assert_eq!(
            state.encode_exact().unwrap(),
            state.encode_legacy_exact().unwrap()
        );
        assert!(state.encode_exact().unwrap().starts_with(MAGIC));
    }
    #[test]
    fn composite_roundtrip_and_ordered_registration() {
        let mut s = composite_fixture();
        s.recovery_mut()
            .unwrap()
            .register_verified_output(5, 1001, [10; 7])
            .unwrap();
        let b = s.encode_exact().unwrap();
        assert!(b.starts_with(COMPOSITE_MAGIC));
        assert_eq!(AssetRegistryStateV1::decode_exact(&b).unwrap(), s);
        let next = s.advance_parent(1).unwrap();
        assert_eq!(next.recovery().unwrap().parent_height(), 1);
        assert_eq!(next.registry.context().parent_height, 1);
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(AssetRegistryStateV1::decode_exact(&trailing).is_err());
        let mut source = b;
        source[16] ^= 1;
        assert!(AssetRegistryStateV1::decode_exact(&source).is_err());
    }
    #[test]
    fn composite_cannot_mismatch_current_state_or_downgrade_opted_spends() {
        let mut s = composite_fixture();
        assert!(s.require_legacy_spend_allowed(1001).is_err());
        assert!(s.require_legacy_spend_allowed(1002).is_ok());
        let before = s.encode_exact().unwrap();
        s.recovery = Some(s.recovery().unwrap().advance_parent(1).unwrap());
        assert!(s.encode_exact().is_err());
        let restored = AssetRegistryStateV1::decode_exact(&before).unwrap();
        assert!(restored.recovery().unwrap().is_opted(1001));
    }
    #[test]
    fn opted_ordinary_controls_cannot_leave_the_recovery_depth_four_profile() {
        let s = composite_fixture();
        assert!(s.require_legacy_controls_allowed(1001, 4).is_ok());
        for depth in [8, 16] {
            assert!(matches!(s.require_legacy_controls_allowed(1001, depth),
                Err(AssetStateErrorV1::PolicyFields)));
            assert!(s.require_legacy_controls_allowed(1002, depth).is_ok());
        }
    }
    #[test]
    fn opted_assets_keep_ordinary_control_updates() {
        // Structural coexistence only; this test grants no admin proof token.
        let s = composite_fixture();
        let mut next = s.clone();
        let old = *next.registry.row(1001).unwrap();
        let mut controls = old.controls();
        controls.frozen = true;
        controls.mint_enabled = false;
        let prepared = next
            .registry
            .prepare_controls_update(next.registry.context(), 1001, controls)
            .unwrap();
        next.registry
            .apply_controls_update_after_authorization(prepared)
            .unwrap();
        assert_eq!(next.recovery, s.recovery);
        next.validate_recovery_binding().unwrap();
        assert!(next.registry.row(1001).unwrap().frozen);
        assert!(!next.registry.row(1001).unwrap().mint_enabled);
    }
    #[test]
    fn full_rows_and_consumed_admin_ids_survive_exact_snapshot() {
        let first = row(1001);
        let second = row(1002);
        let mut state = AssetRegistryStateV1::from_genesis_rows([1; 32], &[second, first]).unwrap();
        let root = state.registry.root();
        // This only exercises canonical snapshot storage of consumed IDs; the
        // production insertion path requires a real admin proof above.
        state.admin_action_ids.extend([[1; 32], [2; 32]]);
        let bytes = state.encode_exact().unwrap();
        let restored = AssetRegistryStateV1::decode_exact(&bytes).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.registry.root(), root);
        assert_eq!(restored.registered_asset_ids(), &[1001, 1002]);
        assert!(restored.admin_action_is_consumed(&[1; 32]));
        assert!(restored.admin_action_is_consumed(&[2; 32]));
        assert!(!restored.admin_action_is_consumed(&[3; 32]));
        assert_eq!(
            decode_asset_policy_row(&encode_asset_policy_row(&first).unwrap()).unwrap(),
            first
        );

        let mut reordered = bytes.clone();
        let rows_end = HEADER_BYTES + 2 * ASSET_POLICY_ROW_BYTES_V1;
        reordered[HEADER_BYTES..HEADER_BYTES + ASSET_POLICY_ROW_BYTES_V1]
            .copy_from_slice(&bytes[HEADER_BYTES + ASSET_POLICY_ROW_BYTES_V1..rows_end]);
        reordered[HEADER_BYTES + ASSET_POLICY_ROW_BYTES_V1..rows_end]
            .copy_from_slice(&bytes[HEADER_BYTES..HEADER_BYTES + ASSET_POLICY_ROW_BYTES_V1]);
        assert!(AssetRegistryStateV1::decode_exact(&reordered).is_err());
        let mut duplicate = bytes;
        duplicate[rows_end + 32..rows_end + 64].copy_from_slice(&[1; 32]);
        assert!(AssetRegistryStateV1::decode_exact(&duplicate).is_err());

        for counter in 0..4 {
            let mut funded = first;
            match counter {
                0 => funded.counters.epoch_id = 1,
                1 => funded.counters.minted_in_epoch = 1,
                2 => funded.counters.total_debt = 1,
                _ => funded.counters.sequence = 1,
            }
            assert!(matches!(
                AssetRegistryStateV1::from_genesis_rows([1; 32], &[funded]),
                Err(AssetStateErrorV1::GenesisSupply)
            ));
        }
    }

    #[test]
    fn malformed_native_actions_leave_all_registry_replay_bytes_unchanged() {
        let state = AssetRegistryStateV1::from_genesis_rows([1; 32], &[row(1001)]).unwrap();
        let before = state.encode_exact().unwrap();
        let current = AssetCanonicalContextV1 {
            chain_id: [1; 32],
            reference_parent_hash: [2; 32],
            parent_height: 0,
            note_root: [3; 7],
        };
        for action in [
            AssetReplayActionV1::Spend(b"HGANSP01"),
            AssetReplayActionV1::Controls(b"HGANAD01"),
        ] {
            assert!(state
                .plan_verified_actions_at_parent(current, &[action], |_| Ok(false))
                .is_err());
            assert_eq!(state.encode_exact().unwrap(), before);
        }
        let mut stale = current;
        stale.parent_height = 1;
        assert!(matches!(
            state.plan_verified_actions_at_parent(stale, &[], |_| Ok(false)),
            Err(AssetStateErrorV1::Context)
        ));
        assert_eq!(state.encode_exact().unwrap(), before);
    }
    #[test]
    fn moving_reference_window_keeps_current_registry_and_height_checks() {
        let mut state = AssetRegistryStateV1::from_genesis_rows([1; 32], &[row(1001)]).unwrap();
        for height in 1..=20 {
            state = state.advance_parent(height).unwrap();
        }
        let before = state.encode_exact().unwrap();
        let current = AssetCanonicalContextV1 {
            chain_id: [1; 32],
            reference_parent_hash: [20; 32],
            parent_height: 20,
            note_root: [20; 7],
        };
        let reference = AssetCanonicalContextV1 {
            reference_parent_hash: [8; 32],
            parent_height: 8,
            note_root: [8; 7],
            ..current
        };
        let root = words(state.registry.root());
        let plan = state
            .plan_verified_actions_at_reference(current, reference, root, &[], |_| Ok(false))
            .unwrap();
        assert_eq!(plan.projected, state);
        for height in [7, 21] {
            let invalid = AssetCanonicalContextV1 {
                parent_height: height,
                ..reference
            };
            assert!(matches!(
                state
                    .plan_verified_actions_at_reference(current, invalid, root, &[], |_| Ok(false)),
                Err(AssetStateErrorV1::Context)
            ));
        }
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(matches!(
            state.plan_verified_actions_at_reference(current, reference, wrong_root, &[], |_| Ok(
                false
            )),
            Err(AssetStateErrorV1::Context)
        ));
        let wrong_current = AssetCanonicalContextV1 {
            parent_height: 19,
            ..current
        };
        assert!(matches!(
            state.plan_verified_actions_at_reference(wrong_current, reference, root, &[], |_| Ok(
                false
            )),
            Err(AssetStateErrorV1::Context)
        ));
        assert_eq!(state.encode_exact().unwrap(), before);
    }

    #[test]
    fn moving_admin_reconstructs_current_controls_and_checks_public_expiry() {
        let mut reference_state =
            AssetRegistryStateV1::from_genesis_rows([1; 32], &[row(1001)]).unwrap();
        for height in 1..=8 {
            reference_state = reference_state.advance_parent(height).unwrap();
        }
        let mut current_state = reference_state.clone();
        for height in 9..=20 {
            current_state = current_state.advance_parent(height).unwrap();
        }
        let before = current_state.encode_exact().unwrap();
        let current = AssetCanonicalContextV1 {
            chain_id: [1; 32],
            reference_parent_hash: [20; 32],
            parent_height: 20,
            note_root: [20; 7],
        };
        let reference = AssetCanonicalContextV1 {
            reference_parent_hash: [8; 32],
            parent_height: 8,
            note_root: [8; 7],
            ..current
        };
        let controls = admin::AssetControlsV1 {
            frozen: true,
            ..row(1001).controls()
        };
        let prepared = reference_state
            .registry
            .prepare_controls_update(reference_state.registry.context(), 1001, controls)
            .unwrap();
        // Framed but invalid proofs deliberately stop at verification. Reaching
        // that error distinguishes a valid historical/current public join from
        // an obsolete exact-parent guard; no fixture grants proof authority.
        let encode = |expiry| {
            let public = admin::PolicyAdminPublicV1::from_prepared(
                &prepared,
                reference.reference_parent_hash,
                expiry,
                [23; 7],
            )
            .unwrap();
            transaction_circuit::asset_spend_v1_wire::encode_native_asset_admin_action_v1(
                &public, b"SMZE",
            )
        };
        let expired = match encode(19) {
            Ok(bytes) => bytes,
            Err(
                transaction_circuit::asset_spend_v1_wire::AssetSpendWireErrorV1::RelationSource,
            ) => {
                use transaction_circuit::asset_spend_v1_admission as admission;
                assert_eq!(
                    admission::admin_profile_upper_bound_v1(),
                    Err(admission::NativeAssetAdmissionErrorV1::SourceIdentity)
                );
                assert_ne!(
                    hex::encode(admin::relation_digest()),
                    admission::QUALIFIED_ADMIN_SOURCE_SHA512
                );
                assert_eq!(current_state.encode_exact().unwrap(), before);
                assert_eq!(
                    current_state.registry.row(1001).unwrap().controls(),
                    row(1001).controls()
                );
                eprintln!("inactive admin source: exact RelationSource rejection before expiry/proof work; current state unchanged");
                return;
            }
            Err(error) => panic!("unexpected moving admin fixture error: {error}"),
        };
        assert!(matches!(
            current_state.plan_verified_actions_at_reference(
                current,
                reference,
                words(reference_state.registry.root()),
                &[AssetReplayActionV1::Controls(&expired)],
                |_| Ok(false)
            ),
            Err(AssetStateErrorV1::Context)
        ));
        let live = encode(20).unwrap();
        assert!(matches!(
            current_state.plan_verified_actions_at_reference(
                current,
                reference,
                words(reference_state.registry.root()),
                &[AssetReplayActionV1::Controls(&live)],
                |_| Ok(false)
            ),
            Err(AssetStateErrorV1::Proof(_))
        ));
        let mut changed = current_state.clone();
        let update = changed
            .registry
            .prepare_controls_update(changed.registry.context(), 1001, controls)
            .unwrap();
        changed
            .registry
            .apply_controls_update_after_authorization(update)
            .unwrap();
        assert!(matches!(
            changed.plan_verified_actions_at_reference(
                current,
                reference,
                words(reference_state.registry.root()),
                &[AssetReplayActionV1::Controls(&live)],
                |_| Ok(false)
            ),
            Err(AssetStateErrorV1::Context)
        ));
        assert_eq!(current_state.encode_exact().unwrap(), before);
    }

    #[test]
    fn empty_snapshot_exact_codec_and_source_guards() {
        let state = AssetRegistryStateV1::from_genesis_rows([1; 32], &[]).unwrap();
        let bytes = state.encode_exact().unwrap();
        assert_eq!(bytes.len(), HEADER_BYTES);
        assert_eq!(AssetRegistryStateV1::decode_exact(&bytes).unwrap(), state);
        for offset in [0, 8, 56, 120, 184, 188, 192] {
            let mut changed = bytes.clone();
            changed[offset] ^= 0x80;
            assert!(AssetRegistryStateV1::decode_exact(&changed).is_err());
        }
        assert!(AssetRegistryStateV1::decode_exact(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes;
        extra.push(0);
        assert!(AssetRegistryStateV1::decode_exact(&extra).is_err());
    }
    #[test]
    fn pure_empty_block_plan_reorg_readback_and_height_sequence() {
        let state = AssetRegistryStateV1::from_genesis_rows([1; 32], &[]).unwrap();
        let current = AssetCanonicalContextV1 {
            chain_id: [1; 32],
            reference_parent_hash: [2; 32],
            parent_height: 0,
            note_root: [3; 7],
        };
        let plan = state
            .plan_verified_block(current, &[], |_| Ok(false))
            .unwrap();
        assert_eq!(state.registry.context().parent_height, 0);
        assert_eq!(plan.projected.registry.context().parent_height, 1);
        assert!(plan.effects.is_empty());
        assert_eq!(plan.before_bytes(), state.encode_exact().unwrap());
        assert_eq!(plan.after_bytes(), plan.projected.encode_exact().unwrap());
        state
            .verify_canonical_readback(plan.before_bytes())
            .unwrap();
        assert!(state.verify_canonical_readback(plan.after_bytes()).is_err());
        let leaf_plan = state
            .plan_verified_actions_at_parent(current, &[], |_| Ok(false))
            .unwrap();
        assert_eq!(leaf_plan.projected, state);
        assert_eq!(leaf_plan.before, leaf_plan.after);
        assert_eq!(
            leaf_plan.projected.advance_parent(1).unwrap(),
            plan.projected
        );
        assert!(state.advance_parent(0).is_err());
        assert!(state.advance_parent(2).is_err());
        assert!(plan.projected.advance_parent(1).is_err());
        // A reorg obtains the ancestor by independently replaying canonical
        // proofs. Decoding or restoring arbitrary disk bytes is not authority.
        let replayed_ancestor = AssetRegistryStateV1::from_genesis_rows([1; 32], &[]).unwrap();
        assert_eq!(replayed_ancestor, state);
    }
}
