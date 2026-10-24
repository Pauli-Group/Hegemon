//! Standalone staged recovery state. No DB, native fee or nullifier authority.
//! Caller authenticates canonical context and genesis manifest, registers ONLY
//! outputs from actually verified transitions, and atomically persists this plan
//! alongside existing asset registry, shared notes/NFs and canonical block rows.
use core::{
    Digest, RecoveryContextV1, RecoveryControlsV1, RecoveryDescriptorV1, RecoveryPowersV1,
    RecoveryRowV1,
};
use std::collections::{BTreeMap, BTreeSet};
use transaction_circuit::{asset_recovery_admin_v1 as admin, asset_recovery_wire_v1 as wire};
use transaction_core::{
    asset_recovery_v1 as core,
    asset_registry_v1::{validate_asset_policy_v1, AssetPolicyV1},
    stablecoin_poseidon2_v8::StablecoinPoseidon2V8Counters,
};
const MAGIC: &[u8; 8] = b"HGRST001";
pub(crate) const MAX_ROWS: usize = 256;
pub(crate) const MAX_NOTES: usize = 1_048_576;
pub(crate) const MAX_ADMIN_IDS: usize = 65_536;
const MAX_BYTES: usize = 128 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryStateErrorV1 {
    Codec(&'static str),
    Context,
    Genesis,
    Missing,
    Duplicate,
    Limit,
    Freeze,
    Replay,
    Core(String),
    Proof(String),
}
impl std::fmt::Display for RecoveryStateErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RecoveryStateErrorV1 {}
type Result<T> = std::result::Result<T, RecoveryStateErrorV1>;
fn err(e: impl std::fmt::Debug) -> RecoveryStateErrorV1 {
    RecoveryStateErrorV1::Core(format!("{e:?}"))
}
fn digest(d: Digest) -> Result<Digest> {
    if d == [0; 7] || d.iter().any(|x| *x >= transaction_core::constants::FIELD_MODULUS_U64) {
        return Err(RecoveryStateErrorV1::Codec("digest"));
    }
    Ok(d)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryCanonicalContextV1 {
    pub chain_id: [u8; 32],
    pub parent_hash: [u8; 32],
    pub parent_height: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryLedgerStateV1 {
    chain_id: [u8; 32],
    parent_height: u64,
    rows: BTreeMap<u32, RecoveryRowV1>,
    notes: BTreeMap<u32, (u32, Digest)>,
    frozen: BTreeMap<u32, BTreeMap<u32, Digest>>,
    admin_ids: BTreeSet<[u8; 32]>,
}
#[derive(Clone, Debug)]
pub(crate) struct RecoveryAdminPlanV1 {
    before: Vec<u8>,
    after: Vec<u8>,
    projected: RecoveryLedgerStateV1,
}
impl RecoveryAdminPlanV1 {
    pub(crate) fn before_bytes(&self) -> &[u8] {
        &self.before
    }
    pub(crate) fn after_bytes(&self) -> &[u8] {
        &self.after
    }
    pub(crate) fn projected_state(&self) -> &RecoveryLedgerStateV1 {
        &self.projected
    }
}
impl RecoveryLedgerStateV1 {
    /// Authenticated fresh manifest only: cannot opt existing issued notes in.
    pub(crate) fn from_genesis_rows(
        chain_id: &[u8; 32],
        existing: &[AssetPolicyV1],
        initial: &[RecoveryRowV1],
    ) -> Result<Self> {
        if *chain_id == [0; 32] || initial.len() > MAX_ROWS {
            return Err(RecoveryStateErrorV1::Genesis);
        }
        let mut originals = BTreeMap::new();
        for r in existing {
            validate_asset_policy_v1(r).map_err(err)?;
            if originals.insert(r.config.asset_id, r).is_some() {
                return Err(RecoveryStateErrorV1::Duplicate);
            }
        }
        let mut s = Self {
            chain_id: *chain_id,
            parent_height: 0,
            rows: BTreeMap::new(),
            notes: BTreeMap::new(),
            frozen: BTreeMap::new(),
            admin_ids: BTreeSet::new(),
        };
        for r in initial {
            r.validate().map_err(err)?;
            let id = r.descriptor.asset_id;
            let old = originals.get(&id).ok_or(RecoveryStateErrorV1::Genesis)?;
            if old.counters != StablecoinPoseidon2V8Counters::default()
                || old
                    .config
                    .policy_admin_commitment
                    .map(|f| f.as_canonical_u64())
                    != r.descriptor.policy_admin_commitment
                || r.controls.epoch != 0
                || r.controls.note_freeze_root
                    != core::freeze_defaults(&r.descriptor, *chain_id).map_err(err)?[32]
            {
                return Err(RecoveryStateErrorV1::Genesis);
            }
            if s.rows.insert(id, *r).is_some() {
                return Err(RecoveryStateErrorV1::Duplicate);
            }
            s.frozen.insert(id, BTreeMap::new());
        }
        s.validate()?;
        Ok(s)
    }
    pub(crate) fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }
    pub(crate) fn parent_height(&self) -> u64 {
        self.parent_height
    }
    pub(crate) fn row(&self, asset: u32) -> Result<&RecoveryRowV1> {
        self.rows.get(&asset).ok_or(RecoveryStateErrorV1::Missing)
    }
    pub(crate) fn rows(&self) -> impl Iterator<Item = &RecoveryRowV1> {
        self.rows.values()
    }
    pub(crate) fn is_opted(&self, asset: u32) -> bool {
        self.rows.contains_key(&asset)
    }
    pub(crate) fn note_at(&self, position: u32) -> Option<(u32, Digest)> {
        self.notes.get(&position).copied()
    }
    pub(crate) fn admin_action_is_consumed(&self, id: &[u8; 32]) -> bool {
        self.admin_ids.contains(id)
    }
    /// Called after all block leaves; restore a canonical snapshot for a reorg.
    pub(crate) fn advance_parent(&self, height: u64) -> Result<Self> {
        if height > core::MAX_EPOCH || self.parent_height.checked_add(1) != Some(height) {
            return Err(RecoveryStateErrorV1::Context);
        }
        let mut s = self.clone();
        s.parent_height = height;
        Ok(s)
    }
    /// Calling this does not verify a proof. Global canonical append position must
    /// be supplied by the existing verified shared-pool plan, never an RPC caller.
    pub(crate) fn register_verified_output(
        &mut self,
        position: u32,
        asset: u32,
        commitment: Digest,
    ) -> Result<()> {
        self.row(asset)?;
        digest(commitment)?;
        if self.notes.contains_key(&position) {
            return Err(RecoveryStateErrorV1::Duplicate);
        }
        if self.notes.len() >= MAX_NOTES {
            return Err(RecoveryStateErrorV1::Limit);
        }
        self.notes.insert(position, (asset, commitment));
        Ok(())
    }
    fn levels(&self, asset: u32) -> Result<(Vec<BTreeMap<u32, Digest>>, [Digest; 33])> {
        let row = self.row(asset)?;
        let defaults = core::freeze_defaults(&row.descriptor, self.chain_id).map_err(err)?;
        let mut levels = Vec::with_capacity(33);
        let mut leaves = BTreeMap::new();
        for (&pos, &cm) in self
            .frozen
            .get(&asset)
            .ok_or(RecoveryStateErrorV1::Freeze)?
        {
            if self.notes.get(&pos) != Some(&(asset, cm)) {
                return Err(RecoveryStateErrorV1::Freeze);
            }
            leaves.insert(
                pos,
                core::freeze_leaf(&row.descriptor, self.chain_id, pos, cm, true).map_err(err)?,
            );
        }
        levels.push(leaves);
        for i in 0..32 {
            let parents: BTreeSet<u32> = levels[i].keys().map(|x| x >> 1).collect();
            let mut next = BTreeMap::new();
            for parent in parents {
                let left = *levels[i].get(&(parent << 1)).unwrap_or(&defaults[i]);
                let right = *levels[i].get(&((parent << 1) | 1)).unwrap_or(&defaults[i]);
                next.insert(
                    parent,
                    core::freeze_node(&row.descriptor, self.chain_id, i, left, right)
                        .map_err(err)?,
                );
            }
            levels.push(next);
        }
        Ok((levels, defaults))
    }
    fn computed_root(&self, asset: u32) -> Result<Digest> {
        let (levels, defaults) = self.levels(asset)?;
        Ok(*levels[32].get(&0).unwrap_or(&defaults[32]))
    }
    pub(crate) fn freeze_witness(&self, asset: u32, position: u32) -> Result<[Digest; 32]> {
        if self.notes.get(&position).map(|v| v.0) != Some(asset) {
            return Err(RecoveryStateErrorV1::Missing);
        }
        let (levels, defaults) = self.levels(asset)?;
        if *levels[32].get(&0).unwrap_or(&defaults[32])
            != self.row(asset)?.controls.note_freeze_root
        {
            return Err(RecoveryStateErrorV1::Freeze);
        }
        Ok(std::array::from_fn(|i| {
            *levels[i]
                .get(&((position >> i) ^ 1))
                .unwrap_or(&defaults[i])
        }))
    }
    /// Always verifies the actual candidate proof. Canonical context and current
    /// governance must come from the old authenticated asset registry/block plan.
    /// Returned bytes are a plan, not an independent durable state writer.
    pub(crate) fn apply_verified_admin(
        &self,
        public: &admin::Public,
        proof: &[u8],
        canonical: RecoveryCanonicalContextV1,
        current_policy_admin: Digest,
    ) -> Result<RecoveryAdminPlanV1> {
        if canonical.chain_id != self.chain_id
            || canonical.parent_height != self.parent_height
            || canonical.parent_hash == [0; 32]
            || public.context.chain_id != canonical.chain_id
            || public.context.parent_hash != canonical.parent_hash
            || public.context.parent_height != canonical.parent_height
            || public.expires_at < canonical.parent_height
        {
            return Err(RecoveryStateErrorV1::Context);
        }
        let asset = public.before.descriptor.asset_id;
        let before = *self.row(asset)?;
        if before != public.before
            || before.descriptor.policy_admin_commitment != digest(current_policy_admin)?
        {
            return Err(RecoveryStateErrorV1::Context);
        }
        let context = RecoveryContextV1 {
            chain_id: self.chain_id,
            parent_hash: canonical.parent_hash,
            parent_height: self.parent_height,
            row_commitment: before.commitment(self.chain_id).map_err(err)?,
        };
        if public.context != context {
            return Err(RecoveryStateErrorV1::Context);
        }
        let prepared = core::prepare_controls_update(context, before, public.after).map_err(err)?;
        public
            .verify_prepared(&prepared)
            .map_err(|e| RecoveryStateErrorV1::Proof(e.to_string()))?;
        let id = public
            .action_id()
            .map_err(|e| RecoveryStateErrorV1::Proof(e.to_string()))?;
        if self.admin_ids.contains(&id) {
            return Err(RecoveryStateErrorV1::Replay);
        }
        if self.admin_ids.len() >= MAX_ADMIN_IDS {
            return Err(RecoveryStateErrorV1::Limit);
        }
        let mut staged = self.clone();
        if let Some(f) = public.freeze {
            if staged.notes.get(&f.position) != Some(&(asset, f.note_commitment)) {
                return Err(RecoveryStateErrorV1::Freeze);
            }
            let map = staged
                .frozen
                .get_mut(&asset)
                .ok_or(RecoveryStateErrorV1::Freeze)?;
            if map.contains_key(&f.position) != f.before_frozen || f.before_frozen == f.after_frozen
            {
                return Err(RecoveryStateErrorV1::Freeze);
            }
            if f.after_frozen {
                map.insert(f.position, f.note_commitment);
            } else {
                map.remove(&f.position);
            }
        }
        if staged.computed_root(asset)? != public.after.note_freeze_root {
            return Err(RecoveryStateErrorV1::Freeze);
        }
        admin::verify_candidate(public, proof)
            .map_err(|e| RecoveryStateErrorV1::Proof(e.to_string()))?;
        core::apply_controls_after_proof(staged.rows.get_mut(&asset).unwrap(), context, prepared)
            .map_err(err)?;
        staged.admin_ids.insert(id);
        Ok(RecoveryAdminPlanV1 {
            before: self.encode_exact()?,
            after: staged.encode_exact()?,
            projected: staged,
        })
    }
    fn validate(&self) -> Result<()> {
        if self.chain_id == [0; 32]
            || self.parent_height > core::MAX_EPOCH
            || self.rows.len() > MAX_ROWS
            || self.notes.len() > MAX_NOTES
            || self.admin_ids.len() > MAX_ADMIN_IDS
            || self.frozen.len() != self.rows.len()
        {
            return Err(RecoveryStateErrorV1::Limit);
        }
        for (&id, row) in &self.rows {
            row.validate().map_err(err)?;
            if id != row.descriptor.asset_id
                || self.computed_root(id)? != row.controls.note_freeze_root
            {
                return Err(RecoveryStateErrorV1::Freeze);
            }
        }
        for (&pos, &(asset, cm)) in &self.notes {
            let _ = pos;
            self.row(asset)?;
            digest(cm)?;
        }
        for id in &self.admin_ids {
            if *id == [0; 32] {
                return Err(RecoveryStateErrorV1::Codec("zero action id"));
            }
        }
        Ok(())
    }
    pub(crate) fn encode_exact(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut w = Vec::new();
        w.extend(MAGIC);
        w.extend(self.chain_id);
        put64(&mut w, self.parent_height);
        put32(&mut w, self.rows.len() as u32);
        for row in self.rows.values() {
            for x in wire::encode_recovery_row(self.chain_id, row).map_err(err)? {
                put64(&mut w, x);
            }
        }
        put32(&mut w, self.notes.len() as u32);
        for (&p, &(a, c)) in &self.notes {
            put32(&mut w, p);
            put32(&mut w, a);
            put_digest(&mut w, c);
        }
        let count: usize = self.frozen.values().map(|m| m.len()).sum();
        put32(&mut w, count as u32);
        for (&a, map) in &self.frozen {
            for (&p, &cm) in map {
                put32(&mut w, a);
                put32(&mut w, p);
                put_digest(&mut w, cm);
            }
        }
        put32(&mut w, self.admin_ids.len() as u32);
        for id in &self.admin_ids {
            w.extend(id);
        }
        if w.len() > MAX_BYTES {
            return Err(RecoveryStateErrorV1::Limit);
        }
        Ok(w)
    }
    /// Parse only; caller must authenticate genesis and replay actual block proofs.
    /// A decoded cached snapshot must never authorize a skipped proof verification.
    pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(RecoveryStateErrorV1::Limit);
        }
        let mut r = Reader(bytes);
        if r.take(8)? != MAGIC {
            return Err(RecoveryStateErrorV1::Codec("magic"));
        }
        let chain_id = r.take(32)?.try_into().unwrap();
        let parent_height = r.u64()?;
        let mut s = Self {
            chain_id,
            parent_height,
            rows: BTreeMap::new(),
            notes: BTreeMap::new(),
            frozen: BTreeMap::new(),
            admin_ids: BTreeSet::new(),
        };
        for _ in 0..r.count(MAX_ROWS)? {
            let mut words = [0u64; 48];
            for x in &mut words {
                *x = r.u64()?;
            }
            let (chain, row) = wire::decode_recovery_row(&words).map_err(err)?;
            if chain != chain_id {
                return Err(RecoveryStateErrorV1::Context);
            }
            let asset_id = row.descriptor.asset_id;
            if s.rows.keys().next_back().is_some_and(|x| *x >= asset_id) {
                return Err(RecoveryStateErrorV1::Codec("row order"));
            }
            s.rows.insert(asset_id, row);
            s.frozen.insert(asset_id, BTreeMap::new());
        }
        for _ in 0..r.count(MAX_NOTES)? {
            let pos = r.u32()?;
            let asset = r.u32()?;
            let cm = r.digest()?;
            if s.notes.keys().next_back().is_some_and(|x| *x >= pos) {
                return Err(RecoveryStateErrorV1::Codec("note order"));
            }
            s.notes.insert(pos, (asset, cm));
        }
        let mut last = None;
        for _ in 0..r.count(MAX_NOTES)? {
            let asset = r.u32()?;
            let pos = r.u32()?;
            let cm = r.digest()?;
            if last.is_some_and(|x| x >= (asset, pos)) {
                return Err(RecoveryStateErrorV1::Codec("freeze order"));
            }
            last = Some((asset, pos));
            s.frozen
                .get_mut(&asset)
                .ok_or(RecoveryStateErrorV1::Missing)?
                .insert(pos, cm);
        }
        for _ in 0..r.count(MAX_ADMIN_IDS)? {
            let id: [u8; 32] = r.take(32)?.try_into().unwrap();
            if s.admin_ids.last().is_some_and(|x| *x >= id) {
                return Err(RecoveryStateErrorV1::Codec("admin order"));
            }
            s.admin_ids.insert(id);
        }
        if !r.0.is_empty() {
            return Err(RecoveryStateErrorV1::Codec("trailing"));
        }
        s.validate()?;
        if s.encode_exact()?.as_slice() != bytes {
            return Err(RecoveryStateErrorV1::Codec("roundtrip"));
        }
        Ok(s)
    }
}
fn put32(w: &mut Vec<u8>, n: u32) {
    w.extend(n.to_le_bytes());
}
fn put64(w: &mut Vec<u8>, n: u64) {
    w.extend(n.to_le_bytes());
}
fn put_digest(w: &mut Vec<u8>, d: Digest) {
    for x in d {
        put64(w, x);
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(RecoveryStateErrorV1::Codec("short"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn count(&mut self, max: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(RecoveryStateErrorV1::Limit);
        }
        Ok(n)
    }
    fn canonical_digest(&mut self) -> Result<Digest> {
        let mut d = [0; 7];
        for x in &mut d {
            *x = self.u64()?;
            if *x >= transaction_core::constants::FIELD_MODULUS_U64 {
                return Err(RecoveryStateErrorV1::Codec("canonical"));
            }
        }
        Ok(d)
    }
    fn digest(&mut self) -> Result<Digest> {
        digest(self.canonical_digest()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> RecoveryLedgerStateV1 {
        let descriptor = RecoveryDescriptorV1 {
            asset_id: 17,
            stable_policy_id: [1; 7],
            policy_admin_commitment: [2; 7],
            archive_key_commitment: [3; 7],
            maximum_powers: RecoveryPowersV1 {
                transfer: true,
                burn: true,
            },
        };
        let controls = RecoveryControlsV1 {
            epoch: 0,
            delegate_action_commitment: [4; 7],
            revoked: false,
            powers: descriptor.maximum_powers,
            note_freeze_root: core::freeze_defaults(&descriptor, [5; 32]).unwrap()[32],
        };
        RecoveryLedgerStateV1 {
            chain_id: [5; 32],
            parent_height: 0,
            rows: BTreeMap::from([(
                17,
                RecoveryRowV1 {
                    descriptor,
                    controls,
                },
            )]),
            notes: BTreeMap::new(),
            frozen: BTreeMap::from([(17, BTreeMap::new())]),
            admin_ids: BTreeSet::new(),
        }
    }
    #[test]
    fn codec_strict_and_roundtrip() {
        let mut s = fixture();
        s.register_verified_output(7, 17, [6; 7]).unwrap();
        s.admin_ids.insert([7; 32]);
        let b = s.encode_exact().unwrap();
        assert_eq!(RecoveryLedgerStateV1::decode_exact(&b).unwrap(), s);
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(RecoveryLedgerStateV1::decode_exact(&trailing).is_err());
        assert!(RecoveryLedgerStateV1::decode_exact(&b[..b.len() - 1]).is_err());
        let mut noncanonical = b.clone();
        noncanonical[448..456].copy_from_slice(&transaction_core::constants::FIELD_MODULUS_U64.to_le_bytes());
        assert!(RecoveryLedgerStateV1::decode_exact(&noncanonical).is_err());
        let mut duplicate = b[..440].to_vec();
        duplicate.extend_from_slice(&b[440..504]);
        duplicate.extend_from_slice(&b[440..504]);
        duplicate.extend_from_slice(&b[504..]);
        duplicate[436..440].copy_from_slice(&2u32.to_le_bytes());
        assert!(RecoveryLedgerStateV1::decode_exact(&duplicate).is_err());
        let mut epoch = b.clone();
        epoch[40..48].copy_from_slice(&(1u64 << 48).to_le_bytes());
        assert!(RecoveryLedgerStateV1::decode_exact(&epoch).is_err());
    }
    #[test]
    fn known_note_identity_and_status_root() {
        let mut s = fixture();
        assert!(s.register_verified_output(7, 0, [6; 7]).is_err());
        s.register_verified_output(7, 17, [6; 7]).unwrap();
        assert!(s.register_verified_output(7, 17, [6; 7]).is_err());
        assert!(s.freeze_witness(17, 8).is_err());
        let p = s.freeze_witness(17, 7).unwrap();
        assert_eq!(
            core::freeze_root(
                &s.row(17).unwrap().descriptor,
                s.chain_id,
                7,
                [6; 7],
                false,
                &p
            )
            .unwrap(),
            s.row(17).unwrap().controls.note_freeze_root
        );
        s.frozen.get_mut(&17).unwrap().insert(7, [9; 7]);
        assert!(s.encode_exact().is_err());
    }
    #[test]
    fn persisted_admin_ids_and_canonical_snapshot_rollback() {
        let before = fixture();
        let mut after = before.advance_parent(1).unwrap();
        after.admin_ids.insert([9; 32]);
        let restored =
            RecoveryLedgerStateV1::decode_exact(&before.encode_exact().unwrap()).unwrap();
        assert_eq!(restored, before);
        assert!(!restored.admin_action_is_consumed(&[9; 32]));
        assert!(
            RecoveryLedgerStateV1::decode_exact(&after.encode_exact().unwrap())
                .unwrap()
                .admin_action_is_consumed(&[9; 32])
        );
        assert!(after.advance_parent(1).is_err());
    }
    #[test]
    fn genesis_requires_existing_zero_supply_and_admin_row() {
        let r = fixture();
        assert!(
            RecoveryLedgerStateV1::from_genesis_rows(&[5; 32], &[], &[*r.row(17).unwrap()])
                .is_err()
        );
        assert!(RecoveryLedgerStateV1::from_genesis_rows(&[0; 32], &[], &[]).is_err());
        let empty = RecoveryLedgerStateV1::from_genesis_rows(&[5; 32], &[], &[]).unwrap();
        assert!(!empty.is_opted(0));
        assert!(!empty.is_opted(17));
    }
    #[test]
    fn stale_epoch_rejects_before_real_verifier() {
        let s = fixture();
        let row = *s.row(17).unwrap();
        let context = RecoveryContextV1 {
            chain_id: s.chain_id,
            parent_hash: [8; 32],
            parent_height: 0,
            row_commitment: row.commitment(s.chain_id).unwrap(),
        };
        let mut next = row.controls;
        next.epoch = 1;
        let prepared = core::prepare_controls_update(context, row, next).unwrap();
        let mut public = admin::Public::from_prepared(&prepared, 1, [9; 7], None).unwrap();
        let id = public.action_id().unwrap();
        let mut replay = s.clone();
        replay.admin_ids.insert(id);
        assert!(matches!(
            replay.apply_verified_admin(
                &public,
                &[],
                RecoveryCanonicalContextV1 {
                    chain_id: s.chain_id,
                    parent_hash: [8; 32],
                    parent_height: 0
                },
                [2; 7]
            ),
            Err(RecoveryStateErrorV1::Replay)
        ));
        public.after.epoch = 0;
        let before = s.encode_exact().unwrap();
        assert!(s
            .apply_verified_admin(
                &public,
                &[],
                RecoveryCanonicalContextV1 {
                    chain_id: s.chain_id,
                    parent_hash: [8; 32],
                    parent_height: 0
                },
                [2; 7]
            )
            .is_err());
        assert_eq!(s.encode_exact().unwrap(), before);
    }
}
