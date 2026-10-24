//! Unintegrated opt-in foundation. These deterministic helpers verify no proof.
//! Genesis must authenticate descriptors before any notes exist; no retroactive
//! opt-in. Caller verifies exact admin proofs before applying prepared controls,
//! and all routes enforce current credentials, full-asset freeze, target status,
//! conservation, native fee authorization and the existing global nullifier set.
//! Recovery capsule correctness/availability is a separate unsolved interface.
use crate::poseidon2_width16::{poseidon2_width16_compress14, poseidon2_width16_sponge, Felt};
use alloc::vec::Vec;

pub type Digest = [u64; 7];
pub const MAX_EPOCH: u64 = (1 << 48) - 1;
/// Exact existing Smallwood V8 real-nullifier domain; never successor-domain it.
pub const EXISTING_NULLIFIER_DOMAIN: u64 = 0x484e_554c_5632_0001;
pub const DESCRIPTOR: u64 = 0x4152_4445_5343_0001;
pub const CONTROL: u64 = 0x4152_4354_524c_0001;
pub const OWNER: u64 = 0x4152_4f57_4e52_0001;
pub const NF_KEY: u64 = 0x4152_4e46_4b59_0001;
pub const EMPTY: u64 = 0x4152_454d_5054_0001;
pub const FROZEN: u64 = 0x4152_4652_5a4e_0001;
pub const ARCHIVE_KEY_COMMITMENT_DOMAIN_V1: u64 = 0x4152_4152_4348_0001;
pub const DELEGATE_ACTION: u64 = 0x4152_4445_4c47_0001;
pub const NODE: u64 = 0x4152_4e4f_4445_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetRecoveryErrorV1 {
    NativeAsset,
    InvalidDigest,
    InvalidEpoch,
    InvalidPowers,
    Disabled,
    Context,
    Stale,
    Frozen,
    Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryPowersV1 {
    pub transfer: bool,
    pub burn: bool,
}
impl RecoveryPowersV1 {
    fn bits(self) -> u64 {
        self.transfer as u64 | ((self.burn as u64) << 1)
    }
    fn subset(self, max: Self) -> bool {
        self.bits() & !max.bits() == 0
    }
}
/// Immutable, pre-issuance descriptor. Merely constructing it grants no opt-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryDescriptorV1 {
    pub asset_id: u32,
    pub stable_policy_id: Digest,
    pub policy_admin_commitment: Digest,
    pub archive_key_commitment: Digest,
    pub maximum_powers: RecoveryPowersV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryControlsV1 {
    pub epoch: u64,
    pub delegate_action_commitment: Digest,
    pub revoked: bool,
    pub powers: RecoveryPowersV1,
    pub note_freeze_root: Digest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryRowV1 {
    pub descriptor: RecoveryDescriptorV1,
    pub controls: RecoveryControlsV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryContextV1 {
    pub chain_id: [u8; 32],
    pub parent_hash: [u8; 32],
    pub parent_height: u64,
    /// Caller authenticates this commitment within the current registry.
    pub row_commitment: Digest,
}
/// Secret material deliberately has neither Debug nor serde. Caller supplies
/// independently sampled randomness, not a derivation from either action key.
pub struct SharedNullifierKeyV1(pub [u64; 5]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedRecoveryControlsV1 {
    context: RecoveryContextV1,
    before: RecoveryRowV1,
    after: RecoveryRowV1,
    after_commitment: Digest,
}
impl PreparedRecoveryControlsV1 {
    pub fn context(&self) -> RecoveryContextV1 {
        self.context
    }
    pub fn before(&self) -> &RecoveryRowV1 {
        &self.before
    }
    pub fn after(&self) -> &RecoveryRowV1 {
        &self.after
    }
    pub fn after_commitment(&self) -> Digest {
        self.after_commitment
    }
    pub fn governance_commitment(&self) -> Digest {
        self.before.descriptor.policy_admin_commitment
    }
}
fn canonical(words: &[u64]) -> Result<(), AssetRecoveryErrorV1> {
    if words
        .iter()
        .any(|x| *x >= hegemon_field::GOLDILOCKS_MODULUS)
    {
        return Err(AssetRecoveryErrorV1::InvalidDigest);
    }
    Ok(())
}
fn digest(d: &Digest, nonzero: bool) -> Result<(), AssetRecoveryErrorV1> {
    canonical(d)?;
    if nonzero && *d == [0; 7] {
        return Err(AssetRecoveryErrorV1::InvalidDigest);
    }
    Ok(())
}
fn hash(domain: u64, words: &[u64]) -> Result<Digest, AssetRecoveryErrorV1> {
    canonical(words)?;
    poseidon2_width16_sponge(
        domain,
        &words
            .iter()
            .copied()
            .map(Felt::from_u64)
            .collect::<Vec<_>>(),
    )
    .map(|d| d.map(|x| x.as_canonical_u64()))
    .map_err(|_| AssetRecoveryErrorV1::Hash)
}
pub fn chain_words(chain: [u8; 32]) -> Vec<u64> {
    chain
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64)
        .collect()
}
impl RecoveryDescriptorV1 {
    pub fn validate(&self) -> Result<(), AssetRecoveryErrorV1> {
        if self.asset_id == 0 {
            return Err(AssetRecoveryErrorV1::NativeAsset);
        }
        digest(&self.stable_policy_id, true)?;
        digest(&self.policy_admin_commitment, true)?;
        digest(&self.archive_key_commitment, true)?;
        if self.maximum_powers.bits() == 0 {
            return Err(AssetRecoveryErrorV1::InvalidPowers);
        }
        Ok(())
    }
    pub fn commitment(&self, chain: [u8; 32]) -> Result<Digest, AssetRecoveryErrorV1> {
        hash(DESCRIPTOR, &descriptor_words(self, chain)?)
    }
}
impl RecoveryRowV1 {
    pub fn validate(&self) -> Result<(), AssetRecoveryErrorV1> {
        self.descriptor.validate()?;
        let c = self.controls;
        if c.epoch > MAX_EPOCH {
            return Err(AssetRecoveryErrorV1::InvalidEpoch);
        }
        digest(&c.note_freeze_root, true)?;
        digest(&c.delegate_action_commitment, !c.revoked)?;
        if !c.powers.subset(self.descriptor.maximum_powers) {
            return Err(AssetRecoveryErrorV1::InvalidPowers);
        }
        Ok(())
    }
    pub fn commitment(&self, chain: [u8; 32]) -> Result<Digest, AssetRecoveryErrorV1> {
        hash(CONTROL, &row_words(self, chain)?)
    }
    /// This power check never substitutes for note proof or mandatory freeze path.
    pub fn require_power(&self, burn: bool) -> Result<(), AssetRecoveryErrorV1> {
        self.validate()?;
        if self.controls.revoked || self.controls.delegate_action_commitment == [0; 7] {
            return Err(AssetRecoveryErrorV1::Disabled);
        }
        if !(if burn {
            self.controls.powers.burn
        } else {
            self.controls.powers.transfer
        }) {
            return Err(AssetRecoveryErrorV1::InvalidPowers);
        }
        Ok(())
    }
}
pub fn prepare_controls_update(
    context: RecoveryContextV1,
    current: RecoveryRowV1,
    next: RecoveryControlsV1,
) -> Result<PreparedRecoveryControlsV1, AssetRecoveryErrorV1> {
    if context.parent_hash == [0; 32]
        || context.parent_height > MAX_EPOCH
        || current.commitment(context.chain_id)? != context.row_commitment
    {
        return Err(AssetRecoveryErrorV1::Context);
    }
    if current.controls.epoch.checked_add(1) != Some(next.epoch) || next.epoch > MAX_EPOCH {
        return Err(AssetRecoveryErrorV1::InvalidEpoch);
    }
    let after = RecoveryRowV1 {
        descriptor: current.descriptor,
        controls: next,
    };
    let after_commitment = after.commitment(context.chain_id)?;
    Ok(PreparedRecoveryControlsV1 {
        context,
        before: current,
        after,
        after_commitment,
    })
}
/// No proof is checked here. Caller must verify the declared EXISTING policy
/// admin against prepared context/before/after/intent and persist replay identity.
/// Reorgs restore a canonical row/context; epochs are monotone on each branch.
pub fn apply_controls_after_proof(
    current: &mut RecoveryRowV1,
    context: RecoveryContextV1,
    prepared: PreparedRecoveryControlsV1,
) -> Result<(), AssetRecoveryErrorV1> {
    if context != prepared.context || *current != prepared.before {
        return Err(AssetRecoveryErrorV1::Stale);
    }
    *current = prepared.after;
    Ok(())
}
/// Canonical public descriptor preimage: chain8(u32le),asset,policy7,admin7,archive7,powerbits.
pub fn descriptor_words(
    d: &RecoveryDescriptorV1,
    chain: [u8; 32],
) -> Result<Vec<u64>, AssetRecoveryErrorV1> {
    d.validate()?;
    let mut w = chain_words(chain);
    w.push(d.asset_id as u64);
    w.extend(d.stable_policy_id);
    w.extend(d.policy_admin_commitment);
    w.extend(d.archive_key_commitment);
    w.push(d.maximum_powers.bits());
    Ok(w)
}
/// Canonical control preimage; subset-of-maximum validation belongs to row.validate.
pub fn controls_words(c: &RecoveryControlsV1) -> Result<Vec<u64>, AssetRecoveryErrorV1> {
    if c.epoch > MAX_EPOCH {
        return Err(AssetRecoveryErrorV1::InvalidEpoch);
    }
    digest(&c.delegate_action_commitment, !c.revoked)?;
    digest(&c.note_freeze_root, true)?;
    let mut w = Vec::new();
    w.push(c.epoch);
    w.extend(c.delegate_action_commitment);
    w.push(c.revoked as u64);
    w.push(c.powers.bits());
    w.extend(c.note_freeze_root);
    Ok(w)
}
pub fn row_words(r: &RecoveryRowV1, chain: [u8; 32]) -> Result<Vec<u64>, AssetRecoveryErrorV1> {
    r.validate()?;
    let mut w = r.descriptor.commitment(chain)?.to_vec();
    w.extend(controls_words(&r.controls)?);
    Ok(w)
}
/// All 256-bit preimages are allowed, including zero. Exactly eight little-endian
/// u32 words are hashed; descriptor validation separately requires a nonzero digest.
/// Secret-bearing input is never formatted or serialized here.
pub fn archive_key_commitment(secret: &[u8; 32]) -> Result<Digest, AssetRecoveryErrorV1> {
    hash(ARCHIVE_KEY_COMMITMENT_DOMAIN_V1, &chain_words(*secret))
}
/// Secret-bearing parameter is never formatted or serialized here.
pub fn delegate_action_commitment(secret: Digest) -> Result<Digest, AssetRecoveryErrorV1> {
    digest(&secret, true)?;
    let d = hash(DELEGATE_ACTION, &secret)?;
    digest(&d, true)?;
    Ok(d)
}
pub fn recovery_owner(
    chain: [u8; 32],
    asset_id: u32,
    stable_policy_id: Digest,
    holder_authority: Digest,
    shared_nf_key: [u64; 5],
) -> Result<Digest, AssetRecoveryErrorV1> {
    if asset_id == 0 {
        return Err(AssetRecoveryErrorV1::NativeAsset);
    }
    digest(&stable_policy_id, true)?;
    digest(&holder_authority, true)?;
    let k = key7(shared_nf_key)?;
    let mut w = chain_words(chain);
    w.push(asset_id as u64);
    w.extend(stable_policy_id);
    w.extend(holder_authority);
    w.extend(hash(NF_KEY, &k)?);
    hash(OWNER, &w)
}
fn key7(k: [u64; 5]) -> Result<Digest, AssetRecoveryErrorV1> {
    canonical(&k)?;
    if k == [0; 5] {
        return Err(AssetRecoveryErrorV1::InvalidDigest);
    }
    Ok([k[0], k[1], k[2], k[3], k[4], 0, 0])
}
pub fn recovery_nullifier(
    shared_nf_key: [u64; 5],
    position: u32,
    rho: [u64; 4],
) -> Result<Digest, AssetRecoveryErrorV1> {
    let mut w = key7(shared_nf_key)?.to_vec();
    w.push(position as u64);
    w.extend(rho);
    hash(EXISTING_NULLIFIER_DOMAIN, &w)
}
/// Sparse32 defaults are uniform empty leaves but context-bound. Frozen leaves
/// additionally bind canonical note position AND exact note commitment. Empty leaves are uniform;
/// the proof must independently authenticate the note at this position.
pub fn freeze_empty(
    descriptor: &RecoveryDescriptorV1,
    chain: [u8; 32],
) -> Result<Digest, AssetRecoveryErrorV1> {
    hash(EMPTY, &descriptor.commitment(chain)?)
}
pub fn freeze_leaf(
    descriptor: &RecoveryDescriptorV1,
    chain: [u8; 32],
    position: u32,
    note_commitment: Digest,
    frozen: bool,
) -> Result<Digest, AssetRecoveryErrorV1> {
    digest(&note_commitment, true)?;
    let mut w = descriptor.commitment(chain)?.to_vec();
    if frozen {
        w.push(position as u64);
        w.extend(note_commitment);
    }
    hash(if frozen { FROZEN } else { EMPTY }, &w)
}
/// Level-separated compression domains for this fresh tree only.
pub fn freeze_node_domain(level: usize) -> Result<u64, AssetRecoveryErrorV1> {
    if level >= 32 {
        return Err(AssetRecoveryErrorV1::Context);
    }
    Ok(NODE + level as u64)
}
/// Context is authenticated in every empty/frozen leaf. Internal nodes use the
/// existing one-permutation compression; moving a subtree across contexts would
/// require a leaf/node collision, not a repeated context hash at every level.
pub fn freeze_node(
    descriptor: &RecoveryDescriptorV1,
    chain: [u8; 32],
    level: usize,
    left: Digest,
    right: Digest,
) -> Result<Digest, AssetRecoveryErrorV1> {
    descriptor.validate()?;
    if chain == [0; 32] {
        return Err(AssetRecoveryErrorV1::Context);
    }
    digest(&left, false)?;
    digest(&right, false)?;
    Ok(poseidon2_width16_compress14(
        freeze_node_domain(level)?,
        &left.map(Felt::from_u64),
        &right.map(Felt::from_u64),
    )
    .map(|f| f.as_canonical_u64()))
}
pub fn freeze_defaults(
    descriptor: &RecoveryDescriptorV1,
    chain: [u8; 32],
) -> Result<[Digest; 33], AssetRecoveryErrorV1> {
    let mut d = [[0; 7]; 33];
    d[0] = freeze_empty(descriptor, chain)?;
    for i in 0..32 {
        d[i + 1] = freeze_node(descriptor, chain, i, d[i], d[i])?;
    }
    Ok(d)
}
pub fn freeze_root(
    descriptor: &RecoveryDescriptorV1,
    chain: [u8; 32],
    position: u32,
    note_commitment: Digest,
    frozen: bool,
    path: &[Digest; 32],
) -> Result<Digest, AssetRecoveryErrorV1> {
    let mut r = freeze_leaf(descriptor, chain, position, note_commitment, frozen)?;
    for (i, s) in path.iter().enumerate() {
        r = if position >> i & 1 == 0 {
            freeze_node(descriptor, chain, i, r, *s)?
        } else {
            freeze_node(descriptor, chain, i, *s, r)?
        };
    }
    Ok(r)
}
/// No skip/default path option. Every route must supply its current status path.
pub fn require_unfrozen(
    row: &RecoveryRowV1,
    chain: [u8; 32],
    position: u32,
    note_commitment: Digest,
    path: &[Digest; 32],
) -> Result<(), AssetRecoveryErrorV1> {
    row.validate()?;
    if freeze_root(
        &row.descriptor,
        chain,
        position,
        note_commitment,
        false,
        path,
    )? != row.controls.note_freeze_root
    {
        return Err(AssetRecoveryErrorV1::Frozen);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row() -> RecoveryRowV1 {
        let descriptor = RecoveryDescriptorV1 {
            asset_id: 17,
            stable_policy_id: [1; 7],
            policy_admin_commitment: [2; 7],
            archive_key_commitment: [3; 7],
            maximum_powers: RecoveryPowersV1 {
                transfer: true,
                burn: false,
            },
        };
        let note_freeze_root = freeze_defaults(&descriptor, [4; 32]).unwrap()[32];
        RecoveryRowV1 {
            descriptor,
            controls: RecoveryControlsV1 {
                epoch: 0,
                delegate_action_commitment: [5; 7],
                revoked: false,
                powers: descriptor.maximum_powers,
                note_freeze_root,
            },
        }
    }
    fn context(r: RecoveryRowV1) -> RecoveryContextV1 {
        RecoveryContextV1 {
            chain_id: [4; 32],
            parent_hash: [6; 32],
            parent_height: 7,
            row_commitment: r.commitment([4; 32]).unwrap(),
        }
    }
    #[test]
    fn epochs_replay_and_canonical_rollback() {
        let mut r = row();
        let original = r;
        let ctx = context(r);
        let mut next = r.controls;
        next.epoch = 1;
        next.revoked = true;
        let p = prepare_controls_update(ctx, r, next).unwrap();
        apply_controls_after_proof(&mut r, ctx, p).unwrap();
        assert_eq!(
            apply_controls_after_proof(&mut r, ctx, p),
            Err(AssetRecoveryErrorV1::Stale)
        );
        assert_eq!(r.require_power(false), Err(AssetRecoveryErrorV1::Disabled));
        r = original;
        apply_controls_after_proof(&mut r, ctx, p).unwrap();
        assert_eq!(r.controls.epoch, 1);
        next.epoch = MAX_EPOCH + 1;
        assert!(prepare_controls_update(context(r), r, next).is_err());
    }
    #[test]
    fn immutable_asset_and_power_boundary() {
        let r = row();
        let mut next = r.controls;
        next.epoch = 1;
        next.powers.burn = true;
        assert_eq!(
            prepare_controls_update(context(r), r, next),
            Err(AssetRecoveryErrorV1::InvalidPowers)
        );
        let mut wrong = r;
        wrong.descriptor.asset_id = 18;
        assert_eq!(
            prepare_controls_update(context(r), wrong, next),
            Err(AssetRecoveryErrorV1::Context)
        );
        let mut native = r.descriptor;
        native.asset_id = 0;
        assert_eq!(native.validate(), Err(AssetRecoveryErrorV1::NativeAsset));
    }
    #[test]
    fn holder_and_delegate_share_exact_nf() {
        let k = [9; 5];
        let owner = recovery_owner([4; 32], 17, [1; 7], [8; 7], k).unwrap();
        assert_ne!(
            owner,
            recovery_owner([4; 32], 18, [1; 7], [8; 7], k).unwrap()
        );
        assert_ne!(
            owner,
            recovery_owner([4; 32], 17, [1; 7], [8; 7], [10; 5]).unwrap()
        );
        let nf = recovery_nullifier(k, 41, [12; 4]).unwrap();
        let mut exact = vec![9, 9, 9, 9, 9, 0, 0, 41];
        exact.extend([12; 4]);
        assert_eq!(nf, hash(EXISTING_NULLIFIER_DOMAIN, &exact).unwrap());
        assert_ne!(nf, recovery_nullifier(k, 42, [12; 4]).unwrap());
    }
    #[test]
    fn archive_key_all_bits_and_zero_encoding() {
        assert_eq!(
            archive_key_commitment(&[0; 32]).unwrap(),
            hash(ARCHIVE_KEY_COMMITMENT_DOMAIN_V1, &[0; 8]).unwrap()
        );
        assert_eq!(
            archive_key_commitment(&[255; 32]).unwrap(),
            hash(ARCHIVE_KEY_COMMITMENT_DOMAIN_V1, &[u32::MAX as u64; 8]).unwrap()
        );
        let mut high = [0; 32];
        high[31] = 128;
        assert_ne!(
            archive_key_commitment(&high).unwrap(),
            archive_key_commitment(&[0; 32]).unwrap()
        );
    }
    #[test]
    fn encoding_and_delegate_commitment() {
        let r = row();
        assert_eq!(descriptor_words(&r.descriptor, [4; 32]).unwrap().len(), 31);
        assert_eq!(controls_words(&r.controls).unwrap().len(), 17);
        assert_eq!(row_words(&r, [4; 32]).unwrap().len(), 24);
        assert_eq!(
            delegate_action_commitment([0; 7]),
            Err(AssetRecoveryErrorV1::InvalidDigest)
        );
        assert_ne!(
            delegate_action_commitment([8; 7]).unwrap(),
            hash(NF_KEY, &[8; 7]).unwrap()
        );
        assert_ne!(
            freeze_leaf(&r.descriptor, [4; 32], 41, [9; 7], true).unwrap(),
            freeze_leaf(&r.descriptor, [4; 32], 41, [10; 7], true).unwrap()
        );
    }
    #[test]
    fn compressed_nodes_level_domains_and_context_leaves() {
        let r = row();
        let d = &r.descriptor;
        let a = freeze_defaults(d, [4; 32]).unwrap();
        let b = freeze_defaults(d, [7; 32]).unwrap();
        assert_ne!(a[0], b[0]);
        assert_ne!(a[32], b[32]);
        assert_ne!(
            freeze_node(d, [4; 32], 0, a[0], a[0]).unwrap(),
            freeze_node(d, [4; 32], 1, a[0], a[0]).unwrap()
        );
        assert_eq!(
            freeze_node(d, [4; 32], 0, a[0], a[0]).unwrap(),
            poseidon2_width16_compress14(
                NODE,
                &a[0].map(Felt::from_u64),
                &a[0].map(Felt::from_u64)
            )
            .map(|f| f.as_canonical_u64())
        );
        assert!(freeze_node_domain(32).is_err());
        assert!(freeze_node(d, [0; 32], 0, a[0], a[0]).is_err());
        let mut invalid = a[0];
        invalid[0] = hegemon_field::GOLDILOCKS_MODULUS;
        assert!(freeze_node(d, [4; 32], 0, invalid, a[0]).is_err());
    }
    #[test]
    fn current_status_no_skip_and_context_binding() {
        let mut r = row();
        let d = freeze_defaults(&r.descriptor, [4; 32]).unwrap();
        let path: [Digest; 32] = core::array::from_fn(|i| d[i]);
        require_unfrozen(&r, [4; 32], 41, [9; 7], &path).unwrap();
        r.controls.note_freeze_root =
            freeze_root(&r.descriptor, [4; 32], 41, [9; 7], true, &path).unwrap();
        assert_eq!(
            require_unfrozen(&r, [4; 32], 41, [9; 7], &path),
            Err(AssetRecoveryErrorV1::Frozen)
        );
        assert_ne!(
            r.controls.note_freeze_root,
            freeze_root(&r.descriptor, [7; 32], 41, [9; 7], true, &path).unwrap()
        );
        assert_ne!(
            r.controls.note_freeze_root,
            freeze_root(&r.descriptor, [4; 32], 42, [9; 7], true, &path).unwrap()
        );
    }
}
