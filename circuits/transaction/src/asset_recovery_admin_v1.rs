//! Fresh opt-in recovery governance: existing per-asset policy-admin knowledge,
//! exact current row transition, and authenticated sparse32 freeze mutation.
//! The ledger authenticates the descriptor/admin against CURRENT asset state,
//! target position/commitment/asset, canonical context/expiry, and replay identity.
//! This module grants neither native HGN powers nor production authority.
#![forbid(unsafe_code)]
pub use crate::asset_policy_admin_v1::policy_admin_commitment;
use crate::{
    asset_policy_admin_v1::POLICY_ADMIN_COMMITMENT_DOMAIN,
    smallwood_engine::SmallwoodArithmetization,
    smallwood_htlc::circuit::{
        boolean, equal, input, nonzero, range, select, HtlcAdapter, HtlcGeometry, Scope, Word,
    },
    smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView},
    TransactionCircuitError,
};
use hegemon_field::{PrimeCharacteristicRing, GOLDILOCKS_MODULUS};
use transaction_core::{
    asset_recovery_v1::{
        self as recovery, PreparedRecoveryControlsV1, RecoveryContextV1, RecoveryControlsV1,
        RecoveryRowV1,
    },
    poseidon2_width16::{poseidon2_width16_compress14_ring, poseidon2_width16_sponge_ring},
};
pub type Digest = [u64; 7];
pub const RELATION_ID: &str = "Hegemon.AssetRecoveryAdmin.ControlsFreeze32.CompFF01.v1";
pub const PUBLIC_WORDS: usize = 128;
pub const PRODUCTION_AUTHORIZED: bool = false;
pub const SOURCE_LOWERING_CERTIFICATE_COMPLETE: bool = false;
pub const CANDIDATE_PROOF_MAGIC: [u8; 4] = *b"SMZR";
pub const BINDING_HEADER: &[u8; 16] = b"HGRECOV1\x03\x00\x00\x00\x00\x00\x00\x00";
pub const MAX_CANDIDATE_PROOF_BYTES: usize = crate::asset_recovery_backend_v1::MAX_PROOF_BYTES;
const HEIGHT: usize = 39;
const BEFORE: usize = 40;
const AFTER: usize = 57;
const ROW: usize = 74;
const EXPIRES: usize = 81;
const INTENT: usize = 82;
const FREEZE: usize = 89;
const POSITION: usize = 90;
const NOTE: usize = 91;
const WAS: usize = 98;
const NOW: usize = 99;
const AFTER_ROW: usize = 100;
const SOURCE: usize = 107;
const UNUSED: usize = 123;
fn error(s: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(s)
}
fn canonical_nonzero(d: &Digest) -> bool {
    d.iter().any(|x| *x != 0) && d.iter().all(|x| *x < GOLDILOCKS_MODULUS)
}
fn source_words() -> [u64; 16] {
    let d = relation_digest();
    core::array::from_fn(|i| u32::from_le_bytes(d[4 * i..4 * i + 4].try_into().unwrap()) as u64)
}
fn append_bytes(w: &mut Vec<u64>, b: &[u8; 32]) {
    w.extend(
        b.chunks_exact(4)
            .map(|x| u32::from_le_bytes(x.try_into().unwrap()) as u64),
    );
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreezeMutation {
    pub position: u32,
    pub note_commitment: Digest,
    pub before_frozen: bool,
    pub after_frozen: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub context: RecoveryContextV1,
    pub before: RecoveryRowV1,
    pub after: RecoveryControlsV1,
    pub expires_at: u64,
    pub action_intent: Digest,
    pub freeze: Option<FreezeMutation>,
}
impl Public {
    pub fn from_prepared(
        p: &PreparedRecoveryControlsV1,
        expires_at: u64,
        action_intent: Digest,
        freeze: Option<FreezeMutation>,
    ) -> Result<Self, TransactionCircuitError> {
        let public = Self {
            context: p.context(),
            before: *p.before(),
            after: p.after().controls,
            expires_at,
            action_intent,
            freeze,
        };
        public.validate_structure()?;
        Ok(public)
    }
    /// `p` must come from CURRENT authenticated state, not an attacker row.
    /// Target membership/asset and global action replay are ledger obligations.
    pub fn verify_prepared(
        &self,
        p: &PreparedRecoveryControlsV1,
    ) -> Result<(), TransactionCircuitError> {
        self.validate_structure()?;
        if *self != Self::from_prepared(p, self.expires_at, self.action_intent, self.freeze)? {
            return Err(error("recovery admin current prepared transition mismatch"));
        }
        Ok(())
    }
    pub fn validate_structure(&self) -> Result<(), TransactionCircuitError> {
        if self.context.chain_id == [0; 32]
            || self.context.parent_hash == [0; 32]
            || self.expires_at > recovery::MAX_EPOCH
            || self.expires_at < self.context.parent_height
            || !canonical_nonzero(&self.action_intent)
        {
            return Err(error("recovery admin public context or expiry"));
        }
        recovery::prepare_controls_update(self.context, self.before, self.after)
            .map_err(|_| error("recovery admin row or epoch"))?;
        match self.freeze {
            Some(f)
                if !canonical_nonzero(&f.note_commitment) || f.before_frozen == f.after_frozen =>
            {
                return Err(error("recovery admin freeze shape"))
            }
            None if self.before.controls.note_freeze_root != self.after.note_freeze_root => {
                return Err(error("recovery admin no-path root change"))
            }
            _ => (),
        }
        Ok(())
    }
    /// descriptor31, hash8,height, before17,after17,row7,expiry,intent7,
    /// freeze/position/note7/flags, after-row7, source16, five canonical zeros.
    pub fn words(&self) -> Result<[u64; PUBLIC_WORDS], TransactionCircuitError> {
        self.validate_structure()?;
        let mut w = recovery::descriptor_words(&self.before.descriptor, self.context.chain_id)
            .map_err(|_| error("recovery admin descriptor"))?;
        append_bytes(&mut w, &self.context.parent_hash);
        w.push(self.context.parent_height);
        w.extend(
            recovery::controls_words(&self.before.controls)
                .map_err(|_| error("recovery admin before"))?,
        );
        w.extend(recovery::controls_words(&self.after).map_err(|_| error("recovery admin after"))?);
        w.extend(self.context.row_commitment);
        w.push(self.expires_at);
        w.extend(self.action_intent);
        if let Some(f) = self.freeze {
            w.extend([1, u64::from(f.position)]);
            w.extend(f.note_commitment);
            w.extend([u64::from(f.before_frozen), u64::from(f.after_frozen)]);
        } else {
            w.extend([0; 11]);
        }
        w.extend(
            RecoveryRowV1 {
                descriptor: self.before.descriptor,
                controls: self.after,
            }
            .commitment(self.context.chain_id)
            .map_err(|_| error("recovery admin after commitment"))?,
        );
        w.extend(source_words());
        if w.len() != UNUSED {
            return Err(error("recovery admin schema drift"));
        }
        w.resize(PUBLIC_WORDS, 0);
        if w.iter().any(|x| *x >= GOLDILOCKS_MODULUS) {
            return Err(error("recovery admin noncanonical public word"));
        }
        w.try_into()
            .map_err(|_| error("recovery admin public length"))
    }
    pub fn binding_bytes(&self) -> Result<Vec<u8>, TransactionCircuitError> {
        let mut b = BINDING_HEADER.to_vec();
        b.extend(self.words()?.into_iter().flat_map(u64::to_le_bytes));
        Ok(b)
    }
    /// Semantic identity excludes randomized proof bytes. Persist atomically.
    pub fn action_id(&self) -> Result<[u8; 32], TransactionCircuitError> {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(b"Hegemon.AssetRecoveryAdmin.Action.v1");
        h.update(self.binding_bytes()?);
        Ok(h.finalize().into())
    }
}
/// Secrets/paths are never Debug/serde/public statement fields.
#[derive(Clone)]
pub struct Witness {
    pub admin_secret: Digest,
    pub freeze_siblings: [Digest; 32],
}
pub struct Adapter {
    inner: HtlcAdapter,
}
fn hash(d: u64, w: &[Word]) -> Result<[Word; 7], TransactionCircuitError> {
    poseidon2_width16_sponge_ring(d, w).map_err(|_| error("recovery admin hash shape"))
}
fn vector_nonzero(active: Word, w: &[Word], values: &[u64]) {
    let i = values.iter().position(|x| *x != 0).unwrap_or(0);
    nonzero(Word::ONE - active + active * w[i]);
}
impl Adapter {
    pub fn from_public(public: &Public) -> Result<Self, TransactionCircuitError> {
        let words = public.words()?;
        let scope = Scope::start();
        let p: [Word; PUBLIC_WORDS] = core::array::from_fn(|_| input());
        let secret: [Word; 7] = core::array::from_fn(|_| input());
        let selectors: [Word; 7] = core::array::from_fn(|_| input());
        let path: [[Word; 7]; 32] = core::array::from_fn(|_| core::array::from_fn(|_| input()));
        for x in &p[..8] {
            range(*x, 32);
        }
        for x in &p[31..39] {
            range(*x, 32);
        }
        range(p[8], 32);
        nonzero(p[8]);
        range(p[HEIGHT], 48);
        for start in [9, 16, 23] {
            vector_nonzero(Word::ONE, &p[start..start + 7], &words[start..start + 7]);
        }
        let max = range(p[30], 2);
        nonzero(p[30]);
        for start in [BEFORE, AFTER] {
            range(p[start], 48);
            boolean(p[start + 8]);
            let bits = range(p[start + 9], 2);
            for i in 0..2 {
                equal(bits[i] * (Word::ONE - max[i]), Word::ZERO);
            }
            vector_nonzero(
                Word::ONE - p[start + 8],
                &p[start + 1..start + 8],
                &words[start + 1..start + 8],
            );
            vector_nonzero(
                Word::ONE,
                &p[start + 10..start + 17],
                &words[start + 10..start + 17],
            );
        }
        equal(p[AFTER], p[BEFORE] + Word::ONE);
        range(p[EXPIRES], 48);
        range(p[EXPIRES] - p[HEIGHT], 48);
        vector_nonzero(
            Word::ONE,
            &p[INTENT..INTENT + 7],
            &words[INTENT..INTENT + 7],
        );
        let descriptor = hash(recovery::DESCRIPTOR, &p[..31])?;
        for (start, target) in [(BEFORE, ROW), (AFTER, AFTER_ROW)] {
            let mut w = descriptor.to_vec();
            w.extend_from_slice(&p[start..start + 17]);
            for (a, b) in hash(recovery::CONTROL, &w)?
                .into_iter()
                .zip(&p[target..target + 7])
            {
                equal(a, *b);
            }
        }
        for x in selectors {
            boolean(x);
        }
        equal(selectors.into_iter().sum(), Word::ONE);
        nonzero(secret.into_iter().zip(selectors).map(|(a, b)| a * b).sum());
        let binding = [
            p[8],
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
        ];
        let admin =
            poseidon2_width16_compress14_ring(POLICY_ADMIN_COMMITMENT_DOMAIN, &secret, &binding);
        for i in 0..7 {
            equal(admin[i], p[16 + i]);
        }
        boolean(p[FREEZE]);
        boolean(p[WAS]);
        boolean(p[NOW]);
        let directions = range(p[POSITION], 32);
        equal(p[FREEZE] * (p[WAS] + p[NOW] - Word::ONE), Word::ZERO);
        for x in &p[POSITION..AFTER_ROW] {
            equal((Word::ONE - p[FREEZE]) * *x, Word::ZERO);
        }
        vector_nonzero(p[FREEZE], &p[NOTE..NOTE + 7], &words[NOTE..NOTE + 7]);
        for sibling in path {
            for x in sibling {
                equal((Word::ONE - p[FREEZE]) * x, Word::ZERO);
            }
        }
        if public.freeze.is_some() {
            let empty = hash(recovery::EMPTY, &descriptor)?;
            let mut frozen_words = descriptor.to_vec();
            frozen_words.push(p[POSITION]);
            frozen_words.extend_from_slice(&p[NOTE..NOTE + 7]);
            let frozen = hash(recovery::FROZEN, &frozen_words)?;
            let mut before = core::array::from_fn(|i| select(p[WAS], empty[i], frozen[i]));
            let mut after = core::array::from_fn(|i| select(p[NOW], empty[i], frozen[i]));
            for level in 0..32 {
                let sibling = path[level];
                let next = |root: [Word; 7]| -> Result<[Word; 7], TransactionCircuitError> {
                    let left: [Word; 7] =
                        core::array::from_fn(|i| select(directions[level], root[i], sibling[i]));
                    let right: [Word; 7] =
                        core::array::from_fn(|i| select(directions[level], sibling[i], root[i]));
                    let domain = recovery::freeze_node_domain(level)
                        .map_err(|_| error("recovery admin freeze level"))?;
                    Ok(poseidon2_width16_compress14_ring(domain, &left, &right))
                };
                before = next(before)?;
                after = next(after)?;
            }
            for i in 0..7 {
                equal(before[i], p[BEFORE + 10 + i]);
                equal(after[i], p[AFTER + 10 + i]);
            }
        } else {
            for i in 0..7 {
                equal(p[BEFORE + 10 + i], p[AFTER + 10 + i]);
            }
        }
        for (i, v) in source_words().into_iter().enumerate() {
            equal(p[SOURCE + i], Word::from_u64(v));
        }
        for x in &p[UNUSED..] {
            equal(*x, Word::ZERO);
        }
        let mut inner = HtlcAdapter::from_graph(scope.finish());
        for (wire, value) in p.into_iter().zip(words) {
            inner.bind_public(wire, value);
        }
        Ok(Self { inner })
    }
    pub fn geometry(&self) -> &HtlcGeometry {
        self.inner.geometry()
    }
    pub fn lower(
        &self,
        public: &Public,
        witness: &Witness,
    ) -> Result<Vec<u64>, TransactionCircuitError> {
        if !canonical_nonzero(&witness.admin_secret)
            || witness
                .freeze_siblings
                .iter()
                .flatten()
                .any(|x| *x >= GOLDILOCKS_MODULUS)
        {
            return Err(error("recovery admin witness shape"));
        }
        let mut w = public.words()?.to_vec();
        w.extend(witness.admin_secret);
        let selected = witness.admin_secret.iter().position(|x| *x != 0);
        w.extend((0..7).map(|i| u64::from(selected == Some(i))));
        w.extend(witness.freeze_siblings.into_iter().flatten());
        self.inner.evaluate(&w)
    }
    pub fn verify_packed_witness(&self, w: &[u64]) -> Result<(), TransactionCircuitError> {
        self.inner.verify_packed_witness(w)
    }
}
pub fn compile(
    public: &Public,
    witness: &Witness,
) -> Result<(Adapter, Vec<u64>), TransactionCircuitError> {
    let a = Adapter::from_public(public)?;
    let w = a.lower(public, witness)?;
    a.verify_packed_witness(&w)?;
    Ok((a, w))
}
impl SmallwoodConstraintAdapter for Adapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::DirectPacked64AssetSpendSha512Smze
    }
    fn row_count(&self) -> usize {
        self.inner.row_count()
    }
    fn packing_factor(&self) -> usize {
        64
    }
    fn constraint_degree(&self) -> usize {
        2
    }
    fn linear_constraint_count(&self) -> usize {
        self.inner.linear_constraint_count()
    }
    fn constraint_count(&self) -> usize {
        self.inner.constraint_count()
    }
    fn linear_constraint_offsets(&self) -> &[u32] {
        self.inner.linear_constraint_offsets()
    }
    fn linear_constraint_indices(&self) -> &[u32] {
        self.inner.linear_constraint_indices()
    }
    fn linear_constraint_coefficients(&self) -> &[u64] {
        self.inner.linear_constraint_coefficients()
    }
    fn linear_targets(&self) -> &[u64] {
        self.inner.linear_targets()
    }
    fn auxiliary_witness_words(&self) -> &[u64] {
        &[]
    }
    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(0)
    }
    fn nonlinear_eval_view<'a>(
        &self,
        point: u64,
        rows: &'a [u64],
        auxiliary: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        self.inner.nonlinear_eval_view(point, rows, auxiliary)
    }
    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        self.inner.compute_constraints_u64(view, out)
    }
}

pub fn candidate_proof_size_hint(public: &Public) -> Result<usize, TransactionCircuitError> {
    crate::asset_recovery_backend_v1::projected_bytes(&Adapter::from_public(public)?)
}

pub fn prove_candidate(
    public: &Public,
    witness: &Witness,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let (adapter, packed) = compile(public, witness)?;
    crate::asset_recovery_backend_v1::prove(
        &adapter,
        &packed,
        &public.binding_bytes()?,
        &relation_digest(),
    )
}

/// This verifies secret knowledge and binding, not registry freshness. The
/// integrating ledger must also call `verify_prepared` against current state.
pub fn verify_candidate(public: &Public, proof: &[u8]) -> Result<(), TransactionCircuitError> {
    if candidate_proof_size_hint(public)? > MAX_CANDIDATE_PROOF_BYTES {
        return Err(error("recovery admin projection exceeds cap"));
    }
    crate::asset_recovery_backend_v1::verify(
        &Adapter::from_public(public)?,
        &public.binding_bytes()?,
        &relation_digest(),
        proof,
    )
}

pub fn relation_digest() -> [u8; 64] {
    use sha2::{Digest as _, Sha512};
    static DIGEST: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut hash = Sha512::new();
        hash.update(b"Hegemon.AssetRecoveryAdmin.SourceManifest.v1");
        hash.update(RELATION_ID.as_bytes());
        hash.update(include_bytes!("asset_recovery_backend_v1.rs"));
        let sources: &[(&str, &[u8])] = &[
            (
                "asset_policy_admin_v1.rs",
                include_bytes!("asset_policy_admin_v1.rs"),
            ),
            (
                "../../transaction-core/src/asset_recovery_v1.rs",
                include_bytes!("../../transaction-core/src/asset_recovery_v1.rs"),
            ),
            (
                "asset_recovery_admin_v1.rs",
                include_bytes!("asset_recovery_admin_v1.rs"),
            ),
            (
                "smallwood_htlc/circuit.rs",
                include_bytes!("smallwood_htlc/circuit.rs"),
            ),
            ("smallwood_engine.rs", include_bytes!("smallwood_engine.rs")),
            (
                "smallwood_semantics.rs",
                include_bytes!("smallwood_semantics.rs"),
            ),
            (
                "smallwood_hx512_transcript.rs",
                include_bytes!("smallwood_hx512_transcript.rs"),
            ),
            (
                "smallwood_v6_transcript.rs",
                include_bytes!("smallwood_v6_transcript.rs"),
            ),
            (
                "smallwood_poseidon2_v8_rng_refinement.rs",
                include_bytes!("smallwood_poseidon2_v8_rng_refinement.rs"),
            ),
            (
                "smallwood_poseidon2_v8_hash_schedule.rs",
                include_bytes!("smallwood_poseidon2_v8_hash_schedule.rs"),
            ),
            (
                "smallwood_poseidon2_v8_types.rs",
                include_bytes!("smallwood_poseidon2_v8_types.rs"),
            ),
            (
                "smallwood_poseidon2_v8_zk_refinement.rs",
                include_bytes!("smallwood_poseidon2_v8_zk_refinement.rs"),
            ),
            (
                "smallwood_v6_envelope.rs",
                include_bytes!("smallwood_v6_envelope.rs"),
            ),
            (
                "full_shake448_statement.rs",
                include_bytes!("full_shake448_statement.rs"),
            ),
            ("error.rs", include_bytes!("error.rs")),
            (
                "../../transaction-core/src/asset_registry_v1.rs",
                include_bytes!("../../transaction-core/src/asset_registry_v1.rs"),
            ),
            (
                "../../transaction-core/src/stablecoin_poseidon2_v8.rs",
                include_bytes!("../../transaction-core/src/stablecoin_poseidon2_v8.rs"),
            ),
            (
                "../../transaction-core/src/poseidon2_width16.rs",
                include_bytes!("../../transaction-core/src/poseidon2_width16.rs"),
            ),
            (
                "../../transaction-core/src/poseidon2.rs",
                include_bytes!("../../transaction-core/src/poseidon2.rs"),
            ),
            (
                "../../transaction-core/src/poseidon2_constants.rs",
                include_bytes!("../../transaction-core/src/poseidon2_constants.rs"),
            ),
            (
                "../../transaction-core/src/constants.rs",
                include_bytes!("../../transaction-core/src/constants.rs"),
            ),
            (
                "../../transaction-core/src/types.rs",
                include_bytes!("../../transaction-core/src/types.rs"),
            ),
            (
                "../../transaction-core/src/hashing_pq.rs",
                include_bytes!("../../transaction-core/src/hashing_pq.rs"),
            ),
            (
                "../../hegemon-field/src/lib.rs",
                include_bytes!("../../hegemon-field/src/lib.rs"),
            ),
            ("../../../Cargo.lock", include_bytes!("../../../Cargo.lock")),
        ];
        for (path, bytes) in sources {
            hash.update((path.len() as u64).to_le_bytes());
            hash.update(path.as_bytes());
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        hash.finalize().into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use recovery::{RecoveryDescriptorV1, RecoveryPowersV1};
    const SECRET: Digest = [0, 2, 3, 4, 5, 6, 7];
    fn fixture() -> (Public, Witness) {
        let descriptor = RecoveryDescriptorV1 {
            asset_id: 17,
            stable_policy_id: [3; 7],
            policy_admin_commitment: policy_admin_commitment(17, SECRET).unwrap(),
            archive_key_commitment: [4; 7],
            maximum_powers: RecoveryPowersV1 {
                transfer: true,
                burn: true,
            },
        };
        let chain = [21; 32];
        let defaults = recovery::freeze_defaults(&descriptor, chain).unwrap();
        let before = RecoveryRowV1 {
            descriptor,
            controls: RecoveryControlsV1 {
                epoch: 0,
                delegate_action_commitment: [13; 7],
                revoked: false,
                powers: RecoveryPowersV1 {
                    transfer: true,
                    burn: false,
                },
                note_freeze_root: defaults[32],
            },
        };
        let context = RecoveryContextV1 {
            chain_id: chain,
            parent_hash: [22; 32],
            parent_height: 40,
            row_commitment: before.commitment(chain).unwrap(),
        };
        let after = RecoveryControlsV1 {
            epoch: 1,
            delegate_action_commitment: [17; 7],
            powers: RecoveryPowersV1 {
                transfer: false,
                burn: true,
            },
            ..before.controls
        };
        let prepared = recovery::prepare_controls_update(context, before, after).unwrap();
        (
            Public::from_prepared(&prepared, 42, [23; 7], None).unwrap(),
            Witness {
                admin_secret: SECRET,
                freeze_siblings: [[0; 7]; 32],
            },
        )
    }
    #[test]
    fn rotation_revocation_and_exact_prepared_binding() {
        let (mut p, w) = fixture();
        compile(&p, &w).unwrap();
        let prepared = recovery::prepare_controls_update(p.context, p.before, p.after).unwrap();
        p.verify_prepared(&prepared).unwrap();
        let original = p.action_id().unwrap();
        p.action_intent[0] += 1;
        assert_ne!(p.action_id().unwrap(), original);
        p.after.revoked = true;
        p.after.delegate_action_commitment = [0; 7];
        compile(&p, &w).unwrap();
        assert!(p.verify_prepared(&prepared).is_err());
        p.after.revoked = false;
        assert!(p.validate_structure().is_err());
    }
    #[test]
    fn wrong_secret_epoch_powers_and_private_padding_reject() {
        let (p, w) = fixture();
        let mut bad = w.clone();
        bad.admin_secret[1] += 1;
        assert!(compile(&p, &bad).is_err());
        let mut changed = p.clone();
        changed.after.epoch = p.before.controls.epoch;
        assert!(changed.validate_structure().is_err());
        let mut changed = p.clone();
        changed.before.descriptor.maximum_powers.burn = false;
        changed.context.row_commitment =
            changed.before.commitment(changed.context.chain_id).unwrap();
        assert!(changed.validate_structure().is_err());
        let mut bad = w.clone();
        bad.freeze_siblings[0][0] = 1;
        assert!(compile(&p, &bad).is_err());
    }
    #[test]
    fn sparse32_freeze_exact_roots_note_and_unfreeze() {
        let (mut p, mut w) = fixture();
        let chain = p.context.chain_id;
        let d = p.before.descriptor;
        let defaults = recovery::freeze_defaults(&d, chain).unwrap();
        w.freeze_siblings = core::array::from_fn(|i| defaults[i]);
        let f = FreezeMutation {
            position: 41,
            note_commitment: [9; 7],
            before_frozen: false,
            after_frozen: true,
        };
        p.after.note_freeze_root = recovery::freeze_root(
            &d,
            chain,
            f.position,
            f.note_commitment,
            true,
            &w.freeze_siblings,
        )
        .unwrap();
        p.freeze = Some(f);
        compile(&p, &w).unwrap();
        let mut bad = p.clone();
        bad.after.note_freeze_root[0] += 1;
        assert!(compile(&bad, &w).is_err());
        let mut bad = p.clone();
        bad.freeze.as_mut().unwrap().note_commitment[0] += 1;
        assert!(compile(&bad, &w).is_err());
        let mut bad = p.clone();
        bad.freeze.as_mut().unwrap().after_frozen = false;
        assert!(bad.validate_structure().is_err());
        let prior_after = p.after;
        p.before.controls = prior_after;
        p.after.epoch += 1;
        p.after.note_freeze_root = defaults[32];
        p.context.row_commitment = p.before.commitment(chain).unwrap();
        p.freeze = Some(FreezeMutation {
            before_frozen: true,
            after_frozen: false,
            ..f
        });
        compile(&p, &w).unwrap();
    }
    #[test]
    fn all_public_words_binding_zero_padding_and_cap_are_canonical() {
        let (p, w) = fixture();
        let a = Adapter::from_public(&p).unwrap();
        let words = p.words().unwrap();
        assert_eq!(&words[UNUSED..], &[0; 5]);
        let bytes = p.binding_bytes().unwrap();
        assert_eq!(bytes.len(), 1040);
        assert_eq!(&bytes[..8], b"HGRECOV1");
        assert_eq!(&bytes[8..16], &3u64.to_le_bytes());
        let mut inputs = words.to_vec();
        inputs[UNUSED] = 1;
        inputs.extend(w.admin_secret);
        inputs.extend([0, 1, 0, 0, 0, 0, 0]);
        inputs.extend([0; 224]);
        assert!(a
            .inner
            .evaluate(&inputs)
            .and_then(|x| a.inner.verify_packed_witness(&x))
            .is_err());
        assert_eq!(MAX_CANDIDATE_PROOF_BYTES, 2 * 1024 * 1024);
        assert!(verify_candidate(&p, b"SMZE").is_err());
        assert!(verify_candidate(&p, &vec![0; MAX_CANDIDATE_PROOF_BYTES + 1]).is_err());
    }
}
