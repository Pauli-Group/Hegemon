//! Inactive, proof-backed administrator controls for a single non-native asset.
//!
//! This relation proves knowledge of the current row's policy-admin secret and
//! binds the complete proposed control transition. Registry membership and the
//! exact old/new rows are public checks performed by `verify_prepared`; the
//! integrating ledger must perform that check, verify the proof, and consume the
//! action identity before applying the prepared update atomically. A registry
//! root may recur after freeze/unfreeze, so root freshness alone is not replay
//! protection. No native HGN authority, recovery authority, key rotation, oracle
//! authority or production route is created by this module.
#![forbid(unsafe_code)]

use crate::{
    smallwood_engine::{
        self, SmallwoodArithmetization, SmallwoodDecsEvaluationDomain, SmallwoodTranscriptBackend,
        ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
    },
    smallwood_htlc::circuit::{
        boolean, equal, input, nonzero, range, HtlcAdapter, HtlcGeometry, Scope, Word,
    },
    smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView},
    TransactionCircuitError,
};
use hegemon_field::{PrimeCharacteristicRing, GOLDILOCKS_MODULUS};
use transaction_core::{
    asset_registry_v1::{asset_policy_leaf_v1, PreparedAssetControlsV1},
    poseidon2_width16::{poseidon2_width16_compress14, poseidon2_width16_compress14_ring, Felt},
};

pub use transaction_core::asset_registry_v1::AssetControlsV1;
pub type Digest = [u64; 7];
pub const RELATION_ID: &str = "Hegemon.AssetPolicyAdmin.Controls.CompFF01.v2";
pub const PRODUCTION_AUTHORIZED: bool = false;
pub const SOURCE_LOWERING_CERTIFICATE_COMPLETE: bool = false;
pub const PUBLIC_WORDS: usize = 134;
pub const CONTEXT_TAG: u64 = 0x4847_5041_444d_0002;
pub const POLICY_ADMIN_COMMITMENT_DOMAIN: u64 = 0x4150_4144_4d49_0001;
pub const CANDIDATE_PROOF_MAGIC: [u8; 4] = *b"SMZE";
pub const MAX_CANDIDATE_PROOF_BYTES: usize =
    smallwood_engine::SMALLWOOD_ASSET_SPEND_SMZE_MAX_INNER_PROOF_BYTES;

const HEIGHT: usize = 17;
const ASSET: usize = 32;
const OLD_VERSION: usize = 33;
const NEW_VERSION: usize = 34;
const ADMIN: usize = 35;
const DEPTH: usize = 63;
const FROZEN: usize = 64;
const MINT_ENABLED: usize = 65;
const EXPIRES: usize = 66;
const SOURCE_DIGEST: usize = 74;
const UNUSED: usize = 90;

fn error(message: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(message)
}
fn canonical_nonzero(digest: &Digest) -> bool {
    digest.iter().any(|word| *word != 0) && digest.iter().all(|word| *word < GOLDILOCKS_MODULUS)
}
fn digest_words(digest: &[u8; 64]) -> [u64; 16] {
    core::array::from_fn(|index| {
        u64::from(u32::from_le_bytes(
            digest[index * 4..index * 4 + 4].try_into().unwrap(),
        ))
    })
}
fn append_bytes(words: &mut Vec<u64>, bytes: &[u8; 32]) {
    words.extend(
        bytes
            .chunks_exact(4)
            .map(|chunk| u64::from(u32::from_le_bytes(chunk.try_into().unwrap()))),
    );
}

/// Exact action statement. Controls may change only credential membership root,
/// credential depth, whole-asset freeze, and mint enablement. The complete V8
/// policy and supply counters remain unchanged, including the version used by
/// the issuer commitment. Current authenticated registry roots revoke old
/// credentials without requiring the issuer to rotate its secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyAdminPublicV1 {
    pub chain_id: [u8; 32],
    pub reference_parent_hash: [u8; 32],
    pub parent_height: u64,
    pub registry_root: Digest,
    pub after_registry_root: Digest,
    pub asset_id: u32,
    pub old_policy_version: u32,
    pub new_policy_version: u32,
    pub policy_admin_commitment: Digest,
    pub before_policy_leaf: Digest,
    pub after_policy_leaf: Digest,
    pub controls: AssetControlsV1,
    pub expires_at: u64,
    pub action_intent: Digest,
}

impl PolicyAdminPublicV1 {
    pub fn from_prepared(
        prepared: &PreparedAssetControlsV1,
        reference_parent_hash: [u8; 32],
        expires_at: u64,
        action_intent: Digest,
    ) -> Result<Self, TransactionCircuitError> {
        let context = prepared.context();
        let before = prepared.before();
        let after = prepared.after();
        let public = Self {
            chain_id: context.chain_id,
            reference_parent_hash,
            parent_height: context.parent_height,
            registry_root: context.registry_root.map(|word| word.as_canonical_u64()),
            after_registry_root: prepared.after_root().map(|word| word.as_canonical_u64()),
            asset_id: before.config.asset_id,
            old_policy_version: before.config.policy_version,
            new_policy_version: after.config.policy_version,
            policy_admin_commitment: before
                .config
                .policy_admin_commitment
                .map(|word| word.as_canonical_u64()),
            before_policy_leaf: asset_policy_leaf_v1(before).map(|word| word.as_canonical_u64()),
            after_policy_leaf: asset_policy_leaf_v1(after).map(|word| word.as_canonical_u64()),
            controls: after.controls(),
            expires_at,
            action_intent,
        };
        public.validate_structure()?;
        Ok(public)
    }

    /// Public authentication must accompany ZK verification. `prepared` must be
    /// obtained from the integrating ledger's CURRENT authenticated registry.
    /// Its private fields ensure this API cannot silently promote an arbitrary
    /// replacement row to an authorized controls-only update.
    pub fn verify_prepared(
        &self,
        prepared: &PreparedAssetControlsV1,
        expected_reference_parent_hash: [u8; 32],
    ) -> Result<(), TransactionCircuitError> {
        self.validate_structure()?;
        if *self
            != Self::from_prepared(
                prepared,
                expected_reference_parent_hash,
                self.expires_at,
                self.action_intent,
            )?
        {
            return Err(error(
                "asset policy admin authenticated transition mismatch",
            ));
        }
        Ok(())
    }

    /// A canonical 134-field schema uses a distinct context tag, the exact
    /// source identity, and canonical zero padding. It shares proof parameters
    /// with SMZE asset spends, while accepting no spend statement as an admin
    /// statement. Every word is a bound graph input.
    pub fn words(&self) -> [u64; PUBLIC_WORDS] {
        let mut words = Vec::with_capacity(PUBLIC_WORDS);
        words.push(CONTEXT_TAG);
        append_bytes(&mut words, &self.chain_id);
        append_bytes(&mut words, &self.reference_parent_hash);
        words.push(self.parent_height);
        words.extend(self.registry_root);
        words.extend(self.after_registry_root);
        words.extend([
            u64::from(self.asset_id),
            u64::from(self.old_policy_version),
            u64::from(self.new_policy_version),
        ]);
        words.extend(self.policy_admin_commitment);
        words.extend(self.before_policy_leaf);
        words.extend(self.after_policy_leaf);
        words.extend(
            self.controls
                .credential_root
                .map(|word| word.as_canonical_u64()),
        );
        words.extend([
            u64::from(self.controls.credential_depth),
            u64::from(self.controls.frozen),
            u64::from(self.controls.mint_enabled),
            self.expires_at,
        ]);
        words.extend(self.action_intent);
        words.extend(digest_words(&relation_digest()));
        words.resize(PUBLIC_WORDS, 0);
        words.try_into().expect("fixed policy admin schema")
    }

    pub fn binding_bytes(&self) -> Vec<u8> {
        self.words()
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect()
    }

    /// Proof-independent identity, for atomic replay tracking by a ledger. A
    /// different randomized proof of this action must not create a second id.
    pub fn action_id(&self) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"Hegemon.AssetPolicyAdmin.Action.v2");
        hash.update(self.binding_bytes());
        hash.finalize().into()
    }

    pub fn validate_structure(&self) -> Result<(), TransactionCircuitError> {
        if self.chain_id == [0; 32]
            || self.reference_parent_hash == [0; 32]
            || self.asset_id == 0
            || self.old_policy_version != self.new_policy_version
            || self.parent_height >= 1 << 48
            || self.expires_at >= 1 << 48
            || self.expires_at < self.parent_height
            || !matches!(self.controls.credential_depth, 4 | 8 | 16)
            || !canonical_nonzero(&self.registry_root)
            || !canonical_nonzero(&self.after_registry_root)
            || !canonical_nonzero(&self.policy_admin_commitment)
            || !canonical_nonzero(&self.before_policy_leaf)
            || !canonical_nonzero(&self.after_policy_leaf)
            || !canonical_nonzero(&self.action_intent)
            || self
                .controls
                .credential_root
                .iter()
                .all(|word| *word == Felt::ZERO)
            || self.words().iter().any(|word| *word >= GOLDILOCKS_MODULUS)
        {
            return Err(error("asset policy admin public shape"));
        }
        Ok(())
    }
}

/// Secret-bearing witness deliberately has no Debug or serde implementation.
#[derive(Clone)]
pub struct PolicyAdminWitnessV1 {
    pub secret: Digest,
}

/// Fresh, per-asset, version-independent role commitment. The administrator can
/// revoke credentials or freeze an asset without acquiring issuer authority or
/// invalidating the issuer's separate version-bound commitment.
pub fn policy_admin_commitment(
    asset_id: u32,
    secret: Digest,
) -> Result<Digest, TransactionCircuitError> {
    if asset_id == 0 || !canonical_nonzero(&secret) {
        return Err(error("asset policy admin secret shape"));
    }
    let binding = [
        Felt::from_u64(u64::from(asset_id)),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    Ok(poseidon2_width16_compress14(
        POLICY_ADMIN_COMMITMENT_DOMAIN,
        &secret.map(Felt::from_u64),
        &binding,
    )
    .map(|word| word.as_canonical_u64()))
}

pub struct PolicyAdminAdapterV1 {
    inner: HtlcAdapter,
}

impl PolicyAdminAdapterV1 {
    pub fn from_public(public: &PolicyAdminPublicV1) -> Result<Self, TransactionCircuitError> {
        public.validate_structure()?;
        let words = public.words();
        let scope = Scope::start();
        let p: [Word; PUBLIC_WORDS] = core::array::from_fn(|_| input());
        let secret: [Word; 7] = core::array::from_fn(|_| input());
        let selected: [Word; 7] = core::array::from_fn(|_| input());

        equal(p[0], Word::from_u64(CONTEXT_TAG));
        for &word in &p[1..HEIGHT] {
            range(word, 32);
        }
        range(p[HEIGHT], 48);
        range(p[ASSET], 32);
        nonzero(p[ASSET]);
        range(p[OLD_VERSION], 32);
        range(p[NEW_VERSION], 32);
        equal(p[OLD_VERSION], p[NEW_VERSION]);
        equal(
            p[DEPTH],
            Word::from_u64(u64::from(public.controls.credential_depth)),
        );
        boolean(p[FROZEN]);
        boolean(p[MINT_ENABLED]);
        range(p[EXPIRES], 48);
        // Both scalars are48 bits, so this bounded difference cannot wrap the
        // Goldilocks field to satisfy a false integer expiry comparison.
        range(p[EXPIRES] - p[HEIGHT], 48);
        for (index, word) in digest_words(&relation_digest()).into_iter().enumerate() {
            equal(p[SOURCE_DIGEST + index], Word::from_u64(word));
        }
        for &word in &p[UNUSED..] {
            equal(word, Word::ZERO);
        }

        // A private one-hot selector identifies one nonzero secret limb. This
        // accepts any nonzero canonical secret, without a cancellation-prone
        // sum-of-limbs nonzero check or a host authorization boolean.
        for &bit in &selected {
            boolean(bit);
        }
        equal(selected.into_iter().sum(), Word::ONE);
        nonzero(
            secret
                .into_iter()
                .zip(selected)
                .map(|(word, bit)| word * bit)
                .sum(),
        );
        let binding = [
            p[ASSET],
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
        ];
        let commitment =
            poseidon2_width16_compress14_ring(POLICY_ADMIN_COMMITMENT_DOMAIN, &secret, &binding);
        for index in 0..7 {
            equal(commitment[index], p[ADMIN + index]);
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
        public: &PolicyAdminPublicV1,
        witness: &PolicyAdminWitnessV1,
    ) -> Result<Vec<u64>, TransactionCircuitError> {
        if !canonical_nonzero(&witness.secret) {
            return Err(error("asset policy admin secret shape"));
        }
        let mut inputs = public.words().to_vec();
        inputs.extend(witness.secret);
        let selected = witness.secret.iter().position(|word| *word != 0);
        inputs.extend((0..7).map(|index| u64::from(selected == Some(index))));
        self.inner.evaluate(&inputs)
    }

    pub fn verify_packed_witness(&self, witness: &[u64]) -> Result<(), TransactionCircuitError> {
        self.inner.verify_packed_witness(witness)
    }
}

pub fn compile(
    public: &PolicyAdminPublicV1,
    witness: &PolicyAdminWitnessV1,
) -> Result<(PolicyAdminAdapterV1, Vec<u64>), TransactionCircuitError> {
    let adapter = PolicyAdminAdapterV1::from_public(public)?;
    let packed = adapter.lower(public, witness)?;
    adapter.verify_packed_witness(&packed)?;
    Ok((adapter, packed))
}

impl SmallwoodConstraintAdapter for PolicyAdminAdapterV1 {
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

pub fn candidate_proof_size_hint(
    public: &PolicyAdminPublicV1,
) -> Result<usize, TransactionCircuitError> {
    smallwood_engine::projected_asset_spend_smze_inner_proof_bytes(
        &PolicyAdminAdapterV1::from_public(public)?,
    )
}

pub fn prove_candidate(
    public: &PolicyAdminPublicV1,
    witness: &PolicyAdminWitnessV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let (adapter, packed) = compile(public, witness)?;
    if candidate_proof_size_hint(public)? > MAX_CANDIDATE_PROOF_BYTES {
        return Err(error("asset policy admin proof projection exceeds cap"));
    }
    smallwood_engine::prove_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &packed,
        &public.binding_bytes(),
        ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512AssetSpendSmze,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// This verifies secret knowledge and binding, not registry freshness. The
/// integrating ledger must also call `verify_prepared` against current state.
pub fn verify_candidate(
    public: &PolicyAdminPublicV1,
    proof: &[u8],
) -> Result<(), TransactionCircuitError> {
    if proof.get(..4) != Some(CANDIDATE_PROOF_MAGIC.as_slice())
        || proof.len() > MAX_CANDIDATE_PROOF_BYTES
    {
        return Err(error("asset policy admin requires exact SMZE proof/cap"));
    }
    smallwood_engine::verify_statement_with_transcript_backend_profile_and_domain(
        &PolicyAdminAdapterV1::from_public(public)?,
        &public.binding_bytes(),
        proof,
        ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512AssetSpendSmze,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// Actual graph, core row semantics, field/hash, compression, transcript and
/// dependency-lock provenance. This is not a Rust/Lean equivalence certificate.
pub fn relation_digest() -> [u8; 64] {
    use sha2::{Digest as _, Sha512};
    static DIGEST: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut hash = Sha512::new();
        hash.update(b"Hegemon.AssetPolicyAdmin.SourceManifest.v2");
        hash.update(RELATION_ID.as_bytes());
        let sources: &[(&str, &[u8])] = &[
            (
                "asset_policy_admin_v1.rs",
                include_bytes!("asset_policy_admin_v1.rs"),
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
    use transaction_core::{
        asset_registry_v1::{AssetPolicyV1, AssetRegistryV1},
        stablecoin_poseidon2_v8::{StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters},
    };

    const SECRET: Digest = [0, 2, 3, 4, 5, 6, 7];
    const PARENT: [u8; 32] = [19; 32];
    fn tagged(tag: u64) -> [Felt; 7] {
        core::array::from_fn(|index| Felt::from_u64(tag + index as u64))
    }
    fn fixture() -> (
        AssetRegistryV1,
        PreparedAssetControlsV1,
        PolicyAdminPublicV1,
    ) {
        let row = AssetPolicyV1 {
            config: StablecoinPoseidon2V8Config {
                asset_id: 1001,
                policy_version: 7,
                active: true,
                enabled_at: 1,
                retired_at: None,
                issuer_commitment: tagged(11),
                min_collateral_ratio_ppm: 1_500_000,
                max_mint_per_epoch: 1_000_000,
                oracle_submitted_at: 89,
                oracle_max_age: 500,
                oracle_price_numerator: 2,
                oracle_price_denominator: 1,
                collateral_amount: 10_000,
                attestation_created_at: 88,
                attestation_disputed: false,
                attestation_present: true,
                attestation_max_age: 500,
                policy_admin_commitment: policy_admin_commitment(1001, SECRET)
                    .unwrap()
                    .map(Felt::from_u64),
                oracle_authority_commitment: tagged(201),
                attestation_authority_commitment: tagged(301),
                collateral_asset_id: 0,
                collateral_decimals: 6,
                collateral_scale: 1_000_000,
                locked_collateral_commitment: tagged(401),
            },
            counters: StablecoinPoseidon2V8Counters {
                epoch_id: 0,
                minted_in_epoch: 100,
                total_debt: 1_000,
                sequence: 9,
            },
            credential_root: tagged(701),
            credential_depth: 4,
            frozen: false,
            mint_enabled: true,
        };
        let registry = AssetRegistryV1::from_rows([17; 32], 100, &[row]).unwrap();
        let prepared = registry
            .prepare_controls_update(
                registry.context(),
                1001,
                AssetControlsV1 {
                    credential_root: tagged(801),
                    credential_depth: 8,
                    frozen: true,
                    mint_enabled: false,
                },
            )
            .unwrap();
        let public = PolicyAdminPublicV1::from_prepared(&prepared, PARENT, 120, [23; 7]).unwrap();
        (registry, prepared, public)
    }

    #[test]
    fn controls_authentication_matches_only_exact_current_prepared_transition() {
        let (registry, prepared, public) = fixture();
        public.verify_prepared(&prepared, PARENT).unwrap();
        assert_eq!(prepared.before().config, prepared.after().config);
        assert_eq!(prepared.before().counters, prepared.after().counters);
        assert_ne!(prepared.context().registry_root, prepared.after_root());
        assert!(public.verify_prepared(&prepared, [21; 32]).is_err());
        let mut changed = public.clone();
        changed.controls.frozen = false;
        assert!(changed.verify_prepared(&prepared, PARENT).is_err());
        changed = public.clone();
        changed.after_registry_root[0] ^= 1;
        assert!(changed.verify_prepared(&prepared, PARENT).is_err());
        let mut advanced = registry;
        advanced
            .apply_controls_update_after_authorization(prepared.clone())
            .unwrap();
        let restore = advanced
            .prepare_controls_update(advanced.context(), 1001, prepared.before().controls())
            .unwrap();
        assert!(public.verify_prepared(&restore, PARENT).is_err());
        assert_eq!(restore.after_root(), prepared.context().registry_root);
        // A freeze/unfreeze cycle restores the public root. The ledger must
        // retain the action id, rather than relying on root novelty.
        advanced
            .apply_controls_update_after_authorization(restore)
            .unwrap();
        let repeated = advanced
            .prepare_controls_update(advanced.context(), 1001, prepared.after().controls())
            .unwrap();
        public.verify_prepared(&repeated, PARENT).unwrap();
        assert_eq!(
            public.action_id(),
            PolicyAdminPublicV1::from_prepared(&repeated, PARENT, 120, [23; 7])
                .unwrap()
                .action_id()
        );
    }

    #[test]
    fn admin_secret_is_proved_with_native_and_issuer_domain_isolation() {
        let (_, _, public) = fixture();
        let (_, packed) = compile(&public, &PolicyAdminWitnessV1 { secret: SECRET }).unwrap();
        assert!(!packed.is_empty());
        assert!(compile(&public, &PolicyAdminWitnessV1 { secret: [9; 7] }).is_err());
        assert!(compile(&public, &PolicyAdminWitnessV1 { secret: [0; 7] }).is_err());
        assert!(compile(
            &public,
            &PolicyAdminWitnessV1 {
                secret: [GOLDILOCKS_MODULUS; 7]
            }
        )
        .is_err());
        assert!(policy_admin_commitment(0, SECRET).is_err());
        assert_ne!(
            policy_admin_commitment(1001, SECRET).unwrap(),
            policy_admin_commitment(1002, SECRET).unwrap()
        );
        let issuer =
            transaction_core::stablecoin_poseidon2_v8::stablecoin_poseidon2_v8_issuer_commitment(
                1001,
                7,
                &SECRET.map(Felt::from_u64),
            )
            .map(|word| word.as_canonical_u64());
        assert_ne!(public.policy_admin_commitment, issuer);
    }

    #[test]
    fn packed_witness_binds_each_public_transition_field() {
        let (_, _, public) = fixture();
        let (_, packed) = compile(&public, &PolicyAdminWitnessV1 { secret: SECRET }).unwrap();
        let changes: &[fn(&mut PolicyAdminPublicV1)] = &[
            |p| p.chain_id[0] ^= 1,
            |p| p.reference_parent_hash[0] ^= 1,
            |p| p.parent_height += 1,
            |p| p.registry_root[0] ^= 1,
            |p| p.after_registry_root[0] ^= 1,
            |p| p.asset_id += 1,
            |p| {
                p.old_policy_version += 1;
                p.new_policy_version += 1;
            },
            |p| p.policy_admin_commitment[0] ^= 1,
            |p| p.before_policy_leaf[0] ^= 1,
            |p| p.after_policy_leaf[0] ^= 1,
            |p| p.controls.credential_root[0] += Felt::ONE,
            |p| p.controls.credential_depth = 16,
            |p| p.controls.frozen = !p.controls.frozen,
            |p| p.controls.mint_enabled = !p.controls.mint_enabled,
            |p| p.expires_at += 1,
            |p| p.action_intent[0] ^= 1,
        ];
        for change in changes {
            let mut altered = public.clone();
            change(&mut altered);
            let adapter = PolicyAdminAdapterV1::from_public(&altered).unwrap();
            assert!(adapter.verify_packed_witness(&packed).is_err());
            assert_ne!(public.action_id(), altered.action_id());
        }
        assert_eq!(public.words()[0], CONTEXT_TAG);
        assert!(public.words()[UNUSED..].iter().all(|word| *word == 0));
        assert_eq!(public.binding_bytes().len(), PUBLIC_WORDS * 8);
    }

    #[test]
    fn admin_public_rejects_native_expired_and_policy_rotation_statements() {
        let (_, _, public) = fixture();
        let changes: [fn(&mut PolicyAdminPublicV1); 5] = [
            |p: &mut PolicyAdminPublicV1| p.asset_id = 0,
            |p: &mut PolicyAdminPublicV1| p.expires_at = p.parent_height - 1,
            |p: &mut PolicyAdminPublicV1| p.new_policy_version += 1,
            |p: &mut PolicyAdminPublicV1| p.controls.credential_depth = 5,
            |p: &mut PolicyAdminPublicV1| p.action_intent = [0; 7],
        ];
        for change in changes {
            let mut invalid = public.clone();
            change(&mut invalid);
            assert!(invalid.validate_structure().is_err());
        }
        assert!(verify_candidate(&public, b"SMZA").is_err());
        assert!(verify_candidate(&public, b"SMZE").is_err());
    }

    #[test]
    #[ignore = "real SMZE proof benchmark; run with the coordinated builder and usage headroom"]
    fn candidate_admin_proof_roundtrip_and_exact_binding() {
        use sha2::{Digest as _, Sha256};
        use std::time::Instant;
        let (_, prepared, public) = fixture();
        public.verify_prepared(&prepared, PARENT).unwrap();
        let adapter = PolicyAdminAdapterV1::from_public(&public).unwrap();
        let start = Instant::now();
        let proof = prove_candidate(&public, &PolicyAdminWitnessV1 { secret: SECRET }).unwrap();
        let proving_seconds = start.elapsed().as_secs_f64();
        let start = Instant::now();
        verify_candidate(&public, &proof).unwrap();
        let verification_seconds = start.elapsed().as_secs_f64();
        let proof_sha256 = Sha256::digest(&proof)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let geometry = adapter.geometry();
        let security_config =
            smallwood_engine::asset_spend_smze_geometry_receipt(&adapter).unwrap();
        let wire_receipt = crate::asset_spend_v1::proof_wire_receipt(&proof).unwrap();
        let receipt = serde_json::json!({
            "schema": "Hegemon.AssetPolicyAdmin.ProofReceipt.v2",
            "relation_id": RELATION_ID,
            "relation_digest_sha512": hex::encode(relation_digest()),
            "action_id_sha256": hex::encode(public.action_id()),
            "proof_sha256": proof_sha256,
            "proof_bytes": proof.len(),
            "public_bytes": public.binding_bytes().len(),
            "proof_plus_public_bytes": proof.len() + public.binding_bytes().len(),
            "public_words": public.words().to_vec(),
            "proving_seconds": proving_seconds,
            "verification_seconds": verification_seconds,
            "geometry": {
                "rows": geometry.rows, "canonical_wires": geometry.canonical_wires,
                "nonlinear_batches": geometry.nonlinear_batches,
                "constraints": adapter.constraint_count(),
                "linear_constraints": adapter.linear_constraint_count(),
                "graph_inputs": geometry.private_inputs,
                "private_witness_words": geometry.private_inputs - PUBLIC_WORDS,
                "packed_witness_words": geometry.rows * geometry.packing,
                "public_words": PUBLIC_WORDS,
            },
            "security_config": security_config,
            "wire_receipt": wire_receipt,
            "prepared_transition_authenticated": true,
            "proof_verified": true,
            "production_authorized": PRODUCTION_AUTHORIZED,
            "source_lowering_certificate_complete": SOURCE_LOWERING_CERTIFICATE_COMPLETE,
        });
        println!("policy_admin_smze proof_bytes={} public_bytes={} proving_s={proving_seconds:.6} verification_s={verification_seconds:.6} rows={} wires={} constraints={} linear={} graph_inputs={} private_witness_words={} proof_sha256={proof_sha256}",
            proof.len(), public.binding_bytes().len(), adapter.geometry().rows,
            adapter.geometry().canonical_wires, adapter.constraint_count(),
            adapter.linear_constraint_count(), geometry.private_inputs,
            geometry.private_inputs - PUBLIC_WORDS);
        println!("policy_admin_smze_receipt={receipt}");
        if let Ok(path) = std::env::var("HEGEMON_ASSET_POLICY_ADMIN_PROOF_OUT") {
            std::fs::write(path, &proof).unwrap();
        }
        if let Ok(path) = std::env::var("HEGEMON_ASSET_POLICY_ADMIN_RECEIPT_OUT") {
            std::fs::write(path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
        }
        let mut changed = public.clone();
        changed.controls.frozen = !changed.controls.frozen;
        assert!(verify_candidate(&changed, &proof).is_err());
        let mut damaged = proof;
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(verify_candidate(&public, &damaged).is_err());
    }
}
