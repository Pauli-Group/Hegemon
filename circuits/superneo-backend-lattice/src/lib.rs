use anyhow::{anyhow, ensure, Result};
use blake3::Hasher;
use getrandom::getrandom;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Instant,
};
use superneo_ccs::{
    digest_shape, CcsShape, RelationId, ShapeDigest, StatementDigest, StatementEncoding,
};
use superneo_core::{validate_fold_pair, Backend, FoldedInstance, SecurityParams};
use superneo_ring::PackedWitness;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RingProfile {
    GoldilocksCyclotomic24,
    GoldilocksFrog,
}

impl RingProfile {
    fn label(self) -> &'static [u8] {
        match self {
            Self::GoldilocksCyclotomic24 => b"goldilocks-cyclotomic24",
            Self::GoldilocksFrog => b"goldilocks-frog",
        }
    }

    fn degree(self) -> usize {
        match self {
            Self::GoldilocksCyclotomic24 => 8,
            Self::GoldilocksFrog => 54,
        }
    }

    fn reduction_terms(self) -> &'static [(usize, i8)] {
        match self {
            Self::GoldilocksCyclotomic24 => &[(0, -1)],
            Self::GoldilocksFrog => &[(0, -1), (27, -1)],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BackendManifest {
    pub family_label: &'static str,
    pub spec_label: &'static str,
    pub commitment_scheme_label: &'static str,
    pub challenge_schedule_label: &'static str,
    pub maturity_label: &'static str,
}

impl BackendManifest {
    pub fn goldilocks_128b_structural_commitment() -> Self {
        Self {
            family_label: "goldilocks_128b_structural_commitment",
            spec_label:
                "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v8",
            commitment_scheme_label: "bounded_message_random_matrix_commitment",
            challenge_schedule_label: "quint_goldilocks_fs_challenge_profile_mix",
            maturity_label: "structural_candidate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NativeBackendParams {
    pub manifest: BackendManifest,
    pub security_bits: u32,
    pub ring_profile: RingProfile,
    pub matrix_rows: usize,
    pub matrix_cols: usize,
    pub challenge_bits: u32,
    pub fold_challenge_count: u32,
    pub max_fold_arity: u32,
    pub transcript_domain_label: &'static str,
    pub decomposition_bits: u32,
    pub opening_randomness_bits: u32,
    pub commitment_security_model: CommitmentSecurityModel,
    pub commitment_estimator_model: CommitmentEstimatorModel,
    pub max_commitment_message_ring_elems: u32,
    pub max_claimed_receipt_root_leaves: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentSecurityModel {
    GeometryProxy,
    BoundedKernelModuleSis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentEstimatorModel {
    SisLatticeEuclideanAdps16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    Experimental,
    CandidateUnderReview,
    Accepted,
    Blocked,
    Killed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NativeSecurityClaim {
    pub claimed_security_bits: u32,
    pub transcript_soundness_bits: u32,
    pub opening_hiding_bits: u32,
    pub commitment_codomain_bits: u32,
    pub commitment_same_seed_search_bits: u32,
    pub commitment_random_matrix_bits: u32,
    pub commitment_problem_equations: u32,
    pub commitment_problem_dimension: u32,
    pub commitment_problem_coeff_bound: u32,
    pub commitment_problem_l2_bound: u32,
    pub commitment_estimator_dimension: u32,
    pub commitment_estimator_block_size: u32,
    pub commitment_estimator_classical_bits: u32,
    pub commitment_estimator_quantum_bits: u32,
    pub commitment_estimator_paranoid_bits: u32,
    pub commitment_reduction_loss_bits: u32,
    pub commitment_binding_bits: u32,
    pub composition_loss_bits: u32,
    pub soundness_floor_bits: u32,
    pub assumption_ids: Vec<&'static str>,
    pub review_state: ReviewState,
}

impl NativeBackendParams {
    pub fn goldilocks_128b_structural_commitment() -> Self {
        Self {
            manifest: BackendManifest::goldilocks_128b_structural_commitment(),
            security_bits: 128,
            ring_profile: RingProfile::GoldilocksFrog,
            matrix_rows: 11,
            matrix_cols: 54,
            challenge_bits: 63,
            fold_challenge_count: 5,
            max_fold_arity: 2,
            transcript_domain_label: "hegemon.superneo.fold.v3",
            decomposition_bits: 8,
            opening_randomness_bits: 256,
            commitment_security_model: CommitmentSecurityModel::BoundedKernelModuleSis,
            commitment_estimator_model: CommitmentEstimatorModel::SisLatticeEuclideanAdps16,
            max_commitment_message_ring_elems: 76,
            max_claimed_receipt_root_leaves: 128,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.manifest.family_label.is_empty(),
            "manifest.family_label must be non-empty"
        );
        ensure!(
            !self.manifest.commitment_scheme_label.is_empty(),
            "manifest.commitment_scheme_label must be non-empty"
        );
        ensure!(
            !self.manifest.spec_label.is_empty(),
            "manifest.spec_label must be non-empty"
        );
        ensure!(
            !self.manifest.challenge_schedule_label.is_empty(),
            "manifest.challenge_schedule_label must be non-empty"
        );
        ensure!(
            !self.manifest.maturity_label.is_empty(),
            "manifest.maturity_label must be non-empty"
        );
        ensure!(
            self.matrix_rows > 0,
            "matrix_rows must be strictly positive"
        );
        ensure!(
            self.matrix_cols > 0,
            "matrix_cols must be strictly positive"
        );
        ensure!(
            self.matrix_cols == self.ring_profile.degree(),
            "matrix_cols {} must match ring profile degree {}",
            self.matrix_cols,
            self.ring_profile.degree()
        );
        ensure!(
            (1..=63).contains(&self.challenge_bits),
            "challenge_bits must be in 1..=63"
        );
        ensure!(
            (1..=8).contains(&self.fold_challenge_count),
            "fold_challenge_count must be in 1..=8"
        );
        ensure!(
            self.security_bits > 0,
            "security_bits must be strictly positive"
        );
        ensure!(
            self.max_fold_arity == 2,
            "binary fold backend requires max_fold_arity == 2"
        );
        ensure!(
            !self.transcript_domain_label.is_empty(),
            "transcript_domain_label must be non-empty"
        );
        ensure!(
            (1..=16).contains(&self.decomposition_bits),
            "decomposition_bits must be in 1..=16"
        );
        ensure!(
            self.opening_randomness_bits > 0 && self.opening_randomness_bits <= 256,
            "opening_randomness_bits must be in 1..=256"
        );
        if matches!(
            self.commitment_security_model,
            CommitmentSecurityModel::BoundedKernelModuleSis
        ) {
            let _ = self.commitment_estimator_model;
        }
        ensure!(
            self.max_commitment_message_ring_elems > 0,
            "max_commitment_message_ring_elems must be strictly positive"
        );
        ensure!(
            self.max_claimed_receipt_root_leaves > 0,
            "max_claimed_receipt_root_leaves must be strictly positive"
        );
        let claim = self.security_claim()?;
        ensure!(
            self.security_bits <= claim.soundness_floor_bits,
            "security_bits {} exceeds native backend soundness floor {} under review_state {:?}",
            self.security_bits,
            claim.soundness_floor_bits,
            claim.review_state
        );
        Ok(())
    }

    pub fn security_claim_uses_opening_hiding(&self) -> bool {
        !matches!(
            (
                self.manifest.family_label,
                self.manifest.commitment_scheme_label,
            ),
            (
                "goldilocks_128b_structural_commitment",
                "bounded_message_random_matrix_commitment",
            )
        )
    }

    pub fn security_claim(&self) -> Result<NativeSecurityClaim> {
        ensure!(
            (1..=63).contains(&self.challenge_bits),
            "challenge_bits must be in 1..=63"
        );
        ensure!(
            (1..=8).contains(&self.fold_challenge_count),
            "fold_challenge_count must be in 1..=8"
        );
        ensure!(
            self.max_fold_arity == 2,
            "binary fold backend requires max_fold_arity == 2"
        );
        ensure!(
            self.opening_randomness_bits > 0 && self.opening_randomness_bits <= 256,
            "opening_randomness_bits must be in 1..=256"
        );
        if matches!(
            self.commitment_security_model,
            CommitmentSecurityModel::BoundedKernelModuleSis
        ) {
            let _ = self.commitment_estimator_model;
        }
        ensure!(
            self.max_commitment_message_ring_elems > 0,
            "max_commitment_message_ring_elems must be strictly positive"
        );
        ensure!(
            self.max_claimed_receipt_root_leaves > 0,
            "max_claimed_receipt_root_leaves must be strictly positive"
        );

        let transcript_soundness_bits = self
            .challenge_bits
            .saturating_mul(self.fold_challenge_count)
            / 2;
        let opening_hiding_bits = if self.security_claim_uses_opening_hiding() {
            (self.opening_randomness_bits / 2).min(128)
        } else {
            0
        };
        let commitment_codomain_bits = goldilocks_field_capacity_bits(self.ring_profile)
            .saturating_mul(self.matrix_rows as u32)
            .saturating_mul(self.ring_degree() as u32);
        let commitment_same_seed_search_bits = self
            .max_commitment_message_ring_elems
            .saturating_mul(self.ring_degree() as u32)
            .saturating_mul(self.decomposition_bits.saturating_add(1));
        let commitment_random_matrix_bits =
            commitment_codomain_bits.saturating_sub(commitment_same_seed_search_bits);
        let commitment_problem_equations =
            self.matrix_rows.saturating_mul(self.ring_degree()) as u32;
        let commitment_problem_dimension = self
            .max_commitment_message_ring_elems
            .saturating_mul(self.ring_degree() as u32);
        let commitment_problem_coeff_bound = ((1u32 << self.digit_bits()) - 1).max(1);
        let commitment_problem_l2_bound = ceil_sqrt_u64(
            u64::from(commitment_problem_dimension).saturating_mul(
                u64::from(commitment_problem_coeff_bound)
                    .saturating_mul(u64::from(commitment_problem_coeff_bound)),
            ),
        ) as u32;
        let commitment_estimate = match self.commitment_security_model {
            CommitmentSecurityModel::GeometryProxy => None,
            CommitmentSecurityModel::BoundedKernelModuleSis => {
                Some(estimate_bounded_kernel_module_sis(
                    self.commitment_estimator_model,
                    commitment_problem_equations,
                    commitment_problem_dimension,
                    commitment_problem_l2_bound,
                )?)
            }
        };
        let commitment_reduction_loss_bits = 0;
        let commitment_binding_bits = match self.commitment_security_model {
            CommitmentSecurityModel::GeometryProxy => commitment_random_matrix_bits,
            CommitmentSecurityModel::BoundedKernelModuleSis => commitment_estimate
                .as_ref()
                .expect("bounded_kernel_module_sis estimate must exist")
                .quantum_bits
                .saturating_sub(commitment_reduction_loss_bits),
        };
        let composition_loss_bits = ceil_log2_u32(self.max_claimed_receipt_root_leaves);
        let transcript_floor_bits = transcript_soundness_bits.saturating_sub(composition_loss_bits);
        let mut soundness_floor_bits = transcript_floor_bits.min(commitment_binding_bits);
        if self.security_claim_uses_opening_hiding() {
            soundness_floor_bits = soundness_floor_bits.min(opening_hiding_bits);
        }
        let (assumption_ids, review_state) = match (
            self.manifest.family_label,
            self.manifest.challenge_schedule_label,
            self.fold_challenge_count,
            self.security_claim_uses_opening_hiding(),
        ) {
            (
                "goldilocks_128b_structural_commitment",
                "quint_goldilocks_fs_challenge_profile_mix",
                5,
                false,
            ) => (
                vec![
                    "random_oracle.blake3_fiat_shamir",
                    "serialization.canonical_native_artifact_bytes",
                    "fs.quint_goldilocks_profile_fold_challenges",
                    "commitment.deterministic_public_witness_reconstruction",
                    "commitment.bounded_kernel_module_sis_exact_reduction",
                    "commitment.sis_lattice_euclidean_adps16_quantum_estimator",
                ],
                ReviewState::CandidateUnderReview,
            ),
            (_, _, _, true) => (
                vec![
                    "random_oracle.family_owned_fiat_shamir",
                    "serialization.canonical_native_artifact_bytes",
                    "fs.custom_multichallenge_fold_schedule",
                    "opening.explicit_mask_seed_entropy",
                    "commitment.family_owned_linear_binding",
                ],
                ReviewState::Experimental,
            ),
            _ => (
                vec![
                    "random_oracle.family_owned_fiat_shamir",
                    "serialization.canonical_native_artifact_bytes",
                    "fs.custom_multichallenge_fold_schedule",
                    "commitment.deterministic_public_witness_reconstruction",
                    match self.commitment_security_model {
                        CommitmentSecurityModel::GeometryProxy => {
                            "commitment.family_owned_linear_binding"
                        }
                        CommitmentSecurityModel::BoundedKernelModuleSis => {
                            "commitment.bounded_kernel_module_sis_exact_reduction"
                        }
                    },
                    if matches!(
                        self.commitment_security_model,
                        CommitmentSecurityModel::BoundedKernelModuleSis
                    ) {
                        "commitment.sis_lattice_euclidean_adps16_quantum_estimator"
                    } else {
                        "commitment.family_owned_structural_bound"
                    },
                ],
                ReviewState::Experimental,
            ),
        };
        Ok(NativeSecurityClaim {
            claimed_security_bits: self.security_bits,
            transcript_soundness_bits,
            opening_hiding_bits,
            commitment_codomain_bits,
            commitment_same_seed_search_bits,
            commitment_random_matrix_bits,
            commitment_problem_equations,
            commitment_problem_dimension,
            commitment_problem_coeff_bound,
            commitment_problem_l2_bound,
            commitment_estimator_dimension: commitment_estimate
                .as_ref()
                .map(|estimate| estimate.dimension)
                .unwrap_or(0),
            commitment_estimator_block_size: commitment_estimate
                .as_ref()
                .map(|estimate| estimate.block_size)
                .unwrap_or(0),
            commitment_estimator_classical_bits: commitment_estimate
                .as_ref()
                .map(|estimate| estimate.classical_bits)
                .unwrap_or(0),
            commitment_estimator_quantum_bits: commitment_estimate
                .as_ref()
                .map(|estimate| estimate.quantum_bits)
                .unwrap_or(0),
            commitment_estimator_paranoid_bits: commitment_estimate
                .as_ref()
                .map(|estimate| estimate.paranoid_bits)
                .unwrap_or(0),
            commitment_reduction_loss_bits,
            commitment_binding_bits,
            composition_loss_bits,
            soundness_floor_bits,
            assumption_ids,
            review_state,
        })
    }

    pub fn security_params(&self) -> SecurityParams {
        SecurityParams {
            target_security_bits: self.security_bits,
            max_fold_arity: self.max_fold_arity,
            transcript_domain: self.transcript_domain_label.as_bytes(),
        }
    }

    pub fn parameter_fingerprint(&self) -> [u8; 48] {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.native-backend-params.v2");
        hasher.update(self.manifest.family_label.as_bytes());
        hasher.update(self.manifest.spec_label.as_bytes());
        hasher.update(self.manifest.commitment_scheme_label.as_bytes());
        hasher.update(self.manifest.challenge_schedule_label.as_bytes());
        hasher.update(self.manifest.maturity_label.as_bytes());
        hasher.update(&self.security_bits.to_le_bytes());
        hasher.update(self.ring_profile.label());
        hasher.update(&(self.matrix_rows as u64).to_le_bytes());
        hasher.update(&(self.matrix_cols as u64).to_le_bytes());
        hasher.update(&self.challenge_bits.to_le_bytes());
        hasher.update(&self.fold_challenge_count.to_le_bytes());
        hasher.update(&self.max_fold_arity.to_le_bytes());
        hasher.update(self.transcript_domain_label.as_bytes());
        hasher.update(&self.decomposition_bits.to_le_bytes());
        hasher.update(&self.opening_randomness_bits.to_le_bytes());
        hasher.update(&[match self.commitment_security_model {
            CommitmentSecurityModel::GeometryProxy => 0u8,
            CommitmentSecurityModel::BoundedKernelModuleSis => 1u8,
        }]);
        hasher.update(commitment_estimator_model_label(self.commitment_estimator_model).as_bytes());
        hasher.update(&self.max_commitment_message_ring_elems.to_le_bytes());
        hasher.update(&self.max_claimed_receipt_root_leaves.to_le_bytes());
        hash48(hasher)
    }

    pub fn spec_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.native-backend-spec-digest.v1");
        hasher.update(self.manifest.family_label.as_bytes());
        hasher.update(self.manifest.spec_label.as_bytes());
        hasher.update(self.manifest.commitment_scheme_label.as_bytes());
        hasher.update(self.manifest.challenge_schedule_label.as_bytes());
        hasher.update(self.manifest.maturity_label.as_bytes());
        hasher.update(&self.security_bits.to_le_bytes());
        hasher.update(self.ring_profile.label());
        hasher.update(&(self.matrix_rows as u64).to_le_bytes());
        hasher.update(&(self.matrix_cols as u64).to_le_bytes());
        hasher.update(&self.challenge_bits.to_le_bytes());
        hasher.update(&self.fold_challenge_count.to_le_bytes());
        hasher.update(&self.max_fold_arity.to_le_bytes());
        hasher.update(self.transcript_domain_label.as_bytes());
        hasher.update(&self.decomposition_bits.to_le_bytes());
        hasher.update(&self.opening_randomness_bits.to_le_bytes());
        hasher.update(&[match self.commitment_security_model {
            CommitmentSecurityModel::GeometryProxy => 0u8,
            CommitmentSecurityModel::BoundedKernelModuleSis => 1u8,
        }]);
        hasher.update(commitment_estimator_model_label(self.commitment_estimator_model).as_bytes());
        hasher.update(&self.max_commitment_message_ring_elems.to_le_bytes());
        hasher.update(&self.max_claimed_receipt_root_leaves.to_le_bytes());
        hash32(hasher)
    }

    pub fn artifact_version(&self, artifact_label: &[u8]) -> u16 {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.native-artifact-version.v1");
        hasher.update(self.manifest.family_label.as_bytes());
        hasher.update(artifact_label);
        hasher.update(&self.parameter_fingerprint());
        let mut bytes = [0u8; 2];
        hasher.finalize_xof().fill(&mut bytes);
        let raw = u16::from_le_bytes(bytes);
        raw.max(1)
    }

    pub fn ring_degree(&self) -> usize {
        self.ring_profile.degree()
    }

    pub fn digit_bits(&self) -> u16 {
        self.decomposition_bits as u16
    }

    pub fn randomness_bytes(&self) -> usize {
        self.opening_randomness_bits.div_ceil(8) as usize
    }
}

fn ceil_log2_u32(value: u32) -> u32 {
    if value <= 1 {
        0
    } else {
        u32::BITS - (value - 1).leading_zeros()
    }
}

fn ceil_sqrt_u64(value: u64) -> u64 {
    if value <= 1 {
        return value;
    }
    let floor = (value as f64).sqrt().floor() as u64;
    if floor.saturating_mul(floor) == value {
        floor
    } else {
        floor.saturating_add(1)
    }
}

fn goldilocks_field_capacity_bits(_profile: RingProfile) -> u32 {
    63
}

const GOLDILOCKS_MODULUS_U64: u64 = 18_446_744_069_414_584_321;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BoundedKernelModuleSisEstimate {
    dimension: u32,
    block_size: u32,
    classical_bits: u32,
    quantum_bits: u32,
    paranoid_bits: u32,
}

fn commitment_estimator_model_label(model: CommitmentEstimatorModel) -> &'static str {
    match model {
        CommitmentEstimatorModel::SisLatticeEuclideanAdps16 => "sis_lattice_euclidean_adps16",
    }
}

fn estimate_bounded_kernel_module_sis(
    estimator_model: CommitmentEstimatorModel,
    equation_dimension: u32,
    witness_dimension: u32,
    l2_bound: u32,
) -> Result<BoundedKernelModuleSisEstimate> {
    ensure!(
        equation_dimension > 0,
        "BK-MSIS equation dimension must be strictly positive"
    );
    ensure!(
        witness_dimension > 0,
        "BK-MSIS witness dimension must be strictly positive"
    );
    ensure!(
        l2_bound > 0,
        "BK-MSIS Euclidean bound must be strictly positive"
    );
    match estimator_model {
        CommitmentEstimatorModel::SisLatticeEuclideanAdps16 => {
            estimate_sis_lattice_euclidean_adps16(equation_dimension, witness_dimension, l2_bound)
        }
    }
}

fn estimate_sis_lattice_euclidean_adps16(
    equation_dimension: u32,
    witness_dimension: u32,
    l2_bound: u32,
) -> Result<BoundedKernelModuleSisEstimate> {
    let n = equation_dimension as f64;
    let m = witness_dimension as f64;
    let q = GOLDILOCKS_MODULUS_U64 as f64;
    let bound = l2_bound as f64;
    ensure!(
        bound < (q - 1.0) / 2.0,
        "BK-MSIS Euclidean bound {} must be below (q-1)/2 {}",
        l2_bound,
        ((GOLDILOCKS_MODULUS_U64 - 1) / 2)
    );

    let log2_q = q.log2();
    let log2_bound = bound.log2();
    let log_delta = (log2_bound * log2_bound) / (4.0 * n * log2_q);
    let d = (n * log2_q / log_delta).sqrt().floor().min(m).max(2.0) as u32;
    let d_f = f64::from(d);
    let delta_log2 = (log2_bound - ((n / d_f) * log2_q)) / (d_f - 1.0);
    let delta = 2f64.powf(delta_log2);
    ensure!(
        delta >= 1.0,
        "BK-MSIS Euclidean estimator failed: target delta {} is below 1",
        delta
    );
    let beta = beta_from_root_hermite_factor(delta);
    ensure!(
        beta <= d,
        "BK-MSIS Euclidean estimator failed: required block size {} exceeds lattice dimension {}",
        beta,
        d
    );
    let lb = (n * q.ln())
        .sqrt()
        .min(d_f.sqrt() * 2f64.powf(log2_q * (n / d_f)));
    ensure!(
        bound > lb,
        "BK-MSIS Euclidean estimator failed: bound {} does not exceed success threshold {}",
        bound,
        lb
    );

    Ok(BoundedKernelModuleSisEstimate {
        dimension: d,
        block_size: beta,
        classical_bits: (0.2920 * f64::from(beta)).floor() as u32,
        quantum_bits: (0.2650 * f64::from(beta)).floor() as u32,
        paranoid_bits: (0.2075 * f64::from(beta)).floor() as u32,
    })
}

fn beta_from_root_hermite_factor(delta: f64) -> u32 {
    let mut beta = 40u32;
    while reduction_delta((beta.saturating_mul(2)) as f64) > delta {
        beta = beta.saturating_mul(2);
    }
    while reduction_delta((beta.saturating_add(10)) as f64) > delta {
        beta = beta.saturating_add(10);
    }
    while reduction_delta(beta as f64) >= delta {
        beta = beta.saturating_add(1);
    }
    beta
}

fn reduction_delta(beta: f64) -> f64 {
    const SMALL: &[(u32, f64)] = &[
        (2, 1.02190),
        (5, 1.01862),
        (10, 1.01616),
        (15, 1.01485),
        (20, 1.01420),
        (25, 1.01342),
        (28, 1.01331),
        (40, 1.01295),
    ];

    if beta <= 2.0 {
        return 1.02190;
    }
    if beta < 40.0 {
        for window in SMALL.windows(2) {
            if f64::from(window[1].0) > beta {
                return window[0].1;
            }
        }
        return SMALL[SMALL.len() - 2].1;
    }
    if (beta - 40.0).abs() < f64::EPSILON {
        return SMALL[SMALL.len() - 1].1;
    }
    (beta / (2.0 * std::f64::consts::PI * std::f64::consts::E)
        * (std::f64::consts::PI * beta).powf(1.0 / beta))
    .powf(1.0 / (2.0 * (beta - 1.0)))
}

impl Default for NativeBackendParams {
    fn default() -> Self {
        Self::goldilocks_128b_structural_commitment()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticeBackend {
    pub params: NativeBackendParams,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelCostReport {
    pub bit_unpack_ns: u128,
    pub digit_expand_ns: u128,
    pub matrix_prepare_ns: u128,
    pub commitment_kernel_ns: u128,
    pub leaf_hash_ns: u128,
    pub fold_kernel_ns: u128,
    pub small_small_ops: u64,
    pub small_big_ops: u64,
    pub big_big_ops: u64,
    pub delayed_reduction_batches: u64,
    pub evaluation_windows: u64,
    pub streamed_message_windows: u64,
    pub matrix_cache_hits: u64,
    pub matrix_cache_misses: u64,
    pub matrix_cache_evictions: u64,
}

impl KernelCostReport {
    pub fn merge(&mut self, other: &Self) {
        self.bit_unpack_ns += other.bit_unpack_ns;
        self.digit_expand_ns += other.digit_expand_ns;
        self.matrix_prepare_ns += other.matrix_prepare_ns;
        self.commitment_kernel_ns += other.commitment_kernel_ns;
        self.leaf_hash_ns += other.leaf_hash_ns;
        self.fold_kernel_ns += other.fold_kernel_ns;
        self.small_small_ops += other.small_small_ops;
        self.small_big_ops += other.small_big_ops;
        self.big_big_ops += other.big_big_ops;
        self.delayed_reduction_batches += other.delayed_reduction_batches;
        self.evaluation_windows += other.evaluation_windows;
        self.streamed_message_windows += other.streamed_message_windows;
        self.matrix_cache_hits += other.matrix_cache_hits;
        self.matrix_cache_misses += other.matrix_cache_misses;
        self.matrix_cache_evictions += other.matrix_cache_evictions;
    }
}

#[derive(Clone, Debug, Default)]
struct KernelLocalStats {
    small_small_ops: u64,
    small_big_ops: u64,
    big_big_ops: u64,
    delayed_reduction_batches: u64,
    evaluation_windows: u64,
    streamed_message_windows: u64,
}

#[derive(Clone, Debug)]
struct PreparedCommitmentMatrix {
    rows: Vec<Vec<RingElem>>,
}

#[derive(Clone, Debug, Default)]
struct PreparedMatrixCache {
    entries: BTreeMap<[u8; 32], Arc<PreparedCommitmentMatrix>>,
    access_order: VecDeque<[u8; 32]>,
}

#[derive(Clone, Debug)]
struct EmbeddedRingElem {
    ring: RingElem,
    source_width_bits: u16,
}

const GOLDILOCKS_MODULUS_I128: i128 = 18_446_744_069_414_584_321;
const COMMITMENT_WINDOW_COLUMNS: usize = 32;
const PREPARED_MATRIX_CACHE_MAX_ENTRIES: usize = 16;

thread_local! {
    static KERNEL_COST_REPORT: RefCell<KernelCostReport> = RefCell::new(KernelCostReport::default());
    static PREPARED_MATRIX_CACHE: RefCell<PreparedMatrixCache> =
        RefCell::new(PreparedMatrixCache::default());
}

impl PreparedMatrixCache {
    fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
    }

    fn get(&mut self, key: &[u8; 32]) -> Option<Arc<PreparedCommitmentMatrix>> {
        let entry = self.entries.get(key).cloned()?;
        self.touch(*key);
        Some(entry)
    }

    fn insert(
        &mut self,
        key: [u8; 32],
        value: Arc<PreparedCommitmentMatrix>,
        capacity: usize,
    ) -> u64 {
        if capacity == 0 {
            return 0;
        }
        self.entries.insert(key, value);
        self.touch(key);

        let mut evictions = 0;
        while self.entries.len() > capacity {
            let Some(evicted_key) = self.access_order.pop_front() else {
                break;
            };
            if self.entries.remove(&evicted_key).is_some() {
                evictions += 1;
            }
        }
        evictions
    }

    fn touch(&mut self, key: [u8; 32]) {
        if let Some(position) = self
            .access_order
            .iter()
            .position(|existing| *existing == key)
        {
            self.access_order.remove(position);
        }
        self.access_order.push_back(key);
    }
}

impl Default for LatticeBackend {
    fn default() -> Self {
        Self {
            params: NativeBackendParams::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendKey {
    pub params_fingerprint: [u8; 48],
    pub shape_digest: ShapeDigest,
    pub security_bits: u32,
    pub challenge_bits: u32,
    pub fold_challenge_count: u32,
    pub max_fold_arity: u32,
    pub transcript_domain_digest: [u8; 32],
    pub ring_profile: RingProfile,
    pub commitment_rows: usize,
    pub ring_degree: usize,
    pub digit_bits: u16,
    pub opening_randomness_bits: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingElem {
    pub coeffs: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeCommitment {
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub digest: [u8; 48],
    pub rows: Vec<RingElem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafDigestProof {
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub witness_commitment_digest: [u8; 48],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldDigestProof {
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub params_fingerprint: [u8; 48],
    pub challenges: Vec<u64>,
    pub parent_statement_digest: StatementDigest,
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub parent_commitment_digest: [u8; 48],
    pub parent_rows: Vec<RingElem>,
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentOpening {
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub params_fingerprint: [u8; 48],
    pub packed_witness: PackedWitness<u64>,
    #[serde(
        serialize_with = "serialize_fixed_bytes_32",
        deserialize_with = "deserialize_fixed_bytes_32"
    )]
    pub randomness_seed: [u8; 32],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub opening_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendShape {
    pub shape_digest: ShapeDigest,
    pub num_rows: usize,
    pub num_cols: usize,
    pub matrix_count: usize,
    pub selector_count: usize,
    pub witness_bits: usize,
}

impl RingElem {
    pub fn from_coeffs(coeffs: Vec<u64>) -> Self {
        Self { coeffs }
    }

    fn byte_size(&self) -> usize {
        4 + (self.coeffs.len() * 8)
    }
}

fn serialize_fixed_bytes_48<S>(
    bytes: &[u8; 48],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(bytes)
}

fn serialize_fixed_bytes_32<S>(
    bytes: &[u8; 32],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(bytes)
}

fn deserialize_fixed_bytes_48<'de, D>(deserializer: D) -> std::result::Result<[u8; 48], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::invalid_length(len, &"48 bytes"))
}

fn deserialize_fixed_bytes_32<'de, D>(deserializer: D) -> std::result::Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::invalid_length(len, &"32 bytes"))
}

impl LatticeCommitment {
    pub const DIGEST_BYTES: usize = 48;

    pub fn from_rows(rows: Vec<RingElem>) -> Self {
        Self {
            digest: digest_commitment_rows(&rows),
            rows,
        }
    }

    pub fn digest_only(digest: [u8; 48]) -> Self {
        Self {
            digest,
            rows: Vec::new(),
        }
    }

    pub fn byte_size(&self) -> usize {
        Self::DIGEST_BYTES + 4 + self.rows.iter().map(RingElem::byte_size).sum::<usize>()
    }

    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(self.digest.len() * 2);
        for byte in self.digest {
            out.push(hex_nibble(byte >> 4));
            out.push(hex_nibble(byte & 0x0f));
        }
        out
    }
}

impl LeafDigestProof {
    pub fn byte_size(&self) -> usize {
        48 + 48
    }
}

impl FoldDigestProof {
    pub fn byte_size(&self) -> usize {
        48 + 4
            + (self.challenges.len() * 8)
            + StatementDigest::BYTES
            + LatticeCommitment::DIGEST_BYTES
            + 4
            + self
                .parent_rows
                .iter()
                .map(RingElem::byte_size)
                .sum::<usize>()
            + 48
    }
}

impl CommitmentOpening {
    pub fn byte_size(&self) -> usize {
        48 + 4
            + (self.packed_witness.coeffs.len() * 8)
            + 2
            + 4
            + (self.packed_witness.value_bit_widths.len() * 2)
            + 32
            + 48
    }
}

impl LatticeBackend {
    pub fn new(params: NativeBackendParams) -> Self {
        Self { params }
    }

    pub fn native_params(&self) -> &NativeBackendParams {
        &self.params
    }

    pub fn security_params(&self) -> SecurityParams {
        self.params.security_params()
    }

    fn ensure_native_params(&self, params: &NativeBackendParams) -> Result<()> {
        ensure!(
            params == &self.params,
            "backend parameter mismatch: backend is configured for {} but caller requested {}",
            self.params.manifest.family_label,
            params.manifest.family_label
        );
        Ok(())
    }
}

pub trait NativeCommitmentScheme {
    type Commitment;
    type OpeningProof;

    fn commit(
        &self,
        params: &NativeBackendParams,
        witness: &PackedWitness<u64>,
    ) -> Result<(Self::Commitment, Self::OpeningProof)>;

    fn verify_opening(
        &self,
        params: &NativeBackendParams,
        commitment: &Self::Commitment,
        opening: &Self::OpeningProof,
    ) -> Result<()>;
}

// Review-tooling entry point for deterministic vector generation.
pub fn commit_packed_witness_with_seed(
    params: &NativeBackendParams,
    witness: &PackedWitness<u64>,
    randomness_seed: [u8; 32],
) -> Result<(LatticeCommitment, CommitmentOpening)> {
    commit_with_seed(params, witness, randomness_seed)
}

pub fn canonical_opening_randomness_seed(
    params: &NativeBackendParams,
    randomness_seed: [u8; 32],
) -> [u8; 32] {
    canonicalize_opening_randomness_seed(params, randomness_seed)
}

fn review_backend_key(
    params: &NativeBackendParams,
    shape_digest: ShapeDigest,
) -> Result<BackendKey> {
    params.validate()?;
    Ok(BackendKey {
        params_fingerprint: params.parameter_fingerprint(),
        shape_digest,
        security_bits: params.security_bits,
        challenge_bits: params.challenge_bits,
        fold_challenge_count: params.fold_challenge_count,
        max_fold_arity: params.max_fold_arity,
        transcript_domain_digest: digest32_with_label(
            b"hegemon.superneo.transcript-domain.v1",
            params.transcript_domain_label.as_bytes(),
        ),
        ring_profile: params.ring_profile,
        commitment_rows: params.matrix_rows,
        ring_degree: params.ring_degree(),
        digit_bits: params.digit_bits(),
        opening_randomness_bits: params.opening_randomness_bits,
    })
}

pub fn review_leaf_proof_digest(
    params: &NativeBackendParams,
    shape_digest: ShapeDigest,
    relation_id: &RelationId,
    statement_digest: &StatementDigest,
    packed: &PackedWitness<u64>,
    commitment_digest: &[u8; 48],
) -> Result<[u8; 48]> {
    let pk = review_backend_key(params, shape_digest)?;
    Ok(leaf_proof_digest(
        &pk,
        relation_id,
        statement_digest,
        packed,
        commitment_digest,
    ))
}

pub fn review_fold_challenges(
    params: &NativeBackendParams,
    shape_digest: ShapeDigest,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
) -> Result<Vec<u64>> {
    validate_fold_pair(left, right)?;
    ensure!(
        left.shape_digest == shape_digest && right.shape_digest == shape_digest,
        "review fold challenge shape digest mismatch"
    );
    let pk = review_backend_key(params, shape_digest)?;
    Ok(derive_fold_challenges(&pk, left, right))
}

pub fn review_fold_rows(
    params: &NativeBackendParams,
    left: &LatticeCommitment,
    right: &LatticeCommitment,
    challenges: &[u64],
) -> Result<Vec<RingElem>> {
    fold_commitment_rows(params.ring_profile, left, right, challenges)
}

pub fn review_fold_statement_digest(
    left: &StatementDigest,
    right: &StatementDigest,
    challenges: &[u64],
    parent_commitment_digest: &[u8; 48],
) -> StatementDigest {
    fold_statement_digest(left, right, challenges, parent_commitment_digest)
}

pub fn review_fold_proof_digest(
    params: &NativeBackendParams,
    shape_digest: ShapeDigest,
    relation_id: &RelationId,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
    challenges: &[u64],
    parent_statement_digest: &StatementDigest,
    parent_rows: &[RingElem],
) -> Result<[u8; 48]> {
    validate_fold_pair(left, right)?;
    ensure!(
        left.shape_digest == shape_digest && right.shape_digest == shape_digest,
        "review fold proof shape digest mismatch"
    );
    let pk = review_backend_key(params, shape_digest)?;
    Ok(fold_proof_digest(
        &pk,
        relation_id,
        left,
        right,
        challenges,
        parent_statement_digest,
        parent_rows,
    ))
}

pub fn reset_kernel_cost_report() {
    KERNEL_COST_REPORT.with(|report| {
        *report.borrow_mut() = KernelCostReport::default();
    });
}

pub fn reset_kernel_runtime_state() {
    reset_kernel_cost_report();
    clear_prepared_matrix_cache();
}

pub fn current_kernel_cost_report() -> KernelCostReport {
    KERNEL_COST_REPORT.with(|report| report.borrow().clone())
}

pub fn take_kernel_cost_report() -> KernelCostReport {
    KERNEL_COST_REPORT.with(|report| {
        let mut report = report.borrow_mut();
        let current = report.clone();
        *report = KernelCostReport::default();
        current
    })
}

pub fn clear_prepared_matrix_cache() {
    PREPARED_MATRIX_CACHE.with(|cache| cache.borrow_mut().clear());
}

fn update_kernel_cost_report(f: impl FnOnce(&mut KernelCostReport)) {
    KERNEL_COST_REPORT.with(|report| f(&mut report.borrow_mut()));
}

fn flush_kernel_stats(stats: &KernelLocalStats) {
    update_kernel_cost_report(|report| {
        report.small_small_ops += stats.small_small_ops;
        report.small_big_ops += stats.small_big_ops;
        report.big_big_ops += stats.big_big_ops;
        report.delayed_reduction_batches += stats.delayed_reduction_batches;
        report.evaluation_windows += stats.evaluation_windows;
        report.streamed_message_windows += stats.streamed_message_windows;
    });
}

impl NativeCommitmentScheme for LatticeBackend {
    type Commitment = LatticeCommitment;
    type OpeningProof = CommitmentOpening;

    fn commit(
        &self,
        params: &NativeBackendParams,
        witness: &PackedWitness<u64>,
    ) -> Result<(Self::Commitment, Self::OpeningProof)> {
        self.ensure_native_params(params)?;
        let mut randomness_seed = [0u8; 32];
        getrandom(&mut randomness_seed)
            .map_err(|err| anyhow!("failed to sample native commitment randomness: {err}"))?;
        commit_with_seed(params, witness, randomness_seed)
    }

    fn verify_opening(
        &self,
        params: &NativeBackendParams,
        commitment: &Self::Commitment,
        opening: &Self::OpeningProof,
    ) -> Result<()> {
        self.ensure_native_params(params)?;
        ensure!(
            opening.params_fingerprint == params.parameter_fingerprint(),
            "commitment opening parameter fingerprint mismatch"
        );
        ensure!(
            opening.randomness_seed
                == canonicalize_opening_randomness_seed(params, opening.randomness_seed),
            "commitment opening randomness seed is not canonical for configured entropy"
        );
        let expected_digest =
            commitment_opening_digest(params, &opening.packed_witness, &opening.randomness_seed);
        ensure!(
            opening.opening_digest == expected_digest,
            "commitment opening digest mismatch"
        );
        let (expected_commitment, _) =
            commit_with_seed(params, &opening.packed_witness, opening.randomness_seed)?;
        ensure!(
            commitment.digest == expected_commitment.digest,
            "commitment opening digest does not match commitment"
        );
        ensure!(
            commitment.rows == expected_commitment.rows,
            "commitment opening rows do not match commitment"
        );
        Ok(())
    }
}

impl Backend<Goldilocks> for LatticeBackend {
    type ProverKey = BackendKey;
    type VerifierKey = BackendKey;
    type PackedWitness = PackedWitness<u64>;
    type Commitment = LatticeCommitment;
    type LeafProof = LeafDigestProof;
    type FoldProof = FoldDigestProof;

    fn setup(
        &self,
        security: &SecurityParams,
        shape: &CcsShape<Goldilocks>,
    ) -> Result<(Self::ProverKey, Self::VerifierKey)> {
        shape.validate()?;
        self.params.validate()?;
        ensure!(
            security.target_security_bits == self.params.security_bits,
            "security target {} does not match native backend params {}",
            security.target_security_bits,
            self.params.security_bits
        );
        ensure!(
            security.max_fold_arity == self.params.max_fold_arity,
            "max_fold_arity {} does not match native backend params {}",
            security.max_fold_arity,
            self.params.max_fold_arity
        );
        ensure!(
            security.transcript_domain == self.params.transcript_domain_label.as_bytes(),
            "transcript_domain does not match native backend params {}",
            self.params.transcript_domain_label
        );
        let key = BackendKey {
            params_fingerprint: self.params.parameter_fingerprint(),
            shape_digest: digest_shape(shape),
            security_bits: self.params.security_bits,
            challenge_bits: self.params.challenge_bits,
            fold_challenge_count: self.params.fold_challenge_count,
            max_fold_arity: self.params.max_fold_arity,
            transcript_domain_digest: digest32_with_label(
                b"hegemon.superneo.transcript-domain.v1",
                self.params.transcript_domain_label.as_bytes(),
            ),
            ring_profile: self.params.ring_profile,
            commitment_rows: self.params.matrix_rows,
            ring_degree: self.params.ring_degree(),
            digit_bits: self.params.digit_bits(),
            opening_randomness_bits: self.params.opening_randomness_bits,
        };
        Ok((key.clone(), key))
    }

    fn commit_witness(
        &self,
        pk: &Self::ProverKey,
        packed: &Self::PackedWitness,
    ) -> Result<Self::Commitment> {
        let ring_message = embed_packed_witness(pk, packed)?;
        let rows = commit_ring_message(pk, &ring_message);
        Ok(LatticeCommitment::from_rows(rows))
    }

    fn prove_leaf(
        &self,
        pk: &Self::ProverKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        packed: &Self::PackedWitness,
        commitment: &Self::Commitment,
    ) -> Result<Self::LeafProof> {
        let hash_start = Instant::now();
        let proof_digest = leaf_proof_digest(
            pk,
            relation_id,
            &statement.statement_digest,
            packed,
            &commitment.digest,
        );
        update_kernel_cost_report(|report| {
            report.leaf_hash_ns += hash_start.elapsed().as_nanos();
        });
        Ok(LeafDigestProof {
            witness_commitment_digest: commitment.digest,
            proof_digest,
        })
    }

    fn verify_leaf(
        &self,
        vk: &Self::VerifierKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        expected_packed: &Self::PackedWitness,
        proof: &Self::LeafProof,
    ) -> Result<()> {
        let expected_commitment = self.commit_witness(vk, expected_packed)?;
        ensure!(
            proof.witness_commitment_digest == expected_commitment.digest,
            "leaf witness commitment digest mismatch"
        );
        let expected_proof_digest = leaf_proof_digest(
            vk,
            relation_id,
            &statement.statement_digest,
            expected_packed,
            &expected_commitment.digest,
        );
        ensure!(
            proof.proof_digest == expected_proof_digest,
            "leaf proof digest mismatch"
        );
        Ok(())
    }

    fn fold_pair(
        &self,
        pk: &Self::ProverKey,
        left: &FoldedInstance<Self::Commitment>,
        right: &FoldedInstance<Self::Commitment>,
    ) -> Result<(FoldedInstance<Self::Commitment>, Self::FoldProof)> {
        validate_fold_pair(left, right)?;
        let challenges = derive_fold_challenges(pk, left, right);
        let fold_start = Instant::now();
        let parent_rows = fold_commitment_rows(
            pk.ring_profile,
            &left.witness_commitment,
            &right.witness_commitment,
            &challenges,
        )?;
        let parent_commitment = LatticeCommitment::from_rows(parent_rows.clone());
        let parent_statement_digest = fold_statement_digest(
            &left.statement_digest,
            &right.statement_digest,
            &challenges,
            &parent_commitment.digest,
        );
        let proof_digest = fold_proof_digest(
            pk,
            &left.relation_id,
            left,
            right,
            &challenges,
            &parent_statement_digest,
            &parent_rows,
        );
        let proof = FoldDigestProof {
            params_fingerprint: pk.params_fingerprint,
            challenges: challenges.clone(),
            parent_statement_digest,
            parent_commitment_digest: parent_commitment.digest,
            parent_rows: parent_rows.clone(),
            proof_digest,
        };
        let parent = FoldedInstance {
            relation_id: left.relation_id,
            shape_digest: left.shape_digest,
            statement_digest: parent_statement_digest,
            witness_commitment: parent_commitment,
        };
        update_kernel_cost_report(|report| {
            report.fold_kernel_ns += fold_start.elapsed().as_nanos();
        });
        Ok((parent, proof))
    }

    fn verify_fold(
        &self,
        vk: &Self::VerifierKey,
        parent: &FoldedInstance<Self::Commitment>,
        left: &FoldedInstance<Self::Commitment>,
        right: &FoldedInstance<Self::Commitment>,
        proof: &Self::FoldProof,
    ) -> Result<()> {
        validate_fold_pair(left, right)?;
        ensure!(
            left.shape_digest == vk.shape_digest,
            "left folded instance shape digest does not match verifier key"
        );
        ensure!(
            right.shape_digest == vk.shape_digest,
            "right folded instance shape digest does not match verifier key"
        );
        ensure!(
            parent.shape_digest == vk.shape_digest,
            "parent folded instance shape digest does not match verifier key"
        );
        ensure!(
            parent.relation_id == left.relation_id && left.relation_id == right.relation_id,
            "parent relation id does not match folded children"
        );
        ensure!(
            proof.params_fingerprint == vk.params_fingerprint,
            "fold proof parameter fingerprint mismatch"
        );
        ensure!(
            parent.shape_digest == left.shape_digest && left.shape_digest == right.shape_digest,
            "parent shape digest does not match folded children"
        );

        let expected_challenges = derive_fold_challenges(vk, left, right);
        ensure!(
            proof.challenges == expected_challenges,
            "fold challenge vector mismatch"
        );

        let expected_rows = fold_commitment_rows(
            vk.ring_profile,
            &left.witness_commitment,
            &right.witness_commitment,
            &expected_challenges,
        )?;
        ensure!(
            proof.parent_rows == expected_rows,
            "fold proof parent rows mismatch"
        );
        let expected_commitment = LatticeCommitment::from_rows(expected_rows.clone());
        ensure!(
            parent.witness_commitment.digest == expected_commitment.digest,
            "folded witness commitment digest mismatch"
        );
        if !parent.witness_commitment.rows.is_empty() {
            ensure!(
                parent.witness_commitment.rows == expected_commitment.rows,
                "folded witness commitment rows mismatch"
            );
        }
        ensure!(
            proof.parent_commitment_digest == expected_commitment.digest,
            "fold proof parent commitment digest mismatch"
        );

        let expected_statement_digest = fold_statement_digest(
            &left.statement_digest,
            &right.statement_digest,
            &expected_challenges,
            &expected_commitment.digest,
        );
        ensure!(
            parent.statement_digest == expected_statement_digest,
            "folded statement digest mismatch"
        );
        ensure!(
            proof.parent_statement_digest == expected_statement_digest,
            "fold proof parent statement digest mismatch"
        );

        let expected_proof_digest = fold_proof_digest(
            vk,
            &left.relation_id,
            left,
            right,
            &expected_challenges,
            &expected_statement_digest,
            &expected_rows,
        );
        ensure!(
            proof.proof_digest == expected_proof_digest,
            "fold proof digest mismatch"
        );
        Ok(())
    }
}

pub fn to_backend_ccs(shape: &CcsShape<Goldilocks>) -> Result<BackendShape> {
    shape.validate()?;
    Ok(BackendShape {
        shape_digest: digest_shape(shape),
        num_rows: shape.num_rows,
        num_cols: shape.num_cols,
        matrix_count: shape.matrices.len(),
        selector_count: shape.selectors.len(),
        witness_bits: shape.witness_schema.total_witness_bits(),
    })
}

fn embed_packed_witness(
    pk: &BackendKey,
    packed: &PackedWitness<u64>,
) -> Result<Vec<EmbeddedRingElem>> {
    embed_packed_witness_with_layout(pk.ring_degree, pk.digit_bits, packed)
}

fn embed_packed_witness_with_layout(
    ring_degree: usize,
    digit_bits: u16,
    packed: &PackedWitness<u64>,
) -> Result<Vec<EmbeddedRingElem>> {
    ensure!(
        packed.value_bit_widths.len() == packed.original_len,
        "packed witness width metadata length {} does not match original_len {}",
        packed.value_bit_widths.len(),
        packed.original_len
    );
    ensure!(ring_degree > 0, "ring degree must be strictly positive");
    let (digits, digit_source_widths) = expand_packed_digits(packed, digit_bits)?;
    let mut ring_elems = Vec::with_capacity(digits.len().div_ceil(ring_degree));
    for (chunk_index, chunk) in digits.chunks(ring_degree).enumerate() {
        let mut coeffs = vec![0u64; ring_degree];
        for (idx, digit) in chunk.iter().enumerate() {
            coeffs[idx] = *digit;
        }
        let source_width_bits = digit_source_widths
            .iter()
            .skip(chunk_index * ring_degree)
            .take(chunk.len())
            .copied()
            .max()
            .unwrap_or(1);
        ring_elems.push(EmbeddedRingElem {
            ring: RingElem::from_coeffs(coeffs),
            source_width_bits,
        });
    }
    Ok(ring_elems)
}

fn expand_packed_digits(
    packed: &PackedWitness<u64>,
    digit_bits: u16,
) -> Result<(Vec<u64>, Vec<u16>)> {
    ensure!(
        (1..=64).contains(&packed.coeff_capacity_bits),
        "packed witness coeff capacity must be in 1..=64"
    );
    ensure!(
        (1..=16).contains(&digit_bits),
        "digit_bits must be in 1..=16"
    );
    let digit_start = Instant::now();
    let bits = expand_packed_bits(packed)?;
    let mut digits = Vec::with_capacity(bits.len().div_ceil(digit_bits as usize));
    let bit_source_widths = expand_packed_bit_source_widths(packed)?;
    ensure!(
        bit_source_widths.len() == bits.len(),
        "bit source width metadata length {} does not match expanded bits {}",
        bit_source_widths.len(),
        bits.len()
    );
    let mut digit_source_widths = Vec::with_capacity(bits.len().div_ceil(digit_bits as usize));
    let mut cursor = 0usize;
    while cursor < bits.len() {
        let mut digit = 0u64;
        let mut source_width_bits = 1u16;
        for offset in 0..digit_bits as usize {
            let bit_index = cursor + offset;
            if bit_index >= bits.len() {
                break;
            }
            digit |= u64::from(bits[bit_index]) << offset;
            source_width_bits = source_width_bits.max(bit_source_widths[bit_index]);
        }
        digits.push(digit);
        digit_source_widths.push(source_width_bits);
        cursor += digit_bits as usize;
    }
    update_kernel_cost_report(|report| {
        report.digit_expand_ns += digit_start.elapsed().as_nanos();
    });
    Ok((digits, digit_source_widths))
}

fn expand_packed_bits(packed: &PackedWitness<u64>) -> Result<Vec<u8>> {
    ensure!(
        (1..=64).contains(&packed.coeff_capacity_bits),
        "packed witness coeff capacity must be in 1..=64"
    );
    let bit_unpack_start = Instant::now();
    let coeff_capacity = packed.coeff_capacity_bits as usize;
    let mut bits = Vec::with_capacity(packed.used_bits);
    for bit_index in 0..packed.used_bits {
        let coeff_index = bit_index / coeff_capacity;
        let bit_offset = (bit_index % coeff_capacity) as u16;
        let coeff = *packed
            .coeffs
            .get(coeff_index)
            .ok_or_else(|| anyhow!("packed witness ended early while expanding bits"))?;
        bits.push(((coeff >> bit_offset) & 1) as u8);
    }
    update_kernel_cost_report(|report| {
        report.bit_unpack_ns += bit_unpack_start.elapsed().as_nanos();
    });
    Ok(bits)
}

fn expand_packed_bit_source_widths(packed: &PackedWitness<u64>) -> Result<Vec<u16>> {
    let total_value_bits = packed
        .value_bit_widths
        .iter()
        .map(|width| usize::from(*width))
        .sum::<usize>();
    ensure!(
        total_value_bits == packed.used_bits,
        "packed witness width metadata covers {} bits but used_bits is {}",
        total_value_bits,
        packed.used_bits
    );
    let mut bit_source_widths = Vec::with_capacity(packed.used_bits);
    for width in &packed.value_bit_widths {
        bit_source_widths.extend(std::iter::repeat_n(*width, usize::from(*width)));
    }
    Ok(bit_source_widths)
}

fn commit_ring_message(pk: &BackendKey, message: &[EmbeddedRingElem]) -> Vec<RingElem> {
    let prepared = prepare_commitment_matrix(pk, message.len());
    let commit_start = Instant::now();
    let window_size = message.len().clamp(1, COMMITMENT_WINDOW_COLUMNS);
    let mut accumulators = vec![vec![0i128; pk.ring_degree]; pk.commitment_rows];
    let mut stats = KernelLocalStats::default();
    let row_count = pk.commitment_rows;

    for (window_index, chunk) in message.chunks(window_size).enumerate() {
        stats.evaluation_windows += 1;
        stats.streamed_message_windows += 1;
        let base_col = window_index * window_size;
        for (offset, message_elem) in chunk.iter().enumerate() {
            let col_index = base_col + offset;
            for (row_index, accumulator) in accumulators.iter_mut().enumerate().take(row_count) {
                if message_elem.source_width_bits <= 16 {
                    accumulate_ring_product_narrow_source(
                        pk.ring_profile,
                        accumulator,
                        &prepared.rows[row_index][col_index],
                        &message_elem.ring,
                        &mut stats,
                    );
                } else {
                    accumulate_ring_product_generic_source(
                        pk.ring_profile,
                        accumulator,
                        &prepared.rows[row_index][col_index],
                        &message_elem.ring,
                        &mut stats,
                    );
                }
            }
        }
    }

    let rows = accumulators
        .into_iter()
        .map(|coeffs| {
            stats.delayed_reduction_batches += 1;
            RingElem::from_coeffs(
                coeffs
                    .into_iter()
                    .map(reduce_goldilocks_signed)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    flush_kernel_stats(&stats);
    update_kernel_cost_report(|report| {
        report.commitment_kernel_ns += commit_start.elapsed().as_nanos();
    });
    rows
}

fn commit_with_seed(
    params: &NativeBackendParams,
    packed: &PackedWitness<u64>,
    randomness_seed: [u8; 32],
) -> Result<(LatticeCommitment, CommitmentOpening)> {
    params.validate()?;
    let randomness_seed = canonicalize_opening_randomness_seed(params, randomness_seed);
    let key = native_commitment_key(params);
    let ring_message =
        embed_packed_witness_with_layout(params.ring_degree(), params.digit_bits(), packed)?;
    ensure!(
        ring_message.len() as u32 <= params.max_commitment_message_ring_elems,
        "embedded commitment message length {} exceeds max_commitment_message_ring_elems {}",
        ring_message.len(),
        params.max_commitment_message_ring_elems
    );
    let deterministic_rows = commit_ring_message(&key, &ring_message);
    let randomizer_rows = derive_randomizer_rows(params, randomness_seed);
    let rows = add_ring_rows(params.ring_profile, &deterministic_rows, &randomizer_rows)?;
    let commitment = LatticeCommitment::from_rows(rows);
    let opening = CommitmentOpening {
        params_fingerprint: params.parameter_fingerprint(),
        packed_witness: packed.clone(),
        randomness_seed,
        opening_digest: commitment_opening_digest(params, packed, &randomness_seed),
    };
    Ok((commitment, opening))
}

fn native_commitment_key(params: &NativeBackendParams) -> BackendKey {
    BackendKey {
        params_fingerprint: params.parameter_fingerprint(),
        shape_digest: ShapeDigest([0u8; 32]),
        security_bits: params.security_bits,
        challenge_bits: params.challenge_bits,
        fold_challenge_count: params.fold_challenge_count,
        max_fold_arity: params.max_fold_arity,
        transcript_domain_digest: digest32_with_label(
            b"hegemon.superneo.native-commitment-domain.v1",
            params.transcript_domain_label.as_bytes(),
        ),
        ring_profile: params.ring_profile,
        commitment_rows: params.matrix_rows,
        ring_degree: params.ring_degree(),
        digit_bits: params.digit_bits(),
        opening_randomness_bits: params.opening_randomness_bits,
    }
}

fn derive_randomizer_rows(
    params: &NativeBackendParams,
    randomness_seed: [u8; 32],
) -> Vec<RingElem> {
    let canonical_seed = canonicalize_opening_randomness_seed(params, randomness_seed);
    (0..params.matrix_rows)
        .map(|row_index| {
            let coeffs = (0..params.ring_degree())
                .map(|coeff_index| {
                    let mut hasher = Hasher::new();
                    hasher.update(b"hegemon.superneo.commitment-randomizer.v1");
                    hasher.update(&params.parameter_fingerprint());
                    hasher.update(&canonical_seed);
                    hasher.update(&(row_index as u64).to_le_bytes());
                    hasher.update(&(coeff_index as u64).to_le_bytes());
                    let mut out = [0u8; 16];
                    hasher.finalize_xof().fill(&mut out);
                    let sample = u128::from_le_bytes(out);
                    reduce_goldilocks_u128(sample)
                })
                .collect();
            RingElem::from_coeffs(coeffs)
        })
        .collect()
}

fn add_ring_rows(
    ring_profile: RingProfile,
    left: &[RingElem],
    right: &[RingElem],
) -> Result<Vec<RingElem>> {
    ensure!(
        left.len() == right.len(),
        "cannot add {} commitment rows to {} randomizer rows",
        left.len(),
        right.len()
    );
    let mut stats = KernelLocalStats::default();
    let rows = left
        .iter()
        .zip(right)
        .map(|(left_row, right_row)| {
            delayed_linear_combine_with_schedule(
                ring_profile,
                left_row,
                right_row,
                &[1],
                &mut stats,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    flush_kernel_stats(&stats);
    Ok(rows)
}

fn commitment_opening_digest(
    params: &NativeBackendParams,
    packed: &PackedWitness<u64>,
    randomness_seed: &[u8; 32],
) -> [u8; 48] {
    let randomness_seed = canonicalize_opening_randomness_seed(params, *randomness_seed);
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.commitment-opening.v1");
    hasher.update(&params.parameter_fingerprint());
    hasher.update(&(packed.original_len as u64).to_le_bytes());
    hasher.update(&(packed.used_bits as u64).to_le_bytes());
    hasher.update(&(packed.coeffs.len() as u64).to_le_bytes());
    for coeff in &packed.coeffs {
        hasher.update(&coeff.to_le_bytes());
    }
    hasher.update(&(packed.value_bit_widths.len() as u64).to_le_bytes());
    for width in &packed.value_bit_widths {
        hasher.update(&width.to_le_bytes());
    }
    hasher.update(&packed.coeff_capacity_bits.to_le_bytes());
    hasher.update(&randomness_seed);
    hash48(hasher)
}

fn canonicalize_opening_randomness_seed(
    params: &NativeBackendParams,
    randomness_seed: [u8; 32],
) -> [u8; 32] {
    let allowed_bits = params.opening_randomness_bits.min(256) as usize;
    if allowed_bits >= 256 {
        return randomness_seed;
    }
    let mut canonical = [0u8; 32];
    let full_bytes = allowed_bits / 8;
    let partial_bits = allowed_bits % 8;
    if full_bytes > 0 {
        canonical[..full_bytes].copy_from_slice(&randomness_seed[..full_bytes]);
    }
    if partial_bits > 0 && full_bytes < canonical.len() {
        canonical[full_bytes] = randomness_seed[full_bytes] & ((1u8 << partial_bits) - 1);
    }
    canonical
}

fn matrix_entry(pk: &BackendKey, row_index: usize, col_index: usize) -> RingElem {
    let mut coeffs = Vec::with_capacity(pk.ring_degree);
    for coeff_index in 0..pk.ring_degree {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.ajtai-matrix.v1");
        hasher.update(&pk.params_fingerprint);
        hasher.update(pk.ring_profile.label());
        hasher.update(&pk.shape_digest.0);
        hasher.update(&pk.security_bits.to_le_bytes());
        hasher.update(&pk.challenge_bits.to_le_bytes());
        hasher.update(&pk.max_fold_arity.to_le_bytes());
        hasher.update(&pk.transcript_domain_digest);
        hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
        hasher.update(&(pk.ring_degree as u64).to_le_bytes());
        hasher.update(&pk.digit_bits.to_le_bytes());
        hasher.update(&pk.opening_randomness_bits.to_le_bytes());
        hasher.update(&(row_index as u64).to_le_bytes());
        hasher.update(&(col_index as u64).to_le_bytes());
        hasher.update(&(coeff_index as u64).to_le_bytes());
        let mut out = [0u8; 8];
        hasher.finalize_xof().fill(&mut out);
        coeffs.push(Goldilocks::new(u64::from_le_bytes(out)).as_canonical_u64());
    }
    RingElem::from_coeffs(coeffs)
}

fn prepare_commitment_matrix(pk: &BackendKey, message_len: usize) -> Arc<PreparedCommitmentMatrix> {
    let cache_key = prepared_matrix_cache_key(pk, message_len);
    if let Some(hit) = PREPARED_MATRIX_CACHE.with(|cache| cache.borrow_mut().get(&cache_key)) {
        update_kernel_cost_report(|report| {
            report.matrix_cache_hits += 1;
        });
        return hit;
    }

    let prepare_start = Instant::now();
    let mut rows = Vec::with_capacity(pk.commitment_rows);
    for row_index in 0..pk.commitment_rows {
        let mut row = Vec::with_capacity(message_len);
        for col_index in 0..message_len {
            row.push(matrix_entry(pk, row_index, col_index));
        }
        rows.push(row);
    }
    let prepared = Arc::new(PreparedCommitmentMatrix { rows });
    let evictions = PREPARED_MATRIX_CACHE.with(|cache| {
        cache.borrow_mut().insert(
            cache_key,
            prepared.clone(),
            PREPARED_MATRIX_CACHE_MAX_ENTRIES,
        )
    });
    update_kernel_cost_report(|report| {
        report.matrix_cache_misses += 1;
        report.matrix_cache_evictions += evictions;
        report.matrix_prepare_ns += prepare_start.elapsed().as_nanos();
    });
    prepared
}

fn prepared_matrix_cache_key(pk: &BackendKey, message_len: usize) -> [u8; 32] {
    let mut material = Vec::with_capacity(32 + 8 * 6);
    material.extend_from_slice(&pk.params_fingerprint);
    material.extend_from_slice(&pk.shape_digest.0);
    material.extend_from_slice(pk.ring_profile.label());
    material.extend_from_slice(&pk.security_bits.to_le_bytes());
    material.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    material.extend_from_slice(&pk.fold_challenge_count.to_le_bytes());
    material.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    material.extend_from_slice(&pk.transcript_domain_digest);
    material.extend_from_slice(&(pk.commitment_rows as u64).to_le_bytes());
    material.extend_from_slice(&(pk.ring_degree as u64).to_le_bytes());
    material.extend_from_slice(&pk.digit_bits.to_le_bytes());
    material.extend_from_slice(&pk.opening_randomness_bits.to_le_bytes());
    material.extend_from_slice(&(message_len as u64).to_le_bytes());
    digest32_with_label(b"hegemon.superneo.prepared-matrix.v1", &material)
}

fn digest_commitment_rows(rows: &[RingElem]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.commitment-digest.v2");
    hasher.update(&(rows.len() as u64).to_le_bytes());
    for row in rows {
        hasher.update(&(row.coeffs.len() as u64).to_le_bytes());
        for coeff in &row.coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
    }
    hash48(hasher)
}

fn derive_fold_challenges(
    pk: &BackendKey,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
) -> Vec<u64> {
    let mut transcript = Vec::with_capacity(48 + 32 + 32 + 48 + 48 + 64);
    transcript.extend_from_slice(&pk.params_fingerprint);
    transcript.extend_from_slice(pk.ring_profile.label());
    transcript.extend_from_slice(&pk.shape_digest.0);
    transcript.extend_from_slice(&left.relation_id.0);
    transcript.extend_from_slice(&pk.security_bits.to_le_bytes());
    transcript.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    transcript.extend_from_slice(&pk.fold_challenge_count.to_le_bytes());
    transcript.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    transcript.extend_from_slice(&pk.transcript_domain_digest);
    transcript.extend_from_slice(&(pk.commitment_rows as u64).to_le_bytes());
    transcript.extend_from_slice(&(pk.ring_degree as u64).to_le_bytes());
    transcript.extend_from_slice(&pk.digit_bits.to_le_bytes());
    transcript.extend_from_slice(&pk.opening_randomness_bits.to_le_bytes());
    transcript.extend_from_slice(&left.statement_digest.0);
    transcript.extend_from_slice(&right.statement_digest.0);
    transcript.extend_from_slice(&left.witness_commitment.digest);
    transcript.extend_from_slice(&right.witness_commitment.digest);

    (0..pk.fold_challenge_count as usize)
        .map(|challenge_index| {
            let mut hasher = Hasher::new();
            hasher.update(b"hegemon.superneo.fold-challenge.v3");
            hasher.update(&transcript);
            hasher.update(&(challenge_index as u64).to_le_bytes());
            let mut out = [0u8; 8];
            hasher.finalize_xof().fill(&mut out);
            reduce_fold_challenge(pk.challenge_bits, u64::from_le_bytes(out))
        })
        .collect()
}

fn fold_commitment_rows(
    ring_profile: RingProfile,
    left: &LatticeCommitment,
    right: &LatticeCommitment,
    challenges: &[u64],
) -> Result<Vec<RingElem>> {
    ensure!(
        !left.rows.is_empty() && !right.rows.is_empty(),
        "folded commitments require concrete row data"
    );
    ensure!(
        left.rows.len() == right.rows.len(),
        "folded commitments must have the same row length"
    );
    ensure!(
        !challenges.is_empty(),
        "folded commitments require at least one challenge"
    );
    let mut stats = KernelLocalStats::default();
    let rows = left
        .rows
        .iter()
        .zip(&right.rows)
        .map(|(left_row, right_row)| {
            delayed_linear_combine_with_schedule(
                ring_profile,
                left_row,
                right_row,
                challenges,
                &mut stats,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    flush_kernel_stats(&stats);
    Ok(rows)
}

fn delayed_linear_combine_with_schedule(
    ring_profile: RingProfile,
    left: &RingElem,
    right: &RingElem,
    challenges: &[u64],
    stats: &mut KernelLocalStats,
) -> Result<RingElem> {
    ensure!(
        left.coeffs.len() == right.coeffs.len(),
        "cannot combine ring elements with different degrees"
    );
    ensure!(
        !challenges.is_empty(),
        "fold schedule must contain at least one challenge"
    );
    ensure!(
        left.coeffs.len() == ring_profile.degree(),
        "left row degree {} does not match ring profile degree {}",
        left.coeffs.len(),
        ring_profile.degree()
    );
    stats.delayed_reduction_batches += 1;
    ensure!(
        challenges.len() <= ring_profile.degree(),
        "fold schedule length {} exceeds ring profile degree {}",
        challenges.len(),
        ring_profile.degree()
    );
    let mut challenge_coeffs = vec![0u64; ring_profile.degree()];
    for (rotation, challenge) in challenges.iter().copied().enumerate() {
        challenge_coeffs[rotation] = challenge;
    }
    let challenge_poly = RingElem::from_coeffs(challenge_coeffs);
    let folded_right =
        multiply_ring_elems_with_mode(ring_profile, &challenge_poly, right, stats, false)?;
    let mut coeffs = Vec::with_capacity(left.coeffs.len());
    for (left_coeff, folded_coeff) in left.coeffs.iter().zip(folded_right) {
        let value = Goldilocks::new(*left_coeff) + goldilocks_from_signed(folded_coeff);
        coeffs.push(value.as_canonical_u64());
    }
    Ok(RingElem::from_coeffs(coeffs))
}

fn reduce_fold_challenge(challenge_bits: u32, raw: u64) -> u64 {
    let mask_bits = challenge_bits.min(63);
    let modulus = 1u64 << mask_bits;
    let reduced = if modulus <= 1 {
        1
    } else {
        (raw % (modulus - 1)) + 1
    };
    Goldilocks::new(reduced).as_canonical_u64()
}

fn goldilocks_from_signed(value: i128) -> Goldilocks {
    Goldilocks::new(reduce_goldilocks_signed(value))
}

fn leaf_proof_digest(
    pk: &BackendKey,
    relation_id: &RelationId,
    statement_digest: &StatementDigest,
    packed: &PackedWitness<u64>,
    commitment_digest: &[u8; 48],
) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.leaf-proof.v2");
    hasher.update(&pk.params_fingerprint);
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
    hasher.update(&(pk.ring_degree as u64).to_le_bytes());
    hasher.update(&pk.digit_bits.to_le_bytes());
    hasher.update(&pk.opening_randomness_bits.to_le_bytes());
    hasher.update(&statement_digest.0);
    hasher.update(commitment_digest);
    hasher.update(&(packed.original_len as u64).to_le_bytes());
    hasher.update(&(packed.used_bits as u64).to_le_bytes());
    hasher.update(&packed.coeff_capacity_bits.to_le_bytes());
    hasher.update(&(packed.coeffs.len() as u64).to_le_bytes());
    for coeff in &packed.coeffs {
        hasher.update(&coeff.to_le_bytes());
    }
    hash48(hasher)
}

fn fold_statement_digest(
    left: &StatementDigest,
    right: &StatementDigest,
    challenges: &[u64],
    parent_commitment_digest: &[u8; 48],
) -> StatementDigest {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-statement.v3");
    hasher.update(&(challenges.len() as u32).to_le_bytes());
    for challenge in challenges {
        hasher.update(&challenge.to_le_bytes());
    }
    hasher.update(&left.0);
    hasher.update(&right.0);
    hasher.update(parent_commitment_digest);
    StatementDigest(hash48(hasher))
}

fn fold_proof_digest(
    pk: &BackendKey,
    relation_id: &RelationId,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
    challenges: &[u64],
    parent_statement_digest: &StatementDigest,
    parent_rows: &[RingElem],
) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-proof.v3");
    hasher.update(&pk.params_fingerprint);
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.fold_challenge_count.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
    hasher.update(&(pk.ring_degree as u64).to_le_bytes());
    hasher.update(&pk.digit_bits.to_le_bytes());
    hasher.update(&pk.opening_randomness_bits.to_le_bytes());
    hasher.update(&(challenges.len() as u32).to_le_bytes());
    for challenge in challenges {
        hasher.update(&challenge.to_le_bytes());
    }
    hasher.update(&left.statement_digest.0);
    hasher.update(&right.statement_digest.0);
    hasher.update(&left.witness_commitment.digest);
    hasher.update(&right.witness_commitment.digest);
    hasher.update(&parent_statement_digest.0);
    hasher.update(&digest_commitment_rows(parent_rows));
    hasher.update(&(parent_rows.len() as u64).to_le_bytes());
    for row in parent_rows {
        hasher.update(&(row.coeffs.len() as u64).to_le_bytes());
        for coeff in &row.coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
    }
    hash48(hasher)
}

fn accumulate_ring_product_narrow_source(
    ring_profile: RingProfile,
    accumulator: &mut [i128],
    left: &RingElem,
    right: &RingElem,
    stats: &mut KernelLocalStats,
) {
    accumulate_ring_product_with_mode(ring_profile, accumulator, left, right, stats, true)
        .expect("narrow ring product must succeed");
}

fn accumulate_ring_product_generic_source(
    ring_profile: RingProfile,
    accumulator: &mut [i128],
    left: &RingElem,
    right: &RingElem,
    stats: &mut KernelLocalStats,
) {
    accumulate_ring_product_with_mode(ring_profile, accumulator, left, right, stats, false)
        .expect("generic ring product must succeed");
}

fn accumulate_ring_product_with_mode(
    ring_profile: RingProfile,
    accumulator: &mut [i128],
    left: &RingElem,
    right: &RingElem,
    stats: &mut KernelLocalStats,
    narrow_source: bool,
) -> Result<()> {
    let degree = left.coeffs.len();
    ensure!(
        degree == ring_profile.degree(),
        "left ring degree {} does not match profile degree {}",
        degree,
        ring_profile.degree()
    );
    ensure!(
        right.coeffs.len() == degree,
        "cannot multiply ring elements with different degrees"
    );
    ensure!(
        accumulator.len() == degree,
        "ring accumulator length {} does not match degree {}",
        accumulator.len(),
        degree
    );
    stats.delayed_reduction_batches += 1;
    let mut reduced =
        multiply_ring_elems_with_mode(ring_profile, left, right, stats, narrow_source)?;
    for (slot, value) in accumulator.iter_mut().zip(reduced.drain(..)) {
        *slot += value;
    }
    Ok(())
}

fn multiply_ring_elems_with_mode(
    ring_profile: RingProfile,
    left: &RingElem,
    right: &RingElem,
    stats: &mut KernelLocalStats,
    narrow_source: bool,
) -> Result<Vec<i128>> {
    let degree = left.coeffs.len();
    ensure!(
        degree == ring_profile.degree(),
        "left ring degree {} does not match profile degree {}",
        degree,
        ring_profile.degree()
    );
    ensure!(
        right.coeffs.len() == degree,
        "cannot multiply ring elements with different degrees"
    );
    let mut raw = vec![0i128; degree.saturating_mul(2).saturating_sub(1)];
    for (i, left_coeff) in left.coeffs.iter().enumerate() {
        for (j, right_coeff) in right.coeffs.iter().enumerate() {
            if *right_coeff == 0 {
                continue;
            }
            let target = i + j;
            let product = if narrow_source {
                stats.small_big_ops += 1;
                i128::from(*left_coeff) * i128::from((*right_coeff) as u16)
            } else {
                stats.big_big_ops += 1;
                i128::from(*left_coeff) * i128::from(*right_coeff)
            };
            raw[target] += i128::from(reduce_goldilocks_signed(product));
        }
    }
    reduce_ring_polynomial(ring_profile, &mut raw)?;
    raw.truncate(degree);
    Ok(raw)
}

fn reduce_ring_polynomial(ring_profile: RingProfile, coeffs: &mut [i128]) -> Result<()> {
    let degree = ring_profile.degree();
    ensure!(
        coeffs.len() >= degree,
        "coefficient buffer length {} must be at least ring degree {}",
        coeffs.len(),
        degree
    );
    for index in (degree..coeffs.len()).rev() {
        let carry = coeffs[index];
        if carry == 0 {
            continue;
        }
        coeffs[index] = 0;
        let base = index - degree;
        for (shift, factor) in ring_profile.reduction_terms() {
            let target = base + shift;
            ensure!(
                target < coeffs.len(),
                "ring reduction target {} exceeds coefficient buffer {}",
                target,
                coeffs.len()
            );
            coeffs[target] += carry * i128::from(*factor);
        }
    }
    Ok(())
}

fn reduce_goldilocks_signed(value: i128) -> u64 {
    let mut reduced = value % GOLDILOCKS_MODULUS_I128;
    if reduced < 0 {
        reduced += GOLDILOCKS_MODULUS_I128;
    }
    reduced as u64
}

fn reduce_goldilocks_u128(value: u128) -> u64 {
    (value % (GOLDILOCKS_MODULUS_I128 as u128)) as u64
}

fn hash48(hasher: Hasher) -> [u8; 48] {
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn hash32(hasher: Hasher) -> [u8; 32] {
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn digest32_with_label(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn hex_nibble(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[value as usize] as char
}

#[cfg(test)]
mod tests {
    use p3_goldilocks::Goldilocks;
    use superneo_ccs::{
        digest_statement, Assignment, CcsShape, RelationId, ShapeDigest, SparseEntry, SparseMatrix,
        StatementDigest, StatementEncoding, WitnessField, WitnessSchema,
    };
    use superneo_core::{Backend, FoldedInstance};
    use superneo_ring::{
        GoldilocksPackingConfig, GoldilocksPayPerBitPacker, PackedWitness, WitnessPacker,
    };

    use super::{
        clear_prepared_matrix_cache, reset_kernel_cost_report, review_fold_challenges,
        review_leaf_proof_digest, take_kernel_cost_report, BackendManifest,
        CommitmentSecurityModel, LatticeBackend, LatticeCommitment, NativeBackendParams,
        NativeCommitmentScheme, PreparedCommitmentMatrix, PreparedMatrixCache, ReviewState,
        RingElem, RingProfile,
    };
    use std::sync::Arc;

    fn shape() -> CcsShape<Goldilocks> {
        CcsShape {
            num_rows: 2,
            num_cols: 4,
            matrices: vec![SparseMatrix {
                row_count: 2,
                col_count: 4,
                entries: vec![SparseEntry {
                    row: 0,
                    col: 0,
                    value: Goldilocks::new(1),
                }],
            }],
            selectors: vec![Goldilocks::new(1)],
            witness_schema: WitnessSchema {
                fields: vec![
                    WitnessField {
                        name: "a",
                        bit_width: 8,
                        signed: false,
                        count: 2,
                    },
                    WitnessField {
                        name: "b",
                        bit_width: 4,
                        signed: false,
                        count: 1,
                    },
                ],
            },
        }
    }

    fn wide_shape() -> CcsShape<Goldilocks> {
        CcsShape {
            num_rows: 2,
            num_cols: 2,
            matrices: vec![SparseMatrix {
                row_count: 2,
                col_count: 2,
                entries: vec![SparseEntry {
                    row: 0,
                    col: 0,
                    value: Goldilocks::new(1),
                }],
            }],
            selectors: vec![Goldilocks::new(1)],
            witness_schema: WitnessSchema {
                fields: vec![
                    WitnessField {
                        name: "wide",
                        bit_width: 64,
                        signed: false,
                        count: 1,
                    },
                    WitnessField {
                        name: "narrow",
                        bit_width: 8,
                        signed: false,
                        count: 1,
                    },
                ],
            },
        }
    }

    #[test]
    fn leaf_and_fold_roundtrip() {
        let backend = LatticeBackend::new(NativeBackendParams::default());
        let security = backend.security_params();
        let (pk, vk) = backend.setup(&security, &shape()).unwrap();

        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let left_assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let right_assignment = Assignment {
            witness: vec![Goldilocks::new(11), Goldilocks::new(21), Goldilocks::new(4)],
        };
        let left_packed = packer.pack(&shape(), &left_assignment).unwrap();
        let right_packed = packer.pack(&shape(), &right_assignment).unwrap();
        let left_statement = StatementEncoding {
            public_inputs: vec![Goldilocks::new(1)],
            statement_digest: digest_statement(b"left"),
        };
        let right_statement = StatementEncoding {
            public_inputs: vec![Goldilocks::new(2)],
            statement_digest: digest_statement(b"right"),
        };
        let left_commitment = backend.commit_witness(&pk, &left_packed).unwrap();
        let right_commitment = backend.commit_witness(&pk, &right_packed).unwrap();

        let left_proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &left_statement,
                &left_packed,
                &left_commitment,
            )
            .unwrap();
        let right_proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &right_statement,
                &right_packed,
                &right_commitment,
            )
            .unwrap();
        backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &left_statement,
                &left_packed,
                &left_proof,
            )
            .unwrap();
        backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &right_statement,
                &right_packed,
                &right_proof,
            )
            .unwrap();

        let left_instance = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: left_statement.statement_digest,
            witness_commitment: left_commitment,
        };
        let right_instance = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: right_statement.statement_digest,
            witness_commitment: right_commitment,
        };
        let (parent, proof) = backend
            .fold_pair(&pk, &left_instance, &right_instance)
            .unwrap();
        backend
            .verify_fold(&vk, &parent, &left_instance, &right_instance, &proof)
            .unwrap();
    }

    #[test]
    fn verify_leaf_rejects_tampered_expected_witness() {
        let backend = LatticeBackend::new(NativeBackendParams::default());
        let security = backend.security_params();
        let (pk, vk) = backend.setup(&security, &shape()).unwrap();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let packed = packer.pack(&shape(), &assignment).unwrap();
        let statement = StatementEncoding {
            public_inputs: vec![Goldilocks::new(1)],
            statement_digest: digest_statement(b"left"),
        };
        let commitment = backend.commit_witness(&pk, &packed).unwrap();
        let proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &statement,
                &packed,
                &commitment,
            )
            .unwrap();
        let mut tampered = packed.clone();
        tampered.coeffs[0] ^= 1;
        assert!(backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &statement,
                &tampered,
                &proof,
            )
            .is_err());
    }

    #[test]
    fn native_commitment_opening_round_trip_and_randomizes() {
        let backend = LatticeBackend::new(NativeBackendParams::default());
        let params = backend.native_params().clone();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let packed = packer.pack(&shape(), &assignment).unwrap();
        let (first_commitment, first_opening) = backend.commit(&params, &packed).unwrap();
        let (second_commitment, second_opening) = backend.commit(&params, &packed).unwrap();
        backend
            .verify_opening(&params, &first_commitment, &first_opening)
            .unwrap();
        backend
            .verify_opening(&params, &second_commitment, &second_opening)
            .unwrap();
        assert_ne!(
            first_opening.randomness_seed,
            second_opening.randomness_seed
        );
        assert_ne!(first_commitment.digest, second_commitment.digest);
    }

    #[test]
    fn native_commitment_opening_rejects_wrong_randomness_and_params() {
        let backend = LatticeBackend::new(NativeBackendParams::default());
        let params = backend.native_params().clone();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let packed = packer.pack(&shape(), &assignment).unwrap();
        let (commitment, opening) = backend.commit(&params, &packed).unwrap();

        let mut wrong_randomness = opening.clone();
        wrong_randomness.randomness_seed[0] ^= 0x7f;
        assert!(backend
            .verify_opening(&params, &commitment, &wrong_randomness)
            .is_err());

        let wrong_params = NativeBackendParams {
            opening_randomness_bits: 12,
            ..params.clone()
        };
        assert!(backend
            .verify_opening(&wrong_params, &commitment, &opening)
            .is_err());
    }

    #[test]
    fn native_commitment_opening_rejects_noncanonical_randomness_seed() {
        let backend = LatticeBackend::new(NativeBackendParams::default());
        let params = backend.native_params().clone();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let packed = packer.pack(&shape(), &assignment).unwrap();
        let (commitment, opening) = backend.commit(&params, &packed).unwrap();

        let mut noncanonical = opening.clone();
        noncanonical.randomness_seed[31] ^= 0x80;
        assert!(backend
            .verify_opening(&params, &commitment, &noncanonical)
            .is_err());
    }

    #[test]
    fn verify_fold_rejects_parent_metadata_mismatch() {
        let backend = LatticeBackend::new(NativeBackendParams::default());
        let security = backend.security_params();
        let (pk, vk) = backend.setup(&security, &shape()).unwrap();

        let left = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: digest_statement(b"left"),
            witness_commitment: LatticeCommitment::from_rows(vec![
                RingElem::from_coeffs(
                    vec![1u64; pk.ring_degree]
                );
                pk.commitment_rows
            ]),
        };
        let right = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: digest_statement(b"right"),
            witness_commitment: LatticeCommitment::from_rows(vec![
                RingElem::from_coeffs(
                    vec![2u64; pk.ring_degree]
                );
                pk.commitment_rows
            ]),
        };
        let (mut parent, proof) = backend.fold_pair(&pk, &left, &right).unwrap();
        parent.relation_id = superneo_ccs::RelationId::from_label("wrong");
        assert!(backend
            .verify_fold(&vk, &parent, &left, &right, &proof)
            .is_err());
    }

    #[test]
    fn verify_fold_rejects_tampered_parent_rows() {
        let backend = LatticeBackend::new(NativeBackendParams::default());
        let security = backend.security_params();
        let (pk, vk) = backend.setup(&security, &shape()).unwrap();
        let left = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: digest_statement(b"left"),
            witness_commitment: LatticeCommitment::from_rows(vec![
                RingElem::from_coeffs(
                    vec![1u64; pk.ring_degree]
                );
                pk.commitment_rows
            ]),
        };
        let right = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: digest_statement(b"right"),
            witness_commitment: LatticeCommitment::from_rows(vec![
                RingElem::from_coeffs(
                    vec![2u64; pk.ring_degree]
                );
                pk.commitment_rows
            ]),
        };
        let (parent, mut proof) = backend.fold_pair(&pk, &left, &right).unwrap();
        proof.parent_rows[0].coeffs[0] ^= 1;
        assert!(backend
            .verify_fold(&vk, &parent, &left, &right, &proof)
            .is_err());
    }

    #[test]
    fn kernel_report_tracks_cache_hits_and_delayed_reduction() {
        clear_prepared_matrix_cache();
        reset_kernel_cost_report();

        let backend = LatticeBackend::new(NativeBackendParams::default());
        let security = backend.security_params();
        let (pk, _) = backend.setup(&security, &shape()).unwrap();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let packed = packer.pack(&shape(), &assignment).unwrap();

        let first = backend.commit_witness(&pk, &packed).unwrap();
        let second = backend.commit_witness(&pk, &packed).unwrap();
        assert_eq!(first.digest, second.digest);

        let report = take_kernel_cost_report();
        assert_eq!(report.matrix_cache_misses, 1);
        assert!(report.matrix_cache_hits >= 1);
        assert!(report.commitment_kernel_ns > 0);
        assert!(report.delayed_reduction_batches > 0);
        assert!(report.small_big_ops > 0);
        assert_eq!(report.big_big_ops, 0);
    }

    #[test]
    fn prepared_matrix_cache_key_separates_ring_profiles() {
        clear_prepared_matrix_cache();
        reset_kernel_cost_report();

        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let packed = packer.pack(&shape(), &assignment).unwrap();

        let cyclotomic_backend = LatticeBackend::new(NativeBackendParams {
            ring_profile: RingProfile::GoldilocksCyclotomic24,
            matrix_rows: 74,
            matrix_cols: 8,
            max_commitment_message_ring_elems: 513,
            ..NativeBackendParams::default()
        });
        let frog_backend = LatticeBackend::new(NativeBackendParams::default());
        let cyclotomic_security = cyclotomic_backend.security_params();
        let frog_security = frog_backend.security_params();
        let (cyclotomic_pk, _) = cyclotomic_backend
            .setup(&cyclotomic_security, &shape())
            .unwrap();
        let (frog_pk, _) = frog_backend.setup(&frog_security, &shape()).unwrap();

        let cyclotomic_commitment = cyclotomic_backend
            .commit_witness(&cyclotomic_pk, &packed)
            .unwrap();
        let frog_commitment = frog_backend.commit_witness(&frog_pk, &packed).unwrap();

        let report = take_kernel_cost_report();
        assert_eq!(report.matrix_cache_misses, 2);
        assert_eq!(report.matrix_cache_hits, 0);
        assert_ne!(cyclotomic_commitment.digest, frog_commitment.digest);
        assert_ne!(cyclotomic_commitment.rows, frog_commitment.rows);
    }

    #[test]
    fn prepared_matrix_cache_evicts_least_recently_used_entries() {
        let mut cache = PreparedMatrixCache::default();
        let matrix = |seed| {
            Arc::new(PreparedCommitmentMatrix {
                rows: vec![vec![RingElem::from_coeffs(vec![seed])]],
            })
        };
        let first = [1u8; 32];
        let second = [2u8; 32];
        let third = [3u8; 32];

        assert_eq!(cache.insert(first, matrix(1), 2), 0);
        assert_eq!(cache.insert(second, matrix(2), 2), 0);
        assert!(cache.get(&first).is_some());

        assert_eq!(cache.insert(third, matrix(3), 2), 1);
        assert!(cache.get(&first).is_some());
        assert!(cache.get(&second).is_none());
        assert!(cache.get(&third).is_some());
        assert_eq!(cache.entries.len(), 2);
    }

    #[test]
    fn width_metadata_drives_generic_commitment_kernel() {
        clear_prepared_matrix_cache();
        reset_kernel_cost_report();

        let backend = LatticeBackend::new(NativeBackendParams::default());
        let security = backend.security_params();
        let (pk, _) = backend.setup(&security, &wide_shape()).unwrap();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(1u64 << 40), Goldilocks::new(7)],
        };
        let packed = packer.pack(&wide_shape(), &assignment).unwrap();

        backend.commit_witness(&pk, &packed).unwrap();

        let report = take_kernel_cost_report();
        assert!(report.big_big_ops > 0);
    }

    #[test]
    fn derive_fold_challenge_uses_configured_width_above_16_bits() {
        let params = NativeBackendParams {
            security_bits: 20,
            challenge_bits: 20,
            fold_challenge_count: 2,
            opening_randomness_bits: 40,
            commitment_security_model: CommitmentSecurityModel::BoundedKernelModuleSis,
            max_claimed_receipt_root_leaves: 1,
            ..NativeBackendParams::default()
        };
        let backend = LatticeBackend::new(params);
        let security = backend.security_params();
        let (pk, _) = backend.setup(&security, &shape()).unwrap();

        for attempt in 0..128u64 {
            let left = FoldedInstance {
                relation_id: superneo_ccs::RelationId::from_label("test"),
                shape_digest: pk.shape_digest,
                statement_digest: digest_statement(&attempt.to_le_bytes()),
                witness_commitment: LatticeCommitment::from_rows(vec![
                    RingElem::from_coeffs(
                        vec![attempt + 1; pk.ring_degree]
                    );
                    pk.commitment_rows
                ]),
            };
            let right = FoldedInstance {
                relation_id: superneo_ccs::RelationId::from_label("test"),
                shape_digest: pk.shape_digest,
                statement_digest: digest_statement(&(attempt + 1000).to_le_bytes()),
                witness_commitment: LatticeCommitment::from_rows(vec![
                    RingElem::from_coeffs(
                        vec![attempt + 2; pk.ring_degree]
                    );
                    pk.commitment_rows
                ]),
            };
            let challenges = super::derive_fold_challenges(&pk, &left, &right);
            if challenges
                .iter()
                .any(|challenge| *challenge > u16::MAX as u64)
            {
                return;
            }
        }

        panic!("configured 20-bit fold challenges never exceeded 16 bits");
    }

    #[test]
    fn setup_rejects_security_param_drift() {
        let backend = LatticeBackend::new(NativeBackendParams::default());
        let mut security = backend.security_params();
        security.max_fold_arity = 4;
        assert!(backend.setup(&security, &shape()).is_err());

        let mut security = backend.security_params();
        security.transcript_domain = b"hegemon.superneo.fold.alt";
        assert!(backend.setup(&security, &shape()).is_err());
    }

    #[test]
    fn parameter_fingerprint_covers_security_regime() {
        let base = NativeBackendParams::default();
        let different_manifest = NativeBackendParams {
            manifest: BackendManifest {
                family_label: "goldilocks_structural_commitment_alt",
                ..base.manifest
            },
            ..base.clone()
        };
        assert_ne!(
            base.parameter_fingerprint(),
            different_manifest.parameter_fingerprint()
        );

        let different_arity = NativeBackendParams {
            max_fold_arity: 4,
            ..base.clone()
        };
        assert_ne!(
            base.parameter_fingerprint(),
            different_arity.parameter_fingerprint()
        );

        let different_commitment_security_model = NativeBackendParams {
            commitment_security_model: CommitmentSecurityModel::GeometryProxy,
            ..base.clone()
        };
        assert_ne!(
            base.parameter_fingerprint(),
            different_commitment_security_model.parameter_fingerprint()
        );

        let different_message_cap = NativeBackendParams {
            max_commitment_message_ring_elems: 1024,
            ..base.clone()
        };
        assert_ne!(
            base.parameter_fingerprint(),
            different_message_cap.parameter_fingerprint()
        );

        let different_receipt_cap = NativeBackendParams {
            max_claimed_receipt_root_leaves: 64,
            ..base.clone()
        };
        assert_ne!(
            base.parameter_fingerprint(),
            different_receipt_cap.parameter_fingerprint()
        );

        let different_binding_model = NativeBackendParams {
            commitment_security_model: match base.commitment_security_model {
                CommitmentSecurityModel::GeometryProxy => {
                    CommitmentSecurityModel::BoundedKernelModuleSis
                }
                CommitmentSecurityModel::BoundedKernelModuleSis => {
                    CommitmentSecurityModel::GeometryProxy
                }
            },
            ..base.clone()
        };
        assert_ne!(
            base.parameter_fingerprint(),
            different_binding_model.parameter_fingerprint()
        );

        let different_domain = NativeBackendParams {
            transcript_domain_label: "hegemon.superneo.fold.alt",
            ..base
        };
        assert_ne!(
            NativeBackendParams::default().parameter_fingerprint(),
            different_domain.parameter_fingerprint()
        );
    }

    #[test]
    fn spec_digest_covers_spec_identity() {
        let base = NativeBackendParams::default();
        let different_spec = NativeBackendParams {
            manifest: BackendManifest {
                spec_label: "hegemon.superneo.native-backend-spec.goldilocks-128b-rewrite.v1.alt",
                ..base.manifest
            },
            ..base.clone()
        };
        assert_ne!(base.spec_digest(), different_spec.spec_digest());
        assert_ne!(
            base.parameter_fingerprint(),
            different_spec.parameter_fingerprint()
        );
    }

    #[test]
    fn structural_128b_security_claim_matches_current_floor() {
        let claim = NativeBackendParams::goldilocks_128b_structural_commitment()
            .security_claim()
            .unwrap();
        assert_eq!(claim.claimed_security_bits, 128);
        assert_eq!(claim.transcript_soundness_bits, 157);
        assert_eq!(claim.opening_hiding_bits, 0);
        assert_eq!(claim.commitment_codomain_bits, 37_422);
        assert_eq!(claim.commitment_same_seed_search_bits, 36_936);
        assert_eq!(claim.commitment_random_matrix_bits, 486);
        assert_eq!(claim.commitment_problem_equations, 594);
        assert_eq!(claim.commitment_problem_dimension, 4_104);
        assert_eq!(claim.commitment_problem_coeff_bound, 255);
        assert_eq!(claim.commitment_problem_l2_bound, 16_336);
        assert_eq!(claim.commitment_estimator_dimension, 4_104);
        assert_eq!(claim.commitment_estimator_block_size, 3_294);
        assert_eq!(claim.commitment_estimator_classical_bits, 961);
        assert_eq!(claim.commitment_estimator_quantum_bits, 872);
        assert_eq!(claim.commitment_estimator_paranoid_bits, 683);
        assert_eq!(claim.commitment_reduction_loss_bits, 0);
        assert_eq!(claim.commitment_binding_bits, 872);
        assert_eq!(claim.composition_loss_bits, 7);
        assert_eq!(claim.soundness_floor_bits, 150);
        assert_eq!(claim.review_state, ReviewState::CandidateUnderReview);
        assert!(claim
            .assumption_ids
            .contains(&"fs.quint_goldilocks_profile_fold_challenges"));
        assert!(claim
            .assumption_ids
            .contains(&"commitment.deterministic_public_witness_reconstruction"));
        assert!(claim
            .assumption_ids
            .contains(&"commitment.bounded_kernel_module_sis_exact_reduction"));
        assert!(claim
            .assumption_ids
            .contains(&"commitment.sis_lattice_euclidean_adps16_quantum_estimator"));
    }

    #[test]
    fn fold_challenges_change_when_transcript_domain_changes() {
        let params = NativeBackendParams::goldilocks_128b_structural_commitment();
        let mut alternate = params.clone();
        alternate.transcript_domain_label = "hegemon.superneo.fold.alt";
        let shape_digest = ShapeDigest([9u8; 32]);
        let relation_id = RelationId::from_label("hegemon.superneo.test.fold");
        let left = FoldedInstance {
            relation_id,
            shape_digest,
            statement_digest: StatementDigest([1u8; 48]),
            witness_commitment: LatticeCommitment::from_rows(vec![
                RingElem::from_coeffs(
                    vec![3u64; params.matrix_cols]
                );
                params.matrix_rows
            ]),
        };
        let right = FoldedInstance {
            relation_id,
            shape_digest,
            statement_digest: StatementDigest([2u8; 48]),
            witness_commitment: LatticeCommitment::from_rows(vec![
                RingElem::from_coeffs(
                    vec![5u64; params.matrix_cols]
                );
                params.matrix_rows
            ]),
        };
        let base = review_fold_challenges(&params, shape_digest, &left, &right).unwrap();
        let changed = review_fold_challenges(&alternate, shape_digest, &left, &right).unwrap();
        assert_ne!(base, changed);
    }

    #[test]
    fn leaf_proof_digest_changes_when_relation_id_changes() {
        let params = NativeBackendParams::goldilocks_128b_structural_commitment();
        let packed = PackedWitness {
            coeffs: vec![1, 2],
            original_len: 2,
            used_bits: 2,
            coeff_capacity_bits: 60,
            value_bit_widths: vec![1, 1],
            width_summary: superneo_ring::PackedWidthSummary {
                one_bit_values: 2,
                byte_values: 0,
                word16_values: 0,
                word32_values: 0,
                wide_values: 0,
                max_bit_width: 1,
            },
        };
        let digest_a = review_leaf_proof_digest(
            &params,
            ShapeDigest([7u8; 32]),
            &RelationId::from_label("hegemon.superneo.test.leaf.a"),
            &StatementDigest([11u8; 48]),
            &packed,
            &[19u8; 48],
        )
        .unwrap();
        let digest_b = review_leaf_proof_digest(
            &params,
            ShapeDigest([7u8; 32]),
            &RelationId::from_label("hegemon.superneo.test.leaf.b"),
            &StatementDigest([11u8; 48]),
            &packed,
            &[19u8; 48],
        )
        .unwrap();
        assert_ne!(digest_a, digest_b);
    }

    #[test]
    fn validate_rejects_security_target_above_soundness_floor() {
        let baseline = NativeBackendParams::goldilocks_128b_structural_commitment();
        let floor = baseline
            .security_claim()
            .expect("baseline claim")
            .soundness_floor_bits;
        let params = NativeBackendParams {
            security_bits: floor.saturating_add(1),
            ..baseline
        };
        let error = params
            .validate()
            .expect_err("overclaimed security must fail");
        let message = error.to_string();
        assert!(message.contains("exceeds native backend soundness floor"));
        assert!(message.contains(&(floor.saturating_add(1)).to_string()));
        assert!(message.contains(&floor.to_string()));
    }
}
