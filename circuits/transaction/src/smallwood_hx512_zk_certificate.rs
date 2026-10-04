//! Fail-closed complete-ZK/refinement certificate for the fresh HX512
//! SmallWood profile.
//!
//! This module is deliberately independent of `smallwood_engine` and of every
//! historical `SMZ*` authority flag.  It derives the candidate geometry,
//! enumerates the complete verifier-visible view, checks the finite-field
//! linear maps used by the local simulators, and exposes a witness-free lazy
//! classical-ROM candidate simulator.  Local ranks are necessary evidence;
//! they are not a joint simulator, an adaptive QROM lift, compiled
//! refinement, or production authorization.  All authority flags below are
//! therefore hard false.

use num_bigint::BigUint;
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;
use std::fmt;

pub const HX512_GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
const GOLDILOCKS_TWO_ADIC_ROOT: u64 = 0x1856_29dc_da58_878c;
const GOLDILOCKS_TWO_ADICITY: u32 = 32;

pub const HX512_Q48_DECS_OPENINGS: usize = 48;
pub const HX512_Q48_PIOP_OPENINGS: usize = 6;
pub const HX512_Q48_DECS_ETA: usize = 5;
pub const HX512_Q48_SALT_BYTES: usize = 64;
pub const HX512_Q48_LEAF_TAPE_BYTES: usize = 72;
pub const HX512_Q48_DIGEST_BYTES: usize = 64;
pub const HX512_CMS_QROM_QUERY_BOUND_LOG2: u32 = 64;
pub const HX512_CMS_QROM_LOSS_FACTOR: u32 = 12;
pub const HX512_COMPOSED_SECURITY_TARGET_BITS: u32 = 128;

const PROFILE_DOMAIN: &[u8] = b"hegemon.smallwood.hx512.zk-certificate.profile.v1";
const VIEW_SEED_DOMAIN: &[u8] = b"hegemon.smallwood.hx512.zk-certificate.view-seed.v1";
const VIEW_FIELD_DOMAIN: &[u8] = b"hegemon.smallwood.hx512.zk-certificate.field.v1";
const COVERAGE_DOMAIN: &[u8] = b"hegemon.smallwood.hx512.zk-certificate.coverage.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hx512ZkCertificateError {
    InvalidProfile(&'static str),
    InvalidIdentity(&'static str),
    InvalidWire(&'static str),
    ArithmeticOverflow(&'static str),
    InvalidFieldElement,
    SingularMatrix(&'static str),
    RaggedMatrix,
    InvalidViewLedger(&'static str),
    InvalidCoordinate(&'static str),
    UnrefinedField(Hx512VerifierViewField),
}

impl fmt::Display for Hx512ZkCertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile(message) => {
                write!(formatter, "invalid HX512 ZK profile: {message}")
            }
            Self::InvalidIdentity(message) => {
                write!(formatter, "invalid HX512 identity pins: {message}")
            }
            Self::InvalidWire(message) => {
                write!(formatter, "invalid HX512 wire grammar: {message}")
            }
            Self::ArithmeticOverflow(label) => {
                write!(formatter, "HX512 certificate arithmetic overflow: {label}")
            }
            Self::InvalidFieldElement => write!(formatter, "noncanonical Goldilocks element"),
            Self::SingularMatrix(label) => write!(formatter, "singular HX512 matrix: {label}"),
            Self::RaggedMatrix => write!(formatter, "ragged HX512 matrix"),
            Self::InvalidViewLedger(message) => {
                write!(formatter, "invalid HX512 verifier-view ledger: {message}")
            }
            Self::InvalidCoordinate(message) => {
                write!(formatter, "invalid HX512 simulated coordinate: {message}")
            }
            Self::UnrefinedField(field) => {
                write!(
                    formatter,
                    "HX512 view field {field:?} is not executable-refined"
                )
            }
        }
    }
}

impl std::error::Error for Hx512ZkCertificateError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ZkProfile {
    pub packing_factor: usize,
    pub relation_rows: usize,
    pub constraint_degree: usize,
    pub rho: usize,
    /// SmallWood's `nb_opened_evals`, conventionally denoted `s` below.
    pub piop_openings: usize,
    pub beta: usize,
    pub decs_domain_size: usize,
    /// DECS query/opening count, conventionally denoted `q_D`.
    pub decs_openings: usize,
    /// Number of DECS challenge/masking polynomials.  This is not `s`.
    pub decs_eta: usize,
    pub salt_bytes: usize,
    /// Number of independent DECS leaf tapes committed before openings.
    /// Only `decs_openings` of these tapes are subsequently serialized.
    pub decs_committed_leaf_tape_count: usize,
    pub decs_leaf_tape_bytes: usize,
    pub digest_bytes: usize,
    pub nonce_bytes: usize,
    pub auxiliary_word_count: usize,
    pub statement_bytes: usize,
    pub verifier_context_bytes: usize,
    pub opening_pow_bits: u32,
    pub decs_pow_bits: u32,
    pub max_piop_trials: Option<u32>,
    pub decs_sampler_candidates: Option<usize>,
}

impl Hx512ZkProfile {
    /// Construct the q48/s6 algebra around caller-supplied, still-unfrozen
    /// relation geometry.  The complete relation row count is deliberately an
    /// argument: hash-topology rows alone are not the final adapter relation.
    pub fn unfrozen_q48_s6(
        relation_rows: usize,
        constraint_degree: usize,
        statement_bytes: usize,
        verifier_context_bytes: usize,
    ) -> Self {
        Self {
            packing_factor: 1024,
            relation_rows,
            constraint_degree,
            rho: 5,
            piop_openings: HX512_Q48_PIOP_OPENINGS,
            beta: 2,
            decs_domain_size: 1 << 20,
            decs_openings: HX512_Q48_DECS_OPENINGS,
            decs_eta: HX512_Q48_DECS_ETA,
            salt_bytes: HX512_Q48_SALT_BYTES,
            decs_committed_leaf_tape_count: 1 << 20,
            decs_leaf_tape_bytes: HX512_Q48_LEAF_TAPE_BYTES,
            digest_bytes: HX512_Q48_DIGEST_BYTES,
            nonce_bytes: 4,
            auxiliary_word_count: 0,
            statement_bytes,
            verifier_context_bytes,
            opening_pow_bits: 0,
            decs_pow_bits: 0,
            max_piop_trials: None,
            decs_sampler_candidates: None,
        }
    }

    pub fn validate_q48(&self) -> Result<(), Hx512ZkCertificateError> {
        if self.packing_factor == 0 || self.relation_rows == 0 {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "packing factor and relation row count must be nonzero",
            ));
        }
        if !(2..=8).contains(&self.constraint_degree) {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "constraint degree must be in the SmallWood 2..=8 envelope",
            ));
        }
        if self.rho != 5 || self.beta != 2 {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "fresh q48 profile requires rho=5 and beta=2",
            ));
        }
        if self.piop_openings != HX512_Q48_PIOP_OPENINGS {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "q48 strict profile requires exactly six PIOP openings/high randomizers; s=5 is disqualified",
            ));
        }
        if self.decs_eta != HX512_Q48_DECS_ETA {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "q48 strict profile keeps DECS eta at five; eta must not be aliased to s=6",
            ));
        }
        if self.piop_openings == self.decs_eta {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "PIOP opening dimension s and DECS eta are distinct profile coordinates",
            ));
        }
        if self.decs_domain_size != 1 << 20 || !self.decs_domain_size.is_power_of_two() {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "q48 profile requires the exact 2^20 DECS domain",
            ));
        }
        if self.decs_openings != HX512_Q48_DECS_OPENINGS {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "q48 profile requires exactly 48 DECS openings",
            ));
        }
        if self.decs_committed_leaf_tape_count != self.decs_domain_size {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "DECS requires one independently sampled committed tape for every domain leaf",
            ));
        }
        if self.salt_bytes != HX512_Q48_SALT_BYTES
            || self.decs_leaf_tape_bytes != HX512_Q48_LEAF_TAPE_BYTES
            || self.digest_bytes != HX512_Q48_DIGEST_BYTES
        {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "q48 profile requires 64-byte salt/digest and 72-byte leaf tapes",
            ));
        }
        if self.nonce_bytes != 4 {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "fresh canonical PIOP nonce must be a four-byte counter",
            ));
        }
        if self.auxiliary_word_count != 0 {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "HX512 aggregate witness must have aux_count=0",
            ));
        }
        if self.statement_bytes == 0 || self.verifier_context_bytes == 0 {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "statement and verifier-context widths must be explicit",
            ));
        }
        if self.opening_pow_bits != 0 || self.decs_pow_bits != 0 {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "q48 certificate forbids prover grinding",
            ));
        }
        if let Some(candidates) = self.decs_sampler_candidates {
            if candidates < self.decs_openings {
                return Err(Hx512ZkCertificateError::InvalidProfile(
                    "DECS candidate pool is smaller than the opening count",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ZkIdentityPins {
    pub allocated: bool,
    pub engine_source_sha512: [u8; 64],
    pub transcript_source_sha512: [u8; 64],
    pub relation_shape_sha512: [u8; 64],
    pub adapter_topology_sha512: [u8; 64],
    pub typed_hash_schedule_sha512: [u8; 64],
    pub wire_grammar_sha512: [u8; 64],
    pub statement_grammar_sha512: [u8; 64],
    pub context_grammar_sha512: [u8; 64],
    pub domain_registry_sha512: [u8; 64],
    pub profile_sha512: [u8; 64],
    pub consensus_rules_sha512: [u8; 64],
}

impl Hx512ZkIdentityPins {
    pub fn unallocated() -> Self {
        Self {
            allocated: false,
            engine_source_sha512: [0; 64],
            transcript_source_sha512: [0; 64],
            relation_shape_sha512: [0; 64],
            adapter_topology_sha512: [0; 64],
            typed_hash_schedule_sha512: [0; 64],
            wire_grammar_sha512: [0; 64],
            statement_grammar_sha512: [0; 64],
            context_grammar_sha512: [0; 64],
            domain_registry_sha512: [0; 64],
            profile_sha512: [0; 64],
            consensus_rules_sha512: [0; 64],
        }
    }

    fn pin_slices(&self) -> [&[u8; 64]; 11] {
        [
            &self.engine_source_sha512,
            &self.transcript_source_sha512,
            &self.relation_shape_sha512,
            &self.adapter_topology_sha512,
            &self.typed_hash_schedule_sha512,
            &self.wire_grammar_sha512,
            &self.statement_grammar_sha512,
            &self.context_grammar_sha512,
            &self.domain_registry_sha512,
            &self.profile_sha512,
            &self.consensus_rules_sha512,
        ]
    }

    pub fn is_frozen(&self) -> bool {
        self.allocated
            && self
                .pin_slices()
                .iter()
                .all(|digest| digest.iter().any(|byte| *byte != 0))
    }

    pub fn validate_frozen(&self) -> Result<(), Hx512ZkCertificateError> {
        if !self.allocated {
            return Err(Hx512ZkCertificateError::InvalidIdentity(
                "successor identity is not allocated",
            ));
        }
        if self
            .pin_slices()
            .iter()
            .any(|digest| digest.iter().all(|byte| *byte == 0))
        {
            return Err(Hx512ZkCertificateError::InvalidIdentity(
                "one or more required SHA-512 pins are zero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512WireGrammar {
    /// Number of canonical bytes before the separately inventoried salt.
    pub prefix_bytes_before_salt: Option<usize>,
    pub matrix_dimension_bytes: usize,
    pub auth_path_count_bytes: usize,
    pub auth_path_length_bytes: usize,
    pub opened_witness_tag_bytes: usize,
    pub auxiliary_count_bytes: usize,
    pub parser_cap_bytes: Option<usize>,
    pub exact_consumption: bool,
    pub frozen: bool,
}

impl Hx512WireGrammar {
    pub fn provisional() -> Self {
        Self {
            prefix_bytes_before_salt: None,
            matrix_dimension_bytes: 4,
            auth_path_count_bytes: 2,
            auth_path_length_bytes: 1,
            opened_witness_tag_bytes: 1,
            auxiliary_count_bytes: 8,
            parser_cap_bytes: None,
            exact_consumption: true,
            frozen: false,
        }
    }

    pub fn validate(&self) -> Result<(), Hx512ZkCertificateError> {
        if self.matrix_dimension_bytes == 0
            || self.auth_path_count_bytes == 0
            || self.auth_path_length_bytes == 0
            || self.opened_witness_tag_bytes == 0
            || self.auxiliary_count_bytes == 0
        {
            return Err(Hx512ZkCertificateError::InvalidWire(
                "wire framing widths must be nonzero",
            ));
        }
        if !self.exact_consumption {
            return Err(Hx512ZkCertificateError::InvalidWire(
                "fresh parser must reject trailing bytes",
            ));
        }
        if self.frozen && self.prefix_bytes_before_salt.is_none() {
            return Err(Hx512ZkCertificateError::InvalidWire(
                "frozen wire needs an exact canonical prefix width",
            ));
        }
        Ok(())
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen && self.prefix_bytes_before_salt.is_some() && self.exact_consumption
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ZkGeometry {
    pub witness_polynomial_degree: usize,
    /// Degree before division by the packing-domain vanishing polynomial.
    pub raw_constraint_polynomial_degree: usize,
    pub nonlinear_mask_degree: usize,
    pub linear_mask_degree: usize,
    pub witness_width: usize,
    pub nonlinear_width: usize,
    pub linear_width: usize,
    pub witness_delta: usize,
    pub nonlinear_delta: usize,
    pub linear_delta: usize,
    pub polynomial_count: usize,
    pub unstacked_rows: usize,
    pub unstacked_cols: usize,
    pub lvcs_rows: usize,
    pub lvcs_cols: usize,
    pub opened_combinations: usize,
    pub partial_values_per_opening: usize,
    pub lvcs_interpolation_points: usize,
    pub decs_polynomial_degree: usize,
    pub decs_auth_path_depth: usize,
    pub disjoint_coset_shift: u64,
}

impl Hx512ZkGeometry {
    pub fn derive(profile: &Hx512ZkProfile) -> Result<Self, Hx512ZkCertificateError> {
        profile.validate_q48()?;
        let k = profile.packing_factor;
        let s = profile.piop_openings;
        let witness_polynomial_degree = checked_sub(
            checked_add(k, s, "witness degree sum")?,
            1,
            "witness degree",
        )?;
        let raw_constraint_polynomial_degree = checked_mul(
            profile.constraint_degree,
            witness_polynomial_degree,
            "raw constraint polynomial degree",
        )?;
        let nonlinear_mask_degree =
            checked_sub(raw_constraint_polynomial_degree, k, "nonlinear degree")?;
        let linear_mask_degree = checked_add(
            witness_polynomial_degree,
            checked_sub(k, 1, "packing factor minus one")?,
            "linear degree",
        )?;
        let polynomial_count = checked_add(
            profile.relation_rows,
            checked_mul(2, profile.rho, "mask polynomial count")?,
            "polynomial count",
        )?;

        let (witness_width, witness_delta) =
            polynomial_width_delta(witness_polynomial_degree, k, s)?;
        let (nonlinear_width, nonlinear_delta) =
            polynomial_width_delta(nonlinear_mask_degree, k, s)?;
        let (linear_width, linear_delta) = polynomial_width_delta(linear_mask_degree, k, s)?;

        let unstacked_rows = checked_add(k, s, "unstacked rows")?;
        let unstacked_cols = checked_add(
            checked_mul(
                profile.relation_rows,
                witness_width,
                "witness unstacked columns",
            )?,
            checked_add(
                checked_mul(profile.rho, nonlinear_width, "nonlinear unstacked columns")?,
                checked_mul(profile.rho, linear_width, "linear unstacked columns")?,
                "mask unstacked columns",
            )?,
            "unstacked columns",
        )?;
        let lvcs_rows = checked_mul(unstacked_rows, profile.beta, "LVCS rows")?;
        let lvcs_cols = unstacked_cols.div_ceil(profile.beta);
        let opened_combinations = checked_mul(profile.beta, s, "opened LVCS combinations")?;
        if lvcs_rows <= opened_combinations || unstacked_cols < polynomial_count {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "LVCS/PCS geometry leaves no hidden or partial coordinates",
            ));
        }
        let partial_values_per_opening = checked_sub(
            unstacked_cols,
            polynomial_count,
            "partial values per opening",
        )?;
        let lvcs_interpolation_points = checked_add(
            lvcs_cols,
            profile.decs_openings,
            "LVCS interpolation length",
        )?;
        let decs_polynomial_degree =
            checked_sub(lvcs_interpolation_points, 1, "DECS polynomial degree")?;
        let decs_auth_path_depth = profile.decs_domain_size.ilog2() as usize;
        let disjoint_coset_shift =
            first_disjoint_coset_shift(profile.decs_domain_size, lvcs_interpolation_points)?;

        Ok(Self {
            witness_polynomial_degree,
            raw_constraint_polynomial_degree,
            nonlinear_mask_degree,
            linear_mask_degree,
            witness_width,
            nonlinear_width,
            linear_width,
            witness_delta,
            nonlinear_delta,
            linear_delta,
            polynomial_count,
            unstacked_rows,
            unstacked_cols,
            lvcs_rows,
            lvcs_cols,
            opened_combinations,
            partial_values_per_opening,
            lvcs_interpolation_points,
            decs_polynomial_degree,
            decs_auth_path_depth,
            disjoint_coset_shift,
        })
    }
}

/// Exact integer certificate for the CMS19 epsilon-3 term after the explicit
/// `12 * Q^2` QROM/composition charge used by the fresh profile.  Byte strings
/// are canonical unsigned big-endian encodings; the Boolean verdict is
/// computed by an exact integer comparison, never floating point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512CmsQromEnvelopeReport {
    pub piop_openings: usize,
    pub qrom_query_bound_log2: u32,
    pub cms_loss_factor: u32,
    pub target_security_bits: u32,
    pub epsilon3_numerator_be: Vec<u8>,
    pub epsilon3_denominator_be: Vec<u8>,
    pub target_scaled_numerator_be: Vec<u8>,
    pub strict_more_than_target_bits: bool,
}

/// Evaluate
///
/// `12 * (2^64)^2 * falling(d_Q + K, s) / falling(|F| - K, s) < 2^-128`
///
/// using exact integers.  Here `raw_constraint_polynomial_degree` is the
/// engine's `d_Q + K`, namely the degree before division by the packing-domain
/// vanishing polynomial.  This helper intentionally accepts arbitrary `s` so
/// tests can retain the disqualifying s=5 counterexample even though the fresh
/// profile parser only admits s=6.
pub fn exact_cms19_qrom_epsilon3_envelope(
    raw_constraint_polynomial_degree: usize,
    packing_factor: usize,
    piop_openings: usize,
) -> Result<Hx512CmsQromEnvelopeReport, Hx512ZkCertificateError> {
    if piop_openings == 0 {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "CMS epsilon-3 opening count must be nonzero",
        ));
    }
    let opening_domain_size = (HX512_GOLDILOCKS_MODULUS as u128)
        .checked_sub(packing_factor as u128)
        .ok_or(Hx512ZkCertificateError::ArithmeticOverflow(
            "CMS opening-domain size",
        ))?;
    let numerator = falling_product_exact(raw_constraint_polynomial_degree as u128, piop_openings)?;
    let denominator = falling_product_exact(opening_domain_size, piop_openings)?;
    let target_shift = HX512_CMS_QROM_QUERY_BOUND_LOG2
        .checked_mul(2)
        .and_then(|bits| bits.checked_add(HX512_COMPOSED_SECURITY_TARGET_BITS))
        .ok_or(Hx512ZkCertificateError::ArithmeticOverflow(
            "CMS QROM target exponent",
        ))?;
    let target_scaled_numerator =
        (&numerator * BigUint::from(HX512_CMS_QROM_LOSS_FACTOR)) << target_shift;
    let strict_more_than_target_bits = target_scaled_numerator < denominator;
    Ok(Hx512CmsQromEnvelopeReport {
        piop_openings,
        qrom_query_bound_log2: HX512_CMS_QROM_QUERY_BOUND_LOG2,
        cms_loss_factor: HX512_CMS_QROM_LOSS_FACTOR,
        target_security_bits: HX512_COMPOSED_SECURITY_TARGET_BITS,
        epsilon3_numerator_be: numerator.to_bytes_be(),
        epsilon3_denominator_be: denominator.to_bytes_be(),
        target_scaled_numerator_be: target_scaled_numerator.to_bytes_be(),
        strict_more_than_target_bits,
    })
}

fn falling_product_exact(base: u128, count: usize) -> Result<BigUint, Hx512ZkCertificateError> {
    if base < count as u128 {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "falling-product base is smaller than its count",
        ));
    }
    Ok((0..count).fold(BigUint::from(1u8), |product, index| {
        product * BigUint::from(base - index as u128)
    }))
}

fn checked_add(
    left: usize,
    right: usize,
    label: &'static str,
) -> Result<usize, Hx512ZkCertificateError> {
    left.checked_add(right)
        .ok_or(Hx512ZkCertificateError::ArithmeticOverflow(label))
}

fn checked_mul(
    left: usize,
    right: usize,
    label: &'static str,
) -> Result<usize, Hx512ZkCertificateError> {
    left.checked_mul(right)
        .ok_or(Hx512ZkCertificateError::ArithmeticOverflow(label))
}

fn checked_sub(
    left: usize,
    right: usize,
    label: &'static str,
) -> Result<usize, Hx512ZkCertificateError> {
    left.checked_sub(right)
        .ok_or(Hx512ZkCertificateError::ArithmeticOverflow(label))
}

fn polynomial_width_delta(
    degree: usize,
    packing_factor: usize,
    openings: usize,
) -> Result<(usize, usize), Hx512ZkCertificateError> {
    let numerator = checked_sub(
        checked_add(degree, 1, "polynomial coefficient count")?,
        openings,
        "polynomial width numerator",
    )?;
    let width = numerator.div_ceil(packing_factor);
    if width == 0 {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "polynomial width is zero",
        ));
    }
    let delta = checked_sub(
        checked_add(
            checked_mul(packing_factor, width, "polynomial padded width")?,
            openings,
            "polynomial padded width with openings",
        )?,
        checked_add(degree, 1, "polynomial coefficient count")?,
        "polynomial delta",
    )?;
    if width == 1 && delta != 0 {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "single-width polynomial has nonzero delta",
        ));
    }
    Ok((width, delta))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Hx512VerifierViewField {
    ProfileAndIdentity = 0,
    PublicStatement = 1,
    VerifierContext = 2,
    CanonicalHeader = 3,
    Salt = 4,
    PiopNonce = 5,
    HPiop = 6,
    PiopPpolHighs = 7,
    PiopPlinHighs = 8,
    PcsRcombiTails = 9,
    LvcsSubsetEvaluations = 10,
    PcsPartialEvaluations = 11,
    DecsAuthPathCount = 12,
    DecsAuthPathLengths = 13,
    DecsAuthPathNodes = 14,
    DecsLeafTapes = 15,
    DecsMaskingEvaluations = 16,
    DecsHighCoefficients = 17,
    OpenedWitnessMode = 18,
    OpenedWitnessRowScalars = 19,
    AuxiliaryLimbCount = 20,
    AuxiliaryWords = 21,
    ExactEndOfInput = 22,
    PiopOpeningPoints = 23,
    PcsCombinationCoefficients = 24,
    PcsCombinationHeads = 25,
    DecsOpeningIndexes = 26,
    DecsCosetPoints = 27,
    LvcsOmittedRows = 28,
    DecsFullPolynomials = 29,
    MerkleRoot = 30,
    TranscriptEvents = 31,
    RetryAbortOutcome = 32,
}

pub const HX512_ALL_VERIFIER_VIEW_FIELDS: [Hx512VerifierViewField; 33] = [
    Hx512VerifierViewField::ProfileAndIdentity,
    Hx512VerifierViewField::PublicStatement,
    Hx512VerifierViewField::VerifierContext,
    Hx512VerifierViewField::CanonicalHeader,
    Hx512VerifierViewField::Salt,
    Hx512VerifierViewField::PiopNonce,
    Hx512VerifierViewField::HPiop,
    Hx512VerifierViewField::PiopPpolHighs,
    Hx512VerifierViewField::PiopPlinHighs,
    Hx512VerifierViewField::PcsRcombiTails,
    Hx512VerifierViewField::LvcsSubsetEvaluations,
    Hx512VerifierViewField::PcsPartialEvaluations,
    Hx512VerifierViewField::DecsAuthPathCount,
    Hx512VerifierViewField::DecsAuthPathLengths,
    Hx512VerifierViewField::DecsAuthPathNodes,
    Hx512VerifierViewField::DecsLeafTapes,
    Hx512VerifierViewField::DecsMaskingEvaluations,
    Hx512VerifierViewField::DecsHighCoefficients,
    Hx512VerifierViewField::OpenedWitnessMode,
    Hx512VerifierViewField::OpenedWitnessRowScalars,
    Hx512VerifierViewField::AuxiliaryLimbCount,
    Hx512VerifierViewField::AuxiliaryWords,
    Hx512VerifierViewField::ExactEndOfInput,
    Hx512VerifierViewField::PiopOpeningPoints,
    Hx512VerifierViewField::PcsCombinationCoefficients,
    Hx512VerifierViewField::PcsCombinationHeads,
    Hx512VerifierViewField::DecsOpeningIndexes,
    Hx512VerifierViewField::DecsCosetPoints,
    Hx512VerifierViewField::LvcsOmittedRows,
    Hx512VerifierViewField::DecsFullPolynomials,
    Hx512VerifierViewField::MerkleRoot,
    Hx512VerifierViewField::TranscriptEvents,
    Hx512VerifierViewField::RetryAbortOutcome,
];

impl Hx512VerifierViewField {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::ProfileAndIdentity => b"profile-and-identity",
            Self::PublicStatement => b"public-statement",
            Self::VerifierContext => b"verifier-context",
            Self::CanonicalHeader => b"canonical-header",
            Self::Salt => b"salt",
            Self::PiopNonce => b"piop-nonce",
            Self::HPiop => b"h-piop",
            Self::PiopPpolHighs => b"piop-ppol-highs",
            Self::PiopPlinHighs => b"piop-plin-highs",
            Self::PcsRcombiTails => b"pcs-rcombi-tails",
            Self::LvcsSubsetEvaluations => b"lvcs-subset-evaluations",
            Self::PcsPartialEvaluations => b"pcs-partial-evaluations",
            Self::DecsAuthPathCount => b"decs-auth-path-count",
            Self::DecsAuthPathLengths => b"decs-auth-path-lengths",
            Self::DecsAuthPathNodes => b"decs-auth-path-nodes",
            Self::DecsLeafTapes => b"decs-leaf-tapes",
            Self::DecsMaskingEvaluations => b"decs-masking-evaluations",
            Self::DecsHighCoefficients => b"decs-high-coefficients",
            Self::OpenedWitnessMode => b"opened-witness-mode",
            Self::OpenedWitnessRowScalars => b"opened-witness-row-scalars",
            Self::AuxiliaryLimbCount => b"auxiliary-limb-count",
            Self::AuxiliaryWords => b"auxiliary-words",
            Self::ExactEndOfInput => b"exact-end-of-input",
            Self::PiopOpeningPoints => b"piop-opening-points",
            Self::PcsCombinationCoefficients => b"pcs-combination-coefficients",
            Self::PcsCombinationHeads => b"pcs-combination-heads",
            Self::DecsOpeningIndexes => b"decs-opening-indexes",
            Self::DecsCosetPoints => b"decs-coset-points",
            Self::LvcsOmittedRows => b"lvcs-omitted-rows",
            Self::DecsFullPolynomials => b"decs-full-polynomials",
            Self::MerkleRoot => b"merkle-root",
            Self::TranscriptEvents => b"transcript-events",
            Self::RetryAbortOutcome => b"retry-abort-outcome",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512ViewSurface {
    ExternalPublic,
    Serialized,
    DerivedVerifierState,
    ParserInvariant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512SimulatorSource {
    PublicInput,
    FrozenProfileConstant,
    UniformBytes,
    UniformGoldilocks,
    WitnessOpeningBijection,
    PiopMaskBijection,
    PcsEquation6Randomizers,
    LvcsTailCauchyBijection,
    OmittedRowVandermondeSolve,
    DecsMaskBijection,
    ClassicalRomProgrammingCandidate,
    DeterministicTranscriptDerivation,
    CanonicalEmpty,
    UnresolvedJointCorrelation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512RefinementState {
    ExecutableLocal,
    ConditionalClassicalRom,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ZkLedgerEntry {
    pub field: Hx512VerifierViewField,
    pub surface: Hx512ViewSurface,
    pub field_elements: Option<usize>,
    pub encoded_bytes: Option<usize>,
    pub maximum_encoded_bytes: Option<usize>,
    pub simulator_source: Hx512SimulatorSource,
    pub refinement_state: Hx512RefinementState,
    pub real_view_may_depend_on_witness: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hx512RankObligation {
    WitnessRandomHighs,
    PiopNonlinearMask,
    PiopLinearZeroSumMask,
    PcsEquation6Randomizers,
    LvcsRandomTails,
    LvcsOmittedRows,
    DecsMasksAndHighs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ComponentRankReport {
    pub obligation: Hx512RankObligation,
    pub scalar_rows: usize,
    pub scalar_columns: usize,
    pub rank: usize,
    pub core_matrix_rows: usize,
    pub core_matrix_columns: usize,
    pub core_matrix_rank: usize,
    pub block_count: usize,
    pub exact_full_rank: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hx512ZkBlocker {
    SuccessorIdentityUnallocated,
    EngineSourceUnpinned,
    TranscriptSourceUnpinned,
    RelationShapeUnpinned,
    AdapterTopologyUnpinned,
    HashScheduleUnpinned,
    WireGrammarDigestUnpinned,
    StatementGrammarUnpinned,
    ContextGrammarUnpinned,
    DomainRegistryUnpinned,
    ProfileDigestUnpinned,
    ConsensusRulesUnpinned,
    WireGrammarUnfrozen,
    SamplerGrammarUnfrozen,
    SaltTapeRngIndependenceUnproved,
    SimulatorEntropyFreshnessUnproved,
    TranscriptPointRankUniversalityUnproved,
    WholeViewDistributionEqualityUnproved,
    PiopPcsJointCorrelationUnproved,
    LvcsDecsJointConditioningUnproved,
    ClassicalRomMerkleProgrammingUnproved,
    RetryAbortDistributionUnproved,
    FiatShamirAdaptiveSimulationUnproved,
    GhcmAdaptiveEventAccountingUnproved,
    QromLiftUnproved,
    ConcreteSha512ShakeBridgeUnproved,
    Cms19PremiseRefinementUnproved,
    Bcs16RbrPremiseRefinementUnproved,
    CanonicalParserSerializerRefinementUnproved,
    CompiledProverRefinementUnproved,
    CompiledVerifierRefinementUnproved,
    ProductionLifecycleBindingUnproved,
    MeasuredProofArtifactMissing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512ZkCapabilities {
    pub local_component_rank_certificate: bool,
    pub witness_free_classical_rom_candidate: bool,
    pub classical_rom_joint_simulator_proved: bool,
    pub adaptive_qrom_lift_proved: bool,
    pub complete_zero_knowledge: bool,
    pub compiled_refinement: bool,
    pub production_authorized: bool,
}

impl Hx512ZkCapabilities {
    fn fail_closed(local_ranks: bool, candidate: bool) -> Self {
        Self {
            local_component_rank_certificate: local_ranks,
            witness_free_classical_rom_candidate: candidate,
            classical_rom_joint_simulator_proved: false,
            adaptive_qrom_lift_proved: false,
            complete_zero_knowledge: false,
            compiled_refinement: false,
            production_authorized: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512PremiseStatus {
    ExecutableLocalCheck,
    PinnedPremiseOnly,
    UnprovedComposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512TheoremPremise {
    pub identifier: &'static str,
    pub requirement: &'static str,
    pub status: Hx512PremiseStatus,
}

pub const HX512_THEOREM_PREMISES: [Hx512TheoremPremise; 11] = [
    Hx512TheoremPremise {
        identifier: "CMS19-Theorem-8.6(3)-SmallWood-specialization",
        requirement: "s independent witness highs, universal full-rank off-domain opening map, and exact SmallWood specialization",
        status: Hx512PremiseStatus::PinnedPremiseOnly,
    },
    Hx512TheoremPremise {
        identifier: "CMS19-epsilon3-composed-QROM-integer-envelope",
        requirement: "12 * 2^256 * falling(d_Q + K, s) < falling(|F| - K, s)",
        status: Hx512PremiseStatus::ExecutableLocalCheck,
    },
    Hx512TheoremPremise {
        identifier: "SmallWood-PIOP-nonlinear-mask",
        requirement: "uniform degree-D mask represented by s evaluations and D+1-s highs",
        status: Hx512PremiseStatus::ExecutableLocalCheck,
    },
    Hx512TheoremPremise {
        identifier: "SmallWood-PIOP-linear-zero-sum-mask",
        requirement: "uniform packing-sum kernel mask and nonzero correction map",
        status: Hx512PremiseStatus::ExecutableLocalCheck,
    },
    Hx512TheoremPremise {
        identifier: "SmallWood-PCS-Equation-6",
        requirement: "independent width-minus-one partial randomizers for every opened polynomial",
        status: Hx512PremiseStatus::ExecutableLocalCheck,
    },
    Hx512TheoremPremise {
        identifier: "SmallWood-LVCS-random-tail-hiding",
        requirement: "q random tails, q distinct disjoint-coset openings, full-rank Cauchy action",
        status: Hx512PremiseStatus::ExecutableLocalCheck,
    },
    Hx512TheoremPremise {
        identifier: "SmallWood-DECS-classical-ROM-simulator",
        requirement: "independent tapes, masks, programmed leaves, paths, and unopened-oracle consistency",
        status: Hx512PremiseStatus::PinnedPremiseOnly,
    },
    Hx512TheoremPremise {
        identifier: "BCS16-RBR-interactive-to-Fiat-Shamir-boundary",
        requirement: "exact interactive transcript, extraction, challenge, and random-oracle premises",
        status: Hx512PremiseStatus::UnprovedComposition,
    },
    Hx512TheoremPremise {
        identifier: "GHCM-adaptive-transcript-events",
        requirement: "adaptive event multiplicities, conditioning, and oracle-query accounting",
        status: Hx512PremiseStatus::UnprovedComposition,
    },
    Hx512TheoremPremise {
        identifier: "classical-ROM-whole-view-distribution",
        requirement: "one simulator matches all serialized fields and abort/retry behavior jointly",
        status: Hx512PremiseStatus::UnprovedComposition,
    },
    Hx512TheoremPremise {
        identifier: "adaptive-QROM-lift-and-concrete-hash-bridge",
        requirement: "measure/reprogram loss plus deployed SHA-512/SHAKE QROM instantiation",
        status: Hx512PremiseStatus::UnprovedComposition,
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ZkAuditReport {
    pub profile: Hx512ZkProfile,
    pub geometry: Hx512ZkGeometry,
    pub cms_qrom_envelope: Hx512CmsQromEnvelopeReport,
    pub ledger: Vec<Hx512ZkLedgerEntry>,
    pub coverage_sha512: [u8; 64],
    pub rank_reports: Vec<Hx512ComponentRankReport>,
    pub blockers: BTreeSet<Hx512ZkBlocker>,
    pub capabilities: Hx512ZkCapabilities,
    pub projected_serialized_bytes: Option<usize>,
    pub measured_proof_bytes: Option<usize>,
}

pub fn audit_hx512_q48_zk_candidate(
    profile: &Hx512ZkProfile,
    identity: &Hx512ZkIdentityPins,
    wire: &Hx512WireGrammar,
) -> Result<Hx512ZkAuditReport, Hx512ZkCertificateError> {
    profile.validate_q48()?;
    wire.validate()?;
    let geometry = Hx512ZkGeometry::derive(profile)?;
    let cms_qrom_envelope = exact_cms19_qrom_epsilon3_envelope(
        geometry.raw_constraint_polynomial_degree,
        profile.packing_factor,
        profile.piop_openings,
    )?;
    if !cms_qrom_envelope.strict_more_than_target_bits {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "CMS epsilon-3 misses the strict composed 128-bit QROM envelope",
        ));
    }
    let opening_points = representative_piop_opening_points(profile)?;
    let decs_indexes = representative_decs_indexes(profile);
    let rank_reports = component_rank_reports(profile, &geometry, &opening_points, &decs_indexes)?;
    let local_ranks = rank_reports.iter().all(|report| report.exact_full_rank);
    if !local_ranks {
        return Err(Hx512ZkCertificateError::SingularMatrix(
            "one or more local simulator maps",
        ));
    }
    let ledger = build_view_ledger(profile, &geometry, wire)?;
    validate_view_ledger(&ledger)?;
    let coverage_sha512 = view_coverage_sha512(&ledger);
    let blockers = retained_blockers(profile, identity, wire);
    let projected_serialized_bytes = if wire.is_frozen() {
        let lengths = compact_merkle_auth_path_lengths(
            &decs_indexes
                .iter()
                .map(|index| *index as usize)
                .collect::<Vec<_>>(),
            geometry.decs_auth_path_depth,
        )?;
        Some(projected_wire_bytes(profile, &geometry, wire, &lengths)?)
    } else {
        None
    };
    Ok(Hx512ZkAuditReport {
        profile: profile.clone(),
        geometry,
        cms_qrom_envelope,
        ledger,
        coverage_sha512,
        rank_reports,
        blockers,
        capabilities: Hx512ZkCapabilities::fail_closed(true, true),
        projected_serialized_bytes,
        measured_proof_bytes: None,
    })
}

fn retained_blockers(
    profile: &Hx512ZkProfile,
    identity: &Hx512ZkIdentityPins,
    wire: &Hx512WireGrammar,
) -> BTreeSet<Hx512ZkBlocker> {
    let mut blockers = BTreeSet::from([
        Hx512ZkBlocker::WholeViewDistributionEqualityUnproved,
        Hx512ZkBlocker::PiopPcsJointCorrelationUnproved,
        Hx512ZkBlocker::LvcsDecsJointConditioningUnproved,
        Hx512ZkBlocker::ClassicalRomMerkleProgrammingUnproved,
        Hx512ZkBlocker::RetryAbortDistributionUnproved,
        Hx512ZkBlocker::FiatShamirAdaptiveSimulationUnproved,
        Hx512ZkBlocker::GhcmAdaptiveEventAccountingUnproved,
        Hx512ZkBlocker::QromLiftUnproved,
        Hx512ZkBlocker::ConcreteSha512ShakeBridgeUnproved,
        Hx512ZkBlocker::Cms19PremiseRefinementUnproved,
        Hx512ZkBlocker::Bcs16RbrPremiseRefinementUnproved,
        Hx512ZkBlocker::CanonicalParserSerializerRefinementUnproved,
        Hx512ZkBlocker::CompiledProverRefinementUnproved,
        Hx512ZkBlocker::CompiledVerifierRefinementUnproved,
        Hx512ZkBlocker::ProductionLifecycleBindingUnproved,
        Hx512ZkBlocker::MeasuredProofArtifactMissing,
        Hx512ZkBlocker::SaltTapeRngIndependenceUnproved,
        Hx512ZkBlocker::SimulatorEntropyFreshnessUnproved,
        Hx512ZkBlocker::TranscriptPointRankUniversalityUnproved,
    ]);
    if !identity.allocated {
        blockers.insert(Hx512ZkBlocker::SuccessorIdentityUnallocated);
    }
    let pins = identity.pin_slices();
    let pin_blockers = [
        Hx512ZkBlocker::EngineSourceUnpinned,
        Hx512ZkBlocker::TranscriptSourceUnpinned,
        Hx512ZkBlocker::RelationShapeUnpinned,
        Hx512ZkBlocker::AdapterTopologyUnpinned,
        Hx512ZkBlocker::HashScheduleUnpinned,
        Hx512ZkBlocker::WireGrammarDigestUnpinned,
        Hx512ZkBlocker::StatementGrammarUnpinned,
        Hx512ZkBlocker::ContextGrammarUnpinned,
        Hx512ZkBlocker::DomainRegistryUnpinned,
        Hx512ZkBlocker::ProfileDigestUnpinned,
        Hx512ZkBlocker::ConsensusRulesUnpinned,
    ];
    for (digest, blocker) in pins.iter().zip(pin_blockers) {
        if digest.iter().all(|byte| *byte == 0) {
            blockers.insert(blocker);
        }
    }
    if !wire.is_frozen() {
        blockers.insert(Hx512ZkBlocker::WireGrammarUnfrozen);
    }
    if profile.max_piop_trials.is_none() || profile.decs_sampler_candidates.is_none() {
        blockers.insert(Hx512ZkBlocker::SamplerGrammarUnfrozen);
    }
    blockers
}

fn build_view_ledger(
    profile: &Hx512ZkProfile,
    geometry: &Hx512ZkGeometry,
    wire: &Hx512WireGrammar,
) -> Result<Vec<Hx512ZkLedgerEntry>, Hx512ZkCertificateError> {
    let matrix_bytes = |elements: usize| -> Result<usize, Hx512ZkCertificateError> {
        checked_add(
            wire.matrix_dimension_bytes,
            checked_mul(elements, 8, "matrix field bytes")?,
            "matrix wire bytes",
        )
    };
    let ppol_elements = checked_mul(
        profile.rho,
        checked_sub(
            checked_add(geometry.nonlinear_mask_degree, 1, "nonlinear coefficients")?,
            profile.piop_openings,
            "nonlinear high count",
        )?,
        "nonlinear high elements",
    )?;
    let plin_elements = checked_mul(
        profile.rho,
        checked_sub(
            geometry.linear_mask_degree,
            profile.piop_openings,
            "linear high count",
        )?,
        "linear high elements",
    )?;
    let rcombi_elements = checked_mul(
        geometry.opened_combinations,
        profile.decs_openings,
        "rcombi tail elements",
    )?;
    let subset_elements = checked_mul(
        profile.decs_openings,
        checked_sub(
            geometry.lvcs_rows,
            geometry.opened_combinations,
            "subset row width",
        )?,
        "subset elements",
    )?;
    let partial_elements = checked_mul(
        profile.piop_openings,
        geometry.partial_values_per_opening,
        "partial elements",
    )?;
    let masking_elements = checked_mul(
        profile.decs_openings,
        profile.decs_eta,
        "DECS masking elements",
    )?;
    let high_elements = checked_mul(profile.decs_eta, geometry.lvcs_cols, "DECS high elements")?;
    let opened_witness_elements = checked_mul(
        profile.piop_openings,
        geometry.polynomial_count,
        "opened witness elements",
    )?;
    let max_auth_nodes = checked_mul(
        profile.decs_openings,
        geometry.decs_auth_path_depth,
        "maximum auth nodes",
    )?;

    let entry = |field,
                 surface,
                 field_elements,
                 encoded_bytes,
                 maximum_encoded_bytes,
                 simulator_source,
                 refinement_state,
                 real_view_may_depend_on_witness| Hx512ZkLedgerEntry {
        field,
        surface,
        field_elements,
        encoded_bytes,
        maximum_encoded_bytes,
        simulator_source,
        refinement_state,
        real_view_may_depend_on_witness,
    };

    Ok(vec![
        entry(
            Hx512VerifierViewField::ProfileAndIdentity,
            Hx512ViewSurface::ExternalPublic,
            None,
            None,
            None,
            Hx512SimulatorSource::FrozenProfileConstant,
            Hx512RefinementState::Blocked,
            false,
        ),
        entry(
            Hx512VerifierViewField::PublicStatement,
            Hx512ViewSurface::ExternalPublic,
            None,
            Some(profile.statement_bytes),
            Some(profile.statement_bytes),
            Hx512SimulatorSource::PublicInput,
            Hx512RefinementState::ExecutableLocal,
            false,
        ),
        entry(
            Hx512VerifierViewField::VerifierContext,
            Hx512ViewSurface::ExternalPublic,
            None,
            Some(profile.verifier_context_bytes),
            Some(profile.verifier_context_bytes),
            Hx512SimulatorSource::PublicInput,
            Hx512RefinementState::ExecutableLocal,
            false,
        ),
        entry(
            Hx512VerifierViewField::CanonicalHeader,
            Hx512ViewSurface::Serialized,
            None,
            wire.prefix_bytes_before_salt,
            wire.prefix_bytes_before_salt,
            Hx512SimulatorSource::FrozenProfileConstant,
            Hx512RefinementState::Blocked,
            false,
        ),
        entry(
            Hx512VerifierViewField::Salt,
            Hx512ViewSurface::Serialized,
            None,
            Some(profile.salt_bytes),
            Some(profile.salt_bytes),
            Hx512SimulatorSource::UniformBytes,
            Hx512RefinementState::ConditionalClassicalRom,
            false,
        ),
        entry(
            Hx512VerifierViewField::PiopNonce,
            Hx512ViewSurface::Serialized,
            None,
            Some(profile.nonce_bytes),
            Some(profile.nonce_bytes),
            Hx512SimulatorSource::DeterministicTranscriptDerivation,
            Hx512RefinementState::Blocked,
            false,
        ),
        entry(
            Hx512VerifierViewField::HPiop,
            Hx512ViewSurface::Serialized,
            None,
            Some(profile.digest_bytes),
            Some(profile.digest_bytes),
            Hx512SimulatorSource::ClassicalRomProgrammingCandidate,
            Hx512RefinementState::ConditionalClassicalRom,
            true,
        ),
        entry(
            Hx512VerifierViewField::PiopPpolHighs,
            Hx512ViewSurface::Serialized,
            Some(ppol_elements),
            Some(matrix_bytes(ppol_elements)?),
            Some(matrix_bytes(ppol_elements)?),
            Hx512SimulatorSource::PiopMaskBijection,
            Hx512RefinementState::ExecutableLocal,
            true,
        ),
        entry(
            Hx512VerifierViewField::PiopPlinHighs,
            Hx512ViewSurface::Serialized,
            Some(plin_elements),
            Some(matrix_bytes(plin_elements)?),
            Some(matrix_bytes(plin_elements)?),
            Hx512SimulatorSource::PiopMaskBijection,
            Hx512RefinementState::ExecutableLocal,
            true,
        ),
        entry(
            Hx512VerifierViewField::PcsRcombiTails,
            Hx512ViewSurface::Serialized,
            Some(rcombi_elements),
            Some(matrix_bytes(rcombi_elements)?),
            Some(matrix_bytes(rcombi_elements)?),
            Hx512SimulatorSource::LvcsTailCauchyBijection,
            Hx512RefinementState::ConditionalClassicalRom,
            true,
        ),
        entry(
            Hx512VerifierViewField::LvcsSubsetEvaluations,
            Hx512ViewSurface::Serialized,
            Some(subset_elements),
            Some(matrix_bytes(subset_elements)?),
            Some(matrix_bytes(subset_elements)?),
            Hx512SimulatorSource::LvcsTailCauchyBijection,
            Hx512RefinementState::ExecutableLocal,
            true,
        ),
        entry(
            Hx512VerifierViewField::PcsPartialEvaluations,
            Hx512ViewSurface::Serialized,
            Some(partial_elements),
            Some(matrix_bytes(partial_elements)?),
            Some(matrix_bytes(partial_elements)?),
            Hx512SimulatorSource::PcsEquation6Randomizers,
            Hx512RefinementState::ExecutableLocal,
            true,
        ),
        entry(
            Hx512VerifierViewField::DecsAuthPathCount,
            Hx512ViewSurface::Serialized,
            None,
            Some(wire.auth_path_count_bytes),
            Some(wire.auth_path_count_bytes),
            Hx512SimulatorSource::FrozenProfileConstant,
            Hx512RefinementState::Blocked,
            false,
        ),
        entry(
            Hx512VerifierViewField::DecsAuthPathLengths,
            Hx512ViewSurface::Serialized,
            None,
            Some(checked_mul(
                profile.decs_openings,
                wire.auth_path_length_bytes,
                "auth path length bytes",
            )?),
            Some(checked_mul(
                profile.decs_openings,
                wire.auth_path_length_bytes,
                "auth path length bytes",
            )?),
            Hx512SimulatorSource::DeterministicTranscriptDerivation,
            Hx512RefinementState::Blocked,
            false,
        ),
        entry(
            Hx512VerifierViewField::DecsAuthPathNodes,
            Hx512ViewSurface::Serialized,
            None,
            None,
            Some(checked_mul(
                max_auth_nodes,
                profile.digest_bytes,
                "maximum auth node bytes",
            )?),
            Hx512SimulatorSource::ClassicalRomProgrammingCandidate,
            Hx512RefinementState::ConditionalClassicalRom,
            true,
        ),
        entry(
            Hx512VerifierViewField::DecsLeafTapes,
            Hx512ViewSurface::Serialized,
            None,
            Some(checked_mul(
                profile.decs_openings,
                profile.decs_leaf_tape_bytes,
                "opened leaf tape bytes",
            )?),
            Some(checked_mul(
                profile.decs_openings,
                profile.decs_leaf_tape_bytes,
                "opened leaf tape bytes",
            )?),
            Hx512SimulatorSource::UniformBytes,
            Hx512RefinementState::ConditionalClassicalRom,
            false,
        ),
        entry(
            Hx512VerifierViewField::DecsMaskingEvaluations,
            Hx512ViewSurface::Serialized,
            Some(masking_elements),
            Some(matrix_bytes(masking_elements)?),
            Some(matrix_bytes(masking_elements)?),
            Hx512SimulatorSource::DecsMaskBijection,
            Hx512RefinementState::ExecutableLocal,
            true,
        ),
        entry(
            Hx512VerifierViewField::DecsHighCoefficients,
            Hx512ViewSurface::Serialized,
            Some(high_elements),
            Some(matrix_bytes(high_elements)?),
            Some(matrix_bytes(high_elements)?),
            Hx512SimulatorSource::DecsMaskBijection,
            Hx512RefinementState::ExecutableLocal,
            true,
        ),
        entry(
            Hx512VerifierViewField::OpenedWitnessMode,
            Hx512ViewSurface::Serialized,
            None,
            Some(wire.opened_witness_tag_bytes),
            Some(wire.opened_witness_tag_bytes),
            Hx512SimulatorSource::FrozenProfileConstant,
            Hx512RefinementState::Blocked,
            false,
        ),
        entry(
            Hx512VerifierViewField::OpenedWitnessRowScalars,
            Hx512ViewSurface::Serialized,
            Some(opened_witness_elements),
            Some(matrix_bytes(opened_witness_elements)?),
            Some(matrix_bytes(opened_witness_elements)?),
            Hx512SimulatorSource::WitnessOpeningBijection,
            Hx512RefinementState::ExecutableLocal,
            true,
        ),
        entry(
            Hx512VerifierViewField::AuxiliaryLimbCount,
            Hx512ViewSurface::Serialized,
            None,
            Some(wire.auxiliary_count_bytes),
            Some(wire.auxiliary_count_bytes),
            Hx512SimulatorSource::CanonicalEmpty,
            Hx512RefinementState::ExecutableLocal,
            false,
        ),
        entry(
            Hx512VerifierViewField::AuxiliaryWords,
            Hx512ViewSurface::Serialized,
            Some(0),
            Some(0),
            Some(0),
            Hx512SimulatorSource::CanonicalEmpty,
            Hx512RefinementState::ExecutableLocal,
            false,
        ),
        entry(
            Hx512VerifierViewField::ExactEndOfInput,
            Hx512ViewSurface::ParserInvariant,
            None,
            Some(0),
            Some(0),
            Hx512SimulatorSource::CanonicalEmpty,
            Hx512RefinementState::Blocked,
            false,
        ),
        entry(
            Hx512VerifierViewField::PiopOpeningPoints,
            Hx512ViewSurface::DerivedVerifierState,
            Some(profile.piop_openings),
            None,
            None,
            Hx512SimulatorSource::DeterministicTranscriptDerivation,
            Hx512RefinementState::Blocked,
            false,
        ),
        entry(
            Hx512VerifierViewField::PcsCombinationCoefficients,
            Hx512ViewSurface::DerivedVerifierState,
            Some(checked_mul(
                geometry.opened_combinations,
                geometry.lvcs_rows,
                "PCS coefficient elements",
            )?),
            None,
            None,
            Hx512SimulatorSource::DeterministicTranscriptDerivation,
            Hx512RefinementState::ExecutableLocal,
            false,
        ),
        entry(
            Hx512VerifierViewField::PcsCombinationHeads,
            Hx512ViewSurface::DerivedVerifierState,
            Some(checked_mul(
                geometry.opened_combinations,
                geometry.lvcs_cols,
                "PCS combination head elements",
            )?),
            None,
            None,
            Hx512SimulatorSource::PcsEquation6Randomizers,
            Hx512RefinementState::ConditionalClassicalRom,
            true,
        ),
        entry(
            Hx512VerifierViewField::DecsOpeningIndexes,
            Hx512ViewSurface::DerivedVerifierState,
            None,
            None,
            None,
            Hx512SimulatorSource::DeterministicTranscriptDerivation,
            Hx512RefinementState::Blocked,
            false,
        ),
        entry(
            Hx512VerifierViewField::DecsCosetPoints,
            Hx512ViewSurface::DerivedVerifierState,
            Some(profile.decs_openings),
            None,
            None,
            Hx512SimulatorSource::DeterministicTranscriptDerivation,
            Hx512RefinementState::ExecutableLocal,
            false,
        ),
        entry(
            Hx512VerifierViewField::LvcsOmittedRows,
            Hx512ViewSurface::DerivedVerifierState,
            Some(checked_mul(
                profile.decs_openings,
                geometry.opened_combinations,
                "omitted row elements",
            )?),
            None,
            None,
            Hx512SimulatorSource::OmittedRowVandermondeSolve,
            Hx512RefinementState::ExecutableLocal,
            true,
        ),
        entry(
            Hx512VerifierViewField::DecsFullPolynomials,
            Hx512ViewSurface::DerivedVerifierState,
            Some(checked_mul(
                profile.decs_eta,
                geometry.lvcs_interpolation_points,
                "full DECS polynomial elements",
            )?),
            None,
            None,
            Hx512SimulatorSource::DecsMaskBijection,
            Hx512RefinementState::ExecutableLocal,
            true,
        ),
        entry(
            Hx512VerifierViewField::MerkleRoot,
            Hx512ViewSurface::DerivedVerifierState,
            None,
            None,
            None,
            Hx512SimulatorSource::ClassicalRomProgrammingCandidate,
            Hx512RefinementState::ConditionalClassicalRom,
            true,
        ),
        entry(
            Hx512VerifierViewField::TranscriptEvents,
            Hx512ViewSurface::DerivedVerifierState,
            None,
            None,
            None,
            Hx512SimulatorSource::UnresolvedJointCorrelation,
            Hx512RefinementState::Blocked,
            true,
        ),
        entry(
            Hx512VerifierViewField::RetryAbortOutcome,
            Hx512ViewSurface::DerivedVerifierState,
            None,
            None,
            None,
            Hx512SimulatorSource::UnresolvedJointCorrelation,
            Hx512RefinementState::Blocked,
            true,
        ),
    ])
}

pub fn validate_view_ledger(ledger: &[Hx512ZkLedgerEntry]) -> Result<(), Hx512ZkCertificateError> {
    if ledger.len() != HX512_ALL_VERIFIER_VIEW_FIELDS.len() {
        return Err(Hx512ZkCertificateError::InvalidViewLedger(
            "wrong field count",
        ));
    }
    let seen = ledger
        .iter()
        .map(|entry| entry.field)
        .collect::<BTreeSet<_>>();
    let expected = HX512_ALL_VERIFIER_VIEW_FIELDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if seen != expected {
        return Err(Hx512ZkCertificateError::InvalidViewLedger(
            "missing, duplicate, or unknown field",
        ));
    }
    for (entry, expected_field) in ledger.iter().zip(HX512_ALL_VERIFIER_VIEW_FIELDS) {
        if entry.field != expected_field {
            return Err(Hx512ZkCertificateError::InvalidViewLedger(
                "canonical field order changed",
            ));
        }
        if entry.surface == Hx512ViewSurface::Serialized
            && entry.encoded_bytes.is_none()
            && entry.maximum_encoded_bytes.is_none()
            && entry.refinement_state != Hx512RefinementState::Blocked
        {
            return Err(Hx512ZkCertificateError::InvalidViewLedger(
                "nonblocked serialized field lacks an exact or bounded byte count",
            ));
        }
        if entry.field == Hx512VerifierViewField::AuxiliaryWords
            && (entry.field_elements != Some(0) || entry.encoded_bytes != Some(0))
        {
            return Err(Hx512ZkCertificateError::InvalidViewLedger(
                "aux_count=0 is not reflected in the wire ledger",
            ));
        }
    }
    Ok(())
}

fn view_coverage_sha512(ledger: &[Hx512ZkLedgerEntry]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(COVERAGE_DOMAIN);
    for entry in ledger {
        hasher.update([entry.field as u8]);
        hasher.update([entry.surface as u8]);
        hasher.update([entry.simulator_source as u8]);
        hasher.update([entry.refinement_state as u8]);
        hash_option_usize(&mut hasher, entry.field_elements);
        hash_option_usize(&mut hasher, entry.encoded_bytes);
        hash_option_usize(&mut hasher, entry.maximum_encoded_bytes);
        hasher.update([u8::from(entry.real_view_may_depend_on_witness)]);
    }
    hasher.finalize().into()
}

fn hash_option_usize(hasher: &mut Sha512, value: Option<usize>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update((value as u128).to_le_bytes());
        }
        None => hasher.update([0]),
    }
}

fn component_rank_reports(
    profile: &Hx512ZkProfile,
    geometry: &Hx512ZkGeometry,
    opening_points: &[u64],
    decs_indexes: &[u32],
) -> Result<Vec<Hx512ComponentRankReport>, Hx512ZkCertificateError> {
    let s = profile.piop_openings;
    if opening_points.len() != s {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "wrong representative PIOP opening count",
        ));
    }
    validate_opening_points(profile.packing_factor, opening_points)?;

    let witness_core = witness_tail_opening_matrix(profile.packing_factor, opening_points)?;
    let witness_rank = matrix_rank(witness_core.clone())?;

    let nonlinear_core = vandermonde(opening_points, s);
    let nonlinear_core_rank = matrix_rank(nonlinear_core)?;
    let nonlinear_total = checked_add(geometry.nonlinear_mask_degree, 1, "nonlinear rank")?;
    let nonlinear_rank = checked_add(
        nonlinear_core_rank,
        checked_sub(nonlinear_total, s, "nonlinear identity rank")?,
        "nonlinear total rank",
    )?;

    let linear_core = linear_zero_sum_low_map(profile.packing_factor, opening_points)?;
    let linear_core_rank = matrix_rank(linear_core)?;
    let linear_total = geometry.linear_mask_degree;
    let linear_rank = checked_add(
        linear_core_rank,
        checked_sub(linear_total, s, "linear identity rank")?,
        "linear total rank",
    )?;

    let pcs_randomizers = checked_mul(
        s,
        geometry.partial_values_per_opening,
        "PCS Eq. (6) randomizers",
    )?;
    validate_pcs_equation6_weights(profile, geometry, opening_points)?;

    let query_points = decs_indexes
        .iter()
        .map(|index| {
            coset_point(
                profile.decs_domain_size,
                geometry.disjoint_coset_shift,
                *index as usize,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let lvcs_core = lvcs_tail_cauchy_matrix(geometry, &query_points)?;
    let lvcs_core_rank = matrix_rank(lvcs_core)?;
    let lvcs_total = checked_mul(
        geometry.lvcs_rows,
        profile.decs_openings,
        "aggregate LVCS tail rank",
    )?;

    let omitted = omitted_row_matrix(profile, opening_points)?;
    let omitted_rank = matrix_rank(omitted.clone())?;

    let decs_core = vandermonde(&query_points, profile.decs_openings);
    let decs_core_rank = matrix_rank(decs_core)?;
    let decs_per_poly = geometry.lvcs_interpolation_points;
    let decs_total = checked_mul(profile.decs_eta, decs_per_poly, "DECS mask rank")?;
    let decs_rank = checked_mul(
        profile.decs_eta,
        checked_add(
            decs_core_rank,
            geometry.lvcs_cols,
            "DECS per-polynomial rank",
        )?,
        "DECS aggregate rank",
    )?;

    Ok(vec![
        Hx512ComponentRankReport {
            obligation: Hx512RankObligation::WitnessRandomHighs,
            scalar_rows: s,
            scalar_columns: s,
            rank: witness_rank,
            core_matrix_rows: s,
            core_matrix_columns: s,
            core_matrix_rank: witness_rank,
            block_count: profile.relation_rows,
            exact_full_rank: witness_rank == s,
        },
        Hx512ComponentRankReport {
            obligation: Hx512RankObligation::PiopNonlinearMask,
            scalar_rows: nonlinear_total,
            scalar_columns: nonlinear_total,
            rank: nonlinear_rank,
            core_matrix_rows: s,
            core_matrix_columns: s,
            core_matrix_rank: nonlinear_core_rank,
            block_count: profile.rho,
            exact_full_rank: nonlinear_core_rank == s && nonlinear_rank == nonlinear_total,
        },
        Hx512ComponentRankReport {
            obligation: Hx512RankObligation::PiopLinearZeroSumMask,
            scalar_rows: linear_total,
            scalar_columns: linear_total,
            rank: linear_rank,
            core_matrix_rows: s,
            core_matrix_columns: s,
            core_matrix_rank: linear_core_rank,
            block_count: profile.rho,
            exact_full_rank: linear_core_rank == s && linear_rank == linear_total,
        },
        Hx512ComponentRankReport {
            obligation: Hx512RankObligation::PcsEquation6Randomizers,
            scalar_rows: pcs_randomizers,
            scalar_columns: pcs_randomizers,
            rank: pcs_randomizers,
            core_matrix_rows: geometry.partial_values_per_opening,
            core_matrix_columns: geometry.partial_values_per_opening,
            core_matrix_rank: geometry.partial_values_per_opening,
            block_count: s,
            exact_full_rank: true,
        },
        Hx512ComponentRankReport {
            obligation: Hx512RankObligation::LvcsRandomTails,
            scalar_rows: lvcs_total,
            scalar_columns: lvcs_total,
            rank: if lvcs_core_rank == profile.decs_openings {
                lvcs_total
            } else {
                0
            },
            core_matrix_rows: profile.decs_openings,
            core_matrix_columns: profile.decs_openings,
            core_matrix_rank: lvcs_core_rank,
            block_count: geometry.lvcs_rows,
            exact_full_rank: lvcs_core_rank == profile.decs_openings,
        },
        Hx512ComponentRankReport {
            obligation: Hx512RankObligation::LvcsOmittedRows,
            scalar_rows: geometry.opened_combinations,
            scalar_columns: geometry.opened_combinations,
            rank: omitted_rank,
            core_matrix_rows: geometry.opened_combinations,
            core_matrix_columns: geometry.opened_combinations,
            core_matrix_rank: omitted_rank,
            block_count: 1,
            exact_full_rank: omitted_rank == geometry.opened_combinations,
        },
        Hx512ComponentRankReport {
            obligation: Hx512RankObligation::DecsMasksAndHighs,
            scalar_rows: decs_total,
            scalar_columns: decs_total,
            rank: decs_rank,
            core_matrix_rows: profile.decs_openings,
            core_matrix_columns: profile.decs_openings,
            core_matrix_rank: decs_core_rank,
            block_count: profile.decs_eta,
            exact_full_rank: decs_core_rank == profile.decs_openings && decs_rank == decs_total,
        },
    ])
}

fn validate_pcs_equation6_weights(
    profile: &Hx512ZkProfile,
    geometry: &Hx512ZkGeometry,
    opening_points: &[u64],
) -> Result<(), Hx512ZkCertificateError> {
    let classes = [
        (geometry.witness_width, geometry.witness_delta),
        (geometry.nonlinear_width, geometry.nonlinear_delta),
        (geometry.linear_width, geometry.linear_delta),
    ];
    for &point in opening_points {
        if point == 0 {
            return Err(Hx512ZkCertificateError::SingularMatrix(
                "PCS Eq. (6) zero opening point",
            ));
        }
        for &(width, delta) in &classes {
            if width == 0 || delta >= profile.packing_factor {
                return Err(Hx512ZkCertificateError::InvalidProfile(
                    "invalid PCS width/delta class",
                ));
            }
            let mut weights = Vec::with_capacity(width);
            let mut weight = 1u64;
            let r_to_k = pow_mod(point, profile.packing_factor as u64);
            for index in 0..width {
                weights.push(weight);
                if width > 1 {
                    if index < width.saturating_sub(2) {
                        weight = mul_mod(weight, r_to_k);
                    } else if index == width.saturating_sub(2) {
                        weight = mul_mod(
                            weight,
                            pow_mod(point, (profile.packing_factor - delta) as u64),
                        );
                    }
                }
            }
            if weights.iter().any(|weight| *weight == 0) {
                return Err(Hx512ZkCertificateError::SingularMatrix(
                    "PCS Eq. (6) reconstruction weight",
                ));
            }
        }
    }
    Ok(())
}

fn representative_piop_opening_points(
    profile: &Hx512ZkProfile,
) -> Result<Vec<u64>, Hx512ZkCertificateError> {
    (0..profile.piop_openings)
        .map(|offset| {
            let value = checked_add(
                profile.packing_factor,
                checked_add(offset, 1, "opening point offset")?,
                "opening point",
            )?;
            u64::try_from(value).map_err(|_| {
                Hx512ZkCertificateError::ArithmeticOverflow("opening point conversion")
            })
        })
        .collect()
}

fn representative_decs_indexes(profile: &Hx512ZkProfile) -> Vec<u32> {
    (0..profile.decs_openings)
        .map(|index| index as u32)
        .collect()
}

fn validate_opening_points(
    packing_factor: usize,
    points: &[u64],
) -> Result<(), Hx512ZkCertificateError> {
    let mut seen = BTreeSet::new();
    for &point in points {
        if point >= HX512_GOLDILOCKS_MODULUS || point < packing_factor as u64 {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "PIOP opening point is noncanonical or in the packing domain",
            ));
        }
        if !seen.insert(point) {
            return Err(Hx512ZkCertificateError::InvalidProfile(
                "PIOP opening points are not distinct",
            ));
        }
    }
    Ok(())
}

fn witness_tail_opening_matrix(
    packing_factor: usize,
    opening_points: &[u64],
) -> Result<Vec<Vec<u64>>, Hx512ZkCertificateError> {
    opening_points
        .iter()
        .map(|&point| {
            let mut vanishing = 1u64;
            for root in 0..packing_factor {
                vanishing = mul_mod(vanishing, sub_mod(point, root as u64));
            }
            if vanishing == 0 {
                return Err(Hx512ZkCertificateError::SingularMatrix(
                    "witness packing vanishing factor",
                ));
            }
            let mut row = Vec::with_capacity(opening_points.len());
            let mut power = 1u64;
            for _ in 0..opening_points.len() {
                row.push(mul_mod(vanishing, power));
                power = mul_mod(power, point);
            }
            Ok(row)
        })
        .collect()
}

fn linear_zero_sum_low_map(
    packing_factor: usize,
    opening_points: &[u64],
) -> Result<Vec<Vec<u64>>, Hx512ZkCertificateError> {
    let inv_k = inv_mod((packing_factor as u64) % HX512_GOLDILOCKS_MODULUS)?;
    let mut average_powers = vec![0u64; opening_points.len()];
    for packing_point in 0..packing_factor as u64 {
        let mut power = packing_point;
        for average in &mut average_powers {
            *average = add_mod(*average, power);
            power = mul_mod(power, packing_point);
        }
    }
    for average in &mut average_powers {
        *average = mul_mod(*average, inv_k);
    }
    Ok(opening_points
        .iter()
        .map(|&point| {
            let mut power = point;
            average_powers
                .iter()
                .map(|average| {
                    let value = sub_mod(power, *average);
                    power = mul_mod(power, point);
                    value
                })
                .collect::<Vec<_>>()
        })
        .collect())
}

fn omitted_row_matrix(
    profile: &Hx512ZkProfile,
    opening_points: &[u64],
) -> Result<Vec<Vec<u64>>, Hx512ZkCertificateError> {
    let size = checked_mul(
        profile.beta,
        profile.piop_openings,
        "omitted row matrix size",
    )?;
    let mut matrix = vec![vec![0u64; size]; size];
    for (opening, &point) in opening_points.iter().enumerate() {
        for beta_block in 0..profile.beta {
            let row = opening * profile.beta + beta_block;
            let mut power = 1u64;
            for column in 0..profile.piop_openings {
                matrix[row][beta_block * profile.piop_openings + column] = power;
                power = mul_mod(power, point);
            }
        }
    }
    Ok(matrix)
}

fn lvcs_tail_cauchy_matrix(
    geometry: &Hx512ZkGeometry,
    query_points: &[u64],
) -> Result<Vec<Vec<u64>>, Hx512ZkCertificateError> {
    if query_points.len() + geometry.lvcs_cols != geometry.lvcs_interpolation_points {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "LVCS random-tail count does not match q",
        ));
    }
    query_points
        .iter()
        .map(|&query| {
            (geometry.lvcs_cols..geometry.lvcs_interpolation_points)
                .map(|node| inv_mod(sub_mod(query, node as u64)))
                .collect()
        })
        .collect()
}

fn vandermonde(points: &[u64], columns: usize) -> Vec<Vec<u64>> {
    points
        .iter()
        .map(|&point| {
            let mut row = Vec::with_capacity(columns);
            let mut power = 1u64;
            for _ in 0..columns {
                row.push(power);
                power = mul_mod(power, point);
            }
            row
        })
        .collect()
}

fn matrix_rank(mut matrix: Vec<Vec<u64>>) -> Result<usize, Hx512ZkCertificateError> {
    if matrix.is_empty() {
        return Ok(0);
    }
    let columns = matrix[0].len();
    if matrix.iter().any(|row| row.len() != columns) {
        return Err(Hx512ZkCertificateError::RaggedMatrix);
    }
    let mut rank = 0usize;
    for column in 0..columns {
        let Some(pivot) = (rank..matrix.len()).find(|row| matrix[*row][column] != 0) else {
            continue;
        };
        matrix.swap(rank, pivot);
        let inverse = inv_mod(matrix[rank][column])?;
        for value in &mut matrix[rank][column..] {
            *value = mul_mod(*value, inverse);
        }
        let pivot_row = matrix[rank].clone();
        for (row_index, row) in matrix.iter_mut().enumerate() {
            if row_index == rank || row[column] == 0 {
                continue;
            }
            let factor = row[column];
            for index in column..columns {
                row[index] = sub_mod(row[index], mul_mod(factor, pivot_row[index]));
            }
        }
        rank += 1;
        if rank == matrix.len() {
            break;
        }
    }
    Ok(rank)
}

fn add_mod(left: u64, right: u64) -> u64 {
    ((left as u128 + right as u128) % HX512_GOLDILOCKS_MODULUS as u128) as u64
}

fn sub_mod(left: u64, right: u64) -> u64 {
    ((left as u128 + HX512_GOLDILOCKS_MODULUS as u128 - right as u128)
        % HX512_GOLDILOCKS_MODULUS as u128) as u64
}

fn mul_mod(left: u64, right: u64) -> u64 {
    ((left as u128 * right as u128) % HX512_GOLDILOCKS_MODULUS as u128) as u64
}

fn pow_mod(mut base: u64, mut exponent: u64) -> u64 {
    let mut result = 1u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base);
        }
        base = mul_mod(base, base);
        exponent >>= 1;
    }
    result
}

fn inv_mod(value: u64) -> Result<u64, Hx512ZkCertificateError> {
    if value == 0 || value >= HX512_GOLDILOCKS_MODULUS {
        return Err(Hx512ZkCertificateError::InvalidFieldElement);
    }
    Ok(pow_mod(value, HX512_GOLDILOCKS_MODULUS - 2))
}

fn subgroup_generator(size: usize) -> Result<u64, Hx512ZkCertificateError> {
    if size == 0 || !size.is_power_of_two() {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "DECS domain is not a power of two",
        ));
    }
    let log_size = size.ilog2();
    if log_size > GOLDILOCKS_TWO_ADICITY {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "DECS domain exceeds Goldilocks two-adicity",
        ));
    }
    let root = pow_mod(
        GOLDILOCKS_TWO_ADIC_ROOT,
        1u64 << (GOLDILOCKS_TWO_ADICITY - log_size),
    );
    if pow_mod(root, size as u64) != 1 || (size > 1 && pow_mod(root, (size / 2) as u64) == 1) {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "derived DECS root has the wrong order",
        ));
    }
    Ok(root)
}

fn subgroup_point(size: usize, index: usize) -> Result<u64, Hx512ZkCertificateError> {
    if index >= size {
        return Err(Hx512ZkCertificateError::InvalidCoordinate(
            "DECS leaf index exceeds domain",
        ));
    }
    Ok(pow_mod(subgroup_generator(size)?, index as u64))
}

fn coset_point(size: usize, shift: u64, index: usize) -> Result<u64, Hx512ZkCertificateError> {
    Ok(mul_mod(shift, subgroup_point(size, index)?))
}

fn coset_is_disjoint(
    size: usize,
    interpolation_points: usize,
    shift: u64,
) -> Result<bool, Hx512ZkCertificateError> {
    if shift == 0 || shift >= HX512_GOLDILOCKS_MODULUS {
        return Ok(false);
    }
    let inverse = inv_mod(shift)?;
    for point in 1..interpolation_points {
        let normalized = mul_mod(point as u64, inverse);
        if pow_mod(normalized, size as u64) == 1 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn first_disjoint_coset_shift(
    size: usize,
    interpolation_points: usize,
) -> Result<u64, Hx512ZkCertificateError> {
    if interpolation_points == 0 || interpolation_points as u128 >= HX512_GOLDILOCKS_MODULUS as u128
    {
        return Err(Hx512ZkCertificateError::InvalidProfile(
            "invalid LVCS interpolation length",
        ));
    }
    for offset in 0..4096usize {
        let candidate = checked_add(interpolation_points, offset, "disjoint coset search")? as u64;
        if coset_is_disjoint(size, interpolation_points, candidate)? {
            return Ok(candidate);
        }
    }
    Err(Hx512ZkCertificateError::InvalidProfile(
        "bounded disjoint-coset search exhausted",
    ))
}

fn compact_merkle_auth_path_lengths(
    indices: &[usize],
    depth: usize,
) -> Result<Vec<usize>, Hx512ZkCertificateError> {
    if indices.is_empty() || indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Hx512ZkCertificateError::InvalidCoordinate(
            "DECS indexes must be nonempty, sorted, and distinct",
        ));
    }
    let mut lengths = vec![0usize; indices.len()];
    let mut current = indices.to_vec();
    for _ in 0..depth {
        let opened = current.iter().copied().collect::<BTreeSet<_>>();
        for (path_index, &index) in current.iter().enumerate() {
            let sibling = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            if !opened.contains(&sibling) {
                lengths[path_index] += 1;
            }
        }
        for index in &mut current {
            *index /= 2;
        }
    }
    Ok(lengths)
}

fn projected_wire_bytes(
    profile: &Hx512ZkProfile,
    geometry: &Hx512ZkGeometry,
    wire: &Hx512WireGrammar,
    auth_path_lengths: &[usize],
) -> Result<usize, Hx512ZkCertificateError> {
    if auth_path_lengths.len() != profile.decs_openings
        || auth_path_lengths
            .iter()
            .any(|length| *length > geometry.decs_auth_path_depth)
    {
        return Err(Hx512ZkCertificateError::InvalidCoordinate(
            "auth path length vector does not match q/depth",
        ));
    }
    let ledger = build_view_ledger(profile, geometry, wire)?;
    let mut total = 0usize;
    for entry in ledger
        .iter()
        .filter(|entry| entry.surface == Hx512ViewSurface::Serialized)
    {
        if entry.field == Hx512VerifierViewField::DecsAuthPathNodes {
            let nodes = auth_path_lengths.iter().try_fold(0usize, |acc, length| {
                checked_add(acc, *length, "auth node count")
            })?;
            total = checked_add(
                total,
                checked_mul(nodes, profile.digest_bytes, "auth node bytes")?,
                "proof bytes",
            )?;
        } else {
            total = checked_add(
                total,
                entry
                    .encoded_bytes
                    .ok_or(Hx512ZkCertificateError::InvalidWire(
                        "wire field remains runtime-sized",
                    ))?,
                "proof bytes",
            )?;
        }
    }
    if let Some(cap) = wire.parser_cap_bytes {
        if total > cap {
            return Err(Hx512ZkCertificateError::InvalidWire(
                "projected canonical view exceeds parser cap",
            ));
        }
    }
    Ok(total)
}

fn profile_commitment(
    profile: &Hx512ZkProfile,
    identity: &Hx512ZkIdentityPins,
    wire: &Hx512WireGrammar,
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(PROFILE_DOMAIN);
    for value in [
        profile.packing_factor,
        profile.relation_rows,
        profile.constraint_degree,
        profile.rho,
        profile.piop_openings,
        profile.beta,
        profile.decs_domain_size,
        profile.decs_openings,
        profile.decs_eta,
        profile.salt_bytes,
        profile.decs_committed_leaf_tape_count,
        profile.decs_leaf_tape_bytes,
        profile.digest_bytes,
        profile.nonce_bytes,
        profile.auxiliary_word_count,
        profile.statement_bytes,
        profile.verifier_context_bytes,
    ] {
        hasher.update((value as u128).to_le_bytes());
    }
    hasher.update(profile.opening_pow_bits.to_le_bytes());
    hasher.update(profile.decs_pow_bits.to_le_bytes());
    hasher.update(HX512_CMS_QROM_QUERY_BOUND_LOG2.to_le_bytes());
    hasher.update(HX512_CMS_QROM_LOSS_FACTOR.to_le_bytes());
    hasher.update(HX512_COMPOSED_SECURITY_TARGET_BITS.to_le_bytes());
    hash_option_u32(&mut hasher, profile.max_piop_trials);
    hash_option_usize(&mut hasher, profile.decs_sampler_candidates);
    hasher.update([u8::from(identity.allocated)]);
    for pin in identity.pin_slices() {
        hasher.update(pin);
    }
    hash_option_usize(&mut hasher, wire.prefix_bytes_before_salt);
    for value in [
        wire.matrix_dimension_bytes,
        wire.auth_path_count_bytes,
        wire.auth_path_length_bytes,
        wire.opened_witness_tag_bytes,
        wire.auxiliary_count_bytes,
    ] {
        hasher.update((value as u128).to_le_bytes());
    }
    hash_option_usize(&mut hasher, wire.parser_cap_bytes);
    hasher.update([u8::from(wire.exact_consumption), u8::from(wire.frozen)]);
    hasher.finalize().into()
}

fn hash_option_u32(hasher: &mut Sha512, value: Option<u32>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_le_bytes());
        }
        None => hasher.update([0]),
    }
}

/// Lazy witness-free sample of every verifier-view coordinate.  This object
/// is a classical-ROM *candidate*, not an accepted-proof generator: joint
/// PIOP/PCS/DECS/Merkle correlations, canonical retry conditioning, and the
/// QROM lift remain explicit blockers in `audit`.
#[derive(Clone, Debug)]
pub struct Hx512SimulatedVerifierView {
    profile: Hx512ZkProfile,
    geometry: Hx512ZkGeometry,
    identity: Hx512ZkIdentityPins,
    wire: Hx512WireGrammar,
    public_statement: Vec<u8>,
    verifier_context: Vec<u8>,
    seed: [u8; 64],
    decs_indexes: Vec<u32>,
    auth_path_lengths: Vec<usize>,
    audit: Hx512ZkAuditReport,
}

impl Hx512SimulatedVerifierView {
    /// Constructs a profile/public-input-bound candidate view.  There is
    /// intentionally no witness parameter.
    pub fn sample_classical_rom_candidate(
        profile: Hx512ZkProfile,
        identity: Hx512ZkIdentityPins,
        wire: Hx512WireGrammar,
        public_statement: &[u8],
        verifier_context: &[u8],
        entropy: [u8; 64],
    ) -> Result<Self, Hx512ZkCertificateError> {
        if public_statement.len() != profile.statement_bytes {
            return Err(Hx512ZkCertificateError::InvalidCoordinate(
                "public statement has the wrong width",
            ));
        }
        if verifier_context.len() != profile.verifier_context_bytes {
            return Err(Hx512ZkCertificateError::InvalidCoordinate(
                "verifier context has the wrong width",
            ));
        }
        let audit = audit_hx512_q48_zk_candidate(&profile, &identity, &wire)?;
        let geometry = audit.geometry.clone();
        let profile_digest = profile_commitment(&profile, &identity, &wire);
        let mut hasher = Sha512::new();
        hasher.update(VIEW_SEED_DOMAIN);
        hasher.update(profile_digest);
        hasher.update((public_statement.len() as u64).to_le_bytes());
        hasher.update(public_statement);
        hasher.update((verifier_context.len() as u64).to_le_bytes());
        hasher.update(verifier_context);
        hasher.update(entropy);
        let seed: [u8; 64] = hasher.finalize().into();
        let decs_indexes = sample_distinct_decs_indexes(&profile, &seed)?;
        let auth_path_lengths = compact_merkle_auth_path_lengths(
            &decs_indexes
                .iter()
                .map(|index| *index as usize)
                .collect::<Vec<_>>(),
            geometry.decs_auth_path_depth,
        )?;
        Ok(Self {
            profile,
            geometry,
            identity,
            wire,
            public_statement: public_statement.to_vec(),
            verifier_context: verifier_context.to_vec(),
            seed,
            decs_indexes,
            auth_path_lengths,
            audit,
        })
    }

    pub fn audit(&self) -> &Hx512ZkAuditReport {
        &self.audit
    }

    pub fn profile(&self) -> &Hx512ZkProfile {
        &self.profile
    }

    pub fn geometry(&self) -> &Hx512ZkGeometry {
        &self.geometry
    }

    pub fn identity(&self) -> &Hx512ZkIdentityPins {
        &self.identity
    }

    pub fn public_statement(&self) -> &[u8] {
        &self.public_statement
    }

    pub fn verifier_context(&self) -> &[u8] {
        &self.verifier_context
    }

    pub fn decs_indexes(&self) -> &[u32] {
        &self.decs_indexes
    }

    pub fn auth_path_lengths(&self) -> &[usize] {
        &self.auth_path_lengths
    }

    pub fn exact_projected_wire_bytes(&self) -> Result<usize, Hx512ZkCertificateError> {
        if !self.wire.is_frozen() {
            return Err(Hx512ZkCertificateError::InvalidWire(
                "projected bytes require a frozen wire grammar",
            ));
        }
        projected_wire_bytes(
            &self.profile,
            &self.geometry,
            &self.wire,
            &self.auth_path_lengths,
        )
    }

    pub fn sample_field_element(
        &self,
        field: Hx512VerifierViewField,
        coordinate: usize,
    ) -> Result<u64, Hx512ZkCertificateError> {
        let entry = self
            .audit
            .ledger
            .iter()
            .find(|entry| entry.field == field)
            .ok_or(Hx512ZkCertificateError::InvalidCoordinate(
                "field is not in the ledger",
            ))?;
        let count = entry
            .field_elements
            .ok_or(Hx512ZkCertificateError::InvalidCoordinate(
                "field is not a Goldilocks matrix",
            ))?;
        if coordinate >= count {
            return Err(Hx512ZkCertificateError::InvalidCoordinate(
                "field element coordinate is out of range",
            ));
        }
        sample_goldilocks(&self.seed, field, coordinate as u64)
    }

    pub fn sample_byte(
        &self,
        field: Hx512VerifierViewField,
        coordinate: usize,
    ) -> Result<u8, Hx512ZkCertificateError> {
        match field {
            Hx512VerifierViewField::PublicStatement => {
                self.public_statement.get(coordinate).copied().ok_or(
                    Hx512ZkCertificateError::InvalidCoordinate(
                        "public statement byte is out of range",
                    ),
                )
            }
            Hx512VerifierViewField::VerifierContext => {
                self.verifier_context.get(coordinate).copied().ok_or(
                    Hx512ZkCertificateError::InvalidCoordinate(
                        "verifier context byte is out of range",
                    ),
                )
            }
            Hx512VerifierViewField::Salt
            | Hx512VerifierViewField::PiopNonce
            | Hx512VerifierViewField::HPiop
            | Hx512VerifierViewField::DecsAuthPathNodes
            | Hx512VerifierViewField::DecsLeafTapes
            | Hx512VerifierViewField::MerkleRoot => {
                let limit = self.concrete_byte_count(field)?;
                if coordinate >= limit {
                    return Err(Hx512ZkCertificateError::InvalidCoordinate(
                        "byte coordinate is out of range",
                    ));
                }
                Ok(sample_byte(&self.seed, field, coordinate as u64))
            }
            _ => Err(Hx512ZkCertificateError::UnrefinedField(field)),
        }
    }

    pub fn concrete_byte_count(
        &self,
        field: Hx512VerifierViewField,
    ) -> Result<usize, Hx512ZkCertificateError> {
        if field == Hx512VerifierViewField::DecsAuthPathNodes {
            let nodes = self
                .auth_path_lengths
                .iter()
                .try_fold(0usize, |sum, length| {
                    checked_add(sum, *length, "simulated auth nodes")
                })?;
            return checked_mul(nodes, self.profile.digest_bytes, "simulated auth bytes");
        }
        if field == Hx512VerifierViewField::MerkleRoot {
            return Ok(self.profile.digest_bytes);
        }
        self.audit
            .ledger
            .iter()
            .find(|entry| entry.field == field)
            .and_then(|entry| entry.encoded_bytes)
            .ok_or(Hx512ZkCertificateError::UnrefinedField(field))
    }
}

fn sample_distinct_decs_indexes(
    profile: &Hx512ZkProfile,
    seed: &[u8; 64],
) -> Result<Vec<u32>, Hx512ZkCertificateError> {
    let mut indexes = BTreeSet::new();
    let mut draw = 0u64;
    let max_draws = checked_mul(profile.decs_openings, 1024, "simulator DECS draw cap")? as u64;
    while indexes.len() < profile.decs_openings && draw < max_draws {
        let word = sample_u64(seed, Hx512VerifierViewField::DecsOpeningIndexes, draw);
        indexes.insert((word % profile.decs_domain_size as u64) as u32);
        draw += 1;
    }
    if indexes.len() != profile.decs_openings {
        return Err(Hx512ZkCertificateError::InvalidCoordinate(
            "candidate simulator exhausted its DECS draw cap",
        ));
    }
    Ok(indexes.into_iter().collect())
}

fn sample_goldilocks(
    seed: &[u8; 64],
    field: Hx512VerifierViewField,
    coordinate: u64,
) -> Result<u64, Hx512ZkCertificateError> {
    for attempt in 0..1024u64 {
        let value = sample_u64_with_attempt(seed, field, coordinate, attempt);
        if value < HX512_GOLDILOCKS_MODULUS {
            return Ok(value);
        }
    }
    Err(Hx512ZkCertificateError::InvalidCoordinate(
        "Goldilocks rejection sampler exhausted",
    ))
}

fn sample_u64(seed: &[u8; 64], field: Hx512VerifierViewField, coordinate: u64) -> u64 {
    sample_u64_with_attempt(seed, field, coordinate, 0)
}

fn sample_u64_with_attempt(
    seed: &[u8; 64],
    field: Hx512VerifierViewField,
    coordinate: u64,
    attempt: u64,
) -> u64 {
    let digest = sample_digest(seed, field, coordinate / 8, attempt);
    let offset = (coordinate % 8) as usize * 8;
    u64::from_le_bytes(
        digest[offset..offset + 8]
            .try_into()
            .expect("eight-byte chunk"),
    )
}

fn sample_byte(seed: &[u8; 64], field: Hx512VerifierViewField, coordinate: u64) -> u8 {
    let digest = sample_digest(seed, field, coordinate / 64, 0);
    digest[(coordinate % 64) as usize]
}

fn sample_digest(
    seed: &[u8; 64],
    field: Hx512VerifierViewField,
    block: u64,
    attempt: u64,
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(VIEW_FIELD_DOMAIN);
    hasher.update(seed);
    hasher.update([field as u8]);
    hasher.update((field.tag().len() as u64).to_le_bytes());
    hasher.update(field.tag());
    hasher.update(block.to_le_bytes());
    hasher.update(attempt.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic row-count fixture retained only to exercise the parametric
    /// algebra.  It is not the unfrozen complete HX512 relation geometry.
    fn reference_profile() -> Hx512ZkProfile {
        Hx512ZkProfile::unfrozen_q48_s6(11_209, 6, 983, 136)
    }

    fn synthetic_frozen_identity() -> Hx512ZkIdentityPins {
        let mut next = 1u8;
        let mut digest = || {
            let output = [next; 64];
            next = next.wrapping_add(1);
            output
        };
        Hx512ZkIdentityPins {
            allocated: true,
            engine_source_sha512: digest(),
            transcript_source_sha512: digest(),
            relation_shape_sha512: digest(),
            adapter_topology_sha512: digest(),
            typed_hash_schedule_sha512: digest(),
            wire_grammar_sha512: digest(),
            statement_grammar_sha512: digest(),
            context_grammar_sha512: digest(),
            domain_registry_sha512: digest(),
            profile_sha512: digest(),
            consensus_rules_sha512: digest(),
        }
    }

    fn synthetic_frozen_wire() -> Hx512WireGrammar {
        Hx512WireGrammar {
            prefix_bytes_before_salt: Some(768),
            matrix_dimension_bytes: 4,
            auth_path_count_bytes: 2,
            auth_path_length_bytes: 1,
            opened_witness_tag_bytes: 1,
            auxiliary_count_bytes: 8,
            parser_cap_bytes: Some(4 * 1024 * 1024),
            exact_consumption: true,
            frozen: true,
        }
    }

    #[test]
    fn synthetic_q48_s6_geometry_matches_independent_parametric_derivation() {
        let profile = reference_profile();
        let geometry = Hx512ZkGeometry::derive(&profile).expect("derive q48/s6 geometry");
        assert_eq!(geometry.witness_polynomial_degree, 1029);
        assert_eq!(geometry.raw_constraint_polynomial_degree, 6174);
        assert_eq!(geometry.nonlinear_mask_degree, 5150);
        assert_eq!(geometry.linear_mask_degree, 2052);
        assert_eq!((geometry.witness_width, geometry.witness_delta), (1, 0));
        assert_eq!(
            (geometry.nonlinear_width, geometry.nonlinear_delta),
            (6, 999)
        );
        assert_eq!((geometry.linear_width, geometry.linear_delta), (2, 1));
        assert_eq!(geometry.polynomial_count, 11_219);
        assert_eq!(
            (geometry.unstacked_rows, geometry.unstacked_cols),
            (1030, 11_249)
        );
        assert_eq!((geometry.lvcs_rows, geometry.lvcs_cols), (2060, 5625));
        assert_eq!(geometry.opened_combinations, 12);
        assert_eq!(geometry.partial_values_per_opening, 30);
        assert_eq!(geometry.lvcs_interpolation_points, 5673);
        assert_eq!(geometry.decs_polynomial_degree, 5672);
        assert_eq!(geometry.disjoint_coset_shift, 5673);
    }

    #[test]
    fn s5_and_s_eta_alias_are_rejected() {
        let s5 = exact_cms19_qrom_epsilon3_envelope(6 * (1024 + 5 - 1), 1024, 5)
            .expect("evaluate retained s5 counterexample");
        assert!(!s5.strict_more_than_target_bits);
        let s6 = exact_cms19_qrom_epsilon3_envelope(6 * (1024 + 6 - 1), 1024, 6)
            .expect("evaluate s6 candidate");
        assert!(s6.strict_more_than_target_bits);
        assert_eq!(s6.qrom_query_bound_log2, 64);
        assert_eq!(s6.cms_loss_factor, 12);
        assert_eq!(s6.target_security_bits, 128);

        let mut profile = reference_profile();
        profile.piop_openings = 5;
        assert!(matches!(
            profile.validate_q48(),
            Err(Hx512ZkCertificateError::InvalidProfile(_))
        ));

        let mut profile = reference_profile();
        profile.decs_eta = 6;
        assert!(matches!(
            profile.validate_q48(),
            Err(Hx512ZkCertificateError::InvalidProfile(_))
        ));
    }

    #[test]
    fn q48_s6_component_maps_have_the_exact_declared_ranks() {
        let profile = reference_profile();
        let report = audit_hx512_q48_zk_candidate(
            &profile,
            &Hx512ZkIdentityPins::unallocated(),
            &Hx512WireGrammar::provisional(),
        )
        .expect("audit q48/s6");
        assert!(report.rank_reports.iter().all(|rank| rank.exact_full_rank));
        let rank = |obligation| {
            report
                .rank_reports
                .iter()
                .find(|rank| rank.obligation == obligation)
                .expect("rank obligation")
        };
        assert_eq!(rank(Hx512RankObligation::WitnessRandomHighs).rank, 6);
        assert_eq!(rank(Hx512RankObligation::PiopNonlinearMask).rank, 5151);
        assert_eq!(rank(Hx512RankObligation::PiopLinearZeroSumMask).rank, 2052);
        assert_eq!(rank(Hx512RankObligation::PcsEquation6Randomizers).rank, 180);
        assert_eq!(rank(Hx512RankObligation::LvcsRandomTails).rank, 98_880);
        assert_eq!(rank(Hx512RankObligation::LvcsOmittedRows).rank, 12);
        assert_eq!(rank(Hx512RankObligation::DecsMasksAndHighs).rank, 28_365);
    }

    #[test]
    fn duplicated_piop_point_and_intersecting_coset_fail_rank_premises() {
        let profile = reference_profile();
        let geometry = Hx512ZkGeometry::derive(&profile).expect("geometry");
        let mut points = representative_piop_opening_points(&profile).expect("points");
        points[5] = points[4];
        assert!(component_rank_reports(
            &profile,
            &geometry,
            &points,
            &representative_decs_indexes(&profile)
        )
        .is_err());
        assert!(!coset_is_disjoint(
            profile.decs_domain_size,
            geometry.lvcs_interpolation_points,
            1
        )
        .expect("check colliding coset"));
    }

    #[test]
    fn ledger_covers_every_serialized_and_derived_field_once() {
        let report = audit_hx512_q48_zk_candidate(
            &reference_profile(),
            &Hx512ZkIdentityPins::unallocated(),
            &Hx512WireGrammar::provisional(),
        )
        .expect("audit");
        validate_view_ledger(&report.ledger).expect("complete ledger");
        assert_eq!(report.ledger.len(), HX512_ALL_VERIFIER_VIEW_FIELDS.len());
        let mut missing = report.ledger.clone();
        missing.pop();
        assert!(validate_view_ledger(&missing).is_err());
        let mut duplicate = report.ledger.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(validate_view_ledger(&duplicate).is_err());
        let aux = report
            .ledger
            .iter()
            .find(|entry| entry.field == Hx512VerifierViewField::AuxiliaryWords)
            .expect("aux ledger");
        assert_eq!((aux.field_elements, aux.encoded_bytes), (Some(0), Some(0)));
    }

    #[test]
    fn witness_free_view_is_public_bound_deterministic_and_canonical() {
        let profile = reference_profile();
        let statement = vec![0x11; profile.statement_bytes];
        let context = vec![0x22; profile.verifier_context_bytes];
        let view = Hx512SimulatedVerifierView::sample_classical_rom_candidate(
            profile.clone(),
            Hx512ZkIdentityPins::unallocated(),
            Hx512WireGrammar::provisional(),
            &statement,
            &context,
            [0x33; 64],
        )
        .expect("sample candidate view");
        let first = view
            .sample_field_element(Hx512VerifierViewField::OpenedWitnessRowScalars, 0)
            .expect("sample field element");
        let again = view
            .sample_field_element(Hx512VerifierViewField::OpenedWitnessRowScalars, 0)
            .expect("repeat field element");
        assert_eq!(first, again);
        assert!(first < HX512_GOLDILOCKS_MODULUS);
        assert_eq!(view.decs_indexes().len(), profile.decs_openings);
        assert!(view.decs_indexes().windows(2).all(|pair| pair[0] < pair[1]));
        assert!(view
            .auth_path_lengths()
            .iter()
            .all(|length| *length <= view.geometry().decs_auth_path_depth));
        assert_eq!(
            view.sample_byte(Hx512VerifierViewField::PublicStatement, 0)
                .expect("public byte"),
            0x11
        );
        assert_eq!(
            view.concrete_byte_count(Hx512VerifierViewField::MerkleRoot)
                .expect("derived root width"),
            HX512_Q48_DIGEST_BYTES
        );
        assert!(view
            .sample_byte(Hx512VerifierViewField::MerkleRoot, 63)
            .is_ok());
        assert!(view
            .sample_byte(Hx512VerifierViewField::MerkleRoot, 64)
            .is_err());

        let mut changed_statement = statement;
        changed_statement[0] ^= 1;
        let changed = Hx512SimulatedVerifierView::sample_classical_rom_candidate(
            profile,
            Hx512ZkIdentityPins::unallocated(),
            Hx512WireGrammar::provisional(),
            &changed_statement,
            &context,
            [0x33; 64],
        )
        .expect("sample changed view");
        assert_ne!(
            first,
            changed
                .sample_field_element(Hx512VerifierViewField::OpenedWitnessRowScalars, 0)
                .expect("changed field element")
        );
    }

    #[test]
    fn compact_auth_paths_and_frozen_wire_have_one_exact_projection() {
        let profile = reference_profile();
        let view = Hx512SimulatedVerifierView::sample_classical_rom_candidate(
            profile,
            synthetic_frozen_identity(),
            synthetic_frozen_wire(),
            &vec![7; 983],
            &vec![8; 136],
            [9; 64],
        )
        .expect("sample frozen synthetic view");
        let bytes = view.exact_projected_wire_bytes().expect("project bytes");
        assert!(bytes > 1_000_000);
        assert!(bytes < 4 * 1024 * 1024);
        let auth_bytes = view
            .concrete_byte_count(Hx512VerifierViewField::DecsAuthPathNodes)
            .expect("auth bytes");
        assert_eq!(
            auth_bytes,
            view.auth_path_lengths().iter().sum::<usize>() * HX512_Q48_DIGEST_BYTES
        );
        let mut bad_lengths = view.auth_path_lengths().to_vec();
        bad_lengths[0] = view.geometry().decs_auth_path_depth + 1;
        assert!(projected_wire_bytes(
            view.profile(),
            view.geometry(),
            &synthetic_frozen_wire(),
            &bad_lengths
        )
        .is_err());
    }

    #[test]
    fn identity_and_sampler_drift_remain_typed_blockers() {
        let profile = reference_profile();
        let report = audit_hx512_q48_zk_candidate(
            &profile,
            &Hx512ZkIdentityPins::unallocated(),
            &Hx512WireGrammar::provisional(),
        )
        .expect("audit");
        for blocker in [
            Hx512ZkBlocker::SuccessorIdentityUnallocated,
            Hx512ZkBlocker::EngineSourceUnpinned,
            Hx512ZkBlocker::TranscriptSourceUnpinned,
            Hx512ZkBlocker::WireGrammarUnfrozen,
            Hx512ZkBlocker::SamplerGrammarUnfrozen,
            Hx512ZkBlocker::MeasuredProofArtifactMissing,
        ] {
            assert!(report.blockers.contains(&blocker));
        }

        let mut frozen_profile = profile;
        frozen_profile.max_piop_trials = Some(16);
        frozen_profile.decs_sampler_candidates = Some(96);
        let report = audit_hx512_q48_zk_candidate(
            &frozen_profile,
            &synthetic_frozen_identity(),
            &synthetic_frozen_wire(),
        )
        .expect("synthetic frozen audit");
        assert!(!report
            .blockers
            .contains(&Hx512ZkBlocker::SamplerGrammarUnfrozen));
        assert!(!report
            .blockers
            .contains(&Hx512ZkBlocker::WireGrammarUnfrozen));
        assert!(report
            .blockers
            .contains(&Hx512ZkBlocker::WholeViewDistributionEqualityUnproved));

        let mut partial_identity = synthetic_frozen_identity();
        partial_identity.domain_registry_sha512 = [0; 64];
        let report = audit_hx512_q48_zk_candidate(
            &frozen_profile,
            &partial_identity,
            &synthetic_frozen_wire(),
        )
        .expect("partially pinned audit remains fail closed");
        assert!(report
            .blockers
            .contains(&Hx512ZkBlocker::DomainRegistryUnpinned));
        assert!(partial_identity.validate_frozen().is_err());
    }

    #[test]
    fn every_authority_capability_stays_false() {
        let report = audit_hx512_q48_zk_candidate(
            &reference_profile(),
            &synthetic_frozen_identity(),
            &synthetic_frozen_wire(),
        )
        .expect("audit");
        assert!(report.capabilities.local_component_rank_certificate);
        assert!(report.capabilities.witness_free_classical_rom_candidate);
        assert!(!report.capabilities.classical_rom_joint_simulator_proved);
        assert!(!report.capabilities.adaptive_qrom_lift_proved);
        assert!(!report.capabilities.complete_zero_knowledge);
        assert!(!report.capabilities.compiled_refinement);
        assert!(!report.capabilities.production_authorized);
        assert_eq!(report.measured_proof_bytes, None);
        assert!(HX512_THEOREM_PREMISES
            .iter()
            .any(|premise| premise.identifier.contains("GHCM")));
    }

    #[test]
    fn aux_words_canonical_field_and_parser_mutations_fail_closed() {
        let mut profile = reference_profile();
        profile.auxiliary_word_count = 1;
        assert!(profile.validate_q48().is_err());
        let mut profile = reference_profile();
        profile.decs_committed_leaf_tape_count -= 1;
        assert!(profile.validate_q48().is_err());
        assert!(inv_mod(HX512_GOLDILOCKS_MODULUS).is_err());
        let mut wire = synthetic_frozen_wire();
        wire.exact_consumption = false;
        assert!(wire.validate().is_err());
        let mut identity = synthetic_frozen_identity();
        identity.engine_source_sha512 = [0; 64];
        assert!(identity.validate_frozen().is_err());
    }
}
