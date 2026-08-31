//! Exact source-level map to the read-only Plonky3 snapshot.
//!
//! Nothing in this module claims that `HidingWhirPcs` is an R1CS proof
//! system. The upstream trait accepts one multilinear polynomial and opening
//! points. CFW26 Section 11 is the missing carrier from Hegemon's R1CS to that
//! interface, and the primary construction is ambiguous in two independent
//! places.

use crate::{AdapterError, ProductionBlocker};

pub const PLONKY3_HEAD: &str = "5df89eeadae18d6935bb874f8a92808dcc200c9d";
pub const PLONKY3_CRATE_VERSION: &str = "0.6.0";
pub const PLONKY3_PCS_TYPE: &str = "p3_whir::pcs::zk::HidingWhirPcs<EF,F,Dft,MT,Challenger,R>";
pub const PLONKY3_WITNESS_TYPE: &str = "p3_multilinear_util::poly::Poly<F>";
pub const PLONKY3_OPENING_PROTOCOL_TYPE: &str =
    "alloc::vec::Vec<p3_multilinear_util::point::Point<EF>>";
pub const PLONKY3_PROOF_TYPE: &str = "p3_whir::pcs::zk::ZkWhirProof<F,EF,MT>";
pub const PLONKY3_ERROR_TYPE: &str = "p3_whir::pcs::zk::ZkVerifierError";

/// The only high-cardinality Goldilocks extension implemented by the pinned
/// source and admitted by `HidingWhirPcs`'s `EF: ExtensionField<F> +
/// TwoAdicField` bounds.
pub const GOLDILOCKS_E320_TYPE: &str =
    "p3_field::extension::BinomialExtensionField<p3_goldilocks::Goldilocks,5>";
pub const GOLDILOCKS_E320_EXTENSION_DEGREE: usize = 5;
pub const GOLDILOCKS_E320_TWO_ADICITY: usize = 32;
pub const GOLDILOCKS_E320_SOURCE_FEASIBLE: bool = true;
pub const GOLDILOCKS_E320_SECURITY_SELECTED: bool = false;
pub const GOLDILOCKS_E320_CANDIDATE_HALF_NUM_VARIABLES: usize = 25;
pub const GOLDILOCKS_E320_PCS_POLYNOMIAL_COUNT_SELECTED: Option<usize> = None;
pub const PLONKY3_LOCAL_SECURITY_LEVEL_IS_STRICT_AUTHORITY: bool = false;
pub const PLONKY3_CAPACITY_BOUND_PRODUCTION_ALLOWED: bool = false;
pub const PLONKY3_JOHNSON_DOMINANT_TERM_PRODUCTION_ALLOWED: bool = false;

/// These names are intentionally rejected: the pinned Goldilocks source has
/// no degree-six or degree-eight binomial implementation.
pub const UNSUPPORTED_GOLDILOCKS_ALIASES: [&str; 2] = [
    "BinomialExtensionField<Goldilocks,6>",
    "BinomialExtensionField<Goldilocks,8>",
];

/// A conventional 64-byte SHA-512 instantiation is type-shaped by the pinned
/// generic APIs. This is the precise map; it has not been compiled under the
/// disk gate and, more importantly, does not yet refine Hegemon's role-framed
/// transcript/MMCS bytes.
pub const SHA512_BYTE_HASH_TYPE: &str =
    "HegemonSha512Hasher implementing CryptographicHasher<u8,[u8;64]>";
pub const SHA512_FIELD_HASH_TYPE: &str = "p3_symmetric::SerializingHasher<HegemonSha512Hasher>";
pub const SHA512_COMPRESSION_TYPE: &str =
    "p3_symmetric::CompressionFunctionFromHasher<HegemonSha512Hasher,2,64>";
pub const SHA512_MMCS_TYPE: &str = "p3_merkle_tree::MerkleTreeMmcs<Goldilocks,u8,SerializingHasher<HegemonSha512Hasher>,CompressionFunctionFromHasher<HegemonSha512Hasher,2,64>,2,64>";
pub const SHA512_INNER_CHALLENGER_TYPE: &str =
    "p3_challenger::HashChallenger<u8,HegemonSha512Hasher,64>";
pub const SHA512_FIELD_CHALLENGER_TYPE: &str =
    "p3_challenger::SerializingChallenger64<Goldilocks,HashChallenger<u8,HegemonSha512Hasher,64>>";
pub const SHA512_CHALLENGER_CONSTRUCTOR: &str =
    "SerializingChallenger64::new(HashChallenger::new(initial_state, HegemonSha512Hasher))";
pub const SHA512_DOMAIN_SEPARATOR_DIGEST_ELEMS: usize = 64;
pub const SHA512_TYPE_MAP_SOURCE_FEASIBLE: bool = true;
pub const SHA512_EXACT_ROLE_FRAMING_REFINEMENT_PROVED: bool = false;
pub const SHA512_MMCS_ROLE_FRAMING_REFINEMENT_PROVED: bool = false;
pub const LOCAL_KECCAK256_FALLBACK_ALLOWED: bool = false;

/// Parameter provenance is separate from Plonky3's local
/// `ProtocolParameters::security_level`. That field is a configuration target,
/// not a composed PQ/QROM certificate. Capacity mode is conjectural, while the
/// pinned Johnson calculation retains only the BCSS25 dominant term and uses
/// `f64`; both are diagnostic-only here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityParameterSource {
    IndependentExactUniqueDecoding,
    IndependentExactFullJohnson,
    Plonky3UniqueDecodingLocalTargetDiagnostic,
    Plonky3JohnsonDominantTermF64Diagnostic,
    Plonky3CapacityConjecturalDiagnostic,
}

impl SecurityParameterSource {
    pub const fn is_independent_exact(self) -> bool {
        matches!(
            self,
            Self::IndependentExactUniqueDecoding | Self::IndependentExactFullJohnson
        )
    }
}

pub const MAX_INDEPENDENT_SECURITY_CERTIFICATE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndependentSecurityCertificate<'a> {
    pub source: SecurityParameterSource,
    pub canonical_bytes: &'a [u8],
    pub canonical_sha512: [u8; 64],
    pub strict_composed_lower_bound_bits: u16,
    pub exact_integer_or_rational_arithmetic: bool,
    pub includes_full_johnson_terms: bool,
    pub includes_pcs_iop_fiat_shamir_hash_grinding_union_terms: bool,
    pub includes_modified_bcs_hiding_term: bool,
    pub total_iop_proof_length_p_exact: Option<u64>,
    pub modified_bcs_lambda_bits: u32,
    pub all_105_oracle_code_lengths_fixed: bool,
    pub field_encoding_fixed: bool,
    pub modified_bcs_term_strictly_below_target_proved: bool,
    pub qrom_reduction_included: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityParameterError {
    DiagnosticSource,
    EmptyCertificate,
    CertificateTooLarge,
    CertificateDigestMismatch,
    LowerBoundNotStrictlyAbove128,
    InexactArithmetic,
    JohnsonTermsOmitted,
    CompositionTermsOmitted,
    ModifiedBcsHidingTermOmitted,
    TotalIopProofLengthUnknown,
    ModifiedBcsLambdaBelowKnownE320Floor,
    OracleCodeLengthsUnfixed,
    FieldEncodingUnfixed,
    ModifiedBcsTargetUnproved,
    QromReductionOmitted,
}

/// Structurally admits an independently supplied exact certificate for later
/// source mapping. This never authorizes production: every backend entry point
/// still returns the adapter's complete unresolved production-gate set.
pub fn validate_independent_security_certificate(
    certificate: &IndependentSecurityCertificate<'_>,
) -> Result<(), SecurityParameterError> {
    if !certificate.source.is_independent_exact() {
        return Err(SecurityParameterError::DiagnosticSource);
    }
    if certificate.canonical_bytes.is_empty() {
        return Err(SecurityParameterError::EmptyCertificate);
    }
    if certificate.canonical_bytes.len() > MAX_INDEPENDENT_SECURITY_CERTIFICATE_BYTES {
        return Err(SecurityParameterError::CertificateTooLarge);
    }
    if crate::sha512(certificate.canonical_bytes) != certificate.canonical_sha512 {
        return Err(SecurityParameterError::CertificateDigestMismatch);
    }
    if certificate.strict_composed_lower_bound_bits <= 128 {
        return Err(SecurityParameterError::LowerBoundNotStrictlyAbove128);
    }
    if !certificate.exact_integer_or_rational_arithmetic {
        return Err(SecurityParameterError::InexactArithmetic);
    }
    if certificate.source == SecurityParameterSource::IndependentExactFullJohnson
        && !certificate.includes_full_johnson_terms
    {
        return Err(SecurityParameterError::JohnsonTermsOmitted);
    }
    if !certificate.includes_pcs_iop_fiat_shamir_hash_grinding_union_terms {
        return Err(SecurityParameterError::CompositionTermsOmitted);
    }
    if !certificate.includes_modified_bcs_hiding_term {
        return Err(SecurityParameterError::ModifiedBcsHidingTermOmitted);
    }
    if certificate.total_iop_proof_length_p_exact.is_none() {
        return Err(SecurityParameterError::TotalIopProofLengthUnknown);
    }
    if certificate.modified_bcs_lambda_bits
        < crate::MODIFIED_BCS_E320_RATE_ONE_INTEGER_LAMBDA_FLOOR_BITS as u32
    {
        return Err(SecurityParameterError::ModifiedBcsLambdaBelowKnownE320Floor);
    }
    if !certificate.all_105_oracle_code_lengths_fixed {
        return Err(SecurityParameterError::OracleCodeLengthsUnfixed);
    }
    if !certificate.field_encoding_fixed {
        return Err(SecurityParameterError::FieldEncodingUnfixed);
    }
    if !certificate.modified_bcs_term_strictly_below_target_proved {
        return Err(SecurityParameterError::ModifiedBcsTargetUnproved);
    }
    if !certificate.qrom_reduction_included {
        return Err(SecurityParameterError::QromReductionOmitted);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcsApiStep {
    DeriveConfig,
    ConstructPcs,
    AddDomainSeparator,
    CommitMultilinearPolynomial,
    OpenEvaluationPoints,
    VerifyEvaluationPoints,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcsApiMapping {
    pub step: PcsApiStep,
    pub source: &'static str,
    pub signature: &'static str,
}

pub const PINNED_API_SEQUENCE: [PcsApiMapping; 6] = [
    PcsApiMapping {
        step: PcsApiStep::DeriveConfig,
        source: "whir/src/pcs/zk/config.rs",
        signature: "ZkWhirConfig::new(num_variables, ProtocolParameters, ZkParameters) -> Result<ZkWhirConfig, ZkConfigError>",
    },
    PcsApiMapping {
        step: PcsApiStep::ConstructPcs,
        source: "whir/src/pcs/zk/adapter.rs",
        signature: "HidingWhirPcs::new(config, dft, mmcs, rng) -> HidingWhirPcs",
    },
    PcsApiMapping {
        step: PcsApiStep::AddDomainSeparator,
        source: "whir/src/pcs/zk/adapter.rs",
        signature: "HidingWhirPcs::add_domain_separator::<DIGEST_ELEMS>(&mut DomainSeparator)",
    },
    PcsApiMapping {
        step: PcsApiStep::CommitMultilinearPolynomial,
        source: "commit/src/pcs/multilinear.rs; whir/src/pcs/zk/adapter.rs",
        signature: "MultilinearPcs::commit(Poly<F>, &mut Challenger) -> (MT::Commitment, HidingWhirProverData)",
    },
    PcsApiMapping {
        step: PcsApiStep::OpenEvaluationPoints,
        source: "commit/src/pcs/multilinear.rs; whir/src/pcs/zk/adapter.rs",
        signature: "MultilinearPcs::open(prover_data, Vec<Point<EF>>, &mut Challenger) -> ZkWhirProof",
    },
    PcsApiMapping {
        step: PcsApiStep::VerifyEvaluationPoints,
        source: "commit/src/pcs/multilinear.rs; whir/src/pcs/zk/adapter.rs",
        signature: "MultilinearPcs::verify(&commitment, &proof, &mut Challenger, Vec<Point<EF>>) -> Result<(), ZkVerifierError>",
    },
];

pub const PINNED_GENERIC_BOUNDS: &[&str] = &[
    "F: TwoAdicField",
    "EF: ExtensionField<F> + TwoAdicField",
    "Dft: TwoAdicSubgroupDft<F>",
    "MT: Mmcs<F>",
    "Challenger: FieldChallenger<F> + GrindingChallenger<Witness=F> + CanSampleUniformBits<F> + CanObserve<MT::Commitment>",
    "R: CryptoRng + Send + Sync",
    "StandardUniform: Distribution<EF> + Distribution<F>",
];

/// There is no honest implementation of this conversion at the pinned API.
/// Returning the precise blocker keeps callers from confusing PCS plumbing
/// with the absent R1CS-to-constrained-code IOR.
pub fn map_r1cs_to_hiding_whir_pcs() -> Result<(), AdapterError> {
    Err(AdapterError::ProductionBlocked(&[
        ProductionBlocker::Cfw26Section11SpecificationAmbiguous,
        ProductionBlocker::R1csToConstrainedCodeCarrierAbsent,
    ]))
}
