//! Fail-closed source adapter for the Hegemon odd-field HVZK-WHIR challenger.
//!
//! This crate implements the bounded outer codec, exact HX448C02 public and
//! private transport contracts, conventional SHA-512/SHAKE256 framing, and a
//! source-level map to Plonky3 `HidingWhirPcs` at commit `5df89ee`. It does not
//! implement or authorize a transaction proof. In particular, Plonky3 supplies
//! a hiding multilinear PCS only; it does not supply the ambiguous CFW26
//! Section 11 R1CS carrier.

#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

pub mod hash;
pub mod plonky3_api;

pub use hash::{
    DIGEST_BYTES, HashError, HashPrimitive, HashRole, framed_hash, framed_shake256, sha512,
    shake256,
};

pub const PRODUCTION_AUTHORIZED: bool = false;
pub const PROOF_BYTES: Option<usize> = None;
pub const COMPOSED_PQ_SECURITY_BITS: Option<f64> = None;
pub const COMPLETE_ZERO_KNOWLEDGE_PROVED: bool = false;
pub const PLONKY3_IS_PCS_ONLY: bool = true;
pub const CFW26_SECTION11_SPECIFICATION_UNAMBIGUOUS: bool = false;

pub const WIRE_MAGIC: [u8; 8] = *b"HGWAWH01";
pub const STATEMENT_MAGIC: [u8; 8] = *b"HGWAST01";
pub const WIRE_VERSION: u16 = 1;
pub const STATEMENT_VERSION: u16 = 1;
pub const DOMAIN_SET_VERSION: u16 = 1;
pub const HASH_SUITE_ID: u16 = 2;
pub const WIRE_HEADER_BYTES: usize = 168;
pub const STATEMENT_HEADER_BYTES: usize = 92;
pub const SECTION_HEADER_BYTES: usize = 8;

pub const HX_STATEMENT_BYTES: usize = 869;
pub const CONSENSUS_STATE_WORDS: usize = 50;
pub const CONSENSUS_STATE_BYTES: usize = CONSENSUS_STATE_WORDS * 8;
pub const PUBLIC_ARGUMENT_BYTES: usize = HX_STATEMENT_BYTES + CONSENSUS_STATE_BYTES;
pub const PRIVATE_TRANSPORT_WORDS: usize = 1_209;
pub const PRIVATE_TRANSPORT_BYTES: usize = PRIVATE_TRANSPORT_WORDS * 8;
pub const PUBLIC_BITS: usize = PUBLIC_ARGUMENT_BYTES * 8;
pub const PRIVATE_TRANSPORT_BITS: usize = PRIVATE_TRANSPORT_BYTES * 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportSectionLayout {
    pub name: &'static str,
    pub offset_words: usize,
    pub words: usize,
    pub semantic_bytes: Option<usize>,
    pub required_zero_pad_bytes: usize,
}

pub const PRIVATE_TRANSPORT_SECTIONS: [TransportSectionLayout; 7] = [
    TransportSectionLayout {
        name: "input[0]",
        offset_words: 0,
        words: 261,
        semantic_bytes: None,
        required_zero_pad_bytes: 0,
    },
    TransportSectionLayout {
        name: "input[1]",
        offset_words: 261,
        words: 261,
        semantic_bytes: None,
        required_zero_pad_bytes: 0,
    },
    TransportSectionLayout {
        name: "output[0]",
        offset_words: 522,
        words: 30,
        semantic_bytes: None,
        required_zero_pad_bytes: 0,
    },
    TransportSectionLayout {
        name: "output[1]",
        offset_words: 552,
        words: 30,
        semantic_bytes: None,
        required_zero_pad_bytes: 0,
    },
    TransportSectionLayout {
        name: "authorization",
        offset_words: 582,
        words: 89,
        semantic_bytes: None,
        required_zero_pad_bytes: 0,
    },
    TransportSectionLayout {
        name: "ciphertext[0]",
        offset_words: 671,
        words: 269,
        semantic_bytes: Some(2_147),
        required_zero_pad_bytes: 5,
    },
    TransportSectionLayout {
        name: "ciphertext[1]",
        offset_words: 940,
        words: 269,
        semantic_bytes: Some(2_147),
        required_zero_pad_bytes: 5,
    },
];

pub const PRIVATE_NOTE_LAYOUT_WORDS: usize = 26;
pub const PRIVATE_INPUT_POSITION_WORDS: usize = 1;
pub const PRIVATE_INPUT_MERKLE_SIBLING_WORDS: usize = 224;
pub const PRIVATE_INPUT_SPEND_KEY_WORDS: usize = 6;
pub const PRIVATE_INPUT_BALANCE_SELECTOR_WORDS: usize = 4;
pub const PRIVATE_INPUT_LAYOUT_WORDS: usize = 261;
pub const PRIVATE_AUTHORIZATION_MODE_WORDS: usize = 1;
pub const PRIVATE_AUTHORIZATION_ACCUMULATOR_WORDS: usize = 23;
pub const PRIVATE_AUTHORIZATION_SIGNER_TAG_WORDS: usize = 42;
pub const PRIVATE_AUTHORIZATION_LAYOUT_WORDS: usize = 89;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusFieldKind {
    U32,
    U64,
    Bool,
    U128LowHigh,
    Digest48,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusFieldLayout {
    pub name: &'static str,
    pub offset_words: usize,
    pub words: usize,
    pub kind: ConsensusFieldKind,
}

pub const CONSENSUS_STATE_FIELDS: [ConsensusFieldLayout; 23] = [
    ConsensusFieldLayout {
        name: "seam_version",
        offset_words: 0,
        words: 1,
        kind: ConsensusFieldKind::U32,
    },
    ConsensusFieldLayout {
        name: "expected_current_height",
        offset_words: 1,
        words: 1,
        kind: ConsensusFieldKind::U64,
    },
    ConsensusFieldLayout {
        name: "provided_current_height",
        offset_words: 2,
        words: 1,
        kind: ConsensusFieldKind::U64,
    },
    ConsensusFieldLayout {
        name: "selected_entry_index",
        offset_words: 3,
        words: 1,
        kind: ConsensusFieldKind::U32,
    },
    ConsensusFieldLayout {
        name: "selected_entry_present",
        offset_words: 4,
        words: 1,
        kind: ConsensusFieldKind::Bool,
    },
    ConsensusFieldLayout {
        name: "asset_id",
        offset_words: 5,
        words: 1,
        kind: ConsensusFieldKind::U32,
    },
    ConsensusFieldLayout {
        name: "oracle_feed",
        offset_words: 6,
        words: 1,
        kind: ConsensusFieldKind::U32,
    },
    ConsensusFieldLayout {
        name: "attestation_id",
        offset_words: 7,
        words: 1,
        kind: ConsensusFieldKind::U64,
    },
    ConsensusFieldLayout {
        name: "min_collateral_ratio_ppm",
        offset_words: 8,
        words: 2,
        kind: ConsensusFieldKind::U128LowHigh,
    },
    ConsensusFieldLayout {
        name: "max_mint_per_epoch",
        offset_words: 10,
        words: 2,
        kind: ConsensusFieldKind::U128LowHigh,
    },
    ConsensusFieldLayout {
        name: "oracle_max_age",
        offset_words: 12,
        words: 1,
        kind: ConsensusFieldKind::U64,
    },
    ConsensusFieldLayout {
        name: "oracle_submitted_at",
        offset_words: 13,
        words: 1,
        kind: ConsensusFieldKind::U64,
    },
    ConsensusFieldLayout {
        name: "enabled_at",
        offset_words: 14,
        words: 1,
        kind: ConsensusFieldKind::U64,
    },
    ConsensusFieldLayout {
        name: "retired_present",
        offset_words: 15,
        words: 1,
        kind: ConsensusFieldKind::Bool,
    },
    ConsensusFieldLayout {
        name: "retired_at",
        offset_words: 16,
        words: 1,
        kind: ConsensusFieldKind::U64,
    },
    ConsensusFieldLayout {
        name: "policy_version",
        offset_words: 17,
        words: 1,
        kind: ConsensusFieldKind::U32,
    },
    ConsensusFieldLayout {
        name: "active",
        offset_words: 18,
        words: 1,
        kind: ConsensusFieldKind::Bool,
    },
    ConsensusFieldLayout {
        name: "policy_hash",
        offset_words: 19,
        words: 6,
        kind: ConsensusFieldKind::Digest48,
    },
    ConsensusFieldLayout {
        name: "oracle_commitment",
        offset_words: 25,
        words: 6,
        kind: ConsensusFieldKind::Digest48,
    },
    ConsensusFieldLayout {
        name: "attestation_commitment",
        offset_words: 31,
        words: 6,
        kind: ConsensusFieldKind::Digest48,
    },
    ConsensusFieldLayout {
        name: "attestation_disputed",
        offset_words: 37,
        words: 1,
        kind: ConsensusFieldKind::Bool,
    },
    ConsensusFieldLayout {
        name: "expected_manifest_state_commitment_v1",
        offset_words: 38,
        words: 6,
        kind: ConsensusFieldKind::Digest48,
    },
    ConsensusFieldLayout {
        name: "provided_manifest_state_commitment_v1",
        offset_words: 44,
        words: 6,
        kind: ConsensusFieldKind::Digest48,
    },
];

pub const MAX_PUBLIC_ARGUMENT_BYTES: usize = PUBLIC_ARGUMENT_BYTES;
pub const MAX_STATEMENT_BYTES: usize = STATEMENT_HEADER_BYTES + PUBLIC_ARGUMENT_BYTES;
pub const MAX_PROOF_BODY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SECTION_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SECTIONS: usize = 4_096;
pub const MAX_ENVELOPE_BYTES: usize = 17 * 1024 * 1024;
pub const MAX_CHALLENGE_BYTES: usize = 4_096;
pub const MAX_REJECTION_DRAWS: usize = 16;

pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
pub const EXPECTED_CIRCUIT_VERSION: u16 = 17_537;
pub const EXPECTED_CRYPTO_SUITE: u16 = 17_538;
pub const EXPECTED_FAMILY_ID: u16 = 17_539;
pub const EXPECTED_ACTION_ID: u16 = 17_540;
pub const EXPECTED_NETWORK_ID: u32 = 0x0102_0304;
pub const EXPECTED_BACKEND_ID: u8 = 69;
pub const EXPECTED_PROOF_PROFILE: u8 = 70;
pub const EXPECTED_HX_DOMAIN_SET: u16 = 17_543;
pub const MAX_SIGNED_MAGNITUDE: u64 = (1u64 << 61) - 1;

pub const R1CS_CONSTRAINTS: usize = 20_457_227;
pub const R1CS_PUBLIC_VARIABLES: usize = 10_152;
pub const R1CS_PRIVATE_TRANSPORT_VARIABLES: usize = 77_376;
pub const R1CS_DERIVED_AUXILIARY_VARIABLES: usize = 19_224_027;
pub const R1CS_AUXILIARY_VARIABLES_TOTAL: usize = 19_301_403;
pub const R1CS_NONCONSTANT_VARIABLES: usize = 19_311_555;
pub const R1CS_Z_VECTOR_LENGTH: usize = 19_311_556;
pub const R1CS_MATRIX_NONZEROS: usize = 94_551_238;
pub const CFW26_CANDIDATE_ELL: usize = 1 << 25;
pub const CFW26_CANDIDATE_ROWS: usize = 2 * CFW26_CANDIDATE_ELL;
pub const CFW26_CANDIDATE_COLUMNS: usize = 2 * CFW26_CANDIDATE_ELL;
pub const CFW26_CANDIDATE_PUBLIC_ZERO_PADDING: usize =
    CFW26_CANDIDATE_ELL - (R1CS_PUBLIC_VARIABLES + 1);
pub const CFW26_CANDIDATE_WITNESS_ZERO_PADDING: usize =
    CFW26_CANDIDATE_ELL - R1CS_AUXILIARY_VARIABLES_TOTAL;
pub const CFW26_CANDIDATE_ROW_ZERO_PADDING: usize =
    CFW26_CANDIDATE_ROWS - R1CS_CONSTRAINTS - CFW26_CANDIDATE_WITNESS_ZERO_PADDING;
pub const CFW26_CANDIDATE_EMBEDDED_NONZEROS: usize =
    R1CS_MATRIX_NONZEROS + 2 * CFW26_CANDIDATE_WITNESS_ZERO_PADDING;
pub const CFW26_CANDIDATE_HALF_NUM_VARIABLES: usize = 25;
pub const CFW26_CANDIDATE_HALF_ELEMENTS: usize = 1 << CFW26_CANDIDATE_HALF_NUM_VARIABLES;
pub const CFW26_CANDIDATE_ONE_BASE_FIELD_HALF_RAW_BYTES: usize =
    CFW26_CANDIDATE_HALF_ELEMENTS * core::mem::size_of::<u64>();
pub const CFW26_CANDIDATE_TOTAL_ASSIGNMENT_RAW_BYTES: usize =
    CFW26_CANDIDATE_COLUMNS * core::mem::size_of::<u64>();
pub const E320_EXTENSION_DEGREE: usize = 5;
pub const E320_BASE_COEFFICIENT_BYTES: usize = 8;
pub const E320_CANONICAL_ELEMENT_BYTES: usize = E320_EXTENSION_DEGREE * E320_BASE_COEFFICIENT_BYTES;
pub const CFW26_CANDIDATE_ONE_E320_HALF_RAW_BYTES: usize =
    CFW26_CANDIDATE_HALF_ELEMENTS * E320_CANONICAL_ELEMENT_BYTES;
pub const CFW26_CANDIDATE_TOTAL_E320_ASSIGNMENT_RAW_BYTES: usize =
    CFW26_CANDIDATE_COLUMNS * E320_CANONICAL_ELEMENT_BYTES;
pub const E320_PROFILE_SELECTED: bool = false;
pub const PCS_POLYNOMIAL_COUNT_SELECTED: Option<usize> = None;
pub const CFW26_PAPER_INNER_MASK_ORACLES: usize = 3 * (CFW26_CANDIDATE_HALF_NUM_VARIABLES + 1);
pub const CFW26_PAPER_OUTER_MASK_ORACLES: usize = CFW26_CANDIDATE_HALF_NUM_VARIABLES + 1;
pub const CFW26_PAPER_WITNESS_ORACLES: usize = 1;
pub const CFW26_PAPER_ENCODED_ORACLES: usize =
    CFW26_PAPER_INNER_MASK_ORACLES + CFW26_PAPER_OUTER_MASK_ORACLES + CFW26_PAPER_WITNESS_ORACLES;
pub const CFW26_PAPER_ZK_UNION_MULTIPLIER: usize = 4 * CFW26_CANDIDATE_HALF_NUM_VARIABLES + 5;
pub const CFW26_STEP9_TYPING_DEFECTS: usize = 2;
pub const CFW26_THEOREM_INHERITED: bool = false;
pub const CFW26_ORACLES_MAPPED_TO_PLONKY3_PCS: bool = false;
pub const CFW26_PRINTED_ENDPOINT_STATE_SELECTS_S_AT_ONE: bool = false;
pub const CFW26_TYPED_MAIN_FORM_ROW_DEFINED: bool = false;
pub const CFW26_PRINTED_THEOREM_CARRIER_COMPATIBLE: bool = false;
pub const CFW26_REQUIRED_ENDPOINT_STATE: &str = "pow(1)=(1,1,...)";
pub const CFW26_REQUIRED_MAIN_FORM_TYPING: &str = "row_M(M,alpha)[b]=Mhat(alpha,b,1)";
pub const MODIFIED_BCS_P_LOWER_BOUND_LOG2: usize = CFW26_CANDIDATE_HALF_NUM_VARIABLES;
pub const MODIFIED_BCS_LAMBDA_512_FLOOR_TERM_LOG2: i16 = -101;
pub const MODIFIED_BCS_STRICT_LAMBDA_EXCLUSIVE_FLOOR_BITS: usize = 620;
pub const MODIFIED_BCS_STRICT_LAMBDA_INTEGER_FLOOR_BITS: usize = 621;
pub const MODIFIED_BCS_STRICT_LAMBDA_BYTE_ALIGNED_FLOOR_BITS: usize = 624;
pub const MODIFIED_BCS_BYTE_ALIGNED_FLOOR_SALT_BYTES: usize = 78;
pub const MODIFIED_BCS_FLOOR_DELTA_OVER_64_BYTES: usize = 14;
pub const CFW26_E320_RATE_ONE_INNER_MESSAGE_ELEMENTS: usize = 4;
pub const CFW26_E320_RATE_ONE_OUTER_MASK_ELEMENTS: usize = 8;
pub const CFW26_E320_RATE_ONE_OUTER_MESSAGE_ELEMENTS: usize = 9;
pub const CFW26_E320_RATE_ONE_FINAL_ELEMENTS: usize = 4;
pub const CFW26_E320_RATE_ONE_P_FIELD_ELEMENTS_FLOOR: u64 = CFW26_CANDIDATE_ELL as u64
    + CFW26_PAPER_INNER_MASK_ORACLES as u64 * CFW26_E320_RATE_ONE_INNER_MESSAGE_ELEMENTS as u64
    + CFW26_PAPER_OUTER_MASK_ORACLES as u64 * CFW26_E320_RATE_ONE_OUTER_MASK_ELEMENTS as u64
    + CFW26_PAPER_OUTER_MASK_ORACLES as u64 * CFW26_E320_RATE_ONE_OUTER_MESSAGE_ELEMENTS as u64
    + CFW26_E320_RATE_ONE_FINAL_ELEMENTS as u64;
pub const CFW26_E320_RATE_ONE_P_BITS_FLOOR: u64 = CFW26_E320_RATE_ONE_P_FIELD_ELEMENTS_FLOOR * 320;
pub const MODIFIED_BCS_E320_RATE_ONE_INTEGER_LAMBDA_FLOOR_BITS: usize = 654;
pub const MODIFIED_BCS_E320_RATE_ONE_BYTE_ALIGNED_LAMBDA_FLOOR_BITS: usize = 656;
pub const MODIFIED_BCS_E320_RATE_ONE_FLOOR_SALT_BYTES: usize = 82;
pub const MODIFIED_BCS_E320_RATE_ONE_FLOOR_DELTA_OVER_64_BYTES: usize = 18;
pub const MODIFIED_BCS_TOTAL_IOP_PROOF_LENGTH_P: Option<u64> = None;
pub const MODIFIED_BCS_ACTUAL_MINIMUM_LAMBDA_BITS: Option<usize> = None;
pub const MODIFIED_BCS_SECURITY_SALT_SELECTED: bool = false;
pub const MODIFIED_BCS_SECURITY_SALT_WIRE_LOCATION_ASSIGNED: bool = false;
pub const MODIFIED_BCS_TOTAL_WIRE_DELTA_BYTES: Option<usize> = None;

const _: () = {
    assert!(PUBLIC_BITS == R1CS_PUBLIC_VARIABLES);
    assert!(PRIVATE_TRANSPORT_BITS == R1CS_PRIVATE_TRANSPORT_VARIABLES);
    assert!(PRIVATE_INPUT_LAYOUT_WORDS == 26 + 1 + 224 + 6 + 4);
    assert!(PRIVATE_AUTHORIZATION_LAYOUT_WORDS == 1 + 23 + 23 + 42);
    assert!(
        PRIVATE_TRANSPORT_SECTIONS[6].offset_words + PRIVATE_TRANSPORT_SECTIONS[6].words
            == PRIVATE_TRANSPORT_WORDS
    );
    assert!(
        CONSENSUS_STATE_FIELDS[22].offset_words + CONSENSUS_STATE_FIELDS[22].words
            == CONSENSUS_STATE_WORDS
    );
    assert!(R1CS_PUBLIC_VARIABLES + R1CS_AUXILIARY_VARIABLES_TOTAL == R1CS_NONCONSTANT_VARIABLES);
    assert!(R1CS_NONCONSTANT_VARIABLES + 1 == R1CS_Z_VECTOR_LENGTH);
    assert!(CFW26_CANDIDATE_ELL.is_power_of_two());
    assert!(CFW26_CANDIDATE_ELL >= R1CS_AUXILIARY_VARIABLES_TOTAL);
    assert!(CFW26_CANDIDATE_ROWS >= R1CS_CONSTRAINTS + CFW26_CANDIDATE_WITNESS_ZERO_PADDING);
    assert!(CFW26_PAPER_INNER_MASK_ORACLES == 78);
    assert!(CFW26_PAPER_OUTER_MASK_ORACLES == 26);
    assert!(CFW26_PAPER_ENCODED_ORACLES == 105);
    assert!(CFW26_PAPER_ZK_UNION_MULTIPLIER == 105);
    assert!(MODIFIED_BCS_LAMBDA_512_FLOOR_TERM_LOG2 == 25 - 512 / 4 + 2);
    assert!(MODIFIED_BCS_STRICT_LAMBDA_EXCLUSIVE_FLOOR_BITS == 4 * (25 + 2 + 128));
    assert!(MODIFIED_BCS_STRICT_LAMBDA_INTEGER_FLOOR_BITS == 621);
    assert!(MODIFIED_BCS_STRICT_LAMBDA_BYTE_ALIGNED_FLOOR_BITS == 624);
    assert!(MODIFIED_BCS_BYTE_ALIGNED_FLOOR_SALT_BYTES == 78);
    assert!(CFW26_E320_RATE_ONE_P_FIELD_ELEMENTS_FLOOR == 33_555_190);
    assert!(CFW26_E320_RATE_ONE_P_BITS_FLOOR == 10_737_660_800);
    assert!(MODIFIED_BCS_E320_RATE_ONE_INTEGER_LAMBDA_FLOOR_BITS == 654);
    assert!(MODIFIED_BCS_E320_RATE_ONE_BYTE_ALIGNED_LAMBDA_FLOOR_BITS == 656);
    assert!(MODIFIED_BCS_E320_RATE_ONE_FLOOR_SALT_BYTES == 82);
};

pub const RELATION_MANIFEST_DIGEST: [u8; DIGEST_BYTES] = hex64(
    b"81f88eb0afd355bbd50d90d0760b65e341b4b490a29af3d5e0a8acf1721e4279\
      2bd547fd62559263f1c70edf365fb482fde2f88117c3ae98b2360934a3c75254",
);

pub const PROFILE_RECORD: &[u8] = b"hegemon.hvzk-whir-backend-adapter.source.v1\0plonky3=5df89eeadae18d6935bb874f8a92808dcc200c9d\0relation=81f88eb0afd355bbd50d90d0760b65e341b4b490a29af3d5e0a8acf1721e42792bd547fd62559263f1c70edf365fb482fde2f88117c3ae98b2360934a3c75254\0field=goldilocks\0public_bits=10152\0private_bits=77376\0wire=HGWAWH01/HGWAST01/v1\0hash=SHA-512+SHAKE256-512\0goldilocks_extension=degree5-source-feasible-security-unselected\0production=false";

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("invalid lowercase hex constant"),
    }
}

const fn hex64(input: &[u8; 128]) -> [u8; 64] {
    let mut output = [0u8; 64];
    let mut index = 0;
    while index < 64 {
        output[index] = (hex_nibble(input[2 * index]) << 4) | hex_nibble(input[2 * index + 1]);
        index += 1;
    }
    output
}

pub fn profile_digest() -> [u8; DIGEST_BYTES] {
    framed_hash(
        HashPrimitive::Shake256_512,
        HashRole::ProfileId,
        &[PROFILE_RECORD],
    )
    .expect("the compile-time profile record is within every framing bound")
}

pub fn source_attestation() -> [u8; DIGEST_BYTES] {
    framed_hash(
        HashPrimitive::Sha512,
        HashRole::SourceAttestation,
        &[
            plonky3_api::PLONKY3_HEAD.as_bytes(),
            &RELATION_MANIFEST_DIGEST,
            PROFILE_RECORD,
        ],
    )
    .expect("the compile-time source attestation is within every framing bound")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R1csInputContract {
    pub field_modulus: u64,
    pub public_bits: usize,
    pub private_transport_bits: usize,
    pub constraints: usize,
    pub derived_auxiliary_variables: usize,
    pub z_vector_length: usize,
    pub matrix_nonzeros: usize,
    pub relation_manifest_digest: [u8; DIGEST_BYTES],
}

pub const R1CS_INPUT_CONTRACT: R1csInputContract = R1csInputContract {
    field_modulus: GOLDILOCKS_MODULUS,
    public_bits: R1CS_PUBLIC_VARIABLES,
    private_transport_bits: R1CS_PRIVATE_TRANSPORT_VARIABLES,
    constraints: R1CS_CONSTRAINTS,
    derived_auxiliary_variables: R1CS_DERIVED_AUXILIARY_VARIABLES,
    z_vector_length: R1CS_Z_VECTOR_LENGTH,
    matrix_nonzeros: R1CS_MATRIX_NONZEROS,
    relation_manifest_digest: RELATION_MANIFEST_DIGEST,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    TruncatedHeader,
    EnvelopeTooLarge,
    BadMagic,
    BadWireVersion,
    BadHeaderLength,
    BadDomainVersion,
    BadHashSuite,
    ProfileDigestMismatch,
    RelationDigestMismatch,
    NonzeroReservedFlags,
    StatementLength,
    SectionCount,
    ProofBodyTooLarge,
    DeclaredTotalMismatch,
    TruncatedEnvelope,
    TrailingBytes,
    TruncatedStatementHeader,
    BadStatementMagic,
    BadStatementVersion,
    BadStatementHeaderLength,
    BadStatementDomainVersion,
    BadStatementHashSuite,
    PublicArgumentLength,
    TruncatedPublicArguments,
    StatementTrailingBytes,
    NetworkBindingMismatch,
    ActionBindingMismatch,
    ActionVersionBindingMismatch,
    StatementRelationBindingMismatch,
    BadHxMagic,
    BadHxGrammar,
    NoncanonicalBoolean,
    AllEmptyActivity,
    SignedMagnitudeRange,
    ActivationMismatch,
    DisabledStateSeamNonzero,
    StateSeamNoncanonicalU32,
    StateSeamNoncanonicalBoolean,
    StateSeamNoncanonicalRetirement,
    PrivateTransportLength,
    NonzeroPrivatePadding,
    TruncatedSectionHeader,
    UnknownSectionRole,
    NoncanonicalSectionInstance,
    EmptySectionPayload,
    SectionTooLarge,
    TruncatedSectionPayload,
    ProofBodyTrailingBytes,
    NoncanonicalReencoding,
    GoldilocksLength,
    NoncanonicalGoldilocks,
    ChallengeStateLength,
    ChallengeOutputLength,
    SecuritySaltStateLength,
    SecuritySaltStatementLength,
    SecuritySaltLambdaBelowKnownE320Floor,
    SecuritySaltLambdaNotByteAligned,
    SecuritySaltOutputTooLarge,
    SampleUpperRange,
    ChallengeRejectionCap,
    LengthOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionBlocker {
    RelationIdentityNotProductionFrozen,
    HostOnlyStablecoinBoundaryOpen,
    ExpandedR1csMatrixAbsent,
    ScalarToR1csRefinementAbsent,
    Cfw26Section11SpecificationAmbiguous,
    R1csToConstrainedCodeCarrierAbsent,
    ConstrainedCodeIoppCompositionAbsent,
    IndependentExactSecurityCertificateAbsent,
    ModifiedBcsHidingBoundUnproved,
    CanonicalSecuritySaltWireBindingAbsent,
    ExactShaTranscriptToPlonky3BridgeAbsent,
    ExactShaMmcsToPlonky3BridgeAbsent,
    CompleteWholeViewZeroKnowledgeUnproved,
    ComposedQromPq128LedgerIncomplete,
    CanonicalInnerProofSerializerAbsent,
    RustVerifierRefinementAbsent,
    ConsensusLifecycleRefinementAbsent,
    RetainedProofArtifactAbsent,
    MeasuredProofBytesAbsent,
}

pub const ALL_PRODUCTION_BLOCKERS: &[ProductionBlocker] = &[
    ProductionBlocker::RelationIdentityNotProductionFrozen,
    ProductionBlocker::HostOnlyStablecoinBoundaryOpen,
    ProductionBlocker::ExpandedR1csMatrixAbsent,
    ProductionBlocker::ScalarToR1csRefinementAbsent,
    ProductionBlocker::Cfw26Section11SpecificationAmbiguous,
    ProductionBlocker::R1csToConstrainedCodeCarrierAbsent,
    ProductionBlocker::ConstrainedCodeIoppCompositionAbsent,
    ProductionBlocker::IndependentExactSecurityCertificateAbsent,
    ProductionBlocker::ModifiedBcsHidingBoundUnproved,
    ProductionBlocker::CanonicalSecuritySaltWireBindingAbsent,
    ProductionBlocker::ExactShaTranscriptToPlonky3BridgeAbsent,
    ProductionBlocker::ExactShaMmcsToPlonky3BridgeAbsent,
    ProductionBlocker::CompleteWholeViewZeroKnowledgeUnproved,
    ProductionBlocker::ComposedQromPq128LedgerIncomplete,
    ProductionBlocker::CanonicalInnerProofSerializerAbsent,
    ProductionBlocker::RustVerifierRefinementAbsent,
    ProductionBlocker::ConsensusLifecycleRefinementAbsent,
    ProductionBlocker::RetainedProofArtifactAbsent,
    ProductionBlocker::MeasuredProofBytesAbsent,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterError {
    Parse(ParseError),
    Hash(HashError),
    ProductionBlocked(&'static [ProductionBlocker]),
}

impl From<ParseError> for AdapterError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

impl From<HashError> for AdapterError {
    fn from(value: HashError) -> Self {
        Self::Hash(value)
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "canonical adapter parse error: {error:?}"),
            Self::Hash(error) => write!(formatter, "adapter hash error: {error:?}"),
            Self::ProductionBlocked(blockers) => {
                write!(
                    formatter,
                    "production blocked by {} unresolved gates",
                    blockers.len()
                )
            }
        }
    }
}

impl std::error::Error for AdapterError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HxStatementView<'a> {
    pub raw: &'a [u8],
    pub input_flags: [bool; 2],
    pub output_flags: [bool; 2],
    pub stable_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicInputView<'a> {
    pub raw: &'a [u8],
    pub statement: HxStatementView<'a>,
    pub consensus_state: &'a [u8],
}

impl PublicInputView<'_> {
    pub fn bit(&self, index: usize) -> Option<u8> {
        (index < PUBLIC_BITS).then(|| (self.raw[index / 8] >> (index % 8)) & 1)
    }

    pub fn consensus_state_word(&self, index: usize) -> Option<u64> {
        let start = index.checked_mul(8)?;
        let bytes = self.consensus_state.get(start..start + 8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateInputView<'a> {
    pub raw: &'a [u8],
}

impl PrivateInputView<'_> {
    pub fn transport_word(&self, index: usize) -> Option<u64> {
        let start = index.checked_mul(8)?;
        let bytes = self.raw.get(start..start + 8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }
}

fn parse_bool(byte: u8) -> Result<bool, ParseError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ParseError::NoncanonicalBoolean),
    }
}

fn read_be_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed-width input"),
    )
}

fn read_be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed-width input"),
    )
}

fn read_be_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed-width input"),
    )
}

pub fn parse_hx_statement(bytes: &[u8]) -> Result<HxStatementView<'_>, ParseError> {
    if bytes.len() != HX_STATEMENT_BYTES {
        return Err(ParseError::PublicArgumentLength);
    }
    if &bytes[..8] != b"HX448C02" {
        return Err(ParseError::BadHxMagic);
    }
    if read_be_u16(bytes, 8) != 2 {
        return Err(ParseError::BadHxGrammar);
    }
    let input_flags = [parse_bool(bytes[10])?, parse_bool(bytes[11])?];
    let output_flags = [parse_bool(bytes[12])?, parse_bool(bytes[13])?];
    if !input_flags.into_iter().chain(output_flags).any(|flag| flag) {
        return Err(ParseError::AllEmptyActivity);
    }

    let value_negative = parse_bool(bytes[454])?;
    let value_magnitude = read_be_u64(bytes, 455);
    let stable_enabled = parse_bool(bytes[463])?;
    let issuance_negative = parse_bool(bytes[476])?;
    let issuance_magnitude = read_be_u64(bytes, 477);
    let _ = stable_enabled;
    if value_magnitude > MAX_SIGNED_MAGNITUDE
        || issuance_magnitude > MAX_SIGNED_MAGNITUDE
        || value_negative && value_magnitude == 0
        || issuance_negative && issuance_magnitude == 0
    {
        return Err(ParseError::SignedMagnitudeRange);
    }

    if read_be_u16(bytes, 685) != EXPECTED_CIRCUIT_VERSION
        || read_be_u16(bytes, 687) != EXPECTED_CRYPTO_SUITE
        || read_be_u16(bytes, 689) != EXPECTED_FAMILY_ID
        || read_be_u16(bytes, 691) != EXPECTED_ACTION_ID
        || read_be_u32(bytes, 693) != EXPECTED_NETWORK_ID
        || bytes[697] != EXPECTED_BACKEND_ID
        || bytes[698] != EXPECTED_PROOF_PROFILE
        || read_be_u16(bytes, 699) != EXPECTED_HX_DOMAIN_SET
        || bytes[701..757].iter().all(|byte| *byte == 0)
        || bytes[757..813].iter().all(|byte| *byte == 0)
        || bytes[813..869].iter().all(|byte| *byte == 0)
    {
        return Err(ParseError::ActivationMismatch);
    }

    Ok(HxStatementView {
        raw: bytes,
        input_flags,
        output_flags,
        stable_enabled,
    })
}

fn parse_consensus_state(bytes: &[u8], stable_enabled: bool) -> Result<(), ParseError> {
    if !stable_enabled {
        if bytes.iter().any(|byte| *byte != 0) {
            return Err(ParseError::DisabledStateSeamNonzero);
        }
        return Ok(());
    }

    let word = |index: usize| {
        let start = index * 8;
        u64::from_le_bytes(
            bytes[start..start + 8]
                .try_into()
                .expect("fixed-width consensus-state seam"),
        )
    };
    for index in [0usize, 3, 5, 6, 17] {
        if word(index) > u32::MAX as u64 {
            return Err(ParseError::StateSeamNoncanonicalU32);
        }
    }
    for index in [4usize, 15, 18, 37] {
        if word(index) > 1 {
            return Err(ParseError::StateSeamNoncanonicalBoolean);
        }
    }
    if word(15) == 0 && word(16) != 0 {
        return Err(ParseError::StateSeamNoncanonicalRetirement);
    }
    Ok(())
}

pub fn parse_public_input(bytes: &[u8]) -> Result<PublicInputView<'_>, ParseError> {
    if bytes.len() != PUBLIC_ARGUMENT_BYTES {
        return Err(ParseError::PublicArgumentLength);
    }
    let (statement_bytes, consensus_state) = bytes.split_at(HX_STATEMENT_BYTES);
    let statement = parse_hx_statement(statement_bytes)?;
    parse_consensus_state(consensus_state, statement.stable_enabled)?;
    Ok(PublicInputView {
        raw: bytes,
        statement,
        consensus_state,
    })
}

pub fn parse_private_input(bytes: &[u8]) -> Result<PrivateInputView<'_>, ParseError> {
    if bytes.len() != PRIVATE_TRANSPORT_BYTES {
        return Err(ParseError::PrivateTransportLength);
    }
    // Each 2,147-byte ciphertext occupies 269 transport words. The five
    // trailing bytes in each allocation are canonically zero.
    const CIPHERTEXT0_START: usize = 671 * 8;
    const CIPHERTEXT1_START: usize = 940 * 8;
    const SEMANTIC_CIPHERTEXT_BYTES: usize = 2_147;
    if bytes[CIPHERTEXT0_START + SEMANTIC_CIPHERTEXT_BYTES..CIPHERTEXT1_START]
        .iter()
        .chain(bytes[CIPHERTEXT1_START + SEMANTIC_CIPHERTEXT_BYTES..].iter())
        .any(|byte| *byte != 0)
    {
        return Err(ParseError::NonzeroPrivatePadding);
    }
    Ok(PrivateInputView { raw: bytes })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SectionRole {
    IorPublicInputBinding = 0x0101,
    IorOracleCommitment = 0x0102,
    IorRoundMessage = 0x0103,
    PcsInitialCommitment = 0x0201,
    PcsClaimedEvaluations = 0x0202,
    PcsSumcheckMaskCommitment = 0x0203,
    PcsSumcheckMessage = 0x0204,
    PcsCodeSwitchCommitment = 0x0205,
    PcsCodeSwitchMaskCommitment = 0x0206,
    PcsOutOfDomainAnswers = 0x0207,
    PcsGrindingWitness = 0x0208,
    PcsQueryOpenings = 0x0209,
    PcsMmcsMultiproof = 0x020a,
    PcsMaskedBaseCase = 0x020b,
}

impl SectionRole {
    fn parse(value: u16) -> Result<Self, ParseError> {
        match value {
            0x0101 => Ok(Self::IorPublicInputBinding),
            0x0102 => Ok(Self::IorOracleCommitment),
            0x0103 => Ok(Self::IorRoundMessage),
            0x0201 => Ok(Self::PcsInitialCommitment),
            0x0202 => Ok(Self::PcsClaimedEvaluations),
            0x0203 => Ok(Self::PcsSumcheckMaskCommitment),
            0x0204 => Ok(Self::PcsSumcheckMessage),
            0x0205 => Ok(Self::PcsCodeSwitchCommitment),
            0x0206 => Ok(Self::PcsCodeSwitchMaskCommitment),
            0x0207 => Ok(Self::PcsOutOfDomainAnswers),
            0x0208 => Ok(Self::PcsGrindingWitness),
            0x0209 => Ok(Self::PcsQueryOpenings),
            0x020a => Ok(Self::PcsMmcsMultiproof),
            0x020b => Ok(Self::PcsMaskedBaseCase),
            _ => Err(ParseError::UnknownSectionRole),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofSection<'a> {
    pub role: SectionRole,
    pub instance: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatementFrame<'a> {
    pub raw: &'a [u8],
    pub network_id: u32,
    pub action_kind: u16,
    pub action_version: u16,
    pub relation_digest: [u8; DIGEST_BYTES],
    pub public_input: PublicInputView<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedEnvelope<'a> {
    pub raw: &'a [u8],
    pub profile_digest: [u8; DIGEST_BYTES],
    pub statement: StatementFrame<'a>,
    pub sections: Vec<ProofSection<'a>>,
}

fn get_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ParseError> {
    let end = offset.checked_add(N).ok_or(ParseError::LengthOverflow)?;
    bytes
        .get(offset..end)
        .ok_or(ParseError::TruncatedEnvelope)?
        .try_into()
        .map_err(|_| ParseError::TruncatedEnvelope)
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, ParseError> {
    Ok(u16::from_le_bytes(get_array(bytes, offset)?))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, ParseError> {
    Ok(u32::from_le_bytes(get_array(bytes, offset)?))
}

fn append_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn append_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

pub fn encode_statement(public_arguments: &[u8]) -> Result<Vec<u8>, ParseError> {
    parse_public_input(public_arguments)?;
    let mut output = Vec::with_capacity(MAX_STATEMENT_BYTES);
    output.extend_from_slice(&STATEMENT_MAGIC);
    append_u16(&mut output, STATEMENT_VERSION);
    append_u16(&mut output, STATEMENT_HEADER_BYTES as u16);
    append_u32(&mut output, EXPECTED_NETWORK_ID);
    append_u16(&mut output, EXPECTED_ACTION_ID);
    append_u16(&mut output, EXPECTED_CIRCUIT_VERSION);
    append_u16(&mut output, DOMAIN_SET_VERSION);
    append_u16(&mut output, HASH_SUITE_ID);
    output.extend_from_slice(&RELATION_MANIFEST_DIGEST);
    append_u32(&mut output, PUBLIC_ARGUMENT_BYTES as u32);
    output.extend_from_slice(public_arguments);
    Ok(output)
}

pub fn parse_statement(bytes: &[u8]) -> Result<StatementFrame<'_>, ParseError> {
    if bytes.len() < STATEMENT_HEADER_BYTES {
        return Err(ParseError::TruncatedStatementHeader);
    }
    if &bytes[..8] != STATEMENT_MAGIC.as_slice() {
        return Err(ParseError::BadStatementMagic);
    }
    if le_u16(bytes, 8)? != STATEMENT_VERSION {
        return Err(ParseError::BadStatementVersion);
    }
    if le_u16(bytes, 10)? as usize != STATEMENT_HEADER_BYTES {
        return Err(ParseError::BadStatementHeaderLength);
    }
    if le_u16(bytes, 20)? != DOMAIN_SET_VERSION {
        return Err(ParseError::BadStatementDomainVersion);
    }
    if le_u16(bytes, 22)? != HASH_SUITE_ID {
        return Err(ParseError::BadStatementHashSuite);
    }
    let relation_digest = get_array::<DIGEST_BYTES>(bytes, 24)?;
    if relation_digest != RELATION_MANIFEST_DIGEST {
        return Err(ParseError::StatementRelationBindingMismatch);
    }
    let public_length = le_u32(bytes, 88)? as usize;
    if public_length != PUBLIC_ARGUMENT_BYTES {
        return Err(ParseError::PublicArgumentLength);
    }
    let expected = STATEMENT_HEADER_BYTES
        .checked_add(public_length)
        .ok_or(ParseError::LengthOverflow)?;
    if bytes.len() < expected {
        return Err(ParseError::TruncatedPublicArguments);
    }
    if bytes.len() > expected {
        return Err(ParseError::StatementTrailingBytes);
    }
    let network_id = le_u32(bytes, 12)?;
    let action_kind = le_u16(bytes, 16)?;
    let action_version = le_u16(bytes, 18)?;
    if network_id != EXPECTED_NETWORK_ID {
        return Err(ParseError::NetworkBindingMismatch);
    }
    if action_kind != EXPECTED_ACTION_ID {
        return Err(ParseError::ActionBindingMismatch);
    }
    if action_version != EXPECTED_CIRCUIT_VERSION {
        return Err(ParseError::ActionVersionBindingMismatch);
    }
    let public_input = parse_public_input(&bytes[STATEMENT_HEADER_BYTES..])?;
    Ok(StatementFrame {
        raw: bytes,
        network_id,
        action_kind,
        action_version,
        relation_digest,
        public_input,
    })
}

fn validate_sections(sections: &[ProofSection<'_>]) -> Result<(), ParseError> {
    if sections.is_empty() || sections.len() > MAX_SECTIONS {
        return Err(ParseError::SectionCount);
    }
    let mut next_instances = [0u16; 14];
    let mut body_size = 0usize;
    for section in sections {
        let role_index = role_index(section.role);
        if section.instance != next_instances[role_index] {
            return Err(ParseError::NoncanonicalSectionInstance);
        }
        next_instances[role_index] = next_instances[role_index]
            .checked_add(1)
            .ok_or(ParseError::NoncanonicalSectionInstance)?;
        if section.payload.is_empty() {
            return Err(ParseError::EmptySectionPayload);
        }
        if section.payload.len() > MAX_SECTION_BYTES {
            return Err(ParseError::SectionTooLarge);
        }
        body_size = body_size
            .checked_add(SECTION_HEADER_BYTES)
            .and_then(|size| size.checked_add(section.payload.len()))
            .ok_or(ParseError::LengthOverflow)?;
        if body_size > MAX_PROOF_BODY_BYTES {
            return Err(ParseError::ProofBodyTooLarge);
        }
    }
    Ok(())
}

fn role_index(role: SectionRole) -> usize {
    match role {
        SectionRole::IorPublicInputBinding => 0,
        SectionRole::IorOracleCommitment => 1,
        SectionRole::IorRoundMessage => 2,
        SectionRole::PcsInitialCommitment => 3,
        SectionRole::PcsClaimedEvaluations => 4,
        SectionRole::PcsSumcheckMaskCommitment => 5,
        SectionRole::PcsSumcheckMessage => 6,
        SectionRole::PcsCodeSwitchCommitment => 7,
        SectionRole::PcsCodeSwitchMaskCommitment => 8,
        SectionRole::PcsOutOfDomainAnswers => 9,
        SectionRole::PcsGrindingWitness => 10,
        SectionRole::PcsQueryOpenings => 11,
        SectionRole::PcsMmcsMultiproof => 12,
        SectionRole::PcsMaskedBaseCase => 13,
    }
}

pub fn encode_envelope(
    public_arguments: &[u8],
    sections: &[ProofSection<'_>],
) -> Result<Vec<u8>, ParseError> {
    let statement = encode_statement(public_arguments)?;
    validate_sections(sections)?;
    let body_length = sections.iter().try_fold(0usize, |size, section| {
        size.checked_add(SECTION_HEADER_BYTES + section.payload.len())
            .ok_or(ParseError::LengthOverflow)
    })?;
    let total_length = WIRE_HEADER_BYTES
        .checked_add(statement.len())
        .and_then(|size| size.checked_add(body_length))
        .ok_or(ParseError::LengthOverflow)?;
    if total_length > MAX_ENVELOPE_BYTES {
        return Err(ParseError::EnvelopeTooLarge);
    }

    let mut output = Vec::with_capacity(total_length);
    output.extend_from_slice(&WIRE_MAGIC);
    append_u16(&mut output, WIRE_VERSION);
    append_u16(&mut output, WIRE_HEADER_BYTES as u16);
    append_u16(&mut output, DOMAIN_SET_VERSION);
    append_u16(&mut output, HASH_SUITE_ID);
    output.extend_from_slice(&profile_digest());
    append_u32(&mut output, EXPECTED_NETWORK_ID);
    append_u16(&mut output, EXPECTED_ACTION_ID);
    append_u16(&mut output, EXPECTED_CIRCUIT_VERSION);
    output.extend_from_slice(&RELATION_MANIFEST_DIGEST);
    append_u32(&mut output, statement.len() as u32);
    append_u16(&mut output, sections.len() as u16);
    append_u16(&mut output, 0);
    append_u32(&mut output, body_length as u32);
    append_u32(&mut output, total_length as u32);
    output.extend_from_slice(&statement);
    for section in sections {
        append_u16(&mut output, section.role as u16);
        append_u16(&mut output, section.instance);
        append_u32(&mut output, section.payload.len() as u32);
        output.extend_from_slice(section.payload);
    }
    debug_assert_eq!(output.len(), total_length);
    Ok(output)
}

pub fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope<'_>, ParseError> {
    if bytes.len() < WIRE_HEADER_BYTES {
        return Err(ParseError::TruncatedHeader);
    }
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(ParseError::EnvelopeTooLarge);
    }
    if &bytes[..8] != WIRE_MAGIC.as_slice() {
        return Err(ParseError::BadMagic);
    }
    if le_u16(bytes, 8)? != WIRE_VERSION {
        return Err(ParseError::BadWireVersion);
    }
    if le_u16(bytes, 10)? as usize != WIRE_HEADER_BYTES {
        return Err(ParseError::BadHeaderLength);
    }
    if le_u16(bytes, 12)? != DOMAIN_SET_VERSION {
        return Err(ParseError::BadDomainVersion);
    }
    if le_u16(bytes, 14)? != HASH_SUITE_ID {
        return Err(ParseError::BadHashSuite);
    }
    let encoded_profile_digest = get_array::<DIGEST_BYTES>(bytes, 16)?;
    if encoded_profile_digest != profile_digest() {
        return Err(ParseError::ProfileDigestMismatch);
    }
    let network_id = le_u32(bytes, 80)?;
    let action_kind = le_u16(bytes, 84)?;
    let action_version = le_u16(bytes, 86)?;
    let relation_digest = get_array::<DIGEST_BYTES>(bytes, 88)?;
    if relation_digest != RELATION_MANIFEST_DIGEST {
        return Err(ParseError::RelationDigestMismatch);
    }
    let statement_length = le_u32(bytes, 152)? as usize;
    let section_count = le_u16(bytes, 156)? as usize;
    if le_u16(bytes, 158)? != 0 {
        return Err(ParseError::NonzeroReservedFlags);
    }
    let body_length = le_u32(bytes, 160)? as usize;
    let total_length = le_u32(bytes, 164)? as usize;
    if statement_length != MAX_STATEMENT_BYTES {
        return Err(ParseError::StatementLength);
    }
    if section_count == 0 || section_count > MAX_SECTIONS {
        return Err(ParseError::SectionCount);
    }
    if body_length > MAX_PROOF_BODY_BYTES {
        return Err(ParseError::ProofBodyTooLarge);
    }
    let expected_total = WIRE_HEADER_BYTES
        .checked_add(statement_length)
        .and_then(|size| size.checked_add(body_length))
        .ok_or(ParseError::LengthOverflow)?;
    if total_length != expected_total {
        return Err(ParseError::DeclaredTotalMismatch);
    }
    if total_length > MAX_ENVELOPE_BYTES {
        return Err(ParseError::EnvelopeTooLarge);
    }
    if bytes.len() < total_length {
        return Err(ParseError::TruncatedEnvelope);
    }
    if bytes.len() > total_length {
        return Err(ParseError::TrailingBytes);
    }

    let statement_end = WIRE_HEADER_BYTES + statement_length;
    let statement = parse_statement(&bytes[WIRE_HEADER_BYTES..statement_end])?;
    if network_id != statement.network_id {
        return Err(ParseError::NetworkBindingMismatch);
    }
    if action_kind != statement.action_kind {
        return Err(ParseError::ActionBindingMismatch);
    }
    if action_version != statement.action_version {
        return Err(ParseError::ActionVersionBindingMismatch);
    }
    if relation_digest != statement.relation_digest {
        return Err(ParseError::StatementRelationBindingMismatch);
    }

    let body_end = statement_end + body_length;
    let mut cursor = statement_end;
    let mut sections = Vec::with_capacity(section_count);
    let mut next_instances = [0u16; 14];
    for _ in 0..section_count {
        if body_end.saturating_sub(cursor) < SECTION_HEADER_BYTES {
            return Err(ParseError::TruncatedSectionHeader);
        }
        let role = SectionRole::parse(le_u16(bytes, cursor)?)?;
        let instance = le_u16(bytes, cursor + 2)?;
        let payload_length = le_u32(bytes, cursor + 4)? as usize;
        cursor += SECTION_HEADER_BYTES;
        let role_index = role_index(role);
        if instance != next_instances[role_index] {
            return Err(ParseError::NoncanonicalSectionInstance);
        }
        next_instances[role_index] = next_instances[role_index]
            .checked_add(1)
            .ok_or(ParseError::NoncanonicalSectionInstance)?;
        if payload_length == 0 {
            return Err(ParseError::EmptySectionPayload);
        }
        if payload_length > MAX_SECTION_BYTES {
            return Err(ParseError::SectionTooLarge);
        }
        let payload_end = cursor
            .checked_add(payload_length)
            .ok_or(ParseError::LengthOverflow)?;
        if payload_end > body_end {
            return Err(ParseError::TruncatedSectionPayload);
        }
        sections.push(ProofSection {
            role,
            instance,
            payload: &bytes[cursor..payload_end],
        });
        cursor = payload_end;
    }
    if cursor != body_end {
        return Err(ParseError::ProofBodyTrailingBytes);
    }

    let parsed = ParsedEnvelope {
        raw: bytes,
        profile_digest: encoded_profile_digest,
        statement,
        sections,
    };
    let canonical = encode_envelope(parsed.statement.public_input.raw, &parsed.sections)?;
    if canonical.as_slice() != bytes {
        return Err(ParseError::NoncanonicalReencoding);
    }
    Ok(parsed)
}

pub fn statement_id(statement_bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], AdapterError> {
    parse_statement(statement_bytes)?;
    Ok(framed_hash(
        HashPrimitive::Shake256_512,
        HashRole::StatementId,
        &[statement_bytes],
    )?)
}

pub fn transcript_digest(
    envelope: &ParsedEnvelope<'_>,
) -> Result<[u8; DIGEST_BYTES], AdapterError> {
    let network = envelope.statement.network_id.to_le_bytes();
    let action = envelope.statement.action_kind.to_le_bytes();
    let version = envelope.statement.action_version.to_le_bytes();
    let mut state = framed_hash(
        HashPrimitive::Shake256_512,
        HashRole::TranscriptInit,
        &[
            &envelope.profile_digest,
            &envelope.statement.relation_digest,
            &network,
            &action,
            &version,
            envelope.statement.raw,
        ],
    )?;
    for (step, section) in envelope.sections.iter().enumerate() {
        let step = (step as u32).to_le_bytes();
        let role = (section.role as u16).to_le_bytes();
        let instance = section.instance.to_le_bytes();
        state = framed_hash(
            HashPrimitive::Shake256_512,
            HashRole::TranscriptAbsorbSection,
            &[&state, &step, &role, &instance, section.payload],
        )?;
    }
    let statement_id = statement_id(envelope.statement.raw)?;
    Ok(framed_hash(
        HashPrimitive::Shake256_512,
        HashRole::ProofId,
        &[&state, &statement_id],
    )?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ChallengeRole {
    IorConstraintCombination = 1,
    PcsInitialCombination = 2,
    PcsSumcheckFold = 3,
    PcsCodeSwitch = 4,
    PcsOutOfDomainPoint = 5,
    PcsQueryIndex = 6,
    PcsMaskCoefficient = 7,
    PcsGrinding = 8,
    PcsMaskedBaseCase = 9,
}

pub fn challenge_bytes(
    transcript_state: &[u8],
    role: ChallengeRole,
    ordinal: u64,
    output_bytes: usize,
) -> Result<Vec<u8>, AdapterError> {
    if transcript_state.len() != DIGEST_BYTES {
        return Err(ParseError::ChallengeStateLength.into());
    }
    if output_bytes == 0 || output_bytes > MAX_CHALLENGE_BYTES {
        return Err(ParseError::ChallengeOutputLength.into());
    }
    let mut output = Vec::with_capacity(output_bytes);
    let role = (role as u16).to_le_bytes();
    let ordinal = ordinal.to_le_bytes();
    let output_length = (output_bytes as u32).to_le_bytes();
    let mut block = 0u32;
    while output.len() < output_bytes {
        let block_bytes = block.to_le_bytes();
        let digest = framed_hash(
            HashPrimitive::Shake256_512,
            HashRole::TranscriptChallenge,
            &[
                transcript_state,
                &role,
                &ordinal,
                &output_length,
                &block_bytes,
            ],
        )?;
        let take = (output_bytes - output.len()).min(DIGEST_BYTES);
        output.extend_from_slice(&digest[..take]);
        block = block.checked_add(1).ok_or(ParseError::LengthOverflow)?;
    }
    Ok(output)
}

/// Derives an unselected, byte-aligned SHAKE256 salt candidate. The 656-bit
/// lower bound accepted here is necessary only for the pinned E320, rate-one
/// message floor. Actual code lengths and randomness can make the total IOP
/// proof length `p` larger. Callers must not interpret successful derivation as
/// security-profile or production admission.
pub fn derive_unselected_security_salt(
    transcript_state: &[u8],
    statement_digest: &[u8],
    lambda_bits: usize,
) -> Result<Vec<u8>, AdapterError> {
    if transcript_state.len() != DIGEST_BYTES {
        return Err(ParseError::SecuritySaltStateLength.into());
    }
    if statement_digest.len() != DIGEST_BYTES {
        return Err(ParseError::SecuritySaltStatementLength.into());
    }
    if lambda_bits < MODIFIED_BCS_E320_RATE_ONE_BYTE_ALIGNED_LAMBDA_FLOOR_BITS {
        return Err(ParseError::SecuritySaltLambdaBelowKnownE320Floor.into());
    }
    if lambda_bits % 8 != 0 {
        return Err(ParseError::SecuritySaltLambdaNotByteAligned.into());
    }
    let output_bytes = lambda_bits / 8;
    if output_bytes > MAX_CHALLENGE_BYTES {
        return Err(ParseError::SecuritySaltOutputTooLarge.into());
    }
    let lambda = (lambda_bits as u64).to_le_bytes();
    let profile = profile_digest();
    Ok(framed_shake256(
        HashRole::CandidateSecuritySalt,
        &[
            &profile,
            &RELATION_MANIFEST_DIGEST,
            transcript_state,
            statement_digest,
            &lambda,
        ],
        output_bytes,
    )?)
}

pub fn sample_uniform_index(
    transcript_state: &[u8],
    ordinal: u64,
    upper: u64,
) -> Result<u64, AdapterError> {
    if upper == 0 || upper > 1u64 << 63 {
        return Err(ParseError::SampleUpperRange.into());
    }
    let zone = u64::MAX - (u64::MAX % upper);
    let bytes = challenge_bytes(
        transcript_state,
        ChallengeRole::PcsQueryIndex,
        ordinal,
        MAX_REJECTION_DRAWS * 8,
    )?;
    for chunk in bytes.chunks_exact(8) {
        let candidate = u64::from_le_bytes(chunk.try_into().expect("eight-byte draw"));
        if candidate < zone {
            return Ok(candidate % upper);
        }
    }
    Err(ParseError::ChallengeRejectionCap.into())
}

pub fn encode_goldilocks(value: u64) -> Result<[u8; 8], ParseError> {
    if value >= GOLDILOCKS_MODULUS {
        return Err(ParseError::NoncanonicalGoldilocks);
    }
    Ok(value.to_le_bytes())
}

pub fn decode_goldilocks(bytes: &[u8]) -> Result<u64, ParseError> {
    let encoded: [u8; 8] = bytes.try_into().map_err(|_| ParseError::GoldilocksLength)?;
    let value = u64::from_le_bytes(encoded);
    if value >= GOLDILOCKS_MODULUS {
        return Err(ParseError::NoncanonicalGoldilocks);
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OddFieldWhirBackendAdapter;

impl OddFieldWhirBackendAdapter {
    pub fn validate_inputs<'a>(
        &self,
        public_input: &'a [u8],
        private_input: &'a [u8],
    ) -> Result<(PublicInputView<'a>, PrivateInputView<'a>), AdapterError> {
        Ok((
            parse_public_input(public_input)?,
            parse_private_input(private_input)?,
        ))
    }

    pub fn inspect_research_envelope<'a>(
        &self,
        encoded: &'a [u8],
    ) -> Result<ParsedEnvelope<'a>, AdapterError> {
        Ok(parse_envelope(encoded)?)
    }

    pub fn prove(
        &self,
        public_input: &[u8],
        private_input: &[u8],
    ) -> Result<Vec<u8>, AdapterError> {
        self.validate_inputs(public_input, private_input)?;
        Err(AdapterError::ProductionBlocked(ALL_PRODUCTION_BLOCKERS))
    }

    pub fn verify(&self, encoded: &[u8]) -> Result<(), AdapterError> {
        self.inspect_research_envelope(encoded)?;
        Err(AdapterError::ProductionBlocked(ALL_PRODUCTION_BLOCKERS))
    }

    pub const fn require_production_authority(&self) -> Result<(), AdapterError> {
        Err(AdapterError::ProductionBlocked(ALL_PRODUCTION_BLOCKERS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_arguments() -> Vec<u8> {
        let mut bytes = vec![0u8; PUBLIC_ARGUMENT_BYTES];
        bytes[..8].copy_from_slice(b"HX448C02");
        bytes[8..10].copy_from_slice(&2u16.to_be_bytes());
        bytes[10..14].copy_from_slice(&[1, 1, 1, 1]);
        bytes[685..687].copy_from_slice(&EXPECTED_CIRCUIT_VERSION.to_be_bytes());
        bytes[687..689].copy_from_slice(&EXPECTED_CRYPTO_SUITE.to_be_bytes());
        bytes[689..691].copy_from_slice(&EXPECTED_FAMILY_ID.to_be_bytes());
        bytes[691..693].copy_from_slice(&EXPECTED_ACTION_ID.to_be_bytes());
        bytes[693..697].copy_from_slice(&EXPECTED_NETWORK_ID.to_be_bytes());
        bytes[697] = EXPECTED_BACKEND_ID;
        bytes[698] = EXPECTED_PROOF_PROFILE;
        bytes[699..701].copy_from_slice(&EXPECTED_HX_DOMAIN_SET.to_be_bytes());
        bytes[701] = 1;
        bytes[757] = 2;
        bytes[813] = 3;
        bytes
    }

    #[test]
    fn codec_round_trip_remains_research_only() {
        let public = public_arguments();
        let sections = [
            ProofSection {
                role: SectionRole::IorPublicInputBinding,
                instance: 0,
                payload: b"unimplemented-section11-carrier",
            },
            ProofSection {
                role: SectionRole::PcsInitialCommitment,
                instance: 0,
                payload: b"opaque-not-a-plonky3-proof",
            },
        ];
        let encoded = encode_envelope(&public, &sections).unwrap();
        let parsed = parse_envelope(&encoded).unwrap();
        assert_eq!(parsed.statement.public_input.raw, public);
        assert!(matches!(
            OddFieldWhirBackendAdapter.verify(&encoded),
            Err(AdapterError::ProductionBlocked(_))
        ));
    }

    #[test]
    fn private_padding_and_goldilocks_are_canonical() {
        let mut private = vec![0u8; PRIVATE_TRANSPORT_BYTES];
        assert!(parse_private_input(&private).is_ok());
        private[PRIVATE_TRANSPORT_BYTES - 1] = 1;
        assert_eq!(
            parse_private_input(&private),
            Err(ParseError::NonzeroPrivatePadding)
        );
        assert_eq!(
            decode_goldilocks(&GOLDILOCKS_MODULUS.to_le_bytes()),
            Err(ParseError::NoncanonicalGoldilocks)
        );
    }

    #[test]
    fn state_seam_and_unselected_salt_floor_are_canonical() {
        let mut public = public_arguments();
        public[HX_STATEMENT_BYTES] = 1;
        assert_eq!(
            parse_public_input(&public),
            Err(ParseError::DisabledStateSeamNonzero)
        );

        assert_eq!(
            derive_unselected_security_salt(&[0u8; 64], &[0u8; 64], 624),
            Err(AdapterError::Parse(
                ParseError::SecuritySaltLambdaBelowKnownE320Floor
            ))
        );
        let salt = derive_unselected_security_salt(&[0u8; 64], &[0u8; 64], 656).unwrap();
        assert_eq!(salt.len(), 82);
        assert_eq!(
            sha512(&salt),
            hex64(
                b"3b87c9b138209e269726b6cf26c2b0a63baf472d6410bffa3db5a51a9dd3ac9e\
                  2a715b357bf966de75064a23d99e35eec7e372252ea076b0f3e14bd4f4833888"
            )
        );
        assert!(!MODIFIED_BCS_SECURITY_SALT_SELECTED);
        assert_eq!(MODIFIED_BCS_ACTUAL_MINIMUM_LAMBDA_BITS, None);
    }
}
