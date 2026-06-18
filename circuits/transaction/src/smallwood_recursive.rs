use std::io::Cursor;

use protocol_versioning::{tx_proof_backend_for_version, TxProofBackend, VersionBinding};
use serde::{Deserialize, Serialize};
use synthetic_crypto::hashes::blake3_384;

use crate::{
    error::TransactionCircuitError,
    smallwood_engine::{
        build_smallwood_verifier_trace_v1, ensure_canonical_smallwood_proof_bytes,
        projected_candidate_proof_bytes_with_profile, prove_statement_with_transcript_backend,
        smallwood_no_grinding_profile_for_arithmetization,
        verify_statement_with_transcript_backend, SmallwoodArithmetization,
        SmallwoodTranscriptBackend, SmallwoodVerifierTraceV1,
    },
    smallwood_semantics::SmallwoodConstraintAdapter,
};

pub const SMALLWOOD_RECURSIVE_DESCRIPTOR_DOMAIN: &[u8] =
    b"hegemon.smallwood.recursive-descriptor.v1";
pub const SMALLWOOD_RECURSIVE_ENVELOPE_DOMAIN: &[u8] = b"hegemon.smallwood.recursive-envelope.v1";
pub const SMALLWOOD_RECURSIVE_BINDING_DOMAIN: &[u8] = b"hegemon.smallwood.recursive-binding.v1";
pub const SMALLWOOD_RECURSIVE_ENCODING_DOMAIN: &[u8] =
    b"hegemon.smallwood.recursive-proof-encoding.v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmallwoodRecursiveProfileTagV1 {
    A,
    B,
}

impl SmallwoodRecursiveProfileTagV1 {
    pub fn tag(self) -> u32 {
        match self {
            Self::A => 1,
            Self::B => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmallwoodRecursiveRelationKindV1 {
    BaseA,
    StepA,
    StepB,
    ChunkA,
    MergeA,
    MergeB,
    CarryA,
    CarryB,
}

impl SmallwoodRecursiveRelationKindV1 {
    pub fn tag(self) -> u32 {
        match self {
            Self::BaseA => 1,
            Self::StepA => 2,
            Self::StepB => 3,
            Self::ChunkA => 4,
            Self::MergeA => 5,
            Self::MergeB => 6,
            Self::CarryA => 7,
            Self::CarryB => 8,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursiveSmallwoodProfileV1 {
    pub version: VersionBinding,
    pub profile: SmallwoodRecursiveProfileTagV1,
    pub arithmetization: SmallwoodArithmetization,
}

impl RecursiveSmallwoodProfileV1 {
    fn transcript_backend(&self) -> SmallwoodTranscriptBackend {
        SmallwoodTranscriptBackend::Poseidon2
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodRecursiveVerifierDescriptorV1 {
    pub version: VersionBinding,
    pub arithmetization: SmallwoodArithmetization,
    pub profile: SmallwoodRecursiveProfileTagV1,
    pub relation_kind: SmallwoodRecursiveRelationKindV1,
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub vk_digest: [u8; 32],
}

impl SmallwoodRecursiveVerifierDescriptorV1 {
    pub fn serialized_v1(&self) -> Vec<u8> {
        serialize_smallwood_recursive_verifier_descriptor_v1(self)
    }

    pub fn digest_v1(&self) -> [u8; 48] {
        smallwood_recursive_verifier_descriptor_digest_v1(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodRecursiveProofEnvelopeV1 {
    pub descriptor: SmallwoodRecursiveVerifierDescriptorV1,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmallwoodRecursiveVerifierTraceV1 {
    pub descriptor: SmallwoodRecursiveVerifierDescriptorV1,
    pub binded_data: Vec<u8>,
    pub trace: SmallwoodVerifierTraceV1,
}

impl SmallwoodRecursiveVerifierTraceV1 {
    pub fn validate_sections_v1(&self) -> Result<(), TransactionCircuitError> {
        self.trace.validate_sections_v1()
    }

    pub fn flatten_transcript_section_words_v1(&self) -> Vec<u64> {
        self.trace.flatten_transcript_section_words_v1()
    }

    pub fn flatten_pcs_section_words_v1(&self) -> Vec<u64> {
        self.trace.flatten_pcs_section_words_v1()
    }

    pub fn flatten_decs_section_words_v1(&self) -> Vec<u64> {
        self.trace.flatten_decs_section_words_v1()
    }

    pub fn flatten_merkle_section_words_v1(&self) -> Vec<u64> {
        self.trace.flatten_merkle_section_words_v1()
    }
}

impl SmallwoodRecursiveProofEnvelopeV1 {
    pub fn descriptor_ref(&self) -> &SmallwoodRecursiveVerifierDescriptorV1 {
        &self.descriptor
    }

    pub fn proof_bytes_ref(&self) -> &[u8] {
        &self.proof_bytes
    }

    pub fn into_parts(self) -> (SmallwoodRecursiveVerifierDescriptorV1, Vec<u8>) {
        (self.descriptor, self.proof_bytes)
    }
}

pub fn recursive_profile_a_v1(version: VersionBinding) -> RecursiveSmallwoodProfileV1 {
    RecursiveSmallwoodProfileV1 {
        version,
        profile: SmallwoodRecursiveProfileTagV1::A,
        arithmetization: SmallwoodArithmetization::Bridge64V1,
    }
}

pub fn recursive_profile_b_v1(version: VersionBinding) -> RecursiveSmallwoodProfileV1 {
    RecursiveSmallwoodProfileV1 {
        version,
        profile: SmallwoodRecursiveProfileTagV1::B,
        arithmetization: SmallwoodArithmetization::Bridge64V1,
    }
}

pub fn recursive_descriptor_v1(
    profile: &RecursiveSmallwoodProfileV1,
    relation_kind: SmallwoodRecursiveRelationKindV1,
    relation_id: [u8; 32],
    shape_digest: [u8; 32],
    vk_digest: [u8; 32],
) -> SmallwoodRecursiveVerifierDescriptorV1 {
    SmallwoodRecursiveVerifierDescriptorV1 {
        version: profile.version,
        arithmetization: profile.arithmetization,
        profile: profile.profile,
        relation_kind,
        relation_id,
        shape_digest,
        vk_digest,
    }
}

pub fn serialize_smallwood_recursive_verifier_descriptor_v1(
    descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(SMALLWOOD_RECURSIVE_DESCRIPTOR_DOMAIN);
    bytes.extend_from_slice(&descriptor.version.circuit.to_le_bytes());
    bytes.extend_from_slice(&descriptor.version.crypto.to_le_bytes());
    bytes.extend_from_slice(&(descriptor.arithmetization as u32).to_le_bytes());
    bytes.extend_from_slice(&descriptor.profile.tag().to_le_bytes());
    bytes.extend_from_slice(&descriptor.relation_kind.tag().to_le_bytes());
    bytes.extend_from_slice(&descriptor.relation_id);
    bytes.extend_from_slice(&descriptor.shape_digest);
    bytes.extend_from_slice(&descriptor.vk_digest);
    bytes
}

pub fn smallwood_recursive_verifier_descriptor_digest_v1(
    descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
) -> [u8; 48] {
    blake3_384(&serialize_smallwood_recursive_verifier_descriptor_v1(
        descriptor,
    ))
}

pub fn smallwood_recursive_proof_encoding_digest_v1() -> [u8; 48] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SMALLWOOD_RECURSIVE_ENCODING_DOMAIN);
    bytes.extend_from_slice(b"bincode");
    bytes.extend_from_slice(b"descriptor");
    bytes.extend_from_slice(b"proof_len:u32");
    bytes.extend_from_slice(b"proof_bytes:opaque");
    blake3_384(&bytes)
}

pub fn encode_smallwood_recursive_proof_envelope_v1(
    envelope: &SmallwoodRecursiveProofEnvelopeV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    bincode::serialize(envelope).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to serialize smallwood recursive proof envelope: {err}"
        ))
    })
}

pub fn decode_smallwood_recursive_proof_envelope_v1(
    bytes: &[u8],
) -> Result<SmallwoodRecursiveProofEnvelopeV1, TransactionCircuitError> {
    let mut cursor = Cursor::new(bytes);
    let envelope: SmallwoodRecursiveProofEnvelopeV1 = bincode::deserialize_from(&mut cursor)
        .map_err(|err| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "failed to decode smallwood recursive proof envelope: {err}"
            ))
        })?;
    if cursor.position() as usize != bytes.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood recursive proof envelope has trailing bytes",
        ));
    }
    let canonical = bincode::serialize(&envelope).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to reserialize smallwood recursive proof envelope: {err}"
        ))
    })?;
    if canonical != bytes {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood recursive proof envelope must use canonical serialization",
        ));
    }
    Ok(envelope)
}

pub fn parse_smallwood_recursive_proof_envelope_v1(
    bytes: &[u8],
) -> Result<SmallwoodRecursiveProofEnvelopeV1, TransactionCircuitError> {
    decode_smallwood_recursive_proof_envelope_v1(bytes)
}

pub fn projected_smallwood_recursive_envelope_bytes_v1(
    descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    proof_bytes_len: usize,
) -> Result<usize, TransactionCircuitError> {
    Ok(
        encode_smallwood_recursive_proof_envelope_v1(&SmallwoodRecursiveProofEnvelopeV1 {
            descriptor: descriptor.clone(),
            proof_bytes: vec![0u8; proof_bytes_len],
        })?
        .len(),
    )
}

fn ensure_recursive_profile(
    profile: &RecursiveSmallwoodProfileV1,
) -> Result<(), TransactionCircuitError> {
    if tx_proof_backend_for_version(profile.version) != Some(TxProofBackend::SmallwoodCandidate) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive Smallwood profile requires a SmallwoodCandidate version binding",
        ));
    }
    Ok(())
}

fn ensure_recursive_descriptor_matches(
    profile: &RecursiveSmallwoodProfileV1,
    descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<(), TransactionCircuitError> {
    ensure_recursive_profile(profile)?;
    if descriptor.version != profile.version {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive descriptor version does not match profile",
        ));
    }
    if descriptor.profile != profile.profile {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive descriptor profile tag does not match profile",
        ));
    }
    if descriptor.arithmetization != profile.arithmetization {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive descriptor arithmetization does not match profile",
        ));
    }
    if statement.arithmetization() != profile.arithmetization {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive statement arithmetization does not match profile",
        ));
    }
    Ok(())
}

pub fn recursive_binding_bytes_v1(
    descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    binded_data: &[u8],
) -> Vec<u8> {
    let descriptor_bytes = serialize_smallwood_recursive_verifier_descriptor_v1(descriptor);
    let mut out = Vec::with_capacity(
        SMALLWOOD_RECURSIVE_BINDING_DOMAIN.len()
            + 4
            + descriptor_bytes.len()
            + 4
            + binded_data.len(),
    );
    out.extend_from_slice(SMALLWOOD_RECURSIVE_BINDING_DOMAIN);
    out.extend_from_slice(&(descriptor_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&descriptor_bytes);
    out.extend_from_slice(&(binded_data.len() as u32).to_le_bytes());
    out.extend_from_slice(binded_data);
    let padding = (8 - (out.len() % 8)) % 8;
    out.resize(out.len() + padding, 0);
    out
}

pub fn verify_recursive_statement_direct_v1(
    profile: &RecursiveSmallwoodProfileV1,
    descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    ensure_recursive_descriptor_matches(profile, descriptor, statement)?;
    ensure_canonical_smallwood_proof_bytes(proof_bytes)?;
    let binding = recursive_binding_bytes_v1(descriptor, binded_data);
    verify_statement_with_transcript_backend(
        statement,
        &binding,
        proof_bytes,
        profile.transcript_backend(),
    )
}

pub fn build_recursive_verifier_trace_v1(
    profile: &RecursiveSmallwoodProfileV1,
    descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<SmallwoodRecursiveVerifierTraceV1, TransactionCircuitError> {
    ensure_recursive_descriptor_matches(profile, descriptor, statement)?;
    ensure_canonical_smallwood_proof_bytes(proof_bytes)?;
    let trace = build_smallwood_verifier_trace_v1(
        statement,
        &recursive_binding_bytes_v1(descriptor, binded_data),
        proof_bytes,
        profile.transcript_backend(),
    )?;
    Ok(SmallwoodRecursiveVerifierTraceV1 {
        descriptor: descriptor.clone(),
        binded_data: binded_data.to_vec(),
        trace,
    })
}

pub fn verify_recursive_proof_envelope_v1(
    profile: &RecursiveSmallwoodProfileV1,
    expected_descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    envelope_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    let envelope = decode_smallwood_recursive_proof_envelope_v1(envelope_bytes)?;
    if envelope.descriptor != *expected_descriptor {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope descriptor mismatch",
        ));
    }
    verify_recursive_statement_direct_v1(
        profile,
        expected_descriptor,
        statement,
        binded_data,
        &envelope.proof_bytes,
    )
}

pub fn verify_recursive_proof_components_v1(
    profile: &RecursiveSmallwoodProfileV1,
    expected_descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    verify_recursive_statement_direct_v1(
        profile,
        expected_descriptor,
        statement,
        binded_data,
        proof_bytes,
    )
}

pub fn prove_recursive_statement_v1(
    profile: &RecursiveSmallwoodProfileV1,
    descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_values: &[u64],
    binded_data: &[u8],
) -> Result<Vec<u8>, TransactionCircuitError> {
    ensure_recursive_descriptor_matches(profile, descriptor, statement)?;
    let binding = recursive_binding_bytes_v1(descriptor, binded_data);
    prove_statement_with_transcript_backend(
        statement,
        witness_values,
        &binding,
        profile.transcript_backend(),
    )
}

pub fn verify_recursive_statement_v1(
    profile: &RecursiveSmallwoodProfileV1,
    descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    verify_recursive_statement_direct_v1(profile, descriptor, statement, binded_data, proof_bytes)
}

pub fn projected_smallwood_recursive_proof_bytes_v1(
    profile: &RecursiveSmallwoodProfileV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<usize, TransactionCircuitError> {
    ensure_recursive_profile(profile)?;
    if statement.arithmetization() != profile.arithmetization {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive statement arithmetization does not match profile",
        ));
    }
    projected_candidate_proof_bytes_with_profile(
        statement,
        smallwood_no_grinding_profile_for_arithmetization(profile.arithmetization),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smallwood_semantics::SmallwoodNonlinearEvalView;
    use serde::Deserialize;

    #[derive(Clone)]
    struct ToyRecursiveStatement {
        linear_offsets: Vec<u32>,
    }

    impl ToyRecursiveStatement {
        fn new() -> Self {
            Self {
                linear_offsets: vec![0],
            }
        }
    }

    impl SmallwoodConstraintAdapter for ToyRecursiveStatement {
        fn arithmetization(&self) -> SmallwoodArithmetization {
            SmallwoodArithmetization::Bridge64V1
        }

        fn row_count(&self) -> usize {
            1
        }

        fn packing_factor(&self) -> usize {
            8
        }

        fn constraint_degree(&self) -> usize {
            2
        }

        fn linear_constraint_count(&self) -> usize {
            0
        }

        fn constraint_count(&self) -> usize {
            1
        }

        fn linear_constraint_offsets(&self) -> &[u32] {
            &self.linear_offsets
        }

        fn linear_constraint_indices(&self) -> &[u32] {
            &[]
        }

        fn linear_constraint_coefficients(&self) -> &[u64] {
            &[]
        }

        fn linear_targets(&self) -> &[u64] {
            &[]
        }

        fn auxiliary_witness_words(&self) -> &[u64] {
            &[]
        }

        fn auxiliary_witness_limb_count(&self) -> Option<usize> {
            None
        }

        fn nonlinear_eval_view<'a>(
            &self,
            eval_point: u64,
            row_scalars: &'a [u64],
            auxiliary_words: &'a [u64],
        ) -> SmallwoodNonlinearEvalView<'a> {
            SmallwoodNonlinearEvalView::RowScalars {
                eval_point,
                rows: row_scalars,
                auxiliary_words,
            }
        }

        fn compute_constraints_u64(
            &self,
            view: SmallwoodNonlinearEvalView<'_>,
            out: &mut [u64],
        ) -> Result<(), TransactionCircuitError> {
            let SmallwoodNonlinearEvalView::RowScalars { .. } = view;
            out[0] = 0;
            Ok(())
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSmallwoodRecursiveEnvelopeWireVectorFile {
        schema_version: u32,
        smallwood_recursive_envelope_wire_cases: Vec<LeanSmallwoodRecursiveEnvelopeWireCase>,
        smallwood_recursive_envelope_admission_cases:
            Vec<LeanSmallwoodRecursiveEnvelopeAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSmallwoodRecursiveEnvelopeWireCase {
        name: String,
        raw_hex: String,
        canonical_hex: String,
        expected_len: usize,
        parser_accepts: bool,
        consumed_all_bytes: bool,
        canonical_reencode_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSmallwoodRecursiveEnvelopeAdmissionCase {
        name: String,
        raw_hex: String,
        expected_descriptor_hex: String,
        expected_wire_valid: bool,
        descriptor_matches: bool,
        expected_admission_valid: bool,
        expected_admission_rejection: Option<String>,
    }

    fn load_recursive_envelope_wire_vectors() -> LeanSmallwoodRecursiveEnvelopeWireVectorFile {
        if let Ok(path) = std::env::var("HEGEMON_LEAN_SMALLWOOD_RECURSIVE_ENVELOPE_WIRE_VECTORS") {
            let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| {
                panic!("read Lean SmallWood recursive envelope wire vectors {path}: {err}")
            });
            return serde_json::from_str(&raw).unwrap_or_else(|err| {
                panic!("parse Lean SmallWood recursive envelope wire vectors {path}: {err}")
            });
        }

        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest_dir
            .parent()
            .and_then(std::path::Path::parent)
            .expect("transaction crate must live under circuits/transaction");
        let output = std::process::Command::new("lake")
            .args(["exe", "gen_smallwood_recursive_envelope_wire_vectors"])
            .current_dir(root.join("formal/lean"))
            .output()
            .unwrap_or_else(|err| {
                panic!("failed to run Lean SmallWood recursive envelope generator: {err}")
            });
        assert!(
            output.status.success(),
            "Lean SmallWood recursive envelope generator failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout)
            .expect("parse generated Lean SmallWood recursive envelope wire vectors")
    }

    #[test]
    fn lean_generated_smallwood_recursive_envelope_wire_vectors_match_production() {
        let vectors = load_recursive_envelope_wire_vectors();
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.smallwood_recursive_envelope_wire_cases.is_empty(),
            "Lean SmallWood recursive envelope wire cases must not be empty"
        );
        assert!(
            !vectors
                .smallwood_recursive_envelope_admission_cases
                .is_empty(),
            "Lean SmallWood recursive envelope admission cases must not be empty"
        );

        let valid_fixture =
            encode_smallwood_recursive_proof_envelope_v1(&lean_default_recursive_envelope())
                .expect("encode default recursive envelope fixture");
        let alternate_fixture =
            encode_smallwood_recursive_proof_envelope_v1(&lean_alternate_recursive_envelope())
                .expect("encode alternate recursive envelope fixture");

        for case in &vectors.smallwood_recursive_envelope_wire_cases {
            verify_lean_recursive_envelope_wire_case(case, &valid_fixture, &alternate_fixture);
        }
        for case in &vectors.smallwood_recursive_envelope_admission_cases {
            verify_lean_recursive_envelope_admission_case(case);
        }
    }

    fn verify_lean_recursive_envelope_wire_case(
        case: &LeanSmallwoodRecursiveEnvelopeWireCase,
        valid_fixture: &[u8],
        alternate_fixture: &[u8],
    ) {
        let raw = decode_lean_hex_bytes(&case.raw_hex);
        let canonical = decode_lean_hex_bytes(&case.canonical_hex);
        assert_eq!(
            raw.len(),
            case.expected_len,
            "{} Lean raw byte length drifted",
            case.name
        );
        if case.name == "valid-recursive-envelope" {
            assert_eq!(
                raw, valid_fixture,
                "{} Lean valid fixture drifted from production bincode",
                case.name
            );
        } else if case.name == "alternate-recursive-envelope" {
            assert_eq!(
                raw, alternate_fixture,
                "{} Lean alternate fixture drifted from production bincode",
                case.name
            );
        }

        let actual = decode_smallwood_recursive_proof_envelope_v1(&raw);
        assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} exact SmallWood recursive envelope validity drifted from Lean spec: {actual:?}",
            case.name
        );

        match actual {
            Ok(decoded) => {
                assert!(
                    case.parser_accepts
                        && case.consumed_all_bytes
                        && case.canonical_reencode_matches,
                    "{} Lean marked a valid recursive envelope without all codec gates",
                    case.name
                );
                let reencoded = encode_smallwood_recursive_proof_envelope_v1(&decoded)
                    .expect("reencode recursive envelope");
                assert_eq!(
                    reencoded, canonical,
                    "{} decoded recursive envelope reencoded to non-Lean canonical bytes",
                    case.name
                );
                assert_eq!(
                    raw, canonical,
                    "{} accepted recursive envelope raw bytes must be canonical",
                    case.name
                );
            }
            Err(err) => {
                let actual_rejection = recursive_envelope_wire_rejection_label(&err);
                assert_eq!(
                    Some(actual_rejection.as_str()),
                    case.expected_rejection.as_deref(),
                    "{} exact recursive envelope rejection label drifted: {err:?}",
                    case.name
                );
                if case.parser_accepts && !case.consumed_all_bytes {
                    assert!(
                        raw.starts_with(&canonical),
                        "{} trailing fixture must carry the canonical prefix",
                        case.name
                    );
                    assert!(
                        raw.len() > canonical.len(),
                        "{} trailing fixture must extend canonical bytes",
                        case.name
                    );
                }
            }
        }
    }

    fn verify_lean_recursive_envelope_admission_case(
        case: &LeanSmallwoodRecursiveEnvelopeAdmissionCase,
    ) {
        let raw = decode_lean_hex_bytes(&case.raw_hex);
        let expected_descriptor = decode_lean_hex_bytes(&case.expected_descriptor_hex);
        let decoded = decode_smallwood_recursive_proof_envelope_v1(&raw);
        assert_eq!(
            decoded.is_ok(),
            case.expected_wire_valid,
            "{} recursive envelope admission wire-validity drifted",
            case.name
        );
        let decoded = match decoded {
            Ok(decoded) => decoded,
            Err(_) => return,
        };
        let actual_descriptor =
            bincode::serialize(&decoded.descriptor).expect("serialize decoded descriptor");
        let actual_descriptor_matches = actual_descriptor == expected_descriptor;
        assert_eq!(
            actual_descriptor_matches, case.descriptor_matches,
            "{} recursive envelope descriptor match drifted",
            case.name
        );
        let actual_valid = actual_descriptor_matches;
        assert_eq!(
            actual_valid, case.expected_admission_valid,
            "{} recursive envelope admission validity drifted",
            case.name
        );
        let actual_rejection = if actual_valid {
            None
        } else {
            Some("descriptor_mismatch".to_string())
        };
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_admission_rejection.as_deref(),
            "{} recursive envelope admission rejection drifted",
            case.name
        );
    }

    fn lean_default_recursive_envelope() -> SmallwoodRecursiveProofEnvelopeV1 {
        let profile = recursive_profile_b_v1(VersionBinding {
            circuit: 2,
            crypto: 2,
        });
        SmallwoodRecursiveProofEnvelopeV1 {
            descriptor: recursive_descriptor_v1(
                &profile,
                SmallwoodRecursiveRelationKindV1::StepB,
                [4u8; 32],
                [5u8; 32],
                [6u8; 32],
            ),
            proof_bytes: vec![7u8; 17],
        }
    }

    fn lean_alternate_recursive_envelope() -> SmallwoodRecursiveProofEnvelopeV1 {
        let profile = recursive_profile_a_v1(VersionBinding {
            circuit: 2,
            crypto: 2,
        });
        SmallwoodRecursiveProofEnvelopeV1 {
            descriptor: recursive_descriptor_v1(
                &profile,
                SmallwoodRecursiveRelationKindV1::BaseA,
                [9u8; 32],
                [10u8; 32],
                [11u8; 32],
            ),
            proof_bytes: (0..19)
                .map(|index| 0x21u8.wrapping_add((index as u8).wrapping_mul(17)))
                .collect(),
        }
    }

    fn recursive_envelope_wire_rejection_label(err: &TransactionCircuitError) -> String {
        let message = err.to_string();
        if message.contains("trailing bytes") {
            "trailing_bytes".to_string()
        } else if message.contains("canonical serialization") {
            "non_canonical_encoding".to_string()
        } else {
            "parser_rejected".to_string()
        }
    }

    fn decode_lean_hex_bytes(value: &str) -> Vec<u8> {
        let hex = value
            .strip_prefix("0x")
            .expect("Lean vectors use 0x-prefixed hex");
        assert!(
            hex.len().is_multiple_of(2),
            "hex value must have an even number of digits"
        );
        (0..hex.len())
            .step_by(2)
            .map(|idx| {
                u8::from_str_radix(&hex[idx..idx + 2], 16).expect("Lean vector hex bytes are valid")
            })
            .collect()
    }

    #[test]
    fn recursive_descriptor_digest_changes_with_relation_identity() {
        let profile = recursive_profile_a_v1(VersionBinding {
            circuit: 2,
            crypto: 2,
        });
        let base = recursive_descriptor_v1(
            &profile,
            SmallwoodRecursiveRelationKindV1::BaseA,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );
        let mut changed = base.clone();
        changed.relation_kind = SmallwoodRecursiveRelationKindV1::StepA;
        assert_ne!(
            smallwood_recursive_verifier_descriptor_digest_v1(&base),
            smallwood_recursive_verifier_descriptor_digest_v1(&changed)
        );
    }

    #[test]
    fn recursive_envelope_roundtrip() {
        let profile = recursive_profile_b_v1(VersionBinding {
            circuit: 2,
            crypto: 2,
        });
        let envelope = SmallwoodRecursiveProofEnvelopeV1 {
            descriptor: recursive_descriptor_v1(
                &profile,
                SmallwoodRecursiveRelationKindV1::StepB,
                [4u8; 32],
                [5u8; 32],
                [6u8; 32],
            ),
            proof_bytes: vec![7u8; 123],
        };
        let encoded = encode_smallwood_recursive_proof_envelope_v1(&envelope).unwrap();
        let decoded = decode_smallwood_recursive_proof_envelope_v1(&encoded).unwrap();
        assert_eq!(decoded, envelope);

        let parsed = parse_smallwood_recursive_proof_envelope_v1(&encoded).unwrap();
        assert_eq!(parsed.descriptor_ref(), envelope.descriptor_ref());
        assert_eq!(parsed.proof_bytes_ref(), envelope.proof_bytes_ref());
        assert_eq!(
            parsed.clone().into_parts(),
            (envelope.descriptor, envelope.proof_bytes)
        );
    }

    #[test]
    fn recursive_envelope_rejects_trailing_bytes() {
        let profile = recursive_profile_b_v1(VersionBinding {
            circuit: 2,
            crypto: 2,
        });
        let envelope = SmallwoodRecursiveProofEnvelopeV1 {
            descriptor: recursive_descriptor_v1(
                &profile,
                SmallwoodRecursiveRelationKindV1::StepB,
                [4u8; 32],
                [5u8; 32],
                [6u8; 32],
            ),
            proof_bytes: vec![7u8; 123],
        };
        let mut encoded = encode_smallwood_recursive_proof_envelope_v1(&envelope).unwrap();
        encoded.push(0);
        let err = decode_smallwood_recursive_proof_envelope_v1(&encoded)
            .expect_err("trailing recursive envelope bytes accepted");
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn recursive_profiles_prove_and_verify_toy_statement() {
        let version = VersionBinding {
            circuit: 2,
            crypto: 2,
        };
        let statement = ToyRecursiveStatement::new();
        let witness = vec![7u64; statement.row_count() * statement.packing_factor()];
        let descriptor_a = recursive_descriptor_v1(
            &recursive_profile_a_v1(version),
            SmallwoodRecursiveRelationKindV1::BaseA,
            [9u8; 32],
            [10u8; 32],
            [11u8; 32],
        );
        let proof_a = prove_recursive_statement_v1(
            &recursive_profile_a_v1(version),
            &descriptor_a,
            &statement,
            &witness,
            b"toy-binding-a",
        )
        .unwrap();
        verify_recursive_statement_v1(
            &recursive_profile_a_v1(version),
            &descriptor_a,
            &statement,
            b"toy-binding-a",
            &proof_a,
        )
        .unwrap();

        let descriptor_b = recursive_descriptor_v1(
            &recursive_profile_b_v1(version),
            SmallwoodRecursiveRelationKindV1::StepB,
            [12u8; 32],
            [13u8; 32],
            [14u8; 32],
        );
        let proof_b = prove_recursive_statement_v1(
            &recursive_profile_b_v1(version),
            &descriptor_b,
            &statement,
            &witness,
            b"toy-binding-b",
        )
        .unwrap();
        verify_recursive_statement_v1(
            &recursive_profile_b_v1(version),
            &descriptor_b,
            &statement,
            b"toy-binding-b",
            &proof_b,
        )
        .unwrap();

        verify_recursive_proof_components_v1(
            &recursive_profile_b_v1(version),
            &descriptor_b,
            &statement,
            b"toy-binding-b",
            &proof_b,
        )
        .unwrap();

        assert_eq!(
            projected_smallwood_recursive_proof_bytes_v1(
                &recursive_profile_a_v1(version),
                &statement
            )
            .unwrap(),
            projected_smallwood_recursive_proof_bytes_v1(
                &recursive_profile_b_v1(version),
                &statement
            )
            .unwrap()
        );
    }

    #[test]
    fn recursive_verifier_trace_builder_emits_accepting_trace() {
        let version = VersionBinding {
            circuit: 2,
            crypto: 2,
        };
        let statement = ToyRecursiveStatement::new();
        let witness = vec![7u64; statement.row_count() * statement.packing_factor()];
        let profile = recursive_profile_a_v1(version);
        let descriptor = recursive_descriptor_v1(
            &profile,
            SmallwoodRecursiveRelationKindV1::BaseA,
            [9u8; 32],
            [10u8; 32],
            [11u8; 32],
        );
        let proof =
            prove_recursive_statement_v1(&profile, &descriptor, &statement, &witness, b"trace")
                .unwrap();
        let trace =
            build_recursive_verifier_trace_v1(&profile, &descriptor, &statement, b"trace", &proof)
                .unwrap();
        assert_eq!(trace.descriptor, descriptor);
        assert!(trace.trace.accept);
        assert_eq!(trace.trace.eval_points.len(), 3);
        assert!(!trace.trace.piop_transcript_words.is_empty());
        trace.validate_sections_v1().unwrap();
    }

    #[test]
    fn recursive_verifier_trace_sections_have_consistent_lengths() {
        let version = VersionBinding {
            circuit: 2,
            crypto: 2,
        };
        let statement = ToyRecursiveStatement::new();
        let witness = vec![7u64; statement.row_count() * statement.packing_factor()];
        let profile = recursive_profile_a_v1(version);
        let descriptor = recursive_descriptor_v1(
            &profile,
            SmallwoodRecursiveRelationKindV1::BaseA,
            [9u8; 32],
            [10u8; 32],
            [11u8; 32],
        );
        let proof = prove_recursive_statement_v1(
            &profile,
            &descriptor,
            &statement,
            &witness,
            b"trace-sections",
        )
        .unwrap();
        let trace = build_recursive_verifier_trace_v1(
            &profile,
            &descriptor,
            &statement,
            b"trace-sections",
            &proof,
        )
        .unwrap();

        trace.validate_sections_v1().unwrap();

        let transcript_len = trace.flatten_transcript_section_words_v1().len();
        let expected_transcript_len = trace.trace.binding_words.len()
            + trace.trace.eval_points.len()
            + trace
                .trace
                .piop_gamma_prime
                .iter()
                .map(Vec::len)
                .sum::<usize>()
            + trace.trace.pcs_transcript_words.len()
            + trace.trace.piop_input_words.len()
            + trace.trace.piop_transcript_words.len()
            + 4
            + 1;
        assert_eq!(transcript_len, expected_transcript_len);

        let pcs_len = trace.flatten_pcs_section_words_v1().len();
        let expected_pcs_len = trace
            .trace
            .pcs_opened_witness_row_scalars_v1()
            .iter()
            .map(Vec::len)
            .sum::<usize>()
            + trace
                .trace
                .pcs_partial_evals_v1()
                .iter()
                .map(Vec::len)
                .sum::<usize>()
            + trace
                .trace
                .pcs_rcombi_tails_v1()
                .iter()
                .map(Vec::len)
                .sum::<usize>()
            + trace
                .trace
                .pcs_subset_evals_v1()
                .iter()
                .map(Vec::len)
                .sum::<usize>()
            + trace
                .trace
                .pcs_trace
                .coeffs
                .iter()
                .map(Vec::len)
                .sum::<usize>()
            + trace
                .trace
                .pcs_trace
                .combi_heads
                .iter()
                .map(Vec::len)
                .sum::<usize>()
            + 4
            + trace.trace.pcs_transcript_words.len();
        assert_eq!(pcs_len, expected_pcs_len);

        let decs_len = trace.flatten_decs_section_words_v1().len();
        let expected_decs_len = 4
            + trace.trace.pcs_trace.decs_leaf_indexes.len()
            + 1
            + trace.trace.pcs_trace.decs_eval_points.len()
            + trace
                .trace
                .decs_masking_evals_v1()
                .iter()
                .map(Vec::len)
                .sum::<usize>()
            + trace
                .trace
                .decs_high_coeffs_v1()
                .iter()
                .map(Vec::len)
                .sum::<usize>()
            + trace.trace.pcs_trace.decs_commitment_transcript.len();
        assert_eq!(decs_len, expected_decs_len);

        let merkle_len = trace.flatten_merkle_section_words_v1().len();
        let expected_merkle_len = trace
            .trace
            .pcs_trace
            .rows
            .iter()
            .map(Vec::len)
            .sum::<usize>()
            + trace
                .trace
                .merkle_auth_paths_v1()
                .iter()
                .map(|path| path.len() * 4)
                .sum::<usize>()
            + 4;
        assert_eq!(merkle_len, expected_merkle_len);
    }

    #[test]
    fn recursive_verifier_trace_transcript_validator_rejects_input_drift() {
        let version = VersionBinding {
            circuit: 2,
            crypto: 2,
        };
        let statement = ToyRecursiveStatement::new();
        let witness = vec![7u64; statement.row_count() * statement.packing_factor()];
        let profile = recursive_profile_a_v1(version);
        let descriptor = recursive_descriptor_v1(
            &profile,
            SmallwoodRecursiveRelationKindV1::BaseA,
            [9u8; 32],
            [10u8; 32],
            [11u8; 32],
        );
        let proof = prove_recursive_statement_v1(
            &profile,
            &descriptor,
            &statement,
            &witness,
            b"trace-transcript-drift",
        )
        .unwrap();
        let mut trace = build_recursive_verifier_trace_v1(
            &profile,
            &descriptor,
            &statement,
            b"trace-transcript-drift",
            &proof,
        )
        .unwrap();
        trace.trace.piop_input_words.pop();
        assert!(trace.trace.validate_transcript_section_v1().is_err());
    }

    #[test]
    fn recursive_verifier_trace_pcs_and_merkle_validators_reject_section_drift() {
        let version = VersionBinding {
            circuit: 2,
            crypto: 2,
        };
        let statement = ToyRecursiveStatement::new();
        let witness = vec![7u64; statement.row_count() * statement.packing_factor()];
        let profile = recursive_profile_a_v1(version);
        let descriptor = recursive_descriptor_v1(
            &profile,
            SmallwoodRecursiveRelationKindV1::BaseA,
            [9u8; 32],
            [10u8; 32],
            [11u8; 32],
        );
        let proof = prove_recursive_statement_v1(
            &profile,
            &descriptor,
            &statement,
            &witness,
            b"trace-pcs-merkle-drift",
        )
        .unwrap();

        let mut pcs_trace = build_recursive_verifier_trace_v1(
            &profile,
            &descriptor,
            &statement,
            b"trace-pcs-merkle-drift",
            &proof,
        )
        .unwrap();
        pcs_trace.trace.pcs_trace.decs_commitment_transcript.push(1);
        assert!(pcs_trace.trace.validate_pcs_section_v1().is_err());

        let mut merkle_trace = build_recursive_verifier_trace_v1(
            &profile,
            &descriptor,
            &statement,
            b"trace-pcs-merkle-drift",
            &proof,
        )
        .unwrap();
        merkle_trace.trace.pcs_trace.rows.pop();
        assert!(merkle_trace.trace.validate_merkle_section_v1().is_err());
    }
}
