//! Canonical, source-owned export and replay checker for one accepted SMZA
//! verifier invocation. This is execution evidence only; it is not a Lean
//! verifier-refinement or production-authorization proof.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::TransactionCircuitError;
use crate::smallwood_engine::{
    SmallwoodDecsEvaluationDomain, SmallwoodSha512OracleProgramKindV1, SmallwoodTranscriptBackend,
    POSEIDON2_V8_SMZA_SMALLWOOD_NO_GRINDING_PROFILE,
};
use crate::smallwood_poseidon2_v8_frontend::{
    SmallwoodPoseidon2V8VerifierInput, SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS,
    SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS, SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES,
};
use crate::smallwood_poseidon2_v8_zk_refinement::{
    SmallwoodPoseidon2V8SmzaAcceptedRunEvidenceV1, SmallwoodPoseidon2V8SmzaAcceptedRunPhasesV1,
};

const ENVELOPE_SCHEMA: &str = "hegemon.smallwood.poseidon2-v8.smza.accepted-run-envelope.v1";
const BACKEND_ID: &str = "sha512-poseidon2-v8-smza";
const DECS_DOMAIN_ID: &str = "radix2-disjoint-coset-2^23";
const DOMAIN_SIZE: u64 = 1 << 23;
const LVCS_COLUMNS: u64 = 368;
const INTERPOLATION_POINTS: u64 = LVCS_COLUMNS + 38;
const Q38_COUNT: usize = 38;
const PIOP_WORDS: usize = 3113;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeAcceptedRunImportError {
    Native(String),
    Json(String),
    NonCanonicalEncoding,
    InvalidEnvelope(&'static str),
    ReplayMismatch,
}

impl std::fmt::Display for NativeAcceptedRunImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(message) => write!(f, "native accepted-run replay failed: {message}"),
            Self::Json(message) => write!(f, "accepted-run JSON error: {message}"),
            Self::NonCanonicalEncoding => {
                f.write_str("accepted-run envelope is not canonical JSON")
            }
            Self::InvalidEnvelope(message) => write!(f, "invalid accepted-run envelope: {message}"),
            Self::ReplayMismatch => f.write_str("accepted-run envelope differs from source replay"),
        }
    }
}

impl std::error::Error for NativeAcceptedRunImportError {}

impl From<TransactionCircuitError> for NativeAcceptedRunImportError {
    fn from(error: TransactionCircuitError) -> Self {
        Self::Native(error.to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeAcceptedRunInputV1 {
    pub network_id: u32,
    pub relation_digest: Vec<u8>,
    pub public_values: Vec<u64>,
    pub relation_balance_binding: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeAcceptedRunProfileV1 {
    pub rho: u64,
    pub nb_opened_evals: u64,
    pub beta: u64,
    pub opening_pow_bits: u32,
    pub decs_nb_evals: u64,
    pub decs_nb_opened_evals: u64,
    pub decs_eta: u64,
    pub decs_pow_bits: u32,
    pub lvcs_columns: u64,
    pub interpolation_points: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeAcceptedRunXofQueryV1 {
    pub profile_domain: Option<Vec<u8>>,
    pub role_domain: Vec<u8>,
    pub words: Vec<u64>,
    pub counter: u64,
    pub output: Vec<u8>,
    pub programmed_kind: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeAcceptedRunPhasesV1 {
    pub trace_start: Option<u64>,
    pub trace_end: Option<u64>,
    pub core_start: Option<u64>,
    pub core_end: Option<u64>,
    pub trace_xof_scope_completed: bool,
    pub core_xof_scope_completed: bool,
}

/// Fixed JSON field order is part of this internal evidence envelope's
/// canonical encoding. The proof wire itself remains byte-for-byte unchanged.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeAcceptedRunEnvelopeV1 {
    pub schema: String,
    pub input: NativeAcceptedRunInputV1,
    pub binded_data: Vec<u8>,
    pub relation_id: String,
    pub backend: String,
    pub decs_domain: String,
    pub proof_bytes: Vec<u8>,
    pub accepted: bool,
    pub profile: NativeAcceptedRunProfileV1,
    pub phases: NativeAcceptedRunPhasesV1,
    pub piop_transcript_words: Vec<u64>,
    pub expected_piop_digest: Vec<u8>,
    pub recomputed_piop_digest: Vec<u8>,
    pub decs_leaf_indexes: Vec<u32>,
    pub decs_eval_points: Vec<u64>,
    pub decs_gamma_all: Vec<Vec<u64>>,
    pub lvcs_recovered_rows: Vec<Vec<u64>>,
    pub pcs_coefficients: Vec<Vec<u64>>,
    pub pcs_combi_heads: Vec<Vec<u64>>,
    pub pcs_rcombi_tails: Vec<Vec<u64>>,
    pub pcs_subset_evals: Vec<Vec<u64>>,
    pub decs_commitment_transcript: Vec<u64>,
    pub decs_root_digest: Vec<u8>,
    pub decs_nonce: Vec<u8>,
    pub xof_queries: Vec<NativeAcceptedRunXofQueryV1>,
}

impl NativeAcceptedRunEnvelopeV1 {
    fn validate_shape(&self) -> Result<(), NativeAcceptedRunImportError> {
        if self.schema != ENVELOPE_SCHEMA {
            return Err(NativeAcceptedRunImportError::InvalidEnvelope("schema"));
        }
        if self.backend != BACKEND_ID || self.decs_domain != DECS_DOMAIN_ID {
            return Err(NativeAcceptedRunImportError::InvalidEnvelope(
                "backend/domain",
            ));
        }
        if !self.accepted
            || !self.phases.trace_xof_scope_completed
            || !self.phases.core_xof_scope_completed
        {
            return Err(NativeAcceptedRunImportError::InvalidEnvelope(
                "acceptance/XOF completion",
            ));
        }
        if self.input.relation_digest.len() != SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES
            || self.input.public_values.len() != SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS
            || self.input.relation_balance_binding.len()
                != SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS
        {
            return Err(NativeAcceptedRunImportError::InvalidEnvelope("input shape"));
        }
        if self.profile.decs_nb_evals != DOMAIN_SIZE
            || self.profile.decs_nb_opened_evals != Q38_COUNT as u64
            || self.profile.lvcs_columns != LVCS_COLUMNS
            || self.profile.interpolation_points != INTERPOLATION_POINTS
        {
            return Err(NativeAcceptedRunImportError::InvalidEnvelope(
                "current 406/q38 geometry",
            ));
        }
        if self.piop_transcript_words.len() != PIOP_WORDS
            || self.expected_piop_digest.len() != 64
            || self.recomputed_piop_digest.len() != 64
            || self.expected_piop_digest != self.recomputed_piop_digest
        {
            return Err(NativeAcceptedRunImportError::InvalidEnvelope("final PIOP"));
        }
        if self.decs_leaf_indexes.len() != Q38_COUNT
            || self.decs_eval_points.len() != Q38_COUNT
            || self.lvcs_recovered_rows.len() != Q38_COUNT
            || self.lvcs_recovered_rows.iter().any(|row| row.is_empty())
            || self.decs_gamma_all.len() != self.profile.decs_eta as usize
            || self
                .lvcs_recovered_rows
                .iter()
                .any(|row| row.len() != self.lvcs_recovered_rows[0].len())
            || self
                .decs_gamma_all
                .iter()
                .any(|row| row.len() != self.lvcs_recovered_rows[0].len())
            || self.decs_root_digest.len() != 64
            || self.decs_nonce.len() != 4
        {
            return Err(NativeAcceptedRunImportError::InvalidEnvelope("DECS shape"));
        }
        let mut indexes = BTreeSet::new();
        if self
            .decs_leaf_indexes
            .iter()
            .any(|&index| u64::from(index) >= DOMAIN_SIZE || !indexes.insert(index))
        {
            return Err(NativeAcceptedRunImportError::InvalidEnvelope(
                "DECS indexes",
            ));
        }
        let phases = &self.phases;
        if phases.trace_start != Some(0)
            || phases.trace_end != phases.core_start
            || phases.core_end != Some(self.xof_queries.len() as u64)
        {
            return Err(NativeAcceptedRunImportError::InvalidEnvelope(
                "XOF phase boundaries",
            ));
        }
        if self
            .xof_queries
            .iter()
            .any(|query| query.output.len() != 64 || query.programmed_kind.is_some())
        {
            return Err(NativeAcceptedRunImportError::InvalidEnvelope(
                "XOF query record",
            ));
        }
        Ok(())
    }
}

fn profile_from_source(
    evidence: &SmallwoodPoseidon2V8SmzaAcceptedRunEvidenceV1,
) -> Result<NativeAcceptedRunProfileV1, NativeAcceptedRunImportError> {
    let profile = evidence.trace.profile;
    let expected = POSEIDON2_V8_SMZA_SMALLWOOD_NO_GRINDING_PROFILE;
    if profile != expected
        || evidence.transcript_backend != SmallwoodTranscriptBackend::Sha512Poseidon2V8Smza
        || evidence.decs_domain != SmallwoodDecsEvaluationDomain::Radix2DisjointCoset
    {
        return Err(NativeAcceptedRunImportError::InvalidEnvelope(
            "source profile",
        ));
    }
    Ok(NativeAcceptedRunProfileV1 {
        rho: profile.rho as u64,
        nb_opened_evals: profile.nb_opened_evals as u64,
        beta: profile.beta as u64,
        opening_pow_bits: profile.opening_pow_bits,
        decs_nb_evals: profile.decs_nb_evals as u64,
        decs_nb_opened_evals: profile.decs_nb_opened_evals as u64,
        decs_eta: profile.decs_eta as u64,
        decs_pow_bits: profile.decs_pow_bits,
        lvcs_columns: LVCS_COLUMNS,
        interpolation_points: INTERPOLATION_POINTS,
    })
}

fn phase_export(
    phases: SmallwoodPoseidon2V8SmzaAcceptedRunPhasesV1,
    query_count: usize,
) -> Result<NativeAcceptedRunPhasesV1, NativeAcceptedRunImportError> {
    let completed = phases.trace_start == Some(0)
        && phases.trace_end == phases.core_start
        && phases.core_end == Some(query_count);
    if !completed {
        return Err(NativeAcceptedRunImportError::InvalidEnvelope(
            "incomplete XOF phases",
        ));
    }
    Ok(NativeAcceptedRunPhasesV1 {
        trace_start: phases.trace_start.map(|x| x as u64),
        trace_end: phases.trace_end.map(|x| x as u64),
        core_start: phases.core_start.map(|x| x as u64),
        core_end: phases.core_end.map(|x| x as u64),
        trace_xof_scope_completed: true,
        core_xof_scope_completed: true,
    })
}

fn envelope_from_attempt(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
    attempt: crate::smallwood_poseidon2_v8_zk_refinement::SmallwoodPoseidon2V8SmzaAcceptedRunAttemptV1,
) -> Result<NativeAcceptedRunEnvelopeV1, NativeAcceptedRunImportError> {
    let phases = phase_export(attempt.phases, attempt.queries.len())?;
    let evidence = attempt
        .result
        .map_err(|error| NativeAcceptedRunImportError::Native(error.to_string()))?;
    if evidence.binded_data.as_slice()
        != input.smza_candidate_transcript_preamble_v1()?.as_bytes()
        || evidence.proof_bytes.as_slice() != proof_bytes
        || !evidence.audit.canonical_decode_reencode_exact
        || !evidence.audit.verifier_trace_replay_exact
        || !evidence.audit.candidate_verifier_accepts
        || !evidence.trace.accept
        || evidence.trace.recomputed_piop_digest != evidence.trace.proof.h_piop
    {
        return Err(NativeAcceptedRunImportError::InvalidEnvelope(
            "accepted-run binding",
        ));
    }
    evidence.trace.validate_sections_v1()?;
    let profile = profile_from_source(&evidence)?;
    let trace = &evidence.trace;
    let xof_queries = attempt
        .queries
        .into_iter()
        .map(|query| NativeAcceptedRunXofQueryV1 {
            profile_domain: query.key.profile_domain,
            role_domain: query.key.role_domain,
            words: query.key.words,
            counter: query.key.counter,
            output: query.output.to_vec(),
            programmed_kind: query.programmed_kind.map(|kind| match kind {
                SmallwoodSha512OracleProgramKindV1::LazyMerkle => "lazy-merkle".to_owned(),
                SmallwoodSha512OracleProgramKindV1::FinalPiop => "final-piop".to_owned(),
            }),
        })
        .collect::<Vec<_>>();
    let envelope = NativeAcceptedRunEnvelopeV1 {
        schema: ENVELOPE_SCHEMA.to_owned(),
        input: NativeAcceptedRunInputV1 {
            network_id: input.network_id,
            relation_digest: input.relation_digest.to_vec(),
            public_values: input.public_values.to_vec(),
            relation_balance_binding: input.relation_balance_binding.to_vec(),
        },
        binded_data: evidence.binded_data,
        relation_id: evidence.relation_id.to_owned(),
        backend: BACKEND_ID.to_owned(),
        decs_domain: DECS_DOMAIN_ID.to_owned(),
        proof_bytes: evidence.proof_bytes,
        accepted: true,
        profile,
        phases,
        piop_transcript_words: trace.piop_transcript_words.clone(),
        expected_piop_digest: trace.proof.h_piop.to_vec(),
        recomputed_piop_digest: trace.recomputed_piop_digest.to_vec(),
        decs_leaf_indexes: trace.decs_leaf_indexes_v1().to_vec(),
        decs_eval_points: trace.decs_eval_points_v1().to_vec(),
        decs_gamma_all: trace.decs_gamma_all_v1().to_vec(),
        lvcs_recovered_rows: trace.pcs_trace.rows.clone(),
        pcs_coefficients: trace.pcs_coeffs_v1().to_vec(),
        pcs_combi_heads: trace.pcs_combi_heads_v1().to_vec(),
        pcs_rcombi_tails: trace.pcs_rcombi_tails_v1().to_vec(),
        pcs_subset_evals: trace.pcs_subset_evals_v1().to_vec(),
        decs_commitment_transcript: trace.pcs_trace.decs_commitment_transcript.clone(),
        decs_root_digest: trace.pcs_trace.root_digest.to_vec(),
        decs_nonce: trace.pcs_trace.decs_nonce.to_vec(),
        xof_queries,
    };
    envelope.validate_shape()?;
    Ok(envelope)
}

fn canonical_json(
    envelope: &NativeAcceptedRunEnvelopeV1,
) -> Result<Vec<u8>, NativeAcceptedRunImportError> {
    serde_json::to_vec(envelope)
        .map_err(|error| NativeAcceptedRunImportError::Json(error.to_string()))
}

/// Run the current frontend and verifier once and export the retained
/// accepted-run measurements. The proof bytes are copied unchanged into the
/// evidence envelope; no proof-wire field is added or rewritten.
pub fn export_native_accepted_run_v1(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: &[u8],
) -> Result<Vec<u8>, NativeAcceptedRunImportError> {
    let frontend = crate::smallwood_poseidon2_v8_frontend::
        verify_smallwood_poseidon2_v8_smza_candidate_with_evidence_v1(input, proof_bytes)?;
    let (_, attempt) = frontend.into_parts();
    canonical_json(&envelope_from_attempt(input, proof_bytes, attempt)?)
}

fn input_from_envelope(
    input: &NativeAcceptedRunInputV1,
) -> Result<SmallwoodPoseidon2V8VerifierInput, NativeAcceptedRunImportError> {
    let relation_digest: [u8; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES] = input
        .relation_digest
        .clone()
        .try_into()
        .map_err(|_| NativeAcceptedRunImportError::InvalidEnvelope("relation digest length"))?;
    let public_values: [u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS] = input
        .public_values
        .clone()
        .try_into()
        .map_err(|_| NativeAcceptedRunImportError::InvalidEnvelope("public value length"))?;
    let relation_balance_binding: [u64; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS] = input
        .relation_balance_binding
        .clone()
        .try_into()
        .map_err(|_| NativeAcceptedRunImportError::InvalidEnvelope("binding length"))?;
    Ok(SmallwoodPoseidon2V8VerifierInput {
        network_id: input.network_id,
        relation_digest,
        public_values,
        relation_balance_binding,
    })
}

/// Canonically parse an envelope, reconstruct the source relation from its
/// input, rerun the accepted verifier with raw XOF recording, and require an
/// exact byte-for-byte match with the freshly exported trace. A successful
/// result is current native execution evidence, not a proof of the Rust/Lean
/// relation-refinement theorem.
pub fn verify_imported_native_accepted_run_v1(
    bytes: &[u8],
) -> Result<NativeAcceptedRunEnvelopeV1, NativeAcceptedRunImportError> {
    let envelope: NativeAcceptedRunEnvelopeV1 = serde_json::from_slice(bytes)
        .map_err(|error| NativeAcceptedRunImportError::Json(error.to_string()))?;
    envelope.validate_shape()?;
    if canonical_json(&envelope)?.as_slice() != bytes {
        return Err(NativeAcceptedRunImportError::NonCanonicalEncoding);
    }
    if envelope.relation_id
        != crate::smallwood_poseidon2_v8_relation::SMALLWOOD_POSEIDON2_V8_RELATION_ID
    {
        return Err(NativeAcceptedRunImportError::InvalidEnvelope("relation id"));
    }
    let input = input_from_envelope(&envelope.input)?;
    let replayed = export_native_accepted_run_v1(&input, &envelope.proof_bytes)?;
    if replayed.as_slice() != bytes {
        return Err(NativeAcceptedRunImportError::ReplayMismatch);
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_envelope() -> NativeAcceptedRunEnvelopeV1 {
        let profile = POSEIDON2_V8_SMZA_SMALLWOOD_NO_GRINDING_PROFILE;
        NativeAcceptedRunEnvelopeV1 {
            schema: ENVELOPE_SCHEMA.to_owned(),
            input: NativeAcceptedRunInputV1 {
                network_id: 1,
                relation_digest: vec![0; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES],
                public_values: vec![0; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
                relation_balance_binding: vec![0; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS],
            },
            binded_data: vec![],
            relation_id: crate::smallwood_poseidon2_v8_relation::SMALLWOOD_POSEIDON2_V8_RELATION_ID
                .to_owned(),
            backend: BACKEND_ID.to_owned(),
            decs_domain: DECS_DOMAIN_ID.to_owned(),
            proof_bytes: vec![],
            accepted: true,
            profile: NativeAcceptedRunProfileV1 {
                rho: profile.rho as u64,
                nb_opened_evals: profile.nb_opened_evals as u64,
                beta: profile.beta as u64,
                opening_pow_bits: profile.opening_pow_bits,
                decs_nb_evals: DOMAIN_SIZE,
                decs_nb_opened_evals: Q38_COUNT as u64,
                decs_eta: profile.decs_eta as u64,
                decs_pow_bits: profile.decs_pow_bits,
                lvcs_columns: LVCS_COLUMNS,
                interpolation_points: INTERPOLATION_POINTS,
            },
            phases: NativeAcceptedRunPhasesV1 {
                trace_start: Some(0),
                trace_end: Some(0),
                core_start: Some(0),
                core_end: Some(0),
                trace_xof_scope_completed: true,
                core_xof_scope_completed: true,
            },
            piop_transcript_words: vec![0; PIOP_WORDS],
            expected_piop_digest: vec![0; 64],
            recomputed_piop_digest: vec![0; 64],
            decs_leaf_indexes: (0..Q38_COUNT as u32).collect(),
            decs_eval_points: vec![0; Q38_COUNT],
            decs_gamma_all: vec![vec![0; 70]; 5],
            lvcs_recovered_rows: vec![vec![0; 70]; Q38_COUNT],
            pcs_coefficients: vec![],
            pcs_combi_heads: vec![],
            pcs_rcombi_tails: vec![],
            pcs_subset_evals: vec![],
            decs_commitment_transcript: vec![],
            decs_root_digest: vec![0; 64],
            decs_nonce: vec![0; 4],
            xof_queries: vec![],
        }
    }

    #[test]
    fn accepted_run_envelope_has_one_canonical_json_encoding() {
        let envelope = test_envelope();
        envelope.validate_shape().unwrap();
        let encoded = canonical_json(&envelope).unwrap();
        let decoded: NativeAcceptedRunEnvelopeV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(canonical_json(&decoded).unwrap(), encoded);
        assert_eq!(decoded.decs_leaf_indexes.len(), Q38_COUNT);
        assert_eq!(decoded.profile.interpolation_points, 406);

        // JSON whitespace is semantically irrelevant to serde, but this
        // source-owned import format rejects it as noncanonical.
        let mut with_space = encoded.clone();
        with_space.push(b' ');
        let decoded: NativeAcceptedRunEnvelopeV1 = serde_json::from_slice(&with_space).unwrap();
        assert_ne!(canonical_json(&decoded).unwrap(), with_space);
    }

    #[test]
    fn imported_run_rejects_a_tampered_q38_index_set() {
        let mut envelope = test_envelope();
        envelope.decs_leaf_indexes[1] = envelope.decs_leaf_indexes[0];
        let bytes = canonical_json(&envelope).unwrap();
        assert!(matches!(
            verify_imported_native_accepted_run_v1(&bytes),
            Err(NativeAcceptedRunImportError::InvalidEnvelope(
                "DECS indexes"
            ))
        ));
    }
}
