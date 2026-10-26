//! Exact common proof entry points. Candidate identity is not release authority.
use super::*;
use crate::smallwood_engine::{
    prove_statement_with_transcript_backend_profile_and_domain,
    verify_statement_with_transcript_backend_profile_and_domain, SmallwoodDecsEvaluationDomain,
    SmallwoodTranscriptBackend, NATIVE_PRIVATE_SPEND_SMZD_SMALLWOOD_NO_GRINDING_PROFILE,
    SMALLWOOD_NATIVE_PRIVATE_SPEND_SMZD_MAX_INNER_PROOF_BYTES,
};

pub const CANDIDATE_PROOF_MAGIC: [u8; 4] = *b"SMZL";
pub const MAX_CANDIDATE_PROOF_BYTES: usize =
    SMALLWOOD_NATIVE_PRIVATE_SPEND_SMZD_MAX_INNER_PROOF_BYTES;

pub fn candidate_proof_size_hint(
    public: &PrivateSpendPublic,
) -> Result<usize, TransactionCircuitError> {
    let adapter = PrivateSpendAdapter::from_public(public)?;
    crate::smallwood_engine::projected_native_private_spend_smzd_inner_proof_bytes(&adapter)
}

pub fn prove_candidate(
    public: &PrivateSpendPublic,
    witness: &PrivateSpendWitness,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let (adapter, packed) = compile(public, witness)?;
    let hint =
        crate::smallwood_engine::projected_native_private_spend_smzd_inner_proof_bytes(&adapter)?;
    if hint > MAX_CANDIDATE_PROOF_BYTES {
        return Err(error("private spend projected proof exceeds candidate cap"));
    }
    prove_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &packed,
        &public.binding_bytes(),
        NATIVE_PRIVATE_SPEND_SMZD_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512NativePrivateSpendSmzd,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

pub fn verify_candidate(
    public: &PrivateSpendPublic,
    proof: &[u8],
) -> Result<(), TransactionCircuitError> {
    if proof.get(..4) != Some(CANDIDATE_PROOF_MAGIC.as_slice())
        || proof.len() > MAX_CANDIDATE_PROOF_BYTES
    {
        return Err(error(
            "private spend requires exact compact SMZL proof and candidate cap",
        ));
    }
    let adapter = PrivateSpendAdapter::from_public(public)?;
    verify_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &public.binding_bytes(),
        proof,
        NATIVE_PRIVATE_SPEND_SMZD_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512NativePrivateSpendSmzd,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// Qualification-only path for testing adversarial packed assignments at the
/// actual proof verifier. It never creates a release capability.
#[cfg(feature = "private-spend-dev-artifacts")]
pub fn prove_unchecked_for_qualification(
    public: &PrivateSpendPublic,
    packed: &[u64],
) -> Result<Vec<u8>, TransactionCircuitError> {
    let adapter = PrivateSpendAdapter::from_public(public)?;
    prove_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        packed,
        &public.binding_bytes(),
        NATIVE_PRIVATE_SPEND_SMZD_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512NativePrivateSpendSmzd,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}
