//! Fresh SMZE candidate identity with the unchanged native SmallWood parameters.
use super::*;
use crate::smallwood_engine::{
    self, SmallwoodDecsEvaluationDomain, SmallwoodTranscriptBackend,
    ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
};
pub const CANDIDATE_PROOF_MAGIC: [u8; 4] = *b"SMZE";
pub const MAX_CANDIDATE_PROOF_BYTES: usize =
    smallwood_engine::SMALLWOOD_ASSET_SPEND_SMZE_MAX_INNER_PROOF_BYTES;
pub fn candidate_proof_size_hint(
    public: &AssetSpendPublic,
) -> Result<usize, crate::TransactionCircuitError> {
    smallwood_engine::projected_asset_spend_smze_inner_proof_bytes(&AssetSpendAdapter::from_public(
        public,
    )?)
}
pub fn prove_candidate(
    public: &AssetSpendPublic,
    witness: &AssetSpendWitness,
) -> Result<Vec<u8>, crate::TransactionCircuitError> {
    let (adapter, packed) = compile(public, witness)?;
    if smallwood_engine::projected_asset_spend_smze_inner_proof_bytes(&adapter)?
        > MAX_CANDIDATE_PROOF_BYTES
    {
        return Err(error("asset proof projection exceeds cap"));
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
pub fn verify_candidate(
    public: &AssetSpendPublic,
    proof: &[u8],
) -> Result<(), crate::TransactionCircuitError> {
    if proof.get(..4) != Some(CANDIDATE_PROOF_MAGIC.as_slice())
        || proof.len() > MAX_CANDIDATE_PROOF_BYTES
    {
        return Err(error("asset spend requires exact SMZE proof/cap"));
    }
    smallwood_engine::verify_statement_with_transcript_backend_profile_and_domain(
        &AssetSpendAdapter::from_public(public)?,
        &public.binding_bytes(),
        proof,
        ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512AssetSpendSmze,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// Reports the actual adapter configuration and serialization ceiling. This is
/// structural evidence; timings and actual proof bytes require a real proof.
pub fn geometry_receipt(
    public: &AssetSpendPublic,
) -> Result<serde_json::Value, crate::TransactionCircuitError> {
    use crate::smallwood_semantics::SmallwoodConstraintAdapter;
    use sha2::{Digest as _, Sha512};
    let adapter = AssetSpendAdapter::from_public(public)?;
    let geometry = adapter.geometry();
    let policy_mode = public.policy_mode;
    let offsets = adapter.linear_constraint_offsets();
    let indices = adapter.linear_constraint_indices();
    let coefficients = adapter.linear_constraint_coefficients();
    let targets = adapter.linear_targets();
    let suffix = targets
        .len()
        .checked_sub(PUBLIC_WORDS)
        .ok_or_else(|| error("asset public binding suffix missing"))?;
    for (index, value) in public.words().into_iter().enumerate() {
        let start = offsets[suffix + index] as usize;
        let end = offsets[suffix + index + 1] as usize;
        if end != start + 1
            || indices.get(start) != Some(&(index as u32))
            || coefficients.get(start) != Some(&1)
            || targets[suffix + index] != value
        {
            return Err(error("asset public binding suffix mismatch"));
        }
    }
    let mut digest = Sha512::new();
    digest.update(b"AssetSpendNormalizedCSR-v2");
    for value in [
        geometry.rows,
        geometry.canonical_wires,
        geometry.nonlinear_batches,
        geometry.linear_equations,
        geometry.private_inputs,
        geometry.packing,
        geometry.degree,
    ] {
        digest.update((value as u64).to_le_bytes());
    }
    for values in [offsets, indices] {
        digest.update((values.len() as u64).to_le_bytes());
        for value in values {
            digest.update(value.to_le_bytes());
        }
    }
    for value in coefficients {
        digest.update(value.to_le_bytes());
    }
    for (index, value) in targets.iter().enumerate() {
        digest.update((if index < suffix { *value } else { 0 }).to_le_bytes());
    }
    let mut report = smallwood_engine::asset_spend_smze_geometry_receipt(&adapter)?;
    let object = report
        .as_object_mut()
        .ok_or_else(|| error("asset geometry report shape"))?;
    object.insert("policy_mode".into(), serde_json::json!(policy_mode));
    object.insert("public_geometry_disclosed".into(), serde_json::json!(true));
    object.insert(
        "canonical_wires".into(),
        serde_json::json!(geometry.canonical_wires),
    );
    object.insert("rows".into(), serde_json::json!(geometry.rows));
    object.insert(
        "nonlinear_batches".into(),
        serde_json::json!(geometry.nonlinear_batches),
    );
    object.insert(
        "linear_equations".into(),
        serde_json::json!(geometry.linear_equations),
    );
    object.insert(
        "csr_nonzero_entries".into(),
        serde_json::json!(indices.len()),
    );
    object.insert(
        "input_words_including_public".into(),
        serde_json::json!(geometry.private_inputs),
    );
    object.insert(
        "private_witness_input_words".into(),
        serde_json::json!(geometry.private_inputs - PUBLIC_WORDS),
    );
    object.insert(
        "public_binding_rows".into(),
        serde_json::json!(PUBLIC_WORDS),
    );
    object.insert(
        "normalized_csr_sha512".into(),
        serde_json::json!(hex::encode(digest.finalize())),
    );
    object.insert(
        "normalization".into(),
        serde_json::json!(format!(
            "Only final{PUBLIC_WORDS} exact public RHS values replaced by zero"
        )),
    );
    object.insert(
        "source_lowering_certificate_complete".into(),
        serde_json::json!(SOURCE_LOWERING_CERTIFICATE_COMPLETE),
    );
    Ok(report)
}

/// Exact decoder readback, including canonical structured bytes and zero padding.
pub fn proof_wire_receipt(
    proof: &[u8],
) -> Result<serde_json::Value, crate::TransactionCircuitError> {
    smallwood_engine::asset_spend_smze_proof_wire_receipt(proof)
}

/// Decode historical native SMZD bytes under their existing wire identity and
/// report their structured payload size. This does not relabel or verify them.
pub fn native_frame_payload_size(proof: &[u8]) -> Result<usize, crate::TransactionCircuitError> {
    smallwood_engine::native_private_spend_smzd_payload_size(proof)
}
