//! HTLC candidate adapter. Callers supply their authenticated canonical context.
//! Production admission remains disabled until a separately reviewed registry binds it.
use protocol_versioning::{
    launch_candidate::{self, LaunchProofKind, LaunchProofRequest},
    ProofAuthorityClass, TxProofBackend,
};
use std::collections::HashSet;
use transaction_circuit::{
    smallwood_htlc::{self, HtlcStatement},
    smallwood_htlc_transport,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct HtlcCanonicalContext {
    pub network_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub manifest_digest: [u8; 64],
    pub parent_hash: [u8; 32],
    pub parent_height: u64,
    pub note_root: [u64; 7],
}

/// No persistence or state mutation occurs before the entire proof verifies.
#[cfg(test)]
pub(crate) fn verify_development_carrier<'a>(
    exact_bytes: &'a [u8],
    context: HtlcCanonicalContext,
    spent_nullifiers: &HashSet<[u64; 7]>,
) -> Result<smallwood_htlc_transport::HtlcCarrier<'a>, String> {
    let carrier = smallwood_htlc_transport::decode_exact(exact_bytes).map_err(|e| e.to_string())?;
    carrier
        .statement
        .validate_context(
            context.network_id,
            context.parent_hash,
            context.parent_height,
            context.note_root,
        )
        .map_err(|e| e.to_string())?;
    if spent_nullifiers.contains(&carrier.statement.nullifier) {
        return Err("HTLC input already spent".to_owned());
    }
    smallwood_htlc::verify_development(&carrier.statement, carrier.proof)
        .map_err(|e| e.to_string())?;
    Ok(carrier)
}

/// Deliberately no caller-provided enable flag, proof receipt, or RP05 fallback.
pub(crate) fn verify_production_carrier(
    bytes: &[u8],
    context: HtlcCanonicalContext,
    spent_nullifiers: &HashSet<[u64; 7]>,
) -> Result<HtlcStatement, String> {
    let carrier =
        smallwood_htlc_transport::decode_candidate_exact(bytes).map_err(|e| e.to_string())?;
    carrier
        .statement
        .validate_context(
            context.network_id,
            context.parent_hash,
            context.parent_height,
            context.note_root,
        )
        .map_err(|e| e.to_string())?;
    let request = LaunchProofRequest {
        kind: LaunchProofKind::Htlc,
        chain_id: context.network_id,
        genesis_hash: context.genesis_hash,
        manifest_digest: context.manifest_digest,
        relation_digest: smallwood_htlc::relation_digest(),
        height: context
            .parent_height
            .checked_add(1)
            .ok_or("HTLC candidate height overflow")?,
        binding: launch_candidate::HTLC_VERSION_BINDING,
        family_id: launch_candidate::LAUNCH_SHIELDED_FAMILY_ID,
        action_id: launch_candidate::HTLC_ACTION_ID,
        proof_class: ProofAuthorityClass::Transaction,
        backend_id: TxProofBackend::SmallwoodCandidate.wire_id(),
        profile_id: launch_candidate::HTLC_PROFILE_ID,
        domain_set: launch_candidate::HTLC_DOMAIN_SET,
        proof_bytes: carrier.proof.len(),
    };
    launch_candidate::launch_proof_authority(request)
        .ok_or("HTLC successor has no production authorization")?;
    if spent_nullifiers.contains(&carrier.statement.nullifier) {
        return Err("HTLC input already spent".to_owned());
    }
    smallwood_htlc::verify_candidate(&carrier.statement, carrier.proof)
        .map_err(|e| e.to_string())?;
    Ok(carrier.statement)
}
