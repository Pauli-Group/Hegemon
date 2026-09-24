use anyhow::Result;
use serde_json::json;
use superneo_hegemon::native_superneo_fixed_identity_v2;

fn main() -> Result<()> {
    let identity = native_superneo_fixed_identity_v2()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": identity.schema_version,
            "params_fingerprint_hex": hex::encode(identity.params_fingerprint),
            "spec_digest_hex": hex::encode(identity.spec_digest),
            "relation_id_hex": hex::encode(identity.relation_id),
            "shape_digest_hex": hex::encode(identity.shape_digest),
            "tx_leaf_artifact_version": identity.tx_leaf_artifact_version,
            "receipt_root_artifact_version": identity.receipt_root_artifact_version,
            "tx_leaf_verifier_profile_hex": hex::encode(identity.tx_leaf_verifier_profile),
            "policy": {
                "identity_selection": "compiled-single-release-target",
                "attacker_selected_registry": false,
                "pre_proof_exact_match_required": true,
                "fixed_32_byte_target_quantum_preimage_bits": 128
            }
        }))?
    );
    Ok(())
}
