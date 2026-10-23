//! Exact graph checks and cost receipts. Projections are not accepted proofs.
use crate::{
    asset_recovery_admin_v1 as admin, asset_recovery_capsule_v1 as capsule,
    asset_recovery_spend_v1 as spend, asset_recovery_v1 as recovery,
};

#[test]
fn preserved_baseline_source_identity() {
    assert_eq!(hex::encode(crate::asset_spend_v1::relation_digest()), "ca5887169d89d2f5b01ef5b48851183cc4b270c3f49f1be099a7717715dbd7b7a849f8b4494a5811ccac0b37d6c09de7b38ea9b62c0b72a6b099bf3d2580025b");
    assert_eq!(hex::encode(crate::asset_policy_admin_v1::relation_digest()), "db34857cf3b8816ef59e779f129fc279bb0ef5ee03744d7ffcd4c87e394aad41ba18417a59a28dcb0c255da7737f42af65856fc63d19b69e7370c0ac26de764a");
}

#[test]
fn emit_exact_graph_costs() {
    let mut receipts = Vec::new();
    for (op, delegate, name) in [
        (0, false, "holder"),
        (0, true, "delegate"),
        (1, false, "mint"),
        (2, true, "delegate_burn"),
    ] {
        let (p, w) = spend::fixtures::fixture(op, delegate).unwrap();
        let (adapter, packed) = spend::compile(&p, &w).unwrap();
        adapter.verify_packed_witness(&packed).unwrap();
        receipts.push(serde_json::json!({"route":name,"geometry":spend::geometry_receipt(&p).unwrap(),"projected_bytes":spend::candidate_proof_size_hint(&p).unwrap(),"source_sha512":hex::encode(spend::relation_digest())}));
    }
    let (p, w) = capsule::fixtures::fixture().unwrap();
    let mut components = Vec::new();
    let mut projected_bundle_bytes = capsule::BUNDLE_HEADER_BYTES;
    for segment in 0..capsule::SEGMENT_COUNT {
        let (adapter, packed) = capsule::compile_segment(&p, &w, segment).unwrap();
        adapter.verify_packed_witness(&packed).unwrap();
        let projected = crate::asset_recovery_backend_v1::projected_bytes(&adapter).unwrap();
        assert!(projected <= capsule::MAX_PROOF_BYTES);
        projected_bundle_bytes = projected_bundle_bytes.checked_add(projected).unwrap();
        components.push(serde_json::json!({
            "segment":segment,
            "source_sha512":hex::encode(capsule::segment_relation_digest(capsule::relation_digest(),segment).unwrap()),
            "packed_witness_verified":true,
            "projected_bytes":projected,
            "component_cap_bytes":capsule::MAX_PROOF_BYTES,
            "geometry":crate::asset_recovery_backend_v1::geometry_receipt(&adapter).unwrap(),
        }));
    }
    assert_eq!(components.len(), capsule::SEGMENT_COUNT);
    assert!(projected_bundle_bytes <= capsule::MAX_CAPSULE_BUNDLE_BYTES);
    receipts.push(serde_json::json!({
        "route":"capsule","proof_magic":"SMRC","component_proof_magic":"SMZR",
        "segment_count":capsule::SEGMENT_COUNT,"components":components,
        "projected_bytes":projected_bundle_bytes,
        "bundle_header_bytes":capsule::BUNDLE_HEADER_BYTES,
        "bundle_cap_bytes":capsule::MAX_CAPSULE_BUNDLE_BYTES,
        "collection_within_bound":true,
        "source_sha512":hex::encode(capsule::relation_digest()),
        "actual_proof_generated":false,
    }));

    let secret = [0, 2, 3, 4, 5, 6, 7];
    let chain = [21; 32];
    let descriptor = recovery::RecoveryDescriptorV1 {
        asset_id: 17,
        stable_policy_id: [3; 7],
        policy_admin_commitment: crate::asset_policy_admin_v1::policy_admin_commitment(
            17, secret,
        )
        .unwrap(),
        archive_key_commitment: [4; 7],
        maximum_powers: recovery::RecoveryPowersV1 {
            transfer: true,
            burn: true,
        },
    };
    let defaults = recovery::freeze_defaults(&descriptor, chain).unwrap();
    let before = recovery::RecoveryRowV1 {
        descriptor,
        controls: recovery::RecoveryControlsV1 {
            epoch: 0,
            delegate_action_commitment: [13; 7],
            revoked: false,
            powers: recovery::RecoveryPowersV1 {
                transfer: true,
                burn: false,
            },
            note_freeze_root: defaults[32],
        },
    };
    let context = recovery::RecoveryContextV1 {
        chain_id: chain,
        parent_hash: [22; 32],
        parent_height: 40,
        row_commitment: before.commitment(chain).unwrap(),
    };
    for freeze in [false, true] {
        let mut after = recovery::RecoveryControlsV1 {
            epoch: 1,
            delegate_action_commitment: [17; 7],
            ..before.controls
        };
        let siblings = core::array::from_fn(|i| defaults[i]);
        let mutation = if freeze {
            after.note_freeze_root =
                recovery::freeze_root(&descriptor, chain, 41, [9; 7], true, &siblings).unwrap();
            Some(admin::FreezeMutation {
                position: 41,
                note_commitment: [9; 7],
                before_frozen: false,
                after_frozen: true,
            })
        } else {
            None
        };
        let prepared = recovery::prepare_controls_update(context, before, after).unwrap();
        let p = admin::Public::from_prepared(&prepared, 42, [23; 7], mutation).unwrap();
        let w = admin::Witness {
            admin_secret: secret,
            freeze_siblings: if freeze { siblings } else { [[0; 7]; 32] },
        };
        let (adapter, packed) = admin::compile(&p, &w).unwrap();
        adapter.verify_packed_witness(&packed).unwrap();
        receipts.push(serde_json::json!({"route":if freeze{"note_freeze"}else{"rotation"},"geometry":crate::asset_recovery_backend_v1::geometry_receipt(&adapter).unwrap(),"projected_bytes":admin::candidate_proof_size_hint(&p).unwrap(),"source_sha512":hex::encode(admin::relation_digest())}));
    }
    println!(
        "RECOVERY_GRAPH_COSTS_V1={}",
        serde_json::to_string(&receipts).unwrap()
    );
}
