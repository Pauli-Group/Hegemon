use protocol_kernel::manifest::{kernel_manifest, protocol_manifest};
use protocol_shielded_pool::family::{
    ACTION_SMALLWOOD_V5_CONVENTIONAL_HASH_INLINE, FAMILY_SHIELDED_POOL,
};
use protocol_versioning::{
    tx_proof_backend_for_version, SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
};

#[test]
fn smallwood_v5_candidate_is_absent_from_every_active_manifest_surface() {
    let protocol = protocol_manifest();
    assert!(!protocol
        .version_bindings
        .contains(&SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING));
    assert!(protocol
        .tx_proof_backends
        .iter()
        .all(|entry| { entry.version != SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING }));
    assert_eq!(
        tx_proof_backend_for_version(SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING),
        None
    );

    let kernel = kernel_manifest();
    assert!(!kernel
        .allowed_bindings
        .contains(&SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING.into()));
    let shielded = kernel
        .families
        .get(&FAMILY_SHIELDED_POOL)
        .expect("shielded family exists");
    assert!(!shielded
        .supported_actions
        .contains(&ACTION_SMALLWOOD_V5_CONVENTIONAL_HASH_INLINE));
}
