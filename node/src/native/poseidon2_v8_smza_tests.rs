// Additive SMZA candidate tests deliberately do not consume the q20 inventory.
#[cfg(feature = "poseidon2-v8-retained-test-support")]
fn load_retained_smza_socket_artifact(
    relative: &str,
    role: &str,
    production: Poseidon2V8ProductionBinding,
) -> RetainedSmz9Artifact {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap();
    let path = retained_carrier_manifest_path(&workspace, relative).unwrap();
    let root = path.parent().unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        manifest["schema"],
        "hegemon-smallwood-poseidon2-v8-smza-retained-artifact-v1"
    );
    assert_eq!(manifest["production_eligible"], false);
    assert_eq!(manifest["identity"]["profile_id"], 9);
    assert_eq!(manifest["identity"]["domain_set"], 5);
    assert_eq!(
        manifest["identity"]["network_id"],
        production.expected_context().network_id()
    );
    assert_eq!(
        manifest["identity"]["relation_digest_hex"],
        hex::encode(production.expected_context().relation_digest())
    );
    let role = match role {
        RETAINED_SMZ9_PRIMARY_ROLE => "primary",
        RETAINED_SMZ9_INDEPENDENT_ROLE => "independent",
        _ => panic!("unrecognized exact SMZA artifact role"),
    };
    let read = |name: &str| {
        let path = root.join(role).join(name);
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert!(metadata.len() <= 169_772);
        assert_eq!(path.canonicalize().unwrap(), path);
        let bytes = std::fs::read(path).unwrap();
        let pin = &manifest["artifacts"][role]["files"][name];
        assert_eq!(pin["bytes"], bytes.len());
        assert_eq!(pin["sha512"], sha512_hex(&bytes));
        bytes
    };
    let proof = read("proof.bin");
    let native_leaf = read("native-leaf.bin");
    let envelope = read("rpc-envelope.bin");
    let inline_args = read("inline-args.bin");
    let decoded = production
        .connector
        .decode_inline_args(&inline_args)
        .unwrap();
    assert_eq!(decoded.envelope().raw(), envelope);
    assert_eq!(decoded.envelope().native_leaf(), native_leaf);
    assert_eq!(decoded.envelope().decoded_native_leaf().proof(), proof);
    let leaf = decoded.envelope().decoded_native_leaf();
    let input = SmallwoodPoseidon2V8VerifierInput {
        network_id: production.expected_context().network_id(),
        relation_digest: production.expected_context().relation_digest(),
        public_values: core::array::from_fn(|i| leaf.statement_word(i).unwrap()),
        relation_balance_binding: core::array::from_fn(|i| {
            leaf.relation_balance_binding_limb(i).unwrap()
        }),
    };
    let words = |values: &[u64]| {
        values
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        read("context.bin"),
        input
            .smza_candidate_transcript_preamble_v1()
            .unwrap()
            .as_bytes()
    );
    assert_eq!(read("public-inputs.bin"), words(&input.public_values));
    assert_eq!(
        read("kernel-binding.bin"),
        words(&input.relation_balance_binding)
    );
    transaction_circuit::smallwood_poseidon2_v8_frontend::verify_smallwood_poseidon2_v8_smza_candidate_v1(&input, &proof).unwrap();
    let statement =
        SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&input.public_values).unwrap();
    let trace = transaction_circuit::smallwood_poseidon2_v8_frontend::build_smallwood_poseidon2_v8_smza_candidate_verifier_trace_v1(&input, &proof).unwrap();
    assert!(trace.accept);
    let wire_salt_hex = hex::encode(trace.proof.salt);
    let decs_transcript_root_hex = hex::encode(trace.pcs_trace.root_digest);
    assert_eq!(
        manifest["artifacts"][role]["proof_evidence"]["wire_salt_hex"],
        wire_salt_hex
    );
    assert_eq!(
        manifest["artifacts"][role]["proof_evidence"]["decs_transcript_root_hex"],
        decs_transcript_root_hex
    );
    for (height, name) in [
        (1_u64, "coinbase-height1.bin"),
        (2_u64, "coinbase-height2.bin"),
    ] {
        let path = root.join(name);
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert!(metadata.len() <= 169_772);
        assert_eq!(path.canonicalize().unwrap(), path);
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(manifest["fixture_files"][name]["bytes"], bytes.len());
        let sha = manifest["fixture_files"][name]["sha512"].as_str().unwrap();
        assert_eq!(sha, sha512_hex(&bytes));
        let _ = retained_coinbase_action(height, &bytes, sha);
    }
    let witness_definition_sha512 = manifest["fixture"]
        ["synthetic_fixture_witness_definition_sha512"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        witness_definition_sha512,
        "62644d23ffb2f01aba180f6e1ff36401fdc3011df22e57a841b2292eecc765c27557f6d3ac00c4ce8644e8b5d5490e7e67566c0873aaa773d5b33cdb6999b57f"
    );
    let input_merkle_path_sha512 = manifest["fixture"]["input_merkle_path_sha512"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let mut pending_action = pending_poseidon2_v8_action_from_inline_args(
        production,
        3,
        protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
        inline_args.clone(),
    )
    .unwrap();
    pending_action.tx_hash = crate::native::pending_action_hash(&pending_action);
    let pending_action_bytes = pending_action.encode();
    RetainedSmz9Artifact {
        proof,
        native_leaf,
        envelope,
        inline_args,
        pending_action_bytes,
        pending_action,
        statement,
        witness_definition_sha512,
        input_merkle_path_sha512,
        wire_salt_hex,
        decs_transcript_root_hex,
    }
}

#[cfg(feature = "poseidon2-v8-retained-test-support")]
pub(crate) fn retained_smza_manifest_coinbase(index: u8) -> (Vec<u8>, String) {
    assert!(index < 2);
    let relative =
        std::env::var("HEGEMON_TEST_RETAINED_SMZA_MANIFEST_PATH").expect("explicit SMZA manifest");
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap();
    let manifest = retained_carrier_manifest_path(&workspace, &relative).unwrap();
    let root = manifest.parent().unwrap();
    let manifest_bytes = std::fs::read(&manifest).unwrap();
    assert_eq!(
        sha512_hex(&manifest_bytes),
        std::env::var(RETAINED_CARRIER_SHA_ENV).expect("pinned SMZA manifest SHA512")
    );
    let value: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let name = format!("coinbase-height{}.bin", u64::from(index) + 1);
    let path = root.join(&name);
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(path.canonicalize().unwrap(), path);
    assert!(metadata.len() <= 169_772);
    let bytes = std::fs::read(path).unwrap();
    let sha = value["fixture_files"][&name]["sha512"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(value["fixture_files"][&name]["bytes"], bytes.len());
    assert_eq!(sha, sha512_hex(&bytes));
    let _ = retained_coinbase_action(u64::from(index) + 1, &bytes, &sha);
    (bytes, sha)
}

#[test]
fn smza_native_profile_selection_is_explicit_and_cross_profile_closed() {
    use protocol_shielded_pool::poseidon2_production_transport::{
        encode_poseidon2_production_smza_envelope, encode_poseidon2_production_smza_inline_args,
        encode_poseidon2_production_smza_native_leaf,
    };
    let historical = test_production(17);
    let candidate = historical.with_test_smza_profile();
    let (old, statement, ciphertext) = action_fixture(historical);
    assert!(Poseidon2V8ActionView::from_pending(candidate, TEST_HEIGHT, &old).is_err());
    let mut proof = vec![0xa5; 64];
    proof[..4].copy_from_slice(b"SMZA");
    let leaf = encode_poseidon2_production_smza_native_leaf(
        candidate.expected_context(),
        &statement.to_public_words(),
        &statement.expected_action_intent().unwrap(),
        [Some(&ciphertext), None],
        &proof,
    )
    .unwrap();
    let envelope =
        encode_poseidon2_production_smza_envelope(candidate.expected_context(), &leaf).unwrap();
    let args =
        encode_poseidon2_production_smza_inline_args(candidate.expected_context(), &envelope)
            .unwrap();
    let mut action = pending_poseidon2_v8_action_from_inline_args(
        candidate,
        TEST_HEIGHT,
        protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
        args,
    )
    .unwrap();
    action.tx_hash = crate::native::pending_action_hash(&action);
    assert!(Poseidon2V8ActionView::from_pending(historical, TEST_HEIGHT, &action).is_err());
    let view = Poseidon2V8ActionView::from_pending(candidate, TEST_HEIGHT, &action).unwrap();
    assert_eq!(view.exact_native_leaf(), leaf);
    let _selected = install_poseidon2_v8_test_binding(candidate);
    crate::native::validate_transfer_action_payload(&action).unwrap();
    assert!(crate::native::validate_transfer_action_payload(&old).is_err());
    let error = candidate
        .connector()
        .verify_exact_v8_leaf(block(0), 0, &leaf)
        .unwrap_err();
    assert!(error.contains("SMZA proof rejected"), "{error}");
    assert_eq!(POSEIDON2_V8_MAX_PENDING_ACTION_BYTES, 131_297);
    assert_eq!(
        super::super::POSEIDON2_V8_SMZA_MAX_PENDING_ACTION_BYTES,
        169_772
    );
    assert!(protocol_versioning::smallwood_poseidon2_production_capability().is_none());
}

#[test]
#[cfg(feature = "poseidon2-v8-retained-test-support")]
#[ignore = "requires explicit source-generated SMZA pair via HEGEMON_TEST_RETAINED_SMZA_MANIFEST_PATH"]
fn retained_smza_pair_survives_native_pending_mining_reorg_restart_and_fresh_import() {
    let path = PathBuf::from(
        std::env::var("HEGEMON_TEST_RETAINED_SMZA_MANIFEST_PATH").expect("explicit SMZA manifest"),
    );
    let root = path.parent().unwrap();
    let allowed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(".agent/artifacts/smallwood-poseidon2-v8-smza");
    assert!(std::fs::canonicalize(root)
        .unwrap()
        .starts_with(std::fs::canonicalize(allowed).unwrap()));
    assert!(!std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        manifest["schema"],
        "hegemon-smallwood-poseidon2-v8-smza-retained-artifact-v1"
    );
    assert_eq!(manifest["identity"]["profile_id"], 9);
    assert_eq!(manifest["identity"]["domain_set"], 5);
    assert!(protocol_versioning::smallwood_poseidon2_production_capability().is_none());
    let production =
        test_production(protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID)
            .with_test_smza_profile()
            .with_test_activation_genesis_hash(
                crate::native::genesis_meta(0x207f_ffff).unwrap().hash,
            );
    let _binding = install_poseidon2_v8_test_binding(production);
    assert_eq!(
        manifest["identity"]["network_id"],
        production.expected_context().network_id()
    );
    assert_eq!(
        manifest["identity"]["relation_digest_hex"],
        hex::encode(production.expected_context().relation_digest())
    );
    let read = |directory: &str, name: &str, pin: &serde_json::Value| {
        let payload_path = root.join(directory).join(name);
        let metadata = std::fs::symlink_metadata(&payload_path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert!(metadata.len() <= 169_772);
        assert!(std::fs::canonicalize(&payload_path)
            .unwrap()
            .starts_with(std::fs::canonicalize(root).unwrap()));
        let bytes = std::fs::read(payload_path).unwrap();
        assert_eq!(pin["bytes"].as_u64(), Some(bytes.len() as u64));
        assert_eq!(pin["sha512"], sha512_hex(&bytes));
        bytes
    };
    let load = |role: &str| {
        let pins = &manifest["artifacts"][role]["files"];
        let args = read(role, "inline-args.bin", &pins["inline-args.bin"]);
        let leaf = read(role, "native-leaf.bin", &pins["native-leaf.bin"]);
        let proof = read(role, "proof.bin", &pins["proof.bin"]);
        let envelope = read(role, "rpc-envelope.bin", &pins["rpc-envelope.bin"]);
        let decoded = decode_poseidon2_production_smza_inline_args_exact(
            production.expected_context(),
            &args,
        )
        .unwrap();
        assert_eq!(decoded.envelope().raw(), envelope);
        assert_eq!(decoded.envelope().decoded_native_leaf().raw(), leaf);
        assert_eq!(decoded.envelope().decoded_native_leaf().proof(), proof);
        let mut action = pending_poseidon2_v8_action_from_inline_args(
            production,
            3,
            protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
            args,
        )
        .unwrap();
        action.tx_hash = crate::native::pending_action_hash(&action);
        assert!(action.encoded_size() <= super::super::POSEIDON2_V8_SMZA_MAX_PENDING_ACTION_BYTES);
        (action, envelope, leaf, proof)
    };
    let (primary, envelope, leaf, proof) = load("primary");
    let (independent, _, independent_leaf, independent_proof) = load("independent");
    assert_ne!(proof, independent_proof);
    let pview = Poseidon2V8ActionView::from_pending(production, 3, &primary).unwrap();
    let iview = Poseidon2V8ActionView::from_pending(production, 3, &independent).unwrap();
    assert_eq!(pview.statement(), iview.statement());
    assert_eq!(pview.statement().activity_mask(), 15);
    let coinbase = |height: u64| {
        let name = format!("coinbase-height{height}.bin");
        let pin = &manifest["fixture_files"][&name];
        let bytes = read("", &name, pin);
        retained_coinbase_action(height, &bytes, pin["sha512"].as_str().unwrap()).0
    };
    let directory = tempfile::tempdir().unwrap();
    let config = retained_native_config(directory.path(), "smza-primary");
    let node = crate::native::NativeNode::open(config.clone()).unwrap();
    let b1 = mine_exact_pending_fixture(&node, &coinbase(1));
    let b2 = mine_exact_pending_fixture(&node, &coinbase(2));
    let mut corrupted_envelope = envelope.clone();
    *corrupted_envelope.last_mut().unwrap() ^= 1;
    let corrupted_request =
        wallet::node_rpc::prepare_poseidon2_smza_submit_request_json_for_retained_test(
            production.expected_context(),
            &corrupted_envelope,
        )
        .unwrap();
    let rejection = node
        .validate_and_stage_action(corrupted_request)
        .unwrap_err();
    assert!(
        rejection.to_string().contains("SMZA proof rejected"),
        "{rejection}"
    );
    let request = wallet::node_rpc::prepare_poseidon2_smza_submit_request_json_for_retained_test(
        production.expected_context(),
        &envelope,
    )
    .unwrap();
    let staged = node.validate_and_stage_action(request).unwrap();
    assert_eq!(staged.encode(), primary.encode());
    let b3 = mine_current_retained_template(&node, &[primary.encode()]);
    let other_dir = tempfile::tempdir().unwrap();
    let other = crate::native::NativeNode::open(retained_native_config(
        other_dir.path(),
        "smza-independent",
    ))
    .unwrap();
    import_exact_retained_blocks(&other, &[b1.clone(), b2.clone()]);
    let relayed =
        crate::native::decode_native_peer_pending_action_v3(&independent.encode(), 3).unwrap();
    assert_eq!(
        other
            .stage_relayed_pending_action(relayed)
            .unwrap()
            .unwrap()
            .encode(),
        independent.encode()
    );
    let i3 = mine_current_retained_template(&other, &[independent.encode()]);
    let i4 = mine_current_retained_template(&other, &[]);
    let branch_dir = tempfile::tempdir().unwrap();
    let branch =
        crate::native::NativeNode::open(retained_native_config(branch_dir.path(), "smza-branch"))
            .unwrap();
    import_exact_retained_blocks(&branch, &[b1.clone(), b2.clone(), b3.clone()]);
    let b4 = mine_current_retained_template(&branch, &[]);
    let b5 = mine_current_retained_template(&branch, &[]);
    import_exact_retained_blocks(&node, &[i3, i4.clone()]);
    assert_eq!(node.best_meta().hash, i4.hash);
    assert_eq!(
        node.load_canonical_block_at_height_unverified(3)
            .unwrap()
            .action_bytes,
        vec![independent.encode()]
    );
    import_exact_retained_blocks(&node, &[b4.clone(), b5.clone()]);
    assert_eq!(node.best_meta().hash, b5.hash);
    drop(node);
    let restarted = crate::native::NativeNode::reopen_after_sled_release_for_test(config).unwrap();
    let fresh_dir = tempfile::tempdir().unwrap();
    let fresh =
        crate::native::NativeNode::open(retained_native_config(fresh_dir.path(), "smza-fresh"))
            .unwrap();
    import_exact_retained_blocks(&fresh, &[b1, b2, b3, b4, b5.clone()]);
    for current in [&restarted, &fresh] {
        assert_eq!(current.best_meta().hash, b5.hash);
        assert_eq!(
            current
                .load_canonical_block_at_height_unverified(3)
                .unwrap()
                .action_bytes,
            vec![primary.encode()]
        );
    }
    let canonical_state = |node: &crate::native::NativeNode| {
        let store = Poseidon2V8StateStore::open(
            &node.db,
            Poseidon2V8Checkpoint::new(
                0,
                production.activation_genesis_hash(),
                production.stablecoin_genesis_root(),
            ),
            production.note_genesis_root(),
        )
        .unwrap();
        (store.tip().unwrap(), store.note_tip().unwrap())
    };
    assert_eq!(canonical_state(&restarted), canonical_state(&fresh));
    assert_eq!(pview.exact_native_leaf(), leaf);
    assert_eq!(iview.exact_native_leaf(), independent_leaf);
    assert!(protocol_versioning::smallwood_poseidon2_production_capability().is_none());
}
