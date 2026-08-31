//! Exhaustive executable-relation acceptance and mutation tests for SmallWood Poseidon2 V8.
//!
//! These tests deliberately use only the public compiler and verifier API.  In
//! particular, no prover-only assignment helper is imported from the relation
//! implementation.  A passing fixture therefore demonstrates that an ordinary
//! caller can construct the typed witness, compile it, and replay verification.

use transaction_circuit::{
    projected_poseidon2_v8_smz9_inner_proof_bytes,
    smallwood_frontend::SmallwoodPrivateAuthMode,
    smallwood_poseidon2_v8_hash_constraints::smallwood_poseidon2_v8_hash_call_initial_witness_index,
    smallwood_poseidon2_v8_hash_schedule::build_smallwood_poseidon2_v8_hash_schedule,
    smallwood_poseidon2_v8_program::{
        SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES,
        SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES,
    },
    smallwood_poseidon2_v8_semantic_refinement::{
        audit_smallwood_poseidon2_v8_typed_lowering, SMALLWOOD_POSEIDON2_V8_EXACT_SEMANTIC_TARGET,
        SMALLWOOD_POSEIDON2_V8_SEMANTIC_REFINEMENT_SCHEMA,
    },
    smallwood_poseidon2_v8_semantics::{
        compile_smallwood_poseidon2_v8_relation, decode_smallwood_poseidon2_v8_packed_witness,
        SmallwoodPoseidon2V8ConstraintAdapter, SmallwoodPoseidon2V8RelationError,
        SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START, SMALLWOOD_POSEIDON2_V8_HASH_ROW_START,
        SMALLWOOD_POSEIDON2_V8_INLINE_ROW_START, SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT,
        SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR, SMALLWOOD_POSEIDON2_V8_ROW_COUNT,
        SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START,
    },
    smallwood_poseidon2_v8_types::{
        SmallwoodPoseidon2V8AccumulatorOpening, SmallwoodPoseidon2V8CompatibilityStablecoin,
        SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8InputWitness,
        SmallwoodPoseidon2V8NoteOpening, SmallwoodPoseidon2V8OutputWitness,
        SmallwoodPoseidon2V8PrivateAuthWitness, SmallwoodPoseidon2V8PublicStatement,
        SmallwoodPoseidon2V8SurfaceError, SmallwoodPoseidon2V8Witness,
    },
    SmallwoodConfig, POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
};
use transaction_core::{
    constants::{BALANCE_SLOT_PADDING_FIELD_ID, NATIVE_ASSET_ID},
    poseidon2_width16::Felt,
    stablecoin_poseidon2_v8::{
        stablecoin_poseidon2_v8_config_digest, stablecoin_poseidon2_v8_issuer_authorization,
        stablecoin_poseidon2_v8_issuer_commitment, stablecoin_poseidon2_v8_root,
        StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters, StablecoinPoseidon2V8Direction,
        StablecoinPoseidon2V8Public, StablecoinPoseidon2V8Witness,
    },
};

const INPUT_0_NOTE_FINAL: usize = 3;
const INPUT_0_ROOT_FINAL: usize = 35;
const INPUT_0_NULLIFIER_FINAL: usize = 36;
const INPUT_1_NOTE_FINAL: usize = 39;
const INPUT_1_ROOT_FINAL: usize = 71;
const INPUT_1_NULLIFIER_FINAL: usize = 72;
const OUTPUT_0_NOTE_FINAL: usize = 75;
const OUTPUT_1_NOTE_FINAL: usize = 78;
const POLICY_FINAL: usize = 97;
const CURRENT_FINAL: usize = 100;
const NEXT_FINAL: usize = 103;
const VALUE_LOCK_FINAL: usize = 105;
const DISABLED_PARENT_HEIGHT: u64 = 9_001;

fn install_disabled_stablecoin_context(statement: &mut SmallwoodPoseidon2V8PublicStatement) {
    statement.stablecoin = StablecoinPoseidon2V8Public::disabled_at_context(
        DISABLED_PARENT_HEIGHT,
        felt_digest(70_000),
    );
}

fn assert_exact_csr_program_receipt(adapter: &SmallwoodPoseidon2V8ConstraintAdapter) {
    let receipt = adapter.csr_family_receipt();
    assert_eq!(
        receipt
            .attempted_instances
            .iter()
            .map(|count| *count as usize)
            .sum::<usize>(),
        SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES
    );
    assert_eq!(
        receipt.attempted_instances,
        SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES.map(|family| family.instances)
    );
    assert_eq!(
        receipt.emitted_total as usize,
        adapter.geometry().linear_constraints
    );
    assert_eq!(
        adapter.linear_constraint_family_ids().len(),
        adapter.geometry().linear_constraints
    );
    for family_index in 0..SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES.len() {
        let span = receipt
            .emitted_span(family_index)
            .expect("all canonical family indices have an emitted span");
        assert_eq!(span.len(), receipt.emitted_instances[family_index] as usize);
        assert!(
            adapter.linear_constraint_family_ids()[span.start as usize..span.end as usize]
                .iter()
                .all(|family| usize::from(*family) == family_index)
        );
    }
}

fn digest(tag: u64) -> SmallwoodPoseidon2V8Digest {
    core::array::from_fn(|limb| tag + limb as u64)
}

fn felt_digest(tag: u64) -> [Felt; 7] {
    digest(tag).map(Felt::from_u64)
}

fn note(tag: u64, value: u64, asset_id: u64) -> SmallwoodPoseidon2V8NoteOpening {
    SmallwoodPoseidon2V8NoteOpening {
        value,
        asset_id,
        recipient_key: core::array::from_fn(|limb| tag + 10 + limb as u64),
        authorization_key: [0; 4],
        rho: core::array::from_fn(|limb| tag + 20 + limb as u64),
        randomness: core::array::from_fn(|limb| tag + 30 + limb as u64),
    }
}

fn set_activity(
    mask: u8,
    statement: &mut SmallwoodPoseidon2V8PublicStatement,
    witness: &mut SmallwoodPoseidon2V8Witness,
) {
    for input in 0..2 {
        let active = mask & (1 << input) != 0;
        statement.input_flags[input] = active;
        if active {
            witness.inputs[input] = SmallwoodPoseidon2V8InputWitness {
                active: true,
                spend_key: [101, 102, 103, 104],
                note: note(1_000 + input as u64 * 100, 0, NATIVE_ASSET_ID),
                position: input as u64,
                siblings: [[0; 7]; 32],
                balance_slot_selectors: [true, false, false, false],
            };
        }
    }
    for output in 0..2 {
        let active = mask & (1 << (output + 2)) != 0;
        statement.output_flags[output] = active;
        if active {
            statement.ciphertext_commitments[output] =
                core::array::from_fn(|limb| 2_000 + output as u64 * 100 + limb as u64);
            witness.outputs[output] = SmallwoodPoseidon2V8OutputWitness {
                active: true,
                note: note(3_000 + output as u64 * 100, 0, NATIVE_ASSET_ID),
                balance_slot_selectors: [true, false, false, false],
            };
        }
    }
}

fn install_merkle_paths(
    statement: &mut SmallwoodPoseidon2V8PublicStatement,
    witness: &mut SmallwoodPoseidon2V8Witness,
) {
    let preliminary = build_smallwood_poseidon2_v8_hash_schedule(statement, witness).unwrap();
    let leaves = [
        preliminary.calls[INPUT_0_NOTE_FINAL].final_digest(),
        preliminary.calls[INPUT_1_NOTE_FINAL].final_digest(),
    ];
    match statement.input_flags {
        [false, false] => {}
        [true, false] | [false, true] => {
            let input = usize::from(statement.input_flags[1]);
            witness.inputs[input].position = 0;
            witness.inputs[input].siblings =
                core::array::from_fn(|level| digest(4_000 + level as u64 * 20));
        }
        [true, true] => {
            witness.inputs[0].position = 0;
            witness.inputs[1].position = 1;
            witness.inputs[0].siblings[0] = leaves[1];
            witness.inputs[1].siblings[0] = leaves[0];
            for level in 1..32 {
                let sibling = digest(4_000 + level as u64 * 20);
                witness.inputs[0].siblings[level] = sibling;
                witness.inputs[1].siblings[level] = sibling;
            }
        }
    }

    let material = build_smallwood_poseidon2_v8_hash_schedule(statement, witness).unwrap();
    let mut expected_root = None;
    for (input, call) in [INPUT_0_ROOT_FINAL, INPUT_1_ROOT_FINAL]
        .into_iter()
        .enumerate()
    {
        if statement.input_flags[input] {
            let root = material.calls[call].final_digest();
            if let Some(previous) = expected_root {
                assert_eq!(root, previous, "two active paths must share one root");
            }
            expected_root = Some(root);
        }
    }
    statement.merkle_root = expected_root.unwrap_or([0; 7]);
}

fn install_transaction_public_hashes(
    statement: &mut SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) {
    let material = build_smallwood_poseidon2_v8_hash_schedule(statement, witness).unwrap();
    for (input, call) in [INPUT_0_NULLIFIER_FINAL, INPUT_1_NULLIFIER_FINAL]
        .into_iter()
        .enumerate()
    {
        if statement.input_flags[input] {
            statement.nullifiers[input] = material.calls[call].final_digest();
        }
    }
    for (output, call) in [OUTPUT_0_NOTE_FINAL, OUTPUT_1_NOTE_FINAL]
        .into_iter()
        .enumerate()
    {
        if statement.output_flags[output] {
            statement.commitments[output] = material.calls[call].final_digest();
        }
    }
}

fn policy_tags(member: [u64; 5]) -> [[u64; 5]; 6] {
    let mut tags = [[0; 5]; 6];
    tags[0] = member;
    tags[1] = core::array::from_fn(|limb| 8_000 + limb as u64);
    assert_ne!(tags[0][0], tags[1][0]);
    tags
}

fn opening(
    policy_root: SmallwoodPoseidon2V8Digest,
    intent_digest: SmallwoodPoseidon2V8Digest,
    approval_count: u64,
    approved_slots: [bool; 6],
) -> SmallwoodPoseidon2V8AccumulatorOpening {
    SmallwoodPoseidon2V8AccumulatorOpening {
        policy_root,
        intent_digest,
        threshold: 1,
        signer_count: 2,
        approval_count,
        approved_slots,
    }
}

fn single_key_fixture(
    mask: u8,
) -> (
    SmallwoodPoseidon2V8PublicStatement,
    SmallwoodPoseidon2V8Witness,
) {
    let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
    install_disabled_stablecoin_context(&mut statement);
    let mut witness = SmallwoodPoseidon2V8Witness::default();
    set_activity(mask, &mut statement, &mut witness);

    let legacy = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)
        .unwrap()
        .calls[0]
        .final_digest();
    for input in 0..2 {
        if statement.input_flags[input] {
            witness.inputs[input]
                .note
                .authorization_key
                .copy_from_slice(&legacy[1..5]);
        }
    }
    install_merkle_paths(&mut statement, &mut witness);
    install_transaction_public_hashes(&mut statement, &witness);
    (statement, witness)
}

fn approval_fixture(
    mask: u8,
) -> (
    SmallwoodPoseidon2V8PublicStatement,
    SmallwoodPoseidon2V8Witness,
) {
    assert!(matches!(mask, 0b0111 | 0b1111));
    let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
    install_disabled_stablecoin_context(&mut statement);
    let mut witness = SmallwoodPoseidon2V8Witness::default();
    set_activity(mask, &mut statement, &mut witness);

    let legacy = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)
        .unwrap()
        .calls[0]
        .final_digest();
    let tags = policy_tags(legacy[..5].try_into().unwrap());
    let intent = digest(9_000);
    witness.auth = SmallwoodPoseidon2V8PrivateAuthWitness {
        mode: SmallwoodPrivateAuthMode::ApprovalStep,
        current: opening(digest(9_100), intent, 0, [false; 6]),
        next: opening(
            digest(9_100),
            intent,
            1,
            [true, false, false, false, false, false],
        ),
        policy_signer_tags: tags,
    };
    let material = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness).unwrap();
    let root = material.calls[POLICY_FINAL].final_digest();
    witness.auth.current.policy_root = root;
    witness.auth.next.policy_root = root;

    let material = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness).unwrap();
    let current = material.calls[CURRENT_FINAL].final_digest();
    let next = material.calls[NEXT_FINAL].final_digest();
    witness.inputs[0]
        .note
        .authorization_key
        .copy_from_slice(&current[..4]);
    witness.inputs[1]
        .note
        .authorization_key
        .copy_from_slice(&legacy[1..5]);
    witness.outputs[0]
        .note
        .authorization_key
        .copy_from_slice(&next[..4]);

    install_merkle_paths(&mut statement, &mut witness);
    install_transaction_public_hashes(&mut statement, &witness);
    (statement, witness)
}

fn six_signer_approval_fixture() -> (
    SmallwoodPoseidon2V8PublicStatement,
    SmallwoodPoseidon2V8Witness,
) {
    let (mut statement, mut witness) = approval_fixture(0b1111);
    witness.auth.current.signer_count = 6;
    witness.auth.next.signer_count = 6;
    for slot in 2..6 {
        witness.auth.policy_signer_tags[slot] =
            core::array::from_fn(|limb| 8_000 + slot as u64 * 100 + limb as u64);
    }

    let policy = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)
        .unwrap()
        .calls[POLICY_FINAL]
        .final_digest();
    witness.auth.current.policy_root = policy;
    witness.auth.next.policy_root = policy;

    let material = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness).unwrap();
    let legacy = material.calls[0].final_digest();
    let current = material.calls[CURRENT_FINAL].final_digest();
    let next = material.calls[NEXT_FINAL].final_digest();
    witness.inputs[0]
        .note
        .authorization_key
        .copy_from_slice(&current[..4]);
    witness.inputs[1]
        .note
        .authorization_key
        .copy_from_slice(&legacy[1..5]);
    witness.outputs[0]
        .note
        .authorization_key
        .copy_from_slice(&next[..4]);

    install_merkle_paths(&mut statement, &mut witness);
    install_transaction_public_hashes(&mut statement, &witness);
    (statement, witness)
}

fn final_fixture(
    mask: u8,
) -> (
    SmallwoodPoseidon2V8PublicStatement,
    SmallwoodPoseidon2V8Witness,
) {
    assert!(matches!(mask, 0b0011 | 0b0111 | 0b1011 | 0b1111));
    let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
    install_disabled_stablecoin_context(&mut statement);
    let mut witness = SmallwoodPoseidon2V8Witness::default();
    set_activity(mask, &mut statement, &mut witness);

    let legacy = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)
        .unwrap()
        .calls[0]
        .final_digest();
    let tags = policy_tags(legacy[..5].try_into().unwrap());
    witness.auth = SmallwoodPoseidon2V8PrivateAuthWitness {
        mode: SmallwoodPrivateAuthMode::FinalThresholdSpend,
        current: opening(
            digest(9_100),
            digest(9_200),
            1,
            [true, false, false, false, false, false],
        ),
        next: SmallwoodPoseidon2V8AccumulatorOpening::ZERO,
        policy_signer_tags: tags,
    };
    let policy = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)
        .unwrap()
        .calls[POLICY_FINAL]
        .final_digest();
    witness.auth.current.policy_root = policy;

    // Output commitments and their public ciphertext commitments are independent
    // of the final authorization intent.  Install them before deriving that
    // intent so the final plan commits to its exact outputs.
    install_transaction_public_hashes(&mut statement, &witness);
    witness.auth.current.intent_digest = statement.expected_action_intent().unwrap();

    let material = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness).unwrap();
    let current = material.calls[CURRENT_FINAL].final_digest();
    let value_lock = material.calls[VALUE_LOCK_FINAL].final_digest();
    witness.inputs[0]
        .note
        .authorization_key
        .copy_from_slice(&value_lock[..4]);
    witness.inputs[1]
        .note
        .authorization_key
        .copy_from_slice(&current[..4]);

    install_merkle_paths(&mut statement, &mut witness);
    install_transaction_public_hashes(&mut statement, &witness);
    assert_eq!(
        witness.auth.current.intent_digest,
        statement.expected_action_intent().unwrap(),
        "the canonical final intent projection must not depend on input-tree placement"
    );
    (statement, witness)
}

fn stable_fixture(
    direction: StablecoinPoseidon2V8Direction,
) -> (
    SmallwoodPoseidon2V8PublicStatement,
    SmallwoodPoseidon2V8Witness,
) {
    const HEIGHT: u64 = 9_000;
    const ASSET: u32 = 1_001;
    const POLICY_VERSION: u32 = 7;
    const MAGNITUDE: u64 = 25;

    let issuer_secret = felt_digest(11);
    let config = StablecoinPoseidon2V8Config {
        asset_id: ASSET,
        policy_version: POLICY_VERSION,
        active: true,
        enabled_at: 1,
        retired_at: Some(20_000),
        issuer_commitment: stablecoin_poseidon2_v8_issuer_commitment(
            ASSET,
            POLICY_VERSION,
            &issuer_secret,
        ),
        min_collateral_ratio_ppm: 1_500_000,
        max_mint_per_epoch: 1_000_000,
        oracle_submitted_at: 8_900,
        oracle_max_age: 500,
        oracle_price_numerator: 2,
        oracle_price_denominator: 1,
        collateral_amount: 10_000,
        attestation_created_at: 8_800,
        attestation_disputed: false,
        attestation_present: true,
        attestation_max_age: 500,
        policy_admin_commitment: felt_digest(101),
        oracle_authority_commitment: felt_digest(201),
        attestation_authority_commitment: felt_digest(301),
        collateral_asset_id: 0,
        collateral_decimals: 6,
        collateral_scale: 1_000_000,
        locked_collateral_commitment: felt_digest(401),
    };
    let before = StablecoinPoseidon2V8Counters {
        epoch_id: HEIGHT >> 12,
        minted_in_epoch: 100,
        total_debt: 1_000,
        sequence: 9,
    };
    let mut after = before;
    after.sequence += 1;
    match direction {
        StablecoinPoseidon2V8Direction::Mint => {
            after.minted_in_epoch += MAGNITUDE;
            after.total_debt += MAGNITUDE;
        }
        StablecoinPoseidon2V8Direction::Burn => after.total_debt -= MAGNITUDE,
        StablecoinPoseidon2V8Direction::Disabled => unreachable!(),
    }
    let siblings = [
        felt_digest(501),
        felt_digest(601),
        felt_digest(701),
        felt_digest(801),
    ];
    let config_digest = stablecoin_poseidon2_v8_config_digest(config);
    let before_root =
        stablecoin_poseidon2_v8_root(ASSET, config_digest, before, &siblings).unwrap();
    let after_root = stablecoin_poseidon2_v8_root(ASSET, config_digest, after, &siblings).unwrap();

    let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
    let mut witness = SmallwoodPoseidon2V8Witness::default();
    statement.balance_assets = [
        NATIVE_ASSET_ID,
        u64::from(ASSET),
        BALANCE_SLOT_PADDING_FIELD_ID,
        BALANCE_SLOT_PADDING_FIELD_ID,
    ];
    statement.compatibility_stablecoin = SmallwoodPoseidon2V8CompatibilityStablecoin {
        enabled: true,
        asset_id: u64::from(ASSET),
        policy_version: POLICY_VERSION,
        issuance_sign: direction == StablecoinPoseidon2V8Direction::Mint,
        issuance_magnitude: MAGNITUDE,
        reserved_legacy_stablecoin_commitments: [[0; 6]; 3],
    };
    statement.stablecoin = StablecoinPoseidon2V8Public {
        direction,
        asset_id: ASSET,
        policy_version: POLICY_VERSION,
        magnitude: MAGNITUDE,
        action_intent: [Felt::ZERO; 7],
        parent_height: HEIGHT,
        before_root,
        after_root,
        after,
        issuer_authorization: [Felt::ZERO; 7],
    };
    witness.stablecoin = StablecoinPoseidon2V8Witness {
        config,
        before,
        siblings,
        issuer_secret: if direction == StablecoinPoseidon2V8Direction::Mint {
            issuer_secret
        } else {
            [Felt::ZERO; 7]
        },
    };

    match direction {
        StablecoinPoseidon2V8Direction::Mint => {
            statement.output_flags[0] = true;
            statement.ciphertext_commitments[0] = [2_001, 2_002, 2_003, 2_004, 2_005, 2_006];
            witness.outputs[0] = SmallwoodPoseidon2V8OutputWitness {
                active: true,
                note: note(12_000, MAGNITUDE, u64::from(ASSET)),
                balance_slot_selectors: [false, true, false, false],
            };
        }
        StablecoinPoseidon2V8Direction::Burn => {
            statement.input_flags[0] = true;
            witness.inputs[0] = SmallwoodPoseidon2V8InputWitness {
                active: true,
                spend_key: [101, 102, 103, 104],
                note: note(13_000, MAGNITUDE, u64::from(ASSET)),
                position: 0,
                siblings: [[0; 7]; 32],
                balance_slot_selectors: [false, true, false, false],
            };
            let legacy = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)
                .unwrap()
                .calls[0]
                .final_digest();
            witness.inputs[0]
                .note
                .authorization_key
                .copy_from_slice(&legacy[1..5]);
            install_merkle_paths(&mut statement, &mut witness);
        }
        StablecoinPoseidon2V8Direction::Disabled => unreachable!(),
    }
    install_transaction_public_hashes(&mut statement, &witness);
    let intent = statement
        .expected_action_intent()
        .unwrap()
        .map(Felt::from_u64);
    statement.stablecoin.action_intent = intent;
    if direction == StablecoinPoseidon2V8Direction::Mint {
        statement.stablecoin.issuer_authorization =
            stablecoin_poseidon2_v8_issuer_authorization(&intent, &issuer_secret);
    }
    (statement, witness)
}

fn compile_and_replay(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) {
    let semantic_receipt = audit_smallwood_poseidon2_v8_typed_lowering(statement, witness).unwrap();
    assert_eq!(
        semantic_receipt.schema,
        SMALLWOOD_POSEIDON2_V8_SEMANTIC_REFINEMENT_SCHEMA
    );
    assert_eq!(
        semantic_receipt.semantic_target,
        SMALLWOOD_POSEIDON2_V8_EXACT_SEMANTIC_TARGET
    );
    assert_eq!(semantic_receipt.activity_mask, statement.activity_mask());
    assert!(semantic_receipt.packed_program_accepts_typed_lowering);
    assert!(!semantic_receipt.universal_accepted_witness_soundness_proved);
    assert!(!semantic_receipt.production_authority);

    let lowered = compile_smallwood_poseidon2_v8_relation(statement, witness).unwrap();
    assert_eq!(
        decode_smallwood_poseidon2_v8_packed_witness(statement, &lowered.witness_values).unwrap(),
        *witness,
        "the arbitrary packed-assignment decoder must recover the exact typed witness"
    );
    SmallwoodConfig::new_with_profile(
        &lowered.adapter,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
    )
    .unwrap();
    assert_eq!(
        projected_poseidon2_v8_smz9_inner_proof_bytes(&lowered.adapter).unwrap(),
        122_863
    );
    lowered
        .adapter
        .verify_packed_witness(&lowered.witness_values)
        .unwrap();
}

#[test]
fn all_sixteen_single_key_masks_compile_and_replay() {
    for mask in 0..16u8 {
        let (statement, witness) = single_key_fixture(mask);
        compile_and_replay(&statement, &witness);
    }
}

#[test]
fn every_valid_approval_and_final_mask_compiles_and_all_other_masks_fail_closed() {
    for mask in 0..16u8 {
        if matches!(mask, 0b0111 | 0b1111) {
            let (statement, witness) = approval_fixture(mask);
            compile_and_replay(&statement, &witness);
        } else {
            let (statement, mut witness) = single_key_fixture(mask);
            witness.auth.mode = SmallwoodPrivateAuthMode::ApprovalStep;
            assert!(matches!(
                witness.validate_against_statement(&statement),
                Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationShape)
                    | Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening)
            ));
        }

        if matches!(mask, 0b0011 | 0b0111 | 0b1011 | 0b1111) {
            let (statement, witness) = final_fixture(mask);
            compile_and_replay(&statement, &witness);
        } else {
            let (statement, mut witness) = single_key_fixture(mask);
            witness.auth.mode = SmallwoodPrivateAuthMode::FinalThresholdSpend;
            assert!(matches!(
                witness.validate_against_statement(&statement),
                Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationShape)
                    | Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening)
            ));
        }
    }
}

#[test]
fn disabled_mint_and_burn_stablecoin_relations_compile_and_replay() {
    let (statement, witness) = single_key_fixture(0b0101);
    assert_eq!(statement.stablecoin.parent_height, DISABLED_PARENT_HEIGHT);
    assert_eq!(statement.stablecoin.before_root, felt_digest(70_000));
    assert_eq!(statement.stablecoin.after_root, felt_digest(70_000));
    assert_eq!(
        statement.stablecoin,
        StablecoinPoseidon2V8Public::disabled_at_context(
            DISABLED_PARENT_HEIGHT,
            felt_digest(70_000),
        )
    );
    assert_eq!(witness.stablecoin, StablecoinPoseidon2V8Witness::ZERO);
    compile_and_replay(&statement, &witness);

    let mut wrong_height = statement;
    wrong_height.stablecoin.parent_height += 1;
    assert!(SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&wrong_height).is_ok());
    let wrong_height_context =
        transaction_core::stablecoin_poseidon2_v8::StablecoinPoseidon2V8Context {
            current_root: statement.stablecoin.before_root,
            parent_height: DISABLED_PARENT_HEIGHT,
            expected_action_intent: [Felt::ZERO; 7],
        };
    assert!(
        transaction_core::stablecoin_poseidon2_v8::verify_stablecoin_transition_v8(
            wrong_height_context,
            wrong_height.stablecoin,
            witness.stablecoin,
        )
        .is_err()
    );

    let mut wrong_after_root = statement;
    wrong_after_root.stablecoin.after_root[0] += Felt::ONE;
    assert!(matches!(
        wrong_after_root.validate_public_structure(),
        Err(SmallwoodPoseidon2V8SurfaceError::NonCanonicalStablecoinCompatibility)
    ));

    for direction in [
        StablecoinPoseidon2V8Direction::Mint,
        StablecoinPoseidon2V8Direction::Burn,
    ] {
        let (statement, witness) = stable_fixture(direction);
        compile_and_replay(&statement, &witness);
    }
}

#[test]
fn transparent_value_balance_words_reject_in_typed_and_executable_surfaces() {
    let (statement, witness) = single_key_fixture(0b1111);
    let lowered = compile_smallwood_poseidon2_v8_relation(&statement, &witness).unwrap();
    let family_index = SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES
        .iter()
        .position(|family| family.name == "base.transparent_value_balance_zero")
        .expect("transparent value-balance family is frozen in HGV8RP03");
    let span = lowered
        .adapter
        .csr_family_receipt()
        .emitted_span(family_index)
        .expect("canonical value-balance family span exists");
    assert_eq!(span.len(), 2);

    let mut signed = statement;
    signed.value_balance_sign = true;
    assert!(matches!(
        signed.validate_public_structure(),
        Err(SmallwoodPoseidon2V8SurfaceError::NegativeZeroValueBalance)
    ));

    let mut magnitude = statement;
    magnitude.value_balance_magnitude = 1;
    assert!(matches!(
        magnitude.validate_public_structure(),
        Err(SmallwoodPoseidon2V8SurfaceError::ValueOutOfRange)
    ));
}

#[test]
fn private_hash_public_and_inactive_mutations_all_fail_closed() {
    let (statement, witness) = single_key_fixture(0b1111);
    let lowered = compile_smallwood_poseidon2_v8_relation(&statement, &witness).unwrap();

    let mut private_row = lowered.witness_values.clone();
    private_row[0] ^= 1;
    assert!(lowered.adapter.verify_packed_witness(&private_row).is_err());

    let mut hash_link = lowered.witness_values.clone();
    let relative = smallwood_poseidon2_v8_hash_call_initial_witness_index(0, 0);
    let index =
        SMALLWOOD_POSEIDON2_V8_HASH_ROW_START * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR + relative;
    hash_link[index] ^= 1;
    assert!(lowered.adapter.verify_packed_witness(&hash_link).is_err());

    let mut changed_public = statement;
    changed_public.ciphertext_commitments[0][0] += 1;
    let changed_adapter =
        SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&changed_public).unwrap();
    assert!(changed_adapter
        .verify_packed_witness(&lowered.witness_values)
        .is_err());

    let inactive_statement = SmallwoodPoseidon2V8PublicStatement::default();
    let inactive_witness = SmallwoodPoseidon2V8Witness::default();
    let inactive =
        compile_smallwood_poseidon2_v8_relation(&inactive_statement, &inactive_witness).unwrap();
    let mut inactive_private = inactive.witness_values.clone();
    inactive_private[0] = 1;
    assert!(inactive
        .adapter
        .verify_packed_witness(&inactive_private)
        .is_err());
}

#[test]
fn padding_asset_cannot_escape_the_executable_balance_relation() {
    let (statement, witness) = single_key_fixture(0b0001);
    let lowered = compile_smallwood_poseidon2_v8_relation(&statement, &witness).unwrap();

    // Exercise the verifier-only attack surface directly: replace the private active asset with
    // the repeated padding sentinel, then coherently rebuild the Poseidon2 trace and public root.
    // Typed witness admission rejects this value, but the executable relation must reject it too.
    let mut malicious_witness = witness;
    malicious_witness.inputs[0].note.asset_id = BALANCE_SLOT_PADDING_FIELD_ID;
    let malicious_schedule =
        build_smallwood_poseidon2_v8_hash_schedule(&statement, &malicious_witness).unwrap();
    let mut malicious_statement = statement;
    malicious_statement.merkle_root = malicious_schedule.calls[INPUT_0_ROOT_FINAL].final_digest();
    let malicious_adapter =
        SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&malicious_statement).unwrap();

    let mut malicious_values = lowered.witness_values;
    // Input zero's asset is raw row one, replicated across all 64 packing lanes.
    malicious_values
        [SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR..2 * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR]
        .fill(BALANCE_SLOT_PADDING_FIELD_ID);
    for (row, values) in malicious_schedule.packed_rows.as_rows().iter().enumerate() {
        let start =
            (SMALLWOOD_POSEIDON2_V8_HASH_ROW_START + row) * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR;
        malicious_values[start..start + SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR]
            .copy_from_slice(values);
    }
    for input in 0..2 {
        let note_final = if input == 0 {
            INPUT_0_NOTE_FINAL
        } else {
            INPUT_1_NOTE_FINAL
        };
        let merkle_start = if input == 0 { 4 } else { 40 };
        for level in 0..32 {
            let call = merkle_start + level;
            let previous = if level == 0 {
                malicious_schedule.calls[note_final].final_digest()
            } else {
                malicious_schedule.calls[call - 1].final_digest()
            };
            let direction = (malicious_witness.inputs[input].position >> level) & 1;
            for limb in 0..7 {
                let slot = (input * 32 + level) * 7 + limb;
                let group = slot / SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR;
                let lane = slot % SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR;
                let base = (SMALLWOOD_POSEIDON2_V8_INLINE_ROW_START + group * 4)
                    * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR;
                malicious_values[base + lane] = previous[limb];
                malicious_values[base + SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR + lane] =
                    malicious_schedule.calls[call].initial_state[limb];
                malicious_values[base + 2 * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR + lane] =
                    malicious_schedule.calls[call].initial_state[7 + limb];
                malicious_values[base + 3 * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR + lane] =
                    direction;
            }
        }
    }

    assert_eq!(
        malicious_adapter.verify_packed_witness(&malicious_values),
        Err(
            SmallwoodPoseidon2V8RelationError::NonlinearConstraintViolation {
                lane: 0,
                constraint: 63,
            }
        )
    );
}

#[test]
fn every_typed_nonzero_authorization_field_is_linked_to_the_packed_verifier() {
    const FIRST_EXTRA_ROLE_CONDITION: usize = 21;
    let (statement, witness) = six_signer_approval_fixture();
    let lowered = compile_smallwood_poseidon2_v8_relation(&statement, &witness).unwrap();
    assert_eq!(
        lowered.adapter.geometry().witness_rows,
        SMALLWOOD_POSEIDON2_V8_ROW_COUNT
    );
    assert_eq!(
        lowered.adapter.geometry().nonlinear_constraints,
        SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT
    );
    assert_eq!(lowered.adapter.geometry().auxiliary_words, 0);
    assert_eq!(
        projected_poseidon2_v8_smz9_inner_proof_bytes(&lowered.adapter).unwrap(),
        122_863
    );

    let unit_padded = |words: &[u64]| {
        let mut digest = [0u64; 7];
        digest[..words.len()].copy_from_slice(words);
        digest
    };
    let expected = [
        unit_padded(&witness.inputs[0].spend_key),
        witness.auth.current.policy_root,
        witness.auth.current.intent_digest,
        unit_padded(&witness.auth.policy_signer_tags[0]),
        unit_padded(&witness.auth.policy_signer_tags[1]),
        unit_padded(&witness.auth.policy_signer_tags[2]),
        unit_padded(&witness.auth.policy_signer_tags[3]),
        unit_padded(&witness.auth.policy_signer_tags[4]),
        unit_padded(&witness.auth.policy_signer_tags[5]),
    ];

    for (offset, expected_difference) in expected.into_iter().enumerate() {
        let condition = FIRST_EXTRA_ROLE_CONDITION + offset;
        for (limb, expected_limb) in expected_difference.into_iter().enumerate() {
            let index = (SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 2 + limb)
                * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
                + condition;
            assert_eq!(lowered.witness_values[index], expected_limb);
        }

        let selector_index = (SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 9)
            * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
            + condition;
        let inverse_index = (SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 10)
            * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
            + condition;
        let selected_limb = lowered.witness_values[selector_index] as usize;
        assert!(selected_limb < 7);
        assert_ne!(expected_difference[selected_limb], 0);
        assert_ne!(lowered.witness_values[inverse_index], 0);

        let mut missing_nonzero_inverse = lowered.witness_values.clone();
        missing_nonzero_inverse[inverse_index] = 0;
        assert_eq!(
            lowered
                .adapter
                .verify_packed_witness(&missing_nonzero_inverse),
            Err(
                SmallwoodPoseidon2V8RelationError::NonlinearConstraintViolation {
                    lane: condition,
                    constraint: 804,
                }
            )
        );

        let mut erased_difference = lowered.witness_values.clone();
        for limb in 0..7 {
            let index = (SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 2 + limb)
                * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
                + condition;
            erased_difference[index] = 0;
        }
        erased_difference[selector_index] = 0;
        erased_difference[inverse_index] = 0;
        assert!(lowered
            .adapter
            .verify_packed_witness(&erased_difference)
            .is_err());
    }

    let mut zero_spend_key = witness;
    zero_spend_key.inputs[0].spend_key = [0; 4];
    zero_spend_key.inputs[1].spend_key = [0; 4];
    assert!(zero_spend_key
        .validate_against_statement(&statement)
        .is_err());

    let mut zero_policy = witness;
    zero_policy.auth.current.policy_root = [0; 7];
    assert!(zero_policy.validate_against_statement(&statement).is_err());

    let mut zero_intent = witness;
    zero_intent.auth.current.intent_digest = [0; 7];
    assert!(zero_intent.validate_against_statement(&statement).is_err());

    for slot in 0..6 {
        let mut zero_tag = witness;
        zero_tag.auth.policy_signer_tags[slot] = [0; 5];
        assert!(zero_tag.validate_against_statement(&statement).is_err());
    }
}

#[test]
fn stable_role_source_hash_root_and_issuer_mutations_fail_closed() {
    let (mint_statement, mint_witness) = stable_fixture(StablecoinPoseidon2V8Direction::Mint);

    let mut wrong_role_statement = mint_statement;
    let mut wrong_role_witness = mint_witness;
    wrong_role_statement.stablecoin.direction = StablecoinPoseidon2V8Direction::Burn;
    wrong_role_statement.compatibility_stablecoin.issuance_sign = false;
    wrong_role_statement.stablecoin.issuer_authorization = [Felt::ZERO; 7];
    wrong_role_witness.stablecoin.issuer_secret = [Felt::ZERO; 7];
    wrong_role_statement.stablecoin.action_intent = wrong_role_statement
        .expected_action_intent()
        .unwrap()
        .map(Felt::from_u64);
    assert!(
        compile_smallwood_poseidon2_v8_relation(&wrong_role_statement, &wrong_role_witness)
            .is_err()
    );

    let mut reused_role = mint_witness;
    reused_role.stablecoin.config.policy_admin_commitment =
        reused_role.stablecoin.config.issuer_commitment;
    assert!(compile_smallwood_poseidon2_v8_relation(&mint_statement, &reused_role).is_err());

    let mut wrong_source = mint_witness;
    wrong_source.stablecoin.before.total_debt += 1;
    assert!(compile_smallwood_poseidon2_v8_relation(&mint_statement, &wrong_source).is_err());

    let mut wrong_sibling = mint_witness;
    wrong_sibling.stablecoin.siblings[0][0] += Felt::ONE;
    assert!(compile_smallwood_poseidon2_v8_relation(&mint_statement, &wrong_sibling).is_err());

    let lowered = compile_smallwood_poseidon2_v8_relation(&mint_statement, &mint_witness).unwrap();
    let mut wrong_hash = lowered.witness_values.clone();
    let relative = smallwood_poseidon2_v8_hash_call_initial_witness_index(106, 0);
    let index =
        SMALLWOOD_POSEIDON2_V8_HASH_ROW_START * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR + relative;
    wrong_hash[index] ^= 1;
    assert!(lowered.adapter.verify_packed_witness(&wrong_hash).is_err());

    let mut wrong_range_digit = lowered.witness_values.clone();
    // Stable magnitude is the seventh base-four ranged value: slot 180.
    let range_index = (SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START + 180 / 64)
        * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
        + 180 % 64;
    wrong_range_digit[range_index] ^= 1;
    assert!(lowered
        .adapter
        .verify_packed_witness(&wrong_range_digit)
        .is_err());

    let mut wrong_carry_boolean = lowered.witness_values.clone();
    let carry_index =
        (SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 11) * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR + 27;
    wrong_carry_boolean[carry_index] ^= 1;
    assert!(lowered
        .adapter
        .verify_packed_witness(&wrong_carry_boolean)
        .is_err());

    let mut wrong_mul_lane = lowered.witness_values.clone();
    let mul_index =
        (SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 13) * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR;
    wrong_mul_lane[mul_index] ^= 1;
    assert!(lowered
        .adapter
        .verify_packed_witness(&wrong_mul_lane)
        .is_err());

    let mut wrong_padding_helper = lowered.witness_values.clone();
    // Stable source slot 120 is the canonical zero helper used to route an
    // impossible public-only CSR equation without permitting an empty row.
    let padding_index =
        (SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 1) * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR + 56;
    wrong_padding_helper[padding_index] = 1;
    assert!(lowered
        .adapter
        .verify_packed_witness(&wrong_padding_helper)
        .is_err());

    let mut wrong_intent = mint_statement;
    wrong_intent.stablecoin.action_intent[0] += Felt::ONE;
    assert!(compile_smallwood_poseidon2_v8_relation(&wrong_intent, &mint_witness).is_err());

    let mut wrong_root = mint_statement;
    wrong_root.stablecoin.before_root[0] += Felt::ONE;
    wrong_root.stablecoin.action_intent = wrong_root
        .expected_action_intent()
        .unwrap()
        .map(Felt::from_u64);
    wrong_root.stablecoin.issuer_authorization = stablecoin_poseidon2_v8_issuer_authorization(
        &wrong_root.stablecoin.action_intent,
        &mint_witness.stablecoin.issuer_secret,
    );
    assert!(compile_smallwood_poseidon2_v8_relation(&wrong_root, &mint_witness).is_err());

    let mut wrong_after = mint_statement;
    wrong_after.stablecoin.after.total_debt += 1;
    let config_digest = stablecoin_poseidon2_v8_config_digest(mint_witness.stablecoin.config);
    wrong_after.stablecoin.after_root = stablecoin_poseidon2_v8_root(
        wrong_after.stablecoin.asset_id,
        config_digest,
        wrong_after.stablecoin.after,
        &mint_witness.stablecoin.siblings,
    )
    .unwrap();
    wrong_after.stablecoin.action_intent = wrong_after
        .expected_action_intent()
        .unwrap()
        .map(Felt::from_u64);
    wrong_after.stablecoin.issuer_authorization = stablecoin_poseidon2_v8_issuer_authorization(
        &wrong_after.stablecoin.action_intent,
        &mint_witness.stablecoin.issuer_secret,
    );
    assert!(compile_smallwood_poseidon2_v8_relation(&wrong_after, &mint_witness).is_err());

    let mut wrong_issuer = mint_statement;
    wrong_issuer.stablecoin.issuer_authorization[0] += Felt::ONE;
    assert!(compile_smallwood_poseidon2_v8_relation(&wrong_issuer, &mint_witness).is_err());

    let mut wrong_secret_witness = mint_witness;
    wrong_secret_witness.stablecoin.issuer_secret[0] += Felt::ONE;
    let mut wrong_secret_statement = mint_statement;
    wrong_secret_statement.stablecoin.issuer_authorization =
        stablecoin_poseidon2_v8_issuer_authorization(
            &wrong_secret_statement.stablecoin.action_intent,
            &wrong_secret_witness.stablecoin.issuer_secret,
        );
    assert!(compile_smallwood_poseidon2_v8_relation(
        &wrong_secret_statement,
        &wrong_secret_witness
    )
    .is_err());

    let mut wrong_reserved = mint_statement;
    wrong_reserved
        .compatibility_stablecoin
        .reserved_legacy_stablecoin_commitments[0][0] = 1;
    assert!(compile_smallwood_poseidon2_v8_relation(&wrong_reserved, &mint_witness).is_err());
}

#[test]
fn report_statement_specialized_linear_constraint_inventory() {
    let mut entries = Vec::new();
    for mask in 0..16u8 {
        let (statement, _) = single_key_fixture(mask);
        let adapter =
            SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement).unwrap();
        assert_exact_csr_program_receipt(&adapter);
        entries.push(("single", mask, adapter.geometry().linear_constraints));
    }
    for mask in [0b0111, 0b1111] {
        let (statement, _) = approval_fixture(mask);
        let adapter =
            SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement).unwrap();
        assert_exact_csr_program_receipt(&adapter);
        entries.push(("approval", mask, adapter.geometry().linear_constraints));
    }
    for mask in [0b0011, 0b0111, 0b1011, 0b1111] {
        let (statement, _) = final_fixture(mask);
        let adapter =
            SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement).unwrap();
        assert_exact_csr_program_receipt(&adapter);
        entries.push(("final", mask, adapter.geometry().linear_constraints));
    }
    for (name, direction) in [
        ("mint", StablecoinPoseidon2V8Direction::Mint),
        ("burn", StablecoinPoseidon2V8Direction::Burn),
    ] {
        let (statement, _) = stable_fixture(direction);
        let adapter =
            SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement).unwrap();
        assert_exact_csr_program_receipt(&adapter);
        entries.push((
            name,
            statement.activity_mask(),
            adapter.geometry().linear_constraints,
        ));
    }
    eprintln!("V8 statement-specialized linear counts: {entries:?}");
    assert_eq!(
        &entries[..16],
        &[
            ("single", 0, 20_473),
            ("single", 1, 20_207),
            ("single", 2, 20_207),
            ("single", 3, 19_945),
            ("single", 4, 20_450),
            ("single", 5, 20_184),
            ("single", 6, 20_184),
            ("single", 7, 19_922),
            ("single", 8, 20_450),
            ("single", 9, 20_184),
            ("single", 10, 20_184),
            ("single", 11, 19_922),
            ("single", 12, 20_427),
            ("single", 13, 20_161),
            ("single", 14, 20_161),
            ("single", 15, 19_899),
        ]
    );
    assert_eq!(
        &entries[16..],
        &[
            ("approval", 7, 19_922),
            ("approval", 15, 19_899),
            ("final", 3, 19_945),
            ("final", 7, 19_922),
            ("final", 11, 19_922),
            ("final", 15, 19_899),
            ("mint", 4, 20_348),
            ("burn", 1, 20_129),
        ]
    );
    assert_eq!(
        entries.iter().map(|(_, _, count)| *count).max(),
        Some(20_473)
    );
}
