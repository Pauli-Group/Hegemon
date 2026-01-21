use std::time::Instant;

use p3_batch_stark::CommonData;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::config;
use p3_circuit_prover::{BatchStarkProver, TablePacking};
use p3_poseidon2::ExternalLayerConstants;
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{generate_challenges, verify_circuit};
use p3_uni_stark::get_log_num_quotient_chunks;
use transaction_circuit::{
    StablecoinPolicyBinding, TransactionAirP3, TransactionProverP3, TransactionWitness,
    hashing_pq::{felts_to_bytes48, merkle_node, note_commitment, HashFelt},
    note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    p3_config::{
        Challenge, Compress, Config, DIGEST_ELEMS, FRI_LOG_BLOWUP, FRI_NUM_QUERIES, Hash, Perm,
        POSEIDON2_RATE, POSEIDON2_WIDTH, Val, ValMmcs, ChallengeMmcs, config_with_fri,
        default_fri_config,
    },
};
use transaction_core::poseidon2_constants::{EXTERNAL_ROUND_CONSTANTS, INTERNAL_ROUND_CONSTANTS};

type InnerFri = FriProofTargets<
    Val,
    Challenge,
    RecExtensionValMmcs<
        Val,
        Challenge,
        DIGEST_ELEMS,
        RecValMmcs<Val, DIGEST_ELEMS, Hash, Compress>,
    >,
    InputProofTargets<Val, Challenge, RecValMmcs<Val, DIGEST_ELEMS, Hash, Compress>>,
    Witness<Val>,
>;

fn compute_merkle_root_from_path(leaf: HashFelt, position: u64, path: &MerklePath) -> HashFelt {
    let mut current = leaf;
    let mut pos = position;
    for sibling in &path.siblings {
        current = if pos & 1 == 0 {
            merkle_node(current, *sibling)
        } else {
            merkle_node(*sibling, current)
        };
        pos >>= 1;
    }
    current
}

fn sample_witness() -> TransactionWitness {
    let input_note = NoteData {
        value: 100,
        asset_id: 0,
        pk_recipient: [1u8; 32],
        rho: [2u8; 32],
        r: [3u8; 32],
    };
    let output_note = NoteData {
        value: 80,
        asset_id: 0,
        pk_recipient: [4u8; 32],
        rho: [5u8; 32],
        r: [6u8; 32],
    };
    let merkle_path = MerklePath::default();
    let leaf = note_commitment(
        input_note.value,
        input_note.asset_id,
        &input_note.pk_recipient,
        &input_note.rho,
        &input_note.r,
    );
    let merkle_root = felts_to_bytes48(&compute_merkle_root_from_path(leaf, 0, &merkle_path));

    TransactionWitness {
        inputs: vec![InputNoteWitness {
            note: input_note,
            position: 0,
            rho_seed: [7u8; 32],
            merkle_path,
        }],
        outputs: vec![OutputNoteWitness { note: output_note }],
        sk_spend: [8u8; 32],
        merkle_root,
        fee: 0,
        value_balance: -20,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

#[test]
#[ignore = "known failure: recursion circuit witness conflict for Goldilocks proofs"]
fn aggregate_single_transaction_proof() {
    let witness = sample_witness();
    witness.validate().expect("witness valid");

    let prover = TransactionProverP3::new();
    let trace = prover.build_trace(&witness).expect("trace build");
    let pub_inputs = prover.public_inputs(&witness).expect("public inputs");
    let pub_inputs_vec = pub_inputs.to_vec();
    let log_chunks =
        get_log_num_quotient_chunks::<Val, _>(&TransactionAirP3, 0, pub_inputs_vec.len(), 0);
    let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
    let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
    let proof = prover.prove(trace, &pub_inputs);

    let inner_bytes = postcard::to_allocvec(&proof).expect("serialize inner proof");
    println!("inner_tx_proof_bytes={}", inner_bytes.len());

    let perm = {
        let external_constants =
            ExternalLayerConstants::<Val, POSEIDON2_WIDTH>::new_from_saved_array(
                EXTERNAL_ROUND_CONSTANTS,
                Val::new_array,
            );
        let internal_constants = Val::new_array(INTERNAL_ROUND_CONSTANTS).to_vec();
        Perm::new(external_constants, internal_constants)
    };
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs);
    let fri_params = default_fri_config(challenge_mmcs, log_blowup, FRI_NUM_QUERIES);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let pow_bits = fri_params.query_proof_of_work_bits;
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;

    let mut circuit_builder = CircuitBuilder::new();
    let verifier_inputs =
        StarkVerifierInputsBuilder::<Config, HashTargets<Val, DIGEST_ELEMS>, InnerFri>::allocate(
            &mut circuit_builder,
            &proof,
            None,
            pub_inputs_vec.len(),
        );

    verify_circuit::<
        TransactionAirP3,
        Config,
        HashTargets<Val, DIGEST_ELEMS>,
        InputProofTargets<Val, Challenge, RecValMmcs<Val, DIGEST_ELEMS, Hash, Compress>>,
        InnerFri,
        POSEIDON2_RATE,
    >(
        &config.config,
        &TransactionAirP3,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        &fri_verifier_params,
    )
    .expect("build recursion verifier circuit");

    let circuit = circuit_builder.build().expect("build circuit");
    let all_challenges = generate_challenges(
        &TransactionAirP3,
        &config.config,
        &proof,
        &pub_inputs_vec,
        Some(&[pow_bits, log_height_max]),
    )
    .expect("generate challenges");
    let num_queries = proof.opening_proof.query_proofs.len();
    let public_inputs =
        verifier_inputs.pack_values(&pub_inputs_vec, &proof, &None, &all_challenges, num_queries);

    let table_packing = TablePacking::new(4, 4, 1);
    let (airs_degrees, witness_multiplicities) =
        get_airs_and_degrees_with_prep::<config::GoldilocksConfig, _, 2>(
            &circuit,
            table_packing,
            None,
        )
        .expect("build circuit airs");
    let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let outer_config = config::goldilocks().build();
    let common = CommonData::from_airs_and_degrees(&outer_config, &mut airs, &degrees);

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&public_inputs)
        .expect("set public inputs");
    let traces = runner.run().expect("run recursion circuit");

    let outer_prover = BatchStarkProver::new(outer_config).with_table_packing(table_packing);
    let prove_start = Instant::now();
    let outer_proof = outer_prover
        .prove_all_tables(&traces, &common, witness_multiplicities)
        .expect("prove outer circuit");
    let prove_elapsed = prove_start.elapsed();
    let outer_bytes = postcard::to_allocvec(&outer_proof.proof).expect("serialize outer proof");

    let verify_start = Instant::now();
    outer_prover
        .verify_all_tables(&outer_proof, &common)
        .expect("verify outer circuit");
    let verify_elapsed = verify_start.elapsed();

    println!(
        "outer_aggregate_proof_bytes={}, outer_prove_ms={}, outer_verify_ms={}",
        outer_bytes.len(),
        prove_elapsed.as_millis(),
        verify_elapsed.as_millis()
    );
}
