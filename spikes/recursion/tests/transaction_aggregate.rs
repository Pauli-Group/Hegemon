use std::collections::BTreeMap;
use std::time::Instant;

use p3_batch_stark::{BatchCommitments, CommonData};
use p3_circuit::{CircuitBuilder, CircuitError};
use p3_circuit_prover::air::PublicAir;
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::config;
use p3_circuit_prover::{BatchStarkProver, TablePacking};
use p3_commit::PolynomialSpace;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_poseidon2::ExternalLayerConstants;
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::types::{CommitmentTargets, OpenedValuesTargets};
use p3_recursion::{Recursive, generate_challenges, verify_circuit};
use p3_util::reverse_bits_len;
use p3_uni_stark::{Proof, StarkGenericConfig, get_log_num_quotient_chunks};
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
use transaction_circuit::p3_verifier::verify_transaction_proof_p3;
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
        ciphertext_hashes: vec![[0u8; 48]; 1],
        sk_spend: [8u8; 32],
        merkle_root,
        fee: 0,
        value_balance: -20,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

type MatOpenings = Vec<(TwoAdicMultiplicativeCoset<Val>, Vec<(Challenge, Vec<Challenge>)>)>;

fn compute_reduced_openings_host(
    log_global_max_height: usize,
    index: usize,
    alpha: Challenge,
    log_blowup: usize,
    mats_per_batch: &[MatOpenings],
    batch_opened_values: &[Vec<Vec<Val>>],
) -> Vec<(usize, Challenge)> {
    let mut reduced_openings = BTreeMap::<usize, (Challenge, Challenge)>::new();

    for (mats, batch_openings) in mats_per_batch.iter().zip(batch_opened_values.iter()) {
        for ((mat_domain, mat_points_and_values), mat_opening) in
            mats.iter().zip(batch_openings.iter())
        {
            let log_height = mat_domain.log_size() + log_blowup;
            let bits_reduced = log_global_max_height - log_height;
            let reduced_index = index >> bits_reduced;
            let rev_reduced_index = reverse_bits_len(reduced_index, log_height);

            let x = Val::GENERATOR
                * Val::two_adic_generator(log_height).exp_u64(rev_reduced_index as u64);
            let x_chal = Challenge::from(x);

            let (alpha_pow, ro) = reduced_openings
                .entry(log_height)
                .or_insert((Challenge::ONE, Challenge::ZERO));

            for (z, ps_at_z) in mat_points_and_values {
                let quotient = (*z - x_chal).inverse();
                for (&p_at_x, &p_at_z) in mat_opening.iter().zip(ps_at_z.iter()) {
                    let p_at_x_chal = Challenge::from(p_at_x);
                    *ro += *alpha_pow * (p_at_z - p_at_x_chal) * quotient;
                    *alpha_pow *= alpha;
                }
            }
        }
    }

    reduced_openings
        .into_iter()
        .rev()
        .map(|(log_height, (_ap, ro))| (log_height, ro))
        .collect()
}

fn fold_row_chain_host(
    index: usize,
    log_max_height: usize,
    betas: &[Challenge],
    sibling_values: &[Challenge],
    roll_ins: &[Option<Challenge>],
    initial_folded_eval: Challenge,
) -> Challenge {
    let mut folded = initial_folded_eval;
    for (i, beta) in betas.iter().enumerate() {
        let log_folded_height = log_max_height - i - 1;
        let parent_index = index >> (i + 1);
        let rev_parent_index = reverse_bits_len(parent_index, log_folded_height);
        let x0 = Val::two_adic_generator(log_folded_height + 1)
            .exp_u64(rev_parent_index as u64);
        let x0_chal = Challenge::from(x0);
        let x1_chal = -x0_chal;

        let bit = (index >> i) & 1;
        let sibling_is_right = bit == 0;
        let e0 = if sibling_is_right {
            folded
        } else {
            sibling_values[i]
        };
        let e1 = if sibling_is_right {
            sibling_values[i]
        } else {
            folded
        };

        let inv = (x1_chal - x0_chal).inverse();
        folded = e0 + (*beta - x0_chal) * (e1 - e0) * inv;

        if let Some(ro) = roll_ins[i] {
            folded += beta.square() * ro;
        }
    }

    folded
}

#[test]
#[ignore = "slow aggregation spike; run with --ignored for metrics"]
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
    verify_transaction_proof_p3(&proof, &pub_inputs).expect("inner proof verifies");

    let inner_bytes = postcard::to_allocvec(&proof).expect("serialize inner proof");
    println!(
        "inner_tx_proof_bytes={}, degree_bits={}, commit_phase_len={}",
        inner_bytes.len(),
        proof.degree_bits,
        proof.opening_proof.commit_phase_commits.len()
    );

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
    let commit_pow_bits = fri_params.commit_proof_of_work_bits;
    let query_pow_bits = fri_params.query_proof_of_work_bits;
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    println!(
        "fri_params_log_blowup={}, log_final_poly_len={}, log_height_max={}",
        fri_params.log_blowup, fri_params.log_final_poly_len, log_height_max
    );

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
    let public_rows = circuit.public_rows.clone();
    let all_challenges = generate_challenges(
        &TransactionAirP3,
        &config.config,
        &proof,
        &pub_inputs_vec,
        Some(&[commit_pow_bits, query_pow_bits, log_height_max]),
    )
    .expect("generate challenges");
    let num_phases = proof.opening_proof.commit_phase_commits.len();
    let num_queries = proof.opening_proof.query_proofs.len();
    let has_commit_pow = commit_pow_bits > 0;
    let has_query_pow = query_pow_bits > 0;
    let fri_challenges_len = 1
        + (num_phases * (1 + usize::from(has_commit_pow)))
        + usize::from(has_query_pow)
        + num_queries;
    let fri_start = all_challenges
        .len()
        .checked_sub(fri_challenges_len)
        .expect("fri challenge length underflow");
    let zeta = all_challenges[fri_start - 1];
    let fri_alpha = all_challenges[fri_start];
    let mut cursor = fri_start + 1;
    let mut betas = Vec::with_capacity(num_phases);
    for _ in 0..num_phases {
        if has_commit_pow {
            let _commit_pow = all_challenges[cursor];
            cursor += 1;
        }
        betas.push(all_challenges[cursor]);
        cursor += 1;
    }
    if has_query_pow {
        let _query_pow = all_challenges[cursor];
        cursor += 1;
    }
    let query_indices = &all_challenges[cursor..cursor + num_queries];
    if cursor + num_queries != all_challenges.len() {
        println!(
            "fri_challenge_parse_mismatch len={}, expected_end={}",
            all_challenges.len(),
            cursor + num_queries
        );
    }

    let log_quotient_degree =
        get_log_num_quotient_chunks::<Val, _>(&TransactionAirP3, 0, pub_inputs_vec.len(), 0);
    let quotient_degree = 1 << (log_quotient_degree + config.config.is_zk());
    let trace_domain =
        TwoAdicMultiplicativeCoset::new(Val::ONE, proof.degree_bits).expect("trace domain");
    let quotient_domain =
        trace_domain.create_disjoint_domain(1 << (proof.degree_bits + log_quotient_degree));
    let quotient_chunks_domains = quotient_domain.split_domains(quotient_degree);

    let degree_bits_minus_zk = proof.degree_bits.saturating_sub(config.config.is_zk());
    let init_trace_domain = TwoAdicMultiplicativeCoset::new(Val::ONE, degree_bits_minus_zk)
        .expect("init trace domain");
    let zeta_next = zeta * Challenge::from(init_trace_domain.subgroup_generator());

    let mut mats_per_batch: Vec<MatOpenings> = Vec::new();
    mats_per_batch.push(vec![(
        trace_domain,
        vec![
            (zeta, proof.opened_values.trace_local.clone()),
            (zeta_next, proof.opened_values.trace_next.clone()),
        ],
    )]);
    let quotient_mats = quotient_chunks_domains
        .iter()
        .zip(proof.opened_values.quotient_chunks.iter())
        .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
        .collect();
    mats_per_batch.push(quotient_mats);

    let log_global_max_height =
        num_phases + fri_params.log_blowup + fri_params.log_final_poly_len;
    for (q, query_proof) in proof.opening_proof.query_proofs.iter().enumerate() {
        let index_coeffs: &[Val] = query_indices[q].as_basis_coefficients_slice();
        let index = index_coeffs[0].as_canonical_u64() as usize;
        let batch_opened_values: Vec<Vec<Vec<Val>>> = query_proof
            .input_proof
            .iter()
            .map(|batch| batch.opened_values.clone())
            .collect();
        let reduced_by_height = compute_reduced_openings_host(
            log_global_max_height,
            index,
            fri_alpha,
            log_blowup,
            &mats_per_batch,
            &batch_opened_values,
        );
        let initial_folded_eval = reduced_by_height[0].1;
        let mut roll_ins = vec![None; num_phases];
        for &(h, ro) in reduced_by_height.iter().skip(1) {
            let phase = log_global_max_height - 1 - h;
            if phase < num_phases {
                roll_ins[phase] = Some(ro);
            }
        }
        let sibling_values: Vec<Challenge> = query_proof
            .commit_phase_openings
            .iter()
            .map(|opening| opening.sibling_value)
            .collect();
        let folded_eval = fold_row_chain_host(
            index,
            log_global_max_height,
            &betas,
            &sibling_values,
            &roll_ins,
            initial_folded_eval,
        );

        let domain_index = index >> num_phases;
        let x = Val::two_adic_generator(log_global_max_height)
            .exp_u64(reverse_bits_len(domain_index, log_global_max_height) as u64);
        let mut final_eval = Challenge::ZERO;
        for &coeff in proof.opening_proof.final_poly.iter().rev() {
            final_eval = final_eval * Challenge::from(x) + coeff;
        }

        if folded_eval != final_eval {
            println!(
                "fri_fold_mismatch query={}, index={}, reduced_heights={:?}, folded_eval={:?}, final_eval={:?}, final_poly_len={}",
                q,
                index,
                reduced_by_height.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
                folded_eval,
                final_eval,
                proof.opening_proof.final_poly.len()
            );
            break;
        }
    }
    let public_inputs =
        verifier_inputs.pack_values(&pub_inputs_vec, &proof, &None, &all_challenges, num_queries);
    let commitments_no_lookups = BatchCommitments {
        main: proof.commitments.trace.clone(),
        permutation: None,
        quotient_chunks: proof.commitments.quotient_chunks.clone(),
        random: proof.commitments.random.clone(),
    };
    let commitments_len =
        CommitmentTargets::<Challenge, HashTargets<Val, DIGEST_ELEMS>>::get_values(
            &commitments_no_lookups,
        )
        .len();
    let opened_values_len = OpenedValuesTargets::<Config>::get_values(&proof.opened_values).len();
    let opening_proof_len = InnerFri::get_values(&proof.opening_proof).len();
    let proof_values_len = commitments_len + opened_values_len + opening_proof_len;
    let fri_commit_phase_len = proof.opening_proof.commit_phase_commits.len() * DIGEST_ELEMS;
    let fri_commit_pow_len = proof.opening_proof.commit_pow_witnesses.len();
    let fri_final_poly_len = proof.opening_proof.final_poly.len();
    let fri_pow_witness_len = 1;
    let fri_query_len = opening_proof_len
        .saturating_sub(
            fri_commit_phase_len + fri_commit_pow_len + fri_final_poly_len + fri_pow_witness_len,
        );
    println!(
        "recursion_public_inputs_len={}, air_public_len={}, proof_values_len={}, challenges_len={}, commitments_len={}, opened_values_len={}, opening_proof_len={}",
        public_inputs.len(),
        pub_inputs_vec.len(),
        proof_values_len,
        all_challenges.len(),
        commitments_len,
        opened_values_len,
        opening_proof_len
    );

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

    let mut runner = circuit.clone().runner();
    runner
        .set_public_inputs(&public_inputs)
        .expect("set public inputs");
    let traces = match runner.run() {
        Ok(traces) => traces,
        Err(err) => {
            if let CircuitError::WitnessConflict {
                witness_id,
                existing,
                new,
            } = &err
            {
                if let Some(pos) = public_rows.iter().position(|id| id == witness_id) {
                    let air_len = pub_inputs_vec.len();
                    let challenge_len = all_challenges.len();
                    let proof_len = proof_values_len;
                    let mut detail = String::new();
                    if pos >= air_len && pos < air_len + proof_len {
                        let pos_in_proof = pos - air_len;
                        if pos_in_proof < commitments_len {
                            detail = format!("commitments[{}]", pos_in_proof);
                        } else if pos_in_proof < commitments_len + opened_values_len {
                            let idx = pos_in_proof - commitments_len;
                            detail = format!("opened_values[{}]", idx);
                        } else {
                            let pos_in_fri = pos_in_proof - commitments_len - opened_values_len;
                            if pos_in_fri < fri_commit_phase_len {
                                detail = format!("fri_commit_phase_commits[{}]", pos_in_fri);
                            } else if pos_in_fri < fri_commit_phase_len + fri_commit_pow_len {
                                detail = format!(
                                    "fri_commit_pow_witnesses[{}]",
                                    pos_in_fri - fri_commit_phase_len
                                );
                            } else if pos_in_fri < fri_commit_phase_len + fri_commit_pow_len + fri_query_len
                            {
                                detail = format!(
                                    "fri_query_proofs[{}]",
                                    pos_in_fri - fri_commit_phase_len - fri_commit_pow_len
                                );
                            } else if pos_in_fri
                                < fri_commit_phase_len
                                    + fri_commit_pow_len
                                    + fri_query_len
                                    + fri_final_poly_len
                            {
                                detail = format!(
                                    "fri_final_poly[{}]",
                                    pos_in_fri
                                        - fri_commit_phase_len
                                        - fri_commit_pow_len
                                        - fri_query_len
                                );
                            } else {
                                detail = "fri_pow_witness".to_string();
                            }
                        }
                    }
                    let segment = if pos < air_len {
                        "air_public_values"
                    } else if pos < air_len + proof_len {
                        "proof_values"
                    } else if pos < air_len + proof_len + challenge_len {
                        "challenges"
                    } else {
                        "unknown_segment"
                    };
                    let value = public_inputs
                        .get(pos)
                        .map(|v| format!("{v:?}"))
                        .unwrap_or_else(|| "<missing>".to_string());
                    println!(
                        "witness_conflict_public_input_index={}, segment={}, detail={}, value={}, existing={}, new={}",
                        pos, segment, detail, value, existing, new
                    );
                } else {
                    println!(
                        "witness_conflict_non_public witness_id={:?}, existing={}, new={}",
                        witness_id, existing, new
                    );
                }
            }
            panic!("run recursion circuit: {err:?}");
        }
    };

    let outer_prover = BatchStarkProver::new(outer_config).with_table_packing(table_packing);
    let prove_start = Instant::now();
    let outer_proof = outer_prover
        .prove_all_tables(&traces, &common, witness_multiplicities)
        .expect("prove outer circuit");
    let prove_elapsed = prove_start.elapsed();
    let outer_bytes = postcard::to_allocvec(&outer_proof.proof).expect("serialize outer proof");

    let public_values = PublicAir::<Val, 2>::trace_to_public_values(&traces.public_trace);
    let verify_start = Instant::now();
    outer_prover
        .verify_all_tables_with_public_values(&outer_proof, &common, Some(public_values))
        .expect("verify outer circuit");
    let verify_elapsed = verify_start.elapsed();

    println!(
        "outer_aggregate_proof_bytes={}, outer_prove_ms={}, outer_verify_ms={}",
        outer_bytes.len(),
        prove_elapsed.as_millis(),
        verify_elapsed.as_millis()
    );

    let mut bad_proof: Proof<Config> =
        postcard::from_bytes(&inner_bytes).expect("deserialize inner proof");
    if bad_proof.opening_proof.final_poly.is_empty() {
        panic!("expected non-empty FRI final polynomial");
    }
    bad_proof.opening_proof.final_poly[0] += Challenge::ONE;

    let bad_challenges = generate_challenges(
        &TransactionAirP3,
        &config.config,
        &bad_proof,
        &pub_inputs_vec,
        Some(&[commit_pow_bits, query_pow_bits, log_height_max]),
    )
    .expect("generate challenges for corrupted proof");
    let bad_public_inputs =
        verifier_inputs.pack_values(&pub_inputs_vec, &bad_proof, &None, &bad_challenges, num_queries);
    let mut bad_runner = circuit.runner();
    bad_runner
        .set_public_inputs(&bad_public_inputs)
        .expect("set corrupted public inputs");
    match bad_runner.run() {
        Ok(_) => panic!("corrupted proof unexpectedly satisfied recursion circuit"),
        Err(err) => println!("corrupted_proof_rejected: {err:?}"),
    }
}

#[test]
#[ignore = "slow aggregation spike; set HEGEMON_AGG_COUNTS=2,4,8,16 and run with --ignored"]
fn aggregate_transaction_proof_batch() {
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
    verify_transaction_proof_p3(&proof, &pub_inputs).expect("inner proof verifies");

    let inner_bytes = postcard::to_allocvec(&proof).expect("serialize inner proof");
    println!(
        "inner_tx_proof_bytes={}, degree_bits={}, commit_phase_len={}",
        inner_bytes.len(),
        proof.degree_bits,
        proof.opening_proof.commit_phase_commits.len()
    );

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
    let commit_pow_bits = fri_params.commit_proof_of_work_bits;
    let query_pow_bits = fri_params.query_proof_of_work_bits;
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;

    let all_challenges = generate_challenges(
        &TransactionAirP3,
        &config.config,
        &proof,
        &pub_inputs_vec,
        Some(&[commit_pow_bits, query_pow_bits, log_height_max]),
    )
    .expect("generate challenges");
    let num_queries = proof.opening_proof.query_proofs.len();

    let counts: Vec<usize> = std::env::var("HEGEMON_AGG_COUNTS")
        .ok()
        .and_then(|raw| {
            let parsed: Vec<usize> = raw
                .split(',')
                .filter_map(|item| item.trim().parse::<usize>().ok())
                .collect();
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        })
        .unwrap_or_else(|| vec![2, 4, 8, 16]);

    let allow_large = std::env::var("HEGEMON_AGG_ALLOW_LARGE")
        .ok()
        .map(|raw| matches!(raw.trim(), "1" | "true" | "yes"))
        .unwrap_or(false);

    for count in counts {
        if count > 64 && !allow_large {
            println!(
                "Skipping aggregate_count={} (set HEGEMON_AGG_ALLOW_LARGE=1 to run; may exhaust RAM on laptops)",
                count
            );
            continue;
        }
        let mut circuit_builder = CircuitBuilder::new();
        let mut verifier_inputs = Vec::with_capacity(count);
        for _ in 0..count {
            let inputs =
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
                &inputs.proof_targets,
                &inputs.air_public_targets,
                &None,
                &fri_verifier_params,
            )
            .expect("build recursion verifier circuit");
            verifier_inputs.push(inputs);
        }

        let circuit = circuit_builder.build().expect("build circuit");
        let packed_values = verifier_inputs[0].pack_values(
            &pub_inputs_vec,
            &proof,
            &None,
            &all_challenges,
            num_queries,
        );
        let mut public_inputs = Vec::with_capacity(packed_values.len() * count);
        for _ in 0..count {
            public_inputs.extend(packed_values.iter().cloned());
        }

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

        let public_values = PublicAir::<Val, 2>::trace_to_public_values(&traces.public_trace);
        let verify_start = Instant::now();
        outer_prover
            .verify_all_tables_with_public_values(&outer_proof, &common, Some(public_values))
            .expect("verify outer circuit");
        let verify_elapsed = verify_start.elapsed();

        println!(
            "aggregate_count={}, outer_aggregate_proof_bytes={}, outer_prove_ms={}, outer_verify_ms={}",
            count,
            outer_bytes.len(),
            prove_elapsed.as_millis(),
            verify_elapsed.as_millis()
        );
    }
}
