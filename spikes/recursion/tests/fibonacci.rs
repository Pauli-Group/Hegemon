use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::create_test_fri_params;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{VerificationError, generate_challenges, verify_circuit};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

type InnerFriGeneric<MyConfig, MyHash, MyCompress, const DIGEST_ELEMS: usize> = FriProofTargets<
    Val<MyConfig>,
    <MyConfig as StarkGenericConfig>::Challenge,
    RecExtensionValMmcs<
        Val<MyConfig>,
        <MyConfig as StarkGenericConfig>::Challenge,
        DIGEST_ELEMS,
        RecValMmcs<Val<MyConfig>, DIGEST_ELEMS, MyHash, MyCompress>,
    >,
    InputProofTargets<
        Val<MyConfig>,
        <MyConfig as StarkGenericConfig>::Challenge,
        RecValMmcs<Val<MyConfig>, DIGEST_ELEMS, MyHash, MyCompress>,
    >,
    Witness<Val<MyConfig>>,
>;

mod baby_bear_params {
    use super::*;
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};

    pub type F = BabyBear;
    pub const D: usize = 4;
    pub const RATE: usize = 8;
    pub const DIGEST_ELEMS: usize = 8;
    pub type Challenge = BinomialExtensionField<F, D>;
    pub type Dft = Radix2DitParallel<F>;
    pub type Perm = Poseidon2BabyBear<16>;
    pub type MyHash = PaddingFreeSponge<Perm, 16, RATE, 8>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    pub type ValMmcs =
        MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
    pub type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
    pub type Challenger = DuplexChallenger<F, Perm, 16, RATE>;
    pub type MyPcs = p3_fri::TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
    pub type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

    pub type InnerFri = super::InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;
}

#[test]
fn recursion_fibonacci_spike() -> Result<(), VerificationError> {
    use baby_bear_params::*;

    let mut rng = SmallRng::seed_from_u64(1);
    let n = 1 << 3;
    let x = 21;

    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let trace = generate_trace_rows::<F>(0, 1, n);
    let log_final_poly_len = 0;
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let pow_bits = fri_params.query_proof_of_work_bits;
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![F::ZERO, F::ONE, F::from_u64(x)];

    let air = FibonacciAir {};
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());

    let mut circuit_builder = CircuitBuilder::new();
    let verifier_inputs =
        StarkVerifierInputsBuilder::<MyConfig, HashTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
            &mut circuit_builder,
            &proof,
            None,
            pis.len(),
        );

    verify_circuit::<
        FibonacciAir,
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        RATE,
    >(
        &config,
        &air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        &fri_verifier_params,
    )?;

    let circuit = circuit_builder.build()?;
    let mut runner = circuit.runner();
    let all_challenges =
        generate_challenges(&air, &config, &proof, &pis, Some(&[pow_bits, log_height_max]))?;
    let num_queries = proof.opening_proof.query_proofs.len();
    let public_inputs =
        verifier_inputs.pack_values(&pis, &proof, &None, &all_challenges, num_queries);

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;
    Ok(())
}
