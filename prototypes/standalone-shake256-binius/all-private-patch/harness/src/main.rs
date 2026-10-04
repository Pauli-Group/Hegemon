mod relation;

use std::{env, process::ExitCode, time::Instant};

use binius_field::{BinaryField128bGhash as B128, Field, arch::OptimalPackedB128};
use binius_hash::StdHashSuite;
use binius_spartan_frontend::{
    circuit_builder::{
        ConstraintBuilder, InstanceGenerator, PublicWire, WitnessGenerator, WitnessWire,
    },
    compiler::compile,
    constraint_system::{ConstraintWire, WitnessLayout},
};
use binius_spartan_prover::Prover;
use binius_spartan_verifier::{Verifier, config::StdChallenger};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use rand::{SeedableRng, rngs::StdRng};
use relation::{
    DIGEST_BYTES, ParentWires, bytes_to_field_bits, constrain_parent, parent_hash,
};
use serde_json::{Value, json};

const REVISION: &str = "3f96163049f680b2909f6545690bd929f1b48c44";

#[derive(Clone)]
struct Assignment {
    left: [u8; DIGEST_BYTES],
    right: [u8; DIGEST_BYTES],
    output: [u8; DIGEST_BYTES],
}

#[derive(Clone, Copy)]
enum Topology {
    Chain,
    Independent,
}

impl Topology {
    const fn name(self) -> &'static str {
        match self {
            Self::Chain => "chain_final_public_only",
            Self::Independent => "independent_all_outputs_public",
        }
    }
}

fn assignments(count: usize, topology: Topology) -> Vec<Assignment> {
    let mut prior_output = None;
    (0..count)
        .map(|parent| {
            let fresh_left = std::array::from_fn(|i| {
                (i as u8)
                    .wrapping_add((parent as u8).wrapping_mul(29))
                    .rotate_left((parent % 8) as u32)
            });
            let left = match (topology, prior_output) {
                (Topology::Chain, Some(output)) => output,
                _ => fresh_left,
            };
            let right = std::array::from_fn(|i| {
                0xa5u8 ^ (i as u8).wrapping_mul(17) ^ (parent as u8).wrapping_mul(43)
            });
            let output = parent_hash(&left, &right);
            prior_output = Some(output);
            Assignment { left, right, output }
        })
        .collect()
}

fn allocate_private_bits(
    builder: &mut ConstraintBuilder<B128>,
) -> Vec<ConstraintWire> {
    (0..relation::DIGEST_BITS)
        .map(|_| builder.alloc_private())
        .collect()
}

fn build_relation(
    builder: &mut ConstraintBuilder<B128>,
    parents: usize,
    topology: Topology,
) -> Vec<ParentWires<ConstraintWire>> {
    let mut wires = Vec::with_capacity(parents);
    let mut prior_output = None;
    for parent_index in 0..parents {
        let left = match (topology, prior_output.take()) {
            (Topology::Chain, Some(output)) => output,
            _ => allocate_private_bits(builder),
        };
        let right = allocate_private_bits(builder);
        let output = if matches!(topology, Topology::Chain) && parent_index + 1 < parents {
            allocate_private_bits(builder)
        } else {
            (0..relation::DIGEST_BITS)
                .map(|_| builder.alloc_inout())
                .collect()
        };
        let parent = ParentWires { left, right, output };
        constrain_parent(builder, &parent);
        prior_output = Some(parent.output.clone());
        wires.push(parent);
    }
    wires
}

fn public_instance(
    layout: &WitnessLayout<B128>,
    wires: &[ParentWires<ConstraintWire>],
    values: &[Assignment],
    topology: Topology,
) -> Vec<B128> {
    let mut generator = InstanceGenerator::new(layout);
    let mut prior_output = None;
    for (parent_index, (parent, value)) in wires.iter().zip(values).enumerate() {
        let left = match (topology, prior_output.take()) {
            (Topology::Chain, Some(output)) => output,
            _ => parent
                .left
                .iter()
                .map(|&wire| generator.placeholder_private(wire))
                .collect(),
        };
        let right = parent
            .right
            .iter()
            .map(|&wire| generator.placeholder_private(wire))
            .collect();
        let output: Vec<PublicWire<B128>> = if matches!(topology, Topology::Chain)
            && parent_index + 1 < wires.len()
        {
            parent
                .output
                .iter()
                .map(|&wire| generator.placeholder_private(wire))
                .collect()
        } else {
            parent
                .output
                .iter()
                .zip(bytes_to_field_bits(&value.output))
                .map(|(&wire, bit)| generator.write_inout(wire, bit))
                .collect()
        };
        prior_output = Some(output.clone());
        constrain_parent(&mut generator, &ParentWires { left, right, output });
    }
    generator.build()
}

fn witness(
    layout: &WitnessLayout<B128>,
    wires: &[ParentWires<ConstraintWire>],
    values: &[Assignment],
    topology: Topology,
) -> binius_spartan_frontend::constraint_system::Witness<B128> {
    let mut generator = WitnessGenerator::new(layout);
    let mut prior_output: Option<Vec<WitnessWire<B128>>> = None;
    for (parent_index, (parent, value)) in wires.iter().zip(values).enumerate() {
        let left = match (topology, prior_output.take()) {
            (Topology::Chain, Some(output)) => output,
            _ => parent
                .left
                .iter()
                .zip(bytes_to_field_bits(&value.left))
                .map(|(&wire, bit)| generator.write_private(wire, bit))
                .collect(),
        };
        let right = parent
            .right
            .iter()
            .zip(bytes_to_field_bits(&value.right))
            .map(|(&wire, bit)| generator.write_private(wire, bit))
            .collect();
        let output: Vec<WitnessWire<B128>> = if matches!(topology, Topology::Chain)
            && parent_index + 1 < wires.len()
        {
            parent
                .output
                .iter()
                .zip(bytes_to_field_bits(&value.output))
                .map(|(&wire, bit)| generator.write_private(wire, bit))
                .collect()
        } else {
            parent
                .output
                .iter()
                .zip(bytes_to_field_bits(&value.output))
                .map(|(&wire, bit)| generator.write_inout(wire, bit))
                .collect()
        };
        prior_output = Some(output.clone());
        constrain_parent(&mut generator, &ParentWires { left, right, output });
    }
    generator
        .build()
        .expect("host SHAKE256 results must satisfy the all-private relation")
}

fn verify_exact(
    verifier: &Verifier<B128, StdHashSuite>,
    public: &[B128],
    proof: &[u8],
) -> bool {
    let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
    verifier.verify(public, &mut transcript).is_ok() && transcript.finalize().is_ok()
}

fn run(parents: usize, rate: usize, topology: Topology) -> Value {
    let values = assignments(parents, topology);
    let compile_started = Instant::now();
    let mut builder = ConstraintBuilder::<B128>::new();
    let wires = build_relation(&mut builder, parents, topology);
    let (cs, layout) = compile(builder);
    assert_eq!(cs.n_precommit(), 0);
    let compile_ms = compile_started.elapsed().as_secs_f64() * 1_000.0;

    let setup_started = Instant::now();
    let verifier = Verifier::<_, StdHashSuite>::setup(cs, rate).expect("verifier setup");
    let prover = Prover::<OptimalPackedB128, StdHashSuite>::setup(&verifier).expect("prover setup");
    let setup_ms = setup_started.elapsed().as_secs_f64() * 1_000.0;
    let padded = verifier.constraint_system();
    let layout = layout.with_blinding(*padded.blinding_info());

    let witness_started = Instant::now();
    let witness = witness(&layout, &wires, &values, topology);
    padded.validate(&witness);
    let public = public_instance(&layout, &wires, &values, topology);
    assert_eq!(public, witness.public());
    assert_eq!(public.len(), padded.n_public() as usize);
    let witness_ms = witness_started.elapsed().as_secs_f64() * 1_000.0;

    let mut transcript = ProverTranscript::new(StdChallenger::default());
    let mut rng = StdRng::seed_from_u64(0x4845_4745_4d4f_4e01 ^ parents as u64 ^ rate as u64);
    let prove_started = Instant::now();
    prover.prove(&witness, &mut rng, &mut transcript).expect("prove");
    let proof = transcript.finalize();
    let prove_ms = prove_started.elapsed().as_secs_f64() * 1_000.0;

    let verify_started = Instant::now();
    let honest = verify_exact(&verifier, &public, &proof);
    let verify_ms = verify_started.elapsed().as_secs_f64() * 1_000.0;
    assert!(honest);

    let mut changed_public = public.clone();
    changed_public[padded.constants().len()] += B128::ONE;
    let changed_public_rejected = !verify_exact(&verifier, &changed_public, &proof);
    assert!(changed_public_rejected);

    let mut changed_proof = proof.clone();
    let middle = changed_proof.len() / 2;
    changed_proof[middle] ^= 1;
    let changed_proof_rejected = !verify_exact(&verifier, &public, &changed_proof);
    assert!(changed_proof_rejected);

    let mut trailing = proof.clone();
    trailing.push(0);
    let trailing_rejected = !verify_exact(&verifier, &public, &trailing);
    assert!(trailing_rejected);

    json!({
        "revision": REVISION,
        "parents": parents,
        "topology": topology.name(),
        "log_inverse_rate": rate,
        "proof_bytes": proof.len(),
        "compiled_constraints": padded.mul_constraints().len(),
        "compiled_private_inputs_and_wires": padded.n_private(),
        "compiled_precommit_inputs": padded.n_precommit(),
        "compiled_inout_fields": padded.n_inout(),
        "compiled_public_fields": padded.n_public(),
        "oracle_log_private": padded.log_private(),
        "oracle_log_precommit_dummy_only": padded.log_precommit(),
        "mask_log": padded.mask_dims().0 + padded.mask_dims().1,
        "compile_ms": compile_ms,
        "setup_ms": setup_ms,
        "witness_ms": witness_ms,
        "prove_ms": prove_ms,
        "verify_ms": verify_ms,
        "honest_roundtrip": honest,
        "changed_public_rejected": changed_public_rejected,
        "changed_proof_rejected": changed_proof_rejected,
        "trailing_proof_rejected": trailing_rejected,
        "security_release_qualified": false,
        "security_limitation": "Upstream still fixes 96 query bits, SHA-256, and GF(2^128)."
    })
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let parents = args.next().and_then(|arg| arg.parse().ok()).unwrap_or(1);
    let rate = args.next().and_then(|arg| arg.parse().ok()).unwrap_or(3);
    let topology = match args.next().as_deref().unwrap_or("chain") {
        "chain" => Topology::Chain,
        "independent" => Topology::Independent,
        _ => {
            eprintln!("topology must be chain or independent");
            return ExitCode::from(2);
        }
    };
    if !matches!(parents, 1 | 40) || !(1..=6).contains(&rate) || args.next().is_some() {
        eprintln!(
            "usage: hegemon-binius-all-private-spike [1|40] [rate 1..6] [chain|independent]"
        );
        return ExitCode::from(2);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&run(parents, rate, topology)).unwrap()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    #[test]
    fn one_parent_real_proof_rejects_mutations() {
        let result = super::run(1, 3, super::Topology::Chain);
        assert_eq!(result["proof_bytes"], 231_200);
        assert_eq!(result["honest_roundtrip"], true);
        assert_eq!(result["changed_public_rejected"], true);
        assert_eq!(result["changed_proof_rejected"], true);
        assert_eq!(result["trailing_proof_rejected"], true);
    }

    #[test]
    fn forty_parent_chain_real_proof_rejects_mutations() {
        let result = super::run(40, 3, super::Topology::Chain);
        assert_eq!(result["proof_bytes"], 350_800);
        assert_eq!(result["honest_roundtrip"], true);
        assert_eq!(result["changed_public_rejected"], true);
        assert_eq!(result["changed_proof_rejected"], true);
        assert_eq!(result["trailing_proof_rejected"], true);
    }
}
