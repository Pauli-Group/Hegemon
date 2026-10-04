use std::{env, process::ExitCode, time::Instant};

use binius_field::{arch::OptimalPackedB128, BinaryField128bGhash as B128};
use binius_hash::StdHashSuite;
use binius_spartan_frontend::{
    circuit_builder::{ConstraintBuilder, InstanceGenerator, WitnessGenerator},
    compiler::compile,
    constraint_system::{ConstraintSystem, ConstraintWire, Witness, WitnessLayout},
};
use binius_spartan_prover::Prover;
use binius_spartan_verifier::{config::StdChallenger, Verifier};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use hegemon_standalone_shake256_binius_backend::{
    allocate_parent_wires, bytes_to_field_bits, constrain_parent, hex, parent_hash, ParentWires,
    DIGEST_BITS, DIGEST_BYTES, FRAME_BYTES, MERKLE_PARENT_ROLE, PROFILE_TAG,
};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value};

const BACKEND_SCHEMA: &str = "hegemon.standalone-shake256.backend-measurement.v1";
const PROFILE: &str = "pay1x2";
const UPSTREAM_REVISION: &str = "3f96163049f680b2909f6545690bd929f1b48c44";
const ENVELOPE_OVERHEAD_BYTES: usize = 12;
const MAX_PROXY_PARENTS: usize = 40;

#[derive(Clone, Debug)]
struct Options {
    parents: usize,
    rates: Vec<usize>,
    deterministic_test: bool,
}

#[derive(Clone, Debug)]
struct ParentAssignment {
    left: [u8; DIGEST_BYTES],
    right: [u8; DIGEST_BYTES],
    output: [u8; DIGEST_BYTES],
}

#[derive(Debug)]
struct RateOutcome {
    log_inverse_rate: usize,
    canonical_proof_bytes: usize,
    padded_constraints: usize,
    setup_ms: f64,
    witness_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    honest_roundtrip: bool,
    changed_public_output_rejected: bool,
    changed_proof_rejected: bool,
    trailing_proof_rejected: bool,
}

impl RateOutcome {
    fn verification_passed(&self) -> bool {
        self.honest_roundtrip
            && self.changed_public_output_rejected
            && self.changed_proof_rejected
            && self.trailing_proof_rejected
    }

    fn as_json(&self) -> Value {
        json!({
            "log_inverse_rate": self.log_inverse_rate,
            "canonical_proof_bytes": self.canonical_proof_bytes,
            "padded_constraints": self.padded_constraints,
            "setup_ms": self.setup_ms,
            "witness_ms": self.witness_ms,
            "prove_ms": self.prove_ms,
            "verify_ms": self.verify_ms,
            "verification": {
                "valid": self.honest_roundtrip,
                "changed_public_output_rejected": self.changed_public_output_rejected,
                "changed_proof_rejected": self.changed_proof_rejected,
                "trailing_proof_rejected": self.trailing_proof_rejected
            }
        })
    }
}

fn usage() -> &'static str {
    "usage: hegemon-standalone-shake256-binius-backend [--parents 1..40] [--rate 1..4]... [--deterministic-test]"
}

fn parse_options() -> Result<Options, String> {
    let mut parents = 1usize;
    let mut rates = Vec::new();
    let mut deterministic_test = false;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--parents" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--parents requires a value".to_owned())?;
                parents = value
                    .parse()
                    .map_err(|_| format!("invalid --parents value {value:?}"))?;
            }
            "--rate" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--rate requires a value".to_owned())?;
                rates.push(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --rate value {value:?}"))?,
                );
            }
            "--deterministic-test" => deterministic_test = true,
            "--help" | "-h" => return Err(usage().to_owned()),
            _ => return Err(format!("unknown argument {argument:?}; {}", usage())),
        }
    }
    if !(1..=MAX_PROXY_PARENTS).contains(&parents) {
        return Err(format!("--parents must be in 1..={MAX_PROXY_PARENTS}"));
    }
    if rates.is_empty() {
        rates = if parents == 1 {
            vec![1, 2, 3, 4]
        } else {
            return Err("--rate is required when --parents is greater than one".to_owned());
        };
    }
    rates.sort_unstable();
    rates.dedup();
    if rates.iter().any(|rate| !(1..=4).contains(rate)) {
        return Err("every --rate must be in 1..=4".to_owned());
    }
    Ok(Options {
        parents,
        rates,
        deterministic_test,
    })
}

fn verify_exact(verifier: &Verifier<B128, StdHashSuite>, public: &[B128], proof: &[u8]) -> bool {
    let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
    if verifier.verify(public, &mut transcript).is_err() {
        return false;
    }
    transcript.finalize().is_ok()
}

fn assignments(count: usize) -> Vec<ParentAssignment> {
    (0..count)
        .map(|parent_index| {
            let left = std::array::from_fn(|byte_index| {
                (byte_index as u8)
                    .wrapping_add((parent_index as u8).wrapping_mul(29))
                    .rotate_left((parent_index % 8) as u32)
            });
            let right = std::array::from_fn(|byte_index| {
                0xa5u8 ^ (byte_index as u8).wrapping_mul(17) ^ (parent_index as u8).wrapping_mul(43)
            });
            let output = parent_hash(&left, &right);
            ParentAssignment {
                left,
                right,
                output,
            }
        })
        .collect()
}

fn build_public(
    layout: &WitnessLayout<B128>,
    wires: &[ParentWires<ConstraintWire>],
    values: &[ParentAssignment],
) -> Vec<B128> {
    let mut generator = InstanceGenerator::new(layout);
    for (parent_wires, assignment) in wires.iter().zip(values) {
        let left = parent_wires
            .left
            .iter()
            .map(|&wire| generator.placeholder_precommit(wire))
            .collect();
        let right = parent_wires
            .right
            .iter()
            .map(|&wire| generator.placeholder_precommit(wire))
            .collect();
        let public_output = parent_wires
            .output
            .iter()
            .zip(bytes_to_field_bits(&assignment.output))
            .map(|(&wire, value)| generator.write_inout(wire, value))
            .collect();
        constrain_parent(
            &mut generator,
            &ParentWires {
                left,
                right,
                output: public_output,
            },
        );
    }
    generator.build()
}

fn build_witness(
    layout: &WitnessLayout<B128>,
    wires: &[ParentWires<ConstraintWire>],
    values: &[ParentAssignment],
) -> Witness<B128> {
    let mut generator = WitnessGenerator::new(layout);
    for (parent_wires, assignment) in wires.iter().zip(values) {
        let left = parent_wires
            .left
            .iter()
            .zip(bytes_to_field_bits(&assignment.left))
            .map(|(&wire, value)| generator.write_precommit(wire, value))
            .collect();
        let right = parent_wires
            .right
            .iter()
            .zip(bytes_to_field_bits(&assignment.right))
            .map(|(&wire, value)| generator.write_precommit(wire, value))
            .collect();
        let output = parent_wires
            .output
            .iter()
            .zip(bytes_to_field_bits(&assignment.output))
            .map(|(&wire, value)| generator.write_inout(wire, value))
            .collect();
        constrain_parent(
            &mut generator,
            &ParentWires {
                left,
                right,
                output,
            },
        );
    }
    generator
        .build()
        .expect("host SHAKE256 outputs must satisfy every bit circuit")
}

fn prove(
    prover: &Prover<OptimalPackedB128, StdHashSuite>,
    witness: &Witness<B128>,
    deterministic_test: bool,
    log_inverse_rate: usize,
) -> Vec<u8> {
    let mut transcript = ProverTranscript::new(StdChallenger::default());
    if deterministic_test {
        // Measurement/KAT mode only. A production prover must obtain fresh
        // cryptographic randomness from the operating system for every proof.
        let mut rng = StdRng::seed_from_u64(0x4845_4745_4d4f_4e01u64 ^ (log_inverse_rate as u64));
        prover
            .prove(witness, &mut rng, &mut transcript)
            .expect("honest deterministic-test proof generation must succeed");
    } else {
        let mut rng = rand::rng();
        prover
            .prove(witness, &mut rng, &mut transcript)
            .expect("honest OS-seeded proof generation must succeed");
    }
    transcript.finalize()
}

fn run_rate(
    constraint_system: &ConstraintSystem<B128>,
    base_layout: &WitnessLayout<B128>,
    wires: &[ParentWires<ConstraintWire>],
    values: &[ParentAssignment],
    log_inverse_rate: usize,
    deterministic_test: bool,
) -> RateOutcome {
    let setup_started = Instant::now();
    let verifier = Verifier::<_, StdHashSuite>::setup(constraint_system.clone(), log_inverse_rate)
        .expect("upstream verifier setup must succeed");
    let prover = Prover::<OptimalPackedB128, StdHashSuite>::setup(&verifier)
        .expect("upstream prover setup must succeed");
    let setup_ms = setup_started.elapsed().as_secs_f64() * 1_000.0;
    let padded_constraints = verifier.constraint_system().mul_constraints().len();
    let layout = base_layout
        .clone()
        .with_blinding(*verifier.constraint_system().blinding_info());

    let witness_started = Instant::now();
    let witness = build_witness(&layout, wires, values);
    verifier.constraint_system().validate(&witness);
    let public = build_public(&layout, wires, values);
    assert_eq!(public, witness.public());
    let witness_ms = witness_started.elapsed().as_secs_f64() * 1_000.0;

    let prove_started = Instant::now();
    let proof = prove(&prover, &witness, deterministic_test, log_inverse_rate);
    let prove_ms = prove_started.elapsed().as_secs_f64() * 1_000.0;

    let verify_started = Instant::now();
    let honest_roundtrip = verify_exact(&verifier, &public, &proof);
    let verify_ms = verify_started.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        honest_roundtrip,
        "honest proof must verify and consume exactly"
    );

    let mut changed_assignments = values.to_vec();
    changed_assignments[0].output[0] ^= 1;
    let changed_public = build_public(&layout, wires, &changed_assignments);
    let changed_public_output_rejected = !verify_exact(&verifier, &changed_public, &proof);
    assert!(changed_public_output_rejected);

    let mut changed_proof = proof.clone();
    let changed_index = changed_proof.len() / 2;
    changed_proof[changed_index] ^= 1;
    let changed_proof_rejected = !verify_exact(&verifier, &public, &changed_proof);
    assert!(changed_proof_rejected);

    let mut trailing_proof = proof.clone();
    trailing_proof.push(0);
    let trailing_proof_rejected = !verify_exact(&verifier, &public, &trailing_proof);
    assert!(trailing_proof_rejected);

    RateOutcome {
        log_inverse_rate,
        canonical_proof_bytes: proof.len(),
        padded_constraints,
        setup_ms,
        witness_ms,
        prove_ms,
        verify_ms,
        honest_roundtrip,
        changed_public_output_rejected,
        changed_proof_rejected,
        trailing_proof_rejected,
    }
}

fn execute(options: Options) -> Value {
    let values = assignments(options.parents);
    let compile_started = Instant::now();
    let mut builder = ConstraintBuilder::<B128>::new();
    let wires: Vec<_> = (0..options.parents)
        .map(|_| allocate_parent_wires(&mut builder))
        .collect();
    for parent_wires in &wires {
        constrain_parent(&mut builder, parent_wires);
    }
    let (constraint_system, layout) = compile(builder);
    let compile_ms = compile_started.elapsed().as_secs_f64() * 1_000.0;
    let compiled_constraints = constraint_system.mul_constraints().len();
    let compiled_private_wires = constraint_system.n_private();
    let compiled_precommit_wires = constraint_system.n_precommit();
    let compiled_public_wires = constraint_system.n_public();

    let outcomes: Vec<_> = options
        .rates
        .iter()
        .copied()
        .map(|rate| {
            run_rate(
                &constraint_system,
                &layout,
                &wires,
                &values,
                rate,
                options.deterministic_test,
            )
        })
        .collect();
    let selected = outcomes
        .iter()
        .min_by_key(|outcome| outcome.canonical_proof_bytes)
        .expect("at least one rate is required");
    assert!(outcomes.iter().all(RateOutcome::verification_passed));

    json!({
        "schema": BACKEND_SCHEMA,
        "profile": PROFILE,
        "canonical_proof_bytes": selected.canonical_proof_bytes,
        "envelope_bytes": selected.canonical_proof_bytes + ENVELOPE_OVERHEAD_BYTES,
        "prove_ms": selected.prove_ms,
        "verify_ms": selected.verify_ms,
        "peak_rss_bytes": Value::Null,
        "shake256_permutations": options.parents,
        "security_profile": {
            "status": "unsupported",
            "release_qualified": false,
            "semantic_hash": "SHAKE256-448",
            "proof_hash": "SHA-256 StdHashSuite (target: SHAKE256-512)",
            "challenge_field": "GF(2^128) BinaryField128bGhash (target: GF(2^384))",
            "fri_classical_bits": binius_spartan_verifier::SECURITY_BITS,
            "qrom_accounting_complete": false,
            "composed_pq_bits": Value::Null,
            "zero_knowledge": false,
            "upstream_protocol_claims_zero_knowledge": true,
            "limitation": "Upstream fixes 96 query-security bits, SHA-256 proof hashing, and GF(2^128); the Hegemon-specific end-to-end ZK and composed strict-PQ128 arguments are not complete."
        },
        "verification": {
            "valid": selected.honest_roundtrip,
            "mutation_rejected": selected.changed_public_output_rejected && selected.changed_proof_rejected,
            "canonical_roundtrip": selected.trailing_proof_rejected,
            "changed_public_output_rejected": selected.changed_public_output_rejected,
            "changed_proof_rejected": selected.changed_proof_rejected,
            "trailing_proof_rejected": selected.trailing_proof_rejected
        },
        "coverage": {
            "full_pay1x2_relation": false,
            "geometry_proxy": options.parents > 1,
            "description": if options.parents == 1 {
                "one exact fixed-frame Merkle-parent SHAKE256 permutation component"
            } else {
                "repeated independent exact Merkle-parent components; proof geometry proxy only"
            }
        },
        "semantic_registry": {
            "profile_tag_ascii": String::from_utf8_lossy(&PROFILE_TAG),
            "role_ascii": String::from_utf8_lossy(&MERKLE_PARENT_ROLE),
            "frame_bytes": FRAME_BYTES,
            "reference_output_hex": hex(&values[0].output)
        },
        "constraint_system": {
            "compiled_constraints": compiled_constraints,
            "compiled_precommit_wires": compiled_precommit_wires,
            "compiled_private_wires": compiled_private_wires,
            "compiled_public_wires": compiled_public_wires,
            "keccak_chi_multiplications": 38_400usize * options.parents,
            "external_booleanity_constraints": 3usize * DIGEST_BITS * options.parents,
            "compile_ms": compile_ms
        },
        "selected_log_inverse_rate": selected.log_inverse_rate,
        "rate_sweep": outcomes.iter().map(RateOutcome::as_json).collect::<Vec<_>>(),
        "rng": {
            "mode": if options.deterministic_test { "deterministic-test-only" } else { "OS-seeded thread CSPRNG" },
            "production_approved": false,
            "warning": if options.deterministic_test {
                "The deterministic seed is only for repeatable measurements and must never be used by a production prover."
            } else {
                "Fresh OS-seeded randomness is exercised, but this prototype remains non-production for independent security reasons."
            }
        },
        "upstream": {
            "repository": "https://github.com/binius-zk/binius64.git",
            "revision": UPSTREAM_REVISION,
            "rust_toolchain": "1.97.1"
        }
    })
}

fn main() -> ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let result = execute(options);
    println!(
        "{}",
        serde_json::to_string(&result).expect("measurement JSON must serialize")
    );
    ExitCode::SUCCESS
}
