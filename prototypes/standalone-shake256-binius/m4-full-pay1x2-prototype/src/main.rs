use std::{env, fs, path::PathBuf, process::ExitCode};

use hegemon_m4_full_pay1x2_prototype::{
    PAY1X2_SHAKE256_PERMUTATIONS, PRIVATE_WITNESS_BYTES, PUBLIC_STATEMENT_BYTES, UPSTREAM_REVISION,
    build_pay1x2_m4, canonical_fixture, circuit_stats, generate_fixture_witness,
    prove_and_check_gates,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let mut prove = false;
    let mut rate = 3usize;
    let mut proof_out: Option<PathBuf> = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--prove" => prove = true,
            "--proof-out" => {
                proof_out = Some(args.next().map(PathBuf::from).unwrap_or_else(|| usage()));
            }
            "--rate" => {
                rate = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .filter(|value| (1..=6).contains(value))
                    .unwrap_or_else(|| usage());
            }
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            _ => usage(),
        }
    }
    if proof_out.is_some() && !prove {
        usage();
    }

    let built = build_pay1x2_m4();
    let stats = circuit_stats(&built);
    let (_, witness_value, statement) = canonical_fixture();
    let witness = generate_fixture_witness(&built, &witness_value, &statement)
        .expect("the scalar KAT must satisfy the full M4 circuit");
    witness
        .verify(&built.circuit.to_constraint_system())
        .expect("native constraint-system verification must accept the KAT");

    let proof = prove.then(|| prove_and_check_gates(&built, &witness, &statement, rate));
    let proof_sha256 = proof.as_ref().map(|report| {
        assert!(
            report.honest_roundtrip
                && report.all_public_mutations_rejected
                && report.changed_proof_rejected
                && report.trailing_proof_rejected,
            "a proof artifact cannot be emitted before every exact gate passes"
        );
        hex_lower(&Sha256::digest(&report.proof))
    });
    if let (Some(path), Some(report)) = (proof_out.as_deref(), proof.as_ref()) {
        fs::write(path, &report.proof)
            .unwrap_or_else(|error| panic!("failed to write proof {}: {error}", path.display()));
    }
    let output = json!({
        "schema": "hegemon.m4-full-pay1x2-prototype.v1",
        "upstream_revision": UPSTREAM_REVISION,
        "single_main": built.circuit.chips.is_empty(),
        "private_witness_bytes": PRIVATE_WITNESS_BYTES,
        "canonical_public_statement_bytes": PUBLIC_STATEMENT_BYTES,
        "public_transport_words": stats.n_inout,
        "shake256_permutations": PAY1X2_SHAKE256_PERMUTATIONS,
        "circuit": {
            "gates": stats.n_gates,
            "eval_instructions": stats.n_eval_insn,
            "zero_constraints": stats.n_zero_constraints,
            "and_constraints": stats.n_and_constraints,
            "imul_constraints": stats.n_imul_constraints,
            "bmul_constraints": stats.n_bmul_constraints,
            "zero_allocated": stats.zero_allocated,
            "and_allocated": stats.and_allocated,
            "imul_allocated": stats.imul_allocated,
            "bmul_allocated": stats.bmul_allocated,
            "committed_allocated": stats.committed_allocated,
            "private_inputs": stats.n_witness,
            "public_inputs": stats.n_inout,
            "internal_values": stats.n_internal,
        },
        "kat": {
            "scalar_relation_valid": true,
            "circuit_witness_valid": true,
        },
        "proof": proof.as_ref().map(|report| json!({
            "log_inverse_rate": report.log_inverse_rate,
            "bytes": report.proof.len(),
            "sha256": proof_sha256,
            "proof_output": proof_out.as_ref().map(|path| path.display().to_string()),
            "honest_roundtrip": report.honest_roundtrip,
            "all_public_mutations_rejected": report.all_public_mutations_rejected,
            "changed_proof_rejected": report.changed_proof_rejected,
            "trailing_proof_rejected": report.trailing_proof_rejected,
        })),
        "security": {
            "transparent_not_zero_knowledge": true,
            "upstream_96_bit_profile": true,
            "strict_pq128": false,
            "production_authorized": false,
        }
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    ExitCode::SUCCESS
}

fn usage() -> ! {
    print_usage();
    std::process::exit(2)
}

fn print_usage() {
    eprintln!("usage: hegemon-m4-full-pay1x2-prototype [--prove] [--rate 1..6] [--proof-out PATH]");
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
