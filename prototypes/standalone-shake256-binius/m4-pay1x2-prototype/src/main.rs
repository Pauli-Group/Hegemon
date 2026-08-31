use std::{env, time::Instant};

use hegemon_standalone_shake256_m4_pay1x2_prototype::{
    KAT_LEFT, KAT_OUTPUT, KAT_RIGHT, MerkleParentCircuit, prove, scalar_kat, verify_exact,
};
use serde_json::json;

fn main() {
    let prove_requested = env::args().skip(1).any(|arg| arg == "--prove");
    let circuit = MerkleParentCircuit::build();
    circuit.circuit.validate().expect("valid M4 circuit");
    let witness = circuit.generate_witness(&KAT_LEFT, &KAT_RIGHT);
    witness
        .verify(&circuit.circuit.to_constraint_system())
        .expect("valid native witness");

    let circuit_output = circuit.output_from_witness(&witness);
    assert_eq!(scalar_kat(), KAT_OUTPUT);
    assert_eq!(circuit_output, KAT_OUTPUT);

    let mut report = json!({
        "profile": "HEG-S4V2",
        "role": "merk.nd1",
        "frame_bytes": 133,
        "private_child_bytes": 112,
        "public_output_bytes": 56,
        "keccak_f1600_permutations": 1,
        "scalar_kat_matches": true,
        "native_witness_verifies": true,
        "public_inout_words": witness.main.inout().len(),
        "strict_pq128": false,
        "zero_knowledge": false,
        "circuit_stats": circuit.stats(),
    });

    if prove_requested {
        const LOG_INV_RATE: usize = 3;
        let started = Instant::now();
        let proof = prove(&circuit, &witness, LOG_INV_RATE);
        let prove_millis = started.elapsed().as_millis();
        let statement = witness.main.inout().to_vec();
        let valid = verify_exact(&circuit, &statement, proof.clone(), LOG_INV_RATE);

        let mut wrong_statement = statement.clone();
        wrong_statement[0] = binius_core::word::Word(wrong_statement[0].as_u64() ^ 1);
        let public_output_mutation_rejects =
            !verify_exact(&circuit, &wrong_statement, proof.clone(), LOG_INV_RATE);

        let mut corrupted = proof.clone();
        let middle = corrupted.len() / 2;
        corrupted[middle] ^= 1;
        let proof_mutation_rejects = !verify_exact(&circuit, &statement, corrupted, LOG_INV_RATE);

        let mut trailing = proof.clone();
        trailing.push(0);
        let trailing_rejects = !verify_exact(&circuit, &statement, trailing, LOG_INV_RATE);

        report["proof"] = json!({
            "bytes": proof.len(),
            "log_inverse_rate": LOG_INV_RATE,
            "prove_millis": prove_millis,
            "valid_verifies": valid,
            "public_output_mutation_rejects": public_output_mutation_rejects,
            "proof_mutation_rejects": proof_mutation_rejects,
            "trailing_bytes_reject": trailing_rejects,
        });
    }

    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
