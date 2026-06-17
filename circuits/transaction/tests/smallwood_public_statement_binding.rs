use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_versioning::{VersionBinding, SMALLWOOD_CANDIDATE_VERSION_BINDING};
use serde::Deserialize;
use transaction_circuit::constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID};
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, spend_auth_key_bytes, Felt};
use transaction_circuit::note::{MerklePath, NoteData};
use transaction_circuit::{
    build_smallwood_candidate_profile_surface_for_arithmetization,
    smallwood_public_statement_values_for_p3, InputNoteWitness, OutputNoteWitness,
    SmallwoodArithmetization, StablecoinPolicyBinding, TransactionProverP3,
    TransactionPublicInputsP3, TransactionWitness,
};

#[derive(Debug, Deserialize)]
struct SmallwoodPublicStatementBindingVectors {
    p3_public_input_base_length: usize,
    smallwood_public_statement_value_count: usize,
    active_circuit_version: u16,
    active_crypto_suite: u16,
    smallwood_public_statement_binding_cases: Vec<SmallwoodPublicStatementBindingCase>,
}

#[derive(Debug, Deserialize)]
struct SmallwoodPublicStatementBindingCase {
    name: String,
    p3_public_values: Vec<u64>,
    statement_values: Vec<u64>,
    circuit_version: u16,
    crypto_suite: u16,
    expected_statement_values: Vec<u64>,
    expected_valid: bool,
}

fn compute_merkle_root(leaf: [Felt; 6], position: u64, siblings: &[[Felt; 6]]) -> [Felt; 6] {
    let mut current = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if ((position >> level) & 1) == 0 {
            merkle_node(current, *sibling)
        } else {
            merkle_node(*sibling, current)
        };
    }
    current
}

fn build_two_leaf_merkle_tree(
    leaf0: [Felt; 6],
    leaf1: [Felt; 6],
) -> (MerklePath, MerklePath, [Felt; 6]) {
    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];
    let mut current = merkle_node(leaf0, leaf1);
    for _ in 1..CIRCUIT_MERKLE_DEPTH {
        let zero = [Felt::ZERO; 6];
        siblings0.push(zero);
        siblings1.push(zero);
        current = merkle_node(current, zero);
    }
    (
        MerklePath {
            siblings: siblings0,
        },
        MerklePath {
            siblings: siblings1,
        },
        current,
    )
}

fn sample_witness() -> TransactionWitness {
    let sk_spend = [42u8; 32];
    let pk_auth = spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 8,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [2u8; 32],
        pk_auth,
        rho: [3u8; 32],
        r: [4u8; 32],
    };
    let input_note_asset = NoteData {
        value: 5,
        asset_id: 1,
        pk_recipient: [5u8; 32],
        pk_auth,
        rho: [6u8; 32],
        r: [7u8; 32],
    };
    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);
    assert_eq!(
        compute_merkle_root(leaf0, 0, &merkle_path0.siblings),
        merkle_root
    );
    assert_eq!(
        compute_merkle_root(leaf1, 1, &merkle_path1.siblings),
        merkle_root
    );

    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_note_native,
                position: 0,
                rho_seed: [9u8; 32],
                merkle_path: merkle_path0,
            },
            InputNoteWitness {
                note: input_note_asset,
                position: 1,
                rho_seed: [8u8; 32],
                merkle_path: merkle_path1,
            },
        ],
        outputs: vec![
            OutputNoteWitness {
                note: NoteData {
                    value: 3,
                    asset_id: NATIVE_ASSET_ID,
                    pk_recipient: [11u8; 32],
                    pk_auth: [111u8; 32],
                    rho: [12u8; 32],
                    r: [13u8; 32],
                },
            },
            OutputNoteWitness {
                note: NoteData {
                    value: 5,
                    asset_id: 1,
                    pk_recipient: [21u8; 32],
                    pk_auth: [121u8; 32],
                    rho: [22u8; 32],
                    r: [23u8; 32],
                },
            },
        ],
        ciphertext_hashes: vec![[0u8; 48]; 2],
        sk_spend,
        merkle_root: felts_to_bytes48(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: SMALLWOOD_CANDIDATE_VERSION_BINDING,
    }
}

fn stablecoin_witness() -> TransactionWitness {
    let sk_spend = [8u8; 32];
    let pk_auth = spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 5,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [1u8; 32],
        pk_auth,
        rho: [2u8; 32],
        r: [3u8; 32],
    };
    let leaf0 = input_note_native.commitment();
    let leaf1 = [Felt::ZERO; 6];
    let (merkle_path0, _merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    TransactionWitness {
        inputs: vec![InputNoteWitness {
            note: input_note_native,
            position: 0,
            rho_seed: [7u8; 32],
            merkle_path: merkle_path0,
        }],
        outputs: vec![OutputNoteWitness {
            note: NoteData {
                value: 5,
                asset_id: 4242,
                pk_recipient: [4u8; 32],
                pk_auth: [104u8; 32],
                rho: [5u8; 32],
                r: [6u8; 32],
            },
        }],
        ciphertext_hashes: vec![[0u8; 48]; 1],
        sk_spend,
        merkle_root: felts_to_bytes48(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding {
            enabled: true,
            asset_id: 4242,
            policy_hash: [10u8; 48],
            oracle_commitment: [11u8; 48],
            attestation_commitment: [12u8; 48],
            issuance_delta: -5,
            policy_version: 1,
        },
        version: SMALLWOOD_CANDIDATE_VERSION_BINDING,
    }
}

fn assert_witness_public_statement_binding(
    label: &str,
    witness: &TransactionWitness,
    expected_base_len: usize,
    expected_statement_len: usize,
) {
    let prover = TransactionProverP3::new();
    let p3_public_inputs = prover.public_inputs(witness).expect("p3 public inputs");
    let p3_values = p3_public_inputs.to_vec();
    assert_eq!(
        p3_values.len(),
        expected_base_len,
        "{label}: P3 public vector length drift"
    );
    let expected_statement_values =
        smallwood_public_statement_values_for_p3(&p3_public_inputs, witness.version);
    assert_eq!(
        expected_statement_values.len(),
        expected_statement_len,
        "{label}: SmallWood public statement length drift"
    );
    assert_eq!(
        &expected_statement_values[..expected_base_len],
        p3_values
            .iter()
            .map(|felt| felt.as_canonical_u64())
            .collect::<Vec<_>>()
            .as_slice(),
        "{label}: SmallWood public statement no longer exposes the P3 prefix"
    );
    assert_eq!(
        &expected_statement_values[expected_base_len..],
        &[
            u64::from(witness.version.circuit),
            u64::from(witness.version.crypto)
        ],
        "{label}: SmallWood public statement version suffix drift"
    );

    let surface = build_smallwood_candidate_profile_surface_for_arithmetization(
        witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
    )
    .expect("smallwood candidate profile surface");
    assert_eq!(
        surface.public_statement.public_values, expected_statement_values,
        "{label}: SmallWood candidate surface is not the P3 public vector plus version binding"
    );
    assert_eq!(
        surface.public_statement.public_value_count as usize, expected_statement_len,
        "{label}: SmallWood public value count metadata drift"
    );
}

#[test]
fn lean_generated_smallwood_public_statement_binding_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_SMALLWOOD_PUBLIC_STATEMENT_BINDING_VECTORS") else {
        eprintln!(
            "HEGEMON_LEAN_SMALLWOOD_PUBLIC_STATEMENT_BINDING_VECTORS not set; skipping generated Lean vector check"
        );
        return;
    };
    let vectors: SmallwoodPublicStatementBindingVectors = serde_json::from_slice(
        &std::fs::read(path).expect("read Lean SmallWood public statement binding vectors"),
    )
    .expect("parse Lean SmallWood public statement binding vectors");
    assert_eq!(
        vectors.active_circuit_version,
        SMALLWOOD_CANDIDATE_VERSION_BINDING.circuit
    );
    assert_eq!(
        vectors.active_crypto_suite,
        SMALLWOOD_CANDIDATE_VERSION_BINDING.crypto
    );

    for case in vectors.smallwood_public_statement_binding_cases {
        let version = VersionBinding::new(case.circuit_version, case.crypto_suite);
        let actual_valid_input = case.p3_public_values.len() == vectors.p3_public_input_base_length;
        if actual_valid_input {
            let felts: Vec<Felt> = case
                .p3_public_values
                .iter()
                .copied()
                .map(Felt::from_u64)
                .collect();
            let p3 = TransactionPublicInputsP3::try_from_slice(&felts)
                .unwrap_or_else(|err| panic!("{}: decode P3 vector: {err}", case.name));
            let actual_statement_values = smallwood_public_statement_values_for_p3(&p3, version);
            assert_eq!(
                actual_statement_values, case.expected_statement_values,
                "{}: Lean expected statement values drift from production helper",
                case.name
            );
            assert_eq!(
                actual_statement_values == case.statement_values,
                case.expected_valid,
                "{}: production validity disagrees with Lean vector case",
                case.name
            );
        } else {
            assert!(
                !case.expected_valid,
                "{}: Lean marked invalid-length P3 vector valid",
                case.name
            );
        }
    }

    assert_witness_public_statement_binding(
        "normal witness",
        &sample_witness(),
        vectors.p3_public_input_base_length,
        vectors.smallwood_public_statement_value_count,
    );
    assert_witness_public_statement_binding(
        "stablecoin witness",
        &stablecoin_witness(),
        vectors.p3_public_input_base_length,
        vectors.smallwood_public_statement_value_count,
    );
}
