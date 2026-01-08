use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;

use p3_field::PrimeCharacteristicRing;
use serde::Serialize;

use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, HashFelt};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::MerklePath;
use transaction_circuit::proof::{prove, TransactionProof};
use transaction_circuit::{
    InputNoteWitness, OutputNoteWitness, StablecoinPolicyBinding, TransactionWitness,
};

fn build_two_leaf_merkle_tree(
    leaf0: HashFelt,
    leaf1: HashFelt,
) -> (MerklePath, MerklePath, HashFelt) {
    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];
    let mut current = merkle_node(leaf0, leaf1);

    for _ in 1..transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH {
        let zero = [transaction_circuit::hashing_pq::Felt::ZERO; 6];
        siblings0.push(zero);
        siblings1.push(zero);
        current = merkle_node(current, zero);
    }

    (
        MerklePath { siblings: siblings0 },
        MerklePath { siblings: siblings1 },
        current,
    )
}

fn sample_witness() -> TransactionWitness {
    let input_native_data = transaction_circuit::note::NoteData {
        value: 8,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_recipient: [2u8; 32],
        rho: [3u8; 32],
        r: [4u8; 32],
    };
    let input_asset_data = transaction_circuit::note::NoteData {
        value: 5,
        asset_id: 1,
        pk_recipient: [5u8; 32],
        rho: [6u8; 32],
        r: [7u8; 32],
    };

    let leaf0 = input_native_data.commitment();
    let leaf1 = input_asset_data.commitment();
    let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    let input_note_native = InputNoteWitness {
        note: input_native_data,
        position: 0,
        rho_seed: [9u8; 32],
        merkle_path: merkle_path0,
    };
    let input_note_asset = InputNoteWitness {
        note: input_asset_data,
        position: 1,
        rho_seed: [8u8; 32],
        merkle_path: merkle_path1,
    };
    let output_native = OutputNoteWitness {
        note: transaction_circuit::note::NoteData {
            value: 3,
            asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
            pk_recipient: [11u8; 32],
            rho: [12u8; 32],
            r: [13u8; 32],
        },
    };
    let output_asset = OutputNoteWitness {
        note: transaction_circuit::note::NoteData {
            value: 5,
            asset_id: 1,
            pk_recipient: [21u8; 32],
            rho: [22u8; 32],
            r: [23u8; 32],
        },
    };
    TransactionWitness {
        inputs: vec![input_note_native, input_note_asset],
        outputs: vec![output_native, output_asset],
        sk_spend: [42u8; 32],
        merkle_root: felts_to_bytes48(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (proving_key, verifying_key) = generate_keys();
    let witness = sample_witness();
    let proof = prove(&witness, &proving_key)?;

    let fixtures_dir = Path::new("circuits/transaction/fixtures");
    fs::create_dir_all(fixtures_dir)?;

    let proving_key_path = fixtures_dir.join("proving_key.json");
    let verifying_key_path = fixtures_dir.join("verifying_key.json");
    let valid_path = fixtures_dir.join("valid_proof.json");
    let invalid_path = fixtures_dir.join("invalid_balance.json");

    write_fixture(&proving_key_path, &proving_key)?;
    write_fixture(&verifying_key_path, &verifying_key)?;
    write_fixture(&valid_path, &proof)?;

    let mut invalid_proof: TransactionProof = proof.clone();
    if let Some(slot) = invalid_proof
        .balance_slots
        .iter_mut()
        .find(|slot| slot.asset_id == transaction_circuit::constants::NATIVE_ASSET_ID)
    {
        slot.delta += 1;
    }
    write_fixture(&invalid_path, &invalid_proof)?;

    println!("fixtures written to {}", fixtures_dir.display());
    Ok(())
}

fn write_fixture<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.flush()?;
    Ok(())
}
