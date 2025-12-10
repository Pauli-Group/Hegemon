//! Generate dev account for Hegemon using ML-DSA
//!
//! Run with: cargo run --example gen_dev_account --release -p wallet
//!
//! This generates the AccountId32 that should be used in genesis config.

use synthetic_crypto::ml_dsa::MlDsaSecretKey;
use synthetic_crypto::traits::{SigningKey, VerifyKey};

fn main() {
    // Dev seed (known for testing - DO NOT USE IN PRODUCTION)
    // This is "//Alice" and "//Bob" as blake2-256 hashed seeds
    let alice_seed = blake2_256(b"//Alice");
    let bob_seed = blake2_256(b"//Bob");

    println!("=== Hegemon Dev Accounts (ML-DSA) ===\n");

    print_account("Alice", &alice_seed);
    print_account("Bob", &bob_seed);

    println!("\n=== For genesis config (SS58 format, ss58Format=42) ===");
    let alice_id = get_account_id(&alice_seed);
    let bob_id = get_account_id(&bob_seed);
    let alice_ss58 = to_ss58(&alice_id, 42);
    let bob_ss58 = to_ss58(&bob_id, 42);
    println!("\"balances\": {{");
    println!("    \"balances\": [");
    println!(
        "        [\"{}\", 1_000_000_000_000_000_000_000_u128],",
        alice_ss58
    );
    println!(
        "        [\"{}\", 500_000_000_000_000_000_000_u128]",
        bob_ss58
    );
    println!("    ],");
    println!("    \"devAccounts\": null");
    println!("}}");
    println!("\"sudo\": {{");
    println!("    \"key\": \"{}\"", alice_ss58);
    println!("}}");
}

fn get_account_id(seed: &[u8; 32]) -> [u8; 32] {
    let secret_key = MlDsaSecretKey::generate_deterministic(seed);
    let public_key = secret_key.verify_key();
    let pk_bytes = public_key.to_bytes();
    blake2_256(&pk_bytes)
}

fn print_account(name: &str, seed: &[u8; 32]) {
    // Generate ML-DSA keypair
    let secret_key = MlDsaSecretKey::generate_deterministic(seed);
    let public_key = secret_key.verify_key();

    // AccountId is blake2_256 hash of public key
    let pk_bytes = public_key.to_bytes();
    let account_id = blake2_256(&pk_bytes);
    let ss58 = to_ss58(&account_id, 42);

    println!("{} Dev Account:", name);
    println!("  Seed: 0x{}", hex::encode(seed));
    println!("  Public Key Len: {} bytes", pk_bytes.len());
    println!("  AccountId (hex): 0x{}", hex::encode(&account_id));
    println!("  AccountId (SS58): {}", ss58);
    println!();
}

fn blake2_256(data: &[u8]) -> [u8; 32] {
    sp_crypto_hashing::blake2_256(data)
}

/// Encode account ID to SS58 format
fn to_ss58(account_id: &[u8; 32], ss58_format: u16) -> String {
    // SS58 encoding: prefix + account_id + checksum
    let mut payload = Vec::new();

    // Simple prefix for format < 64
    if ss58_format < 64 {
        payload.push(ss58_format as u8);
    } else {
        // Two-byte prefix for format >= 64
        payload.push(((ss58_format & 0x00FC) >> 2) as u8 | 0x40);
        payload.push(((ss58_format >> 8) as u8) | ((ss58_format & 0x0003) << 6) as u8);
    }

    payload.extend_from_slice(account_id);

    // Checksum: blake2b of "SS58PRE" + payload, take first 2 bytes
    let checksum_input: Vec<u8> = b"SS58PRE".iter().chain(payload.iter()).copied().collect();
    let hash = sp_crypto_hashing::blake2_512(&checksum_input);
    payload.extend_from_slice(&hash[..2]);

    // Base58 encode
    bs58::encode(payload).into_string()
}
