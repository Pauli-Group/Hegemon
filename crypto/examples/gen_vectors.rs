//! Generate new test vectors with real ML-KEM and ML-DSA crypto
//! Run with: cargo run -p synthetic-crypto --example gen_vectors
//!
//! These vectors MUST use the exact same inputs as crypto/tests/crypto_vectors.rs

use hex::encode;
use synthetic_crypto::hashes::{
    blake3_256, commit_note, commit_note_with, derive_nullifier, derive_prf_key, poseidon_hash,
    sha256, sha3_256, CommitmentHash, FieldElement,
};
use synthetic_crypto::ml_dsa::MlDsaSecretKey;
use synthetic_crypto::ml_kem::MlKemKeyPair;
use synthetic_crypto::slh_dsa::SlhDsaSecretKey;
use synthetic_crypto::traits::{KemKeyPair, KemPublicKey, Signature, SigningKey, VerifyKey};

fn main() {
    println!("{{");

    // ML-DSA vectors - EXACT same seeds as crypto_vectors.rs
    let seed = b"synthetic-ml-dsa-seed";
    let message = b"synthetic message for ml-dsa";
    let sk = MlDsaSecretKey::generate_deterministic(seed);
    let pk = sk.verify_key();
    let signature = sk.sign(message);

    println!("  \"ml_dsa_pk\": \"{}\",", encode(pk.to_bytes()));
    println!("  \"ml_dsa_sk\": \"{}\",", encode(sk.to_bytes()));
    println!("  \"ml_dsa_sig\": \"{}\",", encode(signature.as_bytes()));

    // SLH-DSA vectors - EXACT same seeds as crypto_vectors.rs
    let seed = b"synthetic-slh-dsa-seed";
    let message = b"synthetic message for slh-dsa";
    let sk = SlhDsaSecretKey::generate_deterministic(seed);
    let pk = sk.verify_key();
    let signature = sk.sign(message);

    println!("  \"slh_dsa_pk\": \"{}\",", encode(pk.to_bytes()));
    println!("  \"slh_dsa_sk\": \"{}\",", encode(sk.to_bytes()));
    println!("  \"slh_dsa_sig\": \"{}\",", encode(signature.as_bytes()));

    // ML-KEM vectors - EXACT same seeds as crypto_vectors.rs
    let seed = b"synthetic-ml-kem-seed";
    let encapsulation_seed = b"synthetic-ml-kem-encapsulation-seed";
    let keypair = MlKemKeyPair::generate_deterministic(seed);
    let public_key = keypair.public_key();
    let (ciphertext, shared_secret) = public_key.encapsulate(encapsulation_seed);

    println!("  \"ml_kem_pk\": \"{}\",", encode(public_key.to_bytes()));
    println!("  \"ml_kem_ct\": \"{}\",", encode(ciphertext.as_bytes()));
    println!("  \"ml_kem_ss\": \"{}\",", encode(shared_secret.as_bytes()));

    // Hash vectors - EXACT same inputs as crypto_vectors.rs hash_commitment_and_prf_vectors test
    let message = b"note message";
    let randomness = [0x42u8; 32];
    let spend_key = b"spend secret key";
    let rho = b"rho value";
    let note_position = 42u64;

    let commitment = commit_note(message, &randomness);
    let commitment_sha3 = commit_note_with(message, &randomness, CommitmentHash::Sha3);
    let prf_key = derive_prf_key(spend_key);
    let nullifier = derive_nullifier(&prf_key, note_position, rho);
    let sha = sha256(message);
    let sha3 = sha3_256(message);
    let blake = blake3_256(message);

    let field_inputs = [
        FieldElement::from_bytes(message),
        FieldElement::from_u64(note_position),
    ];
    let poseidon = poseidon_hash(&field_inputs);

    println!("  \"commitment\": \"{}\",", encode(commitment));
    println!("  \"commitment_sha3\": \"{}\",", encode(commitment_sha3));
    println!("  \"prf\": \"{}\",", encode(prf_key));
    println!("  \"nullifier\": \"{}\",", encode(nullifier));
    println!("  \"sha\": \"{}\",", encode(sha));
    println!("  \"sha3\": \"{}\",", encode(sha3));
    println!("  \"blake\": \"{}\",", encode(blake));
    println!("  \"poseidon\": \"{}\"", encode(poseidon.to_bytes()));

    println!("}}");
}
