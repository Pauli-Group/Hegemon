use hex::encode;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use synthetic_crypto::hashes::{
    blake3_256, commit_note, commit_note_with, derive_nullifier, derive_prf_key, poseidon_hash,
    sha256, sha3_256, CommitmentHash, FieldElement,
};
use synthetic_crypto::ml_dsa::{MlDsaSecretKey, ML_DSA_PUBLIC_KEY_LEN, ML_DSA_SIGNATURE_LEN};
use synthetic_crypto::ml_kem::{
    MlKemKeyPair, ML_KEM_CIPHERTEXT_LEN, ML_KEM_PUBLIC_KEY_LEN, ML_KEM_SHARED_SECRET_LEN,
};
use synthetic_crypto::slh_dsa::{SlhDsaSecretKey, SLH_DSA_PUBLIC_KEY_LEN, SLH_DSA_SIGNATURE_LEN};
use synthetic_crypto::traits::{KemKeyPair, KemPublicKey, Signature, SigningKey, VerifyKey};

#[derive(Deserialize)]
struct CryptoVectors {
    ml_dsa_pk: String,
    ml_dsa_sk: String,
    ml_dsa_sig: String,
    slh_dsa_pk: String,
    slh_dsa_sk: String,
    slh_dsa_sig: String,
    ml_kem_pk: String,
    ml_kem_ct: String,
    ml_kem_ss: String,
    commitment: String,
    commitment_sha3: String,
    prf: String,
    nullifier: String,
    sha: String,
    blake: String,
    poseidon: String,
}

fn load_vectors() -> CryptoVectors {
    let path = Path::new("tests/vectors.json");
    let contents = fs::read_to_string(path).expect("vectors.json readable");
    serde_json::from_str(&contents).expect("valid json vectors")
}

#[test]
fn ml_dsa_deterministic_vectors() {
    let vectors = load_vectors();
    let seed = b"synthetic-ml-dsa-seed";
    let message = b"synthetic message for ml-dsa";
    let sk = MlDsaSecretKey::generate_deterministic(seed);
    let pk = sk.verify_key();
    let signature = sk.sign(message);
    pk.verify(message, &signature)
        .expect("signature must verify");

    assert_eq!(pk.to_bytes().len(), ML_DSA_PUBLIC_KEY_LEN);
    assert_eq!(signature.as_bytes().len(), ML_DSA_SIGNATURE_LEN);

    let pk_hex = encode(pk.to_bytes());
    let sig_hex = encode(signature.as_bytes());
    let sk_hex = encode(sk.to_bytes());

    assert_eq!(pk_hex, vectors.ml_dsa_pk);
    assert_eq!(sig_hex, vectors.ml_dsa_sig);
    assert_eq!(sk_hex, vectors.ml_dsa_sk);
}

#[test]
fn slh_dsa_deterministic_vectors() {
    let vectors = load_vectors();
    let seed = b"synthetic-slh-dsa-seed";
    let message = b"synthetic message for slh-dsa";
    let sk = SlhDsaSecretKey::generate_deterministic(seed);
    let pk = sk.verify_key();
    let signature = sk.sign(message);
    pk.verify(message, &signature)
        .expect("signature must verify");

    assert_eq!(pk.to_bytes().len(), SLH_DSA_PUBLIC_KEY_LEN);
    assert_eq!(signature.as_bytes().len(), SLH_DSA_SIGNATURE_LEN);

    let pk_hex = encode(pk.to_bytes());
    let sig_hex = encode(signature.as_bytes());
    let sk_hex = encode(sk.to_bytes());

    assert_eq!(pk_hex, vectors.slh_dsa_pk);
    assert_eq!(sig_hex, vectors.slh_dsa_sig);
    assert_eq!(sk_hex, vectors.slh_dsa_sk);
}

#[test]
fn ml_kem_deterministic_vectors() {
    let vectors = load_vectors();
    let seed = b"synthetic-ml-kem-seed";
    let encapsulation_seed = b"synthetic-ml-kem-encapsulation-seed";
    let keypair = MlKemKeyPair::generate_deterministic(seed);
    let public_key = keypair.public_key();

    assert_eq!(public_key.to_bytes().len(), ML_KEM_PUBLIC_KEY_LEN);

    let (ciphertext, shared_secret) = public_key.encapsulate(encapsulation_seed);
    assert_eq!(ciphertext.as_bytes().len(), ML_KEM_CIPHERTEXT_LEN);
    assert_eq!(shared_secret.as_bytes().len(), ML_KEM_SHARED_SECRET_LEN);

    let recovered = keypair
        .decapsulate(&ciphertext)
        .expect("decapsulation should succeed");
    assert_eq!(recovered.as_bytes(), shared_secret.as_bytes());

    let keypair_roundtrip = MlKemKeyPair::from_bytes(&keypair.to_bytes()).expect("roundtrip bytes");
    let (ciphertext_again, shared_secret_again) = keypair_roundtrip.encapsulate(encapsulation_seed);
    assert_eq!(ciphertext_again.as_bytes(), ciphertext.as_bytes());
    assert_eq!(shared_secret_again.as_bytes(), shared_secret.as_bytes());

    let pk_hex = encode(public_key.to_bytes());
    let ct_hex = encode(ciphertext.as_bytes());
    let ss_hex = encode(shared_secret.as_bytes());
    assert_eq!(pk_hex, vectors.ml_kem_pk);
    assert_eq!(ct_hex, vectors.ml_kem_ct);
    assert_eq!(ss_hex, vectors.ml_kem_ss);
}

#[test]
fn hash_commitment_and_prf_vectors() {
    let vectors = load_vectors();
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

    let commitment_hex = encode(commitment);
    let prf_hex = encode(prf_key);
    let nullifier_hex = encode(nullifier);
    let sha_hex = encode(sha);
    let sha3_hex = encode(sha3);
    let blake_hex = encode(blake);
    let poseidon_hex = encode(poseidon.to_bytes());

    println!("commitment_blake3: {commitment_hex}");
    println!("commitment_sha3: {}", encode(commitment_sha3));
    println!("prf: {prf_hex}");
    println!("nullifier: {nullifier_hex}");
    println!("sha256: {sha_hex}");
    println!("sha3: {sha3_hex}");
    println!("blake3: {blake_hex}");
    println!("poseidon: {poseidon_hex}");

    assert_eq!(commitment_hex, vectors.commitment);
    assert_eq!(encode(commitment_sha3), vectors.commitment_sha3);
    assert_eq!(prf_hex, vectors.prf);
    assert_eq!(nullifier_hex, vectors.nullifier);
    assert_eq!(sha_hex, vectors.sha);
    assert_eq!(sha3_hex, vectors.sha3);
    assert_eq!(blake_hex, vectors.blake);
    assert_eq!(poseidon_hex, vectors.poseidon);
}
