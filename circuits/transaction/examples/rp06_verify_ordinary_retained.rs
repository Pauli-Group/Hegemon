//! Public-only verification of one retained ordinary RP06 carrier; no release authority.
#![forbid(unsafe_code)]
use protocol_shielded_pool::rp06_transport::{
    decode_rp06_inline_args_exact, Rp06ExpectedContext, RP06_NATIVE_LEAF_HEADER_BYTES,
    RP06_PREAMBLE_BYTES,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{error::Error, fs, path::PathBuf};
use transaction_circuit::smallwood_poseidon2_v8_rp06::{
    rp06_program_digest, rp06_program_identity_sha512, validate_rp06_transcript_bytes,
    verify_rp06_candidate_bytes, Rp06PublicStatement,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn require(valid: bool, reason: &'static str) -> Result<()> {
    if valid {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn sha512(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}
fn receipt_matches(receipt: &Value, field: &str, actual: Value) -> Result<()> {
    if receipt.get(field) == Some(&actual) {
        Ok(())
    } else {
        Err(format!("public receipt field mismatch: {field}").into())
    }
}
fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let directory = PathBuf::from(
        args.next()
            .ok_or("usage: rp06_verify_ordinary_retained DIRECTORY EXPECTED_CHAIN_HEX")?,
    );
    let expected_chain: [u8; 32] =
        hex::decode(args.next().ok_or("independent expected chain required")?)?
            .try_into()
            .map_err(|_| "expected chain must contain exactly 32 bytes")?;
    require(args.next().is_none(), "unexpected argument")?;
    let digest = rp06_program_digest();
    let expected = Rp06ExpectedContext::new(expected_chain, digest)?;
    // Read only the four public files, never the producer's wallet or witnesses.
    let carrier = fs::read(directory.join("carrier.bin"))?;
    let preamble = fs::read(directory.join("preamble.bin"))?;
    let proof = fs::read(directory.join("proof.smzb"))?;
    let receipt_bytes = fs::read(directory.join("receipt.json"))?;
    let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
    let leaf = decode_rp06_inline_args_exact(expected, &carrier)?.native_leaf();
    require(
        leaf.preamble().as_slice() == preamble,
        "carrier and retained preamble differ",
    )?;
    require(leaf.proof() == proof, "carrier and retained proof differ")?;
    validate_rp06_transcript_bytes(&preamble)?;
    let public = leaf.public_words();
    let statement = Rp06PublicStatement::try_from_public_words(&public)
        .map_err(|error| format!("invalid public statement: {error:?}"))?;
    require(
        statement.chain_id == expected_chain,
        "public chain differs from expected chain",
    )?;
    let identity = hex::encode(rp06_program_identity_sha512());
    for (field, actual) in [
        ("schema", json!("hegemon-rp06-ordinary-public-artifact-v1")),
        ("production_authorized", json!(false)),
        ("actual_smzb_generated_and_verified", json!(true)),
        ("chain_id", json!(hex::encode(expected_chain))),
        ("relation_identity_sha512", json!(identity)),
        ("carrier_bytes", json!(carrier.len())),
        ("carrier_sha512", json!(sha512(&carrier))),
        ("preamble_bytes", json!(preamble.len())),
        ("preamble_sha512", json!(sha512(&preamble))),
        ("smzb_bytes", json!(proof.len())),
        ("smzb_sha512", json!(sha512(&proof))),
        ("public_words", json!(public.to_vec())),
        (
            "reference_height",
            json!(statement.base.stablecoin.parent_height),
        ),
        ("reference_anchor", json!(statement.base.merkle_root)),
        (
            "stablecoin_root",
            json!(statement
                .base
                .stablecoin
                .before_root
                .map(|word| word.as_canonical_u64())),
        ),
    ] {
        receipt_matches(&receipt, field, actual)?;
    }
    // Reference hash, genesis and manifest are receipt metadata. This public
    // verifier has no authenticated chain ancestry or production capability.
    verify_rp06_candidate_bytes(&public, digest, &proof, expected_chain)?;

    let mut wrong_chain = expected_chain;
    wrong_chain[0] ^= 1;
    require(
        Rp06ExpectedContext::new(wrong_chain, digest)
            .and_then(|context| decode_rp06_inline_args_exact(context, &carrier).map(|_| ()))
            .is_err(),
        "wrong expected chain accepted",
    )?;
    let mut trailing = carrier.clone();
    trailing.push(0);
    require(
        decode_rp06_inline_args_exact(expected, &trailing).is_err(),
        "trailing carrier byte accepted",
    )?;
    let leaf_start = carrier
        .len()
        .checked_sub(leaf.raw().len())
        .ok_or("invalid leaf extent")?;
    let preamble_start = leaf_start + RP06_NATIVE_LEAF_HEADER_BYTES;
    let proof_start = carrier
        .len()
        .checked_sub(proof.len())
        .ok_or("invalid proof extent")?;
    let mut changed = carrier.clone();
    changed[proof_start] ^= 1;
    require(
        decode_rp06_inline_args_exact(expected, &changed).is_err(),
        "changed proof magic accepted",
    )?;
    let mut changed = carrier.clone();
    // Public network word 120 must exactly match the independently checked header.
    changed[preamble_start + 112 + 120 * 8] ^= 1;
    require(
        decode_rp06_inline_args_exact(expected, &changed).is_err(),
        "changed public chain accepted",
    )?;
    require(
        leaf.ciphertext(0).or(leaf.ciphertext(1)).is_some(),
        "ordinary carrier lacks a ciphertext",
    )?;
    let mut changed = carrier.clone();
    changed[preamble_start + RP06_PREAMBLE_BYTES + 64] ^= 1;
    require(
        decode_rp06_inline_args_exact(expected, &changed).is_err(),
        "changed ciphertext accepted",
    )?;
    let mut changed = proof.clone();
    let middle = changed.len() / 2;
    changed[middle] ^= 1;
    require(
        verify_rp06_candidate_bytes(&public, digest, &changed, expected_chain).is_err(),
        "changed proof body accepted",
    )?;
    let mut changed = proof.clone();
    changed.push(0);
    require(
        verify_rp06_candidate_bytes(&public, digest, &changed, expected_chain).is_err(),
        "trailing proof byte accepted",
    )?;
    println!(
        "{}",
        json!({
            "verified":true, "production_authorized":false, "chain_ancestry_verified":false,
            "expected_chain_id":hex::encode(expected_chain), "source_program_sha512":identity,
            "carrier_bytes":carrier.len(), "carrier_sha512":sha512(&carrier),
            "preamble_bytes":preamble.len(), "preamble_sha512":sha512(&preamble),
            "proof_bytes":proof.len(), "proof_sha512":sha512(&proof),
            "receipt_sha512":sha512(&receipt_bytes),
            "negative_checks_passed":["wrong_expected_chain", "trailing_carrier", "changed_proof_magic",
                "changed_public_chain", "changed_ciphertext", "changed_proof_body", "trailing_proof"]
        })
    );
    Ok(())
}
