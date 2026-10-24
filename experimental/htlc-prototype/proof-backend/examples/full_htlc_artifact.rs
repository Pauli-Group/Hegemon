//! Retain only public statement/proof/receipts, never witness or secrets.
#[path = "full_htlc_artifact_fixture.rs"]
mod fixture;
use hegemon_isolated_htlc_smallwood::smallwood_htlc::{
    self, HtlcAction, HtlcStatement, SecretRelease,
};
use sha2::{Digest, Sha512};
use std::{path::PathBuf, time::Instant};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--project"] {
        let mut cases = Vec::new();
        for (action, release) in [
            (HtlcAction::Lock, SecretRelease::HiddenOnHegemon),
            (HtlcAction::Claim, SecretRelease::HiddenOnHegemon),
            (HtlcAction::Claim, SecretRelease::PublicOnHegemon),
            (HtlcAction::Refund, SecretRelease::HiddenOnHegemon),
        ] {
            let (statement, witness) = fixture::fixture(action, release);
            let (adapter, _) = smallwood_htlc::compile(&statement, &witness)?;
            let binding = statement.candidate_binding_bytes()?;
            assert_eq!(binding.len(), smallwood_htlc::CANDIDATE_PREAMBLE_BYTES);
            assert_eq!(binding[..8], smallwood_htlc::CANDIDATE_PREAMBLE_MAGIC);
            for changed in [
                {
                    let mut changed = statement.clone();
                    changed.network_id[0] ^= 1;
                    changed
                },
                {
                    let mut changed = statement.clone();
                    changed.parent_hash[0] ^= 1;
                    changed
                },
                {
                    let mut changed = statement.clone();
                    changed.ciphertext_commitment[47] ^= 1;
                    changed
                },
            ] {
                assert_ne!(binding, changed.candidate_binding_bytes()?);
            }
            cases.push(serde_json::json!({
                "action": action,
                "public_secret": statement.revealed_secret.is_some(),
                "projected_bytes": smallwood_htlc::candidate_proof_size_hint(&statement)?,
                "rows": adapter.geometry().rows,
                "preamble_bytes": binding.len(),
                "binding_sha512": hex::encode(Sha512::digest(binding)),
            }));
        }
        println!(
            "{}",
            serde_json::json!({
                "proof_magic": "SMZC",
                "candidate_profile": "rho5/open6/beta2/N2^23/q58/eta5/PoW0/degree2/K64/SHA512",
                "max_inner_proof_bytes": smallwood_htlc::MAX_CANDIDATE_PROOF_BYTES,
                "relation_digest": hex::encode(smallwood_htlc::relation_digest()),
                "retained_proof": false,
                "production_authorized": false,
                "cases": cases,
            })
        );
        return Ok(());
    }
    if args.len() != 2 {
        return Err(
            "usage: full_htlc_artifact --project | (--generate|--verify) public-artifact-directory"
                .into(),
        );
    }
    let path = PathBuf::from(&args[1]);
    if args[0] == "--verify" {
        let statement: HtlcStatement =
            serde_json::from_slice(&std::fs::read(path.join("statement.json"))?)?;
        let proof = std::fs::read(path.join("claim.smz1"))?;
        let start = Instant::now();
        smallwood_htlc::verify_development(&statement, &proof)?;
        println!(
            "{}",
            serde_json::json!({"accepted":true,"private_witness_loaded":false,"production_authorized":false,"proof_bytes":proof.len(),"verify_seconds":start.elapsed().as_secs_f64(),"proof_sha512":hex::encode(Sha512::digest(&proof)),"relation_id":smallwood_htlc::RELATION_ID})
        );
        return Ok(());
    }
    if args[0] != "--generate" || path.exists() {
        return Err("generation requires a fresh directory".into());
    }
    std::fs::create_dir(&path)?;
    let (statement, witness) = fixture::fixture(HtlcAction::Claim, SecretRelease::HiddenOnHegemon);
    let (adapter, packed) = smallwood_htlc::compile(&statement, &witness)?;
    let start = Instant::now();
    let proof = smallwood_htlc::prove_development_unchecked_for_qualification(&statement, &packed)?;
    let proving = start.elapsed().as_secs_f64();
    let start = Instant::now();
    smallwood_htlc::verify_development(&statement, &proof)?;
    let verification = start.elapsed().as_secs_f64();
    std::fs::write(
        path.join("statement.json"),
        serde_json::to_vec_pretty(&statement)?,
    )?;
    std::fs::write(path.join("claim.smz1"), &proof)?;
    // Evaluate a complete changed-secret arithmetic/SHA trace without the
    // host equation audit; the original committed policy stays unchanged.
    let (_, mut changed_witness) =
        fixture::fixture(HtlcAction::Claim, SecretRelease::HiddenOnHegemon);
    changed_witness.secret[0] ^= 1;
    let invalid_packed =
        smallwood_htlc::unchecked_packed_witness_for_qualification(&statement, &changed_witness)?;
    let start = Instant::now();
    let invalid =
        smallwood_htlc::prove_development_unchecked_for_qualification(&statement, &invalid_packed)?;
    let invalid_seconds = start.elapsed().as_secs_f64();
    assert!(smallwood_htlc::verify_development(&statement, &invalid).is_err());
    std::fs::write(path.join("invalid-witness.smz1"), &invalid)?;
    let mut altered = statement.clone();
    altered.network_id[0] ^= 1;
    assert!(smallwood_htlc::verify_development(&altered, &proof).is_err());
    let mut altered = statement.clone();
    altered.parent_hash[0] ^= 1;
    assert!(smallwood_htlc::verify_development(&altered, &proof).is_err());
    let mut altered = statement.clone();
    altered.output_commitment[6] ^= 1;
    assert!(smallwood_htlc::verify_development(&altered, &proof).is_err());
    let mut appended = proof.clone();
    appended.push(0);
    assert!(smallwood_htlc::verify_development(&statement, &appended).is_err());
    let receipt = serde_json::json!({"relation_id":smallwood_htlc::RELATION_ID,"relation_digest":hex::encode(smallwood_htlc::relation_digest()),"profile":"development-only SMZ1/K64/degree2/rho5/open5/beta2/N2^20/q23/eta5/PoW0/disjointcoset/SHA512","production_authorized":false,"proof_bytes":proof.len(),"rp05_cap_unchanged":164113,"proving_seconds":proving,"verification_seconds":verification,"unchecked_invalid_seconds":invalid_seconds,"unchecked_invalid_rejected":true,"network_parent_output_trailing_negatives_rejected":true,"geometry":{"rows":adapter.geometry().rows,"canonical_wires":adapter.geometry().canonical_wires,"linear_equations":adapter.geometry().linear_equations,"nonlinear_batches":adapter.geometry().nonlinear_batches},"private_inputs_retained":false,"proof_sha512":hex::encode(Sha512::digest(&proof))});
    std::fs::write(
        path.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!("{}", receipt);
    Ok(())
}
