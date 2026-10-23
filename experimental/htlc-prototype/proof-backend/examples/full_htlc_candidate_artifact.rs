//! Exact-source SMZC qualification. Retain public statement/proofs only.
#[path = "full_htlc_artifact_fixture.rs"]
mod fixture;

use hegemon_isolated_htlc_smallwood::smallwood_htlc::{
    self, HtlcAction, HtlcStatement, SecretRelease,
};
use sha2::{Digest, Sha512};
use std::{path::PathBuf, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "--verify" {
        let path = PathBuf::from(&args[1]);
        let statement: HtlcStatement =
            serde_json::from_slice(&std::fs::read(path.join("statement.json"))?)?;
        let proof = std::fs::read(path.join("candidate.smzc"))?;
        let start = Instant::now();
        smallwood_htlc::verify_candidate(&statement, &proof)?;
        println!(
            "{}",
            serde_json::json!({
                "accepted": true,
                "action": statement.action,
                "private_witness_loaded": false,
                "production_authorized": false,
                "proof_bytes": proof.len(),
                "verify_seconds": start.elapsed().as_secs_f64(),
                "proof_sha512": hex::encode(Sha512::digest(&proof)),
                "relation_digest": hex::encode(smallwood_htlc::relation_digest()),
            })
        );
        return Ok(());
    }
    if !(args.len() == 3 || args.len() == 4)
        || args[0] != "--generate"
        || (args.len() == 4 && args[3] != "--invalid-witness")
    {
        return Err("usage: full_htlc_candidate_artifact --generate (lock|claim|refund) fresh-public-directory [--invalid-witness] | --verify public-directory".into());
    }
    let action = match args[1].as_str() {
        "lock" => HtlcAction::Lock,
        "claim" => HtlcAction::Claim,
        "refund" => HtlcAction::Refund,
        _ => return Err("unknown HTLC branch".into()),
    };
    let path = PathBuf::from(&args[2]);
    if path.exists() {
        return Err("generation requires a fresh public-artifact directory".into());
    }
    std::fs::create_dir(&path)?;
    let (statement, witness) = fixture::fixture(action, SecretRelease::HiddenOnHegemon);
    let (adapter, _) = smallwood_htlc::compile(&statement, &witness)?;
    let projected_max_bytes = smallwood_htlc::candidate_proof_size_hint(&statement)?;
    let start = Instant::now();
    let proof = smallwood_htlc::prove_candidate(&statement, &witness)?;
    let proving_seconds = start.elapsed().as_secs_f64();
    assert!(
        proof.len() <= projected_max_bytes,
        "literal wire hint underestimates actual proof"
    );
    let start = Instant::now();
    smallwood_htlc::verify_candidate(&statement, &proof)?;
    let verification_seconds = start.elapsed().as_secs_f64();
    std::fs::write(
        path.join("statement.json"),
        serde_json::to_vec_pretty(&statement)?,
    )?;
    std::fs::write(path.join("candidate.smzc"), &proof)?;

    // Reconstruct every public binding with one changed component. The actual
    // strict verifier must reject, even when the arithmetic graph is unchanged.
    for component in 0..9 {
        let mut changed = statement.clone();
        match component {
            0 => changed.network_id[31] ^= 1,
            1 => changed.parent_hash[31] ^= 1,
            2 => changed.parent_height += 1,
            3 => changed.merkle_root[6] ^= 1,
            4 => changed.nullifier[6] ^= 1,
            5 => changed.output_commitment[6] ^= 1,
            6 => changed.ciphertext_commitment[47] ^= 1,
            7 => changed.fee += 1,
            _ => {
                changed.action = match action {
                    HtlcAction::Lock => HtlcAction::Refund,
                    HtlcAction::Claim | HtlcAction::Refund => HtlcAction::Lock,
                }
            }
        }
        assert!(
            smallwood_htlc::verify_candidate(&changed, &proof).is_err(),
            "public mutation {component}"
        );
    }
    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(smallwood_htlc::verify_candidate(&statement, &trailing).is_err());
    let invalid_seconds = if args.len() == 4 {
        let (_, mut changed) = fixture::fixture(action, SecretRelease::HiddenOnHegemon);
        match action {
            HtlcAction::Claim => changed.secret[0] ^= 1,
            HtlcAction::Lock | HtlcAction::Refund => changed.spend_key[4] += 1,
        }
        let packed =
            smallwood_htlc::unchecked_packed_witness_for_qualification(&statement, &changed)?;
        let start = Instant::now();
        let invalid =
            smallwood_htlc::prove_candidate_unchecked_for_qualification(&statement, &packed)?;
        let seconds = start.elapsed().as_secs_f64();
        assert!(smallwood_htlc::verify_candidate(&statement, &invalid).is_err());
        std::fs::write(path.join("invalid-witness.smzc"), invalid)?;
        Some(seconds)
    } else {
        None
    };
    let receipt = serde_json::json!({
        "action": action,
        "fixture_network_only": true,
        "relation_id": smallwood_htlc::RELATION_ID,
        "relation_digest": hex::encode(smallwood_htlc::relation_digest()),
        "profile": "SMZC/K64/degree2/rho5/open6/beta2/N2^23/q58/eta5/PoW0/disjointcoset/SHA512/80candidatefixedsampler",
        "production_authorized": false,
        "proof_bytes": proof.len(),
        "projected_max_bytes": projected_max_bytes,
        "projection_slack_bytes": projected_max_bytes - proof.len(),
        "inner_cap_bytes": smallwood_htlc::MAX_CANDIDATE_PROOF_BYTES,
        "proving_seconds": proving_seconds,
        "verification_seconds": verification_seconds,
        "unchecked_invalid_seconds": invalid_seconds,
        "unchecked_invalid_rejected": invalid_seconds.is_some(),
        "all_public_component_and_trailing_negatives_rejected": true,
        "geometry": {
            "rows": adapter.geometry().rows,
            "canonical_wires": adapter.geometry().canonical_wires,
            "linear_equations": adapter.geometry().linear_equations,
            "nonlinear_batches": adapter.geometry().nonlinear_batches,
        },
        "private_inputs_retained": false,
        "proof_sha512": hex::encode(Sha512::digest(&proof)),
    });
    std::fs::write(
        path.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!("{receipt}");
    Ok(())
}
