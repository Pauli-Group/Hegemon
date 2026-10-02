//! Retained-artifact measurement for the native private hashlock component.
//! No secret, witness assignment or authorization data is emitted.

use crate::hashlock_claim::{
    self as claim, ClaimAdapter, ClaimStatement, CLAIM_VERSION, PRODUCTION_RP05_INNER_CAP,
};
use htlc_prototype::hashlock::Sha256Hashlock;
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};
use std::{error::Error, fs, path::Path, time::Instant};

#[derive(Serialize)]
pub struct Measurement {
    pub schema: &'static str,
    pub claimed_relation: &'static str,
    pub backend: &'static str,
    pub profile: &'static str,
    pub source_closure_sha256: &'static str,
    pub rustc: &'static str,
    pub topology_sha512: String,
    pub digest_hex: String,
    pub context_hex: String,
    pub rows: usize,
    pub packing: usize,
    pub nonlinear_polynomials: usize,
    pub degree: usize,
    pub linear_constraints: usize,
    pub private_input_pins: usize,
    pub auxiliary_witness_words: usize,
    pub proof_bytes: usize,
    pub proof_sha512: String,
    pub production_rp05_inner_cap_bytes: usize,
    pub fits_production_rp05_inner_cap: bool,
    pub prove_seconds: f64,
    pub verify_seconds: f64,
    pub valid_proof_accepted: bool,
    pub changed_digest_rejected: bool,
    pub changed_context_rejected: bool,
    pub changed_version_rejected: bool,
    pub changed_domain_rejected: bool,
    pub changed_proof_rejected: bool,
    pub trailing_proof_rejected: bool,
    pub wrong_preimage_rejected: bool,
    pub unchecked_invalid_engine_exercised: bool,
    pub unchecked_invalid_engine_rejected: Option<bool>,
    pub unchecked_invalid_engine_seconds: Option<f64>,
    pub full_htlc_relation_proved: bool,
    pub production_authorized: bool,
    pub rp05_geometry_changed: bool,
    pub composed_pq128_claim: bool,
}

pub fn measure(
    output: &Path,
    exercise_invalid_engine: bool,
) -> Result<Measurement, Box<dyn Error>> {
    // Require a fresh evidence directory to preserve retained artifacts.
    fs::create_dir(output)?;
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|error| format!("OS secret randomness failed: {error}"))?;
    let digest: [u8; 32] = Sha256::digest(secret).into();
    let statement = ClaimStatement {
        version: CLAIM_VERSION,
        digest,
        context:
            b"isolated HTLC lane: private SHA256 component only; no authorization/consensus proof"
                .to_vec(),
    };
    let adapter = ClaimAdapter::from_statement(&statement)?;
    fs::write(
        output.join("statement.json"),
        serde_json::to_vec_pretty(&statement)?,
    )?;
    let geometry = adapter.geometry();
    eprintln!(
        "native hashlock: rows={} packing={} degree={} nonlinear={} linear={}",
        geometry.total_rows,
        geometry.packing_factor,
        geometry.maximum_degree,
        geometry.nonlinear_polynomials,
        geometry.linear_constraints
    );
    let start = Instant::now();
    let proof = claim::prove(&statement, &secret)?;
    let prove_seconds = start.elapsed().as_secs_f64();
    fs::write(output.join("claim.smz1"), &proof)?;
    fs::write(
        output.join("source-closure.sha256"),
        claim::SOURCE_INVENTORY,
    )?;
    let start = Instant::now();
    claim::verify(&statement, &proof)?;
    let verify_seconds = start.elapsed().as_secs_f64();
    let mut changed = statement.clone();
    changed.digest[0] ^= 1;
    let changed_digest_rejected = claim::verify(&changed, &proof).is_err();
    let mut changed = statement.clone();
    changed.context.push(0);
    let changed_context_rejected = claim::verify(&changed, &proof).is_err();
    let mut changed = statement.clone();
    changed.version += 1;
    let changed_version_rejected = claim::verify(&changed, &proof).is_err();
    let mut changed_binding = claim::binding_bytes(&statement)?;
    changed_binding[8] ^= 1;
    let changed_domain_rejected =
        crate::smallwood_engine::verify_statement_with_transcript_backend_profile_and_domain(
            &adapter,
            &changed_binding,
            &proof,
            claim::PROFILE,
            crate::SmallwoodTranscriptBackend::Sha512Level5,
            crate::smallwood_engine::SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .is_err();
    let mut changed_proof = proof.clone();
    changed_proof[4] ^= 1;
    let changed_proof_rejected = claim::verify(&statement, &changed_proof).is_err();
    let mut trailing = proof.clone();
    trailing.push(0);
    let trailing_proof_rejected = claim::verify(&statement, &trailing).is_err();
    let mut wrong_secret = secret;
    wrong_secret[0] ^= 1;
    let wrong_preimage_rejected = claim::prove(&statement, &wrong_secret).is_err();
    let (unchecked_invalid_engine_rejected, unchecked_invalid_engine_seconds) =
        if exercise_invalid_engine {
            // Construct a coherent valid SHA trace for the wrong secret. All gate
            // and copy checks pass; ONLY old public digest pins fail. Bypass host
            // preflight and force this witness through the actual engine.
            let circuit = Sha256Hashlock::new();
            let assignment = circuit.evaluate(&wrong_secret);
            let witness = adapter
                .program
                .pack(&assignment)
                .map_err(|e| format!("pack: {e:?}"))?;
            let start = Instant::now();
            let rejected = match claim::prove_unchecked_for_falsification(
                &adapter,
                &claim::binding_bytes(&statement)?,
                &witness,
            ) {
                Err(_) => true,
                Ok(invalid_proof) => {
                    fs::write(output.join("invalid-witness.smz1"), &invalid_proof)?;
                    claim::verify(&statement, &invalid_proof).is_err()
                }
            };
            (Some(rejected), Some(start.elapsed().as_secs_f64()))
        } else {
            (None, None)
        };
    if !(changed_digest_rejected
        && changed_context_rejected
        && changed_version_rejected
        && changed_domain_rejected
        && changed_proof_rejected
        && trailing_proof_rejected
        && wrong_preimage_rejected)
        || unchecked_invalid_engine_rejected == Some(false)
    {
        return Err("native hashlock falsification failure".into());
    }
    let measurement=Measurement {
        schema:"hegemon.experimental.native-private-sha256-claim.v1",
        claimed_relation:"exists secret:[u8;32]. SHA256(secret)=public_digest; public context bound in transcript",
        backend:"unchanged native SmallWood engine, historical strict SMZ1/Sha512Level5",
        profile:"Goldilocks/K64/d3/rho5/open5/beta2/N1048576/q23/eta5/PoW0/disjoint-coset/tape64",
        source_closure_sha256:claim::SOURCE_CLOSURE_SHA256,rustc:claim::RUSTC_VERSION,
        topology_sha512:hex::encode(claim::topology_digest()),digest_hex:hex::encode(statement.digest),context_hex:hex::encode(&statement.context),
        rows:geometry.total_rows,packing:geometry.packing_factor,nonlinear_polynomials:geometry.nonlinear_polynomials,
        degree:geometry.maximum_degree,linear_constraints:geometry.linear_constraints,
        private_input_pins:geometry.private_input_pins,auxiliary_witness_words:0,
        proof_bytes:proof.len(),proof_sha512:hex::encode(Sha512::digest(&proof)),
        production_rp05_inner_cap_bytes:PRODUCTION_RP05_INNER_CAP,fits_production_rp05_inner_cap:proof.len()<=PRODUCTION_RP05_INNER_CAP,
        prove_seconds,verify_seconds,valid_proof_accepted:true,
        changed_digest_rejected,changed_context_rejected,changed_version_rejected,changed_domain_rejected,changed_proof_rejected,
        trailing_proof_rejected,wrong_preimage_rejected,unchecked_invalid_engine_exercised:exercise_invalid_engine,
        unchecked_invalid_engine_rejected,unchecked_invalid_engine_seconds,
        full_htlc_relation_proved:false,production_authorized:false,rp05_geometry_changed:false,composed_pq128_claim:false,
    };
    fs::write(
        output.join("measurement.json"),
        serde_json::to_vec_pretty(&measurement)?,
    )?;
    Ok(measurement)
}

#[derive(Serialize)]
pub struct VerificationReceipt {
    pub schema: &'static str,
    pub source_closure_sha256: &'static str,
    pub rustc: &'static str,
    pub digest_hex: String,
    pub context_hex: String,
    pub proof_bytes: usize,
    pub proof_sha512: String,
    pub verify_seconds: f64,
    pub accepted: bool,
    pub preimage_or_assignment_loaded: bool,
    pub production_authorized: bool,
}

/// Independently reopen retained public statement+proof in a fresh process.
/// There is no API/file for supplying a secret or assignment to this verifier.
pub fn verify_artifact(directory: &Path) -> Result<VerificationReceipt, Box<dyn Error>> {
    let statement_path = directory.join("statement.json");
    let proof_path = directory.join("claim.smz1");
    if fs::metadata(&statement_path)?.len() > 32_768 || fs::metadata(&proof_path)?.len() > 8_388_608
    {
        return Err("isolated artifact input exceeds component parser resource bound".into());
    }
    let statement: ClaimStatement = serde_json::from_slice(&fs::read(statement_path)?)?;
    let proof = fs::read(proof_path)?;
    let start = Instant::now();
    claim::verify(&statement, &proof)?;
    Ok(VerificationReceipt {
        schema: "hegemon.experimental.native-private-sha256-reopen.v1",
        source_closure_sha256: claim::SOURCE_CLOSURE_SHA256,
        rustc: claim::RUSTC_VERSION,
        digest_hex: hex::encode(statement.digest),
        context_hex: hex::encode(statement.context),
        proof_bytes: proof.len(),
        proof_sha512: hex::encode(Sha512::digest(&proof)),
        verify_seconds: start.elapsed().as_secs_f64(),
        accepted: true,
        preimage_or_assignment_loaded: false,
        production_authorized: false,
    })
}
