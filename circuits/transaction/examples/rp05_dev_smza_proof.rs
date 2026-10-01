//! One offline RP05 SMZA proof measurement. Requires `rp05-dev-artifacts`.
//! The ordinary verifier and production capability remain fail-closed.

use sha2::{Digest, Sha512};
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::Instant,
};
use transaction_circuit::{
    smallwood_poseidon2_v8_frontend::{
        compile_and_prove_smallwood_poseidon2_v8_smza_development_artifact_v1,
        verify_smallwood_poseidon2_v8_smza_development_artifact_v1,
        SMALLWOOD_POSEIDON2_V8_SMZA_INLINE_ACTION_BYTES,
    },
    smallwood_poseidon2_v8_program::{
        SMALLWOOD_POSEIDON2_V8_PROGRAM_IDENTITY_REGENERATION_REQUIRED,
        SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512,
    },
    smallwood_poseidon2_v8_types::{
        SmallwoodPoseidon2V8PublicStatement, SmallwoodPoseidon2V8Witness,
    },
};

fn create_new_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    if protocol_versioning::smallwood_poseidon2_production_authorized() {
        return Err("development artifact runner refuses an authorized production profile".into());
    }
    let output_root = std::env::args_os()
        .nth(1)
        .ok_or("usage: rp05_dev_smza_proof NEW_OUTPUT_DIRECTORY")?;
    if std::env::args_os().nth(2).is_some() {
        return Err("expected exactly one output directory".into());
    }
    let output_root = Path::new(&output_root);
    if output_root.exists() {
        return Err("RP05 development proof output directory already exists".into());
    }
    let statement = SmallwoodPoseidon2V8PublicStatement::default();
    let witness = SmallwoodPoseidon2V8Witness::default();
    let proof_started = Instant::now();
    eprintln!("rp05-dev-artifact: proving started");
    let candidate = compile_and_prove_smallwood_poseidon2_v8_smza_development_artifact_v1(
        &statement, &witness, 17,
    )?;
    eprintln!(
        "rp05-dev-artifact: prove and inline self-verification completed in {:.2}s",
        proof_started.elapsed().as_secs_f64()
    );
    let proof = candidate.proof_bytes();
    if proof.len() > candidate.projected_max_proof_bytes()
        || candidate.measured_action_bytes() > SMALLWOOD_POSEIDON2_V8_SMZA_INLINE_ACTION_BYTES
    {
        return Err("RP05 proof exceeded the unchanged inner or action cap".into());
    }
    eprintln!("rp05-dev-artifact: pinned offline verification started");
    verify_smallwood_poseidon2_v8_smza_development_artifact_v1(candidate.verifier_input(), proof)?;
    eprintln!("rp05-dev-artifact: pinned offline verification accepted");
    let preamble = candidate
        .verifier_input()
        .smza_candidate_transcript_preamble_v1()?;
    let manifest = serde_json::json!({
        "schema": "hegemon.rp05.offline-smza-development-proof.v1",
        "fixture": "all-inactive-single-key",
        "network_id": candidate.verifier_input().network_id,
        "relation_digest_hex": hex::encode(candidate.verifier_input().relation_digest),
        "program_sha512_hex": hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512),
        "proof_bytes": proof.len(),
        "proof_sha512_hex": hex::encode(Sha512::digest(proof)),
        "preamble_bytes": preamble.as_bytes().len(),
        "preamble_sha512_hex": hex::encode(Sha512::digest(preamble.as_bytes())),
        "measured_action_bytes": candidate.measured_action_bytes(),
        "inner_cap_bytes": candidate.projected_max_proof_bytes(),
        "action_cap_bytes": SMALLWOOD_POSEIDON2_V8_SMZA_INLINE_ACTION_BYTES,
        "identity_regeneration_required": SMALLWOOD_POSEIDON2_V8_PROGRAM_IDENTITY_REGENERATION_REQUIRED,
        "production_authorized": false,
        "offline_feature_verifier_accepts": true
    });
    fs::create_dir(output_root)?;
    eprintln!("rp05-dev-artifact: writing and checking retained bytes");
    create_new_file(&output_root.join("proof.bin"), proof)?;
    create_new_file(&output_root.join("preamble.bin"), preamble.as_bytes())?;
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    create_new_file(&output_root.join("manifest.json"), &manifest_bytes)?;
    let readback = fs::read(output_root.join("proof.bin"))?;
    if readback != proof {
        return Err("RP05 retained proof differs from the verified bytes".into());
    }
    verify_smallwood_poseidon2_v8_smza_development_artifact_v1(
        candidate.verifier_input(),
        &readback,
    )?;
    println!("{}", serde_json::to_string(&manifest)?);
    Ok(())
}
