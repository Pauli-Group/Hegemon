#![forbid(unsafe_code)]

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process,
    time::Instant,
};

use binius_prover::{zk_config::ZKProver, OptimalPackedB128};
use binius_transcript::{fiat_shamir::HasherChallenger, ProverTranscript, VerifierTranscript};
use binius_verifier::zk_config::ZKVerifier;
use hegemon_binius_strict_hash_profile::{StrictShake256HashSuite, StrictTranscriptDigest};
use hegemon_m4_full_production_prototype::strict_baseline_material::{
    canonical, ciphertext_hash_variant, StrictBaselineMaterial,
};
use rand::{rngs::StdRng, RngExt, SeedableRng};
use serde_json::json;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const UPSTREAM_REVISION: &str = "3f96163049f680b2909f6545690bd929f1b48c44";
const COEFFICIENT_PATCH_SHA256: &str =
    "684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54";
const GROUPED_PATCH_SHA256: &str =
    "37dfdee589e476c09fe5c955bd46942cd5aa293a3177d7a43d07f14aeb8ef9df";
const LOG_INVERSE_RATE: usize = 3;
const REPETITIONS: usize = 3;
const PER_COPY_CLASSICAL_BITS: f64 = 96.0;
const ENVELOPE_MAGIC: [u8; 4] = *b"HGSB";
const ENVELOPE_VERSION: u16 = 1;
const ENVELOPE_HEADER_BYTES: usize = 48;
const MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;
const NONCE_BYTES: usize = 32;
const RECORD_HEADER_BYTES: usize = NONCE_BYTES + 4;
const TRANSCRIPT_DOMAIN: &[u8] = b"hegemon.full-m4.strict-repeated-zk.v1\0";

type StrictChallenger = HasherChallenger<StrictTranscriptDigest>;

const SOURCE_BUNDLE: &[(&[u8], &[u8])] = &[
    (
        b"strict-baseline/Cargo.toml",
        include_bytes!("../Cargo.toml"),
    ),
    (
        b"strict-baseline/Cargo.lock",
        include_bytes!("../Cargo.lock"),
    ),
    (b"strict-baseline/src/main.rs", include_bytes!("main.rs")),
    (
        b"full-m4/Cargo.toml",
        include_bytes!("../../m4-full-production-prototype/Cargo.toml"),
    ),
    (
        b"full-m4/src/lib.rs",
        include_bytes!("../../m4-full-production-prototype/src/lib.rs"),
    ),
    (
        b"strict-hash/src/lib.rs",
        include_bytes!("../../strict-hash-profile/src/lib.rs"),
    ),
    (
        b"scalar/src/lib.rs",
        include_bytes!(
            "../../../../circuits/standalone-full-shake256-relation-prototype/src/lib.rs"
        ),
    ),
    (
        b"scalar/src/composed_envelope.rs",
        include_bytes!(
            "../../../../circuits/standalone-full-shake256-relation-prototype/src/composed_envelope.rs"
        ),
    ),
    (
        b"scalar/src/action_adapter.rs",
        include_bytes!(
            "../../../../circuits/standalone-full-shake256-relation-prototype/src/action_adapter.rs"
        ),
    ),
    (
        b"coefficient-mask.patch",
        include_bytes!(
            "../../m4-zk-coefficient-mask-patch/hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch"
        ),
    ),
    (
        b"grouped-relation.patch",
        include_bytes!(
            "../../m4-zk-grouped-relation-patch/hegemon-m4-zk-grouped-relation-after-coefficient-3f961630.patch"
        ),
    ),
    (
        b"grouped-stack-compile-fix.patch",
        include_bytes!("../patches/grouped-stack-compile-fix.patch"),
    ),
];

#[derive(Clone)]
struct Repetition {
    nonce: [u8; NONCE_BYTES],
    proof: Vec<u8>,
}

struct DecodedEnvelope<'a> {
    rate: usize,
    records: Vec<([u8; NONCE_BYTES], &'a [u8])>,
}

fn main() {
    if let Err(error) = real_main() {
        eprintln!("strict full baseline failed: {error}");
        process::exit(1);
    }
}

fn real_main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("prove") => {
            let out = parse_out(&mut args)?;
            require_no_more(args)?;
            prove_artifact(&out)
        }
        Some("verify") => {
            let artifact = parse_artifact(&mut args)?;
            require_no_more(args)?;
            verify_artifact(&artifact)
        }
        Some("--source-digest") => {
            require_no_more(args)?;
            println!("{}", hex(&source_bundle_digest()));
            Ok(())
        }
        _ => Err(
            "usage: hegemon-m4-strict-full-baseline-v0 prove --out DIR | verify --artifact DIR | --source-digest"
                .to_owned(),
        ),
    }
}

fn parse_out(args: &mut impl Iterator<Item = String>) -> Result<PathBuf, String> {
    if args.next().as_deref() != Some("--out") {
        return Err("prove requires --out DIR".to_owned());
    }
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| "missing output directory".to_owned())
}

fn parse_artifact(args: &mut impl Iterator<Item = String>) -> Result<PathBuf, String> {
    if args.next().as_deref() != Some("--artifact") {
        return Err("verify requires --artifact DIR".to_owned());
    }
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| "missing artifact directory".to_owned())
}

fn require_no_more(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    if let Some(extra) = args.next() {
        Err(format!("unexpected argument: {extra}"))
    } else {
        Ok(())
    }
}

fn prove_artifact(out: &Path) -> Result<(), String> {
    if out.exists() {
        return Err(format!(
            "refusing to overwrite output directory: {}",
            out.display()
        ));
    }
    let source_digest = source_bundle_digest();
    let material = canonical();
    let forged = ciphertext_hash_variant();
    if material.constraint_system.n_inout != forged.constraint_system.n_inout
        || material.constraint_system.n_private != forged.constraint_system.n_private
        || material.constraint_system.and_constraints.len()
            != forged.constraint_system.and_constraints.len()
    {
        return Err("the fresh-forgery control changed constraint geometry".to_owned());
    }
    let setup_start = Instant::now();
    let verifier = ZKVerifier::<StrictShake256HashSuite>::setup(
        material.constraint_system.clone(),
        LOG_INVERSE_RATE,
    )
    .map_err(|error| format!("verifier setup: {error:?}"))?;
    let prover = ZKProver::<OptimalPackedB128, StrictShake256HashSuite>::setup(&verifier)
        .map_err(|error| format!("prover setup: {error:?}"))?;
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1_000.0;

    let prove_start = Instant::now();
    let canonical_records = prove_repetitions(&prover, &material, &source_digest)?;
    let canonical_envelope = encode_envelope(LOG_INVERSE_RATE, &source_digest, &canonical_records)?;
    let canonical_prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;
    require(
        verify_envelope(&verifier, &material, &canonical_envelope, &source_digest),
        "canonical repeated proof did not verify",
    )?;

    let forgery_start = Instant::now();
    let forged_records = prove_repetitions(&prover, &forged, &source_digest)?;
    let forged_envelope = encode_envelope(LOG_INVERSE_RATE, &source_digest, &forged_records)?;
    let forgery_prove_ms = forgery_start.elapsed().as_secs_f64() * 1_000.0;
    require(
        verify_envelope(&verifier, &forged, &forged_envelope, &source_digest),
        "fresh alternate-statement proof did not verify against its own statement",
    )?;
    require(
        !verify_envelope(&verifier, &material, &forged_envelope, &source_digest),
        "fresh alternate-statement proof replayed against the canonical statement",
    )?;
    require(
        !verify_envelope(&verifier, &forged, &canonical_envelope, &source_digest),
        "canonical proof replayed against the alternate statement",
    )?;
    mutation_gates(&verifier, &material, &canonical_envelope, &source_digest)?;

    fs::create_dir(out).map_err(|error| format!("create output directory: {error}"))?;
    write_new(&out.join("statement.bin"), &material.statement_bytes)?;
    write_new(&out.join("proof.hgsb"), &canonical_envelope)?;
    write_new(
        &out.join("forgery-control-statement.bin"),
        &forged.statement_bytes,
    )?;
    write_new(&out.join("forgery-control-proof.hgsb"), &forged_envelope)?;

    let repeated_classical_bits = PER_COPY_CLASSICAL_BITS * REPETITIONS as f64;
    let qrom_protocol_bits = repeated_classical_bits / 2.0;
    let semantic_collision_bits = 448.0 / 3.0;
    let proof_collision_bits = 512.0 / 3.0;
    let composed_bits = union_bound_bits(&[
        qrom_protocol_bits,
        semantic_collision_bits,
        proof_collision_bits,
    ]);
    require(
        composed_bits >= 128.0,
        "composed repeated-QROM screen fell below PQ128",
    )?;
    let proof_lengths: Vec<usize> = canonical_records
        .iter()
        .map(|record| record.proof.len())
        .collect();
    let manifest = json!({
        "schema": "hegemon.full-m4.strict-repeated-zk-baseline.v1",
        "status": "strict-baseline-not-production-authorized",
        "relation": {
            "maximum_full_m4": true,
            "statement_bytes": material.statement_bytes.len(),
            "private_words": material.constraint_system.n_private,
            "public_words": material.constraint_system.n_inout,
            "and_constraints": material.constraint_system.and_constraints.len(),
            "numbered_chips": 0,
            "keccak_f": 83
        },
        "backend": {
            "upstream_revision": UPSTREAM_REVISION,
            "hash_suite": "StrictShake256HashSuite",
            "proof_hash": "SHAKE256-512",
            "challenge_field_per_copy": "BinaryField128bGhash",
            "log_inverse_rate": LOG_INVERSE_RATE,
            "sequential_repetitions": REPETITIONS,
            "coefficient_patch_sha256": COEFFICIENT_PATCH_SHA256,
            "grouped_patch_sha256": GROUPED_PATCH_SHA256,
            "source_bundle_sha256": hex(&source_digest)
        },
        "artifact": {
            "canonical_envelope_bytes": canonical_envelope.len(),
            "canonical_envelope_sha256": sha256_hex(&canonical_envelope),
            "canonical_envelope_shake256_512": shake256_512_hex(&canonical_envelope),
            "statement_sha256": sha256_hex(&material.statement_bytes),
            "per_repetition_proof_bytes": proof_lengths,
            "forgery_control_envelope_bytes": forged_envelope.len(),
            "forgery_control_envelope_sha256": sha256_hex(&forged_envelope)
        },
        "security": {
            "grouped_precommit_private_relation_active": true,
            "stock_wrapper_without_grouped_repair": false,
            "fresh_os_randomness_per_repetition": true,
            "domain_separated_sequential_repetition": true,
            "per_copy_classical_bits": PER_COPY_CLASSICAL_BITS,
            "repeated_classical_bits": repeated_classical_bits,
            "qrom_square_root_protocol_bits": qrom_protocol_bits,
            "semantic_hash_quantum_collision_bits": semantic_collision_bits,
            "proof_hash_quantum_collision_bits": proof_collision_bits,
            "composed_union_bound_bits": composed_bits,
            "complete_zk_basis": "pinned upstream ZK wrapper plus grouped precommit/private Phase-A relation; sequential composition uses independent fresh coins",
            "production_authorized": false,
            "remaining_release_gates": [
                "independent review of the grouped joint simulator and QROM direct-product reduction",
                "arbitrary-input Rust/M4 refinement certificate",
                "production action and wallet parser integration",
                "proof must satisfy the production 512-KiB envelope cap"
            ]
        },
        "gates": {
            "honest_roundtrip": true,
            "exact_envelope_consumption": true,
            "each_repetition_transcript_finalized": true,
            "proof_mutations_rejected": true,
            "statement_mutation_rejected": true,
            "truncation_rejected": true,
            "trailing_bytes_rejected": true,
            "fresh_alternate_statement_proof_verified": true,
            "fresh_alternate_statement_replay_rejected": true
        },
        "timing_ms": {
            "setup": setup_ms,
            "canonical_prove": canonical_prove_ms,
            "forgery_control_prove": forgery_prove_ms
        }
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize manifest: {error}"))?;
    write_new(&out.join("manifest.json"), &manifest_bytes)?;
    println!(
        "{}",
        String::from_utf8(manifest_bytes).expect("JSON is UTF-8")
    );
    Ok(())
}

fn verify_artifact(artifact: &Path) -> Result<(), String> {
    let source_digest = source_bundle_digest();
    let material = canonical();
    let forged = ciphertext_hash_variant();
    let statement = fs::read(artifact.join("statement.bin"))
        .map_err(|error| format!("read statement: {error}"))?;
    require(
        statement == material.statement_bytes,
        "artifact statement is not canonical",
    )?;
    let proof =
        fs::read(artifact.join("proof.hgsb")).map_err(|error| format!("read proof: {error}"))?;
    let forged_statement = fs::read(artifact.join("forgery-control-statement.bin"))
        .map_err(|error| format!("read forgery statement: {error}"))?;
    require(
        forged_statement == forged.statement_bytes,
        "forgery statement drift",
    )?;
    let forged_proof = fs::read(artifact.join("forgery-control-proof.hgsb"))
        .map_err(|error| format!("read forgery proof: {error}"))?;
    let verifier = ZKVerifier::<StrictShake256HashSuite>::setup(
        material.constraint_system.clone(),
        LOG_INVERSE_RATE,
    )
    .map_err(|error| format!("verifier setup: {error:?}"))?;
    require(
        verify_envelope(&verifier, &material, &proof, &source_digest),
        "restart verify failed",
    )?;
    require(
        verify_envelope(&verifier, &forged, &forged_proof, &source_digest),
        "restart forgery-control verify failed",
    )?;
    require(
        !verify_envelope(&verifier, &material, &forged_proof, &source_digest),
        "restart replay gate failed",
    )?;
    mutation_gates(&verifier, &material, &proof, &source_digest)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "hegemon.full-m4.strict-repeated-zk-restart-verification.v1",
            "verified": true,
            "proof_bytes": proof.len(),
            "proof_sha256": sha256_hex(&proof),
            "source_bundle_sha256": hex(&source_digest),
            "all_mutations_rejected": true,
            "fresh_forgery_replay_rejected": true
        }))
        .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn prove_repetitions(
    prover: &ZKProver<OptimalPackedB128, StrictShake256HashSuite>,
    material: &StrictBaselineMaterial,
    source_digest: &[u8; 32],
) -> Result<Vec<Repetition>, String> {
    let mut records = Vec::with_capacity(REPETITIONS);
    for index in 0..REPETITIONS {
        let mut os = rand::rng();
        let nonce: [u8; NONCE_BYTES] = os.random();
        let seed: [u8; 32] = os.random();
        let mut rng = domain_rng(&seed, index, &nonce, source_digest);
        let context = transcript_context(material, index, &nonce, source_digest);
        let mut transcript = ProverTranscript::new(StrictChallenger::default());
        transcript.observe().write_bytes(&context);
        prover
            .prove(&material.witness, &mut rng, &mut transcript)
            .map_err(|error| format!("repetition {index} prove: {error:?}"))?;
        records.push(Repetition {
            nonce,
            proof: transcript.finalize(),
        });
    }
    Ok(records)
}

fn verify_envelope(
    verifier: &ZKVerifier<StrictShake256HashSuite>,
    material: &StrictBaselineMaterial,
    encoded: &[u8],
    source_digest: &[u8; 32],
) -> bool {
    let decoded = match decode_envelope(encoded, source_digest) {
        Ok(decoded) => decoded,
        Err(_) => return false,
    };
    if decoded.rate != LOG_INVERSE_RATE || decoded.records.len() != REPETITIONS {
        return false;
    }
    decoded
        .records
        .iter()
        .enumerate()
        .all(|(index, (nonce, proof))| {
            let context = transcript_context(material, index, nonce, source_digest);
            let mut transcript =
                VerifierTranscript::new(StrictChallenger::default(), proof.to_vec());
            transcript.observe().write_bytes(&context);
            verifier.verify(&material.public, &mut transcript).is_ok()
                && transcript.finalize().is_ok()
        })
}

fn encode_envelope(
    rate: usize,
    source_digest: &[u8; 32],
    records: &[Repetition],
) -> Result<Vec<u8>, String> {
    require(records.len() == REPETITIONS, "wrong repetition count")?;
    let body_bytes: usize = records
        .iter()
        .map(|record| RECORD_HEADER_BYTES + record.proof.len())
        .sum();
    let total = ENVELOPE_HEADER_BYTES
        .checked_add(body_bytes)
        .ok_or("envelope length overflow")?;
    require(
        total <= MAX_ENVELOPE_BYTES,
        "strict baseline envelope exceeds 16 MiB",
    )?;
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&ENVELOPE_MAGIC);
    output.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    output.push(u8::try_from(rate).map_err(|_| "rate does not fit u8")?);
    output.push(u8::try_from(records.len()).map_err(|_| "repetitions do not fit u8")?);
    output.extend_from_slice(
        &u64::try_from(body_bytes)
            .map_err(|_| "body length does not fit u64")?
            .to_le_bytes(),
    );
    output.extend_from_slice(source_digest);
    for record in records {
        output.extend_from_slice(&record.nonce);
        output.extend_from_slice(
            &u32::try_from(record.proof.len())
                .map_err(|_| "proof too large")?
                .to_le_bytes(),
        );
        output.extend_from_slice(&record.proof);
    }
    Ok(output)
}

fn decode_envelope<'a>(
    encoded: &'a [u8],
    expected_source: &[u8; 32],
) -> Result<DecodedEnvelope<'a>, String> {
    require(
        encoded.len() >= ENVELOPE_HEADER_BYTES,
        "truncated envelope header",
    )?;
    require(encoded.len() <= MAX_ENVELOPE_BYTES, "oversized envelope")?;
    require(encoded[..4] == ENVELOPE_MAGIC, "wrong envelope magic")?;
    let version = u16::from_le_bytes(encoded[4..6].try_into().unwrap());
    require(version == ENVELOPE_VERSION, "wrong envelope version")?;
    let rate = encoded[6] as usize;
    let repetitions = encoded[7] as usize;
    require(repetitions == REPETITIONS, "noncanonical repetition count")?;
    let body_bytes = usize::try_from(u64::from_le_bytes(encoded[8..16].try_into().unwrap()))
        .map_err(|_| "body length does not fit usize".to_owned())?;
    require(
        &encoded[16..48] == expected_source,
        "source bundle mismatch",
    )?;
    require(
        body_bytes == encoded.len() - ENVELOPE_HEADER_BYTES,
        "body length mismatch",
    )?;
    let mut cursor = ENVELOPE_HEADER_BYTES;
    let mut records = Vec::with_capacity(repetitions);
    for _ in 0..repetitions {
        require(
            cursor + RECORD_HEADER_BYTES <= encoded.len(),
            "truncated repetition header",
        )?;
        let nonce = encoded[cursor..cursor + NONCE_BYTES].try_into().unwrap();
        cursor += NONCE_BYTES;
        let proof_bytes =
            u32::from_le_bytes(encoded[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        require(proof_bytes > 0, "empty repetition proof")?;
        require(
            cursor + proof_bytes <= encoded.len(),
            "truncated repetition proof",
        )?;
        records.push((nonce, &encoded[cursor..cursor + proof_bytes]));
        cursor += proof_bytes;
    }
    require(cursor == encoded.len(), "trailing envelope bytes")?;
    Ok(DecodedEnvelope { rate, records })
}

fn transcript_context(
    material: &StrictBaselineMaterial,
    index: usize,
    nonce: &[u8; NONCE_BYTES],
    source_digest: &[u8; 32],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(material.transcript_preamble.len() + 192);
    append_field(&mut context, TRANSCRIPT_DOMAIN);
    append_field(&mut context, UPSTREAM_REVISION.as_bytes());
    append_field(&mut context, COEFFICIENT_PATCH_SHA256.as_bytes());
    append_field(&mut context, GROUPED_PATCH_SHA256.as_bytes());
    append_field(&mut context, source_digest);
    append_field(&mut context, &(LOG_INVERSE_RATE as u64).to_be_bytes());
    append_field(&mut context, &(REPETITIONS as u64).to_be_bytes());
    append_field(&mut context, &(index as u64).to_be_bytes());
    append_field(&mut context, nonce);
    append_field(&mut context, &material.transcript_preamble);
    context
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn domain_rng(seed: &[u8; 32], index: usize, nonce: &[u8; 32], source: &[u8; 32]) -> StdRng {
    let mut hash = Sha256::new();
    Sha2Digest::update(&mut hash, b"hegemon.full-m4.strict-zk-coins.v1\0");
    Sha2Digest::update(&mut hash, seed);
    Sha2Digest::update(&mut hash, (index as u64).to_be_bytes());
    Sha2Digest::update(&mut hash, nonce);
    Sha2Digest::update(&mut hash, source);
    StdRng::from_seed(hash.finalize().into())
}

fn mutation_gates(
    verifier: &ZKVerifier<StrictShake256HashSuite>,
    material: &StrictBaselineMaterial,
    canonical: &[u8],
    source_digest: &[u8; 32],
) -> Result<(), String> {
    let decoded = decode_envelope(canonical, source_digest)?;
    for (index, (_, proof)) in decoded.records.iter().enumerate() {
        let proof_offset = proof.as_ptr() as usize - canonical.as_ptr() as usize;
        let mut changed = canonical.to_vec();
        changed[proof_offset + proof.len() / 2] ^= 1;
        require(
            !verify_envelope(verifier, material, &changed, source_digest),
            &format!("proof mutation {index} accepted"),
        )?;
    }
    let mut trailing = canonical.to_vec();
    trailing.push(0);
    require(
        !verify_envelope(verifier, material, &trailing, source_digest),
        "trailing byte accepted",
    )?;
    require(
        !verify_envelope(
            verifier,
            material,
            &canonical[..canonical.len() - 1],
            source_digest,
        ),
        "truncation accepted",
    )?;
    let mut wrong_source = canonical.to_vec();
    wrong_source[16] ^= 1;
    require(
        !verify_envelope(verifier, material, &wrong_source, source_digest),
        "source mutation accepted",
    )?;
    Ok(())
}

fn source_bundle_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    Sha2Digest::update(
        &mut hash,
        b"hegemon.full-m4.strict-baseline.source-bundle.v1\0",
    );
    for &(name, bytes) in SOURCE_BUNDLE {
        Sha2Digest::update(&mut hash, (name.len() as u64).to_be_bytes());
        Sha2Digest::update(&mut hash, name);
        Sha2Digest::update(&mut hash, (bytes.len() as u64).to_be_bytes());
        Sha2Digest::update(&mut hash, bytes);
    }
    hash.finalize().into()
}

fn union_bound_bits(bits: &[f64]) -> f64 {
    -bits.iter().map(|bits| 2f64.powf(-bits)).sum::<f64>().log2()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}

fn shake256_512_hex(bytes: &[u8]) -> String {
    let mut hash = Shake256::default();
    Update::update(&mut hash, bytes);
    let mut output = [0u8; 64];
    hash.finalize_xof().read(&mut output);
    hex(&output)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", path.display()))
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
