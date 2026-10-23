//! One-branch executable qualification generator. Retains only public bytes.
//! Fixed public fixture secrets make these artifacts unsuitable for real funds.
#![forbid(unsafe_code)]
use protocol_shielded_pool::private_spend_transport as transport;
use rand_core::{CryptoRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha512};
use std::{
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};
use synthetic_crypto::{
    ml_kem::MlKemKeyPair,
    private_note_encryption::{PrivateNoteCiphertext, PrivateNoteContext},
    private_note_payload::{
        HtlcOpening, NoteOpening, NoteState, PrivateNotePayload, TreasuryOpening as PayloadTreasury,
    },
    traits::KemKeyPair,
};
use transaction_circuit::private_spend::{
    self as spend, qualification, PrivateSpendPublic, PrivateSpendWitness,
};

/// Deterministic SHA512 stream ONLY for public disposable qualification fixtures.
/// The marker satisfies the encryption API, not a production randomness claim.
struct FixtureRng {
    tag: [u8; 32],
    counter: u64,
}
impl RngCore for FixtureRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(64) {
            let mut h = Sha512::new();
            h.update(b"PrivateSpendQualificationRngOnly-v1");
            h.update(self.tag);
            h.update(self.counter.to_le_bytes());
            self.counter += 1;
            chunk.copy_from_slice(&h.finalize()[..chunk.len()]);
        }
    }
}
impl CryptoRng for FixtureRng {}
fn hexhash(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn Error>> {
    write_new(path, &serde_json::to_vec_pretty(value)?)
}
fn wordbytes(words: impl IntoIterator<Item = u64>) -> Vec<u8> {
    words.into_iter().flat_map(u64::to_le_bytes).collect()
}
fn payload(mode: usize, slot: usize, w: &PrivateSpendWitness) -> PrivateNotePayload {
    let n = w.outputs[slot];
    let state = if slot == 0 && mode == 1 {
        let t = &w.treasury;
        NoteState::TreasuryAccumulator(PayloadTreasury {
            policy_key: t.policy_key,
            signer_tags: t.signer_tags,
            approved: core::array::from_fn(|i| t.approved[i] + t.selected_signer[i]),
            selected_signer: [0; 3],
            intent: t.intent.clone().try_into().unwrap(),
        })
    } else if slot == 0 && mode == 3 {
        let h = &w.htlc;
        NoteState::Htlc(HtlcOpening {
            nullifier_key: h.nullifier_key,
            hashlock: h.hashlock,
            claim_authority: h.claim_authority,
            refund_authority: h.refund_authority,
            claim_recipient: h.claim_recipient,
            refund_recipient: h.refund_recipient,
            timeout: h.timeout,
            secret: [0; 32],
            release_secret: h.release_secret,
        })
    } else {
        NoteState::Ordinary {
            authority: w.output_authorities[slot],
        }
    };
    PrivateNotePayload {
        recipient_index: 0,
        note: NoteOpening {
            value: n.value,
            asset_id: n.asset_id,
            recipient_key: n.recipient_key,
            authorization_key: n.authorization_key,
            rho: n.rho,
            randomness: n.randomness,
        },
        state,
    }
}
struct Prepared {
    public: PrivateSpendPublic,
    witness: PrivateSpendWitness,
    ciphertexts: [[u8; 2608]; 2],
}
fn prepare(mode: usize, relation48: [u8; 48]) -> Result<Prepared, Box<dyn Error>> {
    let (mut p, mut w) = qualification::fixture(mode);
    if mode == 1 {
        // A real final template with actual ciphertext hashes, rather than an
        // all-zero intent that could never authorize a valid final statement.
        let final_fixture = prepare(2, relation48)?;
        w.treasury.intent = final_fixture.public.intent_words().to_vec();
        let next = core::array::from_fn(|i| w.treasury.approved[i] + w.treasury.selected_signer[i]);
        let owner = spend::treasury_accumulator_owner(&w.treasury, next)?;
        spend::set_note_owner(&mut w.outputs[0], owner);
        qualification::refresh_fixture(&mut p, &mut w);
    }
    let mut ciphertexts = [[0u8; 2608]; 2];
    let mut bindings = [[0u8; 48]; 2];
    for slot in 0..2 {
        let record = payload(mode, slot, &w);
        let plaintext = record.encode(p.chain_id)?;
        let commitment: [u8; 56] = wordbytes(p.commitments[slot]).try_into().unwrap();
        let ctx = PrivateNoteContext::new(relation48, p.chain_id, slot as u8, commitment)?;
        let keys = MlKemKeyPair::generate_deterministic(
            format!("private-spend-disposable-artifact-recipient-{slot}-v1").as_bytes(),
        );
        let mut tag = [0; 32];
        tag[0] = mode as u8;
        tag[1] = slot as u8;
        tag[2] = 1;
        let ciphertext = PrivateNoteCiphertext::encrypt(
            &keys.public_key(),
            &ctx,
            &plaintext,
            &mut FixtureRng { tag, counter: 0 },
        )?;
        let decrypted = ciphertext.decrypt(keys.secret_key(), &ctx)?;
        if decrypted.as_bytes() != plaintext.as_bytes() {
            return Err("ciphertext roundtrip mismatch".into());
        }
        let decoded = PrivateNotePayload::decode(&decrypted, p.chain_id)?;
        if decoded.expected_owner(p.chain_id)? != record.expected_owner(p.chain_id)? {
            return Err("decrypted note owner mismatch".into());
        }
        ciphertexts[slot] = *ciphertext.as_bytes();
        bindings[slot] = transaction_core::hashing_pq::ciphertext_hash_bytes(ciphertext.as_bytes());
    }
    qualification::bind_fixture_ciphertexts(mode, &mut p, &mut w, bindings);
    Ok(Prepared {
        public: p,
        witness: w,
        ciphertexts,
    })
}
fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        return Err("usage: private_spend_candidate_artifact ordinary|approval|final|lock|claim|refund NEW_OUTPUT_DIRECTORY [--geometry-only]".into());
    }
    let names = ["ordinary", "approval", "final", "lock", "claim", "refund"];
    let mode = names
        .iter()
        .position(|n| *n == args[1])
        .ok_or("unknown branch")?;
    let geometry_only = args.get(3).map(|s| s.as_str());
    if geometry_only.is_some_and(|s| s != "--geometry-only") {
        return Err("unknown option".into());
    }
    let out = PathBuf::from(&args[2]);
    fs::create_dir(&out)?;
    let identity = spend::relation_digest();
    let relation48 = identity[..48].try_into().unwrap();
    let start = Instant::now();
    let fixture = prepare(mode, relation48)?;
    let (adapter, packed) = spend::compile(&fixture.public, &fixture.witness)?;
    let geometry = qualification::geometry_receipt(&fixture.public, &adapter)?;
    // No private witness/packed rows/keys/plaintext are serialized below.
    drop(packed);
    let binding = fixture.public.binding_bytes();
    write_new(&out.join("public-binding.bin"), &binding)?;
    for i in 0..2 {
        write_new(
            &out.join(format!("output-{i}.ciphertext")),
            &fixture.ciphertexts[i],
        )?;
    }
    write_json(
        &out.join("source-config.json"),
        &json!({
            "status":"actual_static_relation_and_public_config_constructed",
            "qualification_branch":names[mode],"branch_label_is_artifact_metadata_not_carrier":true,
            "relation_id":spend::RELATION_ID,"relation_digest_sha512":hex::encode(identity),
            "public_grammar":"86 canonical u64LE words, committed public release, no operation/occupancy field","public_words":fixture.public.words().to_vec(),
            "public_binding_bytes":binding.len(),"public_binding_sha512":hexhash(&binding),"geometry":geometry,
            "ciphertext_bytes_each":2608,"ciphertext_sha512":[hexhash(&fixture.ciphertexts[0]),hexhash(&fixture.ciphertexts[1])],
            "ciphertext_status":"actual ML-KEM1024/ChaCha20Poly1305; canonical PrivateNotePayload codec; decrypt/owner roundtrip checked",
            "fixture_secret_status":"Fixed disposable secrets are public in source; no confidentiality evidence and no real funds",
            "wallet_status":"Wallet selection, discovery, submission and real recipient-key routing not exercised",
            "fixture_tree":"canonical depth32 V8 defaults, occupied fixture leaves at positions0/1",
            "qualification_source_sha512":hexhash(include_bytes!("../src/private_spend/qualification.rs")),
            "generator_source_sha512":hexhash(include_bytes!("private_spend_candidate_artifact.rs")),
            "production_authorized":false,"q58_security_qualified":false,"all_eight_launch_gates_closed":false,
            "preproof_elapsed_seconds":start.elapsed().as_secs_f64(),
            "formal_obligations":[
                "lowered_row_iff must instantiate exact source Word/read/lower operations",
                "coalesce_eval must refine this CSR BTreeMap accumulation and zero removal",
                "each canonical product must reach its exact copied occurrence rows",
                "public input wires0..85 must equal exact decoded binding targets",
                "six selector booleans must sum to one in the actual field",
                "occupied membership includes zero-valued authorization accumulator notes",
                "real nullifier selects one committed credential independent of branch/slot",
                "linear recompute requires six distinct nonzero openings and correction guard",
                "nonlinear recompute requires openings disjoint from packing points",
                "generic algebra does not establish program security or Rust acceptance refinement"]
        }),
    )?;
    if geometry_only.is_some() {
        write_json(
            &out.join("result.json"),
            &json!({"status":"geometry_only_no_proof_attempted","production_authorized":false}),
        )?;
        return Ok(());
    }
    drop(adapter); // avoid retaining a graph while prove_candidate constructs its adapter
    let proof_start = Instant::now();
    let proof = match spend::prove_candidate(&fixture.public, &fixture.witness) {
        Ok(p) => p,
        Err(e) => {
            write_json(
                &out.join("result.json"),
                &json!({"status":"proof_generation_failed","error":e.to_string(),"elapsed_seconds":proof_start.elapsed().as_secs_f64(),"production_authorized":false}),
            )?;
            return Err(e.into());
        }
    };
    let proving_seconds = proof_start.elapsed().as_secs_f64();
    write_new(&out.join("proof.smzd"), &proof)?;
    let structured_proof_bytes =
        transaction_circuit::asset_spend_v1::native_frame_payload_size(&proof)?;
    let p = &fixture.public;
    let public = transport::PublicStatement {
        relation_digest: relation48,
        chain_id: p.chain_id,
        reference_parent_hash: p.reference_parent_hash,
        reference_parent_height: p.reference_parent_height,
        merkle_root: p.merkle_root,
        fee: p.fee,
        nullifiers: p.nullifiers,
        commitments: p.commitments,
        ciphertext_commitments: p.ciphertext_commitments,
        secret_release: p.secret_release,
        released_secret: p.released_secret,
    };
    let carrier = transport::encode(&public, fixture.ciphertexts.each_ref(), &proof)?;
    let context = transport::ExpectedContext::new(p.chain_id, relation48)?;
    let decoded = transport::decode_exact(context, &carrier)?;
    if decoded.raw != carrier
        || decoded.public != public
        || decoded.proof != proof
        || decoded.ciphertexts != fixture.ciphertexts.each_ref()
    {
        return Err("complete carrier identity changed during exact decode".into());
    }
    write_new(&out.join("carrier.hgps"), &carrier)?;
    let verify_start = Instant::now();
    let verified = spend::verify_candidate(&fixture.public, decoded.proof);
    let verification_seconds = verify_start.elapsed().as_secs_f64();
    write_json(
        &out.join("result.json"),
        &json!({"status":if verified.is_ok(){"candidate_proof_verified"}else{"candidate_proof_rejected"},
        "proof_bytes":proof.len(),"proof_sha512":hexhash(&proof),
        "structured_proof_bytes":structured_proof_bytes,"canonical_padding_bytes":proof.len()-structured_proof_bytes,
        "carrier_bytes":carrier.len(),"carrier_sha512":hexhash(&carrier),
        "complete_carrier_exact_decode_checked":true,"unchanged_inner_proof_checked":true,"proof_generation_and_verify_seconds":proof_start.elapsed().as_secs_f64(),
        "proving_seconds_including_compile":proving_seconds,"verification_seconds_including_compile":verification_seconds,
        "error":verified.as_ref().err().map(ToString::to_string),"production_authorized":false,"resources_measured_by_external_runner":true}),
    )?;
    verified?;
    println!("candidate artifact verified: {}", out.display());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("private spend qualification: {e}");
        std::process::exit(1)
    }
}
