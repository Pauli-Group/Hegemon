//! Coordinator-only actual proof qualification. Every ignored case proves and
//! verifies the compiled relation, retaining only public bindings/proof bytes.
//! These fixtures establish neither canonical ledger admission nor production,
//! cryptographic/refinement or archive-custody authorization.
use crate::{
    asset_recovery_admin_v1 as admin, asset_recovery_backend_v1 as backend,
    asset_recovery_capsule_v1 as capsule, asset_recovery_spend_v1 as spend,
    asset_spend_v1::{BURN, MINT, TRANSFER},
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Mutex,
    time::Instant,
};
use transaction_core::asset_recovery_v1 as recovery;

// All cases remain serialized even under a default parallel Rust test runner.
static PROVER_LANE: Mutex<()> = Mutex::new(());

struct Artifact {
    dir: PathBuf,
    report: Value,
    start: Instant,
    complete: bool,
}
impl Artifact {
    fn begin(name: &str, relation: &str, source: [u8; 64], binding: &[u8], words: usize) -> Self {
        let root = PathBuf::from(
            std::env::var_os("HEGEMON_RECOVERY_ARTIFACT_DIR")
                .expect("set an absolute HEGEMON_RECOVERY_ARTIFACT_DIR"),
        );
        assert!(root.is_absolute(), "artifact directory must be absolute");
        fs::create_dir_all(&root).expect("create artifact root");
        let dir = root.join(name);
        fs::create_dir(&dir).expect("case artifact directory must be fresh");
        let mut artifact = Self {
            dir,
            report: json!({
                "schema":"hegemon.asset-recovery.actual-proof.v1",
                "case":name,"status":"running","stage":"fixture",
                "relation_id":relation,"source_sha512":hex::encode(source),
                "test_source_sha256":hex::encode(Sha256::digest(include_bytes!("asset_recovery_actual_v1.rs"))),
                "public_words":words,"binding_bytes":binding.len(),
                "binding_sha256":hex::encode(Sha256::digest(binding)),
                "proof_magic":"SMZR","inner_proof_magic":"SMZE",
                "actual_proof_generated":false,"proof_verified":false,
                "negative_checks":{},"production_authorized":false,
                "source_lowering_certificate_complete":false,"native_acceptance_established":false,
                "scope":"actual compiled proof and public-binding checks; disposable fixtures; no ledger admission claim"
            }),
            start: Instant::now(),
            complete: false,
        };
        artifact.write_new("public.binding", binding);
        artifact.save();
        artifact
    }
    fn write_new(&self, name: &str, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.dir.join(name))
            .expect("create fresh public artifact");
        file.write_all(bytes).expect("retain public artifact");
        file.sync_all().expect("sync public artifact");
    }
    fn save(&mut self) {
        self.report["elapsed_ms"] = json!(self.start.elapsed().as_millis());
        let bytes = serde_json::to_vec_pretty(&self.report).expect("encode public report");
        let next = self.dir.join("report.next.json");
        fs::write(&next, bytes).expect("write report checkpoint");
        fs::rename(next, self.dir.join("report.json")).expect("publish report checkpoint");
    }
    fn stage(&mut self, stage: &'static str) {
        self.report["stage"] = json!(stage);
        self.save();
    }
    fn negative(&mut self, name: &'static str, rejected: bool) {
        self.report["negative_checks"][name] = json!(rejected);
        self.save();
        assert!(rejected, "required negative proof check failed: {name}");
    }
    fn proof(&mut self, proof: &[u8], prove_ms: u128) {
        self.write_new("proof.smzr", proof);
        self.report["actual_proof_generated"] = json!(true);
        self.report["proof_bytes"] = json!(proof.len());
        self.report["proof_sha256"] = json!(hex::encode(Sha256::digest(proof)));
        self.report["prove_ms"] = json!(prove_ms);
        self.save();
        assert!(proof.len() <= backend::MAX_PROOF_BYTES);
        assert_eq!(proof.get(..4), Some(b"SMZR".as_slice()));
        self.report["wire"] = backend::wire_receipt(proof).expect("actual exact SMZR/SMZE framing");
        self.save();
    }
    fn capsule_bundle(&mut self, proof: &[u8], prove_ms: u128) {
        // Retain completed PUBLIC artifacts before checks so a later negative
        // cannot erase expensive proof evidence. This is a collection of two
        // independent capped SMZR proofs, never a larger single proof.
        self.write_new("proof.smrc", proof);
        self.report["proof_magic"] = json!("SMRC");
        self.report["actual_proof_generated"] = json!(true);
        self.report["generated_proof_count"] = json!(capsule::SEGMENT_COUNT);
        self.report["proof_bytes"] = json!(proof.len());
        self.report["proof_sha256"] = json!(hex::encode(Sha256::digest(proof)));
        self.report["prove_ms"] = json!(prove_ms);
        self.save();
        assert!(proof.len() <= capsule::MAX_CAPSULE_BUNDLE_BYTES);
        assert_eq!(proof.get(..4), Some(b"SMRC".as_slice()));
        let components = capsule::bundle_components(proof).expect("exact two-component bundle");
        let mut receipts = Vec::new();
        for (index, component) in components.into_iter().enumerate() {
            self.write_new(&format!("component-{index}.smzr"), component);
            assert!(component.len() <= capsule::MAX_PROOF_BYTES);
            assert_eq!(component.get(..4), Some(b"SMZR".as_slice()));
            receipts.push(json!({
                "index":index,"proof_bytes":component.len(),
                "proof_sha256":hex::encode(Sha256::digest(component)),
                "source_sha512":hex::encode(capsule::segment_relation_digest(capsule::relation_digest(), index).unwrap()),
                "wire":capsule::component_proof_wire_receipt(component,index).unwrap(),
                "individual_prove_ms":null,"individual_verify_ms":null,
                "timing_scope":"collection timing; component timings not measured separately"
            }));
        }
        assert_eq!(receipts.len(), capsule::SEGMENT_COUNT);
        self.report["components"] = json!(receipts);
        self.report["wire"] =
            capsule::proof_wire_receipt(proof).expect("exact capsule collection framing");
        self.save();
    }
    fn verified(&mut self, verify_ms: u128) {
        self.report["verify_ms"] = json!(verify_ms);
        self.report["proof_verified"] = json!(true);
        if let Some(components) = self
            .report
            .get_mut("components")
            .and_then(Value::as_array_mut)
        {
            for component in components {
                component["proof_verified_by_collection"] = json!(true);
            }
        }
        self.save();
    }
    fn finish(&mut self, verify_ms: u128) {
        self.verified(verify_ms);
        self.report["status"] = json!("passed");
        self.report["stage"] = json!("complete");
        self.complete = true;
        self.save();
        println!(
            "RECOVERY_ACTUAL_PROOF_V1={}",
            serde_json::to_string(&self.report).unwrap()
        );
    }
}
impl Drop for Artifact {
    fn drop(&mut self) {
        if !self.complete {
            self.report["status"] = json!("failed");
            // No witness, secret, panic payload or error interpolation is retained.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.save()));
        }
    }
}

fn mutated_proof(proof: &[u8]) -> Vec<u8> {
    let mut bad = proof.to_vec();
    *bad.last_mut().expect("nonempty real proof") ^= 1;
    bad
}

#[test]
#[ignore = "actual two-segment SmallWood capsule; coordinator-only absolute artifact directory required"]
fn actual_capsule() {
    let _lane = PROVER_LANE.lock().unwrap_or_else(|p| p.into_inner());
    let (public, witness) = capsule::fixtures::fixture().expect("disposable capsule fixture");
    let binding = public.binding_bytes().unwrap();
    let mut artifact = Artifact::begin(
        "capsule",
        capsule::RELATION_ID,
        capsule::relation_digest(),
        &binding,
        capsule::PUBLIC_WORDS,
    );
    artifact.report["proof_magic"] = json!("SMRC");
    artifact.report["segment_count"] = json!(capsule::SEGMENT_COUNT);
    artifact.report["component_cap_bytes"] = json!(capsule::MAX_PROOF_BYTES);
    artifact.report["bundle_cap_bytes"] = json!(capsule::MAX_CAPSULE_BUNDLE_BYTES);
    artifact.stage("compile_segments");
    let mut geometry = Vec::new();
    for index in 0..capsule::SEGMENT_COUNT {
        let (adapter, packed) = capsule::compile_segment(&public, &witness, index)
            .expect("compile actual capsule component graph");
        adapter.verify_packed_witness(&packed).unwrap();
        drop((adapter, packed));
        let projected = capsule::component_projected_size(&public, index).unwrap();
        let receipt = capsule::component_geometry_receipt(&public, index).unwrap();
        geometry.push(json!({"index":index,"projected_bytes":projected,"geometry":receipt}));
        artifact.report["component_geometry"] = json!(geometry);
        artifact.save();
        assert!(
            projected <= capsule::MAX_PROOF_BYTES,
            "actual component projection exceeds unchanged2MiB cap"
        );
    }
    let projected = capsule::projected_size(&public).unwrap();
    artifact.report["projected_bundle_bytes"] = json!(projected);
    artifact.report["geometry"] = capsule::geometry_receipt(&public).unwrap();
    artifact.save();
    assert!(projected <= capsule::MAX_CAPSULE_BUNDLE_BYTES);
    artifact.stage("wrong_secret_compile_segments");
    let bad = capsule::AssetRecoveryCapsuleWitnessV1 {
        archive_secret: [24; 32],
        material: witness.material,
    };
    for index in 0..capsule::SEGMENT_COUNT {
        let name = match index {
            0 => "wrong_archive_secret_segment0_compile",
            1 => "wrong_archive_secret_segment1_compile",
            _ => panic!("unexpected capsule segment"),
        };
        artifact.negative(
            name,
            capsule::compile_segment(&public, &bad, index).is_err(),
        );
    }
    artifact.stage("prove_bundle");
    let timer = Instant::now();
    let proof =
        capsule::prove(&public, &witness).expect("generate actual capsule proof collection");
    artifact.capsule_bundle(&proof, timer.elapsed().as_millis());
    artifact.stage("verify_bundle");
    let timer = Instant::now();
    capsule::verify(&public, &proof).expect("verify both actual capsule proofs");
    let verify_ms = timer.elapsed().as_millis();
    artifact.verified(verify_ms);
    artifact.stage("negative_verify");
    artifact.negative(
        "mutated_proof_collection",
        capsule::verify(&public, &mutated_proof(&proof)).is_err(),
    );
    // First encrypted byte is in segment0, last byte in segment1. Both public
    // mutations remain well formed, exercising the actual proof verification.
    for (offset, name) in [
        (0, "changed_segment0_ciphertext"),
        (capsule::CIPHERTEXT_BYTES - 1, "changed_segment1_ciphertext"),
    ] {
        let mut changed = public.clone();
        changed.ciphertext[offset] ^= 1;
        changed
            .words()
            .expect("well-shaped changed ciphertext public");
        artifact.negative(name, capsule::verify(&changed, &proof).is_err());
    }
    let mut changed = public.clone();
    changed.note_commitment[0] ^= 1;
    changed
        .words()
        .expect("well-shaped changed capsule note public");
    artifact.negative(
        "changed_note_commitment",
        capsule::verify(&changed, &proof).is_err(),
    );
    artifact.finish(verify_ms);
}

fn actual_spend(name: &str, operation: u8, delegate: bool) {
    let _lane = PROVER_LANE.lock().unwrap_or_else(|p| p.into_inner());
    let (public, witness) =
        spend::fixtures::fixture(operation, delegate).expect("disposable spend fixture");
    let binding = public.binding_bytes().unwrap();
    let mut artifact = Artifact::begin(
        name,
        spend::RELATION_ID,
        spend::relation_digest(),
        &binding,
        spend::PUBLIC_WORDS,
    );
    artifact.report["operation"] = json!(operation);
    artifact.report["delegate"] = json!(delegate);
    artifact.stage("compile");
    let (adapter, packed) = spend::compile(&public, &witness).expect("compile actual spend graph");
    adapter.verify_packed_witness(&packed).unwrap();
    artifact.report["geometry"] = backend::geometry_receipt(&adapter).unwrap();
    drop((adapter, packed));
    artifact.stage("wrong_secret_compile");
    let mut bad = witness.clone();
    if operation == MINT {
        bad.base.issuer_secret[0] ^= 1;
    } else if delegate {
        bad.delegate_secret[0] ^= 1;
    } else {
        bad.base.inputs[0].spend_key[0] ^= 1;
    }
    artifact.negative(
        "wrong_selected_authority_compile",
        spend::compile(&public, &bad).is_err(),
    );
    artifact.stage("prove");
    let timer = Instant::now();
    let proof = spend::prove_candidate(&public, &witness).expect("generate actual spend proof");
    artifact.proof(&proof, timer.elapsed().as_millis());
    artifact.stage("verify");
    let timer = Instant::now();
    spend::verify_candidate(&public, &proof).expect("verify actual spend proof");
    let verify_ms = timer.elapsed().as_millis();
    artifact.verified(verify_ms);
    artifact.stage("negative_verify");
    artifact.negative(
        "mutated_proof",
        spend::verify_candidate(&public, &mutated_proof(&proof)).is_err(),
    );
    let mut changed = public.clone();
    changed.base.commitments[0][0] ^= 1;
    changed
        .words()
        .expect("well-shaped changed destination public");
    artifact.negative(
        "changed_public_destination_commitment",
        spend::verify_candidate(&changed, &proof).is_err(),
    );
    let mut changed = public.clone();
    changed.row.controls.epoch += 1;
    changed
        .words()
        .expect("well-shaped changed row epoch public");
    artifact.negative(
        "changed_current_row_epoch",
        spend::verify_candidate(&changed, &proof).is_err(),
    );
    artifact.finish(verify_ms);
}

#[test]
#[ignore = "actual SmallWood proof; coordinator only"]
fn actual_holder() {
    actual_spend("holder", TRANSFER, false);
}
#[test]
#[ignore = "actual SmallWood proof; coordinator only"]
fn actual_delegate() {
    actual_spend("delegate", TRANSFER, true);
}
#[test]
#[ignore = "actual SmallWood proof; coordinator only"]
fn actual_mint() {
    actual_spend("mint", MINT, false);
}
#[test]
#[ignore = "actual SmallWood proof; coordinator only"]
fn actual_burn() {
    actual_spend("burn", BURN, true);
}

fn admin_fixture(freeze: bool) -> (admin::Public, admin::Witness) {
    let secret = [0, 2, 3, 4, 5, 6, 7];
    let chain = [21; 32];
    let descriptor = recovery::RecoveryDescriptorV1 {
        asset_id: 17,
        stable_policy_id: [3; 7],
        policy_admin_commitment: admin::policy_admin_commitment(17, secret).unwrap(),
        archive_key_commitment: recovery::archive_key_commitment(&[23; 32]).unwrap(),
        maximum_powers: recovery::RecoveryPowersV1 {
            transfer: true,
            burn: true,
        },
    };
    let defaults = recovery::freeze_defaults(&descriptor, chain).unwrap();
    let before = recovery::RecoveryRowV1 {
        descriptor,
        controls: recovery::RecoveryControlsV1 {
            epoch: 0,
            delegate_action_commitment: recovery::delegate_action_commitment([12; 7]).unwrap(),
            revoked: false,
            powers: recovery::RecoveryPowersV1 {
                transfer: true,
                burn: true,
            },
            note_freeze_root: defaults[32],
        },
    };
    let context = recovery::RecoveryContextV1 {
        chain_id: chain,
        parent_hash: [22; 32],
        parent_height: 40,
        row_commitment: before.commitment(chain).unwrap(),
    };
    let mut after = recovery::RecoveryControlsV1 {
        epoch: 1,
        delegate_action_commitment: recovery::delegate_action_commitment([17; 7]).unwrap(),
        ..before.controls
    };
    let mut siblings = [[0; 7]; 32];
    let mutation = if freeze {
        siblings = core::array::from_fn(|level| defaults[level]);
        // A real note commitment from the disposable capsule fixture; canonical
        // position membership is deliberately not a proof-test claim.
        let note = capsule::fixtures::fixture().unwrap().0.note_commitment;
        after.note_freeze_root =
            recovery::freeze_root(&descriptor, chain, 41, note, true, &siblings).unwrap();
        Some(admin::FreezeMutation {
            position: 41,
            note_commitment: note,
            before_frozen: false,
            after_frozen: true,
        })
    } else {
        None
    };
    let prepared = recovery::prepare_controls_update(context, before, after).unwrap();
    let public = admin::Public::from_prepared(&prepared, 42, [23; 7], mutation).unwrap();
    public.verify_prepared(&prepared).unwrap();
    (
        public,
        admin::Witness {
            admin_secret: secret,
            freeze_siblings: siblings,
        },
    )
}

fn actual_admin(name: &str, freeze: bool) {
    let _lane = PROVER_LANE.lock().unwrap_or_else(|p| p.into_inner());
    let (public, witness) = admin_fixture(freeze);
    let binding = public.binding_bytes().unwrap();
    let mut artifact = Artifact::begin(
        name,
        admin::RELATION_ID,
        admin::relation_digest(),
        &binding,
        admin::PUBLIC_WORDS,
    );
    artifact.report["freeze"] = json!(freeze);
    artifact.report["admin_action_id"] = json!(hex::encode(public.action_id().unwrap()));
    artifact.stage("compile");
    let (adapter, packed) = admin::compile(&public, &witness).expect("compile actual admin graph");
    adapter.verify_packed_witness(&packed).unwrap();
    artifact.report["geometry"] = backend::geometry_receipt(&adapter).unwrap();
    drop((adapter, packed));
    artifact.stage("wrong_secret_compile");
    let mut bad = witness.clone();
    bad.admin_secret[1] ^= 1;
    artifact.negative(
        "wrong_admin_secret_compile",
        admin::compile(&public, &bad).is_err(),
    );
    artifact.stage("prove");
    let timer = Instant::now();
    let proof = admin::prove_candidate(&public, &witness).expect("generate actual admin proof");
    artifact.proof(&proof, timer.elapsed().as_millis());
    artifact.stage("verify");
    let timer = Instant::now();
    admin::verify_candidate(&public, &proof).expect("verify actual admin proof");
    let verify_ms = timer.elapsed().as_millis();
    artifact.verified(verify_ms);
    artifact.stage("negative_verify");
    artifact.negative(
        "mutated_proof",
        admin::verify_candidate(&public, &mutated_proof(&proof)).is_err(),
    );
    let mut changed = public.clone();
    changed.before.controls.epoch += 1;
    changed.after.epoch += 1;
    changed.context.row_commitment = changed.before.commitment(changed.context.chain_id).unwrap();
    changed
        .validate_structure()
        .expect("well-shaped changed admin epoch");
    artifact.negative(
        "changed_row_epoch",
        admin::verify_candidate(&changed, &proof).is_err(),
    );
    if freeze {
        let mut changed = public.clone();
        changed.freeze.as_mut().unwrap().note_commitment[0] ^= 1;
        changed
            .validate_structure()
            .expect("well-shaped changed freeze note public");
        artifact.negative(
            "changed_freeze_note_commitment",
            admin::verify_candidate(&changed, &proof).is_err(),
        );
    } else {
        let mut changed = public.clone();
        changed.after.delegate_action_commitment[0] ^= 1;
        changed
            .validate_structure()
            .expect("well-shaped changed delegate public");
        artifact.negative(
            "changed_rotated_delegate",
            admin::verify_candidate(&changed, &proof).is_err(),
        );
    }
    artifact.finish(verify_ms);
}

#[test]
#[ignore = "actual SmallWood proof; coordinator only"]
fn actual_admin_rotation() {
    actual_admin("admin_rotation", false);
}
#[test]
#[ignore = "actual SmallWood proof; coordinator only"]
fn actual_admin_note_freeze() {
    actual_admin("admin_note_freeze", true);
}
