//! Two genuine one-input spends of disjoint notes at one RP05 parent.
//! Create-only development evidence; never a production authorization.
#![forbid(unsafe_code)]

#[cfg(feature = "rp05-dev-artifacts")]
#[allow(dead_code)]
#[path = "smallwood_poseidon2_v8_artifact.rs"]
mod shared;

#[cfg(feature = "rp05-dev-artifacts")]
mod runner {
    use super::shared;
    use protocol_shielded_pool::poseidon2_production_transport::{
        decode_poseidon2_production_smza_inline_args_exact,
        encode_poseidon2_production_smza_envelope, encode_poseidon2_production_smza_inline_args,
        encode_poseidon2_production_smza_native_leaf, Poseidon2ProductionExpectedContext,
        POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES, POSEIDON2_PRODUCTION_SMZA_MAX_ENVELOPE_BYTES,
        POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES,
    };
    use serde_json::{json, Value};
    use sha2::{Digest, Sha512};
    use std::{
        collections::BTreeMap,
        env,
        error::Error,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        path::{Component, Path, PathBuf},
        time::Instant,
    };
    use transaction_circuit::{
        smallwood_poseidon2_v8_frontend::{
            build_smallwood_poseidon2_v8_smza_development_artifact_verifier_trace_v1,
            compile_and_prove_smallwood_poseidon2_v8_smza_development_artifact_v1,
            verify_smallwood_poseidon2_v8_smza_development_artifact_v1,
            SmallwoodPoseidon2V8VerifierInput, SMALLWOOD_POSEIDON2_V8_SMZA_DOMAIN_SET,
            SMALLWOOD_POSEIDON2_V8_SMZA_PROFILE_ID,
        },
        smallwood_poseidon2_v8_hash_schedule::build_smallwood_poseidon2_v8_hash_schedule,
        smallwood_poseidon2_v8_program::smallwood_poseidon2_v8_program_digest_from_bytes,
        smallwood_poseidon2_v8_semantics::compile_smallwood_poseidon2_v8_relation_for_development_artifact,
        smallwood_poseidon2_v8_types::{
            SmallwoodPoseidon2V8InlineCiphertexts, SmallwoodPoseidon2V8PublicStatement,
            SmallwoodPoseidon2V8Witness,
        },
    };

    type Result<T> = std::result::Result<T, Box<dyn Error>>;
    const SCHEMA: &str = "hegemon-smallwood-poseidon2-v8-smza-disjoint-spends-v1";
    const NETWORK: u32 = protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID;
    const PROGRAM: &str = "testdata/formal_core_vectors/poseidon2_v8_relation_program_hgv8rp05.bin";
    const SOURCE: &str = "circuits/transaction/examples/rp05_smza_disjoint_spends_artifact.rs";
    const FILE_CAP: u64 = 2 * 1024 * 1024;
    const ROLES: [&str; 2] = ["spend-note0", "spend-note1"];
    // Fixed call positions in the unchanged source-owned RP05 hash schedule.
    const INPUT_0_ROOT_FINAL: usize = 35;
    const INPUT_0_NULLIFIER_FINAL: usize = 37;
    const OUTPUT_0_NOTE_FINAL: usize = 77;

    fn ensure(ok: bool, message: &str) -> Result<()> {
        if ok {
            Ok(())
        } else {
            Err(std::io::Error::other(message).into())
        }
    }

    fn sha512(bytes: &[u8]) -> String {
        hex::encode(Sha512::digest(bytes))
    }
    fn descriptor(bytes: &[u8]) -> Value {
        json!({"bytes": bytes.len(), "sha512": sha512(bytes)})
    }
    fn words(values: &[u64]) -> Vec<u8> {
        values.iter().flat_map(|word| word.to_le_bytes()).collect()
    }
    fn repository_root() -> Result<PathBuf> {
        Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?)
    }
    fn artifact_path(path: &Path) -> Result<PathBuf> {
        let root = repository_root()?.join(".agent/artifacts/smallwood-poseidon2-v8-smza");
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()?.join(path)
        };
        ensure(
            path.starts_with(root),
            "artifact directory outside retained development root",
        )?;
        ensure(
            !path
                .components()
                .any(|part| matches!(part, Component::ParentDir)),
            "parent traversal forbidden",
        )?;
        for ancestor in path.ancestors() {
            if let Ok(metadata) = fs::symlink_metadata(ancestor) {
                ensure(
                    !metadata.file_type().is_symlink(),
                    "symlink artifact path forbidden",
                )?;
            }
        }
        Ok(path)
    }
    fn read_bounded(path: &Path) -> Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure(
            metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= FILE_CAP,
            "artifact must be a bounded regular file",
        )?;
        let mut bytes = Vec::new();
        File::open(path)?
            .take(FILE_CAP + 1)
            .read_to_end(&mut bytes)?;
        ensure(bytes.len() as u64 <= FILE_CAP, "artifact exceeds read cap")?;
        Ok(bytes)
    }
    fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
        ensure(bytes.len() as u64 <= FILE_CAP, "artifact exceeds write cap")?;
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        ensure(read_bounded(path)? == bytes, "artifact readback differs")
    }
    fn file_identity(path: &Path) -> Result<Value> {
        let metadata = fs::symlink_metadata(path)?;
        ensure(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= 1024 * 1024 * 1024,
            "identity input must be a regular file below one GiB",
        )?;
        let mut file = File::open(path)?;
        let mut hasher = Sha512::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or("identity length overflow")?;
            ensure(
                total <= 1024 * 1024 * 1024,
                "identity input grew beyond cap",
            )?;
            hasher.update(&buffer[..count]);
        }
        Ok(json!({"bytes":total,"sha512":hex::encode(hasher.finalize())}))
    }
    fn generator_identity() -> Result<Value> {
        Ok(json!({
            "source_path":SOURCE,
            "source":file_identity(&repository_root()?.join(SOURCE))?,
            "shared_fixture_source":file_identity(&repository_root()?.join("circuits/transaction/examples/smallwood_poseidon2_v8_artifact.rs"))?,
            "executable":file_identity(&env::current_exe()?)?,
            "scope":"informational_unattested_generation_metadata"
        }))
    }
    fn identity() -> Result<(Vec<u8>, Value)> {
        let program = read_bounded(&repository_root()?.join(PROGRAM))?;
        ensure(
            program.starts_with(b"HGV8RP05"),
            "relation fixture is not RP05",
        )?;
        let digest = smallwood_poseidon2_v8_program_digest_from_bytes(&program);
        ensure(
            digest.as_slice() == &Sha512::digest(&program)[..48],
            "relation digest differs from source program",
        )?;
        Ok((
            program.clone(),
            json!({
                "network_id":NETWORK,"profile_id":SMALLWOOD_POSEIDON2_V8_SMZA_PROFILE_ID,
                "domain_set":SMALLWOOD_POSEIDON2_V8_SMZA_DOMAIN_SET,
                "relation_digest_hex":hex::encode(digest),"relation_program":descriptor(&program)
            }),
        ))
    }

    struct Fixture {
        statement: SmallwoodPoseidon2V8PublicStatement,
        witness: SmallwoodPoseidon2V8Witness,
        ciphertexts: SmallwoodPoseidon2V8InlineCiphertexts,
    }

    fn fixtures() -> Result<[Fixture; 2]> {
        let (base, witness, ciphertexts, _) = shared::shared_positive_fixture()?;
        ensure(
            base.stablecoin.parent_height == 2,
            "source fixture parent height drift",
        )?;
        let mut spends = Vec::new();
        for index in 0..2 {
            let mut statement = SmallwoodPoseidon2V8PublicStatement {
                input_flags: [true, false],
                output_flags: [true, false],
                merkle_root: base.merkle_root,
                stablecoin: base.stablecoin,
                ..SmallwoodPoseidon2V8PublicStatement::default()
            };
            let mut spend_witness = SmallwoodPoseidon2V8Witness::default();
            spend_witness.inputs[0] = witness.inputs[index];
            spend_witness.outputs[0] = witness.outputs[index];
            spend_witness.auth = witness.auth;
            spend_witness.stablecoin = witness.stablecoin;
            let spend_ciphertexts = SmallwoodPoseidon2V8InlineCiphertexts {
                ciphertexts: [ciphertexts.ciphertexts[index], None],
            };
            statement.ciphertext_commitments[0] = base.ciphertext_commitments[index];
            let schedule = build_smallwood_poseidon2_v8_hash_schedule(&statement, &spend_witness)?;
            ensure(
                schedule.calls[INPUT_0_ROOT_FINAL].final_digest() == base.merkle_root,
                "relocated input does not open the two-note parent root",
            )?;
            statement.nullifiers[0] = schedule.calls[INPUT_0_NULLIFIER_FINAL].final_digest();
            statement.commitments[0] = schedule.calls[OUTPUT_0_NOTE_FINAL].final_digest();
            ensure(
                statement.nullifiers[0] == base.nullifiers[index]
                    && statement.commitments[0] == base.commitments[index],
                "relocated input/output differs from exact repaired source fixture",
            )?;
            ensure(
                spend_witness.inputs[0].position == index as u64
                    && spend_witness.inputs[0].note.value > 0,
                "fixture must spend the corresponding positive coinbase note",
            )?;
            spend_witness
                .validate_against_statement(&statement)
                .map_err(|error| format!("one-input witness invalid: {error:?}"))?;
            spend_ciphertexts
                .validate_against_statement(&statement)
                .map_err(|error| format!("one-output ciphertext invalid: {error:?}"))?;
            let lowered = compile_smallwood_poseidon2_v8_relation_for_development_artifact(
                &statement,
                &spend_witness,
            )?;
            lowered
                .adapter
                .verify_packed_witness(&lowered.witness_values)?;
            spends.push(Fixture {
                statement,
                witness: spend_witness,
                ciphertexts: spend_ciphertexts,
            });
        }
        ensure(
            spends[0].statement.nullifiers[0] != spends[1].statement.nullifiers[0]
                && spends[0].statement.commitments[0] != spends[1].statement.commitments[0],
            "fixture inputs or outputs are not disjoint",
        )?;
        Ok(spends.try_into().map_err(|_| "wrong fixture count")?)
    }
    fn fixture_metadata(fixture: &Fixture) -> Value {
        json!({
            "input_position":fixture.witness.inputs[0].position,
            "input_value":fixture.witness.inputs[0].note.value,
            "output_value":fixture.witness.outputs[0].note.value,
            "active_nullifier_words":fixture.statement.nullifiers[0],
            "output_commitment_words":fixture.statement.commitments[0],
            "statement_sha512":sha512(&fixture.statement.to_public_bytes()),
            "witness_sha512":sha512(&words(&fixture.witness.to_witness_words())),
            "input_flags":[true,false],"output_flags":[true,false],
            "output_origin":"exact_source_fixture_authenticated_v5_ciphertext",
            "wallet_generated_outputs":false
        })
    }
    fn carriers(
        fixture: &Fixture,
        input: &SmallwoodPoseidon2V8VerifierInput,
        proof: &[u8],
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        let lowered = compile_smallwood_poseidon2_v8_relation_for_development_artifact(
            &fixture.statement,
            &fixture.witness,
        )?;
        let expected_input =
            SmallwoodPoseidon2V8VerifierInput::from_relation(NETWORK, &lowered.adapter);
        ensure(
            input.relation_digest == expected_input.relation_digest
                && input.public_values == expected_input.public_values
                && input.relation_balance_binding == expected_input.relation_balance_binding,
            "candidate differs from exact one-input source adapter",
        )?;
        ensure(
            words(&input.public_values) == fixture.statement.to_public_bytes(),
            "candidate public statement changed",
        )?;
        verify_smallwood_poseidon2_v8_smza_development_artifact_v1(input, proof)?;
        let expected = Poseidon2ProductionExpectedContext::new(NETWORK, input.relation_digest)?;
        let leaf = encode_poseidon2_production_smza_native_leaf(
            expected,
            &input.public_values,
            &input.relation_balance_binding,
            [fixture.ciphertexts.ciphertexts[0].as_ref(), None],
            proof,
        )?;
        let envelope = encode_poseidon2_production_smza_envelope(expected, &leaf)?;
        let args = encode_poseidon2_production_smza_inline_args(expected, &envelope)?;
        let decoded = decode_poseidon2_production_smza_inline_args_exact(expected, &args)?;
        ensure(
            decoded.envelope().raw() == envelope.as_slice()
                && decoded.envelope().decoded_native_leaf().raw() == leaf.as_slice()
                && decoded.envelope().decoded_native_leaf().proof() == proof,
            "proof or carrier bytes changed across exact decoding",
        )?;
        ensure(
            proof.len() <= POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES
                && args.len() <= POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES
                && envelope.len() <= POSEIDON2_PRODUCTION_SMZA_MAX_ENVELOPE_BYTES,
            "proof or carrier exceeds unchanged SMZA source cap",
        )?;
        Ok(BTreeMap::from([
            ("proof.bin".into(), proof.to_vec()),
            ("native-leaf.bin".into(), leaf),
            ("rpc-envelope.bin".into(), envelope),
            ("inline-args.bin".into(), args),
            ("public-inputs.bin".into(), words(&input.public_values)),
            (
                "kernel-binding.bin".into(),
                words(&input.relation_balance_binding),
            ),
            (
                "context.bin".into(),
                input
                    .smza_candidate_transcript_preamble_v1()?
                    .as_bytes()
                    .to_vec(),
            ),
        ]))
    }
    fn randomness(input: &SmallwoodPoseidon2V8VerifierInput, proof: &[u8]) -> Result<Value> {
        let trace =
            build_smallwood_poseidon2_v8_smza_development_artifact_verifier_trace_v1(input, proof)?;
        ensure(
            trace.accept && trace.proof.salt != [0; 32] && trace.pcs_trace.root_digest != [0; 64],
            "source verifier did not bind nonzero proof randomness",
        )?;
        Ok(json!({"wire_salt_hex":hex::encode(trace.proof.salt),
            "decs_transcript_root_hex":hex::encode(trace.pcs_trace.root_digest)}))
    }
    fn pins(files: &BTreeMap<String, Vec<u8>>) -> Value {
        json!(files
            .iter()
            .map(|(name, bytes)| (name.clone(), descriptor(bytes)))
            .collect::<BTreeMap<_, _>>())
    }
    fn verify(directory: &Path) -> Result<Value> {
        let directory = artifact_path(directory)?;
        let manifest: Value =
            serde_json::from_slice(&read_bounded(&directory.join("manifest.json"))?)?;
        let inventory = shared::shared_current_source_inventory()?;
        let generator = generator_identity()?;
        let (program, identity) = identity()?;
        ensure(
            manifest["schema"] == SCHEMA
                && manifest["features"] == json!(["rp05-dev-artifacts"])
                && manifest["qualification_scope"] == "source_bound_development_only"
                && manifest["production_eligible"] == false
                && manifest["production_authorized"] == false,
            "unsupported or authorizing fixture manifest",
        )?;
        ensure(
            manifest["identity"] == identity
                && manifest["proof_source_inventory"] == inventory
                && manifest["generator"] == generator,
            "fixture source/program/generator identity drift",
        )?;
        ensure(
            read_bounded(&directory.join("relation-program.bin"))? == program,
            "relation bytes changed",
        )?;
        let fixtures = fixtures()?;
        ensure(
            manifest["parent_height"] == 2
                && manifest["note_root_words"] == json!(fixtures[0].statement.merkle_root)
                && manifest["note_root_hex"]
                    == hex::encode(words(&fixtures[0].statement.merkle_root))
                && manifest["stablecoin_root_words"] == json!(vec![0u64; 7])
                && manifest["disjoint_inputs"] == true,
            "same-parent fixture context changed",
        )?;
        let mut coinbases = BTreeMap::new();
        for (name, bytes) in shared::shared_coinbase_fixture_files()? {
            ensure(
                read_bounded(&directory.join(name))? == bytes,
                "coinbase source bytes changed",
            )?;
            coinbases.insert(name.to_owned(), bytes);
        }
        ensure(
            manifest["fixture_files"] == pins(&coinbases),
            "coinbase file pins changed",
        )?;
        let mut receipts = BTreeMap::new();
        let mut random = Vec::new();
        for (index, role) in ROLES.iter().enumerate() {
            let fixture = &fixtures[index];
            let lowered = compile_smallwood_poseidon2_v8_relation_for_development_artifact(
                &fixture.statement,
                &fixture.witness,
            )?;
            let input = SmallwoodPoseidon2V8VerifierInput::from_relation(NETWORK, &lowered.adapter);
            ensure(
                hex::encode(input.relation_digest) == identity["relation_digest_hex"],
                "one-input source program drift",
            )?;
            let proof = read_bounded(&directory.join(role).join("proof.bin"))?;
            let files = carriers(fixture, &input, &proof)?;
            let evidence = randomness(&input, &proof)?;
            ensure(
                manifest["artifacts"][role]["fixture"] == fixture_metadata(fixture)
                    && manifest["artifacts"][role]["files"] == pins(&files)
                    && manifest["artifacts"][role]["randomness"] == evidence
                    && manifest["artifacts"][role]["source_owned_verification"] == true,
                "artifact metadata or source verification evidence changed",
            )?;
            for (name, bytes) in files {
                ensure(
                    read_bounded(&directory.join(role).join(name))? == bytes,
                    "exact retained carrier readback changed",
                )?;
            }
            random.push(evidence);
            receipts.insert(*role, json!({"proof_sha512":sha512(&proof),"source_owned_verification":true,"unchanged_carriers":true}));
        }
        ensure(
            random[0]["wire_salt_hex"] != random[1]["wire_salt_hex"]
                && random[0]["decs_transcript_root_hex"] != random[1]["decs_transcript_root_hex"]
                && receipts[ROLES[0]]["proof_sha512"] != receipts[ROLES[1]]["proof_sha512"],
            "independent invocations did not produce distinct proof randomness",
        )?;
        ensure(
            inventory == shared::shared_current_source_inventory()?
                && generator == generator_identity()?,
            "source/generator changed during verification",
        )?;
        Ok(
            json!({"schema":"hegemon-smza-disjoint-spends-readback-v1","artifacts":receipts,
            "same_parent":true,"disjoint_inputs":true,"distinct_proofs":true,
            "production_eligible":false,"production_authorized":false}),
        )
    }
    fn generate(directory: &Path) -> Result<Value> {
        let directory = artifact_path(directory)?;
        ensure(!directory.exists(), "generation is create-only")?;
        let inventory = shared::shared_current_source_inventory()?;
        let generator = generator_identity()?;
        let (program, identity) = identity()?;
        let fixtures = fixtures()?;
        fs::create_dir_all(directory.parent().ok_or("output has no parent")?)?;
        fs::create_dir(&directory)?;
        write_new(&directory.join("relation-program.bin"), &program)?;
        let mut coinbases = BTreeMap::new();
        for (name, bytes) in shared::shared_coinbase_fixture_files()? {
            write_new(&directory.join(name), &bytes)?;
            coinbases.insert(name.to_owned(), bytes);
        }
        let mut artifacts = BTreeMap::new();
        for (index, role) in ROLES.iter().enumerate() {
            let fixture = &fixtures[index];
            let started = Instant::now();
            let candidate = compile_and_prove_smallwood_poseidon2_v8_smza_development_artifact_v1(
                &fixture.statement,
                &fixture.witness,
                NETWORK,
            )?;
            let generation_seconds = started.elapsed().as_secs_f64();
            ensure(
                hex::encode(candidate.verifier_input().relation_digest)
                    == identity["relation_digest_hex"],
                "generated candidate program differs from unchanged source identity",
            )?;
            let files = carriers(fixture, candidate.verifier_input(), candidate.proof_bytes())?;
            ensure(
                candidate.measured_action_bytes() == files["inline-args.bin"].len()
                    && candidate.projected_max_proof_bytes()
                        <= POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES,
                "candidate measurement or projection exceeds exact source caps",
            )?;
            let evidence = randomness(candidate.verifier_input(), candidate.proof_bytes())?;
            fs::create_dir(directory.join(role))?;
            for (name, bytes) in &files {
                write_new(&directory.join(role).join(name), bytes)?;
            }
            artifacts.insert(
                *role,
                json!({"fixture":fixture_metadata(fixture),"files":pins(&files),
                "randomness":evidence,"source_owned_verification":true,
                "independent_entropy_invocation":true,"generation_seconds":generation_seconds}),
            );
        }
        ensure(
            inventory == shared::shared_current_source_inventory()?
                && generator == generator_identity()?,
            "source/generator changed during generation",
        )?;
        let manifest = json!({"schema":SCHEMA,"features":["rp05-dev-artifacts"],
            "qualification_scope":"source_bound_development_only","identity":identity,
            "proof_source_inventory":inventory,"generator":generator,
            "parent_height":2,"note_root_words":fixtures[0].statement.merkle_root,
            "note_root_hex":hex::encode(words(&fixtures[0].statement.merkle_root)),"stablecoin_root_words":vec![0u64; 7],
            "disjoint_inputs":true,"fixture_files":pins(&coinbases),"artifacts":artifacts,
            "public_test_wallet_seed_hex":hex::encode([0x51u8;32]),"public_test_wallet_diversifier":9,
            "production_eligible":false,"production_authorized":false});
        write_new(
            &directory.join("manifest.json"),
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
        let receipt = verify(&directory)?;
        write_new(
            &directory.join("readback.json"),
            &serde_json::to_vec_pretty(&receipt)?,
        )?;
        Ok(receipt)
    }
    pub fn main() -> Result<()> {
        let arguments: Vec<_> = env::args().skip(1).collect();
        let receipt = match arguments.as_slice() {
            [command,path] if command == "generate" => generate(Path::new(path))?,
            [command,path] if command == "verify" => verify(Path::new(path))?,
            _ => return Err("usage: rp05_smza_disjoint_spends_artifact generate NEW_DIRECTORY | verify DIRECTORY".into()),
        };
        println!("{}", serde_json::to_string_pretty(&receipt)?);
        Ok(())
    }
}

#[cfg(feature = "rp05-dev-artifacts")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    runner::main()
}

#[cfg(not(feature = "rp05-dev-artifacts"))]
fn main() {
    panic!("disjoint development fixtures require --features rp05-dev-artifacts");
}
