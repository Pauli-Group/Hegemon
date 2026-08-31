//! Generate, verify, mutate-check, transport-check, and retain one real HX512 proof.

use std::{env, error::Error, fs, path::PathBuf};

use protocol_shielded_pool::hx512_inline_transport::{
    validate_hx512_inline_action, Hx512InlineAction, Hx512InlineAdmissionVerifier,
    Hx512InlineTransportContext, HX512_INLINE_ACTIVITY_MASK_OFFSET, HX512_INLINE_CIPHERTEXT_BYTES,
    HX512_INLINE_IDENTITY_BYTES, HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
    HX512_INLINE_STATEMENT_BYTES,
};
use sha2::{Digest, Sha512};
use transaction_circuit::{
    hx512_production_relation::{
        hx512_refinement_fixtures, Hx512ExpectedStatementBinding, Hx512ProductionWitness,
        HX512_CIPHERTEXT_BYTES, HX512_STATEMENT_BYTES,
    },
    smallwood_hx512_adapter::{
        compile_hx512_executable_hash_relation, Hx512VerifierRelationProfile,
    },
    smallwood_hx512_engine::{
        maximum_smallwood_hx512_inner_bytes, prove_smallwood_hx512_candidate,
        verify_smallwood_hx512_candidate,
    },
    smallwood_hx512_transcript::{Hx512VerifierContextBinding, HX512_EXTERNAL_STATEMENT_BYTES},
};
use wallet::hx512_lifecycle::prepare_hx512_candidate_rpc_request;

const DEFAULT_OUTPUT_DIRECTORY: &str = ".agent/artifacts/hx512-working-proof";

struct ExactHx512Verifier {
    profile: Hx512VerifierRelationProfile,
    expected_binding: Hx512ExpectedStatementBinding,
    statement: [u8; HX512_INLINE_STATEMENT_BYTES],
    verifier_context: Hx512VerifierContextBinding,
    identity_header: [u8; HX512_INLINE_IDENTITY_BYTES],
    maximum_inner_proof_bytes: usize,
    ciphertexts: [[u8; HX512_INLINE_CIPHERTEXT_BYTES]; 2],
}

impl Hx512InlineAdmissionVerifier for ExactHx512Verifier {
    fn validate_statement(&self, statement: &[u8; HX512_INLINE_STATEMENT_BYTES]) -> bool {
        statement == &self.statement
    }

    fn validate_proof(&self, statement: &[u8; HX512_INLINE_STATEMENT_BYTES], proof: &[u8]) -> bool {
        statement == &self.statement
            && verify_smallwood_hx512_candidate(
                &self.profile,
                &self.expected_binding,
                statement,
                &self.verifier_context,
                &self.identity_header,
                self.maximum_inner_proof_bytes,
                proof,
            )
            .is_ok()
    }

    fn validate_ciphertext(
        &self,
        output_slot: usize,
        statement: &[u8; HX512_INLINE_STATEMENT_BYTES],
        ciphertext: &[u8; HX512_INLINE_CIPHERTEXT_BYTES],
    ) -> bool {
        statement == &self.statement && self.ciphertexts.get(output_slot) == Some(ciphertext)
    }
}

fn sha512_hex(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}

fn main() -> Result<(), Box<dyn Error>> {
    assert_eq!(HX512_STATEMENT_BYTES, HX512_INLINE_STATEMENT_BYTES);
    assert_eq!(HX512_CIPHERTEXT_BYTES, HX512_INLINE_CIPHERTEXT_BYTES);

    let mut arguments = env::args_os().skip(1);
    let first = arguments.next();
    let replay = first.as_deref() == Some(std::ffi::OsStr::new("--replay"));
    let output_directory = if replay {
        arguments.next().map(PathBuf::from)
    } else {
        first.map(PathBuf::from)
    }
    .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_DIRECTORY));
    let fixture = hx512_refinement_fixtures()?
        .into_iter()
        .next()
        .ok_or("HX512 working fixture matrix is empty")?;
    let statement: [u8; HX512_EXTERNAL_STATEMENT_BYTES] =
        fixture.statement.as_slice().try_into()?;
    let verifier_context = Hx512VerifierContextBinding::decode_exact(&fixture.context)?;
    let assignment = compile_hx512_executable_hash_relation(
        &fixture.statement,
        &fixture.context,
        &fixture.witness,
        &fixture.expected_binding,
    )?;
    assignment
        .adapter
        .verify_packed_witness(&assignment.witness_values)?;
    let verifier_profile = assignment.adapter.retained_verifier_profile();
    let maximum_inner_proof_bytes = maximum_smallwood_hx512_inner_bytes(&assignment.adapter)?;
    let identity_header: [u8; HX512_INLINE_IDENTITY_BYTES] =
        statement[..HX512_INLINE_IDENTITY_BYTES].try_into()?;

    let proof_path = output_directory.join("proof.bin");
    let proof = if replay {
        fs::read(&proof_path)?
    } else {
        prove_smallwood_hx512_candidate(
            &assignment,
            &statement,
            &verifier_context,
            &identity_header,
            maximum_inner_proof_bytes,
        )?
    };
    verify_smallwood_hx512_candidate(
        &verifier_profile,
        &fixture.expected_binding,
        &statement,
        &verifier_context,
        &identity_header,
        maximum_inner_proof_bytes,
        &proof,
    )?;

    let mut mutated_proof = proof.clone();
    let mutation_index = mutated_proof
        .len()
        .checked_sub(1)
        .ok_or("HX512 prover returned an empty proof")?;
    mutated_proof[mutation_index] ^= 1;
    if verify_smallwood_hx512_candidate(
        &verifier_profile,
        &fixture.expected_binding,
        &statement,
        &verifier_context,
        &identity_header,
        maximum_inner_proof_bytes,
        &mutated_proof,
    )
    .is_ok()
    {
        return Err("mutated HX512 proof was accepted".into());
    }

    let witness = Hx512ProductionWitness::decode_exact(&fixture.witness)?;
    let ciphertexts = [witness.outputs[0].ciphertext, witness.outputs[1].ciphertext];
    let verifier = ExactHx512Verifier {
        profile: verifier_profile,
        expected_binding: fixture.expected_binding,
        statement,
        verifier_context,
        identity_header,
        maximum_inner_proof_bytes,
        ciphertexts,
    };
    let transport_cap = u32::try_from(maximum_inner_proof_bytes)?;
    let transport = Hx512InlineTransportContext::new(
        &verifier.identity_header,
        transport_cap,
        HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
    )?;
    let activity_mask = statement[HX512_INLINE_ACTIVITY_MASK_OFFSET];
    let ciphertext_options = core::array::from_fn(|slot| {
        (activity_mask & (1 << (2 + slot)) != 0).then_some(&verifier.ciphertexts[slot])
    });
    let action = Hx512InlineAction::from_parts(
        transport,
        &statement,
        &proof,
        ciphertext_options,
        &verifier,
    )?;
    if action.proof() != proof {
        return Err("transport changed the proof bytes".into());
    }
    let action_bytes = action.into_bytes();
    validate_hx512_inline_action(transport, &action_bytes, &verifier)?;

    let wallet_request =
        prepare_hx512_candidate_rpc_request(transport, action_bytes.clone(), &verifier)?;
    if wallet_request.canonical_action_bytes()? != action_bytes {
        return Err("wallet RPC changed the canonical HX512 action bytes".into());
    }
    let wallet_rpc_json = serde_json::to_vec(&wallet_request)?;

    let mut mutated_action = action_bytes.clone();
    let proof_offset = HX512_INLINE_STATEMENT_BYTES + 4;
    mutated_action[proof_offset + mutation_index] ^= 1;
    if validate_hx512_inline_action(transport, &mutated_action, &verifier).is_ok() {
        return Err("transport admitted a mutated HX512 proof".into());
    }

    fs::create_dir_all(&output_directory)?;
    let action_path = output_directory.join("canonical-action.bin");
    let wallet_rpc_path = output_directory.join("wallet-rpc.json");
    fs::write(&proof_path, &proof)?;
    fs::write(&action_path, &action_bytes)?;
    fs::write(&wallet_rpc_path, wallet_rpc_json)?;
    let retained_proof = fs::read(&proof_path)?;
    let retained_action = fs::read(&action_path)?;
    if retained_proof != proof || retained_action != action_bytes {
        return Err("retained HX512 artifact changed during readback".into());
    }
    verify_smallwood_hx512_candidate(
        &verifier.profile,
        &verifier.expected_binding,
        &statement,
        &verifier_context,
        &identity_header,
        maximum_inner_proof_bytes,
        &retained_proof,
    )?;
    validate_hx512_inline_action(transport, &retained_action, &verifier)?;

    println!("proof_bytes={}", proof.len());
    println!("proof_sha512={}", sha512_hex(&proof));
    println!("action_bytes={}", action_bytes.len());
    println!("action_sha512={}", sha512_hex(&action_bytes));
    println!("proof_path={}", proof_path.display());
    println!("action_path={}", action_path.display());
    println!("wallet_rpc_path={}", wallet_rpc_path.display());
    Ok(())
}
