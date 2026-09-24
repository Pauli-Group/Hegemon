//! Replay the retained real HX512 action through the complete native lifecycle.

use std::{env, error::Error, fs, path::PathBuf};

use hegemon_node::native::hx512_lifecycle::exercise_hx512_candidate_lifecycle;
use protocol_shielded_pool::hx512_inline_transport::{
    Hx512InlineAdmissionVerifier, HX512_INLINE_CIPHERTEXT_BYTES, HX512_INLINE_IDENTITY_BYTES,
    HX512_INLINE_STATEMENT_BYTES,
};
use sha2::{Digest, Sha512};
use transaction_circuit::{
    hx512_production_relation::{
        hx512_refinement_fixtures, Hx512ExpectedStatementBinding, Hx512ProductionWitness,
    },
    smallwood_hx512_adapter::{
        compile_hx512_executable_hash_relation, Hx512VerifierRelationProfile,
    },
    smallwood_hx512_engine::{
        maximum_smallwood_hx512_inner_bytes, verify_smallwood_hx512_candidate,
    },
    smallwood_hx512_transcript::Hx512VerifierContextBinding,
};

const DEFAULT_ARTIFACT_DIRECTORY: &str = ".agent/artifacts/hx512-working-proof";

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
    let artifact_directory = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ARTIFACT_DIRECTORY));
    let fixture = hx512_refinement_fixtures()?
        .into_iter()
        .next()
        .ok_or("HX512 working fixture matrix is empty")?;
    let statement: [u8; HX512_INLINE_STATEMENT_BYTES] = fixture.statement.as_slice().try_into()?;
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
    let maximum_inner_proof_bytes = maximum_smallwood_hx512_inner_bytes(&assignment.adapter)?;
    let identity_header: [u8; HX512_INLINE_IDENTITY_BYTES] =
        statement[..HX512_INLINE_IDENTITY_BYTES].try_into()?;
    let witness = Hx512ProductionWitness::decode_exact(&fixture.witness)?;
    let verifier = ExactHx512Verifier {
        profile: assignment.adapter.retained_verifier_profile(),
        expected_binding: fixture.expected_binding,
        statement,
        verifier_context,
        identity_header,
        maximum_inner_proof_bytes,
        ciphertexts: [witness.outputs[0].ciphertext, witness.outputs[1].ciphertext],
    };

    let action_path = artifact_directory.join("canonical-action.bin");
    let action = fs::read(&action_path)?;
    let final_bytes = exercise_hx512_candidate_lifecycle(
        action.clone(),
        identity_header,
        u32::try_from(maximum_inner_proof_bytes)?,
        &artifact_directory.join("native-lifecycle.sled"),
        &verifier,
    )?;
    if final_bytes != action {
        return Err("native lifecycle changed the retained canonical action".into());
    }
    let final_path = artifact_directory.join("native-lifecycle-final.bin");
    fs::write(&final_path, &final_bytes)?;
    if fs::read(&final_path)? != action {
        return Err("native lifecycle final readback changed the action".into());
    }

    println!("lifecycle_bytes={}", final_bytes.len());
    println!("lifecycle_sha512={}", sha512_hex(&final_bytes));
    println!("lifecycle_path={}", final_path.display());
    Ok(())
}
