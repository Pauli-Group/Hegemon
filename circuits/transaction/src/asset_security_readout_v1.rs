//! Source-owned, development-only readout of the existing SMZE verifier.
//!
//! Reconstructs a retained proof with its exact asset/admin adapter. This is a
//! classical verifier execution, not the original adversary's quantum run or a
//! witness extractor. The engine currently exposes ordered field-XOF calls and
//! aggregate raw SHA512 counts, not a complete ordered raw-oracle query ledger.
#![forbid(unsafe_code)]

use crate::{
    asset_policy_admin_v1::{self as admin, PolicyAdminPublicV1},
    asset_spend_v1::{self as asset, AssetSpendPublic},
    smallwood_engine::{
        self as engine, SmallwoodDecsEvaluationDomain, SmallwoodTranscriptBackend,
        ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
        SMALLWOOD_ASSET_SPEND_SMZE_SHA512_PROFILE_DOMAIN,
    },
    smallwood_semantics::SmallwoodConstraintAdapter,
    TransactionCircuitError,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256, Sha512};

fn error(message: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(message)
}

fn words(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("word aligned")))
        .collect()
}

fn word_digest(values: &[u64]) -> String {
    let mut hash = Sha256::new();
    for word in values {
        hash.update(word.to_le_bytes());
    }
    hex::encode(hash.finalize())
}

fn raw_key(domain: &[u8], message: &[u64], counter: u64) -> Vec<u8> {
    let profile = SMALLWOOD_ASSET_SPEND_SMZE_SHA512_PROFILE_DOMAIN;
    let mut bytes = Vec::new();
    bytes.extend((profile.len() as u64).to_le_bytes());
    bytes.extend(profile);
    bytes.extend((domain.len() as u64).to_le_bytes());
    bytes.extend(domain);
    bytes.extend((message.len() as u64).to_le_bytes());
    for word in message {
        bytes.extend(word.to_le_bytes());
    }
    bytes.extend(counter.to_le_bytes());
    bytes
}

fn commitment(domain: &str, message: &[u64]) -> (Vec<u8>, [u8; 64]) {
    let key = raw_key(domain.as_bytes(), message, 0);
    let digest = Sha512::digest(&key).into();
    (key, digest)
}

fn commitment_row(
    role: &str,
    domain: &str,
    message: &[u64],
    expected: &[u8],
) -> Result<Value, TransactionCircuitError> {
    let (key, digest) = commitment(domain, message);
    if digest.as_slice() != expected {
        return Err(error("SMZE readout raw commitment mismatch"));
    }
    Ok(
        json!({"role":role,"domain":domain,"counter":0,"input_words":message,
        "raw_key_hex":hex::encode(key),"output_sha512":hex::encode(digest)}),
    )
}

fn readout(
    adapter: &(dyn SmallwoodConstraintAdapter + Sync),
    binding: &[u8],
    proof: &[u8],
    relation_id: &str,
    relation_digest: &[u8; 64],
    role: &str,
) -> Result<Value, TransactionCircuitError> {
    if proof.get(..4) != Some(b"SMZE".as_slice())
        || proof.len() > engine::SMALLWOOD_ASSET_SPEND_SMZE_MAX_INNER_PROOF_BYTES
    {
        return Err(error("SMZE readout requires exact bounded candidate wire"));
    }
    let (trace, operations, stages, calls) = engine::profile_smallwood_verifier_with_profile_v1(
        adapter,
        binding,
        proof,
        ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512AssetSpendSmze,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    if !trace.accept || trace.binding_words != words(binding) || trace.binding_words.len() != 134 {
        return Err(error(
            "SMZE readout requires accepted exact134 public binding",
        ));
    }
    let pcs = &trace.pcs_transcript_words;
    let piop_input = &trace.piop_input_words;
    if pcs.len() < 8
        || (pcs.len() - 8) % 5 != 0
        || (pcs.len() - 8) / 5 < 58
        || piop_input.len() != pcs.len() + 134
        || piop_input[..pcs.len()] != pcs[..]
        || piop_input[pcs.len()..] != trace.binding_words[..]
        || trace.piop_transcript_words.len() < 8
        || trace.proof.nonce != [0; 4]
        || trace.pcs_trace.decs_nonce != [0; 4]
    {
        return Err(error("SMZE readout source chronology/shape mismatch"));
    }
    let lvcs_cols = (pcs.len() - 8) / 5 - 58;
    let fpp_offset = 8 * pcs.len();
    let mut root_message = words(&trace.proof.salt);
    root_message.extend(words(&trace.pcs_trace.root_digest));
    root_message.extend(&trace.binding_words);
    let root_digest_bytes: Vec<u8> = pcs[..8].iter().flat_map(|w| w.to_le_bytes()).collect();
    let fpp_digest_bytes: Vec<u8> = trace.piop_transcript_words[..8]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let mut decs_message = words(&trace.proof.h_piop);
    for (heads, tails) in trace
        .pcs_trace
        .combi_heads
        .iter()
        .zip(&trace.proof.pcs.rcombi_tails)
    {
        decs_message.extend(heads);
        decs_message.extend(tails);
    }
    let commitments = vec![
        commitment_row(
            "root",
            "hegemon.smallwood.level5.merkle-root",
            &root_message,
            &root_digest_bytes,
        )?,
        commitment_row(
            "fpp",
            "hegemon.smallwood.level5.piop-input",
            piop_input,
            &fpp_digest_bytes,
        )?,
        commitment_row(
            "piop",
            "hegemon.smallwood.level5.piop-transcript",
            &trace.piop_transcript_words,
            &trace.recomputed_piop_digest,
        )?,
        commitment_row(
            "decs",
            "hegemon.smallwood.level5.decs-opening",
            &decs_message,
            &trace.pcs_trace.decs_trans_hash,
        )?,
    ];
    let field_calls: Vec<Value> = calls.iter().enumerate().map(|(index,call)| {
        let domain = String::from_utf8_lossy(&call.domain);
        let role = match domain.as_ref() {
            "hegemon.smallwood.level5.decs-coefficient" => "decs_matrix",
            "hegemon.smallwood.level5.piop-coefficient" => "piop_matrix",
            "hegemon.smallwood.level5.piop-opening" => "piop_opening",
            "hegemon.smallwood.asset-spend.smze.compff01.decs-fixed-sampling.v1" => "decs_sample",
            _ => "other",
        };
        json!({"execution_call_index":index,"role":role,"domain":domain,"input_words":call.input_words,
            "output_word_count":call.output_words.len(),"output_words_le_sha256":word_digest(&call.output_words),"raw_digest_calls":call.raw_digest_calls,
            "counter_start":0,"counter_end_exclusive":call.raw_digest_calls,
            "counter0_raw_key_hex":hex::encode(raw_key(&call.domain,&call.input_words,0))})
    }).collect();
    Ok(json!({
        "schema":"hegemon.smze.actual-verifier-source-readout.v1", "execution_kind":"classical existing-proof verifier trace reconstruction",
        "relation_role":role,"relation_id":relation_id,"relation_digest_sha512":hex::encode(relation_digest),
        "proof_bytes":proof.len(),"proof_sha256":hex::encode(Sha256::digest(proof)),"proof_sha512":hex::encode(Sha512::digest(proof)),
        "accepted":true,"public_words":trace.binding_words,"binding_sha256":hex::encode(Sha256::digest(binding)),
        "actual_pcs_transcript_words":pcs,"actual_piop_input_words":piop_input,
        "actual_piop_transcript_words":trace.piop_transcript_words,
        "actual_piop_matrix_rows":trace.piop_gamma_prime.len(),
        "actual_piop_matrix_columns":trace.piop_gamma_prime.first().map(Vec::len),
        "actual_lvcs_cols":lvcs_cols,"root_public_prefix_bytes":96,"fpp_public_prefix_bytes":fpp_offset,
        "expected_fpp_public_prefix_bytes":8*(8+5*(lvcs_cols+58)),
        "reconstructed_commitment_queries":commitments,"ordered_field_xof_calls":field_calls,
        "operations":operations,"stage_operations":stages,
        "full_ordered_raw_oracle_ledger":false,"original_adversary_execution_readout":false,
        "authenticated_state_transition_checked":false,"recovered_source_assignment":false,"expanded_hash_call_locators":false,
        "sampler_abort_probability_qualified":false,"efficient_extraction_established":false,
        "shared_qro_composition_qualified":false,"privacy_qualified":false,"production_authorized":false
    }))
}

pub fn asset_readout(
    public: &AssetSpendPublic,
    proof: &[u8],
) -> Result<Value, TransactionCircuitError> {
    public.validate_structure()?;
    readout(
        &asset::AssetSpendAdapter::from_public(public)?,
        &public.binding_bytes(),
        proof,
        asset::RELATION_ID,
        &asset::relation_digest(),
        "asset",
    )
}

pub fn admin_readout(
    public: &PolicyAdminPublicV1,
    proof: &[u8],
) -> Result<Value, TransactionCircuitError> {
    public.validate_structure()?;
    readout(
        &admin::PolicyAdminAdapterV1::from_public(public)?,
        &public.binding_bytes(),
        proof,
        admin::RELATION_ID,
        &admin::relation_digest(),
        "admin",
    )
}
