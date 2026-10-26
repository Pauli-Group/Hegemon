//! Complete, factored classical SMZE verifier raw-SHA512 readout.
//!
//! Uses the frozen engine's recorder-only overlay. No oracle answers are
//! programmed. This does not recover the prover's or a quantum adversary's run.
#![forbid(unsafe_code)]

use crate::{
    asset_policy_admin_v1::{self as admin, PolicyAdminPublicV1},
    asset_spend_v1::{self as asset, AssetSpendPublic},
    smallwood_engine::{self as engine, SmallwoodSha512OracleKeyV1 as Key},
    smallwood_semantics::SmallwoodConstraintAdapter,
    TransactionCircuitError,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256, Sha512};

const MAX_QUERIES: usize = 2_100_000;
const MAX_KEY_BYTES: usize = 2_000_000;
const ROLLING_DOMAIN: &[u8] = b"hegemon.asset.classical-raw-ledger.v1";
const PROFILE: &[u8] = engine::SMALLWOOD_ASSET_SPEND_SMZE_SHA512_PROFILE_DOMAIN;
const LEAF: &[u8] = b"hegemon.smallwood.strict-zk.merkle-leaf.asset-spend.v1";
const NODE: &[u8] = b"hegemon.smallwood.level5.merkle-node";
const DECS: &[u8] = b"hegemon.smallwood.level5.decs-opening";
const ROOT: &[u8] = b"hegemon.smallwood.level5.merkle-root";
const FPP: &[u8] = b"hegemon.smallwood.level5.piop-input";
const PIOP: &[u8] = b"hegemon.smallwood.level5.piop-transcript";
const FIELD_DOMAINS: [&[u8]; 6] = [
    b"hegemon.smallwood.level5.piop-opening",
    b"hegemon.smallwood.level5.piop-opening",
    b"hegemon.smallwood.asset-spend.smze.compff01.decs-fixed-sampling.v1",
    b"hegemon.smallwood.level5.decs-coefficient",
    b"hegemon.smallwood.level5.piop-coefficient",
    b"hegemon.smallwood.level5.piop-coefficient",
];

fn fail(message: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(message)
}

fn words(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("word aligned")))
        .collect()
}

fn encode_key(key: &Key, out: &mut Vec<u8>) -> Result<(), TransactionCircuitError> {
    if key.profile_domain.as_deref() != Some(PROFILE) {
        return Err(fail("raw ledger unexpected oracle profile"));
    }
    let count = 32 + PROFILE.len() + key.role_domain.len() + 8 * key.words.len();
    if count > MAX_KEY_BYTES {
        return Err(fail("raw ledger key exceeds bounded supported geometry"));
    }
    out.clear();
    out.extend((PROFILE.len() as u64).to_le_bytes());
    out.extend(PROFILE);
    out.extend((key.role_domain.len() as u64).to_le_bytes());
    out.extend(&key.role_domain);
    out.extend((key.words.len() as u64).to_le_bytes());
    for word in &key.words {
        out.extend(word.to_le_bytes());
    }
    out.extend(key.counter.to_le_bytes());
    Ok(())
}

fn record(
    adapter: &(dyn SmallwoodConstraintAdapter + Sync),
    binding: &[u8],
    proof: &[u8],
    relation_id: &str,
    relation_digest: &[u8; 64],
    role: &str,
    matrix_words: usize,
) -> Result<Value, TransactionCircuitError> {
    let cap =
        |n: usize| (n + engine::SMALLWOOD_SHA512_FIELD_XOF_EXTRA_CANDIDATE_WORDS_V1).div_ceil(8);
    let raw_cap = 1397 + 2 * cap(6) + cap(80) + cap(700) + 2 * cap(matrix_words);
    if raw_cap > MAX_QUERIES
        || proof.get(..4) != Some(b"SMZE".as_slice())
        || proof.len() > engine::SMALLWOOD_ASSET_SPEND_SMZE_MAX_INNER_PROOF_BYTES
    {
        return Err(fail("raw ledger unsupported wire or preflight query cap"));
    }
    // Conservative allocation model for the recorder's logical storage on
    // this target. Vec growth/capacity and allocator overhead are reported
    // separately after the run; this is not a process RSS bound. Field seeds
    // are at most9 words, not the large FPP/public prefix.
    let preflight_logical_storage_bytes = raw_cap
        * (std::mem::size_of::<engine::SmallwoodSha512OracleQueryV1>() + 61 + 66 + 72)
        + 5 * MAX_KEY_BYTES
        + 58 * 294 * 8
        + 1334 * 16 * 8;
    // These exact supported graphs have six capped field requests and 1397
    // singleton calls. The recorder retains a Vec; it has no streaming hook.
    let recorded = engine::record_smallwood_sha512_queries_v1(|| {
        engine::profile_smallwood_verifier_with_profile_v1(
            adapter,
            binding,
            proof,
            engine::ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
            engine::SmallwoodTranscriptBackend::Sha512AssetSpendSmze,
            engine::SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
    })?;
    let (trace, operations, stages, calls) = recorded.result?;
    let queries = recorded.queries;
    if !trace.accept
        || trace.binding_words != words(binding)
        || trace.binding_words.len() != 134
        || trace.proof.nonce != [0; 4]
        || trace.pcs_trace.decs_nonce != [0; 4]
        || queries.len() > raw_cap
        || queries.len() > MAX_QUERIES
        || operations.sha512_digest_calls != queries.len() as u64
        || calls.len() != 6
        || operations.merkle_leaf_hashes != 58
        || operations.merkle_internal_hashes != 1334
    {
        return Err(fail("raw ledger accepted trace/count mismatch"));
    }
    for (i, call) in calls.iter().enumerate() {
        let expected_words = match i {
            0 | 1 => 6,
            2 => 80,
            3 => 700,
            _ => matrix_words,
        };
        if call.domain != FIELD_DOMAINS[i]
            || call.input_words.len() != if i < 2 { 9 } else { 8 }
            || call.output_words.len() != expected_words
            || call.raw_digest_calls as usize > cap(expected_words)
        {
            return Err(fail(
                "raw ledger six field requests differ from supported source",
            ));
        }
    }
    let field_count: usize = calls.iter().map(|c| c.raw_digest_calls as usize).sum();
    if queries.len() != field_count + 1397 {
        return Err(fail("raw ledger singleton gap is not1397"));
    }
    let recorder_vec_reserved =
        queries.capacity() * std::mem::size_of::<engine::SmallwoodSha512OracleQueryV1>();
    let recorder_key_heaps_reserved: usize = queries
        .iter()
        .map(|q| {
            q.key.profile_domain.as_ref().map_or(0, Vec::capacity)
                + q.key.role_domain.capacity()
                + 8 * q.key.words.capacity()
        })
        .sum();

    let mut root = words(&trace.proof.salt);
    root.extend(words(&trace.pcs_trace.root_digest));
    root.extend(&trace.binding_words);
    let mut decs = words(&trace.proof.h_piop);
    for (heads, tails) in trace
        .pcs_trace
        .combi_heads
        .iter()
        .zip(&trace.proof.pcs.rcombi_tails)
    {
        decs.extend(heads);
        decs.extend(tails);
    }
    // Each piece occupies a disjoint contiguous interval in the recorded run.
    // A stream descriptor regenerates every concrete SHA512 answer, and its
    // digest authenticates the complete actually recorded sequence of answers.
    enum Piece<'a> {
        Stream(usize),
        Single(
            &'static str,
            &'a [u8],
            Option<&'a [u64]>,
            Option<(usize, usize)>,
        ),
    }
    let mut pieces = vec![
        Piece::Stream(0),
        Piece::Stream(1),
        Piece::Single("decs", DECS, Some(&decs), None),
        Piece::Stream(2),
    ];
    for j in 0..58 {
        pieces.push(Piece::Single("strict_leaf", LEAF, None, Some((0, j))));
    }
    for level in 0..23 {
        for j in 0..58 {
            pieces.push(Piece::Single("internal_node", NODE, None, Some((level, j))));
        }
    }
    pieces.extend([
        Piece::Single("root", ROOT, Some(&root), None),
        Piece::Stream(3),
        Piece::Single("fpp", FPP, Some(&trace.piop_input_words), None),
        Piece::Stream(4),
        Piece::Single("piop", PIOP, Some(&trace.piop_transcript_words), None),
        Piece::Single("fpp", FPP, Some(&trace.piop_input_words), None),
        Piece::Stream(5),
    ]);
    let mut index = 0usize;
    let mut ledger = Sha512::new();
    ledger.update(ROLLING_DOMAIN);
    let mut scratch = Vec::new();
    let mut events = Vec::with_capacity(1403);
    let mut framed_key_and_output_bytes = 0u64;
    for piece in pieces {
        let (count, stream) = match &piece {
            Piece::Stream(i) => (calls[*i].raw_digest_calls as usize, Some(*i)),
            _ => (1, None),
        };
        let start = index;
        let mut actual_answers = Sha512::new();
        let mut accepted_field_words = 0usize;
        let mut rejected_field_words = 0usize;
        for offset in 0..count {
            let query = queries.get(index).ok_or(fail("raw ledger premature end"))?;
            if query.programmed_kind.is_some() {
                return Err(fail(
                    "raw ledger recorder unexpectedly programmed an answer",
                ));
            }
            if let Some(i) = stream {
                if query.key.role_domain != calls[i].domain
                    || query.key.words != calls[i].input_words
                    || query.key.counter != offset as u64
                {
                    return Err(fail("raw ledger stream key/counter/order mismatch"));
                }
            } else if let Piece::Single(name, domain, expected, locator) = &piece {
                if query.key.role_domain != *domain || query.key.counter != 0 {
                    return Err(fail("raw ledger singleton role/order mismatch"));
                }
                if let Some(expected) = expected {
                    if query.key.words.as_slice() != *expected {
                        return Err(fail("raw ledger commitment differs from actual trace"));
                    }
                }
                if *name == "strict_leaf" {
                    let j = locator.expect("leaf locator").1;
                    let mut expected_leaf = trace.binding_words.clone();
                    expected_leaf.extend(words(&trace.proof.salt));
                    expected_leaf.push(trace.pcs_trace.decs_leaf_indexes[j] as u64);
                    expected_leaf.extend(words(&trace.proof.pcs.decs.leaf_tapes[j]));
                    expected_leaf.push(trace.pcs_trace.rows[j].len() as u64);
                    expected_leaf.extend(&trace.pcs_trace.rows[j]);
                    expected_leaf.push(trace.proof.pcs.decs.masking_evals[j].len() as u64);
                    expected_leaf.extend(&trace.proof.pcs.decs.masking_evals[j]);
                    if query.key.words != expected_leaf || expected_leaf.len() != 294 {
                        return Err(fail("raw ledger strict leaf differs from trace"));
                    }
                }
                if *name == "internal_node" && query.key.words.len() != 16 {
                    return Err(fail("raw ledger internal node width mismatch"));
                }
            }
            encode_key(&query.key, &mut scratch)?;
            let recomputed: [u8; 64] = Sha512::digest(&scratch).into();
            if recomputed != query.output {
                return Err(fail("raw ledger raw concrete answer mismatch"));
            }
            if let Some(i) = stream {
                if accepted_field_words == calls[i].output_words.len() {
                    return Err(fail("raw ledger field stream has excess digest blocks"));
                }
                for chunk in query.output.chunks_exact(8) {
                    let candidate = u64::from_le_bytes(chunk.try_into().expect("word aligned"));
                    if candidate < 18_446_744_069_414_584_321 {
                        if calls[i].output_words.get(accepted_field_words) != Some(&candidate) {
                            return Err(fail("raw ledger canonical field output mismatch"));
                        }
                        accepted_field_words += 1;
                        if accepted_field_words == calls[i].output_words.len() {
                            break;
                        }
                    } else {
                        rejected_field_words += 1;
                    }
                }
            }
            ledger.update((index as u64).to_le_bytes());
            ledger.update((scratch.len() as u64).to_le_bytes());
            ledger.update(&scratch);
            ledger.update(query.output);
            actual_answers.update(query.output);
            framed_key_and_output_bytes += scratch.len() as u64 + 64;
            index += 1;
        }
        if let Some(i) = stream {
            if accepted_field_words != calls[i].output_words.len() {
                return Err(fail("raw ledger field stream ends before requested output"));
            }
            events.push(json!({"kind":"counter_run","field_call_index":i,
                "raw_start":start,"raw_end_exclusive":index,"profile_domain_hex":hex::encode(PROFILE),
                "role_domain_hex":hex::encode(&calls[i].domain),"input_words":calls[i].input_words,
                "counter_start":0,"counter_end_exclusive":count,
                "answer_rule":"SHA512(exact_canonical_key_frame(counter))",
                "actual_answer_sequence_sha512":hex::encode(actual_answers.finalize()),
                "requested_field_words":calls[i].output_words.len(),"raw_digest_call_cap":cap(calls[i].output_words.len()),
                "accepted_field_words_checked":accepted_field_words,"rejected_field_candidates":rejected_field_words,
                "canonical_field_modulus":18446744069414584321u64}));
        } else if let Piece::Single(name, _, _, locator) = piece {
            let query = &queries[start];
            events.push(json!({"kind":"singleton","role":name,"raw_start":start,
                "raw_end_exclusive":index,"profile_domain_hex":hex::encode(PROFILE),
                "role_domain_hex":hex::encode(&query.key.role_domain),"input_words":query.key.words,
                "counter":query.key.counter,"output_sha512":hex::encode(query.output),
                "source_loop_locator_level_and_original_leaf_ordinal":locator}));
        }
    }
    if index != queries.len() || events.len() != 1403 {
        return Err(fail("raw ledger descriptor coverage mismatch"));
    }
    Ok(
        json!({"schema":"hegemon.smze.complete-classical-raw-ledger.v1",
        "execution_kind":"actual classical verifier recomputation under empty-program recorder",
        "relation_role":role,"relation_id":relation_id,"relation_digest_sha512":hex::encode(relation_digest),
        "proof_sha256":hex::encode(Sha256::digest(proof)),"public_words":trace.binding_words,
        "accepted":true,"raw_query_count":queries.len(),"preflight_raw_query_cap":raw_cap,
        "maximum_supported_raw_query_cap":MAX_QUERIES,"field_stream_count":6,
        "preflight_logical_recorder_storage_bytes_upper_bound":preflight_logical_storage_bytes,
        "preflight_memory_bound_excludes_vec_slack_allocator_and_engine_trace":true,
        "singleton_counts":{"strict_leaf":58,"internal_node":1334,"decs":1,"root":1,"fpp":2,"piop":1,"total":1397},
        "framed_key_and_output_bytes_unfactored":framed_key_and_output_bytes,
        "recorder_reserved_vec_bytes":recorder_vec_reserved,
        "recorder_reserved_key_heap_bytes":recorder_key_heaps_reserved,
        "recorder_reserved_bytes_excluding_allocator_and_other_trace_memory":recorder_vec_reserved+recorder_key_heaps_reserved,
        "recorder_is_in_memory_not_streaming":true,"rolling_ledger_sha512":hex::encode(ledger.finalize()),
        "rolling_ledger_grammar":"domain UTF8; each LE64(index)||LE64(frame_len)||frame||answer64; no deduplication",
        "rolling_ledger_domain_hex":hex::encode(ROLLING_DOMAIN),
        "key_frame_grammar":"LE64(profile_len)||profile||LE64(role_len)||role||LE64(word_count)||LE64(words)||LE64(counter)",
        "all_actual_recorded_keys_and_outputs_checked":true,"all_raw_positions_covered_once":true,
        "descriptors":events,"operations":operations,"stage_operations":stages,
        "full_classical_raw_query_ledger":true,"original_adversary_execution_readout":false,
        "F1_original_computational_basis_constructed":false,"recovered_source_assignment":false,
        "changed_role_failure_event_coverage_qualified":false,"shared_qro_composition_qualified":false,
        "efficient_extraction_established":false,"privacy_qualified":false,"production_authorized":false}),
    )
}

pub fn asset_ledger(
    public: &AssetSpendPublic,
    proof: &[u8],
) -> Result<Value, TransactionCircuitError> {
    public.validate_structure()?;
    let matrix_words = match (public.policy_mode, public.credential_depth) {
        (0, 4) => 2_608_480,
        (0, 8) => 2_874_460,
        (0, 16) => 3_406_740,
        (1, 4) => 6_937_380,
        (1, 8) => 7_203_680,
        (1, 16) => 7_735_640,
        _ => {
            return Err(fail(
                "raw ledger supports only the six qualified asset geometries",
            ))
        }
    };
    record(
        &asset::AssetSpendAdapter::from_public(public)?,
        &public.binding_bytes(),
        proof,
        asset::RELATION_ID,
        &asset::relation_digest(),
        "asset",
        matrix_words,
    )
}

pub fn admin_ledger(
    public: &PolicyAdminPublicV1,
    proof: &[u8],
) -> Result<Value, TransactionCircuitError> {
    public.validate_structure()?;
    record(
        &admin::PolicyAdminAdapterV1::from_public(public)?,
        &public.binding_bytes(),
        proof,
        admin::RELATION_ID,
        &admin::relation_digest(),
        "admin",
        57_300,
    )
}
