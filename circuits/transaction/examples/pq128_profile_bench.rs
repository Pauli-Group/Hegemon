use std::time::Instant;

use protocol_versioning::SMALLWOOD_CANDIDATE_VERSION_BINDING;
use serde_json::json;
use transaction_circuit::constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID};
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, spend_auth_key_bytes, Felt};
use transaction_circuit::note::{MerklePath, NoteData};
use transaction_circuit::{
    analyze_smallwood_candidate_profile_for_arithmetization,
    exact_smallwood_candidate_backend_opening_surface_report_from_witness,
    project_smallwood_candidate_lvcs_planner_report_from_witness, InputNoteWitness,
    OutputNoteWitness, SmallwoodArithmetization, SmallwoodNoGrindingProfileV1,
    StablecoinPolicyBinding, TransactionWitness,
};

fn sample_witness() -> TransactionWitness {
    let sk_spend = [42u8; 32];
    let pk_auth = spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 8,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [2u8; 32],
        pk_auth,
        rho: [3u8; 32],
        r: [4u8; 32],
    };
    let input_note_asset = NoteData {
        value: 5,
        asset_id: 1,
        pk_recipient: [5u8; 32],
        pk_auth,
        rho: [6u8; 32],
        r: [7u8; 32],
    };
    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];
    let mut current = merkle_node(leaf0, leaf1);
    for _ in 1..CIRCUIT_MERKLE_DEPTH {
        let zero = [Felt::ZERO; 6];
        siblings0.push(zero);
        siblings1.push(zero);
        current = merkle_node(current, zero);
    }
    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_note_native,
                position: 0,
                rho_seed: [9u8; 32],
                merkle_path: MerklePath {
                    siblings: siblings0,
                },
            },
            InputNoteWitness {
                note: input_note_asset,
                position: 1,
                rho_seed: [8u8; 32],
                merkle_path: MerklePath {
                    siblings: siblings1,
                },
            },
        ],
        outputs: vec![
            OutputNoteWitness {
                note: NoteData {
                    value: 3,
                    asset_id: NATIVE_ASSET_ID,
                    pk_recipient: [11u8; 32],
                    pk_auth: [111u8; 32],
                    rho: [12u8; 32],
                    r: [13u8; 32],
                },
            },
            OutputNoteWitness {
                note: NoteData {
                    value: 5,
                    asset_id: 1,
                    pk_recipient: [21u8; 32],
                    pk_auth: [121u8; 32],
                    rho: [22u8; 32],
                    r: [23u8; 32],
                },
            },
        ],
        ciphertext_hashes: vec![[0u8; 48]; 2],
        sk_spend,
        merkle_root: felts_to_bytes48(&current),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: SMALLWOOD_CANDIDATE_VERSION_BINDING,
    }
}

fn profile(domain: usize, openings: usize) -> SmallwoodNoGrindingProfileV1 {
    SmallwoodNoGrindingProfileV1 {
        rho: 5,
        nb_opened_evals: 5,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: domain,
        decs_nb_opened_evals: openings,
        decs_eta: 5,
        decs_pow_bits: 0,
    }
}

fn median(values: &mut [u128]) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn main() {
    let repeats = std::env::args()
        .nth(1)
        .map(|value| value.parse::<usize>().expect("repetition count"))
        .unwrap_or(3);
    let label_filter = std::env::args().nth(2);
    assert!(repeats > 0);

    let witness = sample_witness();
    let arithmetization = SmallwoodArithmetization::DirectPacked64CompressedLevel5;
    let candidates = [
        ("2pow19-q25", profile(524_288, 25)),
        ("2pow19-q26", profile(524_288, 26)),
        ("active-2pow20-q23", profile(1_048_576, 23)),
        ("2pow21-q21", profile(2_097_152, 21)),
        ("2pow22-q20", profile(4_194_304, 20)),
        ("2pow23-q19", profile(8_388_608, 19)),
    ];

    for (label, candidate) in candidates {
        if label_filter
            .as_deref()
            .is_some_and(|filter| filter != label)
        {
            continue;
        }
        let analysis = analyze_smallwood_candidate_profile_for_arithmetization(
            &witness,
            arithmetization,
            candidate,
        )
        .expect("profile analysis");
        let planners = project_smallwood_candidate_lvcs_planner_report_from_witness(
            &witness,
            arithmetization,
            candidate,
        )
        .expect("LVCS planner analysis");

        let mut elapsed_ms = Vec::with_capacity(repeats);
        let mut exact_bytes = Vec::with_capacity(repeats);
        let mut reports = Vec::with_capacity(repeats);
        for _ in 0..repeats {
            let started = Instant::now();
            let report = exact_smallwood_candidate_backend_opening_surface_report_from_witness(
                &witness,
                arithmetization,
                candidate,
            )
            .expect("canonical candidate proof and verifier round trip");
            elapsed_ms.push(started.elapsed().as_millis());
            exact_bytes.push(report.exact_total_bytes as u128);
            reports.push(report);
        }
        let median_ms = median(&mut elapsed_ms);
        let median_bytes = median(&mut exact_bytes);
        let representative = reports
            .iter()
            .min_by_key(|report| report.exact_total_bytes.abs_diff(median_bytes as usize))
            .expect("at least one report");

        // The conservative rational envelope in SmallWoodBcsQrom is dominated here by
        // 12 * Q^2 * epsilon at Q=2^128. This diagnostic excludes the uninstantiated
        // deployed-hash loss, exactly as the checked Lean numerical theorem does.
        let cms_envelope_at_2pow128_excluding_hash_loss = 12.0
            * 2.0f64.powf(256.0 - analysis.soundness.security_floor_bits)
            + 48.0 * 2.0f64.powi(-128)
            + 2.0 * (candidate.decs_nb_evals as f64).powi(2) * 2.0f64.powi(-512);

        println!(
            "{}",
            serde_json::to_string(&json!({
                "label": label,
                "profile": candidate,
                "projected_total_bytes": analysis.projected_total_bytes,
                "interactive_floor_bits": analysis.soundness.security_floor_bits,
                "cms_envelope_at_2pow128_excluding_hash_loss": cms_envelope_at_2pow128_excluding_hash_loss,
                "conditional_half_success_threshold_met": cms_envelope_at_2pow128_excluding_hash_loss < 0.5,
                "repetitions": repeats,
                "roundtrip_elapsed_ms": elapsed_ms,
                "roundtrip_elapsed_median_ms": median_ms,
                "exact_total_bytes": exact_bytes,
                "exact_total_median_bytes": median_bytes,
                "representative_opening_surface": representative,
                "lvcs_planners": planners,
            }))
            .expect("serialize benchmark record")
        );
    }
}
