use std::{cmp::Reverse, fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use superneo_ccs::{Relation, WitnessSchema};
use superneo_hegemon::{NativeTxValidityRelation, TxLeafPublicRelation};
use transaction_core::p3_air::{BASE_TRACE_WIDTH, MIN_TRACE_LENGTH, TRACE_WIDTH};

const SMALLWOOD_MIN_WITNESS_ELEMENTS: usize = 1 << 6;
const SMALLWOOD_MAX_WITNESS_ELEMENTS: usize = 1 << 16;
const SMALLWOOD_FIELD_BYTES_F64: usize = 8;
const SMALLWOOD_NONCE_BYTES: usize = 4;
const SMALLWOOD_PARAM_SEED_BYTES: usize = 32;
const SMALLWOOD_PARAM_SALT_BYTES: usize = 32;
const HEGEMON_RECOMMENDED_SMALLWOOD_OPENED_EVALS: usize = 2;
const HEGEMON_RECOMMENDED_SMALLWOOD_RHO: usize = 2;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[arg(long)]
    json: bool,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
struct SmallWoodWindow {
    min_elements: usize,
    max_elements: usize,
    min_log2: usize,
    max_log2: usize,
}

#[derive(Clone, Debug, Serialize)]
struct ReportSummary {
    credible_next_target: &'static str,
    air_trace_is_too_large: bool,
    native_tx_validity_fits_window: bool,
    tx_leaf_public_fits_window: bool,
    native_tx_validity_padded_elements: usize,
    native_tx_validity_log2_padded: u32,
    native_vs_air_base_raw_shrink_factor: f64,
    native_vs_air_full_raw_shrink_factor: f64,
    recommended_lppc_rows: usize,
    recommended_lppc_packing_factor: usize,
    recommended_lppc_witness_degree: usize,
    official_goldilocks_profiles_require_grinding: bool,
    recommended_next_step: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct AirSurfaceReport {
    label: &'static str,
    rows: usize,
    width: usize,
    raw_elements: usize,
    padded_elements: usize,
    log2_padded_elements: u32,
    fits_smallwood_window: bool,
    overflow_factor_vs_window_max: f64,
    recommendation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct FieldContribution {
    name: &'static str,
    bit_width: u16,
    count: usize,
    total_bits: usize,
}

#[derive(Clone, Debug, Serialize)]
struct RelationSurfaceReport {
    label: &'static str,
    relation_id_hex: String,
    ccs_rows: usize,
    raw_witness_elements: usize,
    raw_witness_bits: usize,
    padded_witness_elements: usize,
    log2_padded_witness_elements: u32,
    fits_smallwood_window: bool,
    field_contributions: Vec<FieldContribution>,
    recommendation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct SmallWoodOfficialGoldilocksProfile {
    label: &'static str,
    source_variant: u32,
    tree_nb_leaves: usize,
    rho: usize,
    nb_opened_evals: usize,
    beta: usize,
    opening_pow_bits: usize,
    decs_nb_opened_evals: usize,
    decs_eta: usize,
    decs_pow_bits: usize,
    uses_grinding: bool,
    release_supported_under_hegemon_rule: bool,
}

#[derive(Clone, Debug, Serialize)]
struct DerivedDegreePoint {
    semantic_constraint_degree: usize,
    masked_polynomial_degree: usize,
    masked_linear_degree: usize,
}

#[derive(Clone, Debug, Serialize)]
struct NativeFrontendCandidate {
    label: String,
    packing_factor: usize,
    raw_witness_elements: usize,
    minimal_row_count: usize,
    recommended_row_count: usize,
    zero_padding_elements: usize,
    witness_polynomial_degree: usize,
    rho: usize,
    nb_opened_evals: usize,
    opened_eval_payload_floor_bytes: usize,
    degree_points: Vec<DerivedDegreePoint>,
    recommendation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct SmallWoodTxShapeReport {
    smallwood_window: SmallWoodWindow,
    summary: ReportSummary,
    air_surfaces: Vec<AirSurfaceReport>,
    relation_surfaces: Vec<RelationSurfaceReport>,
    official_goldilocks_profiles: Vec<SmallWoodOfficialGoldilocksProfile>,
    native_frontend_candidates: Vec<NativeFrontendCandidate>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let report = build_report();
    let output =
        serde_json::to_string_pretty(&report).context("serialize SmallWood tx shape report")?;
    let should_print = cli.json || cli.output.is_none();

    if let Some(path) = cli.output {
        fs::write(&path, output.as_bytes())
            .with_context(|| format!("write SmallWood tx shape report to {}", path.display()))?;
    }

    if should_print {
        println!("{output}");
    }

    Ok(())
}

fn build_report() -> SmallWoodTxShapeReport {
    let air_base = air_surface_report(
        "transaction_air_base_trace",
        MIN_TRACE_LENGTH,
        BASE_TRACE_WIDTH,
        "Do not target SmallWood directly at the current AIR witness; it is far outside the intended regime.",
    );
    let air_full = air_surface_report(
        "transaction_air_full_trace",
        MIN_TRACE_LENGTH,
        TRACE_WIDTH,
        "Do not target SmallWood directly at the current AIR main trace; it is even further outside the intended regime.",
    );

    let tx_leaf_public = relation_surface_report(
        "tx_leaf_public_relation",
        &TxLeafPublicRelation::default(),
        "Fits the SmallWood witness window, but it is only a public bridge around an external STARK receipt and is not a tx-proof replacement target.",
    );
    let native_tx_validity = relation_surface_report(
        "native_tx_validity_relation",
        &NativeTxValidityRelation::default(),
        "Best SmallWood tx-proof spike target: compact enough for the intended regime and directly tied to tx validity witness semantics.",
    );
    let official_goldilocks_profiles = official_goldilocks_profiles();
    let native_frontend_candidates =
        native_frontend_candidates(native_tx_validity.raw_witness_elements);
    let recommended_frontend = native_frontend_candidates
        .iter()
        .find(|candidate| candidate.packing_factor == 8)
        .expect("recommended native frontend candidate present");

    SmallWoodTxShapeReport {
        smallwood_window: SmallWoodWindow {
            min_elements: SMALLWOOD_MIN_WITNESS_ELEMENTS,
            max_elements: SMALLWOOD_MAX_WITNESS_ELEMENTS,
            min_log2: 6,
            max_log2: 16,
        },
        summary: ReportSummary {
            credible_next_target: "native_tx_validity_relation",
            air_trace_is_too_large: !air_base.fits_smallwood_window && !air_full.fits_smallwood_window,
            native_tx_validity_fits_window: native_tx_validity.fits_smallwood_window,
            tx_leaf_public_fits_window: tx_leaf_public.fits_smallwood_window,
            native_tx_validity_padded_elements: native_tx_validity.padded_witness_elements,
            native_tx_validity_log2_padded: native_tx_validity.log2_padded_witness_elements,
            native_vs_air_base_raw_shrink_factor: air_base.raw_elements as f64
                / native_tx_validity.raw_witness_elements as f64,
            native_vs_air_full_raw_shrink_factor: air_full.raw_elements as f64
                / native_tx_validity.raw_witness_elements as f64,
            recommended_lppc_rows: recommended_frontend.recommended_row_count,
            recommended_lppc_packing_factor: recommended_frontend.packing_factor,
            recommended_lppc_witness_degree: recommended_frontend.witness_polynomial_degree,
            official_goldilocks_profiles_require_grinding: official_goldilocks_profiles
                .iter()
                .all(|profile| profile.uses_grinding),
            recommended_next_step:
                "Prototype a no-grinding SmallWood LPPC/PACS frontend with a 512x8 witness matrix for NativeTxValidityRelation semantics, not against TransactionAirP3.",
        },
        air_surfaces: vec![air_base, air_full],
        relation_surfaces: vec![tx_leaf_public, native_tx_validity],
        official_goldilocks_profiles,
        native_frontend_candidates,
    }
}

fn air_surface_report(
    label: &'static str,
    rows: usize,
    width: usize,
    recommendation: &'static str,
) -> AirSurfaceReport {
    let raw_elements = rows.saturating_mul(width);
    let padded_elements = raw_elements.next_power_of_two();
    AirSurfaceReport {
        label,
        rows,
        width,
        raw_elements,
        padded_elements,
        log2_padded_elements: padded_elements.ilog2(),
        fits_smallwood_window: within_smallwood_window(padded_elements),
        overflow_factor_vs_window_max: raw_elements as f64 / SMALLWOOD_MAX_WITNESS_ELEMENTS as f64,
        recommendation,
    }
}

fn relation_surface_report<R>(
    label: &'static str,
    relation: &R,
    recommendation: &'static str,
) -> RelationSurfaceReport
where
    R: Relation<transaction_core::hashing_pq::Felt>,
{
    let shape = relation.shape();
    let raw_witness_elements = shape.witness_schema.total_witness_elements();
    let padded_witness_elements = raw_witness_elements.next_power_of_two();
    RelationSurfaceReport {
        label,
        relation_id_hex: relation.relation_id().to_hex(),
        ccs_rows: shape.num_rows,
        raw_witness_elements,
        raw_witness_bits: shape.witness_schema.total_witness_bits(),
        padded_witness_elements,
        log2_padded_witness_elements: padded_witness_elements.ilog2(),
        fits_smallwood_window: within_smallwood_window(padded_witness_elements),
        field_contributions: field_contributions(&shape.witness_schema),
        recommendation,
    }
}

fn field_contributions(schema: &WitnessSchema) -> Vec<FieldContribution> {
    let mut contributions: Vec<_> = schema
        .fields
        .iter()
        .map(|field| FieldContribution {
            name: field.name,
            bit_width: field.bit_width,
            count: field.count,
            total_bits: field.bit_width as usize * field.count,
        })
        .collect();
    contributions
        .sort_by_key(|field| (Reverse(field.total_bits), Reverse(field.count), field.name));
    contributions
}

fn within_smallwood_window(elements: usize) -> bool {
    (SMALLWOOD_MIN_WITNESS_ELEMENTS..=SMALLWOOD_MAX_WITNESS_ELEMENTS).contains(&elements)
}

fn official_goldilocks_profiles() -> Vec<SmallWoodOfficialGoldilocksProfile> {
    vec![
        SmallWoodOfficialGoldilocksProfile {
            label: "f64_short",
            source_variant: 0,
            tree_nb_leaves: 4096 * 4,
            rho: 2,
            nb_opened_evals: 2,
            beta: 3,
            opening_pow_bits: 4,
            decs_nb_opened_evals: 13,
            decs_eta: 8,
            decs_pow_bits: 7,
            uses_grinding: true,
            release_supported_under_hegemon_rule: false,
        },
        SmallWoodOfficialGoldilocksProfile {
            label: "f64_default",
            source_variant: 1,
            tree_nb_leaves: 4096,
            rho: 2,
            nb_opened_evals: 2,
            beta: 3,
            opening_pow_bits: 4,
            decs_nb_opened_evals: 17,
            decs_eta: 8,
            decs_pow_bits: 6,
            uses_grinding: true,
            release_supported_under_hegemon_rule: false,
        },
        SmallWoodOfficialGoldilocksProfile {
            label: "f64_fast",
            source_variant: 2,
            tree_nb_leaves: 1024,
            rho: 2,
            nb_opened_evals: 2,
            beta: 2,
            opening_pow_bits: 8,
            decs_nb_opened_evals: 24,
            decs_eta: 7,
            decs_pow_bits: 8,
            uses_grinding: true,
            release_supported_under_hegemon_rule: false,
        },
    ]
}

fn native_frontend_candidates(raw_witness_elements: usize) -> Vec<NativeFrontendCandidate> {
    [4usize, 8, 16]
        .into_iter()
        .map(|packing_factor| {
            let minimal_row_count = raw_witness_elements.div_ceil(packing_factor);
            let recommended_row_count = minimal_row_count.next_power_of_two();
            let zero_padding_elements = recommended_row_count * packing_factor - raw_witness_elements;
            let witness_polynomial_degree =
                packing_factor + HEGEMON_RECOMMENDED_SMALLWOOD_OPENED_EVALS - 1;
            let opened_eval_payload_floor_bytes = SMALLWOOD_NONCE_BYTES
                + SMALLWOOD_PARAM_SALT_BYTES
                + SMALLWOOD_PARAM_SEED_BYTES
                + HEGEMON_RECOMMENDED_SMALLWOOD_OPENED_EVALS
                    * (recommended_row_count + 2 * HEGEMON_RECOMMENDED_SMALLWOOD_RHO)
                    * SMALLWOOD_FIELD_BYTES_F64;
            let recommendation = match packing_factor {
                8 => "Recommended first frontend shape: aligns with the current 512-row native relation, keeps witness degree moderate, and stays exactly at padded witness size 4096.",
                4 => "Valid but row-heavy: doubles witness rows relative to the 8-column candidate and increases the opened-evaluation payload floor.",
                16 => "Valid but degree-heavy: halves rows relative to the 8-column candidate, but pushes witness and mask degrees up faster.",
                _ => "Candidate packing factor.",
            };
            NativeFrontendCandidate {
                label: format!("native_tx_validity_{}x{}", recommended_row_count, packing_factor),
                packing_factor,
                raw_witness_elements,
                minimal_row_count,
                recommended_row_count,
                zero_padding_elements,
                witness_polynomial_degree,
                rho: HEGEMON_RECOMMENDED_SMALLWOOD_RHO,
                nb_opened_evals: HEGEMON_RECOMMENDED_SMALLWOOD_OPENED_EVALS,
                opened_eval_payload_floor_bytes,
                degree_points: [2usize, 3, 5]
                    .into_iter()
                    .map(|semantic_constraint_degree| {
                        let masked_polynomial_degree = semantic_constraint_degree
                            * (packing_factor + HEGEMON_RECOMMENDED_SMALLWOOD_OPENED_EVALS - 1)
                            - packing_factor;
                        let masked_linear_degree = (packing_factor
                            + HEGEMON_RECOMMENDED_SMALLWOOD_OPENED_EVALS
                            - 1)
                            + (packing_factor - 1);
                        DerivedDegreePoint {
                            semantic_constraint_degree,
                            masked_polynomial_degree,
                            masked_linear_degree,
                        }
                    })
                    .collect(),
                recommendation,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_air_surfaces_are_outside_smallwood_window() {
        let report = build_report();
        assert!(report
            .air_surfaces
            .iter()
            .all(|surface| !surface.fits_smallwood_window));
        assert_eq!(report.air_surfaces[0].raw_elements, 851_968);
        assert_eq!(report.air_surfaces[1].raw_elements, 1_196_032);
    }

    #[test]
    fn native_tx_validity_relation_fits_smallwood_window() {
        let report = build_report();
        let native = report
            .relation_surfaces
            .iter()
            .find(|surface| surface.label == "native_tx_validity_relation")
            .expect("native tx validity relation present");
        assert!(native.fits_smallwood_window);
        assert_eq!(native.raw_witness_elements, 3_991);
        assert_eq!(native.padded_witness_elements, 4_096);
        assert_eq!(native.raw_witness_bits, 32_787);
        assert_eq!(
            native.field_contributions[0].name,
            "input_merkle_sibling_byte"
        );
        assert_eq!(native.field_contributions[0].count, 3_072);
    }

    #[test]
    fn tx_leaf_public_relation_also_fits_but_is_not_the_target() {
        let report = build_report();
        let tx_leaf = report
            .relation_surfaces
            .iter()
            .find(|surface| surface.label == "tx_leaf_public_relation")
            .expect("tx leaf public relation present");
        assert!(tx_leaf.fits_smallwood_window);
        assert!(tx_leaf.raw_witness_elements < 1_024);
    }

    #[test]
    fn recommends_balanced_native_frontend_shape() {
        let report = build_report();
        assert_eq!(report.summary.recommended_lppc_rows, 512);
        assert_eq!(report.summary.recommended_lppc_packing_factor, 8);
        assert!(report.summary.official_goldilocks_profiles_require_grinding);
        let candidate = report
            .native_frontend_candidates
            .iter()
            .find(|candidate| candidate.packing_factor == 8)
            .expect("8-column candidate present");
        assert_eq!(candidate.minimal_row_count, 499);
        assert_eq!(candidate.recommended_row_count, 512);
        assert_eq!(candidate.zero_padding_elements, 105);
        assert_eq!(candidate.witness_polynomial_degree, 9);
        assert_eq!(candidate.opened_eval_payload_floor_bytes, 8_324);
    }
}
