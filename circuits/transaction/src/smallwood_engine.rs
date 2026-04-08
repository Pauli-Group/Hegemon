use std::cmp::min;
use std::time::Instant;

use blake3::Hasher;
use getrandom::fill as getrandom_fill;
use p3_field::{Field, PrimeField64};
use p3_goldilocks::Goldilocks;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    error::TransactionCircuitError,
    smallwood_semantics::{compute_constraints_u64, packed_constraint_count, PackedStatement},
};

const FIELD_ORDER: u64 = 0xffff_ffff_0000_0001;
const NEG_ORDER: u64 = FIELD_ORDER.wrapping_neg();
const DIGEST_BYTES: usize = 32;
const DIGEST_WORDS: usize = DIGEST_BYTES / 8;
const SALT_BYTES: usize = 32;
const SALT_WORDS: usize = SALT_BYTES / 8;
const NONCE_BYTES: usize = 4;

const SMALLWOOD_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.f64-xof.v1";
const SMALLWOOD_COMPRESS2_DOMAIN: &[u8] = b"hegemon.smallwood.f64-compress2.v1";

const SMALLWOOD_RHO: usize = 2;
const SMALLWOOD_NB_OPENED_EVALS: usize = 3;
const SMALLWOOD_BETA: usize = 3;
const SMALLWOOD_DECS_NB_EVALS: usize = 16384;
const SMALLWOOD_DECS_NB_OPENED_EVALS: usize = 26;
const SMALLWOOD_DECS_ETA: usize = 3;
const SMALLWOOD_DECS_POW_BITS: u32 = 0;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SmallwoodProof {
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    h_piop: [u8; DIGEST_BYTES],
    piop: PiopProof,
    pcs: PcsProof,
    all_evals: Vec<Vec<u64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PiopProof {
    ppol_highs: Vec<Vec<u64>>,
    plin_highs: Vec<Vec<u64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PcsProof {
    rcombi_tails: Vec<Vec<u64>>,
    subset_evals: Vec<Vec<u64>>,
    partial_evals: Vec<Vec<u64>>,
    decs: DecsProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DecsProof {
    auth_paths: Vec<Vec<[u8; DIGEST_BYTES]>>,
    masking_evals: Vec<Vec<u64>>,
    high_coeffs: Vec<Vec<u64>>,
}

#[derive(Clone, Debug)]
struct SmallwoodConfig {
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    linear_constraint_count: usize,
    witness_size: usize,
    constraint_count: usize,
    wit_poly_degree: usize,
    mpol_poly_degree: usize,
    mlin_poly_degree: usize,
    nb_polys: usize,
    degree: Vec<usize>,
    width: Vec<usize>,
    delta: Vec<usize>,
    nb_unstacked_rows: usize,
    nb_unstacked_cols: usize,
    nb_lvcs_rows: usize,
    nb_lvcs_cols: usize,
    nb_lvcs_opened_combi: usize,
    fullrank_cols: Vec<usize>,
    packing_points: Vec<u64>,
}

#[derive(Clone, Debug)]
struct DecsKey {
    committed_domain_evals: Vec<Vec<u64>>,
    masking_domain_evals: Vec<Vec<u64>>,
    dec_polys: Vec<Vec<u64>>,
    tree_levels: Vec<Vec<[u8; DIGEST_BYTES]>>,
}

#[derive(Clone, Debug)]
struct LvcsKey {
    extended_rows: Vec<Vec<u64>>,
    decs_key: DecsKey,
}

#[derive(Clone, Debug)]
struct PcsKey {
    lvcs_key: LvcsKey,
}

pub(crate) fn prove_candidate(
    witness_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
    binded_data: &[u8],
) -> Result<Vec<u8>, TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let stage_started = Instant::now();
    let mut last_stage = stage_started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(stage_started)
            );
            *last = now;
        }
    };
    let cfg = SmallwoodConfig::new(
        row_count,
        packing_factor,
        constraint_degree as usize,
        linear_constraint_targets.len(),
    )?;
    if trace_enabled {
        eprintln!(
                "[smallwood] cfg rows={} packing={} constraints={} linear_constraints={} nb_polys={} nb_lvcs_rows={} nb_lvcs_cols={} projected_proof_bytes={}",
                cfg.row_count,
                cfg.packing_factor,
                cfg.constraint_count,
                cfg.linear_constraint_count,
                cfg.nb_polys,
                cfg.nb_lvcs_rows,
                cfg.nb_lvcs_cols,
                serialized_proof_size_hint(&cfg)
            );
    }
    let statement = PackedStatement::new(
        row_count,
        packing_factor,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    );
    log_stage("statement", &mut last_stage);
    let binded_words = bytes_to_words(binded_data)?;
    log_stage("binded_words", &mut last_stage);
    let witness_polys = witness_values
        .par_chunks_exact(packing_factor)
        .map(|row_values| {
            poly_interpolate_random(row_values, &cfg.packing_points, SMALLWOOD_NB_OPENED_EVALS)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut mpol_ppoly = Vec::with_capacity(SMALLWOOD_RHO);
    let mut mpol_plin = Vec::with_capacity(SMALLWOOD_RHO);
    for _ in 0..SMALLWOOD_RHO {
        mpol_ppoly.push(random_poly(cfg.mpol_poly_degree)?);
        mpol_plin.push(poly_random_sum_zero(
            &cfg.packing_points,
            cfg.mlin_poly_degree,
        )?);
    }
    log_stage("witness_polys", &mut last_stage);

    let salt = random_bytes::<SALT_BYTES>()?;
    let pcs_key = pcs_commit(&cfg, &witness_polys, &mpol_ppoly, &mpol_plin, &salt)?;
    log_stage("pcs_commit", &mut last_stage);
    let piop = piop_run(
        &cfg,
        &statement,
        &witness_polys,
        &mpol_ppoly,
        &mpol_plin,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        &binded_words,
    )?;
    log_stage("piop_run", &mut last_stage);
    let h_piop = hash_piop_transcript(&piop.transcript_words);
    let nonce = choose_opening_nonce(&cfg.packing_points, &h_piop)?;
    log_stage("opening_nonce", &mut last_stage);
    let eval_points = xof_piop_opening_points(&nonce, &h_piop);
    let (pcs_proof, all_evals) = pcs_open(
        &cfg,
        &pcs_key,
        &witness_polys,
        &mpol_ppoly,
        &mpol_plin,
        &eval_points,
        &h_piop,
    )?;
    log_stage("pcs_open", &mut last_stage);
    let proof = SmallwoodProof {
        salt,
        nonce,
        h_piop,
        piop: piop.proof,
        pcs: pcs_proof,
        all_evals,
    };
    let encoded = bincode::serialize(&proof).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to serialize rust smallwood proof: {err}"
        ))
    })?;
    if trace_enabled {
        eprintln!(
            "[smallwood] serialized proof bytes={} total={:?}",
            encoded.len(),
            stage_started.elapsed()
        );
    }
    Ok(encoded)
}

pub(crate) fn verify_candidate(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    let proof: SmallwoodProof = bincode::deserialize(proof_bytes).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to deserialize rust smallwood proof: {err}"
        ))
    })?;
    let cfg = SmallwoodConfig::new(
        row_count,
        packing_factor,
        constraint_degree as usize,
        linear_constraint_targets.len(),
    )?;
    if proof.all_evals.len() != SMALLWOOD_NB_OPENED_EVALS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof opened evaluation count mismatch",
        ));
    }
    let statement = PackedStatement::new(
        row_count,
        packing_factor,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    );
    validate_proof_shape(&cfg, &proof)?;
    let binded_words = bytes_to_words(binded_data)?;
    let eval_points = xof_piop_opening_points(&proof.nonce, &proof.h_piop);
    ensure_no_packing_collisions(&cfg.packing_points, &eval_points)?;
    let _pcs_transcript = pcs_recompute_transcript(
        &cfg,
        &proof.salt,
        &eval_points,
        &proof.all_evals,
        &proof.pcs,
        &proof.h_piop,
    )?;
    let mut piop_input = pcs_commitment_profile_words();
    piop_input.extend_from_slice(&binded_words);
    let piop_transcript = piop_recompute_transcript(
        &cfg,
        &statement,
        &piop_input,
        &eval_points,
        &proof.all_evals,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        &proof.piop,
    )?;
    let recomputed = hash_piop_transcript(&piop_transcript);
    if recomputed != proof.h_piop {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood piop transcript hash mismatch",
        ));
    }
    Ok(())
}

fn validate_proof_shape(
    cfg: &SmallwoodConfig,
    proof: &SmallwoodProof,
) -> Result<(), TransactionCircuitError> {
    if proof.all_evals.len() != SMALLWOOD_NB_OPENED_EVALS
        || proof.all_evals.iter().any(|row| row.len() != cfg.nb_polys)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof opened evaluation shape mismatch",
        ));
    }
    if proof.piop.ppol_highs.len() != SMALLWOOD_RHO
        || proof
            .piop
            .ppol_highs
            .iter()
            .any(|poly| poly.len() != cfg.mpol_poly_degree + 1 - SMALLWOOD_NB_OPENED_EVALS)
        || proof.piop.plin_highs.len() != SMALLWOOD_RHO
        || proof
            .piop
            .plin_highs
            .iter()
            .any(|poly| poly.len() != cfg.mlin_poly_degree + 1 - (SMALLWOOD_NB_OPENED_EVALS + 1))
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood piop proof shape mismatch",
        ));
    }
    if proof.pcs.rcombi_tails.len() != cfg.nb_lvcs_opened_combi
        || proof
            .pcs
            .rcombi_tails
            .iter()
            .any(|tail| tail.len() != SMALLWOOD_DECS_NB_OPENED_EVALS)
        || proof.pcs.subset_evals.len() != SMALLWOOD_DECS_NB_OPENED_EVALS
        || proof
            .pcs
            .subset_evals
            .iter()
            .any(|row| row.len() != cfg.nb_lvcs_rows)
        || proof.pcs.partial_evals.len() != SMALLWOOD_NB_OPENED_EVALS
        || proof
            .pcs
            .partial_evals
            .iter()
            .any(|row| row.len() != cfg.nb_unstacked_cols - cfg.nb_polys)
        || proof
            .pcs
            .partial_evals
            .iter()
            .flat_map(|row| row.iter())
            .any(|value| *value != 0)
        || proof.pcs.decs.auth_paths.len() != SMALLWOOD_DECS_NB_OPENED_EVALS
        || proof
            .pcs
            .decs
            .auth_paths
            .iter()
            .any(|path| path.len() != SMALLWOOD_DECS_NB_EVALS.ilog2() as usize)
        || proof.pcs.decs.masking_evals.len() != SMALLWOOD_DECS_NB_OPENED_EVALS
        || proof
            .pcs
            .decs
            .masking_evals
            .iter()
            .any(|row| row.len() != SMALLWOOD_DECS_ETA)
        || proof.pcs.decs.high_coeffs.len() != SMALLWOOD_DECS_ETA
        || proof
            .pcs
            .decs
            .high_coeffs
            .iter()
            .any(|poly| poly.len() != cfg.nb_lvcs_cols)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood PCS proof shape mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn projected_candidate_proof_bytes(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    linear_constraint_count: usize,
) -> Result<usize, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(
        row_count,
        packing_factor,
        constraint_degree as usize,
        linear_constraint_count,
    )?;
    Ok(serialized_proof_size_hint(&cfg))
}

struct PiopRunOutput {
    transcript_words: Vec<u64>,
    proof: PiopProof,
}

impl SmallwoodConfig {
    fn new(
        row_count: usize,
        packing_factor: usize,
        constraint_degree: usize,
        linear_constraint_count: usize,
    ) -> Result<Self, TransactionCircuitError> {
        if row_count == 0 || packing_factor == 0 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood row_count and packing_factor must be non-zero",
            ));
        }
        let wit_poly_degree = packing_factor + SMALLWOOD_NB_OPENED_EVALS - 1;
        let mpol_poly_degree =
            constraint_degree * (packing_factor + SMALLWOOD_NB_OPENED_EVALS - 1) - packing_factor;
        let mlin_poly_degree =
            (packing_factor + SMALLWOOD_NB_OPENED_EVALS - 1) + (packing_factor - 1);
        let nb_polys = row_count + 2 * SMALLWOOD_RHO;
        let mut degree = vec![wit_poly_degree; row_count];
        degree.extend(std::iter::repeat_n(mpol_poly_degree, SMALLWOOD_RHO));
        degree.extend(std::iter::repeat_n(mlin_poly_degree, SMALLWOOD_RHO));
        let mut width = Vec::with_capacity(nb_polys);
        let mut delta = Vec::with_capacity(nb_polys);
        let nb_unstacked_rows = packing_factor + SMALLWOOD_NB_OPENED_EVALS;
        let mut nb_unstacked_cols = 0usize;
        for &deg in &degree {
            let w = (deg + 1 - SMALLWOOD_NB_OPENED_EVALS + (packing_factor - 1)) / packing_factor;
            width.push(w);
            let d = (packing_factor * w + SMALLWOOD_NB_OPENED_EVALS) - (deg + 1);
            if w == 1 && d != 0 {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood invalid polynomial width/delta pair for degree {deg}"
                )));
            }
            delta.push(d);
            nb_unstacked_cols += w;
        }
        let nb_lvcs_rows = nb_unstacked_rows * SMALLWOOD_BETA;
        let nb_lvcs_cols = nb_unstacked_cols.div_ceil(SMALLWOOD_BETA);
        let nb_lvcs_opened_combi = SMALLWOOD_BETA * SMALLWOOD_NB_OPENED_EVALS;
        let mut fullrank_cols = Vec::with_capacity(nb_lvcs_opened_combi);
        for i in 0..SMALLWOOD_BETA {
            for j in 0..SMALLWOOD_NB_OPENED_EVALS {
                fullrank_cols.push(i * (packing_factor + SMALLWOOD_NB_OPENED_EVALS) + j);
            }
        }
        let packing_points = (0..packing_factor).map(|i| i as u64).collect();
        Ok(Self {
            row_count,
            packing_factor,
            constraint_degree,
            linear_constraint_count,
            witness_size: row_count * packing_factor,
            constraint_count: packed_constraint_count(),
            wit_poly_degree,
            mpol_poly_degree,
            mlin_poly_degree,
            nb_polys,
            degree,
            width,
            delta,
            nb_unstacked_rows,
            nb_unstacked_cols,
            nb_lvcs_rows,
            nb_lvcs_cols,
            nb_lvcs_opened_combi,
            fullrank_cols,
            packing_points,
        })
    }
}

fn piop_run(
    cfg: &SmallwoodConfig,
    statement: &PackedStatement<'_>,
    witness_polys: &[Vec<u64>],
    mpol_ppoly: &[Vec<u64>],
    mpol_plin: &[Vec<u64>],
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    binded_words: &[u64],
) -> Result<PiopRunOutput, TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let started = Instant::now();
    let mut last = started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood/piop] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(started)
            );
            *last = now;
        }
    };
    let mut in_transcript = pcs_commitment_profile_words();
    in_transcript.extend_from_slice(binded_words);
    let hash_fpp = hash_piop(&in_transcript);
    let gammas = derive_gamma_prime(cfg, &hash_fpp);
    log_stage("derive_gamma_prime", &mut last);
    let in_ppol = get_constraint_polynomials(cfg, statement, witness_polys)?;
    log_stage("constraint_polynomials", &mut last);
    let in_plin = get_constraint_linear_polynomials_batched(
        cfg,
        witness_polys,
        &cfg.packing_points,
        &gammas,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
    )?;
    log_stage("constraint_linear_polynomials", &mut last);
    let vanishing = poly_set_vanishing(&cfg.packing_points);
    let mut transcript_words = Vec::new();
    transcript_words.extend(digest_to_words(&hash_fpp));
    let mut ppol_highs = Vec::with_capacity(SMALLWOOD_RHO);
    let mut plin_highs = Vec::with_capacity(SMALLWOOD_RHO);
    for rep in 0..SMALLWOOD_RHO {
        let mut out_ppol = vec![0u64; cfg.mpol_poly_degree + cfg.packing_factor + 1];
        for (poly, gamma) in in_ppol.iter().zip(gammas[rep].iter()) {
            poly_add_assign_scaled(&mut out_ppol, poly, *gamma);
        }
        for root in &cfg.packing_points {
            out_ppol = poly_remove_one_degree_factor(&out_ppol, *root);
        }
        poly_add_assign(&mut out_ppol, &mpol_ppoly[rep]);

        let mut out_plin = in_plin[rep].clone();
        poly_add_assign(&mut out_plin, &mpol_plin[rep]);

        transcript_words.extend_from_slice(&out_ppol);
        transcript_words.extend_from_slice(&out_plin[1..]);
        ppol_highs.push(out_ppol[SMALLWOOD_NB_OPENED_EVALS..].to_vec());
        plin_highs.push(out_plin[(SMALLWOOD_NB_OPENED_EVALS + 1)..].to_vec());

        let _ = &vanishing;
    }
    log_stage("transcript_assembly", &mut last);
    Ok(PiopRunOutput {
        transcript_words,
        proof: PiopProof {
            ppol_highs,
            plin_highs,
        },
    })
}

fn piop_recompute_transcript(
    cfg: &SmallwoodConfig,
    statement: &PackedStatement<'_>,
    in_transcript: &[u64],
    eval_points: &[u64],
    all_evals: &[Vec<u64>],
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    proof: &PiopProof,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let hash_fpp = hash_piop(in_transcript);
    let gammas = derive_gamma_prime(cfg, &hash_fpp);
    let wit_evals = all_evals
        .iter()
        .map(|row| row[..cfg.row_count].to_vec())
        .collect::<Vec<_>>();
    let meval_ppoly = all_evals
        .iter()
        .map(|row| row[cfg.row_count..cfg.row_count + SMALLWOOD_RHO].to_vec())
        .collect::<Vec<_>>();
    let meval_plin = all_evals
        .iter()
        .map(|row| row[cfg.row_count + SMALLWOOD_RHO..cfg.row_count + 2 * SMALLWOOD_RHO].to_vec())
        .collect::<Vec<_>>();
    let in_epol = get_constraint_polynomial_evals(cfg, statement, eval_points, &wit_evals)?;
    let in_elin = get_constraint_linear_evals(
        cfg,
        eval_points,
        &wit_evals,
        &cfg.packing_points,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
    )?;
    let linear_targets = linear_targets_as_field(statement);
    let mut transcript_words = Vec::new();
    transcript_words.extend(digest_to_words(&hash_fpp));
    let vanishing = poly_set_vanishing(&cfg.packing_points);
    let eval_points_with_zero = {
        let mut v = eval_points.to_vec();
        v.push(0);
        v
    };
    let lag = poly_set_lagrange(&eval_points_with_zero, SMALLWOOD_NB_OPENED_EVALS);
    let mut correction_factor = 0u64;
    for num in 0..cfg.packing_factor {
        correction_factor = add_mod(correction_factor, poly_eval(&lag, cfg.packing_points[num]));
    }
    for rep in 0..SMALLWOOD_RHO {
        let mut out_epol = vec![0u64; SMALLWOOD_NB_OPENED_EVALS];
        for j in 0..SMALLWOOD_NB_OPENED_EVALS {
            let mut acc = 0u64;
            for num in 0..cfg.constraint_count {
                acc = add_mod(acc, mul_mod(in_epol[j][num], gammas[rep][num]));
            }
            let mut denom = 1u64;
            for root in &cfg.packing_points {
                denom = mul_mod(denom, sub_mod(eval_points[j], *root));
            }
            acc = div_mod(acc, denom);
            out_epol[j] = add_mod(acc, meval_ppoly[j][rep]);
        }
        let out_ppol = poly_restore(
            &proof.ppol_highs[rep],
            &out_epol,
            eval_points,
            cfg.mpol_poly_degree,
        )?;

        let mut out_elin = vec![0u64; SMALLWOOD_NB_OPENED_EVALS + 1];
        for j in 0..SMALLWOOD_NB_OPENED_EVALS {
            let mut acc = 0u64;
            for num in 0..cfg.linear_constraint_count {
                acc = add_mod(acc, mul_mod(in_elin[j][num], gammas[rep][num]));
            }
            out_elin[j] = add_mod(acc, meval_plin[j][rep]);
        }
        let mut out_plin = if cfg.mlin_poly_degree > SMALLWOOD_NB_OPENED_EVALS {
            poly_restore(
                &proof.plin_highs[rep],
                &out_elin,
                &eval_points_with_zero,
                cfg.mlin_poly_degree,
            )?
        } else {
            poly_interpolate_generic(&out_elin, &eval_points_with_zero)
        };
        let mut res = 0u64;
        for num in 0..cfg.linear_constraint_count {
            res = add_mod(res, mul_mod(linear_targets[num], gammas[rep][num]));
        }
        for root in &cfg.packing_points {
            res = sub_mod(res, poly_eval(&out_plin, *root));
        }
        res = div_mod(res, correction_factor);
        let scaled_lag = poly_mul_scalar(&lag, res);
        poly_add_assign(&mut out_plin, &scaled_lag);

        let _ = &vanishing;
        transcript_words.extend_from_slice(&out_ppol);
        transcript_words.extend_from_slice(&out_plin[1..]);
    }
    Ok(transcript_words)
}

fn pcs_commit(
    cfg: &SmallwoodConfig,
    witness_polys: &[Vec<u64>],
    mpol_ppoly: &[Vec<u64>],
    mpol_plin: &[Vec<u64>],
    salt: &[u8; SALT_BYTES],
) -> Result<PcsKey, TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let started = Instant::now();
    let mut last = started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood/pcs_commit] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(started)
            );
            *last = now;
        }
    };
    let mut polys = witness_polys.to_vec();
    polys.extend_from_slice(mpol_ppoly);
    polys.extend_from_slice(mpol_plin);

    let mut rows = vec![vec![0u64; cfg.nb_unstacked_cols]; cfg.nb_unstacked_rows];
    let mut offset = 0usize;
    for (j, poly) in polys.iter().enumerate() {
        let width = cfg.width[j];
        let degree = cfg.degree[j];
        let delta = cfg.delta[j];
        let mut ind = 0usize;
        for i in 0..(width - 1) {
            for row in rows.iter_mut().take(cfg.packing_factor) {
                row[offset + i] = poly[ind];
                ind += 1;
            }
        }
        for row in rows.iter_mut().take(cfg.nb_unstacked_rows).skip(delta) {
            row[offset + (width - 1)] = poly[ind];
            ind += 1;
        }
        if width > 1 {
            for open_idx in 0..SMALLWOOD_NB_OPENED_EVALS {
                let rnd = random_vec(width - 1)?;
                let target_row = cfg.packing_factor + open_idx;
                rows[target_row][offset..offset + width - 1].copy_from_slice(&rnd);
                for i in 0..(width - 2) {
                    rows[open_idx][offset + 1 + i] =
                        sub_mod(rows[open_idx][offset + 1 + i], rnd[i]);
                }
                let last_row = delta + open_idx;
                rows[last_row][offset + (width - 1)] =
                    sub_mod(rows[last_row][offset + (width - 1)], rnd[width - 2]);
            }
            for row in rows.iter_mut().take(delta) {
                row[offset + (width - 1)] = 0;
            }
        }
        let _ = degree;
        offset += width;
    }
    log_stage("unstack_rows", &mut last);

    let mut stacked_rows = vec![vec![0u64; cfg.nb_lvcs_cols]; cfg.nb_lvcs_rows];
    for (i, row) in stacked_rows.iter_mut().enumerate() {
        let num_unstacked_row = i % cfg.nb_unstacked_rows;
        let num_unstacked_offset = (i / cfg.nb_unstacked_rows) * cfg.nb_lvcs_cols;
        if num_unstacked_offset < cfg.nb_unstacked_cols {
            let copy = min(
                cfg.nb_lvcs_cols,
                cfg.nb_unstacked_cols - num_unstacked_offset,
            );
            row[..copy].copy_from_slice(
                &rows[num_unstacked_row][num_unstacked_offset..num_unstacked_offset + copy],
            );
        }
    }
    log_stage("stack_rows", &mut last);
    let lvcs_key = lvcs_commit(cfg, &stacked_rows, salt)?;
    log_stage("lvcs_commit", &mut last);
    Ok(PcsKey { lvcs_key })
}

fn pcs_open(
    cfg: &SmallwoodConfig,
    key: &PcsKey,
    witness_polys: &[Vec<u64>],
    mpol_ppoly: &[Vec<u64>],
    mpol_plin: &[Vec<u64>],
    eval_points: &[u64],
    h_piop: &[u8; DIGEST_BYTES],
) -> Result<(PcsProof, Vec<Vec<u64>>), TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let started = Instant::now();
    let mut last = started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood/pcs_open] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(started)
            );
            *last = now;
        }
    };
    let mut polys = witness_polys.to_vec();
    polys.extend_from_slice(mpol_ppoly);
    polys.extend_from_slice(mpol_plin);
    let all_evals = eval_points
        .iter()
        .map(|&point| {
            polys
                .iter()
                .map(|poly| poly_eval(poly, point))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    log_stage("all_evals", &mut last);

    let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.nb_lvcs_opened_combi];
    pcs_build_coefficients(cfg, eval_points, &mut coeffs);
    log_stage("build_coefficients", &mut last);
    let (rcombi_tails, subset_evals, decs_proof) = lvcs_open(cfg, &key.lvcs_key, &coeffs, h_piop)?;
    log_stage("lvcs_open", &mut last);

    // The current verifier does not consume `partial_evals` when recomputing the
    // PCS transcript, so keep the serialized envelope shape but pin the contents
    // to zero and reject any non-zero tampering during verification.
    let partial_evals =
        vec![vec![0u64; cfg.nb_unstacked_cols - cfg.nb_polys]; SMALLWOOD_NB_OPENED_EVALS];
    log_stage("partial_evals", &mut last);

    Ok((
        PcsProof {
            rcombi_tails,
            subset_evals,
            partial_evals,
            decs: decs_proof,
        },
        all_evals,
    ))
}

fn pcs_recompute_transcript(
    cfg: &SmallwoodConfig,
    salt: &[u8; SALT_BYTES],
    eval_points: &[u64],
    all_evals: &[Vec<u64>],
    proof: &PcsProof,
    h_piop: &[u8; DIGEST_BYTES],
) -> Result<Vec<u64>, TransactionCircuitError> {
    let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.nb_lvcs_opened_combi];
    pcs_build_coefficients(cfg, eval_points, &mut coeffs);
    let decs_trans_hash = hash_challenge_opening_decs(cfg, &[], h_piop, &proof.rcombi_tails);
    let (decs_leaf_indexes, _decs_nonce) = xof_decs_opening(
        SMALLWOOD_DECS_NB_EVALS,
        SMALLWOOD_DECS_NB_OPENED_EVALS,
        SMALLWOOD_DECS_POW_BITS,
        &decs_trans_hash,
    )?;
    let decs_eval_points = decs_leaf_indexes
        .iter()
        .map(|&idx| idx as u64)
        .collect::<Vec<_>>();
    let rows = if proof
        .subset_evals
        .first()
        .is_some_and(|row| row.len() == cfg.nb_lvcs_rows)
    {
        proof.subset_evals.clone()
    } else {
        lvcs_recompute_rows(
            cfg,
            &coeffs,
            &proof.rcombi_tails,
            &proof.subset_evals,
            &decs_eval_points,
        )?
    };
    let root_words = decs_recompute_root(cfg, salt, &rows, &decs_eval_points, &proof.decs)?;
    let transcript = decs_commitment_transcript(
        cfg,
        salt,
        &rows,
        &root_words,
        &decs_eval_points,
        &proof.decs,
    )?;
    let lvcs_transcript = digest_to_words(&hash_challenge_opening_decs(
        cfg,
        &rows,
        h_piop,
        &proof.rcombi_tails,
    ));
    let mut pcs_transcript = transcript;
    pcs_transcript.splice(0..0, lvcs_transcript);
    let _ = all_evals;
    Ok(pcs_transcript)
}

fn get_constraint_polynomials(
    cfg: &SmallwoodConfig,
    statement: &PackedStatement<'_>,
    witness_polys: &[Vec<u64>],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let degree = cfg.constraint_degree * cfg.wit_poly_degree;
    let nb_samples = degree + 1;
    let sample_points = (0..nb_samples).map(|i| i as u64).collect::<Vec<_>>();
    let wit_evals = sample_points
        .par_iter()
        .map(|&point| {
            witness_polys
                .iter()
                .map(|poly| poly_eval(poly, point))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let evaluated_constraints = wit_evals
        .par_iter()
        .map(|row| {
            let mut row_constraints = vec![0u64; cfg.constraint_count];
            compute_constraints_u64(statement, row, &mut row_constraints)?;
            Ok::<_, TransactionCircuitError>(row_constraints)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut constraint_evals = vec![vec![0u64; nb_samples]; cfg.constraint_count];
    for (sample_idx, row_constraints) in evaluated_constraints.iter().enumerate() {
        for idx in 0..cfg.constraint_count {
            constraint_evals[idx][sample_idx] = row_constraints[idx];
        }
    }
    constraint_evals
        .par_iter()
        .map(|evals| interpolate_consecutive(evals))
        .collect::<Result<Vec<_>, _>>()
}

fn get_constraint_polynomial_evals(
    cfg: &SmallwoodConfig,
    statement: &PackedStatement<'_>,
    eval_points: &[u64],
    witness_evals: &[Vec<u64>],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut out = vec![vec![0u64; cfg.constraint_count]; eval_points.len()];
    let _ = eval_points;
    for (row_idx, rows) in witness_evals.iter().enumerate() {
        compute_constraints_u64(statement, rows, &mut out[row_idx])?;
    }
    Ok(out)
}

fn get_constraint_linear_polynomials_batched(
    cfg: &SmallwoodConfig,
    witness_polys: &[Vec<u64>],
    packing_points: &[u64],
    gammas: &[Vec<u64>],
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let lag = build_lagrange_basis(cfg.packing_factor, packing_points)?;
    let out_degree = cfg.wit_poly_degree + (cfg.packing_factor - 1);
    (0..SMALLWOOD_RHO)
        .into_par_iter()
        .map(|rep| {
            let mut aggregated = vec![0u64; cfg.witness_size];
            for check in 0..cfg.linear_constraint_count {
                let gamma = gammas[rep][check];
                if gamma == 0 {
                    continue;
                }
                let start = linear_constraint_offsets[check] as usize;
                let end = linear_constraint_offsets[check + 1] as usize;
                for term_idx in start..end {
                    let coeff = linear_constraint_coefficients[term_idx];
                    let idx = linear_constraint_indices[term_idx] as usize;
                    if coeff == 0 || idx >= cfg.witness_size {
                        continue;
                    }
                    aggregated[idx] = add_mod(aggregated[idx], mul_mod(coeff, gamma));
                }
            }
            let mut tmp_out = vec![0u64; out_degree + 1];
            let mut tmp = vec![0u64; out_degree + 1];
            let mut lag_combo = vec![0u64; cfg.packing_factor];
            for row in 0..cfg.row_count {
                let weights = &aggregated[row * cfg.packing_factor..(row + 1) * cfg.packing_factor];
                if weights.iter().all(|weight| *weight == 0) {
                    continue;
                }
                lag_combo.fill(0);
                for col in 0..cfg.packing_factor {
                    let weight = weights[col];
                    if weight != 0 {
                        poly_add_assign_scaled(&mut lag_combo, &lag[col], weight);
                    }
                }
                poly_mul_into(
                    &mut tmp,
                    &witness_polys[row],
                    &lag_combo,
                    cfg.wit_poly_degree,
                    cfg.packing_factor - 1,
                );
                poly_add_assign(&mut tmp_out, &tmp);
            }
            Ok::<_, TransactionCircuitError>(tmp_out)
        })
        .collect::<Result<Vec<_>, _>>()
}

fn get_constraint_linear_evals(
    cfg: &SmallwoodConfig,
    eval_points: &[u64],
    witness_evals: &[Vec<u64>],
    packing_points: &[u64],
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let lag = build_lagrange_basis(cfg.packing_factor, packing_points)?;
    let mut lag_evals = vec![vec![0u64; cfg.packing_factor]; eval_points.len()];
    for (num, &eval_point) in eval_points.iter().enumerate() {
        for col in 0..cfg.packing_factor {
            lag_evals[num][col] = poly_eval(&lag[col], eval_point);
        }
    }
    let mut out = vec![vec![0u64; cfg.linear_constraint_count]; eval_points.len()];
    for num in 0..eval_points.len() {
        for check in 0..cfg.linear_constraint_count {
            let start = linear_constraint_offsets[check] as usize;
            let end = linear_constraint_offsets[check + 1] as usize;
            let mut acc = 0u64;
            for term_idx in start..end {
                let coeff = linear_constraint_coefficients[term_idx];
                let idx = linear_constraint_indices[term_idx] as usize;
                let row = idx / cfg.packing_factor;
                let col = idx % cfg.packing_factor;
                if coeff == 0 || idx >= cfg.witness_size || row >= cfg.row_count {
                    continue;
                }
                let term = mul_mod(witness_evals[num][row], mul_mod(lag_evals[num][col], coeff));
                acc = add_mod(acc, term);
            }
            out[num][check] = acc;
        }
    }
    Ok(out)
}

fn linear_targets_as_field(statement: &PackedStatement<'_>) -> Vec<u64> {
    statement
        .linear_targets()
        .iter()
        .copied()
        .map(canon)
        .collect()
}

fn pcs_build_coefficients(cfg: &SmallwoodConfig, eval_points: &[u64], coeffs: &mut [Vec<u64>]) {
    let m = cfg.packing_factor + SMALLWOOD_NB_OPENED_EVALS;
    for (j, &r) in eval_points.iter().enumerate() {
        let mut powers = vec![0u64; m];
        powers[0] = 1;
        for k in 1..m {
            powers[k] = mul_mod(powers[k - 1], r);
        }
        for k in 0..SMALLWOOD_BETA {
            let row = &mut coeffs[j * SMALLWOOD_BETA + k];
            row.fill(0);
            let start = m * k;
            row[start..start + m].copy_from_slice(&powers);
        }
    }
}

fn lvcs_commit(
    cfg: &SmallwoodConfig,
    rows: &[Vec<u64>],
    salt: &[u8; SALT_BYTES],
) -> Result<LvcsKey, TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let started = Instant::now();
    let mut last = started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood/lvcs_commit] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(started)
            );
            *last = now;
        }
    };
    let mut extended_rows =
        vec![vec![0u64; cfg.nb_lvcs_cols + SMALLWOOD_DECS_NB_OPENED_EVALS]; cfg.nb_lvcs_rows];
    for row in 0..cfg.nb_lvcs_rows {
        extended_rows[row][..cfg.nb_lvcs_cols].copy_from_slice(&rows[row]);
        let rnd = random_vec(SMALLWOOD_DECS_NB_OPENED_EVALS)?;
        extended_rows[row][cfg.nb_lvcs_cols..].copy_from_slice(&rnd);
    }
    log_stage("extend_rows", &mut last);
    let rotated_rows = extended_rows
        .par_iter()
        .map(|row| rotate_left_words(row, cfg.nb_lvcs_cols))
        .collect::<Vec<_>>();
    let decs_key = decs_commit(
        cfg.nb_lvcs_rows,
        cfg.nb_lvcs_cols + SMALLWOOD_DECS_NB_OPENED_EVALS - 1,
        &rotated_rows,
        salt,
    )?;
    log_stage("decs_commit", &mut last);
    Ok(LvcsKey {
        extended_rows,
        decs_key,
    })
}

fn lvcs_open(
    cfg: &SmallwoodConfig,
    key: &LvcsKey,
    coeffs: &[Vec<u64>],
    h_piop: &[u8; DIGEST_BYTES],
) -> Result<(Vec<Vec<u64>>, Vec<Vec<u64>>, DecsProof), TransactionCircuitError> {
    let mut extended_combis = vec![
        vec![0u64; cfg.nb_lvcs_cols + SMALLWOOD_DECS_NB_OPENED_EVALS];
        cfg.nb_lvcs_opened_combi
    ];
    mat_mul(
        &mut extended_combis,
        coeffs,
        &key.extended_rows,
        cfg.nb_lvcs_opened_combi,
        cfg.nb_lvcs_rows,
        cfg.nb_lvcs_cols + SMALLWOOD_DECS_NB_OPENED_EVALS,
    );
    let mut rcombi_tails = Vec::with_capacity(cfg.nb_lvcs_opened_combi);
    for combi in &extended_combis {
        rcombi_tails.push(combi[cfg.nb_lvcs_cols..].to_vec());
    }
    let trans_hash = hash_challenge_opening_decs(cfg, &[], h_piop, &rcombi_tails);
    let (leaves_indexes, nonce) = xof_decs_opening(
        SMALLWOOD_DECS_NB_EVALS,
        SMALLWOOD_DECS_NB_OPENED_EVALS,
        SMALLWOOD_DECS_POW_BITS,
        &trans_hash,
    )?;
    let eval_points = leaves_indexes
        .iter()
        .map(|&idx| idx as u64)
        .collect::<Vec<_>>();
    let mut evals = vec![vec![0u64; cfg.nb_lvcs_rows]; SMALLWOOD_DECS_NB_OPENED_EVALS];
    let decs_proof = decs_open(
        cfg.nb_lvcs_rows,
        cfg.nb_lvcs_cols + SMALLWOOD_DECS_NB_OPENED_EVALS - 1,
        &key.decs_key,
        &eval_points,
        &mut evals,
        nonce,
    )?;

    Ok((rcombi_tails, evals, decs_proof))
}

fn lvcs_recompute_rows(
    cfg: &SmallwoodConfig,
    coeffs: &[Vec<u64>],
    rcombi_tails: &[Vec<u64>],
    subset_evals: &[Vec<u64>],
    eval_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut extended_combis = vec![
        vec![0u64; cfg.nb_lvcs_cols + SMALLWOOD_DECS_NB_OPENED_EVALS];
        cfg.nb_lvcs_opened_combi
    ];
    for k in 0..cfg.nb_lvcs_opened_combi {
        extended_combis[k][..cfg.nb_lvcs_cols].fill(0);
        extended_combis[k][cfg.nb_lvcs_cols..].copy_from_slice(&rcombi_tails[k]);
    }
    let mut combi_polys = Vec::with_capacity(cfg.nb_lvcs_opened_combi);
    for combi in &extended_combis {
        let rotated = rotate_left_words(combi, cfg.nb_lvcs_cols);
        combi_polys.push(interpolate_consecutive(&rotated)?);
    }
    let mut coeffs_part1 = vec![vec![0u64; cfg.nb_lvcs_opened_combi]; cfg.nb_lvcs_opened_combi];
    let mut coeffs_part2 =
        vec![vec![0u64; cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi]; cfg.nb_lvcs_opened_combi];
    for j in 0..cfg.nb_lvcs_opened_combi {
        let mut ind = 0usize;
        for k in 0..cfg.nb_lvcs_rows {
            if ind < cfg.nb_lvcs_opened_combi && cfg.fullrank_cols[ind] == k {
                coeffs_part1[j][ind] = coeffs[j][k];
                ind += 1;
            } else {
                coeffs_part2[j][k - ind] = coeffs[j][k];
            }
        }
    }
    let coeffs_part1_inv = mat_inv(&coeffs_part1)?;
    let mut evals = vec![vec![0u64; cfg.nb_lvcs_rows]; subset_evals.len()];
    for j in 0..subset_evals.len() {
        let q = combi_polys
            .iter()
            .map(|poly| poly_eval(poly, eval_points[j]))
            .collect::<Vec<_>>();
        let tmp = mat_vec_mul_owned(&coeffs_part2, &subset_evals[j]);
        let rhs = q
            .iter()
            .zip(tmp.iter())
            .map(|(&a, &b)| sub_mod(a, b))
            .collect::<Vec<_>>();
        let res = mat_vec_mul_owned(&coeffs_part1_inv, &rhs);
        let mut ind = 0usize;
        for k in 0..cfg.nb_lvcs_rows {
            if ind < cfg.nb_lvcs_opened_combi && cfg.fullrank_cols[ind] == k {
                evals[j][k] = res[ind];
                ind += 1;
            } else {
                evals[j][k] = subset_evals[j][k - ind];
            }
        }
    }
    Ok(evals)
}

fn decs_commit(
    nb_polys: usize,
    poly_degree: usize,
    initial_domain_evals: &[Vec<u64>],
    salt: &[u8; SALT_BYTES],
) -> Result<DecsKey, TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let started = Instant::now();
    let mut last = started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood/decs_commit] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(started)
            );
            *last = now;
        }
    };
    let masking_polys = (0..SMALLWOOD_DECS_ETA)
        .map(|_| random_poly(poly_degree))
        .collect::<Result<Vec<_>, _>>()?;
    log_stage("masking_polys", &mut last);
    let committed_domain_evals = initial_domain_evals
        .par_iter()
        .map(|evals| extend_consecutive_evals(evals, SMALLWOOD_DECS_NB_EVALS))
        .collect::<Vec<_>>();
    let masking_domain_evals = masking_polys
        .par_iter()
        .map(|poly| evaluate_poly_on_consecutive_domain(poly, SMALLWOOD_DECS_NB_EVALS))
        .collect::<Vec<_>>();
    log_stage("domain_evals", &mut last);
    let salt_words = bytes_to_words_unchecked(salt);
    let mut tree_levels = vec![vec![[0u8; DIGEST_BYTES]; SMALLWOOD_DECS_NB_EVALS]];
    tree_levels[0] = (0..SMALLWOOD_DECS_NB_EVALS)
        .into_par_iter()
        .map(|leaf_idx| {
            hash_merkle_leave_from_tables(
                &salt_words,
                &committed_domain_evals,
                &masking_domain_evals,
                leaf_idx,
            )
        })
        .collect();
    log_stage("leaf_hashes", &mut last);
    let root = merkle_build_levels(&mut tree_levels);
    log_stage("merkle_tree", &mut last);
    let hash_mt = hash_merkle_root(salt, &root);
    let gamma_all = derive_decs_challenge(nb_polys, &hash_mt);
    log_stage("challenge", &mut last);
    let initial_len = poly_degree + 1;
    let mut combined_domain_evals = vec![vec![0u64; initial_len]; SMALLWOOD_DECS_ETA];
    mat_mul(
        &mut combined_domain_evals,
        &gamma_all,
        initial_domain_evals,
        SMALLWOOD_DECS_ETA,
        nb_polys,
        initial_len,
    );
    let dec_polys = combined_domain_evals
        .par_iter()
        .enumerate()
        .map(|(k, evals)| {
            let mut poly = interpolate_consecutive(evals)?;
            poly_add_assign(&mut poly, &masking_polys[k]);
            Ok::<_, TransactionCircuitError>(poly)
        })
        .collect::<Result<Vec<_>, _>>()?;
    log_stage("dec_polys", &mut last);
    Ok(DecsKey {
        committed_domain_evals,
        masking_domain_evals,
        dec_polys,
        tree_levels,
    })
}

fn decs_open(
    nb_polys: usize,
    poly_degree: usize,
    key: &DecsKey,
    eval_points: &[u64],
    evals_out: &mut [Vec<u64>],
    nonce: [u8; NONCE_BYTES],
) -> Result<DecsProof, TransactionCircuitError> {
    let indices = eval_points.iter().map(|&x| x as usize).collect::<Vec<_>>();
    let mut auth_paths = Vec::with_capacity(indices.len());
    let mut masking_evals = Vec::with_capacity(indices.len());
    for (j, &idx) in indices.iter().enumerate() {
        evals_out[j] = key
            .committed_domain_evals
            .iter()
            .map(|poly| poly[idx])
            .collect();
        masking_evals.push(
            key.masking_domain_evals
                .iter()
                .map(|poly| poly[idx])
                .collect::<Vec<_>>(),
        );
        auth_paths.push(merkle_auth_path(&key.tree_levels, idx));
    }
    let high_coeffs = key
        .dec_polys
        .iter()
        .map(|poly| poly[SMALLWOOD_DECS_NB_OPENED_EVALS..].to_vec())
        .collect::<Vec<_>>();
    let _ = (nb_polys, poly_degree, nonce);
    Ok(DecsProof {
        auth_paths,
        masking_evals,
        high_coeffs,
    })
}

fn decs_recompute_root(
    cfg: &SmallwoodConfig,
    salt: &[u8; SALT_BYTES],
    evals: &[Vec<u64>],
    eval_points: &[u64],
    proof: &DecsProof,
) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
    let mut root = None;
    for j in 0..eval_points.len() {
        let mut leaf_evals = evals[j].clone();
        leaf_evals.extend_from_slice(&proof.masking_evals[j]);
        let leaf = hash_merkle_leave(cfg.nb_lvcs_rows, &leaf_evals, salt);
        let computed = merkle_compute_root(eval_points[j] as usize, &leaf, &proof.auth_paths[j]);
        match root {
            Some(current) if current != computed => {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood decs root mismatch across opened leaves",
                ));
            }
            None => root = Some(computed),
            _ => {}
        }
    }
    root.ok_or(TransactionCircuitError::ConstraintViolation(
        "smallwood decs root recomputation missing",
    ))
}

fn decs_commitment_transcript(
    cfg: &SmallwoodConfig,
    salt: &[u8; SALT_BYTES],
    evals: &[Vec<u64>],
    root_words: &[u8; DIGEST_BYTES],
    eval_points: &[u64],
    proof: &DecsProof,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let hash_mt = hash_merkle_root(salt, root_words);
    let gamma_all = derive_decs_challenge(cfg.nb_lvcs_rows, &hash_mt);
    let mut transcript = Vec::new();
    transcript.extend(digest_to_words(&hash_mt));
    for k in 0..SMALLWOOD_DECS_ETA {
        let mut dec_evals = vec![0u64; SMALLWOOD_DECS_NB_OPENED_EVALS];
        for i in 0..SMALLWOOD_DECS_NB_OPENED_EVALS {
            let mut acc = 0u64;
            for j in 0..cfg.nb_lvcs_rows {
                acc = add_mod(acc, mul_mod(evals[i][j], gamma_all[k][j]));
            }
            acc = add_mod(acc, proof.masking_evals[i][k]);
            dec_evals[i] = acc;
        }
        let dec_poly = poly_restore(
            &proof.high_coeffs[k],
            &dec_evals,
            eval_points,
            cfg.nb_lvcs_cols + SMALLWOOD_DECS_NB_OPENED_EVALS - 1,
        )?;
        transcript.extend_from_slice(&dec_poly);
    }
    Ok(transcript)
}

fn hash_piop(words: &[u64]) -> [u8; DIGEST_BYTES] {
    words_xof(words, DIGEST_WORDS)
}

fn hash_piop_transcript(words: &[u64]) -> [u8; DIGEST_BYTES] {
    words_xof(words, DIGEST_WORDS)
}

fn hash_challenge_opening_decs(
    cfg: &SmallwoodConfig,
    rows: &[Vec<u64>],
    h_piop: &[u8; DIGEST_BYTES],
    rcombi_tails: &[Vec<u64>],
) -> [u8; DIGEST_BYTES] {
    let mut input = Vec::new();
    input.extend_from_slice(&digest_to_words(h_piop));
    if rcombi_tails.is_empty() {
        for row in rows {
            input.extend_from_slice(row);
        }
    } else {
        for k in 0..cfg.nb_lvcs_opened_combi {
            input.extend(std::iter::repeat_n(0u64, cfg.nb_lvcs_cols));
            input.extend_from_slice(&rcombi_tails[k]);
        }
    }
    words_xof(&input, DIGEST_WORDS)
}

fn hash_merkle_leave(
    _nb_polys: usize,
    evals: &[u64],
    salt: &[u8; SALT_BYTES],
) -> [u8; DIGEST_BYTES] {
    let mut input = Vec::with_capacity(SALT_WORDS + evals.len());
    input.extend(bytes_to_words_unchecked(salt));
    input.extend_from_slice(evals);
    words_xof(&input, DIGEST_WORDS)
}

fn hash_merkle_leave_from_tables(
    salt_words: &[u64],
    committed_domain_evals: &[Vec<u64>],
    masking_domain_evals: &[Vec<u64>],
    leaf_idx: usize,
) -> [u8; DIGEST_BYTES] {
    let word_len =
        (salt_words.len() + committed_domain_evals.len() + masking_domain_evals.len()) as u64;
    let mut hasher = Hasher::new();
    hasher.update(SMALLWOOD_XOF_DOMAIN);
    hasher.update(&word_len.to_le_bytes());
    for word in salt_words {
        hasher.update(&word.to_le_bytes());
    }
    for poly in committed_domain_evals {
        hasher.update(&poly[leaf_idx].to_le_bytes());
    }
    for poly in masking_domain_evals {
        hasher.update(&poly[leaf_idx].to_le_bytes());
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; DIGEST_BYTES];
    for chunk in out.chunks_exact_mut(8) {
        let mut buf = [0u8; 16];
        reader.fill(&mut buf);
        let word = (u128::from_le_bytes(buf) % FIELD_ORDER as u128) as u64;
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn hash_merkle_root(salt: &[u8; SALT_BYTES], root: &[u8; DIGEST_BYTES]) -> [u8; DIGEST_BYTES] {
    let mut input = Vec::with_capacity(SALT_WORDS + DIGEST_WORDS);
    input.extend(bytes_to_words_unchecked(salt));
    input.extend(digest_to_words(root));
    words_xof(&input, DIGEST_WORDS)
}

fn derive_decs_challenge(nb_polys: usize, hash_mt: &[u8; DIGEST_BYTES]) -> Vec<Vec<u64>> {
    let gamma_words = words_xof_vec(&digest_to_words(hash_mt), SMALLWOOD_DECS_ETA);
    let mut out = vec![vec![0u64; nb_polys]; SMALLWOOD_DECS_ETA];
    for k in 0..SMALLWOOD_DECS_ETA {
        out[k][0] = gamma_words[k];
        for j in 1..nb_polys {
            out[k][j] = mul_mod(out[k][j - 1], gamma_words[k]);
        }
    }
    out
}

fn derive_gamma_prime(cfg: &SmallwoodConfig, hash_fpp: &[u8; DIGEST_BYTES]) -> Vec<Vec<u64>> {
    let nb_max_constraints = cfg.constraint_count.max(cfg.linear_constraint_count);
    let gamma_words = words_xof_vec(
        &digest_to_words(hash_fpp),
        (SMALLWOOD_RHO + 1) + (SMALLWOOD_RHO + 1) * SMALLWOOD_RHO,
    );
    let mut mat_rnd = vec![vec![0u64; SMALLWOOD_RHO + 1]; SMALLWOOD_RHO];
    let mut mat_powers = vec![vec![0u64; nb_max_constraints]; SMALLWOOD_RHO + 1];
    for k in 0..SMALLWOOD_RHO {
        for j in 0..(SMALLWOOD_RHO + 1) {
            mat_rnd[k][j] = gamma_words[k * (SMALLWOOD_RHO + 1) + j];
        }
    }
    for k in 0..(SMALLWOOD_RHO + 1) {
        let base = gamma_words[SMALLWOOD_RHO * (SMALLWOOD_RHO + 1) + k];
        mat_powers[k][0] = 1;
        for j in 1..nb_max_constraints {
            mat_powers[k][j] = mul_mod(mat_powers[k][j - 1], base);
        }
    }
    let mut out = vec![vec![0u64; nb_max_constraints]; SMALLWOOD_RHO];
    mat_mul(
        &mut out,
        &mat_rnd,
        &mat_powers,
        SMALLWOOD_RHO,
        SMALLWOOD_RHO + 1,
        nb_max_constraints,
    );
    out
}

fn choose_opening_nonce(
    packing_points: &[u64],
    h_piop: &[u8; DIGEST_BYTES],
) -> Result<[u8; NONCE_BYTES], TransactionCircuitError> {
    let mut counter = 0u32;
    loop {
        let nonce = counter.to_le_bytes();
        let eval_points = xof_piop_opening_points(&nonce, h_piop);
        if opening_points_are_valid(packing_points, &eval_points) {
            return Ok(nonce);
        }
        counter = counter
            .checked_add(1)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood opening nonce overflow",
            ))?;
    }
}

fn serialized_proof_size_hint(cfg: &SmallwoodConfig) -> usize {
    let proof = SmallwoodProof {
        salt: [0u8; SALT_BYTES],
        nonce: [0u8; NONCE_BYTES],
        h_piop: [0u8; DIGEST_BYTES],
        piop: PiopProof {
            ppol_highs: vec![
                vec![0u64; cfg.mpol_poly_degree + 1 - SMALLWOOD_NB_OPENED_EVALS];
                SMALLWOOD_RHO
            ],
            plin_highs: vec![
                vec![0u64; cfg.mlin_poly_degree + 1 - (SMALLWOOD_NB_OPENED_EVALS + 1)];
                SMALLWOOD_RHO
            ],
        },
        pcs: PcsProof {
            rcombi_tails: vec![
                vec![0u64; SMALLWOOD_DECS_NB_OPENED_EVALS];
                cfg.nb_lvcs_opened_combi
            ],
            subset_evals: vec![vec![0u64; cfg.nb_lvcs_rows]; SMALLWOOD_DECS_NB_OPENED_EVALS],
            partial_evals: vec![
                vec![0u64; cfg.nb_unstacked_cols - cfg.nb_polys];
                SMALLWOOD_NB_OPENED_EVALS
            ],
            decs: DecsProof {
                auth_paths: vec![
                    vec![[0u8; DIGEST_BYTES]; SMALLWOOD_DECS_NB_EVALS.ilog2() as usize];
                    SMALLWOOD_DECS_NB_OPENED_EVALS
                ],
                masking_evals: vec![vec![0u64; SMALLWOOD_DECS_ETA]; SMALLWOOD_DECS_NB_OPENED_EVALS],
                high_coeffs: vec![vec![0u64; cfg.nb_lvcs_cols]; SMALLWOOD_DECS_ETA],
            },
        },
        all_evals: vec![vec![0u64; cfg.nb_polys]; SMALLWOOD_NB_OPENED_EVALS],
    };
    bincode::serialize(&proof)
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

fn ensure_no_packing_collisions(
    packing_points: &[u64],
    eval_points: &[u64],
) -> Result<(), TransactionCircuitError> {
    if !opening_points_are_valid(packing_points, eval_points) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood opening points must be distinct and outside the packing domain",
        ));
    }
    Ok(())
}

fn opening_points_are_valid(packing_points: &[u64], eval_points: &[u64]) -> bool {
    for (idx, point) in eval_points.iter().enumerate() {
        if packing_points.iter().any(|packing| packing == point) {
            return false;
        }
        if eval_points[..idx].iter().any(|seen| seen == point) {
            return false;
        }
    }
    true
}

fn xof_piop_opening_points(nonce: &[u8; NONCE_BYTES], h_piop: &[u8; DIGEST_BYTES]) -> Vec<u64> {
    let mut input = Vec::with_capacity(1 + DIGEST_WORDS);
    input.push(u32::from_le_bytes(*nonce) as u64);
    input.extend(digest_to_words(h_piop));
    words_xof_vec(&input, SMALLWOOD_NB_OPENED_EVALS)
}

fn xof_decs_opening(
    nb_evals: usize,
    nb_opened_evals: usize,
    pow_bits: u32,
    trans_hash: &[u8; DIGEST_BYTES],
) -> Result<(Vec<u32>, [u8; NONCE_BYTES]), TransactionCircuitError> {
    let log2_order = 63.999999f64;
    let log2_nb_evals = (nb_evals as f64).log2();
    let maxi = ((log2_order / log2_nb_evals) - 0.001).floor() as usize;
    let mut delta_opening_size = 0usize;
    loop {
        let opening_challenge_size = nb_opened_evals.div_ceil(maxi) + delta_opening_size;
        let min_queries = nb_opened_evals / opening_challenge_size;
        let max_queries = nb_opened_evals.div_ceil(opening_challenge_size);
        let nb_at_max = nb_opened_evals % opening_challenge_size;
        let mut nb_queries = vec![0usize; opening_challenge_size];
        let mut additional_bits = vec![0u32; opening_challenge_size];
        let mut current_w = 0f64;
        for i in 0..opening_challenge_size {
            nb_queries[i] = if i < nb_at_max {
                max_queries
            } else {
                min_queries
            };
            let exact = log2_order - (nb_queries[i] as f64) * log2_nb_evals;
            additional_bits[i] = exact.floor() as u32;
            current_w += exact - additional_bits[i] as f64;
        }
        let mut ind = 0usize;
        let mut can_continue = true;
        while current_w < pow_bits as f64 {
            let missing = (pow_bits as f64 - current_w).floor() as u32;
            let add_w = missing.min(additional_bits[ind]);
            current_w += add_w as f64;
            additional_bits[ind] -= add_w;
            ind += 1;
            if current_w < pow_bits as f64 && ind >= opening_challenge_size {
                can_continue = false;
                delta_opening_size += 1;
                break;
            }
        }
        if !can_continue {
            continue;
        }
        let mut max_keep = vec![0u64; opening_challenge_size];
        let mut acc = nb_evals as u64;
        for _ in 1..min_queries {
            acc = mul_mod(acc, nb_evals as u64);
        }
        for i in nb_at_max..opening_challenge_size {
            let mut value = acc;
            value = (value << additional_bits[i]) % FIELD_ORDER;
            max_keep[i] = if value == 0 {
                FIELD_ORDER - 1
            } else {
                value - 1
            };
        }
        if nb_at_max > 0 {
            acc = mul_mod(acc, nb_evals as u64);
            for i in 0..nb_at_max {
                let mut value = acc;
                value = (value << additional_bits[i]) % FIELD_ORDER;
                max_keep[i] = if value == 0 {
                    FIELD_ORDER - 1
                } else {
                    value - 1
                };
            }
        }
        let mut nonce_counter = 0u32;
        loop {
            let nonce = nonce_counter.to_le_bytes();
            let mut input = Vec::with_capacity(1 + DIGEST_WORDS);
            input.push(u32::from_le_bytes(nonce) as u64);
            input.extend(digest_to_words(trans_hash));
            let lhash_output = words_xof_vec(&input, opening_challenge_size);
            if lhash_output
                .iter()
                .zip(max_keep.iter())
                .all(|(&value, &limit)| value <= limit)
            {
                let mut leaves_indexes = vec![0u32; nb_opened_evals];
                let mut ind = 0usize;
                for i in 0..opening_challenge_size {
                    let mut value = lhash_output[i];
                    for _ in 0..nb_queries[i] {
                        leaves_indexes[ind] = (value % nb_evals as u64) as u32;
                        value /= nb_evals as u64;
                        ind += 1;
                    }
                }
                leaves_indexes.sort_unstable();
                if leaves_indexes.windows(2).all(|pair| pair[0] != pair[1]) {
                    return Ok((leaves_indexes, nonce));
                }
            }
            nonce_counter = nonce_counter.checked_add(1).ok_or(
                TransactionCircuitError::ConstraintViolation(
                    "smallwood decs opening nonce overflow",
                ),
            )?;
        }
    }
}

fn pcs_commitment_profile_words() -> Vec<u64> {
    Vec::new()
}

fn bytes_to_words(bytes: &[u8]) -> Result<Vec<u64>, TransactionCircuitError> {
    if bytes.len() % 8 != 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood binded_data must be padded to 8-byte words",
        ));
    }
    Ok(bytes_to_words_unchecked(bytes))
}

fn bytes_to_words_unchecked(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(chunk);
            u64::from_le_bytes(buf)
        })
        .collect()
}

fn digest_to_words(bytes: &[u8; DIGEST_BYTES]) -> Vec<u64> {
    bytes_to_words_unchecked(bytes)
}

fn words_to_digest(words: &[u64]) -> [u8; DIGEST_BYTES] {
    let mut out = [0u8; DIGEST_BYTES];
    for (idx, word) in words.iter().enumerate().take(DIGEST_WORDS) {
        out[idx * 8..(idx + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn words_xof(words: &[u64], out_words: usize) -> [u8; DIGEST_BYTES] {
    words_to_digest(&words_xof_vec(words, out_words))
}

fn words_xof_vec(words: &[u64], out_words: usize) -> Vec<u64> {
    if out_words == 4 && words.len() <= 8 {
        let mut padded = [0u64; 8];
        for (idx, word) in words.iter().enumerate() {
            padded[idx] = *word;
        }
        return compress2_words(&padded).to_vec();
    }
    let mut hasher = Hasher::new();
    hasher.update(SMALLWOOD_XOF_DOMAIN);
    hasher.update(&(words.len() as u64).to_le_bytes());
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u64; out_words];
    for slot in &mut out {
        let mut buf = [0u8; 16];
        reader.fill(&mut buf);
        *slot = (u128::from_le_bytes(buf) % FIELD_ORDER as u128) as u64;
    }
    out
}

fn compress2_words(words: &[u64; 8]) -> [u64; 4] {
    let mut hasher = Hasher::new();
    hasher.update(SMALLWOOD_COMPRESS2_DOMAIN);
    hasher.update(&(words.len() as u64).to_le_bytes());
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u64; 4];
    for slot in &mut out {
        let mut buf = [0u8; 16];
        reader.fill(&mut buf);
        *slot = (u128::from_le_bytes(buf) % FIELD_ORDER as u128) as u64;
    }
    out
}

fn merkle_build_levels(levels: &mut Vec<Vec<[u8; DIGEST_BYTES]>>) -> [u8; DIGEST_BYTES] {
    let mut current = levels[0].clone();
    while current.len() > 1 {
        let mut parents = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let mut input = Vec::with_capacity(pair.len() * DIGEST_WORDS);
            for child in pair {
                input.extend(digest_to_words(child));
            }
            parents.push(words_xof(&input, DIGEST_WORDS));
        }
        levels.push(parents.clone());
        current = parents;
    }
    current[0]
}

fn merkle_auth_path(
    levels: &[Vec<[u8; DIGEST_BYTES]>],
    mut index: usize,
) -> Vec<[u8; DIGEST_BYTES]> {
    let mut path = Vec::with_capacity(levels.len().saturating_sub(1));
    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        let sibling = if index % 2 == 0 {
            min(index + 1, level.len() - 1)
        } else {
            index - 1
        };
        path.push(level[sibling]);
        index /= 2;
    }
    path
}

fn merkle_compute_root(
    mut index: usize,
    leaf: &[u8; DIGEST_BYTES],
    path: &[[u8; DIGEST_BYTES]],
) -> [u8; DIGEST_BYTES] {
    let mut current = *leaf;
    for sibling in path {
        let mut input = Vec::with_capacity(2 * DIGEST_WORDS);
        if index % 2 == 0 {
            input.extend(digest_to_words(&current));
            input.extend(digest_to_words(sibling));
        } else {
            input.extend(digest_to_words(sibling));
            input.extend(digest_to_words(&current));
        }
        current = words_xof(&input, DIGEST_WORDS);
        index /= 2;
    }
    current
}

fn rotate_left_words(values: &[u64], by: usize) -> Vec<u64> {
    let n = values.len();
    let by = by % n;
    values[by..]
        .iter()
        .chain(values[..by].iter())
        .copied()
        .collect()
}

fn poly_interpolate_random(
    evals: &[u64],
    eval_points: &[u64],
    nb_random: usize,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let rnd = random_vec(nb_random)?;
    poly_restore(&rnd, evals, eval_points, evals.len() + nb_random - 1)
}

fn poly_random_sum_zero(
    eval_points: &[u64],
    degree: usize,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let mut p = vec![0u64; degree + 1];
    let rnd = random_vec(degree)?;
    p[1..].copy_from_slice(&rnd);
    let mut acc = 0u64;
    let mut factor = 0u64;
    for &point in eval_points {
        acc = add_mod(acc, poly_eval(&p, point));
        factor = add_mod(factor, 1);
    }
    p[0] = div_mod(neg_mod(acc), factor);
    Ok(p)
}

fn poly_eval(poly: &[u64], point: u64) -> u64 {
    let mut acc = *poly.last().unwrap_or(&0);
    for coeff in poly.iter().rev().skip(1) {
        acc = add_mod(mul_mod(acc, point), *coeff);
    }
    acc
}

fn evaluate_poly_on_consecutive_domain(poly: &[u64], total_len: usize) -> Vec<u64> {
    let initial_len = poly.len();
    let initial = (0..initial_len)
        .map(|point| poly_eval(poly, point as u64))
        .collect::<Vec<_>>();
    extend_consecutive_evals(&initial, total_len)
}

fn extend_consecutive_evals(initial: &[u64], total_len: usize) -> Vec<u64> {
    if initial.is_empty() || total_len == 0 {
        return Vec::new();
    }
    let keep = total_len.min(initial.len());
    if total_len <= initial.len() {
        return initial[..keep].to_vec();
    }
    let mut work = initial.to_vec();
    let mut diffs = Vec::with_capacity(initial.len());
    diffs.push(work[0]);
    for order in 1..initial.len() {
        for idx in 0..(initial.len() - order) {
            work[idx] = sub_mod(work[idx + 1], work[idx]);
        }
        diffs.push(work[0]);
    }
    let mut out = Vec::with_capacity(total_len);
    out.push(diffs[0]);
    for _ in 1..total_len {
        for idx in (0..diffs.len() - 1).rev() {
            diffs[idx] = add_mod(diffs[idx], diffs[idx + 1]);
        }
        out.push(diffs[0]);
    }
    out
}

fn poly_interpolate_generic(evals: &[u64], eval_points: &[u64]) -> Vec<u64> {
    let degree = evals.len() - 1;
    let mut p = vec![0u64; degree + 1];
    for i in 0..evals.len() {
        let mut lag = vec![0u64; degree + 1];
        lag[0] = 1;
        let mut acc = 1u64;
        for j in 0..evals.len() {
            if j == i {
                continue;
            }
            lag = poly_mul_linear_normalized(&lag, eval_points[j]);
            acc = mul_mod(acc, sub_mod(eval_points[i], eval_points[j]));
        }
        let scale = div_mod(evals[i], acc);
        poly_add_assign_scaled(&mut p, &lag, scale);
    }
    p
}

fn interpolate_consecutive(evals: &[u64]) -> Result<Vec<u64>, TransactionCircuitError> {
    let n = evals.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut dd = evals.to_vec();
    for order in 1..n {
        let inv = inv_mod(order as u64)?;
        for i in (order..n).rev() {
            dd[i] = mul_mod(sub_mod(dd[i], dd[i - 1]), inv);
        }
    }
    let mut poly = vec![0u64; n];
    let mut basis = vec![1u64];
    for (k, coeff) in dd.iter().enumerate() {
        poly_add_assign_scaled(&mut poly, &basis, *coeff);
        if k + 1 < n {
            basis = poly_mul_linear_normalized(&basis, k as u64);
        }
    }
    Ok(poly)
}

fn poly_set_vanishing(roots: &[u64]) -> Vec<u64> {
    let mut vanishing = vec![1u64];
    for root in roots {
        vanishing = poly_mul_linear_normalized(&vanishing, *root);
    }
    vanishing
}

fn poly_set_lagrange(points: &[u64], ind: usize) -> Vec<u64> {
    let degree = points.len() - 1;
    let mut lag = vec![0u64; degree + 1];
    lag[0] = 1;
    let mut acc = 1u64;
    for (j, point) in points.iter().enumerate() {
        if j == ind {
            continue;
        }
        lag = poly_mul_linear_normalized(&lag, *point);
        acc = mul_mod(acc, sub_mod(points[ind], *point));
    }
    let scale = div_mod(1, acc);
    poly_mul_scalar(&lag, scale)
}

fn build_lagrange_basis(
    packing_factor: usize,
    packing_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut out = Vec::with_capacity(packing_factor);
    let consecutive = points_are_consecutive(packing_points);
    for j in 0..packing_factor {
        let evals = (0..packing_factor)
            .map(|idx| if idx == j { 1 } else { 0 })
            .collect::<Vec<_>>();
        out.push(if consecutive {
            interpolate_consecutive(&evals)?
        } else {
            poly_interpolate_generic(&evals, packing_points)
        });
    }
    Ok(out)
}

fn poly_remove_one_degree_factor(poly: &[u64], root: u64) -> Vec<u64> {
    let in_degree = poly.len() - 1;
    let mut out = vec![0u64; in_degree];
    out[in_degree - 1] = poly[in_degree];
    for i in (0..(in_degree - 1)).rev() {
        out[i] = add_mod(poly[i + 1], mul_mod(root, out[i + 1]));
    }
    out
}

fn poly_restore(
    high: &[u64],
    evals: &[u64],
    eval_points: &[u64],
    degree: usize,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let nb_evals = evals.len();
    let mut shifted = vec![0u64; nb_evals];
    for i in 0..nb_evals {
        let mut pow_eval = eval_points[i];
        for _ in 0..(nb_evals - 1) {
            pow_eval = mul_mod(pow_eval, eval_points[i]);
        }
        let shift = mul_mod(poly_eval(high, eval_points[i]), pow_eval);
        shifted[i] = sub_mod(evals[i], shift);
    }
    let mut p = vec![0u64; degree + 1];
    let low = if points_are_consecutive(eval_points) {
        interpolate_consecutive(&shifted)?
    } else {
        poly_interpolate_generic(&shifted, eval_points)
    };
    p[..nb_evals].copy_from_slice(&low);
    p[nb_evals..].copy_from_slice(high);
    Ok(p)
}

fn points_are_consecutive(points: &[u64]) -> bool {
    points
        .iter()
        .enumerate()
        .all(|(idx, point)| *point == idx as u64)
}

fn poly_mul_linear_normalized(poly: &[u64], root: u64) -> Vec<u64> {
    let degree = poly.len() - 1;
    let mut out = vec![0u64; degree + 2];
    let neg_root = neg_mod(root);
    out[degree + 1] = poly[degree];
    for i in 0..degree {
        let idx = degree - i;
        out[idx] = add_mod(poly[idx - 1], mul_mod(neg_root, poly[idx]));
    }
    out[0] = mul_mod(neg_root, poly[0]);
    out
}

fn poly_mul_scalar(poly: &[u64], scalar: u64) -> Vec<u64> {
    poly.iter().map(|&c| mul_mod(c, scalar)).collect()
}

fn poly_mul_into(out: &mut [u64], a: &[u64], b: &[u64], degree_a: usize, degree_b: usize) {
    out.fill(0);
    let degree_c = degree_a + degree_b;
    for num in 0..=degree_c {
        let mut acc = 0u64;
        for i in 0..=min(num, degree_a) {
            let j = num - i;
            if j > degree_b {
                continue;
            }
            acc = add_mod(acc, mul_mod(a[i], b[j]));
        }
        out[num] = acc;
    }
}

fn poly_add_assign(dst: &mut [u64], src: &[u64]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = add_mod(*d, *s);
    }
}

fn poly_add_assign_scaled(dst: &mut [u64], src: &[u64], scalar: u64) {
    if scalar == 0 {
        return;
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = add_mod(*d, mul_mod(*s, scalar));
    }
}

fn mat_mul(c: &mut [Vec<u64>], a: &[Vec<u64>], b: &[Vec<u64>], m: usize, n: usize, p: usize) {
    for i in 0..m {
        for k in 0..p {
            let mut acc = 0u64;
            for j in 0..n {
                acc = add_mod(acc, mul_mod(a[i][j], b[j][k]));
            }
            c[i][k] = acc;
        }
    }
}

fn mat_vec_mul_owned(a: &[Vec<u64>], b: &[u64]) -> Vec<u64> {
    let mut out = vec![0u64; a.len()];
    for i in 0..a.len() {
        let mut acc = 0u64;
        for j in 0..b.len() {
            acc = add_mod(acc, mul_mod(a[i][j], b[j]));
        }
        out[i] = acc;
    }
    out
}

fn mat_inv(a: &[Vec<u64>]) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let n = a.len();
    let mut a_copy = a.to_vec();
    let mut inv = vec![vec![0u64; n]; n];
    for i in 0..n {
        inv[i][i] = 1;
    }
    for i in 0..n {
        let mut pivot = i;
        while pivot < n && a_copy[pivot][i] == 0 {
            pivot += 1;
        }
        if pivot == n {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood matrix inversion failed",
            ));
        }
        if pivot != i {
            a_copy.swap(i, pivot);
            inv.swap(i, pivot);
        }
        let inv_pivot = inv_mod(a_copy[i][i])?;
        for j in 0..n {
            a_copy[i][j] = mul_mod(a_copy[i][j], inv_pivot);
            inv[i][j] = mul_mod(inv[i][j], inv_pivot);
        }
        for k in 0..n {
            if k == i {
                continue;
            }
            let factor = a_copy[k][i];
            if factor == 0 {
                continue;
            }
            for j in 0..n {
                a_copy[k][j] = sub_mod(a_copy[k][j], mul_mod(a_copy[i][j], factor));
                inv[k][j] = sub_mod(inv[k][j], mul_mod(inv[i][j], factor));
            }
        }
    }
    Ok(inv)
}

fn random_poly(degree: usize) -> Result<Vec<u64>, TransactionCircuitError> {
    random_vec(degree + 1)
}

fn random_vec(size: usize) -> Result<Vec<u64>, TransactionCircuitError> {
    let mut bytes = vec![0u8; size * 8];
    getrandom_fill(&mut bytes).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood random generation failed: {err}"
        ))
    })?;
    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(chunk);
            canon(u64::from_le_bytes(buf))
        })
        .collect())
}

fn random_bytes<const N: usize>() -> Result<[u8; N], TransactionCircuitError> {
    let mut out = [0u8; N];
    getrandom_fill(&mut out).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood random byte generation failed: {err}"
        ))
    })?;
    Ok(out)
}

#[inline]
fn canon(x: u64) -> u64 {
    let mut c = x;
    if c >= FIELD_ORDER {
        c -= FIELD_ORDER;
    }
    c
}

#[inline(always)]
fn add_mod(a: u64, b: u64) -> u64 {
    let (sum, over) = a.overflowing_add(b);
    let (mut sum, over) = sum.overflowing_add(u64::from(over) * NEG_ORDER);
    if over {
        sum = sum.wrapping_add(NEG_ORDER);
    }
    sum
}

#[inline(always)]
fn sub_mod(a: u64, b: u64) -> u64 {
    let (diff, under) = a.overflowing_sub(b);
    let (mut diff, under) = diff.overflowing_sub(u64::from(under) * NEG_ORDER);
    if under {
        diff = diff.wrapping_sub(NEG_ORDER);
    }
    diff
}

#[inline(always)]
fn mul_mod(a: u64, b: u64) -> u64 {
    reduce128((a as u128) * (b as u128))
}

#[inline]
fn neg_mod(a: u64) -> u64 {
    let canonical = canon(a);
    if canonical == 0 {
        0
    } else {
        FIELD_ORDER - canonical
    }
}

fn inv_mod(a: u64) -> Result<u64, TransactionCircuitError> {
    Goldilocks::new(a)
        .try_inverse()
        .map(|value| value.as_canonical_u64())
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood inversion of zero",
        ))
}

#[inline]
fn div_mod(a: u64, b: u64) -> u64 {
    mul_mod(a, inv_mod(b).expect("non-zero divisor"))
}

#[inline(always)]
fn reduce128(x: u128) -> u64 {
    let x_lo = x as u64;
    let x_hi = (x >> 64) as u64;
    let x_hi_hi = x_hi >> 32;
    let x_hi_lo = x_hi & NEG_ORDER;

    let (mut t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
    if borrow {
        t0 = t0.wrapping_sub(NEG_ORDER);
    }
    let t1 = x_hi_lo.wrapping_mul(NEG_ORDER);
    add_no_canonicalize_trashing_input(t0, t1)
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
    unsafe {
        let res_wrapped: u64;
        let adjustment: u64;
        core::arch::asm!(
            "add {0}, {1}",
            "sbb {1:e}, {1:e}",
            inlateout(reg) x => res_wrapped,
            inlateout(reg) y => adjustment,
            options(pure, nomem, nostack),
        );
        res_wrapped.wrapping_add(adjustment)
    }
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
    let (res_wrapped, carry) = x.overflowing_add(y);
    res_wrapped.wrapping_add(NEG_ORDER.wrapping_mul(u64::from(carry)))
}
