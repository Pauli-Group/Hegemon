use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet};

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use transaction_circuit::{
    smallwood_no_grinding_profile_for_arithmetization, SmallwoodArithmetization,
    SmallwoodConstraintAdapter, SmallwoodLinearConstraintForm, SmallwoodNoGrindingProfileV1,
    SmallwoodProofTraceV1, SmallwoodTranscriptBackend, TransactionCircuitError, DIGEST_BYTES,
    NONCE_BYTES,
};
use transaction_core::poseidon2::{poseidon2_permutation, Felt};

const FIELD_ORDER: u64 = 0xffff_ffff_0000_0001;
const SMALLWOOD_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.f64-xof.v1";
const SMALLWOOD_POSEIDON2_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.poseidon2-xof.v1";
const SMALLWOOD_POSEIDON2_RATE: usize = 6;
const DIGEST_WORDS: usize = DIGEST_BYTES / 8;
const SALT_BYTES: usize = 32;
const SALT_WORDS: usize = SALT_BYTES / 8;

#[derive(Clone, Debug)]
pub struct SmallwoodConfig {
    profile: SmallwoodNoGrindingProfileV1,
    row_count: usize,
    packing_factor: usize,
    linear_constraint_count: usize,
    witness_size: usize,
    constraint_count: usize,
    mpol_poly_degree: usize,
    mlin_poly_degree: usize,
    nb_polys: usize,
    width: Vec<usize>,
    delta: Vec<usize>,
    nb_unstacked_cols: usize,
    nb_lvcs_rows: usize,
    nb_lvcs_cols: usize,
    nb_lvcs_opened_combi: usize,
    fullrank_cols: Vec<usize>,
    packing_points: Vec<u64>,
}

fn validate_identity_witness_form(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_size: usize,
    linear_constraint_count: usize,
) -> Result<(), TransactionCircuitError> {
    if statement.linear_constraint_form() != SmallwoodLinearConstraintForm::IdentityWitness {
        return Ok(());
    }
    if linear_constraint_count != witness_size {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "identity witness linear constraints must cover the full witness: constraints={} witness_size={witness_size}",
            linear_constraint_count
        )));
    }
    if statement.linear_targets().len() != linear_constraint_count {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "identity witness linear target count mismatch: targets={} constraints={linear_constraint_count}",
            statement.linear_targets().len()
        )));
    }
    let offsets = statement.linear_constraint_offsets();
    let indices = statement.linear_constraint_indices();
    let coefficients = statement.linear_constraint_coefficients();
    if offsets.len() != linear_constraint_count + 1
        || indices.len() != linear_constraint_count
        || coefficients.len() != linear_constraint_count
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "identity witness linear metadata length mismatch",
        ));
    }
    for check in 0..linear_constraint_count {
        if offsets[check] as usize != check
            || offsets[check + 1] as usize != check + 1
            || indices[check] as usize != check
            || coefficients[check] != 1
        {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "identity witness linear metadata mismatch at constraint {check}"
            )));
        }
    }
    Ok(())
}

impl SmallwoodConfig {
    pub fn new(
        statement: &(dyn SmallwoodConstraintAdapter + Sync),
    ) -> Result<Self, TransactionCircuitError> {
        Self::new_with_profile(
            statement,
            smallwood_no_grinding_profile_for_arithmetization(statement.arithmetization()),
        )
    }

    pub fn new_with_profile(
        statement: &(dyn SmallwoodConstraintAdapter + Sync),
        profile: SmallwoodNoGrindingProfileV1,
    ) -> Result<Self, TransactionCircuitError> {
        let row_count = statement.row_count();
        let packing_factor = statement.packing_factor();
        let constraint_degree = statement.constraint_degree();
        let linear_constraint_count = statement.linear_constraint_count();
        let constraint_count = statement.constraint_count();
        if row_count == 0 || packing_factor == 0 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood row_count and packing_factor must be non-zero",
            ));
        }
        let witness_size = row_count * packing_factor;
        validate_identity_witness_form(statement, witness_size, linear_constraint_count)?;
        if profile.rho == 0
            || profile.nb_opened_evals == 0
            || profile.beta == 0
            || profile.decs_nb_evals == 0
            || !profile.decs_nb_evals.is_power_of_two()
            || profile.decs_nb_opened_evals == 0
            || profile.decs_eta == 0
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood profile parameters must be non-zero and use a power-of-two DECS domain",
            ));
        }
        let wit_poly_degree = packing_factor + profile.nb_opened_evals - 1;
        let mpol_poly_degree =
            constraint_degree * (packing_factor + profile.nb_opened_evals - 1) - packing_factor;
        let mlin_poly_degree =
            (packing_factor + profile.nb_opened_evals - 1) + (packing_factor - 1);
        let nb_polys = row_count + 2 * profile.rho;
        let mut degree = vec![wit_poly_degree; row_count];
        degree.extend(std::iter::repeat_n(mpol_poly_degree, profile.rho));
        degree.extend(std::iter::repeat_n(mlin_poly_degree, profile.rho));
        let mut width = Vec::with_capacity(nb_polys);
        let mut delta = Vec::with_capacity(nb_polys);
        let nb_unstacked_rows = packing_factor + profile.nb_opened_evals;
        let mut nb_unstacked_cols = 0usize;
        for &deg in &degree {
            let w = (deg + 1 - profile.nb_opened_evals + (packing_factor - 1)) / packing_factor;
            width.push(w);
            let d = (packing_factor * w + profile.nb_opened_evals) - (deg + 1);
            if w == 1 && d != 0 {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood invalid polynomial width/delta pair for degree {deg}"
                )));
            }
            delta.push(d);
            nb_unstacked_cols += w;
        }
        let nb_lvcs_rows = nb_unstacked_rows * profile.beta;
        let nb_lvcs_cols = nb_unstacked_cols.div_ceil(profile.beta);
        let nb_lvcs_opened_combi = profile.beta * profile.nb_opened_evals;
        let mut fullrank_cols = Vec::with_capacity(nb_lvcs_opened_combi);
        for i in 0..profile.beta {
            for j in 0..profile.nb_opened_evals {
                fullrank_cols.push(i * (packing_factor + profile.nb_opened_evals) + j);
            }
        }
        let packing_points = (0..packing_factor).map(|i| i as u64).collect();
        Ok(Self {
            profile,
            row_count,
            packing_factor,
            linear_constraint_count,
            witness_size,
            constraint_count,
            mpol_poly_degree,
            mlin_poly_degree,
            nb_polys,
            width,
            delta,
            nb_unstacked_cols,
            nb_lvcs_rows,
            nb_lvcs_cols,
            nb_lvcs_opened_combi,
            fullrank_cols,
            packing_points,
        })
    }

    pub fn packing_points_v1(&self) -> &[u64] {
        &self.packing_points
    }

    pub fn nb_lvcs_rows_v1(&self) -> usize {
        self.nb_lvcs_rows
    }

    pub fn nb_lvcs_opened_combi_v1(&self) -> usize {
        self.nb_lvcs_opened_combi
    }

    pub fn profile_v1(&self) -> SmallwoodNoGrindingProfileV1 {
        self.profile
    }

    #[inline]
    fn rho(&self) -> usize {
        self.profile.rho
    }

    #[inline]
    fn nb_opened_evals(&self) -> usize {
        self.profile.nb_opened_evals
    }

    #[inline]
    fn beta(&self) -> usize {
        self.profile.beta
    }

    #[inline]
    fn decs_nb_evals(&self) -> usize {
        self.profile.decs_nb_evals
    }

    #[inline]
    fn decs_nb_opened_evals(&self) -> usize {
        self.profile.decs_nb_opened_evals
    }

    #[inline]
    fn decs_eta(&self) -> usize {
        self.profile.decs_eta
    }
}

pub fn ensure_row_polynomial_arithmetization(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<(), TransactionCircuitError> {
    match statement.arithmetization() {
        SmallwoodArithmetization::Bridge64V1
        | SmallwoodArithmetization::DirectPacked64V1
        | SmallwoodArithmetization::DirectPacked64CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked128CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked16CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked32CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked64CompactBindingsSkipInitialMdsV1
        | SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1 => {
            Ok(())
        }
    }
}

pub fn validate_proof_shape(
    cfg: &SmallwoodConfig,
    proof_trace: &SmallwoodProofTraceV1,
) -> Result<(), TransactionCircuitError> {
    if proof_trace.opened_witness_row_scalars.len() != cfg.nb_opened_evals()
        || proof_trace
            .opened_witness_row_scalars
            .iter()
            .any(|row| row.len() != cfg.nb_polys)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof opened evaluation shape mismatch",
        ));
    }
    if proof_trace.auxiliary_witness_limb_count > proof_trace.auxiliary_witness_words.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood auxiliary witness limb count exceeds proof-carried words",
        ));
    }
    if proof_trace.auxiliary_witness_words[proof_trace.auxiliary_witness_limb_count..]
        .iter()
        .any(|&word| word != 0)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood auxiliary witness padding must be zero",
        ));
    }
    if proof_trace.piop_ppol_highs_v1().len() != cfg.rho()
        || proof_trace
            .piop_ppol_highs_v1()
            .iter()
            .any(|poly| poly.len() != cfg.mpol_poly_degree + 1 - cfg.nb_opened_evals())
        || proof_trace.piop_plin_highs_v1().len() != cfg.rho()
        || proof_trace
            .piop_plin_highs_v1()
            .iter()
            .any(|poly| poly.len() != cfg.mlin_poly_degree + 1 - (cfg.nb_opened_evals() + 1))
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood piop proof shape mismatch",
        ));
    }
    if proof_trace.pcs_rcombi_tails_v1().len() != cfg.nb_lvcs_opened_combi
        || proof_trace
            .pcs_rcombi_tails_v1()
            .iter()
            .any(|tail| tail.len() != cfg.decs_nb_opened_evals())
        || proof_trace.pcs_subset_evals_v1().len() != cfg.decs_nb_opened_evals()
        || proof_trace
            .pcs_subset_evals_v1()
            .iter()
            .any(|row| row.len() != cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi)
        || proof_trace.pcs_partial_evals_v1().len() != cfg.nb_opened_evals()
        || proof_trace
            .pcs_partial_evals_v1()
            .iter()
            .any(|row| row.len() != cfg.nb_unstacked_cols - cfg.nb_polys)
        || proof_trace.decs_auth_paths_v1().len() != cfg.decs_nb_opened_evals()
        || proof_trace
            .decs_auth_paths_v1()
            .iter()
            .any(|path| path.is_empty() || path.len() > cfg.decs_nb_evals().ilog2() as usize)
        || proof_trace.decs_masking_evals_v1().len() != cfg.decs_nb_opened_evals()
        || proof_trace
            .decs_masking_evals_v1()
            .iter()
            .any(|row| row.len() != cfg.decs_eta())
        || proof_trace.decs_high_coeffs_v1().len() != cfg.decs_eta()
        || proof_trace
            .decs_high_coeffs_v1()
            .iter()
            .any(|poly| poly.len() != cfg.nb_lvcs_cols)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood PCS proof shape mismatch",
        ));
    }
    Ok(())
}

fn poseidon2_domain_words(domain: &[u8]) -> Vec<u64> {
    let mut words = Vec::with_capacity(1 + domain.len().div_ceil(8));
    words.push(domain.len() as u64);
    for chunk in domain.chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        words.push(u64::from_le_bytes(word));
    }
    words
}

fn transcript_xof_words(
    backend: SmallwoodTranscriptBackend,
    domain: &[u8],
    words: &[u64],
    out_words: usize,
) -> Vec<u64> {
    match backend {
        SmallwoodTranscriptBackend::Poseidon2 => {
            let mut state = [Felt::ZERO; transaction_core::constants::POSEIDON2_WIDTH];
            let poseidon_domain = match domain {
                SMALLWOOD_XOF_DOMAIN => SMALLWOOD_POSEIDON2_XOF_DOMAIN,
                _ => SMALLWOOD_POSEIDON2_XOF_DOMAIN,
            };
            let mut absorb = poseidon2_domain_words(poseidon_domain);
            absorb.push(words.len() as u64);
            absorb.extend_from_slice(words);
            absorb.push(1);
            for chunk in absorb.chunks(SMALLWOOD_POSEIDON2_RATE) {
                for (idx, word) in chunk.iter().enumerate() {
                    state[idx] += Felt::from_u64(canon(*word));
                }
                poseidon2_permutation(&mut state);
            }
            let mut out = Vec::with_capacity(out_words);
            while out.len() < out_words {
                for elem in state.iter().take(SMALLWOOD_POSEIDON2_RATE) {
                    if out.len() == out_words {
                        break;
                    }
                    out.push(elem.as_canonical_u64());
                }
                if out.len() < out_words {
                    poseidon2_permutation(&mut state);
                }
            }
            out
        }
        SmallwoodTranscriptBackend::Blake3 => {
            panic!("block-recursion local verifier only supports Poseidon2")
        }
    }
}

fn transcript_xof_digest(
    backend: SmallwoodTranscriptBackend,
    domain: &[u8],
    words: &[u64],
) -> [u8; DIGEST_BYTES] {
    words_to_digest(&transcript_xof_words(backend, domain, words, DIGEST_WORDS))
}

pub fn hash_piop_transcript(
    words: &[u64],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    transcript_xof_digest(transcript_backend, SMALLWOOD_XOF_DOMAIN, words)
}

pub fn hash_challenge_opening_decs(
    cfg: &SmallwoodConfig,
    combi_heads: &[Vec<u64>],
    h_piop: &[u8; DIGEST_BYTES],
    rcombi_tails: &[Vec<u64>],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    let mut input = Vec::new();
    input.extend_from_slice(&digest_to_words(h_piop));
    for k in 0..cfg.nb_lvcs_opened_combi {
        input.extend_from_slice(&combi_heads[k]);
        input.extend_from_slice(&rcombi_tails[k]);
    }
    transcript_xof_digest(transcript_backend, SMALLWOOD_XOF_DOMAIN, &input)
}

pub fn derive_gamma_prime(
    cfg: &SmallwoodConfig,
    hash_fpp: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Vec<Vec<u64>> {
    let nb_max_constraints = cfg.constraint_count.max(cfg.linear_constraint_count);
    let gamma_words = transcript_xof_words(
        transcript_backend,
        SMALLWOOD_XOF_DOMAIN,
        &digest_to_words(hash_fpp),
        (cfg.rho() + 1) + (cfg.rho() + 1) * cfg.rho(),
    );
    let mut mat_rnd = vec![vec![0u64; cfg.rho() + 1]; cfg.rho()];
    let mut mat_powers = vec![vec![0u64; nb_max_constraints]; cfg.rho() + 1];
    for k in 0..cfg.rho() {
        for j in 0..(cfg.rho() + 1) {
            mat_rnd[k][j] = gamma_words[k * (cfg.rho() + 1) + j];
        }
    }
    for k in 0..(cfg.rho() + 1) {
        let base = gamma_words[cfg.rho() * (cfg.rho() + 1) + k];
        mat_powers[k][0] = 1;
        for j in 1..nb_max_constraints {
            mat_powers[k][j] = mul_mod(mat_powers[k][j - 1], base);
        }
    }
    let mut out = vec![vec![0u64; nb_max_constraints]; cfg.rho()];
    mat_mul(
        &mut out,
        &mat_rnd,
        &mat_powers,
        cfg.rho(),
        cfg.rho() + 1,
        nb_max_constraints,
    );
    out
}

pub fn ensure_no_packing_collisions(
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

pub fn xof_piop_opening_points(
    cfg: &SmallwoodConfig,
    nonce: &[u8; NONCE_BYTES],
    h_piop: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Vec<u64> {
    let mut input = Vec::with_capacity(1 + DIGEST_WORDS);
    input.push(u32::from_le_bytes(*nonce) as u64);
    input.extend(digest_to_words(h_piop));
    transcript_xof_words(
        transcript_backend,
        SMALLWOOD_XOF_DOMAIN,
        &input,
        cfg.nb_opened_evals(),
    )
}

pub fn xof_decs_opening(
    nb_evals: usize,
    nb_opened_evals: usize,
    pow_bits: u32,
    trans_hash: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
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
            let lhash_output = transcript_xof_words(
                transcript_backend,
                SMALLWOOD_XOF_DOMAIN,
                &input,
                opening_challenge_size,
            );
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

pub fn pcs_build_coefficients(cfg: &SmallwoodConfig, eval_points: &[u64], coeffs: &mut [Vec<u64>]) {
    let m = cfg.packing_factor + cfg.nb_opened_evals();
    for (j, &r) in eval_points.iter().enumerate() {
        let mut powers = vec![0u64; m];
        powers[0] = 1;
        for k in 1..m {
            powers[k] = mul_mod(powers[k - 1], r);
        }
        for k in 0..cfg.beta() {
            let row = &mut coeffs[j * cfg.beta() + k];
            row.fill(0);
            let start = m * k;
            row[start..start + m].copy_from_slice(&powers);
        }
    }
}

pub fn pcs_reconstruct_combi_heads(
    cfg: &SmallwoodConfig,
    eval_points: &[u64],
    row_scalars: &[Vec<u64>],
    partial_evals: &[Vec<u64>],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut combi_heads = vec![vec![0u64; cfg.nb_lvcs_cols]; cfg.nb_lvcs_opened_combi];
    for (j, &eval_point) in eval_points.iter().enumerate() {
        let mut r_to_mu = eval_point;
        for _ in 1..cfg.packing_factor {
            r_to_mu = mul_mod(r_to_mu, eval_point);
        }
        let mut unstacked_vec = vec![0u64; cfg.nb_unstacked_cols];
        let mut poly_ind = 0usize;
        let mut partial_ind = 0usize;
        for (k, row_scalar) in row_scalars[j].iter().enumerate().take(cfg.nb_polys) {
            let mut sum = 0u64;
            let mut pow = 1u64;
            for i in 1..cfg.width[k] {
                let value = partial_evals[j][partial_ind];
                partial_ind += 1;
                unstacked_vec[poly_ind + i] = value;
                if i < cfg.width[k] - 1 {
                    pow = mul_mod(pow, r_to_mu);
                } else {
                    for _ in 0..(cfg.packing_factor - cfg.delta[k]) {
                        pow = mul_mod(pow, eval_point);
                    }
                }
                sum = add_mod(sum, mul_mod(value, pow));
            }
            unstacked_vec[poly_ind] = sub_mod(*row_scalar, sum);
            poly_ind += cfg.width[k];
        }
        for i in 0..cfg.beta() {
            let num_combi = j * cfg.beta() + i;
            let offset = i * cfg.nb_lvcs_cols;
            combi_heads[num_combi].fill(0);
            if offset < cfg.nb_unstacked_cols {
                let copy = min(cfg.nb_lvcs_cols, cfg.nb_unstacked_cols - offset);
                combi_heads[num_combi][..copy]
                    .copy_from_slice(&unstacked_vec[offset..offset + copy]);
            }
        }
    }
    Ok(combi_heads)
}

pub fn lvcs_recompute_rows(
    cfg: &SmallwoodConfig,
    coeffs: &[Vec<u64>],
    combi_heads: &[Vec<u64>],
    rcombi_tails: &[Vec<u64>],
    subset_evals: &[Vec<u64>],
    eval_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut extended_combis =
        vec![vec![0u64; cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals()]; cfg.nb_lvcs_opened_combi];
    for k in 0..cfg.nb_lvcs_opened_combi {
        extended_combis[k][..cfg.nb_lvcs_cols].copy_from_slice(&combi_heads[k]);
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

pub fn decs_recompute_root(
    cfg: &SmallwoodConfig,
    salt: &[u8; SALT_BYTES],
    evals: &[Vec<u64>],
    eval_points: &[u64],
    proof_trace: &SmallwoodProofTraceV1,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
    let depth = cfg.decs_nb_evals().ilog2() as usize;
    let indices = eval_points
        .iter()
        .map(|&point| point as usize)
        .collect::<Vec<_>>();
    let expected_lengths = expected_compact_merkle_auth_path_lengths(&indices, depth);
    if proof_trace.decs_auth_paths_v1().len() != expected_lengths.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood decs auth path count mismatch",
        ));
    }
    let mut current_hashes = Vec::with_capacity(eval_points.len());
    let mut current_indices = Vec::with_capacity(eval_points.len());
    let mut auth_path_cursors = vec![0usize; eval_points.len()];
    for j in 0..eval_points.len() {
        if proof_trace.decs_auth_paths_v1()[j].len() != expected_lengths[j] {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood decs compact auth path length mismatch",
            ));
        }
        let mut leaf_evals = evals[j].clone();
        leaf_evals.extend_from_slice(&proof_trace.decs_masking_evals_v1()[j]);
        current_hashes.push(hash_merkle_leave(
            cfg.nb_lvcs_rows,
            &leaf_evals,
            salt,
            transcript_backend,
        ));
        current_indices.push(eval_points[j] as usize);
    }
    for _level in 0..depth {
        let mut level_hashes = BTreeMap::new();
        for (&index, &hash) in current_indices.iter().zip(current_hashes.iter()) {
            match level_hashes.insert(index, hash) {
                Some(existing) if existing != hash => {
                    return Err(TransactionCircuitError::ConstraintViolation(
                        "smallwood decs duplicate subtree hash mismatch",
                    ));
                }
                _ => {}
            }
        }
        let mut next_hashes = Vec::with_capacity(current_hashes.len());
        let mut next_indices = Vec::with_capacity(current_indices.len());
        for j in 0..current_indices.len() {
            let index = current_indices[j];
            let sibling_index = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            let sibling_hash = if let Some(hash) = level_hashes.get(&sibling_index) {
                *hash
            } else {
                let cursor = auth_path_cursors[j];
                let hash = proof_trace.decs_auth_paths_v1()[j]
                    .get(cursor)
                    .copied()
                    .ok_or(TransactionCircuitError::ConstraintViolation(
                        "smallwood decs compact auth path underflow",
                    ))?;
                auth_path_cursors[j] += 1;
                hash
            };
            let parent = hash_merkle_children(
                if index.is_multiple_of(2) {
                    &current_hashes[j]
                } else {
                    &sibling_hash
                },
                if index.is_multiple_of(2) {
                    &sibling_hash
                } else {
                    &current_hashes[j]
                },
                transcript_backend,
            );
            next_hashes.push(parent);
            next_indices.push(index / 2);
        }
        current_hashes = next_hashes;
        current_indices = next_indices;
    }
    for (cursor, path) in auth_path_cursors
        .iter()
        .zip(proof_trace.decs_auth_paths_v1().iter())
    {
        if *cursor != path.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood decs compact auth path overflow",
            ));
        }
    }
    let root =
        current_hashes
            .first()
            .copied()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood decs root recomputation missing",
            ))?;
    if current_hashes.iter().any(|hash| *hash != root) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood decs root mismatch across opened leaves",
        ));
    }
    Ok(root)
}

pub fn decs_commitment_transcript(
    cfg: &SmallwoodConfig,
    salt: &[u8; SALT_BYTES],
    evals: &[Vec<u64>],
    root_words: &[u8; DIGEST_BYTES],
    eval_points: &[u64],
    proof_trace: &SmallwoodProofTraceV1,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let hash_mt = hash_merkle_root(salt, root_words, transcript_backend);
    let gamma_all = derive_decs_challenge(cfg, cfg.nb_lvcs_rows, &hash_mt, transcript_backend);
    let mut transcript = Vec::new();
    transcript.extend(digest_to_words(&hash_mt));
    for (k, gamma_row) in gamma_all.iter().enumerate().take(cfg.decs_eta()) {
        let mut dec_evals = vec![0u64; cfg.decs_nb_opened_evals()];
        for i in 0..cfg.decs_nb_opened_evals() {
            let mut acc = 0u64;
            for j in 0..cfg.nb_lvcs_rows {
                acc = add_mod(acc, mul_mod(evals[i][j], gamma_row[j]));
            }
            acc = add_mod(acc, proof_trace.decs_masking_evals_v1()[i][k]);
            dec_evals[i] = acc;
        }
        let dec_poly = poly_restore(
            &proof_trace.decs_high_coeffs_v1()[k],
            &dec_evals,
            eval_points,
            cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals() - 1,
        )?;
        transcript.extend_from_slice(&dec_poly);
    }
    Ok(transcript)
}

pub fn piop_recompute_transcript(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    in_transcript: &[u64],
    eval_points: &[u64],
    proof_trace: &SmallwoodProofTraceV1,
    auxiliary_words: &[u64],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let hash_fpp = hash_piop(in_transcript, transcript_backend);
    let gammas = derive_gamma_prime(cfg, &hash_fpp, transcript_backend);
    let wit_evals = proof_trace
        .opened_witness_row_scalars
        .iter()
        .map(|row| row[..cfg.row_count].to_vec())
        .collect::<Vec<_>>();
    let meval_ppoly = proof_trace
        .opened_witness_row_scalars
        .iter()
        .map(|row| row[cfg.row_count..cfg.row_count + cfg.rho()].to_vec())
        .collect::<Vec<_>>();
    let meval_plin = proof_trace
        .opened_witness_row_scalars
        .iter()
        .map(|row| row[cfg.row_count + cfg.rho()..cfg.row_count + 2 * cfg.rho()].to_vec())
        .collect::<Vec<_>>();
    let in_epol =
        get_constraint_polynomial_evals(cfg, statement, eval_points, &wit_evals, auxiliary_words)?;
    let in_elin =
        get_constraint_linear_evals(cfg, statement, eval_points, &wit_evals, &cfg.packing_points)?;
    let linear_targets = effective_linear_targets(statement, auxiliary_words);
    let mut transcript_words = Vec::new();
    transcript_words.extend(digest_to_words(&hash_fpp));
    let eval_points_with_zero = {
        let mut v = eval_points.to_vec();
        v.push(0);
        v
    };
    let lag = poly_set_lagrange(&eval_points_with_zero, cfg.nb_opened_evals());
    let mut correction_factor = 0u64;
    for num in 0..cfg.packing_factor {
        correction_factor = add_mod(correction_factor, poly_eval(&lag, cfg.packing_points[num]));
    }
    for rep in 0..cfg.rho() {
        let mut out_epol = vec![0u64; cfg.nb_opened_evals()];
        for j in 0..cfg.nb_opened_evals() {
            let mut acc = 0u64;
            for num in 0..cfg.constraint_count {
                acc = add_mod(acc, mul_mod(in_epol[j][num], gammas[rep][num]));
            }
            let mut denom = 1u64;
            for root in &cfg.packing_points {
                denom = mul_mod(denom, sub_mod(eval_points[j], *root));
            }
            acc = div_mod(acc, denom)?;
            out_epol[j] = add_mod(acc, meval_ppoly[j][rep]);
        }
        let out_ppol = poly_restore(
            &proof_trace.piop_ppol_highs_v1()[rep],
            &out_epol,
            eval_points,
            cfg.mpol_poly_degree,
        )?;

        let mut out_elin = vec![0u64; cfg.nb_opened_evals() + 1];
        for j in 0..cfg.nb_opened_evals() {
            let mut acc = 0u64;
            for num in 0..cfg.linear_constraint_count {
                acc = add_mod(acc, mul_mod(in_elin[j][num], gammas[rep][num]));
            }
            out_elin[j] = add_mod(acc, meval_plin[j][rep]);
        }
        let mut out_plin = if cfg.mlin_poly_degree > cfg.nb_opened_evals() {
            poly_restore(
                &proof_trace.piop_plin_highs_v1()[rep],
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
        res = div_mod(res, correction_factor)?;
        let scaled_lag = poly_mul_scalar(&lag, res);
        poly_add_assign(&mut out_plin, &scaled_lag);

        transcript_words.extend_from_slice(&out_ppol);
        transcript_words.extend_from_slice(&out_plin[1..]);
    }
    Ok(transcript_words)
}

fn hash_piop(words: &[u64], transcript_backend: SmallwoodTranscriptBackend) -> [u8; DIGEST_BYTES] {
    transcript_xof_digest(transcript_backend, SMALLWOOD_XOF_DOMAIN, words)
}

fn get_constraint_polynomial_evals(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    eval_points: &[u64],
    witness_evals: &[Vec<u64>],
    auxiliary_words: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut out = vec![vec![0u64; cfg.constraint_count]; eval_points.len()];
    for (row_idx, rows) in witness_evals.iter().enumerate() {
        let view = statement.nonlinear_eval_view(eval_points[row_idx], rows, auxiliary_words);
        statement.compute_constraints_u64(view, &mut out[row_idx])?;
    }
    Ok(out)
}

fn get_constraint_linear_evals(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    eval_points: &[u64],
    witness_evals: &[Vec<u64>],
    packing_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let lag = build_lagrange_basis(cfg.packing_factor, packing_points)?;
    let mut lag_evals = vec![vec![0u64; cfg.packing_factor]; eval_points.len()];
    for (num, &eval_point) in eval_points.iter().enumerate() {
        for col in 0..cfg.packing_factor {
            lag_evals[num][col] = poly_eval(&lag[col], eval_point);
        }
    }
    if statement.linear_constraint_form() == SmallwoodLinearConstraintForm::IdentityWitness {
        let mut out = vec![vec![0u64; cfg.linear_constraint_count]; eval_points.len()];
        for num in 0..eval_points.len() {
            let mut out_idx = 0usize;
            for &witness in witness_evals[num].iter().take(cfg.row_count) {
                for &lag_eval in lag_evals[num].iter().take(cfg.packing_factor) {
                    out[num][out_idx] = mul_mod(witness, lag_eval);
                    out_idx += 1;
                }
            }
        }
        return Ok(out);
    }
    let mut out = vec![vec![0u64; cfg.linear_constraint_count]; eval_points.len()];
    for num in 0..eval_points.len() {
        for (check, out_eval) in out[num]
            .iter_mut()
            .enumerate()
            .take(cfg.linear_constraint_count)
        {
            let start = statement.linear_constraint_offsets()[check] as usize;
            let end = statement.linear_constraint_offsets()[check + 1] as usize;
            let mut acc = 0u64;
            for term_idx in start..end {
                let coeff = statement.linear_constraint_coefficients()[term_idx];
                let idx = statement.linear_constraint_indices()[term_idx] as usize;
                let row = idx / cfg.packing_factor;
                let col = idx % cfg.packing_factor;
                if coeff == 0 || idx >= cfg.witness_size || row >= cfg.row_count {
                    continue;
                }
                let term = mul_mod(witness_evals[num][row], mul_mod(lag_evals[num][col], coeff));
                acc = add_mod(acc, term);
            }
            *out_eval = acc;
        }
    }
    Ok(out)
}

fn linear_targets_as_field(statement: &(dyn SmallwoodConstraintAdapter + Sync)) -> Vec<u64> {
    statement
        .linear_targets()
        .iter()
        .copied()
        .map(canon)
        .collect()
}

fn effective_linear_targets(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    auxiliary_words: &[u64],
) -> Vec<u64> {
    if auxiliary_words.is_empty() {
        linear_targets_as_field(statement)
    } else {
        auxiliary_words.iter().copied().map(canon).collect()
    }
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

fn hash_merkle_leave(
    _nb_polys: usize,
    evals: &[u64],
    salt: &[u8; SALT_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    let mut input = Vec::with_capacity(SALT_WORDS + evals.len());
    input.extend(bytes_to_words_unchecked(salt));
    input.extend_from_slice(evals);
    transcript_xof_digest(transcript_backend, SMALLWOOD_XOF_DOMAIN, &input)
}

fn hash_merkle_root(
    salt: &[u8; SALT_BYTES],
    root: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    let mut input = Vec::with_capacity(SALT_WORDS + DIGEST_WORDS);
    input.extend(bytes_to_words_unchecked(salt));
    input.extend(digest_to_words(root));
    transcript_xof_digest(transcript_backend, SMALLWOOD_XOF_DOMAIN, &input)
}

fn derive_decs_challenge(
    cfg: &SmallwoodConfig,
    nb_polys: usize,
    hash_mt: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Vec<Vec<u64>> {
    let gamma_words = transcript_xof_words(
        transcript_backend,
        SMALLWOOD_XOF_DOMAIN,
        &digest_to_words(hash_mt),
        cfg.decs_eta(),
    );
    let mut out = vec![vec![0u64; nb_polys]; cfg.decs_eta()];
    for k in 0..cfg.decs_eta() {
        out[k][0] = gamma_words[k];
        for j in 1..nb_polys {
            out[k][j] = mul_mod(out[k][j - 1], gamma_words[k]);
        }
    }
    out
}

fn hash_merkle_children(
    left: &[u8; DIGEST_BYTES],
    right: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    let mut input = Vec::with_capacity(2 * DIGEST_WORDS);
    input.extend(digest_to_words(left));
    input.extend(digest_to_words(right));
    transcript_xof_digest(transcript_backend, SMALLWOOD_XOF_DOMAIN, &input)
}

fn expected_compact_merkle_auth_path_lengths(indices: &[usize], depth: usize) -> Vec<usize> {
    let mut lengths = vec![0usize; indices.len()];
    let mut current_indices = indices.to_vec();
    for _ in 0..depth {
        let level_opened = current_indices.iter().copied().collect::<BTreeSet<_>>();
        for (path_idx, &index) in current_indices.iter().enumerate() {
            let sibling = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            if !level_opened.contains(&sibling) {
                lengths[path_idx] += 1;
            }
        }
        for index in &mut current_indices {
            *index /= 2;
        }
    }
    lengths
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

fn poly_eval(poly: &[u64], point: u64) -> u64 {
    let mut acc = *poly.last().unwrap_or(&0);
    for coeff in poly.iter().rev().skip(1) {
        acc = add_mod(mul_mod(acc, point), *coeff);
    }
    acc
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
        let scale = div_mod(evals[i], acc).expect("non-zero interpolation denominator");
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
    let scale = div_mod(1, acc).expect("non-zero lagrange denominator");
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
    for (i, row) in inv.iter_mut().enumerate().take(n) {
        row[i] = 1;
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

fn canon(x: u64) -> u64 {
    Goldilocks::new(x).as_canonical_u64()
}

fn add_mod(a: u64, b: u64) -> u64 {
    (Goldilocks::new(a) + Goldilocks::new(b)).as_canonical_u64()
}

fn sub_mod(a: u64, b: u64) -> u64 {
    (Goldilocks::new(a) - Goldilocks::new(b)).as_canonical_u64()
}

fn mul_mod(a: u64, b: u64) -> u64 {
    (Goldilocks::new(a) * Goldilocks::new(b)).as_canonical_u64()
}

fn neg_mod(a: u64) -> u64 {
    if canon(a) == 0 {
        0
    } else {
        (Goldilocks::ZERO - Goldilocks::new(a)).as_canonical_u64()
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

fn div_mod(a: u64, b: u64) -> Result<u64, TransactionCircuitError> {
    Ok(mul_mod(a, inv_mod(b)?))
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
