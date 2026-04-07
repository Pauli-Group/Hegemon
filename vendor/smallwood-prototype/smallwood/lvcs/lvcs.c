#include "lvcs-internal.h"
#include "lvcs-hash.h"
#include "benchmark.h"
#include "utils.h"
#include <stdio.h>

uint32_t lvcs_get_transcript_size(const lvcs_t* lvcs) {
    return decs_get_transcript_size(lvcs->decs);
}

uint32_t lvcs_get_key_bytesize(const lvcs_t* lvcs) {
    return lvcs_key_alloc_bytesize(lvcs);
}

int lvcs_commit(const lvcs_t* lvcs, const uint8_t salt[PARAM_SALT_SIZE], vec_t const* const rows, uint8_t* transcript, lvcs_key_t* key) {
    uint32_t nb_rows = lvcs->nb_rows;
    uint32_t nb_cols = lvcs->nb_cols;
    uint32_t nb_opened_evals = lvcs->nb_opened_evals;
    vec_t interpolation_points = lvcs->interpolation_points;
    const decs_t* decs = lvcs->decs;
    int ret = 0;

    ret = lvcs_key_init(key, lvcs); ERR(ret, err);

    // Extend the committed rows with randomness
    for(uint32_t j=0; j<nb_rows; j++) {
        vec_set(key->extended_rows[j], rows[j], nb_cols);
        vec_random(&key->extended_rows[j][nb_cols], nb_opened_evals);
    }

    // Interpolate the (extended) committed rows
    __BENCHMARK_START__(LVCS_COMMIT_INTERPOLATE);
    poly_t* polys = malloc_poly_array(nb_rows, nb_cols+nb_opened_evals-1);
    poly_interpolate_multiple(polys, key->extended_rows, interpolation_points, nb_cols+nb_opened_evals, nb_rows);
    __BENCHMARK_STOP__(LVCS_COMMIT_INTERPOLATE);

    // Commit the interpolated polynomials using the DECS
    ret = decs_commit(decs, salt, polys, transcript, key->decs_key);
    free(polys);

err:
    return ret;
}

uint32_t lvcs_max_sizeof_proof(const lvcs_t* lvcs) {
    uint32_t nb_rows = lvcs->nb_rows;
    uint32_t nb_opened_evals = lvcs->nb_opened_evals;
    uint32_t nb_opened_combi = lvcs->nb_opened_combi;

    uint32_t rcombi_bytesize = nb_opened_combi*vec_get_bytesize(nb_opened_evals);
    uint32_t decs_opened_values_bytesize = nb_opened_evals*vec_get_bytesize(nb_rows - nb_opened_combi);
    uint32_t proof_size = NONCE_BYTESIZE;
    proof_size += decs_max_sizeof_proof(lvcs->decs);
    proof_size += rcombi_bytesize + decs_opened_values_bytesize;
    return proof_size;
}

uint8_t* lvcs_open(const lvcs_t* lvcs, const lvcs_key_t* key, felt_t* const* const coeffs, uint32_t* fullrank_cols, const uint8_t* prtranscript, uint32_t prtranscript_bytesize, vec_t* combi, uint32_t* proof_size) {
    uint32_t j, k;
    uint32_t nb_rows = lvcs->nb_rows;
    uint32_t nb_cols = lvcs->nb_cols;
    uint32_t nb_opened_evals = lvcs->nb_opened_evals;
    uint32_t nb_opened_combi = lvcs->nb_opened_combi;
    const decs_t* decs = lvcs->decs;

    __BENCHMARK_START__(LVCS_OPEN_COMPUTE_EXTENDED_COMBIS);
    vec_t* extended_combis = malloc_vec_array(nb_opened_combi, nb_cols+nb_opened_evals);
    mat_mul(extended_combis, coeffs, key->extended_rows, nb_opened_combi, nb_rows, nb_cols+nb_opened_evals);
    for(k=0; k<nb_opened_combi; k++)
        vec_set(combi[k], extended_combis[k], nb_cols);
    __BENCHMARK_STOP__(LVCS_OPEN_COMPUTE_EXTENDED_COMBIS);

    __BENCHMARK_START__(LVCS_OPEN_COMPUTE_OPENING_CHALLENGE);
    // Derive the challenge hash
    uint8_t trans_hash[PARAM_DIGEST_SIZE];
    hash_challenge_opening_decs(lvcs, trans_hash, extended_combis, prtranscript, prtranscript_bytesize);

    // Get the opening challenge
    vec_t eval_points = malloc_vec(nb_opened_evals);
    uint8_t nonce[NONCE_BYTESIZE];
    decs_get_opening_challenge(decs, trans_hash, eval_points, nonce);
    __BENCHMARK_STOP__(LVCS_OPEN_COMPUTE_OPENING_CHALLENGE);

    // Open DECS: get opened evaluations and the corresponding opening proof
    uint32_t decs_proof_size;
    vec_t* evals = malloc_vec_array(nb_opened_evals, nb_rows);
    uint8_t* decs_proof = decs_open(decs, key->decs_key, eval_points, evals, &decs_proof_size);
    if(decs_proof == NULL) {
        free(eval_points);
        free(evals);
        free(extended_combis);
        return NULL;
    }

    // Compute the byte-size of the opening proof
    uint32_t rcombi_bytesize = nb_opened_combi*vec_get_bytesize(nb_opened_evals);
    uint32_t decs_opened_values_bytesize = nb_opened_evals*vec_get_bytesize(nb_rows-nb_opened_combi);
    *proof_size = NONCE_BYTESIZE + decs_proof_size + rcombi_bytesize + decs_opened_values_bytesize;

    // Build opening proof
    uint8_t* proof = malloc(*proof_size);
    uint8_t* proof_buffer = proof;
    for(k=0; k<nb_opened_combi; k++)
        WRITE_BUFFER_VEC(proof_buffer, &extended_combis[k][nb_cols], nb_opened_evals);
    WRITE_BUFFER_BYTES(proof_buffer, nonce, NONCE_BYTESIZE);
    vec_t subset_evals = malloc_vec(nb_rows-nb_opened_combi);
    for(j=0; j<nb_opened_evals; j++) {
        uint32_t ind = 0;
        felt_t* pos = subset_evals;
        for(k=0; k<nb_rows; k++) {
            if(ind < nb_opened_combi && fullrank_cols[ind] == k) {
                ind++;
            } else {
                felt_set(pos, &evals[j][k]);
                pos++;
            }
        }
        WRITE_BUFFER_VEC(proof_buffer, subset_evals, nb_rows-nb_opened_combi);
    }
    free(subset_evals);
    WRITE_BUFFER_BYTES(proof_buffer, decs_proof, decs_proof_size);
 
    free(decs_proof);
    free(eval_points);
    free(evals);
    free(extended_combis);

#ifdef VERBOSE
    printf(" - LVCS Proof Size: %d B\n", *proof_size);
    printf("    - Nonce: %d B\n", NONCE_BYTESIZE);
    printf("    - DECS Proof Size: %d B\n", decs_proof_size);
    printf("    - DECS Opened Values: %d B\n", decs_opened_values_bytesize);
    printf("    - Opened combinations - Extended part: %d B\n", rcombi_bytesize);
#endif
    return proof;
}

int lvcs_recompute_transcript(const lvcs_t* lvcs, const uint8_t salt[PARAM_SALT_SIZE], felt_t* const* const coeffs, uint32_t* fullrank_cols, const uint8_t* prtranscript, uint32_t prtranscript_bytesize, felt_t* const* const combi, const uint8_t* proof, uint32_t proof_size, uint8_t* transcript) {
    uint32_t j, k;
    uint32_t nb_rows = lvcs->nb_rows;
    uint32_t nb_cols = lvcs->nb_cols;
    uint32_t nb_opened_evals = lvcs->nb_opened_evals;
    uint32_t nb_opened_combi = lvcs->nb_opened_combi;
    vec_t interpolation_points = lvcs->interpolation_points;
    const decs_t* decs = lvcs->decs;
    int ret = 0;

    __BENCHMARK_START__(LVCS_RECOMPUTE_COMPUTE_OPENING_CHALLENGE);
    vec_t* extended_combis = malloc_vec_array(nb_opened_combi, nb_cols+nb_opened_evals);
    for(k=0; k<nb_opened_combi; k++) {
        vec_set(extended_combis[k], combi[k], nb_cols);
        READ_BUFFER_VEC(&extended_combis[k][nb_cols], proof, nb_opened_evals);
    }
    uint8_t trans_hash[PARAM_DIGEST_SIZE];
    hash_challenge_opening_decs(lvcs, trans_hash, extended_combis, prtranscript, prtranscript_bytesize);

    uint8_t nonce[NONCE_BYTESIZE];
    READ_BUFFER_BYTES(nonce, proof, NONCE_BYTESIZE);
    vec_t eval_points = malloc_vec(nb_opened_evals);
    ret = decs_recompute_opening_challenge(decs, trans_hash, nonce, eval_points);
    __BENCHMARK_STOP__(LVCS_RECOMPUTE_COMPUTE_OPENING_CHALLENGE);

    __BENCHMARK_START__(LVCS_RECOMPUTE_INTERPOLATE);
    poly_t* polys = malloc_poly_array(nb_opened_combi, nb_cols+nb_opened_evals-1);
    vec_t* evals_q = malloc_vec_array(nb_opened_evals, nb_opened_combi);
    __BENCHMARK_STOP__(LVCS_RECOMPUTE_INTERPOLATE);
    __BENCHMARK_START__(LVCS_RECOMPUTE_INTERPOLATE);
    poly_interpolate_multiple(polys, extended_combis, interpolation_points, nb_cols+nb_opened_evals, nb_opened_combi);
    __BENCHMARK_STOP__(LVCS_RECOMPUTE_INTERPOLATE);
    __BENCHMARK_START__(LVCS_RECOMPUTE_EVALUATE_POLYS);
    poly_eval_multiple(evals_q, polys, eval_points, nb_cols+nb_opened_evals-1, nb_opened_combi, nb_opened_evals);
    __BENCHMARK_STOP__(LVCS_RECOMPUTE_EVALUATE_POLYS);
    free(polys);

    __BENCHMARK_START__(LVCS_RECOMPUTE_RECOMPUTE_EVALS);
    vec_t* coeffs_part1 = malloc_vec_array(nb_opened_combi, nb_opened_combi);
    vec_t* coeffs_part2 = malloc_vec_array(nb_opened_combi, nb_rows-nb_opened_combi);
    for(j=0; j<nb_opened_combi; j++) {
        uint32_t ind = 0;
        for(k=0; k<nb_rows; k++) {
            if(ind < nb_opened_combi && fullrank_cols[ind] == k) {
                felt_set(&coeffs_part1[j][ind], &coeffs[j][k]);
                ind++;
            } else {
                felt_set(&coeffs_part2[j][k-ind], &coeffs[j][k]);
            }
        }        
    }
    vec_t* coeffs_part1_inv = malloc_vec_array(nb_opened_combi, nb_opened_combi);
    ret |= mat_inv(coeffs_part1_inv, coeffs_part1, nb_opened_combi);

    vec_t* evals = malloc_vec_array(nb_opened_evals, nb_rows);
    vec_t subset_evals = malloc_vec(nb_rows-nb_opened_combi);
    vec_t tmp = malloc_vec(nb_opened_combi);
    vec_t res = malloc_vec(nb_opened_combi);
    for(j=0; j<nb_opened_evals; j++) {
        READ_BUFFER_VEC(subset_evals, proof, nb_rows-nb_opened_combi);
        mat_vec_mul(tmp, coeffs_part2, subset_evals, nb_opened_combi, nb_rows-nb_opened_combi);
        vec_sub(tmp, evals_q[j], tmp, nb_opened_combi);
        mat_vec_mul(res, coeffs_part1_inv, tmp, nb_opened_combi, nb_opened_combi);
        uint32_t ind = 0;
        for(k=0; k<nb_rows; k++) {
            if(ind < nb_opened_combi && fullrank_cols[ind] == k) {
                felt_set(&evals[j][k], &res[ind]);
                ind++;
            } else {
                felt_set(&evals[j][k], &subset_evals[k-ind]);
            }
        }
    }
    free(subset_evals);
    free(tmp);
    free(res);
    free(coeffs_part1_inv);
    free(coeffs_part1);
    free(coeffs_part2);
    free(evals_q);
    __BENCHMARK_STOP__(LVCS_RECOMPUTE_RECOMPUTE_EVALS);

    uint32_t rcombi_bytesize = nb_opened_combi*vec_get_bytesize(nb_opened_evals);
    uint32_t decs_opened_values_bytesize = nb_opened_evals*vec_get_bytesize(nb_rows-nb_opened_combi);
    uint32_t decs_proof_size = proof_size - (sizeof(uint32_t) + rcombi_bytesize + decs_opened_values_bytesize);
    ret |= decs_recompute_transcript(decs, salt, eval_points, evals, proof, decs_proof_size, transcript);

    free(evals);
    free(eval_points);
    free(extended_combis);
    return ret;
}

