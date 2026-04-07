#include "pcs-internal.h"
#include "benchmark.h"
#include <stdio.h>

uint32_t pcs_get_transcript_size(const pcs_t* pcs) {
    return lvcs_get_transcript_size(pcs->lvcs);
}

int pcs_commit(const pcs_t* pcs, const uint8_t salt[PARAM_SALT_SIZE], poly_t const* const polys, uint8_t* transcript, pcs_key_t* key) {
    //printf("[[PCS.Commit]]\n");
    uint32_t i, j, k;
    uint32_t nb_polys = pcs->nb_polys;
    uint32_t nb_opened_evals = pcs->nb_opened_evals;
    uint32_t mu = pcs->mu;
    uint32_t* width = pcs->width; 
    uint32_t* delta = pcs->delta; 
    uint32_t nb_unstacked_rows = pcs->nb_unstacked_rows;
    uint32_t nb_unstacked_cols = pcs->nb_unstacked_cols;
    uint32_t nb_lvcs_rows = pcs->nb_lvcs_rows;
    uint32_t nb_lvcs_cols = pcs->nb_lvcs_cols;
    key->lvcs_key = (lvcs_key_t*) (key + 1);

    vec_t* rows = malloc_vec_array(nb_unstacked_rows, nb_unstacked_cols);
    vec_t* stacked_rows = malloc_vec_array(nb_lvcs_rows, nb_lvcs_cols);

    __BENCHMARK_START__(PCS_COMMIT_BUILD_ROWS);
    uint32_t offset = 0;
    for(j=0; j<nb_polys; j++) {
        // Set the polynomial coefficients
        uint32_t ind = 0;
        for(i=0; i<width[j]-1; i++) {
            for(k=0; k<mu; k++) {
                felt_set(&rows[k][offset+i], &polys[j][ind]);
                ind++;
            }
        }
        for(k=delta[j]; k<nb_unstacked_rows; k++) {
            felt_set(&rows[k][offset+(width[j]-1)], &polys[j][ind]);
            ind++;
        }
            
        // Introduce random values to ensure hiding
        if(width[j] > 1) {
            vec_t rnd = malloc_vec(width[j]-1);
            for(i=0; i<nb_opened_evals; i++) {
                vec_random(rnd, width[j]-1);
                vec_set(&rows[mu+i][offset], rnd, width[j]-1);
                vec_sub(&rows[i][offset+1], &rows[i][offset+1], rnd, width[j]-2);
                felt_sub(&rows[delta[j]+i][offset+(width[j]-1)], &rows[delta[j]+i][offset+(width[j]-1)], &rnd[width[j]-2]);
            }
            free(rnd);
            for(i=0; i<delta[j]; i++)
                felt_set_zero(&rows[i][offset+(width[j]-1)]);
        }

        offset += width[j];
    }
    __BENCHMARK_STOP__(PCS_COMMIT_BUILD_ROWS);

    __BENCHMARK_START__(PCS_COMMIT_STACK_ROWS);
    for(i=0; i<nb_lvcs_rows; i++) {
        uint32_t num_unstacked_row = i % nb_unstacked_rows;
        uint32_t num_unstacked_offset = (i / nb_unstacked_rows)*nb_lvcs_cols;
        if(num_unstacked_offset + nb_lvcs_cols <= nb_unstacked_cols) {
            vec_set(stacked_rows[i], &rows[num_unstacked_row][num_unstacked_offset], nb_lvcs_cols);
        } else {
            vec_set(stacked_rows[i], &rows[num_unstacked_row][num_unstacked_offset], nb_unstacked_cols-num_unstacked_offset);
            vec_set_zero(&stacked_rows[i][nb_unstacked_cols-num_unstacked_offset], nb_lvcs_cols-(nb_unstacked_cols-num_unstacked_offset));
        }
    }
    __BENCHMARK_STOP__(PCS_COMMIT_STACK_ROWS);

    int ret = lvcs_commit(pcs->lvcs, salt, stacked_rows, transcript, key->lvcs_key);
    free(stacked_rows);
    free(rows);
    return ret;
}

static int pcs_build_coefficients(const pcs_t* pcs, const vec_t eval_points, felt_t** coeffs) {
    uint32_t j, k;
    uint32_t nb_opened_evals = pcs->nb_opened_evals;
    uint32_t mu = pcs->mu;
    uint32_t beta = pcs->beta;
    uint32_t nb_lvcs_rows = pcs->nb_lvcs_rows;

    vec_t powers = malloc_vec(mu+nb_opened_evals);
    if(powers == NULL)
        return -1;
    for(j=0; j<nb_opened_evals; j++) {
        // Compute (1, r, ..., r^{mu+m-1})
        felt_set_one(&powers[0]);
        for(k=1; k<mu+nb_opened_evals; k++)
            felt_mul(&powers[k], &powers[k-1], &eval_points[j]);
        
        for(k=0; k<beta; k++) {
            vec_set_zero(coeffs[j*beta+k], nb_lvcs_rows);
            vec_set(&coeffs[j*beta+k][(mu+nb_opened_evals)*k], powers, mu+nb_opened_evals);
        }
    }
    free(powers);
    return 0;
}

uint32_t pcs_max_sizeof_proof(const pcs_t* pcs) {
    uint32_t nb_polys = pcs->nb_polys;
    uint32_t* width = pcs->width;

    uint32_t partial_eval_bytesize = 0;
    for(uint32_t k=0; k<nb_polys; k++)
        partial_eval_bytesize += vec_get_bytesize(width[k]-1);
    partial_eval_bytesize *= pcs->nb_opened_evals;
    uint32_t lvcs_proof_size = lvcs_max_sizeof_proof(pcs->lvcs);
    uint32_t proof_size = lvcs_proof_size + partial_eval_bytesize;
    return proof_size;
}

uint8_t* pcs_open(const pcs_t* pcs, const pcs_key_t* key, const vec_t eval_points, const uint8_t* prtranscript, uint32_t prtranscript_bytesize, felt_t** evals, uint32_t* proof_size) {
    //printf("[[PCS.Open]]\n");
    uint32_t i, j, k;
    uint32_t nb_polys = pcs->nb_polys;
    uint32_t nb_lvcs_rows = pcs->nb_lvcs_rows;
    uint32_t nb_lvcs_cols = pcs->nb_lvcs_cols;
    uint32_t nb_lvcs_opened_combi = pcs->nb_lvcs_opened_combi;
    uint32_t nb_opened_evals = pcs->nb_opened_evals;
    uint32_t* width = pcs->width;
    uint32_t* delta = pcs->delta;
    uint32_t mu = pcs->mu;
    uint32_t beta = pcs->beta;
    uint32_t* fullrank_cols = pcs->fullrank_cols;

    vec_t* coeffs = malloc_vec_array(nb_lvcs_opened_combi, nb_lvcs_rows);
    vec_t* combi  = malloc_vec_array(nb_lvcs_opened_combi, nb_lvcs_cols);

    // Compute the opened coefficients for LVCS
    __BENCHMARK_START__(PCS_OPEN_BUILD_COEFFS);
    pcs_build_coefficients(pcs, eval_points, coeffs);
    __BENCHMARK_STOP__(PCS_OPEN_BUILD_COEFFS);

    // Open LVCS
    uint32_t lvcs_proof_size;
    uint8_t* lvcs_proof = lvcs_open(pcs->lvcs, key->lvcs_key, coeffs, fullrank_cols, prtranscript, prtranscript_bytesize, combi, &lvcs_proof_size);
    if(lvcs_proof == NULL) {
        free(combi);
        free(coeffs);
        return NULL;
    }

    uint32_t partial_eval_bytesize = 0;
    for(k=0; k<nb_polys; k++)
        partial_eval_bytesize += vec_get_bytesize(width[k]-1);
    partial_eval_bytesize *= pcs->nb_opened_evals;
    *proof_size = lvcs_proof_size + partial_eval_bytesize;
    uint8_t* proof = malloc(*proof_size);
    uint8_t* proof_buffer = proof;
    memcpy(proof_buffer, lvcs_proof, lvcs_proof_size);
    proof_buffer += lvcs_proof_size;
    free(lvcs_proof);

    // Build the partial evaluations
    int ret = 0;
    vec_t vec_in_proof = malloc_vec(pcs->nb_unstacked_cols);
    felt_t zero;
    felt_set_zero(&zero);
    __BENCHMARK_START__(PCS_OPEN_COMPUTE_EVALS);
    for(j=0; j<nb_opened_evals; j++) {
        // Compute r^mu
        felt_t r_to_mu;
        felt_set(&r_to_mu, &eval_points[j]);
        for(i=1; i<mu; i++)
            felt_mul(&r_to_mu, &r_to_mu, &eval_points[j]);

        uint32_t num_col = 0;
        uint32_t num_combi = beta*j;
        uint32_t ind=0;
        felt_t pow, tmp;
        for(k=0; k<nb_polys; k++) {
            uint32_t poly_ind = ind;
            felt_set_zero(&evals[j][k]);
            felt_set_one(&pow);
            for(i=0; i<width[k]; i++) {
                if(i>0) {
                    felt_set(&vec_in_proof[ind], &combi[num_combi][num_col]);
                    ind++;
                }
                felt_mul(&tmp, &combi[num_combi][num_col], &pow);
                felt_add(&evals[j][k], &evals[j][k], &tmp);
                if(i<width[k]-2) {
                    felt_mul(&pow, &pow, &r_to_mu);
                } else if(i == width[k]-2) {
                    for(uint32_t h=0; h<mu-delta[k]; h++)
                        felt_mul(&pow, &pow, &eval_points[j]);
                }
                num_col++;
                if(num_col >= nb_lvcs_cols) {
                    num_col=0;
                    num_combi++;
                }
            }
            vec_serialize(proof_buffer, &vec_in_proof[poly_ind], width[k]-1);
            proof_buffer += vec_get_bytesize(width[k]-1);
        }
        if(num_combi<beta*(j+1)) {
            for(; num_col<nb_lvcs_cols; num_col++) {
                //printf("//%d,%d//\n", num_combi, num_col);
                if(!felt_is_equal(&combi[num_combi][num_col], &zero)) {
                    printf("Alert\n");
                    ret = -1;
                }
            }
        }
    }
    free(vec_in_proof);
    __BENCHMARK_STOP__(PCS_OPEN_COMPUTE_EVALS);

    free(combi);
    free(coeffs);

#ifdef VERBOSE
    printf(" - PCS Proof Size: %d B\n", *proof_size);
    printf("    - LVCS Proof Size: %d B\n", lvcs_proof_size);
    printf("    - Partial Evals: %d B\n", partial_eval_bytesize);
#endif

    if(ret != 0) {
        free(proof);
        return NULL;
    } else {
        return proof;
    }
}

int pcs_recompute_transcript(const pcs_t* pcs, const uint8_t salt[PARAM_SALT_SIZE], const vec_t eval_points, const uint8_t* prtranscript, uint32_t prtranscript_bytesize, felt_t* const* const evals, const uint8_t* proof, uint32_t proof_size, uint8_t* transcript) {
    //printf("[[PCS.Recompute]]\n");
    uint32_t i, j, k;
    uint32_t nb_polys = pcs->nb_polys;
    uint32_t nb_lvcs_rows = pcs->nb_lvcs_rows;
    uint32_t nb_lvcs_cols = pcs->nb_lvcs_cols;
    uint32_t nb_opened_evals = pcs->nb_opened_evals;
    uint32_t nb_unstacked_cols = pcs->nb_unstacked_cols;
    uint32_t nb_lvcs_opened_combi = pcs->nb_lvcs_opened_combi;
    uint32_t* width = pcs->width;
    uint32_t* delta = pcs->delta;
    uint32_t mu = pcs->mu;
    uint32_t beta = pcs->beta;
    uint32_t* fullrank_cols = pcs->fullrank_cols;

    vec_t* coeffs = malloc_vec_array(nb_lvcs_opened_combi, nb_lvcs_rows);
    vec_t* combi  = malloc_vec_array(nb_lvcs_opened_combi, nb_lvcs_cols);

    // Compute the opened coefficients for LVCS
    __BENCHMARK_START__(PCS_RECOMPUTE_BUILD_COEFFS);
    pcs_build_coefficients(pcs, eval_points, coeffs);
    __BENCHMARK_STOP__(PCS_RECOMPUTE_BUILD_COEFFS);

    uint32_t partial_eval_bytesize = 0;
    for(k=0; k<nb_polys; k++)
        partial_eval_bytesize += vec_get_bytesize(width[k]-1);
    partial_eval_bytesize *= pcs->nb_opened_evals;
    uint32_t lvcs_proof_size = proof_size - partial_eval_bytesize;
    const uint8_t* lvcs_proof = proof;
    proof += lvcs_proof_size;

    __BENCHMARK_START__(PCS_RECOMPUTE_RECOMPUTE_COMBIS);
    vec_t unstacked_vec = malloc_vec(nb_unstacked_cols);
    for(j=0; j<nb_opened_evals; j++) {
        felt_t r_to_mu;
        felt_set(&r_to_mu, &eval_points[j]);
        for(i=1; i<mu; i++)
            felt_mul(&r_to_mu, &r_to_mu, &eval_points[j]);

        uint32_t poly_ind=0;
        felt_t pow, tmp;
        for(k=0; k<nb_polys; k++) {
            vec_deserialize(&unstacked_vec[poly_ind+1], proof, width[k]-1);
            proof += vec_get_bytesize(width[k]-1);

            felt_t sum;
            felt_set_zero(&sum);
            felt_set_one(&pow);
            for(i=1; i<width[k]; i++) {
                if(i<width[k]-1) {
                    felt_mul(&pow, &pow, &r_to_mu);
                } else {
                    for(uint32_t h=0; h<mu-delta[k]; h++)
                        felt_mul(&pow, &pow, &eval_points[j]);
                }
                felt_mul(&tmp, &unstacked_vec[poly_ind+i], &pow);
                felt_add(&sum, &sum, &tmp);
            }
            felt_sub(&unstacked_vec[poly_ind], &evals[j][k], &sum);
            poly_ind += width[k];
        }

        for(i=0; i<beta; i++) {
            uint32_t num_stacked_row = j*beta + i;
            uint32_t num_unstacked_offset = i*nb_lvcs_cols;
            if(num_unstacked_offset + nb_lvcs_cols <= nb_unstacked_cols) {
                vec_set(combi[num_stacked_row], &unstacked_vec[num_unstacked_offset], nb_lvcs_cols);
            } else {
                vec_set(combi[num_stacked_row], &unstacked_vec[num_unstacked_offset], nb_unstacked_cols-num_unstacked_offset);
                vec_set_zero(&combi[num_stacked_row][nb_unstacked_cols-num_unstacked_offset], nb_lvcs_cols-(nb_unstacked_cols-num_unstacked_offset));
            }
        }
    }
    free(unstacked_vec);
    __BENCHMARK_STOP__(PCS_RECOMPUTE_RECOMPUTE_COMBIS);

    int ret = lvcs_recompute_transcript(pcs->lvcs, salt, coeffs, fullrank_cols, prtranscript, prtranscript_bytesize, combi, lvcs_proof, lvcs_proof_size, transcript);
    free(combi);
    free(coeffs);
    return ret;
}
