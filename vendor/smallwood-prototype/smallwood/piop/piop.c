#include "piop-internal.h"
#include "piop-hash.h"
#include "utils.h"
#include <stdio.h>
#include "benchmark.h"

vec_t piop_get_packing_points(const piop_t* piop) {
    return piop->packing_points;
}

uint32_t piop_get_proof_size(const piop_t* piop) {
    return piop->proof_bytesize;
}

uint32_t piop_get_transcript_size(const piop_t* piop) {
    return piop->transcript_bytesize;
}

static void poly_interpolate_random(poly_t p, const vec_t evals, const vec_t eval_points, uint32_t nb_evals, uint32_t nb_random) {
    vec_t rnd = malloc_vec(nb_random);
    vec_random(rnd, nb_random);
    poly_restore(p, rnd, evals, eval_points, nb_evals+nb_random-1, nb_evals);
    free(rnd);
}

static void poly_random_sum_zero(poly_t p, const vec_t eval_points, uint32_t nb_evals, uint32_t degree) {
    poly_random(&p[1], degree-1);
    felt_set_zero(&p[0]);
    felt_t one, factor, tmp, acc;
    felt_set_one(&one);
    felt_set_zero(&acc);
    felt_set_zero(&factor);
    for(uint32_t i=0; i<nb_evals; i++) {
        poly_eval(&tmp, p, &eval_points[i], degree);
        felt_add(&acc, &acc, &tmp);
        felt_add(&factor, &factor, &one);
    }
    felt_neg(&acc, &acc);
    felt_div(&p[0], &acc, &factor);
}

void piop_get_input_degrees(const lppc_cfg_t* lppc_cfg, const piop_cfg_t* piop_cfg, uint32_t* wit_degree, uint32_t* mpol_pol_degree, uint32_t* mpol_lin_degree) {
    uint32_t constraint_degree = lppc_cfg->constraint_degree;
    uint32_t packing_factor = lppc_cfg->packing_factor;
    uint32_t nb_opened_evals = piop_cfg->nb_opened_evals;
    *wit_degree = packing_factor + nb_opened_evals - 1;
    *mpol_pol_degree = constraint_degree*(packing_factor+nb_opened_evals-1)-packing_factor;
    *mpol_lin_degree = (packing_factor+nb_opened_evals-1)+(packing_factor-1);
}

int piop_prepare_input_polynomials(const piop_t* piop, vec_t witness, poly_t* wit_polys, poly_t* mpol_ppol, poly_t* mpol_plin) {
    const lppc_cfg_t* lppc_cfg = &piop->lppc_cfg;
    uint32_t nb_wit_rows = lppc_cfg->nb_wit_rows;
    uint32_t packing_factor = lppc_cfg->packing_factor;
    uint32_t nb_opened_evals = piop->nb_opened_evals;
    uint32_t rho = piop->rho;
    vec_t packing_points = piop->packing_points;
    uint32_t out_ppol_degree = piop->out_ppol_degree;
    uint32_t out_plin_degree = piop->out_plin_degree;

    // Interpolate the witness polynomials
    for(uint32_t i=0; i<nb_wit_rows; i++)
        poly_interpolate_random(wit_polys[i], &witness[i*packing_factor], packing_points, packing_factor, nb_opened_evals);

    // Sample the mask polynomials for polynomial constraints
    for(uint32_t i=0; i<rho; i++)
        poly_random(mpol_ppol[i], out_ppol_degree);

    // Sample the mask polynomials for linear constraints
    for(uint32_t i=0; i<rho; i++)
        poly_random_sum_zero(mpol_plin[i], packing_points, packing_factor, out_plin_degree);

    return 0;
}

static void derive_gamma_prime(const piop_t* piop, uint8_t hash_fpp[PARAM_DIGEST_SIZE], vec_t* gamma_prime_all) {
    uint32_t j, k;
    const lppc_cfg_t* lppc_cfg = &piop->lppc_cfg;
    uint32_t format_challenge = piop->format_challenge;
    uint32_t nb_poly_constraints = lppc_cfg->nb_poly_constraints;
    uint32_t nb_linear_constraints = lppc_cfg->nb_linear_constraints;
    uint32_t nb_max_constraints = (nb_poly_constraints > nb_linear_constraints) ? nb_poly_constraints : nb_linear_constraints;
    uint32_t rho = piop->rho;
    
    if(format_challenge == 0) {
        vec_t gamma_prime = malloc_vec(rho);
        xof_piop_challenge(piop, gamma_prime, hash_fpp, rho);
        for(k=0; k<rho; k++) {
            felt_set(&gamma_prime_all[k][0], &gamma_prime[k]);
            for(j=1; j<nb_max_constraints; j++)
                felt_mul(&gamma_prime_all[k][j], &gamma_prime_all[k][j-1], &gamma_prime[k]);
        }
        free(gamma_prime);
    } else if(format_challenge == 1) {
        vec_t gamma_prime = malloc_vec(rho*nb_max_constraints);
        xof_piop_challenge(piop, gamma_prime, hash_fpp, rho*nb_max_constraints);
        for(k=0; k<rho; k++)
            for(j=0; j<nb_max_constraints; j++)
                felt_set(&gamma_prime_all[k][j], &gamma_prime[k*nb_max_constraints+j]);
        free(gamma_prime);
    } else if(format_challenge == 2) {
        vec_t gamma_prime = malloc_vec((rho+1)+(rho+1)*rho);
        vec_t* mat_rnd = malloc_vec_array(rho, rho+1);
        vec_t* mat_powers = malloc_vec_array(rho+1, nb_max_constraints);
        xof_piop_challenge(piop, gamma_prime, hash_fpp, (rho+1)+(rho+1)*rho);
        for(k=0; k<rho; k++)
            for(j=0; j<rho+1; j++)
                felt_set(&mat_rnd[k][j], &gamma_prime[k*(rho+1)+j]);
        for(k=0; k<rho+1; k++) {
            felt_set_one(&mat_powers[k][0]);
            for(j=1; j<nb_max_constraints; j++)
                felt_mul(&mat_powers[k][j], &mat_powers[k][j-1], &gamma_prime[rho*(rho+1)+k]);
        }
        mat_mul(gamma_prime_all, mat_rnd, mat_powers, rho, rho+1, nb_max_constraints);
        free(mat_rnd);
        free(mat_powers);
        free(gamma_prime);
    }
}

int piop_run(const piop_t* piop, const lppc_t* lppc, const uint8_t* in_transcript, uint32_t in_transcript_bytesize, const poly_t* wit_polys, const poly_t* mpol_ppoly, const poly_t* mpol_plin, uint8_t* out_transcript, uint8_t* proof) {
    const lppc_cfg_t* lppc_cfg = &piop->lppc_cfg;
    uint32_t packing_factor = lppc_cfg->packing_factor;
    uint32_t nb_poly_constraints = lppc_cfg->nb_poly_constraints;
    uint32_t nb_linear_constraints = lppc_cfg->nb_linear_constraints;
    uint32_t nb_max_constraints = (nb_poly_constraints > nb_linear_constraints) ? nb_poly_constraints : nb_linear_constraints;
    uint32_t rho = piop->rho;
    uint32_t nb_opened_evals = piop->nb_opened_evals;
    uint32_t out_ppol_degree = piop->out_ppol_degree;
    uint32_t out_plin_degree = piop->out_plin_degree;
    vec_t packing_points = piop->packing_points;
    uint32_t ext_out_ppol_degree = out_ppol_degree + packing_factor;
    uint32_t wit_poly_degree = packing_factor + nb_opened_evals - 1;

    // Compute FPP challenge
    uint8_t hash_fpp[PARAM_DIGEST_SIZE];
    __BENCHMARK_START__(PIOP_RUN_XOF_FPP);
    hash_piop(piop, hash_fpp, in_transcript, in_transcript_bytesize);
    vec_t* gammas = malloc_vec_array(rho, nb_max_constraints);
    derive_gamma_prime(piop, hash_fpp, gammas);
    __BENCHMARK_STOP__(PIOP_RUN_XOF_FPP);

    // Build out transcript
    WRITE_BUFFER_BYTES(out_transcript, hash_fpp, PARAM_DIGEST_SIZE);

    poly_t* in_ppol = malloc_poly_array(nb_poly_constraints, ext_out_ppol_degree);
    //poly_t* in_plin = malloc_poly_array(nb_linear_constraints, out_plin_degree);
    poly_t* in_plin = malloc_poly_array(rho, out_plin_degree);
    __BENCHMARK_START__(PIOP_RUN_POL_CONSTRAINT_IND);
    lppc_cfg->get_constraint_pol_polynomials(lppc, wit_polys, piop->preprocessing_material, in_ppol, wit_poly_degree);
    __BENCHMARK_STOP__(PIOP_RUN_POL_CONSTRAINT_IND);
    __BENCHMARK_START__(PIOP_RUN_LIN_CONSTRAINT_IND);
    //lppc_cfg->get_constraint_lin_polynomials(lppc, wit_polys, piop->preprocessing_material, in_plin, wit_poly_degree);
    lppc_cfg->get_constraint_lin_polynomials_batched(lppc, wit_polys, piop->preprocessing_material, gammas, in_plin, wit_poly_degree, rho);
    __BENCHMARK_STOP__(PIOP_RUN_LIN_CONSTRAINT_IND);

    poly_t out_ppol = malloc_poly(ext_out_ppol_degree);
    poly_t out_plin = malloc_poly(out_plin_degree);
    poly_t tmp_ppol = malloc_poly(ext_out_ppol_degree);
    poly_t tmp_plin = malloc_poly(out_plin_degree);
    for(uint32_t num_rep=0; num_rep<rho; num_rep++) {

        //// Polynomial Constraints
        // Random Linear Combination
        __BENCHMARK_START__(PIOP_RUN_POL_CONSTRAINT_OUT);
        poly_set_zero(out_ppol, ext_out_ppol_degree);
        for(uint32_t num=0; num<nb_poly_constraints; num++) {
            poly_mul_scalar(tmp_ppol, in_ppol[num], &gammas[num_rep][num], ext_out_ppol_degree);
            poly_add(out_ppol, out_ppol, tmp_ppol, ext_out_ppol_degree);
        }
        // Check
        /*if(num_rep == 0) {
            felt_t test;
            for(uint32_t i=0; i<packing_factor; i++) {
                poly_eval(&test, out_ppol, &packing_points[i], ext_out_ppol_degree);
                felt_printf(&test);
                printf("\n");
            }
        }*/
        // Division by the vanishing polynomial
        for(uint32_t num=0; num<packing_factor; num++) {
            poly_remove_one_degree_factor(tmp_ppol, out_ppol, &packing_points[num], ext_out_ppol_degree-num);
            poly_set(out_ppol, tmp_ppol, ext_out_ppol_degree-num);
        }
        // Add Mask
        poly_add(out_ppol, out_ppol, mpol_ppoly[num_rep], out_ppol_degree);
        __BENCHMARK_STOP__(PIOP_RUN_POL_CONSTRAINT_OUT);

        //// Linear Constraints
        // Random Linear Combination
        __BENCHMARK_START__(PIOP_RUN_LIN_CONSTRAINT_OUT);
        //poly_set_zero(out_plin, out_plin_degree);
        //for(uint32_t num=0; num<nb_linear_constraints; num++) {
        //    poly_mul_scalar(tmp_plin, in_plin[num], &gammas[num_rep][num], out_plin_degree);
        //    poly_add(out_plin, out_plin, tmp_plin, out_plin_degree);
        //}
        poly_set(out_plin, in_plin[num_rep], out_plin_degree);
        // Add Mask
        poly_add(out_plin, out_plin, mpol_plin[num_rep], out_plin_degree);
        __BENCHMARK_STOP__(PIOP_RUN_LIN_CONSTRAINT_OUT);

        // Update Proof and Transcript
        WRITE_BUFFER_POLY(out_transcript, out_ppol, out_ppol_degree);
        WRITE_BUFFER_POLY(out_transcript, &out_plin[1], out_plin_degree-1);
        vec_t out_ppol_high = &out_ppol[nb_opened_evals];
        WRITE_BUFFER_VEC(proof, out_ppol_high, out_ppol_degree+1-nb_opened_evals);
        vec_t out_plin_high = &out_plin[nb_opened_evals+1];
        WRITE_BUFFER_VEC(proof, out_plin_high, out_plin_degree-nb_opened_evals);
    }
    free(out_ppol);
    free(out_plin);
    free(tmp_ppol);
    free(tmp_plin);

    free(in_ppol);
    free(in_plin);
    free(gammas);

#ifdef VERBOSE
    printf(" - PIOP Proof Size: %d B\n", piop_get_proof_size(piop));
#endif
    return 0;
}

int piop_recompute_transcript(const piop_t* piop, const lppc_t* lppc, const uint8_t* in_transcript, uint32_t in_transcript_bytesize, const vec_t eval_points, const vec_t* wit_evals, const vec_t* meval_ppoly, vec_t* meval_plin, const uint8_t* proof, uint8_t* out_transcript) {
    const lppc_cfg_t* lppc_cfg = &piop->lppc_cfg;
    uint32_t packing_factor = lppc_cfg->packing_factor;
    uint32_t nb_poly_constraints = lppc_cfg->nb_poly_constraints;
    uint32_t nb_linear_constraints = lppc_cfg->nb_linear_constraints;
    uint32_t nb_max_constraints = (nb_poly_constraints > nb_linear_constraints) ? nb_poly_constraints : nb_linear_constraints;
    uint32_t rho = piop->rho;
    uint32_t nb_opened_evals = piop->nb_opened_evals;
    uint32_t out_ppol_degree = piop->out_ppol_degree;
    uint32_t out_plin_degree = piop->out_plin_degree;
    vec_t packing_points = piop->packing_points;

    // Compute FPP challenge
    uint8_t hash_fpp[PARAM_DIGEST_SIZE];
    __BENCHMARK_START__(PIOP_RECOMPUTE_XOF_FPP);
    hash_piop(piop, hash_fpp, in_transcript, in_transcript_bytesize);
    vec_t* gammas = malloc_vec_array(rho, nb_max_constraints);
    derive_gamma_prime(piop, hash_fpp, gammas);
    __BENCHMARK_STOP__(PIOP_RECOMPUTE_XOF_FPP);

    // Build out transcript
    uint8_t* out_transcript_buffer = out_transcript;
    WRITE_BUFFER_BYTES(out_transcript_buffer, hash_fpp, PARAM_DIGEST_SIZE);

    vec_t* in_epol = malloc_poly_array(nb_opened_evals, nb_poly_constraints);
    vec_t* in_elin = malloc_poly_array(nb_opened_evals, nb_linear_constraints);
    __BENCHMARK_START__(PIOP_RECOMPUTE_POL_CONSTRAINT_IND_EVALS);
    lppc_cfg->get_constraint_pol_evals(lppc, eval_points, wit_evals, piop->preprocessing_material, nb_opened_evals, in_epol);
    __BENCHMARK_STOP__(PIOP_RECOMPUTE_POL_CONSTRAINT_IND_EVALS);
    __BENCHMARK_START__(PIOP_RECOMPUTE_LIN_CONSTRAINT_IND_EVALS);
    lppc_cfg->get_constraint_lin_evals(lppc, eval_points, wit_evals, piop->preprocessing_material, nb_opened_evals, in_elin);
    __BENCHMARK_STOP__(PIOP_RECOMPUTE_LIN_CONSTRAINT_IND_EVALS);

    vec_t vt = malloc_vec(nb_linear_constraints);
    lppc_cfg->get_linear_result(lppc, vt);

    poly_t out_ppol = malloc_poly(out_ppol_degree);
    poly_t out_plin = malloc_poly(out_plin_degree);
    vec_t out_epol = malloc_vec(nb_opened_evals);
    vec_t out_elin  = malloc_vec(nb_opened_evals+1);
    vec_t out_ppol_high = malloc_vec(out_ppol_degree+1-nb_opened_evals);
    vec_t out_plin_high = malloc_vec(out_plin_degree+1-nb_opened_evals);
    felt_t tmp, tmp2;

    vec_t eval_points_with_zero = malloc_vec(nb_opened_evals+1);
    vec_set(eval_points_with_zero, eval_points, nb_opened_evals);
    felt_set_zero(&eval_points_with_zero[nb_opened_evals]);
    poly_t lag = malloc_poly(nb_opened_evals);
    poly_t scaled_lag = malloc_poly(nb_opened_evals);
    poly_set_lagrange(lag, eval_points_with_zero, nb_opened_evals, nb_opened_evals+1);
    felt_t correction_factor;
    felt_set_zero(&correction_factor);
    for(uint32_t num=0; num<packing_factor; num++) {
        poly_eval(&tmp, lag, &packing_points[num], nb_opened_evals);
        felt_add(&correction_factor, &correction_factor, &tmp);
    }
    felt_set_zero(&out_elin[nb_opened_evals]);

    for(uint32_t num_rep=0; num_rep<rho; num_rep++) {

        //// Polynomial Constraints
        __BENCHMARK_START__(PIOP_RECOMPUTE_POL_CONSTRAINT_OUT);
        for(uint32_t j=0; j<nb_opened_evals; j++) {
            // Random Linear Combination
            felt_set_zero(&out_epol[j]);
            for(uint32_t num=0; num<nb_poly_constraints; num++) {
                felt_mul(&tmp, &in_epol[j][num], &gammas[num_rep][num]);
                felt_add(&out_epol[j], &out_epol[j], &tmp);
            }
            // Division by the vanishing polynomial
            felt_set_one(&tmp);
            for(uint32_t num=0; num<packing_factor; num++) {
                felt_sub(&tmp2, &eval_points[j], &packing_points[num]);
                felt_mul(&tmp, &tmp, &tmp2);
            }
            felt_div(&out_epol[j], &out_epol[j], &tmp);
            // Add Mask
            felt_add(&out_epol[j], &out_epol[j], &meval_ppoly[j][num_rep]);
        }
        READ_BUFFER_VEC(out_ppol_high, proof, out_ppol_degree+1-nb_opened_evals);

        poly_restore(out_ppol, out_ppol_high, out_epol, eval_points, out_ppol_degree, nb_opened_evals);
        __BENCHMARK_STOP__(PIOP_RECOMPUTE_POL_CONSTRAINT_OUT);

        //// Linear Constraints
        __BENCHMARK_START__(PIOP_RECOMPUTE_LIN_CONSTRAINT_OUT);
        for(uint32_t j=0; j<nb_opened_evals; j++) {
            // Random Linear Combination
            felt_set_zero(&out_elin[j]);
            for(uint32_t num=0; num<nb_linear_constraints; num++) {
                felt_mul(&tmp, &in_elin[j][num], &gammas[num_rep][num]);
                felt_add(&out_elin[j], &out_elin[j], &tmp);
            }
            // Add Mask
            felt_add(&out_elin[j], &out_elin[j], &meval_plin[j][num_rep]);
        }
        READ_BUFFER_VEC(out_plin_high, proof, out_plin_degree-nb_opened_evals);
        // We restore assuming the constant term is zero
        poly_restore(out_plin, out_plin_high, out_elin, eval_points_with_zero, out_plin_degree, nb_opened_evals+1);
        // We now correct the polynomials
        felt_t res;
        felt_set_zero(&res);
        for(uint32_t num=0; num<nb_linear_constraints; num++) {
            felt_mul(&tmp, &vt[num], &gammas[num_rep][num]);
            felt_add(&res, &res, &tmp);
        }
        for(uint32_t num=0; num<packing_factor; num++) {
            poly_eval(&tmp, out_plin, &packing_points[num], out_plin_degree);
            felt_sub(&res, &res, &tmp);
        }
        felt_div(&res, &res, &correction_factor);
        poly_mul_scalar(scaled_lag, lag, &res, nb_opened_evals);
        poly_add(out_plin, out_plin, scaled_lag, nb_opened_evals);
        __BENCHMARK_STOP__(PIOP_RECOMPUTE_LIN_CONSTRAINT_OUT);

        // Update Transcript
        WRITE_BUFFER_POLY(out_transcript_buffer, out_ppol, out_ppol_degree);
        WRITE_BUFFER_POLY(out_transcript_buffer, &out_plin[1], out_plin_degree-1);
    }
    free(lag);
    free(scaled_lag);
    free(eval_points_with_zero);

    free(out_ppol);
    free(out_plin);
    free(out_epol);
    free(out_elin);
    free(out_ppol_high);
    free(out_plin_high);

    free(vt);
    free(in_epol);
    free(in_elin);
    free(gammas);
    return 0;
}
