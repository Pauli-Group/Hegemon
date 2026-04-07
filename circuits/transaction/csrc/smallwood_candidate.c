#include "field.h"
#include "lppc.h"
#include "smallwood.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEGEMON_SMALLWOOD_RHO 2
#define HEGEMON_SMALLWOOD_NB_OPENED_EVALS 2
#define HEGEMON_SMALLWOOD_BETA 3
#define HEGEMON_SMALLWOOD_OPENING_POW_BITS 0
#define HEGEMON_SMALLWOOD_DECS_NB_EVALS 4096
#define HEGEMON_SMALLWOOD_DECS_NB_OPENED_EVALS 21
#define HEGEMON_SMALLWOOD_DECS_ETA 10
#define HEGEMON_SMALLWOOD_DECS_POW_BITS 0
#define HEGEMON_SMALLWOOD_TREE_HEIGHT 12
#define HEGEMON_SMALLWOOD_TREE_ARITY 2

typedef struct {
    lppc_cfg_t main;
    uint32_t witness_size;
    uint32_t binding_check_count;
    const felt_t* linear_coefficients;
    const felt_t* linear_targets;
} hegemon_smallwood_lppc_t;

static const hegemon_smallwood_lppc_t* as_hegemon_smallwood_lppc(const lppc_t* lppc) {
    return (const hegemon_smallwood_lppc_t*) lppc;
}

static const hegemon_smallwood_lppc_t* as_hegemon_smallwood_cfg(const lppc_cfg_t* cfg) {
    return (const hegemon_smallwood_lppc_t*) cfg;
}

static uint32_t hegemon_smallwood_get_preprocessing_material_bytesize(const lppc_cfg_t* lppc_cfg) {
    return sizeof(felt_t) * lppc_cfg->packing_factor;
}

static void hegemon_smallwood_preprocess_packing_points(
    const lppc_cfg_t* lppc_cfg,
    const vec_t packing_points,
    uint8_t* preprocessing_material
) {
    memcpy(
        preprocessing_material,
        packing_points,
        sizeof(felt_t) * lppc_cfg->packing_factor
    );
}

static poly_t* hegemon_smallwood_build_lagrange_basis(
    uint32_t packing_factor,
    const vec_t packing_points
) {
    poly_t* lag = malloc_poly_array(packing_factor, packing_factor - 1);
    vec_t evec = malloc_vec(packing_factor);
    if(lag == NULL || evec == NULL) {
        free(lag);
        free(evec);
        return NULL;
    }
    for(uint32_t j = 0; j < packing_factor; j++) {
        vec_set_zero(evec, packing_factor);
        felt_set_one(&evec[j]);
        poly_interpolate(lag[j], evec, packing_points, packing_factor);
    }
    free(evec);
    return lag;
}

static void hegemon_smallwood_zero_polynomials(
    const lppc_t* lppc,
    const poly_t* wit_polys,
    const uint8_t* preprocessing_material,
    poly_t* in_ppol,
    uint32_t wit_poly_degree
) {
    (void) lppc;
    (void) wit_polys;
    (void) preprocessing_material;
    poly_set_zero(in_ppol[0], 8 * wit_poly_degree);
}

static void hegemon_smallwood_get_constraint_pol_polynomials(
    const lppc_t* lppc,
    const poly_t* wit_polys,
    const uint8_t* preprocessing_material,
    poly_t* in_ppol,
    uint32_t wit_poly_degree
) {
    hegemon_smallwood_zero_polynomials(lppc, wit_polys, preprocessing_material, in_ppol, wit_poly_degree);
}

static void hegemon_smallwood_get_constraint_pol_evals(
    const lppc_t* lppc,
    const vec_t eval_points,
    const vec_t* evals,
    const uint8_t* preprocessing_material,
    uint32_t nb_evals,
    vec_t* in_epol
) {
    (void) lppc;
    (void) eval_points;
    (void) evals;
    (void) preprocessing_material;
    for(uint32_t i = 0; i < nb_evals; i++) {
        felt_set_zero(&in_epol[i][0]);
    }
}

static void hegemon_smallwood_get_constraint_lin_polynomials(
    const lppc_t* lppc,
    const poly_t* wit_polys,
    const uint8_t* preprocessing_material,
    poly_t* in_plin,
    uint32_t wit_poly_degree
) {
    const hegemon_smallwood_lppc_t* statement = as_hegemon_smallwood_lppc(lppc);
    const lppc_cfg_t* lppc_cfg = lppc_get_config(lppc);
    vec_t packing_points = (vec_t) preprocessing_material;
    uint32_t packing_factor = lppc_cfg->packing_factor;
    uint32_t nb_rows = lppc_cfg->nb_wit_rows;
    uint32_t out_degree = wit_poly_degree + (packing_factor - 1);
    poly_t* lag = hegemon_smallwood_build_lagrange_basis(packing_factor, packing_points);
    poly_t tmp = malloc_poly(out_degree);
    poly_t scaled = malloc_poly(out_degree);
    if(lag == NULL || tmp == NULL || scaled == NULL) {
        free(lag);
        free(tmp);
        free(scaled);
        return;
    }

    for(uint32_t check = 0; check < statement->binding_check_count; check++) {
        poly_set_zero(in_plin[check], out_degree);
        for(uint32_t row = 0; row < nb_rows; row++) {
            for(uint32_t col = 0; col < packing_factor; col++) {
                uint32_t idx = row * packing_factor + col;
                const felt_t* coeff =
                    &statement->linear_coefficients[check * statement->witness_size + idx];
                if(felt_is_zero(coeff)) {
                    continue;
                }
                poly_mul(tmp, wit_polys[row], lag[col], wit_poly_degree, packing_factor - 1);
                poly_mul_scalar(scaled, tmp, coeff, out_degree);
                poly_add(in_plin[check], in_plin[check], scaled, out_degree);
            }
        }
    }

    free(lag);
    free(tmp);
    free(scaled);
}

static void hegemon_smallwood_get_constraint_lin_polynomials_batched(
    const lppc_t* lppc,
    const poly_t* wit_polys,
    const uint8_t* preprocessing_material,
    const vec_t* gammas,
    poly_t* in_plin,
    uint32_t wit_poly_degree,
    uint32_t rho
) {
    const hegemon_smallwood_lppc_t* statement = as_hegemon_smallwood_lppc(lppc);
    const lppc_cfg_t* lppc_cfg = lppc_get_config(lppc);
    vec_t packing_points = (vec_t) preprocessing_material;
    uint32_t packing_factor = lppc_cfg->packing_factor;
    uint32_t nb_rows = lppc_cfg->nb_wit_rows;
    uint32_t out_degree = wit_poly_degree + (packing_factor - 1);
    poly_t* lag = hegemon_smallwood_build_lagrange_basis(packing_factor, packing_points);
    vec_t* combined = malloc_vec_array(rho, statement->witness_size);
    poly_t tmp = malloc_poly(out_degree);
    poly_t scaled = malloc_poly(out_degree);
    felt_t term;
    if(lag == NULL || combined == NULL || tmp == NULL || scaled == NULL) {
        free(lag);
        free(combined);
        free(tmp);
        free(scaled);
        return;
    }

    for(uint32_t rep = 0; rep < rho; rep++) {
        vec_set_zero(combined[rep], statement->witness_size);
        for(uint32_t check = 0; check < statement->binding_check_count; check++) {
            const felt_t* gamma = &gammas[rep][check];
            if(felt_is_zero(gamma)) {
                continue;
            }
            for(uint32_t idx = 0; idx < statement->witness_size; idx++) {
                felt_mul(&term, gamma, &statement->linear_coefficients[check * statement->witness_size + idx]);
                felt_add(&combined[rep][idx], &combined[rep][idx], &term);
            }
        }
    }

    for(uint32_t rep = 0; rep < rho; rep++) {
        poly_set_zero(in_plin[rep], out_degree);
        for(uint32_t row = 0; row < nb_rows; row++) {
            for(uint32_t col = 0; col < packing_factor; col++) {
                uint32_t idx = row * packing_factor + col;
                if(felt_is_zero(&combined[rep][idx])) {
                    continue;
                }
                poly_mul(tmp, wit_polys[row], lag[col], wit_poly_degree, packing_factor - 1);
                poly_mul_scalar(scaled, tmp, &combined[rep][idx], out_degree);
                poly_add(in_plin[rep], in_plin[rep], scaled, out_degree);
            }
        }
    }

    free(lag);
    free(combined);
    free(tmp);
    free(scaled);
}

static void hegemon_smallwood_get_constraint_lin_evals(
    const lppc_t* lppc,
    const vec_t eval_points,
    const vec_t* evals,
    const uint8_t* preprocessing_material,
    uint32_t nb_evals,
    vec_t* in_elin
) {
    const hegemon_smallwood_lppc_t* statement = as_hegemon_smallwood_lppc(lppc);
    const lppc_cfg_t* lppc_cfg = lppc_get_config(lppc);
    vec_t packing_points = (vec_t) preprocessing_material;
    uint32_t packing_factor = lppc_cfg->packing_factor;
    uint32_t nb_rows = lppc_cfg->nb_wit_rows;
    poly_t* lag = hegemon_smallwood_build_lagrange_basis(packing_factor, packing_points);
    vec_t lag_evals = malloc_vec(packing_factor);
    felt_t term;
    if(lag == NULL || lag_evals == NULL) {
        free(lag);
        free(lag_evals);
        return;
    }

    for(uint32_t num = 0; num < nb_evals; num++) {
        for(uint32_t col = 0; col < packing_factor; col++) {
            poly_eval(&lag_evals[col], lag[col], &eval_points[num], packing_factor - 1);
        }
        for(uint32_t check = 0; check < statement->binding_check_count; check++) {
            felt_set_zero(&in_elin[num][check]);
            for(uint32_t row = 0; row < nb_rows; row++) {
                for(uint32_t col = 0; col < packing_factor; col++) {
                    uint32_t idx = row * packing_factor + col;
                    const felt_t* coeff =
                        &statement->linear_coefficients[check * statement->witness_size + idx];
                    if(felt_is_zero(coeff)) {
                        continue;
                    }
                    felt_mul(&term, &evals[num][row], &lag_evals[col]);
                    felt_mul(&term, &term, coeff);
                    felt_add(&in_elin[num][check], &in_elin[num][check], &term);
                }
            }
        }
    }

    free(lag);
    free(lag_evals);
}

static void hegemon_smallwood_get_linear_result(const lppc_t* lppc, vec_t vt) {
    const hegemon_smallwood_lppc_t* statement = as_hegemon_smallwood_lppc(lppc);
    vec_set(vt, (vec_t) statement->linear_targets, statement->binding_check_count);
}

static void hegemon_smallwood_init_statement(
    hegemon_smallwood_lppc_t* statement,
    uint32_t nb_rows,
    uint32_t packing_factor,
    uint32_t constraint_degree,
    uint32_t binding_check_count,
    const felt_t* linear_coefficients,
    const felt_t* linear_targets
) {
    memset(statement, 0, sizeof(*statement));
    statement->main.nb_wit_rows = nb_rows;
    statement->main.packing_factor = packing_factor;
    statement->main.constraint_degree = constraint_degree;
    statement->main.nb_poly_constraints = 1;
    statement->main.nb_linear_constraints = binding_check_count;
    statement->main.get_preprocessing_material_bytesize = hegemon_smallwood_get_preprocessing_material_bytesize;
    statement->main.preprocess_packing_points = hegemon_smallwood_preprocess_packing_points;
    statement->main.get_constraint_pol_polynomials = hegemon_smallwood_get_constraint_pol_polynomials;
    statement->main.get_constraint_lin_polynomials = hegemon_smallwood_get_constraint_lin_polynomials;
    statement->main.get_constraint_lin_polynomials_batched = hegemon_smallwood_get_constraint_lin_polynomials_batched;
    statement->main.get_linear_result = hegemon_smallwood_get_linear_result;
    statement->main.get_constraint_pol_evals = hegemon_smallwood_get_constraint_pol_evals;
    statement->main.get_constraint_lin_evals = hegemon_smallwood_get_constraint_lin_evals;
    statement->witness_size = nb_rows * packing_factor;
    statement->binding_check_count = binding_check_count;
    statement->linear_coefficients = linear_coefficients;
    statement->linear_targets = linear_targets;
}

static int hegemon_smallwood_make_instance(
    const lppc_t* lppc,
    smallwood_t** out
) {
    uint32_t arities[HEGEMON_SMALLWOOD_TREE_HEIGHT];
    for(uint32_t i = 0; i < HEGEMON_SMALLWOOD_TREE_HEIGHT; i++) {
        arities[i] = HEGEMON_SMALLWOOD_TREE_ARITY;
    }
    merkle_tree_cfg_t tree_cfg = {
        .nb_leaves = HEGEMON_SMALLWOOD_DECS_NB_EVALS,
        .height = HEGEMON_SMALLWOOD_TREE_HEIGHT,
        .arities = arities,
    };
    smallwood_cfg_t sw_cfg = {
        .rho = HEGEMON_SMALLWOOD_RHO,
        .nb_opened_evals = HEGEMON_SMALLWOOD_NB_OPENED_EVALS,
        .beta = HEGEMON_SMALLWOOD_BETA,
        .piop_format_challenge = 2,
        .opening_pow_bits = HEGEMON_SMALLWOOD_OPENING_POW_BITS,
        .decs_nb_evals = HEGEMON_SMALLWOOD_DECS_NB_EVALS,
        .decs_nb_opened_evals = HEGEMON_SMALLWOOD_DECS_NB_OPENED_EVALS,
        .decs_eta = HEGEMON_SMALLWOOD_DECS_ETA,
        .decs_pow_bits = HEGEMON_SMALLWOOD_DECS_POW_BITS,
        .decs_use_commitment_tapes = 0,
        .decs_format_challenge = 0,
        .decs_tree_cfg = &tree_cfg,
    };
    *out = malloc_smallwood(lppc_get_config(lppc), &sw_cfg);
    return (*out == NULL) ? -1 : 0;
}

int hegemon_smallwood_candidate_prove(
    const uint64_t* witness_values,
    uint32_t witness_len,
    uint32_t nb_rows,
    uint32_t packing_factor,
    uint32_t constraint_degree,
    const uint64_t* linear_coefficients,
    const uint64_t* linear_targets,
    uint32_t binding_check_count,
    const uint8_t* binded_data,
    uint32_t binded_data_bytesize,
    uint8_t** proof_out,
    uint32_t* proof_size_out
) {
    if(
        witness_values == NULL ||
        linear_coefficients == NULL ||
        linear_targets == NULL ||
        proof_out == NULL ||
        proof_size_out == NULL ||
        binding_check_count == 0 ||
        packing_factor == 0 ||
        nb_rows == 0
    ) {
        return -1;
    }
    if(witness_len != nb_rows * packing_factor) {
        return -2;
    }

    hegemon_smallwood_lppc_t statement;
    hegemon_smallwood_init_statement(
        &statement,
        nb_rows,
        packing_factor,
        constraint_degree,
        binding_check_count,
        (const felt_t*) linear_coefficients,
        (const felt_t*) linear_targets
    );

    smallwood_t* sw = NULL;
    if(hegemon_smallwood_make_instance((const lppc_t*) &statement, &sw) != 0) {
        return -3;
    }

    uint32_t proof_size = 0;
    uint8_t* proof = smallwood_prove_with_data(
        sw,
        (const lppc_t*) &statement,
        (vec_t) witness_values,
        binded_data,
        binded_data_bytesize,
        &proof_size
    );
    free(sw);
    if(proof == NULL) {
        return -4;
    }
    *proof_out = proof;
    *proof_size_out = proof_size;
    return 0;
}

int hegemon_smallwood_candidate_verify(
    const uint64_t* witness_values,
    uint32_t witness_len,
    uint32_t nb_rows,
    uint32_t packing_factor,
    uint32_t constraint_degree,
    const uint64_t* linear_coefficients,
    const uint64_t* linear_targets,
    uint32_t binding_check_count,
    const uint8_t* binded_data,
    uint32_t binded_data_bytesize,
    const uint8_t* proof,
    uint32_t proof_size
) {
    if(
        witness_values == NULL ||
        linear_coefficients == NULL ||
        linear_targets == NULL ||
        proof == NULL ||
        binding_check_count == 0 ||
        packing_factor == 0 ||
        nb_rows == 0
    ) {
        return -1;
    }
    if(witness_len != nb_rows * packing_factor) {
        return -2;
    }

    hegemon_smallwood_lppc_t statement;
    hegemon_smallwood_init_statement(
        &statement,
        nb_rows,
        packing_factor,
        constraint_degree,
        binding_check_count,
        (const felt_t*) linear_coefficients,
        (const felt_t*) linear_targets
    );

    smallwood_t* sw = NULL;
    if(hegemon_smallwood_make_instance((const lppc_t*) &statement, &sw) != 0) {
        return -3;
    }
    int ret = smallwood_verify_with_data(
        sw,
        (const lppc_t*) &statement,
        binded_data,
        binded_data_bytesize,
        proof,
        proof_size
    );
    free(sw);
    return ret;
}

void hegemon_smallwood_candidate_free(void* ptr) {
    free(ptr);
}
