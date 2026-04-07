#include "lppc.h"

int lppc_test_witness(const lppc_t* lppc, const vec_t witness) {
    const lppc_cfg_t* lppc_cfg = lppc_get_config(lppc);

    uint32_t packing_factor = lppc_cfg->packing_factor;
    uint32_t nb_wit_rows = lppc_cfg->nb_wit_rows;
    uint32_t nb_poly_constraints = lppc_cfg->nb_poly_constraints;
    uint32_t nb_linear_constraints = lppc_cfg->nb_linear_constraints;
    uint32_t constraint_degree = lppc_cfg->constraint_degree;

    int ret = 0;
    felt_t zero;
    felt_set_zero(&zero);

    // Get the packing points
    vec_t packing_points = malloc_vec(packing_factor);
    for(uint32_t j=0; j<packing_factor; j++)
        felt_from_uint32(&packing_points[j], j);
    uint32_t preprocessing_material_bytesize = lppc_cfg->get_preprocessing_material_bytesize(lppc_cfg);
    uint8_t* preprocessing_material = malloc(preprocessing_material_bytesize);
    lppc_cfg->preprocess_packing_points(lppc_cfg, packing_points, preprocessing_material);

    // Build the witness polynomial (without randomness)
    poly_t* wit_polys = malloc_poly_array(nb_wit_rows, packing_factor-1);
    for(uint32_t i=0; i<nb_wit_rows; i++) {
        poly_interpolate(wit_polys[i], &witness[i*packing_factor], packing_points, packing_factor);
    }

    // Test Polynomial Constraints
    poly_t* in_ppol = malloc_poly_array(nb_poly_constraints, constraint_degree*(packing_factor-1));
    lppc_cfg->get_constraint_pol_polynomials(lppc, wit_polys, preprocessing_material, in_ppol, packing_factor-1);
    for(uint32_t i=0; i<nb_poly_constraints; i++) {
        felt_t res;
        for(uint32_t j=0; j<packing_factor; j++) {
            poly_eval(&res, in_ppol[i], &packing_points[j], constraint_degree*(packing_factor-1));
            if(!felt_is_equal(&res, &zero)) {
                ret = -1;
            }
        }
    }
    free(in_ppol);
    
    // Test Linear Constraints
    poly_t* in_plin = malloc_poly_array(nb_linear_constraints, 2*(packing_factor-1));
    lppc_cfg->get_constraint_lin_polynomials(lppc, wit_polys, preprocessing_material, in_plin, packing_factor-1);
    vec_t vt = malloc_vec(nb_linear_constraints);
    lppc_cfg->get_linear_result(lppc, vt);
    for(uint32_t i=0; i<nb_linear_constraints; i++) {
        felt_t res, tmp;
        felt_set_zero(&res);
        for(uint32_t j=0; j<packing_factor; j++) {
            poly_eval(&tmp, in_plin[i], &packing_points[j], 2*(packing_factor-1));
            felt_add(&res, &res, &tmp);
        }
        if(!felt_is_equal(&res, &vt[i])) {
            ret = -1;
        }
    }
    free(in_plin);
    free(vt);

    free(wit_polys);
    free(packing_points);
    free(preprocessing_material);
    return ret;
}
