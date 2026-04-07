#ifndef __FIELD_POLY_GENERIC_H__
#define __FIELD_POLY_GENERIC_H__

#include "field-base-struct.h"

static inline poly_t generic_malloc_poly(uint32_t degree) {
    return (poly_t) malloc(sizeof(felt_t)*(degree+1));
}

static inline poly_t* generic_malloc_poly_array(uint32_t array_size, uint32_t degree) {
    uint32_t first_dim_bytesize = array_size*sizeof(poly_t);
    uint32_t poly_bytesize = (degree+1)*sizeof(felt_t);
    uint8_t* ptr = malloc(first_dim_bytesize + array_size*poly_bytesize);
    poly_t* array = (poly_t*) ptr;
    if(ptr != NULL) {
        array[0] = (poly_t) (ptr + first_dim_bytesize);
        for(uint32_t num=1; num<array_size; num++)
            array[num] = (vec_t) (((uint8_t*) array[num-1]) + poly_bytesize);
    }
    return array;
}

static inline void generic_poly_set(poly_t c, const poly_t a, uint32_t degree) {
    memcpy(c, a, sizeof(felt_t)*(degree+1));
}

static inline void generic_poly_set_zero(poly_t c, uint32_t degree) {
    memset(c, 0, sizeof(felt_t)*(degree+1));
}

static inline void generic_poly_random(poly_t p, uint32_t degree) {
    for(uint32_t num=0; num<=degree; num++)
        felt_random(&p[num]);
}

static inline void generic_poly_add(poly_t c, const poly_t a, const poly_t b, uint32_t degree) {
    for(uint32_t num=0; num<=degree; num++)
        felt_add(&c[num], &a[num], &b[num]);
}

static inline void generic_poly_neg(poly_t c, const poly_t a, uint32_t degree) {
    for(uint32_t num=0; num<=degree; num++)
        felt_neg(&c[num], &a[num]);
}

static inline void generic_poly_sub(poly_t c, const poly_t a, const poly_t b, uint32_t degree) {
    for(uint32_t num=0; num<=degree; num++)
        felt_sub(&c[num], &a[num], &b[num]);
}

static inline void generic_poly_mul(poly_t c, const poly_t a, const poly_t b, uint32_t degree_a, uint32_t degree_b) {
    uint32_t degree_c = degree_a + degree_b;
    poly_t c_safe = generic_malloc_poly(degree_c);
    generic_poly_set_zero(c_safe, degree_c);
    for(uint32_t num=0; num<=degree_c; num++) {
        for(uint32_t i=0; (i<=num) && (i<=degree_a); i++) {
            uint32_t j=num-i;
            if(j > degree_b) { continue; }
            felt_mul_add(&c_safe[num], &a[i], &b[j]);
        }
    }
    generic_poly_set(c, c_safe, degree_c);
    free(c_safe);
}

static inline void generic_poly_mul_scalar(poly_t c, const poly_t a, const felt_t* b, uint32_t degree) {
    for(uint32_t num=0; num<=degree; num++)
        felt_mul(&c[num], &a[num], b);
}

static inline void generic_poly_eval(felt_t* eval, const poly_t p, const felt_t* eval_point, uint32_t degree) {
    felt_set(eval, &p[degree]);
    for(uint32_t num=1; num<=degree; num++) {
        felt_mul(eval, eval, eval_point);
        felt_add(eval, eval, &p[degree-num]);
    }
}

static inline void generic_poly_eval_multiple(vec_t* eval, const poly_t* polys, const vec_t eval_points, uint32_t degree, uint32_t nb_polys, uint32_t nb_evals) {
    // Precompute powers
    vec_t* powers = malloc_vec_array(nb_evals, degree+1);
    for(uint32_t num_eval=0; num_eval<nb_evals; num_eval++) {
        felt_set_one(&powers[num_eval][0]);
        for(uint32_t i=1; i<=degree; i++)
            felt_mul(&powers[num_eval][i], &powers[num_eval][i-1], &eval_points[num_eval]);
    }
    // Evaluate
    for(uint32_t num_eval=0; num_eval<nb_evals; num_eval++) {
        for(uint32_t j=0; j<nb_polys; j++) {
            felt_set(&eval[num_eval][j], &polys[j][0]);
            for(uint32_t i=1; i<=degree; i++)
                felt_mul_add(&eval[num_eval][j], &polys[j][i], &powers[num_eval][i]);
        }
    }
    free(powers);
}

static inline uint32_t generic_poly_get_bytesize(uint32_t degree) { 
    return vec_get_bytesize(degree+1);
}

static inline void generic_poly_serialize(uint8_t* buffer, const poly_t p, uint32_t degree) {
    vec_serialize(buffer, p, degree+1);
}

static inline void generic_poly_deserialize(poly_t p, const uint8_t* buffer, uint32_t degree) {
    vec_deserialize(p, buffer, degree+1);
}

static inline int generic_poly_is_equal(const vec_t a, const vec_t b, uint32_t degree) {
    for(uint32_t num=0; num<=degree; num++)
        if(!felt_is_equal(&a[num], &b[num]))
            return 0;
    return 1;
}

static inline void generic_poly_mul_linear_normalized(poly_t p_out, poly_t p_in, const felt_t* root, uint32_t degree) {
    felt_t neg_root, tmp;
    felt_neg(&neg_root, root);
    felt_set(&p_out[degree+1], &p_in[degree]);
    for(uint32_t i=0; i<degree; i++) {
        felt_set(&tmp, &p_in[degree-i]);
        felt_set(&p_out[degree-i], &p_in[degree-i-1]);
        felt_mul_add(&p_out[degree-i], &neg_root, &tmp);
    }
    felt_mul(&p_out[0], &neg_root, &p_in[0]);
}

static inline void generic_poly_set_vanishing(poly_t vanishing, const vec_t roots, uint32_t nb_roots) {
    generic_poly_set_zero(vanishing, nb_roots);
    felt_set_one(&vanishing[0]);
    for(uint32_t j=0; j<nb_roots; j++) {
        generic_poly_mul_linear_normalized(vanishing, vanishing, &roots[j], j);
    }
}

static inline void generic_poly_set_lagrange(poly_t lag, const vec_t points, uint32_t ind, uint32_t nb_points) {
    felt_t acc, tmp;
    generic_poly_set_zero(lag, nb_points-1);
    felt_set_one(&lag[0]);
    felt_set_one(&acc);
    for(uint32_t j=0; j<nb_points; j++) {
        if(j == ind)
            continue;
        generic_poly_mul_linear_normalized(lag, lag, &points[j], (j<ind) ? j : j-1);
        felt_sub(&tmp, &points[ind], &points[j]);
        felt_mul(&acc, &acc, &tmp);
    }
    felt_inv(&acc, &acc);
    generic_poly_mul_scalar(lag, lag, &acc, nb_points-1);
}

static inline void generic_poly_interpolate(poly_t p, const vec_t evals, const vec_t eval_points, uint32_t nb_evals) {
    uint32_t degree = nb_evals-1;
    generic_poly_set_zero(p, degree);
    poly_t lag = generic_malloc_poly(degree);
    felt_t acc, tmp;
    for(uint32_t i=0; i<nb_evals; i++) {
        generic_poly_set_zero(lag, degree);
        felt_set_one(&lag[0]);
        felt_set_one(&acc);
        for(uint32_t j=0; j<nb_evals; j++) {
            if(j == i)
                continue;
            generic_poly_mul_linear_normalized(lag, lag, &eval_points[j], (j<i) ? j : j-1);
            felt_sub(&tmp, &eval_points[i], &eval_points[j]);
            felt_mul(&acc, &acc, &tmp);
        }
        felt_inv(&acc, &acc);
        felt_mul(&acc, &acc, &evals[i]);
        generic_poly_mul_scalar(lag, lag, &acc, degree);
        generic_poly_add(p, p, lag, degree);
    }
    free(lag);
}

// If (X-alpha) divides P_in, returns P_in / (X-alpha)
static inline void generic_poly_remove_one_degree_factor(poly_t p_out, const poly_t p_in, felt_t* root, uint32_t in_degree) {
    felt_set(&p_out[in_degree-1], &p_in[in_degree]);
    for(int i=in_degree-2; i>=0; i--) {
        felt_set(&p_out[i], &p_in[i+1]);
        felt_mul_add(&p_out[i], root, &p_out[i+1]);
    }
}

static inline void generic_build_interpolation_material(const vec_t eval_points, vec_t* preprocessing, uint32_t nb_evals) {
    uint32_t degree = nb_evals-1;
    // Compute the vanishing polynomial
    poly_t vanishing = generic_malloc_poly(degree+1);
    generic_poly_set_vanishing(vanishing, eval_points, nb_evals);

    poly_t lag = generic_malloc_poly(degree);
    felt_t acc, tmp;
    for(uint32_t i=0; i<nb_evals; i++) {
        generic_poly_remove_one_degree_factor(lag, vanishing, &eval_points[i], degree+1);
        felt_set_one(&acc);
        for(uint32_t j=0; j<nb_evals; j++) {
            if(j == i)
                continue;
            felt_sub(&tmp, &eval_points[i], &eval_points[j]);
            felt_mul(&acc, &acc, &tmp);
        }
        felt_inv(&acc, &acc);
        generic_poly_mul_scalar(lag, lag, &acc, degree);
        for(uint32_t j=0; j<nb_evals; j++)
            felt_set(&preprocessing[j][i], &lag[j]);
    }
    free(lag);
    free(vanishing);
}

static inline void generic_poly_interpolate_with_preprocessing(poly_t p, const vec_t evals, vec_t const * const preprocessing, uint32_t nb_evals) {
    mat_vec_mul(p, preprocessing, evals, nb_evals, nb_evals);
}

static inline void generic_poly_interpolate_multiple_with_preprocessing(poly_t* p, const vec_t* evals, vec_t const * const preprocessing, uint32_t nb_evals, uint32_t nb_polys) {
    for(uint32_t k=0; k<nb_polys; k++)
        mat_vec_mul(p[k], preprocessing, evals[k], nb_evals, nb_evals);
}

static inline void generic_poly_interpolate_multiple(poly_t* p, const vec_t* evals, const vec_t eval_points, uint32_t nb_evals, uint32_t nb_polys) {
    vec_t* interpolation_material = malloc_vec_array(nb_evals, nb_evals);
    generic_build_interpolation_material(eval_points, interpolation_material, nb_evals);
    generic_poly_interpolate_multiple_with_preprocessing(p, evals, interpolation_material, nb_evals, nb_polys);
    free(interpolation_material);
}

static inline void generic_poly_restore(poly_t p, const vec_t high, const vec_t evals, const vec_t eval_points, uint32_t degree, uint32_t nb_evals) {
    vec_t shifted_evals = malloc_vec(nb_evals);
    for(uint32_t i=0; i<nb_evals; i++) {
        felt_t pow_eval;
        felt_set(&pow_eval, &eval_points[i]);
        for(uint32_t j=0; j<nb_evals-1; j++)
            felt_mul(&pow_eval, &pow_eval, &eval_points[i]);
        felt_t shift;
        generic_poly_eval(&shift, high, &eval_points[i], degree-nb_evals);
        felt_mul(&shift, &shift, &pow_eval);
        felt_sub(&shifted_evals[i], &evals[i], &shift);
    }
    generic_poly_set_zero(p, degree);
    generic_poly_interpolate(p, shifted_evals, eval_points, nb_evals);
    generic_poly_set(&p[nb_evals], high, degree-nb_evals);
    free(shifted_evals);
}

#endif /* __FIELD_POLY_GENERIC_H__ */

