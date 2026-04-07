#ifndef __FIELD_VEC_GENERIC_H__
#define __FIELD_VEC_GENERIC_H__

#include "field-base-struct.h"

static inline vec_t generic_malloc_vec(uint32_t size) {
    return (vec_t) malloc(sizeof(felt_t)*size);
}

static inline vec_t* generic_malloc_vec_array(uint32_t array_size, uint32_t vec_size) {
    uint32_t first_dim_bytesize = array_size*sizeof(vec_t);
    uint32_t vec_bytesize = vec_size*sizeof(felt_t);
    uint8_t* ptr = malloc(first_dim_bytesize + array_size*vec_bytesize);
    vec_t* array = (vec_t*) ptr;
    if(ptr != NULL) {
        array[0] = (vec_t) (ptr + first_dim_bytesize);
        for(uint32_t num=1; num<array_size; num++)
            array[num] = (vec_t) (((uint8_t*) array[num-1]) + vec_bytesize);
    }
    return array;
}

static inline void generic_vec_random(vec_t v, uint32_t size) {
    for(uint32_t num=0; num<size; num++)
        felt_random(&v[num]);
}

static inline void generic_vec_set(vec_t c, const vec_t a, uint32_t size) {
    memcpy(c, a, sizeof(felt_t)*size);
}

static inline void generic_vec_set_zero(vec_t c, uint32_t size) {
    memset(c, 0, sizeof(felt_t)*size);
}

static inline void generic_vec_add(vec_t c, const vec_t a, const vec_t b, uint32_t size) {
    for(uint32_t num=0; num<size; num++)
        felt_add(&c[num], &a[num], &b[num]);
}

static inline void generic_vec_neg(vec_t c, const vec_t a, uint32_t size) {
    for(uint32_t num=0; num<size; num++)
        felt_neg(&c[num], &a[num]);
}

static inline void generic_vec_sub(vec_t c, const vec_t a, const vec_t b, uint32_t size) {
    for(uint32_t num=0; num<size; num++)
        felt_sub(&c[num], &a[num], &b[num]);
}

static inline void generic_vec_mul(vec_t c, const vec_t a, const vec_t b, uint32_t size) {
    for(uint32_t num=0; num<size; num++)
        felt_mul(&c[num], &a[num], &b[num]);
}

static inline void generic_vec_scale(vec_t c, const vec_t a, const felt_t* b, uint32_t size) {
    for(uint32_t num=0; num<size; num++)
        felt_mul(&c[num], &a[num], b);
}

static inline void generic_vec_serialize(uint8_t* buffer, const vec_t a, uint32_t size) {
    memcpy(buffer, a, size*sizeof(felt_t));
}

static inline void generic_vec_deserialize(vec_t a, const uint8_t* buffer, uint32_t size) {
    memcpy(a, buffer, size*sizeof(felt_t));
}

static inline uint32_t generic_vec_get_bytesize(uint32_t size) {
    return size*sizeof(felt_t);
}

static inline void generic_vec_serialize_from_field(uint8_t* buffer, const vec_t a, uint32_t size) {
    uint32_t chunk_size = felt_get_bytesize();
    for(uint32_t num=0; num<size; num++) {
        felt_serialize(buffer, &a[num]);
        buffer += chunk_size;
    }
}

static inline void generic_vec_deserialize_from_field(vec_t a, const uint8_t* buffer, uint32_t size) {
    uint32_t chunk_size = felt_get_bytesize();
    for(uint32_t num=0; num<size; num++) {
        felt_deserialize(&a[num], buffer);
        buffer += chunk_size;
    }
}

static inline uint32_t generic_vec_get_bytesize_from_field(uint32_t size) {
    return size*felt_get_bytesize();
}

static inline int generic_vec_is_equal(const vec_t a, const vec_t b, uint32_t size) {
    for(uint32_t num=0; num<size; num++)
        if(!felt_is_equal(&a[num], &b[num]))
            return 0;
    return 1;
}

static inline void generic_mat_mul(vec_t* c, const vec_t* a, const vec_t* b, uint32_t m, uint32_t n, uint32_t p) {
    for(uint32_t i=0; i<m; i++) {
        for(uint32_t k=0; k<p; k++) {
            felt_set_zero(&c[i][k]);
            for(uint32_t j=0; j<n; j++)
                felt_mul_add(&c[i][k], &a[i][j], &b[j][k]);
        }
    }
}

static inline void generic_mat_vec_mul(vec_t c, const vec_t* a, const vec_t b, uint32_t m, uint32_t n) {
    for(uint32_t i=0; i<m; i++) {
        felt_set_zero(&c[i]);
        for(uint32_t j=0; j<n; j++)
            felt_mul_add(&c[i], &a[i][j], &b[j]);
    }
}

static inline int generic_mat_inv(vec_t* inv, const vec_t* a, uint32_t n) {
    uint32_t i, j, k;
    vec_t tmp = generic_malloc_vec(n);
    vec_t* a_copy = generic_malloc_vec_array(n, n);
    for(i = 0; i < n; i++)
        generic_vec_set(a_copy[i], a[i], n);

    int ret = -1;

    // Initialize inv as the identity matrix
    for(i = 0; i < n; i++) {
        for(j = 0; j < n; j++) {
            if(i == j)
                felt_set_one(&inv[i][j]);
            else
                felt_set_zero(&inv[i][j]);
        }
    }

    // For each column
    for(i = 0; i < n; i++) {
        // Find the pivot
        uint32_t pivot_row = 0;
        for(k = i; k < n; k++) {
            if(!felt_is_zero(&a_copy[k][i])) {
                pivot_row = k;
                break;
            }
        }

        if(k == n) {
            // Non invertible
            goto err;
        }

        // Swap lines if necessary
        if(pivot_row != i) {
            generic_vec_set(tmp, a_copy[i], n);
            generic_vec_set(a_copy[i], a_copy[pivot_row], n);
            generic_vec_set(a_copy[pivot_row], tmp, n);

            generic_vec_set(tmp, inv[i], n);
            generic_vec_set(inv[i], inv[pivot_row], n);
            generic_vec_set(inv[pivot_row], tmp, n);
        }

        // Invert the pivot
        felt_t inv_pivot;
        felt_inv(&inv_pivot, &a_copy[i][i]);

        // Normalize the pivot line
        generic_vec_scale(a_copy[i], a_copy[i], &inv_pivot, n);
        generic_vec_scale(inv[i], inv[i], &inv_pivot, n);

        // Eliminate the other lines
        felt_t factor;
        for(k = 0; k < n; k++) {
            if(k != i) {
                felt_set(&factor, &a_copy[k][i]);

                generic_vec_scale(tmp, a_copy[i], &factor, n);
                generic_vec_sub(a_copy[k], a_copy[k], tmp, n);

                generic_vec_scale(tmp, inv[i], &factor, n);
                generic_vec_sub(inv[k], inv[k], tmp, n);
            }
        }
    }

    ret = 0;
err:
    free(tmp);
    free(a_copy);
    return ret;
}

#endif /* __FIELD_VEC_GENERIC_H__ */
