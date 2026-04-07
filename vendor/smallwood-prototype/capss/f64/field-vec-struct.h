#ifndef __FIELD_VEC_STRUCT_H__
#define __FIELD_VEC_STRUCT_H__

#include "field-vec-generic.h"
#define malloc_vec                generic_malloc_vec
#define malloc_vec_array          generic_malloc_vec_array
#define vec_random                generic_vec_random
#define vec_set                   generic_vec_set
#define vec_set_zero              generic_vec_set_zero
#define vec_add                   generic_vec_add
#define vec_neg                   generic_vec_neg
#define vec_sub                   generic_vec_sub
#define vec_mul                   generic_vec_mul
#define vec_scale                 generic_vec_scale
#define vec_serialize             generic_vec_serialize
#define vec_deserialize           generic_vec_deserialize
#define vec_get_bytesize          generic_vec_get_bytesize
#define vec_is_equal              generic_vec_is_equal
#define mat_mul                   generic_mat_mul
#define mat_vec_mul               generic_mat_vec_mul
#define mat_inv                   generic_mat_inv

#endif /* __FIELD_VEC_STRUCT_H__ */
