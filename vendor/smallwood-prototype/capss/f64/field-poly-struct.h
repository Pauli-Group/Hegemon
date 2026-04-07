#ifndef __FIELD_POLY_STRUCT_H__
#define __FIELD_POLY_STRUCT_H__

#include "field-poly-generic.h"
#define malloc_poly                generic_malloc_poly
#define malloc_poly_array          generic_malloc_poly_array
#define poly_set                   generic_poly_set
#define poly_set_zero              generic_poly_set_zero
#define poly_random                generic_poly_random
#define poly_add                   generic_poly_add
#define poly_neg                   generic_poly_neg
#define poly_sub                   generic_poly_sub
#define poly_mul                   generic_poly_mul
#define poly_mul_scalar            generic_poly_mul_scalar
#define poly_eval                  generic_poly_eval
#define poly_eval_multiple         generic_poly_eval_multiple
#define poly_get_bytesize          generic_poly_get_bytesize
#define poly_serialize             generic_poly_serialize
#define poly_deserialize           generic_poly_deserialize
#define poly_is_equal              generic_poly_is_equal
#define poly_mul_linear_normalized generic_poly_mul_linear_normalized
#define poly_set_vanishing         generic_poly_set_vanishing
#define poly_set_lagrange          generic_poly_set_lagrange
#define poly_interpolate           generic_poly_interpolate
#define poly_remove_one_degree_factor generic_poly_remove_one_degree_factor
#define build_interpolation_material generic_build_interpolation_material
#define poly_interpolate_with_preprocessing generic_poly_interpolate_with_preprocessing
#define poly_interpolate_multiple_with_preprocessing generic_poly_interpolate_multiple_with_preprocessing
#define poly_interpolate_multiple  generic_poly_interpolate_multiple
#define poly_restore               generic_poly_restore

#endif /* __FIELD_POLY_STRUCT_H__ */

