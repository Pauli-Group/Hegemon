#ifndef __FIELD_POLY_H__
#define __FIELD_POLY_H__

/**
 * \struct poly_t
 * \ingroup arithmetic
 * \brief Polynomials with field elements as coefficients
 * \headerfile ""
 * 
 * The polynomial is represented as the vector of its coefficients.
 */
typedef vec_t poly_t;
#include "field-poly-struct.h"

/*=================================================*
 *=====              ALLOCATION               =====*
 *=================================================*/

/**
 * \brief Allocate a polynomial of the given degree
 * \relates poly_t
 * \param degree degree of the polynomial
 * \return a polynomial of the right degree, or NULL if the memory allocation failed
 * 
 * The polynomial can be desallocated using free.
 */
poly_t malloc_poly(uint32_t degree);

/**
 * \brief Allocate a array of polynomials
 * \relates poly_t
 * \param array_size size of the array
 * \param degree length of the polynomials
 * \return a array of polynomials, or NULL if the memory allocation failed
 *
 * The array can be desallocated using free.
 */
poly_t* malloc_poly_array(uint32_t array_size, uint32_t degree);

/*=================================================*
 *=====               SETTERS                 =====*
 *=================================================*/

/**
 * \brief Sample a polynomial
 * \relates poly_t
 * \param p the sampled polynomial
 * \param degree degree of the polynomial
 */
void poly_random(poly_t p, uint32_t degree);
 
/**
 * \brief Set a polynomial from another one
 * \relates poly_t
 * \param c the copied polynomial
 * \param a the polynomial to copy
 * \param degree degree of the polynomial
 */
void poly_set(poly_t c, const poly_t a, uint32_t degree);

/**
 * \brief Set a polynomial as zero
 * \relates poly_t
 * \param c the set polynomial
 * \param degree degree of the polynomial
 */
void poly_set_zero(poly_t c, uint32_t degree);

/*=================================================*
 *=====                TESTS                  =====*
 *=================================================*/

/**
 * \brief Test whether two polynomials are equal
 * \relates poly_t
 * \param a the first tested polynomial
 * \param b the second tested polynomial
 * \param degree degree of the polynomials
 * \return a non-zero value if the polynomials are equal, zero otherwise
 */
int poly_is_equal(const vec_t a, const vec_t b, uint32_t degree);

/*=================================================*
 *=====              OPERATIONS               =====*
 *=================================================*/

/**
 * \brief Add two polynomials (c = a + b)
 * \relates poly_t
 * \param c the addition result
 * \param a the first polynomial to add
 * \param b the second polynomial to add
 * \param degree degree of the polynomials
 */
void poly_add(poly_t c, const poly_t a, const poly_t b, uint32_t degree);

/**
 * \brief Negate a polynomial (c = -a)
 * \relates poly_t
 * \param c the negation result
 * \param a the polynomial to negate
 * \param degree degree of the polynomial
 */
void poly_neg(poly_t c, const poly_t a, uint32_t degree);

/**
 * \brief Perform a substraction between two polynomials (c = a - b)
 * \relates poly_t
 * \param c the substraction result
 * \param a the left-term polynomial of the substraction
 * \param b the right-term polynomial of the substraction
 * \param degree degree of the polynomials
 */
void poly_sub(poly_t c, const poly_t a, const poly_t b, uint32_t degree);

/**
 * \brief Multiply two polynomials (c = a * b)
 * \relates poly_t
 * \param c the multiplication result
 * \param a the first polynomial to multiply
 * \param b the second polynomial to multiply
 * \param degree_a degree of the first polynomial
 * \param degree_b degree of the second polynomial
 */
void poly_mul(poly_t c, const poly_t a, const poly_t b, uint32_t degree_a, uint32_t degree_b);


/**
 * \brief Multiply a polynomial with a field element (c = a * b)
 * \relates poly_t
 * \param c the multiplication result
 * \param a the polynomial to multiply
 * \param b the field element to multiply
 * \param degree degree of the polynomial
 */
void poly_mul_scalar(poly_t c, const poly_t a, const felt_t* b, uint32_t degree);

/*=================================================*
 *=====             SERIALIZATION             =====*
 *=================================================*/

 /**
 * \brief Return the byte size of a serialized polynomial
 * \relates poly_t
 * \param degree degree of the polynomial
 * \return a byte size
 */
uint32_t poly_get_bytesize(uint32_t degree);

/**
 * \brief Serialize a polynomial
 * \relates poly_t
 * \param buffer a byte array that contains the serialized polynomial
 * \param p the polynomial to serialize
 * \param degree degree of the polynomial
 */
void poly_serialize(uint8_t* buffer, const poly_t p, uint32_t degree);

/**
 * \brief Deserialize a polynomial
 * \relates poly_t
 * \param p the deserialized polynomial
 * \param buffer a byte array that contains the serialized polynomial
 * \param degree degree of the polynomial
 */
void poly_deserialize(poly_t p, const uint8_t* buffer, uint32_t degree);

/*=================================================*
 *=====              EVALUATION               =====*
 *=================================================*/

/**
 * \brief Evaluate a polynomial
 * \relates poly_t
 * \param eval the polynomial evaluation
 * \param p the polynomial to evaluate
 * \param eval_point the evaluation point
 * \param degree degree of the polynomial
 */
void poly_eval(felt_t* eval, const poly_t p, const felt_t* eval_point, uint32_t degree);

/**
 * \brief Evaluate several polynomials into several evaluation points
 * \relates poly_t
 * \param eval the array of evaluations, eval[i][j] refers to the evaluation of the j-th polynomial into the i-th evaluation point
 * \param polys an array of polynomials
 * \param eval_points a vector of evaluation points
 * \param degree degree of the polynomials
 * \param nb_polys number of polynomials
 * \param nb_evals number of evaluation points
 */
void poly_eval_multiple(vec_t* eval, const poly_t* polys, const vec_t eval_points, uint32_t degree, uint32_t nb_polys, uint32_t nb_evals);

/*=================================================*
 *=====             INTERPOLATION             =====*
 *=================================================*/

 /**
 * \brief Get the (normalized) vanishing polynomial that corresponds to the given roots
 * \relates poly_t
 * \param vanishing the vanishing polynomial
 * \param roots the roots of the vanishing polynomial
 * \param nb_roots number of roots
 */
void poly_set_vanishing(poly_t vanishing, const vec_t roots, uint32_t nb_roots);

/**
 * \brief Get a Lagrange polynomial
 * \relates poly_t
 * \param lag the Lagrange polynomial
 * \param points the evaluation points
 * \param ind index of the Lagrange points
 * \param nb_points number of evaluation points
 */
void poly_set_lagrange(poly_t lag, const vec_t points, uint32_t ind, uint32_t nb_points);

/**
 * \brief Multiply a polynomial with (X-root)
 * \relates poly_t
 * \param p_out the multiplication result
 * \param p_in the polynomial to multiply
 * \param root the root of the second polynomial (X-root) to multiply
 * \param degree degree of the polynomial to multiply
 */
void poly_mul_linear_normalized(poly_t p_out, poly_t p_in, const felt_t* root, uint32_t degree);

/**
 * \brief Divide a polynomial by (X-root), assuming root is a root of this polynomial
 * \relates poly_t
 * \param p_out the quotient polynomial
 * \param p_in the dividend polynomial
 * \param root the root of the divisor polynomial
 * \param in_degree degree of the dividend polynomial
 */
void poly_remove_one_degree_factor(poly_t p_out, const poly_t p_in, felt_t* root, uint32_t in_degree);

/**
 * \brief Interpolate a polynomial
 * \relates poly_t
 * \param p the interpolated polynomial
 * \param evals the polynomial evaluations
 * \param eval_points the evaluation points
 * \param nb_evals number of evaluations
 */
void poly_interpolate(poly_t p, const vec_t evals, const vec_t eval_points, uint32_t nb_evals);

/**
 * \brief Interpolate several polynomials
 * \relates poly_t
 * \param p the interpolated polynomials
 * \param evals array of polynomial evaluations
 * \param eval_points the evaluation points
 * \param nb_evals number of evaluations
 * \param nb_polys number of polynomials
 */
void poly_interpolate_multiple(poly_t* p, const vec_t* evals, const vec_t eval_points, uint32_t nb_evals, uint32_t nb_polys);

/**
 * \brief Preprocess the evaluation points for interpolation
 * \relates poly_t
 * \param eval_points the evaluation points
 * \param preprocessing the preprocessing material, an array of vectors of dimensions (nb_evals, nb_evals)
 * \param nb_evals number of evaluations
 */
void build_interpolation_material(const vec_t eval_points, vec_t* preprocessing, uint32_t nb_evals);

/**
 * \brief Interpolate a polynomial using the preprocessing material
 * \relates poly_t
 * \param p the interpolated polynomial
 * \param evals the polynomial evaluations
 * \param preprocessing the preprocessing material, an array of vectors of dimensions (nb_evals, nb_evals)
 * \param nb_evals number of evaluations
 */
void poly_interpolate_with_preprocessing(poly_t p, const vec_t evals, vec_t const * const preprocessing, uint32_t nb_evals);

/**
 * \brief Interpolate several polynomials using the preprocessing material
 * \relates poly_t
 * \param p the interpolated polynomials
 * \param evals array of polynomial evaluations
 * \param preprocessing the preprocessing material, an array of vectors of dimensions (nb_evals, nb_evals)
 * \param nb_evals number of evaluations
 * \param nb_polys number of polynomials
 */
void poly_interpolate_multiple_with_preprocessing(poly_t* p, const vec_t* evals, vec_t const * const preprocessing, uint32_t nb_evals, uint32_t nb_polys);

/**
 * \brief Interpolate a polynomial with given leading coefficients
 * \relates poly_t
 * \param p the interpolated polynomial
 * \param high the leading coefficients of the polynomial
 * \param evals the polynomial evaluations
 * \param eval_points the evaluation points
 * \param degree degree of the interpolated polynomial
 * \param nb_evals number of evaluations
 */
void poly_restore(poly_t p, const vec_t high, const vec_t evals, const vec_t eval_points, uint32_t degree, uint32_t nb_evals);

#endif /* __FIELD_POLY_H__ */
