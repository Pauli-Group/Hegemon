#ifndef __FIELD_VEC_H__
#define __FIELD_VEC_H__

/**
 * \struct vec_t
 * \ingroup arithmetic
 * \brief Vector of field elements
 * \headerfile ""
 * 
 * The i-th coordinate of a vector v is accessible using v[i].
 */
typedef felt_t* vec_t;
#include "field-vec-struct.h"

/*=================================================*
 *=====              ALLOCATION               =====*
 *=================================================*/

/**
 * \brief Allocate a vector of the given length
 * \relates vec_t
 * \param size length of the vector
 * \return a vector of the right length, or NULL if the memory allocation failed
 * 
 * The vector can be desallocated using free.
 */
vec_t malloc_vec(uint32_t size);

/**
 * \brief Allocate a array of vectors
 * \relates vec_t
 * \param array_size size of the array
 * \param vec_size length of the vectors
 * \return a array of vectors, or NULL if the memory allocation failed
 *
 * The array can be desallocated using free.
 */
vec_t* malloc_vec_array(uint32_t array_size, uint32_t vec_size);

/*=================================================*
 *=====               SETTERS                 =====*
 *=================================================*/

/**
 * \brief Sample a vector of field elements
 * \relates vec_t
 * \param v the sampled vector
 * \param size length of the vector
 */
void vec_random(vec_t v, uint32_t size);

/**
 * \brief Set a vector from another one
 * \relates vec_t
 * \param c the copied vector
 * \param a the vector to copy
 * \param size length of the vector
 */
void vec_set(vec_t c, const vec_t a, uint32_t size);

/**
 * \brief Set a vector as zero
 * \relates vec_t
 * \param c the set vector
 * \param size length of the vector
 */
void vec_set_zero(vec_t c, uint32_t size);

/*=================================================*
 *=====                TESTS                  =====*
 *=================================================*/

/**
 * \brief Test whether two vectors are equal
 * \relates vec_t
 * \param a the first tested vector
 * \param b the second tested field vector
 * \param size length of the vectors
 * \return a non-zero value if the vectors are equal, zero otherwise
 */
int vec_is_equal(const vec_t a, const vec_t b, uint32_t size);

/*=================================================*
 *=====              OPERATIONS               =====*
 *=================================================*/

/**
 * \brief Add two vectors (c = a + b)
 * \relates vec_t
 * \param c the addition result
 * \param a the first vector to add
 * \param b the second vector to add
 * \param size length of the vectors
 */
void vec_add(vec_t c, const vec_t a, const vec_t b, uint32_t size);

/**
 * \brief Negate a vector (c = -a)
 * \relates vec_t
 * \param c the negation result
 * \param a the vector to negate
 * \param size length of the vector
 */
void vec_neg(vec_t c, const vec_t a, uint32_t size);

/**
 * \brief Perform a substraction between two vectors (c = a - b)
 * \relates vec_t
 * \param c the substraction result
 * \param a the left-term vector of the substraction
 * \param b the right-term vector of the substraction
 * \param size length of the vectors
 */
void vec_sub(vec_t c, const vec_t a, const vec_t b, uint32_t size);

/**
 * \brief Multiply two vectors coordinate-wise (c = a * b)
 * \relates vec_t
 * \param c the multiplication result
 * \param a the first vector to multiply
 * \param b the second vector to multiply
 * \param size length of the vectors
 */
void vec_mul(vec_t c, const vec_t a, const vec_t b, uint32_t size);

/**
 * \brief Multiply a vector with a field element (c = a * b)
 * \relates vec_t
 * \param c the multiplication result
 * \param a the vector to multiply
 * \param b the field element to multiply
 * \param size length of the vector
 */
void vec_scale(vec_t c, const vec_t a, const felt_t* b, uint32_t size);

/*=================================================*
 *=====             SERIALIZATION             =====*
 *=================================================*/

/**
 * \brief Return the byte size of a serialized vector
 * \relates vec_t
 * \param size length of the vector
 * \return a byte size
 */
uint32_t vec_get_bytesize(uint32_t size);

/**
 * \brief Serialize a vector
 * \relates vec_t
 * \param buffer a byte array that contains the serialized vector
 * \param a the vector to serialize
 * \param size length of the vector
 */
void vec_serialize(uint8_t* buffer, const vec_t a, uint32_t size);

/**
 * \brief Deserialize a vector
 * \relates vec_t
 * \param a the deserialized vector
 * \param buffer a byte array that contains the serialized vector
 * \param size length of the vector
 */
void vec_deserialize(vec_t a, const uint8_t* buffer, uint32_t size);

/*=================================================*
 *=====           MATRIX OPERATIONS           =====*
 *=================================================*/

/**
 * \brief Multiply two matrices (c = a * b)
 * \relates vec_t
 * \param c the product matrix (as an array of vectors, in row-major order)
 * \param a the first matrix to multiply (as an array of vectors, in row-major order)
 * \param b the second matrix to multiply (as an array of vectors, in row-major order)
 * \param m the number of rows of the first matrix
 * \param n the number of columns of the first matrix = number of rows of the second matrix
 * \param p the number of columns of the second matrix
 */
void mat_mul(vec_t* c, const vec_t* a, const vec_t* b, uint32_t m, uint32_t n, uint32_t p);

/**
 * \brief Multiply a matrix with a vector (c = a * b)
 * \relates vec_t
 * \param c the result vector
 * \param a the matrix to multiply (as an array of vectors, in row-major order)
 * \param b the vector to multiply
 * \param m the number of rows of the matrix
 * \param n the number of columns of the matrix
 */
void mat_vec_mul(vec_t c, const vec_t* a, const vec_t b, uint32_t m, uint32_t n);

/**
 * \brief Invert a square matrix (c = a^{-1})
 * \relates vec_t
 * \param inv the inverted matrix (as an array of vectors, in row-major order)
 * \param a the matrix to invert (as an array of vectors, in row-major order)
 * \param n the number of rows/columns of the matrix
 * \return 0 if the inversion is successful, a non-zero value otherwise
 */
int mat_inv(vec_t* inv, const vec_t* a, uint32_t n);

#endif /* __FIELD_VEC_H__ */
