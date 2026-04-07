#ifndef __FIELD_BASE_H__
#define __FIELD_BASE_H__

#include "field-base-struct.h"
#include <stdint.h>

/**
 * \struct felt_t
 * \ingroup arithmetic
 * \brief Field element
 * \headerfile ""
 */

/**
 * \brief Return the base-2 logarithm of field order
 * \relates felt_t
 * \return the base-2 logarithm of field order
 */
double felt_get_log2_field_order(void);

/**
 * \brief Print the field element
 * \relates felt_t
 * \param a the field element to print
 */
void felt_printf(const felt_t* a);

/**
 * \brief Sample a field element
 * \relates felt_t
 * \param a the sampled field element
 */
void felt_random(felt_t* a);

/*=================================================*
 *=====               SETTERS                 =====*
 *=================================================*/

/**
 * \brief Set a field element from another one
 * \relates felt_t
 * \param c the copied field element
 * \param a the field element to copy
 */
void felt_set(felt_t* c, const felt_t* a);

/**
 * \brief Set a field element from a 32-bit unsigned integer
 * \relates felt_t
 * \param c the set field element
 * \param a the unsigned integer to set
 */
void felt_from_uint32(felt_t* c, uint32_t a);

/**
 * \brief Convert a field element to a 32-bit unsigned integer, inverse operation of \ref felt_from_uint32
 * \relates felt_t
 * \param a the field element to convert
 * \return the unsigned integer
 */
uint32_t felt_to_uint32(const felt_t* a);

/**
 * \brief Set a field element as zero (the identity element for the additive operation)
 * \relates felt_t
 * \param c the set field element
 */
void felt_set_zero(felt_t* c);

/**
 * \brief Set a field element as one (the identity element for the multiplicative operation)
 * \relates felt_t
 * \param c the set field element
 */
void felt_set_one(felt_t* c);

/*=================================================*
 *=====                TESTS                  =====*
 *=================================================*/

/**
 * \brief Test whether a field element is zero 
 * \relates felt_t
 * \param a the field element to test
 * \return a non-zero value if the field element is zero, zero otherwise
 */
int felt_is_zero(const felt_t* a);

/**
 * \brief Test whether two field elements are equal
 * \relates felt_t
 * \param a the first tested field element
 * \param b the second tested field element
 * \return a non-zero value if the field elements are equal, zero otherwise
 */
int felt_is_equal(const felt_t* a, const felt_t* b);

/*=================================================*
 *=====              OPERATIONS               =====*
 *=================================================*/

/**
 * \brief Add two field elements (c = a + b)
 * \relates felt_t
 * \param c the addition result
 * \param a the first field element to add
 * \param b the second field element to add
 */
void felt_add(felt_t* c, const felt_t* a, const felt_t* b);

/**
 * \brief Negate a field element (c = -a)
 * \relates felt_t
 * \param c the negation result
 * \param a the field element to negate
 */
void felt_neg(felt_t* c, const felt_t* a);

/**
 * \brief Perform a substraction between two field elements (c = a - b)
 * \relates felt_t
 * \param c the substraction result
 * \param a the left-term field element of the substraction
 * \param b the right-term field element of the substraction
 */
void felt_sub(felt_t* c, const felt_t* a, const felt_t* b);

/**
 * \brief Multiply two field elements (c = a * b)
 * \relates felt_t
 * \param c the multiplication result
 * \param a the first field element to multiply
 * \param b the second field element to multiply
 */
void felt_mul(felt_t* c, const felt_t* a, const felt_t* b);

/**
 * \brief Multiply two field elements and add the result (c += a * b)
 * \relates felt_t
 * \param c the result (c += a*b)
 * \param a the first field element to multiply
 * \param b the second field element to multiply
 */
void felt_mul_add(felt_t* c, const felt_t* a, const felt_t* b);

/**
 * \brief Invert a field element (c = 1/a)
 * \relates felt_t
 * \param c the inversion result
 * \param a the field element to invert
 * 
 * The behavior for inverting a zero value is undefined.
 */
void felt_inv(felt_t* c, const felt_t* a);

/**
 * \brief Perform a division between two field elements (c = a / b)
 * \relates felt_t
 * \param c the division result
 * \param a the dividend
 * \param b the divisor
 *
 * The behavior when the divisor is zero is undefined.
 */
void felt_div(felt_t* c, const felt_t* a, const felt_t* b);

/*=================================================*
 *=====             SERIALIZATION             =====*
 *=================================================*/

/**
 * \brief Return the byte size of a serialized field element
 * \relates felt_t
 * \return a byte size
 */
uint32_t felt_get_bytesize(void);

/**
 * \brief Serialize a field element
 * \relates felt_t
 * \param buffer a byte array that contains the serialized field element
 * \param a the field element to serialize
 */
void felt_serialize(uint8_t* buffer, const felt_t* a);

/**
 * \brief Deserialize a field element
 * \relates felt_t
 * \param a the deserialized field element
 * \param buffer a byte array that contains the serialized field element
 */
void felt_deserialize(felt_t* a, const uint8_t* buffer);

#endif /* __FIELD_BASE_H__ */
