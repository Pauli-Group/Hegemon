#ifndef __LPPC_H__
#define __LPPC_H__

#include <stdint.h>
#include "field.h"

/**
 * \struct lppc_t
 * \ingroup proof
 * \brief Instance of a generic LPPC statement
 * \headerfile ""
 */
typedef struct lppc_t lppc_t;

typedef struct lppc_cfg_t lppc_cfg_t;

/**
 * \struct lppc_cfg_t
 * \brief Configuration of a LPPC statement
 * \headerfile ""
 */
struct lppc_cfg_t {
    /*! \brief Number of rows in the matrix witness
     */
    uint32_t nb_wit_rows;

    /*! \brief Packing factor (numbers of columns in the matrix witness)
     */
    uint32_t packing_factor;

    /*! \brief Degree of the polynomial contraints
     */
    uint32_t constraint_degree;

    /*! \brief Number of the (parallel) polynomial contraints
     */
    uint32_t nb_poly_constraints;

    /*! \brief Number of the linear contraints
     */
    uint32_t nb_linear_constraints;

    /*! \brief Function that returns the byte size of the preprocessing material to evaluate constraints
     */
    uint32_t (*get_preprocessing_material_bytesize)(const lppc_cfg_t*);

    /*! \brief Function that preprocess the packing points
     */
    void (*preprocess_packing_points)(const lppc_cfg_t*, const vec_t, uint8_t*);

    /*! \brief Function that evaluate a polynomial constraint where the witness is represented as polynomials
     */
    void (*get_constraint_pol_polynomials)(const lppc_t*, const poly_t*, const uint8_t*, poly_t*, uint32_t);

    /*! \brief Function that evaluate a linear constraint where the witness is represented as polynomials
     */
    void (*get_constraint_lin_polynomials)(const lppc_t*, const poly_t*, const uint8_t*, poly_t*, uint32_t);

    /*! \brief Function that evaluate all the linear constraints where the witness is represented as polynomials
     */
    void (*get_constraint_lin_polynomials_batched)(const lppc_t* lppc, const poly_t*, const uint8_t*, const vec_t*, poly_t*, uint32_t, uint32_t);

    /*! \brief Function that returns the (public) outputs of the linear constraints
     */
    void (*get_linear_result)(const lppc_t*, vec_t);
    
    /*! \brief Function that evaluate a polynomial constraint where the witness is represented as evaluations
     */
    void (*get_constraint_pol_evals)(const lppc_t*, const vec_t, const vec_t*, const uint8_t*, uint32_t, vec_t*);

    /*! \brief Function that evaluate a linear constraint where the witness is represented as evaluations
     */
    void (*get_constraint_lin_evals)(const lppc_t*, const vec_t, const vec_t*, const uint8_t*, uint32_t, vec_t*);
};

/**
 * \brief Return the size (in field elements) of the matrix witness
 * \relates lppc_cfg_t
 * \param lppc_cfg a configuration of a LPPC statement
 * \return the size in field elements
 */
static inline uint32_t lppc_get_witness_size(const lppc_cfg_t* lppc_cfg) {
    return lppc_cfg->nb_wit_rows*lppc_cfg->packing_factor;
}

/**
 * \brief Return the configuration of a LPPC statement
 * \relates lppc_t
 * \param lppc an instance of a LPPC statement
 * \return a configuration of a LPPC statement
 */
static inline const lppc_cfg_t* lppc_get_config(const lppc_t* lppc) {
    return (const lppc_cfg_t*) lppc;
}

/**
 * \brief Test if the given vector is a valid witness for the LPPC statement
 * \relates lppc_t
 * \param lppc an instance of a LPPC statement
 * \param witness the tested vector as witness
 * \return 0 if the given vector is indeed a valid witness, a non-zero value otherwise
 */
int lppc_test_witness(const lppc_t* lppc, const vec_t witness);

#endif /* __LPPC_H__ */
