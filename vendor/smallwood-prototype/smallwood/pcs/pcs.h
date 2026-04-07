#ifndef __PCS_H__
#define __PCS_H__

#include "field.h"
#include "parameters.h"
#include "merkle.h"

/*!
 * \defgroup pcs Polynomial Commitment Schemes
 * \brief All the structures to commit to polynomials
 */

/**
 * \struct pcs_cfg_t
 * \brief Configuration of a polynomial commitment scheme (PCS)
 * \headerfile ""
 * 
 * This data structure contains all the configurable parameters of the
 * polynomial commitment scheme, enabling us to instantiate concrete
 * PCS instances.
 */
typedef struct {
    /*! \brief Number of committed polynomials
     *
     * Should be a non-zero value.
     */
    uint32_t nb_polys;

    /*! \brief Degrees of the committed polynomials
     *
     * Should be an array of length \ref nb_polys
     */
    uint32_t* degree;

    /*! \brief Number of the opened evaluations
     */
    uint32_t nb_opened_evals;

    /*! \brief Number of coefficients rows in PCS matrices
     */
    uint32_t mu;

    /*! \brief PCS stacking factor
     */
    uint32_t beta;

    /*! \brief Number of the openable evaluations in the used DECS
     *
     * Should be a non-zero value.
     */
    uint32_t decs_nb_evals;

    /*! \brief Number of the opened evaluations in the used DECS
     *
     * Should be smaller than (or equal to) \ref decs_nb_evals
     */
    uint32_t decs_nb_opened_evals;

    /*! \brief Number of repetitions of the DEC test
     */
    uint32_t decs_eta;

    /*! \brief The size in bits of the proof of work in the used DECS
     */
    uint32_t decs_pow_bits;

    /*! \brief Indicate whatever the leave hash include some random tapes
     *    in the used DECS
     */
    uint32_t decs_use_commitment_tapes;

    /*! \brief Format of the DEC challenge
     *
     * C.f. \ref decs_cfg_t.format_challenge
     */
    uint32_t decs_format_challenge;

    /*! \brief Configuration of the used Merkle tree
     *
     * C.f. \ref decs_cfg_t.tree_cfg
     */
    merkle_tree_cfg_t* decs_tree_cfg;
} pcs_cfg_t;

/**
 * \struct pcs_t
 * \ingroup pcs
 * \brief Instance of a PCS scheme
 * \headerfile ""
 */
typedef struct pcs_t pcs_t;

/**
 * \struct pcs_key_t
 * \brief Structure that represents an opening key of a PCS scheme
 * \headerfile ""
 */
typedef struct pcs_key_t pcs_key_t;

/**
 * \brief Return the byte size of the corresponding PCS scheme (pcs_t)
 * \relates pcs_t
 * \param pcs_cfg a PCS configuration
 * \return a byte size
 */
uint32_t pcs_alloc_bytesize(const pcs_cfg_t* pcs_cfg);

/**
 * \brief Initialize a PCS scheme using the provided configuration
 * \relates pcs_t
 * \param pcs a (empty) PCS scheme
 * \param pcs_cfg a PCS configuration
 * \return 0 if the initialization was successful, otherwise a non-zero value
 * 
 * The pointer \ref pcs should point to a allocated memory
 *  area of size provided by \ref pcs_alloc_bytesize
 */
int pcs_init(pcs_t* pcs, const pcs_cfg_t* pcs_cfg);

/**
 * \brief Allocate a PCS scheme using the provided configuration
 * \relates pcs_t
 * \param pcs_cfg a PCS configuration
 * \return a PCS instance
 */
pcs_t* malloc_pcs(const pcs_cfg_t* pcs_cfg);

/**
 * \brief Return the byte size of the transcript provided by \ref pcs_commit
 * \relates pcs_t
 * \param pcs a PCS instance
 * \return a byte size
 */
uint32_t pcs_get_transcript_size(const pcs_t* pcs);

/**
 * \brief Return the byte size of the key of the PCS scheme (\ref pcs_key_t)
 * \relates pcs_key_t
 * \param pcs a PCS instance
 * \return a byte size
 */
uint32_t pcs_get_key_bytesize(const pcs_t* pcs);

/**
 * \brief Return the maximal byte size of the opening proof output by \ref pcs_open
 * \relates pcs_t
 * \param pcs a PCS instance
 * \return a byte size
 */
uint32_t pcs_max_sizeof_proof(const pcs_t* pcs);

/**
 * \brief Commit to polynomials using the provided PCS instance
 * \relates pcs_t
 * \param pcs a PCS instance
 * \param salt a salt of PARAM_SALT_SIZE bytes, can be a null pointer
 * \param polys array of polynomials of length "nb_polys" and of degrees "degree"
 * \param transcript output transcript, should point to a allocated memory area of size provided by \ref pcs_get_transcript_size
 * \param key output key, should point to a allocated memory area of size provided by \ref pcs_get_key_bytesize
 * \return 0 if the commitment was successful, otherwise a non-zero value
 */
int pcs_commit(const pcs_t* pcs, const uint8_t salt[PARAM_SALT_SIZE], poly_t const* const polys, uint8_t* transcript, pcs_key_t* key);

/**
 * \brief Open some evaluations of the committed polynomials
 * \relates pcs_t
 * \param pcs a PCS instance
 * \param key should be a opened key provided by \ref pcs_commit using the same PCS instance
 * \param eval_points a vector of length "nb_opened_evals"
 * \param prtranscript a byte string of size \p prtranscript_bytesize, the opening is binded to this string
 * \param prtranscript_bytesize the size of the byte string \p prtranscript
 * \param evals an 2D array of field elements of dimensions (nb_opened_evals, nb_polys)
 * \param proof_size will contain the size of the output opening proof
 * \return the opening proof if the opening was successful, otherwise NULL
 */
uint8_t* pcs_open(const pcs_t* pcs, const pcs_key_t* key, const vec_t eval_points, const uint8_t* prtranscript, uint32_t prtranscript_bytesize, felt_t** evals, uint32_t* proof_size);

/**
 * \brief Recompute the commitment transcript from an opening proof
 * \relates pcs_t
 * \param pcs a PCS instance
 * \param salt a salt of PARAM_SALT_SIZE bytes, can be a null pointer (refer to the same salt used in \ref pcs_commit)
 * \param eval_points refers to the opened evaluation points used to produce the opening proof with \ref pcs_open
 * \param prtranscript a byte string of size \p prtranscript_bytesize, used for the opening
 * \param prtranscript_bytesize the size of the byte string \p prtranscript
 * \param evals refers to the opened evaluations of the committed polynomials
 * \param proof is the opening proof outputted by \ref pcs_open
 * \param proof_size the byte size of the opening proof
 * \param transcript the re-computed transcript
 * \return 0 if the transcript recomputation was successful, otherwise a non-zero value
 */
int pcs_recompute_transcript(const pcs_t* pcs, const uint8_t salt[PARAM_SALT_SIZE], const vec_t eval_points, const uint8_t* prtranscript, uint32_t prtranscript_bytesize, felt_t* const* const evals, const uint8_t* proof, uint32_t proof_size, uint8_t* transcript);

#endif /* __PCS_H__ */
