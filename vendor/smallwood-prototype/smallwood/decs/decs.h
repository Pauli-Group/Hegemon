#ifndef __DECS_H__
#define __DECS_H__

#include "field.h"
#include "merkle.h"

/**
 * \struct decs_cfg_t
 * \brief Configuration of a degree-enforcing commitment scheme (DECS)
 * \headerfile ""
 * 
 * This data structure contains all the configurable parameters of DECS,
 * enabling us to instantiate concrete DECS instances.
 */
typedef struct {
    /*! \brief Number of committed polynomials
     *
     * Should be a non-zero value.
     */
    uint32_t nb_polys;

    /*! \brief Degree of the committed polynomials
     */
    uint32_t poly_degree;

    /*! \brief Number of the openable evaluations
     *
     * Should be a non-zero value.
     */
    uint32_t nb_evals;

    /*! \brief Number of the opened evaluations
     *
     * Should be smaller than (or equal to) \ref nb_evals
     */
    uint32_t nb_opened_evals;

    /*! \brief Number of repetitions of the DEC test
     */
    uint32_t eta;

    /*! \brief The size in bits of the proof of work
     */
    uint32_t pow_bits;

    /*! \brief Indicate whatever the leave hash include some random tapes
     */
    uint32_t use_commitment_tapes;

    /*! \brief Format of the DEC challenge
     *
     * Possible options:
     *  - 0: the coefficients are powers of a random value
     *  - 1: the coefficients are uniformly random
     *  - 2: hybrid, the coefficients are small random linear combinations of powers
     */
    uint32_t format_challenge;

    /*! \brief Configuration of the used Merkle tree
     *
     * Optional value. By default, it will be a binary tree
     * that matches the number of evaluations. 
     */
    merkle_tree_cfg_t* tree_cfg;
} decs_cfg_t;

/**
 * \struct decs_t
 * \ingroup pcs
 * \brief Instance of a DECS scheme
 * \headerfile ""
 */
typedef struct decs_t decs_t;

/**
 * \struct decs_key_t
 * \brief Structure that represents an opening key of a DECS scheme
 * \headerfile ""
 */
typedef struct decs_key_t decs_key_t;

/**
 * \brief Return the byte size of the corresponding DECS scheme (decs_t)
 * \relates decs_t
 * \param decs_cfg a DECS configuration
 * \return a byte size
 */
uint32_t decs_alloc_bytesize(const decs_cfg_t* decs_cfg);

/**
 * \brief Initialize a DECS scheme using the provided configuration
 * \relates decs_t
 * \param decs a (empty) DECS scheme
 * \param decs_cfg a DECS configuration
 * \return 0 if the initialization was successful, otherwise a non-zero value
 * 
 * The pointer \p decs should point to a allocated memory
 *  area of size provided by \ref decs_alloc_bytesize
 */
int decs_init(decs_t* decs, const decs_cfg_t* decs_cfg);

/**
 * \brief Allocate a DECS scheme using the provided configuration
 * \relates decs_t
 * \param decs_cfg a DECS configuration
 * \return a DECS instance
 */
decs_t* malloc_decs(const decs_cfg_t* decs_cfg);

/**
 * \brief Return the byte size of the transcript provided by \ref decs_commit
 * \relates decs_t
 * \param decs a DECS instance
 * \return a byte size
 */
uint32_t decs_get_transcript_size(const decs_t* decs);

/**
 * \brief Return the byte size of the key of the DECS scheme (\ref decs_key_t)
 * \relates decs_key_t
 * \param decs a DECS instance
 * \return a byte size
 */
uint32_t decs_get_key_bytesize(const decs_t* decs);

/**
 * \brief Return the maximal byte size of the opening proof output by \ref decs_open
 * \relates decs_t
 * \param decs a DECS instance
 * \return a byte size
 */
uint32_t decs_max_sizeof_proof(const decs_t* decs);

/**
 * \brief Commit to polynomials using the provided DECS instance
 * \relates decs_t
 * \param decs a DECS instance
 * \param salt a salt of PARAM_SALT_SIZE bytes, can be a null pointer
 * \param polys array of polynomials of length "nb_polys" and of degree "poly_degree"
 * \param transcript output transcript, should point to a allocated memory area of size provided by \ref decs_get_transcript_size
 * \param key output key, should point to a allocated memory area of size provided by \ref decs_get_key_bytesize
 * \return 0 if the commitment was successful, otherwise a non-zero value
 */
int decs_commit(const decs_t* decs, const uint8_t salt[PARAM_SALT_SIZE], const poly_t* polys, uint8_t* transcript, decs_key_t* key);

/**
 * \brief Open some evaluations of the committed polynomials
 * \relates decs_t
 * \param decs a DECS instance
 * \param key should be a opened key provided by \ref decs_commit using the same DECS scheme
 * \param eval_points a vector of length "nb_opened_evals"
 * \param evals an 2D array of field elements of dimensions (nb_opened_evals, nb_polys)
 * \param proof_size will contain the size of the output opening proof
 * \return the opening proof if the opening was successful, otherwise NULL
 */
uint8_t* decs_open(const decs_t* decs, const decs_key_t* key, const vec_t eval_points, felt_t** evals, uint32_t* proof_size);

/**
 * \brief Recompute the commitment transcript from an opening proof
 * \relates decs_t
 * \param decs a DECS instance
 * \param salt a salt of PARAM_SALT_SIZE bytes, can be a null pointer (refer to the same salt used in \ref decs_commit)
 * \param eval_points refers to the opened evaluation points used to produce the opening proof with \ref decs_open
 * \param evals refers to the opened evaluations of the committed polynomials
 * \param proof is the opening proof outputted by \ref decs_open
 * \param proof_size the byte size of the opening proof
 * \param transcript the re-computed transcript
 * \return 0 if the transcript recomputation was successful, otherwise a non-zero value
 */
int decs_recompute_transcript(const decs_t* decs, const uint8_t salt[PARAM_SALT_SIZE], const vec_t eval_points, felt_t* const* const evals, const uint8_t* proof, uint32_t proof_size, uint8_t* transcript);

/**
 * \brief Compute an opening challenge from a hash digest using a proof of work of "pow_bits" bits
 * \relates decs_t
 * \param decs a DECS instance
 * \param trans_hash a hash digest
 * \param eval_points the outputted evaluation points
 * \param nonce the outputted proof-of-work nonce
 * \return 0 if successful, otherwise a non-zero value
 */
int decs_get_opening_challenge(const decs_t* decs, const uint8_t trans_hash[PARAM_DIGEST_SIZE], vec_t eval_points, uint8_t nonce[NONCE_BYTESIZE]);

/**
 * \brief Recompute an opening challenge from a hash digest and a proof-of-work nonce
 * \relates decs_t
 * \param decs a DECS instance
 * \param trans_hash a hash digest
 * \param nonce a proof-of-work nonce
 * \param eval_points the outputted evaluation points
 * \return 0 if successful, otherwise a non-zero value
 */
int decs_recompute_opening_challenge(const decs_t* decs, const uint8_t trans_hash[PARAM_DIGEST_SIZE], uint8_t nonce[NONCE_BYTESIZE], vec_t eval_points);

#endif /* __DECS_H__ */
