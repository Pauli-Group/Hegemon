#ifndef __SMALLWOOD_H__
#define __SMALLWOOD_H__

#include <stdint.h>
#include "lppc.h"
#include "merkle.h"

/*!
 * \defgroup proof Proof Systems
 * \brief All the structures to prove statements
 */

/**
 * \struct smallwood_cfg_t
 * \brief Configuration of an instance of the SmallWood proof system
 * \headerfile ""
 * 
 * This data structure contains all the configurable parameters of the
 * SmallWood proof system.
 */
typedef struct {
    uint32_t rho;
    uint32_t nb_opened_evals;
    uint32_t beta;
    uint32_t piop_format_challenge;
    uint32_t opening_pow_bits;

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
} smallwood_cfg_t;

/**
 * \struct smallwood_t
 * \ingroup proof
 * \brief Instance of a SmallWood proof system
 * \headerfile ""
 */
typedef struct smallwood_t smallwood_t;

/**
 * \brief Return the byte size of the corresponding SmallWood instance (smallwood_t)
 * \relates smallwood_t
 * \param lppc_cfg a LPPC configuration
 * \param sw_cfg a SmallWood configuration
 * \return a byte size
 */
uint32_t smallwood_alloc_bytesize(const lppc_cfg_t* lppc_cfg, const smallwood_cfg_t* sw_cfg);

/**
 * \brief Initialize a SmallWood instance using the provided configuration
 * \relates smallwood_t
 * \param sw a (empty) SmallWood instance
 * \param lppc_cfg a LPPC configuration
 * \param sw_cfg a SmallWood configuration
 * \return 0 if the initialization was successful, otherwise a non-zero value
 * 
 * The pointer \p sw should point to a allocated memory
 *  area of size provided by \ref smallwood_alloc_bytesize
 */
int smallwood_init(smallwood_t* sw, const lppc_cfg_t* lppc_cfg, const smallwood_cfg_t* sw_cfg);

/**
 * \brief Allocate a SmallWood instance using the provided configuration
 * \relates smallwood_t
 * \param lppc_cfg a LPPC configuration
 * \param sw_cfg a SmallWood configuration
 * \return a SmallWood instance
 */
smallwood_t* malloc_smallwood(const lppc_cfg_t* lppc_cfg, const smallwood_cfg_t* sw_cfg);

/**
 * \brief Return the maximal byte size of the proof transcript of the provided SmallWood instance
 * \relates smallwood_t
 * \param sw a SmallWood instance
 * \return a byte size
 */
uint32_t smallwood_max_sizeof_proof(const smallwood_t* sw);

/**
 * \brief Build a proof system for the given LPPC instance with the provided SmallWood instance
 * \relates smallwood_t
 * \param sw a SmallWood instance
 * \param lppc a LPPC instance
 * \param witness a LPPC witness that corresponds to the given LPPC instance \p lppc
 * \param binded_data a byte string of size \p binded_data_bytesize, the produced proof transcript is binded to this string
 * \param binded_data_bytesize the size of the byte string \p binded_data
 * \param proof_size will contain the byte size of the output proof transcript
 * \return the proof transcript if the proving algorithm was successful, otherwise NULL
 */
uint8_t* smallwood_prove_with_data(const smallwood_t* sw, const lppc_t* lppc, const vec_t witness, const uint8_t* binded_data, uint32_t binded_data_bytesize, uint32_t* proof_size);

/**
 * \brief Verify a proof transcript for the given LPPC instance with the provided SmallWood instance
 * \relates smallwood_t
 * \param sw a SmallWood instance
 * \param lppc a LPPC instance
 * \param binded_data a byte string of size \p binded_data_bytesize, used in the proving algorithm
 * \param binded_data_bytesize the size of the byte string \p binded_data
 * \param proof is the proof transcript outputted by \ref smallwood_prove_with_data
 * \param proof_size will contain the byte size of the output proof transcript
 * \return 0 if the verification was successful, otherwise a non-zero value
 */
int smallwood_verify_with_data(const smallwood_t* sw, const lppc_t* lppc, const uint8_t* binded_data, uint32_t binded_data_bytesize, const uint8_t* proof, uint32_t proof_size);

/**
 * \brief Build a proof system for the given LPPC instance with the provided SmallWood instance
 * \relates smallwood_t
 * \param sw a SmallWood instance
 * \param lppc a LPPC instance
 * \param witness a LPPC witness that corresponds to the given LPPC instance \p lppc
 * \param proof_size will contain the byte size of the output proof transcript
 * \return the proof transcript if the proving algorithm was successful, otherwise NULL
 */
static inline uint8_t* smallwood_prove(const smallwood_t* sw, const lppc_t* lppc, const vec_t witness, uint32_t* proof_size) {
    return smallwood_prove_with_data(sw, lppc, witness, NULL, 0, proof_size);
}

/**
 * \brief Verify a proof transcript for the given LPPC instance with the provided SmallWood instance
 * \relates smallwood_t
 * \param sw a SmallWood instance
 * \param lppc a LPPC instance
 * \param proof is the proof transcript outputted by \ref smallwood_prove
 * \param proof_size will contain the byte size of the output proof transcript
 * \return 0 if the verification was successful, otherwise a non-zero value
 */
static inline int smallwood_verify(const smallwood_t* sw, const lppc_t* lppc, const uint8_t* proof, uint32_t proof_size) {
    return smallwood_verify_with_data(sw, lppc, NULL, 0, proof, proof_size);
}

#endif /* __SMALLWOOD_H__ */
