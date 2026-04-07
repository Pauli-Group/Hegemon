#ifndef __MERKLE_H__
#define __MERKLE_H__

#include <stdint.h>
#include "parameters.h"

/**
 * \struct merkle_tree_cfg_t
 * \brief Configuration of a Merkle tree
 * \headerfile ""
 * 
 * This data structure contains all the configurable parameters of a Merkle tree.
 */
typedef struct {
    /*! \brief Number of leaves
     *
     * If not provided, then it will consider a complete tree with the given
     * height and the given arities (if provided)
     */
    uint32_t nb_leaves;

    /*! \brief Height of the tree
     *
     * If not provided (if it is zero), then it will consider a binary
     * tree of minimal height with \ref nb_leaves leaves.
     */
    uint32_t height;

    /*! \brief Arities of each tree depth
     *
     * If not provided (while the height is provided), then it will consider
     * a binary tree. If provided, it should be an array of size \ref height,
     * where arities[i] refers to the arities of nodes at depth i.
     */
    uint32_t* arities;

    /*! \brief Tree truncation
     *
     * If provided, the produced authentication paths enables us to deduce
     * all the nodes at depth \ref truncated. If truncated=0, it refers to
     * the standard definition of authentication paths.
     */
    uint32_t truncated;
} merkle_tree_cfg_t;

/**
 * \struct merkle_tree_t
 * \brief Instance of a Merkle tree
 * \headerfile ""
 */
typedef struct merkle_tree_t merkle_tree_t;

/**
 * \struct merkle_tree_key_t
 * \brief Structure that represents an opening key of a Merkle tree
 * \headerfile ""
 */
typedef struct merkle_tree_key_t merkle_tree_key_t;

/**
 * \brief Return the byte size of the corresponding Merkle tree (merkle_tree_t)
 * \relates merkle_tree_t
 * \param tree_cfg a configuration of a Merkle tree
 * \return a byte size
 */
uint32_t merkle_tree_sizeof(const merkle_tree_cfg_t* tree_cfg);

/**
 * \brief Initialize a Merkle tree using the provided configuration
 * \relates merkle_tree_t
 * \param tree a (empty) Merkle tree
 * \param tree_cfg a configuration of a Merkle tree
 * \return 0 if the initialization was successful, otherwise a non-zero value
 * 
 * The pointer \p tree  should point to a allocated memory
 *  area of size provided by \ref merkle_tree_sizeof
 */
int merkle_tree_init(merkle_tree_t* tree, const merkle_tree_cfg_t* tree_cfg);

/**
 * \brief Return the byte size of the key of the Merkle tree (\ref merkle_tree_t)
 * \relates merkle_tree_t
 * \param tree a Merkle tree
 * \return a byte size
 */
uint32_t merkle_tree_sizeof_key(const merkle_tree_t* tree);

/**
 * \brief Return the number of leaves of a Merkle tree
 * \relates merkle_tree_t
 * \param tree a Merkle tree
 * \return the number of leaves
 */
uint32_t merkle_tree_get_nb_leaves(const merkle_tree_t* tree);

/**
 * \brief Return the maximal byte size of an authentication path produced by \ref merkle_tree_open
 * \relates merkle_tree_t
 * \param tree a Merkle tree
 * \param nb_open_leaves the number of opened leaves
 * \return a byte size
 */
uint32_t merkle_tree_max_sizeof_auth(const merkle_tree_t* tree, uint32_t nb_open_leaves);

/**
 * \brief Expand a Merkle tree from the given leaves
 * \relates merkle_tree_t
 * \param tree a Merkle tree
 * \param salt a salt of PARAM_SALT_SIZE bytes, can be a null pointer
 * \param leaf_data a 2D array containing all the committed leaves (each leaf is a byte string of lenth PARAM_DIGEST_SIZE)
 * \param root the root of the Merkle tree (output)
 * \param key the opening key that enables us to get authentication path (output)
 * \return 0 if the transcript recomputation was successful, otherwise a non-zero value
 */
int merkle_tree_expand(const merkle_tree_t* tree, const uint8_t* salt, uint8_t const* const* leaf_data, uint8_t root[PARAM_DIGEST_SIZE], merkle_tree_key_t* key);

/**
 * \brief Compute an authentication path to open the given leaves
 * \relates merkle_tree_t
 * \param tree a Merkle tree
 * \param key should be a opened key provided by \ref merkle_tree_expand using the same Merkle tree
 * \param open_leaves indexes of the opened leaves, array of length \p nb_open_leaves. Must be in the increasing order
 * \param nb_open_leaves number of opened leaves
 * \param auth_size will contain the size of the output authentication path
 * \return the authentication path if the opening was successful, otherwise NULL
 */
uint8_t* merkle_tree_open(const merkle_tree_t* tree, const merkle_tree_key_t* key, const uint32_t* open_leaves, uint32_t nb_open_leaves, uint32_t* auth_size);

/**
 * \brief Recompute the root of the Merkle tree from the given authentication path
 * \relates merkle_tree_t
 * \param tree a Merkle tree
 * \param salt a salt of PARAM_SALT_SIZE bytes, can be a null pointer
 * \param nb_revealed_leaves number of opened leaves
 * \param leaves_indexes indexes of the opened leaves, array of length \p nb_revealed_leaves. Must be in the increasing order
 * \param leaves the (concatenated) opened leaves, byte string of length nb_revealed_leaves*PARAM_DIGEST_SIZE
 * \param auth the authentication path
 * \param auth_size the byte size of the authentication path
 * \param root the root of the Merkle tree (output)
 * \return 0 if the root computation was successful, otherwise a non-zero value
 * 
 * Warning: the method destroyes the content in \p leaves.
 */
int merkle_tree_retrieve_root(const merkle_tree_t* tree, const uint8_t* salt, uint32_t nb_revealed_leaves, const uint32_t* leaves_indexes, uint8_t* leaves, const uint8_t* auth, uint32_t auth_size, uint8_t root[PARAM_DIGEST_SIZE]);

/**
 * \brief In-place sorting of the indexes of the leaves.
 * \param nb_revealed_leaves number of opened leaves
 * \param leaves_indexes array of indexes of length \p nb_revealed_leaves that will be sorted
 */
void merkle_tree_sort_leave_indexes(uint32_t nb_revealed_leaves, uint32_t* leaves_indexes);

#endif /* __MERKLE_H__ */
