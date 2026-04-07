#ifndef __MERKLE_INTERNAL_H__
#define __MERKLE_INTERNAL_H__

#include "merkle.h"

/* Binary and complete Merkle tree */
typedef struct merkle_tree_t {
    uint8_t height;       /* The height of the tree */
    uint32_t nb_nodes;    /* The total number of nodes in the tree  */
    uint32_t nb_leaves;   /* The total number of leaves in the tree */
    uint32_t* depth_width;
    uint32_t* arities;
    uint32_t truncated;
} merkle_tree_t;

struct merkle_tree_key_t {
    uint8_t** nodes;
};

int merkle_tree_key_init(merkle_tree_key_t* key, const merkle_tree_t* tree);

#endif /* __MERKLE_INTERNAL_H__ */
