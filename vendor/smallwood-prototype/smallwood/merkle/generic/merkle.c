#include "merkle-internal.h"
#include <stdlib.h>
#include "utils.h"
#include "merkle-hash.h"
#include <string.h>

void merkle_tree_sort_leave_indexes(uint32_t nb_revealed_leaves, uint32_t* leaves_indexes) {
    uint32_t i, j, c;
    for(i=0; i<nb_revealed_leaves-1; i++) {
        for(j=i+1; j<nb_revealed_leaves; j++) {
            if(leaves_indexes[i] > leaves_indexes[j]) {
                c = leaves_indexes[i];
                leaves_indexes[i] = leaves_indexes[j];
                leaves_indexes[j] = c;
            }
        }
    }
}

uint32_t merkle_tree_get_nb_leaves(const merkle_tree_t* tree) {
    return tree->nb_leaves;
}

#define get_node(key,dp,idx) &key->nodes[dp][(idx)*PARAM_DIGEST_SIZE]

int merkle_tree_expand(const merkle_tree_t* tree, const uint8_t* salt, uint8_t const* const* leaf_data, uint8_t root[PARAM_DIGEST_SIZE], merkle_tree_key_t* key) {
//void merkle_tree_expand(merkle_tree_t* tree, uint8_t** leaf_data, const uint8_t* salt)
//{
    uint32_t nb_leaves = tree->nb_leaves;
    uint32_t height = tree->height;
    uint32_t* arities = tree->arities;
    int ret = 0;

    ret = merkle_tree_key_init(key, tree); ERR(ret, err);

    uint32_t last_index = nb_leaves-1;

    // Initialize the leaves with leaf_data
    for (uint32_t i = 0; i < nb_leaves; i++)
        memcpy(get_node(key, height, i), leaf_data[i], PARAM_DIGEST_SIZE);

    for(int h=height-1; h>= 0; h--) {
        // last_nb_children:
        //   indicates if the last node has a single child
        uint32_t last_nb_children = (last_index+1) % arities[h];
        if(last_nb_children == 0)
            last_nb_children = arities[h];
        // Current floor:
        //    {0, ..., last_index}
        last_index /= arities[h];
        // For each node
        for(uint32_t parent_index=0; parent_index<=last_index; parent_index++) {
            uint8_t* parent = get_node(key, h, parent_index);
            uint8_t* first = get_node(key, h+1, arities[h]*parent_index);
            uint32_t nb_nodes = (parent_index == last_index) ? last_nb_children : arities[h];
            compress_nodes(parent, parent_index, salt, first, nb_nodes);
        }
    }

    memcpy(root, get_node(key, 0, 0), PARAM_DIGEST_SIZE);

err:
    return ret;
}

uint32_t merkle_tree_max_sizeof_auth(const merkle_tree_t* tree, uint32_t nb_open_leaves) {
    uint32_t upper_bound_1 = tree->nb_leaves;
    uint32_t upper_bound_2 = 0;
    for(uint32_t i=0; i<tree->height; i++)
        upper_bound_2 += (tree->arities[i]-1)*nb_open_leaves;
    uint32_t upper_bound = (upper_bound_2 < upper_bound_1) ? upper_bound_2 : upper_bound_1;
    return upper_bound*PARAM_DIGEST_SIZE;
}

static int32_t get_revealed_nodes(uint32_t* revealed_nodes, const merkle_tree_t* tree, uint32_t nb_revealed_leaves, const uint32_t* leaves_indexes) {
    uint32_t height = tree->height;
    uint32_t* arities = tree->arities;
    uint32_t nb_leaves = tree->nb_leaves;
    uint32_t truncated = tree->truncated;

    uint32_t nb_revealed_nodes = 0; 

    // Check that the leave indexes is in the ascending order
    for(uint32_t i=0; i<nb_revealed_leaves-1; i++) {
        if(leaves_indexes[i] >= leaves_indexes[i+1])
            return -1;
    }

    // Initialisation
    uint32_t last_index = nb_leaves - 1;
    // We use "leaves" as a circular queue, so it destroys the input data.
    uint32_t queue_start = 0;
    uint32_t queue_stop = 0;
    uint32_t* queue_indexes = (uint32_t*) malloc(nb_revealed_leaves*sizeof(uint32_t));
    for(uint32_t i=0; i<nb_revealed_leaves; i++)
        queue_indexes[i] = leaves_indexes[i];
    uint32_t* queue_depth = (uint32_t*) malloc(nb_revealed_leaves*sizeof(uint32_t));
    for(uint32_t i=0; i<nb_revealed_leaves; i++)
        queue_depth[i] = height;
    uint32_t current_depth = height;

    // While the queue head does not corresponds to the root of the Merkle tree
    while(queue_depth[queue_start] != truncated) {
        // Get the first node in the queue
        uint32_t index = queue_indexes[queue_start];
        uint32_t depth = queue_depth[queue_start];
        queue_start++;
        if(queue_start == nb_revealed_leaves)
            queue_start = 0;
        // Detect if we change of tree height
        if(depth < current_depth) {
            last_index /= arities[depth-1];
        }
        current_depth = depth;
        uint32_t parent_index = index / arities[depth-1];

        // Get the sibling node
        uint32_t first_sibling = index - (index % arities[depth-1]);
        uint32_t next_first_sibling = first_sibling + arities[depth-1];
        if(next_first_sibling > last_index)
            next_first_sibling = last_index+1;
        uint32_t nb_children = next_first_sibling-first_sibling;
        for(uint32_t i=0; i<nb_children; i++) {
            int queue_is_empty = (queue_start == queue_stop);
            if(first_sibling + i < index) {
                // The sibling node is given in the authentication paths
                revealed_nodes[2*nb_revealed_nodes+0] = depth;
                revealed_nodes[2*nb_revealed_nodes+1] = first_sibling + i;
                nb_revealed_nodes++;
            } else if(!queue_is_empty && (queue_depth[queue_start] == depth && index < queue_indexes[queue_start] && queue_indexes[queue_start] < next_first_sibling)) {
                // The next sibling node is in the queue
                index = queue_indexes[queue_start];
                queue_start++;
                if(queue_start == nb_revealed_leaves)
                    queue_start = 0;
            } else {
                // The next sibling node is NOT in the queue
                index = next_first_sibling;
            }
        }

        // Compute the parent node, and push it in the queue
        queue_indexes[queue_stop] = parent_index;
        queue_depth[queue_stop] = depth-1;
        queue_stop++;
        if(queue_stop == nb_revealed_leaves)
            queue_stop = 0;
    }

    if(truncated > 0) {
        // Truncated
        last_index /= arities[truncated-1];
        for(uint32_t i=0; i<=last_index; i++) {
            int queue_is_empty = (queue_start == queue_stop);
            if(!queue_is_empty && queue_indexes[queue_start] == i) {
                queue_start++;
                if(queue_start == nb_revealed_leaves)
                    queue_start = 0;
            } else {
                revealed_nodes[2*nb_revealed_nodes+0] = truncated;
                revealed_nodes[2*nb_revealed_nodes+1] = i;
                nb_revealed_nodes++;
            }
        }
    } 

    // Free memory
    free(queue_indexes);
    free(queue_depth);
    return nb_revealed_nodes;
}

uint8_t* merkle_tree_open(const merkle_tree_t* tree, const merkle_tree_key_t* key, const uint32_t* open_leaves, uint32_t nb_open_leaves, uint32_t* auth_size)
{
    uint32_t* revealed = malloc(tree->nb_leaves*2*sizeof(uint32_t));
    int32_t nb_revealed = get_revealed_nodes(revealed, tree, nb_open_leaves, open_leaves);
    if(nb_revealed < 0) {
        return NULL;
    }

    *auth_size = nb_revealed * PARAM_DIGEST_SIZE;
    uint8_t* output = malloc(*auth_size);
    uint8_t* outputBase = output;

    for(int32_t i = 0; i < nb_revealed; i++) {
        memcpy(output, get_node(key,revealed[2*i+0],revealed[2*i+1]), PARAM_DIGEST_SIZE);
        output += PARAM_DIGEST_SIZE;
    }

    free(revealed);

    return outputBase;
}

int merkle_tree_retrieve_root(const merkle_tree_t* tree, const uint8_t* salt, uint32_t nb_revealed_leaves, const uint32_t* leaves_indexes, uint8_t* leaves, const uint8_t* auth, uint32_t auth_size, uint8_t root[PARAM_DIGEST_SIZE]) {
    uint32_t height = tree->height;
    uint32_t* arities = tree->arities;
    uint32_t nb_leaves = tree->nb_leaves;
    uint32_t truncated = tree->truncated;

    uint32_t max_arity = arities[0];
    for(uint32_t i=1; i<height; i++)
        if(arities[i] > max_arity)
            max_arity = arities[i];
    
    // Check that the leave indexes is in the ascending order
    for(uint32_t i=0; i<nb_revealed_leaves-1; i++) {
        if(leaves_indexes[i] >= leaves_indexes[i+1])
            return -1;
    }

    // Initialisation
    uint32_t last_index = nb_leaves - 1;
    // We use "leaves" as a circular queue, so it destroy the input data.
    uint8_t* queue = leaves;
    uint32_t queue_start = 0;
    uint32_t queue_stop = 0;
    uint32_t* queue_indexes = (uint32_t*) malloc(nb_revealed_leaves*sizeof(uint32_t));
    for(uint32_t i=0; i<nb_revealed_leaves; i++)
        queue_indexes[i] = leaves_indexes[i];
    uint32_t* queue_depth = (uint32_t*) malloc(nb_revealed_leaves*sizeof(uint32_t));
    for(uint32_t i=0; i<nb_revealed_leaves; i++)
        queue_depth[i] = height;
    uint32_t current_depth = height;
        
    // While the queue head does not corresponds to the root of the Merkle tree
    uint8_t* children = malloc(PARAM_DIGEST_SIZE*max_arity);
    while(queue_depth[queue_start] != truncated) {
        // Get the first node in the queue
        const uint8_t* node = &queue[PARAM_DIGEST_SIZE*queue_start];
        uint32_t index = queue_indexes[queue_start];
        uint32_t depth = queue_depth[queue_start];
        queue_start++;
        if(queue_start == nb_revealed_leaves)
            queue_start = 0;
        // Detect if we change of tree height
        if(depth < current_depth) {
            last_index /= arities[depth-1];
        }
        current_depth = depth;
        uint32_t parent_index = index / arities[depth-1];

        // Get the sibling nodes
        uint32_t first_sibling = index - (index % arities[depth-1]);
        uint32_t next_first_sibling = first_sibling + arities[depth-1];
        if(next_first_sibling > last_index)
            next_first_sibling = last_index+1;
        uint32_t nb_children = next_first_sibling-first_sibling;
        for(uint32_t i=0; i<nb_children; i++) {
            uint8_t* child = &children[i*PARAM_DIGEST_SIZE];
            int queue_is_empty = (queue_start == queue_stop);
            if(first_sibling + i < index) {
                // The sibling node is given in the authentication paths
                if(auth_size >= PARAM_DIGEST_SIZE) {
                    memcpy(child, auth, PARAM_DIGEST_SIZE);
                    auth += PARAM_DIGEST_SIZE;
                    auth_size -= PARAM_DIGEST_SIZE;    
                } else {
                    // Failure: the authentication paths are not long enough
                    return -1;
                }
            } else if(!queue_is_empty && (queue_depth[queue_start] == depth && index < queue_indexes[queue_start] && queue_indexes[queue_start] < next_first_sibling)) {
                // The next sibling node is in the queue
                memcpy(child, node, PARAM_DIGEST_SIZE);
                node = &queue[PARAM_DIGEST_SIZE*queue_start];
                index = queue_indexes[queue_start];
                queue_start++;
                if(queue_start == nb_revealed_leaves)
                    queue_start = 0;
            } else {
                // The next sibling node is NOT in the queue
                memcpy(child, node, PARAM_DIGEST_SIZE);
                index = next_first_sibling;
            }
        }

        // Compute the parent node, and push it in the queue        
        uint8_t* parent = &queue[PARAM_DIGEST_SIZE*queue_stop];
        compress_nodes(parent, parent_index, salt, children, nb_children);

        queue_indexes[queue_stop] = parent_index;
        queue_depth[queue_stop] = depth-1;
        queue_stop++;
        if(queue_stop == nb_revealed_leaves)
            queue_stop = 0;
    }
    free(children);

    if(truncated > 0) {
        // Truncated
        last_index /= arities[truncated-1];
        uint8_t* last_nodes_data = malloc((last_index+1)*PARAM_DIGEST_SIZE);
        uint8_t** last_nodes = malloc((last_index+1)*sizeof(uint8_t*));
        for(uint32_t i=0; i<=last_index; i++) {
            last_nodes[i] = &last_nodes_data[i*PARAM_DIGEST_SIZE];
            uint8_t* child = last_nodes[i];
            int queue_is_empty = (queue_start == queue_stop);
            if(!queue_is_empty && queue_indexes[queue_start] == i) {
                memcpy(child, &queue[PARAM_DIGEST_SIZE*queue_start], PARAM_DIGEST_SIZE);
                queue_start++;
                if(queue_start == nb_revealed_leaves)
                    queue_start = 0;
            } else {
                if(auth_size >= PARAM_DIGEST_SIZE) {
                    memcpy(child, auth, PARAM_DIGEST_SIZE);
                    auth += PARAM_DIGEST_SIZE;
                    auth_size -= PARAM_DIGEST_SIZE;    
                } else {
                    // Failure: the authentication paths are not long enough
                    return -1;
                }
            }
        }
        merkle_tree_cfg_t treetop_cfg = {
            .nb_leaves = last_index+1,
            .height = truncated,
            .arities = arities,
        };
        merkle_tree_t* treetop = malloc(merkle_tree_sizeof(&treetop_cfg));
        merkle_tree_init(treetop, &treetop_cfg);
        merkle_tree_key_t* treetop_key = malloc(merkle_tree_sizeof_key(treetop));
        merkle_tree_expand(treetop, salt, (uint8_t const* const*) last_nodes, root, treetop_key);
        free(treetop_key);
        free(treetop);
        free(last_nodes);
        free(last_nodes_data);
    } else {
        // Standard
        memcpy(root, &queue[PARAM_DIGEST_SIZE*queue_start], PARAM_DIGEST_SIZE);
    }

    // Free memory
    free(queue_indexes);
    free(queue_depth);
    return 0;
}
