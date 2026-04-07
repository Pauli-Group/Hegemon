#include "field.h"
#include "field-xof.h"
#include "merkle-hash.h"
#include <stdio.h>

#if (PARAM_DIGEST_SIZE % FIELD_BYTESIZE) != 0
#error PARAM_DIGEST_SIZE % FIELD_BYTESIZE != 0
#endif

#if (PARAM_SALT_SIZE % FIELD_BYTESIZE) != 0
#error PARAM_SALT_SIZE % FIELD_BYTESIZE != 0
#endif

#define PARAM_DIGEST_FELT_SIZE (PARAM_DIGEST_SIZE/FIELD_BYTESIZE)
#define PARAM_SALT_FELT_SIZE (PARAM_SALT_SIZE/FIELD_BYTESIZE)

/*
void compress_two_node_children(uint8_t parent[PARAM_DIGEST_SIZE], uint32_t parent_index, const uint8_t salt[PARAM_SALT_SIZE], const uint8_t left[PARAM_DIGEST_SIZE], const uint8_t right[PARAM_DIGEST_SIZE]) {
    uint32_t lhash_input_felt_size = PARAM_DIGEST_FELT_SIZE;
    //if(salt != NULL)
    //    lhash_input_felt_size += PARAM_SALT_FELT_SIZE;
    if(right)
        lhash_input_felt_size += PARAM_DIGEST_FELT_SIZE;
    uint8_t* lhash_input = malloc(lhash_input_felt_size*FIELD_BYTESIZE);
    uint8_t* buffer = lhash_input;

    (void) salt;
    //if(salt != NULL) {
    //    memcpy(buffer, salt, PARAM_SALT_SIZE); buffer += PARAM_SALT_SIZE;
    //}
    (void) parent_index;
    memcpy(buffer, left, PARAM_DIGEST_SIZE); buffer += PARAM_DIGEST_SIZE;
    if(right) {
        memcpy(buffer, right, PARAM_DIGEST_SIZE); buffer += PARAM_DIGEST_SIZE;
    }

    vec_xof((felt_t*) parent, (felt_t*) lhash_input, lhash_input_felt_size, PARAM_DIGEST_FELT_SIZE);
    free(lhash_input);
}

void compress_two_node_children_x4(uint8_t* parent[4], const uint32_t parent_index[4], const uint8_t salt[PARAM_SALT_SIZE], uint8_t const* left[4], uint8_t const* right[4]) {
    compress_two_node_children(parent[0], parent_index[0], salt, left[0], right[0]);
    compress_two_node_children(parent[1], parent_index[1], salt, left[1], right[1]);
    compress_two_node_children(parent[2], parent_index[2], salt, left[2], right[2]);
    compress_two_node_children(parent[3], parent_index[3], salt, left[3], right[3]);
}
*/

void compress_nodes(uint8_t digest[PARAM_DIGEST_SIZE], uint32_t index, const uint8_t salt[PARAM_SALT_SIZE], const uint8_t* nodes, uint32_t nb_nodes) {
    uint32_t lhash_input_felt_size = PARAM_DIGEST_FELT_SIZE*nb_nodes;
    //if(salt != NULL)
    //    lhash_input_felt_size += PARAM_SALT_FELT_SIZE;
    uint8_t* lhash_input = malloc(lhash_input_felt_size*FIELD_BYTESIZE);
    uint8_t* buffer = lhash_input;

    (void) salt;
    //if(salt != NULL) {
    //    memcpy(buffer, salt, PARAM_SALT_SIZE); buffer += PARAM_SALT_SIZE;
    //}
    (void) index;
    memcpy(buffer, nodes, PARAM_DIGEST_SIZE*nb_nodes);

    vec_xof((felt_t*) digest, (felt_t*) lhash_input, lhash_input_felt_size, PARAM_DIGEST_FELT_SIZE);
    free(lhash_input);
}

