#ifndef __MERKLE_HASH_H__
#define __MERKLE_HASH_H__

#include <stdint.h>
#include "parameters.h"

void compress_nodes(uint8_t digest[PARAM_DIGEST_SIZE], uint32_t index, const uint8_t salt[PARAM_SALT_SIZE], const uint8_t* nodes, uint32_t nb_nodes);

#endif /* __MERKLE_HASH_H__ */
