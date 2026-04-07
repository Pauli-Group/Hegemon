#ifndef __DECS_HASH_H__
#define __DECS_HASH_H__

#include <stdint.h>
#include "decs.h"

void hash_merkle_leave(const decs_t* decs, uint8_t* digest, const uint8_t salt[PARAM_SALT_SIZE], const vec_t evals, uint8_t tape[PARAM_SEED_SIZE]);
void hash_merkle_root(const decs_t* decs, uint8_t* digest, const uint8_t salt[PARAM_SALT_SIZE], const uint8_t root[PARAM_DIGEST_SIZE]);
void xof_decs_challenge(const decs_t* decs, vec_t gamma, const uint8_t hash_mt[PARAM_DIGEST_SIZE], uint32_t gamma_size);
void xof_decs_opening(const decs_t* decs, uint32_t* leaves_indexes, uint32_t* vpow, const uint8_t nonce[NONCE_BYTESIZE], const uint8_t trans_hash[PARAM_DIGEST_SIZE]);

#endif /* __DECS_HASH_H__ */
