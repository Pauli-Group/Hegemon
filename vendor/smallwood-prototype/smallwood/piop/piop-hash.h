#ifndef __PIOP_HASH_H__
#define __PIOP_HASH_H__

#include <stdint.h>
#include "parameters.h"
#include "piop.h"

void hash_piop(const piop_t* piop, uint8_t hash_fpp[PARAM_DIGEST_SIZE], const uint8_t* transcript, uint32_t transcript_bytesize);
void xof_piop_challenge(const piop_t* piop, vec_t gamma_prime, const uint8_t hash_fpp[PARAM_DIGEST_SIZE], uint32_t gamma_prime_size);

#endif /* __PIOP_HASH_H__ */
