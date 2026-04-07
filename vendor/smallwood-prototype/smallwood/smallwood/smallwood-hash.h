#ifndef __SMALLWOOD_HASH_H__
#define __SMALLWOOD_HASH_H__

#include <stdint.h>
#include "parameters.h"
#include "field.h"
#include "decs.h" // for NONCE_BYTESIZE
#include "smallwood.h"

void hash_piop_transcript(const smallwood_t* sw, uint8_t h_piop[PARAM_DIGEST_SIZE], const uint8_t* piop_transcript, uint32_t piop_transcript_size);
void xof_piop_opening_challenge(const smallwood_t* sw, vec_t eval_points, uint32_t* vpow, const uint8_t nonce[NONCE_BYTESIZE], const uint8_t h_piop[PARAM_DIGEST_SIZE], uint32_t nb_opened_evals);

#endif /* __PIOP_HASH_H__ */
