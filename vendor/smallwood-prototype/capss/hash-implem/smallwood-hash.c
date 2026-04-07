#include "field.h"
#include "field-xof.h"
#include "smallwood-internal.h"
#include "smallwood-hash.h"
#include <stdio.h>

#if (PARAM_DIGEST_SIZE % FIELD_BYTESIZE) != 0
#error PARAM_DIGEST_SIZE % FIELD_BYTESIZE != 0
#endif

#define PARAM_DIGEST_FELT_SIZE (PARAM_DIGEST_SIZE/FIELD_BYTESIZE)

void hash_piop_transcript(const smallwood_t* sw, uint8_t h_piop[PARAM_DIGEST_SIZE], const uint8_t* piop_transcript, uint32_t piop_transcript_size) {
    (void) sw;
    memset(h_piop, 0, PARAM_DIGEST_SIZE);
    if(piop_transcript_size % FIELD_BYTESIZE != 0) {
        printf("hash_piop_transcript: failure (piop_transcript)\n");
        return;
    }

    vec_xof((felt_t*) h_piop, (felt_t*) piop_transcript, piop_transcript_size/FIELD_BYTESIZE, PARAM_DIGEST_FELT_SIZE);
}

void xof_piop_opening_challenge(const smallwood_t* sw, vec_t eval_points, uint32_t* vpow, const uint8_t nonce[NONCE_BYTESIZE], const uint8_t h_piop[PARAM_DIGEST_SIZE], uint32_t nb_opened_evals) {
    uint32_t lhash_input_felt_size = 1 + PARAM_DIGEST_FELT_SIZE;
    vec_t lhash_input = malloc_vec(lhash_input_felt_size);
    uint32_t pow_bits = sw->opening_pow_bits;

    uint32_t nonce_uint32 = 0;
    nonce_uint32 |= ((uint32_t) nonce[0]) <<  0;
    nonce_uint32 |= ((uint32_t) nonce[1]) <<  8;
    nonce_uint32 |= ((uint32_t) nonce[2]) << 16;
    nonce_uint32 |= ((uint32_t) nonce[3]) << 24;

    felt_t* nonce_felt = lhash_input;
    felt_from_uint32(nonce_felt, nonce_uint32);
    vec_set(lhash_input+1, (felt_t*) h_piop, PARAM_DIGEST_FELT_SIZE);

    if(pow_bits) {
        uint32_t lhash_output_felt_size = nb_opened_evals + 1;
        vec_t lhash_output = malloc_vec(lhash_output_felt_size);
        vec_xof(lhash_output, lhash_input, lhash_input_felt_size, lhash_output_felt_size);
        vec_set(eval_points, lhash_output, nb_opened_evals);

        felt_t* vpow_felt = &lhash_output[nb_opened_evals];
        uint8_t* vpow_bytes = (uint8_t*) vpow_felt;
        *vpow = ((uint32_t) vpow_bytes[0]) | (((uint32_t) vpow_bytes[1])<<8);
        *vpow &= (1<<pow_bits)-1;

        free(lhash_output);
    } else {
        vec_xof(eval_points, lhash_input, lhash_input_felt_size, nb_opened_evals);
        *vpow = 0;
    }
    free(lhash_input);
}
