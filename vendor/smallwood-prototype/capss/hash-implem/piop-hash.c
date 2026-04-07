#include "field.h"
#include "field-xof.h"
#include "piop-internal.h"
#include "piop-hash.h"
#include <stdio.h>

#if (PARAM_DIGEST_SIZE % FIELD_BYTESIZE) != 0
#error PARAM_DIGEST_SIZE % FIELD_BYTESIZE != 0
#endif

#define PARAM_DIGEST_FELT_SIZE (PARAM_DIGEST_SIZE/FIELD_BYTESIZE)

void hash_piop(const piop_t* piop, uint8_t hash_fpp[PARAM_DIGEST_SIZE], const uint8_t* transcript, uint32_t transcript_bytesize) {
    (void) piop;
    memset(hash_fpp, 0, PARAM_DIGEST_SIZE);
    if(transcript_bytesize % FIELD_BYTESIZE != 0) {
        printf("hash_piop: failure (transcript)\n");
        return;
    }

    vec_xof((felt_t*) hash_fpp, (felt_t*) transcript, transcript_bytesize/FIELD_BYTESIZE, PARAM_DIGEST_FELT_SIZE);
}

void xof_piop_challenge(const piop_t* piop, vec_t gamma_prime, const uint8_t hash_fpp[PARAM_DIGEST_SIZE], uint32_t gamma_prime_size) {
    (void) piop;
    vec_xof(gamma_prime, (felt_t*) hash_fpp, PARAM_DIGEST_FELT_SIZE, gamma_prime_size);
}
