#include "field.h"
#include "field-xof.h"
#include "lvcs-internal.h"
#include "lvcs-hash.h"
#include <stdio.h>

#if (PARAM_DIGEST_SIZE % FIELD_BYTESIZE) != 0
#error PARAM_DIGEST_SIZE % FIELD_BYTESIZE != 0
#endif

#define PARAM_DIGEST_FELT_SIZE (PARAM_DIGEST_SIZE/FIELD_BYTESIZE)

void hash_challenge_opening_decs(const lvcs_t* lvcs, uint8_t* digest, vec_t* extended_combis, const uint8_t* prtranscript, uint32_t prtranscript_bytesize) {
    memset(digest, 0, PARAM_DIGEST_SIZE);
    if(prtranscript_bytesize % FIELD_BYTESIZE != 0) {
        printf("hash_challenge_opening_decs: failure (prtranscript)\n");
        return;
    }

    uint32_t nb_cols = lvcs->nb_cols;
    uint32_t nb_opened_combi = lvcs->nb_opened_combi;
    uint32_t nb_opened_evals = lvcs->nb_opened_evals;

    uint32_t lhash_input_felt_size = (prtranscript_bytesize/FIELD_BYTESIZE) + (nb_cols+nb_opened_evals)*nb_opened_combi;
    uint8_t* lhash_input = malloc(lhash_input_felt_size*FIELD_BYTESIZE);
    uint8_t* buffer = lhash_input;

    memcpy(buffer, prtranscript, prtranscript_bytesize); buffer += prtranscript_bytesize;
    for(uint32_t k=0; k<nb_opened_combi; k++) {
        memcpy(buffer, extended_combis[k], FIELD_BYTESIZE*(nb_cols+nb_opened_evals));
        buffer += FIELD_BYTESIZE*(nb_cols+nb_opened_evals);
    }

    vec_xof((felt_t*) digest, (felt_t*) lhash_input, lhash_input_felt_size, PARAM_DIGEST_FELT_SIZE);
    free(lhash_input);
}
