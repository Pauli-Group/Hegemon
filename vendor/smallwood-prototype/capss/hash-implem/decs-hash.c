#include "field.h"
#include "field-xof.h"
#include "field-int.h"
#include "parameters.h"
#include "decs-internal.h"
#include "decs-hash.h"
#include <stdio.h>
#include <math.h>

#if (PARAM_DIGEST_SIZE % FIELD_BYTESIZE) != 0
#error PARAM_DIGEST_SIZE % FIELD_BYTESIZE != 0
#endif

#if (PARAM_SALT_SIZE % FIELD_BYTESIZE) != 0
#error PARAM_SALT_SIZE % FIELD_BYTESIZE != 0
#endif

#define PARAM_DIGEST_FELT_SIZE (PARAM_DIGEST_SIZE/FIELD_BYTESIZE)
#define PARAM_SALT_FELT_SIZE (PARAM_SALT_SIZE/FIELD_BYTESIZE)


void hash_merkle_leave(const decs_t* decs, uint8_t* digest, const uint8_t salt[PARAM_SALT_SIZE], const vec_t evals, uint8_t tape[PARAM_SEED_SIZE]) {
    memset(digest, 0, PARAM_DIGEST_SIZE);
    if(tape != NULL && PARAM_SEED_SIZE % FIELD_BYTESIZE != 0) {
        printf("hash_merkle_leave: failure (tape)\n");
        return;
    }

    uint32_t nb_polys = decs->cfg.nb_polys;
    uint32_t eta = decs->cfg.eta;
    uint32_t use_commitment_tapes = decs->cfg.use_commitment_tapes;

    uint32_t lhash_input_felt_size = PARAM_SALT_FELT_SIZE + (nb_polys+eta);
    if(use_commitment_tapes)
        lhash_input_felt_size += (PARAM_SEED_SIZE/FIELD_BYTESIZE);
    vec_t lhash_input = malloc_vec(lhash_input_felt_size);
    vec_t buffer = lhash_input;

    vec_set(buffer, (vec_t) salt, PARAM_SALT_FELT_SIZE);
    buffer += PARAM_SALT_FELT_SIZE;
    vec_set(buffer, evals, nb_polys+eta);
    buffer += nb_polys+eta;
    if(use_commitment_tapes)
        vec_set(buffer, (vec_t) tape, PARAM_SEED_SIZE/FIELD_BYTESIZE);

    vec_xof((vec_t) digest, lhash_input, lhash_input_felt_size, PARAM_DIGEST_FELT_SIZE);
    free(lhash_input);
}

void hash_merkle_root(const decs_t* decs, uint8_t* digest, const uint8_t salt[PARAM_SALT_SIZE], const uint8_t root[PARAM_DIGEST_SIZE]) {
    (void) decs;

    uint32_t lhash_input_felt_size = PARAM_SALT_FELT_SIZE + PARAM_DIGEST_FELT_SIZE;
    vec_t lhash_input = malloc_vec(lhash_input_felt_size);
    vec_t buffer = lhash_input;

    vec_set(buffer, (vec_t) salt, PARAM_SALT_FELT_SIZE);
    buffer += PARAM_SALT_FELT_SIZE;
    vec_set(buffer, (vec_t) root, PARAM_DIGEST_FELT_SIZE);

    vec_xof((vec_t) digest, lhash_input, lhash_input_felt_size, PARAM_DIGEST_FELT_SIZE);
    free(lhash_input);
}

void xof_decs_challenge(const decs_t* decs, vec_t gamma, const uint8_t hash_mt[PARAM_DIGEST_SIZE], uint32_t gamma_size) {
    (void) decs;
    vec_xof(gamma, (felt_t*) hash_mt, PARAM_DIGEST_SIZE/FIELD_BYTESIZE, gamma_size);
}

void xof_decs_opening(const decs_t* decs, uint32_t* leaves_indexes, uint32_t* vpow, const uint8_t nonce[NONCE_BYTESIZE], const uint8_t trans_hash[PARAM_DIGEST_SIZE]) {
    uint32_t nb_evals = decs->cfg.nb_evals;
    uint32_t nb_opened_evals = decs->cfg.nb_opened_evals;
    uint32_t pow_bits = decs->cfg.pow_bits;

    double log2_order = felt_get_log2_field_order();
    double log2_nb_evals = log2(nb_evals);
    double margin = 0.001;
    uint32_t maxi = floor((log2_order/log2_nb_evals)-margin);

    uint32_t* nb_queries_per_chal_value = NULL;
    vec_t maxi_to_keep_per_chal_value = NULL;

    uint32_t opening_challenge_size = 0;
    uint32_t delta_opening_size = 0;
    uint32_t can_continue = 0;
    //printf("EXT: %d\n", *((uint32_t*) nonce));
    while(!can_continue) {
        opening_challenge_size = (nb_opened_evals+maxi-1)/maxi + delta_opening_size;
        uint32_t min_nb_queries_per_chal_value = nb_opened_evals/opening_challenge_size;
        uint32_t max_nb_queries_per_chal_value = (nb_opened_evals+opening_challenge_size-1)/opening_challenge_size;
        uint32_t nb_at_max = nb_opened_evals % opening_challenge_size;
        can_continue = 1;
        //printf("opening_challenge_size = %d\n", opening_challenge_size);

        nb_queries_per_chal_value = malloc(sizeof(uint32_t)*opening_challenge_size);
        maxi_to_keep_per_chal_value = malloc_vec(opening_challenge_size);
        uint32_t* nb_additional_bits_per_chal_value = malloc(sizeof(uint32_t)*opening_challenge_size);

        double current_w = 0;
        for(uint32_t i=0; i<opening_challenge_size; i++) {
            nb_queries_per_chal_value[i] = (i < nb_at_max) ? max_nb_queries_per_chal_value : min_nb_queries_per_chal_value;
            double nb_additional_bits_per_chal_value_exact = log2_order - nb_queries_per_chal_value[i]*log2_nb_evals;
            nb_additional_bits_per_chal_value[i] = floor(nb_additional_bits_per_chal_value_exact);
            current_w += nb_additional_bits_per_chal_value_exact - nb_additional_bits_per_chal_value[i];
        }
        uint32_t ind = 0;
        while(current_w < pow_bits) {
            uint32_t missing = pow_bits - floor(current_w);
            uint32_t add_w = (missing < nb_additional_bits_per_chal_value[ind]) ? missing : nb_additional_bits_per_chal_value[ind];
            current_w += add_w;
            nb_additional_bits_per_chal_value[ind] -= add_w;
            ind++;
            if((current_w < pow_bits) && (ind >= opening_challenge_size)) {
                can_continue = 0;
                delta_opening_size++;
                break;
            }
        }

        if(!can_continue) {
            free(nb_queries_per_chal_value);
            free(maxi_to_keep_per_chal_value);
        } else {
            felt_t acc, nb_evals_felt;
            felt_from_uint32(&nb_evals_felt, nb_evals);
            felt_set(&acc, &nb_evals_felt);
            for(uint32_t i=1; i<min_nb_queries_per_chal_value; i++)
                felt_mul(&acc, &acc, &nb_evals_felt);
            for(uint32_t i=nb_at_max; i<opening_challenge_size; i++) {
                felt_set(&maxi_to_keep_per_chal_value[i], &acc);
                felt_int_left_shift(&maxi_to_keep_per_chal_value[i], &maxi_to_keep_per_chal_value[i], nb_additional_bits_per_chal_value[i]);
                felt_int_minus_one(&maxi_to_keep_per_chal_value[i], &maxi_to_keep_per_chal_value[i]);
            }
            if(nb_at_max) {
                felt_mul(&acc, &acc, &nb_evals_felt);
                for(uint32_t i=0; i<nb_at_max; i++) {
                    felt_set(&maxi_to_keep_per_chal_value[i], &acc);
                    felt_int_left_shift(&maxi_to_keep_per_chal_value[i], &maxi_to_keep_per_chal_value[i], nb_additional_bits_per_chal_value[i]);
                    felt_int_minus_one(&maxi_to_keep_per_chal_value[i], &maxi_to_keep_per_chal_value[i]);
                }
            }

            // for(uint32_t i=0; i<opening_challenge_size; i++)
            //     printf("maxi_to_keep_per_chal_value[%d] = %llu\n", i, maxi_to_keep_per_chal_value[i]);

            // printf("real pow=%f\n", current_w);
        }
        free(nb_additional_bits_per_chal_value);
    }

    uint32_t nonce_uint32 = 0;
    nonce_uint32 |= ((uint32_t) nonce[0]) <<  0;
    nonce_uint32 |= ((uint32_t) nonce[1]) <<  8;
    nonce_uint32 |= ((uint32_t) nonce[2]) << 16;
    nonce_uint32 |= ((uint32_t) nonce[3]) << 24;

    uint32_t lhash_input_felt_size = 1 + PARAM_DIGEST_FELT_SIZE;
    vec_t lhash_input = malloc_vec(lhash_input_felt_size);

    felt_from_uint32(lhash_input, nonce_uint32);
    memcpy(lhash_input+1, trans_hash, PARAM_DIGEST_SIZE);

    uint32_t lhash_output_felt_size = opening_challenge_size;
    vec_t lhash_output = malloc_vec(lhash_output_felt_size);
    vec_xof(lhash_output, lhash_input, lhash_input_felt_size, lhash_output_felt_size);
    free(lhash_input);

    uint32_t is_ok = 1;
    for(uint32_t i=0; i<opening_challenge_size; i++) {
        if(!felt_int_leq(&lhash_output[i], &maxi_to_keep_per_chal_value[i])) {
            is_ok = 0;
            break;
        }
    }

    if(is_ok) {
        felt_t quotient;

        uint32_t ind = 0;
        for(uint32_t i=0; i<opening_challenge_size; i++) {
            for(uint32_t j=0; j<nb_queries_per_chal_value[i]; j++) {
                felt_int_div_euclid(&quotient, &leaves_indexes[ind], &lhash_output[i], nb_evals);
                felt_set(&lhash_output[i], &quotient);
                ind++;
            }
        }
        *vpow = 0;

    } else {
        for(uint32_t j=0; j<nb_opened_evals; j++)
            leaves_indexes[j] = 0;
        *vpow = 1;
    }

    free(nb_queries_per_chal_value);
    free(maxi_to_keep_per_chal_value);
    free(lhash_output);
}
