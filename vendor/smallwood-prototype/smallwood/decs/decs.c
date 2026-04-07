#include "decs-internal.h"
#include "decs-hash.h"
#include "benchmark.h"
#include "utils.h"
#include <stdio.h>

extern int randombytes(unsigned char* x, unsigned long long xlen);

uint32_t decs_get_transcript_size(const decs_t* decs) {
    check_non_null_pointer("decs_get_transcript_size", "decs", decs, 0);
    uint32_t eta = decs->cfg.eta;
    uint32_t poly_degree = decs->cfg.poly_degree;
    return PARAM_DIGEST_SIZE + eta * poly_get_bytesize(poly_degree);
}

uint32_t decs_get_key_bytesize(const decs_t* decs) {
    check_non_null_pointer("decs_get_key_bytesize", "decs", decs, 0);
    return decs_key_alloc_bytesize(decs);
}

static void derive_decs_challenge(const decs_t* decs, vec_t* gamma_all, uint8_t hash_mt[PARAM_DIGEST_SIZE]) {
    uint32_t j, k;
    uint32_t format_challenge = decs->cfg.format_challenge;
    uint32_t eta = decs->cfg.eta;
    uint32_t nb_polys = decs->cfg.nb_polys;
    
    if(format_challenge == 0) {
        vec_t gamma = malloc_vec(eta);
        xof_decs_challenge(decs, gamma, hash_mt, eta);
        for(k=0; k<eta; k++) {
            felt_set(&gamma_all[k][0], &gamma[k]);
            for(j=1; j<nb_polys; j++)
                felt_mul(&gamma_all[k][j], &gamma_all[k][j-1], &gamma[k]);
        }
        free(gamma);
    } else if(format_challenge == 1) {
        vec_t gamma = malloc_vec(eta*nb_polys);
        xof_decs_challenge(decs, gamma, hash_mt, eta*nb_polys);
        for(k=0; k<eta; k++)
            for(j=0; j<nb_polys; j++)
                felt_set(&gamma_all[k][j], &gamma[k*nb_polys+j]);
        free(gamma);
    } else if(format_challenge == 2) {
        vec_t gamma = malloc_vec((eta+1)+(eta+1)*eta);
        vec_t* mat_rnd = malloc_vec_array(eta, eta+1);
        vec_t* mat_powers = malloc_vec_array(eta+1, nb_polys);
        xof_decs_challenge(decs, gamma, hash_mt, (eta+1)+(eta+1)*eta);
        for(k=0; k<eta; k++)
            for(j=0; j<eta+1; j++)
                felt_set(&mat_rnd[k][j], &gamma[k*(eta+1)+j]);
        for(k=0; k<eta+1; k++) {
            felt_set_one(&mat_powers[k][0]);
            for(j=1; j<nb_polys; j++)
                felt_mul(&mat_powers[k][j], &mat_powers[k][j-1], &gamma[eta*(eta+1)+k]);
        }
        mat_mul(gamma_all, mat_rnd, mat_powers, eta, eta+1, nb_polys);
        free(mat_rnd);
        free(mat_powers);
        free(gamma);
    }
}

int decs_commit(const decs_t* decs, const uint8_t salt[PARAM_SALT_SIZE], const poly_t* polys, uint8_t* transcript, decs_key_t* key) {
    uint32_t i, j, k;
    uint32_t nb_polys = decs->cfg.nb_polys;
    uint32_t degree = decs->cfg.poly_degree;
    uint32_t eta = decs->cfg.eta;
    uint32_t nb_evals = decs->cfg.nb_evals;
    uint32_t use_commitment_tapes = decs->cfg.use_commitment_tapes;
    int ret = 0;

    /**** Initialization the DECS opening key ****/
    check_non_null_pointer("decs_commit", "decs", decs, -1);
    check_non_null_pointer("decs_commit", "polys", polys, -1);
    check_non_null_pointer("decs_commit", "transcript", transcript, -1);
    check_non_null_pointer("decs_commit", "key", key, -1);

    // Malloc the DECS opening key
    ret = decs_key_init(key, decs); ERR(ret, err);
    for(j=0; j<nb_polys; j++)
        poly_set(key->committed_polys[j], polys[j], degree);

    // Sample masking polynomials
    for(k=0; k<eta; k++)
        poly_random(key->masking_polys[k], degree);

    /**** Compute Merkle leaves ****/
    poly_t* all_polys = malloc(sizeof(poly_t)*(nb_polys+eta));
    for(i=0; i<nb_polys; i++)
        all_polys[i] = polys[i];
    for(i=0; i<eta; i++)
        all_polys[nb_polys+i] = key->masking_polys[i];

    uint8_t** leaves = malloc(sizeof(uint8_t*)*nb_evals);
    uint8_t* leaves_data = malloc(nb_evals*PARAM_DIGEST_SIZE);
    map_pointer_array(leaves, leaves_data, uint8_t, nb_evals, PARAM_DIGEST_SIZE);

    vec_t evals = malloc_vec(nb_polys+eta);
    for(uint32_t num=0; num<nb_evals; num++) {
        // Evaluate all the polynomials (committed & masking ones)
        //   for the current leave
        __BENCHMARK_START__(DECS_COMMIT_COMPUTE_LEAVES);
        felt_t eval_point;
        felt_from_uint32(&eval_point, num);
        poly_eval_multiple(&evals, all_polys, &eval_point, degree, nb_polys+eta, 1);
        __BENCHMARK_STOP__(DECS_COMMIT_COMPUTE_LEAVES);

        // Hash the computed evaluation to get the Merkle leave
        __BENCHMARK_START__(DECS_COMMIT_HASH_LEAVES);
        if(use_commitment_tapes) {
            randombytes(key->commitment_tapes[num], PARAM_SEED_SIZE);
            hash_merkle_leave(decs, leaves[num], salt, evals, key->commitment_tapes[num]);
        } else {
            hash_merkle_leave(decs, leaves[num], salt, evals, NULL);
        }
        __BENCHMARK_STOP__(DECS_COMMIT_HASH_LEAVES);
    }
    free(evals);
    free(all_polys);

    /**** Expand Merkle Tree & Hash root ****/

    // Expand Merkle Tree
    __BENCHMARK_START__(DECS_COMMIT_MERKLE_TREE);
    uint8_t mt_root[PARAM_DIGEST_SIZE];
    merkle_tree_expand(decs->tree, salt, (uint8_t const* const*) leaves, mt_root, key->mt_key);
    free(leaves_data);
    free(leaves);

    // Hash root
    uint8_t hash_mt[PARAM_DIGEST_SIZE];
    hash_merkle_root(decs, hash_mt, salt, mt_root);
    __BENCHMARK_STOP__(DECS_COMMIT_MERKLE_TREE);

    /**** Run DEC test ****/

    // Expand DEC challenge
    __BENCHMARK_START__(DECS_COMMIT_XOF_MERKLE_ROOT);
    vec_t* gamma_all = malloc_vec_array(eta, nb_polys);
    derive_decs_challenge(decs, gamma_all, hash_mt);    
    __BENCHMARK_STOP__(DECS_COMMIT_XOF_MERKLE_ROOT);

    // Compute DEC polynomials
    __BENCHMARK_START__(DECS_COMMIT_COMPUTE_DEC_POLYS);
    poly_t poly_tmp = malloc_poly(degree);
    for(k=0; k<eta; k++) {
        poly_set_zero(key->dec_polys[k], degree);
        for(j=0; j<nb_polys; j++) {
            poly_mul_scalar(poly_tmp, polys[j], &gamma_all[k][j], degree);
            poly_add(key->dec_polys[k], key->dec_polys[k], poly_tmp, degree);
        }
        poly_add(key->dec_polys[k], key->dec_polys[k], key->masking_polys[k], degree);
    }
    free(poly_tmp);
    __BENCHMARK_STOP__(DECS_COMMIT_COMPUTE_DEC_POLYS);
    free(gamma_all);

    /**** Build Transcript ****/
    WRITE_BUFFER_BYTES(transcript, hash_mt, PARAM_DIGEST_SIZE);
    for(k=0; k<eta; k++)
        WRITE_BUFFER_POLY(transcript, key->dec_polys[k], degree);

err:
    return ret;
}

uint32_t decs_max_sizeof_proof(const decs_t* decs) {
    check_non_null_pointer("decs_max_sizeof_proof", "decs", decs, 0);

    uint32_t degree = decs->cfg.poly_degree;
    uint32_t eta = decs->cfg.eta;
    uint32_t nb_opened_evals = decs->cfg.nb_opened_evals;
    uint32_t use_commitment_tapes = decs->cfg.use_commitment_tapes;

    uint32_t proof_size = 0;
    proof_size += merkle_tree_max_sizeof_auth(decs->tree, nb_opened_evals);
    proof_size += vec_get_bytesize(eta)*nb_opened_evals + eta*vec_get_bytesize(degree+1-nb_opened_evals);
    if(use_commitment_tapes)
        proof_size += nb_opened_evals*PARAM_SEED_SIZE;
    return proof_size;
}

uint8_t* decs_open(const decs_t* decs, const decs_key_t* key, const vec_t eval_points, felt_t** evals, uint32_t* proof_size) {
    uint32_t j, k;
    uint32_t nb_polys = decs->cfg.nb_polys;
    uint32_t degree = decs->cfg.poly_degree;
    uint32_t eta = decs->cfg.eta;
    uint32_t nb_opened_evals = decs->cfg.nb_opened_evals;
    uint32_t use_commitment_tapes = decs->cfg.use_commitment_tapes;

    check_non_null_pointer("decs_open", "decs", decs, NULL);
    check_non_null_pointer("decs_open", "key", key, NULL);
    check_non_null_pointer("decs_open", "eval_points", eval_points, NULL);
    check_non_null_pointer("decs_open", "evals", evals, NULL);
    check_non_null_pointer("decs_open", "proof_size", proof_size, NULL);

    // Open authentication path
    __BENCHMARK_START__(DECS_OPEN_OPEN_TREE);
    uint32_t* leaves_indexes = malloc(sizeof(uint32_t)*nb_opened_evals);
    for(j=0; j<nb_opened_evals; j++)
        leaves_indexes[j] = felt_to_uint32(&eval_points[j]);
    uint32_t auth_size;
    uint8_t* auth = merkle_tree_open(decs->tree, key->mt_key, leaves_indexes, nb_opened_evals, &auth_size);
    if(auth == NULL) {
        free(leaves_indexes);
        return NULL;
    }
    __BENCHMARK_STOP__(DECS_OPEN_OPEN_TREE);

    *proof_size = auth_size + vec_get_bytesize(eta)*nb_opened_evals + eta*vec_get_bytesize(degree+1-nb_opened_evals);
    if(use_commitment_tapes)
        *proof_size += nb_opened_evals*PARAM_SEED_SIZE;
    uint8_t* proof = malloc(*proof_size);
    uint8_t* proof_buffer = proof;

    WRITE_BUFFER_BYTES(proof_buffer, auth, auth_size);
    free(auth);

    __BENCHMARK_START__(DECS_OPEN_COMPUTE_EVALS);
    vec_t masking_evals_j = malloc_vec(eta);
    for(j=0; j<nb_opened_evals; j++) {
        poly_eval_multiple(&evals[j], key->committed_polys, &eval_points[j], degree, nb_polys, 1);

        poly_eval_multiple(&masking_evals_j, key->masking_polys, &eval_points[j], degree, eta, 1);
        WRITE_BUFFER_VEC(proof_buffer, masking_evals_j, eta);
        if(use_commitment_tapes)
            WRITE_BUFFER_BYTES(proof_buffer, key->commitment_tapes[leaves_indexes[j]], PARAM_SEED_SIZE);
    }
    free(masking_evals_j);
    free(leaves_indexes);
    __BENCHMARK_STOP__(DECS_OPEN_COMPUTE_EVALS);

    for(k=0; k<eta; k++) {
        vec_t high = &key->dec_polys[k][nb_opened_evals];
        WRITE_BUFFER_VEC(proof_buffer, high, degree+1-nb_opened_evals);
    }

#ifdef VERBOSE
    printf(" - DECS Proof Size: %d B\n", *proof_size);
    printf("    - Authentication Path: %d B\n", auth_size);
    printf("    - DEC Polys - high degree terms: %d B\n", eta*vec_get_bytesize(degree+1-nb_opened_evals));
    printf("    - Masking Polys - evaluations: %d B\n", vec_get_bytesize(eta)*nb_opened_evals);
#endif
    return proof;
}

int decs_recompute_transcript(const decs_t* decs, const uint8_t salt[PARAM_SALT_SIZE], const vec_t eval_points, felt_t * const * const evals, const uint8_t* proof, uint32_t proof_size, uint8_t* transcript) {
    uint32_t i, j, k;
    uint32_t nb_polys = decs->cfg.nb_polys;
    uint32_t degree = decs->cfg.poly_degree;
    uint32_t eta = decs->cfg.eta;
    uint32_t nb_opened_evals = decs->cfg.nb_opened_evals;
    uint32_t use_commitment_tapes = decs->cfg.use_commitment_tapes;

    check_non_null_pointer("decs_recompute_transcript", "decs", decs, -1);
    check_non_null_pointer("decs_recompute_transcript", "eval_points", eval_points, -1);
    check_non_null_pointer("decs_recompute_transcript", "evals", evals, -1);
    check_non_null_pointer("decs_recompute_transcript", "proof", proof, -1);
    check_non_null_pointer("decs_recompute_transcript", "transcript", transcript, -1);

    uint32_t proof_bytesize_removing_auth = vec_get_bytesize(eta)*nb_opened_evals + eta*vec_get_bytesize(degree+1-nb_opened_evals);
    if(use_commitment_tapes)
        proof_bytesize_removing_auth += nb_opened_evals*PARAM_SEED_SIZE;
    if(proof_size < proof_bytesize_removing_auth) {
        return -1;
    }

    uint32_t* leaves_indexes = malloc(sizeof(uint32_t)*nb_opened_evals);
    for(j=0; j<nb_opened_evals; j++)
        leaves_indexes[j] = felt_to_uint32(&eval_points[j]);

    uint32_t auth_size = proof_size - proof_bytesize_removing_auth;
    const uint8_t* auth = proof;
    const uint8_t* buf = proof + auth_size;

    uint32_t lhash_input_bytesize = PARAM_SALT_SIZE + vec_get_bytesize(nb_polys+eta);
    uint8_t* lhash_input = malloc(lhash_input_bytesize);
    memcpy(lhash_input, salt, PARAM_SALT_SIZE);
    vec_t evals_all = malloc_vec(nb_polys+eta);
    uint8_t* evals_ser = lhash_input + PARAM_SALT_SIZE;
    uint8_t* open_leaves = malloc(nb_opened_evals*PARAM_DIGEST_SIZE);
    vec_t* masking_evals = malloc_vec_array(nb_opened_evals, eta);
    __BENCHMARK_START__(DECS_RECOMPUTE_HASH_LEAVES);
    for(j=0; j<nb_opened_evals; j++) {
        READ_BUFFER_VEC(masking_evals[j], buf, eta);
        vec_set(evals_all, evals[j], nb_polys);
        vec_set(&evals_all[nb_polys], masking_evals[j], eta);
        vec_serialize(evals_ser, evals_all, nb_polys+eta);
        if(use_commitment_tapes) {
            uint8_t commitment_tape[PARAM_SEED_SIZE];
            READ_BUFFER_BYTES(commitment_tape, buf, PARAM_SEED_SIZE);
            hash_merkle_leave(decs, &open_leaves[j*PARAM_DIGEST_SIZE], salt, evals_all, commitment_tape);
        } else {
            hash_merkle_leave(decs, &open_leaves[j*PARAM_DIGEST_SIZE], salt, evals_all, NULL);
        }
    }
    __BENCHMARK_STOP__(DECS_RECOMPUTE_HASH_LEAVES);
    free(lhash_input);
    free(evals_all);

    uint8_t root[PARAM_DIGEST_SIZE];
    __BENCHMARK_START__(DECS_RECOMPUTE_RETRIEVE_ROOT);
    int ret = merkle_tree_retrieve_root(decs->tree, salt, nb_opened_evals, leaves_indexes, open_leaves, auth, auth_size, root);
    __BENCHMARK_STOP__(DECS_RECOMPUTE_RETRIEVE_ROOT);
    free(leaves_indexes);
    free(open_leaves);
    if(ret != 0) {
        free(masking_evals);
        return -1;
    }
    uint8_t hash_mt[PARAM_DIGEST_SIZE];
    __BENCHMARK_START__(DECS_RECOMPUTE_XOF_MERKLE_ROOT);
    hash_merkle_root(decs, hash_mt, salt, root);
    memcpy(transcript, hash_mt, PARAM_DIGEST_SIZE);
    transcript += PARAM_DIGEST_SIZE;
    //print_hex_nl(hash_mt, PARAM_DIGEST_SIZE);

    vec_t* gamma_all = malloc_vec_array(eta, nb_polys);
    derive_decs_challenge(decs, gamma_all, hash_mt);    
    __BENCHMARK_STOP__(DECS_RECOMPUTE_XOF_MERKLE_ROOT);
    vec_t dec_evals = malloc_vec(nb_opened_evals);
    vec_t high_degree_R = malloc_vec(degree+1-nb_opened_evals);
    poly_t dec_poly = malloc_poly(degree);
    felt_t tmp;
    for(k=0; k<eta; k++) {
        // Recompute the opened evaluation of the DEC polynomial
        __BENCHMARK_START__(DECS_RECOMPUTE_COMPUTE_DEC_EVALS);
        vec_set_zero(dec_evals, nb_opened_evals);
        for(i=0; i<nb_opened_evals; i++) {
            for(j=0; j<nb_polys; j++) {
                felt_mul(&tmp, &evals[i][j], &gamma_all[k][j]);
                felt_add(&dec_evals[i], &dec_evals[i], &tmp);
            }
            felt_add(&dec_evals[i], &dec_evals[i], &masking_evals[i][k]);
        }
        __BENCHMARK_STOP__(DECS_RECOMPUTE_COMPUTE_DEC_EVALS);

        // Restore the DEC polynomial
        __BENCHMARK_START__(DECS_RECOMPUTE_RETRIEVE_DEC_POLYS);
        READ_BUFFER_VEC(high_degree_R, buf, degree+1-nb_opened_evals);
        poly_restore(dec_poly, high_degree_R, dec_evals, eval_points, degree, nb_opened_evals);
        WRITE_BUFFER_POLY(transcript, dec_poly, degree);
        __BENCHMARK_STOP__(DECS_RECOMPUTE_RETRIEVE_DEC_POLYS);
    }
    free(dec_poly);
    free(dec_evals);
    free(high_degree_R);
    free(gamma_all);
    free(masking_evals);

    return 0;
}

static int decs_compute_opening_challenge(const decs_t* decs, const uint8_t trans_hash[PARAM_DIGEST_SIZE], uint8_t nonce[NONCE_BYTESIZE], vec_t eval_points) {

    uint32_t nb_opened_evals = decs->cfg.nb_opened_evals;
    int ret = 0;

    uint32_t* leaves_indexes = (uint32_t*) malloc(sizeof(uint32_t)*nb_opened_evals);
    uint32_t vpow;
    xof_decs_opening(decs, leaves_indexes, &vpow, nonce, trans_hash); ERR(ret, err);
    merkle_tree_sort_leave_indexes(nb_opened_evals, leaves_indexes);

    for(uint32_t j=0; j<nb_opened_evals; j++)
        felt_from_uint32(&eval_points[j], leaves_indexes[j]);

    for(uint32_t i=0; i<nb_opened_evals; i++) {
        for(uint32_t j=i+1; j<nb_opened_evals; j++) {
            if(felt_is_equal(&eval_points[i], &eval_points[j])) {
                ret = -1;
            }
        }
    }

err:
    free(leaves_indexes);
    return ret;
}

int decs_get_opening_challenge(const decs_t* decs, const uint8_t trans_hash[PARAM_DIGEST_SIZE], vec_t eval_points, uint8_t nonce[NONCE_BYTESIZE]) {
    check_non_null_pointer("decs_get_opening_challenge", "decs", decs, -1);
    check_non_null_pointer("decs_get_opening_challenge", "trans_hash", trans_hash, -1);
    check_non_null_pointer("decs_get_opening_challenge", "eval_points", eval_points, -1);
    check_non_null_pointer("decs_get_opening_challenge", "nonce", nonce, -1);

    uint32_t* counter = (uint32_t*) nonce;
    *counter = 0;
    while(decs_compute_opening_challenge(decs, trans_hash, nonce, eval_points) != 0) {
        (*counter)++;
    }
    return 0;
}

int decs_recompute_opening_challenge(const decs_t* decs, const uint8_t trans_hash[PARAM_DIGEST_SIZE], uint8_t nonce[NONCE_BYTESIZE], vec_t eval_points) {
    check_non_null_pointer("decs_recompute_opening_challenge", "decs", decs, -1);
    check_non_null_pointer("decs_recompute_opening_challenge", "trans_hash", trans_hash, -1);
    check_non_null_pointer("decs_recompute_opening_challenge", "eval_points", eval_points, -1);
    check_non_null_pointer("decs_recompute_opening_challenge", "nonce", nonce, -1);

    return decs_compute_opening_challenge(decs, trans_hash, nonce, eval_points);
}
