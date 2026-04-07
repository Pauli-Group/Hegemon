#include "smallwood-internal.h"
#include "utils.h"
#include "smallwood-hash.h"

uint32_t smallwood_max_sizeof_proof(const smallwood_t* sw) {
    uint32_t proof_size_without_pcs_proof = sw->proof_size_without_pcs_proof;
    uint32_t pcs_proof_size = pcs_max_sizeof_proof(sw->pcs);
    uint32_t proof_size = proof_size_without_pcs_proof + pcs_proof_size;
    return proof_size;
}

uint8_t* smallwood_prove_with_data(const smallwood_t* sw, const lppc_t* lppc, const vec_t witness, const uint8_t* binded_data, uint32_t binded_data_bytesize, uint32_t* proof_size) {
    const lppc_cfg_t* lppc_cfg = &sw->lppc_cfg;
    piop_t* piop = sw->piop;
    uint32_t nb_wit_rows = lppc_cfg->nb_wit_rows;
    uint32_t nb_opened_evals = sw->nb_opened_evals;
    uint32_t rho = sw->rho;
    uint32_t wit_poly_degree = sw->wit_poly_degree;
    uint32_t mpol_poly_degree = sw->mpol_poly_degree;
    uint32_t mlin_poly_degree = sw->mlin_poly_degree;
    uint32_t piop_transcript_size = piop_get_transcript_size(piop);
    uint32_t piop_proof_size = piop_get_proof_size(piop);
    pcs_t* pcs = sw->pcs;
    uint32_t pcs_transcript_size = pcs_get_transcript_size(pcs);
    uint32_t proof_size_without_pcs_proof = sw->proof_size_without_pcs_proof;

    int ret = 0;
    uint8_t* proof = NULL;

    // Initialization
    poly_t* wit_polys = malloc_poly_array(nb_wit_rows, wit_poly_degree);
    poly_t* pmask_polys = malloc_poly_array(rho, mpol_poly_degree);
    poly_t* lmask_polys = malloc_poly_array(rho, mlin_poly_degree);
    poly_t* all_polys = malloc(sizeof(poly_t*)*(nb_wit_rows+2*rho));
    for(uint32_t i=0; i<nb_wit_rows; i++)
        all_polys[i] = wit_polys[i];
    for(uint32_t i=0; i<rho; i++)
        all_polys[i+nb_wit_rows] = pmask_polys[i];
    for(uint32_t i=0; i<rho; i++)
        all_polys[i+nb_wit_rows+rho] = lmask_polys[i];
    uint8_t* piop_transcript = malloc(piop_transcript_size);
    uint8_t* piop_proof = malloc(piop_proof_size);
    uint8_t* pcs_transcript_with_data = malloc(pcs_transcript_size+binded_data_bytesize);
    vec_t eval_points = malloc_vec(nb_opened_evals);
    vec_t* all_evals = malloc_vec_array(nb_opened_evals, nb_wit_rows+2*rho);
    pcs_key_t* pcs_key = malloc(pcs_get_key_bytesize(pcs));

    uint8_t salt[PARAM_SALT_SIZE];
    randombytes(salt, PARAM_SALT_SIZE);

    // Polynomial Commitment
    ret = piop_prepare_input_polynomials(piop, witness, wit_polys, pmask_polys, lmask_polys); ERR(ret, err);
    ret = pcs_commit(pcs, salt, all_polys, pcs_transcript_with_data, pcs_key); ERR(ret, err);

    // Polynomial IOP
    memcpy(pcs_transcript_with_data+pcs_transcript_size, binded_data, binded_data_bytesize);
    ret = piop_run(piop, lppc, pcs_transcript_with_data, pcs_transcript_size+binded_data_bytesize, wit_polys, pmask_polys, lmask_polys, piop_transcript, piop_proof); ERR(ret, err);

    uint8_t h_piop[PARAM_DIGEST_SIZE];
    hash_piop_transcript(sw, h_piop, piop_transcript, piop_transcript_size);
    uint8_t nonce[NONCE_BYTESIZE];
    uint32_t counter;
    counter = 0;
    uint32_t can_continue;
    vec_t packing_points = piop_get_packing_points(piop);
    do {
        *((uint32_t*) nonce) = counter;

        uint32_t vpow;
        xof_piop_opening_challenge(sw, eval_points, &vpow, nonce, h_piop, nb_opened_evals);

        can_continue = (vpow == 0);
        for(uint32_t i=0; i<nb_opened_evals; i++)
            for(uint32_t j=0; j<lppc_cfg->packing_factor; j++)
                if(felt_is_equal(&eval_points[i], &packing_points[j]))
                    can_continue = 0;

        counter++;
    } while(!can_continue);

    // PCS Opening
    uint32_t pcs_proof_size;
    uint8_t* pcs_proof = pcs_open(pcs, pcs_key, eval_points, h_piop, PARAM_DIGEST_SIZE, all_evals, &pcs_proof_size);
    if(pcs_proof == NULL) {
        goto err;
    }

    // Signature assembling
    *proof_size = proof_size_without_pcs_proof + pcs_proof_size;
    proof = malloc(*proof_size);
    uint8_t* buffer = proof;
    WRITE_BUFFER_BYTES(buffer, nonce, NONCE_BYTESIZE);
    WRITE_BUFFER_BYTES(buffer, salt, PARAM_SALT_SIZE);
    WRITE_BUFFER_BYTES(buffer, h_piop, PARAM_DIGEST_SIZE);
    WRITE_BUFFER_BYTES(buffer, piop_proof, piop_proof_size);
    WRITE_BUFFER_BYTES(buffer, pcs_proof, pcs_proof_size);
    for(uint32_t num_eval=0; num_eval<nb_opened_evals; num_eval++)
        WRITE_BUFFER_VEC(buffer, all_evals[num_eval], nb_wit_rows+2*rho);
    free(pcs_proof);

#ifdef VERBOSE
    printf(" - SmallWood Proof Size: %d B\n", *proof_size);
    printf("    - PCS Proof Size: %d B\n", pcs_proof_size);
    printf("    - PIOP Proof Size: %d B\n", piop_get_proof_size(piop));
    uint32_t nb_polys = nb_wit_rows + 2*rho;
    printf("    - Opened Evaluations: %d B\n", nb_opened_evals*vec_get_bytesize(nb_polys));
#endif
err:
    free(pcs_key);
    free(wit_polys);
    free(pmask_polys);
    free(lmask_polys);
    free(all_polys);
    free(piop_transcript);
    free(piop_proof);
    free(pcs_transcript_with_data);
    free(eval_points);
    free(all_evals);
    return proof;
}

int smallwood_verify_with_data(const smallwood_t* sw, const lppc_t* lppc, const uint8_t* binded_data, uint32_t binded_data_bytesize, const uint8_t* proof, uint32_t proof_size) {
    const lppc_cfg_t* lppc_cfg = &sw->lppc_cfg;
    piop_t* piop = sw->piop;
    uint32_t nb_wit_rows = lppc_cfg->nb_wit_rows;
    uint32_t nb_opened_evals = sw->nb_opened_evals;
    uint32_t rho = sw->rho;
    uint32_t piop_transcript_size = piop_get_transcript_size(piop);
    uint32_t piop_proof_size = piop_get_proof_size(piop);
    pcs_t* pcs = sw->pcs;
    uint32_t pcs_transcript_size = pcs_get_transcript_size(pcs);
    uint32_t proof_size_without_pcs_proof = sw->proof_size_without_pcs_proof;
    int ret = 0;

    // Initialization: Proof Parsing
    const uint8_t *nonce, *salt, *h_piop, *pi_piop, *pcs_proof;
    uint8_t* pcs_transcript_with_data = malloc(pcs_transcript_size+binded_data_bytesize);
    uint8_t* piop_transcript = malloc(piop_transcript_size);
    vec_t eval_points = malloc_vec(nb_opened_evals);
    vec_t* all_evals = malloc_vec_array(nb_opened_evals, nb_wit_rows+2*rho);
    vec_t* wit_evals = malloc_vec_array(nb_opened_evals, nb_wit_rows);
    vec_t* pmask_evals = malloc_vec_array(nb_opened_evals, rho);
    vec_t* lmask_evals = malloc_vec_array(nb_opened_evals, rho);

    if(proof_size < proof_size_without_pcs_proof) {
        ret = -1;
        goto err;
    }
    uint32_t pcs_proof_size = proof_size - proof_size_without_pcs_proof;
    SET_BUFFER_BYTES(nonce,   proof, NONCE_BYTESIZE);
    SET_BUFFER_BYTES(salt,    proof, PARAM_SALT_SIZE);
    SET_BUFFER_BYTES(h_piop,  proof, PARAM_DIGEST_SIZE);
    SET_BUFFER_BYTES(pi_piop, proof, piop_proof_size);
    SET_BUFFER_BYTES(pcs_proof, proof, pcs_proof_size);
    for(uint32_t num_eval=0; num_eval<nb_opened_evals; num_eval++)
        READ_BUFFER_VEC(all_evals[num_eval], proof, nb_wit_rows+2*rho);

    // PIOP Challenge Recomputation
    uint32_t vpow;
    xof_piop_opening_challenge(sw, eval_points, &vpow, nonce, h_piop, nb_opened_evals);
    if(vpow != 0) {
        ret = -1;
        goto err;
    }

    // Polynomial Commitment Recomputation
    ret = pcs_recompute_transcript(pcs, salt, eval_points, h_piop, PARAM_DIGEST_SIZE, all_evals, pcs_proof, pcs_proof_size, pcs_transcript_with_data);
    if(ret != 0)
        goto err;

    // PIOP Transcript Recomputation
    for(uint32_t num_eval=0; num_eval<nb_opened_evals; num_eval++) {
        for(uint32_t i=0; i<nb_wit_rows; i++)
            felt_set(&wit_evals[num_eval][i], &all_evals[num_eval][i]);
        for(uint32_t i=0; i<rho; i++)
            felt_set(&pmask_evals[num_eval][i], &all_evals[num_eval][i+nb_wit_rows]);
        for(uint32_t i=0; i<rho; i++)
            felt_set(&lmask_evals[num_eval][i], &all_evals[num_eval][i+nb_wit_rows+rho]);
    }
    memcpy(pcs_transcript_with_data+pcs_transcript_size, binded_data, binded_data_bytesize);
    ret = piop_recompute_transcript(piop, lppc, pcs_transcript_with_data, pcs_transcript_size+binded_data_bytesize, eval_points, wit_evals, pmask_evals, lmask_evals, pi_piop, piop_transcript);
    if(ret != 0)
        goto err;

    // Final Verification
    uint8_t h_piop_recomputed[PARAM_DIGEST_SIZE];
    hash_piop_transcript(sw, h_piop_recomputed, piop_transcript, piop_transcript_size);
    if(memcmp(h_piop_recomputed, h_piop, PARAM_DIGEST_SIZE) != 0) {
        ret = -1;
        goto err;
    }

err:
    free(pcs_transcript_with_data);
    free(piop_transcript);
    free(eval_points);
    free(all_evals);
    free(wit_evals);
    free(pmask_evals);
    free(lmask_evals);
    return ret;
}

