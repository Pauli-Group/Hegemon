#include "decs-internal.h"
#include "utils.h"
#include <stdio.h>

/////// ALLOCATION MAIN STRUCTURE //////

#define DECS_SIZE_MEMORY_MAPPING 2
static int decs_init_internal(const decs_cfg_t* decs_cfg, decs_t** decs, uint32_t* decs_bytesize, uint32_t dry_run, uint32_t allocate) {
    int ret = -1;
    if(dry_run != 0 && allocate != 0)
        return ret;
    if(allocate)
        *decs = NULL;

    uint32_t decs_bytesize_mem;
    if(decs_bytesize == NULL)
        decs_bytesize = &decs_bytesize_mem;

    if(decs_cfg == NULL) {
        fprintf(stderr, "decs_init: decs should not be a null pointer.\n");
        return ret;
    }
    if(decs_cfg->nb_polys == 0) {
        fprintf(stderr, "decs_init: the number of polynomial (%d) should be non-zero.\n", decs_cfg->nb_polys);
        return ret;
    }
    if(decs_cfg->nb_evals == 0) {
        fprintf(stderr, "decs_init: the total number of evaluations (%d) should be non-zero.\n", decs_cfg->nb_evals);
        return ret;
    }
    if(decs_cfg->nb_opened_evals > decs_cfg->nb_evals) {
        fprintf(stderr, "decs_init: the number of opened evaluations (%d) should be smaller than (or equal to) the total number of evaluations (%d).\n", decs_cfg->nb_opened_evals, decs_cfg->nb_evals);
        return ret;
    }
    if(decs_cfg->pow_bits >= 32) {
        fprintf(stderr, "decs_init: the proof of work (%d bits) should be strictly smaller than 32 bits.\n", decs_cfg->pow_bits);
        return -1;
    }
    if(decs_cfg->format_challenge >= 3) {
        fprintf(stderr, "decs_init: the challenge format (%d bits) should be in {0, 1, 2}.\n", decs_cfg->format_challenge);
        return ret;
    }

    merkle_tree_cfg_t default_tree_cfg = {
        .nb_leaves = decs_cfg->nb_evals
    };
    merkle_tree_cfg_t* tree_cfg = (decs_cfg->tree_cfg) ? decs_cfg->tree_cfg : &default_tree_cfg;

    uint32_t data_bytesize[DECS_SIZE_MEMORY_MAPPING];
    data_bytesize[0] = sizeof(decs_t);
    data_bytesize[1] = merkle_tree_sizeof(tree_cfg);

    *decs_bytesize = get_bytesize_from_array(data_bytesize, DECS_SIZE_MEMORY_MAPPING);

    if(!dry_run) {
        if(allocate) {
            *decs = malloc(*decs_bytesize);
        }
        if(*decs == NULL)
            goto err;

        uint8_t* data_mapping[DECS_SIZE_MEMORY_MAPPING];
        build_memory_mapping(data_mapping, *decs, data_bytesize, DECS_SIZE_MEMORY_MAPPING);

        memcpy(&(*decs)->cfg, decs_cfg, sizeof(decs_cfg_t));
        (*decs)->tree = (merkle_tree_t*) data_mapping[1];
        merkle_tree_init((*decs)->tree, tree_cfg);
        if(merkle_tree_get_nb_leaves((*decs)->tree) != decs_cfg->nb_evals) {
            fprintf(stderr, "decs_init: the number of leaves in the Merkle tree configuration (%d) does not match the number of evaluations (%d).\n", merkle_tree_get_nb_leaves((*decs)->tree), decs_cfg->nb_evals);
            goto err;
        }
    
    #ifdef VERBOSE
        printf("=======  DECS  =====\n");
        printf("== Nb polys: %d\n", decs_cfg->nb_polys);
        printf("== Degree: %d\n", decs_cfg->poly_degree);
        printf("== Nb Evals: %d\n", decs_cfg->nb_evals);
        printf("== Nb Opened Evals: %d\n", decs_cfg->nb_opened_evals);
        printf("== Eta: %d\n", decs_cfg->eta);
        printf("== PoW Bits: %d\n", decs_cfg->pow_bits);
        printf("== Use tape commitments: %d\n", decs_cfg->use_commitment_tapes);
        printf("== Format Challenge: %d\n", decs_cfg->format_challenge);
    #endif
    }

    ret = 0;
err:
    if(allocate && ret != 0)
        free(*decs);
    return ret;
}

uint32_t decs_alloc_bytesize(const decs_cfg_t* decs_cfg) {
    uint32_t decs_bytesize;
    int ret = decs_init_internal(decs_cfg, NULL, &decs_bytesize, 1, 0);
    return (ret == 0) ? decs_bytesize : 0;
}

int decs_init(decs_t* decs, const decs_cfg_t* decs_cfg) {
    return decs_init_internal(decs_cfg, &decs, NULL, 0, 0);
}

decs_t* malloc_decs(const decs_cfg_t* decs_cfg) {
    decs_t* decs;
    int ret = decs_init_internal(decs_cfg, &decs, NULL, 0, 1);
    return (ret == 0) ? decs : NULL;
}

/////// ALLOCATION KEY STRUCTURE //////

#define DECS_KEY_SIZE_MEMORY_MAPPING 6
static int decs_key_init_internal(const decs_t* decs, decs_key_t** key, uint32_t* key_bytesize, uint32_t dry_run, uint32_t allocate) {
    int ret = -1;
    if(dry_run != 0 && allocate != 0)
        return ret;
    if(allocate)
        *key = NULL;

    uint32_t key_bytesize_mem;
    if(key_bytesize == NULL)
        key_bytesize = &key_bytesize_mem;

    uint32_t nb_polys = decs->cfg.nb_polys;
    uint32_t poly_degree = decs->cfg.poly_degree;
    uint32_t nb_evals = decs->cfg.nb_evals;
    uint32_t eta = decs->cfg.eta;
    uint32_t use_commitment_tapes = decs->cfg.use_commitment_tapes;

    uint32_t data_bytesize[DECS_KEY_SIZE_MEMORY_MAPPING];
    data_bytesize[0] = sizeof(decs_key_t);
    data_bytesize[1] = merkle_tree_sizeof_key(decs->tree);
    data_bytesize[2] = get_array_alloc_bytesize(felt_t, eta, poly_degree+1);
    data_bytesize[3]= get_array_alloc_bytesize(felt_t, nb_polys, poly_degree+1);
    data_bytesize[4] = get_array_alloc_bytesize(felt_t, eta, poly_degree+1);
    if(use_commitment_tapes)
        data_bytesize[5] = get_array_alloc_bytesize(uint8_t, nb_evals, PARAM_SEED_SIZE);
    else
        data_bytesize[5] = 0;

    *key_bytesize = get_bytesize_from_array(data_bytesize, DECS_KEY_SIZE_MEMORY_MAPPING);

    if(!dry_run) {
        if(allocate) {
            *key = malloc(*key_bytesize);
        }
        if(*key == NULL)
            goto err;

        uint8_t* data_mapping[DECS_KEY_SIZE_MEMORY_MAPPING];
        build_memory_mapping(data_mapping, *key, data_bytesize, DECS_KEY_SIZE_MEMORY_MAPPING);
    
        (*key)->mt_key = (merkle_tree_key_t*) data_mapping[1];
        set_pointer_array((*key)->masking_polys, data_mapping[2], felt_t, eta, poly_degree+1);
        set_pointer_array((*key)->committed_polys, data_mapping[3], felt_t, nb_polys, poly_degree+1);
        set_pointer_array((*key)->dec_polys, data_mapping[4], felt_t, eta, poly_degree+1);
        if(use_commitment_tapes) {
            set_pointer_array((*key)->commitment_tapes, data_mapping[5], uint8_t, nb_evals, PARAM_SEED_SIZE);
        } else
            (*key)->commitment_tapes = NULL;
    }

    ret = 0;
err:
    if(allocate && ret != 0)
        free(*key);
    return ret;
}

uint32_t decs_key_alloc_bytesize(const decs_t* decs) {
    uint32_t key_bytesize;
    int ret = decs_key_init_internal(decs, NULL, &key_bytesize, 1, 0);
    return (ret == 0) ? key_bytesize : 0;
}

int decs_key_init(decs_key_t* key, const decs_t* decs) {
    return decs_key_init_internal(decs, &key, NULL, 0, 0);
}

decs_key_t* malloc_decs_key(const decs_t* decs) {
    decs_key_t* key;
    int ret = decs_key_init_internal(decs, &key, NULL, 0, 1);
    return (ret == 0) ? key : NULL;
}
