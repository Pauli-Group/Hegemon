#include "pcs-internal.h"
#include "utils.h"
#include <stdio.h>

#define PCS_SIZE_MEMORY_MAPPING 6
static int pcs_init_internal(const pcs_cfg_t* pcs_cfg, pcs_t** pcs, uint32_t* pcs_bytesize, uint32_t dry_run, uint32_t allocate) {
    int ret = -1;
    if(dry_run != 0 && allocate != 0)
        return ret;
    if(allocate)
        *pcs = NULL;

    uint32_t pcs_bytesize_mem;
    if(pcs_bytesize == NULL)
        pcs_bytesize = &pcs_bytesize_mem;

    uint32_t nb_polys = pcs_cfg->nb_polys;
    uint32_t* degree = pcs_cfg->degree;
    uint32_t nb_opened_evals = pcs_cfg->nb_opened_evals;
    uint32_t mu = pcs_cfg->mu;
    uint32_t beta = pcs_cfg->beta;

    uint32_t *width = malloc(sizeof(uint32_t)*nb_polys);
    uint32_t nb_unstacked_rows = mu + nb_opened_evals;
    uint32_t nb_unstacked_cols = 0;
    for(uint32_t j=0; j<nb_polys; j++) {
        width[j] = (degree[j] + 1 - nb_opened_evals + (mu-1))/mu;
        nb_unstacked_cols += width[j];
    }
    uint32_t nb_lvcs_rows = nb_unstacked_rows*beta;
    uint32_t nb_lvcs_cols = (nb_unstacked_cols + (beta-1))/beta;
    uint32_t nb_opened_combi = beta*nb_opened_evals;

    lvcs_cfg_t lvcs_cfg = {
        .nb_rows = nb_lvcs_rows,
        .nb_cols = nb_lvcs_cols,
        .nb_opened_combi = nb_opened_combi,
        .decs_nb_evals = pcs_cfg->decs_nb_evals,
        .decs_nb_opened_evals = pcs_cfg->decs_nb_opened_evals,
        .decs_eta = pcs_cfg->decs_eta,
        .decs_pow_bits = pcs_cfg->decs_pow_bits,
        .decs_use_commitment_tapes = pcs_cfg->decs_use_commitment_tapes,
        .decs_format_challenge = pcs_cfg->decs_format_challenge,
        .decs_tree_cfg = pcs_cfg->decs_tree_cfg,
    };

    uint32_t data_bytesize[PCS_SIZE_MEMORY_MAPPING];
    data_bytesize[0] = sizeof(pcs_t);
    data_bytesize[1] = sizeof(uint32_t)*nb_polys; // degree
    data_bytesize[2] = sizeof(uint32_t)*nb_polys; // width
    data_bytesize[3] = sizeof(uint32_t)*nb_polys; // delta
    data_bytesize[4] = sizeof(uint32_t)*nb_opened_combi; // fullrank_cols
    data_bytesize[5] = lvcs_alloc_bytesize(&lvcs_cfg);

    *pcs_bytesize = get_bytesize_from_array(data_bytesize, PCS_SIZE_MEMORY_MAPPING);

    if(!dry_run) {
        if(allocate)
            *pcs = malloc(*pcs_bytesize);
        if(*pcs == NULL)
            goto err;

        uint8_t* data_mapping[PCS_SIZE_MEMORY_MAPPING];
        build_memory_mapping(data_mapping, *pcs, data_bytesize, PCS_SIZE_MEMORY_MAPPING);
        (*pcs)->degree = (uint32_t*) data_mapping[1];
        (*pcs)->width = (uint32_t*) data_mapping[2];
        (*pcs)->delta = (uint32_t*) data_mapping[3];
        (*pcs)->fullrank_cols = (uint32_t*) data_mapping[4];
        (*pcs)->lvcs = (lvcs_t*) data_mapping[5];
    
        // Definition
        (*pcs)->nb_polys = nb_polys;
        (*pcs)->nb_opened_evals = nb_opened_evals;
        for(uint32_t j=0; j<nb_polys; j++) {
            (*pcs)->degree[j] = degree[j];
            (*pcs)->width[j] = width[j];
            (*pcs)->delta[j] = (mu*width[j] + nb_opened_evals) - (degree[j]+1);
            // If the polynomial is contained in only one column, it should fill the entire column, otherwise we can not ensure its degree.
            if(width[j] == 1 && (*pcs)->delta[j] != 0) {
                if(allocate)
                    free(*pcs);
                goto err;
            }
        }
        (*pcs)->mu = mu;
        (*pcs)->beta = beta;
        (*pcs)->nb_unstacked_rows = nb_unstacked_rows;
        (*pcs)->nb_unstacked_cols = nb_unstacked_cols;
        (*pcs)->nb_lvcs_rows = nb_lvcs_rows;
        (*pcs)->nb_lvcs_cols = nb_lvcs_cols;
        (*pcs)->nb_lvcs_opened_combi = nb_opened_combi;
        for(uint32_t i=0; i<beta; i++)
            for(uint32_t j=0; j<nb_opened_evals; j++)
            (*pcs)->fullrank_cols[i*nb_opened_evals+j] = i*(mu+nb_opened_evals) + j;
        ret = lvcs_init((*pcs)->lvcs, &lvcs_cfg);
        if(ret != 0) {
            if(allocate)
                free(*pcs);
            goto err;
        }
    
#ifdef VERBOSE
        printf("=======  PCS  =====\n");
        printf("== Nb polys: %d\n", nb_polys);
        printf("== Nb opened evals: %d\n", nb_opened_evals);
        printf("== Mu: %d\n", mu);
        printf("== Beta: %d\n", beta);
#endif
    }

    ret = 0;
err:
    free(width);
    if(allocate && ret != 0)
        free(*pcs);
    return ret;
}

uint32_t pcs_alloc_bytesize(const pcs_cfg_t* pcs_cfg) {
    uint32_t pcs_bytesize;
    int ret = pcs_init_internal(pcs_cfg, NULL, &pcs_bytesize, 1, 0);
    return (ret == 0) ? pcs_bytesize : 0;
}

int pcs_init(pcs_t* pcs, const pcs_cfg_t* pcs_cfg) {
    return pcs_init_internal(pcs_cfg, &pcs, NULL, 0, 0);
}

pcs_t* malloc_pcs(const pcs_cfg_t* pcs_cfg) {
    pcs_t* pcs;
    int ret = pcs_init_internal(pcs_cfg, &pcs, NULL, 0, 1);
    return (ret == 0) ? pcs : NULL;
}

uint32_t pcs_get_key_bytesize(const pcs_t* pcs) {
    return sizeof(pcs_key_t) + lvcs_get_key_bytesize(pcs->lvcs);
}
