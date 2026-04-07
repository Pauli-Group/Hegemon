#include "smallwood-internal.h"
#include "utils.h"
#include <stdio.h>

#define SW_SIZE_MEMORY_MAPPING 3
static int smallwood_init_internal(const lppc_cfg_t* lppc_cfg, const smallwood_cfg_t* sw_cfg, smallwood_t** sw, uint32_t* sw_bytesize, uint32_t dry_run, uint32_t allocate) {
    int ret = -1;
    if(dry_run != 0 && allocate != 0)
        return ret;
    if(allocate)
        *sw = NULL;

    uint32_t sw_bytesize_mem;
    if(sw_bytesize == NULL)
        sw_bytesize = &sw_bytesize_mem;

    uint32_t rho = sw_cfg->rho;
    uint32_t nb_opened_evals = sw_cfg->nb_opened_evals;
    uint32_t opening_pow_bits = sw_cfg->opening_pow_bits;
    uint32_t beta = sw_cfg->beta;
    uint32_t piop_format_challenge = sw_cfg->piop_format_challenge;
    uint32_t decs_nb_evals = sw_cfg->decs_nb_evals;
    uint32_t decs_nb_opened_evals = sw_cfg->decs_nb_opened_evals;
    uint32_t decs_eta = sw_cfg->decs_eta;
    uint32_t decs_pow_bits = sw_cfg->decs_pow_bits;
    uint32_t decs_use_commitment_tapes = sw_cfg->decs_use_commitment_tapes;
    uint32_t decs_format_challenge = sw_cfg->decs_format_challenge;
    merkle_tree_cfg_t* decs_tree_cfg = sw_cfg->decs_tree_cfg;
    
    uint32_t nb_wit_rows = lppc_cfg->nb_wit_rows;
    uint32_t nb_polys = nb_wit_rows + 2*rho;

    piop_cfg_t piop_cfg = {
        .rho = rho,
        .nb_opened_evals = nb_opened_evals,
        .format_challenge = piop_format_challenge,
    };

    uint32_t* degree = malloc(sizeof(uint32_t)*nb_polys);
    if(degree == NULL)
        goto err;
    
    uint32_t wit_degree, mpol_pol_degree, mpol_lin_degree;
    piop_get_input_degrees(lppc_cfg, &piop_cfg, &wit_degree, &mpol_pol_degree, &mpol_lin_degree);

    for(uint32_t i=0; i<nb_wit_rows; i++)
        degree[i] = wit_degree;
    for(uint32_t i=0; i<rho; i++)
        degree[i+nb_wit_rows] = mpol_pol_degree;
    for(uint32_t i=0; i<rho; i++)
        degree[i+nb_wit_rows+rho] = mpol_lin_degree;
    uint32_t mu = lppc_cfg->packing_factor;

    pcs_cfg_t pcs_cfg = {
        .nb_polys = nb_polys,
        .degree = degree,
        .nb_opened_evals = nb_opened_evals,
        .mu = mu,
        .beta = beta,
        .decs_nb_evals = decs_nb_evals,
        .decs_nb_opened_evals = decs_nb_opened_evals,
        .decs_eta = decs_eta,
        .decs_pow_bits = decs_pow_bits,
        .decs_use_commitment_tapes = decs_use_commitment_tapes,
        .decs_format_challenge = decs_format_challenge,
        .decs_tree_cfg = decs_tree_cfg
    };

    uint32_t data_bytesize[SW_SIZE_MEMORY_MAPPING];
    data_bytesize[0] = sizeof(smallwood_t);
    data_bytesize[1] = pcs_alloc_bytesize(&pcs_cfg);
    data_bytesize[2] = piop_alloc_bytesize(lppc_cfg, &piop_cfg);

    *sw_bytesize = get_bytesize_from_array(data_bytesize, SW_SIZE_MEMORY_MAPPING);

    if(!dry_run) {
        if(allocate)
            *sw = malloc(*sw_bytesize);
        if(*sw == NULL)
            goto err;

        uint8_t* data_mapping[SW_SIZE_MEMORY_MAPPING];
        build_memory_mapping(data_mapping, *sw, data_bytesize, SW_SIZE_MEMORY_MAPPING);
        (*sw)->pcs = (pcs_t*) data_mapping[1];
        (*sw)->piop = (piop_t*) data_mapping[2];
    
        ret = pcs_init((*sw)->pcs, &pcs_cfg);
        if(ret != 0)
            goto err;
        ret = piop_init((*sw)->piop, lppc_cfg, &piop_cfg);
        if(ret != 0)
            goto err;

        (*sw)->proof_size_without_pcs_proof = NONCE_BYTESIZE + PARAM_SALT_SIZE + PARAM_DIGEST_SIZE;
        (*sw)->proof_size_without_pcs_proof += piop_get_proof_size((*sw)->piop) + nb_opened_evals*vec_get_bytesize(nb_polys);
    
        memcpy(&(*sw)->lppc_cfg, lppc_cfg, sizeof(lppc_cfg_t));
        (*sw)->nb_opened_evals = nb_opened_evals;
        (*sw)->rho = rho;
        (*sw)->opening_pow_bits = opening_pow_bits;
        (*sw)->wit_poly_degree = wit_degree;
        (*sw)->mpol_poly_degree = mpol_pol_degree;
        (*sw)->mlin_poly_degree = mpol_lin_degree;        
    }

    ret = 0;
err:
    free(degree);
    if(allocate && ret != 0)
        free(*sw);
    return ret;
}

uint32_t smallwood_alloc_bytesize(const lppc_cfg_t* lppc_cfg, const smallwood_cfg_t* sw_cfg) {
    uint32_t sw_bytesize;
    int ret = smallwood_init_internal(lppc_cfg, sw_cfg, NULL, &sw_bytesize, 1, 0);
    return (ret == 0) ? sw_bytesize : 0;
}

int smallwood_init(smallwood_t* sw, const lppc_cfg_t* lppc_cfg, const smallwood_cfg_t* sw_cfg) {
    return smallwood_init_internal(lppc_cfg, sw_cfg, &sw, NULL, 0, 0);
}

smallwood_t* malloc_smallwood(const lppc_cfg_t* lppc_cfg, const smallwood_cfg_t* sw_cfg) {
    smallwood_t* sw;
    int ret = smallwood_init_internal(lppc_cfg, sw_cfg, &sw, NULL, 0, 1);
    return (ret == 0) ? sw : NULL;
}
