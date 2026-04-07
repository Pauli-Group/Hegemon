#include "piop-internal.h"
#include "utils.h"
#include "parameters.h"
#include <stdio.h>

#define PIOP_SIZE_MEMORY_MAPPING 3
static int piop_init_internal(const lppc_cfg_t* lppc_cfg, const piop_cfg_t* piop_cfg, piop_t** piop, uint32_t* piop_bytesize, uint32_t dry_run, uint32_t allocate) {
    int ret = -1;
    if(dry_run != 0 && allocate != 0)
        return ret;
    if(allocate)
        *piop = NULL;
        
    uint32_t piop_bytesize_mem;
    if(piop_bytesize == NULL)
        piop_bytesize = &piop_bytesize_mem;

    uint32_t rho = piop_cfg->rho;
    uint32_t nb_opened_evals = piop_cfg->nb_opened_evals;
    uint32_t format_challenge = piop_cfg->format_challenge;
    if(format_challenge >= 3)
        return ret;

    uint32_t data_bytesize[PIOP_SIZE_MEMORY_MAPPING];
    data_bytesize[0] = sizeof(piop_t);
    data_bytesize[1] = sizeof(felt_t)*lppc_cfg->packing_factor;
    data_bytesize[2] = lppc_cfg->get_preprocessing_material_bytesize(lppc_cfg);

    *piop_bytesize = get_bytesize_from_array(data_bytesize, PIOP_SIZE_MEMORY_MAPPING);

    if(!dry_run) {
        if(allocate)
            *piop = malloc(*piop_bytesize);
        if(*piop == NULL)
            goto err;

        uint8_t* data_mapping[PIOP_SIZE_MEMORY_MAPPING];
        build_memory_mapping(data_mapping, *piop, data_bytesize, PIOP_SIZE_MEMORY_MAPPING);
        (*piop)->packing_points = (vec_t) data_mapping[1];
        (*piop)->preprocessing_material = data_mapping[2];
        
        memcpy(&(*piop)->lppc_cfg, lppc_cfg, sizeof(lppc_cfg_t));
        (*piop)->rho = rho;
        (*piop)->nb_opened_evals = nb_opened_evals;
        (*piop)->format_challenge = format_challenge;
        (*piop)->out_ppol_degree = lppc_cfg->constraint_degree*(lppc_cfg->packing_factor+nb_opened_evals-1)-lppc_cfg->packing_factor;
        (*piop)->out_plin_degree = (lppc_cfg->packing_factor+nb_opened_evals-1)+(lppc_cfg->packing_factor-1);
        for(uint32_t i=0; i<lppc_cfg->packing_factor; i++) {
            felt_from_uint32(&(*piop)->packing_points[i], i);
        }
        lppc_cfg->preprocess_packing_points(lppc_cfg, (*piop)->packing_points, (*piop)->preprocessing_material);
        
        (*piop)->proof_bytesize = rho*(vec_get_bytesize((*piop)->out_ppol_degree+1-(*piop)->nb_opened_evals)+vec_get_bytesize((*piop)->out_plin_degree-(*piop)->nb_opened_evals));
        (*piop)->transcript_bytesize = PARAM_DIGEST_SIZE+rho*(poly_get_bytesize((*piop)->out_ppol_degree)+poly_get_bytesize((*piop)->out_plin_degree-1));

#ifdef VERBOSE
        printf("=======  LPPC  =====\n");
        printf("== Constraint Degree: %d\n", lppc_cfg->constraint_degree);
        printf("=======  PIOP  =====\n");
        printf("== Rho: %d\n", rho);
        printf("== Nb opened evals: %d\n", nb_opened_evals);
#endif
    }

    ret = 0;
err:
    if(allocate && ret != 0)
        free(*piop);
    return ret;
}


uint32_t piop_alloc_bytesize(const lppc_cfg_t* lppc_cfg, const piop_cfg_t* piop_cfg) {
    uint32_t pcs_bytesize;
    int ret = piop_init_internal(lppc_cfg, piop_cfg, NULL, &pcs_bytesize, 1, 0);
    return (ret == 0) ? pcs_bytesize : 0;
}

int piop_init(piop_t* piop, const lppc_cfg_t* lppc_cfg, const piop_cfg_t* piop_cfg) {
    return piop_init_internal(lppc_cfg, piop_cfg, &piop, NULL, 0, 0);
}

piop_t* malloc_piop(const lppc_cfg_t* lppc_cfg, const piop_cfg_t* piop_cfg) {
    piop_t* piop;
    int ret = piop_init_internal(lppc_cfg, piop_cfg, &piop, NULL, 0, 1);
    return (ret == 0) ? piop : NULL;
}
