#ifndef __PIOP_INTERNAL_H__
#define __PIOP_INTERNAL_H__

#include "piop.h"

struct piop_t {
    lppc_cfg_t lppc_cfg;
    uint32_t rho;
    uint32_t nb_opened_evals;
    uint32_t format_challenge;
    uint32_t out_ppol_degree;
    uint32_t out_plin_degree;
    uint32_t proof_bytesize;
    uint32_t transcript_bytesize;
    vec_t packing_points;
    uint8_t* preprocessing_material;
};

#endif /* __PIOP_INTERNAL_H__ */
