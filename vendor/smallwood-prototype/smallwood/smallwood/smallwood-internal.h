#ifndef __SMALLWOOD_INTERNAL_H__
#define __SMALLWOOD_INTERNAL_H__

#include "smallwood.h"
#include "pcs.h"
#include "piop.h"

struct smallwood_t {
    piop_t* piop;
    pcs_t* pcs;
    uint32_t proof_size_without_pcs_proof;
    lppc_cfg_t lppc_cfg;
    uint32_t nb_opened_evals;
    uint32_t rho;
    uint32_t opening_pow_bits;
    uint32_t wit_poly_degree;
    uint32_t mpol_poly_degree;
    uint32_t mlin_poly_degree;
};

#endif /* __SMALLWOOD_INTERNAL_H__ */
