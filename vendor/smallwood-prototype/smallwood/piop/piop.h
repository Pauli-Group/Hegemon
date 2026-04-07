#ifndef __PIOP_H__
#define __PIOP_H__

#include "lppc.h"

typedef struct {
    uint32_t rho;
    uint32_t nb_opened_evals;
    uint32_t pow_bits;
    uint32_t format_challenge; // 0 = powers, 1 = uniform, 2 = hybrid
} piop_cfg_t;

typedef struct piop_t piop_t;

vec_t piop_get_packing_points(const piop_t* piop);

uint32_t piop_get_transcript_size(const piop_t* piop);
uint32_t piop_get_proof_size(const piop_t* piop);

uint32_t piop_alloc_bytesize(const lppc_cfg_t* lppc_cfg, const piop_cfg_t* piop_cfg);
int piop_init(piop_t* piop, const lppc_cfg_t* lppc_cfg, const piop_cfg_t* piop_cfg);
piop_t* malloc_piop(const lppc_cfg_t* lppc_cfg, const piop_cfg_t* piop_cfg);

void piop_get_input_degrees(const lppc_cfg_t* lppc_cfg, const piop_cfg_t* piop_cfg, uint32_t* wit_degree, uint32_t* mpol_pol_degree, uint32_t* mpol_lin_degree);
int piop_prepare_input_polynomials(const piop_t* piop, vec_t witness, poly_t* wit_polys, poly_t* mpol_ppol, poly_t* mpol_plin);

int piop_run(const piop_t* piop, const lppc_t* lppc, const uint8_t* in_transcript, uint32_t in_transcript_bytesize, const poly_t* wit_polys, const poly_t* mpol_ppoly, const poly_t* mpol_plin, uint8_t* out_transcript, uint8_t* proof);
int piop_recompute_transcript(const piop_t* piop, const lppc_t* lppc, const uint8_t* in_transcript, uint32_t in_transcript_bytesize, const vec_t eval_points, const vec_t* wit_evals, const vec_t* meval_ppoly, vec_t* meval_plin, const uint8_t* proof, uint8_t* out_transcript);

#endif /* __PIOP_H__ */
