#ifndef __DECS_INTERNAL_H__
#define __DECS_INTERNAL_H__

#include "decs.h"

struct decs_t {
    decs_cfg_t cfg;
    merkle_tree_t* tree;
};

struct decs_key_t {
    merkle_tree_key_t* mt_key;
    poly_t* committed_polys;
    poly_t* masking_polys;
    poly_t* dec_polys;
    uint8_t** commitment_tapes;
};

uint32_t decs_key_alloc_bytesize(const decs_t* decs);
int decs_key_init(decs_key_t* key, const decs_t* decs);

#endif /* __DECS_INTERNAL_H__ */
