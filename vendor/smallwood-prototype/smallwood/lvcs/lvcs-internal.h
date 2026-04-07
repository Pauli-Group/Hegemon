#ifndef __LVCS_INTERNAL_H__
#define __LVCS_INTERNAL_H__

#include "lvcs.h"
#include "decs.h"

struct lvcs_t {
    uint32_t nb_rows;
    uint32_t nb_cols;
    uint32_t nb_opened_combi;
    uint32_t nb_opened_evals;
    vec_t interpolation_points;
    decs_t* decs;
} ;

struct lvcs_key_t {
    decs_key_t* decs_key;
    vec_t* extended_rows;
};

uint32_t lvcs_key_alloc_bytesize(const lvcs_t* lvcs);
int lvcs_key_init(lvcs_key_t* key, const lvcs_t* lvcs);
lvcs_key_t* lvcs_key_malloc(const lvcs_t* lvcs);

#endif /* __LVCS_INTERNAL_H__ */
