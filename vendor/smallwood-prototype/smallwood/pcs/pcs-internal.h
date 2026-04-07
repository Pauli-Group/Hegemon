#ifndef __PCS_INTERNAL_H__
#define __PCS_INTERNAL_H__

#include "pcs.h"
#include "lvcs.h"

struct pcs_t {
    uint32_t nb_polys;
    uint32_t nb_opened_evals;
    uint32_t* degree;
    uint32_t* width;
    uint32_t* delta;
    uint32_t mu;
    uint32_t beta;
    uint32_t nb_unstacked_rows;
    uint32_t nb_unstacked_cols;
    uint32_t nb_lvcs_rows;
    uint32_t nb_lvcs_cols;
    uint32_t nb_lvcs_opened_combi;
    uint32_t* fullrank_cols;
    lvcs_t* lvcs;
};

struct pcs_key_t {
    lvcs_key_t* lvcs_key;
};

#endif /* __PCS_INTERNAL_H__ */
