#ifndef __LVCS_H__
#define __LVCS_H__

#include "field.h"
#include "parameters.h"
#include "merkle.h"

typedef struct {
    uint32_t nb_rows;
    uint32_t nb_cols;
    uint32_t nb_opened_combi;
    uint32_t decs_nb_evals;
    uint32_t decs_nb_opened_evals;
    uint32_t decs_eta;
    uint32_t decs_pow_bits;
    uint32_t decs_use_commitment_tapes;
    uint32_t decs_format_challenge;
    merkle_tree_cfg_t* decs_tree_cfg;
} lvcs_cfg_t;

typedef struct lvcs_t lvcs_t;
typedef struct lvcs_key_t lvcs_key_t;

uint32_t lvcs_alloc_bytesize(const lvcs_cfg_t* lvcs_cfg);
int lvcs_init(lvcs_t* lvcs, const lvcs_cfg_t* lvcs_cfg);
lvcs_t* malloc_lvcs(const lvcs_cfg_t* lvcs_cfg);

uint32_t lvcs_get_transcript_size(const lvcs_t* lvcs);
uint32_t lvcs_get_key_bytesize(const lvcs_t* lvcs);
uint32_t lvcs_max_sizeof_proof(const lvcs_t* lvcs);

int lvcs_commit(const lvcs_t* lvcs, const uint8_t salt[PARAM_SALT_SIZE], vec_t const* const rows, uint8_t* transcript, lvcs_key_t* key);
uint8_t* lvcs_open(const lvcs_t* lvcs, const lvcs_key_t* key, felt_t* const* const coeffs, uint32_t* fullrank_cols, const uint8_t* prtranscript, uint32_t prtranscript_bytesize, vec_t* combi, uint32_t* proof_size);

int lvcs_recompute_transcript(const lvcs_t* lvcs, const uint8_t salt[PARAM_SALT_SIZE], felt_t* const* const coeffs, uint32_t* fullrank_cols, const uint8_t* prtranscript, uint32_t prtranscript_bytesize, felt_t* const* const combi, const uint8_t* proof, uint32_t proof_size, uint8_t* transcript);

#endif /* __LVCS_H__ */
