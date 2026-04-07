#include "lvcs-internal.h"
#include "utils.h"

/////// ALLOCATION MAIN STRUCTURE //////

#define LVCS_SIZE_MEMORY_MAPPING 3
static int lvcs_init_internal(const lvcs_cfg_t* lvcs_cfg, lvcs_t** lvcs, uint32_t* lvcs_bytesize, uint32_t dry_run, uint32_t allocate) {
    int ret = -1;
    if(dry_run != 0 && allocate != 0)
        return ret;
    if(allocate)
        *lvcs = NULL;

    uint32_t lvcs_bytesize_mem;
    if(lvcs_bytesize == NULL)
        lvcs_bytesize = &lvcs_bytesize_mem;

    decs_cfg_t decs_cfg = {
        .nb_polys = lvcs_cfg->nb_rows,
        .poly_degree = lvcs_cfg->nb_cols+lvcs_cfg->decs_nb_opened_evals-1,
        .nb_evals = lvcs_cfg->decs_nb_evals,
        .nb_opened_evals = lvcs_cfg->decs_nb_opened_evals,
        .eta = lvcs_cfg->decs_eta,
        .pow_bits = lvcs_cfg->decs_pow_bits,
        .use_commitment_tapes = lvcs_cfg->decs_use_commitment_tapes,
        .format_challenge = lvcs_cfg->decs_format_challenge,
        .tree_cfg = lvcs_cfg->decs_tree_cfg,
    };
    
    uint32_t data_bytesize[LVCS_SIZE_MEMORY_MAPPING];
    data_bytesize[0] = sizeof(lvcs_t);
    data_bytesize[1] = decs_alloc_bytesize(&decs_cfg);
    data_bytesize[2] = (lvcs_cfg->nb_cols+lvcs_cfg->decs_nb_opened_evals)*sizeof(felt_t);

    *lvcs_bytesize = get_bytesize_from_array(data_bytesize, LVCS_SIZE_MEMORY_MAPPING);

    if(!dry_run) {
        if(allocate)
            *lvcs = malloc(*lvcs_bytesize);
        if(*lvcs == NULL)
            goto err;

        uint8_t* data_mapping[LVCS_SIZE_MEMORY_MAPPING];
        build_memory_mapping(data_mapping, *lvcs, data_bytesize, LVCS_SIZE_MEMORY_MAPPING);

        (*lvcs)->decs = (decs_t*) data_mapping[1];
        (*lvcs)->interpolation_points = (vec_t) data_mapping[2];

        // Parameters
        (*lvcs)->nb_rows = lvcs_cfg->nb_rows;
        (*lvcs)->nb_cols = lvcs_cfg->nb_cols;
        (*lvcs)->nb_opened_combi = lvcs_cfg->nb_opened_combi;
        (*lvcs)->nb_opened_evals = lvcs_cfg->decs_nb_opened_evals;

        ret = decs_init((*lvcs)->decs, &decs_cfg);
        if(ret != 0) {
            goto err;
        }

        for(uint32_t i=0; i<(*lvcs)->nb_cols; i++)
            felt_from_uint32(&(*lvcs)->interpolation_points[i], (*lvcs)->nb_opened_evals+i);
        for(uint32_t i=0; i<(*lvcs)->nb_opened_evals; i++)
            felt_from_uint32(&(*lvcs)->interpolation_points[(*lvcs)->nb_cols+i], i);

        #ifdef VERBOSE
        printf("=======  LVCS  =====\n");
        printf("== Nb rows: %d\n", (*lvcs)->nb_rows);
        printf("== Nb cols: %d\n", (*lvcs)->nb_cols);
        printf("== Nb Opened Combi: %d\n", (*lvcs)->nb_opened_combi);
        #endif
    }

    ret = 0;
err:
    if(allocate && ret != 0)
        free(*lvcs);
    return ret;
}

uint32_t lvcs_alloc_bytesize(const lvcs_cfg_t* lvcs_cfg) {
    uint32_t lvcs_bytesize;
    int ret = lvcs_init_internal(lvcs_cfg, NULL, &lvcs_bytesize, 1, 0);
    return (ret == 0) ? lvcs_bytesize : 0;
}

int lvcs_init(lvcs_t* lvcs, const lvcs_cfg_t* lvcs_cfg) {
    return lvcs_init_internal(lvcs_cfg, &lvcs, NULL, 0, 0);
}

lvcs_t* malloc_lvcs(const lvcs_cfg_t* lvcs_cfg) {
    lvcs_t* lvcs;
    int ret = lvcs_init_internal(lvcs_cfg, &lvcs, NULL, 0, 1);
    return (ret == 0) ? lvcs : NULL;
}

/////// ALLOCATION KEY STRUCTURE //////

#define LVCS_KEY_SIZE_MEMORY_MAPPING 3
static int lvcs_key_init_internal(const lvcs_t* lvcs, lvcs_key_t** key, uint32_t* key_bytesize, uint32_t dry_run, uint32_t allocate) {
    int ret = -1;
    if(dry_run != 0 && allocate != 0)
        return ret;
    if(allocate)
        *key = NULL;

    uint32_t key_bytesize_mem;
    if(key_bytesize == NULL)
        key_bytesize = &key_bytesize_mem;

    uint32_t nb_rows = lvcs->nb_rows;
    uint32_t nb_cols = lvcs->nb_cols;
    uint32_t nb_opened_evals = lvcs->nb_opened_evals;
    
    uint32_t data_bytesize[LVCS_KEY_SIZE_MEMORY_MAPPING];
    data_bytesize[0] = sizeof(lvcs_key_t);
    data_bytesize[1] = decs_get_key_bytesize(lvcs->decs);
    data_bytesize[2] = get_array_alloc_bytesize(felt_t, nb_rows, nb_cols+nb_opened_evals);

    *key_bytesize = get_bytesize_from_array(data_bytesize, LVCS_KEY_SIZE_MEMORY_MAPPING);

    if(!dry_run) {
        if(allocate) {
            *key = malloc(*key_bytesize);
        }
        if(*key == NULL)
            goto err;

        uint8_t* data_mapping[LVCS_KEY_SIZE_MEMORY_MAPPING];
        build_memory_mapping(data_mapping, *key, data_bytesize, LVCS_KEY_SIZE_MEMORY_MAPPING);
        (*key)->decs_key = (decs_key_t*) data_mapping[1];
        set_pointer_array((*key)->extended_rows, data_mapping[2], felt_t, nb_rows, nb_cols+nb_opened_evals);
    }

    ret = 0;
err:
    if(allocate && ret != 0)
        free(*key);
    return ret;
}

uint32_t lvcs_key_alloc_bytesize(const lvcs_t* lvcs) {
    uint32_t key_bytesize;
    int ret = lvcs_key_init_internal(lvcs, NULL, &key_bytesize, 1, 0);
    return (ret == 0) ? key_bytesize : 0;
}

int lvcs_key_init(lvcs_key_t* key, const lvcs_t* lvcs) {
    return lvcs_key_init_internal(lvcs, &key, NULL, 0, 0);
}

lvcs_key_t* malloc_lvcs_key(const lvcs_t* lvcs) {
    lvcs_key_t* key;
    int ret = lvcs_key_init_internal(lvcs, &key, NULL, 0, 1);
    return (ret == 0) ? key : NULL;
}
