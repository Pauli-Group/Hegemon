#include "merkle-internal.h"
#include "utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static uint32_t nlz(uint32_t x)
{
    uint32_t n;

    if (x == 0) return (32);
    n = 1;
    if((x >> 16) == 0) {n = n + 16; x = x << 16;}
    if((x >> 24) == 0) {n = n + 8;  x = x << 8;}
    if((x >> 28) == 0) {n = n + 4;  x = x << 4;}
    if((x >> 30) == 0) {n = n + 2;  x = x << 2;}
    n = n - (x >> 31);

    return n;
}

static uint32_t ceil_log2(uint32_t x)
{
    if (x == 0) {
        return 0;
    }
    return 32 - nlz(x - 1);
}

/////// ALLOCATION MAIN STRUCTURE //////

static inline int deduce_tree_parameters(const merkle_tree_cfg_t* tree_cfg, uint32_t* height, uint32_t* nb_leaves, uint32_t** arities) {
    if(tree_cfg->nb_leaves == 0 && (tree_cfg->height == 0))
        return -1;
        
    uint32_t height_, nb_leaves_;
    uint32_t* arities_ = NULL;
    if(tree_cfg->height != 0) {
        height_ = tree_cfg->height;
        arities_ = malloc(sizeof(uint32_t)*height_);
        if(arities_ == NULL)
            return -1;
        uint32_t max_nb_leaves;
        if(tree_cfg->arities == NULL) {
            if(height_ >= 32) {
                free(arities_);
                return -1;
            }
            max_nb_leaves = (1<<height_);
            for(uint32_t i=0; i<height_; i++)
            arities_[i] = 2;
        } else {
            max_nb_leaves = 1;
            for(uint32_t i=0; i<height_; i++) {
                if(tree_cfg->arities[i] < 2) {
                    free(arities_);
                    return -1;
                }
                uint64_t prod = ((uint64_t) max_nb_leaves)*tree_cfg->arities[i];
                if(prod > 0x100000000) {
                    free(arities_);
                    return -1;
                }
                max_nb_leaves = (uint32_t) prod;
                arities_[i] = tree_cfg->arities[i];
            }
        }
        if(tree_cfg->nb_leaves > 0) {
            if(tree_cfg->nb_leaves > max_nb_leaves) {
                free(arities_);
                return -1;
            }
            nb_leaves_ = tree_cfg->nb_leaves;
        } else {
            nb_leaves_ = max_nb_leaves;
        }
    } else {
        height_ = (uint8_t) ceil_log2(tree_cfg->nb_leaves);
        arities_ = malloc(sizeof(uint32_t)*height_);
        if(arities_ == NULL)
            return -1;
        for(uint32_t i=0; i<height_; i++)
            arities_[i] = 2;
        nb_leaves_ = tree_cfg->nb_leaves;
    }

    *height = height_;
    *nb_leaves = nb_leaves_;
    *arities = arities_;
    return 0;
}

#define MT_SIZE_MEMORY_MAPPING 3
static int merkle_tree_init_internal(const merkle_tree_cfg_t* tree_cfg, merkle_tree_t** tree, uint32_t* tree_bytesize, uint32_t dry_run, uint32_t allocate) {
    int ret = -1;
    if(dry_run != 0 && allocate != 0)
        return ret;
    if(allocate)
        *tree = NULL;

    uint32_t tree_bytesize_mem;
    if(tree_bytesize == NULL)
        tree_bytesize = &tree_bytesize_mem;

    uint32_t height, nb_leaves, *arities;
    ret = deduce_tree_parameters(tree_cfg, &height, &nb_leaves, &arities);
    if(ret != 0) {
        return ret;
    }
    if(tree_cfg->truncated >= height) {
        return -1;
    }

    uint32_t data_bytesize[MT_SIZE_MEMORY_MAPPING];
    data_bytesize[0] = sizeof(merkle_tree_t);
    data_bytesize[1] = height*sizeof(uint32_t);
    data_bytesize[2] = (height+1)*sizeof(uint32_t);

    *tree_bytesize = get_bytesize_from_array(data_bytesize, MT_SIZE_MEMORY_MAPPING);

    if(!dry_run) {
        if(allocate)
            *tree = malloc(*tree_bytesize);
        if(*tree == NULL)
            goto err;

        uint8_t* data_mapping[MT_SIZE_MEMORY_MAPPING];
        build_memory_mapping(data_mapping, *tree, data_bytesize, MT_SIZE_MEMORY_MAPPING);
    
        uint32_t nb_maxi_leaves = 1;
        uint32_t nb_internal_nodes = 0;
        for(uint32_t i=0; i<height; i++) {
            nb_internal_nodes += nb_maxi_leaves;
            nb_maxi_leaves *= arities[i];
        }
        uint32_t nb_nodes = nb_internal_nodes + nb_leaves;
    
        (*tree)->height = height;
        (*tree)->nb_leaves = nb_leaves;
        (*tree)->nb_nodes = nb_nodes;
        (*tree)->truncated = tree_cfg->truncated;
        
        (*tree)->arities = (uint32_t*) data_mapping[1];
        memcpy((*tree)->arities, arities, sizeof(uint32_t)*height);
    
        (*tree)->depth_width = (uint32_t*) data_mapping[2];
        nb_maxi_leaves = 1;
        for(uint32_t i=0; i<height; i++) {
            (*tree)->depth_width[i] = nb_maxi_leaves;
            nb_maxi_leaves *= (*tree)->arities[i];
        }
        (*tree)->depth_width[height] = nb_leaves;
    }

    ret = 0;
err:
    free(arities);
    if(allocate && ret != 0)
        free(*tree);
    return ret;
}

uint32_t merkle_tree_sizeof(const merkle_tree_cfg_t* tree_cfg) {
    uint32_t tree_bytesize;
    int ret = merkle_tree_init_internal(tree_cfg, NULL, &tree_bytesize, 1, 0);
    return (ret == 0) ? tree_bytesize : 0;
}

int merkle_tree_init(merkle_tree_t* tree, const merkle_tree_cfg_t* tree_cfg) {
    return merkle_tree_init_internal(tree_cfg, &tree, NULL, 0, 0);
}

merkle_tree_t* malloc_merkle_tree(const merkle_tree_cfg_t* tree_cfg) {
    merkle_tree_t* tree;
    int ret = merkle_tree_init_internal(tree_cfg, &tree, NULL, 0, 1);
    return (ret == 0) ? tree : NULL;
}

/////// ALLOCATION KEY STRUCTURE //////

#define MT_KEY_SIZE_MEMORY_MAPPING 3
static int merkle_tree_key_init_internal(const merkle_tree_t* tree, merkle_tree_key_t** key, uint32_t* key_bytesize, uint32_t dry_run, uint32_t allocate) {
    int ret = -1;
    if(dry_run != 0 && allocate != 0)
        return ret;
    if(allocate)
        *key = NULL;

    uint32_t key_bytesize_mem;
    if(key_bytesize == NULL)
        key_bytesize = &key_bytesize_mem;

    uint32_t data_bytesize[MT_KEY_SIZE_MEMORY_MAPPING];
    data_bytesize[0] = sizeof(merkle_tree_key_t);
    data_bytesize[1] = (tree->height+1)*sizeof(uint8_t*);
    data_bytesize[2] = (tree->nb_nodes)*PARAM_DIGEST_SIZE;

    *key_bytesize = get_bytesize_from_array(data_bytesize, MT_KEY_SIZE_MEMORY_MAPPING);

    if(!dry_run) {
        if(allocate) {
            *key = malloc(*key_bytesize);
        }
        if(*key == NULL)
            goto err;

        uint8_t* data_mapping[MT_KEY_SIZE_MEMORY_MAPPING];
        build_memory_mapping(data_mapping, *key, data_bytesize, MT_KEY_SIZE_MEMORY_MAPPING);
    
        (*key)->nodes = (uint8_t**) data_mapping[1];
        uint8_t* slab = (uint8_t*) data_mapping[2];
        (*key)->nodes[0] = slab;
        for(uint32_t i=1; i<=tree->height; i++)
            (*key)->nodes[i] = (*key)->nodes[i-1] + tree->depth_width[i-1]*PARAM_DIGEST_SIZE;    
    }


    ret = 0;
err:
    if(allocate && ret != 0)
        free(*key);
    return ret;
}


uint32_t merkle_tree_sizeof_key(const merkle_tree_t* tree) {
    uint32_t key_bytesize;
    int ret = merkle_tree_key_init_internal(tree, NULL, &key_bytesize, 1, 0);
    return (ret == 0) ? key_bytesize : 0;
}

int merkle_tree_key_init(merkle_tree_key_t* key, const merkle_tree_t* tree) {
    return merkle_tree_key_init_internal(tree, &key, NULL, 0, 0);
}

merkle_tree_key_t* malloc_merkle_tree_key(const merkle_tree_t* tree) {
    merkle_tree_key_t* key;
    int ret = merkle_tree_key_init_internal(tree, &key, NULL, 0, 1);
    return (ret == 0) ? key : NULL;
}
