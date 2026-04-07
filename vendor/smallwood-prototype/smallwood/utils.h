#ifndef __UTILS_H__
#define __UTILS_H__

#undef ERR
#define ERR(r, e) if(r) { goto e; }

#undef ERR_NULL
#define ERR_NULL(p, r, e) if((p) == NULL) { r = -1; goto e; }

#define check_non_null_pointer(fn, name, var, ret)                              \
if(var == NULL) {                                                               \
    fprintf(stderr, fn ": " name " should not be a null pointer.\n"); \
    return ret;                                                                 \
}

#define run_get_alloc_bytesize(prefix, nb, ...) {                   \
    uint32_t data_bytesize[nb];                                     \
    int ret = prefix ##_alloc_bytesize_detailed(data_bytesize, __VA_ARGS__);  \
    if(ret != 0) return 0;                                          \
    uint32_t tot = 0;                                               \
    for(uint32_t num=0; num<nb; num++) {                            \
        tot += data_bytesize[num];                                  \
    }                                                               \
    return tot;                                                     \
}

#define get_memory_mapping(prefix, nb, data, data_mapping, ...) {   \
    if(data == NULL)                                                \
        return -1;                                                  \
    uint8_t* ptr = (uint8_t*) data;                                 \
    uint32_t data_bytesize[nb];                                     \
    prefix ##_alloc_bytesize_detailed(data_bytesize, __VA_ARGS__);  \
    uint32_t tot = 0;                                               \
    for(uint32_t num=0; num<nb; num++) {                            \
        data_mapping[num] = ptr + tot;                              \
        tot += data_bytesize[num];                                  \
    }                                                               \
}

#define run_malloc_function(prefix, struct_t, ...) {                \
    uint32_t bytesize = prefix ##_alloc_bytesize(__VA_ARGS__);      \
    struct_t* data = malloc(bytesize);                              \
    if(data != NULL) {                                              \
        int ret = prefix ##_init(data, __VA_ARGS__);                \
        if(ret != 0) {                                              \
            free(data);                                             \
            return NULL;                                            \
        }                                                           \
    }                                                               \
    return data;                                                    \
}

static inline uint32_t get_bytesize_from_array(uint32_t* data_bytesize, uint32_t array_size) {
    uint32_t tot = 0;
    for(uint32_t num=0; num<array_size; num++)
        tot += data_bytesize[num];
    return tot;
}

static inline uint32_t build_memory_mapping(uint8_t** data_mapping, void* ptr, uint32_t* data_bytesize, uint32_t array_size) {
    uint8_t* ptr_data = (uint8_t*) ptr;
    uint32_t tot = 0;
    for(uint32_t num=0; num<array_size; num++) {
        data_mapping[num] = ptr_data + tot;
        tot += data_bytesize[num];
    }
    return tot;
}

#define get_array_alloc_bytesize(struct_t, array_size, data_size) \
    ((array_size)*sizeof(struct_t*) + (array_size)*(data_size)*sizeof(struct_t))

#define set_pointer_array(array, ptr, struct_t, array_size, data_size) { \
    array = (struct_t**) ptr;                                            \
    struct_t* buffer = (struct_t*) (((uint8_t*) ptr) + (array_size)*sizeof(struct_t*)); \
    for (uint32_t num=0; num<array_size; num++) {                        \
        array[num] = buffer;                                             \
        buffer += data_size;                                             \
    }                                                                    \
}

#define map_pointer_array(array, ptr, struct_t, array_size, data_size) { \
    struct_t* buffer = (struct_t*) ptr;                                  \
    for (uint32_t num=0; num<array_size; num++) {                        \
        array[num] = buffer;                                             \
        buffer += data_size;                                             \
    }                                                                    \
}

#define WRITE_BUFFER_BYTES(buffer, data, data_bytesize) { \
    memcpy(buffer, data, data_bytesize);                  \
    buffer += data_bytesize;                              \
}
#define WRITE_BUFFER_VEC(buffer, vec, vec_size) { \
    vec_serialize(buffer, vec, vec_size);         \
    buffer += vec_get_bytesize(vec_size);         \
}
#define WRITE_BUFFER_POLY(buffer, poly, degree) { \
    poly_serialize(buffer, poly, degree);         \
    buffer += poly_get_bytesize(degree);          \
}
#define READ_BUFFER_BYTES(data, buffer, data_bytesize) { \
    memcpy(data, buffer, data_bytesize);                 \
    buffer += data_bytesize;                             \
}
#define READ_BUFFER_VEC(vec, buffer, vec_size) { \
    vec_deserialize(vec, buffer, vec_size);      \
    buffer += vec_get_bytesize(vec_size);        \
}
#define READ_BUFFER_POLY(poly, buffer, degree) { \
    poly_deserialize(poly, buffer, degree);      \
    buffer += poly_get_bytesize(degree);         \
}
#define SET_BUFFER_BYTES(data, buffer, data_bytesize) { \
    data = buffer;                                      \
    buffer += data_bytesize;                            \
}

#endif /* __UTILS_H__ */
