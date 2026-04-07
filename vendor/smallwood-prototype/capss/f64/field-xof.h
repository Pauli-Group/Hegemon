#ifndef __FIELD_XOF_H__
#define __FIELD_XOF_H__

#include "field-vec.h"

extern void f64_xof(uint64_t* output, const uint64_t* input, uint32_t input_size, uint32_t output_size);
extern void f64_compress2(uint64_t* output, const uint64_t* input);

static inline void vec_xof(vec_t out, const vec_t in, uint32_t in_size, uint32_t out_size) {
    if(in_size == 8 && out_size == 4) {
        f64_compress2(out, in);
    } else if(in_size < 8 && out_size == 4) {
        uint64_t input[8];
        uint32_t i=0;
        for(; i<in_size; i++)
            input[i] = in[i];
        for(; i<8; i++)
            input[i] = 0;
        f64_compress2(out, input);
    } else {
        f64_xof(out, in, in_size, out_size);
    }
}

#endif /* __FIELD_XOF_H__ */

