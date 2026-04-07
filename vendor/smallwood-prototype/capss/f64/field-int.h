#ifndef __FIELD_INT_H__
#define __FIELD_INT_H__

#include "field-base.h"

static inline void felt_int_left_shift(felt_t* c, const felt_t* a, uint32_t shift) {
    (*c) = (*a) << shift;
}

static inline void felt_int_minus_one(felt_t* c, const felt_t* a) {
    (*c) = ((*a) == 0) ? FIELD_ORDER-1 : (*a) - 1;
}

static inline int felt_int_leq(const felt_t* a, const felt_t* b) {
    return (*a) <= (*b);
}

static inline void felt_int_div_euclid(felt_t* q, uint32_t* r, const felt_t* a, uint32_t d) {
    *q = (*a) / d;
    *r = (*a) - (*q) * d;
}

#endif /* __FIELD_INT_H__ */

