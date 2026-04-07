#ifndef __FIELD_BASE_STRUCT_H__
#define __FIELD_BASE_STRUCT_H__

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

typedef uint64_t felt_t;

#define FIELD_ORDER 0xffffffff00000001
#define FIELD_BYTESIZE 8

extern int randombytes(unsigned char* x, unsigned long long xlen);

static inline double felt_get_log2_field_order(void) {
    return 63.999999;
}

static inline uint32_t felt_get_bytesize(void) { return sizeof(felt_t); }

static inline void felt_random(felt_t* a) {
    randombytes((uint8_t*) a, sizeof(felt_t));
    *a = (*a) % FIELD_ORDER;
}

static inline void felt_set(felt_t* c, const felt_t* a) {
    (*c) = (*a);
}

static inline void felt_from_uint32(felt_t* c, uint32_t a) {
    (*c) = a;
}

static inline uint32_t felt_to_uint32(const felt_t* a) {
    return (*a) & 0xffffffff;
}

static inline void felt_from_bytestring(felt_t* c, const uint8_t* a) {
    memcpy(c, a, sizeof(felt_t));
}

static inline void felt_printf(const felt_t* a) {
    printf("%" PRIx64, (*a));
}

static inline void felt_set_zero(felt_t* c) {
    (*c) = 0;
}

static inline void felt_set_one(felt_t* c) {
    (*c) = 1;
}

static inline void felt_add(felt_t* c, const felt_t* a, const felt_t* b) {
    (*c) = (((unsigned _BitInt(128)) *a) + (*b)) % FIELD_ORDER;
}

static inline void felt_neg(felt_t* c, const felt_t* a) {
    (*c) = (FIELD_ORDER - (*a)) % FIELD_ORDER;
}

static inline void felt_sub(felt_t* c, const felt_t* a, const felt_t* b) {
    (*c) = (((unsigned _BitInt(128)) *a) + FIELD_ORDER - (*b)) % FIELD_ORDER;
}

static inline void felt_mul(felt_t* c, const felt_t* a, const felt_t* b) {
    (*c) = (((unsigned _BitInt(128)) *a) * ((unsigned _BitInt(128)) *b)) % FIELD_ORDER;
}

static inline void felt_mul_add(felt_t* c, const felt_t* a, const felt_t* b) {
    (*c) = ((*c) + ((unsigned _BitInt(128)) *a) * ((unsigned _BitInt(128)) *b)) % FIELD_ORDER;
}

static inline void update_step_gcd(uint64_t* oldr2, uint64_t* r2, uint64_t oldr1, uint64_t r1, uint64_t quotient) {
    *oldr2 = r1;
    *r2 = (((unsigned _BitInt(128))oldr1) + FIELD_ORDER - (((unsigned _BitInt(128)) quotient*r1) % FIELD_ORDER)) % FIELD_ORDER;
}

static inline void felt_inv(felt_t* c, const felt_t* a) {
    uint64_t old_r = *a, r = FIELD_ORDER;
    uint64_t old_s = 1, s = 0;
    while(r != 0) {
        uint64_t quotient = old_r / r;
        update_step_gcd(&old_r, &r, old_r, r, quotient);
        update_step_gcd(&old_s, &s, old_s, s, quotient);
    }
    *c = old_s;
}

static inline void felt_div(felt_t* c, const felt_t* a, const felt_t* b) {
    felt_t inv_b;
    felt_inv(&inv_b, b);
    felt_mul(c, a, &inv_b);
}

static inline int felt_is_equal(const felt_t* a, const felt_t* b) {
    return (*a)==(*b);
}

static inline int felt_is_zero(const felt_t* a) {
    return (*a)==0;
}

static inline void felt_serialize(uint8_t* buffer, const felt_t* a) {
    memcpy(buffer, a, sizeof(felt_t));
}

static inline void felt_deserialize(felt_t* a, const uint8_t* buffer) {
    memcpy(a, buffer, sizeof(felt_t));
}

#endif /* __FIELD_BASE_STRUCT_H__ */

