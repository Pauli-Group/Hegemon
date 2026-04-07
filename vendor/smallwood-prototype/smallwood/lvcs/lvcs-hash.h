#ifndef __LVCS_HASH_H__
#define __LVCS_HASH_H__

#include <stdint.h>
#include "lvcs.h"

void hash_challenge_opening_decs(const lvcs_t* lvcs, uint8_t* digest, vec_t* extended_combis, const uint8_t* prtranscript, uint32_t prtranscript_bytesize);

#endif /* __LVCS_HASH_H__ */
