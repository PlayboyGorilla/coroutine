#ifndef __LIB_DEBUG_H__
#define __LIB_DEBUG_H__

#include <stdint.h>

#ifdef __DEBUG__
extern void dbg_hex_dump(const uint8_t *data, unsigned int len);
#else
static inline void dbg_hex_dump(const uint8_t *data, unsigned int len)
{
}
#endif

#endif
