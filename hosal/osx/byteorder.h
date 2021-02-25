#ifndef __HOSAL_BYTEORDER_H__
#define __HOSAL_BYTEORDER_H__

#include <libkern/OSByteOrder.h>

#include <lib/types.h>

static inline uint16_t sys_htole16(uint16_t val)
{
	return OSSwapHostToLittleInt16(val);
}

static inline uint16_t sys_letoh16(uint16_t val)
{
	return OSSwapLittleToHostInt16(val);
}

static inline uint32_t sys_htole32(uint32_t val)
{
	return OSSwapHostToLittleInt32(val);
}

static inline uint32_t sys_letoh32(uint32_t val)
{
	return OSSwapLittleToHostInt32(val);
}

static inline uint16_t sys_htobe16(uint16_t val)
{
	return OSSwapHostToBigInt16(val);
}

static inline uint16_t sys_betoh16(uint16_t val)
{
	return OSSwapBigToHostInt16(val);
}

static inline uint32_t sys_htobe32(uint32_t val)
{
	return OSSwapHostToBigInt32(val);
}

static inline uint32_t sys_betoh32(uint32_t val)
{
	return OSSwapBigToHostInt32(val);
}

static inline uint64_t sys_htobe64(uint64_t val)
{
	return OSSwapHostToBigInt64(val);
}

static inline uint64_t sys_betoh64(uint64_t val)
{
	return OSSwapBigToHostInt64(val);
}

#endif
