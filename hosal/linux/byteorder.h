#ifndef __HOSAL_BYTEORDER_H__
#define __HOSAL_BYTEORDER_H__

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#include <endian.h>
#undef _BSD_SOURCE
#else
#include <endian.h>
#endif

#include <stdint.h>

#include "lib/types.h"

static inline uint16_t sys_htole16(uint16_t val)
{
	return htole16(val);
}

static inline uint16_t sys_letoh16(uint16_t val)
{
	return le16toh(val);
}

static inline uint32_t sys_htole32(uint32_t val)
{
	return htole32(val);
}

static inline uint32_t sys_letoh32(uint32_t val)
{
	return le32toh(val);
}

static inline uint16_t sys_htobe16(uint16_t val)
{
	return htobe16(val);
}

static inline uint16_t sys_betoh16(uint16_t val)
{
	return be16toh(val);
}

static inline uint32_t sys_htobe32(uint32_t val)
{
	return htobe32(val);
}

static inline uint32_t sys_betoh32(uint32_t val)
{
	return be32toh(val);
}

static inline uint64_t sys_htobe64(uint64_t val)
{
	return htobe64(val);
}

static inline uint64_t sys_betoh64(uint64_t val)
{
	return be64toh(val);
}

#endif
