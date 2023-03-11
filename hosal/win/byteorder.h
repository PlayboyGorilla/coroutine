#ifndef __HOSAL_BYTEORDER_WIN_H__
#define __HOSAL_BYTEORDER_WIN_H__

#include <stdint.h>

#include <stdint.h>
#include <winsock2.h>
#include <windows.h>

static inline uint16_t sys_htole16(uint16_t val)
{
	return val;
}

static inline uint16_t sys_letoh16(uint16_t val)
{
	return val;
}

static inline uint32_t sys_htole32(uint32_t val)
{
	return val;
}

static inline uint32_t sys_letoh32(uint32_t val)
{
	return val;
}

static inline uint16_t sys_htobe16(uint16_t val)
{
	return htons(val);
}

static inline uint16_t sys_betoh16(uint16_t val)
{
	return ntohs(val);
}

static inline uint32_t sys_htobe32(uint32_t val)
{
	return htonl(val);
}

static inline uint32_t sys_betoh32(uint32_t val)
{
	return ntohl(val);
}

static inline uint64_t sys_htobe64(uint64_t val)
{
	return (((unsigned __int64)htonl(val & 0xFFFFFFFFUL)) << 32) | htonl((u_long)(val >> 32));
}

static inline uint64_t sys_betoh64(uint64_t val)
{
	return (((unsigned __int64)ntohl(val & 0xFFFFFFFFUL)) << 32) | ntohl((u_long)(val >> 32));
}


#endif
