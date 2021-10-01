#include <stdint.h>
#include <winsock.h>

uint16_t sys_htole16(uint16_t val)
{
	return val;
}

uint16_t sys_letoh16(uint16_t val)
{
	return val;
}

uint32_t sys_htole32(uint32_t val)
{
	return val;
}

uint32_t sys_letoh32(uint32_t val)
{
	return val;
}

uint16_t sys_htobe16(uint16_t val)
{
	return htons(val);
}

uint16_t sys_betoh16(uint16_t val)
{
	return ntohs(val);
}

uint32_t sys_htobe32(uint32_t val)
{
	return htonl(val);
}

uint32_t sys_betoh32(uint32_t val)
{
	return ntohl(val);
}
