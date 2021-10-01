#ifndef __HOSAL_BYTEORDER_WIN_H__
#define __HOSAL_BYTEORDER_WIN_H__

#include <stdint.h>

extern uint16_t sys_htole16(uint16_t val);
extern uint16_t sys_letoh16(uint16_t val);
extern uint32_t sys_htole32(uint32_t val);
extern uint32_t sys_letoh32(uint32_t val);
extern uint16_t sys_htobe16(uint16_t val);
extern uint16_t sys_betoh16(uint16_t val);
extern uint32_t sys_htobe32(uint32_t val);
extern uint32_t sys_betoh32(uint32_t val);

#endif
