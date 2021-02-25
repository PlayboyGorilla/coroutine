#ifndef __LIB_TYPES_H
#define __LIB_TYPES_H

#if defined WIN32
typedef unsigned __int8   uint8;
typedef unsigned __int16 uint16;
typedef unsigned __int32 uint32;
typedef unsigned __int64 uint64;

typedef __int8   sint8;
typedef __int16 sint16;
typedef __int32 sint32;
typedef __int64 sint64;

typedef uint8 BYTE;
#else
#include <stdint.h>
#endif

typedef uint16_t	be16_t;
typedef uint32_t	be32_t;

#endif
