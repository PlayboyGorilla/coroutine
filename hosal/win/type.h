#ifndef __HOSAL_TYPE_WIN_H__
#define __HOSAL_TYPE_WIN_H__

#include <stdint.h>

#if _WIN64
typedef uint64_t uint_pointer;
#else
typedef uint32_t uint_pointer;
#endif

#endif
