#ifndef __LIB_DEBUG_H__
#define __LIB_DEBUG_H__

#ifdef __DEBUG__
#define DEBUG_PRINTF(...)	printf(__VA_ARGS__)
#else
#define DEBUG_PRINTF(...)	do{}while(0)
#endif

#define LOG(...)	printf(__VA_ARGS__)

#endif
