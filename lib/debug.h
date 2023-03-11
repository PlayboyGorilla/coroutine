#ifndef __LIB_DEBUG_H__
#define __LIB_DEBUG_H__

#ifdef __MAXWAVE_DEBUG__
#define DEBUG_PRINTF(...)	printf(__VA_ARGS__)
#define BUG_ON(cond)	do {									\
		if(cond) {									\
			fprintf(stderr, "%s: line %d, BUG_ON hit\n", __FILE__, __LINE__);	\
		}										\
	} while (0)

#define WARN_ON(cond, msg) do {					\
		if(cond) {					\
			fprintf(stderr, "WARNING: %s\n", msg);	\
		}						\
	} while (0)
#else
#define DEBUG_PRINTF(...)	do{}while(0)
#define BUG_ON(cond)	do{}while(0)
#define WARN_ON(cond, msg)	do{}while(0)
#endif

#define LOG(...)	printf(__VA_ARGS__)

#endif
