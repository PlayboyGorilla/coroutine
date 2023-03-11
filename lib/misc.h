#ifndef __LIB_MISC_H
#define __LIB_MISC_H

#include "types.h"
#include "hosal/type.h"

/*utils*/
#define ARRAY_SIZE(x) ( sizeof(x)/sizeof(x[0]) )
//#define ARRAY_IDX(e, a)  (((e) - (a))/(sizeof(a[0])))
#define ARRAY_IDX(e, a) ((e)-(a))
/*x:uint32*/
#define ALIGN_UP(x, align)		(((x) + (align) - 1) / (align) * (align))
#define ALIGN_UP_PADDING(x, align)	(ALIGN_UP(x, align) - (x))
#define ALIGN_DOWN(x, align)		((x) / (align) * (align))
#define ALIGN_DOWN_PADDING(x, align)	((x) - ALIGN_DOWN(x, align))

#define ALIGN_UP_ULONG(x)	ALIGN_UP((x), sizeof(unsigned long))

#define IS_ALIGNED(addr, n)	!(((uint_pointer)(addr)) & ((n) - 1))

#define MAX_SINT_POSITIVE (((unsigned int)(-1)) >> 1)

/* rand */
extern void rand_buf(uint8_t * buf, unsigned int size);

/* number */
#ifndef max
#define max(a, b)	((a) > (b) ? (a) : (b))
#endif

#ifndef min
#define min(a, b)	((a) < (b) ? (a) : (b))
#endif

#define BIT(x)	(1 << (x))

#define container_of(ptr, type, member) \
	 ( (type*)( (char*)(ptr) - (uint_pointer)&(((type*)0)->member) ) )

#define offset_of(type, member)	\
	((uint_pointer)&(((type*)0)->member))

extern void debug_hex(const uint8_t * buf, unsigned int len ,unsigned int perline, const char * headline);

#endif
