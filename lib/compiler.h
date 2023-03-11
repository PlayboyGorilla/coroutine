#ifndef __LIB_COMPILER_H__
#define __LIB_COMPILER_H__

#define likely(x)  (x)
#define unlikely(x)  (x)

#define __may_block__

#define compile_time_assert(cond)	\
	do {				\
		switch(0) {		\
			case 0:		\
			case cond:	\
			;		\
		}			\
	} while(0)

#endif
