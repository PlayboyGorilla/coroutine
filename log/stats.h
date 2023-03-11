#ifndef __LOG_STATS_H__
#define __LOG_STATS_H__

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include "hosal/atomic.h"

enum stats_index {
	STATS_VERSION,			/* version */
	STATS_FIBER,			/* object_fiber */
	STATS_FIBER_UEVENT,		/* object_fiber_uevent */
	STATS_SOCKET,			/* object_socket */
	STATS_MAX,
};

extern atomic_t runtime_stats[STATS_MAX];

#define STATS_INC(member)		sys_atomic_inc(&runtime_stats[member])
#define STATS_DEC(member)		sys_atomic_dec(&runtime_stats[member])
#define STATS_ADD(member, val)		sys_atomic_add(&runtime_stats[member], val)
#define STATS_DEL(member, val)		sys_atomic_sub(&runtime_stats[member], val)
#define STATS_SET(member, val)		sys_atomic_set(&runtime_stats[member], val);
#define STATS_GET(member)		runtime_stats[member]

static inline void *mem_logged_alloc(size_t size, enum stats_index idx)
{
        void *p;

        p = malloc(size);
        if (!p) {
                return NULL;
	}
	STATS_INC(idx);
        return p;
}

static inline void mem_logged_free(void *p, enum stats_index idx)
{
        free(p);
	STATS_DEC(idx);
}

#endif
