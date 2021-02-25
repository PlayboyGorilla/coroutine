#ifndef __LOG_ALLOCATOR_H__
#define __LOG_ALLOCATOR_H__

#include <stdlib.h>
#include <stdint.h>

#include "lib/compiler.h"
#include "hosal/atomic.h"

enum mem_block_index {
	MEM_FIBER_UEVENT = 0,
	MEM_FIBER_FEVENT,
	MEM_BLOCK_MAX,
};

extern atomic_t mem_alloc_counter[MEM_BLOCK_MAX];
extern atomic_t mem_free_counter[MEM_BLOCK_MAX];

static inline void *mem_logged_alloc(unsigned int size, enum mem_block_index idx)
{
	void *p;

	compile_time_assert(sizeof(uint32_t) == sizeof(atomic_t));

	p = malloc(size);
	if (!p)
		return NULL;

	sys_atomic_inc(&mem_alloc_counter[idx]);
	return p;
}

static inline void mem_logged_free(void *p, enum mem_block_index idx)
{
	free(p);
	sys_atomic_inc(&mem_free_counter[idx]);
}

#endif
