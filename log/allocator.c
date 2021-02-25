#include "allocator.h"

atomic_t mem_alloc_counter[MEM_BLOCK_MAX];
atomic_t mem_free_counter[MEM_BLOCK_MAX];
