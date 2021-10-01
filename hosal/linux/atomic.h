#ifndef __HOSAL_ATOMIC_LINUX__
#define __HOSAL_ATOMIC_LINUX__

typedef unsigned int atomic_t;

static inline void sys_atomic_inc(atomic_t *atomic)
{
	__sync_add_and_fetch(atomic, 1);
}

static inline atomic_t sys_atomic_inc_return(atomic_t *atomic)
{
	return __sync_add_and_fetch(atomic, 1);
}

static inline void sys_atomic_dec(atomic_t *atomic)
{
	__sync_sub_and_fetch(atomic, 1);
}

static inline atomic_t sys_atomic_dec_return(atomic_t *atomic)
{
	return __sync_sub_and_fetch(atomic, 1);
}

static inline void sys_atomic_add(atomic_t *atomic, atomic_t val)
{
	__sync_add_and_fetch(atomic, val);
}

static inline atomic_t sys_atomic_add_return(atomic_t *atomic, atomic_t val)
{
	return __sync_add_and_fetch(atomic, val);
}

static inline void sys_atomic_sub(atomic_t *atomic, atomic_t val)
{
	__sync_sub_and_fetch(atomic, val);
}

static inline atomic_t sys_atomic_sub_return(atomic_t *atomic, atomic_t val)
{
	return __sync_sub_and_fetch(atomic, val);
}

static inline void sys_atomic_set(atomic_t *atomic, atomic_t val)
{
	__sync_lock_test_and_set(atomic, val);
}

static inline atomic_t sys_atomic_read(atomic_t *atomic)
{
	return __sync_fetch_and_add(atomic, 0);
}

#endif
