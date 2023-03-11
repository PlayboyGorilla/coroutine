#ifndef __HOSAL_THREAD_LINUX_H__
#define __HOSAL_THREAD_LINUX_H__

#include "lib/compiler.h"

#include <pthread.h>

/*
 * Infrastructures of:
 * thread, lock, event(condition), 
*/

struct sys_lock {
	pthread_mutex_t posix_mutex;
};

typedef void *(*thread_func_type)(void *);
struct sys_thread {
	thread_func_type thread_func;
	void *thread_arg;
	pthread_t thread_id;
};

struct sys_cond {
/* TODO: put sth here */
	pthread_cond_t posix_cond;
	struct sys_lock *lock; /* bound to a sys_lock */
};

typedef pthread_t	sys_thread_t;

/*
* Interface: must remain the same across different
* platforms/hw/os
*/

#define DEFINE_SYS_LOCK(lock)	struct sys_lock	lock = { \
		PTHREAD_MUTEX_INITIALIZER }

extern int sys_lock_init(struct sys_lock *);
/*TODO: below*/
extern int sys_try_locking(struct sys_lock *);

static inline void sys_lock_finit(struct sys_lock *lock)
{
	pthread_mutex_destroy(&lock->posix_mutex);
}

static inline void sys_locking(struct sys_lock *lock)
{
	pthread_mutex_lock(&lock->posix_mutex);
}

static inline void sys_unlocking(struct sys_lock *lock)
{
	pthread_mutex_unlock(&lock->posix_mutex);
}

/*TODO: trylock */

/* Thread */
extern void sys_thread_init(struct sys_thread *, void *func, void *arg);
extern int sys_thread_create(struct sys_thread *);
extern void sys_thread_wait(struct sys_thread *);
static inline void sys_thread_destroy(struct sys_thread *thread)
{
}

static inline void sys_thread_exit() {
	/* called by thread context */
	pthread_exit(NULL);
}

static inline sys_thread_t sys_thread_id() {
	return pthread_self();
}

extern int sys_thread_kill(struct sys_thread *);

/* Event */
extern int sys_cond_init(struct sys_cond *, struct sys_lock *);
extern void sys_cond_finit(struct sys_cond *);
extern void sys_cond_wait(struct sys_cond *);
static inline void sys_cond_signal(struct sys_cond *cond)
{
	pthread_cond_signal(&cond->posix_cond);
}

/* thread-local storage */
extern int sys_set_tls(void *data);
extern void *sys_get_tls(void);

/* subsys init/exit */
extern int subsys_thread_init(void);
extern void subsys_thread_exit(void);

#endif
