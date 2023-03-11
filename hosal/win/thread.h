#ifndef __HOSAL_THREAD_WIN_H__
#define __HOSAL_THREAD_WIN_H__

#include <winsock2.h>
#include <windows.h>
#include <process.h>

#include "lib/compiler.h"
#include "lib/errno.h"

/*
 * Infrastructures of:
 * thread, lock, event(condition), 
*/
struct sys_lock {
	CRITICAL_SECTION cs;
};

typedef unsigned(*thread_func_type)(void *);
struct sys_thread {
	thread_func_type thread_func;
	HANDLE h_thread;
	void *tls_data;
	void *thread_arg;
};

struct sys_cond {
	HANDLE h_event;
	struct sys_lock *lock; /* bound to a sys_lock */
};

/*
* Interface: must remain the same across different
* platforms/hw/os
*/

static inline int sys_lock_init(struct sys_lock *lock)
{
	InitializeCriticalSection(&lock->cs);
	return ERR_OK;
}

static inline void sys_lock_finit(struct sys_lock *lock)
{
	DeleteCriticalSection(&lock->cs);
}

static inline void sys_locking(struct sys_lock *lock)
{
	EnterCriticalSection(&lock->cs);
}

static inline void sys_unlocking(struct sys_lock *lock)
{
	LeaveCriticalSection(&lock->cs);
}

/* Thread */
static inline void sys_thread_init(struct sys_thread *thread, void *func, void *arg)
{
	thread->thread_func = (thread_func_type)func;
	thread->h_thread = NULL;
	thread->tls_data = NULL;
	thread->thread_arg = arg;
}

static inline int sys_thread_create(struct sys_thread *thread)
{
	unsigned thread_id;
	thread->h_thread = (HANDLE)_beginthreadex(NULL, 0, thread->thread_func, thread->thread_arg, 0, &thread_id);
	if (thread->h_thread == NULL) {
		return ERR_UNKNOWN;
	}
	return ERR_OK;
}

static inline void sys_thread_wait(struct sys_thread *thread)
{
	WaitForSingleObject(thread->h_thread, INFINITE);
}

static inline void sys_thread_destroy(struct sys_thread *thread)
{
	CloseHandle(thread->h_thread);
}

static inline void sys_thread_exit()
{
	/* called in the thread context */
	_endthreadex(0);
}

static inline int sys_thread_kill(struct sys_thread *thread)
{
	TerminateThread(thread->h_thread, 0);
	return ERR_OK;
}

/* Event */
static inline int sys_cond_init(struct sys_cond *cond, struct sys_lock *lock)
{
	cond->h_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (cond->h_event == NULL) {
		return ERR_UNKNOWN;
	}
	cond->lock = lock;
	return ERR_OK;
}

static inline void sys_cond_finit(struct sys_cond *cond)
{
	CloseHandle(cond->h_event);
}

static inline void sys_cond_wait(struct sys_cond *cond)
{
	sys_unlocking(cond->lock);
	WaitForSingleObject(cond->h_event, INFINITE);
	sys_locking(cond->lock);
}

static inline void sys_cond_signal(struct sys_cond *cond)
{
	SetEvent(cond->h_event);
}

/* thread-local storage */
extern int sys_set_tls(void *data);
extern void *sys_get_tls(void);

/* subsys init/exit */
extern int subsys_thread_init(void);
extern void subsys_thread_exit(void);

#endif
