#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include "thread.h"

#include "lib/misc.h"
#include "lib/errno.h"

static pthread_key_t pthread_tls;

int sys_lock_init(struct sys_lock *lock)
{
	int ret;

	ret = pthread_mutex_init(&lock->posix_mutex, NULL);
	if (likely(ret == 0))
		return 0;
	return ERR_NOMEM;
}

/* Thread */
void sys_thread_init (struct sys_thread *thread, void *func, void *arg)
{
	thread->thread_func = (thread_func_type)func;
	thread->thread_arg = arg;
}

int sys_thread_create(struct sys_thread *thread)
{
	int ret;
	
	ret = pthread_create(&thread->thread_id, NULL, thread->thread_func, thread->thread_arg);
	if (ret == 0)
		ret = ERR_OK;
	else if (ret == EAGAIN)
		ret = ERR_AGAIN;
	else
		ret = ERR_UNKNOWN;

	return ret;
}

__may_block__ void sys_thread_wait (struct sys_thread *thread)
{
	pthread_join(thread->thread_id, NULL);
}

int sys_thread_detach(struct sys_thread *thread)
{
	int ret;

	ret = pthread_detach(thread->thread_id);
	if (ret == 0)
		ret = ERR_OK;
	else
		ret = ERR_INVAL;

	return ret;
}

int sys_thread_kill(struct sys_thread *thread)
{
	int ret;

	ret = pthread_kill(thread->thread_id, SIGQUIT);
	if (ret == 0)
		ret = ERR_OK;
	else
		ret = ERR_INVAL;

	return ret;
}

/* Event(cond) */
int sys_cond_init (struct sys_cond *cond, struct sys_lock *lock)
{
	int ret;
	ret = pthread_cond_init(&cond->posix_cond, NULL);
	
	if (ret == EAGAIN || ret == ENOMEM)
		return ERR_NOMEM;
	else if (ret != 0)
		return ERR_INVAL;

	cond->lock = lock;
	return 0;
}

void sys_cond_finit (struct sys_cond *cond)
{
	int ret;

	ret = pthread_cond_destroy(&cond->posix_cond); /* FIXME: */
	BUG_ON(ret);

	cond->lock = NULL;
}

void sys_cond_wait (struct sys_cond *cond)
{
	pthread_cond_wait(&cond->posix_cond, &cond->lock->posix_mutex);
}

/* thread-local storage */
int sys_set_tls(void *data)
{
	int ret;

	ret = pthread_setspecific(pthread_tls, data);
	if (ret == 0) {
		return ERR_OK;
	} else if (ret == ENOMEM) {
		return ERR_NOMEM;
	} else {
		return ERR_UNKNOWN;
	}
}

void *sys_get_tls(void)
{
	return pthread_getspecific(pthread_tls);
}

/* subsys init/exit */
int subsys_thread_init(void)
{
	int ret;
	sigset_t set;

	ret = pthread_key_create(&pthread_tls, NULL);
	if (ret == 0) {
		return ERR_OK;
	} else if (ret == EAGAIN) {
		return ERR_AGAIN;
	} else if (ret == ENOMEM) {
		return ERR_NOMEM;
	} else {
		return ERR_UNKNOWN;
	}

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	ret = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (ret != 0) {
		return ERR_UNKNOWN;
	}

	return ERR_OK;
}

void subsys_thread_exit(void)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_UNBLOCK, &set, NULL);

	pthread_key_delete(pthread_tls);
}
