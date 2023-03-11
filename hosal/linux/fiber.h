#ifndef __HOSAL_FIBER_LINUX__
#define __HOSAL_FIBER_LINUX__

#include <sys/epoll.h>
#ifdef __ANDROID__
#include <jni.h>
#endif

#define EPOLL_MAX_EVENTS	512
struct sys_fiber_loop {
	int			epoll_fd;
	int			fifo_rd;
	int			fifo_wr;
	char			fifo_name[128];
	struct epoll_event	poll_events[EPOLL_MAX_EVENTS];
#ifdef __ANDROID__
	JNIEnv			*jni_env;
#endif
};

#endif
