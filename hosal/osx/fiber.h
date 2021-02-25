#ifndef __HOSAL_FIBER_LINUX__
#define __HOSAL_FIBER_LINUX__

#include <sys/event.h>

#define KQUEUE_MAX_EVENTS	512
struct sys_fiber_loop {
	int			kq_fd;
	int			fifo_rd;
	int			fifo_wr;
	char			fifo_name[128];
	struct kevent		poll_events[KQUEUE_MAX_EVENTS];
};

#endif
