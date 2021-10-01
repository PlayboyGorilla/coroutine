#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)

#include "lib/compiler.h"
#include "lib/errno.h"
#include "hosal/timer.h"
#include "hosal/byteorder.h"
#include "hosal/fiber.h"
#include "fiber/socket.h"
#include "fiber/fiber.h"

#include "socket_priv.h"

static const char *FIBER_FIFO_PREFIX;
void subsys_fiber_init(const char *fifo_base)
{
	FIBER_FIFO_PREFIX = fifo_base;
}

int sys_fiber_thread_init(struct sys_fiber_loop *fbl)
{
	int ret;
	struct epoll_event event;

	snprintf(fbl->fifo_name, sizeof(fbl->fifo_name), "%s_%lu_%lu_%lu", FIBER_FIFO_PREFIX,
		sys_get_timestamp_specific(SYS_JIFFY_T_IN_MS), (unsigned long)getpid(),
		(unsigned long)rand());

	ret = mkfifo(fbl->fifo_name, 0666);
	if (ret < 0 && errno != EEXIST) {
		return ERR_IO;
	}

	fbl->fifo_rd = open(fbl->fifo_name, O_NONBLOCK | O_RDONLY);
	if (fbl->fifo_rd < 0) {
		goto unlink_out;
	}

	/* create epoll */
	fbl->epoll_fd = epoll_create(EPOLL_MAX_EVENTS);
	if (fbl->epoll_fd < 0) {
		goto close_out;
	}

	event.events = (EPOLLERR | EPOLLHUP | EPOLLRDHUP | EPOLLIN);
	event.data.ptr = fbl;
	ret = epoll_ctl(fbl->epoll_fd, EPOLL_CTL_ADD, fbl->fifo_rd, &event);
	if (ret < 0) {
		goto close_ep_out;
	}

	return ERR_OK;
close_ep_out:
	close(fbl->epoll_fd);
close_out:
	close(fbl->fifo_rd);
unlink_out:
	unlink(fbl->fifo_name);
	return ERR_IO;
}

void sys_fiber_thread_exit(struct sys_fiber_loop *fbl)
{
	struct epoll_event event;

	event.events = 0;
	event.data.ptr = fbl;
	epoll_ctl(fbl->epoll_fd, EPOLL_CTL_DEL, fbl->fifo_rd, &event);

	close(fbl->fifo_rd);
	unlink(fbl->fifo_name);
}

int sys_fiber_send_cmd(struct sys_fiber_loop *fbl, uint8_t event_type,
	uint64_t pointer_data, uint64_t pointer_data2, void *user_data)
{
	struct sys_fiber_event sfevent;
	uint64_t user_data_be64;
	int ret;

	compile_time_assert(sizeof(uint64_t) >= sizeof(void *));

	sfevent.type = event_type;
	sfevent.pointer = sys_htobe64(pointer_data);
	sfevent.pointer2 = sys_htobe64(pointer_data2);
	user_data_be64 = sys_htobe64((uint64_t)user_data);
	memset(sfevent.user_data, 0, sizeof(sfevent.user_data));
	memcpy(sfevent.user_data, &user_data_be64, sizeof(user_data_be64));

	ret = write(fbl->fifo_wr, &sfevent, sizeof(sfevent));
	if (ret != sizeof(sfevent))
		return ERR_IO;

	return ERR_OK;
}

int sys_fiber_creator_init(struct sys_fiber_loop *fbl)
{
	fbl->fifo_wr = open(fbl->fifo_name, O_WRONLY);
	if (fbl->fifo_wr < 0)
		return ERR_IO;

	return ERR_OK;
}

void sys_fiber_creator_exit(struct sys_fiber_loop *fbl)
{
	close(fbl->fifo_wr);
}

void sys_fiber_wait4_event(struct sys_fiber_loop *fbl, struct fiber_loop *floop,
	unsigned long wait_ms,
	void (*event_cbk)(struct fiber_loop *, struct fiber_event *))
{
	int ret;
	int ret2;
	int i;
	struct epoll_event *event;
	struct sys_fiber_event sfevent;
	struct fiber_event f_event;
	struct linux_socket *sock;

	ret = epoll_wait(fbl->epoll_fd, fbl->poll_events, EPOLL_MAX_EVENTS,
		wait_ms == FIBER_WAIT4_INFINITE ? -1 : (int)wait_ms);
	if (ret == 0) {
		/* timeout */
		f_event.data = 0;
		f_event.type = FIBER_EVENT_T_TIMEOUT;
		event_cbk(floop, &f_event);
		return;
	}

	for (i = 0; i < ret; i++) {
		event = &fbl->poll_events[i];
		if (event->data.ptr == fbl) {
			ret2 = read(fbl->fifo_rd, &sfevent, sizeof(sfevent));
			if (ret2 != sizeof(sfevent)) {
				printf("FIFO read fail with return value %d\n", ret2);
				continue;
			}
			f_event.data = sys_betoh64(sfevent.pointer);
			f_event.data2 = sys_betoh64(sfevent.pointer2);
			f_event.type = sfevent.type;
			memcpy(f_event.user_data, sfevent.user_data, sizeof(f_event.user_data));
			event_cbk(floop, &f_event);
		} else {
			sock = event->data.ptr;
			if (event->events & (EPOLLIN | EPOLLRDHUP)) {
				f_event.type = FIBER_EVENT_T_READ;
				f_event.data = (uint64_t)sock;
				event_cbk(floop, &f_event);

				event->events &= ~(EPOLLIN | EPOLLRDHUP);
			}
			if (event->events & EPOLLOUT) {
				f_event.type = FIBER_EVENT_T_WRITE;
				f_event.data = (uint64_t)sock;
				event_cbk(floop, &f_event);

				event->events &= ~EPOLLOUT;
			}
			if (event->events) {
				f_event.type = FIBER_EVENT_T_ERROR;
				f_event.data = (uint64_t)sock;
				event_cbk(floop, &f_event);
			}
		}
	}
}

#define SYS_FIBER_FTASK_NONE		0
#define SYS_FIBER_FTASK_ADDED		1
#define SYS_FIBER_FTASK_DELETED		2
#define SYS_FIBER_FTASK_MASK		0x00FF
#define SYS_FIBER_FTASK_HAS_BUDDY	BIT(8)
static inline unsigned int sys_fiber_find_ftask(struct fiber_task **array, unsigned int nr,
	struct fiber_task *ftask, uint16_t *has_buddy)
{
	unsigned int i;
	unsigned int ret = nr;

	for (i = 0; i < nr; i++) {
		if (array[i] == ftask) {
			ret = i;
		} else if (array[i]) {
			*has_buddy = SYS_FIBER_FTASK_HAS_BUDDY;
		}
	}
	return ret;
}

static inline uint16_t sys_fiber_add_ftask_epoll(struct fiber_task **array, unsigned int nr,
	struct fiber_task *ftask)
{
	unsigned int i;
	unsigned int idx;
	uint16_t action = SYS_FIBER_FTASK_NONE;
	uint16_t has_buddy = 0;

	idx = sys_fiber_find_ftask(array, nr, ftask, &has_buddy);
	action |= has_buddy;
	if (idx != nr) {
		return action;
	}

	for (i = 0; i < nr; i++) {
		if (array[i] == NULL) {
			array[i] = ftask;
			action |= SYS_FIBER_FTASK_ADDED;
			return action;
		}
	}

	assert(0);
	return action;
}

static inline uint16_t sys_fiber_del_ftask_epoll(struct fiber_task **array, unsigned int nr,
	struct fiber_task *ftask)
{
	unsigned int idx;
	uint16_t action = SYS_FIBER_FTASK_NONE;
	uint16_t has_buddy = 0;

	idx = sys_fiber_find_ftask(array, nr, ftask, &has_buddy);
	action |= has_buddy;
	if (idx == nr) {
		return action;
	}

	array[idx] = NULL;
	action |= SYS_FIBER_FTASK_DELETED;

	return action;
}

static int sys_fiber_monitor(struct fiber_task *ftask,
	struct sys_fiber_loop *fbl, struct linux_socket *sock, int is_set,
	struct epoll_fiber_info *info)
{
	uint32_t sock_old_events = sock->epoll_events;
	uint32_t sock_new_events;
	uint16_t action;
	uint16_t has_buddy;
	uint32_t event_mask = info->event_mask;
	struct epoll_event event;
	int ret;

	if (is_set) {
		action = sys_fiber_add_ftask_epoll(info->ftask, ARRAY_SIZE(info->ftask), ftask);
		has_buddy = !!(action & ~SYS_FIBER_FTASK_MASK);
		action = (action & SYS_FIBER_FTASK_MASK);

		if (has_buddy) {
			assert(info->on);
			return ERR_OK;
		} else if (action == SYS_FIBER_FTASK_NONE) {
			return ERR_OK;
		} else {
			assert(!info->on);
		}
	} else {
		action = sys_fiber_del_ftask_epoll(info->ftask, ARRAY_SIZE(info->ftask), ftask);
		has_buddy = !!(action & ~SYS_FIBER_FTASK_MASK);
		action = (action & SYS_FIBER_FTASK_MASK);

		if (has_buddy) {
			assert(info->on);
			return ERR_OK;
		} else if (action == SYS_FIBER_FTASK_NONE) {
			return ERR_OK;
		} else {
			assert(info->on);
		}
	}

	if (action == SYS_FIBER_FTASK_ADDED) {
		sock_new_events = ((sock_old_events & ~event_mask) | event_mask);
	} else {
		assert(action == SYS_FIBER_FTASK_DELETED);
		sock_new_events = (sock_old_events & ~event_mask);
	}

	assert(sock_new_events != sock_old_events);

	event.events = sock_new_events;
	event.data.ptr = sock;

	if (sock_old_events && !sock_new_events) {
		ret = epoll_ctl(fbl->epoll_fd, EPOLL_CTL_DEL, sock->fd, &event);
	} else if (!sock_old_events && sock_new_events) {
		ret = epoll_ctl(fbl->epoll_fd, EPOLL_CTL_ADD, sock->fd, &event);
	} else {
		ret = epoll_ctl(fbl->epoll_fd, EPOLL_CTL_MOD, sock->fd, &event);
	}

	if (likely(ret == 0)) {
		info->on = !info->on;
		sock->epoll_events = sock_new_events;
		return ERR_OK;
	}

	/*
	 * something is wrong - revert what's been done in the sock epoll table
	 */
	if (action == SYS_FIBER_FTASK_ADDED) {
		sys_fiber_del_ftask_epoll(info->ftask, ARRAY_SIZE(info->ftask), ftask);
	} else if (action == SYS_FIBER_FTASK_DELETED) {
		sys_fiber_add_ftask_epoll(info->ftask, ARRAY_SIZE(info->ftask), ftask);
	}

	return ERR_IO;
}

int sys_fiber_read_monitor(struct fiber_task *ftask,
        struct sys_fiber_loop *fbl, struct socket *s, int is_set)
{
	struct linux_socket *sock = (struct linux_socket *)s;

	return sys_fiber_monitor(ftask, fbl, sock, is_set, &sock->read_info);
}

int sys_fiber_write_monitor(struct fiber_task *ftask,
	struct sys_fiber_loop *fbl, struct socket *s, int is_set)
{
	struct linux_socket *sock = (struct linux_socket *)s;

	return sys_fiber_monitor(ftask, fbl, sock, is_set, &sock->write_info);
}

void sys_fiber_read_ftask(struct socket *s, struct fiber_task *array[SYS_FIBER_FTASK_MAX])
{
	struct linux_socket *sock = (struct linux_socket *)s;

	assert(s->cls->domain == SOCK_DOMAIN_SYS_INET);
	memcpy(array, sock->read_info.ftask, sizeof(sock->read_info.ftask));
}

void sys_fiber_write_ftask(struct socket *s, struct fiber_task *array[SYS_FIBER_FTASK_MAX])
{
	struct linux_socket *sock = (struct linux_socket *)s;

	assert(s->cls->domain == SOCK_DOMAIN_SYS_INET);
	memcpy(array, sock->write_info.ftask, sizeof(sock->write_info.ftask));
}
