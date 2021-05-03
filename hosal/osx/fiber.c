#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/event.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "lib/compiler.h"
#include "lib/errno.h"
#include "lib/debug.h"
#include "hosal/timer.h"
#include "hosal/byteorder.h"
#include "hosal/fiber.h"
#include "fiber/socket.h"
#include "fiber/fiber.h"

#include "socket_priv.h"

#define FIBER_FIFO_PREFIX	"/tmp/coroutine_fb_%lu_%lu"
int sys_fiber_thread_init(struct sys_fiber_loop *fbl)
{
	struct kevent event;
	int ret;

	snprintf(fbl->fifo_name, sizeof(fbl->fifo_name), FIBER_FIFO_PREFIX,
		sys_get_timestamp_specific(SYS_JIFFY_T_IN_MS), (unsigned long)getpid());	/* FIXME */
	ret = mkfifo(fbl->fifo_name, 0666);
	if (ret < 0 && errno != EEXIST)
		return ERR_IO;

	fbl->fifo_rd = open(fbl->fifo_name, O_NONBLOCK | O_RDONLY);
	if (fbl->fifo_rd < 0)
		goto unlink_out;

	fbl->kq_fd = kqueue();
	if (fbl->kq_fd < 0)
		goto close_out;

	EV_SET(&event, fbl->fifo_rd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, fbl);
	ret = kevent(fbl->kq_fd, &event, 1, NULL, 0, NULL);
	if (ret < 0)
		goto close_kq_out;

	return ERR_OK;
close_kq_out:
	close(fbl->kq_fd);
close_out:
	close(fbl->fifo_rd);
unlink_out:
	unlink(fbl->fifo_name);
	return ERR_IO;
}

void sys_fiber_thread_exit(struct sys_fiber_loop *fbl)
{
	struct kevent event;

	EV_SET(&event, fbl->fifo_rd, EVFILT_READ, EV_DELETE, 0, 0, fbl);
	kevent(fbl->kq_fd, &event, 1, NULL, 0, NULL);

	close(fbl->fifo_rd);
	unlink(fbl->fifo_name);
}

int sys_fiber_send_cmd(struct sys_fiber_loop *fbl, uint8_t event_type,
	uint64_t pointer_data, uint64_t pointer_data2, void *user_data)
{
	struct sys_fiber_event event;
	uint64_t user_data_be64;
	int ret;

	compile_time_assert(sizeof(uint64_t) >= sizeof(void *));

	event.type = event_type;
	event.pointer = sys_htobe64(pointer_data);
	event.pointer2 = sys_htobe64(pointer_data2);
	user_data_be64 = sys_htobe64((uint64_t)user_data);
	memset(event.user_data, 0, sizeof(event.user_data));
	memcpy(event.user_data, &user_data_be64, sizeof(user_data_be64));

	ret = write(fbl->fifo_wr, &event, sizeof(event));
	if (ret != sizeof(event))
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
	struct kevent *event;
	struct sys_fiber_event sfevent;
	struct fiber_event f_event;
	struct osx_socket *sock;
	struct timespec timeout;

	if (wait_ms != FIBER_WAIT4_INFINITE) {
		timeout.tv_sec = wait_ms / 1000;
		timeout.tv_nsec = (wait_ms % 1000) * 1000000;
	}

	ret = kevent(fbl->kq_fd, NULL, 0, fbl->poll_events, KQUEUE_MAX_EVENTS,
		wait_ms == FIBER_WAIT4_INFINITE ? NULL : &timeout);
	if (ret == 0) {
		/* timeout */
		f_event.data = 0;
		f_event.type = FIBER_EVENT_T_TIMEOUT;
		event_cbk(floop, &f_event);
		return;
	} else if (unlikely(ret < 0)) {
		return;
	}

	for (i = 0; i < ret; i++) {
		event = &fbl->poll_events[i];
		if (event->udata == fbl) {
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
			sock = event->udata;
			f_event.data = (uint64_t)sock;
			if (event->filter == EVFILT_READ) {
				f_event.type = FIBER_EVENT_T_READ;
			} else if (event->filter == EVFILT_WRITE) {
				f_event.type = FIBER_EVENT_T_WRITE;
			} else {
				/*
				 * treat everything other than READ and WRITE
				 * as errors -- REVISIT
				 */
				f_event.type = FIBER_EVENT_T_ERROR;
			}

			event_cbk(floop, &f_event);
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

static inline uint16_t sys_fiber_add_ftask_kqueue(struct fiber_task **array, unsigned int nr,
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

static inline uint16_t sys_fiber_del_ftask_kqueue(struct fiber_task **array, unsigned int nr,
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
	struct sys_fiber_loop *fbl, struct socket *s, int is_set,
	struct kqueue_event_info *info)
{
	struct osx_socket *sock = (struct osx_socket *)s;
	struct kevent event;
	uint16_t action;
	uint16_t has_buddy;
	int ret;

	if (is_set) {
		action = sys_fiber_add_ftask_kqueue(info->ftask, ARRAY_SIZE(info->ftask), ftask);
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
		action = sys_fiber_del_ftask_kqueue(info->ftask, ARRAY_SIZE(info->ftask), ftask);
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
		EV_SET(&event, sock->fd, info->filter, EV_ADD | EV_ENABLE, 0, 0, sock);
	} else {
		assert(action == SYS_FIBER_FTASK_DELETED);
		EV_SET(&event, sock->fd, info->filter, EV_DELETE, 0, 0, sock);
	}

	ret = kevent(fbl->kq_fd, &event, 1, NULL, 0, NULL);
	if (likely(ret >= 0)) {
		info->on = !info->on;
		return ERR_OK;
	}

	if (action == SYS_FIBER_FTASK_ADDED) {
		sys_fiber_del_ftask_kqueue(info->ftask, ARRAY_SIZE(info->ftask), ftask);
	} else {
		sys_fiber_add_ftask_kqueue(info->ftask, ARRAY_SIZE(info->ftask), ftask);
	}

	return ERR_IO;
}

int sys_fiber_read_monitor(struct fiber_task *ftask,
	struct sys_fiber_loop *fbl, struct socket *s, int is_set)
{
	struct osx_socket *sock = (struct osx_socket *)s;

	return sys_fiber_monitor(ftask, fbl, s, is_set, &sock->read_info);
}

int sys_fiber_write_monitor(struct fiber_task *ftask,
	struct sys_fiber_loop *fbl, struct socket *s, int is_set)
{
	struct osx_socket *sock = (struct osx_socket *)s;

	return sys_fiber_monitor(ftask, fbl, s, is_set, &sock->write_info);
}

void sys_fiber_read_ftask(struct socket *s, struct fiber_task *array[SYS_FIBER_FTASK_MAX])
{
	struct osx_socket *sock = (struct osx_socket *)s;

	assert(s->cls->domain == SOCK_DOMAIN_SYS_INET);
	memcpy(array, sock->read_info.ftask, sizeof(sock->read_info.ftask));
}

void sys_fiber_write_ftask(struct socket *s, struct fiber_task *array[SYS_FIBER_FTASK_MAX])
{
	struct osx_socket *sock = (struct osx_socket *)s;

	assert(s->cls->domain == SOCK_DOMAIN_SYS_INET);
	memcpy(array, sock->write_info.ftask, sizeof(sock->write_info.ftask));
}
