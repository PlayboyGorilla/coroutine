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

static const char *FIBER_FIFO_PREFIX;
void subsys_fiber_init(const char *fifo_base)
{
	FIBER_FIFO_PREFIX = fifo_base;
}

int sys_fiber_thread_init(struct sys_fiber_loop *fbl)
{
	struct kevent event;
	int ret;

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

	fbl->kq_fd = kqueue();
	if (fbl->kq_fd < 0) {
		goto close_out;
	}

	EV_SET(&event, fbl->fifo_rd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, fbl);
	ret = kevent(fbl->kq_fd, &event, 1, NULL, 0, NULL);
	if (ret < 0) {
		goto close_kq_out;
	}

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
	if (ret != sizeof(event)) {
		return ERR_IO;
	}

	return ERR_OK;
}

int sys_fiber_creator_init(struct sys_fiber_loop *fbl)
{
	fbl->fifo_wr = open(fbl->fifo_name, O_NONBLOCK | O_WRONLY);
	if (fbl->fifo_wr < 0) {
		return ERR_IO;
	}

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
		DEBUG_PRINTF("kevent() returns %d, errno=%d\n", ret, errno);
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

int sys_fiber_adjust_monitor(struct sys_fiber_loop *fbl, struct socket *s, int is_add, int is_read)
{
	struct osx_socket *sock = (struct osx_socket *)s;
	struct kevent event;
	int16_t filter;
	uint16_t flags;
	int ret;

	filter = (is_read ? EVFILT_READ : EVFILT_WRITE);
	flags = (is_add ? (EV_ADD | EV_ENABLE) : EV_DELETE);

	EV_SET(&event, sock->fd, filter, flags, 0, 0, sock);

	ret = kevent(fbl->kq_fd, &event, 1, NULL, 0, NULL);
	if (likely(ret >= 0)) {
		return ERR_OK;
	}
	return ERR_IO;
}
