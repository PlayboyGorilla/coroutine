#include <winsock2.h>
#include <windows.h>

#include "hosal/timer.h"
#include "hosal/fiber.h"
#include "hosal/byteorder.h"
#include "hosal/win/socket_priv.h"
#include "fiber/socket.h"
#include "fiber/fiber.h"
#include "lib/errno.h"
#include "lib/misc.h"

static const char *FIBER_FIFO_PREFIX;
void subsys_fiber_init(const char *fifo_base)
{
	FIBER_FIFO_PREFIX = fifo_base;
}

static int sys_fiber_initiate_read(struct sys_fiber_loop *fbl)
{
	BOOL bret;

	memset(&fbl->read_olap, 0, sizeof(fbl->read_olap));
	bret = ReadFile(fbl->h_npipe_server, fbl->read_buf, sizeof(fbl->read_buf),
		&fbl->read_bytes, &fbl->read_olap);
	if (bret == FALSE && GetLastError() != ERROR_IO_PENDING) {
		return ERR_UNKNOWN;
	}
	return ERR_OK;
}

int sys_fiber_thread_init(struct sys_fiber_loop *fbl)
{
	BOOL bret;
	HANDLE h_iocp;
	DWORD pipe_mode;
	int ret;

	snprintf(fbl->pipe_name, ARRAY_SIZE(fbl->pipe_name) - 1, "\\\\.\\pipe\\%s_%lu_%lu_%u",
		FIBER_FIFO_PREFIX,
		sys_get_timestamp_specific(SYS_JIFFY_T_IN_MS), GetCurrentThreadId(),
		(unsigned int)rand());

	/* named pipe */
	fbl->h_npipe_server = CreateNamedPipeA(fbl->pipe_name,
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		64 * 1024,
		64 * 1024,
		~0,
		NULL);
	if (fbl->h_npipe_server == INVALID_HANDLE_VALUE) {
		return ERR_UNKNOWN;
	}

	/* client-side */
	fbl->h_npipe_client = CreateFileA(fbl->pipe_name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
	if (fbl->h_npipe_client == INVALID_HANDLE_VALUE) {
		CloseHandle(fbl->h_npipe_server);
		return ERR_UNKNOWN;
	}

	pipe_mode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
	bret = SetNamedPipeHandleState(fbl->h_npipe_client, &pipe_mode, NULL, NULL);
	if (bret == FALSE) {
		CloseHandle(fbl->h_npipe_client);
		CloseHandle(fbl->h_npipe_server);
		return ERR_UNKNOWN;
	}

	/* server-side */
	memset(&fbl->connect_olap, 0, sizeof(fbl->connect_olap));
	bret = ConnectNamedPipe(fbl->h_npipe_server, &fbl->connect_olap);
	if (bret == FALSE && GetLastError() != ERROR_PIPE_CONNECTED) {
		CloseHandle(fbl->h_npipe_client);
		CloseHandle(fbl->h_npipe_server);
		return ERR_UNKNOWN;
	}

	/* IOCP creation */
	fbl->h_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
	if (fbl->h_iocp == NULL) {
		CloseHandle(fbl->h_npipe_client);
		CloseHandle(fbl->h_npipe_server);
		return ERR_UNKNOWN;
	}
	/* attach pipe server-side reading handle to IOCP */
	h_iocp = CreateIoCompletionPort(fbl->h_npipe_server, fbl->h_iocp, (ULONG_PTR)fbl, 0);
	if (h_iocp == NULL) {
		goto err_out;
	}

	/* initiate a read on the server side */
	ret = sys_fiber_initiate_read(fbl);
	if (ret != ERR_OK) {
		goto err_out;
	}

	return ERR_OK;
err_out:
	CloseHandle(fbl->h_npipe_client);
	CloseHandle(fbl->h_npipe_server);
	CloseHandle(fbl->h_iocp);
	return ERR_UNKNOWN;
}

void sys_fiber_thread_exit(struct sys_fiber_loop *fbl)
{
	CloseHandle(fbl->h_npipe_client);
	CloseHandle(fbl->h_npipe_server);
	CloseHandle(fbl->h_iocp);
}

int sys_fiber_send_cmd(struct sys_fiber_loop *fbl, uint8_t event_type,
	uint64_t pointer_data, uint64_t pointer_data2, void *user_data)
{
	struct sys_fiber_event sfevent;
	uint64_t user_data_be64;
	BOOL bret;
	DWORD written_bytes;

	compile_time_assert(sizeof(uint64_t) >= sizeof(void *));

	sfevent.type = event_type;
	sfevent.pointer = sys_htobe64(pointer_data);
	sfevent.pointer2 = sys_htobe64(pointer_data2);
	user_data_be64 = sys_htobe64((uint64_t)user_data);
	memset(sfevent.user_data, 0, sizeof(sfevent.user_data));
	memcpy(sfevent.user_data, &user_data_be64, sizeof(user_data_be64));

	bret = WriteFile(fbl->h_npipe_client, &sfevent, sizeof(sfevent), &written_bytes, NULL);
	if (bret == FALSE) {
		return ERR_IO;
	}

	return ERR_OK;
}

int sys_fiber_creator_init(struct sys_fiber_loop *fbl)
{
	return ERR_OK;
}

void sys_fiber_creator_exit(struct sys_fiber_loop *fbl)
{
}

void sys_fiber_wait4_event(struct sys_fiber_loop *fbl, struct fiber_loop *floop,
	unsigned long wait_ms,
	void (*event_cbk)(struct fiber_loop *, struct fiber_event *))
{
	DWORD dw_num_bytes;
	ULONG_PTR comp_key;
	OVERLAPPED *p_olap;
	BOOL bret;
	DWORD dw_error;
	struct sys_fiber_event sfevent;
	struct fiber_event f_event;
	struct win_socket *sock;
	int ret;

	/*
	 * P324, Windows via C/C++
	 */
	bret = GetQueuedCompletionStatus(fbl->h_iocp,
		&dw_num_bytes, &comp_key, &p_olap, wait_ms);
	dw_error = GetLastError();

	if (bret) {
		/* Process a successfully completed I/O request */
		if (comp_key == (ULONG_PTR)fbl) {
			if (dw_num_bytes != sizeof(struct sys_fiber_event)) {
				printf("FIFO read wrong bytes %lu\n", dw_num_bytes);
				return;
			}

			memcpy(&sfevent, fbl->read_buf, sizeof(sfevent));
			f_event.data = sys_betoh64(sfevent.pointer);
			f_event.data2 = sys_betoh64(sfevent.pointer2);
			f_event.type = sfevent.type;
			memcpy(f_event.user_data, sfevent.user_data, sizeof(f_event.user_data));
			event_cbk(floop, &f_event);

			ret = sys_fiber_initiate_read(fbl);
			if (ret != ERR_OK) {
				fprintf(stderr, "WARNING: named pipe down on the server\n");
				return;
			}
		} else {
			sock = (struct win_socket *)comp_key;
			if (p_olap == &sock->rx_olap) {
				f_event.type = FIBER_EVENT_T_READ;
				f_event.data = (uint64_t)sock;
				event_cbk(floop, &f_event);
			} else {
				assert(p_olap == &sock->tx_olap);

				f_event.type = FIBER_EVENT_T_WRITE;
				f_event.data = (uint64_t)sock;
				event_cbk(floop, &f_event);
			}
		}
	} else {
		if (p_olap != NULL) {
			/*
			 * Process a failed completed I/O request
			 * dw_error contains the reason for failure
			 */
			if (comp_key == (ULONG_PTR)fbl) {
				ret = sys_fiber_initiate_read(fbl);
				if (ret != ERR_OK) {
					fprintf(stderr, "WARNING: named pipe down on the server\n");
					return;
				}
			} else {
				sock = (struct win_socket *)comp_key;
				f_event.type = FIBER_EVENT_T_ERROR;
				f_event.data = (uint64_t)sock;
				event_cbk(floop, &f_event);
			}
		} else {
			if (dw_error == WAIT_TIMEOUT) {
				/*
				 * Time-out while waiting for completed I/O entry
				 */
				f_event.data = 0;
				f_event.type = FIBER_EVENT_T_TIMEOUT;
				event_cbk(floop, &f_event);
			} else {
				/*
				 * FIXME: Bad call to GetQueuedCompletionStatus
				 * dw_error contains the reason for the bad call
				 */
 			}
		}
	}
}

int sys_fiber_adjust_monitor(struct sys_fiber_loop *fbl, struct socket *s, int is_add, int is_read)
{
	/* Nothing to be done on windows */
	return ERR_OK;
}
