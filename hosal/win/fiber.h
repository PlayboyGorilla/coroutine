#ifndef __HOSAL_FIBER_WIN__
#define __HOSAL_FIBER_WIN__

#include <winsock2.h>
#include <windows.h>

#define IOCP_MAX_EVENTS	512
struct sys_fiber_loop {
	HANDLE			h_iocp;
	HANDLE			h_npipe_server;
	HANDLE			h_npipe_client;
	OVERLAPPED		connect_olap;
	OVERLAPPED		read_olap;
	DWORD			read_bytes;
	char			pipe_name[256];
	uint8_t			read_buf[256];
	//OVERLAPPED		iocp_events[IOCP_MAX_EVENTS];
};

#endif
