#ifndef __HOSAL_SOCKET_PRIVATE_WIN__
#define __HOSAL_SOCKET_PRIVATE_WIN__

#include <winsock2.h>
#include <windows.h>

#include "fiber/socket.h"
#include "hosal/fiber.h"
#include "openssl/ssl.h"

struct fiber_task;
struct fiber_loop;
struct win_socket {
	struct socket			sock;
	SOCKET				fd;
	SSL				*ssl;
	struct fiber_task		*ssl_hs_ftask;
#define SOCK_T_TCP_NONE			0
#define SOCK_T_TCP_SERVER		1
#define SOCK_T_TCP_CLIENT		2
#define SOCK_T_TCP_ACCEPTED_CLIENT	3
#define SOCK_T_UDP			4
#define SOCK_T_ICMP			5
#define SOCK_T_SSL_NONE			6
#define SOCK_T_SSL_SERVER		7
#define SOCK_T_SSL_CLIENT		8
#define SOCK_T_SSL_ACCEPTED_CLIENT	9
#define SOCK_T_TUNIF			10
	unsigned int			type;
#define SOCK_S_TCP_CONNECTED		BIT(0)
#define SOCK_S_SSL_ATTACHING		BIT(1)
#define SOCK_S_SSL_ATTACHED		BIT(2)
#define SOCK_S_SSL_SCHED_SHUTDOWN	BIT(3)
#define SOCK_S_BOUND			BIT(4)
	unsigned int			state;
	struct fiber_loop		*attached_floop;
	DWORD				rx_flags;
	WSABUF				tx_buf;
	WSABUF				rx_buf;
	WSAOVERLAPPED			tx_olap;
	WSAOVERLAPPED			rx_olap;
	SOCKET				accept_sock;
	uint8_t				accept_buf[(sizeof(struct sockaddr_in) + 16) * 2];	/* Used by AcceptEx */
	void				*extra_data;
};

#define to_win_sock(s)		container_of(s, struct win_socket, sock);	

#endif
