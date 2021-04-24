#ifndef __HOSAL_SOCKET_PRIVATE_LINUX__
#define __HOSAL_SOCKET_PRIVATE_LINUX__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "fiber/socket.h"

#include "openssl/ssl.h"

struct linux_socket {
	struct socket		sock;
	int			fd;
	SSL			*ssl;
#define SOCK_T_TCP_NONE			0
#define SOCK_T_TCP_SERVER		1
#define SOCK_T_TCP_CLIENT		2
#define SOCK_T_TCP_ACCEPT		3
#define SOCK_T_UDP			4
#define SOCK_T_ICMP			5
#define SOCK_T_SSL_NONE			6
#define SOCK_T_SSL_SERVER		7
#define SOCK_T_SSL_CLIENT		8
#define SOCK_T_SSL_ACCEPT		9
	unsigned int		type;
#define SOCK_S_TCP_CONNECTED		BIT(0)
#define SOCK_S_SSL_ATTACHED		BIT(1)
#define SOCK_S_SSL_CONNECTED		BIT(2)
#define SOCK_S_SSL_SCHED_SHUTDOWN	BIT(3)
	unsigned int		state;
	uint32_t		epoll_events;
};

#endif
