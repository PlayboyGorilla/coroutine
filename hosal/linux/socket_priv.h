#ifndef __HOSAL_SOCKET_PRIVATE_LINUX__
#define __HOSAL_SOCKET_PRIVATE_LINUX__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "fiber/socket.h"

struct linux_socket {
	struct socket		sock;
	int			fd;
#define SOCK_T_TCP_NONE			0
#define SOCK_T_TCP_SERVER		1
#define SOCK_T_TCP_CLIENT		2
#define SOCK_T_TCP_ACCEPT		3
#define SOCK_T_UDP			4
#define SOCK_T_ICMP			5
	unsigned int		type;
#define SOCK_S_TCP_CONNECTED		BIT(0)
	unsigned int		state;
	uint32_t		epoll_events;
};

#endif
