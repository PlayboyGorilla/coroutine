#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "socket.h"

#include "fiber/socket.h"
#include "fiber/fiber.h"
#include "hosal/atomic.h"

#include "lib/list.h"
#include "lib/errno.h"
#include "lib/misc.h"
#include "lib/compiler.h"

#include "socket_priv.h"

static int sys_error_map(int err)
{
	/*
	 * FIXME:
	 * 1. it can be called on the critical path, optimize it into table-driven or something
	 * 2. put it somewhere else like lib/errno.c
	 */
	switch (err) {
	case 0:
		return ERR_OK;
	case EBADF:
		return ERR_INVAL;
	case EINTR:
		return ERR_NOT_HANDLED;
	case EIO:
		return ERR_IO;
	case ENOPROTOOPT:
		return ERR_NOTSUPPORTED;
	case ECONNRESET:
		return ERR_RESET;
	case ETIMEDOUT:
		return ERR_TIMEOUT;
	default:
		return ERR_NOT_HANDLED;
	}
}

static int socket_set_nonblock(int sock_fd)
{
	int flags;
	flags = fcntl(sock_fd, F_GETFL, 0);
	if (flags < 0)
		return ERR_NOT_HANDLED;
	if (fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return ERR_NOT_HANDLED;

	return ERR_OK;
}

static struct socket *socket_wrap(int fd, unsigned int type, unsigned int priv_data)
{
	struct osx_socket *sock;

	int value = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(value));

	if (socket_set_nonblock(fd) != ERR_OK)
		return NULL;

	sock = (struct osx_socket *)malloc(sizeof(struct osx_socket) + priv_data);
	if (!sock)
		return NULL;
	memset(sock, 0, sizeof(struct osx_socket));

	sock->fd = fd;
	sock->type = type;
	sock->monitor_read = 0;
	sock->monitor_write = 0;

	if (priv_data) {
		sock->sock.priv_data = ((uint8_t *)sock) + sizeof(struct osx_socket);
		sock->sock.priv_len = priv_data;
	}

	return &sock->sock;
}

/* return file descriptor of socket being wrapped by @sock */
static void socket_unwrap(struct socket *s)
{
	struct osx_socket *sock = (struct osx_socket *)s;

	free(sock);
}

/* common socket operators */
static int common_socket_bind(struct osx_socket *sock, const struct sockaddr_ex *addr)
{
	int ret;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	if (!(addr->flags & ADDREX_F_IP))
		return ERR_INVAL;

	ret = bind(sock->fd, (const struct sockaddr *)&addr->ipaddr, addrlen);
	if (ret != 0) {
		/* FIXME: mapping OSX error code to return value */
		return ERR_AGAIN;
	}

	return ERR_OK;
}

static int common_socket_shutdown(struct osx_socket *sock, const struct socket_req *req)
{
	int how = req->param.shutdown.how;

	if (how == SOCK_SHUTDOWN_RD)
		how = SHUT_RD;
	else if (how == SOCK_SHUTDOWN_WR)
		how = SHUT_WR;
	else
		how = SHUT_RDWR;

	shutdown(sock->fd, how);

	return ERR_OK;
}

static int common_socket_setopt(struct socket *s, int level, int optname, const void *optval, socklen_t optlen)
{
	struct osx_socket *sock = (struct osx_socket *)s;
	int ret;

	ret = setsockopt(sock->fd, level, optname, optval, optlen);
	if (ret < 0)
		return sys_error_map(errno);

	return ERR_OK;
}

static struct socket *osx_tcp_open(unsigned int priv_data, void *init_data)
{
	struct socket *s;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		return NULL;

	s = socket_wrap(fd, SOCK_T_TCP_NONE, priv_data);
	if (!s)
		goto err_closesock_out;

	return s;

err_closesock_out:
	close(fd);
	return NULL;
}

static int osx_tcp_bind(struct socket *s, const struct sockaddr_ex *addr)
{
	struct osx_socket *sock = (struct osx_socket *)s;

	return common_socket_bind(sock, addr);
}

static int osx_tcp_get_connect_result(struct osx_socket *sock,
	struct socket_req *req, int ret)
{
	int result;
	socklen_t retlen;

	if (ret != ERR_OK) {
		return ret;
	}

	retlen = sizeof(result);
	if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &result, &retlen) != 0) {
		ret = ERR_IO;
	} else if (result) {
		ret = sys_error_map(result);
	} else {
		sock->state |= SOCK_S_TCP_CONNECTED;
		ret = ERR_OK;
	}
	return ret;
}
/* fiber coroutine */
static int osx_tcp_connect(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	/* sanity check */
	if (!(req->param.conn.addr->flags & ADDREX_F_IP)) {
		return ERR_INVAL;
	}

	ret = connect(sock->fd, (struct sockaddr *)&req->param.conn.addr->ipaddr,
		sizeof(struct sockaddr_in));
	if (likely(ret < 0 && errno == EINPROGRESS)) {
		goto yield_out;
	} else if (ret < 0) {
		return ERR_NOT_HANDLED;
	} else {
		return ERR_OK;
	}

yield_out:
	FIBER_SOCKET_YIELD(ftask, FIBER_YIELD_R_WAIT4_WRITE, req, req->s);
	/* check connect result */
	ret = osx_tcp_get_connect_result(sock, req, ret);
	FIBER_SOCKET_END(ftask, ret);

}

static int osx_tcp_listen(struct socket *s)
{
	static const int LISTEN_Q_MAX = 2048;
	struct osx_socket *sock = (struct osx_socket *)s;
	int ret;

	ret = listen(sock->fd, LISTEN_Q_MAX);
	if (ret != 0)
		return ERR_AGAIN;

	return ERR_OK;
}

static inline int __osx_tcp_accept(struct osx_socket *sock)
{
	struct sockaddr_in claddr;
	socklen_t len = sizeof(struct sockaddr_in);

	return accept(sock->fd, (struct sockaddr *)&claddr, &len);
}

/* fiber coroutine */
static int osx_tcp_accept(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	do {
		ret = __osx_tcp_accept(sock);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			goto yield_out;
		} else if (ret < 0) {
			return sys_error_map(errno);
		}
		/*
		 * return without waiting
		 * @ret contains a new socket descriptor
		 */
		req->param.accept.s = socket_wrap(ret, SOCK_T_TCP_ACCEPT,
			sock->sock.priv_len);
		if (!req->param.accept.s) {
			close(ret);
			ret = ERR_NOMEM;
		} else {
			ret = ERR_OK;
		}
		return ret;
yield_out:
		FIBER_SOCKET_YIELD(ftask, FIBER_YIELD_R_WAIT4_READ, req, req->s);
	} while(1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int osx_tcp_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	do {
		ret = send(sock->fd, req->param.send.buf + req->ret,
			req->param.send.len - req->ret, 0);
		assert(ret != 0);

		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			goto yield_out;
		} else if (ret < 0) {
			return sys_error_map(errno);
		} else if (ret == 0) {
			return ERR_RESET;
		} else {
			return ret;
		}
	yield_out:
		FIBER_SOCKET_YIELD(ftask, FIBER_YIELD_R_WAIT4_WRITE, req, req->s);
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int osx_tcp_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	do {
		ret = recv(sock->fd, req->param.recv.buf + req->ret,
			req->param.recv.len - req->ret, 0);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			goto yield_out;
		} else if (ret < 0) {
			return sys_error_map(errno);
		} else if (ret == 0) {
			return ERR_RESET;
		} else {
			return ret;
		}
	yield_out:
		FIBER_SOCKET_YIELD(ftask, FIBER_YIELD_R_WAIT4_READ, req, req->s);
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int osx_tcp_shutdown(struct fiber_task *ftask, void *arg)
{
	struct socket_req *req = arg;
	struct osx_socket *sock = (struct osx_socket *)(req->s);

	return common_socket_shutdown(sock, req);
}

static int osx_tcp_close(struct socket *s)
{
	struct osx_socket *sock = (struct osx_socket *)s;

	close(sock->fd);
	socket_unwrap(s);
	return ERR_OK;
}

struct socket_class sys_tcp_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_STREAM,
	.protocol	= SOCK_PROTO_TCP,
	.flags		= SOCKCLS_F_CONNECT,
	.name		= "osx_tcp_socket",
	.socket		= osx_tcp_open,
	.close		= osx_tcp_close,
	.bind		= osx_tcp_bind,
	.listen		= osx_tcp_listen,
	.accept		= osx_tcp_accept,
	.connect	= osx_tcp_connect,
	.shutdown	= osx_tcp_shutdown,
	.send		= osx_tcp_send,
	.recv		= osx_tcp_recv,
	.setsockopt	= common_socket_setopt,
};

/* UDP operations */
static struct socket *osx_udp_open(unsigned int priv_data, void *init_data)
{
	struct socket *s;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return NULL;

	s = socket_wrap(fd, SOCK_T_UDP, priv_data);
	if (!s)
		close(fd);

	return s;
}

static int osx_udp_bind(struct socket *s, const struct sockaddr_ex *addr)
{
	struct osx_socket *sock = (struct osx_socket *)s;

	return common_socket_bind(sock, addr);
}

/* fiber coroutine */
static int osx_udp_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	do {
		req->param.recv.src_addr_len = sizeof(req->param.recv.src_addr->ipaddr);
		ret = recvfrom(sock->fd, req->param.recv.buf, req->param.recv.len, 0,
			(struct sockaddr *)&req->param.recv.src_addr->ipaddr,
			&req->param.recv.src_addr_len);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			goto yield_out;
		} else if (ret < 0) {
			return sys_error_map(errno);
		} else if (ret == 0) {
			return ERR_RESET;
		} else {
			/* ret >= 0 */
			return ret;
		}
yield_out:
		FIBER_SOCKET_YIELD(ftask, FIBER_YIELD_R_WAIT4_READ, req, req->s);
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int osx_udp_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	do {
		ret = sendto(sock->fd, req->param.send.buf, req->param.send.len, 0,
			(struct sockaddr *)&req->param.send.dest_addr->ipaddr,
			sizeof(req->param.send.dest_addr->ipaddr));
		assert(ret != 0);

		if ((ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
			goto yield_out;
		} else if (ret < 0) {
			return sys_error_map(errno);
		} else if (ret == 0) {
			return ERR_RESET;
		} else {
			/* ret > 0 */
			return ret;
		}
yield_out:
		FIBER_SOCKET_YIELD(ftask, FIBER_YIELD_R_WAIT4_WRITE, req, req->s);
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int osx_udp_shutdown(struct fiber_task *ftask, void *arg)
{
	struct socket_req *req = arg;
	struct osx_socket *sock = (struct osx_socket *)(req->s);

	return common_socket_shutdown(sock, req);
}

static int osx_udp_close(struct socket *s)
{
	struct osx_socket *sock = (struct osx_socket *)s;

	close(sock->fd);
	socket_unwrap(s);
	return ERR_OK;
}

struct socket_class sys_udp_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_DGRAM,
	.protocol	= SOCK_PROTO_UDP,
	.flags		= 0,
	.name		= "osx_udp_socket",
	.socket		= osx_udp_open,
	.close		= osx_udp_close,
	.bind		= osx_udp_bind,
	.listen		= NULL,
	.accept		= NULL,
	.connect	= NULL,
	.shutdown	= osx_udp_shutdown,
	.send		= osx_udp_send,
	.recv		= osx_udp_recv,
	.setsockopt	= common_socket_setopt,
};

static struct socket *osx_icmp_open(unsigned int priv_data, void *init_data)
{
	struct socket *s;
	int fd;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0)
		return NULL;

	s = socket_wrap(fd, SOCK_T_ICMP, priv_data);
	if (!s)
		close(fd);

	return s;
}

static int osx_icmp_close(struct socket *s)
{
	struct osx_socket *sock = (struct osx_socket *)s;

	close(sock->fd);
	socket_unwrap(s);
	return ERR_OK;
}

/* fiber coroutine */
static int osx_icmp_shutdown(struct fiber_task *ftask, void *arg)
{
	struct socket_req *req = arg;
	struct osx_socket *sock = (struct osx_socket *)(req->s);

	return common_socket_shutdown(sock, req);
}

/* fiber coroutine */
static int osx_icmp_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	do {
		ret = sendto(sock->fd, req->param.send.buf, req->param.send.len, 0,
			(struct sockaddr *)&req->param.send.dest_addr->ipaddr,
			sizeof(req->param.send.dest_addr->ipaddr));
		assert(ret != 0);

		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			goto yield_out;
		} else if (ret < 0) {
			return sys_error_map(ret);
		} else if (ret == 0) {
			return ERR_RESET;
		} else {
			/* ret > 0 */
			return ret;
		}
yield_out:
		FIBER_SOCKET_YIELD(ftask, FIBER_YIELD_R_WAIT4_WRITE, req, req->s);
	} while(1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int osx_icmp_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	do {
		req->param.recv.src_addr_len = sizeof(req->param.recv.src_addr->ipaddr);
		ret = recvfrom(sock->fd, req->param.recv.buf, req->param.recv.len, 0,
			(struct sockaddr *)&req->param.recv.src_addr->ipaddr,
			&req->param.recv.src_addr_len);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			goto yield_out;
		} else if (ret < 0) {
			return sys_error_map(errno);
		} else if (ret == 0) {
			return ERR_RESET;
		} else {
			/* ret > 0 */
			return ret;
		}
yield_out:
		FIBER_SOCKET_YIELD(ftask, FIBER_YIELD_R_WAIT4_READ, req, req->s);
	} while(1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

struct socket_class sys_icmp_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_RAW,
	.protocol	= SOCK_PROTO_ICMP,
	.flags		= 0,
	.name		= "osx_icmp_socket",
	.socket		= osx_icmp_open,
	.close		= osx_icmp_close,
	.bind		= NULL,
	.listen		= NULL,
	.accept		= NULL,
	.connect	= NULL,
	.shutdown	= osx_icmp_shutdown,
	.send		= osx_icmp_send,
	.recv		= osx_icmp_recv,
	.setsockopt	= common_socket_setopt,
};

/* subsystem init/exit */
int subsys_sys_socket_init(void)
{
	register_socket_class(&sys_tcp_socket);
	register_socket_class(&sys_udp_socket);
	register_socket_class(&sys_icmp_socket);

	return ERR_OK;
}

void subsys_sys_socket_exit(void)
{
	unregister_socket_class(&sys_icmp_socket);
	unregister_socket_class(&sys_udp_socket);
	unregister_socket_class(&sys_tcp_socket);
}
