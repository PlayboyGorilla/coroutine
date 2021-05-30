#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <sys/epoll.h>
#include <assert.h>

#include "openssl/ssl.h"

#include "fiber/fiber.h"
#include "fiber/socket.h"
#include "lib/socketex.h"
#include "lib/errno.h"
#include "lib/compiler.h"

#include "socket.h"
#include "socket_priv.h"

#define LISTEN_Q_MAX 2048

static SSL_CTX *ssl_client_ctx;
static SSL_CTX *ssl_server_ctx;

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

/* common socket operators */
static int common_socket_bind(struct linux_socket *sock, const struct sockaddr_ex *addr)
{
	int ret;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	if (!(addr->flags & ADDREX_F_IP))
		return ERR_INVAL;

	ret = bind(sock->fd, (const struct sockaddr *)&addr->ipaddr, addrlen);
	if (ret != 0)
		return sys_error_map(errno);

	return ERR_OK;
}

static int common_socket_shutdown(struct linux_socket *sock, const struct socket_req *req)
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
	struct linux_socket *sock = (struct linux_socket *)s;
	int ret;

	ret = setsockopt(sock->fd, level, optname, optval, optlen);
	if (ret < 0)
		return sys_error_map(errno);

	return ERR_OK;
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
	struct linux_socket *sock;
	unsigned int aligned_size = ALIGN_UP(sizeof(struct linux_socket), sizeof(uint64_t));

	if (socket_set_nonblock(fd) != ERR_OK) {
		return NULL;
	}

	sock = (struct linux_socket *)malloc(aligned_size + priv_data);
	if (!sock) {
		return NULL;
	}
	memset(sock, 0, sizeof(struct linux_socket));

	sock->fd = fd;
	sock->type = type;
	sock->epoll_events = 0;
	sock->read_info.event_mask = (EPOLLIN | EPOLLRDHUP);
	sock->write_info.event_mask = EPOLLOUT;

	if (priv_data) {
		sock->sock.priv_data = ((uint8_t *)sock) + aligned_size;
		sock->sock.priv_len = priv_data;
	}

	return &sock->sock;
}

static void socket_unwrap_clear_ftask(struct socket *s,
	struct epoll_fiber_info *info)
{
	struct fiber_task *ftask;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(info->ftask); i++) {
		ftask = info->ftask[i];

		if (ftask) {
			assert(ftask->last_yield_sock == s);
			ftask->last_yield_sock = NULL;
		}
	}
}

/* return file descriptor of socket being wrapped by @sock */
static void socket_unwrap(struct socket *s)
{
	struct linux_socket *sock = (struct linux_socket *)s;

	socket_unwrap_clear_ftask(s, &sock->read_info);
	socket_unwrap_clear_ftask(s, &sock->write_info);

	free(s);
}

static struct socket *linux_tcp_open(unsigned int priv_data, void *init_data)
{
	struct socket *s;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		return NULL;

	/*
	 * NOTE: TCP client socket must be added to epoll monitoring
	 * after issuing connect call, otherwise a EPOLLHUP will be
	 * received and cause some confusion
	 */
	s = socket_wrap(fd, SOCK_T_TCP_NONE, priv_data);
	if (!s) {
		close(fd);
		return NULL;
	}

	return s;
}

static int linux_tcp_bind(struct socket *s, const struct sockaddr_ex *addr)
{
	struct linux_socket *sock = (struct linux_socket *)s;

	return common_socket_bind(sock, addr);
}

/* fiber coroutine */
static int linux_tcp_get_connect_result(struct linux_socket *sock,
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

static int linux_tcp_connect(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

	/* sanity check */
	if (!(req->param.conn.addr->flags & ADDREX_F_IP)) {
		return ERR_INVAL;
	}

	sock->type = SOCK_T_TCP_CLIENT;

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
	FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
	/* check connect result */
	ret = linux_tcp_get_connect_result(sock, req, ret);
	FIBER_SOCKET_END(ftask, ret);
}

static int linux_tcp_listen(struct socket *s)
{
	struct linux_socket *sock = (struct linux_socket *)s;
	int ret;

	ret = listen(sock->fd, LISTEN_Q_MAX);
	if (ret != 0)
		return ERR_AGAIN;

	return ERR_OK;
}

static inline int __linux_tcp_accept(struct linux_socket *sock, struct sockaddr_in *addr)
{
	socklen_t len = sizeof(struct sockaddr_in);

	return accept(sock->fd, (struct sockaddr *)addr, &len);
}

/* fiber coroutine */
static int linux_tcp_accept(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

	do {
		ret = __linux_tcp_accept(sock, &req->param.accept.src_addr->ipaddr);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			goto yield_out;
		} else if (ret < 0) {
			return ERR_NOT_HANDLED;
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
			req->param.accept.src_addr->flags = ADDREX_F_IP;
			req->param.accept.s->cls = &sys_tcp_socket;
			ret = ERR_OK;
		}
		return ret;
yield_out:
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
	} while(1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int linux_tcp_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

	do {
		ret = send(sock->fd, req->param.send.buf + req->ret,
			req->param.send.len - req->ret, MSG_NOSIGNAL);
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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int linux_tcp_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int linux_tcp_shutdown(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);
	ret = common_socket_shutdown(sock, req);
	FIBER_SOCKET_END(ftask, ret);
}

static int linux_tcp_close(struct socket *s)
{
	struct linux_socket *sock = (struct linux_socket *)s;

	close(sock->fd);
	socket_unwrap(s);
	return ERR_OK;
}

struct socket_class sys_tcp_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_STREAM,
	.protocol	= SOCK_PROTO_TCP,
	.flags		= SOCKCLS_F_CONNECT | SOCKCLS_F_ACCEPT_NOWAIT
			| SOCKCLS_F_SEND_NOWAIT | SOCKCLS_F_RECV_NOWAIT,
	.name		= "linux_tcp_socket",
	.socket		= linux_tcp_open,
	.close		= linux_tcp_close,
	.bind		= linux_tcp_bind,
	.listen		= linux_tcp_listen,
	.accept		= linux_tcp_accept,
	.connect	= linux_tcp_connect,
	.shutdown	= linux_tcp_shutdown,
	.send		= linux_tcp_send,
	.recv		= linux_tcp_recv,
	.setsockopt	= common_socket_setopt,
};

/* UDP operations */
static struct socket *linux_udp_open(unsigned int priv_data, void *init_data)
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

static int linux_udp_bind(struct socket *s, const struct sockaddr_ex *addr)
{
	struct linux_socket *sock = (struct linux_socket *)s;

	return common_socket_bind(sock, addr);
}

/* fiber coroutine */
static int linux_udp_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int linux_udp_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int linux_udp_shutdown(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);
	ret = common_socket_shutdown(sock, req);
	FIBER_SOCKET_END(ftask, ret);
}

static int linux_udp_close(struct socket *s)
{
	struct linux_socket *sock = (struct linux_socket *)s;

	close(sock->fd);
	socket_unwrap(s);
	return ERR_OK;
}

struct socket_class sys_udp_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_DGRAM,
	.protocol	= SOCK_PROTO_UDP,
	.flags		= SOCKCLS_F_SEND_NOWAIT | SOCKCLS_F_RECV_NOWAIT,
	.name		= "linux_udp_socket",
	.socket		= linux_udp_open,
	.close		= linux_udp_close,
	.bind		= linux_udp_bind,
	.listen		= NULL,
	.accept		= NULL,
	.connect	= NULL,
	.shutdown	= linux_udp_shutdown,
	.send		= linux_udp_send,
	.recv		= linux_udp_recv,
	.setsockopt	= common_socket_setopt,
};

static struct socket *linux_icmp_open(unsigned int priv_data, void *init_data)
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

static int linux_icmp_close(struct socket *s)
{
	struct linux_socket *sock = (struct linux_socket *)s;

	close(sock->fd);
	socket_unwrap(s);
	return ERR_OK;
}

static int linux_icmp_bind(struct socket *s, const struct sockaddr_ex *addr)
{
	struct linux_socket *sock = (struct linux_socket *)s;

	return common_socket_bind(sock, addr);
}

/* fiber coroutine */
static int linux_icmp_shutdown(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);
	ret = common_socket_shutdown(sock, req);
	FIBER_SOCKET_END(ftask, ret);
}

/* fiber coroutine */
static int linux_icmp_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
	} while(1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int linux_icmp_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
	} while(1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

struct socket_class sys_icmp_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_RAW,
	.protocol	= SOCK_PROTO_ICMP,
	.flags		= SOCKCLS_F_SEND_NOWAIT | SOCKCLS_F_RECV_NOWAIT,
	.name		= "linux_icmp_socket",
	.socket		= linux_icmp_open,
	.close		= linux_icmp_close,
	.bind		= linux_icmp_bind,
	.listen		= NULL,
	.accept		= NULL,
	.connect	= NULL,
	.shutdown	= linux_icmp_shutdown,
	.send		= linux_icmp_send,
	.recv		= linux_icmp_recv,
	.setsockopt	= common_socket_setopt,
};

/* SSL */
static struct socket *linux_ssl_open(unsigned int priv_data, void *init_data)
{
	struct socket *s;
	struct linux_socket *sock;
	SSL *ssl;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		return NULL;

	ssl = SSL_new(ssl_client_ctx);
	if (!ssl) {
		close(fd);
		return NULL;
	}

	/*
	 * NOTE: TCP client socket must be added to epoll monitoring
	 * after issuing connect call, otherwise a EPOLLHUP will be
	 * received and cause some confusion
	 */
	s = socket_wrap(fd, SOCK_T_SSL_NONE, priv_data);
	if (!s)
		goto err_closesock_out;
	sock = (struct linux_socket *)s;
	sock->ssl = ssl;

	return s;

err_closesock_out:
	SSL_free(ssl);
	close(fd);
	return NULL;
}

/* fiber coroutine */
static int linux_ssl_shutdown(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

	if (!(sock->state & SOCK_S_SSL_ATTACHED)) {
		FIBER_SUBCO(ftask, linux_tcp_shutdown, arg);
		return ret;
	}

	/* we don't do anything as SSL doesn't do RD shutdown */
	if (req->param.shutdown.how == SOCK_SHUTDOWN_RD) {
		return ERR_OK;
	}

	do {
		ret = SSL_shutdown(sock->ssl);
		if (ret == 0 || ret == 1) {
			return ERR_OK;
		} else {
			unsigned int yield_reason;
			int ssl_error;
			ssl_error = SSL_get_error(sock->ssl, ret);
			if (ssl_error == SSL_ERROR_WANT_WRITE) {
				yield_reason = FIBER_YIELD_R_WAIT4_WRITE;
			} else if (ssl_error == SSL_ERROR_WANT_READ) {
				yield_reason = FIBER_YIELD_R_WAIT4_READ;
			} else {
				return ERR_IO;
			}

			sock->state |= SOCK_S_SSL_SCHED_SHUTDOWN;
			FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, yield_reason, req->timeout);
		}
	} while (1);

	FIBER_SOCKET_END(ftask, ERR_OK);
}

static int linux_ssl_close(struct socket *s)
{
	struct linux_socket *sock = (struct linux_socket *)s;
	SSL *ssl = sock->ssl;

	if (sock->extra_data) {
		socket_unwrap((struct socket *)(sock->extra_data));
	}

	close(sock->fd);
	socket_unwrap(s);
	SSL_free(ssl);
	return ERR_OK;
}

static int linux_ssl_bind(struct socket *s, const struct sockaddr_ex *addr)
{
	struct linux_socket *sock = (struct linux_socket *)s;

	return common_socket_bind(sock, addr);
}

static int linux_ssl_create_facade(struct linux_socket *sock)
{
	struct socket *facade_sock;

	facade_sock = socket_wrap(sock->fd, SOCK_T_SSL_ACCEPT, sizeof(struct socket_req));
	if (!facade_sock) {
		return ERR_NOMEM;
	}
	facade_sock->cls = &sys_tcp_socket;
	sock->extra_data = facade_sock;

	return ERR_OK;
}

static int linux_ssl_listen(struct socket *s)
{
	struct linux_socket *sock = (struct linux_socket *)s;
	int ret;

	if (!ssl_server_ctx) {
		return ERR_NOTPERMIT;
	}

	if (!sock->extra_data) {
		ret = linux_ssl_create_facade(sock);
		if (ret != ERR_OK) {
			return ret;
		}
	}

	ret = listen(sock->fd, LISTEN_Q_MAX);
	if (ret != 0) {
		socket_unwrap((struct socket *)(sock->extra_data));
		sock->extra_data = NULL;
		return ERR_AGAIN;
	}

	return ERR_OK;
}

static inline struct socket *get_ssl_facade_socket(struct linux_socket *ssl_svr)
{
	return (struct socket *)(ssl_svr->extra_data);
}

static inline struct socket_req *get_ssl_facade_req(struct linux_socket *ssl_svr)
{
	return (struct socket_req *)socket_private(get_ssl_facade_socket(ssl_svr));
}

/* fiber coroutine */
static int linux_ssl_accept(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

	socket_init_accept_req(get_ssl_facade_socket(sock), get_ssl_facade_req(sock),
		req->param.accept.src_addr, req->timeout);
	FIBER_SOCKET_ACCEPT(ftask, get_ssl_facade_req(sock));
	if (ret != ERR_OK) {
		return ret;
	}

	/*
	 * from this point, @sock points to the new socket created by linux_tcp_accept()
	 */
	sock = (struct linux_socket *)(get_ssl_facade_req(sock)->param.accept.s);
	sock->ssl = SSL_new(ssl_server_ctx);
	if (!sock->ssl) {
		linux_tcp_close(&sock->sock);
		return ERR_NOMEM;
	}
	SSL_set_fd(sock->ssl, sock->fd);
	sock->sock.cls = &sys_ssl_socket;
	sock->state |= SOCK_S_SSL_ATTACHED;

	/*
	 * store the new socket in socket_req and free temporary request
	 */
	req->param.accept.s = &sock->sock;

	do {
		int ssl_error;
		unsigned int yield_reason;
		struct linux_socket *client;

		client = (struct linux_socket *)(req->param.accept.s);

		ret = SSL_accept(client->ssl);
		if (ret <= 0) {
			ssl_error = SSL_get_error(client->ssl, ret);
			if (ssl_error == SSL_ERROR_WANT_READ) {
				yield_reason = FIBER_YIELD_R_WAIT4_READ;
			} else if (ssl_error == SSL_ERROR_WANT_WRITE) {
				yield_reason = FIBER_YIELD_R_WAIT4_WRITE;
			} else {
				linux_ssl_close(&client->sock);
				req->param.accept.s = NULL;
				return ERR_NOT_HANDLED;
			}
		} else {
			break;
		}

		FIBER_YIELD(ftask, &client->sock, yield_reason, req->timeout);
		if (ret != ERR_OK) {
			linux_ssl_close(req->param.accept.s);
			req->param.accept.s = NULL;
			return ret;
		}
	} while(1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int linux_ssl_connect(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);	

	/* sanity check */
	if (!(req->param.conn.addr->flags & ADDREX_F_IP)) {
		return ERR_INVAL;
	}
	if (sock->type != SOCK_T_SSL_NONE && sock->type != SOCK_T_SSL_CLIENT) {
		return ERR_INVAL;
	}

	sock->type = SOCK_T_SSL_CLIENT;

	if (!(sock->state & SOCK_S_TCP_CONNECTED)) {
		ret = connect(sock->fd, (struct sockaddr *)&req->param.conn.addr->ipaddr,
			sizeof(struct sockaddr_in));
		if (likely(ret < 0 && errno == EINPROGRESS)) {
			FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
			ret = linux_tcp_get_connect_result(sock, req, ret);
			if (ret != ERR_OK) {
				return ret;
			} else {
				sock->state |= SOCK_S_TCP_CONNECTED;
			}
		} else if (ret == 0) {
			sock->state |= SOCK_S_TCP_CONNECTED;
		} else {
			sock->type = SOCK_T_SSL_NONE;
			return sys_error_map(errno);
		}
	}

	assert(sock->state & SOCK_S_TCP_CONNECTED);
	if (!(req->param.conn.flags & SOCK_REQP_F_SSL)) {
		return ERR_OK;
	}

	if (!(sock->state & SOCK_S_SSL_ATTACHED)) {
		SSL_set_fd(sock->ssl, sock->fd);
		sock->state |= SOCK_S_SSL_ATTACHED;
	}

	do {
		ret = SSL_connect(sock->ssl);
		if (unlikely(ret == 1)) {
			sock->state |= SOCK_S_SSL_CONNECTED;
			return ERR_OK;
		} else {
			int ssl_error;
			unsigned int yield_reason;

			ssl_error = SSL_get_error(sock->ssl, ret);
			if (ssl_error == SSL_ERROR_WANT_READ) {
				yield_reason = FIBER_YIELD_R_WAIT4_READ;
			} else if (ssl_error == SSL_ERROR_WANT_WRITE) {
				yield_reason = FIBER_YIELD_R_WAIT4_WRITE;
			} else {
				return ERR_NOT_HANDLED;
			}

			FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, yield_reason, req->timeout);
		}
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int linux_ssl_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

	if (!(sock->state & SOCK_S_SSL_ATTACHED)) {
		FIBER_SUBCO(ftask, linux_tcp_send, arg);
		return ret;
	}

	do {
		ret = SSL_write(sock->ssl, req->param.send.buf + req->ret,
			req->param.send.len - req->ret);
		if (ret <= 0) {
			unsigned int yield_reason;
			int ssl_error;

			ssl_error = SSL_get_error(sock->ssl, ret);
			if (ssl_error == SSL_ERROR_WANT_READ) {
				yield_reason = FIBER_YIELD_R_WAIT4_READ;
			} else if (ssl_error == SSL_ERROR_WANT_WRITE) {
				yield_reason = FIBER_YIELD_R_WAIT4_WRITE;
			} else {
				return ERR_IO;
			}
			FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, yield_reason, req->timeout);
		} else {
			return ret;
		}
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int linux_ssl_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct linux_socket, arg);

	if (!(sock->state & SOCK_S_SSL_ATTACHED)) {
		FIBER_SUBCO(ftask, linux_tcp_recv, arg);
		return ret;
	}

	do {
		ret = SSL_read(sock->ssl, req->param.recv.buf + req->ret,
			req->param.recv.len - req->ret);
		if (ret <= 0) {
			unsigned int yield_reason;
			int ssl_error;

			ssl_error = SSL_get_error(sock->ssl, ret);
			if (ssl_error == SSL_ERROR_WANT_READ) {
				yield_reason = FIBER_YIELD_R_WAIT4_READ;
			} else if (ssl_error == SSL_ERROR_WANT_WRITE) {
				yield_reason = FIBER_YIELD_R_WAIT4_WRITE;
			} else {
				return ERR_IO;
			}
			FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, yield_reason, req->timeout);
		} else {
			return ret;
		}
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

struct socket_class sys_ssl_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_STREAM,
	.protocol	= SOCK_PROTO_SSL,
	.flags		= SOCKCLS_F_CONNECT | SOCKCLS_F_SEND_NOWAIT
			| SOCKCLS_F_RECV_NOWAIT,
	.name		= "linux_ssl_socket",
	.socket		= linux_ssl_open,
	.close		= linux_ssl_close,
	.bind		= linux_ssl_bind,
	.listen		= linux_ssl_listen,
	.accept		= linux_ssl_accept,
	.connect	= linux_ssl_connect,
	.shutdown	= linux_ssl_shutdown,
	.send		= linux_ssl_send,
	.recv		= linux_ssl_recv,
	.setsockopt	= NULL,
};

/* subsystem init/exit */
static SSL_CTX *subsys_new_server_ctx(const char *keyfile, const char *certfile)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	if (!keyfile || !certfile) {
		return NULL;
	}

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		return NULL;
	}

	(void)SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx);
		return NULL;
	}

	return ctx;
}

int subsys_sys_socket_init(const char *keyfile, const char *certfile)
{
	ssl_client_ctx = SSL_CTX_new(TLS_client_method());
	if (!ssl_client_ctx) {
		return ERR_NOMEM;
	}

	ssl_server_ctx = subsys_new_server_ctx(keyfile, certfile);
	if (!ssl_server_ctx) {
		fprintf(stderr, "WARNING: TLS server socket will not be allowed\n");
	}

	register_socket_class(&sys_tcp_socket);
	register_socket_class(&sys_udp_socket);
	register_socket_class(&sys_icmp_socket);
	register_socket_class(&sys_ssl_socket);

	return ERR_OK;
}

void subsys_sys_socket_exit(void)
{
	unregister_socket_class(&sys_ssl_socket);
	unregister_socket_class(&sys_icmp_socket);
	unregister_socket_class(&sys_udp_socket);
	unregister_socket_class(&sys_tcp_socket);

	if (ssl_server_ctx) {
		SSL_CTX_free(ssl_server_ctx);
	}
	SSL_CTX_free(ssl_client_ctx);
}
