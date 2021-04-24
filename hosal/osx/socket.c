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

#include "openssl/ssl.h"

#include "fiber/socket.h"
#include "fiber/fiber.h"
#include "hosal/atomic.h"

#include "lib/list.h"
#include "lib/errno.h"
#include "lib/misc.h"
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
	FIBER_SOCKET_YIELD(ftask, FIBER_YIELD_R_WAIT4_WRITE, req, req->s, SOCK_IO_OP_TX);
	/* check connect result */
	ret = osx_tcp_get_connect_result(sock, req, ret);
	FIBER_SOCKET_END(ftask, ret);

}

static int osx_tcp_listen(struct socket *s)
{
	struct osx_socket *sock = (struct osx_socket *)s;
	int ret;

	if (!ssl_server_ctx) {
		return ERR_NOTPERMIT;
	}

	ret = listen(sock->fd, LISTEN_Q_MAX);
	if (ret != 0)
		return ERR_AGAIN;

	return ERR_OK;
}

static inline int __osx_tcp_accept(struct osx_socket *sock, struct sockaddr_in *addr)
{
	socklen_t len = sizeof(struct sockaddr_in);

	return accept(sock->fd, (struct sockaddr *)addr, &len);
}

/* fiber coroutine */
static int osx_tcp_accept(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	do {
		ret = __osx_tcp_accept(sock, &req->param.accept.src_addr->ipaddr);
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
			req->param.accept.src_addr->flags = ADDREX_F_IP;
			req->param.accept.s->cls = &sys_tcp_socket;
			ret = ERR_OK;
		}
		return ret;
yield_out:
		FIBER_SOCKET_YIELD_ERR_RETURN(ftask, FIBER_YIELD_R_WAIT4_READ, req, req->s, SOCK_IO_OP_RX);
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
		FIBER_SOCKET_YIELD_ERR_RETURN(ftask, FIBER_YIELD_R_WAIT4_WRITE, req, req->s, SOCK_IO_OP_TX);
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
		FIBER_SOCKET_YIELD_ERR_RETURN(ftask, FIBER_YIELD_R_WAIT4_READ, req, req->s, SOCK_IO_OP_RX);
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
		FIBER_SOCKET_YIELD_ERR_RETURN(ftask, FIBER_YIELD_R_WAIT4_READ, req, req->s, SOCK_IO_OP_RX);
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
		FIBER_SOCKET_YIELD_ERR_RETURN(ftask, FIBER_YIELD_R_WAIT4_WRITE, req, req->s, SOCK_IO_OP_TX);
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
		FIBER_SOCKET_YIELD_ERR_RETURN(ftask, FIBER_YIELD_R_WAIT4_WRITE, req, req->s, SOCK_IO_OP_TX);
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
		FIBER_SOCKET_YIELD_ERR_RETURN(ftask, FIBER_YIELD_R_WAIT4_READ, req, req->s, SOCK_IO_OP_RX);
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

/* SSL */
static struct socket *osx_ssl_open(unsigned int priv_data, void *init_data)
{
	struct socket *s;
	struct osx_socket *sock;
	SSL *ssl;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		return NULL;

	ssl = SSL_new(ssl_client_ctx);
	if (!ssl) {
		close(fd);
		return NULL;
	}

	s = socket_wrap(fd, SOCK_T_SSL_NONE, priv_data);
	if (!s)
		goto err_closesock_out;
	sock = (struct osx_socket *)s;
	sock->ssl = ssl;

	return s;

err_closesock_out:
	SSL_free(ssl);
	close(fd);
	return NULL;
}

/* fiber coroutine */
static int osx_ssl_shutdown(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	if (!(sock->state & SOCK_S_SSL_ATTACHED)) {
		FIBER_SUBCO(ftask, osx_tcp_shutdown, arg);
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
			FIBER_SOCKET_YIELD_ERR_RETURN(ftask, yield_reason, req, req->s, SOCK_IO_OP_SHUTDOWN);
		}
	} while (1);

	FIBER_SOCKET_END(ftask, ERR_OK);
}

static int osx_ssl_bind(struct socket *s, const struct sockaddr_ex *addr)
{
	struct osx_socket *sock = (struct osx_socket *)s;

	return common_socket_bind(sock, addr);
}

static int osx_ssl_close(struct socket *s)
{
	struct osx_socket *sock = (struct osx_socket *)s;
	SSL *ssl = sock->ssl;

	close(sock->fd);
	socket_unwrap(s);
	SSL_free(ssl);
	return ERR_OK;
}

static int osx_ssl_listen(struct socket *s)
{
	struct osx_socket *sock = (struct osx_socket *)s;
	int ret;

	ret = listen(sock->fd, LISTEN_Q_MAX);
	if (ret != 0)
		return ERR_AGAIN;

	return ERR_OK;
}

/* temporary SSL server socket */
static struct socket *osx_ssl_temp_open(unsigned int priv_data, void *init_data)
{
	int fd;

	fd = *((int *)init_data);
	return socket_wrap(fd, SOCK_T_SSL_SERVER, priv_data);
}

static int osx_ssl_temp_close(struct socket *s)
{
	socket_unwrap(s);
	return ERR_OK;
}

static struct socket_class ssl_temp_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_STREAM,
	.protocol	= SOCK_PROTO_SSL,
	.flags		= 0,
	.name		= "osx_ssl_temp_socket",
	.socket		= osx_ssl_temp_open,
	.close		= osx_ssl_temp_close,
	.accept		= osx_tcp_accept,
};

/* fiber coroutine */
static inline struct socket *get_ssl_temp_socket(struct socket_req *orig_req)
{
	return (struct socket *)(orig_req->u.extra_pointer);
}

static inline struct socket_req *get_ssl_temp_req(struct socket_req *orig_req)
{
	return (struct socket_req *)socket_private(get_ssl_temp_socket(orig_req));
}

static int osx_ssl_accept(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	assert(req->u.extra_pointer == NULL);
	req->u.extra_pointer = socket_create_from_class(&ssl_temp_socket, sizeof(struct socket_req), &sock->fd);
	if (!req->u.extra_pointer) {
		return ERR_NOMEM;
	}

	socket_init_accept_req(get_ssl_temp_socket(req), get_ssl_temp_req(req),
		req->param.accept.src_addr, FIBER_WAIT4_INFINITE);
	FIBER_SOCKET_ACCEPT(ftask, get_ssl_temp_req(req));

	if (ret != ERR_OK) {
		socket_close(get_ssl_temp_socket(req));
		return ret;
	}

	/*
	 * from this point, @sock points to the new socket created by osx_tcp_accept()
	 */
	sock = (struct osx_socket *)(get_ssl_temp_req(req)->param.accept.s);
	sock->ssl = SSL_new(ssl_server_ctx);
	if (!sock->ssl) {
		osx_tcp_close(&sock->sock);
		socket_close(get_ssl_temp_socket(req));
		return ERR_NOMEM;
	}
	SSL_set_fd(sock->ssl, sock->fd);
	sock->sock.cls = &sys_ssl_socket;
	sock->state |= SOCK_S_SSL_ATTACHED;

	/*
	 * store the new socket in socket_req and free temporary request
	 */
	req->s = &sock->sock;
	req->param.accept.s = &sock->sock;
	socket_close(get_ssl_temp_socket(req));
	req->u.extra_pointer = NULL;

	do {
		int ssl_error;
		unsigned int yield_reason;

		ret = SSL_accept(sock->ssl);
		if (ret <= 0) {
			ssl_error = SSL_get_error(sock->ssl, ret);
			if (ssl_error == SSL_ERROR_WANT_READ) {
				yield_reason = FIBER_YIELD_R_WAIT4_READ;
			} else if (ssl_error == SSL_ERROR_WANT_WRITE) {
				yield_reason = FIBER_YIELD_R_WAIT4_WRITE;
			} else {
				osx_ssl_close(&sock->sock);
				return ERR_NOT_HANDLED;
			}
		} else {
			break;
		}

		FIBER_SOCKET_YIELD(ftask, yield_reason, req, &sock->sock, SOCK_IO_OP_RX);
		if (ret != ERR_OK) {
			osx_ssl_close(&sock->sock);
			return ret;
		}
	} while(1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int osx_ssl_connect(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);	

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
			FIBER_SOCKET_YIELD(ftask, FIBER_YIELD_R_WAIT4_WRITE, req, req->s, SOCK_IO_OP_TX);
			ret = osx_tcp_get_connect_result(sock, req, ret);
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
		if (ret == 1) {
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

			FIBER_SOCKET_YIELD_ERR_RETURN(ftask, yield_reason, req, req->s, SOCK_IO_OP_TX);
		}
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int osx_ssl_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	if (!(sock->state & SOCK_S_SSL_ATTACHED)) {
		FIBER_SUBCO(ftask, osx_tcp_send, arg);
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
			FIBER_SOCKET_YIELD_ERR_RETURN(ftask, yield_reason, req, req->s, SOCK_IO_OP_TX);
		} else {
			return ret;
		}
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int osx_ssl_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	if (!(sock->state & SOCK_S_SSL_ATTACHED)) {
		FIBER_SUBCO(ftask, osx_tcp_recv, arg);
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
			FIBER_SOCKET_YIELD_ERR_RETURN(ftask, yield_reason, req, req->s, SOCK_IO_OP_RX);
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
	.flags		= 0,
	.name		= "osx_ssl_socket",
	.socket		= osx_ssl_open,
	.close		= osx_ssl_close,
	.bind		= osx_ssl_bind,
	.listen		= osx_ssl_listen,
	.accept		= osx_ssl_accept,
	.connect	= osx_ssl_connect,
	.shutdown	= osx_ssl_shutdown,
	.send		= osx_ssl_send,
	.recv		= osx_ssl_recv,
	.setsockopt	= NULL,
};

/* subsystem init/exit */
static SSL_CTX *subsys_new_server_ctx(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		return NULL;
	}

	(void)SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx);
		return NULL;
	}

	return ctx;
}

int subsys_sys_socket_init(void)
{
	ssl_client_ctx = SSL_CTX_new(TLS_client_method());
	if (!ssl_client_ctx) {
		return ERR_NOMEM;
	}

	ssl_server_ctx = subsys_new_server_ctx();
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
