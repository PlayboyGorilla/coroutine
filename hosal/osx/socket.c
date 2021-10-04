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
	unsigned int aligned_size = ALIGN_UP(sizeof(struct osx_socket), sizeof(uint64_t));

	int value = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(value));

	if (socket_set_nonblock(fd) != ERR_OK) {
		return NULL;
	}

	sock = (struct osx_socket *)malloc(aligned_size + priv_data);
	if (!sock) {
		return NULL;
	}
	memset(sock, 0, sizeof(struct osx_socket));

	sock->fd = fd;
	sock->type = type;
	sock->read_info.filter = EVFILT_READ;
	sock->write_info.filter = EVFILT_WRITE;

	if (priv_data) {
		sock->sock.priv_data = ((uint8_t *)sock) + aligned_size;
		sock->sock.priv_len = priv_data;
	}

	return &sock->sock;
}

static void socket_unwrap_clear_ftask(struct socket *s,
	struct kqueue_event_info *info)
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
	struct osx_socket *sock = (struct osx_socket *)s;

	socket_unwrap_clear_ftask(s, &sock->read_info);
	socket_unwrap_clear_ftask(s, &sock->write_info);

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

static int common_socket_setopt(struct socket *s, int option, int val)
{
	struct osx_socket *sock = (struct osx_socket *)s;
	int level;
	int optname;
	int ret; 

	if (option == SOCK_OPT_REUSE_ADDR) {
		level = SOL_SOCKET;
		optname = SO_REUSEADDR;
	} else if (option == SOCK_OPT_KEEPALIVE) {
		level = SOL_SOCKET;
		optname = SO_KEEPALIVE;
	} else {
		return ERR_NOTSUPPORTED;
	}

	ret = setsockopt(sock->fd, level, optname, &val, sizeof(val));
	if (ret < 0) { 
		return sys_error_map(errno);
	}
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
	FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
	/* check connect result */
	ret = osx_tcp_get_connect_result(sock, req, ret);
	FIBER_SOCKET_END(ftask, ret);

}

static int osx_tcp_listen(struct socket *s)
{
	struct osx_socket *sock = (struct osx_socket *)s;
	int ret;

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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
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
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
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
			FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, yield_reason, req->timeout);
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

	if (sock->extra_data) {
		socket_unwrap((struct socket *)(sock->extra_data));
	}

	close(sock->fd);
	socket_unwrap(s);
	SSL_free(ssl);
	return ERR_OK;
}

static int osx_ssl_create_facade(struct osx_socket *sock)
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

static int osx_ssl_listen(struct socket *s)
{
	struct osx_socket *sock = (struct osx_socket *)s;
	int ret;

	if (!ssl_server_ctx) {
		return ERR_NOTPERMIT;
	}

	if (!sock->extra_data) {
		ret = osx_ssl_create_facade(sock);
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

static inline struct socket *get_ssl_facade_socket(struct osx_socket *ssl_svr)
{
	return (struct socket *)(ssl_svr->extra_data);
}

static inline struct socket_req *get_ssl_facade_req(struct osx_socket *ssl_svr)
{
	return (struct socket_req *)socket_private(get_ssl_facade_socket(ssl_svr));
}

/* fiber coroutine */
static int osx_ssl_accept(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct osx_socket, arg);

	socket_init_accept_req(get_ssl_facade_socket(sock), get_ssl_facade_req(sock),
		req->param.accept.src_addr, req->timeout);
	FIBER_SOCKET_ACCEPT(ftask, get_ssl_facade_req(sock));
	if (ret != ERR_OK) {
		return ret;
	}

	/*
	 * from this point, @sock points to the new socket created by osx_tcp_accept()
	 */
	sock = (struct osx_socket *)(get_ssl_facade_req(sock)->param.accept.s);
	sock->ssl = SSL_new(ssl_server_ctx);
	if (!sock->ssl) {
		osx_tcp_close(&sock->sock);
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
		struct osx_socket *client;

		client = (struct osx_socket *)(req->param.accept.s);

		ret = SSL_accept(client->ssl);
		if (ret <= 0) {
			ssl_error = SSL_get_error(client->ssl, ret);
			if (ssl_error == SSL_ERROR_WANT_READ) {
				yield_reason = FIBER_YIELD_R_WAIT4_READ;
			} else if (ssl_error == SSL_ERROR_WANT_WRITE) {
				yield_reason = FIBER_YIELD_R_WAIT4_WRITE;
			} else {
				osx_ssl_close(&client->sock);
				req->param.accept.s = NULL;
				return ERR_NOT_HANDLED;
			}
		} else {
			break;
		}

		FIBER_YIELD(ftask, &client->sock, yield_reason, req->timeout);
		if (ret != ERR_OK) {
			socket_close(req->param.accept.s);
			req->param.accept.s = NULL;
			return ret;
		}
	} while(1);

	/* Never here */
	FIBER_SOCKET_END(ftask, ERR_OK);
}

static int osx_ssl_verify_cert(struct osx_socket *sock, struct socket_req *req)
{
	X509 *cert;
	EVP_PKEY *evp_pkey;
	EVP_PKEY *evp_pkey_local;

	if (!req->param.conn.svr_cert) {
		return ERR_OK;
	}

	assert(sock->ssl != NULL);
	cert = SSL_get_peer_certificate(sock->ssl);
	if (!cert) {
		return ERR_AUTH_FAIL;
	}

	evp_pkey = X509_get0_pubkey(cert);
	if (!evp_pkey) {
		return ERR_AUTH_FAIL;
	}

	evp_pkey_local = X509_get0_pubkey(req->param.conn.svr_cert);
	if (!evp_pkey_local) {
		return ERR_AUTH_FAIL;
	}

	if (EVP_PKEY_cmp(evp_pkey, evp_pkey_local) == 1) {
		return ERR_OK;
	}

	return ERR_AUTH_FAIL;
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
			FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
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
			return osx_ssl_verify_cert(sock, req);
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
			FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, yield_reason, req->timeout);
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

