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
#include <net/if.h> 
#include <assert.h>

#include "fiber/socket.h"
#include "fiber/fiber.h"
#include "tcpip/ip.h"
#include "lib/list.h"
#include "lib/errno.h"
#include "lib/misc.h"
#include "lib/compiler.h"

#include "socket.h"
#include "socket_priv.h"

#define LISTEN_Q_MAX 2048

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
	if (flags < 0) {
		return ERR_NOT_HANDLED;
	}
	if (fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		return ERR_NOT_HANDLED;
	}

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

	if (priv_data) {
		sock->sock.priv_data = ((uint8_t *)sock) + aligned_size;
		sock->sock.priv_len = priv_data;
	}

	return &sock->sock;
}

/* return file descriptor of socket being wrapped by @sock */
static inline void socket_unwrap(struct socket *s)
{
	free(s);
}

/* common socket operators */
static int common_socket_bind(struct osx_socket *sock, const struct sockaddr_ex *addr)
{
	int ret;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	if (!(addr->flags & ADDREX_F_IP)) {
		return ERR_INVAL;
	}
	ret = bind(sock->fd, (const struct sockaddr *)&addr->ipaddr, addrlen);
	if (ret != 0) {
		/* FIXME: mapping OSX error code to return value */
		return ERR_AGAIN;
	}

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
	if (fd < 0) {
		return NULL;
	}

	s = socket_wrap(fd, SOCK_T_TCP_NONE, priv_data);
	if (!s) {
		goto err_closesock_out;
	}

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
	if (ret != 0) {
		return ERR_AGAIN;
	}

	sock->type = SOCK_T_TCP_SERVER;
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
		req->param.accept.s = socket_wrap(ret, SOCK_T_TCP_ACCEPTED_CLIENT,
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
	FIBER_SOCKET_END(ftask, 0);
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
	FIBER_SOCKET_END(ftask, 0);
}

/* fiber coroutine */
static int osx_shutdown_read(struct fiber_task *ftask, void *arg)
{
	struct socket_req *req = arg;
	struct osx_socket *sock = (struct osx_socket *)(req->s);

	shutdown(sock->fd, SHUT_RD);

	return ERR_OK;
}

/* fiber coroutine */
static int osx_shutdown_write(struct fiber_task *ftask, void *arg)
{
	struct socket_req *req = arg;
	struct osx_socket *sock = (struct osx_socket *)(req->s);

	shutdown(sock->fd, SHUT_WR);

	return ERR_OK;
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
	.shutdown_read	= osx_shutdown_read,
	.shutdown_write	= osx_shutdown_write,
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
	if (fd < 0) {
		return NULL;
	}

	s = socket_wrap(fd, SOCK_T_UDP, priv_data);
	if (!s) {
		close(fd);
	}

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
			req->param.recv.src_addr->flags = ADDREX_F_IP;
			return ret;
		}
yield_out:
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
	} while (1);

	/* Never here */
	FIBER_SOCKET_END(ftask, 0);
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
	FIBER_SOCKET_END(ftask, 0);
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
	.shutdown_read	= osx_shutdown_read,
	.shutdown_write	= osx_shutdown_write,
	.send		= osx_udp_send,
	.recv		= osx_udp_recv,
	.setsockopt	= common_socket_setopt,
};

static struct socket *osx_icmp_open(unsigned int priv_data, void *init_data)
{
	struct socket *s;
	int fd;
	int ip_hdrincl = 0;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) {
		return NULL;
	}

	s = socket_wrap(fd, SOCK_T_ICMP, priv_data);
	if (!s) {
		close(fd);
		return NULL;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &ip_hdrincl, sizeof(ip_hdrincl)) < 0) {
		close(fd);
		socket_unwrap(s);
		return NULL;
	}

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
	FIBER_SOCKET_END(ftask, 0);
}

static int osx_icmp_recv_fixup(uint8_t *buf, int len)
{
	struct ip_hdr *iphdr = (struct ip_hdr *)buf;
	unsigned int iph_len;
	unsigned int payload_len;

	/*
	 * All BSD (maybe not FreeBSD) tweaks the total_length field of
	 * header before it delivers a packet to raw socket. It's converted
	 * to host order and IP header length is substracted from it
	 */
	iph_len = (IPH_HL(iphdr) << 2);
	payload_len = IPH_LEN(iphdr);

	if (iph_len + payload_len > (unsigned int)len) {
		return ERR_FORMAT;
	}

	memmove(buf, buf + iph_len, payload_len);
	return payload_len;
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
			req->param.recv.src_addr->flags = ADDREX_F_IP;
			return osx_icmp_recv_fixup(req->param.recv.buf, ret);
		}
yield_out:
		FIBER_YIELD_ERR_RETURN(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
	} while(1);

	/* Never here */
	FIBER_SOCKET_END(ftask, 0);
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
	.shutdown_read	= osx_shutdown_read,
	.shutdown_write	= osx_shutdown_write,
	.send		= osx_icmp_send,
	.recv		= osx_icmp_recv,
	.setsockopt	= common_socket_setopt,
};

int subsys_sys_socket_init(const char *keyfile, const char *certfile)
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

