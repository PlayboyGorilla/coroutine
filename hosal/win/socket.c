#include <winsock2.h>
#include <mswsock.h>

#include "fiber/fiber.h"
#include "fiber/socket.h"
#include "lib/socketex.h"
#include "lib/errno.h"
#include "lib/compiler.h"
#include "hosal/win/fiber.h"
#include "hosal/win/socket_priv.h"
#include "tcpip/ip.h"

static LPFN_CONNECTEX __ConnectEx;
static LPFN_ACCEPTEX __AcceptEx;
static LPFN_GETACCEPTEXSOCKADDRS __GetAcceptExSockaddrs;

/* common socket operators */
static int common_socket_bind(struct win_socket *sock, const struct sockaddr_ex *addr)
{
	int ret;
	int addrlen = sizeof(struct sockaddr_in);

	if (!(addr->flags & ADDREX_F_IP)) {
		return ERR_INVAL;
	}
	ret = bind(sock->fd, (const struct sockaddr *)&addr->ipaddr, addrlen);
	if (ret != 0) {
		return ERR_IO;
	}
	sock->state |= SOCK_S_BOUND;
	return ERR_OK;
}

static struct socket *socket_wrap(SOCKET fd, unsigned int type, unsigned int priv_data)
{
	struct win_socket *sock;
	unsigned int aligned_size = ALIGN_UP(sizeof(struct win_socket), sizeof(uint64_t));

	sock = (struct win_socket *)malloc(aligned_size + priv_data);
	if (!sock) {
		return NULL;
	}
	memset(sock, 0, sizeof(struct win_socket));
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

static struct socket *win_tcp_open(unsigned int priv_data, void *init_data)
{
	struct socket *s;
	SOCKET fd;

	fd = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (fd == INVALID_SOCKET) {
                return NULL;
        }
	s = socket_wrap(fd, SOCK_T_TCP_NONE, priv_data);
	if (!s) {
		closesocket(fd);
	}

	return s;
}

static int win_tcp_bind(struct socket *s, const struct sockaddr_ex *addr)
{
	struct win_socket *sock = (struct win_socket *)s;

	return common_socket_bind(sock, addr);
}

static int win_may_attach_iocp(struct fiber_task *ftask, struct win_socket *sock)
{
	struct sys_fiber_loop *sfloop;
	HANDLE h_iocp;

	if (sock->attached_floop) {
		assert(ftask->floop == sock->attached_floop);
		return ERR_OK;
	}

	sfloop = fiber_loop_platform(ftask->floop);
	assert(sfloop != NULL);

	h_iocp = CreateIoCompletionPort((HANDLE)(sock->fd), sfloop->h_iocp, (ULONG_PTR)sock, 0);
	if (h_iocp == NULL) {
		//debugg
		fprintf(stderr, "%s: CreateIoCompletionPort() failed with %lu\n", __func__, GetLastError());
		return ERR_UNKNOWN;
	}
	sock->attached_floop = ftask->floop;
	return ERR_OK;
}

/* fiber coroutine */
static int win_tcp_connect(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct win_socket, arg);

	if (unlikely(!__ConnectEx)) {
		return ERR_NOTSUPPORTED;
	}

	/* common for all fiber coroutine */
	ret = win_may_attach_iocp(ftask, sock);
	if (unlikely(ret != ERR_OK)) {
		return ret;
	}

	/* sanity check */
	if (!(req->param.conn.addr->flags & ADDREX_F_IP)) {
		return ERR_INVAL;
	}

	sock->type = SOCK_T_TCP_CLIENT;

	/*
	 * ConnectEx requires the socket to be bound,
	 * WSAEINVAL is returned otherwise
	 */
	if (!(sock->state & SOCK_S_BOUND)) {
		struct sockaddr_ex local_addr;
		addrex_init(&local_addr);
		addrex_set_ip(&local_addr, INADDR_ANY, 0);
		ret = win_tcp_bind(&sock->sock, &local_addr);
		if (ret != ERR_OK) {
			return ret;
		}
	}

	BOOL bret;
	int wsa_err;
	memset(&sock->tx_olap, 0, sizeof(sock->tx_olap));
	bret = __ConnectEx(sock->fd,
		(struct sockaddr *)&req->param.conn.addr->ipaddr, sizeof(req->param.conn.addr->ipaddr),
		NULL, 0, NULL, (LPOVERLAPPED)(&sock->tx_olap));
	wsa_err = WSAGetLastError();
	if (bret == TRUE) {
		return ERR_OK;
	} else if (wsa_err != ERROR_IO_PENDING) {
		return ERR_NOT_HANDLED;
	}

        FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
	if (ret != ERR_OK) {
		BOOL b_ret;
		b_ret = CancelIoEx((HANDLE)sock->fd, (LPOVERLAPPED)(&sock->tx_olap));
		if (b_ret == TRUE) {
			FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, FIBER_WAIT4_INFINITE);
		}
	}

	DWORD dw_flags = 0;
	DWORD dw_bytes_transferred;
	bret = WSAGetOverlappedResult(sock->fd, &sock->tx_olap, &dw_bytes_transferred, FALSE, &dw_flags);
	if (bret == FALSE) {
		return ERR_IO;
	}

	ret = setsockopt(sock->fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
	if (ret == SOCKET_ERROR) {
		return ERR_UNKNOWN;
	}

        FIBER_SOCKET_END(ftask, ERR_OK);
}

static int win_tcp_listen(struct socket *s)
{
	struct win_socket *sock = (struct win_socket *)s;
	int ret;

	ret = listen(sock->fd, SOMAXCONN);
	if (ret == SOCKET_ERROR) {
		return ERR_AGAIN;
	}

	sock->type = SOCK_T_TCP_SERVER;
	return ERR_OK;
}

struct socket_class sys_tcp_socket;

/* fiber coroutine */
static int win_tcp_accept(struct fiber_task *ftask, void *arg)
{
        FIBER_SOCKET_BEGIN(ftask, struct win_socket, arg);

	if (unlikely(!__AcceptEx)) {
		return ERR_NOTSUPPORTED;
	}

	/* common for all fiber coroutine */
	ret = win_may_attach_iocp(ftask, sock);
	if (unlikely(ret != ERR_OK)) {
		return ret;
	}

	sock->accept_sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == sock->accept_sock) {
		return ERR_UNKNOWN;
	}
	memset(&sock->rx_olap, 0, sizeof(sock->rx_olap));

	BOOL bret;
	DWORD dw_bytes;
	bret = __AcceptEx(sock->fd, sock->accept_sock, sock->accept_buf, 0,
		sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, &dw_bytes, &sock->rx_olap);
	if (bret == FALSE && WSAGetLastError() != ERROR_IO_PENDING) {
		closesocket(sock->accept_sock);
		return ERR_UNKNOWN;
	}

	FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
	if (ret != ERR_OK) {
		BOOL b_ret;
		b_ret = CancelIoEx((HANDLE)sock->fd, (LPOVERLAPPED)(&sock->rx_olap));
		if (b_ret == TRUE) {
			FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, FIBER_WAIT4_INFINITE);
		}
	}

	DWORD dw_flags = 0;
	DWORD dw_bytes_transferred;
	bret = WSAGetOverlappedResult(sock->fd, &sock->rx_olap, &dw_bytes_transferred, FALSE, &dw_flags);
	if (bret == FALSE) {
		closesocket(sock->accept_sock);
		return ERR_IO;
	}

	ret = setsockopt(sock->accept_sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
		(char *)&sock->fd, sizeof(sock->fd));
	if (ret == SOCKET_ERROR) {
		closesocket(sock->accept_sock);
		return ERR_UNKNOWN;
	}

	req->param.accept.s = socket_wrap(sock->accept_sock, SOCK_T_TCP_ACCEPTED_CLIENT,
		sock->sock.priv_len);
	if (!req->param.accept.s) {
		closesocket(sock->accept_sock);
		return ERR_NOMEM;
	}

	SOCKADDR_IN *addr_local = NULL;
	SOCKADDR_IN *addr_client = NULL;
	int local_len = sizeof(SOCKADDR_IN);
	int client_len = sizeof(SOCKADDR_IN);
	__GetAcceptExSockaddrs(sock->accept_buf, 0,   
		sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16,   
		(LPSOCKADDR*)&addr_local, &local_len,  
		(LPSOCKADDR*)&addr_client, &client_len);
	assert(client_len <= sizeof(req->param.accept.src_addr->ipaddr));
	memcpy(&req->param.accept.src_addr->ipaddr, addr_client, client_len);
	req->param.accept.src_addr->flags |= ADDREX_F_IP;
	req->param.accept.s->cls = &sys_tcp_socket;

	FIBER_SOCKET_END(ftask, ERR_OK);
}

/* fiber coroutine */
static int win_tcp_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct win_socket, arg);

	/* common for all fiber coroutine */
	ret = win_may_attach_iocp(ftask, sock);
	if (unlikely(ret != ERR_OK)) {
		return ret;
	}

	sock->tx_buf.buf = (char *)req->param.send.buf;
	sock->tx_buf.len = req->param.send.len;
	memset(&sock->tx_olap, 0, sizeof(sock->tx_olap));

	ret = WSASend(sock->fd, &sock->tx_buf, 1, NULL, 0, &sock->tx_olap, NULL);
	if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		return ERR_IO;
	}

	FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
	if (ret != ERR_OK) {
		BOOL b_ret;
		b_ret = CancelIoEx((HANDLE)sock->fd, (LPOVERLAPPED)(&sock->tx_olap));
		if (b_ret == TRUE) {
			FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, FIBER_WAIT4_INFINITE);
		}
	}

	BOOL bret;
	DWORD dw_flags;
	DWORD dw_bytes_transferred;
	bret = WSAGetOverlappedResult(sock->fd, &sock->tx_olap, &dw_bytes_transferred, FALSE, &dw_flags);
	if (bret == FALSE) {
		return ERR_IO;
	}

	FIBER_SOCKET_END(ftask, (int)dw_bytes_transferred);
}

/* fiber coroutine */
static int win_tcp_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct win_socket, arg);

	/* common for all fiber coroutine */
	ret = win_may_attach_iocp(ftask, sock);
	if (unlikely(ret != ERR_OK)) {
		return ret;
	}

	sock->rx_buf.buf = (char *)req->param.recv.buf;
	sock->rx_buf.len = req->param.recv.len;
	memset(&sock->rx_olap, 0, sizeof(sock->rx_olap));
	sock->rx_flags = 0;

	ret = WSARecv(sock->fd, &sock->rx_buf, 1, NULL, &sock->rx_flags, &sock->rx_olap, NULL);
	if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		return ERR_IO;
	}

	FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
	if (ret != ERR_OK) {
		BOOL b_ret;
		b_ret = CancelIoEx((HANDLE)sock->fd, (LPOVERLAPPED)(&sock->rx_olap));
		if (b_ret == TRUE) {
			FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, FIBER_WAIT4_INFINITE);
		}
	}

	BOOL bret;
	DWORD dw_flags;
	DWORD dw_bytes_transferred;
	bret = WSAGetOverlappedResult(sock->fd, &sock->rx_olap, &dw_bytes_transferred, FALSE, &dw_flags);
	if (bret == FALSE) {
		return ERR_IO;
	} else if (dw_bytes_transferred == 0) {
		return ERR_RESET;
	}

	FIBER_SOCKET_END(ftask, (int)dw_bytes_transferred);
}

/* fiber coroutine */
static int win_shutdown_read(struct fiber_task *ftask, void *arg)
{
	struct socket_req *req = arg;
	struct win_socket *sock = (struct win_socket *)(req->s);

	assert(sock->attached_floop != NULL);
	shutdown(sock->fd, SD_RECEIVE);

	return ERR_OK;
}

/* fiber coroutine */
static int win_shutdown_write(struct fiber_task *ftask, void *arg)
{
	struct socket_req *req = arg;
	struct win_socket *sock = (struct win_socket *)(req->s);

	assert(sock->attached_floop != NULL);
	shutdown(sock->fd, SD_SEND);

	return ERR_OK;
}

static int win_tcp_close(struct socket *s)
{
	struct win_socket *sock = (struct win_socket *)s;

	closesocket(sock->fd);
	socket_unwrap(s);
	return ERR_OK;
}

struct socket_class sys_tcp_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_STREAM,
	.protocol	= SOCK_PROTO_TCP,
	.flags		= SOCKCLS_F_CONNECT,
	.name		= "win_tcp_socket",
	.socket		= win_tcp_open,
	.close		= win_tcp_close,
	.bind		= win_tcp_bind,
	.listen		= win_tcp_listen,
	.accept		= win_tcp_accept,
	.connect	= win_tcp_connect,
	.shutdown_read	= win_shutdown_read,
	.shutdown_write	= win_shutdown_write,
	.send		= win_tcp_send,
	.recv		= win_tcp_recv,
	.setsockopt	= /* common_socket_setopt, */NULL,
};

static struct socket *win_udp_open(unsigned int priv_data, void *init_data)
{
	struct socket *s;
	SOCKET fd;

	fd = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (fd == INVALID_SOCKET) {
                return NULL;
        }
	s = socket_wrap(fd, SOCK_T_UDP, priv_data);
	if (!s) {
		closesocket(fd);
	}

        return s;
}

static int win_udp_close(struct socket *s)
{
	struct win_socket *sock = (struct win_socket *)s;

	closesocket(sock->fd);
	socket_unwrap(s);
	return ERR_OK;
}

static int win_udp_bind(struct socket *s, const struct sockaddr_ex *addr)
{
	struct win_socket *sock = (struct win_socket *)s;

	return common_socket_bind(sock, addr);
}

/* fiber coroutine */
static int win_udp_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct win_socket, arg);

	/* common for all fiber coroutine */
	ret = win_may_attach_iocp(ftask, sock);
	if (unlikely(ret != ERR_OK)) {
		return ret;
	}

	/* sanity check */
	if (!(req->param.conn.addr->flags & ADDREX_F_IP)) {
		return ERR_INVAL;
	}

	sock->tx_buf.buf = (char *)req->param.send.buf;
	sock->tx_buf.len = req->param.send.len;
	memset(&sock->tx_olap, 0, sizeof(sock->tx_olap));

	ret = WSASendTo(sock->fd, &sock->tx_buf, 1, NULL, 0,
		(const struct sockaddr *)(&req->param.send.dest_addr->ipaddr), sizeof(struct sockaddr_in),
		&sock->tx_olap, NULL);
	if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		return ERR_IO;
	}

	FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
	if (ret != ERR_OK) {
		BOOL b_ret;
		b_ret = CancelIoEx((HANDLE)sock->fd, (LPOVERLAPPED)(&sock->tx_olap));
		if (b_ret == TRUE) {
			FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, FIBER_WAIT4_INFINITE);
		}
	}

	BOOL bret;
	DWORD dw_flags;
	DWORD dw_bytes_transferred;
	bret = WSAGetOverlappedResult(sock->fd, &sock->tx_olap, &dw_bytes_transferred, FALSE, &dw_flags);
	if (bret == FALSE) {
		return ERR_IO;
	}

	FIBER_SOCKET_END(ftask, (int)dw_bytes_transferred);
}

/* fiber coroutine */
static int win_udp_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct win_socket, arg);

	/* common for all fiber coroutine */
	ret = win_may_attach_iocp(ftask, sock);
	if (unlikely(ret != ERR_OK)) {
		return ret;
	}

	sock->rx_buf.buf = (char *)req->param.recv.buf;
	sock->rx_buf.len = req->param.recv.len;
	memset(&sock->rx_olap, 0, sizeof(sock->rx_olap));
	sock->rx_flags = 0;
	req->param.recv.src_addr_len = sizeof(req->param.recv.src_addr->ipaddr);

	ret = WSARecvFrom(sock->fd, &sock->rx_buf, 1, NULL, &sock->rx_flags,
		(struct sockaddr *)&req->param.recv.src_addr->ipaddr,
		&req->param.recv.src_addr_len,
		&sock->rx_olap, NULL);
	if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		return ERR_IO;
	}

	FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
	if (ret != ERR_OK) {
		BOOL b_ret;
		b_ret = CancelIoEx((HANDLE)sock->fd, (LPOVERLAPPED)(&sock->rx_olap));
		if (b_ret == TRUE) {
			FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, FIBER_WAIT4_INFINITE);
		}
	}

	BOOL bret;
	DWORD dw_flags;
	DWORD dw_bytes_transferred;
	bret = WSAGetOverlappedResult(sock->fd, &sock->rx_olap, &dw_bytes_transferred, FALSE, &dw_flags);
	if (bret == FALSE) {
		return ERR_IO;
	} else if (dw_bytes_transferred == 0) {
		return ERR_RESET;
	}

	req->param.recv.src_addr->flags = ADDREX_F_IP;

	FIBER_SOCKET_END(ftask, (int)dw_bytes_transferred);
}

struct socket_class sys_udp_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_DGRAM,
	.protocol	= SOCK_PROTO_UDP,
	.flags		= 0,
	.name		= "win_udp_socket",
	.socket		= win_udp_open,
	.close		= win_udp_close,
	.bind		= win_udp_bind,
	.listen		= NULL,
	.accept		= NULL,
	.connect	= NULL,
	.shutdown_read	= win_shutdown_read,
	.shutdown_write	= win_shutdown_write,
	.send		= win_udp_send,
	.recv		= win_udp_recv,
	.setsockopt	= /* common_socket_setopt, */NULL,
};

static struct socket *win_icmp_open(unsigned int priv_data, void *init_data)
{
	struct socket *s;
	SOCKET fd;

	fd = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (fd == INVALID_SOCKET) {
                return NULL;
        }
	s = socket_wrap(fd, SOCK_T_ICMP, priv_data);
	if (!s) {
		closesocket(fd);
	}

	return s;
}

static int win_icmp_close(struct socket *s)
{
	struct win_socket *sock = (struct win_socket *)s;

	closesocket(sock->fd);
	socket_unwrap(s);
	return ERR_OK;
}

static int win_icmp_bind(struct socket *s, const struct sockaddr_ex *addr)
{
	struct win_socket *sock = (struct win_socket *)s;

	return common_socket_bind(sock, addr);
}

/* fiber coroutine */
static int win_icmp_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct win_socket, arg);

	/* common for all fiber coroutine */
	ret = win_may_attach_iocp(ftask, sock);
	if (unlikely(ret != ERR_OK)) {
		return ret;
	}

	/* sanity check */
	if (!(req->param.conn.addr->flags & ADDREX_F_IP)) {
		return ERR_INVAL;
	}

	sock->tx_buf.buf = (char *)req->param.send.buf;
	sock->tx_buf.len = req->param.send.len;
	memset(&sock->tx_olap, 0, sizeof(sock->tx_olap));

	ret = WSASendTo(sock->fd, &sock->tx_buf, 1, NULL, 0,
		(const struct sockaddr *)(&req->param.send.dest_addr->ipaddr), sizeof(struct sockaddr_in),
		&sock->tx_olap, NULL);
	if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		return ERR_IO;
	}

	FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, req->timeout);
	if (ret != ERR_OK) {
		BOOL b_ret;
		b_ret = CancelIoEx((HANDLE)sock->fd, (LPOVERLAPPED)(&sock->tx_olap));
		if (b_ret == TRUE) {
			FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_WRITE, FIBER_WAIT4_INFINITE);
		}
	}

	BOOL bret;
	DWORD dw_flags;
	DWORD dw_bytes_transferred;
	bret = WSAGetOverlappedResult(sock->fd, &sock->tx_olap, &dw_bytes_transferred, FALSE, &dw_flags);
	if (bret == FALSE) {
		return ERR_IO;
	}

	FIBER_SOCKET_END(ftask, (int)dw_bytes_transferred);
}

static int win_icmp_recv_fixup(uint8_t *buf, int len)
{
	struct ip_hdr *iphdr = (struct ip_hdr *)buf;
	unsigned int iph_len;
	unsigned int tot_len;

	iph_len = (IPH_HL(iphdr) << 2);
	tot_len = ntohs(IPH_LEN(iphdr));

	if (iph_len >= (unsigned int)len || tot_len > (unsigned int)len) {
		return ERR_FORMAT;
	}

	memmove(buf, buf + iph_len, (unsigned int)len - iph_len);
	return ((unsigned int)len - iph_len);
}

/* fiber coroutine */
static int win_icmp_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct win_socket, arg);

	/* common for all fiber coroutine */
	ret = win_may_attach_iocp(ftask, sock);
	if (unlikely(ret != ERR_OK)) {
		return ret;
	}

	sock->rx_buf.buf = (char *)req->param.recv.buf;
	sock->rx_buf.len = req->param.recv.len;
	memset(&sock->rx_olap, 0, sizeof(sock->rx_olap));
	sock->rx_flags = 0;
	req->param.recv.src_addr_len = sizeof(req->param.recv.src_addr->ipaddr);

	ret = WSARecvFrom(sock->fd, &sock->rx_buf, 1, NULL, &sock->rx_flags,
		(struct sockaddr *)&req->param.recv.src_addr->ipaddr,
		&req->param.recv.src_addr_len,
		&sock->rx_olap, NULL);
	if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		return ERR_IO;
	}

	FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, req->timeout);
	if (ret != ERR_OK) {
		BOOL b_ret;
		b_ret = CancelIoEx((HANDLE)sock->fd, (LPOVERLAPPED)(&sock->rx_olap));
		if (b_ret == TRUE) {
			FIBER_YIELD(ftask, &sock->sock, FIBER_YIELD_R_WAIT4_READ, FIBER_WAIT4_INFINITE);
		}
	}

	BOOL bret;
	DWORD dw_flags;
	DWORD dw_bytes_transferred;
	bret = WSAGetOverlappedResult(sock->fd, &sock->rx_olap, &dw_bytes_transferred, FALSE, &dw_flags);
	if (bret == FALSE) {
		return ERR_IO;
	} else if (dw_bytes_transferred == 0) {
		return ERR_RESET;
	}

	req->param.recv.src_addr->flags = ADDREX_F_IP;
	ret = win_icmp_recv_fixup(req->param.recv.buf, (int)dw_bytes_transferred);

	FIBER_SOCKET_END(ftask, ret);
}

struct socket_class sys_icmp_socket = {
	.domain		= SOCK_DOMAIN_SYS_INET,
	.type		= SOCK_TYPE_RAW,
	.protocol	= SOCK_PROTO_ICMP,
	.flags		= 0,
	.name		= "win_icmp_socket",
	.socket		= win_icmp_open,
	.close		= win_icmp_close,
	.bind		= win_icmp_bind,
	.listen		= NULL,
	.accept		= NULL,
	.connect	= NULL,
	.shutdown_read	= win_shutdown_read,
	.shutdown_write	= win_shutdown_write,
	.send		= win_icmp_send,
	.recv		= win_icmp_recv,
	.setsockopt	= /* common_socket_setopt, */NULL,
};

/* subsystem init/exit */
static void subsys_load_mswsock(void)
{
	static GUID guidConnectEx = WSAID_CONNECTEX;
	static GUID guidAcceptEx = WSAID_ACCEPTEX;
	static GUID guidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;  
	SOCKET sock;
	DWORD dw_bytes;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sock) {
		return;
	}
	if (SOCKET_ERROR == WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&guidConnectEx, sizeof(guidConnectEx),
			&__ConnectEx, sizeof(__ConnectEx), &dw_bytes, NULL, NULL)) {
		fprintf(stderr, "WARNING: ConnectEx is not available\n");
		__ConnectEx = NULL;
	}
	if (SOCKET_ERROR == WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,   
			&guidAcceptEx, sizeof(guidAcceptEx),
			&__AcceptEx, sizeof(__AcceptEx), &dw_bytes, NULL, NULL)) {
		fprintf(stderr, "WARNING: AcceptEx is not available\n");
		__AcceptEx = NULL;
	}
	if (SOCKET_ERROR == WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,   
			&guidGetAcceptExSockaddrs, sizeof(guidGetAcceptExSockaddrs),   
			&__GetAcceptExSockaddrs, sizeof(__GetAcceptExSockaddrs), &dw_bytes, NULL, NULL)) {
		fprintf(stderr, "WARNING: GetAcceptExSockaddrs is not available");
		__GetAcceptExSockaddrs = NULL;
	}
	closesocket(sock);
}

int subsys_sys_socket_init(const char *keyfile, const char *certfile)
{
	int ret;
	WSADATA wsa_data;

	ret = WSAStartup(0x0202, &wsa_data);
	if (ret != 0) {
		return ERR_UNKNOWN;
	}

	subsys_load_mswsock();

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

	WSACleanup();
}
