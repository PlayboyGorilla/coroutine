#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "hosal/thread.h"
#include "lib/misc.h"
#include "lib/errno.h"
#include "fiber/socket.h"
#include "fiber/fiber.h"
#include "log/stats.h"

static DEFINE_LIST_HEAD(sock_class_list);

void register_socket_class(struct socket_class *sockcls)
{
	/*
	 * FIXME: The list should be protected by a lock
	 * since all potential calls will be in initialization,
	 * no synchronization issues
	 */
	list_add_tail(&sock_class_list, &sockcls->node);
}

void unregister_socket_class(struct socket_class *sockcls)
{
	/* same as above */
	list_del_node(&sock_class_list, &sockcls->node);
}

/* unified interfaces */
static inline void socket_init_io(struct socket_io *sio)
{
	sio->in_progress = 0;
}

static inline void socket_init_pending_ftask(struct fiber_task *ftasks[SOCK_PENDING_FTASK_MAX])
{
	unsigned int i;

	for (i = 0; i < SOCK_PENDING_FTASK_MAX; i++) {
		ftasks[i] = NULL;
	}
}

struct socket *socket_create_from_class(struct socket_class *sockcls, unsigned int priv_data, void *init_data)
{
	struct socket *s;

	s = sockcls->socket(priv_data, init_data);
	if (s) {
		s->cls = sockcls;
		socket_init_io(&s->io[SOCK_IO_OP_TX]);
		socket_init_io(&s->io[SOCK_IO_OP_RX]);
		socket_init_io(&s->io[SOCK_IO_OP_SHUTDOWN_READ]);
		socket_init_io(&s->io[SOCK_IO_OP_SHUTDOWN_WRITE]);

		socket_init_pending_ftask(s->read_ftask);
		socket_init_pending_ftask(s->write_ftask);
		s->read_mon_on = 0;
		s->write_mon_on = 0;

		STATS_INC(STATS_SOCKET);
	}

	return s;
}

struct socket *socket_create(int domain, int type, int protocol, unsigned int priv_data, void *init_data)
{
	struct list_node *node;
	struct socket_class *sockcls;

	list_for_head2tail(&sock_class_list, node) {
		sockcls = container_of(node, struct socket_class, node);
		if (domain == sockcls->domain
				&& type == sockcls->type
				&& protocol == sockcls->protocol) {
			return socket_create_from_class(sockcls, priv_data, init_data);
		}
	}

	return NULL;
}

static void socket_unwrap_clear_ftask(struct socket *s,
	struct fiber_task *ftasks[SOCK_PENDING_FTASK_MAX])
{
	struct fiber_task *ftask;
	unsigned int i;

	for (i = 0; i < SOCK_PENDING_FTASK_MAX; i++) {
		ftask = ftasks[i];
		if (ftask) {
			assert(ftask->last_yield_sock == s);
			ftask->last_yield_sock = NULL;
		}
	}
}

/*
 * NOTE: owner of the socket must ensure no more socket calls 
 */
int socket_close(struct socket *sock)
{
	assert(!socket_is_in_progress(sock, SOCK_IO_OP_TX));
	assert(!socket_is_in_progress(sock, SOCK_IO_OP_RX));
	assert(!socket_is_in_progress(sock, SOCK_IO_OP_SHUTDOWN_READ));
	assert(!socket_is_in_progress(sock, SOCK_IO_OP_SHUTDOWN_WRITE));

	socket_unwrap_clear_ftask(sock, sock->read_ftask);
	socket_unwrap_clear_ftask(sock, sock->write_ftask);

	STATS_DEC(STATS_SOCKET);

	return sock->cls->close(sock);
}

int socket_bind(struct socket *sock, const struct sockaddr_ex *addr)
{
	if (!sock->cls->bind) {
		return ERR_NOTSUPPORTED;
	}
	return sock->cls->bind(sock, addr);
}

int socket_listen(struct socket *sock)
{
	if (!sock->cls->listen) {
		return ERR_NOTSUPPORTED;
	}
	return sock->cls->listen(sock);
}

int socket_setopt(struct socket *sock, int option, int val)
{
	if (!sock->cls->setsockopt) {
		return ERR_NOTSUPPORTED;
	}
	return sock->cls->setsockopt(sock, option, val);
}

void socket_cancel(struct socket_req *req)
{
	if (!req->ftask) {
		return;
	}

	fiber_schedule(req->ftask, ERR_ABORTED);
}

#define SOCK_REQ_RETURN(req, _ret)	\
	do {				\
		(req)->ret = (_ret);	\
		return (_ret);		\
	} while(0)

#define FIBER_SOCKET_SUBCO_1(_ftask, _subco, _arg, _sio)						\
	do {												\
		/* re-entry point */									\
		FIBER_CONCAT(FIBER_LABEL, __LINE__):							\
		(_ftask)->tier++;									\
		ret = (_subco)(_ftask, _arg);								\
		(_ftask)->tier--;									\
		if (ret == ERR_INPROGRESS) {								\
			(_ftask)->labels[(_ftask)->tier] = &&FIBER_CONCAT(FIBER_LABEL, __LINE__);	\
			(_sio)->in_progress = 1;							\
			req->ftask = (_ftask);								\
			return ret;									\
		} else {										\
			(_sio)->in_progress = 0;							\
			req->ret = ret;									\
			req->ftask = NULL;								\
		}											\
	} while (0)

int socket_accept(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct socket, arg);

	if (!sock->cls->accept) {
		SOCK_REQ_RETURN(req, ERR_NOTSUPPORTED);
	}
	if (unlikely(sock->io[SOCK_IO_OP_RX].in_progress)) {
		SOCK_REQ_RETURN(req, ERR_BUSY);
	}

	FIBER_SOCKET_SUBCO_1(ftask, sock->cls->accept, arg, &sock->io[SOCK_IO_OP_RX]);
	FIBER_SOCKET_END(ftask, ret);
}

int socket_connect(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct socket, arg);

	if (!sock->cls->connect) {
		SOCK_REQ_RETURN(req, ERR_NOTSUPPORTED);
	}
	if (unlikely(sock->io[SOCK_IO_OP_TX].in_progress)) {
		SOCK_REQ_RETURN(req, ERR_BUSY);
	}

	FIBER_SOCKET_SUBCO_1(ftask, sock->cls->connect, arg, &sock->io[SOCK_IO_OP_TX]);
	FIBER_SOCKET_END(ftask, ret);
}

int socket_shutdown_read(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct socket, arg);

	if (!sock->cls->shutdown_read) {
		SOCK_REQ_RETURN(req, ERR_OK);
	}
	if (unlikely(sock->io[SOCK_IO_OP_SHUTDOWN_READ].in_progress)) {
		SOCK_REQ_RETURN(req, ERR_BUSY);
	}

	FIBER_SOCKET_SUBCO_1(ftask, sock->cls->shutdown_read, arg, &sock->io[SOCK_IO_OP_SHUTDOWN_READ]);
	FIBER_SOCKET_END(ftask, ret);
}

int socket_shutdown_write(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct socket, arg);

	if (!sock->cls->shutdown_write) {
		SOCK_REQ_RETURN(req, ERR_OK);
	}
	if (unlikely(sock->io[SOCK_IO_OP_SHUTDOWN_WRITE].in_progress)) {
		SOCK_REQ_RETURN(req, ERR_BUSY);
	}

	FIBER_SOCKET_SUBCO_1(ftask, sock->cls->shutdown_write, arg, &sock->io[SOCK_IO_OP_SHUTDOWN_WRITE]);
	FIBER_SOCKET_END(ftask, ret);
}

#define FIBER_SOCKET_SUBCO_TX(_ftask, _arg)								\
	do {												\
		FIBER_CONCAT(FIBER_LABEL, __LINE__):							\
		(_ftask)->tier++;									\
		ret = (sock->cls->send)(_ftask, _arg);							\
		(_ftask)->tier--;									\
		if (ret == ERR_INPROGRESS) {								\
			(_ftask)->labels[(_ftask)->tier] = &&FIBER_CONCAT(FIBER_LABEL, __LINE__);	\
			sock->io[SOCK_IO_OP_TX].in_progress = 1;					\
			req->ftask = (_ftask);								\
			return ret;									\
		} else if (ret > 0) {									\
			req->ret += ret;								\
			assert(req->ret <= req->param.send.len);					\
			if (req->ret == req->param.send.len						\
					|| req->wait_type != SOCKIO_WAIT_ALL) {				\
				sock->io[SOCK_IO_OP_TX].in_progress = 0;				\
				req->ftask = NULL;							\
				ret = ERR_OK;								\
				break;									\
			}										\
		} else if (ret < 0) {									\
			if (req->ret <= 0) {								\
				req->ret = ret;								\
			}										\
			sock->io[SOCK_IO_OP_TX].in_progress = 0;					\
			req->ftask = NULL;								\
			break;										\
		} else {										\
			/* cls->send/recv should never return 0 */					\
			assert(0);									\
		}											\
	} while (1)

int socket_send(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct socket, arg);

	if (sock->cls->type != SOCK_TYPE_STREAM &&
			req->wait_type == SOCKIO_WAIT_ALL) {
		req->wait_type = SOCKIO_WAIT_NORMAL;
	}
	if (unlikely(sock->io[SOCK_IO_OP_TX].in_progress)) {
		SOCK_REQ_RETURN(req, ERR_BUSY);
	}

	FIBER_SOCKET_SUBCO_TX(ftask, arg);
	FIBER_SOCKET_END(ftask, ret);
}

#define FIBER_SOCKET_SUBCO_RX(_ftask, _arg)								\
	do {												\
		FIBER_CONCAT(FIBER_LABEL, __LINE__):							\
		(_ftask)->tier++;									\
		ret = (sock->cls->recv)(_ftask, _arg);							\
		(_ftask)->tier--;									\
		if (ret == ERR_INPROGRESS) {								\
			(_ftask)->labels[(_ftask)->tier] = &&FIBER_CONCAT(FIBER_LABEL, __LINE__);	\
			sock->io[SOCK_IO_OP_RX].in_progress = 1;					\
			req->ftask = (_ftask);								\
			return ret;									\
		} else if (ret > 0) {									\
			req->ret += ret;								\
			assert(req->ret <= req->param.recv.len);					\
			(_ftask)->last_ret = ERR_OK;							\
			if (req->ret == req->param.recv.len						\
					|| req->wait_type != SOCKIO_WAIT_ALL) {				\
				sock->io[SOCK_IO_OP_RX].in_progress = 0;				\
				req->ftask = NULL;							\
				ret = ERR_OK;								\
				break;									\
			}										\
		} else if (ret < 0) {									\
			if (req->ret <= 0) {								\
				req->ret = ret;								\
			}										\
			sock->io[SOCK_IO_OP_RX].in_progress = 0;					\
			req->ftask = NULL;								\
			break;										\
		} else {										\
			/* cls->send/recv should never return 0 */					\
			assert(0);									\
		}											\
	} while (1)

int socket_recv(struct fiber_task *ftask, void *arg)
{
	FIBER_SOCKET_BEGIN(ftask, struct socket, arg);

	if (sock->cls->type != SOCK_TYPE_STREAM &&
			req->wait_type == SOCKIO_WAIT_ALL) {
		req->wait_type = SOCKIO_WAIT_NORMAL;
	}

	if (unlikely(sock->io[SOCK_IO_OP_RX].in_progress)) {
		SOCK_REQ_RETURN(req, ERR_BUSY);
	}

	FIBER_SOCKET_SUBCO_RX(ftask, arg);
	FIBER_SOCKET_END(ftask, ret);
}

/* request interfaces */
void socket_init_connect_req(struct socket *s, struct socket_req *req,
	const struct sockaddr_ex *addr, int is_ssl, unsigned long timeout)
{
	req->s = s;
	req->ret = 0;
	req->ftask = NULL;
	req->timeout = timeout;
	req->io_type = SOCKIO_T_CONNECT;
	req->wait_type = SOCKIO_WAIT_NORMAL;
	req->param.conn.addr = addr;
	req->param.conn.flags = (is_ssl ? SOCK_REQP_F_SSL : 0);
	memset(&req->u, 0, sizeof(req->u));
}

void socket_init_accept_req(struct socket *s, struct socket_req *req,
	struct sockaddr_ex *addr, unsigned long timeout)
{
	req->s = s;
	req->ret = 0;
	req->ftask = NULL;
	req->timeout = timeout;
	req->io_type = SOCKIO_T_ACCEPT;
	req->wait_type = SOCKIO_WAIT_NORMAL;
	req->param.accept.s = NULL;
	req->param.accept.src_addr = addr;
	memset(&req->u, 0, sizeof(req->u));
}

void socket_init_send_req(struct socket *s, struct socket_req *req, const struct sockaddr_ex *dest_addr,
	const uint8_t *buf, unsigned int len, uint16_t wait_type, unsigned long timeout)
{
	req->s = s;
	req->ret = 0;
	req->ftask = NULL;
	req->timeout = timeout;
	req->io_type = SOCKIO_T_SEND;
	req->wait_type = wait_type;
	req->param.send.dest_addr = dest_addr;
	req->param.send.buf = buf;
	req->param.send.len = len;
	memset(&req->u, 0, sizeof(req->u));
}

void socket_init_recv_req(struct socket *s, struct socket_req *req, struct sockaddr_ex *src_addr,
	uint8_t *buf, unsigned int len, uint16_t wait_type, unsigned long timeout)
{
	req->s = s;
	req->ret = 0;
	req->ftask = NULL;
	req->timeout = timeout;
	req->io_type = SOCKIO_T_RECV;
	req->wait_type = wait_type;
	req->param.recv.src_addr = src_addr;
	req->param.recv.buf = buf;
	req->param.recv.len = len;
	memset(&req->u, 0, sizeof(req->u));
}

void socket_init_shutdown_read_req(struct socket *s, struct socket_req *req, unsigned long timeout)
{
	req->s = s;
	req->ret = 0;
	req->ftask = NULL;
	req->timeout = timeout;
	req->io_type = SOCKIO_T_SHUTDOWN_READ;
	req->wait_type = SOCKIO_WAIT_NORMAL;
	memset(&req->u, 0, sizeof(req->u));
}

void socket_init_shutdown_write_req(struct socket *s, struct socket_req *req, unsigned long timeout)
{
	req->s = s;
	req->ret = 0;
	req->ftask = NULL;
	req->timeout = timeout;
	req->io_type = SOCKIO_T_SHUTDOWN_WRITE;
	req->wait_type = SOCKIO_WAIT_NORMAL;
	memset(&req->u, 0, sizeof(req->u));
}
