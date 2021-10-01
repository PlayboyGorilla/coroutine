#ifndef __FIBER_SOCKET_H__
#define __FIBER_SOCKET_H__
#include <stdint.h>

#include "fiber/fiber_priv.h"
#include "fiber/fiber.h"

#include "lib/list.h"
#include "lib/socketex.h"
#include "lib/misc.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

struct socket_req;
/*
 * describe on-going I/O operation
 */
struct socket_io {
	int			in_progress;
};

struct socket_class;
struct socket {
	struct socket_class	*cls;
#define SOCK_IO_OP_TX		0
#define SOCK_IO_OP_RX		1
#define SOCK_IO_OP_SHUTDOWN	2
#define SOCK_IO_OP_MAX		3
	struct socket_io	io[SOCK_IO_OP_MAX];
	void			*priv_data;
	unsigned int		priv_len;
};

static inline int socket_is_in_progress(const struct socket *sock, unsigned int which_op)
{
	return sock->io[which_op].in_progress;
}

#define SOCK_DOMAIN_SYS_INET	1
#define SOCK_DOMAIN_SYS_INET6	2

#define SOCK_TYPE_STREAM	1 
#define SOCK_TYPE_DGRAM		2
#define SOCK_TYPE_RAW		3

#define SOCK_PROTO_TCP		1
#define SOCK_PROTO_UDP		2
#define SOCK_PROTO_ICMP		3
#define SOCK_PROTO_SSL		4
#define SOCK_PROTO_RAW		5

#define SOCK_SHUTDOWN_RD	BIT(0)
#define SOCK_SHUTDOWN_WR	BIT(1)
#define SOCK_SHUTDOWN_RDWR	(SOCK_SHUTDOWN_RD | SOCK_SHUTDOWN_WR)

struct fiber_task;
struct socket_req;
struct socket_class {
	int domain;
	int type;
	int protocol;
#define SOCKCLS_F_REMOTE_DNS		BIT(0)		/* capable of remote DNS */
#define SOCKCLS_F_CONNECT		BIT(1)		/* connection oriented */
#define SOCKCLS_F_CONNECT_NOWAIT	BIT(2)
#define SOCKCLS_F_ACCEPT_NOWAIT		BIT(3)
#define SOCKCLS_F_SEND_NOWAIT		BIT(4)
#define SOCKCLS_F_RECV_NOWAIT		BIT(5)
	unsigned int flags;

	const char *name;

	struct socket* (*socket)(unsigned int priv_data, void *init_data);
	int (*close)(struct socket *);

	int (*bind)(struct socket *, const struct sockaddr_ex *);
	int (*listen)(struct socket *);

	fiber_callback	accept;
	fiber_callback	connect;
	fiber_callback	shutdown;
	fiber_callback	send;
	fiber_callback	recv;

	int (*setsockopt)(struct socket *, int level, int optname, const void *optval, socklen_t optlen);

	/* internal -- never touch directly */
	struct list_node	node;
};

extern void register_socket_class(struct socket_class *);
extern void unregister_socket_class(struct socket_class *);

/* unified interfaces */
union socket_req_param {
	struct {
		const struct sockaddr_ex *addr;
#define SOCK_REQP_F_SSL		BIT(0)
		unsigned int flags;
		X509	*svr_cert;	/* server certificate to verify against */
	}conn;
	struct {
		struct socket *s;		/* output -- returned by tcp_accept */
		struct sockaddr_ex *src_addr;	/* output -- address that initiate the TCP connection */
	}accept;
	struct {
		struct sockaddr_ex *src_addr;	/* output -- source address, used by UDP */
		socklen_t	src_addr_len;	/* output -- source address length*/
		uint8_t *buf;			/* input -- associated user buffer */
		unsigned int len;		/* input -- associated user buffer len */
	}recv;
	struct {
		const struct sockaddr_ex *dest_addr;	/* input -- UDP */
		const uint8_t *buf;			/* input -- associated user buffer */
		unsigned int len;			/* input -- associated user buffer len */
	}send;
	struct {
		int	how;
	}shutdown;
};

struct fiber_task;
struct socket_req {
	struct socket *s;	/* a socket_req is bound with a socket */
#define SOCKIO_T_CONNECT	0
#define SOCKIO_T_ACCEPT		1
#define SOCKIO_T_RECV		2
#define SOCKIO_T_SEND		3
#define SOCKIO_T_SHUTDOWN	4
#define SOCKIO_T_MAX		5
	uint16_t io_type;
#define SOCKIO_WAIT_NORMAL      0
#define SOCKIO_WAIT_ALL		1
	uint16_t wait_type;
	union socket_req_param param;
	int			ret;
	struct fiber_task	*ftask;
	unsigned long		timeout;
	struct list_node	node;		/* internal -- link this request to 'struct sock' object internal queue */
	/* used by porting layer */
	union {
		uint64_t		extra_data;
		void			*extra_pointer;
	}u;
};
#define SOCK_REQ_PRIV_MAX	(sizeof(unsigned long) * 16)
#define socket_req_priv(type, req)	((type *)((req)->extra))

extern struct socket *socket_create(int domain, int type, int protocol, unsigned int priv_data, void *init_data);
extern struct socket *socket_create_from_class(struct socket_class *, unsigned int priv_data, void *init_data);
extern int socket_close(struct socket *);

extern int socket_bind(struct socket *, const struct sockaddr_ex *);
extern int socket_listen(struct socket *);

extern int socket_setopt(struct socket *, int level, int optname, const void *optval, socklen_t optlen);
extern void socket_cancel(struct socket_req *);

static inline void *socket_private(struct socket *s)
{
	return s->priv_data;
}

extern int socket_accept(struct fiber_task *, void *arg);
extern int socket_connect(struct fiber_task *, void *arg);
extern int socket_send(struct fiber_task *, void *arg);
extern int socket_recv(struct fiber_task *, void *arg);
extern int socket_shutdown(struct fiber_task *, void *arg);

/* facilitations to write fiber-based sockets */
#define FIBER_SOCKET_ACCEPT(_ftask, _req)	FIBER_SUBCO(_ftask, socket_accept, _req)
#define FIBER_SOCKET_CONNECT(_ftask, _req)	FIBER_SUBCO(_ftask, socket_connect, _req)
#define FIBER_SOCKET_SEND(_ftask, _req)		FIBER_SUBCO(_ftask, socket_send, _req)
#define FIBER_SOCKET_RECV(_ftask, _req)		FIBER_SUBCO(_ftask, socket_recv, _req)
#define FIBER_SOCKET_SHUTDOWN(_ftask, _req)	FIBER_SUBCO(_ftask, socket_shutdown, _req)

#define FIBER_SOCKET_BEGIN(_ftask, _socket_type, _arg)			\
	volatile int ret = (_ftask)->last_ret;				\
	struct socket_req *req = (struct socket_req *)(_arg);		\
	_socket_type *sock = (_socket_type *)(req->s);			\
	(void)ret;							\
	(void)req;							\
	(void)sock;							\
	assert((_ftask)->tier < FIBER_TASK_MAX_TIER);			\
	if ((_ftask)->labels[(_ftask)->tier] != NULL) {			\
		__attribute__((unused)) void *__unused_goto_p = &&unused_label;			\
		void *__goto_p = (_ftask)->labels[(_ftask)->tier];	\
unused_label:		\
		(ftask)->labels[(_ftask)->tier] = NULL;			\
		goto *__goto_p;						\
	}

#define FIBER_SOCKET_END(_ftask, _result)		return (_result)

/* request interfaces */
extern void socket_init_connect_req(struct socket *,struct socket_req *,
	const struct sockaddr_ex *, int is_ssl, unsigned long timeout);
extern void socket_init_accept_req(struct socket *, struct socket_req *,
	struct sockaddr_ex *, unsigned long timeout);
extern void socket_init_send_req(struct socket *, struct socket_req *, const struct sockaddr_ex *dest_addr,
	const uint8_t *buf, unsigned int len, uint16_t wait_type, unsigned long timeout);
extern void socket_init_recv_req(struct socket *, struct socket_req *, struct sockaddr_ex *src_addr,
	uint8_t *buf, unsigned int len, uint16_t wait_type, unsigned long timeout);
extern void socket_init_shutdown_req(struct socket *, struct socket_req *, int how, unsigned long timeout);

#endif
