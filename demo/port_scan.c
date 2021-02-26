#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "init.h"
#include "fiber/fiber.h"
#include "fiber/socket.h"
#include "lib/types.h"
#include "lib/socketex.h"
#include "lib/errno.h"
#include "hosal/timer.h"
#include "hosal/socket.h"

#define PS_CONNECT_TIMEOUT	10000
#define PS_MAX_FIBER		240
#define PS_MAX_PORT		65536
#define PS_BATCH		(PS_MAX_PORT  / PS_MAX_FIBER)

struct ps_task {
	struct socket		*s;
	struct socket_req	req;
        struct sockaddr_ex	addr;
	uint16_t		port_curr;
	/* INPUT */
	be32_t			ip;
	uint16_t		port_begin;
	uint16_t		port_end;
};

static int port_scan_fiber(struct fiber_task *ftask, void *arg)
{
	FIBER_BEGIN(ftask, struct ps_task, ps);

	for (ps->port_curr = ps->port_begin; ps->port_curr <= ps->port_end;
			ps->port_curr++) {
		ps->s = socket_create_from_class(&sys_tcp_socket, 0, NULL);
		if (!ps->s) {
			printf("socket_create failed. port_begin=%u, port_end=%u\n",
				ps->port_begin, ps->port_end);
			return ERR_NOMEM;
		}

		addrex_init(&ps->addr);
		addrex_set_ip(&ps->addr, ps->ip, htons(ps->port_curr));
		socket_init_connect_req(ps->s, &ps->req, &ps->addr, 0, PS_CONNECT_TIMEOUT, ftask);

		FIBER_SOCKET_CONNECT(ftask, &ps->req);
		if (ps->req.ret == ERR_OK) {
			printf("port %u open\n", ps->port_curr);
		}

		socket_close(ps->s);
	}

	FIBER_END(ftask, ERR_OK);
}

static void port_scan_done(struct fiber_task *ftask)
{
	fiber_free(ftask);
}

int main(int argc, char *argv[])
{
	int ret;
	struct fiber_loop *floop;
	struct fiber_task *ftask;
	struct ps_task *ps;
	fiber_task_id fid_unused;
	unsigned int i;
	be32_t ip;

	if (argc != 2) {
		fprintf(stdout, "Usage: port_scan <IP_to_scan>\n");
		return 0;
	}
	ip = (be32_t)inet_addr(argv[1]);

	/* init */
	ret = sys_init();
	assert(ret == ERR_OK);

	floop = fiber_loop_create();
	if (!floop) {
		printf("fiber_loop_create failed\n");
		return -1;
	}

	for (i = 0; i < PS_MAX_FIBER; i++) {
		ftask = fiber_alloc(sizeof(struct ps_task), port_scan_fiber, port_scan_done);
		assert(ftask != NULL);

		ps = fiber_local(ftask);
		ps->port_begin = i * PS_BATCH;
		ps->port_end = ps->port_begin + PS_BATCH - 1;
		ps->ip = ip;

		fiber_submit(floop, ftask, &fid_unused);
	}

	fiber_loop_destroy(floop);

	return 0;
}
