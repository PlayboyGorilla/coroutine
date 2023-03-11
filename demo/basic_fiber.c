#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <setjmp.h>

#include "init.h"
#include "fiber/fiber.h"
#include "lib/types.h"
#include "lib/errno.h"
#include "hosal/timer.h"
#include "hosal/socket.h"

#define TEST_TASKLET_NR		1000

/* test fiber 1 */
struct test_fiber_task {
        int a;
        char str[18];
        unsigned int b;
	unsigned int rand1;	/* 1 ~ 1000 */
	unsigned int rand2;	/* 1 ~ 1000 */
};

static int test_fiber_func_recur(struct fiber_task *ftask, void *arg)
{
	FIBER_BEGIN(ftask, struct test_fiber_task, ftask_local);

	FIBER_MSLEEP(ftask, ftask_local->rand2);
	ftask_local->b++;

	FIBER_END(ftask, ERR_OK);
}

static int test_fiber_func(struct fiber_task *ftask, void *arg)
{
	FIBER_BEGIN(ftask, struct test_fiber_task, ftask_local);

	ftask_local->rand1 = rand();
	ftask_local->rand2 = rand();
	ftask_local->rand1 = ftask_local->rand1 % 1000 + 1;
	ftask_local->rand2 = ftask_local->rand2 % 1000 + 1;

	FIBER_MSLEEP(ftask, ftask_local->rand1);
	ftask_local->a++;

	FIBER_SUBCO(ftask, test_fiber_func_recur, NULL);

	FIBER_END(ftask, ERR_OK);
}

static void test_fiber_destructor(struct fiber_task *ftask)
{
	fiber_free(ftask);
}

static void fiber_msleep_test(struct fiber_loop *floop, int a, unsigned int b)
{
	struct fiber_task *ftask;
	fiber_task_id tid;
	struct test_fiber_task *ftask_local;
	int ret;

	ftask = fiber_alloc(sizeof(struct test_fiber_task), test_fiber_func, test_fiber_destructor);
	assert(ftask);

	ftask_local = fiber_local(ftask);
	ftask_local->a = a;
	ftask_local->b = b;
	strcpy(ftask_local->str, "hello");

	ret = fiber_submit(floop, ftask, &tid);
	if (ret != ERR_OK) {
		printf("%s: i=%d, ret=%d\n", __func__, a, ret);
	}
	assert(ret == ERR_OK);
}

#if 0
/* test fiber sock */
struct test_fiber_sock {
	struct socket		*s;
	int			index;
	struct sockaddr_ex	conn_addr;
	struct socket_req	req;
};

#define SERVER_IP	"9.9.9.9"
#define SERVER_PORT	443

static int test_fiber_sock_func(struct fiber_task *ftask)
{
	FIBER_BEGIN(ftask, struct test_fiber_sock, local);

	memset(&local->conn_addr, 0, sizeof(local->conn_addr));
	local->conn_addr.ipaddr.sin_family = AF_INET;
	local->conn_addr.ipaddr.sin_port = htons(SERVER_PORT);
	local->conn_addr.ipaddr.sin_addr.s_addr = (uint32_t)inet_addr(SERVER_IP);
	local->conn_addr.flags = ADDREX_F_IP;

	socket_init_connect_req(&local->req,
		&local->conn_addr, 1);

	FIBER_SOCKET_CONNECT(ftask, local->s, &local->req);
	printf("%s: task index %d: connect result %d\n", __func__, local->index, local->req.ret);

	socket_init_shutdown_req(&local->req, SOCK_SHUTDOWN_RDWR);
	FIBER_SOCKET_SHUTDOWN(ftask, local->s, &local->req);
	printf("%s: task index %d: shutdown result %d\n", __func__, local->index, local->req.ret);

	FIBER_END(ftask, ERR_OK);
}

static void test_fiber_sock_destructor(struct fiber_task *ftask)
{
	struct test_fiber_sock *ftask_local;

	ftask_local = fiber_local(ftask);
	socket_close(ftask_local->s);
	fiber_free(ftask);
}

static void fiber_sock_test(struct fiber_loop *floop, int index)
{
	struct fiber_task *ftask;
	fiber_task_id tid;
	struct test_fiber_sock *ftask_local;
	int ret;

	ftask = fiber_alloc(sizeof(struct test_fiber_sock), test_fiber_sock_func, test_fiber_sock_destructor);
	assert(ftask);

	ftask_local = fiber_local(ftask);
	ftask_local->s = socket_create_from_class(&sys_ssl_socket, 0, NULL);
	assert(ftask_local->s != NULL);
	ftask_local->index = index;

	ret = fiber_submit(floop, ftask, &tid);
	assert(ret == ERR_OK);
}
#endif

/* test user event/notify */
struct test_fiber_uevent {
	int index;
	struct fiber_user_event *uevent;
};

static int test_fiber_uevent_func(struct fiber_task *ftask, void *arg)
{
	FIBER_BEGIN(ftask, struct test_fiber_uevent, local);

	FIBER_GET_USER_EVENT(ftask, local->uevent);
	printf("%s: event data=\"%s\"\n", __func__, (const char *)(local->uevent->msg_data));
	fiber_return_user_event(local->uevent, ERR_OK);

	FIBER_GET_USER_EVENT(ftask, local->uevent);
	printf("%s-2: event data=\"%s\"\n", __func__, (const char *)(local->uevent->msg_data));
	fiber_return_user_event(local->uevent, ERR_OK);

	FIBER_END(ftask, ERR_OK);
}

static void test_fiber_uevent_destructor(struct fiber_task *ftask)
{
	fiber_free(ftask);
}

static void test_fiber_uevent_done(void *msg_data, int result)
{
	const char *str = msg_data;

	printf("%s: \"%s\", result=%d\n", __func__, str, result);
}

static char uevent_text[100] = "hello,fiber";
static char uevent_text2[100] = "hello again, fiber";

static void fiber_uevent_test(struct fiber_loop *floop, int index)
{
	struct fiber_task *ftask;
	fiber_task_id tid;
	struct test_fiber_uevent *local;
	int ret;

	ftask = fiber_alloc(sizeof(struct test_fiber_uevent), test_fiber_uevent_func, test_fiber_uevent_destructor);
	assert(ftask);

	local = fiber_local(ftask);
	local->index = index;

	ret = fiber_submit(floop, ftask, &tid);
	assert(ret == ERR_OK);

	sleep(1);

	fiber_notify(floop, tid, uevent_text, test_fiber_uevent_done);
	fiber_notify(floop, tid, uevent_text2, test_fiber_uevent_done);
}

int main(void)
{
	int ret;
	struct fiber_loop *floop;
	unsigned int i;
	struct sys_init_param iparam;

	/* init */
	iparam.keyfile = NULL;
	iparam.certfile = NULL;
	iparam.fifo_base = "/tmp/coroutine_fb";
	ret = sys_init(&iparam);
	assert(ret == ERR_OK);

	floop = fiber_loop_create();
	if (!floop) {
		printf("fiber_loop_create failed\n");
		return -1;
	}

	(void)fiber_msleep_test;
	//(void)fiber_sock_test;
	(void)fiber_uevent_test;
	(void)i;

	for (i = 0; i < TEST_TASKLET_NR; i++) {
		fiber_msleep_test(floop, i, 0x12345678);
	}

	//fiber_sock_test(floop, 0);
	//fiber_msleep_test(floop, 10, 0x12345678);
	//fiber_sock_test(floop, 1);
	//fiber_msleep_test(floop, 11, 0x12345679);

	fiber_uevent_test(floop, 0);

	fiber_loop_destroy(floop);
	return 0;
}
