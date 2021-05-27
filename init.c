#include <stdio.h>
#include <stdlib.h>

#include "hosal/timer.h"
#include "hosal/thread.h"
#include "hosal/socket.h"
#include "lib/errno.h"

int sys_init(void)
{
	int ret;

	/* hosal */
	ret = subsys_thread_init();
	if (ret != ERR_OK)
		return ret;

	subsys_timer_init();

	ret = subsys_sys_socket_init();
	if (ret != ERR_OK)
		return ret;

	return ERR_OK;
}

void sys_exit(void)
{
	/* hosal */
	subsys_sys_socket_exit();
	subsys_timer_exit();
	subsys_thread_exit();
}
