#ifndef __SYSTEM_INIT_H__
#define __SYSTEM_INIT_H__

struct sys_init_param {
	const char	*keyfile;
	const char	*certfile;
};

extern int sys_init(const struct sys_init_param *param);
extern void sys_exit(void);

#endif
