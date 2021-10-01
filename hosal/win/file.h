#ifndef __HOSAL_FILE_WIN__
#define __HOSAL_FILE_WIN__

#include "lib/types.h"
#include "lib/misc.h"

struct sys_file {
	int fd;
};

#define SYS_FILE_OPEN_READ	0
#define SYS_FILE_OPEN_WRITE	1
#define SYS_FILE_OPEN_APPEND	2
extern struct sys_file *sys_file_open(const char *name, int open_mode);
extern void sys_file_close(struct sys_file *);

#define SYS_FILE_IO_WAITALL	BIT(0)
extern int sys_file_read(struct sys_file *, uint8_t *buf, int len, int flags);
extern int sys_file_write(struct sys_file *, const uint8_t *buf, int len, int flags);
extern int sys_file_exist(const char *name);
extern unsigned int sys_file_size(const char *name);

#endif
