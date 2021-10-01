#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <io.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "hosal/file.h"
#include "lib/errno.h"

struct sys_file *sys_file_open(const char *name, int open_mode)
{
	struct sys_file *sf;
	int fd;

	if (open_mode == SYS_FILE_OPEN_READ) {
		fd = open(name, _O_RDONLY | _O_BINARY);
	} else if (open_mode == SYS_FILE_OPEN_WRITE) {
		fd = open(name, _O_RDWR | _O_BINARY | _O_CREAT | _O_TRUNC, _S_IRUSR | _S_IWUSR);
	} else if (open_mode == SYS_FILE_OPEN_APPEND) {
		fd = open(name, _O_RDWR | _O_BINARY | _O_CREAT, _S_IRUSR | _S_IWUSR);
	} else {
		return NULL;
	}
	if (fd < 0) {
		return NULL;
	} 

	sf = (struct sys_file *)malloc(sizeof(*sf));
	if (!sf) {
		_close(fd);
		return NULL;
	}
	sf->fd = fd;
	return sf;
}

void sys_file_close(struct sys_file *sf)
{
	_close(sf->fd);
	free(sf);
}

int sys_file_read(struct sys_file *sf, uint8_t *buf, int len, int flags)
{
	int proced = 0;
	int ret;

	if (len <= 0)
		return ERR_INVAL;

	while(1) {
		ret = _read(sf->fd, buf + proced, len - proced);
		if (ret <= 0) {
			return ERR_IO;
		}

		proced += ret;
		if (proced == len || !(flags & SYS_FILE_IO_WAITALL))
			return proced;
	}

	return 0;
}

int sys_file_write(struct sys_file *sf, const uint8_t *buf, int len, int flags)
{
	int proced = 0;
	int ret;

	if (len <= 0)
		return ERR_INVAL;

	while (1) {
		ret = _write(sf->fd, buf + proced, len - proced);
		if (ret <= 0)
			return ERR_IO;
	
		proced += ret;
		if (proced == len || !(flags & SYS_FILE_IO_WAITALL))
			return proced;
	}

	return 0;
}

int sys_file_exist(const char *name)
{
	int ret;
	struct _stat file_info;

	ret = _stat(name, &file_info);
	if (ret < 0)
		return 0;

	return 1;
}

unsigned int sys_file_size(const char *name)
{
	int ret;
	struct _stat file_info;

	ret = _stat(name, &file_info);
	if (ret < 0)
		return 0;

	return (unsigned int)(file_info.st_size);
}
