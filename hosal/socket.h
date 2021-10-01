#ifndef __HOSAL_SOCKET_H__
#define __HOSAL_SOCKET_H__

extern int subsys_sys_socket_init(const char *keyfile, const char *certfile);
extern void subsys_sys_socket_exit(void);

#ifdef __linux__
#include "hosal/linux/socket.h"
#elif defined WIN32
#include "hosal/win/socket.h"
#elif defined __APPLE__
#include "hosal/osx/socket.h"
#else
#error "Non-supported OS model"
#endif

#endif
