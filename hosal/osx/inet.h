#ifndef __HOSAL_INET_OSX_H__
#define __HOSAL_INET_OSX_H__

#include "lib/types.h"
#include "lib/misc.h"

extern int sys_inet_str2ip(const char *str, be32_t *ip);
extern void sys_inet_ip2str(be32_t ip, char *out);

#endif
