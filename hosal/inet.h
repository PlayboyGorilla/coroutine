#ifndef __HOSAL_INET_H__
#define __HOSAL_INET_H__

#include "lib/types.h"

int sys_inet_str2ip(const char *str, be32_t *ip);

#define SYS_INET_IPSTR_MAX	16	/* 123.456.789.abc */
void sys_inet_ip2str(be32_t ip, char *out);

#endif
