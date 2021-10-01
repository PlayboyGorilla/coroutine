#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include "lib/types.h"
#include "lib/errno.h"

extern INT WSAAPI inet_pton(INT Family, PCSTR pszAddrString, PVOID pAddrBuf);

int sys_inet_str2ip(const char *str, be32_t *ip)
{
	struct in_addr addr;
	int ret;

	ret = inet_pton(AF_INET, str, &addr);
	if (ret == 0) {
		return ERR_FORMAT;
	}

	*ip = addr.s_addr;
	return ERR_OK;
}

void sys_inet_ip2str(be32_t ip, char *out)
{
	char *str;
	struct in_addr addr;

	addr.s_addr = ip;
	str = inet_ntoa(addr);
	strcpy(out, str);
}
