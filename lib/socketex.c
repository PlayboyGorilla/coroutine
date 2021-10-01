#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "socketex.h"
#include "errno.h"

#include "hosal/byteorder.h"

/*sockaddr_ex operations*/
void addrex_init(struct sockaddr_ex *addr)
{
	memset(addr, 0, sizeof(struct sockaddr_ex));
	addr->ipaddr.sin_family = AF_INET;
}

/*ip, port -- network order*/
void addrex_set_ip(struct sockaddr_ex *addr, be32_t ip, be16_t port)
{
	addr->ipaddr.sin_addr.s_addr = ip;
	addr->ipaddr.sin_port = port;
	
	addr->flags |= ADDREX_F_IP;
}

void addrex_clear_ip(struct sockaddr_ex *addr)
{
	memset(&addr->ipaddr, 0, sizeof(addr->ipaddr));

	addr->ipaddr.sin_family = AF_INET;
	
	addr->flags &= ~ADDREX_F_IP;
}

/*port -- host order*/
int addrex_set_name(struct sockaddr_ex *addr, const char *name, uint16_t port)
{
	if(strlen(name) >= MAX_DOMAIN_LEN)
		return ERR_OVERFLOW;

	strncpy(addr->naddr.name, name, MAX_DOMAIN_LEN);
	addr->naddr.port = port;

	addr->flags |= ADDREX_F_NAME;

	return ERR_OK;
}

void addrex_clear_name(struct sockaddr_ex * addr)
{
	memset(&addr->naddr, 0, sizeof(addr->naddr));

	addr->flags &= ~ADDREX_F_NAME;
}

const struct sockaddr_in * addrex_get_ip(struct sockaddr_ex * addr)
{
	if((addr->flags & ADDREX_F_IP) == 0)
		return NULL;

	return &addr->ipaddr;
}

const char * addrex_get_name(struct sockaddr_ex * addr, unsigned short * port)
{
	if((addr->flags & ADDREX_F_NAME) == 0)
		return NULL;

	*port = addr->naddr.port;
	return addr->naddr.name;
}

/*port returns in network order*/
int addrex_get_port(const struct sockaddr_ex * addr, be16_t *port)
{
	int iret;

	if(addr->flags & ADDREX_F_NAME) {
		*port = sys_htobe16(addr->naddr.port);
		iret = ERR_OK;
	}else if(addr->flags & ADDREX_F_IP) {
		*port = addr->ipaddr.sin_port;
		iret = ERR_OK;
	}else {
		iret = ERR_INVAL;
	}

	return iret;
}

void addrex_set_port(struct sockaddr_ex * addr, be16_t port)
{
	addr->ipaddr.sin_port = port;
	addr->naddr.port = sys_betoh16(port);
}

void addrex_copy(struct sockaddr_ex *dst, const struct sockaddr_ex *src)
{
	memcpy(dst, src, sizeof(*dst));
}

int addrex_is_equal(const struct sockaddr_ex * addr1, const struct sockaddr_ex * addr2)
{
	if(addr1->flags != addr2->flags)
		return 0;

	if(addr1->flags & ADDREX_F_IP) {
		if(addr1->ipaddr.sin_addr.s_addr != addr2->ipaddr.sin_addr.s_addr)
			return 0;
		if(addr1->ipaddr.sin_port != addr2->ipaddr.sin_port)
			return 0;
	}
	
	if(addr1->flags & ADDREX_F_NAME) {
		if(strcmp(addr1->naddr.name, addr2->naddr.name) != 0)
			return 0;
		if(addr1->naddr.port != addr2->naddr.port)
			return 0;
	}

	return 1;
}

int addrex_to_string(const struct sockaddr_ex * addr, char * out, unsigned int out_len, int with_port)
{
	if (addr->flags & ADDREX_F_NAME) {
		if(with_port)
			return snprintf(out, out_len, "%s:%u", addr->naddr.name, addr->naddr.port);
		else
			return snprintf(out, out_len, "%s", addr->naddr.name);
	} else if (addr->flags & ADDREX_F_IP) {
		if (with_port)
			return snprintf(out, out_len, "%s:%u", inet_ntoa(addr->ipaddr.sin_addr), sys_betoh16(addr->ipaddr.sin_port));
		else
			return snprintf(out, out_len, "%s", inet_ntoa(addr->ipaddr.sin_addr));
	}

	return 0;
}
