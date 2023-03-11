#ifndef __LIB_SOCKETEX_H
#define __LIB_SOCKETEX_H

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#define AF_INET		2
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "types.h"
#include "misc.h"

#define MAX_DOMAIN_LEN		256

struct name_addr {
	char name[MAX_DOMAIN_LEN];
	uint16_t port; /*host order*/
};
struct sockaddr_ex {
	struct sockaddr_in ipaddr;
	struct name_addr naddr;
#define ADDREX_F_IP		BIT(0)
#define ADDREX_F_NAME		BIT(1)
	unsigned int flags;
};

static inline int addrex_has_ip(const struct sockaddr_ex *addr)
{
	return (addr->flags & ADDREX_F_IP);
}

static inline int addrex_has_name(const struct sockaddr_ex *addr)
{
	return (addr->flags & ADDREX_F_NAME);
}

extern void addrex_init(struct sockaddr_ex *addr);
extern void addrex_set_ip(struct sockaddr_ex *addr, be32_t ip, be16_t port);
extern int addrex_set_name(struct sockaddr_ex *addr, const char *name, uint16_t port);
extern void addrex_clear_ip(struct sockaddr_ex *addr);
extern void addrex_clear_name(struct sockaddr_ex *addr);
extern void addrex_set_port(struct sockaddr_ex *addr, be16_t port);
extern void addrex_copy(struct sockaddr_ex *dst, const struct sockaddr_ex *src);
extern int addrex_get_ip(const struct sockaddr_ex *addr, be32_t *ip);
extern const char * addrex_get_name(struct sockaddr_ex *addr, unsigned short *port);
extern int addrex_get_port(const struct sockaddr_ex *addr, be16_t *port);
extern int addrex_is_equal(const struct sockaddr_ex *addr1, const struct sockaddr_ex *addr2);
extern int addrex_to_string(const struct sockaddr_ex *addr, char *out, unsigned int out_len, int with_port);

#endif
