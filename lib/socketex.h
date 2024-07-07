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

#include <stdbool.h>
#include "types.h"
#include "misc.h"

#define MAX_DOMAIN_LEN		256

struct name_addr {
	char name[MAX_DOMAIN_LEN];
	uint16_t port; /* host order */
};
struct sockaddr_ex {
	struct sockaddr_in ipaddr;
	struct name_addr naddr;
#define ADDREX_F_IP		BIT(0)
#define ADDREX_F_IPV6		BIT(1)
#define ADDREX_F_NAME		BIT(2)
	unsigned int flags;
};

static inline bool addrex_has_ip(const struct sockaddr_ex *addr)
{
	return !!(addr->flags & ADDREX_F_IP);
}

static inline bool addrex_has_name(const struct sockaddr_ex *addr)
{
	return !!(addr->flags & ADDREX_F_NAME);
}

extern void addrex_init(struct sockaddr_ex *addr);
extern void addrex_set_ip(struct sockaddr_ex *addr, be32_t ip, be16_t port);
extern int addrex_set_name(struct sockaddr_ex *addr, const char *name, uint16_t port);
extern void addrex_clear_ip(struct sockaddr_ex *addr);
extern void addrex_clear_name(struct sockaddr_ex *addr);
extern void addrex_set_port(struct sockaddr_ex *addr, be16_t port);
extern void addrex_copy(struct sockaddr_ex *dst, const struct sockaddr_ex *src);
extern int addrex_get_ip(const struct sockaddr_ex *addr, be32_t *ip);
extern const char *addrex_get_name(const struct sockaddr_ex *addr, uint16_t *port);
extern int addrex_get_port(const struct sockaddr_ex *addr, be16_t *port);
extern int addrex_is_equal(const struct sockaddr_ex *addr1, const struct sockaddr_ex *addr2);
extern int addrex_to_string(const struct sockaddr_ex *addr, char *out, unsigned int out_len, bool with_port);

/* serialized address representation */
struct sockaddr_ex_serialized {
	uint16_t addr_len;	/* total length: this field itself is excluded */
	uint16_t port;
#define SOCKADDR_EX_F_IPV4	BIT(0)
#define SOCKADDR_EX_F_IPV6	BIT(1)
#define SOCKADDR_EX_F_HOST	BIT(2)
	uint8_t addr_flags;	/* types of entries */
	/*
	 * 3 entries at most, each following below format:
	 * uint8_t: type
	 * uint8_t: len
	 * uint8_t[]: data, network order
	 */
	uint8_t data[0];
} __attribute__((packed));

#define SOCKADDR_EX_SERIALIZED_MAX_LEN	(sizeof(struct sockaddr_ex_serialized) + 2 + 4 + 2 + 16 + 2 + MAX_DOMAIN_LEN)

extern unsigned int sockaddr_ex_ser_len(const struct sockaddr_ex *addr, uint8_t addr_mask);
extern int sockaddr_ex_serialize(const struct sockaddr_ex *in, uint8_t out[SOCKADDR_EX_SERIALIZED_MAX_LEN], unsigned int *out_len, uint8_t addr_mask);
extern int sockaddr_ex_deserialize(const uint8_t *in, unsigned int in_len, struct sockaddr_ex *out, unsigned int *parsed_len);

#endif
