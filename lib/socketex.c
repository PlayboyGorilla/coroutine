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
	if (strlen(name) >= MAX_DOMAIN_LEN) {
		return ERR_OVERFLOW;
	}

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

int addrex_get_ip(const struct sockaddr_ex *addr, be32_t *ip)
{
	if (!(addr->flags & ADDREX_F_IP)) {
		return ERR_NOT_FOUND;
	}
	*ip = addr->ipaddr.sin_addr.s_addr;
	return ERR_OK;
}

const char *addrex_get_name(const struct sockaddr_ex *addr, uint16_t *port)
{
	if((addr->flags & ADDREX_F_NAME) == 0) {
		return NULL;
	}

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
	if(addr1->flags != addr2->flags) {
		return 0;
	}

	if(addr1->flags & ADDREX_F_IP) {
		if(addr1->ipaddr.sin_addr.s_addr != addr2->ipaddr.sin_addr.s_addr) {
			return 0;
		}
		if(addr1->ipaddr.sin_port != addr2->ipaddr.sin_port) {
			return 0;
		}
	}
	
	if(addr1->flags & ADDREX_F_NAME) {
		if(strcmp(addr1->naddr.name, addr2->naddr.name) != 0) {
			return 0;
		}
		if(addr1->naddr.port != addr2->naddr.port) {
			return 0;
		}
	}

	return 1;
}

int addrex_to_string(const struct sockaddr_ex * addr, char * out, unsigned int out_len, bool with_port)
{
	if (addr->flags & ADDREX_F_NAME) {
		if (with_port) {
			return snprintf(out, out_len, "%s:%u", addr->naddr.name, addr->naddr.port);
		} else {
			return snprintf(out, out_len, "%s", addr->naddr.name);
		}
	} else if (addr->flags & ADDREX_F_IP) {
		if (with_port) {
			return snprintf(out, out_len, "%s:%u", inet_ntoa(addr->ipaddr.sin_addr), sys_betoh16(addr->ipaddr.sin_port));
		} else {
			return snprintf(out, out_len, "%s", inet_ntoa(addr->ipaddr.sin_addr));
		}
	}

	return 0;
}

/* serialization/deserialization */
unsigned int sockaddr_ex_ser_len(const struct sockaddr_ex *addr, uint8_t addr_mask)
{
	/* compute the number of bytes needed to contain the output */
	unsigned int buf_len = sizeof(struct sockaddr_ex_serialized);

	if ((addr->flags & ADDREX_F_NAME) && (addr_mask & ADDREX_F_NAME)) {
		uint8_t host_len;
		host_len = strlen(addr->naddr.name);
		buf_len += 2 + host_len + 1;
	}
	if ((addr->flags & ADDREX_F_IP) && (addr_mask & ADDREX_F_IP)) {
		buf_len += 2 + sizeof(be32_t);
	}
	if ((addr->flags & ADDREX_F_IPV6) && (addr_mask & ADDREX_F_IPV6)) {
		buf_len += 2 + 16;	/* TODO: a macro for IPv6 address length */
	}
	return buf_len;
}

int sockaddr_ex_serialize(const struct sockaddr_ex *in, uint8_t out[SOCKADDR_EX_SERIALIZED_MAX_LEN], unsigned int *out_len,
	uint8_t addr_mask)
{
	uint16_t total_len = sizeof(struct sockaddr_ex_serialized) - sizeof(uint16_t);
	uint8_t addr_flags = 0;
	struct sockaddr_ex_serialized *out_buf = (struct sockaddr_ex_serialized *)out;
	uint16_t offset = 0;
	be16_t total_len_be;
	be16_t port;

	if ((in->flags & ADDREX_F_IP) && (addr_mask & SOCKADDR_EX_F_IPV4)) {
		addr_flags |= SOCKADDR_EX_F_IPV4;
	}
	if ((in->flags & ADDREX_F_NAME) && (addr_mask & SOCKADDR_EX_F_HOST)) {
		addr_flags |= SOCKADDR_EX_F_HOST;
	}
	if (addr_flags == 0) {
		return ERR_NOTSUPPORTED;
	}

	if (addr_flags & SOCKADDR_EX_F_IPV4) {
		be32_t ip;
		addrex_get_ip(in, &ip);

		out_buf->data[offset] = SOCKADDR_EX_F_IPV4;
		out_buf->data[offset + 1] = sizeof(be32_t);
		memcpy(&out_buf->data[offset + 2], &ip, sizeof(ip));
		total_len += (2 + sizeof(be32_t));
		offset += (2 + sizeof(be32_t));
	}
	/* FIXME: IPv6 support */
	if (addr_flags & SOCKADDR_EX_F_HOST) {
		const char *host;
		uint16_t port;
		uint8_t host_len;
		host = addrex_get_name(in, &port);
		host_len = (uint8_t)strlen(host);

		out_buf->data[offset] = SOCKADDR_EX_F_HOST;
		out_buf->data[offset + 1] = host_len;
		memcpy(&out_buf->data[offset + 2], host, host_len);
		out_buf->data[offset + 2 + host_len] = '\0';
		total_len += (2 + host_len + 1);
	}

	addrex_get_port(in, &port);
	total_len_be = sys_htobe16(total_len);
	memcpy(&out_buf->addr_len, &total_len_be, sizeof(out_buf->addr_len));
	memcpy(&out_buf->port, &port, sizeof(out_buf->port));
	out_buf->addr_flags = addr_flags;

	*out_len = (total_len + sizeof(uint16_t));
	return ERR_OK;
}

int sockaddr_ex_deserialize(const uint8_t *in, unsigned int in_len, struct sockaddr_ex *out, unsigned int *parsed_len)
{
	const struct sockaddr_ex_serialized *in_buf = (struct sockaddr_ex_serialized *)in;
	uint16_t addr_len;
	be16_t port;
	uint8_t addr_flags;
	uint16_t offset = 0;
	be32_t ip;
	bool has_ip = false;
	const uint8_t *host = NULL;
	uint8_t host_len = 0;

	if (in_len <= sizeof(struct sockaddr_ex_serialized)) {
		goto err_out;
	}

	memcpy(&addr_len, &in_buf->addr_len, sizeof(addr_len));
	memcpy(&port, &in_buf->port, sizeof(port));
	addr_flags = in_buf->addr_flags;
	addr_len = sys_betoh16(addr_len);

	if (!addr_flags) {
		goto err_out;
	}

	while (sizeof(*in_buf) + offset < in_len && addr_flags) {
		switch (in_buf->data[offset]) {
		case SOCKADDR_EX_F_IPV4:
			if (sizeof(*in_buf) + offset + 2 + sizeof(be32_t) > in_len) {
				goto err_out;
			}
			if (in_buf->data[offset + 1] != sizeof(be32_t)) {
				goto err_out;
			}
			if (!(addr_flags & SOCKADDR_EX_F_IPV4)) {
				goto err_out;
			}
			memcpy(&ip, &in_buf->data[offset + 2], sizeof(ip));
			has_ip = true;
			addr_flags &= ~SOCKADDR_EX_F_IPV4;
			offset += 2 + sizeof(be32_t);
			break;
		case SOCKADDR_EX_F_IPV6:
			/* FIXME: IPv6 support */
			goto err_out;
		case SOCKADDR_EX_F_HOST:
			if (sizeof(*in_buf) + offset + 2 > in_len) {
				goto err_out;
			}
			if (!(addr_flags & SOCKADDR_EX_F_HOST)) {
				goto err_out;
			}
			host_len = in_buf->data[offset + 1];
			if (sizeof(*in_buf) + offset + 2 + host_len + 1 > in_len) {
				goto err_out;
			}
			if (in_buf->data[offset + 2 + host_len] != '\0') {
				goto err_out;
			}
			addr_flags &= ~SOCKADDR_EX_F_HOST;
			host = &in_buf->data[offset + 2];
			offset += 2 + host_len + 1;
			break;
		default:
			goto err_out;
		}
	}

	addrex_init(out);

	if (has_ip) {
		addrex_set_ip(out, ip, port);
	}
	if (host) {
		addrex_set_name(out, (const char *)host, sys_betoh16(port));
	}

	*parsed_len = sizeof(*in_buf) + offset;
	return ERR_OK;
err_out:
	*parsed_len = 0;
	return ERR_INVAL;
}
