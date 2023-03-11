#ifndef __IPV4_IP_H__
#define __IPV4_IP_H__

#include "lib/types.h"
#include "lib/errno.h" 

#define IP_V4		4
#define IP_V6		6

#define IP_PROTO_ICMP		1
#define IP_PROTO_IGMP		2
#define IP_PROTO_TCP		6
#define IP_PROTO_UDP		17
#define IP_PROTO_UDPLITE	136
#define IP_PROTO_RAW		255

#define IP_MAX_LEN	(64 * 1024)

#define IP_HLEN 20
struct ip_hdr {
	/* version / header length */
	uint8_t _v_hl;
	/* type of service */
	uint8_t _tos;
	/* total length */
	be16_t _len;
	/* identification */
	be16_t _id;
	/* fragment offset field */
	be16_t _offset;
#define IP_RF 0x8000U        /* reserved fragment flag */
#define IP_DF 0x4000U        /* dont fragment flag */
#define IP_MF 0x2000U        /* more fragments flag */
#define IP_OFFMASK 0x1fffU   /* mask for fragmenting bits */
	/* time to live */
	uint8_t _ttl;
	/* protocol*/
	uint8_t _proto;
	/* checksum */
	be16_t _chksum;
	/* source and destination IP addresses */
	be32_t src;
	be32_t dest; 
}__attribute__((packed));

#define IPH_V(hdr)  ((hdr)->_v_hl >> 4)
#define IPH_HL(hdr) ((hdr)->_v_hl & 0x0f)
#define IPH_TOS(hdr) ((hdr)->_tos)
#define IPH_LEN(hdr) ((hdr)->_len)
#define IPH_ID(hdr) ((hdr)->_id)
#define IPH_OFFSET(hdr) ((hdr)->_offset)
#define IPH_TTL(hdr) ((hdr)->_ttl)
#define IPH_PROTO(hdr) ((hdr)->_proto)
#define IPH_CHKSUM(hdr) ((hdr)->_chksum)

#define IPH_VHL_SET(hdr, v, hl) (hdr)->_v_hl = (((v) << 4) | (hl))
#define IPH_TOS_SET(hdr, tos) (hdr)->_tos = (tos)
#define IPH_LEN_SET(hdr, len) (hdr)->_len = (len)
#define IPH_ID_SET(hdr, id) (hdr)->_id = (id)
#define IPH_OFFSET_SET(hdr, off) (hdr)->_offset = (off)
#define IPH_TTL_SET(hdr, ttl) (hdr)->_ttl = (uint8_t)(ttl)
#define IPH_PROTO_SET(hdr, proto) (hdr)->_proto = (uint8_t)(proto)
#define IPH_CHKSUM_SET(hdr, chksum) (hdr)->_chksum = (chksum)

struct tor_buffer;
struct netif;

int ip_input(struct tor_buffer *, struct netif *inp);
int ip_output(struct tor_buffer *, uint32_t src, uint32_t dest,
	uint8_t ttl, uint8_t tos, uint8_t proto,
	int free);

#endif /* __IPV4_IP_H__ */
