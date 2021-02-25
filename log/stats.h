#ifndef __LOG_STATS_H__
#define __LOG_STATS_H__

#include <stdint.h>

struct log_stats {
	/* hosal */
	uint32_t	sock_alloc;
	uint32_t	sock_tcp_alloc;
	uint32_t	sock_udp_alloc;
	uint32_t	sock_icmp_alloc;
	uint32_t	sock_ssl_alloc;
	uint32_t	sock_free;
	uint32_t	sock_tcp_free;
	uint32_t	sock_udp_free;
	uint32_t	sock_icmp_free;
	uint32_t	sock_ssl_free;
	uint32_t	sock_user_free;
	uint32_t	sock_epoll_free;
	uint32_t	sock_tcp_direct_success;
	uint32_t	sock_tcp_direct_fail;
	uint32_t	epollin;
	uint32_t	epollpri;
	uint32_t	epollout;
	uint32_t	epollrdnorm;
	uint32_t	epollrdband;
	uint32_t	epollwrnorm;
	uint32_t	epollwrband;
	uint32_t	epollmsg;
	uint32_t	epollerr;
	uint32_t	epollhup;
	uint32_t	epollrdhup;
	uint32_t	epolloneshot;
	uint32_t	epollet;
	uint32_t	sock_kqueue_free;
	uint32_t	event_read;
	uint32_t	event_write;
	uint32_t	event_eof;
	uint32_t	event_error;
};

extern struct log_stats		runtime_stats;

#define STATS_INC(member)		(++runtime_stats.member)
#define STATS_DEC(member)		(--runtime_stats.member)
#define STATS_ADD(member, val)		(runtime_stats.member += (val))
#define STATS_DEL(member, val)		(runtime_stats.member -= (val))	

#endif
