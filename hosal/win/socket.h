#ifndef __HOSAL_SOCKET_WIN__
#define __HOSAL_SOCKET_WIN__

/* EXPORT socket_class */
extern struct socket_class sys_tcp_socket;
extern struct socket_class sys_udp_socket;
extern struct socket_class sys_icmp_socket;
#if 0
extern struct socket_class sys_ssl_socket;
#endif

#endif
