/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#include <config.h>
#include <sys/types.h>
#include <stdlib.h>
#include "tcp.h"
#include "util.h"
#include "nids.h"
#if LIBNET_VER == 0
#include <libnet.h>

static int libnetsock = 0;

void nids_killtcp_seq(struct tcp_stream *a_tcp, int seqoff)
{
    char buf[IP_H + TCP_H];

    if (libnetsock == 0)
	return;

    libnet_build_ip(TCP_H, 0, 12345, 0, 64, IPPROTO_TCP, a_tcp->addr.saddr,
		    a_tcp->addr.daddr, 0, 0, buf);
    libnet_build_tcp(a_tcp->addr.source, a_tcp->addr.dest,
	a_tcp->client.first_data_seq + 
		a_tcp->server.count + a_tcp->server.urg_count +
		(seqoff?(a_tcp->server.window/2):0), 
		     0, 0x4, 32000, 0, 0, 0, buf + IP_H);
    libnet_do_checksum(buf, IPPROTO_TCP, TCP_H);
    libnet_write_ip(libnetsock, buf, TCP_H + IP_H);

    libnet_build_ip(TCP_H, 0, 12345, 0, 64, IPPROTO_TCP, a_tcp->addr.daddr,
		    a_tcp->addr.saddr, 0, 0, buf);
    libnet_build_tcp(a_tcp->addr.dest, a_tcp->addr.source,
        a_tcp->server.first_data_seq +
                a_tcp->client.count + a_tcp->client.urg_count +
                (seqoff?(a_tcp->client.window/2):0),

                     0, 0x4, 32000, 0, 0, 0, buf + IP_H);
    libnet_do_checksum(buf, IPPROTO_TCP, TCP_H);
    libnet_write_ip(libnetsock, buf, TCP_H + IP_H);
}
void nids_killtcp(struct tcp_stream *a_tcp)
{
    nids_killtcp_seq(a_tcp, 0);
    nids_killtcp_seq(a_tcp, 1);
}    
int raw_init()
{
    libnetsock = libnet_open_raw_sock(IPPROTO_RAW);
    if (libnetsock <= 0)
	return 0;
    else
	return 1;
}
#elif LIBNET_VER == 1
#include <libnet.h>
static libnet_ptag_t tcp_tag = LIBNET_PTAG_INITIALIZER,
    ip_tag = LIBNET_PTAG_INITIALIZER;
static libnet_t *l = 0;
int raw_init()
{
    char errbuf[1024];
    l = libnet_init(LIBNET_RAW4,	/* injection type */
		    NULL,	/* network interface */
		    errbuf);	/* error buffer */

    if (!l) {
	printf("%s\n", errbuf);
	return 0;
    } else
	return 1;
}

void nids_killtcp_seq(struct tcp_stream *a_tcp, int seqoff)
{
    if (!l)
	return;
    tcp_tag = libnet_build_tcp(a_tcp->addr.source, a_tcp->addr.dest,
	a_tcp->client.first_data_seq + 
		a_tcp->server.count + a_tcp->server.urg_count +
		(seqoff?(a_tcp->server.window/2):0), 
	0, 0x4, 32000, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp_tag);
    ip_tag =
	libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H, 0, 12345, 0, 64,
			  IPPROTO_TCP, 0, a_tcp->addr.saddr,
			  a_tcp->addr.daddr, 0, 0, l, ip_tag);
    libnet_write(l);
    tcp_tag = libnet_build_tcp(a_tcp->addr.dest, a_tcp->addr.source,
        a_tcp->server.first_data_seq +
                a_tcp->client.count + a_tcp->client.urg_count +
                (seqoff?(a_tcp->client.window/2):0),
0, 0x4, 32000, 0,
			       0, LIBNET_TCP_H, NULL, 0, l, tcp_tag);
    ip_tag =
	libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H, 0, 12345, 0, 64,
			  IPPROTO_TCP, 0, a_tcp->addr.daddr,
			  a_tcp->addr.saddr, 0, 0, l, ip_tag);
    libnet_write(l);
}
void nids_killtcp(struct tcp_stream *a_tcp)
{
    nids_killtcp_seq(a_tcp, 0);
    nids_killtcp_seq(a_tcp, 1);
}   
#elif LIBNET_VER == -1
static int initialized = 0;
int raw_init()
{
    initialized = 1;
    return 1;
}

void nids_killtcp(struct tcp_stream *a_tcp)
{
    (void)a_tcp;
    if (initialized)
	abort();
}
#else
#error Something wrong with LIBNET_VER
#endif
