/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "nids.h"

#include <config.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <alloca.h>
#include <pcap.h>
#include <errno.h>
#include <config.h>
#if (HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <stdlib.h>
#include "../src/checksum.h"
#include "../src/ip_fragment.h"
#include "../src/scan.h"
#include "../src/tcp.h"
#include "../src/util.h"
#include "../src/nids.h"
#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

static void nids_syslog_hook(int type, int errnum, struct ip *iph, void *data) {
    char saddr[20], daddr[20];
    char buf[1024];
    struct host *this_host;
    unsigned char flagsand = 255, flagsor = 0;
    int i;

    switch (type) {

    case NIDS_WARN_IP:
	if (errnum != NIDS_WARN_IP_HDR) {
	    strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	    strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	    printf(
		   "%s, packet (apparently) from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	} else
	    printf( "%s\n",
		   nids_warnings[errnum]);
	break;

    case NIDS_WARN_TCP:
	strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	if (errnum != NIDS_WARN_TCP_HDR)
	    printf(
		   "%s,from %s:%hu to  %s:%hu\n", nids_warnings[errnum],
		   saddr, ntohs(((struct tcphdr *) data)->th_sport), daddr,
		   ntohs(((struct tcphdr *) data)->th_dport));
	else
	    printf( "%s,from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	break;

    case NIDS_WARN_SCAN:
	this_host = (struct host *) data;
	sprintf(buf, "Scan from %s. Scanned ports: ",
		int_ntoa(this_host->addr));
	for (i = 0; i < this_host->n_packets; i++) {
	    strcat(buf, int_ntoa(this_host->packets[i].addr));
	    sprintf(buf + strlen(buf), ":%hu,",
		    this_host->packets[i].port);
	    flagsand &= this_host->packets[i].flags;
	    flagsor |= this_host->packets[i].flags;
	}
	if (flagsand == flagsor) {
	    i = flagsand;
	    switch (flagsand) {
	    case 2:
		strcat(buf, "scan type: SYN");
		break;
	    case 0:
		strcat(buf, "scan type: NULL");
		break;
	    case 1:
		strcat(buf, "scan type: FIN");
		break;
	    default:
		sprintf(buf + strlen(buf), "flags=0x%x", i);
	    }
	} else
	    strcat(buf, "various flags");
	printf( "%s", buf);
	break;

    default:
	printf( "Unknown warning number ?\n");
    }
}


// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
char *
adres (struct tuple4 addr)
{
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ",%i,", addr.source);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ",%i", addr.dest);
  return buf;
}

void
tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{
  char buf[1024];
  strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
  if (a_tcp->nids_state == NIDS_JUST_EST)
    {
    // connection described by a_tcp is established
    // here we decide, if we wish to follow this stream
    // sample condition: if (a_tcp->addr.dest!=23) return;
    // in this simple app we follow each stream, so..
      a_tcp->client.collect++; // we want data received by a client
      a_tcp->server.collect++; // and by a server, too
      a_tcp->server.collect_urg++; // we want urgent data received by a
                                   // server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
      a_tcp->client.collect_urg++; // if we don't increase this value,
                                   // we won't be notified of urgent data
                                   // arrival
#endif
      fprintf (stderr, "%s established\n", buf);
      return;
    }
  if (a_tcp->nids_state == NIDS_CLOSE)
    {
      // connection has been closed normally
      fprintf (stderr, "%s closing\n", buf);
      return;
    }
  if (a_tcp->nids_state == NIDS_RESET)
    {
      // connection has been closed by RST
      fprintf (stderr, "%s reset\n", buf);
      return;
    }

  if (a_tcp->nids_state == NIDS_DATA)
    {
      // new data has arrived; gotta determine in what direction
      // and if it's urgent or not

      struct half_stream *hlf;

      if (a_tcp->server.count_new_urg)
      {
        // new byte of urgent data has arrived 
        strcat(buf,"(urgent->)");
        buf[strlen(buf)+1]=0;
        buf[strlen(buf)]=a_tcp->server.urgdata;
        write(1,buf,strlen(buf));
        return;
      }
      // We don't have to check if urgent data to client has arrived,
      // because we haven't increased a_tcp->client.collect_urg variable.
      // So, we have some normal data to take care of.
      if (a_tcp->client.count_new)
	{
          // new data for client
	  hlf = &a_tcp->client; // from now on, we will deal with hlf var,
                                // which will point to client side of conn
	  strcat (buf, "(<-)"); // symbolic direction of data
	}
      else
	{
	  hlf = &a_tcp->server; // analogical
	  strcat (buf, "(->)");
	}
    fprintf(stderr,"%s",buf); // we print the connection parameters
                              // (saddr, daddr, sport, dport) accompanied
                              // by data flow direction (-> or <-)

   write(2,hlf->data,hlf->count_new); // we print the newly arrived data
      
    }
  return ;
}

int 
main ()
{
    struct nids_chksum_ctl chksum_ctl;
    chksum_ctl.netaddr = 0;
    chksum_ctl.mask = 0;
    chksum_ctl.action = NIDS_DONT_CHKSUM;
    chksum_ctl.reserved = 0;
    nids_register_chksum_ctl(&chksum_ctl, 1);
    //nids_params.syslog = nids_syslog_hook;
  // here we can alter libnids params, for instance:
  // nids_params.n_hosts=256;
  if (!nids_init ())
  {
  	fprintf(stderr,"%s\n",nids_errbuf);
  	exit(1);
  }
  nids_register_tcp (tcp_callback);
  nids_run ();
  return 0;
}

