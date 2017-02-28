/*
   Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
   See the file COPYING for license details.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include "nids.h"

#define LOG_MAX 100
#define SZLACZEK "\n--------------------------------------------------\n"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

char *
adres (struct tuple4 addr)
{
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ",%i,", addr.source);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ",%i : ", addr.dest);
  return buf;
}

int logfd;
void
do_log (char *adres_txt, char *data, int ile)
{
  write (logfd, adres_txt, strlen (adres_txt));
  write (logfd, data, ile);
  write (logfd, SZLACZEK, strlen (SZLACZEK));
}

void
sniff_callback (struct tcp_stream *a_tcp, void **this_time_not_needed)
{
  int dest;
  if (a_tcp->nids_state == NIDS_JUST_EST)
    {
      dest = a_tcp->addr.dest;
      if (dest == 21 || dest == 23 || dest == 110 || dest == 143 || dest == 513)
	a_tcp->server.collect++;
      return;
    }
  if (a_tcp->nids_state != NIDS_DATA)
    {
      // seems the stream is closing, log as much as possible
      do_log (adres (a_tcp->addr), a_tcp->server.data,
	      a_tcp->server.count - a_tcp->server.offset);
      return;
    }
  if (a_tcp->server.count - a_tcp->server.offset < LOG_MAX)
    {
      // we haven't got enough data yet; keep all of it
      nids_discard (a_tcp, 0);
      return;
    }
    
  // enough data  
  do_log (adres (a_tcp->addr), a_tcp->server.data, LOG_MAX);

  // Now procedure sniff_callback doesn't want to see this stream anymore.
  // So, we decrease all the "collect" fields we have previously increased.
  // If there were other callbacks following a_tcp stream, they would still
  // receive data
  a_tcp->server.collect--;
}


int
main ()
{
  logfd = open ("./logfile", O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (logfd < 0)
    {
      perror ("opening ./logfile:");
      exit (1);
    }
  if (!nids_init ())
    {
      fprintf (stderr, "%s\n", nids_errbuf);
      exit (1);
    }
  nids_register_tcp (sniff_callback);
  nids_run ();
  return 0;
}
