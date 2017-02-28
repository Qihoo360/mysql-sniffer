/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/

/* 
This code attempts to detect attack against imapd (AUTHENTICATE hole) and
wuftpd (creation of deep directory). This code is to ilustrate use of libnids;
in order to improve readability, some simplifications were made, which enables
an attacker to bypass this code (note, the below routines should be improved, 
not libnids)
*/  

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "nids.h"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

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


/*
if we find a pattern AUTHENTICATE {an_int} in data stream sent to an imap 
server, where an_int >1024, it means an buffer overflow attempt. We kill the 
connection.
*/

#define PATTERN "AUTHENTICATE {"
#define PATLEN strlen(PATTERN)
void
detect_imap (struct tcp_stream *a_tcp)
{
  char numbuf[30];
  int i, j, datalen, numberlen;
  struct half_stream *hlf;
  if (a_tcp->nids_state == NIDS_JUST_EST)
    {
      if (a_tcp->addr.dest == 143)
	{
	  a_tcp->server.collect++;
	  return;
	}
      else
	return;
    }
  if (a_tcp->nids_state != NIDS_DATA)
    return;
  hlf = &a_tcp->server;
  datalen = hlf->count - hlf->offset;
  if (datalen < PATLEN)
    {
      // we have too small amount of data to work on. Keep all data in buffer.
      nids_discard (a_tcp, 0);
      return;
    }
  for (i = 0; i <= datalen - PATLEN; i++)
    if (!memcmp (PATTERN, hlf->data + i, PATLEN)) //searching for a pattern
      break;
  if (i > datalen - PATLEN)
    {
      // retain PATLEN bytes in buffer
      nids_discard (a_tcp, datalen - PATLEN);
      return;
    }
  for (j = i + PATLEN; j < datalen; j++) // searching for a closing '}'
    if (*(hlf->data + j) == '}')
      break;
  if (j > datalen)
    {
      if (datalen > 20)
	{
	  //number too long, perhaps we should log it, too
	}
      return;
    }
  numberlen = j - i - PATLEN;
  memcpy (numbuf, hlf->data + i + PATLEN, numberlen); //numbuf contains
                                                      // AUTH argument
  numbuf[numberlen] = 0;
  if (atoi (numbuf) > 1024)
    {
      // notify admin
      syslog(nids_params.syslog_level,
      "Imapd exploit attempt, connection %s\n",adres(a_tcp->addr));
      // kill the connection
      nids_killtcp (a_tcp);
    }
  nids_discard (a_tcp, datalen - PATLEN);
  return;
}

// auxiliary structure, needed to keep current dir of ftpd daemon 
struct supp
{
  char *currdir;
  int last_newline;
};

// the below function adds "elem" string to "path" string, taking care of
// ".." and multiple '/'. If the resulting path is longer than 768, 
// return value is 1, otherwise 0 
int 
add_to_path (char *path, char *elem, int len)
{
int plen;
char * ptr;
  if (len > 768)
    return 1;
  if (len == 2 && elem[0] == '.' && elem[1] == '.')
    {
      ptr = rindex (path, '/');
      if (ptr != path)
	*ptr = 0;
    }
  else if (len > 0)
    {
      plen = strlen (path);
      if (plen + len + 1 > 768)
	return 1;
	if (plen==1)
	{
	strncpy(path+1,elem,len);
	path[1+len]=0;
	}
	else
	{
      path[plen] = '/';
      strncpy (path + plen + 1, elem, len);
      path[plen + 1 + len] = 0;
	}
    }
return 0;
}

void
do_detect_ftp (struct tcp_stream *a_tcp, struct supp **param_ptr)
{
  struct supp *p = *param_ptr;
  int index = p->last_newline + 1;
  char *buf = a_tcp->server.data;
  int offset = a_tcp->server.offset;
  int n_bytes = a_tcp->server.count - offset;
  int path_index, pi2, index2, remcaret;
  for (;;)
    {
      index2 = index;
      while (index2 - offset < n_bytes && buf[index2 - offset] != '\n')
	index2++;
      if (index2 - offset >= n_bytes)
	break;
      if (!strncasecmp (buf + index - offset, "cwd ", 4))
	{
	  path_index = index + 4;
	  if (buf[path_index - offset] == '/')
	    {
	      strcpy (p->currdir, "/");
	      path_index++;
	    }
	  for (;;)
	    {
	      pi2 = path_index;
	      while (buf[pi2 - offset] != '\n' && buf[pi2 - offset] != '/')
		pi2++;
		if (buf[pi2-offset]=='\n' && buf[pi2-offset-1]=='\r')
		remcaret=1;
		else remcaret=0;
	      if (add_to_path (p->currdir, buf + path_index-offset, pi2 - path_index-remcaret))
		{
		  // notify admin
		  syslog(nids_params.syslog_level,
		  "Ftpd exploit attempt, connection %s\n",adres(a_tcp->addr)); 
		  nids_killtcp (a_tcp);
		  return;
		}
	      if (buf[pi2 - offset] == '\n')
		break;
	      path_index = pi2 + 1;
	    }
	}
      index = index2 + 1;
    }
  p->last_newline = index - 1;
  nids_discard (a_tcp, index - offset);
}

void
detect_ftpd (struct tcp_stream *a_tcp, struct supp **param)
{
  if (a_tcp->nids_state == NIDS_JUST_EST)
    {
      if (a_tcp->addr.dest == 21)
	{
          struct supp *one_for_conn;
	  a_tcp->server.collect++;
	  one_for_conn = (struct supp *) malloc (sizeof (struct supp));
	  one_for_conn->currdir = malloc (1024);
	  strcpy (one_for_conn->currdir, "/");
	  one_for_conn->last_newline = 0;
	  *param=one_for_conn;
	}
      return;
    }
  if (a_tcp->nids_state != NIDS_DATA)
    {
      free ((*param)->currdir);
      free (*param);
      return;
    }
  do_detect_ftp (a_tcp, param);
}

int
main ()
{
  if (!nids_init ())
  {
  	fprintf(stderr,"%s\n",nids_errbuf);
  	exit(1);
  }
  nids_register_tcp (detect_imap);
  nids_register_tcp (detect_ftpd);
  nids_run ();
  return 0;
}
