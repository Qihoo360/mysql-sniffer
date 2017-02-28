/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "nids.h"
#include "scan.h"

static struct host **hashhost;
static int time0;
static int timenow;

static int
gettime()
{
  struct timeval tv;
  
  if (timenow)
    return timenow;
  gettimeofday(&tv, 0);
  timenow = (tv.tv_sec - time0) * 1000 + tv.tv_usec / 1000;

  return timenow;
}

void
scan_init(void)
{
  struct timeval tv;

  if (nids_params.scan_num_hosts > 0) {
    gettimeofday(&tv, 0);
    time0 = tv.tv_sec;
    hashhost = (struct host **) calloc(nids_params.scan_num_hosts, sizeof(struct host *));
    if (!hashhost)
      nids_params.no_mem("scan_init");
  }
}

void
scan_exit(void)
{
  if (hashhost) {
    free(hashhost);
    hashhost = NULL;
  }
}

static int
scan_hash(int addr)
{
  return ((addr % 65536) ^ (addr >> 16)) % (nids_params.scan_num_hosts);
}

void
detect_scan(struct ip * iph)
{
  int i;
  struct tcphdr *th;
  int hash;
  struct host *this_host;
  struct host *oldest;
  int mtime = 2147483647;

  if (nids_params.scan_num_hosts <= 0)
    return;
  
  th = (struct tcphdr *) (((char *) iph) + 4 * iph->ip_hl);
  hash = scan_hash(iph->ip_src.s_addr);
  this_host = hashhost[hash];
  oldest = 0;
  timenow = 0;

  for (i = 0; this_host && this_host->addr != iph->ip_src.s_addr; i++) {
    if (this_host->modtime < mtime) {
      mtime = this_host->modtime;
      oldest = this_host;
    }
    this_host = this_host->next;
  }
  if (!this_host) {
    if (i == 10)
      this_host = oldest;
    else {
      this_host = (struct host *) malloc(sizeof(struct host) + \
		    (nids_params.scan_num_ports + 1) * sizeof(struct scan));
      if (!this_host)
	nids_params.no_mem("detect_scan");
      this_host->packets = (struct scan *) (((char *) this_host) + sizeof(struct host));
      if (hashhost[hash]) {
	hashhost[hash]->prev = this_host;
	this_host->next = hashhost[hash];
      }
      else
	this_host->next = 0;
      this_host->prev = 0;
      hashhost[hash] = this_host;
    }
    this_host->addr = iph->ip_src.s_addr;
    this_host->modtime = gettime();
    this_host->n_packets = 0;
  }
  if (this_host->modtime - gettime() > nids_params.scan_delay)
    this_host->n_packets = 0;
  this_host->modtime = gettime();
  for (i = 0; i < this_host->n_packets; i++)
    if (this_host->packets[i].addr == iph->ip_dst.s_addr &&
	this_host->packets[i].port == ntohs(th->th_dport))
      return;
  this_host->packets[this_host->n_packets].addr = iph->ip_dst.s_addr;
  this_host->packets[this_host->n_packets].port = ntohs(th->th_dport);
  this_host->packets[this_host->n_packets].flags = *((unsigned char *) (th) + 13);
  this_host->n_packets++;
  if (this_host->n_packets > nids_params.scan_num_ports) {
    nids_params.syslog(NIDS_WARN_SCAN, 0, 0, this_host);
    this_host->n_packets = 0;
  }
}
