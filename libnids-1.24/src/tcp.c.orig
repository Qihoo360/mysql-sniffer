/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
 */

#include <config.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include "checksum.h"
#include "scan.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"
#include "hash.h"

#if ! HAVE_TCP_STATES
enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING			/* now a valid state */
};

#endif

#define FIN_SENT 120
#define FIN_CONFIRMED 121
#define COLLECT_cc 1
#define COLLECT_sc 2
#define COLLECT_ccu 4
#define COLLECT_scu 8

#define EXP_SEQ (snd->first_data_seq + rcv->count + rcv->urg_count)

extern struct proc_node *tcp_procs;

static struct tcp_stream **tcp_stream_table;
static struct tcp_stream *streams_pool;
static int tcp_num = 0;
static int tcp_stream_table_size;
static int max_stream;
static struct tcp_stream *tcp_latest = 0, *tcp_oldest = 0;
static struct tcp_stream *free_streams;
static struct ip *ugly_iphdr;
struct tcp_timeout *nids_tcp_timeouts = 0;

static void purge_queue(struct half_stream * h)
{
  struct skbuff *tmp, *p = h->list;

  while (p) {
    free(p->data);
    tmp = p->next;
    free(p);
    p = tmp;
  }
  h->list = h->listtail = 0;
  h->rmem_alloc = 0;
}

static void
add_tcp_closing_timeout(struct tcp_stream * a_tcp)
{
  struct tcp_timeout *to;
  struct tcp_timeout *newto;

  if (!nids_params.tcp_workarounds)
    return;
  newto = malloc(sizeof (struct tcp_timeout));
  if (!newto)
      nids_params.no_mem("add_tcp_closing_timeout");
  newto->a_tcp = a_tcp;
  newto->timeout.tv_sec = nids_last_pcap_header->ts.tv_sec + 10;
  newto->prev = 0;
  for (newto->next = to = nids_tcp_timeouts; to; newto->next = to = to->next) {
    if (to->a_tcp == a_tcp) {
      free(newto);
      return;
    }
    if (to->timeout.tv_sec > newto->timeout.tv_sec)
      break;
    newto->prev = to;
  }
  if (!newto->prev)
    nids_tcp_timeouts = newto;
  else
    newto->prev->next = newto;
  if (newto->next)
    newto->next->prev = newto;
}

static void
del_tcp_closing_timeout(struct tcp_stream * a_tcp)
{
  struct tcp_timeout *to;

  if (!nids_params.tcp_workarounds)
    return;
  for (to = nids_tcp_timeouts; to; to = to->next)
    if (to->a_tcp == a_tcp)
      break;
  if (!to)
    return;
  if (!to->prev)
    nids_tcp_timeouts = to->next;
  else
    to->prev->next = to->next;
  if (to->next)
    to->next->prev = to->prev;
  free(to);
}

void
nids_free_tcp_stream(struct tcp_stream * a_tcp)
{
  int hash_index = a_tcp->hash_index;
  struct lurker_node *i, *j;

  del_tcp_closing_timeout(a_tcp);
  purge_queue(&a_tcp->server);
  purge_queue(&a_tcp->client);
   
  if (a_tcp->next_node)
    a_tcp->next_node->prev_node = a_tcp->prev_node;
  if (a_tcp->prev_node)
    a_tcp->prev_node->next_node = a_tcp->next_node;
  else
    tcp_stream_table[hash_index] = a_tcp->next_node;
  if (a_tcp->client.data)
    free(a_tcp->client.data);
  if (a_tcp->server.data)
    free(a_tcp->server.data);
  if (a_tcp->next_time)
    a_tcp->next_time->prev_time = a_tcp->prev_time;
  if (a_tcp->prev_time)
    a_tcp->prev_time->next_time = a_tcp->next_time;
  if (a_tcp == tcp_oldest)
    tcp_oldest = a_tcp->prev_time;
  if (a_tcp == tcp_latest)
    tcp_latest = a_tcp->next_time;
  
  i = a_tcp->listeners;
  
  while (i) {
    j = i->next;
    free(i);
    i = j;
  }
  a_tcp->next_free = free_streams;
  free_streams = a_tcp;
  tcp_num--;
}

void
tcp_check_timeouts(struct timeval *now)
{
  struct tcp_timeout *to;
  struct tcp_timeout *next;
  struct lurker_node *i;

  for (to = nids_tcp_timeouts; to; to = next) {
    if (now->tv_sec < to->timeout.tv_sec)
      return;
    to->a_tcp->nids_state = NIDS_TIMED_OUT;
    for (i = to->a_tcp->listeners; i; i = i->next)
      (i->item) (to->a_tcp, &i->data);
    next = to->next;
    nids_free_tcp_stream(to->a_tcp);
  }
}

static int
mk_hash_index(struct tuple4 addr)
{
  int hash=mkhash(addr.saddr, addr.source, addr.daddr, addr.dest);
  return hash % tcp_stream_table_size;
}

static int get_ts(struct tcphdr * this_tcphdr, unsigned int * ts)
{
  int len = 4 * this_tcphdr->th_off;
  unsigned int tmp_ts;
  unsigned char * options = (unsigned char*)(this_tcphdr + 1);
  int ind = 0, ret = 0;
  while (ind <=  len - (int)sizeof (struct tcphdr) - 10 )
  	switch (options[ind]) {
		case 0: /* TCPOPT_EOL */
			return ret;
		case 1: /* TCPOPT_NOP */
			ind++;
			continue;	
  		case 8: /* TCPOPT_TIMESTAMP */
	  		memcpy((char*)&tmp_ts, options + ind + 2, 4);
  			*ts=ntohl(tmp_ts);
			ret = 1;
			/* no break, intentionally */
		default:	
			if (options[ind+1] < 2 ) /* "silly option" */
				return ret;
			ind += options[ind+1];
	}			
			
  return ret;
}  		

static int get_wscale(struct tcphdr * this_tcphdr, unsigned int * ws)
{
  int len = 4 * this_tcphdr->th_off;
  unsigned int tmp_ws;
  unsigned char * options = (unsigned char*)(this_tcphdr + 1);
  int ind = 0, ret = 0;
  *ws=1;
  while (ind <=  len - (int)sizeof (struct tcphdr) - 3 )
  	switch (options[ind]) {
		case 0: /* TCPOPT_EOL */
			return ret;
		case 1: /* TCPOPT_NOP */
			ind++;
			continue;	
  		case 3: /* TCPOPT_WSCALE */
  			tmp_ws=options[ind+2];
  			if (tmp_ws>14) 
  				tmp_ws=14;
			*ws=1<<tmp_ws;
			ret = 1;
			/* no break, intentionally */
		default:	
			if (options[ind+1] < 2 ) /* "silly option" */
				return ret;
			ind += options[ind+1];
	}			
			
  return ret;
}  		

    


static void
add_new_tcp(struct tcphdr * this_tcphdr, struct ip * this_iphdr)
{
  struct tcp_stream *tolink;
  struct tcp_stream *a_tcp;
  int hash_index;
  struct tuple4 addr;
  
  addr.source = ntohs(this_tcphdr->th_sport);
  addr.dest = ntohs(this_tcphdr->th_dport);
  addr.saddr = this_iphdr->ip_src.s_addr;
  addr.daddr = this_iphdr->ip_dst.s_addr;
  hash_index = mk_hash_index(addr);
  
  if (tcp_num > max_stream) {
    struct lurker_node *i;
    int orig_client_state=tcp_oldest->client.state;
    tcp_oldest->nids_state = NIDS_TIMED_OUT;
    for (i = tcp_oldest->listeners; i; i = i->next)
      (i->item) (tcp_oldest, &i->data);
    nids_free_tcp_stream(tcp_oldest);
    if (orig_client_state!=TCP_SYN_SENT)
      nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_TOOMUCH, ugly_iphdr, this_tcphdr);
  }
  a_tcp = free_streams;
  if (!a_tcp) {
    fprintf(stderr, "gdb me ...\n");
    pause();
  }
  free_streams = a_tcp->next_free;
  
  tcp_num++;
  tolink = tcp_stream_table[hash_index];
  memset(a_tcp, 0, sizeof(struct tcp_stream));
  a_tcp->hash_index = hash_index;
  a_tcp->addr = addr;
  a_tcp->client.state = TCP_SYN_SENT;
  a_tcp->client.seq = ntohl(this_tcphdr->th_seq) + 1;
  a_tcp->client.first_data_seq = a_tcp->client.seq;
  a_tcp->client.window = ntohs(this_tcphdr->th_win);
  a_tcp->client.ts_on = get_ts(this_tcphdr, &a_tcp->client.curr_ts);
  a_tcp->client.wscale_on = get_wscale(this_tcphdr, &a_tcp->client.wscale);
  a_tcp->server.state = TCP_CLOSE;
  a_tcp->next_node = tolink;
  a_tcp->prev_node = 0;
  if (tolink)
    tolink->prev_node = a_tcp;
  tcp_stream_table[hash_index] = a_tcp;
  a_tcp->next_time = tcp_latest;
  a_tcp->prev_time = 0;
  if (!tcp_oldest)
    tcp_oldest = a_tcp;
  if (tcp_latest)
    tcp_latest->prev_time = a_tcp;
  tcp_latest = a_tcp;
}

static void
add2buf(struct half_stream * rcv, char *data, int datalen)
{
  int toalloc;
  
  if (datalen + rcv->count - rcv->offset > rcv->bufsize) {
    if (!rcv->data) {
      if (datalen < 2048)
	toalloc = 4096;
      else
	toalloc = datalen * 2;
      rcv->data = malloc(toalloc);
      rcv->bufsize = toalloc;
    }
    else {
      if (datalen < rcv->bufsize)
      	toalloc = 2 * rcv->bufsize;
      else	
      	toalloc = rcv->bufsize + 2*datalen;
      rcv->data = realloc(rcv->data, toalloc);
      rcv->bufsize = toalloc;
    }
    if (!rcv->data)
      nids_params.no_mem("add2buf");
  }
  memcpy(rcv->data + rcv->count - rcv->offset, data, datalen);
  rcv->count_new = datalen;
  rcv->count += datalen;
}

static void
ride_lurkers(struct tcp_stream * a_tcp, char mask)
{
  struct lurker_node *i;
  char cc, sc, ccu, scu;
  
  for (i = a_tcp->listeners; i; i = i->next)
    if (i->whatto & mask) {
      cc = a_tcp->client.collect;
      sc = a_tcp->server.collect;
      ccu = a_tcp->client.collect_urg;
      scu = a_tcp->server.collect_urg;

      (i->item) (a_tcp, &i->data);
      if (cc < a_tcp->client.collect)
	i->whatto |= COLLECT_cc;
      if (ccu < a_tcp->client.collect_urg)
	i->whatto |= COLLECT_ccu;
      if (sc < a_tcp->server.collect)
	i->whatto |= COLLECT_sc;
      if (scu < a_tcp->server.collect_urg)
	i->whatto |= COLLECT_scu;
      if (cc > a_tcp->client.collect)
	i->whatto &= ~COLLECT_cc;
      if (ccu > a_tcp->client.collect_urg)
	i->whatto &= ~COLLECT_ccu;
      if (sc > a_tcp->server.collect)
	i->whatto &= ~COLLECT_sc;
      if (scu > a_tcp->server.collect_urg)
	i->whatto &= ~COLLECT_scu;
    }
}

static void
notify(struct tcp_stream * a_tcp, struct half_stream * rcv)
{
  struct lurker_node *i, **prev_addr;
  char mask;

  if (rcv->count_new_urg) {
    if (!rcv->collect_urg)
      return;
    if (rcv == &a_tcp->client)
      mask = COLLECT_ccu;
    else
      mask = COLLECT_scu;
    ride_lurkers(a_tcp, mask);
    goto prune_listeners;
  }
  if (rcv->collect) {
    if (rcv == &a_tcp->client)
      mask = COLLECT_cc;
    else
      mask = COLLECT_sc;
   do {
	int total;
		a_tcp->read = rcv->count - rcv->offset;
		  total=a_tcp->read;
  
	    ride_lurkers(a_tcp, mask);
	    if (a_tcp->read>total-rcv->count_new)
	    	rcv->count_new=total-a_tcp->read;
	    
	    if (a_tcp->read > 0) {
	      memmove(rcv->data, rcv->data + a_tcp->read, rcv->count - rcv->offset - a_tcp->read);
	      rcv->offset += a_tcp->read;
	    }
	}while (nids_params.one_loop_less && a_tcp->read>0 && rcv->count_new); 
// we know that if one_loop_less!=0, we have only one callback to notify
   rcv->count_new=0;	    
  }
 prune_listeners:
  prev_addr = &a_tcp->listeners;
  i = a_tcp->listeners;
  while (i)
    if (!i->whatto) {
      *prev_addr = i->next;
      free(i);
      i = *prev_addr;
    }
    else {
      prev_addr = &i->next;
      i = i->next;
    }
}

static void
add_from_skb(struct tcp_stream * a_tcp, struct half_stream * rcv,
	     struct half_stream * snd,
	     u_char *data, int datalen,
	     u_int this_seq, char fin, char urg, u_int urg_ptr)
{
  u_int lost = EXP_SEQ - this_seq;
  int to_copy, to_copy2;
  
  if (urg && after(urg_ptr, EXP_SEQ - 1) &&
      (!rcv->urg_seen || after(urg_ptr, rcv->urg_ptr))) {
    rcv->urg_ptr = urg_ptr;
    rcv->urg_seen = 1;
  }
  if (rcv->urg_seen && after(rcv->urg_ptr + 1, this_seq + lost) &&
      before(rcv->urg_ptr, this_seq + datalen)) {
    to_copy = rcv->urg_ptr - (this_seq + lost);
    if (to_copy > 0) {
      if (rcv->collect) {
	add2buf(rcv, (char *)(data + lost), to_copy);
	notify(a_tcp, rcv);
      }
      else {
	rcv->count += to_copy;
	rcv->offset = rcv->count; /* clear the buffer */
      }
    }
    rcv->urgdata = data[rcv->urg_ptr - this_seq];
    rcv->count_new_urg = 1;
    notify(a_tcp, rcv);
    rcv->count_new_urg = 0;
    rcv->urg_seen = 0;
    rcv->urg_count++;
    to_copy2 = this_seq + datalen - rcv->urg_ptr - 1;
    if (to_copy2 > 0) {
      if (rcv->collect) {
	add2buf(rcv, (char *)(data + lost + to_copy + 1), to_copy2);
	notify(a_tcp, rcv);
      }
      else {
	rcv->count += to_copy2;
	rcv->offset = rcv->count; /* clear the buffer */
      }
    }
  }
  else {
    if (datalen - lost > 0) {
      if (rcv->collect) {
	add2buf(rcv, (char *)(data + lost), datalen - lost);
	notify(a_tcp, rcv);
      }
      else {
	rcv->count += datalen - lost;
	rcv->offset = rcv->count; /* clear the buffer */
      }
    }
  }
  if (fin) {
    snd->state = FIN_SENT;
    if (rcv->state == TCP_CLOSING)
      add_tcp_closing_timeout(a_tcp);
  }
}

static void
tcp_queue(struct tcp_stream * a_tcp, struct tcphdr * this_tcphdr,
	  struct half_stream * snd, struct half_stream * rcv,
	  char *data, int datalen, int skblen
	  )
{
  u_int this_seq = ntohl(this_tcphdr->th_seq);
  struct skbuff *pakiet, *tmp;
  
  /*
   * Did we get anything new to ack?
   */
  
  if (!after(this_seq, EXP_SEQ)) {
    if (after(this_seq + datalen + (this_tcphdr->th_flags & TH_FIN), EXP_SEQ)) {
      /* the packet straddles our window end */
      get_ts(this_tcphdr, &snd->curr_ts);
      add_from_skb(a_tcp, rcv, snd, (u_char *)data, datalen, this_seq,
		   (this_tcphdr->th_flags & TH_FIN),
		   (this_tcphdr->th_flags & TH_URG),
		   ntohs(this_tcphdr->th_urp) + this_seq - 1);
      /*
       * Do we have any old packets to ack that the above
       * made visible? (Go forward from skb)
       */
      pakiet = rcv->list;
      while (pakiet) {
	if (after(pakiet->seq, EXP_SEQ))
	  break;
	if (after(pakiet->seq + pakiet->len + pakiet->fin, EXP_SEQ)) {
	  add_from_skb(a_tcp, rcv, snd, pakiet->data,
		       pakiet->len, pakiet->seq, pakiet->fin, pakiet->urg,
		       pakiet->urg_ptr + pakiet->seq - 1);
        }
	rcv->rmem_alloc -= pakiet->truesize;
	if (pakiet->prev)
	  pakiet->prev->next = pakiet->next;
	else
	  rcv->list = pakiet->next;
	if (pakiet->next)
	  pakiet->next->prev = pakiet->prev;
	else
	  rcv->listtail = pakiet->prev;
	tmp = pakiet->next;
	free(pakiet->data);
	free(pakiet);
	pakiet = tmp;
      }
    }
    else
      return;
  }
  else {
    struct skbuff *p = rcv->listtail;

    pakiet = mknew(struct skbuff);
    pakiet->truesize = skblen;
    rcv->rmem_alloc += pakiet->truesize;
    pakiet->len = datalen;
    pakiet->data = malloc(datalen);
    if (!pakiet->data)
      nids_params.no_mem("tcp_queue");
    memcpy(pakiet->data, data, datalen);
    pakiet->fin = (this_tcphdr->th_flags & TH_FIN);
    /* Some Cisco - at least - hardware accept to close a TCP connection
     * even though packets were lost before the first TCP FIN packet and
     * never retransmitted; this violates RFC 793, but since it really
     * happens, it has to be dealt with... The idea is to introduce a 10s
     * timeout after TCP FIN packets were sent by both sides so that
     * corresponding libnids resources can be released instead of waiting
     * for retransmissions which will never happen.  -- Sebastien Raveau
     */
    if (pakiet->fin) {
      snd->state = TCP_CLOSING;
      if (rcv->state == FIN_SENT || rcv->state == FIN_CONFIRMED)
	add_tcp_closing_timeout(a_tcp);
    }
    pakiet->seq = this_seq;
    pakiet->urg = (this_tcphdr->th_flags & TH_URG);
    pakiet->urg_ptr = ntohs(this_tcphdr->th_urp);
    for (;;) {
      if (!p || !after(p->seq, this_seq))
	break;
      p = p->prev;
    }
    if (!p) {
      pakiet->prev = 0;
      pakiet->next = rcv->list;
      if (rcv->list)
         rcv->list->prev = pakiet;
      rcv->list = pakiet;
      if (!rcv->listtail)
	rcv->listtail = pakiet;
    }
    else {
      pakiet->next = p->next;
      p->next = pakiet;
      pakiet->prev = p;
      if (pakiet->next)
	pakiet->next->prev = pakiet;
      else
	rcv->listtail = pakiet;
    }
  }
}

static void
prune_queue(struct half_stream * rcv, struct tcphdr * this_tcphdr)
{
  struct skbuff *tmp, *p = rcv->list;

  nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BIGQUEUE, ugly_iphdr, this_tcphdr);
  while (p) {
    free(p->data);
    tmp = p->next;
    free(p);
    p = tmp;
  }
  rcv->list = rcv->listtail = 0;
  rcv->rmem_alloc = 0;
}

static void
handle_ack(struct half_stream * snd, u_int acknum)
{
  int ackdiff;

  ackdiff = acknum - snd->ack_seq;
  if (ackdiff > 0) {
    snd->ack_seq = acknum;
  }
}
#if 0
static void
check_flags(struct ip * iph, struct tcphdr * th)
{
  u_char flag = *(((u_char *) th) + 13);
  if (flag & 0x40 || flag & 0x80)
    nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BADFLAGS, iph, th);
//ECN is really the only cause of these warnings...
}
#endif

struct tcp_stream *
find_stream(struct tcphdr * this_tcphdr, struct ip * this_iphdr,
	    int *from_client)
{
  struct tuple4 this_addr, reversed;
  struct tcp_stream *a_tcp;

  this_addr.source = ntohs(this_tcphdr->th_sport);
  this_addr.dest = ntohs(this_tcphdr->th_dport);
  this_addr.saddr = this_iphdr->ip_src.s_addr;
  this_addr.daddr = this_iphdr->ip_dst.s_addr;
  a_tcp = nids_find_tcp_stream(&this_addr);
  if (a_tcp) {
    *from_client = 1;
    return a_tcp;
  }
  reversed.source = ntohs(this_tcphdr->th_dport);
  reversed.dest = ntohs(this_tcphdr->th_sport);
  reversed.saddr = this_iphdr->ip_dst.s_addr;
  reversed.daddr = this_iphdr->ip_src.s_addr;
  a_tcp = nids_find_tcp_stream(&reversed);
  if (a_tcp) {
    *from_client = 0;
    return a_tcp;
  }
  return 0;
}

struct tcp_stream *
nids_find_tcp_stream(struct tuple4 *addr)
{
  int hash_index;
  struct tcp_stream *a_tcp;

  hash_index = mk_hash_index(*addr);
  for (a_tcp = tcp_stream_table[hash_index];
       a_tcp && memcmp(&a_tcp->addr, addr, sizeof (struct tuple4));
       a_tcp = a_tcp->next_node);
  return a_tcp ? a_tcp : 0;
}


void tcp_exit(void)
{
  int i;
  struct lurker_node *j;
  struct tcp_stream *a_tcp, *t_tcp;

  if (!tcp_stream_table || !streams_pool)
    return;
  for (i = 0; i < tcp_stream_table_size; i++) {
    a_tcp = tcp_stream_table[i];
    while(a_tcp) {
      t_tcp = a_tcp;
      a_tcp = a_tcp->next_node;
      for (j = t_tcp->listeners; j; j = j->next) {
          t_tcp->nids_state = NIDS_EXITING;
	  (j->item)(t_tcp, &j->data);
      }
      nids_free_tcp_stream(t_tcp);
    }
  }
  free(tcp_stream_table);
  tcp_stream_table = NULL;
  free(streams_pool);
  streams_pool = NULL;
  /* FIXME: anything else we should free? */
  /* yes plz.. */
  tcp_latest = tcp_oldest = NULL;
  tcp_num = 0;
}

void
process_tcp(u_char * data, int skblen)
{
  struct ip *this_iphdr = (struct ip *)data;
  struct tcphdr *this_tcphdr = (struct tcphdr *)(data + 4 * this_iphdr->ip_hl);
  int datalen, iplen;
  int from_client = 1;
  unsigned int tmp_ts;
  struct tcp_stream *a_tcp;
  struct half_stream *snd, *rcv;

  ugly_iphdr = this_iphdr;
  iplen = ntohs(this_iphdr->ip_len);
  if ((unsigned)iplen < 4 * this_iphdr->ip_hl + sizeof(struct tcphdr)) {
    nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
		       this_tcphdr);
    return;
  } // ktos sie bawi
  
  datalen = iplen - 4 * this_iphdr->ip_hl - 4 * this_tcphdr->th_off;
  
  if (datalen < 0) {
    nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
		       this_tcphdr);
    return;
  } // ktos sie bawi

  if ((this_iphdr->ip_src.s_addr | this_iphdr->ip_dst.s_addr) == 0) {
    nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
		       this_tcphdr);
    return;
  }
  if (!(this_tcphdr->th_flags & TH_ACK))
    detect_scan(this_iphdr);
  if (!nids_params.n_tcp_streams) return;
  if (my_tcp_check(this_tcphdr, iplen - 4 * this_iphdr->ip_hl,
		   this_iphdr->ip_src.s_addr, this_iphdr->ip_dst.s_addr)) {
    nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
		       this_tcphdr);
    return;
  }
#if 0
  check_flags(this_iphdr, this_tcphdr);
//ECN
#endif
  if (!(a_tcp = find_stream(this_tcphdr, this_iphdr, &from_client))) {
    if ((this_tcphdr->th_flags & TH_SYN) &&
	!(this_tcphdr->th_flags & TH_ACK) &&
	!(this_tcphdr->th_flags & TH_RST))
      add_new_tcp(this_tcphdr, this_iphdr);
    return;
  }
  if (from_client) {
    snd = &a_tcp->client;
    rcv = &a_tcp->server;
  }
  else {
    rcv = &a_tcp->client;
    snd = &a_tcp->server;
  }
  if ((this_tcphdr->th_flags & TH_SYN)) {
    if (from_client || a_tcp->client.state != TCP_SYN_SENT ||
      a_tcp->server.state != TCP_CLOSE || !(this_tcphdr->th_flags & TH_ACK))
      return;
    if (a_tcp->client.seq != ntohl(this_tcphdr->th_ack))
      return;
    a_tcp->server.state = TCP_SYN_RECV;
    a_tcp->server.seq = ntohl(this_tcphdr->th_seq) + 1;
    a_tcp->server.first_data_seq = a_tcp->server.seq;
    a_tcp->server.ack_seq = ntohl(this_tcphdr->th_ack);
    a_tcp->server.window = ntohs(this_tcphdr->th_win);
    if (a_tcp->client.ts_on) {
    	a_tcp->server.ts_on = get_ts(this_tcphdr, &a_tcp->server.curr_ts);
	if (!a_tcp->server.ts_on)
		a_tcp->client.ts_on = 0;
    } else a_tcp->server.ts_on = 0;	
    if (a_tcp->client.wscale_on) {
    	a_tcp->server.wscale_on = get_wscale(this_tcphdr, &a_tcp->server.wscale);
	if (!a_tcp->server.wscale_on) {
		a_tcp->client.wscale_on = 0;
		a_tcp->client.wscale  = 1;
		a_tcp->server.wscale = 1;
	}	
    } else {
    	a_tcp->server.wscale_on = 0;	
    	a_tcp->server.wscale = 1;
    }	
    return;
  }
  if (
  	! (  !datalen && ntohl(this_tcphdr->th_seq) == rcv->ack_seq  )
  	&&
  	( !before(ntohl(this_tcphdr->th_seq), rcv->ack_seq + rcv->window*rcv->wscale) ||
          before(ntohl(this_tcphdr->th_seq) + datalen, rcv->ack_seq)  
        )
     )     
     return;

  if ((this_tcphdr->th_flags & TH_RST)) {
    if (a_tcp->nids_state == NIDS_DATA) {
      struct lurker_node *i;

      a_tcp->nids_state = NIDS_RESET;
      for (i = a_tcp->listeners; i; i = i->next)
	(i->item) (a_tcp, &i->data);
    }
    nids_free_tcp_stream(a_tcp);
    return;
  }

  /* PAWS check */
  if (rcv->ts_on && get_ts(this_tcphdr, &tmp_ts) && 
  	before(tmp_ts, snd->curr_ts))
  return; 	
  
  if ((this_tcphdr->th_flags & TH_ACK)) {
    if (from_client && a_tcp->client.state == TCP_SYN_SENT &&
	a_tcp->server.state == TCP_SYN_RECV) {
      if (ntohl(this_tcphdr->th_ack) == a_tcp->server.seq) {
	a_tcp->client.state = TCP_ESTABLISHED;
	a_tcp->client.ack_seq = ntohl(this_tcphdr->th_ack);
	{
	  struct proc_node *i;
	  struct lurker_node *j;
	  void *data;
	  
	  a_tcp->server.state = TCP_ESTABLISHED;
	  a_tcp->nids_state = NIDS_JUST_EST;
	  for (i = tcp_procs; i; i = i->next) {
	    char whatto = 0;
	    char cc = a_tcp->client.collect;
	    char sc = a_tcp->server.collect;
	    char ccu = a_tcp->client.collect_urg;
	    char scu = a_tcp->server.collect_urg;
	    
	    (i->item) (a_tcp, &data);
	    if (cc < a_tcp->client.collect)
	      whatto |= COLLECT_cc;
	    if (ccu < a_tcp->client.collect_urg)
	      whatto |= COLLECT_ccu;
	    if (sc < a_tcp->server.collect)
	      whatto |= COLLECT_sc;
	    if (scu < a_tcp->server.collect_urg)
	      whatto |= COLLECT_scu;
	    if (nids_params.one_loop_less) {
	    		if (a_tcp->client.collect >=2) {
	    			a_tcp->client.collect=cc;
	    			whatto&=~COLLECT_cc;
	    		}
	    		if (a_tcp->server.collect >=2 ) {
	    			a_tcp->server.collect=sc;
	    			whatto&=~COLLECT_sc;
	    		}
	    }  
	    if (whatto) {
	      j = mknew(struct lurker_node);
	      j->item = i->item;
	      j->data = data;
	      j->whatto = whatto;
	      j->next = a_tcp->listeners;
	      a_tcp->listeners = j;
	    }
	  }
	  if (!a_tcp->listeners) {
	    nids_free_tcp_stream(a_tcp);
	    return;
	  }
	  a_tcp->nids_state = NIDS_DATA;
	}
      }
      // return;
    }
  }
  if ((this_tcphdr->th_flags & TH_ACK)) {
    handle_ack(snd, ntohl(this_tcphdr->th_ack));
    if (rcv->state == FIN_SENT)
      rcv->state = FIN_CONFIRMED;
    if (rcv->state == FIN_CONFIRMED && snd->state == FIN_CONFIRMED) {
      struct lurker_node *i;

      a_tcp->nids_state = NIDS_CLOSE;
      for (i = a_tcp->listeners; i; i = i->next)
	(i->item) (a_tcp, &i->data);
      nids_free_tcp_stream(a_tcp);
      return;
    }
  }
  if (datalen + (this_tcphdr->th_flags & TH_FIN) > 0)
    tcp_queue(a_tcp, this_tcphdr, snd, rcv,
	      (char *) (this_tcphdr) + 4 * this_tcphdr->th_off,
	      datalen, skblen);
  snd->window = ntohs(this_tcphdr->th_win);
  if (rcv->rmem_alloc > 65535)
    prune_queue(rcv, this_tcphdr);
  if (!a_tcp->listeners)
    nids_free_tcp_stream(a_tcp);
}

void
nids_discard(struct tcp_stream * a_tcp, int num)
{
  if (num < a_tcp->read)
    a_tcp->read = num;
}

void
nids_register_tcp(void (*x))
{
  register_callback(&tcp_procs, x);
}

void
nids_unregister_tcp(void (*x))
{
  unregister_callback(&tcp_procs, x);
}

int
tcp_init(int size)
{
  int i;
  struct tcp_timeout *tmp;

  if (!size) return 0;
  tcp_stream_table_size = size;
  tcp_stream_table = calloc(tcp_stream_table_size, sizeof(char *));
  if (!tcp_stream_table) {
    nids_params.no_mem("tcp_init");
    return -1;
  }
  max_stream = 3 * tcp_stream_table_size / 4;
  streams_pool = (struct tcp_stream *) malloc((max_stream + 1) * sizeof(struct tcp_stream));
  if (!streams_pool) {
    nids_params.no_mem("tcp_init");
    return -1;
  }
  for (i = 0; i < max_stream; i++)
    streams_pool[i].next_free = &(streams_pool[i + 1]);
  streams_pool[max_stream].next_free = 0;
  free_streams = streams_pool;
  init_hash();
  while (nids_tcp_timeouts) {
    tmp = nids_tcp_timeouts->next;
    free(nids_tcp_timeouts);
    nids_tcp_timeouts = tmp;
  }
  return 0;
}

#if HAVE_ICMPHDR
#define STRUCT_ICMP struct icmphdr
#define ICMP_CODE   code
#define ICMP_TYPE   type
#else
#define STRUCT_ICMP struct icmp
#define ICMP_CODE   icmp_code
#define ICMP_TYPE   icmp_type
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH ICMP_UNREACH
#define ICMP_PROT_UNREACH ICMP_UNREACH_PROTOCOL
#define ICMP_PORT_UNREACH ICMP_UNREACH_PORT
#define NR_ICMP_UNREACH   ICMP_MAXTYPE
#endif				


void
process_icmp(u_char * data)
{
  struct ip *iph = (struct ip *) data;
  struct ip *orig_ip;
  STRUCT_ICMP *pkt;
  struct tcphdr *th;
  struct half_stream *hlf;
  int match_addr;
  struct tcp_stream *a_tcp;
  struct lurker_node *i;

  int from_client;
  /* we will use unsigned, to suppress warning; we must be careful with
     possible wrap when substracting 
     the following is ok, as the ip header has already been sanitized */
  unsigned int len = ntohs(iph->ip_len) - (iph->ip_hl << 2);
  
  if (len < sizeof(STRUCT_ICMP))
    return;
  pkt = (STRUCT_ICMP *) (data + (iph->ip_hl << 2));
  if (ip_compute_csum((char *) pkt, len))
    return;
  if (pkt->ICMP_TYPE != ICMP_DEST_UNREACH)
    return;
  /* ok due to check 7 lines above */  
  len -= sizeof(STRUCT_ICMP);
  // sizeof(struct icmp) is not what we want here
  
  if (len < sizeof(struct ip))
    return;

  orig_ip = (struct ip *) (((char *) pkt) + 8);
  if (len < (unsigned)(orig_ip->ip_hl << 2) + 8)
     return;
  /* subtraction ok due to the check above */
  len -= orig_ip->ip_hl << 2;
  if ((pkt->ICMP_CODE & 15) == ICMP_PROT_UNREACH ||
      (pkt->ICMP_CODE & 15) == ICMP_PORT_UNREACH)
    match_addr = 1;
  else
    match_addr = 0;
  if (pkt->ICMP_CODE > NR_ICMP_UNREACH)
    return;
  if (match_addr && (iph->ip_src.s_addr != orig_ip->ip_dst.s_addr))
    return;
  if (orig_ip->ip_p != IPPROTO_TCP)
    return;
  th = (struct tcphdr *) (((char *) orig_ip) + (orig_ip->ip_hl << 2));
  if (!(a_tcp = find_stream(th, orig_ip, &from_client)))
    return;
  if (a_tcp->addr.dest == iph->ip_dst.s_addr)
    hlf = &a_tcp->server;
  else
    hlf = &a_tcp->client;
  if (hlf->state != TCP_SYN_SENT && hlf->state != TCP_SYN_RECV)
    return;
  a_tcp->nids_state = NIDS_RESET;
  for (i = a_tcp->listeners; i; i = i->next)
    (i->item) (a_tcp, &i->data);
  nids_free_tcp_stream(a_tcp);
}
