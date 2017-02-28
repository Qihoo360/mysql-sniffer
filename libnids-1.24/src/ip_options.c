/*
  This file is taken from Linux 2.0.36 kernel source.
  Modified in Jun 99 by Nergal.
*/
#include <config.h>
#include <string.h>

#define __u8 unsigned char
#define __u16 unsigned short
#define __u32 unsigned int

#define IPOPT_END	0
#define IPOPT_NOOP	1
#define IPOPT_SEC	130
#define IPOPT_LSRR	131
#define IPOPT_SSRR	137
#define IPOPT_RR	7
#define IPOPT_SID	136
#define IPOPT_TIMESTAMP	68

#define MAXTTL		255


struct timestamp {
  __u8 len;
  __u8 ptr;
#ifdef WORDS_BIGENDIAN
  __u8 overflow:4, flags:4;
#else
  __u8 flags:4, overflow:4;
#endif
  __u32 data[9];
};

#define MAX_ROUTE	16

struct route {
  char route_size;
  char pointer;
  unsigned long route[MAX_ROUTE];
};

#define IPOPT_OPTVAL 0
#define IPOPT_OLEN   1
#define IPOPT_OFFSET 2
#define IPOPT_MINOFF 4
#define MAX_IPOPTLEN 40
#define IPOPT_NOP IPOPT_NOOP
#define IPOPT_EOL IPOPT_END
#define IPOPT_TS  IPOPT_TIMESTAMP

#define	IPOPT_TS_TSONLY		0	/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1	/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	3	/* specified modules only */

struct options {
  __u32 faddr;			/* Saved first hop address */
  unsigned char optlen;
  unsigned char srr;
  unsigned char rr;
  unsigned char ts;
  unsigned char is_setbyuser:1,	/* Set by setsockopt?			 */
       is_data:1,		/* Options in __data, rather than skb	 */
       is_strictroute:1,	/* Strict source route			 */
       srr_is_hit:1,		/* Packet destination addr was our one	 */
       is_changed:1,		/* IP checksum more not valid		 */
       rr_needaddr:1,		/* Need to record addr of outgoing dev	 */
       ts_needtime:1,		/* Need to record timestamp		 */
       ts_needaddr:1;		/* Need to record addr of outgoing dev  */
  unsigned char __pad1;
  unsigned char __pad2;
  unsigned char __pad3;
  unsigned char __data[];
};

struct iphdr {
#ifdef WORDS_BIGENDIAN
  __u8 version:4, ihl:4;
#else
  __u8 ihl:4, version:4;
#endif
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
  /* The options start here. */
};

#define ip_chk_addr(x) 0

int 
ip_options_compile(unsigned char *iph)
{
  int l;
  unsigned char *optptr;
  int optlen;
  unsigned char *pp_ptr = 0;
  char optholder[16];
  struct options *opt;
  int skb = 1;
  int skb_pa_addr = 314159;

  opt = (struct options *) optholder;
  memset(opt, 0, sizeof(struct options));
  opt->optlen = ((struct iphdr *) iph)->ihl * 4 - sizeof(struct iphdr);
  optptr = iph + sizeof(struct iphdr);
  opt->is_data = 0;

  for (l = opt->optlen; l > 0;) {
    switch (*optptr) {
    case IPOPT_END:
      for (optptr++, l--; l > 0; l--) {
	if (*optptr != IPOPT_END) {
	  *optptr = IPOPT_END;
	  opt->is_changed = 1;
	}
      }
      goto eol;
    case IPOPT_NOOP:
      l--;
      optptr++;
      continue;
    }
    optlen = optptr[1];
    if (optlen < 2 || optlen > l) {
      pp_ptr = optptr;
      goto error;
    }
    switch (*optptr) {
    case IPOPT_SSRR:
    case IPOPT_LSRR:
      if (optlen < 3) {
	pp_ptr = optptr + 1;
	goto error;
      }
      if (optptr[2] < 4) {
	pp_ptr = optptr + 2;
	goto error;
      }
      /* NB: cf RFC-1812 5.2.4.1 */
      if (opt->srr) {
	pp_ptr = optptr;
	goto error;
      }
      if (!skb) {
	if (optptr[2] != 4 || optlen < 7 || ((optlen - 3) & 3)) {
	  pp_ptr = optptr + 1;
	  goto error;
	}
	memcpy(&opt->faddr, &optptr[3], 4);
	if (optlen > 7)
	  memmove(&optptr[3], &optptr[7], optlen - 7);
      }
      opt->is_strictroute = (optptr[0] == IPOPT_SSRR);
      opt->srr = optptr - iph;
      break;
    case IPOPT_RR:
      if (opt->rr) {
	pp_ptr = optptr;
	goto error;
      }
      if (optlen < 3) {
	pp_ptr = optptr + 1;
	goto error;
      }
      if (optptr[2] < 4) {
	pp_ptr = optptr + 2;
	goto error;
      }
      if (optptr[2] <= optlen) {
	if (optptr[2] + 3 > optlen) {
	  pp_ptr = optptr + 2;
	  goto error;
	}
	if (skb) {
	  memcpy(&optptr[optptr[2] - 1], &skb_pa_addr, 4);
	  opt->is_changed = 1;
	}
	optptr[2] += 4;
	opt->rr_needaddr = 1;
      }
      opt->rr = optptr - iph;
      break;
    case IPOPT_TIMESTAMP:
      if (opt->ts) {
	pp_ptr = optptr;
	goto error;
      }
      if (optlen < 4) {
	pp_ptr = optptr + 1;
	goto error;
      }
      if (optptr[2] < 5) {
	pp_ptr = optptr + 2;
	goto error;
      }
      if (optptr[2] <= optlen) {
	struct timestamp *ts = (struct timestamp *) (optptr + 1);
	__u32 *timeptr = 0;

	if (ts->ptr + 3 > ts->len) {
	  pp_ptr = optptr + 2;
	  goto error;
	}
	switch (ts->flags) {
	case IPOPT_TS_TSONLY:
	  opt->ts = optptr - iph;
	  if (skb)
	    timeptr = (__u32 *) & optptr[ts->ptr - 1];
	  opt->ts_needtime = 1;
	  ts->ptr += 4;
	  break;
	case IPOPT_TS_TSANDADDR:
	  if (ts->ptr + 7 > ts->len) {
	    pp_ptr = optptr + 2;
	    goto error;
	  }
	  opt->ts = optptr - iph;
	  if (skb) {
	    memcpy(&optptr[ts->ptr - 1], &skb_pa_addr, 4);
	    timeptr = (__u32 *) & optptr[ts->ptr + 3];
	  }
	  opt->ts_needaddr = 1;
	  opt->ts_needtime = 1;
	  ts->ptr += 8;
	  break;
	case IPOPT_TS_PRESPEC:
	  if (ts->ptr + 7 > ts->len) {
	    pp_ptr = optptr + 2;
	    goto error;
	  }
	  opt->ts = optptr - iph;
	  {
	    __u32 addr;

	    memcpy(&addr, &optptr[ts->ptr - 1], 4);
	    if (ip_chk_addr(addr) == 0)
	      break;
	    if (skb)
	      timeptr = (__u32 *) & optptr[ts->ptr + 3];
	  }
	  opt->ts_needaddr = 1;
	  opt->ts_needtime = 1;
	  ts->ptr += 8;
	  break;
	default:
	  pp_ptr = optptr + 3;
	  goto error;
	}
	if (timeptr) {
	  //struct timeval tv;
	  __u32 midtime = 1;

	  //do_gettimeofday(&tv);
	  //midtime = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
	  memcpy(timeptr, &midtime, sizeof(__u32));
	  opt->is_changed = 1;
	}
      }
      else {
	struct timestamp *ts = (struct timestamp *) (optptr + 1);

	if (ts->overflow == 15) {
	  pp_ptr = optptr + 3;
	  goto error;
	}
	opt->ts = optptr - iph;
	if (skb) {
	  ts->overflow++;
	  opt->is_changed = 1;
	}
      }
      break;
    case IPOPT_SEC:
    case IPOPT_SID:
    default:
      if (!skb) {
	pp_ptr = optptr;
	goto error;
      }
      break;
    }
    l -= optlen;
    optptr += optlen;
  }

eol:
  opt = (struct options *) optholder;
  if (!pp_ptr)
    if (!opt->srr)
      return 0;

error:
  return -1;
}
