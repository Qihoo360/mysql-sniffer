/*
  This file is taken from Linux 2.0.36 kernel source.
  Modified in Jun 99 by Nergal.
*/

#include <config.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "checksum.h"
#include "ip_fragment.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"

#define IP_CE		0x8000	/* Flag: "Congestion" */
#define IP_DF		0x4000	/* Flag: "Don't Fragment" */
#define IP_MF		0x2000	/* Flag: "More Fragments" */
#define IP_OFFSET	0x1FFF	/* "Fragment Offset" part */

#define IP_FRAG_TIME	(30 * 1000)	/* fragment lifetime */

#define UNUSED 314159
#define FREE_READ UNUSED
#define FREE_WRITE UNUSED
#define GFP_ATOMIC UNUSED
#define NETDEBUG(x)

struct sk_buff {
  char *data;
  int truesize;
};

struct timer_list {
  struct timer_list *prev;
  struct timer_list *next;
  int expires;
  void (*function)();
  unsigned long data;
  // struct ipq *frags;
};

struct hostfrags {
  struct ipq *ipqueue;
  int ip_frag_mem;
  u_int ip;
  int hash_index;
  struct hostfrags *prev;
  struct hostfrags *next;
};

/* Describe an IP fragment. */
struct ipfrag {
  int offset;			/* offset of fragment in IP datagram    */
  int end;			/* last byte of data in datagram        */
  int len;			/* length of this fragment              */
  struct sk_buff *skb;		/* complete received fragment           */
  unsigned char *ptr;		/* pointer into real fragment data      */
  struct ipfrag *next;		/* linked list pointers                 */
  struct ipfrag *prev;
};

/* Describe an entry in the "incomplete datagrams" queue. */
struct ipq {
  unsigned char *mac;		/* pointer to MAC header                */
  struct ip *iph;		/* pointer to IP header                 */
  int len;			/* total length of original datagram    */
  short ihlen;			/* length of the IP header              */
  short maclen;			/* length of the MAC header             */
  struct timer_list timer;	/* when will this queue expire?         */
  struct ipfrag *fragments;	/* linked list of received fragments    */
  struct hostfrags *hf;
  struct ipq *next;		/* linked list pointers                 */
  struct ipq *prev;
  // struct device *dev;	/* Device - for icmp replies */
};

/*
  Fragment cache limits. We will commit 256K at one time. Should we
  cross that limit we will prune down to 192K. This should cope with
  even the most extreme cases without allowing an attacker to
  measurably harm machine performance.
*/
#define IPFRAG_HIGH_THRESH		(256*1024)
#define IPFRAG_LOW_THRESH		(192*1024)

/*
  This fragment handler is a bit of a heap. On the other hand it works
  quite happily and handles things quite well.
*/
static struct hostfrags **fragtable;
static struct hostfrags *this_host;
static int numpack = 0;
static int hash_size;
static int timenow;
static unsigned int time0;
static struct timer_list *timer_head = 0, *timer_tail = 0;

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

static int
jiffies()
{
  struct timeval tv;

  if (timenow)
    return timenow;
  gettimeofday(&tv, 0);
  timenow = (tv.tv_sec - time0) * 1000 + tv.tv_usec / 1000;
  
  return timenow;
}

/* Memory Tracking Functions */
static void
atomic_sub(int ile, int *co)
{
  *co -= ile;
}

static void
atomic_add(int ile, int *co)
{
  *co += ile;
}

static void
kfree_skb(struct sk_buff * skb, int type)
{
  (void)type;
  free(skb);
}

static void
panic(char *str)
{
  fprintf(stderr, "%s", str);
  exit(1);
}

static void
add_timer(struct timer_list * x)
{
  if (timer_tail) {
    timer_tail->next = x;
    x->prev = timer_tail;
    x->next = 0;
    timer_tail = x;
  }
  else {
    x->prev = 0;
    x->next = 0;
    timer_tail = timer_head = x;
  }
}

static void
del_timer(struct timer_list * x)
{
  if (x->prev)
    x->prev->next = x->next;
  else
    timer_head = x->next;
  if (x->next)
    x->next->prev = x->prev;
  else
    timer_tail = x->prev;
}

static void
frag_kfree_skb(struct sk_buff * skb, int type)
{
  if (this_host)
    atomic_sub(skb->truesize, &this_host->ip_frag_mem);
  kfree_skb(skb, type);
}

static void
frag_kfree_s(void *ptr, int len)
{
  if (this_host)
    atomic_sub(len, &this_host->ip_frag_mem);
  free(ptr);
}

static void *
frag_kmalloc(int size, int dummy)
{
  void *vp = (void *) malloc(size);
  (void)dummy;
  if (!vp)
    return NULL;
  atomic_add(size, &this_host->ip_frag_mem);
  
  return vp;
}

/* Create a new fragment entry. */
static struct ipfrag *
ip_frag_create(int offset, int end, struct sk_buff * skb, unsigned char *ptr)
{
  struct ipfrag *fp;
  
  fp = (struct ipfrag *) frag_kmalloc(sizeof(struct ipfrag), GFP_ATOMIC);
  if (fp == NULL) {
    // NETDEBUG(printk("IP: frag_create: no memory left !\n"));
    nids_params.no_mem("ip_frag_create");
    return (NULL);
  }
  memset(fp, 0, sizeof(struct ipfrag));
  
  /* Fill in the structure. */
  fp->offset = offset;
  fp->end = end;
  fp->len = end - offset;
  fp->skb = skb;
  fp->ptr = ptr;

  /* Charge for the SKB as well. */
  this_host->ip_frag_mem += skb->truesize;
  
  return (fp);
}

static int
frag_index(struct ip * iph)
{
  unsigned int ip = ntohl(iph->ip_dst.s_addr);

  return (ip % hash_size);
}

static int
hostfrag_find(struct ip * iph)
{
  int hash_index = frag_index(iph);
  struct hostfrags *hf;
  
  this_host = 0;
  for (hf = fragtable[hash_index]; hf; hf = hf->next)
    if (hf->ip == iph->ip_dst.s_addr) {
      this_host = hf;
      break;
    }
  if (!this_host)
    return 0;
  else
    return 1;
}

static void
hostfrag_create(struct ip * iph)
{
  struct hostfrags *hf = mknew(struct hostfrags);
  int hash_index = frag_index(iph);

  hf->prev = 0;
  hf->next = fragtable[hash_index];
  if (hf->next)
    hf->next->prev = hf;
  fragtable[hash_index] = hf;
  hf->ip = iph->ip_dst.s_addr;
  hf->ipqueue = 0;
  hf->ip_frag_mem = 0;
  hf->hash_index = hash_index;
  this_host = hf;
}

static void
rmthis_host()
{
  int hash_index = this_host->hash_index;

  if (this_host->prev) {
    this_host->prev->next = this_host->next;
    if (this_host->next)
      this_host->next->prev = this_host->prev;
  }
  else {
    fragtable[hash_index] = this_host->next;
    if (this_host->next)
      this_host->next->prev = 0;
  }
  free(this_host);
  this_host = 0;
}

/*
  Find the correct entry in the "incomplete datagrams" queue for this
  IP datagram, and return the queue entry address if found.
*/
static struct ipq *
ip_find(struct ip * iph)
{
  struct ipq *qp;
  struct ipq *qplast;
  
  qplast = NULL;
  for (qp = this_host->ipqueue; qp != NULL; qplast = qp, qp = qp->next) {
    if (iph->ip_id == qp->iph->ip_id &&
	iph->ip_src.s_addr == qp->iph->ip_src.s_addr &&
	iph->ip_dst.s_addr == qp->iph->ip_dst.s_addr &&
	iph->ip_p == qp->iph->ip_p) {
      del_timer(&qp->timer);	/* So it doesn't vanish on us. The timer will
				   be reset anyway */
      return (qp);
    }
  }
  return (NULL);
}

/*
  Remove an entry from the "incomplete datagrams" queue, either
  because we completed, reassembled and processed it, or because it
  timed out.
*/
static void
ip_free(struct ipq * qp)
{
  struct ipfrag *fp;
  struct ipfrag *xp;

  /* Stop the timer for this entry. */
  del_timer(&qp->timer);
  
  /* Remove this entry from the "incomplete datagrams" queue. */
  if (qp->prev == NULL) {
    this_host->ipqueue = qp->next;
    if (this_host->ipqueue != NULL)
      this_host->ipqueue->prev = NULL;
    else
      rmthis_host();
  }
  else {
    qp->prev->next = qp->next;
    if (qp->next != NULL)
      qp->next->prev = qp->prev;
  }
  /* Release all fragment data. */
  fp = qp->fragments;
  while (fp != NULL) {
    xp = fp->next;
    frag_kfree_skb(fp->skb, FREE_READ);
    frag_kfree_s(fp, sizeof(struct ipfrag));
    fp = xp;
  }
  /* Release the IP header. */
  frag_kfree_s(qp->iph, 64 + 8);
  
  /* Finally, release the queue descriptor itself. */
  frag_kfree_s(qp, sizeof(struct ipq));
}

/* Oops- a fragment queue timed out.  Kill it and send an ICMP reply. */
static void
ip_expire(unsigned long arg)
{
  struct ipq *qp;
  
  qp = (struct ipq *) arg;

  /* Nuke the fragment queue. */
  ip_free(qp);
}

/*
  Memory limiting on fragments. Evictor trashes the oldest fragment
  queue until we are back under the low threshold.
*/
static void
ip_evictor(void)
{
  // fprintf(stderr, "ip_evict:numpack=%i\n", numpack);
  while (this_host && this_host->ip_frag_mem > IPFRAG_LOW_THRESH) {
    if (!this_host->ipqueue)
      panic("ip_evictor: memcount");
    ip_free(this_host->ipqueue);
  }
}

/*
  Add an entry to the 'ipq' queue for a newly received IP datagram.
  We will (hopefully :-) receive all other fragments of this datagram
  in time, so we just create a queue for this datagram, in which we
  will insert the received fragments at their respective positions.
*/
static struct ipq *
ip_create(struct ip * iph)
{
  struct ipq *qp;
  int ihlen;

  qp = (struct ipq *) frag_kmalloc(sizeof(struct ipq), GFP_ATOMIC);
  if (qp == NULL) {
    // NETDEBUG(printk("IP: create: no memory left !\n"));
    nids_params.no_mem("ip_create");
    return (NULL);
  }
  memset(qp, 0, sizeof(struct ipq));
  
  /* Allocate memory for the IP header (plus 8 octets for ICMP). */
  ihlen = iph->ip_hl * 4;
  qp->iph = (struct ip *) frag_kmalloc(64 + 8, GFP_ATOMIC);
  if (qp->iph == NULL) {
    //NETDEBUG(printk("IP: create: no memory left !\n"));
    nids_params.no_mem("ip_create");
    frag_kfree_s(qp, sizeof(struct ipq));
    return (NULL);
  }
  memcpy(qp->iph, iph, ihlen + 8);
  qp->len = 0;
  qp->ihlen = ihlen;
  qp->fragments = NULL;
  qp->hf = this_host;

  /* Start a timer for this entry. */
  qp->timer.expires = jiffies() + IP_FRAG_TIME;	/* about 30 seconds     */
  qp->timer.data = (unsigned long) qp;	/* pointer to queue     */
  qp->timer.function = ip_expire;	/* expire function      */
  add_timer(&qp->timer);

  /* Add this entry to the queue. */
  qp->prev = NULL;
  qp->next = this_host->ipqueue;
  if (qp->next != NULL)
    qp->next->prev = qp;
  this_host->ipqueue = qp;
  
  return (qp);
}

/* See if a fragment queue is complete. */
static int
ip_done(struct ipq * qp)
{
  struct ipfrag *fp;
  int offset;
  
  /* Only possible if we received the final fragment. */
  if (qp->len == 0)
    return (0);
  
  /* Check all fragment offsets to see if they connect. */
  fp = qp->fragments;
  offset = 0;
  while (fp != NULL) {
    if (fp->offset > offset)
      return (0);		/* fragment(s) missing */
    offset = fp->end;
    fp = fp->next;
  }
  /* All fragments are present. */
  return (1);
}


/*
  Build a new IP datagram from all its fragments.
 
  FIXME: We copy here because we lack an effective way of handling
  lists of bits on input. Until the new skb data handling is in I'm
  not going to touch this with a bargepole.
*/
static char *
ip_glue(struct ipq * qp)
{
  char *skb;
  struct ip *iph;
  struct ipfrag *fp;
  unsigned char *ptr;
  int count, len;

  /* Allocate a new buffer for the datagram. */
  len = qp->ihlen + qp->len;
  
  if (len > 65535) {
    // NETDEBUG(printk("Oversized IP packet from %s.\n", int_ntoa(qp->iph->ip_src.s_addr)));
    nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, qp->iph, 0);
    ip_free(qp);
    return NULL;
  }
  if ((skb = (char *) malloc(len)) == NULL) {
    // NETDEBUG(printk("IP: queue_glue: no memory for gluing queue %p\n", qp));
    nids_params.no_mem("ip_glue");
    ip_free(qp);
    return (NULL);
  }
  /* Fill in the basic details. */
  ptr = (unsigned char *)skb;
  memcpy(ptr, ((unsigned char *) qp->iph), qp->ihlen);
  ptr += qp->ihlen;
  count = 0;

  /* Copy the data portions of all fragments into the new buffer. */
  fp = qp->fragments;
  while (fp != NULL) {
    if (fp->len < 0 || fp->offset + qp->ihlen + fp->len > len) {
      //NETDEBUG(printk("Invalid fragment list: Fragment over size.\n"));
      nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_INVLIST, qp->iph, 0);
      ip_free(qp);
      //kfree_skb(skb, FREE_WRITE);
      //ip_statistics.IpReasmFails++;
      free(skb);
      return NULL;
    }
    memcpy((ptr + fp->offset), fp->ptr, fp->len);
    count += fp->len;
    fp = fp->next;
  }
  /* We glued together all fragments, so remove the queue entry. */
  ip_free(qp);

  /* Done with all fragments. Fixup the new IP header. */
  iph = (struct ip *) skb;
  iph->ip_off = 0;
  iph->ip_len = htons((iph->ip_hl * 4) + count);
  // skb->ip_hdr = iph;

  return (skb);
}

/* Process an incoming IP datagram fragment. */
static char *
ip_defrag(struct ip *iph, struct sk_buff *skb)
{
  struct ipfrag *prev, *next, *tmp;
  struct ipfrag *tfp;
  struct ipq *qp;
  char *skb2;
  unsigned char *ptr;
  int flags, offset;
  int i, ihl, end;

  if (!hostfrag_find(iph) && skb)
    hostfrag_create(iph);

  /* Start by cleaning up the memory. */
  if (this_host)
    if (this_host->ip_frag_mem > IPFRAG_HIGH_THRESH)
      ip_evictor();
  
  /* Find the entry of this IP datagram in the "incomplete datagrams" queue. */
  if (this_host)
    qp = ip_find(iph);
  else
    qp = 0;

  /* Is this a non-fragmented datagram? */
  offset = ntohs(iph->ip_off);
  flags = offset & ~IP_OFFSET;
  offset &= IP_OFFSET;
  if (((flags & IP_MF) == 0) && (offset == 0)) {
    if (qp != NULL)
      ip_free(qp);		/* Fragmented frame replaced by full
				   unfragmented copy */
    return 0;
  }

  /* ip_evictor() could have removed all queues for the current host */
  if (!this_host)
    hostfrag_create(iph);

  offset <<= 3;			/* offset is in 8-byte chunks */
  ihl = iph->ip_hl * 4;

  /*
    If the queue already existed, keep restarting its timer as long as
    we still are receiving fragments.  Otherwise, create a fresh queue
    entry.
  */
  if (qp != NULL) {
    /* ANK. If the first fragment is received, we should remember the correct
       IP header (with options) */
    if (offset == 0) {
      qp->ihlen = ihl;
      memcpy(qp->iph, iph, ihl + 8);
    }
    del_timer(&qp->timer);
    qp->timer.expires = jiffies() + IP_FRAG_TIME;	/* about 30 seconds */
    qp->timer.data = (unsigned long) qp;	/* pointer to queue */
    qp->timer.function = ip_expire;	/* expire function */
    add_timer(&qp->timer);
  }
  else {
    /* If we failed to create it, then discard the frame. */
    if ((qp = ip_create(iph)) == NULL) {
      kfree_skb(skb, FREE_READ);
      return NULL;
    }
  }
  /* Attempt to construct an oversize packet. */
  if (ntohs(iph->ip_len) + (int) offset > 65535) {
    // NETDEBUG(printk("Oversized packet received from %s\n", int_ntoa(iph->ip_src.s_addr)));
    nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, iph, 0);
    kfree_skb(skb, FREE_READ);
    return NULL;
  }
  /* Determine the position of this fragment. */
  end = offset + ntohs(iph->ip_len) - ihl;

  /* Point into the IP datagram 'data' part. */
  ptr = (unsigned char *)(skb->data + ihl);

  /* Is this the final fragment? */
  if ((flags & IP_MF) == 0)
    qp->len = end;

  /*
    Find out which fragments are in front and at the back of us in the
    chain of fragments so far.  We must know where to put this
    fragment, right?
  */
  prev = NULL;
  for (next = qp->fragments; next != NULL; next = next->next) {
    if (next->offset >= offset)
      break;			/* bingo! */
    prev = next;
  }
  /*
    We found where to put this one.  Check for overlap with preceding
    fragment, and, if needed, align things so that any overlaps are
    eliminated.
  */
  if (prev != NULL && offset < prev->end) {
    nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERLAP, iph, 0);
    i = prev->end - offset;
    offset += i;		/* ptr into datagram */
    ptr += i;			/* ptr into fragment data */
  }
  /*
    Look for overlap with succeeding segments.
    If we can merge fragments, do it.
  */
  for (tmp = next; tmp != NULL; tmp = tfp) {
    tfp = tmp->next;
    if (tmp->offset >= end)
      break;			/* no overlaps at all */
    nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERLAP, iph, 0);
    
    i = end - next->offset;	/* overlap is 'i' bytes */
    tmp->len -= i;		/* so reduce size of    */
    tmp->offset += i;		/* next fragment        */
    tmp->ptr += i;
    /*
      If we get a frag size of <= 0, remove it and the packet that it
      goes with. We never throw the new frag away, so the frag being
      dumped has always been charged for.
    */
    if (tmp->len <= 0) {
      if (tmp->prev != NULL)
	tmp->prev->next = tmp->next;
      else
	qp->fragments = tmp->next;
      
      if (tmp->next != NULL)
	tmp->next->prev = tmp->prev;
      
      next = tfp;		/* We have killed the original next frame */

      frag_kfree_skb(tmp->skb, FREE_READ);
      frag_kfree_s(tmp, sizeof(struct ipfrag));
    }
  }
  /* Insert this fragment in the chain of fragments. */
  tfp = NULL;
  tfp = ip_frag_create(offset, end, skb, ptr);
  
  /*
    No memory to save the fragment - so throw the lot. If we failed
    the frag_create we haven't charged the queue.
  */
  if (!tfp) {
    nids_params.no_mem("ip_defrag");
    kfree_skb(skb, FREE_READ);
    return NULL;
  }
  /* From now on our buffer is charged to the queues. */
  tfp->prev = prev;
  tfp->next = next;
  if (prev != NULL)
    prev->next = tfp;
  else
    qp->fragments = tfp;

  if (next != NULL)
    next->prev = tfp;

  /*
    OK, so we inserted this new fragment into the chain.  Check if we
    now have a full IP datagram which we can bump up to the IP
    layer...
  */
  if (ip_done(qp)) {
    skb2 = ip_glue(qp);		/* glue together the fragments */
    return (skb2);
  }
  return (NULL);
}

int
ip_defrag_stub(struct ip *iph, struct ip **defrag)
{
  int offset, flags, tot_len;
  struct sk_buff *skb;

  numpack++;
  timenow = 0;
  while (timer_head && timer_head->expires < jiffies()) {
    this_host = ((struct ipq *) (timer_head->data))->hf;
    timer_head->function(timer_head->data);
  }
  offset = ntohs(iph->ip_off);
  flags = offset & ~IP_OFFSET;
  offset &= IP_OFFSET;
  if (((flags & IP_MF) == 0) && (offset == 0)) {
    ip_defrag(iph, 0);
    return IPF_NOTF;
  }
  tot_len = ntohs(iph->ip_len);
  skb = (struct sk_buff *) malloc(tot_len + sizeof(struct sk_buff));
  if (!skb)
      nids_params.no_mem("ip_defrag_stub");
  skb->data = (char *) (skb + 1);
  memcpy(skb->data, iph, tot_len);
  skb->truesize = tot_len + 16 + nids_params.dev_addon;
  skb->truesize = (skb->truesize + 15) & ~15;
  skb->truesize += nids_params.sk_buff_size;

  if ((*defrag = (struct ip *)ip_defrag((struct ip *) (skb->data), skb)))
    return IPF_NEW;

  return IPF_ISF;
}

void
ip_frag_init(int n)
{
  struct timeval tv;

  gettimeofday(&tv, 0);
  time0 = tv.tv_sec;
  fragtable = (struct hostfrags **) calloc(n, sizeof(struct hostfrags *));
  if (!fragtable)
    nids_params.no_mem("ip_frag_init");
  hash_size = n;
}

void
ip_frag_exit(void)
{
  if (fragtable) {
    free(fragtable);
    fragtable = NULL;
  }
  /* FIXME: do we need to free anything else? */
}
