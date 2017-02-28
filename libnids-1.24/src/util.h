/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_UTIL_H
#define _NIDS_UTIL_H

#define mknew(x)	(x *)test_malloc(sizeof(x))
#define b_comp(x,y)	(!memcmp(&(x), &(y), sizeof(x)))

struct proc_node {
  void (*item)();
  struct proc_node *next;
};

struct lurker_node {
  void (*item)();
  void *data;
  char whatto;
  struct lurker_node *next;
};

void nids_no_mem(char *);
char *test_malloc(int);
void register_callback(struct proc_node **procs, void (*x));
void unregister_callback(struct proc_node **procs, void (*x));

static inline int
before(u_int seq1, u_int seq2)
{
  return ((int)(seq1 - seq2) < 0);
}

static inline int
after(u_int seq1, u_int seq2)
{
  return ((int)(seq2 - seq1) < 0);
}

#endif /* _NIDS_UTIL_H */
