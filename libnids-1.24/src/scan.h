/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_SCAN_H
#define _NIDS_SCAN_H

struct scan {
  u_int addr;
  unsigned short port;
  u_char flags;
};

struct host {
  struct host *next;
  struct host *prev;
  u_int addr;
  int modtime;
  int n_packets;
  struct scan *packets;
};

void scan_init(void);
void scan_exit(void);
void detect_scan(struct ip *);

#endif /* _NIDS_SCAN_H */
