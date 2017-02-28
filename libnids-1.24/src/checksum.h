
#ifndef _NIDS_CHECKSUM_H
#define _NIDS_CHECKSUM_H

u_short ip_fast_csum(u_char *, u_int);
extern u_short ip_compute_csum(char *, int len);
u_short my_tcp_check(struct tcphdr *, int, u_int, u_int);
u_short my_udp_check(void *, int, u_int, u_int);

#endif /* _NIDS_CHECKSUM_H */
