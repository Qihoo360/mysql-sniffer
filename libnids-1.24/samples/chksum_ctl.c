#include "nids.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

/* Example 1: simple disabling of checksums on a predefined network */
void simple_chksum_ctl_example()
{
	static struct nids_chksum_ctl ctl;

	ctl.netaddr = inet_addr("172.16.99.0");
	ctl.mask = inet_addr("255.255.255.0");
	ctl.action = NIDS_DONT_CHKSUM;
	nids_register_chksum_ctl(&ctl, 1);
}

/* Example 2: disabling checksums of packets with src ip of any local interface */
static int get_all_ifaces(struct ifreq **, int *);
static unsigned int get_addr_from_ifreq(struct ifreq *);

int all_local_ipaddrs_chksum_disable()
{
	struct ifreq *ifaces;
	int ifaces_count;
	int i, ind = 0;
	struct nids_chksum_ctl *ctlp;
	unsigned int tmp;

	if (!get_all_ifaces(&ifaces, &ifaces_count))
		return -1;
	ctlp =
	    (struct nids_chksum_ctl *) malloc(ifaces_count *
					      sizeof(struct
						     nids_chksum_ctl));
	if (!ctlp)
		return -1;
	for (i = 0; i < ifaces_count; i++) {
		tmp = get_addr_from_ifreq(ifaces + i);
		if (tmp) {
			ctlp[ind].netaddr = tmp;
			ctlp[ind].mask = inet_addr("255.255.255.255");
			ctlp[ind].action = NIDS_DONT_CHKSUM;
			ind++;
		}
	}
	free(ifaces);
	nids_register_chksum_ctl(ctlp, ind);
}

/* helper functions for Example 2 */
unsigned int get_addr_from_ifreq(struct ifreq *iface)
{
	if (iface->ifr_addr.sa_family == AF_INET)
		return ((struct sockaddr_in *) &(iface->ifr_addr))->
		    sin_addr.s_addr;
	return 0;
}

static int get_all_ifaces(struct ifreq **ifaces, int *count)
{
	int ifaces_size = 8 * sizeof(struct ifreq);
	struct ifconf param;
	int sock;
	unsigned int i;

	*ifaces = malloc(ifaces_size);
	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock <= 0)
		return 0;
	for (;;) {
		param.ifc_len = ifaces_size;
		param.ifc_req = *ifaces;
		if (ioctl(sock, SIOCGIFCONF, &param))
			goto err;
		if (param.ifc_len < ifaces_size)
			break;
		free(*ifaces);
		ifaces_size *= 2;
		ifaces = malloc(ifaces_size);
	}
	*count = param.ifc_len / sizeof(struct ifreq);
	close(sock);
	return 1;
      err:
	close(sock);
	return 0;
}

#ifdef TESTING
main()
{
	all_local_ipaddrs_chksum_disable();
}
#endif
