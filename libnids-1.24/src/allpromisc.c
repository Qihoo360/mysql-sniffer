#include "nids.h"
#ifdef __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

int set_all_promisc()
{
	struct ifreq * ifaces;
	int ifaces_size=8 * sizeof(struct ifreq);
	struct ifconf param;
	int sock;
	unsigned int i;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock <= 0)
		return 0;
        do {
        ifaces_size*=2;
        ifaces=alloca(ifaces_size);
	param.ifc_len = ifaces_size;
	param.ifc_req = ifaces;
	if (ioctl(sock, SIOCGIFCONF, &param))
		goto err;
	} while (param.ifc_len>=ifaces_size);	
	for (i = 0; i < param.ifc_len / sizeof(struct ifreq); i++) {
		if (ioctl(sock, SIOCGIFFLAGS, ifaces + i))
			goto err;
		ifaces[i].ifr_flags |= IFF_PROMISC;
		if (ioctl(sock, SIOCSIFFLAGS, ifaces + i))
			goto err;
	}
	close(sock);
	return 1;
err:
	close(sock);
	return 0;	
}

#endif
