#
# Makefile for libnids.
#
# Dug Song <dugsong@monkey.org>

srcdir		= .


install_prefix	=
prefix		= /usr/local
exec_prefix	= /usr/local
includedir	= ${prefix}/include
libdir		= ${exec_prefix}/lib
mandir		= ${prefix}/man
LIBSTATIC      = libnids.a
LIBSHARED      = libnids.so.1.24

CC		= gcc
CFLAGS		= -g -O2 -D_BSD_SOURCE -DLIBNET_VER=1 -DHAVE_ICMPHDR=1 -DHAVE_TCP_STATES=1 -DHAVE_BSD_UDPHDR=1 -DENABLE_TCPREASM=1
LDFLAGS		= 

PCAP_CFLAGS	= -I/usr/include/pcap
PCAPLIB		= -lpcap

LNET_CFLAGS	= -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H -DENABLE_TCPREASM
LNETLIB		= -lnet

LIBS_CFLAGS	= $(PCAP_CFLAGS) $(LNET_CFLAGS) -I/usr/local/include/glib-2.0 -I/usr/local/lib/glib-2.0/include   -pthread -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/lib64/glib-2.0/include 
LIBS		= -lgthread-2.0 -lnsl  -L/usr/local/lib -lglib-2.0   -pthread -L/usr/local/lib -lgthread-2.0 -lrt -lglib-2.0  
RANLIB		= ranlib
INSTALL		= /usr/bin/install -c

OBJS		= checksum.o ip_fragment.o ip_options.o killtcp.o \
		  libnids.o scan.o tcp.o util.o allpromisc.o hash.o tcp_conn_pool.o
OBJS_SHARED	= $(OBJS:.o=_pic.o)
.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<
static: $(LIBSTATIC)
shared: $(LIBSHARED)
# How to write the following rules compactly and portably ? 
# gmake accepts "%_pic.o: %.c", bsd make does not.
checksum_pic.o: checksum.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c checksum.c -o $@
ip_fragment_pic.o: ip_fragment.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c ip_fragment.c -o $@
ip_options_pic.o: ip_options.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c ip_options.c -o $@
killtcp_pic.o: killtcp.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c killtcp.c -o $@
libnids_pic.o: libnids.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c libnids.c -o $@
scan_pic.o: scan.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c scan.c -o $@
tcp_pic.o: tcp.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c tcp.c -o $@
util_pic.o: util.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c util.c -o $@
allpromisc_pic.o: allpromisc.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c allpromisc.c -o $@
hash_pic.o: hash.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c hash.c -o $@
tcp_conn_pool_pic.o: tcp_conn_pool.c
	$(CC) -fPIC $(CFLAGS) -I. $(LIBS_CFLAGS) -c tcp_conn_pool.c -o $@

$(LIBSTATIC): $(OBJS)
	ar -cr $@ $(OBJS)
	$(RANLIB) $@
	cp libnids.a ../../lib/libnidstcpreasm.a
	#cp libnids.a ../../lib/libnidstcpreasm-dbg.a

$(LIBSHARED): $(OBJS_SHARED)
	$(CC) -shared -Wl,-soname,$(LIBSHARED) -o $(LIBSHARED) $(OBJS_SHARED) $(LIBS) $(LNETLIB) $(PCAPLIB)

_install install: $(LIBSTATIC)
	../mkinstalldirs $(install_prefix)$(libdir)
	../mkinstalldirs $(install_prefix)$(includedir)
	../mkinstalldirs $(install_prefix)$(mandir)/man3
	$(INSTALL) -c -m 644 libnids.a $(install_prefix)$(libdir)
	$(INSTALL) -c -m 644 nids.h $(install_prefix)$(includedir)
	$(INSTALL) -c -m 644 libnids.3 $(install_prefix)$(mandir)/man3
_installshared installshared: install $(LIBSHARED)
	$(INSTALL) -c -m 755 $(LIBSHARED) $(install_prefix)$(libdir)
	ln -s -f $(LIBSHARED) $(install_prefix)$(libdir)/libnids.so
 
clean:
	rm -f *.o *~ $(LIBSTATIC) $(LIBSHARED)

# EOF
