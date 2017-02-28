
                             ====================
                                 libnids-1.24
                             ====================

1. What is libnids ?
------------------------

	Libnids is a library that provides a functionality of one of NIDS 
(Network Intrusion Detection System) components, namely E-component. It means 
that libnids code watches all local network traffic, cooks received datagrams 
a bit (quite a bit ;)), and provides convenient information on them to 
analyzing modules of NIDS. Libnids performs:
a) assembly of TCP segments into TCP streams
b) IP defragmentation
c) TCP port scan detection 
More technical info can be found in MISC file.
	So, if you intend to develop a custom NIDS, you don't have to build
low-level network code. If you decide to use libnids, you have got
E-component ready - you can focus on implementing other parts of NIDS.

2. Why is libnids valuable ?
----------------------------

	On January 98, Thomas H. Ptacek and Timothy N. Newsham published an
excellent paper entitled "Eluding Network Intrusion Detection". It's a
must-read for all security concerned people, available from
http://www.robertgraham.com/mirror/Ptacek-Newsham-Evasion-98.html
In this paper one can find description of variety of attack against NIDS.
During libnids development a lot of effort was made to make libnids immune
to these attacks. During tests libnids performed TCP assembly and IP 
defragmentation in exactly the same way as Linux 2.0.36 hosts
(targets of test packets). For details, see file TESTS; here let's just 
mention two things:
a) libnids passed all tests implemented in fragrouter by Dug Song (see 
   http://www.anzen.com/research/nidsbench/ ). In fact, fragrouter's tests were
   fairly simple when compared with other, custom ones.
b) libnids IP defragmenting module contains slightly modified Linux 2.0.36 
   kernel source files ip_fragment.c and ip_options.c. It means that libnids IP
   defragmentation is as reliable as one implemented in Linux 2.0.36.
Libnids is easy to use and highly configurable - see API file for details.

3. On what platform does it run ?
---------------------------------

Currently libnids will compile on Linux, Solaris, any *BSD. WIN32 port is
available at http://www.datanerds.net/~mike/libnids.html, but currently only
obsoleted versions are present there; newer ports may appear at
http://www.checksum.org (in "downloads" section).

4. Who is allowed to use it ?
-----------------------------

Libnids is licensed under GPL. See the file COPYING for details.

5. Contact info ?
-----------------

The primary libnids site is 
http://libnids.sourceforge.net/
Please send bug reports, comments, or questions about this software to
<nergal@7bulls.com>.
