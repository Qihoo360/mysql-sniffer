#
# Makefile for libnids.
#
# Dug Song <dugsong@monkey.org>


all: static 
install: _install
static shared _install _installshared:
	cd src ; $(MAKE) $(AM_MAKEFLAGS) $@
#	cd samples; $(MAKE) $(AM_MAKEFLAGS) $@
clean:
	cd src ; $(MAKE) $(AM_MAKEFLAGS) $@
	cd samples; $(MAKE) $(AM_MAKEFLAGS) $@
	
distclean: clean
	rm -f Makefile */Makefile */config.h config.status config.cache config.log *~ 

# EOF
