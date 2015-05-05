#
# Makefile.am -- build make file in the package build directory
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.7 2001/04/04 23:36:38 afm Exp $
#
EXTRA_DIST = README pkginfo.in prototype.in copyright postinstall request

all-local:	@PKG@

pkgname = OpenSCEP

package:	s/$(pkgname) $(pkgname)-$(VERSION).tar.gz

$(pkgname)-$(VERSION).tar.gz:	p
	(cd p; tar cf - $(pkgname)) | gzip -c >$(pkgname)-$(VERSION).tar.gz

p/$(pkgname):	pkginfo prototype copyright $(binaries)
	if test -d p; then :; else mkdir p; fi
	pkgmk -o -r / -f prototype -d p

s/$(pkgname):	p/$(pkgname)
	if test -d s; then :; else mkdir s; fi
	touch s/$(pkgname)
	pkgtrans -so p s/$(pkgname) $(pkgname)

rpm:

pkginfo:	pkginfo.in Makefile.am
	sed -e 's/PSTAMP=.*/PSTAMP='`date +%y%m%d`/ -e 's/VeRsIoN/'$(VERSION)/ \
		<pkginfo.in >pkginfo

prototype:	prototype.in Makefile.am
	LIBVERSION="`../shtool version -d libtool ../lib/openscep_vers.c | sed -e s/:/.0./`"; \
	LIBVER="`../shtool version -d libtool ../lib/openscep_vers.c | sed 's/:.*//'"; \
	sed	-e s/LiBvErSiOn/$${LIBVERSION}/g			\
		-e s/LiBvEr/$${LIBVER}/g				\
		<prototype.in >prototype

.PHONY:	package

