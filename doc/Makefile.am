#
# Makefile.am -- generate Makefile for documentation directory of OpenSCEP
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.7 2001/10/30 13:54:38 afm Exp $
#
HTMLINSTALLDIR = @HTMLINSTALLDIR@

EXTRA_DIST = CA draft-nourse-scep-05.txt 				\
	draft-ietf-ipsra-getcert-00.txt	revocation.html

install-data-local:
	if [ ! -d $(HTMLINSTALLDIR) ]; 					\
	then								\
		mkdir $(HTMLINSTALLDIR);				\
	fi
	cp draft-nourse-scep-05.txt $(HTMLINSTALLDIR)
	cp revocation.html $(HTMLINSTALLDIR)
