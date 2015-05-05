#
# Makefile.am -- generate the Makefile to build the OpenSCEP project
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.9 2001/04/04 23:36:31 afm Exp $
#
HTMLINSTALLDIR = @HTMLINSTALLDIR@
PACKAGEDIR = @PKG@

EXTRA_DIST = README TODO BUGS acconfig.h config.sh.in shtool SETUP

# it is important to go into openssl before scepd, or a configuration
# file will not be available for tests
SUBDIRS = libltdl include openssl ldap lib scepd scep cgi-bin doc 	\
	html man package rpm

update-tools:
	libtoolize --ltdl -c -f
	shtoolize -q all

# this target makes the most important top level files available as HTTP
# documentation
install-data-local:
	cp NEWS COPYING README INSTALL SETUP TODO ChangeLog $(HTMLINSTALLDIR)
