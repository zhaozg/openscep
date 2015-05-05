#
# Makefile for the scep library
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.8 2002/02/19 23:40:05 afm Exp $
#
OPENSSLDIR = @OPENSSLDIR@
OPENSCEPDIR = @OPENSCEPDIR@

lib_LTLIBRARIES = libscep.la

LDADD = libscep.la
LDFLAGS = -R$(libdir) $(LIBS)
CPPFLAGS = -DOPENSCEPDIR=\"$(OPENSCEPDIR)\"

VERSION_FILE = openscep_vers.c

libscep_la_LDFLAGS = -version-info `../shtool version -d libtool $(VERSION_FILE)`

libscep_la_SOURCES = init.c isasu.c decode.c sigattr.c pkcsreq.c	\
	certrep.c getcertinitial.c getcert.c getcrl.c badreply.c attr.c	\
	goodreply.c encode.c check.c grant.c scepldap.c fingerprint.c	\
	openscep_vers.c selfsigned.c createreq.c http.c iser.c proxy.c	\
	payload.c v2request.c transcheck.c pending.c spki2file.c

INCLUDES = $(INCLTDL) -I$(top_srcdir)/include -I$(OPENSSLDIR)/include

openscep_vers.c:	../configure.in
	../shtool version -l c -s @VERSION@ -n OpenSCEP -p openscep_ 	\
		openscep_vers.c
