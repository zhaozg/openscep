#
# Makefile.am -- generate the Makefile to build the main scep process
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.9 2002/01/11 17:07:49 afm Exp $
#
EXTRA_DIST = scepgrant.in scepreject.in updatecrl.in createcrl.in
SCRIPT = scepgrant scepreject updatecrl createcrl

bin_PROGRAMS = derdump scepconf sceplist
sbin_PROGRAMS = scepd crl2ldap dn2xid cafingerprint

derdump_SOURCES = derdump.c
scepconf_SOURCES = scepconf.c

scepd_SOURCES = scepd.c
crl2ldap_SOURCES = crl2ldap.c
dn2xid_SOURCES = dn2xid.c
sceplist_SOURCES = sceplist.c
cafingerprint_SOURCES = cafingerprint.c

OPENSSLDIR = @OPENSSLDIR@
OPENSCEPDIR = @OPENSCEPDIR@
USER = @USER@
GROUP = @GROUP@
CAUSER = @CAUSER@
CAGROUP = @CAGROUP@

LIBS = @LIBS@

LDADD = ../lib/libscep.la
LDFLAGS = -R$(libdir)

CPPFLAGS = -DOPENSCEPDIR=\"$(OPENSCEPDIR)\"

INCLUDES = $(INCLTDL) -I$(top_srcdir)/include -I$(OPENSSLDIR)/include

all-local:	scepgrant scepreject updatecrl createcrl

scepgrant:	scepgrant.in ../config.sh
	sh ../config.sh <scepgrant.in >scepgrant
scepreject:	scepreject.in ../config.sh
	sh ../config.sh <scepreject.in >scepreject
updatecrl:	updatecrl.in ../config.sh
	sh ../config.sh <updatecrl.in >updatecrl
createcrl:	createcrl.in ../config.sh
	sh ../config.sh <createcrl.in >createcrl

install-exec-local:	$(SCRIPT)
	for f in $(SCRIPT); do						\
		../shtool install -o $(USER) -g $(GROUP) -m 0755 $${f} 	\
			${sbindir} ;					\
	done

test:	scepd
	./scepd -d -f `pwd`/../openssl/openscep.cnf
