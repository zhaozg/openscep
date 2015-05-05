#
# Makefile to build CGI programs used for the openscep system
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.4 2001/03/18 23:53:33 afm Exp $
#
EXTRA_DIST = scep.pl.in pending.pl.in log.pl.in add.pl.in crl.pl.in	\
	granted.pl.in rejected.pl.in revoked.pl.in

CGIDIR = @CGIDIR@
PKICLIENTEXE = @PKICLIENTEXE@
CGIINSTALLDIR = @CGIINSTALLDIR@

CGIS = pending.pl log.pl add.pl crl.pl granted.pl revoked.pl rejected.pl

all-local: $(CGIS) scep.pl

scep.pl:	scep.pl.in ../config.sh
	sh ../config.sh scep.pl.in >scep.pl
pending.pl:	pending.pl.in ../config.sh
	sh ../config.sh pending.pl.in >pending.pl
log.pl:	log.pl.in ../config.sh
	sh ../config.sh log.pl.in >log.pl
add.pl:	add.pl.in ../config.sh
	sh ../config.sh add.pl.in >add.pl
crl.pl:	crl.pl.in ../config.sh
	sh ../config.sh crl.pl.in >crl.pl
granted.pl:	granted.pl.in ../config.sh
	sh ../config.sh granted.pl.in >granted.pl
rejected.pl:	rejected.pl.in ../config.sh
	sh ../config.sh rejected.pl.in >rejected.pl
revoked.pl:	revoked.pl.in ../config.sh
	sh ../config.sh revoked.pl.in >revoked.pl

install-exec-local:	$(CGIS)
	if [ ! -d $(CGIINSTALLDIR) ];					\
	then								\
		mkdir -p $(CGIINSTALLDIR);				\
	fi
	for c in $(CGIS);						\
	do 								\
		cp $${c} $(CGIINSTALLDIR);  				\
		chmod 755 $(CGIINSTALLDIR)/$${c};			\
	done
	d=`dirname $(PKICLIENTEXE)`;					\
	if [ ! -d "$${d}" ];						\
	then								\
		mkdir -p $${d};						\
	fi
	cp scep.pl $(PKICLIENTEXE)
	chmod 755 $(PKICLIENTEXE)


