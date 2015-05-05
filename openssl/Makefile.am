#
# Makefile.am -- create the Makefile for the openssl directory of the
#                OpenSCEP distribution
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.5 2001/03/26 10:36:44 afm Exp $
#
EXTRA_DIST = README openscepsetup.in openscep.cnf.in v3_alt.c.diff
OPENSCEPDIR = @OPENSCEPDIR@
CAOWNER = @CAOWNER@
CAGROUP = @CAGROUP@

all-local:	openscepsetup openscep.cnf

openscepsetup:	openscepsetup.in ../config.sh
	sh ../config.sh <openscepsetup.in >openscepsetup
openscep.cnf:	openscep.cnf.in ../config.sh
	sh ../config.sh <openscep.cnf.in >openscep.cnf

install-exec-local:	openscepsetup
	cp openscepsetup $(sbindir)
	chmod 755 $(sbindir)/openscepsetup

install-data-local:	openscep.cnf
	if [ ! -d $(OPENSCEPDIR) ];					\
	then								\
		mkdir -p $(OPENSCEPDIR);				\
		chown $(CAOWNER) $(OPENSCEPDIR);			\
		chgrp $(CAGROUP) $(OPENSCEPDIR);			\
		chmod 1755 $(OPENSCEPDIR);				\
	fi
	@if [ -f $(OPENSCEPDIR)/openscep.cnf ]; 			\
	then								\
		echo preserving existing openscep.cnf;			\
		cp openscep.cnf $(OPENSCEPDIR)/openscep.cnf.dist;	\
	else								\
		echo installing openscep.cnf;				\
		cp openscep.cnf $(OPENSCEPDIR);				\
	fi

