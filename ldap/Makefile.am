#
# Makefile.am -- generate Makefile for the LDAP subdirectory of the 
#                OpenSCEP project
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.6 2001/12/17 11:13:22 afm Exp $
#
EXTRA_DIST = README openscep.schema openscep.ldif.in base.ldif 		\
	slapd.conf.in setupldap.in

OPENSCEPDIR = @OPENSCEPDIR@

all-local:	openscep.ldif slapd.conf setupldap

install-data-local: openscep.ldif slapd.conf openscep.schema
	cp openscep.ldif $(OPENSCEPDIR)
	cp slapd.conf $(OPENSCEPDIR)
	cp openscep.schema $(OPENSCEPDIR)

openscep.ldif:	../config.sh openscep.ldif.in
	sh ../config.sh <openscep.ldif.in >openscep.ldif

slapd.conf:	slapd.conf.in
	sh ../config.sh <slapd.conf.in >slapd.conf

setupldap:	setupldap.in
	sh ../config.sh <setupldap.in >setupldap
