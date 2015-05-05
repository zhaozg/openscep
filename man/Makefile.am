#
# Makefile.am -- create the Makefile for the manual page directory
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.10 2001/05/07 00:07:50 afm Exp $
#
man_MANS = scepd.8 scepgrant.8 scepreject.8 derdump.1 			\
	scepconf.1 openscep.cnf.5 crl2ldap.8 dn2xid.8			\
	scep.1 scepclient.1 sceplist.1 scepxid.1 updatecrl.8		\
	createcrl.8 cafingerprint.8
EXTRA_DIST = scepd.8.in scepgrant.8.in scepreject.8.in derdump.1.in	\
	scepconf.1.in openscep.cnf.5.in crl2ldap.8.in dn2xid.8.in	\
	scep.1.in scepclient.1.in sceplist.1.in scepxid.1.in		\
	updatecrl.8.in createcrl.8.in cafingerprint.8.in		\
	$(man_MANS)

scepd.8:	scepd.8.in ../config.sh
	sh ../config.sh <scepd.8.in >scepd.8

scepgrant.8:	scepgrant.8.in ../config.sh
	sh ../config.sh <scepgrant.8.in >scepgrant.8

scepreject.8:	scepreject.8.in ../config.sh
	sh ../config.sh <scepreject.8.in >scepreject.8

derdump.1:	derdump.1.in ../config.sh
	sh ../config.sh <derdump.1.in >derdump.1

scepconf.1:	scepconf.1.in ../config.sh
	sh ../config.sh <scepconf.1.in >scepconf.1

openscep.cnf.5:	openscep.cnf.5.in ../config.sh
	sh ../config.sh <openscep.cnf.5.in >openscep.cnf.5

crl2ldap.8:	crl2ldap.8.in ../config.sh
	sh ../config.sh <crl2ldap.8.in >crl2ldap.8

dn2xid.8:	dn2xid.8.in ../config.sh
	sh ../config.sh <dn2xid.8.in >dn2xid.8

scep.1:	scep.1.in ../config.sh
	sh ../config.sh <scep.1.in >scep.1

scepclient.1:	scepclient.1.in ../config.sh
	sh ../config.sh <scepclient.1.in >scepclient.1

sceplist.1:	sceplist.1.in ../config.sh
	sh ../config.sh <sceplist.1.in >sceplist.1

scepxid.1:	scepxid.1.in ../config.sh
	sh ../config.sh <scepxid.1.in >scepxid.1

updatecrl.8:	updatecrl.8.in ../config.sh
	sh ../config.sh <updatecrl.8.in >updatecrl.8

createcrl.8:	createcrl.8.in ../config.sh
	sh ../config.sh <createcrl.8.in >createcrl.8

cafingerprint.8:	cafingerprint.8.in ../config.sh
	sh ../config.sh <cafingerprint.8.in >cafingerprint.8

