#
# Makefile.am -- generate the Makefile for the HTML directory of the 
#                OpenSCEP project
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.6 2001/05/06 23:55:35 afm Exp $
#
IMAGES = openscep.png openscep.gif requests.gif crl.gif help.gif 	\
	add.gif log.gif granted.gif rejected.gif revoked.gif
PAGES = index.html welcome.html contents.html help.html title.html
INPAGES = $(PAGES:.html=.html.in)
MANPAGES = crl2ldap.8.html derdump.1.html dn2xid.8.html 		\
	openscep.cnf.5.html scep.1.html scepclient.1.html 		\
	scepconf.1.html scepd.8.html scepgrant.8.html sceplist.1.html	\
	scepreject.8.html scepxid.1.html updatecrl.8.html		\
	createcrl.8.html cafingerprint.8.html
EXTRA_DIST = $(INPAGES) $(IMAGES) $(MANPAGES) man2html.sh
all-local: $(PAGES) $(MANPAGES)

HTMLINSTALLDIR = @HTMLINSTALLDIR@

index.html:	index.html.in ../config.sh
	sh ../config.sh <index.html.in >index.html

welcome.html:	welcome.html.in ../config.sh
	sh ../config.sh <welcome.html.in >welcome.html

help.html:	help.html.in ../config.sh
	sh ../config.sh <help.html.in >help.html

contents.html:	contents.html.in ../config.sh
	sh ../config.sh <contents.html.in >contents.html

title.html:	title.html.in ../config.sh
	sh ../config.sh <title.html.in >title.html

install-data-local:	$(PAGES) $(IMAGES)
	if [ ! -d $(HTMLINSTALLDIR) ]; then mkdir -p $(HTMLINSTALLDIR); fi
	cp $(PAGES) $(IMAGES) $(MANPAGES) $(HTMLINSTALLDIR)

#
# HTML forms of the manual pages are distributed with the package, and
# are built from the manual sources in the man directory
#
crl2ldap.8.html:	../man/crl2ldap.8
	sh man2html.sh $< $@
derdump.1.html:	../man/derdump.1
	sh man2html.sh $< $@
dn2xid.8.html:	../man/dn2xid.8
	sh man2html.sh $< $@
openscep.cnf.5.html:	../man/openscep.cnf.5
	sh man2html.sh $< $@
scep.1.html:	../man/scep.1
	sh man2html.sh $< $@
scepclient.1.html:	../man/scepclient.1
	sh man2html.sh $< $@
scepconf.1.html:	../man/scepconf.1
	sh man2html.sh $< $@
scepd.8.html:	../man/scepd.8
	sh man2html.sh $< $@
scepgrant.8.html:	../man/scepgrant.8
	sh man2html.sh $< $@
sceplist.1.html:	../man/sceplist.1
	sh man2html.sh $< $@
scepreject.8.html:	../man/scepreject.8
	sh man2html.sh $< $@
scepxid.1.html:	../man/scepxid.1
	sh man2html.sh $< $@
updatecrl.8.html: ../man/updatecrl.8
	sh man2html.sh $< $@
createcrl.8.html: ../man/createcrl.8
	sh man2html.sh $< $@
cafingerprint.8.html: ../man/cafingerprint.8
	sh man2html.sh $< $@
