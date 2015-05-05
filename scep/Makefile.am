#
# Makefile.am -- generate Makefile to build scep client and other client 
#                oriented auxiliary files
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: Makefile.am,v 1.13 2002/02/24 21:40:01 afm Exp $
#
EXTRA_DIST = README scepkey.in scepclient.in test1.key test2.key

GROUP = @GROUP@
USER = @USER@
CAGROUP = @CAGROUP@
CAUSER = @CAUSER@

CACERT = @OPENSCEPDIR@/cacert.pem

bin_PROGRAMS = scep scepxid

scep_SOURCES = scep.c
scepxid_SOURCES = scepxid.c

SCRIPT = scepkey scepclient

LIBS = @LIBS@

LDADD = ../lib/libscep.la

INCLUDES = $(INCLTDL) -I$(top_srcdir)/include -I$(OPENSSLDIR)/include

all-local:	scepkey scepclient

scepkey:	../config.sh scepkey.in
	sh ../config.sh <scepkey.in >scepkey
scepclient:	../config.sh scepclient.in
	sh ../config.sh <scepclient.in >scepclient

install-exec-local:	$(SCRIPT)
	for f in $(SCRIPT); do						\
		../shtool install -o $(USER) -g $(GROUP) -m 0755 $${f} 	\
			${bindir} ;					\
	done

# test1	creates a version1 request from a valid X509 request. Automatic
#	enrollment can only work if a challenge password attribute is 
#	included with the request
test1:	scep test1.key test1.req
	./scep -d -k test1.key -r test1.req				\
		-c $(CACERT) 
test1-poll:	scep test1.key test1.req
	./scep -d -p -k test1.key -r test1.req				\
		-c $(CACERT) 

# test2	creates a version2 request from a valid X509 request for the SCEP
#	client and an end entity request. The challenge password for auto-
#	matic enrollment must be included in the end entity request.
test2:	scep test1.key test1.req test2.req
	./scep -d -k test1.key -r test1.req				\
		-c $(CACERT)						\
		-2 -e test2.req -q cvurg3nfnbvbt75
test2-poll:	scep test1.key test1.req test2.req
	./scep -d -p -k test1.key -r test1.req				\
		-c $(CACERT)						\
		-2 -e test2.req -q cvurg3nfnbvbt75

# test3	creates a version2 request from a Netscape SPKI request, distinguished
#	name components are converted to attributes in the payload.
#	For automatic enrollment, the challenge must be set to the
#	challenge password
test3:	scep test1.key test1.req test3.spki
	./scep -d -k test1.key -r test1.req				\
		-c $(CACERT)						\
		-2 -a test3.spki -q cvurg3nfnbvbt75			\
		"CN=Lukas Mueller,O=Othello,C=CH"
test3-poll:	scep test1.key test1.req test3.spki
	./scep -d -p -k test1.key -r test1.req				\
		-c $(CACERT)						\
		-2 -a test3.spki -q cvurg3nfnbvbt75			\
		"CN=Lukas Mueller,O=Othello,C=CH"

