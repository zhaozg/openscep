#!/bin/sh
#
# this script is here to work arround the problem that man2html is
# not a standard componente of every unix system. So we just touch
# the html files if the Makefile tries to rebuild them.
#
# (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
#
# $Id: man2html.sh,v 1.1 2001/03/18 22:09:10 afm Exp $
#
if type man2html 2>&1 >/dev/null
then
	tbl $1 | nroff -man | man2html > $2
else
	touch $2
	exit 0
fi
