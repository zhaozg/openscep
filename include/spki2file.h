/*
 * spki2file.c -- convert an SPKI request and a X509_NAME into the input
 *                file openssl requires to grant an SPKI request
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: spki2file.h,v 1.1 2002/02/19 23:40:05 afm Exp $
 */
#ifndef _SPKI2FILE_H
#define _SPKI2FILE_H

#include <openssl/x509.h>

extern int	spki2file(char *filename, X509_NAME *name,
			unsigned char *spkidata, int spkilength);

#endif /* _SPKI2FILE_H */
