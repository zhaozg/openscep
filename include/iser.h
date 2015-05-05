/*
 * iser.h -- de- and encode issuer and serial from/to a bio
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: iser.h,v 1.2 2002/02/19 23:40:04 afm Exp $
 */
#ifndef _ISER_H
#define _ISER_H

#include <openssl/bio.h>
#include <openssl/pkcs7.h>

#if 0
extern PKCS7_ISSUER_AND_SERIAL	*d2i_PKCS7_ISSUER_AND_SERIAL_bio(
	PKCS7_ISSUER_AND_SERIAL **is, BIO *b);

extern int	i2d_PKCS7_ISSUER_AND_SERIAL_bio(BIO *b,
	PKCS7_ISSUER_AND_SERIAL *is);
#endif /* 0 */

#define	d2i_PKCS7_ISSUER_AND_SERIAL_bio(bp,p7)	\
		(PKCS7_ISSUER_AND_SERIAL *)ASN1_d2i_bio((char *(*)())\
		PKCS7_ISSUER_AND_SERIAL_new, \
		(char *(*)())d2i_PKCS7_ISSUER_AND_SERIAL, (bp),\
		(unsigned char **)(p7))
#define	i2d_PKCS7_ISSUER_AND_SERIAL_bio(bp,p7)	\
		ASN1_i2d_bio(i2d_PKCS7_ISSUER_AND_SERIAL, (bp),\
		 (unsigned char *)(p7))

#endif /* _ISER_H */
