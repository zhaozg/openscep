/*
 * missl.h -- macros missing from OpenSSL
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: missl.h,v 1.1 2002/02/19 23:40:04 afm Exp $ 
 */
#ifndef _MISSL_H
#define _MISSL_H

#ifndef d2i_NETSCAPE_SPKAC_bio
#define d2i_NETSCAPE_SPKAC_BIO(bp, ns)					\
	(NETSCAPE_SPKAC *)ASN1_d2i_bio(					\
		(char *(*)())NETSCAPE_SPKAC_new,			\
		(char *(*)())d2i_NETSCAPE_SPKAC, (bp),			\
		(unsigned char **)ns)
#endif

#ifndef i2d_NETSCAPE_SPKAC_bio
#define i2d_NETSCAPE_SPKAC_bio(bp, ns)					\
	ASN1_i2d_bio(i2d_NETSCAPE_SPKAC, bp, (unsigned char *)ns)
#endif

#ifndef d2i_NETSCAPE_SPKI_bio
#define d2i_NETSCAPE_SPKI_bio(bp, ns)					\
	(NETSCAPE_SPKI *)ASN1_d2i_bio(					\
		(char *(*)())NETSCAPE_SPKI_new,				\
		(char *(*)())d2i_NETSCAPE_SPKI, (bp),			\
		(unsigned char **)ns)
#endif

#ifndef i2d_NETSCAPE_SPKI_bio
#define i2d_NETSCAPE_SPKI_bio(bp, ns)					\
	ASN1_i2d_bio(i2d_NETSCAPE_SPKI, bp, (unsigned char *)ns)
#endif

#endif /* _MISSL_H */
