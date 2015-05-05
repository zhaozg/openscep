/*
 * decode.h -- decoding operations on PKCS#7 structures
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: decode.h,v 1.1.1.1 2001/03/03 22:18:46 afm Exp $
 */
#ifndef _DECODE_H
#define _DECODE_H

#include <scep.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>

extern int	decode(scep_t *, BIO *b);

#endif /* _DECODE_H */
