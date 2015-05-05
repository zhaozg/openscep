/*
 * fingerprint.h
 * 
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: fingerprint.h,v 1.2 2001/03/05 12:03:47 afm Exp $
 */
#ifndef _FINGERPRINT_H
#define _FINGERPRINT_H

#include <openssl/x509.h>

extern int	fingerprint_cmp(const char *f1, const char *f2);
extern char	*fingerprint(unsigned char *data, int length);
extern char	*x509_key_fingerprint(X509_REQ *req);
extern char	*key_fingerprint(EVP_PKEY *req);
extern void	fingerprint_blanks(int);

#endif /* _FINGERPRINT_H */
