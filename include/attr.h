/*
 * attr.h -- some attribute handling utilities
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: attr.h,v 1.1.1.1 2001/03/03 22:18:47 afm Exp $
 */
#ifndef _ATTR_H
#define _ATTR_H

#include <openssl/x509.h>

extern int	attr_add_string(STACK_OF(X509_ATTRIBUTE) *attrs, int nid,
		char *data);
extern int	attr_add_octet(STACK_OF(X509_ATTRIBUTE) *attrs, int nid,
		unsigned char *data, int len);

#endif /* _ATTR_H */
