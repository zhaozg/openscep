/*
 * sigattr.h -- signed attribute mangling routines
 * 
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 * 
 * $Id: sigattr.h,v 1.2 2002/02/19 23:40:05 afm Exp $
 */
#ifndef _SIGATTR_H
#define _SIGATTR_H

#include <scep.h>

extern char		*sigattr_string(scep_t *, char *attrname);
extern unsigned char	*sigattr_octet(scep_t *, char *attrname, int *len);
extern ASN1_OCTET_STRING	*sigattr_asn1_octet(scep_t *, char *attrname);

#endif /* _SIGATTR_H */
