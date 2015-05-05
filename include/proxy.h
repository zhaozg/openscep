/* 
 * proxy.h -- handle proxy requests
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: proxy.h,v 1.1 2002/02/19 23:40:05 afm Exp $
 */
#ifndef _PROXY_H
#define _PROXY_H

#include <openssl/asn1.h>

extern ASN1_OCTET_STRING	*proxy_authenticator(scepmsg_t *msg,
					char *community);
extern int	proxy_check(scep_t *scep, scepmsg_t *msg,
			ASN1_OCTET_STRING *auth);

#endif /* _PROXY_H */
