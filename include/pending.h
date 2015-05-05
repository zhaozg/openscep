/*
 * pending.h -- create a pending request in the queue
 * 
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: pending.h,v 1.1 2002/02/19 23:40:05 afm Exp $
 */
#ifndef _PENDING_H
#define _PENDING_H

#include <scep.h>
#include <openssl/x509.h>

extern void		pending_get_request(scep_t *scep);
extern X509_NAME	*pending_getsubject(scep_t *scep);
extern int		create_pending(scep_t *scep);

#endif /* _PENDING_H */
