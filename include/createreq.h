/*
 * createreq.h -- create a certification request in PKCS10 format,
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: createreq.h,v 1.1 2001/03/05 12:03:47 afm Exp $
 */
#ifndef _CREATEREQ_H
#define _CREATEREQ_H

#include <scep.h>

extern int	createreq(scep_t *scep, char *dn, char *challenge);

#endif /* _CREATEREQ_H */
