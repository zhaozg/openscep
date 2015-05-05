/*
 * selfsigned.c -- create a self signed certificate from a request and a
 *                 private key
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: selfsigned.h,v 1.1 2001/03/05 12:03:47 afm Exp $
 */
#ifndef _SELFSIGNED_H
#define _SELFSIGNED_H

#include <scep.h>

extern int	selfsigned(scep_t *scep);

#endif /* _SELFSIGNED_H */
