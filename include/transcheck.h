/*
 * transcheck.h -- check the state of the current transaction
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: transcheck.h,v 1.1 2002/02/19 23:40:05 afm Exp $
 */
#ifndef _TRANSCHECK_H
#define _TRANSCHECK_H

#include <scep.h>

extern int	transcheck_granted(scep_t *scep);
extern int	transcheck_pending(scep_t *scep);
extern int	transcheck_rejected(scep_t *scep);

#endif /* _TRANSCHECK_H */
