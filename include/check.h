/*
 * check.h -- verify a client during automatic enrollment
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: check.h,v 1.2 2001/03/11 14:58:52 afm Exp $
 */
#ifndef _CHECK_H
#define _CHECK_H

#include <scep.h>

extern char	*get_challenge(scep_t *scep);
extern int	check_challenge(scep_t *scep);

#endif /* _CHECK_H */
