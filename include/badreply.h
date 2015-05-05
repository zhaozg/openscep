/*
 * badreply.h -- formulate a pending or failure reply
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: badreply.h,v 1.1.1.1 2001/03/03 22:18:46 afm Exp $
 */
#ifndef _BADREPLY_H
#define _BADREPLY_H

#include <scep.h>

extern int	badreply(scep_t *scep, char *type);

#endif /* _BADREPLY_H */
