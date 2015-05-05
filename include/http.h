/*
 * http.h -- extremely simplified HTTP client implementation to post a
 *           request to a server and read a reply
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 * 
 * $Id: http.h,v 1.3 2002/02/19 23:40:04 afm Exp $
 */
#ifndef _HTTP_H
#define _HTTP_H

#include <scep.h>

extern char	*urlencode(const char *data);
extern int	parseurl(scep_t *scep, char *url);
extern BIO	*getrequest(scep_t *scep);

#endif /* _HTTP_H */
