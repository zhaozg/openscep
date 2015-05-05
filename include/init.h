/*
 * init.h -- common library initializations used in all programs that
 *           work with openssl
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: init.h,v 1.3 2001/03/11 14:58:52 afm Exp $
 */
#ifndef _INIT_H
#define _INIT_H

#include <openssl/bio.h>
#include <scep.h>

extern int	debug;
extern char	*tmppath;
extern BIO	*bio_err;

extern int	scepinit(void);
extern int	scep_config(scep_t *scep, char *configfile);
extern void	scep_clear(scep_t *scep);

#endif /* _INIT_H */
