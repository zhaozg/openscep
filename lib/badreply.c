/*
 * badreply.c -- formulate a pending or failure reply
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 * 
 * $Id: badreply.c,v 1.4 2001/03/14 01:27:42 afm Exp $
 */
#include <badreply.h>
#include <attr.h>
#include <init.h>
#include <openssl/evp.h>
#include <syslog.h>

int	badreply(scep_t *scep, char *pkistatus) {
	scepmsg_t			*reply;

	reply = &scep->reply;

	/* debugging							*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: preparing a bad reply of type %s\n",
			__FILE__, __LINE__, SCEP_STATUS(pkistatus));

	/* logging							*/
	syslog(LOG_WARNING, "%s:%d: sending bad reply of type %s", __FILE__,
		__LINE__, SCEP_STATUS(pkistatus));

	reply->pkiStatus = pkistatus;
	if ((!reply->failinfo)
		&& SCEP_PKISTATUS_is(SCEP_PKISTATUS_FAILURE, pkistatus))
		reply->failinfo = SCEP_FAILURE_BADREQUEST;

	/* we don't have to do anything else, encode will do the pkging	*/

	/* ok return							*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: PKCS7 ready to return\n",
			__FILE__, __LINE__);
	return 0;
}
