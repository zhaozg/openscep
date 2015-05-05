/*
 * getcertinitial.c -- handle a GetCertInitial message
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: getcertinitial.c,v 1.4 2002/02/19 23:40:06 afm Exp $
 */
#include <stdlib.h>
#include <stdio.h>
#include <scep.h>
#include <init.h>
#include <getcertinitial.h>
#include <goodreply.h>
#include <badreply.h>
#include <config.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * there are the following possible reactions to a GetCertInitial
 * request
 * - if the certificate has been granted, it can be returned to the
 *   caller
 * - if the certificate is still pending, a pending reply is sent to
 *   the caller
 * - if the certificate was rejected, a failure reply is sent to the
 *   caller
 */
int	getcertinitial(scep_t *scep) {
	char		filename[1024];
	struct stat	sb;
	scepmsg_t	*msg;
	int		havereq = 0;

	if (debug)
		BIO_printf(bio_err, "%s:%d: handling GetCertInitial\n",
			__FILE__, __LINE__);
	msg = &scep->request;

	/* check whether the certificate request for this transaction	*/
	/* has already been rejected					*/
	if (transcheck_rejected(scep)) {
		badreply(scep, SCEP_PKISTATUS_FAILURE);
		return 0;
	}

	/* find out whether the certificate request is still around, so	*/
	/* that we can retrieve the challengePassword from it if we	*/
	/* want to set the password in the LDAP directory based on the	*/
	/* challenge, the request can be in one of two places: either	*/
	/* the cert was already signed, then it is in the granted 	*/
	/* directory, or it wasn't, then the request is in the pending	*/
	/* directory							*/
	scep->clientreq = NULL;
	if (transcheck_granted(scep)) {
		goodreply(scep, 1);
		return 0;
	}
	
	/* check whether the certificate request for this transaction 	*/
	/* id is still pending						*/
	if (transcheck_pending(scep)) {
		badreply(scep, SCEP_PKISTATUS_PENDING);
		return 0;
	}

	/* it may be the case that the certificate is only known to	*/
	/* the directory, in which case we should retrieve it based	*/
	/* on issuer and subject					*/

	/* XXX missing XXX missing XXX missing				*/

	BIO_printf(bio_err, "%s:%d: don't really know what to do\n",
		__FILE__, __LINE__);
	return -11;
}
