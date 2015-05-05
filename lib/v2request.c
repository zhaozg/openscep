/*
 * v2request.c -- handle a request with a v2 payload
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: v2request.c,v 1.1 2002/02/19 23:40:07 afm Exp $
 */
#include <v2request.h>
#include <transcheck.h>
#include <pending.h>
#include <goodreply.h>
#include <badreply.h>
#include <init.h>

int	v2request(scep_t *scep) {
	if (debug)
		BIO_printf(bio_err, "%s:%d: processing v2 request\n",
			__FILE__, __LINE__);
	/* first find out whether there is a pending/granded/rejected	*/
	/* thingy for the transaction ID of this request, in which case	*/
	/* we send the appropriate reply				*/
	if (transcheck_granted(scep)) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: sending CERT reply\n",
				__FILE__, __LINE__);
		return goodreply(scep, 1);
	}

	if (transcheck_pending(scep)) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: sending pending reply\n",
				__FILE__, __LINE__);
		return badreply(scep, SCEP_PKISTATUS_PENDING);
	}

	if (transcheck_rejected(scep)) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: sending rejected reply\n",
				__FILE__, __LINE__);
		return badreply(scep, SCEP_PKISTATUS_FAILURE);
	}

	/* further processing is very similar to what happens in the	*/
	/* pkcsreq method						*/
	if (create_pending(scep) < 0) {
		BIO_printf(bio_err, "%s:%d: failed to create pending\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* handle automatic enrollment					*/
	if ((scep->automatic) && (scep->l.ldap != NULL)) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: automatic enrollment in "
				"effect\n", __FILE__, __LINE__);
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: automatic enrollment denied\n",
			__FILE__, __LINE__);

	/* prepare a pending reply					*/
	badreply(scep, SCEP_PKISTATUS_PENDING);
	return 0;

err:
	badreply(scep, SCEP_PKISTATUS_FAILURE);
	return 0;
}
