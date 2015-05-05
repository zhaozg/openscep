/*
 * pkcsreq.c -- handle a PKCS request
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: pkcsreq.c,v 1.11 2002/02/19 23:40:06 afm Exp $
 */
#include <config.h>
#include <init.h>
#include <pkcsreq.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <fingerprint.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <goodreply.h>
#include <badreply.h>
#include <grant.h>
#include <check.h>
#include <transcheck.h>
#include <pending.h>

int	pkcsreq(scep_t *scep) {
	BIO		*outbio;
	char		filename[1024];	/* XXX should do something more	*/
					/* generic here			*/
	scepmsg_t	*msg;
	
	/* pkcsreq messages are created by the server			*/
	msg = &scep->request;

	/* debug message to inform debugger what we are doing		*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: handling PKCSreq message\n",
			__FILE__, __LINE__);

	/* compute the fingerprint of the data found in content/length	*/
	/* fields of the scep structure					*/
	scep->fingerprint = fingerprint(msg->data, msg->length);
	if (debug)
		BIO_printf(bio_err, "%s:%d: the request fingerprint is '%s'\n",
			__FILE__, __LINE__, scep->fingerprint);

	/* extract the public key from the X509_REQ, and fingerprint it	*/
	scep->keyfingerprt = x509_key_fingerprint(msg->rd.req);
	if (debug)
		BIO_printf(bio_err, "%s:%d: key fingerprint is %s\n", 
			__FILE__, __LINE__, scep->keyfingerprt);

	/* optionally check the key fingerprint matches the 		*/
	/*transaction id						*/
	if (scep->check_transid) {
		if (fingerprint_cmp(scep->keyfingerprt, scep->transId)) {
			BIO_printf(bio_err, "%s:%d: key fingerprint != "
				"transId\n", __FILE__, __LINE__);
			syslog(LOG_ERR, "%s:%d: fingerprint does not match "
				"transid", __FILE__, __LINE__);
			goto err;
		}
		if (debug)
			BIO_printf(bio_err, "%s:%d: key fingerprint matches "
				"transId %s\n", __FILE__, __LINE__,
				scep->transId);
	}

	/* check whether a certificate for the same key finerprint	*/
	/* has already been granted					*/
	if (transcheck_granted(scep))
		return goodreply(scep, 1);

	/* check for a request with the same transaction ID in the 	*/
	/* queue							*/
	if (transcheck_pending(scep))
		return badreply(scep, SCEP_PKISTATUS_PENDING);

	/* create a file containing the request description		*/
	create_pending(scep);

	/* remember the request through the pointer clientreq in the	*/
	/* SCEP structure						*/
	scep->clientreq = scep->request.rd.req;
	if (debug)
		BIO_printf(bio_err, "%s:%d: client request is at %p\n",
			__FILE__, __LINE__, scep->clientreq);

	/* write the request DER to a file with name <transId>.der	*/
	outbio = BIO_new(BIO_s_file());
	snprintf(filename, sizeof(filename), "%s/%s/%s.der", OPENSCEPDIR,
		"pending", scep->transId);
	BIO_write_filename(outbio, filename);
	if (i2d_X509_REQ_bio(outbio, msg->rd.req) <= 0) {
		BIO_printf(bio_err, "%s:%d: failed to write request to "
			"queue as %s\n", __FILE__, __LINE__, filename);
		syslog(LOG_ERR, "%s:%d: failed to write request to queue as %s",
			__FILE__, __LINE__, filename);
		goto err;
	}
	BIO_free(outbio);
	if (debug)
		BIO_printf(bio_err, "%s:%d: pending request written to %s\n",
			__FILE__, __LINE__, filename);

	/* handle automatic enrollment					*/
	if ((scep->automatic) && (scep->l.ldap != NULL)) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: automatic enrollment in "
				"effect\n", __FILE__, __LINE__);

		/* verify the caller					*/
		if (check_challenge(scep) == 0) {
			/* automatically grant the request		*/
			if (debug)
				BIO_printf(bio_err, "%s:%d: automatic grant\n",
					__FILE__, __LINE__);
			if (cert_grant(scep) < 0) {
				BIO_printf(bio_err, "%s:%d: grant failed\n",
					__FILE__, __LINE__);
				msg->failinfo =  SCEP_FAILURE_BADCERTID;
				badreply(scep, SCEP_PKISTATUS_FAILURE);
				return 0;
			}
			goodreply(scep, 1);
			return 0;
		}
	} else {
		BIO_printf(bio_err, "%s:%d: automatic enrollment disabled\n",
			__FILE__, __LINE__);
	}

	if (debug)
		BIO_printf(bio_err, "%s:%d: automatic enrollment "
			"denied\n", __FILE__, __LINE__);
	syslog(LOG_DEBUG, "%s:%d: automatic enrollment denied",
		__FILE__, __LINE__);

	/* prepare a pending reply					*/
	badreply(scep, SCEP_PKISTATUS_PENDING);
	return 0;

	/* but we may as well fail					*/
err:
	badreply(scep, SCEP_PKISTATUS_FAILURE);
	return 0;
}
