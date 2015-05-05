/*
 * pending.c -- create a pending request in the queue
 * 
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: pending.c,v 1.1 2002/02/19 23:40:06 afm Exp $
 */
#include <pending.h>
#include <init.h>
#include <syslog.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <missl.h>

/*
 * a pending PKCS10 request consists simply in the requestors x509 request
 * in DER format and the info file
 */
static int	create_pending_pkcs10(scep_t *scep) {
	BIO		*outbio;
	char		filename[1024];
	int		rc = -1;

        /* write the request DER to a file with name <transId>.der      */
        outbio = BIO_new(BIO_s_file());
        snprintf(filename, sizeof(filename), "%s/%s/%s.der", OPENSCEPDIR,
                "pending", scep->transId);
        BIO_write_filename(outbio, filename);
        if (i2d_X509_REQ_bio(outbio, scep->requestorreq) <= 0) {
                BIO_printf(bio_err, "%s:%d: failed to write request to "
                        "queue as %s\n", __FILE__, __LINE__, filename);
                syslog(LOG_ERR, "%s:%d: failed to write request to queue as %s",                        __FILE__, __LINE__, filename);
                goto err;
        }
	rc = 0;
        if (debug)
                BIO_printf(bio_err, "%s:%d: pending request written to %s\n",
                        __FILE__, __LINE__, filename);
err:
        BIO_free(outbio);
	return rc;
}

static int 	create_pending_spki(scep_t *scep, X509_NAME *name) {
	char		filename[1024];
	int		rc = -1;

        /* write the request DER to a file with name <transId>.der      */
        snprintf(filename, sizeof(filename), "%s/%s/%s.spki", OPENSCEPDIR,
                "pending", scep->transId);
	if (spki2file(filename, name,
		scep->request.rd.payload->original->data,
		scep->request.rd.payload->original->length) < 0) {
                BIO_printf(bio_err, "%s:%d: failed to write request to "
                        "queue as %s\n", __FILE__, __LINE__, filename);
                syslog(LOG_ERR, "%s:%d: failed to write request to queue as %s",                        __FILE__, __LINE__, filename);
                goto err;
        }
	rc = 0;
        if (debug)
                BIO_printf(bio_err, "%s:%d: pending request written to %s\n",
                        __FILE__, __LINE__, filename);
err:
	return rc;
}

/*
 * extract the request from the payload
 */
void	pending_get_request(scep_t *scep) {
	/* traditional SCEP requests contain a PKCS10 request		*/
	if (atoi(scep->request.messageType) == MSG_PKCSREQ) {
		scep->clientreq = scep->request.rd.req;
		return;
	}

	/* new requests have the request buried in the payload		*/
	switch (payload_get_requesttype(scep->request.rd.payload)) {
	case 0:
		scep->requestorreq = payload_getreq(scep->request.rd.payload);
		break;
	case 1:
		scep->requestorspki = payload_getspki(scep->request.rd.payload);
		break;
	}
}

/*
 * get the subject name from the request
 */
X509_NAME	*pending_getsubject(scep_t *scep) {
	STACK_OF(X509_ATTRIBUTE)	*attrs;

	/* try to extract the distinguished name from the request	*/
	if (scep->requestorreq != NULL) {
		/* the X509 name can be extracted directly		*/
		if (debug)
			BIO_printf(bio_err, "%s:%d: extracting DN from "
				"request\n", __FILE__, __LINE__);

		return X509_REQ_get_subject_name(scep->requestorreq);
	} else {
		/* for spki requests, use the attributes		*/
		if (debug)
			BIO_printf(bio_err, "%s:%d: extracting DN from "
				"attributes\n", __FILE__, __LINE__);
		attrs = scep->request.rd.payload->attributes;
		return x509_name_from_attributes(attrs);
	}
}

/*
 * create a pending request, i.e. write the following stuff to the pending
 * directory:
 */
int	create_pending(scep_t *scep) {
	X509_NAME	*sn;
	char		subject[1024];
	int		i;
	char		filename[1024];
	BIO		*outbio;

	/* make sure we have the requestor extracted			*/
	pending_get_request(scep);

	/* make sure we have the subject name				*/
	sn = pending_getsubject(scep);
	if (debug)
		BIO_printf(bio_err, "%s:%d: subject name is @%p\n",
			__FILE__, __LINE__, sn);

	/* save the requests in the pending directory			*/
	if (scep->requestorreq)
		create_pending_pkcs10(scep);
	if (scep->requestorspki)
		create_pending_spki(scep, sn);

	/* info file containing some textual information about the	*/
	/* request							*/
	snprintf(filename, sizeof(filename), "%s/%s/%s.info", OPENSCEPDIR,
		"pending", scep->transId);
	if (debug)
		BIO_printf(bio_err, "%s:%d: creating info file %s\n",
			__FILE__, __LINE__, filename);
	outbio = BIO_new(BIO_s_file());
	BIO_write_filename(outbio, filename);

	/* the subject name comes from the request (PKCS#10) or from	*/
	/* the attributes						*/
	X509_NAME_oneline(sn, subject, sizeof(subject));
	BIO_printf(outbio, "subject: %s\n", subject);

	/* transaction ID and sender nonce were set by the client	*/
	BIO_printf(outbio, "transId: %s\n", scep->transId);
	BIO_printf(outbio, "senderNonce: ");
	for (i = 0; i < scep->senderNonceLength; i++) {
		BIO_printf(outbio, "%02X", scep->senderNonce[i]);
	}
	BIO_printf(outbio, "\n");

	/* key fingerprints are nice to have, but there origin is 	*/
	/* unclear							*/
	BIO_printf(outbio, "fingerprint: %s\n", scep->fingerprint);
	BIO_printf(outbio, "keyfingerprint: %s\n", scep->keyfingerprt);
	BIO_free(outbio);

	/* return success						*/
	return 0;
}

