/*
 * goodreply.c -- return a certificate to a SCEP client
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: goodreply.c,v 1.6 2002/02/19 23:40:06 afm Exp $
 */
#include <config.h>
#include <goodreply.h>
#include <badreply.h>
#include <init.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <syslog.h>
#include <scepldap.h>
#include <encode.h>

/*
 * create a PKCS structure containing only the newly issued certificate
 *
 * note that we don't have to do anything special for v2 requests, as the
 * PKCS7 reply is not encrypted, only signed. The public key of the SCEP
 * client does not enter into the equation.
 */
int	goodreply(scep_t *scep, int store) {
	char		filename[1024];
	BIO		*certbio;
	scepmsg_t	*reply;

	reply = &scep->reply;

	/* message to the debugger					*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: preparing a SUCCESS reply\n",
			__FILE__, __LINE__);

	/* global things to set						*/
	reply->pkiStatus = SCEP_PKISTATUS_SUCCESS;

	/* get hold of the certificate of the caller			*/
	snprintf(filename, sizeof(filename), "%s/granted/%s.der", OPENSCEPDIR,
		scep->transId);
	if (debug)
		BIO_printf(bio_err, "%s:%d: granted certificate in %s\n",
			__FILE__, __LINE__, filename);
	if (NULL == (certbio = BIO_new(BIO_s_file()))) {
		BIO_printf(bio_err, "%s:%d: cannot allocate bio to read cert\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (BIO_read_filename(certbio, filename) <= 0) {
		BIO_printf(bio_err, "%s:%d: cannot open cert file\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* add the certificate to the scep structure			*/
	scep->clientcert = d2i_X509_bio(certbio, NULL);
	if (scep->clientcert == NULL) {
		reply->failinfo = SCEP_FAILURE_BADCERTID;
		badreply(scep, SCEP_PKISTATUS_FAILURE);
		return 0;
	}

	/* log the certificate reply					*/
	do {
		char	client[1024];
		X509_NAME_oneline(X509_get_subject_name(scep->clientcert),
			client, sizeof(client));
		syslog(LOG_INFO, "%s:%d: sending certificate to %s",
			__FILE__, __LINE__, client);
	} while (0 == 1);

	/* if asked to do so, store the thing in the directory		*/
	if (ldap_store_cert(scep) < 0) {
		BIO_printf(bio_err, "%s:%d: there was a problem storing the "
			"certificate in the directory\n", __FILE__, __LINE__);
		goto err;
	}

	/* create a new signed data PKCS#7				*/
	reply->rd.p7 = PKCS7_new();
	PKCS7_set_type(reply->rd.p7, NID_pkcs7_signed);
	PKCS7_content_new(reply->rd.p7, NID_pkcs7_data);
	PKCS7_add_certificate(reply->rd.p7, scep->clientcert);
	PKCS7_add_certificate(reply->rd.p7, scep->cacert);
/*
	PKCS7_add_signature(reply->rd.p7, scep->cacert, scep->capkey,
		EVP_md5());
*/

	/* encoding is done after return				*/
	return 0;
	
	/* if we get to this point, then we are not quite satisfied	*/
err:
	ERR_print_errors(bio_err);
	syslog(LOG_ERR, "%s:%d: goodreply failed to prepare a reply",
		__FILE__, __LINE__);
	return -1;
}
