/*
 * getcert.c -- handle a GetCert message
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: getcert.c,v 1.5 2001/03/11 14:58:54 afm Exp $
 */
#include <config.h>
#include <getcert.h>
#include <init.h>
#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <scepldap.h>
#include <goodreply.h>

int	getcert(scep_t *scep) {
	PKCS7_ISSUER_AND_SERIAL	*ias;
	scepmsg_t		*msg;
	
	if (debug)
		BIO_printf(bio_err, "%s:%d: certificate access msg received\n",
			__FILE__, __LINE__);
	msg = &scep->request;

	/* write the content to a file for debugging purposes		*/
	if ((debug) && (tmppath)) {
		char	filename[1024];
		int	fd;
		snprintf(filename, sizeof(filename),
			"%s/getcert.%d", tmppath, getpid());
		fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0666);
		if (fd < 0) {
			BIO_printf(bio_err, "%s:%d: cannot open file %s: "
				"%s (%d)\n", filename, __FILE__, __LINE__,
				strerror(errno), errno);
			goto err;
		}
		if (msg->length != write(fd, msg->data, msg->length)) {
			BIO_printf(bio_err, "%s:%d: failed to completely write "
				"request: %s (%d)\n", __FILE__, __LINE__,
				strerror(errno), errno);
			goto err;
		}
		BIO_printf(bio_err, "%s:%d: GetCert request written to %s\n",
			__FILE__, __LINE__, filename);
		close(fd);
	}

	/* extract the issuer and serial information from the request	*/
	/* (this is identical to the GetCRL message handler)		*/
	ias = msg->rd.iser;
	if (debug) {
		char	issuer[1024];
		X509_NAME_oneline(ias->issuer, issuer, sizeof(issuer));
		BIO_printf(bio_err, "%s:%d: request for Cert from CA %s\n",
			__FILE__, __LINE__, issuer);
	}

	/* search the directory for the certificate with this issuer	*/
	/* distinguished name and serial number				*/
	if (ldap_get_cert_from_issuer_and_serial(scep, ias) < 0) {
		BIO_printf(bio_err, "%s:%d: certificate not found in "
			"directory\n", __FILE__, __LINE__);
		goto err;
	}

	/* the certificate is now in scep->clientcert			*/
	if (goodreply(scep, 0) < 0) {
		BIO_printf(bio_err, "%s:%d: preparing OK reply failed\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* pack as a reply message					*/
	return 0;

	/* error return							*/
err:
	ERR_print_errors(bio_err);
	return -1;
}
