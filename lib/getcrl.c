/*
 * getcrl.c -- handle a GetCRL message
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: getcrl.c,v 1.8 2001/03/14 01:03:19 afm Exp $
 */
#include <getcrl.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <init.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <errno.h>
#include <string.h>
#include <encode.h>

/*
 * the GetCRL message presents the request for the current CRL
 * by the data identifying the CA issueing the CRL. This usually
 * is the CA issuer distinguished name and the serial number of
 * the CA ceritificate. If the CRL distribution point is supported,
 * the CRL request includes the CRL distribution point (there may
 * be only one).
 */
int	getcrl(scep_t *scep) {
	PKCS7_ISSUER_AND_SERIAL	*ias;
	X509			x;
	X509_CINF		cinf;
	scepmsg_t		*request, *reply;

	request = &scep->request;
	reply = &scep->reply;

	/* the reply to a GetCRL will always be a CertRep		*/
	reply->messageType = SCEP_MESSAGE_TYPE_CERTREP;
	reply->pkiStatus = SCEP_PKISTATUS_FAILURE;
	if (debug)
		BIO_printf(bio_err, "%s:%d: preparing a CertRep message with "
			"CRL\n", __FILE__, __LINE__);

	/* first write the content of the message to a file for debug	*/
	/* purposes							*/
	if ((debug) && (tmppath)) {
		char	filename[1024];
		int	fd;
		snprintf(filename, sizeof(filename),
			"%s/getcrl.%d", tmppath, getpid());
		fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0666);
		if (fd < 0) {
			BIO_printf(bio_err, "%s:%d: cannot open file: "
				"%s (%d)\n", __FILE__, __LINE__,
				strerror(errno), errno);
			goto err;
		}
		if (request->length != write(fd, request->data, request->length)) {
			BIO_printf(bio_err, "%s:%d: failed to write request: "
				"%s (%d)\n", __FILE__, __LINE__,
				strerror(errno), errno);
			goto err;
		}
		BIO_printf(bio_err, "%s:%d: CetCRL request written to %s\n",
			__FILE__, __LINE__, filename);
		close(fd);
	}

	/* find out what kind of request this is issuer and serial only	*/
	/* or a request including the CRL distribution point, we assume	*/
	/* the first case, i.e. that the thing was already unpacked, in	*/
	/* the decode function before this was called			*/
	ias = request->rd.iser;
	if (ias == NULL) {
		BIO_printf(bio_err, "%s:%d: request seems to b lacking an "
			"issuer and serial field\n", __FILE__, __LINE__);
		goto err;
	}
	
	/* we only have one CA certificate in our current implemen-	*/
	/* tation, so we only have to check that the CRL requests	*/
	/* asks for the CRL of _our_ CA. This code isn't too good style	*/
	/* as it uses OpenSSL data stractures, not macros.		*/
	x.cert_info = &cinf;
	cinf.serialNumber = ias->serial;
	cinf.issuer = ias->issuer;
	if ((cinf.issuer == NULL) || (cinf.serialNumber == NULL)) {
		BIO_printf(bio_err, "%s:%d: issuer and serial seems to be "
			"incomplete\n", __FILE__, __LINE__);
		goto err;
	}
	if (X509_issuer_and_serial_cmp(scep->cacert, &x) != 0) {
		char	dn1[1024], dn2[1024];
		X509_NAME_oneline(ias->issuer, dn1, sizeof(dn1));
		X509_NAME_oneline(X509_get_issuer_name(scep->cacert), dn2,
			sizeof(dn2));
		BIO_printf(bio_err, "%s:%d: issuer and serial don't match: "
			"%s, %s\n", __FILE__, __LINE__, dn1, dn2);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: the request matches our CRL\n",
			__FILE__, __LINE__);
	
	/* we already have the CRL handy, so we simply have to build 	*/
	/* suitable reply message, which we then envelope and sign by	*/
	/* the standard encode method					*/
	reply->rd.p7 = PKCS7_new();
	PKCS7_set_type(reply->rd.p7, NID_pkcs7_signed);
	PKCS7_content_new(reply->rd.p7, NID_pkcs7_data);
	PKCS7_add_crl(reply->rd.p7, scep->crl);
	if (debug)
		BIO_printf(bio_err, "%s:%d: PKCS#7 containing CRL created\n",
			__FILE__, __LINE__);

	/* we have to decide which certificate should be used to 	*/
	/* encrypt the reply. If the sender used a self signed 		*/
	/* certificate to sign his request, we use it to encrypt the	*/
	/* reply. If the sender used her real ceritficat, we can use	*/
	/* that one. But as this decision is the same in all protocol	*/
	/* handlers, encode should do it				*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: have clientcert at %p and self "
			"signed cert at %p\n", __FILE__, __LINE__,
			scep->clientcert, scep->selfsignedcert);

	/* nothing more to be done					*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: GetCRL reply ready to send\n",
			__FILE__, __LINE__);

	reply->pkiStatus = SCEP_PKISTATUS_SUCCESS;
	return 0;
	/* error return							*/
err:
	ERR_print_errors(bio_err);
	return -1;
}
