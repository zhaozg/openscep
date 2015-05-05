/*
 * encode.c -- pack a SCEP reply message
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: encode.c,v 1.12 2002/02/25 23:01:06 afm Exp $
 */
#include <encode.h>
#include <init.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <attr.h>
#include <unistd.h>
#include <fcntl.h>
#include <iser.h>
#include <proxy.h>

int	encode(scep_t *scep) {
	BIO				*inbio, *p7bio, *membio, *ebio,
					*b64, *outbio;
	PKCS7				*p7e;
	unsigned char			*enveloped = NULL;
	int				envelopedlen = 0, rc;
	STACK_OF(X509_ATTRIBUTE)	*attribs;
	STACK_OF(X509)			*recips;
	PKCS7_SIGNER_INFO		*si;
	scepmsg_t			*msg;
	EVP_PKEY			*signerpkey;
	X509				*signercert, *recipientcert;
	int				nMessageType = -1, nPkiStatus = -1,
					proxy = 0;
	X509_ATTRIBUTE			*auth;

	/* the client encodes the request, the server the reply		*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: encode of %s message\n",
			__FILE__, __LINE__,
			(scep->client) ? "client" : "server");
	if (scep->client)
		msg = &scep->request;
	else
		msg = &scep->reply;

	/* convert status to numeric form, for easier comparisons	*/
	if (msg->messageType)
		nMessageType = atoi(msg->messageType);
	if (msg->pkiStatus)
		nPkiStatus = atoi(msg->pkiStatus);

	/* decide about recipient and signer certs/keys			*/
	if (!((scep->clientcert)  || (scep->selfsignedcert))) {
		BIO_printf(bio_err, "%s:%d: no certificate to encrypt reply\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (scep->client) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: using CA cert for "
				"recipient\n", __FILE__, __LINE__);
		recipientcert = scep->cacert;
		if (debug)
			BIO_printf(bio_err, "%s:%d: using self signed cert "
				"for signature\n", __FILE__, __LINE__);
		signercert = scep->selfsignedcert;
		signerpkey = scep->clientpkey;
	} else {
		recipientcert = (scep->selfsignedcert)
				? scep->selfsignedcert : scep->clientcert;
		if (debug)
			BIO_printf(bio_err, "%s:%d: using %s cert for "
				"encryption (%p)\n", __FILE__, __LINE__,
				(scep->selfsignedcert)
					? "selfsigned" : "client",
				recipientcert);
		signercert = scep->cacert;
		signerpkey = scep->capkey;
		if (debug)
			BIO_printf(bio_err, "%s:%d: using CA cert for "
				"signature\n", __FILE__, __LINE__);
	}

	/* debug message about recipient				*/
	if ((debug) && (recipientcert)) {
		char	rec[1024];
		X509_NAME_oneline(X509_get_subject_name(recipientcert), rec,
			sizeof(rec));
		BIO_printf(bio_err, "%s:%d: encrypting for '%s'\n",
			__FILE__, __LINE__, rec);
	}

	/* create a memory be to later write the data to it		*/
	inbio = BIO_new(BIO_s_mem());
	if (debug)
		BIO_printf(bio_err, "%s:%d: writing a message of type %s, "
			"status %s\n", __FILE__, __LINE__,
			SCEP_TYPE(msg->messageType),
			SCEP_STATUS(msg->pkiStatus));
	switch (atoi(msg->messageType)) {
	case MSG_CERTREP:
		/* write the data to a buffer if there is something	*/
		if (msg->rd.p7)
			rc = i2d_PKCS7_bio(inbio, msg->rd.p7);
		else {
			if (debug)
				BIO_printf(bio_err, "%s:%d: there is no data "
					"to encode, jump to signed only\n",
					__FILE__, __LINE__);
			goto signedonly;
		}
		break;
	case MSG_V2PROXY:
		/* proxy request, need to add a proxy authenticator	*/
		/* attribute						*/
		proxy = 1;
	case MSG_V2REQUEST:
		/* convert the internal payload data into DER		*/
		if (debug)
			BIO_printf(bio_err, "%s:%d: converting v2 request\n",
				__FILE__, __LINE__);
		rc = i2d_payload_bio(inbio, msg->rd.payload);
		break;
	case MSG_PKCSREQ:
		if (debug)
			BIO_printf(bio_err, "%s:%d: converting X509 request\n",
				__FILE__, __LINE__);
		rc = i2d_X509_REQ_bio(inbio, msg->rd.req);
		if (rc <= 0) {
			BIO_printf(bio_err, "%s:%d: failed to write X509_REQ "
				"to bio\n", __FILE__, __LINE__);
			goto err;
		}
		break;
	case MSG_GETCERTINITIAL:
		/* must be implemented					*/
		rc = i2d_issuer_and_subject_bio(inbio, msg->rd.is);
		break;
	case MSG_GETCERT:
	case MSG_GETCRL:
		rc = i2d_PKCS7_ISSUER_AND_SERIAL_bio(inbio, msg->rd.iser);
		if (rc <= 0) {
			BIO_printf(bio_err, "%s:%d: cannot write issuer and "
				"serial to bio\n", __FILE__, __LINE__);
			goto err;
		}
		break;
	}
	BIO_flush(inbio);
	if (rc <= 0) {
		BIO_printf(bio_err, "%s:%d: cannot write interior data "
			"as DER\n", __FILE__, __LINE__);
		goto err;
	}

	/* get the memory from the memory bio				*/
	BIO_set_flags(inbio, BIO_FLAGS_MEM_RDONLY);
	msg->length = BIO_get_mem_data(inbio, &msg->data);
	BIO_free(inbio);
	if (debug)
		BIO_printf(bio_err, "%s:%d: payload to encrypt: %d bytes\n",
			__FILE__, __LINE__, msg->length);

	/* write data to envelope for debugging				*/
	if ((debug) && (tmppath)) {
		char	filename[1024];
		int	fd;
		snprintf(filename, sizeof(filename), "%s/%d.e-1-payload.der",
			tmppath, getpid());
		if ((fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0666)) >= 0){
			write(fd, msg->data, msg->length);
			close(fd);
		}
	}

	/* perform encryption						*/
	if (NULL == (recips = sk_X509_new(NULL))) {
		BIO_printf(bio_err, "%s:%d: cannot create recipient stack\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (sk_X509_push(recips, recipientcert) <= 0) {
		BIO_printf(bio_err, "%s:%d: adding recipient cert failed\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (debug) {
		char	recipientname[1024];
		X509_NAME_oneline(X509_get_subject_name(recipientcert),
			recipientname, sizeof(recipientname));
		BIO_printf(bio_err, "%s:%d: added recipient certificate for %s "
			"at %p\n", __FILE__, __LINE__,
			recipientname, recipientcert);
	}
	if (NULL == (ebio = BIO_new_mem_buf(msg->data, msg->length))) {
		BIO_printf(bio_err, "%s:%d: creating data bio failed\n",
			__FILE__, __LINE__);
		goto err;
	}
	p7e = PKCS7_encrypt(recips, ebio, EVP_des_cbc(), PKCS7_BINARY);
	if (p7e == NULL) {
		BIO_printf(bio_err, "%s:%d: encryption failed\n", __FILE__,
			__LINE__);
	}

	if (debug)
		BIO_printf(bio_err, "%s:%d: data encrypted\n", __FILE__,
			__LINE__);

	/* convert to a data block					*/
	membio = BIO_new(BIO_s_mem());
	if (i2d_PKCS7_bio(membio, p7e) <= 0) {
		BIO_printf(bio_err, "%s:%d: failed to write enveloped data\n",
			__FILE__, __LINE__);
		goto err;
	}
	BIO_flush(membio);
	BIO_set_flags(membio, BIO_FLAGS_MEM_RDONLY);
	envelopedlen = BIO_get_mem_data(membio, &enveloped);
	if (debug)
		BIO_printf(bio_err, "%s:%d: %d bytes of evenloped data at %p\n",
			__FILE__, __LINE__, envelopedlen, enveloped);
	BIO_free(membio);
	if ((debug) && (tmppath)) {
		char	filename[1024];
		int	fd;
		snprintf(filename, sizeof(filename), "%s/%d.e-2-enveloped.der",
			tmppath, getpid());
		if ((fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0666)) >= 0){
			write(fd, enveloped, envelopedlen);
			close(fd);
		}
	}

signedonly:
	/* sign for the same recipients					*/
	msg->p7 = PKCS7_new();
	if (msg->p7 == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot create PKCS#7 for sig\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (!PKCS7_set_type(msg->p7, NID_pkcs7_signed)) {
		BIO_printf(bio_err, "%s:%d: cannot set PKCS#7 type\n", 
			__FILE__, __LINE__);
		goto err;
	}
	if (!PKCS7_content_new(msg->p7, NID_pkcs7_data)) {
		BIO_printf(bio_err, "%s:%d: cannot set content type\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: PKCS#7 type and content set up\n",
			__FILE__, __LINE__);

	/* decide about sender certificate				*/
	if (signercert == NULL) {
		BIO_printf(bio_err, "%s:%d: no signer certificate\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* add signer private key					*/
	if (signerpkey == NULL) {
		BIO_printf(bio_err, "%s:%d: no signer key\n");
		goto err;
	}
	si = PKCS7_add_signature(msg->p7, signercert, signerpkey, EVP_md5());
	if (si == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot add sender signature\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: sender signature added\n", __FILE__,
			__LINE__);

	/* add the signer certificate, but only in requests and SUCCES 	*/
	/* responses							*/
	switch (nMessageType) {
	case MSG_CERTREP:
		if (nPkiStatus == PKI_SUCCESS) {
			PKCS7_add_certificate(msg->p7, scep->clientcert);
			PKCS7_add_certificate(msg->p7, scep->cacert);
		}
		break;
	case MSG_PKCSREQ:
	case MSG_GETCERTINITIAL:
	case MSG_V2REQUEST:
	case MSG_V2PROXY:
		PKCS7_add_certificate(msg->p7, signercert);
		break;
	}

	/* start adding data						*/
	p7bio = PKCS7_dataInit(msg->p7, NULL);
	if (p7bio == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot create BIO to write data\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (envelopedlen > 0) {
		if (envelopedlen != BIO_write(p7bio, enveloped, envelopedlen)) {
			BIO_printf(bio_err, "%s:%d: unable to write all data\n",
				__FILE__, __LINE__);
			goto err;
		}
	}

	/* set signed attributes: message type, transaction id, 	*/
	/* pki status, recipient nonce, sender nonce			*/
	/* prepare the attributes					*/
	attribs = sk_X509_ATTRIBUTE_new_null();
	attr_add_string(attribs, OBJ_sn2nid("transId"), scep->transId);
	attr_add_string(attribs, OBJ_sn2nid("messageType"),
		msg->messageType);
	if (msg->pkiStatus)
		attr_add_string(attribs, OBJ_sn2nid("pkiStatus"),
			msg->pkiStatus);
	if (msg->failinfo)
		attr_add_string(attribs, OBJ_sn2nid("failinfo"), msg->failinfo);
	if (scep->senderNonce)
		attr_add_octet(attribs, OBJ_sn2nid("senderNonce"),
			scep->senderNonce, scep->senderNonceLength);
	if (scep->recipientNonce)
		attr_add_octet(attribs, OBJ_sn2nid("recipientNonce"),
			scep->recipientNonce, scep->recipientNonceLength);
	if ((scep->community) && (proxy)) {
		scep->authenticator = proxy_authenticator(msg, scep->community);
		auth = X509_ATTRIBUTE_create(
			OBJ_sn2nid("proxyAuthenticator"),
			V_ASN1_OCTET_STRING, scep->authenticator);
		sk_X509_ATTRIBUTE_push(attribs, auth);
	}
	PKCS7_set_signed_attributes(si, attribs);
	if (debug)
		BIO_printf(bio_err, "%s:%d: all authenticated attributes "
			"added\n", __FILE__, __LINE__);

	/* add content type to signed attributes			*/
	PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
		V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));

	/* finalize, thus computing the signature			*/
	PKCS7_dataFinal(msg->p7, p7bio);
	if (debug)
		BIO_printf(bio_err, "%s:%d: signature finalized\n",
			__FILE__, __LINE__);

	/* convert the data to a memory block, with base64 encoding if	*/
	/* required							*/
	membio = BIO_new(BIO_s_mem());
	if (msg->base64) {
		b64 = BIO_new(BIO_f_base64());
		outbio = BIO_push(b64, membio);
	} else {
		outbio = membio;
	}
	i2d_PKCS7_bio(outbio, msg->p7);
	BIO_flush(outbio);

	/* copy the data from the memory bio to where it belongs in the	*/
	/* the scep structure. As in some cases	the bio data is base64	*/
	/* we should write the whole thing again			*/
	BIO_set_flags(membio, BIO_FLAGS_MEM_RDONLY);
	msg->length = BIO_get_mem_data(membio, &msg->data);
	if (debug)
		BIO_printf(bio_err, "%s:%d: encoded bytes: %d %s\n", __FILE__,
			__LINE__, msg->length,
			(msg->base64) ? "(base64)" : "(DER)");
	BIO_free(outbio);
	if ((debug) && (tmppath)) {
		char	filename[1024];
		BIO	*b;
		snprintf(filename, sizeof(filename), "%s/%d.e-3-signed.der",
			tmppath, getpid());
		b = BIO_new(BIO_s_file());
		BIO_write_filename(b, filename);
		i2d_PKCS7_bio(b, msg->p7);
		BIO_flush(b);
		BIO_free(b);
	}

	/* return this message						*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: encode(%s) completes "
			"successfully\n", __FILE__, __LINE__,
			SCEP_TYPE(msg->messageType));
	return 0;
err:
	if (debug)
		BIO_printf(bio_err, "%s:%d: error return from encode\n",
			__FILE__, __LINE__);
	ERR_print_errors(bio_err);
	return -1;
}

