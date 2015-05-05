/*
 * decode.c -- decoding operations on PCKS#7 structures
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 * 
 * $Id: decode.c,v 1.14 2002/02/25 23:01:06 afm Exp $
 */
#include <decode.h>
#include <init.h>
#include <sigattr.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <iser.h>
#include <isasu.h>
#include <proxy.h>

/*
 * decoding a PKCS#7 request from a SCEP transaction has the following
 * steps:
 * 1. convert from base64 to internal representation
 * 2. check signature
 * 3. extract signed attributes
 * 4. extract signing certificates
 * 5. extract enveloped data
 * 6. decrypt enveloped data
 */
int	decode(scep_t *scep, BIO *bio) {
	BIO				*b64, *inbio, *p7bio, *outbio,
					*membio;
	int				bytes, length, fd, used;
	int				nMessageType = -1, nPkiStatus = -1;
	STACK_OF(PKCS7_SIGNER_INFO)	*sinfo;
	PKCS7_ISSUER_AND_SERIAL		*ias;
	X509				*x509, *signercert;
	STACK_OF(X509_ATTRIBUTE)	*sig_attribs;
	scepmsg_t			*msg;
	PKCS7				*p7enveloped;
	char				buffer[1024];
	char				*data;
	EVP_PKEY			*recipientpkey;
	X509				*recipientcert;

	/* find out which part is sender and which is recipient		*/
	if (scep->client)
		msg = &scep->reply;
	else
		msg = &scep->request;
	if (debug)
		BIO_printf(bio_err, "%s:%d: decoding %s message\n", __FILE__,
			__LINE__, (scep->client) ? "reply" : "request");

	/* convert from base64 to internal representation		*/
	if (msg->base64) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: prepending Base64 "
				"decoder\n", __FILE__, __LINE__);
		b64 = BIO_new(BIO_f_base64());
		inbio = BIO_push(b64, bio);
	} else {
		inbio = bio;
	}
	membio = BIO_new(BIO_s_mem());
	while ((bytes = BIO_read(inbio, buffer, sizeof(buffer))) > 0) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: chunk of %d bytes\n",
				__FILE__, __LINE__, bytes);
		BIO_write(membio, buffer, bytes);
	}
	BIO_set_flags(membio, BIO_FLAGS_MEM_RDONLY);
	length = BIO_get_mem_data(membio, &data);
	if (debug)
		BIO_printf(bio_err, "%s:%d: decoded data at %p: %d bytes\n",
			__FILE__, __LINE__, data, length);

	/* write the data from the BIO to a file			*/
	if ((debug) && (tmppath)) {
		char	filename[1024];
		snprintf(filename, sizeof(filename), "%s/%d.d-1-signed.der",
			tmppath, getpid());
		BIO_printf(bio_err, "%s:%d: write data to %s\n", __FILE__,
			__LINE__, filename);
		if (0 <= (fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
			0666))) {
			write(fd, data, length);
			close(fd);
		} else {
			BIO_printf(bio_err, "%s:%d: cannot open file %s: %s "
				"(%d)\n", __FILE__, __LINE__, filename,
				strerror(errno), errno);
		}
	}

	/* decode the data in the memory bio				*/
	msg->p7 = d2i_PKCS7_bio(membio, NULL);
	if (msg->p7 == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot decode message\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* make sure this is a signed data PKCS#7			*/
	if (!PKCS7_type_is_signed(msg->p7)) {
		BIO_printf(bio_err, "%s:%d: supplied PKCS#7 is not signed "
			"data\n", __FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: received message is signed\n",
			__FILE__, __LINE__);

	/* create BIOs to read signed content data from			*/
	p7bio = PKCS7_dataInit(msg->p7, NULL);
	if (p7bio == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot extract data from PKCS#7\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* prepare a memory BIO to write signed content to, after the	*/
	/* following loop, the outbio will be filled with the data for	*/
	/* the internal PKCS#7, so we can simple d2i from that BIO to	*/
	/* retrieve the internal PKCS#7					*/
	outbio = BIO_new(BIO_s_mem());
	used = 0;
	for (;;) {
		unsigned char	buf[1024];
		bytes = BIO_read(p7bio, buf, sizeof(buf));
		used += bytes;
		if (bytes <= 0) break;
		BIO_write(outbio, buf, bytes);
	}
	BIO_flush(outbio);
	if (debug)
		BIO_printf(bio_err, "%s:%d: got %d bytes of enveloped data\n",
			__FILE__, __LINE__, used);
	if ((debug) && (tmppath)) {
		char	filename[1024];
		snprintf(filename, sizeof(filename), "%s/%d.d-2-enveloped.der",
			tmppath, getpid());
		if ((fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, 0666)) >= 0){
			length = BIO_get_mem_data(outbio, &data);
			if ((length > 0) && (data)) {
				write(fd, data, length);
			}
			close(fd);
		}
	}

	/* there should be exactly one signer info			*/
	sinfo = PKCS7_get_signer_info(msg->p7);
	if (sinfo == NULL) {
		BIO_printf(bio_err, "%s:%d: no signer info\n", __FILE__,
			__LINE__);
		goto err;
	}
	if (sk_PKCS7_SIGNER_INFO_num(sinfo) != 1) {
		BIO_printf(bio_err, "%s:%d: wrong number of signers: %d\n",
			__FILE__, __LINE__, sk_PKCS7_SIGNER_INFO_num(sinfo));
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: found exactly one signer: good\n",
			__FILE__, __LINE__);

	/* retrieve the signer from the signer info			*/
	msg->si = sk_PKCS7_SIGNER_INFO_value(sinfo, 0);
	ias = msg->si->issuer_and_serial;
	x509 = X509_find_by_issuer_and_serial(msg->p7->d.sign->cert,
		ias->issuer, ias->serial);

	/* x509 is now the unique signed certificate in the PKCS#7, 	*/
	/* log what we have						*/
	if (x509 == NULL) {
		char	name[1024];
		if (debug) {
			BIO_printf(bio_err, "%s:%d: no signer certificate, "
				"probably CA is signer\n",
				__FILE__, __LINE__);
			X509_NAME_oneline(ias->issuer, name, sizeof(name));
			BIO_printf(bio_err, "%s:%d: signer cert issued by %s\n",
				__FILE__, __LINE__, name);
			BIO_printf(bio_err, "%s:%d: signer cert serial: %s\n",
				__FILE__, __LINE__,
				BN_bn2hex(ASN1_INTEGER_to_BN(ias->serial,
				NULL)));
		}
	} else {
		char	name[1024];
		if (debug) {
			X509_NAME_oneline(X509_get_issuer_name(x509), name,
				sizeof(name));
			BIO_printf(bio_err, "%s:%d: issuer of signer %s\n",
				__FILE__, __LINE__, name);
			X509_NAME_oneline(X509_get_subject_name(x509), name,
				sizeof(name));
			BIO_printf(bio_err, "%s:%d: subject of signer: %s\n",
				__FILE__, __LINE__, name);
		}
	}

	/* this certificate may be self signed, but for the PKCS7_-	*/
	/* signatureVerify method, this does not matter			*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: preparing cert store for "
			"signature verification\n", __FILE__, __LINE__);
	if (scep->client) {
		signercert = scep->cacert;
		if (debug)
			BIO_printf(bio_err, "%s:%d: verifying server signature "
				"against known CA cert\n", __FILE__, __LINE__);
	} else {
		if (debug)
			BIO_printf(bio_err, "%s:%d: working with signer @%p\n",
				__FILE__, __LINE__, x509);
		if (!X509_NAME_cmp(X509_get_subject_name(x509),
			X509_get_issuer_name(x509))) {
			/* client and issuer have the same dn, i.e.	*/
			/* this is the case for the self signed cert	*/
			scep->selfsignedcert = x509;
			if (debug)
				BIO_printf(bio_err, "%s:%d: verify against "
					"selfsigned cert %p\n", __FILE__,
					__LINE__, x509);
		} else {
			scep->clientcert = x509;
			if (debug)
				BIO_printf(bio_err, "%s:%d: verify against "
					"official cert at %p\n", __FILE__,
					__LINE__, x509);
		}
		signercert = x509;
		if (debug) {
			char	name[1024];
			X509_NAME_oneline(X509_get_subject_name(signercert),
				name, 1024);
			BIO_printf(bio_err, "%s:%d: certificate (@%p) for '%s' "
				"added to store\n", __FILE__, __LINE__, x509,
				name);
		}
	}

	/* verify the PKCS#7 using the store just constructed		*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: verifying signature\n", __FILE__,
			__LINE__);
	if (PKCS7_signatureVerify(p7bio, msg->p7, msg->si, signercert) <= 0) {
		BIO_printf(bio_err, "%s:%d: verification failed\n", __FILE__,
			__LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: signature verfied OK\n", __FILE__,
			__LINE__);

	/* extract the signed attributes				*/
	sig_attribs = PKCS7_get_signed_attributes(msg->si);
	if ((sig_attribs == NULL) || (sk_X509_ATTRIBUTE_num(sig_attribs) == 0)){
		BIO_printf(bio_err, "%s:%d: no signed attributes found\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* scan for all the attributes defined in the SCEP spec		*/
	scep->transId = sigattr_string(scep, "transId");
	msg->messageType = sigattr_string(scep, "messageType");
	msg->pkiStatus =  sigattr_string(scep, "pkiStatus");
	msg->failinfo =  sigattr_string(scep, "failinfo");
	scep->senderNonce = sigattr_octet(scep, "senderNonce",
		&scep->senderNonceLength);
	scep->recipientNonce = sigattr_octet(scep, "recipientNonce",
		&scep->recipientNonceLength);
	scep->authenticator = sigattr_asn1_octet(scep, "proxyAuthenticator");
	if (debug)
		BIO_printf(bio_err, "%s:%d: signed attributes retrieved\n",
			__FILE__, __LINE__);

	/* perform some consistency checks				*/

	/* UniCert 3.1.2 seems to out the message type, so fudge 	*/
	/* the value of 3 (CertRep) if it is missing (problem pointed	*/
	/* out by Peter Onion						*/
	if (NULL == msg->messageType) {
		BIO_printf(bio_err, "%s:%d: no message type (setting to 3)\n",
			__FILE__, __LINE__);
		msg->messageType = "3";	/* XXX should we strdup here?	*/
	}

	/* UniCert doesn't seem to bother to put in a senderNonce,	*/
	/* so don't get upset if it is missing.				*/
	if (NULL == scep->senderNonce) {
		BIO_printf(bio_err, "%s:%d: senderNonce missing\n",
			__FILE__, __LINE__);
	}

	if (NULL == msg->messageType) {
		BIO_printf(bio_err, "%s:%d: message type missing\n",
			__FILE__, __LINE__);
		goto err;
	}
	nMessageType = atoi(msg->messageType);
	if (msg->pkiStatus) {
		nPkiStatus = atoi(msg->pkiStatus);
	}

	/* perform some type/status dependent checks			*/
	if ((used == 0) && (nMessageType != 3)) {
		BIO_printf(bio_err, "%s:%d: only CertRep message may be "
			"empty\n", __FILE__, __LINE__);
		goto err;
	}
	if ((used == 0) && (nMessageType == 3) && (nPkiStatus == 0)) {
		BIO_printf(bio_err, "%s:%d: CertRep may only be empty for "
			"failure or pending\n", __FILE__, __LINE__);
		goto err;
	}

	/* no content is only allowed if the message is a CertRep with	*/
	/* a pkiStatus of failure or pending				*/
	if (used == 0) {
		BIO_printf(bio_err, "%s:%d: empty PKCSReq, must be failure or "
			"pending\n", __FILE__, __LINE__);
		goto signedonly;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: working on inner pkcs#7\n",
			__FILE__, __LINE__);

	/* unpack the internal PKCS#7					*/
	p7enveloped = d2i_PKCS7_bio(outbio, NULL);
	if (p7enveloped == NULL) {
		/* this may happen if the message is a CertRep 		*/
		if (strcmp(msg->messageType, SCEP_MESSAGE_TYPE_CERTREP)) {
			BIO_printf(bio_err, "%s:%d: cannot decode signed "
				"data\n", __FILE__, __LINE__);
			goto err;
		}
		msg->p7 = NULL;
		BIO_printf(bio_err, "%s:%d: no enveloped data to decrypt, "
			"but we should have seen that earlier\n",
			__FILE__, __LINE__);
		goto err;
	}

	recipientpkey = (scep->client) ? scep->clientpkey : scep->capkey;
	recipientcert = (scep->client) ? scep->selfsignedcert : scep->cacert;
	/* decrypt the enveloped data PKCS#7				*/
	if (debug) {
		char	recipientdn[1024];
		
		X509_NAME_oneline(X509_get_subject_name(recipientcert),
			recipientdn, sizeof(recipientdn));
		BIO_printf(bio_err, "%s:%d: decrypting data with key at %p, "
			"certificate for %s at %p\n", __FILE__, __LINE__,
			recipientpkey, recipientdn, recipientcert);
	}
	outbio = BIO_new(BIO_s_mem());
	if (0 == PKCS7_decrypt(p7enveloped, recipientpkey, recipientcert,
		outbio, 0)) {
		BIO_printf(bio_err, "%s:%d: decryption failed\n", __FILE__,
			__LINE__);
		goto err;
	}
	BIO_flush(outbio);
	msg->length = BIO_get_mem_data(outbio, &msg->data);
	if (debug)
		BIO_printf(bio_err, "%s:%d: got %d bytes of decrypted data\n",
			__FILE__, __LINE__, msg->length);

	/* transfer ownership of the memory from the BIO to the SCEP	*/
	BIO_set_flags(outbio, BIO_FLAGS_MEM_RDONLY);

	/* write the payload to a file					*/
	if ((debug) && (tmppath)) {
		char	filename[1024];
		snprintf(filename, sizeof(filename), "%s/%d.d-3-payload.der",
			tmppath, getpid());
		if ((fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, 0666)) >= 0){
			write(fd, msg->data, msg->length);
		}
	}

	/* decode the content memory block according to the message	*/
	/* type								*/
	switch (atoi(msg->messageType)) {
	case MSG_CERTREP:
		if (debug)
			BIO_printf(bio_err, "%s:%d: decoding CertRep\n",
				__FILE__, __LINE__);
		msg->rd.p7 = d2i_PKCS7_bio(outbio, NULL);
		break;
	case MSG_V2PROXY:
		/* verify the proxy authenticator			*/
		if (scep->authenticator == NULL) {
			BIO_printf(bio_err, "%s:%d: authenticator missing\n",
				__FILE__, __LINE__);
			goto err;
		}
		if (!proxy_check(scep, msg, scep->authenticator)) {
			BIO_printf(bio_err, "%s:%d: proxy authentication "
				"fails\n", __FILE__, __LINE__);
			goto err;
		}
		/* now fall through to version 2 handling		*/
	case MSG_V2REQUEST:
		/* decode as a version 2 packet				*/
		if (debug)
			BIO_printf(bio_err, "%s:%d: decoding v2 payload\n",
				__FILE__, __LINE__);
		msg->rd.payload = d2i_payload_bio(outbio, NULL);
		if (debug)
			BIO_printf(bio_err, "%s:%d: decoded a payload of "
				"type %d, payload data length %d\n",
				__FILE__, __LINE__, msg->rd.payload->rt,
				msg->rd.payload->original->length);
		break;
	case MSG_PKCSREQ:
		if (debug)
			BIO_printf(bio_err, "%s:%d: decoding X509_REQ\n",
				__FILE__, __LINE__);
		scep->clientreq = msg->rd.req = d2i_X509_REQ_bio(outbio, NULL);
		scep->requestorreq = scep->clientreq;
		break;
	case MSG_GETCERTINITIAL:
		if (debug)
			BIO_printf(bio_err, "%s:%d: decoding issuer and "
				"subject\n", __FILE__, __LINE__);
		msg->rd.is = d2i_issuer_and_subject_bio(outbio, NULL);
		break;
	case MSG_GETCERT:
	case MSG_GETCRL:
		if (debug)
			BIO_printf(bio_err, "%s:%d: decoding issuer and "
				"serial\n", __FILE__, __LINE__);
		msg->rd.iser = d2i_PKCS7_ISSUER_AND_SERIAL_bio(NULL, outbio);
		break;
	default:
		BIO_printf(bio_err, "%s:%d: unknown message type: %s\n",
			__FILE__, __LINE__, msg->messageType);
		break;
	}
	if (msg->rd.unknown == NULL) {
		BIO_printf(bio_err, "%s:%d: decoding the message failed\n",
			__FILE__, __LINE__);
		goto err;
	}
	BIO_free(outbio);
signedonly:

	/* we were successfull in extracting the telescoping PKCS#7's	*/
	return 0;
err:
	if (debug)
		BIO_printf(bio_err, "%s:%d: error return from decode\n",
			__FILE__, __LINE__);
	ERR_print_errors(bio_err);
	return -1;
}
