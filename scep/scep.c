/*
 * scep.c -- scep command line client
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: scep.c,v 1.13 2002/02/25 23:01:06 afm Exp $
 */
#include <stdlib.h>
#include <stdio.h>
#include <config.h>
#include <init.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <selfsigned.h>
#include <createreq.h>
#include <unistd.h>
#include <fingerprint.h>
#include <http.h>
#include <encode.h>
#include <decode.h>
#include <missl.h>
#include <scepldap.h>

extern int	optind;
extern char	*optarg;

/*
 * the following function is needed to extract a certificate from the 
 * reply receveived from the SCEP server. The reply will contain two
 * certificates, the CA certificate which signed the message, and the
 * certificate destined for the end entity (which may be different from
 * the SCEP client's self signed certificate). So we must extract the
 * certificate the does not match the CA certificate.
 */
static X509	*extract_cert(scep_t *scep) {
	PKCS7		*p7;
	STACK_OF(X509)	*certs;
	X509		*x;
	int		i, ncerts;
	char		name_buffer[1024];

	/* get the structure						*/
	p7 = scep->reply.rd.p7;

	/* get the certificate from this pkcs#7				*/
	certs = p7->d.sign->cert;
	BIO_printf(bio_err, "%s:%d: %d certificates in the pkcs7\n",
		__FILE__, __LINE__, ncerts = sk_X509_num(certs));
	if (ncerts != 2) {
		
	}
	for (i = 0; i < sk_X509_num(certs); i++) {
		x = sk_X509_value(certs, i);
#if 0
		/* Peter Onion points out that asking for the issuer to	*/
		/* match is probably too much				*/
		if (X509_NAME_cmp(X509_get_issuer_name(x),
			X509_get_subject_name(scep->cacert))) {
			goto not;
		}
#endif
		/* we are not interested in the CA certificate		*/
		if (X509_NAME_cmp(X509_get_subject_name(x),
			X509_get_subject_name(scep->cacert)) == 0) {
			if (debug)
				BIO_printf(bio_err, "%s:%d: skipping CA cert\n",
					__FILE__, __LINE__);
			goto not;
		}

		/* we are not interested in the self signed certificate	*/
		/* either						*/
		if (ASN1_INTEGER_cmp(X509_get_serialNumber(x),
			X509_get_serialNumber(scep->selfsignedcert)) == 0) {
			if (debug)
				BIO_printf(bio_err, "%s:%d: skipping self "
					"signed certificate\n", __FILE__,
					__LINE__);
			goto not;
		}

		/* by exclusion, this certificate seems to be the one 	*/
		/* we are looking for					*/
		return x;
	not:
		BIO_printf(bio_err, "%s:%d: certificate excluded:\n",
			__FILE__, __LINE__);
		X509_NAME_oneline(X509_get_issuer_name(x),
			name_buffer, sizeof(name_buffer));
		BIO_printf(bio_err, "\tcert_issuer_name =  %s\n", name_buffer);
		X509_NAME_oneline(X509_get_subject_name(x),
			name_buffer, sizeof(name_buffer));
		BIO_printf(bio_err, "\tcert_subject_name = %s\n", name_buffer);
	}
	return NULL;
}

/*
 * read client data
 *
 * this function reads the client private key and the client certificate
 * request from files
 */
static int	read_clientstuff(scep_t *scep, char *requestfile, char *keyfile) {
	BIO	*bio;

	/* read the public key from the request				*/
	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, requestfile) <= 0) {
		BIO_printf(bio_err, "%s:%d: cannot open request file\n",
			__FILE__, __LINE__);
		goto err;
	}
	scep->clientreq = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	if (scep->clientreq == NULL) {
		BIO_printf(bio_err, "%s:%d: couldn't read the request "
			"from %s\n", __FILE__, __LINE__, requestfile);
		goto err;
	}
	scep->clientpubkey = X509_REQ_get_pubkey(scep->clientreq);
	if (scep->clientpubkey == NULL) {
		BIO_printf(bio_err, "%s:%d: no public key available\n",
			__FILE__, __LINE__);
	}
	BIO_free(bio);
	if (debug)
		BIO_printf(bio_err, "%s:%d: public key decoded\n",
			__FILE__, __LINE__);

	/* read private key (this probably needs a password)		*/
	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, keyfile) <= 0) {
		BIO_printf(bio_err, "%s:%d: cannot open private key "
			"file %s\n", __FILE__, __LINE__, keyfile);
		goto err;
	}
	scep->clientpkey = PEM_read_bio_PrivateKey(bio, NULL, NULL,
		NULL);
	if (scep->clientpkey == NULL) {
		BIO_printf(bio_err, "%s:%d: no private key available\n",
			__FILE__, __LINE__);
		goto err;
	}
	BIO_free(bio);
	if (debug)
		BIO_printf(bio_err, "%s:%d: private key decoded @%p\n",
			__FILE__, __LINE__, scep->clientpkey);
	if (debug > 1) {
		/* dump the key information so we can check whether	*/
		/* we have private and public key information in the	*/
		/* clientpkey member					*/
	}
	return 0;
err:
	/* some error has occured					*/
	ERR_print_errors(bio_err);
	return -1;
}

/*
 * read requestor data
 *
 * for version 2 requests, the requestor and the SCEP client can be different
 * and the request does not need to be a PKCS#10
 */
static int	read_requestorstuff(scep_t *scep, int type, char *filename) {
	BIO		*bio;
	NETSCAPE_SPKI	*spki = NULL;
	X509_REQ	*req = NULL;
	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) < 0) {
		BIO_printf(bio_err, "%s:%d: cannot read request file '%s'\n",
			__FILE__, __LINE__, filename);
		goto err;
	}
	switch (type) {
	case 0:
		scep->requestorreq = d2i_X509_REQ_bio(bio, &req);
		if (scep->requestorreq == NULL) {
			BIO_printf(bio_err, "%s:%d: cannot decode X509_REQ\n",
				__FILE__, __LINE__);
			goto err;
		}
		scep->requestorpubkey
			= X509_REQ_get_pubkey(scep->requestorreq);
		break;
	case 1:
		scep->requestorspki = d2i_NETSCAPE_SPKI_bio(bio, &spki);
		if (scep->requestorspki == NULL) {
			BIO_printf(bio_err, "%s:%d: cannot decode SPKI\n",
				__FILE__, __LINE__);
			goto err;
		}
		scep->requestorpubkey
			= NETSCAPE_SPKI_get_pubkey(scep->requestorspki);
		break;
	default:
		goto err;
	}
	return 0;
err:
	ERR_print_errors(bio_err);
	return -1;
}

/*
 * read the ca stuff
 */
static int	read_castuff(scep_t *scep, char *cacertfile) {
	BIO	*bio;

	if (cacertfile != NULL) {
		bio = BIO_new(BIO_s_file());
		if (BIO_read_filename(bio, cacertfile) <= 0) {
			BIO_printf(bio_err, "%s:%d: cannot open CA "
				"certificate file\n", __FILE__, __LINE__);
			goto err;
		}
		scep->cacert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (scep->cacert == NULL) {
			BIO_printf(bio_err, "%s:%d: cannot decode CA "
				"certificate\n", __FILE__, __LINE__);
			goto err;
		}
		BIO_free(bio);
		if (debug)
			BIO_printf(bio_err, "%s:%d: CA certificate decoded\n",
				__FILE__, __LINE__);
		return 0;
	err:
		return -1;
	}
	return 0;
}

/*
 * this is the scep client main function
 *
 * it does the following
 * 0. initialize the libraries
 * 1. parse the command line options
 * 2.
 * 3.
 * 4.
 * 5.
 * 6.
 * 7.
 * 8.
 * 9.
 */

int	main(int argc, char *argv[]) {
	int		c, poll = 0, reqversion = 0, rc = -1;
	char		*cacertfile = NULL, *keyfile = NULL, *challenge = NULL,
			*savedrequestfile = NULL, *requestfile = NULL,
			*dn = NULL, *spkacfile = NULL, *endrequest = NULL;
	scep_t		scep;
	BIO		*repbio;
	char		*url = "http://localhost/cgi-bin";
	scepmsg_t	*msg;
	unsigned char	*checkNonce = NULL;

	/* initialize what you can					*/
	scepinit();
	scep_clear(&scep);

	/* we are a client 						*/
	scep.client = 1;

	/* parse command line						*/
	while (EOF != (c = getopt(argc, argv, "dc:e:r:s:k:w:pu:2a:q:")))
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'e':
			endrequest = optarg;
			break;
		case 'c':
			cacertfile = optarg;
			break;
		case 's':
			savedrequestfile = optarg;
		case 'r':
			/* the request file will also contain the self	*/
			/* signed certificate				*/
			requestfile = optarg;
			break;
		case 'k':
			keyfile = optarg;
			break;
		case 'w':
			challenge = optarg;
			break;
		case 'p':
			poll = 1;
			break;
		case 'q':
			scep.community = optarg;
			break;
		case 'u':
			url = optarg;
			break;
		case '2':
			reqversion = 1;
			break;
		case 'a':
			spkacfile = optarg;
			break;
		}

	/* stop immediately if request or key is missing		*/
	/* (even in the case of a version 2 proxied request, we need	*/
	/* a request as the carrier of the proxy entities public key)	*/
	if (keyfile == NULL) {
		BIO_printf(bio_err, "%s:%d: key file is required argument\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (requestfile == NULL) {
		BIO_printf(bio_err, "%s:%d: request file is required "
			"argument\n", __FILE__, __LINE__);
		goto err;
	}

	/* we are preparing the request message				*/
	msg = &scep.request;

	/* decode the URL						*/
	if (parseurl(&scep, url) < 0) {
		BIO_printf(bio_err, "%s:%d: cannot parse url\n", __FILE__,
			__LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: decoded URL %s|%d|%s\n", __FILE__,
			__LINE__, scep.h.httphost, scep.h.httpport,
			scep.h.httppath);

	/* read the client key and request information			*/
	if (read_clientstuff(&scep, requestfile, keyfile) < 0) {
		BIO_printf(bio_err, "%s:%d: failed to read client stuff\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* now we have to decide about the payload we want to have	*/
	/* with our scep request:					*/
	/*  - for a version 1 request, this will always be the original	*/
	/*    certificate signing request				*/
	/*  - for a version 2 request, it will be a payload structure	*/
	switch (reqversion) {
	case 0:
		/* for a version 1 client, client pubkey and client req	*/
		/* coincide						*/
		scep.requestorpubkey = scep.clientpubkey;
		scep.requestorreq = scep.clientreq;
		if (debug)
			BIO_printf(bio_err, "%s:%d: end request coincides "
				"with SCEP client\n", __FILE__, __LINE__);
		break;
	case 1:
		msg->rd.payload = payload_new();
		rc = -1;
		if (spkacfile) {
			if (debug)
				BIO_printf(bio_err, "%s:%d: reading spki "
					"from %s\n", __FILE__, __LINE__,
					spkacfile);
			rc = read_requestorstuff(&scep, 1, spkacfile);
		} else if (endrequest) {
			if (debug)
				BIO_printf(bio_err, "%s:%d: reading X509 req "
					"from %s\n", __FILE__, __LINE__,
					endrequest);
			rc = read_requestorstuff(&scep, 0, endrequest);
		}
		if (rc < 0) {
			BIO_printf(bio_err, "%s:%d: could not read end "
				"request data\n", __FILE__, __LINE__);
			goto err;
		}
		if (debug)
			BIO_printf(bio_err, "%s:%d: end request read\n",
				__FILE__, __LINE__);
		break;
	}

	/* set the transaction id value					*/
	scep.transId = key_fingerprint(scep.requestorpubkey);
	if (debug)
		BIO_printf(bio_err, "%s:%d: transaction ID is %s\n",
			__FILE__, __LINE__, scep.transId);

	/* read the CA certificate file					*/
	if (read_castuff(&scep, cacertfile) < 0) {
		BIO_printf(bio_err, "%s:%d: read CA certificate info\n",
			__FILE__, __LINE__);
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: CA certificate read\n",
			__FILE__, __LINE__);

	/* for SPKI requests, there should be exactly one more argument	*/
	/* namely the distinguished name				*/
	if (spkacfile) {
		if ((argc - optind) != 1) {
			BIO_printf(bio_err, "%s:%d: DN argument needed\n",
				__FILE__, __LINE__);
			goto err;
		}
		dn = argv[optind];
		if (debug)
			BIO_printf(bio_err, "%s:%d: DN argument is '%s'\n",
				__FILE__, __LINE__, dn);

		/* convert the DN into attributes and add them to the	*/
		/* payload						*/
		if (payload_dn_to_attrs(msg->rd.payload, dn) < 0) {
			BIO_printf(bio_err, "%s:%d: failed to add DN attrs\n",
				__FILE__, __LINE__);
			goto err;
		}
	}

	/* skip creation of a request message when polling		*/
	if (poll)
		goto pollinginit;

	/* pack the request as a PKSCReq message, of type PKCSReq 	*/
	switch (reqversion) {
	case 0:
		msg->messageType = SCEP_MESSAGE_TYPE_PKCSREQ;
		msg->rd.req = scep.clientreq;
		break;
	case 1:
		/* build a version 2 payload				*/
		if (debug)
			BIO_printf(bio_err, "%s:%d: building version 2 "
				"payload\n", __FILE__, __LINE__);
		if (scep.requestorreq)
			payload_set_req(msg->rd.payload, scep.requestorreq);
		if (scep.requestorspki)
			payload_set_spki(msg->rd.payload, scep.requestorspki);

		/* set the correct message type				*/
		if (scep.community) {
			/* compute the authenticator from the original 	*/
			/* request and the community			*/
			msg->messageType = SCEP_MESSAGE_TYPE_V2PROXY;
		} else {
			msg->messageType = SCEP_MESSAGE_TYPE_V2REQUEST;
		}
		break;
	}

	/* write the request to the request file, for later perusal	*/
	if (savedrequestfile) {
		BIO	*reqbio;
		reqbio = BIO_new(BIO_s_file());
		BIO_write_filename(reqbio, savedrequestfile);
		switch (reqversion) {
		case 0:
			/* version 1 request has a X509_REQ payload	*/
			PEM_write_bio_X509_REQ(reqbio, msg->rd.req);
			break;
		case 1:
			/* version 2 requests have a "real" payload	*/
			i2d_payload_bio(reqbio, msg->rd.payload);
			break;
		}
		BIO_free(reqbio);
	}

	goto common;

pollinginit:
	/* when polling, the request is a GetCertInitial message	*/
	msg->messageType = SCEP_MESSAGE_TYPE_GETCERTINITIAL;

	/* the contents is the pair issuer and subject			*/
	msg->rd.is = (issuer_and_subject_t *)malloc(
		sizeof(issuer_and_subject_t));
	msg->rd.is->issuer = X509_get_subject_name(scep.cacert);
	msg->rd.is->subject = NULL;

	/* when polling we should read the request from request file	*/
	/* (only needed for the distinguished name of the client)	*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: getting subject X509_NAME\n",
			__FILE__, __LINE__);
	switch (reqversion) {
	case 0:
		msg->rd.is->subject = X509_REQ_get_subject_name(scep.clientreq);
		break;
	case 1:
		if (scep.requestorreq)
			msg->rd.is->subject
				= X509_REQ_get_subject_name(scep.requestorreq);
		if (scep.requestorspki) {
			if (debug)
				BIO_printf(bio_err, "%s:%d: converting DN '%s' "
					"to X509_NAME\n",
					__FILE__, __LINE__, dn);
			msg->rd.is->subject = ldap_to_x509(dn);
		}
		break;
	}
	if (msg->rd.is->subject == NULL) {
		BIO_printf(bio_err, "%s:%d: no subject found\n", 
			__FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: issuer and subject found\n",
			__FILE__, __LINE__);

common:
	/* create a self signed certificate for use with SCEP		*/
	if (selfsigned(&scep) < 0) {
		BIO_printf(bio_err, "%s:%d: failed to create self signed "
			"certificate\n", __FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: self signed certificate created\n",
			__FILE__, __LINE__);

	/* set the senderNonce						*/
	scep.senderNonceLength = 16;
	scep.senderNonce = (unsigned char *)malloc(scep.senderNonceLength);
	RAND_bytes(scep.senderNonce, scep.senderNonceLength);
	if (debug)
		BIO_printf(bio_err, "%s:%d: senderNonce set\n", __FILE__,
			__LINE__);
	checkNonce = scep.senderNonce;

	/* all messages sent from the client are base 64 encoded	*/
	msg->base64 = 1;

	/* encode							*/
	if (encode(&scep) < 0) {
		BIO_printf(bio_err, "%s:%d: encoding the request failed\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: encoded bytes: %d\n", 
			__FILE__, __LINE__, scep.request.length);

	/* send the request to the server, read the reply		*/
	repbio = getrequest(&scep);
	if (repbio == NULL) {
		BIO_printf(bio_err, "%s:%d: failed to read correct reply\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* analyze  the reply						*/
	if (decode(&scep, repbio) < 0) {
		BIO_printf(bio_err, "%s:%d: decoding the reply failed\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* display some information about the reply			*/
	printf("transaction id: %s\n", scep.transId);
	printf("PKIstatus: %s\n", (scep.reply.pkiStatus)
		? scep.reply.pkiStatus : "(null)");
	printf("reply message type: %s\n", scep.reply.messageType);
	if (scep.reply.failinfo) {
		printf("failinfo: %s\n", scep.reply.failinfo);
	}

	/* make sure we get a CertRep message back			*/
	if (strcmp(scep.reply.messageType, SCEP_MESSAGE_TYPE_CERTREP)) {
		BIO_printf(bio_err, "%s:%d: only CertRep message acceptable "
			" in response to PKCSReq/GetCertInitial\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* check for the Nonces						*/
	if (memcmp(checkNonce, scep.recipientNonce, 16)) {
		BIO_printf(bio_err, "%s:%d: recipientNonce != sent "
			"senderNonce\n", __FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: Nonce check OK\n", __FILE__, 
			__LINE__);

	if (scep.reply.pkiStatus == NULL) {
		BIO_printf(bio_err, "no pkiStatus returned\n");
		exit(1);
	}

	switch (atoi(scep.reply.pkiStatus)) {
	case PKI_SUCCESS:
		/* Success						*/
		scep.clientcert = extract_cert(&scep);
		if (debug)
			BIO_printf(bio_err, "%s:%d: certificate returned %p\n",
				__FILE__, __LINE__, scep.clientcert);
		if (scep.clientcert) {
			BIO	*cb;
			cb = BIO_new(BIO_s_file());
			BIO_set_fp(cb, stdout, BIO_NOCLOSE);
			PEM_write_bio_X509(cb, scep.clientcert);
			BIO_free(cb);
		}
		exit(EXIT_SUCCESS);
		break;
	case PKI_FAILURE:	/* Failure				*/
		if (debug)
			BIO_printf(bio_err, "%s:%d: request failed: %s\n",
				__FILE__, __LINE__, scep.reply.failinfo);
		exit(1);
		break;
	case PKI_PENDING:	/* Pending				*/
		if (debug)
			BIO_printf(bio_err, "%s:%d: request still pending\n",
				__FILE__, __LINE__);
		exit(2);
		break;
	}

	/* error return							*/
err:
	ERR_print_errors(bio_err);
	exit(EXIT_FAILURE);
}
