/*
 * createreq.c -- create a certification request in PKCS10 format,
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: createreq.c,v 1.5 2002/02/19 23:40:06 afm Exp $
 */
#include <config.h>
#include <init.h>
#include <scep.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <createreq.h>
#include <ctype.h>

int	createreq(scep_t *scep, char *dn, char *challenge) {
	X509_REQ			*req;
	X509_NAME			*subj;
	EVP_MD				*digest = EVP_md5();
	BIO				*out;
	char				*p, *dn2, *type, *value;
	int				pos = 0;

	/* create a new request structure				*/
	if (NULL == (req = X509_REQ_new())) {
		return -1;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: new request allocated\n",
			__FILE__, __LINE__);

	/* prepare a new distinguished name				*/
	subj = X509_NAME_new();

	/* split the distinguished name into components, and add values	*/
	/* to the subj 							*/
	dn2 = strdup(dn);
	p = strtok(dn2, ",");
	do {
		if (debug)
			BIO_printf(bio_err, "%s:%d: token seen: %s\n",
				__FILE__, __LINE__, p);

		/* skip white space					*/
		while ((*p) && (isspace(*p))) p++;

		/* this is the type (attribute name)			*/
		type = p;

		/* scan for '=' character				*/
		value = p;
		while ((*value) && (*value != '=')) value++;
		*value = '\0';
		value++;

		/* the C attribute should always be upper case		*/
		if (!strcmp(type, "C")) {
			for (p = value; *p; p++) *p = toupper(*p);
		}

		/* adding type/value pair				*/
		if (X509_NAME_add_entry_by_txt(subj, type, MBSTRING_ASC, value,
			strlen(value), pos++, 0) <= 0) {
			BIO_printf(bio_err, "%s:%d:failed to add entry %s=%s\n",
				__FILE__, __LINE__, type, value);
			goto err;
		}
		if (debug)
			BIO_printf(bio_err, "%s:%d: %s=%s added\n", __FILE__,
				__LINE__, type, value);
			
	} while (NULL != (p = strtok(NULL, ",")));
#if 0
	free(dn2);
#endif
	X509_REQ_set_subject_name(req, subj);
	if (debug) {
		char	sdn[1024];
		X509_NAME_oneline(X509_REQ_get_subject_name(req), sdn,
			sizeof(sdn));
		BIO_printf(bio_err, "%s:%d: subject dn set to '%s'\n",
			__FILE__, __LINE__, sdn);
	}
	
	/* set version							*/
	X509_REQ_set_version(req, 0L);

	/* set extensions						*/
	if (challenge) {
		/* create the challenge password extension		*/
		X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword,
			MBSTRING_ASC, challenge, -1);
	}

	/* set public key						*/
	X509_REQ_set_pubkey(req, scep->clientpubkey);

	/* sign the request						*/
	X509_REQ_sign(req, scep->clientpkey, digest);

	/* for debugging: write request to a file			*/
	if ((debug) && (tmppath)) {
		char	reqfilename[1024];
		snprintf(reqfilename, sizeof(reqfilename),
			"%s/req.%d", tmppath, getpid());
		out = BIO_new(BIO_s_file());
		BIO_write_filename(out, reqfilename);
		i2d_X509_REQ_bio(out, req);
		BIO_free(out);
		if (debug)
			BIO_printf(bio_err, "%s:%d: request written to %s\n",
				__FILE__, __LINE__, reqfilename);
	}

	/* ok return 							*/
	scep->clientreq = req;
	return 0;

	/* error return							*/
err:
	ERR_print_errors(bio_err);
	return -1;
}

