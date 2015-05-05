/*
 * selfsigned.c -- create a self signed certificate from a request and a
 *                 private key
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 */
#include <stdlib.h>
#include <stdio.h>
#include <config.h>
#include <selfsigned.h>
#include <init.h>
#include <scep.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int	selfsigned(scep_t *scep) {
	X509		*ss;
	X509V3_CTX	ctx;
	EVP_PKEY	*tmpkey;
	BIO		*out;
	char		selfsignedname[1024];
	unsigned char	*p;
	ASN1_INTEGER	*serial;

	/* convert the request to a X509				*/
	ss = X509_new();

	/* set various attributes					*/
	if (X509_set_version(ss, 3) <= 0) {
		BIO_printf(bio_err, "%s:%d: cannot set version number\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* using 4711 in as the serial is not really correct, it should	*/
	/* be the transaction id					*/
	p = (unsigned char *)scep->transId;
	if (p) {
		serial = c2i_ASN1_INTEGER(NULL, &p, 32);
		if (!serial) {
			BIO_printf(bio_err, "%s:%d: cannot convert transid "
				"into serial number\n", __FILE__, __LINE__);
			goto err;
		}
		if (X509_set_serialNumber(ss, serial) <= 0) {
			BIO_printf(bio_err, "%s:%d: cannot set serial number\n",
				__FILE__, __LINE__);
			goto err;
		}
		if (debug)
			BIO_printf(bio_err, "%s:%d: serial set to trans id\n",
				__FILE__, __LINE__);
	} else {
		BIO_printf(bio_err, "%s:%d: must have trans id as serial\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* set issuer							*/
	if (0 >= X509_set_issuer_name(ss,
		X509_REQ_get_subject_name(scep->clientreq))) {
		BIO_printf(bio_err, "%s:%d: set subject name\n", __FILE__,
			__LINE__);
		goto err;
	}

	/* set time before						*/
	if (0 == X509_gmtime_adj(X509_get_notBefore(ss), 0)) {
		BIO_printf(bio_err, "%s:%d: cannot set notBefore time\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* grant self signed certificate for 30 days, although cisco	*/
	/* does it for 10 years						*/
	if (0 == X509_gmtime_adj(X509_get_notAfter(ss), (long)3600 * 24 * 30)) {
		BIO_printf(bio_err, "%s:%d: cannot set notAfter time\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* set subject name						*/
	if (0 >= X509_set_subject_name(ss,
		X509_REQ_get_subject_name(scep->clientreq))) {
		BIO_printf(bio_err, "%s:%d: cannot set subject name\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* extract the public key from the request and set it in the 	*/
	/* certificate							*/
	tmpkey = X509_REQ_get_pubkey(scep->clientreq);
	if (tmpkey == NULL) {
		BIO_printf(bio_err, "%s:%d: own public key not found\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (0 >= X509_set_pubkey(ss, tmpkey)) {
		BIO_printf(bio_err, "%s:%d: cannot set public key\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* prepare signing of the certificate				*/
	X509V3_set_ctx(&ctx, ss, ss, NULL, NULL, 0);
	if (debug)
		BIO_printf(bio_err, "%s:%d: setting signing context failed\n",
			__FILE__, __LINE__);

	/* XXX add extensions 						*/

	/* sign the X509 using the private key				*/
	if (0 >= X509_sign(ss, scep->clientpkey, EVP_md5())) {
		BIO_printf(bio_err, "%s:%d: signing failed\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* some debug info						*/
	if (debug) {
		char		issuerdn[1024], subjectdn[1024];
		X509_NAME	*n;
		if ((n = X509_get_issuer_name(ss)) == NULL) {
			BIO_printf(bio_err, "%s:%d: issuer dn not found\n",
				__FILE__, __LINE__);
			goto err;
		}
		X509_NAME_oneline(n, issuerdn, sizeof(issuerdn));

		if ((n = X509_get_subject_name(ss)) == NULL) {
			BIO_printf(bio_err, "%s:%d: subject dn not found\n",
				__FILE__, __LINE__);
			goto err;
		}
		X509_NAME_oneline(n, subjectdn, sizeof(subjectdn));

		BIO_printf(bio_err, "%s:%d: self signed certificate %s/%s "
			"prepared @%p\n", __FILE__, __LINE__,
			issuerdn, subjectdn, ss);
	}

	/* for debugging, output the self signed certificate		*/
	if ((debug) && (tmppath)) {
		out = BIO_new(BIO_s_file());
		snprintf(selfsignedname, sizeof(selfsignedname),
			"%s/%d.selfsigned.der", tmppath, getpid());
		BIO_write_filename(out, selfsignedname);
		i2d_X509_bio(out, ss);
		BIO_free(out);
		BIO_printf(bio_err, "%s:%d: selfsigned certificate written "
			"to '%s'\n", __FILE__, __LINE__, selfsignedname);
	}

	/* return the self signed certificate				*/
	scep->selfsignedcert = ss;
	return 0;

	/* error return							*/
err:
	ERR_print_errors(bio_err);
	return -1;
}
