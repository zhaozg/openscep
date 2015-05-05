/*
 * scepxid.c -- compute the transaction id belonging to some RSA private
 *              key
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: scepxid.c,v 1.3 2002/02/19 23:40:07 afm Exp $
 */
#include <config.h>
#include <init.h>
#include <scep.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <fingerprint.h>
#include <missl.h>

extern int	optind;
extern char	*optarg;

int	main(int argc, char *argv[]) {
	int		c;
	char		*reqfile = NULL, *fp;
	BIO		*bio;
	X509_REQ	*req;
	EVP_PKEY	*pkey;
	int		netscape = 0;
	NETSCAPE_SPKI	*spki = NULL;

	/* parse command line						*/
	while (EOF != (c = getopt(argc, argv, "dn"))) 
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'n':
			netscape = 1;
			break;
		}

	/* remaining argument must be the name of the rsa key file	*/
	if ((argc - optind) != 1) {
		fprintf(stderr, "%s:%d: exactly one argument expected: "
			"reqfile\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	reqfile = argv[optind];
	if (debug)
		BIO_printf(bio_err, "%s:%d: key file is %s\n", __FILE__,
			__LINE__, reqfile);

	/* initialize everything you can				*/
	scepinit();

	/* open the key file						*/
	bio = BIO_new(BIO_s_file());
	BIO_read_filename(bio, reqfile);
	switch (netscape) {
	case 0:
		req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
		pkey = X509_REQ_get_pubkey(req);
		break;
	case 1:
		d2i_NETSCAPE_SPKI_bio(bio, &spki);
		if (spki == NULL) {
			BIO_printf(bio_err, "%s:%d: cannot read spki\n",
				__FILE__, __LINE__);
			goto err;
		}
		pkey = NETSCAPE_SPKI_get_pubkey(spki);
		break;
	}
	if (pkey == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot read request\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* compute the fingerprint for this key				*/
	fp = key_fingerprint(pkey);
	if (fp == NULL) {
		BIO_printf(bio_err, "%s:%s: no key fingerprint obtained\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* display the fingerprint					*/
	printf("public key fingerprint: %s\n", fp);

	/* return success						*/
	exit(EXIT_SUCCESS);

	/* error return							*/
err:
	ERR_print_errors(bio_err);
	exit(EXIT_FAILURE);
}
