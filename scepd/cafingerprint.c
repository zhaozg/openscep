/*
 * cafingerprint.c -- retrieve the CA fingerprint from an X.509 CA certificate
 *                    This works by looking for the Subject key identifier
 *                    attribute
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: cafingerprint.c,v 1.1 2002/02/17 12:06:57 afm Exp $ 
 */
#include <stdlib.h>
#include <stdio.h>
#include <init.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

extern int	optind;
extern char	*optarg;

int	main(int argc, char *argv[]) {
	BIO			*inbio, *out;
	int			c, i, nid;
	char			*filename = NULL;
	X509			*x509;
	X509_EXTENSION		*ex;

	/* parse the command line					*/
	while ((c = getopt(argc, argv, "")) != EOF)
		switch (c) {
		default:
			; /* shut up compiler */
		}

	/* initialize the scep specific object ids			*/
	scepinit();
	out = BIO_new(BIO_s_file());
	BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

	/* get the filename from the command line			*/
	filename = argv[optind];

	/* open the file given as an argument, und read the contents	*/
	/* as a DER encoded X.509 certificate				*/
	inbio = BIO_new(BIO_s_file());
	if (0 >= BIO_read_filename(inbio, filename)) {
		ERR_print_errors(bio_err);
		exit(EXIT_FAILURE);
	}
	if (NULL == (x509 = d2i_X509_bio(inbio, NULL))) {
		ERR_print_errors(bio_err);
		exit(EXIT_FAILURE);
	}

	/* get the subjectKeyIdentifier extensions from the certificate	*/
	nid = OBJ_sn2nid("subjectKeyIdentifier");
	if (nid < 0) {
		BIO_printf(bio_err, "%s:%d: object identifier for "
			"subjectKeyIdentifier found\n", __FILE__, __LINE__);
		ERR_print_errors(bio_err);
		exit(EXIT_FAILURE);
	}

	/* get the subject key identifier from the certificate		*/
	i = X509v3_get_ext_by_NID(x509->cert_info->extensions, nid, -1);
	if (i < 0) {
		BIO_printf(bio_err, "%s:%d: no matching extension found\n",
			__FILE__, __LINE__);
		ERR_print_errors(bio_err);
		exit(EXIT_FAILURE);
	}
	ex = X509_get_ext(x509, i);

	/* format the subject key identifier as a sequence of bytes	*/
	X509V3_EXT_print(out, ex, 0, 0);
	BIO_printf(out, "\n");

	/* return 0 to the caller					*/
	exit(EXIT_SUCCESS);
}
