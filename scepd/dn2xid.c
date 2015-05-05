/*
 * dn2cert.c -- retrieve the certificate to a given distinguished name
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: dn2xid.c,v 1.2 2001/03/26 10:36:47 afm Exp $
 */
#include <stdlib.h>
#include <stdio.h>
#include <lber.h>
#include <ldap.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <fingerprint.h>
#include <ctype.h>
#include <string.h>

int	debug = 0;

extern int	optind;
extern char	*optarg;

char	*ldaphost = "localhost";
int	ldapport = LDAP_PORT;
char	*binddn = NULL;
char	*bindpw = NULL;

BIO	*bio_err;

int	main(int argc, char *argv[]) {
	int		c, length, l;
	char		*dn, *fp, *p;
	LDAP		*ldap;
	LDAPMessage	*result, *e;
	struct berval	**bs;
	BIO		*bio;
	X509		*x509;
	unsigned char	*data;

	/* parse command line						*/
	while (EOF != (c = getopt(argc, argv, "dD:w:h:p:")))
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'D':
			binddn = optarg;
			break;
		case 'w':
			bindpw = optarg;
			break;
		case 'h':
			ldaphost = optarg;
			break;
		case 'p':
			ldapport = atoi(optarg);
			if ((ldapport < 0) || (ldapport > 65535))
				ldapport = LDAP_PORT;
			break;
		}
	

	/* remaining argument should be the DN				*/
	if ((argc - optind) != 1) {
		fprintf(stderr, "%s:%d: wrong number of arguments\n",
			__FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	dn = argv[optind];

	/* create an ldap session					*/
	ldap = ldap_init(ldaphost, ldapport);
	if (ldap == NULL) {
		fprintf(stderr, "%s:%d: cannot connect to LDAP\n", __FILE__,
			__LINE__);
		exit(EXIT_FAILURE);
	}
	if (LDAP_SUCCESS != ldap_simple_bind_s(ldap, binddn, bindpw)) {
		fprintf(stderr, "%s:%d: cannot bind to the directory\n",
			__FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	/* retrieve the certificate to a given DN			*/
	if (LDAP_SUCCESS != ldap_search_s(ldap, dn, LDAP_SCOPE_BASE,
		"(userCertificate=*)", NULL, 0, &result)) {
		fprintf(stderr, "%s:%d: search for '%s' failed: %s\n", __FILE__,
			__LINE__, dn,
			ldap_err2string(ldap_result2error(ldap, result, 0)));
		exit(EXIT_FAILURE);
	}
	if (ldap_count_entries(ldap, result) != 1) {
		fprintf(stderr, "%s:%d: not exactly one entry found\n",
			__FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	e = ldap_first_entry(ldap, result);

	/* parse reply for certificate					*/
	bs = ldap_get_values_len(ldap, e, "userCertificate;binary");
	if (bs == 0) {
		fprintf(stderr, "%s:%d: userCertificate not found\n",
			__FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	if (bs[1] != NULL) {
		fprintf(stderr, "%s:%d: cannot handle more than one "
			"certificate\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	/* initialize as much of OpenSSL as we need			*/
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	bio_err = BIO_new(BIO_s_file());
	BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

	/* create a memory BIO to write the certificate to		*/
	bio = BIO_new(BIO_s_mem());
	if (bs[0]->bv_len != BIO_write(bio, bs[0]->bv_val, bs[0]->bv_len)) {
		fprintf(stderr, "%s:%d: writing cert to bio failed\n",
			__FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	/* convert certificate data to X509 structure			*/
	x509 = d2i_X509_bio(bio, NULL);
	BIO_free(bio);

	/* convert the public key to a memory block			*/
	bio = BIO_new(BIO_s_mem());
	i2d_PUBKEY_bio(bio, X509_get_pubkey(x509));

	/* compute a data block of private key				*/
	length = BIO_get_mem_data(bio, &data);
	BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);
	BIO_free(bio);

	/* fingerprint the data						*/
	fp = fingerprint(data, length);

	/* remove all whitespace					*/
	p = fp;
	for (p = fp; *p; p++) {
		while ((*p) && (isspace(*p))) {
			l = strlen(p + 1);
			memmove(p, p + 1, strlen(p + 1));
			*(p + l) = '\0';
		}
	}

	/* display the transaction id					*/
	printf("%s\n", fp);

	/* that's it							*/
	ldap_unbind(ldap);
	exit(EXIT_SUCCESS);
}
