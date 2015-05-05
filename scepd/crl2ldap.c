/*
 * crl2ldap.c -- push the crl to the LDAP directory, has the name of the
 *               CA node as argument and reads the CRL from standard input
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: crl2ldap.c,v 1.1.1.1 2001/03/03 22:23:22 afm Exp $
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <lber.h>
#include <ldap.h>

extern int	optind;
extern char	*optarg;

char	*ldaphost = "localhost";
int	ldapport = LDAP_PORT;
char	*binddn = NULL;
char	*bindpw = NULL;
int	debug = 0;

int	main(int argc, char *argv[]) {
	int		c, used, bytes;
	LDAP		*ldap;
	LDAPMod		crlmod, *mods[2];
	struct berval	crlval;
	struct berval	*crlvals[2];
	unsigned char 	*buffer;
	char		*dn;

	/* parse command line						*/
	while (EOF != (c = getopt(argc, argv, "D:w:b:h:p:d")))
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
			if ((ldapport <= 0) || (ldapport > 65535))
				ldapport = LDAP_PORT;
			break;
		}

	/* one remaining argument expected, must be the distinguished	*/
	/* name of the CA node						*/
	if ((argc - optind) != 1) {
		fprintf(stderr, "%s:%d: expecting exaclty one argument: CA "
			"distinguished name\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	dn = argv[optind];

	/* read the CRL from standard input				*/
	used = 0;
	buffer = (unsigned char *)malloc(1024);
	while (0 < (bytes = read(0, &buffer[used], 1024))) {
		used += bytes;
		buffer = (unsigned char *)realloc(buffer, used + 1024);
	}

	/* bind to the directory					*/
	ldap = ldap_init(ldaphost, ldapport);
	if (ldap == NULL) {
		fprintf(stderr, "%s:%d: cannot create LDAP structure\n",
			__FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	if (LDAP_SUCCESS != ldap_simple_bind_s(ldap, binddn, bindpw)) {
		fprintf(stderr, "%s:%d: cannot bind to the directory\n",
			__FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	/* perform the update						*/
	crlval.bv_len = used;
	crlval.bv_val = buffer;
	crlvals[0] = &crlval;
	crlvals[1] = NULL;
	crlmod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
	crlmod.mod_type = "certificateRevocationList;binary";
	crlmod.mod_bvalues = crlvals;
	mods[0] = &crlmod;
	mods[1] = NULL;

	if (LDAP_SUCCESS != ldap_modify_s(ldap, dn, mods)) {
		fprintf(stderr, "%s:%d: pushing CRL to LDAP failed\n",
			__FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	
	/* disconnect from the directory				*/
	ldap_unbind(ldap);
	exit(EXIT_SUCCESS);
}
