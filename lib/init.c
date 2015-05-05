/*
 * init.c -- common library initializations used in all programs that
 *           work with openssl
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: init.c,v 1.9 2002/02/19 23:40:06 afm Exp $
 */
#include <init.h>
#include <config.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <lber.h>
#include <ldap.h>
#include <syslog.h>
#include <openscep_vers.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define	TMPPATH	"/var/tmp/openscep"

int	debug = 1;
char	*tmppath = NULL;	
BIO	*bio_err = NULL;

typedef struct {
	int	nid;
	char	*oid;
	char	*name1;
	char	*name2;
} niddef_t;
#define	NEW_NIDS	8
static niddef_t	scep_oid_def[NEW_NIDS] = {
    { 0, "2.16.840.1.113733.1.9.2", "messageType",	"messageType" },
    { 0, "2.16.840.1.113733.1.9.3", "pkiStatus",	"pkiStatus" },
    { 0, "2.16.840.1.113733.1.9.4", "failInfo",		"failInfo" },
    { 0, "2.16.840.1.113733.1.9.5", "senderNonce",	"senderNonce" },
    { 0, "2.16.840.1.113733.1.9.6", "recipientNonce",	"recipientNonce" },
    { 0, "2.16.840.1.113733.1.9.7", "transId",		"transId" },
    { 0, "2.16.840.1.113733.1.9.8", "extensionReq",	"extensionReq" },
    { 0, "1.3.6.1.4.1.4263.5.5",    "proxyAuthenticator","proxyAuthenticator" },
};

/*
 * initialize the openssl library and any library related data structures
 * used in all SCEP transactions
 * XXX improve error checking
 */
int	scepinit(void) {
	int		i;
	unsigned char	randpool[1024];
	struct stat	sb;

	/* initialize the syslog					*/
	openlog("scep", LOG_PID|LOG_NDELAY, LOG_FACILITY);

	/* log the version of scepd starting				*/
	syslog(LOG_DEBUG, "version %s starting", openscep_version.v_long);

	/* initialize error message strings				*/
	ERR_load_crypto_strings();
	if (debug)
		fprintf(stderr, "%s:%d: crypto strings loaded\n", __FILE__,
			__LINE__);

	/* add the encryption algorithms available			*/
	OpenSSL_add_all_algorithms();
	if (debug)
		fprintf(stderr, "%s:%d: algorithms added\n", __FILE__,
			__LINE__);

	/* provide a entropy source					*/
	RAND_seed(randpool, sizeof(randpool));
	if (debug)
		fprintf(stderr, "%s:%d: random source seeded\n", __FILE__,
			__LINE__);

	/* activate the standard error BIO, which we use for error	*/
	/* messages							*/
	if ((bio_err = BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
	if (debug)
		BIO_printf(bio_err, "%s:%d: stderr BIO initialized\n",
			__FILE__, __LINE__);

	/* define the new object definitions needed for SCEP		*/
	for (i = 0; i < NEW_NIDS; i++) {
		scep_oid_def[i].nid = OBJ_create(scep_oid_def[i].oid,
			scep_oid_def[i].name1, scep_oid_def[i].name2);
		if (debug)
			BIO_printf(bio_err, "%s:%d: added oid %s for name %s\n",
				__FILE__, __LINE__, scep_oid_def[i].oid,
				scep_oid_def[i].name1);
	}

	/* find out whether the /var/tmp/openscep directory is there	*/
	if (stat(TMPPATH, &sb) == 0) {
		if (S_ISDIR(sb.st_mode))
			if (access(TMPPATH, W_OK) == 0)
				tmppath = TMPPATH;
	}

	/* no problem encountered					*/
	return 0;
}

void	scep_clear(scep_t *scep) {
	/* set the whole structure to NULL				*/
	if (scep)
		memset(scep, 0, sizeof(scep_t));
	scep->check_transid = 1;
	scep->l.ldaphost = "localhost";
	scep->l.ldapport = LDAP_PORT;
	if (debug)
		BIO_printf(bio_err, "%s:%d: scep structure initialized\n",
			__FILE__, __LINE__);
}

int	scep_config(scep_t *scep, char *configfile) {
	char	*name;
	BIO	*bio;
	long	eline;

	/* open the configuration file					*/
	scep->conf = CONF_load(NULL, (configfile) ? configfile
				: OPENSCEPDIR "/openscep.cnf", &eline);
	if (scep->conf == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot read config file %s\n",
			__FILE__, __LINE__, configfile);
		goto err;
	}

	/* see whether the configuration knows something about debug	*/
	name = CONF_get_string(scep->conf, "scepd", "debug");
	if (name) {
		if (atoi(name) > 0)
			debug = atoi(name);
		if (debug)
			BIO_printf(bio_err, "%s:%d: conf sets debug to %d\n",
				__FILE__, __LINE__, debug);
	}

	/* scan the configuration for some common values		*/
	scep->name = CONF_get_string(scep->conf, "scepd", "name");
	if (debug)
		BIO_printf(bio_err, "%s:%d: name: %s\n", __FILE__, __LINE__,
			scep->name);

	/* get the ca certificate, private key and crl			*/
	name = CONF_get_string(scep->conf, "scepd", "cacert");
	name = (name) ? name : OPENSCEPDIR "/cacert.pem";
	bio = BIO_new(BIO_s_file());
	BIO_read_filename(bio, name);
	scep->cacert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (scep->cacert == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot read CA "
			"certificate\n", __FILE__, __LINE__);
		goto err;
	}
	BIO_free(bio);
	if (debug)
		BIO_printf(bio_err, "%s:%d: CA certificate from %s read\n",
			__FILE__, __LINE__, name);

	name = CONF_get_string(scep->conf, "scepd", "cakey");
	name = (name) ? name : OPENSCEPDIR "/cakey.pem";
	bio = BIO_new(BIO_s_file());
	BIO_read_filename(bio, name);
	scep->capkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (scep->capkey == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot read private key\n",
			__FILE__, __LINE__);
		goto err;
	}
	BIO_free(bio);
	if (debug)
		BIO_printf(bio_err, "%s:%d: CA private key from %s read\n",
			__FILE__, __LINE__, name);

	name = CONF_get_string(scep->conf, "scepd", "crl");
	name = (name) ? name : OPENSCEPDIR "/crl.pem";
	bio = BIO_new(BIO_s_file());
	BIO_read_filename(bio, name);
	scep->crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
	if (scep->crl == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot read CRL\n",
			__FILE__, __LINE__);
		goto err;
	}
	BIO_free(bio);
	if (debug)
		BIO_printf(bio_err, "%s:%d: CA CRL from %s read\n",
			__FILE__, __LINE__, name);

	/* set ldap parameters						*/
	scep->l.ldaphost = CONF_get_string(scep->conf, "ldap", "ldaphost");
	scep->l.ldapport = atoi(CONF_get_string(scep->conf, "ldap", "ldapport"));
	scep->l.ldapbase = CONF_get_string(scep->conf, "ldap", "ldapbase");
	scep->l.binddn = CONF_get_string(scep->conf, "ldap", "binddn");
	scep->l.bindpw = CONF_get_string(scep->conf, "ldap", "bindpw");
	if (debug)
		BIO_printf(bio_err, "%s:%d: LDAP parameters ldap://%s:%d, "
			"base %s, bind as %s/%s\n", __FILE__, __LINE__,
			scep->l.ldaphost, scep->l.ldapport,
			(scep->l.ldapbase) ? scep->l.ldapbase : "(not set)",
			(scep->l.binddn) ? scep->l.binddn : "(not set)",
			(scep->l.bindpw) ? scep->l.bindpw : "(not set)");

	/* configure automatic granting of requests			*/
	name = CONF_get_string(scep->conf, "scepd", "automatic");
	if (name != NULL) {
		if (strcasecmp(name, "true") == 0) {
			scep->automatic = 1;
			if (debug)
				BIO_printf(bio_err, "%s:%d: automatic mode "
					"enabled\n", __FILE__, __LINE__);
		}
	}

	/* check for transaction id checking against fingerprint	*/
	name = CONF_get_string(scep->conf, "scepd", "checktransid");
	if (name != NULL) {
		if ((strcasecmp(name, "false") == 0) ||
			(strcasecmp(name, "no") == 0)) {
			scep->check_transid = 0;
			if (debug)
				BIO_printf(bio_err, "%s:%d: check of transid "
					"against fingerprint disabled\n",
					__FILE__, __LINE__);
		}
	}

	/* check for the proxy community string				*/
	name = CONF_get_string(scep->conf, "scepd", "proxycommunity");
	if (name != NULL) {
		scep->community = strdup(name);
		if (debug)
			BIO_printf(bio_err, "%s:%d: proxy community is '%s'\n",
				__FILE__, __LINE__, scep->community);
	}

	return 0;
	/* error return							*/
err:
	ERR_print_errors(bio_err);
	return -1;
}
