/*
 * check.c -- verify a client during automatic enrollment
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: check.c,v 1.5 2001/03/26 10:36:41 afm Exp $
 */
#include <check.h>
#include <init.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <ldap.h>
#include <scepldap.h>
#include <syslog.h>

char	*get_challenge(scep_t *scep) {
	int		loc, type, n;
	X509_ATTRIBUTE	*attr;
	X509_REQ	*req;
	ASN1_TYPE	*asn1;
	ASN1_IA5STRING	*asn1_string;
	char		*challenge;

	/* get our hands on the request					*/
	req = scep->clientreq;
	if (debug)
		BIO_printf(bio_err, "%s:%d: getting challenge password from "
			"X.509 request %p\n", __FILE__, __LINE__, req);

	/* if the client req is not set, we have no chance of finding	*/
	/* password							*/
	if (NULL == req) {
		BIO_printf(bio_err, "%s:%d: no X.509 request available\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* get the challengePassword attribute from the request		*/
	n = X509_REQ_get_attr_count(req);
	if (debug)
		BIO_printf(bio_err, "%s%d: %d attributes found\n", __FILE__,
			__LINE__, n);
	loc = X509_REQ_get_attr_by_NID(req, NID_pkcs9_challengePassword, -1);
	if (loc < 0) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: challengePassword not "
				"found\n", __FILE__, __LINE__);
		return NULL;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: challengePassword at offset %d\n",
			__FILE__, __LINE__, loc);
	attr = X509_REQ_get_attr(req, loc);

	/* retrieve the value of the challengePassword attribute	*/
	if (NULL == (asn1 = X509_ATTRIBUTE_get0_type(attr, 0))) {
		BIO_printf(bio_err, "%s:%d: cannot retrieve value\n",
			__FILE__, __LINE__);
		goto err;
	}
	
	type = ASN1_TYPE_get(asn1);
	if (debug)
		BIO_printf(bio_err, "%s:%d: type of challengePassword is %d\n",
			__FILE__, __LINE__, type);
	if ((type != V_ASN1_IA5STRING) && (type != V_ASN1_PRINTABLESTRING)) {
		BIO_printf(bio_err, "%s:%d: challengePassword has wrong type\n",
			__FILE__, __LINE__, type);
		goto err;
	}

	asn1_string = (ASN1_STRING *)asn1->value.ptr;
	challenge = (char *)malloc(asn1_string->length + 1);
	memcpy(challenge, asn1_string->data, asn1_string->length);
	challenge[asn1_string->length] = '\0';
	if (debug)
		BIO_printf(bio_err, "%s:%d: challenge Password '%s'\n",
			__FILE__, __LINE__, challenge);

	/* return the challenge password we have found			*/
	return challenge;

	/* error return							*/
err:
	ERR_print_errors(bio_err);
	return NULL;
}

int	check_challenge(scep_t *scep) {
	X509_REQ	*req;
	char		*challenge, *dn;
	X509_NAME	*subject;
	LDAP		*ldap = NULL;

	/* the clientreq field in the scep structure contains the 	*/
	/* request, even for getcertinitial messages where the request	*/
	/* does not contain the data originally sent with the request	*/
	req = scep->clientreq;
	if (debug)
		BIO_printf(bio_err, "%s:%d: checking challenge password in "
			"request %p\n", __FILE__, __LINE__, req);

	/* check whether is at all challenge password in the request	*/
	if (NULL == (challenge = get_challenge(scep))) {
		BIO_printf(bio_err, "%s:%d: no challenge password found\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: challenge Password '%s'\n",
			__FILE__, __LINE__, challenge);

	/* a challenge password of zero length is not authenticable	*/
	if (strlen(challenge) == 0) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: zero challenge\n",
				__FILE__, __LINE__);
		goto err;
	}

	/* get the client distinguished name				*/
	subject = X509_REQ_get_subject_name(req);
	if (debug) {
		char	name[1024];
		X509_NAME_oneline(subject, name, sizeof(name));
		BIO_printf(bio_err, "%s:%d: requestor: %s\n", __FILE__,
			__LINE__, name);
	}

	/* map to a suitable LDAP distinguished name			*/
	dn = x509_to_ldap(scep, subject);
	if (debug)
		BIO_printf(bio_err, "%s:%d: mapped requestor to LDAP DN '%s'\n",
			__FILE__, __LINE__, dn);

	/* connect to the ldap directory				*/
	ldap = ldap_open(scep->l.ldaphost, scep->l.ldapport);
	if (ldap == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot connect to %s:%d\n",
			__FILE__, __LINE__, scep->l.ldaphost, scep->l.ldapport);
		goto err;
	}

	/* authenticate the LDAP DN in the directory			*/
	if (ldap_simple_bind_s(ldap, dn, challenge) != LDAP_SUCCESS) {
		BIO_printf(bio_err, "%s:%d: cannot ldap_simple_bind_s\n",
			__FILE__, __LINE__);
		syslog(LOG_ERR, "LDAP authentication for %s failed", dn);
		goto err;
	}

	/* clean up any ldap connection					*/
	ldap_unbind(ldap);

	/* if we get to this point, then authentication was successful	*/
	BIO_printf(bio_err, "%s:%d: check successful\n", __FILE__, __LINE__);
	return 0;
err:
	/* XXX should do some cleanup here to prevent memory leaks	*/
	if (ldap) ldap_unbind(ldap);
	ERR_print_errors(bio_err);
	return -1;
}
