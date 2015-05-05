/*
 * ldap.c -- ldap interface for openscep
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: scepldap.c,v 1.7 2002/02/19 23:40:06 afm Exp $
 */
#include <config.h>
#include <lber.h>
#include <ldap.h>
#include <scep.h>
#include <scepldap.h>
#include <init.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <errno.h>
#include <string.h>
#include <check.h>

/*
 * there are essentially two types of mappings: 
 * - if the client specifies an unstructuredName name component of value x,
 *   then the LDAP distinguished name is just built from a fixed suffix
 *	unstructuredName=<x>,<suffix>
 * - if the client specifies reasonable name components, the are read backwards
 *   and concatenated to give a distinguished name
 */
char	*x509_to_ldap(scep_t *scep, X509_NAME *name) {
	char		*dn = NULL;
	int		ncomponents, dl = 0, nl, i, dnl;
	X509_NAME_ENTRY	*ne;
	char		oname[1024];
	const char	*sn;
	ASN1_OBJECT	*us;
	ASN1_STRING	*as;

	if (debug) {
		X509_NAME_oneline(name, oname, sizeof(oname));
		BIO_printf(bio_err, "%s:%d: LDAP mapping of %s requested\n",
			__FILE__, __LINE__, oname);
	}

	/* find out the object matching the unstructured name		*/
	if (NULL == (us = OBJ_nid2obj(NID_pkcs9_unstructuredName))) {
		BIO_printf(bio_err, "%s:%d: unstructuredName not found\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* find out whether the distinguished name contains an 		*/
	/* unstructuredName attribute					*/
	ncomponents = X509_NAME_entry_count(name);
	for (i = 0; i < ncomponents; i++) {
		ASN1_OBJECT	*o;
		o = X509_NAME_ENTRY_get_object(X509_NAME_get_entry(name, i));
		if (OBJ_cmp(o, us) == 0) {
			ne = X509_NAME_get_entry(name, i);
			break;
		}
	}

	/* create dn for an unstructured name				*/
	if (ne) {
		as = X509_NAME_ENTRY_get_data(ne);
		if (as == NULL) {
			BIO_printf(bio_err, "%s:%d: no data for unstruturedName"
				" attribute\n", __FILE__, __LINE__);
			goto err;
		}
		dnl = strlen("unstructuredName=,") + strlen(scep->l.ldapbase)
			+ as->length + 1;
		dn = (char *)malloc(dnl);
		if (debug)
			BIO_printf(bio_err, "%s:%d: unstructuredName has type "
				"%d length %d with value '%*.*s', allocated %d "
				" bytes\n", __FILE__,
				__LINE__, as->type, as->length, as->length,
				as->length, as->data, dnl);
		snprintf(dn, dnl, "unstructuredName=%*.*s,%s", as->length,
			as->length, as->data, scep->l.ldapbase);
		goto reply;
	}

	/* create dn for a ``normal'' name				*/
	for (i = X509_NAME_entry_count(name) - 1; i >= 0; i--) {
		us = X509_NAME_ENTRY_get_object(X509_NAME_get_entry(name, i));
		as = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i));
		sn = OBJ_nid2sn(OBJ_obj2nid(us));
		nl = strlen(sn) + as->length + 1;
		if (dl == 0) { nl += 2; }
		dn = (char *)realloc(dn, dl + nl + 2);
		snprintf(dn + dl, nl + 2, "%s%s=%*.*s",
			(dl == 0) ? "" : ",", us->sn, as->length, as->length,
			as->data);
		if (dl == 0)
			dl = nl;
		else
			dl += nl + 1;
	}

	/* common return (for debugging)				*/
reply:
	if (debug)
		BIO_printf(bio_err, "%s:%d: X509_NAME '%s' mapped to '%s'\n",
			__FILE__, __LINE__, oname, dn);
	return dn;

	/* error return							*/
err:
	return NULL;
}

/*
 * parsing an ldap distinguished name assumes (currently) that no dn component
 * contains any commas. It then separates the dn at the commas, splits
 * each part at the equal sign and creates a new X509 distinguished name
 * by retrieving an object for every dn attribute name and assigning
 * a ASN1_STRING as value.
 */
X509_NAME	*ldap_to_x509(char *dn) {
	char		*wdn, *comp, *name, *value;
	X509_NAME	*DN;
	X509_NAME_ENTRY	*ne;
	int		i = 0, type;

	/* create a copy of the distinguished name to work on		*/
	wdn = strdup(dn);

	/* create a new X509_NAME structure				*/
	DN = X509_NAME_new();

	/* start from right, looking for ','				*/
	do {
		/* get the last component				*/
		comp = strrchr(wdn, ',');
		if (comp == NULL) {
			comp = wdn;
		} else {
			*comp = '\0'; comp++;
		}

		/* split the string at the =				*/
		name = comp;
		value = strchr(name, '=');
		if (value == NULL) {
			BIO_printf(bio_err, "%s:%d: no = on dn component %s\n",
				__FILE__, __LINE__, name);
			goto err;
		}
		*value = '\0'; value++;
		if (debug)
			BIO_printf(bio_err, "%s:%d: found name = '%s', "
				"value = '%s'\n", __FILE__, __LINE__, name,
				value);

		/* find the type an attribute of this name should have	*/
		type = V_ASN1_PRINTABLESTRING;

		/* create a new name component				*/
		ne = X509_NAME_ENTRY_create_by_txt(NULL, name, type,
			(unsigned char *)value, strlen(value));
		if (ne == NULL) {
			BIO_printf(bio_err, "%s:%d: cannot create name entry "
				"%s=%s\n", __FILE__, __LINE__, name, value);
			goto err;
		}
		X509_NAME_add_entry(DN, ne, i++, 0);
	} while (wdn != comp);

	/* distinguished name constructed				*/
	return DN;
	
	/* error return							*/
err:
	return NULL;
}

/*
 * initialize the ldap connection
 */
int	scep_ldap_init(scep_t *scep) {
	/* initialize the LDAP structure				*/
	if (NULL == (scep->l.ldap = ldap_init(scep->l.ldaphost,
		scep->l.ldapport))) {
		BIO_printf(bio_err, "%s:%d: cannot initialize LDAP: %s (%d)\n",
			__FILE__, __LINE__, strerror(errno), errno);
		goto err;
        }
	if (debug)
		BIO_printf(bio_err, "%s:%d: LDAP %s:%d initialized\n",
			__FILE__, __LINE__, scep->l.ldaphost, scep->l.ldapport);

	/* perform a bind, if required by the configuration		*/
	if ((scep->l.binddn) && (scep->l.bindpw)) {
		if (LDAP_SUCCESS != ldap_simple_bind_s(scep->l.ldap,
			scep->l.binddn, scep->l.bindpw)) {
			BIO_printf(bio_err, "%s:%d: bind failed\n", __FILE__,
				__LINE__);
			goto err;
		}
		if (debug)
			BIO_printf(bio_err, "%s:%d: LDAP bind complete\n",
				__FILE__, __LINE__);
	} else
		if (debug)
			BIO_printf(bio_err, "%s:%d: LDAP bind not necessary, "
				"insufficient parameters\n", __FILE__,
				__LINE__);
	return 0;

	/* error return							*/
err:
	/* make sure the LDAP structure is deleted			*/
	if (scep->l.ldap != NULL) {
		ldap_unbind(scep->l.ldap);
		scep->l.ldap = NULL;
	}
	ERR_print_errors(bio_err);
	return -1;
}

/*
 * asn1_to_string
 *
 * convert an ASN1_INTEGER into string form, for easy storage of the serial
 * number of a certificate in the directory. We do this by converting the
 * bytes into colon separated hex codes. Stolen from mod_authz_ldap.
 */
static char	*asn1_to_string(ASN1_INTEGER *i) {
	char	*cp, *p;
	int	j;

	cp = (char *)malloc(1 + (3 * i->length));
	p = cp;
	if (i->type == V_ASN1_NEG_INTEGER) {
		*(p++) = '-';
	}
	for (j = 0; j < i->length; j++) {
		if (j) *(p++) = ':';
		snprintf(p, 3, "%02X", i->data[j]); p += 2;
	}
	return cp;
}

/*
 * store a certificate readily available from the filesystem in the LDAP
 * directory
 */
int	ldap_store_cert(scep_t *scep) {
	char		filename[1024];
	char		issuerDN[1024], subjectDN[1024];
	ASN1_INTEGER	*serialNumber;
	char		*dn, *serial, *challenge;
	LDAPMessage	*result;
	char		*ocvals[3], *idnvals[2], *sdnvals[2], *servals[2],
			*upvals[2];
	struct berval	*certvals[2];
	struct berval	certval;
	LDAPMod		ocmod, idnmod, sdnmod, sermod, certmod, upmod;
	LDAPMod		*mods[5];
	BIO		*bio_mem;
	int		rc;

	/* if we don't have LDAP, we just fake a successful storing of	*/
	/* the certificate						*/
	if (scep->l.ldap == NULL) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: no LDAP, store_cert "
				"faked\n", __FILE__, __LINE__);
		return 0;
	}

	/* first get the certificate from the file system		*/
	if (scep->clientcert != NULL) {
		BIO	*x509_bio;
		snprintf(filename, sizeof(filename), "%s/granted/%s.der",
			OPENSCEPDIR, scep->transId);
		x509_bio = BIO_new(BIO_s_file());
		BIO_read_filename(x509_bio, filename);
		scep->clientcert = d2i_X509_bio(x509_bio, NULL);
		if (scep->clientcert == NULL) {
			BIO_printf(bio_err, "%s:%d: cannot get the client "
				"certificate from the file system\n", __FILE__,
				__LINE__);
			goto err;
		}
		BIO_free(x509_bio);
	}

	/* convert the distinguished name of the certificate to an LDAP	*/
	/* distinguished name						*/
	dn = x509_to_ldap(scep, X509_get_subject_name(scep->clientcert));
	if (dn == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot convert DN to LDAP form\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* find out whether the node already exists			*/
	if (LDAP_SUCCESS != (rc = ldap_search_s(scep->l.ldap, dn,
		LDAP_SCOPE_BASE, "(objectclass=*)", NULL, 1, &result))) {
		/* add the node if it does not exist yet		*/
		ocvals[0] = "top";
		ocvals[1] = "sCEPClient";
		ocvals[2] = NULL;
		ocmod.mod_op = LDAP_MOD_ADD;
		ocmod.mod_type = "objectclass";
		ocmod.mod_values = ocvals;
		mods[0] = &ocmod;
		mods[1] = NULL;
		if (ldap_add_s(scep->l.ldap, dn, mods) != LDAP_SUCCESS) {
			BIO_printf(bio_err, "%s:%d: cannot add new node %s\n",
				__FILE__, __LINE__, dn);
			goto err;
		}
		if (debug)
			BIO_printf(bio_err, "%s:%d: adding skeleton node for "
				"%s\n", __FILE__, __LINE__, dn);
	}

	/* convert distinguished names and serial numbers into text	*/
	X509_NAME_oneline(X509_get_issuer_name(scep->clientcert),
		issuerDN, sizeof(issuerDN));
	X509_NAME_oneline(X509_get_subject_name(scep->clientcert),
		subjectDN, sizeof(subjectDN));
	serialNumber = X509_get_serialNumber(scep->clientcert);
	serial = asn1_to_string(serialNumber);
	if (debug) {
		BIO_printf(bio_err, "%s:%d: replacing attributes in dn = %s:\n",
			__FILE__, __LINE__, dn);
		BIO_printf(bio_err, "%s:%d:\tissuerDN=%s\n", __FILE__,
			__LINE__, issuerDN);
		BIO_printf(bio_err, "%s:%d:\tsubjectDN=%s\n", __FILE__,
			__LINE__, subjectDN);
		BIO_printf(bio_err, "%s:%d:\tserialNumber=%s\n", __FILE__,
			__LINE__, serial);
	}

	/* get the challenge password from the request, if it is there	*/
	challenge = get_challenge(scep);
	if (debug)
		BIO_printf(bio_err, "%s:%d: got challenge password: %s\n",
			__FILE__, __LINE__, (challenge) ? challenge: "<null>");

	/* add certificate, serial number, issuer distinguished named	*/
	/* and subject distinguished name as read from the certificate	*/
	/* (without mapping) as attributes to possibly new the entry	*/
	servals[0] = serial;
	servals[1] = NULL;
	sermod.mod_op = LDAP_MOD_REPLACE;
	sermod.mod_type = "serialNumber";
	sermod.mod_values = servals;

	idnvals[0] = issuerDN;
	idnvals[1] = NULL;
	idnmod.mod_op = LDAP_MOD_REPLACE;
	idnmod.mod_type = "issuerDN";
	idnmod.mod_values = idnvals;

	sdnvals[0] = subjectDN;
	sdnvals[1] = NULL;
	sdnmod.mod_op = LDAP_MOD_REPLACE;
	sdnmod.mod_type = "subjectDN";
	sdnmod.mod_values = sdnvals;

	certvals[0] = &certval;
	certvals[1] = NULL;
	certmod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
	certmod.mod_type = "userCertificate;binary";
	certmod.mod_bvalues = certvals;

	bio_mem = BIO_new(BIO_s_mem());
	if (!i2d_X509_bio(bio_mem, scep->clientcert)) {
		BIO_printf(bio_err, "%s:%d: cannot write client cert as DER\n",
			__FILE__, __LINE__);
		goto err;
	}
	BIO_set_flags(bio_mem, BIO_FLAGS_MEM_RDONLY);
	certval.bv_len = BIO_get_mem_data(bio_mem, &certval.bv_val);
	BIO_free(bio_mem);

	mods[0] = &sermod;
	mods[1] = &idnmod;
	mods[2] = &sdnmod;
	mods[3] = &certmod;
	if (challenge) {
		upvals[0] = challenge;
		upvals[1] = NULL;
		upmod.mod_op = LDAP_MOD_REPLACE;
		upmod.mod_type = "userPassword";
		upmod.mod_values = upvals;
		mods[4] = &upmod;
	} else {
		mods[4] = NULL;
	}
	mods[5] = NULL;

	if (LDAP_SUCCESS != ldap_modify_s(scep->l.ldap, dn, mods)) {
		BIO_printf(bio_err, "%s:%d: cannot update directory with cert "
			"and attributes\n", __FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: certificate and attributes for "
			"%s successfully added\n", __FILE__, __LINE__, dn);

	/* cleanup							*/
	free(certval.bv_val);
	free(serial);
	free(dn);

	/* success							*/
	return 0;

	/* error return							*/
err:
	ERR_print_errors(bio_err);
	return -1;
}

/*
 * ldap_get_cert_from_issuer_and_{serial,subject}
 *
 * retrieve a certificate from the LDAP directory based on issuer DN and
 * either serial number or subject DN.
 * At the end of either routine, the certificate is is referenced through
 * the clientcert field of the scep structure
 */
static int	ldap_get_cert_common(scep_t *scep, char *filter) {
	LDAPMessage	*result, *e;
	struct berval	**bv;
	BIO		*bio;

	/* perform the search						*/
	if (LDAP_SUCCESS != ldap_search_s(scep->l.ldap, scep->l.ldapbase,
		LDAP_SCOPE_SUBTREE, filter, NULL, 0, &result)) {
		BIO_printf(bio_err, "%s:%d: cannot find certificate\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* the filter should return exactly one value			*/
	if (ldap_count_entries(scep->l.ldap, result) != 1) {
		BIO_printf(bio_err, "%s:%d: wrong number of entries returned\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* retrieve the the entry from the result			*/
	e = ldap_first_entry(scep->l.ldap, result);
	if (debug)
		BIO_printf(bio_err, "%s:%d: retrieving certificate from %s\n",
			__FILE__, __LINE__, ldap_get_dn(scep->l.ldap, e));

	/* retrieve the attribute, as we only asked for the 		*/
	/* userCertificate attribute, the first attribute should be ok	*/
	bv = ldap_get_values_len(scep->l.ldap, e, "userCertificate");
	if (bv == NULL) {
		BIO_printf(bio_err, "%s:%d: attribute not found\n", __FILE__,
			__LINE__);
		goto err;
	}

	/* add the certificate retrieved to the clientcert field of the	*/
	/* scep structure						*/
	bio = BIO_new(BIO_s_mem());
	BIO_write(bio, bv[0]->bv_val, bv[0]->bv_len);
	scep->clientcert = d2i_X509_bio(bio, NULL);
	if (scep->clientcert == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot decode certificate "
			"retrieved from LDAP directory\n", __FILE__, __LINE__);
		goto err;
	}
	BIO_free(bio);

	/* success							*/
	return 0;

	/* error return							*/
err:
	ERR_print_errors(bio_err);
	return -1;
}

int	ldap_get_cert_from_issuer_and_serial(scep_t *scep,
	PKCS7_ISSUER_AND_SERIAL *ias) {
	char		issuerDN[1024], filter[2048];
	char		*serial = NULL;
	int		rc;

	/* without LDAP, we must signal an error			*/
	if (scep->l.ldap == NULL)
		goto err;

	/* formulate an appropriate search filter: get an entry of	*/
	/* class sCEPClient, with matching serial number and issuerDN	*/
	/* and having a userCertificate attribute			*/
	X509_NAME_oneline(ias->issuer, issuerDN, sizeof(issuerDN));
	serial = asn1_to_string(ias->serial);
	snprintf(filter, sizeof(filter), "(&(objectclass=sCEPClient)"
		"(issuerDN=%s)(serialNumber=%s)(userCertificate=*)",
		issuerDN, serial);
	if (debug)
		BIO_printf(bio_err, "%s:%d: search filter: %s\n",
			__FILE__, __LINE__, filter);

	/* common part of certificate retrieval				*/
	rc = ldap_get_cert_common(scep, filter);
	if (rc < 0) {
		BIO_printf(bio_err, "%s:%d: certificate retrieval common part "
			"failed\n", __FILE__, __LINE__);
		goto err;
	}

	/* success							*/
	free(serial);
	return 0;

	/* error return							*/
err:
	ERR_print_errors(bio_err);
	if (serial) free(serial);
	return -1;
}

int	ldap_get_cert_from_issuer_and_subject(scep_t *scep,
	issuer_and_subject_t *ias) {
	char		filter[2048];
	char		issuerDN[1024], subjectDN[1024];
	int		rc;

	/* without LDAP, we must signal an error			*/
	if (scep->l.ldap == NULL)
		goto err;

	/* convert the ias structure into an LDAP filter		*/
	X509_NAME_oneline(ias->issuer, issuerDN, sizeof(issuerDN));
	X509_NAME_oneline(ias->subject, subjectDN, sizeof(subjectDN));
	snprintf(filter, sizeof(filter), "(&objectClass=sCEPClient)"
		"(issuerDN=%s)(subjectDN=%s)(userCertificate=*))",
		issuerDN, subjectDN);
	if (debug)
		BIO_printf(bio_err, "%s:%d: searching for certificate with "
			"filter '%s'\n", __FILE__, __LINE__, filter);

	/* perform the search using the common part 			*/
	rc = ldap_get_cert_common(scep, filter);
	if (rc < 0) {
		BIO_printf(bio_err, "%s:%d: cannot get cert common\n", 
			__FILE__, __LINE__);
		goto err;
	}

	return 0;
	/* error return							*/
err:
	ERR_print_errors(bio_err);
	return -1;
}
