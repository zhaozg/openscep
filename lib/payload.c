/*
 * payload.c -- the version 2 draft specifies various request data types,
 *              so if a SCEP request contains the proxyRequestType attribute
 *              we should parse the decrypted data as a payload structure
 *              and not as PKCS#10
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: payload.c,v 1.2 2002/02/24 21:40:01 afm Exp $
 */
#include <openssl/asn1_mac.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <payload.h>
#include <init.h>
#include <missl.h>
#include <scepldap.h>
#include <fcntl.h>

/*
 * payload_build_original	convert the original request into a bit string
 */
void	payload_build_original(payload_t *pl) {
	unsigned char	*r = NULL, *r2;
	long		l;

	if (debug)
		BIO_printf(bio_err, "%s:%d: converting type %d payload\n",
			__FILE__, __LINE__, pl->rt);

	/* convert the structure into a block of memory			*/
	switch (pl->rt) {
	case 0:
		l = i2d_X509_REQ(pl->od.req, NULL);
		r2 = r = (unsigned char *)malloc(l);
		l = i2d_X509_REQ(pl->od.req, &r2);
		if (debug)
			BIO_printf(bio_err, "%s:%d: payload request converted "
				"to DER: %d bytes\n", __FILE__, __LINE__, l);
		break;
	case 1:
		l = i2d_NETSCAPE_SPKI(pl->od.spki, NULL);
		r2 = r = (unsigned char *)malloc(l);
		l = i2d_NETSCAPE_SPKI(pl->od.spki, &r2);
		if (debug)
			BIO_printf(bio_err, "%s:%d: payload SPKI converted "
				"to DER: %d bytes\n", __FILE__, __LINE__, l);
		break;
	}

	/* as the ASN1_BIT_STRING is already there, we only have to 	*/
	/* assign it the data						*/
	ASN1_BIT_STRING_set(pl->original, r, l);
	BIO_printf(bio_err, "%s:%d: saved %d bytes at %p in pl->original\n",
		__FILE__, __LINE__, l, r);
}

/*
 * allocators and deallocators for the payload_t functions
 */
payload_t	*payload_new() {
	payload_t	*p = NULL;
	ASN1_CTX	c;
	M_ASN1_New_Malloc(p, payload_t);
	M_ASN1_New(p->requesttype, ASN1_INTEGER_new);
	M_ASN1_New(p->original, ASN1_BIT_STRING_new);
	M_ASN1_New(p->attributes, sk_X509_ATTRIBUTE_new_null);
	p->rt = -1;
	p->od.req = NULL;
	return p;
	M_ASN1_New_Error(ASN1_F_X509_REQ_INFO_NEW);	/* wrong error code */
}

void	payload_free(payload_t *a) {
	if (NULL == a)
		return;
	ASN1_INTEGER_free(a->requesttype);
	ASN1_BIT_STRING_free(a->original);
	sk_X509_ATTRIBUTE_pop_free(a->attributes, X509_ATTRIBUTE_free);
	switch (a->rt) {
	case 0:
		if (a->od.req) {
			X509_REQ_free(a->od.req);
			a->od.req = NULL;
		}
		break;
	case 1:
		if (a->od.spki) {
			NETSCAPE_SPKI_free(a->od.spki);
			a->od.spki = NULL;
		}
		break;
	default:
		/* should not happen					*/
		break;
	}
	OPENSSL_free(a);
}

/*
 * encoding and decodign functions for the payload structure
 */
int	i2d_payload(payload_t *a, unsigned char **pp) {
	M_ASN1_I2D_vars(a);
	if (debug)
		BIO_printf(bio_err, "%s:%d: i2d_payload called\n",
			__FILE__, __LINE__);
	payload_build_original(a);
	M_ASN1_I2D_len(a->requesttype, i2d_ASN1_INTEGER);
	M_ASN1_I2D_len(a->original, i2d_ASN1_BIT_STRING);
	M_ASN1_I2D_len_IMP_SET_type(X509_ATTRIBUTE, a->attributes,
		i2d_X509_ATTRIBUTE, 1);
	M_ASN1_I2D_seq_total();
	M_ASN1_I2D_put(a->requesttype, i2d_ASN1_INTEGER);
	M_ASN1_I2D_put(a->original, i2d_ASN1_BIT_STRING);
	M_ASN1_I2D_put_IMP_SET_type(X509_ATTRIBUTE, a->attributes,
		i2d_X509_ATTRIBUTE, 1);
	M_ASN1_I2D_finish();
}

payload_t	*d2i_payload(payload_t **a, unsigned char **pp, long length) {
	unsigned char	*u;
	long		l;
	X509_REQ	*r1;
	NETSCAPE_SPKI	*r2;

	M_ASN1_D2I_vars(a, payload_t *, payload_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->requesttype, d2i_ASN1_INTEGER);
	M_ASN1_D2I_get(ret->original, d2i_ASN1_BIT_STRING);
	M_ASN1_D2I_get_IMP_set_type(X509_ATTRIBUTE, ret->attributes,
		d2i_X509_ATTRIBUTE, X509_ATTRIBUTE_free, 1);
	ret->rt = ASN1_INTEGER_get(ret->requesttype);
	if (debug)
		BIO_printf(bio_err, "%s:%d: payload type: %d\n",
			__FILE__, __LINE__, ret->rt);
	u = ret->original->data;
	l = ret->original->length;
	if (debug) {
		BIO_printf(bio_err, "%s:%d: decoding %d payload bytes\n",
			__FILE__, __LINE__, l);
		if (tmppath) {
			char	filename[1024];
			int	fd;
			/* compute filename for original data		*/
			snprintf(filename, sizeof(filename),
				"%s/%d.d-4-original.der", tmppath, getpid());
			BIO_printf(bio_err, "%s:%d: write original data to "
				"%s\n", __FILE__, __LINE__, filename);

			/* write data to file				*/
			if (0 <= (fd = open(filename, O_WRONLY | O_CREAT
				| O_TRUNC, 066))) {
				write(fd, u, l);
				close(fd);
			} else {
				BIO_printf(bio_err, "%s:%d: cannot open file "
					"%s: %s (%d)\n", __FILE__, __LINE__,
					filename, strerror(errno), errno);
			}
		}
	}
	switch (ret->rt) {
	case 0:
		r1 = NULL;
		ret->od.req = d2i_X509_REQ(&r1, &u, l);
		break;
	case 1:
		r2 = NULL;
		ret->od.spki = d2i_NETSCAPE_SPKI(&r2, &u, l);
		break;
	}
	M_ASN1_D2I_Finish(a, payload_free, ASN1_F_D2I_X509_REQ_INFO);
}

/*
 * functions used to extract a certificate request
 */
X509_REQ	*payload_getreq(payload_t *pl) {
	/* make sure the request really contains a PKCS#10 request	*/
	if (pl->rt != 0) {
		BIO_printf(bio_err, "%s:%d: not a PKCS#10 request\n",
			__FILE__, __LINE__);
		return NULL;
	}

	return pl->od.req;
}

NETSCAPE_SPKI	*payload_getspki(payload_t *pl) {
	/* make sure thre request really contains SPKAC request		*/
	if (pl->rt != 1) {
		BIO_printf(bio_err, "%s:%d: not an SPKI request\n", __FILE__,
			__LINE__);
		return NULL;
	}

	return pl->od.spki;
}

long	payload_get_requesttype(payload_t *pl) {
	return pl->rt;
}

/*
 * clean the original data section from any previous structures which
 * are no longer needed
 */
static void	payload_free_od(payload_t *pl) {
	if (NULL == pl->od.req)
		return;
	switch (pl->rt) {
	case 0:
		X509_REQ_free(pl->od.req);
		pl->od.req = NULL;
		break;
	case 1:
		NETSCAPE_SPKI_free(pl->od.spki);
		pl->od.spki = NULL;
		break;
	}
}

/*
 * payload_set_common	open the file and prepare a BIO to read any type
 *			of request from
 */
static BIO	*payload_set_common(payload_t *pl, char *filename) {
	BIO	*inbio = NULL;
	payload_free_od(pl);
	inbio = BIO_new(BIO_s_file());
	BIO_read_filename(inbio, filename);
	return inbio;
	
}

/*
 * payload_set_req_from_file	read a X509 Request from a file and assign
 *				it to the request structure
 */
int	payload_set_req(payload_t *pl, X509_REQ *req) {
	if (debug)
		BIO_printf(bio_err, "%s:%d: setting X509 req in payload\n",
			__FILE__, __LINE__);
	pl->rt = 0;
	ASN1_INTEGER_set(pl->requesttype, pl->rt);
	pl->od.req = req;
	payload_build_original(pl);
	return 0;
}
int	payload_set_req_from_file(payload_t *pl, char *filename) {
	BIO	*inbio;
	inbio = payload_set_common(pl, filename);
	if (inbio == NULL)
		return -1;
	/* read an X509 request (in DER form) from the file		*/
	payload_set_req(pl, d2i_X509_REQ_bio(inbio, NULL));
	BIO_free(inbio);
	return 0;
}

/*
 * payload_set_spki_from_file	read a Nescape SPKI request from a file an
 *				assign it to the spki member
 */
int	payload_set_spki(payload_t *pl, NETSCAPE_SPKI *spki) {
	if (debug)
		BIO_printf(bio_err, "%s:%d: setting SPKI in payload\n",
			__FILE__, __LINE__);
	pl->rt = 1;
	ASN1_INTEGER_set(pl->requesttype, pl->rt);
	pl->od.spki = spki;
	payload_build_original(pl);
	return 0;
}
int	payload_set_spki_from_file(payload_t *pl, char *filename) {
	BIO	*inbio;
	inbio = payload_set_common(pl, filename);
	if (inbio == NULL)
		return -1;
	/* read a SPKI from the file					*/
	payload_set_spki(pl, d2i_NETSCAPE_SPKI_bio(inbio, NULL));
	BIO_free(inbio);
	return 0;
}

/*
 * payload_get_pubkey	extract the public key from the payload request, used
 *			to compute transaction ids and such stuff
 */
EVP_PKEY	*payload_get_pubkey(payload_t *pl) {
	switch (pl->rt) {
	case 0:
		return X509_REQ_get_pubkey(pl->od.req);
		break;
	case 1:
		return NETSCAPE_SPKI_get_pubkey(pl->od.spki);
		break;
	}
	return NULL;
}

/*
 * payload_dn_to_attrs	set attributes from the distinguished name
 */
int	payload_dn_to_attrs(payload_t *pl, char *dn) {
	X509_NAME	*name;
	ASN1_OBJECT	*us;
	ASN1_STRING	*as;
	X509_NAME_ENTRY	*ne;
	int		i, n;

	/* getting a X509_name from the dn is easy...			*/
	name = ldap_to_x509(dn);
	if (name == NULL)
		return -1;
	if (debug)
		BIO_printf(bio_err, "%s:%d: converted dn '%s' to X509_NAME "
			"@%p\n", __FILE__, __LINE__, dn, name);

	/* new we have to fetch the components and store them as attrs	*/
	n = X509_NAME_entry_count(name);
	if (debug)
		BIO_printf(bio_err, "%s:%d: X509_NAME has %d components\n",
			__FILE__, __LINE__, n);
	for (i = 0; i < n; i++) {
		ne = X509_NAME_get_entry(name, i);
		us = X509_NAME_ENTRY_get_object(ne);
		as = X509_NAME_ENTRY_get_data(ne);
		if (debug)
			BIO_printf(bio_err, "%s:%d: adding attr %s = %*.*s "
				"(type %d)\n", __FILE__, __LINE__,
				OBJ_nid2sn(OBJ_obj2nid(us)), 
				as->length, as->length,
				(as->data) ? (char *)as->data : "(null)",
				as->type);
		X509at_add1_attr_by_OBJ(&pl->attributes, us,
			as->type, as->data, as->length);
	}
	return 0;
}

#define	nNameattrs	6
static char	*nameattrs[nNameattrs] = { "CN", "OU", "O", "L", "ST", "C" };

X509_NAME	*x509_name_from_attributes(STACK_OF(X509_ATTRIBUTE) *attrs) {
	int		i = 0, j;
	X509_NAME	*n;
	X509_ATTRIBUTE	*xa;
	ASN1_TYPE	*t;

	n = X509_NAME_new();
	if (debug)
		BIO_printf(bio_err, "%s:%d: converting attributes into "
			"X509_NAME\n", __FILE__, __LINE__);

	/* find out whether an unstructuredName was requested		*/
	i = X509at_get_attr_by_NID(attrs, OBJ_ln2nid("unstructuredName"), 0);
	if (i >= 0) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: unstructuredName case\n",
				__FILE__, __LINE__);
		xa = X509at_get_attr(attrs, i);
		t = X509_ATTRIBUTE_get0_type(xa, 0); 
		X509_NAME_add_entry_by_txt(n, "unstructuredName",
			V_ASN1_PRINTABLESTRING,
			t->value.asn1_string->data,
			t->value.asn1_string->length, 0, 1);
			
		return n;
	}
	
	/* construct an X509 name from the attributes			*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: complex name case\n", __FILE__,
			__LINE__);
	for (i = 0; i < nNameattrs; i++) {
		j = X509at_get_attr_by_NID(attrs, OBJ_sn2nid(nameattrs[i]), -1);
		if (j >= 0) {
			if (debug)
				BIO_printf(bio_err, "%s:%d: adding attribute "
					"%s\n", __FILE__, __LINE__,
					nameattrs[i]);
			xa = X509at_get_attr(attrs, j);
			t = X509_ATTRIBUTE_get0_type(xa, 0); 
			X509_NAME_add_entry_by_NID(n, OBJ_sn2nid(nameattrs[i]),
				V_ASN1_PRINTABLESTRING,
				t->value.asn1_string->data,
				t->value.asn1_string->length, 0, 1);
			if (debug)
				BIO_printf(bio_err, "%s:%d: value '%*.*s'\n",
					__FILE__, __LINE__, 
					t->value.asn1_string->length,
					t->value.asn1_string->length,
					t->value.asn1_string->data);
		}
	}
	return n;
}

