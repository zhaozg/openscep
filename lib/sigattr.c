/*
 * sigattr.c -- signed attribute mangling routines
 * 
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: sigattr.c,v 1.5 2002/02/19 23:40:06 afm Exp $
 */
#include <sigattr.h>
#include <init.h>
#include <openssl/err.h>

/*
 * read an attribute of type string
 */
char	*sigattr_string(scep_t *scep, char *attrname) {
	STACK_OF(X509_ATTRIBUTE)	*sig_attribs;
	ASN1_OBJECT			*asn1_obj;
	ASN1_TYPE			*asn1_type;
	X509_ATTRIBUTE			*attr;
	int				len, i;
	char				*data = NULL;
	scepmsg_t			*msg;
	
	if (debug)
		BIO_printf(bio_err, "%s:%d: looking for attribute '%s'\n",
			__FILE__, __LINE__, attrname);

	/* decide which message to study: client reads attrs from reply	*/
	if (scep->client)
		msg = &scep->reply;
	else
		msg = &scep->request;

	/* find the object we by name					*/
	asn1_obj = OBJ_nid2obj(OBJ_sn2nid(attrname));
	asn1_type = NULL;

	/* retrieve the stack of signed attributes			*/
	if (NULL == (sig_attribs = PKCS7_get_signed_attributes(msg->si))) {
		BIO_printf(bio_err, "%s:%d: no signed attributes\n",
			__FILE__, __LINE__);
		return NULL;
	}

	/* scan all attributes for the one we are looking for		*/
	for (i = 0; i < sk_X509_ATTRIBUTE_num(sig_attribs); i++) {
		attr = sk_X509_ATTRIBUTE_value(sig_attribs, i);
		if (OBJ_cmp(attr->object, asn1_obj) == 0) {
			if (debug)
				BIO_printf(bio_err, "%s:%d: found attribute\n",
					__FILE__, __LINE__);
			asn1_type = sk_ASN1_TYPE_value(attr->value.set, 0);
			break;
		}
	}

	/* if we cannot find the required argument, we just return NULL	*/
	if (asn1_type == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot find attribute\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (ASN1_TYPE_get(asn1_type) != V_ASN1_PRINTABLESTRING) {
		BIO_printf(bio_err, "%s:%d: attribute has wrong type\n",
			__FILE__, __LINE__);
		goto err;
	}

	if (debug)
		BIO_printf(bio_err, "%s:%d: found attribute '%s'\n", 
			__FILE__, __LINE__, attrname);
	/* unpack the ASN1_STRING into a C-String (0-terminated)	*/
	len = ASN1_STRING_length(asn1_type->value.asn1_string);
	data = (char *)malloc(1 + len);
	memcpy(data, ASN1_STRING_data(asn1_type->value.asn1_string), len);
	data[len] = '\0';
	if (debug)
		BIO_printf(bio_err, "%s:%d: value of %d bytes retrieved\n",
			__FILE__, __LINE__, len);

	/* return the data						*/
	return data;
err:
	ERR_print_errors(bio_err);
	return NULL;
}

/*
 * read an attribute of type octet string
 */
unsigned char	*sigattr_octet(scep_t *scep, char *attrname, int *len) {
	ASN1_OCTET_STRING		*asn1;
	unsigned char			*data = NULL;

	/* get the attribute as an ASN1_OCTET_STRING			*/
	asn1 = sigattr_asn1_octet(scep, attrname);
	if (asn1 == NULL)
		return NULL;
	if (debug)
		BIO_printf(bio_err, "%s:%d: go an asn1 string for %s\n",
			__FILE__, __LINE__);
	
	/* unpack the ASN1_STRING into a C-String (0-terminated)	*/
	*len = ASN1_STRING_length(asn1);
	data = (unsigned char *)malloc(*len);
	memcpy(data, ASN1_STRING_data(asn1), *len);
	if (debug)
		BIO_printf(bio_err, "%s:%d: allocated %d new bytes for value\n",
			__FILE__, __LINE__, *len);

	/* return the data						*/
	return data;
}


ASN1_OCTET_STRING	*sigattr_asn1_octet(scep_t *scep, char *attrname) {
	STACK_OF(X509_ATTRIBUTE)	*sig_attribs;
	ASN1_OBJECT			*asn1_obj;
	ASN1_TYPE			*asn1_type;
	X509_ATTRIBUTE			*attr;
	int				i;
	scepmsg_t			*msg;
	
	if (debug)
		BIO_printf(bio_err, "%s:%d: looking for attribute '%s'\n",
			__FILE__, __LINE__, attrname);

	/* decide which message to study: client reads attrs from reply	*/
	if (scep->client)
		msg = &scep->reply;
	else
		msg = &scep->request;

	/* find the object we by name					*/
	asn1_obj = OBJ_nid2obj(OBJ_sn2nid(attrname));
	asn1_type = NULL;

	/* retrieve the stack of signed attributes			*/
	if (NULL == (sig_attribs = PKCS7_get_signed_attributes(msg->si))) {
		BIO_printf(bio_err, "%s:%d: signed attributes not found\n",
			__FILE__, __LINE__);
		return NULL;
	}

	/* scan all attributes for the one we are looking for		*/
	for (i = 0; i < sk_X509_ATTRIBUTE_num(sig_attribs); i++) {
		attr = sk_X509_ATTRIBUTE_value(sig_attribs, i);
		if (OBJ_cmp(attr->object, asn1_obj) == 0) {
			if ((!attr->set) || (sk_ASN1_TYPE_num(attr->value.set)
				== 0)) {
				BIO_printf(bio_err, "%s:%d: attr has no val\n",
					__FILE__, __LINE__);
				goto err;
			}
			if (debug)
				BIO_printf(bio_err, "%s:%d: found matching "
					"attribute with %d values\n", __FILE__,
					__LINE__,
					sk_ASN1_TYPE_num(attr->value.set));
			asn1_type = sk_ASN1_TYPE_value(attr->value.set, 0);
			if (debug)
				BIO_printf(bio_err, "%s:%d: type found: %p\n",
					__FILE__, __LINE__, asn1_type);
			break;
		}
	}

	/* if we cannot find the required argument, we just return NULL	*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: checking for attribute\n",
			__FILE__, __LINE__);
	if (asn1_type == NULL) {
		BIO_printf(bio_err, "%s:%d: attribute has no type\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (ASN1_TYPE_get(asn1_type) != V_ASN1_OCTET_STRING) {
		BIO_printf(bio_err, "%s:%d: attribute has wrong type\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: found attribute '%s'\n", 
			__FILE__, __LINE__, attrname);

	/* this is an ASN1_OCTET_STRING, so we can retrieve the 	*/
	/* appropriate element of the union				*/
	return asn1_type->value.octet_string;

	/* error return, or attribute not found				*/
err:
	if (debug)
		BIO_printf(bio_err, "%s:%d: attribute not found or error\n",
			__FILE__, __LINE__);
	ERR_print_errors(bio_err);
	return NULL;
}


