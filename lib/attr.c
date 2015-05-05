/*
 * attr.c -- some attribute handling routines
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: attr.c,v 1.3 2002/02/19 23:40:06 afm Exp $
 */
#include <attr.h>
#include <init.h>

int	attr_add_string(STACK_OF(X509_ATTRIBUTE) *attrs, int nid, char *data) {
	ASN1_STRING	*asn1_string = NULL;
	X509_ATTRIBUTE	*xa;

	if (debug)
		BIO_printf(bio_err, "%s:%d: adding string attr %s (nid = %d) = '%s'\n",
			__FILE__, __LINE__, OBJ_nid2sn(nid), nid, data);
	asn1_string = ASN1_STRING_new();
	ASN1_STRING_set(asn1_string, data, strlen(data));
	xa = X509_ATTRIBUTE_create(nid, V_ASN1_PRINTABLESTRING, asn1_string);
	sk_X509_ATTRIBUTE_push(attrs, xa);
/*
	ASN1_STRING_free(asn1_string);
*/
	return 0;
}

int	attr_add_octet(STACK_OF(X509_ATTRIBUTE) *attrs, int nid,
	unsigned char *data, int len) {
	ASN1_STRING	*asn1_string = NULL;
	X509_ATTRIBUTE	*xa;

	if (debug)
		BIO_printf(bio_err, "%s:%d: adding octet attr %s (nid = %d) length %d\n",
			__FILE__, __LINE__, OBJ_nid2sn(nid), nid, len);
	asn1_string = ASN1_STRING_new();
	ASN1_STRING_set(asn1_string, data, len);
	xa = X509_ATTRIBUTE_create(nid, V_ASN1_OCTET_STRING, asn1_string);
	sk_X509_ATTRIBUTE_push(attrs, xa);
/*
	ASN1_STRING_free(asn1_string);
*/
	return 0;

}
