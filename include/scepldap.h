/*
 * scepldap.h -- LDAP interface for openscep
 * 
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: scepldap.h,v 1.1.1.1 2001/03/03 22:18:47 afm Exp $
 */
#ifndef _SCEPLDAP_H
#define _SCEPLDAP_H

#include <ldap.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <isasu.h>

extern char		*x509_to_ldap(scep_t *scep, X509_NAME *name);
extern X509_NAME	*ldap_to_x509(char *dn);

extern int	scep_ldap_init(scep_t *scep);
extern int	ldap_store_cert(scep_t *scep);
extern int	ldap_get_cert_from_issuer_and_serial(scep_t *scep,
		PKCS7_ISSUER_AND_SERIAL *ias);
extern int	ldap_get_cert_from_issuer_and_subject(scep_t *scep,
		issuer_and_subject_t *ias);

#endif /* _SCEPLDAP_H */
