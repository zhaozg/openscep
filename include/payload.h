/*
 * payload.h -- 
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: payload.h,v 1.1 2002/02/19 23:40:05 afm Exp $
 */
#ifndef _PAYLOAD_H
#define _PAYLOAD_H

#include <openssl/asn1.h>
#include <openssl/x509.h>

typedef struct payload_s {
	/* these attribute are for encoding/decoding only		*/
	ASN1_INTEGER			*requesttype;
	ASN1_BIT_STRING			*original;
	STACK_OF(X509_ATTRIBUTE)	*attributes;
	/* the next attributes are initialized after decoding, so that	*/
	/* the contents of the original request become more easily	*/
	/* accessible							*/
	long				rt;
	union {
		X509_REQ	*req;
		NETSCAPE_SPKI	*spki;
	} od;
} payload_t;

/* standard methods as for all other ASN.1 structures in OpenSSL	*/
extern payload_t	*payload_new(void);
extern void		payload_free(payload_t *a);
extern int		i2d_payload(payload_t *a, unsigned char **pp);
extern payload_t	*d2i_payload(payload_t **a, unsigned char **pp,
				long length);
#define	d2i_payload_bio(bp,pl)	(payload_t *)ASN1_d2i_bio((char *(*)())\
		payload_new, (char *(*)())d2i_payload, (bp),\
		(unsigned char **)(pl))
#define	i2d_payload_bio(bp,pl)	ASN1_i2d_bio(i2d_payload, (bp),\
		(unsigned char *)(pl))

/* function to build the original data ASN1_BIT_STRING 			*/
extern void	payload_build_original(payload_t *pl);

/* setters								*/
extern int	payload_set_spki(payload_t *pl, NETSCAPE_SPKI *spki);
extern int	payload_set_spki_from_file(payload_t *pl, char *filename);
extern int	payload_set_req(payload_t *pl, X509_REQ *req);
extern int	payload_set_req_from_file(payload_t *pl, char *filename);

/* getters								*/
extern X509_REQ		*payload_getreq(payload_t *);
extern NETSCAPE_SPKI	*payload_getspki(payload_t *);
extern long	payload_get_requesttype(payload_t *);
extern EVP_PKEY	*payload_get_pubkey(payload_t *pl);

extern int	payload_dn_to_attrs(payload_t *pl, char *dn);
extern char	*payload_attrs_to_dn(payload_t *pl);

extern X509_NAME	*x509_name_from_attributes(
				STACK_OF(X509_ATTRIBUTE) *attrs);

#endif /* _PAYLOAD_H */
