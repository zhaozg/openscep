/*
 * isasu.h -- implements issuer and subject methods
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: isasu.h,v 1.3 2001/03/12 19:45:03 afm Exp $
 */
#ifndef _ISASU_H
#define _ISASU_H

#include <openssl/x509.h>

typedef struct {
	X509_NAME	*issuer;
	X509_NAME	*subject;
} issuer_and_subject_t;

extern int	i2d_issuer_and_subject(issuer_and_subject_t *isasu,
			unsigned char **data);
#define	i2d_issuer_and_subject_bio(bp, isasu)				\
	ASN1_i2d_bio(i2d_issuer_and_subject,bp,(unsigned char *)isasu)
extern issuer_and_subject_t	*d2i_issuer_and_subject(
		issuer_and_subject_t **a, unsigned char **pp, long length);
#define	d2i_issuer_and_subject_bio(bp, isasu)				\
	(issuer_and_subject_t *)ASN1_d2i_bio(				\
		(char *(*)())issuer_and_subject_new,			\
		(char *(*)())d2i_issuer_and_subject, (bp),		\
		(unsigned char **)isasu)
extern issuer_and_subject_t	*issuer_and_subject_new(void);
extern void	issuer_and_subject_free(issuer_and_subject_t *isasu);

/*
   The defines for the {d2i,i2d}_issuer_and_serial_bio functions above
   replace prototypes of the the following form:

	extern issuer_and_subject_t	*d2i_issuer_and_subject_bio(BIO *in,
		issuer_and_subject_t **isasu);
	extern int	i2d_issuer_and_subject_bio(BIO *out,
			issuer_and_subject_t *isasu);
*/

#endif /* _ISASU_H */





